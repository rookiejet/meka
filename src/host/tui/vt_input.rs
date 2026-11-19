//! The raw-VT input path for Windows.
//!
//! crossterm's Windows input reads `INPUT_RECORD`s through `ReadConsoleInput`, which never reports
//! bracketed paste: the console swallows the `\e[200~`/`\e[201~` markers and every pasted line
//! break arrives as the Enter that sends a prompt. Turning on `ENABLE_VIRTUAL_TERMINAL_INPUT` and
//! reading the terminal as a byte stream instead is what makes the markers visible, so a pasted
//! paragraph can be reassembled into the single `Event::Paste` the append renderer already knows
//! how to send as one prompt.
//!
//! The bytes are parsed by `vt_parse`, a vendored copy of crossterm's own VT parser, so a key and
//! a paste arrive exactly as they do on Unix. A raw read sees neither a resize nor the mouse (the
//! append renderer captures no mouse), so the terminal size is re-checked on a timer.

use std::{
    io::{self, Read},
    time::Duration,
};

use crossterm::event::Event;
use tokio::sync::mpsc;

use super::vt_parse::VtParser;

/// The console input mode flag that makes the terminal's VT sequences — above all the
/// bracketed-paste markers — reach the reader as bytes rather than as keystrokes.
const ENABLE_VIRTUAL_TERMINAL_INPUT: u32 = 0x0200;

/// How much to read from the terminal at a time, the same figure crossterm reads by.
const READ_BUF: usize = 1_024;

/// How often to re-check the terminal size while waiting for input: a raw read reports keys and
/// paste, never a window resize.
const RESIZE_POLL: Duration = Duration::from_millis(200);

/// Turn on raw-VT input so the terminal's escape sequences reach the reader as bytes. Without it
/// the console filters the paste markers out and a multi-line paste submits once per line.
fn enable_vt_input() -> io::Result<()> {
    use windows_sys::Win32::System::Console::{
        GetConsoleMode, GetStdHandle, STD_INPUT_HANDLE, SetConsoleMode,
    };
    // SAFETY: the standard input handle is valid for the life of the process; the mode word is read
    // then written back with one flag added, so the raw-mode bits crossterm already set stay as
    // they are.
    let stdin = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
    let mut mode = 0u32;
    if unsafe { GetConsoleMode(stdin, &mut mode) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { SetConsoleMode(stdin, mode | ENABLE_VIRTUAL_TERMINAL_INPUT) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Read the terminal on its own thread, since a read blocks until the user types, and hand each
/// block of bytes to the parser over a channel the async side can wait on. Reading here rather than
/// in the task keeps a slow key from being cancelled mid-read and its bytes lost.
fn spawn_reader() -> mpsc::Receiver<io::Result<Vec<u8>>> {
    let (sender, receiver) = mpsc::channel(16);
    std::thread::spawn(move || {
        let mut stdin = io::stdin();
        loop {
            let mut buffer = [0u8; READ_BUF];
            let read = match stdin.read(&mut buffer) {
                Ok(0) => break, // the terminal is gone
                Ok(read) => read,
                Err(error) => {
                    let _ = sender.blocking_send(Err(error));
                    break;
                }
            };
            if sender
                .blocking_send(Ok(buffer.get(..read).unwrap_or(&[]).to_vec()))
                .is_err()
            {
                break; // the reader has been dropped
            }
        }
    });
    receiver
}

/// A source of crossterm events read from a raw VT byte stream on Windows, standing in for
/// `EventStream` where that would lose the bracketed paste. Its [`next`](Self::next) matches
/// `EventStream`'s so the append renderer's loop reads either one the same way.
pub(crate) struct RawVtSource {
    parser: VtParser,
    reader: mpsc::Receiver<io::Result<Vec<u8>>>,
    size: (u16, u16),
}

impl RawVtSource {
    pub(crate) fn new() -> Self {
        if let Err(error) = enable_vt_input() {
            tracing::debug!("failed to turn on raw-VT input: {error}");
        }
        Self {
            parser: VtParser::default(),
            reader: spawn_reader(),
            size: crossterm::terminal::size().unwrap_or((0, 0)),
        }
    }

    /// The next input event, or `None` once the terminal is gone. Bytes are read and parsed until
    /// one arrives; the size is re-checked whenever a wait for input times out, so a resize is not
    /// missed while the user is idle.
    pub(crate) async fn next(&mut self) -> Option<io::Result<Event>> {
        loop {
            if let Some(event) = self.parser.next_event() {
                return Some(Ok(event));
            }
            if let Some(resize) = self.resize() {
                return Some(Ok(resize));
            }
            tokio::select! {
                block = self.reader.recv() => match block {
                    Some(Ok(bytes)) => {
                        // As crossterm reads: more is pending only when a full block came back.
                        let more = bytes.len() == READ_BUF;
                        self.parser.feed(&bytes, more);
                    }
                    Some(Err(error)) => return Some(Err(error)),
                    None => return None,
                },
                () = tokio::time::sleep(RESIZE_POLL) => {}
            }
        }
    }

    /// A resize since the last look, which a raw read never reports and so is polled instead.
    fn resize(&mut self) -> Option<Event> {
        let size = crossterm::terminal::size().ok()?;
        if size != self.size {
            self.size = size;
            return Some(Event::Resize(size.0, size.1));
        }
        None
    }
}
