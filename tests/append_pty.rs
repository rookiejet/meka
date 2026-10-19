//! The append renderer, driven through a real pseudo-terminal.
//!
//! The screen suite (`tui_pty.rs`) asserts on rows as a terminal emulator sees them; the append
//! renderer's claim is stronger and more primitive, so its suite asserts on both: the raw byte
//! stream, where a row that prints twice cannot hide behind a redraw, and the terminal emulator's
//! rows, where what the user sees is read back. The terminal is kept the whole run, so a test can
//! also say what the child left it like.
//!
//! Unix only, and only where the scripted provider (`MEKA_MOCK_PROVIDER`) is compiled in, which a
//! release build does without the `mock-provider` feature.
#![cfg(all(unix, any(debug_assertions, feature = "mock-provider")))]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "a test panics on failure by design"
)]

use std::{
    ffi::CString,
    os::{fd::RawFd, unix::ffi::OsStrExt},
    time::{Duration, Instant},
};

use support::Install;

#[path = "harness/support.rs"]
mod support;

const ROWS: u16 = 40;
const COLUMNS: u16 = 100;

/// The interactive config every test runs on, with the renderer as the one thing each varies.
fn config_install(renderer: &str) -> Install {
    let install = Install::new();
    install.write_config(&format!(
        "default_profile = \"default\"\n\n\
         [permissions]\ndefault = \"read\"\nenabled = [\"read\"]\n\n\
         [display]\nrenderer = \"{renderer}\"\n\
         [accounts.default]\nbackend = \"openai-chat-completions\"\n\
         base_url = \"http://127.0.0.1:9/\"\n\n\
         [profiles.default]\naccount = \"default\"\nmodel = \"mock-model\"\n"
    ));
    install
}

/// The append renderer, as the config asks for it.
fn append_install() -> Install {
    config_install("append")
}

/// What the screen showed just before each beat was acted on, in order. The rows are trimmed on
/// the right, and trailing blank rows are dropped.
type Screens = Vec<Vec<String>>;

/// One step of a driven session: a line sent to the child, or a look at the screen with nothing
/// sent, which is how a test catches a turn in progress.
#[derive(Debug, Clone, Copy)]
enum Beat {
    Type(&'static str),
    /// Keys written as they are, with no Enter after them: what stays in the composer.
    Keys(&'static str),
    Observe,
}

/// What one driven session came to.
struct Run {
    /// The screen as it stood before each beat.
    screens: Screens,
    /// Every byte the child ever wrote, escapes included.
    raw: Vec<u8>,
    /// The status the child left with on its own: its exit code, or -1 when a signal took it. A
    /// child that never leaves fails the run before this exists.
    exit: i32,
    /// Whether the terminal was left with its line editing and echo back, the way raw mode takes
    /// them and gives them back.
    cooked: bool,
}

impl Run {
    /// The screen before the last beat, which is the one every test ends with.
    fn final_screen(&self) -> &[String] {
        self.screens.last().expect("at least one beat was played")
    }

    /// The whole run as text, escapes stripped: what the terminal's scrollback would hold.
    fn text(&self) -> String {
        strip_ansi(&self.raw)
    }
}

/// Run one interactive session on the script, playing `beats` one at a time whenever the child
/// has been quiet for a moment.
fn drive(install: &Install, args: &[&str], beats: &[Beat]) -> Run {
    let mut master: RawFd = -1;
    let size = libc::winsize {
        ws_row: ROWS,
        ws_col: COLUMNS,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    let prepared = PreparedExec::meka(install, args);
    // SAFETY: `forkpty` with a null termios and a sized window is the documented way to get a pty
    // pair plus a child. The child branch below does nothing but `exec`, which is the one thing
    // that is defined after `fork` in a threaded process.
    let pid = unsafe {
        libc::forkpty(
            &mut master,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &size as *const libc::winsize as *mut libc::winsize,
        )
    };
    assert!(pid >= 0, "forkpty failed");
    if pid == 0 {
        // SAFETY: the child of a threaded process, so only what `PreparedExec::exec` promises.
        unsafe { prepared.exec() }
    }
    keep_master_here(master);
    let (screens, raw) = pump(master, beats);
    // The child is asked to leave by every test's last beat; this waits for that rather than
    // forcing it, so the status is its own and the terminal it left behind is its own too. A
    // child that never leaves is killed, and the give-up fails the test that ran it with the
    // kernel's account of what the child was doing attached to the failure.
    // SAFETY: `pid` is the child `forkpty` forked, reaped here and nowhere else, and `master` is
    // the descriptor it handed back, still open until the close below.
    let exit = unsafe {
        let mut status = 0;
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            if libc::waitpid(pid, &mut status, libc::WNOHANG) == pid {
                break if libc::WIFEXITED(status) {
                    libc::WEXITSTATUS(status)
                } else {
                    -1
                };
            }
            if Instant::now() > deadline {
                let account = hang_account(pid);
                libc::kill(pid, libc::SIGKILL);
                libc::waitpid(pid, &mut status, 0);
                panic!("the session never left when it was asked to; the child was:\n{account}");
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    };
    let cooked = terminal_is_cooked(master);
    // SAFETY: `master` is the fd `forkpty` handed back and is still open here.
    unsafe { libc::close(master) };
    Run {
        screens,
        raw,
        exit,
        cooked,
    }
}

/// Keep the pty's master out of every child this process forks from here on: `forkpty` hands it
/// back without close-on-exec, and tests fork in parallel, so another test's child would carry
/// a copy of it and keep that terminal open past the close that is meant to hang it up.
fn keep_master_here(master: RawFd) {
    // SAFETY: `master` is the fd `forkpty` just handed back.
    let flagged = unsafe { libc::fcntl(master, libc::F_SETFD, libc::FD_CLOEXEC) };
    assert!(flagged == 0, "close-on-exec on the master");
}

/// The kernel's account of where a driven session stood when the driver gave up waiting for it to
/// leave: what it is doing and what it holds open, for a give-up that means the run under test
/// hung. Best effort and cross-platform: a tool that is missing simply notes itself in the text.
/// The account rides the failure that accompanies it out of the test harness — it must never
/// touch the working tree.
fn hang_account(pid: i32) -> String {
    let cmd = format!(
        "ps -o pid,stat,wchan,command -p {pid}
        procstat -t {pid}
        procstat -f {pid} | head -30
        timeout 3 truss -p {pid} 2>&1 | tail -30"
    );
    let Ok(out) = std::process::Command::new("sh").arg("-c").arg(cmd).output() else {
        return format!("nothing: the tools that read what child {pid} holds did not run");
    };
    let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&out.stderr));
    text
}

/// A `meka` command line with everything its exec needs laid out ahead of the fork: the child of
/// a threaded process may allocate nothing and take no lock between the fork and the exec, since
/// a lock another thread held at the fork is held forever in the child.
struct PreparedExec {
    program: CString,
    directory: CString,
    /// One past the highest descriptor the child closes, read ahead of the fork since the child
    /// may not ask: the soft limit, within bounds, as a test process holds a few hundred at most.
    descriptors: libc::c_int,
    /// Owned by the two vectors below the pointers, which point into them.
    _arguments: Vec<CString>,
    _environment: Vec<CString>,
    argv: Vec<*const libc::c_char>,
    envp: Vec<*const libc::c_char>,
}

impl PreparedExec {
    fn meka(install: &Install, args: &[&str]) -> Self {
        let mut command = support::meka();
        command
            .args(args)
            .current_dir(install.work_dir())
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("TERM", "xterm-256color")
            // The sandbox advisories are facts about the kernel the suite runs on, and would be
            // rows of their own on the screen. The two `rmcp` directives are meka's defaults,
            // restated because `RUST_LOG` replaces the filter outright.
            .env(
                "RUST_LOG",
                "warn,meka::sandbox=error,rmcp::transport::common::client_side_sse=error,\
                 rmcp::transport::worker=off",
            );
        install.env(&mut command);
        let c_string = |text: &std::ffi::OsStr| CString::new(text.as_bytes()).expect("no NUL");
        let arguments: Vec<CString> = std::iter::once(command.get_program())
            .chain(command.get_args())
            .map(c_string)
            .collect();
        let environment: Vec<CString> = command
            .get_envs()
            .filter_map(|(key, value)| {
                let mut pair = key.to_os_string();
                pair.push("=");
                pair.push(value?);
                Some(c_string(&pair))
            })
            .collect();
        let with_end = |strings: &[CString]| -> Vec<*const libc::c_char> {
            strings
                .iter()
                .map(|string| string.as_ptr())
                .chain(std::iter::once(std::ptr::null()))
                .collect()
        };
        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: `getrlimit` writes the struct it is given.
        let read = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) };
        assert!(read == 0, "the descriptor limit");
        Self {
            descriptors: libc::c_int::try_from(limit.rlim_cur)
                .unwrap_or(libc::c_int::MAX)
                .clamp(1024, 65_536),
            program: c_string(command.get_program()),
            directory: c_string(install.work_dir().as_os_str()),
            argv: with_end(&arguments),
            envp: with_end(&environment),
            _arguments: arguments,
            _environment: environment,
        }
    }

    /// Replace the process with the command. Only `close`, `chdir`, `execve` and `_exit`, each
    /// async-signal-safe, which is what makes this callable in the child of a threaded process.
    /// Every descriptor past the three standard ones is closed first: a master another test
    /// opened between its `forkpty` and its close-on-exec flag would otherwise ride along.
    ///
    /// # Safety
    ///
    /// Call only in a child just forked from this process; it never returns.
    unsafe fn exec(&self) -> ! {
        // SAFETY: the strings and pointer arrays were laid out before the fork and are
        // NUL-terminated; nothing here allocates.
        unsafe {
            for descriptor in 3..self.descriptors {
                libc::close(descriptor);
            }
            libc::chdir(self.directory.as_ptr());
            libc::execve(
                self.program.as_ptr(),
                self.argv.as_ptr(),
                self.envp.as_ptr(),
            );
            libc::_exit(127)
        }
    }
}

/// Read the master side into a terminal emulator, snapshotting the screen and playing the next
/// beat whenever the child falls quiet. The append renderer writes nothing while it waits, so
/// quiet here is bytes and not rows standing still.
fn pump(master: RawFd, beats: &[Beat]) -> (Screens, Vec<u8>) {
    let mut parser = vt100::Parser::new(ROWS, COLUMNS, 0);
    let mut screens = Vec::new();
    let mut raw: Vec<u8> = Vec::new();
    let mut pending: Vec<Beat> = beats.to_vec();
    pending.reverse();
    let mut buffer = [0u8; 65536];
    let mut last_activity = Instant::now();
    // The first beat waits longer: the child has a store to migrate before it draws anything.
    let mut quiet_needed = Duration::from_millis(2500);
    let deadline = Instant::now() + Duration::from_secs(90);

    while Instant::now() < deadline {
        // SAFETY: `master` is open, and the buffer outlives the call.
        let read = unsafe {
            let mut poll = libc::pollfd {
                fd: master,
                events: libc::POLLIN,
                revents: 0,
            };
            if libc::poll(&mut poll, 1, 250) > 0 && poll.revents & libc::POLLIN != 0 {
                libc::read(master, buffer.as_mut_ptr().cast(), buffer.len())
            } else {
                -1
            }
        };
        if read > 0 {
            // A terminal that speaks the kitty keyboard protocol answers the flags query; the
            // device attributes after it are what a terminal that does not would send alone.
            if buffer[..read as usize]
                .windows(4)
                .any(|window| window == b"\x1b[?u")
            {
                write_all(master, b"\x1b[?0u\x1b[?1;2c");
            }
            raw.extend_from_slice(&buffer[..read as usize]);
            let before = quiet_rows(&parser);
            parser.process(&buffer[..read as usize]);
            // The working row redraws while a turn runs, which is not the screen moving on: the
            // bytes count as activity only when something other than the working row changed.
            if quiet_rows(&parser) != before {
                last_activity = Instant::now();
            }
        } else if read == 0 {
            break;
        }
        if last_activity.elapsed() > quiet_needed {
            match pending.pop() {
                Some(Beat::Type(line)) => {
                    screens.push(rows_of(&parser));
                    write_all(master, line.as_bytes());
                    // A lone control byte is a keystroke, not a line.
                    if line.len() > 1 || !line.starts_with(|c: char| c.is_control()) {
                        write_all(master, b"\r");
                    }
                    last_activity = Instant::now();
                    quiet_needed = Duration::from_millis(1500);
                }
                Some(Beat::Keys(keys)) => {
                    screens.push(rows_of(&parser));
                    write_all(master, keys.as_bytes());
                    last_activity = Instant::now();
                    quiet_needed = Duration::from_millis(1500);
                }
                Some(Beat::Observe) => {
                    screens.push(rows_of(&parser));
                    last_activity = Instant::now();
                    quiet_needed = Duration::from_millis(1500);
                }
                // Everything played and the child has gone quiet: it has exited or is idle, and
                // either way there is nothing left to capture.
                None if last_activity.elapsed() > Duration::from_secs(4) => break,
                None => {}
            }
        }
    }
    (screens, raw)
}

/// Whether the terminal is left the way a shell wants it: line editing and echo on, which raw
/// mode takes and gives back.
fn terminal_is_cooked(master: RawFd) -> bool {
    let mut settings: libc::termios = unsafe { std::mem::zeroed() };
    // SAFETY: `master` is an open pty; `tcgetattr` fills the struct it is given.
    let got = unsafe { libc::tcgetattr(master, &mut settings) };
    got == 0 && settings.c_lflag & libc::ICANON != 0 && settings.c_lflag & libc::ECHO != 0
}

/// The screen as the pump judges whether it has settled: the working row masked, since its spinner
/// and seconds move for as long as a turn runs.
fn quiet_rows(parser: &vt100::Parser) -> Vec<String> {
    rows_of(parser)
        .into_iter()
        .map(|row| {
            if row.contains("Esc to stop") || row.contains("Waiting for your answer") {
                "<working row>".to_string()
            } else {
                row
            }
        })
        .collect()
}

fn rows_of(parser: &vt100::Parser) -> Vec<String> {
    let mut rows: Vec<String> = parser
        .screen()
        .rows(0, parser.screen().size().1)
        .map(|row| row.trim_end().to_string())
        .collect();
    while rows.last().is_some_and(String::is_empty) {
        rows.pop();
    }
    rows
}

fn write_all(fd: RawFd, bytes: &[u8]) {
    let mut written = 0;
    while written < bytes.len() {
        // SAFETY: writing a sub-slice of a live buffer to an open fd.
        let count =
            unsafe { libc::write(fd, bytes[written..].as_ptr().cast(), bytes.len() - written) };
        if count <= 0 {
            return;
        }
        written += count as usize;
    }
}

/// The bytes as text with every escape sequence taken out: what the scrollback reads as.
fn strip_ansi(raw: &[u8]) -> String {
    let text = String::from_utf8_lossy(raw);
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch != '\x1b' {
            out.push(ch);
            continue;
        }
        match chars.peek() {
            Some('[') => {
                chars.next();
                for ch in chars.by_ref() {
                    if ('\x40'..='\x7e').contains(&ch) {
                        break;
                    }
                }
            }
            Some(']') => {
                chars.next();
                for ch in chars.by_ref() {
                    if ch == '\x07' {
                        break;
                    }
                    if ch == '\x1b' {
                        chars.next();
                        break;
                    }
                }
            }
            Some(_) => {
                chars.next();
            }
            None => {}
        }
    }
    out
}

fn count(haystack: &str, needle: &str) -> usize {
    haystack.match_indices(needle).count()
}

const ONE_TURN: &str = r#"[
 [{"type":"text","text":"First answer."},
  {"type":"message_end","stop_reason":"end_turn"}]
]"#;

const TWO_TURNS: &str = r#"[
 [{"type":"text","text":"First answer."},
  {"type":"message_end","stop_reason":"end_turn"}],
 [{"type":"text","text":"Second answer."},
  {"type":"message_end","stop_reason":"end_turn"}]
]"#;

const TWO_WRITES: &str = r#"[
 [{"type":"tool_use_start","id":"t1","name":"file_write"},
  {"type":"tool_use_end","input":{"path":"a.txt","content":"a"}},
  {"type":"message_end","stop_reason":"tool_use"}],
 [{"type":"text","text":"wrote a"},
  {"type":"message_end","stop_reason":"end_turn"}]
]"#;

/// One paragraph settled early, then a pause a driver can watch the turn through, then the rest.
const STREAMED: &str = r#"[
 [{"type":"text","text":"First paragraph.\n\n"},
  {"type":"sleep","ms":2800},
  {"type":"text","text":"Second paragraph."},
  {"type":"message_end","stop_reason":"end_turn"}]
]"#;

/// A turn that takes a while to answer, so a line sent in the middle of it steers it.
const SLOW_TURN: &str = r#"[
 [{"type":"sleep","ms":2800},
  {"type":"text","text":"Done."},
  {"type":"message_end","stop_reason":"end_turn"}]
]"#;

/// The append renderer never takes the screen: no alternate buffer, no mouse capture, no
/// clipboard writes. The terminal a shell handed over is the terminal the run prints on.
#[test]
fn the_normal_buffer_is_never_taken() {
    let install = append_install();
    install.write_script(ONE_TURN);
    let run = drive(&install, &["-c"], &[Beat::Type("hi"), Beat::Type("/exit")]);
    let raw = String::from_utf8_lossy(&run.raw);
    for taken in [
        "\x1b[?1049", // the alternate screen
        "\x1b[?1000",
        "\x1b[?1002",
        "\x1b[?1003", // the mouse
        "\x1b[?1006",
        "\x1b]52;", // the clipboard
    ] {
        assert!(
            !raw.contains(taken),
            "the run took {taken:?} away from the normal buffer"
        );
    }
    assert!(
        run.text().contains("First answer."),
        "and it still prints the conversation: {:?}",
        run.text()
    );
}

/// The rows of two turns are in the scrollback once each and in the order they happened: what
/// printing once means on a terminal that nothing redraws. The `--renderer` flag runs this one,
/// over a config that asks for the screen.
#[test]
fn a_turns_rows_append_once_in_order() {
    let install = config_install("screen");
    install.write_script(TWO_TURNS);
    let run = drive(&install, &["-c", "--renderer", "append"], &[
        Beat::Type("hi"),
        Beat::Type("again"),
        Beat::Type("/exit"),
    ]);
    let text = run.text();
    for row in ["First answer.", "Second answer."] {
        assert_eq!(count(&text, row), 1, "{row} printed once: {text:?}");
    }
    assert_eq!(
        count(&text, "• Finished at"),
        2,
        "one closing row per turn: {text:?}"
    );
    let first = text.find("First answer.").expect("the first answer");
    let closed = text.find("• Finished at").expect("the closing row");
    let second = text.find("Second answer.").expect("the second answer");
    assert!(
        first < closed && closed < second,
        "rows in the order they happened: {text:?}"
    );
    let rows = run.final_screen();
    assert_eq!(
        rows.iter().filter(|row| *row == "  First answer.").count(),
        1,
        "and the screen shows each exactly once: {rows:#?}"
    );
    assert_eq!(
        rows.iter().filter(|row| *row == "  Second answer.").count(),
        1,
        "{rows:#?}"
    );
    assert!(
        rows.iter()
            .position(|row| row == "> again")
            .is_some_and(|again| {
                rows.iter()
                    .position(|row| row == "  First answer.")
                    .is_some_and(|first| first < again)
            }),
        "the second prompt is below the whole first turn: {rows:#?}"
    );
}

/// A streamed answer prints as it arrives: the first paragraph is in the scrollback while the
/// turn is still running, and the second follows it as a block of its own.
#[test]
fn streaming_text_prints_before_the_turn_ends() {
    let install = append_install();
    install.write_script(STREAMED);
    let run = drive(&install, &["-c"], &[
        Beat::Type("hi"),
        Beat::Observe,
        Beat::Type("/exit"),
    ]);
    let midturn = run
        .screens
        .get(1)
        .expect("the screen caught mid-turn is snapshotted");
    assert!(
        midturn.iter().any(|row| row == "  First paragraph."),
        "the settled paragraph printed while the turn ran: {midturn:#?}"
    );
    assert!(
        !midturn.iter().any(|row| row.contains("Second paragraph.")),
        "the turn has not finished speaking: {midturn:#?}"
    );
    let rows = run.final_screen();
    let first = rows
        .iter()
        .position(|row| row == "  First paragraph.")
        .expect("the first paragraph: {rows:#?}");
    let second = rows
        .iter()
        .position(|row| row == "  Second paragraph.")
        .expect("the second paragraph: {rows:#?}");
    assert!(
        first < second && rows[first + 1].is_empty() && rows[second - 1].is_empty(),
        "the two paragraphs are separate blocks with one blank between: {rows:#?}"
    );
}

/// A line sent while the turn runs is queued for it, marked as waiting rather than dropped.
#[test]
fn a_line_sent_mid_turn_steers_the_turn() {
    let install = append_install();
    install.write_script(SLOW_TURN);
    let run = drive(&install, &["-c"], &[
        Beat::Type("hi"),
        Beat::Type("more"),
        Beat::Type("/exit"),
    ]);
    let rows = run.final_screen();
    assert!(
        rows.iter().any(|row| row == "> more"),
        "the line is on the transcript when it is sent: {rows:#?}"
    );
    assert!(
        rows.iter().any(|row| row.trim() == "(steer, waiting)"),
        "and marked as waiting for the running turn: {rows:#?}"
    );
}

/// While the turn runs, a working row sits above the composer: the spinner, what the agent does,
/// the seconds it has run, and the key that stops it. When the turn ends the row is gone.
#[test]
fn a_running_turn_shows_a_working_row_that_clears_when_it_ends() {
    let install = append_install();
    install.write_script(SLOW_TURN);
    let run = drive(&install, &["-c"], &[
        Beat::Type("hi"),
        Beat::Observe,
        Beat::Type("/exit"),
    ]);
    let midturn = run
        .screens
        .get(1)
        .expect("the screen caught mid-turn is snapshotted");
    assert!(
        midturn
            .iter()
            .any(|row| row.contains("Working") && row.contains("Esc to stop")),
        "the working row shows while the turn runs: {midturn:#?}"
    );
    assert!(
        !run.final_screen()
            .iter()
            .any(|row| row.contains("Esc to stop")),
        "the working row is gone when the run leaves: {:#?}",
        run.final_screen()
    );
}

/// The permission prompt is rows of the transcript with an answer line under them: the call and
/// its args, the answers it takes, and one line to answer on.
#[test]
fn an_approval_prints_inline_and_answers_on_one_line() {
    let install = append_install();
    install.write_script(TWO_WRITES);
    let run = drive(&install, &["-c"], &[
        Beat::Type("/approvals on"),
        Beat::Type("write a"),
        Beat::Type("y"),
        Beat::Type("/exit"),
    ]);
    let asked = run
        .screens
        .get(2)
        .expect("the screen with the question on it");
    assert!(
        asked.iter().any(|row| row == "  └ content: a"),
        "the call's arguments as a tree: {asked:#?}"
    );
    assert!(
        asked.iter().any(|row| {
            row == "  Allow (y) / Allow for the session (a) / Deny (n) / Deny for the session"
        }),
        "and the answers it takes: {asked:#?}"
    );
    let rows = run.final_screen();
    assert!(
        rows.iter().any(|row| row == "• file_write allowed"),
        "the answer is a row of its own: {rows:#?}"
    );
    assert!(
        rows.iter().any(|row| row == "• file_write a.txt  +1 -0"),
        "and the call settled into its tool row: {rows:#?}"
    );
    assert!(
        install.work_dir().join("a.txt").exists(),
        "the approved write ran"
    );
}

/// Slash commands answer in rows, on the same transcript as everything else.
#[test]
fn slash_commands_answer_in_rows() {
    let install = append_install();
    install.write_script(ONE_TURN);
    let run = drive(&install, &["-c"], &[
        Beat::Type("hi"),
        Beat::Type("/help"),
        Beat::Type("/session"),
        Beat::Type("/exit"),
    ]);
    let rows = run.final_screen();
    assert!(
        rows.iter()
            .any(|row| row.starts_with("  Current session: ")),
        "/session names the session: {rows:#?}"
    );
    let text = run.text();
    assert!(
        text.contains("/compact") && text.contains("/rewind"),
        "/help prints the command table: {text:?}"
    );
}

/// A log line is drawn only where the user's own filter lets it through, as on the screen: the
/// run keeps every line the wider filter passes for `/log`, and a default run (`warn`) must not
/// print the debug lines a turn writes between its rows. `/log` then has them.
#[test]
fn logs_below_the_users_filter_wait_for_slash_log() {
    let install = append_install();
    install.write_script(ONE_TURN);
    let run = drive(&install, &["-c"], &[
        Beat::Type("hi"),
        Beat::Type("/log"),
        Beat::Type("/exit"),
    ]);
    let before = run.screens[1].join("\n");
    assert!(
        before.contains("First answer."),
        "the turn has printed by then: {before}"
    );
    assert!(
        !before.contains("round usage"),
        "a debug line is not drawn under a `warn` filter: {before}"
    );
    let after = run.final_screen().join("\n");
    assert!(
        after.contains("round usage"),
        "but it was kept, and /log prints it: {after}"
    );
}

/// `/exit` leaves cleanly and gives the terminal its line editing and echo back.
#[test]
fn slash_exit_leaves_and_restores_the_terminal() {
    let install = append_install();
    install.write_script(ONE_TURN);
    let run = drive(&install, &["-c"], &[Beat::Type("hi"), Beat::Type("/exit")]);
    assert_eq!(run.exit, 0, "the run left on its own");
    assert!(run.cooked, "the terminal was given back cooked");
}

/// So does `Ctrl+D` on the empty composer of an idle run.
#[test]
fn ctrl_d_on_an_empty_composer_leaves() {
    let install = append_install();
    install.write_script(ONE_TURN);
    let run = drive(&install, &["-c"], &[Beat::Type("\x04")]);
    assert_eq!(run.exit, 0, "the run left on its own");
    assert!(run.cooked, "the terminal was given back cooked");
}

/// The status row the screen keeps under the composer sits under the composer here too, the
/// permission level first: what level the run sits at is on screen at all times, and it follows
/// `/permission` when the level changes. The row is redrawn chrome — the test reads the terminal
/// as it stands, since the scrollback must never carry it.
#[test]
fn the_permission_level_sits_under_the_composer() {
    let install = Install::new();
    install.write_config(
        "default_profile = \"default\"\n\n\
         [permissions]\ndefault = \"read\"\nenabled = [\"read\", \"unrestricted\"]\n\n\
         [display]\nrenderer = \"append\"\n\
         [session]\ncontext_window = 200000\n\
         [accounts.default]\nbackend = \"openai-chat-completions\"\n\
         base_url = \"http://127.0.0.1:9/\"\n\n\
         [profiles.default]\naccount = \"default\"\nmodel = \"mock-model\"\n",
    );
    let run = drive(&install, &["-c"], &[
        Beat::Type("/permission unrestricted"),
        Beat::Observe,
        Beat::Type("/exit"),
    ]);
    let rows = &run.screens[0];
    assert!(
        rows.len() >= 2 && rows[rows.len() - 2] == ">" && rows[rows.len() - 1].contains("read · "),
        "the level is on the row under the composer's input row, from the start: {rows:#?}"
    );
    let rows = &run.screens[1];
    assert!(
        rows.last()
            .is_some_and(|row| row.contains("unrestricted · ")),
        "and it follows /permission when the level changes: {rows:#?}"
    );
    assert_eq!(run.exit, 0, "the run left on its own");
}

/// The context gauge is on the same row, as soon as the window is known: the fact the screen
/// draws beside the level, redrawn under the composer rather than printed into the scrollback.
#[test]
fn the_context_gauge_sits_under_the_composer() {
    let install = Install::new();
    install.write_config(
        "default_profile = \"default\"\n\n\
         [permissions]\ndefault = \"read\"\nenabled = [\"read\"]\n\n\
         [display]\nrenderer = \"append\"\n\
         [session]\ncontext_window = 200000\n\
         [accounts.default]\nbackend = \"openai-chat-completions\"\n\
         base_url = \"http://127.0.0.1:9/\"\n\n\
         [profiles.default]\naccount = \"default\"\nmodel = \"mock-model\"\n",
    );
    let run = drive(&install, &["-c"], &[Beat::Type("/exit")]);
    let rows = run.final_screen();
    assert!(
        rows.last().is_some_and(|row| row.contains("/200.0k 0%")),
        "the gauge is on the row under the composer: {rows:#?}"
    );
    assert_eq!(run.exit, 0, "the run left on its own");
}

/// A pasted paragraph is one prompt: the terminal's bracketed paste is on, the composer takes the
/// paste with its line breaks, and the Enter after it sends the lot as one turn. Without it each
/// pasted line would be sent by the carriage return that ends it.
#[test]
fn a_multi_line_paste_is_one_prompt() {
    let install = append_install();
    install.write_script(ONE_TURN);
    let run = drive(&install, &["-c"], &[
        Beat::Type("\x1b[200~first line\rsecond line\x1b[201~"),
        Beat::Type("/exit"),
    ]);
    let raw = String::from_utf8_lossy(&run.raw);
    assert!(raw.contains("\x1b[?2004h"), "bracketed paste was asked for");
    let text = run.text();
    assert_eq!(
        count(&text, "First answer."),
        1,
        "one prompt, one turn: {text:?}"
    );
    let first = text.find("first line").expect("the first line is printed");
    let second = text
        .rfind("second line")
        .expect("the second line is printed");
    assert!(first < second, "in order: {text:?}");
    assert!(
        !text[first..second].contains("First answer."),
        "both lines are the one prompt, sent before the answer: {text:?}"
    );
    assert_eq!(run.exit, 0, "the run left on its own");
    assert!(run.cooked, "and gave the terminal back cooked");
    assert!(raw.contains("\x1b[?2004l"), "bracketed paste is turned off");
}

/// Alt+Enter and Ctrl+J type a line break into the composer; the Enter after them sends the
/// lines as one prompt, as a paste's breaks do.
#[test]
fn alt_enter_and_ctrl_j_type_a_line_break() {
    let install = append_install();
    install.write_script(ONE_TURN);
    let run = drive(&install, &["-c"], &[
        Beat::Type("top\x1b\rmiddle\x0abottom"),
        Beat::Type("/exit"),
    ]);
    let text = run.text();
    assert_eq!(
        count(&text, "First answer."),
        1,
        "one prompt, one turn: {text:?}"
    );
    let top = text.find("top").expect("the first line is printed");
    let middle = text.find("middle").expect("the second line is printed");
    let bottom = text.rfind("bottom").expect("the third line is printed");
    assert!(top < middle && middle < bottom, "in order: {text:?}");
    assert!(
        !text[top..bottom].contains("First answer."),
        "all three are the one prompt, sent before the answer: {text:?}"
    );
    assert_eq!(run.exit, 0, "the run left on its own");
}

/// A line break typed into the composer opens a row for the line after it: the composer grows
/// to show each line, rather than folding the break into a `↵` glyph on one row.
#[test]
fn a_line_break_in_the_composer_opens_a_row_for_the_next_line() {
    let install = append_install();
    install.write_script(ONE_TURN);
    let run = drive(&install, &["-c"], &[
        Beat::Keys("top\x1b\rmiddle"),
        Beat::Observe,
        Beat::Keys("\r"),
        Beat::Type("/exit"),
    ]);
    let rows = &run.screens[1];
    assert!(
        rows.iter().all(|row| !row.contains('\u{21b5}')),
        "no line-break glyph stands in for the break: {rows:#?}"
    );
    let top = rows
        .iter()
        .position(|row| row.starts_with("> top"))
        .unwrap_or_else(|| panic!("the first line is on the input row: {rows:#?}"));
    assert!(
        rows.get(top + 1)
            .is_some_and(|row| row.trim_end() == "  middle"),
        "the next line is on the row under it, indented to the text: {rows:#?}"
    );
    assert!(
        rows.get(top + 2)
            .is_some_and(|row| row.contains("read · ")),
        "the status row is under the input rows: {rows:#?}"
    );
    assert_eq!(run.exit, 0, "the run left on its own");
}

/// Backspacing over a line break takes its row away again: the composer shrinks back to the one
/// line, with nothing left over from the rows it had grown to.
#[test]
fn backspacing_over_a_line_break_shrinks_the_composer() {
    let install = append_install();
    install.write_script(ONE_TURN);
    let run = drive(&install, &["-c"], &[
        Beat::Keys("top\x1b\rmiddle"),
        Beat::Observe,
        Beat::Keys("\x7f\x7f\x7f\x7f\x7f\x7f\x7f"),
        Beat::Observe,
        Beat::Keys("\r"),
        Beat::Type("/exit"),
    ]);
    let rows = &run.screens[3];
    assert!(
        rows.iter().all(|row| !row.contains("middle")),
        "the deleted line is gone from the screen: {rows:#?}"
    );
    let top = rows
        .iter()
        .position(|row| row.starts_with("> top"))
        .unwrap_or_else(|| panic!("the composer keeps its first line: {rows:#?}"));
    assert_eq!(
        rows.iter().filter(|row| row.starts_with("> top")).count(),
        1,
        "and it is drawn once: {rows:#?}"
    );
    assert!(
        rows.get(top + 1)
            .is_some_and(|row| row.contains("read · ")),
        "the status row is straight under the one input row: {rows:#?}"
    );
    assert_eq!(run.exit, 0, "the run left on its own");
}

/// The readline keys edit the composer line: Alt+B steps back a word, so the character typed
/// next lands before it, and Ctrl+F, Ctrl+K and Ctrl+Y move, cut and put back as a shell would.
#[test]
fn readline_keys_edit_the_composer_line() {
    let install = append_install();
    install.write_script(ONE_TURN);
    let run = drive(&install, &["-c"], &[
        // `one two`, back a word, `X`; then Ctrl+F steps over the `t`, Ctrl+K cuts `wo`, and
        // Ctrl+Y puts it back after the `!`.
        Beat::Type("one two\x1bbX\x06\x0b!\x19"),
        Beat::Type("/exit"),
    ]);
    let text = run.text();
    assert!(
        text.contains("one Xt!wo"),
        "the line was edited where the keys said: {text:?}"
    );
    assert_eq!(run.exit, 0, "the run left on its own");
}

/// Shift+Tab walks the permission level, as it does on the screen, in both spellings a terminal
/// has for it; the status row under the composer follows.
#[test]
fn shift_tab_cycles_the_permission_level() {
    let install = Install::new();
    install.write_config(
        "default_profile = \"default\"\n\n\
         [permissions]\ndefault = \"read\"\nenabled = [\"read\", \"unrestricted\"]\n\n\
         [display]\nrenderer = \"append\"\n\
         [accounts.default]\nbackend = \"openai-chat-completions\"\n\
         base_url = \"http://127.0.0.1:9/\"\n\n\
         [profiles.default]\naccount = \"default\"\nmodel = \"mock-model\"\n",
    );
    let run = drive(&install, &["-c"], &[
        Beat::Type("\x1b[Z"),
        Beat::Observe,
        Beat::Type("\x1b[9;2u"),
        Beat::Observe,
        Beat::Type("/exit"),
    ]);
    let level = |screen: usize| run.screens[screen].last().cloned().unwrap_or_default();
    assert!(
        level(1).contains("unrestricted · "),
        "Shift+Tab moved read to unrestricted: {:#?}",
        run.screens[1]
    );
    assert!(
        level(3).contains("read · "),
        "and the keyboard protocol's spelling moved it on, wrapping round: {:#?}",
        run.screens[3]
    );
    assert_eq!(run.exit, 0, "the run left on its own");
}

/// Tab completes a command word and then its argument's typed rest: `/pe`, Tab, and `unrestricted`
/// run as `/permission unrestricted`, which moves the level and says so in the scrollback.
#[test]
fn tab_completes_a_slash_command_in_append_mode() {
    let install = Install::new();
    install.write_config(
        "default_profile = \"default\"\n\n\
         [permissions]\ndefault = \"read\"\nenabled = [\"read\", \"unrestricted\"]\n\n\
         [display]\nrenderer = \"append\"\n\
         [accounts.default]\nbackend = \"openai-chat-completions\"\n\
         base_url = \"http://127.0.0.1:9/\"\n\n\
         [profiles.default]\naccount = \"default\"\nmodel = \"mock-model\"\n",
    );
    let run = drive(&install, &["-c"], &[
        Beat::Type("/pe\tunrestricted"),
        Beat::Type("/exit"),
    ]);
    assert!(
        run.text().contains("Permission level set to: unrestricted"),
        "Tab filled in /permission, and the typed argument reached it: {:?}",
        run.text()
    );
    assert_eq!(run.exit, 0, "the run left on its own");
}

/// Tab on an ambiguous command word lists the matches with their help, since nothing is shared.
#[test]
fn tab_lists_the_matches_when_they_share_nothing() {
    let install = append_install();
    install.write_script(ONE_TURN);
    let run = drive(&install, &["-c"], &[Beat::Type("/\t"), Beat::Type("/exit")]);
    let text = run.text();
    assert!(
        text.contains("/approvals") && text.contains("/permission"),
        "Tab on a bare slash listed the command words: {text:?}"
    );
    assert_eq!(run.exit, 0, "the run left on its own");
}

/// A paste that is one path to an image file attaches the file, and Enter sends it as the next
/// prompt: the transcript shows the image row and the turn runs on it.
#[test]
fn a_pasted_image_path_is_attached_and_sent() {
    let install = append_install();
    install.write_script(ONE_TURN);
    let path = install.work_dir().join("dot.png");
    let mut png = std::io::Cursor::new(Vec::new());
    image::DynamicImage::ImageRgba8(image::RgbaImage::from_pixel(
        2,
        2,
        image::Rgba([255, 0, 0, 255]),
    ))
    .write_to(&mut png, image::ImageFormat::Png)
    .expect("a png");
    std::fs::write(&path, png.into_inner()).expect("write the png");
    let paste: &'static str =
        Box::leak(format!("\x1b[200~{}\x1b[201~", path.display()).into_boxed_str());
    let run = drive(&install, &["-c"], &[Beat::Type(paste), Beat::Type("/exit")]);
    let text = run.text();
    assert!(
        text.contains("• image"),
        "the image went with the prompt: {text:?}"
    );
    assert_eq!(
        count(&text, "First answer."),
        1,
        "the turn ran on it: {text:?}"
    );
    assert_eq!(run.exit, 0, "the run left on its own");
}

/// Where the terminal speaks the kitty keyboard protocol the renderer asks for its disambiguated
/// keys, Shift+Enter is then a line break in the composer rather than Enter, and the flags are
/// popped on the way out.
#[test]
fn shift_enter_is_a_line_break_under_the_kitty_keyboard_protocol() {
    let install = append_install();
    install.write_script(ONE_TURN);
    let run = drive(&install, &["-c"], &[
        Beat::Type("above\x1b[13;2ubelow"),
        Beat::Type("/exit"),
    ]);
    let raw = String::from_utf8_lossy(&run.raw);
    assert!(raw.contains("\x1b[>1u"), "the protocol was asked for");
    assert!(raw.contains("\x1b[<1u"), "and given back");
    let text = run.text();
    assert_eq!(
        count(&text, "First answer."),
        1,
        "one prompt, one turn: {text:?}"
    );
    let above = text.find("above").expect("the first line is printed");
    let below = text.rfind("below").expect("the second line is printed");
    assert!(
        !text[above..below].contains("First answer."),
        "both lines are the one prompt, sent before the answer: {text:?}"
    );
    assert_eq!(run.exit, 0, "the run left on its own");
    assert!(run.cooked, "and gave the terminal back cooked");
}
