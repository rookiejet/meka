//! The terminal of an append-mode run: the one writer for everything it prints, and the one rule
//! for the space between two things it prints.
//!
//! Every block (an answer paragraph, a tool row, a notice, a turn's closing row) is set off from
//! the one before it by a single blank line, and the first prints flush under the row the prompt
//! was typed on. [`RowState`] exists because a blank line only makes a gap when the cursor is at
//! column zero: the composer parks the cursor mid-row on purpose, and whatever prints next erases
//! that row first. The blank above an erased row stays where it is, so the row's replacement owes
//! none. A paragraph of a streamed answer is a block like any other, which is what lets the
//! composer park in the gap below one without the next paragraph adding a second gap.
//!
//! Restored from the write-once renderer a one-shot run used to drive, adapted to today's render
//! layer: one streamed block kind (the answer; thinking is a collapsed row of its own), and rows
//! written whole, so the cursor is never left mid-row by a stream.

use std::io::Write;

use crate::render;

/// What ends a row. A run reads keys in raw mode, which takes the terminal's newline translation
/// with it, so the writer carries the carriage return the cooked terminal used to add.
const EOL: &str = "\r\n";

/// What occupies the row the cursor is sitting on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RowState {
    /// Column zero of a row nothing has written to. Anything may print immediately.
    Empty,
    /// In-place rows the writer expects to overwrite or erase: the composer and the status row
    /// under it, the question being asked. Not content, so meka's own output replaces the block
    /// rather than following it.
    Transient,
}

/// Something that happens to the console, as a value, so the decision it forces can be tested
/// without a terminal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Action {
    /// A `tracing` line is about to print. It takes a row of its own, because the row it would land
    /// on may be a status line about to be erased, and it is not a block, so no blank is spent.
    AnnounceLog,
    /// A block is about to print.
    Block,
    /// An in-place status line is about to be drawn.
    OpenTransient,
    /// Keep the transient line by writing the newline its writer withheld.
    CommitTransient,
    /// Discard the transient line, because something is about to render in its place.
    EraseTransient,
}

/// What has to happen to the current row before anything else prints on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Settle {
    Nothing,
    /// End the row, keeping what is on it.
    Terminate,
    /// Blank the row and return to column zero, discarding what is on it.
    Erase,
}

/// Everything an action writes before its own content, and nothing else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Emit {
    pub(crate) settle: Settle,
    /// The blank that sets a block off from the one above it.
    pub(crate) separator_blank: bool,
}

/// The console's state, separated from the console so [`step`] can be a pure function of it.
#[derive(Clone, Copy)]
pub(crate) struct State {
    pub(crate) row: RowState,
    /// Whether a block has printed and nothing has yet been set off from it: the next block owes
    /// a blank above. Cleared when the blank is spent on a transient row, which keeps it when the
    /// row is erased, so its replacement does not add a second.
    owes_separator: bool,
}

impl State {
    fn new(row: RowState) -> Self {
        Self {
            row,
            owes_separator: false,
        }
    }
}

/// The whole decision, as a pure function.
///
/// Every blank line an append-mode run prints is the one in [`Emit`], and this is the only place it
/// is decided. Split out from the printing because, in a dispatch that mixes the two, the only way
/// to see a wrong answer is to run a terminal and look at it.
pub(crate) fn step(state: State, action: Action) -> (Emit, State) {
    let mut next = state;
    match action {
        Action::AnnounceLog => {
            let settle = settle_row(&mut next);
            (
                Emit {
                    settle,
                    separator_blank: false,
                },
                next,
            )
        }
        Action::Block => {
            let settle = settle_row(&mut next);
            let separator_blank = state.owes_separator;
            next.owes_separator = true;
            (
                Emit {
                    settle,
                    separator_blank,
                },
                next,
            )
        }
        Action::OpenTransient => {
            // A redraw overwrites its own row, so nothing has to be moved past; the first draw
            // takes the blank the block above is owed, and the row is not a block until it is
            // committed.
            let separator_blank = state.owes_separator;
            next.owes_separator = false;
            next.row = RowState::Transient;
            (
                Emit {
                    settle: Settle::Nothing,
                    separator_blank,
                },
                next,
            )
        }
        Action::CommitTransient => {
            let settle = if state.row == RowState::Transient {
                Settle::Terminate
            } else {
                Settle::Nothing
            };
            next.row = RowState::Empty;
            next.owes_separator = true;
            (
                Emit {
                    settle,
                    separator_blank: false,
                },
                next,
            )
        }
        Action::EraseTransient => {
            let settle = if state.row == RowState::Transient {
                Settle::Erase
            } else {
                Settle::Nothing
            };
            next.row = RowState::Empty;
            (
                Emit {
                    settle,
                    separator_blank: false,
                },
                next,
            )
        }
    }
}

/// Settle the row so the next thing printed starts at column zero of a row of its own.
fn settle_row(next: &mut State) -> Settle {
    let settle = match next.row {
        RowState::Empty => Settle::Nothing,
        RowState::Transient => Settle::Erase,
    };
    next.row = RowState::Empty;
    settle
}

/// A streamed answer in progress: the text that has arrived but not settled into a block yet.
///
/// Markdown is rendered one settled block at a time (a paragraph, a whole table, a closed fence),
/// because rendering the running text would re-wrap what has already printed every time a word
/// lands. A block settles at its blank line; the tail is held back until the block closes and then
/// printed whole. Each settled block is printed as a block of its own, through
/// [`Action::Block`], so the blank between two of them is the one rule and a
/// composer parked in the gap spends it rather than doubling it.
struct TextStream {
    /// Arrived but not yet a settled block.
    buffer: String,
}

impl TextStream {
    fn new() -> Self {
        Self {
            buffer: String::new(),
        }
    }

    /// Take `text` in. The first delta of a stream drops the blank lines an answer opens with, so
    /// its first words are the first words printed.
    fn push(&mut self, text: &str) {
        if self.buffer.is_empty() {
            let trimmed = text.trim_start_matches('\n');
            if !trimmed.is_empty() {
                self.buffer.push_str(trimmed);
            }
        } else {
            self.buffer.push_str(text);
        }
    }

    /// The blocks settled so far, in order, leaving only the one still arriving.
    fn settled(&mut self) -> Vec<String> {
        let mut blocks = Vec::new();
        while let Some(cut) = block_boundary(&self.buffer) {
            let rest = self.buffer.split_off(cut);
            let block = std::mem::take(&mut self.buffer);
            self.buffer = rest.trim_start_matches('\n').to_string();
            if !block.trim().is_empty() {
                blocks.push(block);
            }
        }
        blocks
    }

    /// The block still arriving, for the moment the answer closes.
    fn finish(&mut self) -> Option<String> {
        let tail = std::mem::take(&mut self.buffer);
        (!tail.trim().is_empty()).then_some(tail)
    }

    /// The rows of one block: its markdown rendered at `width`, edge included.
    fn block_rows(block: &str, width: usize) -> Vec<String> {
        let inner = width
            .saturating_sub(render::tui::TEXT_EDGE)
            .max(render::MIN_OUTPUT_WIDTH);
        let lines = render::tui::markdown_lines(block.trim_end_matches('\n'), inner);
        render::tui::lines_to_ansi(&render::tui::edge_rows(lines))
    }
}

/// Where the first settled block in `buffer` ends, or `None` while it is still arriving.
///
/// A block ends at its blank line, consuming the blank run with it. Inside a fenced code block no
/// blank line ends anything: the fence is one block until it closes. A blank line whose next
/// content continues a block (a list item's sibling, an indented line, a quote) does not split
/// either, because a numbered list renumbers from one per document.
fn block_boundary(buffer: &str) -> Option<usize> {
    let mut offset = 0;
    let mut fenced = false;
    for line in buffer.split_inclusive('\n') {
        offset += line.len();
        if is_fence_line(line) {
            fenced = !fenced;
            continue;
        }
        if fenced || !line.trim().is_empty() {
            continue;
        }
        let rest = &buffer[offset..];
        let blanks = rest.len() - rest.trim_start_matches('\n').len();
        let Some(next) = rest.lines().find(|next| !next.trim().is_empty()) else {
            // The blank line settled the block; whatever arrives after it starts the next one.
            return Some(offset + blanks);
        };
        if continues_block(next) {
            continue;
        }
        return Some(offset + blanks);
    }
    None
}

/// Whether `line` opens or closes a fenced code block.
fn is_fence_line(line: &str) -> bool {
    let trimmed = line.trim_start();
    trimmed.starts_with("```") || trimmed.starts_with("~~~")
}

/// Whether the content after a blank line belongs to the block above it.
fn continues_block(line: &str) -> bool {
    let trimmed = line.trim_start();
    line.starts_with(' ')
        || trimmed.starts_with('>')
        || trimmed.starts_with("- ")
        || trimmed.starts_with("* ")
        || trimmed.starts_with("+ ")
        || trimmed.split_once(". ").is_some_and(|(number, _)| {
            !number.is_empty() && number.bytes().all(|byte| byte.is_ascii_digit())
        })
        || trimmed.split_once(") ").is_some_and(|(number, _)| {
            !number.is_empty() && number.bytes().all(|byte| byte.is_ascii_digit())
        })
}

/// The single writer for everything an append-mode run prints.
pub(crate) struct Console {
    state: State,
    /// The answer being streamed. Open across consecutive deltas; closed by any other block, and
    /// by the end of the turn.
    stream: Option<TextStream>,
    /// The terminal width rows are composed for. Refreshed on a resize.
    width: usize,
    /// How many rows the open transient block takes: the row the cursor rests on and the chrome
    /// rows drawn under it, which are rewritten in place and erased as one.
    transient_rows: usize,
    /// Which of the transient block's rows the cursor rests on, counted from its top row. A
    /// multi-line composer parks the cursor on the row it is typing in, not on the first.
    transient_cursor_row: usize,
}

impl Console {
    pub(crate) fn new(width: usize) -> Self {
        Self {
            state: State::new(RowState::Empty),
            stream: None,
            width: width.max(render::MIN_OUTPUT_WIDTH),
            transient_rows: 1,
            transient_cursor_row: 0,
        }
    }

    pub(crate) fn set_width(&mut self, width: usize) {
        self.width = width.max(render::MIN_OUTPUT_WIDTH);
    }

    fn act(&mut self, action: Action) {
        let (emit, next) = step(self.state, action);
        self.state = next;
        match emit.settle {
            Settle::Nothing => {}
            Settle::Terminate => self.put(EOL),
            Settle::Erase => self.erase_block(),
        }
        if emit.separator_blank {
            self.put(EOL);
        }
    }

    /// Write through to the terminal. A failure here is logged and otherwise ignored: the writer
    /// is a terminal with nowhere to report to, and the run is about to notice on its own.
    fn put(&mut self, text: &str) {
        match render::write_stdout(text) {
            Ok(()) => {}
            Err(error) => tracing::warn!("failed to write to the terminal: {error}"),
        }
    }

    /// Blank the transient block and park the cursor at its top row, discarding what is on the
    /// rows: what prints next replaces the block. Attributes are reset first: the erase reuses
    /// the current ones, so a stray escape that reached the terminal must not make everything
    /// printed next invisible.
    fn erase_block(&mut self) {
        let rows = self.transient_rows.max(1);
        let mut out = std::io::stdout();
        // The cursor may rest below the block's top row: climb to the top before clearing down.
        self.climb_to_block_top();
        let mut done = crossterm::queue!(
            out,
            crossterm::style::ResetColor,
            crossterm::style::SetAttribute(crossterm::style::Attribute::Reset),
            crossterm::cursor::MoveToColumn(0),
            crossterm::terminal::Clear(crossterm::terminal::ClearType::UntilNewLine),
        );
        for _ in 1..rows {
            if done.is_err() {
                break;
            }
            done = crossterm::queue!(
                out,
                crossterm::cursor::MoveDown(1),
                crossterm::terminal::Clear(crossterm::terminal::ClearType::UntilNewLine),
            );
        }
        if done.is_ok() && rows > 1 {
            done = crossterm::queue!(out, crossterm::cursor::MoveUp((rows - 1) as u16));
        }
        let done = done.and_then(|()| out.flush());
        if let Err(error) = done {
            tracing::warn!("failed to clear the row: {error}");
        }
    }

    /// Move the cursor from the row it rests on up to the transient block's top row.
    fn climb_to_block_top(&mut self) {
        let up = self.transient_cursor_row;
        if up == 0 {
            return;
        }
        let mut out = std::io::stdout();
        let done =
            crossterm::queue!(out, crossterm::cursor::MoveUp(up as u16)).and_then(|()| out.flush());
        if let Err(error) = done {
            tracing::warn!("failed to move to the block's top row: {error}");
        }
    }

    /// Blank the transient block's rows under the one the cursor rests on and return it there,
    /// keeping what is on that row: the chrome under the composer's input row is redrawn and
    /// must not survive into the scrollback when the row is kept.
    fn erase_rows_below(&mut self) {
        let below = self
            .transient_rows
            .saturating_sub(1 + self.transient_cursor_row);
        if below == 0 {
            return;
        }
        let mut out = std::io::stdout();
        let mut done = crossterm::queue!(out, crossterm::cursor::MoveToColumn(0));
        for _ in 0..below {
            if done.is_err() {
                break;
            }
            done = crossterm::queue!(
                out,
                crossterm::cursor::MoveDown(1),
                crossterm::terminal::Clear(crossterm::terminal::ClearType::UntilNewLine),
            );
        }
        if done.is_ok() {
            done = crossterm::queue!(out, crossterm::cursor::MoveUp(below as u16));
        }
        let done = done.and_then(|()| out.flush());
        if let Err(error) = done {
            tracing::warn!("failed to clear the rows: {error}");
        }
    }

    /// Begin the run's output, given what is on the row the cursor sits on.
    pub(crate) fn start(&mut self, row: RowState) {
        self.state = State::new(row);
    }

    /// End the output: flush the open block, and erase the transient block left drawn, which is
    /// not content and must not survive into the shell's prompt.
    pub(crate) fn finish(&mut self) {
        self.close_stream();
        self.act(Action::EraseTransient);
    }

    /// Print log rows beside the conversation: each takes a row of its own, none is a block, and
    /// an open streaming block is not disturbed by chatter. See [`Action::AnnounceLog`].
    pub(crate) fn log(&mut self, rows: &[String]) {
        if rows.is_empty() {
            return;
        }
        self.act(Action::AnnounceLog);
        self.write_rows(rows);
    }

    /// Print a block of rows, one per row. The rows are whole: a caller that wraps at the terminal
    /// width hands over what each row says and nothing else.
    pub(crate) fn block(&mut self, rows: &[String]) {
        if rows.is_empty() {
            return;
        }
        self.close_stream();
        self.act(Action::Block);
        self.write_rows(rows);
    }

    /// A streamed answer's delta. Blocks print as they settle; the tail waits for
    /// [`Self::close_stream`].
    pub(crate) fn text_delta(&mut self, text: &str) {
        let sanitized = crate::text::sanitize_stream_text(text);
        if sanitized.is_empty() {
            return;
        }
        let width = self.width;
        let stream = self.stream.get_or_insert_with(TextStream::new);
        stream.push(&sanitized);
        let blocks = stream.settled();
        for block in blocks {
            self.act(Action::Block);
            let rows = TextStream::block_rows(&block, width);
            self.write_rows(&rows);
        }
    }

    /// Flush the block still arriving, so block types don't interleave.
    pub(crate) fn close_stream(&mut self) {
        let Some(mut stream) = self.stream.take() else {
            return;
        };
        if let Some(tail) = stream.finish() {
            self.act(Action::Block);
            let rows = TextStream::block_rows(&tail, self.width);
            self.write_rows(&rows);
        }
    }

    fn write_rows(&mut self, rows: &[String]) {
        for row in rows {
            self.put(row);
            self.put(EOL);
        }
    }

    /// Draw an in-place block of `rows` rows, returning whether anything reached the terminal.
    /// The draw writes the rows downward from the row the cursor is on, which is the block's top
    /// row, and leaves the cursor on its row `cursor_row`, counted from the top; a redraw
    /// overwrites its own rows and moves nothing past them. The block is not content until
    /// [`Self::commit_transient`] keeps the cursor's row, and every other print erases the block
    /// whole.
    pub(crate) fn transient(
        &mut self,
        rows: usize,
        cursor_row: usize,
        draw: impl FnOnce() -> bool,
    ) -> bool {
        // A redraw starts from the block's top row, so a block whose cursor rests lower climbs
        // back to it first; the rows are then written over, not beside the ones already drawn.
        if self.state.row == RowState::Transient && self.transient_cursor_row > 0 {
            self.climb_to_block_top();
        }
        self.transient_rows = rows.max(1);
        self.transient_cursor_row = cursor_row.min(self.transient_rows - 1);
        self.act(Action::OpenTransient);
        let drawn = draw();
        if !drawn {
            self.state.row = RowState::Empty;
        }
        drawn
    }

    /// Keep the transient block's first row — the one the cursor rests on, the line its writer
    /// withheld the newline of — and discard the chrome rows under it: they are redrawn, and
    /// must not survive into the scrollback.
    pub(crate) fn commit_transient(&mut self) {
        if self.state.row == RowState::Transient {
            self.erase_rows_below();
        }
        self.act(Action::CommitTransient);
    }

    /// Discard the transient block, for the one case where something is about to render in its
    /// place.
    pub(crate) fn erase_transient(&mut self) {
        self.act(Action::EraseTransient);
    }
}

#[cfg(test)]
impl Console {
    /// Whether an answer is still streaming: anything else printing closes it.
    fn has_open_stream(&self) -> bool {
        self.stream.is_some()
    }

    /// Put the row into a state a test cannot reach through the drawing API: the transient paths
    /// write to the terminal, which a test process has none of.
    fn force_row(&mut self, row: RowState) {
        self.state.row = row;
    }

    /// What the cursor is sitting on, for the same tests.
    fn row(&self) -> RowState {
        self.state.row
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Replay a sequence from a fresh console, returning what each action emitted.
    fn run(actions: &[Action]) -> Vec<Emit> {
        let mut state = State::new(RowState::Empty);
        actions
            .iter()
            .map(|action| {
                let (emit, next) = step(state, *action);
                state = next;
                emit
            })
            .collect()
    }

    /// The first block prints flush under the shell's command line; every later one is set off
    /// from the one above by one blank, whatever kind either is.
    #[test]
    fn every_block_after_the_first_is_set_off_by_one_blank() {
        let emits = run(&[Action::Block, Action::Block, Action::Block]);
        assert!(!emits[0].separator_blank, "nothing above the first");
        assert!(emits[1].separator_blank);
        assert!(emits[2].separator_blank);
        assert!(
            emits.iter().all(|emit| emit.settle == Settle::Nothing),
            "an empty row needs no settling"
        );
    }

    /// A blank line only makes a gap from column zero. An in-place status line is discarded rather
    /// than terminated, because its row is not content, and the blank spent above it serves the
    /// block that replaces it.
    #[test]
    fn a_transient_row_is_erased_by_whatever_prints_next_and_its_blank_is_kept() {
        let emits = run(&[
            Action::Block,
            Action::OpenTransient,
            Action::OpenTransient,
            Action::Block,
        ]);
        assert!(
            emits[1].separator_blank,
            "the first draw is set off from the block above"
        );
        assert!(!emits[2].separator_blank, "a redraw overwrites its own row");
        assert_eq!(emits[3].settle, Settle::Erase);
        assert!(
            !emits[3].separator_blank,
            "the blank above the erased row already sets the block off"
        );
        let erased = run(&[
            Action::Block,
            Action::OpenTransient,
            Action::EraseTransient,
            Action::Block,
        ]);
        assert_eq!(erased[2].settle, Settle::Erase);
        assert!(!erased[3].separator_blank);
    }

    /// A committed status line is a block: the next one is set off from it.
    #[test]
    fn committing_a_transient_line_keeps_it_and_sets_the_next_block_off() {
        let emits = run(&[
            Action::OpenTransient,
            Action::CommitTransient,
            Action::Block,
        ]);
        assert_eq!(emits[1].settle, Settle::Terminate);
        assert!(emits[2].separator_blank);
        let nothing = run(&[Action::CommitTransient, Action::EraseTransient]);
        assert!(
            nothing.iter().all(|emit| emit.settle == Settle::Nothing),
            "with no transient row drawn there is nothing to keep or discard"
        );
    }

    /// A transient block remembers how tall it is drawn, so what prints next erases the block
    /// whole — the row the cursor rests on and the chrome rows under it — and a commit keeps that
    /// row alone. The erases write to the terminal itself; this is the state they read.
    #[test]
    fn a_transient_block_remembers_the_rows_it_occupies() {
        let mut console = Console::new(80);
        assert!(console.transient(2, 0, || true));
        assert_eq!(console.state.row, RowState::Transient);
        assert_eq!(console.transient_rows, 2, "the block is two rows tall");
        console.commit_transient();
        assert_eq!(console.state.row, RowState::Empty);
        assert_eq!(console.transient_rows, 2, "and its shape outlives it");
    }

    /// A composer of several lines parks the cursor on one of its rows below the top: the cursor
    /// row is remembered, and the commit keeps that row and clears only the rows under it.
    #[test]
    fn a_transient_block_remembers_which_of_its_rows_the_cursor_is_on() {
        let mut console = Console::new(80);
        assert!(console.transient(4, 1, || true));
        assert_eq!(console.transient_cursor_row, 1);
        assert_eq!(console.transient_rows, 4);
        assert!(console.transient(2, 9, || true));
        assert_eq!(
            console.transient_cursor_row, 1,
            "a cursor row past the block is held on its last row"
        );
    }

    /// A log line takes a row of its own: the row it would land on may be a status line about to
    /// be erased. It is not a block, so it spends no blank.
    #[test]
    fn a_log_line_settles_its_row_and_spends_no_blank() {
        let emits = run(&[Action::Block, Action::OpenTransient, Action::AnnounceLog]);
        assert_eq!(emits[2].settle, Settle::Erase);
        assert!(!emits[2].separator_blank);
        let flush = run(&[Action::AnnounceLog, Action::Block]);
        assert!(
            !flush[1].separator_blank,
            "a warning at startup earns the first block no blank"
        );
    }

    /// Finishing erases the status line left drawn and flushes the block still arriving; finishing
    /// twice is finishing once.
    #[test]
    fn finishing_erases_a_leftover_status_line() {
        let mut console = Console::new(80);
        console.start(RowState::Empty);
        console.text_delta("half an answer");
        assert!(console.has_open_stream(), "the paragraph is held back");
        console.force_row(RowState::Transient);
        console.finish();
        assert!(!console.has_open_stream());
        assert_eq!(console.row(), RowState::Empty);
        console.finish();
        assert_eq!(console.row(), RowState::Empty);
    }

    /// Blocks settle at a blank line and are printed as they settle; the tail of a paragraph is
    /// held until the block closes, so nothing re-wraps what has already printed.
    #[test]
    fn a_streamed_answer_prints_each_block_when_its_blank_line_settles_it() {
        let mut stream = TextStream::new();
        stream.push("First paragraph.");
        assert!(stream.settled().is_empty(), "the paragraph is held");
        stream.push("\n\nSecond one.\n\n");
        let blocks = stream.settled();
        assert_eq!(blocks.len(), 2, "both paragraphs settled: {blocks:?}");
        assert!(blocks[0].contains("First paragraph."), "{blocks:?}");
        assert!(blocks[1].contains("Second one."), "{blocks:?}");
        assert!(stream.settled().is_empty(), "nothing is left");
    }

    /// A fenced code block is one block until it closes, blank lines inside it notwithstanding.
    #[test]
    fn a_fence_holds_its_blank_lines_until_it_closes() {
        let mut stream = TextStream::new();
        stream.push("```\nfirst\n\nsecond\n```\n\nAfter.\n\n");
        let blocks = stream.settled();
        assert_eq!(blocks.len(), 2, "{blocks:?}");
        assert!(
            blocks[0].contains("first") && blocks[0].contains("second"),
            "{blocks:?}"
        );
        assert!(blocks[1].contains("After."), "{blocks:?}");
    }

    /// A list whose items the source separates with blank lines is one block: a numbered list
    /// renumbers from one per document, and splitting it would print two ones.
    #[test]
    fn a_loose_list_is_one_block() {
        let block = block_boundary("1. First\n\n2. Second\n\nAfter.\n\n").expect("a boundary");
        assert_eq!(
            &"1. First\n\n2. Second\n\nAfter.\n\n"[..block],
            "1. First\n\n2. Second\n\n"
        );
    }

    /// The tail of an unfinished paragraph is the last block, handed over when the answer closes.
    #[test]
    fn the_tail_is_handed_over_when_the_answer_closes() {
        let mut stream = TextStream::new();
        stream.push("One.\n\nTwo.");
        let settled = stream.settled();
        assert_eq!(settled.len(), 1, "{settled:?}");
        assert!(settled[0].contains("One."), "{settled:?}");
        let tail = stream.finish().expect("the tail");
        assert!(tail.contains("Two."), "{tail}");
        assert!(stream.finish().is_none(), "finishing is once");
    }

    /// The composer parks in the gap below a streamed paragraph, and the next paragraph prints
    /// where the composer stood: one blank between the paragraphs, whatever drew in it.
    #[test]
    fn a_paragraph_printed_past_a_parked_composer_adds_no_second_blank() {
        let emits = run(&[
            Action::Block,
            Action::OpenTransient,
            Action::Block,
            Action::Block,
        ]);
        assert!(emits[1].separator_blank, "the composer's gap");
        assert_eq!(emits[2].settle, Settle::Erase, "the composer is replaced");
        assert!(
            !emits[2].separator_blank,
            "the gap the composer parked in sets the paragraph off"
        );
        assert!(emits[3].separator_blank, "the one blank between paragraphs");
    }
}
