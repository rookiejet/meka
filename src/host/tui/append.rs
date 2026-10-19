//! The append renderer: every row of a run prints once and stays where the terminal scrolled it,
//! so the shell's own scrollback is the transcript and the rows above can be copied, searched and
//! piped like anything else the terminal printed.
//!
//! The rows come from the screen's vocabulary ([`view::entry_lines`] turns each item into the rows
//! it draws) and their spacing from [`crate::console`], restored from the write-once renderer a
//! one-shot run used to drive. Nothing here redraws: a streamed answer prints one settled
//! markdown block at a time, a tool call prints when it settles, and the composer parks on the
//! row below whatever printed last until something else replaces it there.
//!
//! Where the screen has an overlay -- a permission prompt, a picker -- this has a line: the
//! question is printed as rows and answered on the prompt line below it, with the same answers
//! (`y`, `a`, `n` and the words behind them). Pickers take their argument form.

use std::{
    collections::VecDeque,
    io::Write as _,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use crossterm::event::{Event, EventStream, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use futures::StreamExt;
use ratatui::{
    style::Style,
    text::{Line, Span},
};

use super::{
    commands::{self, Answerer, SlashCommand},
    frontend::{ApprovalDecision, ApprovalRequest, HostEvent, Ui, UiEvent},
    input::HISTORY_WALK_ENTRIES,
    model::{self, Entry, Item, ToolState, Transcript},
    screen::{self, APPROVAL_CHOICES, URL_CHOICES, description_of, log_item, one_line},
    view,
};
use crate::{
    console::{Console, RowState},
    conversation::ContentBlock,
    frontend::{
        ElicitationKind, ElicitationPrompt, ElicitationResponse, Frontend, FrontendEvent,
        PermissionOutcome, PermissionRequest,
    },
    render,
    store::inbox::{InboxClass, NewInboxItem},
};

/// How often the row the cursor sits on is refreshed and the ambient work is read: log lines,
/// questions whose turn has moved on.
const TICK: Duration = Duration::from_millis(100);

/// A question takes no answer this soon after opening: a key already on its way to the composer,
/// Enter above all, would otherwise land on the answer line.
const QUESTION_GRACE: Duration = Duration::from_millis(350);

/// A listing cut to its last bytes past this; a task's outcome is the one that can run long.
const LISTING_KEEP_BYTES: usize = crate::text::MIB;
/// How often the status row under the composer reads back the work running beside the turn.
const WORK_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

/// Log lines kept for `/log`: enough to read back a turn's worth, little enough to hold.
const LOG_RING_LINES: usize = 500;

/// The agent's [`Frontend`] for the append renderer: the same question protocol as the screen's
/// ([`super::frontend::TuiFrontend`] is the channel end every interactive host asks through), under
/// a name of its own because the run dispatches on the renderer to pick one.
pub(crate) struct AppendFrontend(super::frontend::TuiFrontend);

impl AppendFrontend {
    pub(crate) fn new(ui: Ui) -> Self {
        Self(super::frontend::TuiFrontend::new(ui))
    }
}

#[async_trait]
impl Frontend for AppendFrontend {
    fn retains_reasoning(&self) -> bool {
        // Rows print once and stay in the scrollback, so a retried attempt would show the same
        // reasoning twice. What the screen keeps in its transcript, the terminal keeps above.
        self.0.retains_reasoning()
    }

    fn forget_session_answers(&self) {
        self.0.forget_session_answers();
    }

    async fn emit(&self, event: FrontendEvent) {
        self.0.emit(event).await;
    }

    async fn request_permission(&self, request: PermissionRequest) -> PermissionOutcome {
        self.0.request_permission(request).await
    }

    async fn handle_elicitation(&self, prompt: ElicitationPrompt) -> ElicitationResponse {
        self.0.handle_elicitation(prompt).await
    }
}

/// What the append renderer is launched with: the same channels the screen runs on, minus the
/// panel state and the pickers it has none of.
pub(crate) struct AppendLaunch {
    pub(crate) ui_receiver: tokio::sync::mpsc::UnboundedReceiver<UiEvent>,
    pub(crate) host: tokio::sync::mpsc::UnboundedSender<HostEvent>,
    pub(crate) logs: crate::relay::ScreenLogs,
    pub(crate) transcript: Transcript,
    pub(crate) log_end: Option<i64>,
    pub(crate) settings: model::Settings,
    pub(crate) shared_permission: crate::permission::SharedPermission,
    pub(crate) sandbox_state: crate::sandbox::SandboxState,
    pub(crate) cwd: crate::workspace::SharedCwd,
    pub(crate) launch_cwd: PathBuf,
    pub(crate) history: Option<crate::store::history::HistoryStore>,
    pub(crate) skill_roots: Vec<PathBuf>,
    pub(crate) current_profile: Arc<std::sync::RwLock<String>>,
    /// The facts the status row under the composer shows, in order: the screen's
    /// `display.status_row` list.
    pub(crate) status_row: Vec<crate::config::StatusFact>,
    /// The context gauge's two cells: tokens used and the window, when the status row shows it.
    pub(crate) context: Option<(
        Arc<std::sync::atomic::AtomicU64>,
        Arc<std::sync::atomic::AtomicU64>,
    )>,
    /// The configured profiles, so the status row can name the model as the screen's does.
    pub(crate) configured_profiles: Vec<crate::config::ProfileSummary>,
    /// The sub-agents running in this process, for the status row's work counts.
    pub(crate) running_subagents: crate::session::RunningSubagents,
    pub(crate) schedule: crate::config::ResolvedScheduleConfig,
    /// `[memory] inline_max_bytes`, the budget the memory commands read under.
    pub(crate) memory_inline_max_bytes: usize,
    /// The slash-command completer the screen uses, so Tab offers the same names.
    pub(crate) completer: super::input::Completer,
    pub(crate) store: crate::store::Store,
    pub(crate) agent: Arc<crate::agent::Agent>,
    pub(crate) cancel: crate::host::CancelCell,
    pub(crate) send_class: InboxClass,
    /// Whether a turn is running before the first key is read.
    pub(crate) busy: bool,
    /// Whether the run opened on the session picker, which an append-mode run has no screen for.
    pub(crate) pick_session: bool,
}

/// A tool call in flight, kept until it settles so the row it prints is the whole call.
struct OpenCall {
    id: String,
    name: String,
    input: Option<serde_json::Value>,
    summary: String,
    output: String,
    activity: String,
    /// The tool's own progress reports — the last one — as the screen folds them onto the row
    /// while the call runs. A row printed once carries the last of them when the call settles.
    progress: Option<String>,
    state: ToolState,
}

impl OpenCall {
    /// The row the screen draws for a call like this one: the tool line, and what a collapsed call
    /// body shows of it.
    fn into_item(
        self,
        state: ToolState,
        result: Option<String>,
        result_images: usize,
        change: Option<model::TextChange>,
    ) -> Item {
        Item::ToolCall {
            id: self.id,
            name: self.name,
            input: self.input,
            summary: (!self.summary.is_empty()).then_some(self.summary),
            state,
            output: self.output,
            result,
            result_images,
            activity: self.activity,
            progress: self.progress,
            change,
        }
    }
}

/// The line being typed at the prompt: the text, where in it the cursor is, and the walk through
/// what was sent before.
#[derive(Default)]
struct LineEditor {
    text: String,
    cursor: usize,
    walk: Option<Walk>,
    /// What the last cut took, for `Ctrl+Y`. The editor's own, never the system clipboard.
    killed: String,
    /// The lines before each edit, newest last, for `Ctrl+_` and `Ctrl+Z`.
    undo: Vec<(String, usize)>,
    /// The last edit was a typed character, so the next one joins its undo step.
    typing: bool,
}

/// One walk up through the history: what was being typed when it began, and where in the entries
/// it now stands. `index == entries.len()` is the draft again.
struct Walk {
    draft: String,
    entries: Vec<String>,
    index: usize,
}

impl LineEditor {
    fn text(&self) -> &str {
        &self.text
    }

    fn cursor(&self) -> usize {
        self.cursor
    }

    fn is_empty(&self) -> bool {
        self.text.is_empty()
    }

    fn clear(&mut self) {
        self.text.clear();
        self.cursor = 0;
        self.walk = None;
        self.undo.clear();
        self.typing = false;
    }

    /// Keep the line as it stands before an edit, so undo can return to it. A run of typed
    /// characters is one step, as in a shell.
    fn record(&mut self, typing: bool) {
        if !(typing && self.typing) {
            self.undo.push((self.text.clone(), self.cursor));
        }
        self.typing = typing;
        self.walk = None;
    }

    fn insert(&mut self, ch: char) {
        self.record(true);
        self.text.insert(self.cursor, ch);
        self.cursor += ch.len_utf8();
    }

    /// A paste at the cursor. A line break is kept as the `\n` it is when `multiline`, so the
    /// prompt is sent as pasted; a one-line field takes it as a space. A terminal pastes the
    /// carriage return Enter sends, and a tab or any other control character is not text.
    fn insert_paste(&mut self, pasted: &str, multiline: bool) {
        let unified = pasted.replace("\r\n", "\n").replace('\r', "\n");
        let text: String = unified
            .chars()
            .filter_map(|ch| match ch {
                '\n' if multiline => Some('\n'),
                '\n' | '\t' => Some(' '),
                ch if ch.is_control() => None,
                ch => Some(ch),
            })
            .collect();
        self.record(false);
        self.text.insert_str(self.cursor, &text);
        self.cursor += text.len();
    }

    fn backspace(&mut self) {
        if self.cursor == 0 {
            return;
        }
        self.record(false);
        let step = self.text[..self.cursor]
            .chars()
            .next_back()
            .map_or(0, char::len_utf8);
        self.cursor -= step;
        self.text.remove(self.cursor);
    }

    fn delete(&mut self) {
        if self.cursor < self.text.len() {
            self.record(false);
            self.text.remove(self.cursor);
        }
    }

    fn left(&mut self) {
        self.typing = false;
        self.cursor = self.text[..self.cursor]
            .chars()
            .next_back()
            .map_or(self.cursor, |ch| self.cursor - ch.len_utf8());
    }

    fn right(&mut self) {
        self.typing = false;
        self.cursor = self.text[self.cursor..]
            .chars()
            .next()
            .map_or(self.cursor, |ch| self.cursor + ch.len_utf8());
    }

    fn home(&mut self) {
        self.typing = false;
        self.cursor = 0;
    }

    fn end(&mut self) {
        self.typing = false;
        self.cursor = self.text.len();
    }

    /// Where the word behind `from` starts: past the spaces, then the word, or the punctuation
    /// when it is all there is.
    fn word_start(&self, from: usize) -> usize {
        let trimmed = self.text[..from].trim_end_matches(char::is_whitespace);
        let word = trimmed.trim_end_matches(is_word_char);
        if word.len() < trimmed.len() {
            return word.len();
        }
        trimmed.trim_end_matches(is_punctuation).len()
    }

    /// Where the word ahead of `from` ends, the mirror of [`Self::word_start`].
    fn word_end(&self, from: usize) -> usize {
        let after = self.text[from..].trim_start_matches(char::is_whitespace);
        let word = after.trim_start_matches(is_word_char);
        let rest = if word.len() < after.len() {
            word
        } else {
            after.trim_start_matches(is_punctuation)
        };
        self.text.len() - rest.len()
    }

    fn word_left(&mut self) {
        self.typing = false;
        self.cursor = self.word_start(self.cursor);
    }

    fn word_right(&mut self) {
        self.typing = false;
        self.cursor = self.word_end(self.cursor);
    }

    /// Cut `range` out of the line and keep it for [`Self::yank`].
    /// Replace `range` with `value` as one undo step, leaving the cursor after it.
    fn replace_range(&mut self, range: std::ops::Range<usize>, value: &str) {
        if self.text.get(range.clone()).is_none() {
            return;
        }
        self.record(false);
        self.text.replace_range(range.clone(), value);
        self.cursor = range.start + value.len();
    }

    fn cut(&mut self, range: std::ops::Range<usize>) {
        if range.is_empty() {
            return;
        }
        self.record(false);
        self.killed = self.text[range.clone()].to_string();
        self.cursor = range.start;
        self.text.replace_range(range, "");
    }

    fn kill_to_end(&mut self) {
        self.cut(self.cursor..self.text.len());
    }

    fn kill_to_start(&mut self) {
        self.cut(0..self.cursor);
    }

    /// The word behind the cursor: the spaces before it, then the word itself.
    fn kill_word_back(&mut self) {
        self.cut(self.word_start(self.cursor)..self.cursor);
    }

    /// The word ahead of the cursor: the spaces before it, then the word itself.
    fn kill_word_forward(&mut self) {
        self.cut(self.cursor..self.word_end(self.cursor));
    }

    /// Put back what the last cut took.
    fn yank(&mut self) {
        if self.killed.is_empty() {
            return;
        }
        self.record(false);
        let killed = std::mem::take(&mut self.killed);
        self.text.insert_str(self.cursor, &killed);
        self.cursor += killed.len();
        self.killed = killed;
    }

    /// Take back the last edit.
    fn undo(&mut self) {
        if let Some((text, cursor)) = self.undo.pop() {
            self.text = text;
            self.cursor = cursor;
            self.typing = false;
            self.walk = None;
        }
    }

    /// The editing keys every shell answers to, shared by the composer and a question's answer
    /// line. Returns whether the key was one of them. Enter, the history and the keys that mean
    /// something to the run itself (Ctrl+C, Ctrl+D) are the caller's.
    fn readline(&mut self, key: &KeyEvent) -> bool {
        let control = key.modifiers.contains(KeyModifiers::CONTROL);
        let alt = key.modifiers.contains(KeyModifiers::ALT);
        match (key.code, control, alt) {
            (KeyCode::Char('a'), true, _) | (KeyCode::Home, ..) => self.home(),
            (KeyCode::Char('e'), true, _) | (KeyCode::End, ..) => self.end(),
            (KeyCode::Char('f'), false, true)
            | (KeyCode::Right, true, _)
            | (KeyCode::Right, _, true) => {
                self.word_right();
            }
            (KeyCode::Char('b'), false, true)
            | (KeyCode::Left, true, _)
            | (KeyCode::Left, _, true) => {
                self.word_left();
            }
            (KeyCode::Char('f'), true, _) | (KeyCode::Right, ..) => self.right(),
            (KeyCode::Char('b'), true, _) | (KeyCode::Left, ..) => self.left(),
            (KeyCode::Char('k'), true, _) => self.kill_to_end(),
            (KeyCode::Char('u'), true, _) => self.kill_to_start(),
            (KeyCode::Char('w'), true, _) | (KeyCode::Backspace, _, true) => self.kill_word_back(),
            (KeyCode::Char('d'), false, true) => self.kill_word_forward(),
            (KeyCode::Char('d'), true, _) | (KeyCode::Delete, ..) => self.delete(),
            (KeyCode::Char('h'), true, _) | (KeyCode::Backspace, ..) => self.backspace(),
            (KeyCode::Char('y'), true, _) => self.yank(),
            (KeyCode::Char('_' | 'z'), true, _) => self.undo(),
            _ => return false,
        }
        true
    }

    /// The line sent before this one. The first call opens a walk with `entries`, oldest first.
    fn previous(&mut self, entries: &[String]) {
        if entries.is_empty() && self.walk.is_none() {
            return;
        }
        let draft = self.text.clone();
        let walk = self.walk.get_or_insert_with(|| Walk {
            draft,
            entries: entries.to_vec(),
            index: entries.len(),
        });
        if walk.index > 0 {
            walk.index -= 1;
            self.text = walk.entries.get(walk.index).cloned().unwrap_or_default();
            self.cursor = self.text.len();
        }
    }

    /// Back toward the draft, past what was sent before. The draft itself is what the walk ends
    /// on; the walk stays open so the next [`Self::previous`] picks up where this left off.
    fn next(&mut self) {
        let Some(walk) = &mut self.walk else {
            return;
        };
        if walk.index < walk.entries.len() {
            walk.index += 1;
            self.text = if walk.index == walk.entries.len() {
                walk.draft.clone()
            } else {
                walk.entries.get(walk.index).cloned().unwrap_or_default()
            };
            self.cursor = self.text.len();
        }
    }
}

/// Where a word stops: a space, or a letter's edge against punctuation.
/// The longest prefix every value starts with, cut at a character boundary.
fn common_prefix<'a>(mut values: impl Iterator<Item = &'a str>) -> String {
    let Some(first) = values.next() else {
        return String::new();
    };
    let mut shared = first.to_string();
    for value in values {
        let len = shared
            .chars()
            .zip(value.chars())
            .take_while(|(a, b)| a == b)
            .map(|(a, _)| a.len_utf8())
            .sum::<usize>();
        shared.truncate(len);
    }
    shared
}

fn is_word_break(ch: char) -> bool {
    ch.is_whitespace() || matches!(ch, '/' | '\\' | ':' | ',' | '.')
}

fn is_word_char(ch: char) -> bool {
    !is_word_break(ch)
}

/// A word break that is not a space: what a word motion crosses when no word is in reach.
fn is_punctuation(ch: char) -> bool {
    is_word_break(ch) && !ch.is_whitespace()
}

/// Where the cursor belongs on the row `lead` and `text` draw: the visible slice of `text`,
/// scrolled so the cursor is in it, and the column the cursor sits in.
fn fit_input(lead_cols: usize, text: &str, cursor: usize, width: usize) -> (String, usize) {
    let cut = cursor.min(text.len());
    let before = &text[..cut];
    let after = &text[cut..];
    let budget = width.saturating_sub(lead_cols).max(1);
    if crate::text::display_width(text) <= budget {
        return (text.to_string(), crate::text::display_width(before));
    }
    // The cursor is kept one column off the right edge: the tail of what is typed before it fits
    // to there, and what follows fills the rest of the row.
    let mut shown_before = String::new();
    let mut used = 0;
    for ch in before.chars().rev() {
        let wide = crate::text::display_width(&ch.to_string());
        if used + wide > budget.saturating_sub(1) {
            break;
        }
        shown_before.insert(0, ch);
        used += wide;
    }
    let mut shown_after = String::new();
    for ch in after.chars() {
        let wide = crate::text::display_width(&ch.to_string());
        if used + wide > budget {
            break;
        }
        shown_after.push(ch);
        used += wide;
    }
    let cursor_col = crate::text::display_width(&shown_before);
    (format!("{shown_before}{shown_after}"), cursor_col)
}

/// The rows the composer's input takes for `text` when it shows at most `max` of them: each line
/// of the text on a row of its own, and the window of those rows that holds the cursor. Returns
/// the window's lines, the cursor's row within it, and the cursor's byte offset in its line.
fn composer_lines(text: &str, cursor: usize, max: usize) -> (Vec<&str>, usize, usize) {
    let cut = cursor.min(text.len());
    let lines: Vec<&str> = text.split('\n').collect();
    let line = text[..cut].matches('\n').count();
    let line_start = text[..cut].rfind('\n').map_or(0, |at| at + 1);
    let size = max.max(1).min(lines.len());
    // The window ends on the cursor's line when the text runs past it, so the line typed on is
    // always in view; the lines above it are what gives way.
    let start = (line + 1).saturating_sub(size);
    let window: Vec<&str> = lines.iter().skip(start).take(size).copied().collect();
    (window, line - start, cut - line_start)
}

/// How many input rows the composer may take: the terminal's rows less the status row under the
/// input and the row above the block, so the block always fits on the screen.
fn composer_row_cap() -> usize {
    let rows = crossterm::terminal::size().map_or(24, |(_, rows)| usize::from(rows));
    rows.saturating_sub(2).max(1)
}

/// The composer block the cursor sits on: the input rows — `lead` on the first, then the text
/// typed after it, one row per line, with the cursor where it was left — and the screen's status
/// row under them. The rows are transient chrome the console rewrites in place and erases whole,
/// so each row is cut to the terminal's columns rather than allowed to wrap. Returns whether
/// anything reached the terminal.
fn draw_composer(
    lead: &str,
    lines: &[&str],
    cursor_row: usize,
    cursor_at: usize,
    working: Option<&Line<'_>>,
    status: &Line<'_>,
    width: usize,
) -> bool {
    let lead_cols = crate::text::display_width(lead);
    let pad = " ".repeat(lead_cols);
    let mut out = std::io::stdout();
    let mut column = lead_cols;
    let mut done = crossterm::queue!(out, crossterm::cursor::MoveToColumn(0));
    // The working row, when the turn runs, sits above the input rows.
    if let Some(line) = working {
        done = done.and_then(|()| {
            crossterm::queue!(
                out,
                crossterm::terminal::Clear(crossterm::terminal::ClearType::UntilNewLine),
                crossterm::style::Print(render::tui::line_to_ansi(line)),
                crossterm::style::Print("\r\n"),
            )
        });
    }
    for (row, text) in lines.iter().enumerate() {
        if row > 0 {
            done = done.and_then(|()| crossterm::queue!(out, crossterm::style::Print("\r\n")));
        }
        // Only the cursor's row is cut around the cursor; the rows above and below show their
        // start, which is what a line typed earlier has in view.
        let cursor_here = if row == cursor_row { cursor_at } else { 0 };
        let (shown, cursor_col) = fit_input(lead_cols, text, cursor_here, width);
        if row == cursor_row {
            column = lead_cols + cursor_col;
        }
        // The first row carries the lead; the rows under it are indented to the text's column.
        let prefix = if row == 0 { lead } else { pad.as_str() };
        let line = Line::from(vec![
            Span::styled(
                prefix.to_string(),
                Style::default().fg(render::tui::PROMPT_GLYPH_COLOR),
            ),
            Span::styled(shown, Style::default().fg(render::tui::WHITE)),
        ]);
        done = done.and_then(|()| {
            crossterm::queue!(
                out,
                crossterm::cursor::MoveToColumn(0),
                crossterm::terminal::Clear(crossterm::terminal::ClearType::UntilNewLine),
                crossterm::style::Print(render::tui::line_to_ansi(&line)),
            )
        });
    }
    let rows = lines.len();
    let column = u16::try_from(column).unwrap_or(u16::MAX);
    let done = done
        .and_then(|()| {
            crossterm::queue!(
                out,
                // The status row under the input rows, as the screen keeps it under the composer.
                // The newline scrolls only when the block sits on the terminal's last row and
                // needs room made; a redraw overwrites its rows in place and moves nothing.
                crossterm::style::Print("\r\n"),
                crossterm::terminal::Clear(crossterm::terminal::ClearType::UntilNewLine),
                crossterm::style::Print(fit_status(status, width)),
                // Rows a taller block drew before this one are blank from here down.
                crossterm::terminal::Clear(crossterm::terminal::ClearType::FromCursorDown),
                crossterm::cursor::MoveUp((rows - cursor_row) as u16),
                crossterm::cursor::MoveToColumn(column),
            )
        })
        .and_then(|()| out.flush());
    match done {
        Ok(()) => true,
        Err(error) => {
            tracing::warn!("failed to draw the composer: {error}");
            false
        }
    }
}

/// The status row as bytes to print and forget, cut to the terminal's columns: each span applies
/// its own styles and closes them, and the first span to reach the edge ends the row.
fn fit_status(status: &Line<'_>, width: usize) -> String {
    let mut out = String::new();
    let mut used = 0;
    for span in &status.spans {
        if used >= width {
            break;
        }
        let content = crate::text::truncate_to_width(span.content.as_ref(), width - used);
        used += crate::text::display_width(&content);
        out.push_str(&render::tui::line_to_ansi(&Line::from(Span::styled(
            content, span.style,
        ))));
    }
    out
}

/// An answer the approval prompt takes, as the decision behind it.
fn approval_answer(answer: &str) -> Option<ApprovalDecision> {
    match answer.trim().to_ascii_lowercase().as_str() {
        "y" | "allow" => Some(ApprovalDecision::Allow),
        "a" | "always" | "allow for the session" => Some(ApprovalDecision::AllowAlways),
        "n" | "deny" => Some(ApprovalDecision::Deny),
        "never" | "deny for the session" => Some(ApprovalDecision::DenyAlways),
        _ => None,
    }
}

/// An answer the URL consent flow takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UrlAnswer {
    Open,
    Skip,
    Decline,
}

fn url_answer(answer: &str) -> Option<UrlAnswer> {
    match answer.trim().to_ascii_lowercase().as_str() {
        "y" | "open" => Some(UrlAnswer::Open),
        "s" | "skip" => Some(UrlAnswer::Skip),
        "n" | "decline" => Some(UrlAnswer::Decline),
        _ => None,
    }
}

/// The choices line an approval prompt prints, from the screen's own vocabulary.
fn approval_choices() -> String {
    APPROVAL_CHOICES
        .iter()
        .map(|(label, key, _)| match key {
            Some(key) => format!("{label} ({key})"),
            None => (*label).to_string(),
        })
        .collect::<Vec<_>>()
        .join(" / ")
}

/// The choices line a URL consent prompt prints.
fn url_choices() -> String {
    URL_CHOICES
        .iter()
        .map(|(label, key)| match key {
            Some(key) => format!("{label} ({key})"),
            None => (*label).to_string(),
        })
        .collect::<Vec<_>>()
        .join(" / ")
}

/// The rows an approval prompt prints: the call, its args the way a collapsed call shows them,
/// and the answers taken.
fn approval_rows(request: &ApprovalRequest, width: usize) -> Vec<String> {
    let name = one_line(&request.tool_name, 64);
    let mut lines = vec![render::tui::tool_row(&name, None, None, None, width)];
    lines.extend(render::tui::approval_rows(&name, &request.input, width));
    let inner = width
        .saturating_sub(render::tui::TEXT_EDGE)
        .max(render::MIN_OUTPUT_WIDTH);
    lines.extend(render::tui::edge_rows(render::tui::plain_lines(
        &approval_choices(),
        inner,
        Style::default(),
    )));
    render::tui::lines_to_ansi(&lines)
}

/// The rows a URL consent flow prints: what the server says, the URL it points at, and the
/// answers taken.
fn elicitation_rows(prompt: &ElicitationPrompt, width: usize) -> Vec<String> {
    let inner = width
        .saturating_sub(render::tui::TEXT_EDGE)
        .max(render::MIN_OUTPUT_WIDTH);
    let mut lines = render::tui::edge_rows(render::tui::glyph_text_rows(
        render::tui::ACT_GLYPH,
        render::tui::gray(),
        &format!(
            "{}: {}",
            one_line(&prompt.server_name, 64),
            one_line(&prompt.message, 120)
        ),
        render::tui::gray(),
        inner,
    ));
    if let ElicitationKind::Url { url, .. } = &prompt.kind {
        lines.extend(render::tui::edge_rows(render::tui::plain_lines(
            url,
            inner,
            render::tui::gray(),
        )));
    }
    lines.extend(render::tui::edge_rows(render::tui::plain_lines(
        &url_choices(),
        inner,
        Style::default(),
    )));
    render::tui::lines_to_ansi(&lines)
}

/// Raw mode, bracketed paste and, where the terminal speaks it, the kitty keyboard protocol's
/// disambiguated keys: the whole of what the append renderer takes from the terminal, with no
/// alternate screen, no mouse capture and no clipboard. Bracketed paste is what lets a pasted
/// paragraph arrive as one paste rather than as lines each ended by the Enter that sends one; the
/// keyboard protocol is what lets Shift+Enter be told from Enter. Dropped in whatever ends the
/// run, including a panic.
struct RawMode;

/// Whether the keyboard protocol's flags are pushed, which the panic hook has to know to pop.
static KEYBOARD_ENHANCED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Give the terminal back: the keyboard flags popped, bracketed paste off, line editing and echo
/// on. A mode is given back once, so the panic hook and the drop can both call it.
fn restore_terminal() {
    if KEYBOARD_ENHANCED.swap(false, std::sync::atomic::Ordering::SeqCst)
        && let Err(error) = crossterm::execute!(
            std::io::stdout(),
            crossterm::event::PopKeyboardEnhancementFlags
        )
    {
        tracing::debug!("failed to disable the keyboard enhancement: {error}");
    }
    if let Err(error) =
        crossterm::execute!(std::io::stdout(), crossterm::event::DisableBracketedPaste)
    {
        tracing::debug!("failed to disable bracketed paste: {error}");
    }
    if let Err(error) = crossterm::terminal::disable_raw_mode() {
        tracing::debug!("failed to give the terminal back: {error}");
    }
}

impl RawMode {
    fn enter() -> std::io::Result<Self> {
        crossterm::terminal::enable_raw_mode()?;
        if let Err(error) =
            crossterm::execute!(std::io::stdout(), crossterm::event::EnableBracketedPaste)
        {
            tracing::debug!("failed to enable bracketed paste: {error}");
        }
        // Asked for only where the terminal says it speaks the protocol; the legacy codes stay
        // everywhere else, and a terminal that never answers is treated as one that does not.
        // Asked before the event stream exists, which would otherwise read the answer.
        match crossterm::terminal::supports_keyboard_enhancement() {
            Ok(true) => match crossterm::execute!(
                std::io::stdout(),
                crossterm::event::PushKeyboardEnhancementFlags(
                    crossterm::event::KeyboardEnhancementFlags::DISAMBIGUATE_ESCAPE_CODES
                )
            ) {
                Ok(()) => KEYBOARD_ENHANCED.store(true, std::sync::atomic::Ordering::SeqCst),
                Err(error) => {
                    tracing::debug!("failed to enable the keyboard enhancement: {error}");
                }
            },
            Ok(false) => {}
            Err(error) => {
                tracing::debug!("failed to ask about the keyboard enhancement: {error}");
            }
        }
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            restore_terminal();
            previous(info);
        }));
        Ok(Self)
    }
}

impl Drop for RawMode {
    fn drop(&mut self) {
        restore_terminal();
    }
}

/// The terminal width rows are composed for.
fn output_width() -> usize {
    crossterm::terminal::size()
        .map(|(columns, _)| usize::from(columns))
        .unwrap_or(80)
        .max(render::MIN_OUTPUT_WIDTH)
}

/// The append renderer's state between keys: the console that prints, the line being typed, and
/// the question waiting for its answer.
struct AppendState {
    launch: AppendLaunch,
    console: Console,
    width: usize,
    editor: LineEditor,
    /// Images to send with the next prompt, named in the composer's lead until they are.
    attachments: Vec<super::input::Attachment>,
    history_entries: Vec<String>,
    questions: VecDeque<screen::Question>,
    open: Option<(screen::Question, LineEditor, Instant)>,
    busy: bool,
    wake_pending: bool,
    followups: VecDeque<String>,
    leaving: bool,
    /// Whether the row the cursor sits on needs drawing again.
    dirty: bool,
    /// The work running beside the turn — background tasks and sub-agents — counted once a
    /// second for the status row under the composer, as the screen counts it.
    work: view::RunningWork,
    work_polled: Option<Instant>,
    turn_started: Option<Instant>,
    /// What the agent is doing, as the stream last said: the working row's word.
    activity: view::Activity,
    /// Since when the turn has been busy, from the tick that first saw it; `None` while idle.
    working_since: Option<Instant>,
    /// The seconds and the spinner frame the working row last showed, so a change redraws it.
    shown_working: Option<(u64, usize)>,
    /// The turn's closing row, held until the row that says what went wrong has printed.
    pending_turn_end: Option<Item>,
    thinking: Option<String>,
    thinking_estimate: Option<u64>,
    open_calls: Vec<OpenCall>,
    last_checklist: Option<Vec<crate::checklist::ChecklistItem>>,
    log_ring: VecDeque<crate::relay::LogLine>,
    /// The inbox items this run drew, by id: what it enqueued itself and what a turn's opening
    /// message printed. [`Self::draws_inbox_item`] answers the screen's question with these.
    drawn_inbox: Vec<uuid::Uuid>,
}

impl AppendState {
    fn new(launch: AppendLaunch) -> Self {
        let width = output_width();
        let history_entries = launch
            .history
            .as_ref()
            .map(|history| history.recent(HISTORY_WALK_ENTRIES).unwrap_or_default())
            .unwrap_or_default();
        Self {
            launch,
            console: Console::new(width),
            width,
            editor: LineEditor::default(),
            attachments: Vec::new(),
            history_entries,
            questions: VecDeque::new(),
            open: None,
            busy: false,
            wake_pending: false,
            followups: VecDeque::new(),
            leaving: false,
            dirty: true,
            work: view::RunningWork::default(),
            work_polled: None,
            turn_started: None,
            activity: view::Activity::Working,
            working_since: None,
            shown_working: None,
            pending_turn_end: None,
            thinking: None,
            thinking_estimate: None,
            open_calls: Vec::new(),
            last_checklist: None,
            log_ring: VecDeque::new(),
            drawn_inbox: Vec::new(),
        }
    }

    /// Print the run's opening rows: what the transcript holds at launch (the banner, the session
    /// this one resumes, the prompt that opened it) and, for a resumed session, the log above them
    /// read back page by page until the top. Every row prints once and is never touched again.
    async fn open(&mut self) {
        self.console.start(RowState::Empty);
        self.busy = self.launch.busy;
        let tail_mark = self
            .launch
            .transcript
            .drawn()
            .map(|entry| entry.id)
            .max()
            .unwrap_or(0);
        let mut printed = tail_mark;
        if let Some(session_id) = self.launch.agent.session_id() {
            match self
                .launch
                .store
                .background_store()
                .list_background_tasks(session_id)
                .await
            {
                Ok(tasks) => self.launch.transcript.remember_background_tasks(tasks),
                Err(error) => tracing::warn!("failed to read the background tasks: {error}"),
            }
            if let Some(through) = self.launch.log_end {
                let mut after = 0;
                loop {
                    let page = match self
                        .launch
                        .store
                        .log_page_after(session_id, after, through, model::HISTORY_PAGE_ROWS)
                        .await
                    {
                        Ok(page) => page,
                        Err(error) => {
                            tracing::warn!("failed to read the log: {error}");
                            break;
                        }
                    };
                    let more = page.more;
                    after = page.rows.last().map_or(after, |row| row.id);
                    let empty = page.rows.is_empty();
                    self.launch.transcript.load_page_below(page);
                    self.print_window(&mut printed, tail_mark);
                    if !more || empty {
                        break;
                    }
                }
            }
        }
        self.print_tail(tail_mark);
        if self.launch.pick_session {
            self.reply(
                "The session picker is not available in append mode; pass `--resume <session>`.",
            );
        }
        crate::sandbox::warn_if_sandbox_issues(
            &self.launch.sandbox_state,
            crate::sandbox::WarnContext::ReadModeEntry,
        );
        self.dirty = true;
    }

    /// Print the rows of the transcript's window that have not printed yet (the pages read back
    /// so far, oldest first).
    fn print_window(&mut self, printed: &mut u64, tail_mark: u64) {
        let width = self.width;
        let mut blocks = Vec::new();
        for entry in self.launch.transcript.drawn() {
            if entry.id <= *printed || entry.id <= tail_mark {
                continue;
            }
            *printed = (*printed).max(entry.id);
            blocks.push(render::tui::lines_to_ansi(&view::entry_lines(entry, width)));
        }
        for rows in &blocks {
            self.console.block(rows);
        }
    }

    /// Print the rows this run opened with: the banner or the session this one resumes, then the
    /// prompt that opened it.
    fn print_tail(&mut self, tail_mark: u64) {
        let width = self.width;
        let mut blocks = Vec::new();
        for entry in self.launch.transcript.drawn() {
            if entry.id > tail_mark {
                continue;
            }
            blocks.push(render::tui::lines_to_ansi(&view::entry_lines(entry, width)));
        }
        for rows in &blocks {
            self.console.block(rows);
        }
    }

    /// Print the rows of an item as a block of its own, then the turn's closing row one that failed
    /// was waiting on.
    fn print_item(&mut self, item: Item) {
        self.print_rows_of(&item, false);
        self.flush_pending();
    }

    fn print_rows_of(&mut self, item: &Item, expanded: bool) {
        let entry = Entry {
            id: 0,
            item: item.clone(),
            expanded,
            revision: 0,
        };
        let width = self.width;
        let rows = render::tui::lines_to_ansi(&view::entry_lines(&entry, width));
        self.console.block(&rows);
        self.dirty = true;
    }

    fn flush_pending(&mut self) {
        if let Some(item) = self.pending_turn_end.take() {
            self.print_rows_of(&item, false);
        }
    }

    /// A reply from meka's side: what it says, wrapped to the terminal, set off like any block.
    fn reply(&mut self, text: impl AsRef<str>) {
        let width = self.width;
        let inner = width
            .saturating_sub(render::tui::TEXT_EDGE)
            .max(render::MIN_OUTPUT_WIDTH);
        let rows = render::tui::lines_to_ansi(&render::tui::edge_rows(render::tui::plain_lines(
            text.as_ref(),
            inner,
            Style::default(),
        )));
        self.console.block(&rows);
        self.dirty = true;
    }

    fn note(&mut self, text: impl AsRef<str>) {
        self.print_item(Item::note(text.as_ref().to_string()));
    }

    /// Ask a question: it queues behind any other, and the first in line prints as rows with its
    /// answer line below.
    fn ask(&mut self, question: screen::Question) {
        self.questions.push_back(question);
        self.dirty = true;
    }

    /// Draw the row the cursor sits on, if anything moved since the last draw.
    fn refresh(&mut self) {
        if !self.dirty {
            return;
        }
        self.dirty = false;
        let width = self.width;
        let (text, cursor) = match &self.open {
            Some((_, answer, _)) => (answer.text().to_string(), answer.cursor()),
            None => (self.editor.text().to_string(), self.editor.cursor()),
        };
        let status = self.status_row_line(width);
        let lead = self.composer_lead();
        let working = self.working_line_now(width);
        let working_rows = usize::from(working.is_some());
        let (lines, cursor_row, cursor_at) = composer_lines(
            &text,
            cursor,
            composer_row_cap().saturating_sub(working_rows).max(1),
        );
        // The block is the working row, when the turn runs, the input rows, and the status row
        // under them.
        let rows = working_rows + lines.len() + 1;
        self.console.transient(rows, working_rows + cursor_row, || {
            draw_composer(
                &lead,
                &lines,
                cursor_row,
                cursor_at,
                working.as_ref(),
                &status,
                width,
            )
        });
    }

    /// The working row as it stands: what the agent does, the seconds it has run and the spinner's
    /// frame, while the turn runs. `None` while idle.
    fn working_line_now(&self, width: usize) -> Option<Line<'static>> {
        let since = self.working_since?;
        let activity = if self.open.is_some() {
            view::Activity::Waiting
        } else {
            self.activity
        };
        let frame = self.shown_working.map_or(0, |(_, frame)| frame);
        Some(view::working_line(&activity, since.elapsed(), frame, width))
    }

    /// Keep the working row's clock: the turn's start is noted by the first tick that sees it busy,
    /// and the row is redrawn when its seconds or its spinner frame change. The spinner stills
    /// while the turn waits on the user.
    fn tick_working(&mut self) {
        if !self.busy {
            if self.working_since.take().is_some() {
                self.shown_working = None;
                self.dirty = true;
            }
            return;
        }
        let since = *self.working_since.get_or_insert_with(Instant::now);
        let waiting = self.open.is_some();
        let elapsed = since.elapsed();
        let frame = if waiting {
            self.shown_working.map_or(0, |(_, frame)| frame)
        } else {
            view::spinner_frame(elapsed)
        };
        let shown = (elapsed.as_secs(), frame);
        if self.shown_working != Some(shown) {
            self.shown_working = Some(shown);
            self.dirty = true;
        }
    }

    /// What leads the input row: the images waiting for the next prompt, as the screen's chips
    /// name them, then the prompt glyph. An open question's answer line has the glyph alone.
    fn composer_lead(&self) -> String {
        if self.open.is_some() {
            return "> ".to_string();
        }
        let mut lead = String::new();
        for (index, attachment) in self.attachments.iter().enumerate() {
            lead.push_str(&format!("[image {}  {}] ", index + 1, attachment.label));
        }
        lead.push_str("> ");
        lead
    }

    /// The screen's status row: the facts of the session laid out as the screen lays them out,
    /// under the composer where the screen keeps it. The hints are events this renderer speaks
    /// in rows, so the row says nothing of them.
    fn status_row_line(&self, width: usize) -> Line<'static> {
        let facts = view::StatusFacts {
            shown: &self.launch.status_row,
            permission: self.launch.shared_permission.get(),
            path: Some(super::input::shorten_path_with_tilde(
                &self.launch.cwd.get(),
            )),
            project: self.launch.agent.project(),
            profile: self.profile_fact(),
            model: self.model_fact(),
            context: self.context_gauge(),
            work: self.work,
            hint: None,
            shell_mode: false,
        };
        view::status_line(&facts, width)
    }

    /// The profile in effect, as the screen's status row names it.
    fn profile_fact(&self) -> Option<String> {
        let name = crate::sync::read(&self.launch.current_profile).clone();
        (!name.is_empty()).then_some(name)
    }

    /// The model the profile runs, looked up the way the screen's status row looks it up.
    fn model_fact(&self) -> Option<String> {
        let name = crate::sync::read(&self.launch.current_profile).clone();
        self.launch
            .configured_profiles
            .iter()
            .find(|profile| profile.name == name)
            .and_then(|profile| profile.model.clone())
    }

    /// The context gauge's text, `None` while the window is unknown, as on the screen.
    fn context_gauge(&self) -> Option<String> {
        let (tokens, window) = self.launch.context.as_ref()?;
        view::context_gauge_text(
            tokens.load(std::sync::atomic::Ordering::Relaxed),
            window.load(std::sync::atomic::Ordering::Relaxed),
        )
    }

    /// Read back how much work runs beside the turn, once a second: the session's background
    /// tasks from the store, the sub-agents from the process. A change redraws the status row.
    async fn poll_work(&mut self) {
        if self
            .work_polled
            .is_some_and(|at| at.elapsed() < WORK_POLL_INTERVAL)
        {
            return;
        }
        self.work_polled = Some(Instant::now());
        let tasks = match self.launch.agent.session_id() {
            Some(session_id) => match self
                .launch
                .store
                .background_store()
                .list_running_background_tasks(session_id)
                .await
            {
                // A sub-agent run in the background is a task row too; it is counted as the
                // sub-agent it is.
                Ok(rows) => rows
                    .iter()
                    .filter(|task| task.tool != "agent_spawn")
                    .count(),
                Err(error) => {
                    tracing::debug!("failed to count the running tasks: {error}");
                    self.work.tasks
                }
            },
            None => 0,
        };
        let work = view::RunningWork {
            tasks,
            subagents: self.launch.running_subagents.running_ids().len(),
        };
        if work != self.work {
            self.work = work;
            self.dirty = true;
        }
    }

    fn resize(&mut self, columns: u16) {
        self.width = usize::from(columns).max(render::MIN_OUTPUT_WIDTH);
        self.console.set_width(self.width);
        self.dirty = true;
    }

    /// Put the typed line through the host the way the screen's composer sends it.
    async fn submit(&mut self) {
        let text = self.editor.text().trim().to_string();
        if text.is_empty() && self.attachments.is_empty() {
            return;
        }
        // An image rides on a prompt that opens a turn; the inbox a busy turn reads carries words
        // alone.
        if self.busy && !self.attachments.is_empty() {
            self.reply("An image goes with the next prompt; wait for the turn to end.");
            return;
        }
        if !text.is_empty() {
            self.remember(&text);
        }
        self.editor.clear();
        self.console.erase_transient();
        self.dirty = true;
        if !self.attachments.is_empty() {
            self.send_with_images(text);
            return;
        }
        if text.eq_ignore_ascii_case("exit") || text.eq_ignore_ascii_case("quit") {
            self.leave();
            return;
        }
        if text.starts_with('/') {
            self.run_command_line(text).await;
            return;
        }
        if text.starts_with('!') {
            self.reply("The shell escape (!) is not available in append mode.");
            return;
        }
        if self.busy {
            self.send_while_busy(text).await;
            return;
        }
        self.print_item(Item::Prompt {
            text: text.clone(),
            class: None,
            inbox_id: None,
            delivered: true,
        });
        self.send_host(HostEvent::UserInput {
            text,
            images: Vec::new(),
        });
    }

    /// The prompt and the images waiting with it, sent as the screen sends them: not as a command
    /// or an exit, whatever the words say.
    fn send_with_images(&mut self, text: String) {
        let attachments = std::mem::take(&mut self.attachments);
        if !text.is_empty() {
            self.print_item(Item::Prompt {
                text: text.clone(),
                class: None,
                inbox_id: None,
                delivered: true,
            });
        }
        for _ in &attachments {
            self.print_item(Item::Image);
        }
        self.send_host(HostEvent::UserInput {
            text,
            images: attachments
                .into_iter()
                .map(|attachment| attachment.source)
                .collect(),
        });
    }

    /// Attach image bytes to the next prompt, through the door the screen and the HTTP API's
    /// images take, so the limits and the format rules are one set.
    fn attach_image(&mut self, bytes: &[u8], label: String) {
        if !self.launch.agent.cells().profile.current().vision {
            self.reply(format!(
                "The profile '{}' does not accept images.",
                crate::sync::read(&self.launch.current_profile)
            ));
            return;
        }
        match crate::image::prepare_image_source(crate::image::classify_bytes(bytes), bytes) {
            Ok(source) => {
                self.attachments
                    .push(super::input::Attachment { source, label });
                self.dirty = true;
            }
            Err(error) => self.reply(error),
        }
    }

    /// A line sent while the turn runs: a followup queues for the next gap in the answer, anything
    /// else steers the running turn through the session's inbox.
    async fn send_while_busy(&mut self, text: String) {
        let class = self.launch.send_class;
        if class == InboxClass::Followup {
            self.print_item(Item::Prompt {
                text: text.clone(),
                class: Some(class),
                inbox_id: None,
                delivered: false,
            });
            self.followups.push_back(text);
            return;
        }
        let Some(session_id) = self.launch.agent.session_id() else {
            self.reply("No active session yet.");
            return;
        };
        let item = match NewInboxItem::from_parts(
            session_id,
            class,
            Some("terminal".to_string()),
            text.as_str(),
        ) {
            Ok(item) => item,
            Err(error) => {
                self.reply(error.to_string());
                return;
            }
        };
        match self.launch.store.inbox_store().enqueue(item).await {
            Ok(enqueued) => {
                self.drawn_inbox.push(enqueued.id);
                self.print_item(Item::Prompt {
                    text,
                    class: Some(class),
                    inbox_id: Some(enqueued.id),
                    delivered: false,
                });
            }
            Err(error) => self.reply(error.to_string()),
        }
    }

    /// Whether an inbox item is already drawn: printed by this run when it enqueued the item, or
    /// sitting in the rows of the session this run resumed. The screen asks its own transcript the
    /// same question, and the answer keeps one message from printing twice when the turn that
    /// reads it opens with it.
    fn draws_inbox_item(&self, id: uuid::Uuid) -> bool {
        self.drawn_inbox.contains(&id)
            || self.launch.transcript.drawn().any(|entry| {
                matches!(&entry.item, Item::Prompt { inbox_id: Some(drawn), .. } if *drawn == id)
            })
    }

    /// Remember a line sent, so Up walks to it: the newest one is not repeated.
    fn remember(&mut self, text: &str) {
        if self.history_entries.last().map(String::as_str) == Some(text) {
            return;
        }
        self.history_entries.push(text.to_string());
        if self.history_entries.len() > HISTORY_WALK_ENTRIES {
            self.history_entries.remove(0);
        }
        if let Some(history) = &self.launch.history
            && let Err(error) = history.append(text)
        {
            tracing::debug!("failed to remember the line: {error}");
        }
    }

    fn send_host(&self, event: HostEvent) {
        if self.launch.host.send(event).is_err() {
            tracing::debug!("the host loop is gone");
        }
    }

    fn leave(&mut self) {
        self.leave_with(false);
    }

    fn leave_with(&mut self, interrupted: bool) {
        self.launch
            .cancel
            .cancel(crate::store::turns::CancelReason::Client);
        self.send_host(HostEvent::Exit { interrupted });
        self.leaving = true;
    }

    fn hang_up(&mut self) {
        self.leave_with(true);
    }

    /// The screen's interruption ladder: the first press stops the turn, the second the background
    /// work, the third leaves.
    async fn interrupt(&mut self) {
        if !self.busy
            && self.open.is_none()
            && !(self.editor.is_empty() && self.attachments.is_empty())
        {
            self.editor.clear();
            self.attachments.clear();
            self.dirty = true;
            return;
        }
        let press = crate::host::terminal::INTERRUPT_RELAY.count_press(&self.launch.cancel);
        match crate::host::terminal::escalation_for(press) {
            crate::host::terminal::Escalation::CancelTurn => {
                self.withdraw_questions();
                if !self.busy {
                    self.note("Ctrl+C again stops background tasks, a third leaves");
                }
            }
            crate::host::terminal::Escalation::CancelBackgroundTasks => {
                let stopped = crate::host::terminal::cancel_background_tasks(
                    &self.launch.agent.background_tasks(),
                    &self.launch.agent.store(),
                )
                .await;
                if let Some(notice) = crate::host::terminal::background_cancellation_notice(stopped)
                {
                    self.note(notice);
                }
            }
            crate::host::terminal::Escalation::Leave => self.leave_with(true),
        }
    }

    /// Answer every question the safe way: a turn the user has stopped is not waiting on one.
    fn withdraw_questions(&mut self) {
        let mut withdrawn = false;
        if let Some((question, ..)) = self.open.take() {
            question.withdraw();
            withdrawn = true;
        }
        while let Some(question) = self.questions.pop_front() {
            question.withdraw();
            withdrawn = true;
        }
        if withdrawn {
            self.reply(screen::QUESTION_WITHDRAWN_HINT);
        }
        self.dirty = true;
    }

    /// A question whose turn has moved on is answered rather than left hanging.
    fn withdraw_stopped_questions(&mut self) {
        if self
            .open
            .as_ref()
            .is_some_and(|(question, ..)| question.is_withdrawn())
            && let Some((question, ..)) = self.open.take()
        {
            question.withdraw();
            self.reply(screen::QUESTION_WITHDRAWN_HINT);
            self.dirty = true;
        }
    }

    /// Take the next queued question, if any, and print it as rows with its answer line below.
    fn open_question(&mut self) {
        if self.open.is_some() {
            return;
        }
        let Some(question) = self.questions.pop_front() else {
            return;
        };
        let width = self.width;
        let rows = match &question {
            screen::Question::Approval(request) => approval_rows(request, width),
            screen::Question::Elicitation { prompt, .. } => elicitation_rows(prompt, width),
        };
        self.console.block(&rows);
        self.open = Some((question, LineEditor::default(), Instant::now()));
        self.dirty = true;
    }

    /// Answer the open question from the line below it.
    fn answer_open(&mut self) {
        let Some((question, answer, _)) = self.open.take() else {
            return;
        };
        let said = answer.text().to_string();
        match question {
            screen::Question::Approval(request) => match approval_answer(&said) {
                Some(decision) => self.decide(request, decision),
                None => {
                    self.reply("Takes y, a, n, or the words allow, always, deny, never.");
                    self.open = Some((
                        screen::Question::Approval(request),
                        LineEditor::default(),
                        Instant::now(),
                    ));
                }
            },
            screen::Question::Elicitation { prompt, responder } => match url_answer(&said) {
                Some(answer) => self.decide_url(prompt, responder, answer),
                None => {
                    self.reply("Takes y, s, n, or the words open, skip, decline.");
                    self.open = Some((
                        screen::Question::Elicitation { prompt, responder },
                        LineEditor::default(),
                        Instant::now(),
                    ));
                }
            },
        }
        self.dirty = true;
    }

    /// Answer an approval prompt the way the screen's panel would, with the note it makes. The
    /// `always` and `never` answers stick in the frontend, which answers the calls that follow
    /// without asking.
    fn decide(&mut self, request: ApprovalRequest, decision: ApprovalDecision) {
        self.console.commit_transient();
        let name = one_line(&request.tool_name, 64);
        if request.responder.is_closed() {
            self.reply("discarded: the turn had already been stopped");
            return;
        }
        match decision {
            ApprovalDecision::Allow => self.note(format!("{name} allowed")),
            ApprovalDecision::AllowAlways => self.note(format!("{name} allowed for the session")),
            ApprovalDecision::Deny => self.note(format!("{name} denied")),
            ApprovalDecision::DenyAlways => self.note(format!("{name} denied for the session")),
        }
        if request.responder.send(decision).is_err() {
            tracing::trace!("the turn that asked has already moved on");
        }
    }

    /// Answer a URL consent flow: the URL is opened outside meka, skipped, or declined.
    fn decide_url(
        &mut self,
        prompt: ElicitationPrompt,
        responder: tokio::sync::oneshot::Sender<ElicitationResponse>,
        answer: UrlAnswer,
    ) {
        self.console.commit_transient();
        if responder.is_closed() {
            self.reply("discarded: the turn had already been stopped");
            return;
        }
        let response = match answer {
            UrlAnswer::Open => {
                if let ElicitationKind::Url { url, .. } = &prompt.kind {
                    match open::that(url) {
                        Ok(()) => self.note("opened in the browser"),
                        Err(error) => self.note(format!("failed to open the link: {error}")),
                    }
                }
                ElicitationResponse::Accept { content: None }
            }
            UrlAnswer::Skip => {
                self.note("skipped");
                ElicitationResponse::Cancel
            }
            UrlAnswer::Decline => {
                self.note("declined");
                ElicitationResponse::Decline
            }
        };
        if responder.send(response).is_err() {
            tracing::trace!("the turn that asked has already moved on");
        }
    }

    /// Put a slash command through the same dispatch the screen's composer uses.
    async fn run_command_line(&mut self, line: String) {
        match commands::parse_slash_command(&line) {
            Some(command) => match command.answered_by() {
                Answerer::Screen => self.answer_locally(command).await,
                Answerer::Host if self.busy => self.reply(SlashCommand::busy_refusal(&line)),
                Answerer::Host => self.send_host(HostEvent::Command(command)),
            },
            None => self.reply(commands::unknown_command_message(&line)),
        }
    }

    /// The commands the screen answers on its own, answered here in rows.
    async fn answer_locally(&mut self, command: SlashCommand) {
        match command {
            SlashCommand::Exit => self.leave(),
            SlashCommand::Log => self.print_log_ring(),
            SlashCommand::Help => {
                // The command table is the same in both renderers; the keys under it are not, so
                // the screen's shortcut list is left out for the ones this renderer reads.
                let help = commands::help_text();
                let table = help
                    .split_once("\n  Shortcuts:")
                    .map_or(help.as_str(), |(table, _)| table.trim_end());
                self.reply(format!(
                    "{table}\n\n  Keys here:\n\
                     \x20   Up/Down   Walk what you sent before\n\
                     \x20   Ctrl+A/E  The start and the end of the line\n\
                     \x20   Ctrl+K/U  Cut to the end, cut to the start\n\
                     \x20   Ctrl+W    Cut the word behind the cursor\n\
                     \x20   Enter     Send\n\
                     \x20   (paste) A path to an image file attaches it to the next prompt\n\
                     \x20   Alt+Enter A line break (Ctrl+J; Shift+Enter on a kitty-protocol terminal)\n\
                     \x20   Ctrl+C    Stop the turn, then background work, then leave\n\
                     \x20   Ctrl+D    Leave, on the empty composer of an idle run"
                ));
            }
            SlashCommand::Session => self.reply(match self.launch.agent.session_id() {
                Some(id) => format!("Current session: {id}"),
                None => "No active session yet.".to_string(),
            }),
            SlashCommand::Resume(None) => {
                self.reply("The session picker is not available in append mode; pass an argument: /resume <session>.");
            }
            SlashCommand::Profile(None) => {
                let current = crate::sync::read(&self.launch.current_profile).clone();
                self.reply(format!("Profile: {current}"));
            }
            SlashCommand::Permission(None) => {
                let level = self.launch.shared_permission.get();
                self.reply(format!(
                    "Permission level: {level}. `/permission <level>` changes it."
                ));
            }
            SlashCommand::Permission(Some(level)) => {
                match level.parse::<crate::permission::Permission>() {
                    Ok(permission) => self.set_permission(permission),
                    Err(error) => self.reply(error),
                }
            }
            SlashCommand::Approvals(argument) => match argument.as_deref().map(str::trim) {
                None | Some("") => {
                    let on = self.launch.shared_permission.approvals();
                    self.reply(format!("Approvals: {}", if on { "on" } else { "off" }));
                }
                Some(word @ ("on" | "off")) => self.set_approvals(word == "on"),
                Some(other) => {
                    self.reply(format!(
                        "'{other}' is not a setting: `/approvals` takes on or off"
                    ));
                }
            },
            SlashCommand::Cd(argument) => {
                match super::input::handle_cd(
                    &self.launch.cwd,
                    &self.launch.launch_cwd,
                    argument.as_deref().unwrap_or(""),
                ) {
                    Ok(moved) => {
                        self.note(format!(
                            "Working directory set to: {}",
                            super::input::shorten_path_with_tilde(&moved)
                        ));
                        self.send_host(HostEvent::CwdChanged(moved));
                    }
                    Err(message) => self.reply(message),
                }
            }
            SlashCommand::SkillList => self.list_skills(),
            SlashCommand::MemoryList => self.list_memories().await,
            SlashCommand::MemoryShow { name } => self.show_memory(&name).await,
            SlashCommand::ScheduleList => self.list_schedule().await,
            SlashCommand::ScheduleShow { id } => self.show_scheduled_job(&id).await,
            SlashCommand::ScheduleCancel { id } => self.cancel_scheduled_job(&id).await,
            SlashCommand::TaskList => self.list_background_tasks().await,
            SlashCommand::TaskShow { id } => self.show_background_task(id).await,
            SlashCommand::TaskCancel { id } => self.cancel_background_tasks(id).await,
            other => debug_assert_eq!(
                other.answered_by(),
                Answerer::Screen,
                "a host command reached the append renderer"
            ),
        }
    }

    fn set_permission(&mut self, level: crate::permission::Permission) {
        match self.launch.shared_permission.try_set(level) {
            Ok(()) => {
                self.note(format!("Permission level set to: {level}"));
                self.send_host(HostEvent::PermissionChanged(level));
            }
            Err(error) => self.reply(error.to_string()),
        }
    }

    fn set_approvals(&mut self, on: bool) {
        self.launch.shared_permission.set_approvals(on);
        self.note(format!(
            "Approvals set to: {}",
            if on { "on" } else { "off" }
        ));
        self.send_host(HostEvent::ApprovalsChanged(on));
    }

    /// The rows `/log` prints back: what the run has kept of what was written to its log.
    fn print_log_ring(&mut self) {
        let width = self.width;
        let mut rows = Vec::new();
        for line in self.log_ring.clone() {
            let entry = Entry {
                id: 0,
                item: log_item(line),
                expanded: false,
                revision: 0,
            };
            rows.extend(render::tui::lines_to_ansi(&view::entry_lines(
                &entry, width,
            )));
        }
        if rows.is_empty() {
            self.reply("Nothing logged this run.");
            return;
        }
        self.console.block(&rows);
        self.dirty = true;
    }

    fn list_skills(&mut self) {
        let index = crate::skills::discover_skills_in_roots(&self.launch.skill_roots);
        let rows: Vec<String> = index
            .skills
            .iter()
            .map(|skill| match description_of(&skill.description) {
                Some(description) => format!("{}: {description}", skill.name),
                None => skill.name.clone(),
            })
            .collect();
        if rows.is_empty() {
            self.reply("No skills available.");
            return;
        }
        self.reply(rows.join("\n"));
    }

    async fn list_memories(&mut self) {
        let store = self
            .launch
            .store
            .memory_store(true, self.launch.memory_inline_max_bytes);
        let view =
            crate::store::memory::MemoryView::for_session(self.launch.agent.project().as_deref());
        let index = match store.index(&view).await {
            Ok(index) => index,
            Err(error) => {
                self.reply(error.to_string());
                return;
            }
        };
        let rows: Vec<String> = index
            .iter()
            .map(|memory| match description_of(&memory.description) {
                Some(description) => format!("{}: {description}", memory.name),
                None => memory.name.clone(),
            })
            .collect();
        if rows.is_empty() {
            self.reply("No memories yet.");
            return;
        }
        self.reply(rows.join("\n"));
    }

    async fn show_memory(&mut self, name: &str) {
        let store = self
            .launch
            .store
            .memory_store(true, self.launch.memory_inline_max_bytes);
        let view =
            crate::store::memory::MemoryView::for_session(self.launch.agent.project().as_deref());
        let (outcome, printed) =
            crate::streams::capture(crate::cli::memory::run_show(&store, name, &view)).await;
        self.listing(printed, outcome);
    }

    async fn list_schedule(&mut self) {
        let Some(session_id) = self.launch.agent.session_id() else {
            self.reply("No active session yet.");
            return;
        };
        let jobs = match self
            .launch
            .store
            .schedule_store()
            .list_scheduled_jobs(session_id)
            .await
        {
            Ok(jobs) => jobs,
            Err(error) => {
                self.reply(error.to_string());
                return;
            }
        };
        let levels =
            crate::cli::schedule::with_levels(&self.launch.store, &self.launch.schedule, jobs)
                .await;
        let rows: Vec<String> = levels
            .iter()
            .map(|(job, level)| {
                let held = match crate::schedule::job_withheld(
                    self.launch.store.scheduler_memory(),
                    job,
                    *level,
                    None,
                ) {
                    crate::schedule::Withheld::Yes(_) => "  held",
                    crate::schedule::Withheld::Undetermined => "  held?",
                    crate::schedule::Withheld::No => "",
                };
                format!(
                    "{}: {} — {}{held}",
                    one_line(&job.id, 8),
                    job.schedule.describe(),
                    one_line(&job.prompt, 80)
                )
            })
            .collect();
        if rows.is_empty() {
            self.reply("No scheduled jobs.");
            return;
        }
        self.reply(rows.join("\n"));
    }

    async fn show_scheduled_job(&mut self, id: &str) {
        let session = self.launch.agent.session_id();
        let (outcome, printed) = crate::streams::capture(crate::cli::schedule::show(
            &self.launch.store,
            id,
            &self.launch.schedule,
            session,
        ))
        .await;
        self.listing(printed, outcome);
    }

    async fn cancel_scheduled_job(&mut self, id: &str) {
        let Some(session_id) = self.launch.agent.session_id() else {
            self.reply("No active session yet.");
            return;
        };
        match self
            .launch
            .store
            .schedule_store()
            .cancel_scheduled_job(session_id, id)
            .await
        {
            Ok(Some(canceled)) => self.note(format!("Canceled job {}", one_line(&canceled, 8))),
            Ok(None) => self.reply(format!("No scheduled job matching '{id}'.")),
            Err(error) => self.reply(error.to_string()),
        }
    }

    async fn list_background_tasks(&mut self) {
        let Some(session_id) = self.launch.agent.session_id() else {
            self.reply("No active session yet.");
            return;
        };
        let tasks = match self
            .launch
            .store
            .background_store()
            .list_background_tasks(session_id)
            .await
        {
            Ok(tasks) => tasks,
            Err(error) => {
                self.reply(error.to_string());
                return;
            }
        };
        let rows: Vec<String> = tasks
            .iter()
            .map(|task| {
                format!(
                    "{}: {} — {}",
                    one_line(&task.id, 8),
                    task.status.name(),
                    one_line(&task.label, 64)
                )
            })
            .collect();
        if rows.is_empty() {
            self.reply("No background tasks.");
            return;
        }
        self.reply(rows.join("\n"));
    }

    async fn show_background_task(&mut self, id: String) {
        let Some(session) = self.launch.agent.session_id() else {
            self.reply("No active session yet.");
            return;
        };
        let (outcome, printed) = crate::streams::capture(crate::cli::background::show(
            &self.launch.store,
            session,
            &id,
            render::Stream::Stderr,
        ))
        .await;
        self.listing(printed, outcome);
    }

    async fn cancel_background_tasks(&mut self, id: Option<String>) {
        let Some(session_id) = self.launch.agent.session_id() else {
            self.reply("No active session yet.");
            return;
        };
        let cancelled =
            match crate::cli::background::cancel(&self.launch.store, session_id, id.as_deref())
                .await
            {
                Ok(cancelled) => cancelled,
                Err(error) => {
                    self.reply(error.to_string());
                    return;
                }
            };
        if cancelled.is_empty() {
            self.reply("No running background tasks.");
            return;
        }
        let tasks = self.launch.agent.background_tasks();
        for task_id in &cancelled {
            tasks.cancel(task_id).await;
        }
        self.note(format!("Canceling {} background task(s).", cancelled.len()));
    }

    /// A listing, cut like the screen's panels and standing in place of one.
    fn listing<E: std::fmt::Display>(&mut self, mut printed: String, outcome: Result<(), E>) {
        if printed.len() > LISTING_KEEP_BYTES {
            model::keep_tail(&mut printed, LISTING_KEEP_BYTES);
            printed.insert_str(
                0,
                &format!(
                    "(cut to the last {})\n",
                    crate::text::format_size(LISTING_KEEP_BYTES)
                ),
            );
        }
        if let Err(error) = outcome {
            if !printed.is_empty() && !printed.ends_with('\n') {
                printed.push('\n');
            }
            printed.push_str(&error.to_string());
        }
        self.reply(printed);
    }

    /// The rows of a tool call that settled: printed once, the way the screen draws a collapsed
    /// call.
    fn settle_call(
        &mut self,
        call: OpenCall,
        is_error: bool,
        change: Option<model::TextChange>,
        result: Option<String>,
        result_images: usize,
    ) {
        let item = call.into_item(ToolState::Done { is_error }, result, result_images, change);
        self.print_item(item);
    }

    /// Calls still open when the turn ends print in the state they were left in.
    fn close_open_calls(&mut self) {
        for call in std::mem::take(&mut self.open_calls) {
            let state = call.state;
            let item = call.into_item(state, None, 0, None);
            self.print_item(item);
        }
    }

    /// A thinking block's row, collapsed: what it said, or just its size when it said nothing.
    /// `content` is the whole block for a turn that did not stream it.
    fn close_thinking(&mut self, content: Option<String>, seen: bool) {
        let text = match self.thinking.take() {
            Some(text) if !text.trim().is_empty() => text,
            Some(_) | None => content
                .map(|content| crate::text::sanitize_stream_text(&content))
                .unwrap_or_default(),
        };
        if text.trim().is_empty() && self.thinking_estimate.is_none() && !seen {
            return;
        }
        let estimate = self.thinking_estimate.take();
        self.print_item(Item::Thinking {
            text,
            estimate,
            ended: true,
        });
    }

    /// Take in the events the agent sends, printed as they arrive.
    fn handle_event(&mut self, event: FrontendEvent) {
        self.activity.note(&event);
        self.dirty = true;
        match event {
            FrontendEvent::SessionStarted { id } => {
                if self.launch.settings.show_session_id_on_create {
                    self.print_item(Item::SessionId {
                        label: "Creating new session".to_string(),
                        id: id.to_string(),
                    });
                }
            }
            FrontendEvent::TurnStarted { .. } => {
                self.busy = true;
                self.flush_pending();
                self.turn_started = Some(Instant::now());
                self.console.close_stream();
            }
            FrontendEvent::TurnFinished => self.console.close_stream(),
            FrontendEvent::TurnEnded { ending, .. } => {
                let elapsed = self.turn_started.take().map(|started| started.elapsed());
                self.close_open_calls();
                self.thinking = None;
                self.thinking_estimate = None;
                let ended_at = chrono::Utc::now();
                if let Some(text) = render::turn_end_summary(
                    &self.launch.settings.turn_end_summary,
                    ending.status,
                    ended_at,
                    elapsed,
                    &ending.usage,
                    ended_at,
                ) {
                    if ending.status == crate::store::turns::TurnStatus::Succeeded {
                        self.print_item(Item::TurnEnd(text));
                    } else {
                        self.pending_turn_end = Some(Item::TurnEnd(text));
                    }
                }
            }
            // The message a turn opens with, whichever door opened it. The person's own words are
            // drawn as they are typed and the context block is meka's; a fire and a report are
            // said as the stage directions a replay of the log says, so the two read alike.
            FrontendEvent::MessageAppended {
                message,
                outcomes,
                late,
            } => {
                for block in &message.content {
                    match block {
                        ContentBlock::Scheduled { job_id, prompt, .. } => {
                            self.note(render::fire_direction(job_id, prompt, late));
                        }
                        ContentBlock::BackgroundReport { .. } => {
                            self.note(crate::background::report_direction(&outcomes));
                        }
                        // Words another client posted to the inbox, read by the model with this
                        // turn: printed as a replay prints them, unless this run already printed
                        // them when it enqueued them itself.
                        ContentBlock::Inbox {
                            item_id,
                            class,
                            body,
                            ..
                        } => {
                            if item_id.is_some_and(|id| self.draws_inbox_item(id)) {
                                continue;
                            }
                            if let Some(id) = item_id {
                                self.drawn_inbox.push(*id);
                            }
                            self.print_item(Item::Prompt {
                                text: body.trim().to_string(),
                                class: *class,
                                inbox_id: *item_id,
                                delivered: false,
                            });
                        }
                        ContentBlock::Text { .. }
                        | ContentBlock::TurnContext { .. }
                        | ContentBlock::Nudge { .. }
                        | ContentBlock::Image { .. }
                        | ContentBlock::Thinking { .. }
                        | ContentBlock::RedactedThinking { .. }
                        | ContentBlock::ToolUse { .. }
                        | ContentBlock::ToolResult { .. } => {}
                    }
                }
            }
            FrontendEvent::AssistantTextDelta(text) => self.console.text_delta(&text),
            FrontendEvent::ThinkingDelta(text) => {
                let open = self.thinking.get_or_insert_with(String::new);
                open.push_str(&crate::text::sanitize_stream_text(&text));
            }
            FrontendEvent::ThinkingProgress { estimated_tokens } => {
                self.thinking.get_or_insert_with(String::new);
                if estimated_tokens.is_some() {
                    self.thinking_estimate = estimated_tokens;
                }
            }
            FrontendEvent::ThinkingEnded => {
                if self.thinking.is_some() {
                    self.close_thinking(None, false);
                }
            }
            FrontendEvent::ThinkingBlock { content } => self.close_thinking(Some(content), true),
            FrontendEvent::ToolCallComposing { id, name, .. } => {
                self.open_calls.retain(|call| call.id != id);
                self.open_calls.push(OpenCall {
                    id,
                    name,
                    input: None,
                    summary: String::new(),
                    output: String::new(),
                    activity: String::new(),
                    progress: None,
                    state: ToolState::Composing,
                });
            }
            FrontendEvent::ToolCallStarted {
                id,
                name,
                input,
                display_summary,
            } => {
                self.open_calls.retain(|call| call.id != id);
                self.open_calls.push(OpenCall {
                    id,
                    name,
                    input: Some(input),
                    summary: display_summary.unwrap_or_default(),
                    output: String::new(),
                    activity: String::new(),
                    progress: None,
                    state: ToolState::Running,
                });
            }
            FrontendEvent::ToolCallOutputDelta { id, chunk } => {
                if let Some(call) = self.open_calls.iter_mut().find(|call| call.id == id) {
                    call.output.push_str(&chunk);
                    model::keep_tail(&mut call.output, model::TOOL_TEXT_KEEP_BYTES);
                }
            }
            FrontendEvent::ToolCallCompleted {
                id,
                is_error,
                content,
                metadata,
                ..
            } => {
                let Some(index) = self.open_calls.iter().position(|call| call.id == id) else {
                    return;
                };
                let call = self.open_calls.remove(index);
                let (result, result_images) = model::result_text(&content);
                let change = match metadata {
                    Some(crate::frontend::ToolOutputMetadata::Diff {
                        old_text, new_text, ..
                    }) if !is_error => Some(model::TextChange {
                        old: old_text,
                        new: new_text,
                    }),
                    _ => None,
                };
                self.settle_call(
                    call,
                    is_error,
                    change,
                    (!result.is_empty()).then_some(result),
                    result_images,
                );
            }
            FrontendEvent::ChecklistUpdated { items } => {
                if self.last_checklist.as_ref() != Some(&items) {
                    self.last_checklist = Some(items.clone());
                    if !items.is_empty() {
                        self.print_item(Item::Checklist { items });
                    }
                }
            }
            FrontendEvent::SubAgentActivity {
                tool_call_id,
                summary,
            } => {
                if let Some(call) = self
                    .open_calls
                    .iter_mut()
                    .find(|call| call.id == tool_call_id)
                {
                    call.activity = summary;
                }
            }
            FrontendEvent::McpProgress(update) => {
                // The call's own row carries the reports, as the screen folds them onto it: a
                // row printed once cannot move with a progress bar, and the last report is the
                // fact worth keeping once the call settles.
                let line = crate::text::sanitize_to_line(
                    &format!(
                        "{}/{} {}{}",
                        update.server_name,
                        update.tool_name,
                        match update.total {
                            Some(total) if total > 0.0 =>
                                format!("{:.0}/{:.0}", update.progress, total),
                            _ => format!("{:.0}", update.progress),
                        },
                        update
                            .message
                            .as_deref()
                            .map(|message| format!(" {message}"))
                            .unwrap_or_default()
                    ),
                    usize::MAX,
                );
                let call = match update.tool_use_id.as_deref() {
                    Some(id) => self.open_calls.iter_mut().find(|call| call.id == id),
                    // With no call id to name it, the screen attaches the update to the call in
                    // flight; this renderer reads it the same way.
                    None => self
                        .open_calls
                        .iter_mut()
                        .rev()
                        .find(|call| call.state == ToolState::Running),
                };
                if let Some(call) = call {
                    call.progress = Some(line);
                }
            }
            FrontendEvent::BackgroundReported { tasks, .. } => {
                self.note(crate::background::report_direction(&tasks));
            }
            FrontendEvent::Notice(notice) => self.print_item(Item::Notice {
                level: notice.level,
                text: notice.text,
            }),
            // What a run needs of these arrives as notes and turn rows; rows carry no rate-limit
            // banner or compaction marker of their own.
            FrontendEvent::TokenUsage { .. }
            | FrontendEvent::ContextMeasured { .. }
            | FrontendEvent::CompactionStarted { .. }
            | FrontendEvent::Compacted { .. }
            | FrontendEvent::CompactionFailed { .. }
            | FrontendEvent::PromptWithdrawn
            | FrontendEvent::InboxDelivered { .. }
            | FrontendEvent::Nudged { .. } => {}
        }
    }

    /// Take in what the host and the agent's side hand the UI.
    fn handle_ui(&mut self, event: UiEvent) {
        match event {
            UiEvent::Agent(event) => self.handle_event(event),
            UiEvent::Approval(request) => self.ask(screen::Question::Approval(request)),
            UiEvent::Elicitation { prompt, responder } => match &prompt.kind {
                ElicitationKind::Form { .. } => {
                    self.reply(format!(
                        "{}: {} (declined: the append renderer cannot show a form)",
                        one_line(&prompt.server_name, 64),
                        one_line(&prompt.message, 120)
                    ));
                    if responder.send(ElicitationResponse::Decline).is_err() {
                        tracing::trace!("the turn that asked has already moved on");
                    }
                }
                ElicitationKind::Url { .. } => {
                    self.ask(screen::Question::Elicitation { prompt, responder });
                }
            },
            UiEvent::ShellFinished { .. } => {}
            UiEvent::Item(item) => self.print_item(item),
            UiEvent::Done => {
                self.busy = false;
                self.activity = view::Activity::Working;
                self.flush_pending();
                if self.wake_pending {
                    self.wake_pending = false;
                    self.send_host(HostEvent::Wake);
                } else if let Some(text) = self.followups.pop_front() {
                    self.send_host(HostEvent::UserInput {
                        text,
                        images: Vec::new(),
                    });
                    self.busy = true;
                }
            }
            UiEvent::Wake => {
                if self.busy {
                    self.wake_pending = true;
                } else {
                    self.send_host(HostEvent::Wake);
                }
            }
            UiEvent::Leave => self.leaving = true,
            UiEvent::Reload => {}
            UiEvent::Reloaded { .. } | UiEvent::HistoryPage { .. } => {}
            UiEvent::McpServers(servers) => {
                let rows: Vec<String> = servers
                    .iter()
                    .map(|server| format!("{}: {}", server.name, server.state))
                    .collect();
                if rows.is_empty() {
                    self.reply("No MCP servers.");
                    return;
                }
                self.reply(rows.join("\n"));
            }
            UiEvent::Panel(text) => self.reply(text),
        }
    }

    /// A key, as the composer or the open question reads it.
    async fn handle_key(&mut self, key: KeyEvent) {
        if key.kind == KeyEventKind::Release {
            return;
        }
        let control = key.modifiers.contains(KeyModifiers::CONTROL);
        if self.open.is_some() {
            self.handle_question_key(key, control).await;
            self.dirty = true;
            return;
        }
        // A line break typed by hand, where a paste brings its own: Alt+Enter, Shift+Enter where
        // the terminal speaks the keyboard protocol, and Ctrl+J, which a raw terminal tells from
        // Enter.
        if matches!(key.code, KeyCode::Enter)
            && key
                .modifiers
                .intersects(KeyModifiers::ALT | KeyModifiers::SHIFT)
            || control && matches!(key.code, KeyCode::Char('j'))
        {
            self.editor.insert('\n');
            self.dirty = true;
            return;
        }
        let alt = key.modifiers.contains(KeyModifiers::ALT);
        match key.code {
            KeyCode::Char('c') if control => self.interrupt().await,
            KeyCode::Char('d') if control && self.editor.is_empty() && !self.busy => self.leave(),
            // Shift+Tab walks the permission level, as it does on the screen. A terminal on the
            // keyboard protocol reports it as Tab with Shift.
            KeyCode::BackTab => self.cycle_permission(),
            KeyCode::Tab if key.modifiers.contains(KeyModifiers::SHIFT) => self.cycle_permission(),
            // Tab completes the word under the cursor as the screen's composer does.
            KeyCode::Tab if !control && !alt => self.complete_line(),
            KeyCode::Up => self.history_previous(),
            KeyCode::Char('p') if control => self.history_previous(),
            KeyCode::Down => self.editor.next(),
            KeyCode::Char('n') if control => self.editor.next(),
            KeyCode::Enter if !control && !alt => self.submit().await,
            // Backspace on an empty line takes the last image back, as the screen's does.
            KeyCode::Backspace
                if !control && !alt && self.editor.is_empty() && !self.attachments.is_empty() =>
            {
                self.attachments.pop();
            }
            KeyCode::Char(ch) if !control && !alt => self.editor.insert(ch),
            _ => {
                self.editor.readline(&key);
            }
        }
        self.dirty = true;
    }

    /// Tab: a single match fills in the word, with a space when a value follows; several share a
    /// prefix, which is filled in; otherwise the matches are listed in the scrollback.
    fn complete_line(&mut self) {
        let line = self.editor.text().to_string();
        if line.starts_with("/skill") {
            let names: Vec<String> =
                crate::skills::discover_skills_in_roots(&self.launch.skill_roots)
                    .skills
                    .iter()
                    .map(|skill| skill.name.clone())
                    .collect();
            *crate::sync::write(&self.launch.completer.skill_names) = names;
        }
        let pos = self.editor.cursor();
        let rows = self.launch.completer.suggestions(&line, pos);
        let Some(first) = rows.first() else {
            return;
        };
        let (start, end) = (first.start, first.end);
        if let [only] = rows.as_slice() {
            let mut value = only.value.clone();
            if only.append_whitespace && !line.get(end..).unwrap_or("").starts_with(' ') {
                value.push(' ');
            }
            self.editor.replace_range(start..end, &value);
            return;
        }
        let typed = line.get(start..end).unwrap_or("");
        let shared = common_prefix(rows.iter().map(|row| row.value.as_str()));
        if shared.len() > typed.len() {
            self.editor.replace_range(start..end, &shared);
            return;
        }
        let listing: Vec<String> = rows
            .iter()
            .map(|row| match &row.description {
                Some(description) => format!("{}  {description}", row.value),
                None => row.value.clone(),
            })
            .collect();
        self.reply(listing.join("\n"));
    }

    fn history_previous(&mut self) {
        let entries = std::mem::take(&mut self.history_entries);
        self.editor.previous(&entries);
        self.history_entries = entries;
    }

    /// The next permission level the run allows, as Shift+Tab on the screen takes it. The status
    /// row under the composer shows the level, so no row is printed for it.
    fn cycle_permission(&mut self) {
        let level = self.launch.shared_permission.cycle();
        tracing::debug!("permission cycled to {level}");
        // Recorded on the row, not just in this process's cell, as the screen does.
        self.send_host(HostEvent::PermissionChanged(level));
        if level == crate::permission::Permission::Read {
            crate::sandbox::warn_if_sandbox_issues(
                &self.launch.sandbox_state,
                crate::sandbox::WarnContext::ReadModeEntry,
            );
        }
    }

    /// A paste: text for the composer with its line breaks kept, or for the open question's answer
    /// line, which reads one line, with them as spaces. Nothing is sent until Enter.
    fn handle_paste(&mut self, pasted: &str) {
        match &mut self.open {
            // The grace a key gets none in applies to a paste: it was typed ahead of the question.
            Some((_, answer, opened)) => {
                if opened.elapsed() >= QUESTION_GRACE {
                    answer.insert_paste(pasted, false);
                }
            }
            // A paste that is one path to an image file attaches the file, which is how a drag
            // from a file manager arrives; anything else is text for the line.
            None => match screen::pasted_image_path(pasted) {
                Some(path) => self.attach_image_file(&path),
                None => self.editor.insert_paste(pasted, true),
            },
        }
        self.dirty = true;
    }

    fn attach_image_file(&mut self, path: &std::path::Path) {
        let label = path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| path.display().to_string());
        match std::fs::read(path) {
            Ok(bytes) => self.attach_image(&bytes, label),
            Err(error) => self.reply(format!("Cannot read '{}': {error}", path.display())),
        }
    }

    /// A question's answer line reads one line; Esc withdraws, Ctrl+C takes the interruption
    /// ladder. A question takes no answer the moment it opens, or a key already on its way to the
    /// composer would land on it.
    async fn handle_question_key(&mut self, key: KeyEvent, control: bool) {
        let Some((question, mut answer, opened)) = self.open.take() else {
            return;
        };
        if control && matches!(key.code, KeyCode::Char('c')) {
            self.open = Some((question, answer, opened));
            self.interrupt().await;
            return;
        }
        if key.code == KeyCode::Esc {
            question.withdraw();
            self.reply(screen::QUESTION_WITHDRAWN_HINT);
            self.dirty = true;
            return;
        }
        if opened.elapsed() < QUESTION_GRACE {
            self.open = Some((question, answer, opened));
            return;
        }
        match key.code {
            KeyCode::Enter => {
                self.open = Some((question, answer, opened));
                self.answer_open();
                return;
            }
            KeyCode::Char(ch) if !control && !key.modifiers.contains(KeyModifiers::ALT) => {
                answer.insert(ch);
            }
            _ => {
                answer.readline(&key);
            }
        }
        self.open = Some((question, answer, opened));
    }

    /// What every tick is for: the log written off-prompt, questions whose turn has moved on, the
    /// work running beside the turn, and the rows the cursor sits on.
    async fn tick(&mut self) {
        self.drain_logs();
        self.withdraw_stopped_questions();
        self.open_question();
        self.tick_working();
        self.poll_work().await;
        self.refresh();
    }

    /// Log lines the user's own filter shows are printed beside whatever the conversation is
    /// printing, one row each, without disturbing it. Every line goes into the ring whether it is
    /// printed or not: the relay hands over what a wider filter passed so `/log` has the lines a
    /// `-v` would have shown, and printing them all would put debug chatter between the rows of a
    /// run that asked for warnings.
    fn drain_logs(&mut self) {
        let width = self.width;
        let mut rows = Vec::new();
        while let Some(line) = self.launch.logs.try_recv() {
            if line.shown {
                let entry = Entry {
                    id: 0,
                    item: log_item(line.clone()),
                    expanded: false,
                    revision: 0,
                };
                rows.extend(render::tui::lines_to_ansi(&view::entry_lines(
                    &entry, width,
                )));
            }
            self.log_ring.push_back(line);
            while self.log_ring.len() > LOG_RING_LINES {
                self.log_ring.pop_front();
            }
        }
        if !rows.is_empty() {
            self.console.log(&rows);
            self.dirty = true;
        }
    }
}

/// Read keys and host events until the user leaves, printing rows as they come.
pub(crate) async fn run_append(launch: AppendLaunch) -> anyhow::Result<()> {
    let raw = RawMode::enter()?;
    let mut state = AppendState::new(launch);
    state.open().await;
    state.refresh();
    let mut events = EventStream::new();
    let mut tick = tokio::time::interval(TICK);
    while !state.leaving {
        tokio::select! {
            event = events.next() => match event {
                Some(Ok(Event::Key(key))) => state.handle_key(key).await,
                Some(Ok(Event::Paste(text))) => state.handle_paste(&text),
                Some(Ok(Event::Resize(columns, _))) => state.resize(columns),
                Some(Ok(_)) => {}
                Some(Err(error)) => {
                    tracing::warn!("failed to read the terminal: {error}");
                    state.hang_up();
                }
                None => state.hang_up(),
            },
            event = state.launch.ui_receiver.recv() => match event {
                Some(event) => state.handle_ui(event),
                None => state.leaving = true,
            },
            _ = tick.tick() => state.tick().await,
        }
        state.refresh();
    }
    state.console.finish();
    drop(raw);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typing_edits_the_line_where_the_cursor_is() {
        let mut editor = LineEditor::default();
        editor.insert('h');
        editor.insert('i');
        assert_eq!(editor.text(), "hi");
        assert_eq!(editor.cursor(), 2);
        editor.left();
        editor.insert('a');
        assert_eq!(editor.text(), "hai", "the cursor is between the letters");
        editor.backspace();
        assert_eq!(editor.text(), "hi");
        editor.home();
        editor.delete();
        assert_eq!(editor.text(), "i");
        editor.end();
        editor.kill_to_start();
        assert!(editor.is_empty());
    }

    #[test]
    fn a_paste_keeps_its_line_breaks_in_the_composer_and_flattens_them_in_an_answer() {
        let mut editor = LineEditor::default();
        editor.insert('>');
        editor.insert_paste("one\r\ntwo\rthree\x1b\tx", true);
        assert_eq!(editor.text(), ">one\ntwo\nthree x");
        assert_eq!(editor.cursor(), editor.text().len());
        let mut answer = LineEditor::default();
        answer.insert_paste("a\nb", false);
        assert_eq!(answer.text(), "a b");
    }

    #[test]
    fn ctrl_k_and_ctrl_u_cut_to_the_end_and_to_the_start() {
        let mut editor = LineEditor::default();
        for ch in "one two three".chars() {
            editor.insert(ch);
        }
        editor.cursor = 8;
        editor.kill_to_end();
        assert_eq!(editor.text(), "one two ");
        editor.kill_word_back();
        assert_eq!(editor.text(), "one ");
    }

    #[test]
    fn tab_fills_in_what_the_matches_share() {
        assert_eq!(common_prefix(["/permission", "/profile"].into_iter()), "/p");
        assert_eq!(common_prefix(["/mcp list"].into_iter()), "/mcp list");
        assert_eq!(common_prefix(std::iter::empty()), "");
        assert_eq!(common_prefix(["héllo", "hélp"].into_iter()), "hél");
    }

    #[test]
    fn replacing_a_word_is_one_undo_step() {
        let mut editor = typed("/per");
        editor.replace_range(0..4, "/permission ");
        assert_eq!(editor.text(), "/permission ");
        assert_eq!(editor.cursor(), "/permission ".len());
        editor.undo();
        assert_eq!(editor.text(), "/per");
    }

    fn press(editor: &mut LineEditor, code: KeyCode, modifiers: KeyModifiers) -> bool {
        editor.readline(&KeyEvent::new(code, modifiers))
    }

    fn typed(text: &str) -> LineEditor {
        let mut editor = LineEditor::default();
        for ch in text.chars() {
            editor.insert(ch);
        }
        editor
    }

    #[test]
    fn the_readline_keys_move_by_character_and_by_word() {
        let ctrl = KeyModifiers::CONTROL;
        let alt = KeyModifiers::ALT;
        let mut editor = typed("one two/three");
        press(&mut editor, KeyCode::Char('b'), alt);
        assert_eq!(&editor.text()[editor.cursor()..], "three");
        press(&mut editor, KeyCode::Char('b'), alt);
        assert_eq!(&editor.text()[editor.cursor()..], "/three");
        press(&mut editor, KeyCode::Left, ctrl);
        assert_eq!(&editor.text()[editor.cursor()..], "two/three");
        press(&mut editor, KeyCode::Char('f'), alt);
        assert_eq!(&editor.text()[editor.cursor()..], "/three");
        press(&mut editor, KeyCode::Char('b'), ctrl);
        assert_eq!(&editor.text()[editor.cursor()..], "o/three");
        press(&mut editor, KeyCode::Char('f'), ctrl);
        assert_eq!(&editor.text()[editor.cursor()..], "/three");
        press(&mut editor, KeyCode::Char('a'), ctrl);
        assert_eq!(editor.cursor(), 0);
        press(&mut editor, KeyCode::Char('e'), ctrl);
        assert_eq!(editor.cursor(), editor.text().len());
        assert!(!press(&mut editor, KeyCode::Char('x'), KeyModifiers::NONE));
    }

    #[test]
    fn the_readline_keys_cut_yank_and_undo() {
        let ctrl = KeyModifiers::CONTROL;
        let alt = KeyModifiers::ALT;
        let mut editor = typed("one two three");
        press(&mut editor, KeyCode::Char('w'), ctrl);
        assert_eq!(editor.text(), "one two ");
        press(&mut editor, KeyCode::Char('y'), ctrl);
        assert_eq!(editor.text(), "one two three");
        press(&mut editor, KeyCode::Char('_'), ctrl);
        assert_eq!(editor.text(), "one two ");
        press(&mut editor, KeyCode::Char('z'), ctrl);
        assert_eq!(
            editor.text(),
            "one two three",
            "undo takes the typing back whole"
        );
        editor.cursor = 4;
        press(&mut editor, KeyCode::Char('d'), alt);
        assert_eq!(editor.text(), "one  three");
        press(&mut editor, KeyCode::Backspace, alt);
        assert_eq!(editor.text(), " three");
        press(&mut editor, KeyCode::Char('h'), ctrl);
        assert_eq!(editor.text(), " three");
        editor.cursor = 1;
        press(&mut editor, KeyCode::Char('h'), ctrl);
        assert_eq!(editor.text(), "three");
    }

    #[test]
    fn a_word_motion_crosses_punctuation_when_no_word_is_in_reach() {
        let mut editor = typed("dir/");
        editor.kill_word_back();
        assert_eq!(editor.text(), "dir");
        editor.kill_word_back();
        assert_eq!(editor.text(), "");
    }

    #[test]
    fn up_and_down_walk_the_history_and_end_on_the_draft() {
        let entries = vec!["first".to_string(), "second".to_string()];
        let mut editor = LineEditor::default();
        editor.insert('x');
        editor.previous(&entries);
        assert_eq!(editor.text(), "second");
        editor.previous(&entries);
        assert_eq!(editor.text(), "first");
        editor.previous(&entries);
        assert_eq!(editor.text(), "first", "the walk stops at the oldest");
        editor.next();
        assert_eq!(editor.text(), "second");
        editor.next();
        assert_eq!(editor.text(), "x", "the draft comes back");
    }

    #[test]
    fn a_line_longer_than_the_row_keeps_the_cursor_in_view() {
        let text = "abcdefghij";
        let (shown, column) = fit_input(2, text, 10, 6);
        assert_eq!(
            shown, "hij",
            "the tail is what fits, with the cursor's column kept"
        );
        assert_eq!(column, 3);
        let (shown, column) = fit_input(2, text, 0, 6);
        assert_eq!(column, 0, "the cursor at the start is at the start");
        assert!(shown.starts_with('a'), "{shown}");
        let (whole, column) = fit_input(2, text, 5, 20);
        assert_eq!(whole, text);
        assert_eq!(column, 5);
    }

    #[test]
    fn each_line_of_the_composer_takes_a_row_and_the_cursor_is_on_its_own() {
        let text = "one\ntwo\nthree";
        let (lines, row, at) = composer_lines(text, text.len(), 8);
        assert_eq!(lines, vec!["one", "two", "three"]);
        assert_eq!((row, at), (2, 5), "the cursor ends on the last line");
        let (lines, row, at) = composer_lines(text, 5, 8);
        assert_eq!(lines.len(), 3, "the rows do not change with the cursor");
        assert_eq!((row, at), (1, 1), "the cursor after `t` in the second line");
        let (lines, row, at) = composer_lines("", 0, 8);
        assert_eq!(
            (lines, row, at),
            (vec![""], 0, 0),
            "an empty composer is one row"
        );
    }

    #[test]
    fn a_composer_taller_than_the_screen_shows_the_lines_around_its_cursor() {
        let text = "a\nb\nc\nd\ne";
        let (lines, row, _) = composer_lines(text, text.len(), 3);
        assert_eq!(
            lines,
            vec!["c", "d", "e"],
            "the window ends on the cursor's line"
        );
        assert_eq!(row, 2);
        let (lines, row, _) = composer_lines(text, 0, 3);
        assert_eq!(
            lines,
            vec!["a", "b", "c"],
            "the top of the text is shown from the top"
        );
        assert_eq!(row, 0);
        let (lines, row, _) = composer_lines(text, 6, 3);
        assert_eq!(lines, vec!["b", "c", "d"]);
        assert_eq!(row, 2, "the cursor on `d` is on the window's last row");
    }

    #[test]
    fn an_answer_takes_the_keys_and_the_words_behind_them() {
        assert_eq!(approval_answer("y"), Some(ApprovalDecision::Allow));
        assert_eq!(
            approval_answer("ALWAYS"),
            Some(ApprovalDecision::AllowAlways)
        );
        assert_eq!(
            approval_answer("deny for the session"),
            Some(ApprovalDecision::DenyAlways)
        );
        assert_eq!(approval_answer("sure"), None);
        assert_eq!(url_answer("open"), Some(UrlAnswer::Open));
        assert_eq!(url_answer("s"), Some(UrlAnswer::Skip));
        assert_eq!(url_answer("later"), None);
    }

    #[test]
    fn the_choices_line_is_the_screens_own_vocabulary() {
        assert_eq!(
            approval_choices(),
            "Allow (y) / Allow for the session (a) / Deny (n) / Deny for the session"
        );
        assert_eq!(
            url_choices(),
            "Open in the browser (y) / Skip (s) / Decline (n)"
        );
    }
}
