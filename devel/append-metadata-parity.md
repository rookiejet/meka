# Append renderer: metadata parity with the screen

Design draft, 2026-10-20. Scope: what the default (screen) renderer displays that the append
renderer (`--renderer append` / `[display].renderer = "append"`) does not, and how to close the
gap without breaking the append renderer's one rule — every transcript row prints once and is
never touched again.

## Review: what each renderer displays

The screen's metadata surfaces are the status row under the composer, the transcript rows, and
the on-demand `/status` body. The append renderer shares the transcript vocabulary
(`view::entry_lines`) and answers `/status` through the same host code, so the gap is exactly the
ambient surface.

| Fact | Screen | Append today |
|---|---|---|
| Permission level (`none`/`read`/`workspace`/`unrestricted`) | status row, **always**: colored gutter cell + name | nowhere ambient; `/permission` query, a note on change, `/status` |
| Working directory (`path`) | status row, `[display].status_row` | `/status`; a note on `/cd` |
| Profile name | status row | `/profile`; `/status` |
| Model name | status row | `/status` |
| Context gauge (`128.4k/1.0M 13%`) | status row, `context` | `/status` |
| Background tasks running | status row, `tasks`, while any | `/task list` |
| Sub-agents running | status row, `subagents`, while any | nothing live (activity folds into the call's row) |
| Hints (`copied 3 rows`, `the question was withdrawn`) | status row, right edge | printed as rows where they apply |
| Shell-mode label (red, replaces the row) | status row | n/a — append refuses `!command` |
| MCP tool progress (`server/tool 3/10 message`) | a live line per update | **dropped** (`McpProgress` is ignored) |
| Inbox delivered marks | prompts re-marked in place | impossible write-once (documented) |
| Session id lines, turn-end summary, thinking, tool calls, approvals, questions, checklist, notices | rows/panels | rows — parity |
| Token usage, compaction markers, nudges, withdrawn prompts | ignored by design | ignored — parity |

So "feature parity in metadata displayed" is one surface (the status row facts, permission level
first) plus one event (`McpProgress`), and one doc bug: the config page's `display.renderer`
section claims `display.status_row` "still applies to the rows it prints" while the usage page
correctly says "the status row facts under the composer do not print here". Only one of those can
stay true; this design makes the config page's claim true.

## Design: a two-row composer

The screen puts its status row directly under the composer, and the append renderer already
redraws exactly one row — the line being typed. Extend that redraw to the same two rows the
screen owns: the input row and, under it, the screen's status row. Both are transient (erased and
rewritten in place); the transcript above them stays write-once. The `>` marker of a sent line is
untouched, and no status information ever becomes a transcript row, so nothing in the scrollback
churns.

### 1. Reuse the screen's vocabulary verbatim

`view::status_line(&StatusFacts, width)` already renders the row: the permission level's colored
gutter cell and name, then whichever `[display].status_row` facts are set (`path`, `profile`,
`model`, `context`, `tasks`, `subagents`) in the configured order, then the hint at the right edge.
`render::tui::lines_to_ansi` is the append printer's ratatui-to-ANSI path already. So the append
renderer gains no rendering code of its own, and `display.status_row` means one thing in both
renderers.

`StatusFacts` fields for append: `hint: None` (the screen's hints are panel events; append prints
its equivalents as rows) and `shell_mode: false` always. Everything else is filled exactly as
`screen.rs` does at draw time.

### 2. Console: a transient block of N rows

`Console::transient` today draws one row and withholds its newline (`Action::OpenTransient` /
`EraseTransient`, `RowState`). Widen it to draw a block of rows and leave the cursor on the row
the caller names (the input row): erase both rows, rewrite both, restore the cursor. The
drawn/not-drawn contract (`bool`, "whether anything reached the terminal") is kept per row — the
bottom-of-scrollback guard the input row already carries applies to the block.

Placement mirrors the screen: input row, status row under it. The one mechanics cost is that the
cursor ends on the input row rather than after the last write. If the terminal-edge cases bite
(cursor restore after a scroll), the status row can go above the input row instead; the metadata
parity is the same, only the layout differs, and the screen's layout is the better default.

### 3. Plumb the facts (all already in scope at the launch site)

`host/tui.rs` builds `AppendLaunch` and `ScreenLaunch` side by side; everything the status row
reads is in scope there:

| Fact | Source (as the screen reads it) | Append change |
|---|---|---|
| `shown` | `config.status_row` (`ScreenLaunch::status_row`) | carry it in `AppendLaunch` (or fold into `model::Settings` beside `turn_end_summary`) |
| `permission` | `shared_permission.get()` | already present |
| `path` | `shorten_path_with_tilde(&cwd.get())` | already present |
| `profile` | `current_profile` when non-empty | already present |
| `model` | `configured_profiles` lookup by current profile | carry `config.profile_summaries` |
| `context` | the shared atomics pair, built only when the list asks for `Context` (`context_indicator`) | carry it — the run builds it before either launch |
| `work` | running background tasks (`store`, excluding `agent_spawn`) + `running_subagents.running_ids().len()` | carry `shared.running_subagents`; count tasks on the tick (or reuse the `/task` query), on a slower cadence than every 100 ms |

`AppendState::refresh()` builds the `StatusFacts` and draws the block through the widened
`transient`, alongside the redraw it already does on its 100 ms tick and on every keystroke.

### 4. The permission level specifically

The ask this design exists for: with the row in place, `workspace` (or whatever level the run is
at) is on screen at all times, in the screen's color coding, and `/permission <level>` changes it
where it shows. The existing change note (`Permission level set to: …`) stays — a row records the
moment the level changed, the row under the composer records the level now. That is also the
screen's behavior.

### 5. `McpProgress`

Fold each update into the tool call it belongs to, in the field the screen folds it into —
`Item::ToolCall`'s own `progress`, which `view::tool_body` already draws as rows under the call.
A write-once renderer cannot show a progress bar; the update replaces the last one while the call
runs, and the settled call row carries the last progress line, which is the fact worth keeping.

### 6. What deliberately stays out

- No status facts as transcript rows, on any cadence. The context gauge moves every turn; rows
  for it would be exactly the noise append mode exists to avoid.
- The input-row lead (`> `) stays `> `: it is the transcript's own marker for what the person
  sent, and a `workspace > ` lead would break that reading (it also steals input width on an
  80-column terminal, where the two-row composer costs none).
- `InboxDelivered` marks stay impossible; the rows carry `delivered: false` forever. If the gap
  ever matters, a one-line note on delivery, not an in-place mark.
- Hints stay rows; `hint: None` on the status row.

### 7. Docs and tests

- `config-file.md`'s `display.renderer` section: the `display.status_row` claim becomes true;
  add the same "redrawn under the composer, like the input line" caveat the no-redraws sentence
  needs.
- `interactive-mode.md`'s append section: replace "The status row facts under the composer do not
  print here" with the two-row composer description.
- `tests/append_pty.rs`: one PTY test — the level shows under the composer and follows
  `/permission unrestricted` in the same run; one — the context gauge appears when the profile's
  window is known. The existing tests keep passing (the composer area now writes two rows; the
  assertions read printed blocks, not the transient area).
- `view::status_line`'s unit tests cover the row itself already; no new render tests are needed
  unless the N-row `transient` gets its own console tests (it should: the erase/rewrite contract
  is the delicate part).

### Phasing

1. Console: N-row transient + its tests (mechanics only, no behavior change).
2. Plumb the four fields into `AppendLaunch`, build `StatusFacts` in `refresh()`, draw the block.
   This is the parity commit: level, path, profile, model, context, work counts all land at once.
3. `McpProgress` into `call.activity`; doc fixes; PTY tests.

Steps 1 and 2 are one PR's worth; 3 is follow-up.
