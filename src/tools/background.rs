//! The `task_*` tools: the agent watching and stopping its own background work
//! ([`crate::background`]).
//!
//! Both gate at [`Permission::Read`]. Neither runs anything: listing reads Meka's own store, and
//! canceling only signals a token belonging to work whose permission was already checked when it
//! was dispatched. Requiring `unrestricted` to stop something the agent itself started would leave
//! it unable to clean up after a call it had every right to make.
//!
//! Sub-agents deliberately get neither, for the same reason they get no `schedule_*`: a sub-agent's
//! session ends with the single turn that spawned it, so it can neither start a task that outlives
//! that turn nor be around to hear about one.

use std::sync::Arc;

use async_trait::async_trait;

use super::{
    Tool, ToolOutput,
    util::{require_str, resolve_session_id},
};
use crate::{
    background::{BackgroundTasks, StopReport, TASK_INDEX_TOOL},
    error::Result,
    permission::Permission,
    provider::ToolDefinition,
    store::{Store, background::StopReason},
};

/// How much of a finished task's output `task_list` shows. Enough to recognize what happened, not
/// enough to make listing tasks a way to re-read every result.
const OUTCOME_EXCERPT_CHARS: usize = 200;

/// Ceiling on the rendered label. `format_columns` widens a column to its longest cell, so an
/// unbounded command line would push everything after it far off to the right.
const LABEL_EXCERPT_CHARS: usize = 48;

struct TaskContext {
    store: Store,
    site: crate::session::ToolSite,
    tasks: BackgroundTasks,
}

pub(super) struct TaskListTool {
    context: TaskContext,
}

#[async_trait]
impl Tool for TaskListTool {
    fn definition(&self) -> ToolDefinition {
        ToolDefinition {
            name: TASK_INDEX_TOOL.to_string(),
            description: "List this session's background tasks: what is still running, and what \
                has already reported. Your per-turn context carries a short index of the running \
                ones, so reach for this when you want the full picture including finished tasks."
                .to_string(),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {}
            }),
            ..Default::default()
        }
    }

    fn required_permission(&self) -> Permission {
        Permission::Read
    }

    async fn execute(
        &self,
        _input: serde_json::Value,
        _context: crate::tools::ToolContext,
    ) -> Result<ToolOutput> {
        let session_id = resolve_session_id(&self.context.site.session_id, TASK_INDEX_TOOL)?;
        let tasks = self
            .context
            .store
            .background_store()
            .list_background_tasks(session_id)
            .await?;
        if tasks.is_empty() {
            return Ok(ToolOutput::text(
                "No background tasks in this session.".to_string(),
                false,
            ));
        }

        // The same column layout every other listing in Meka uses (`scratchpad_list`, `meka session
        // list`, `meka mcp list`), so a reader who has seen one has seen them all.
        let rows: Vec<Vec<String>> = tasks
            .iter()
            .map(|task| {
                vec![
                    task.short_id().to_string(),
                    task.status.name().to_string(),
                    task.tool.clone(),
                    // The sub-agent a task drives, by the prefix `agent_steer` takes.
                    task.subagent_id.map_or_else(
                        || "-".to_string(),
                        |subagent| {
                            subagent
                                .to_string()
                                .get(..crate::text::ID_PREFIX)
                                .unwrap_or_default()
                                .to_string()
                        },
                    ),
                    crate::background::excerpt(&task.label, LABEL_EXCERPT_CHARS),
                    humantime_serde::re::humantime::format_duration(
                        std::time::Duration::from_secs(task.elapsed().num_seconds().max(0) as u64),
                    )
                    .to_string(),
                    // An excerpt for anything already finished. Outcomes are delivered as their
                    // own turn, but that delivery is stamped before the turn runs, so a turn that
                    // fails (a provider error, an interrupt) consumes the report. Without this the
                    // result would be reachable only by reading the database by hand, which for
                    // the agent means not at all.
                    match (&task.outcome, &task.scratchpad_entry) {
                        (_, Some(name)) => format!("in scratchpad entry '{name}'"),
                        (Some(outcome), None) if task.status.is_terminal() => {
                            crate::background::excerpt(outcome, OUTCOME_EXCERPT_CHARS)
                        }
                        _ => "-".to_string(),
                    },
                ]
            })
            .collect();

        let mut rendered = crate::text::format_columns(
            &[
                "ID",
                "Status",
                "Tool",
                "Sub-agent",
                "What",
                "Elapsed",
                "Result",
            ],
            &rows,
        );
        rendered.push_str(
            "\nA finished task's full result is delivered to you on its own; this listing is for \
             checking what is still running.",
        );
        Ok(ToolOutput::text(rendered, false))
    }
}

pub(super) struct TaskCancelTool {
    context: TaskContext,
}

#[async_trait]
impl Tool for TaskCancelTool {
    fn definition(&self) -> ToolDefinition {
        ToolDefinition {
            name: "task_cancel".to_string(),
            description:
                "Stop a running background task by id (the short form from `task_list` is \
                enough), or every one of them with all=true. A canceled task still reports back, \
                so you will be told when it has actually stopped."
                    .to_string(),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "id": {
                        "type": "string",
                        "description": "Task id, in full or the short prefix `task_list` shows.",
                    },
                    "all": {
                        "type": "boolean",
                        "default": false,
                        "description": "Cancel every running task in this session instead of one by id. Default: false.",
                    }
                }
            }),
            ..Default::default()
        }
    }

    fn required_permission(&self) -> Permission {
        Permission::Read
    }

    async fn execute(
        &self,
        input: serde_json::Value,
        _context: crate::tools::ToolContext,
    ) -> Result<ToolOutput> {
        let session_id = resolve_session_id(&self.context.site.session_id, "task_cancel")?;

        if super::util::optional_bool(&input, "all", "task_cancel")?.unwrap_or(false) {
            // One stop path for the whole session: each task's live owner is claimed and signaled
            // before the request is recorded, and rows already `stopping` are included so their
            // owners are signaled again rather than told a prior request succeeded.
            let store = self.context.store.background_store();
            let reports = self
                .context
                .tasks
                .request_stop_session(&store, session_id, StopReason::AgentRequest)
                .await?;
            let mut asked = 0;
            let mut unconfirmed = 0;
            for (_, report) in &reports {
                match report {
                    StopReport::AlreadyEnded => {}
                    StopReport::Signaled { .. } => asked += 1,
                    StopReport::NotSignaled { .. } => unconfirmed += 1,
                }
            }
            if asked == 0 && unconfirmed == 0 {
                return Ok(ToolOutput::text(
                    "No running background tasks to cancel.".to_string(),
                    false,
                ));
            }
            let mut text = format!(
                "Asked {asked} background task(s) to stop. Each will report back once it has."
            );
            if unconfirmed > 0 {
                text.push_str(&format!(
                    " {unconfirmed} more had no live runner in this process: their stops are \
                     recorded, but nothing signaled them and nothing here can confirm how they \
                     ended. Their rows stay open until their work reports or a reopen reconciles \
                     them."
                ));
            }
            return Ok(ToolOutput::text(text, false));
        }

        let id_prefix = require_str(&input, "id", "task_cancel")?;
        let Some(task) = self
            .context
            .store
            .background_store()
            .resolve_background_task(session_id, &id_prefix)
            .await?
        else {
            return Ok(ToolOutput::text(
                format!(
                    "Error: no background task in this session matches '{id_prefix}'. Call `task_list` for \
                     the current ids."
                ),
                true,
            ));
        };

        if task.status.is_terminal() {
            return Ok(ToolOutput::text(
                format!(
                    "Task {} already {} and is not running.",
                    task.short_id(),
                    task.status.name()
                ),
                false,
            ));
        }
        // An open `stopping` row is deliberately stopped again: its record is not proof the signal
        // ever reached its owner, and a repeat request that reports success from that state is
        // exactly the lie this path exists not to tell.
        let store = self.context.store.background_store();
        let report = self
            .context
            .tasks
            .request_stop(&store, session_id, &task.id, StopReason::AgentRequest)
            .await?;
        Ok(ToolOutput::text(
            match report {
                StopReport::AlreadyEnded => {
                    format!(
                        "Task {} already finished and is not running.",
                        task.short_id()
                    )
                }
                StopReport::Signaled { repeated: true, .. } => format!(
                    "Asked task {} ({}) to stop again; its signal has been re-sent. It will \
                     report back once it has.",
                    task.short_id(),
                    task.label
                ),
                StopReport::Signaled { .. } => format!(
                    "Asked task {} ({}) to stop. It will report back once it has.",
                    task.short_id(),
                    task.label
                ),
                StopReport::NotSignaled { recorded: true, .. } => format!(
                    "Task {} ({}) is recorded as stopping, but no live runner for it is held in \
                     this process: nothing signaled it, and its teardown cannot be confirmed \
                     here. Its row stays open until its work reports or a reopen reconciles it.",
                    task.short_id(),
                    task.label
                ),
                StopReport::NotSignaled {
                    recorded: false, ..
                } => format!(
                    "Task {} ({}) could not be stopped here: no live runner holds it and the \
                     stop could not be recorded. Its row will be reconciled when the session is \
                     reopened.",
                    task.short_id(),
                    task.label
                ),
            },
            false,
        ))
    }
}

pub(super) fn build(
    store: Store,
    site: crate::session::ToolSite,
    tasks: BackgroundTasks,
) -> Vec<Arc<dyn Tool>> {
    vec![
        Arc::new(TaskListTool {
            context: TaskContext {
                store: store.clone(),
                tasks: tasks.clone(),
                site: site.clone(),
            },
        }),
        Arc::new(TaskCancelTool {
            context: TaskContext { store, tasks, site },
        }),
    ]
}

#[cfg(test)]
mod tests {
    use tokio_util::sync::CancellationToken;
    use uuid::Uuid;

    use super::*;
    use crate::store::background::{BackgroundTask, TaskStatus};

    async fn context() -> (TaskContext, Uuid) {
        let store = Store::for_test().await;
        let session_id = store
            .create_session(None, "test-profile".to_string())
            .await
            .expect("create session");
        (
            TaskContext {
                store,
                tasks: BackgroundTasks::default(),
                site: crate::session::ToolSite::for_test()
                    .with_session_id(crate::session::SharedSessionId::new(Some(session_id))),
            },
            session_id,
        )
    }

    async fn seed(context: &TaskContext, session_id: Uuid, label: &str) -> BackgroundTask {
        let task = BackgroundTask {
            id: Uuid::new_v4().to_string(),
            session_id,
            tool: "shell_execute".to_string(),
            label: label.to_string(),
            status: TaskStatus::Running,
            outcome: None,
            scratchpad_entry: None,
            started_at: chrono::Utc::now(),
            finished_at: None,
            announced_at: None,
            delivered_at: None,
            subagent_id: None,
        };
        context
            .store
            .background_store()
            .start_background_task(&task)
            .await
            .expect("start task");
        task
    }

    async fn cancel(tool: &TaskCancelTool, input: serde_json::Value) -> ToolOutput {
        tool.execute(
            input,
            crate::tools::ToolContext::for_test(CancellationToken::new()),
        )
        .await
        .expect("ok")
    }

    #[tokio::test]
    async fn task_list_reports_nothing_when_there_is_nothing() {
        let (context, _) = context().await;
        let tool = TaskListTool { context };
        let result = tool
            .execute(
                serde_json::json!({}),
                crate::tools::ToolContext::for_test(CancellationToken::new()),
            )
            .await
            .expect("ok");
        assert!(!result.is_error);
        assert!(result.text_content().contains("No background tasks"));
    }

    #[tokio::test]
    async fn task_list_names_each_task_and_its_state() {
        let (context, session_id) = context().await;
        seed(&context, session_id, "cargo test --all").await;
        let tool = TaskListTool { context };
        let result = tool
            .execute(
                serde_json::json!({}),
                crate::tools::ToolContext::for_test(CancellationToken::new()),
            )
            .await
            .expect("ok");
        let text = result.text_content();
        assert!(text.contains("ID"), "column headers: {text}");
        assert!(text.contains("cargo test --all"), "{text}");
        assert!(text.contains("running"), "{text}");
    }

    /// `[failed] … running for 30s` reads as a contradiction and invites the agent to keep waiting
    /// on work that already stopped.
    #[tokio::test]
    async fn task_list_does_not_say_a_finished_task_is_running() {
        let (context, session_id) = context().await;
        let task = seed(&context, session_id, "make").await;
        context
            .store
            .background_store()
            .finish_background_task(&task.id, TaskStatus::Failed, Some("boom".to_string()), None)
            .await
            .expect("finish");

        let tool = TaskListTool { context };
        let result = tool
            .execute(
                serde_json::json!({}),
                crate::tools::ToolContext::for_test(CancellationToken::new()),
            )
            .await
            .expect("ok");
        let text = result.text_content();
        // Scoped to the task's own row: the trailing note legitimately mentions what is still
        // running, and asserting over the whole output would be testing the footer.
        let row = text
            .lines()
            .find(|line| line.contains(task.short_id()))
            .unwrap_or_else(|| panic!("no row for the task: {text}"));
        assert!(row.contains("failed"), "{row}");
        // The `Status` column is the single place a task's state is stated.
        assert!(!row.contains("running"), "{row}");
    }

    /// A missing in-process handle is not evidence the work ended. A stop that reaches no live
    /// runner records its request and says what that means (nothing was signaled, nothing
    /// confirmed) and leaves the row open, because a terminal outcome claimed here would be a
    /// guess the agent would read as fact.
    #[tokio::test]
    async fn a_stop_with_no_live_runner_records_intent_without_claiming_an_outcome() {
        let (context, session_id) = context().await;
        let task = seed(&context, session_id, "sleep 600").await;
        let store = context.store.clone();
        let tool = TaskCancelTool { context };

        let result = cancel(&tool, serde_json::json!({"id": &task.id[..8]})).await;
        assert!(!result.is_error, "{:?}", result.content);
        assert!(
            result.text_content().contains("no live runner"),
            "{}",
            result.text_content()
        );
        assert!(
            result
                .text_content()
                .contains("teardown cannot be confirmed"),
            "{}",
            result.text_content()
        );

        // The row records the request and nothing more: open, `stopping`, and out of every
        // delivery pool until the work reports or a reopen reconciles it.
        let row = store
            .background_store()
            .background_task_by_id(&task.id)
            .await
            .expect("load")
            .expect("row");
        assert_eq!(row.status, TaskStatus::Stopping);
        assert!(row.finished_at.is_none(), "nothing has ended it");
        assert!(
            store
                .background_store()
                .list_undelivered_background_tasks(session_id)
                .await
                .expect("list")
                .is_empty(),
            "a request is not an outcome, so there is nothing to deliver"
        );
    }

    /// A cancel request is not an outcome: the row has to stay open, out of the delivery pool,
    /// until the work it signaled reports. A terminal row written at request time is the row the
    /// work's own result can no longer correct, which is how a stopped build came to be reported
    /// with the outcome the stop guessed rather than the teardown it got.
    #[tokio::test]
    async fn a_cancel_request_leaves_the_row_open_until_the_work_ends() {
        let (context, session_id) = context().await;
        let task = seed(&context, session_id, "sleep 600").await;
        let store = context.store.clone();
        let tasks = context.tasks.clone();
        let token = CancellationToken::new();
        assert!(
            tasks
                .try_reserve(task.id.clone(), session_id, token.clone(), 10)
                .await
        );
        let tool = TaskCancelTool { context };

        let result = cancel(&tool, serde_json::json!({"id": &task.id[..8]})).await;
        assert!(!result.is_error, "{:?}", result.content);
        assert!(
            result.text_content().contains("will report back"),
            "{}",
            result.text_content()
        );
        assert!(token.is_cancelled(), "the work is told to stop");

        let background = store.background_store();
        let row = background
            .background_task_by_id(&task.id)
            .await
            .expect("load")
            .expect("row");
        assert_eq!(
            row.status,
            TaskStatus::Stopping,
            "the request is recorded, the outcome is not"
        );
        assert!(row.finished_at.is_none(), "nothing has ended it yet");
        assert!(
            background
                .list_undelivered_background_tasks(session_id)
                .await
                .expect("list")
                .is_empty(),
            "a request must not be delivered as if it were the outcome"
        );
        assert_eq!(
            background
                .list_running_background_tasks(session_id)
                .await
                .expect("list")
                .len(),
            1,
            "it is still running, and shown as stopping"
        );

        // The work observes the token, reports its interruption, and that result is the outcome.
        let (status, _reason) = tasks.outcome_end(&task.id, true).await;
        assert_eq!(status, TaskStatus::Canceled);
        background
            .finish_background_task(
                &task.id,
                status,
                Some("Tool execution interrupted.".to_string()),
                None,
            )
            .await
            .expect("finish");

        let delivered = background
            .list_undelivered_background_tasks(session_id)
            .await
            .expect("list");
        assert_eq!(delivered.len(), 1);
        assert_eq!(delivered[0].status, TaskStatus::Canceled);
        let outcome = delivered[0].outcome.as_deref().unwrap_or_default();
        assert!(
            outcome.contains("local teardown is confirmed"),
            "the run's own result is what ended it: {outcome}"
        );
        assert!(
            outcome.contains("Tool execution interrupted."),
            "and what it reported is kept below the note: {outcome}"
        );
    }

    /// Canceling in the window between reserving and spawning is the case the join handle could
    /// not cover: there is nothing to join yet, so a wait that keyed on it returned while the work
    /// the stop had just signaled ran on. The reservation is what the wait observes instead.
    #[tokio::test]
    async fn a_cancel_before_the_work_is_attached_still_ends_the_row() {
        let (context, session_id) = context().await;
        let task = seed(&context, session_id, "sleep 600").await;
        let store = context.store.clone();
        let tasks = context.tasks.clone();
        let token = CancellationToken::new();
        assert!(
            tasks
                .try_reserve(task.id.clone(), session_id, token.clone(), 10)
                .await
        );
        let tool = TaskCancelTool { context };
        cancel(&tool, serde_json::json!({"id": task.id.clone()})).await;
        assert!(token.is_cancelled());

        // The spawn the dispatch wrapper was about to make, and the wait a host would run.
        tasks
            .attach(
                &task.id,
                tokio::spawn({
                    let (tasks, store, id) = (tasks.clone(), store.clone(), task.id.clone());
                    async move {
                        let (status, _reason) = tasks.outcome_end(&id, true).await;
                        store
                            .background_store()
                            .finish_background_task(
                                &id,
                                status,
                                Some("Tool execution interrupted.".to_string()),
                                None,
                            )
                            .await
                            .expect("finish");
                        tasks.forget(&id).await;
                    }
                }),
            )
            .await;
        tasks.wait_all().await;

        let row = store
            .background_store()
            .background_task_by_id(&task.id)
            .await
            .expect("load")
            .expect("row");
        assert_eq!(row.status, TaskStatus::Canceled);
        assert_eq!(tasks.running_count(session_id).await, 0);
    }

    /// A task that has already ended keeps the outcome its work reported: the stop loses the race
    /// in the store, so nothing is signaled and nothing is rewritten.
    #[tokio::test]
    async fn canceling_a_finished_task_keeps_its_outcome() {
        let (context, session_id) = context().await;
        let task = seed(&context, session_id, "cargo test").await;
        let store = context.store.clone();
        let token = CancellationToken::new();
        assert!(
            context
                .tasks
                .try_reserve(task.id.clone(), session_id, token.clone(), 10)
                .await
        );
        store
            .background_store()
            .finish_background_task(
                &task.id,
                TaskStatus::Completed,
                Some("42 passed".to_string()),
                None,
            )
            .await
            .expect("finish");
        let tool = TaskCancelTool { context };

        let result = cancel(&tool, serde_json::json!({"id": task.id.clone()})).await;
        assert!(!result.is_error);
        assert!(
            result.text_content().contains("already completed"),
            "{}",
            result.text_content()
        );
        assert!(!token.is_cancelled(), "a finished task is not signaled");

        let row = store
            .background_store()
            .background_task_by_id(&task.id)
            .await
            .expect("load")
            .expect("row");
        assert_eq!(row.status, TaskStatus::Completed);
        assert_eq!(row.outcome.as_deref(), Some("42 passed"));
    }

    /// A shell task stopped locally may have been routed over SSH or into WSL, and the stop here
    /// cannot tell which, so the delivered outcome must not name a route the run never recorded,
    /// which is exactly how a WSL command came to inherit an SSH caveat. It carries the hedge true
    /// of every route instead; per-route evidence speaks only where the run recorded one.
    #[tokio::test]
    async fn a_cancelled_shell_task_hedges_about_a_route_it_never_recorded() {
        let (context, session_id) = context().await;
        let task = seed(&context, session_id, "ssh build-host make").await;
        let store = context.store.clone();
        let tasks = context.tasks.clone();
        let token = CancellationToken::new();
        assert!(
            tasks
                .try_reserve(task.id.clone(), session_id, token.clone(), 10)
                .await
        );
        let tool = TaskCancelTool { context };
        cancel(&tool, serde_json::json!({"id": task.id.clone()})).await;

        // The work observes the stop and reports; what the run saw of its own teardown is only
        // that its result landed, never that anything it started elsewhere was stopped.
        let (status, reason) = tasks.outcome_end(&task.id, true).await;
        store
            .background_store()
            .finish_background_task_observed(
                &task.id,
                status,
                Some("Tool execution interrupted.".to_string()),
                None,
                crate::store::background::Teardown {
                    started: true,
                    confirmed: false,
                    route: crate::store::background::RouteEvidence::Unrecorded,
                    reason,
                },
            )
            .await
            .expect("finish");

        let delivered = store
            .background_store()
            .list_undelivered_background_tasks(session_id)
            .await
            .expect("list");
        assert_eq!(delivered[0].status, TaskStatus::Canceled);
        let outcome = delivered[0].outcome.as_deref().unwrap_or_default();
        assert!(
            outcome.contains("Stopped at the agent's request"),
            "the reason rides into the outcome: {outcome}"
        );
        assert!(
            outcome.contains("local teardown is unconfirmed"),
            "{outcome}"
        );
        assert!(
            outcome.contains("recorded no route for this call"),
            "{outcome}"
        );
        assert!(
            !outcome.contains("remote command") && !outcome.contains("guest command"),
            "no route was recorded, so no route may be named: {outcome}"
        );
        let rendered = crate::background::render_outcomes(&delivered);
        assert!(rendered.contains("was canceled"), "{rendered}");
        assert!(
            rendered.contains("recorded no route"),
            "the hedge has to survive into the delivered text: {rendered}"
        );
    }

    /// A stop that reached no live runner still left its ask in the row; when the work reports its
    /// own end afterwards, that result is what ended the task and the outcome keeps both facts (
    /// its own end is recorded as it reported it, and the ask's teardown is what nothing confirmed)
    /// rather than burying the one thing the run could not tell anyone at the time.
    #[tokio::test]
    async fn a_result_landing_after_an_unreached_stop_keeps_both_facts() {
        let (context, session_id) = context().await;
        let task = seed(&context, session_id, "sleep 600").await;
        let store = context.store.clone();
        let tool = TaskCancelTool { context };
        cancel(&tool, serde_json::json!({"id": task.id.clone()})).await;

        store
            .background_store()
            .finish_background_task(
                &task.id,
                TaskStatus::Failed,
                Some("the build failed on its own".to_string()),
                None,
            )
            .await
            .expect("finish");

        let delivered = store
            .background_store()
            .list_undelivered_background_tasks(session_id)
            .await
            .expect("list");
        assert_eq!(
            delivered[0].status,
            TaskStatus::Failed,
            "its own result is what ended it: nothing here ever signaled it"
        );
        let outcome = delivered[0].outcome.as_deref().unwrap_or_default();
        assert!(
            outcome.contains("A stop was requested"),
            "the pending ask is part of the record: {outcome}"
        );
        assert!(
            outcome.contains("the build failed on its own"),
            "and its own words are kept below the note: {outcome}"
        );
    }

    #[tokio::test]
    async fn task_cancel_rejects_an_unknown_id() {
        let (context, _) = context().await;
        let tool = TaskCancelTool { context };
        let result = tool
            .execute(
                serde_json::json!({"id": "deadbeef"}),
                crate::tools::ToolContext::for_test(CancellationToken::new()),
            )
            .await
            .expect("ok");
        assert!(result.is_error);
        assert!(result.text_content().contains("no background task"));
    }

    /// Canceling in bulk must record `canceled`, not leave the task's own interruption to land as
    /// `failed`. "Your build failed" and "you stopped your build" call for different next moves.
    /// Outcome delivery is stamped before its turn runs, so a turn that fails consumes the report.
    /// Listing has to be able to recover it, or the result is reachable only by reading the
    /// database by hand.
    #[tokio::test]
    async fn task_list_shows_a_finished_task_s_result() {
        let (context, session_id) = context().await;
        let task = seed(&context, session_id, "cargo test").await;
        context
            .store
            .background_store()
            .finish_background_task(
                &task.id,
                TaskStatus::Completed,
                Some("42 passed; 0 failed".to_string()),
                None,
            )
            .await
            .expect("finish");

        let tool = TaskListTool { context };
        let result = tool
            .execute(
                serde_json::json!({}),
                crate::tools::ToolContext::for_test(CancellationToken::new()),
            )
            .await
            .expect("ok");
        let text = result.text_content();
        assert!(text.contains("42 passed"), "{text}");
    }

    /// A running task has no result yet, so listing must not invent one.
    #[tokio::test]
    async fn task_list_shows_no_result_for_a_running_task() {
        let (context, session_id) = context().await;
        seed(&context, session_id, "sleep 600").await;
        let tool = TaskListTool { context };
        let result = tool
            .execute(
                serde_json::json!({}),
                crate::tools::ToolContext::for_test(CancellationToken::new()),
            )
            .await
            .expect("ok");
        let text = result.text_content();
        let row = text
            .lines()
            .find(|line| line.contains("sleep 600"))
            .unwrap_or_else(|| panic!("the running task's row is missing from:\n{text}"));
        assert!(
            row.trim_end().ends_with('-'),
            "a running task's Result cell must be the `-` placeholder: {row}"
        );
    }

    /// Canceling in bulk records a request too: the row must not be `failed` (the run's own
    /// interruption) once the work answers, and must not be `canceled` before it does.
    #[tokio::test]
    async fn task_cancel_all_records_canceled_not_failed() {
        let (context, session_id) = context().await;
        let task = seed(&context, session_id, "sleep 600").await;
        // A live handle, so the bulk path has something to signal.
        let token = CancellationToken::new();
        assert!(
            context
                .tasks
                .try_reserve(task.id.clone(), session_id, token.clone(), 10)
                .await
        );
        let store = context.store.clone();
        let tasks = context.tasks.clone();
        let tool = TaskCancelTool { context };

        let result = cancel(&tool, serde_json::json!({"all": true})).await;
        assert!(!result.is_error);
        assert!(token.is_cancelled());

        let background = store.background_store();
        let row = background
            .background_task_by_id(&task.id)
            .await
            .expect("load")
            .expect("row");
        assert_eq!(row.status, TaskStatus::Stopping);
        assert!(
            background
                .list_undelivered_background_tasks(session_id)
                .await
                .expect("list")
                .is_empty(),
            "a request is not delivered as the outcome"
        );

        let (status, _reason) = tasks.outcome_end(&task.id, true).await;
        assert_eq!(status, TaskStatus::Canceled);
        background
            .finish_background_task(
                &task.id,
                status,
                Some("Tool execution interrupted.".to_string()),
                None,
            )
            .await
            .expect("finish");
        let undelivered = background
            .list_undelivered_background_tasks(session_id)
            .await
            .expect("list");
        assert_eq!(undelivered.len(), 1);
        assert_eq!(undelivered[0].status, TaskStatus::Canceled);
    }

    /// Only the tasks recorded as canceled are signaled and counted: one whose own outcome landed
    /// first keeps it and is left alone, though its handle is still held.
    #[tokio::test]
    async fn task_cancel_all_signals_only_what_it_recorded() {
        let (context, session_id) = context().await;
        let running = seed(&context, session_id, "sleep 600").await;
        let finishing = seed(&context, session_id, "cargo test").await;
        let running_token = CancellationToken::new();
        let finishing_token = CancellationToken::new();
        for (task, token) in [(&running, &running_token), (&finishing, &finishing_token)] {
            context
                .tasks
                .try_reserve(task.id.clone(), session_id, token.clone(), 10)
                .await;
        }
        context
            .store
            .background_store()
            .finish_background_task(
                &finishing.id,
                TaskStatus::Completed,
                Some("42 passed".to_string()),
                None,
            )
            .await
            .expect("finish");
        let tool = TaskCancelTool { context };

        let result = tool
            .execute(
                serde_json::json!({"all": true}),
                crate::tools::ToolContext::for_test(CancellationToken::new()),
            )
            .await
            .expect("ok");

        assert!(
            result.text_content().contains("Asked 1 "),
            "{}",
            result.text_content()
        );
        assert!(running_token.is_cancelled());
        assert!(
            !finishing_token.is_cancelled(),
            "a finished task is not signaled"
        );
    }

    #[tokio::test]
    async fn task_cancel_all_is_a_no_op_when_nothing_runs() {
        let (context, _) = context().await;
        let tool = TaskCancelTool { context };
        let result = tool
            .execute(
                serde_json::json!({"all": true}),
                crate::tools::ToolContext::for_test(CancellationToken::new()),
            )
            .await
            .expect("ok");
        assert!(!result.is_error);
        assert!(result.text_content().contains("No running background"));
    }
}
