//! Background tasks: the `background_tasks` table.

use chrono::{DateTime, Utc};

use super::*;

/// A background call's whole output, for the scratchpad entry the call named.
#[derive(Clone)]
pub(crate) struct SavedOutput {
    pub(crate) session_id: Uuid,
    pub(crate) name: String,
    pub(crate) content: String,
}

/// Where a task's work ran, which decides what ending it on this machine can prove about it. A
/// native process tree can be killed and reaped here; a guest command leaves this machine with a
/// launcher, and a remote one with a client, whose end is not the command's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RouteEvidence {
    /// Work native to this machine: what was ended here is the whole of it.
    Local,
    /// A command in the managed WSL guest: ending the local launcher does not end the guest's
    /// namespace.
    Guest,
    /// A command on a remote host over SSH: ending the local client does not end the remote
    /// command. Constructed when a run records the route it took; until `TeardownObservation`
    /// carries one (the tool-side seam in `crate::tools`), only tests build this variant.
    #[cfg_attr(not(test), allow(dead_code))]
    Remote,
    /// The run recorded no route, so nothing here speaks for what the work started elsewhere.
    Unrecorded,
}

/// Who asked for a stop. The note a stopped task's outcome opens with names it, so a stored and
/// delivered outcome says why the work ended rather than only that it did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StopReason {
    /// The agent's own `task_cancel` call.
    AgentRequest,
    /// A person or client at a host surface: `/task cancel`, `meka task cancel`,
    /// `DELETE /v1/tasks/{id}`.
    UserRequest,
    /// The host releasing the session or shutting down: nobody asked for this work to stop, so it
    /// reports `interrupted`, not `canceled`.
    HostRelease,
}
impl StopReason {
    /// The status a task stopped for this reason reports.
    pub(crate) fn status(self) -> TaskStatus {
        match self {
            Self::AgentRequest | Self::UserRequest => TaskStatus::Canceled,
            Self::HostRelease => TaskStatus::Interrupted,
        }
    }

    /// The reason a stop recorded as `status` reports, for the callers that stop work in bulk and
    /// name the status rather than the door they stand in.
    pub(crate) fn matching(status: TaskStatus) -> Self {
        match status {
            TaskStatus::Interrupted => Self::HostRelease,
            _ => Self::UserRequest,
        }
    }
}

/// What the run recorded about the end of a stopped task: whether the work had begun at all,
/// whether the task's own result landed after the stop, where the work ran, and who asked it to
/// stop. The note [`stop_outcome`] builds is worded from these, so a stored and delivered outcome
/// carries the evidence instead of a guess about a route the run may never have taken.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Teardown {
    /// Whether the work had begun. A stop that won before the start has no run to report and
    /// nothing to tear down; its note says so and drops the route clause, since nothing ran
    /// anywhere.
    pub(crate) started: bool,
    /// Whether the task's own result landed after the stop. Only that says the cleanup the run
    /// performs after observing the stop happened; a caller that only asked cannot establish it.
    pub(crate) confirmed: bool,
    /// Where the work ran.
    pub(crate) route: RouteEvidence,
    /// Who asked for the stop, when a stop is what ended the task.
    pub(crate) reason: Option<StopReason>,
}
impl Teardown {
    /// A caller that observed only its own result: a run that began and ended, with nothing
    /// recorded about where the work ran or who stopped it.
    pub(crate) const RECORDED: Teardown = Teardown {
        started: true,
        confirmed: true,
        route: RouteEvidence::Unrecorded,
        reason: None,
    };
}

/// The tools whose calls can run off this machine: a shell command routed through WSL or SSH, and
/// the WSL subshell tools. Only these get the route hedge below when the run recorded no route;
/// for anything else there is nothing off this machine to speak for.
fn route_capable(tool: &str) -> bool {
    matches!(
        tool,
        "shell_execute"
            | "subshell_open"
            | "subshell_execute"
            | "subshell_export"
            | "subshell_close"
    )
}

/// The route a tool's work always runs on when the run recorded none. A subshell call is guest
/// work by definition and any other tool is local by definition; a shell command is neither, so
/// `Unrecorded` is the honest answer for one until its run records the route it took.
fn default_route(tool: &str) -> RouteEvidence {
    match tool {
        "subshell_open" | "subshell_execute" | "subshell_export" | "subshell_close" => {
            RouteEvidence::Guest
        }
        "shell_execute" => RouteEvidence::Unrecorded,
        _ => RouteEvidence::Local,
    }
}

/// The sentence a stopped task's outcome opens with: who asked, what the stop itself established,
/// and the one thing stopping on this machine cannot establish for work that runs elsewhere.
///
/// The route clause is per route evidence, never keyed on the tool alone: a WSL command must not
/// inherit an SSH caveat. A run that recorded no route and ran on a tool that can route gets the
/// neutral sentence that says exactly that, rather than a claim about any one route.
fn stop_outcome(tool: &str, teardown: Teardown, outcome: Option<String>) -> String {
    let mut note = match teardown.reason {
        Some(StopReason::AgentRequest) => "Stopped at the agent's request",
        Some(StopReason::UserRequest) => "Stopped on request",
        Some(StopReason::HostRelease) => "Stopped when the host released the session",
        None => "A stop was requested",
    }
    .to_string();
    if !teardown.started {
        note.push_str(" before the work began: nothing ran, so there is nothing to tear down.");
    } else if teardown.confirmed {
        note.push_str("; the task's own work ended afterwards, so local teardown is confirmed.");
    } else {
        note.push_str(", but nothing reported after it: local teardown is unconfirmed.");
    }
    if teardown.started {
        match teardown.route {
            RouteEvidence::Local => {}
            RouteEvidence::Guest => note.push_str(
                "\nThe guest command's state is unknown: stopping the local launcher does not stop \
                 what it started.",
            ),
            RouteEvidence::Remote => note.push_str(
                "\nThe remote command's state is unknown: stopping the local client does not stop \
                 what it started.",
            ),
            RouteEvidence::Unrecorded => match default_route(tool) {
                RouteEvidence::Guest => note.push_str(
                    "\nThe guest command's state is unknown: stopping the local launcher does not \
                     stop what it started.",
                ),
                _ if route_capable(tool) => note.push_str(
                    "\nThe run recorded no route for this call, so what it started beyond this \
                     process is unknown.",
                ),
                _ => {}
            },
        }
    }
    match outcome {
        Some(outcome) if !outcome.trim().is_empty() => format!("{note}\n\n{outcome}"),
        _ => note,
    }
}

/// Background work's slice of the session database, handed out by
/// [`crate::store::Store::background_store`].
#[derive(Clone)]
pub(crate) struct BackgroundStore {
    pub(crate) connection: std::sync::Arc<super::connection::Connection>,
}
impl BackgroundStore {
    /// A handle on the table over `connection`.
    pub(crate) fn new(connection: std::sync::Arc<super::connection::Connection>) -> Self {
        Self { connection }
    }

    /// Record a task as started. Written before the work is spawned, so a process that dies between
    /// the two leaves a `running` row the sweep will retire rather than a task nobody knows about.
    pub(crate) async fn start_background_task(
        &self,
        task: &BackgroundTask,
    ) -> crate::error::Result<()> {
        let id = task.id.clone();
        let session_id = task.session_id.to_string();
        let tool = task.tool.clone();
        let label = task.label.clone();
        let status = task.status.name().to_string();
        let started_at = task.started_at.to_rfc3339();

        self.connection
            .call(move |connection| -> rusqlite::Result<_> {
                connection.execute(
                    "INSERT INTO background_tasks \
                     (id, session_id, tool, label, status, started_at) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    rusqlite::params![id, session_id, tool, label, status, started_at],
                )?;
                Ok(())
            })
            .await
            .map_err(|error| {
                MekaError::Database(format!("failed to start background task: {error}"))
            })
    }

    /// Record a terminal outcome.
    ///
    /// Guarded on the task not having ended yet, so one swept to `interrupted` cannot be
    /// overwritten by its own work finishing a moment later. A `stopping` row is still open: a
    /// stop request moved it there without deciding how it ended, and this write is the one that
    /// does, which is why the first *terminal* write still wins and a canceled task cannot report
    /// success.
    ///
    /// This form is the run's own result landing, with nothing recorded about where the work ran
    /// or who stopped it; a caller holding that evidence takes
    /// [`Self::finish_background_task_observed`].
    pub(crate) async fn finish_background_task(
        &self,
        id: &str,
        status: TaskStatus,
        outcome: Option<String>,
        scratchpad_entry: Option<String>,
    ) -> crate::error::Result<()> {
        self.finish_background_task_observed(
            id,
            status,
            outcome,
            scratchpad_entry,
            Teardown::RECORDED,
        )
        .await
    }

    /// [`Self::finish_background_task`] with what the run saw of its own stop. A caller that
    /// watched a cancellation request cannot assume confirmation: only an observation can say
    /// the work's processes ended. The evidence rides into the stored outcome, so what is
    /// delivered says who asked for the stop and what ending it here could and could not prove.
    pub(crate) async fn finish_background_task_observed(
        &self,
        id: &str,
        status: TaskStatus,
        outcome: Option<String>,
        scratchpad_entry: Option<String>,
        teardown: Teardown,
    ) -> crate::error::Result<()> {
        let id = id.to_string();
        let stopped = matches!(status, TaskStatus::Canceled | TaskStatus::Interrupted);
        let status = status.name().to_string();
        let finished_at = chrono::Utc::now().to_rfc3339();
        self.connection
            .call(move |connection| -> rusqlite::Result<_> {
                // Read first only to word a stop: what the row ends as is decided by the one
                // guarded write below, so a row that moves between the two reads changes nothing,
                // and a write that fails leaves no half-done work behind. A run reporting its own
                // end on a row a stop was recorded against keeps the ask in the outcome too: the
                // record is half of what the row carries, and dropping it would hide the one thing
                // nobody could tell the agent at the time.
                let open = connection
                    .query_row(
                        "SELECT tool, status FROM background_tasks \
                         WHERE id = ?1 AND status IN ('running', 'stopping')",
                        [id.as_str()],
                        |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
                    )
                    .optional()?;
                let outcome = match open {
                    Some((tool, recorded)) if stopped || recorded == "stopping" => {
                        Some(stop_outcome(&tool, teardown, outcome))
                    }
                    _ => outcome,
                };
                connection.execute(
                    "UPDATE background_tasks \
                     SET status = ?2, outcome = ?3, scratchpad_entry = ?4, finished_at = ?5 \
                     WHERE id = ?1 AND status IN ('running', 'stopping')",
                    rusqlite::params![id, status, outcome, scratchpad_entry, finished_at],
                )?;
                Ok(())
            })
            .await
            .map_err(|error| {
                MekaError::Database(format!("failed to finish background task: {error}"))
            })
    }

    /// Record each of `ids` still running as stopped with `status`, in one transaction, and answer
    /// the ids whose row moved: the ones to signal, since a task whose own outcome landed first
    /// keeps it.
    ///
    /// For a test that simulates a terminal stop recorded by another owner: the row is terminal
    /// before the work ends, so its own result is never recorded. Production paths record a
    /// request with [`Self::request_stop_background_tasks`] and let the work's result end the row,
    /// because a caller cannot observe a teardown it did not perform.
    #[cfg(test)]
    pub(crate) async fn stop_background_tasks(
        &self,
        ids: Vec<String>,
        status: TaskStatus,
    ) -> crate::error::Result<Vec<String>> {
        if ids.is_empty() {
            return Ok(ids);
        }
        let stopped_word = matches!(status, TaskStatus::Canceled | TaskStatus::Interrupted);
        let reason = stopped_word.then(|| StopReason::matching(status));
        let status = status.name().to_string();
        let finished_at = chrono::Utc::now().to_rfc3339();
        self.connection
            .call(move |connection| -> rusqlite::Result<_> {
                let transaction = connection
                    .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
                let mut stopped = Vec::with_capacity(ids.len());
                for id in ids {
                    let open = transaction
                        .query_row(
                            "SELECT tool FROM background_tasks \
                             WHERE id = ?1 AND status = 'running'",
                            [id.as_str()],
                            |row| row.get::<_, String>(0),
                        )
                        .optional()?;
                    let Some(tool) = open else {
                        continue;
                    };
                    let outcome = stopped_word.then(|| {
                        stop_outcome(
                            &tool,
                            Teardown {
                                started: true,
                                confirmed: false,
                                route: RouteEvidence::Unrecorded,
                                reason,
                            },
                            None,
                        )
                    });
                    let moved = transaction.execute(
                        "UPDATE background_tasks SET status = ?3, outcome = ?4, finished_at = ?2 \
                         WHERE id = ?1 AND status = 'running'",
                        rusqlite::params![id, finished_at, status, outcome],
                    )?;
                    if moved > 0 {
                        stopped.push(id);
                    }
                }
                transaction.commit()?;
                Ok(stopped)
            })
            .await
            .map_err(|error| {
                MekaError::Database(format!("failed to stop background tasks: {error}"))
            })
    }

    /// Record that `ids` were asked to stop, without deciding how they ended: each row becomes
    /// `stopping`, stays out of every delivery pool, and the work's own result ends it.
    ///
    /// This is the durable acceptance of a stop, recorded by the stop service *after* the live
    /// claim has signaled the owner: a request whose future dies before this write has still
    /// stopped its task, and a row left `stopping` here is what a retry re-signals against. A
    /// task whose outcome landed first is left alone, and answers the ids whose row moved: those
    /// are the requests this write accepted.
    pub(crate) async fn request_stop_background_tasks(
        &self,
        ids: Vec<String>,
    ) -> crate::error::Result<Vec<String>> {
        if ids.is_empty() {
            return Ok(ids);
        }
        let stopping = TaskStatus::Stopping.name().to_string();
        self.connection
            .call(move |connection| -> rusqlite::Result<_> {
                let transaction = connection
                    .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
                let mut requested = Vec::with_capacity(ids.len());
                for id in ids {
                    let moved = transaction.execute(
                        "UPDATE background_tasks SET status = ?2 \
                         WHERE id = ?1 AND status = 'running'",
                        rusqlite::params![id, stopping],
                    )?;
                    if moved > 0 {
                        requested.push(id);
                    }
                }
                transaction.commit()?;
                Ok(requested)
            })
            .await
            .map_err(|error| {
                MekaError::Database(format!("failed to request a background task stop: {error}"))
            })
    }

    /// Claim the start of `id` against recorded stop intent, as the durable half of
    /// [`crate::background::BackgroundTasks::claim_start`].
    ///
    /// The guarded write is the serialization point against
    /// [`Self::request_stop_background_tasks`]: both only move a `running` row, so exactly one of
    /// them observes it as `running` and the loser sees what the winner wrote. `false` means a
    /// stop intent or a terminal outcome already owns the row (or there is no row), and the work
    /// must not start.
    pub(crate) async fn claim_task_start(&self, id: &str) -> crate::error::Result<bool> {
        let id = id.to_string();
        let running = TaskStatus::Running.name().to_string();
        self.connection
            .call(move |connection| -> rusqlite::Result<_> {
                let moved = connection.execute(
                    "UPDATE background_tasks SET status = ?2 \
                     WHERE id = ?1 AND status = ?2",
                    rusqlite::params![id, running],
                )?;
                Ok(moved > 0)
            })
            .await
            .map_err(|error| {
                MekaError::Database(format!("failed to claim a background task start: {error}"))
            })
    }

    /// [`Self::finish_background_task`] for a call that named a scratchpad entry: the entry is
    /// saved with the outcome, in one transaction and only while the row is still open, so a task
    /// stopped before its work came back has no say over an entry the model named.
    pub(crate) async fn finish_background_task_into_entry_observed(
        &self,
        id: &str,
        status: TaskStatus,
        outcome: String,
        entry: SavedOutput,
        teardown: Teardown,
    ) -> crate::error::Result<()> {
        let id = id.to_string();
        let stopped = matches!(status, TaskStatus::Canceled | TaskStatus::Interrupted);
        let status = status.name().to_string();
        let finished_at = chrono::Utc::now().to_rfc3339();
        self.connection
            .call(move |connection| -> rusqlite::Result<_> {
                let transaction = connection
                    .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
                let open = transaction
                    .query_row(
                        "SELECT tool, status FROM background_tasks \
                         WHERE id = ?1 AND status IN ('running', 'stopping')",
                        [id.as_str()],
                        |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
                    )
                    .optional()?;
                let Some((tool, recorded)) = open else {
                    transaction.commit()?;
                    return Ok(());
                };
                // A run reporting its own end on a row a stop was recorded against keeps the ask
                // in the outcome, for the same reason
                // [`Self::finish_background_task_observed`] does.
                let outcome = if stopped || recorded == "stopping" {
                    stop_outcome(&tool, teardown, Some(outcome))
                } else {
                    outcome
                };
                let finished = transaction.execute(
                    "UPDATE background_tasks \
                     SET status = ?2, outcome = ?3, scratchpad_entry = NULL, finished_at = ?4 \
                     WHERE id = ?1 AND status IN ('running', 'stopping')",
                    rusqlite::params![id, status, outcome, finished_at],
                )?;
                if finished > 0 {
                    transaction.execute(
                        "INSERT OR REPLACE INTO scratchpad_entries \
                         (session_id, name, content, created_at) VALUES (?1, ?2, ?3, ?4)",
                        rusqlite::params![
                            entry.session_id.to_string(),
                            entry.name,
                            entry.content,
                            finished_at
                        ],
                    )?;
                }
                transaction.commit()
            })
            .await
            .map_err(|error| {
                MekaError::Database(format!("failed to finish background task: {error}"))
            })
    }

    /// Every task belonging to one session, newest first.
    pub(crate) async fn list_background_tasks(
        &self,
        session_id: Uuid,
    ) -> crate::error::Result<Vec<BackgroundTask>> {
        self.query_background_tasks(
            "SELECT id, session_id, tool, label, status, outcome, scratchpad_entry, \
             started_at, finished_at, announced_at, delivered_at, subagent_id FROM background_tasks \
             WHERE session_id = ?1 ORDER BY started_at DESC",
            vec![session_id.to_string()],
        )
        .await
    }

    /// A session's tasks still running, oldest first. Backs the `[Background]` index and the Ctrl+C
    /// survivor line.
    ///
    /// A task with a stop requested is still running until its work answers, so it belongs here:
    /// the model should see that it is on its way out, not read the task as gone before the
    /// teardown has happened.
    pub(crate) async fn list_running_background_tasks(
        &self,
        session_id: Uuid,
    ) -> crate::error::Result<Vec<BackgroundTask>> {
        self.query_background_tasks(
            "SELECT id, session_id, tool, label, status, outcome, scratchpad_entry, \
             started_at, finished_at, announced_at, delivered_at, subagent_id FROM background_tasks \
             WHERE session_id = ?1 AND status IN ('running', 'stopping') ORDER BY started_at ASC",
            vec![session_id.to_string()],
        )
        .await
    }

    /// A session's finished-but-unreported tasks, oldest first. The delivery poll's query; served
    /// by `idx_background_tasks_session_id_status`.
    ///
    /// A `stopping` row is excluded: a stop request is not an outcome, and delivering one would
    /// tell the agent the work had ended before anything established that it had.
    ///
    /// This and [`Self::mark_background_tasks_delivered`] are two statements, not one transaction,
    /// so two processes that both list before either marks would each render the same outcome. That
    /// is currently unreachable (delivery only happens inside a session, and a session is held by
    /// one process at a time from the moment its row exists), so the pair rests on the session
    /// lock rather than on its own atomicity. Anything that ever lets two hosts open one
    /// session at once has to make this a transaction first.
    pub(crate) async fn list_undelivered_background_tasks(
        &self,
        session_id: Uuid,
    ) -> crate::error::Result<Vec<BackgroundTask>> {
        self.query_background_tasks(
            "SELECT id, session_id, tool, label, status, outcome, scratchpad_entry, \
             started_at, finished_at, announced_at, delivered_at, subagent_id FROM background_tasks \
             WHERE session_id = ?1 AND status NOT IN ('running', 'stopping') \
             AND delivered_at IS NULL ORDER BY finished_at ASC",
            vec![session_id.to_string()],
        )
        .await
    }

    /// Stamp outcomes as delivered.
    ///
    /// Called *before* the turn runs: an outcome that reliably wedges the process would otherwise
    /// be redelivered on every restart, turning one bad result into a boot loop. Losing one report
    /// is the cheaper failure.
    ///
    /// A schedule's occurrence is spent only once its fire is in the inbox
    /// ([`crate::store::schedule::ScheduleStore::queue_fire`]), because a lease plus an attempt
    /// ceiling gives it the same boot-loop protection without paying an occurrence for every
    /// crash. A background outcome has no lease to hold, so it keeps the cruder rule.
    pub(crate) async fn mark_background_tasks_delivered(
        &self,
        ids: &[String],
    ) -> crate::error::Result<Vec<String>> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let ids = ids.to_vec();
        let delivered_at = chrono::Utc::now().to_rfc3339();
        self.connection
            .call(move |connection| -> rusqlite::Result<_> {
                // One transaction, so a failure part-way cannot leave half a batch stamped. The
                // caller renders every one of these into a single turn, and stamping only some of
                // them would repeat the rest alongside it on the next tick.
                let transaction = connection.transaction()?;
                let mut claimed = Vec::new();
                {
                    let mut statement = transaction.prepare(
                        "UPDATE background_tasks SET delivered_at = ?2 \
                         WHERE id = ?1 AND delivered_at IS NULL",
                    )?;
                    for id in &ids {
                        if statement.execute(rusqlite::params![id, delivered_at])? == 1 {
                            claimed.push(id.clone());
                        }
                    }
                }
                transaction.commit()?;
                Ok(claimed)
            })
            .await
            .map_err(|error| {
                MekaError::Database(format!("failed to mark tasks delivered: {error}"))
            })
    }

    /// Put claimed outcomes back in the undelivered pool, for a claimer whose save of the message
    /// carrying them failed: a later turn then reads them, where otherwise nothing would. A crash
    /// releases nothing, which keeps the rule [`Self::mark_background_tasks_delivered`] gives.
    pub(crate) async fn release_background_tasks(
        &self,
        ids: &[String],
    ) -> crate::error::Result<()> {
        if ids.is_empty() {
            return Ok(());
        }
        let ids = ids.to_vec();
        self.connection
            .call(move |connection| -> rusqlite::Result<_> {
                let transaction = connection.transaction()?;
                for id in &ids {
                    transaction.execute(
                        "UPDATE background_tasks SET delivered_at = NULL WHERE id = ?1",
                        [id],
                    )?;
                }
                transaction.commit()
            })
            .await
            .map_err(|error| {
                MekaError::Database(format!("failed to release background outcomes: {error}"))
            })
    }

    /// A session's finished-but-unannounced tasks, oldest first.
    ///
    /// The poller's own question, and deliberately not [`Self::list_undelivered_background_tasks`]:
    /// telling subscribers a task finished needs nothing from a live session, while telling the
    /// model needs a turn. An outcome that waits for one must stay undelivered without also being
    /// re-announced on every poll.
    ///
    /// Bounded to the undelivered pool, which is what keeps it news. `announced_at` is written only
    /// by `meka serve`, so every task a screen or ACP session ever ran is unannounced forever in a
    /// shared store; without this clause, opening one of those sessions in `meka serve` would fire
    /// `task.finished` for work that finished weeks ago and was reported at the time. A task still
    /// in the pool has been reported to nobody, which is the case worth pushing.
    pub(crate) async fn list_unannounced_background_tasks(
        &self,
        session_id: Uuid,
    ) -> crate::error::Result<Vec<BackgroundTask>> {
        self.query_background_tasks(
            "SELECT id, session_id, tool, label, status, outcome, scratchpad_entry, \
             started_at, finished_at, announced_at, delivered_at, subagent_id FROM background_tasks \
             WHERE session_id = ?1 AND status NOT IN ('running', 'stopping') \
             AND announced_at IS NULL AND delivered_at IS NULL ORDER BY finished_at ASC",
            vec![session_id.to_string()],
        )
        .await
    }

    /// Stamp a batch announced. One transaction, for the reason
    /// [`Self::mark_background_tasks_delivered`] gives.
    pub(crate) async fn mark_background_tasks_announced(
        &self,
        ids: &[String],
    ) -> crate::error::Result<Vec<String>> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let ids = ids.to_vec();
        let announced_at = chrono::Utc::now().to_rfc3339();
        self.connection
            .call(move |connection| -> rusqlite::Result<_> {
                let transaction = connection.transaction()?;
                let mut claimed = Vec::new();
                {
                    let mut statement = transaction.prepare(
                        "UPDATE background_tasks SET announced_at = ?2 \
                         WHERE id = ?1 AND announced_at IS NULL",
                    )?;
                    for id in &ids {
                        if statement.execute(rusqlite::params![id, announced_at])? == 1 {
                            claimed.push(id.clone());
                        }
                    }
                }
                transaction.commit()?;
                Ok(claimed)
            })
            .await
            .map_err(|error| {
                MekaError::Database(format!("failed to mark tasks announced: {error}"))
            })
    }

    /// Retire every task in this session that a dead process left `running` or `stopping`, as
    /// [`TaskStatus::Interrupted`], returning how many were swept, sparing only the rows named in
    /// `still_live`.
    ///
    /// Called when a process takes ownership of a session. The session lock
    /// ([`crate::store::Store::lock_session`]) is the lease: a release holds it until its work has
    /// settled, so the lock can only be taken once every previous owner has finished or died, and
    /// a row that still says `running` with no live handle behind it belongs to a process that is
    /// gone. Without this a task in flight at shutdown would leave the agent waiting on a report
    /// that can never arrive, having very likely already promised one.
    ///
    /// A `stopping` row is a stop somebody asked for and no result answered, so its outcome says
    /// the teardown is unconfirmed: the agent asked for the work to end and is owed the fact that
    /// nothing established that it did. A swept `running` row keeps no outcome of its own: nothing
    /// reported one, and `interrupted` is the whole of what is known.
    pub(crate) async fn sweep_interrupted_background_tasks_except(
        &self,
        session_id: Uuid,
        still_live: &[String],
    ) -> crate::error::Result<usize> {
        let session_id = session_id.to_string();
        let still_live = still_live.to_vec();
        let status = TaskStatus::Interrupted.name().to_string();
        let finished_at = chrono::Utc::now().to_rfc3339();
        self.connection
            .call(move |connection| -> rusqlite::Result<_> {
                let transaction = connection
                    .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
                let open: Vec<(String, String, String)> = {
                    let mut statement = transaction.prepare(
                        "SELECT id, tool, status FROM background_tasks \
                         WHERE session_id = ?1 AND status IN ('running', 'stopping')",
                    )?;
                    statement
                        .query_map([session_id.as_str()], |row| {
                            Ok((
                                row.get::<_, String>(0)?,
                                row.get::<_, String>(1)?,
                                row.get::<_, String>(2)?,
                            ))
                        })?
                        .collect::<std::result::Result<Vec<_>, _>>()?
                };
                let mut swept = 0;
                for (id, tool, was) in &open {
                    if still_live.contains(id) {
                        continue;
                    }
                    let outcome = (was == TaskStatus::Stopping.name()).then(|| {
                        stop_outcome(
                            tool,
                            Teardown {
                                started: true,
                                confirmed: false,
                                route: RouteEvidence::Unrecorded,
                                reason: None,
                            },
                            None,
                        )
                    });
                    swept += transaction.execute(
                        "UPDATE background_tasks SET status = ?2, outcome = ?3, finished_at = ?4 \
                         WHERE id = ?1 AND status IN ('running', 'stopping')",
                        rusqlite::params![id, status, outcome, finished_at],
                    )?;
                }
                transaction.commit()?;
                Ok(swept)
            })
            .await
            .map_err(|error| {
                MekaError::Database(format!("failed to sweep background tasks: {error}"))
            })
    }

    /// [`Self::sweep_interrupted_background_tasks_except`] sparing nothing: the form for a caller
    /// that holds no live work of this session in its process and so can retire every open row the
    /// lease behind the sweep proves dead.
    // Exercised only by tests today: every live door may hold released work and spares it. Kept at
    // this arity for `agent/turn`'s sweep test, which simulates a later process sweeping.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) async fn sweep_interrupted_background_tasks(
        &self,
        session_id: Uuid,
    ) -> crate::error::Result<usize> {
        self.sweep_interrupted_background_tasks_except(session_id, &[])
            .await
    }

    /// One task by its full id, whatever session it is in, or `None` when no task has it.
    pub(crate) async fn background_task_by_id(
        &self,
        id: &str,
    ) -> crate::error::Result<Option<BackgroundTask>> {
        let tasks = self
            .query_background_tasks(
                "SELECT id, session_id, tool, label, status, outcome, scratchpad_entry, \
                 started_at, finished_at, announced_at, delivered_at, subagent_id FROM background_tasks \
                 WHERE id = ?1",
                vec![id.to_string()],
            )
            .await?;
        Ok(tasks.into_iter().next())
    }

    /// Remove the row of a call that did not start, so the call leaves no task. A stop recorded on
    /// it while the call was starting goes with it, since nothing ran for a report to tell of; a
    /// row with an outcome or a delivery is not one this call alone wrote, and stays.
    pub(crate) async fn withdraw_background_task(&self, id: &str) -> crate::error::Result<()> {
        let id = id.to_string();
        self.connection
            .call(move |connection| -> rusqlite::Result<_> {
                connection.execute(
                    "DELETE FROM background_tasks \
                     WHERE id = ?1 AND outcome IS NULL AND delivered_at IS NULL",
                    rusqlite::params![id],
                )?;
                Ok(())
            })
            .await
            .map_err(|error| {
                MekaError::Database(format!("failed to withdraw a background task: {error}"))
            })
    }

    /// Record the sub-agent a backgrounded `agent_spawn` or `agent_followup` drives, on the task's
    /// row.
    pub(crate) async fn record_task_subagent(
        &self,
        task_id: &str,
        subagent_id: Uuid,
    ) -> crate::error::Result<()> {
        let task_id = task_id.to_string();
        self.connection
            .call(move |connection| -> rusqlite::Result<_> {
                connection.execute(
                    "UPDATE background_tasks SET subagent_id = ?2 WHERE id = ?1",
                    rusqlite::params![task_id, subagent_id.to_string()],
                )?;
                Ok(())
            })
            .await
            .map_err(|error| {
                MekaError::Database(format!("failed to record the task's sub-agent: {error}"))
            })
    }

    /// Every session's tasks, newest first, or only those in one `status`.
    pub(crate) async fn list_all_background_tasks(
        &self,
        status: Option<TaskStatus>,
    ) -> crate::error::Result<Vec<BackgroundTask>> {
        match status {
            Some(status) => {
                self.query_background_tasks(
                    "SELECT id, session_id, tool, label, status, outcome, scratchpad_entry, \
                     started_at, finished_at, announced_at, delivered_at, subagent_id \
                     FROM background_tasks WHERE status = ?1 ORDER BY started_at DESC",
                    vec![status.name().to_string()],
                )
                .await
            }
            None => {
                self.query_background_tasks(
                    "SELECT id, session_id, tool, label, status, outcome, scratchpad_entry, \
                     started_at, finished_at, announced_at, delivered_at, subagent_id \
                     FROM background_tasks ORDER BY started_at DESC",
                    Vec::new(),
                )
                .await
            }
        }
    }

    /// Resolve a full or unique-prefix task id within a session. An ambiguous prefix is an error
    /// rather than an arbitrary pick, matching
    /// [`crate::store::schedule::ScheduleStore::cancel_schedule`] in behavior and in error
    /// variant, so a tool, the screen's `/task` and `meka` name a prefix the same way for tasks
    /// and schedules. The HTTP routes take a task's full id ([`Self::background_task_by_id`]).
    pub(crate) async fn resolve_background_task(
        &self,
        session_id: Uuid,
        id_prefix: &str,
    ) -> crate::error::Result<Option<BackgroundTask>> {
        if !crate::text::is_usable_id_prefix(id_prefix) {
            return Ok(None);
        }
        let wanted = crate::text::id_prefix_for_matching(id_prefix);
        let tasks = self.list_background_tasks(session_id).await?;
        let matches: Vec<BackgroundTask> = tasks
            .into_iter()
            .filter(|task| task.id.starts_with(&wanted))
            .collect();
        match matches.len() {
            0 => Ok(None),
            1 => Ok(matches.into_iter().next()),
            _ => Err(MekaError::Usage(format!(
                "task id '{}' is ambiguous; it matches {} tasks",
                id_prefix,
                matches.len()
            ))),
        }
    }

    /// Shared row decoder, mirroring `ScheduleStore::query_schedules`: one unreadable row is
    /// skipped with a warning rather than failing every other task in the query.
    pub(crate) async fn query_background_tasks(
        &self,
        sql: &'static str,
        params: Vec<String>,
    ) -> crate::error::Result<Vec<BackgroundTask>> {
        let rows: Vec<BackgroundTaskRow> = self
            .connection
            .call(move |connection| -> rusqlite::Result<_> {
                let mut statement = connection.prepare(sql)?;
                let rows = statement
                    .query_map(rusqlite::params_from_iter(params.iter()), |row| {
                        Ok(BackgroundTaskRow {
                            id: row.get(0)?,
                            session_id: row.get(1)?,
                            tool: row.get(2)?,
                            label: row.get(3)?,
                            status: row.get(4)?,
                            outcome: row.get(5)?,
                            scratchpad_entry: row.get(6)?,
                            started_at: row.get(7)?,
                            finished_at: row.get(8)?,
                            announced_at: row.get(9)?,
                            delivered_at: row.get(10)?,
                            subagent_id: row.get(11)?,
                        })
                    })?
                    .collect::<std::result::Result<Vec<_>, _>>()?;
                Ok(rows)
            })
            .await
            .map_err(|error| {
                MekaError::Database(format!("failed to load background tasks: {error}"))
            })?;

        Ok(rows
            .into_iter()
            .filter_map(|row| {
                let id = row.id.clone();
                row.decode()
                    .inspect_err(|error| {
                        tracing::warn!("skipping unreadable background task {id}: {error}");
                    })
                    .ok()
            })
            .collect())
    }
}
/// Raw `background_tasks` row, decoded outside the database closure so a parse failure can be
/// logged and skipped individually.
pub(crate) struct BackgroundTaskRow {
    pub(crate) id: String,
    pub(crate) session_id: String,
    pub(crate) tool: String,
    pub(crate) label: String,
    pub(crate) status: String,
    pub(crate) outcome: Option<String>,
    pub(crate) scratchpad_entry: Option<String>,
    pub(crate) started_at: String,
    pub(crate) finished_at: Option<String>,
    pub(crate) announced_at: Option<String>,
    pub(crate) delivered_at: Option<String>,
    pub(crate) subagent_id: Option<String>,
}
impl BackgroundTaskRow {
    /// The row as a [`BackgroundTask`], or what about it did not parse.
    pub(crate) fn decode(self) -> std::result::Result<BackgroundTask, String> {
        let parse_time =
            |text: &str| -> std::result::Result<chrono::DateTime<chrono::Utc>, String> {
                chrono::DateTime::parse_from_rfc3339(text)
                    .map(|at| at.with_timezone(&chrono::Utc))
                    .map_err(|error| format!("bad timestamp '{text}': {error}"))
            };
        let parse_optional = |text: Option<String>| -> std::result::Result<_, String> {
            text.as_deref().map(parse_time).transpose()
        };

        Ok(BackgroundTask {
            id: self.id,
            session_id: Uuid::parse_str(&self.session_id)
                .map_err(|error| format!("bad session id: {error}"))?,
            tool: self.tool,
            label: self.label,
            status: self.status.parse()?,
            outcome: self.outcome,
            scratchpad_entry: self.scratchpad_entry,
            started_at: parse_time(&self.started_at)?,
            finished_at: parse_optional(self.finished_at)?,
            announced_at: parse_optional(self.announced_at)?,
            delivered_at: parse_optional(self.delivered_at)?,
            subagent_id: self
                .subagent_id
                .as_deref()
                .map(Uuid::parse_str)
                .transpose()
                .map_err(|error| format!("bad sub-agent id: {error}"))?,
        })
    }
}
/// How a task ended, or that it hasn't.
///
/// The terminal states deliver identically and differ only in their rendered header. Keeping them
/// distinct is what lets the agent tell "your build failed" from "your build never ran". The two
/// open states are told apart for the same reason: one says the work is still going, the other
/// that it has been asked to stop and has not said yet how it went.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TaskStatus {
    Running,
    /// A stop was asked for and the work has not reported since. Open: the request is not an
    /// outcome, and a row in this state is never delivered.
    Stopping,
    Completed,
    /// The tool returned an error, or panicked.
    Failed,
    /// Stopped on request, via `task_cancel` or a second Ctrl+C.
    Canceled,
    /// The process holding it went away. Reconstructed by the session-load sweep, never written by
    /// the task itself, which by definition is not around to write it.
    Interrupted,
}
impl TaskStatus {
    /// Every status, in lifecycle order.
    pub(crate) const ALL: [TaskStatus; 6] = [
        Self::Running,
        Self::Stopping,
        Self::Completed,
        Self::Failed,
        Self::Canceled,
        Self::Interrupted,
    ];

    /// Whether a finished task should wake a host, or wait for the next turn to carry it.
    ///
    /// Every terminal outcome is delivered; this decides only whether delivering it is worth a turn
    /// nobody asked for. A cancellation is always somebody's deliberate act (`/task cancel`, the
    /// `task_cancel` tool, a second Ctrl+C, `POST .../cancel`), so the one party who would learn
    /// something from the turn already knows, and a command whose whole purpose is to stop work
    /// would be starting some. The outcome still reaches the model, on the next turn there is.
    ///
    /// The others are nobody's decision: a build finished, a tool failed, or a host died holding
    /// the task. The agent asked to be told about the first two and cannot infer the third, and
    /// there may be no human about to type.
    pub(crate) fn wakes_a_host(self) -> bool {
        self.is_terminal() && !matches!(self, Self::Canceled)
    }

    /// The one spelling of this status: the `status` column, the HTTP view and `task_list`.
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Stopping => "stopping",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Canceled => "canceled",
            Self::Interrupted => "interrupted",
        }
    }

    /// The names, joined for a refusal that lists what would have been accepted.
    pub(crate) fn supported() -> String {
        Self::ALL
            .iter()
            .map(|status| status.name())
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// Whether the task has ended, whichever way.
    pub(crate) fn is_terminal(self) -> bool {
        !matches!(self, Self::Running | Self::Stopping)
    }

    /// The header word the delivered turn leads with.
    pub(crate) fn headline(self) -> &'static str {
        match self {
            Self::Running => "is still running",
            Self::Stopping => "is stopping",
            Self::Completed => "finished",
            Self::Failed => "failed",
            Self::Canceled => "was canceled",
            Self::Interrupted => "was interrupted",
        }
    }
}
impl std::fmt::Display for TaskStatus {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.name())
    }
}
impl std::str::FromStr for TaskStatus {
    type Err = String;

    /// Refuses with the names that would have been accepted; `decode` turns the refusal into a
    /// skipped row rather than a hard error, matching how the session store treats a
    /// forward-compatible event it can't read.
    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        Self::ALL
            .iter()
            .copied()
            .find(|status| status.name() == value)
            .ok_or_else(|| {
                format!(
                    "'{value}' is not a task status. Supported: {}",
                    Self::supported()
                )
            })
    }
}
/// A persisted background task.
#[derive(Debug, Clone)]
pub(crate) struct BackgroundTask {
    pub(crate) id: String,
    pub(crate) session_id: Uuid,
    /// The tool that was backgrounded, e.g. `shell_execute`.
    pub(crate) tool: String,
    /// Human-readable summary of what was started, from
    /// [`crate::tools::resolve_primary_param`]. Carried so `task_list` and the delivered turn can
    /// name the work without re-deriving it from arguments that are no longer around.
    pub(crate) label: String,
    pub(crate) status: TaskStatus,
    /// The tool's own output, for a terminal task. Truncated to
    /// [`crate::background::OUTCOME_INLINE_BYTES`] when it is also spilled to the scratchpad.
    pub(crate) outcome: Option<String>,
    /// Scratchpad entry holding the full output, when it was too large to carry inline.
    pub(crate) scratchpad_entry: Option<String>,
    pub(crate) started_at: DateTime<Utc>,
    pub(crate) finished_at: Option<DateTime<Utc>>,
    /// When subscribers were told, which is the poller's job and happens whether or not a session
    /// is ever live again. Separate from `delivered_at` because the two stopped coinciding once an
    /// outcome could wait for a turn instead of causing one.
    pub(crate) announced_at: Option<DateTime<Utc>>,
    pub(crate) delivered_at: Option<DateTime<Utc>>,
    /// The sub-agent a backgrounded `agent_spawn` or `agent_followup` drives, linked once its
    /// start step has made or found it.
    pub(crate) subagent_id: Option<Uuid>,
}
impl BackgroundTask {
    /// Short id for display, matching the width `task_cancel` accepts. Same convention as
    /// [`crate::schedule::Schedule::short_id`].
    pub(crate) fn short_id(&self) -> &str {
        self.id.get(..crate::text::ID_PREFIX).unwrap_or(&self.id)
    }

    /// How long the task ran, or has been running.
    pub(crate) fn elapsed(&self) -> chrono::Duration {
        self.finished_at.unwrap_or_else(Utc::now) - self.started_at
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn task_fixture(
        store: &Store,
        session_id: Uuid,
        label: &str,
    ) -> crate::store::background::BackgroundTask {
        let task = crate::store::background::BackgroundTask {
            id: Uuid::new_v4().to_string(),
            session_id,
            tool: "shell_execute".to_string(),
            label: label.to_string(),
            status: crate::store::background::TaskStatus::Running,
            outcome: None,
            scratchpad_entry: None,
            started_at: chrono::Utc::now(),
            finished_at: None,
            announced_at: None,
            delivered_at: None,
            subagent_id: None,
        };
        store
            .background_store()
            .start_background_task(&task)
            .await
            .expect("start background task");
        task
    }

    /// A detached spawn names the session it runs on its task's row, and the server-wide listing
    /// answers for every session, or for one status of task.
    #[tokio::test]
    async fn a_detached_spawn_names_its_sub_agent_on_the_task() {
        let store = Store::for_test().await;
        let session = store
            .create_session(None, "test-profile".to_string())
            .await
            .expect("create");
        let other = store
            .create_session(None, "test-profile".to_string())
            .await
            .expect("create");
        let spawn = task_fixture(&store, session, "agent_spawn: count the files").await;
        let command = task_fixture(&store, other, "sleep 5").await;
        store
            .background_store()
            .finish_background_task(
                &command.id,
                TaskStatus::Completed,
                Some("done".to_string()),
                None,
            )
            .await
            .expect("finish");
        let child = Uuid::new_v4();
        store
            .background_store()
            .record_task_subagent(&spawn.id, child)
            .await
            .expect("record");

        let all = store
            .background_store()
            .list_all_background_tasks(None)
            .await
            .expect("list");
        let ids: Vec<&str> = all.iter().map(|task| task.id.as_str()).collect();
        assert!(ids.contains(&spawn.id.as_str()) && ids.contains(&command.id.as_str()));
        let spawned = all.iter().find(|task| task.id == spawn.id).expect("listed");
        assert_eq!(spawned.subagent_id, Some(child));
        assert_eq!(
            all.iter()
                .find(|task| task.id == command.id)
                .expect("listed")
                .subagent_id,
            None
        );
        let running = store
            .background_store()
            .list_all_background_tasks(Some(TaskStatus::Running))
            .await
            .expect("list");
        assert_eq!(
            running
                .iter()
                .map(|task| task.id.as_str())
                .collect::<Vec<_>>(),
            vec![spawn.id.as_str()]
        );
    }

    #[tokio::test]
    async fn background_task_round_trips_through_the_database() {
        let store = Store::for_test().await;
        let session_id = store
            .create_session(None, "test-profile".to_string())
            .await
            .expect("create session");
        let written = task_fixture(&store, session_id, "cargo test --all").await;

        let running = store
            .background_store()
            .list_running_background_tasks(session_id)
            .await
            .expect("list running");
        assert_eq!(running.len(), 1);
        assert_eq!(running[0].id, written.id);
        assert_eq!(running[0].label, "cargo test --all");

        store
            .background_store()
            .finish_background_task(
                &written.id,
                crate::store::background::TaskStatus::Completed,
                Some("42 passed".to_string()),
                Some("task_log".to_string()),
            )
            .await
            .expect("finish");

        let undelivered = store
            .background_store()
            .list_undelivered_background_tasks(session_id)
            .await
            .expect("list undelivered");
        assert_eq!(undelivered.len(), 1);
        assert_eq!(
            undelivered[0].status,
            crate::store::background::TaskStatus::Completed
        );
        assert_eq!(undelivered[0].outcome.as_deref(), Some("42 passed"));
        assert_eq!(undelivered[0].scratchpad_entry.as_deref(), Some("task_log"));
        assert!(undelivered[0].finished_at.is_some());
        assert!(
            store
                .background_store()
                .list_running_background_tasks(session_id)
                .await
                .expect("list running")
                .is_empty()
        );
    }

    /// The whole point of `delivered_at`: an outcome reaches the conversation once, including
    /// across a restart that re-runs the delivery poll.
    #[tokio::test]
    async fn a_delivered_outcome_is_not_delivered_again() {
        let store = Store::for_test().await;
        let session_id = store
            .create_session(None, "test-profile".to_string())
            .await
            .expect("create session");
        let task = task_fixture(&store, session_id, "sleep 60").await;
        store
            .background_store()
            .finish_background_task(
                &task.id,
                crate::store::background::TaskStatus::Completed,
                None,
                None,
            )
            .await
            .expect("finish");

        store
            .background_store()
            .mark_background_tasks_delivered(std::slice::from_ref(&task.id))
            .await
            .expect("mark delivered");

        assert!(
            store
                .background_store()
                .list_undelivered_background_tasks(session_id)
                .await
                .expect("list undelivered")
                .is_empty()
        );
    }

    /// Two claimers, one row, exactly one winner.
    ///
    /// Listing and stamping are two statements, and there are now two claimers per host: a poller
    /// and whichever turn the user sends. Both can read the same row as undelivered before either
    /// writes, so the `WHERE delivered_at IS NULL` on the stamp is the only arbiter -- without it
    /// both render the same outcome and the model is told twice.
    ///
    /// Two managers over one file on disk, not two clones of one store: a clone shares an
    /// `Arc<Connection>` and therefore one worker thread, so the two claims cannot interleave and
    /// the test proves only that the statement is atomic against itself. Separate connections are
    /// what a second Meka process actually is.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn only_one_of_two_racing_claimers_takes_each_outcome() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("meka.db");
        let store = Store::open(Some(&path), &Default::default())
            .await
            .expect("open");
        let rival = Store::open(Some(&path), &Default::default())
            .await
            .expect("a second connection to the same file");
        let session_id = store
            .create_session(None, "test-profile".to_string())
            .await
            .expect("create session");
        const ROWS: usize = 24;
        for index in 0..ROWS {
            let task = task_fixture(&store, session_id, &format!("job {index}")).await;
            store
                .background_store()
                .finish_background_task(
                    &task.id,
                    crate::store::background::TaskStatus::Completed,
                    None,
                    None,
                )
                .await
                .expect("finish");
        }

        let first = {
            let store = store.clone();
            tokio::spawn(
                async move { crate::background::claim_outcomes_now(&store, session_id).await },
            )
        };
        let second = {
            let store = rival;
            tokio::spawn(
                async move { crate::background::claim_outcomes_now(&store, session_id).await },
            )
        };
        let (first, second) = (first.await.expect("join"), second.await.expect("join"));

        let mut seen: Vec<String> = first
            .iter()
            .chain(second.iter())
            .map(|task| task.id.clone())
            .collect();
        let total = seen.len();
        seen.sort();
        seen.dedup();
        assert_eq!(
            total, ROWS,
            "every outcome must be claimed exactly once across both claimers, not {total}"
        );
        assert_eq!(
            seen.len(),
            ROWS,
            "and no id may appear in both claims: that is one outcome delivered twice"
        );
        assert!(
            store
                .background_store()
                .list_undelivered_background_tasks(session_id)
                .await
                .expect("list undelivered")
                .is_empty(),
            "and nothing may be left behind"
        );
    }

    /// The same arbitration for the announce stamp, which decides who fires `task.finished`.
    ///
    /// Two connections for the reason its sibling gives: one store cloned is one worker thread.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn only_one_of_two_racing_announcers_takes_each_outcome() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("meka.db");
        let store = Store::open(Some(&path), &Default::default())
            .await
            .expect("open");
        let rival = Store::open(Some(&path), &Default::default())
            .await
            .expect("a second connection to the same file");
        let session_id = store
            .create_session(None, "test-profile".to_string())
            .await
            .expect("create session");
        const ROWS: usize = 24;
        let mut ids = Vec::new();
        for index in 0..ROWS {
            let task = task_fixture(&store, session_id, &format!("job {index}")).await;
            store
                .background_store()
                .finish_background_task(
                    &task.id,
                    crate::store::background::TaskStatus::Canceled,
                    None,
                    None,
                )
                .await
                .expect("finish");
            ids.push(task.id);
        }

        // Both read the row as unannounced first, which is what the two callers really do.
        let first = {
            let (store, ids) = (store.clone(), ids.clone());
            tokio::spawn(async move {
                store
                    .background_store()
                    .mark_background_tasks_announced(&ids)
                    .await
                    .expect("announce")
            })
        };
        let second = {
            let (store, ids) = (rival, ids.clone());
            tokio::spawn(async move {
                store
                    .background_store()
                    .mark_background_tasks_announced(&ids)
                    .await
                    .expect("announce")
            })
        };
        let (first, second) = (first.await.expect("join"), second.await.expect("join"));

        assert_eq!(
            first.len() + second.len(),
            ROWS,
            "a subscriber must hear about each task once: {} + {}",
            first.len(),
            second.len()
        );
        let mut seen: Vec<&String> = first.iter().chain(second.iter()).collect();
        seen.sort();
        seen.dedup();
        assert_eq!(seen.len(), ROWS, "and no id may be won twice");
    }

    /// Each stamp is won once, and the loser is told it won nothing.
    ///
    /// The stamps are compare-and-swaps and they return the rows they took, which is what every
    /// caller filters its report by. A second attempt on an already-stamped row must come back
    /// empty rather than claiming it again -- that empty answer is what stops a second webhook and
    /// a second delivery. The concurrent case is
    /// [`only_one_of_two_racing_claimers_takes_each_outcome`]; this is the sequential contract the
    /// callers read.
    #[tokio::test]
    async fn a_second_attempt_on_a_stamped_row_wins_nothing() {
        let store = Store::for_test().await;
        let session_id = store
            .create_session(None, "test-profile".to_string())
            .await
            .expect("create session");
        let task = task_fixture(&store, session_id, "cargo build").await;
        store
            .background_store()
            .finish_background_task(
                &task.id,
                crate::store::background::TaskStatus::Completed,
                None,
                None,
            )
            .await
            .expect("finish");
        let ids = vec![task.id.clone()];

        assert_eq!(
            store
                .background_store()
                .mark_background_tasks_delivered(&ids)
                .await
                .expect("deliver"),
            ids,
            "the first claimer wins the row"
        );
        assert!(
            store
                .background_store()
                .mark_background_tasks_delivered(&ids)
                .await
                .expect("deliver")
                .is_empty(),
            "and the second wins nothing, so it reports nothing"
        );

        assert_eq!(
            store
                .background_store()
                .mark_background_tasks_announced(&ids)
                .await
                .expect("announce"),
            ids,
            "the first announcer wins the row"
        );
        assert!(
            store
                .background_store()
                .mark_background_tasks_announced(&ids)
                .await
                .expect("announce")
                .is_empty(),
            "and the second sends no second `task.finished`"
        );
    }

    /// A task that goes terminal between the poller's two queries is still announced.
    ///
    /// The sweep asks `list_unannounced_background_tasks` and then, separately,
    /// `list_undelivered_background_tasks`. A task finishing in the gap is absent from the first
    /// and present in the second, so it was delivered and then unannounceable forever -- both
    /// pools exclude a delivered row. Announcing the claimed batch as well closes it, and is
    /// idempotent because the stamp is a compare-and-swap.
    #[tokio::test]
    async fn a_task_finishing_between_the_two_queries_is_still_announced() {
        let store = Store::for_test().await;
        let session_id = store
            .create_session(None, "test-profile".to_string())
            .await
            .expect("create session");

        // The announce pass runs first and sees nothing: the task is still running.
        let early = store
            .background_store()
            .list_unannounced_background_tasks(session_id)
            .await
            .expect("list unannounced");
        let task = task_fixture(&store, session_id, "cargo build").await;
        assert!(
            early.iter().all(|seen| seen.id != task.id),
            "the task must not be in the earlier snapshot"
        );

        // It finishes in the gap, so the delivery pass is the first to see it.
        store
            .background_store()
            .finish_background_task(
                &task.id,
                crate::store::background::TaskStatus::Completed,
                None,
                None,
            )
            .await
            .expect("finish");
        let claimed = crate::background::claim_outcomes_now(&store, session_id).await;
        assert_eq!(claimed.len(), 1, "the delivery pass claims it");
        assert!(
            claimed[0].announced_at.is_none(),
            "and it is still unannounced at the point the caller must act on"
        );

        // Which is why the claimed batch is announced too: nothing else ever can.
        let ids: Vec<String> = claimed.iter().map(|task| task.id.clone()).collect();
        let won = store
            .background_store()
            .mark_background_tasks_announced(&ids)
            .await
            .expect("announce");
        assert_eq!(won, ids, "the claim is the last chance to announce it");
        assert!(
            store
                .background_store()
                .list_unannounced_background_tasks(session_id)
                .await
                .expect("list unannounced")
                .is_empty(),
            "and afterwards no pool can return it: a delivered row is excluded from both"
        );
    }

    /// The announce pool is the undelivered pool, so old news is never pushed as new.
    ///
    /// `announced_at` is written only by `meka serve`, and a data directory is shared: every task a
    /// screen or ACP session ever ran sits unannounced forever. Opening one of those sessions in
    /// `meka serve` must not fire `task.finished` for work that finished weeks ago and was reported
    /// to the model at the time. A task still undelivered has been reported to nobody, which is the
    /// case worth pushing -- including one interrupted before any host could report it.
    #[tokio::test]
    async fn an_outcome_already_reported_is_not_announced_as_news() {
        let store = Store::for_test().await;
        let session_id = store
            .create_session(None, "test-profile".to_string())
            .await
            .expect("create session");
        let reported = task_fixture(&store, session_id, "cargo build").await;
        let unreported = task_fixture(&store, session_id, "sleep 600").await;
        for task in [&reported, &unreported] {
            store
                .background_store()
                .finish_background_task(
                    &task.id,
                    crate::store::background::TaskStatus::Completed,
                    None,
                    None,
                )
                .await
                .expect("finish");
        }

        // Delivered without being announced, which is exactly what a screen turn leaves behind.
        store
            .background_store()
            .mark_background_tasks_delivered(std::slice::from_ref(&reported.id))
            .await
            .expect("mark delivered");

        let unannounced = store
            .background_store()
            .list_unannounced_background_tasks(session_id)
            .await
            .expect("list unannounced");
        assert_eq!(
            unannounced.iter().map(|task| &task.id).collect::<Vec<_>>(),
            vec![&unreported.id],
            "only the outcome nobody has had is news"
        );

        store
            .background_store()
            .mark_background_tasks_announced(std::slice::from_ref(&unreported.id))
            .await
            .expect("mark announced");
        assert!(
            store
                .background_store()
                .list_unannounced_background_tasks(session_id)
                .await
                .expect("list unannounced")
                .is_empty(),
            "and it is announced once, not on every poll"
        );
    }

    /// A task in flight when the process died would otherwise leave the agent waiting on a report
    /// that can never arrive, having usually already promised one.
    #[tokio::test]
    async fn the_sweep_retires_tasks_left_running_by_a_dead_process() {
        let store = Store::for_test().await;
        let session_id = store
            .create_session(None, "test-profile".to_string())
            .await
            .expect("create session");
        task_fixture(&store, session_id, "sleep 600").await;

        let swept = store
            .background_store()
            .sweep_interrupted_background_tasks_except(session_id, &[])
            .await
            .expect("sweep");
        assert_eq!(swept, 1);

        let undelivered = store
            .background_store()
            .list_undelivered_background_tasks(session_id)
            .await
            .expect("list undelivered");
        assert_eq!(undelivered.len(), 1);
        assert_eq!(
            undelivered[0].status,
            crate::store::background::TaskStatus::Interrupted,
            "the agent must be told the work stopped, not left waiting"
        );

        // Idempotent: a second attach must not re-report what the first already retired.
        assert_eq!(
            store
                .background_store()
                .sweep_interrupted_background_tasks_except(session_id, &[])
                .await
                .expect("second sweep"),
            0
        );
    }

    /// The shape a `--oneshot` resume hits: the previous process died mid-task, so the sweep
    /// produces an outcome that no task in *this* process is waiting on. A host that only looked
    /// for outcomes when it had started something itself would answer the prompt and exit with that
    /// report still sitting undelivered.
    #[tokio::test]
    async fn a_swept_outcome_is_pending_for_a_process_that_started_nothing() {
        let store = Store::for_test().await;
        let session_id = store
            .create_session(None, "test-profile".to_string())
            .await
            .expect("create session");
        task_fixture(&store, session_id, "sleep 400").await;

        // A fresh process takes the session: it holds no handles, and the sweep is all it knows.
        store
            .background_store()
            .sweep_interrupted_background_tasks_except(session_id, &[])
            .await
            .expect("sweep");

        let ready = store
            .background_store()
            .list_undelivered_background_tasks(session_id)
            .await
            .expect("list undelivered");
        assert_eq!(ready.len(), 1, "the report must be waiting to be collected");
        assert_eq!(
            ready[0].status,
            crate::store::background::TaskStatus::Interrupted
        );
    }

    /// A canceled task whose work happens to finish a moment later must not overwrite the
    /// cancellation and report success. The cancellation's own word says what was and was not
    /// established: the work ended, so its teardown is behind it, and a routed command's remote
    /// side is not something stopping here can speak for.
    #[tokio::test]
    async fn the_first_terminal_write_wins() {
        let store = Store::for_test().await;
        let session_id = store
            .create_session(None, "test-profile".to_string())
            .await
            .expect("create session");
        let task = task_fixture(&store, session_id, "sleep 600").await;

        store
            .background_store()
            .finish_background_task(
                &task.id,
                crate::store::background::TaskStatus::Canceled,
                None,
                None,
            )
            .await
            .expect("cancel");
        store
            .background_store()
            .finish_background_task(
                &task.id,
                crate::store::background::TaskStatus::Completed,
                Some("finished anyway".to_string()),
                None,
            )
            .await
            .expect("late completion is accepted but ignored");

        let undelivered = store
            .background_store()
            .list_undelivered_background_tasks(session_id)
            .await
            .expect("list undelivered");
        assert_eq!(
            undelivered[0].status,
            crate::store::background::TaskStatus::Canceled
        );
        let outcome = undelivered[0].outcome.as_deref().unwrap_or_default();
        assert!(outcome.contains("local teardown is confirmed"), "{outcome}");
        assert!(
            !outcome.contains("finished anyway"),
            "the late result must not be carried into the cancellation: {outcome}"
        );
    }

    /// A stop request is a state of its own, not an outcome: the row leaves the running pools'
    /// delivery side but stays open, so the work's own result is what the agent is told. Writing
    /// `canceled` here would make that result unwritable, which is how the reported outcome came to
    /// be the stop's guess at the teardown rather than the teardown.
    #[tokio::test]
    async fn a_stop_request_is_not_an_outcome() {
        let store = Store::for_test().await;
        let session_id = store
            .create_session(None, "test-profile".to_string())
            .await
            .expect("create session");
        let task = task_fixture(&store, session_id, "sleep 600").await;

        let requested = store
            .background_store()
            .request_stop_background_tasks(vec![task.id.clone()])
            .await
            .expect("request");
        assert_eq!(requested, vec![task.id.clone()]);

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
                .expect("list undelivered")
                .is_empty(),
            "a request must never be delivered as the outcome"
        );
        assert!(
            store
                .background_store()
                .list_unannounced_background_tasks(session_id)
                .await
                .expect("list unannounced")
                .is_empty(),
            "and never announced as one either"
        );
        assert_eq!(
            store
                .background_store()
                .list_running_background_tasks(session_id)
                .await
                .expect("list running")
                .iter()
                .map(|task| task.status)
                .collect::<Vec<_>>(),
            vec![TaskStatus::Stopping],
            "it is still running, and says it is stopping"
        );

        // A second request has nothing left to move, and the work's result still ends the row.
        assert!(
            store
                .background_store()
                .request_stop_background_tasks(vec![task.id.clone()])
                .await
                .expect("request again")
                .is_empty()
        );
        store
            .background_store()
            .finish_background_task(
                &task.id,
                TaskStatus::Canceled,
                Some("Tool execution interrupted.".to_string()),
                None,
            )
            .await
            .expect("finish");
        let delivered = store
            .background_store()
            .list_undelivered_background_tasks(session_id)
            .await
            .expect("list undelivered");
        assert_eq!(delivered.len(), 1);
        assert_eq!(delivered[0].status, TaskStatus::Canceled);
        let outcome = delivered[0].outcome.as_deref().unwrap_or_default();
        assert!(outcome.contains("local teardown is confirmed"), "{outcome}");
        assert!(
            outcome.contains("Tool execution interrupted."),
            "the work's own report is kept: {outcome}"
        );
    }

    /// An outcome nothing confirmed says which side could not be confirmed: a routed command's
    /// remote state, a WSL command's guest state, or what an unrecorded run started beyond this
    /// process. A call that never runs code beyond this process has no route to hedge about, and a
    /// routed call whose route was never recorded must not borrow another route's caveat.
    #[tokio::test]
    async fn an_unconfirmed_stop_carries_the_evidence_for_its_route() {
        async fn unconfirmed_outcome(
            store: &Store,
            session_id: Uuid,
            tool: &'static str,
            route: RouteEvidence,
        ) -> String {
            let task = BackgroundTask {
                id: Uuid::new_v4().to_string(),
                session_id,
                tool: tool.to_string(),
                label: "make".to_string(),
                status: TaskStatus::Running,
                outcome: None,
                scratchpad_entry: None,
                started_at: chrono::Utc::now(),
                finished_at: None,
                announced_at: None,
                delivered_at: None,
                subagent_id: None,
            };
            store
                .background_store()
                .start_background_task(&task)
                .await
                .expect("record");
            store
                .background_store()
                .finish_background_task_observed(
                    &task.id,
                    TaskStatus::Canceled,
                    None,
                    None,
                    Teardown {
                        started: true,
                        confirmed: false,
                        route,
                        reason: Some(StopReason::UserRequest),
                    },
                )
                .await
                .expect("finish");
            store
                .background_store()
                .list_undelivered_background_tasks(session_id)
                .await
                .expect("list undelivered")
                .into_iter()
                .find(|row| row.id == task.id)
                .expect("delivered")
                .outcome
                .unwrap_or_default()
        }

        let store = Store::for_test().await;
        let session_id = store
            .create_session(None, "test-profile".to_string())
            .await
            .expect("create session");

        let remote =
            unconfirmed_outcome(&store, session_id, "shell_execute", RouteEvidence::Remote).await;
        assert!(
            remote.contains("remote command's state is unknown"),
            "{remote}"
        );
        assert!(!remote.contains("local teardown is confirmed"), "{remote}");

        // A WSL command must not inherit the SSH caveat: the side it cannot reach is the guest.
        let guest =
            unconfirmed_outcome(&store, session_id, "shell_execute", RouteEvidence::Guest).await;
        assert!(
            guest.contains("guest command's state is unknown"),
            "{guest}"
        );
        assert!(!guest.contains("remote command"), "{guest}");

        // A routed command whose route was never recorded can borrow neither caveat; the hedge
        // says what is actually unknown.
        let unrecorded = unconfirmed_outcome(
            &store,
            session_id,
            "shell_execute",
            RouteEvidence::Unrecorded,
        )
        .await;
        assert!(
            unrecorded.contains("The run recorded no route for this call"),
            "{unrecorded}"
        );
        assert!(!unrecorded.contains("the remote command"), "{unrecorded}");
        assert!(!unrecorded.contains("the guest command"), "{unrecorded}");

        let local =
            unconfirmed_outcome(&store, session_id, "agent_spawn", RouteEvidence::Unrecorded).await;
        assert!(local.contains("local teardown is unconfirmed"), "{local}");
        assert!(!local.contains("recorded no route"), "{local}");
        assert!(!local.contains("remote command"), "{local}");
    }

    /// A process that died between recording a stop and hearing the result leaves the row
    /// `stopping`. The sweep is what ends it, and it has to end it as the stop it was: unconfirmed,
    /// hedged for a tool that runs code beyond this process.
    #[tokio::test]
    async fn a_stop_left_by_a_dead_process_is_swept_as_an_unconfirmed_stop() {
        let store = Store::for_test().await;
        let session_id = store
            .create_session(None, "test-profile".to_string())
            .await
            .expect("create session");
        let task = task_fixture(&store, session_id, "sleep 600").await;
        store
            .background_store()
            .request_stop_background_tasks(vec![task.id.clone()])
            .await
            .expect("request");

        assert_eq!(
            store
                .background_store()
                .sweep_interrupted_background_tasks_except(session_id, &[])
                .await
                .expect("sweep"),
            1
        );
        let delivered = store
            .background_store()
            .list_undelivered_background_tasks(session_id)
            .await
            .expect("list undelivered");
        assert_eq!(delivered.len(), 1);
        assert_eq!(
            delivered[0].status,
            crate::store::background::TaskStatus::Interrupted
        );
        let outcome = delivered[0].outcome.as_deref().unwrap_or_default();
        assert!(
            outcome.contains("local teardown is unconfirmed"),
            "the stop was never answered by the work: {outcome}"
        );
        assert!(
            outcome.contains("The run recorded no route for this call"),
            "what a routed command started beyond this process is the unknown part: {outcome}"
        );
    }

    /// The sweep ends rows whose owners are gone and spares rows whose owners are live in this
    /// process: a row with a live handle behind it has an owner that can still report, and ending
    /// it would race that owner's own result.
    #[tokio::test]
    async fn the_sweep_spares_tasks_whose_owners_are_still_live() {
        let store = Store::for_test().await;
        let session_id = store
            .create_session(None, "test-profile".to_string())
            .await
            .expect("create session");
        let owned = task_fixture(&store, session_id, "sleep 600").await;
        let orphaned = task_fixture(&store, session_id, "sleep 601").await;

        assert_eq!(
            store
                .background_store()
                .sweep_interrupted_background_tasks_except(
                    session_id,
                    std::slice::from_ref(&owned.id)
                )
                .await
                .expect("sweep"),
            1,
            "only the row whose owner is gone is retired"
        );
        assert!(
            store
                .background_store()
                .background_task_by_id(&owned.id)
                .await
                .expect("load")
                .expect("row")
                .finished_at
                .is_none(),
            "the live owner's row is untouched, and it still reports in its own time"
        );
        assert_eq!(
            store
                .background_store()
                .background_task_by_id(&orphaned.id)
                .await
                .expect("load")
                .expect("row")
                .status,
            TaskStatus::Interrupted
        );

        // Once the owner is gone too, the sweep retires the rest.
        assert_eq!(
            store
                .background_store()
                .sweep_interrupted_background_tasks_except(session_id, &[])
                .await
                .expect("second sweep"),
            1
        );
    }

    /// A start claim only wins against a row nothing has stopped: a stop that recorded its intent
    /// first owns the row, and a row that already ended keeps the end it has.
    #[tokio::test]
    async fn a_start_claim_yields_to_a_stop_that_recorded_first() {
        let store = Store::for_test().await;
        let session_id = store
            .create_session(None, "test-profile".to_string())
            .await
            .expect("create session");
        let task = task_fixture(&store, session_id, "sleep 600").await;

        assert!(
            store
                .background_store()
                .claim_task_start(&task.id)
                .await
                .expect("first claim"),
            "an open row is the start's to claim"
        );
        store
            .background_store()
            .request_stop_background_tasks(vec![task.id.clone()])
            .await
            .expect("request");
        assert!(
            !store
                .background_store()
                .claim_task_start(&task.id)
                .await
                .expect("claim after the stop"),
            "a recorded stop intent owns the row: the work must not start"
        );

        store
            .background_store()
            .finish_background_task(&task.id, TaskStatus::Canceled, None, None)
            .await
            .expect("finish");
        assert!(
            !store
                .background_store()
                .claim_task_start(&task.id)
                .await
                .expect("claim after the end"),
            "a natural terminal write that already won stays"
        );
    }

    #[tokio::test]
    async fn resolve_background_task_by_prefix() {
        let store = Store::for_test().await;
        let session_id = store
            .create_session(None, "test-profile".to_string())
            .await
            .expect("create session");
        let task = task_fixture(&store, session_id, "sleep 60").await;

        let found = store
            .background_store()
            .resolve_background_task(session_id, &task.id[..8])
            .await
            .expect("resolve")
            .expect("matched");
        assert_eq!(found.id, task.id);

        assert!(
            store
                .background_store()
                .resolve_background_task(session_id, "zzzzzzzz")
                .await
                .expect("resolve")
                .is_none()
        );
    }

    #[tokio::test]
    async fn deleting_a_session_cascades_to_its_background_tasks() {
        let store = Store::for_test().await;
        let session_id = store
            .create_session(None, "test-profile".to_string())
            .await
            .expect("create session");
        task_fixture(&store, session_id, "sleep 600").await;

        store
            .delete_session(session_id)
            .await
            .expect("delete session");

        assert!(
            store
                .background_store()
                .list_background_tasks(session_id)
                .await
                .expect("list")
                .is_empty()
        );
    }
}
