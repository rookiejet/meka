//! Background tool calls: work the agent starts and does not wait for.
//!
//! An ordinary tool call blocks the turn until it returns. That is right for a file read and wrong
//! for a twenty-minute build, where the agent's only alternatives today are to hold the turn open
//! or to approximate detachment with `nohup … &` and then poll for a result nothing will announce.
//!
//! A backgrounded call returns a handle immediately and delivers its outcome later: as a turn, over
//! the same path [`crate::schedule`] already uses to inject one from outside the conversation, or,
//! while a turn is running, inside it at its next round boundary, the way a steer reaches it.
//!
//! The invariant that shapes everything here: **a task always ends in a delivered outcome.**
//! [`crate::agent::Agent::run_turn`] is not resumable mid-tool-loop, so work in flight when the
//! process dies cannot be recovered. Silence would be worse than never having offered, because the
//! agent has usually already told someone it would report back. So a task that cannot finish is
//! [`crate::store::background::TaskStatus::Interrupted`] and is delivered as such, and the lease
//! that decides *when* a task counts as dead is the session lock itself
//! ([`crate::store::Store::lock_session`]): holding it means nothing else can still be running that
//! session's tasks.

use chrono::Utc;
use uuid::Uuid;

use crate::store::background::{BackgroundTask, StopReason};

/// Live handles for the tasks *this process* started.
///
/// The database row is the durable record; this is the control surface. Deliberately not persisted
/// and deliberately not global: a `CancellationToken` cannot outlive the process holding it, and a
/// task started elsewhere is not this process's to stop. That asymmetry is exactly why the
/// session-load sweep exists, since a row with no handle behind it is a task nobody can finish.
#[derive(Clone, Default)]
pub(crate) struct BackgroundTasks {
    inner: std::sync::Arc<tokio::sync::Mutex<std::collections::HashMap<String, TaskHandle>>>,
}

struct TaskHandle {
    session_id: Uuid,
    cancellation: tokio_util::sync::CancellationToken,
    /// Flipped once the work is over, and readable any number of times, by any number of waiters:
    /// a wait must not consume the thing that says the task is done, or a second wait (after a
    /// first one was cut short by a timeout, or alongside it) would return as if it were.
    ///
    /// The sender is dropped with the handle, which a waiter reads as done too: the entry is what
    /// a stop reaches, so its removal means there is nothing left here to wait for.
    completion: tokio::sync::watch::Sender<bool>,
    /// The stop this task was claimed by: the status its outcome reports in place of the failure
    /// an interruption reads as, and who asked for it. Set the moment a stop claims the task and
    /// before the token is fired, so a start that claims afterwards sees the stop even though the
    /// signal has only just been sent. First claim wins: a repeat stop re-fires the token but
    /// cannot reword an end already chosen.
    ///
    /// The reason is `None` for a stop that reached this owner through the durable record alone
    /// (`deliver_durable_stops`), whose requester is another process's to know.
    stopped: Option<Stopped>,
}

/// A stop's live claim on a task; see [`TaskHandle::stopped`].
type Stopped = (
    crate::store::background::TaskStatus,
    Option<crate::store::background::StopReason>,
);

/// One observation of a task's completion, taken from [`BackgroundTasks::completion`].
///
/// Separate from the handle so it can outlive the wait that took it: what it observes is a
/// `watch` channel, and subscribing is what repeats, not waiting on a taken join.
pub(crate) struct TaskCompletion(tokio::sync::watch::Receiver<bool>);

impl TaskCompletion {
    /// Wait until the work is over. Repeatable, in that another observation can be taken and
    /// waited on for the same task; a `watch` receiver is not a queue and nothing is consumed.
    pub(crate) async fn wait(mut self) {
        loop {
            if *self.0.borrow_and_update() {
                return;
            }
            if self.0.changed().await.is_err() {
                // The sender is gone, so its handle was dropped: nothing is left to wait for.
                return;
            }
        }
    }
}

impl BackgroundTasks {
    /// Claim a slot for `session_id`, or refuse because the ceiling is full. The cancellation
    /// token and the completion signal are both created here, so a stop or a wait works in the
    /// window before the work is spawned as well as after.
    ///
    /// Check and insert happen under one lock, which is the whole point. Several background calls
    /// in a single assistant message are dispatched concurrently by `execute_tool_calls`, so a
    /// separate count-then-register would let every one of them read the same pre-registration
    /// count and sail past a ceiling of one.
    pub(crate) async fn try_reserve(
        &self,
        id: String,
        session_id: Uuid,
        cancellation: tokio_util::sync::CancellationToken,
        max_tasks: usize,
    ) -> bool {
        let mut guard = self.inner.lock().await;
        let mut running = guard
            .values()
            .filter(|handle| handle.session_id == session_id)
            .count();
        // Work a release left settling still counts against the session's ceiling: it is as much
        // in flight as anything in this registry, and undercounting would let a session overspawn.
        for registry in released_registries(session_id) {
            running += registry
                .inner
                .lock()
                .await
                .values()
                .filter(|handle| handle.session_id == session_id)
                .count();
        }
        if running >= max_tasks {
            return false;
        }
        let (completion, _) = tokio::sync::watch::channel(false);
        guard.insert(id, TaskHandle {
            session_id,
            cancellation,
            completion,
            stopped: None,
        });
        true
    }

    /// What task `id`'s work records: the status and the stop reason behind it. A success is
    /// `completed` with no reason; a failure reports the stop that claimed the task if one did
    /// (its status in place of the failure the interruption reads as), else `failed`. A task
    /// stopped while it was starting has no row for a stop to record on, so its own outcome is the
    /// one place that can say why it ended.
    pub(crate) async fn outcome_end(
        &self,
        id: &str,
        is_error: bool,
    ) -> (
        crate::store::background::TaskStatus,
        Option<crate::store::background::StopReason>,
    ) {
        use crate::store::background::TaskStatus;
        if !is_error {
            return (TaskStatus::Completed, None);
        }
        match self
            .inner
            .lock()
            .await
            .get(id)
            .and_then(|handle| handle.stopped)
        {
            Some((status, reason)) => (status, reason),
            None => (TaskStatus::Failed, None),
        }
    }

    /// Attach the spawned work to a slot already reserved by [`Self::try_reserve`].
    ///
    /// The join is watched by a supervisor rather than held for a waiter to take, so the
    /// completion outlives the first wait: a wait that is cut short, or one that never comes,
    /// leaves the same signal for the next.
    pub(crate) async fn attach(&self, id: &str, join: tokio::task::JoinHandle<()>) {
        let Some(completion) = self
            .inner
            .lock()
            .await
            .get(id)
            .map(|handle| handle.completion.clone())
        else {
            // The slot is gone (a start nothing admitted, or work that already forgot itself), so
            // nothing here will wait for this: drop the handle and let the work finish on its own.
            return;
        };
        tokio::spawn(async move {
            if let Err(error) = join.await {
                tracing::warn!("background task ended abnormally: {error}");
            }
            completion.send_replace(true);
        });
    }

    /// An observation of task `id`'s completion, or `None` when this process does not hold it.
    ///
    /// Several may be outstanding at once, and another may be taken after one has been waited on:
    /// the signal is a `watch`, not a join handle, so observing it cannot take it from anyone else.
    pub(crate) async fn completion(&self, id: &str) -> Option<TaskCompletion> {
        self.inner
            .lock()
            .await
            .get(id)
            .map(|handle| TaskCompletion(handle.completion.subscribe()))
    }

    /// Drop a task's handle: on the way out of the work itself, and on the failure path between
    /// reserving a slot and spawning into it, so a refused start cannot leak the reservation and
    /// shrink the ceiling for the rest of the session.
    pub(crate) async fn forget(&self, id: &str) {
        self.inner.lock().await.remove(id);
    }

    /// How many tasks this process is running that nothing has told to stop, across sessions,
    /// since the screen that asks cannot name one for the same reason [`Self::cancel_all`] cannot.
    /// One told to stop is on its way out (its row already `stopping`, its outcome to be written
    /// by the work that accepted the stop) so the screen's move to another session does not wait
    /// for it and its survivor line does not count it.
    pub(crate) async fn unstopped_count_all(&self) -> usize {
        self.inner
            .lock()
            .await
            .values()
            .filter(|handle| !handle.cancellation.is_cancelled())
            .count()
    }

    /// How many of `session_id`'s tasks are running here, work a release left settling included.
    /// Backs the `max_tasks` ceiling: the ceiling is about how much the session has in flight in
    /// this process, not about which registry remembers it.
    pub(crate) async fn running_count(&self, session_id: Uuid) -> usize {
        let mut running = self.live_ids(session_id).await.len();
        for registry in released_registries(session_id) {
            running += registry.live_ids(session_id).await.len();
        }
        running
    }

    /// Claim one task's stop at the registry gate and fire its token: the whole live half of a
    /// stop, done under the lock and before anything awaits, so a start that claims afterwards
    /// sees the stop even though the signal has only just been sent, and the signal cannot be lost
    /// to a requesting future that disappears at the next await. `false` when this process holds
    /// no such task, which is the honest answer for one whose process is gone: its row is swept,
    /// not canceled.
    ///
    /// The first claim wins the recorded status and reason; the token is re-fired regardless, so a
    /// retry re-signals an open `stopping` task rather than trusting a record that may never have
    /// reached its owner. A `None` reason is a stop that arrived through the durable record alone,
    /// whose requester is another process's to know.
    ///
    /// `session_id` scopes the walk of released registries: task ids are unique in production, but
    /// a session's registry is the only place its ids can live, and keeping the walk to the one
    /// session is what keeps two sessions' work from answering for each other.
    pub(crate) async fn claim_stop(
        &self,
        session_id: Uuid,
        id: &str,
        reason: Option<StopReason>,
    ) -> bool {
        if Self::claim_stop_here(self, id, reason).await {
            return true;
        }
        // A release whose work is still settling keeps its registry here; the task the caller
        // names may be in one of those rather than in this one.
        for registry in released_registries(session_id) {
            if Self::claim_stop_here(&registry, id, reason).await {
                return true;
            }
        }
        false
    }

    /// [`Self::claim_stop`] for this registry alone: what the released-registry walk above calls
    /// on each of them, without recursing into the walk again.
    async fn claim_stop_here(&self, id: &str, reason: Option<StopReason>) -> bool {
        let claim = match reason {
            Some(reason) => (reason.status(), Some(reason)),
            None => (crate::store::background::TaskStatus::Canceled, None),
        };
        let mut guard = self.inner.lock().await;
        let Some(handle) = guard.get_mut(id) else {
            return false;
        };
        handle.stopped.get_or_insert(claim);
        handle.cancellation.cancel();
        drop(guard);
        true
    }

    /// Stop every task this process runs, recording the request for each, returning how many were
    /// signaled.
    ///
    /// The claim under the registry's lock comes first and the durable record second, without the
    /// lock held across it: the signal is delivered even if this future disappears before the
    /// record lands, and a record that lands without one is re-signaled by the next stop request.
    /// Every task in the registry is signaled, a task still starting whose row has not landed
    /// included, since nothing else would stop it, and its outcome reports `status`
    /// ([`Self::outcome_end`]). One whose outcome already landed keeps it. A request that cannot
    /// be recorded stops them all the same: stopping is what was asked, and only the recorded word
    /// is lost.
    pub(crate) async fn stop_all(
        &self,
        store: &crate::store::background::BackgroundStore,
        status: crate::store::background::TaskStatus,
    ) -> usize {
        let ids: Vec<String> = self.inner.lock().await.keys().cloned().collect();
        let signaled = self.cancel_all(status).await;
        if let Err(error) = store.request_stop_background_tasks(ids).await {
            tracing::warn!(
                "failed to record background tasks as {status}; stopping them anyway: {error}",
                status = status.name()
            );
        }
        signaled
    }

    /// Signal every task this process is running, each left `status` for its outcome to report,
    /// returning how many were signaled: the signal [`Self::stop_all`] sends once it has recorded
    /// why.
    pub(crate) async fn cancel_all(&self, status: crate::store::background::TaskStatus) -> usize {
        let mut guard = self.inner.lock().await;
        for handle in guard.values_mut() {
            handle
                .stopped
                .get_or_insert((status, Some(StopReason::matching(status))));
            handle.cancellation.cancel();
        }
        guard.len()
    }

    /// The one stop path every surface converges on: claim the live stop and signal the owner in
    /// this process, record the durable acceptance, and answer honestly which of the two
    /// happened.
    ///
    /// The claim is under the registry's lock before any await ([`Self::claim_stop`]), so a start
    /// that claims after it cannot win, and the signal is delivered even if this future disappears
    /// before the record lands. The record is the retryable acceptance: a row left `stopping` is
    /// what a later request re-signals against, which is why a repeat request on one signals again
    /// rather than reporting success from a state where a prior attempt never reached its owner.
    ///
    /// A stop with no live owner in this process records pending intent at most and says so in the
    /// answer; it never claims a terminal outcome for the work, because a missing in-process
    /// handle is not evidence of anything having ended. Only the work's own result or the
    /// owner-loss sweep ends a row.
    pub(crate) async fn request_stop(
        &self,
        store: &crate::store::background::BackgroundStore,
        session_id: Uuid,
        id: &str,
        reason: StopReason,
    ) -> crate::error::Result<StopReport> {
        let signaled = self.claim_stop(session_id, id, Some(reason)).await;
        let moved = !store
            .request_stop_background_tasks(vec![id.to_string()])
            .await?
            .is_empty();
        if moved {
            return Ok(stop_report(signaled, true, false));
        }
        // The move takes only a `running` row; what it left untouched says why.
        match store.background_task_by_id(id).await? {
            // A prior request's acceptance is already recorded, so this one re-signaled it.
            Some(row) if row.status == crate::store::background::TaskStatus::Stopping => {
                Ok(stop_report(signaled, true, true))
            }
            // Its own outcome won and stays.
            Some(row) if row.status.is_terminal() => Ok(StopReport::AlreadyEnded),
            // The row has not landed yet (a reservation still starting), or a launch landed it
            // after the move: only the first of those is live here, and only it was signaled.
            None if signaled => Ok(stop_report(signaled, false, false)),
            None => Ok(StopReport::AlreadyEnded),
            Some(_) => Ok(stop_report(signaled, false, false)),
        }
    }

    /// [`Self::request_stop`] for everything still open in a session: the `task_cancel` all-case
    /// and the screens' stop-everything. Rows already `stopping` are included, so their owners are
    /// re-signaled rather than told a prior request succeeded, and each id answers with its own
    /// [`StopReport`].
    pub(crate) async fn request_stop_session(
        &self,
        store: &crate::store::background::BackgroundStore,
        session_id: Uuid,
        reason: StopReason,
    ) -> crate::error::Result<Vec<(String, StopReport)>> {
        let open = store.list_running_background_tasks(session_id).await?;
        if open.is_empty() {
            return Ok(Vec::new());
        }
        let mut claimed = Vec::with_capacity(open.len());
        for task in &open {
            let signaled = self.claim_stop(session_id, &task.id, Some(reason)).await;
            claimed.push((task.id.clone(), task.status, signaled));
        }
        let moved = store
            .request_stop_background_tasks(claimed.iter().map(|(id, ..)| id.clone()).collect())
            .await?;
        // The listing is enough to classify: `moved` covers what this request recorded, and a row
        // that was `stopping` already carries a prior request's acceptance. A row that slipped to
        // terminal between the two reads is answered from the claim, which is all that is left to
        // say about it.
        Ok(claimed
            .into_iter()
            .map(|(id, was, signaled)| {
                let recorded_now = moved.contains(&id);
                let repeated =
                    !recorded_now && was == crate::store::background::TaskStatus::Stopping;
                (
                    id,
                    stop_report(signaled, recorded_now || repeated, repeated),
                )
            })
            .collect())
    }

    /// Claim `id`'s start against stop intent: the atomic half of a launch, for a caller that
    /// spawns work into a task it reserved with [`Self::try_reserve`].
    ///
    /// * Order it after the reservation and after the task's durable row lands, before the launch.
    ///   The reservation is what a stop signals; this claim decides whether the launch may use it
    ///   at all.
    /// * [`StartClaim::StopWon`] means a stop intent owns the task and the work must not start. The
    ///   task's completion is recorded here (the stop's status and reason, and the fact that
    ///   nothing ran) so the requester gets the report it was promised; the caller only skips the
    ///   launch. A natural terminal write that already won keeps its outcome. Nothing is recorded
    ///   when no reservation exists here: a launch goes through a reservation so a stop has
    ///   something to signal, and starting without one would make the work unownable.
    /// * [`StartClaim::StartWon`] means the claim beat every stop claim: a stop landing after this
    ///   point fires the token and its claim is already in place for the work's outcome, so the
    ///   caller launches and supervises the work against the token, checking it immediately after
    ///   the launch.
    ///
    /// Two serialization points, in order: the registry gate, where a stop claimed before this
    /// claim cannot be overtaken, and the row's guarded write
    /// ([`crate::store::background::BackgroundStore::claim_task_start`], whose only rival is
    /// [`crate::store::background::BackgroundStore::request_stop_background_tasks`]). What no
    /// in-process claim can close is a stop recorded by *another process* landing after the row's
    /// claim: the launch then supervises a durable stop it cannot see, which is what
    /// [`Self::deliver_durable_stops`] exists to settle.
    pub(crate) async fn claim_start(
        &self,
        store: &crate::store::background::BackgroundStore,
        id: &str,
    ) -> crate::error::Result<StartClaim> {
        let claimed = {
            let guard = self.inner.lock().await;
            match guard.get(id) {
                // Nothing reserved this task here: see the doc on what that means.
                None => return Ok(StartClaim::StopWon),
                Some(handle) if handle.stopped.is_none() && !handle.cancellation.is_cancelled() => {
                    None
                }
                Some(handle) => Some(
                    handle
                        .stopped
                        .unwrap_or((crate::store::background::TaskStatus::Canceled, None)),
                ),
            }
        };
        if let Some(stopped) = claimed {
            return self.refuse_start(store, id, Some(stopped)).await;
        }
        if !store.claim_task_start(id).await? {
            // The row's claim lost to a stop recorded outside this registry's claim: another
            // process's, or one this process recorded before it held this handle. What the
            // registry learned meanwhile is what the completion record reports.
            let stopped = self
                .inner
                .lock()
                .await
                .get(id)
                .and_then(|handle| handle.stopped);
            return self.refuse_start(store, id, stopped).await;
        }
        Ok(StartClaim::StartWon)
    }

    /// Record the completion of a start [`Self::claim_start`] refused. The requester of the stop
    /// is owed the report of what it prevented, so the row keeps the outcome of the run that never
    /// began, and keeps it past the caller's withdraw, which only takes rows no outcome was
    /// written on. The reservation's wait is released here as well, so nothing is left waiting on
    /// work that will never attach; the caller drops the slot with [`Self::forget`], next to
    /// whatever else it withdraws.
    async fn refuse_start(
        &self,
        store: &crate::store::background::BackgroundStore,
        id: &str,
        stopped: Option<Stopped>,
    ) -> crate::error::Result<StartClaim> {
        let (status, reason) =
            stopped.unwrap_or((crate::store::background::TaskStatus::Canceled, None));
        if let Some(completion) = self
            .inner
            .lock()
            .await
            .get(id)
            .map(|handle| handle.completion.clone())
        {
            completion.send_replace(true);
        }
        store
            .finish_background_task_observed(
                id,
                status,
                None,
                None,
                crate::store::background::Teardown {
                    confirmed: true,
                    started: false,
                    route: crate::store::background::RouteEvidence::Unrecorded,
                    reason,
                },
            )
            .await?;
        Ok(StartClaim::StopWon)
    }

    /// Re-signal the stops a durable record claims but a signal may never have reached: every open
    /// `stopping` row of the session whose owner is live in this process has its token fired
    /// again. Returns how many were (re-)signaled.
    ///
    /// The explicit recovery half of a stop. A request recorded by another process (or one whose
    /// future died between its record and its signal) leaves a `stopping` row its owner may never
    /// have heard about; a host that calls this on a timer lets that stop land after all. Rows
    /// whose owners are gone are left alone: the sweep reconciles those as owner loss, which is
    /// the only thing that can.
    pub(crate) async fn deliver_durable_stops(
        &self,
        store: &crate::store::background::BackgroundStore,
        session_id: Uuid,
    ) -> crate::error::Result<usize> {
        let mut delivered = 0;
        for task in store.list_running_background_tasks(session_id).await? {
            if task.status == crate::store::background::TaskStatus::Stopping
                && self.claim_stop(session_id, &task.id, None).await
            {
                delivered += 1;
            }
        }
        Ok(delivered)
    }

    /// Wait for every task this process is running, for a host that is about to exit.
    ///
    /// [`Self::cancel_all`] only fires the tokens, and firing a token is not the same as the task
    /// acting on it. A task parked at an await is dropped without ever being polled again when the
    /// runtime goes, so it reaches neither the kill of its command's tree (leaving the
    /// `setsid()`-ed child running with no Meka process tracking it) nor `finish_background_task`
    /// (leaving the row `running` for the next session open to sweep to `interrupted`).
    ///
    /// Callers should bound this: canceling asks, and a task that does not answer must not hold
    /// the terminal.
    pub(crate) async fn wait_all(&self) {
        self.wait_for(|_| true).await;
    }

    /// Wait for the tasks `wanted` selects, removing each entry once its work is over.
    ///
    /// The entry stays registered for the whole wait, so a Ctrl+C during it still has something
    /// for `cancel_all` to reach. What is observed is the completion signal every reservation
    /// holds from the start, not a join handle taken from it: a reservation whose work is not
    /// attached yet is waited for rather than skipped, and a wait that is cut short consumes
    /// nothing, so the next one sees the same tasks.
    async fn wait_for(&self, wanted: impl Fn(&TaskHandle) -> bool) {
        let ids: Vec<String> = {
            let guard = self.inner.lock().await;
            guard
                .iter()
                .filter(|(_, handle)| wanted(handle))
                .map(|(id, _)| id.clone())
                .collect()
        };
        let mut waiting = Vec::with_capacity(ids.len());
        for id in ids {
            if let Some(completion) = self.completion(&id).await {
                waiting.push((id, completion));
            }
        }
        for (id, completion) in waiting {
            completion.wait().await;
            self.forget(&id).await;
        }
    }

    /// Wait for this session's tasks to finish, for a host with nowhere to deliver an outcome
    /// later. `--oneshot` is the case: the process exits with the turn, so a background call there
    /// has to degrade into a slow synchronous one rather than a promise nothing will keep.
    ///
    /// Includes work a release left settling in this process: a host waiting for a session's tasks
    /// waits for all of them, whatever registry they were reserved in.
    pub(crate) async fn wait_for_session(&self, session_id: Uuid) {
        self.wait_for(|handle| handle.session_id == session_id)
            .await;
        for registry in released_registries(session_id) {
            registry
                .wait_for(|handle| handle.session_id == session_id)
                .await;
        }
    }

    /// The ids of this registry's live tasks of `session_id`, for the sweep that must not retire
    /// rows whose owners can still report.
    async fn live_ids(&self, session_id: Uuid) -> Vec<String> {
        self.inner
            .lock()
            .await
            .iter()
            .filter(|(_, handle)| handle.session_id == session_id)
            .map(|(id, _)| id.clone())
            .collect()
    }
}

/// What a stop request established; see [`BackgroundTasks::request_stop`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StopReport {
    /// The task had already ended (or no row ever landed and nothing is live here): its own
    /// outcome won and stays. Nothing was signaled and nothing recorded.
    AlreadyEnded,
    /// The stop reached the live owner in this process. `recorded` says the durable acceptance is
    /// in place; `repeated` says it already was, so this request re-signaled an open `stopping`
    /// task a prior request may never have reached.
    Signaled { recorded: bool, repeated: bool },
    /// No live owner in this process to signal. `recorded` says the row now records the pending
    /// stop; nothing here claims how the work ended, and the row stays open and undeliverable
    /// until the work reports or the owner-loss sweep reconciles it.
    NotSignaled { recorded: bool, repeated: bool },
}

/// The report for one stop from the three facts a request establishes: whether a live owner in
/// this process was signaled, whether a durable acceptance is recorded, and whether one was
/// already recorded before this request.
fn stop_report(signaled: bool, recorded: bool, repeated: bool) -> StopReport {
    if signaled {
        StopReport::Signaled { recorded, repeated }
    } else {
        StopReport::NotSignaled { recorded, repeated }
    }
}

/// Stop a session's task named by id prefix (or every open one when the prefix is `None`)
/// through the one stop path, for a surface that holds the live registry: the screens'
/// `/task cancel`. Answers one report per task, in the request's order.
///
/// The prefix rules are [`crate::store::background::BackgroundStore::resolve_background_task`]'s:
/// an unusable or unknown prefix is a usage error, and so is one naming a task that already ended:
/// the user said stop and nothing needed it. A task already `stopping` is stopped again rather
/// than answered for: its record is not proof the signal ever reached its owner.
pub(crate) async fn stop_by_prefix(
    tasks: &BackgroundTasks,
    store: &crate::store::Store,
    session_id: Uuid,
    id_prefix: Option<&str>,
    reason: StopReason,
) -> crate::error::Result<Vec<(String, StopReport)>> {
    let background = store.background_store();
    let Some(id_prefix) = id_prefix else {
        return tasks
            .request_stop_session(&background, session_id, reason)
            .await;
    };
    let Some(task) = background
        .resolve_background_task(session_id, id_prefix)
        .await?
    else {
        return Err(crate::error::MekaError::Usage(format!(
            "no background task matching '{id_prefix}'"
        )));
    };
    if task.status.is_terminal() {
        return Err(crate::error::MekaError::Usage(format!(
            "task {} already {}",
            task.short_id(),
            task.status.name()
        )));
    }
    let report = tasks
        .request_stop(&background, session_id, &task.id, reason)
        .await?;
    Ok(vec![(task.id, report)])
}

/// What a launch's start claim established; see [`BackgroundTasks::claim_start`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StartClaim {
    /// A stop intent owns the task: the work must not start. The task's completion is recorded.
    StopWon,
    /// The start claimed the task; a stop landing later is supervised against the token.
    StartWon,
}

/// Work a release left running past its grace, still owned by this process: the live registry the
/// work is registered in, and the session's file lock.
///
/// The lock is the cross-process proof that rows still `running` belong here. A release that
/// cannot wait for its work therefore cannot let the lock go: the next opener would sweep rows
/// whose work is live in this very process and report their teardowns as unconfirmed while they
/// are still writing. Ownership moves here instead, and the lock is let go only once the work has
/// settled or the process dies, either of which is proof the owners can no longer report.
struct ReleasedWork {
    /// The session's file lock while this entry holds it. `None` once a reopen in this process
    /// adopted it into its own entry, which then owns the release.
    lock: Option<crate::fs::FileLock>,
    /// Registries of release cycles whose work has not settled yet.
    registries: Vec<BackgroundTasks>,
}

/// The released work of every session this process still owns.
///
/// `std::sync::Mutex` for the same reason [`crate::store::SessionLockSlot`] is one: every access
/// is a move in or out with nothing awaited in between.
fn released_work() -> &'static std::sync::Mutex<std::collections::HashMap<Uuid, ReleasedWork>> {
    static RELEASED: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<Uuid, ReleasedWork>>,
    > = std::sync::OnceLock::new();
    RELEASED.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

/// Hand a release's unfinished work to this process's cleanup: `tasks` keeps settling here (still
/// signaled, waited for and spared by the sweep) and `lock` is held until it does. Called by a
/// release whose bounded wait ran out; [`settle_released_work`] is its end.
pub(crate) fn retire_released_work(
    session_id: Uuid,
    lock: Option<crate::fs::FileLock>,
    tasks: BackgroundTasks,
) {
    let mut released = crate::sync::lock(released_work());
    let entry = released.entry(session_id).or_insert_with(|| ReleasedWork {
        lock: None,
        registries: Vec::new(),
    });
    if lock.is_some() {
        if entry.lock.is_some() {
            // Unreachable in practice: a second lock for the session cannot exist while the first
            // is held. Kept rather than replaced, so the held one is never dropped by accident.
            tracing::warn!("session {session_id} retired twice with a lock; keeping the first");
        } else {
            entry.lock = lock;
        }
    }
    entry.registries.push(tasks);
    drop(released);
}

/// The cleanup half of [`retire_released_work`]: `registry`'s work has settled, so it is out, and
/// the lock is let go once no registry is left to hold it for. A reopen that adopted the lock
/// meanwhile owns the release, and this only drops the registry.
pub(crate) fn settle_released_work(session_id: Uuid, registry: &BackgroundTasks) {
    let lock = {
        let mut released = crate::sync::lock(released_work());
        let Some(entry) = released.get_mut(&session_id) else {
            return;
        };
        entry
            .registries
            .retain(|other| !std::sync::Arc::ptr_eq(&other.inner, &registry.inner));
        if entry.registries.is_empty() {
            released
                .remove(&session_id)
                .and_then(|settled| settled.lock)
        } else {
            None
        }
    };
    if lock.is_some() {
        tracing::info!(
            "released background work for session {session_id} settled; its lock is let go"
        );
    }
}

/// Adopt the lock of a session this process released but still owns: a reopen calls this before
/// locking anew, because a `flock` is per open file description and a lock this process already
/// holds cannot be taken again. The work left behind stays where it is: the reopener must still
/// signal, wait for and sweep around it.
pub(crate) fn take_released_lock(session_id: Uuid) -> Option<crate::fs::FileLock> {
    let mut released = crate::sync::lock(released_work());
    let entry = released.get_mut(&session_id)?;
    let lock = entry.lock.take();
    if entry.registries.is_empty() {
        released.remove(&session_id);
    }
    lock
}

/// The registries of `session_id`'s released work still settling in this process.
fn released_registries(session_id: Uuid) -> Vec<BackgroundTasks> {
    crate::sync::lock(released_work())
        .get(&session_id)
        .map(|entry| entry.registries.clone())
        .unwrap_or_default()
}

/// The ids of `session_id`'s live tasks in this process's released work: what the sweep must spare
/// alongside this registry's own, because those rows' owners are still here and may still report.
pub(crate) async fn released_live_ids(session_id: Uuid) -> Vec<String> {
    let mut live = Vec::new();
    for registry in released_registries(session_id) {
        live.extend(registry.live_ids(session_id).await);
    }
    live
}

/// Ceiling on outcome text carried inline in the delivered turn. Past this the full output goes to
/// a scratchpad entry and the turn carries the head plus the entry name: a twenty-minute build log
/// would otherwise land in the conversation permanently, for a result that mattered once.
///
/// `split_outcome` keeps only the head, because an outcome arrives unbidden and should cost less
/// window than a result the model asked for. Nothing is lost either way: the scratchpad holds all
/// of it.
pub(crate) const OUTCOME_INLINE_BYTES: usize = 4 * crate::text::KIB;

/// Longest task label shown in the `[Background]` index and in delivered headers.
pub(crate) const LABEL_MAX_CHARS: usize = 80;

/// Keep only the outcomes a stamp actually won.
///
/// The stamps are compare-and-swaps that return the rows they took, and every caller must report
/// against that rather than against the snapshot it chose from: two claimers reading the same row
/// as unclaimed is the ordinary case, and acting on the read is how the same outcome reaches the
/// model twice.
pub(crate) fn only_what_was_won(
    ready: Vec<BackgroundTask>,
    claimed: &[String],
) -> Vec<BackgroundTask> {
    ready
        .into_iter()
        .filter(|task| claimed.contains(&task.id))
        .collect()
}

/// Claim every undelivered outcome of `session_id`: list, stamp, keep what the stamp won.
///
/// For a caller that puts the batch into the conversation at once: a turn at its round boundary,
/// a host folding it into the prompt it is about to run, the one-shot's post-turn report. The
/// stamp is undone only by the turn that carries the batch, when it is refused before it opens or
/// cannot store the message that carries it, so a caller that might not run a turn after all asks
/// the host layer's gated form, which first asks whether one can start.
pub(crate) async fn claim_outcomes_now(
    store: &crate::store::Store,
    session_id: Uuid,
) -> Vec<BackgroundTask> {
    let store = store.background_store();
    let ready = match store.list_undelivered_background_tasks(session_id).await {
        Ok(ready) => ready,
        Err(error) => {
            tracing::warn!("failed to load background task outcomes: {error}");
            return Vec::new();
        }
    };
    if ready.is_empty() {
        return ready;
    }
    let ids: Vec<String> = ready.iter().map(|task| task.id.clone()).collect();
    let claimed = match store.mark_background_tasks_delivered(&ids).await {
        Ok(claimed) => claimed,
        Err(error) => {
            tracing::warn!("failed to stamp background outcomes as delivered: {error}");
            return Vec::new();
        }
    };
    // Only what this caller won. Listing and stamping are two statements, and a poller can claim
    // the same row in the gap: whoever the `WHERE delivered_at IS NULL` refuses reports nothing,
    // rather than both of them reporting it.
    only_what_was_won(ready, &claimed)
}

/// How a call that went to the background is answered: the task it became and what it runs. The
/// directions the dispatcher adds after it are the model's.
pub(crate) fn started_notice(short_id: &str, label: &str) -> String {
    format!("Started in the background as task {short_id} ({label}).")
}

/// A task's label as a person or the model is shown it. Sanitized like an outcome: the label is
/// derived from the tool's primary argument, which for `shell_execute` is a shell command line the
/// *model* wrote, so it is no more trusted than the output it names.
pub(crate) fn shown_label(task: &BackgroundTask) -> String {
    elide(&crate::text::sanitize_text(&task.label), LABEL_MAX_CHARS)
}

/// The tasks a report's `task_ids` name among `known`, in the report's order. A converted row
/// names a task by its short id, so a prefix matches; a task the store no longer holds is left
/// out.
pub(crate) fn reported_tasks(known: &[BackgroundTask], task_ids: &[String]) -> Vec<BackgroundTask> {
    task_ids
        .iter()
        .filter_map(|id| {
            known
                .iter()
                .find(|task| task.id.starts_with(id.as_str()))
                .cloned()
        })
        .collect()
}

/// The stage direction for a replayed report: the tasks [`reported_tasks`] finds, said as the
/// live run said them, or a bare direction when the store holds none of them.
pub(crate) fn replayed_report_direction(known: &[BackgroundTask], task_ids: &[String]) -> String {
    let tasks = reported_tasks(known, task_ids);
    if tasks.is_empty() {
        "Background task report".to_string()
    } else {
        report_direction(&tasks)
    }
}

/// The stage direction a screen says where a report lands: which tasks ended and how. The report
/// itself is the model's to read and stays off the screen, as every tool's output does; the reply
/// that follows carries what matters.
pub(crate) fn report_direction(tasks: &[BackgroundTask]) -> String {
    match tasks {
        [task] => format!(
            "Background task {} {} after {}",
            task.short_id(),
            task.status.headline(),
            format_elapsed(task)
        ),
        _ => {
            let ended = tasks
                .iter()
                .map(|task| format!("{} {}", task.short_id(), task.status.headline()))
                .collect::<Vec<_>>()
                .join(", ");
            format!("{} background tasks: {ended}", tasks.len())
        }
    }
}

/// The retention a carrier prompt deserves once an outcome may be riding on it.
///
/// A recurring schedule asks for [`crate::conversation::PromptRetention::Withdraw`] because its
/// next occurrence regenerates the prompt, so a failed copy carries nothing worth keeping. That
/// stops being true the moment an outcome joins it: the row is stamped delivered when it is claimed
/// and is never handed out again, so withdrawing the message loses the only copy. Three hosts fold
/// an outcome into a fired schedule's prompt, and an interrupt lands one on the prompt of a turn in
/// flight; all four ask this, rather than each remembering.
pub(crate) fn retention_carrying(
    riding: &[BackgroundTask],
    schedule: crate::conversation::PromptRetention,
) -> crate::conversation::PromptRetention {
    if riding.is_empty() {
        schedule
    } else {
        crate::conversation::PromptRetention::Keep
    }
}

/// [`render_outcomes`] for a report that rides a prompt somebody else wrote, in that turn's
/// context block.
///
/// The standalone form ends "Pick the work back up from here", which is right when it *is* the
/// prompt and wrong above an unrelated question. Riding the prompt's own message rather than
/// being appended as a message of its own is what keeps this off the conversation as a turn
/// boundary: a lone user message opens a turn (`crate::conversation::opens_turn`), and one nobody
/// answers would be rewound in place of the user's last exchange and sent as a second consecutive
/// user turn.
pub(crate) fn render_outcomes_riding(tasks: &[BackgroundTask]) -> String {
    render_outcomes_with_trailer(tasks, PREAMBLE_TRAILER)
}

/// [`render_outcomes`] for a report read at a round boundary of a turn in flight, behind that
/// round's own blocks: the model is mid-task, so the trailer tells it to carry on rather than to
/// answer.
pub(crate) fn render_outcomes_mid_turn(tasks: &[BackgroundTask]) -> String {
    render_outcomes_with_trailer(tasks, MID_TURN_TRAILER)
}

/// What the standalone form tells the model to do next.
const STANDALONE_TRAILER: &str = "\nYou started these earlier and did not wait for them. Pick the \
    work back up from here; do not restate this header.\n";

/// The same, for a report that precedes a prompt of its own.
const PREAMBLE_TRAILER: &str = "\nYou started these earlier and did not wait for them. Read them, \
    then answer what follows; do not restate this header.\n";

/// The same, for a report landing while the model works.
const MID_TURN_TRAILER: &str = "\nYou started these earlier and did not wait for them. Carry on \
    with them in mind; do not restate this header.\n";

/// Render one or more finished tasks as the user-turn text that delivers them.
///
/// The header is not decoration, for the same reason [`crate::prompt::render_fire`] carries one:
/// without it the model reads a bare result as though a human had just typed it, and answers
/// conversationally to nobody. It also has to be unambiguous about *who* is speaking,
/// because a backgrounded `agent_spawn` reports in a sub-agent's words, and a sub-agent is
/// permission-clamped by `resolve_subagent_permission` while its words are not.
///
/// Several outcomes ready at once coalesce into one turn rather than one turn each, as the
/// scheduler already does for a backlog.
pub(crate) fn render_outcomes(tasks: &[BackgroundTask]) -> String {
    render_outcomes_with_trailer(tasks, STANDALONE_TRAILER)
}

fn render_outcomes_with_trailer(tasks: &[BackgroundTask], trailer: &str) -> String {
    let mut rendered = format!(
        "[Background {} reporting at {}]",
        if tasks.len() == 1 {
            "task".to_string()
        } else {
            format!("tasks ({})", tasks.len())
        },
        crate::text::format_timestamp(Utc::now(), crate::text::Precision::Minutes),
    );
    rendered.push_str(trailer);

    for task in tasks {
        rendered.push_str(&format!(
            "\n---\n\n**{}** ({}) {} after {}.\n",
            task.short_id(),
            shown_label(task),
            task.status.headline(),
            format_elapsed(task),
        ));
        if let Some(name) = &task.scratchpad_entry {
            rendered.push_str(&format!(
                "\nFull output is in scratchpad entry `{name}`; the beginning follows.\n"
            ));
        }
        if let Some(outcome) = &task.outcome
            && !outcome.trim().is_empty()
        {
            rendered.push('\n');
            // Sanitized for the same reason MCP text is: this is content from a shell command or a
            // sub-agent, and a terminal-control or bidi-override sequence in it would be rendered
            // to the user and fed to the model verbatim. Quoted, so no line of it can pass for the
            // report's header, the next task's or a prompt after the report; the quoting drops
            // the output's trailing line endings, a shell's final newline above all, which would
            // only put a blank line under it.
            rendered.push_str(&crate::text::quote_lines(&crate::text::sanitize_text(
                outcome,
            )));
            rendered.push('\n');
        }
    }
    rendered
}

/// Split a tool's output into what the turn carries inline and what, if anything, needs a
/// scratchpad entry. `None` in the second slot means it fit.
///
/// Measured in bytes throughout, including the cut. Deciding in bytes and then cutting in
/// characters would make the head of a non-ASCII log as much as four times the budget, and could
/// spill an output whose "head" is then the whole of it: a delivered turn announcing a scratchpad
/// entry and quoting the entire text it was supposed to spare the conversation.
pub(crate) fn split_outcome(output: &str) -> (String, Option<String>) {
    if output.len() <= OUTCOME_INLINE_BYTES {
        return (output.to_string(), None);
    }
    let mut end = OUTCOME_INLINE_BYTES;
    while end > 0 && !output.is_char_boundary(end) {
        end -= 1;
    }
    (output[..end].to_string(), Some(output.to_string()))
}

/// Scratchpad entry name for a spilled outcome. Namespaced by the short id so two tasks of the same
/// tool cannot collide, and recognizable so the agent can find it without being told twice.
pub(crate) fn spill_entry_name(task_id: &str, tool_name: &str) -> String {
    let short = task_id.get(..8).unwrap_or(task_id);
    format!("task_{short}_{tool_name}")
}

/// How long a task ran, or has been running, as every surface states a duration.
pub(crate) fn format_elapsed(task: &BackgroundTask) -> String {
    crate::text::format_elapsed(task.elapsed().to_std().unwrap_or_default())
}

/// A single-line excerpt of `text`, whitespace collapsed and clipped to `limit`. For listing a
/// finished task's result without reprinting it.
pub(crate) fn excerpt(text: &str, limit: usize) -> String {
    elide(text, limit)
}

/// Shorten `text` to `limit` characters on a whitespace boundary.
fn elide(text: &str, limit: usize) -> String {
    let collapsed = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.chars().count() <= limit {
        return collapsed;
    }
    let clipped: String = collapsed.chars().take(limit).collect();
    let trimmed = match clipped.rfind(char::is_whitespace) {
        Some(space) => &clipped[..space],
        None => clipped.as_str(),
    };
    format!("{}…", trimmed.trim_end())
}

/// Name of the tool the `[Background]` index exists to drive. Without it the index would be a menu
/// with nothing to order from.
pub(crate) const TASK_INDEX_TOOL: &str = "task_list";
#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::background::TaskStatus;

    fn task(status: TaskStatus, outcome: Option<&str>) -> BackgroundTask {
        BackgroundTask {
            id: "7f3a1c22-0000-0000-0000-000000000000".to_string(),
            session_id: Uuid::nil(),
            tool: "shell_execute".to_string(),
            label: "cargo test --all".to_string(),
            status,
            outcome: outcome.map(str::to_string),
            scratchpad_entry: None,
            started_at: Utc::now() - chrono::Duration::seconds(90),
            finished_at: Some(Utc::now()),
            announced_at: None,
            delivered_at: None,
            subagent_id: None,
        }
    }

    /// A task told to stop is still registered until its work has ended, and is no longer one a
    /// move to another session waits for: what was asked of it has been asked.
    #[tokio::test]
    async fn a_task_told_to_stop_is_no_longer_counted_as_unstopped() {
        let tasks = BackgroundTasks::default();
        let session_id = Uuid::new_v4();
        for id in ["one", "two"] {
            assert!(
                tasks
                    .try_reserve(
                        id.to_string(),
                        session_id,
                        tokio_util::sync::CancellationToken::new(),
                        4,
                    )
                    .await
            );
        }
        assert_eq!(tasks.unstopped_count_all().await, 2);

        assert!(
            tasks
                .claim_stop(session_id, "one", Some(StopReason::UserRequest))
                .await
        );
        assert_eq!(tasks.unstopped_count_all().await, 1);
        assert_eq!(
            tasks.running_count(session_id).await,
            2,
            "both are still registered"
        );

        tasks.cancel_all(TaskStatus::Canceled).await;
        assert_eq!(tasks.unstopped_count_all().await, 0);
    }

    /// The ceiling has to hold against the sibling calls in one assistant message, which
    /// `execute_tool_calls` dispatches concurrently: counting and then registering separately lets
    /// every call read "zero running" and start.
    #[tokio::test]
    async fn the_ceiling_holds_against_concurrent_reservations() {
        let tasks = BackgroundTasks::default();
        let session_id = Uuid::new_v4();

        let attempts: Vec<_> = (0..8)
            .map(|index| {
                let tasks = tasks.clone();
                tokio::spawn(async move {
                    tasks
                        .try_reserve(
                            format!("task-{index}"),
                            session_id,
                            tokio_util::sync::CancellationToken::new(),
                            3,
                        )
                        .await
                })
            })
            .collect();

        let mut granted = 0;
        for attempt in attempts {
            if attempt.await.expect("join") {
                granted += 1;
            }
        }
        assert_eq!(
            granted, 3,
            "exactly the ceiling, no matter the interleaving"
        );
        assert_eq!(tasks.running_count(session_id).await, 3);
    }

    /// A start that fails after reserving must hand the slot back, or the ceiling shrinks for the
    /// rest of the session.
    #[tokio::test]
    async fn a_released_reservation_frees_its_slot() {
        let tasks = BackgroundTasks::default();
        let session_id = Uuid::new_v4();
        let token = tokio_util::sync::CancellationToken::new;

        assert!(
            tasks
                .try_reserve("a".to_string(), session_id, token(), 1)
                .await
        );
        assert!(
            !tasks
                .try_reserve("b".to_string(), session_id, token(), 1)
                .await
        );

        tasks.forget("a").await;
        assert!(
            tasks
                .try_reserve("b".to_string(), session_id, token(), 1)
                .await
        );
    }

    /// Canceling and leaving is not enough: the task has to be given the chance to act on it.
    ///
    /// `/exit` returns straight into `Runtime::shutdown_background`, which drops every task where
    /// it stands. A task parked at an await is then never polled again, so the cleanup that follows
    /// its cancellation check (killing its process group, writing its terminal row) never happens.
    /// The task here records the same way: it observes the token, then does one more await before
    /// setting the flag.
    #[tokio::test]
    async fn canceling_every_task_and_waiting_lets_them_run_their_cleanup() {
        let tasks = BackgroundTasks::default();
        let session_id = Uuid::new_v4();
        let token = tokio_util::sync::CancellationToken::new();
        let cleaned_up = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));

        assert!(
            tasks
                .try_reserve("a".to_string(), session_id, token.clone(), 4)
                .await
        );
        let join = tokio::spawn({
            let cleaned_up = std::sync::Arc::clone(&cleaned_up);
            async move {
                token.cancelled().await;
                tokio::task::yield_now().await;
                cleaned_up.store(true, std::sync::atomic::Ordering::Release);
            }
        });
        tasks.attach("a", join).await;

        assert_eq!(tasks.cancel_all(TaskStatus::Interrupted).await, 1);
        tasks.wait_all().await;

        assert!(
            cleaned_up.load(std::sync::atomic::Ordering::Acquire),
            "the task must have reached its cleanup before the wait returned",
        );
        assert_eq!(
            tasks.running_count(session_id).await,
            0,
            "and the registry must be empty afterwards",
        );
    }

    /// The stop's signal is delivered at the claim, before and independently of its durable
    /// record: a record stuck behind another connection's write lock must not leave work running
    /// while a stop was asked for and answered for. The record is the retryable acceptance, not a
    /// gate the signal waits at, and when it lands, the work's own result still ends the row with
    /// the stop's status and reason, not the failure the interruption reads as.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_stop_signals_even_while_its_durable_record_waits_for_the_database() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("meka.db");
        let store = crate::store::Store::open(Some(&path), &Default::default())
            .await
            .expect("open");
        let session_id = store
            .create_session(None, "p".to_string())
            .await
            .expect("session");
        let tasks = BackgroundTasks::default();
        let token = tokio_util::sync::CancellationToken::new();
        let row = BackgroundTask {
            session_id,
            status: TaskStatus::Running,
            finished_at: None,
            ..task(TaskStatus::Running, None)
        };
        let background = store.background_store();
        background.start_background_task(&row).await.expect("start");
        assert!(
            tasks
                .try_reserve(row.id.clone(), session_id, token.clone(), 4)
                .await
        );
        let (locked, held) = std::sync::mpsc::channel();
        let holder = std::thread::spawn({
            let (token, path) = (token.clone(), path.clone());
            move || {
                let connection = rusqlite::Connection::open(&path).expect("second connection");
                connection
                    .execute_batch("BEGIN IMMEDIATE")
                    .expect("the write lock");
                locked.send(()).expect("say it is held");
                let until = std::time::Instant::now() + std::time::Duration::from_millis(500);
                while !token.is_cancelled() && std::time::Instant::now() < until {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                let signaled_while_held = token.is_cancelled();
                connection.execute_batch("ROLLBACK").expect("let go");
                signaled_while_held
            }
        });
        held.recv().expect("the lock is held");

        assert_eq!(
            tasks.stop_all(&background, TaskStatus::Interrupted).await,
            1
        );

        assert!(
            holder.join().expect("the holder"),
            "the signal goes out at the claim and does not wait for the record"
        );
        let recorded = background
            .list_background_tasks(session_id)
            .await
            .expect("tasks");
        assert_eq!(
            recorded[0].status,
            TaskStatus::Stopping,
            "a request is not an outcome, so the row is still open"
        );
        assert!(
            recorded[0].finished_at.is_none(),
            "and nothing has ended it yet"
        );

        // The work notices the stop, reports its interruption, and that result ends the row with
        // the stop's status and reason.
        let (status, reason) = tasks.outcome_end(&row.id, true).await;
        assert_eq!(status, TaskStatus::Interrupted);
        assert_eq!(reason, Some(StopReason::HostRelease));
        background
            .finish_background_task(&row.id, status, Some("interrupted".to_string()), None)
            .await
            .expect("finish");
        let recorded = background
            .list_background_tasks(session_id)
            .await
            .expect("tasks");
        assert_eq!(recorded[0].status, TaskStatus::Interrupted);
    }

    /// A reservation is part of what a wait waits for, even before its work is attached: the join
    /// used to be the only thing a wait could hold, so a stop that came in this window was waited
    /// for by nobody and the wait returned while the work it had just signaled ran on.
    #[tokio::test]
    async fn a_wait_covers_a_reservation_whose_work_is_not_attached_yet() {
        let tasks = BackgroundTasks::default();
        let session_id = Uuid::new_v4();
        assert!(
            tasks
                .try_reserve(
                    "a".to_string(),
                    session_id,
                    tokio_util::sync::CancellationToken::new(),
                    4,
                )
                .await
        );

        let waiting = tokio::spawn({
            let tasks = tasks.clone();
            async move { tasks.wait_all().await }
        });
        tokio::task::yield_now().await;
        assert!(
            !waiting.is_finished(),
            "the reservation is not work that is already over"
        );

        tasks.attach("a", tokio::spawn(async {})).await;
        waiting.await.expect("join");
        assert_eq!(
            tasks.running_count(session_id).await,
            0,
            "the wait ends with the registry it watched"
        );
    }

    /// A wait that is cut short must leave the completion for the next one. A join handle is taken
    /// by whoever waits first, so a host's bounded wait used to consume it: the second wait found
    /// nothing to join and returned before the work it had signaled had run.
    #[tokio::test]
    async fn a_wait_that_is_cut_short_does_not_take_the_completion_with_it() {
        let tasks = BackgroundTasks::default();
        let session_id = Uuid::new_v4();
        let token = tokio_util::sync::CancellationToken::new();
        let cleaned_up = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        assert!(
            tasks
                .try_reserve("a".to_string(), session_id, token.clone(), 4)
                .await
        );
        tasks
            .attach(
                "a",
                tokio::spawn({
                    let cleaned_up = std::sync::Arc::clone(&cleaned_up);
                    async move {
                        token.cancelled().await;
                        tokio::task::yield_now().await;
                        cleaned_up.store(true, std::sync::atomic::Ordering::Release);
                    }
                }),
            )
            .await;

        let cut_short =
            tokio::time::timeout(std::time::Duration::from_millis(20), tasks.wait_all()).await;
        assert!(
            cut_short.is_err(),
            "the first wait runs out before the stop"
        );

        assert_eq!(tasks.cancel_all(TaskStatus::Canceled).await, 1);
        tasks.wait_all().await;
        assert!(
            cleaned_up.load(std::sync::atomic::Ordering::Acquire),
            "the second wait must observe the work the first one stopped waiting for"
        );
        assert_eq!(tasks.running_count(session_id).await, 0);
    }

    /// Completion is observable more than once and by more than one waiter: what a wait holds is a
    /// subscription, so a second `completion` sees the same end as the first, however late it is
    /// asked for.
    #[tokio::test]
    async fn a_completion_can_be_observed_more_than_once() {
        let tasks = BackgroundTasks::default();
        let session_id = Uuid::new_v4();
        let token = tokio_util::sync::CancellationToken::new();
        assert!(
            tasks
                .try_reserve("a".to_string(), session_id, token.clone(), 4)
                .await
        );
        let first = tasks.completion("a").await.expect("reserved");
        let second = tasks.completion("a").await.expect("reserved");
        tasks
            .attach(
                "a",
                tokio::spawn(async move {
                    token.cancelled().await;
                }),
            )
            .await;

        let waiting = tokio::spawn(async move { second.wait().await });
        assert!(
            tasks
                .claim_stop(session_id, "a", Some(StopReason::UserRequest))
                .await
        );
        first.wait().await;
        waiting.await.expect("join");
        assert!(
            tasks.completion("missing").await.is_none(),
            "a task this process does not hold has no completion to observe"
        );
    }

    /// A stop that lands while a task's row is still being written records nothing for it, so the
    /// task's own outcome reports the stop: the failure its interruption reads as is recorded as
    /// the stop's status, where a task no stop signaled still fails and one that succeeded keeps
    /// its outcome.
    #[tokio::test]
    async fn a_task_stopped_before_its_row_landed_reports_the_stop() {
        let store = crate::store::Store::for_test().await;
        let session_id = store
            .create_session(None, "p".to_string())
            .await
            .expect("session");
        let tasks = BackgroundTasks::default();
        let row = BackgroundTask {
            session_id,
            status: TaskStatus::Running,
            finished_at: None,
            ..task(TaskStatus::Running, None)
        };
        let token = tokio_util::sync::CancellationToken::new();
        assert!(
            tasks
                .try_reserve(row.id.clone(), session_id, token.clone(), 4)
                .await
        );
        let background = store.background_store();
        assert_eq!(
            tasks.stop_all(&background, TaskStatus::Interrupted).await,
            1
        );
        assert!(token.is_cancelled());

        background.start_background_task(&row).await.expect("start");
        let (status, reason) = tasks.outcome_end(&row.id, true).await;
        assert_eq!(status, TaskStatus::Interrupted);
        assert_eq!(reason, Some(StopReason::HostRelease));
        background
            .finish_background_task(&row.id, status, Some("interrupted".to_string()), None)
            .await
            .expect("finish");
        let recorded = background
            .list_background_tasks(session_id)
            .await
            .expect("tasks");
        assert_eq!(recorded[0].status, TaskStatus::Interrupted);
        assert_eq!(
            tasks.outcome_end(&row.id, false).await,
            (TaskStatus::Completed, None)
        );
        assert_eq!(
            tasks.outcome_end("unstopped", true).await,
            (TaskStatus::Failed, None)
        );
    }

    /// The start claim is the primitive a launch stands in for, and a stop landing in its window
    /// takes one of two honest orders: the claim wins and the launched work reports the stop's own
    /// status when it ends, or the stop wins and the launch runs nothing at all, its completion
    /// recorded then and there, so the requester of the stop is owed no report that cannot come.
    #[tokio::test]
    async fn a_stand_in_launch_claims_its_start_against_a_stop_in_the_window() {
        let temp = tempfile::tempdir().expect("tempdir");
        let store =
            crate::store::Store::open(Some(&temp.path().join("meka.db")), &Default::default())
                .await
                .expect("open");
        let session_id = store
            .create_session(None, "p".to_string())
            .await
            .expect("session");
        let background = store.background_store();
        let tasks = BackgroundTasks::default();

        // The order where the launch claims first: it runs, and the stop it loses to is what its
        // result reports.
        let row = BackgroundTask {
            id: Uuid::new_v4().to_string(),
            session_id,
            status: TaskStatus::Running,
            finished_at: None,
            ..task(TaskStatus::Running, None)
        };
        background.start_background_task(&row).await.expect("start");
        let token = tokio_util::sync::CancellationToken::new();
        assert!(
            tasks
                .try_reserve(row.id.clone(), session_id, token.clone(), 4)
                .await
        );
        assert!(matches!(
            tasks
                .claim_start(&background, &row.id)
                .await
                .expect("claim"),
            StartClaim::StartWon
        ));
        assert!(
            tasks
                .claim_stop(session_id, &row.id, Some(StopReason::UserRequest))
                .await
        );
        assert!(token.is_cancelled(), "the launched work is signaled");
        assert_eq!(
            tasks.outcome_end(&row.id, true).await,
            (TaskStatus::Canceled, Some(StopReason::UserRequest))
        );

        // The order where the stop claims first: the launch must run nothing, and the completion
        // the stop's requester was promised is already recorded, including that nothing ran.
        let row = BackgroundTask {
            id: Uuid::new_v4().to_string(),
            session_id,
            status: TaskStatus::Running,
            finished_at: None,
            ..task(TaskStatus::Running, None)
        };
        background.start_background_task(&row).await.expect("start");
        let token = tokio_util::sync::CancellationToken::new();
        assert!(
            tasks
                .try_reserve(row.id.clone(), session_id, token.clone(), 4)
                .await
        );
        assert!(
            tasks
                .claim_stop(session_id, &row.id, Some(StopReason::AgentRequest))
                .await
        );
        assert!(matches!(
            tasks
                .claim_start(&background, &row.id)
                .await
                .expect("claim"),
            StartClaim::StopWon
        ));
        let recorded = background
            .list_background_tasks(session_id)
            .await
            .expect("tasks");
        let refused = recorded
            .iter()
            .find(|found| found.id == row.id)
            .expect("the completion record the refusal writes");
        assert_eq!(refused.status, TaskStatus::Canceled);
        assert!(
            refused
                .outcome
                .as_deref()
                .unwrap_or_default()
                .contains("before the work began"),
            "{:?}",
            refused.outcome
        );
    }

    /// A repeat stop on a task left `stopping` signals its owner again rather than reporting the
    /// first request's success: the record that landed says a request was accepted, not that its
    /// signal ever reached the owner, and a retry that trusted it would leave work running behind
    /// a request reported as done.
    #[tokio::test]
    async fn a_repeat_stop_re_signals_the_owner_of_an_open_stopping_task() {
        let temp = tempfile::tempdir().expect("tempdir");
        let store =
            crate::store::Store::open(Some(&temp.path().join("meka.db")), &Default::default())
                .await
                .expect("open");
        let session_id = store
            .create_session(None, "p".to_string())
            .await
            .expect("session");
        let background = store.background_store();
        let tasks = BackgroundTasks::default();
        let row = BackgroundTask {
            id: Uuid::new_v4().to_string(),
            session_id,
            status: TaskStatus::Running,
            finished_at: None,
            ..task(TaskStatus::Running, None)
        };
        background.start_background_task(&row).await.expect("start");
        let token = tokio_util::sync::CancellationToken::new();
        assert!(
            tasks
                .try_reserve(row.id.clone(), session_id, token.clone(), 4)
                .await
        );

        // A durable request whose signal never went out: the requesting future died in between,
        // which is exactly the state a record alone leaves behind.
        assert_eq!(
            background
                .request_stop_background_tasks(vec![row.id.clone()])
                .await
                .expect("record"),
            vec![row.id.clone()]
        );
        assert!(!token.is_cancelled(), "and nothing signaled it");

        let report = tasks
            .request_stop(&background, session_id, &row.id, StopReason::UserRequest)
            .await
            .expect("stop");
        assert!(token.is_cancelled(), "the retry delivers the signal");
        assert!(
            matches!(report, StopReport::Signaled { repeated: true, .. }),
            "{report:?}"
        );
        tasks.forget(&row.id).await;

        // And the recovery a host runs on its own finds the same thing to do.
        let row = BackgroundTask {
            id: Uuid::new_v4().to_string(),
            session_id,
            status: TaskStatus::Running,
            finished_at: None,
            ..task(TaskStatus::Running, None)
        };
        background.start_background_task(&row).await.expect("start");
        let token = tokio_util::sync::CancellationToken::new();
        assert!(
            tasks
                .try_reserve(row.id.clone(), session_id, token.clone(), 4)
                .await
        );
        background
            .request_stop_background_tasks(vec![row.id.clone()])
            .await
            .expect("record");
        assert!(!token.is_cancelled());
        assert_eq!(
            tasks
                .deliver_durable_stops(&background, session_id)
                .await
                .expect("recover"),
            1
        );
        assert!(token.is_cancelled(), "the recovery signals the owner");
    }

    /// The ceiling is per session, so one session filling it must not starve another.
    #[tokio::test]
    async fn the_ceiling_is_per_session() {
        let tasks = BackgroundTasks::default();
        let first = Uuid::new_v4();
        let second = Uuid::new_v4();
        let token = tokio_util::sync::CancellationToken::new;

        assert!(tasks.try_reserve("a".to_string(), first, token(), 1).await);
        assert!(!tasks.try_reserve("b".to_string(), first, token(), 1).await);
        assert!(tasks.try_reserve("c".to_string(), second, token(), 1).await);
    }

    #[test]
    fn status_round_trips_through_its_string() {
        for status in [
            TaskStatus::Running,
            TaskStatus::Stopping,
            TaskStatus::Completed,
            TaskStatus::Failed,
            TaskStatus::Canceled,
            TaskStatus::Interrupted,
        ] {
            assert_eq!(status.name().parse::<TaskStatus>(), Ok(status));
        }
        assert!("wedged".parse::<TaskStatus>().is_err());
    }

    /// An open status is not terminal: a `stopping` row is out of every delivery pool and still
    /// counted as running, and a stop request has to be distinguished from the `running` it came
    /// from or the row would read as if nothing had been asked of it.
    #[test]
    fn a_stop_request_is_open_and_only_a_terminal_status_wakes_a_host() {
        assert!(!TaskStatus::Stopping.is_terminal());
        assert!(!TaskStatus::Running.is_terminal());
        assert!(!TaskStatus::Stopping.wakes_a_host());
        for status in [
            TaskStatus::Completed,
            TaskStatus::Failed,
            TaskStatus::Interrupted,
        ] {
            assert!(status.is_terminal());
            assert!(status.wakes_a_host());
        }
        assert!(TaskStatus::Canceled.is_terminal());
        assert!(!TaskStatus::Canceled.wakes_a_host());
    }

    #[test]
    fn render_names_the_task_and_what_happened() {
        let rendered = render_outcomes(&[task(TaskStatus::Completed, Some("42 passed"))]);
        assert!(rendered.contains("7f3a1c22"), "{rendered}");
        assert!(rendered.contains("cargo test --all"), "{rendered}");
        assert!(rendered.contains("finished"), "{rendered}");
        assert!(rendered.contains("42 passed"), "{rendered}");
    }

    /// A shell's output ends with a newline; the report ends with its own, so the output's would
    /// only put a blank line under it, on every surface that shows the report.
    #[test]
    fn an_outputs_own_trailing_newline_is_not_carried_into_the_report() {
        let rendered = render_outcomes(&[task(TaskStatus::Completed, Some("42 passed\n\n"))]);
        assert!(rendered.ends_with(".\n\n> 42 passed\n"), "{rendered:?}");
    }

    /// A task's output is whatever its command or sub-agent printed, a fetched page included, and
    /// the report is read in the user's role: no line of it may pass for the report's own header,
    /// another task's, or a prompt after it.
    #[test]
    fn a_tasks_output_is_quoted_line_by_line_in_its_report() {
        let rendered = render_outcomes(&[task(
            TaskStatus::Completed,
            Some(crate::text::FORGING_PAYLOAD),
        )]);
        crate::text::assert_payload_is_quoted(&rendered);
    }

    /// Each terminal state has to read differently: "your build failed" and "your build never ran"
    /// call for different next moves.
    #[test]
    fn each_terminal_status_reads_differently() {
        let headlines: Vec<String> = [
            TaskStatus::Completed,
            TaskStatus::Failed,
            TaskStatus::Canceled,
            TaskStatus::Interrupted,
        ]
        .into_iter()
        .map(|status| render_outcomes(&[task(status, None)]))
        .collect();
        for (index, first) in headlines.iter().enumerate() {
            for second in headlines.iter().skip(index + 1) {
                assert_ne!(first, second);
            }
        }
    }

    #[test]
    fn several_outcomes_coalesce_into_one_turn() {
        let rendered = render_outcomes(&[
            task(TaskStatus::Completed, Some("one")),
            task(TaskStatus::Failed, Some("two")),
        ]);
        assert!(rendered.contains("tasks (2)"), "{rendered}");
        assert!(
            rendered.contains("one") && rendered.contains("two"),
            "{rendered}"
        );
    }

    /// Outcome text is a shell command's stdout or a sub-agent's prose. Either can carry a bidi
    /// override or a terminal escape, and both are rendered to the user on the way past.
    #[test]
    fn outcome_text_is_sanitized() {
        let rendered = render_outcomes(&[task(
            TaskStatus::Completed,
            Some("done\u{202E}gnihtemos rehto"),
        )]);
        assert!(!rendered.contains('\u{202E}'), "{rendered}");
    }

    #[test]
    fn split_outcome_spills_only_when_oversized() {
        let (inline, spilled) = split_outcome("short");
        assert_eq!(inline, "short");
        assert!(spilled.is_none());

        let long = "x".repeat(OUTCOME_INLINE_BYTES + 100);
        let (inline, spilled) = split_outcome(&long);
        assert_eq!(inline.len(), OUTCOME_INLINE_BYTES);
        assert_eq!(spilled.as_deref(), Some(long.as_str()));
    }

    /// The limit bounds what lands in the conversation, which is measured in bytes. Cutting in
    /// characters would let a multi-byte log carry several times the budget inline, and just past
    /// the threshold the "head" would be the whole output.
    #[test]
    fn split_outcome_bounds_multibyte_output_by_bytes() {
        // Over the limit in bytes (three each), comfortably under it in characters.
        let log = "√".repeat(OUTCOME_INLINE_BYTES / 2);
        assert!(log.len() > OUTCOME_INLINE_BYTES);
        assert!(log.chars().count() < OUTCOME_INLINE_BYTES);

        let (inline, spilled) = split_outcome(&log);
        assert!(inline.len() <= OUTCOME_INLINE_BYTES, "{}", inline.len());
        assert!(
            inline.len() < log.len(),
            "a spilled outcome must not also carry the whole log inline",
        );
        assert_eq!(spilled.as_deref(), Some(log.as_str()));
    }

    #[test]
    fn spill_entry_name_is_unique_per_task() {
        assert_ne!(
            spill_entry_name("7f3a1c22-aaaa", "shell_execute"),
            spill_entry_name("91bd0e44-bbbb", "shell_execute"),
        );
        assert!(spill_entry_name("7f3a1c22-aaaa", "shell_execute").contains("7f3a1c22"));
    }

    #[test]
    fn spilled_outcome_names_its_entry() {
        let mut spilled = task(TaskStatus::Completed, Some("head of the log"));
        spilled.scratchpad_entry = Some("task_7f3a1c22_execute_command".to_string());
        let rendered = render_outcomes(&[spilled]);
        assert!(
            rendered.contains("task_7f3a1c22_execute_command"),
            "{rendered}"
        );
    }

    /// Only a cancellation is somebody's deliberate act, so only a cancellation waits.
    ///
    /// Every terminal outcome still reaches the model; this decides whether reaching it is worth a
    /// turn nobody asked for. Written over the whole enum rather than the two cases that motivated
    /// it, so a status added later has to answer the question rather than inherit an answer.
    #[test]
    fn only_a_cancellation_waits_for_a_turn_that_was_happening_anyway() {
        for status in [
            TaskStatus::Completed,
            TaskStatus::Failed,
            TaskStatus::Interrupted,
        ] {
            assert!(
                status.wakes_a_host(),
                "{} is nobody's decision, so the agent has to be told when it happens",
                status.name()
            );
        }
        assert!(
            !TaskStatus::Canceled.wakes_a_host(),
            "whoever canceled it already knows, and a stop command must not start a turn"
        );
        assert!(
            !TaskStatus::Stopping.wakes_a_host(),
            "a request is not an outcome, so there is nothing to deliver yet"
        );
    }

    /// A caller reports what the stamp gave it, not what it read a moment earlier.
    ///
    /// Two claimers reading the same row as unclaimed is ordinary, the compare-and-swap picks one,
    /// and a loser that reports its snapshot anyway delivers the outcome a second time.
    #[test]
    fn a_report_carries_only_the_outcomes_the_stamp_won() {
        // Distinct ids: the shared fixture hands out a fixed one, and a filter keyed on id cannot
        // be tested with two rows that carry the same one.
        let mut won = task(TaskStatus::Completed, Some("built"));
        won.id = "11111111-0000-0000-0000-000000000000".to_string();
        let mut lost = task(TaskStatus::Canceled, None);
        lost.id = "22222222-0000-0000-0000-000000000000".to_string();
        let read = vec![won.clone(), lost.clone()];

        let reported = only_what_was_won(read.clone(), &[won.id.clone()]);
        assert_eq!(
            reported.iter().map(|task| &task.id).collect::<Vec<_>>(),
            vec![&won.id],
            "the row this caller lost must not be reported by it"
        );
        assert!(
            only_what_was_won(read.clone(), &[]).is_empty(),
            "a caller that won nothing reports nothing"
        );
        assert_eq!(
            only_what_was_won(read, &[won.id, lost.id]).len(),
            2,
            "and winning everything reports everything"
        );
    }

    /// A prompt carrying an outcome is never withdrawn, whatever the schedule asked for.
    ///
    /// The branch only matters when a turn fails, so nothing that drives a successful turn can see
    /// it. Withdrawing a carrier prompt destroys the only copy of the outcome: the row was stamped
    /// delivered before the turn began and `list_undelivered_background_tasks` never returns it
    /// again.
    #[test]
    fn a_prompt_carrying_an_outcome_is_never_withdrawn() {
        let carried = [task(TaskStatus::Canceled, None)];
        for asked in [
            crate::conversation::PromptRetention::Keep,
            crate::conversation::PromptRetention::Withdraw,
        ] {
            assert_eq!(
                retention_carrying(&carried, asked),
                crate::conversation::PromptRetention::Keep,
                "an outcome rides on this prompt, so a failure must not take it with it"
            );
        }
        assert_eq!(
            retention_carrying(&[], crate::conversation::PromptRetention::Withdraw),
            crate::conversation::PromptRetention::Withdraw,
            "and a schedule carrying only its own prompt keeps the schedule's answer: the next occurrence \
             regenerates it"
        );
        assert_eq!(
            retention_carrying(&[], crate::conversation::PromptRetention::Keep),
            crate::conversation::PromptRetention::Keep
        );
    }

    /// The notice rides on a prompt rather than standing as a message of its own.
    ///
    /// A lone user message opens a turn (`crate::conversation::opens_turn`), so one nobody answers
    /// is a boundary with no turn behind it: `/rewind 1` cuts there instead of at the user's last
    /// exchange, compaction reads the conversation as ending on an unanswered prompt, and the next
    /// real prompt goes out as a second consecutive user turn.
    #[test]
    fn an_outcome_joins_a_prompt_rather_than_becoming_one() {
        let task = BackgroundTask {
            id: uuid::Uuid::new_v4().to_string(),
            session_id: uuid::Uuid::new_v4(),
            tool: "shell_execute".to_string(),
            label: "sleep 900".to_string(),
            status: TaskStatus::Canceled,
            outcome: None,
            scratchpad_entry: None,
            announced_at: None,
            started_at: chrono::Utc::now(),
            finished_at: Some(chrono::Utc::now()),
            delivered_at: None,
            subagent_id: None,
        };
        let joined = render_outcomes_riding(std::slice::from_ref(&task));

        assert!(
            joined.contains("was canceled"),
            "the outcome has to be in it: {joined}"
        );
        assert!(
            !joined.contains("Pick the work back up from here"),
            "the standalone trailer instructs the model to resume the canceled work, which is \
             wrong above somebody else's question: {joined}"
        );
        assert!(
            render_outcomes(std::slice::from_ref(&task))
                .contains("Pick the work back up from here"),
            "while the standalone form, which is the whole prompt, still says it"
        );
    }

    fn task_that_ran(id: &str, status: TaskStatus, seconds: i64) -> BackgroundTask {
        let finished_at = Utc::now();
        BackgroundTask {
            id: id.to_string(),
            started_at: finished_at - chrono::Duration::seconds(seconds),
            finished_at: Some(finished_at),
            outcome: Some("ok\n".to_string()),
            ..task(status, None)
        }
    }

    /// One task names how it ended and how long it ran; a batch names each task and its end. The
    /// output is never in it.
    #[test]
    fn a_report_direction_names_the_tasks_and_how_they_ended() {
        let one = report_direction(&[task_that_ran(
            "3881c9c6-0000-4000-8000-000000000000",
            TaskStatus::Completed,
            30,
        )]);
        assert_eq!(one, "Background task 3881c9c6 finished after 30s");
        let two = report_direction(&[
            task_that_ran(
                "3881c9c6-0000-4000-8000-000000000000",
                TaskStatus::Failed,
                5,
            ),
            task_that_ran(
                "7f3a1c22-0000-4000-8000-000000000000",
                TaskStatus::Canceled,
                5,
            ),
        ]);
        assert_eq!(
            two,
            "2 background tasks: 3881c9c6 failed, 7f3a1c22 was canceled"
        );
        assert!(!one.contains("ok") && !two.contains("ok"));
    }

    /// The mid-turn form tells the model to carry on, where the standalone form has it pick the
    /// work back up and the riding form answer what follows.
    #[test]
    fn the_mid_turn_form_tells_the_model_to_carry_on() {
        let tasks = [task(TaskStatus::Completed, Some("ok"))];
        let mid_turn = render_outcomes_mid_turn(&tasks);
        assert!(
            mid_turn.starts_with("[Background task reporting at ")
                && mid_turn.contains("Carry on with them in mind")
                && !mid_turn.contains("answer what follows")
                && !mid_turn.contains("Pick the work back up"),
            "{mid_turn}"
        );
    }
}
