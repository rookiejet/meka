//! `shell_execute` tool. Spawns a shell process, optionally constrained by the platform sandbox
//! when permissions are read-only, and streams stdout/stderr back to the agent as it arrives.
//!
//! The sandbox is Landlock or Bubblewrap on Linux (see [`crate::sandbox`] for which is preferred),
//! `sandbox-exec` on macOS, and a low-integrity token on Windows, which is spawned through
//! `CreateProcessAsUserW` rather than `tokio::process` because the standard library offers no hook
//! for injecting one.

#[cfg(windows)]
use std::os::windows::fs::MetadataExt;
use std::sync::Arc;

use async_trait::async_trait;

use super::{Tool, ToolOutput, util::require_str};
use crate::{
    error::{MekaError, Result},
    permission::Permission,
    provider::ToolDefinition,
};

/// `timeout_ms` when the caller passes none. Single source of truth for both the parameter unwrap
/// and the description shown to the agent.
const DEFAULT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// The directories Bubblewrap masks with a private tmpfs: where socket-on-disk IPC lives, replaced
/// by empty, writable, throwaway space.
#[cfg(target_os = "linux")]
fn bwrap_masks() -> Vec<std::path::PathBuf> {
    let mut masks: Vec<std::path::PathBuf> = ["/tmp", "/run", "/var/tmp"]
        .iter()
        .map(std::path::PathBuf::from)
        .collect();
    if let Ok(xdg) = std::env::var("XDG_RUNTIME_DIR")
        && std::path::Path::new(&xdg).is_absolute()
    {
        masks.push(xdg.into());
    }
    existing_directories(masks)
}

/// The `candidates` that are directories. Under the read-only root Bubblewrap cannot make the mount
/// point for a mask over a path that does not exist, and fails the command; where there is no
/// directory there is nothing to hide.
#[cfg(target_os = "linux")]
fn existing_directories(candidates: Vec<std::path::PathBuf>) -> Vec<std::path::PathBuf> {
    candidates
        .into_iter()
        .filter(|path| path.is_dir())
        .collect()
}

/// Every bwrap argument up to the `--` separator, for `writable` roots, reading everywhere or only
/// beneath `readable`.
///
/// Factored out of the spawn so the ordering rule below is testable without a live child. Order is
/// the whole correctness argument here and it is invisible in the resulting mount namespace: bwrap
/// applies operations onto the new root in sequence and the last one to touch a path wins, so a
/// bind placed before the tmpfs masks is silently undone by them. A workspace under `/tmp` (where
/// every test fixture and a fair number of real scratch directories live) would come out read-only
/// with no error from bwrap, no error from Meka, and a level that quietly confines the shell to
/// nothing.
#[cfg(target_os = "linux")]
fn bwrap_args(
    writable: &[std::path::PathBuf],
    readable: Option<&[std::path::PathBuf]>,
    cwd: &std::path::Path,
    private: &[std::path::PathBuf],
    network: crate::config::Network,
) -> Vec<std::ffi::OsString> {
    // Reading everywhere, `--ro-bind /` enforces "no writes". Reading within a boundary, the root
    // is an empty tmpfs instead and only the readable paths are bound into it, read-only: what is
    // not bound is absent rather than refused, so a confined command sees no name outside its
    // roots and a symlink out of them points at nothing. `--unshare-*` cuts off PID / user / UTS /
    // IPC views, and the tmpfs masks over `/run`, `/tmp`, `/var/tmp` and `$XDG_RUNTIME_DIR` make
    // the dbus and systemd-user sockets unreachable so the agent cannot `dbus-send` state-changing
    // methods. `--unshare-net` only on `none`: by default the network stays open for `curl |
    // pdftotext` and similar pipelines.
    let root: &[&str] = match readable {
        Some(_) => &["--tmpfs", "/"],
        None => &["--ro-bind", "/", "/"],
    };
    let mut args: Vec<std::ffi::OsString> = ["--new-session", "--die-with-parent"]
        .iter()
        .chain(root)
        .chain(&[
            "--dev",
            "/dev",
            "--proc",
            "/proc",
            "--unshare-user",
            "--unshare-pid",
            "--unshare-uts",
            "--unshare-ipc",
            "--unshare-cgroup-try",
        ])
        .map(std::ffi::OsString::from)
        .collect();
    // Against `host` rather than `none`: a setting the namespace cannot express, `remote`, is cut
    // off whole here whatever the caller passed, never let through.
    if network != crate::config::Network::Host {
        args.push("--unshare-net".into());
    }

    for mask in bwrap_masks() {
        args.push("--tmpfs".into());
        args.push(mask.into());
    }

    // The readable paths, after the masks so a root under one is bound back in, and before the
    // writable binds, whose later mount makes a root read-write. `/dev` and `/proc` are the two
    // mounts above, and binding the host's over them would hand back every device and every
    // process.
    for path in readable.unwrap_or_default() {
        if path == std::path::Path::new("/dev") || path == std::path::Path::new("/proc") {
            continue;
        }
        args.push("--ro-bind-try".into());
        args.push(path.into());
        args.push(path.into());
    }

    // The working directory, read-only, after the masks and before the writable binds.
    //
    // Without it a session whose cwd is under a masked directory loses the directory entirely, and
    // bwrap's fallback is silent: `Command::current_dir` chdirs before `execve`, bwrap cannot
    // re-enter that path inside the new root, and it lands the child in `$HOME` instead, while
    // `file_read` and `file_search` run in-process and see the real files.
    //
    // Read-only because a writable root that happens to be the cwd is bound read-write by the loop
    // below, and a later mount wins.
    //
    // Skipped when the cwd is a masked directory, or an ancestor of one, because the same
    // last-mount-wins rule would otherwise undo every mask above it: a session at `/tmp` would see
    // the host's tmux socket, one at `$XDG_RUNTIME_DIR` the session bus, and one at `/` the host's
    // PIDs. That is the escape `is_system_root` exists to prevent, arriving through the one door it
    // does not guard: it filters the writable roots, and the cwd is bound whether or not it is one.
    //
    // Nothing is lost by skipping it. `--chdir` below is unconditional, and a masked directory
    // still exists inside the sandbox as the empty tmpfs, so the child lands there and sees what
    // the mask intends rather than being relocated to `$HOME`. A path merely under a mask
    // (`/tmp/work`) is not a masked root, so it still gets its bind and still works.
    if !crate::workspace::is_system_root(cwd) {
        args.push("--ro-bind-try".into());
        args.push(cwd.into());
        args.push(cwd.into());
    }

    for root in writable {
        // `--bind-try`, not `--bind`. A root is canonicalized when the confinement is resolved and
        // mounted a moment later; a concurrent `shell_execute` running `rm -rf` on it in between
        // makes plain `--bind` abort the whole spawn with a bwrap error the model cannot act on.
        // Landlock already degrades the same way (it skips a root it cannot open rather than
        // failing the command), and this is the same rule spelled in bwrap's own vocabulary.
        args.push("--bind-try".into());
        args.push(root.into());
        args.push(root.into());
    }

    // Every directory between a writable root and a private directory under it, bound onto itself
    // so it is a mount point, which cannot be renamed or removed. The masks below are anchored to
    // paths: a command that renamed `~/.local` would carry the credential store out from under the
    // path the next command's mask names, and that command would read it at the new one.
    for directory in crate::workspace::pinned_ancestors(writable, private) {
        args.push("--bind-try".into());
        args.push(directory.clone().into());
        args.push(directory.into());
    }

    // Meka's own directories, masked after every bind so they stay hidden under a writable root
    // that contains them: later mounts win, which is what would otherwise let a root at `$HOME`
    // hand `~/.config/meka` and the credential store beside it to a confined shell. See
    // `workspace::private_directories` for what is in the list and why.
    for directory in private {
        args.push("--tmpfs".into());
        args.push(directory.into());
    }

    // Asked for explicitly rather than inherited through the pre-`execve` chdir, so that a cwd
    // bwrap cannot enter is a loud failure the model can read instead of a silent relocation to
    // `$HOME`. Last, so it applies to the mounts above it.
    args.push("--chdir".into());
    args.push(cwd.into());
    args
}

/// The command Bubblewrap execs when the kernel has a usable Landlock: Meka itself, reached as
/// `program`, which enacts the ruleset after bwrap's mounts and then becomes the shell.
///
/// The workspace roots are writable; every mask and `/dev` are scratch. The masks because bwrap
/// already made them writable throwaway space and the layer must not take that back, though a
/// socket from outside that a bind put under one stays out of reach; `/dev` because bwrap's is the
/// private minimal set rather than the host's devices, and refusing an ioctl there would only break
/// pty allocation (`script`, `expect`). Private directories are not passed: the masks hide them,
/// and a walk inside the sandbox would find only empty tmpfs.
#[cfg(target_os = "linux")]
fn inner_confinement_argv(
    program: &std::path::Path,
    writable: &[std::path::PathBuf],
    readable: Option<&[std::path::PathBuf]>,
) -> Vec<std::ffi::OsString> {
    let mut argv: Vec<std::ffi::OsString> = vec![program.into(), "confine".into()];
    for root in writable {
        argv.push("--writable".into());
        argv.push(root.into());
    }
    for path in readable.unwrap_or_default() {
        argv.push("--readable".into());
        argv.push(path.into());
    }
    let mut scratch = bwrap_masks();
    scratch.push("/dev".into());
    for directory in scratch {
        argv.push("--scratch".into());
        argv.push(directory.into());
    }
    argv.push("--".into());
    argv
}

/// The executable that enacts the Landlock layer inside the sandbox: this process's own, opened
/// through `/proc/self/exe`, which names the running image even after the file behind it was
/// replaced or deleted. Bubblewrap execs it through the descriptor rather than a path, so a
/// package upgrade under a running server does not break the shell until a restart.
///
/// An error rather than a fallback to bwrap alone: a command run one layer short would report
/// nothing, and `/proc/self/exe` is unreadable only on a host where `/proc` itself is missing.
#[cfg(target_os = "linux")]
fn inner_layer_executable() -> Result<std::fs::File> {
    #[cfg(test)]
    let opened = INNER_LAYER_EXECUTABLE
        .with(|slot| slot.borrow().as_ref().map(std::fs::File::try_clone))
        .unwrap_or_else(|| std::fs::File::open("/proc/self/exe"));
    #[cfg(not(test))]
    let opened = std::fs::File::open("/proc/self/exe");
    opened.map_err(|error| MekaError::ToolExecution {
        tool_name: "shell_execute".to_string(),
        message: format!(
            "failed to open Meka's own executable for the sandbox's Landlock layer: {error}"
        ),
    })
}

#[cfg(all(test, target_os = "linux"))]
thread_local! {
    /// The executable [`inner_layer_executable`] hands to bwrap under test, when a test has set
    /// one: the built `meka`, since the test binary has no `confine` verb.
    static INNER_LAYER_EXECUTABLE: std::cell::RefCell<Option<std::fs::File>> =
        const { std::cell::RefCell::new(None) };
}

#[derive(Clone)]
pub(crate) struct ExecuteCommandTool {
    /// The managed WSL target this shell may route a literal invocation through, when one is
    /// configured. The channel is call-bound: created and destroyed within one `shell_execute`
    /// call, never a general-purpose endpoint. `None` keeps the native shell only.
    #[cfg(windows)]
    pub(crate) wsl_target: Option<Arc<crate::subshell::Target>>,
    /// Named SSH targets this shell may reach, when configured. The SSH transport requires
    /// `unrestricted`.
    pub(crate) ssh_targets: std::collections::BTreeMap<String, Arc<crate::subshell::SshTarget>>,
    /// The process's workspace-ACE ledger on Windows.
    ///
    /// A handle on the one `process_grants()` singleton, not a per-tool ledger. It reads as a
    /// field because that is how the tool reaches it, and the distinction matters: an ACE is
    /// machine state, so a per-registry ledger had a sub-agent's teardown revoke the ACEs its
    /// parent was still writing through. Released by `release_process_grants` at process exit
    /// rather than by `Drop`; see [`crate::sandbox::windows::WindowsGrants`] for what
    /// that does and does not cover.
    #[cfg(windows)]
    pub(crate) windows_grants: std::sync::Arc<crate::sandbox::windows::WindowsGrants>,
    /// The write boundary, shared with `file_write`. The shell derives its sandbox allow-list from
    /// the same [`crate::workspace::WriteScope`] the file tools fence against, so the two cannot
    /// disagree about where a write may land.
    pub(crate) scope: crate::workspace::WriteScope,
    pub(crate) sandbox_capability: crate::sandbox::SandboxCapability,
    /// Backend chosen in config (or auto-resolved), named by the hard-error message in
    /// [`Tool::execute`].
    pub(crate) sandbox_backend: crate::config::SandboxBackend,
    /// Probe outcome for [`Self::sandbox_backend`]. Drives the hard-error path at `read` when
    /// the backend isn't usable (bwrap missing, user namespaces denied, etc.). When `Ok(_)`,
    /// [`Self::sandbox_capability`] mirrors the inner capability and the spawn path runs normally.
    pub(crate) backend_probe: crate::sandbox::BackendProbe,
    pub(crate) sandbox_enabled: bool,
    pub(crate) site: crate::session::ToolSite,
}

impl ExecuteCommandTool {
    /// Whether a command may be spawned at `permission` given that its confinement `sandboxed` it
    /// or did not. Asked by `execute` ahead of the spawn and by `refusal_at_level` ahead of the
    /// approval prompt, so the two cannot disagree about a refusal approval could never lift.
    ///
    /// `[shell].sandbox = false` unconfines every level. That is right for the levels that never
    /// promised a boundary and wrong for every level that did: left alone it would run the shell
    /// with no confinement while the file tools stayed fenced, so one config key would make the
    /// level mean two different things and the weaker meaning would be the silent one.
    ///
    /// Refused rather than hidden. `required_permission` cannot hide it: `Workspace.allows` is true
    /// for everything by design, because scope is meant to be enforced at the door rather than by
    /// withholding tools. Refusing at that door is the same shape as the write fence, and it can
    /// say what to do about it where a missing tool could not.
    ///
    /// `unrestricted` is the only level whose intent is `Unconfined`; every other level reaching an
    /// unconfined spawn is a configuration that cannot deliver what the level says. Keyed on
    /// `workspace` alone, the sibling case stays open: `[tools.tool_permissions]` overrides a
    /// tool's required level with no floor, so `shell_execute = "read"` plus `[shell].sandbox =
    /// false` would run a plain `sh -c` at `read`, with the full parent environment, since the
    /// scrub is gated on `sandboxed` too.
    fn admit_confinement(&self, permission: Permission, sandboxed: bool) -> Result<()> {
        if permission != Permission::Unrestricted && !sandboxed {
            return Err(MekaError::ToolExecution {
                tool_name: "shell_execute".to_string(),
                message: "`[shell].sandbox = false` leaves nothing to confine this command \
                          below `unrestricted`; set `[shell].sandbox = true`"
                    .to_string(),
            });
        }
        if !sandboxed {
            return Ok(());
        }
        // Configured backend isn't usable on this host. Hard-error with the specific reason so the
        // model can surface it via `render::render_error` rather than treat the failure as a tool
        // result it could try to recover from.
        let Some(reason) = crate::sandbox::backend_unavailable_reason(&self.backend_probe) else {
            return Ok(());
        };
        let named = crate::sandbox::backend_label(self.sandbox_backend, &self.backend_probe)
            .map(|label| format!(" ({label})"))
            .unwrap_or_default();
        let remedy = crate::sandbox::backend_remedy(&self.backend_probe)
            .map(|remedy| format!("; {remedy}"))
            .unwrap_or_default();
        Err(MekaError::ToolExecution {
            tool_name: "shell_execute".to_string(),
            message: format!("sandbox backend{named} is unavailable: {reason}{remedy}"),
        })
    }
}

#[async_trait]
impl Tool for ExecuteCommandTool {
    /// A command's exit code and output are its result however it ended, so a failed command's
    /// output goes where the call sent it.
    fn reports_failure_as_output(&self) -> bool {
        true
    }

    fn definition(&self) -> ToolDefinition {
        let mut properties = serde_json::Map::new();
        properties.insert(
            "command".to_string(),
            serde_json::json!({
                "type": "string",
                "description": "The shell command to execute."
            }),
        );
        properties.insert(
            "timeout_ms".to_string(),
            serde_json::json!({
                "type": "integer",
                "default": DEFAULT_TIMEOUT.as_millis(),
                "description": format!(
                    "Timeout in milliseconds. Default: {} ({} seconds).",
                    DEFAULT_TIMEOUT.as_millis(),
                    DEFAULT_TIMEOUT.as_secs(),
                )
            }),
        );
        properties.insert(
            "scratchpad".to_string(),
            serde_json::json!({
                "type": "string",
                "description": "If provided, save the output to the scratchpad under this name instead of returning it inline."
            }),
        );
        #[cfg(windows)]
        if self.wsl_target.is_some() {
            properties.insert(
                "wsl".to_string(),
                serde_json::json!({
                    "type": "object",
                    "description": "Route this command through the managed WSL target as a one-shot confined call instead of the native shell. The channel is call-bound: it is created and destroyed within this call, never a persistent endpoint.",
                    "properties": {
                        "working_directory": {"type": "string", "description": "A granted WSL directory to mount at /workspace."},
                        "workspace": {"type": "array", "items": {"type": "string"}, "description": "Additional workspace grants, mounted at /workspaces/0, /workspaces/1, etc."},
                        "readable": {"type": "array", "items": {"type": "string"}, "description": "Additional read-only grants, mounted at /references/0, /references/1, etc."},
                        "read_only": {"type": "boolean", "default": false, "description": "Mount everything read-only."}
                    },
                    "required": ["working_directory"]
                }),
            );
        }
        if !self.ssh_targets.is_empty() {
            properties.insert(
                "ssh".to_string(),
                serde_json::json!({
                    "type": "object",
                    "description": "Route this command through a named SSH target. The transport requires unrestricted permission and `[permissions].network = \"host\"`: the local client dials whatever address the target names, so a remote-only setting cannot be enforced for it. The command is interpreted by the remote login shell, not by this host's shell.",
                    "properties": {
                        "target": {"type": "string", "enum": self.ssh_targets.keys().cloned().collect::<Vec<_>>(), "description": "The name of the SSH target from [shell.ssh]."},
                        "working_directory": {"type": "string", "description": "An absolute path on the remote host for command placement. Not a sandbox boundary."}
                    },
                    "required": ["target"]
                }),
            );
        }
        ToolDefinition {
            name: "shell_execute".to_string(),
            description: {
                #[cfg(windows)]
                let wsl_note = if self.wsl_target.is_some() {
                    " With `wsl`, the command runs in the managed WSL target instead of the native shell."
                } else {
                    ""
                };
                #[cfg(not(windows))]
                let wsl_note = "";
                format!(
                    "{} Each call starts in the session's working directory; shell state does not \
                     persist between calls. At restricted levels a suitable sandbox is required. \
                     Background execution keeps `timeout_ms` unchanged. A command that prints more \
                     than {} is stopped.{}",
                    if cfg!(windows) {
                        "Run PowerShell syntax via `powershell.exe -Command`. Do not nest another `powershell -Command`."
                    } else {
                        "Run a POSIX shell command via `sh -c`. Use POSIX quoting."
                    },
                    crate::text::format_size(MAX_OUTPUT_BYTES),
                    wsl_note,
                )
            },
            parameters: serde_json::json!({
                "type": "object",
                "properties": properties,
                "required": ["command"]
            }),
            ..Default::default()
        }
    }

    fn required_permission(&self) -> Permission {
        let native = self.sandbox_enabled
            && !matches!(
                self.sandbox_capability,
                crate::sandbox::SandboxCapability::Unavailable
            );
        // A route confines itself, so a session with one is a `read` session even when no native
        // backend can run: the dispatcher's gate must let the call reach `refusal_at_level`, which
        // judges the route it names and refuses a native command that has nothing to confine it.
        #[cfg(windows)]
        let routed = self.wsl_target.is_some() || !self.ssh_targets.is_empty();
        #[cfg(not(windows))]
        let routed = !self.ssh_targets.is_empty();
        if native || routed {
            Permission::Read
        } else {
            Permission::Unrestricted
        }
    }

    /// The level and the configuration decide whether anything can confine a command; the command
    /// itself and the user's answer do not. A routed call is judged by its route: a WSL target
    /// confines itself, an SSH target runs only at `unrestricted`, and neither depends on a native
    /// sandbox backend the route does not use.
    async fn refusal_at_level(
        &self,
        level: Permission,
        input: &serde_json::Value,
    ) -> Option<ToolOutput> {
        match Self::selected_route(input) {
            Err(error) => return Some(ToolOutput::from_error(&error)),
            Ok(Some(route)) => return self.route_refusal(level, route),
            Ok(None) => {}
        }
        let confinement = crate::sandbox::Confinement::resolve(
            self.sandbox_enabled,
            level,
            &self.scope,
            &self.site.read_scope(),
            &self.site.cwd,
            self.site.network,
        );
        self.admit_confinement(level, confinement.is_sandboxed())
            .err()
            .map(|error| ToolOutput::from_error(&error))
    }

    fn as_detachable(&self) -> Option<&dyn crate::tools::Detachable> {
        Some(self)
    }

    async fn execute(
        &self,
        input: serde_json::Value,
        context: crate::tools::ToolContext,
    ) -> Result<ToolOutput> {
        crate::tools::start_and_run(self, input, context).await
    }
}

#[async_trait]
impl crate::tools::Detachable for ExecuteCommandTool {
    /// The arguments and the confinement the level admits; the run spawns the command, so no
    /// process exists before the call is recorded.
    async fn start(
        &self,
        input: serde_json::Value,
        _context: &crate::tools::ToolContext,
    ) -> Result<crate::tools::Started> {
        let command = require_str(&input, "command", "shell_execute")?;
        let timeout = super::util::optional_u64(&input, "timeout_ms", "shell_execute")?
            .map(std::time::Duration::from_millis)
            .unwrap_or(DEFAULT_TIMEOUT);
        match Self::selected_route(&input)? {
            Some(SubshellRoute::Wsl) => {
                #[cfg(windows)]
                {
                    let wsl = super::util::optional_object(&input, "wsl", "shell_execute")?
                        .cloned()
                        .unwrap_or_default();
                    return self.start_wsl(command, timeout, &serde_json::Value::Object(wsl));
                }
                #[cfg(not(windows))]
                return Err(subshell_error(
                    "shell_execute",
                    "the managed WSL route is available on Windows only",
                ));
            }
            Some(SubshellRoute::Ssh(ssh)) => {
                return self.start_ssh(command, timeout, &serde_json::Value::Object(ssh.clone()));
            }
            None => {}
        }
        let permission = self.site.permission.get();
        // Three states, resolved once: the run asks the `Confinement` rather than re-deriving "is
        // it sandboxed" from the level, which is how the read-only and workspace-writable cases
        // would drift apart.
        let confinement = crate::sandbox::Confinement::resolve(
            self.sandbox_enabled,
            permission,
            &self.scope,
            &self.site.read_scope(),
            &self.site.cwd,
            self.site.network,
        );
        self.admit_confinement(permission, confinement.is_sandboxed())?;
        let tool = self.clone();
        Ok(crate::tools::Started::running(
            None,
            move |context| async move { tool.run(command, timeout, confinement, context).await },
        ))
    }
}

/// The route a `shell_execute` call selected. `Wsl` exists only where a WSL target can run, but it
/// is a distinct route on every platform so the refusal for naming it elsewhere has one home.
enum SubshellRoute<'a> {
    #[allow(dead_code, reason = "the route only runs on Windows")]
    Wsl,
    Ssh(&'a serde_json::Map<String, serde_json::Value>),
}

impl ExecuteCommandTool {
    /// The route a `shell_execute` input selects. `wsl` and `ssh` are mutually exclusive, and a
    /// selector that cannot run here is refused rather than silently ignored: a command must not
    /// fall through to the native shell because its route was misspelled or unsupported.
    fn selected_route(input: &serde_json::Value) -> Result<Option<SubshellRoute<'_>>> {
        let wsl = super::util::optional_object(input, "wsl", "shell_execute")?;
        let ssh = super::util::optional_object(input, "ssh", "shell_execute")?;
        match (wsl, ssh) {
            (Some(_), Some(_)) => Err(subshell_error(
                "shell_execute",
                "`wsl` and `ssh` select different routes; pass at most one",
            )),
            (Some(_), None) => {
                #[cfg(windows)]
                {
                    Ok(Some(SubshellRoute::Wsl))
                }
                #[cfg(not(windows))]
                {
                    Err(subshell_error(
                        "shell_execute",
                        "the `wsl` route is only available on Windows",
                    ))
                }
            }
            (None, Some(ssh)) => Ok(Some(SubshellRoute::Ssh(ssh))),
            (None, None) => Ok(None),
        }
    }

    /// The refusal a routed call meets from its own target, before anything is launched. A route
    /// answers to what it runs, not to the native backend the call does not use.
    fn route_refusal(&self, level: Permission, route: SubshellRoute<'_>) -> Option<ToolOutput> {
        match route {
            SubshellRoute::Wsl => {
                #[cfg(windows)]
                {
                    if self.wsl_target.is_none() {
                        return Some(ToolOutput::from_error(&subshell_error(
                            "shell_execute",
                            "no managed WSL target is configured",
                        )));
                    }
                    if !Permission::Read.is_within(level) {
                        return Some(ToolOutput::from_error(&subshell_error(
                            "shell_execute",
                            format!(
                                "managed WSL requires at least `read` permission; the session is \
                                 at `{level}`"
                            ),
                        )));
                    }
                    None
                }
                #[cfg(not(windows))]
                Some(ToolOutput::from_error(&subshell_error(
                    "shell_execute",
                    "the `wsl` route is only available on Windows",
                )))
            }
            SubshellRoute::Ssh(ssh) => {
                let refusal = (|| -> Result<()> {
                    let name = require_str(
                        &serde_json::Value::Object(ssh.clone()),
                        "target",
                        "shell_execute",
                    )?;
                    let target = self.ssh_targets.get(&name).ok_or_else(|| {
                        subshell_error("shell_execute", format!("unknown SSH target {name:?}"))
                    })?;
                    let minimum = target.minimum_permission();
                    if !minimum.is_within(level) {
                        return Err(subshell_error(
                            "shell_execute",
                            format!(
                                "SSH target {name:?} requires `{}` permission; the session is at \
                                 `{level}`",
                                minimum.name()
                            ),
                        ));
                    }
                    if self.site.network != crate::config::Network::Host {
                        return Err(subshell_error(
                            "shell_execute",
                            format!(
                                "SSH target {name:?} needs `[permissions].network = \"host\"`; \
                                 `{}` cannot be enforced for a client that dials the target's \
                                 address",
                                self.site.network
                            ),
                        ));
                    }
                    Ok(())
                })();
                refusal.err().map(|error| ToolOutput::from_error(&error))
            }
        }
    }

    /// Route a literal invocation through the managed WSL broker as a one-shot call-bound
    /// channel. The channel lives and dies within this call: no persistent handle, no endpoint
    /// the Windows user could reach after the call ends.
    #[cfg(windows)]
    fn start_wsl(
        &self,
        command: String,
        timeout: std::time::Duration,
        wsl: &serde_json::Value,
    ) -> Result<crate::tools::Started> {
        use super::util::{optional_bool, string_or_list};

        let target = self.wsl_target.as_ref().ok_or_else(|| {
            subshell_error("shell_execute", "no managed WSL target is configured")
        })?;
        let lease = self.site.permission.lease();
        let working_directory = require_str(wsl, "working_directory", "shell_execute")?;
        let workspace = string_or_list(wsl, "workspace", "shell_execute")?.unwrap_or_default();
        let readable = string_or_list(wsl, "readable", "shell_execute")?.unwrap_or_default();
        let read_only = optional_bool(wsl, "read_only", "shell_execute")?.unwrap_or(false);
        let timeout_ms = timeout.as_millis() as u64;
        let (request, proofs) = target
            .request(
                crate::subshell::Selection {
                    working_directory,
                    workspace,
                    readable,
                    read_only,
                    timeout_ms,
                    command,
                    scratch: None,
                    transfer: None,
                },
                lease.level,
            )
            .map_err(|error| subshell_error("shell_execute", error))?;
        let request_timeout = request.timeout();
        let frame = request
            .encode()
            .map_err(|error| subshell_error("shell_execute", error))?;
        let target = Arc::clone(target);
        Ok(crate::tools::Started::running(
            None,
            move |context| async move {
                // The proofs live as long as the request they mounted: until this call is done.
                let _proofs = proofs;
                let started = tokio::time::Instant::now();
                // Bound delivery as well as execution, and let a stop interrupt the delivery.
                // A request stopped here may already have reached the guest, so whether a command
                // started is unconfirmed; once the launcher is owned, `run_wsl_command_tree`
                // observes the stop itself.
                let launching = tokio::time::timeout(
                    request_timeout,
                    crate::sandbox::wsl_host::launch(&target, &frame),
                );
                tokio::pin!(launching);
                let delivered = tokio::select! {
                    biased;
                    () = lease.revoked() => {
                        if let Some(observation) = &context.teardown {
                            observation.note(false);
                        }
                        return Err(subshell_error("shell_execute", "permission was lowered during setup; whether the managed WSL command started is unconfirmed"));
                    }
                    () = context.cancellation.cancelled() => {
                        if let Some(observation) = &context.teardown {
                            observation.note(false);
                        }
                        return Err(MekaError::Interrupted);
                    }
                    delivered = &mut launching => delivered,
                };
                let child = delivered
                    .map_err(|_| {
                        subshell_error(
                            "shell_execute",
                            "timed out delivering the managed WSL request",
                        )
                    })?
                    .map_err(|error| subshell_error("shell_execute", format!("{error:#}")))?;
                run_wsl_command_tree(
                    child,
                    &request.op,
                    lease.level,
                    request_timeout.saturating_sub(started.elapsed()),
                    &context,
                    &lease,
                    None,
                )
                .await
                .map_err(|failure| match failure {
                    CommandTreeError::Interrupted => MekaError::Interrupted,
                    CommandTreeError::Wait(error) => subshell_error(
                        "shell_execute",
                        format!("failed to wait for the WSL launcher: {error}"),
                    ),
                })
            },
        ))
    }

    /// Route a command through a named SSH target. A remote login reaches a machine this process
    /// has no boundary on, so the transport runs only at `unrestricted`, and only when the
    /// session's network setting permits a remote connection. The target address is the scope.
    fn start_ssh(
        &self,
        command: String,
        timeout: std::time::Duration,
        ssh: &serde_json::Value,
    ) -> Result<crate::tools::Started> {
        if let Some(fields) = ssh.as_object() {
            for field in fields.keys() {
                if !matches!(field.as_str(), "target" | "working_directory") {
                    return Err(subshell_error(
                        "shell_execute",
                        format!(
                            "unknown `ssh` parameter {field:?}; the route takes `target` and \
                             `working_directory` only"
                        ),
                    ));
                }
            }
        }
        let target_name = require_str(ssh, "target", "shell_execute")?;
        let target = self.ssh_targets.get(&target_name).ok_or_else(|| {
            subshell_error(
                "shell_execute",
                format!("unknown SSH target {target_name:?}"),
            )
        })?;
        if self.site.network != crate::config::Network::Host {
            return Err(subshell_error(
                "shell_execute",
                format!(
                    "SSH target {target_name:?} needs `[permissions].network = \"host\"`; `{}` \
                     cannot be enforced for a client that dials the target's address",
                    self.site.network
                ),
            ));
        }
        let lease = self.site.permission.lease();
        let minimum = target.minimum_permission();
        if !minimum.is_within(lease.level) {
            return Err(subshell_error(
                "shell_execute",
                format!(
                    "SSH target {target_name:?} requires `{}` permission; the session is at `{}`",
                    minimum.name(),
                    lease.level
                ),
            ));
        }
        let working_directory =
            super::util::optional_str(ssh, "working_directory", "shell_execute")?;
        let full_command = match working_directory {
            Some(working_directory) => {
                if !working_directory.starts_with('/')
                    || working_directory.chars().any(char::is_control)
                {
                    return Err(subshell_error(
                        "shell_execute",
                        format!(
                            "an SSH working directory must be an absolute remote path: \
                             {working_directory:?}"
                        ),
                    ));
                }
                format!(
                    "cd -- {} || exit 1\n{command}",
                    shell_quote(working_directory)
                )
            }
            None => command,
        };
        let (args, known_hosts) = target
            .ssh_args(&full_command)
            .map_err(|error| subshell_error("shell_execute", error))?;
        let binary = ssh_binary()?;
        let label = target.name.clone();
        Ok(crate::tools::Started::running(
            None,
            move |context| async move {
                // The pinned key file lives until `ssh` has read it.
                let _known_hosts = known_hosts;
                // The level that admitted the call can fall before this run reaches the spawn,
                // and a downgrade followed by a raise must not revive the lease either. A stop
                // accepted before the run reaches this point is settled in the same step: with
                // the same locks a downgrade takes held, there is no window in which a stopped
                // call still starts a client. Checking outside the gate and spawning inside it
                // would leave exactly that window.
                enum Launch {
                    NotStarted,
                    Spawned(Box<std::io::Result<crate::process::Tree>>),
                }
                let launched = lease.with_current_authority(minimum, || {
                    if context.cancellation.is_cancelled() {
                        return Launch::NotStarted;
                    }
                    let mut process = tokio::process::Command::new(&binary);
                    process
                        .args(&args)
                        .stdin(std::process::Stdio::null())
                        // Both streams are pipes: what the remote command prints comes back
                        // through the same collector as a native command, so it is bounded,
                        // relayed to a live view, and never written to Meka's own stdout (which
                        // in ACP carries the protocol).
                        .stdout(std::process::Stdio::piped())
                        .stderr(std::process::Stdio::piped());
                    ssh_environment(&mut process);
                    Launch::Spawned(Box::new(crate::process::spawn_tree(&mut process)))
                });
                let Some(launched) = launched else {
                    if let Some(observation) = &context.teardown {
                        observation.note(true);
                    }
                    return Err(subshell_error(
                        "shell_execute",
                        format!(
                            "permission was lowered; the SSH call to {label:?} was not started"
                        ),
                    ));
                };
                let Launch::Spawned(spawned) = launched else {
                    if let Some(observation) = &context.teardown {
                        observation.note(true);
                    }
                    return Err(subshell_error(
                        "shell_execute",
                        format!("the SSH call to {label:?} was stopped before ssh was started"),
                    ));
                };
                let child = (*spawned).map_err(|error| {
                    subshell_error(
                        "shell_execute",
                        format!("failed to start {}: {error}", binary.display()),
                    )
                })?;
                // The route observes both stop authorities itself, so a cancellation or a
                // revocation ends the client through the collector and the result still holds
                // what it printed. Neither says anything about the remote command.
                run_ssh_command_tree(child, timeout, &context, &lease)
                    .await
                    .map_err(|failure| match failure {
                        CommandTreeError::Interrupted => MekaError::Interrupted,
                        CommandTreeError::Wait(error) => subshell_error(
                            "shell_execute",
                            format!("failed to wait for ssh: {error}"),
                        ),
                    })
            },
        ))
    }

    /// Spawn `command` under `confinement`, as admitted, and collect what it printed.
    async fn run(
        &self,
        command: String,
        timeout: std::time::Duration,
        confinement: crate::sandbox::Confinement,
        context: crate::tools::ToolContext,
    ) -> Result<ToolOutput> {
        #[cfg(any(windows, target_os = "freebsd"))]
        let cancellation = context.cancellation.clone();
        let sandboxed = confinement.is_sandboxed();

        // Windows + AppContainer: the policy is Meka's own model of this call, encoded per
        // command, and the OS enforces it; no ACE is written and no token derived.
        #[cfg(windows)]
        if sandboxed
            && let crate::sandbox::SandboxCapability::AppContainer { minor, .. } =
                self.sandbox_capability
        {
            use crate::sandbox::appcontainer;
            let drive_roots = appcontainer::drive_roots();
            let private = crate::workspace::private_directories();
            let policy = appcontainer::policy_for(&appcontainer::PolicyInputs {
                version: (appcontainer::SCHEMA_MAJOR, minor),
                network: crate::sandbox::held_network(
                    &self.sandbox_capability,
                    confinement.network(),
                ),
                writable: confinement.writable(),
                readable: confinement.readable(),
                drive_roots: &drive_roots,
                private: &private,
                ui_restrictions: appcontainer::ui_restrictions_here(),
            });
            let relay = OutputRelay::for_call(&context);
            return run_windows_sandboxed(
                &command,
                &crate::sandbox::windows::WindowsConfinement::AppContainer(policy),
                self.site.cwd.get(),
                timeout,
                cancellation,
                relay,
            )
            .await;
        }

        // Windows + restricted token: spawn directly via CreateProcessAsUserW with a derived
        // token. This path can't go through tokio::process because the stdlib gives no hook for
        // injecting a custom token.
        #[cfg(windows)]
        if sandboxed
            && matches!(
                self.sandbox_capability,
                crate::sandbox::SandboxCapability::RestrictedToken
            )
        {
            // Two different mechanisms, picked by what the level promises. A workspace confinement
            // needs the ACEs in place *before* the token names them, so the grant happens here
            // rather than inside the spawn.
            let windows_confinement = match confinement.writable() {
                [] => crate::sandbox::windows::WindowsConfinement::LowIntegrity,
                roots => {
                    // Off the async executor. `ensure` calls `SetNamedSecurityInfoW`, which
                    // propagates the inheritable ACE over the *entire* existing tree -- seconds to
                    // minutes for a large workspace -- synchronously, while holding the ledger
                    // mutex. On a tokio worker that stalls streaming, every other `meka serve`
                    // session, and cancellation. `clippy::await_holding_lock` does not catch this
                    // shape: there is no `.await` inside the lock, just a long blocking syscall.
                    let grants = Arc::clone(&self.windows_grants);
                    let owned: Vec<std::path::PathBuf> = roots.to_vec();
                    let granted = tokio::task::spawn_blocking(move || {
                        for root in &owned {
                            if let Err(error) = grants.ensure(root) {
                                return Err((root.clone(), error));
                            }
                        }
                        Ok(())
                    })
                    .await
                    .map_err(|error| MekaError::ToolExecution {
                        tool_name: "shell_execute".to_string(),
                        message: format!("granting workspace write access panicked: {error}"),
                    })?;

                    if let Err((root, error)) = &granted {
                        return Err(MekaError::ToolExecution {
                            tool_name: "shell_execute".to_string(),
                            message: format!(
                                "failed to make '{}' writable for the sandboxed shell: {}; a \
                                 workspace root on Windows must be a directory Meka owns",
                                root.display(),
                                error
                            ),
                        });
                    }
                    crate::sandbox::windows::WindowsConfinement::WriteRestricted(roots.to_vec())
                }
            };
            let relay = OutputRelay::for_call(&context);
            return run_windows_sandboxed(
                &command,
                &windows_confinement,
                self.site.cwd.get(),
                timeout,
                cancellation,
                relay,
            )
            .await;
        }

        // Admitted as sandboxed on the probe, spawned on the capability: the two agree today, and
        // this is what keeps a disagreement from running the command unconfined.
        #[cfg(windows)]
        if sandboxed {
            return Err(unconfinable_command());
        }

        #[cfg(windows)]
        let mut command_builder = {
            // Wrap with the UTF-8 output prelude so pipe output matches what the sandboxed path
            // produces; both on Rust's side this is decoded as UTF-8. Without the wrap, PowerShell
            // 5.1 defaults to the legacy console code page and mangles non-ASCII characters into
            // `?`.
            let wrapped = crate::sandbox::wrap_command_with_utf8_output(&command);
            let mut cmd = tokio::process::Command::new("powershell.exe");
            cmd.arg("-NoProfile")
                .arg("-NonInteractive")
                .arg("-Command")
                .arg(&wrapped);
            cmd
        };

        // Every Unix platform runs `sh -c` unless a sandbox replaces the builder with the program
        // that imposes it, so the fallback is written once here and overwritten by the platform
        // blocks below. Windows builds its own, above.
        #[cfg(unix)]
        let mut command_builder = {
            let mut cmd = tokio::process::Command::new("sh");
            cmd.arg("-c").arg(&command);
            cmd
        };

        // FreeBSD: the confinement is a jail `jailbrokerd` builds, so there is nothing to spawn
        // here and the whole drain/cancel/assemble path is the daemon's shape of work rather than
        // this one's. See `run_jailbroker`.
        #[cfg(target_os = "freebsd")]
        if sandboxed {
            // Admitted as sandboxed on the probe, spawned on the capability: the two agree today,
            // and this is what keeps a disagreement from running the command unconfined. FreeBSD
            // has no other backend, so the jail is the only thing that can confine the command and
            // a capability that is anything else is a disagreement rather than a level to fall
            // back to.
            let crate::sandbox::SandboxCapability::Jailbroker { socket, .. } =
                &self.sandbox_capability
            else {
                return Err(unconfinable_command());
            };
            let relay = OutputRelay::for_call(&context);
            return run_jailbroker(
                socket,
                &command,
                &confinement,
                &self.site.cwd,
                timeout,
                cancellation,
                relay,
            )
            .await;
        }

        #[cfg(target_os = "macos")]
        if sandboxed
            && matches!(
                self.sandbox_capability,
                crate::sandbox::SandboxCapability::SandboxExec
            )
        {
            let (profile, params) = crate::sandbox::seatbelt::sandbox_profile_for(
                confinement.writable(),
                confinement.readable(),
                &crate::workspace::private_directories(),
                crate::sandbox::held_network(&self.sandbox_capability, confinement.network()),
            );
            let mut cmd = tokio::process::Command::new(crate::sandbox::seatbelt::SANDBOX_EXEC_PATH);
            cmd.arg("-p").arg(&profile);
            // `-D KEY=value` pairs, so a path never has to survive SBPL string quoting.
            cmd.args(&params);
            cmd.arg("sh").arg("-c").arg(&command);
            command_builder = cmd;
        } else if sandboxed {
            // Admitted as sandboxed on the probe, spawned on the capability: the two agree today,
            // and this is what keeps a disagreement from running the command unconfined.
            return Err(unconfinable_command());
        }

        // The executable that enacts the Landlock layer inside Bubblewrap, held open from here to
        // the spawn: the sandbox execs it through the descriptor, which the `pre_exec` below lets
        // through, and the verb closes it again before becoming the command.
        #[cfg(target_os = "linux")]
        let inner_executable: Option<std::fs::File> = match (sandboxed, &self.sandbox_capability) {
            (
                true,
                crate::sandbox::SandboxCapability::Bubblewrap {
                    landlock_abi: Some(_),
                    ..
                },
            ) => Some(inner_layer_executable()?),
            _ => None,
        };

        #[cfg(target_os = "linux")]
        if sandboxed
            && let crate::sandbox::SandboxCapability::Bubblewrap { bwrap_path, .. } =
                &self.sandbox_capability
        {
            // Bubblewrap path: `--ro-bind /` enforces "no writes", `--unshare-*` cuts off PID /
            // user / UTS / IPC views, tmpfs masks over `/run`, `/tmp`, `/var/tmp`, and
            // `$XDG_RUNTIME_DIR` make the dbus and systemd-user sockets unreachable so the agent
            // can't `dbus-send` state-changing methods. The network stays open unless the
            // session's setting is `none`, which unshares it. The Landlock layer inside closes
            // what the masks do not reach: a socket under `$HOME`, the abstract namespace, device
            // ioctls.
            let mut cmd = tokio::process::Command::new(bwrap_path);
            cmd.args(bwrap_args(
                confinement.writable(),
                confinement.readable(),
                &self.site.cwd.get(),
                &crate::workspace::private_directories(),
                crate::sandbox::held_network(&self.sandbox_capability, confinement.network()),
            ));
            cmd.arg("--");
            if let Some(executable) = &inner_executable {
                let program = format!(
                    "/proc/self/fd/{}",
                    std::os::fd::AsRawFd::as_raw_fd(executable)
                );
                cmd.args(inner_confinement_argv(
                    std::path::Path::new(&program),
                    confinement.writable(),
                    confinement.readable(),
                ));
            }
            cmd.arg("sh").arg("-c").arg(&command);
            command_builder = cmd;
        } else if sandboxed
            && !matches!(
                self.sandbox_capability,
                crate::sandbox::SandboxCapability::Landlock { .. }
            )
        {
            // Admitted as sandboxed on the probe, spawned on the capability: the two agree today,
            // and this is what keeps a disagreement from running the command unconfined.
            return Err(unconfinable_command());
        }

        // The Landlock dialect's ABI, when this command runs under it.
        #[cfg(target_os = "linux")]
        let landlock_abi: Option<i32> = match (sandboxed, &self.sandbox_capability) {
            (true, crate::sandbox::SandboxCapability::Landlock { abi_version }) => {
                Some(*abi_version)
            }
            _ => None,
        };

        // Unix: the child-side steps, run by the door after its own placement and the `setsid`
        // that gives the command a tree of its own. On Linux the Landlock setup runs here, and
        // only for the Landlock dialect: under Bubblewrap the ruleset is enacted inside the
        // sandbox by `meka confine`, after bwrap's mounts, because a domain that handles any
        // filesystem right refuses `mount(2)`.
        #[cfg(unix)]
        let in_child = {
            // Planned here, in the parent, because `pre_exec` runs after `fork` in a
            // single-threaded child where reading the filesystem and allocating are not
            // async-signal-safe.
            // No scratch paths: Landlock alone offers a command no temporary directory, because
            // the only one it could offer is a real directory under the real `/tmp`, and below
            // `unrestricted` Meka writes to nothing but its store. Bubblewrap's tmpfs is the
            // answer for a tool that needs one.
            #[cfg(target_os = "linux")]
            let grants: Vec<crate::sandbox::LandlockGrant> = match landlock_abi {
                Some(abi) => crate::sandbox::landlock_grants(
                    abi,
                    confinement.writable(),
                    confinement.readable(),
                    &[],
                    &crate::workspace::private_directories(),
                ),
                None => Vec::new(),
            };
            #[cfg(target_os = "linux")]
            let network =
                crate::sandbox::held_network(&self.sandbox_capability, confinement.network());

            move || {
                // The layer's executable rides into Bubblewrap on its descriptor, which stays
                // close-on-exec until here so no other child of Meka inherits it. `fcntl(2)`
                // is async-signal-safe.
                #[cfg(target_os = "linux")]
                if let Some(executable) = &inner_executable
                    && unsafe {
                        libc::fcntl(
                            std::os::fd::AsRawFd::as_raw_fd(executable),
                            libc::F_SETFD,
                            0,
                        )
                    } == -1
                {
                    return Err(std::io::Error::last_os_error());
                }
                #[cfg(target_os = "linux")]
                if let Some(abi) = landlock_abi {
                    // SAFETY: called between `fork` and `exec` with the grants planned above, which
                    // is the contract `apply_landlock` states.
                    unsafe { crate::sandbox::apply_landlock(abi, &grants, network) }
                        .map_err(std::io::Error::from_raw_os_error)?;
                }
                Ok(())
            }
        };

        // Scrub env before spawn so secrets in the parent process (`ANTHROPIC_API_KEY`, `AWS_*`,
        // `GITHUB_TOKEN`, …) cannot ride along into a confined child. Sandboxes block writes/IPC
        // but leave the network open, so leaked env is a live exfiltration vector under prompt
        // injection. Only `unrestricted` keeps the full parent environment, and an approved command
        // still runs in its level's sandbox with the scrubbed environment, as
        // `docs/book/src/tools/shell.md` states. The Windows sandboxed branch applies the same
        // scrub inside its own spawn.
        #[cfg(unix)]
        if sandboxed {
            command_builder.env_clear();
            command_builder.envs(crate::sandbox::sandbox_child_env());
        }

        // Resolve commands against the agent's per-session cwd, not the process cwd. `/cd` mutates
        // the agent's cwd; this is how it actually reaches the child.
        command_builder.current_dir(self.site.cwd.get());
        command_builder
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());

        // SAFETY: `in_child` makes only async-signal-safe calls over values planned in the parent
        // and allocates nothing.
        #[cfg(unix)]
        let spawned =
            unsafe { crate::process::spawn_tree_with_pre_exec(&mut command_builder, in_child) };
        #[cfg(windows)]
        let spawned = crate::process::spawn_tree(&mut command_builder);
        let child = spawned.map_err(|error| MekaError::ToolExecution {
            tool_name: "shell_execute".to_string(),
            message: format!("failed to spawn command: {error}"),
        })?;

        run_command_tree(child, timeout, &context)
            .await
            .map_err(|failure| match failure {
                CommandTreeError::Interrupted => MekaError::Interrupted,
                CommandTreeError::Wait(error) => wait_failed(error),
            })
    }
}

#[cfg(windows)]
pub(crate) struct SubshellOpenTool {
    pub(crate) handles: Arc<crate::subshell::Handles>,
    pub(crate) target: Arc<crate::subshell::Target>,
    pub(crate) permission: crate::permission::SharedPermission,
    pub(crate) required: Permission,
    pub(crate) site: crate::session::ToolSite,
}

#[cfg(windows)]
pub(crate) struct SubshellExecuteTool {
    pub(crate) handles: Arc<crate::subshell::Handles>,
    pub(crate) target: Arc<crate::subshell::Target>,
    pub(crate) permission: crate::permission::SharedPermission,
    pub(crate) required: Permission,
}

#[cfg(windows)]
pub(crate) struct SubshellExportTool {
    pub(crate) handles: Arc<crate::subshell::Handles>,
    pub(crate) target: Arc<crate::subshell::Target>,
    pub(crate) permission: crate::permission::SharedPermission,
    pub(crate) required: Permission,
    pub(crate) scope: crate::workspace::WriteScope,
    pub(crate) site: crate::session::ToolSite,
}

#[cfg(windows)]
pub(crate) struct SubshellCloseTool {
    pub(crate) handles: Arc<crate::subshell::Handles>,
    pub(crate) permission: crate::permission::SharedPermission,
    pub(crate) required: Permission,
}

#[cfg(windows)]
const SUBSHELL_OPEN: &str = "subshell_open";
#[cfg(windows)]
const SUBSHELL_EXECUTE: &str = "subshell_execute";
#[cfg(windows)]
const SUBSHELL_EXPORT: &str = "subshell_export";
#[cfg(windows)]
const SUBSHELL_CLOSE: &str = "subshell_close";

/// One word quoted for a POSIX shell, so the remote shell reads it as a single literal argument.
fn shell_quote(word: &str) -> String {
    format!("'{}'", word.replace('\'', r"'\''"))
}

/// The OpenSSH client this process runs: the one the platform installs, found by absolute path so
/// a `PATH` entry cannot substitute another program for it.
fn ssh_binary() -> Result<std::path::PathBuf> {
    #[cfg(windows)]
    let candidate = crate::sandbox::wsl_host::system_directory()
        .map_err(|error| {
            subshell_error("shell_execute", format!("cannot locate Windows: {error}"))
        })?
        .join("OpenSSH")
        .join("ssh.exe");
    #[cfg(not(windows))]
    let candidate = std::path::PathBuf::from("/usr/bin/ssh");
    if candidate.is_file() {
        Ok(candidate)
    } else {
        Err(subshell_error(
            "shell_execute",
            format!(
                "OpenSSH client not found at {}; install the OpenSSH client to use an SSH target",
                candidate.display()
            ),
        ))
    }
}

/// The minimal environment `ssh` runs with. The caller clears everything first: an ambient
/// `SSH_*`, `HOME` or config path could otherwise change what the pinned call does. What is kept
/// is what the client cannot start without: the system roots Windows loads from, and the machine
/// root OpenSSH resolves its program data under, without which the client exits 255 without a
/// word.
fn ssh_environment(process: &mut tokio::process::Command) {
    process.env_clear();
    #[cfg(windows)]
    for name in ["SystemRoot", "WINDIR", "ProgramData"] {
        if let Some(value) = std::env::var_os(name) {
            process.env(name, value);
        }
    }
    #[cfg(unix)]
    process.env("HOME", std::env::temp_dir());
    process.env("LANG", "C");
}

fn subshell_error(tool_name: &str, message: impl std::fmt::Display) -> MekaError {
    MekaError::ToolExecution {
        tool_name: tool_name.to_string(),
        message: message.to_string(),
    }
}

/// The permission refusal every subshell call meets before its arguments are read: the call needs
/// `required`, and `subshell_export` states `Permission::Workspace` there because a read-level
/// session cannot export to disk however the operator configured the family.
#[cfg(windows)]
fn admit_subshell(tool_name: &str, level: Permission, required: Permission) -> Result<()> {
    if required.is_within(level) {
        Ok(())
    } else {
        Err(subshell_error(
            tool_name,
            format!("managed WSL requires `{required}` permission; the session is at `{level}`"),
        ))
    }
}

/// The handle one call is addressed to, re-checked against the session that owns it.
#[cfg(windows)]
fn addressed_handle(
    handles: &crate::subshell::Handles,
    session: Option<uuid::Uuid>,
    input: &serde_json::Value,
    tool_name: &str,
) -> Result<Arc<crate::subshell::Handle>> {
    let name = require_str(input, "handle", tool_name)?;
    handles
        .get(session, &name)
        .map_err(|error| subshell_error(tool_name, error))
}

#[cfg(windows)]
#[async_trait]
impl Tool for SubshellOpenTool {
    fn definition(&self) -> ToolDefinition {
        ToolDefinition {
            name: SUBSHELL_OPEN.to_string(),
            description: format!(
                "Open a session-owned subshell handle over the granted WSL directories. {} \
                 The handle pins this scope for later `subshell_execute`, `subshell_export` and \
                 `subshell_close` calls; every call starts a fresh shell, so nothing carries \
                 between them. With `scratch` the handle runs in a private Linux-native workspace \
                 holding a snapshot of an admitted source instead of the live tree, at `workspace` \
                 permission only. At `read`, only private temporary storage is writable.",
                self.target.scope_description(),
            ),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "handle": {"type": "string", "description": "The name to open the handle under, unique within the session. Later subshell calls address the handle by this name."},
                    "working_directory": {"type": "string", "description": "An exact CLI grant's Linux or Windows path, mounted at /workspace. Required unless `scratch` is given."},
                    "scratch": {"type": "object", "description": "Open the handle over a private scratch workspace instead of a live directory: a snapshot of `source` (a Windows path beneath one of the session's workspace roots, or a granted WSL directory) is staged into a private /var/tmp/meka-scratch/<id> directory in the guest and deleted when the handle closes, so anything worth keeping must be exported first. Exporting back over the staged source refuses conflicts: a file changed, deleted or created there since the snapshot is never overwritten. Runs only at `workspace` permission or above.", "properties": {"source": {"type": "string", "description": "The directory to snapshot."}, "quota_mb": {"type": "integer", "description": "Snapshot quota in MiB, 1 to 8192. Default 1024."}}, "required": ["source"]},
                    "workspace": {"type": "array", "items": {"type": "string"}, "description": "Additional workspace grants, mounted at /workspaces/0, /workspaces/1, etc. Omit to mount none."},
                    "readable": {"type": "array", "items": {"type": "string"}, "description": "Additional grants to mount read-only at /references/0, /references/1, etc. Omit to mount none."},
                    "read_only": {"type": "boolean", "default": false, "description": "Make all mounts read-only even at workspace or unrestricted."}
                },
                "required": ["handle"]
            }),
            ..Default::default()
        }
    }

    fn required_permission(&self) -> Permission {
        Permission::Read
    }

    async fn refusal_at_level(
        &self,
        level: Permission,
        _: &serde_json::Value,
    ) -> Option<ToolOutput> {
        admit_subshell(SUBSHELL_OPEN, level, self.required)
            .err()
            .map(|error| ToolOutput::from_error(&error))
    }

    async fn execute(
        &self,
        input: serde_json::Value,
        context: crate::tools::ToolContext,
    ) -> Result<ToolOutput> {
        use super::util::{optional_bool, optional_object, optional_str, string_or_list};

        let lease = self.permission.lease();
        admit_subshell(SUBSHELL_OPEN, lease.level, self.required)?;
        let name = require_str(&input, "handle", SUBSHELL_OPEN)?;
        let working_directory = optional_str(&input, "working_directory", SUBSHELL_OPEN)?;
        let scratch_input = optional_object(&input, "scratch", SUBSHELL_OPEN)?;
        if working_directory.is_some() == scratch_input.is_some() {
            return Err(subshell_error(
                SUBSHELL_OPEN,
                "open exactly one of `working_directory` or `scratch`",
            ));
        }
        let workspace = string_or_list(&input, "workspace", SUBSHELL_OPEN)?.unwrap_or_default();
        let readable = string_or_list(&input, "readable", SUBSHELL_OPEN)?.unwrap_or_default();
        let read_only = optional_bool(&input, "read_only", SUBSHELL_OPEN)?.unwrap_or(false);
        if let Some(scratch) = scratch_input {
            if !workspace.is_empty() {
                return Err(subshell_error(
                    SUBSHELL_OPEN,
                    "scratch mode mounts only its own workspace; additional `workspace` grants \
                     cannot be combined with it",
                ));
            }
            let scratch = serde_json::Value::Object(scratch.clone());
            return self
                .open_scratch(context, &name, &scratch, &readable, read_only)
                .await;
        }
        let working_directory = working_directory.unwrap_or_default();
        // Re-checked here and again at every later use: authority is admitted when it is used,
        // never trusted from when the handle was opened.
        let writable = self
            .target
            .admit(working_directory, &workspace, &readable)
            .map_err(|error| subshell_error(SUBSHELL_OPEN, error))?;
        let access = if read_only || !writable {
            Permission::Read
        } else {
            lease.level.greatest_within_both(Permission::Workspace)
        };
        let handle = crate::subshell::Handle::new(
            Arc::clone(&self.target),
            context.session_id,
            working_directory.to_owned(),
            workspace,
            readable,
            read_only,
            lease.level,
        );
        let handle = self
            .handles
            .open(context.session_id, &name, handle)
            .map_err(|error| subshell_error(SUBSHELL_OPEN, error))?;
        Ok(ToolOutput::text(
            format!(
                "opened subshell handle {name:?}\n{}\naccess: {access}",
                handle.scope_description()
            ),
            false,
        ))
    }
}

#[cfg(windows)]
impl SubshellOpenTool {
    /// Open a handle over a scratch workspace: one typed transfer creates the private guest
    /// directory and installs the admitted snapshot in it. A guest source is walked by the runner
    /// itself; a Windows source is walked by the host under its native read fence and uploaded,
    /// and the runner refuses any file whose received bytes are not the digest announced for it.
    ///
    /// The order is the isolation argument. The runner creates the directory at the `0700` mode it
    /// enforces again on every launch, so no other guest user can read it; the snapshot lands
    /// second. A Windows source is read under the host's read fence before the request is sent,
    /// and a guest source was admitted by the target's grants. A failure at either step asks
    /// the runner to remove the workspace before the refusal comes back.
    async fn open_scratch(
        &self,
        context: crate::tools::ToolContext,
        name: &str,
        scratch: &serde_json::Value,
        readable: &[String],
        read_only: bool,
    ) -> Result<ToolOutput> {
        use super::util::optional_u64;

        let lease = self.permission.lease();
        if read_only {
            return Err(subshell_error(
                SUBSHELL_OPEN,
                "scratch mode is a writable workspace; `read_only` cannot apply to it",
            ));
        }
        if !Permission::Workspace.is_within(lease.level) {
            return Err(subshell_error(
                SUBSHELL_OPEN,
                format!(
                    "scratch mode needs `workspace` permission; the session is at {}",
                    lease.level
                ),
            ));
        }
        let source = require_str(scratch, "source", SUBSHELL_OPEN)?;
        let quota_bytes = match optional_u64(scratch, "quota_mb", SUBSHELL_OPEN)? {
            Some(mebibytes) => mebibytes.saturating_mul(crate::text::MIB as u64),
            None => crate::subshell::DEFAULT_SCRATCH_BYTES,
        };
        if !(1..=crate::subshell::MAX_SCRATCH_BYTES).contains(&quota_bytes) {
            return Err(subshell_error(
                SUBSHELL_OPEN,
                format!(
                    "the scratch quota must be between 1 and {} MiB",
                    crate::subshell::MAX_SCRATCH_BYTES / crate::text::MIB as u64
                ),
            ));
        }
        let unique = uuid::Uuid::new_v4().simple().to_string();
        let id = &unique[..crate::subshell::SCRATCH_ID_BYTES * 2];
        let guest_path = format!("{}/{id}", crate::subshell::SCRATCH_ROOT);
        let timeout_ms =
            u64::try_from(crate::subshell::TRANSFER_TIMEOUT.as_millis()).unwrap_or(u64::MAX);
        // The source is named by the spelling its kind uses: a guest path the runner opens and
        // walks itself, or a Windows path the host snapshots under its native read fence and
        // uploads, since a Windows-backed tree walked through DrvFS cannot bind every object the
        // walk would copy.
        enum StagePlan {
            /// The runner copies this guest source into the workspace itself.
            Guest(crate::subshell::MountRoot),
            /// The host sends the snapshot it read; the manifest and bytes follow the request.
            Upload(StageSnapshot),
        }
        let (plan, source_root, guest_source) = if source.starts_with('/') {
            if !crate::subshell::is_normalized_guest_path(&source)
                || source.contains('\\')
                || !self.target.admits_source(&source)
            {
                return Err(subshell_error(
                    SUBSHELL_OPEN,
                    format!(
                        "the source must be a normalized directory beneath a granted WSL \
                         directory, and may not spell a Windows separator: {source:?}"
                    ),
                ));
            }
            (
                StagePlan::Guest(crate::subshell::MountRoot::Guest(std::path::PathBuf::from(
                    &source,
                ))),
                std::path::PathBuf::from(&source),
                true,
            )
        } else {
            let spelled = crate::workspace::resolve_against_cwd(&self.site.cwd, &source);
            let resolved = crate::workspace::strip_verbatim(
                crate::workspace::resolve_existing_prefix(&spelled),
            );
            let roots = crate::workspace::writable_roots(&self.site.cwd, &self.site.roots);
            if !roots.iter().any(|root| resolved.starts_with(root)) {
                return Err(subshell_error(
                    SUBSHELL_OPEN,
                    format!(
                        "the source {source:?} must be a directory beneath one of the session's \
                         workspace roots"
                    ),
                ));
            }
            if !resolved.is_dir() {
                return Err(subshell_error(
                    SUBSHELL_OPEN,
                    format!("the source {source:?} is not a directory"),
                ));
            }
            verify_native_ancestors(&resolved).map_err(|refusal| {
                subshell_error(
                    SUBSHELL_OPEN,
                    format!("the source is not a real directory: {refusal}"),
                )
            })?;
            let fence = self.site.read_scope().fence(&self.site.cwd);
            if let Some(refusal) = fence.refusal(&resolved) {
                return Err(subshell_error(
                    SUBSHELL_OPEN,
                    format!("the source was not staged: {refusal}"),
                ));
            }
            let resolved_text = resolved.to_string_lossy().into_owned();
            if crate::subshell::windows_components(&resolved_text).is_none()
                || !self.target.admits_source(&resolved_text)
            {
                return Err(subshell_error(
                    SUBSHELL_OPEN,
                    format!(
                        "the source must be a normalized drive-absolute directory beneath a \
                         granted WSL directory; a guest directory is named by its Linux path: \
                         {source:?}"
                    ),
                ));
            }
            let snapshot = snapshot_stage_tree(&resolved, quota_bytes).map_err(|refusal| {
                subshell_error(
                    SUBSHELL_OPEN,
                    format!("the source was not staged: {refusal}"),
                )
            })?;
            (StagePlan::Upload(snapshot), resolved, false)
        };
        // One typed transfer creates the workspace and installs the snapshot in it: the runner
        // copies a guest source itself, and writes the host's fence-read bytes digest-checked for
        // a Windows one. The request's reference-mount proofs are held until the transfer is done.
        let selection = crate::subshell::Selection {
            working_directory: guest_path.clone(),
            workspace: Vec::new(),
            readable: readable.to_vec(),
            read_only: false,
            timeout_ms,
            command: String::new(),
            scratch: Some(crate::subshell::ScratchSelection {
                path: guest_path.clone(),
                quota_bytes,
                create: true,
            }),
            transfer: Some(match &plan {
                StagePlan::Guest(source) => crate::subshell::Transfer::Stage {
                    source: source.clone(),
                },
                StagePlan::Upload(_) => crate::subshell::Transfer::Upload,
            }),
        };
        let mut manifest = crate::subshell::ManifestOnly::default();
        let staged = async {
            let (request, _request_proofs) = self
                .target
                .request(selection, lease.level)
                .map_err(|error| format!("{error:#}"))?;
            let mut frame = request.encode().map_err(|error| format!("{error:#}"))?;
            if let StagePlan::Upload(snapshot) = &plan {
                let upload =
                    upload_stream(&request.op, snapshot).map_err(|error| format!("{error:#}"))?;
                frame.extend_from_slice(&upload);
            }
            drive_transfer(
                &self.target,
                &request.op,
                &frame,
                &lease,
                &context,
                &mut manifest,
            )
            .await
        }
        .await;
        // A manifest entry is the only evidence that the runner created and wrote this workspace.
        // A request that never got that far is left to the guest reaper: removing an id this open
        // cannot prove it owns is worse than a workspace that expires on its own.
        let staged_workspace = !manifest.entries.is_empty();
        let scratch_path = guest_path.clone();
        let discard = async {
            if staged_workspace {
                self.discard_scratch(&scratch_path, quota_bytes, readable, lease.level)
                    .await;
            }
        };
        let run = match staged {
            Ok(run) => run,
            Err(detail) => {
                discard.await;
                return Err(subshell_error(
                    SUBSHELL_OPEN,
                    format!(
                        "the source was not staged: {detail}{}",
                        if staged_workspace {
                            "; the partial workspace was removed"
                        } else {
                            "; any workspace the runner created is left to its reaper"
                        }
                    ),
                ));
            }
        };
        match run {
            TransferRun::Done => {}
            TransferRun::Lowered => {
                discard.await;
                return Err(subshell_error(
                    SUBSHELL_OPEN,
                    "permission was lowered; the scratch workspace was not staged",
                ));
            }
            TransferRun::Cancelled | TransferRun::Stopped => {
                discard.await;
                return Err(MekaError::Interrupted);
            }
        }
        let baseline = match stage_baseline(&manifest) {
            Ok(baseline) => baseline,
            Err(detail) => {
                discard.await;
                return Err(subshell_error(
                    SUBSHELL_OPEN,
                    format!("the source was not staged: {detail}"),
                ));
            }
        };
        let staged_files = baseline.len();
        let staged_bytes: u64 = baseline.values().map(|entry| entry.len).sum();
        let scratch_path = guest_path.clone();
        let handle = crate::subshell::Handle::new(
            Arc::clone(&self.target),
            context.session_id,
            guest_path.clone(),
            Vec::new(),
            readable.to_vec(),
            false,
            lease.level,
        )
        .with_scratch(crate::subshell::ScratchState {
            path: guest_path,
            source: source.to_owned(),
            source_root,
            quota_bytes,
            guest_source,
            baseline,
        });
        let handle = match self.handles.open(context.session_id, name, handle) {
            Ok(handle) => handle,
            Err(error) => {
                // The workspace was staged before the handle could claim it; a name already open
                // must not leave that copy behind for the guest reaper to find a day later.
                self.discard_scratch(&scratch_path, quota_bytes, readable, lease.level)
                    .await;
                return Err(subshell_error(SUBSHELL_OPEN, error));
            }
        };
        Ok(ToolOutput::text(
            format!(
                "opened subshell handle {name:?}\n{}\naccess: workspace\nstaged {staged_files} \
                 file(s), {staged_bytes} bytes from {source:?}",
                handle.scope_description()
            ),
            false,
        ))
    }

    /// Ask the runner to remove a scratch workspace this open created but will not keep. The
    /// caller reports its own refusal; a removal that fails is left to the runner's lease sweep,
    /// which reaps workspaces no live handle holds.
    async fn discard_scratch(
        &self,
        guest_path: &str,
        quota_bytes: u64,
        readable: &[String],
        level: Permission,
    ) {
        let timeout_ms =
            u64::try_from(crate::subshell::TRANSFER_TIMEOUT.as_millis()).unwrap_or(u64::MAX);
        let selection = crate::subshell::Selection {
            working_directory: guest_path.to_owned(),
            workspace: Vec::new(),
            readable: readable.to_vec(),
            read_only: false,
            timeout_ms,
            command: String::new(),
            scratch: Some(crate::subshell::ScratchSelection {
                path: guest_path.to_owned(),
                quota_bytes,
                create: false,
            }),
            transfer: Some(crate::subshell::Transfer::RemoveScratch),
        };
        let removal = async {
            let (request, _request_proofs) = self
                .target
                .request(selection, level)
                .map_err(|error| format!("{error:#}"))?;
            let frame = request.encode().map_err(|error| format!("{error:#}"))?;
            let timeout = crate::subshell::TRANSFER_TIMEOUT;
            let tree = tokio::time::timeout(
                timeout,
                crate::sandbox::wsl_host::launch(&self.target, &frame),
            )
            .await
            .map_err(|_| "timed out starting the removal".to_string())?
            .map_err(|error| format!("{error:#}"))?;
            let mut visitor = crate::subshell::ManifestOnly::default();
            crate::sandbox::wsl_host::collect_transfer(
                tree,
                &request.op,
                timeout,
                None,
                &mut visitor,
            )
            .await
            .map_err(|error| format!("{error:#}"))?;
            Ok::<(), String>(())
        }
        .await;
        if let Err(error) = removal {
            tracing::debug!(
                "the refused open left scratch workspace {guest_path} for the reaper: {error}"
            );
        }
    }
}

/// Read a stage response's manifest into the snapshot baseline: every file the runner copied,
/// keyed by its `/`-separated path below the source root. Directory entries describe the tree the
/// runner created and carry no file baseline; a stage names no root and numbers its only source
/// zero.
#[cfg(windows)]
fn stage_baseline(
    manifest: &crate::subshell::ManifestOnly,
) -> std::result::Result<std::collections::HashMap<String, crate::subshell::BaselineEntry>, String>
{
    let mut baseline = std::collections::HashMap::new();
    if !manifest.roots.is_empty() {
        return Err("the stage response names a source root".to_string());
    }
    for entry in &manifest.entries {
        if entry.directory {
            // The runner records the directories it created so a host can rebuild the tree, but a
            // snapshot baseline holds only the files a later export back over the source compares.
            continue;
        }
        if entry.root != 0 {
            return Err(format!(
                "the stage response names the unknown source {}",
                entry.root
            ));
        }
        let digest = entry.parsed_digest().ok_or_else(|| {
            format!(
                "the stage response holds an invalid digest for {:?}",
                entry.path
            )
        })?;
        let previous = baseline.insert(entry.path.clone(), crate::subshell::BaselineEntry {
            len: entry.len,
            modified: entry.modified(),
            digest,
        });
        if previous.is_some() {
            return Err(format!("the stage response names {:?} twice", entry.path));
        }
    }
    Ok(baseline)
}

/// The identity of one volume object: the volume serial and the 128-bit file id Windows reports
/// for it. Two names that resolve to one identity are one object; a name that resolves to another
/// is a swap, and nothing the export publishes writes through one.
#[cfg(windows)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FileIdentity {
    volume: u64,
    id: [u8; 16],
}

/// The identity behind one open handle.
#[cfg(windows)]
fn file_identity(handle: std::os::windows::io::RawHandle) -> std::io::Result<FileIdentity> {
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ID_INFO, FileIdInfo, GetFileInformationByHandleEx,
    };

    let mut info: FILE_ID_INFO = unsafe { std::mem::zeroed() };
    // SAFETY: the handle is open and the output buffer is a whole FILE_ID_INFO, the size passed.
    let reported = unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileIdInfo,
            std::ptr::from_mut(&mut info).cast(),
            std::mem::size_of::<FILE_ID_INFO>() as u32,
        )
    };
    if reported == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(FileIdentity {
        volume: info.VolumeSerialNumber,
        id: info.FileId.Identifier,
    })
}

/// How many names an open object has. A file another name can change is refused by the walks,
/// since a fence on one name cannot bind a write that arrives through the other.
#[cfg(windows)]
fn file_link_count(file: &std::fs::File) -> std::io::Result<u32> {
    use std::os::windows::io::AsRawHandle as _;

    use windows_sys::Win32::Storage::FileSystem::{
        FILE_STANDARD_INFO, FileStandardInfo, GetFileInformationByHandleEx,
    };

    let mut info: FILE_STANDARD_INFO = unsafe { std::mem::zeroed() };
    // SAFETY: the handle is open and the output buffer is one FILE_STANDARD_INFO, the size passed.
    let reported = unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            FileStandardInfo,
            std::ptr::from_mut(&mut info).cast(),
            std::mem::size_of::<FILE_STANDARD_INFO>() as u32,
        )
    };
    if reported == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(info.NumberOfLinks)
}

/// The Windows providers an export may publish through: a local fixed NTFS or ReFS volume, and
/// nothing else. Those are the providers where an identity is stable, a no-replace rename fails
/// on a name that exists, and a held open handle denies the deletion and rename of what it holds.
/// A DrvFS or network-backed name, a FAT volume and anything unrecognized cannot promise those,
/// so they are refused at the door rather than trusted to behave.
#[cfg(windows)]
fn publication_provider_allows(fs_name: &str, drive_type: u32) -> bool {
    /// `GetDriveTypeW`'s fixed local volume.
    const DRIVE_FIXED: u32 = 3;
    drive_type == DRIVE_FIXED && matches!(fs_name, "NTFS" | "ReFS")
}

/// Refuse a destination that is not on a supported publication provider.
#[cfg(windows)]
fn publication_provider(target: &std::path::Path) -> std::result::Result<(), String> {
    use std::{os::windows::ffi::OsStrExt as _, path::Component};

    use windows_sys::Win32::Storage::FileSystem::{GetDriveTypeW, GetVolumeInformationW};
    // The volume root is the prefix and root components, like `C:\`; the API classifies a root,
    // not a deep path, so the target's own depth plays no part in the judgement.
    let root: std::path::PathBuf = target
        .components()
        .take_while(|component| matches!(component, Component::Prefix(_) | Component::RootDir))
        .collect();
    if root.as_os_str().is_empty() {
        return Err(format!("{} has no volume root to judge", target.display()));
    }
    let mut wide: Vec<u16> = root.as_os_str().encode_wide().collect();
    if !root.to_string_lossy().ends_with(['\\', '/']) {
        wide.push(u16::from(b'\\'));
    }
    wide.push(0);
    let mut fs_name = [0u16; 64];
    let mut flags = 0u32;
    // SAFETY: the buffers are writable for the lengths passed and the root is NUL-terminated.
    let ok = unsafe {
        GetVolumeInformationW(
            wide.as_ptr(),
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            std::ptr::from_mut(&mut flags),
            std::ptr::null_mut(),
            fs_name.as_mut_ptr(),
            fs_name.len() as u32,
        )
    };
    let fs_name = if ok == 0 {
        "unknown".to_string()
    } else {
        let length = fs_name
            .iter()
            .position(|unit| *unit == 0)
            .unwrap_or(fs_name.len());
        String::from_utf16_lossy(fs_name.get(..length).unwrap_or_default())
    };
    // SAFETY: the root is NUL-terminated; the call only classifies it.
    let drive_type = unsafe { GetDriveTypeW(wide.as_ptr()) };
    if !publication_provider_allows(&fs_name, drive_type) {
        return Err(format!(
            "{} is not on a local fixed NTFS or ReFS volume ({}); the export's identity checks \
             and no-replace publication cannot be established there",
            target.display(),
            fs_name
        ));
    }
    Ok(())
}

/// A destination directory pinned by an open handle that denies its deletion and rename for as
/// long as it is held. Everything the commit does to the directory's names is relative to this
/// handle, so a path that changes under the export cannot redirect the publication.
#[cfg(windows)]
struct PinnedDirectory {
    handle: std::os::windows::io::OwnedHandle,
    path: std::path::PathBuf,
    /// The identity the directory had when it was pinned.
    identity: FileIdentity,
}

#[cfg(windows)]
impl PinnedDirectory {
    /// Pin the directory `path` names, refusing one that is not the object `expected` saw when
    /// that identity is given. The handle is opened without delete sharing, so nothing can delete
    /// or rename the pinned directory until the commit is done with it.
    fn pin(
        path: &std::path::Path,
        expected: Option<FileIdentity>,
    ) -> std::result::Result<Self, String> {
        use std::os::windows::{ffi::OsStrExt as _, io::AsRawHandle as _};

        use windows_sys::Win32::{
            Foundation::{GENERIC_READ, GENERIC_WRITE},
            Storage::FileSystem::{
                CreateFileW, DELETE, FILE_ADD_FILE, FILE_FLAG_BACKUP_SEMANTICS, FILE_SHARE_READ,
                FILE_SHARE_WRITE, OPEN_EXISTING,
            },
        };

        let wide = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect::<Vec<u16>>();
        // SAFETY: the name is NUL-terminated and the handle is closed by the OwnedHandle below.
        // The delete and add rights are what a handle-relative rename publishes through this
        // handle; without them the rename is refused at the API door.
        let raw = unsafe {
            CreateFileW(
                wide.as_ptr(),
                GENERIC_READ | GENERIC_WRITE | FILE_ADD_FILE | DELETE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS,
                std::ptr::null_mut(),
            )
        };
        if raw == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
            let error = std::io::Error::last_os_error();
            return Err(format!(
                "cannot pin the destination directory {}: {error}",
                path.display()
            ));
        }
        // SAFETY: the handle was just opened by this call and nothing else owns it.
        let handle = unsafe {
            use std::os::windows::io::FromRawHandle as _;

            std::os::windows::io::OwnedHandle::from_raw_handle(raw.cast())
        };
        let identity = file_identity(handle.as_raw_handle())
            .map_err(|error| format!("cannot identify {}: {error}", path.display()))?;
        if expected.is_some_and(|expected| expected != identity) {
            return Err(format!(
                "{} is no longer the directory the export admitted; it changed under the export",
                path.display()
            ));
        }
        Ok(Self {
            handle,
            path: path.to_path_buf(),
            identity,
        })
    }

    /// Refuse when the name the pin was taken on no longer resolves to the pinned directory. The
    /// publication runs against the handle either way; this is what says the tree around it did
    /// not change under the export. The check reads the name without the delete access a rename
    /// would need, so it never weakens the pin's own protection.
    fn still_pins_its_name(&self) -> std::result::Result<(), String> {
        use std::os::windows::{
            ffi::OsStrExt as _,
            io::{AsRawHandle as _, FromRawHandle as _},
        };

        use windows_sys::Win32::{
            Foundation::GENERIC_READ,
            Storage::FileSystem::{
                CreateFileW, FILE_FLAG_BACKUP_SEMANTICS, FILE_SHARE_DELETE, FILE_SHARE_READ,
                FILE_SHARE_WRITE, OPEN_EXISTING,
            },
        };

        let wide = self
            .path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect::<Vec<u16>>();
        // SAFETY: the name is NUL-terminated and the handle is closed by the OwnedHandle below.
        // The share includes delete only because the pin itself holds delete access; the pin
        // stays what denies everyone else.
        let raw = unsafe {
            CreateFileW(
                wide.as_ptr(),
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS,
                std::ptr::null_mut(),
            )
        };
        if raw == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
            return Err(format!(
                "{} cannot be read back to verify the pinned directory; the export refuses to \
                 publish under a name it cannot verify",
                self.path.display()
            ));
        }
        // SAFETY: the handle was just opened by this call and nothing else owns it.
        let handle = unsafe { std::os::windows::io::OwnedHandle::from_raw_handle(raw.cast()) };
        match file_identity(handle.as_raw_handle()) {
            Ok(identity) if identity == self.identity => Ok(()),
            Ok(_) => Err(format!(
                "{} is no longer the directory the export admitted; it changed under the export",
                self.path.display()
            )),
            Err(error) => Err(format!(
                "{} cannot be identified to verify the pinned directory: {error}",
                self.path.display()
            )),
        }
    }

    fn raw(&self) -> std::os::windows::io::RawHandle {
        use std::os::windows::io::AsRawHandle as _;

        self.handle.as_raw_handle()
    }
}

/// A temporary sibling the export owns until it is published or dropped. It is created
/// exclusively in the destination that will hold it, so it takes that directory's ACL; it is
/// bound by identity to the bytes the export wrote; and it is published by a no-replace rename
/// relative to the pinned parent directory, never by a path that could have been swapped. What
/// cleanup removes is the identity it holds, never a name that could meanwhile name something
/// else.
#[cfg(windows)]
struct ExportTemp {
    path: std::path::PathBuf,
    identity: FileIdentity,
    /// The digest of the bytes this temporary holds, checked again before it is published.
    digest: [u8; 32],
    written: u64,
    published: bool,
}

#[cfg(windows)]
impl ExportTemp {
    /// Create the empty temporary sibling a writer fills, in the parent directory of `target`.
    /// The caller keeps both halves: the guard removes the file unless it is published, and the
    /// writer is where the bytes go. The staged identity and digest bind the publication to these
    /// bytes.
    fn create_writer(
        target: &std::path::Path,
    ) -> std::result::Result<(Self, std::fs::File), String> {
        use std::os::windows::io::AsRawHandle as _;

        let parent = target
            .parent()
            .ok_or_else(|| format!("{} has no parent directory", target.display()))?;
        let path = parent.join(format!(".meka-export-{}", uuid::Uuid::new_v4().simple()));
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        let writer = options
            .open(&path)
            .map_err(|error| format!("cannot create {}: {error}", path.display()))?;
        let identity = file_identity(writer.as_raw_handle())
            .map_err(|error| format!("cannot identify {}: {error}", path.display()))?;
        Ok((
            Self {
                path,
                identity,
                digest: [0; 32],
                written: 0,
                published: false,
            },
            writer,
        ))
    }

    /// Record what the writer held, after its last byte: the length and digest the publication
    /// must still find when it opens the file again.
    fn sealed(&mut self, written: u64, digest: [u8; 32]) {
        self.written = written;
        self.digest = digest;
    }

    fn published(mut self) {
        self.published = true;
    }
}

#[cfg(windows)]
impl Drop for ExportTemp {
    fn drop(&mut self) {
        if self.published {
            return;
        }
        // The identity-bound cleanup: what is removed is the object the export created, checked
        // on the same handle the deletion runs through, never a name that meanwhile came to name
        // something else.
        remove_staged(&self.path, self.identity);
    }
}

/// Publish one sealed temporary into `target`, only when `target` does not exist.
///
/// The temporary is reopened by name and must still be the object the export wrote: the identity
/// it was created with, and the length and digest its writer sealed. The destination is the
/// pinned parent handle the rename is relative to, so a path swapped under the export cannot
/// redirect the publication. The rename is `FILE_RENAME_INFORMATION` through the kernel with that
/// root handle and no replace flag: an entry created in any gap is a failure, never something the
/// export replaces. There is no replacement path: the export contract is a fresh name, and
/// "replace the file that was here" is refused when the plan is made rather than attempted here.
#[cfg(windows)]
fn publish_export_temp(
    temporary: ExportTemp,
    target: &std::path::Path,
    parent: PinnedDirectory,
) -> std::result::Result<u64, String> {
    use std::os::windows::io::AsRawHandle as _;

    let name = target
        .file_name()
        .ok_or_else(|| format!("{} has no file name to publish it under", target.display()))?;
    let staged = open_staged(&temporary.path)
        .map_err(|error| format!("cannot reopen {}: {error}", temporary.path.display()))?;
    if file_identity(staged.as_raw_handle())
        .map_err(|error| format!("cannot identify {}: {error}", temporary.path.display()))?
        != temporary.identity
    {
        return Err(format!(
            "{} is no longer the file the export wrote; nothing is published through a name that \
             changed",
            temporary.path.display()
        ));
    }
    let (len, digest) = digest_staged(&staged)
        .map_err(|error| format!("cannot read {}: {error}", temporary.path.display()))?;
    if len != temporary.written || digest != temporary.digest {
        return Err(format!(
            "{} no longer holds the bytes the export wrote to it; nothing is published from it",
            temporary.path.display()
        ));
    }
    parent.still_pins_its_name()?;
    rename_relative_no_replace(staged.as_raw_handle(), parent.raw(), name).map_err(|error| {
        if error.kind() == std::io::ErrorKind::AlreadyExists {
            format!(
                "{} appeared at the destination while the export was staging it; nothing was \
                 replaced",
                target.display()
            )
        } else {
            format!(
                "cannot create {}: {error}; nothing was replaced",
                target.display()
            )
        }
    })?;
    drop(parent);
    let written = temporary.written;
    temporary.published();
    Ok(written)
}

/// Reopen a staged temporary for the commit: the handle the identity is checked on and the rename
/// runs through, opened without write or delete sharing so nothing changes the file between the
/// check and the publish.
#[cfg(windows)]
fn open_staged(path: &std::path::Path) -> std::io::Result<std::os::windows::io::OwnedHandle> {
    use std::os::windows::{ffi::OsStrExt as _, io::FromRawHandle as _};

    use windows_sys::Win32::{
        Foundation::{GENERIC_READ, INVALID_HANDLE_VALUE},
        Storage::FileSystem::{
            CreateFileW, DELETE, FILE_SHARE_READ, FILE_WRITE_ATTRIBUTES, OPEN_EXISTING,
        },
    };

    let wide = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<u16>>();
    // SAFETY: the name is NUL-terminated; a successful call returns an unowned handle this
    // function takes at once.
    let raw = unsafe {
        CreateFileW(
            wide.as_ptr(),
            GENERIC_READ | DELETE | FILE_WRITE_ATTRIBUTES,
            FILE_SHARE_READ,
            std::ptr::null(),
            OPEN_EXISTING,
            0,
            std::ptr::null_mut(),
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: the handle was just opened by this call and nothing else owns it.
    Ok(unsafe { std::os::windows::io::OwnedHandle::from_raw_handle(raw.cast()) })
}

/// The length and SHA-256 of one staged file, read whole from its open handle.
#[cfg(windows)]
fn digest_staged(staged: &std::os::windows::io::OwnedHandle) -> std::io::Result<(u64, [u8; 32])> {
    use std::io::Read as _;

    use sha2::Digest as _;

    let mut file = std::fs::File::from(staged.try_clone()?);
    let mut hasher = sha2::Sha256::new();
    let mut buffer = [0u8; 64 * crate::text::KIB];
    let mut len = 0u64;
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(buffer.get(..read).unwrap_or_default());
        len = len.saturating_add(read as u64);
    }
    Ok((len, hasher.finalize().into()))
}

/// Rename the open file to `name` beneath the pinned `parent`, only when that name does not
/// exist. `NtSetInformationFile` with `FILE_RENAME_INFORMATION` is the interface that takes a
/// root directory handle: the rename is relative to the pinned directory and cannot be redirected
/// by a path that changed under the export. `ReplaceIfExists` stays false, so a name that exists
/// fails the call rather than being taken. The commit is where this was checked on real NTFS:
/// `SetFileInformationByHandle` refuses the root-handle form outright (`ERROR_INVALID_PARAMETER`
/// for both `FileRenameInfo` and `FileRenameInfoEx`), so the commit speaks the kernel interface
/// that carries the root, and there is no pathname rename to fall back to.
#[cfg(windows)]
fn rename_relative_no_replace(
    file: std::os::windows::io::RawHandle,
    parent: std::os::windows::io::RawHandle,
    name: &std::ffi::OsStr,
) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt as _;

    /// The kernel's `FILE_RENAME_INFORMATION` class number.
    const FILE_RENAME_INFORMATION: u32 = 10;
    /// `STATUS_OBJECT_NAME_COLLISION`: the name is taken and nothing replaces it.
    const NAME_COLLISION: i32 = 0xC000_0035u32 as i32;

    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn NtSetInformationFile(
            file: *mut core::ffi::c_void,
            status: *mut [u8; 16],
            info: *const core::ffi::c_void,
            length: u32,
            class: u32,
        ) -> i32;
    }

    let units = name.encode_wide().collect::<Vec<u16>>();
    let name_bytes = u32::try_from(units.len() * 2).unwrap_or(u32::MAX);
    // FILE_RENAME_INFORMATION: the flags union (zero: never replace), the root handle, the
    // name's byte length, then the name itself. The name is not NUL-terminated; its length
    // travels with it.
    let mut buffer = Vec::with_capacity(24 + name_bytes as usize);
    buffer.extend_from_slice(&0u32.to_ne_bytes());
    buffer.extend_from_slice(&[0u8; 4]);
    buffer.extend_from_slice(&(parent as usize as u64).to_ne_bytes());
    buffer.extend_from_slice(&name_bytes.to_ne_bytes());
    for unit in name.encode_wide() {
        buffer.extend_from_slice(&unit.to_ne_bytes());
    }
    let mut status = [0u8; 16];
    // SAFETY: the buffer is one FILE_RENAME_INFORMATION carrying its name, sized and filled
    // above; both handles are open and the status block is writable.
    let code = unsafe {
        NtSetInformationFile(
            file.cast(),
            &mut status,
            buffer.as_ptr().cast(),
            buffer.len() as u32,
            FILE_RENAME_INFORMATION,
        )
    };
    match code {
        0 => Ok(()),
        NAME_COLLISION => Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "the export name is already taken",
        )),
        other => Err(std::io::Error::other(format!(
            "the handle-relative rename was refused (NTSTATUS {other:#x})"
        ))),
    }
}

/// What can stop a publication at the shared commit gate.
#[cfg(windows)]
#[derive(Debug)]
enum CommitStop {
    Closed,
    Canceled,
    LeaseLowered,
}

/// The one commit gate every publication passes: a close, a cancellation, or a permission that
/// was lowered after the call was admitted stops the commit, whatever the live level reads now.
/// A stop that wins here leaves what already committed in place; the gate is not a rollback.
#[cfg(windows)]
fn commit_gate(
    closed: &tokio_util::sync::CancellationToken,
    cancellation: &tokio_util::sync::CancellationToken,
    lease: &crate::permission::PermissionLease,
) -> std::result::Result<(), CommitStop> {
    if closed.is_cancelled() {
        return Err(CommitStop::Closed);
    }
    if cancellation.is_cancelled() {
        return Err(CommitStop::Canceled);
    }
    if lease.is_revoked() {
        return Err(CommitStop::LeaseLowered);
    }
    Ok(())
}

#[cfg(windows)]
impl CommitStop {
    /// The honest partial report: what stopped the export and what was published before it,
    /// which remains on disk.
    fn report(&self, committed: usize) -> String {
        match self {
            Self::Closed => format!(
                "the handle was closed during the export; {committed} file(s) were published \
                 before the close and remain"
            ),
            Self::Canceled => format!(
                "the export was cancelled; {committed} file(s) were published before the stop \
                 and remain"
            ),
            Self::LeaseLowered => format!(
                "permission was lowered during the export; {committed} file(s) were published \
                 before the lease ended and remain"
            ),
        }
    }
}

/// Stage one native exported file into a temporary sibling of its destination. The source is
/// read to exactly the length it announced and refused if it changes while it is copied: what the
/// export later publishes is what the plan admitted, or nothing. The publication itself is a
/// separate step, so the gate can run again between the copy and the rename.
#[cfg(windows)]
fn stage_export_file(
    source: &std::path::Path,
    target: &std::path::Path,
) -> std::result::Result<ExportTemp, String> {
    use std::{io::Read as _, os::windows::io::AsRawHandle as _};

    use sha2::Digest as _;

    let (temporary, mut writer) = ExportTemp::create_writer(target)?;
    let sealed = (|| {
        let mut reader = std::fs::File::open(source)
            .map_err(|error| format!("cannot read {}: {error}", source.display()))?;
        let before = reader
            .metadata()
            .map_err(|error| format!("cannot read {}: {error}", source.display()))?;
        let before_identity = file_identity(reader.as_raw_handle())
            .map_err(|error| format!("cannot identify {}: {error}", source.display()))?;
        let expected = before.len();
        let mut hasher = sha2::Sha256::new();
        let mut buffer = [0u8; 64 * crate::text::KIB];
        let mut copied = 0u64;
        while copied < expected {
            let room = usize::try_from(expected - copied).unwrap_or(buffer.len());
            let take = room.min(buffer.len());
            let read = reader
                .read(buffer.get_mut(..take).unwrap_or_default())
                .map_err(|error| format!("cannot read {}: {error}", source.display()))?;
            if read == 0 {
                break;
            }
            hasher.update(buffer.get(..read).unwrap_or_default());
            std::io::Write::write_all(&mut writer, buffer.get(..read).unwrap_or_default())
                .map_err(|error| format!("cannot write {}: {error}", target.display()))?;
            copied = copied.saturating_add(read as u64);
        }
        let mut extra = [0u8];
        let grew = reader
            .read(&mut extra)
            .map_err(|error| format!("cannot read {}: {error}", source.display()))?;
        let after = reader
            .metadata()
            .map_err(|error| format!("cannot read {}: {error}", source.display()))?;
        let after_identity = file_identity(reader.as_raw_handle())
            .map_err(|error| format!("cannot identify {}: {error}", source.display()))?;
        if copied != expected
            || grew != 0
            || after.len() != before.len()
            || after_identity != before_identity
        {
            return Err(format!(
                "{} changed while it was copied; nothing is published from it",
                source.display()
            ));
        }
        Ok((copied, hasher.finalize().into()))
    })();
    let (copied, digest) = sealed?;
    drop(writer);
    let mut temporary = temporary;
    temporary.sealed(copied, digest);
    Ok(temporary)
}

/// The digest an entry with no bytes carries: the hash of nothing.
#[cfg(windows)]
fn empty_digest() -> [u8; 32] {
    use sha2::Digest as _;

    sha2::Sha256::new().finalize().into()
}

/// The snapshot of one Windows-backed stage source: every entry as the fence read it, and the
/// announced bytes, read once through the handles that bound them. The manifest travels before
/// the bytes and the runner re-checks every digest as it writes, so what lands in the guest-owned
/// workspace is exactly what this walk read.
#[cfg(windows)]
struct StageSnapshot {
    entries: Vec<crate::subshell::TransferEntry>,
    payload: Vec<u8>,
}

/// Walk one Windows-backed stage source under the native read fence and return its snapshot: the
/// same refusal set the runner's own walk applies (a reparse point, a hard link, a name outside
/// the transfer grammar), with every file read to exactly the length it announced and refused if
/// it changed while it was read. The announced bytes are bounded by the workspace quota before
/// any of them are held, so an upload can never carry more than the workspace may hold.
#[cfg(windows)]
fn snapshot_stage_tree(
    root: &std::path::Path,
    quota_bytes: u64,
) -> std::result::Result<StageSnapshot, String> {
    verify_native_ancestors(root)?;
    check_real_directory(root)?;
    let mut snapshot = StageSnapshot {
        entries: Vec::new(),
        payload: Vec::new(),
    };
    snapshot_directory(root, &mut Vec::new(), quota_bytes, &mut snapshot)?;
    Ok(snapshot)
}

/// The walk itself: one directory's names in a stable order, each entry judged on the metadata of
/// the object its name resolved to, never on the name alone.
#[cfg(windows)]
fn snapshot_directory(
    directory: &std::path::Path,
    relative: &mut Vec<String>,
    quota_bytes: u64,
    snapshot: &mut StageSnapshot,
) -> std::result::Result<(), String> {
    use std::os::windows::fs::MetadataExt as _;

    let mut names: Vec<std::ffi::OsString> = std::fs::read_dir(directory)
        .map_err(|error| format!("cannot read {}: {error}", directory.display()))?
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<std::result::Result<_, _>>()
        .map_err(|error| format!("cannot read {}: {error}", directory.display()))?;
    names.sort();
    for name in names {
        let Some(text) = name.to_str() else {
            return Err(format!(
                "{} is not Unicode; nothing is staged from a name the wire cannot carry",
                name.to_string_lossy()
            ));
        };
        // A name in the proof artifact namespace is internal bookkeeping, never transfer data.
        if crate::subshell::is_proof_name(text) {
            continue;
        }
        if !crate::subshell::is_transfer_component(text) {
            return Err(format!("invalid source name: {text:?}"));
        }
        relative.push(text.to_owned());
        let path = relative.join("/");
        if !crate::subshell::is_transfer_entry_path(&path) {
            return Err(format!("a source path is too long or too deep: {path:?}"));
        }
        let child = directory.join(&name);
        let metadata = std::fs::symlink_metadata(&child)
            .map_err(|error| format!("cannot inspect {}: {error}", child.display()))?;
        if metadata.file_attributes() & 0x400 != 0 {
            return Err(format!(
                "{} is a symlink or reparse point; nothing is read through one",
                child.display()
            ));
        }
        if snapshot.entries.len() >= crate::subshell::MAX_TRANSFER_ENTRIES {
            return Err(format!(
                "the source has more than {} entries",
                crate::subshell::MAX_TRANSFER_ENTRIES
            ));
        }
        let modified = metadata.modified().map_err(|error| {
            format!(
                "cannot read {}'s modification time: {error}",
                child.display()
            )
        })?;
        let (modified_secs, modified_nanos) = crate::subshell::system_time_parts(modified);
        if metadata.is_dir() {
            check_real_directory(&child)?;
            snapshot.entries.push(crate::subshell::TransferEntry {
                root: 0,
                path,
                len: 0,
                modified_secs,
                modified_nanos,
                digest: crate::subshell::digest_hex(&empty_digest()),
                directory: true,
            });
            snapshot_directory(&child, relative, quota_bytes, snapshot)?;
        } else if metadata.is_file() {
            let len = metadata.len();
            // A declared length past any one budget is refused before the copy allocates or
            // writes for it.
            if len > crate::subshell::MAX_TRANSFER_FILE_BYTES {
                return Err(format!("{path} is larger than one transferred file may be"));
            }
            let held = snapshot.payload.len() as u64;
            if held.saturating_add(len) > quota_bytes
                || held.saturating_add(len) > crate::subshell::MAX_TRANSFER_BYTES
            {
                return Err(format!(
                    "the source is larger than the {quota_bytes} byte scratch quota"
                ));
            }
            let (bytes, digest) = read_snapshot_file(&child, &path, len)?;
            snapshot.payload.extend_from_slice(&bytes);
            snapshot.entries.push(crate::subshell::TransferEntry {
                root: 0,
                path,
                len,
                modified_secs,
                modified_nanos,
                digest: crate::subshell::digest_hex(&digest),
                directory: false,
            });
        } else {
            return Err(format!(
                "{} is not a regular file or a real directory; nothing else is staged",
                child.display()
            ));
        }
        relative.pop();
    }
    Ok(())
}

/// Read one file for a stage snapshot under the fence `stage_export_file` publishes under: the
/// object is identified at the handle it is read from, exactly the announced length is read and
/// hashed, and a file that grew or was replaced while it was read refuses the snapshot instead of
/// carrying a mixture of moments into the workspace.
#[cfg(windows)]
fn read_snapshot_file(
    path: &std::path::Path,
    entry_path: &str,
    expected_len: u64,
) -> std::result::Result<(Vec<u8>, [u8; 32]), String> {
    use std::{io::Read as _, os::windows::io::AsRawHandle as _};

    use sha2::Digest as _;

    let mut reader = std::fs::File::open(path)
        .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    let before = reader
        .metadata()
        .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    let before_identity = file_identity(reader.as_raw_handle())
        .map_err(|error| format!("cannot identify {}: {error}", path.display()))?;
    if file_link_count(&reader)
        .map_err(|error| format!("cannot identify {}: {error}", path.display()))?
        != 1
    {
        return Err(format!(
            "{entry_path} has another name; a stage refuses a file another name can change"
        ));
    }
    let capacity = usize::try_from(expected_len).unwrap_or(usize::MAX);
    let mut bytes = Vec::with_capacity(capacity.min(64 * crate::text::KIB));
    let mut hasher = sha2::Sha256::new();
    let mut buffer = [0u8; 64 * crate::text::KIB];
    let mut copied = 0u64;
    while copied < expected_len {
        let room = usize::try_from(expected_len - copied).unwrap_or(buffer.len());
        let take = room.min(buffer.len());
        let read = reader
            .read(buffer.get_mut(..take).unwrap_or_default())
            .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
        if read == 0 {
            break;
        }
        let chunk = buffer.get(..read).unwrap_or_default();
        hasher.update(chunk);
        bytes.extend_from_slice(chunk);
        copied = copied.saturating_add(read as u64);
    }
    let mut extra = [0u8];
    let grew = reader
        .read(&mut extra)
        .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    let after = reader
        .metadata()
        .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    let after_identity = file_identity(reader.as_raw_handle())
        .map_err(|error| format!("cannot identify {}: {error}", path.display()))?;
    let after_links = file_link_count(&reader)
        .map_err(|error| format!("cannot identify {}: {error}", path.display()))?;
    if copied != expected_len
        || grew != 0
        || after.len() != before.len()
        || after_identity != before_identity
        || after_links != 1
    {
        return Err(format!(
            "{entry_path} changed while it was staged; nothing is staged from it"
        ));
    }
    Ok((bytes, hasher.finalize().into()))
}

/// The bytes an upload follows its request with: one manifest line carrying the snapshot's
/// entries in the frame shape a transfer answers with, then every file's announced bytes in
/// manifest order.
#[cfg(windows)]
fn upload_stream(op: &str, snapshot: &StageSnapshot) -> anyhow::Result<Vec<u8>> {
    let mut stream = crate::subshell::Frame::Manifest {
        op: op.to_owned(),
        roots: Vec::new(),
        entries: snapshot.entries.clone(),
    }
    .encode()?;
    stream.extend_from_slice(&snapshot.payload);
    Ok(stream)
}

/// Remove one staged temporary through the handle that names it, so what is removed is the
/// object the export created and never a name that meanwhile came to name something else.
#[cfg(windows)]
fn remove_staged(path: &std::path::Path, expected: FileIdentity) {
    use std::os::windows::io::AsRawHandle as _;

    use windows_sys::Win32::Storage::FileSystem::{
        FILE_DISPOSITION_INFO, FileDispositionInfo, SetFileInformationByHandle,
    };

    let Ok(staged) = open_staged(path) else {
        return;
    };
    let identity = match file_identity(staged.as_raw_handle()) {
        Ok(identity) => identity,
        Err(error) => {
            tracing::warn!(
                "cannot identify the staged file {}: {error}",
                path.display()
            );
            return;
        }
    };
    if identity != expected {
        tracing::warn!(
            "the staged file {} now names another object; the export leaves it alone",
            path.display()
        );
        return;
    }
    let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
    // SAFETY: the handle is open on the verified file and the buffer is one disposition record.
    let deleted = unsafe {
        SetFileInformationByHandle(
            staged.as_raw_handle(),
            FileDispositionInfo,
            std::ptr::from_ref(&disposition).cast(),
            std::mem::size_of::<FILE_DISPOSITION_INFO>() as u32,
        )
    };
    if deleted == 0 {
        tracing::warn!(
            "cannot remove the staged file {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        );
    }
}

/// Create every directory between the admitted `root` and `target`, one component at a time,
/// refusing an existing entry that is not a real directory. Creating a level by name cannot pass
/// through a link, and the metadata check on an existing level refuses one planted there.
#[cfg(windows)]
fn create_verified_directories(
    root: &std::path::Path,
    target: &std::path::Path,
) -> std::result::Result<(), String> {
    use std::path::Component;

    let relative = target.strip_prefix(root).map_err(|_| {
        format!(
            "{} is outside the export destination {}",
            target.display(),
            root.display()
        )
    })?;
    let mut current = root.to_path_buf();
    check_real_directory(&current)?;
    for component in relative.components() {
        if !matches!(component, Component::Normal(_)) {
            return Err(format!("invalid export path: {}", target.display()));
        }
        current.push(component);
        match std::fs::symlink_metadata(&current) {
            Ok(_) => check_real_directory(&current)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                std::fs::create_dir(&current)
                    .map_err(|error| format!("cannot create {}: {error}", current.display()))?;
                check_real_directory(&current)?;
            }
            Err(error) => return Err(format!("cannot read {}: {error}", current.display())),
        }
    }
    Ok(())
}

/// Refuse a path that is not a real directory: a reparse point is never followed.
#[cfg(windows)]
fn check_real_directory(path: &std::path::Path) -> std::result::Result<(), String> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    if metadata.file_attributes() & 0x400 != 0 {
        return Err(format!(
            "{} is a symlink or reparse point; nothing is read through one",
            path.display()
        ));
    }
    if !metadata.is_dir() {
        return Err(format!("{} is not a directory", path.display()));
    }
    Ok(())
}

/// Check the ancestors of a native path, so a junction above the final object cannot lead a walk
/// outside the grant.
#[cfg(windows)]
fn verify_native_ancestors(path: &std::path::Path) -> std::result::Result<(), String> {
    let mut ancestors: Vec<&std::path::Path> = path.ancestors().skip(1).collect();
    ancestors.reverse();
    for ancestor in ancestors {
        check_real_directory(ancestor)?;
    }
    Ok(())
}

/// One export source spelling resolved to a scratch handle's workspace when it names one: the
/// workspace the snapshot landed in is what the model was told to work in, so `/workspace` and the
/// staged path are the same directory to it.
#[cfg(windows)]
fn scratch_workspace_alias<'path>(
    handle: &crate::subshell::Handle,
    path: &'path str,
) -> std::borrow::Cow<'path, str> {
    let Some(scratch) = handle.scratch() else {
        return std::borrow::Cow::Borrowed(path);
    };
    if path == "/workspace" {
        return std::borrow::Cow::Owned(scratch.path.clone());
    }
    if let Some(rest) = path.strip_prefix("/workspace/") {
        return std::borrow::Cow::Owned(format!("{}/{}", scratch.path, rest));
    }
    std::borrow::Cow::Borrowed(path)
}

/// The export targets within the staged source region that no longer match the snapshot: what
/// exporting back would silently lose.
///
/// The baseline is the only witness: a file that changed since the copy, one deleted since, and
/// one that appeared where the snapshot had none each refuse the plan. They would be lost to
/// whoever changed them, and no flag buys that back.
#[cfg(windows)]
fn scratch_conflicts(
    scratch: &crate::subshell::ScratchState,
    files: &[(PlannedSource, std::path::PathBuf)],
) -> Vec<String> {
    let mut conflicts = Vec::new();
    for (_source, target) in files {
        let Ok(relative) = target.strip_prefix(&scratch.source_root) else {
            continue;
        };
        let display = target.display().to_string();
        let Some(key) = relative.to_str() else {
            conflicts.push(format!(
                "{display}: the path cannot be compared with the snapshot because it is not Unicode"
            ));
            continue;
        };
        let key = key.replace('\\', "/");
        let baseline = scratch.baseline.get(&key).or_else(|| {
            // A Windows source is case-insensitive, so the baseline is matched the way the
            // filesystem would. A guest source is not: two names that differ only in case are two
            // files there, and the exact key is the only one that names the staged one.
            (!scratch.guest_source)
                .then(|| {
                    scratch
                        .baseline
                        .iter()
                        .find(|(staged, _)| staged.eq_ignore_ascii_case(&key))
                        .map(|(_, entry)| entry)
                })
                .flatten()
        });
        let current = match std::fs::symlink_metadata(target) {
            Ok(current) => Some(current),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => {
                conflicts.push(format!("{display}: cannot be read: {error}"));
                continue;
            }
        };
        match (baseline, current) {
            (Some(baseline), Some(current)) => {
                let changed = current.len() != baseline.len
                    || current
                        .modified()
                        .map(|stamp| stamp != baseline.modified)
                        .unwrap_or(true)
                    || file_digest(target)
                        .map(|digest| digest != baseline.digest)
                        .unwrap_or(true);
                if changed {
                    conflicts.push(format!("{display}: changed after it was staged"));
                }
            }
            (Some(_), None) => {
                conflicts.push(format!("{display}: deleted after it was staged"));
            }
            (None, Some(_)) => conflicts.push(format!("{display}: appeared after staging")),
            (None, None) => {}
        }
    }
    conflicts
}

/// The SHA-256 of one file, streamed; `None` when it cannot be read.
#[cfg(windows)]
fn file_digest(path: &std::path::Path) -> Option<[u8; 32]> {
    use std::io::Read as _;

    use sha2::Digest as _;

    let mut file = std::fs::File::open(path).ok()?;
    let mut hasher = sha2::Sha256::new();
    let mut buffer = [0u8; 64 * crate::text::KIB];
    loop {
        let read = file.read(&mut buffer).ok()?;
        if read == 0 {
            return Some(hasher.finalize().into());
        }
        hasher.update(buffer.get(..read).unwrap_or_default());
    }
}

#[cfg(windows)]
#[async_trait]
impl Tool for SubshellExecuteTool {
    fn definition(&self) -> ToolDefinition {
        ToolDefinition {
            name: SUBSHELL_EXECUTE.to_string(),
            description: format!(
                "Run one POSIX shell command in a confined WSL workspace under a handle opened by \
                 `subshell_open`. {} Every call starts a fresh shell with the handle's mounts, so \
                 `cd`, environment changes and background processes do not carry between calls. \
                 No network or Windows drives. Output is capped at {}.",
                self.target.scope_description(),
                crate::text::format_size(MAX_OUTPUT_BYTES),
            ),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "handle": {"type": "string", "description": "The handle name opened by `subshell_open`."},
                    "command": {"type": "string", "description": "POSIX shell command to run."},
                    "timeout_ms": {"type": "integer", "default": DEFAULT_TIMEOUT.as_millis(), "maximum": crate::subshell::MAX_TIMEOUT.as_millis(), "description": "Command timeout in milliseconds."},
                    "scratchpad": {"type": "string", "description": "Save command output under this scratchpad entry name."}
                },
                "required": ["handle", "command"]
            }),
            ..Default::default()
        }
    }

    fn required_permission(&self) -> Permission {
        Permission::Read
    }

    async fn refusal_at_level(
        &self,
        level: Permission,
        _: &serde_json::Value,
    ) -> Option<ToolOutput> {
        admit_subshell(SUBSHELL_EXECUTE, level, self.required)
            .err()
            .map(|error| ToolOutput::from_error(&error))
    }

    fn reports_failure_as_output(&self) -> bool {
        true
    }

    fn as_detachable(&self) -> Option<&dyn crate::tools::Detachable> {
        Some(self)
    }

    async fn execute(
        &self,
        input: serde_json::Value,
        context: crate::tools::ToolContext,
    ) -> Result<ToolOutput> {
        crate::tools::start_and_run(self, input, context).await
    }
}

#[cfg(windows)]
#[async_trait]
impl crate::tools::Detachable for SubshellExecuteTool {
    async fn start(
        &self,
        input: serde_json::Value,
        context: &crate::tools::ToolContext,
    ) -> Result<crate::tools::Started> {
        use super::util::optional_u64;

        let lease = self.permission.lease();
        admit_subshell(SUBSHELL_EXECUTE, lease.level, self.required)?;
        let handle = addressed_handle(&self.handles, context.session_id, &input, SUBSHELL_EXECUTE)?;
        let effective = handle.effective_level(lease.level);
        if handle.scratch().is_some() && !Permission::Workspace.is_within(effective) {
            return Err(subshell_error(
                SUBSHELL_EXECUTE,
                format!(
                    "a scratch handle needs `workspace` permission; this call runs at {effective}"
                ),
            ));
        }
        let timeout_ms = optional_u64(&input, "timeout_ms", SUBSHELL_EXECUTE)?
            .unwrap_or(DEFAULT_TIMEOUT.as_millis() as u64);
        let (request, proofs) = handle
            .request(
                require_str(&input, "command", SUBSHELL_EXECUTE)?,
                timeout_ms,
                lease.level,
            )
            .map_err(|error| subshell_error(SUBSHELL_EXECUTE, error))?;
        let timeout = request.timeout();
        let frame = request
            .encode()
            .map_err(|error| subshell_error(SUBSHELL_EXECUTE, error))?;
        let target = Arc::clone(&self.target);
        // The claim this call holds on the handle, returned when the call ends however it ends, so
        // a close can report what it stopped. A handle already closed refuses here rather than
        // starting a command in a scope the close has released.
        let outstanding = handle
            .begin()
            .map_err(|error| subshell_error(SUBSHELL_EXECUTE, error))?;
        let closed = handle.cancelled();
        Ok(crate::tools::Started::running(
            None,
            move |context| async move {
                // The proofs live as long as the request they mounted: until this call is done.
                let _proofs = proofs;
                let _outstanding = outstanding;
                let started = tokio::time::Instant::now();
                // Bound delivery as well as execution. The launcher may not consume its input if
                // the distro cannot start. A stop during setup is unconfirmed: the request may
                // already have reached the guest, and the local launcher's end says nothing about
                // the namespace it asked for.
                let launch = tokio::time::timeout(
                    timeout,
                    crate::sandbox::wsl_host::launch(&target, &frame),
                );
                tokio::pin!(launch);
                let child = tokio::select! {
                    biased;
                    () = lease.revoked() => {
                        if let Some(observation) = &context.teardown {
                            observation.note(false);
                        }
                        return Err(subshell_error(SUBSHELL_EXECUTE, "permission was lowered during setup; whether the managed WSL command started is unconfirmed"));
                    }
                    () = closed.cancelled() => {
                        if let Some(observation) = &context.teardown {
                            observation.note(false);
                        }
                        return Err(subshell_error(SUBSHELL_EXECUTE, "the subshell handle was closed during setup; whether the command started is unconfirmed"));
                    }
                    () = context.cancellation.cancelled() => {
                        if let Some(observation) = &context.teardown {
                            observation.note(false);
                        }
                        return Err(MekaError::Interrupted);
                    }
                    launched = &mut launch => launched
                        .map_err(|_| subshell_error(SUBSHELL_EXECUTE, "timed out delivering the managed WSL request"))?
                        .map_err(|error| subshell_error(SUBSHELL_EXECUTE, format!("{error:#}")))?,
                };
                run_wsl_command_tree(
                    child,
                    &request.op,
                    handle.effective_level(lease.level),
                    timeout.saturating_sub(started.elapsed()),
                    &context,
                    &lease,
                    Some(&closed),
                )
                .await
                .map_err(|failure| match failure {
                    CommandTreeError::Interrupted => MekaError::Interrupted,
                    CommandTreeError::Wait(error) => subshell_error(
                        SUBSHELL_EXECUTE,
                        format!("failed to wait for the WSL launcher: {error}"),
                    ),
                })
            },
        ))
    }
}

#[cfg(windows)]
#[async_trait]
impl Tool for SubshellExportTool {
    fn definition(&self) -> ToolDefinition {
        ToolDefinition {
            name: SUBSHELL_EXPORT.to_string(),
            description: format!(
                "Copy files or directories out of a subshell handle's admitted scope into an \
                 authorized Windows destination. {} The destination is rechecked against the \
                 session's current write scope at every call, and a `read` session cannot export. \
                 Sources must be real paths within the handle's scope, never symlinks. A destination \
                 name that already exists is refused: export to a fresh name.",
                self.target.scope_description(),
            ),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "handle": {"type": "string", "description": "The handle name opened by `subshell_open`."},
                    "paths": {"type": "array", "items": {"type": "string"}, "description": "Guest Linux paths within the handle's admitted scope to copy."},
                    "destination": {"type": "string", "description": "An existing directory within the session's write scope to copy into."}
                },
                "required": ["handle", "paths", "destination"]
            }),
            ..Default::default()
        }
    }

    fn required_permission(&self) -> Permission {
        Permission::Read
    }

    async fn refusal_at_level(
        &self,
        level: Permission,
        _: &serde_json::Value,
    ) -> Option<ToolOutput> {
        // A read-level session cannot export to disk: the floor is the operation's own, whatever
        // the operator configured for the family.
        admit_subshell(
            SUBSHELL_EXPORT,
            level,
            self.required.max(Permission::Workspace),
        )
        .err()
        .map(|error| ToolOutput::from_error(&error))
    }

    async fn execute(
        &self,
        input: serde_json::Value,
        context: crate::tools::ToolContext,
    ) -> Result<ToolOutput> {
        use super::util::{optional_bool, string_or_list};

        // The `overwrite` argument was removed with the behavior it named: an export never
        // replaces an existing entry. A caller still passing the boolean it once took gets the
        // migration, not a silent drop of the flag.
        if optional_bool(&input, "overwrite", SUBSHELL_EXPORT)?.is_some() {
            return Err(subshell_error(
                SUBSHELL_EXPORT,
                "the `overwrite` argument was removed: an export never replaces an existing \
                 entry; export to a fresh name",
            ));
        }
        let lease = self.permission.lease();
        admit_subshell(
            SUBSHELL_EXPORT,
            lease.level,
            self.required.max(Permission::Workspace),
        )?;
        let handle = addressed_handle(&self.handles, context.session_id, &input, SUBSHELL_EXPORT)?;
        // Hold the handle open for the whole export and watch its close token: a close removes the
        // handle, but a copy already under way would otherwise keep reading the scope the close
        // released.
        let _outstanding = handle
            .begin()
            .map_err(|error| subshell_error(SUBSHELL_EXPORT, error))?;
        let closed = handle.cancelled();
        if !Permission::Workspace.is_within(handle.effective_level(lease.level)) {
            return Err(subshell_error(
                SUBSHELL_EXPORT,
                "a read-only subshell handle cannot export to disk; reopen it at `workspace`",
            ));
        }
        let paths = string_or_list(&input, "paths", SUBSHELL_EXPORT)?.unwrap_or_default();
        let destination = require_str(&input, "destination", SUBSHELL_EXPORT)?;
        let mut copies = plan_export(
            &handle,
            &self.site.cwd,
            &self.scope,
            lease.level,
            &paths,
            &destination,
        )?;
        // Guest sources are read by the runner, not by a host walk: the request carries the exact
        // paths the handle admitted, and the response's manifest is planned and refused before the
        // first byte arrives.
        if !copies.guest_sources.is_empty() {
            let sources = copies.guest_sources.clone();
            let transfer = crate::subshell::Transfer::Export {
                sources: sources.clone(),
            };
            let timeout_ms =
                u64::try_from(crate::subshell::TRANSFER_TIMEOUT.as_millis()).unwrap_or(u64::MAX);
            let (request, _proofs) = handle
                .transfer_request(timeout_ms, transfer, lease.level)
                .map_err(|error| subshell_error(SUBSHELL_EXPORT, format!("{error:#}")))?;
            let frame = request
                .encode()
                .map_err(|error| subshell_error(SUBSHELL_EXPORT, format!("{error:#}")))?;
            let (streamed, planned) = {
                let mut visitor = GuestExportVisitor::new(
                    &self.site,
                    &self.scope,
                    &self.permission,
                    &context.cancellation,
                    &closed,
                    &lease,
                    &handle,
                    &mut copies,
                    &sources,
                );
                visitor.scratch = handle.scratch();
                let run = drive_transfer(
                    &self.target,
                    &request.op,
                    &frame,
                    &lease,
                    &context,
                    &mut visitor,
                )
                .await
                .map_err(|detail| subshell_error(SUBSHELL_EXPORT, detail))?;
                match run {
                    TransferRun::Done => {}
                    TransferRun::Lowered => {
                        return Err(subshell_error(
                            SUBSHELL_EXPORT,
                            "permission was lowered during the export; the export ended",
                        ));
                    }
                    TransferRun::Cancelled | TransferRun::Stopped => {
                        return Err(MekaError::Interrupted);
                    }
                }
                (visitor.streamed(), visitor.planned())
            };
            if streamed != planned {
                return Err(subshell_error(
                    SUBSHELL_EXPORT,
                    format!(
                        "the runner's transfer ended after {streamed} of {planned} file(s); the \
                         export is incomplete"
                    ),
                ));
            }
        }
        // Every target is re-admitted against the level in force *now*, not the one the call was
        // admitted at, and its destination chain is created one verified component at a time. A
        // downgrade or a revocation stops the export between files.
        let mut copied = Vec::new();
        let mut copied_bytes = 0u64;
        for (source, target) in &copies.files {
            if let PlannedSource::Guest { len, .. } = source {
                copied_bytes = copied_bytes.saturating_add(*len);
                copied.push(target.display().to_string());
            }
        }
        let admit = |target: &std::path::Path| -> Result<()> {
            let live = self.permission.get();
            let resolved = crate::workspace::resolve_existing_prefix(target);
            self.scope
                .admit_shown_at(live, &self.site.cwd, target, &resolved)
                .map_err(|refusal| {
                    subshell_error(
                        SUBSHELL_EXPORT,
                        format!("the export stopped at {}: {refusal}", target.display()),
                    )
                })
        };
        for (source, target) in &copies.files {
            let PlannedSource::Native(source) = source else {
                continue;
            };
            if let Err(stop) = commit_gate(&closed, &context.cancellation, &lease) {
                return match stop {
                    CommitStop::Canceled => Err(MekaError::Interrupted),
                    other => Err(subshell_error(SUBSHELL_EXPORT, other.report(copied.len()))),
                };
            }
            admit(target)?;
            if let Some(parent) = target.parent() {
                create_verified_directories(&copies.root, parent)
                    .map_err(|refusal| subshell_error(SUBSHELL_EXPORT, refusal))?;
            }
            let staged = stage_export_file(source, target)
                .map_err(|refusal| subshell_error(SUBSHELL_EXPORT, refusal))?;
            // The gate again after the copy and before the rename: a stop or downgrade that won
            // while the bytes moved must not be overtaken by the publication.
            if let Err(stop) = commit_gate(&closed, &context.cancellation, &lease) {
                return match stop {
                    CommitStop::Canceled => Err(MekaError::Interrupted),
                    other => Err(subshell_error(SUBSHELL_EXPORT, other.report(copied.len()))),
                };
            }
            admit(target)?;
            let pinned = target
                .parent()
                .map(|parent| PinnedDirectory::pin(parent, None))
                .transpose()
                .map_err(|refusal| subshell_error(SUBSHELL_EXPORT, refusal))?
                .ok_or_else(|| {
                    subshell_error(
                        SUBSHELL_EXPORT,
                        format!("{} has no parent directory", target.display()),
                    )
                })?;
            copied_bytes = copied_bytes.saturating_add(
                publish_export_temp(staged, target, pinned).map_err(|refusal| {
                    subshell_error(
                        SUBSHELL_EXPORT,
                        format!(
                            "{refusal}; {} file(s) were published before it and remain",
                            copied.len()
                        ),
                    )
                })?,
            );
            copied.push(target.display().to_string());
        }
        for directory in &copies.directories {
            if closed.is_cancelled() {
                return Err(subshell_error(
                    SUBSHELL_EXPORT,
                    "the handle was closed during the export; the export ended",
                ));
            }
            if context.cancellation.is_cancelled() {
                return Err(MekaError::Interrupted);
            }
            if lease.is_revoked() {
                return Err(subshell_error(
                    SUBSHELL_EXPORT,
                    "permission was lowered during the export; the export ended",
                ));
            }
            admit(directory)?;
            create_verified_directories(&copies.root, directory)
                .map_err(|refusal| subshell_error(SUBSHELL_EXPORT, refusal))?;
        }
        Ok(ToolOutput::text(
            format!(
                "exported {copied_bytes} byte(s) in {} file(s) to {}:\n{}",
                copied.len(),
                destination,
                copied
                    .iter()
                    .map(|path| format!("  {path}"))
                    .collect::<Vec<_>>()
                    .join("\n")
            ),
            false,
        ))
    }
}

#[cfg(windows)]
#[async_trait]
impl Tool for SubshellCloseTool {
    fn definition(&self) -> ToolDefinition {
        ToolDefinition {
            name: SUBSHELL_CLOSE.to_string(),
            description: "Close a subshell handle: stop the work running under it and release its \
                 scope. Anything worth keeping must be exported first."
                .to_string(),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "handle": {"type": "string", "description": "The handle name opened by `subshell_open`."}
                },
                "required": ["handle"]
            }),
            ..Default::default()
        }
    }

    fn required_permission(&self) -> Permission {
        Permission::Read
    }

    async fn refusal_at_level(
        &self,
        level: Permission,
        _: &serde_json::Value,
    ) -> Option<ToolOutput> {
        admit_subshell(SUBSHELL_CLOSE, level, self.required)
            .err()
            .map(|error| ToolOutput::from_error(&error))
    }

    async fn execute(
        &self,
        input: serde_json::Value,
        context: crate::tools::ToolContext,
    ) -> Result<ToolOutput> {
        let lease = self.permission.lease();
        admit_subshell(SUBSHELL_CLOSE, lease.level, self.required)?;
        let name = require_str(&input, "handle", SUBSHELL_CLOSE)?;
        let handle = self
            .handles
            .close(context.session_id, &name)
            .map_err(|error| subshell_error(SUBSHELL_CLOSE, error))?;
        // Cancellation is a request, not a result. A call whose last check already passed keeps
        // its process tree alive until it returns, so the close waits for the calls it stopped
        // before it claims they stopped: saying "stopped" over work that is still unwinding is
        // the one report a caller cannot act on.
        let stopping = handle.outstanding();
        let idle = stopping == 0
            || tokio::time::timeout(CLOSE_WAIT, handle.wait_idle())
                .await
                .is_ok();
        let mut text = if idle {
            format!(
                "closed subshell handle {name:?}; stopped {stopping} running command(s). Released: {}",
                handle.scope_description()
            )
        } else {
            format!(
                "closed subshell handle {name:?}; stop requested for {stopping} running command(s), \
                 which had not returned within {}s. The guest teardown is unconfirmed and the \
                 scratch workspace is left for the reaper. Released: {}",
                CLOSE_WAIT.as_secs(),
                handle.scope_description()
            )
        };
        if idle && let Some(scratch) = handle.scratch() {
            // The runner removes the workspace it created, by the id the handle was opened with,
            // and never by a host path. A removal the runner does not confirm is reported as
            // unconfirmed: the lease sweep reaps whatever remains.
            let removal = async {
                let timeout_ms = u64::try_from(crate::subshell::TRANSFER_TIMEOUT.as_millis())
                    .unwrap_or(u64::MAX);
                let (request, _proofs) = handle
                    .transfer_request(
                        timeout_ms,
                        crate::subshell::Transfer::RemoveScratch,
                        lease.level,
                    )
                    .map_err(|error| format!("{error:#}"))?;
                let frame = request.encode().map_err(|error| format!("{error:#}"))?;
                let mut visitor = crate::subshell::ManifestOnly::default();
                drive_transfer(
                    handle.target(),
                    &request.op,
                    &frame,
                    &lease,
                    &context,
                    &mut visitor,
                )
                .await
            }
            .await;
            match removal {
                Ok(TransferRun::Done) => {}
                Ok(_) => text.push_str(&format!(
                    "\nthe scratch workspace {} was not confirmed removed; it will be reaped",
                    scratch.path
                )),
                Err(error) => text.push_str(&format!(
                    "\nthe scratch workspace {} was not confirmed removed: {error}; it will be \
                     reaped",
                    scratch.path
                )),
            }
        }
        Ok(ToolOutput::text(text, false))
    }
}

/// Everything one export will copy, decided before the first byte moves: the file pairs, the
/// directories to create, and the destination spelling the model named.
///
/// Check-then-copy rather than copy-as-you-go because every refusal has to land before anything
/// is written: a source outside the handle's scope, a symlink anywhere in a source, a destination
/// outside the write scope, or a name already taken at the destination must each leave the
/// destination untouched. The destination is judged against the parent's *current* write scope at
/// every call, so a lowered permission cannot be routed around by a handle opened earlier.
#[cfg(windows)]
struct ExportPlan {
    /// The admitted destination root every target lives beneath.
    root: std::path::PathBuf,
    files: Vec<(PlannedSource, std::path::PathBuf)>,
    directories: Vec<std::path::PathBuf>,
    /// Every destination already planned, lowercased for Windows' case-insensitive names.
    seen: std::collections::HashSet<String>,
    /// The typed guest sources the runner reads, in the order its manifest's root indices name.
    guest_sources: Vec<crate::subshell::ExportSource>,
}

/// Where one planned file's bytes will come from: the host reads a native source itself, while a
/// guest source is streamed by the runner after its manifest is planned and refused or accepted.
#[cfg(windows)]
#[derive(Clone, Debug)]
enum PlannedSource {
    Native(std::path::PathBuf),
    Guest { root: usize, path: String, len: u64 },
}

#[cfg(windows)]
fn plan_export(
    handle: &crate::subshell::Handle,
    cwd: &crate::workspace::SharedCwd,
    scope: &crate::workspace::WriteScope,
    level: Permission,
    paths: &[String],
    destination: &str,
) -> Result<ExportPlan> {
    let spelled = crate::workspace::resolve_against_cwd(cwd, destination);
    let resolved = crate::workspace::resolve_existing_prefix(&spelled);
    scope
        .admit_shown_at(level, cwd, &spelled, &resolved)
        .map_err(|refusal| subshell_error(SUBSHELL_EXPORT, refusal))?;
    let destination = std::fs::metadata(&resolved)
        .map_err(|error| {
            subshell_error(
                SUBSHELL_EXPORT,
                format!(
                    "the export destination must be an existing directory: {}: {error}",
                    spelled.display()
                ),
            )
        })
        .and_then(|metadata| {
            if metadata.is_dir() {
                Ok(resolved)
            } else {
                Err(subshell_error(
                    SUBSHELL_EXPORT,
                    format!(
                        "the export destination is not a directory: {}",
                        spelled.display()
                    ),
                ))
            }
        })?;
    // The door for the publication's guarantees: a destination that cannot offer stable
    // identities, a no-replace rename bound to a held directory, and a deletion that names one
    // object is refused before the plan, never trusted to behave at the commit.
    publication_provider(&destination)
        .map_err(|refusal| subshell_error(SUBSHELL_EXPORT, refusal))?;
    if paths.is_empty() {
        return Err(subshell_error(SUBSHELL_EXPORT, "no paths to export"));
    }

    let mut plan = ExportPlan {
        root: destination.clone(),
        files: Vec::new(),
        directories: Vec::new(),
        seen: std::collections::HashSet::new(),
        guest_sources: Vec::new(),
    };
    for path in paths {
        let path = scratch_workspace_alias(handle, path);
        let path: &str = &path;
        if crate::subshell::windows_components(path).is_some() {
            let source = export_source(handle, path)?;
            let name = source.file_name().ok_or_else(|| {
                subshell_error(SUBSHELL_EXPORT, format!("not a file name: {path:?}"))
            })?;
            let target = destination.join(name);
            collect_export(&source, &target, &mut plan)?;
        } else {
            let source = guest_export_source(handle, path)?;
            plan.guest_sources.push(source);
        }
    }
    preflight_export(&plan).map_err(|detail| subshell_error(SUBSHELL_EXPORT, detail))?;
    if let Some(scratch) = handle.scratch() {
        let conflicts = scratch_conflicts(scratch, &plan.files);
        if !conflicts.is_empty() {
            return Err(subshell_error(
                SUBSHELL_EXPORT,
                format!(
                    "exporting back over the staged source would lose changes the snapshot does \
                     not hold:\n{}",
                    conflicts
                        .iter()
                        .map(|conflict| format!("  {conflict}"))
                        .collect::<Vec<_>>()
                        .join("\n")
                ),
            ));
        }
    }
    Ok(plan)
}

/// One guest export source as the wire carries it: the request root the handle admitted the path
/// under and the validated components beneath it. The runner resolves it beneath the root it
/// opens itself, so no free-standing absolute path travels and no path walk decides authority.
#[cfg(windows)]
fn guest_export_source(
    handle: &crate::subshell::Handle,
    path: &str,
) -> Result<crate::subshell::ExportSource> {
    if !(path.starts_with('/')
        && !path.contains('\0')
        && !path.contains('\\')
        && crate::subshell::is_normalized_guest_path(path))
    {
        return Err(subshell_error(
            SUBSHELL_EXPORT,
            format!(
                "not an absolute normalized Linux path (a Windows separator is not a path \
                 character here): {path:?}"
            ),
        ));
    }
    if !handle.admits_path(path) {
        return Err(subshell_error(
            SUBSHELL_EXPORT,
            format!("{path:?} is outside the handle's admitted scope"),
        ));
    }
    handle.export_source(path).ok_or_else(|| {
        subshell_error(
            SUBSHELL_EXPORT,
            format!("{path:?} is outside the handle's admitted scope"),
        )
    })
}

/// How a transfer run ended when it was not an error.
#[cfg(windows)]
enum TransferRun {
    /// The response was complete.
    Done,
    /// Permission was lowered while the transfer ran.
    Lowered,
    /// The call was cancelled while the transfer ran.
    Cancelled,
    /// The runner was stopped for another reason.
    Stopped,
}

/// Launch one transfer request and read its response to the end, interrupting the run when the
/// lease ends or the call is cancelled. A dropped run kills the runner's process tree.
#[cfg(windows)]
async fn drive_transfer(
    target: &crate::subshell::Target,
    op: &str,
    frame: &[u8],
    lease: &crate::permission::PermissionLease,
    context: &crate::tools::ToolContext,
    visitor: &mut dyn crate::subshell::TransferVisitor,
) -> std::result::Result<TransferRun, String> {
    let timeout = crate::subshell::TRANSFER_TIMEOUT;
    let launched = tokio::select! {
        biased;
        () = lease.revoked() => return Ok(TransferRun::Lowered),
        () = context.cancellation.cancelled() => return Ok(TransferRun::Cancelled),
        launched = tokio::time::timeout(
            timeout,
            crate::sandbox::wsl_host::launch(target, frame),
        ) => launched,
    };
    let tree = match launched {
        Ok(launched) => launched.map_err(|error| format!("{error:#}"))?,
        Err(_) => {
            return Err(format!(
                "timed out after {}ms starting the transfer",
                timeout.as_millis()
            ));
        }
    };
    let collected = tokio::select! {
        biased;
        () = lease.revoked() => return Ok(TransferRun::Lowered),
        () = context.cancellation.cancelled() => return Ok(TransferRun::Cancelled),
        collected = crate::sandbox::wsl_host::collect_transfer(
            tree,
            op,
            timeout,
            Some(crate::process::Stop::Graceful(&context.cancellation)),
            visitor,
        ) => collected,
    };
    match collected {
        Ok(crate::sandbox::wsl_host::Collected::Done) => Ok(TransferRun::Done),
        Ok(crate::sandbox::wsl_host::Collected::Stopped) => Ok(TransferRun::Stopped),
        Err(error) => Err(format!("{error:#}")),
    }
}

/// Join one manifest path below the directory its root names, one validated component at a time.
#[cfg(windows)]
fn join_transfer_path(
    base: &std::path::Path,
    path: &str,
) -> std::result::Result<std::path::PathBuf, String> {
    let mut target = base.to_path_buf();
    for component in path.split('/') {
        export_component(std::ffi::OsStr::new(component))?;
        target.push(component);
    }
    Ok(target)
}

/// One file the guest is streaming, from its `File` header until its last byte.
#[cfg(windows)]
struct OpenGuestFile {
    entry: crate::subshell::TransferEntry,
    target: std::path::PathBuf,
    temporary: ExportTemp,
    writer: std::fs::File,
    written: u64,
    hasher: sha2::Sha256,
}

/// One file written to a temporary sibling of the export root, waiting for the transfer's `Done`
/// and a successful runner exit before it takes its destination name.
#[cfg(windows)]
struct PendingGuestFile {
    temporary: ExportTemp,
    target: std::path::PathBuf,
}

/// The host visitor that turns one export transfer into the same plan a native export builds: the
/// manifest is admitted, refused, or planned before any byte arrives, then each streamed file is
/// written to a temporary sibling and published under the existing no-replace and identity rules.
#[cfg(windows)]
struct GuestExportVisitor<'a> {
    site: &'a crate::session::ToolSite,
    scope: &'a crate::workspace::WriteScope,
    permission: &'a crate::permission::SharedPermission,
    cancellation: &'a tokio_util::sync::CancellationToken,
    closed: &'a tokio_util::sync::CancellationToken,
    /// The lease the call was admitted under, rechecked at every commit: a live level that still
    /// reads high after a downgrade and a raise is not the authority the call was given.
    lease: &'a crate::permission::PermissionLease,
    handle: &'a crate::subshell::Handle,
    plan: &'a mut ExportPlan,
    sources: &'a [crate::subshell::ExportSource],
    /// The staged workspace this handle runs in, when it has one.
    scratch: Option<&'a crate::subshell::ScratchState>,
    /// Every file the manifest announced, by source index and relative path.
    entries: std::collections::HashMap<(usize, String), crate::subshell::TransferEntry>,
    open: Option<OpenGuestFile>,
    /// Files whose bytes and digest were accepted and wait for `complete`.
    pending: Vec<PendingGuestFile>,
    streamed: usize,
}

#[cfg(windows)]
impl<'a> GuestExportVisitor<'a> {
    #[allow(clippy::too_many_arguments)]
    fn new(
        site: &'a crate::session::ToolSite,
        scope: &'a crate::workspace::WriteScope,
        permission: &'a crate::permission::SharedPermission,
        cancellation: &'a tokio_util::sync::CancellationToken,
        closed: &'a tokio_util::sync::CancellationToken,
        lease: &'a crate::permission::PermissionLease,
        handle: &'a crate::subshell::Handle,
        plan: &'a mut ExportPlan,
        sources: &'a [crate::subshell::ExportSource],
    ) -> Self {
        Self {
            site,
            scope,
            permission,
            cancellation,
            closed,
            lease,
            handle,
            plan,
            sources,
            scratch: None,
            entries: std::collections::HashMap::new(),
            open: None,
            pending: Vec::new(),
            streamed: 0,
        }
    }

    /// How many files the guest streamed to completion.
    fn streamed(&self) -> usize {
        self.streamed
    }

    /// How many files the manifest announced.
    fn planned(&self) -> usize {
        self.entries.len()
    }

    fn admit(&self, target: &std::path::Path) -> anyhow::Result<()> {
        let live = self.permission.get();
        let resolved = crate::workspace::resolve_existing_prefix(target);
        self.scope
            .admit_shown_at(live, &self.site.cwd, target, &resolved)
            .map_err(|refusal| {
                anyhow::anyhow!("the export stopped at {}: {refusal}", target.display())
            })
    }

    fn interrupted(&self) -> Option<anyhow::Error> {
        if self.closed.is_cancelled() {
            return Some(anyhow::anyhow!(
                "the handle was closed during the export; the export ended"
            ));
        }
        if self.cancellation.is_cancelled() {
            return Some(anyhow::anyhow!("the export was cancelled"));
        }
        None
    }
}

#[cfg(windows)]
#[async_trait]
impl crate::subshell::TransferVisitor for GuestExportVisitor<'_> {
    async fn manifest(
        &mut self,
        roots: &[crate::subshell::TransferRoot],
        entries: &[crate::subshell::TransferEntry],
    ) -> anyhow::Result<()> {
        use anyhow::ensure;

        ensure!(
            roots.len() == self.sources.len(),
            "the runner read {} source(s), not {}",
            roots.len(),
            self.sources.len()
        );
        let mut bases = Vec::with_capacity(roots.len());
        for (index, (root, source)) in roots.iter().zip(self.sources).enumerate() {
            ensure!(
                root.source == *source,
                "the runner read {:?}, not the source the request named",
                root.source
            );
            let expected_name = self.handle.export_name(source).ok_or_else(|| {
                anyhow::anyhow!("the export source has no name a host could publish it under")
            })?;
            ensure!(
                root.name == expected_name,
                "the runner named the source {:?}, not its own final component",
                root.name
            );
            export_component(std::ffi::OsStr::new(&root.name))
                .map_err(|detail| anyhow::anyhow!("{detail}"))?;
            let base = self.plan.root.join(&root.name);
            claim_export_target(self.plan, &base).map_err(|detail| anyhow::anyhow!("{detail}"))?;
            if root.directory {
                self.plan.directories.push(base.clone());
            }
            bases.push((index, base, root.directory));
        }
        let mut seen = std::collections::HashSet::new();
        let mut file_roots = vec![0usize; roots.len()];
        for entry in entries {
            ensure!(
                entry.root < roots.len(),
                "a manifest entry names an unknown source"
            );
            ensure!(
                seen.insert((entry.root, entry.path.clone())),
                "the manifest names {:?} twice",
                entry.path
            );
            let (_, base, directory) = bases
                .get(entry.root)
                .ok_or_else(|| anyhow::anyhow!("a manifest entry names an unknown source"))?;
            if entry.directory {
                ensure!(*directory, "a file source cannot carry a directory entry");
                let target = join_transfer_path(base, &entry.path)
                    .map_err(|detail| anyhow::anyhow!("{detail}"))?;
                claim_export_target(self.plan, &target)
                    .map_err(|detail| anyhow::anyhow!("{detail}"))?;
                self.plan.directories.push(target);
                continue;
            }
            ensure!(
                entry.parsed_digest().is_some(),
                "invalid transfer digest: {:?}",
                entry.digest
            );
            let target = if *directory {
                let target = join_transfer_path(base, &entry.path)
                    .map_err(|detail| anyhow::anyhow!("{detail}"))?;
                claim_export_target(self.plan, &target)
                    .map_err(|detail| anyhow::anyhow!("{detail}"))?;
                planned_destination(&target).map_err(|error| anyhow::anyhow!("{error:#}"))?;
                target
            } else {
                let root = roots
                    .get(entry.root)
                    .ok_or_else(|| anyhow::anyhow!("a manifest entry names an unknown source"))?;
                ensure!(
                    entry.path == root.name,
                    "a file source's only entry must be the file itself"
                );
                let count = file_roots
                    .get_mut(entry.root)
                    .ok_or_else(|| anyhow::anyhow!("a manifest entry names an unknown source"))?;
                *count = count.saturating_add(1);
                planned_destination(base).map_err(|error| anyhow::anyhow!("{error:#}"))?;
                base.clone()
            };
            self.entries
                .insert((entry.root, entry.path.clone()), entry.clone());
            self.plan.files.push((
                PlannedSource::Guest {
                    root: entry.root,
                    path: entry.path.clone(),
                    len: entry.len,
                },
                target,
            ));
        }
        for (index, root) in roots.iter().enumerate() {
            if !root.directory {
                ensure!(
                    file_roots.get(index) == Some(&1),
                    "a file source must name exactly one file"
                );
            }
        }
        if let Some(scratch) = self.scratch {
            let conflicts = scratch_conflicts(scratch, &self.plan.files);
            if !conflicts.is_empty() {
                anyhow::bail!(
                    "exporting back over the staged source would lose changes the snapshot does \
                     not hold:\n{}",
                    conflicts
                        .iter()
                        .map(|conflict| format!("  {conflict}"))
                        .collect::<Vec<_>>()
                        .join("\n")
                );
            }
        }
        preflight_export(self.plan).map_err(|detail| anyhow::anyhow!("{detail}"))?;
        // Directories no file lands in are created only once the transfer has ended; a file's
        // parent directory is created when its bytes arrive. Admission still happens here, so a
        // destination outside the live scope is refused before any byte moves.
        let directories = self.plan.directories.clone();
        for directory in &directories {
            self.admit(directory)?;
        }
        Ok(())
    }

    async fn begin(&mut self, entry: &crate::subshell::TransferEntry) -> anyhow::Result<()> {
        use anyhow::ensure;
        use sha2::Digest as _;

        if let Some(error) = self.interrupted() {
            return Err(error);
        }
        ensure!(self.open.is_none(), "a transfer file arrived mid-payload");
        let planned = self
            .entries
            .get(&(entry.root, entry.path.clone()))
            .ok_or_else(|| anyhow::anyhow!("a transfer file arrived that no manifest named"))?;
        ensure!(!planned.directory, "a directory entry carried file bytes");
        ensure!(
            entry.len == planned.len
                && entry.digest == planned.digest
                && entry.modified_secs == planned.modified_secs
                && entry.modified_nanos == planned.modified_nanos,
            "a transfer file header does not match its manifest entry"
        );
        let (target, _) = self
            .plan
            .files
            .iter()
            .find_map(|(source, target)| match source {
                PlannedSource::Guest { root, path, .. }
                    if *root == entry.root && *path == entry.path =>
                {
                    Some((target.clone(), ()))
                }
                _ => None,
            })
            .ok_or_else(|| anyhow::anyhow!("a transfer file has no planned destination"))?;
        self.admit(&target)?;
        // The temporary is created beside its destination, so every directory between the
        // admitted root and the file has to exist before its bytes arrive. The pass after the
        // transfer still creates the directories no file landed in.
        if let Some(parent) = target.parent() {
            create_verified_directories(&self.plan.root, parent)
                .map_err(|detail| anyhow::anyhow!("{detail}"))?;
        }
        let (temporary, writer) =
            ExportTemp::create_writer(&target).map_err(|detail| anyhow::anyhow!("{detail}"))?;
        self.open = Some(OpenGuestFile {
            entry: entry.clone(),
            target,
            temporary,
            writer,
            written: 0,
            hasher: sha2::Sha256::new(),
        });
        Ok(())
    }

    async fn payload(&mut self, chunk: &[u8]) -> anyhow::Result<()> {
        use std::io::Write as _;

        use sha2::Digest as _;

        if let Some(error) = self.interrupted() {
            return Err(error);
        }
        let open = self
            .open
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("transfer bytes arrived before their file header"))?;
        open.writer
            .write_all(chunk)
            .map_err(|error| anyhow::anyhow!("cannot write {}: {error}", open.target.display()))?;
        open.hasher.update(chunk);
        open.written = open.written.saturating_add(chunk.len() as u64);
        Ok(())
    }

    async fn end(&mut self, _entry: &crate::subshell::TransferEntry) -> anyhow::Result<()> {
        use anyhow::ensure;
        use sha2::Digest as _;

        let open = self
            .open
            .take()
            .ok_or_else(|| anyhow::anyhow!("a transfer file ended without its header"))?;
        ensure!(
            open.written == open.entry.len,
            "the runner sent {} byte(s) for {:?}, not the {} it announced",
            open.written,
            open.entry.path,
            open.entry.len
        );
        let digest: [u8; 32] = open.hasher.finalize().into();
        ensure!(
            Some(digest) == open.entry.parsed_digest(),
            "the bytes of {:?} do not match the manifest digest",
            open.entry.path
        );
        drop(open.writer);
        let mut temporary = open.temporary;
        // The sealed identity and digest are what the publication must still find when it opens
        // the file again.
        temporary.sealed(open.written, digest);
        self.pending.push(PendingGuestFile {
            temporary,
            target: open.target,
        });
        self.streamed = self.streamed.saturating_add(1);
        Ok(())
    }

    async fn complete(&mut self) -> anyhow::Result<()> {
        if let Some(error) = self.interrupted() {
            return Err(error);
        }
        let directories = self.plan.directories.clone();
        for directory in &directories {
            self.admit(directory)?;
            create_verified_directories(&self.plan.root, directory)
                .map_err(|detail| anyhow::anyhow!("{detail}"))?;
        }
        let pending = std::mem::take(&mut self.pending);
        let mut committed = Vec::new();
        for pending in pending {
            // The gate again, per publication: a stop or downgrade that won while the bytes moved
            // must not be overtaken by the commit, and the lease the call was admitted under is
            // rechecked, not only the live level.
            if let Err(stop) = commit_gate(self.closed, self.cancellation, self.lease) {
                return Err(anyhow::anyhow!("{}", stop.report(committed.len())));
            }
            if let Some(parent) = pending.target.parent() {
                create_verified_directories(&self.plan.root, parent)
                    .map_err(|detail| anyhow::anyhow!("{detail}"))?;
            }
            self.admit(&pending.target)?;
            let pinned = pending
                .target
                .parent()
                .map(|parent| PinnedDirectory::pin(parent, None))
                .transpose()
                .map_err(|detail| anyhow::anyhow!("{detail}"))?
                .ok_or_else(|| {
                    anyhow::anyhow!("{} has no parent directory", pending.target.display())
                })?;
            match publish_export_temp(pending.temporary, &pending.target, pinned) {
                Ok(_) => committed.push(pending.target.display().to_string()),
                Err(detail) => {
                    return Err(anyhow::anyhow!(
                        "{detail}; {} file(s) were published before it and remain",
                        committed.len()
                    ));
                }
            }
        }
        Ok(())
    }
}

/// One native export source as the Windows path the host reads itself: the spelling is the
/// operator's grant, resolved as written. A symlink or reparse point is refused rather than
/// followed, and a path that resolves elsewhere is refused because it has left the admitted
/// scope however the link was spelled. A guest source is read by the runner instead.
#[cfg(windows)]
fn export_source(handle: &crate::subshell::Handle, path: &str) -> Result<std::path::PathBuf> {
    let path = scratch_workspace_alias(handle, path);
    let path: &str = &path;
    if crate::subshell::windows_components(path).is_some() {
        if !handle.admits_path(path) {
            return Err(subshell_error(
                SUBSHELL_EXPORT,
                format!("{path:?} is outside the handle's admitted scope"),
            ));
        }
        let native = std::path::PathBuf::from(path);
        let metadata = std::fs::symlink_metadata(&native).map_err(|error| {
            subshell_error(
                SUBSHELL_EXPORT,
                format!("cannot read the export source {path:?}: {error}"),
            )
        })?;
        if metadata.file_attributes() & 0x400 != 0 {
            return Err(subshell_error(
                SUBSHELL_EXPORT,
                format!(
                    "{path:?} is a symlink or reparse point; export sources must be real paths"
                ),
            ));
        }
        if !metadata.is_dir() && !metadata.is_file() {
            return Err(subshell_error(
                SUBSHELL_EXPORT,
                format!("{path:?} is not a regular file or directory"),
            ));
        }
        if metadata.is_file() {
            let links = crate::fs::hard_link_count(&native).map_err(|error| {
                subshell_error(SUBSHELL_EXPORT, format!("cannot read {path:?}: {error}"))
            })?;
            if links > 1 {
                return Err(subshell_error(
                    SUBSHELL_EXPORT,
                    format!(
                        "{path:?} has {links} hard links; exporting a file another name can \
                         change would not be the file the scope admitted"
                    ),
                ));
            }
        }
        verify_native_ancestors(&native)
            .map_err(|refusal| subshell_error(SUBSHELL_EXPORT, refusal))?;
        // The spelling admitted above is the operator's; the directory it resolves to is what the
        // copy actually reads. A junction anywhere below an admitted grant could otherwise carry
        // the read to a tree the grant never named.
        let canonical = std::fs::canonicalize(&native).map_err(|error| {
            subshell_error(
                SUBSHELL_EXPORT,
                format!("cannot resolve the export source {path:?}: {error}"),
            )
        })?;
        if !handle.admits_canonical_windows(&canonical) {
            return Err(subshell_error(
                SUBSHELL_EXPORT,
                format!(
                    "{path:?} resolves to {}, outside the handle's admitted scope",
                    canonical.display()
                ),
            ));
        }
        return Ok(native);
    }
    Err(subshell_error(
        SUBSHELL_EXPORT,
        format!("{path:?} is not a Windows path; a guest source is read by the runner"),
    ))
}

/// Validate one guest name as the single Windows path component it will become. A Linux name may
/// hold a backslash, a colon, a control character, or a device name, each of which Windows reads as
/// structure rather than as text; joining such a name would silently build a different path.
#[cfg(windows)]
fn export_component(name: &std::ffi::OsStr) -> std::result::Result<&str, String> {
    let name = name.to_str().ok_or_else(|| {
        "a source name is not Unicode and cannot be represented as a Windows path".to_string()
    })?;
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.ends_with(' ')
        || name.ends_with('.')
        || name.encode_utf16().count() > 255
    {
        return Err(format!(
            "{name:?} is not a safe Windows file name: empty, relative, too long, or ending in a \
             dot or space"
        ));
    }
    if name.chars().any(|character| {
        character.is_control()
            || matches!(
                character,
                '\\' | '/' | ':' | '*' | '?' | '"' | '<' | '>' | '|'
            )
    }) {
        return Err(format!(
            "{name:?} is not a safe Windows file name: it contains a reserved character"
        ));
    }
    let stem = name.split('.').next().unwrap_or(name).trim_end();
    let numbered = |prefix: &str| {
        stem.len() == prefix.len() + 1
            && stem
                .get(..prefix.len())
                .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
            && stem.get(prefix.len()..).is_some_and(|tail| {
                // Windows reserves the device names with a digit, and the superscript digits too:
                // `COM¹` names the COM1 device as surely as `COM1` does.
                matches!(
                    tail,
                    "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
                )
            })
    };
    if matches!(
        stem.to_ascii_uppercase().as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$" | "CLOCK$"
    ) || numbered("COM")
        || numbered("LPT")
    {
        return Err(format!(
            "{name:?} is a reserved Windows device name and cannot be an exported file"
        ));
    }
    Ok(name)
}

/// Record one destination and refuse a second source that differs only in case. NTFS resolves
/// those names to one file, so planning both would copy one over the other.
#[cfg(windows)]
fn claim_export_target(
    plan: &mut ExportPlan,
    target: &std::path::Path,
) -> std::result::Result<(), String> {
    let key = target.as_os_str().to_string_lossy().to_lowercase();
    if !plan.seen.insert(key) {
        return Err(format!(
            "{} names the same Windows destination as an earlier source; two sources that differ \
             only in case would overwrite each other",
            target.display()
        ));
    }
    Ok(())
}

/// Refuse, before the first byte moves, a destination that cannot take the planned tree: an
/// existing file where a directory is needed, a directory where a file is needed, or a reparse
/// point at either. The copy repeats these checks on the handles it opens; this pass is what keeps
/// a late refusal from leaving earlier files behind.
#[cfg(windows)]
fn preflight_export(plan: &ExportPlan) -> std::result::Result<(), String> {
    for directory in &plan.directories {
        if std::fs::symlink_metadata(directory).is_ok() {
            check_real_directory(directory)?;
        }
        preflight_export_ancestors(&plan.root, directory)?;
    }
    for (_, target) in &plan.files {
        match std::fs::symlink_metadata(target) {
            Ok(metadata) => {
                if metadata.file_attributes() & 0x400 != 0 {
                    return Err(format!(
                        "{} is a symlink or reparse point; nothing is written through one",
                        target.display()
                    ));
                }
                if metadata.is_dir() {
                    return Err(format!(
                        "{} is a directory; the source is a file",
                        target.display()
                    ));
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(format!("cannot read {}: {error}", target.display())),
        }
        preflight_export_ancestors(&plan.root, target)?;
    }
    Ok(())
}

/// Check every existing directory between the admitted root and `target`, stopping at the first
/// component that does not exist yet. The copy creates those levels one by one.
#[cfg(windows)]
fn preflight_export_ancestors(
    root: &std::path::Path,
    target: &std::path::Path,
) -> std::result::Result<(), String> {
    let relative = target.strip_prefix(root).map_err(|_| {
        format!(
            "{} is outside the export destination {}",
            target.display(),
            root.display()
        )
    })?;
    check_real_directory(root)?;
    let mut components = relative.components().peekable();
    let mut current = root.to_path_buf();
    while let Some(component) = components.next() {
        if components.peek().is_none() {
            break;
        }
        if !matches!(component, std::path::Component::Normal(_)) {
            return Err(format!("invalid export path: {}", target.display()));
        }
        current.push(component);
        match std::fs::symlink_metadata(&current) {
            Ok(_) => check_real_directory(&current)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(error) => return Err(format!("cannot read {}: {error}", current.display())),
        }
    }
    Ok(())
}

/// Refuse a destination name that is already taken, or that is not a name a fresh file can be
/// created under.
///
/// Only absence is publishable. No supported provider here can bind the bytes a destination held at
/// plan time to the object a later rename would replace, so "replace this file" is refused now
/// rather than attempted optimistically at commit. The caller exports to a fresh name.
#[cfg(windows)]
fn planned_destination(target: &std::path::Path) -> Result<()> {
    match std::fs::symlink_metadata(target) {
        Ok(metadata) => {
            if metadata.file_attributes() & 0x400 != 0 {
                return Err(subshell_error(
                    SUBSHELL_EXPORT,
                    format!(
                        "{} is a symlink or reparse point; nothing is written through one",
                        target.display()
                    ),
                ));
            }
            if metadata.is_dir() {
                return Err(subshell_error(
                    SUBSHELL_EXPORT,
                    format!("{} is a directory; the source is a file", target.display()),
                ));
            }
            Err(subshell_error(
                SUBSHELL_EXPORT,
                format!(
                    "{} already exists at the destination; export to a new name",
                    target.display()
                ),
            ))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(subshell_error(
            SUBSHELL_EXPORT,
            format!("cannot read {}: {error}", target.display()),
        )),
    }
}

/// Add one source subtree to the plan: the files to copy and the directories to create, refusing
/// any entry that is a symlink and any destination name already taken.
#[cfg(windows)]
fn collect_export(
    source: &std::path::Path,
    target: &std::path::Path,
    plan: &mut ExportPlan,
) -> Result<()> {
    let name = target.file_name().ok_or_else(|| {
        subshell_error(
            SUBSHELL_EXPORT,
            format!("{} has no file name", target.display()),
        )
    })?;
    export_component(name).map_err(|detail| subshell_error(SUBSHELL_EXPORT, detail))?;
    claim_export_target(plan, target).map_err(|detail| subshell_error(SUBSHELL_EXPORT, detail))?;
    let metadata = std::fs::symlink_metadata(source).map_err(|error| {
        subshell_error(
            SUBSHELL_EXPORT,
            format!("cannot read {}: {error}", source.display()),
        )
    })?;
    if metadata.file_attributes() & 0x400 != 0 {
        return Err(subshell_error(
            SUBSHELL_EXPORT,
            format!(
                "{} is a symlink or reparse point; export sources must be real paths",
                source.display()
            ),
        ));
    }
    if !metadata.is_dir() {
        if !metadata.is_file() {
            return Err(subshell_error(
                SUBSHELL_EXPORT,
                format!(
                    "{} is not a regular file or directory; nothing else is exported",
                    source.display()
                ),
            ));
        }
        planned_destination(target)?;
        let links = crate::fs::hard_link_count(source).map_err(|error| {
            subshell_error(
                SUBSHELL_EXPORT,
                format!("cannot read {}: {error}", source.display()),
            )
        })?;
        if links > 1 {
            return Err(subshell_error(
                SUBSHELL_EXPORT,
                format!(
                    "{} has {links} hard links; exporting a file another name can change would \
                     not be the file the plan admitted",
                    source.display()
                ),
            ));
        }
        plan.files
            .push((PlannedSource::Native(source.to_owned()), target.to_owned()));
        return Ok(());
    }
    plan.directories.push(target.to_owned());
    for entry in std::fs::read_dir(source).map_err(|error| {
        subshell_error(
            SUBSHELL_EXPORT,
            format!("cannot read {}: {error}", source.display()),
        )
    })? {
        let entry = entry.map_err(|error| {
            subshell_error(
                SUBSHELL_EXPORT,
                format!("cannot read {}: {error}", source.display()),
            )
        })?;
        collect_export(&entry.path(), &target.join(entry.file_name()), plan)?;
    }
    Ok(())
}

#[derive(Debug)]
enum CommandTreeError {
    Interrupted,
    Wait(std::io::Error),
}

/// Which program the command under the collector is: a local command, whose exit status is the
/// call's outcome; the SSH client, whose status 255 is its own failure rather than a remote exit
/// and whose termination leaves the remote side unaccounted for; or a WSL launcher, whose end says
/// nothing about the guest namespace behind it.
#[derive(Clone, Copy, PartialEq, Eq)]
enum CommandRoute {
    Native,
    Ssh,
    #[cfg_attr(
        not(windows),
        allow(dead_code, reason = "only the Windows host starts a WSL launcher")
    )]
    Wsl,
}

async fn run_command_tree(
    child: crate::process::Tree,
    timeout: std::time::Duration,
    context: &crate::tools::ToolContext,
) -> std::result::Result<ToolOutput, CommandTreeError> {
    run_command_tree_route(
        child,
        None,
        timeout,
        context,
        CommandRoute::Native,
        None,
        None,
    )
    .await
}

/// [`run_command_tree`] for the SSH client. The client's own failures and the remote command's
/// outcome share a wait and a capture, but not a meaning, so the result says which one it saw.
async fn run_ssh_command_tree(
    child: crate::process::Tree,
    timeout: std::time::Duration,
    context: &crate::tools::ToolContext,
    lease: &crate::permission::PermissionLease,
) -> std::result::Result<ToolOutput, CommandTreeError> {
    run_command_tree_route(
        child,
        None,
        timeout,
        context,
        CommandRoute::Ssh,
        Some(lease),
        None,
    )
    .await
}

/// What asked a managed launcher or client to stop.
#[derive(Clone, Copy)]
enum StopCause {
    Turn,
    Lease,
    Handle,
}

/// Run one managed WSL command to its end, watching every authority that can end it.
///
/// The launcher belongs to one call: a turn stop, a permission downgrade and a handle close all
/// end it through the collector rather than by dropping the wait, so what the guest printed before
/// the stop is still captured and the result states what was and was not observed. The start
/// permit is committed here at the guest's readiness, under the authority the call was admitted
/// at, and every stop is a withdrawal first and a kill only when the guest's terminal proof does
/// not arrive within the teardown grace.
#[cfg(windows)]
async fn run_wsl_command_tree(
    child: crate::process::Tree,
    op: &str,
    required: Permission,
    timeout: std::time::Duration,
    context: &crate::tools::ToolContext,
    lease: &crate::permission::PermissionLease,
    closed: Option<&tokio_util::sync::CancellationToken>,
) -> std::result::Result<ToolOutput, CommandTreeError> {
    run_command_tree_route(
        child,
        Some(WslRun {
            op: op.to_owned(),
            required,
        }),
        timeout,
        context,
        CommandRoute::Wsl,
        Some(lease),
        closed,
    )
    .await
}

async fn run_command_tree_route(
    child: crate::process::Tree,
    wsl: Option<WslRun>,
    timeout: std::time::Duration,
    context: &crate::tools::ToolContext,
    route: CommandRoute,
    lease: Option<&crate::permission::PermissionLease>,
    closed: Option<&tokio_util::sync::CancellationToken>,
) -> std::result::Result<ToolOutput, CommandTreeError> {
    let stop = tokio_util::sync::CancellationToken::new();
    let budget = Arc::new(crate::process::OutputBudget::new(MAX_OUTPUT_BYTES));
    let relay = OutputRelay::for_call(context);
    #[cfg(windows)]
    let mut relay = relay;
    #[cfg_attr(
        not(windows),
        allow(
            unused_mut,
            reason = "the Windows controller takes the launcher's stdin"
        )
    )]
    let mut child = child;
    let managed = wsl.is_some();
    // One owner for a managed launch's whole life: the route holds the launcher's stdin (the
    // guest's lifetime signal), answers the guest's readiness through the commit gate, and turns
    // every stop authority into a withdrawal first and a kill only when the guest does not answer
    // with its terminal proof.
    #[cfg(windows)]
    let (frames, mut guest) = match wsl {
        Some(run) => {
            let (ready_tx, ready_rx) = tokio::sync::mpsc::channel(1);
            let permit = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let frames = Arc::new(CommandFrames::new(
                run.op,
                Arc::clone(&budget),
                stop.clone(),
                relay.take(),
                ready_tx,
                Arc::clone(&permit),
            ));
            let input = child.take_lease_input();
            let (writes, written) = tokio::sync::mpsc::channel::<LeaseWrite>(2);
            // The writer detaches with its channel: it ends when the route drops the sender, and
            // its last act is the hangup that withdraws from the guest.
            drop(input.map(|input| tokio::spawn(lease_writer(input, written))));
            let guest = GuestChannel {
                writes: Some(writes),
                permit,
                ready: ready_rx,
                decided: false,
                required: run.required,
            };
            (Some(frames), Some(guest))
        }
        None => (None, None),
    };
    #[cfg(not(windows))]
    let mut guest: Option<()> = {
        drop(wsl);
        None
    };
    let capture = {
        #[cfg(windows)]
        if let Some(frames) = &frames {
            crate::process::Capture {
                stdout: crate::process::Keep::Head(0),
                stderr: crate::process::Keep::Head(8 * crate::text::KIB),
                sink: Some(frames.clone() as Arc<dyn crate::process::Sink>),
            }
        } else {
            command_capture(&budget, relay)
        }
        #[cfg(not(windows))]
        {
            command_capture(&budget, relay)
        }
    };
    // A managed launcher answers its own end to the host's deadline and every stop: the route
    // withdraws first, so the run keeps no timeout of its own and kills the tree only at the
    // backstop after the teardown grace. The other routes keep the collector's own timeout.
    let run_timeout = if managed { None } else { Some(timeout) };
    let running = crate::process::run(
        child,
        capture,
        run_timeout,
        Some(crate::process::Stop::Graceful(&stop)),
        DRAIN_TIMEOUT,
    );
    tokio::pin!(running);
    // A route whose transport has no boundary of its own watches the authority that admitted it
    // and the handle that owns it beside the turn. The first cause to fire is the one reported;
    // the collector keeps running until the command has ended and its output has been taken.
    let started = tokio::time::Instant::now();
    let deadline = started + timeout;
    let mut stopped_by = None;
    let mut deadline_hit = false;
    let mut withdraw_at: Option<tokio::time::Instant> = None;
    let finished = loop {
        let teardown_wait = async {
            match withdraw_at {
                Some(at) => tokio::time::sleep_until(at).await,
                None => std::future::pending().await,
            }
        };
        tokio::select! {
            biased;
            result = &mut running => break result.map_err(CommandTreeError::Wait)?,
            () = context.cancellation.cancelled(), if stopped_by.is_none() => {
                stopped_by = Some(StopCause::Turn);
                withdraw_at = Some(withdraw_guest(&mut guest));
            }
            () = until_revoked(lease), if stopped_by.is_none() => {
                stopped_by = Some(StopCause::Lease);
                withdraw_at = Some(withdraw_guest(&mut guest));
            }
            () = until_closed(closed), if stopped_by.is_none() => {
                stopped_by = Some(StopCause::Handle);
                withdraw_at = Some(withdraw_guest(&mut guest));
            }
            notice = guest_ready(&mut guest) => {
                if notice {
                    commit_permit(
                        &mut guest,
                        lease,
                        timeout.saturating_sub(started.elapsed()),
                    );
                }
            }
            () = teardown_wait, if withdraw_at.is_some() => {
                // The guest did not answer the withdrawal with its terminal proof in time. What
                // the local kill establishes is only the launcher's end; the record says so.
                withdraw_at = None;
                stop.cancel();
            }
            () = tokio::time::sleep_until(deadline), if managed && !deadline_hit && stopped_by.is_none() => {
                deadline_hit = true;
                withdraw_at = Some(withdraw_guest(&mut guest));
            }
        }
    };
    #[cfg(windows)]
    if route == CommandRoute::Wsl {
        return wsl_route_result(
            finished,
            &frames,
            context,
            stopped_by,
            deadline_hit,
            timeout,
            &budget,
        )
        .await;
    }
    let drained = DrainedOutput::from(finished.drained);
    match (route, finished.ended) {
        (_, crate::process::Ended::Stopped) => {
            if let Some(observation) = &context.teardown {
                // A local client or launcher reaped is the only thing this end observed. The SSH
                // client's remote command is beyond it.
                observation.note(route == CommandRoute::Native && finished.local_exit.is_some());
            }
            match (route, stopped_by) {
                (_, Some(StopCause::Turn)) | (_, None) => Err(CommandTreeError::Interrupted),
                (CommandRoute::Ssh, Some(StopCause::Lease)) => Ok(killed_command_output(
                    &drained,
                    &ssh_stopped_reason("Permission was lowered; the SSH call was stopped"),
                )),
                (CommandRoute::Native, Some(StopCause::Lease | StopCause::Handle)) => {
                    Err(CommandTreeError::Interrupted)
                }
                (CommandRoute::Ssh, Some(StopCause::Handle)) => Err(CommandTreeError::Interrupted),
                (CommandRoute::Wsl, Some(StopCause::Lease | StopCause::Handle)) => {
                    Err(CommandTreeError::Wait(std::io::Error::other(
                        "a managed WSL run must end through its own result path",
                    )))
                }
            }
        }
        (CommandRoute::Ssh, crate::process::Ended::OutputBound) => Ok(killed_command_output(
            &drained,
            &ssh_stopped_reason(&output_bound_reason()),
        )),
        (CommandRoute::Ssh, crate::process::Ended::TimedOut) => Ok(killed_command_output(
            &drained,
            &ssh_timed_out_reason(timeout, &budget),
        )),
        (CommandRoute::Native, crate::process::Ended::OutputBound) => {
            Ok(killed_command_output(&drained, &output_bound_reason()))
        }
        (CommandRoute::Native, crate::process::Ended::TimedOut) => Ok(killed_command_output(
            &drained,
            &timed_out_reason(timeout, &budget),
        )),
        (CommandRoute::Ssh, crate::process::Ended::Exited(status))
            if status.code() == Some(255) =>
        {
            Ok(led_by_reason(&drained, ssh_client_failure_reason()))
        }
        (
            CommandRoute::Wsl,
            crate::process::Ended::OutputBound | crate::process::Ended::TimedOut,
        ) => Err(CommandTreeError::Wait(std::io::Error::other(
            "a managed WSL run must end through its own result path",
        ))),
        (_, crate::process::Ended::Exited(status)) => {
            Ok(finish_command(&status, &drained, &budget))
        }
    }
}

/// Until the lease is revoked; never, when this route holds none.
async fn until_revoked(lease: Option<&crate::permission::PermissionLease>) {
    match lease {
        Some(lease) => lease.revoked().await,
        None => std::future::pending().await,
    }
}

/// Until `closed` fires; never, when the caller has no handle to watch.
async fn until_closed(closed: Option<&tokio_util::sync::CancellationToken>) {
    match closed {
        Some(closed) => closed.cancelled().await,
        None => std::future::pending().await,
    }
}

/// What a managed WSL run is: the operation every control frame must echo, and the level the call
/// was admitted at. The start permit commits only while that authority still holds, so the level
/// preserved is the one that admitted the call, not whatever the session reads later.
#[cfg_attr(
    not(windows),
    allow(dead_code, reason = "the Windows controller owns managed launches")
)]
struct WslRun {
    op: String,
    required: Permission,
}

/// How long a stopped managed WSL run is given to answer the host's withdrawal with its terminal
/// proof before the local launcher is torn down anyway. The withdrawal asks the guest to end the
/// namespace and reap it; the grace is what the question gets before the answer stops mattering.
#[cfg(windows)]
const TEARDOWN_GRACE: std::time::Duration = std::time::Duration::from_secs(3);

/// What one write to a managed launcher's stdin means. The permit is the only thing ever written
/// after the request; hanging up the pipe is the withdrawal.
#[cfg(windows)]
enum LeaseWrite {
    /// The start permit line: the remaining budget of the one deadline, in milliseconds.
    Permit(String),
}

/// The launcher's stdin, held by one writer task. Everything the host writes to the guest goes
/// through the channel, so no lock ever sits across pipe I/O and the commit that authorizes a
/// start is a synchronous step.
#[cfg(windows)]
struct GuestChannel {
    /// Dropping the sender ends the writer's loop and with it the launcher's stdin: the hangup is
    /// the withdrawal the guest reads.
    writes: Option<tokio::sync::mpsc::Sender<LeaseWrite>>,
    /// Set in the same synchronous step that commits the start permit, so `Started` before the
    /// commit is a protocol failure rather than a race.
    permit: Arc<std::sync::atomic::AtomicBool>,
    /// The guest's readiness notice, at most one.
    ready: tokio::sync::mpsc::Receiver<()>,
    /// The commit decision was made: grant or deny, once.
    decided: bool,
    /// The authority the permit commits under.
    required: Permission,
}

#[cfg(windows)]
async fn lease_writer(
    mut input: tokio::process::ChildStdin,
    mut writes: tokio::sync::mpsc::Receiver<LeaseWrite>,
) {
    use tokio::io::AsyncWriteExt as _;

    while let Some(LeaseWrite::Permit(line)) = writes.recv().await {
        if input.write_all(line.as_bytes()).await.is_err() {
            break;
        }
    }
    // Dropping the input hangs up the launcher's stdin, which the guest reads as the host's
    // withdrawal and answers by tearing its namespace down and reaping it.
}

/// The guest's readiness notice: the route answers it through the commit gate. Once the decision
/// is made this pends, so the select arm cannot fire twice.
#[cfg(windows)]
async fn guest_ready(guest: &mut Option<GuestChannel>) -> bool {
    let Some(ready) = guest.as_mut().filter(|guest| !guest.decided) else {
        std::future::pending::<()>().await;
        return false;
    };
    ready.ready.recv().await.is_some()
}

/// See the Windows definition: a platform with no managed launcher has nothing to wait for.
#[cfg(not(windows))]
async fn guest_ready(_guest: &mut Option<()>) -> bool {
    std::future::pending::<()>().await;
    false
}

/// Withdraw from the guest and return when the teardown grace for its terminal proof ends. A
/// route with no managed launcher has nothing to ask: its grace is already over, and the kill it
/// backs is the only end it can establish.
#[cfg(windows)]
fn withdraw_guest(guest: &mut Option<GuestChannel>) -> tokio::time::Instant {
    let now = tokio::time::Instant::now();
    if let Some(guest) = guest.as_mut() {
        // Dropping the sender ends the writer's loop and with it the launcher's stdin: the hangup
        // is the withdrawal the guest reads.
        drop(guest.writes.take());
        return now + TEARDOWN_GRACE;
    }
    now
}

/// See the Windows definition: a platform with no managed launcher withdraws from nothing.
#[cfg(not(windows))]
fn withdraw_guest(_guest: &mut Option<()>) -> tokio::time::Instant {
    tokio::time::Instant::now()
}

/// The one synchronous step that decides a start. Under the lease's own setter locks, enqueue the
/// permit and mark it committed, or refuse: a downgrade or stop that won before the commit cannot
/// be overtaken, and one landing after it is supervised like any later stop. The permit carries
/// the one deadline's remaining budget, so what the launch spent is not the guest's to spend.
#[cfg(windows)]
fn commit_permit(
    guest: &mut Option<GuestChannel>,
    lease: Option<&crate::permission::PermissionLease>,
    budget: std::time::Duration,
) {
    let Some(guest) = guest.as_mut() else {
        return;
    };
    use std::sync::atomic::Ordering;

    guest.decided = true;
    let line = crate::subshell::permit_line(budget);
    let granted = {
        let permit = &guest.permit;
        let writes = guest.writes.as_ref();
        let commit = || {
            let Some(writes) = writes else {
                return false;
            };
            // The flag turns before the line can reach the guest, so a `Started` frame can never
            // outrun the commit it must match; a failed enqueue turns it back, and a guest that
            // could see it then cannot exist because no permit line was ever sent.
            permit.store(true, Ordering::Release);
            if writes.try_send(LeaseWrite::Permit(line.clone())).is_err() {
                permit.store(false, Ordering::Release);
                return false;
            }
            true
        };
        match lease {
            // The commit runs under the lease's own setter locks, so a downgrade or stop that won
            // before it cannot be overtaken.
            Some(lease) => lease
                .with_current_authority(guest.required, commit)
                .unwrap_or(false),
            // A route that holds no lease has nothing to re-check: the commit is the enqueue.
            None => commit(),
        }
    };
    if !granted {
        drop(guest.writes.take());
    }
}

/// See the Windows definition: a platform with no managed launcher permits no start.
#[cfg(not(windows))]
fn commit_permit(
    _guest: &mut Option<()>,
    _lease: Option<&crate::permission::PermissionLease>,
    _budget: std::time::Duration,
) {
}

/// What stopping or ending a managed WSL launch established, in the three shapes the record may
/// take: the guest reported the reaped namespace, the command never started, or the end is
/// unconfirmed. The host never derives the guest's end from the launcher's.
#[cfg(windows)]
fn wsl_end_reason(reason: &str, end: GuestEnd) -> String {
    match (end.started, end.stopped) {
        (false, _) => format!(
            "{reason}\nThe managed WSL command was never started: no start permit was acknowledged"
        ),
        (true, Some(code)) => format!(
            "{reason}\nThe guest reported the command was reaped and its namespace torn down \
             (status {code})"
        ),
        (true, None) => format!(
            "{reason}\nThe guest namespace's end is unconfirmed: the local launcher's end does \
             not confirm it"
        ),
    }
}

/// One managed WSL run's result, from what the guest's own frames proved and what the launcher's
/// end did. The three shapes of [`wsl_end_reason`] are the whole vocabulary here, and the guest's
/// reserved exit codes reconcile a launcher status with the outcome the runner reported.
#[cfg(windows)]
async fn wsl_route_result(
    finished: crate::process::Finished,
    frames: &Option<Arc<CommandFrames>>,
    context: &crate::tools::ToolContext,
    stopped_by: Option<StopCause>,
    deadline_hit: bool,
    timeout: std::time::Duration,
    budget: &crate::process::OutputBudget,
) -> std::result::Result<ToolOutput, CommandTreeError> {
    let Some(frames) = frames else {
        return Err(CommandTreeError::Wait(std::io::Error::other(
            "a managed WSL run without its command stream is a bug in the route",
        )));
    };
    if let Some(error) = frames.error().await {
        return Err(CommandTreeError::Wait(std::io::Error::other(format!(
            "the runner's command stream was refused: {error}"
        ))));
    }
    let (drained, end) = match finished.ended {
        // The runner ended on its own: a stream that stops short of its terminal frames is a
        // stale or broken runner, and the host says so instead of presenting its partial output.
        crate::process::Ended::Exited(_) => match frames.outcome().await {
            Ok(parts) => parts,
            Err(error) => {
                // Even a broken stream leaves the record honest: the snapshot says whether a
                // start was ever observed, which is what the teardown note is derived from.
                let (_partial, end) = frames.snapshot().await;
                if let Some(observation) = &context.teardown {
                    observation.note(!end.started || end.stopped.is_some());
                }
                let stderr = String::from_utf8_lossy(&finished.drained.stderr.bytes).into_owned();
                let stderr = stderr.trim();
                return Err(CommandTreeError::Wait(std::io::Error::other(
                    if stderr.is_empty() {
                        format!("the WSL runner ended before a complete command stream: {error}")
                    } else {
                        format!(
                            "the WSL runner ended before a complete command stream: {error}: \
                             {stderr}"
                        )
                    },
                )));
            }
        },
        // The host ended the run: a guest killed before it could report owes no terminal frames,
        // and their absence is the honest record of an unconfirmed end.
        _ => frames.snapshot().await,
    };
    if let Some(observation) = &context.teardown {
        // Nothing running is a confirmed end: a command that never started has nothing left to
        // end, and a guest reap is the guest's own record of one.
        observation.note(!end.started || end.stopped.is_some());
    }
    let reason = |lead: &str| wsl_end_reason(lead, end);
    let guest_cut = frames.output_bound().await;
    if guest_cut && stopped_by.is_none() && !deadline_hit {
        return Ok(killed_command_output(
            &drained,
            &reason(&output_bound_reason()),
        ));
    }
    match (stopped_by, deadline_hit, finished.ended) {
        (Some(StopCause::Turn), ..) => Err(CommandTreeError::Interrupted),
        (Some(StopCause::Lease), ..) => Ok(killed_command_output(
            &drained,
            &reason("Permission was lowered; the managed WSL command was stopped."),
        )),
        (Some(StopCause::Handle), ..) => Ok(killed_command_output(
            &drained,
            &reason("The subshell handle was closed; the managed WSL command was stopped."),
        )),
        (None, true, _) => Ok(killed_command_output(
            &drained,
            &reason(&timed_out_reason(timeout, budget)),
        )),
        (None, false, crate::process::Ended::Exited(status)) => {
            match status.code() {
                Some(code) if code == crate::subshell::RUNNER_TIMED_OUT => Ok(
                    killed_command_output(&drained, &reason(&timed_out_reason(timeout, budget))),
                ),
                Some(code) if code == crate::subshell::RUNNER_CANCELED => {
                    Ok(killed_command_output(
                        &drained,
                        &reason("The managed WSL command was canceled."),
                    ))
                }
                Some(code) if code == crate::subshell::RUNNER_ERROR => {
                    let stderr = String::from_utf8_lossy(&finished.drained.stderr.bytes);
                    let stderr = stderr.trim();
                    Err(CommandTreeError::Wait(std::io::Error::other(
                        if stderr.is_empty() {
                            "the managed WSL runner failed".to_owned()
                        } else {
                            format!("the managed WSL runner failed: {stderr}")
                        },
                    )))
                }
                // A command's own exit: the launcher's status and the reaped outcome the guest
                // reported must agree, or the record says which one the host saw and refuses to
                // present either as the command's exit.
                code => match (code, end.stopped) {
                    (Some(code), Some(reported)) if code == reported => {
                        Ok(finish_command(&status, &drained, budget))
                    }
                    (_, Some(reported)) => {
                        Err(CommandTreeError::Wait(std::io::Error::other(format!(
                            "the WSL launcher exited {status:?} but the runner reported the \
                             command was reaped with status {reported}"
                        ))))
                    }
                    (_, None) => Err(CommandTreeError::Wait(std::io::Error::other(
                        "the WSL runner exited without reporting the command's outcome",
                    ))),
                },
            }
        }
        (None, false, ended) => {
            let lead = match ended {
                crate::process::Ended::OutputBound => output_bound_reason(),
                crate::process::Ended::TimedOut => timed_out_reason(timeout, budget),
                _ => "The managed WSL launcher was stopped.".to_owned(),
            };
            Ok(killed_command_output(&drained, &reason(&lead)))
        }
    }
}

/// Why an SSH call ended before the client reported an exit, with the one fact the local kill
/// cannot establish: what the remote command is doing now.
fn ssh_stopped_reason(reason: &str) -> String {
    format!("{reason}\nThe local SSH client was stopped; the remote command's state is unknown")
}

fn ssh_timed_out_reason(
    timeout: std::time::Duration,
    budget: &crate::process::OutputBudget,
) -> String {
    let mut reason = format!(
        "SSH call timed out after {}ms; the local client was stopped, so the remote command's \
         state is unknown",
        timeout.as_millis()
    );
    if budget.is_exhausted() {
        reason.push('\n');
        reason.push_str(&output_cut_note());
    }
    reason
}

/// What status 255 from `ssh` establishes. The client uses it for its own failures, and a remote
/// command that exits 255 reports the same number, so the outcome is not a confirmed remote exit.
fn ssh_client_failure_reason() -> &'static str {
    "The SSH client exited 255: the client failed, or the remote command exited 255. Meka cannot \
     tell which, so no remote exit status was confirmed"
}

/// The result of a command that ran to its end: its exit status with what the drains collected.
///
/// The drains may still cross the bound after the exit: a child exits once its last write fits in
/// the pipe, so it can finish within a pipe's worth of the bound and leave the crossing to the
/// drains' collection. That output is cut like a killed command's, and the result says so first,
/// because a clean exit code over an incomplete transcript is the one shape the record must never
/// take.
fn finish_command(
    status: &std::process::ExitStatus,
    drained: &DrainedOutput,
    budget: &crate::process::OutputBudget,
) -> ToolOutput {
    if drained.stopped_early {
        tracing::warn!(
            "command output drain stopped after {DRAIN_TIMEOUT:?}; a background process may be \
             holding the pipe open"
        );
    }

    if budget.is_exhausted() {
        let cut = output_cut_note();
        return led_by_reason(drained, &cut).with_metadata(command_exit_metadata(
            status,
            Some(&cut),
            closing_words("", drained.stopped_early),
        ));
    }

    // No output-length truncation here: the agent layer's `persist_oversized_results`
    // auto-persists any oversized result to the scratchpad losslessly. Truncating here would
    // corrupt binary-in-base64 pipelines (see #1 in the trial feedback).
    let exit_code = status.code().unwrap_or(-1);
    let mut output = assemble_command_output(&drained.stdout, &drained.stderr, exit_code);
    if drained.stopped_early {
        append_drain_stopped_note(&mut output);
    }
    output.with_metadata(command_exit_metadata(
        status,
        None,
        closing_words(&exit_words(exit_code), drained.stopped_early),
    ))
}

/// The framed command response the WSL runner writes: control frames and stdout/stderr chunks on
/// one stream. The parser enforces the order (ready, started, output, stopped, done), the operation
/// identifier on every control frame, the payload bound and the shared output budget, and hands
/// every accepted chunk to the live relay in arrival order. Raw bytes never reach the transcript,
/// so the teardown proof cannot be forged by a command's own output.
///
/// `ready` is where the guest's sandbox proof reaches the route: the guest proved its sandbox and
/// waits for the one line that permits a start. The route answers it through the commit gate, and
/// `Started` is only accepted after that commit, so a permit is never inferred from a start.
#[cfg(windows)]
struct CommandFrames {
    state: tokio::sync::Mutex<CommandFrameState>,
    budget: Arc<crate::process::OutputBudget>,
    stop: tokio_util::sync::CancellationToken,
    relay: Option<OutputRelay>,
    /// The operation every control frame must echo.
    op: String,
    /// Where the readiness notice goes; bounded, and Ready happens at most once.
    ready: tokio::sync::mpsc::Sender<()>,
    /// Set in the same synchronous step that commits the start permit, so `Started` before the
    /// commit is a protocol failure rather than a race.
    permit: Arc<std::sync::atomic::AtomicBool>,
}

#[cfg(windows)]
#[derive(Default)]
struct CommandFrameState {
    buffer: Vec<u8>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    ready: bool,
    started: bool,
    stopped: Option<i32>,
    done: bool,
    error: Option<String>,
    cut: bool,
}

#[cfg(windows)]
impl CommandFrames {
    fn new(
        op: String,
        budget: Arc<crate::process::OutputBudget>,
        stop: tokio_util::sync::CancellationToken,
        relay: Option<OutputRelay>,
        ready: tokio::sync::mpsc::Sender<()>,
        permit: Arc<std::sync::atomic::AtomicBool>,
    ) -> Self {
        Self {
            state: tokio::sync::Mutex::new(CommandFrameState::default()),
            budget,
            stop,
            relay,
            op,
            ready,
            permit,
        }
    }

    /// Parse every complete frame in `chunk`, relaying accepted output after the lock is released.
    async fn push(&self, chunk: &[u8]) {
        use std::sync::atomic::Ordering;

        let mut state = self.state.lock().await;
        if state.error.is_some() {
            return;
        }
        if state.done {
            if !chunk.is_empty() {
                state.error = Some("the runner wrote past its done frame".to_string());
                self.stop.cancel();
            }
            return;
        }
        state.buffer.extend_from_slice(chunk);
        let mut relayed = Vec::new();
        loop {
            let Some(newline) = state.buffer.iter().position(|byte| *byte == b'\n') else {
                if state.buffer.len() > crate::subshell::FRAME_BYTES {
                    state.error = Some("a command frame exceeded its bound".to_string());
                    self.stop.cancel();
                }
                break;
            };
            if newline > crate::subshell::FRAME_BYTES {
                state.error = Some("a command frame exceeded its bound".to_string());
                self.stop.cancel();
                break;
            }
            let line = state.buffer.get(..newline).unwrap_or_default();
            let frame = match crate::subshell::Frame::decode(line) {
                Ok(frame) => frame,
                Err(error) => {
                    state.error = Some(format!("{error:#}"));
                    self.stop.cancel();
                    break;
                }
            };
            let payload = match &frame {
                crate::subshell::Frame::Output { len, .. } => match usize::try_from(*len) {
                    Ok(len) if len <= crate::subshell::FRAME_BYTES => len,
                    _ => {
                        state.error = Some("a command output frame exceeded its bound".to_string());
                        self.stop.cancel();
                        break;
                    }
                },
                _ => 0,
            };
            if state.buffer.len() < newline + 1 + payload {
                break;
            }
            state.buffer.drain(..=newline);
            let bytes: Vec<u8> = state.buffer.drain(..payload).collect();
            match frame {
                crate::subshell::Frame::Ready { op } => {
                    if op != self.op {
                        state.error = Some("the runner named another operation".to_string());
                        self.stop.cancel();
                        break;
                    }
                    if state.ready || state.started || state.stopped.is_some() || state.done {
                        state.error =
                            Some("the runner reported readiness out of order".to_string());
                        self.stop.cancel();
                        break;
                    }
                    state.ready = true;
                    if self.ready.try_send(()).is_err() {
                        // The route already stopped watching: no permit can authorize this
                        // start, and the teardown path owns the launcher now.
                        state.error = Some(
                            "the runner reported readiness after the host stopped".to_string(),
                        );
                        self.stop.cancel();
                        break;
                    }
                }
                crate::subshell::Frame::Started { op } => {
                    if op != self.op {
                        state.error = Some("the runner named another operation".to_string());
                        self.stop.cancel();
                        break;
                    }
                    if !self.permit.load(Ordering::Acquire) {
                        state.error = Some("the runner started without a start permit".to_string());
                        self.stop.cancel();
                        break;
                    }
                    if !state.ready || state.started || state.stopped.is_some() || state.done {
                        state.error = Some("a command started out of order".to_string());
                        self.stop.cancel();
                        break;
                    }
                    state.started = true;
                }
                crate::subshell::Frame::Output { stream, .. } => {
                    if !state.started || state.stopped.is_some() || state.done {
                        state.error = Some("command output arrived out of order".to_string());
                        self.stop.cancel();
                        break;
                    }
                    let keep = self.budget.spend(bytes.len());
                    match stream {
                        crate::subshell::OutputStream::Stdout => {
                            state.stdout.extend_from_slice(&bytes)
                        }
                        crate::subshell::OutputStream::Stderr => {
                            state.stderr.extend_from_slice(&bytes)
                        }
                    }
                    if !keep {
                        state.cut = true;
                        self.stop.cancel();
                        break;
                    }
                    relayed.push((
                        match stream {
                            crate::subshell::OutputStream::Stdout => crate::process::Stream::Stdout,
                            crate::subshell::OutputStream::Stderr => crate::process::Stream::Stderr,
                        },
                        bytes,
                    ));
                }
                crate::subshell::Frame::Stopped { op, code } => {
                    if op != self.op {
                        state.error = Some("the runner named another operation".to_string());
                        self.stop.cancel();
                        break;
                    }
                    if !state.started || state.stopped.is_some() || state.done {
                        state.error = Some("a command stopped out of order".to_string());
                        self.stop.cancel();
                        break;
                    }
                    state.stopped = Some(code);
                }
                crate::subshell::Frame::Done { op } => {
                    if op != self.op {
                        state.error = Some("the runner named another operation".to_string());
                        self.stop.cancel();
                        break;
                    }
                    if state.stopped.is_none() || state.done {
                        state.error = Some("a command finished out of order".to_string());
                        self.stop.cancel();
                        break;
                    }
                    state.done = true;
                }
                _ => {
                    state.error = Some("a transfer frame arrived on a command stream".to_string());
                    self.stop.cancel();
                    break;
                }
            }
        }
        drop(state);
        if let Some(relay) = &self.relay {
            for (stream, bytes) in relayed {
                crate::process::Sink::receive(relay, stream, &bytes).await;
            }
        }
    }

    /// What the parser accepted and what the guest proved. A stream that ends before an observed
    /// start owes no terminal frames and is a complete answer of its own: the command never
    /// started. A stream that started and then ended before its terminal frames, or that carries
    /// a protocol failure, is refused: the host reports a failed transfer-like end rather than
    /// presenting partial output as a normal command result.
    async fn outcome(&self) -> std::result::Result<(DrainedOutput, GuestEnd), String> {
        let state = self.state.lock().await;
        if let Some(error) = &state.error {
            return Err(error.clone());
        }
        if state.done {
            if !state.buffer.is_empty() {
                return Err("the runner ended mid-frame".to_string());
            }
            return Ok((state.drained(), state.guest_end()));
        }
        if !state.started {
            return Ok((state.drained(), state.guest_end()));
        }
        drop(state);
        Err("the runner ended before its terminal frames".to_string())
    }

    /// What the parser accepted and what the guest proved, for a run the host ended itself: the
    /// missing terminal frames of a guest that was killed before it could report are the record,
    /// not a stream failure.
    async fn snapshot(&self) -> (DrainedOutput, GuestEnd) {
        let state = self.state.lock().await;
        (state.drained(), state.guest_end())
    }

    async fn output_bound(&self) -> bool {
        self.state.lock().await.cut
    }

    async fn error(&self) -> Option<String> {
        self.state.lock().await.error.clone()
    }
}

#[cfg(windows)]
impl CommandFrameState {
    fn drained(&self) -> DrainedOutput {
        DrainedOutput {
            stdout: String::from_utf8_lossy(&self.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&self.stderr).into_owned(),
            stopped_early: false,
        }
    }

    fn guest_end(&self) -> GuestEnd {
        GuestEnd {
            started: self.started,
            stopped: self.stopped,
        }
    }
}

/// What the guest's own frames proved about a managed WSL command and its namespace.
///
/// The host never derives the guest's end from the launcher's: `stopped` is what the guest
/// reported after it tore its namespace down and reaped it, which it does on cancellation and
/// timeout as well as on a normal exit. Its absence is the record's honest answer, not a gap to
/// paper over.
#[cfg(windows)]
#[derive(Clone, Copy, Debug)]
struct GuestEnd {
    /// The guest acknowledged the start permit with an observed start.
    started: bool,
    /// The reaped namespace's exit status, when the guest reported one.
    stopped: Option<i32>,
}

#[cfg(windows)]
#[async_trait]
impl crate::process::Sink for CommandFrames {
    async fn receive(&self, stream: crate::process::Stream, chunk: &[u8]) {
        if stream == crate::process::Stream::Stdout {
            self.push(chunk).await;
        }
    }
}

/// What a command's drains keep: every byte of both streams, within `budget`, relayed to the
/// call's live view when one is open.
fn command_capture(
    budget: &Arc<crate::process::OutputBudget>,
    relay: Option<OutputRelay>,
) -> crate::process::Capture {
    crate::process::Capture {
        stdout: crate::process::Keep::Budgeted(Arc::clone(budget)),
        stderr: crate::process::Keep::Budgeted(Arc::clone(budget)),
        sink: relay.map(|relay| Arc::new(relay) as Arc<dyn crate::process::Sink>),
    }
}

/// The failure of waiting on a command that was started.
fn wait_failed(error: std::io::Error) -> MekaError {
    MekaError::ToolExecution {
        tool_name: "shell_execute".to_string(),
        message: format!("failed to wait for command: {error}"),
    }
}

/// The result of a command Meka killed, at its timeout or at the output bound: the reason, then
/// everything it printed up to the kill. A frontend rendering a terminal shows "terminated" rather
/// than an exit code.
fn killed_command_output(drained: &DrainedOutput, reason: &str) -> ToolOutput {
    led_by_reason(drained, reason).with_metadata(killed_exit_metadata(
        reason,
        closing_words("", drained.stopped_early),
    ))
}

/// A failed result that states `reason` first and carries what the command printed after it.
///
/// The reason leads because the output can be 64 MiB and every surface shows a result's head (the
/// scratchpad preview, a background outcome, the screen banner), so a reason at the end would be
/// the one line nobody reads; the record holds all of it either way.
fn led_by_reason(drained: &DrainedOutput, reason: &str) -> ToolOutput {
    let mut text = reason.to_string();
    let printed = join_streams(&drained.stdout, &drained.stderr);
    if !printed.is_empty() {
        text.push('\n');
        text.push_str(&printed);
    }
    let mut output = ToolOutput::text(text, true);
    if drained.stopped_early {
        append_drain_stopped_note(&mut output);
    }
    output
}

/// Why a command was killed at its timeout, in the words the model and every test read. When the
/// drains also reached the bound while the command died, the result says that too, since the
/// transcript is then cut as well as ended.
fn timed_out_reason(timeout: std::time::Duration, budget: &crate::process::OutputBudget) -> String {
    let mut reason = format!("Command timed out after {}ms", timeout.as_millis());
    if budget.is_exhausted() {
        reason.push('\n');
        reason.push_str(&output_cut_note());
    }
    reason
}

/// Why a command was killed at the output bound. Names the bound, so the model reruns with a
/// narrower command rather than a longer timeout.
fn output_bound_reason() -> String {
    format!(
        "Command stopped: its output exceeded {}",
        crate::text::format_size(MAX_OUTPUT_BYTES)
    )
}

/// What a result says when the output reached the bound while the command was ending for another
/// reason, or on its own: the transcript stops there, whatever the exit status says.
fn output_cut_note() -> String {
    format!(
        "Output exceeded {}; what the command printed past that point is not included",
        crate::text::format_size(MAX_OUTPUT_BYTES)
    )
}

/// The refusal for a command admitted at a level that confines it when no backend can: it fails
/// toward not running, never toward a plain `sh -c`.
fn unconfinable_command() -> MekaError {
    MekaError::ToolExecution {
        tool_name: "shell_execute".to_string(),
        message: "cannot confine the command: no sandbox backend is available at this level"
            .to_string(),
    }
}

/// Upper bound on draining a child's stdout/stderr after it has exited or been killed. A
/// backgrounded grandchild that inherited the pipe write handle can keep the pipe open past the
/// direct child's exit; rather than block the tool call, the drains are told to stop and return
/// what they have, and the result says so.
const DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// How long a close waits for the calls it cancelled to return. Comfortably more than a stopped
/// command's drain, and short enough that a wedged guest does not hold the tool call open: past it
/// the close says the teardown is unconfirmed rather than pretending it finished.
#[cfg(windows)]
const CLOSE_WAIT: std::time::Duration = std::time::Duration::from_secs(10);
/// Forwards a running command's output to the frontend as it is produced. The sink of both drains,
/// so stdout and stderr land in one stream in arrival order, which is what a terminal shows.
///
/// A read can end inside a multi-byte character, so what each stream has read and not yet relayed
/// waits here for the read that completes it rather than being relayed as replacement characters.
/// What is relayed still covers the whole stream, so the live view is unaffected by how the reads
/// happened to split, and bytes that are no character at all are relayed as the result spells them.
///
/// `None` when no live view is open on the call, in which case the output is only collected.
struct OutputRelay {
    frontend: Arc<dyn crate::frontend::Frontend>,
    tool_call_id: String,
    stdout_pending: std::sync::Mutex<Vec<u8>>,
    stderr_pending: std::sync::Mutex<Vec<u8>>,
}

impl OutputRelay {
    /// The relay for the call `context` runs, or `None` when no live view is open on it; see
    /// [`crate::tools::ToolContext::live_call_id`].
    fn for_call(context: &crate::tools::ToolContext) -> Option<Self> {
        context.live_call_id().map(|tool_call_id| Self {
            frontend: Arc::clone(&context.frontend),
            tool_call_id: tool_call_id.to_string(),
            stdout_pending: std::sync::Mutex::default(),
            stderr_pending: std::sync::Mutex::default(),
        })
    }

    async fn send(&self, chunk: String) {
        self.frontend
            .emit(crate::frontend::FrontendEvent::ToolCallOutputDelta {
                id: self.tool_call_id.clone(),
                chunk,
            })
            .await;
    }
}

#[async_trait]
impl crate::process::Sink for OutputRelay {
    async fn receive(&self, stream: crate::process::Stream, chunk: &[u8]) {
        let pending = match stream {
            crate::process::Stream::Stdout => &self.stdout_pending,
            crate::process::Stream::Stderr => &self.stderr_pending,
        };
        let text = {
            let mut pending = crate::sync::lock(pending);
            pending.extend_from_slice(chunk);
            let (text, taken) = relayable(&pending);
            pending.drain(..taken);
            text
        };
        if !text.is_empty() {
            self.send(text).await;
        }
    }
}

/// How much a command may print, stdout and stderr together, before Meka stops it.
///
/// Every byte under the bound is kept: in memory while the command runs, then in the scratchpad
/// when the result is too large for the conversation. So a bound is the only thing standing between
/// a command that writes faster than the turn ends (`cat /dev/zero`, a runaway build log) and the
/// process going down with it. Reaching it kills the command and says so, the way the timeout does,
/// rather than dropping part of what was printed: an elided middle is a hole in the record for the
/// operator and the agent alike, and a stopped command is something the agent can rerun narrower.
///
/// Above the largest legitimate outputs measured (a whole `git log -p`, an `ls -lR /usr`, both in
/// the tens of MiB) and well below the runaway cases.
const MAX_OUTPUT_BYTES: usize = 64 * crate::text::MIB;

/// The text of `pending` that can be relayed now and the bytes it covers: every complete
/// character, and U+FFFD for each sequence that can never become one, as a lossy decode of the
/// whole stream spells it. A sequence the next read may still complete is left behind; one that
/// is invalid is stepped over, since waiting on it would hold back everything after it.
fn relayable(pending: &[u8]) -> (String, usize) {
    let mut text = String::new();
    let mut taken = 0;
    loop {
        let rest = pending.get(taken..).unwrap_or_default();
        let error = match std::str::from_utf8(rest) {
            Ok(valid) => {
                text.push_str(valid);
                return (text, taken + valid.len());
            }
            Err(error) => error,
        };
        let valid = error.valid_up_to();
        // A verified-UTF-8 prefix, so the lossy decode substitutes nothing; it is the
        // panic-free spelling.
        text.push_str(&String::from_utf8_lossy(
            rest.get(..valid).unwrap_or_default(),
        ));
        taken += valid;
        match error.error_len() {
            Some(invalid) => {
                text.push(char::REPLACEMENT_CHARACTER);
                taken += invalid;
            }
            None => return (text, taken),
        }
    }
}

/// What the two drains returned, and whether they were stopped before the pipes closed.
#[derive(Debug)]
struct DrainedOutput {
    stdout: String,
    stderr: String,
    /// A grandchild kept a pipe open past [`DRAIN_TIMEOUT`], so the drains were told to stop and
    /// anything printed after that is not in `stdout` or `stderr`.
    stopped_early: bool,
}

impl From<crate::process::Drained> for DrainedOutput {
    /// Lossy rather than a hard error: a command that emits a stray non-UTF-8 byte (a progress bar
    /// in a foreign encoding, a binary blob on stderr) should still hand the model everything else
    /// it printed.
    fn from(drained: crate::process::Drained) -> Self {
        Self {
            stdout: String::from_utf8_lossy(&drained.stdout.bytes).into_owned(),
            stderr: String::from_utf8_lossy(&drained.stderr.bytes).into_owned(),
            stopped_early: drained.stopped_early,
        }
    }
}

/// Structured exit status for frontends that render a terminal. `ExitStatus::code()` is `None`
/// exactly when a signal ended the process, so the two are read as alternatives rather than both
/// being guessed from the same number. `reason` is what the result's text opens with when Meka cut
/// the output of a command that then exited on its own, and `closing` what it adds after the
/// output.
fn command_exit_metadata(
    status: &std::process::ExitStatus,
    reason: Option<&str>,
    closing: Option<String>,
) -> crate::frontend::ToolOutputMetadata {
    #[cfg(unix)]
    let signal = {
        use std::os::unix::process::ExitStatusExt;
        status.signal().map(signal_name)
    };
    #[cfg(not(unix))]
    let signal = None;
    crate::frontend::ToolOutputMetadata::CommandExit {
        exit_code: status.code(),
        signal,
        reason: reason.map(str::to_string),
        closing,
    }
}

/// Symbolic name for the signals a command realistically dies from. The number alone would render
/// as `SIG9` in a client's terminal UI next to a `SIGKILL` we report elsewhere for the same kill,
/// so the two paths have to agree. Numbers outside this set are stable enough nowhere to name.
#[cfg(unix)]
fn signal_name(number: i32) -> String {
    match number {
        libc::SIGHUP => "SIGHUP".to_string(),
        libc::SIGINT => "SIGINT".to_string(),
        libc::SIGQUIT => "SIGQUIT".to_string(),
        libc::SIGABRT => "SIGABRT".to_string(),
        libc::SIGKILL => "SIGKILL".to_string(),
        libc::SIGSEGV => "SIGSEGV".to_string(),
        libc::SIGPIPE => "SIGPIPE".to_string(),
        libc::SIGTERM => "SIGTERM".to_string(),
        other => format!("SIG{other}"),
    }
}

/// Exit status for a command Meka killed, at its timeout or at the output bound. The child is torn
/// down without its status being reaped, so there is nothing to read it from. On Unix the kill
/// really is a signal (to the tree, by [`crate::process::run`]); Windows has no signals, and
/// claiming one there would put a name in the client's terminal that never existed on that
/// platform. `reason` is why Meka killed it, as the result's text opens, and `closing` what the
/// text adds after the output.
fn killed_exit_metadata(
    reason: &str,
    closing: Option<String>,
) -> crate::frontend::ToolOutputMetadata {
    crate::frontend::ToolOutputMetadata::CommandExit {
        exit_code: None,
        #[cfg(unix)]
        signal: Some("SIGKILL".to_string()),
        #[cfg(not(unix))]
        signal: None,
        reason: Some(reason.to_string()),
        closing,
    }
}

/// Both streams as one text, stderr under its own divider when both have something to show.
fn join_streams(stdout: &str, stderr: &str) -> String {
    let mut text = String::new();
    if !stdout.is_empty() {
        text.push_str(stdout);
    }
    if !stderr.is_empty() {
        if !text.is_empty() {
            text.push_str("\n--- stderr ---\n");
        }
        text.push_str(stderr);
    }
    text
}

/// The line a command's output ends with when it exited with a code other than 0, which a screen
/// stating the code beside the call leaves out of the output.
pub(crate) fn exit_line(exit_code: i32) -> String {
    format!("Exit code: {exit_code}")
}

/// What a result's text says of the exit after the command's output: the exit line on a line of
/// its own for a code other than 0, nothing for 0.
fn exit_words(exit_code: i32) -> String {
    if exit_code == 0 {
        String::new()
    } else {
        format!("\n{}", exit_line(exit_code))
    }
}

/// What a result's text adds after the command's own output, as the text carries it: `exit`
/// (see [`exit_words`]), then the note that the output's pipe was left open. `None` when it adds
/// nothing.
fn closing_words(exit: &str, drain_stopped_early: bool) -> Option<String> {
    let mut closing = exit.to_string();
    if drain_stopped_early {
        closing.push_str(&drain_stopped_note());
    }
    (!closing.is_empty()).then_some(closing)
}

fn assemble_command_output(stdout: &str, stderr: &str, exit_code: i32) -> ToolOutput {
    let mut result_text = join_streams(stdout, stderr);
    result_text.push_str(&exit_words(exit_code));

    ToolOutput::text(
        if result_text.is_empty() {
            "(no output)".to_string()
        } else {
            result_text
        },
        exit_code != 0,
    )
}

/// Run a command in a jail the broker builds.
///
/// The FreeBSD sibling of the Unix spawn path, and a different shape of work: there is no child in
/// this process to kill and no pipes to drain. The daemon owns the command, and its output arrives
/// as two streams the same tasks read; everything downstream of the spawn is shared, so the relay,
/// the residency ceiling, the capture to a file and the assembly behave exactly as they do for a
/// command Meka spawned itself.
#[cfg(target_os = "freebsd")]
async fn run_jailbroker(
    socket: &std::path::Path,
    command: &str,
    confinement: &crate::sandbox::Confinement,
    cwd: &crate::workspace::SharedCwd,
    timeout: std::time::Duration,
    cancellation: tokio_util::sync::CancellationToken,
    relay: Option<OutputRelay>,
) -> Result<ToolOutput> {
    let plan = crate::sandbox::jailbroker::plan_for(
        confinement,
        &cwd.get(),
        &crate::workspace::private_directories(),
        &crate::sandbox::sandbox_child_env(),
        command,
    );
    let crate::sandbox::jailbroker::Running {
        stdout,
        stderr,
        mut outcome,
        cancel,
    } = crate::sandbox::jailbroker::run(socket, plan)
        .await
        .map_err(|failure| MekaError::ToolExecution {
            tool_name: "shell_execute".to_string(),
            message: failure.message().to_string(),
        })?;

    // The same shape as the standard path: both drains start before anything is awaited, so a
    // command writing faster than the turn reads cannot fill the socket and stall the daemon. The
    // output bound is the same one too, so a runaway command is stopped on this backend as it is
    // on the others.
    let budget = Arc::new(crate::process::OutputBudget::new(MAX_OUTPUT_BYTES));
    let drains =
        crate::process::Drains::start(Some(stdout), Some(stderr), command_capture(&budget, relay));

    // What the run ended as, short of the stop: its arm returns in its own right.
    enum Ended {
        // The output bound was reached while the command ran.
        Bound,
        // The command outlived its timeout and Meka stopped it.
        TimedOut,
        // The daemon reported the command's end.
        Ran(crate::sandbox::jailbroker::Outcome),
    }

    // `biased`, so a bound reached in the same instant the command exits is reported as the bound,
    // as it is on the spawn path: the random pick would otherwise call the command clean while its
    // last reads were never taken.
    let ended = tokio::select! {
        biased;
        _ = cancellation.cancelled() => {
            stop_jailbroker_command(&cancel).await;
            abort_after_timeout(outcome, JAILBROKER_STOP_GRACE).await;
            // The stop is all the record needs: returning drops the drains, whose drop guard stops
            // their reads at once and keeps nothing of what they read after the stop.
            return Err(MekaError::Interrupted);
        }
        () = drains.bound_reached() => {
            stop_jailbroker_command(&cancel).await;
            abort_after_timeout(outcome, JAILBROKER_STOP_GRACE).await;
            Ended::Bound
        }
        _ = tokio::time::sleep(timeout) => {
            stop_jailbroker_command(&cancel).await;
            abort_after_timeout(outcome, JAILBROKER_STOP_GRACE).await;
            Ended::TimedOut
        }
        outcome = &mut outcome => {
            let outcome = outcome
                .map_err(|error| MekaError::ToolExecution {
                    tool_name: "shell_execute".to_string(),
                    message: format!("failed to wait for the jailbroker: {error}"),
                })?
                .map_err(|failure| MekaError::ToolExecution {
                    tool_name: "shell_execute".to_string(),
                    message: failure.message().to_string(),
                })?;
            Ended::Ran(outcome)
        }
    };
    let drained = DrainedOutput::from(drains.collect(DRAIN_TIMEOUT).await);
    match ended {
        Ended::Bound => Ok(killed_command_output(&drained, &output_bound_reason())),
        // Timed out means Meka stopped it, so this reports the stop rather than inventing an
        // exit status; a frontend rendering a terminal shows "terminated" rather than "exit 0".
        Ended::TimedOut => Ok(killed_command_output(
            &drained,
            &timed_out_reason(timeout, &budget),
        )),
        Ended::Ran(outcome) => {
            if drained.stopped_early {
                tracing::warn!(
                    "command output drain stopped after {DRAIN_TIMEOUT:?}; a background process may \
                     be holding the pipe open"
                );
            }
            // The drains may cross the bound after the command exits, for the reason the spawn path
            // gives: a clean exit code over an incomplete transcript is the one shape the record
            // must never take.
            if budget.is_exhausted() {
                let cut = output_cut_note();
                Ok(
                    led_by_reason(&drained, &cut).with_metadata(jailbroker_exit_metadata(
                        outcome.status,
                        Some(&cut),
                        closing_words("", drained.stopped_early),
                    )),
                )
            } else {
                let mut output =
                    assemble_command_output(&drained.stdout, &drained.stderr, outcome.status);
                if drained.stopped_early {
                    append_drain_stopped_note(&mut output);
                }
                Ok(output.with_metadata(jailbroker_exit_metadata(
                    outcome.status,
                    None,
                    closing_words(&exit_words(outcome.status), drained.stopped_early),
                )))
            }
        }
    }
}

/// How long a stopped command has to report its exit before Meka stops waiting for it.
///
/// The daemon kills the process group on a cancel and answers promptly. If it does not answer, the
/// tool call must still end, and dropping the session is what stops the command in any case: the
/// daemon takes a session apart when its client goes away.
#[cfg(target_os = "freebsd")]
const JAILBROKER_STOP_GRACE: std::time::Duration = std::time::Duration::from_secs(5);

/// Ask the daemon to stop the running command.
///
/// A failure here is not fatal and is not silent: the session is about to be dropped, which stops
/// the command anyway, so what went wrong is a diagnostic rather than something to report to the
/// model as the outcome of a command it asked for.
#[cfg(target_os = "freebsd")]
async fn stop_jailbroker_command(cancel: &crate::sandbox::jailbroker::Cancel) {
    if let Err(failure) = cancel.send().await {
        tracing::debug!(
            "failed to ask the jailbroker to stop the command: {}",
            failure.message()
        );
    }
}

/// The exit status of a command the daemon ran.
///
/// The daemon reports a code, or 128 plus the signal that killed the command, which is the shell's
/// own convention. Nothing on the wire says which of the two a number above 128 is, and a command
/// that exits 137 is a thing that happens, so Meka reports the number it was given and claims no
/// signal: a name in a client's terminal is worth having only when the kernel is what said it.
#[cfg(target_os = "freebsd")]
fn jailbroker_exit_metadata(
    status: i32,
    reason: Option<&str>,
    closing: Option<String>,
) -> crate::frontend::ToolOutputMetadata {
    crate::frontend::ToolOutputMetadata::CommandExit {
        exit_code: Some(status),
        signal: None,
        reason: reason.map(str::to_string),
        closing,
    }
}

/// Windows-only: spawn via `CreateProcessAsUserW` with a Low-integrity token, read stdout/stderr
/// from the pipe `File`s, and wait/kill through blocking tasks. Mirrors the timeout/cancellation
/// semantics of the standard path.
///
/// Stdout/stderr are drained on dedicated tasks that start *before* the child wait begins. Without
/// that, a child that writes more than the pipe buffer (1 MiB hinted; smaller if the kernel rounds
/// down) before anyone reads will block in `WriteFile`, the wait never returns, and the whole call
/// times out with truncated output. After the child exits or is killed, the pipe write ends close
/// and the drain tasks terminate at EOF.
///
/// # Drain timeouts
///
/// The job the child runs in ends every process it started, but only when the child is killed or
/// this call returns. A grandchild that inherited the pipe write handles can therefore keep the
/// pipe alive past the direct child's own exit, and the drain tasks would block on `ReadFile`
/// until the job took it. To bound the tool-call wall time the drains are collected under
/// [`DRAIN_TIMEOUT`] and told to stop at it, keeping what they read.
#[cfg(windows)]
async fn run_windows_sandboxed(
    command: &str,
    confinement: &crate::sandbox::windows::WindowsConfinement,
    cwd: std::path::PathBuf,
    timeout: std::time::Duration,
    cancellation: tokio_util::sync::CancellationToken,
    relay: Option<OutputRelay>,
) -> Result<ToolOutput> {
    use std::{sync::Arc, time::Duration};

    // Bound the post-kill cleanup wait so a stuck `TerminateProcess` can't hang the tool
    // indefinitely. Two seconds is generous for kernel-side teardown.
    const POST_KILL_TIMEOUT: Duration = Duration::from_secs(2);

    let mut sandboxed =
        crate::sandbox::windows::spawn_sandboxed_command(command, confinement, &cwd).map_err(
            |error| MekaError::ToolExecution {
                tool_name: "shell_execute".to_string(),
                message: format!("failed to spawn sandboxed command: {error}"),
            },
        )?;

    let stdout = sandboxed.take_stdout().map(tokio::fs::File::from_std);
    let stderr = sandboxed.take_stderr().map(tokio::fs::File::from_std);

    let child = Arc::new(sandboxed);
    let budget = Arc::new(crate::process::OutputBudget::new(MAX_OUTPUT_BYTES));
    let drains = crate::process::Drains::start(stdout, stderr, command_capture(&budget, relay));

    let wait_child = Arc::clone(&child);
    // `tokio::select!` requires the future passed to the happy-path branch (`join = ...`) to be
    // polled without consuming ownership of the handle, because the other branches need to move
    // the same handle into `abort_after_timeout` if their future resolves first. Polling `&mut
    // wait_handle` satisfies `JoinHandle`'s `Future` impl (it has a `&mut self`-based `poll`)
    // without committing the move until we know which branch wins.
    let mut wait_handle = tokio::task::spawn_blocking(move || wait_child.wait_blocking());

    // `biased` for the reason `process::run` gives: a bound reached as the child exits is the
    // bound, not a clean exit.
    tokio::select! {
        biased;
        _ = cancellation.cancelled() => {
            if let Err(error) = child.kill() {
                tracing::debug!("failed to kill sandboxed child: {error}");
            }
            abort_after_timeout(wait_handle, POST_KILL_TIMEOUT).await;
            Err(MekaError::Interrupted)
        }
        _ = drains.bound_reached() => {
            if let Err(error) = child.kill() {
                tracing::debug!("failed to kill sandboxed child: {error}");
            }
            abort_after_timeout(wait_handle, POST_KILL_TIMEOUT).await;
            let drained = DrainedOutput::from(drains.collect(DRAIN_TIMEOUT).await);
            Ok(killed_command_output(&drained, &output_bound_reason()))
        }
        _ = tokio::time::sleep(timeout) => {
            if let Err(error) = child.kill() {
                tracing::debug!("failed to kill sandboxed child: {error}");
            }
            abort_after_timeout(wait_handle, POST_KILL_TIMEOUT).await;
            let drained = DrainedOutput::from(drains.collect(DRAIN_TIMEOUT).await);
            Ok(killed_command_output(&drained, &timed_out_reason(timeout, &budget)))
        }
        join = &mut wait_handle => {
            let status = join.map_err(|error| MekaError::ToolExecution {
                tool_name: "shell_execute".to_string(),
                message: format!("wait task panicked: {error}"),
            })?;
            let status = status.map_err(wait_failed)?;
            let drained = DrainedOutput::from(drains.collect(DRAIN_TIMEOUT).await);
            Ok(finish_command(&status, &drained, &budget))
        }
    }
}

/// Abort any pending `JoinHandle` after `timeout`. Used on cancel/timeout cleanup paths where we
/// don't need the task's output, just its termination.
#[cfg_attr(
    not(any(target_os = "freebsd", windows)),
    allow(
        dead_code,
        reason = "read only by the platforms that stop a command over a channel"
    )
)]
async fn abort_after_timeout<T: 'static>(
    mut handle: tokio::task::JoinHandle<T>,
    timeout: std::time::Duration,
) {
    tokio::select! {
        _ = &mut handle => {}
        _ = tokio::time::sleep(timeout) => {
            handle.abort();
        }
    }
}

/// Tell the model that the drains were stopped with a pipe still open, so output printed after
/// that point by whatever held it is not in the result.
fn append_drain_stopped_note(output: &mut ToolOutput) {
    if let Some(crate::conversation::ToolResultContent::Text { text }) = output.content.last_mut() {
        text.push_str(&drain_stopped_note());
    }
}

/// The note [`append_drain_stopped_note`] ends a result's text with, on a line of its own.
fn drain_stopped_note() -> String {
    format!(
        "\n(a background process kept the output pipe open for {} seconds past the command's \
         exit; anything it printed after that is not included)",
        DRAIN_TIMEOUT.as_secs()
    )
}

#[cfg(test)]
mod tests {
    use tokio_util::sync::CancellationToken;

    use super::*;

    /// A detached command streams nothing: its call returned when it detached, so a chunk would
    /// land on whatever call the id names next. A call that waits for its command streams.
    #[test]
    fn a_detached_command_streams_no_output() {
        // `detached` is the constructor for a call outside any session; the task id is what
        // makes a call a background one.
        let waited_for = crate::tools::ToolContext {
            tool_call_id: Some("call_0".to_string()),
            ..crate::tools::ToolContext::for_test(CancellationToken::new())
        };
        assert!(OutputRelay::for_call(&waited_for).is_some());
        let in_the_background = crate::tools::ToolContext {
            task_id: Some("7f3a1c22".to_string()),
            ..waited_for
        };
        assert!(OutputRelay::for_call(&in_the_background).is_none());
    }

    fn shared_permission_for_test() -> crate::permission::SharedPermission {
        crate::permission::SharedPermission::new(
            Permission::Unrestricted,
            crate::permission::EnabledPermissions::ALL,
        )
    }

    /// Every text block of a tool output, joined.
    #[cfg(target_os = "linux")]
    pub(super) fn text_of(output: &ToolOutput) -> String {
        output
            .content
            .iter()
            .filter_map(|content| {
                if let crate::conversation::ToolResultContent::Text { text } = content {
                    Some(text.as_str())
                } else {
                    None
                }
            })
            .collect()
    }

    /// A frontend that keeps every output delta it is handed, so a test can see what the relay
    /// sent and when.
    #[derive(Default)]
    struct ChunkRecorder {
        chunks: std::sync::Mutex<Vec<String>>,
    }

    impl ChunkRecorder {
        fn relayed(&self) -> String {
            self.chunks.lock().expect("lock").concat()
        }
    }

    #[async_trait]
    impl crate::frontend::Frontend for ChunkRecorder {
        async fn emit(&self, event: crate::frontend::FrontendEvent) {
            if let crate::frontend::FrontendEvent::ToolCallOutputDelta { chunk, .. } = event
                && let Ok(mut chunks) = self.chunks.lock()
            {
                chunks.push(chunk);
            }
        }

        async fn request_permission(
            &self,
            _request: crate::frontend::PermissionRequest,
        ) -> crate::frontend::PermissionOutcome {
            crate::frontend::PermissionOutcome::Deny
        }
    }

    /// A relay into `recorder`, tagged as one tool call.
    fn relay_into(recorder: &Arc<ChunkRecorder>) -> Option<OutputRelay> {
        let frontend: Arc<dyn crate::frontend::Frontend> = recorder.clone();
        Some(OutputRelay {
            frontend,
            tool_call_id: "call_1".to_string(),
            stdout_pending: std::sync::Mutex::default(),
            stderr_pending: std::sync::Mutex::default(),
        })
    }

    /// A drain over `reader` with the real bound and nothing telling it to stop: what a command
    /// that behaves gets.
    async fn drain_for_test<R>(reader: R, relay: Option<OutputRelay>) -> String
    where
        R: tokio::io::AsyncRead + Unpin + Send + 'static,
    {
        let budget = Arc::new(crate::process::OutputBudget::new(MAX_OUTPUT_BYTES));
        let drained = crate::process::Drains::start(
            Some(reader),
            None::<tokio::io::Empty>,
            command_capture(&budget, relay),
        )
        .collect(DRAIN_TIMEOUT)
        .await;
        DrainedOutput::from(drained).stdout
    }

    /// Construct an `ExecuteCommandTool` for tests with a backend probe matching whatever the host
    /// actually supports. Tests that need a specific probe state (e.g. exercising the "backend
    /// unavailable" hard-error path) should build `ExecuteCommandTool` directly with the desired
    /// `BackendProbe` rather than going through this helper.
    pub(super) fn tool_for_test(
        shared_permission: crate::permission::SharedPermission,
        sandbox_enabled: bool,
    ) -> ExecuteCommandTool {
        let sandbox_capability = crate::sandbox::detect();
        let backend_probe = crate::sandbox::BackendProbe::Ok(sandbox_capability.clone());
        ExecuteCommandTool {
            #[cfg(windows)]
            wsl_target: None,
            ssh_targets: Default::default(),
            #[cfg(windows)]
            windows_grants: std::sync::Arc::new(crate::sandbox::windows::WindowsGrants::default()),
            scope: crate::workspace::WriteScope::unconfined(),
            sandbox_capability,
            sandbox_backend: crate::config::SandboxBackend::Landlock,
            backend_probe,
            sandbox_enabled,
            site: crate::session::ToolSite::for_test()
                .with_permission(shared_permission)
                .with_cwd(crate::workspace::cwd_for_test()),
        }
    }

    /// With `[shell].sandbox = false`, nothing can confine a command below `unrestricted`, and that
    /// follows from the level alone, so the tool states the refusal ahead of the approval prompt in
    /// the words `execute` would use. `unrestricted` promised no boundary and has nothing to say.
    #[tokio::test]
    async fn the_shell_states_its_confinement_refusal_ahead_of_the_prompt() {
        let tool = tool_for_test(shared_permission_for_test(), false);
        let input = serde_json::json!({"command": "true"});

        let refusal = tool
            .refusal_at_level(Permission::Read, &input)
            .await
            .expect("nothing confines the command at `read`");
        assert!(refusal.is_error);
        assert!(
            refusal.text_content().contains("`[shell].sandbox = false`"),
            "{}",
            refusal.text_content()
        );
        assert!(
            tool.refusal_at_level(Permission::Unrestricted, &input)
                .await
                .is_none(),
            "`unrestricted` runs unconfined by design"
        );
    }

    /// A real signal kill and Meka's own timeout kill must spell the same signal the same way; a
    /// client's terminal shows this string, and `SIG9` next to `SIGKILL` for the same event reads
    /// as two different failures.
    #[cfg(unix)]
    #[test]
    fn signal_naming_is_consistent_between_a_real_kill_and_a_timeout() {
        assert_eq!(signal_name(libc::SIGKILL), "SIGKILL");
        assert_eq!(signal_name(libc::SIGTERM), "SIGTERM");
        assert_eq!(
            signal_name(4242),
            "SIG4242",
            "unknown signals stay unambiguous"
        );

        let crate::frontend::ToolOutputMetadata::CommandExit {
            exit_code, signal, ..
        } = killed_exit_metadata("stopped", None)
        else {
            panic!("a kill must report a command exit");
        };
        assert_eq!(
            exit_code, None,
            "a killed command never produced an exit code"
        );
        assert_eq!(
            signal.as_deref(),
            Some(signal_name(libc::SIGKILL).as_str()),
            "the timeout path must name the signal the same way the reaped-status path does",
        );
    }

    /// A command a signal ended has no exit code for a frontend to state beside it, and its text
    /// still ends on the line that gives it one: the closing words carry that line, so a frontend
    /// showing the output it streamed can end as the text does.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_command_a_signal_ended_carries_the_line_its_text_ends_on() {
        let tool = tool_for_test(shared_permission_for_test(), false);
        let result = tool
            .execute(
                serde_json::json!({"command": "echo before; kill -KILL $$"}),
                crate::tools::ToolContext::for_test(CancellationToken::new()),
            )
            .await
            .expect("tool runs");
        assert!(result.is_error, "a command a signal ended failed");
        let text = result.text_content();
        let Some(crate::frontend::ToolOutputMetadata::CommandExit {
            exit_code,
            signal,
            reason,
            closing,
        }) = result.frontend_metadata
        else {
            panic!("expected CommandExit metadata");
        };
        assert_eq!(exit_code, None, "a signal leaves no exit code");
        assert_eq!(signal.as_deref(), Some("SIGKILL"));
        assert_eq!(reason, None, "Meka did not end it");
        let closing = closing.expect("the text ends on an exit line");
        assert_eq!(closing, format!("\n{}", exit_line(-1)));
        assert!(
            text.starts_with("before\n") && text.ends_with(&closing),
            "{text}"
        );
    }

    /// `shell_execute` reports its exit status structurally, not only inside the prose the model
    /// reads, so a frontend rendering a terminal can show the real code instead of guessing from
    /// the error flag.
    #[tokio::test]
    async fn execute_command_reports_its_exit_code_as_metadata() {
        let tool = tool_for_test(shared_permission_for_test(), false);
        let result = tool
            .execute(
                serde_json::json!({"command": "exit 42"}),
                crate::tools::ToolContext::for_test(CancellationToken::new()),
            )
            .await
            .expect("tool runs");
        assert!(result.is_error, "a non-zero exit is a failed call");
        let text = result.text_content();
        let Some(crate::frontend::ToolOutputMetadata::CommandExit {
            exit_code,
            signal,
            reason,
            closing,
        }) = result.frontend_metadata
        else {
            panic!(
                "expected CommandExit metadata; got {:?}",
                result.frontend_metadata
            );
        };
        assert_eq!(exit_code, Some(42));
        assert_eq!(signal, None, "a clean exit carries no signal");
        assert_eq!(
            reason, None,
            "Meka ended nothing, so there is no reason to give"
        );
        let closing = closing.expect("the text ends on the exit line");
        assert_eq!(closing, format!("\n{}", exit_line(42)));
        assert!(
            text.ends_with(&closing),
            "the closing words are the text's own: {text}"
        );
    }

    /// A read can end partway through a multi-byte character. Relaying the raw bytes would show
    /// the client replacement characters that were never in the output, so the incomplete tail has
    /// to wait for the read that completes it. Feeds the reader one byte at a time to force the
    /// split on every character.
    #[tokio::test]
    async fn reader_relays_chunks_without_splitting_characters() {
        let recorder = Arc::new(ChunkRecorder::default());
        let relay = relay_into(&recorder);

        let source = "ünïcödé ✓ done\n";
        // `tokio::io::AsyncRead` over a byte slice yields whatever the caller's buffer allows, so
        // cap reads at one byte to guarantee every multi-byte character straddles a read.
        let reader = tokio::io::AsyncReadExt::take(source.as_bytes(), u64::MAX);
        let collected = drain_for_test(OneByteAtATime(reader), relay).await;

        assert_eq!(collected, source, "the full stream must survive intact");
        let chunks = recorder.chunks.lock().expect("lock").clone();
        assert_eq!(
            chunks.concat(),
            source,
            "the relayed chunks must reassemble to the same bytes",
        );
        assert!(
            !chunks.iter().any(|chunk| chunk.contains('\u{fffd}')),
            "no chunk may contain a replacement character; got {chunks:?}",
        );
    }

    /// Bytes that are no character do not stop the live view: each is relayed as the replacement
    /// character the result holds in its place and the stream goes on after it, however the
    /// reads split, where a relay that waited for it to become text would show nothing more of
    /// the command.
    #[tokio::test]
    async fn the_relay_goes_on_past_bytes_that_are_no_character() {
        let source: &[u8] = b"caf\xe9 au lait\n\xe2\x28\xa1 \xe2\x9c\x93 done\n";
        let expected = String::from_utf8_lossy(source).into_owned();
        assert!(
            expected.ends_with("\u{fffd}(\u{fffd} ✓ done\n"),
            "{expected:?}"
        );

        let whole = Arc::new(ChunkRecorder::default());
        let collected = drain_for_test(std::io::Cursor::new(source), relay_into(&whole)).await;
        assert_eq!(collected, expected);
        assert_eq!(whole.relayed(), expected, "read at once");

        let split = Arc::new(ChunkRecorder::default());
        let reader = tokio::io::AsyncReadExt::take(source, u64::MAX);
        drain_for_test(OneByteAtATime(reader), relay_into(&split)).await;
        assert_eq!(split.relayed(), expected, "read a byte at a time");
    }

    /// The relay must reassemble to the source across a stream of many reads, each carrying a
    /// partial character into the next: what a read leaves unrelayed waits for the next, and a
    /// carry-over that drifts by one byte loses a whole read from the live view while the result
    /// stays complete, which no single-read test can show.
    #[tokio::test]
    async fn the_relay_loses_nothing_across_a_stream_of_many_reads() {
        // A 3-byte character repeated, so no power-of-two read size can land on a boundary and
        // every read carries a partial character into the next.
        let unit = "日";
        let source = unit.repeat(crate::text::MIB / unit.len() + 4096);

        let recorder = Arc::new(ChunkRecorder::default());
        let relay = relay_into(&recorder);

        let collected =
            drain_for_test(std::io::Cursor::new(source.clone().into_bytes()), relay).await;

        assert_eq!(collected, source, "the result is the whole stream");
        let chunks = recorder.chunks.lock().expect("lock").clone();
        assert_eq!(
            chunks.concat(),
            source,
            "every byte printed must reach the client",
        );
        assert!(
            !chunks.iter().any(|chunk| chunk.contains('\u{fffd}')),
            "and no chunk may be cut mid-character",
        );
    }

    /// The common case must be untouched: byte-for-byte what was printed.
    #[tokio::test]
    async fn a_stream_within_the_bound_is_returned_whole() {
        let source = b"just a normal amount of output\n".to_vec();
        let collected = drain_for_test(std::io::Cursor::new(source.clone()), None).await;
        assert_eq!(collected.as_bytes(), source.as_slice());
    }

    /// Reader that hands out at most one byte per `poll_read`, so every multi-byte character in
    /// the source is guaranteed to span a read boundary.
    struct OneByteAtATime<R>(R);

    impl<R: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for OneByteAtATime<R> {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            context: &mut std::task::Context<'_>,
            buffer: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            let mut single = [0u8; 1];
            let mut limited = tokio::io::ReadBuf::new(&mut single);
            match std::pin::Pin::new(&mut self.0).poll_read(context, &mut limited) {
                std::task::Poll::Ready(Ok(())) => {
                    let filled = limited.filled().to_vec();
                    buffer.put_slice(&filled);
                    std::task::Poll::Ready(Ok(()))
                }
                other => other,
            }
        }
    }

    #[tokio::test]
    async fn execute_command_runs_a_command_and_returns_its_output() {
        let tool = tool_for_test(shared_permission_for_test(), true);
        let result = tool
            .execute(
                serde_json::json!({"command": "echo hello"}),
                crate::tools::ToolContext::for_test(CancellationToken::new()),
            )
            .await
            .expect("should succeed");

        assert!(!result.is_error);
        assert_eq!(result.text_content().trim(), "hello");
    }

    /// A command that backgrounds a long-running helper (`(sleep 30 &)`) must have that helper
    /// killed when the tool times out, not outlive the agent. The child is placed in its own
    /// process group via `setsid` so the tool can signal the whole tree via `kill(-pgid, …)`.
    #[cfg(unix)]
    #[tokio::test]
    async fn execute_command_timeout_kills_grandchild() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let marker = temp_dir.path().join("marker");
        let marker_str = marker.to_str().expect("utf-8 path").to_string();

        let tool = tool_for_test(shared_permission_for_test(), false);

        // The grandchild sleeps 3s then touches `marker`. If it survived the timeout, the marker
        // file will appear. The timeout is 300ms and we wait 5s below for a definitive "did it
        // survive?" answer.
        let script = format!("( sleep 3 && : > '{marker_str}' ) & echo backgrounded; sleep 30");
        let result = tool
            .execute(
                serde_json::json!({ "command": script, "timeout_ms": 300u64 }),
                crate::tools::ToolContext::for_test(CancellationToken::new()),
            )
            .await
            .expect("execute should not error");

        // Tool reports timeout.
        assert!(result.is_error);
        let text = result.text_content();
        assert!(text.contains("timed out"), "got: {text:?}");

        // Wait well past the grandchild's sleep-3s. If the marker materializes, the grandchild
        // wasn't killed; the bug is back.
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        assert!(
            !marker.exists(),
            "grandchild survived timeout and created marker at {marker:?}"
        );
    }

    /// A command admitted as sandboxed is refused when the capability cannot confine it, never
    /// run through a plain `sh -c`: the probe that admits and the capability that spawns agree
    /// today, and this is what a disagreement costs.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_sandboxed_command_with_no_backend_is_refused_not_run_bare() {
        let tool = ExecuteCommandTool {
            scope: crate::workspace::WriteScope::unconfined(),
            sandbox_capability: crate::sandbox::SandboxCapability::Unavailable,
            sandbox_backend: crate::config::SandboxBackend::Landlock,
            backend_probe: crate::sandbox::BackendProbe::Ok(
                crate::sandbox::SandboxCapability::Landlock { abi_version: 9 },
            ),
            sandbox_enabled: true,
            ssh_targets: Default::default(),
            site: crate::session::ToolSite::for_test()
                .with_permission(crate::permission::SharedPermission::new(
                    Permission::Read,
                    crate::permission::EnabledPermissions::ALL,
                ))
                .with_cwd(crate::workspace::cwd_for_test()),
        };
        let error = tool
            .execute(
                serde_json::json!({ "command": "true" }),
                crate::tools::ToolContext::for_test(CancellationToken::new()),
            )
            .await
            .expect_err("nothing can confine it, so it does not run");
        assert!(error.to_string().contains("cannot confine"), "{error}");
    }

    /// Dropping the future is as safe as canceling it: a caller that times the tool out by
    /// dropping `execute` (a gate) never reaches the arms that kill the group, and the command
    /// would run on to its own end. The sleep's odd duration is what the process list is
    /// searched for.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_dropped_execute_kills_the_command_and_its_group() {
        let tool = tool_for_test(shared_permission_for_test(), false);
        let dropped = tokio::time::timeout(
            std::time::Duration::from_millis(300),
            tool.execute(
                serde_json::json!({ "command": "sleep 31.4159 & sleep 31.4159", "timeout_ms": 60_000u64 }),
                crate::tools::ToolContext::for_test(CancellationToken::new()),
            ),
        )
        .await;
        assert!(dropped.is_err(), "the future was dropped by the timeout");
        // The kill is synchronous; the reaping is the kernel's, so a moment for it.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        let listing = std::process::Command::new("ps")
            .args(["-eo", "args"])
            .output()
            .expect("ps runs");
        let listing = String::from_utf8_lossy(&listing.stdout);
        assert!(
            !listing.contains("sleep 31.4159"),
            "the command and its group must be gone once the future is dropped:\n{listing}"
        );
    }

    /// A command that outgrows the bound is stopped, and everything it printed up to the stop is in
    /// the result: the record is complete, the model is told why the command ended and how much it
    /// printed, and the kill is reported the way the timeout's is.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_command_that_prints_past_the_bound_is_stopped_and_its_output_kept() {
        let tool = tool_for_test(shared_permission_for_test(), false);
        // Past the bound by a margin, with a recognizable first line, so the result can be checked
        // for both ends of what it must hold.
        let past_the_bound = MAX_OUTPUT_BYTES + 4 * crate::text::MIB;
        let result = tool
            .execute(
                serde_json::json!({
                    "command": format!(
                        "echo FIRST-LINE; head -c {past_the_bound} /dev/zero | tr '\\0' x; \
                         echo NEVER-REACHED"
                    ),
                    "timeout_ms": 60_000u64,
                }),
                crate::tools::ToolContext::for_test(CancellationToken::new()),
            )
            .await
            .expect("a stopped command is a result");

        assert!(result.is_error, "a stopped command is a failed call");
        let text = result.text_content();
        assert!(
            text.starts_with(&format!("{}\nFIRST-LINE\n", output_bound_reason())),
            "the reason leads and what the command printed follows: {text:.120}"
        );
        assert!(
            text.len() >= MAX_OUTPUT_BYTES,
            "everything read up to the bound is kept, got {} bytes",
            text.len()
        );
        assert!(
            !text.contains("NEVER-REACHED"),
            "the command was stopped rather than run to its end"
        );
        let Some(crate::frontend::ToolOutputMetadata::CommandExit {
            exit_code,
            signal,
            reason,
            ..
        }) = result.frontend_metadata
        else {
            panic!("expected CommandExit metadata");
        };
        assert_eq!(exit_code, None, "a killed command has no exit code");
        assert_eq!(signal.as_deref(), Some("SIGKILL"));
        assert_eq!(
            reason,
            Some(output_bound_reason()),
            "a frontend showing the output it streamed is told why the command ended"
        );
    }

    /// A child exits once its last write fits in the pipe, so it can finish within a pipe's worth
    /// of the bound and leave the crossing to the drains' collection. That result must not read as
    /// a clean exit: it leads with the cut and is an error, whatever the exit status says.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_command_whose_drains_reach_the_bound_after_it_exits_is_not_reported_clean() {
        use std::os::unix::process::ExitStatusExt;
        let budget = crate::process::OutputBudget::new(16);
        assert!(!budget.spend(32), "the budget is spent past its bound");
        let drained = DrainedOutput {
            stdout: "printed before the cut\n".to_string(),
            stderr: String::new(),
            stopped_early: false,
        };

        let result = finish_command(&std::process::ExitStatus::from_raw(0), &drained, &budget);

        assert!(result.is_error, "a cut transcript is never a clean result");
        let text = result.text_content();
        assert!(
            text.starts_with(&format!("{}\nprinted before the cut\n", output_cut_note())),
            "the cut leads and the output follows: {text}"
        );
        let Some(crate::frontend::ToolOutputMetadata::CommandExit {
            exit_code,
            signal,
            reason,
            ..
        }) = result.frontend_metadata
        else {
            panic!("expected CommandExit metadata");
        };
        assert_eq!(exit_code, Some(0), "the real exit status is still reported");
        assert_eq!(signal, None);
        assert_eq!(
            reason,
            Some(output_cut_note()),
            "and the cut is said beside it"
        );
    }

    /// End to end, a command whose output ends within a pipe's worth past the bound may exit
    /// before or after the drains cross it, so either the bound arm or the exit arm can win.
    /// Whichever does, the result is an error that leads with the bound.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_command_ending_just_past_the_bound_is_never_reported_clean() {
        let tool = tool_for_test(shared_permission_for_test(), false);
        let just_past = MAX_OUTPUT_BYTES + 100;
        let result = tool
            .execute(
                serde_json::json!({
                    "command": format!("head -c {just_past} /dev/zero | tr '\\0' x"),
                    "timeout_ms": 60_000u64,
                }),
                crate::tools::ToolContext::for_test(CancellationToken::new()),
            )
            .await
            .expect("a result");

        assert!(
            result.is_error,
            "output past the bound is never a clean result"
        );
        let text = result.text_content();
        assert!(
            text.starts_with(&output_bound_reason()) || text.starts_with(&output_cut_note()),
            "the result leads with the bound either way: {text:.120}"
        );
        assert!(
            text.len() >= MAX_OUTPUT_BYTES,
            "everything read up to the bound is kept, got {} bytes",
            text.len()
        );
    }

    /// A command killed at its timeout keeps what it printed before the kill. A build that logged
    /// for twenty-nine seconds and died at thirty used to come back as the timeout line alone.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_timed_out_command_keeps_the_output_it_printed() {
        let tool = tool_for_test(shared_permission_for_test(), false);
        let result = tool
            .execute(
                serde_json::json!({
                    "command": "echo before-the-stall; echo on-stderr >&2; sleep 30",
                    "timeout_ms": 300u64,
                }),
                crate::tools::ToolContext::for_test(CancellationToken::new()),
            )
            .await
            .expect("a timeout is a result");

        assert!(result.is_error);
        let text = result.text_content();
        let reason = timed_out_reason(
            std::time::Duration::from_millis(300),
            &crate::process::OutputBudget::new(MAX_OUTPUT_BYTES),
        );
        assert!(
            text.starts_with(&format!("{reason}\nbefore-the-stall\n")),
            "the timeout is stated first and stdout printed before the kill follows: {text}"
        );
        assert!(
            text.ends_with("--- stderr ---\non-stderr\n"),
            "and so does stderr: {text}"
        );
    }

    /// A grandchild that keeps the pipe open past the command's exit delays the result by the drain
    /// timeout and costs only what it prints afterwards; what the command itself printed is kept,
    /// and the result says why the pipe was abandoned.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_pipe_held_open_by_a_grandchild_does_not_lose_the_output_already_read() {
        let tool = tool_for_test(shared_permission_for_test(), false);
        // The shell exits at once; the backgrounded `sleep` inherits stdout and holds it open for
        // longer than the drain timeout, then ends on its own.
        let hold = DRAIN_TIMEOUT.as_secs() + 3;
        let started = std::time::Instant::now();
        let result = tool
            .execute(
                serde_json::json!({
                    "command": format!("echo kept; sleep {hold} &"),
                    "timeout_ms": 60_000u64,
                }),
                crate::tools::ToolContext::for_test(CancellationToken::new()),
            )
            .await
            .expect("the command itself succeeds");

        assert!(
            started.elapsed() < std::time::Duration::from_secs(hold),
            "the result arrives at the drain timeout, not when the grandchild lets go"
        );
        assert!(!result.is_error, "the command exited 0");
        let text = result.text_content();
        assert!(
            text.starts_with("kept\n"),
            "the output read before the pipe was abandoned is kept: {text}"
        );
        assert!(
            text.contains("kept the output pipe open"),
            "and the result says the drain stopped early: {text}"
        );
        let Some(crate::frontend::ToolOutputMetadata::CommandExit {
            closing: Some(closing),
            ..
        }) = result.frontend_metadata
        else {
            panic!(
                "the note is carried beside the exit: {:?}",
                result.frontend_metadata
            );
        };
        assert!(
            closing.contains("kept the output pipe open") && text.ends_with(&closing),
            "a frontend showing what it streamed is handed the note the text ends on: {closing}"
        );
    }

    #[tokio::test]
    async fn execute_command_failure() {
        let tool = tool_for_test(shared_permission_for_test(), true);
        let result = tool
            .execute(
                serde_json::json!({"command": "false"}),
                crate::tools::ToolContext::for_test(CancellationToken::new()),
            )
            .await
            .expect("should succeed");

        assert!(result.is_error);
    }

    /// `workspace` refuses the shell outright when `[shell].sandbox = false` leaves nothing to
    /// confine it with.
    ///
    /// The failure this guards is silent and one-sided: the config key unconfines the shell while
    /// the file tools stay fenced, so `workspace` keeps reporting a boundary it is only half
    /// holding. `read` never had the problem, because `Read.allows(Unrestricted)` is false and the
    /// tool simply disappears; `Workspace.allows` is true for everything, so the refusal has to be
    /// here.
    #[tokio::test]
    async fn workspace_refuses_the_shell_when_the_sandbox_is_disabled() {
        // Every level that promises confinement, not just `workspace`: narrowed to `workspace`
        // alone, `[tools.tool_permissions] shell_execute = "read"` plus `[shell].sandbox = false`
        // would run a plain `sh -c` at `read`, with the full parent environment since the scrub is
        // gated on the same flag.
        for level in [Permission::None, Permission::Read, Permission::Workspace] {
            refuses_at(level).await;
        }
    }

    async fn refuses_at(level: Permission) {
        let workspace_perm = crate::permission::SharedPermission::new(
            level,
            crate::permission::EnabledPermissions::ALL,
        );
        let tool = ExecuteCommandTool {
            #[cfg(windows)]
            wsl_target: None,
            ssh_targets: Default::default(),
            #[cfg(windows)]
            windows_grants: std::sync::Arc::clone(crate::sandbox::windows::process_grants()),
            scope: crate::workspace::WriteScope::confined(vec![]),
            sandbox_capability: crate::sandbox::SandboxCapability::Unavailable,
            sandbox_backend: crate::config::SandboxBackend::Bubblewrap,
            backend_probe: crate::sandbox::BackendProbe::Missing {
                reason: "sandbox disabled in config".to_string(),
            },
            sandbox_enabled: false,
            site: crate::session::ToolSite::for_test()
                .with_cwd(crate::workspace::cwd_for_test())
                .with_permission(workspace_perm),
        };
        let result = tool
            .execute(
                serde_json::json!({"command": "echo nope"}),
                crate::tools::ToolContext::for_test(CancellationToken::new()),
            )
            .await;
        match result {
            Err(MekaError::ToolExecution { tool_name, message }) => {
                assert_eq!(tool_name, "shell_execute");
                assert!(
                    message.contains("[shell].sandbox = false"),
                    "the refusal must name the key responsible: {message}"
                );
            }
            other => {
                panic!("expected a hard error at {level} with no sandbox, got {other:?}")
            }
        }
    }

    /// When the configured sandbox backend isn't usable, `shell_execute` at `read` must return
    /// `Err(MekaError::ToolExecution)`, *not* `Ok(ToolOutput { is_error: true })`. The hard error
    /// path is how the model is forced to surface the failure to the user rather than just retrying
    /// or describing it as a tool result.
    #[tokio::test]
    async fn execute_command_hard_errors_when_backend_unavailable() {
        let read_only_perm = crate::permission::SharedPermission::new(
            Permission::Read,
            crate::permission::EnabledPermissions::ALL,
        );
        let tool = ExecuteCommandTool {
            #[cfg(windows)]
            wsl_target: None,
            ssh_targets: Default::default(),
            #[cfg(windows)]
            windows_grants: std::sync::Arc::new(crate::sandbox::windows::WindowsGrants::default()),
            scope: crate::workspace::WriteScope::unconfined(),
            sandbox_capability: crate::sandbox::SandboxCapability::Unavailable,
            sandbox_backend: crate::config::SandboxBackend::Bubblewrap,
            backend_probe: crate::sandbox::BackendProbe::Missing {
                reason: "bwrap not found on PATH".to_string(),
            },
            sandbox_enabled: true,
            site: crate::session::ToolSite::for_test()
                .with_cwd(crate::workspace::cwd_for_test())
                .with_permission(read_only_perm),
        };
        let result = tool
            .execute(
                serde_json::json!({"command": "echo nope"}),
                crate::tools::ToolContext::for_test(CancellationToken::new()),
            )
            .await;
        match result {
            Err(MekaError::ToolExecution { tool_name, message }) => {
                assert_eq!(tool_name, "shell_execute");
                // The backend as this platform calls it: the value's name where the platform takes
                // one, the mechanism where it takes none, so the assertion holds on macOS as on
                // Linux.
                let label = crate::sandbox::backend_label(
                    crate::config::SandboxBackend::Bubblewrap,
                    &tool.backend_probe,
                )
                .expect("every platform in the matrix names its backend");
                assert!(
                    message.contains(label),
                    "expected the backend as this platform calls it in error: {message}"
                );
                assert!(
                    message.contains("bwrap not found on PATH"),
                    "expected probe reason in error: {message}"
                );
                // The remedy where a setting can fix it and none where none can: macOS has one
                // backend and no value for it, so an unusable probe there names nothing to set.
                match crate::sandbox::backend_remedy(&tool.backend_probe) {
                    Some(remedy) => assert!(
                        message.contains(remedy),
                        "expected the remedy in error: {message}"
                    ),
                    None => assert!(
                        !message.contains("`[shell].sandbox_backend`"),
                        "no setting fixes this platform's backend, so none is named: {message}"
                    ),
                }
            }
            Err(other) => panic!("expected ToolExecution, got {other:?}"),
            Ok(output) => panic!("expected hard error, got Ok({:?})", output.text_content()),
        }
    }

    /// At `unrestricted` an unavailable sandbox backend must NOT short-circuit the spawn: that
    /// level promises no boundary, so there is nothing for a missing backend to fail to provide.
    /// `workspace` and `read` are the opposite case and are refused outright, which is what makes
    /// this arm worth pinning separately.
    #[tokio::test]
    async fn execute_command_runs_without_sandbox_when_unrestricted() {
        let unrestricted_perm = crate::permission::SharedPermission::new(
            Permission::Unrestricted,
            crate::permission::EnabledPermissions::ALL,
        );
        let tool = ExecuteCommandTool {
            #[cfg(windows)]
            wsl_target: None,
            ssh_targets: Default::default(),
            #[cfg(windows)]
            windows_grants: std::sync::Arc::new(crate::sandbox::windows::WindowsGrants::default()),
            scope: crate::workspace::WriteScope::unconfined(),
            sandbox_capability: crate::sandbox::SandboxCapability::Unavailable,
            sandbox_backend: crate::config::SandboxBackend::Bubblewrap,
            backend_probe: crate::sandbox::BackendProbe::Missing {
                reason: "bwrap not found on PATH".to_string(),
            },
            sandbox_enabled: true,
            site: crate::session::ToolSite::for_test()
                .with_cwd(crate::workspace::cwd_for_test())
                .with_permission(unrestricted_perm),
        };
        let result = tool
            .execute(
                serde_json::json!({"command": "echo hello"}),
                crate::tools::ToolContext::for_test(CancellationToken::new()),
            )
            .await
            .expect("should succeed at unrestricted");
        assert!(!result.is_error);
        assert_eq!(result.text_content().trim(), "hello");
    }

    #[tokio::test]
    async fn execute_command_large_output_not_truncated() {
        // Output well over any plausible inline cap: the tool must return it in full. The agent
        // layer handles oversize downstream.
        let tool = tool_for_test(shared_permission_for_test(), true);
        let result = tool
            .execute(
                // 50 000 "x" characters, in each host shell's own vocabulary. The Unix spelling
                // is POSIX-portable (`head` and `tr` rather than bash brace expansion, so it
                // works under `dash`) and the Windows one is PowerShell, which is the shell
                // `shell_execute` actually invokes there.
                serde_json::json!({
                    "command": if cfg!(windows) {
                        "Write-Output ('x' * 50000)"
                    } else {
                        "head -c 50000 /dev/zero | tr '\\0' x"
                    }
                }),
                crate::tools::ToolContext::for_test(CancellationToken::new()),
            )
            .await
            .expect("should succeed");

        let text = result.text_content();
        assert!(
            !text.contains("(output truncated"),
            "no truncation marker expected, got: {text:.200}..."
        );
        assert!(
            text.trim().len() >= 50_000,
            "expected >= 50 000 chars, got {}",
            text.trim().len()
        );
    }

    /// A command writing far more than the OS pipe buffer (~64 KiB on Linux) must complete without
    /// blocking: unless stdout/stderr are drained on dedicated tasks that start before
    /// `child.wait()`, the child blocks in `write()`, `wait()` never returns, and the call hits a
    /// spurious timeout with truncated output.
    #[cfg(unix)]
    #[tokio::test]
    async fn execute_command_large_output_no_deadlock() {
        let tool = tool_for_test(shared_permission_for_test(), true);
        // 5 MiB of 'x', two orders of magnitude past any pipe buffer.
        let result = tool
            .execute(
                serde_json::json!({
                    "command": "head -c 5242880 /dev/zero | tr '\\0' x"
                }),
                crate::tools::ToolContext::for_test(CancellationToken::new()),
            )
            .await
            .expect("should succeed");

        assert!(!result.is_error, "large output spuriously flagged as error");
        let text = result.text_content();
        assert!(
            !text.contains("kept the output pipe open"),
            "unexpected drain note: {text:.200}"
        );
        assert!(
            text.trim().len() >= 5_242_880,
            "expected >= 5 MiB of output, got {}",
            text.trim().len()
        );
    }

    #[cfg(windows)]
    mod windows_sandbox {
        use super::*;

        /// Where the process-read probe's parent leaves the target for its child.
        ///
        /// A file in the child's working directory rather than an environment variable, because
        /// the sandboxed spawn path hands the child a *curated* environment on purpose and a
        /// probe-specific variable has no business being added to that allow-list.
        const PROBE_HANDOFF: &str = "probe-target.txt";

        /// Marks the probe child's one line of output, so the parent can tell a real verdict from
        /// a child that never ran. Without it a host where the re-entry silently failed would read
        /// as "no read happened", which is the same shape as success. It earned its keep on the
        /// first hardware run, catching a filter that selected zero tests.
        const PROBE_VERDICT_PREFIX: &str = "MEKA-PROBE-VERDICT ";

        /// The probe child's libtest name, which `--exact` needs in full.
        ///
        /// Derived from [`module_path!`] rather than written out, so moving the module cannot leave
        /// a filter that silently matches nothing. `module_path!` is crate-qualified and libtest's
        /// names are not, so the leading crate segment comes off.
        fn probe_child_test_name() -> String {
            let module = module_path!()
                .split_once("::")
                .map_or(module_path!(), |(_crate_name, rest)| rest);
            format!("{module}::windows_process_read_probe_child")
        }

        fn read_permission() -> crate::permission::SharedPermission {
            crate::permission::SharedPermission::new(
                Permission::Read,
                crate::permission::EnabledPermissions::ALL,
            )
        }

        /// Build an `ExecuteCommandTool` for the restricted-token Windows path. Mirrors
        /// `super::tool_for_test` (which always calls `sandbox::detect()` and would resolve to
        /// `RestrictedToken` on Windows anyway) but constructs the fields explicitly so the tests
        /// document the intended state.
        fn windows_test_tool(
            shared_permission: crate::permission::SharedPermission,
        ) -> ExecuteCommandTool {
            let sandbox_capability = crate::sandbox::SandboxCapability::RestrictedToken;
            let backend_probe = crate::sandbox::BackendProbe::Ok(sandbox_capability.clone());
            ExecuteCommandTool {
                #[cfg(windows)]
                wsl_target: None,
                ssh_targets: Default::default(),
                scope: crate::workspace::WriteScope::unconfined(),
                windows_grants: std::sync::Arc::new(
                    crate::sandbox::windows::WindowsGrants::default(),
                ),
                sandbox_capability,
                sandbox_backend: crate::config::SandboxBackend::RestrictedToken,
                backend_probe,
                sandbox_enabled: true,
                site: crate::session::ToolSite::for_test()
                    .with_permission(shared_permission)
                    .with_cwd(crate::workspace::cwd_for_test()),
            }
        }

        /// The `workspace` restricted-token path, end to end, on real Windows.
        ///
        /// This is the whole Windows half of the level and nothing in the suite reached it: the two
        /// tests below drive the Low-integrity path, which is a different token, a different set of
        /// spawn flags, and no ACE at all. Everything specific to `workspace` -- the
        /// `WRITE_RESTRICTED` token, the synthesized capability SID, the inheritable ACE, the
        /// console a restricted child must inherit rather than create, and `lpCurrentDirectory` --
        /// only runs here.
        ///
        /// Both directions are checked in one command, because a token that denies *everything*
        /// would pass a refused-outside test on its own.
        #[tokio::test]
        async fn a_workspace_shell_writes_inside_the_root_and_is_refused_outside() {
            let temp = tempfile::tempdir().expect("tempdir");
            let base = crate::workspace::canonical_for_test(temp.path());
            let work = base.join("work");
            let outside = base.join("outside");
            std::fs::create_dir(&work).expect("work");
            std::fs::create_dir(&outside).expect("outside");

            let mut tool = windows_test_tool(crate::permission::SharedPermission::new(
                Permission::Workspace,
                crate::permission::EnabledPermissions::ALL,
            ));
            tool.site.cwd = crate::workspace::SharedCwd::new(work.clone());
            tool.scope = crate::workspace::WriteScope::confined(vec![work.clone()]);

            let result = tool
                .execute(
                    serde_json::json!({
                        "command": format!(
                            "Set-Content -Path '{}\\inside.txt' -Value 'in'; \
                             Set-Content -Path '{}\\escaped.txt' -Value 'out'",
                            work.display(),
                            outside.display()
                        ),
                    }),
                    crate::tools::ToolContext::for_test(CancellationToken::new()),
                )
                .await
                .expect("execute should not error");

            // Ground truth on disk, not the tool's narration: a shell that never started would
            // report failure just as convincingly as one the ACE confined.
            assert!(
                work.join("inside.txt").exists(),
                "a write inside the granted root must land, but did not: {result:?}"
            );
            assert!(
                !outside.join("escaped.txt").exists(),
                "a write outside every root must be refused by the token, not by Meka: {result:?}"
            );

            tool.windows_grants.revoke_all();
        }

        /// The probe half of [`a_confined_child_reads_our_memory_at_workspace_and_cannot_at_read`].
        ///
        /// Re-entered as a child process rather than shelled out to, because the natural scripted
        /// probe cannot be trusted here: at `workspace` the `WRITE_RESTRICTED` token puts
        /// PowerShell into ConstrainedLanguage mode, where constructing the .NET types such a probe
        /// needs fails outright, and that failure is indistinguishable from a denied handle. This
        /// ran as a hand-cross-compiled C binary until the staging step became the only thing
        /// keeping the parent `#[ignore]`d.
        ///
        /// Stays ignored so a plain suite run never selects it, and no-ops when the handoff file is
        /// absent so selecting it by hand does nothing either. The parent passes the target through
        /// that file rather than the environment, because the spawn path hands the child a curated
        /// environment by design.
        #[tokio::test]
        #[ignore = "re-entered by its parent test; does nothing on its own"]
        async fn windows_process_read_probe_child() {
            let Ok(handoff) = std::fs::read_to_string(PROBE_HANDOFF) else {
                return;
            };
            let mut parts = handoff.split_whitespace();
            let (Some(pid), Some(address)) = (parts.next(), parts.next()) else {
                return;
            };
            let (Ok(pid), Ok(address)) = (pid.parse::<u32>(), usize::from_str_radix(address, 16))
            else {
                return;
            };

            use windows_sys::Win32::System::{
                Diagnostics::Debug::ReadProcessMemory,
                Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ},
            };

            // SAFETY: `pid` names a live process (the parent, which is blocked awaiting this
            // child), and the buffer is sized from itself. A denied handle comes back null and is
            // reported rather than dereferenced.
            let verdict = unsafe {
                let handle = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, 0, pid);
                if handle.is_null() {
                    format!(
                        "OPEN_FAILED {}",
                        std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
                    )
                } else {
                    let mut buffer = [0u8; 64];
                    let mut read = 0usize;
                    let ok = ReadProcessMemory(
                        handle,
                        address as *const std::ffi::c_void,
                        buffer.as_mut_ptr().cast(),
                        buffer.len(),
                        &mut read,
                    );
                    windows_sys::Win32::Foundation::CloseHandle(handle);
                    if ok == 0 {
                        format!(
                            "READ_FAILED {}",
                            std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
                        )
                    } else {
                        let text: String = buffer[..read]
                            .iter()
                            .copied()
                            .take_while(|byte| byte.is_ascii_graphic() || *byte == b' ')
                            .map(char::from)
                            .collect();
                        format!("READ_OK {text}")
                    }
                }
            };
            println!("{PROBE_VERDICT_PREFIX}{verdict}");
        }

        /// A `workspace` child can read Meka's own process memory; a `read` child cannot.
        ///
        /// The two levels are compared in one test because either result alone is uninformative: a
        /// token that denied everything would pass a "refused" assertion on its own merits, and a
        /// host where the probe simply failed to run would look like confinement.
        ///
        /// **The `read` leg is the guard.** Low integrity has to deny `OpenProcess` against Meka,
        /// and nothing else in the suite defends that. **The `workspace` leg is a tripwire on the
        /// documentation.** It asserts the measured weakness still exists, so hardening the spawn
        /// path fails this test and forces `docs/book/src/usage/permissions.md` to be corrected
        /// rather than left quietly wrong in the safe direction.
        ///
        /// Why the weakness exists: `WRITE_RESTRICTED` intersects the restricting SIDs for write
        /// access only, and the `workspace` path deliberately leaves the integrity label alone so
        /// ordinary tooling keeps working. Neither restricts a *read*, and Meka's memory holds
        /// provider credentials. Measured on hardware 2026-08-24: `workspace` returned the canary,
        /// `read` returned `ERROR_ACCESS_DENIED`.
        ///
        /// What this does **not** show is that an attacker could locate those credentials unaided.
        /// The parent hands the child the exact address, so this measures the capability -- a
        /// readable handle plus a successful read -- and not a search.
        #[tokio::test]
        async fn a_confined_child_reads_our_memory_at_workspace_and_cannot_at_read() {
            // Leaked so the marker stays mapped for as long as the child needs to read it.
            let secret: &'static str =
                Box::leak("MEKA-CANARY-7f3a91d4c8e2".to_string().into_boxed_str());
            let temp = tempfile::tempdir().expect("tempdir");
            let work = crate::workspace::canonical_for_test(temp.path());
            let runner = std::env::current_exe().expect("the test binary's own path");

            for (label, permission) in [
                ("workspace", Permission::Workspace),
                ("read", Permission::Read),
            ] {
                // Written fresh per leg, and inside the child's working directory, which is the
                // one path both confinements agree the child can reach.
                std::fs::write(
                    work.join(PROBE_HANDOFF),
                    format!("{} {:x}", std::process::id(), secret.as_ptr() as usize),
                )
                .expect("hand the target to the child");

                let mut tool = windows_test_tool(crate::permission::SharedPermission::new(
                    permission,
                    crate::permission::EnabledPermissions::ALL,
                ));
                tool.site.cwd = crate::workspace::SharedCwd::new(work.clone());
                tool.scope = crate::workspace::WriteScope::confined(vec![work.clone()]);

                let result = tool
                    .execute(
                        serde_json::json!({
                            "command": format!(
                                "& '{}' {} --ignored --exact --nocapture",
                                runner.display(),
                                probe_child_test_name()
                            ),
                        }),
                        crate::tools::ToolContext::for_test(CancellationToken::new()),
                    )
                    .await
                    .expect("execute should not error");

                let reported = format!("{result:?}");
                tool.windows_grants.revoke_all();
                assert!(
                    reported.contains(PROBE_VERDICT_PREFIX),
                    "the probe child did not report a verdict, so nothing below is meaningful: \
                     {reported}"
                );

                match permission {
                    // The canary itself, not just `READ_OK`: a read that succeeded against the
                    // wrong page and returned zeroes would satisfy the weaker check.
                    Permission::Workspace => assert!(
                        reported.contains("READ_OK") && reported.contains(secret),
                        "the `{label}` child could not read our memory. If the spawn path was \
                         hardened this is the good outcome, but permissions.md still documents \
                         the old one: {reported}"
                    ),
                    _ => assert!(
                        reported.contains("OPEN_FAILED"),
                        "`{label}` runs at Low integrity, which must refuse OpenProcess against \
                         Meka: {reported}"
                    ),
                }
            }
        }

        /// Under Low integrity, writing to the user's profile directory must be denied by the OS.
        /// The test probes a path under `%USERPROFILE%` and asserts the file is never created.
        #[tokio::test]
        async fn windows_sandbox_blocks_write_to_userprofile() {
            let probe_path = format!(
                "{}\\meka-sandbox-probe.txt",
                std::env::var("USERPROFILE").expect("USERPROFILE must be set on Windows")
            );
            // Clean any stray file from an earlier failed run before starting.
            let _ = std::fs::remove_file(&probe_path);

            let tool = windows_test_tool(read_permission());
            let _ = tool
                .execute(
                    serde_json::json!({
                        "command": format!("echo hello > \"{probe_path}\""),
                    }),
                    crate::tools::ToolContext::for_test(CancellationToken::new()),
                )
                .await
                .expect("execute should not error");

            let existed = std::path::Path::new(&probe_path).exists();
            // Defensive cleanup even if the assertion below fails.
            let _ = std::fs::remove_file(&probe_path);
            assert!(
                !existed,
                "Low-integrity sandbox should have blocked write to {probe_path}"
            );
        }

        /// A command that produces well over the default Windows pipe buffer (~4 KB) of output must
        /// complete without deadlocking and without truncation. Before the concurrent-drain fix,
        /// the child would block in `WriteFile` past the buffer, the wait would never return, and
        /// the tool would report a spurious timeout.
        #[tokio::test]
        async fn windows_sandbox_large_output_under_sandbox() {
            let tool = windows_test_tool(read_permission());
            // PowerShell builds a 262144-char string in memory then emits it as one line. Total
            // output is ~256 KB, well past any plausible pipe buffer.
            let result = tool
                .execute(
                    serde_json::json!({
                        "command": "'x' * 262144",
                        "timeout_ms": 60000u64,
                    }),
                    crate::tools::ToolContext::for_test(CancellationToken::new()),
                )
                .await
                .expect("execute should not error");

            assert!(
                !result.is_error,
                "large-output command should not be flagged as an error"
            );
            let text = result.text_content();
            let x_count = text.matches('x').count();
            assert!(
                x_count >= 262144,
                "expected >= 262144 'x' characters in output, got {x_count}"
            );
        }

        /// The child's stdin must be connected to `NUL`, not inherited from the agent's TTY and not
        /// left as an invalid handle. `$input` enumerates pipeline input; piped from NUL it yields
        /// zero objects. The command must complete promptly rather than hanging on a dangling
        /// stdin.
        #[tokio::test]
        async fn windows_sandbox_stdin_is_null() {
            let tool = windows_test_tool(read_permission());
            let result = tokio::time::timeout(
                std::time::Duration::from_secs(10),
                tool.execute(
                    serde_json::json!({
                        "command": "($input | Measure-Object).Count",
                        "timeout_ms": 5000u64,
                    }),
                    crate::tools::ToolContext::for_test(CancellationToken::new()),
                ),
            )
            .await
            .expect("command must not hang waiting for stdin")
            .expect("execute should not error");

            assert!(!result.is_error);
            let text = result.text_content();
            assert!(
                text.trim().starts_with('0'),
                "expected stdin-object count of 0, got {text:?}"
            );
        }

        /// Round-trip a grab-bag of tricky marker strings through PowerShell to confirm
        /// `quote_command_arg` + PowerShell's argv parser are inverses. Uses PowerShell
        /// single-quote literals internally so the test exercises our command-line encoding, not PS
        /// string rules.
        #[tokio::test]
        async fn windows_sandbox_quoting_roundtrip() {
            let tool = windows_test_tool(read_permission());

            let cases: &[&str] = &[
                "plain",
                "with spaces",
                r#"quotes "inside""#,
                r"back\slashes",
                "meta & chars | pipe > redir",
                "日本語 unicode",
            ];
            for marker in cases {
                // Escape ' as '' inside the PS single-quote literal.
                let script = format!("Write-Output '{}'", marker.replace('\'', "''"));
                let result = tool
                    .execute(
                        serde_json::json!({ "command": script, "timeout_ms": 10000u64 }),
                        crate::tools::ToolContext::for_test(CancellationToken::new()),
                    )
                    .await
                    .expect("execute should not error");
                assert!(!result.is_error, "command for marker {marker:?} errored");
                let text = result.text_content();
                assert!(
                    text.contains(marker),
                    "marker {marker:?} missing from output {text:?}"
                );
            }
        }

        /// Regression test for the parent-env-inheritance leak: secrets set in the parent (API
        /// keys, OAuth tokens) must not appear in the sandboxed child's environment, because a
        /// Low-integrity child can still open outbound sockets and exfiltrate them.
        #[tokio::test]
        async fn windows_sandbox_scrubs_provider_api_keys() {
            // SAFETY: tests run under `cargo test`, which is single-threaded per target by default
            // for integration tests, and this env var is scoped to the test's probe command.
            // Acceptable for a test.
            unsafe {
                std::env::set_var("ANTHROPIC_API_KEY", "probe-12345-leaked");
            }

            let tool = windows_test_tool(read_permission());
            let result = tool
                .execute(
                    serde_json::json!({
                        "command": "$env:ANTHROPIC_API_KEY",
                        "timeout_ms": 10000u64,
                    }),
                    crate::tools::ToolContext::for_test(CancellationToken::new()),
                )
                .await
                .expect("execute should not error");

            unsafe {
                std::env::remove_var("ANTHROPIC_API_KEY");
            }

            let text = result.text_content();
            assert!(
                !text.contains("probe-12345-leaked"),
                "parent API key leaked into sandboxed child env: {text:?}"
            );
        }

        /// Reads must still succeed under Low integrity. The hosts file is readable by Everyone on
        /// stock Windows, so it's a good probe.
        #[tokio::test]
        async fn windows_sandbox_allows_read() {
            let tool = windows_test_tool(read_permission());
            let result = tool
                .execute(
                    serde_json::json!({
                        "command": "type C:\\Windows\\System32\\drivers\\etc\\hosts",
                    }),
                    crate::tools::ToolContext::for_test(CancellationToken::new()),
                )
                .await
                .expect("execute should not error");

            assert!(
                !result.is_error,
                "reading %WINDIR%\\System32\\drivers\\etc\\hosts should succeed under Low integrity"
            );
        }
    }

    /// The Bubblewrap workspace binding, exercised against a real `bwrap`.
    ///
    /// The Landlock dialect had a live confinement test and Bubblewrap had none, which left the
    /// ordering rule in `bwrap_args` unguarded: bind before the tmpfs masks and every workspace
    /// under `/tmp` silently comes out read-only, with bwrap reporting success. Both halves are
    /// checked here, the order in the argument list and the outcome on disk, because the first
    /// is what a future edit would break and the second is what a user would feel.
    #[cfg(target_os = "linux")]
    mod bubblewrap_boundary {
        use std::path::PathBuf;

        /// A mask is kept over a directory that exists and dropped over a path that does not, which
        /// Bubblewrap cannot make a mount point for under the read-only root.
        #[test]
        fn a_mask_is_kept_over_a_directory_and_dropped_where_there_is_none() {
            let dir = tempfile::tempdir().expect("tempdir");
            let missing = dir.path().join("never-made");
            assert_eq!(
                super::existing_directories(vec![dir.path().to_path_buf(), missing]),
                [dir.path().to_path_buf()]
            );
        }

        /// With reads confined the root is an empty tmpfs and only the readable paths are bound,
        /// read-only, after the masks and before the writable binds; `/dev` and `/proc` stay the
        /// sandbox's own rather than the host's.
        #[test]
        fn a_confined_read_set_starts_from_an_empty_root_and_binds_only_what_it_names() {
            let work = PathBuf::from("/tmp/work");
            let readable = vec![
                PathBuf::from("/usr"),
                PathBuf::from("/etc"),
                PathBuf::from("/dev"),
                PathBuf::from("/proc"),
                work.clone(),
            ];
            let text: Vec<String> = super::bwrap_args(
                std::slice::from_ref(&work),
                Some(&readable),
                &work,
                &[],
                crate::config::Network::Host,
            )
            .iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();
            let at = |pair: [&str; 2]| text.windows(2).position(|w| w == pair);
            assert_eq!(at(["--tmpfs", "/"]), Some(2), "the root is empty: {text:?}");
            assert!(
                !text.windows(3).any(|w| w == ["--ro-bind", "/", "/"]),
                "the host's root is not bound: {text:?}"
            );
            let bound = |path: &str| at(["--ro-bind-try", path]);
            assert!(
                bound("/usr").is_some() && bound("/etc").is_some(),
                "{text:?}"
            );
            assert!(
                bound("/dev").is_none() && bound("/proc").is_none(),
                "the host's /dev and /proc must not replace the sandbox's: {text:?}"
            );
            let last_mask = at(["--tmpfs", "/var/tmp"]).expect("a mask");
            let first_bind = bound("/usr").expect("a bind");
            let rw = at(["--bind-try", "/tmp/work"]).expect("the writable root");
            assert!(last_mask < first_bind && first_bind < rw, "{text:?}");
        }

        /// The inner layer is told the readable paths too, so the Landlock ruleset inside bwrap
        /// confines reads as the mounts do.
        #[test]
        fn the_inner_layer_is_told_the_readable_directories() {
            let readable = vec![PathBuf::from("/usr"), PathBuf::from("/home/someone/work")];
            let text: Vec<String> = super::inner_confinement_argv(
                std::path::Path::new("/proc/self/fd/7"),
                &[PathBuf::from("/home/someone/work")],
                Some(&readable),
            )
            .iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();
            let after = |flag: &str| -> Vec<&str> {
                text.windows(2)
                    .filter(|w| w[0] == flag)
                    .map(|w| w[1].as_str())
                    .collect()
            };
            assert_eq!(after("--readable"), ["/usr", "/home/someone/work"]);
            assert_eq!(after("--writable"), ["/home/someone/work"]);
            let unconfined =
                super::inner_confinement_argv(std::path::Path::new("/proc/self/fd/7"), &[], None);
            assert!(
                !unconfined.iter().any(|arg| arg == "--readable"),
                "reading everywhere names no readable path"
            );
        }

        /// End-to-end through a real bwrap: a confined command reads its root and the platform's
        /// own directories, and nothing else exists for it, the home directory included.
        #[test]
        fn a_bubblewrapped_shell_with_confined_reads_sees_nothing_outside_its_roots() {
            let Some(bwrap) = which_bwrap() else {
                return;
            };
            let temp = tempfile::tempdir().expect("tempdir");
            let base = crate::workspace::canonical_for_test(temp.path());
            let work = base.join("work");
            let outside = base.join("outside");
            std::fs::create_dir(&work).expect("work");
            std::fs::create_dir(&outside).expect("outside");
            std::fs::write(work.join("inside.txt"), "inside\n").expect("write");
            std::fs::write(outside.join("secret.txt"), "secret\n").expect("write");
            let home = std::env::var_os("HOME").map(PathBuf::from);
            let boundary = crate::workspace::ReadBoundary::new(true, &[], &[]);
            let readable: Vec<PathBuf> = std::iter::once(work.clone())
                .chain(boundary.base.iter().cloned())
                .collect();

            let script = format!(
                "cat {work}/inside.txt >/dev/null 2>&1 || exit 3\n\
                 ls /usr/bin >/dev/null 2>&1 || exit 5\n\
                 if cat {outside}/secret.txt >/dev/null 2>&1; then exit 4; fi\n\
                 if [ -e {outside} ]; then exit 6; fi\n\
                 {home_check}\n\
                 exit 0",
                work = work.display(),
                outside = outside.display(),
                home_check = match &home {
                    Some(home) =>
                        format!("if ls {} >/dev/null 2>&1; then exit 7; fi", home.display()),
                    None => String::new(),
                },
            );
            let status = std::process::Command::new(bwrap)
                .args(super::bwrap_args(
                    &[],
                    Some(&readable),
                    &work,
                    &[],
                    crate::config::Network::Host,
                ))
                .arg("--")
                .arg("sh")
                .arg("-c")
                .arg(&script)
                .status()
                .expect("spawn bwrap");
            match status.code() {
                Some(0) => {}
                Some(3) => panic!("the read inside the root was refused"),
                Some(4) => panic!("the read outside every root was permitted"),
                Some(5) => panic!("the system directories were not readable"),
                Some(6) => panic!("a directory outside the roots was visible"),
                Some(7) => panic!("the home directory was visible"),
                other => panic!("bwrap did not run the command: exit {other:?}"),
            }
        }

        /// A confined command under a writable root cannot rename or remove a directory on the
        /// way down to a private one. The masks name paths, so a rename would leave the next
        /// command's mask over an empty directory and the credential store readable where it went.
        #[test]
        fn a_bubblewrapped_shell_cannot_move_a_private_directory_from_under_its_mask() {
            let Some(bwrap) = which_bwrap() else {
                return;
            };
            let temp = tempfile::tempdir().expect("tempdir");
            let home = crate::workspace::canonical_for_test(temp.path());
            let private = home.join(".local").join("share").join("meka");
            std::fs::create_dir_all(&private).expect("private");
            std::fs::write(private.join("meka.db"), "secret\n").expect("write");

            let status = std::process::Command::new(bwrap)
                .args(super::bwrap_args(
                    std::slice::from_ref(&home),
                    None,
                    &home,
                    std::slice::from_ref(&private),
                    crate::config::Network::Host,
                ))
                .arg("--")
                .arg("sh")
                .arg("-c")
                .arg(
                    "mv .local .local.moved 2>/dev/null; mv .local/share .local/moved \
                     2>/dev/null; rmdir .local/share/meka 2>/dev/null; touch .local/written; \
                     exit 0",
                )
                .status()
                .expect("spawn bwrap");
            assert!(
                status.success(),
                "bwrap did not run the command: {status:?}"
            );
            assert!(
                private.join("meka.db").exists(),
                "the private directory moved out from under its mask"
            );
            assert!(
                home.join(".local").join("written").exists(),
                "a write inside the root was refused"
            );
        }

        /// The level `shell_execute` needs depends on whether a sandbox can actually confine it.
        ///
        /// `read` only when the sandbox is both enabled *and* backed by a working backend;
        /// otherwise `unrestricted`, because a command Meka cannot confine is a command only the
        /// boundary-free level may authorize. The conjunction is the whole rule: flipped to `||`,
        /// the tool would be offered at `read` with `[shell].sandbox = false`, or with the sandbox
        /// on but no usable backend. The runtime guard in `execute` still refuses the command in
        /// both cases, so this is a wrong catalog entry rather than an escape, but the catalog is
        /// what the model plans against.
        #[test]
        fn the_shell_needs_unrestricted_whenever_nothing_can_confine_it() {
            use crate::{permission::Permission, sandbox::SandboxCapability, tools::Tool};

            let check =
                |sandbox_enabled: bool, capability: SandboxCapability, expected: Permission| {
                    let mut tool = super::tool_for_test(
                        crate::permission::SharedPermission::new(
                            Permission::Read,
                            crate::permission::EnabledPermissions::ALL,
                        ),
                        sandbox_enabled,
                    );
                    tool.sandbox_capability = capability.clone();
                    assert_eq!(
                        tool.required_permission(),
                        expected,
                        "sandbox_enabled={sandbox_enabled}, capability={capability:?}"
                    );
                };

            // Nothing can confine: either Meka was told not to, or the host offers no backend.
            check(
                true,
                SandboxCapability::Unavailable,
                Permission::Unrestricted,
            );
            check(
                false,
                SandboxCapability::Unavailable,
                Permission::Unrestricted,
            );

            // Which backend is available does not enter the rule, and the variants are
            // per-platform, so the positive leg uses whatever this host actually has.
            // Skipped rather than faked where there is none: an invented variant would
            // assert against a state Meka cannot reach here.
            let available = crate::sandbox::detect();
            if matches!(available, SandboxCapability::Unavailable) {
                eprintln!("skipping the confined leg: no sandbox backend on this host");
                return;
            }
            check(true, available.clone(), Permission::Read);
            check(false, available, Permission::Unrestricted);
        }

        /// A cwd that *is* a masked directory must not be bound back over its own mask.
        ///
        /// The cwd bind and the tmpfs masks obey the same rule (last mount wins), so an
        /// unconditional bind hands a masked-directory session the host directory: a session at
        /// `/tmp` could `connect()` the tmux socket, one at `$XDG_RUNTIME_DIR` the session bus, and
        /// one at `/` would see the host's PIDs, defeating `--unshare-pid` as well. A read-only
        /// bind does not help, because `connect(2)` on a socket inode is not a write.
        ///
        /// `/` is in the table because it is systemd's default working directory for a daemon, so
        /// `meka serve` under a unit file lands there without anyone choosing it.
        ///
        /// The counterpart is `the_child_is_given_a_working_directory_it_can_reach`: a path merely
        /// *under* a mask still needs its bind, and still gets one.
        #[test]
        fn a_masked_working_directory_is_not_bound_back_over_its_own_mask() {
            let masked = [
                std::path::PathBuf::from("/tmp"),
                std::path::PathBuf::from("/var/tmp"),
                std::path::PathBuf::from("/run"),
                std::path::PathBuf::from("/"),
            ];
            for cwd in masked {
                let text: Vec<String> =
                    super::bwrap_args(&[], None, &cwd, &[], crate::config::Network::Host)
                        .iter()
                        .map(|arg| arg.to_string_lossy().into_owned())
                        .collect();

                // The bind is what undoes the mask, so its absence is the property. Checked as an
                // adjacent pair rather than by searching for the path alone, because `/tmp` also
                // appears as a `--tmpfs` operand and `/` as the `--ro-bind / /` operand.
                let rebound = text.windows(3).any(|window| {
                    window[0] == "--ro-bind-try"
                        && window[1] == cwd.to_string_lossy()
                        && window[2] == cwd.to_string_lossy()
                });
                assert!(
                    !rebound,
                    "binding {} back over its own mask restores the host directory the mask hides, \
                     which is the sandbox escape `is_system_root` exists to prevent: {text:?}",
                    cwd.display()
                );

                // And the child still has somewhere to stand: the mask leaves an empty tmpfs at
                // that path, so `--chdir` succeeds and nothing is silently relocated to `$HOME`.
                let chdir = text
                    .iter()
                    .position(|arg| arg == "--chdir")
                    .expect("the cwd must still be requested explicitly");
                assert_eq!(
                    text.get(chdir + 1).map(String::as_str),
                    Some(cwd.to_string_lossy().as_ref()),
                    "the masked cwd is still where the child starts"
                );
            }
        }

        /// The child is told which directory to start in, and can read it.
        ///
        /// bwrap's fallback when it cannot enter the pre-`execve` cwd is silent and lands the child
        /// in `$HOME`: without these two arguments `pwd` reports the user's home directory and the
        /// workspace is unreachable even by absolute path, with exit 0 and empty stderr; with them
        /// `pwd` is correct, the file reads, and a write is still refused read-only at `read`.
        ///
        /// The bind sits after the masks and before the writable binds, so a cwd under `/tmp` is
        /// restored, and a cwd that is also a writable root is upgraded to read-write by the loop
        /// that follows: last mount wins.
        /// `--unshare-net` goes with every setting but `host`: `remote`, which the namespace
        /// cannot express, is cut off whole rather than let through.
        #[test]
        #[cfg(target_os = "linux")]
        fn the_network_is_unshared_on_every_setting_but_host() {
            let cwd = PathBuf::from("/tmp/session-cwd");
            for (network, unshared) in [
                (crate::config::Network::Host, false),
                (crate::config::Network::Remote, true),
                (crate::config::Network::None, true),
            ] {
                let args = super::bwrap_args(&[], None, &cwd, &[], network);
                assert_eq!(
                    args.iter().any(|arg| arg == "--unshare-net"),
                    unshared,
                    "{network}"
                );
            }
        }

        #[test]
        #[cfg(target_os = "linux")]
        fn the_child_is_given_a_working_directory_it_can_reach() {
            let cwd = PathBuf::from("/tmp/session-cwd");
            let args = super::bwrap_args(&[], None, &cwd, &[], crate::config::Network::Host);
            let text: Vec<String> = args
                .iter()
                .map(|arg| arg.to_string_lossy().into_owned())
                .collect();

            let chdir = text.iter().position(|arg| arg == "--chdir");
            assert!(
                chdir.is_some(),
                "the cwd must be requested explicitly: {text:?}"
            );
            assert_eq!(
                text.get(chdir.expect("checked above") + 1)
                    .map(String::as_str),
                Some("/tmp/session-cwd")
            );

            let bind = text
                .iter()
                .position(|arg| arg == "--ro-bind-try")
                .expect("the cwd must be bound back in, or `read` cannot see it");
            let last_mask = text
                .iter()
                .rposition(|arg| arg == "--tmpfs")
                .expect("the masks are always present");
            assert!(
                bind > last_mask,
                "a cwd bound before the masks is undone by them: {text:?}"
            );

            // A cwd that is also a writable root ends up read-write, because the rw bind comes
            // later.
            let rw = super::bwrap_args(
                std::slice::from_ref(&cwd),
                None,
                &cwd,
                &[],
                crate::config::Network::Host,
            );
            let rw: Vec<String> = rw
                .iter()
                .map(|arg| arg.to_string_lossy().into_owned())
                .collect();
            let ro_at = rw.iter().position(|arg| arg == "--ro-bind-try");
            let rw_at = rw.iter().position(|arg| arg == "--bind-try");
            assert!(
                ro_at < rw_at,
                "the writable bind must win over the read-only one: {rw:?}"
            );
        }

        #[test]
        fn every_workspace_bind_comes_after_every_mask() {
            let args = super::bwrap_args(
                &[PathBuf::from("/tmp/work")],
                None,
                std::path::Path::new("/tmp/work"),
                &[],
                crate::config::Network::Host,
            );
            let last_mask = args
                .iter()
                .rposition(|arg| arg == "--tmpfs")
                .expect("the masks are part of the recipe");
            let bind = args
                .iter()
                .position(|arg| arg == "--bind-try")
                .expect("the workspace root is bound");
            assert!(
                bind > last_mask,
                "a bind before a mask is undone by it, silently: {args:?}"
            );
        }

        #[test]
        fn a_bubblewrapped_shell_writes_inside_the_root_and_is_refused_outside() {
            let Some(bwrap) = which_bwrap() else {
                // Not `#[ignore]`: this must run wherever bwrap exists, and skipping loudly beats a
                // test that silently never runs on the machines that have the backend.
                eprintln!("skipping: bwrap is not on PATH");
                return;
            };

            let temp = tempfile::tempdir().expect("tempdir");
            let base = crate::workspace::canonical_for_test(temp.path());
            let work = base.join("work");
            std::fs::create_dir(&work).expect("work");

            // The "outside" target lives in `$HOME`, not beside the workspace.
            //
            // A sibling under the tempdir is itself under `/tmp`, which the recipe masks with a
            // tmpfs, so a write there fails with ENOENT: the directory does not exist inside the
            // namespace at all. That is not the boundary refusing anything, and it would keep
            // passing with the boundary removed. `$HOME` is present and writable outside the
            // sandbox, so a refusal there is the ruleset's doing.
            let outside = crate::workspace::canonical_for_test(
                std::env::var_os("HOME")
                    .map(std::path::PathBuf::from)
                    .unwrap_or_else(std::env::temp_dir),
            )
            .join(format!("meka-bwrap-probe-{}", uuid::Uuid::new_v4()));
            assert!(!outside.exists(), "the probe target must start absent");

            // `base` is under `/tmp` on virtually every machine, so this is also the regression:
            // the root has to survive the `--tmpfs /tmp` that the recipe applies before
            // binding it.
            let script = format!(
                "echo in > {}/inside.txt 2>/dev/null || exit 3\n\
                 if echo out > {} 2>/dev/null; then exit 4; fi\n\
                 exit 0",
                work.display(),
                outside.display()
            );

            let status = std::process::Command::new(bwrap)
                .args(super::bwrap_args(
                    std::slice::from_ref(&work),
                    None,
                    &work,
                    &[],
                    crate::config::Network::Host,
                ))
                .arg("--")
                .arg("sh")
                .arg("-c")
                .arg(&script)
                .status()
                .expect("spawn bwrap");

            match status.code() {
                Some(0) => {}
                Some(3) => panic!("the write inside the workspace root was refused"),
                Some(4) => panic!("the write outside every root was permitted"),
                other => panic!("bwrap did not run the command: exit {other:?}"),
            }
            // The bytes are visible outside the namespace, which is what makes the bind a bind
            // rather than a tmpfs the child happened to be able to write.
            assert_eq!(
                std::fs::read_to_string(work.join("inside.txt")).expect("read back"),
                "in\n"
            );
            assert!(
                !outside.exists(),
                "the write outside every root must not have landed in $HOME: {}",
                outside.display()
            );
            let _ = std::fs::remove_file(&outside);
        }

        /// The masks over Meka's own directories come after every bind, so a writable root that
        /// contains the store does not hand it back: later mounts win.
        #[test]
        fn meka_s_own_directories_are_masked_after_every_writable_bind() {
            let root = std::path::PathBuf::from("/home/someone");
            let store = root.join(".local/share/meka");
            let text: Vec<String> = super::bwrap_args(
                std::slice::from_ref(&root),
                None,
                &root,
                std::slice::from_ref(&store),
                crate::config::Network::Host,
            )
            .iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();
            let bind_at = text
                .windows(3)
                .position(|window| {
                    window[0] == "--bind-try"
                        && window[1] == root.to_string_lossy()
                        && window[2] == root.to_string_lossy()
                })
                .expect("the root is bound writable");
            let mask_at = text
                .windows(2)
                .position(|window| window[0] == "--tmpfs" && window[1] == store.to_string_lossy())
                .expect("the store is masked");
            let chdir_at = text
                .iter()
                .position(|arg| arg == "--chdir")
                .expect("the working directory is entered last");
            assert!(
                bind_at < mask_at && mask_at < chdir_at,
                "the mask must come after the bind it has to beat and before the chdir: {text:?}"
            );
        }

        /// The store stays hidden under a writable root that contains it, on real bubblewrap.
        #[test]
        fn a_confined_shell_cannot_read_meka_s_store_under_a_workspace_directory() {
            let Some(bwrap) = which_bwrap() else {
                eprintln!("bwrap not installed; skipping");
                return;
            };
            let temp = tempfile::tempdir().expect("tempdir");
            let root = crate::workspace::canonical_for_test(temp.path());
            let store = root.join("meka-store");
            std::fs::create_dir(&store).expect("store");
            std::fs::write(store.join("meka.db"), "secret").expect("seed the store");
            let work = root.join("work");
            std::fs::create_dir(&work).expect("work");

            let script = format!(
                "if cat {}/meka.db >/dev/null 2>&1; then exit 4; fi\n\
                 echo ok > {}/inside.txt 2>/dev/null || exit 3\n\
                 exit 0",
                store.display(),
                work.display()
            );
            let status = std::process::Command::new(bwrap)
                .args(super::bwrap_args(
                    std::slice::from_ref(&root),
                    None,
                    &work,
                    std::slice::from_ref(&store),
                    crate::config::Network::Host,
                ))
                .arg("--")
                .arg("sh")
                .arg("-c")
                .arg(&script)
                .status()
                .expect("spawn bwrap");
            match status.code() {
                Some(0) => {}
                Some(4) => panic!("the store was readable inside a root that contains it"),
                Some(3) => panic!("the write inside the workspace root was refused"),
                other => panic!("bwrap did not run the command: exit {other:?}"),
            }
            assert_eq!(
                std::fs::read_to_string(work.join("inside.txt")).expect("read back"),
                "ok\n"
            );
        }

        /// The layer is told to keep writable exactly what bwrap made writable: the roots as
        /// roots, every mask and `/dev` as scratch, never the other way around, since a mask
        /// passed as a root would hand back the sockets a bind can put under it. Its argv ends in
        /// `--`, so the shell after it is never read as a flag.
        #[test]
        fn the_inner_layer_keeps_the_roots_the_masks_and_dev_writable() {
            let text = strings(&super::inner_confinement_argv(
                std::path::Path::new("/proc/self/fd/7"),
                &[PathBuf::from("/home/someone/work")],
                None,
            ));
            assert_eq!(&text[..2], ["/proc/self/fd/7", "confine"]);
            let after = |flag: &str| -> Vec<&str> {
                text.windows(2)
                    .filter(|window| window[0] == flag)
                    .map(|window| window[1].as_str())
                    .collect()
            };
            assert_eq!(after("--writable"), ["/home/someone/work"]);
            let scratch = after("--scratch");
            for expected in ["/tmp", "/run", "/var/tmp", "/dev"] {
                assert!(
                    scratch.contains(&expected),
                    "'{expected}' must stay writable inside, as scratch: {text:?}"
                );
            }
            assert_eq!(text.last().map(String::as_str), Some("--"));
        }

        /// The built `meka` beside the test binary (`target/debug/meka`), which `cargo test`
        /// builds for the integration tests. A test binary has no `confine` verb, so the layer's
        /// tests need the real one; absent (a bare `cargo test --bin meka`), they skip loudly.
        pub(super) fn meka_binary_for_test() -> Option<PathBuf> {
            let binary = std::env::current_exe()
                .ok()?
                .parent()?
                .parent()?
                .join("meka");
            binary.is_file().then_some(binary)
        }

        pub(super) fn on_path(name: &str) -> Option<PathBuf> {
            let path = std::env::var_os("PATH")?;
            std::env::split_paths(&path)
                .map(|dir| dir.join(name))
                .find(|candidate| candidate.is_file())
        }

        fn strings(args: &[std::ffi::OsString]) -> Vec<String> {
            args.iter()
                .map(|arg| arg.to_string_lossy().into_owned())
                .collect()
        }

        /// The network namespace is unshared on `none` and kept on `host`.
        #[test]
        fn the_bubblewrap_arguments_unshare_the_network_only_on_none() {
            let cwd = PathBuf::from("/tmp/session-cwd");
            let open = strings(&super::bwrap_args(
                &[],
                None,
                &cwd,
                &[],
                crate::config::Network::Host,
            ));
            assert!(!open.iter().any(|arg| arg == "--unshare-net"), "{open:?}");
            let closed = strings(&super::bwrap_args(
                &[],
                None,
                &cwd,
                &[],
                crate::config::Network::None,
            ));
            assert!(
                closed.iter().any(|arg| arg == "--unshare-net"),
                "{closed:?}"
            );
        }

        /// On real bubblewrap, a command cannot connect to a TCP port on `none` and can on
        /// `host`, against a listener this test holds.
        #[test]
        fn a_confined_shell_cannot_connect_on_none() {
            let Some(bwrap) = which_bwrap() else {
                eprintln!("bwrap not installed; skipping");
                return;
            };
            let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("listen");
            let port = listener.local_addr().expect("address").port();
            let temp = tempfile::tempdir().expect("tempdir");
            let work = crate::workspace::canonical_for_test(temp.path());
            let script = format!(
                "python3 -c \"import socket; socket.create_connection(('127.0.0.1', {port}), 2)\" \
                 >/dev/null 2>&1 && exit 5; exit 6"
            );
            let exit_under = |network: crate::config::Network| -> Option<i32> {
                std::process::Command::new(&bwrap)
                    .args(super::bwrap_args(&[], None, &work, &[], network))
                    .arg("--")
                    .arg("sh")
                    .arg("-c")
                    .arg(&script)
                    .status()
                    .expect("spawn bwrap")
                    .code()
            };
            assert_eq!(
                exit_under(crate::config::Network::Host),
                Some(5),
                "the listener must be reachable on `host`, or the test proves nothing"
            );
            assert_eq!(
                exit_under(crate::config::Network::None),
                Some(6),
                "the connect must fail on `none`"
            );
        }

        /// Every mount a confined command sees is read-only, in both forms of the root, unless
        /// it is the workspace, a mask, Meka's own directory, `/dev` or `/proc`: the sandbox's
        /// whole promise rests on no bind landing read-write by mistake, and a regression fails
        /// here rather than in an audit.
        #[test]
        fn every_mount_a_confined_shell_sees_is_read_only_outside_the_workspace() {
            let Some(bwrap) = which_bwrap() else {
                eprintln!("bwrap not installed; skipping");
                return;
            };
            let temp = tempfile::tempdir().expect("tempdir");
            let root = crate::workspace::canonical_for_test(temp.path());
            let work = root.join("work");
            let private = root.join("meka-store");
            for directory in [&work, &private] {
                std::fs::create_dir(directory).expect("mkdir");
            }
            let base = crate::workspace::ReadBoundary::new(true, &[], &[]).base;
            let confined: Vec<PathBuf> = std::iter::once(root.clone()).chain(base).collect();
            // Writable by design: the masks and Meka's directory are empty tmpfs, `/dev` and
            // `/proc` are the sandbox's own, and so is the empty root when reads are confined.
            let scratch: Vec<PathBuf> = super::bwrap_masks()
                .into_iter()
                .chain([private.clone()])
                .collect();
            for (form, readable) in [
                ("reading everywhere", None),
                ("reads confined", Some(confined.as_slice())),
            ] {
                let output = std::process::Command::new(&bwrap)
                    .args(super::bwrap_args(
                        std::slice::from_ref(&work),
                        readable,
                        &work,
                        std::slice::from_ref(&private),
                        crate::config::Network::Host,
                    ))
                    .arg("--")
                    .arg("cat")
                    .arg("/proc/self/mountinfo")
                    .output()
                    .expect("spawn bwrap");
                assert!(
                    output.status.success(),
                    "{form}: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
                let table = String::from_utf8_lossy(&output.stdout);
                // A shadowed mount stays listed, so the workspace is read-write when any of its
                // lines is: the later bind is the one in effect.
                let mut workspace_read_write = false;
                for line in table.lines() {
                    // `<id> <parent> <major:minor> <root> <mount point> <options> ... - <type> ...`
                    let fields: Vec<&str> = line.split(' ').collect();
                    let point = std::path::Path::new(fields[4]);
                    let read_only = fields[5].split(',').any(|option| option == "ro");
                    if point == work {
                        workspace_read_write |= !read_only;
                        continue;
                    }
                    let sandbox_own = point.starts_with("/dev")
                        || point.starts_with("/proc")
                        || (readable.is_some() && point == std::path::Path::new("/"));
                    if sandbox_own || scratch.iter().any(|mask| point == mask) {
                        continue;
                    }
                    assert!(
                        read_only,
                        "{form}: a mount outside the workspace is read-write: {line}"
                    );
                }
                assert!(
                    workspace_read_write,
                    "{form}: the workspace must be mounted read-write:\n{table}"
                );
            }
        }

        fn which_bwrap() -> Option<std::path::PathBuf> {
            let path = std::env::var_os("PATH")?;
            std::env::split_paths(&path)
                .map(|dir| dir.join("bwrap"))
                .find(|candidate| candidate.is_file())
        }
    }

    /// `shell_execute` at `workspace`, end to end, on a real Unix sandbox.
    ///
    /// The Linux dialects are each tested through their helpers (`bwrap_args`, `apply_landlock`)
    /// with a hand-built root list, so nothing else exercises the wire between `Confinement` and
    /// the backend: cut it (`bwrap_args(&[], crate::config::Network::Host)`, `apply_landlock(abi,
    /// &[])`) and the workspace shell is silently read-only, which is the level's central
    /// promise.
    #[cfg(unix)]
    mod workspace_shell_boundary {

        use tokio_util::sync::CancellationToken;

        use super::*;

        #[tokio::test]
        async fn a_workspace_shell_writes_inside_the_root_and_is_refused_outside() {
            // Every backend this host can actually run, not just the one `detect()` names:
            // `detect()` on Linux only consults `probe_landlock`, so it never returns `Bubblewrap`,
            // while production resolves the backend through `resolve_sandbox_backend`, which
            // auto-prefers Bubblewrap whenever `bwrap` probes OK. Testing only what `detect()`
            // returns would leave `Confinement::writable() -> bwrap_args` unexercised end to end on
            // the backend most hosts actually use.
            let mut backends = Vec::new();
            let detected = crate::sandbox::detect();
            if !matches!(detected, crate::sandbox::SandboxCapability::Unavailable) {
                backends.push(detected);
            }
            backends.extend(a_backend_detect_does_not_name());
            // Skip rather than fail where no backend exists: this asserts what confinement does,
            // and a host without one has nothing to assert against. Loud, so it cannot
            // silently never run.
            if backends.is_empty() {
                eprintln!("skipping: no usable sandbox backend on this host");
                return;
            }

            for capability in backends {
                eprintln!("workspace boundary against {capability:?}");
                a_workspace_shell_boundary_holds_for(capability).await;
            }
        }

        /// A backend production would choose that [`crate::sandbox::detect`] does not name.
        ///
        /// Linux only. `detect()` there consults `probe_landlock` alone, so it never returns
        /// `Bubblewrap`, while production resolves through `resolve_sandbox_backend`, which
        /// auto-prefers Bubblewrap whenever `bwrap` probes OK.
        ///
        /// Split behind a `cfg` rather than pushed inline because `SandboxCapability::Bubblewrap`
        /// is itself `cfg(target_os = "linux")`: this module is `cfg(all(test, unix))`, so naming
        /// the variant unconditionally fails the macOS build.
        #[cfg(target_os = "linux")]
        fn a_backend_detect_does_not_name() -> Option<crate::sandbox::SandboxCapability> {
            // Deliberately not `sandbox::bwrap_on_path`, which demands a root-owned binary: this
            // only answers "can this test spawn it", and a developer with a local build in
            // `~/.local/bin` should still get the leg run rather than silently skipped.
            let path = std::env::var_os("PATH")?;
            let bwrap_path = std::env::split_paths(&path)
                .map(|dir| dir.join("bwrap"))
                .find(|candidate| candidate.is_file())?;
            // The layer inside needs the built `meka`, which a test binary is not; without it the
            // leg exercises bwrap alone.
            let landlock_abi = match super::bubblewrap_boundary::meka_binary_for_test()
                .and_then(|binary| std::fs::File::open(binary).ok())
            {
                Some(executable) => {
                    super::super::INNER_LAYER_EXECUTABLE
                        .with(|slot| *slot.borrow_mut() = Some(executable));
                    crate::sandbox::layer_landlock_abi()
                }
                None => None,
            };
            Some(crate::sandbox::SandboxCapability::Bubblewrap {
                bwrap_path,
                landlock_abi,
            })
        }

        /// One `read` call through the tool under `capability`, from `cwd`, and the text it
        /// returned.
        #[cfg(target_os = "linux")]
        async fn read_shell_text(
            capability: crate::sandbox::SandboxCapability,
            cwd: &std::path::Path,
            command: &str,
        ) -> String {
            let mut tool = super::tool_for_test(
                crate::permission::SharedPermission::new(
                    Permission::Read,
                    crate::permission::EnabledPermissions::ALL,
                ),
                true,
            );
            tool.backend_probe = crate::sandbox::BackendProbe::Ok(capability.clone());
            tool.sandbox_capability = capability;
            tool.site.cwd = crate::workspace::SharedCwd::new(cwd.to_path_buf());
            let result = tool
                .execute(
                    serde_json::json!({"command": command}),
                    crate::tools::ToolContext::for_test(CancellationToken::new()),
                )
                .await
                .expect("the shell itself must run");
            super::text_of(&result)
        }

        /// Through the tool, under every layer this host has: with reads confined, a `read` call
        /// reads its working directory and the system directories and is refused a file
        /// outside them, whichever layer refuses first. The same call with reads unconfined
        /// reads the file, which is what shows the refusal is the boundary's.
        #[cfg(target_os = "linux")]
        #[tokio::test]
        async fn a_tool_call_with_confined_reads_is_refused_outside_its_roots() {
            let Some(capability) = a_backend_detect_does_not_name() else {
                eprintln!("skipping: bwrap is needed");
                return;
            };
            let temp = tempfile::tempdir().expect("tempdir");
            let base = crate::workspace::canonical_for_test(temp.path());
            let work = base.join("work");
            // Outside the roots and outside the masks: a target under `/tmp` is invisible to
            // every bwrap confinement, so the control read below would be refused for a reason
            // that is not the boundary's.
            let outside = crate::workspace::canonical_for_test(
                std::env::var_os("HOME")
                    .map(std::path::PathBuf::from)
                    .unwrap_or_else(std::env::temp_dir),
            )
            .join(format!("meka-read-probe-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir(&work).expect("work");
            std::fs::create_dir(&outside).expect("outside");
            std::fs::write(work.join("inside.txt"), "INSIDE\n").expect("write");
            std::fs::write(outside.join("secret.txt"), "SECRET\n").expect("write");
            let probe = format!(
                "cat {}/inside.txt; ls /usr/bin >/dev/null && echo USR; cat {}/secret.txt || \
                 echo REFUSED",
                work.display(),
                outside.display()
            );
            let confined = {
                let mut tool = super::tool_for_test(
                    crate::permission::SharedPermission::new(
                        Permission::Read,
                        crate::permission::EnabledPermissions::ALL,
                    ),
                    true,
                );
                tool.backend_probe = crate::sandbox::BackendProbe::Ok(capability.clone());
                tool.sandbox_capability = capability.clone();
                tool.site.cwd = crate::workspace::SharedCwd::new(work.clone());
                tool.site.read_boundary = crate::workspace::ReadBoundary::new(true, &[], &[]);
                let result = tool
                    .execute(
                        serde_json::json!({"command": probe}),
                        crate::tools::ToolContext::for_test(CancellationToken::new()),
                    )
                    .await
                    .expect("the shell itself must run");
                super::text_of(&result)
            };
            assert!(
                confined.contains("INSIDE") && confined.contains("USR"),
                "the root and the platform's directories stay readable: {confined}"
            );
            assert!(
                confined.contains("REFUSED") && !confined.contains("SECRET"),
                "the file outside the roots must be refused: {confined}"
            );
            let open = read_shell_text(capability, &work, &probe).await;
            std::fs::remove_dir_all(&outside).expect("remove the probe");
            assert!(
                open.contains("SECRET"),
                "unconfined, the same call reads it, so the refusal above is the boundary's: {open}"
            );
        }

        /// The layer reaches the tool's own spawn, not only the argv helpers: a `read` call under
        /// Bubblewrap with a usable Landlock refuses what bwrap alone permits. `/proc/self/comm`
        /// is the dependency-free observable: bwrap's fresh procfs lets a process rename itself,
        /// and the ruleset grants nothing under `/proc`.
        #[cfg(target_os = "linux")]
        #[tokio::test]
        async fn a_bubblewrapped_tool_call_runs_inside_the_landlock_layer() {
            let Some(crate::sandbox::SandboxCapability::Bubblewrap {
                bwrap_path,
                landlock_abi: Some(abi),
            }) = a_backend_detect_does_not_name()
            else {
                eprintln!(
                    "skipping: bwrap, the built Meka binary and a usable Landlock are all needed"
                );
                return;
            };
            let temp = tempfile::tempdir().expect("tempdir");
            let cwd = crate::workspace::canonical_for_test(temp.path());
            let rename = "echo meka > /proc/self/comm 2>/dev/null && echo RENAMED || echo REFUSED";

            let layered = read_shell_text(
                crate::sandbox::SandboxCapability::Bubblewrap {
                    bwrap_path: bwrap_path.clone(),
                    landlock_abi: Some(abi),
                },
                &cwd,
                rename,
            )
            .await;
            assert!(
                layered.contains("REFUSED"),
                "the layer grants nothing under /proc: {layered}"
            );
            let alone = read_shell_text(
                crate::sandbox::SandboxCapability::Bubblewrap {
                    bwrap_path,
                    landlock_abi: None,
                },
                &cwd,
                rename,
            )
            .await;
            assert!(
                alone.contains("RENAMED"),
                "bwrap alone lets a process rename itself, so the refusal above is the layer's: \
                 {alone}"
            );
        }

        /// The property the layer exists for, through the tool: a pathname socket the masks leave
        /// reachable. The socket sits in the cwd, which the recipe binds back in read-only under
        /// the `/tmp` mask, and `connect(2)` on a socket inode is not a write, so bwrap alone
        /// reaches it, the same route a socket under `$HOME` takes on a real machine. It is also
        /// the case that decides how the masks are granted inside: as scratch, without socket
        /// resolution, or this very socket would be reachable through the grant on `/tmp`.
        #[cfg(target_os = "linux")]
        #[tokio::test]
        async fn a_bubblewrapped_tool_call_refuses_a_socket_the_masks_leave_reachable() {
            let Some(crate::sandbox::SandboxCapability::Bubblewrap {
                bwrap_path,
                landlock_abi: Some(abi),
            }) = a_backend_detect_does_not_name()
            else {
                eprintln!(
                    "skipping: bwrap, the built Meka binary and a usable Landlock are all needed"
                );
                return;
            };
            if abi < 9 || super::bubblewrap_boundary::on_path("python3").is_none() {
                eprintln!("skipping: needs Landlock ABI 9 and python3 to connect with");
                return;
            }
            let temp = tempfile::tempdir().expect("tempdir");
            let cwd = crate::workspace::canonical_for_test(temp.path());
            let socket = cwd.join("outside.sock");
            let _listener = std::os::unix::net::UnixListener::bind(&socket).expect("listen");
            let connect = format!(
                "python3 -c \"import socket; socket.socket(socket.AF_UNIX).connect('{}')\" \
                 2>/dev/null && echo CONNECTED || echo REFUSED",
                socket.display()
            );

            let layered = read_shell_text(
                crate::sandbox::SandboxCapability::Bubblewrap {
                    bwrap_path: bwrap_path.clone(),
                    landlock_abi: Some(abi),
                },
                &cwd,
                &connect,
            )
            .await;
            assert!(
                layered.contains("REFUSED"),
                "the layer refuses the socket: {layered}"
            );
            let alone = read_shell_text(
                crate::sandbox::SandboxCapability::Bubblewrap {
                    bwrap_path,
                    landlock_abi: None,
                },
                &cwd,
                &connect,
            )
            .await;
            assert!(
                alone.contains("CONNECTED"),
                "bwrap alone reaches a socket outside its masks, so the refusal is the layer's: \
                 {alone}"
            );
        }

        /// The layer is reached through a descriptor of the running image, not a path, so the
        /// binary being replaced or deleted under a running Meka changes nothing: an upgrade
        /// under `meka serve` must not break every sandboxed command until a restart.
        #[cfg(target_os = "linux")]
        #[tokio::test]
        async fn the_layer_survives_its_executable_being_replaced() {
            let Some(crate::sandbox::SandboxCapability::Bubblewrap {
                bwrap_path,
                landlock_abi: Some(abi),
            }) = a_backend_detect_does_not_name()
            else {
                eprintln!(
                    "skipping: bwrap, the built Meka binary and a usable Landlock are all needed"
                );
                return;
            };
            let binary = super::bubblewrap_boundary::meka_binary_for_test().expect("checked above");
            let temp = tempfile::tempdir().expect("tempdir");
            let cwd = crate::workspace::canonical_for_test(temp.path());
            let copy = cwd.join("meka-that-will-be-gone");
            std::fs::copy(&binary, &copy).expect("copy the binary");
            let executable = std::fs::File::open(&copy).expect("open the copy");
            std::fs::remove_file(&copy).expect("delete the copy while it is open");
            super::super::INNER_LAYER_EXECUTABLE.with(|slot| *slot.borrow_mut() = Some(executable));

            let layered = read_shell_text(
                crate::sandbox::SandboxCapability::Bubblewrap {
                    bwrap_path,
                    landlock_abi: Some(abi),
                },
                &cwd,
                "echo meka > /proc/self/comm 2>/dev/null && echo RENAMED || echo REFUSED",
            )
            .await;
            assert!(
                layered.contains("REFUSED"),
                "the layer ran from an executable that no longer exists on disk: {layered}"
            );
        }

        /// A shell under Landlock alone has no temporary directory: `TMPDIR` is not set for it and
        /// `mktemp` is refused at `read`. Below `unrestricted` Meka writes to nothing but its
        /// store, and a real directory under the real `/tmp` was the one thing the Landlock dialect
        /// wrote outside it.
        #[cfg(target_os = "linux")]
        #[tokio::test]
        async fn a_landlock_shell_has_no_temp_space() {
            let capability = crate::sandbox::detect();
            if !matches!(
                capability,
                crate::sandbox::SandboxCapability::Landlock { .. }
            ) {
                eprintln!("skipping: no usable Landlock on this host");
                return;
            }
            let mut tool = super::tool_for_test(
                crate::permission::SharedPermission::new(
                    Permission::Read,
                    crate::permission::EnabledPermissions::ALL,
                ),
                true,
            );
            tool.backend_probe = crate::sandbox::BackendProbe::Ok(capability.clone());
            tool.sandbox_capability = capability;

            let result = tool
                .execute(
                    serde_json::json!({
                        "command": "echo \"TMPDIR=${TMPDIR-unset}\"; mktemp && echo CREATED",
                    }),
                    crate::tools::ToolContext::for_test(CancellationToken::new()),
                )
                .await
                .expect("the shell itself must run");
            let text = super::text_of(&result);
            assert!(result.is_error, "mktemp is refused: {text}");
            // The scrubbed environment passes the parent's own `TMPDIR` through when there is one,
            // so the child sees exactly that and never a directory Meka made for it.
            let inherited = std::env::var("TMPDIR").unwrap_or_else(|_| "unset".to_string());
            assert!(
                text.contains(&format!("TMPDIR={inherited}\n")),
                "no temporary directory of Meka's is offered: {text}"
            );
            assert!(!text.contains("CREATED"), "{text}");
        }

        /// macOS and FreeBSD each have one `read`-level backend and `detect()` names it, so there
        /// is nothing to add.
        #[cfg(not(target_os = "linux"))]
        fn a_backend_detect_does_not_name() -> Option<crate::sandbox::SandboxCapability> {
            None
        }

        /// A directory the backend under test will accept as a workspace root.
        ///
        /// Every backend but the jailbroker takes a path anywhere: its writable roots are the
        /// operator's to admit, and a root under `/tmp` is refused by name when the policy grants
        /// nothing there, so a fixture placed by habit would exercise the refusal rather than the
        /// boundary. `None` when the policy grants no writable path at all, which is a host where
        /// this boundary cannot be exercised and the test says so instead of failing.
        fn fixture_directory(
            capability: &crate::sandbox::SandboxCapability,
        ) -> Option<tempfile::TempDir> {
            #[cfg(target_os = "freebsd")]
            if let crate::sandbox::SandboxCapability::Jailbroker {
                writable_prefixes, ..
            } = capability
            {
                let parent = writable_prefixes.iter().find(|prefix| prefix.is_dir())?;
                return tempfile::Builder::new()
                    .prefix("meka-boundary-")
                    .tempdir_in(parent)
                    .ok();
            }
            let _ = capability;
            tempfile::tempdir().ok()
        }

        /// One backend's worth of the boundary check above.
        async fn a_workspace_shell_boundary_holds_for(
            capability: crate::sandbox::SandboxCapability,
        ) {
            let Some(temp) = fixture_directory(&capability) else {
                eprintln!(
                    "skipping {capability:?}: its policy grants no path a workspace root may be"
                );
                return;
            };
            let base = crate::workspace::canonical_for_test(temp.path());
            let work = base.join("work");
            let outside = base.join("outside");
            std::fs::create_dir(&work).expect("work");
            std::fs::create_dir(&outside).expect("outside");

            let mut tool = super::tool_for_test(
                crate::permission::SharedPermission::new(
                    Permission::Workspace,
                    crate::permission::EnabledPermissions::ALL,
                ),
                true,
            );
            // The backend under test, not whatever `detect()` picked.
            tool.backend_probe = crate::sandbox::BackendProbe::Ok(capability.clone());
            tool.sandbox_capability = capability;
            tool.site.cwd = crate::workspace::SharedCwd::new(work.clone());
            tool.scope = crate::workspace::WriteScope::confined(vec![work.clone()]);

            let result = tool
                .execute(
                    serde_json::json!({
                        "command": format!(
                            "echo in > {}/inside.txt 2>/dev/null; \
                             echo out > {}/escaped.txt 2>/dev/null; true",
                            work.display(),
                            outside.display()
                        ),
                    }),
                    crate::tools::ToolContext::for_test(CancellationToken::new()),
                )
                .await
                .expect("the shell itself must run");

            // Ground truth on disk, not the tool's narration: a shell that never started would
            // report failure just as convincingly as one the sandbox confined.
            assert!(
                work.join("inside.txt").exists(),
                "a write inside the workspace root must land: {result:?}"
            );
            assert!(
                !outside.join("escaped.txt").exists(),
                "a write outside every root must be refused by the backend: {result:?}"
            );
        }
    }

    /// Scratch staging and the rules that guard copying anything back over the source the
    /// snapshot came from.
    #[cfg(windows)]
    mod scratch {
        use super::*;

        fn target() -> Arc<crate::subshell::Target> {
            let grant = crate::paths::WslDirectory::from_run_directory(std::path::Path::new(
                r"\\wsl.localhost\test-guest\home\project",
            ))
            .expect("grant")
            .expect("grant shape");
            Arc::new(
                crate::subshell::Target::from_grants(
                    "test-guest",
                    crate::subshell::DEFAULT_RUNNER,
                    &[grant],
                    &[],
                    &[],
                )
                .expect("target"),
            )
        }

        /// A scratch open owns its mount table: additional workspace grants would either be
        /// silently dropped or mounted beside the snapshot, so the request is refused before any
        /// transfer runs rather than answered with a handle that does not mean what it says.
        #[tokio::test]
        async fn a_scratch_open_refuses_additional_workspace_grants() {
            let tool = SubshellOpenTool {
                handles: Arc::new(crate::subshell::Handles::default()),
                target: target(),
                permission: crate::permission::SharedPermission::new(
                    Permission::Workspace,
                    crate::permission::EnabledPermissions::ALL,
                ),
                required: Permission::Read,
                site: crate::session::ToolSite::for_test(),
            };
            let refusal = tool
                .execute(
                    serde_json::json!({
                        "handle": "work",
                        "scratch": {"source": "/tmp/source"},
                        "workspace": ["/tmp/other"],
                    }),
                    crate::tools::ToolContext::for_test(CancellationToken::new()),
                )
                .await
                .expect_err("additional workspace grants are refused");
            assert!(
                refusal.to_string().contains("cannot be combined"),
                "{refusal}"
            );
        }

        fn scratch_state(source_root: std::path::PathBuf) -> crate::subshell::ScratchState {
            crate::subshell::ScratchState {
                path: "/var/tmp/meka-scratch/0011223344556677".to_string(),
                source: "the staged source".to_string(),
                source_root,
                quota_bytes: 1024 * 1024,
                guest_source: false,
                baseline: std::collections::HashMap::new(),
            }
        }

        /// What the runner's stage manifest records is what a later export back over the source
        /// region is judged against, keyed by the `/`-separated path below the source root.
        #[test]
        fn a_stage_manifest_becomes_the_snapshot_baseline() {
            use sha2::Digest as _;

            let modified =
                std::time::UNIX_EPOCH + std::time::Duration::from_millis(1_700_000_000_123);
            let (modified_secs, modified_nanos) = crate::subshell::system_time_parts(modified);
            let digest: [u8; 32] = sha2::Sha256::digest(b"hello").into();
            let manifest = crate::subshell::ManifestOnly {
                roots: Vec::new(),
                entries: vec![
                    crate::subshell::TransferEntry {
                        root: 0,
                        path: "nested".to_string(),
                        len: 0,
                        modified_secs,
                        modified_nanos,
                        digest: crate::subshell::digest_hex(&[0; 32]),
                        directory: true,
                    },
                    crate::subshell::TransferEntry {
                        root: 0,
                        path: "nested/inner.txt".to_string(),
                        len: 5,
                        modified_secs,
                        modified_nanos,
                        digest: crate::subshell::digest_hex(&digest),
                        directory: false,
                    },
                ],
            };

            let baseline = stage_baseline(&manifest).expect("the manifest is a baseline");
            assert_eq!(baseline.len(), 1, "a directory carries no baseline");
            let entry = baseline.get("nested/inner.txt").expect("the staged file");
            assert_eq!(entry.len, 5);
            assert_eq!(entry.modified, modified);
            assert_eq!(entry.digest, digest);
        }

        /// A stage has one source, so an entry numbered for any other is a response the request
        /// could not have produced.
        #[test]
        fn a_stage_manifest_entry_from_an_unknown_root_is_refused() {
            let manifest = crate::subshell::ManifestOnly {
                roots: Vec::new(),
                entries: vec![crate::subshell::TransferEntry {
                    root: 1,
                    path: "nested/inner.txt".to_string(),
                    len: 0,
                    modified_secs: 0,
                    modified_nanos: 0,
                    digest: crate::subshell::digest_hex(&[0; 32]),
                    directory: false,
                }],
            };

            let refusal = stage_baseline(&manifest).expect_err("an unknown root is refused");
            assert!(refusal.contains("unknown source"), "{refusal}");
        }

        /// Two entries with one path would make the baseline depend on the runner's order.
        #[test]
        fn a_stage_manifest_naming_one_path_twice_is_refused() {
            use sha2::Digest as _;

            let digest: [u8; 32] = sha2::Sha256::digest(b"x").into();
            let entry = crate::subshell::TransferEntry {
                root: 0,
                path: "same.txt".to_string(),
                len: 1,
                modified_secs: 0,
                modified_nanos: 0,
                digest: crate::subshell::digest_hex(&digest),
                directory: false,
            };
            let manifest = crate::subshell::ManifestOnly {
                roots: Vec::new(),
                entries: vec![entry.clone(), entry],
            };

            let refusal = stage_baseline(&manifest).expect_err("a repeated path is refused");
            assert!(refusal.contains("twice"), "{refusal}");
        }

        /// A stage copies into a workspace it names itself, never into a source root.
        #[test]
        fn a_stage_manifest_that_names_a_root_is_refused() {
            let manifest = crate::subshell::ManifestOnly {
                roots: vec![crate::subshell::TransferRoot {
                    source: crate::subshell::ExportSource {
                        root: crate::subshell::ExportRoot::Mounted(0),
                        relative: Vec::new(),
                    },
                    name: "project".to_string(),
                    directory: true,
                }],
                entries: Vec::new(),
            };

            let refusal = stage_baseline(&manifest).expect_err("a root is refused");
            assert!(refusal.contains("source root"), "{refusal}");
        }

        /// `/workspace` names the staged workspace, as the model was told to work in it; a path
        /// that names no workspace is left for the scope check to judge.
        #[test]
        fn a_scratch_handle_reads_its_workspace_as_workspace_or_by_its_staged_path() {
            let source = tempfile::tempdir().expect("source");
            let handle = crate::subshell::Handle::new(
                target(),
                None,
                "/var/tmp/meka-scratch/0011223344556677".to_string(),
                Vec::new(),
                Vec::new(),
                false,
                Permission::Workspace,
            )
            .with_scratch(scratch_state(source.path().to_path_buf()));

            assert_eq!(
                scratch_workspace_alias(&handle, "/workspace"),
                "/var/tmp/meka-scratch/0011223344556677"
            );
            assert_eq!(
                scratch_workspace_alias(&handle, "/workspace/out.bin"),
                "/var/tmp/meka-scratch/0011223344556677/out.bin"
            );
            assert_eq!(
                scratch_workspace_alias(&handle, "/workspace-else"),
                "/workspace-else"
            );
            assert_eq!(
                scratch_workspace_alias(&handle, "/references/0/x"),
                "/references/0/x"
            );

            let direct = crate::subshell::Handle::new(
                target(),
                None,
                "/home/project".to_string(),
                Vec::new(),
                Vec::new(),
                false,
                Permission::Workspace,
            );
            assert_eq!(scratch_workspace_alias(&direct, "/workspace"), "/workspace");
        }

        /// What an export back over the staged source may never overwrite: a file the snapshot
        /// does not hold as it now stands. Changed, deleted and new each refuse it; a file left as
        /// it was staged is no conflict.
        #[test]
        fn a_copy_back_over_the_staged_source_refuses_changes_the_snapshot_does_not_hold() {
            let source = tempfile::tempdir().expect("source");
            std::fs::write(source.path().join("kept"), b"same").expect("kept");
            std::fs::write(source.path().join("changed"), b"before").expect("changed");
            std::fs::write(source.path().join("deleted"), b"gone").expect("deleted");
            std::fs::write(source.path().join("appeared"), b"new").expect("appeared");
            let mut state = scratch_state(source.path().to_path_buf());
            for name in ["kept", "changed", "deleted"] {
                let held = std::fs::metadata(source.path().join(name)).expect("metadata");
                use sha2::Digest as _;
                let digest: [u8; 32] = sha2::Sha256::digest(
                    std::fs::read(source.path().join(name)).expect("contents"),
                )
                .into();
                state
                    .baseline
                    .insert(name.to_string(), crate::subshell::BaselineEntry {
                        len: held.len(),
                        modified: held.modified().expect("mtime"),
                        digest,
                    });
            }
            std::fs::write(source.path().join("changed"), b"afterwards").expect("changed again");
            std::fs::remove_file(source.path().join("deleted")).expect("delete");

            let files: Vec<(PlannedSource, std::path::PathBuf)> =
                ["kept", "changed", "deleted", "appeared"]
                    .iter()
                    .map(|name| {
                        (
                            PlannedSource::Native(std::path::PathBuf::from("the staged copy")),
                            source.path().join(name),
                        )
                    })
                    .collect();
            let conflicts = scratch_conflicts(&state, &files);

            assert_eq!(conflicts.len(), 3, "{conflicts:?}");
            assert!(
                conflicts.iter().any(|conflict| conflict
                    == &format!(
                        "{}: changed after it was staged",
                        source.path().join("changed").display()
                    )),
                "{conflicts:?}"
            );
            assert!(
                conflicts
                    .iter()
                    .any(|conflict| conflict.ends_with("deleted after it was staged")),
                "{conflicts:?}"
            );
            assert!(
                conflicts
                    .iter()
                    .any(|conflict| conflict.ends_with("appeared after staging")),
                "{conflicts:?}"
            );

            // A target outside the staged source region is not a conflict of the snapshot's.
            let outside = tempfile::tempdir().expect("outside");
            std::fs::write(outside.path().join("elsewhere"), b"new").expect("elsewhere");
            assert!(
                scratch_conflicts(&state, &[(
                    PlannedSource::Native(std::path::PathBuf::from("ignored")),
                    outside.path().join("elsewhere"),
                )],)
                .is_empty()
            );
        }

        /// The staged temporary's name is what the tests use to judge what a refusal left
        /// behind.
        fn export_leftovers(directory: &std::path::Path) -> Vec<String> {
            std::fs::read_dir(directory)
                .expect("read the destination")
                .filter_map(std::result::Result::ok)
                .filter_map(|entry| {
                    let name = entry.file_name().to_string_lossy().to_string();
                    name.starts_with(".meka-export").then_some(name)
                })
                .collect()
        }

        /// The commit's rename is bound to the pinned directory handle and never replaces: a name
        /// that appears before the publish fails the publish and keeps its bytes.
        #[test]
        fn a_handle_relative_rename_takes_only_an_absent_name_beneath_the_pin() {
            use std::os::windows::io::AsRawHandle as _;

            let dir = tempfile::tempdir().expect("dir");
            let pinned = PinnedDirectory::pin(dir.path(), None).expect("pin");
            let staged_path = dir.path().join("staged.bin");
            std::fs::write(&staged_path, b"new").expect("staged");
            let staged = open_staged(&staged_path).expect("open");

            rename_relative_no_replace(
                staged.as_raw_handle(),
                pinned.raw(),
                std::ffi::OsStr::new("artifact.bin"),
            )
            .expect("an absent name is taken");
            assert_eq!(
                std::fs::read(dir.path().join("artifact.bin")).expect("artifact"),
                b"new",
                "the rename publishes the staged bytes"
            );

            let other = dir.path().join("taken.bin");
            std::fs::write(&other, b"original").expect("taken");
            let staged_two = dir.path().join("staged2.bin");
            std::fs::write(&staged_two, b"replacement").expect("staged");
            let staged_two = open_staged(&staged_two).expect("open");
            let refusal = rename_relative_no_replace(
                staged_two.as_raw_handle(),
                pinned.raw(),
                std::ffi::OsStr::new("taken.bin"),
            )
            .expect_err("a taken name is never replaced");
            assert_eq!(
                refusal.kind(),
                std::io::ErrorKind::AlreadyExists,
                "a taken name reads as the name being taken: {refusal}"
            );
            assert_eq!(
                std::fs::read(&other).expect("taken"),
                b"original",
                "the entry that was already there keeps its bytes"
            );
        }

        /// Stage and publish one file the way the export does, for the tests that judge the
        /// commit itself.
        fn publish_one(
            source: &std::path::Path,
            target: &std::path::Path,
        ) -> std::result::Result<u64, String> {
            let staged = stage_export_file(source, target)?;
            let pinned = target
                .parent()
                .map(|parent| PinnedDirectory::pin(parent, None))
                .transpose()?
                .ok_or_else(|| format!("{} has no parent directory", target.display()))?;
            publish_export_temp(staged, target, pinned)
        }

        /// An absent destination is published only while it is still absent: an entry created
        /// after the plan is refused, never replaced by the copy.
        #[test]
        fn an_absent_export_target_is_not_replaced_by_a_later_appearance() {
            let destination = tempfile::tempdir().expect("destination");
            let source = destination.path().join("source.bin");
            std::fs::write(&source, b"new bytes").expect("source");
            let target = destination.path().join("artifact.bin");

            let copied = publish_one(&source, &target).expect("an absent target publishes");
            assert_eq!(copied, 9);
            assert_eq!(std::fs::read(&target).expect("target"), b"new bytes");
            assert!(export_leftovers(destination.path()).is_empty());

            std::fs::write(&target, b"someone else's").expect("the target appears");
            let refusal = publish_one(&source, &target).expect_err("an appearance is refused");
            assert!(refusal.contains("appeared at the destination"), "{refusal}");
            assert_eq!(
                std::fs::read(&target).expect("target"),
                b"someone else's",
                "the entry that appeared keeps its bytes"
            );
            assert!(export_leftovers(destination.path()).is_empty());
        }

        /// The publication is bound to the bytes the export wrote: a staged temporary that
        /// changed under it is refused before the rename, and the name it would have taken stays
        /// absent.
        #[test]
        fn a_staged_file_that_changed_before_the_commit_is_refused() {
            let destination = tempfile::tempdir().expect("destination");
            let source = destination.path().join("source.bin");
            std::fs::write(&source, b"new bytes").expect("source");
            let target = destination.path().join("artifact.bin");

            let staged = stage_export_file(&source, &target).expect("stage");
            std::fs::write(&staged.path, b"tampered").expect("tamper with the staged file");
            let pinned = PinnedDirectory::pin(destination.path(), None).expect("pin");
            let refusal =
                publish_export_temp(staged, &target, pinned).expect_err("a tampered stage");
            assert!(refusal.contains("no longer holds the bytes"), "{refusal}");
            assert!(
                !target.exists(),
                "nothing is published from a tampered stage"
            );
            assert!(export_leftovers(destination.path()).is_empty());
            assert_eq!(
                std::fs::read(&source).expect("source"),
                b"new bytes",
                "the export's own source is untouched"
            );
        }

        /// The supported publication providers are the ones that can hold the identity and
        /// no-replace guarantees: a local fixed NTFS or ReFS volume, and nothing else.
        #[test]
        fn only_a_fixed_ntfs_or_refs_volume_may_take_a_publication() {
            const DRIVE_FIXED: u32 = 3;
            const DRIVE_REMOTE: u32 = 4;
            const DRIVE_NO_ROOT_DIR: u32 = 1;

            assert!(publication_provider_allows("NTFS", DRIVE_FIXED));
            assert!(publication_provider_allows("ReFS", DRIVE_FIXED));
            for refused in [
                ("NTFS", DRIVE_REMOTE),
                ("ReFS", DRIVE_NO_ROOT_DIR),
                ("9p", DRIVE_FIXED),
                ("FAT32", DRIVE_FIXED),
                ("unknown", DRIVE_FIXED),
                ("NTFS", 0),
            ] {
                assert!(
                    !publication_provider_allows(refused.0, refused.1),
                    "{refused:?} was accepted"
                );
            }
        }

        /// A destination name that is already taken is refused while the plan is made, before a
        /// temporary is created or any byte is read. The export's contract is a fresh name; it has
        /// no replacement path to attempt.
        #[test]
        fn an_existing_export_destination_is_refused_before_the_copy() {
            let destination = tempfile::tempdir().expect("destination");
            let source = destination.path().join("source.bin");
            std::fs::write(&source, b"replacement").expect("source");
            let target = destination.path().join("artifact.bin");
            std::fs::write(&target, b"original").expect("target");

            let refusal = planned_destination(&target).expect_err("an existing name is refused");
            assert!(refusal.to_string().contains("already exists"), "{refusal}");
            assert!(refusal.to_string().contains("new name"), "{refusal}");
            assert_eq!(
                std::fs::read(&target).expect("target"),
                b"original",
                "the existing file keeps its bytes"
            );
            assert!(export_leftovers(destination.path()).is_empty());
        }

        /// A Windows-backed export source is admitted in Windows spelling and resolved as the
        /// host path itself, with no UNC translation.
        #[test]
        fn an_export_source_accepts_a_windows_path_beneath_the_grant() {
            let temp = tempfile::tempdir().expect("temp");
            let file_path = temp.path().join("artifact.bin");
            std::fs::write(&file_path, b"payload").expect("write");
            let grant = temp.path().to_string_lossy().to_string();
            let target = Arc::new(
                crate::subshell::Target::from_grants(
                    "test-guest",
                    crate::subshell::DEFAULT_RUNNER,
                    &[],
                    &[],
                    std::slice::from_ref(&grant),
                )
                .expect("target"),
            );
            let handle = crate::subshell::Handle::new(
                Arc::clone(&target),
                None,
                grant.clone(),
                Vec::new(),
                Vec::new(),
                false,
                Permission::Workspace,
            );
            let source = file_path.to_string_lossy().to_string();
            let result = export_source(&handle, &source);
            assert!(result.is_ok(), "{result:?}");
            assert_eq!(result.unwrap(), file_path);
        }

        /// A guest name that Windows would read as structure is refused before the plan runs.
        #[test]
        fn export_names_are_single_windows_components() {
            use std::ffi::OsStr;

            assert_eq!(
                export_component(OsStr::new("artifact.bin")),
                Ok("artifact.bin")
            );
            assert_eq!(export_component(OsStr::new("COM10")), Ok("COM10"));
            assert_eq!(
                export_component(OsStr::new("console.txt")),
                Ok("console.txt")
            );
            for refused in [
                "",
                ".",
                "..",
                "name.",
                "name ",
                "a\\b",
                "a/b",
                "a:b",
                "a*b",
                "a?b",
                "a\"b",
                "a<b",
                "a>b",
                "a|b",
                "a\tb",
                "CON",
                "con.txt",
                "PRN",
                "AUX",
                "NUL",
                "COM1",
                "lpt9.log",
                "CONIN$",
                "conout$.txt",
                "CLOCK$",
            ] {
                assert!(
                    export_component(OsStr::new(refused)).is_err(),
                    "{refused:?} was accepted"
                );
            }
            let long = "a".repeat(256);
            assert!(export_component(OsStr::new(&long)).is_err());
        }

        /// Two planned names that differ only in case would land on one Windows file.
        #[test]
        fn an_export_plan_refuses_case_aliases() {
            let mut plan = ExportPlan {
                root: std::path::PathBuf::from(r"C:\out"),
                files: Vec::new(),
                directories: Vec::new(),
                seen: std::collections::HashSet::new(),
                guest_sources: Vec::new(),
            };
            claim_export_target(&mut plan, std::path::Path::new(r"C:\out\Foo\a")).unwrap();
            let alias = claim_export_target(&mut plan, std::path::Path::new(r"C:\out\foo\A"));
            assert!(alias.is_err(), "{alias:?}");
            assert!(claim_export_target(&mut plan, std::path::Path::new(r"C:\out\Foo\b")).is_ok());
        }
    }

    /// A downgrade after a WSL launcher is owned withdraws the guest first and kills only when no
    /// terminal proof arrives, keeps what the command printed, and records the guest end as
    /// unconfirmed rather than treating the local reap as the namespace's end.
    #[cfg(windows)]
    #[tokio::test]
    async fn a_wsl_command_stopped_by_a_downgrade_keeps_its_output_and_says_the_guest_end_is_unconfirmed()
     {
        let op = crate::subshell::new_op();
        let permission = shared_permission_for_test();
        let lease = permission.lease();
        let context = crate::tools::ToolContext {
            teardown: Some(std::sync::Arc::new(
                crate::tools::TeardownObservation::default(),
            )),
            ..crate::tools::ToolContext::for_test(tokio_util::sync::CancellationToken::new())
        };
        // The stand-in proves its start and then leaves a marker: the downgrade lands only after
        // the route observed the start, so the test's order is its own, not the scheduler's.
        let marker =
            std::env::temp_dir().join(format!("meka-stop-marker-{}", uuid::Uuid::new_v4()));
        let mut command = stand_in_runner(&format!(
            "'{{\"frame\":\"ready\",\"op\":\"{op}\"}}'; \
             if ($null -ne [Console]::In.ReadLine()) {{ \
             '{{\"frame\":\"started\",\"op\":\"{op}\"}}'; \
             [Console]::Out.Write('{{\"frame\":\"output\",\"stream\":\"stdout\",\"len\":7}}' + \"`n\"); \
             [Console]::Out.Write(\"before`n\"); [Console]::Out.Flush(); \
             New-Item -ItemType File -Path '{}' | Out-Null }}; \
             Start-Sleep -Seconds 30",
            marker.display()
        ));
        let tree = crate::process::spawn_tree(&mut command).expect("spawn the stand-in launcher");
        let downgraded = tokio::spawn(async move {
            for _ in 0..600 {
                if marker.exists() {
                    permission.set_unchecked(Permission::Read);
                    return;
                }
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
            panic!("the stand-in never reached its start");
        });
        let output = run_command_tree_route(
            tree,
            Some(WslRun {
                op,
                required: Permission::Read,
            }),
            std::time::Duration::from_secs(30),
            &context,
            CommandRoute::Wsl,
            Some(&lease),
            None,
        )
        .await
        .expect("a stopped route reports what it collected");
        downgraded.await.expect("the downgrade ran");
        let text = output
            .content
            .iter()
            .filter_map(|content| match content {
                crate::conversation::ToolResultContent::Text { text } => Some(text.as_str()),
                _ => None,
            })
            .collect::<String>();
        assert!(text.contains("Permission was lowered"), "{text}");
        assert!(text.contains("before"), "{text}");
        assert!(text.contains("end is unconfirmed"), "{text}");
        assert_eq!(
            context
                .teardown
                .as_ref()
                .expect("the test asked for an observation")
                .confirmed(),
            Some(false),
            "a local launcher's end is not a confirmed guest teardown"
        );
    }

    /// A stop that wins before the guest ever acknowledges a start denies the permit: the command
    /// never runs, and the record says so instead of guessing at a namespace's state.
    #[cfg(windows)]
    #[tokio::test]
    async fn a_wsl_stop_before_the_start_permit_denies_the_start() {
        let op = crate::subshell::new_op();
        let permission = shared_permission_for_test();
        let lease = permission.lease();
        let context = crate::tools::ToolContext {
            teardown: Some(std::sync::Arc::new(
                crate::tools::TeardownObservation::default(),
            )),
            ..crate::tools::ToolContext::for_test(tokio_util::sync::CancellationToken::new())
        };
        // The stand-in waits out the stop before it ever proves its sandbox, and says `ran` only
        // if a permit line actually arrives: the guest that never gets a permit never starts.
        let mut command = stand_in_runner(&format!(
            "Start-Sleep -Milliseconds 500; \
             '{{\"frame\":\"ready\",\"op\":\"{op}\"}}'; \
             if ($null -ne [Console]::In.ReadLine()) {{ [Console]::Out.Write('ran') }}; \
             Start-Sleep -Seconds 30"
        ));
        let tree = crate::process::spawn_tree(&mut command).expect("spawn the stand-in launcher");
        let downgraded = tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            permission.set_unchecked(Permission::Read);
        });
        let output = run_command_tree_route(
            tree,
            Some(WslRun {
                op,
                required: Permission::Workspace,
            }),
            std::time::Duration::from_secs(30),
            &context,
            CommandRoute::Wsl,
            Some(&lease),
            None,
        )
        .await
        .expect("a denied start is a result, not a crash");
        downgraded.await.expect("the downgrade ran");
        let text = output
            .content
            .iter()
            .filter_map(|content| match content {
                crate::conversation::ToolResultContent::Text { text } => Some(text.as_str()),
                _ => None,
            })
            .collect::<String>();
        assert!(!text.contains("ran"), "the command must never run: {text}");
        assert!(text.contains("never started"), "{text}");
        assert_eq!(
            context
                .teardown
                .as_ref()
                .expect("the test asked for an observation")
                .confirmed(),
            Some(true),
            "a command that never started has nothing left running"
        );
    }

    /// A complete framed response presents stdout and stderr separately and records the guest's
    /// own teardown proof, which a local launcher exit alone could not provide.
    #[cfg(windows)]
    #[tokio::test]
    async fn a_wsl_command_with_a_complete_frame_stream_proves_its_teardown() {
        let op = crate::subshell::new_op();
        let context = crate::tools::ToolContext {
            teardown: Some(std::sync::Arc::new(
                crate::tools::TeardownObservation::default(),
            )),
            ..crate::tools::ToolContext::for_test(tokio_util::sync::CancellationToken::new())
        };
        let mut command = stand_in_runner(&format!(
            "'{{\"frame\":\"ready\",\"op\":\"{op}\"}}'; \
             $null = [Console]::In.ReadLine(); \
             '{{\"frame\":\"started\",\"op\":\"{op}\"}}'; \
             [Console]::Out.Write('{{\"frame\":\"output\",\"stream\":\"stdout\",\"len\":6}}' + \"`n\"); \
             [Console]::Out.Write(\"hello`n\"); \
             [Console]::Out.Write('{{\"frame\":\"output\",\"stream\":\"stderr\",\"len\":5}}' + \"`n\"); \
             [Console]::Out.Write(\"warn`n\"); \
             '{{\"frame\":\"stopped\",\"op\":\"{op}\",\"code\":0}}'; \
             '{{\"frame\":\"done\",\"op\":\"{op}\"}}'"
        ));
        let tree = crate::process::spawn_tree(&mut command).expect("spawn the stand-in runner");
        let output = run_command_tree_route(
            tree,
            Some(WslRun {
                op,
                required: Permission::Read,
            }),
            std::time::Duration::from_secs(30),
            &context,
            CommandRoute::Wsl,
            None,
            None,
        )
        .await
        .expect("a complete stream is a result");
        let text = output
            .content
            .iter()
            .filter_map(|content| match content {
                crate::conversation::ToolResultContent::Text { text } => Some(text.as_str()),
                _ => None,
            })
            .collect::<String>();
        assert!(text.contains("hello"), "{text}");
        assert!(text.contains("--- stderr ---\nwarn"), "{text}");
        assert_eq!(
            context
                .teardown
                .as_ref()
                .expect("the test asked for an observation")
                .confirmed(),
            Some(true),
            "the stopped frame proves the guest reaped the shell"
        );
    }

    /// A stand-in launcher for the framed protocol: PowerShell, its stdin piped so the route's
    /// start permit and withdrawal reach it.
    #[cfg(windows)]
    fn stand_in_runner(script: &str) -> tokio::process::Command {
        let mut command = tokio::process::Command::new("powershell.exe");
        command.args(["-NoProfile", "-NonInteractive", "-Command", script]);
        command
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        command
    }

    #[cfg(windows)]
    fn command_frame(frame: crate::subshell::Frame) -> Vec<u8> {
        frame.encode().expect("encode a frame")
    }
    #[cfg(windows)]
    fn output_frame(stream: crate::subshell::OutputStream, bytes: &[u8]) -> Vec<u8> {
        let mut encoded = command_frame(crate::subshell::Frame::Output {
            stream,
            len: bytes.len() as u64,
        });
        encoded.extend_from_slice(bytes);
        encoded
    }

    /// One command stream parser for a test, with the notice channel and the permit flag the
    /// route would hold.
    #[cfg(windows)]
    fn test_frames(
        op: &str,
        bound: usize,
    ) -> (
        CommandFrames,
        tokio::sync::mpsc::Receiver<()>,
        Arc<std::sync::atomic::AtomicBool>,
        tokio_util::sync::CancellationToken,
    ) {
        let (ready_tx, ready_rx) = tokio::sync::mpsc::channel(1);
        let permit = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop = tokio_util::sync::CancellationToken::new();
        let frames = CommandFrames::new(
            op.to_owned(),
            Arc::new(crate::process::OutputBudget::new(bound)),
            stop.clone(),
            None,
            ready_tx,
            Arc::clone(&permit),
        );
        (frames, ready_rx, permit, stop)
    }

    /// A command's framed stream is accepted in one order only: readiness, then the permit the
    /// route commits, then `started`, and only a complete `stopped`, `done` sequence proves the
    /// guest reaped the shell.
    #[cfg(windows)]
    #[tokio::test]
    async fn command_frames_carry_output_and_prove_teardown_in_order() {
        use std::sync::atomic::Ordering;

        use crate::subshell::{Frame, OutputStream};

        let op = crate::subshell::new_op();
        let (frames, mut ready, permit, stop) = test_frames(&op, 1024);
        let mut stream = command_frame(Frame::Ready { op: op.clone() });
        frames.push(&stream).await;
        assert!(ready.try_recv().is_ok(), "readiness reaches the route");
        permit.store(true, Ordering::Release);
        stream.clear();
        stream.extend(command_frame(Frame::Started { op: op.clone() }));
        stream.extend(output_frame(OutputStream::Stdout, b"out\n"));
        stream.extend(output_frame(OutputStream::Stderr, b"err\n"));
        stream.extend(command_frame(Frame::Stopped {
            op: op.clone(),
            code: 0,
        }));
        stream.extend(command_frame(Frame::Done { op: op.clone() }));
        frames.push(&stream).await;
        let (drained, end) = frames.outcome().await.expect("a complete sequence");
        assert_eq!(drained.stdout, "out\n");
        assert_eq!(drained.stderr, "err\n");
        assert!(end.started, "the permit became an observed start");
        assert_eq!(end.stopped, Some(0), "the stopped frame is the reap proof");
        assert!(!stop.is_cancelled(), "a complete sequence needs no stop");
    }

    /// Output before `started`, a start without the committed permit, `done` before `stopped`, a
    /// control frame naming another operation, and any trailing frame are refusals: a command's
    /// own bytes can never stand in for a control frame.
    #[cfg(windows)]
    #[tokio::test]
    async fn command_frames_refuse_control_out_of_order_or_out_of_operation() {
        use std::sync::atomic::Ordering;

        use crate::subshell::{Frame, OutputStream};

        let op = crate::subshell::new_op();
        let (frames, _ready, _permit, _stop) = test_frames(&op, 1024);
        frames
            .push(&output_frame(OutputStream::Stdout, b"early"))
            .await;
        let error = frames.outcome().await.expect_err("output before started");
        assert!(error.contains("out of order"), "{error}");

        // A start before the route committed the permit is refused even after readiness.
        let (frames, _ready, _permit, _stop) = test_frames(&op, 1024);
        let mut stream = command_frame(Frame::Ready { op: op.clone() });
        stream.extend(command_frame(Frame::Started { op: op.clone() }));
        frames.push(&stream).await;
        let error = frames
            .outcome()
            .await
            .expect_err("a start without the permit");
        assert!(error.contains("permit"), "{error}");

        let (frames, _ready, permit, _stop) = test_frames(&op, 1024);
        permit.store(true, Ordering::Release);
        let mut stream = command_frame(Frame::Started { op: op.clone() });
        stream.extend(command_frame(Frame::Done { op: op.clone() }));
        frames.push(&stream).await;
        let error = frames.outcome().await.expect_err("done before stopped");
        assert!(error.contains("out of order"), "{error}");

        // A control frame naming another operation is not this run's answer.
        let (frames, _ready, permit, _stop) = test_frames(&op, 1024);
        permit.store(true, Ordering::Release);
        let other = crate::subshell::new_op();
        let stream = command_frame(Frame::Started { op: other.clone() });
        frames.push(&stream).await;
        let error = frames
            .outcome()
            .await
            .expect_err("another operation's frame");
        assert!(error.contains("another operation"), "{error}");
    }

    /// The budget stops the run and leaves the bytes that crossed it for the result, exactly as a
    /// raw command's drain does; the incomplete sequence is never presented as a clean finish.
    #[cfg(windows)]
    #[tokio::test]
    async fn command_frames_stop_at_the_output_budget() {
        use std::sync::atomic::Ordering;

        use crate::subshell::{Frame, OutputStream};

        let op = crate::subshell::new_op();
        let (frames, mut ready, permit, stop) = test_frames(&op, 4);
        let mut stream = command_frame(Frame::Ready { op: op.clone() });
        frames.push(&stream).await;
        assert!(ready.try_recv().is_ok(), "readiness reaches the route");
        permit.store(true, Ordering::Release);
        stream.clear();
        stream.extend(command_frame(Frame::Started { op: op.clone() }));
        stream.extend(output_frame(OutputStream::Stdout, b"over the bound"));
        frames.push(&stream).await;
        assert!(stop.is_cancelled(), "the run is stopped at the bound");
        assert!(
            frames.output_bound().await,
            "the parser knows it cut output"
        );
        let error = frames
            .outcome()
            .await
            .expect_err("a cut stream has no terminal frames");
        assert!(error.contains("terminal frames"), "{error}");
    }

    /// Bytes that happen to look like a control frame are still the command's own output: the
    /// stream's length-delimited payload is never re-read as control.
    #[cfg(windows)]
    #[tokio::test]
    async fn an_output_payload_that_resembles_a_control_frame_stays_output() {
        use std::sync::atomic::Ordering;

        use crate::subshell::{Frame, OutputStream};

        let op = crate::subshell::new_op();
        let (frames, mut ready, permit, _stop) = test_frames(&op, 1024);
        let mut stream = command_frame(Frame::Ready { op: op.clone() });
        frames.push(&stream).await;
        assert!(ready.try_recv().is_ok(), "readiness reaches the route");
        permit.store(true, Ordering::Release);
        stream.clear();
        stream.extend(command_frame(Frame::Started { op: op.clone() }));
        let disguised = format!("{{\"frame\":\"stopped\",\"op\":\"{op}\",\"code\":0}}");
        stream.extend(output_frame(OutputStream::Stdout, disguised.as_bytes()));
        frames.push(&stream).await;
        let error = frames
            .outcome()
            .await
            .expect_err("the sequence has no terminal frames");
        assert!(error.contains("terminal frames"), "{error}");
        let (drained, end) = frames.snapshot().await;
        assert_eq!(drained.stdout, disguised, "the disguised bytes stay output");
        assert_eq!(
            end.stopped, None,
            "no stopped frame was parsed out of output"
        );
    }

    /// A launcher that ends before it reports anything is reconciled as a broken stream, never
    /// as a clean result, and the record says no start was observed.
    #[cfg(windows)]
    #[tokio::test]
    async fn a_launcher_that_ends_before_it_reports_anything_is_not_a_clean_result() {
        let op = crate::subshell::new_op();
        let context = crate::tools::ToolContext {
            teardown: Some(std::sync::Arc::new(
                crate::tools::TeardownObservation::default(),
            )),
            ..crate::tools::ToolContext::for_test(tokio_util::sync::CancellationToken::new())
        };
        let mut command = stand_in_runner("exit 3");
        let tree = crate::process::spawn_tree(&mut command).expect("spawn the stand-in launcher");
        let error = match run_command_tree_route(
            tree,
            Some(WslRun {
                op,
                required: Permission::Read,
            }),
            std::time::Duration::from_secs(30),
            &context,
            CommandRoute::Wsl,
            None,
            None,
        )
        .await
        {
            Err(error) => error,
            Ok(_) => panic!("a stream with nothing in it is not a result"),
        };
        let CommandTreeError::Wait(error) = error else {
            panic!("a broken stream reads as a wait failure, not a start");
        };
        assert!(
            error
                .to_string()
                .contains("exited without reporting the command's outcome"),
            "{error}"
        );
        assert_eq!(
            context
                .teardown
                .as_ref()
                .expect("the test asked for an observation")
                .confirmed(),
            Some(true),
            "no start was ever observed, so there is nothing left running"
        );
    }

    /// The commit gate is the lease's memory: a permission lowered and raised again still reads
    /// as lowered at the gate, and the wording counts what was published before it.
    #[cfg(windows)]
    #[test]
    fn the_commit_gate_refuses_a_lease_that_was_lowered_and_raised_again() {
        let permission = shared_permission_for_test();
        let lease = permission.lease();
        let closed = tokio_util::sync::CancellationToken::new();
        let cancellation = tokio_util::sync::CancellationToken::new();
        assert!(
            commit_gate(&closed, &cancellation, &lease).is_ok(),
            "an untouched lease passes the gate"
        );

        permission.set_unchecked(Permission::Read);
        permission.set_unchecked(Permission::Workspace);
        let stop = commit_gate(&closed, &cancellation, &lease)
            .expect_err("a lease lowered and raised again is still revoked");
        assert!(matches!(stop, CommitStop::LeaseLowered), "{stop:?}");
        let report = stop.report(2);
        assert!(report.contains("2 file(s) were published"), "{report}");
        assert!(report.contains("and remain"), "{report}");

        let fresh = permission.lease();
        assert!(
            commit_gate(&closed, &cancellation, &fresh).is_ok(),
            "a lease taken after the change is not bound by it"
        );
        cancellation.cancel();
        let stop = commit_gate(&closed, &cancellation, &fresh).expect_err("a cancelled run");
        assert!(matches!(stop, CommitStop::Canceled), "{stop:?}");
    }

    /// The pin is the binding: while the export holds its destination directory, nothing may
    /// rename or remove it, so the names the commit creates cannot be redirected.
    #[cfg(windows)]
    #[test]
    fn a_pinned_destination_directory_cannot_be_renamed_or_removed_while_it_is_held() {
        let outer = tempfile::tempdir().expect("outer");
        let destination = outer.path().join("destination");
        std::fs::create_dir(&destination).expect("destination");
        let pinned = PinnedDirectory::pin(&destination, None).expect("pin");

        let moved = outer.path().join("moved");
        assert!(
            std::fs::rename(&destination, &moved).is_err(),
            "the pinned directory must not be renamed away"
        );
        assert!(
            std::fs::remove_dir(&destination).is_err(),
            "the pinned directory must not be removed"
        );
        assert!(
            destination.exists(),
            "the destination is still the export's"
        );

        drop(pinned);
        std::fs::rename(&destination, &moved).expect("released, the directory may move again");
        assert!(!destination.exists());
    }

    /// A source that grows while it is copied is refused: what the export publishes is what the
    /// plan admitted, and a file that changed under it publishes nothing.
    #[cfg(windows)]
    #[test]
    fn a_source_that_grows_during_the_copy_publishes_nothing() {
        /// Long enough that the grower's appends land while the copy is still reading.
        const GROWING_SOURCE_BYTES: usize = 24 * 1024 * 1024;

        let destination = tempfile::tempdir().expect("destination");
        let source = destination.path().join("source.bin");
        std::fs::write(&source, vec![b'x'; GROWING_SOURCE_BYTES]).expect("source");
        let target = destination.path().join("artifact.bin");
        let grower = {
            let source = source.clone();
            std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_millis(30));
                for _ in 0..64 {
                    let mut appended = std::fs::OpenOptions::new()
                        .append(true)
                        .open(&source)
                        .expect("open to grow");
                    std::io::Write::write_all(&mut appended, b"growth").expect("grow");
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
            })
        };
        let refusal = stage_export_file(&source, &target)
            .err()
            .expect("a growing source");
        grower.join().expect("the grower ran");
        assert!(refusal.contains("changed while it was copied"), "{refusal}");
        assert!(
            !target.exists(),
            "a refused source publishes nothing under its name"
        );
    }

    /// A stage snapshot announces the tree it read in walk order and carries each file's bytes
    /// once: the manifest travels before them and the runner re-checks every digest as it writes.
    #[cfg(windows)]
    #[test]
    fn a_stage_snapshot_announces_the_tree_it_read() {
        use sha2::Digest as _;

        let base = tempfile::tempdir().expect("source");
        std::fs::write(base.path().join("a.txt"), b"alpha").expect("a file");
        std::fs::create_dir(base.path().join("sub")).expect("subdirectory");
        std::fs::write(base.path().join("sub").join("b.txt"), b"beta").expect("a nested file");
        let snapshot =
            snapshot_stage_tree(base.path(), 1024 * 1024).expect("the tree is snapshotted");
        assert_eq!(
            snapshot
                .entries
                .iter()
                .map(|entry| (entry.path.as_str(), entry.directory))
                .collect::<Vec<_>>(),
            vec![("a.txt", false), ("sub", true), ("sub/b.txt", false)]
        );
        assert_eq!(snapshot.payload, b"alphabeta");
        let alpha: [u8; 32] = sha2::Sha256::digest(b"alpha").into();
        assert_eq!(
            snapshot.entries[0].parsed_digest().expect("a digest"),
            alpha
        );
    }

    /// A stage snapshot refuses a reparse point: nothing is read through one, since the tree it
    /// names is not the tree the grant admitted.
    #[cfg(windows)]
    #[test]
    fn a_stage_snapshot_refuses_a_reparse_point() {
        let base = tempfile::tempdir().expect("source");
        std::fs::write(base.path().join("a.txt"), b"alpha").expect("a file");
        std::os::windows::fs::symlink_file(base.path().join("a.txt"), base.path().join("link.txt"))
            .expect("symlink");
        let refusal = snapshot_stage_tree(base.path(), 1024 * 1024)
            .err()
            .expect("a reparse point is refused");
        assert!(refusal.contains("reparse point"), "{refusal}");
    }

    /// A stage snapshot refuses a file another name can change: the fence binds one name, and a
    /// write through the other would not be seen in the bytes it announced.
    #[cfg(windows)]
    #[test]
    fn a_stage_snapshot_refuses_a_file_another_name_can_change() {
        let base = tempfile::tempdir().expect("source");
        std::fs::write(base.path().join("a.txt"), b"alpha").expect("a file");
        std::fs::hard_link(base.path().join("a.txt"), base.path().join("other.txt"))
            .expect("hard link");
        let refusal = snapshot_stage_tree(base.path(), 1024 * 1024)
            .err()
            .expect("a hard link is refused");
        assert!(refusal.contains("another name"), "{refusal}");
    }

    /// A file that grows while it is read refuses the snapshot: what the upload would carry is
    /// what the fence read, and a source that changed under it announces nothing.
    #[cfg(windows)]
    #[test]
    fn a_stage_snapshot_refuses_a_source_that_grows_while_it_is_read() {
        /// Long enough that the grower's appends land while the copy is still reading.
        const GROWING_SOURCE_BYTES: u64 = 24 * 1024 * 1024;

        let base = tempfile::tempdir().expect("source");
        let source = base.path().join("source.bin");
        std::fs::write(&source, vec![b'x'; GROWING_SOURCE_BYTES as usize]).expect("source");
        let grower = {
            let source = source.clone();
            std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_millis(30));
                for _ in 0..64 {
                    let mut appended = std::fs::OpenOptions::new()
                        .append(true)
                        .open(&source)
                        .expect("open to grow");
                    std::io::Write::write_all(&mut appended, b"growth").expect("grow");
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
            })
        };
        let refusal = read_snapshot_file(&source, "source.bin", GROWING_SOURCE_BYTES)
            .expect_err("a growing source");
        grower.join().expect("the grower ran");
        assert!(refusal.contains("changed while it was staged"), "{refusal}");
    }

    /// A stage snapshot is bounded by the workspace quota before its bytes are held: a source
    /// larger than the workspace may hold is refused by the walk, not by the workspace.
    #[cfg(windows)]
    #[test]
    fn a_stage_snapshot_is_bounded_by_the_workspace_quota() {
        let base = tempfile::tempdir().expect("source");
        std::fs::write(base.path().join("a.txt"), vec![b'x'; 64]).expect("a file");
        std::fs::write(base.path().join("b.txt"), vec![b'y'; 64]).expect("another file");
        let refusal = snapshot_stage_tree(base.path(), 96)
            .err()
            .expect("an over-quota source is refused");
        assert!(refusal.contains("scratch quota"), "{refusal}");
    }

    /// An upload stream is one manifest line in the frame shape a transfer answers with, and then
    /// the announced bytes in manifest order: nothing else travels between the request and the
    /// workspace.
    #[cfg(windows)]
    #[test]
    fn an_upload_stream_is_one_manifest_line_and_then_the_announced_bytes() {
        let base = tempfile::tempdir().expect("source");
        std::fs::write(base.path().join("a.txt"), b"alpha").expect("a file");
        let snapshot = snapshot_stage_tree(base.path(), 1024).expect("the tree is snapshotted");
        let op = crate::subshell::new_op();
        let stream = upload_stream(&op, &snapshot).expect("the stream");
        let newline = stream
            .iter()
            .position(|byte| *byte == b'\n')
            .expect("the manifest line");
        let frame = crate::subshell::Frame::decode(&stream[..newline]).expect("the manifest");
        match frame {
            crate::subshell::Frame::Manifest {
                op: named,
                roots,
                entries,
            } => {
                assert_eq!(named, op);
                assert!(roots.is_empty(), "a stage names no roots");
                assert_eq!(entries, snapshot.entries);
            }
            other => panic!("the upload begins with a manifest, not {other:?}"),
        }
        assert_eq!(&stream[newline + 1..], &snapshot.payload[..]);
    }

    /// The start permit commits only under the authority that admitted the call: a lease already
    /// lowered when readiness arrives is a denied start, before any stop could reach the guest.
    #[cfg(windows)]
    #[test]
    fn a_start_permit_denies_a_lease_already_lowered() {
        use std::sync::atomic::Ordering;

        let permission = shared_permission_for_test();
        let lease = permission.lease();
        permission.set_unchecked(Permission::Read);
        let (writes, mut enqueued) = tokio::sync::mpsc::channel(1);
        let permit = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (_ready, ready) = tokio::sync::mpsc::channel(1);
        let guest = GuestChannel {
            writes: Some(writes),
            permit: Arc::clone(&permit),
            ready,
            decided: false,
            required: Permission::Read,
        };
        commit_permit(
            &mut Some(guest),
            Some(&lease),
            std::time::Duration::from_secs(1),
        );
        assert!(
            !permit.load(Ordering::Acquire),
            "a lowered lease never commits a start"
        );
        assert!(
            enqueued.try_recv().is_err(),
            "no permit line is written for a denied start"
        );

        // A lease that still holds the authority commits exactly one permit line.
        let (writes, mut enqueued) = tokio::sync::mpsc::channel(1);
        let permit = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (_ready, ready) = tokio::sync::mpsc::channel(1);
        let guest = GuestChannel {
            writes: Some(writes),
            permit: Arc::clone(&permit),
            ready,
            decided: false,
            required: Permission::Read,
        };
        let fresh = permission.lease();
        commit_permit(
            &mut Some(guest),
            Some(&fresh),
            std::time::Duration::from_secs(1),
        );
        assert!(
            permit.load(Ordering::Acquire),
            "a live lease commits the start"
        );
        assert!(
            matches!(enqueued.try_recv(), Ok(LeaseWrite::Permit(_))),
            "the committed start carries its permit line"
        );
    }

    /// A run that reaches its deadline is stopped through the same withdrawal a stop uses, and
    /// the record says the guest's end is unconfirmed: a deadline is not a guest reap.
    #[cfg(windows)]
    #[tokio::test]
    async fn a_run_that_hits_its_deadline_says_its_end_is_unconfirmed() {
        let op = crate::subshell::new_op();
        let context = crate::tools::ToolContext {
            teardown: Some(std::sync::Arc::new(
                crate::tools::TeardownObservation::default(),
            )),
            ..crate::tools::ToolContext::for_test(tokio_util::sync::CancellationToken::new())
        };
        let mut command = stand_in_runner(&format!(
            "'{{\"frame\":\"ready\",\"op\":\"{op}\"}}'; \
             if ($null -ne [Console]::In.ReadLine()) {{ \
             '{{\"frame\":\"started\",\"op\":\"{op}\"}}'; \
             [Console]::Out.Write('{{\"frame\":\"output\",\"stream\":\"stdout\",\"len\":4}}' + \"`n\"); \
             [Console]::Out.Write(\"here\"); [Console]::Out.Flush() }}; \
             Start-Sleep -Seconds 30"
        ));
        let tree = crate::process::spawn_tree(&mut command).expect("spawn the stand-in launcher");
        let output = run_command_tree_route(
            tree,
            Some(WslRun {
                op,
                required: Permission::Read,
            }),
            std::time::Duration::from_secs(3),
            &context,
            CommandRoute::Wsl,
            None,
            None,
        )
        .await
        .expect("a deadline is a result");
        let text = output
            .content
            .iter()
            .filter_map(|content| match content {
                crate::conversation::ToolResultContent::Text { text } => Some(text.as_str()),
                _ => None,
            })
            .collect::<String>();
        assert!(text.contains("timed out after"), "{text}");
        assert!(text.contains("end is unconfirmed"), "{text}");
        assert_eq!(
            context
                .teardown
                .as_ref()
                .expect("the test asked for an observation")
                .confirmed(),
            Some(false),
            "the local deadline's end does not confirm the guest's"
        );
    }
}
