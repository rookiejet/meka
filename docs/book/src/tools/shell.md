# Shell tool

## `shell_execute` with `wsl`

When a managed WSL target is configured, `shell_execute` takes an optional `wsl` parameter that
routes the command through the managed WSL broker as a one-shot confined call instead of the
native shell. The channel is call-bound: it is created and destroyed within the call, never a
persistent endpoint. This is for a literal invocation from inside PowerShell; raw `wsl.exe`
keeps its current behavior.

| `wsl` parameter | Description |
|---|---|
| `working_directory` | Required, a granted WSL directory to mount at `/workspace`. |
| `workspace` | Optional additional workspace grants, mounted at `/workspaces/0`, `/workspaces/1`, etc. |
| `readable` | Optional additional read-only grants, mounted at `/references/0`, `/references/1`, etc. |
| `read_only` | Optional. Mount everything read-only. |

## `shell_execute` with `ssh`

When `[shell.ssh]` configures named targets, `shell_execute` takes an optional `ssh` parameter to
route a command through one. A remote login is not a boundary this process can enforce, so the
route requires `unrestricted` permission and a session whose `[permissions].network` is `host`.
A remote-only setting cannot be enforced here: the local client dials whatever address the target
names, including one on this machine, so `remote` and `none` both refuse the route. It is not
offered by `meka serve`, whose sessions are built per request, and a scoped
sub-agent does not inherit the targets; a bare worker holds the parent's directories. The target
address is the scope.

Each call runs an absolute `ssh` binary with `-F none`, so no ambient SSH configuration applies.
The configured key is the only identity (`IdentitiesOnly=yes`, `IdentityAgent=none`,
`BatchMode=yes`, so a passphrase prompt cannot hang the call), and the server must present the
key pinned by `host_key`: `StrictHostKeyChecking=yes` reads a private, per-call known-hosts file
holding that one entry. Forwarding, X11, the agent and local commands are off. A certificate
configured for the target is a client credential for `key`, not proof of the server's identity.

| `ssh` parameter | Description |
|---|---|
| `target` | Required, the name of the SSH target from `[shell.ssh]`. |
| `working_directory` | Optional, an absolute path on the remote host; the command runs as `cd -- /absolute/path || exit 1` followed by the command, so a directory that cannot be entered ends the call before any later line runs. Not a sandbox boundary. |

The configured key, and the certificate when one is set, must be readable files before the
client starts. OpenSSH falls back to the user's default identities when a configured key cannot
be used, even with `-F none`, `IdentitiesOnly=yes` and `IdentityAgent=none`, and the call runs
without an ambient `HOME` for it to find them in; a missing credential is therefore a refusal,
never a quiet login as somebody else. Public-key authentication is the only method the client may
try, and `CertificateFile` is the configured certificate or `none`, so a companion certificate
beside the key is not discovered. The launch is serialized with permission changes: it holds
the level's setter lock across the check and the launch, checks the session's snapshot token and
the ceiling under that lock, refuses to start if a downgrade ended that authority, and does not
spawn a client for a call already stopped, so a login cannot slip between the check and the
client.

Output streams under the same capture bound and deadline as the native shell. A timeout,
cancellation or a lowered permission stops the local `ssh` client, and `ssh` closes its channel,
but nothing confirms that the remote job ended: the remote state is unknown and the command may
keep running on the target. Start a cleanup command as a new call where that matters. An exit
status is reported when the client saw the remote shell exit. Status 255 is the client's own
failure code and is also what a remote command exiting 255 returns, so the call reports that
the two cannot be told apart rather than presenting it as a confirmed remote exit; any other
transport failure is reported as a failed call.

## `subshell_open` / `subshell_execute` / `subshell_export` / `subshell_close`

Run POSIX shell commands on a configured WSL 2 distribution from a top-level Windows session.
These tools do not change what PowerShell, Windows file tools, or a raw `wsl.exe` invocation can
access. They are available to sub-agents under the parent's ceiling: a sub-agent may narrow its
level, directories, and network access, never widen them. A scoped sub-agent does not inherit
the WSL or SSH targets; a bare worker holds the parent's directories. They are not available to
schedule gates or HTTP sessions.

### Setup and scope

1. Check that the distro is WSL 2 with `wsl --list --verbose`. Its default Linux user must not be
   root. It needs a Linux-native ext root filesystem, `/bin/sh`, GNU `env` and `stat` in `/usr/bin`,
   a root-owned `/usr/bin/bwrap` with fd bind support, unprivileged user namespaces, seccomp and
   Landlock ABI 6 or newer. The guest runner supports x86-64 and little-endian ARM64.
2. Set [`[shell.wsl]`](../configuration/config-file.md#shellwsl) in the **Windows** config, then
   grant one or more real Linux directories on the distro root filesystem:

```powershell
meka --permission workspace `
  --additional-workspace-directory '\\wsl.localhost\Ubuntu\home\dev\project' `
  --additional-readable-directory '\\wsl$\Ubuntu\home\dev\reference'
```

### Runner selection

Meka tries `/usr/local/bin/meka-runner` first. An administrator can install the matching Linux
Meka binary under that name without replacing an existing `meka` command. It must be an
executable on the distro's root ext filesystem, owned by root with no setuid or setgid bits.
The path may not contain symlinks or components writable by group or others. A present but
untrusted or failing runner is an error, not a reason to try a different binary.

The runner speaks a versioned protocol, currently version 6. Protocol 6 frames command stdout
and stderr on the runner's stdout together with `started`, `stopped` and `done` control frames,
so no raw command byte can be mistaken for a teardown proof; protocol 5 made staging and export
runner-owned typed transfers; protocol 4 changed the hello line and the request shape. An
installed runner left by an older Meka is refused at the first exchange with both versions named
rather than misread; install the matching Linux Meka under the same name to upgrade it. The
bundled runner is built from this tree and speaks the same version.

If the path is absent, the Windows release deploys its bundled x86-64 `meka-runner` on demand:
a bundled loader receives it over the launcher pipe, verifies it in a sealed anonymous Linux
file, and runs it from there without writing an installation. No guest cache is kept and no
interpreter in the distro is required. Deployment needs kernel support for executable, sealable
memory files. It uses no downloads, guest credentials, or elevation. Use an installed runner on
other guest architectures or when the distro restricts executable memory files.
Neither form needs a Linux Meka config or store.

### The handle

`subshell_open` pins one admitted scope and returns a handle: a caller-chosen name of 1 to 64
letters, digits, `.`, `_` or `-`. Every later call names the handle. `subshell_execute` runs one
command in the scope, `subshell_export` copies files out of it, `subshell_close` ends it. The
handle holds a scope, not a live shell: every call starts its own supervised launcher and guest
sandbox, so what a command changes directory into, exports, or leaves running cannot carry
authority into a later call. A handle belongs to the session that opened it and is released at
close or at the session's end; the close report says how many running commands it stopped, and
waits up to ten seconds for the guest namespace to end. A teardown not confirmed by then is
reported as unconfirmed rather than presented as done. The
guest runner is the command namespace's PID 1: it outlives the user shell, reaps it, and kills any
process the shell left behind before it exits, so a stopped command's processes are ended with the
namespace. If the Windows launcher itself is terminated before the runner can end, no guest
acknowledgement reaches Meka and that teardown is unconfirmed.

For example, open one with:

```json
{"handle":"work","working_directory":"/home/dev/project","readable":["/home/dev/reference"]}
```

| `subshell_open` parameter | Description |
|-----------|-------------|
| `handle` | Required, the name the other three tools address. |
| `working_directory` | Required unless `scratch` is given, exact case-sensitive Linux path or Windows drive-absolute path of one grant. Mounted at `/workspace`. |
| `scratch` | Optional, mutually exclusive with `working_directory`. Open the handle over a private Linux-native scratch workspace holding a snapshot of `source` instead of the live tree; see [Scratch workspaces](#scratch-workspaces). |
| `workspace` | Optional additional workspace grants, mounted in order at `/workspaces/0`, `/workspaces/1`, and so on. Refused with `scratch`, whose mount table is the snapshot alone. |
| `readable` | Optional additional workspace or readable grants, mounted read-only in order at `/references/0`, `/references/1`, and so on. |
| `read_only` | Optional. Mount all selected roots read-only even at `workspace` or `unrestricted`. |

The mount scope is fixed at open, and the guest has no network, Windows drives, or ambient
Linux home directory. It has a private 256 MiB `/tmp`, discarded when the handle closes. Files
written to a direct workspace persist. A grant not selected is not mounted; symlinks, mount
crossings and overlapping grants are refused. A workspace directory the runner can resolve is
also a Windows-backed guest view of the managed target: the guest reads the kernel's own mount
table to find the drive mount and checks a per-request identity proof before the mount is
trusted.

### Scratch workspaces

With `scratch` instead of `working_directory`, the handle runs over a private directory the
guest creates under `/var/tmp/meka-scratch` rather than over a live tree. `source` names the
directory to snapshot into it: a Windows path beneath one of the session's workspace roots, or
a granted WSL directory. A Windows grant naming a drive root or one that overlaps Meka's private
directories is refused before a scratch opens. The snapshot is one typed transfer. A guest source
is walked by the runner itself: it opens every source directory and file, records each entry's
length, modification time and SHA-256 digest, and refuses links, hard links and mount crossings
while it copies. A Windows source is walked by the host under its native read fence and uploaded
to the guest instead: every file is read through the handle it is identified at, to exactly the
length it announced, and a file that changed, grew, or took another name while it was read refuses
the snapshot. The runner writes what arrived into the workspace and refuses any file whose bytes
do not hash to the digest announced for it, so the copy is what the fence read or nothing is. A
Windows source is admitted against the file tools' read boundary before the request, and a
guest source is admitted by the target's own grants and ancestor checks, since WSL grants are
deliberately not part of the native read scope. A file
with more than one hard link is refused because another name could change it after its bytes
were copied. The staged size is bounded by `quota_mb` (1 to 8192 MiB, 1024 by default): a guest
stage counts the bytes each write actually produces, and an upload is judged by the lengths its
manifest announces before any byte of it is read, so a file that grows while it is staged cannot
slip past the quota. The guest checks the workspace's allocated blocks before each command; one
command can exceed the quota in its own writes, and the next call then refuses to run until the
handle exports and closes. The directory
is private to the guest user the runner runs as, and only it is bound into commands, at
`/workspace`, so a build runs at Linux speed on the distro's own filesystem.

A scratch workspace holds a copy, not a link: nothing written in it reaches the source on its
own. Exporting is the only way out, and export paths may name `/workspace` or the staged path.
When an export lands over the staged source region it is checked against what the snapshot
recorded for each file, its length, modification time and SHA-256 digest: one that changed,
disappeared, or appeared there since the snapshot refuses the whole export, and no option changes
that, because copying over it would lose work the snapshot does not hold. The fresh-name rule below
also applies there: an unchanged staged file is still an existing destination name, so a copy back
to it is refused and must be exported under a new name.

The workspace is deleted when the handle closes. A session that ends without closing leaves it
to the guest reaper, which removes abandoned workspaces a day past their last use; a failed stage
that produced no manifest is left there too, because the host cannot prove it owns that id. A
scan that cannot read the scratch root refuses to open rather than adopting a directory it cannot
account for. Both deletion paths lose what was never exported, by design: anything worth keeping
must be exported first. Scratch mode runs at `workspace` or above, and cannot combine with
`read_only` or `workspace` mounts.

### Commands

`subshell_execute` runs one POSIX shell script in the handle's sandbox. Each call is a fresh
environment: what one command exports or changes directory into does not survive to the next
call, so the handle's mount scope is the only thing it remembers.

| `subshell_execute` parameter | Description |
|-----------|-------------|
| `handle` | Required, the open handle. |
| `command` | Required, POSIX shell script, up to 64 KiB. |
| `timeout_ms` | Optional, defaults to 30 seconds; at most one hour. |
| `scratchpad` | Optional host scratchpad entry name for the output. |

The tool requires at least `read`. At `read`, or if the working directory is a readable grant,
all roots are read-only. Otherwise only the selected workspace mounts can be written, even at
`unrestricted`. Output streams, the 64 MiB capture bound, cancellation and background tasks
follow the native shell's tool behavior.

A stop or timeout asks the guest to end its command and reap it, then waits a bounded grace for
the guest's own terminal proof before the local launcher is torn down. What the result then says
takes one of three shapes: the guest reported the reaped namespace and its status, the command
never started because no start permit was acknowledged, or the end is unconfirmed. A local
launcher's exit never stands in for the guest's end, and a run whose frames are missing is
reported as broken, never as a clean result.

### Exporting

`subshell_export` copies files and directory trees out of the admitted scope into the session's
current write boundary. A guest source is read by the runner and streamed over the typed
transfer channel; the host writes every file to a private temporary and publishes them together
only after the response's done frame and a successful runner exit, so a failed transfer leaves
no destination behind. A native source is read by the host and published file by file. Nothing
is created inside the guest, and the destination is the Windows path the copy lands in.

| `subshell_export` parameter | Description |
|-----------|-------------|
| `handle` | Required, the open handle. |
| `paths` | Required, absolute normalized Linux paths beneath the scope's grants. |
| `destination` | Required, a Windows path in the session's write boundary. |

Every destination name must be unused: an existing file is refused when the plan is made, before
a temporary is created or a byte is copied, and the tool has no replacement path to offer. Export
to a fresh name. This is a breaking change from earlier versions, where `overwrite` could ask for a
replacement.

Every source must name exactly what the scope admitted: nothing the scope would hide from the
shell comes back through the export. Symlinks, hardlinks the handle's inodes do not account
for, and any file under a symlinked or reparse directory are refused rather than followed, so
the export cannot read outside the scope through a link it did not admit. A directory copies
its whole tree under its own name; two sources with one basename are refused together. The
destination is checked against the session's write boundary as it stands at the call and again
at every target, so a permission downgrade or cancellation stops the export between files. A
native export keeps what it already copied; a guest export publishes nothing until its transfer
completes. Every guest name is checked as one Windows component before
anything is written: a name holding a backslash, slash, colon, wildcard, control character, a
reserved device name, a trailing dot or space, or a second planned target that differs only in
case is refused rather than silently turned into a different path. Each destination component is
created by name and must be a real directory, and a copy is written through no reparse point. The
publish is no-clobber: a destination the plan found absent is moved into place only if it is still
absent, so a file that appears during the copy is refused, never replaced, and the rename runs
against the pinned destination directory handle rather than a pathname that could have been
swapped. Exports are admitted only on a local fixed NTFS or ReFS volume; a DrvFS, network-backed
or unrecognized destination is refused at the door, because those providers cannot promise the
identity and no-replace guarantees the publication runs on. There is no move-aside, recheck or
restore path and no pathname rename or delete fallback: cleanup removes only the object the
export created. If a stop, close or permission downgrade wins between publications, the files
already published remain where they landed and the error says how many were published before it
and remain; the tool never claims a whole-tree publish or a clean slate when part of one landed.
Files earlier commands created are exportable like any other, provided the destination name is
free; there is no automatic copying. For a scratch handle the paths may name `/workspace` or the
staged path, and a copy landing over the staged source region follows the conflict rule in
[Scratch workspaces](#scratch-workspaces) and the fresh-name rule above.

### Closing

`subshell_close` takes one `handle`, reports what its stop observed (the commands it stopped and
the end each one proved, distinguishing a command that never started, a guest-reaped end and an
unconfirmed one) and releases the name for the session to reuse. A released name is free for a
new handle at once; a close only ever reaches the handle it closed, never a later generation
reusing the name. Naming a handle that was never opened, was already closed, or belongs to
another session is refused with the names the session holds.

### Permissions and lifecycle

The tools require at least `read`. A stricter permission override on any of the four raises its
minimum here; approval cannot replace that live session permission. A permission change never
widens what an open handle can reach: a downgrade narrows its access at once and an upgrade
opens none of the granted mounts, and every call re-checks the session's current level and
roots before it acts. Disabling `shell_execute` disables these tools too. If using
`[tools].allowed_tools`, name all four. The Windows Job Object supervises the launcher, not the
Linux guest's memory; the guest runner tears down the command namespace it holds, but a launcher
killed abruptly leaves that teardown unconfirmed, as above. The distro's administrator and system
runtime are trusted; a sandbox setup failure never falls back to an ordinary WSL shell.

## `shell_execute`

Execute a shell command and return its output.

**Permission:** `read` (sandboxed read-only) / `workspace` (sandboxed, writable inside the workspace) / `unrestricted` (unsandboxed)

### Parameters

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `command` | string | yes | The shell command to execute |
| `timeout_ms` | integer | no | Timeout in milliseconds (default: 30000) |
| `scratchpad` | string | no | Save output to the scratchpad under this name |

### Behavior

- Executes the command via `sh -c "<command>"` on Unix, or `powershell.exe -NoProfile -NonInteractive -Command "<command>"` on Windows, whether or not the command is sandboxed.
- Captures both stdout and stderr.
- Returns the exit code along with the output if non-zero.
- Oversized output is losslessly persisted to the scratchpad by the agent layer; the tool never truncates what it returns to the agent.
- A command may print up to 64 MiB across stdout and stderr. Past that it is stopped, the way a timeout stops it, and the result states the reason and then carries everything it printed up to the stop. Nothing is elided and nothing is written to disk: the whole output is in the result, and in the scratchpad when it is too large for the conversation. The bound exists because a command that writes faster than the turn ends (`cat /dev/zero`, a runaway build log) would otherwise grow one buffer until the process died; a command that hits it wants a narrower rerun (`grep`, `head`, `tail`), not a larger bound.
- Default timeout is 30 seconds. If the command exceeds the timeout, it is killed with every process it started (on Unix through its process group, on Windows through its Job Object), and the result keeps what it printed before the kill.
- Supports cancellation: pressing Ctrl+C while a command is running kills the command and everything it started.

### Shell-specific semantics

- **Unix (`sh -c`)**: POSIX `$VAR` expansion applies. Pass a literal `$` with single quotes (`'$foo'`) or backslash escape (`\$foo`).
- **Windows (`powershell.exe -Command`)**: The script body reaches PowerShell directly. Use PowerShell syntax (`$var = ...`, `$env:PATH`), and crucially, **do not** wrap your command in another `powershell -Command "..."`. The outer PowerShell will expand your inner `$var` references to empty strings before the inner shell runs, producing a parser error on mangled syntax. If you need to invoke a nested script, drop it into a `.ps1` file and run it by path, use `-EncodedCommand <base64>`, or escape each `$` as `` `$ ``.

### Network

The sandbox leaves the network open by default: the threat model is "no state mutation", and `curl http://x | pdftotext` must keep working. [`[permissions].network`](../configuration/config-file.md#permissions) narrows it for a confined command and for `web_fetch` alike. `none` cuts a command off: Bubblewrap unshares the network namespace, so not even loopback answers; Landlock handles every TCP bind and connect from ABI v4 and every UDP bind and send from ABI v10 (kernel 7.2), and grants no port, which leaves UDP open on a kernel between the two, and no other protocol, so an ICMP socket (`ping`) still reaches the network where Landlock confines alone; `sandbox-exec` withholds its outbound rule under `(deny default)`, which closes every socket while the system resolver's Mach service stays reachable, so a command can still look names up; the Windows AppContainer grants no network capability. `remote` keeps a command off this machine while other machines stay reachable, which the AppContainer holds; Bubblewrap, Landlock and `sandbox-exec` hold it as `none`, cutting the command off whole, and startup says so once with the value to set that silences the warning. The Windows restricted token cannot cut a command off at all and warns once at startup. A
FreeBSD jail leaves a command's network to its operator's policy instead. The setting reaches `web_fetch` too, which runs in the Meka process where no sandbox reaches: withheld whole under `none`, and under `remote` refusing this machine's own addresses at the URL, at every redirect and at the resolver; with a proxy configured the proxy resolves the target and the resolver sees the proxy's name alone, as under `[web].refuse_private_destinations`. It never reaches an MCP server, which is a process outside the sandbox: withhold the server instead. A sub-agent holds its parent's setting unless its spawn narrows it with `network`, and the scope lines of a session whose network is narrowed name what the shell and `web_fetch` each reach, `Network: none (shell and web_fetch)` or `Network: remote (web_fetch), none (shell)`.

### Memory

A command that takes every byte the machine has is the process that loses it, not Meka, wherever the platform has a lever, so the session survives and the result says the command died:

- **Linux**: every process Meka starts runs at the highest `oom_score_adj`, inherited by the shell, the Bubblewrap or Landlock layer around it and everything they start. Whether the service's cgroup or the whole host runs out of memory, the kernel's OOM killer takes that process, a stdio MCP server included, ahead of Meka and of everything else on the host, whatever Meka's own score is.
- **Windows**: every process Meka starts runs in a Job Object whose committed memory stops at the machine's physical memory. Past it the command's own allocations fail and it exits; Meka's never do. The cap is per command, so two commands can still exhaust the machine together. The job ends with the command: when it returns, times out or is stopped, every process it started is ended, so a server a command left running in the background does not outlive the call. A program started through an app execution alias (the `python` or `winget` shims under `WindowsApps`) runs outside the command's job, so neither the cap nor the kill reaches it; name such an executable by its real path.
- **macOS**: no lever exists for one process over another. The system takes the largest footprint first, which is the runaway command.

This covers every process Meka starts: shell commands, the screen's `!` commands, schedule gates, stdio MCP servers and an HTTP MCP server's `headers_helper`. Two exceptions are the user's own processes: the editor `meka skill edit` and `meka memory edit` open, and the browser the screen opens for a URL a server asks for.

Running `meka serve` under systemd, give the unit a ceiling and tell systemd that a command's death is not Meka's:

```ini
[Service]
MemoryMax=75%
MemorySwapMax=0
OOMPolicy=continue
OOMScoreAdjust=-900
```

`MemoryMax=75%` is relative to the machine's physical memory, so the unit moves with its host. `OOMPolicy=continue` keeps the unit running when the kernel kills a command inside it; the default, `stop`, ends Meka too. `OOMScoreAdjust=-900` ranks Meka below everything else the host runs.

### Read-only sandbox

At **`read`**, commands run inside a sandbox that blocks writes to the user's real data. Reads, program execution, and network access still work normally: the threat model is "no state mutation, but `curl http://x | pdftotext` must keep working."

#### What's blocked vs allowed (across all backends)

| Surface | Blocked | Allowed |
|---|---|---|
| Filesystem writes outside tmp / Low-integrity paths | ✓ | |
| File metadata changes (mode, owner, timestamps, extended attributes) | Bubblewrap / macOS / Windows restricted token / Windows AppContainer, which alone still lets a command rewrite the ACL of a file the user owns, an owner right no grant withdraws | Landlock alone, on every kernel |
| Filesystem reads of Meka's config directory and store | Bubblewrap / Landlock / macOS / FreeBSD / Windows AppContainer | Windows restricted token |
| Filesystem reads outside the session's roots and the system directories, with [`[permissions].confine_reads`](../usage/permissions.md#the-read-boundary) on | Bubblewrap / Landlock / macOS / Windows AppContainer | Windows restricted token (anywhere) / FreeBSD's shell (the jail's mount set) |
| Filesystem reads elsewhere, with `confine_reads` off | | ✓ (FreeBSD's shell: wherever the jail's mount set reaches) |
| Unix sockets the Bubblewrap masks do not cover (`$HOME`, `/var/lib`, the abstract namespace) | Landlock, and Bubblewrap on kernel 7.1+ (6.12+ for the abstract namespace) | Bubblewrap on older kernels / Windows |
| Program execution | | ✓ |
| Outbound network, with [`[permissions].network`](../configuration/config-file.md#permissions) at its default `host` | | ✓ |
| Outbound network, with `[permissions].network = "none"` | Bubblewrap (the namespace is unshared) / Landlock (every TCP port from ABI v4 and every UDP port from ABI v10; UDP stays open below v10) / macOS / Windows AppContainer | Windows restricted token / FreeBSD's shell (the jail keeps the stack it shares) |
| Outbound network to this machine, with `[permissions].network = "remote"` (other machines stay reachable) | Windows AppContainer; Bubblewrap / Landlock / macOS hold it as `none` and cut the command off whole | Windows restricted token / FreeBSD's shell (the jail keeps the stack it shares) |
| dbus / systemd-user state mutations | Bubblewrap / macOS / Landlock | Windows |
| Mach IPC state mutation (launchd, pasteboard, LaunchServices) | macOS | Linux / Windows |
| The user's clipboard, other windows' handles and messages, input injection, global atoms, system parameters, display settings and desktop switches (Windows) | Windows, on both backends: the job's UI restrictions, with the IME and injection bits from the builds that have them | |
| COM / RPC to Low-integrity-accepting services (Windows) | | ✓ |
| Inheritance of sensitive parent env vars (API keys, OAuth tokens, …) | ✓ (all platforms) | |

The sandbox is not an adversarial containment boundary; it's defense-in-depth against an agent accidentally modifying user data. Set permission to `none` if you don't trust a turn at all.

#### Scratch space

Whether a confined command has somewhere to write temporary files differs by backend:

| Backend | Scratch space | Effect |
|---|---|---|
| Bubblewrap (`read`) | Private `/tmp` tmpfs, gone with the sandbox | `mktemp`, Python's `tempfile`, `gcc`, `patch` and `pip` builds all work |
| Landlock (`read` and `workspace`) | A private directory per command, named by `TMPDIR`, `TMP` and `TEMP`, removed when the command ends | The same tools work; a program with a literal `/tmp` in it is still refused |
| FreeBSD jailbroker (both levels) | Private `/tmp` and `/var/tmp` tmpfs | `mktemp`, `git`, `python`, `gpg`, `pip` all work |
| Windows `workspace` | None outside the roots | `New-TemporaryFile` is denied (measured) |
| macOS Seatbelt (`read`) | Per-backend; see below | |

Under Bubblewrap the child writes into an in-memory `/tmp` that vanishes with the sandbox, so nothing real is touched; the FreeBSD jailbroker's jail likewise gets a private writable `/tmp` and `/var/tmp`, so `mktemp` succeeds and the write goes nowhere real. Landlock can only decide which real paths a process may touch, so Meka creates an owner-only directory under the temp directory for each command, grants it in the ruleset, points `TMPDIR` at it and removes it afterwards; a directory a crash left behind is swept a day later. `git` needs none of this: its lock file lives inside the repository, which is read-only under all three backends alike.

The practical cost is diagnostic: the failure is a bare `Permission denied` naming a path in `/tmp` (or `%TEMP%` on Windows), with nothing in the message connecting it to the sandbox. If a command fails that way and you expected it to work, add the directory it wants as a writable root at `workspace`.

#### Environment variable scrubbing

The `read` sandbox still permits outbound network (the threat model intentionally keeps `curl http://x | pdftotext`-style pipelines working), so any secret in the parent process's environment (`ANTHROPIC_API_KEY`, `AWS_SECRET_ACCESS_KEY`, `GITHUB_TOKEN`, OAuth tokens, etc.) would be a live exfiltration vector under prompt injection. Meka scrubs the child environment at spawn time across every backend (Bubblewrap, Landlock, Seatbelt, and both Windows backends).

- **Unix (Linux + macOS): allow-list.** Only a curated set of vars survives into the `read` child: `PATH`, `HOME`, `USER`, `LOGNAME`, `SHELL`, `PWD`, `TERM`, `COLORTERM`, `LANG`, `TMPDIR`, `TMP`, `TEMP`, plus everything matching the `LC_*` and `XDG_*` prefixes. Because `read` intentionally keeps outbound network working, the proxy and CA-bundle vars survive too: `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY`, `ALL_PROXY` (and their lowercase spellings), `SSL_CERT_FILE`, `SSL_CERT_DIR`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE` and `NODE_EXTRA_CA_CERTS`, several of which redirect TLS trust, so treat them as part of the boundary. Anything else is dropped, including credential-shaped vars (`AWS_*`, `GITHUB_TOKEN`, `OPENAI_API_KEY`, …) and credential-pointer vars (`SSH_AUTH_SOCK`, `KUBECONFIG`, `GNUPGHOME`, `NETRC`, `GIT_ASKPASS`, `GIT_SSH_COMMAND`, etc.) as well as benign-but-unlisted vars like `EDITOR`, `PAGER`, `DISPLAY`, custom toolchain vars, and so on. Unknown vars are dropped by default.
- **Windows: deny-list.** PowerShell pulls in a long tail of system vars (`PSModulePath`, `APPDATA`, `ProgramFiles`, etc.) that don't fit a tidy allow-list, so the Windows path lets everything through *except* names that match a heuristic deny-list. Dropped names include:
    - Credential-shaped substrings: `*TOKEN*`, `*SECRET*`, `*PASSWORD*`, `*PASSPHRASE*`, `*API_KEY*`, `*_KEY*`, `*BEARER*`, `*CREDENTIAL*`, etc.
    - Credential-pointer substrings: `SSH_AUTH_SOCK`, `KUBECONFIG`, `GNUPGHOME`, `NETRC`, `GIT_ASKPASS`, `SSH_ASKPASS`, `GIT_SSH_COMMAND`.
    - Provider / service prefixes: `ANTHROPIC_*`, `OPENAI_*`, `AWS_*`, `GCP_*`, `GOOGLE_*`, `AZURE_*`, `GITHUB_*`, `OPENROUTER_*`, `GROQ_*`, `MISTRAL_*`, `COHERE_*`, `DATABASE_*`, `POSTGRES_*`, `MONGO_*`, `STRIPE_*`, `CLOUDFLARE_*`, `VAULT_*`, `OAUTH_*`, `JWT_*`, `SENTRY_*`, `SLACK_*`, `DISCORD_*`, and others; see `is_sensitive_env_name` in `src/sandbox.rs` for the full list.

  The deny-list is intentionally aggressive on false positives (a legitimate `GITHUB_ACTOR` is dropped alongside `GITHUB_TOKEN`) because the cost of a missing env var is a confusing tool error, while the cost of a leaked credential is a live exfiltration channel.

**`unrestricted` keeps the full parent environment.** This is the trusted-operation path where users legitimately need `NPM_TOKEN` for `npm publish`, `AWS_*` creds for `aws s3 cp`, `GH_TOKEN` for `gh pr create`, etc. If you need a specific var inside a sandboxed shell command, switch to it for that turn.

An approved command is not an exception: with [approvals](../usage/permissions.md#approvals) on, a command you approve at `read` or `workspace` still runs in that level's sandbox with the scrubbed environment. Approval never widens reach, so the prompt is a question about whether to run the command, not a grant of the environment behind it.

#### Linux: pick a backend

Linux has two sandbox mechanisms and three values for `[shell].sandbox_backend` in `config.toml`:

- **Bubblewrap** (`sandbox_backend = "bubblewrap"`, recommended): wraps the command in `bwrap` with `--ro-bind /`, tmpfs masks over `/run`, `/tmp`, `/var/tmp`, and `$XDG_RUNTIME_DIR` (each where the directory exists), plus `--unshare-user --unshare-pid --unshare-uts --unshare-ipc`. The tmpfs masks make the dbus session bus, systemd-user socket, and other socket-on-disk IPC paths unreachable, so `systemctl --user start <unit>`, `dbus-send`, and similar state-changing calls fail. Network is not unshared. On a kernel with Landlock ABI v6 (6.12) or newer, the command also runs inside Meka's Landlock ruleset: bwrap execs `meka confine`, which enacts the ruleset after the mounts and then runs the shell. That closes what the masks leave open: the abstract socket namespace and signals to outside processes, ioctls on real devices, and from kernel 7.1 a socket under `$HOME` or `/var/lib` too. Requires the `bubblewrap` package and a kernel with user-namespace creation enabled; Ubuntu 24.04 also needs the `bwrap-userns-restrict` AppArmor profile from `apparmor-profiles`.
- **Bubblewrap with Landlock** (`sandbox_backend = "bubblewrap-landlock"`): the same as Bubblewrap, but the Landlock layer inside is required rather than added where the kernel allows. On a kernel below 6.12 the backend is reported unusable and the shell at `read` fails instead of running under bwrap alone. What the layer closes still follows the kernel, sockets on disk outside the masks only from 7.1. Auto-detection never picks it; pin it on a host where it must be certain the layer is there.
- **Landlock** (`sandbox_backend = "landlock"`, fallback): uses the [Landlock LSM](https://landlock.io/). Blocks filesystem writes via `landlock_restrict_self`. **Requires ABI v9 (kernel 7.1+)**: that is the first ABI with a right over `connect()` to Unix sockets on disk, and below it a sandboxed shell can invoke state-mutating dbus methods and `systemd-run --user` escapes the filesystem restriction entirely. Meka reports Landlock unusable on older kernels rather than sandboxing with a ruleset that leaves that door open, which means kernels below 7.1 (Debian 13, RHEL 10, Ubuntu 24.04 and 26.04 LTS) need Bubblewrap installed for the shell at `read`. Closing that route also breaks socket-based clients such as `docker` and `psql` at `read`. Meka's own directories are hidden by never being covered by a rule: reading files is granted per sibling along the path to each of them, so their names and sizes stay visible but their bytes do not, and the one cost is that a workspace root above them (a root at `$HOME`) can create new files only in its subdirectories. What no Landlock ABI mediates is file metadata: a command at `read` can still `chmod`, `chown`, `touch` and set extended attributes on any file you own. Prefer Bubblewrap, whose read-only bind refuses those and which removes the socket-on-disk paths on any kernel.

`sandbox_backend` is unset unless you pin it yourself; no command writes it. When unset, Meka probes Bubblewrap once at startup and prefers it when available, falling back to Landlock with one warning at startup: that it did so, and that Landlock cannot stop a command changing a file's mode, owner, timestamps or attributes. Pinning `sandbox_backend = "landlock"` accepts that and silences the warning.

```toml
[shell]
sandbox = true                       # default; set to false to disable
sandbox_backend = "bubblewrap"       # or "landlock" or "bubblewrap-landlock"; unset = auto-detect
```

#### macOS

Uses `sandbox-exec` with a hardened SBPL profile (modeled after [Codex](https://github.com/openai/codex)'s vendored seatbelt policy, which is itself based on Chrome's renderer sandbox). The profile is closed-by-default: filesystem writes are blocked, Mach-lookup is restricted to a curated allow-list of safe services, and mutation paths (launchd job control, pasteboard, LaunchServices, distributed notifications) are not in the allow-list. Network and DNS resolution remain available. macOS has one backend, so `sandbox_backend` takes no value there; a value from another platform is refused.

#### Windows: pick a backend

Windows has two backends and two values for `[shell].sandbox_backend`:

- **AppContainer** (`sandbox_backend = "appcontainer"`, preferred): runs the command inside a process security environment the OS enforces, on a Windows 11 build that has the API: 26H2, where Meka measured it, and 24H2 and 25H2 from the August 2026 update, where Microsoft lists it. Meka's config directory and store are denied, the read boundary and a sub-agent's scope hold for the shell as they do for the file tools, `network = "none"` cuts a command off, and no ACE is written to your directories.
- **Restricted token** (`sandbox_backend = "restricted-token"`, fallback): spawns the child with a duplicated primary token dropped to **Low integrity** (`SECURITY_MANDATORY_LOW_RID`) via `SetTokenInformation(TokenIntegrityLevel, …)` at `read`, and under a `WRITE_RESTRICTED` token plus an ACE per workspace directory at `workspace`. Writes to the home directory, `%APPDATA%`, Program Files, and system directories (any location with Medium-or-higher integrity ACLs) are blocked by the kernel. Low integrity also strips token privileges, and the same env scrubbing applied on Unix runs here (see [Environment variable scrubbing](#environment-variable-scrubbing) above). It confines writes only: a command can read Meka's store, `confine_reads` holds for the file tools alone, and `network = "none"` for `web_fetch` alone.

`sandbox_backend` is unset unless you pin it yourself; no command writes it. When unset, Meka probes AppContainer once at startup and prefers it when the build has the API at schema 1.1, falling back to the restricted token with one warning at startup naming what it gives up. A build whose API speaks schema 1.0 has no ingress table and so no loopback exemption: it is not auto-picked, the warning says so, and pinning `sandbox_backend = "appcontainer"` takes it with `network = "host"` held as `remote`. Pinning `sandbox_backend = "restricted-token"` accepts the fallback and silences the warning. A value from another platform (`bubblewrap`, `landlock`) is refused: the shell at `read` fails and startup names the values Windows takes.

Under AppContainer, `read` grants every drive root read-only and denies Meka's config and data directories, `workspace` adds a read-write grant per workspace directory, and `confine_reads` or a sub-agent's scope replaces the drive roots with the readable paths; the environment is created per command and closed after it, which also removes the private `%TEMP%` the OS gives the command. Measured limits of the mechanism, not settings. A read-only grant refuses the directory open that `cd` makes, so `cd` from `cmd`, Python's `os.chdir` and git's own directory change (`git -C`, hooks) fail into a read-only directory, while the command's initial directory, PowerShell's `Set-Location` and `cd` into a workspace directory work; read-only git inspection of a checkout outside the workspace therefore fails at `read` and works at `workspace`. msys2 `bash.exe` cannot start at all, so a tool that runs git's shell scripts fails. A volume without NTFS permissions (a FAT32 removable drive, measured) is unreadable, since it carries no ACE the environment could honor. An app execution alias, such as the `python.exe` the Python install manager places under `WindowsApps`, fails to start with "The file cannot be accessed by the system", while the real executable runs by its own path. A mapped network drive is out of reach, and while one is mapped PowerShell prints `Attempting to perform the InitializeDefaultDrives operation on the 'FileSystem' provider failed.` on stderr once per command, which is noise and not a failure. Pin `sandbox_backend = "restricted-token"` where any of these matters more than the boundary. A Meka started from an SSH session or a service grants its own window station to AppContainer processes at startup (never the interactive `WinSta0`, which has the grant already), since PowerShell cannot start inside the environment without it; a failed grant is warned about once.

Under the restricted token, Low integrity is not a total write-denial: the child can still write to the small residual Low-integrity-writable surface (`%LOCALAPPDATA%\Low`, `%TEMP%\Low`, any path with an explicit Low-integrity write ACE) and to files it creates itself.

Low integrity does not restrict reads at all, and neither does the `workspace` token below, so under the restricted token [`[permissions].confine_reads`](../usage/permissions.md#the-read-boundary) holds for the file tools alone, and startup warns once when it is on. Integrity levels stop a Low-integrity process writing up, not reading up. A command at `read` can therefore read Meka's config directory and store, account credentials included, which the Bubblewrap, Landlock, macOS and AppContainer backends hide; `sandbox_backend = "appcontainer"` is what changes it. Under the restricted token, treat every credential in the store as readable by any sandboxed command, and keep Meka's directories outside every workspace root, because a root's write grant covers everything under it.

#### Windows at `workspace` under the restricted token

`workspace` under the restricted token uses a second mechanism, not the Low-integrity token above; under AppContainer it is a read-write grant in the environment and nothing below applies. Meka derives a capability
SID from each workspace root, places an inheritable `GENERIC_WRITE | DELETE` ACE for it on that
root, and runs the shell under a `WRITE_RESTRICTED` token carrying that capability, so a write
succeeds exactly where one of those ACEs exists. Three consequences worth knowing before you use it:

- Meka has to **own** the root, which is what lets it grant without elevation. A network share or
  another user's folder cannot be a workspace root.
- PowerShell runs in **ConstrainedLanguage** mode under a restricted token, so scripts that
  construct .NET types fail there while working at `unrestricted`. Meka's UTF-8 output preamble is
  skipped for the same reason, so non-ASCII output may be mangled at `workspace`.
- The ACE is real, standing state on your directory, visible in `icacls`. It is released when the
  process exits, Ctrl+C included, but not after a crash or a kill.

See [Permissions](../usage/permissions.md#per-platform-enforcement) for the full account.

#### When the configured backend is unavailable

If the configured backend can't be used (`bwrap` isn't on `$PATH`, user namespaces are denied, the Windows build lacks the AppContainer API, or the value belongs to another platform), `shell_execute` at `read` returns a hard error rather than silently falling back. The error names the configured backend, the specific failure reason and the key to fix. Either install what is missing, set `sandbox_backend` to a value this platform can use, or switch to `unrestricted` (Shift+Tab).

#### FreeBSD

FreeBSD's confinement is not in Meka. `jailbrokerd`, a privileged daemon you run, builds a jail per
command and runs it there as your own uid; Meka sends it a plan over a Unix socket and reads its
events. The platform has no unprivileged mechanism that refuses a write outside a set of paths that
would fit in a process (Capsicum removes pathname lookup rather than write access, and a jail needs
root and is a separate filesystem tree), so the privileged part lives in one small daemon rather
than in Meka.

The only thing to configure here is where that daemon listens:

```toml
[shell]
jailbroker_socket = "/var/run/jailbroker.sock"   # the default
```

`jailbrokerd` and the policy it enforces are set up separately, and that policy is the operator's
rather than Meka's: it names which host paths exist in a jail and which of them may be written. What
the two levels mean once it is listening:

- **`read`** runs the command in a jail whose filesystem is the host as that policy admits it, by
  default `/` read-only with any path the policy denies left out. Nothing is mounted read-write.
  Reads are bounded by that mount set, which is the one place this backend is narrower than the
  others: a path outside it is not there. `/tmp` and `/var/tmp` are masked empty and world-writable
  so a command has a scratch directory (a file another tool left in the host's `/tmp` is not visible
  to it), and Meka's config directory, data directory and command captures are masked last, exactly
  as they are on the other backends. The host's `/var/run` is left alone, because it holds the
  loader's hint file and a mask over that directory takes everything in it, after which every
  program from packages fails to start. What keeps a command out of the daemon's own socket is the
  daemon's rule, which refuses any request that comes from inside a jail it built.
- **`workspace`** is the same jail plus the session's roots, mounted read-write. A root the policy
  grants only for reading is refused by name rather than mounted read-only, and a denied path
  *inside* a root is cut out of it, so the command can write anywhere in that root except there.
  Meka warns when a workspace session comes back with part of a root cut out.

So a `workspace` root has to sit under a path the policy grants for writing, and so does the
session's working directory, which counts as a root because the file tools may write there too. A
policy that grants nothing leaves `read` working everywhere and refuses every `workspace` command;
Meka says so at startup. A refusal names the resolved path and the prefix that decided it, and
nothing is created, so the session you get is never narrower than the level you asked for.

Meka refuses a socket that is not root-owned under a root-owned chain of directories. The daemon
takes orders from whoever can connect, and every plan carries a command's environment and its write
boundary, so a socket another user could have put there is one whose answers are not the broker's.
If nothing is listening, `read` has no shell at all and `shell_execute` at `read` returns the
reason; `unrestricted` runs a command with no jail, as it does everywhere.

The alternative is to run Meka itself inside a jail: every command it spawns is then confined by the
jail's filesystem, network and process view, so `unrestricted` becomes a reasonable level to run at.
The session's roots have to be mounted into the jail at the paths the session uses, Meka's config
and data directories have to live inside it, and its store should be treated as the only copy of
anything the agent may write.

#### Disabling the sandbox entirely

To disable sandboxed shell execution altogether, set `sandbox = false` under `[shell]`. When disabled, shell commands require `unrestricted`: `read` loses the tool entirely, and `workspace` refuses it with an error naming the key, because there is no longer anything to hold the boundary that level promises. Reach for `unrestricted` on those turns rather than expecting `workspace` to quietly run unconfined.

```toml
[shell]
sandbox = false
```
