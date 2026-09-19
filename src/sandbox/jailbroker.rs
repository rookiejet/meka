//! FreeBSD: the confinement a jail builds, and the socket meka reaches it over.
//!
//! meka spawns nothing here. It sends the daemon a plan (a read-only base, masks, the working
//! directory, the writable roots, an environment and an argv) and reads its events; the daemon does
//! the privileged work, which is mounting, creating the jail and running the command as the
//! caller's own uid. What that means for the two levels:
//!
//! - `read` is a jail whose base is the host as the operator's prefix policy admits it and nothing
//!   is mounted read-write. Reads are bounded by that mount set rather than by the host: a path
//!   under a `none` prefix is not there, and a path the operator did not admit is not either.
//! - `workspace` is the same jail plus the session's roots, mounted read-write. A root the policy
//!   grants read-only is refused rather than mounted read-only, and a denied path *inside* a root
//!   is cut out of it, which the daemon reports back as a clip.
//!
//! Two things make the socket the boundary rather than a convenience. The first is [`trust`]: a
//! socket anyone but root could have put there is one whose answers are not the broker's, and the
//! plan meka sends carries an environment and the paths a session may write. The second is that
//! meka states the plan and the daemon decides what it means; the operator's policy is not
//! re-implemented here, only reported.

use std::{
    collections::BTreeMap,
    ffi::OsString,
    path::{Path, PathBuf},
    sync::Arc,
};

use serde::{Deserialize, Serialize};
use tokio::io::BufReader;

use super::{BackendProbe, Confinement, SandboxCapability};

/// The version of the wire this client speaks, and the one it requires the daemon to speak.
const VERSION: u32 = 1;

/// How long the probe waits for an answer before deciding that nothing is listening.
const PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(500);

/// How much of a command's output may be waiting to be read before the daemon is made to wait.
///
/// The daemon streams a line at a time, so without a bound a command producing output faster than
/// the turn consumes it would grow a queue here until the process died. A full channel stops the
/// reader, the socket buffers fill, and the daemon's writer blocks, which is the backpressure every
/// other backend gets from the pipe it spawns.
const OUTPUT_CHANNEL_BYTES: usize = 64 * crate::text::KIB;

/// The read-only base every plan asks for. The daemon clips it to the operator's policy and reports
/// what it cut, which is why meka asks for the whole host rather than assembling a list.
const BASE: &str = "/";

/// The shell a command runs through, named rather than pinned to a path.
///
/// The command is executed by the daemon's `jexec`, which resolves a name against the `PATH` the
/// plan carries, exactly as the unsandboxed path, bubblewrap and `sandbox-exec` resolve theirs
/// inside the process they spawn. An absolute path here would be the one place a shell is found by
/// a rule the command's own words do not follow, and it would break on a plan whose base is not the
/// host's `/`.
const SHELL: &str = "sh";

/// The system paths a jailed command does not see, and the mode each new file system takes.
///
/// `/tmp` and `/var/tmp` are masked empty and world-writable. A command with nowhere to write a
/// scratch file fails at `mktemp`, at `git`'s index lock, at `python`'s `tempfile`, at `gpg` and at
/// `pip`, and the level does not otherwise give it a writable directory. The Linux backends mask
/// them for a different reason, bwrap sharing the host's IPC namespace where a socket in `/tmp`
/// lets something else write on the command's behalf; a jail has its own IPC view, so the only
/// reason here is that a scratch directory has to exist. What it costs is sight of the host's
/// `/tmp`: a file another tool left there is not visible to the command, and a `read` command
/// cannot read one.
///
/// `/var/run` is deliberately not in this list. It holds the loader's hint file,
/// `/var/run/ld-elf.so.hints`, without which every program from packages fails to start, and a mask
/// covers a directory and takes everything in it. The socket the broker listens on sits there too,
/// so masking the directory would hide it; what answers for that socket instead is the broker's
/// own rule, which refuses a request from inside a jail it built, whatever a plan's masks are.
const SYSTEM_MASKS: [(&str, &str); 2] = [("/tmp", "1777"), ("/var/tmp", "1777")];

/// The mode of a mask over one of meka's own directories: empty and unreachable, so the config
/// directory, the credential store and the command-output captures are hidden from the shell the
/// way the write fence refuses them.
const HIDDEN_MASK_MODE: &str = "0700";

/// Whose uid and gid own a mask. Root, because nothing in a mask belongs to the command.
const MASK_OWNER: &str = "root";

/// The level a plan is for, in the daemon's spelling.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Level {
    Read,
    Workspace,
}

impl Level {
    const fn name(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Workspace => "workspace",
        }
    }
}

/// A `tmpfs` the plan asks for: a mask over a path.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct MaskSpec {
    path: PathBuf,
    mode: String,
    owner: String,
}

impl MaskSpec {
    /// A mask over a system path, at the mode the table gives it.
    fn system(path: &str, mode: &str) -> Self {
        Self {
            path: PathBuf::from(path),
            mode: mode.to_string(),
            owner: MASK_OWNER.to_string(),
        }
    }

    /// A mask over one of meka's own directories.
    fn hidden(path: &Path) -> Self {
        Self {
            path: path.to_path_buf(),
            mode: HIDDEN_MASK_MODE.to_string(),
            owner: MASK_OWNER.to_string(),
        }
    }
}

/// One command, in the terms the daemon's plan takes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Plan {
    level: Level,
    cwd: PathBuf,
    base: PathBuf,
    masks: Vec<MaskSpec>,
    writable: Vec<PathBuf>,
    hidden: Vec<MaskSpec>,
    env: BTreeMap<String, String>,
    argv: Vec<String>,
}

/// The plan for one command, from what the shell tool already resolved.
///
/// Everything here is a value the tool has in hand: the confinement it computed once for this call,
/// the session's working directory, meka's own directories and the scrubbed environment. Nothing is
/// read from the host here, and nothing about the operator's policy is decided here.
pub(crate) fn plan_for(
    confinement: &Confinement,
    cwd: &Path,
    private: &[PathBuf],
    environment: &[(OsString, OsString)],
    command: &str,
) -> Plan {
    // An empty root list is a session whose working directory was deleted under it: every backend
    // turns that into "no write lands anywhere", and the daemon refuses a `workspace` plan that
    // names no root, so the level it is sent as is `read`. The roots come from the confinement
    // rather than from a pattern over it, so "what may be written beneath" stays one definition.
    let roots = confinement.writable();
    let (level, writable) = if roots.is_empty() {
        (Level::Read, Vec::new())
    } else {
        (Level::Workspace, roots.to_vec())
    };
    Plan {
        level,
        cwd: cwd.to_path_buf(),
        base: PathBuf::from(BASE),
        masks: SYSTEM_MASKS
            .iter()
            .map(|(path, mode)| MaskSpec::system(path, mode))
            .collect(),
        writable,
        hidden: private.iter().map(|path| MaskSpec::hidden(path)).collect(),
        env: environment
            .iter()
            .filter_map(|(name, value)| {
                Some((name.to_str()?.to_string(), value.to_str()?.to_string()))
            })
            .collect(),
        argv: vec![SHELL.to_string(), "-c".to_string(), command.to_string()],
    }
}

/// One `run` request. The daemon refuses a field it does not know, so this is the whole shape.
#[derive(Serialize)]
struct RunRequest<'a> {
    v: u32,
    op: &'static str,
    id: &'a str,
    level: &'static str,
    cwd: &'a Path,
    base: &'a Path,
    masks: &'a [MaskSpec],
    writable: &'a [PathBuf],
    hidden: &'a [MaskSpec],
    env: &'a BTreeMap<String, String>,
    argv: &'a [String],
}

impl Plan {
    /// The request line for this plan, under the `id` its events come back with.
    fn request(&self, id: &str) -> Result<String, Failure> {
        line(&RunRequest {
            v: VERSION,
            op: "run",
            id,
            level: self.level.name(),
            cwd: &self.cwd,
            base: &self.base,
            masks: &self.masks,
            writable: &self.writable,
            hidden: &self.hidden,
            env: &self.env,
            argv: &self.argv,
        })
    }
}

/// One `probe` request.
#[derive(Serialize)]
struct ProbeRequest {
    v: u32,
    op: &'static str,
}

/// One `cancel` request.
#[derive(Serialize)]
struct CancelRequest<'a> {
    v: u32,
    op: &'static str,
    id: &'a str,
}

/// One line back from the daemon. A field this client does not model is ignored rather than
/// refused: the daemon may add one, and a client that broke on it would be a client that cannot
/// talk to its own broker.
#[derive(Debug, Deserialize)]
#[serde(tag = "event", rename_all = "lowercase")]
enum Event {
    Started {
        jail: String,
        mounts: usize,
        #[serde(default)]
        clipped: Vec<String>,
        dry_run: bool,
    },
    Stdout {
        data: String,
    },
    Stderr {
        data: String,
    },
    Exit {
        status: i32,
        canceled: bool,
    },
    Error {
        kind: String,
        message: String,
    },
    Probe {
        v: u32,
        prefixes: Vec<Prefix>,
    },
}

/// One prefix of the operator's policy, as the probe reports it.
#[derive(Debug, Deserialize)]
struct Prefix {
    path: String,
    mode: String,
}

/// One request, as the wire wants it: JSON and a newline.
fn line<T: Serialize>(value: &T) -> Result<String, Failure> {
    let mut encoded = serde_json::to_string(value)
        .map_err(|error| Failure::new(format!("writing a request for the jailbroker: {error}")))?;
    encoded.push('\n');
    Ok(encoded)
}

/// Decode one line of the protocol.
fn parse_event(text: &str) -> Result<Event, String> {
    serde_json::from_str(text).map_err(|error| {
        format!("the socket is not a jailbroker: it sent a line that is not an event ({error})")
    })
}

/// Why a plan did not run.
#[derive(Debug)]
pub(crate) struct Failure {
    message: String,
}

impl Failure {
    fn new(message: impl std::fmt::Display) -> Self {
        Self {
            message: message.to_string(),
        }
    }

    /// What happened, in one sentence.
    pub(crate) fn message(&self) -> &str {
        &self.message
    }
}

/// Why the socket is not one meka will hand a plan to, or nothing when it is.
///
/// The daemon runs as root and the socket's group is its whole authorization model, so what matters
/// is not who may connect but who could have replaced it. Replacing a socket means writing its
/// directory, so the directories are what this checks, and the socket's own mode is deliberately
/// left out: `0660` with a group is the operator saying which accounts may ask for a jail.
fn trust(socket: &Path) -> Result<(), String> {
    // `symlink_metadata`, not `metadata`: a link is a name that whoever can write the directory can
    // point somewhere else, and this check is about the thing itself.
    let metadata = std::fs::symlink_metadata(socket)
        .map_err(|error| format!("no socket at {} ({error})", socket.display()))?;
    {
        use std::os::unix::fs::{FileTypeExt, MetadataExt};

        if !metadata.file_type().is_socket() {
            return Err(format!("{} is not a socket", socket.display()));
        }
        if metadata.uid() != 0 {
            return Err(format!(
                "the socket at {} is not owned by root, so it is not the broker's",
                socket.display()
            ));
        }
    }
    chain_is_root_owned(socket)
}

/// Whether every directory between `socket` and the root belongs to root alone.
///
/// Split out from [`trust`] for the same reason the bubblewrap check is split from its caller: the
/// interesting inputs are a root-owned socket in a writable directory and a user's socket in a
/// root-owned one, and neither can be built without root. As a predicate it takes the path the
/// daemon usually lives at and a path a test just made, which are the two cases that matter.
fn chain_is_root_owned(socket: &Path) -> Result<(), String> {
    let mut directory = socket.parent();
    while let Some(path) = directory {
        if !super::only_root_can_write(path) {
            return Err(format!(
                "{} is writable by someone other than root, so a socket under it could be anyone's",
                path.display()
            ));
        }
        directory = path.parent();
    }
    Ok(())
}

/// Connect to the socket, having first checked that only root could have put a socket there.
///
/// The one door: the probe and a run both come through it, so a check that is true of a startup
/// probe is true of the call that carries a command.
fn connect_trusted(socket: &Path) -> Result<std::os::unix::net::UnixStream, String> {
    trust(socket)?;
    std::os::unix::net::UnixStream::connect(socket).map_err(|error| {
        format!(
            "connecting to the jailbroker at {} ({error})",
            socket.display()
        )
    })
}

/// What the daemon answers a probe with, as far as meka acts on it.
#[derive(Debug)]
struct Answer {
    /// The prefixes the policy grants for writing. Empty means every `workspace` command is
    /// refused, which is worth saying at startup rather than at the first one, and the paths
    /// themselves are what a caller needs to put a fixture where it will be admitted.
    writable_prefixes: Vec<PathBuf>,
}

/// Ask a connected daemon what it can do.
fn ask(mut stream: std::os::unix::net::UnixStream) -> Result<Answer, String> {
    stream
        .set_read_timeout(Some(PROBE_TIMEOUT))
        .map_err(|error| format!("setting a timeout on the probe: {error}"))?;
    stream
        .set_write_timeout(Some(PROBE_TIMEOUT))
        .map_err(|error| format!("setting a timeout on the probe: {error}"))?;
    let request = line(&ProbeRequest {
        v: VERSION,
        op: "probe",
    })
    .map_err(|failure| failure.message().to_string())?;
    std::io::Write::write_all(&mut stream, request.as_bytes())
        .map_err(|error| format!("asking the jailbroker what it can do: {error}"))?;
    std::io::Write::flush(&mut stream)
        .map_err(|error| format!("asking the jailbroker what it can do: {error}"))?;

    let mut reader = std::io::BufReader::new(stream);
    let mut answer = String::new();
    let read = std::io::BufRead::read_line(&mut reader, &mut answer)
        .map_err(|error| format!("reading the probe's answer: {error}"))?;
    if read == 0 {
        return Err("the jailbroker closed the connection without answering".to_string());
    }
    match parse_event(&answer)? {
        Event::Probe { v, prefixes } => {
            if v != VERSION {
                return Err(format!(
                    "the daemon speaks version {v} and this meka speaks {VERSION}"
                ));
            }
            // Logged rather than compared: the policy is the operator's, and which one meka is
            // talking to is the first question when a command is refused.
            tracing::debug!(
                "the jailbroker's policy: {}",
                prefixes
                    .iter()
                    .map(|prefix| format!("{} {}", prefix.path, prefix.mode))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            Ok(Answer {
                writable_prefixes: prefixes
                    .iter()
                    .filter(|prefix| prefix.mode == "rw")
                    .map(|prefix| PathBuf::from(&prefix.path))
                    .collect(),
            })
        }
        Event::Error { kind, message } => Err(format!(
            "the jailbroker answered the probe with {kind}: {message}"
        )),
        other => Err(format!(
            "the jailbroker answered the probe with {other:?}, which is not one"
        )),
    }
}

/// Probe the daemon: is a trusted socket there, and does it answer.
pub(crate) fn probe(socket: &Path) -> BackendProbe {
    let stream = match connect_trusted(socket) {
        Ok(stream) => stream,
        Err(reason) => return BackendProbe::Missing { reason },
    };
    match ask(stream) {
        Ok(answer) => BackendProbe::Ok(SandboxCapability::Jailbroker {
            socket: socket.to_path_buf(),
            writable_prefixes: answer.writable_prefixes,
        }),
        Err(reason) => BackendProbe::Missing { reason },
    }
}

/// How a command ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Outcome {
    /// An exit code, or 128 plus the signal that killed the command.
    pub(crate) status: i32,
    /// Whether a cancel ended it.
    pub(crate) canceled: bool,
}

/// Stop the command a session is running.
///
/// Cloned rather than borrowed so the timeout and the cancellation path can both hold one while the
/// tool call is still reading output.
#[derive(Clone)]
pub(crate) struct Cancel {
    id: String,
    writer: Arc<tokio::sync::Mutex<tokio::net::unix::OwnedWriteHalf>>,
}

impl Cancel {
    /// Ask the daemon to stop the command. A repeated ask is harmless: a request that is not
    /// running is refused, and the session is dropped either way.
    pub(crate) async fn send(&self) -> Result<(), Failure> {
        use tokio::io::AsyncWriteExt;

        let request = line(&CancelRequest {
            v: VERSION,
            op: "cancel",
            id: &self.id,
        })?;
        let mut writer = self.writer.lock().await;
        writer
            .write_all(request.as_bytes())
            .await
            .map_err(|error| Failure::new(format!("cancelling the command: {error}")))?;
        writer
            .flush()
            .await
            .map_err(|error| Failure::new(format!("cancelling the command: {error}")))
    }
}

/// A command the daemon is running.
pub(crate) struct Running {
    /// The command's standard output, as it arrives.
    pub(crate) stdout: tokio::io::DuplexStream,
    /// The command's standard error, as it arrives.
    pub(crate) stderr: tokio::io::DuplexStream,
    /// The end of the session: the exit status, or why there will not be one.
    ///
    /// Dropping this does not stop the command; dropping the whole [`Running`] does, because the
    /// socket going away is what tells the daemon the client is gone.
    pub(crate) outcome: tokio::task::JoinHandle<Result<Outcome, Failure>>,
    pub(crate) cancel: Cancel,
}

impl std::fmt::Debug for Running {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Running { .. }")
    }
}

/// Connect and run `plan`.
pub(crate) async fn run(socket: &Path, plan: Plan) -> Result<Running, Failure> {
    let stream = connect_trusted(socket).map_err(Failure::new)?;
    stream
        .set_nonblocking(true)
        .map_err(|error| Failure::new(format!("waking the socket for the runtime: {error}")))?;
    let stream = tokio::net::UnixStream::from_std(stream)
        .map_err(|error| Failure::new(format!("handing the socket to the runtime: {error}")))?;
    start(stream, plan).await
}

/// Send one plan over a connected socket and start reading its events.
///
/// Split from [`run`] so a test can drive a socket of its own: the trust check belongs to the door
/// that connects, and one that has not connected has nothing to check.
pub(crate) async fn start(stream: tokio::net::UnixStream, plan: Plan) -> Result<Running, Failure> {
    use tokio::io::AsyncWriteExt;

    let id = uuid::Uuid::new_v4().to_string();
    let request = plan.request(&id)?;
    let (reader, writer) = stream.into_split();
    let mut writer = writer;
    writer
        .write_all(request.as_bytes())
        .await
        .map_err(|error| Failure::new(format!("sending the plan to the jailbroker: {error}")))?;

    // The first event decides whether there is a session at all. A refusal comes back before the
    // daemon has mounted anything, and a run that reaches `started` has a jail behind it.
    let mut reader = BufReader::new(reader);
    let mut first = String::new();
    if read_line(&mut reader, &mut first).await? == 0 {
        return Err(Failure::new(
            "the jailbroker closed the connection without answering",
        ));
    }
    match parse_event(&first).map_err(Failure::new)? {
        Event::Started {
            jail,
            mounts,
            clipped,
            dry_run,
        } => {
            if dry_run {
                tracing::warn!(
                    "the jailbroker is running in dry-run mode, so this command does not run"
                );
            }
            if plan.level == Level::Workspace && !clipped.is_empty() {
                // The session asked to write and got less than it asked for. The operator's policy
                // is what cut it, and the paths say which item did it.
                tracing::warn!(
                    "the jailbroker cut {} path(s) out of this session's write boundary: {}",
                    clipped.len(),
                    clipped.join(", ")
                );
            } else if !clipped.is_empty() {
                tracing::debug!(
                    "the jailbroker's base leaves out {} path(s): {}",
                    clipped.len(),
                    clipped.join(", ")
                );
            }
            tracing::debug!("jailbroker session in jail {jail} over {mounts} mount(s)");
        }
        Event::Error { kind, message } => {
            return Err(Failure::new(format!(
                "the jailbroker refused the command ({kind}): {message}"
            )));
        }
        other => {
            return Err(Failure::new(format!(
                "the jailbroker answered a plan with {other:?}"
            )));
        }
    }

    let (stdout_tx, stdout) = tokio::io::duplex(OUTPUT_CHANNEL_BYTES);
    let (stderr_tx, stderr) = tokio::io::duplex(OUTPUT_CHANNEL_BYTES);
    let outcome = tokio::spawn(pump(reader, stdout_tx, stderr_tx));
    Ok(Running {
        stdout,
        stderr,
        outcome,
        cancel: Cancel {
            id,
            writer: Arc::new(tokio::sync::Mutex::new(writer)),
        },
    })
}

/// Read one line, or nothing at end of file.
async fn read_line<R>(reader: &mut R, into: &mut String) -> Result<usize, Failure>
where
    R: tokio::io::AsyncBufRead + Unpin,
{
    use tokio::io::AsyncBufReadExt;

    reader
        .read_line(into)
        .await
        .map_err(|error| Failure::new(format!("reading from the jailbroker: {error}")))
}

/// Move the daemon's events into the two streams a tool call reads from.
///
/// The daemon streams a line at a time, so nothing here reassembles anything: the bytes go out in
/// the order the command wrote them, and a write into a stream nobody is reading waits, which is
/// the backpressure [`OUTPUT_CHANNEL_BYTES`] describes.
async fn pump(
    mut reader: BufReader<tokio::net::unix::OwnedReadHalf>,
    mut stdout: tokio::io::DuplexStream,
    mut stderr: tokio::io::DuplexStream,
) -> Result<Outcome, Failure> {
    use tokio::io::AsyncWriteExt;

    let mut line = String::new();
    loop {
        line.clear();
        if read_line(&mut reader, &mut line).await? == 0 {
            return Err(Failure::new(
                "the jailbroker closed the connection before the command ended",
            ));
        }
        match parse_event(&line).map_err(Failure::new)? {
            Event::Stdout { data } => stdout
                .write_all(data.as_bytes())
                .await
                .map_err(|error| Failure::new(format!("writing command output: {error}")))?,
            Event::Stderr { data } => stderr
                .write_all(data.as_bytes())
                .await
                .map_err(|error| Failure::new(format!("writing command output: {error}")))?,
            Event::Exit { status, canceled } => {
                // The streams end here: the tool call drains what the command wrote and gets EOF,
                // which is what it would get from a pipe whose writer exited.
                return Ok(Outcome { status, canceled });
            }
            Event::Error { kind, message } => {
                return Err(Failure::new(format!(
                    "the jailbroker failed the command ({kind}): {message}"
                )));
            }
            Event::Started { .. } | Event::Probe { .. } => continue,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(unsafe_code)]
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use std::io::{BufRead, Write};

    use super::*;

    /// A stand-in for the daemon: a socket that answers with whatever a test scripted.
    ///
    /// Nothing here is root-owned, so it is the wire and the pump these tests exercise, never the
    /// trust check: [`trust`] refuses every socket a test can create, which is the point of it.
    struct Fake {
        directory: tempfile::TempDir,
    }

    impl Fake {
        /// Accept one connection and drive it with `script`.
        fn start(script: impl FnOnce(&mut Peer) + Send + 'static) -> Self {
            let directory = tempfile::tempdir().expect("tempdir");
            let path = directory.path().join("jailbroker.sock");
            let listener = std::os::unix::net::UnixListener::bind(&path)
                .expect("binds a socket in a temp dir");
            std::thread::spawn(move || {
                let (stream, _) = listener.accept().expect("accepts the connection");
                let mut peer = Peer::new(stream);
                script(&mut peer);
            });
            Self { directory }
        }

        fn socket(&self) -> PathBuf {
            self.directory.path().join("jailbroker.sock")
        }
    }

    /// The client end of one connection, as the daemon's side of it sees it.
    struct Peer {
        reader: std::io::BufReader<std::os::unix::net::UnixStream>,
        writer: std::os::unix::net::UnixStream,
    }

    impl Peer {
        fn new(stream: std::os::unix::net::UnixStream) -> Self {
            let writer = stream.try_clone().expect("clones the socket");
            Self {
                reader: std::io::BufReader::new(stream),
                writer,
            }
        }

        /// The next request, decoded.
        fn request(&mut self) -> serde_json::Value {
            let mut line = String::new();
            self.reader.read_line(&mut line).expect("reads a request");
            serde_json::from_str(&line).expect("the request is JSON")
        }

        /// One event line.
        fn send(&mut self, event: serde_json::Value) {
            let mut line = serde_json::to_string(&event).expect("event JSON");
            line.push('\n');
            self.writer.write_all(line.as_bytes()).expect("writes");
            self.writer.flush().expect("flushes");
        }
    }

    /// The events a fake sends to accept a plan, so a test's script can get to the part it is
    /// about.
    fn started(peer: &mut Peer) -> serde_json::Value {
        let request = peer.request();
        peer.send(serde_json::json!({
            "event": "started",
            "id": request["id"],
            "jail": "jb-0001-0",
            "mounts": 20,
            "clipped": [],
            "dry_run": false,
        }));
        request
    }

    fn a_plan(confinement: &Confinement) -> Plan {
        plan_for(
            confinement,
            Path::new("/usr/home/example/src/project"),
            &[PathBuf::from("/usr/home/example/.config/meka")],
            &[
                (OsString::from("PATH"), OsString::from("/bin:/usr/bin")),
                (OsString::from("TOKEN"), OsString::from("secret")),
            ],
            "ls -la",
        )
    }

    /// The request the daemon parses is a fixed shape: it refuses a field it does not know, so a
    /// renamed field is a refusal at runtime rather than a compile error here.
    #[test]
    fn the_request_carries_exactly_the_fields_the_daemon_knows() {
        let plan = a_plan(&Confinement::Workspace(vec![PathBuf::from(
            "/usr/home/example/src",
        )]));
        let encoded = plan.request("rjct4m").expect("a request line");
        assert!(encoded.ends_with('\n'), "one request is one line");

        let value: serde_json::Value = serde_json::from_str(&encoded).expect("JSON");
        let object = value.as_object().expect("an object");
        let mut keys: Vec<&String> = object.keys().collect();
        keys.sort();
        assert_eq!(
            keys,
            vec![
                "argv", "base", "cwd", "env", "hidden", "id", "level", "masks", "op", "v",
                "writable"
            ],
            "the daemon refuses a field it does not know"
        );
        assert_eq!(value["v"], 1);
        assert_eq!(value["op"], "run");
        assert_eq!(value["id"], "rjct4m");
        assert_eq!(value["level"], "workspace");
        assert_eq!(value["base"], "/");
        assert_eq!(value["cwd"], "/usr/home/example/src/project");
        assert_eq!(
            value["writable"],
            serde_json::json!(["/usr/home/example/src"])
        );
        assert_eq!(value["argv"], serde_json::json!(["sh", "-c", "ls -la"]));
        assert_eq!(
            value["masks"],
            serde_json::json!([
                { "path": "/tmp", "mode": "1777", "owner": "root" },
                { "path": "/var/tmp", "mode": "1777", "owner": "root" }
            ])
        );
        assert_eq!(
            value["hidden"],
            serde_json::json!([
                { "path": "/usr/home/example/.config/meka", "mode": "0700", "owner": "root" }
            ])
        );
        assert_eq!(value["env"]["PATH"], "/bin:/usr/bin");
    }

    /// `read` names nothing writable, which is the whole of what the level means.
    #[test]
    fn a_read_plan_mounts_nothing_read_write() {
        let plan = a_plan(&Confinement::ReadOnly);
        assert_eq!(plan.level, Level::Read);
        assert!(plan.writable.is_empty());
    }

    /// `workspace` carries the roots the write fence resolved, and nothing else.
    #[test]
    fn a_workspace_plan_carries_the_roots_meka_resolved() {
        let roots = vec![
            PathBuf::from("/usr/home/example/src"),
            PathBuf::from("/usr/home/example/notes"),
        ];
        let plan = a_plan(&Confinement::Workspace(roots.clone()));
        assert_eq!(plan.level, Level::Workspace);
        assert_eq!(plan.writable, roots);
    }

    /// A `workspace` whose roots all failed to resolve is read-only in effect, and the daemon
    /// refuses a `workspace` plan that names no root, so it is sent as `read`.
    #[test]
    fn a_workspace_that_resolved_to_nothing_is_sent_as_read() {
        let plan = a_plan(&Confinement::Workspace(Vec::new()));
        assert_eq!(plan.level, Level::Read);
        assert!(plan.writable.is_empty());
    }

    /// An unconfined call never reaches this backend, but if it did it must not be able to ask for
    /// writes: the mapping is total.
    #[test]
    fn an_unconfined_confinement_is_still_only_read() {
        let plan = a_plan(&Confinement::Unconfined);
        assert_eq!(plan.level, Level::Read);
        assert!(plan.writable.is_empty());
    }

    /// A variable that cannot be written as JSON text is left out rather than mangled.
    #[test]
    fn a_variable_that_is_not_text_is_left_out() {
        use std::os::unix::ffi::OsStringExt;

        let environment = vec![
            (OsString::from("PATH"), OsString::from("/bin")),
            (
                OsString::from("ODD"),
                OsString::from_vec(vec![0x66, 0x80, 0x6f]),
            ),
        ];
        let plan = plan_for(
            &Confinement::ReadOnly,
            Path::new("/tmp"),
            &[],
            &environment,
            "true",
        );
        assert_eq!(plan.env.len(), 1);
        assert_eq!(plan.env["PATH"], "/bin");
    }

    /// A path that cannot be written as JSON makes the whole plan refuse, rather than arriving at
    /// the daemon as a different path.
    #[test]
    fn a_working_directory_that_is_not_text_refuses_the_plan() {
        use std::os::unix::ffi::OsStringExt;

        let cwd = PathBuf::from(OsString::from_vec(vec![0x2f, 0x80]));
        let plan = plan_for(&Confinement::ReadOnly, &cwd, &[], &[], "/bin/true");
        let failure = plan.request("id").expect_err("a path JSON cannot carry");
        assert!(failure.message().contains("request"), "{failure:?}");
    }

    /// A refusal arrives before the daemon has built anything, and it is the daemon's own words
    /// that reach the model.
    #[tokio::test]
    async fn a_refused_plan_fails_the_call_with_the_daemon_s_sentence() {
        let fake = Fake::start(|peer| {
            let _ = peer.request();
            peer.send(serde_json::json!({
                "event": "error",
                "id": "",
                "kind": "policy",
                "message": "the prefix policy refuses /usr/home/example at rw: prefix / grants ro",
            }));
        });
        let stream = tokio::net::UnixStream::connect(fake.socket())
            .await
            .expect("connects");
        let failure = start(stream, a_plan(&Confinement::ReadOnly))
            .await
            .expect_err("a refusal is not a session");
        assert!(
            failure.message().contains("prefix / grants ro"),
            "{failure:?}"
        );
    }

    /// Output arrives on the two streams as the command writes it, and the exit status ends the
    /// session.
    #[tokio::test]
    async fn output_is_streamed_and_the_exit_status_is_the_outcome() {
        let fake = Fake::start(|peer| {
            started(peer);
            for line in ["first\n", "second\n"] {
                peer.send(serde_json::json!({"event": "stdout", "id": "x", "data": line}));
            }
            peer.send(serde_json::json!({"event": "stderr", "id": "x", "data": "complaint\n"}));
            peer.send(
                serde_json::json!({"event": "exit", "id": "x", "status": 3, "canceled": false}),
            );
        });
        let stream = tokio::net::UnixStream::connect(fake.socket())
            .await
            .expect("connects");
        let mut running = start(stream, a_plan(&Confinement::ReadOnly))
            .await
            .expect("a session");

        use tokio::io::AsyncReadExt;

        let mut out = String::new();
        running
            .stdout
            .read_to_string(&mut out)
            .await
            .expect("reads the output");
        let mut err = String::new();
        running
            .stderr
            .read_to_string(&mut err)
            .await
            .expect("reads the output");
        assert_eq!(out, "first\nsecond\n");
        assert_eq!(err, "complaint\n");
        assert_eq!(
            running
                .outcome
                .await
                .expect("the pump ends")
                .expect("an exit"),
            Outcome {
                status: 3,
                canceled: false
            }
        );
    }

    /// A daemon that goes away mid-command is a failure, not a command that exited zero.
    #[tokio::test]
    async fn a_daemon_that_goes_away_mid_command_fails_the_call() {
        let fake = Fake::start(|peer| {
            started(peer);
            peer.send(serde_json::json!({"event": "stdout", "id": "x", "data": "half a line"}));
        });
        let stream = tokio::net::UnixStream::connect(fake.socket())
            .await
            .expect("connects");
        let mut running = start(stream, a_plan(&Confinement::ReadOnly))
            .await
            .expect("a session");
        use tokio::io::AsyncReadExt;
        let mut out = String::new();
        running
            .stdout
            .read_to_string(&mut out)
            .await
            .expect("reads the output");
        assert_eq!(out, "half a line");
        let failure = running
            .outcome
            .await
            .expect("the pump ends")
            .expect_err("no exit status");
        assert!(
            failure.message().contains("before the command ended"),
            "{failure:?}"
        );
    }

    /// A cancelling call sends the id of the request the daemon is running, and the exit it gets
    /// back says it was canceled.
    #[tokio::test]
    async fn cancelling_names_the_running_request() {
        let fake = Fake::start(|peer| {
            let request = started(peer);
            let cancel = peer.request();
            assert_eq!(cancel["op"], "cancel", "{cancel}");
            assert_eq!(cancel["id"], request["id"], "{cancel}");
            peer.send(serde_json::json!({
                "event": "exit",
                "id": request["id"],
                "status": 137,
                "canceled": true,
            }));
        });
        let stream = tokio::net::UnixStream::connect(fake.socket())
            .await
            .expect("connects");
        let running = start(stream, a_plan(&Confinement::ReadOnly))
            .await
            .expect("a session");
        running.cancel.send().await.expect("the cancel is sent");
        let outcome = running
            .outcome
            .await
            .expect("the pump ends")
            .expect("an exit");
        assert_eq!(outcome, Outcome {
            status: 137,
            canceled: true
        });
    }

    /// A line that is not an event is the socket not being a broker, which is a failure rather than
    /// an empty command.
    #[tokio::test]
    async fn a_socket_that_answers_with_anything_else_is_a_failure() {
        let fake = Fake::start(|peer| {
            let mut line = String::new();
            peer.reader.read_line(&mut line).expect("reads the request");
            peer.writer
                .write_all(b"{\"hello\":true}\n")
                .expect("writes");
            peer.writer.flush().expect("flushes");
        });
        let stream = tokio::net::UnixStream::connect(fake.socket())
            .await
            .expect("connects");
        let failure = start(stream, a_plan(&Confinement::ReadOnly))
            .await
            .expect_err("not an event");
        assert!(
            failure.message().contains("not a jailbroker"),
            "{failure:?}"
        );
    }

    /// The probe's answer is what makes the socket a usable backend, and the policy it reports is
    /// what the startup warning is built from.
    #[tokio::test]
    async fn a_probe_answer_becomes_a_capability() {
        let fake = Fake::start(|peer| {
            let request = peer.request();
            assert_eq!(request["op"], "probe");
            peer.send(serde_json::json!({
                "event": "probe",
                "v": 1,
                "levels": ["read", "workspace"],
                "prefixes": [
                    {"path": "/", "mode": "ro"},
                    {"path": "/usr/home/example/src", "mode": "rw"},
                ],
            }));
        });
        let stream = std::os::unix::net::UnixStream::connect(fake.socket()).expect("connects");
        let answer = ask(stream).expect("a probe answer");
        assert_eq!(answer.writable_prefixes, vec![PathBuf::from(
            "/usr/home/example/src"
        )]);
    }

    /// A version this client does not speak is refused rather than half-understood.
    #[tokio::test]
    async fn another_version_is_not_a_backend() {
        let fake = Fake::start(|peer| {
            let _ = peer.request();
            peer.send(serde_json::json!({
                "event": "probe",
                "v": 2,
                "levels": ["read"],
                "prefixes": [],
            }));
        });
        let stream = std::os::unix::net::UnixStream::connect(fake.socket()).expect("connects");
        let reason = ask(stream).expect_err("a version meka does not speak");
        assert!(reason.contains("speaks version 2"), "{reason}");
    }

    /// A policy with no writable prefix is a probe answer too, and it is the one the startup
    /// warning is emitted for.
    #[test]
    fn a_policy_that_grants_no_write_is_reported_to_the_warning() {
        let fake = Fake::start(|peer| {
            let _ = peer.request();
            peer.send(serde_json::json!({
                "event": "probe",
                "v": 1,
                "levels": ["read", "workspace"],
                "prefixes": [{"path": "/", "mode": "ro"}],
            }));
        });
        let stream = std::os::unix::net::UnixStream::connect(fake.socket()).expect("connects");
        let answer = ask(stream).expect("a probe answer");
        assert!(answer.writable_prefixes.is_empty());
    }

    /// A path with nothing at it is refused by name, which is what a user sees when the broker is
    /// not running.
    #[test]
    fn a_socket_that_is_not_there_is_refused_by_name() {
        let temp = tempfile::tempdir().expect("tempdir");
        let missing = temp.path().join("nothing.sock");
        let reason = trust(&missing).expect_err("nothing is there");
        assert!(reason.contains("no socket at"), "{reason}");
        assert!(reason.contains("nothing.sock"), "{reason}");
    }

    /// A directory is not a socket, whatever its name ends in.
    #[test]
    fn a_directory_is_not_a_socket() {
        let temp = tempfile::tempdir().expect("tempdir");
        let reason = trust(temp.path()).expect_err("a directory is not a socket");
        assert!(reason.contains("is not a socket"), "{reason}");
    }

    /// A socket this user owns is not one root put there, whatever its mode says.
    #[test]
    fn a_socket_this_user_owns_is_refused() {
        let fake = Fake::start(|_| {});
        let reason = trust(&fake.socket()).expect_err("a socket this user owns");
        assert!(reason.contains("not owned by root"), "{reason}");
    }

    /// The directories are checked, not only the socket, and the check walks the whole path: a
    /// directory a group or anyone else can write is one where a socket could be swapped for
    /// another, which is why the daemon's own directory is root-owned.
    #[test]
    fn a_directory_this_user_can_write_is_not_a_trusted_chain() {
        let temp = tempfile::tempdir().expect("tempdir");
        let reason = chain_is_root_owned(&temp.path().join("jailbroker.sock"))
            .expect_err("a directory this process just created is writable by this user");
        assert!(
            reason.contains("writable by someone other than root"),
            "{reason}"
        );

        // The control, and why this is a predicate rather than a hardcoded list: where the daemon
        // usually puts its socket is trusted, and an operator who puts it somewhere else that is
        // root-owned gets the same answer.
        let usual = Path::new("/var/run/jailbroker.sock");
        if Path::new("/var/run").is_dir() {
            assert!(
                chain_is_root_owned(usual).is_ok(),
                "/var/run must be trusted, or the broker is unreachable on an ordinary host"
            );
        }
    }
}
