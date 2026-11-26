//! Managed subshell grants and the wire shared by its host and guest.

// The request and mount wire is compiled where an end of it exists: the Windows host and the
// Linux guest. Other platforms build the wire without using it, so it reads as unused there
// rather than being dead.
#![cfg_attr(
    not(any(windows, target_os = "linux")),
    allow(
        dead_code,
        reason = "only the Windows host and the Linux guest use the WSL wire"
    )
)]

#[cfg(windows)]
use std::sync::Arc;
use std::{path::PathBuf, time::Duration};

use anyhow::{Result, ensure};

#[cfg(windows)]
use crate::paths::WslDirectory;
use crate::permission::Permission;

/// The wire version. One exact-version bump carries the coordinated wire changes: the
/// READY/permit/ACK command handshake with its operation identifier, typed export sources, and
/// the shared budget table. There is no legacy fallback: an installed runner that speaks any other
/// version is refused before a request is written, never trusted to mix shapes with this one.
pub(crate) const VERSION: u32 = 7;
/// Hello precedes the request so an unrelated installed executable never receives it.
pub(crate) fn hello() -> String {
    format!("MEKA-RUNNER {VERSION}\n")
}

/// The operation identifier every control frame echoes, so the host can bind a response to the
/// request it launched and a permit to the operation it authorized. A fresh id per call; the
/// spelling is a UUID's simple lowercase hex. Only the Windows controller issues ops.
#[cfg_attr(
    not(windows),
    allow(
        dead_code,
        reason = "the Windows controller issues operation identifiers"
    )
)]
pub(crate) fn new_op() -> String {
    uuid::Uuid::new_v4().simple().to_string()
}

/// Whether `text` is an operation identifier this protocol may carry.
pub(crate) fn is_op(text: &str) -> bool {
    text.len() == 32
        && text
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

/// The one line the host writes on the launcher's stdin to authorize a start: the remaining
/// budget of the call in milliseconds, then a newline. Nothing else is ever written there after
/// the request, so anything readable at any other time, or a hangup, means the host is gone or has
/// withdrawn. The permit carries the remaining budget because one absolute deadline runs from the
/// launch: what the launch already ate is not the guest's to spend again. Only the Windows
/// controller writes permits.
#[cfg_attr(
    not(windows),
    allow(dead_code, reason = "the Windows controller writes start permits")
)]
pub(crate) fn permit_line(budget: Duration) -> String {
    format!("{}\n", budget.as_millis())
}

/// The runner's own exit codes, beside a command's own: the three ends a command cannot report for
/// itself. 124 and 125 are the shells' conventions for a timeout and an interruption, 126 the one
/// for a command that could not run. The host reads these off the launcher to reconcile its status
/// with the outcome the runner reported.
pub(crate) const RUNNER_TIMED_OUT: i32 = 124;
pub(crate) const RUNNER_CANCELED: i32 = 125;
pub(crate) const RUNNER_ERROR: i32 = 126;

/// The most bytes the start permit line may take.
#[cfg_attr(
    not(target_os = "linux"),
    allow(dead_code, reason = "the guest reads the permit line")
)]
pub(crate) const PERMIT_BYTES: usize = 32;

/// The budget a permit line announces, or `None` when the line is not one. A permit names a
/// positive budget no larger than [`MAX_TIMEOUT`]; anything else is a protocol failure, not a
/// start.
#[cfg_attr(
    not(target_os = "linux"),
    allow(dead_code, reason = "the guest reads the permit line")
)]
pub(crate) fn parse_permit(line: &[u8]) -> Option<Duration> {
    let text = line.strip_suffix(b"\n")?;
    let text = std::str::from_utf8(text).ok()?;
    let millis: u64 = text.parse().ok()?;
    (millis > 0 && Duration::from_millis(millis) <= MAX_TIMEOUT)
        .then(|| Duration::from_millis(millis))
}

pub(crate) const REQUEST_BYTES: usize = 128 * crate::text::KIB;
pub(crate) const MAX_ROOTS: usize = 32;
pub(crate) const MAX_TIMEOUT: Duration = Duration::from_secs(60 * 60);
const SCRIPT_BYTES: usize = 64 * crate::text::KIB;

/// How long a transfer may run. The runner stops at the same deadline and at the loss of the host
/// lease, whichever comes first.
#[cfg_attr(
    not(windows),
    allow(dead_code, reason = "the host enforces the launch deadline")
)]
pub(crate) const TRANSFER_TIMEOUT: Duration = MAX_TIMEOUT;
/// The most files one transfer may carry and the most entries one manifest may hold.
pub(crate) const MAX_TRANSFER_ENTRIES: usize = 100_000;
/// How deeply one transferred path may nest beneath the source that holds it.
pub(crate) const MAX_TRANSFER_DEPTH: usize = 64;
/// The most bytes one transferred path may take, relative to its source.
pub(crate) const MAX_TRANSFER_PATH_BYTES: usize = 4096;
/// The most bytes one metadata frame may take.
pub(crate) const FRAME_BYTES: usize = 64 * crate::text::KIB;
/// The most bytes the one manifest frame may take. It carries every entry of a transfer, so it is
/// bounded apart from the per-file headers that share the stream.
pub(crate) const MANIFEST_BYTES: usize = 32 * crate::text::MIB;
/// The most bytes one transferred file may announce or carry. A declared length past it is refused
/// before anything is allocated or copied for it.
pub(crate) const MAX_TRANSFER_FILE_BYTES: u64 = 2 * 1024 * crate::text::MIB as u64;
/// The most bytes one transfer may carry in all. The reader counts payload bytes as they arrive and
/// refuses the chunk that crosses this; the scratch quota is an admission rule of its own and does
/// not raise this ceiling.
pub(crate) const MAX_TRANSFER_BYTES: u64 = 8 * 1024 * crate::text::MIB as u64;

/// Where a scratch workspace lives in the guest: one subdirectory per handle under this root, on
/// the distro's own filesystem so builds run at Linux speed. `/var/tmp` is the standard location
/// for temporary work that outlives a single process, and the sandbox never sees it: only the
/// handle's directory is bound into a command, at `/workspace`.
pub(crate) const SCRATCH_ROOT: &str = "/var/tmp/meka-scratch";
/// The directory name one scratch workspace takes: unguessable, so another guest user cannot
/// name it, and shaped so the runner reaps only its own.
pub(crate) const SCRATCH_ID_BYTES: usize = 8;
/// How long a scratch workspace outlives its last use before the next scratch run reaps it. A
/// handle's host may die without closing anything, so the guest expires the workspace instead of
/// keeping it forever; anything worth keeping must be exported first. Only the guest's runner
/// enforces the lease, so the constant is unused in a host build.
#[cfg_attr(
    not(target_os = "linux"),
    allow(dead_code, reason = "the reaper lives in the guest")
)]
pub(crate) const SCRATCH_LEASE: Duration = Duration::from_secs(24 * 60 * 60);
/// The scratch bytes one handle may hold unless its open names another quota.
#[cfg(windows)]
pub(crate) const DEFAULT_SCRATCH_BYTES: u64 = 1024 * crate::text::MIB as u64;
/// The largest scratch quota an open may ask for.
pub(crate) const MAX_SCRATCH_BYTES: u64 = 8 * 1024 * crate::text::MIB as u64;

/// The guest directory one call may create for a handle's scratch workspace, and what it may
/// hold. `create` is set only on the open's one prepare call; every later call requires the
/// directory to still be there, so a reaped workspace fails loudly instead of coming back empty.
#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Scratch {
    pub(crate) path: PathBuf,
    pub(crate) quota_bytes: u64,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub(crate) create: bool,
}

/// One mount source as the wire carries it: a guest path the runner opens directly, or a Windows
/// path whose guest view the runner resolves and proves before mounting it. A guest source
/// serializes as its plain path, so a request naming only guest sources keeps the shape of the
/// first wire version.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
#[serde(untagged)]
pub(crate) enum MountRoot {
    Guest(PathBuf),
    Windows(WindowsRoot),
}

/// A Windows-backed mount: the directory as the operator's grant spelled it, and the name of the
/// proof file the host dropped into it for this request. The runner resolves the guest view from
/// its own mount table and refuses the mount unless the proof is a regular file in exactly that
/// view, so a wrong translation fails closed instead of mounting some other directory.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WindowsRoot {
    pub(crate) windows: String,
    pub(crate) proof: String,
}

/// The proof file name's prefix, and how much lowercase hex follows it: a fresh name per request,
/// so a file of that name inside a candidate directory is evidence that the host dropped it there
/// for this request and no other.
pub(crate) const PROOF_PREFIX: &str = ".meka-mount-proof-";
pub(crate) const PROOF_HEX: usize = 32;

/// A fresh proof file name.
#[cfg_attr(
    not(windows),
    allow(dead_code, reason = "only the Windows host drops proofs")
)]
pub(crate) fn proof_name() -> String {
    format!("{PROOF_PREFIX}{}", uuid::Uuid::new_v4().simple())
}

/// Whether `name` is a proof file name this protocol may carry.
pub(crate) fn is_proof_name(name: &str) -> bool {
    let Some(hex) = name.strip_prefix(PROOF_PREFIX) else {
        return false;
    };
    hex.len() == PROOF_HEX
        && hex
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

/// Parse a Windows drive-absolute path into its drive letter and components. The host's shape
/// check and the guest's resolution share this one parser, so what one accepts the other can
/// resolve. Separators are `\` or `/`, but every component must be non-empty and neither `.` nor
/// `..`: the spelling is the operator's grant, resolved as written. Components keep their case;
/// what pins the directory down is the proof, not the spelling. The drive root `C:\` has no
/// components and is valid.
pub(crate) fn windows_components(path: &str) -> Option<(char, Vec<&str>)> {
    let [first, colon, separator, rest @ ..] = path.as_bytes() else {
        return None;
    };
    if !first.is_ascii_alphabetic()
        || *colon != b':'
        || !matches!(separator, b'\\' | b'/')
        || path.chars().any(char::is_control)
    {
        return None;
    }
    let rest = std::str::from_utf8(rest).ok()?;
    if rest.ends_with(['\\', '/']) {
        return None;
    }
    if rest.is_empty() {
        return Some((*first as char, Vec::new()));
    }
    let components: Vec<&str> = rest.split(['\\', '/']).collect();
    if components
        .iter()
        .any(|part| part.is_empty() || matches!(*part, "." | ".."))
    {
        return None;
    }
    Some((*first as char, components))
}

/// Whether `text` names a normalized absolute Linux path: no empty, `.` or `..` components. Only
/// such a path has a spelling whose prefixes are its own ancestors, which is what makes a
/// string-beneath grant check sound.
pub(crate) fn is_normalized_guest_path(text: &str) -> bool {
    text.starts_with('/')
        && text
            .split('/')
            .skip(1)
            .all(|part| !part.is_empty() && part != "." && part != "..")
        && !text.contains('\0')
}

impl MountRoot {
    /// The shape the wire may carry: a guest source is a normalized absolute Linux path, a Windows
    /// source a normalized drive-absolute path with a well-formed proof name. The guest resolves
    /// and proves the directory itself; this is only what may travel at all.
    fn validate_shape(&self) -> Result<()> {
        match self {
            MountRoot::Guest(path) => {
                ensure!(
                    is_normalized_guest_path(&path.to_string_lossy()),
                    "invalid subshell directory: {}",
                    path.display()
                );
            }
            MountRoot::Windows(root) => {
                ensure!(
                    windows_components(&root.windows).is_some(),
                    "invalid Windows subshell directory: {:?}",
                    root.windows
                );
                ensure!(is_proof_name(&root.proof), "invalid mount proof name");
            }
        }
        Ok(())
    }
}

/// Where one export source lives: the request's own scratch workspace, or one mounted root of the
/// request by position (the working directory first, then the workspace mounts in order, then the
/// read-only ones). A source is never a free-standing absolute path on the wire: the host names a
/// root it already admitted, and the runner resolves only validated components beneath it.
#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ExportRoot {
    /// The request's own scratch workspace, opened and identity-checked by the runner's scratch
    /// machinery rather than by name.
    Scratch,
    /// The request's mounted root at this position.
    Mounted(usize),
}

/// One export source: a typed root and the validated relative components beneath it. An empty
/// `relative` names the root itself; the final component is the name the host publishes it under.
#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExportSource {
    pub(crate) root: ExportRoot,
    pub(crate) relative: Vec<String>,
}

impl ExportSource {
    /// The shape one source may travel with: a bounded list of single components beneath its root,
    /// so every resolution the runner performs is beneath a root it opened itself.
    fn validate(&self) -> Result<()> {
        ensure!(
            self.relative.len() <= MAX_TRANSFER_DEPTH,
            "an export source is too deep"
        );
        let joined = self.relative.join("/");
        ensure!(
            joined.len() <= MAX_TRANSFER_PATH_BYTES,
            "an export source path is too long"
        );
        for component in &self.relative {
            ensure!(
                is_transfer_component(component),
                "invalid export source component: {component:?}"
            );
        }
        if let ExportRoot::Mounted(root) = self.root {
            ensure!(root < MAX_ROOTS, "an export source names an unknown root");
        }
        Ok(())
    }
}

/// What a transfer asks the runner to do, in place of a shell command.
///
/// A transfer exists so no host walk of the guest's filesystem is needed: the runner resolves and
/// opens every directory itself, refuses anything but a regular file or a real directory, and
/// streams what it read. `stage` copies one guest source tree into the request's scratch
/// workspace, `upload` receives a snapshot the host read under its own read fence, `export` reads
/// the named sources back out, and `remove_scratch` deletes the workspace the request names.
#[derive(Debug, serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum Transfer {
    /// Copy `source` into the scratch workspace the request carries.
    Stage { source: MountRoot },
    /// Install the snapshot the host read under its own read fence into the scratch workspace the
    /// request carries. The manifest line and the announced bytes follow the request on the lease
    /// pipe in manifest order, so a Windows-backed tree is never walked through DrvFS, where the
    /// native read fence could not bind every object the walk would copy.
    Upload,
    /// Read `sources` back, each a typed root of this request and validated components beneath it.
    Export { sources: Vec<ExportSource> },
    /// Remove the scratch workspace the request names. Only the runner's own workspace id is
    /// accepted, and a missing workspace is already removed.
    RemoveScratch,
}

impl<'de> serde::Deserialize<'de> for Transfer {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error as _;

        let value = <serde_json::Value as serde::Deserialize>::deserialize(deserializer)?;
        let object = value
            .as_object()
            .ok_or_else(|| D::Error::custom("a transfer is an object"))?;
        let kind = object
            .get("kind")
            .and_then(|kind| kind.as_str())
            .ok_or_else(|| D::Error::custom("a transfer names its kind"))?;
        // An internally tagged enum's derived decoder ignores unknown fields; this one refuses
        // them, so a field the receiving side does not understand is never silently dropped.
        let fields: &[&str] = match kind {
            "stage" => &["kind", "source"],
            "upload" => &["kind"],
            "export" => &["kind", "sources"],
            "remove_scratch" => &["kind"],
            other => {
                return Err(D::Error::unknown_variant(other, &[
                    "stage",
                    "upload",
                    "export",
                    "remove_scratch",
                ]));
            }
        };
        if let Some(unknown) = object.keys().find(|key| !fields.contains(&key.as_str())) {
            return Err(D::Error::unknown_field(unknown, fields));
        }
        match kind {
            "stage" => {
                let source = object
                    .get("source")
                    .ok_or_else(|| D::Error::missing_field("source"))?;
                let source = <MountRoot as serde::Deserialize>::deserialize(source.clone())
                    .map_err(D::Error::custom)?;
                Ok(Self::Stage { source })
            }
            "upload" => Ok(Self::Upload),
            "export" => {
                let sources = object
                    .get("sources")
                    .ok_or_else(|| D::Error::missing_field("sources"))?;
                let sources =
                    <Vec<ExportSource> as serde::Deserialize>::deserialize(sources.clone())
                        .map_err(D::Error::custom)?;
                Ok(Self::Export { sources })
            }
            _ => Ok(Self::RemoveScratch),
        }
    }
}

impl Transfer {
    /// The shape a transfer may travel with. What a source resolves to is decided by the runner
    /// when it opens it; this refuses only what no open could be asked to do.
    fn validate(&self, scratch: Option<&Scratch>) -> Result<()> {
        match self {
            Transfer::Stage { source } => {
                source.validate_shape()?;
                ensure!(
                    matches!(source, MountRoot::Guest(_)),
                    "a stage source must be a granted guest directory: a Windows-backed tree is \
                     walked through DrvFS, where the native read fence cannot bind every object \
                     the walk would copy"
                );
                let scratch = scratch.ok_or_else(|| {
                    anyhow::anyhow!("a stage transfer names its scratch workspace")
                })?;
                ensure!(
                    scratch.create,
                    "a stage transfer creates its scratch workspace"
                );
            }
            Transfer::Upload => {
                let scratch = scratch
                    .ok_or_else(|| anyhow::anyhow!("an upload names its scratch workspace"))?;
                ensure!(scratch.create, "an upload creates its scratch workspace");
            }
            Transfer::Export { sources } => {
                ensure!(
                    !sources.is_empty() && sources.len() <= MAX_ROOTS,
                    "invalid export source count"
                );
                for source in sources {
                    source.validate()?;
                    ensure!(
                        scratch.is_some() || source.root != ExportRoot::Scratch,
                        "a scratch export names its scratch workspace"
                    );
                }
                if let Some(scratch) = scratch {
                    ensure!(
                        !scratch.create,
                        "an export does not create its scratch workspace"
                    );
                }
            }
            Transfer::RemoveScratch => {
                let scratch = scratch
                    .ok_or_else(|| anyhow::anyhow!("a scratch removal names its workspace"))?;
                ensure!(
                    !scratch.create,
                    "a scratch removal does not create a workspace"
                );
            }
        }
        Ok(())
    }
}

/// One entry as a transfer's manifest describes it. `path` is relative to the source the entry's
/// `root` index names, with `/` between components. A file carries what its bytes must be; a
/// directory is created by the host and streamed no bytes.
#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TransferEntry {
    pub(crate) root: usize,
    pub(crate) path: String,
    pub(crate) len: u64,
    pub(crate) modified_secs: i64,
    pub(crate) modified_nanos: u32,
    /// The file's SHA-256, lowercase hex.
    pub(crate) digest: String,
    /// Whether this entry is a directory the host creates instead of a file it receives bytes
    /// for. Directories carry no length and the digest of no bytes.
    #[serde(default)]
    pub(crate) directory: bool,
}

impl TransferEntry {
    /// The entry's modification time, as the host records it.
    #[cfg_attr(
        not(windows),
        allow(
            dead_code,
            reason = "the host reads this wire metadata; the guest writes it"
        )
    )]
    pub(crate) fn modified(&self) -> std::time::SystemTime {
        system_time(self.modified_secs, self.modified_nanos)
    }

    /// This entry's `File` frame, the header of its streamed bytes.
    #[cfg_attr(
        any(not(test), not(windows)),
        allow(
            dead_code,
            reason = "the guest sends this frame; the host only decodes it"
        )
    )]
    pub(crate) fn frame(&self) -> Frame {
        Frame::File {
            root: self.root,
            path: self.path.clone(),
            len: self.len,
            modified_secs: self.modified_secs,
            modified_nanos: self.modified_nanos,
            digest: self.digest.clone(),
        }
    }

    /// The entry's digest as bytes, when its text is a lowercase hex SHA-256.
    #[cfg_attr(
        not(windows),
        allow(
            dead_code,
            reason = "the host reads this wire metadata; the guest writes it"
        )
    )]
    pub(crate) fn parsed_digest(&self) -> Option<[u8; 32]> {
        parse_digest(&self.digest)
    }
}

/// One source an export read, as its manifest describes it. `source` is the typed source exactly as
/// the request named it; `name` is the final component beneath it, already validated as one Windows
/// path component.
#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TransferRoot {
    pub(crate) source: ExportSource,
    pub(crate) name: String,
    pub(crate) directory: bool,
}

/// Which of a command's two output streams a framed chunk came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum OutputStream {
    Stdout,
    Stderr,
}

/// One metadata frame of a transfer response. A `File` frame is followed by exactly its `len`
/// bytes, so every frame boundary is also a payload boundary. Every control frame carries the
/// operation identifier it belongs to; `File` and `Output` frames carry their operation by order,
/// between the control frames that name it.
#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(tag = "frame", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Frame {
    /// The complete list of files a successful transfer holds, sent before any file bytes.
    Manifest {
        op: String,
        roots: Vec<TransferRoot>,
        entries: Vec<TransferEntry>,
    },
    /// The header of one file whose bytes follow.
    File {
        root: usize,
        path: String,
        len: u64,
        modified_secs: i64,
        modified_nanos: u32,
        digest: String,
    },
    /// The guest proved its sandbox and waits for the host's start permit. It precedes `started`
    /// and every output frame of that command.
    Ready { op: String },
    /// The command sandbox started the shell: the acknowledgement that a permit became an observed
    /// start. It precedes every output frame of that command.
    Started { op: String },
    /// A command output chunk of exactly `len` bytes follows. Command stdout and stderr travel
    /// only in these frames, so a raw stream never has to be told apart from control.
    Output { stream: OutputStream, len: u64 },
    /// The shell was reaped. Its status follows the last output frame; the runner writes this only
    /// after it has waited for the command or torn the namespace down and reaped it, so its arrival
    /// is the guest teardown proof, on cancellation and timeout as well as on a normal exit.
    Stopped { op: String, code: i32 },
    /// The transfer or command ended; nothing follows.
    Done { op: String },
}

impl Frame {
    /// The wire bytes of one frame, newline included.
    #[cfg_attr(
        not(test),
        allow(
            dead_code,
            reason = "the guest encodes frames; the host only decodes them"
        )
    )]
    pub(crate) fn encode(&self) -> Result<Vec<u8>> {
        let limit = match self {
            Frame::Manifest { .. } => MANIFEST_BYTES,
            _ => FRAME_BYTES,
        };
        let mut bytes = serde_json::to_vec(self)?;
        ensure!(bytes.len() <= limit, "subshell transfer frame is too large");
        bytes.push(b'\n');
        Ok(bytes)
    }

    /// One parsed frame line, without its newline.
    #[cfg_attr(
        not(windows),
        allow(
            dead_code,
            reason = "the host reads this wire metadata; the guest writes it"
        )
    )]
    pub(crate) fn decode(line: &[u8]) -> Result<Self> {
        let frame: Frame = serde_json::from_slice(line)
            .map_err(|error| anyhow::anyhow!("invalid subshell transfer frame: {error}"))?;
        match &frame {
            Frame::Manifest { op, roots, entries } => {
                ensure!(is_op(op), "invalid subshell operation identifier");
                ensure!(roots.len() <= MAX_ROOTS, "too many subshell transfer roots");
                ensure!(
                    entries.len() <= MAX_TRANSFER_ENTRIES,
                    "too many subshell transfer entries"
                );
                let mut total = 0u64;
                for entry in entries {
                    entry.validate()?;
                    total = total.saturating_add(entry.len);
                }
                ensure!(
                    total <= MAX_TRANSFER_BYTES,
                    "the subshell transfer manifest announces more than {MAX_TRANSFER_BYTES} bytes"
                );
                for root in roots {
                    root.validate()?;
                }
            }
            Frame::File {
                path, digest, len, ..
            } => {
                ensure!(
                    is_transfer_entry_path(path),
                    "invalid subshell transfer path: {path:?}"
                );
                ensure!(
                    *len <= MAX_TRANSFER_FILE_BYTES,
                    "a subshell transfer file is larger than {MAX_TRANSFER_FILE_BYTES} bytes"
                );
                ensure!(
                    parse_digest(digest).is_some(),
                    "invalid subshell transfer digest"
                );
            }
            Frame::Output { len, .. } => {
                ensure!(
                    *len <= FRAME_BYTES as u64,
                    "subshell command output frame is too large"
                );
            }
            Frame::Ready { op }
            | Frame::Started { op }
            | Frame::Stopped { op, .. }
            | Frame::Done { op } => {
                ensure!(is_op(op), "invalid subshell operation identifier");
            }
        }
        Ok(frame)
    }
}

impl TransferEntry {
    /// The shape one entry may travel with: a relative transfer path and a lowercase SHA-256.
    #[cfg_attr(
        not(windows),
        allow(
            dead_code,
            reason = "the host reads this wire metadata; the guest writes it"
        )
    )]
    fn validate(&self) -> Result<()> {
        ensure!(
            is_transfer_entry_path(&self.path),
            "invalid subshell transfer path: {:?}",
            self.path
        );
        ensure!(
            parse_digest(&self.digest).is_some(),
            "invalid subshell transfer digest"
        );
        // A declared oversize is refused at the manifest, before any payload byte exists to
        // allocate for or copy.
        ensure!(
            self.len <= MAX_TRANSFER_FILE_BYTES,
            "a subshell transfer file is larger than {MAX_TRANSFER_FILE_BYTES} bytes"
        );
        Ok(())
    }
}

impl TransferRoot {
    /// The shape one root may travel with: the typed source the request named and a final
    /// component a host can join below its own directory.
    #[cfg_attr(
        not(windows),
        allow(
            dead_code,
            reason = "the host reads this wire metadata; the guest writes it"
        )
    )]
    fn validate(&self) -> Result<()> {
        self.source.validate()?;
        ensure!(
            is_transfer_component(&self.name) && self.name.len() <= MAX_TRANSFER_PATH_BYTES,
            "invalid subshell transfer root name: {:?}",
            self.name
        );
        Ok(())
    }
}

/// Where a host transfer's frames and bytes go as they arrive. The manifest arrives first and
/// complete, so a visitor that refuses it refuses before any file byte was accepted.
#[cfg(windows)]
#[async_trait::async_trait]
pub(crate) trait TransferVisitor: Send {
    /// The complete manifest of the transfer.
    async fn manifest(&mut self, roots: &[TransferRoot], entries: &[TransferEntry]) -> Result<()>;
    /// The header of one file whose bytes follow.
    async fn begin(&mut self, _entry: &TransferEntry) -> Result<()> {
        Ok(())
    }
    /// The next bytes of the file whose header arrived last.
    async fn payload(&mut self, _chunk: &[u8]) -> Result<()> {
        Ok(())
    }
    /// The file's last byte arrived; what was accepted can be published.
    async fn end(&mut self, _entry: &TransferEntry) -> Result<()> {
        Ok(())
    }
    /// Every frame and byte arrived, the transfer ended with `Done`, and the runner exited
    /// successfully. A visitor that staged what it received publishes it here, so nothing becomes
    /// visible from a transfer that later failed.
    async fn complete(&mut self) -> Result<()> {
        Ok(())
    }
}

/// A visitor that keeps the manifest and ignores the bytes, for a transfer whose files the runner
/// copies for itself.
#[cfg(windows)]
#[derive(Default)]
pub(crate) struct ManifestOnly {
    pub(crate) roots: Vec<TransferRoot>,
    pub(crate) entries: Vec<TransferEntry>,
}

#[cfg(windows)]
#[async_trait::async_trait]
impl TransferVisitor for ManifestOnly {
    async fn manifest(&mut self, roots: &[TransferRoot], entries: &[TransferEntry]) -> Result<()> {
        self.roots = roots.to_vec();
        self.entries = entries.to_vec();
        Ok(())
    }
}

/// The host side of one transfer response: newline-delimited metadata frames, with exactly the
/// bytes a `File` frame announced following it. Every bound is enforced here as the stream
/// arrives, so a malformed or oversized response is refused before it reaches a visitor.
#[cfg(windows)]
pub(crate) struct TransferReader {
    /// The operation this response must name in its control frames.
    op: String,
    buffer: Vec<u8>,
    manifest: bool,
    roots: usize,
    /// The files the manifest announced, by source index and relative path. A `File` frame is
    /// accepted only when it names one of these and repeats its metadata exactly.
    entries: std::collections::HashMap<(usize, String), TransferEntry>,
    /// The files whose bytes were delivered, so a manifest entry cannot be streamed twice or
    /// silently skipped.
    delivered: std::collections::HashSet<(usize, String)>,
    expected: usize,
    streamed: usize,
    /// Payload bytes accepted across the whole response, so one transfer cannot grow past the
    /// aggregate budget by carrying more files than any one of them may hold.
    payload_bytes: u64,
    done: bool,
    payload: Option<Payload>,
}

#[cfg(windows)]
struct Payload {
    entry: TransferEntry,
    remaining: u64,
    written: u64,
    hasher: sha2::Sha256,
}

#[cfg(windows)]
impl TransferReader {
    /// A reader for the response to the operation `op`, which every control frame must echo.
    pub(crate) fn new(op: &str) -> Self {
        Self {
            op: op.to_owned(),
            buffer: Vec::new(),
            manifest: false,
            roots: 0,
            entries: std::collections::HashMap::new(),
            delivered: std::collections::HashSet::new(),
            expected: 0,
            streamed: 0,
            payload_bytes: 0,
            done: false,
            payload: None,
        }
    }

    /// Feed the next bytes of the response, handing each frame and each file's bytes to `visitor`
    /// as they complete.
    pub(crate) async fn push(
        &mut self,
        mut chunk: &[u8],
        visitor: &mut dyn TransferVisitor,
    ) -> Result<()> {
        use sha2::Digest as _;

        while !chunk.is_empty() {
            let Self {
                payload_bytes,
                payload,
                streamed,
                ..
            } = self;
            if let Some(pending) = payload.as_mut() {
                let room = usize::try_from(pending.remaining).unwrap_or(usize::MAX);
                let take = chunk.len().min(room);
                let bytes = chunk.get(..take).unwrap_or(chunk);
                // The aggregate budget sits ahead of the bytes: a response past it is refused
                // before its next chunk is accepted anywhere.
                let grown = payload_bytes.saturating_add(bytes.len() as u64);
                ensure!(
                    grown <= MAX_TRANSFER_BYTES,
                    "the subshell transfer carries more than {MAX_TRANSFER_BYTES} bytes"
                );
                *payload_bytes = grown;
                pending.hasher.update(bytes);
                pending.written = pending.written.saturating_add(bytes.len() as u64);
                pending.remaining -= bytes.len() as u64;
                visitor.payload(bytes).await?;
                chunk = chunk.get(take..).unwrap_or_default();
                if pending.remaining == 0 {
                    let Some(finished) = payload.take() else {
                        anyhow::bail!("the subshell transfer lost a file it was streaming");
                    };
                    let digest: [u8; 32] = finished.hasher.finalize().into();
                    ensure!(
                        finished.written == finished.entry.len
                            && digest_hex(&digest) == finished.entry.digest,
                        "subshell transfer bytes do not match their manifest entry"
                    );
                    *streamed = streamed.saturating_add(1);
                    visitor.end(&finished.entry).await?;
                }
                continue;
            }
            match chunk.iter().position(|byte| *byte == b'\n') {
                Some(index) => {
                    self.buffer
                        .extend_from_slice(chunk.get(..index).unwrap_or_default());
                    chunk = chunk.get(index + 1..).unwrap_or_default();
                    ensure!(
                        self.buffer.len() <= MANIFEST_BYTES,
                        "subshell transfer frame is too large"
                    );
                    let line = std::mem::take(&mut self.buffer);
                    self.frame(line, visitor).await?;
                }
                None => {
                    self.buffer.extend_from_slice(chunk);
                    ensure!(
                        self.buffer.len() <= MANIFEST_BYTES,
                        "subshell transfer frame is too large"
                    );
                    chunk = chunk.get(chunk.len()..).unwrap_or_default();
                }
            }
        }
        Ok(())
    }

    async fn frame(&mut self, line: Vec<u8>, visitor: &mut dyn TransferVisitor) -> Result<()> {
        use sha2::Digest as _;

        ensure!(!self.done, "subshell transfer continued after it was done");
        let frame = Frame::decode(&line)?;
        if !matches!(frame, Frame::Manifest { .. }) {
            ensure!(
                line.len() <= FRAME_BYTES,
                "subshell transfer frame is too large"
            );
        }
        match frame {
            Frame::Manifest { op, roots, entries } => {
                ensure!(op == self.op, "the transfer named another operation");
                ensure!(!self.manifest, "duplicate subshell transfer manifest");
                ensure!(
                    entries.len() <= MAX_TRANSFER_ENTRIES,
                    "too many subshell transfer entries"
                );
                self.manifest = true;
                self.roots = roots.len();
                // A stage response copies for the runner and names no source root; only an
                // export streams file bytes after its manifest.
                self.expected = if roots.is_empty() {
                    0
                } else {
                    entries.iter().filter(|entry| !entry.directory).count()
                };
                for entry in &entries {
                    if !roots.is_empty() {
                        ensure!(
                            entry.root < roots.len(),
                            "a manifest entry names an unknown source"
                        );
                    }
                    ensure!(
                        !entry.directory || entry.len == 0,
                        "a directory entry carries file bytes"
                    );
                    ensure!(
                        self.entries
                            .insert((entry.root, entry.path.clone()), entry.clone())
                            .is_none(),
                        "the manifest names {:?} twice",
                        entry.path
                    );
                }
                visitor.manifest(&roots, &entries).await?;
            }
            Frame::File {
                root,
                path,
                len,
                modified_secs,
                modified_nanos,
                digest,
            } => {
                ensure!(self.manifest, "a transfer file arrived before its manifest");
                ensure!(
                    self.payload.is_none(),
                    "a transfer file arrived mid-payload"
                );
                ensure!(root < self.roots, "a transfer file names an unknown source");
                let entry = TransferEntry {
                    root,
                    path,
                    len,
                    modified_secs,
                    modified_nanos,
                    digest,
                    directory: false,
                };
                let planned = self
                    .entries
                    .get(&(entry.root, entry.path.clone()))
                    .ok_or_else(|| {
                        anyhow::anyhow!("a transfer file arrived that no manifest named")
                    })?;
                ensure!(
                    !planned.directory
                        && planned.len == entry.len
                        && planned.modified_secs == entry.modified_secs
                        && planned.modified_nanos == entry.modified_nanos
                        && planned.digest == entry.digest,
                    "a transfer file header does not match its manifest entry"
                );
                ensure!(
                    self.delivered.insert((entry.root, entry.path.clone())),
                    "a transfer file was delivered twice"
                );
                visitor.begin(&entry).await?;
                if len == 0 {
                    let digest: [u8; 32] = sha2::Sha256::new().finalize().into();
                    ensure!(
                        digest_hex(&digest) == entry.digest,
                        "subshell transfer bytes do not match their manifest entry"
                    );
                    self.streamed = self.streamed.saturating_add(1);
                    visitor.end(&entry).await?;
                } else {
                    self.payload = Some(Payload {
                        entry,
                        remaining: len,
                        written: 0,
                        hasher: sha2::Sha256::new(),
                    });
                }
            }
            Frame::Ready { .. }
            | Frame::Started { .. }
            | Frame::Stopped { .. }
            | Frame::Output { .. } => {
                anyhow::bail!("a transfer carried a command frame");
            }
            Frame::Done { op } => {
                ensure!(op == self.op, "the transfer named another operation");
                ensure!(self.manifest, "a transfer finished before its manifest");
                ensure!(self.payload.is_none(), "a transfer finished mid-payload");
                ensure!(
                    self.streamed == self.expected,
                    "a transfer finished after {} of {} file(s)",
                    self.streamed,
                    self.expected
                );
                self.done = true;
            }
        }
        Ok(())
    }

    /// Check the response ended where it said it would, with nothing after it.
    pub(crate) fn finish(&self) -> Result<()> {
        ensure!(self.done, "subshell transfer ended without a done frame");
        ensure!(
            self.payload.is_none() && self.buffer.is_empty(),
            "subshell transfer ended mid-frame"
        );
        Ok(())
    }
}

pub(crate) fn is_transfer_component(text: &str) -> bool {
    !text.is_empty() && !matches!(text, "." | "..") && !text.contains(['/', '\0'])
}

/// Whether `text` is a relative transfer path: `/`-separated components, no deeper than
/// [`MAX_TRANSFER_DEPTH`] and no longer than [`MAX_TRANSFER_PATH_BYTES`].
pub(crate) fn is_transfer_entry_path(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= MAX_TRANSFER_PATH_BYTES
        && text.split('/').count() <= MAX_TRANSFER_DEPTH
        && text.split('/').all(is_transfer_component)
}

/// The lowercase hex spelling of a SHA-256.
pub(crate) fn digest_hex(digest: &[u8; 32]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(digest.len() * 2);
    for byte in digest {
        for shift in [4, 0] {
            let index = usize::from((byte >> shift) & 0x0f);
            let digit = DIGITS.get(index).copied().unwrap_or(b'0');
            text.push(char::from(digit));
        }
    }
    text
}

/// Parse a lowercase hex SHA-256, or `None` when the text is not one.
#[cfg_attr(
    not(windows),
    allow(
        dead_code,
        reason = "the host reads this wire metadata; the guest writes it"
    )
)]
pub(crate) fn parse_digest(text: &str) -> Option<[u8; 32]> {
    if text.len() != 64 {
        return None;
    }
    let mut digest = [0u8; 32];
    for (index, pair) in text.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let digit = |byte: u8| match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            _ => None,
        };
        let high = digit(*pair.first()?)?;
        let low = digit(*pair.get(1)?)?;
        *digest.get_mut(index)? = (high << 4) | low;
    }
    Some(digest)
}

/// A modification time from the wire's seconds and nanoseconds, including times before 1970.
#[cfg_attr(
    not(windows),
    allow(
        dead_code,
        reason = "the host reads this wire metadata; the guest writes it"
    )
)]
pub(crate) fn system_time(secs: i64, nanos: u32) -> std::time::SystemTime {
    use std::time::{Duration, UNIX_EPOCH};

    let nanos = nanos.min(999_999_999);
    if secs >= 0 {
        UNIX_EPOCH + Duration::new(secs as u64, nanos)
    } else {
        UNIX_EPOCH - Duration::new(secs.unsigned_abs(), 0) + Duration::new(0, nanos)
    }
}

/// The wire's seconds and nanoseconds for one modification time.
#[cfg_attr(
    any(not(windows), not(test)),
    allow(
        dead_code,
        reason = "the host records snapshot times; the guest sends its own"
    )
)]
pub(crate) fn system_time_parts(time: std::time::SystemTime) -> (i64, u32) {
    use std::time::UNIX_EPOCH;

    match time.duration_since(UNIX_EPOCH) {
        Ok(elapsed) => (elapsed.as_secs() as i64, elapsed.subsec_nanos()),
        Err(error) => {
            let elapsed = error.duration();
            let (secs, nanos) = (
                i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX),
                elapsed.subsec_nanos(),
            );
            if nanos == 0 {
                (-secs, 0)
            } else {
                (
                    secs.saturating_add(1).saturating_neg(),
                    1_000_000_000 - nanos,
                )
            }
        }
    }
}

/// The managed subshell tools. Every one drives guest shell work, so one `[tools]` policy covers
/// the family: a policy that denies `shell_execute` denies these too, and one that raises its floor
/// raises theirs. Selecting a guest execution target must not bypass the shell tool policy.
pub(crate) const TOOL_NAMES: &[&str] = &[
    "subshell_close",
    "subshell_execute",
    "subshell_export",
    "subshell_open",
];

/// Whether `name` is one of the managed subshell tools.
pub(crate) fn is_tool(name: &str) -> bool {
    TOOL_NAMES.contains(&name)
}

/// The provisioned Linux runner is separate from the distro's normal `meka` executable.
#[cfg(windows)]
pub(crate) const DEFAULT_RUNNER: &str = "/usr/local/bin/meka-runner";

#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Request {
    pub(crate) version: u32,
    /// The operation identifier every control frame of this request echoes back.
    pub(crate) op: String,
    pub(crate) access: Permission,
    pub(crate) working_directory: MountRoot,
    pub(crate) workspace: Vec<MountRoot>,
    pub(crate) readable: Vec<MountRoot>,
    pub(crate) timeout_ms: u64,
    pub(crate) script: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) scratch: Option<Scratch>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) transfer: Option<Transfer>,
}

impl Request {
    pub(crate) fn validate(&self) -> Result<()> {
        ensure!(
            self.version == VERSION,
            "unsupported subshell protocol version {}",
            self.version
        );
        ensure!(
            is_op(&self.op),
            "invalid subshell operation identifier: {:?}",
            self.op
        );
        ensure!(
            matches!(self.access, Permission::Read | Permission::Workspace),
            "subshell access must be read or workspace"
        );
        ensure!(
            self.workspace.len() + self.readable.len() < MAX_ROOTS,
            "too many subshell roots"
        );
        self.working_directory.validate_shape()?;
        for root in self.workspace.iter().chain(&self.readable) {
            root.validate_shape()?;
        }
        ensure!(
            self.script.len() <= SCRIPT_BYTES && !self.script.contains('\0'),
            "invalid subshell script"
        );
        match &self.transfer {
            Some(transfer) => {
                ensure!(
                    self.script.is_empty(),
                    "a transfer request carries no script"
                );
                ensure!(
                    matches!(self.working_directory, MountRoot::Guest(_)),
                    "a transfer request runs in a guest directory"
                );
                ensure!(
                    self.access == Permission::Workspace
                        || matches!(transfer, Transfer::RemoveScratch),
                    "a transfer requires workspace access"
                );
                transfer.validate(self.scratch.as_ref())?;
            }
            None => ensure!(
                !self.script.trim().is_empty(),
                "missing or invalid subshell script"
            ),
        }
        ensure!(
            !self.timeout().is_zero() && self.timeout() <= MAX_TIMEOUT,
            "invalid subshell timeout"
        );
        if let Some(scratch) = &self.scratch {
            ensure!(
                self.access == Permission::Workspace
                    || matches!(self.transfer, Some(Transfer::RemoveScratch)),
                "a scratch workspace requires workspace access"
            );
            ensure!(
                scratch.path.to_str().is_some_and(|text| {
                    text.strip_prefix(SCRATCH_ROOT)
                        .and_then(|tail| tail.strip_prefix('/'))
                        .is_some_and(|name| !name.is_empty() && !name.contains('/'))
                }),
                "invalid scratch workspace path"
            );
            ensure!(
                matches!(&self.working_directory, MountRoot::Guest(path) if path == &scratch.path),
                "a scratch request mounts its own workspace"
            );
            ensure!(
                self.workspace.is_empty(),
                "a scratch request takes no additional workspace mounts"
            );
            ensure!(
                scratch.quota_bytes > 0 && scratch.quota_bytes <= MAX_SCRATCH_BYTES,
                "invalid scratch quota"
            );
        }
        Ok(())
    }

    pub(crate) fn timeout(&self) -> Duration {
        Duration::from_millis(self.timeout_ms)
    }

    #[cfg(windows)]
    pub(crate) fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut frame = serde_json::to_vec(self)?;
        frame.push(b'\n');
        ensure!(
            frame.len() <= REQUEST_BYTES,
            "subshell request is too large"
        );
        Ok(frame)
    }
}

/// The operator's per-invocation guest grants. No native Windows path participates in this scope.
#[cfg(windows)]
#[derive(Debug)]
pub(crate) struct Target {
    distribution: String,
    runner: String,
    workspace: Vec<String>,
    readable: Vec<String>,
}

#[cfg(windows)]
fn beneath(path: &str, root: &str) -> bool {
    path == root
        || path
            .strip_prefix(root)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

/// Whether `path` is at or below `root`, compared with Windows semantics: that is where a
/// Windows-backed grant lives, so case and separator spelling do not name different directories
/// there the way they would in the guest. The drive root `C:\` already carries its separator and
/// covers everything on its drive.
#[cfg(windows)]
pub(crate) fn windows_beneath(path: &str, root: &str) -> bool {
    let normalize = |text: &str| text.replace('/', "\\").to_lowercase();
    let (path, root) = (normalize(path), normalize(root));
    if root.ends_with('\\') {
        return path.starts_with(&root);
    }
    path == root || path.starts_with(&format!("{root}\\"))
}

/// Whether `path`, in the spelling its kind uses, is at or below the grant `root`. A guest path is
/// only ever checked against a guest grant and a Windows path against a Windows grant, since the
/// two spellings name different trees.
#[cfg(windows)]
pub(crate) fn root_contains(root: &str, path: &str) -> bool {
    match (windows_components(root), windows_components(path)) {
        (Some(_), Some(_)) => windows_beneath(path, root),
        (None, None) => beneath(path, root),
        _ => false,
    }
}

/// The components of the guest `path` beneath the guest `root`, or `None` when it is not beneath
/// it. The root itself yields the empty list; a component that no transfer could carry refuses.
#[cfg(windows)]
fn relative_beneath(root: &str, path: &str) -> Option<Vec<String>> {
    if !path.starts_with('/') {
        return None;
    }
    let tail = if path == root {
        ""
    } else {
        path.strip_prefix(root)?.strip_prefix('/')?
    };
    if tail.is_empty() {
        return Some(Vec::new());
    }
    let components = tail.split('/').map(str::to_owned).collect::<Vec<_>>();
    components
        .iter()
        .all(|component| is_transfer_component(component))
        .then_some(components)
}

/// Refuse a Windows-backed grant that must not become a guest mount, and return the canonical
/// directory it names.
///
/// The proof a request drops in the root shows only that the guest resolved *this* directory. It
/// says nothing about whether the directory is one the native sandbox masks: the guest checks its
/// own Linux private paths, while Meka's configuration and credential store are Windows paths it
/// cannot see. The host therefore decides from the canonical path (the one the kernel reports
/// after following junctions) both where the grant is configured and again before each request
/// writes its proof. A drive root is refused outright: proving it would hand over the whole drive.
#[cfg(windows)]
fn admit_windows_grant(grant: &str, private: &[std::path::PathBuf]) -> Result<std::path::PathBuf> {
    use anyhow::Context as _;

    let (_, components) = windows_components(grant)
        .ok_or_else(|| anyhow::anyhow!("not a normalized drive-absolute path: {grant:?}"))?;
    ensure!(
        !components.is_empty(),
        "a Windows workspace grant cannot be a drive root: {grant:?}"
    );
    let canonical = std::fs::canonicalize(grant)
        .with_context(|| format!("cannot resolve the Windows workspace grant {grant:?}"))?;
    let canonical = crate::fs::strip_verbatim(canonical);
    ensure!(
        canonical.is_dir(),
        "the Windows workspace grant is not a directory: {grant:?}"
    );
    let spelled = canonical.to_string_lossy();
    for directory in private {
        let private = directory.to_string_lossy();
        ensure!(
            !windows_beneath(&spelled, &private) && !windows_beneath(&private, &spelled),
            "the Windows workspace grant {grant:?} overlaps Meka's private directory {}",
            directory.display()
        );
    }
    Ok(canonical)
}

/// One selected grant as a wire mount, dropping the identity proof a Windows-backed root needs
/// into it. The proof is created here so what the request carries is exactly what the guest
/// checks, and the caller holds the markers until the call is done.
#[cfg(windows)]
fn mount_root(grant: &str, markers: &mut WindowsProofs) -> Result<MountRoot> {
    if windows_components(grant).is_none() {
        return Ok(MountRoot::Guest(PathBuf::from(grant)));
    }
    admit_windows_grant(grant, &crate::fs::private_directories())?;
    let proof = proof_name();
    let marker = std::path::Path::new(grant).join(&proof);
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&marker)
        .map_err(|error| {
            anyhow::anyhow!("cannot prove the Windows-backed mount {grant:?}: {error}")
        })?;
    markers.push(marker);
    Ok(MountRoot::Windows(WindowsRoot {
        windows: grant.to_owned(),
        proof,
    }))
}

/// The proof files one request dropped in its Windows-backed roots. They live from before the
/// request is delivered until the call is done; the guest runner removes the one it verified, so
/// each side tolerates the other having cleaned up first.
#[cfg(windows)]
#[derive(Debug, Default)]
pub(crate) struct WindowsProofs(Vec<std::path::PathBuf>);

#[cfg(windows)]
impl WindowsProofs {
    fn push(&mut self, marker: std::path::PathBuf) {
        self.0.push(marker);
    }
}

#[cfg(windows)]
impl Drop for WindowsProofs {
    fn drop(&mut self) {
        for marker in &self.0 {
            let _ = std::fs::remove_file(marker);
        }
    }
}

#[cfg(windows)]
impl Target {
    /// Admit only disjoint grants for the configured distro and outside the runner's ancestry.
    /// Windows-backed workspace grants come in their operator spelling; their guest view is
    /// resolved and proven per request, never assumed here.
    pub(crate) fn from_grants(
        distribution: &str,
        runner: &str,
        workspace: &[WslDirectory],
        readable: &[WslDirectory],
        windows_workspace: &[String],
    ) -> Result<Self> {
        ensure!(
            !distribution.is_empty()
                && distribution.trim() == distribution
                && !distribution.starts_with('-')
                && !distribution.chars().any(
                    |character| character.is_control() || matches!(character, '"' | '/' | '\\')
                ),
            "invalid `[shell.wsl].distribution`"
        );
        ensure!(
            runner
                .strip_prefix('/')
                .is_some_and(|tail| tail.split('/').all(|part| {
                    !matches!(part, "" | "." | "..")
                        && part
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
                })),
            "`[shell.wsl].runner` must be an absolute Linux executable path without spaces or symlinks"
        );
        let mut seen: Vec<&str> = Vec::new();
        for directory in workspace.iter().chain(readable) {
            ensure!(
                directory.distribution() == distribution,
                "WSL grant {directory} is not in the configured distribution {distribution}"
            );
            let path = directory.guest_path();
            ensure!(
                !beneath(runner, path),
                "WSL grant {directory} contains the trusted runner"
            );
            ensure!(
                !seen
                    .iter()
                    .any(|root| beneath(path, root) || beneath(root, path)),
                "overlapping WSL directory grant: {directory}"
            );
            seen.push(path);
        }
        let mut windows_seen: Vec<&str> = Vec::new();
        for directory in windows_workspace {
            ensure!(
                windows_components(directory).is_some(),
                "a Windows workspace grant must be a normalized drive-absolute path: \
                 {directory:?}"
            );
            ensure!(
                !windows_seen.iter().any(
                    |root| windows_beneath(directory, root) || windows_beneath(root, directory)
                ),
                "overlapping WSL directory grant: {directory}"
            );
            windows_seen.push(directory);
        }
        for directory in windows_workspace {
            admit_windows_grant(directory, &crate::fs::private_directories())?;
        }
        ensure!(
            seen.len() + windows_seen.len() <= MAX_ROOTS,
            "too many WSL directory grants"
        );
        Ok(Self {
            distribution: distribution.to_owned(),
            runner: runner.to_owned(),
            workspace: workspace
                .iter()
                .map(|root| root.guest_path().to_owned())
                .chain(windows_workspace.iter().cloned())
                .collect(),
            readable: readable
                .iter()
                .map(|root| root.guest_path().to_owned())
                .collect(),
        })
    }

    /// The target and its permitted selectors, as shown to the model.
    pub(crate) fn scope_description(&self) -> String {
        format!(
            "WSL distribution {:?}. Workspace grants: {:?}. Read-only grants: {:?}.",
            self.distribution, self.workspace, self.readable
        )
    }

    /// Select exact CLI grants. The guest sees Linux path spelling; Windows path comparison
    /// would otherwise conflate distinct names such as `Project` and `project`. A Windows-backed
    /// selection carries a fresh identity proof into its root, which the caller holds until the
    /// call is done.
    pub(crate) fn request(
        &self,
        selection: Selection,
        permission: Permission,
    ) -> Result<(Request, WindowsProofs)> {
        let Selection {
            working_directory,
            workspace,
            readable,
            read_only,
            timeout_ms,
            command,
            scratch,
            transfer,
        } = selection;
        let writable_cwd = if scratch.is_some() {
            self.admit_scratch(&workspace, &readable)?;
            true
        } else {
            self.admit(&working_directory, &workspace, &readable)?
        };
        ensure!(
            Permission::Read.is_within(permission),
            "managed WSL requires at least `read` permission"
        );
        let selects_windows = windows_components(&working_directory).is_some()
            || workspace
                .iter()
                .chain(&readable)
                .any(|grant| windows_components(grant).is_some());
        ensure!(
            !selects_windows || Permission::Workspace.is_within(permission),
            "a Windows-backed mount needs `workspace` access to prove its identity; at `read` only \
             guest directories can be mounted"
        );
        let access = if read_only || !writable_cwd {
            Permission::Read
        } else {
            permission.greatest_within_both(Permission::Workspace)
        };
        // The guard owns the markers from the first one written, so a refusal while building a
        // later mount removes what this request already dropped in a Windows root.
        let mut proofs = WindowsProofs::default();
        let request = Request {
            version: VERSION,
            op: new_op(),
            access,
            working_directory: mount_root(&working_directory, &mut proofs)?,
            workspace: workspace
                .iter()
                .map(|grant| mount_root(grant, &mut proofs))
                .collect::<Result<_>>()?,
            readable: readable
                .iter()
                .map(|grant| mount_root(grant, &mut proofs))
                .collect::<Result<_>>()?,
            timeout_ms,
            script: command,
            scratch: scratch.map(|scratch| Scratch {
                path: scratch.path.into(),
                quota_bytes: scratch.quota_bytes,
                create: scratch.create,
            }),
            transfer,
        };
        request.validate()?;
        Ok((request, proofs))
    }

    /// Admit the mounts a scratch call adds on top of its own workspace. The staged copy is the
    /// handle's own directory, not a CLI grant: its shape is checked on the wire and the runner
    /// keeps it under [`SCRATCH_ROOT`], while every reference mount is still an exact grant.
    fn admit_scratch(&self, workspace: &[String], readable: &[String]) -> Result<()> {
        ensure!(
            workspace.is_empty(),
            "a scratch workspace takes no additional workspace mounts"
        );
        let mut selected: Vec<&str> = Vec::new();
        for path in readable {
            ensure!(
                self.workspace.iter().any(|root| root == path)
                    || self.readable.iter().any(|root| root == path),
                "not a WSL directory grant: {path:?}"
            );
            ensure!(
                !selected.contains(&path.as_str()),
                "duplicate WSL mount: {path:?}"
            );
            selected.push(path);
        }
        Ok(())
    }

    /// Admit one selection of exact CLI grants, in the guest's own spelling, and say whether the
    /// selected working directory is a writable grant.
    ///
    /// The one admission path for the subshell tools: [`Self::request`] asks it on every run and
    /// `subshell_open` asks it before a handle pins a scope, so authority is re-checked whenever
    /// it is used rather than trusted from when it was granted.
    pub(crate) fn admit(
        &self,
        working_directory: &str,
        workspace: &[String],
        readable: &[String],
    ) -> Result<bool> {
        let writable_cwd = self.workspace.iter().any(|root| root == working_directory);
        ensure!(
            writable_cwd || self.readable.iter().any(|root| root == working_directory),
            "working_directory must name an exact WSL directory grant: {working_directory:?}"
        );
        let mut selected = vec![working_directory];
        for path in workspace {
            ensure!(
                self.workspace.iter().any(|root| root == path),
                "not a WSL workspace grant: {path:?}"
            );
            ensure!(
                !selected.contains(&path.as_str()),
                "duplicate WSL mount: {path:?}"
            );
            selected.push(path);
        }
        for path in readable {
            ensure!(
                self.workspace.iter().any(|root| root == path)
                    || self.readable.iter().any(|root| root == path),
                "not a WSL directory grant: {path:?}"
            );
            ensure!(
                !selected.contains(&path.as_str()),
                "duplicate WSL mount: {path:?}"
            );
            selected.push(path);
        }
        Ok(writable_cwd)
    }

    /// The distro that owns the selected directories.
    pub(crate) fn distribution(&self) -> &str {
        &self.distribution
    }

    /// Whether `path`, in the spelling its kind uses, is one of the granted directories or inside
    /// one: what a scratch source must be to be staged. Staging copies from Windows, so the
    /// selection rule is the grants': a source the grants do not cover would be a copy the session
    /// was never admitted to read. A guest path is compared with guest spelling and a Windows path
    /// with Windows spelling, so one kind's rules never reach the other.
    pub(crate) fn admits_source(&self, path: &str) -> bool {
        self.workspace
            .iter()
            .chain(self.readable.iter())
            .any(|root| root_contains(root, path))
    }

    /// The trusted absolute runner path in this distro.
    pub(crate) fn runner(&self) -> &str {
        &self.runner
    }
}

#[cfg(windows)]
/// The command and subset of grants selected for one invocation.
#[derive(Default)]
pub(crate) struct Selection {
    pub(crate) working_directory: String,
    pub(crate) workspace: Vec<String>,
    pub(crate) readable: Vec<String>,
    pub(crate) read_only: bool,
    pub(crate) timeout_ms: u64,
    pub(crate) command: String,
    pub(crate) scratch: Option<ScratchSelection>,
    /// The transfer this request performs instead of running `command`.
    pub(crate) transfer: Option<Transfer>,
}

/// The scratch workspace one invocation runs in, as the wire sees it.
#[cfg(windows)]
#[derive(Clone)]
pub(crate) struct ScratchSelection {
    pub(crate) path: String,
    pub(crate) quota_bytes: u64,
    pub(crate) create: bool,
}

/// A session-owned handle pinning one admitted scope for the subshell tools.
///
/// The handle retains the admitted scope, not a live shell: every call under it starts a fresh
/// shell, so `cd`, environment changes and background processes cannot carry authority into a
/// later call. The scope is re-admitted against the CLI grants at every use, and the level a call
/// runs at is the level the handle was opened at narrowed to what the session holds now: an
/// upgrade never widens an open handle, and a downgrade stops the work already running under it
/// through the permission lease each call holds.
#[cfg(windows)]
pub(crate) struct Handle {
    target: Arc<Target>,
    session: Option<uuid::Uuid>,
    working_directory: String,
    workspace: Vec<String>,
    readable: Vec<String>,
    read_only: bool,
    opened_level: Permission,
    scratch: Option<ScratchState>,
    cancel: tokio_util::sync::CancellationToken,
    /// Open for new work until a close removes the handle from the registry. A call that looks a
    /// handle up and then starts after a close has released its scope would run outside every
    /// boundary the close reported released, so admission and close take this one lock.
    state: std::sync::Mutex<HandleState>,
    /// Pulsed whenever a call under this handle returns, so a close can wait for the work it
    /// stopped instead of reporting it stopped the moment the cancellation is requested.
    idle: tokio::sync::Notify,
}

/// Whether a handle still admits work, and how much it holds.
#[cfg(windows)]
#[derive(Default)]
struct HandleState {
    open: bool,
    running: usize,
}

/// One handle's staged scratch workspace: where the copy lives in the guest, where its snapshot
/// came from, and what that snapshot held.
///
/// The baseline records the staged source, not the copy: an export back over the source region is
/// checked against it, so an edit made while the work ran is reported as a conflict instead of
/// being overwritten.
#[cfg(windows)]
pub(crate) struct ScratchState {
    pub(crate) path: String,
    pub(crate) source: String,
    /// The source region as a Windows path, resolved once at open, so export targets are compared
    /// against the directory the snapshot was taken from.
    pub(crate) source_root: std::path::PathBuf,
    pub(crate) quota_bytes: u64,
    /// Whether `source` names a guest path. Guest names are case-sensitive, so a baseline key
    /// compared against one must match exactly; a Windows source is looked up the way its
    /// filesystem does, case-insensitively.
    pub(crate) guest_source: bool,
    pub(crate) baseline: std::collections::HashMap<String, BaselineEntry>,
}

/// One staged file as the source held it when the snapshot was taken.
#[cfg(windows)]
#[derive(Clone, Copy, Debug)]
pub(crate) struct BaselineEntry {
    pub(crate) len: u64,
    pub(crate) modified: std::time::SystemTime,
    /// SHA-256 of the staged bytes. Length and modification time are what a cheap check reads,
    /// but an edit can preserve both; the digest is what makes a rewrite detectable.
    pub(crate) digest: [u8; 32],
}

#[cfg(windows)]
impl Handle {
    /// Pin one admitted scope. The scope's shape is checked by [`Handles::open`]'s caller through
    /// [`Target::admit`] before it gets here.
    #[allow(
        clippy::too_many_arguments,
        reason = "one pinned scope, set once at open"
    )]
    pub(crate) fn new(
        target: Arc<Target>,
        session: Option<uuid::Uuid>,
        working_directory: String,
        workspace: Vec<String>,
        readable: Vec<String>,
        read_only: bool,
        opened_level: Permission,
    ) -> Self {
        Self {
            target,
            session,
            working_directory,
            workspace,
            readable,
            read_only,
            opened_level,
            scratch: None,
            cancel: tokio_util::sync::CancellationToken::new(),
            state: std::sync::Mutex::new(HandleState {
                open: true,
                running: 0,
            }),
            idle: tokio::sync::Notify::new(),
        }
    }

    /// Give this handle the staged scratch workspace its scope lives in. Set once at open, after
    /// the snapshot is staged and its baseline recorded.
    pub(crate) fn with_scratch(mut self, scratch: ScratchState) -> Self {
        self.scratch = Some(scratch);
        self
    }

    /// The staged workspace this handle runs in, when it has one.
    pub(crate) fn scratch(&self) -> Option<&ScratchState> {
        self.scratch.as_ref()
    }

    /// The scope this handle pins and the mounts a run under it sees, as shown to the model and
    /// recorded in the conversation: the target and path descriptions a later turn may need, since
    /// the grants themselves are never persisted or reused.
    pub(crate) fn scope_description(&self) -> String {
        let workspace = match &self.scratch {
            Some(scratch) => format!(
                "scratch copy of {} staged at {} (quota {} MiB). Export paths may name /workspace \
                 or the staged path.",
                scratch.source,
                scratch.path,
                scratch.quota_bytes / crate::text::MIB as u64
            ),
            None => self.working_directory.clone(),
        };
        let mut described = format!(
            "WSL distribution {:?}. Access: {}. /workspace: {}.",
            self.target.distribution(),
            if self.read_only {
                "read-only"
            } else {
                "the session's level"
            },
            workspace
        );
        for (index, path) in self.workspace.iter().enumerate() {
            described.push_str(&format!(" /workspaces/{index}: {path}."));
        }
        for (index, path) in self.readable.iter().enumerate() {
            described.push_str(&format!(" /references/{index}: {path}."));
        }
        described
    }

    /// The level a call under this handle runs at: the level the handle was opened at, narrowed to
    /// what the session permits now.
    pub(crate) fn effective_level(&self, current: Permission) -> Permission {
        self.opened_level.greatest_within_both(current)
    }

    /// Whether `path`, in the spelling its kind uses, is within the admitted scope.
    pub(crate) fn admits_path(&self, path: &str) -> bool {
        std::iter::once(&self.working_directory)
            .chain(self.workspace.iter())
            .chain(self.readable.iter())
            .any(|root| root_contains(root, path))
    }

    /// The typed source one admitted guest path names: the request root it lives under and the
    /// validated components beneath it, so no free-standing absolute path travels on the wire and
    /// every resolution happens beneath a root the runner opens itself. The scratch workspace is
    /// its own root; every other root is the request mount the path was admitted under, in request
    /// order: the working directory first, then the workspace mounts, then the read-only ones.
    pub(crate) fn export_source(&self, path: &str) -> Option<ExportSource> {
        if let Some(scratch) = &self.scratch
            && let Some(relative) = relative_beneath(&scratch.path, path)
        {
            return Some(ExportSource {
                root: ExportRoot::Scratch,
                relative,
            });
        }
        std::iter::once(&self.working_directory)
            .chain(self.workspace.iter())
            .chain(self.readable.iter())
            .enumerate()
            .find_map(|(index, root)| {
                relative_beneath(root, path).map(|relative| ExportSource {
                    root: ExportRoot::Mounted(index),
                    relative,
                })
            })
    }

    /// The name the runner publishes one export source under: its final component, or the root's
    /// own when the source is the root itself.
    pub(crate) fn export_name(&self, source: &ExportSource) -> Option<String> {
        if let Some(last) = source.relative.last() {
            return Some(last.clone());
        }
        let root = match &source.root {
            ExportRoot::Scratch => self.scratch.as_ref()?.path.as_str(),
            ExportRoot::Mounted(index) => std::iter::once(&self.working_directory)
                .chain(self.workspace.iter())
                .chain(self.readable.iter())
                .nth(*index)?,
        };
        Some(
            root.rsplit(['/', '\\'])
                .next()
                .filter(|name| !name.is_empty())?
                .to_owned(),
        )
    }

    /// Whether the canonical Windows `path` is still within a Windows-backed grant of this handle,
    /// with the grant resolved the same way. The spelling check ([`Self::admits_path`]) admits a
    /// grant as the operator wrote it; this one admits the directory it names, so a junction below
    /// the grant cannot carry a read outside the tree the grant was meant to be.
    pub(crate) fn admits_canonical_windows(&self, path: &std::path::Path) -> bool {
        let path = crate::fs::strip_verbatim(path.to_path_buf());
        let path = path.to_string_lossy();
        std::iter::once(&self.working_directory)
            .chain(self.workspace.iter())
            .chain(self.readable.iter())
            .filter(|root| windows_components(root).is_some())
            .filter_map(|root| std::fs::canonicalize(root).ok())
            .any(|root| {
                let root = crate::fs::strip_verbatim(root);
                windows_beneath(&path, &root.to_string_lossy())
            })
    }

    /// The target this handle's calls launch against.
    pub(crate) fn target(&self) -> &Arc<Target> {
        &self.target
    }

    /// The wire request for one call, re-admitting the pinned scope against the CLI grants on the
    /// way: authority is checked when it is used, not when the handle was opened. The returned
    /// proofs must be held until the call is done.
    pub(crate) fn request(
        &self,
        command: String,
        timeout_ms: u64,
        current: Permission,
    ) -> Result<(Request, WindowsProofs)> {
        self.target.request(
            Selection {
                working_directory: self.working_directory.clone(),
                workspace: self.workspace.clone(),
                readable: self.readable.clone(),
                read_only: self.read_only,
                timeout_ms,
                command,
                scratch: self.scratch.as_ref().map(|scratch| ScratchSelection {
                    path: scratch.path.clone(),
                    quota_bytes: scratch.quota_bytes,
                    create: false,
                }),
                transfer: None,
            },
            self.effective_level(current),
        )
    }

    /// The wire request for one transfer over the pinned scope, with the same re-admission the
    /// command path performs. The returned proofs must be held until the transfer is done.
    pub(crate) fn transfer_request(
        &self,
        timeout_ms: u64,
        transfer: Transfer,
        current: Permission,
    ) -> Result<(Request, WindowsProofs)> {
        let create = matches!(transfer, Transfer::Stage { .. });
        self.target.request(
            Selection {
                working_directory: self.working_directory.clone(),
                workspace: self.workspace.clone(),
                readable: self.readable.clone(),
                read_only: self.read_only,
                timeout_ms,
                command: String::new(),
                scratch: self.scratch.as_ref().map(|scratch| ScratchSelection {
                    path: scratch.path.clone(),
                    quota_bytes: scratch.quota_bytes,
                    create,
                }),
                transfer: Some(transfer),
            },
            self.effective_level(current),
        )
    }

    /// Fires when the handle is closed.
    pub(crate) fn cancelled(&self) -> tokio_util::sync::CancellationToken {
        self.cancel.clone()
    }

    /// Take one unit of outstanding work, so a close can report what it stopped. The guard returns
    /// the unit when the call ends, including on panic.
    ///
    /// A close removes the handle from the registry and then shuts this door under the same state
    /// lock. A caller that already looked the handle up therefore either gets in first, and its
    /// unit is counted so the close waits for it, or arrives after the close and is refused
    /// rather than starting work in a scope the close has released.
    pub(crate) fn begin(self: &Arc<Self>) -> Result<Outstanding> {
        let mut state = crate::sync::lock(&self.state);
        ensure!(
            state.open,
            "the subshell handle was closed before this call started"
        );
        state.running += 1;
        drop(state);
        Ok(Outstanding(Arc::clone(self)))
    }

    /// How many calls under this handle are running right now.
    pub(crate) fn outstanding(&self) -> usize {
        crate::sync::lock(&self.state).running
    }

    /// Refuse new work. Called by the close after the name is out of the registry.
    fn end_operations(&self) {
        crate::sync::lock(&self.state).open = false;
    }

    /// Wait until no call under this handle is running. A call that was already past its last
    /// cancellation check when the close fired finishes here, so the caller can say the work
    /// stopped only after it did.
    pub(crate) async fn wait_idle(&self) {
        loop {
            // `notify_one` stores a permit when nobody is waiting yet, so a return between this
            // check and the await is not lost.
            let idle = self.idle.notified();
            if self.outstanding() == 0 {
                return;
            }
            idle.await;
        }
    }
}

/// One running call's claim on a [`Handle`], returned to the handle when the call ends.
#[cfg(windows)]
pub(crate) struct Outstanding(Arc<Handle>);

#[cfg(windows)]
impl Drop for Outstanding {
    fn drop(&mut self) {
        let mut state = crate::sync::lock(&self.0.state);
        state.running = state.running.saturating_sub(1);
        drop(state);
        self.0.idle.notify_one();
    }
}

/// The open handles one session's subshell tools share.
///
/// Handles live only in this process and only in the registry of the session that opened them: a
/// lookup names both the session and the handle, so a handle cannot be reached from a session that
/// did not open it, and none survives the session or its registry. Nothing here is persisted: the
/// conversation records the target and path descriptions, never reusable grants.
#[cfg(windows)]
#[derive(Default)]
pub(crate) struct Handles {
    inner: std::sync::Mutex<std::collections::HashMap<String, Arc<Handle>>>,
}

#[cfg(windows)]
impl Handles {
    /// Pin one admitted scope under `name`, refusing a name already open in this session.
    pub(crate) fn open(
        &self,
        session: Option<uuid::Uuid>,
        name: &str,
        handle: Handle,
    ) -> Result<Arc<Handle>> {
        ensure!(
            !name.is_empty()
                && name.len() <= 64
                && !name.starts_with('-')
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte)),
            "a subshell handle name must be 1 to 64 letters, digits, dots, underscores or dashes"
        );
        ensure!(
            handle.session == session,
            "a subshell handle belongs to the session that opened it"
        );
        let mut inner = crate::sync::lock(&self.inner);
        ensure!(
            !inner.contains_key(name),
            "a subshell handle named {name:?} is already open in this session"
        );
        let handle = Arc::new(handle);
        inner.insert(name.to_owned(), Arc::clone(&handle));
        drop(inner);
        Ok(handle)
    }

    /// The handle `name` pins in this session, or the refusal naming what went wrong.
    pub(crate) fn get(&self, session: Option<uuid::Uuid>, name: &str) -> Result<Arc<Handle>> {
        let inner = crate::sync::lock(&self.inner);
        let handle = inner.get(name).cloned().ok_or_else(|| {
            anyhow::anyhow!("no subshell handle named {name:?} is open in this session")
        })?;
        drop(inner);
        ensure!(
            handle.session == session,
            "no subshell handle named {name:?} is open in this session"
        );
        Ok(handle)
    }

    /// Close the handle `name`: stop the work running under it and release its scope. The removed
    /// handle comes back so the close can report what it stopped.
    ///
    /// The lookup, the session check and the removal happen under one lock. A close that looked
    /// the handle up first and removed the name afterwards could delete a handle opened under the
    /// same name in between, leaving the reopened one unreachable; taking the name out in the same
    /// guard is what makes the name it removes the one it looked up.
    pub(crate) fn close(&self, session: Option<uuid::Uuid>, name: &str) -> Result<Arc<Handle>> {
        let mut inner = crate::sync::lock(&self.inner);
        let handle = inner.get(name).cloned().ok_or_else(|| {
            anyhow::anyhow!("no subshell handle named {name:?} is open in this session")
        })?;
        ensure!(
            handle.session == session,
            "no subshell handle named {name:?} is open in this session"
        );
        inner.remove(name);
        drop(inner);
        handle.end_operations();
        handle.cancel.cancel();
        Ok(handle)
    }
}

// Session teardown is not a scratch teardown. A workspace is the guest's, which expires it after
// its lease, so nothing here reaches into the guest's filesystem: a session that ended without
// closing its handles leaves them to that reaper.

#[cfg(test)]
#[cfg(windows)]
mod tests {
    use std::path::Path;

    use super::*;

    fn root(path: &str) -> WslDirectory {
        WslDirectory::from_run_directory(Path::new(path))
            .unwrap()
            .unwrap()
    }

    fn target(workspace: &[WslDirectory], readable: &[WslDirectory]) -> Result<Target> {
        Target::from_grants("Test Linux", DEFAULT_RUNNER, workspace, readable, &[])
    }

    #[test]
    fn guest_selections_cannot_widen_or_reclassify_cli_grants() {
        let target = target(&[root(r"\\wsl.localhost\Test Linux\home\Project")], &[
            root(r"\\wsl$\Test Linux\home\Reference"),
        ])
        .unwrap();
        let selection = |cwd: &str| Selection {
            working_directory: cwd.into(),
            workspace: Vec::new(),
            readable: Vec::new(),
            read_only: false,
            timeout_ms: 1000,
            command: "pwd".into(),
            scratch: None,
            transfer: None,
        };
        for path in ["/home/project", "/home", "/home/Project/subdir"] {
            assert!(
                target
                    .request(selection(path), Permission::Unrestricted)
                    .is_err(),
                "{path}"
            );
        }
        assert!(
            target
                .request(
                    Selection {
                        workspace: vec!["/home/Reference".into()],
                        ..selection("/home/Project")
                    },
                    Permission::Workspace
                )
                .is_err()
        );
        assert!(
            target
                .request(
                    Selection {
                        readable: vec!["/home/Outside".into()],
                        ..selection("/home/Project")
                    },
                    Permission::Workspace
                )
                .is_err()
        );
        assert!(
            target
                .request(selection("/home/Project"), Permission::None)
                .is_err()
        );
        for (cwd, permission, read_only, expected) in [
            ("/home/Project", Permission::Read, false, Permission::Read),
            (
                "/home/Project",
                Permission::Unrestricted,
                false,
                Permission::Workspace,
            ),
            (
                "/home/Project",
                Permission::Workspace,
                true,
                Permission::Read,
            ),
            (
                "/home/Reference",
                Permission::Workspace,
                false,
                Permission::Read,
            ),
        ] {
            let (request, _proofs) = target
                .request(
                    Selection {
                        read_only,
                        ..selection(cwd)
                    },
                    permission,
                )
                .unwrap();
            assert_eq!(request.access, expected);
            assert!(request.workspace.is_empty() && request.readable.is_empty());
        }
    }

    /// A scratch selection is the request's own workspace: the wire carries the staged path and
    /// its quota, no additional mounts ride along, and the call is pinned to workspace access.
    #[test]
    fn a_scratch_selection_becomes_the_requests_own_workspace() {
        let target = target(&[root(r"\\wsl.localhost\Test Linux\home\Project")], &[]).unwrap();
        let scratch_path = format!("{SCRATCH_ROOT}/0123456789abcdef");
        let selection = |scratch: Option<ScratchSelection>| Selection {
            working_directory: scratch_path.clone(),
            workspace: Vec::new(),
            readable: Vec::new(),
            read_only: false,
            timeout_ms: 1000,
            command: "pwd".into(),
            scratch,
            transfer: None,
        };
        let staged = ScratchSelection {
            path: scratch_path.clone(),
            quota_bytes: 1024 * 1024,
            create: true,
        };
        let (request, _proofs) = target
            .request(selection(Some(staged)), Permission::Unrestricted)
            .unwrap();
        assert_eq!(request.access, Permission::Workspace);
        let scratch = request.scratch.as_ref().unwrap();
        assert_eq!(
            scratch.path,
            std::path::Path::new(&scratch_path),
            "the wire carries the staged path"
        );
        assert_eq!(scratch.quota_bytes, 1024 * 1024);
        assert!(scratch.create);

        let error = target
            .request(
                Selection {
                    workspace: vec!["/home/Project".into()],
                    ..selection(Some(ScratchSelection {
                        path: scratch_path.clone(),
                        quota_bytes: 1024 * 1024,
                        create: false,
                    }))
                },
                Permission::Workspace,
            )
            .unwrap_err();
        assert!(
            format!("{error:#}").contains("no additional workspace mounts"),
            "{error:#}"
        );

        let error = target
            .request(
                selection(Some(ScratchSelection {
                    path: scratch_path.clone(),
                    quota_bytes: 1024 * 1024,
                    create: false,
                })),
                Permission::Read,
            )
            .unwrap_err();
        assert!(
            format!("{error:#}").contains("a scratch workspace requires workspace access"),
            "{error:#}"
        );
    }

    #[test]
    fn guest_grants_cannot_mix_distros_contain_the_runner_or_overlap() {
        for (path, expected) in [
            (
                r"\\wsl$\Wrong distro\home\Project",
                "not in the configured distribution",
            ),
            (
                r"\\wsl$\Test Linux\usr\local",
                "contains the trusted runner",
            ),
            (
                r"\\wsl$\Test Linux\home\Project\Child",
                "overlapping WSL directory grant",
            ),
        ] {
            let error = target(&[root(r"\\wsl.localhost\Test Linux\home\Project")], &[
                root(path),
            ])
            .expect_err("invalid scope");
            assert!(error.to_string().contains(expected), "{error}");
        }
    }

    fn pinned_target() -> Arc<Target> {
        Arc::new(target(&[root(r"\\wsl.localhost\Test Linux\home\Project")], &[]).unwrap())
    }

    fn handle(target: &Arc<Target>, opened: Permission) -> Handle {
        Handle::new(
            Arc::clone(target),
            None,
            "/home/Project".into(),
            Vec::new(),
            Vec::new(),
            false,
            opened,
        )
    }

    /// The level a call runs at is the level the handle was opened at narrowed to the session's
    /// level now: a downgrade narrows an open handle, and an upgrade never widens one.
    #[test]
    fn a_handle_narrows_to_the_session_level_but_an_upgrade_does_not_widen_it() {
        let target = pinned_target();
        let pinned_read = handle(&target, Permission::Read);
        let pinned_write = handle(&target, Permission::Workspace);
        assert_eq!(
            pinned_read.effective_level(Permission::Unrestricted),
            Permission::Read
        );
        assert_eq!(
            pinned_write.effective_level(Permission::Unrestricted),
            Permission::Workspace
        );
        assert_eq!(
            pinned_write.effective_level(Permission::Read),
            Permission::Read
        );
        let (request, _proofs) = pinned_read
            .request("pwd".into(), 1000, Permission::Unrestricted)
            .unwrap();
        assert_eq!(request.access, Permission::Read);
    }

    /// Authority is re-admitted when it is used: a scope the grants never admitted must be refused
    /// by the request path even if something bypassed the check at open.
    #[test]
    fn a_handle_re_admits_its_scope_at_every_use() {
        let target = pinned_target();
        let smuggled = Handle::new(
            Arc::clone(&target),
            None,
            "/home/Outside".into(),
            Vec::new(),
            Vec::new(),
            false,
            Permission::Workspace,
        );
        assert!(
            smuggled
                .request("pwd".into(), 1000, Permission::Workspace)
                .is_err(),
            "a pinned scope outside the CLI grants must not run"
        );
    }

    /// Handles are addressed by name within the session that opened them, stop their work on
    /// close, and release their name.
    #[test]
    fn handles_are_addressed_by_name_within_the_session_that_opened_them() {
        let target = pinned_target();
        let handles = Handles::default();
        let one = uuid::Uuid::from_u128(1);
        let two = uuid::Uuid::from_u128(2);
        let open = |session: Option<uuid::Uuid>, name: &str| {
            handles.open(
                session,
                name,
                Handle::new(
                    Arc::clone(&target),
                    session,
                    "/home/Project".into(),
                    Vec::new(),
                    Vec::new(),
                    false,
                    Permission::Workspace,
                ),
            )
        };
        let work = open(Some(one), "work").unwrap();
        for bad in ["", "-work", "work space", "w/ork", &"x".repeat(65)] {
            assert!(open(Some(one), bad).is_err(), "{bad:?} must be refused");
        }
        assert!(
            open(Some(one), "work").is_err(),
            "a name already open in the session must not be taken twice"
        );
        assert!(
            handles.get(Some(two), "work").is_err(),
            "another session must not reach the handle"
        );
        assert!(handles.close(Some(two), "work").is_err());
        assert!(work.admits_path("/home/Project/build/out.bin"));
        assert!(!work.admits_path("/home/Projector/secret"));
        {
            let _outstanding = work.begin().expect("an open handle admits work");
            assert_eq!(work.outstanding(), 1);
        }
        assert_eq!(work.outstanding(), 0);
        let closed = handles.close(Some(one), "work").unwrap();
        assert!(closed.cancelled().is_cancelled());
        assert!(
            closed.begin().is_err(),
            "a handle taken out of the registry admits no new work"
        );
        assert!(handles.get(Some(one), "work").is_err());
        assert!(
            open(Some(one), "work").is_ok(),
            "a closed name must be reusable"
        );
    }

    /// A Windows-backed grant is refused when it overlaps another, compared with Windows
    /// semantics so `C:\src` and `c:\SRC` name the same directory.
    #[test]
    fn windows_grants_cannot_overlap_case_insensitively() {
        let error = Target::from_grants("Test Linux", DEFAULT_RUNNER, &[], &[], &[
            r"C:\src".into(),
            r"c:\SRC\child".into(),
        ])
        .expect_err("overlapping Windows grants");
        assert!(
            error
                .to_string()
                .contains("overlapping WSL directory grant"),
            "{error}"
        );
    }

    /// A Windows-backed grant must be a normalized drive-absolute path.
    #[test]
    fn windows_grants_must_be_normalized_drive_absolute() {
        for bad in [
            r"C:relative",
            r"\\server\share",
            r"C:\has\..\dot",
            r"C:\trailing\",
        ] {
            let error = Target::from_grants("Test Linux", DEFAULT_RUNNER, &[], &[], &[bad.into()])
                .expect_err("invalid Windows grant");
            assert!(
                error
                    .to_string()
                    .contains("must be a normalized drive-absolute path"),
                "{bad:?}: {error}"
            );
        }
    }

    /// A Windows-backed grant may not expose Meka's own directories, in either direction, and a
    /// drive root is refused before any proof could claim it.
    #[test]
    fn windows_grants_may_not_overlap_private_directories() {
        let temp =
            std::env::temp_dir().join(format!("meka-private-{}", uuid::Uuid::new_v4().simple()));
        let private = temp.join("private");
        std::fs::create_dir_all(private.join("child")).unwrap();
        let sibling = temp.join("sibling");
        std::fs::create_dir_all(&sibling).unwrap();
        let canonical = |path: &std::path::Path| {
            crate::fs::strip_verbatim(std::fs::canonicalize(path).unwrap())
        };
        let (private, root, sibling) = (canonical(&private), canonical(&temp), canonical(&sibling));
        let private_text = private.to_string_lossy().to_string();
        let root_text = root.to_string_lossy().to_string();

        for grant in [
            private_text.clone(),
            format!("{private_text}\\child"),
            root_text.clone(),
        ] {
            let error = admit_windows_grant(&grant, std::slice::from_ref(&private))
                .expect_err("a grant overlapping a private directory");
            assert!(
                error
                    .to_string()
                    .contains("overlaps Meka's private directory"),
                "{grant}: {error}"
            );
        }
        let error = admit_windows_grant(r"C:\", &[]).expect_err("a drive root");
        assert!(
            error.to_string().contains("cannot be a drive root"),
            "{error}"
        );
        assert_eq!(
            admit_windows_grant(&sibling.to_string_lossy(), &[private]).unwrap(),
            sibling,
            "a grant beside the private directory is fine"
        );
        std::fs::remove_dir_all(&temp).unwrap();
    }

    /// A request carrying a Windows-backed mount creates its identity proof in the root and the
    /// guard removes it when the call is done.
    #[test]
    fn a_windows_mount_drops_its_proof_and_the_guard_removes_it() {
        let temp =
            std::env::temp_dir().join(format!("meka-proof-test-{}", uuid::Uuid::new_v4().simple()));
        std::fs::create_dir_all(&temp).unwrap();
        let grant = temp.to_string_lossy().to_string();
        let target = Target::from_grants(
            "Test Linux",
            DEFAULT_RUNNER,
            &[],
            &[],
            std::slice::from_ref(&grant),
        )
        .unwrap();
        let (request, proofs) = target
            .request(
                Selection {
                    working_directory: grant.clone(),
                    workspace: Vec::new(),
                    readable: Vec::new(),
                    read_only: false,
                    timeout_ms: 1000,
                    command: "pwd".into(),
                    scratch: None,
                    transfer: None,
                },
                Permission::Workspace,
            )
            .unwrap();
        let mount_root = &request.working_directory;
        let proof_name = match mount_root {
            MountRoot::Windows(win) => &win.proof,
            _ => panic!("expected a Windows mount"),
        };
        assert!(is_proof_name(proof_name));
        let marker = temp.join(proof_name);
        assert!(marker.exists(), "the proof must be in the root");
        drop(proofs);
        assert!(!marker.exists(), "the guard must remove the proof");
        std::fs::remove_dir_all(&temp).unwrap();
    }

    /// A Windows-backed mount needs `workspace` access to prove its identity; at `read` only
    /// guest directories may be mounted.
    #[test]
    fn a_windows_mount_is_refused_at_read_level() {
        let temp =
            std::env::temp_dir().join(format!("meka-proof-read-{}", uuid::Uuid::new_v4().simple()));
        std::fs::create_dir_all(&temp).unwrap();
        let grant = temp.to_string_lossy().to_string();
        let target = Target::from_grants(
            "Test Linux",
            DEFAULT_RUNNER,
            &[],
            &[],
            std::slice::from_ref(&grant),
        )
        .unwrap();
        let error = target
            .request(
                Selection {
                    working_directory: grant.clone(),
                    workspace: Vec::new(),
                    readable: Vec::new(),
                    read_only: false,
                    timeout_ms: 1000,
                    command: "pwd".into(),
                    scratch: None,
                    transfer: None,
                },
                Permission::Read,
            )
            .expect_err("read-level Windows mount");
        assert!(
            format!("{error:#}").contains("needs `workspace` access"),
            "{error:#}"
        );
        std::fs::remove_dir_all(&temp).unwrap();
    }

    /// The wire shape check refuses a bad proof name or a bad Windows path before the request
    /// travels.
    #[test]
    fn validate_shape_refuses_a_bad_proof_or_windows_path() {
        let bad_proof = MountRoot::Windows(WindowsRoot {
            windows: r"C:\src".into(),
            proof: "not-a-proof".into(),
        });
        assert!(bad_proof.validate_shape().is_err());
        let bad_path = MountRoot::Windows(WindowsRoot {
            windows: r"C:\has\..\dot".into(),
            proof: proof_name(),
        });
        assert!(bad_path.validate_shape().is_err());
        let good = MountRoot::Windows(WindowsRoot {
            windows: r"C:\src".into(),
            proof: proof_name(),
        });
        assert!(good.validate_shape().is_ok());
    }

    /// One request around a transfer, so each shape is judged the way the wire judges it.
    fn transfer_request(transfer: Transfer, scratch: Option<Scratch>, script: &str) -> Request {
        let working_directory = match &scratch {
            Some(scratch) => MountRoot::Guest(scratch.path.clone()),
            None => MountRoot::Guest("/home/project".into()),
        };
        Request {
            version: VERSION,
            op: new_op(),
            access: Permission::Workspace,
            working_directory,
            workspace: Vec::new(),
            readable: Vec::new(),
            timeout_ms: 1000,
            script: script.to_owned(),
            scratch,
            transfer: Some(transfer),
        }
    }

    fn stage_scratch() -> Scratch {
        Scratch {
            path: format!("{SCRATCH_ROOT}/0123456789abcdef").into(),
            quota_bytes: 1024 * 1024,
            create: true,
        }
    }

    /// A transfer is its own request shape: no script, workspace access, and the scratch workspace
    /// each kind needs. The command rules still hold for a request with no transfer.
    #[test]
    fn transfer_requests_carry_their_own_shape() {
        let stage = transfer_request(
            Transfer::Stage {
                source: MountRoot::Guest("/home/project".into()),
            },
            Some(stage_scratch()),
            "",
        );
        assert!(stage.validate().is_ok(), "{:?}", stage.validate());
        // The execute rules still refuse an empty script when no transfer is asked for.
        let mut command = transfer_request(
            Transfer::Stage {
                source: MountRoot::Guest("/home/project".into()),
            },
            Some(stage_scratch()),
            "",
        );
        command.transfer = None;
        assert!(command.validate().is_err());
        // A transfer carries no script at all.
        let mut with_script = stage;
        with_script.script = "echo hi".into();
        assert!(with_script.validate().is_err());

        // A stage must create its workspace and must name one.
        let mut existing = transfer_request(
            Transfer::Stage {
                source: MountRoot::Guest("/home/project".into()),
            },
            Some(Scratch {
                create: false,
                ..stage_scratch()
            }),
            "",
        );
        assert!(existing.validate().is_err());
        existing.scratch = None;
        assert!(existing.validate().is_err());

        // A removal names an existing workspace and needs no workspace access.
        let removal = transfer_request(
            Transfer::RemoveScratch,
            Some(Scratch {
                create: false,
                ..stage_scratch()
            }),
            "",
        );
        assert!(removal.validate().is_ok());
        let mut read_level = removal;
        read_level.access = Permission::Read;
        assert!(
            read_level.validate().is_ok(),
            "a removal may run at read level"
        );
        let mut creating = read_level;
        creating.scratch = Some(stage_scratch());
        assert!(creating.validate().is_err());
        let mut no_scratch = transfer_request(Transfer::RemoveScratch, None, "");
        assert!(no_scratch.validate().is_err());
        let scratch = Scratch {
            create: false,
            ..stage_scratch()
        };
        no_scratch.working_directory = MountRoot::Guest(scratch.path.clone());
        no_scratch.scratch = Some(scratch);
        assert!(no_scratch.validate().is_ok());
    }

    /// An upload is a transfer kind of its own: the shape it travels with is its kind alone, and
    /// the workspace it installs into is the one its request creates.
    #[test]
    fn an_upload_names_the_workspace_and_travels_with_nothing_else() {
        let upload: Transfer = serde_json::from_str(r#"{"kind":"upload"}"#).expect("the shape");
        assert!(matches!(upload, Transfer::Upload));
        assert_eq!(
            serde_json::to_value(&Transfer::Upload).expect("encoded"),
            serde_json::json!({"kind": "upload"})
        );
        // A field the receiving side does not understand is never silently dropped.
        assert!(serde_json::from_str::<Transfer>(r#"{"kind":"upload","source":"/home"}"#).is_err());
        let creating = transfer_request(Transfer::Upload, Some(stage_scratch()), "");
        assert!(creating.validate().is_ok(), "{:?}", creating.validate());
        let mut existing = transfer_request(
            Transfer::Upload,
            Some(Scratch {
                create: false,
                ..stage_scratch()
            }),
            "",
        );
        assert!(existing.validate().is_err());
        existing.scratch = None;
        assert!(existing.validate().is_err());
    }

    /// An export names typed roots of its own request and validated components beneath them, so no
    /// free-standing absolute path ever travels and every resolution happens beneath a root the
    /// runner opened itself.
    #[test]
    fn export_sources_are_typed_roots_with_validated_components() {
        let export = |sources: Vec<ExportSource>| {
            transfer_request(Transfer::Export { sources }, None, "").validate()
        };
        let source = |root: ExportRoot, relative: &[&str]| ExportSource {
            root,
            relative: relative.iter().map(|part| (*part).to_owned()).collect(),
        };
        // An empty relative names the root itself; longer sources stay single components.
        assert!(export(vec![source(ExportRoot::Mounted(0), &[])]).is_ok());
        assert!(
            export(vec![source(ExportRoot::Mounted(0), &["src", "main.rs"])]).is_ok(),
            "a relative source beneath a mounted root must be accepted"
        );
        // The wire refuses only what no open could resolve: empty, dot, dot-dot, a separator or a
        // NUL inside one component. Windows-name rules are the publisher's door, not the wire's.
        for bad in ["..", ".", "", "a/b", "a\0b"] {
            assert!(
                export(vec![source(ExportRoot::Mounted(0), &[bad])]).is_err(),
                "{bad:?} was accepted"
            );
        }
        // Depth and joined length are bounded before anything is opened.
        let deep = vec!["a".to_owned(); MAX_TRANSFER_DEPTH + 1];
        assert!(
            export(vec![ExportSource {
                root: ExportRoot::Mounted(0),
                relative: deep,
            }])
            .is_err()
        );
        let long = "a".repeat(MAX_TRANSFER_PATH_BYTES + 1);
        assert!(export(vec![source(ExportRoot::Mounted(0), &[&long])]).is_err());
        // A mounted root must be one of the request's own mounts.
        assert!(export(vec![source(ExportRoot::Mounted(MAX_ROOTS), &[])]).is_err());
        // A scratch source names the request's own scratch workspace.
        assert!(export(vec![source(ExportRoot::Scratch, &["out.txt"])]).is_err());
        let scratch = Scratch {
            create: false,
            ..stage_scratch()
        };
        let mut with_scratch = transfer_request(
            Transfer::Export {
                sources: vec![source(ExportRoot::Scratch, &["out.txt"])],
            },
            Some(scratch),
            "",
        );
        with_scratch.working_directory = MountRoot::Guest(
            with_scratch
                .scratch
                .as_ref()
                .map(|scratch| scratch.path.clone())
                .unwrap_or_default(),
        );
        assert!(with_scratch.validate().is_ok());

        assert!(export(Vec::new()).is_err());
        let too_many = vec![source(ExportRoot::Mounted(0), &[]); MAX_ROOTS + 1];
        assert!(export(too_many).is_err());
        // A transfer has no fields beyond the ones its kind names.
        assert!(
            serde_json::from_str::<Transfer>(r#"{"kind":"remove_scratch","extra":1}"#).is_err()
        );
        assert!(serde_json::from_str::<Transfer>(r#"{"kind":"unknown"}"#).is_err());
        // A source is its typed root and components: no absolute path may stand in for them.
        assert!(
            serde_json::from_str::<ExportSource>(
                r#"{"root":{"mounted":0},"relative":["src"],"path":"/etc"}"#
            )
            .is_err()
        );
    }

    /// Frames round-trip through the wire, and each rejects the shapes that could not have come
    /// from a runner: a relative or escaping path, a malformed digest, or trailing data. Every
    /// control frame carries its operation identifier.
    #[test]
    fn transfer_frames_round_trip_and_refuse_malformed_metadata() {
        let op = new_op();
        let entry = TransferEntry {
            root: 1,
            path: "src/main.rs".into(),
            len: 42,
            modified_secs: 1_700_000_000,
            modified_nanos: 123_456_700,
            digest: digest_hex(&[0xab; 32]),
            directory: false,
        };
        let manifest = Frame::Manifest {
            op: op.clone(),
            roots: vec![TransferRoot {
                source: ExportSource {
                    root: ExportRoot::Mounted(0),
                    relative: Vec::new(),
                },
                name: "project".into(),
                directory: true,
            }],
            entries: vec![entry.clone()],
        };
        for frame in [
            manifest,
            entry.frame(),
            Frame::Done { op: op.clone() },
            Frame::Ready { op: op.clone() },
            Frame::Started { op: op.clone() },
            Frame::Stopped {
                op: op.clone(),
                code: 3,
            },
        ] {
            let bytes = frame.encode().expect("encoded");
            assert_eq!(bytes.last(), Some(&b'\n'));
            let line = bytes.get(..bytes.len() - 1).expect("line");
            let decoded = Frame::decode(line).expect("decoded");
            assert_eq!(
                serde_json::to_vec(&decoded).expect("reserialized"),
                serde_json::to_vec(&frame).expect("serialized")
            );
        }
        assert_eq!(entry.parsed_digest(), Some([0xab; 32]));
        assert_eq!(
            system_time_parts(entry.modified()),
            (1_700_000_000, 123_456_700)
        );
        assert_eq!(
            system_time_parts(system_time(-1, 250_000_000)),
            (-1, 250_000_000)
        );
        assert_eq!(system_time_parts(system_time(-2, 0)), (-2, 0));

        // A control frame with an empty or malformed operation identifier is refused at decode.
        for bad_op in ["", "NOT-A-UUID", &new_op().to_uppercase()] {
            let frame = Frame::Done {
                op: (*bad_op).to_owned(),
            };
            assert!(Frame::decode(&frame.encode().expect("line")[..]).is_err());
        }

        let bad_path = Frame::File {
            root: 0,
            path: "../escape".into(),
            len: 0,
            modified_secs: 0,
            modified_nanos: 0,
            digest: digest_hex(&[0; 32]),
        };
        assert!(Frame::decode(&bad_path.encode().expect("line")[..]).is_err());
        let bad_digest = Frame::File {
            root: 0,
            path: "file".into(),
            len: 0,
            modified_secs: 0,
            modified_nanos: 0,
            digest: "AB".repeat(32),
        };
        assert!(Frame::decode(&bad_digest.encode().expect("line")[..]).is_err());
        // The status quo: an unknown frame is refused, not ignored.
        assert!(Frame::decode(br#"{"frame":"delete","path":"/"}"#).is_err());
        // A manifest past the entry bound is refused before it is walked.
        let entries = vec![
            TransferEntry {
                root: 0,
                path: "file".into(),
                len: 0,
                modified_secs: 0,
                modified_nanos: 0,
                digest: digest_hex(&[0; 32]),
                directory: false,
            };
            MAX_TRANSFER_ENTRIES + 1
        ];
        let oversized = serde_json::to_vec(&Frame::Manifest {
            op: new_op(),
            roots: Vec::new(),
            entries,
        })
        .expect("serialized");
        assert!(Frame::decode(&oversized).is_err());
    }

    /// The start permit is one line: the remaining budget in milliseconds. Anything else on the
    /// launcher's stdin is a protocol failure, never a start.
    #[test]
    fn a_start_permit_is_one_line_of_remaining_budget() {
        assert_eq!(permit_line(Duration::from_millis(1500)), "1500\n");
        assert_eq!(
            parse_permit(b"1500\n"),
            Some(Duration::from_millis(1500)),
            "the permit's budget is the rest of the call's deadline"
        );
        for bad in [
            &b""[..],
            b"\n",
            b"0\n",
            b"-1\n",
            b"words\n",
            b"1500 1500\n",
            &b"1500".repeat(PERMIT_BYTES),
        ] {
            assert!(parse_permit(bad).is_none(), "{bad:?} was accepted");
        }
    }

    /// A control frame is bound to the operation the reader was opened for: a response that names
    /// another operation is refused, wherever it appears.
    #[tokio::test]
    async fn a_transfer_response_may_only_name_its_own_operation() {
        let own = new_op();
        let other = new_op();
        let manifest = |op: &str| {
            Frame::Manifest {
                op: op.to_owned(),
                roots: vec![TransferRoot {
                    source: ExportSource {
                        root: ExportRoot::Mounted(0),
                        relative: Vec::new(),
                    },
                    name: "project".into(),
                    directory: true,
                }],
                entries: Vec::new(),
            }
            .encode()
            .expect("manifest")
        };
        // A manifest naming another operation is refused before any entry.
        let mut reader = TransferReader::new(&own);
        assert!(
            reader
                .push(&manifest(&other), &mut ManifestOnly::default())
                .await
                .is_err()
        );
        // And so is a done frame naming another operation.
        let mut reader = TransferReader::new(&own);
        reader
            .push(&manifest(&own), &mut ManifestOnly::default())
            .await
            .expect("the manifest of its own operation");
        let wrong_done = Frame::Done { op: other.clone() }.encode().expect("done");
        assert!(
            reader
                .push(&wrong_done, &mut ManifestOnly::default())
                .await
                .is_err()
        );
        // The same response with its own operation reads clean.
        let mut reader = TransferReader::new(&own);
        let mut response = manifest(&own);
        response.extend(Frame::Done { op: own.clone() }.encode().expect("done"));
        reader
            .push(&response, &mut ManifestOnly::default())
            .await
            .expect("its own operation");
        reader.finish().expect("finished");
    }

    #[tokio::test]
    async fn a_transfer_reader_accepts_only_the_manifest_it_announced() {
        use sha2::Digest as _;

        let op = new_op();
        let payload = b"hello";
        let digest: [u8; 32] = sha2::Sha256::digest(payload).into();
        let entry = TransferEntry {
            root: 0,
            path: "src/main.rs".into(),
            len: payload.len() as u64,
            modified_secs: 1_700_000_000,
            modified_nanos: 123_456_700,
            digest: digest_hex(&digest),
            directory: false,
        };
        let manifest = Frame::Manifest {
            op: op.clone(),
            roots: vec![TransferRoot {
                source: ExportSource {
                    root: ExportRoot::Mounted(0),
                    relative: Vec::new(),
                },
                name: "project".into(),
                directory: true,
            }],
            entries: vec![entry.clone()],
        };
        let mut response = manifest.encode().expect("manifest");
        response.extend(entry.frame().encode().expect("file"));
        response.extend_from_slice(payload);
        response.extend(Frame::Done { op: op.clone() }.encode().expect("done"));

        let mut reader = TransferReader::new(&op);
        let mut visitor = ManifestOnly::default();
        reader
            .push(&response, &mut visitor)
            .await
            .expect("a complete response");
        reader.finish().expect("finished");
        assert_eq!(visitor.entries, vec![entry.clone()]);

        // A file header the manifest never named is refused before a visitor sees it.
        let unplanned = TransferEntry {
            path: "src/other.rs".into(),
            ..entry.clone()
        };
        let mut response = manifest.encode().expect("manifest");
        response.extend(unplanned.frame().encode().expect("file"));
        response.extend_from_slice(payload);
        response.extend(Frame::Done { op: op.clone() }.encode().expect("done"));
        let mut reader = TransferReader::new(&op);
        assert!(
            reader
                .push(&response, &mut ManifestOnly::default())
                .await
                .is_err()
        );

        // A header that repeats a manifest path with different metadata is refused.
        let mut changed = entry.clone();
        changed.modified_nanos = changed.modified_nanos.saturating_add(1);
        let mut response = manifest.encode().expect("manifest");
        response.extend(changed.frame().encode().expect("file"));
        response.extend_from_slice(payload);
        response.extend(Frame::Done { op: op.clone() }.encode().expect("done"));
        let mut reader = TransferReader::new(&op);
        assert!(
            reader
                .push(&response, &mut ManifestOnly::default())
                .await
                .is_err()
        );

        // A manifest whose files never arrive cannot end as a complete transfer.
        let mut reader = TransferReader::new(&op);
        assert!(
            reader
                .push(
                    &manifest.encode().expect("manifest"),
                    &mut ManifestOnly::default()
                )
                .await
                .is_ok()
        );
        assert!(
            reader
                .push(
                    &Frame::Done { op: op.clone() }.encode().expect("done"),
                    &mut ManifestOnly::default()
                )
                .await
                .is_err()
        );
    }

    /// Every documented transfer size is refused where the bytes would be: an announced file over
    /// the per-file budget and an announced total over the aggregate budget are refused at the
    /// manifest, before a byte of payload is allocated or copied.
    #[tokio::test]
    async fn a_transfer_refuses_an_announced_size_past_its_budgets() {
        use sha2::Digest as _;

        let op = new_op();
        let entry = |path: String, len: u64| TransferEntry {
            root: 0,
            path,
            len,
            modified_secs: 1_700_000_000,
            modified_nanos: 0,
            digest: digest_hex(&sha2::Sha256::digest(b"x").into()),
            directory: false,
        };
        let manifest_of = |entries: Vec<TransferEntry>| {
            Frame::Manifest {
                op: op.clone(),
                roots: vec![TransferRoot {
                    source: ExportSource {
                        root: ExportRoot::Mounted(0),
                        relative: Vec::new(),
                    },
                    name: "project".into(),
                    directory: true,
                }],
                entries,
            }
            .encode()
            .expect("manifest")
        };

        let oversize = manifest_of(vec![entry(
            "big.bin".to_owned(),
            MAX_TRANSFER_FILE_BYTES + 1,
        )]);
        let mut reader = TransferReader::new(&op);
        assert!(
            reader
                .push(&oversize, &mut ManifestOnly::default())
                .await
                .is_err(),
            "an announced file over the per-file budget is refused"
        );

        let per_file = MAX_TRANSFER_FILE_BYTES;
        let too_much = (0..=MAX_TRANSFER_BYTES / per_file)
            .map(|index| entry(format!("f{index}.bin"), per_file))
            .collect();
        let mut reader = TransferReader::new(&op);
        assert!(
            reader
                .push(&manifest_of(too_much), &mut ManifestOnly::default())
                .await
                .is_err(),
            "an announced total over the aggregate budget is refused"
        );
    }

    /// Payload is read to the length its header announced and not one byte more: a response that
    /// carries past it ends in refusal rather than the extra bytes being taken for a frame.
    #[tokio::test]
    async fn a_transfer_refuses_payload_past_the_announced_length() {
        use sha2::Digest as _;

        let op = new_op();
        let payload = b"hello";
        let digest: [u8; 32] = sha2::Sha256::digest(payload).into();
        let entry = TransferEntry {
            root: 0,
            path: "src/main.rs".into(),
            len: payload.len() as u64,
            modified_secs: 1_700_000_000,
            modified_nanos: 123_456_700,
            digest: digest_hex(&digest),
            directory: false,
        };
        let manifest = Frame::Manifest {
            op: op.clone(),
            roots: vec![TransferRoot {
                source: ExportSource {
                    root: ExportRoot::Mounted(0),
                    relative: Vec::new(),
                },
                name: "project".into(),
                directory: true,
            }],
            entries: vec![entry.clone()],
        };
        let mut response = manifest.encode().expect("manifest");
        response.extend(entry.frame().encode().expect("file"));
        response.extend_from_slice(payload);
        response.extend_from_slice(b"more than announced");
        let mut reader = TransferReader::new(&op);
        reader
            .push(&response, &mut ManifestOnly::default())
            .await
            .expect("the announced length is taken whole");
        assert!(
            reader.finish().is_err(),
            "bytes past the announced length can never complete the transfer"
        );
    }

    /// A closed name's old generation cannot reach the new one: the close that freed the name
    /// stays bound to the handle it closed, and the reopened handle admits work.
    #[test]
    fn an_old_close_does_not_reach_a_reopened_handle_generation() {
        let target = pinned_target();
        let handles = Handles::default();
        let session = uuid::Uuid::from_u128(7);
        let open = |name: &str| {
            handles.open(
                Some(session),
                name,
                Handle::new(
                    Arc::clone(&target),
                    Some(session),
                    "/home/Project".into(),
                    Vec::new(),
                    Vec::new(),
                    false,
                    Permission::Workspace,
                ),
            )
        };
        let first = open("work").unwrap();
        let closed = handles.close(Some(session), "work").unwrap();
        let second = open("work").unwrap();
        assert!(
            closed.cancelled().is_cancelled(),
            "the old close binds the generation it closed"
        );
        assert!(
            !second.cancelled().is_cancelled(),
            "the reopened generation is untouched by the old close"
        );
        {
            let _outstanding = second.begin().expect("the reopened handle admits work");
            assert_eq!(second.outstanding(), 1);
        }
        drop(first);
    }
}
