//! Windows controller for a configured, confined WSL execution target.

use std::{
    ffi::OsString,
    io,
    os::windows::ffi::OsStringExt as _,
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};

use anyhow::{Context as _, Result};
use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use crate::{
    process::{self, Capture, Ended, Keep, Tree},
    subshell::{self, Target},
    text::KIB,
};

const INSTALLED: u8 = 1;
const DEPLOY: u8 = 2;
const DIAGNOSTIC_BYTES: usize = 8 * KIB;
const DIAGNOSTIC_TIMEOUT: Duration = Duration::from_millis(250);
/// Chunks the transfer parser may owe the drain before the runner is held back.
const TRANSFER_CHANNELS: usize = 8;
/// How long a finished transfer's pipes may stay open after the runner exits.
const TRANSFER_DRAIN: Duration = Duration::from_secs(10);
const BUNDLED_RUNNER: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/meka-runner"));
const BUNDLED_LOADER: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/meka-wsl-loader"));

/// Deliver one request and retain the launcher stdin as the guest's lifetime signal.
pub(crate) async fn launch(target: &Target, frame: &[u8]) -> Result<Tree> {
    let system = system_directory()?;
    let windows = system
        .parent()
        .context("cannot locate the Windows directory")?;
    let mut launcher = tokio::process::Command::new(system.join("wsl.exe"));
    launcher
        .args([
            "--distribution",
            target.distribution(),
            "--cd",
            "/",
            "--exec",
            "/usr/bin/env",
            "-i",
            "/bin/sh",
            "-c",
            BOOTSTRAP,
            "meka-wsl",
            target.runner(),
            if BUNDLED_RUNNER.is_empty() || BUNDLED_LOADER.is_empty() {
                "no-bundle"
            } else {
                "x86_64"
            },
            &BUNDLED_LOADER.len().to_string(),
        ])
        .current_dir(&system)
        .env_clear()
        .env("SystemRoot", windows)
        // Match the guest streams even when the launcher itself reports a startup error.
        .env("WSL_UTF8", "1")
        .creation_flags(windows_sys::Win32::System::Threading::CREATE_NO_WINDOW)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut tree = process::spawn_tree_required(&mut launcher)
        .context("cannot start the managed WSL launcher")?;
    let marker = match tree.piped_stdout()?.read_u8().await {
        Ok(marker) => marker,
        Err(error) => return Err(launch_failed(tree, &[], error).await),
    };
    match marker {
        INSTALLED => (),
        DEPLOY if !BUNDLED_RUNNER.is_empty() && !BUNDLED_LOADER.is_empty() => {
            if let Err(error) =
                send_payloads(tree.lease_input()?, BUNDLED_LOADER, BUNDLED_RUNNER).await
            {
                return Err(launch_failed(tree, &[], error).await);
            }
        }
        _ => {
            return Err(launch_failed(
                tree,
                &[marker],
                io::Error::other("unexpected WSL runner setup response"),
            )
            .await);
        }
    }
    let expected = subshell::hello();
    let mut hello = vec![0; expected.len()];
    let mut received = 0;
    while let Some(remaining) = hello.get_mut(received..).filter(|bytes| !bytes.is_empty()) {
        match tree.piped_stdout()?.read(remaining).await {
            Ok(0) => {
                let error = io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "incompatible meka-runner protocol (no complete handshake); use the matching Linux Meka build",
                );
                return Err(
                    launch_failed(tree, hello.get(..received).unwrap_or_default(), error).await,
                );
            }
            Ok(count) => received += count,
            Err(error) => return Err(launch_failed(tree, &[], error).await),
        }
    }
    if hello != expected.as_bytes() {
        let error = io::Error::other(
            "incompatible meka-runner protocol; use the matching Linux Meka build",
        );
        return Err(launch_failed(tree, &hello, error).await);
    }
    if let Err(error) = tree.lease_input()?.write_all(frame).await {
        return Err(launch_failed(tree, &[], error).await);
    }
    Ok(tree)
}

/// How a transfer response ended.
pub(crate) enum Collected {
    /// The response was complete and consistent.
    Done,
    /// The stop token ended the run before the response was complete.
    Stopped,
}

/// One transfer's stdout chunks, handed to the parser as they are read. The drain waits for each
/// send before reading on, so a slow parser slows the runner instead of queueing its output.
struct TransferSink {
    chunks: tokio::sync::mpsc::Sender<Vec<u8>>,
}

#[async_trait::async_trait]
impl process::Sink for TransferSink {
    async fn receive(&self, stream: process::Stream, chunk: &[u8]) {
        if stream != process::Stream::Stdout {
            return;
        }
        if self.chunks.send(chunk.to_vec()).await.is_err() {
            tracing::debug!("transfer reader closed before the runner's stdout");
        }
    }
}

/// Read one transfer response from a launched runner to its end, feeding `visitor` as frames and
/// file bytes complete. A protocol error or a visitor refusal is returned at once, dropping the run
/// future and with it the runner's tree.
pub(crate) async fn collect_transfer(
    tree: Tree,
    op: &str,
    timeout: Duration,
    stop: Option<process::Stop<'_>>,
    visitor: &mut dyn subshell::TransferVisitor,
) -> Result<Collected> {
    let (chunks, mut receiver) = tokio::sync::mpsc::channel::<Vec<u8>>(TRANSFER_CHANNELS);
    let capture = Capture {
        stdout: Keep::Head(0),
        stderr: Keep::Head(DIAGNOSTIC_BYTES),
        sink: Some(std::sync::Arc::new(TransferSink { chunks })),
    };
    let run = process::run(tree, capture, Some(timeout), stop, TRANSFER_DRAIN);
    tokio::pin!(run);
    let mut reader = subshell::TransferReader::new(op);
    let finished = loop {
        tokio::select! {
            biased;
            finished = &mut run => break finished?,
            chunk = receiver.recv() => match chunk {
                Some(chunk) => reader.push(&chunk, visitor).await.map_err(|error| {
                    anyhow::anyhow!("{error:#}")
                })?,
                None => break (&mut run).await?,
            },
        }
    };
    if let Ended::Stopped = finished.ended {
        return Ok(Collected::Stopped);
    }
    // Decide the terminal outcome before draining anything still queued. A runner that exited
    // nonzero, timed out or hit the diagnostic bound did not finish the transfer, and a frame left
    // in the channel behind that failure must not reach the visitor: the visitor publishes files
    // as their last byte arrives, so draining first would commit data from a transfer that already
    // failed.
    match finished.ended {
        Ended::Exited(status) if status.success() => {}
        Ended::Exited(status) => {
            let stderr = String::from_utf8_lossy(&finished.drained.stderr.bytes);
            let stderr = stderr.trim();
            return Err(if stderr.is_empty() {
                anyhow::anyhow!("the runner exited {status} during the transfer")
            } else {
                anyhow::anyhow!("the runner exited {status} during the transfer: {stderr}")
            });
        }
        Ended::TimedOut => {
            return Err(anyhow::anyhow!(
                "the transfer timed out after {}ms",
                timeout.as_millis()
            ));
        }
        Ended::OutputBound => {
            return Err(anyhow::anyhow!(
                "the transfer's diagnostics reached their bound"
            ));
        }
        Ended::Stopped => return Ok(Collected::Stopped),
    }
    // The drains finish before the run returns, but their last chunks may still be queued. Only a
    // successful terminal sequence reaches this point.
    while let Some(chunk) = receiver.recv().await {
        reader
            .push(&chunk, visitor)
            .await
            .map_err(|error| anyhow::anyhow!("{error:#}"))?;
    }
    reader.finish()?;
    visitor
        .complete()
        .await
        .map_err(|error| anyhow::anyhow!("{error:#}"))?;
    Ok(Collected::Done)
}

async fn send_payloads(
    input: &mut (impl tokio::io::AsyncWrite + Unpin),
    loader: &[u8],
    runner: &[u8],
) -> io::Result<()> {
    input.write_all(loader).await?;
    input
        .write_all(&(runner.len() as u64).to_le_bytes())
        .await?;
    input.write_all(Sha256::digest(runner).as_slice()).await?;
    input.write_all(runner).await
}

async fn launch_failed(tree: Tree, prefix: &[u8], cause: io::Error) -> anyhow::Error {
    // Preserve the launcher's reason (a missing distro, a refused install, or a broken remote
    // pipe). Do not wait on an unrecognized process that is still trying to read the request.
    let capture = Capture {
        stdout: Keep::Head(DIAGNOSTIC_BYTES),
        stderr: Keep::Head(DIAGNOSTIC_BYTES),
        sink: None,
    };
    let result = process::run(
        tree,
        capture,
        Some(DIAGNOSTIC_TIMEOUT),
        None,
        DIAGNOSTIC_TIMEOUT,
    )
    .await;
    let Ok(result) = result else {
        return anyhow::Error::new(cause).context("cannot start meka-runner in WSL");
    };
    let mut stdout = prefix.to_vec();
    stdout.extend(result.drained.stdout.bytes);
    let stdout = String::from_utf8_lossy(&stdout);
    let stderr = String::from_utf8_lossy(&result.drained.stderr.bytes);
    let reason = [stderr.trim(), stdout.trim()]
        .into_iter()
        .filter(|text| !text.is_empty())
        .collect::<Vec<_>>()
        .join("\n");
    if reason.is_empty() {
        anyhow::Error::new(cause).context("cannot start meka-runner in WSL")
    } else if let Ended::Exited(status) = result.ended {
        anyhow::anyhow!("cannot start meka-runner in WSL ({status}; {cause}): {reason}")
    } else {
        anyhow::anyhow!("cannot start meka-runner in WSL ({cause}): {reason}")
    }
}

pub(crate) fn system_directory() -> io::Result<PathBuf> {
    use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;

    let mut buffer = [0u16; 260];
    // SAFETY: the buffer is writable for the stated number of wide characters.
    let units = unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) } as usize;
    if units == 0 {
        return Err(io::Error::last_os_error());
    }
    let path = buffer
        .get(..units)
        .filter(|_| units < buffer.len())
        .ok_or_else(|| io::Error::other("Windows system directory is too long"))?;
    let path = PathBuf::from(OsString::from_wide(path));
    if !Path::is_absolute(&path) {
        return Err(io::Error::other("Windows system directory is not absolute"));
    }
    Ok(path)
}

// An installed runner must not be mutable by the guest account. An absent path is the only
// case that selects the bundled runner. Neither the command nor its grants enter this script.
const BOOTSTRAP: &str = r#"
set -efu
runner=$1
bundle=$2
loader_bytes=$3
fail() { printf 'meka: %s\n' "$1" >&2; exit 126; }
refuse() {
    fail 'the installed meka-runner must be a root-owned executable on the distro root ext filesystem, with no symlinks, setuid/setgid bits on the runner, or group/other-writable path components'
}
trusted() {
    facts=$(/usr/bin/stat -c '%u:%a:%m' -- "$1") || refuse
    case $facts in 0:*:/) ;; *) refuse ;; esac
    mode=${facts#0:}
    mode=${mode%:/}
    [ "$((0$mode & 022))" = 0 ] || refuse
}
[ "$(/usr/bin/stat -f -c '%t' -- /)" = ef53 ] || fail 'managed WSL requires a Linux-native ext root filesystem'
trusted /
prefix=
IFS=/
for part in ${runner#/}; do
    prefix=$prefix/$part
    [ ! -L "$prefix" ] || refuse
    if [ ! -e "$prefix" ]; then
        [ "$bundle" != no-bundle ] || fail 'no installed meka-runner and this Windows build has no bundled runner'
        [ "$(/usr/bin/uname -m)" = "$bundle" ] || fail 'no bundled meka-runner for this guest architecture; install one in the distro'
        case $loader_bytes in ''|*[!0-9]*) fail 'invalid deployment loader length' ;; esac
        [ "$loader_bytes" -gt 0 ] && [ "$loader_bytes" -le 16777216 ] || fail 'invalid deployment loader length'
        [ -d /proc/self/fd ] || fail 'managed WSL deployment requires procfs at /proc'
        # Stage the loader where the file has no name at execution time: an exclusive private
        # file, unlinked before its descriptor is executed through procfs. The descriptor is
        # read-only; a writable handle makes the kernel refuse the execution. The loader is as
        # trusted as this bootstrap; both arrive over the launcher channel.
        umask 077
        staged=$(/usr/bin/mktemp /tmp/meka-wsl-loader.XXXXXX) || fail 'cannot stage the deployment loader'
        trap '/usr/bin/rm -f -- "$staged"' 0
        printf '\002'
        /usr/bin/head -c "$loader_bytes" > "$staged" || fail 'host disconnected during loader deployment'
        [ "$(/usr/bin/wc -c < "$staged")" = "$loader_bytes" ] || fail 'host disconnected during loader deployment'
        /usr/bin/chmod 700 -- "$staged" || fail 'cannot stage the deployment loader'
        exec 3< "$staged"
        /usr/bin/rm -f -- "$staged"
        exec /proc/self/fd/3
    fi
    trusted "$prefix"
    if [ "$prefix" != "$runner" ]; then
        [ -d "$prefix" ] && [ -x "$prefix" ] || refuse
    fi
done
[ "$prefix" = "$runner" ] && [ -f "$runner" ] && [ -x "$runner" ] \
    && [ "$((0$mode & 06000))" = 0 ] || refuse
printf '\001'
exec "$runner" subshell-runner
"#;
