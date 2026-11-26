//! One host-owned shell command in a Linux guest. The stdin pipe is the host's lease, not the
//! shell's input. Bubblewrap and Landlock must both succeed before the script is interpreted.

use std::{
    ffi::CString,
    fs::File,
    io::{self, Write as _},
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
        unix::{ffi::OsStrExt, fs::FileTypeExt as _, process::ExitStatusExt},
    },
    path::{Component, Path, PathBuf},
    process::Stdio,
    time::Duration,
};

use anyhow::{Context as _, Result, bail, ensure};
use tokio::{
    io::{AsyncBufReadExt as _, AsyncReadExt as _, BufReader},
    net::unix::pipe::Receiver,
};

use crate::{
    permission::Permission,
    subshell::{
        self, MountRoot, REQUEST_BYTES, Request, SCRATCH_ID_BYTES, SCRATCH_LEASE, SCRATCH_ROOT,
        Scratch,
    },
};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const SETUP_READY: u8 = 1;
const SETUP_STARTED: u8 = 2;
const BUBBLEWRAP: &str = "/usr/bin/bwrap";
const SHELL: &str = "/bin/sh";
const WORKING_DIRECTORY: &str = "/workspace";
const REFERENCES: &str = "/references";
const TEMPORARY_DIRECTORY: &str = "/tmp";
const TEMPORARY_BYTES: usize = 256 * crate::text::MIB;
const RUNTIME_DIRECTORIES: &[&str] = &["/usr", "/bin", "/sbin", "/lib", "/lib64"];
const LOADER_CACHE: &str = "/etc/ld.so.cache";
const MASKED_RUNTIME_DIRECTORIES: &[&str] = &["/usr/lib/wsl", "/usr/lib/modules", "/usr/src"];
/// The runner's exit codes travel on the wire contract: the host reads them off the launcher to
/// reconcile its status with the outcome the runner reported.
const RUNNER_ERROR: i32 = subshell::RUNNER_ERROR;
const TIMED_OUT: i32 = subshell::RUNNER_TIMED_OUT;
const CANCELED: i32 = subshell::RUNNER_CANCELED;

fn mark_extra_close_on_exec() -> io::Result<()> {
    // SAFETY: this only changes descriptor flags. Stdio is the only implicit inheritance.
    if unsafe {
        libc::syscall(
            libc::SYS_close_range,
            3u32,
            u32::MAX,
            libc::CLOSE_RANGE_CLOEXEC,
        )
    } == -1
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn lease() -> Result<Receiver> {
    // SAFETY: `fcntl` returns a new owned descriptor, or an error without allocating one.
    let descriptor = unsafe { libc::fcntl(libc::STDIN_FILENO, libc::F_DUPFD_CLOEXEC, 3) };
    if descriptor == -1 {
        return Err(io::Error::last_os_error()).context("cannot duplicate the host lease");
    }
    // SAFETY: `descriptor` is the successful duplicate above and is not owned elsewhere.
    let file = unsafe { File::from_raw_fd(descriptor) };
    Receiver::from_file(file).context("the subshell runner requires a host pipe on stdin")
}

async fn read_request(lease: &mut (impl tokio::io::AsyncBufRead + Unpin)) -> Result<Request> {
    let mut frame = Vec::new();
    let bytes = tokio::time::timeout(
        REQUEST_TIMEOUT,
        lease
            .take(REQUEST_BYTES as u64 + 1)
            .read_until(b'\n', &mut frame),
    )
    .await
    .context("the host did not send a subshell request in time")??;
    ensure!(
        bytes <= REQUEST_BYTES && frame.last() == Some(&b'\n'),
        "missing or oversized subshell request"
    );
    let request: Request = serde_json::from_slice(&frame).context("invalid subshell request")?;
    request.validate()?;
    Ok(request)
}

async fn serve() -> Result<i32> {
    let mut lease = BufReader::new(lease()?);
    std::io::stdout().write_all(subshell::hello().as_bytes())?;
    let request = read_request(&mut lease).await?;
    let deadline = tokio::time::Instant::now() + request.timeout();
    if let Some(transfer) = &request.transfer {
        // An upload's manifest and bytes follow the request on this pipe, so data there is the
        // transfer arriving. Every other request keeps the pipe as its lease alone.
        if !matches!(transfer, subshell::Transfer::Upload) {
            // A valid request does not transfer a lease after the host has already disconnected.
            match futures::poll!(std::pin::pin!(lease.fill_buf())) {
                std::task::Poll::Ready(Ok(_)) => return Ok(CANCELED),
                std::task::Poll::Ready(Err(error)) => return Err(error.into()),
                std::task::Poll::Pending => {}
            }
        }
        return serve_transfer(&mut lease, &request, transfer, deadline).await;
    }
    // A valid request does not transfer a lease after the host has already disconnected.
    match futures::poll!(std::pin::pin!(lease.fill_buf())) {
        std::task::Poll::Ready(Ok(_)) => return Ok(CANCELED),
        std::task::Poll::Ready(Err(error)) => return Err(error.into()),
        std::task::Poll::Pending => {}
    }
    // The workspace stays held for the whole command: the descriptors are this run's active lease
    // on it, so the reaper and any removal see it as in use instead of as an expired directory.
    let workspace = match &request.scratch {
        Some(scratch) => Some(prepare_scratch_workspace(scratch, ScratchUse::Execution)?),
        None => None,
    };
    let (mut command, stdout, stderr, prepared, start) = spawn(&request)?;
    // The guest proves its sandbox and then asks the host for the one line that permits the start.
    // Setup can outlast both the lease and the deadline, and it runs inside Bubblewrap, so the
    // checks that matter happen here, before the permit, rather than only after the shell has
    // already run.
    // SAFETY: `prepared` is the read end of the pipe this function owns, no other value holds it,
    // and it stays open until the `AsyncFd` is dropped.
    let prepared = unsafe {
        tokio::io::unix::AsyncFd::register_with_interest(prepared, tokio::io::Interest::READABLE)
    }
    .map_err(|error| anyhow::anyhow!("cannot watch the guest readiness pipe: {error:?}"))?;
    let setup = await_marker(&prepared, &mut lease, deadline, SETUP_READY).await;
    let setup = match setup {
        Ok(setup) => setup,
        Err(error) => {
            command.kill_at_once().await;
            return Err(error);
        }
    };
    match setup {
        Setup::Canceled => {
            command.kill_at_once().await;
            return Ok(CANCELED);
        }
        Setup::TimedOut => {
            command.kill_at_once().await;
            return Ok(TIMED_OUT);
        }
        Setup::Ready => {}
    }
    // The sandbox is proved; the host learns that and decides whether the command may exist. The
    // permit line carries the remaining budget of the one deadline the host measures from the
    // launch, so the guest spends what the launch left rather than a second full budget.
    if let Err(error) = write_frame(&subshell::Frame::Ready {
        op: request.op.clone(),
    }) {
        eprintln!("meka subshell-runner: cannot report readiness: {error:#}");
        command.kill_at_once().await;
        return Ok(CANCELED);
    }
    let deadline = match await_permit(&mut lease, deadline).await {
        Ok(Some(budget)) => deadline.min(tokio::time::Instant::now() + budget),
        Ok(None) => {
            command.kill_at_once().await;
            return Ok(CANCELED);
        }
        Err(Permit::TimedOut) => {
            command.kill_at_once().await;
            return Ok(TIMED_OUT);
        }
        Err(Permit::Invalid(error)) => {
            command.kill_at_once().await;
            return Err(error);
        }
    };
    // The host permitted the start. The guest re-checks its lease and deadline once more before
    // the namespace process can exist: a withdrawal between the permit and here denies the start.
    match futures::poll!(std::pin::pin!(lease.fill_buf())) {
        std::task::Poll::Ready(Ok(_)) => {
            command.kill_at_once().await;
            return Ok(CANCELED);
        }
        std::task::Poll::Ready(Err(error)) => {
            command.kill_at_once().await;
            return Err(error.into());
        }
        std::task::Poll::Pending => {}
    }
    if tokio::time::Instant::now() >= deadline {
        command.kill_at_once().await;
        return Ok(TIMED_OUT);
    }
    let mut start = File::from(start);
    if let Err(error) = start.write_all(&[SETUP_READY]) {
        command.kill_at_once().await;
        return Err(error).context("cannot start the guest sandbox");
    }
    drop(start);
    // The acknowledgement that a permit became an observed start: the inner runner reports the
    // fork of the namespace process, so `started` says the shell exists, not that it was allowed.
    // No terminal frames are owed before it: a stream that ends at `ready` says the command never
    // started, which is the whole of the truth the host needs there.
    match await_marker(&prepared, &mut lease, deadline, SETUP_STARTED).await {
        Ok(Setup::Ready) => {}
        Ok(Setup::Canceled) => {
            drop(prepared);
            command.kill_at_once().await;
            return Ok(CANCELED);
        }
        Ok(Setup::TimedOut) => {
            drop(prepared);
            command.kill_at_once().await;
            return Ok(TIMED_OUT);
        }
        Err(error) => {
            command.kill_at_once().await;
            return Err(error);
        }
    }
    drop(prepared);
    if let Err(error) = write_frame(&subshell::Frame::Started {
        op: request.op.clone(),
    }) {
        eprintln!("meka subshell-runner: cannot report the start: {error:#}");
        command.kill_at_once().await;
        return Ok(CANCELED);
    }
    let (sender, receiver) = tokio::sync::mpsc::channel(COMMAND_FRAME_QUEUE);
    let mut out = tokio::spawn(forward_output(
        stdout,
        subshell::OutputStream::Stdout,
        sender.clone(),
    ));
    let mut err = tokio::spawn(forward_output(
        stderr,
        subshell::OutputStream::Stderr,
        sender.clone(),
    ));
    drop(sender);
    let mut writer = tokio::spawn(write_output_frames(receiver));
    enum End {
        Lease,
        Deadline,
        Status(std::process::ExitStatus),
    }
    let end = tokio::select! {
        biased;
        result = lease.fill_buf() => {
            result?;
            End::Lease
        }
        () = tokio::time::sleep_until(deadline) => End::Deadline,
        status = command.wait() => End::Status(status?),
    };
    // The namespace is ended and reaped here whichever way the run ended. The terminal frames
    // report what that reap observed: a cancellation or a timeout tears the namespace down and the
    // reaped outcome travels in `stopped`, so the host's teardown proof is the guest's own record
    // and never the launcher's end. A reap the kernel did not confirm gets no `stopped` frame, and
    // the host reads the missing proof as unconfirmed.
    let reaped = if matches!(end, End::Status(_)) {
        None
    } else {
        Some(command.kill_at_once_confirmed().await)
    };
    let drained = tokio::time::timeout(COMMAND_DRAIN, async {
        (&mut out).await.context("the output reader panicked")??;
        (&mut err).await.context("the error reader panicked")??;
        Ok::<(), anyhow::Error>(())
    })
    .await;
    if !matches!(drained, Ok(Ok(()))) {
        out.abort();
        err.abort();
    }
    if let Ok(joined) = tokio::time::timeout(COMMAND_DRAIN, &mut writer).await {
        joined.context("the output writer panicked")??;
    } else {
        writer.abort();
    }
    let status = match (&end, reaped) {
        (End::Status(status), _) => Some(*status),
        (_, Some(Some(status))) => Some(status),
        (..) => None,
    };
    let Some(status) = status else {
        // Without a kernel-confirmed reap there is no outcome to report; the missing terminal
        // proof is the honest answer and the host reads it as unconfirmed teardown.
        return Ok(match end {
            End::Deadline => TIMED_OUT,
            _ => CANCELED,
        });
    };
    let code = status
        .code()
        .unwrap_or_else(|| 128 + status.signal().unwrap_or(0));
    if let Err(error) = write_frame(&subshell::Frame::Stopped {
        op: request.op.clone(),
        code,
    }) {
        eprintln!("meka subshell-runner: cannot report the reaped outcome: {error:#}");
    }
    if let Err(error) = write_frame(&subshell::Frame::Done {
        op: request.op.clone(),
    }) {
        eprintln!("meka subshell-runner: cannot report the reaped outcome: {error:#}");
    }
    drop(workspace);
    Ok(match end {
        End::Deadline => TIMED_OUT,
        End::Lease => CANCELED,
        End::Status(_) => code,
    })
}

/// How many command output chunks may wait for the writer before the readers slow down. The bound
/// is what keeps a command that prints faster than the host drains from growing the guest's memory.
const COMMAND_FRAME_QUEUE: usize = 8;
/// How long the guest waits for a command's pipes to reach EOF after it has been reaped, and for
/// the frames already read to be written. A grandchild that inherited a pipe cannot hold the
/// runner past this.
const COMMAND_DRAIN: Duration = Duration::from_secs(5);

/// Read one command stream to its end and hand every chunk to the frame writer in arrival order.
async fn forward_output(
    mut reader: impl tokio::io::AsyncRead + Unpin,
    stream: subshell::OutputStream,
    sender: tokio::sync::mpsc::Sender<(subshell::OutputStream, Vec<u8>)>,
) -> Result<()> {
    use tokio::io::AsyncReadExt as _;

    let mut buffer = vec![0u8; subshell::FRAME_BYTES];
    loop {
        let read = reader.read(&mut buffer).await?;
        if read == 0 {
            return Ok(());
        }
        let chunk = buffer.get(..read).unwrap_or_default().to_vec();
        if sender.send((stream, chunk)).await.is_err() {
            return Err(anyhow::anyhow!("the host stopped reading command output"));
        }
    }
}

/// Write the command's output chunks as framed records, one writer so the frames cannot interleave.
async fn write_output_frames(
    mut receiver: tokio::sync::mpsc::Receiver<(subshell::OutputStream, Vec<u8>)>,
) -> Result<()> {
    while let Some((stream, chunk)) = receiver.recv().await {
        let mut stdout = io::stdout().lock();
        let mut frame = serde_json::to_vec(&subshell::Frame::Output {
            stream,
            len: chunk.len() as u64,
        })?;
        frame.push(b'\n');
        stdout.write_all(&frame)?;
        stdout.write_all(&chunk)?;
        stdout.flush()?;
    }
    Ok(())
}

/// What the guest reported before the host allowed it to start.
enum Setup {
    Ready,
    Canceled,
    TimedOut,
}

/// Wait for one marker byte from the sandbox while watching the host lease and the deadline.
///
/// The pipe is read through `AsyncFd` rather than a blocking read so a lease that ends during a
/// slow sandbox setup is answered by killing the command instead of waiting for Bubblewrap to
/// finish. A notice that is not `expected` is a protocol failure, not permission to start.
async fn await_marker(
    prepared: &tokio::io::unix::AsyncFd<OwnedFd>,
    lease: &mut (impl tokio::io::AsyncBufRead + Unpin),
    deadline: tokio::time::Instant,
    expected: u8,
) -> Result<Setup> {
    loop {
        tokio::select! {
            biased;
            result = lease.fill_buf() => {
                result?;
                return Ok(Setup::Canceled);
            }
            () = tokio::time::sleep_until(deadline) => return Ok(Setup::TimedOut),
            ready = prepared.readable() => {
                let mut ready = ready?;
                let marker = ready.try_io(|inner| {
                    let mut marker = [0u8];
                    // SAFETY: the descriptor is open and the buffer is one initialized byte. A
                    // nonblocking pipe returns EAGAIN, which `try_io` reports as would-block.
                    let read = unsafe {
                        libc::read(inner.as_raw_fd(), marker.as_mut_ptr().cast(), 1)
                    };
                    if read == 0 {
                        Err(io::Error::from(io::ErrorKind::UnexpectedEof))
                    } else if read < 0 {
                        Err(io::Error::last_os_error())
                    } else {
                        Ok(marker[0])
                    }
                });
                match marker {
                    Ok(Ok(marker)) if marker == expected => return Ok(Setup::Ready),
                    Ok(Ok(other)) => bail!("unexpected guest setup marker {other}"),
                    Ok(Err(error)) if error.kind() == io::ErrorKind::WouldBlock => continue,
                    Ok(Err(error)) => {
                        return Err(error).context("the guest sandbox did not report readiness")
                    }
                    Err(_would_block) => continue,
                }
            }
        }
    }
}

/// What a permit wait ended in when it did not permit anything.
enum Permit {
    /// The deadline passed before a permit arrived.
    TimedOut,
    /// The host wrote something that is not one permit line: a protocol failure, not a start.
    Invalid(anyhow::Error),
}

/// Read the host's one permit line while watching the deadline. The line is the remaining budget
/// of the call; its arrival is the authorization, and a hangup before it is the host withdrawing.
/// Anything readable after this read is a withdrawal again, since the permit is the only thing the
/// host ever writes after the request.
async fn await_permit(
    lease: &mut (impl tokio::io::AsyncBufRead + Unpin),
    deadline: tokio::time::Instant,
) -> std::result::Result<Option<Duration>, Permit> {
    let mut line = Vec::new();
    let read = tokio::time::timeout_at(deadline, async {
        lease
            .take(subshell::PERMIT_BYTES as u64 + 1)
            .read_until(b'\n', &mut line)
            .await
    })
    .await;
    let read = match read {
        Ok(read) => read.map_err(|error| {
            Permit::Invalid(anyhow::Error::new(error).context("cannot read the start permit"))
        })?,
        Err(_elapsed) => return Err(Permit::TimedOut),
    };
    if read == 0 {
        return Ok(None);
    }
    match subshell::parse_permit(&line) {
        Some(budget) => Ok(Some(budget)),
        None => Err(Permit::Invalid(anyhow::anyhow!(
            "the host wrote something that is not one start permit"
        ))),
    }
}

/// Serve a single request without opening any installation state or loading user shell profiles.
pub(crate) fn run() -> i32 {
    let result = (|| {
        // A distro's default user may be root. This backend never enters as a privileged user.
        ensure!(
            unsafe { libc::getuid() } != 0 && unsafe { libc::geteuid() } != 0,
            "the subshell runner must run as a non-root guest user"
        );
        // An inherited terminal can make Bubblewrap bind the host console into /dev. The host
        // must drain streams it owns, not hand the guest a terminal or an open socket.
        for descriptor in ["/proc/self/fd/1", "/proc/self/fd/2"] {
            ensure!(
                std::fs::metadata(descriptor)?.file_type().is_fifo(),
                "the subshell runner requires host pipes on stdout and stderr"
            );
        }
        mark_extra_close_on_exec()?;
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(serve())
    })();
    match result {
        Ok(status) => status,
        Err(error) => {
            eprintln!("meka subshell-runner: {error:#}");
            RUNNER_ERROR
        }
    }
}

struct Mount {
    source: File,
    destination: PathBuf,
    writable: bool,
}

/// A drive mount the kernel knows about: the Windows root it serves and where the guest sees it.
/// The translation from a Windows path to a guest path is read from the kernel's own mount table,
/// never assumed from a fixed mount point such as `/mnt/c`.
struct DriveMount {
    windows_root: String,
    point: String,
}

/// Parse `/proc/self/mounts` into the drive mounts it describes. A drive mount is a `9p` mount
/// whose options carry `aname=drvfs` and `path=<windows-root>`. The mount point is unescaped from
/// the octal escapes the kernel uses for bytes a plain field cannot carry; the `path=` value is
/// raw as the options field carries it.
fn parse_mounts(text: &str) -> Vec<DriveMount> {
    let mut drives = Vec::new();
    for line in text.lines() {
        let mut fields = line.split_ascii_whitespace();
        let _source = fields.next();
        let Some(point) = fields.next() else {
            continue;
        };
        let Some(filesystem) = fields.next() else {
            continue;
        };
        let Some(options) = fields.next() else {
            continue;
        };
        if filesystem != "9p" {
            continue;
        }
        let is_drvfs = options
            .split([',', ';'])
            .any(|option| option == "aname=drvfs");
        if !is_drvfs {
            continue;
        }
        let Some(path) = options
            .split([',', ';'])
            .find_map(|option| option.strip_prefix("path="))
        else {
            continue;
        };
        drives.push(DriveMount {
            windows_root: path.to_owned(),
            point: unescape_octal(point),
        });
    }
    drives
}

/// Decode the octal escapes `/proc/self/mounts` uses for bytes a plain field cannot carry, such
/// as a space in a directory name.
fn unescape_octal(text: &str) -> String {
    let mut result = String::with_capacity(text.len());
    let mut chars = text.chars();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            result.push(ch);
            continue;
        }
        let digits: String = chars.by_ref().take(3).collect();
        if digits.len() == 3
            && let Ok(byte) = u8::from_str_radix(&digits, 8)
        {
            result.push(byte as char);
            continue;
        }
        result.push('\\');
        result.push_str(&digits);
    }
    result
}

fn overlaps(left: &Path, right: &Path) -> bool {
    left.starts_with(right) || right.starts_with(left)
}

fn open_guest_directory(path: &Path) -> Result<File> {
    use std::os::unix::fs::OpenOptionsExt as _;

    let path_text = path
        .to_str()
        .context("a subshell directory must be Unicode")?;
    ensure!(
        path.is_absolute()
            && path != Path::new("/")
            && path
                .components()
                .all(|part| matches!(part, Component::RootDir | Component::Normal(_)))
            && !path_text.split('/').any(|part| matches!(part, "." | ".."))
            && !path_text.chars().any(char::is_control),
        "invalid subshell directory: {}",
        path.display()
    );
    let canonical: PathBuf = path.components().collect();
    ensure!(
        !crate::workspace::is_system_root(&canonical),
        "not a subshell workspace directory: {}",
        path.display()
    );
    for restricted in RUNTIME_DIRECTORIES
        .iter()
        .copied()
        .chain(["/etc", "/dev", "/proc", "/sys", "/run", "/mnt", "/init"])
    {
        ensure!(
            !overlaps(path, Path::new(restricted)),
            "not a subshell workspace directory: {}",
            path.display()
        );
    }
    let runner = std::fs::read_link("/proc/self/exe").context("cannot locate the guest runner")?;
    ensure!(
        !runner.starts_with(path)
            && !crate::workspace::private_directories()
                .iter()
                .any(|private| overlaps(path, private)),
        "the subshell directory overlaps Meka's installation: {}",
        path.display()
    );

    // Refuse mount crossings as well as symlinks: an ext4 bind can otherwise alias another root
    // while keeping its new name and its filesystem type. Mount the opened inode, not its name.
    let root = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_PATH | libc::O_NOFOLLOW)
        .open("/")?;
    let relative = CString::new(canonical.strip_prefix("/")?.as_os_str().as_bytes())?;
    // SAFETY: an all-zero open_how sets no flags and is a valid extensible syscall argument.
    let mut how: libc::open_how = unsafe { std::mem::zeroed() };
    how.flags = (libc::O_DIRECTORY | libc::O_PATH | libc::O_CLOEXEC) as u64;
    how.resolve = libc::RESOLVE_BENEATH | libc::RESOLVE_NO_SYMLINKS | libc::RESOLVE_NO_XDEV;
    // SAFETY: the path and open_how point to initialized objects and the root fd is open.
    let descriptor = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            root.as_raw_fd(),
            relative.as_ptr(),
            &raw const how,
            std::mem::size_of_val(&how),
        )
    };
    if descriptor == -1 {
        return Err(io::Error::last_os_error())
            .with_context(|| format!("cannot open subshell directory {}", path.display()));
    }
    // SAFETY: a successful openat2 returns an unowned descriptor (a nonnegative int).
    let directory = unsafe { File::from_raw_fd(descriptor as libc::c_int) };
    let mut status = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: `fstatfs` initializes the output on success and takes an open descriptor.
    if unsafe { libc::fstatfs(directory.as_raw_fd(), status.as_mut_ptr()) } == -1 {
        return Err(io::Error::last_os_error()).context("cannot identify the subshell filesystem");
    }
    // SAFETY: `fstatfs` succeeded above.
    let status = unsafe { status.assume_init() };
    ensure!(
        // `statfs::f_type` is signed on glibc and unsigned on some musl targets.
        status.f_type == 0xef53,
        "subshell roots must be on a Linux-native ext filesystem: {}",
        path.display()
    );
    ensure!(
        std::fs::read_link(format!("/proc/self/fd/{}", directory.as_raw_fd()))? == canonical,
        "the subshell directory changed while opening: {}",
        path.display()
    );
    Ok(directory)
}

/// Resolve a Windows root to the guest path where the kernel has mounted it. The translation reads
/// the kernel's own mount table: the most specific `aname=drvfs` mount whose `path=` is at or
/// above the target wins, and the remaining components are joined beneath its mount point. A
/// spelling the mount table does not cover is refused rather than guessed.
fn resolve_windows_guest_path(mounts_text: &str, windows: &str) -> Result<(String, PathBuf)> {
    let (drive, components) = subshell::windows_components(windows)
        .ok_or_else(|| anyhow::anyhow!("invalid Windows path: {windows:?}"))?;
    let drives = parse_mounts(mounts_text);
    let mut best: Option<(usize, &DriveMount, Vec<&str>)> = None;
    for drive_mount in &drives {
        let (mnt_drive, mnt_components) =
            match subshell::windows_components(&drive_mount.windows_root) {
                Some(parts) => parts,
                None => continue,
            };
        if !mnt_drive.eq_ignore_ascii_case(&drive) {
            continue;
        }
        if mnt_components.len() > components.len() {
            continue;
        }
        let prefix_matches = mnt_components
            .iter()
            .zip(&components)
            .all(|(a, b)| a.eq_ignore_ascii_case(b));
        if !prefix_matches {
            continue;
        }
        if best
            .as_ref()
            .is_none_or(|(len, ..)| mnt_components.len() > *len)
        {
            let Some(remaining) = components.get(mnt_components.len()..) else {
                continue;
            };
            best = Some((mnt_components.len(), drive_mount, remaining.to_vec()));
        }
    }
    let (_, drive_mount, remaining) = best.ok_or_else(|| {
        anyhow::anyhow!("the Windows directory {windows:?} is not mounted into this guest")
    })?;
    let mut guest_path = PathBuf::from(&drive_mount.point);
    for part in remaining {
        guest_path.push(part);
    }
    Ok((drive_mount.point.clone(), guest_path))
}

/// Open a Windows-backed mount: resolve the guest view from the kernel's mount table, open the
/// directory without crossing symlinks or filesystems, and prove the directory holds this
/// request's identity proof before the descriptor is trusted. The proof is removed once verified;
/// the host removes it again when the call is done, so each side tolerates the other having
/// cleaned up first.
fn open_windows_directory(root: &subshell::WindowsRoot) -> Result<(File, PathBuf)> {
    use std::os::unix::fs::OpenOptionsExt as _;

    ensure!(
        subshell::is_proof_name(&root.proof),
        "invalid Windows mount proof name"
    );
    let mounts_text = std::fs::read_to_string("/proc/self/mounts")
        .context("cannot read the guest mount table")?;
    let (point, guest_path) = resolve_windows_guest_path(&mounts_text, &root.windows)?;
    let canonical: PathBuf = guest_path.components().collect();
    ensure!(
        !crate::workspace::is_system_root(&canonical),
        "not a subshell workspace directory: {}",
        guest_path.display()
    );
    let runner = std::fs::read_link("/proc/self/exe").context("cannot locate the guest runner")?;
    ensure!(
        !runner.starts_with(&canonical)
            && !crate::workspace::private_directories()
                .iter()
                .any(|private| overlaps(&canonical, private)),
        "the subshell directory overlaps Meka's installation: {}",
        guest_path.display()
    );

    // Cross into the drive mount at its own mount point, then open only beneath it: the crossing
    // is deliberate, and RESOLVE_NO_XDEV keeps the walk inside the drive filesystem afterwards.
    let rootfs = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_PATH | libc::O_NOFOLLOW)
        .open("/")?;
    let mount_point = PathBuf::from(&point);
    let mount_relative = mount_point.strip_prefix("/")?;
    let mount_fd = openat2_beneath(&rootfs, mount_relative, true)?;
    let remainder = canonical.strip_prefix(&mount_point)?;
    let directory = if remainder.as_os_str().is_empty() {
        openat2_beneath(&mount_fd, Path::new("."), false)?
    } else {
        openat2_beneath(&mount_fd, remainder, false)?
    };

    // The proof: this request's marker, found by openat on the opened directory fd. A wrong
    // translation fails closed: the marker is only in the root the host dropped it into.
    let proof = CString::new(root.proof.as_bytes())?;
    // SAFETY: openat takes the opened directory fd and a NUL-terminated name.
    let marker = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            proof.as_ptr(),
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if marker == -1 {
        return Err(io::Error::last_os_error())
            .context("the Windows-backed mount does not hold its identity proof");
    }
    // SAFETY: a successful openat returns an unowned descriptor.
    let marker = unsafe { File::from_raw_fd(marker) };
    let metadata = marker.metadata()?;
    ensure!(
        metadata.file_type().is_file(),
        "the Windows mount proof is not a regular file"
    );
    drop(marker);
    // SAFETY: unlinkat takes the opened directory fd and a NUL-terminated name. The proof is
    // consumed, not left for a later request to replay; a request whose proof cannot be removed
    // fails here rather than trusting a cleanup to happen later.
    if unsafe { libc::unlinkat(directory.as_raw_fd(), proof.as_ptr(), 0) } != 0 {
        return Err(io::Error::last_os_error())
            .context("cannot remove the consumed mount identity proof");
    }

    Ok((directory, canonical))
}

/// Open `relative` beneath an already-open directory. When `cross_mounts` is true the walk may
/// cross onto another filesystem (the deliberate rootfs-to-drive-mount crossing); when false it
/// must stay inside the filesystem it started in.
fn openat2_beneath(root: &File, relative: &Path, cross_mounts: bool) -> Result<File> {
    let relative = CString::new(relative.as_os_str().as_bytes())?;
    // SAFETY: an all-zero open_how sets no flags and is a valid extensible syscall argument.
    let mut how: libc::open_how = unsafe { std::mem::zeroed() };
    how.flags = (libc::O_DIRECTORY | libc::O_PATH | libc::O_CLOEXEC) as u64;
    how.resolve = libc::RESOLVE_BENEATH
        | libc::RESOLVE_NO_SYMLINKS
        | if cross_mounts {
            0
        } else {
            libc::RESOLVE_NO_XDEV
        };
    // SAFETY: the path and open_how point to initialized objects and the root fd is open.
    let descriptor = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            root.as_raw_fd(),
            relative.as_ptr(),
            &raw const how,
            std::mem::size_of_val(&how),
        )
    };
    if descriptor == -1 {
        return Err(io::Error::last_os_error())
            .context("cannot open the subshell directory safely");
    }
    // SAFETY: a successful openat2 returns an unowned descriptor (a nonnegative int).
    Ok(unsafe { File::from_raw_fd(descriptor as libc::c_int) })
}

/// The workspace directory name one scratch handle owns: lowercase hex of the fixed byte length,
/// so the reaper only ever touches directories the host created for a handle.
fn scratch_name(text: &str) -> Option<&str> {
    (text.len() == SCRATCH_ID_BYTES * 2
        && text
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()))
    .then_some(text)
}

/// The bytes a scratch workspace occupies on disk, measured from the opened directory so a name
/// swapped after the open cannot point the measurement at another tree. Sparse files count what
/// they use, so a command cannot hold a quota hostage with a hole; symlinks and special files
/// count nothing because nothing will follow them.
fn scratch_bytes(directory: &File) -> Result<u64> {
    let mut total = 0u64;
    for name in directory_names(directory, subshell::MAX_TRANSFER_ENTRIES)? {
        let mut status: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: the directory descriptor, NUL-terminated name and output are valid.
        if unsafe {
            libc::fstatat(
                directory.as_raw_fd(),
                name.as_ptr(),
                &mut status,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } == -1
        {
            return Err(io::Error::last_os_error())
                .with_context(|| format!("cannot measure {}", name.to_string_lossy()));
        }
        match status.st_mode & libc::S_IFMT {
            libc::S_IFDIR => {
                let child = open_child(directory, &name, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
                total = total.saturating_add(scratch_bytes(&child)?);
            }
            libc::S_IFREG => {
                total = total.saturating_add((status.st_blocks.max(0) as u64).saturating_mul(512));
            }
            _ => {}
        }
    }
    Ok(total)
}

/// An opened scratch workspace: the root that holds it, the workspace directory itself, and the
/// name under that root. Holding the descriptors is what makes the name private while it is used.
struct ScratchWorkspace {
    root: File,
    directory: File,
    name: CString,
}

impl ScratchWorkspace {
    /// Remove the workspace this value opened, whatever it holds. Only the validated name under
    /// the root this value opened is touched.
    fn remove(self) -> Result<()> {
        remove_directory_tree(&self.directory)?;
        // SAFETY: the root descriptor is open and `name` is one validated NUL-terminated component.
        if unsafe {
            libc::unlinkat(
                self.root.as_raw_fd(),
                self.name.as_ptr(),
                libc::AT_REMOVEDIR,
            )
        } == -1
        {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::NotFound {
                return Err(error).context("cannot remove the scratch workspace");
            }
        }
        Ok(())
    }
}

/// How a scratch workspace is opened. Execution admits work against the quota; the bounded
/// recovery paths (export and removal) open an over-quota tree on purpose, so a workspace that
/// outgrew its quota can still be recovered instead of being wedged past every door.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ScratchUse {
    Execution,
    Recovery,
}

/// Prepare the handle's scratch workspace before its mounts open: reap what the lease expired,
/// create the one call allowed to create it, keep it private to this user, and refuse work past
/// the quota, keeping the descriptors and name the transfer needs to write into the workspace and,
/// after a failure, to remove it again.
///
/// Every scratch call passes through here, so the lease heartbeat, the privacy of the directory
/// and the quota are enforced whenever the workspace is used rather than once when it was staged.
/// The quota is an admission rule for execution and staging, not a runtime write cap: a command
/// that writes past it is recovered by export and removal, which this gate does not hold. Recovery
/// and removal admit separately as [`ScratchUse::Recovery`], so an over-quota workspace is still
/// reachable by the paths that empty it. The descriptors are the workspace's cross-process active
/// lease for as long as this value lives: a removal or a reap that wants the workspace exclusively
/// sees live work and stands down.
fn prepare_scratch_workspace(scratch: &Scratch, use_kind: ScratchUse) -> Result<ScratchWorkspace> {
    let scratch_root = scratch_root();
    let path = scratch.path.as_path();
    let own = path
        .strip_prefix(&scratch_root)
        .ok()
        .and_then(|tail| tail.to_str())
        .filter(|name| !name.is_empty() && !name.contains('/'))
        .and_then(scratch_name)
        .context("invalid scratch workspace path")?;
    let name = CString::new(own).context("invalid scratch workspace name")?;
    let parent = open_scratch_parent()?;
    let root = open_scratch_directory(&parent, &scratch_root_name()?, ScratchDirectory::Ensure)
        .context("cannot open the scratch root")?;
    let directory = open_scratch_directory(
        &root,
        &name,
        if scratch.create {
            ScratchDirectory::CreateNew
        } else {
            ScratchDirectory::Existing
        },
    )?;
    lease_workspace(&directory)?;
    // The lease heartbeat: a workspace untouched for longer than the lease is reaped by the next
    // scratch run, so a host that died without closing anything does not leave storage behind.
    directory
        .set_times(std::fs::FileTimes::new().set_modified(std::time::SystemTime::now()))
        .context("cannot stamp the scratch workspace")?;
    // Expire before touching our own: siblings belong to other handles or to hosts already gone.
    reap_expired_workspaces(&root, own);
    if use_kind == ScratchUse::Execution {
        ensure!(
            scratch_bytes(&directory)? <= scratch.quota_bytes,
            "the scratch workspace is over its {} byte quota; export what it holds and close the \
             handle",
            scratch.quota_bytes
        );
    }
    Ok(ScratchWorkspace {
        root,
        directory,
        name,
    })
}

/// Take the cross-process active lease on a workspace: shared while it is in use. A removal or a
/// reap takes it exclusively first, so live work and a teardown cannot hold the same workspace.
fn lease_workspace(directory: &File) -> Result<()> {
    // SAFETY: the descriptor is open and flock takes no pointers.
    if unsafe { libc::flock(directory.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) } == -1 {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::WouldBlock {
            bail!("the scratch workspace is being removed");
        }
        return Err(error).context("cannot hold the scratch workspace");
    }
    Ok(())
}

/// Try to take the workspace lease exclusively, the one a removal or a reap needs before it may
/// touch anything. `Ok(false)` means live work holds it; an inspection error is a refusal, never a
/// reading of absence.
fn claim_workspace(directory: &File) -> Result<bool> {
    // SAFETY: the descriptor is open and flock takes no pointers.
    if unsafe { libc::flock(directory.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == -1 {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::WouldBlock {
            return Ok(false);
        }
        return Err(error).context("cannot claim the scratch workspace");
    }
    Ok(true)
}

/// Reap the sibling workspaces whose lease expired, opening each candidate by its validated name
/// under the root descriptor and removing the tree through that opened descriptor. A name swapped
/// after the listing cannot redirect the removal to another directory.
fn reap_expired_workspaces(root: &File, own: &str) {
    use std::os::unix::fs::MetadataExt as _;

    let names = match directory_names(root, subshell::MAX_TRANSFER_ENTRIES) {
        Ok(names) => names,
        Err(error) => {
            eprintln!("meka subshell-runner: cannot list the scratch root: {error:#}");
            return;
        }
    };
    let now = std::time::SystemTime::now();
    for name in names {
        let Ok(text) = name.to_str() else {
            continue;
        };
        if text == own || scratch_name(text).is_none() {
            continue;
        }
        let directory = match open_child(root, &name, libc::O_RDONLY | libc::O_DIRECTORY, 0) {
            Ok(directory) => directory,
            Err(error) => {
                let missing = error
                    .downcast_ref::<io::Error>()
                    .is_some_and(|error| error.kind() == io::ErrorKind::NotFound);
                if !missing {
                    eprintln!(
                        "meka subshell-runner: cannot open a scratch workspace to reap: {error:#}"
                    );
                }
                continue;
            }
        };
        let expired = directory.metadata().is_ok_and(|metadata| {
            metadata.is_dir()
                && metadata.uid() == unsafe { libc::getuid() }
                && metadata.modified().is_ok_and(|modified| {
                    now.duration_since(modified)
                        .is_ok_and(|age| age > SCRATCH_LEASE)
                })
        });
        if !expired {
            continue;
        }
        // A workspace live work still holds is neither expired nor this reaper's to take: the
        // exclusive claim is the cross-process proof that no command or transfer is inside it.
        match claim_workspace(&directory) {
            Ok(true) => {}
            Ok(false) => continue,
            Err(error) => {
                eprintln!(
                    "meka subshell-runner: cannot claim a scratch workspace to reap: {error:#}"
                );
                continue;
            }
        }
        let removed = remove_directory_tree(&directory).and_then(|()| {
            // SAFETY: the root descriptor and NUL-terminated name are valid for the call.
            if unsafe { libc::unlinkat(root.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) } == -1
            {
                let error = io::Error::last_os_error();
                if error.kind() != io::ErrorKind::NotFound {
                    return Err(error).context("cannot remove the expired scratch workspace");
                }
            }
            Ok(())
        });
        if let Err(error) = removed {
            eprintln!("meka subshell-runner: cannot reap a scratch workspace: {error:#}");
        }
    }
}

/// How [`open_scratch_directory`] treats a missing or existing entry.
enum ScratchDirectory {
    /// Open the directory, creating it when it is missing.
    Ensure,
    /// Create the directory; an existing name is an error.
    CreateNew,
    /// Open an existing directory; a missing name is an error.
    Existing,
}

/// The scratch root this process uses: [`SCRATCH_ROOT`], unless a test redirects it so the suite
/// never touches the real root.
fn scratch_root() -> PathBuf {
    #[cfg(test)]
    if let Some(root) = std::env::var_os("MEKA_TEST_SCRATCH_ROOT") {
        return PathBuf::from(root);
    }
    PathBuf::from(SCRATCH_ROOT)
}

/// The scratch root's own name, for opening it relative to its parent without following a link.
fn scratch_root_name() -> Result<CString> {
    let root = scratch_root();
    let name = root
        .file_name()
        .context("the scratch root has no name")?
        .to_owned();
    CString::new(name.as_bytes()).context("invalid scratch root name")
}

/// Open the scratch parent by a path whose ancestors are root-owned, so no other local user can
/// replace it between the check and the open.
fn open_scratch_parent() -> Result<File> {
    use std::os::unix::fs::OpenOptionsExt as _;

    // A test redirects the root so the suite never creates or reaps a workspace in the real one.
    #[cfg(test)]
    if let Some(root) = std::env::var_os("MEKA_TEST_SCRATCH_ROOT") {
        let root = PathBuf::from(root);
        let parent = root
            .parent()
            .context("the redirected scratch root has no parent")?;
        let canonical = std::fs::canonicalize(parent)
            .with_context(|| format!("cannot resolve {}", parent.display()))?;
        ensure!(canonical.is_dir(), "the scratch parent is not a directory");
        return std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&canonical)
            .with_context(|| format!("cannot open the scratch parent {}", canonical.display()));
    }

    let canonical = std::fs::canonicalize("/var/tmp").context("cannot resolve /var/tmp")?;
    ensure!(
        canonical.is_dir()
            && canonical
                .ancestors()
                .skip(1)
                .all(super::only_root_can_write),
        "the scratch parent is not a root-owned directory: {}",
        canonical.display()
    );
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&canonical)
        .with_context(|| format!("cannot open the scratch parent {}", canonical.display()))
}

/// Open one scratch directory relative to an already opened parent, never through a symlink, and
/// require it to be this user's own directory. The returned descriptor is what makes the name
/// private; the path is used only after this check.
fn open_scratch_directory(parent: &File, name: &CString, mode: ScratchDirectory) -> Result<File> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let open = || {
        // SAFETY: `name` is a single initialized C string and the parent descriptor is open.
        let descriptor = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if descriptor == -1 {
            Err(io::Error::last_os_error())
        } else {
            // SAFETY: a successful `openat` returns an unowned descriptor.
            Ok(unsafe { File::from_raw_fd(descriptor) })
        }
    };
    let file = match mode {
        ScratchDirectory::Ensure => match open() {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                // SAFETY: the parent descriptor is open and `name` is a valid single component.
                if unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } == -1 {
                    let error = io::Error::last_os_error();
                    if error.kind() != io::ErrorKind::AlreadyExists {
                        return Err(error).context("cannot create the scratch root");
                    }
                }
                open()?
            }
            Err(error) => return Err(error).context("cannot open the scratch root"),
        },
        ScratchDirectory::CreateNew => {
            // SAFETY: the parent descriptor is open and `name` is a valid single component.
            if unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } == -1 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::AlreadyExists {
                    bail!("the scratch workspace id is already in use");
                }
                return Err(error).context("cannot create the scratch workspace");
            }
            open().context("cannot open the scratch workspace just created")?
        }
        ScratchDirectory::Existing => match open() {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => bail!(
                "the scratch workspace expired; anything it held is gone and the handle must be \
                 reopened"
            ),
            Err(error) => return Err(error).context("cannot open the scratch workspace"),
        },
    };
    let metadata = file
        .metadata()
        .context("cannot inspect the scratch directory")?;
    ensure!(
        metadata.is_dir() && metadata.uid() == unsafe { libc::getuid() },
        "the scratch workspace is not this runner's own directory"
    );
    file.set_permissions(std::fs::Permissions::from_mode(0o700))
        .context("cannot keep the scratch workspace private")?;
    Ok(file)
}

/// One directory entry's type, as the descriptor-relative walk sees it.
enum ChildKind {
    Directory,
    File,
}

/// The error a transfer guard returns when the host lease closed or wrote again.
#[derive(Debug)]
struct LeaseEnded;

impl std::fmt::Display for LeaseEnded {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("the host lease ended during the transfer")
    }
}

impl std::error::Error for LeaseEnded {}

/// The error a transfer guard returns when the request's deadline passed.
#[derive(Debug)]
struct TransferDeadline;

impl std::fmt::Display for TransferDeadline {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("the transfer deadline passed")
    }
}

impl std::error::Error for TransferDeadline {}

/// The lease and deadline checks one transfer makes between entries. The lease is the duplicated
/// stdin pipe: anything readable on it, or a hangup, means the host is gone or has stopped waiting.
struct TransferGuard {
    deadline: tokio::time::Instant,
    /// Whether the host's lease is watched. A direct walk in a test has no host pipe; every
    /// served transfer takes this from `new`.
    watch_lease: bool,
}

impl TransferGuard {
    fn new(deadline: tokio::time::Instant) -> Self {
        Self {
            deadline,
            watch_lease: true,
        }
    }

    #[cfg(test)]
    fn without_lease(deadline: tokio::time::Instant) -> Self {
        Self {
            deadline,
            watch_lease: false,
        }
    }

    fn check(&self) -> Result<()> {
        if tokio::time::Instant::now() >= self.deadline {
            return Err(TransferDeadline.into());
        }
        if !self.watch_lease {
            return Ok(());
        }
        let mut descriptor = libc::pollfd {
            fd: libc::STDIN_FILENO,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: `descriptor` is one initialized pollfd and the call only writes its revents.
        let ready = unsafe { libc::poll(&mut descriptor, 1, 0) };
        if ready == -1 {
            return Err(io::Error::last_os_error()).context("cannot watch the host lease");
        }
        if ready > 0 {
            return Err(LeaseEnded.into());
        }
        Ok(())
    }
}

/// Serve one transfer request: no shell, no mounts, only the files the request names. A response
/// is newline-delimited frames with exactly the bytes each `File` frame announced following it.
/// An upload is read instead of walked: its manifest line and the announced bytes follow the
/// request on the lease pipe, and the runner writes what it verified into its own workspace.
async fn serve_transfer(
    lease: &mut (impl tokio::io::AsyncBufRead + Unpin),
    request: &Request,
    transfer: &subshell::Transfer,
    deadline: tokio::time::Instant,
) -> Result<i32> {
    let guard = TransferGuard::new(deadline);
    let result = match transfer {
        subshell::Transfer::Stage { source } => {
            let scratch = request
                .scratch
                .as_ref()
                .context("a stage transfer names its scratch workspace")?;
            stage_transfer(source, scratch, &request.op, &guard)
        }
        subshell::Transfer::Upload => {
            let scratch = request
                .scratch
                .as_ref()
                .context("an upload names its scratch workspace")?;
            upload_transfer(lease, scratch, &request.op, deadline).await
        }
        subshell::Transfer::Export { sources } => {
            // Export is one of the bounded recovery paths: an over-quota workspace must still open
            // for it, so its descriptors are held for the transfer and the execution quota gate is
            // not applied here.
            let workspace = request
                .scratch
                .as_ref()
                .map(|scratch| prepare_scratch_workspace(scratch, ScratchUse::Recovery))
                .transpose()?;
            let result = export_transfer(request, sources, workspace.as_ref(), &guard);
            drop(workspace);
            result
        }
        subshell::Transfer::RemoveScratch => {
            let scratch = request
                .scratch
                .as_ref()
                .context("a scratch removal names its workspace")?;
            remove_scratch_transfer(scratch, &request.op, &guard)
        }
    };
    match result {
        Ok(()) => Ok(0),
        Err(error) if error.downcast_ref::<LeaseEnded>().is_some() => Ok(CANCELED),
        Err(error) if error.downcast_ref::<TransferDeadline>().is_some() => Ok(TIMED_OUT),
        Err(error) => Err(error),
    }
}

/// Write one metadata frame and flush it, so the host can plan before any file byte follows.
fn write_frame(frame: &subshell::Frame) -> Result<()> {
    let mut stdout = io::stdout().lock();
    stdout.write_all(&frame.encode()?)?;
    stdout.flush()?;
    Ok(())
}

/// The kernel's mount identity for an opened object. Two descriptors with one mount id live on the
/// same mounted filesystem, which is what distinguishes a bind mount of the same filesystem from
/// its surrounding tree: `st_dev` cannot tell those apart, and a same-filesystem mount under a
/// source is another tree answering for its name.
fn mount_id(file: &File) -> Result<u64> {
    let details = std::fs::read_to_string(format!("/proc/self/fdinfo/{}", file.as_raw_fd()))
        .context("cannot inspect the transfer object's mount")?;
    details
        .lines()
        .find_map(|line| line.strip_prefix("mnt_id:"))
        .context("missing transfer object mount identity")?
        .trim()
        .parse()
        .context("invalid transfer object mount identity")
}

/// The names of one opened directory, in a stable order, as NUL-terminated components, refusing a
/// directory with more than `bound` entries rather than collecting it whole.
fn directory_names(directory: &File, bound: usize) -> Result<Vec<CString>> {
    // SAFETY: `directory` is an open directory descriptor and `"."` is a valid single component.
    let descriptor = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            c".".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if descriptor == -1 {
        return Err(io::Error::last_os_error()).context("cannot open a transfer directory");
    }
    // SAFETY: `fdopendir` takes ownership of `descriptor` and returns null on failure.
    let stream = unsafe { libc::fdopendir(descriptor) };
    if stream.is_null() {
        // SAFETY: `fdopendir` did not take ownership on failure.
        if unsafe { libc::close(descriptor) } == -1 {
            eprintln!(
                "meka subshell-runner: cannot close a transfer directory: {}",
                io::Error::last_os_error()
            );
        }
        return Err(io::Error::last_os_error()).context("cannot read a transfer directory");
    }
    let mut names = Vec::new();
    loop {
        // SAFETY: `stream` is an open directory stream; `readdir` sets errno on failure.
        unsafe { *libc::__errno_location() = 0 };
        // SAFETY: `stream` is an open directory stream.
        let entry = unsafe { libc::readdir(stream) };
        if entry.is_null() {
            let error = io::Error::last_os_error();
            if error.raw_os_error().is_some_and(|code| code != 0) {
                // SAFETY: `stream` is open and owned by this function.
                if unsafe { libc::closedir(stream) } == -1 {
                    eprintln!(
                        "meka subshell-runner: cannot close a transfer directory: {}",
                        io::Error::last_os_error()
                    );
                }
                return Err(error).context("cannot read a transfer directory");
            }
            break;
        }
        // SAFETY: the entry lives in `stream`'s buffer and its name is NUL-terminated there.
        let name = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) };
        if !matches!(name.to_bytes(), b"." | b"..") {
            // The bound is enforced while the directory is enumerated, before the listing can
            // grow past what the transfer budgets allow it to hold.
            ensure!(
                names.len() < bound,
                "a transfer directory holds more than {bound} entries"
            );
            names.push(name.to_owned());
        }
    }
    // SAFETY: `stream` is open and owned by this function.
    if unsafe { libc::closedir(stream) } == -1 {
        return Err(io::Error::last_os_error()).context("cannot close a transfer directory");
    }
    names.sort_by(|left, right| left.to_bytes().cmp(right.to_bytes()));
    Ok(names)
}

/// Open one name under an opened directory, never through a symlink.
fn open_child(
    directory: &File,
    name: &CString,
    flags: libc::c_int,
    mode: libc::mode_t,
) -> Result<File> {
    // SAFETY: the directory descriptor and the NUL-terminated name are valid for the call.
    let descriptor = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            mode,
        )
    };
    if descriptor == -1 {
        return Err(io::Error::last_os_error())
            .with_context(|| format!("cannot open {}", name.to_string_lossy()));
    }
    // SAFETY: a successful `openat` returns an unowned descriptor.
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

/// Classify one name under an opened directory without following a link.
fn child_kind(directory: &File, name: &CString) -> Result<ChildKind> {
    let mut status: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: the directory descriptor, NUL-terminated name and `stat` output are valid.
    if unsafe {
        libc::fstatat(
            directory.as_raw_fd(),
            name.as_ptr(),
            &mut status,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } == -1
    {
        return Err(io::Error::last_os_error())
            .with_context(|| format!("cannot inspect {}", name.to_string_lossy()));
    }
    match status.st_mode & libc::S_IFMT {
        libc::S_IFDIR => Ok(ChildKind::Directory),
        libc::S_IFREG => {
            ensure!(
                status.st_nlink == 1,
                "{} has {} hard links; a transfer refuses a file another name can change",
                name.to_string_lossy(),
                status.st_nlink
            );
            Ok(ChildKind::File)
        }
        _ => bail!(
            "{} is not a regular file or a real directory; nothing else is transferred",
            name.to_string_lossy()
        ),
    }
}

/// Reopen an opened directory for reading, keeping the inode rather than the name.
fn readable_directory(directory: &File) -> Result<File> {
    // SAFETY: `directory` is an open directory descriptor and `"."` is a valid component.
    let descriptor = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            c".".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if descriptor == -1 {
        return Err(io::Error::last_os_error()).context("cannot open a transfer directory");
    }
    // SAFETY: a successful `openat` returns an unowned descriptor.
    let readable = unsafe { File::from_raw_fd(descriptor) };
    ensure!(
        readable.metadata()?.is_dir(),
        "a transfer directory changed while it was opened"
    );
    Ok(readable)
}

/// Descend from an opened source root to one entry by validated components, without following a
/// link or crossing a mount anywhere in the walk, the final leaf included. The leaf may be a file
/// or a directory; the kind it opened as comes back with it.
fn open_relative_entry(root: &File, components: &[String]) -> Result<(File, bool)> {
    use std::os::unix::fs::MetadataExt as _;

    let (last, directories) = components
        .split_last()
        .context("an export entry has no file name")?;
    let mut directory = readable_directory(root)?;
    let device = directory.metadata()?.dev();
    let mount = mount_id(&directory)?;
    for component in directories {
        let name = CString::new(component.as_bytes())?;
        ensure!(
            matches!(child_kind(&directory, &name)?, ChildKind::Directory),
            "an export directory changed while it was read"
        );
        let child = open_child(&directory, &name, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
        let metadata = child.metadata()?;
        ensure!(
            metadata.dev() == device && mount_id(&child)? == mount,
            "an export source crosses a mount; nothing is exported across one"
        );
        directory = child;
    }
    let name = CString::new(last.as_bytes())?;
    let is_dir = match child_kind(&directory, &name)? {
        ChildKind::Directory => true,
        ChildKind::File => false,
    };
    // O_NONBLOCK keeps a special file that slipped past the type check from blocking the open;
    // the type is judged on the opened descriptor that will supply the bytes.
    let flags = libc::O_RDONLY
        | if is_dir {
            libc::O_DIRECTORY
        } else {
            libc::O_NONBLOCK
        };
    let file = open_child(&directory, &name, flags, 0)?;
    let metadata = file.metadata()?;
    ensure!(
        mount_id(&file)? == mount
            && if is_dir {
                metadata.is_dir()
            } else {
                metadata.is_file() && metadata.nlink() == 1
            },
        "an export source changed while it was opened, or crosses a mount"
    );
    Ok((file, is_dir))
}

/// Open one file beneath an opened source root. A leaf that is no longer the file the manifest
/// recorded, a directory among them, is a change and not a transfer.
fn open_relative_file(root: &File, components: &[String]) -> Result<File> {
    let (file, is_dir) = open_relative_entry(root, components)?;
    ensure!(!is_dir, "an export file changed while it was read");
    Ok(file)
}

/// Copy one source tree into an opened scratch workspace, then send its manifest. The workspace is
/// removed again when anything fails, so a refused stage leaves nothing for the reaper. Staging is
/// an admission path, so the quota gate applies to it as it does to execution.
fn stage_transfer(
    source: &MountRoot,
    scratch: &Scratch,
    op: &str,
    guard: &TransferGuard,
) -> Result<()> {
    guard.check()?;
    let workspace = prepare_scratch_workspace(scratch, ScratchUse::Execution)?;
    let result = stage_into(source, scratch, &workspace.directory, guard);
    match result {
        Ok(entries) => {
            write_frame(&subshell::Frame::Manifest {
                op: op.to_owned(),
                roots: Vec::new(),
                entries,
            })?;
            write_frame(&subshell::Frame::Done { op: op.to_owned() })?;
            Ok(())
        }
        Err(error) => {
            // A failed stage never claims its workspace is gone: what removal confirms is
            // reported by its own result, and what it cannot confirm is left to the reaper.
            if let Err(cleanup) = workspace.remove() {
                eprintln!(
                    "meka subshell-runner: cannot remove a refused scratch workspace: {cleanup:#}"
                );
            }
            Err(error)
        }
    }
}

/// Serve one upload: the manifest line and every announced byte follow the request on the host's
/// pipe, and the snapshot lands in the scratch workspace the request carries. The workspace is
/// removed again when anything fails, so a refused upload leaves nothing for the reaper. The
/// announced totals are judged before a byte is read, and a file whose received bytes do not hash
/// to the digest its entry announced refuses the whole snapshot.
async fn upload_transfer(
    lease: &mut (impl tokio::io::AsyncBufRead + Unpin),
    scratch: &Scratch,
    op: &str,
    deadline: tokio::time::Instant,
) -> Result<()> {
    let entries = read_upload_manifest(lease, op, deadline).await?;
    let workspace = prepare_scratch_workspace(scratch, ScratchUse::Execution)?;
    let result = receive_upload(
        lease,
        &entries,
        &workspace.directory,
        scratch.quota_bytes,
        deadline,
    )
    .await;
    match result {
        Ok(()) => {
            write_frame(&subshell::Frame::Manifest {
                op: op.to_owned(),
                roots: Vec::new(),
                entries,
            })?;
            write_frame(&subshell::Frame::Done { op: op.to_owned() })?;
            Ok(())
        }
        Err(error) => {
            // A refused upload never claims its workspace is gone: what removal confirms is
            // reported by its own result, and what it cannot confirm is left to the reaper.
            if let Err(cleanup) = workspace.remove() {
                eprintln!(
                    "meka subshell-runner: cannot remove a refused scratch workspace: {cleanup:#}"
                );
            }
            Err(error)
        }
    }
}

/// The one manifest line an upload follows its request with: the frame shape a transfer answers
/// with, so its entries pass the same wire validation before any budget is judged or any byte is
/// read.
async fn read_upload_manifest(
    lease: &mut (impl tokio::io::AsyncBufRead + Unpin),
    op: &str,
    deadline: tokio::time::Instant,
) -> Result<Vec<subshell::TransferEntry>> {
    let mut line = Vec::new();
    let read = tokio::time::timeout_at(
        deadline,
        lease
            .take(subshell::MANIFEST_BYTES as u64 + 1)
            .read_until(b'\n', &mut line),
    )
    .await
    .map_err(|_| TransferDeadline)??;
    ensure!(
        read <= subshell::MANIFEST_BYTES && line.last() == Some(&b'\n'),
        "missing or oversized upload manifest"
    );
    match subshell::Frame::decode(&line)? {
        subshell::Frame::Manifest {
            op: named,
            roots,
            entries,
        } => {
            ensure!(named == op, "the upload manifest names another operation");
            ensure!(roots.is_empty(), "a stage names no roots");
            Ok(entries)
        }
        _ => bail!("an upload begins with its manifest"),
    }
}

/// Write every announced entry into the scratch workspace, in manifest order, from the bytes that
/// follow the manifest on the pipe. The announced totals are judged before a byte is read. A
/// directory entry creates its path; a file entry is created exclusive and written to exactly its
/// announced length, hashed as it lands and refused when that hash is not the digest its entry
/// announced. The reads are the lease here: the pipe ending mid-entry is the host going away, not
/// an early file.
async fn receive_upload(
    lease: &mut (impl tokio::io::AsyncBufRead + Unpin),
    entries: &[subshell::TransferEntry],
    workspace: &File,
    quota_bytes: u64,
    deadline: tokio::time::Instant,
) -> Result<()> {
    use sha2::Digest as _;

    let announced: u64 = entries.iter().map(|entry| entry.len).sum();
    ensure!(
        announced <= quota_bytes,
        "the upload is larger than the {quota_bytes} byte scratch quota"
    );
    let mut seen = std::collections::HashSet::new();
    for entry in entries {
        ensure!(
            seen.insert(entry.path.clone()),
            "the upload manifest names {:?} twice",
            entry.path
        );
        if tokio::time::Instant::now() >= deadline {
            return Err(TransferDeadline.into());
        }
        let components: Vec<&str> = entry.path.split('/').collect();
        let (last, directories) = components
            .split_last()
            .context("an upload entry has no name")?;
        let mut directory = workspace
            .try_clone()
            .context("cannot reopen the scratch workspace")?;
        for component in directories {
            directory = ensure_scratch_directory(&directory, &CString::new(*component)?)?;
        }
        let name = CString::new(*last)?;
        if entry.directory {
            ensure_scratch_directory(&directory, &name)?;
            continue;
        }
        let mut writer = open_child(
            &directory,
            &name,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            0o600,
        )?;
        let mut hasher = sha2::Sha256::new();
        let mut buffer = [0u8; 64 * crate::text::KIB];
        let mut remaining = entry.len;
        while remaining > 0 {
            if tokio::time::Instant::now() >= deadline {
                return Err(TransferDeadline.into());
            }
            let take = usize::try_from(remaining)
                .unwrap_or(buffer.len())
                .min(buffer.len());
            let read = tokio::time::timeout_at(
                deadline,
                lease.read(buffer.get_mut(..take).unwrap_or_default()),
            )
            .await
            .map_err(|_| TransferDeadline)??;
            if read == 0 {
                return Err(LeaseEnded.into());
            }
            let chunk = buffer.get(..read).unwrap_or_default();
            hasher.update(chunk);
            writer.write_all(chunk)?;
            remaining = remaining.saturating_sub(read as u64);
        }
        drop(writer);
        let digest: [u8; 32] = hasher.finalize().into();
        ensure!(
            Some(digest) == entry.parsed_digest(),
            "{:?} arrived with other bytes than the digest its entry announced",
            entry.path
        );
    }
    Ok(())
}

/// One directory of an upload's path: created for the first entry that names it and kept for the
/// next. The workspace is fresh and this manifest is its only writer, so a name already there is
/// this manifest's own earlier entry, and a name that is not the directory it made is a refusal.
fn ensure_scratch_directory(destination: &File, name: &CString) -> Result<File> {
    // SAFETY: the destination descriptor is open and `name` is one validated component.
    if unsafe { libc::mkdirat(destination.as_raw_fd(), name.as_ptr(), 0o700) } == -1 {
        let error = io::Error::last_os_error();
        ensure!(
            error.raw_os_error() == Some(libc::EEXIST),
            "cannot create {}: {error}",
            name.to_string_lossy()
        );
        let existing = open_child(destination, name, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
        ensure!(
            existing.metadata()?.is_dir(),
            "{} in an upload is not a real directory",
            name.to_string_lossy()
        );
        return Ok(existing);
    }
    open_child(destination, name, libc::O_RDONLY | libc::O_DIRECTORY, 0)
}

/// The source directory a stage reads, opened by the descriptor its kind can be trusted by.
fn open_stage_source(source: &MountRoot) -> Result<File> {
    let opened = match source {
        // A guest source is a workspace directory the host admitted; it is opened by the same
        // checks a mounted workspace root passes, so a path the session could not mount cannot be
        // staged either.
        MountRoot::Guest(path) => open_guest_directory(path)?,
        MountRoot::Windows(root) => open_windows_directory(root)?.0,
    };
    ensure!(
        opened.metadata()?.is_dir(),
        "a stage source must be a directory"
    );
    readable_directory(&opened)
}

/// The walk that copies one source tree into the scratch workspace and records what it copied.
struct StageWalk<'a> {
    guard: &'a TransferGuard,
    scratch: &'a Scratch,
    /// The filesystem the source root lives on. A mount below the root is a different tree even
    /// when its name is still under the admitted path, so the walk never leaves this device.
    device: u64,
    /// The source root's kernel mount identity, which also refuses a bind mount of the same
    /// filesystem beneath it.
    mount: u64,
    entries: Vec<subshell::TransferEntry>,
    bytes: u64,
}

fn stage_into(
    source: &MountRoot,
    scratch: &Scratch,
    destination: &File,
    guard: &TransferGuard,
) -> Result<Vec<subshell::TransferEntry>> {
    let directory = open_stage_source(source)?;
    let device = {
        use std::os::unix::fs::MetadataExt as _;
        directory.metadata()?.dev()
    };
    let mount = mount_id(&directory)?;
    let mut walk = StageWalk {
        guard,
        scratch,
        device,
        mount,
        entries: Vec::new(),
        bytes: 0,
    };
    walk.directory(&directory, &mut Vec::new(), destination)?;
    Ok(walk.entries)
}

impl StageWalk<'_> {
    fn push(&mut self, entry: subshell::TransferEntry) -> Result<()> {
        ensure!(
            self.entries.len() < subshell::MAX_TRANSFER_ENTRIES,
            "the source has more than {} entries",
            subshell::MAX_TRANSFER_ENTRIES
        );
        self.entries.push(entry);
        Ok(())
    }

    fn directory(
        &mut self,
        source: &File,
        relative: &mut Vec<String>,
        destination: &File,
    ) -> Result<()> {
        use std::os::unix::fs::MetadataExt as _;

        for name in directory_names(source, subshell::MAX_TRANSFER_ENTRIES)? {
            self.guard.check()?;
            let text = name
                .to_str()
                .with_context(|| format!("a source name is not Unicode: {name:?}"))?;
            ensure!(
                subshell::is_transfer_component(text),
                "invalid source name: {text:?}"
            );
            // A name in the proof artifact namespace is internal bookkeeping, never transfer data.
            if subshell::is_proof_name(text) {
                continue;
            }
            relative.push(text.to_owned());
            let path = relative.join("/");
            ensure!(
                subshell::is_transfer_entry_path(&path),
                "a source path is too long or too deep: {path:?}"
            );
            let kind = child_kind(source, &name)?;
            match kind {
                ChildKind::Directory => {
                    let child = open_child(source, &name, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
                    let metadata = child.metadata()?;
                    ensure!(
                        metadata.dev() == self.device && mount_id(&child)? == self.mount,
                        "{path} is on another mount; nothing is staged across one"
                    );
                    self.push(subshell::TransferEntry {
                        root: 0,
                        path,
                        len: 0,
                        modified_secs: metadata.mtime(),
                        modified_nanos: metadata.mtime_nsec() as u32,
                        digest: subshell::digest_hex(&empty_digest()),
                        directory: true,
                    })?;
                    let created = create_scratch_directory(destination, &name)?;
                    self.directory(&child, relative, &created)?;
                    drop(created);
                }
                ChildKind::File => {
                    // O_NONBLOCK keeps a special file that slipped past the type check from
                    // blocking the walk; the type is judged on the opened descriptor that will
                    // supply the bytes, never on the name that was checked before it.
                    let file = open_child(source, &name, libc::O_RDONLY | libc::O_NONBLOCK, 0)?;
                    let before = file.metadata()?;
                    ensure!(
                        before.is_file() && before.nlink() == 1 && before.dev() == self.device,
                        "a stage source changed while it was opened, or crosses a mount"
                    );
                    ensure!(
                        mount_id(&file)? == self.mount,
                        "{path} is on another mount; nothing is staged across one"
                    );
                    let len = before.len();
                    // A declared length past any one budget is refused before the copy allocates
                    // or writes for it.
                    ensure!(
                        len <= subshell::MAX_TRANSFER_FILE_BYTES,
                        "{path} is larger than one transferred file may be"
                    );
                    ensure!(
                        self.bytes.saturating_add(len) <= self.scratch.quota_bytes
                            && self.bytes.saturating_add(len) <= subshell::MAX_TRANSFER_BYTES,
                        "the source is larger than the {} byte scratch quota",
                        self.scratch.quota_bytes
                    );
                    let digest =
                        copy_staged_file(&file, destination, &name, len, &before, self.guard)?;
                    self.bytes = self.bytes.saturating_add(len);
                    self.push(subshell::TransferEntry {
                        root: 0,
                        path,
                        len,
                        modified_secs: before.mtime(),
                        modified_nanos: before.mtime_nsec() as u32,
                        digest: subshell::digest_hex(&digest),
                        directory: false,
                    })?;
                }
            }
            relative.pop();
        }
        Ok(())
    }
}

fn empty_digest() -> [u8; 32] {
    use sha2::Digest as _;

    sha2::Sha256::new().finalize().into()
}

/// Create one directory in the scratch workspace, refusing a name that already exists there.
fn create_scratch_directory(destination: &File, name: &CString) -> Result<File> {
    // SAFETY: the destination descriptor is open and `name` is one validated component.
    if unsafe { libc::mkdirat(destination.as_raw_fd(), name.as_ptr(), 0o700) } == -1 {
        return Err(io::Error::last_os_error())
            .with_context(|| format!("cannot create {}", name.to_string_lossy()));
    }
    open_child(destination, name, libc::O_RDONLY | libc::O_DIRECTORY, 0)
}

/// Copy one regular file into the scratch workspace while hashing it, and refuse a source that
/// changed while it was read. The destination is created exclusive, so the copy can never write
/// through an entry already in the workspace, and exactly the announced length is read and
/// written: a source that grew is a refusal, never extra bytes in the staged copy.
fn copy_staged_file(
    source: &File,
    destination: &File,
    name: &CString,
    expected_len: u64,
    before: &std::fs::Metadata,
    guard: &TransferGuard,
) -> Result<[u8; 32]> {
    use std::{io::Read as _, os::unix::fs::MetadataExt as _};

    use sha2::Digest as _;

    let mut writer = open_child(
        destination,
        name,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        0o600,
    )?;
    let mut reader = source
        .try_clone()
        .context("cannot read a stage source file")?;
    let mut hasher = sha2::Sha256::new();
    let mut buffer = [0u8; 64 * crate::text::KIB];
    let mut copied = 0u64;
    while copied < expected_len {
        guard.check()?;
        let room = usize::try_from(expected_len - copied).unwrap_or(buffer.len());
        let take = room.min(buffer.len());
        let read = reader
            .read(buffer.get_mut(..take).unwrap_or_default())
            .with_context(|| format!("cannot read {}", name.to_string_lossy()))?;
        if read == 0 {
            break;
        }
        let chunk = buffer.get(..read).unwrap_or_default();
        hasher.update(chunk);
        writer
            .write_all(chunk)
            .with_context(|| format!("cannot write {}", name.to_string_lossy()))?;
        copied = copied.saturating_add(read as u64);
    }
    ensure!(
        copied == expected_len,
        "{} changed while it was staged",
        name.to_string_lossy()
    );
    // The announced length is the whole copy. One byte more arriving now means the file grew
    // while it was staged, and growth is a change, not more data to keep.
    let mut extra = [0u8];
    let grew = reader
        .read(&mut extra)
        .with_context(|| format!("cannot read {}", name.to_string_lossy()))?;
    ensure!(
        grew == 0,
        "{} grew while it was staged",
        name.to_string_lossy()
    );
    let after = source
        .metadata()
        .with_context(|| format!("cannot re-inspect {}", name.to_string_lossy()))?;
    ensure!(
        after.is_file()
            && after.nlink() == 1
            && after.len() == before.len()
            && after.mtime() == before.mtime()
            && after.mtime_nsec() == before.mtime_nsec()
            && after.dev() == before.dev()
            && after.ino() == before.ino(),
        "{} changed while it was staged",
        name.to_string_lossy()
    );
    Ok(hasher.finalize().into())
}

/// One file an export read in its first pass, with the identity the second pass must find again.
struct ExportedFile {
    root: usize,
    path: String,
    len: u64,
    modified_secs: i64,
    modified_nanos: u32,
    digest: [u8; 32],
    dev: u64,
    ino: u64,
    components: Vec<String>,
}

/// Read every named source twice: once to hash what it holds and announce the complete manifest,
/// then again to stream it, refusing any file that changed between the two reads. A source is a
/// typed root of this request and validated components beneath it, resolved under the same open
/// rules the execution path mounts with: no link, no mount, and the object's own type and identity
/// checked on the descriptor that supplies the bytes.
fn export_transfer(
    request: &Request,
    sources: &[subshell::ExportSource],
    workspace: Option<&ScratchWorkspace>,
    guard: &TransferGuard,
) -> Result<()> {
    use std::os::unix::fs::MetadataExt as _;

    let mut roots = Vec::new();
    let mut opened = Vec::new();
    let mut entries = Vec::new();
    let mut files = Vec::new();
    let mut bytes = 0u64;
    for (index, source) in sources.iter().enumerate() {
        guard.check()?;
        let (root, name, is_dir) = open_export_source(request, source, workspace)?;
        let metadata = root.metadata()?;
        roots.push(subshell::TransferRoot {
            source: source.clone(),
            name: name.clone(),
            directory: is_dir,
        });
        if is_dir {
            collect_export_directory(
                index,
                &root,
                metadata.dev(),
                mount_id(&root)?,
                &mut bytes,
                &mut Vec::new(),
                &mut entries,
                &mut files,
                guard,
            )?;
        } else {
            guard.check()?;
            let len = metadata.len();
            ensure!(
                len <= subshell::MAX_TRANSFER_FILE_BYTES,
                "{name} is larger than one transferred file may be"
            );
            bytes = bytes.saturating_add(len);
            ensure!(
                bytes <= subshell::MAX_TRANSFER_BYTES,
                "the export is larger than the transfer's byte budget"
            );
            let digest = digest_file(&root, guard)?;
            entries.push(subshell::TransferEntry {
                root: index,
                path: name.clone(),
                len: metadata.len(),
                modified_secs: metadata.mtime(),
                modified_nanos: metadata.mtime_nsec() as u32,
                digest: subshell::digest_hex(&digest),
                directory: false,
            });
            files.push(ExportedFile {
                root: index,
                path: name.clone(),
                len: metadata.len(),
                modified_secs: metadata.mtime(),
                modified_nanos: metadata.mtime_nsec() as u32,
                digest,
                dev: metadata.dev(),
                ino: metadata.ino(),
                components: vec![name],
            });
        }
        ensure!(
            entries.len() <= subshell::MAX_TRANSFER_ENTRIES,
            "the export has more than {} entries",
            subshell::MAX_TRANSFER_ENTRIES
        );
        opened.push((root, is_dir));
    }
    write_frame(&subshell::Frame::Manifest {
        op: request.op.clone(),
        roots,
        entries,
    })?;
    for (index, (root, is_dir)) in opened.iter().enumerate() {
        guard.check()?;
        let root_files = files.iter().filter(|file| file.root == index);
        if !*is_dir {
            for file in root_files {
                guard.check()?;
                verify_export_file(root, file)?;
                stream_export_file(root, file, guard)?;
            }
            continue;
        }
        for file in root_files {
            guard.check()?;
            let opened_file = open_relative_file(root, &file.components)?;
            verify_export_file(&opened_file, file)?;
            stream_export_file(&opened_file, file, guard)?;
        }
    }
    write_frame(&subshell::Frame::Done {
        op: request.op.clone(),
    })?;
    Ok(())
}

/// The mounted root an export source names, in the order the request carries them: the working
/// directory first, then the workspace mounts, then the read-only ones.
fn export_root(request: &Request, index: usize) -> Result<&MountRoot> {
    match index {
        0 => Ok(&request.working_directory),
        n => {
            let n = n - 1;
            request
                .workspace
                .get(n)
                .or_else(|| {
                    n.checked_sub(request.workspace.len())
                        .and_then(|m| request.readable.get(m))
                })
                .ok_or_else(|| anyhow::anyhow!("an export source names an unknown root"))
        }
    }
}

/// Open one typed export source beneath the root it names. The root is opened with the execution
/// path's own rules (a guest directory or a proven Windows mount), and the source's components are
/// resolved beneath it with no symlink and no mount crossing, including the final leaf. The name is
/// the source's final component, or the root's own when the source is the root itself.
fn open_export_source(
    request: &Request,
    source: &subshell::ExportSource,
    workspace: Option<&ScratchWorkspace>,
) -> Result<(File, String, bool)> {
    use std::os::unix::fs::MetadataExt as _;

    let (root, root_name) = match &source.root {
        subshell::ExportRoot::Scratch => {
            let workspace = workspace
                .ok_or_else(|| anyhow::anyhow!("a scratch export names its scratch workspace"))?;
            let name = workspace
                .name
                .to_str()
                .context("the scratch workspace name is not Unicode")?
                .to_owned();
            (
                workspace
                    .directory
                    .try_clone()
                    .context("cannot hold the scratch workspace")?,
                name,
            )
        }
        subshell::ExportRoot::Mounted(index) => {
            let mount = export_root(request, *index)?;
            match mount {
                // A Windows-backed mount is read natively by the host: over DrvFS the guest
                // cannot bind every object a walk would reach to the mount it was admitted under.
                MountRoot::Windows(_) => bail!(
                    "an export from a Windows-backed mount is read natively by the host, not \
                     through the guest"
                ),
                MountRoot::Guest(path) => {
                    let opened = open_guest_directory(path)?;
                    let name = path
                        .file_name()
                        .and_then(|name| name.to_str())
                        .filter(|name| subshell::is_transfer_component(name))
                        .with_context(|| format!("not a transferable file name: {path:?}"))?
                        .to_owned();
                    (readable_directory(&opened)?, name)
                }
            }
        }
    };
    let root_mount = mount_id(&root)?;
    if source.relative.is_empty() {
        let metadata = root.metadata()?;
        ensure!(metadata.is_dir(), "an export root is not a directory");
        return Ok((root, root_name, true));
    }
    let (file, is_dir) = open_relative_entry(&root, &source.relative)?;
    let metadata = file.metadata()?;
    ensure!(
        mount_id(&file)? == root_mount
            && if is_dir {
                metadata.is_dir()
            } else {
                metadata.is_file() && metadata.nlink() == 1
            },
        "an export source changed while it was opened, or crosses a mount"
    );
    let name = source
        .relative
        .last()
        .cloned()
        .context("an export source has no file name")?;
    Ok((file, name, is_dir))
}

/// Walk one source directory, hashing every file and recording every directory the host must
/// create. Symlinks, special files and multiply-linked files are refused, and the walk stops when
/// the host's lease or the request's deadline ends.
#[allow(
    clippy::too_many_arguments,
    reason = "one recursive pass threads its shared walk state in place"
)]
fn collect_export_directory(
    root: usize,
    directory: &File,
    device: u64,
    mount: u64,
    bytes: &mut u64,
    relative: &mut Vec<String>,
    entries: &mut Vec<subshell::TransferEntry>,
    files: &mut Vec<ExportedFile>,
    guard: &TransferGuard,
) -> Result<()> {
    use std::os::unix::fs::MetadataExt as _;

    for name in directory_names(directory, subshell::MAX_TRANSFER_ENTRIES)? {
        guard.check()?;
        let text = name
            .to_str()
            .with_context(|| format!("a source name is not Unicode: {name:?}"))?;
        ensure!(
            subshell::is_transfer_component(text),
            "invalid source name: {text:?}"
        );
        // A name in the proof artifact namespace is internal bookkeeping, never transfer data.
        if subshell::is_proof_name(text) {
            continue;
        }
        relative.push(text.to_owned());
        let path = relative.join("/");
        ensure!(
            subshell::is_transfer_entry_path(&path),
            "a source path is too long or too deep: {path:?}"
        );
        // The entry budget is admission-time work: an entry is refused before it is recorded,
        // not after the whole directory has been collected.
        ensure!(
            entries.len() < subshell::MAX_TRANSFER_ENTRIES,
            "the export has more than {} entries",
            subshell::MAX_TRANSFER_ENTRIES
        );
        match child_kind(directory, &name)? {
            ChildKind::Directory => {
                let child = open_child(directory, &name, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
                let metadata = child.metadata()?;
                ensure!(
                    metadata.dev() == device && mount_id(&child)? == mount,
                    "{path} is on another mount; nothing is exported across one"
                );
                entries.push(subshell::TransferEntry {
                    root,
                    path,
                    len: 0,
                    modified_secs: metadata.mtime(),
                    modified_nanos: metadata.mtime_nsec() as u32,
                    digest: subshell::digest_hex(&empty_digest()),
                    directory: true,
                });
                collect_export_directory(
                    root, &child, device, mount, bytes, relative, entries, files, guard,
                )?;
            }
            ChildKind::File => {
                // O_NONBLOCK keeps a special file that slipped past the type check from blocking
                // the walk; the type is judged on the opened descriptor that supplies the bytes.
                let file = open_child(directory, &name, libc::O_RDONLY | libc::O_NONBLOCK, 0)?;
                let before = file.metadata()?;
                ensure!(
                    before.is_file() && before.nlink() == 1 && before.dev() == device,
                    "a source file changed while it was opened, or crosses a mount"
                );
                ensure!(
                    mount_id(&file)? == mount,
                    "{path} is on another mount; nothing is exported across one"
                );
                // A declared length past any budget is refused before the file is hashed or sent.
                let len = before.len();
                ensure!(
                    len <= subshell::MAX_TRANSFER_FILE_BYTES,
                    "{path} is larger than one transferred file may be"
                );
                *bytes = bytes.saturating_add(len);
                ensure!(
                    *bytes <= subshell::MAX_TRANSFER_BYTES,
                    "the export is larger than the transfer's byte budget"
                );
                let digest = digest_file(&file, guard)?;
                let after = file.metadata()?;
                ensure!(
                    after.len() == before.len()
                        && after.mtime() == before.mtime()
                        && after.mtime_nsec() == before.mtime_nsec()
                        && after.dev() == before.dev()
                        && after.ino() == before.ino(),
                    "{path} changed while the export read it"
                );
                entries.push(subshell::TransferEntry {
                    root,
                    path: path.clone(),
                    len: before.len(),
                    modified_secs: before.mtime(),
                    modified_nanos: before.mtime_nsec() as u32,
                    digest: subshell::digest_hex(&digest),
                    directory: false,
                });
                files.push(ExportedFile {
                    root,
                    path,
                    len: before.len(),
                    modified_secs: before.mtime(),
                    modified_nanos: before.mtime_nsec() as u32,
                    digest,
                    dev: before.dev(),
                    ino: before.ino(),
                    components: relative.clone(),
                });
            }
        }
        relative.pop();
    }
    Ok(())
}

/// Hash one file from its opened descriptor, with the transfer guard checked between chunks so a
/// stop or deadline reaches the hashing pass and not only the stream after it.
fn digest_file(file: &File, guard: &TransferGuard) -> Result<[u8; 32]> {
    use std::io::Read as _;

    use sha2::Digest as _;

    let mut reader = file.try_clone().context("cannot read a transfer file")?;
    let mut hasher = sha2::Sha256::new();
    let mut buffer = [0u8; 64 * crate::text::KIB];
    loop {
        guard.check()?;
        let read = reader
            .read(&mut buffer)
            .context("cannot read a transfer file")?;
        if read == 0 {
            break;
        }
        hasher.update(buffer.get(..read).unwrap_or_default());
    }
    Ok(hasher.finalize().into())
}

/// Require the second pass to hold the same file the first pass hashed.
fn verify_export_file(file: &File, expected: &ExportedFile) -> Result<()> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file()
            && metadata.nlink() == 1
            && metadata.dev() == expected.dev
            && metadata.ino() == expected.ino
            && metadata.len() == expected.len
            && metadata.mtime() == expected.modified_secs
            && metadata.mtime_nsec() as u32 == expected.modified_nanos,
        "{} changed between the export's manifest and its bytes",
        expected.path
    );
    Ok(())
}

/// Send one file's header and bytes, hashing as they go, and refuse a source that changed or a
/// stream that does not hash to the manifest's digest. Exactly the announced length is read and
/// sent: a source that grew is a refusal, never a longer frame sequence than the manifest promised.
fn stream_export_file(file: &File, expected: &ExportedFile, guard: &TransferGuard) -> Result<()> {
    use std::{io::Read as _, os::unix::fs::MetadataExt as _};

    use sha2::Digest as _;

    write_frame(&subshell::Frame::File {
        root: expected.root,
        path: expected.path.clone(),
        len: expected.len,
        modified_secs: expected.modified_secs,
        modified_nanos: expected.modified_nanos,
        digest: subshell::digest_hex(&expected.digest),
    })?;
    let mut reader = file.try_clone().context("cannot read an export file")?;
    std::io::Seek::seek(&mut reader, std::io::SeekFrom::Start(0))
        .context("cannot rewind an export file")?;
    let mut stdout = io::stdout().lock();
    let mut hasher = sha2::Sha256::new();
    let mut buffer = [0u8; 64 * crate::text::KIB];
    let mut sent = 0u64;
    while sent < expected.len {
        guard.check()?;
        let room = usize::try_from(expected.len - sent).unwrap_or(buffer.len());
        let take = room.min(buffer.len());
        let read = reader
            .read(buffer.get_mut(..take).unwrap_or_default())
            .context("cannot read an export file")?;
        if read == 0 {
            break;
        }
        let chunk = buffer.get(..read).unwrap_or_default();
        hasher.update(chunk);
        stdout
            .write_all(chunk)
            .context("cannot send an export file")?;
        sent = sent.saturating_add(read as u64);
    }
    let mut extra = [0u8];
    let grew = reader
        .read(&mut extra)
        .context("cannot read an export file")?;
    stdout.flush().context("cannot send an export file")?;
    drop(stdout);
    let digest: [u8; 32] = hasher.finalize().into();
    ensure!(
        sent == expected.len && grew == 0 && digest == expected.digest,
        "{} changed while the export sent it",
        expected.path
    );
    let after = file.metadata()?;
    ensure!(
        after.len() == expected.len
            && after.mtime() == expected.modified_secs
            && after.mtime_nsec() as u32 == expected.modified_nanos
            && after.ino() == expected.ino,
        "{} changed while the export sent it",
        expected.path
    );
    Ok(())
}

/// Remove the scratch workspace a request names. A workspace that is already gone is proven
/// absent and answered with the same empty completion sequence a removal produces, so the host
/// never has to tell "removed" from "never there" at its parser. Live work holding the workspace,
/// or a directory that will not prove it is this runner's own, is refused: absence is the one
/// thing a removal may conclude from a missing name.
fn remove_scratch_transfer(scratch: &Scratch, op: &str, guard: &TransferGuard) -> Result<()> {
    guard.check()?;
    ensure!(
        !scratch.create,
        "a scratch removal does not create a workspace"
    );
    let scratch_root = scratch_root();
    let path = scratch.path.as_path();
    let own = path
        .strip_prefix(&scratch_root)
        .ok()
        .and_then(|tail| tail.to_str())
        .filter(|name| !name.is_empty() && !name.contains('/'))
        .and_then(scratch_name)
        .context("invalid scratch workspace path")?;
    let name = CString::new(own).context("invalid scratch workspace name")?;
    let parent = open_scratch_parent()?;
    let root = open_scratch_directory(&parent, &scratch_root_name()?, ScratchDirectory::Ensure)
        .context("cannot open the scratch root")?;
    let directory = match open_child(&root, &name, libc::O_RDONLY | libc::O_DIRECTORY, 0) {
        Ok(directory) => directory,
        Err(error)
            if error
                .downcast_ref::<io::Error>()
                .is_some_and(|error| error.kind() == io::ErrorKind::NotFound) =>
        {
            return write_empty_completion(op);
        }
        Err(error) => return Err(error),
    };
    owned_workspace(&directory)?;
    ensure!(
        claim_workspace(&directory)?,
        "the scratch workspace is in use; it cannot be removed while live work holds it"
    );
    let workspace = ScratchWorkspace {
        root,
        directory,
        name,
    };
    workspace.remove()?;
    write_empty_completion(op)
}

/// The valid empty completion sequence: the manifest of a transfer with no entries, then done.
fn write_empty_completion(op: &str) -> Result<()> {
    write_frame(&subshell::Frame::Manifest {
        op: op.to_owned(),
        roots: Vec::new(),
        entries: Vec::new(),
    })?;
    write_frame(&subshell::Frame::Done { op: op.to_owned() })?;
    Ok(())
}

/// The identity one opened scratch workspace must prove before anything removes it: this runner's
/// own private directory. An inspection error is a refusal, never a reading of absence.
fn owned_workspace(directory: &File) -> Result<()> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let metadata = directory
        .metadata()
        .context("cannot inspect the scratch workspace")?;
    ensure!(
        metadata.is_dir() && metadata.uid() == unsafe { libc::getuid() },
        "the scratch workspace is not this runner's own directory"
    );
    ensure!(
        metadata.permissions().mode() & 0o077 == 0,
        "the scratch workspace is not private to this runner"
    );
    Ok(())
}

/// Remove everything inside one opened directory, then the directory's own name under `parent`.
/// The walk is bounded and never crosses a mount: what it may remove is the workspace's own
/// subtree, not whatever another filesystem answers for under a name inside it.
fn remove_directory_tree(directory: &File) -> Result<()> {
    use std::os::unix::fs::MetadataExt as _;

    let device = directory
        .metadata()
        .context("cannot inspect the scratch workspace")?
        .dev();
    let mount = mount_id(directory)?;
    remove_within(directory, device, mount, 0)
}

/// The recursive half of [`remove_directory_tree`], holding the workspace's device and mount
/// identity against every descendant it removes.
fn remove_within(directory: &File, device: u64, mount: u64, depth: usize) -> Result<()> {
    use std::os::unix::fs::MetadataExt as _;

    ensure!(
        depth <= subshell::MAX_TRANSFER_DEPTH,
        "a scratch workspace nests deeper than the removal walk follows"
    );
    for name in directory_names(directory, subshell::MAX_TRANSFER_ENTRIES)? {
        let is_directory = {
            let mut status: libc::stat = unsafe { std::mem::zeroed() };
            // SAFETY: the directory descriptor, name and output are valid for the call.
            if unsafe {
                libc::fstatat(
                    directory.as_raw_fd(),
                    name.as_ptr(),
                    &mut status,
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            } == -1
            {
                return Err(io::Error::last_os_error())
                    .with_context(|| format!("cannot inspect {}", name.to_string_lossy()));
            }
            status.st_mode & libc::S_IFMT == libc::S_IFDIR
        };
        let mut flags = 0;
        if is_directory {
            let child = open_child(directory, &name, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
            let metadata = child
                .metadata()
                .with_context(|| format!("cannot inspect {}", name.to_string_lossy()))?;
            ensure!(
                metadata.dev() == device && mount_id(&child)? == mount,
                "{} is on another mount; nothing is removed across one",
                name.to_string_lossy()
            );
            remove_within(&child, device, mount, depth + 1)?;
            flags = libc::AT_REMOVEDIR;
        }
        // SAFETY: the directory descriptor and NUL-terminated name are valid.
        if unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), flags) } == -1 {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::NotFound {
                return Err(error)
                    .with_context(|| format!("cannot remove {}", name.to_string_lossy()));
            }
        }
    }
    Ok(())
}

fn prepare_mounts(request: &Request) -> Result<Vec<Mount>> {
    let roots: Vec<(&MountRoot, PathBuf, bool)> =
        std::iter::once((
            &request.working_directory,
            PathBuf::from(WORKING_DIRECTORY),
            request.access == Permission::Workspace,
        ))
        .chain(request.workspace.iter().enumerate().map(|(number, path)| {
            (
                path,
                Path::new("/workspaces").join(number.to_string()),
                request.access == Permission::Workspace,
            )
        }))
        .chain(
            request.readable.iter().enumerate().map(|(number, path)| {
                (path, Path::new(REFERENCES).join(number.to_string()), false)
            }),
        )
        .collect();
    // Each root is opened before the mounts are assembled. A Windows root is opened through its
    // proof: the descriptor is only trusted when the directory holds this request's marker, so a
    // translation that lands on the wrong directory fails closed instead of being mounted. The
    // canonical guest path the proof was found at is what overlap checks and the mount source use.
    let resolved: Vec<(File, PathBuf, PathBuf, bool)> = roots
        .iter()
        .map(|(root, destination, writable)| {
            let (directory, path) = match root {
                MountRoot::Guest(path) => (open_guest_directory(path)?, PathBuf::from(path)),
                MountRoot::Windows(win) => open_windows_directory(win)?,
            };
            Ok((directory, path, destination.clone(), *writable))
        })
        .collect::<Result<Vec<_>>>()?;
    let mut mounts: Vec<Mount> = Vec::new();
    let mut sources: Vec<PathBuf> = Vec::new();
    for (source, path, destination, writable) in resolved {
        ensure!(
            !sources.iter().any(|source| overlaps(source, &path)),
            "overlapping subshell roots: {}",
            path.display()
        );
        sources.push(path);
        mounts.push(Mount {
            source,
            destination,
            writable,
        });
    }
    Ok(mounts)
}

fn add_runtime(command: &mut tokio::process::Command) -> Result<Vec<PathBuf>> {
    let mut directories = Vec::new();
    for path in RUNTIME_DIRECTORIES.iter().copied().chain([LOADER_CACHE]) {
        let path = Path::new(path);
        let canonical = match std::fs::canonicalize(path) {
            Ok(path) => path,
            Err(error) if error.kind() == io::ErrorKind::NotFound && path != Path::new("/usr") => {
                continue;
            }
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("cannot resolve guest runtime {}", path.display()));
            }
        };
        ensure!(
            super::only_root_can_write(&canonical)
                && canonical
                    .ancestors()
                    .skip(1)
                    .all(super::only_root_can_write),
            "guest runtime is not root-owned: {}",
            canonical.display()
        );
        if canonical == path {
            command.arg("--ro-bind").arg(path).arg(path);
            directories.push(path.to_path_buf());
        } else {
            ensure!(
                canonical.starts_with("/usr") && canonical.is_dir(),
                "unsupported guest runtime link: {}",
                path.display()
            );
            command.arg("--symlink").arg(canonical).arg(path);
        }
    }
    Ok(directories)
}

fn spawn(
    request: &Request,
) -> Result<(
    crate::process::Tree,
    tokio::process::ChildStdout,
    tokio::process::ChildStderr,
    OwnedFd,
    OwnedFd,
)> {
    ensure!(
        super::layer_landlock_abi().is_some(),
        "managed WSL requires Landlock ABI 6 or newer"
    );
    let bubblewrap = std::fs::canonicalize(BUBBLEWRAP)
        .context("managed WSL requires Bubblewrap at /usr/bin/bwrap")?;
    ensure!(
        bubblewrap.starts_with("/usr") && bubblewrap.ancestors().all(super::only_root_can_write),
        "managed WSL requires a root-owned Bubblewrap installation"
    );
    let mounts = prepare_mounts(request)?;
    let executable =
        File::open("/proc/self/exe").context("cannot pin the guest runner executable")?;
    let (marker, prepared) = tokio::net::unix::pipe::pipe()?;
    let marker = marker.into_blocking_fd()?;
    let prepared = prepared.into_nonblocking_fd()?;
    // The host's start permission. The guest reads one byte after it has proved its sandbox and
    // before it forks the shell; holding the write end here means an abandoned setup can never
    // run the command on its own.
    let (start, start_reader) = tokio::net::unix::pipe::pipe()?;
    let start = start.into_blocking_fd()?;
    let start_reader = start_reader.into_blocking_fd()?;
    let mut command = tokio::process::Command::new(bubblewrap);
    command
        .env_clear()
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .args([
            "--unshare-user",
            "--unshare-pid",
            "--unshare-ipc",
            "--unshare-uts",
            "--unshare-net",
            "--unshare-cgroup-try",
            "--disable-userns",
            "--die-with-parent",
            "--as-pid-1",
            "--new-session",
            "--tmpfs",
            "/",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--clearenv",
            "--setenv",
            "PATH",
            "/usr/bin:/bin:/usr/sbin:/sbin",
            "--setenv",
            "HOME",
            "/tmp",
            "--setenv",
            "TMPDIR",
            "/tmp",
            "--setenv",
            "LANG",
            "C.UTF-8",
            "--chdir",
            WORKING_DIRECTORY,
        ]);
    command.args([
        "--size",
        &TEMPORARY_BYTES.to_string(),
        "--tmpfs",
        TEMPORARY_DIRECTORY,
    ]);
    let runtime = add_runtime(&mut command)?;
    // WSL places host-backed libraries and kernel files beneath /usr. Mask those trees before
    // the command can see them. Other runtime submounts remain unsupported.
    for &path in MASKED_RUNTIME_DIRECTORIES {
        if Path::new(path).is_dir() {
            command.args(["--tmpfs", path, "--remount-ro", path]);
        }
    }
    for mount in &mounts {
        command
            .arg(if mount.writable {
                "--bind-fd"
            } else {
                "--ro-bind-fd"
            })
            .arg(mount.source.as_raw_fd().to_string())
            .arg(&mount.destination);
    }
    command.args([
        "--",
        &format!("/proc/self/fd/{}", executable.as_raw_fd()),
        "subshell-exec",
        "--ready-descriptor",
        &marker.as_raw_fd().to_string(),
        "--start-descriptor",
        &start_reader.as_raw_fd().to_string(),
    ]);
    for directory in &runtime {
        command.arg("--read-only").arg(directory);
    }
    for mount in &mounts {
        command
            .arg(if mount.writable {
                "--writable"
            } else {
                "--read-only"
            })
            .arg(&mount.destination);
    }
    command.arg("--").arg(&request.script);
    let parent = std::process::id() as libc::pid_t;
    // SAFETY: the closure uses only async-signal-safe operations on descriptors we own. The
    // parent thread is the single-threaded runner, so the parent-death signal has its lifetime.
    let tree = unsafe {
        crate::process::spawn_tree_with_pre_exec(&mut command, move || {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) == -1
                || libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1
            {
                return Err(io::Error::last_os_error());
            }
            if libc::getppid() != parent {
                libc::_exit(RUNNER_ERROR);
            }
            for descriptor in [
                executable.as_raw_fd(),
                marker.as_raw_fd(),
                start_reader.as_raw_fd(),
            ]
            .into_iter()
            .chain(mounts.iter().map(|mount| mount.source.as_raw_fd()))
            {
                if libc::fcntl(descriptor, libc::F_SETFD, 0) == -1 {
                    return Err(io::Error::last_os_error());
                }
            }
            Ok(())
        })
    }
    .context("cannot start managed Bubblewrap command")?;
    let mut tree = tree;
    let stdout = tree.take_stdout()?;
    let stderr = tree.take_stderr()?;
    Ok((tree, stdout, stderr, prepared, start))
}

struct MountEntry<'a> {
    id: u64,
    point: &'a str,
    options: &'a str,
    filesystem: &'a str,
    propagates: bool,
}

impl MountEntry<'_> {
    fn require_options(&self, options: &[&str]) -> Result<()> {
        for required in options {
            ensure!(
                self.options.split(',').any(|option| option == *required),
                "sandbox mount {} lacks {required}",
                self.point
            );
        }
        Ok(())
    }
}

fn visible_runtime_mask_ids() -> Result<Vec<(&'static str, u64)>> {
    let mut masks = Vec::new();
    for &path in MASKED_RUNTIME_DIRECTORIES {
        let directory = match File::open(path) {
            Ok(directory) => directory,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(error).with_context(|| format!("cannot open runtime mask {path}"));
            }
        };
        let descriptor = directory.as_raw_fd();
        let details = std::fs::read_to_string(format!("/proc/self/fdinfo/{descriptor}"))?;
        let id = details
            .lines()
            .find_map(|line| line.strip_prefix("mnt_id:"))
            .context("missing runtime mount identity")?
            .trim()
            .parse()?;
        masks.push((path, id));
    }
    Ok(masks)
}

fn verify_mount_table(
    text: &str,
    writable: &[PathBuf],
    read_only: &[PathBuf],
    masks: &[(&str, u64)],
) -> Result<()> {
    let mut mounts = Vec::new();
    for line in text.lines() {
        let mut fields = line.split_ascii_whitespace();
        let id = fields.next().context("missing mount id")?.parse()?;
        let point = fields.nth(3).context("missing mount point")?;
        let options = fields.next().context("missing mount options")?;
        let mut propagates = false;
        loop {
            let field = fields.next().context("missing mount field separator")?;
            if field == "-" {
                break;
            }
            propagates |= field
                .split_once(':')
                .is_some_and(|(key, _)| matches!(key, "shared" | "master" | "propagate_from"));
        }
        let filesystem = fields.next().context("missing mount filesystem")?;
        mounts.push(MountEntry {
            id,
            point,
            options,
            filesystem,
            propagates,
        });
    }
    for &(path, id) in masks {
        ensure!(
            mounts.iter().any(|mount| mount.id == id
                && mount.point == path
                && mount.filesystem == "tmpfs"
                && !mount.propagates
                && ["ro", "nodev", "nosuid"]
                    .iter()
                    .all(|required| mount.options.split(',').any(|option| option == *required))),
            "runtime mask at {path} is not a read-only tmpfs"
        );
    }
    // The kernel lists mounts underneath an overmount as well. Only ignore the subtree if opening
    // its root actually reached the mask, not simply because a mount table row claims it exists.
    mounts.retain(|mount| {
        !masks.iter().any(|(path, _)| {
            mount.point == *path
                || mount
                    .point
                    .strip_prefix(path)
                    .is_some_and(|tail| tail.starts_with('/'))
        })
    });
    let unique = |point: &str| -> Result<&MountEntry<'_>> {
        let mut matching = mounts.iter().filter(|mount| mount.point == point);
        let mount = matching
            .next()
            .with_context(|| format!("missing sandbox mount at {point}"))?;
        ensure!(
            matching.next().is_none(),
            "multiple sandbox mounts at {point}"
        );
        Ok(mount)
    };
    let scratch = unique(TEMPORARY_DIRECTORY)?;
    ensure!(
        scratch.filesystem == "tmpfs",
        "expected a private guest /tmp"
    );
    let root = unique("/")?;
    ensure!(root.filesystem == "tmpfs", "expected a private guest root");
    root.require_options(&["nodev", "nosuid"])?;
    let proc = unique("/proc")?;
    ensure!(proc.filesystem == "proc", "expected a private guest /proc");
    proc.require_options(&["nodev", "nosuid", "noexec"])?;
    for mount in &mounts {
        // A shared or slave bind can gain a new submount after this check. Only the individual
        // kernel device nodes installed by bwrap may have a propagation parent.
        ensure!(
            !mount.propagates
                || (mount.filesystem == "devtmpfs"
                    && matches!(
                        mount.point,
                        "/dev/null"
                            | "/dev/zero"
                            | "/dev/full"
                            | "/dev/random"
                            | "/dev/urandom"
                            | "/dev/tty"
                    )),
            "sandbox mount {} can receive outside mounts",
            mount.point
        );
    }
    for (directory, access) in writable
        .iter()
        .map(|path| (path.as_path(), "rw"))
        .chain(read_only.iter().map(|path| (path.as_path(), "ro")))
        .chain([(Path::new(TEMPORARY_DIRECTORY), "rw")])
    {
        let directory = directory.to_str().context("non-Unicode sandbox mount")?;
        unique(directory)?.require_options(&[access, "nodev", "nosuid"])?;
        ensure!(
            !mounts.iter().any(|mount| mount
                .point
                .strip_prefix(directory)
                .is_some_and(|tail| tail.starts_with('/'))),
            "nested mounts are not supported under {directory}"
        );
    }
    Ok(())
}

fn restrict_command_syscalls() -> Result<()> {
    use std::mem::offset_of;

    // A private network namespace does not hide pathname Unix sockets in the bound roots, and
    // AF_VSOCK does not reliably follow IP namespace isolation. Deny both ways the kernel hands
    // out connected endpoints: socketpair returns a connected pair without calling socket(2).
    // io_uring can open sockets without either call.
    let (architecture, syscall_mask) = match std::env::consts::ARCH {
        "x86_64" if cfg!(target_pointer_width = "64") => (0xc000_003e, 0x4000_0000),
        "aarch64" if cfg!(target_endian = "little") => (0xc000_00b7, 0),
        architecture => anyhow::bail!("managed WSL does not support seccomp on {architecture}"),
    };
    let instruction = |code: u32, value, on_true, on_false| libc::sock_filter {
        code: code as u16,
        jt: on_true,
        jf: on_false,
        k: value,
    };
    let load = |offset| instruction(libc::BPF_LD | libc::BPF_W | libc::BPF_ABS, offset, 0, 0);
    let equals = |value, yes, no| instruction(libc::BPF_JMP | libc::BPF_JEQ, value, yes, no);
    let end = |value| instruction(libc::BPF_RET | libc::BPF_K, value, 0, 0);
    let kill = end(libc::SECCOMP_RET_KILL_PROCESS);
    let deny = end(libc::SECCOMP_RET_ERRNO | libc::EPERM as u32);
    let mut instructions = vec![
        load(offset_of!(libc::seccomp_data, arch) as u32),
        equals(architecture, 1, 0),
        kill,
        load(offset_of!(libc::seccomp_data, nr) as u32),
        // The x32 ABI shares the x86-64 architecture field but uses different syscall numbers.
        instruction(libc::BPF_JMP | libc::BPF_JSET, syscall_mask, 0, 1),
        kill,
    ];
    // Joining a user namespace can also clear death signals, and asynchronous kernel helpers
    // must not become an alternate channel out of the sandbox.
    for syscall in [
        libc::SYS_socket,
        libc::SYS_socketpair,
        libc::SYS_io_uring_setup,
        libc::SYS_setns,
        libc::SYS_request_key,
        libc::SYS_add_key,
        libc::SYS_keyctl,
    ] {
        instructions.extend([equals(syscall as u32, 0, 1), deny]);
    }
    // PID 1 must not clear its parent-death signal, or a command in a new session can outlive
    // both the Bubblewrap monitor and the host lease.
    instructions.extend([
        equals(libc::SYS_prctl as u32, 0, 3),
        load(offset_of!(libc::seccomp_data, args) as u32),
        equals(libc::PR_SET_PDEATHSIG as u32, 0, 1),
        deny,
        end(libc::SECCOMP_RET_ALLOW),
    ]);
    let program = libc::sock_fprog {
        len: u16::try_from(instructions.len())?,
        filter: instructions.as_mut_ptr(),
    };
    // SAFETY: the program and each instruction are initialized and available until seccomp has
    // copied them. NO_NEW_PRIVS was set before starting Bubblewrap.
    let result = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_SET_MODE_FILTER,
            0u32,
            &raw const program,
        )
    };
    if result == -1 {
        return Err(io::Error::last_os_error()).context("cannot install the guest syscall filter");
    }
    Ok(())
}

/// Verify Bubblewrap's mounts and apply the second confinement layer before interpreting a script.
pub(crate) fn run_command(
    ready_descriptor: RawFd,
    start_descriptor: RawFd,
    writable: &[PathBuf],
    read_only: &[PathBuf],
    script: &str,
) -> anyhow::Error {
    use std::os::unix::process::CommandExt as _;

    let setup: Result<()> = (|| {
        // This runner stays namespace PID 1 for the whole command. A command that execs its way
        // into PID 1 would be able to drop the parent-death signal from a non-leader thread; and a
        // command that exits while its background children live on would leave them unreaped.
        // Holding init here means the namespace outlives the command only until this function
        // tears the rest of it down, and a killed init always takes every descendant with it.
        ensure!(std::process::id() == 1, "expected a private PID namespace");
        ensure!(ready_descriptor > 2, "missing the guest readiness pipe");
        ensure!(start_descriptor > 2, "missing the guest start pipe");
        ensure!(
            start_descriptor != ready_descriptor,
            "the guest readiness and start pipes must be distinct"
        );
        let mounts = std::fs::read_to_string("/proc/self/mountinfo")
            .context("cannot verify sandbox mounts")?;
        verify_mount_table(&mounts, writable, read_only, &visible_runtime_mask_ids()?)?;
        restrict_command_syscalls()?;
        let readable: Vec<_> = writable
            .iter()
            .chain(read_only)
            .cloned()
            .chain([PathBuf::from("/proc"), PathBuf::from("/dev")])
            .collect();
        super::confine_command(writable, Some(&readable), &[PathBuf::from(
            TEMPORARY_DIRECTORY,
        )])?;
        mark_extra_close_on_exec()?;
        // SAFETY: the buffer contains a single initialized byte. write checks the descriptor.
        if unsafe { libc::write(ready_descriptor, [SETUP_READY].as_ptr().cast(), 1) } != 1 {
            return Err(io::Error::last_os_error()).context("cannot signal guest readiness");
        }
        // Setup is proved and reported; the host decides whether the command may exist. Nothing in
        // this namespace runs the shell until that byte arrives, and an absent host is a refusal
        // rather than a default start.
        let mut start = [0u8];
        loop {
            // SAFETY: the descriptor is open and the buffer is one byte the kernel may fill.
            let read = unsafe { libc::read(start_descriptor, start.as_mut_ptr().cast(), 1) };
            if read == 1 {
                ensure!(
                    start[0] == SETUP_READY,
                    "the host sent an unexpected start marker"
                );
                break;
            }
            if read == 0 {
                bail!("the host ended before the sandbox was started");
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error).context("cannot read the guest start pipe");
            }
        }
        Ok(())
    })();
    if let Err(error) = setup {
        return error;
    }
    // The shell is a child, never the namespace init, so this process keeps the parent-death
    // signal that Bubblewrap installed and the seccomp rule that forbids clearing it.
    // SAFETY: the setup above leaves this process single-threaded, so the child may only run
    // async-signal-safe code before exec. Both branches own the descriptors they inherited.
    let child = unsafe { libc::fork() };
    if child == -1 {
        return anyhow::Error::new(io::Error::last_os_error())
            .context("cannot start the guest shell");
    }
    if child == 0 {
        let error = std::process::Command::new(SHELL)
            .args(["-c", script])
            .exec();
        eprintln!("meka subshell-command: cannot execute the guest shell: {error}");
        // SAFETY: no destructors may run in a forked child before exec.
        unsafe { libc::_exit(RUNNER_ERROR) }
    }
    // The fork succeeded: the namespace process exists. This second marker is the acknowledgement
    // that the host's permit became an observed start, written only after the shell is a real
    // process. A host that cannot be told has withdrawn; the shell is ended with the runner.
    // SAFETY: the descriptor is open and the buffer is a single initialized byte.
    if unsafe { libc::write(ready_descriptor, [SETUP_STARTED].as_ptr().cast(), 1) } != 1 {
        let error = io::Error::last_os_error();
        // SAFETY: `child` is this runner's own forked shell; SIGKILL ends it and its namespace.
        unsafe { libc::kill(child, libc::SIGKILL) };
        return anyhow::Error::new(error).context("cannot report the guest start");
    }
    let mut status = 0;
    loop {
        // SAFETY: `status` is initialized and `child` is the process just forked.
        let waited = unsafe { libc::waitpid(child, &mut status, 0) };
        if waited == child {
            break;
        }
        if waited == -1 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return anyhow::Error::new(error).context("cannot wait for the guest shell");
        }
    }
    // The shell may have left background processes, which the kernel reparents to PID 1. The
    // command's lifetime ends with the shell, as it did when the shell was PID 1 itself, so take
    // the rest of the namespace down before leaving. PID 1 is excluded from `kill(-1)`.
    // SAFETY: SIGKILL to every other process in this private namespace is the teardown this
    // runner owns; the call cannot be undone and has no memory-safety preconditions.
    unsafe { libc::kill(-1, libc::SIGKILL) };
    if libc::WIFEXITED(status) {
        // SAFETY: exit never returns and needs no cleanup beyond the teardown above.
        unsafe { libc::_exit(libc::WEXITSTATUS(status)) }
    }
    if libc::WIFSIGNALED(status) {
        let signal = libc::WTERMSIG(status);
        // Report the same signal the shell died from, rather than folding it into an exit code.
        // SAFETY: restoring the default disposition and raising it cannot corrupt Rust state,
        // and the fallback exit covers a blocked or ignored signal.
        unsafe {
            libc::signal(signal, libc::SIG_DFL);
            libc::raise(signal);
            libc::_exit(128 + signal)
        }
    }
    // SAFETY: exit never returns.
    unsafe { libc::_exit(RUNNER_ERROR) }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request_frame() -> String {
        let version = subshell::VERSION;
        let op = subshell::new_op();
        format!(
            "{{\"version\":{version},\"op\":\"{op}\",\"access\":\"workspace\",\"working_directory\":\"/home/test/work\",\
             \"workspace\":[],\"readable\":[],\"timeout_ms\":50,\"script\":\"echo ready\"}}"
        )
    }

    #[tokio::test]
    async fn accepts_only_one_bounded_versioned_request_line() {
        let frame = format!("{}\nnot a command", request_frame());
        let mut wire = frame.as_bytes();
        let request = read_request(&mut wire).await.unwrap();
        assert!(request.access == Permission::Workspace);
        assert_eq!(request.script, "echo ready");
        assert_eq!(request.timeout(), Duration::from_millis(50));
        // The supervisor, not the request reader, treats these bytes as loss of the lease.
        assert_eq!(wire, b"not a command");

        let padding = " ".repeat(REQUEST_BYTES);
        let too_large = format!("{}{padding}\n", request_frame());
        for (frame, detail) in [
            (request_frame(), "missing or oversized"),
            (too_large, "missing or oversized"),
            (
                format!(
                    "{}\n",
                    request_frame().replace(
                        &format!("\"version\":{}", subshell::VERSION),
                        "\"version\":4"
                    )
                ),
                "version 4",
            ),
            (
                format!("{}\n", request_frame().replace(":50,", ":0,")),
                "invalid subshell timeout",
            ),
            (
                format!(
                    "{}\n",
                    request_frame().replace(":\"workspace\"", ":\"unrestricted\"")
                ),
                "subshell access must be read or workspace",
            ),
            (
                format!(
                    "{}\n",
                    request_frame().replace("echo ready", "echo \\u0000")
                ),
                "invalid subshell script",
            ),
            (
                format!(
                    "{},\"unknown\":false}}\n",
                    request_frame().trim_end_matches('}')
                ),
                "unknown field",
            ),
        ] {
            let outcome = read_request(&mut frame.as_bytes()).await;
            let error = outcome
                .err()
                .unwrap_or_else(|| panic!("expected refusal: {detail}"));
            assert!(
                format!("{error:#}").contains(detail),
                "expected {detail:?}: {error:#}"
            );
        }
    }

    const MOUNT_TABLE: &str = "\
1 0 0:10 / / rw,nosuid,nodev - tmpfs tmpfs rw
2 1 0:11 / /proc rw,nosuid,nodev,noexec - proc proc rw
3 1 0:12 / /tmp rw,nosuid,nodev - tmpfs tmpfs rw
4 1 8:1 /work /workspace rw,nosuid,nodev - ext4 /dev/sda rw
5 1 8:1 /docs /references/0 ro,nosuid,nodev - ext4 /dev/sda rw
6 1 8:1 /usr /usr ro,nosuid,nodev - ext4 /dev/sda rw
7 6 0:13 / /usr/lib/wsl/lib ro,nosuid,nodev master:20 - 9p drivers ro
8 6 0:14 / /usr/lib/wsl ro,nosuid,nodev - tmpfs tmpfs rw
";

    fn verify(text: &str, masks: &[(&str, u64)]) -> Result<()> {
        verify_mount_table(
            text,
            &[WORKING_DIRECTORY.into()],
            &["/references/0".into(), "/usr".into()],
            masks,
        )
    }

    #[test]
    fn a_runtime_mask_must_be_the_visible_read_only_tmpfs() {
        let path = "/usr/lib/wsl";
        verify(MOUNT_TABLE, &[(path, 8)]).unwrap();
        for masks in [&[][..], &[(path, 7)][..]] {
            assert!(verify(MOUNT_TABLE, masks).is_err());
        }
        let writable = MOUNT_TABLE.replace("wsl ro,", "wsl rw,");
        assert!(verify(&writable, &[(path, 8)]).is_err());
        let sibling = MOUNT_TABLE.replace("/usr/lib/wsl/lib", "/usr/lib/wsl-other/lib");
        assert!(verify(&sibling, &[(path, 8)]).is_err());
    }

    #[test]
    fn workspace_mounts_are_checked_before_the_shell_runs() {
        for (from, to, reason) in [
            ("/references/0 ro,", "/references/0 rw,", "lacks ro"),
            (
                "/workspace rw,nosuid,nodev",
                "/workspace rw,nosuid",
                "lacks nodev",
            ),
            (
                "/workspace rw,nosuid,nodev",
                "/workspace rw,nosuid,nodev master:1",
                "receive outside mounts",
            ),
            (
                "/workspace rw,nosuid,nodev",
                "/not-workspace rw,nosuid,nodev",
                "missing sandbox mount",
            ),
        ] {
            let error = verify(&MOUNT_TABLE.replace(from, to), &[("/usr/lib/wsl", 8)]).unwrap_err();
            assert!(error.to_string().contains(reason), "{error:#}");
        }
        for (point, reason) in [
            ("/workspace", "multiple sandbox mounts"),
            ("/workspace/sub", "nested mounts"),
        ] {
            let table =
                format!("{MOUNT_TABLE}9 4 0:20 / {point} rw,nosuid,nodev - tmpfs tmpfs rw\n");
            let error = verify(&table, &[("/usr/lib/wsl", 8)]).unwrap_err();
            assert!(error.to_string().contains(reason), "{error:#}");
        }
    }

    fn scratch_request(scratch: &str) -> String {
        let version = subshell::VERSION;
        let op = subshell::new_op();
        format!(
            "{{\"version\":{version},\"op\":\"{op}\",\"access\":\"workspace\",\
             \"working_directory\":\"{SCRATCH_ROOT}/0123456789abcdef\",\"workspace\":[],\
             \"readable\":[],\"timeout_ms\":50,\"script\":\"exit 0\",\"scratch\":{scratch}}}"
        )
    }

    #[tokio::test]
    async fn a_scratch_request_pins_its_own_workspace_and_no_other() {
        let good = scratch_request(&format!(
            "{{\"path\":\"{SCRATCH_ROOT}/0123456789abcdef\",\"quota_bytes\":1048576}}"
        ));
        let frame = format!("{good}\n");
        let request = read_request(&mut frame.as_bytes()).await.unwrap();
        let scratch = request.scratch.as_ref().unwrap();
        assert!(!scratch.create);
        assert_eq!(scratch.quota_bytes, 1048576);
        let created = format!("{good}\n").replace(
            "\"quota_bytes\":1048576}",
            "\"quota_bytes\":1048576,\"create\":true}",
        );
        let request = read_request(&mut created.as_bytes()).await.unwrap();
        assert!(request.scratch.as_ref().unwrap().create);
        for (from, to, detail) in [
            (
                "\"access\":\"workspace\"",
                "\"access\":\"read\"",
                "workspace access",
            ),
            (
                "\"workspace\":[]",
                "\"workspace\":[\"/home/test/other\"]",
                "no additional workspace mounts",
            ),
            (
                &format!("\"working_directory\":\"{SCRATCH_ROOT}/0123456789abcdef\""),
                "\"working_directory\":\"/home/test/work\"",
                "mounts its own workspace",
            ),
            (
                &format!("\"path\":\"{SCRATCH_ROOT}/0123456789abcdef\""),
                "\"path\":\"/home/test/work\"",
                "invalid scratch workspace path",
            ),
            (
                &format!("\"path\":\"{SCRATCH_ROOT}/0123456789abcdef\""),
                &format!("\"path\":\"{SCRATCH_ROOT}/aa/bb\""),
                "invalid scratch workspace path",
            ),
            (
                &format!("\"path\":\"{SCRATCH_ROOT}/0123456789abcdef\""),
                &format!("\"path\":\"{SCRATCH_ROOT}0123456789abcdef\""),
                "invalid scratch workspace path",
            ),
            (
                "\"quota_bytes\":1048576",
                "\"quota_bytes\":0",
                "invalid scratch quota",
            ),
            (
                "\"quota_bytes\":1048576",
                &format!("\"quota_bytes\":{}", subshell::MAX_SCRATCH_BYTES + 1),
                "invalid scratch quota",
            ),
        ] {
            let frame = format!("{}\n", good.replace(from, to));
            let outcome = read_request(&mut frame.as_bytes()).await;
            let error = outcome
                .err()
                .unwrap_or_else(|| panic!("expected refusal: {detail}"));
            assert!(
                format!("{error:#}").contains(detail),
                "expected {detail:?}: {error:#}"
            );
        }
    }

    fn scratch_id() -> String {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        format!(
            "{:016x}",
            0x6d65_6b61_0000_0000u64.wrapping_add(NEXT.fetch_add(1, Ordering::SeqCst))
        )
    }

    #[test]
    fn a_scratch_workspace_is_private_reaped_and_quota_bound() {
        use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};

        let root = std::env::temp_dir().join(format!(
            "meka-scratch-test-{}-{:016x}",
            std::process::id(),
            0x6d65_6b61_0000_0000u64
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&root)
            .unwrap();
        // SAFETY: the test process has no other thread reading this variable before it is set, and
        // only this test redirects the scratch root.
        unsafe {
            std::env::set_var("MEKA_TEST_SCRATCH_ROOT", &root);
        }
        let root = root.to_string_lossy().into_owned();
        let spec = |path: &str, quota_bytes: u64, create: bool| Scratch {
            path: path.into(),
            quota_bytes,
            create,
        };
        let own = format!("{root}/{}", scratch_id());
        // The one call allowed to create makes the workspace private to this user.
        prepare_scratch_workspace(&spec(&own, 1024 * 1024, true), ScratchUse::Execution).unwrap();
        let metadata = std::fs::metadata(&own).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
        // A workspace id is never handed out twice.
        assert!(
            prepare_scratch_workspace(&spec(&own, 1024 * 1024, true), ScratchUse::Execution)
                .is_err()
        );
        // An expired workspace is gone, not quietly recreated empty.
        let missing = format!("{root}/{}", scratch_id());
        let error = match prepare_scratch_workspace(
            &spec(&missing, 1024 * 1024, false),
            ScratchUse::Execution,
        ) {
            Err(error) => error,
            Ok(_) => panic!("an absent workspace is refused, not quietly recreated"),
        };
        assert!(format!("{error:#}").contains("expired"), "{error:#}");
        // A workspace name that is a symlink is refused instead of followed.
        let linked = format!("{root}/{}", scratch_id());
        std::os::unix::fs::symlink(&own, &linked).unwrap();
        assert!(
            prepare_scratch_workspace(&spec(&linked, 1024 * 1024, false), ScratchUse::Execution)
                .is_err()
        );
        std::fs::remove_file(&linked).unwrap();
        // A sibling past its lease is reaped by the next use; a live one is left alone.
        let stale = format!("{root}/{}", scratch_id());
        prepare_scratch_workspace(&spec(&stale, 1024 * 1024, true), ScratchUse::Execution).unwrap();
        let past = std::time::SystemTime::now() - SCRATCH_LEASE - Duration::from_secs(60);
        std::fs::File::open(&stale)
            .unwrap()
            .set_times(std::fs::FileTimes::new().set_modified(past))
            .unwrap();
        prepare_scratch_workspace(&spec(&own, 1024 * 1024, false), ScratchUse::Execution).unwrap();
        assert!(!Path::new(&stale).exists(), "the stale workspace was kept");
        assert!(Path::new(&own).exists(), "the live workspace was reaped");
        // The quota is held on every execution use, not only while staging.
        std::fs::write(Path::new(&own).join("blob"), vec![0u8; 128 * 1024]).unwrap();
        let error = match prepare_scratch_workspace(&spec(&own, 1024, false), ScratchUse::Execution)
        {
            Err(error) => error,
            Ok(_) => panic!("an over-quota execution use is refused at admission"),
        };
        assert!(format!("{error:#}").contains("quota"), "{error:#}");
        // And the bounded recovery paths still reach an over-quota tree, so one does not strand
        // the other.
        prepare_scratch_workspace(&spec(&own, 1024, false), ScratchUse::Recovery).unwrap();
        std::fs::remove_dir_all(&own).expect("the workspace is cleaned up");
        std::fs::remove_dir_all(&root).expect("the test root is cleaned up");
    }

    #[test]
    fn remove_directory_tree_removes_directories_and_files() {
        let root = std::env::temp_dir().join(format!(
            "meka-scratch-remove-{}-{:016x}",
            std::process::id(),
            0x6d65_6b61_0000_0001u64
        ));
        std::fs::create_dir_all(root.join("nested").join("deeper")).unwrap();
        std::fs::write(root.join("top"), b"top").unwrap();
        std::fs::write(root.join("nested").join("file"), b"file").unwrap();
        std::fs::write(root.join("nested").join("deeper").join("leaf"), b"leaf").unwrap();
        let opened = std::fs::File::open(&root).unwrap();
        remove_directory_tree(&opened).unwrap();
        let left = std::fs::read_dir(&root).unwrap().count();
        assert_eq!(left, 0, "the opened tree is empty");
        std::fs::remove_dir_all(&root).expect("the test root is cleaned up");
    }

    const DRIVE_MOUNTS: &str = "\
sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0\n\
/dev/sdc /mnt/c 9p rw,noatime,aname=drvfs;path=C:\\;uid=1000;gid=1000;metadata 0 0\n\
/dev/sdd /mnt/wsl/PHYSICALDRIVE0p1 9p rw,noatime,aname=drvfs;path=D:\\data;uid=1000 0 0\n\
/dev/sde /mnt/e 9p rw,noatime,aname=drvfs;path=E:\\dev\\040projects;uid=1000 0 0\n";

    #[test]
    fn parse_mounts_finds_only_drvfs_drive_mounts() {
        let drives = parse_mounts(DRIVE_MOUNTS);
        assert_eq!(drives.len(), 3);
        assert_eq!(drives[0].windows_root, "C:\\");
        assert_eq!(drives[0].point, "/mnt/c");
        assert_eq!(drives[1].windows_root, "D:\\data");
        assert_eq!(drives[1].point, "/mnt/wsl/PHYSICALDRIVE0p1");
        assert_eq!(drives[2].point, "/mnt/e");
    }

    #[test]
    fn unescape_octal_decodes_the_kernel_mount_escapes() {
        assert_eq!(unescape_octal("/mnt/dev\\040projects"), "/mnt/dev projects");
        assert_eq!(unescape_octal("/plain/path"), "/plain/path");
    }

    #[test]
    fn resolve_windows_guest_path_picks_the_longest_match() {
        let (point, path) =
            resolve_windows_guest_path(DRIVE_MOUNTS, "D:\\data\\src\\main.rs").unwrap();
        assert_eq!(point, "/mnt/wsl/PHYSICALDRIVE0p1");
        assert_eq!(path, Path::new("/mnt/wsl/PHYSICALDRIVE0p1/src/main.rs"));
        // The drive root maps to the mount point itself.
        let (point, path) = resolve_windows_guest_path(DRIVE_MOUNTS, "C:\\").unwrap();
        assert_eq!(point, "/mnt/c");
        assert_eq!(path, Path::new("/mnt/c"));
    }

    #[test]
    fn resolve_windows_guest_path_is_case_insensitive_on_components() {
        let (_, path) = resolve_windows_guest_path(DRIVE_MOUNTS, "c:\\Users\\Test").unwrap();
        assert_eq!(path, Path::new("/mnt/c/Users/Test"));
    }

    #[test]
    fn resolve_windows_guest_path_refuses_an_unmounted_path() {
        assert!(resolve_windows_guest_path(DRIVE_MOUNTS, "Z:\\nowhere").is_err());
    }

    /// The host's start gate answers the lease and the deadline before a shell can exist: a
    /// readiness notice is not permission to run, and neither a lost lease nor an expired budget
    /// is overridden by one.
    #[tokio::test]
    async fn a_setup_ready_notice_does_not_start_a_command_after_the_lease_or_deadline() {
        use tokio::io::AsyncWriteExt as _;

        async fn gate(lease: tokio::io::DuplexStream, deadline: tokio::time::Instant) -> Setup {
            let (_writer, reader) = tokio::net::unix::pipe::pipe().expect("a pipe");
            let reader = reader.into_nonblocking_fd().expect("nonblocking");
            // SAFETY: `reader` is the read end this test owns for the guard's lifetime.
            let prepared = unsafe {
                tokio::io::unix::AsyncFd::register_with_interest(
                    reader,
                    tokio::io::Interest::READABLE,
                )
            }
            .expect("registered");
            await_marker(&prepared, &mut BufReader::new(lease), deadline, SETUP_READY)
                .await
                .expect("the gate")
        }

        let (mut lease_writer, lease_reader) = tokio::io::duplex(8);
        lease_writer
            .write_all(b"x")
            .await
            .expect("a lease with a pending byte");
        drop(lease_writer);
        assert!(matches!(
            gate(
                lease_reader,
                tokio::time::Instant::now() + Duration::from_secs(1)
            )
            .await,
            Setup::Canceled
        ));

        let (_lease_writer, lease_reader) = tokio::io::duplex(8);
        assert!(matches!(
            gate(lease_reader, tokio::time::Instant::now()).await,
            Setup::TimedOut
        ));
    }

    /// A readiness byte on the pipe is what the gate reports ready for; the byte is checked, not
    /// just its arrival.
    #[tokio::test]
    async fn a_setup_marker_is_read_as_ready() {
        let (marker, prepared) = tokio::net::unix::pipe::pipe().expect("a pipe");
        let mut marker = File::from(marker.into_blocking_fd().expect("blocking"));
        marker
            .write_all(&[SETUP_READY])
            .expect("write the readiness marker");
        drop(marker);
        let prepared = prepared.into_nonblocking_fd().expect("nonblocking");
        // SAFETY: `prepared` is the read end this test owns for the guard's lifetime.
        let prepared = unsafe {
            tokio::io::unix::AsyncFd::register_with_interest(
                prepared,
                tokio::io::Interest::READABLE,
            )
        }
        .expect("registered");
        let (_lease_writer, lease_reader) = tokio::io::duplex(8);
        let setup = await_marker(
            &prepared,
            &mut BufReader::new(lease_reader),
            tokio::time::Instant::now() + Duration::from_secs(1),
            SETUP_READY,
        )
        .await
        .expect("the gate");
        assert!(matches!(setup, Setup::Ready));
    }

    /// The stage walk copies a regular tree into an opened workspace and refuses a link before it
    /// can carry a source outside the tree the runner opened.
    #[test]
    fn a_stage_walk_copies_a_tree_and_refuses_a_link() {
        let base = tempfile::tempdir_in("/var/tmp").expect("a test directory on the guest root");
        let source = base.path().join("source");
        let destination = base.path().join("destination");
        std::fs::create_dir(&source).expect("source");
        std::fs::create_dir(source.join("sub")).expect("subdirectory");
        std::fs::create_dir(&destination).expect("destination");
        std::fs::write(source.join("a.txt"), b"alpha").expect("a file");
        std::fs::write(source.join("sub/b.txt"), b"beta").expect("a nested file");
        let opened_destination =
            std::fs::File::open(&destination).expect("the destination directory");
        let scratch = Scratch {
            path: PathBuf::from(format!("{SCRATCH_ROOT}/0123456789abcdef")),
            quota_bytes: 1024 * 1024,
            create: true,
        };
        let guard = TransferGuard::without_lease(
            tokio::time::Instant::now() + std::time::Duration::from_secs(10),
        );
        let entries = stage_into(
            &MountRoot::Guest(source.clone()),
            &scratch,
            &opened_destination,
            &guard,
        )
        .expect("the tree is staged");
        assert_eq!(
            entries
                .iter()
                .filter(|entry| !entry.directory)
                .map(|entry| entry.path.as_str())
                .collect::<Vec<_>>(),
            vec!["a.txt", "sub/b.txt"]
        );
        assert_eq!(
            std::fs::read(destination.join("a.txt")).expect("copied file"),
            b"alpha"
        );
        assert_eq!(
            std::fs::read(destination.join("sub/b.txt")).expect("copied nested file"),
            b"beta"
        );

        std::os::unix::fs::symlink(source.join("a.txt"), source.join("link")).expect("symlink");
        let second = base.path().join("second");
        std::fs::create_dir(&second).expect("second destination");
        let opened_second = std::fs::File::open(&second).expect("the second destination");
        let error = stage_into(&MountRoot::Guest(source), &scratch, &opened_second, &guard)
            .expect_err("a link is refused");
        assert!(
            format!("{error:#}").contains("not a regular file"),
            "{error:#}"
        );
        std::fs::remove_dir_all(base.path()).expect("cleanup");
    }

    /// One upload manifest entry as a test announces it.
    fn upload_entry(path: &str, bytes: &[u8], directory: bool) -> subshell::TransferEntry {
        use sha2::Digest as _;

        subshell::TransferEntry {
            root: 0,
            path: path.to_owned(),
            len: if directory { 0 } else { bytes.len() as u64 },
            modified_secs: 0,
            modified_nanos: 0,
            digest: subshell::digest_hex(&sha2::Sha256::digest(bytes).into()),
            directory,
        }
    }

    /// An upload installs the snapshot its manifest announced: a directory entry creates its
    /// path, and a file entry lands with exactly the bytes its length counted, in the order the
    /// manifest carried them.
    #[tokio::test]
    async fn an_upload_installs_the_snapshot_its_manifest_announced() {
        let base = tempfile::tempdir_in("/var/tmp").expect("a test directory on the guest root");
        let destination = base.path().join("workspace");
        std::fs::create_dir(&destination).expect("workspace");
        let opened = std::fs::File::open(&destination).expect("the workspace directory");
        let entries = vec![
            upload_entry("a.txt", b"alpha", false),
            upload_entry("sub", b"", true),
            upload_entry("sub/b.txt", b"beta", false),
        ];
        let mut payload = Vec::new();
        payload.extend_from_slice(b"alpha");
        payload.extend_from_slice(b"beta");
        let mut lease = payload.as_slice();
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
        receive_upload(&mut lease, &entries, &opened, 1024 * 1024, deadline)
            .await
            .expect("the snapshot is installed");
        assert_eq!(
            std::fs::read(destination.join("a.txt")).expect("copied file"),
            b"alpha"
        );
        assert_eq!(
            std::fs::read(destination.join("sub/b.txt")).expect("copied nested file"),
            b"beta"
        );
        std::fs::remove_dir_all(base.path()).expect("cleanup");
    }

    /// An upload refuses bytes another digest announced: what lands in the workspace is what the
    /// manifest named, and a file whose hash disagrees refuses the snapshot instead of keeping a
    /// copy under an entry that says otherwise.
    #[tokio::test]
    async fn an_upload_refuses_bytes_another_digest_announced() {
        use sha2::Digest as _;

        let base = tempfile::tempdir_in("/var/tmp").expect("a test directory on the guest root");
        let destination = base.path().join("workspace");
        std::fs::create_dir(&destination).expect("workspace");
        let opened = std::fs::File::open(&destination).expect("the workspace directory");
        let mut entry = upload_entry("a.txt", b"alpha", false);
        entry.digest = subshell::digest_hex(&sha2::Sha256::digest(b"other").into());
        let mut lease = &b"alpha"[..];
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
        let error = receive_upload(&mut lease, &[entry], &opened, 1024 * 1024, deadline)
            .await
            .expect_err("another digest is refused");
        assert!(
            format!("{error:#}").contains("other bytes than the digest"),
            "{error:#}"
        );
        std::fs::remove_dir_all(base.path()).expect("cleanup");
    }

    /// An upload refuses a payload that ends before its manifest did: the pipe is the host's
    /// lease, so an early end is the host going away and never a short file to keep.
    #[tokio::test]
    async fn an_upload_refuses_a_payload_that_ends_early() {
        let base = tempfile::tempdir_in("/var/tmp").expect("a test directory on the guest root");
        let destination = base.path().join("workspace");
        std::fs::create_dir(&destination).expect("workspace");
        let opened = std::fs::File::open(&destination).expect("the workspace directory");
        let entries = vec![upload_entry("a.txt", b"alpha", false)];
        let mut lease = &b"alp"[..];
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
        let error = receive_upload(&mut lease, &entries, &opened, 1024 * 1024, deadline)
            .await
            .expect_err("an early end is refused");
        assert!(
            error.downcast_ref::<LeaseEnded>().is_some(),
            "an early end is the lease ending: {error:#}"
        );
        std::fs::remove_dir_all(base.path()).expect("cleanup");
    }

    /// An upload refuses a manifest that names one path twice, so no second write can reach what
    /// the first entry made.
    #[tokio::test]
    async fn an_upload_refuses_a_path_its_manifest_named_twice() {
        let base = tempfile::tempdir_in("/var/tmp").expect("a test directory on the guest root");
        let destination = base.path().join("workspace");
        std::fs::create_dir(&destination).expect("workspace");
        let opened = std::fs::File::open(&destination).expect("the workspace directory");
        let entries = vec![
            upload_entry("a.txt", b"alpha", false),
            upload_entry("a.txt", b"alpha", false),
        ];
        let mut payload = Vec::new();
        payload.extend_from_slice(b"alpha");
        payload.extend_from_slice(b"alpha");
        let mut lease = payload.as_slice();
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
        let error = receive_upload(&mut lease, &entries, &opened, 1024 * 1024, deadline)
            .await
            .expect_err("a repeated path is refused");
        assert!(format!("{error:#}").contains("twice"), "{error:#}");
        std::fs::remove_dir_all(base.path()).expect("cleanup");
    }

    /// An upload is judged by its announced totals before a byte of it is read: a snapshot larger
    /// than the workspace quota is refused with nothing written.
    #[tokio::test]
    async fn an_upload_larger_than_the_quota_is_refused_before_its_bytes() {
        let base = tempfile::tempdir_in("/var/tmp").expect("a test directory on the guest root");
        let destination = base.path().join("workspace");
        std::fs::create_dir(&destination).expect("workspace");
        let opened = std::fs::File::open(&destination).expect("the workspace directory");
        let entries = vec![upload_entry("a.txt", b"alpha", false)];
        let mut lease = &b"alpha"[..];
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
        let error = receive_upload(&mut lease, &entries, &opened, 4, deadline)
            .await
            .expect_err("an over-quota upload is refused");
        assert!(format!("{error:#}").contains("scratch quota"), "{error:#}");
        assert!(
            std::fs::read_dir(&destination)
                .expect("the workspace")
                .next()
                .is_none(),
            "a refused upload writes nothing"
        );
        std::fs::remove_dir_all(base.path()).expect("cleanup");
    }
}
