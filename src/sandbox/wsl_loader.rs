//! The deployment loader a managed WSL guest runs when it has no installed `meka-runner`.
//!
//! The launcher stages this program in a private temporary file it unlinks before executing, so
//! the file has no name when it runs. The loader then receives the controller's bundled runner
//! over the launcher pipe, seals it into an executable anonymous file, verifies the sealed
//! bytes, and runs it from that descriptor. The runner never touches the guest's filesystem and
//! cannot change between verification and execution.

#[cfg(target_os = "linux")]
mod linux {
    use std::{
        convert::Infallible,
        fs::File,
        io::{self, Read as _, Seek as _, SeekFrom, Write as _},
        os::fd::{AsRawFd as _, FromRawFd as _},
        process,
    };

    use sha2::{Digest as _, Sha256};

    /// The largest runner payload the deployment protocol carries.
    const MAX_RUNNER_BYTES: u64 = 128 * 1024 * 1024;
    /// The read size for streaming the payload into the file it will be sealed in.
    const CHUNK_BYTES: usize = 64 * 1024;
    // Linux UAPI values the libc crate does not expose on every version worth supporting:
    // `MFD_EXEC`, which kernels with a restrictive `vm.memfd_noexec` require for an executable
    // memory file, and `F_SEAL_EXEC`, which freezes the execute mode set before sealing.
    const MEMORY_EXECUTABLE: libc::c_uint = 0x10;
    const SEAL_EXECUTE_MODE: libc::c_int = 0x20;

    /// Runs until `execveat` replaces the process, or reports why deployment cannot proceed.
    pub(super) fn run() -> ! {
        match deploy() {
            Ok(never) => match never {},
            Err(error) => {
                eprintln!("meka: cannot deploy meka-runner: {error}");
                process::exit(126);
            }
        }
    }

    /// The controller sends a runner as a byte count, the SHA-256 of the payload, and the
    /// payload itself. Every read is a raw descriptor read: a buffered reader could consume the
    /// runner's own request past the payload and strand it here.
    fn deploy() -> io::Result<Infallible> {
        // SAFETY: these return the caller's identities and read no memory.
        if unsafe { libc::getuid() } == 0 || unsafe { libc::geteuid() } == 0 {
            return Err(io::Error::other(
                "the default distribution user must not be root",
            ));
        }
        // SAFETY: fd 0 is the process's own launcher pipe and is not owned elsewhere.
        let mut input = unsafe { File::from_raw_fd(libc::STDIN_FILENO) };
        let mut count = [0u8; 8];
        read_exact(&mut input, &mut count)?;
        let count = u64::from_le_bytes(count);
        if count == 0 || count > MAX_RUNNER_BYTES {
            return Err(io::Error::other("invalid runner payload length"));
        }
        let mut expected = [0u8; 32];
        read_exact(&mut input, &mut expected)?;
        let mut runner = sealed_file()?;
        let mut remaining = count;
        while remaining > 0 {
            let mut chunk = vec![0u8; remaining.min(CHUNK_BYTES as u64) as usize];
            read_exact(&mut input, &mut chunk)?;
            runner.write_all(&chunk)?;
            remaining -= chunk.len() as u64;
        }
        // The seals precede the digest so what is verified is the immutable file the descriptor
        // executes, not the stream that wrote it.
        // SAFETY: the descriptor is the file created above; the mode is read and execute for its
        // owner alone.
        if unsafe { libc::fchmod(runner.as_raw_fd(), 0o500) } == -1 {
            return Err(io::Error::last_os_error());
        }
        let seals = libc::F_SEAL_SEAL
            | libc::F_SEAL_GROW
            | libc::F_SEAL_SHRINK
            | libc::F_SEAL_WRITE
            | SEAL_EXECUTE_MODE;
        // SAFETY: the descriptor is the file created above and the seals are the documented
        // Linux UAPI bits.
        if unsafe { libc::fcntl(runner.as_raw_fd(), libc::F_ADD_SEALS, seals) } == -1 {
            return Err(io::Error::last_os_error());
        }
        runner.seek(SeekFrom::Start(0))?;
        let mut contents = Vec::new();
        runner.read_to_end(&mut contents)?;
        if Sha256::digest(&contents).as_slice() != expected.as_slice() {
            return Err(io::Error::other(
                "bundled runner failed SHA-256 verification",
            ));
        }
        let program = c"meka-runner";
        let verb = c"subshell-runner";
        let arguments = [program.as_ptr(), verb.as_ptr(), std::ptr::null()];
        let environment: [*const libc::c_char; 1] = [std::ptr::null()];
        // SAFETY: the empty pathname with `AT_EMPTY_PATH` executes the descriptor's own inode,
        // and both vectors are null-terminated arrays of literals for the duration of the call.
        unsafe {
            libc::syscall(
                libc::SYS_execveat,
                runner.as_raw_fd(),
                c"".as_ptr(),
                arguments.as_ptr(),
                environment.as_ptr(),
                libc::AT_EMPTY_PATH,
            )
        };
        Err(io::Error::last_os_error())
    }

    /// Reads exactly `into.len()` bytes, mapping a closed pipe to the reason deployment stopped.
    fn read_exact(input: &mut File, into: &mut [u8]) -> io::Result<()> {
        match input.read_exact(into) {
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => Err(io::Error::other(
                "host disconnected during runner deployment",
            )),
            result => result,
        }
    }

    /// The anonymous executable the payload is written into before it is sealed.
    fn sealed_file() -> io::Result<File> {
        // SAFETY: the name is a literal and the flags are the documented Linux UAPI values.
        let descriptor = unsafe {
            libc::memfd_create(
                c"meka-runner".as_ptr(),
                libc::MFD_ALLOW_SEALING | libc::MFD_CLOEXEC | MEMORY_EXECUTABLE,
            )
        };
        if descriptor == -1 {
            let error = io::Error::last_os_error();
            return Err(match error.kind() {
                io::ErrorKind::InvalidInput | io::ErrorKind::Unsupported => {
                    io::Error::other("this kernel cannot run an executable, sealed memory file")
                }
                _ => error,
            });
        }
        // SAFETY: the descriptor is the successful creation above and is owned nowhere else.
        Ok(unsafe { File::from_raw_fd(descriptor) })
    }
}

#[cfg(target_os = "linux")]
fn main() {
    linux::run();
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("meka: cannot deploy meka-runner: the deployment loader runs on Linux");
    std::process::exit(126);
}
