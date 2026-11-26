/// Returns rather than `expect`s, because `[lints.clippy] expect_used` reaches the build script
/// too: the Windows lint job compiles this file, and the panicking call was a hard error there
/// while every other platform cfg'd the block away and never saw it.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=build.rs");
    embed_git_revision();
    size_the_main_thread_stack();
    bundle_wsl_payloads()?;

    // The resource compiler is a build-dependency of the package, and the standalone harness the
    // tests at the bottom of this file run under is not one, so a test build leaves it out.
    #[cfg(all(windows, not(test)))]
    {
        let mut resource = winres::WindowsResource::new();
        resource
            .set_icon("assets/meka.ico")
            .set("ProductName", "Meka")
            .set("FileDescription", "Meka");
        resource.compile()?;
    }
    Ok(())
}

/// The Linux executables a Windows build embeds: the environment variable naming each, the file
/// name it lands under in `OUT_DIR`, and the largest it may be. The guest bootstrap stages the
/// loader in a temporary file and refuses one past 16 MiB before it runs anything, and the loader
/// refuses a runner past 128 MiB as it reads it from the pipe. A payload past its ceiling would
/// embed here and then fail every deployment it was built for, so it fails the build instead.
const PAYLOADS: [(&str, &str, usize); 2] = [
    ("MEKA_WSL_RUNNER", "meka-runner", 128 * MIB),
    ("MEKA_WSL_LOADER", "meka-wsl-loader", 16 * MIB),
];

/// Bytes in a mebibyte, the unit both ceilings are stated in.
const MIB: usize = 1024 * 1024;

/// Embed the release's Linux executables, not runtime paths that workspace files can replace.
fn bundle_wsl_payloads() -> std::io::Result<()> {
    use std::{env, fs, io, path::PathBuf};

    for (variable, ..) in PAYLOADS {
        println!("cargo:rerun-if-env-changed={variable}");
    }
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return Ok(());
    }
    let output = env::var_os("OUT_DIR").ok_or_else(|| io::Error::other("OUT_DIR is unset"))?;
    // In `PAYLOADS` order: the runner first, the loader second.
    let sources = paired_payload_sources(
        env::var_os("MEKA_WSL_RUNNER").map(PathBuf::from),
        env::var_os("MEKA_WSL_LOADER").map(PathBuf::from),
    )?;
    let sources = match sources {
        Some([runner, loader]) => [Some(runner), Some(loader)],
        None => [None, None],
    };
    for ((variable, file_name, limit), source) in PAYLOADS.iter().zip(sources) {
        let destination = PathBuf::from(&output).join(file_name);
        let Some(source) = source else {
            fs::write(destination, [])?;
            continue;
        };
        println!("cargo:rerun-if-changed={}", source.display());
        // Read through the ceiling rather than after it: a mistaken path may name a file of any
        // size, and allocating it whole only to refuse it is the failure the ceiling exists to
        // prevent. One byte past the limit is enough to know it is over.
        let bytes = read_payload(variable, file_name, &source, *limit)?;
        let interpreter = has_program_interpreter(&bytes).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "{variable} must name a Linux x86-64 ELF executable, and {} is not one: \
                     {error}",
                    source.display()
                ),
            )
        })?;
        if interpreter {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "{variable} must name a statically linked executable, and {} names a dynamic \
                     loader",
                    source.display()
                ),
            ));
        }
        fs::write(destination, bytes)?;
    }
    Ok(())
}

/// The two WSL payload sources as a pair: both configured or neither. A Windows build carries
/// the runner and its deployment loader together or not at all: either one alone reaches the
/// guest with no way to start. The pair is returned in `PAYLOADS` order, the runner first.
fn paired_payload_sources(
    runner: Option<std::path::PathBuf>,
    loader: Option<std::path::PathBuf>,
) -> std::io::Result<Option<[std::path::PathBuf; 2]>> {
    match (runner, loader) {
        (Some(runner), Some(loader)) => Ok(Some([runner, loader])),
        (None, None) => Ok(None),
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "MEKA_WSL_RUNNER and MEKA_WSL_LOADER must be set together or not at all",
        )),
    }
}

/// Open `source` once and read at most `limit + 1` bytes through that handle.
///
/// The opened object, not a path looked at separately, supplies both the type check and the
/// bytes: a path replaced between a metadata call and the read would otherwise let a different
/// object through the very check meant for it.
fn read_payload(
    variable: &str,
    file_name: &str,
    source: &std::path::Path,
    limit: usize,
) -> std::io::Result<Vec<u8>> {
    use std::io::Read as _;

    let file = std::fs::File::open(source).map_err(|error| {
        std::io::Error::new(
            error.kind(),
            format!("{variable} names {}: {error}", source.display()),
        )
    })?;
    let metadata = file.metadata().map_err(|error| {
        std::io::Error::new(
            error.kind(),
            format!("{variable} names {}: {error}", source.display()),
        )
    })?;
    if !metadata.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "{variable} must name a regular file, and {} is not one",
                source.display()
            ),
        ));
    }
    let ceiling = u64::try_from(limit).unwrap_or(u64::MAX).saturating_add(1);
    let mut bytes = Vec::new();
    file.take(ceiling)
        .read_to_end(&mut bytes)
        .map_err(|error| {
            std::io::Error::new(
                error.kind(),
                format!("{variable} names {}: {error}", source.display()),
            )
        })?;
    if bytes.len() > limit {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "{variable} may name at most {} MiB for {file_name}, and {} is over it",
                limit / MIB,
                source.display()
            ),
        ));
    }
    Ok(bytes)
}

/// Bytes in an ELF64 header, which states where the program header table starts.
const ELF64_HEADER_BYTES: usize = 64;

/// Bytes in an ELF64 program header, the exact `e_phentsize` Linux reads.
const ELF64_PROGRAM_HEADER_BYTES: usize = 56;

/// `ET_EXEC`: an executable linked at fixed addresses.
const ET_EXEC: u16 = 2;

/// `ET_DYN`: a position-independent executable.
const ET_DYN: u16 = 3;

/// `e_machine` for x86-64.
const EM_X86_64: u16 = 0x3e;

/// `PT_LOAD`: a segment the loader maps from the file.
const PT_LOAD: u32 = 1;

/// `PT_INTERP`: the segment naming the dynamic loader an executable needs.
const PT_INTERP: u32 = 3;

/// Why a payload's ELF header or program headers cannot be read. A file that is malformed,
/// truncated or impossible is an error rather than "no interpreter": the guest could not run such
/// a file either, and reading it as static would let it through to fail on a deployment.
#[derive(Debug)]
struct ElfError(String);

impl std::fmt::Display for ElfError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for ElfError {}

/// The `N` bytes at `at`, `None` when `bytes` does not hold them.
fn bytes_at<const N: usize>(bytes: &[u8], at: usize) -> Option<[u8; N]> {
    let end = at.checked_add(N)?;
    bytes.get(at..end)?.try_into().ok()
}

/// Whether a 64-bit little-endian x86-64 ELF carries a `PT_INTERP` program header: a dynamic
/// loader the guest would have to find at a path the build did not carry.
///
/// The header is checked for the shape the guest can execute before any segment is read: class,
/// data encoding, ident version, `e_type`, machine, ELF version and header size. The program
/// header table must use Linux's exact ELF64 stride, fit the file, hold at least one usable
/// file-backed `PT_LOAD`, and keep every load segment's file bytes within its memory bytes; a
/// segment's alignment must be a power of two and congruent with its file offset. A non-zero
/// entry point must lie inside a load segment's file-backed bytes, because an entry outside
/// every mapping, or in zero-fill memory past the file's bytes, has no code behind it. What the
/// kernel checks beyond this is not claimed: this is the shape of a launchable static
/// executable, not a claim of trust.
fn has_program_interpreter(bytes: &[u8]) -> Result<bool, ElfError> {
    let truncated = || {
        ElfError(format!(
            "the {ELF64_HEADER_BYTES}-byte ELF64 header is truncated to {} bytes",
            bytes.len()
        ))
    };
    if bytes.len() < ELF64_HEADER_BYTES {
        return Err(truncated());
    }
    let ident = bytes_at::<4>(bytes, 0).ok_or_else(truncated)?;
    if ident != *b"\x7fELF" {
        return Err(ElfError(
            "the file does not start with the ELF magic".to_string(),
        ));
    }
    let [class] = bytes_at::<1>(bytes, 4).ok_or_else(truncated)?;
    if class != 2 {
        return Err(ElfError(format!(
            "e_ident class is {class}, and only a 64-bit ELF (2) is accepted"
        )));
    }
    let [data] = bytes_at::<1>(bytes, 5).ok_or_else(truncated)?;
    if data != 1 {
        return Err(ElfError(format!(
            "e_ident data encoding is {data}, and only little-endian (1) is accepted"
        )));
    }
    let [ident_version] = bytes_at::<1>(bytes, 6).ok_or_else(truncated)?;
    if ident_version != 1 {
        return Err(ElfError(format!(
            "e_ident version is {ident_version}, and only the current ELF version (1) is accepted"
        )));
    }
    let kind = u16::from_le_bytes(bytes_at(bytes, 16).ok_or_else(truncated)?);
    if !matches!(kind, ET_EXEC | ET_DYN) {
        return Err(ElfError(format!(
            "e_type is {kind}, and only an executable (ET_EXEC 2) or a position-independent \
             executable (ET_DYN 3) is accepted"
        )));
    }
    let machine = u16::from_le_bytes(bytes_at(bytes, 18).ok_or_else(truncated)?);
    if machine != EM_X86_64 {
        return Err(ElfError(format!(
            "e_machine is {machine}, and only x86-64 ({EM_X86_64}) is accepted"
        )));
    }
    let version = u32::from_le_bytes(bytes_at(bytes, 20).ok_or_else(truncated)?);
    if version != 1 {
        return Err(ElfError(format!(
            "e_version is {version}, and only the current ELF version (1) is accepted"
        )));
    }
    let entry = u64::from_le_bytes(bytes_at(bytes, 24).ok_or_else(truncated)?);
    let (Some(table_offset), Some(header_bytes), Some(entry_size), Some(count)) = (
        bytes_at::<8>(bytes, 32).map(u64::from_le_bytes),
        bytes_at::<2>(bytes, 52).map(u16::from_le_bytes),
        bytes_at::<2>(bytes, 54).map(u16::from_le_bytes),
        bytes_at::<2>(bytes, 56).map(u16::from_le_bytes),
    ) else {
        return Err(ElfError("the ELF64 header is truncated".to_string()));
    };
    if usize::from(header_bytes) != ELF64_HEADER_BYTES {
        return Err(ElfError(format!(
            "e_ehsize is {header_bytes}, and an ELF64 header is {ELF64_HEADER_BYTES} bytes"
        )));
    }
    if usize::from(entry_size) != ELF64_PROGRAM_HEADER_BYTES {
        return Err(ElfError(format!(
            "e_phentsize is {entry_size}, and an ELF64 program header is exactly \
             {ELF64_PROGRAM_HEADER_BYTES} bytes"
        )));
    }
    // A loadable image states at least one program header. `PN_XNUM` (0xffff) puts the real count
    // in a section header, which this check does not read.
    if count == 0 {
        return Err(ElfError(
            "e_phnum is 0, so it has no program headers".to_string(),
        ));
    }
    if count == u16::MAX {
        return Err(ElfError(
            "e_phnum is PN_XNUM, whose count is in a section header".to_string(),
        ));
    }
    let start = usize::try_from(table_offset).map_err(|_| {
        ElfError(format!(
            "e_phoff is {table_offset}, past this host's address space"
        ))
    })?;
    // The table follows the ELF header; a non-zero count cannot describe a table inside it.
    if start < ELF64_HEADER_BYTES {
        return Err(ElfError(format!(
            "e_phoff is {table_offset}, inside the {ELF64_HEADER_BYTES}-byte ELF64 header"
        )));
    }
    let step = usize::from(entry_size);
    let end = usize::from(count)
        .checked_mul(step)
        .and_then(|table| start.checked_add(table))
        .ok_or_else(|| {
            ElfError(format!(
                "a program header table of {count} entries at {table_offset} has no end in this \
                 host's address space"
            ))
        })?;
    if end > bytes.len() {
        return Err(ElfError(format!(
            "the program header table spans {start}..{end}, and the file is {} bytes",
            bytes.len()
        )));
    }
    let mut interpreter = false;
    let mut loadable = false;
    let mut entry_mapped = false;
    for index in 0..usize::from(count) {
        let at = start + index * step;
        let entry_bytes = bytes
            .get(at..at + ELF64_PROGRAM_HEADER_BYTES)
            .ok_or_else(|| ElfError(format!("program header {index} at {at} is truncated")))?;
        let (
            Some(kind),
            Some(file_offset),
            Some(virtual_address),
            Some(file_bytes),
            Some(memory_bytes),
            Some(alignment),
        ) = (
            bytes_at(entry_bytes, 0).map(u32::from_le_bytes),
            bytes_at(entry_bytes, 8).map(u64::from_le_bytes),
            bytes_at(entry_bytes, 16).map(u64::from_le_bytes),
            bytes_at(entry_bytes, 32).map(u64::from_le_bytes),
            bytes_at(entry_bytes, 40).map(u64::from_le_bytes),
            bytes_at(entry_bytes, 48).map(u64::from_le_bytes),
        )
        else {
            return Err(ElfError(format!("program header {index} is truncated")));
        };
        let file_start = usize::try_from(file_offset).map_err(|_| {
            ElfError(format!(
                "program header {index} starts at {file_offset}, past this host's address space"
            ))
        })?;
        let file_size = usize::try_from(file_bytes).map_err(|_| {
            ElfError(format!(
                "program header {index} is {file_bytes} bytes, past this host's address space"
            ))
        })?;
        let file_end = file_start.checked_add(file_size).ok_or_else(|| {
            ElfError(format!(
                "program header {index} covers {file_start}.. and has no end in this host's \
                 address space"
            ))
        })?;
        if file_end > bytes.len() {
            return Err(ElfError(format!(
                "program header {index} covers {file_start}..{file_end}, and the file is {} bytes",
                bytes.len()
            )));
        }
        if kind == PT_LOAD {
            if file_bytes > memory_bytes {
                return Err(ElfError(format!(
                    "program header {index} is a PT_LOAD segment with {file_bytes} file bytes in \
                     {memory_bytes} memory bytes"
                )));
            }
            let memory_end = virtual_address.checked_add(memory_bytes).ok_or_else(|| {
                ElfError(format!(
                    "PT_LOAD segment {index} at {virtual_address:#x} and {memory_bytes} bytes has \
                     no end in this host's address space"
                ))
            })?;
            if alignment > 1 {
                if !alignment.is_power_of_two() {
                    return Err(ElfError(format!(
                        "PT_LOAD segment {index} states an alignment of {alignment:#x}, which is \
                         not a power of two"
                    )));
                }
                if virtual_address % alignment != file_offset % alignment {
                    return Err(ElfError(format!(
                        "PT_LOAD segment {index} maps {virtual_address:#x} from file offset \
                         {file_offset:#x}, which are not congruent modulo its alignment {alignment:#x}"
                    )));
                }
            }
            if memory_end > virtual_address && file_bytes > 0 {
                loadable = true;
            }
            if entry >= virtual_address && entry < virtual_address + file_bytes {
                entry_mapped = true;
            }
        }
        if kind == PT_INTERP {
            if interpreter {
                return Err(ElfError(
                    "more than one PT_INTERP program header".to_string(),
                ));
            }
            // The path is a NUL-terminated string in the bytes the segment covers.
            if file_size == 0 || bytes.get(file_end - 1) != Some(&0) {
                return Err(ElfError(format!(
                    "program header {index} is a PT_INTERP path that does not end in a NUL byte"
                )));
            }
            interpreter = true;
        }
    }
    if !loadable {
        return Err(ElfError(
            "it has no PT_LOAD segment with file-backed memory bytes".to_string(),
        ));
    }
    if entry == 0 {
        return Err(ElfError(
            "e_entry is 0, and a launchable executable states an entry point".to_string(),
        ));
    }
    if !entry_mapped {
        return Err(ElfError(format!(
            "e_entry {entry:#x} lies outside every PT_LOAD segment's file-backed bytes"
        )));
    }
    Ok(interpreter)
}

/// The stack the binary's main thread gets on every platform: what Linux and macOS give it.
const MAIN_THREAD_STACK_BYTES: usize = 8 * 1024 * 1024;

/// Give the main thread [`MAIN_THREAD_STACK_BYTES`] on Windows too, where the linker sets it: 1 MiB
/// from MSVC's, 2 MiB from MinGW's. The main thread polls a host's futures, and a sub-agent's turn
/// runs nested inside its parent's, whose frames in a debug build need more than 1 MiB. Read from
/// the target rather than `cfg(windows)`, which names the host the script runs on.
fn size_the_main_thread_stack() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    match std::env::var("CARGO_CFG_TARGET_ENV").as_deref() {
        Ok("msvc") => println!("cargo:rustc-link-arg-bins=/STACK:{MAIN_THREAD_STACK_BYTES}"),
        Ok("gnu") => {
            println!("cargo:rustc-link-arg-bins=-Wl,--stack,{MAIN_THREAD_STACK_BYTES}");
        }
        _ => {}
    }
}

/// Hand the binary the revision it was built from as `MEKA_GIT_REVISION`, which the screen's
/// banner shows beside the version: the short commit, `-dirty` when the tree had uncommitted
/// changes, so a build from a checkout can be told from the release of the same version. A
/// build outside a checkout, or without `git`, gets no value and the banner shows the version
/// alone; a packager who knows the revision sets the variable in the build's environment.
///
/// The script reruns when the sources or the checkout's head change, which is when the answer
/// can: a change to a file the binary is not built from leaves `-dirty` as it was.
fn embed_git_revision() {
    println!("cargo:rerun-if-env-changed=MEKA_GIT_REVISION");
    for watched in ["src", "tests", "Cargo.toml", "Cargo.lock"] {
        println!("cargo:rerun-if-changed={watched}");
    }
    if std::path::Path::new(".git/HEAD").is_file() {
        println!("cargo:rerun-if-changed=.git/HEAD");
        println!("cargo:rerun-if-changed=.git/index");
    }
    let given = std::env::var("MEKA_GIT_REVISION")
        .ok()
        .map(|revision| revision.trim().to_string())
        .filter(|revision| !revision.is_empty());
    let revision = given.or_else(|| {
        // `--exclude=*` leaves no tag to describe against, so `--always` answers with the short
        // commit. A clean tree at a tag is the release of that tag, which the version line
        // already says, so it gets no revision.
        let described = git(["describe", "--always", "--dirty", "--exclude=*"])?;
        let at_tag = !described.ends_with("-dirty")
            && git(["describe", "--tags", "--exact-match", "HEAD"]).is_some();
        (!at_tag).then_some(described)
    });
    if let Some(revision) = revision {
        println!("cargo:rustc-env=MEKA_GIT_REVISION={revision}");
    }
}

/// `git <args>`'s trimmed output, `None` when git is absent, the command fails or says nothing.
fn git<const N: usize>(args: [&str; N]) -> Option<String> {
    let output = std::process::Command::new("git")
        .args(args)
        .output()
        .ok()
        .filter(|output| output.status.success())?;
    let text = String::from_utf8(output.stdout).ok()?.trim().to_string();
    (!text.is_empty()).then_some(text)
}

/// Cargo has no test target for a build script, so these run as a standalone harness:
/// `rustc --edition 2024 --test build.rs -o build-tests.exe` and then `./build-tests.exe`. The
/// package's clippy and rustfmt gates compile this file without `cfg(test)` and are unaffected.
#[cfg(test)]
mod tests {
    use super::*;

    /// `ET_EXEC`: an executable linked at fixed addresses.
    const ET_EXEC: u16 = 2;

    /// `ET_DYN`: a position-independent executable.
    const ET_DYN: u16 = 3;

    /// `e_machine` for x86-64.
    const EM_X86_64: u16 = 0x3e;

    /// One fixture program header: `(p_type, p_offset, p_filesz, p_memsz)`.
    type ProgramHeader = (u32, u64, u64, u64);

    /// Where the program header at `index` starts.
    fn header_offset(index: usize) -> usize {
        ELF64_HEADER_BYTES + index * ELF64_PROGRAM_HEADER_BYTES
    }

    /// Where the payload of a fixture with `count` program headers starts.
    fn payload_offset(count: usize) -> usize {
        header_offset(count)
    }

    /// An ELF64 little-endian x86-64 image of `kind`, whose `headers` start at offset 64 and whose
    /// `payload` follows them. The offsets in `headers` name bytes in this image.
    fn elf(kind: u16, headers: &[ProgramHeader], payload: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0; payload_offset(headers.len())];
        bytes[..4].copy_from_slice(b"\x7fELF");
        bytes[4] = 2; // `ELFCLASS64`
        bytes[5] = 1; // `ELFDATA2LSB`
        bytes[6] = 1; // `EV_CURRENT`
        bytes[16..18].copy_from_slice(&kind.to_le_bytes());
        bytes[18..20].copy_from_slice(&EM_X86_64.to_le_bytes());
        bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
        bytes[32..40].copy_from_slice(&(ELF64_HEADER_BYTES as u64).to_le_bytes());
        bytes[52..54].copy_from_slice(&(ELF64_HEADER_BYTES as u16).to_le_bytes());
        bytes[54..56].copy_from_slice(&(ELF64_PROGRAM_HEADER_BYTES as u16).to_le_bytes());
        bytes[56..58].copy_from_slice(&(headers.len() as u16).to_le_bytes());
        for (index, &(kind, offset, file_size, memory_size)) in headers.iter().enumerate() {
            let at = header_offset(index);
            bytes[at..at + 4].copy_from_slice(&kind.to_le_bytes());
            bytes[at + 8..at + 16].copy_from_slice(&offset.to_le_bytes());
            bytes[at + 32..at + 40].copy_from_slice(&file_size.to_le_bytes());
            bytes[at + 40..at + 48].copy_from_slice(&memory_size.to_le_bytes());
        }
        bytes.extend_from_slice(payload);
        bytes
    }

    /// A fixture with a single `PT_LOAD` covering the whole image, the shape a static binary has,
    /// entered at the start of its payload: a file-backed address inside the mapping.
    fn static_elf(kind: u16) -> Vec<u8> {
        let payload = [0x90; 8];
        let size = (payload_offset(1) + payload.len()) as u64;
        let mut bytes = elf(kind, &[(PT_LOAD, 0, size, size)], &payload);
        put(&mut bytes, 24, (payload_offset(1) as u64).to_le_bytes());
        bytes
    }

    /// A pie fixture: a `PT_LOAD` covering the image and a `PT_INTERP` naming `path`, entered at
    /// the start of its payload.
    fn pie_elf(path: &[u8]) -> Vec<u8> {
        let start = payload_offset(2) as u64;
        let size = (start as usize + path.len()) as u64;
        let mut bytes = elf(
            ET_DYN,
            &[
                (PT_LOAD, 0, size, size),
                (PT_INTERP, start, path.len() as u64, path.len() as u64),
            ],
            path,
        );
        put(&mut bytes, 24, start.to_le_bytes());
        bytes
    }

    /// Writes `value` over the `N` bytes at `at` of a fixture.
    fn put<const N: usize>(bytes: &mut [u8], at: usize, value: [u8; N]) {
        bytes[at..at + N].copy_from_slice(&value);
    }

    /// The parser's error for `bytes`, or a panic naming the result it produced instead.
    fn parse_error(bytes: &[u8]) -> String {
        match has_program_interpreter(bytes) {
            Ok(interpreter) => panic!("the fixture parsed as interpreter = {interpreter}"),
            Err(error) => error.to_string(),
        }
    }

    /// A statically linked x86-64 executable carries no `PT_INTERP`, whether the linker emitted a
    /// fixed-address `ET_EXEC` or a position-independent `ET_DYN`.
    #[test]
    fn a_static_executable_has_no_interpreter() {
        for kind in [ET_EXEC, ET_DYN] {
            let bytes = static_elf(kind);
            assert!(
                !has_program_interpreter(&bytes).expect("a loadable static executable parses"),
                "e_type {kind} without PT_INTERP"
            );
        }
    }

    /// A position-independent executable names the loader the guest would have to find, so the
    /// parser reports it and the build refuses the payload.
    #[test]
    fn a_pie_that_names_a_loader_is_rejected() {
        let bytes = pie_elf(b"/lib64/ld-linux-x86-64.so.2\0");
        assert!(
            has_program_interpreter(&bytes).expect("a loadable pie parses"),
            "a PT_INTERP names a dynamic loader"
        );
    }

    /// A table that runs past the end of the file is truncated, however it is described: a count
    /// larger than the file holds, an offset past the end, or one inside the ELF header.
    #[test]
    fn a_truncated_program_header_table_is_an_error() {
        let payload = [0x90; 8];
        let size = (payload_offset(2) + payload.len()) as u64;
        let bytes = elf(
            ET_EXEC,
            &[(PT_LOAD, 0, size, size), (PT_LOAD, 0, size, size)],
            &payload,
        );

        // `e_phnum` states two headers and the file stops inside the second.
        let truncated = &bytes[..payload_offset(1)];
        assert!(parse_error(truncated).contains("program header table spans"));

        // `e_phoff` past the end of the file.
        let mut relocated = bytes.clone();
        put(&mut relocated, 32, ((bytes.len() + 1) as u64).to_le_bytes());
        assert!(parse_error(&relocated).contains("program header table spans"));

        // `e_phoff` inside the ELF header, which no table can follow.
        put(&mut relocated, 32, 0u64.to_le_bytes());
        assert!(parse_error(&relocated).contains("inside the 64-byte ELF64 header"));
    }

    /// An entry smaller than an ELF64 program header cannot be read, and zero states no entry at
    /// all; both are malformed rather than a table without `PT_INTERP`.
    #[test]
    fn an_entry_smaller_than_an_elf64_program_header_is_an_error() {
        let mut bytes = static_elf(ET_EXEC);
        put(
            &mut bytes,
            54,
            ((ELF64_PROGRAM_HEADER_BYTES as u16) - 1).to_le_bytes(),
        );
        assert!(parse_error(&bytes).contains("e_phentsize is 55"));

        put(&mut bytes, 54, 0u16.to_le_bytes());
        assert!(parse_error(&bytes).contains("e_phentsize is 0"));
    }

    /// A segment that reaches past the end of the file is truncated: an out-of-bounds `p_offset`
    /// or `p_filesz` is exactly what a payload cut short looks like.
    #[test]
    fn a_segment_outside_the_file_is_an_error() {
        // `p_offset` past the end.
        let mut bytes = static_elf(ET_EXEC);
        let size = bytes.len() as u64;
        put(&mut bytes, 64 + 8, (size + 1).to_le_bytes());
        assert!(parse_error(&bytes).contains("covers"));

        // `p_offset` in range, `p_filesz` reaching past the end.
        let mut bytes = static_elf(ET_EXEC);
        put(&mut bytes, 64 + 32, (size + 1).to_le_bytes());
        put(&mut bytes, 64 + 40, (size + 1).to_le_bytes());
        assert!(parse_error(&bytes).contains("covers"));

        // A `PT_INTERP` path that lies outside the file.
        let mut bytes = pie_elf(b"/lib64/ld-linux-x86-64.so.2\0");
        let size = bytes.len() as u64;
        put(&mut bytes, header_offset(1) + 8, size.to_le_bytes());
        assert!(parse_error(&bytes).contains("covers"));
    }

    /// A header too short to state where its program headers are used to read as "no
    /// interpreter"; it is a malformed payload, and the build now refuses it.
    #[test]
    fn a_header_too_short_to_state_its_table_is_an_error() {
        let bytes = static_elf(ET_EXEC);
        let truncated = &bytes[..20];
        assert!(parse_error(truncated).contains("ELF64 header is truncated"));
    }

    /// A loadable image states at least one program header. Zero states none, and `PN_XNUM` puts
    /// the real count in a section header this check does not read; neither is a static binary.
    #[test]
    fn a_payload_without_a_readable_count_is_an_error() {
        let mut bytes = static_elf(ET_EXEC);
        put(&mut bytes, 56, 0u16.to_le_bytes());
        assert!(parse_error(&bytes).contains("e_phnum is 0"));

        put(&mut bytes, 56, u16::MAX.to_le_bytes());
        assert!(parse_error(&bytes).contains("PN_XNUM"));
    }

    /// The `PT_INTERP` path is a NUL-terminated string; one that is empty or unterminated does not
    /// name a loader the guest could find.
    #[test]
    fn an_unterminated_interpreter_path_is_an_error() {
        let mut bytes = pie_elf(b"/lib64/ld-linux-x86-64.so.2\0");
        let entry = header_offset(1);

        put(&mut bytes, entry + 32, 1u64.to_le_bytes());
        put(&mut bytes, entry + 40, 1u64.to_le_bytes());
        assert!(parse_error(&bytes).contains("does not end in a NUL byte"));

        put(&mut bytes, entry + 32, 0u64.to_le_bytes());
        put(&mut bytes, entry + 40, 0u64.to_le_bytes());
        assert!(parse_error(&bytes).contains("does not end in a NUL byte"));
    }

    /// A `PT_LOAD` segment carries file bytes into memory, so it cannot state more file bytes than
    /// memory bytes.
    #[test]
    fn a_load_segment_larger_in_file_than_in_memory_is_an_error() {
        let payload = [0x90; 8];
        let size = (payload_offset(1) + payload.len()) as u64;
        let bytes = elf(ET_EXEC, &[(PT_LOAD, 0, size, size - 1)], &payload);
        assert!(parse_error(&bytes).contains("PT_LOAD segment with"));
    }

    /// The header must describe a 64-bit little-endian x86-64 executable: the guest runs nothing
    /// else, and a wrong class, encoding, version, type, machine or header size is refused rather
    /// than handed to the loader to fail.
    #[test]
    fn an_unsupported_header_shape_is_refused() {
        let mut bytes = static_elf(ET_EXEC);
        put(&mut bytes, 4, [1]);
        assert!(parse_error(&bytes).contains("class is 1"));

        let mut bytes = static_elf(ET_EXEC);
        put(&mut bytes, 5, [2]);
        assert!(parse_error(&bytes).contains("data encoding is 2"));

        let mut bytes = static_elf(ET_EXEC);
        put(&mut bytes, 6, [2]);
        assert!(parse_error(&bytes).contains("e_ident version is 2"));

        let mut bytes = static_elf(ET_EXEC);
        put(&mut bytes, 16, 1u16.to_le_bytes());
        assert!(parse_error(&bytes).contains("e_type is 1"));

        let mut bytes = static_elf(ET_EXEC);
        put(&mut bytes, 18, 0x28u16.to_le_bytes());
        assert!(parse_error(&bytes).contains("e_machine is 40"));

        let mut bytes = static_elf(ET_EXEC);
        put(&mut bytes, 20, 2u32.to_le_bytes());
        assert!(parse_error(&bytes).contains("e_version is 2"));

        let mut bytes = static_elf(ET_EXEC);
        put(&mut bytes, 52, 0u16.to_le_bytes());
        assert!(parse_error(&bytes).contains("e_ehsize is 0"));

        let mut bytes = static_elf(ET_EXEC);
        put(&mut bytes, 54, 57u16.to_le_bytes());
        assert!(parse_error(&bytes).contains("e_phentsize is 57"));
    }

    /// A loadable image needs a usable file-backed mapping, every load's virtual range must fit
    /// the address space, and an entry point must lie inside a load segment's file-backed bytes.
    #[test]
    fn a_mapping_that_cannot_carry_an_entry_is_an_error() {
        let start = payload_offset(1) as u64;
        let bytes = elf(ET_EXEC, &[(PT_INTERP, start, 1, 1)], b"\0");
        assert!(parse_error(&bytes).contains("no PT_LOAD segment"));

        let mut bytes = static_elf(ET_EXEC);
        put(&mut bytes, 24, 0x1_0000u64.to_le_bytes());
        assert!(parse_error(&bytes).contains("outside every PT_LOAD"));

        let mut bytes = static_elf(ET_EXEC);
        put(&mut bytes, 64 + 16, u64::MAX.to_le_bytes());
        put(&mut bytes, 64 + 32, 0u64.to_le_bytes());
        put(&mut bytes, 64 + 40, 2u64.to_le_bytes());
        assert!(parse_error(&bytes).contains("has no end"));
    }

    /// Linux maps a load at an aligned file offset, so the stated alignment must be a power of two
    /// and congruent with the file offset.
    #[test]
    fn an_unusable_load_alignment_is_an_error() {
        let mut bytes = static_elf(ET_EXEC);
        put(&mut bytes, 64 + 48, 3u64.to_le_bytes());
        assert!(parse_error(&bytes).contains("not a power of two"));

        let mut bytes = static_elf(ET_EXEC);
        put(&mut bytes, 64 + 16, 1u64.to_le_bytes());
        put(&mut bytes, 64 + 48, 2u64.to_le_bytes());
        assert!(parse_error(&bytes).contains("not congruent"));
    }

    /// A payload is read through its ceiling, never allocated whole first, and a non-regular
    /// object is refused before any byte is read.
    #[test]
    fn a_payload_over_its_ceiling_or_not_a_file_is_refused() {
        let path = std::env::temp_dir().join(format!("meka-build-payload-{}", std::process::id()));
        let oversize = vec![0u8; MIB + 1];
        std::fs::write(&path, &oversize).expect("write the oversize fixture");
        let error = read_payload("MEKA_WSL_RUNNER", "meka-runner", &path, MIB)
            .expect_err("an oversize payload");
        assert!(error.to_string().contains("over it"), "{error}");
        std::fs::remove_file(&path).expect("remove the fixture");

        let directory = std::env::temp_dir().join(format!(
            "meka-build-payload-directory-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&directory).expect("create the directory fixture");
        let error = read_payload("MEKA_WSL_RUNNER", "meka-runner", &directory, MIB)
            .expect_err("a directory");
        // Opening a directory fails on Windows before the metadata check can name the reason;
        // both refusals name the variable and the path they were asked about.
        assert!(error.to_string().contains("MEKA_WSL_RUNNER"), "{error}");
        std::fs::remove_dir_all(&directory).expect("remove the directory fixture");
    }

    /// A launchable entry point: non-zero, and inside the file-backed bytes of a load segment.
    /// An entry of zero states nothing to launch, and one in the zero-fill tail past a segment's
    /// file bytes has no code behind it.
    #[test]
    fn a_launchable_entry_lies_in_a_file_backed_mapping() {
        let mut bytes = static_elf(ET_EXEC);
        put(&mut bytes, 24, 0u64.to_le_bytes());
        assert!(parse_error(&bytes).contains("e_entry is 0"));

        // The load's file bytes stop at 64 while its memory reaches 0x1000, so an entry at
        // 0x800 lands in zero-fill memory the file never carried.
        let mut bytes = static_elf(ET_EXEC);
        put(&mut bytes, header_offset(0) + 32, 64u64.to_le_bytes());
        put(&mut bytes, header_offset(0) + 40, 0x1000u64.to_le_bytes());
        put(&mut bytes, 24, 0x800u64.to_le_bytes());
        assert!(parse_error(&bytes).contains("outside every PT_LOAD segment"));
    }

    /// The release pair ships whole or not at all: the runner and the loader are configured
    /// together or neither, each passes its own ceiling as a known-good static executable (the
    /// fixed-address `ET_EXEC` runner and the position-independent `ET_DYN` loader alike), and
    /// half a pair is refused by name.
    #[test]
    fn the_release_pair_ships_whole_or_not_at_all() {
        assert_eq!(
            PAYLOADS.map(|(_, _, limit)| limit),
            [128 * 1024 * 1024, 16 * 1024 * 1024],
            "the ceilings the release pair is built under"
        );

        assert!(
            paired_payload_sources(None, None)
                .expect("neither pair")
                .is_none()
        );
        let runner = std::env::temp_dir().join(format!("meka-build-runner-{}", std::process::id()));
        let loader = std::env::temp_dir().join(format!("meka-build-loader-{}", std::process::id()));
        std::fs::write(&runner, static_elf(ET_EXEC)).expect("the runner fixture");
        std::fs::write(&loader, static_elf(ET_DYN)).expect("the loader fixture");
        let pair = paired_payload_sources(Some(runner.clone()), Some(loader.clone()))
            .expect("a whole pair");
        assert_eq!(pair.expect("the pair"), [runner.clone(), loader.clone()]);

        for (source, (variable, file_name, limit)) in [&runner, &loader].into_iter().zip(PAYLOADS) {
            let bytes =
                read_payload(variable, file_name, source, limit).expect("a bounded payload");
            assert!(
                !has_program_interpreter(&bytes).expect("a known-good static executable parses"),
                "{variable} names a static executable"
            );
        }

        for half in [
            paired_payload_sources(Some(runner.clone()), None),
            paired_payload_sources(None, Some(loader.clone())),
        ] {
            let half = half.expect_err("half a pair");
            assert!(
                half.to_string()
                    .contains("MEKA_WSL_RUNNER and MEKA_WSL_LOADER"),
                "{half}"
            );
        }
        std::fs::remove_file(&runner).expect("remove the runner fixture");
        std::fs::remove_file(&loader).expect("remove the loader fixture");
    }
}
