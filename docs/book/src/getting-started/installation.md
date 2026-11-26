# Installation

Meka is written in Rust and builds as a single binary.

## Pre-built binaries

Download the latest release for your platform from the [GitHub Releases](https://github.com/k4yt3x/meka/releases/latest) page.

| Platform | Archive |
|----------|---------|
| Linux (x86_64) | `meka-linux-amd64.tar.gz` |
| macOS (Apple Silicon) | `meka-macos-arm64.tar.gz` |
| Windows (x86_64) | `meka-windows-amd64.zip` |

Extract the binary and place it somewhere on your `$PATH`:

```bash
# Linux/macOS
tar -xzf meka-*.tar.gz
cp meka ~/.local/bin/
```

## `mekabox`

[`scripts/mekabox`](https://github.com/k4yt3x/meka/blob/master/scripts/mekabox)
runs the Meka installed on the host inside a stock `archlinux:latest` container, with no image of
its own to build or pull: the binary is bind-mounted in, `~/.config/meka` read-only, and
`~/.local/share/meka` writable, since that is where `meka.db` keeps every session and credential.
The agent starts at `unrestricted` with instructions saying it may install whatever the task needs,
and that it must not create memories or schedules unless asked, since the store it writes is
the host's. It is the answer to "let it do anything, just not to my machine": the container is
disposable and the host config cannot be written. The store is the one host file the box shares,
and nothing sandboxes a command at `unrestricted`, so a command in the box can read every
credential in it: the boundary is around your filesystem, not your accounts. It picks podman over
docker when both are present.

## Cargo install

If you have [Rust](https://www.rust-lang.org/tools/install) installed, you can install Meka directly from the Git repository:

```bash
cargo install --locked --git https://github.com/k4yt3x/meka.git
```

This builds the latest version from source and installs it to `~/.cargo/bin/`.

## Building from source

### Prerequisites

- [Rust](https://www.rust-lang.org/tools/install) 1.95 or newer, the version `Cargo.toml` declares
- A C compiler (for the bundled SQLite)

### Build

```bash
git clone https://github.com/k4yt3x/meka.git
cd meka
cargo build --release
```

Windows release builds bundle two Linux executables — the runner, and the `meka-wsl-loader` that
deploys it — so [managed WSL](../tools/shell.md#subshell_open--subshell_execute--subshell_export--subshell_close)
works on a guest with no runner installed. Both are built from the same tree and speak runner
protocol 5. A Windows build from source carries them only when
**both** `MEKA_WSL_RUNNER` and `MEKA_WSL_LOADER` are set, each naming a Linux x86-64 ELF executable.
A statically linked musl build — a static-pie executable without an `INTERP` program header naming
a loader the guest may not have — is the supported shape. Build the pair for x86-64 Linux first —
with `musl-tools` and the `x86_64-unknown-linux-musl` target installed — on the distribution, in a
container, or in CI:

```bash
cargo build --release --target x86_64-unknown-linux-musl   # meka and meka-wsl-loader
```

Then build Meka on Windows with both variables naming those files:

```powershell
$env:MEKA_WSL_RUNNER = 'C:\payload\meka'
$env:MEKA_WSL_LOADER = 'C:\payload\meka-wsl-loader'
cargo build --release
```

The loader may be at most 16 MiB and the runner at most 128 MiB; each input is read through that
ceiling, and the build refuses one variable without the other. It also refuses a file that is not a
64-bit little-endian x86-64 ELF executable of type `ET_EXEC` or `ET_DYN`: the header and every
program header must fit the image, the program-header stride must be Linux's exact 56 bytes, at
least one `PT_LOAD` must have memory bytes, every load segment's file bytes must fit its memory
bytes and a power-of-two alignment congruent with its file offset, a non-zero entry point must lie
inside a load segment, and a `PT_INTERP` segment is refused. That is a format and contract check,
not proof that the payload runs on a particular kernel or distribution: build it from a trusted
toolchain. Both are embedded at build time, not read from the environment at runtime. A Windows
build without them refuses managed WSL deployment: it runs only a runner already installed in the
distribution, and a guest without one is told this build has none to deploy.

The binary will be at `target/release/meka`. Copy it somewhere on your `$PATH`:

```bash
cp target/release/meka ~/.local/bin/
```

## Verify

```bash
meka --version
meka --help
```
