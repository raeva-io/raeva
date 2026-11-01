# Installation

The [release archives](https://github.com/raeva-io/raeva/releases) include
one native `raeva` executable each. Select the archive for your OS and CPU.

| System | Target suffix |
| --- | --- |
| Linux x86_64 with glibc | `x86_64-unknown-linux-gnu` |
| Linux aarch64 with glibc | `aarch64-unknown-linux-gnu` |
| Alpine or other musl Linux, x86_64 | `x86_64-unknown-linux-musl` |
| Alpine or other musl Linux, aarch64 | `aarch64-unknown-linux-musl` |
| macOS Intel | `x86_64-apple-darwin` |
| macOS Apple silicon | `aarch64-apple-darwin` |
| Windows x86_64 | `x86_64-pc-windows-msvc` |

Linux and macOS archives use `.tar.gz`, and the Windows archive `.zip`.
Download the archive and its checksum file from the same release, verify the
checksum, extract it, and put `raeva` in a directory on `PATH`. Run `raeva --version` to check it.

The musl builds link the C runtime statically and also run on glibc Linux.
TLS still reads the system certificate store. Install your distribution's
`ca-certificates` package, including in Alpine containers.

On GitHub Actions, setup-raeva selects musl on Alpine and other musl
containers. Pin the raeva version in CI. See the [README](../README.md#install)
for Homebrew, installers, and Rust installation commands.
