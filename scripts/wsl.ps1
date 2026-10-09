<#
.SYNOPSIS
    Run a command for this repo inside WSL, with the Cargo target dir on the Linux filesystem.

.DESCRIPTION
    Use this on Windows machines where Smart App Control (or another code-integrity policy) blocks
    freshly compiled binaries such as Cargo build scripts and test runners. The sources stay on
    Windows. Builds and tests run in WSL. The target dir sits on the Linux filesystem, because
    building on /mnt/c is slow.

.EXAMPLE
    ./scripts/wsl.ps1 cargo test --workspace
    ./scripts/wsl.ps1 cargo clippy --workspace --all-targets -- -D warnings
#>
# Deliberately no param() block: named parameters would swallow flags such as `-c` or `-p`.
$Command = $args
if ($Command.Count -eq 0) {
    Write-Error 'usage: ./scripts/wsl.ps1 <command> [args...]'
    exit 2
}

$ErrorActionPreference = 'Stop'
$distro = if ($env:SLUICE_WSL_DISTRO) { $env:SLUICE_WSL_DISTRO } else { 'Ubuntu-24.04' }
$repo = Split-Path -Parent $PSScriptRoot
$linuxHome = (wsl.exe -d $distro --exec sh -c 'printf %s "$HOME"').Trim()

$envArgs = @(
    "PATH=$linuxHome/.cargo/bin:/usr/local/bin:/usr/bin:/bin",
    "CARGO_TARGET_DIR=$linuxHome/.cache/sluice-target",
    'CARGO_TERM_COLOR=never'
)

wsl.exe -d $distro --cd $repo --exec /usr/bin/env @envArgs @Command
exit $LASTEXITCODE
