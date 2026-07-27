# attestor installer for Windows PowerShell.
#
#   irm https://raw.githubusercontent.com/asinadarsh/attestor/main/install.ps1 | iex
#
# Installs into %USERPROFILE%\.attestor\src, puts an `attestor` launcher on your
# PATH, and hands off to `attestor setup`. No admin rights required, and nothing
# is installed globally through npm.
#
# When run from a pipe (irm | iex has no interactive stdin) the setup step only
# prints its plan and will not touch your MCP config. To finish unattended, set
# the variable in the same session first — it is the same shell, so this works
# where the POSIX `VAR=1 curl | sh` form would not:
#
#   $env:ATTESTOR_YES=1; irm .../install.ps1 | iex
param([switch]$Yes)
$ErrorActionPreference = 'Stop'
if ($Yes) { $env:ATTESTOR_YES = '1' }

function Say($msg) { Write-Host $msg }
function Die($msg) { Write-Error "attestor: $msg"; exit 1 }

$repo   = if ($env:ATTESTOR_REPO) { $env:ATTESTOR_REPO } else { 'https://github.com/asinadarsh/attestor.git' }
$src    = if ($env:ATTESTOR_SRC) { $env:ATTESTOR_SRC } else { Join-Path $env:USERPROFILE '.attestor\src' }
$binDir = if ($env:ATTESTOR_BIN_DIR) { $env:ATTESTOR_BIN_DIR } else { Join-Path $env:USERPROFILE '.attestor\bin' }

Say 'attestor installer'

# ---- prerequisites ---------------------------------------------------------
if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
  Die 'git is required but not installed — https://git-scm.com/download/win'
}
if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
  Die 'Node.js 24+ is required — https://nodejs.org/en/download'
}
$nodeMajor = [int](node -p 'process.versions.node.split(".")[0]')
if ($nodeMajor -lt 24) {
  Die "Node $(node -v) is too old — attestor needs Node 24+ (https://nodejs.org/en/download)"
}
Say "  node $(node -v)"

# ---- fetch or update -------------------------------------------------------
if (Test-Path (Join-Path $src '.git')) {
  Say "  updating $src"
  git -C $src pull --ff-only --quiet
} else {
  Say "  cloning into $src"
  New-Item -ItemType Directory -Force -Path (Split-Path $src) | Out-Null
  git clone --depth 1 --quiet $repo $src
}

# ---- build (npm install runs the build via the prepare script) -------------
Say '  installing dependencies'
Push-Location $src
try { npm install --silent --no-fund --no-audit } finally { Pop-Location }

$cli = Join-Path $src 'packages\attestor\dist\cli.js'
if (-not (Test-Path $cli)) { Die "build did not produce $cli" }

# ---- launcher on PATH ------------------------------------------------------
New-Item -ItemType Directory -Force -Path $binDir | Out-Null
$nodeExe = (Get-Command node).Source
# a .cmd shim so `attestor` works from cmd.exe and PowerShell alike
@"
@echo off
"$nodeExe" "$cli" %*
"@ | Set-Content -Path (Join-Path $binDir 'attestor.cmd') -Encoding ASCII
Say "  installed $(Join-Path $binDir 'attestor.cmd')"

$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if ($userPath -notlike "*$binDir*") {
  [Environment]::SetEnvironmentVariable('Path', "$userPath;$binDir", 'User')
  $env:Path = "$env:Path;$binDir"
  Say "  added $binDir to your user PATH (restart other terminals to pick it up)"
}

# ---- hand off to the wizard ------------------------------------------------
Say ''
$attestor = Join-Path $binDir 'attestor.cmd'
if ($env:ATTESTOR_YES -eq '1') {
  & $attestor setup --yes
} elseif ([Environment]::UserInteractive -and -not [Console]::IsInputRedirected) {
  & $attestor setup
} else {
  # piped install: show the plan, never rewrite a config unasked
  & $attestor setup
  Say ''
  Say "  Run 'attestor setup' in a terminal to finish, or re-run with `$env:ATTESTOR_YES=1."
}
