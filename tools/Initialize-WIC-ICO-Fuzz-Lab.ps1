[CmdletBinding()]
param(
    [string]$WorkspaceRoot = 'C:\fuzz',
    [string]$HarnessDir    = (Get-Location).Path,
    [string]$WinAflDir     = 'C:\tools\winafl',
    [string]$TinyInstDir   = 'C:\tools\TinyInst',
    [switch]$EnablePageHeap = $true,
    [switch]$DisableAslr    = $true
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Step {
    param([string]$Message)
    Write-Host "`n[+] $Message" -ForegroundColor Cyan
}

function Write-Warn {
    param([string]$Message)
    Write-Host "[!] $Message" -ForegroundColor Yellow
}

function Assert-Administrator {
    $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)

    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
        throw "Run this script from an elevated PowerShell session."
    }
}

function Resolve-ExecutablePath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$CommandName,

        [string[]]$FallbackPaths = @()
    )

    $cmd = Get-Command $CommandName -ErrorAction SilentlyContinue
    if ($cmd) {
        return $cmd.Source
    }

    foreach ($candidate in $FallbackPaths) {
        if ($candidate -and (Test-Path $candidate)) {
            return (Resolve-Path $candidate).Path
        }
    }

    return $null
}

function Ensure-Directory {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

function Enable-FullPageHeap {
    param(
        [Parameter(Mandatory = $true)][string]$GflagsExe,
        [Parameter(Mandatory = $true)][string[]]$ExecutableNames
    )

    foreach ($exe in $ExecutableNames) {
        $exePath = Join-Path $HarnessDir $exe
        if (Test-Path $exePath) {
            Write-Host "    Enabling full PageHeap for $exe"
            & $GflagsExe /i $exe +hpa | Out-Host
        }
        else {
            Write-Warn "Skipping PageHeap for $exe because it was not found in $HarnessDir"
        }
    }
}

function Disable-DynamicBase {
    param(
        [Parameter(Mandatory = $true)][string]$EditBinExe,
        [Parameter(Mandatory = $true)][string[]]$ExecutableNames
    )

    foreach ($exe in $ExecutableNames) {
        $exePath = Join-Path $HarnessDir $exe
        if (Test-Path $exePath) {
            Write-Host "    Disabling ASLR (DYNAMICBASE) for $exe"
            & $EditBinExe /DYNAMICBASE:NO $exePath | Out-Host
        }
        else {
            Write-Warn "Skipping EDITBIN for $exe because it was not found in $HarnessDir"
        }
    }
}

Assert-Administrator

Write-Step "Resolving required tools"
$gflagsExe = Resolve-ExecutablePath -CommandName 'gflags.exe' -FallbackPaths @(
    'C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\gflags.exe',
    'C:\Program Files (x86)\Windows Kits\10\Debuggers\x86\gflags.exe'
)
$editbinExe = Resolve-ExecutablePath -CommandName 'editbin.exe'

if (-not $gflagsExe) {
    throw "gflags.exe not found. Install Windows Debugging Tools / Windows SDK."
}

if (-not $editbinExe) {
    throw "editbin.exe not found. Use a Visual Studio Developer PowerShell or add MSVC tools to PATH."
}

Write-Host "    gflags.exe : $gflagsExe"
Write-Host "    editbin.exe: $editbinExe"

Write-Step "Creating workspace layout"
$dirs = @(
    (Join-Path $WorkspaceRoot 'ondemand_general\corpus'),
    (Join-Path $WorkspaceRoot 'ondemand_general\findings'),

    (Join-Path $WorkspaceRoot 'onload_general\corpus'),
    (Join-Path $WorkspaceRoot 'onload_general\findings'),

    (Join-Path $WorkspaceRoot 'ondemand_fast_triage\corpus'),
    (Join-Path $WorkspaceRoot 'ondemand_fast_triage\findings'),

    (Join-Path $WorkspaceRoot 'ondemand_deep_hunt\corpus'),
    (Join-Path $WorkspaceRoot 'ondemand_deep_hunt\findings'),

    (Join-Path $WorkspaceRoot 'research_repro\artifacts')
)

foreach ($dir in $dirs) {
    Ensure-Directory -Path $dir
}

Write-Step "Applying recommended runtime preparation"
$knownHarnesses = @(
    'harness_c1.exe',
    'harness_c2.exe',
    'harness_deep.exe',
    'harness_research.exe'
)

if ($EnablePageHeap) {
    Enable-FullPageHeap -GflagsExe $gflagsExe -ExecutableNames $knownHarnesses
}

if ($DisableAslr) {
    Disable-DynamicBase -EditBinExe $editbinExe -ExecutableNames @(
        'harness_c1.exe',
        'harness_c2.exe',
        'harness_deep.exe'
    )
}

Write-Step "Workspace summary"
Write-Host "    Harness directory : $HarnessDir"
Write-Host "    Workspace root    : $WorkspaceRoot"
Write-Host "    WinAFL directory  : $WinAflDir"
Write-Host "    TinyInst directory: $TinyInstDir"

Write-Host "`n[+] Notes"
Write-Host "    - Keep CacheOnDemand and CacheOnLoad campaigns in separate output trees."
Write-Host "    - Use only .ico files in corpus directories."
Write-Host "    - Place the desired harness.ini next to the selected binary before launching a campaign."
Write-Host "    - Use the research build only for manual triage and crash reproduction."

Write-Host @'

# =============================================================================
# Example launch commands
# =============================================================================
# All commands below are intentionally commented out.
# Review and adapt paths before use.

# -----------------------------------------------------------------------------
# TinyInst smoke test / instrumentation sanity
# CacheOnDemand build, balanced profile
# -----------------------------------------------------------------------------
# & "$TinyInstDir\litecov.exe" `
#   -coverage_module windowscodecs.dll `
#   -target_module harness_c1.exe `
#   -target_method fuzz_target `
#   -nargs 1 `
#   -- (Join-Path $HarnessDir 'harness_c1.exe') @@

# -----------------------------------------------------------------------------
# Campaign: ondemand_general
# Purpose: sustained production fuzzing
# Build: harness_c1.exe
# Profile: balanced
# -----------------------------------------------------------------------------
# Copy-Item (Join-Path $HarnessDir 'harness.balanced.ini') (Join-Path $HarnessDir 'harness.ini') -Force
# & "$WinAflDir\afl-fuzz.exe" `
#   -i (Join-Path $WorkspaceRoot 'ondemand_general\corpus') `
#   -o (Join-Path $WorkspaceRoot 'ondemand_general\findings') `
#   -coverage_module windowscodecs.dll `
#   -target_module harness_c1.exe `
#   -target_method fuzz_target `
#   -fuzz_iterations 5000 `
#   -nargs 1 `
#   -file_extension ico `
#   -- (Join-Path $HarnessDir 'harness_c1.exe') @@

# -----------------------------------------------------------------------------
# Campaign: onload_general
# Purpose: separate coverage campaign for CacheOnLoad mode
# Build: harness_c2.exe
# Profile: balanced
# -----------------------------------------------------------------------------
# Copy-Item (Join-Path $HarnessDir 'harness.balanced.ini') (Join-Path $HarnessDir 'harness.ini') -Force
# & "$WinAflDir\afl-fuzz.exe" `
#   -i (Join-Path $WorkspaceRoot 'onload_general\corpus') `
#   -o (Join-Path $WorkspaceRoot 'onload_general\findings') `
#   -coverage_module windowscodecs.dll `
#   -target_module harness_c2.exe `
#   -target_method fuzz_target `
#   -fuzz_iterations 5000 `
#   -nargs 1 `
#   -file_extension ico `
#   -- (Join-Path $HarnessDir 'harness_c2.exe') @@

# -----------------------------------------------------------------------------
# Campaign: ondemand_fast_triage
# Purpose: initial corpus triage, large seed exploration, exec/sec benchmarking
# Build: harness_c1.exe
# Profile: fast
# -----------------------------------------------------------------------------
# Copy-Item (Join-Path $HarnessDir 'harness.fast.ini') (Join-Path $HarnessDir 'harness.ini') -Force
# & "$WinAflDir\afl-fuzz.exe" `
#   -i (Join-Path $WorkspaceRoot 'ondemand_fast_triage\corpus') `
#   -o (Join-Path $WorkspaceRoot 'ondemand_fast_triage\findings') `
#   -coverage_module windowscodecs.dll `
#   -target_module harness_c1.exe `
#   -target_method fuzz_target `
#   -fuzz_iterations 10000 `
#   -nargs 1 `
#   -file_extension ico `
#   -- (Join-Path $HarnessDir 'harness_c1.exe') @@

# -----------------------------------------------------------------------------
# Campaign: ondemand_deep_hunt
# Purpose: targeted hunting on interesting subsets, deep coverage, crash repro
# Build: harness_deep.exe
# Profile: deep
# -----------------------------------------------------------------------------
# Copy-Item (Join-Path $HarnessDir 'harness.deep.ini') (Join-Path $HarnessDir 'harness.ini') -Force
# & "$WinAflDir\afl-fuzz.exe" `
#   -i (Join-Path $WorkspaceRoot 'ondemand_deep_hunt\corpus') `
#   -o (Join-Path $WorkspaceRoot 'ondemand_deep_hunt\findings') `
#   -coverage_module windowscodecs.dll `
#   -target_module harness_deep.exe `
#   -target_method fuzz_target `
#   -fuzz_iterations 200 `
#   -nargs 1 `
#   -file_extension ico `
#   -- (Join-Path $HarnessDir 'harness_deep.exe') @@

# -----------------------------------------------------------------------------
# Experimental: extra module instrumentation
# Validate module names first with loader/module tracing.
# -----------------------------------------------------------------------------
# & "$WinAflDir\afl-fuzz.exe" `
#   -i (Join-Path $WorkspaceRoot 'ondemand_general\corpus') `
#   -o (Join-Path $WorkspaceRoot 'ondemand_general\findings_multimodule') `
#   -coverage_module windowscodecs.dll `
#   -target_module harness_c1.exe `
#   -target_method fuzz_target `
#   -fuzz_iterations 5000 `
#   -nargs 1 `
#   -file_extension ico `
#   -instrument_module windowscodecs.dll `
#   -instrument_module WindowsCodecsExt.dll `
#   -- (Join-Path $HarnessDir 'harness_c1.exe') @@

# -----------------------------------------------------------------------------
# Manual crash reproduction
# -----------------------------------------------------------------------------
# & (Join-Path $HarnessDir 'harness_c1.exe') "C:\path\to\crash.ico"

# -----------------------------------------------------------------------------
# Research-only manual repro build
# -----------------------------------------------------------------------------
# & (Join-Path $HarnessDir 'harness_research.exe') "C:\path\to\crash.ico"

# -----------------------------------------------------------------------------
# Test-case minimization
# -----------------------------------------------------------------------------
# & "$WinAflDir\afl-tmin.exe" `
#   -i "C:\path\to\crash.ico" `
#   -o "C:\path\to\crash_min.ico" `
#   -coverage_module windowscodecs.dll `
#   -target_module harness_c1.exe `
#   -target_method fuzz_target `
#   -nargs 1 `
#   -- (Join-Path $HarnessDir 'harness_c1.exe') @@
'@