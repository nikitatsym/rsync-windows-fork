<#
.SYNOPSIS
    AES-128-GCM on Windows on ARM: four implementations, measured.

.DESCRIPTION
    Builds optimization/bench/gcmsustain_arm64.c with the ARM64 toolchain,
    makes it prove itself against CNG, OpenSSL and LibreSSL (same ciphertext,
    same tag, over a whole 32 KB packet), and then measures:

      peak       three interleaved rounds of 1 GB each, best of three, so a
                 machine that throttles cannot decide the ranking by order
      sustained  each implementation flat out for two minutes, throughput
                 sampled once a second, for the decay figure

    Writes optimization/data/gcm-peak_arm64.csv and one
    gcm-<lib>-thr_arm64.csv per implementation; ciphercharts_arm64.py draws
    windows-perf-arm64-cipher-libs from them.

    There is no network end here, unlike the x64 runs behind
    windows-perf-tb-cipher-libs: this measures the cipher alone.

.PARAMETER Seconds
    Length of each sustained run.  Default 120, as the x64 runs used.

.PARAMETER PeakMB
    Bytes per interleaved round, in MB.  Default 1000.

.EXAMPLE
    .\optimization\harness\cipherlibs_arm64.ps1
#>
[CmdletBinding()]
param(
    [int] $Seconds = 120,
    [int] $PeakMB = 1000,
    [int] $Rounds = 3
)

$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$src  = Join-Path $repo 'optimization\bench\gcmsustain_arm64.c'
$data = Join-Path $repo 'optimization\data'
$work = Join-Path $env:TEMP 'cipherbench-arm64'
$exe  = Join-Path $work 'gcmsustain_arm64.exe'
$LIBS = 'neon', 'cng', 'openssl3', 'libressl'

if ($env:PROCESSOR_ARCHITECTURE -ne 'ARM64') {
    throw "this is a $env:PROCESSOR_ARCHITECTURE machine; these numbers only mean anything on ARM64"
}

function Step($m) { Write-Host "==> $m" -ForegroundColor Cyan }

# ------------------------------------------------------------------- build
Step 'build'
$vswhere = "${Env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$vs = & $vswhere -latest -products * `
        -requires Microsoft.VisualStudio.Component.VC.Tools.ARM64 `
        -property installationPath
if (-not $vs) { throw 'no Visual Studio with the ARM64 C++ tools was found' }
$vcvars = Join-Path $vs 'VC\Auxiliary\Build\vcvarsarm64.bat'
New-Item -ItemType Directory -Force $work | Out-Null

# cl has to run under vcvars, and vcvars is a batch file: one cmd for both.
& cmd /c "call `"$vcvars`" >nul && cl /nologo /O2 /W3 /Fo`"$work\\`" /Fe`"$exe`" `"$src`""
if ($LASTEXITCODE -ne 0) { throw 'build failed' }
Write-Host "    $exe"

# ------------------------------------------------------------------- check
# A wrong GHASH is not visibly wrong -- the ciphertext still decrypts -- so
# nothing is measured until the tag agrees with three other implementations.
Step 'known-answer check'
& $exe --check
if ($LASTEXITCODE -ne 0) { throw 'the NEON implementation disagrees with the libraries; not measuring it' }

# -------------------------------------------------------------------- peak
Step "peak: $Rounds interleaved rounds of $PeakMB MB"
$peakCsv = Join-Path $data 'gcm-peak_arm64.csv'
& $exe --peak $PeakMB $Rounds | Set-Content -Encoding ascii $peakCsv
if ($LASTEXITCODE -ne 0) { throw 'peak run failed' }
Write-Host "    -> $peakCsv"
Get-Content $peakCsv | ForEach-Object { Write-Host "    $_" }

# --------------------------------------------------------------- sustained
foreach ($lib in $LIBS) {
    Step "sustained: $lib, $Seconds s"
    $csv = Join-Path $data "gcm-$lib-thr_arm64.csv"
    & $exe $lib $Seconds | Set-Content -Encoding ascii $csv
    if ($LASTEXITCODE -ne 0) { throw "sustained run failed for $lib" }
    # The same quarters the chart uses: a 120 s run's first and last 30 s.
    $v = @(Import-Csv $csv | ForEach-Object { [double]$_.mbps })
    # [Math]::Floor, not [int]: [int] rounds to even, and the chart's
    # len(v)//4 truncates -- which had the two reporting different decay
    # figures for the same file.
    $n = [Math]::Max(1, [int][Math]::Floor($v.Count / 4))
    $mean = ($v | Measure-Object -Average).Average
    $first = ($v[0..($n-1)] | Measure-Object -Average).Average
    $last = ($v[-$n..-1] | Measure-Object -Average).Average
    $change = (100 * ($last / $first - 1)).ToString('+0.0;-0.0')
    Write-Host ("    {0,-9} {1,6:N0} MB/s mean, first {2,6:N0}, last {3,6:N0}, {4}%" -f `
        $lib, $mean, $first, $last, $change)
    Write-Host "    -> $csv"
}

Step 'done'
Write-Host '    python optimization\charts\ciphercharts_arm64.py optimization\data .'
