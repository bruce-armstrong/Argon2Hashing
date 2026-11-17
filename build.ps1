<#
.SYNOPSIS
    Builds the Argon2Hashing .NET assembly and the PowerBuilder demo, and assembles a runnable folder.

.DESCRIPTION
    1. Builds dotnet\Argon2Hashing (net8.0 and net48).
    2. Builds Argon2Demo.pbproj with PBAutoBuild (PBC approach).
    3. Moves the PBD next to the exe and copies Argon2Hashing.dll there.
    4. Copies Argon2Hashing.dll to the solution folder too, for running from the IDE.
    5. With -Test: runs the .NET unit tests first, and afterwards runs "argon2demo.exe /selftest",
       which calls the DLL through the PowerBuilder proxy and writes argon2demo_selftest.txt.

.EXAMPLE
    pwsh -File build.ps1
.EXAMPLE
    pwsh -File build.ps1 -Platform 64 -Test
#>
param(
    # Build a 32-bit (the default) or 64-bit exe.
    [ValidateSet("32", "64")]
    [string]$Platform = "32",
    [switch]$Test,
    [string]$PBAutoBuild = "C:\Program Files (x86)\Appeon\PowerBuilder 25.0\pbautobuild250.exe"
)

$ErrorActionPreference = "Stop"

$root    = $PSScriptRoot
$project = Join-Path $root "Argon2Demo.pbproj"
$outDir  = Join-Path $root "build\argon2demo"
if ($Platform -eq "64") { $outDir += "-x64" }
New-Item -ItemType Directory -Force $outDir | Out-Null
$exe      = Join-Path $outDir "argon2demo.exe"
$buildLog = Join-Path $outDir "build.log"

# --- .NET assembly ----------------------------------------------------------
dotnet build (Join-Path $root "dotnet\Argon2Hashing\Argon2Hashing.csproj") -c Release --nologo -v quiet
if ($LASTEXITCODE -ne 0) { Write-Host "dotnet build failed"; exit 1 }

if ($Test) {
    dotnet run --project (Join-Path $root "dotnet\Argon2Hashing.Tests") -c Release -f net8.0
    if ($LASTEXITCODE -ne 0) { Write-Host ".NET tests failed"; exit 1 }
}

# --- PowerBuilder -----------------------------------------------------------
$build = Start-Process -FilePath $PBAutoBuild -NoNewWindow -Wait -PassThru -RedirectStandardOutput $buildLog `
    -ArgumentList '/pbc', '/d', "`"$project`"", '/o', "`"$exe`"", '/x', $Platform
if ($build.ExitCode -ne 0 -or -not (Test-Path $exe)) {
    Write-Host "PowerBuilder build failed; see $buildLog"
    exit 1
}

# PBC writes the PBD beside its library folder; move it next to the exe.
Move-Item -Force (Join-Path $root "PowerBuilder\argon2demo.pbd") $outDir

# --- Assembly next to the exe (and in the solution folder for the IDE) -------
$dll = Join-Path $root "dotnet\Argon2Hashing\bin\Release\net8.0"
foreach ($file in "Argon2Hashing.dll", "Argon2Hashing.deps.json") {
    Copy-Item (Join-Path $dll $file) $outDir
    Copy-Item (Join-Path $dll $file) $root
}

Write-Host "Built $exe"

# --- End-to-end self-test through PowerBuilder --------------------------------
if ($Test) {
    $report = Join-Path $outDir "argon2demo_selftest.txt"
    Remove-Item $report -ErrorAction SilentlyContinue
    $run = Start-Process -FilePath $exe -ArgumentList '/selftest' -WorkingDirectory $outDir -Wait -PassThru
    if (-not (Test-Path $report)) { Write-Host "Self-test produced no report (exit code $($run.ExitCode))"; exit 1 }
    Get-Content $report
    if (-not (Select-String -Path $report -Pattern '^RESULT: PASS' -Quiet)) { exit 1 }
}
