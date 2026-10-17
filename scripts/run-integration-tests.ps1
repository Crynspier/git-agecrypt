[CmdletBinding()]
param(
    [int]$MaxParallel = 4
)

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$tests = Get-ChildItem (Join-Path $root 'tests') -Filter '*.rs' -File |
    Where-Object { $_.Name -ne 'common.rs' } |
    Sort-Object Name

if ($MaxParallel -lt 1) {
    throw 'MaxParallel must be at least 1.'
}

# Cargo serializes package-cache and target-directory access. Build all integration
# binaries once, then run the already-built executables in parallel; starting one
# cargo process per test would mostly wait on Cargo's global file locks.
Push-Location $root
try {
    & cargo test --workspace --locked --tests --no-run
    if ($LASTEXITCODE -ne 0) {
        throw "Cargo failed to build integration tests with exit code $LASTEXITCODE"
    }
} finally {
    Pop-Location
}

$extension = if ($IsWindows -or $env:OS -eq 'Windows_NT') { '.exe' } else { '' }
$binaryDirectory = Join-Path $root 'target/debug/deps'
$jobs = @()
$failures = @()

function Wait-ForOneJob {
    param([switch]$WaitForAny)

    if ($WaitForAny) {
        $finished = Wait-Job -Job $jobs -Any
    } else {
        $finished = $jobs
        Wait-Job -Job $finished | Out-Null
    }

    foreach ($job in @($finished)) {
        Receive-Job -Job $job -Keep -ErrorAction Continue |
            ForEach-Object { Write-Output $_ }
        if ($job.State -ne 'Completed') {
            $script:failures += $job.Name
        }
        Remove-Job -Job $job -Force
        $script:jobs = @($jobs | Where-Object { $_.Id -ne $job.Id })
    }
}

foreach ($test in $tests) {
    while ($jobs.Count -ge $MaxParallel) {
        Wait-ForOneJob -WaitForAny
    }

    $testName = [IO.Path]::GetFileNameWithoutExtension($test.Name)
    $binary = Get-ChildItem $binaryDirectory -Filter "$testName-*${extension}" -File |
        Where-Object { $_.Name -notmatch '\.(d|pdb)$' } |
        Select-Object -First 1
    if (-not $binary) {
        throw "Could not find built integration test binary for '$testName'."
    }

    Write-Output "Starting $testName"
    $jobs += Start-Job -Name $testName -ArgumentList $binary.FullName -ScriptBlock {
        param($testBinary)
        & $testBinary --test-threads=2 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "Integration test '$testBinary' failed with exit code $LASTEXITCODE"
        }
    }
}

while ($jobs.Count -gt 0) {
    Wait-ForOneJob -WaitForAny
}

if ($failures.Count -gt 0) {
    throw "Integration test failures: $($failures -join ', ')"
}

Write-Output "All $($tests.Count) integration test binaries passed with up to $MaxParallel concurrent jobs."
