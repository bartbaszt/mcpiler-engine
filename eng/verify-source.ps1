#!/usr/bin/env pwsh
# Canonical source-verification entry point for MCPiler Engine (PowerShell).
#
# This script MUST work in a standalone checkout with no parent-directory files and
# no MCPiler Platform assets present. It is behaviourally identical to verify-source.sh;
# the repository-boundary invariants are enforced by MCPiler.Engine.ArchitectureTests so
# there is exactly one cross-platform implementation of that guard.
$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
    $solution = 'MCPiler.Engine.slnx'
    $configuration = 'Release'

    Write-Host "==> dotnet restore $solution"
    & dotnet restore $solution
    if ($LASTEXITCODE -ne 0) { throw 'Restore failed.' }

    Write-Host "==> dotnet build $solution -c $configuration --no-restore"
    & dotnet build $solution -c $configuration --no-restore
    if ($LASTEXITCODE -ne 0) { throw 'Build failed.' }

    $projects = @(
        'tests/MCPiler.Engine.UnitTests/MCPiler.Engine.UnitTests.csproj',
        'tests/MCPiler.Engine.ArchitectureTests/MCPiler.Engine.ArchitectureTests.csproj'
    )
    foreach ($project in $projects) {
        Write-Host "==> dotnet test $project -c $configuration --no-build"
        & dotnet test $project -c $configuration --no-build
        if ($LASTEXITCODE -ne 0) { throw "Tests failed: $project" }
    }

    Write-Host '==> Source verification succeeded'
}
finally {
    Pop-Location
}
