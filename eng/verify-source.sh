#!/usr/bin/env bash
# Canonical source-verification entry point for MCPiler Engine.
#
# This script MUST work in a standalone checkout with no parent-directory files and
# no MCPiler Platform assets present.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

solution="MCPiler.Engine.slnx"
configuration="Release"

echo "==> dotnet restore $solution"
dotnet restore "$solution"

echo "==> dotnet build $solution -c $configuration --no-restore"
dotnet build "$solution" -c "$configuration" --no-restore

for project in \
  tests/MCPiler.Engine.UnitTests/MCPiler.Engine.UnitTests.csproj \
  tests/MCPiler.Engine.IntegrationTests/MCPiler.Engine.IntegrationTests.csproj \
  tests/MCPiler.Engine.ArchitectureTests/MCPiler.Engine.ArchitectureTests.csproj
do
  echo "==> dotnet test $project -c $configuration --no-build"
  dotnet test "$project" -c "$configuration" --no-build
done

echo "==> Source verification succeeded"
