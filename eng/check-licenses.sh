#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HOST="$ROOT/src/MCPiler.Engine.Host/MCPiler.Engine.Host.csproj"
POLICY="$ROOT/eng/licenses"
NOTICE="$ROOT/THIRD-PARTY-NOTICES.md"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

cd "$ROOT"

dotnet tool restore >/dev/null
dotnet restore "$HOST" >/dev/null

dotnet tool run nuget-license -- \
  -i "$HOST" \
  -t \
  --exclude-publish-false \
  -a "$POLICY/allowed-licenses.json" \
  -override "$POLICY/license-overrides.json" \
  -ignore "$POLICY/ignored-build-only-packages.json" \
  -o JsonPretty \
  -fo "$TMP/inventory.json" >/dev/null

python "$POLICY/render-notices.py" "$TMP/inventory.json" "$TMP/THIRD-PARTY-NOTICES.md"

if [[ ! -f "$NOTICE" ]]; then
  echo "FAIL: THIRD-PARTY-NOTICES.md is missing. Generate it from the verified runtime graph." >&2
  exit 1
fi

tr -d '\r' <"$NOTICE" >"$TMP/committed-notices.md"
if ! cmp -s "$TMP/THIRD-PARTY-NOTICES.md" "$TMP/committed-notices.md"; then
  echo "FAIL: THIRD-PARTY-NOTICES.md does not match the current Host runtime dependency graph." >&2
  diff -u "$TMP/committed-notices.md" "$TMP/THIRD-PARTY-NOTICES.md" || true
  exit 1
fi

python - "$TMP/inventory.json" <<'PY'
import json
import sys

items = json.load(open(sys.argv[1], encoding="utf-8-sig"))
actual = {(item["PackageId"], item["PackageVersion"], item["License"]) for item in items}
expected_exceptions = {
    ("Json.More.Net", "3.0.1", "MCPILER-APPROVED-OSMFEULA"),
    ("JsonPointer.Net", "7.0.2", "MCPILER-APPROVED-OSMFEULA"),
    ("JsonSchema.Net", "9.4.0", "MCPILER-APPROVED-OSMFEULA"),
}
actual_exceptions = {row for row in actual if row[2] == "MCPILER-APPROVED-OSMFEULA"}
if actual_exceptions != expected_exceptions:
    raise SystemExit(
        "FAIL: reviewed OSMFEULA exception set drifted: "
        f"expected {sorted(expected_exceptions)!r}, got {sorted(actual_exceptions)!r}"
    )

for analyzer in {
    "Meziantou.Analyzer",
    "Microsoft.CodeAnalysis.BannedApiAnalyzers",
    "Microsoft.VisualStudio.Threading.Analyzers",
}:
    if any(package_id == analyzer for package_id, _, _ in actual):
        raise SystemExit(f"FAIL: build-only analyzer leaked into runtime notice inventory: {analyzer}")
PY

echo "RESULT: PASS - Engine Host runtime licences and deterministic notices are verified."
