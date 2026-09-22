#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HOST="$ROOT/src/MCPiler.Engine.Host/MCPiler.Engine.Host.csproj"
CHANGELOG="$ROOT/CHANGELOG.md"
FORMAT_SUPPORT="$ROOT/src/MCPiler.Engine/Manifest/ManifestFormatSupport.cs"
BOT_NAME='github-actions[bot]'
BOT_EMAIL='41898282+github-actions[bot]@users.noreply.github.com'

release_commit=""
if [[ "${1:-}" == "--release-commit" ]]; then
  release_commit="${2:-}"
  [[ -n "$release_commit" ]] || { echo "FAIL: --release-commit requires a commit." >&2; exit 64; }
  shift 2
fi
[[ $# -eq 0 ]] || { echo "usage: eng/check-release-metadata.sh [--release-commit <sha>]" >&2; exit 64; }

version="$(sed -n 's:.*<Version>\([^<]*\)</Version>.*:\1:p' "$HOST" | head -n 1)"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || {
  echo "FAIL: Host <Version> must be strict stable SemVer, got '$version'." >&2
  exit 1
}

# A `core.autocrlf=true` checkout can materialize CHANGELOG.md as CRLF. Anchored and whole-line
# matching treats the CR as data, so normalize the line endings before reading release markers;
# .gitattributes pins the file to LF for new checkouts, and this keeps an already-materialized
# checkout correct.
changelog_normalized="$(tr -d '\r' <"$CHANGELOG")"

first_header="$(printf '%s\n' "$changelog_normalized" | grep -m1 -E '^## v[0-9]+\.[0-9]+\.[0-9]+$' || true)"
[[ "$first_header" == "## v$version" ]] || {
  echo "FAIL: first changelog release header '$first_header' does not match v$version." >&2
  exit 1
}

minimum="$(sed -n 's/.*Minimum.*new(\([0-9][0-9]*\), \([0-9][0-9]*\)).*/\1.\2/p' "$FORMAT_SUPPORT" | head -n 1)"
maximum="$(sed -n 's/.*Maximum.*new(\([0-9][0-9]*\), \([0-9][0-9]*\)).*/\1.\2/p' "$FORMAT_SUPPORT" | head -n 1)"
[[ -n "$minimum" && -n "$maximum" ]] || { echo "FAIL: could not read supported Manifest range." >&2; exit 1; }
supported="$minimum"
[[ "$minimum" == "$maximum" ]] || supported="$minimum to $maximum"
printf '%s\n' "$changelog_normalized" | grep -Fqx -- "- Manifest format: $supported" || {
  echo "FAIL: v$version changelog must state '- Manifest format: $supported'." >&2
  exit 1
}
printf '%s\n' "$changelog_normalized" | grep -Fq -- "- Diagnostic codes:" || {
  echo "FAIL: v$version changelog must describe diagnostic-code additions." >&2
  exit 1
}
printf '%s\n' "$changelog_normalized" | grep -Fq -- "- Git range:" || {
  echo "FAIL: v$version changelog must identify its Git range." >&2
  exit 1
}

expected_tag="v$version"
if [[ -n "${RELEASE_TAG:-}" && "$RELEASE_TAG" != "$expected_tag" ]]; then
  echo "FAIL: RELEASE_TAG '$RELEASE_TAG' does not match '$expected_tag'." >&2
  exit 1
fi
if [[ -n "${RELEASE_REVISION:-}" && ! "${RELEASE_REVISION}" =~ ^[0-9a-f]{40}$ ]]; then
  echo "FAIL: RELEASE_REVISION must be a full lowercase 40-character Git SHA." >&2
  exit 1
fi

OCI_SOURCE='https://github.com/bartbaszt/mcpiler-engine'
OCI_DOCUMENTATION='https://github.com/bartbaszt/mcpiler-engine/blob/main/docs/hosting.md'
OCI_TITLE='MCPiler Engine'
OCI_DESCRIPTION='MCPiler public MCP resource runtime'
OCI_LICENSES='Apache-2.0'
for value in "$OCI_SOURCE" "$OCI_DOCUMENTATION" "$OCI_TITLE" "$OCI_DESCRIPTION" "$OCI_LICENSES"; do
  [[ -n "$value" ]] || { echo "FAIL: an OCI label input is empty." >&2; exit 1; }
done

if [[ -n "$release_commit" ]]; then
  git -C "$ROOT" cat-file -e "$release_commit^{commit}" 2>/dev/null || {
    echo "FAIL: release commit '$release_commit' does not exist." >&2
    exit 1
  }
  author="$(git -C "$ROOT" show -s --format='%an <%ae>' "$release_commit")"
  [[ "$author" == "$BOT_NAME <$BOT_EMAIL>" ]] || {
    echo "FAIL: release commit author must be '$BOT_NAME <$BOT_EMAIL>', got '$author'." >&2
    exit 1
  }
  git -C "$ROOT" show -s --format='%B' "$release_commit" | grep -Fqx "Signed-off-by: $BOT_NAME <$BOT_EMAIL>" || {
    echo "FAIL: release commit is missing the exact github-actions[bot] Signed-off-by trailer." >&2
    exit 1
  }
fi

echo "ENGINE_VERSION=$version"
echo "ENGINE_TAG=$expected_tag"
echo "OCI_SOURCE=$OCI_SOURCE"
echo "OCI_DOCUMENTATION=$OCI_DOCUMENTATION"
echo "OCI_TITLE=$OCI_TITLE"
echo "OCI_DESCRIPTION=$OCI_DESCRIPTION"
echo "OCI_LICENSES=$OCI_LICENSES"
echo "RESULT: PASS - Engine release metadata is internally consistent for $expected_tag."
