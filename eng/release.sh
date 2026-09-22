#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT/eng/release-lib.sh"

BOT_NAME='github-actions[bot]'
BOT_EMAIL='41898282+github-actions[bot]@users.noreply.github.com'
HOST_PROJECT='src/MCPiler.Engine.Host/MCPiler.Engine.Host.csproj'

mode="inspect"
bump=""
base_sha=""
release_commit=""
release_tag=""
candidate_commit=""

usage() {
  cat <<'EOF'
usage:
  bash eng/release.sh --prepare --bump patch|minor|major
  bash eng/release.sh --publish-git --base-sha <sha> --release-commit <sha> --tag vA.B.C
  bash eng/release.sh --resume --release-commit <sha> --tag vA.B.C --candidate-commit <sha>

With no mutating mode the script prints current release metadata and performs no mutation.
Mutating modes require the dedicated GitHub Actions release context on refs/heads/main.
EOF
}

while (($#)); do
  case "$1" in
    --prepare) mode="prepare"; shift ;;
    --publish-git) mode="publish-git"; shift ;;
    --resume) mode="resume"; shift ;;
    --resume-visibility) mode="resume-visibility"; shift ;;
    --bump) bump="${2:-}"; shift 2 ;;
    --base-sha) base_sha="${2:-}"; shift 2 ;;
    --release-commit) release_commit="${2:-}"; shift 2 ;;
    --tag) release_tag="${2:-}"; shift 2 ;;
    --candidate-commit) candidate_commit="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "FAIL: unknown argument '$1'." >&2; usage >&2; exit 64 ;;
  esac
done

host_version() {
  local value
  value="$(sed -n 's:.*<Version>\([^<]*\)</Version>.*:\1:p' "$ROOT/$HOST_PROJECT" | head -n 1)"
  stable_version "$value" || { echo "FAIL: Host <Version> is not strict stable SemVer: '$value'." >&2; return 1; }
  printf '%s\n' "$value"
}

actions_mutation_guard() {
  if [[ "${GITHUB_ACTIONS:-}" != true || "${MCPILER_ENGINE_RELEASE_WORKFLOW:-}" != true || "${GITHUB_REF:-}" != refs/heads/main ]]; then
    echo 'RESULT: RELEASE_WORKFLOW_REQUIRED' >&2
    echo 'FAIL: Engine stable release mutation is allowed only in the dedicated GitHub Actions workflow on main.' >&2
    return 1
  fi
}

remote_tag_commit() {
  local tag="$1"
  git -C "$ROOT" ls-remote --tags origin "refs/tags/$tag^{}" | awk 'NR==1 {print $1}'
}

ensure_clean_main() {
  [[ "$(git -C "$ROOT" branch --show-current)" == main ]] || { echo 'FAIL: release checkout must be on main.' >&2; return 1; }
  [[ -z "$(git -C "$ROOT" status --porcelain)" ]] || { echo 'FAIL: release checkout is dirty.' >&2; return 1; }
}

replace_host_version() {
  local version="$1"
  python - "$ROOT/$HOST_PROJECT" "$version" <<'PY'
from pathlib import Path
import re
import sys

path = Path(sys.argv[1])
version = sys.argv[2]
text = path.read_text(encoding="utf-8-sig")
updated, count = re.subn(r"<Version>[^<]+</Version>", f"<Version>{version}</Version>", text, count=1)
if count != 1:
    raise SystemExit("Host project must contain exactly one replaceable <Version>.")
path.write_text(updated, encoding="utf-8", newline="\n")
PY
}

manifest_range() {
  local support="$ROOT/src/MCPiler.Engine/Manifest/ManifestFormatSupport.cs" min max
  min="$(sed -n 's/.*Minimum.*new(\([0-9][0-9]*\), \([0-9][0-9]*\)).*/\1.\2/p' "$support" | head -n1)"
  max="$(sed -n 's/.*Maximum.*new(\([0-9][0-9]*\), \([0-9][0-9]*\)).*/\1.\2/p' "$support" | head -n1)"
  [[ -n "$min" && -n "$max" ]] || return 1
  if [[ "$min" == "$max" ]]; then printf '%s\n' "$min"; else printf '%s to %s\n' "$min" "$max"; fi
}

prepare_changelog() {
  local version="$1" previous_tag="$2" base="$3" changelog="$ROOT/CHANGELOG.md" section range diagnostics tmp
  # The idempotence check must not depend on the checkout host's line endings; see changelog_lines.
  if changelog_lines "$changelog" | grep -Fqx "## v$version"; then
    return 0
  fi
  range="${previous_tag:-repository start}..$base"
  diagnostics='none'
  if [[ -n "$previous_tag" ]]; then
    diagnostics="$(git -C "$ROOT" diff "$previous_tag..$base" -- src/MCPiler.Engine/Manifest/Validation/ManifestDiagnosticCodes.cs \
      | sed -n 's/^+.*= "\([^"]*\)".*/\1/p' | sort -u | paste -sd ', ' -)"
    [[ -n "$diagnostics" ]] || diagnostics='none'
  else
    diagnostics='initial public diagnostic-code catalog; there is no prior stable Engine baseline'
  fi
  section="$(cat <<EOF
## v$version

- Git range: $range
- Manifest format: $(manifest_range)
- Diagnostic codes: $diagnostics
- Stable Engine release prepared from the reviewed source range above.
EOF
)"
  tmp="$(mktemp)"
  {
    head -n1 "$changelog"
    printf '\n%s\n\n' "$section"
    tail -n +2 "$changelog" | sed '1{/^[[:space:]]*$/d;}'
  } >"$tmp"
  mv "$tmp" "$changelog"
}

case "$mode" in
  inspect)
    version="$(host_version)"
    echo "ENGINE_VERSION=$version"
    echo "ENGINE_TAG=v$version"
    echo 'RESULT: INSPECT_ONLY'
    ;;

  prepare)
    actions_mutation_guard
    ensure_clean_main
    [[ "$bump" =~ ^(patch|minor|major)$ ]] || { echo 'FAIL: --prepare requires --bump patch|minor|major.' >&2; exit 64; }
    git -C "$ROOT" fetch origin main --tags
    base_sha="$(git -C "$ROOT" rev-parse HEAD)"
    origin_main="$(git -C "$ROOT" rev-parse origin/main)"
    assert_origin_unchanged "$base_sha" "$origin_main" || { echo 'RESULT: ORIGIN_RACE'; exit 1; }

    current="$(host_version)"
    previous_tag="$(git -C "$ROOT" tag --list 'v[0-9]*.[0-9]*.[0-9]*' --sort=-v:refname | head -n1)"
    if [[ -z "$previous_tag" ]]; then
      [[ "$bump" == patch && "$current" == 0.1.0 ]] || {
        echo 'FAIL: the first stable Engine release is fixed at v0.1.0 and must use the Patch entry point.' >&2
        exit 1
      }
      version="$current"
    else
      version="$(next_version "$current" "$bump")"
      replace_host_version "$version"
    fi
    release_tag="v$version"
    existing="$(remote_tag_commit "$release_tag")"
    assert_release_tag_absent "$existing" || { echo "FAIL: immutable Engine tag $release_tag already exists." >&2; exit 1; }
    prepare_changelog "$version" "$previous_tag" "$base_sha"

    git -C "$ROOT" config user.name "$BOT_NAME"
    git -C "$ROOT" config user.email "$BOT_EMAIL"
    git -C "$ROOT" add "$HOST_PROJECT" CHANGELOG.md
    if git -C "$ROOT" diff --cached --quiet; then
      # Bootstrap v0.1.0 already carries its final metadata. Create a release commit whose
      # only purpose is the immutable release boundary and DCO identity.
      (
        cd "$ROOT"
        git commit -s --allow-empty -m "chore(release): mcpiler-engine $release_tag"
      )
    else
      (
        cd "$ROOT"
        git commit -s -m "chore(release): mcpiler-engine $release_tag"
      )
    fi
    release_commit="$(git -C "$ROOT" rev-parse HEAD)"
    expected_signoff="Signed-off-by: $BOT_NAME <$BOT_EMAIL>"
    git -C "$ROOT" log -1 --format=%B "$release_commit" | grep -Fx "$expected_signoff" >/dev/null || {
      echo "FAIL: release commit is missing the exact DCO trailer: $expected_signoff" >&2
      exit 1
    }
    bash "$ROOT/eng/check-release-metadata.sh" --release-commit "$release_commit" >/dev/null
    echo "BASE_SHA=$base_sha"
    echo "RELEASE_VERSION=$version"
    echo "RELEASE_TAG=$release_tag"
    echo "RELEASE_COMMIT=$release_commit"
    echo 'RESULT: RELEASE_COMMITTED'
    ;;

  publish-git)
    actions_mutation_guard
    ensure_clean_main
    [[ "$base_sha" =~ ^[0-9a-f]{40}$ && "$release_commit" =~ ^[0-9a-f]{40}$ && "$release_tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || {
      echo 'FAIL: --publish-git requires full --base-sha, --release-commit and stable --tag.' >&2
      exit 64
    }
    [[ "$(git -C "$ROOT" rev-parse HEAD)" == "$release_commit" ]] || { echo 'FAIL: checkout is not the release commit.' >&2; exit 1; }
    [[ "$(git -C "$ROOT" rev-parse "$release_commit^")" == "$base_sha" ]] || { echo 'FAIL: release commit parent is not the recorded base.' >&2; exit 1; }
    bash "$ROOT/eng/check-release-metadata.sh" --release-commit "$release_commit" >/dev/null
    git -C "$ROOT" fetch origin main --tags
    origin_main="$(git -C "$ROOT" rev-parse origin/main)"
    assert_origin_unchanged "$base_sha" "$origin_main" || { echo 'RESULT: ORIGIN_RACE'; exit 1; }
    existing="$(remote_tag_commit "$release_tag")"
    assert_release_tag_absent "$existing" || { echo "FAIL: immutable Engine tag $release_tag already exists." >&2; exit 1; }
    git -C "$ROOT" tag -a "$release_tag" "$release_commit" -m "MCPiler Engine $release_tag"
    if ! git -C "$ROOT" push --atomic origin "$release_commit:refs/heads/main" "refs/tags/$release_tag"; then
      git -C "$ROOT" tag -d "$release_tag" >/dev/null 2>&1 || true
      echo 'RESULT: GIT_PUBLICATION_FAILED'
      exit 1
    fi
    echo 'RESULT: GIT_PUBLISHED'
    ;;

  resume)
    [[ "$release_commit" =~ ^[0-9a-f]{40}$ && "$candidate_commit" =~ ^[0-9a-f]{40}$ && "$release_tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || {
      echo 'FAIL: --resume requires --release-commit, --candidate-commit and --tag.' >&2
      exit 64
    }
    git -C "$ROOT" fetch origin main --tags
    remote_commit="$(remote_tag_commit "$release_tag")"
    mode_result="$(release_recovery_mode "$remote_commit" "$release_commit" "$candidate_commit")" || {
      echo 'FAIL: remote tag, release commit and candidate identity do not agree.' >&2
      exit 1
    }
    [[ "$mode_result" == RESUME ]] || { echo 'RESULT: RESUME_REFUSED_PRE_GIT'; exit 1; }
    echo 'RESULT: RESUME_ELIGIBLE'
    ;;

  resume-visibility)
    [[ "$release_commit" =~ ^[0-9a-f]{40}$ && "$candidate_commit" =~ ^[0-9a-f]{40}$ && "$release_tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || {
      echo 'FAIL: --resume-visibility requires --release-commit, --candidate-commit and --tag.' >&2
      exit 64
    }
    [[ "$release_commit" == "$candidate_commit" ]] || { echo 'FAIL: first-public candidate identity drifted from the release commit.' >&2; exit 1; }
    git -C "$ROOT" fetch origin main --tags
    remote_commit="$(remote_tag_commit "$release_tag")"
    [[ -z "$remote_commit" ]] || { echo 'FAIL: visibility-resume is only for the pre-Git first-public checkpoint; the release tag already exists.' >&2; exit 1; }
    echo 'RESULT: VISIBILITY_RESUME_ELIGIBLE'
    ;;
esac
