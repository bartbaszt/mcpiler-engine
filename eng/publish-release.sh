#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REGISTRY='ghcr.io'
REPOSITORY='bartbaszt/mcpiler-engine'
mode=""
sha=""
source_ref=""
target_tag=""

usage() {
  cat <<'EOF'
usage:
  bash eng/publish-release.sh --candidate --sha <40-hex-release-commit>
  bash eng/publish-release.sh --promote-stable --source <candidate-ref-or-digest> --target-tag vA.B.C
  bash eng/publish-release.sh --promote-latest --source <candidate-ref-or-digest>
EOF
}

while (($#)); do
  case "$1" in
    --candidate) mode="candidate"; shift ;;
    --promote-stable) mode="stable"; shift ;;
    --promote-latest) mode="latest"; shift ;;
    --sha) sha="${2:-}"; shift 2 ;;
    --source) source_ref="${2:-}"; shift 2 ;;
    --target-tag) target_tag="${2:-}"; shift 2 ;;
    *) echo "FAIL: unknown argument '$1'." >&2; usage >&2; exit 64 ;;
  esac
done

if [[ "${GITHUB_ACTIONS:-}" != true || "${MCPILER_ENGINE_RELEASE_WORKFLOW:-}" != true || "${GITHUB_REF:-}" != refs/heads/main ]]; then
  echo 'RESULT: RELEASE_WORKFLOW_REQUIRED' >&2
  exit 1
fi

image="$REGISTRY/$REPOSITORY"

raw_index() { docker buildx imagetools inspect --raw "$1"; }
exists() { docker buildx imagetools inspect "$1" >/dev/null 2>&1; }
digest() { docker buildx imagetools inspect "$1" --format '{{json .Manifest.Digest}}' | tr -d '"'; }

case "$mode" in
  candidate)
    [[ "$sha" =~ ^[0-9a-f]{40}$ ]] || { echo 'FAIL: candidate SHA must be full 40-character lowercase Git SHA.' >&2; exit 64; }
    ref="$image:$sha"
    exists "$ref" && { echo "FAIL: refusing to overwrite immutable candidate $ref." >&2; exit 1; }
    version="$(sed -n 's:.*<Version>\([^<]*\)</Version>.*:\1:p' "$ROOT/src/MCPiler.Engine.Host/MCPiler.Engine.Host.csproj" | head -n1)"
    [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo 'FAIL: invalid Host release version.' >&2; exit 1; }
    docker buildx build "$ROOT" \
      --platform linux/amd64,linux/arm64 \
      --provenance=false \
      --sbom=false \
      --build-arg "ENGINE_VERSION=$version" \
      --build-arg "SOURCE_REVISION=$sha" \
      --tag "$ref" \
      --push
    bash "$ROOT/eng/verify-container.sh" --image "$ref" --version "$version" --revision "$sha" --index-only
    echo "CANDIDATE_REF=$ref"
    echo "CANDIDATE_DIGEST=$(digest "$ref")"
    echo 'RESULT: CANDIDATE_PUBLISHED'
    ;;

  stable)
    [[ -n "$source_ref" && "$target_tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo 'FAIL: stable promotion requires --source and --target-tag vA.B.C.' >&2; exit 64; }
    target="$image:$target_tag"
    source_digest="$(digest "$source_ref")"
    if exists "$target"; then
      [[ "$(digest "$target")" == "$source_digest" ]] || { echo "FAIL: immutable stable tag $target already names a different digest." >&2; exit 1; }
      echo 'RESULT: STABLE_ALREADY_PROMOTED'
      exit 0
    fi
    docker buildx imagetools create --tag "$target" "$source_ref"
    [[ "$(digest "$target")" == "$source_digest" ]] || { echo 'FAIL: stable promotion digest mismatch.' >&2; exit 1; }
    echo 'RESULT: STABLE_PROMOTED'
    ;;

  latest)
    [[ -n "$source_ref" ]] || { echo 'FAIL: latest promotion requires --source.' >&2; exit 64; }
    target="$image:latest"
    source_digest="$(digest "$source_ref")"
    if exists "$target" && [[ "$(digest "$target")" == "$source_digest" ]]; then
      echo 'RESULT: LATEST_ALREADY_PROMOTED'
      exit 0
    fi
    docker buildx imagetools create --tag "$target" "$source_ref"
    [[ "$(digest "$target")" == "$source_digest" ]] || { echo 'FAIL: latest promotion digest mismatch.' >&2; exit 1; }
    echo 'RESULT: LATEST_PROMOTED'
    ;;

  *) usage >&2; exit 64 ;;
esac
