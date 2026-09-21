#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
usage: eng/verify-container.sh --image <ref> --version <A.B.C> --revision <40-hex-sha> [--index-only|--runtime-only]
       eng/verify-container.sh --compare-index <candidate> <stable> <latest>
EOF
  exit 64
}

image=""
version=""
revision=""
mode="all"
compare=()

while (($#)); do
  case "$1" in
    --image) image="${2:-}"; shift 2 ;;
    --version) version="${2:-}"; shift 2 ;;
    --revision) revision="${2:-}"; shift 2 ;;
    --index-only) mode="index"; shift ;;
    --runtime-only) mode="runtime"; shift ;;
    --compare-index)
      (($# == 4)) || usage
      compare=("$2" "$3" "$4")
      shift 4
      ;;
    *) usage ;;
  esac
done

raw_index() {
  docker buildx imagetools inspect --raw "$1"
}

if ((${#compare[@]})); then
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  raw_index "${compare[0]}" >"$tmp/candidate.json"
  raw_index "${compare[1]}" >"$tmp/stable.json"
  raw_index "${compare[2]}" >"$tmp/latest.json"
  cmp -s "$tmp/candidate.json" "$tmp/stable.json" || {
    echo "FAIL: stable index differs from the verified candidate index." >&2
    exit 1
  }
  cmp -s "$tmp/candidate.json" "$tmp/latest.json" || {
    echo "FAIL: latest index differs from the verified candidate index." >&2
    exit 1
  }
  echo "RESULT: PASS - candidate, stable and latest raw OCI indexes are byte-identical."
  exit 0
fi

[[ -n "$image" && "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ && "$revision" =~ ^[0-9a-f]{40}$ ]] || usage

if [[ "$mode" != "runtime" ]]; then
  tmp_index="$(mktemp)"
  trap 'rm -f "$tmp_index"' EXIT
  raw_index "$image" >"$tmp_index"
  python - "$tmp_index" <<'PY'
import json
import sys

doc = json.load(open(sys.argv[1], encoding="utf-8"))
manifests = doc.get("manifests")
if not isinstance(manifests, list):
    raise SystemExit("FAIL: image reference is not a multi-platform OCI index.")
platforms = []
for descriptor in manifests:
    platform = descriptor.get("platform") or {}
    platforms.append((platform.get("os"), platform.get("architecture")))
expected = [("linux", "amd64"), ("linux", "arm64")]
if sorted(platforms) != expected or len(manifests) != 2:
    raise SystemExit(f"FAIL: root index must contain exactly {expected!r}, got {platforms!r}")
PY
fi

if [[ "$mode" != "index" ]]; then
  docker pull "$image" >/dev/null

  inspect_file="$(mktemp)"
  docker image inspect "$image" >"$inspect_file"
  python - "$version" "$revision" "$inspect_file" <<'PY'
import json
import sys

expected_version, expected_revision, inspect_path = sys.argv[1:4]
image = json.load(open(inspect_path, encoding="utf-8"))[0]
config = image.get("Config") or {}
if config.get("User") != "app":
    raise SystemExit(f"FAIL: runtime user must be 'app', got {config.get('User')!r}")
if "8080/tcp" not in (config.get("ExposedPorts") or {}):
    raise SystemExit("FAIL: image does not expose 8080/tcp.")
if "/data" not in (config.get("Volumes") or {}):
    raise SystemExit("FAIL: image does not declare /data as a volume.")
labels = config.get("Labels") or {}
required = {
    "org.opencontainers.image.source": "https://github.com/bartbaszt/mcpiler-engine",
    "org.opencontainers.image.revision": expected_revision,
    "org.opencontainers.image.version": expected_version,
    "org.opencontainers.image.licenses": "Apache-2.0",
    "org.opencontainers.image.title": "MCPiler Engine",
    "org.opencontainers.image.description": "MCPiler public MCP resource runtime",
    "org.opencontainers.image.documentation": "https://github.com/bartbaszt/mcpiler-engine/blob/main/docs/hosting.md",
}
for key, value in required.items():
    if labels.get(key) != value:
        raise SystemExit(f"FAIL: OCI label {key!r} expected {value!r}, got {labels.get(key)!r}")
env = config.get("Env") or []
if any(item.startswith("MCPILER_MASTER_KEY") for item in env):
    raise SystemExit("FAIL: Platform master-key configuration leaked into Engine image config.")
PY
  rm -f "$inspect_file"

  identity="$(docker run --rm "$image" version)"
  [[ "$identity" == "mcpiler-engine $version"* ]] || {
    echo "FAIL: version verb reported '$identity', expected release $version." >&2
    exit 1
  }

  set +e
  refusal="$(docker run --rm "$image" serve 2>&1)"
  refusal_exit=$?
  set -e
  [[ $refusal_exit -eq 78 ]] || {
    echo "FAIL: missing-Manifest startup must refuse with exit 78, got $refusal_exit: $refusal" >&2
    exit 1
  }

  set +e
  paired_setting_refusal="$(docker run --rm "$image" serve --runtime-state-root /data/runtime-state 2>&1)"
  paired_setting_exit=$?
  set -e
  [[ $paired_setting_exit -eq 78 && "$paired_setting_refusal" == *"runtime-state-key-file"* ]] || {
    echo "FAIL: runtime-state root without its paired key file must refuse with exit 78: $paired_setting_refusal" >&2
    exit 1
  }
  [[ "$paired_setting_refusal" != *"MCPILER_MASTER_KEY"* ]] || {
    echo "FAIL: Engine runtime-state diagnostics advertise the Platform master-key channel." >&2
    exit 1
  }

  container="$(docker create "$image" version)"
  cleanup_container() { docker rm -f "$container" >/dev/null 2>&1 || true; }
  trap cleanup_container EXIT
  for path in \
    /licenses/mcpiler-engine/LICENSE \
    /licenses/mcpiler-engine/NOTICE \
    /licenses/mcpiler-engine/THIRD-PARTY-NOTICES.md \
    /usr/share/dotnet/LICENSE.txt \
    /usr/share/dotnet/ThirdPartyNotices.txt; do
    docker cp "$container:$path" - >/dev/null || {
      echo "FAIL: required redistribution file is missing from image: $path" >&2
      exit 1
    }
  done
  cleanup_container
  trap - EXIT
fi

echo "RESULT: PASS - Engine image contract verified for $image."
