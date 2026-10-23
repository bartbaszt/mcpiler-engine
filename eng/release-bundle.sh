#!/usr/bin/env bash
# Transport of release payloads that GitHub Actions artifacts cannot carry.
#
# The Engine release pipeline stores no GitHub Actions artifacts: the prepared release commit and
# the candidate SBOM travel as base64 text through job outputs (same run) and through the prepare
# job log (resume of an already failed run). Nothing here publishes a Git ref, writes a registry
# tag, or widens a job's `permissions:` block; every payload is authenticated by SHA-256 and the
# release commit identity is proved before a working tree is moved.
#
# A bundle produced by `write` is deliberately incremental: it contains the release commit and
# its trees/blobs and records `base_sha` as a prerequisite. Restoring therefore works only in a
# checkout that already holds the reviewed base commit, which is also what proves the release
# commit sits directly on top of the reviewed base.
set -euo pipefail

PROG='eng/release-bundle.sh'
BUNDLE_BEGIN_MARKER='ENGINE_RELEASE_BUNDLE_BEGIN'
BUNDLE_END_MARKER='ENGINE_RELEASE_BUNDLE_END'

# Every payload reaches a consumer as one step environment string. Linux caps a single such string
# at MAX_ARG_STRLEN = 131072 bytes, counted as NAME + '=' + value + NUL, and rejects the whole step
# with E2BIG above it. Both transport caps therefore have to stay below that ceiling with room for
# the longest variable name - not merely below the 1 MB per-job output cap that `$GITHUB_OUTPUT`
# enforces in the producing job.
PAYLOAD_MAX_ENCODED_BYTES=120000

usage() {
  cat <<'EOF'
usage:
  release-bundle.sh write --repo <dir> --bundle <file> --base-sha <sha> --release-commit <sha>
  release-bundle.sh encode --bundle <file> [--max-bytes <n>]
  release-bundle.sh print-log --bundle <file> --release-commit <sha> --sha256 <hex>
  release-bundle.sh extract-log --repo <dir> --log <file> --bundle <file>
  release-bundle.sh extract-best-block --repo <dir> --input <manifest> --bundle <file>
  release-bundle.sh restore --repo <dir> (--bundle <file> | --base64-stdin) --sha256 <hex>
                            --base-sha <sha> --release-commit <sha>
  release-bundle.sh sbom-encode --input <json> --output <file> [--max-bytes <n>]
  release-bundle.sh sbom-restore --input <file> --output <json> --sha256 <hex>

Bundles are incremental over --base-sha and always carry exactly one head, refs/heads/main.
`encode` emits one unwrapped base64 line for a job output; `print-log` wraps it at 76 columns
between ENGINE_RELEASE_BUNDLE_BEGIN/END markers so a failed run can be resumed from its own log.
`extract-best-block` reads a "<started_at>\t<job_id>\t<log-path>" manifest in newest-first order
and accepts the first log whose block is valid.
EOF
}

fail() {
  printf 'FAIL: %s\n' "$*" >&2
  exit 1
}

die_usage() {
  printf 'FAIL: %s\n' "$*" >&2
  usage >&2
  exit 64
}

# SHA-256 of a file: sha256sum (GitHub runners, Git Bash) with portable fallbacks.
sha256_of() { # file -> hex
  local file="$1"
  [[ -f "$file" ]] || fail "file does not exist: $file"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$file" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$file" | awk '{print $1}'
  elif command -v openssl >/dev/null 2>&1; then
    openssl dgst -sha256 "$file" | awk '{print $NF}'
  else
    fail 'no SHA-256 implementation available (need sha256sum, shasum or openssl).'
  fi
}

require_sha() { # value label
  [[ "${1:-}" =~ ^[0-9a-f]{40}$ ]] || fail "$2 must be a full lowercase 40-character Git SHA."
}

require_hex() { # value label
  [[ "${1:-}" =~ ^[0-9a-f]{64}$ ]] || fail "$2 must be a lowercase 64-character SHA-256 hex digest."
}

require_uint() { # value label
  [[ "${1:-}" =~ ^[0-9]+$ ]] || fail "$2 must be a non-negative integer."
}

absolute_path() { # path -> absolute path, resolved against the current directory
  local dir base
  dir="$(cd "$(dirname "$1")" && pwd)"
  base="$(basename "$1")"
  printf '%s/%s\n' "$dir" "$base"
}

# The single head of a release bundle must be refs/heads/main at the release commit. `git bundle`
# may add a HEAD entry when the bundle is created with a symbolic ref, so require exactly one.
assert_bundle_head() { # repo bundle release-commit
  local repo="$1" bundle="$2" release_commit="$3" heads expected actual
  heads="$(git -C "$repo" bundle list-heads "$bundle")" || {
    printf 'FAIL: cannot read bundle heads: %s\n' "$bundle" >&2
    return 1
  }
  expected="$release_commit refs/heads/main"
  actual="$(printf '%s\n' "$heads" | sed '/^[[:space:]]*$/d')"
  [[ "$actual" == "$expected" ]] || {
    printf "FAIL: bundle must carry exactly one head '%s', got: %s\n" "$expected" "${actual:-<none>}" >&2
    return 1
  }
}

# Bundle prerequisites are recorded in the bundle header; `git bundle verify` prints them and
# needs a repository that already holds the objects. LC_ALL=C pins the message text.
bundle_prerequisite() { # repo bundle -> base sha
  local repo="$1" bundle="$2" output base
  output="$(LC_ALL=C git -C "$repo" bundle verify "$bundle" 2>&1)" || {
    printf '%s\n' "$output" >&2
    printf 'FAIL: bundle verification failed: its prerequisite commits are not present in the repository.\n' >&2
    return 1
  }
  base="$(printf '%s\n' "$output" | awk '/^The bundle requires this ref:/{getline; print $1; exit}')"
  [[ "${base:-}" =~ ^[0-9a-f]{40}$ ]] || {
    printf 'FAIL: bundle prerequisite must be a full lowercase 40-character Git SHA, got %q.\n' "${base:-}" >&2
    return 1
  }
  [[ "$(printf '%s\n' "$output" | grep -c '^The bundle requires this ref:')" -eq 1 ]] || {
    printf 'FAIL: bundle must record exactly one prerequisite commit.\n' >&2
    return 1
  }
  printf '%s\n' "$base"
}

# Extract one marked bundle block from one GitHub job log and authenticate it. Returns non-zero for
# any missing, duplicated, malformed, truncated or digest-mismatched block so the caller can either
# fail closed (`extract-log`) or try the next candidate log (`extract-best-block`).
extract_block() { # repo log bundle -> identity lines on stdout
  local repo="$1" log="$2" bundle="$3" work payload begins ends in_block marker marker_commit marker_sha
  local line clean ansi payload_size actual_sha extracted_base
  [[ -f "$log" ]] || { printf 'FAIL: job log does not exist: %s\n' "$log" >&2; return 1; }
  work="$(mktemp -d)"
  # GitHub job logs prefix every line with an RFC 3339 UTC timestamp. Strip that prefix (and any
  # CR) before matching, so the block is independent of the log transport's formatting.
  tr -d '\r' <"$log" \
    | sed -E 's/^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?Z //' >"$work/lines"
  # GitHub renders `##[group]` and echoed-command headers with ANSI colour escapes. Marker lines may
  # be decorated that way, so classification reads the escape-stripped copy; payload lines must be
  # byte-identical plain base64, which the lockstep comparison below enforces.
  ansi="$(printf '\033')"
  sed -E "s/${ansi}\\[[0-9;]*[A-Za-z]//g" "$work/lines" >"$work/clean" || {
    printf 'FAIL: cannot normalise the job log.\n' >&2
    rm -rf "$work"
    return 1
  }
  payload="$work/payload.b64"
  : >"$payload"
  begins=0
  ends=0
  in_block=0
  marker_commit=''
  marker_sha=''
  exec 3<"$work/clean"
  exec 4<"$work/lines"
  while IFS= read -r clean <&3 || [[ -n "$clean" ]]; do
    IFS= read -r line <&4 || line=''
    if [[ "$clean" == "$BUNDLE_BEGIN_MARKER "* ]]; then
      begins=$((begins + 1))
      ((begins == 1)) || { printf 'FAIL: job log contains more than one release bundle block.\n' >&2; exec 3<&- 4<&-; rm -rf "$work"; return 1; }
      ((in_block == 0)) || { printf 'FAIL: job log contains a nested release bundle block.\n' >&2; exec 3<&- 4<&-; rm -rf "$work"; return 1; }
      marker="${clean#"$BUNDLE_BEGIN_MARKER" }"
      [[ "$marker" =~ ^release_commit=([0-9a-f]{40})\ sha256=([0-9a-f]{64})$ ]] || {
        printf 'FAIL: malformed release bundle begin marker: %s\n' "$clean" >&2
        exec 3<&- 4<&-
        rm -rf "$work"
        return 1
      }
      marker_commit="${BASH_REMATCH[1]}"
      marker_sha="${BASH_REMATCH[2]}"
      in_block=1
    elif [[ "$clean" == "$BUNDLE_END_MARKER" ]]; then
      ((in_block == 1)) || { printf 'FAIL: job log contains a release bundle end marker without a begin marker.\n' >&2; exec 3<&- 4<&-; rm -rf "$work"; return 1; }
      ends=$((ends + 1))
      in_block=0
    elif ((in_block == 1)); then
      [[ "$line" == "$clean" ]] || { printf 'FAIL: job log release bundle block carries escape sequences.\n' >&2; exec 3<&- 4<&-; rm -rf "$work"; return 1; }
      [[ "$clean" =~ ^[A-Za-z0-9+/=]*$ ]] || { printf 'FAIL: job log release bundle block contains a non-base64 line.\n' >&2; exec 3<&- 4<&-; rm -rf "$work"; return 1; }
      printf '%s' "$clean" >>"$payload"
    fi
  done
  exec 3<&- 4<&-

  ((begins == 1)) || { printf 'FAIL: job log does not contain a release bundle block.\n' >&2; rm -rf "$work"; return 1; }
  ((ends == 1)) || { printf 'FAIL: job log release bundle block is missing its end marker.\n' >&2; rm -rf "$work"; return 1; }
  ((in_block == 0)) || { printf 'FAIL: job log release bundle block is truncated.\n' >&2; rm -rf "$work"; return 1; }
  if [[ ! -s "$payload" ]]; then
    printf 'FAIL: job log release bundle block is empty.\n' >&2
    rm -rf "$work"
    return 1
  fi
  payload_size="$(wc -c <"$payload" | tr -d '[:space:]')"
  if ((payload_size % 4 != 0)); then
    printf 'FAIL: job log release bundle block is not complete base64.\n' >&2
    rm -rf "$work"
    return 1
  fi
  if ! base64 -d <"$payload" >"$bundle"; then
    printf 'FAIL: job log release bundle block is not decodable base64.\n' >&2
    rm -rf "$work"
    return 1
  fi
  rm -rf "$work"
  actual_sha="$(sha256_of "$bundle")"
  [[ "$actual_sha" == "$marker_sha" ]] || {
    printf "FAIL: restored bundle SHA-256 %s does not match the marker's %s.\n" "$actual_sha" "$marker_sha" >&2
    return 1
  }
  assert_bundle_head "$repo" "$(absolute_path "$bundle")" "$marker_commit" || return 1
  extracted_base="$(bundle_prerequisite "$repo" "$(absolute_path "$bundle")")" || return 1
  printf 'RELEASE_COMMIT=%s\n' "$marker_commit"
  printf 'RELEASE_BUNDLE_SHA256=%s\n' "$marker_sha"
  printf 'RELEASE_BASE_SHA=%s\n' "$extracted_base"
}

mode="${1:-}"
[[ -n "$mode" ]] || die_usage 'missing subcommand.'
shift

repo=''
bundle=''
base_sha=''
release_commit=''
expected_sha=''
log=''
input=''
output=''
max_bytes=''
base64_stdin='false'

while (($#)); do
  case "$1" in
    --repo) repo="${2:-}"; shift 2 ;;
    --bundle) bundle="${2:-}"; shift 2 ;;
    --base-sha) base_sha="${2:-}"; shift 2 ;;
    --release-commit) release_commit="${2:-}"; shift 2 ;;
    --sha256) expected_sha="${2:-}"; shift 2 ;;
    --log) log="${2:-}"; shift 2 ;;
    --input) input="${2:-}"; shift 2 ;;
    --output) output="${2:-}"; shift 2 ;;
    --max-bytes) max_bytes="${2:-}"; shift 2 ;;
    --base64-stdin) base64_stdin='true'; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die_usage "unknown argument '$1'." ;;
  esac
done

case "$mode" in
  write)
    [[ -n "$repo" && -n "$bundle" ]] || die_usage 'write requires --repo and --bundle.'
    require_sha "$base_sha" '--base-sha'
    require_sha "$release_commit" '--release-commit'
    [[ -d "$repo/.git" || -f "$repo/HEAD" ]] || fail "--repo is not a Git repository: $repo"
    [[ "$(git -C "$repo" rev-parse --verify --quiet "$release_commit^{commit}")" == "$release_commit" ]] || {
      fail "release commit $release_commit is not a commit in $repo."
    }
    [[ "$(git -C "$repo" rev-parse --verify --quiet "$base_sha^{commit}")" == "$base_sha" ]] || {
      fail "base commit $base_sha is not a commit in $repo."
    }
    # The release commit must be exactly one commit on top of the reviewed base. A bundle would
    # still be created for a longer range, so this is asserted before anything is encoded.
    [[ "$(git -C "$repo" rev-parse "$release_commit^")" == "$base_sha" ]] || {
      fail "release commit $release_commit does not have $base_sha as its parent."
    }
    [[ "$(git -C "$repo" rev-parse --verify --quiet refs/heads/main)" == "$release_commit" ]] || {
      fail 'main must point at the release commit before it is bundled.'
    }
    rm -f "$bundle"
    git -C "$repo" bundle create "$(absolute_path "$bundle")" "^$base_sha" main
    assert_bundle_head "$repo" "$(absolute_path "$bundle")" "$release_commit"
    printf 'RELEASE_BUNDLE_SHA256=%s\n' "$(sha256_of "$bundle")"
    printf 'RELEASE_BUNDLE_SIZE=%s\n' "$(wc -c <"$bundle" | tr -d '[:space:]')"
    echo 'RESULT: RELEASE_BUNDLE_WRITTEN'
    ;;

  encode)
    [[ -n "$bundle" ]] || die_usage 'encode requires --bundle.'
    max_bytes="${max_bytes:-$PAYLOAD_MAX_ENCODED_BYTES}"
    require_uint "$max_bytes" '--max-bytes'
    [[ -f "$bundle" ]] || fail "bundle does not exist: $bundle"
    raw_size="$(wc -c <"$bundle" | tr -d '[:space:]')"
    # Standard base64 with padding: exactly 4 * ceil(raw / 3) characters, no line wrapping. The cap
    # protects the step environment string that carries the payload to a consumer job, which Linux
    # limits to 131072 bytes (MAX_ARG_STRLEN) for a single NAME=value entry.
    encoded_size=$(((raw_size + 2) / 3 * 4))
    ((encoded_size <= max_bytes)) || {
      fail "encoded release bundle would be $encoded_size bytes (raw $raw_size), above the $max_bytes-byte payload budget. A step environment string is limited to 131072 bytes, so prepare must stop here instead of letting every consumer job fail at step start with E2BIG."
    }
    base64 -w0 "$bundle"
    printf '\n'
    ;;

  print-log)
    [[ -n "$bundle" ]] || die_usage 'print-log requires --bundle.'
    require_sha "$release_commit" '--release-commit'
    require_hex "$expected_sha" '--sha256'
    [[ -f "$bundle" ]] || fail "bundle does not exist: $bundle"
    actual_sha="$(sha256_of "$bundle")"
    [[ "$actual_sha" == "$expected_sha" ]] || {
      fail "bundle SHA-256 $actual_sha does not match the expected $expected_sha."
    }
    printf '%s release_commit=%s sha256=%s\n' "$BUNDLE_BEGIN_MARKER" "$release_commit" "$expected_sha"
    base64 -w76 "$bundle"
    printf '%s\n' "$BUNDLE_END_MARKER"
    echo 'RESULT: RELEASE_BUNDLE_LOGGED'
    ;;

  extract-log)
    [[ -n "$repo" && -n "$log" && -n "$bundle" ]] || die_usage 'extract-log requires --repo, --log and --bundle.'
    extract_block "$repo" "$log" "$bundle" || exit 1
    echo 'RESULT: RELEASE_BUNDLE_EXTRACTED'
    ;;

  extract-best-block)
    # A re-run attempt can hide the valid block behind a prepare job that failed earlier, so the
    # caller hands over every matching prepare job in newest-first order. The manifest lines are
    # "<started_at>\t<job_id>\t<log-path>"; each log must still carry exactly one well-formed block.
    [[ -n "$repo" && -n "$input" && -n "$bundle" ]] || die_usage 'extract-best-block requires --repo, --input and --bundle.'
    [[ -f "$input" ]] || fail "candidate manifest does not exist: $input"
    selected=''
    while IFS=$'\t' read -r started_at job_id candidate_log; do
      [[ -n "${job_id:-}" && -n "${candidate_log:-}" ]] || continue
      printf 'Trying prepare job %s (started %s) from %s.\n' "$job_id" "${started_at:-<unknown>}" "$candidate_log" >&2
      if result="$(extract_block "$repo" "$candidate_log" "$bundle")"; then
        selected="$job_id"
        printf '%s\n' "$result"
        printf 'JOB_ID=%s\n' "$job_id"
        echo 'RESULT: RELEASE_BUNDLE_EXTRACTED'
        exit 0
      fi
      printf 'Prepare job %s did not yield a valid release bundle block; trying the next candidate.\n' "$job_id" >&2
    done <"$input"
    fail 'no prepare job in the selected run carries a valid release bundle block.'
    ;;

  restore)
    [[ -n "$repo" ]] || die_usage 'restore requires --repo.'
    require_sha "$base_sha" '--base-sha'
    require_sha "$release_commit" '--release-commit'
    require_hex "$expected_sha" '--sha256'
    [[ -d "$repo/.git" || -f "$repo/HEAD" ]] || fail "--repo is not a Git repository: $repo"
    work=''
    if [[ "$base64_stdin" == 'true' ]]; then
      work="$(mktemp -d)"
      trap 'rm -rf "$work"' EXIT
      bundle="$work/release.bundle"
      base64 -d >"$bundle" || fail 'release bundle input is not decodable base64.'
    fi
    [[ -n "$bundle" ]] || die_usage 'restore requires --bundle or --base64-stdin.'
    [[ -f "$bundle" ]] || fail "bundle does not exist: $bundle"
    actual_sha="$(sha256_of "$bundle")"
    [[ "$actual_sha" == "$expected_sha" ]] || {
      fail "release bundle SHA-256 $actual_sha does not match the expected $expected_sha."
    }
    [[ "$(git -C "$repo" rev-parse --verify --quiet "$base_sha^{commit}")" == "$base_sha" ]] || {
      fail "base commit $base_sha is not present in $repo; restore must start from the reviewed base."
    }
    assert_bundle_head "$repo" "$(absolute_path "$bundle")" "$release_commit"
    git -C "$repo" fetch --quiet --no-tags "$(absolute_path "$bundle")" main
    [[ "$(git -C "$repo" rev-parse FETCH_HEAD)" == "$release_commit" ]] || {
      fail 'release bundle identity mismatch: FETCH_HEAD is not the expected release commit.'
    }
    [[ "$(git -C "$repo" rev-parse "FETCH_HEAD^")" == "$base_sha" ]] || {
      fail 'release bundle is not one commit on top of the expected base.'
    }
    git -C "$repo" reset --hard --quiet FETCH_HEAD
    [[ "$(git -C "$repo" rev-parse HEAD)" == "$release_commit" ]] || {
      fail 'working tree did not move to the expected release commit.'
    }
    printf 'HEAD=%s\n' "$release_commit"
    echo 'RESULT: RELEASE_BUNDLE_RESTORED'
    ;;

  sbom-encode)
    [[ -n "$input" && -n "$output" ]] || die_usage 'sbom-encode requires --input and --output.'
    max_bytes="${max_bytes:-$PAYLOAD_MAX_ENCODED_BYTES}"
    require_uint "$max_bytes" '--max-bytes'
    [[ -f "$input" ]] || fail "SBOM does not exist: $input"
    sha="$(sha256_of "$input")"
    gz="$output.gz.tmp"
    # gzip -9n omits the name and mtime fields, so the same SBOM always encodes to identical bytes.
    gzip -9n -c "$input" >"$gz"
    base64 -w0 "$gz" >"$output"
    rm -f "$gz"
    encoded_size="$(wc -c <"$output" | tr -d '[:space:]')"
    ((encoded_size <= max_bytes)) || {
      rm -f "$output"
      fail "encoded SBOM would be $encoded_size bytes, above the $max_bytes-byte payload budget. A step environment string is limited to 131072 bytes, so the SBOM job must stop here instead of letting the supply-chain job fail at step start with E2BIG."
    }
    printf 'SBOM_SHA256=%s\n' "$sha"
    printf 'SBOM_ENCODED_SIZE=%s\n' "$encoded_size"
    echo 'RESULT: SBOM_ENCODED'
    ;;

  sbom-restore)
    [[ -n "$input" && -n "$output" ]] || die_usage 'sbom-restore requires --input and --output.'
    require_hex "$expected_sha" '--sha256'
    [[ -f "$input" ]] || fail "encoded SBOM does not exist: $input"
    gz="$output.gz.tmp"
    base64 -d <"$input" >"$gz" || { rm -f "$gz"; fail 'encoded SBOM is not decodable base64.'; }
    gzip -dc "$gz" >"$output" || { rm -f "$gz" "$output"; fail 'encoded SBOM is not decodable gzip.'; }
    rm -f "$gz"
    actual_sha="$(sha256_of "$output")"
    [[ "$actual_sha" == "$expected_sha" ]] || {
      rm -f "$output"
      fail "restored SBOM SHA-256 $actual_sha does not match the expected $expected_sha."
    }
    printf 'SBOM_SHA256=%s\n' "$actual_sha"
    echo 'RESULT: SBOM_RESTORED'
    ;;

  -h|--help) usage ;;
  *) die_usage "unknown subcommand '$mode'." ;;
esac
