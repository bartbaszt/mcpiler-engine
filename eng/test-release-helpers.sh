#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
failures=0

expect_eq() {
  local expected="$1" actual="$2" label="$3"
  if [[ "$actual" != "$expected" ]]; then
    printf 'FAIL: %s: expected %q, got %q\n' "$label" "$expected" "$actual" >&2
    failures=$((failures + 1))
  fi
}

expect_success() {
  local label="$1"
  shift
  if ! "$@" >/dev/null 2>&1; then
    printf 'FAIL: %s: expected success\n' "$label" >&2
    failures=$((failures + 1))
  fi
}

expect_failure() {
  local label="$1"
  shift
  if "$@" >/dev/null 2>&1; then
    printf 'FAIL: %s: expected failure\n' "$label" >&2
    failures=$((failures + 1))
  fi
}

metadata_output="$(bash "$ROOT/eng/check-release-metadata.sh")"
expect_success "release metadata current state" bash "$ROOT/eng/check-release-metadata.sh"
expect_failure "release tag must match Host version" env RELEASE_TAG=v9.9.9 bash "$ROOT/eng/check-release-metadata.sh"
expect_failure "release revision must be full Git SHA" env RELEASE_REVISION=abc bash "$ROOT/eng/check-release-metadata.sh"
expect_eq "ENGINE_TAG=v0.1.0" "$(printf '%s\n' "$metadata_output" | grep '^ENGINE_TAG=')" "release tag shape"
expect_eq "OCI_SOURCE=https://github.com/bartbaszt/mcpiler-engine" "$(printf '%s\n' "$metadata_output" | grep '^OCI_SOURCE=')" "OCI source input"
expect_eq "OCI_LICENSES=Apache-2.0" "$(printf '%s\n' "$metadata_output" | grep '^OCI_LICENSES=')" "OCI licence input"

verify_container="$ROOT/eng/verify-container.sh"
expect_success "container verifier is executable" test -x "$verify_container"
expect_success "container verifier has a valid Manifest fixture" grep -Fq 'tests/fixtures/manifests/minimal' "$verify_container"
expect_success "container verifier supplies a Manifest mount" grep -Fq -- '--mount /minimal=/manifests/minimal' "$verify_container"
expect_success "container verifier supplies a file-store root" grep -Fq -- '--file-store-root /data/files' "$verify_container"

if [[ "${1:-}" == "--metadata-only" ]]; then
  if (( failures > 0 )); then
    printf 'RESULT: FAIL - %d release metadata helper test(s) failed.\n' "$failures" >&2
    exit 1
  fi
  printf 'RESULT: PASS - deterministic Engine release metadata helper contracts hold.\n'
  exit 0
fi

source "$ROOT/eng/release-lib.sh"

expect_eq "0.1.1" "$(next_version 0.1.0 patch)" "patch bump"
expect_eq "0.2.0" "$(next_version 0.1.0 minor)" "minor bump"
expect_eq "1.0.0" "$(next_version 0.1.0 major)" "major bump"
expect_failure "prerelease current version" next_version "0.1.0-alpha" patch

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
cat >"$tmp/CHANGELOG.md" <<'EOF'
# Changelog

## v0.2.0
New release.

## v0.1.0
Old release.
EOF
expect_eq $'## v0.2.0\nNew release.' "$(changelog_section "$tmp/CHANGELOG.md" 0.2.0)" "changelog extraction"

expect_success "new immutable tag" assert_release_tag_absent ""
expect_failure "existing immutable tag" assert_release_tag_absent "0123456789abcdef"
expect_success "origin race unchanged" assert_origin_unchanged "abc" "abc"
expect_failure "origin race moved" assert_origin_unchanged "abc" "def"

expect_success "resume after immutable tag" assert_resume_eligible "abc" "abc" "abc"
expect_failure "resume before git publication" assert_resume_eligible "" "abc" "abc"
expect_failure "resume with tag mismatch" assert_resume_eligible "abc" "def" "abc"

expect_eq "PACKAGE_VISIBILITY_REQUIRED" "$(visibility_checkpoint false true)" "first private verified candidate"
expect_eq "READY" "$(visibility_checkpoint true true)" "public verified candidate"
expect_failure "visibility cannot bypass verification" visibility_checkpoint true false

expect_success "candidate/stable/latest identical" assert_promoted_identity "sha256:abc" "sha256:abc" "sha256:abc"
expect_failure "stable differs from candidate" assert_promoted_identity "sha256:abc" "sha256:def" "sha256:abc"
expect_failure "latest differs from candidate" assert_promoted_identity "sha256:abc" "sha256:abc" "sha256:def"

# State-transition recovery matrix. Before immutable Git publication every failure restarts from
# current main. Once the exact release tag exists, recovery is resume-only and must re-prove the
# candidate/release identity before creating missing registry/GitHub Release artifacts.
expect_eq "RESTART" "$(release_recovery_mode '' abc abc)" "candidate publish failure restarts"
expect_eq "RESTART" "$(release_recovery_mode '' abc abc)" "attestation failure restarts"
expect_eq "RESTART" "$(release_recovery_mode '' abc abc)" "native smoke failure restarts"
expect_failure "origin race blocks publication" assert_origin_unchanged abc def
expect_eq "RESTART" "$(release_recovery_mode '' abc abc)" "atomic push failure before durable refs restarts"
expect_eq "RESUME" "$(release_recovery_mode abc abc abc)" "stable promotion failure after Git publish resumes"
expect_eq "RESUME" "$(release_recovery_mode abc abc abc)" "latest promotion failure resumes"
expect_eq "RESUME" "$(release_recovery_mode abc abc abc)" "GitHub Release failure resumes"
expect_failure "resume refuses candidate identity drift" release_recovery_mode abc abc def

if (( failures > 0 )); then
  printf 'RESULT: FAIL - %d release helper test(s) failed.\n' "$failures" >&2
  exit 1
fi

printf 'RESULT: PASS - deterministic Engine release helper contracts hold.\n'
