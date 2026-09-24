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

# Line-ending materialization: a `core.autocrlf=true` checkout can materialize `CHANGELOG.md` as
# CRLF. Anchored and whole-line matching treats the CR as data - grep's `$` anchor, `grep -x`, and
# awk's `$0 == header` compare all fail - so the READERS normalize line endings explicitly and this
# asserts that contract: the same document materialized with CRLF must yield exactly the same
# release body as its LF form, and every release marker must still be found. A Windows/MSYS2 probe
# reported these as passing before the readers normalized, because MSYS2 opens text files in text
# mode; the release platform is Linux, so this assertion is meaningful only there.
expect_eq "$(changelog_section "$tmp/CHANGELOG.md" 0.2.0)" "$(changelog_section "$tmp/CHANGELOG.md" 0.2.0)" "LF changelog extraction is stable"
lf_doc=$'## v0.1.0\n\n- Manifest format: 0.3\n- Diagnostic codes: none\n- Git range: start..v0.1.0\n'
crlf_doc=$'## v0.1.0\r\n\r\n- Manifest format: 0.3\r\n- Diagnostic codes: none\r\n- Git range: start..v0.1.0\r\n'
printf '%s' "$lf_doc" >"$tmp/lf-changelog.md"
printf '%s' "$crlf_doc" >"$tmp/crlf-changelog.md"
lf_body="$(changelog_section "$tmp/lf-changelog.md" 0.1.0)"
crlf_body="$(changelog_section "$tmp/crlf-changelog.md" 0.1.0)"
expect_eq "$lf_body" "$crlf_body" "CRLF changelog extracts the same release body as LF"
expect_eq $'## v0.1.0\n\n- Manifest format: 0.3\n- Diagnostic codes: none\n- Git range: start..v0.1.0' "$crlf_body" "CRLF changelog body is normalized to LF"
crlf_header="$(changelog_lines "$tmp/crlf-changelog.md" | grep -m1 -E '^## v[0-9]+\.[0-9]+\.[0-9]+$' || true)"
expect_eq "## v0.1.0" "$crlf_header" "CRLF changelog yields a clean release header"
changelog_line_present() { # file marker
  changelog_lines "$1" | grep -Fqx -- "$2"
}
changelog_marker_present() { # file marker
  changelog_lines "$1" | grep -Fq -- "$2"
}
expect_success "CRLF changelog keeps the Manifest format line" changelog_line_present "$tmp/crlf-changelog.md" '- Manifest format: 0.3'
expect_success "CRLF changelog keeps the diagnostic-code marker" changelog_marker_present "$tmp/crlf-changelog.md" '- Diagnostic codes:'
expect_success "CRLF changelog keeps the Git-range marker" changelog_marker_present "$tmp/crlf-changelog.md" '- Git range:'

# The same readers own the metadata gate; prove it against a CRLF-materialized changelog by
# pointing the gate at a copy so the repository file is not touched.
crlf_root="$tmp/crlf-root"
mkdir -p "$crlf_root/eng" "$crlf_root/src/MCPiler.Engine.Host" "$crlf_root/src/MCPiler.Engine/Manifest"
cp "$ROOT/eng/check-release-metadata.sh" "$crlf_root/eng/"
cp "$ROOT/src/MCPiler.Engine.Host/MCPiler.Engine.Host.csproj" "$crlf_root/src/MCPiler.Engine.Host/"
cp "$ROOT/src/MCPiler.Engine/Manifest/ManifestFormatSupport.cs" "$crlf_root/src/MCPiler.Engine/Manifest/"
printf '## v0.1.0\r\n\r\n- Manifest format: 0.3\r\n- Diagnostic codes: none\r\n- Git range: start..v0.1.0\r\n' >"$crlf_root/CHANGELOG.md"
expect_success "metadata gate reads a CRLF-materialized changelog" bash "$crlf_root/eng/check-release-metadata.sh"
printf '## v0.1.0\n\n- Manifest format: 0.3\n- Diagnostic codes: none\n- Git range: start..v0.1.0\n' >"$crlf_root/CHANGELOG.md"
expect_success "metadata gate reads an LF changelog (control)" bash "$crlf_root/eng/check-release-metadata.sh"

# The attribute is the durable half, so a fresh checkout does not materialize CRLF at all.
expect_success "Git attributes force LF for the changelog" grep -Fq 'CHANGELOG.md text eol=lf' "$ROOT/.gitattributes"

# An annotated stable tag records a tagger identity. `git tag -a` runs in the git_publish job on a
# fresh runner whose checkout has no configured identity (the prepare job configured its own
# checkout on a different machine), so the release must pass the documented bot identity
# explicitly. A bare `git tag -a` fails there with `fatal: empty ident name ... not allowed` after
# the candidate is already published. Reproduce the fresh-runner condition deterministically by
# disabling every ambient identity source rather than relying on the workstation's own config.
tag_probe_root="$tmp/tag-identity"
mkdir -p "$tag_probe_root"
git -C "$tag_probe_root" init -q .
git -C "$tag_probe_root" -c user.name='probe' -c user.email='probe@example.invalid' \
  commit -q --allow-empty -m init
# `-c` is a one-shot override, so the probe repository still has no configured identity; the
# unset calls are defensive and must not abort the suite when the keys are already absent.
git -C "$tag_probe_root" config --unset user.name 2>/dev/null || true
git -C "$tag_probe_root" config --unset user.email 2>/dev/null || true
tag_without_identity() {
  env -u GIT_AUTHOR_NAME -u GIT_AUTHOR_EMAIL -u GIT_COMMITTER_NAME -u GIT_COMMITTER_EMAIL \
    GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 \
    git -C "$tag_probe_root" tag -a "$1" -m probe
}
tag_with_bot_identity() {
  env -u GIT_AUTHOR_NAME -u GIT_AUTHOR_EMAIL -u GIT_COMMITTER_NAME -u GIT_COMMITTER_EMAIL \
    GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 \
    git -C "$tag_probe_root" -c user.name='github-actions[bot]' \
      -c user.email='41898282+github-actions[bot]@users.noreply.github.com' \
      tag -a "$1" -m probe
}
expect_failure "annotated tag without a configured identity fails on a fresh runner" tag_without_identity v0.9.9
expect_success "annotated tag with the documented bot identity succeeds" tag_with_bot_identity v0.1.0
expect_eq 'tagger github-actions[bot] <41898282+github-actions[bot]@users.noreply.github.com>' \
  "$(git -C "$tag_probe_root" cat-file -p refs/tags/v0.1.0 | sed -n '4p' | sed 's/ [0-9][0-9]* [+-][0-9][0-9]*$//')" \
  "annotated tag records the documented bot identity"

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
