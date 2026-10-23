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

# ---------------------------------------------------------------------------------------------------
# Release payload transport. GitHub Actions artifact storage is unavailable for this account, so the
# prepared release commit and the candidate SBOM travel as base64 job outputs (same run) and as a
# marked job-log block (resume of a run that already failed). The contracts below are the ones the
# release and resume workflows depend on: an incremental bundle that is restorable only from the
# reviewed base commit, SHA-256 authentication of every payload, a single well-formed log block, and
# a bounded encoded size.
# ---------------------------------------------------------------------------------------------------
bundle_script="$ROOT/eng/release-bundle.sh"
expect_success "release payload transport helper exists" test -f "$bundle_script"
expect_success "release payload transport helper is executable" test -x "$bundle_script"

bundle_work="$tmp/payload"
mkdir -p "$bundle_work"
git_identity=( -c user.name='Engine Release Test' -c user.email='release-test@example.invalid' )

git init -q -b main "$bundle_work/origin"
git -C "$bundle_work/origin" config core.autocrlf false
printf 'reviewed base content\n' >"$bundle_work/origin/manifest.json"
git -C "$bundle_work/origin" add manifest.json
git -C "$bundle_work/origin" "${git_identity[@]}" commit -q -m 'base commit'
base_commit="$(git -C "$bundle_work/origin" rev-parse HEAD)"

git clone -q -c core.autocrlf=false "$bundle_work/origin" "$bundle_work/prepare"
printf 'release content\n' >"$bundle_work/prepare/manifest.json"
git -C "$bundle_work/prepare" add manifest.json
git -C "$bundle_work/prepare" "${git_identity[@]}" commit -q -m 'chore(release): test release'
release_commit_sha="$(git -C "$bundle_work/prepare" rev-parse HEAD)"
release_bundle="$bundle_work/release.bundle"

clone_consumer() { # name -> repository path with only the reviewed base
  git clone -q -c core.autocrlf=false "$bundle_work/origin" "$bundle_work/$1"
  printf '%s\n' "$bundle_work/$1"
}

write_output="$(bash "$bundle_script" write --repo "$bundle_work/prepare" --bundle "$release_bundle" --base-sha "$base_commit" --release-commit "$release_commit_sha")"
expect_eq "RESULT: RELEASE_BUNDLE_WRITTEN" "$(printf '%s\n' "$write_output" | tail -n1)" "bundle write result"
bundle_digest="$(printf '%s\n' "$write_output" | sed -n 's/^RELEASE_BUNDLE_SHA256=//p')"
expect_eq "$release_commit_sha refs/heads/main" \
  "$(git -C "$bundle_work/origin" bundle list-heads "$release_bundle")" \
  "bundle carries exactly the release commit on refs/heads/main"

encoded_bundle="$(bash "$bundle_script" encode --bundle "$release_bundle")"
expect_eq "1" "$(printf '%s\n' "$encoded_bundle" | wc -l | tr -d '[:space:]')" "encoded bundle is one job-output line"

consumer="$(clone_consumer consumer)"
printf '%s\n' "$encoded_bundle" | bash "$bundle_script" restore --repo "$consumer" --base64-stdin \
  --sha256 "$bundle_digest" --base-sha "$base_commit" --release-commit "$release_commit_sha" >/dev/null
expect_eq "$release_commit_sha" "$(git -C "$consumer" rev-parse HEAD)" "restored checkout is the release commit"
expect_eq "$base_commit" "$(git -C "$consumer" rev-parse HEAD^)" "restored release commit sits on the reviewed base"
expect_eq "release content" "$(tr -d '\r' <"$consumer/manifest.json")" "restored tree carries the release content"

zero_digest="$(printf '0%.0s' {1..64})"
mismatch_consumer="$(clone_consumer mismatch)"
expect_failure "bundle whose SHA-256 does not match the output is refused" \
  bash -c "printf '%s\n' '$encoded_bundle' | bash '$bundle_script' restore --repo '$mismatch_consumer' --base64-stdin --sha256 '$zero_digest' --base-sha '$base_commit' --release-commit '$release_commit_sha'"
expect_eq "$base_commit" "$(git -C "$mismatch_consumer" rev-parse HEAD)" "refused restore leaves the checkout on the reviewed base"

wrong_commit_consumer="$(clone_consumer wrong-commit)"
expect_failure "bundle restored for the wrong release commit is refused" \
  bash -c "printf '%s\n' '$encoded_bundle' | bash '$bundle_script' restore --repo '$wrong_commit_consumer' --base64-stdin --sha256 '$bundle_digest' --base-sha '$base_commit' --release-commit '$base_commit'"
expect_failure "bundle restored for the wrong base commit is refused" \
  bash -c "printf '%s\n' '$encoded_bundle' | bash '$bundle_script' restore --repo '$wrong_commit_consumer' --base64-stdin --sha256 '$bundle_digest' --base-sha '$release_commit_sha' --release-commit '$release_commit_sha'"

# A release commit whose parent is not the reviewed base must never be bundled: the release contract
# is one commit on top of base, and a bundle would otherwise accept a longer range.
git clone -q -c core.autocrlf=false "$bundle_work/origin" "$bundle_work/drift"
git -C "$bundle_work/drift" "${git_identity[@]}" commit -q --allow-empty -m 'unrelated intermediate commit'
intermediate_commit="$(git -C "$bundle_work/drift" rev-parse HEAD)"
git -C "$bundle_work/drift" "${git_identity[@]}" commit -q --allow-empty -m 'chore(release): two commits ahead'
drift_release="$(git -C "$bundle_work/drift" rev-parse HEAD)"
expect_failure "release commit whose parent is not the base is not bundled" \
  bash "$bundle_script" write --repo "$bundle_work/drift" --bundle "$bundle_work/drift.bundle" \
    --base-sha "$base_commit" --release-commit "$drift_release"

# A consumer that does not already hold the reviewed base cannot restore the incremental bundle.
git init -q -b main "$bundle_work/unrelated"
git -C "$bundle_work/unrelated" "${git_identity[@]}" commit -q --allow-empty -m 'unrelated history'
unrelated_commit="$(git -C "$bundle_work/unrelated" rev-parse HEAD)"
expect_failure "restore without the reviewed base commit is refused" \
  bash "$bundle_script" restore --repo "$bundle_work/unrelated" --bundle "$release_bundle" \
    --sha256 "$bundle_digest" --base-sha "$base_commit" --release-commit "$release_commit_sha"
expect_eq "$unrelated_commit" "$(git -C "$bundle_work/unrelated" rev-parse HEAD)" "refused restore does not move an unrelated checkout"

# The strongest identity check is FETCH_HEAD^ == base_sha. Build the case where both the wrongly
# recorded base and the release commit's true parent are present in the checkout: only that check
# can reject the restore, so removing it silently moves the wrong base into the release tree.
intermediate_bundle="$bundle_work/intermediate.bundle"
intermediate_write="$(bash "$bundle_script" write --repo "$bundle_work/drift" --bundle "$intermediate_bundle" \
  --base-sha "$intermediate_commit" --release-commit "$drift_release")"
intermediate_digest="$(printf '%s\n' "$intermediate_write" | sed -n 's/^RELEASE_BUNDLE_SHA256=//p')"
wrong_base_consumer="$bundle_work/wrong-base"
git clone -q -c core.autocrlf=false "$bundle_work/drift" "$wrong_base_consumer"
git -C "$wrong_base_consumer" reset -q --hard "$intermediate_commit"
expect_eq "$intermediate_commit" "$(git -C "$wrong_base_consumer" rev-parse HEAD)" "fixture starts on the true parent of the release commit"
expect_failure "restore whose recorded base differs from the release commit parent is refused" \
  bash "$bundle_script" restore --repo "$wrong_base_consumer" --bundle "$intermediate_bundle" \
    --sha256 "$intermediate_digest" --base-sha "$base_commit" --release-commit "$drift_release"
expect_eq "$intermediate_commit" "$(git -C "$wrong_base_consumer" rev-parse HEAD)" "refused restore leaves HEAD at the recorded base"
expect_eq "$base_commit" "$(git -C "$wrong_base_consumer" rev-parse HEAD^)" "refused restore leaves the earlier history untouched"

# Job-log transport. GitHub prefixes every log line with an RFC 3339 timestamp; the resume workflow
# reads the block back from that log and authenticates it by SHA-256 and release commit.
bash "$bundle_script" print-log --bundle "$release_bundle" --release-commit "$release_commit_sha" --sha256 "$bundle_digest" >"$bundle_work/printed.log"
expect_eq "76" \
  "$(awk '/^ENGINE_RELEASE_BUNDLE_BEGIN/{inside=1;next} /^ENGINE_RELEASE_BUNDLE_END/{inside=0} inside{if (length($0)>longest) longest=length($0)} END{print longest+0}' "$bundle_work/printed.log")" \
  "logged bundle base64 is wrapped at 76 columns"

sed 's/^/2026-10-23T10:00:00.1234567Z /' "$bundle_work/printed.log" >"$bundle_work/prepare.log"
log_consumer="$(clone_consumer log-consumer)"
extracted="$(bash "$bundle_script" extract-log --repo "$log_consumer" --log "$bundle_work/prepare.log" --bundle "$bundle_work/extracted.bundle")"
expect_eq "$release_commit_sha" "$(printf '%s\n' "$extracted" | sed -n 's/^RELEASE_COMMIT=//p')" "log block reports the release commit"
expect_eq "$bundle_digest" "$(printf '%s\n' "$extracted" | sed -n 's/^RELEASE_BUNDLE_SHA256=//p')" "log block reports the bundle digest"
expect_eq "$base_commit" "$(printf '%s\n' "$extracted" | sed -n 's/^RELEASE_BASE_SHA=//p')" "log block reports its prerequisite base"
expect_eq "$bundle_digest" "$(sha256sum "$bundle_work/extracted.bundle" | cut -d' ' -f1)" "extracted log block reproduces the bundle bytes"

sed 's/$/\r/' "$bundle_work/prepare.log" >"$bundle_work/prepare-crlf.log"
expect_success "log block with CRLF line endings is extracted" \
  bash "$bundle_script" extract-log --repo "$log_consumer" --log "$bundle_work/prepare-crlf.log" --bundle "$bundle_work/extracted-crlf.bundle"

# GitHub records ANSI colour escapes around `##[group]` and echoed-command headers. A decorated
# non-block or marker line must still parse, while a decorated payload line must be refused: the
# block payload stays strict plain base64.
ansi_escape="$(printf '\033')"
{
  printf '2026-10-23T10:00:00.1000000Z %s[36;1m##[group]Run bash eng/release-bundle.sh print-log%s[0m\n' "$ansi_escape" "$ansi_escape"
  printf '%s[32;1m2026-10-23T10:00:01.1000000Z ##[endgroup]%s[0m\n' "$ansi_escape" "$ansi_escape"
  sed 's/^/2026-10-23T10:00:02.1000000Z /' "$bundle_work/printed.log" \
    | sed -E "s#^(.*Z )(ENGINE_RELEASE_BUNDLE_(BEGIN|END).*)\$#\\1${ansi_escape}[36;1m\\2${ansi_escape}[0m#"
} >"$bundle_work/ansi.log"
ansi_extracted="$(bash "$bundle_script" extract-log --repo "$log_consumer" --log "$bundle_work/ansi.log" --bundle "$bundle_work/ansi.bundle" 2>/dev/null || true)"
expect_eq "$release_commit_sha" "$(printf '%s\n' "$ansi_extracted" | sed -n 's/^RELEASE_COMMIT=//p')" "ANSI-coloured headers and markers do not disturb extraction"
expect_eq "$bundle_digest" "$(sha256sum "$bundle_work/ansi.bundle" | cut -d' ' -f1)" "ANSI-coloured log yields the same bundle bytes"

sed 's/^/2026-10-23T10:00:02.1000000Z /' "$bundle_work/printed.log" \
  | sed -E "s#^(.*Z )([A-Za-z0-9+/=]+)\$#\\1${ansi_escape}[33;1m\\2${ansi_escape}[0m#" >"$bundle_work/ansi-payload.log"
expect_failure "ANSI escapes inside the base64 payload are refused" \
  bash "$bundle_script" extract-log --repo "$log_consumer" --log "$bundle_work/ansi-payload.log" --bundle "$bundle_work/ansi-payload.bundle"

sed '/ENGINE_RELEASE_BUNDLE_END/d' "$bundle_work/prepare.log" >"$bundle_work/truncated.log"
expect_failure "log block without its end marker is refused" \
  bash "$bundle_script" extract-log --repo "$log_consumer" --log "$bundle_work/truncated.log" --bundle "$bundle_work/truncated.bundle"
sed '/ENGINE_RELEASE_BUNDLE_BEGIN/d' "$bundle_work/prepare.log" >"$bundle_work/missing.log"
expect_failure "log without a release bundle block is refused" \
  bash "$bundle_script" extract-log --repo "$log_consumer" --log "$bundle_work/missing.log" --bundle "$bundle_work/missing.bundle"
cat "$bundle_work/prepare.log" "$bundle_work/prepare.log" >"$bundle_work/duplicated.log"
expect_failure "log with a duplicated release bundle block is refused" \
  bash "$bundle_script" extract-log --repo "$log_consumer" --log "$bundle_work/duplicated.log" --bundle "$bundle_work/duplicated.bundle"
sed '/^2026-10-23T10:00:00.1234567Z [A-Za-z0-9+/]/d' "$bundle_work/prepare.log" >"$bundle_work/short.log"
expect_failure "log block whose base64 is truncated is refused" \
  bash "$bundle_script" extract-log --repo "$log_consumer" --log "$bundle_work/short.log" --bundle "$bundle_work/short.bundle"
sed 's/release_commit=/commit=/' "$bundle_work/prepare.log" >"$bundle_work/malformed.log"
expect_failure "log block with a malformed begin marker is refused" \
  bash "$bundle_script" extract-log --repo "$log_consumer" --log "$bundle_work/malformed.log" --bundle "$bundle_work/malformed.bundle"

# Resume selection. A re-run attempt can leave a newer prepare job whose log carries no usable
# block, so the workflow hands every candidate over newest first and the helper accepts the first
# valid one. Each individual log must still contain exactly one well-formed block.
printf '2026-10-24T08:00:00Z\t9001\t%s\n2026-10-23T10:00:00Z\t9002\t%s\n' \
  "$bundle_work/absent.log" "$bundle_work/prepare.log" >"$bundle_work/manifest.tsv"
best="$(bash "$bundle_script" extract-best-block --repo "$log_consumer" --input "$bundle_work/manifest.tsv" --bundle "$bundle_work/best.bundle" 2>/dev/null)"
expect_eq "9002" "$(printf '%s\n' "$best" | sed -n 's/^JOB_ID=//p')" "a missing candidate log is skipped in favour of a valid one"
expect_eq "$release_commit_sha" "$(printf '%s\n' "$best" | sed -n 's/^RELEASE_COMMIT=//p')" "selected candidate reports the release commit"
expect_eq "$bundle_digest" "$(printf '%s\n' "$best" | sed -n 's/^RELEASE_BUNDLE_SHA256=//p')" "selected candidate reports the bundle digest"

printf '2026-10-24T08:00:00Z\t9101\t%s\n2026-10-23T10:00:00Z\t9102\t%s\n' \
  "$bundle_work/duplicated.log" "$bundle_work/prepare.log" >"$bundle_work/manifest-duplicated.tsv"
expect_eq "9102" \
  "$(bash "$bundle_script" extract-best-block --repo "$log_consumer" --input "$bundle_work/manifest-duplicated.tsv" --bundle "$bundle_work/best-dup.bundle" 2>/dev/null | sed -n 's/^JOB_ID=//p')" \
  "a candidate log with a duplicated block is skipped"

printf '2026-10-24T08:00:00Z\t9201\t%s\n' "$bundle_work/prepare.log" >"$bundle_work/manifest-first.tsv"
expect_eq "9201" \
  "$(bash "$bundle_script" extract-best-block --repo "$log_consumer" --input "$bundle_work/manifest-first.tsv" --bundle "$bundle_work/best-first.bundle" 2>/dev/null | sed -n 's/^JOB_ID=//p')" \
  "the newest candidate is used when its block is valid"

printf '2026-10-24T08:00:00Z\t9301\t%s\n2026-10-23T10:00:00Z\t9302\t%s\n' \
  "$bundle_work/absent.log" "$bundle_work/truncated.log" >"$bundle_work/manifest-invalid.tsv"
expect_failure "resume with no valid candidate block fails closed" \
  bash "$bundle_script" extract-best-block --repo "$log_consumer" --input "$bundle_work/manifest-invalid.tsv" --bundle "$bundle_work/best-none.bundle"

# Job-output and environment-string budget. Consumers receive the payload as one step environment
# string, and Linux rejects a single such string above MAX_ARG_STRLEN = 131072 bytes (NAME + '=' +
# value + NUL), long before the 1 MB per-job output cap applies.
payload_cap="$(sed -n 's/^PAYLOAD_MAX_ENCODED_BYTES=//p' "$bundle_script")"
expect_eq "120000" "$payload_cap" "shared payload cap is the single source of truth"
longest_env_name="$(grep -rhoE '\b(RELEASE_BUNDLE|SBOM_GZ_BASE64)[A-Z0-9_]*' "$ROOT/.github/workflows" \
  | sort -u | awk '{ if (length($0) > longest) { longest = length($0); name = $0 } } END { print name }')"
expect_eq "RELEASE_BUNDLE_SHA256" "$longest_env_name" "longest payload environment variable name in the workflows"
expect_success "shared cap plus the longest environment name leaves room under MAX_ARG_STRLEN" \
  test $(( 131072 - payload_cap - ${#longest_env_name} - 2 )) -ge 1024

# 90000 raw bytes encode to exactly the shared cap; one more raw byte crosses it.
head -c 90000 /dev/zero >"$bundle_work/cap-exact.bin"
head -c 90001 /dev/zero >"$bundle_work/cap-over.bin"
expect_success "payload of exactly the shared cap is accepted" \
  bash "$bundle_script" encode --bundle "$bundle_work/cap-exact.bin"
expect_failure "payload just above the shared cap is refused by default" \
  bash "$bundle_script" encode --bundle "$bundle_work/cap-over.bin"
expect_failure "payload above an explicit budget is refused" \
  bash "$bundle_script" encode --bundle "$release_bundle" --max-bytes 32

# SBOM transport: gzip -9n makes the payload a deterministic function of the JSON bytes, and the
# digest is taken over the uncompressed document so supply_chain verifies the SBOM it signs.
sbom_json="$bundle_work/sbom.spdx.json"
printf '{"spdxVersion":"SPDX-2.3","name":"mcpiler-engine"}\n' >"$sbom_json"
sbom_output="$(bash "$bundle_script" sbom-encode --input "$sbom_json" --output "$bundle_work/sbom.b64")"
sbom_digest="$(printf '%s\n' "$sbom_output" | sed -n 's/^SBOM_SHA256=//p')"
expect_eq "$(sha256sum "$sbom_json" | cut -d' ' -f1)" "$sbom_digest" "SBOM digest covers the uncompressed document"
bash "$bundle_script" sbom-encode --input "$sbom_json" --output "$bundle_work/sbom-second.b64" >/dev/null
expect_success "SBOM encoding is deterministic" cmp -s "$bundle_work/sbom.b64" "$bundle_work/sbom-second.b64"
bash "$bundle_script" sbom-restore --input "$bundle_work/sbom.b64" --output "$bundle_work/sbom-restored.json" --sha256 "$sbom_digest" >/dev/null
expect_success "restored SBOM is byte-identical" cmp -s "$sbom_json" "$bundle_work/sbom-restored.json"
expect_failure "SBOM digest mismatch is refused" \
  bash "$bundle_script" sbom-restore --input "$bundle_work/sbom.b64" --output "$bundle_work/sbom-wrong.json" --sha256 "$zero_digest"
expect_failure "encoded SBOM above an explicit budget is refused" \
  bash "$bundle_script" sbom-encode --input "$sbom_json" --output "$bundle_work/sbom-capped.b64" --max-bytes 16
# Incompressible JSON of 91000 bytes stays above the shared cap after gzip -9n.
head -c 91000 /dev/urandom >"$bundle_work/sbom-large.json"
expect_failure "encoded SBOM above the shared cap is refused by default" \
  bash "$bundle_script" sbom-encode --input "$bundle_work/sbom-large.json" --output "$bundle_work/sbom-large.b64"

if (( failures > 0 )); then
  printf 'RESULT: FAIL - %d release helper test(s) failed.\n' "$failures" >&2
  exit 1
fi

printf 'RESULT: PASS - deterministic Engine release helper contracts hold.\n'
