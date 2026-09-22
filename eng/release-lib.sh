#!/usr/bin/env bash

# Pure release-state helpers. This file performs no Git, registry, or filesystem mutation so
# deterministic tests can exercise failure/recovery decisions without external services.

stable_version() {
  [[ "${1:-}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]
}

# Changelog readers must be independent of the checkout host's line endings. A
# `core.autocrlf=true` checkout materializes `CHANGELOG.md` as CRLF, and anchored/whole-line
# matching treats that CR as data: grep's `$` anchor and `-x` compare, and awk's `$0 == header`
# compare all fail, which yields an empty release body and a missed release header. Normalize the
# line endings explicitly instead of depending on a particular tool's CR behavior.
changelog_lines() { # changelog-file -> stdout with LF line endings
  local changelog="${1:-}"
  [[ -f "$changelog" ]] || return 1
  tr -d '\r' <"$changelog"
}

next_version() {
  local current="${1:-}" bump="${2:-}" major minor patch
  stable_version "$current" || return 1
  IFS=. read -r major minor patch <<<"$current"
  case "${bump,,}" in
    patch) printf '%s.%s.%s\n' "$major" "$minor" "$((patch + 1))" ;;
    minor) printf '%s.%s.0\n' "$major" "$((minor + 1))" ;;
    major) printf '%s.0.0\n' "$((major + 1))" ;;
    *) return 1 ;;
  esac
}

changelog_section() {
  local changelog="${1:-}" version="${2:-}"
  [[ -f "$changelog" ]] || return 1
  stable_version "$version" || return 1
  changelog_lines "$changelog" | awk -v header="## v$version" '
    /^## v[0-9]+\.[0-9]+\.[0-9]+/ {
      if (found) exit
      if ($0 == header) found=1
    }
    found { print }
  '
}

assert_release_tag_absent() {
  [[ -z "${1:-}" ]]
}

assert_origin_unchanged() {
  [[ -n "${1:-}" && "${1:-}" == "${2:-}" ]]
}

assert_resume_eligible() {
  local remote_tag_commit="${1:-}" release_commit="${2:-}" candidate_commit="${3:-}"
  [[ -n "$remote_tag_commit" && "$remote_tag_commit" == "$release_commit" && "$candidate_commit" == "$release_commit" ]]
}

release_recovery_mode() {
  local remote_tag_commit="${1:-}" release_commit="${2:-}" candidate_commit="${3:-}"
  if [[ -z "$remote_tag_commit" ]]; then
    printf 'RESTART\n'
    return 0
  fi
  assert_resume_eligible "$remote_tag_commit" "$release_commit" "$candidate_commit" || return 1
  printf 'RESUME\n'
}

visibility_checkpoint() {
  local is_public="${1:-}" compliance_verified="${2:-}"
  [[ "$compliance_verified" == true ]] || return 1
  if [[ "$is_public" == true ]]; then
    printf 'READY\n'
  else
    printf 'PACKAGE_VISIBILITY_REQUIRED\n'
  fi
}

assert_promoted_identity() {
  local candidate="${1:-}" stable="${2:-}" latest="${3:-}"
  [[ -n "$candidate" && "$candidate" == "$stable" && "$candidate" == "$latest" ]]
}
