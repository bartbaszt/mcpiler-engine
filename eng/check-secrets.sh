#!/usr/bin/env bash
# Scan the Engine repository (never the private Platform superproject).
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

if ! command -v betterleaks >/dev/null 2>&1; then
  echo "BetterLeaks 1.9.0 is required: https://github.com/betterleaks/betterleaks/releases/tag/v1.9.0" >&2
  exit 2
fi

installed_version="$(betterleaks version)"
if [[ "$installed_version" != "1.9.0" ]]; then
  echo "Expected BetterLeaks 1.9.0, found ${installed_version}." >&2
  exit 2
fi

case "${1:-}" in
  --staged)
    exec betterleaks git . --pre-commit --staged --redact --no-banner --no-color --log-level error
    ;;
  --history)
    exec betterleaks git . --log-opts='--all' --redact --no-banner --no-color --log-level error
    ;;
  *)
    echo "Usage: bash eng/check-secrets.sh --staged|--history" >&2
    exit 2
    ;;
esac
