#!/usr/bin/env bash
set -euo pipefail

subject=""
repository='bartbaszt/mcpiler-engine'

while (($#)); do
  case "$1" in
    --subject) subject="${2:-}"; shift 2 ;;
    --repository) repository="${2:-}"; shift 2 ;;
    *) echo "FAIL: unknown argument '$1'." >&2; exit 64 ;;
  esac
done

[[ "$subject" =~ ^ghcr\.io/[a-z0-9_.-]+/[a-z0-9_.-]+@sha256:[0-9a-f]{64}$ ]] || {
  echo 'FAIL: --subject must be an exact GHCR sha256 digest reference.' >&2
  exit 64
}

command -v cosign >/dev/null 2>&1 || { echo 'FAIL: cosign is required.' >&2; exit 1; }

identity="https://github.com/$repository/.github/workflows/release.yml@refs/heads/main"
issuer='https://token.actions.githubusercontent.com'

common=(
  --certificate-identity "$identity"
  --certificate-oidc-issuer "$issuer"
)

cosign verify "${common[@]}" "$subject" >/dev/null
cosign verify-attestation "${common[@]}" --type spdxjson "$subject" >/dev/null
cosign verify-attestation "${common[@]}" --type slsaprovenance "$subject" >/dev/null

echo "RESULT: PASS - keyless signature, SPDX SBOM and SLSA provenance verify for $subject."
