#!/usr/bin/env bash
# Repeatable provider smoke harness for MCPiler Engine's external-issuer boundary.
#
# It provisions a real authorization server (Keycloak, or BYO tokens for authentik), starts a real
# Engine listener with one protected surface, and drives served requests with real provider-issued
# tokens: positive admission, wrong audience, missing scope, tampered signature, foreign issuer and
# the unauthenticated challenge, plus the introspection outage/availability path. Evidence lands
# under artifacts/provider-smoke/ as a transcript and a JSON report.
#
# It deliberately asserts authorization outcomes at the MCP address (401 = not vouched for by the
# issuer, 404 = the uniform refusal for a valid token that names another resource or lacks a scope,
# anything else = admitted past the bearer boundary) instead of a full MCP tool conversation.
#
# Usage: eng/provider-smoke/run-provider-smoke.sh --provider keycloak|byo
# See README.md in this directory for the environment contract and the remote-VM workflow.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"

PROVIDER="keycloak"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --provider) PROVIDER="${2:?}"; shift 2 ;;
    --help|-h) sed -n '2,18p' "$0"; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
done

if [[ "$PROVIDER" != "keycloak" && "$PROVIDER" != "byo" ]]; then
  echo "Unsupported provider '$PROVIDER': use keycloak or byo." >&2
  exit 2
fi

DOTNET="${DOTNET:-dotnet}"
KEYCLOAK_IMAGE="${KEYCLOAK_IMAGE:-quay.io/keycloak/keycloak:26.4.0}"
KEYCLOAK_PORT="${KEYCLOAK_PORT:-18080}"
ENGINE_PORT="${ENGINE_PORT:-19090}"
KEYCLOAK_REALM="${KEYCLOAK_REALM:-mcpiler-smoke}"
PUBLIC_HOST="${SMOKE_PUBLIC_HOST:-smoke.engine.test}"
AUDIENCE="${SMOKE_AUDIENCE:-https://$PUBLIC_HOST/api/interop}"
OTHER_AUDIENCE="${SMOKE_OTHER_AUDIENCE:-https://$PUBLIC_HOST/api/other}"
SMOKE_USER="${SMOKE_USER:-smoke}"
OIDC_FALLBACK="${SMOKE_OIDC_FALLBACK:-}"
VALIDATION="${SMOKE_VALIDATION:-jwks}"

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="$ROOT/artifacts/provider-smoke/$STAMP"
RUN="$OUT/run"
mkdir -p "$RUN"
TRANSCRIPT="$OUT/transcript.log"
REPORT="$OUT/provider-smoke-report.json"
ROWS="$RUN/cases.tsv"
: >"$ROWS"

MCP_PATH="/api/interop"
MCP_URL="http://127.0.0.1:$ENGINE_PORT$MCP_PATH"

# The wire shapes the repository's own McpHttpSession uses: initialize negotiates 2025-06-18,
# the session id comes back as Mcp-Session-Id, and later requests carry it.
MCP_INITIALIZE='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"provider-smoke","version":"1.0"}}}'
MCP_INITIALIZED_NOTIFICATION='{"jsonrpc":"2.0","method":"notifications/initialized"}'
MCP_TOOLS_LIST='{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'

ENGINE_PID=""
KEYCLOAK_STARTED=""

exec > >(tee -a "$TRANSCRIPT") 2>&1

log() { printf '%s\n' "$*"; }

cleanup() {
  stop_engine
  if [[ "$KEYCLOAK_STARTED" == "1" ]]; then
    # Task-scoped cleanup only: remove the smoke project's own containers and volumes.
    docker compose -p mcpiler-provider-smoke -f "$HERE/compose/keycloak.compose.yaml" down -v >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

stop_engine() {
  if [[ -n "$ENGINE_PID" ]]; then
    kill "$ENGINE_PID" >/dev/null 2>&1 || true
    wait "$ENGINE_PID" 2>/dev/null || true
    ENGINE_PID=""
  fi
}

record() { # name expected observed result
  printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" >>"$ROWS"
  log "  [$4] $1 (expected $2, observed $3)"
}

# mcp_post TOKEN BODY HEADERS_FILE BODY_FILE [SESSION] -> HTTP status
#
# The route is the protected MCP surface itself: the bearer boundary runs before the protocol
# handler, so an unauthenticated or rejected token is observable here and an admitted one gets a
# real JSON-RPC answer.
mcp_post() {
  local token="$1" body="$2" headers="$3" out="$4" session="${5:-}"
  local -a args=(-s -D "$headers" -o "$out" -w '%{http_code}' --max-time 15
    -H 'Content-Type: application/json'
    -H 'Accept: application/json, text/event-stream'
    --data "$body")
  if [[ -n "$token" ]]; then
    args+=(-H "Authorization: Bearer $token")
  fi
  if [[ -n "$session" ]]; then
    args+=(-H "Mcp-Session-Id: $session")
  fi

  local status
  status="$(curl "${args[@]}" "$MCP_URL" 2>/dev/null)" || status="${status:-000}"
  printf '%s' "${status:-000}"
}

# Strips event-stream framing the way the repository's wire client does, so a body may be either
# a JSON message or SSE-framed data lines.
mcp_payload() {
  local out="$1"
  if grep -q 'data:' "$out"; then
    sed -n 's/^data:[[:space:]]*//p' "$out" | tr -d '\r' | tr -d '\n'
  else
    tr -d '\n' <"$out"
  fi
}

# The first offline guard: the protected route answers an unauthenticated request with the 401
# challenge that names its protected-resource metadata, before any bearer is evaluated.
expect_challenge() {
  local name="$1" headers="$RUN/challenge.headers" out="$RUN/challenge.body" status
  status="$(mcp_post "" "$MCP_INITIALIZE" "$headers" "$out")"
  if [[ "$status" == "401" ]] && grep -qi '^www-authenticate:.*resource_metadata=' "$headers"; then
    record "$name" "401 challenge with resource_metadata" "$status" PASS
  else
    record "$name" "401 challenge with resource_metadata" "$status" FAIL
    FAILURES=$((FAILURES + 1))
  fi
}

# The positive case is a real MCP session, not a status-code heuristic: initialize must answer
# 200 with a JSON-RPC result and a session id, and tools/list on that session must name the
# protected surface's tool.
expect_mcp_session() {
  local name="$1" token="$2"
  local headers="$RUN/session.headers" out="$RUN/session.body" status payload session
  local list_headers="$RUN/tools.headers" list_out="$RUN/tools.body" list_status list_payload

  status="$(mcp_post "$token" "$MCP_INITIALIZE" "$headers" "$out")"
  payload="$(mcp_payload "$out")"
  session="$(sed -n 's/^[Mm]cp-[Ss]ession-[Ii]d:[[:space:]]*//p' "$headers" | tr -d '\r' | head -n 1)"

  if [[ "$status" != "200" ]] || printf '%s' "$payload" | grep -q '"error"' \
    || ! printf '%s' "$payload" | grep -q '"result"' || [[ -z "$session" ]]; then
    record "$name" "200 initialize result with a session and tools/list read-status" "$status" FAIL
    FAILURES=$((FAILURES + 1))
    log "    initialize body: $(head -c 300 "$out")"
    return
  fi

  mcp_post "$token" "$MCP_INITIALIZED_NOTIFICATION" "$RUN/notify.headers" "$RUN/notify.body" "$session" >/dev/null
  list_status="$(mcp_post "$token" "$MCP_TOOLS_LIST" "$list_headers" "$list_out" "$session")"
  list_payload="$(mcp_payload "$list_out")"

  if [[ "$list_status" == "200" ]] && printf '%s' "$list_payload" | grep -q 'read-status'; then
    record "$name" "200 initialize result with a session and tools/list read-status" "$status/$list_status" PASS
  else
    record "$name" "200 initialize result with a session and tools/list read-status" "$status/$list_status" FAIL
    FAILURES=$((FAILURES + 1))
    log "    tools/list body: $(head -c 300 "$list_out")"
  fi
}

# A refused token must fail on the same exact route and request shape as the positive case.
expect_mcp_refusal() {
  local name="$1" token="$2" expected="$3" status
  status="$(mcp_post "$token" "$MCP_INITIALIZE" "$RUN/$name.headers" "$RUN/$name.body")"
  if [[ "$status" == "$expected" ]]; then
    record "$name" "$expected" "$status" PASS
  else
    record "$name" "$expected" "$status" FAIL
    FAILURES=$((FAILURES + 1))
  fi
}

FAILURES=0

require() { # name value
  if [[ -z "${2:-}" ]]; then
    echo "Missing required setting: $1" >&2
    exit 2
  fi
}

mint_keycloak_token() { # client_id secret scope
  local client_id="$1" secret="$2" scope="$3" response
  local -a form=(--data-urlencode "grant_type=password" --data-urlencode "client_id=$client_id" \
    --data-urlencode "username=$SMOKE_USER" --data-urlencode "password=$SMOKE_PASSWORD" \
    --data-urlencode "scope=$scope")
  if [[ -n "$secret" ]]; then
    form+=(--data-urlencode "client_secret=$secret")
  fi
  response="$(curl -s --max-time 20 "${form[@]}" \
    "http://127.0.0.1:$KEYCLOAK_PORT/realms/$KEYCLOAK_REALM/protocol/openid-connect/token")"
  local token
  token="$(printf '%s' "$response" | sed -n 's/.*"access_token"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"
  if [[ -z "$token" ]]; then
    echo "Token request for '$client_id' returned no access_token. Response: $response" >&2
    exit 1
  fi
  printf '%s' "$token"
}

start_engine() { # mode extra...
  local mode="$1"; shift
  local log_file="$RUN/engine-$mode.log"
  mkdir -p "$RUN/files-$mode"
  local -a args=(
    serve
    "--mount=/api=$RUN/manifest"
    "--file-store-root=$RUN/files-$mode"
    "--issuer=$ISSUER"
    "--token-validation=$mode"
    "--allowed-host=$PUBLIC_HOST"
    "--external-resource=$MCP_PATH=$AUDIENCE"
    "--listen=http://127.0.0.1:$ENGINE_PORT"
    "--oauth-operator-secret-file=$OPERATOR_SECRET_FILE"
  )
  if [[ "$OIDC_FALLBACK" == "1" ]]; then
    args+=("--oidc-discovery-fallback=true")
  fi
  if [[ -n "${SMOKE_JWKS_URI:-}" ]]; then
    args+=("--jwks-uri=$SMOKE_JWKS_URI")
  fi
  if [[ -n "${SMOKE_INTROSPECTION_ENDPOINT:-}" ]]; then
    args+=("--introspection-endpoint=$SMOKE_INTROSPECTION_ENDPOINT")
  fi
  if [[ "$mode" == "introspection" ]]; then
    if [[ -n "${INTROSPECTION_CLIENT_ID:-}" ]]; then
      args+=("--introspection-client-id=$INTROSPECTION_CLIENT_ID")
    fi
    if [[ -n "${INTROSPECTION_CLIENT_SECRET_FILE:-}" ]]; then
      args+=("--introspection-client-secret-file=$INTROSPECTION_CLIENT_SECRET_FILE")
    fi
  fi

  "$DOTNET" "$RUN/publish/mcpiler-engine.dll" "${args[@]}" "$@" >"$log_file" 2>&1 &
  ENGINE_PID=$!

  local attempt code
  for attempt in $(seq 1 60); do
    if ! kill -0 "$ENGINE_PID" >/dev/null 2>&1; then
      echo "Engine ($mode) exited during startup. Log tail:" >&2
      tail -n 20 "$log_file" >&2
      exit 1
    fi
    code="$(mcp_post "" "$MCP_INITIALIZE" "$RUN/readiness.headers" "$RUN/readiness.body")"
    if [[ "$code" == "401" ]]; then
      log "  Engine ($mode) is listening on http://127.0.0.1:$ENGINE_PORT; the protected route answers the 401 challenge"
      return 0
    fi
    sleep 1
  done

  echo "Engine ($mode) did not become ready. Log tail:" >&2
  tail -n 20 "$log_file" >&2
  exit 1
}

operator_status() {
  curl -s --max-time 10 \
    -H "Authorization: Bearer $(cat "$OPERATOR_SECRET_FILE")" \
    -H "X-MCPiler-Contract-Generation: 1" \
    "http://127.0.0.1:$ENGINE_PORT/.engine/oauth/status"
}

expect_observation() { # name category
  local name="$1" category="$2" body
  body="$(operator_status)"
  if printf '%s' "$body" | grep -q "\"$category\""; then
    record "$name" "observation $category" "present" PASS
  else
    record "$name" "observation $category" "absent" FAIL
    FAILURES=$((FAILURES + 1))
    log "    status body: $body"
  fi
}

write_manifest() {
  cat >"$RUN/manifest/manifest.json" <<'JSON'
{
  "manifestFormatVersion": "0.3",
  "sections": {
    "server": {
      "inline": {
        "name": "Provider smoke",
        "authenticationRequired": true,
        "surfaces": [
          {
            "slug": "interop",
            "isDefault": true,
            "requiredScopes": ["tools.invoke"],
            "operations": [ { "operation": "read-status" } ]
          }
        ]
      }
    },
    "policy": { "inline": { "baseUrl": "https://upstream.invalid" } },
    "operations": {
      "inline": {
        "operations": [
          {
            "key": "GET /status",
            "method": "GET",
            "path": "/status",
            "responses": { "200": { "content": { "application/json": { "schema": { "type": "object" } } } } }
          }
        ]
      }
    },
    "agentSurface": {
      "inline": {
        "operations": [
          {
            "slug": "read-status",
            "name": "Read status",
            "binding": { "type": "http", "operation": "GET /status" }
          }
        ]
      }
    }
  }
}
JSON
}

log "Provider smoke: provider=$PROVIDER"
log "Engine checkout: $(git -C "$ROOT" rev-parse HEAD 2>/dev/null || echo unknown)"
log "Run directory: $RUN"

# --- Common preparation -------------------------------------------------------------------------

OPERATOR_SECRET_FILE="$RUN/operator-secret"
openssl rand -hex 32 | tr -d '\n' >"$OPERATOR_SECRET_FILE"
mkdir -p "$RUN/manifest"
write_manifest

log "Publishing Engine..."
"$DOTNET" publish "$ROOT/src/MCPiler.Engine.Host/MCPiler.Engine.Host.csproj" -c Release -o "$RUN/publish" --nologo -v:q

TAMPERED_SUFFIX="X"

# --- Provider-specific preparation --------------------------------------------------------------

if [[ "$PROVIDER" == "keycloak" ]]; then
  for tool in docker curl openssl; do
    command -v "$tool" >/dev/null 2>&1 || { echo "Required tool missing: $tool" >&2; exit 2; }
  done

  SMOKE_PASSWORD="$(openssl rand -hex 16)"
  CLIENT_SECRET="$(openssl rand -hex 24)"
  KEYCLOAK_ADMIN_USER="smoke-admin"
  KEYCLOAK_ADMIN_PASSWORD="$(openssl rand -hex 16)"
  sed -e "s|__SMOKE_PASSWORD__|$SMOKE_PASSWORD|" \
      -e "s|__SMOKE_CLIENT_SECRET__|$CLIENT_SECRET|" \
      -e "s|__SMOKE_AUDIENCE__|$AUDIENCE|" \
      -e "s|__OTHER_AUDIENCE__|$OTHER_AUDIENCE|" \
      "$HERE/compose/keycloak-realm.json" >"$RUN/keycloak-realm.json"
  KEYCLOAK_REALM_FILE="$RUN/keycloak-realm.json"

  # Exported so every compose call in this run (up, stop, down) substitutes the same values.
  export KEYCLOAK_IMAGE KEYCLOAK_PORT KEYCLOAK_ADMIN_USER KEYCLOAK_ADMIN_PASSWORD KEYCLOAK_REALM_FILE

  log "Starting Keycloak ($KEYCLOAK_IMAGE) on 127.0.0.1:$KEYCLOAK_PORT..."
  docker compose -p mcpiler-provider-smoke -f "$HERE/compose/keycloak.compose.yaml" up -d
  KEYCLOAK_STARTED=1

  for attempt in $(seq 1 120); do
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 \
      "http://127.0.0.1:$KEYCLOAK_PORT/realms/$KEYCLOAK_REALM/.well-known/openid-configuration" || echo 000)"
    [[ "$code" == "200" ]] && break
    sleep 1
  done
  [[ "$code" == "200" ]] || { echo "Keycloak did not become ready (last status $code)." >&2; exit 1; }

  ISSUER="http://127.0.0.1:$KEYCLOAK_PORT/realms/$KEYCLOAK_REALM"
  INTROSPECTION_CLIENT_ID="mcp-smoke"
  INTROSPECTION_CLIENT_SECRET_FILE="$RUN/introspection-secret"
  printf '%s' "$CLIENT_SECRET" >"$INTROSPECTION_CLIENT_SECRET_FILE"

  log "Minting real Keycloak tokens..."
  VALID_TOKEN="$(mint_keycloak_token mcp-smoke "$CLIENT_SECRET" "openid tools.invoke")"
  WRONG_AUDIENCE_TOKEN="$(mint_keycloak_token mcp-smoke-wrong-audience "" "openid tools.invoke")"
  WRONG_SCOPE_TOKEN="$(mint_keycloak_token mcp-smoke-wrong-scope "" "openid")"
  OUTAGE_TOKEN="$(mint_keycloak_token mcp-smoke "$CLIENT_SECRET" "openid tools.invoke")"
  FOREIGN_TOKEN="$(curl -s --max-time 20 \
    --data-urlencode "grant_type=password" --data-urlencode "client_id=admin-cli" \
    --data-urlencode "username=$KEYCLOAK_ADMIN_USER" --data-urlencode "password=$KEYCLOAK_ADMIN_PASSWORD" \
    "http://127.0.0.1:$KEYCLOAK_PORT/realms/master/protocol/openid-connect/token" \
    | sed -n 's/.*"access_token"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"
  printf '%s' "${VALID_TOKEN%?}$TAMPERED_SUFFIX" >"$RUN/tampered.token"
else
  require SMOKE_ISSUER "${SMOKE_ISSUER:-}"
  require SMOKE_VALID_TOKEN_FILE "${SMOKE_VALID_TOKEN_FILE:-}"
  ISSUER="$SMOKE_ISSUER"
  INTROSPECTION_CLIENT_ID="${SMOKE_INTROSPECTION_CLIENT_ID:-}"
  INTROSPECTION_CLIENT_SECRET_FILE="${SMOKE_INTROSPECTION_CLIENT_SECRET_FILE:-}"
  VALID_TOKEN="$(tr -d '\n' <"$SMOKE_VALID_TOKEN_FILE")"
  WRONG_AUDIENCE_TOKEN=""
  WRONG_SCOPE_TOKEN=""
  OUTAGE_TOKEN=""
  FOREIGN_TOKEN=""
  [[ -n "${SMOKE_WRONG_AUDIENCE_TOKEN_FILE:-}" ]] && WRONG_AUDIENCE_TOKEN="$(tr -d '\n' <"$SMOKE_WRONG_AUDIENCE_TOKEN_FILE")"
  [[ -n "${SMOKE_WRONG_SCOPE_TOKEN_FILE:-}" ]] && WRONG_SCOPE_TOKEN="$(tr -d '\n' <"$SMOKE_WRONG_SCOPE_TOKEN_FILE")"
  printf '%s' "${VALID_TOKEN%?}$TAMPERED_SUFFIX" >"$RUN/tampered.token"
fi

# --- Served bearer-validation cases -------------------------------------------------------------
#
# Every case speaks MCP to the protected route itself. The canonical resource identity is bound
# explicitly (--external-resource /api/interop=<audience>), so the audience check is decided on
# the deployment-owned value rather than on the loopback request authority.

log "JWKS/introspection cases against a real Engine listener..."
start_engine "$VALIDATION"

expect_challenge "unauthenticated_request_is_challenged"
expect_mcp_session "valid_provider_token_opens_a_real_mcp_session" "$VALID_TOKEN"
expect_mcp_refusal "tampered_signature_is_refused" "$(cat "$RUN/tampered.token")" 401
if [[ -n "$WRONG_AUDIENCE_TOKEN" ]]; then
  expect_mcp_refusal "wrong_audience_is_refused" "$WRONG_AUDIENCE_TOKEN" 404
fi
if [[ -n "$WRONG_SCOPE_TOKEN" ]]; then
  expect_mcp_refusal "missing_scope_is_refused" "$WRONG_SCOPE_TOKEN" 404
fi
if [[ -n "$FOREIGN_TOKEN" ]]; then
  expect_mcp_refusal "foreign_issuer_token_is_refused" "$FOREIGN_TOKEN" 401
fi

if [[ "$VALIDATION" == "jwks" ]]; then
  expect_observation "healthy_key_set_is_observed" "keys-refreshed"

  if [[ "$PROVIDER" == "keycloak" ]]; then
    # Real JWKS outage: keys are already cached, so a locally valid, unexpired token must keep
    # validating while the provider is stopped. The provider is restarted afterwards.
    log "JWKS outage path (provider stopped with cached keys)..."
    docker compose -p mcpiler-provider-smoke -f "$HERE/compose/keycloak.compose.yaml" stop >/dev/null
    expect_mcp_session "cached_keys_keep_serving_a_locally_valid_token_during_an_issuer_outage" "$VALID_TOKEN"
    docker compose -p mcpiler-provider-smoke -f "$HERE/compose/keycloak.compose.yaml" start >/dev/null
    code=000
    for attempt in $(seq 1 60); do
      code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 \
        "http://127.0.0.1:$KEYCLOAK_PORT/realms/$KEYCLOAK_REALM/.well-known/openid-configuration" || echo 000)"
      [[ "$code" == "200" ]] && break
      sleep 1
    done
    [[ "$code" == "200" ]] || { echo "Keycloak did not come back after the JWKS outage case (last status $code)." >&2; exit 1; }
  fi
else
  expect_observation "issuer_answer_is_observed" "issuer-answered"
fi

if [[ "$PROVIDER" == "keycloak" ]]; then
  stop_engine
  log "Introspection outage path (provider stopped after a positive answer)..."
  start_engine introspection
  expect_mcp_session "introspection_active_token_opens_a_real_mcp_session" "$VALID_TOKEN"
  expect_mcp_refusal "unknown_token_is_inactive" "not-a-jwt" 401

  # Real provider-side revocation: a freshly minted token is revoked at Keycloak *before* Engine
  # ever sees it, so the authoritative active:false answer must refuse it on the same route.
  log "Introspection revocation path (a real token revoked before Engine sees it)..."
  REVOKED_TOKEN="$(mint_keycloak_token mcp-smoke "$CLIENT_SECRET" "openid tools.invoke")"
  curl -s -o /dev/null --max-time 20 \
    --data-urlencode "token=$REVOKED_TOKEN" \
    --data-urlencode "token_type_hint=access_token" \
    --data-urlencode "client_id=mcp-smoke" \
    --data-urlencode "client_secret=$CLIENT_SECRET" \
    "http://127.0.0.1:$KEYCLOAK_PORT/realms/$KEYCLOAK_REALM/protocol/openid-connect/revoke"
  expect_mcp_refusal "revoked_token_is_inactive" "$REVOKED_TOKEN" 401

  docker compose -p mcpiler-provider-smoke -f "$HERE/compose/keycloak.compose.yaml" stop >/dev/null
  expect_mcp_refusal "introspection_outage_fails_closed" "$OUTAGE_TOKEN" 401
  expect_observation "introspection_outage_is_observed" "introspection-unavailable"
fi

stop_engine

# --- Report -------------------------------------------------------------------------------------

{
  printf '{\n'
  printf '  "provider": "%s",\n' "$PROVIDER"
  if [[ "$PROVIDER" == "keycloak" ]]; then
    printf '  "providerImage": "%s",\n' "$KEYCLOAK_IMAGE"
  fi
  printf '  "engineHead": "%s",\n' "$(git -C "$ROOT" rev-parse HEAD 2>/dev/null || echo unknown)"
  printf '  "issuer": "%s",\n' "$ISSUER"
  printf '  "validation": "%s",\n' "$VALIDATION"
  printf '  "audience": "%s",\n' "$AUDIENCE"
  printf '  "canonicalIdentity": "external-resource %s=%s",\n' "$MCP_PATH" "$AUDIENCE"
  printf '  "publicHost": "%s",\n' "$PUBLIC_HOST"
  printf '  "cases": [\n'
  awk -F'\t' 'BEGIN { first=1 } { if (!first) printf ",\n"; first=0; printf "    { \"name\": \"%s\", \"expected\": \"%s\", \"observed\": \"%s\", \"result\": \"%s\" }", $1, $2, $3, $4 }' "$ROWS"
  printf '\n  ],\n'
  printf '  "failures": %s\n' "$FAILURES"
  printf '}\n'
} >"$REPORT"

log ""
log "Report: $REPORT"
log "Transcript: $TRANSCRIPT"

if [[ "$FAILURES" -gt 0 ]]; then
  log "Provider smoke FAILED: $FAILURES case(s) did not match."
  exit 1
fi

log "Provider smoke PASSED: every case matched."
