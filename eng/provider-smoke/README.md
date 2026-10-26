# Provider smoke harness

Optional, repeatable evidence harness for Engine's external-issuer boundary: it provisions a real
authorization server, starts a real Engine listener with one protected surface, and drives served
requests with **real provider-issued tokens**. It exists so provider compatibility is never claimed
from documentation, a login page or a metadata probe alone.

## What it exercises

Against a real Engine MCP address (`/api/interop`, protected, scope `tools.invoke`). The surface is
bound to its deployment-owned canonical resource with
`--external-resource /api/interop=<audience>`. That binding is what makes the audience the fixed
public string (`https://<public-host>/api/interop`): a loopback request's own authority is
`127.0.0.1:<port>`, and the audience check compares against the resource identity the deployment
owns, not against whatever host the caller dialled.

| Case | Expected |
| --- | --- |
| No bearer (offline guard, also the readiness probe) | `401` challenge naming `resource_metadata` |
| Valid provider-issued token: `initialize` then `tools/list` on the issued session | `200` with a JSON-RPC result and the surface's `read-status` tool |
| Tampered signature of the valid token | `401` |
| Valid token with another audience | `404` (uniform refusal) |
| Valid token without the required scope | `404` |
| Token from another issuer (foreign realm) | `401` |
| Freshly minted token revoked at the provider before Engine ever saw it (introspection) | `401` |
| Cached-key JWKS outage: the provider is stopped with keys already cached | the same locally valid, unexpired token still opens a session (`200`); the provider is restarted afterwards |
| Availability observations on the authenticated operator status route | category present |

Every refusal is decided on the same route, request shape and session flow as the positive case, so
a refusal cannot come from a different address than the one the token was minted for. Plus the
introspection path when selected: an `active:true` token opens a real session, an unknown token is
`active:false` and refused, and after the provider is stopped a fresh token is refused fail-closed
(`401`) while the status route reports `introspection-unavailable`.

A `200` here is a real MCP exchange, not merely "any status other than 401/404": the harness fails the
positive case if `initialize` answers without a JSON-RPC result, without a session id, or if
`tools/list` on that session does not name the protected surface's tool.

## What it does not prove

- It does not run by itself and does not touch the test gate. A report proves the exact run and
  provider version it describes, nothing more: until a report exists for a provider version, treat
  that provider version as **unverified**.
- It does not prove that a browser login works (the CLI lifecycle tests cover the authorization-code
  redirect with a loopback provider).
- It does not validate long-run refresh rotation, and provider-side revocation only through the
  single introspection case above (a token revoked before Engine ever saw it); capture the report
  from a run and inspect it.

## Prerequisites

A Linux host with Docker (Compose v2), bash, curl, openssl and the .NET SDK. In this repository the
authorized route is the disposable remote Docker VM; use the `remote-docker-vm` workflow: probe the
VM, sync the Engine checkout, run the script there, fetch the artifacts back, then report what
remains and ask the owner about the snapshot. On that VM `dotnet` may not be on `PATH`; set
`DOTNET=$HOME/.dotnet/dotnet` and export `LANG=en_US.UTF-8` for the run.

## Keycloak (fully automated)

```bash
# On the Docker host, from the Engine checkout root:
bash eng/provider-smoke/run-provider-smoke.sh --provider keycloak
```

The harness starts a throwaway Keycloak (`quay.io/keycloak/keycloak:26.4.0` by default; override with
`KEYCLOAK_IMAGE`), templates and imports `compose/keycloak-realm.json` with a generated password and
client secret plus the exact audience, mints real tokens for three clients (positive, wrong
audience, wrong scope), starts Engine with `--token-validation jwks`, runs the cases, then repeats
with `--token-validation introspection`, stops Keycloak and asserts the outage path.

All containers run in the `mcpiler-provider-smoke` Compose project and are removed afterwards; no
credential is written into the repository (the templated realm and secrets live in
`artifacts/provider-smoke/<timestamp>/run/`).

Ports: Keycloak `18080`, Engine `19090` (`KEYCLOAK_PORT`, `ENGINE_PORT`). The public authority and
therefore the audience default to `smoke.engine.test` / `https://smoke.engine.test/api/interop`
(`SMOKE_PUBLIC_HOST`, `SMOKE_AUDIENCE`).

## authentik (BYO tokens)

The harness runs in BYO mode: obtain real caller tokens with the deployment's own flow, then

```bash
SMOKE_ISSUER=https://authentik.example.com/application/o/mcpiler-production/ \
SMOKE_VALIDATION=jwks \
SMOKE_OIDC_FALLBACK=1 \
SMOKE_AUDIENCE=https://mcp.example.com/api/interop \
SMOKE_VALID_TOKEN_FILE=/secure/valid.token \
SMOKE_WRONG_AUDIENCE_TOKEN_FILE=/secure/wrong-audience.token \
SMOKE_WRONG_SCOPE_TOKEN_FILE=/secure/wrong-scope.token \
bash eng/provider-smoke/run-provider-smoke.sh --provider byo
```

`byo.env.example` lists every setting. The verified 2026.8.4 run obtained tokens with the
client-credentials grant (auto-created service account) and a scope mapping returning the exact
canonical `aud`; how you obtain tokens is outside the harness — it only consumes them. A "valid"
token here means: it opens a real MCP session (`initialize` + `tools/list`) on the protected route;
the wrong-audience and wrong-scope tokens are only as meaningful as the provider's configuration, so
record how they were obtained.

## Environment

| Variable | Default | Meaning |
| --- | --- | --- |
| `DOTNET` | `dotnet` | .NET host used to publish and run Engine |
| `KEYCLOAK_IMAGE` | `quay.io/keycloak/keycloak:26.4.0` | Provider image; record tag and digest |
| `KEYCLOAK_PORT` | `18080` | Host port for the provider |
| `ENGINE_PORT` | `19090` | Host port for Engine |
| `KEYCLOAK_REALM` | `mcpiler-smoke` | Imported realm name |
| `KEYCLOAK_ADMIN_USER`, `KEYCLOAK_ADMIN_PASSWORD` | generated per run | Throwaway bootstrap admin, exported to Compose (also used for the foreign-issuer token) |
| `KEYCLOAK_REALM_FILE` | generated per run | Templated realm file mounted into the container for import |
| `SMOKE_PUBLIC_HOST` | `smoke.engine.test` | Public authority for `--allowed-host` and the external-resource identity; must be a DNS name, not loopback |
| `SMOKE_AUDIENCE` | `https://$SMOKE_PUBLIC_HOST/api/interop` | Exact canonical resource audience bound with `--external-resource /api/interop=<value>` |
| `SMOKE_OTHER_AUDIENCE` | `https://$SMOKE_PUBLIC_HOST/api/other` | Audience for the negative client |
| `SMOKE_USER` | `smoke` | Fixture user |
| `SMOKE_VALIDATION` | `jwks` | `jwks` or `introspection` for the first Engine phase |
| `SMOKE_OIDC_FALLBACK` | empty | `1` enables `--oidc-discovery-fallback`; it fires only on an exact 404/410 of the RFC 8414 route (authentik 2026.8.4 serves RFC 8414 directly) |
| `SMOKE_JWKS_URI` | empty | Optional explicit `--jwks-uri` override |
| `SMOKE_INTROSPECTION_ENDPOINT` | empty | Optional explicit `--introspection-endpoint` override |
| `SMOKE_ISSUER` | — | BYO: byte-exact issuer |
| `SMOKE_VALID_TOKEN_FILE` | — | BYO: file with one real bearer |
| `SMOKE_WRONG_AUDIENCE_TOKEN_FILE`, `SMOKE_WRONG_SCOPE_TOKEN_FILE` | empty | BYO: optional negative tokens |
| `SMOKE_INTROSPECTION_CLIENT_ID`, `SMOKE_INTROSPECTION_CLIENT_SECRET_FILE` | empty | BYO introspection resource-server credential |

## Evidence

Every run writes, under ignored `artifacts/provider-smoke/<utc-timestamp>/`:

- `provider-smoke-report.json` — provider and image, Engine commit, issuer, validation mode,
  audience, every case with expected/observed status and `PASS`/`FAIL`, and the failure count;
- `transcript.log` — the full bounded transcript.

The script exits non-zero when any executed case fails. Hand the report to whoever records
verification evidence for the change, and never copy tokens or secrets into this repository: the
report contains statuses only.

## Notes

- Version pinning is deliberate. Record the image reference and digest from the report; a newer
  provider version is a new, unverified configuration until the harness passes against it.
- The introspection phase requires the provider to publish an `introspection_endpoint` and the
  confidential client to introspect its own tokens; the Keycloak fixture is built for that.
- Do not run this against production providers. Fixture clients and generated credentials are
  throwaway by design.
