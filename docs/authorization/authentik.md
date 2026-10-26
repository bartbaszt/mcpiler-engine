# authentik as an external issuer for MCPiler Engine

This guide configures authentik as the authorization server whose tokens a standalone Engine accepts
on its protected MCP surfaces. Engine acts as the OAuth **resource server**: it validates the
caller's bearer token and checks the byte-exact canonical resource audience plus the surface's
required scopes.

## Status and evidence qualification

| Statement | Basis | Evidence |
| --- | --- | --- |
| The OAuth2 provider publishes metadata at `/application/o/{application_slug}/.well-known/openid-configuration`, with a per-provider `iss` of `https://host/application/o/{slug}/` by default | authentik's official OAuth2 provider documentation | **Verified on 2026.8.4** (image digest `sha256:e7226ae116dac5aa0a5643803e735b010038f492c401e08e16b3bf1ac54c090c`): discovery answered with the byte-exact provider-scoped issuer |
| Exact resource audience in issued tokens | **Verified on 2026.8.4** by a scope mapping whose expression returns `{"aud": "<exact canonical resource URL>"}`; requesting that scope puts the canonical value into `aud`. Without such a mapping `aud` defaults to the client ID and is refused | A real client-credentials token carried the exact canonical audience and opened a real MCP session; the client-ID-audience token was refused with the uniform `404` |
| RFC 8414 metadata support | **Older material said "not documented"; verified present on 2026.8.4**: `/.well-known/oauth-authorization-server/application/o/{slug}/` answers `200` JSON with the same byte-exact issuer | Recorded run on 2026-10-17; the opt-in OIDC fallback stays the conservative route for deployments that do not serve it. Re-verify per version |
| End-to-end interoperability with a protected Engine surface | **Verified on 2026.8.4** for the BYO harness cases: JWKS mode, positive session, tampered/wrong-audience/wrong-scope refusals, unauthenticated challenge, availability observation | Recorded `eng/provider-smoke --provider byo` run on 2026-10-17: 6/6 cases PASS, `failures: 0`. Not covered by the pinned harness: browser login, long-run refresh rotation and provider-side revocation |

Do not read a successful OIDC login in a browser, a readable discovery document, or a ready
`issuer readiness` probe as proof of interoperability. Only a real authentik-issued bearer accepted
by a protected MCP surface proves the audience and scope path.

## Issuer URL and discovery

Configure `--issuer` as the **provider-scoped** issuer, exactly as authentik publishes it,
including the trailing slash:

```text
https://authentik.example.com/application/o/mcpiler-production/
```

Engine's default route is RFC 8414 (well-known inserted before the issuer path):

```text
https://authentik.example.com/.well-known/oauth-authorization-server/application/o/mcpiler-production/
```

authentik's documented metadata location appends the well-known suffix to the issuer path:

```text
https://authentik.example.com/application/o/mcpiler-production/.well-known/openid-configuration
```

**Verified on 2026.8.4:** the provider answers the standard RFC 8414 path above with conforming JSON
whose `issuer` is byte-identical to the configured provider-scoped issuer, so Engine resolves
metadata without any fallback. Older authentik material did not document that route, and a
deployment may still not serve it; reach the documented OIDC location through Engine's constrained,
opt-in fallback:

```bash
--oidc-discovery-fallback true
```

Fallback fires **only** when the RFC 8414 request answered exactly HTTP 404/410. A malformed
document, wrong issuer, redirect, 401/403, 5xx, TLS or network failure ends resolution without a
second request; a document that parses but names another issuer is a hard refusal. The alternate URL
is constructed from `--issuer` alone — Engine accepts no arbitrary metadata-URL override and does no
provider-slug inference.

### Global issuer mode

authentik's optional **global issuer** mode still publishes the OIDC document at the slug-specific
URL, not at the root. Engine cannot infer the application slug from a bare root issuer, and it will
not guess one. Configure the provider-scoped issuer above as `--issuer`; do not point Engine at the
bare root and expect discovery to find the application.

## Client registration

Pre-registered clients are the baseline. authentik supports regex redirect-URI entries and dynamic
client registration from **2026.8** (gated behind a bearer token with DCR permission, creating a
provider/application per registration); DCR is not an anonymous self-registration channel and CIMD
support is not established. Treat DCR as a policy-dependent extension.

- **Caller client**: authorization code (+ PKCE where the provider supports it), redirect URI
  registered exactly — for the CLI use a fixed loopback callback such as
  `http://127.0.0.1:8765/oauth/callback`. Avoid catch-all regexes.
- **Refresh tokens**: authentik issues refresh tokens when the `offline_access` scope is requested
  *and* the matching provider scope mapping exists. Without it, Engine's refresh-required profile
  cannot commit a durable authorization.
- **Resource server (introspection mode only)**: Engine needs an `introspection_endpoint` member in
  the discovery document and a client credential for it. Whether a given authentik deployment
  publishes a usable RFC 7662 endpoint must be checked in its discovery document; Engine refuses
  startup with `auth/introspection-endpoint-missing` when the member is absent, rather than
  rejecting every token at request time.

## Audience mapping (verified on 2026.8.4)

Engine accepts exactly one `aud` value, byte-identical to the canonical MCP resource URL of the
addressed surface, for example `https://mcp.example.com/api/interop`. authentik's default access
token audience is the provider's client ID — that is not the same fact as "this token is for this MCP
resource". The verified mechanism on 2026.8.4 is a **scope mapping**:

- Create a scope mapping whose expression returns the canonical value:

  ```python
  return {"aud": "https://mcp.example.com/api/interop"}
  ```

- Select it on the OAuth2 provider and have the caller request that scope; the issued access token
  then carries `aud` exactly as written. Requesting a scope without that mapping leaves `aud` at the
  client ID, which Engine refuses — the wrong-audience refusal is then correct, not a bug.
- The provider-side `audience` parameter of the token-exchange grant names a *target provider client
  ID* and is a different mechanism.

If a deployment cannot produce the exact canonical value this way, do **not** relax Engine: adapt
the provider or document the deployment as not interoperable for the exact-audience model. The
mapping is provider behavior, not a documentation guarantee, so re-verify it per authentik version.

## Engine configuration

```bash
dotnet mcpiler-engine.dll serve \
  --mount /api=/opt/mcpiler-manifests/interop \
  --file-store-root /var/lib/mcpiler/files \
  --issuer https://authentik.example.com/application/o/mcpiler-production/ \
  --oidc-discovery-fallback true \
  --token-validation jwks \
  --allowed-host mcp.example.com \
  --listen http://0.0.0.0:8080
```

Behind a reverse proxy add `--trusted-proxy <proxy-ip>` so the public scheme/host is honoured.
The provider's external base URL must spell the same public issuer; a mismatch between the internal
and external URL makes metadata's `issuer` differ from `--issuer` and Engine refuses it.

Check reachability with `issuer readiness`, remembering its limit: it proves metadata, byte-exact
issuer identity, endpoint reachability and (for introspection) resource-server client
authentication only.

## Reverse proxy and external URL pitfalls

- Proxy both the issuer path and the well-known path for the same external host; authentik's
  `application/o/...` path is part of the issuer identity and must not be rewritten.
- If the proxy terminates TLS, the external URL still has to be the issuer Engine is configured
  with; internal addresses in metadata are refused.
- On a path-based reverse proxy, verify that
  `/.well-known/openid-configuration` resolves under the application path — that is the only
  fallback URL Engine will request.

## Validation modes, caching, availability and recovery

The trust mechanics are provider-independent and documented in full in
[Hosting](../hosting.md):

- JWKS: 5-minute fresh window, early refresh on unknown `kid` (30-second cooldown), up to 15 minutes
  of stale-key service during an outage, then fail closed.
- Introspection: per-token single flight, 30-second default positive revalidation bound, 5-second
  authoritative-inactive bound, outages never negative-cached.
- The authenticated operator status route reports bounded availability observations that separate
  an outage from an authoritative refusal and never influence validation.
- `auth clear` commits the local cleared floor first and attempts declared-endpoint revocation
  best-effort; `auth authority-reset` is the acknowledged key-loss recovery; a restart can be
  required after scope/audience changes because discovery and keys are cached per process.

## Repeatable evidence

The harness runs in BYO-token mode: obtain real tokens for the caller in whatever way the deployment
supports — the verified 2026.8.4 run used the client-credentials grant with the auto-created service
account and the audience scope mapping above; a browser authorization-code flow works equally — then

```bash
SMOKE_PROVIDER=byo \
SMOKE_ISSUER=https://authentik.example.com/application/o/mcpiler-production/ \
SMOKE_VALIDATION=jwks \
SMOKE_OIDC_FALLBACK=1 \
SMOKE_AUDIENCE=https://mcp.example.com/api/interop \
SMOKE_VALID_TOKEN_FILE=/path/valid.token \
SMOKE_WRONG_AUDIENCE_TOKEN_FILE=/path/wrong-audience.token \
SMOKE_WRONG_SCOPE_TOKEN_FILE=/path/wrong-scope.token \
eng/provider-smoke/run-provider-smoke.sh --provider byo
```

The harness starts a real Engine listener with a protected surface and asserts the served
authorization outcomes (positive admission, wrong audience, missing scope, tampered signature,
foreign issuer, unauthenticated challenge) and prints the availability observations. See
[the harness README](../../eng/provider-smoke/README.md). The first recorded run (2026-10-17,
authentik `2026.8.4`, digest
`sha256:e7226ae116dac5aa0a5643803e735b010038f492c401e08e16b3bf1ac54c090c`) passed every applicable
case; a PASS is scoped to the exact run and provider version. Record the authentik version, the token
source and the report as evidence.
