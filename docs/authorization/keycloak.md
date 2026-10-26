# Keycloak as an external issuer for MCPiler Engine

This guide configures Keycloak as the authorization server whose tokens a standalone Engine accepts
on its protected MCP surfaces. Engine is then the OAuth **resource server**: it validates the
caller's bearer token against Keycloak and checks the byte-exact canonical resource audience plus
the surface's required scopes. It does not log callers in and holds no Keycloak session.

## Status and evidence qualification

| Statement | Basis | Evidence |
| --- | --- | --- |
| Keycloak exposes a conforming RFC 8414 metadata endpoint at `/.well-known/oauth-authorization-server/realms/{realm}` | Documented, Keycloak 26.4.0 and later (release notes and upgrade guide) | **Verified on 26.4.0** (image digest `sha256:5f3fb534cde6bf006d79f5912473e5d2c828c707cdfc52e16972803aca9d43dd`): discovery resolved through the RFC 8414 route in a recorded `eng/provider-smoke` run |
| A custom **Included Custom Audience** mapper can put an MCP resource URL into the token `aud` claim | Keycloak's official MCP integration guidance | **Verified on 26.4.0**: a minted real token carried the exact canonical resource as its audience and opened a real MCP session; a token carrying another audience was refused with the uniform `404` |
| End-to-end interoperability (exact `iss`/`aud`/scope accepted by a protected Engine surface, introspection, outage) | **Verified on 26.4.0** for the harness cases: JWKS and introspection phases, positive session, tampered/wrong-audience/wrong-scope/foreign-issuer refusals, provider-stopped introspection outage fail-closed, availability observations | Recorded `eng/provider-smoke --provider keycloak` run on 2026-10-17: 11/11 cases PASS, `failures: 0`. Not covered by the pinned harness: browser login, long-run refresh rotation and provider-side revocation |

The table above is deliberately conservative. A working Keycloak login, a successful
`issuer readiness` probe, or a metadata document that parses is **not** proof that Engine accepts a
Keycloak-issued token: only a real issued bearer accepted by a protected MCP surface proves that.

## Issuer URL and discovery

Engine constructs the RFC 8414 metadata URL by inserting `/.well-known/oauth-authorization-server`
**before** the issuer path. Configure `--issuer` as the realm URL, without a trailing slash:

```text
https://idp.example.com/realms/mcpiler-production
```

Engine then requests:

```text
https://idp.example.com/.well-known/oauth-authorization-server/realms/mcpiler-production
```

- Keycloak **26.4.0 and later** serves that conforming path.
- Older Keycloak installations expose only
  `/realms/{realm}/.well-known/oauth-authorization-server` and
  `/realms/{realm}/.well-known/openid-configuration`. RFC 8414 alone does not reach them; with
  `--oidc-discovery-fallback true` Engine retries the issuer-derived OIDC URL
  (`https://idp.example.com/realms/mcpiler-production/.well-known/openid-configuration`) — but only
  when the RFC 8414 request answered exactly HTTP 404/410. Prefer 26.4.0 or later and keep the
  fallback off unless your version needs it.
- Reverse proxies must route the **root** `/.well-known/` path to Keycloak. Installations that set a
  non-root `http-relative-path` need an explicit proxy mapping for it, or Engine cannot resolve
  metadata.
- The `issuer` member in Keycloak's document must be byte-identical to `--issuer` (Engine compares
  ordinally). A mismatch between the internal and the external URL — for example metadata says
  `https://internal-host:8443/realms/main` — is refused; fix Keycloak's hostname/external URL
  instead of relaxing Engine.

## Client registration

Pre-registered clients are the baseline. Dynamic Client Registration is documented for Keycloak but
is registration-policy dependent (and the MCP ecosystem is moving away from DCR), so treat it as an
optional extension, not a prerequisite.

Two client roles are involved and they must not be conflated:

1. **Caller/MCP client** — the application that presents tokens to Engine. For CLI bootstrap use a
   native public client: authorization code + PKCE (S256), no client secret, redirect URI
   `http://127.0.0.1/<path>` (Keycloak documents the bare `http://127.0.0.1` entry as permitting a
   random port for native apps; a fixed explicitly configured port is the more conservative choice
   — `auth authorize --redirect-uri http://127.0.0.1:8765/oauth/callback`). Never register a
   wildcard or catch-all redirect.
2. **Resource server** — only when Engine uses `--token-validation introspection`: a confidential
   client whose id/secret Engine presents to the introspection endpoint
   (`--introspection-client-id`, `--introspection-client-secret-file`). Public callers never see
   this secret.

### Scopes

Each protected surface declares `requiredScopes` in the Manifest. Create matching Keycloak client
scopes and assign them to the caller client (as default scopes, or request them explicitly):

- `tools.invoke` — a client scope whose `scope` claim reaches the access token. Engine compares
  scope strings ordinally from the token; it does not consult Keycloak at request time in JWKS mode.

### Audience — the step that actually binds Engine

Engine accepts exactly **one** audience value per token, and it must be byte-identical to the
canonical MCP resource URL of the addressed surface. Keycloak's default token audience is typically
`account` or the client ID; neither authorizes an MCP resource. Use the official guidance's
**Included Custom Audience** mapper:

- Mapper type: *Audience*, included custom audience set to the exact resource URL, for example
  `https://mcp.example.com/api/interop` (scheme + public host + mount prefix + surface slug — the
  same spelling Engine derives from `--allowed-host`).
- Add to access token; assign the carrying client scope as a default scope so the mapper always
  applies.
- Keep the token's `aud` singleton. A multi-valued `aud` names no single protected resource and
  Engine refuses it. Do not also assign the `account` scope to the caller client if that would add a
  second audience.

`resource` indicators (RFC 8707) and CIMD are experimental opt-in Keycloak features; this guide does
not rely on them.

## Engine configuration

```bash
dotnet mcpiler-engine.dll serve \
  --mount /api=/opt/mcpiler-manifests/interop \
  --file-store-root /var/lib/mcpiler/files \
  --issuer https://idp.example.com/realms/mcpiler-production \
  --token-validation jwks \
  --allowed-host mcp.example.com \
  --listen http://0.0.0.0:8080
```

- `--allowed-host mcp.example.com` is what makes the canonical audience
  `https://mcp.example.com/api/<surface>`. Behind a reverse proxy also set
  `--trusted-proxy <proxy-ip>` so the public scheme/host is honoured; otherwise Engine derives the
  private listener address and every exact-audience comparison fails.
- For introspection instead of JWKS, replace the mode and add the resource-server client:

  ```bash
  --token-validation introspection \
  --introspection-client-id mcp-engine-resource-server \
  --introspection-client-secret-file /etc/mcpiler/introspection-secret
  ```

  The endpoint itself is discovered from metadata unless `--introspection-endpoint` overrides it.
- Optional explicit overrides skip discovery for that endpoint exactly as the validators do:
  `--jwks-uri`, `--introspection-endpoint`.

Check connectivity before relying on it:

```bash
dotnet mcpiler-engine.dll issuer readiness \
  --file-store-root /var/lib/mcpiler/files \
  --issuer https://idp.example.com/realms/mcpiler-production \
  --token-validation jwks
```

A ready probe proves metadata, exact issuer identity and endpoint reachability only; it never
manufactures a bearer and does not prove audience/scope acceptance by a real token.

## Reverse proxy and external URL pitfalls

The most common failure is an audience that names the internal address:

```text
token aud:  https://internal-keycloak:8443/realms/main      -> Engine refuses (wrong audience)
needed aud: https://mcp.example.com/api/interop
```

Keep the public resource URL in three places consistent: the Keycloak audience mapper, Engine's
`--allowed-host` (plus trusted proxies), and the `resource`/metadata document Engine publishes at
`/.well-known/oauth-protected-resource/...`. A browser can complete an OIDC login against the wrong
spelling and still be refused by Engine — that is the intended behavior, not a bug.

## Validation modes, caching and availability

- **JWKS (recommended default).** Keys are cached; a set is fresh for 5 minutes, an unknown `kid`
  forces one early refresh (30-second cooldown), and the last valid set may serve a transient
  Keycloak outage for up to 15 minutes total. A locally valid JWT keeps working through a short
  outage; after the bound, validation fails closed.
- **Introspection.** Each distinct token gets one RFC 7662 call, coalesced under bounded
  single-flight. A positive `active:true` answer is reused for at most the configured positive TTL
  (default 30 seconds); an authoritative `active:false` is cached for at most 5 seconds; outages are
  never cached as `inactive` and fail closed.
- **Availability observations.** The authenticated operator status route
  (`GET /.engine/oauth/status`) reports bounded, sanitized trust observations
  (`keys-refreshed`, `keys-unavailable`, `metadata-unavailable`, `issuer-answered`,
  `token-inactive`, `introspection-unavailable`, `token-rejected`). They exist to tell an outage
  apart from an authoritative refusal and never influence token validation. See
  [Hosting — standalone-authorization operator channel](../hosting.md#standalone-authorization-operator-channel).
- **Revocation.** `auth clear` commits a local cleared floor first and then attempts best-effort
  revocation at the declared revocation endpoint only. Remote failure never undoes the local clear,
  and neither result invalidates MCP caller access tokens that were already issued. Keycloak access
  tokens remain introspectable until expiry; revoking the refresh token stops future Engine
  refreshes, not existing callers.

## Local recovery

- `auth status` shows the declared source, epoch/revision and the next action.
- `auth clear --mount /api --profile <id>` masks the local refresh authority and attempts provider
  revocation.
- If the runtime-state encryption key is lost, `auth authority-reset` requires an explicit
  acknowledgement naming affected slots and establishes a fail-closed baseline before a new
  `auth authorize`.
- After changing the client's scopes or audience mapper, re-authorize (`auth authorize`) and restart
  `serve` if the process was started before the change.

## Repeatable evidence

`eng/provider-smoke/run-provider-smoke.sh --provider keycloak` provisions a throwaway Keycloak with
a realm fixture (audience mapper, scope client scopes, public and confidential smoke clients), mints
real tokens and drives the served cases against a real Engine listener: positive acceptance, wrong
audience, missing scope, tampered signature, foreign issuer, unauthenticated challenge, and the
introspection outage/availability path. It writes a JSON report and a transcript; both belong in the
change's verification evidence. Record the image tag and digest in the report. The first recorded run
(2026-10-17, Keycloak `26.4.0`, digest
`sha256:5f3fb534cde6bf006d79f5912473e5d2c828c707cdfc52e16972803aca9d43dd`) passed every case in
both modes; a PASS is scoped to the exact run and provider version. Read
[the harness README](../../eng/provider-smoke/README.md) for the VM workflow and environment
variables.
