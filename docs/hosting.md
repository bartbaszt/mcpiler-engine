# Hosting MCPiler Engine

MCPiler Engine is a standalone process. It mounts one or more MCPiler Manifest bundles,
keeps binary file handles in a local store, and serves the derived MCP surfaces over
Streamable HTTP or standard input/output. The client-facing upload/download route contract is
documented in [File handles — HTTP transfer contract](file-handles.md#http-transfer-contract).

For symptom-driven diagnosis, startup refusals, managed-mode recovery, proxy/auth issues and
projection failures, see [Troubleshooting](troubleshooting.md).

## Basic HTTP hosting

A serving process needs at least one mount and a file-store root. HTTP mounts are **protected by
default** because `server.authenticationRequired` defaults to `true`.

For an explicitly open local/demo Manifest (`"authenticationRequired": false`):

```bash
dotnet mcpiler-engine.dll serve \
  --mount /petstore=/manifests/petstore \
  --file-store-root /data
```

JWKS validation keeps a bounded process-local **JWKS key-set cache**: keys are treated as fresh for
5 minutes, an unknown `kid` triggers an early refresh, and the last valid set may be reused for up
to 15 minutes total during a transient JWKS outage. After that bound, validation fails closed.
Introspection has its separate result-cache policy documented below.

For the normal protected HTTP case, configure a real OAuth/OIDC issuer and validation mode:

```bash
dotnet mcpiler-engine.dll serve \
  --mount /petstore=/manifests/petstore \
  --file-store-root /data \
  --issuer https://idp.example.com \
  --token-validation jwks
```

The issuer above is a placeholder; use your actual authority. If discovery does not publish the
required endpoint, supply the documented `--jwks-uri` or introspection override.

`--mount` is repeatable. Its value is `<prefix>=<manifest-directory>`. Each mounted Manifest
keeps its own tool namespace and surfaces; mounts are not merged. The Manifest's default
surface answers at the mount prefix and named surfaces answer below that prefix.

The HTTP listener defaults to `http://127.0.0.1:8080`. Override it with `--listen`.
When binding beyond loopback, keep the protected authorization settings from the serving
configuration above unless the network itself is an intentionally trusted boundary:

```bash
dotnet mcpiler-engine.dll serve \
  --mount /petstore=/manifests/petstore \
  --file-store-root /data \
  --issuer https://idp.example.com \
  --token-validation jwks \
  --allowed-host mcp.example.com \
  --listen http://0.0.0.0:8080
```

Startup is atomic. Engine validates every mount before opening the listener. If one mount or
one process setting is refused, no mount is served.

## Configuration

The host accepts the following settings:

| Setting | Purpose |
| --- | --- |
| `--mount <prefix>=<dir>` | Mounts a Manifest bundle directory. Repeatable; exactly one mode applies. |
| `--file-store-root <dir>` | Directory used for binary response and upload handles. |
| `--runtime-state-root <dir>` | Directory for Engine's encrypted runtime-owned authentication state. Paired with `--runtime-state-key-file`. |
| `--runtime-state-key-file <file>` | Deployment-supplied Engine runtime-state key, 32 raw bytes or 64 hex characters. Paired with `--runtime-state-root`. |
| `--listen <http-url>` | HTTP bind address. Default: `http://127.0.0.1:8080`. |
| `--transport http\|stdio` | Select Streamable HTTP or stdio. Default: `http`. |
| `--served-content-root <dir>` | Declares a directory served by the deployment so the file store can be kept outside it. Repeatable. |
| `--mode file\|managed` | Desired-state authority. `file` (default) serves locally mounted Manifests; `managed` pulls the desired generation from Platform. |
| `--management-endpoint <url>` | Platform base address for managed mode. Required with `--mode managed`. |
| `--deployment-id <id>` | Deployment identity for managed mode. Required with `--mode managed`. |
| `--deployment-secret-file <file>` | File holding the deployment-scoped bearer secret for managed mode. Required with `--mode managed`. |
| `--trusted-proxy <ip>` | Trusts `X-Forwarded-For`/`X-Forwarded-Proto` from this proxy address. Repeatable; IP literals only. |
| `--allowed-host <host[:port]>` | Authority admitted for protected-resource identity. Repeatable. A concrete listen authority is used by default; wildcard listeners require an explicit value. |
| `--allowed-origin <origin>` | Browser origin admitted on served MCP addresses. Repeatable; canonical origins only. Absent means no browser origin is admitted. |
| `--issuer <url>` | Trusted OAuth issuer for mounts that require bearer authorization, or for any mount that does not declare `authenticationRequired: false`. |
| `--token-validation introspection\|jwks` | Token-validation mode. Must be paired with `--issuer`. |
| `--introspection-endpoint <url>` | Override the discovered RFC 7662 endpoint. |
| `--introspection-cache-ttl-seconds <n>` | Maximum positive introspection result age. Inactive-token results are cached for at most `min(5, n)` seconds. Default: 30 seconds; zero disables both caches. Valid only with `--token-validation introspection`. |
| `--introspection-client-id <id>` | Client identity the process authenticates as to the introspection endpoint. Paired with `--introspection-client-secret-file`. |
| `--introspection-client-secret-file <file>` | File holding that client's secret. A path, never a value: a command-line secret is visible to every process listing. Paired with `--introspection-client-id`. |
| `--jwks-uri <url>` | Override the issuer's published JWKS URI. |
| `--drain-timeout-seconds <n>` | Positive whole-second shutdown drain window. Default: 100 seconds. |
| `--response-cache-max-body-bytes <n>` | Narrows the hard 8 MiB per-entry body ceiling. Zero disables response caching. |
| `--response-cache-max-retained-bytes <n>` | Narrows the hard 256 MiB accounted-memory ceiling per mount. Zero disables response caching. |
| `--response-cache-max-entries <n>` | Narrows the hard 4,096-entry ceiling per mount. Zero disables response caching. |
| `--response-cache-max-ttl-seconds <n>` | Narrows the hard 86,400-second effective TTL ceiling. Zero disables response caching. |
| `--response-cache-operator-secret-file <file>` | Enables the authenticated response-cache operator channel using a dedicated bearer secret read from this file. |

Unknown settings are refused by name. Runtime API destinations, allowed origins, credentials,
and Manifest-compiled execution limits are not host configuration.

Response-cache settings are host-only ceilings; they never change published Manifest bytes or
managed desired state. Each value must be a non-negative whole number no greater than its hard
maximum. A value above that maximum is refused with the allowed ceiling in the diagnostic.
Setting any of the four ceilings to zero disables caching while leaving ordinary live HTTP
execution unchanged. Startup and inspection reports show effective ceilings and disabled state.

The introspection cache is separate from the upstream response cache. Its TTL is meaningful only
with `--token-validation introspection`; supplying it with `jwks` validation or without issuer
validation is refused rather than ignored.

### Response-cache operator channel

The response cache has an optional non-MCP operator surface. It is disabled by default: unless
`--response-cache-operator-secret-file` is configured, these routes are not mapped at all.

When enabled:

- `GET /.engine/response-cache?mount=<prefix>` returns sanitized cache observations for the
  currently serving generation and named mount.
- `POST /.engine/response-cache/clear?mount=<prefix>` clears completed entries for that mount.
  Add `&operation=<slug>` to clear only one operation.
- Both routes require `Authorization: Bearer <operator-secret>`, where the secret is read from the
  configured file at startup and is distinct from MCP caller tokens, the introspection client
  secret, and the managed-deployment secret.
- Remote use requires HTTPS. Plain HTTP is accepted only when the request genuinely originates on
  loopback. Forwarded scheme information is honored only from addresses named with
  `--trusted-proxy`.
- Clearing cache entries does not mutate the Manifest or managed desired generation and does not
  cancel an in-flight producer.

Two switches affect Manifest admission:

- `--require-sealed` refuses a Manifest without its completeness seal.
- `--allow-inline-secrets` permits literal secret values in a Manifest. Without it, inline
  credential material is refused.

Both switches may also be written with an explicit Boolean value, for example
`--require-sealed false`.

Compiled limits can only be narrowed. Use `--floor <bound>=<value>` for a process-wide floor,
or `--mount-limit <prefix>:<bound>=<value>` for one mount. A host setting cannot widen a value
compiled into the Manifest.

## Runtime-owned authentication state

A connector may declare authentication with a slot whose value the provider rotates, such as an
OAuth authorization-code refresh token. Engine keeps that runtime-owned value across restarts in a
bounded, encrypted, file-backed store so a rotation cannot be acknowledged and then lost on the
next process restart. A Manifest that declares such a slot requires this store.

The store is configured with two paired settings. Supplying one without the other is refused, and
a refusal names both:

```bash
dotnet mcpiler-engine.dll serve \
  --mount /petstore=/manifests/petstore \
  --file-store-root /data \
  --runtime-state-root /state \
  --runtime-state-key-file /run/secrets/engine-runtime-state-key \
  --issuer https://idp.example.com \
  --token-validation jwks
```

- `--runtime-state-root` is the state directory. Records are written beneath it, one per mount,
  profile, and slot. Engine creates the directory when it does not exist and keeps it
  owner-only.
- `--runtime-state-key-file` holds Engine's own runtime-state key: exactly 32 raw bytes or 64
  hexadecimal characters, with one optional trailing newline. This is a deployment key. It is
  never the Platform master key, and Engine never reads Platform key material.

Without both settings, a deployment whose Manifests declare no runtime-owned mutable slot may
serve and reports `runtime state: memory-only`. If any mounted Manifest declares such a slot,
startup is refused with `host/runtime-state-required`; Engine does not serve a configuration that
could lose an already-rotated provider credential on restart. With both settings, startup reports
`runtime state: durable`.

The store is deliberately narrow. Only a slot a Manifest declares as runtime-owned mutable
authentication state is persistable; today that is the rotating OAuth authorization-code refresh
token. Static credentials, managed provider values, access tokens, token/session exchange
values, challenge sessions, and signing outputs are never written to disk.

Each record is authenticated-encrypted with a random nonce and binds the store format, mount,
profile, slot, scope fingerprint, authority epoch, and runtime revision as authenticated
metadata. A record whose metadata does not match the active Manifest is never used. Replacement
writes a complete ciphertext to a sibling temporary file, flushes it to disk, and atomically
replaces the target, so a crash exposes either the complete predecessor or the complete
successor and never a partial record.

Failures fail closed. A missing or unusable key, or a record that cannot be authenticated
(wrong key, corruption, truncation, moved file), refuses the affected invocation with a
non-secret diagnostic and preserves the ciphertext as evidence; Engine never deletes stored
ciphertext automatically and never falls back to plaintext. Recovery is explicit: reprovision
the key and reauthorize the connector, which establishes a new authority epoch.

Losing the key does not lose the ability to serve from static credentials, and the previous
refresh token remains on disk as ciphertext for an operator to inspect or remove deliberately.

## Deployment modes

Engine has exactly one desired-state authority per process. The mode is explicit and the process
never falls back between modes.

| Mode | Desired-state authority | Activation boundary | Platform dependency |
| --- | --- | --- | --- |
| `file` (default) | locally mounted Manifest bundles | process start or redeploy | none |
| `managed` | the configured Platform deployment | validated generation pointer swap | synchronization only |

`file` mode serves the Manifests given with `--mount`. Replacing a Manifest directory does not
change a running process: the new content takes effect after an Engine redeploy or restart.

`managed` mode rejects mounts and requires a deployment identity, a Platform endpoint, and a
deployment secret file. The endpoint must use HTTPS unless it is a loopback address. On startup
Engine performs a bounded initial synchronization and only opens the listener once it holds a
valid generation; a Platform that cannot be reached within that bound refuses startup with a
synchronization diagnostic rather than serving an empty surface. After activation a background
long-poll keeps the process on Platform's desired generation:

```bash
dotnet mcpiler-engine.dll serve \
  --mode managed \
  --management-endpoint https://mcpiler.example.com \
  --deployment-id <deployment-id> \
  --deployment-secret-file /run/secrets/engine-deployment-secret \
  --file-store-root /data \
  --runtime-state-root /data/runtime-state \
  --runtime-state-key-file /run/secrets/engine-runtime-state-key \
  --issuer https://idp.example.com \
  --token-validation jwks
```

- `--management-endpoint` is Platform's public address. Engine calls only Platform's
  authenticated internal management endpoint beneath it.
- `--deployment-id` names this deployment; it must equal Platform's configured
  `EngineManagement:DeploymentId`.
- `--deployment-secret-file` holds the deployment-scoped bearer secret. The value is read per
  request and the file path, never the value, appears in process arguments.

Every candidate generation is loaded and validated completely before activation, and activation
is one atomic pointer exchange. A candidate that cannot be loaded leaves the running generation
untouched and reports the refusal to Platform as a sanitized diagnostic. A request admitted under
one generation finishes under that generation; the superseded generation's execution graph and
in-memory secret values are disposed once its leases drain.

Platform/channel failure does not stop the running generation. Engine keeps serving its last
active generation and retries with bounded exponential backoff, so an unreachable Platform
degrades synchronization latency but never serving.

### File transfer in both modes

The transfer surface is the same in `file` and `managed` mode:
`POST {surface}/files/upload` issues an opaque handle and
`GET {surface}/files/{capability}` redeems it. Both routes are children of the parent MCP resource
and inherit its audience, required scopes, protected-resource challenge and capability scope. See
[File handles — HTTP transfer contract](file-handles.md#http-transfer-contract) for the request,
response, authorization and out-of-band byte-transfer details. Managed activation does not change
the generation of an already admitted upload or download request.

## Caller token audience is the exact MCP surface resource

A valid signature/issuer and the required scopes are necessary but **not sufficient** to authorize
a protected MCP request.

The token's **audience** must name the exact canonical resource the client addressed. Engine builds
that resource from the HTTP request-target path spelling (excluding the query string), preserving
percent-encoding and a trailing slash for authorization even though routing uses the decoded path:

```text
scheme://host + raw surface path
```

For example:

```text
https://mcp.example.com/trilium
https://mcp.example.com/trilium/read-only
https://mcp.example.com/trilium/full
```

are three distinct audience/resource values even if the first two resolve to the same default
surface/tool set.

Important consequences:

- scheme participates in the identity: `http://...` and `https://...` are different resources;
- host and port participate in the identity;
- the exact path participates in the identity;
- a trailing slash is significant;
- the bare default mount and its explicit default-surface path are not audience aliases;
- no case-insensitive, prefix or trailing-slash normalization is applied;
- percent-encoded spellings are distinct authorization resource names when the client used different
  bytes in the request target, even when ASP.NET routing decodes them to the same mounted surface;
- `requiredScopes` are checked **in addition to** the audience match.

A caller therefore needs a token issued for the exact public MCP URL it will call. In OAuth
deployments, configure the client/authorization flow so the requested `resource`/audience
corresponds to that URL. Do not issue one token for the bare mount and assume adding a write scope
makes it valid for a sibling `/full` surface.

Protected-resource metadata is generated from the addressed public resource and names the
configured authorization server. A capable OAuth/MCP client should use that metadata rather than
guessing the audience.

Behind a TLS-terminating reverse proxy, preserve the public `Host` header, list that exact
`host[:port]` with repeatable `--allowed-host`, and configure the proxy as trusted so Engine
observes the public HTTPS scheme. Engine does not trust `X-Forwarded-Host`; a caller cannot choose
an arbitrary authority and thereby redefine the protected-resource audience.

## Proxy deployments

For protected HTTP surfaces, the reverse proxy must preserve the **public path** byte spelling that
reaches Engine. Scheme is reconstructed only from trusted forwarded-proto handling; Engine does not
trust `X-Forwarded-Host` and does not implement a trusted `X-Forwarded-Prefix`/external PathBase.

Therefore do **not** deploy protected resources behind prefix stripping/path rewriting such as:

~~~text
public  https://host/mcp/trilium
proxy -> https://engine/trilium
~~~

That topology changes the protected-resource identity. Use a proxy rule that forwards the public
path unchanged, or mount Engine at the public path itself.



Behind a reverse proxy the public scheme may arrive in `X-Forwarded-Proto`, while the public
Host must be preserved as the ordinary `Host`/`:authority` value. Engine ignores forwarded scheme
information unless the direct peer is named with `--trusted-proxy`:

```bash
dotnet mcpiler-engine.dll serve \
  --mount /petstore=/manifests/petstore \
  --file-store-root /data \
  --issuer https://idp.example.com \
  --token-validation jwks \
  --allowed-host mcp.example.com \
  --trusted-proxy 172.28.0.2
```

Only `X-Forwarded-For` and `X-Forwarded-Proto` are trusted, and only from a listed address. The
proxy must preserve the original `Host` header unchanged; Engine never trusts `X-Forwarded-Host`.
For a protected surface that authority must also match `--allowed-host`. When no explicit value is
supplied, a concrete listen address contributes its own authority; wildcard listeners such as
`0.0.0.0` require an explicit allowed host.

### Browser origins

The MCP streamable HTTP transport spec requires the endpoint to validate the `Origin` header when
a browser sends one. Name each browser origin that may reach a served address:

```bash
dotnet mcpiler-engine.dll serve \
  --mount /petstore=/manifests/petstore \
  --file-store-root /data \
  --issuer https://idp.example.com \
  --token-validation jwks \
  --allowed-origin https://studio.example.com
```

`--allowed-origin` is repeatable and accepts canonical origins only (`scheme://host[:port]`, no
path, query, or credentials). When no origin is configured, a request carrying an `Origin` header
is refused on served addresses while a client that sends none — every non-browser MCP client — is
served normally. Non-served paths such as health and protected-resource metadata ignore the
header, so discovery keeps working for browser-based clients.

## Inspecting without serving

`inspect` runs the same mount, validation, narrowing, and derivation path as `serve`, prints the
surfaces and tool fingerprints that would be exposed, and opens no listener:

```bash
dotnet mcpiler-engine.dll inspect \
  --mount /petstore=/manifests/petstore \
  --file-store-root /data \
  --issuer https://idp.example.com \
  --token-validation jwks
```

Run `inspect` with the **same host settings** you intend to serve. For HTTP, host-side startup
authorization refusals — for example a protected mount with no issuer, an unusable issuer endpoint,
or a missing/empty/unreadable `--introspection-client-secret-file` — return exit code `78`.
The report still includes the derived surfaces/tools so the configuration can be diagnosed without
opening a listener. `inspect` reads the configured introspection secret file during preflight but
never prints the secret value.

For an explicitly open local/demo Manifest, omit the issuer settings.

For stdio, pass `--transport stdio` to `inspect` as well. The command applies the same
single-target rule as `serve`: exactly one mount and exactly one surface must be selectable,
otherwise both commands exit `78`. Stdio still does not require an HTTP issuer merely because
the Manifest is protected; the local process boundary is the caller-authorization boundary.

Use `version` or `--version` to print the Engine build identity and the supported Manifest
format range.

## File-store operations

The file-store commands inspect metadata only; they never print stored payload bytes:

```bash
dotnet mcpiler-engine.dll files list --file-store-root /data
dotnet mcpiler-engine.dll files show <handle> --file-store-root /data
dotnet mcpiler-engine.dll files sweep --file-store-root /data
```

`files sweep` reclaims expired handles and unreachable orphan content.

## Stdio transport

Select stdio with `--transport stdio`:

```bash
dotnet mcpiler-engine.dll serve \
  --mount /local=/manifests/local \
  --file-store-root /data \
  --transport stdio
```

Stdio opens no network listener. The operating-system process boundary authorizes the local
caller, so bearer-token authorization, host restriction, trusted-proxy processing, and network
rate limiting do not apply to inbound MCP traffic. The selected configuration must resolve to
exactly one surface because stdio has no URL with which to select among surfaces.

Tool definitions, invocation results, and execution error classifications use the same runtime
path as Streamable HTTP.

## Health and shutdown

HTTP mode maps two health endpoints after all mounts have started successfully:

- `GET /health/live` returns HTTP 200 while the process is alive.
- `GET /health/ready` returns HTTP 200 while the file store is usable and the host is accepting
  work. It returns HTTP 503 during shutdown drain or when the file store becomes unusable.

On shutdown, Engine closes admission to new product requests immediately and lets already admitted
tool invocations finish up to `--drain-timeout-seconds`. Health remains observable during that
window. Work still active at the deadline is cancelled and reported.

## Exit codes

The command-line exit codes are stable:

| Code | Meaning |
| ---: | --- |
| `0` | Success. |
| `1` | Runtime failure not attributed to configuration. |
| `64` | Invalid command-line usage or unknown verb. |
| `78` | Configuration or Manifest refusal. Nothing is served. |

## Container image

The repository Dockerfile publishes the host onto the .NET 10 Ubuntu chiseled runtime image. The
runtime process is non-root, exposes port `8080`, declares `/data` as its file-store volume, and
starts as `dotnet mcpiler-engine.dll serve`.

### Official container images

Stable Engine releases are published to `ghcr.io/bartbaszt/mcpiler-engine`. The public package can
be pulled anonymously even while the Engine source repository remains private. The OCI
`org.opencontainers.image.source` label intentionally names that private repository; the label is
provenance metadata, not a promise that source browsing is currently anonymous.

Use a versioned tag for deployments:

```bash
docker pull ghcr.io/bartbaszt/mcpiler-engine:v0.1.0
```

Engine `:latest` is promoted only by a completed stable Engine release and resolves to the same
verified OCI index as that release's `vA.B.C` tag. Unreleased `main` CI never moves it. A release is
built once under its immutable commit-SHA candidate tag and the stable/versioned aliases are
manifest-only promotions from that candidate, so they do not rebuild application bytes.

Every published stable image carries the Engine `LICENSE`, `NOTICE` and deterministic runtime
third-party notices below `/licenses/mcpiler-engine/`. The .NET runtime's `LICENSE.txt` and
`ThirdPartyNotices.txt` remain under `/usr/share/dotnet/`. The inventory identifies the
third-party packages and reviewed licence classification; it does not replace upstream licence or
binary-agreement texts. See [Licensing and redistribution](licensing.md), especially the
JSON-Everything official-binary terms, before redistributing an Engine image.

Release verification keeps the runnable image index separate from supply-chain evidence. The raw
index contains exactly `linux/amd64` and `linux/arm64`; BuildKit root-index attestations are
disabled. A keyless Sigstore signature, machine-readable SBOM and SLSA provenance are attached as
OCI referrers to the verified candidate digest. The release workflow verifies those referrers and
then requires the candidate, `vA.B.C` and `:latest` raw indexes to be byte-identical.

For repository-side verification, `eng/verify-container.sh` checks raw index shape, runtime
identity, non-root/port/volume behavior, missing-Manifest refusal, OCI labels and redistribution
paths. `eng/verify-supply-chain.sh` verifies the signature, SBOM and provenance referrers against
the candidate digest.

A typical container run bind-mounts Manifest directories read-only and keeps the file store on a
writable volume:

```bash
docker run --rm \
  -p 8080:8080 \
  -v "$PWD/manifests:/manifests:ro" \
  -v mcpiler-data:/data \
  <image> \
  serve \
  --mount /petstore=/manifests/petstore \
  --file-store-root /data \
  --issuer https://idp.example.com \
  --token-validation jwks \
  --allowed-host mcp.example.com \
  --listen http://0.0.0.0:8080
```

The issuer values shown in these examples are placeholders; use the real caller-authorization
authority for the served generation. Key material and management credentials are always passed as
file paths, never as argument values, so `docker inspect` shows where a secret lives rather than
what it is. A managed
container adds the management settings and mounts the deployment secret file read-only:

```bash
docker run --rm \
  -p 8080:8080 \
  -v mcpiler-data:/data \
  -v /srv/mcpiler/deployment-secret:/run/secrets/engine-deployment-secret:ro \
  -v /srv/mcpiler/runtime-state-key:/run/secrets/engine-runtime-state-key:ro \
  <image> \
  serve \
  --mode managed \
  --management-endpoint https://mcpiler.example.com \
  --deployment-id <deployment-id> \
  --deployment-secret-file /run/secrets/engine-deployment-secret \
  --file-store-root /data \
  --runtime-state-root /data/runtime-state \
  --runtime-state-key-file /run/secrets/engine-runtime-state-key \
  --issuer https://idp.example.com \
  --token-validation jwks \
  --allowed-host mcp.example.com \
  --listen http://0.0.0.0:8080
```

An Engine container needs no Platform master key and never receives one. Engine's runtime-state
key is its own deployment secret; losing it does not expose the Platform store, and Platform
cannot read Engine's persisted records.

Build an OCI image index for both supported Linux architectures with Buildx:

```bash
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  --provenance=false \
  --sbom=false \
  --build-arg ENGINE_VERSION=0.1.0 \
  --build-arg SOURCE_REVISION=<40-character-git-sha> \
  --output type=oci,dest=mcpiler-engine.oci.tar \
  .
```

For registry publication, replace the OCI output with the registry tag and `--push` used by your
release pipeline.
