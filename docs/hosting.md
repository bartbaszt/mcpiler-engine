# Hosting MCPiler Engine

MCPiler Engine is a standalone process. It mounts one or more MCPiler Manifest bundles,
keeps binary file handles in a local store, and serves the derived MCP surfaces over
Streamable HTTP or standard input/output.

## Basic HTTP hosting

A serving process needs at least one mount and a file-store root:

```bash
dotnet mcpiler-engine.dll serve \
  --mount /petstore=/manifests/petstore \
  --file-store-root /data
```

`--mount` is repeatable. Its value is `<prefix>=<manifest-directory>`. Each mounted Manifest
keeps its own tool namespace and surfaces; mounts are not merged. The Manifest's default
surface answers at the mount prefix and named surfaces answer below that prefix.

The HTTP listener defaults to `http://127.0.0.1:8080`. Override it with `--listen`:

```bash
dotnet mcpiler-engine.dll serve \
  --mount /petstore=/manifests/petstore \
  --file-store-root /data \
  --listen http://0.0.0.0:8080
```

Startup is atomic. Engine validates every mount before opening the listener. If one mount or
one process setting is refused, no mount is served.

## Configuration

The host accepts the following settings:

| Setting | Purpose |
| --- | --- |
| `--file-store-root <dir>` | Directory used for binary response and upload handles. |
| `--listen <http-url>` | HTTP bind address. Default: `http://127.0.0.1:8080`. |
| `--transport http\|stdio` | Select Streamable HTTP or stdio. Default: `http`. |
| `--served-content-root <dir>` | Declares a directory served by the deployment so the file store can be kept outside it. Repeatable. |
| `--issuer <url>` | Trusted OAuth issuer for mounts that require bearer authorization. |
| `--token-validation introspection\|jwks` | Token-validation mode. Must be paired with `--issuer`. |
| `--introspection-endpoint <url>` | Override the discovered RFC 7662 endpoint. |
| `--jwks-uri <url>` | Override the issuer's published JWKS URI. |
| `--drain-timeout-seconds <n>` | Positive whole-second shutdown drain window. Default: 100 seconds. |

Unknown settings are refused by name. Runtime API destinations, allowed origins, credentials,
and Manifest-compiled execution limits are not host configuration.

Two switches affect Manifest admission:

- `--require-sealed` refuses a Manifest without its completeness seal.
- `--allow-inline-secrets` permits literal secret values in a Manifest. Without it, inline
  credential material is refused.

Both switches may also be written with an explicit Boolean value, for example
`--require-sealed false`.

Compiled limits can only be narrowed. Use `--floor <bound>=<value>` for a process-wide floor,
or `--mount-limit <prefix>:<bound>=<value>` for one mount. A host setting cannot widen a value
compiled into the Manifest.

## Inspecting without serving

`inspect` runs the same mount, validation, narrowing, and derivation path as `serve`, prints the
surfaces and tool fingerprints that would be exposed, and opens no listener:

```bash
dotnet mcpiler-engine.dll inspect \
  --mount /petstore=/manifests/petstore \
  --file-store-root /data
```

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
  --listen http://0.0.0.0:8080
```

Build an OCI image index for both supported Linux architectures with Buildx:

```bash
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  --output type=oci,dest=mcpiler-engine.oci.tar \
  .
```

For registry publication, replace the OCI output with the registry tag and `--push` used by your
release pipeline.
