# Troubleshooting MCPiler Engine

This guide starts from symptoms an operator sees. For the complete Manifest diagnostic catalogue,
see [`manifest.md#diagnostics`](manifest.md#diagnostics). For every host setting, see
[`hosting.md`](hosting.md).

## First response checklist

Before changing anything, capture three things:

```bash
dotnet mcpiler-engine.dll version
dotnet mcpiler-engine.dll inspect <the same host settings you intend to serve with>
```

and the complete startup output from stderr/stdout.

The useful minimum is:

1. Engine build identity and supported Manifest root range;
2. exact exit code;
3. stable diagnostic code, section and JSON pointer when one is printed;
4. deployment mode: `file` or `managed`;
5. mount prefix and Manifest directory for file mode;
6. whether the problem happens during startup, one request, or a managed replacement.

Do not paste secret-file contents, bearer tokens, refresh tokens or resolved credential values into
an issue. Engine diagnostics are designed not to require them.

## Exit code 64: command line was not understood

Exit code `64` means CLI usage, not a Manifest problem.

Check:

- the verb is one of `serve`, `inspect`, `files list`, `files show`, `files sweep`,
  `version`;
- options begin with `--`;
- `--mount` has the form `<prefix>=<directory>`;
- file mode has at least one mount;
- managed mode has no local mount.

Run `version` separately first if you are unsure which executable you are invoking.

## Exit code 78: configuration or Manifest refusal

Exit code `78` means Engine deliberately refused the configuration. Nothing is served.

Do not treat it as a crash. Run the same configuration through `inspect`; for HTTP it uses the
same Manifest loading/narrowing and host-side startup authorization checks without opening a
listener. If the exact HTTP configuration is unstartable, `inspect` itself also exits `78`
while retaining the derived mount/surface/tool details in its report. This makes the command safe
to use as a CI preflight rather than a report-only warning.

Common host-level codes include:

| Code | What to check |
| --- | --- |
| `host/no-mount` | File mode needs at least one `--mount`. |
| `host/prefix-duplicate` | Two mounts use the same prefix. |
| `host/file-store-unusable` | File-store path, permissions, overlap with served content, or filesystem usability. |
| `host/runtime-state-required` | A Manifest declares mutable runtime auth state but the durable store/key pair is absent. |
| `host/runtime-state-unusable` | Runtime-state root/key cannot be opened or the key format is invalid. |
| `host/floor-unknown` / `host/limit-unknown` | A local narrowing names a bound Engine does not know. |
| `host/floor-malformed` / `host/limit-malformed` | A narrowing value is not in the expected unit/shape. |
| `auth/issuer-missing` | An HTTP mount is protected (the default) but the host has no issuer/validation boundary. Add `--issuer` + `--token-validation`, or explicitly set `authenticationRequired: false` only for an intentionally open mount. |
| `auth/introspection-client-secret-unusable` | The configured introspection client secret file is missing, empty or unreadable. `inspect` and `serve` both refuse with exit 78 before opening a listener. |
| `auth/issuer-metadata-invalid` | RFC 8414 discovery returned malformed metadata, omitted `issuer`, or declared an issuer that is not byte-identical to the configured `--issuer`. Fix the issuer URL/metadata; do not override the mismatch by trusting the discovered endpoints. |

If the code begins with `manifest/`, `schema/`, `operations/`, `agent/`, `binding/`,
`surface/`, `policy/`, `credential/`, `authentication/`, `tools/`, `search/`,
`vectors/` or `archive/`, use the diagnostic table in the Manifest reference.

## "No Manifest is mounted"

In file mode, `--mount` points to a **directory containing `manifest.json`**:

```text
/manifests/petstore/
└── manifest.json
```

Correct:

```bash
--mount /petstore=/manifests/petstore
```

Not:

```bash
--mount /petstore=/manifests/petstore/manifest.json
```

A `.mcpiler-manifest` transport archive is not mounted directly by the current file-mode CLI.

## Manifest loads in an editor/schema but Engine refuses it

The published JSON Schemas are not the full semantic validator.

Engine additionally checks, among other things:

- operation/binding references;
- surface reachability;
- credential and authentication compatibility;
- origin containment;
- local narrowing;
- transform/projection profiles;
- response-cache eligibility;
- section-version vocabulary.

Use `inspect` as the authoritative preflight. The diagnostic section and JSON pointer should
identify the exact member that disagrees.

## Unsupported Manifest or section version

First run:

```bash
dotnet mcpiler-engine.dll version
```

Then compare the document with [`compatibility.md`](compatibility.md).

Important rules:

- root Manifest version and Engine product version are independent;
- a missing section `formatVersion` means the current version for that section;
- an explicitly declared unsupported section version is refused;
- pre-1.0 root format changes may be breaking;
- Engine does not silently migrate persisted Manifest content.

For a Studio-produced Manifest, re-export with a producer compatible with the target Engine rather
than manually editing generated compatibility metadata.

## Credential reference cannot be resolved

For `credential/reference-unresolved`:

- `fromEnv`: confirm the variable exists in the Engine process environment, not only in your
  interactive shell;
- `fromFile`: confirm the file is mounted into the Engine/container, readable by the Engine user,
  and contains the intended secret;
- `fromProvider`: valid only as part of a managed generation; standalone file mode refuses it;
- `inline`: refused by default unless `--allow-inline-secrets` is explicitly enabled.

Do not print the resolved value while debugging. Test only presence, path visibility and ownership.

## Upstream authentication works in one profile but not another

Separate three questions:

1. Does the binding reference the intended `authenticationRef`?
2. Does that profile reference credentials of the correct scheme/slot?
3. Are the authentication and destination origins permitted for the actual upstream request?

Useful Manifest codes include:

- `binding/authentication-ref-unknown`;
- `authentication/credential-unknown`;
- `authentication/credential-incompatible`;
- `authentication/origin-invalid`;
- `policy/destination-not-allowed`.

A dynamic authentication profile is for Engine → upstream API authentication. It does not
configure bearer authorization for MCP clients.

## Protected MCP endpoint refuses to start

A protected HTTP mount needs host-side caller-token validation.

Configure:

```text
--issuer <issuer>
--token-validation introspection|jwks
```

For introspection, optionally configure the explicit endpoint and paired client id/secret file.
For JWKS, optionally override the published JWKS URI.

The host refuses half-configured combinations rather than ignoring them. Examples of invalid
pairing include:

- `--issuer` without `--token-validation`;
- `--jwks-uri` with introspection mode;
- `--introspection-endpoint` with JWKS mode;
- only one of introspection client id / secret file.

Remote authorization trust endpoints must use HTTPS unless they resolve to loopback.

## Token is rejected even though the issuer is configured

First identify whether validation uses introspection or JWKS.

For introspection:

- verify the issuer/discovery document points at the expected endpoint, or set
  `--introspection-endpoint`;
- if client authentication is required, configure both client id and secret file;
- remember inactive results may be cached briefly; use the documented introspection cache TTL when
  testing a recently changed token state.

For JWKS:

- verify the issuer publishes the expected keys, or set `--jwks-uri`;
- check key rotation and token `kid`;
- check token issuer/audience/scope against the resource that is being called.

Do not try to solve inbound token validation by changing Manifest upstream credentials.

## Browser client gets an Origin refusal

Streamable HTTP validates browser `Origin` on served MCP addresses.

Add the exact canonical origin with repeatable `--allowed-origin`:

```bash
--allowed-origin https://studio.example.com
```

Do not include a path, query, credentials or wildcard.

If no browser origin is configured, requests that carry `Origin` are refused while ordinary
non-browser MCP clients that send no `Origin` remain unaffected.

## Reverse proxy causes HTTPS/origin/operator-channel problems

Only addresses declared with repeatable `--trusted-proxy <ip>` may supply trusted forwarded
client/scheme information.

Check:

- the Engine connection peer is the proxy IP you configured;
- the proxy forwards the expected scheme and client address;
- `X-Forwarded-Proto` is not trusted from arbitrary clients;
- the public browser origin is present in `--allowed-origin`.

The response-cache operator channel requires HTTPS remotely. Plain HTTP is accepted only for a
genuine loopback request; a trusted proxy may establish the forwarded HTTPS scheme.

## Managed mode never becomes ready

Managed mode opens no listener until initial synchronization activates a valid desired generation.

Relevant codes include:

| Code | Meaning |
| --- | --- |
| `managed/initial-generation-absent` | Platform reports no desired generation for this deployment. |
| `managed/initial-candidate-refused` | A first delivered generation could not be loaded; there is no previous generation to serve. |
| `managed/initial-sync-timeout` | Initial synchronization exceeded its startup bound. |

Check:

- `--mode managed`;
- `--management-endpoint`;
- exact `--deployment-id`;
- readable `--deployment-secret-file`;
- HTTPS for a remote management endpoint;
- whether Platform actually has a desired generation for that deployment.

A managed process must not also name local `--mount` values.

## Managed replacement is refused but traffic still works

That is expected fail-safe behavior.

A replacement is completely loaded and validated before activation. If it is refused, the current
generation remains active. Diagnostics may include `managed/candidate-load-failed` or the first
underlying Manifest/runtime refusal.

Fix or republish the candidate. Do not restart a healthy instance merely to force the invalid
candidate to replace the serving generation.

## Runtime state is required or unreadable

For `host/runtime-state-required`, supply both:

```text
--runtime-state-root <directory>
--runtime-state-key-file <file>
```

The key file must contain exactly 32 raw bytes or 64 hexadecimal characters, with at most one
trailing newline.

For an unreadable/authentication-failed record:

- verify the same deployment key is being supplied;
- check filesystem permissions and whether records were copied between unrelated deployments;
- do not delete ciphertext automatically while diagnosing;
- if the key is genuinely lost, re-provision the store/key boundary and reauthorize the connector
  so a new authority epoch can be established.

Engine deliberately does not fall back to plaintext or silently forget a rotated refresh token.

## File store refuses startup

The file store is validated before serving.

Check:

- the configured root exists or can be created;
- the Engine process user can read/write it;
- it is not inside a directory declared with `--served-content-root`;
- the deployment filesystem supports the operations Engine needs;
- enough space remains for the configured workload.

Use:

```bash
dotnet mcpiler-engine.dll files list --file-store-root <dir>
dotnet mcpiler-engine.dll files sweep --file-store-root <dir>
```

These commands inspect metadata; they do not print payload bytes.

## A file handle cannot be redeemed

Check the detailed contract in [`file-handles.md`](file-handles.md).

Common causes are:

- handle expired;
- record/content mismatch;
- requesting surface/caller is not authorized to redeem the handle;
- content was manually modified or removed;
- file store became unavailable.

Do not reconstruct or guess storage paths from a handle. The handle is an opaque capability
resolved by Engine.

## JMESPath projection is refused at startup

Manifest-load failures use the `binding/projection-*` family:

- `binding/projection-invalid`;
- `binding/projection-limit-out-of-range`;
- `binding/projection-version-unsupported`.

Check that:

- `languageVersion` is 1;
- all seven positive limits are present;
- limits do not exceed `policy.jmesPathCeiling`;
- the expression is accepted by the confined validation path.

A JMESPath expression is not validated by executing it inside the serving process.

## JMESPath works at startup but fails during invocation

Runtime evaluation has separate operational limits. Typical classes are:

- worker queue/capacity busy;
- evaluation timeout;
- worker launch/reap failure;
- input not usable as JSON;
- result exceeds node/depth/output bounds.

The declared projection is fail-closed: Engine does not return the original unprojected upstream
body after projection failure.

If failures correlate with load, investigate worker concurrency/queue pressure rather than
loosening Manifest semantic limits first.

## Vector search silently becomes lexical

This is intentionally a degradation, not a mount refusal.

Look for:

- `vectors/unreadable`;
- `vectors/dimension-mismatch`;
- `vectors/operation-mismatch`.

Verify the MVMX header, exact byte length, declared section dimension and operation-id order against
[`manifest.md#vectors`](manifest.md#vectors). The supplied query vector must use the same model
and dimension.

A Manifest without vectors is valid and always uses lexical ranking.

## Response cache does not cache

Check all of the following:

- the agent operation declares `responseCache.ttlSeconds`;
- the effective binding resolves to an eligible `GET`/`HEAD`;
- host cache ceilings are non-zero;
- body size fits the effective per-entry ceiling;
- the invocation identity is cacheable under the implemented safety rules.

`agent/response-cache-policy-invalid` is a Manifest-authoring problem. A valid policy can still
execute live without retaining an entry when runtime admission says the response is not cacheable.

If the operator channel is configured, use `GET /.engine/response-cache?mount=<prefix>` to inspect
sanitized observations without exposing cached bodies.

## Stdio starts but no surface can be selected

Stdio has no URL path with which to choose between mounts/surfaces. The selected configuration must
resolve to exactly **one mount and one surface**.

Run the exact stdio configuration through:

```bash
dotnet mcpiler-engine.dll inspect ... --transport stdio
```

An ambiguous configuration exits `78` from both `inspect` and `serve`; the refusal names
whether more than one mount or more than one surface was found.

If you need several independently addressable surfaces, use Streamable HTTP or run separate stdio
processes with narrower configuration.

Stdio owns stdout byte-for-byte for protocol traffic. Engine writes serving progress to stderr so
logs do not corrupt MCP framing.

## Health endpoint behavior

HTTP mode exposes:

- `/health/live`: 200 while the process is alive;
- `/health/ready`: 200 while work is accepted and the file store is usable, otherwise 503.

During graceful shutdown, readiness becomes unavailable while already admitted requests drain.
Liveness remains observable during that drain.

A 503 readiness response is therefore not automatically a crash.

## Exit code 1

Exit code `1` means a runtime failure not classified as configuration/Manifest refusal.

Capture:

- Engine version;
- complete error output;
- operation being performed;
- whether the failure reproduces with `inspect` or only at runtime;
- relevant non-secret deployment details.

If it is reproducible and appears to be an Engine defect, follow the normal issue process. If the
failure may have security impact, use [`../SECURITY.md`](../SECURITY.md) instead of a public issue.

## When to report a bug

A useful report includes:

- Engine version and deployment mode;
- minimal redacted Manifest or fixture reproducing the problem;
- stable diagnostic codes;
- expected vs observed behavior;
- OS/container architecture;
- whether the same input passes `inspect`;
- whether the problem reproduces on the latest supported stable release.

Never include production credential values. Replace identities and URLs where they are not
material to reproduction.
