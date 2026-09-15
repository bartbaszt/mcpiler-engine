# MCPiler Engine

MCPiler Engine is the runtime half of MCPiler. It loads a versioned **MCPiler Manifest**
and serves it as a Model Context Protocol (MCP) server, compiling MCP tool calls into
deterministic HTTP requests against the upstream API the manifest describes.

Engine is deliberately boring: deterministic, explicit, fail-closed, portable and
independently testable.

## What Engine does

- Loads and validates a MCPiler Manifest.
- Serves MCP endpoints: tool catalogue, direct invocation, navigator discovery, compound tools.
- Compiles MCP arguments into exact HTTP requests: path, query, headers, cookies, bodies,
  multipart and file transfer.
- Applies credentials resolved from the environment, from files, from the active managed
  generation, or from a Manifest-declared runtime-owned slot.
- Enforces outbound containment: origin allow-lists, redirect policy, response size limits.
- Runs input and output transformations declared by the manifest.

## What Engine does not do

Engine never interprets a source API description. It does not parse OpenAPI, Postman
collections or cURL commands, does not repair or normalize contracts, does not perform
curation or tool-budget selection, and does not talk to any MCPiler control plane at
runtime. Those belong to MCPiler Studio, which produces the manifest.

A manifest, an Engine build and locally supplied secrets are sufficient to keep serving
indefinitely. Engine has no phone-home dependency. A deployment may optionally configure
[managed mode](#deployment-modes), in which Engine pulls Platform's desired immutable generation
over an authenticated channel; the Manifest contract is unchanged and standalone serving remains
fully supported without it.

## Deployment modes

Engine has exactly one desired-state authority. **File mode** (the default) serves the Manifest
bundles given with `--mount`; replacing one requires an Engine redeploy or restart. **Managed
mode** (`--mode managed`) is optional automation: Engine performs a bounded initial
synchronization before opening its listener, then long-polls Platform for the complete desired
generation and hot-reloads atomically. A candidate is validated in full before activation, a
failed candidate leaves the running generation untouched, and a Platform outage never stops the
generation already serving. [`docs/hosting.md`](docs/hosting.md) documents the settings.

## Manifests

The format reference is [`docs/manifest.md`](docs/manifest.md): the minimal example, every
section, the diagnostic catalogue and the versioning policy. Machine-readable schemas are
in [`schemas/manifest-0.3/`](schemas/manifest-0.3/) and worked examples of every feature
are in [`tests/fixtures/manifests/`](tests/fixtures/manifests/).

A manifest is a JSON document, or a directory of JSON sections with a small root index.
Both forms use the same schema and the same loader, so a hand-written single file and a
Studio-generated multi-section bundle are the same thing to Engine.

Manifests are designed to be authored and generated outside Studio. Integrity hashes are
optional; when present they are verified and a mismatch fails closed naming the section.
Tamper evidence is a deployment concern handled by detached signatures or container image
digests, not by a self-verifying file.

The manifest format is versioned independently of Engine. During alpha the format version
stays in the `0.x` range and Engine states its supported range when it refuses a manifest.

## Hosting

[`docs/hosting.md`](docs/hosting.md) documents mounts, host configuration, HTTP and stdio
transports, health checks, file-store commands, exit codes, shutdown behavior and the container
contract.

## File handles

A binary upstream response is written to a local store and returned as a handle rather than
inlined into a result. [`docs/file-handles.md`](docs/file-handles.md) is the contract for
that store: where the root may point and what is verified about it at startup, how storage
names are generated, what a handle record holds, the write order that decides what a failed
admission leaves behind, when a handle expires and where that is enforced, and what a scan
verdict claims.

It is the only durable state Engine keeps. Everything else Engine does is a function of the
manifest it was given and the request it was handed.

## Runtime-owned authentication state

The file store is the only durable state Engine keeps by default. A deployment may additionally
enable one narrow exception: a Manifest-declared runtime-owned mutable authentication slot, such
as a rotated OAuth refresh token, in a bounded encrypted store configured with
`--runtime-state-root` and `--runtime-state-key-file`. [`docs/hosting.md`](docs/hosting.md)
documents the pair, what may and may not be stored, and how a key loss is recovered.

Without that configuration the process reports `runtime state: memory-only` and keeps serving;
static credentials, managed provider values, access tokens, exchange sessions, challenge sessions
and signing outputs are never persisted either way.

## Status

Pre-alpha. The manifest format is not stable and no compatibility is promised yet.

## Building

Requires the .NET SDK pinned in `global.json`.

```bash
dotnet build MCPiler.Engine.slnx -c Release
bash eng/verify-source.sh
```

Engine builds and tests from a standalone checkout. It must never depend on files outside
this repository.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Contributions require a Developer Certificate of
Origin sign-off (`git commit -s`).

## Licence

Apache License 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).
Trademark and naming rules: [TRADEMARKS.md](TRADEMARKS.md).
