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
- Applies credentials resolved from the environment, never stored by Engine.
- Enforces outbound containment: origin allow-lists, redirect policy, response size limits.
- Runs input and output transformations declared by the manifest.

## What Engine does not do

Engine never interprets a source API description. It does not parse OpenAPI, Postman
collections or cURL commands, does not repair or normalize contracts, does not perform
curation or tool-budget selection, and does not talk to any MCPiler control plane at
runtime. Those belong to MCPiler Studio, which produces the manifest.

A manifest, an Engine build and locally supplied secrets are sufficient to keep serving
indefinitely. Engine has no phone-home dependency.

## Manifests

A manifest is a JSON document, or a directory of JSON sections with a small root index.
Both forms use the same schema and the same loader, so a hand-written single file and a
Studio-generated multi-section bundle are the same thing to Engine.

Manifests are designed to be authored and generated outside Studio. Integrity hashes are
optional; when present they are verified and a mismatch fails closed naming the section.
Tamper evidence is a deployment concern handled by detached signatures or container image
digests, not by a self-verifying file.

The manifest format is versioned independently of Engine. During alpha the format version
stays in the `0.x` range and Engine states its supported range when it refuses a manifest.

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
