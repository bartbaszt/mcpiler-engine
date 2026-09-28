# MCPiler Manifest 0.2 — historical JSON Schema snapshot

These JSON Schema 2020-12 documents preserve the published description of Manifest format 0.2 for
historical tooling and migration work.

They are **not** evidence that the current Engine serves root format 0.2. The current Engine runtime
support range is documented in [`docs/compatibility.md`](../../docs/compatibility.md) and is
currently exactly 0.3.

## Status

This directory is retained as a historical schema snapshot.

The active schema/reader conformance suite (`PublishedSchemaTests`) targets
[`schemas/manifest-0.3/`](../manifest-0.3/), not this directory. Consequently:

- do not treat a 0.2 schema-valid document as deployable to the current Engine;
- do not assume these historical schemas track the current readers;
- do not update these files merely to match new 0.3 reader vocabulary;
- migrate or re-export a 0.2 Manifest before deploying it to an Engine whose supported root range
  excludes 0.2.

## Authority

For an Engine version that historically implemented format 0.2, its reader was the runtime
authority and these schemas were the machine-readable description. That general rule still applies
to current formats: JSON Schema can describe shape and vocabulary but cannot express every
cross-section runtime invariant.

For current Engine behavior use:

- [Manifest reference](../../docs/manifest.md);
- [Compatibility matrix](../../docs/compatibility.md);
- [current 0.3 schemas](../manifest-0.3/).

## Identifiers

The historical schemas use `urn:mcpiler:manifest:0.2:<name>` identifiers. The version in the URN
is the Manifest format version, not the Engine product version.

## Files

| file | `$id` | section |
| --- | --- | --- |
| `root.schema.json` | `urn:mcpiler:manifest:0.2:root` | the section index |
| `server.schema.json` | `urn:mcpiler:manifest:0.2:server` | `server` |
| `policy.schema.json` | `urn:mcpiler:manifest:0.2:policy` | `policy` |
| `credentials.schema.json` | `urn:mcpiler:manifest:0.2:credentials` | `credentials` |
| `operations.schema.json` | `urn:mcpiler:manifest:0.2:operations` | `operations` |
| `agent-surface.schema.json` | `urn:mcpiler:manifest:0.2:agent-surface` | `agentSurface` |
| `tools.schema.json` | `urn:mcpiler:manifest:0.2:tools` | `tools` |
| `search.schema.json` | `urn:mcpiler:manifest:0.2:search` | `search` |
| `schema.schema.json` | `urn:mcpiler:manifest:0.2:schema` | a schema value |

There is no standalone vector schema in 0.2; vector index metadata, where applicable to that
snapshot, is described by the root schema.
