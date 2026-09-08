# MCPiler Manifest 0.1 — published JSON Schemas

These documents describe the MCPiler Manifest format for editors, generators and
third-party tooling. They are JSON Schema 2020-12.

## They are a description, not the authority

The readers under `src/MCPiler.Engine/Manifest/Loading/` decide what Engine will serve.
These schemas exist so a human or a tool can be told what the format is without reading
that code. Where the two could ever disagree, the reader wins and the schema is the bug.

That is a real risk, so it is tested rather than trusted. `PublishedSchemaTests` asserts:

- every valid fixture in `tests/fixtures/manifests/` validates against these schemas;
- every hostile fixture that declares `"schemaRefuses": true` is also refused here, and
  every one that declares `false` is not — the split is recorded per case in the corpus,
  so a new case cannot be added without deciding which side it falls on;
- the accepted member set at each object location equals the corresponding reader's
  member list, compared by reflection, so adding a member to a reader without updating
  the schema fails the build;
- every closed vocabulary equals the corresponding `Vocabulary` enum.

## What a schema cannot say here

JSON Schema describes shape and vocabulary. It cannot express uniqueness across array
entries, a cross-reference from one section to another, or agreement between two members
computed from each other. So duplicate slugs and keys, an exposure entry naming an unknown
operation, a binding naming an unknown execution key, a destination outside the perimeter,
and a `key` disagreeing with `method` and `path` are all reader-only refusals. The hostile
corpus marks them `"schemaRefuses": false` and the tests assert that this is exactly the
set the schemas let through.

## One deliberate divergence

The readers match closed vocabularies case-insensitively as a courtesy to hand authors.
These schemas describe the canonical camelCase form only, so an editor will flag `Direct`
where the reader would accept it. That is the intended direction — the schema documents the
form to write, the reader is forgiving about the form you wrote. `TheSchemaDescribesTheCanonicalCasing`
pins the divergence so it stays deliberate.

## Identifiers

`$id` uses `urn:mcpiler:manifest:0.1:<name>`. A URN, not an https URL, because Engine has no
published schema host yet and a URL that does not resolve is a worse identifier than one that
never promised to. A hosted alias can be added at publication.

The version in the identifier is the manifest format version, whose versioning policy is
stated in `../../docs/manifest.md`. It is not the Engine assembly version.

## Files

| file | `$id` | section |
| --- | --- | --- |
| `root.schema.json` | `urn:mcpiler:manifest:0.1:root` | the section index |
| `server.schema.json` | `urn:mcpiler:manifest:0.1:server` | `server` |
| `policy.schema.json` | `urn:mcpiler:manifest:0.1:policy` | `policy` |
| `credentials.schema.json` | `urn:mcpiler:manifest:0.1:credentials` | `credentials` |
| `operations.schema.json` | `urn:mcpiler:manifest:0.1:operations` | `operations` |
| `agent-surface.schema.json` | `urn:mcpiler:manifest:0.1:agent-surface` | `agentSurface` |
| `tools.schema.json` | `urn:mcpiler:manifest:0.1:tools` | `tools` |
| `search.schema.json` | `urn:mcpiler:manifest:0.1:search` | `search` |
| `schema.schema.json` | `urn:mcpiler:manifest:0.1:schema` | a schema value, shared |

There is no schema for `vectors`: its payload is binary, and its index entry is described in
`root.schema.json`.
