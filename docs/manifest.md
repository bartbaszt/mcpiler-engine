# The MCPiler Manifest

A manifest is the complete, portable description of an MCP server that Engine can
serve. It carries the HTTP contract, the agent-facing operations, the routing
surfaces, the execution perimeter and the credential references — everything a
deployment needs and nothing that identifies where it was produced.

Engine reads a manifest and nothing else. It does not parse OpenAPI, Postman
collections or cURL commands, it does not reach a database, and it does not call
home. A manifest that loads on one machine loads on every machine.

Manifests are ordinary JSON. A person can write one by hand, a script can
generate one, and MCPiler Studio can export one. None of those three is
privileged: the format is the contract, not the producer.

- Current format version: **0.2**
- Supported by this Engine: **0.2**
- JSON Schemas: [`schemas/manifest-0.2/`](../schemas/manifest-0.2/)
- Worked examples: [`tests/fixtures/manifests/`](../tests/fixtures/manifests/)

## Contents

1. [The smallest useful manifest](#the-smallest-useful-manifest)
2. [Physical shapes](#physical-shapes)
3. [Integrity and sealing](#integrity-and-sealing)
4. [Canonical JSON](#canonical-json)
5. [The root document](#the-root-document)
6. [Sections](#sections)
7. [Schema references](#schema-references)
8. [Derivable sections](#derivable-sections)
9. [Versioning policy](#versioning-policy)
10. [Diagnostics](#diagnostics)

## The smallest useful manifest

Every default in the format is chosen so that a manifest states only what is
specific to the API being served. This is a complete, servable manifest:

```json
{
  "manifestFormatVersion": "0.2",
  "sections": {
    "server": { "inline": { "name": "Example API" } },
    "policy": { "inline": { "baseUrl": "https://api.example.com" } },
    "operations": {
      "inline": {
        "operations": [
          { "key": "GET /pets", "method": "GET", "path": "/pets" }
        ]
      }
    },
    "agentSurface": {
      "inline": {
        "operations": [
          {
            "slug": "list-pets",
            "name": "List pets",
            "binding": { "type": "http", "operation": "GET /pets" }
          }
        ]
      }
    }
  }
}
```

That manifest advertises one tool named `list-pets` on one surface. Engine
supplied: the surface (`default`, the connector's only and therefore default
surface), the tool name and description, the input schema, the allowed-origin
perimeter (the base URL's own origin), every execution limit, and the tool
annotations. Each of those can be stated explicitly to override the default;
none has to be.

Four sections are required: `server`, `policy`, `operations`, `agentSurface`.
The rest are optional.

## Physical shapes

One manifest, three interchangeable layouts. They differ in packaging only; a
loaded manifest is identical whichever was used.

**Single file.** Every section inline in one document. Readable, diffable, ideal
for a hand-written manifest or a small API. Cannot carry a vector matrix, which
is binary.

**Directory bundle.** A root `manifest.json` whose section entries point at
sibling files:

```text
manifest.json
sections/server.json
sections/policy.json
sections/operations.json
sections/agentSurface.json
sections/vectors.bin
```

This is the canonical physical form. A section path must be relative, must not
be absolute, must not be a URI, must not contain a `..` segment, and must resolve
inside the bundle after normalisation. A backslash is refused rather than
translated, because a path that works on one operating system and fails on
another is not portable.

**Transport archive.** A `.mcpiler-manifest` file: an uncompressed ustar archive
of a directory bundle. Every header field that would otherwise record the build
environment is fixed — modification time is the Unix epoch, uid and gid are 0,
user and group names are empty, files are mode 0644 and directories 0755 — so
packing the same bundle twice produces the same bytes. Entries are ordered by
path, which makes the order a property of the manifest rather than of the
producer. Entry names longer than 100 characters are refused rather than encoded
through a long-name extension, because every such extension writes headers that
differ between archivers.

Mixed layouts are allowed: a manifest may inline small sections and point at
files for large ones. `vectors` is the one section that must always be external.

## Integrity and sealing

A section entry may declare `sha256` and `bytes` for its payload, and the root
may declare a `completeness` digest over the section index. A manifest carrying
`completeness` is **sealed**.

Sealing detects accidental corruption, a partial copy, and a section that was
removed from the index. It is **not** tamper-evidence: in a standalone bundle the
index and the payloads are writable by the same actor, so anyone who can change
a section can also change its declared digest. Tamper-evidence belongs to a
detached signature or to the digest of the image the bundle ships in.

Consequently integrity is advisory by default. `--require-sealed` makes a missing
seal a refusal for deployments that want that guarantee.

Sealing recomputes the digests and rewrites the root. It deliberately does not
validate the manifest: the normal reason to seal is that a section was just
edited, so the declared digests are stale by construction, and a sealer that
insisted on a servable manifest could not do its own job. A refused seal leaves
the bundle byte-identical.

A section digest covers the payload bytes **as saved**. Section files in a
generated bundle are written in canonical form because that is the only
representation two independent generators can both reach, but a hand-indented
section file is equally valid — the digest describes whatever bytes are there.
The root document is not covered by any digest, so reformatting or reordering it
does not break the seal.

An inline payload must not declare `sha256` or `bytes`. It already sits inside
the document the seal covers, so a digest there would be a second authority over
the same bytes with no independent writer.

The loader bounds what it will read: 96 MiB for the root document and 64 MiB per
section. The format itself does not bound section size, but a loader must — a
40-byte index pointing at a multi-gigabyte payload would otherwise be a free
memory-exhaustion primitive.

## Canonical JSON

Canonical form is used when sealing, hashing or comparing manifests. It is not a
constraint on hand-written input; any well-formed JSON is accepted.

- Object members sorted by UTF-16 code unit, ordinal.
- Array order preserved.
- No insignificant whitespace.
- UTF-8, no byte-order mark.
- Maximum nesting depth 1000.

Two deliberate divergences from RFC 8785:

**Numbers keep their original token.** `1.50`, `1e3` and `9007199254740993`
round-trip exactly as written. RFC 8785 would rewrite them through ECMAScript
number formatting, which loses the lexical form of a schema bound and changes the
digest of every already-sealed document. `1.50` and `1.5` are therefore *not*
canonically equal, and the format says so rather than promising an equivalence it
does not provide.

**Non-ASCII and HTML-sensitive characters are escaped in uppercase hex**
(`\u00E9`, `\u003C`, `\u2028`), rather than RFC 8785's minimal escaping.

Both exist for byte agreement with documents that were already sealed under these
rules. They are part of the format version: changing either is a format change.

## The root document

| Member | Required | Meaning |
|---|---|---|
| `manifestFormatVersion` | yes | `MAJOR.MINOR`, no leading zeros. Independent of the Engine version. |
| `sections` | yes | The section index. |
| `generator` | no | `name`, `version`, `producedAtUtc`. Diagnostics only; never read. |
| `completeness` | no | `algorithm` (`sha256`) and `value` over the canonicalised section index. |
| `provenance` | no | Opaque. See [Provenance](#provenance). |

Every other root member is refused. Each section entry is either
`{"inline": {...}}` or `{"path": "...", "sha256": "...", "bytes": N}` — never both,
never neither. The `vectors` entry additionally accepts `model` and `dimension`.

Unknown members are refused everywhere except inside `provenance`. This is
deliberate strictness for a format meant to be hand-written: a misspelled
`polcy` accepted and ignored would silently become a perimeter nobody configured.

## Sections

### `server`

Routing identity and the surfaces this manifest serves.

`name` is required and becomes the MCP server's display name. `description` and
`version` are optional. `surfaces` is a list of `{slug, name?, isDefault,
enabled, requiredScopes, navigator{enabled, pageSize}, outputSchemas,
operations[]}`.

Exactly one surface must be the default. When `surfaces` is omitted entirely,
Engine synthesises one: slug `default`, every agent operation exposed directly,
Navigator disabled.

**A surface's `operations` list is the single authority on what can be invoked.**
An operation is invocable on a surface if and only if it appears in that surface's
list with exposure `direct` or `navigator`:

- `direct` — advertised in `tools/list` and invocable.
- `navigator` — reachable only through the Navigator's `invoke` tool.
- `hidden` — declared for diagnostics, never invocable.

Absence from the list means not invocable. There is no second place where
exposure is decided, so no two places can disagree.

### `policy`

The execution perimeter and every bound.

`baseUrl` is required. `allowedOrigins` defaults to the base URL's own origin.
Everything else has a documented default and may be omitted:

| Group | Members and defaults |
|---|---|
| `limits` | `upstreamConnectTimeoutSeconds` 10, `upstreamRequestTimeoutSeconds` 100, `upstreamResponseSizeLimitBytes` 52428800, `redirectHopLimit` 5, `concurrency` 8, `mcpRequestSizeLimitBytes` 1048576 |
| `transformCeiling` | `maxSteps` 64, `maxDepth` 32, `maxNodes` 8192, `maxOutputBytes` 262144, `maxArrayFanout` 1024 |
| `compound` | `maxTotalResponseBytes` 104857600, `workflowTimeoutSeconds` 120 |
| `schemaBounds` | `maxDepth` 32, `maxNodes` 2048, `maxPropertiesPerLevel` 256 |
| `files` | `handleLifetimeSeconds` 86400, `uploadSizeLimitBytes` 104857600, `rejectMagicMismatch` true |

An allowed origin is a scheme, host and optional port. A path, query or fragment
is refused, and a malformed entry refuses the whole section rather than being
skipped — silently dropping one entry would leave the operator believing in a
perimeter they do not have.

**Local configuration may only narrow.** A deployment may reduce any limit and
may not raise one or add an origin. An attempt to widen is refused at startup and
named, rather than silently clamped, because a silent clamp hides an operator's
incorrect belief about the deployed perimeter.

### `credentials`

Credentials by reference. A manifest never carries secret material.

Each entry is `{id, scheme, slot, location?, value}`. Schemes are `basic`,
`bearer`, `apiKey` and `header`. `location` applies to `apiKey` only and is
`header` (default), `query` or `cookie`.

`id` is how a binding names this credential. It matches `^[a-z0-9][a-z0-9-]*$`,
is at most 64 characters, and must be unique within the section. Upper case is
refused rather than folded, so two ids can never differ only by case. An id
selects nothing on its own, implies no scheme, and is never a secret — a produced
manifest derives it from credential metadata, so the same metadata yields the
same id no matter which secret is behind it.

`value` is one of:

- `{"fromEnv": "NAME"}` — an environment variable.
- `{"fromFile": "/absolute/path"}` — a file, trailing newline trimmed.
- `{"inline": "..."}` — refused unless `--allow-inline-secrets`, and always
  warned about.

`basic` uses slots `username` and `password`, which compose one `Authorization`
header; both halves must be declared in the section.

**Declaring a credential grants nothing.** A credential is applied only where a
binding names it, so the section may hold two credentials that address the same
destination — a `bearer` token for one upstream and another for a second — as
long as no single binding references both. Contention is a property of one
executed request, not of the document. A binding that does reference two
credentials writing the same destination is refused, because the request it
describes has no defined outcome.

A credential no binding references is a warning, not a refusal: the document is
servable, but the deployment is being asked for a secret nothing will use.

An unresolvable reference is an authentication fault with its own diagnostic
code, never a network error. No diagnostic ever echoes a credential value, a
resolved secret or the contents of an environment variable.

### `operations`

The HTTP contract, and the only section Engine uses to build a request.

Each operation carries `key` (`"{METHOD} {path}"`), `method`, `path`, and
optionally `upstreamId`, `summary`, `description`, `deprecated`, `tags`,
`parameters`, `requestBody`, `responses`, `security`, `servers`. When `key` is
omitted it is derived from method and path; a key that disagrees with them is
refused.

A parameter's `in` is `query`, `header`, `path` or `cookie`. `style` is one of
`matrix`, `label`, `form`, `simple`, `spaceDelimited`, `pipeDelimited`,
`deepObject`, `cookie`; the default is `simple` for path and header, `form` for
query and cookie. `explode` defaults to true for the `form` style and to false
for every other style, whatever the location. Query and cookie are therefore the
two locations where a parameter that states neither `style` nor `explode`
explodes.

A writer omits an `explode` that equals this default, so the default is part of
the wire contract rather than a reader convenience: a parameter that states no
`explode` and a parameter that states the default one are the same document.

`responses` matters for correctness, not documentation: a declared binary
response media type is how a response becomes a file handle rather than a text
body, and a declared response schema is what structured content is validated
against. Omitting `responses` is legal and warned about.

Schemas use JSON Schema keywords with two documented divergences:
`nullable` is a boolean keyword rather than a `["string","null"]` union, so
"declared nullable" stays distinguishable from "a union that happens to include
null"; and numeric bounds keep their original lexical token.

### `agentSurface`

The operations as an agent sees them.

Each entry carries `slug` (unique, and the reference key used by surface exposure
lists, compound steps and the derivable sections), `name`, and `binding`.
Optionally `kind`, `summary`, `description`, `groups`, `tags`, `inputSchema`,
`outputSchema`, `outputSchemaPolicy`, `annotations`, `risk`, `search`.

**The slug is the manifest's identity for an operation.** No producer-side
identifier is required at runtime. That is what makes a manifest hand-writable
and what keeps an exported manifest and an equivalent hand-written one
interchangeable.

`groups` on an operation names groups declared in the section's own `groups` list;
the join is by name, ordinal and case-sensitive.

Bindings:

- `{"type": "http", "operation": "<execution key>", "serverUrl": "...",
  "credentialRef": ["..."]}` — a direct call. `serverUrl` overrides
  `policy.baseUrl` for this operation and remains fully subject to
  `allowedOrigins`. `credentialRef` names the credentials this request carries.
- `{"type": "transformedHttp", "base": {...}, "inputProgram": {...},
  "outputProgram": {...}}` — a call with a bounded argument or response
  transformation. Input pointers address `/path`, `/query`, `/headers`,
  `/cookies`, `/body`, `/parts`; output pointers read `/status`, `/headers`,
  `/body`.
- `{"type": "compound", "steps": [...], "outputSelection": {...}}` — a workflow
  over other operations in this manifest. A step names another operation's slug.
  Nesting is refused. A step may read a previous step's response, never its own.

**`credentialRef` lives on the request, not on the manifest.** It appears on an
`http` binding and inside a `transformedHttp` binding's `base`, and nowhere else:
on a transformed wrapper or on a compound binding it is an unknown member and the
section is refused. A compound binding has no credentials of its own — each step
carries whatever its own operation's binding names.

Absent and empty mean the same thing, and both mean **no credential**. A binding
that names none sends no credential material, so a manifest that forgets to grant
one fails as unauthorised rather than reaching an upstream with a token it was
never scoped to receive. An id listed twice is accepted; the resolved scope is a
set. Order is not significant — resolution is by id.

Every id a binding names must be declared in `credentials`. A reference to an
undeclared id is refused rather than ignored, because ignoring it would turn an
authoring mistake into a silently unauthenticated request. Referencing exactly
one half of a `basic` pair is refused for the same reason: half an
`Authorization` header is not a weaker credential, it is a malformed one.

`annotations` carries the four MCP hints (`readOnly`, `destructive`,
`idempotent`, `openWorld`). When absent they are derived from `risk`, and when
that is absent too, from the HTTP method. A produced manifest normally states
them explicitly, because an agent deciding whether an action is safe to retry
should not have to traverse two derivation chains.

### `tools`

Optional. When present it pins the exact advertised tool set. When absent Engine
derives it from the surface's exposure list. See
[Derivable sections](#derivable-sections).

### `search`

Optional. A lexical term index used by Navigator discovery. When absent Engine
rebuilds it from `agentSurface` and `operations`.

The index is a term store, not a permission list. It covers every declared
operation, and the surface's exposure list filters every query. A stale,
hand-edited or hostile index can therefore contain an entry it cannot grant.

### `vectors`

Optional, always external: `{path, sha256, bytes, model, dimension}` pointing at
a packed float32 matrix whose row ids are operation slugs.

The vector section **degrades silently**. If it is absent, unreadable, or its
dimension disagrees with the payload, vector ranking is disabled and the manifest
still loads and serves. Discovery falls back to lexical ranking. `validate`
reports the problem; loading does not fail.

### `provenance`

Optional and completely opaque. Engine parses it as an object and reads nothing
inside it. A producer can record whatever traceability it wants — internal
identifiers, digests, selection rationale — without any of it becoming a runtime
input.

This is enforced structurally: no code outside the model may read a member of
`provenance`, and an architecture test proves it.

## Schema references

Within a section document a schema may use a fragment-only `$ref` pointing inside
the same document, typically at `#/components/schemas/<name>`.

Cross-section references, absolute URIs, remote URLs and base-URI resolution are
all refused. Engine resolves a reference lazily, never by inlining eagerly, so a
recursive type terminates on the data rather than on a size limit. Resolution
opens no file and no socket.

Every reference is bounded by `policy.schemaBounds`: depth, total nodes and
properties per level. A reference is an amplification primitive, so the bound is
mandatory rather than advisory.

Shared components are what keep a manifest small. A contract whose references are
fully expanded is several times larger than its source; expressing a shared type
once is both smaller and editable by hand.

## Derivable sections

`tools` and `search` can always be reconstructed from `agentSurface`,
`operations` and `server`, so both are optional.

When either is present it wins, and Engine reports a mismatch loudly rather than
silently preferring one. A pinned section is how a producer guarantees a byte-
stable advertised surface; derivation is how a hand-written manifest avoids
restating what is already implied.

Tool derivation: direct tools in the surface's exposure order, then the Navigator
tools (`catalogue.discover`, `catalogue.describe`, `catalogue.invoke`) when the
surface enables the Navigator. A tool name comes from the operation slug reduced
to `[A-Za-z0-9_.-]`, truncated to 128 characters, with a numeric suffix on
collision. Names are allocated in slug order, so reordering an exposure list
cannot move a bare name onto a different operation.

## Versioning policy

**Two independent version levels.** The root `manifestFormatVersion` is
`MAJOR.MINOR`. Each section may declare its own integer `formatVersion`. Neither
is tied to the Engine's own version number: an Engine release does not imply a
format release, and a format release does not require an Engine release to be
described.

**Engine declares an explicit supported range.** This Engine supports manifest
format `0.2`. Section versions are not uniform, because they move
independently: `credentials` and `agentSurface` are at `2`, while `server`,
`policy`, `operations`, `tools` and `search` are still at `1`. A section that
omits `formatVersion` is accepted at whatever version this Engine supports for
it. A refusal always names the version observed and the range supported. Hostile
input echoed for context is truncated.

**While MAJOR is 0 there is no compatibility promise.** The remedy for an old
manifest is to produce it again, not to migrate it. There is no alpha migrator,
because a migrator would have to guess the intent behind a format that was still
moving.

**From 1.0, a same-MAJOR increase is additive.** A MINOR increase may add
optional members, add a section, add a value to a vocabulary documented as open,
and relax a bound. It must not remove or rename a member, change a default,
change a member's type, add a required member, narrow a bound, change the
canonicalisation rule, or change the meaning of an existing value. Anything else
is a MAJOR increase.

**Vocabularies are closed unless documented otherwise.** An unknown exposure,
parameter location, style, binding type, credential scheme or failure policy is
refused, not ignored.

**Diagnostic codes are part of the public contract.** A code has the shape
`group/kebab-case-detail` and is stable across a MAJOR version. Message text is
not contractual and may be reworded. Programs should match on codes.

**The canonicalisation rule is part of the format version**, including both
divergences described above.

## Diagnostics

Every finding is `{code, severity, section, pointer, message}` with severity
`error` or `warning`. A refusal names the invariant that failed and where, never
a bare "invalid manifest". The validator reports every finding it can, not the
first, because it is the authoring tool for hand-written manifests.

No diagnostic ever discloses a credential value, a resolved secret or the
contents of an environment variable.

The following codes are always warnings; every other code is an error:
`manifest/unsealed`, `operations/no-responses-declared`, `surface/no-operations`,
`credential/inline-discouraged`, `credential/unreferenced`,
`vectors/unreadable`, `vectors/dimension-mismatch`, `vectors/operation-mismatch`,
`search/builder-version-unsupported`.

### `manifest` — document and packaging

| Code | Meaning |
|---|---|
| `manifest/format-version-missing` | No `manifestFormatVersion`. |
| `manifest/format-version-malformed` | Not `MAJOR.MINOR`, or has a leading zero, sign or whitespace. |
| `manifest/format-version-unsupported` | Well formed but outside the supported range. |
| `manifest/root-not-an-object` | The root document is not a JSON object. |
| `manifest/unknown-member` | A member this format does not define. |
| `manifest/member-required` | A required member is absent. |
| `manifest/member-type-invalid` | A member has the wrong JSON type. |
| `manifest/section-not-an-object` | A section payload is not a JSON object. |
| `manifest/section-unknown` | The index names a section this format does not define. |
| `manifest/section-missing` | A required section is absent from the index. |
| `manifest/section-both-inline-and-path` | An entry declares both an inline payload and a path. |
| `manifest/section-neither-inline-nor-path` | An entry declares neither. |
| `manifest/section-path-escapes-bundle` | A path is absolute, a URI, uses a backslash, contains `..`, or resolves outside the bundle. |
| `manifest/section-file-missing` | A declared path has no file. |
| `manifest/section-unparseable` | A section payload is not valid JSON. |
| `manifest/section-hash-mismatch` | A payload does not match its declared `sha256`. |
| `manifest/section-size-mismatch` | A payload does not match its declared `bytes`. |
| `manifest/section-format-version-unsupported` | A section declares an unsupported `formatVersion`. |
| `manifest/section-must-be-external` | `vectors` was declared inline. |
| `manifest/completeness-mismatch` | The seal does not match the section index. |
| `manifest/completeness-algorithm-unknown` | An unrecognised digest algorithm. |
| `manifest/unsealed` | No `completeness`; integrity is unverified. |
| `manifest/seal-required` | `--require-sealed` was set and the manifest is unsealed. |

### `schema` — schemas and references

| Code | Meaning |
|---|---|
| `schema/ref-not-local` | A reference is not a fragment inside the same section. |
| `schema/ref-unresolvable` | A reference points at nothing, or a pure-reference cycle. |
| `schema/bound-exceeded` | Depth, node count or properties per level exceeded `policy.schemaBounds`. |
| `schema/invalid` | A schema value is neither an object nor a boolean. |

### `operations` — the HTTP contract

| Code | Meaning |
|---|---|
| `operations/duplicate-key` | Two operations share an execution key. |
| `operations/key-disagrees-with-method-path` | `key` contradicts `method` and `path`. |
| `operations/unsupported-parameter-location` | A parameter location this format cannot execute. |
| `operations/unknown-style` | A serialisation style outside the vocabulary. |
| `operations/no-responses-declared` | No declared responses, so no file classification or structured-content validation. |

### `agent` — the agent surface

| Code | Meaning |
|---|---|
| `agent/duplicate-slug` | Two operations share a slug. |
| `agent/unknown-group` | An operation names a group the section does not declare. |
| `agent/kind-binding-mismatch` | A declared `kind` contradicts the binding. |

### `binding` — execution bindings

| Code | Meaning |
|---|---|
| `binding/operation-key-unknown` | A binding names an execution key `operations` does not define. |
| `binding/compound-step-unknown-operation` | A step names a slug the surface does not declare. |
| `binding/compound-nested` | A compound step references another compound operation. |
| `binding/duplicate-step-id` | Two steps in one workflow share an id. |
| `binding/step-reference-unknown` | A mapping reads a step that does not precede it. |
| `binding/compound-binding-version-unsupported` | An unsupported `bindingVersion`. |
| `binding/type-unknown` | A binding type outside the vocabulary. |
| `binding/transform-invalid` | A transformation program is not a valid program. |
| `binding/pointer-root-not-allowed` | A pointer addresses a root not allowed in that position. |
| `binding/credential-ref-unknown` | A `credentialRef` names a credential `credentials` does not declare. |
| `binding/credential-basic-incomplete` | A binding references one half of a `basic` pair. |

### `surface` — routing

| Code | Meaning |
|---|---|
| `surface/duplicate-slug` | Two surfaces share a slug. |
| `surface/multiple-defaults` | More than one surface is the default. |
| `surface/no-default` | Surfaces are declared but none is the default. |
| `surface/operation-unknown` | An exposure entry names an undeclared slug. |
| `surface/duplicate-operation` | A surface lists one operation twice. |
| `surface/no-operations` | A surface exposes nothing. |

### `policy` — perimeter and bounds

| Code | Meaning |
|---|---|
| `policy/base-url-invalid` | `baseUrl` is not a usable absolute http(s) URL. |
| `policy/origin-invalid` | An allowed origin is malformed, or an override emptied the perimeter. |
| `policy/limit-widened` | Local configuration tried to raise a bound or add an origin. |
| `policy/limit-out-of-range` | A bound is not a positive value this format can express. |
| `policy/destination-not-allowed` | The base URL or a per-operation server URL is outside the perimeter. |

### `credential` — credential references

| Code | Meaning |
|---|---|
| `credential/scheme-unknown` | A scheme outside the vocabulary. |
| `credential/location-invalid` | A location that scheme does not use. |
| `credential/slot-invalid` | A slot the scheme does not define, or a `basic` pair missing a half. |
| `credential/reference-unresolved` | An environment variable or file the deployment does not supply. |
| `credential/inline-not-permitted` | An inline secret without `--allow-inline-secrets`. |
| `credential/inline-discouraged` | An inline secret was permitted. |
| `credential/reference-ambiguous` | Two credentials claim the same reference name. |
| `credential/id-invalid` | An `id` outside `^[a-z0-9][a-z0-9-]*$`, or longer than 64 characters. |
| `credential/duplicate-id` | Two credentials declare the same `id`. |
| `credential/slot-duplicate` | One binding references two credentials that address the same destination. |
| `credential/unreferenced` | A declared credential no binding references. |

### `tools` — the advertised tool set

| Code | Meaning |
|---|---|
| `tools/derivation-mismatch` | A pinned tool set disagrees with derivation. |
| `tools/navigator-name-required` | A tool without operation identity is not a `catalogue.` tool. |
| `tools/duplicate-name` | Two tools share a name. |
| `tools/name-invalid` | A name is empty, over-long, or has characters the protocol disallows. |
| `tools/surface-unknown` | A pinned set names a surface `server` does not declare. |
| `tools/operation-unknown` | A pinned tool names an operation the surface does not expose directly. |

### `search` — the term index

| Code | Meaning |
|---|---|
| `search/derivation-mismatch` | A pinned index disagrees with derivation. |
| `search/builder-version-unsupported` | An unsupported `builderVersion`; the index is rebuilt. |

### `vectors` — semantic ranking

A Manifest that declares no `vectors` section reports nothing: ranking is lexical, and that
is a supported configuration rather than a defect. The codes below mean a payload was
supplied and cannot be used. In every one of them ranking stays lexical and the mount starts.

| Code | Meaning |
|---|---|
| `vectors/unreadable` | The payload is not a matrix this Engine can parse. |
| `vectors/dimension-mismatch` | The declared shape disagrees with the payload's length, or with the section index. |
| `vectors/operation-mismatch` | The matrix describes operations other than the ones being served. |

### `archive` — the transport archive

| Code | Meaning |
|---|---|
| `archive/unreadable` | The archive is truncated or not a readable archive. |
| `archive/entry-type-unsupported` | An entry is neither a regular file nor a directory. |
| `archive/entry-path-unsafe` | An entry name would resolve outside the destination. |
| `archive/entry-name-too-long` | An entry name exceeds 100 characters. |
| `archive/limit-exceeded` | Too many entries, or too many total bytes. |
| `archive/destination-not-empty` | The unpack destination exists and is not empty. |
