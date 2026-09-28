# Engine and Manifest compatibility

Engine product versions and MCPiler Manifest versions are separate contracts.

A newer Engine does not imply a newer Manifest, and a Manifest format change does not imply a new
Engine major version. Always check both.

This document covers **Engine ↔ Manifest** compatibility. For **Engine ↔ MCP client** compatibility
(transports, capabilities, network origin and current ChatGPT/Claude/Cursor/VS Code integration
paths), see [`clients.md`](clients.md).

## Release-specific compatibility

Documentation in a checkout describes the Engine code in that checkout. Do not use the section
matrix from unreleased `main` as the matrix for an older released binary.

The root format alone is not enough to prove compatibility because section formats version
independently.

| Engine | Root | server | policy | credentials | authentication | operations | agentSurface | tools | search |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `v0.1.0` | `0.3` | 2 | 1 | 3 | 1 | 1 | 3 | 1 | 1 |
| current unreleased source | `0.3` | 2 | 2 | 4 | 2 | 1 | 4..5 (current 5) | 1 | 1 |

This difference is deliberate evidence that Engine product version, root Manifest version and
section versions are separate contracts. A root-`0.3` artifact produced for `v0.1.0` is not
automatically compatible with the current unreleased reader when it explicitly declares the older
section versions.

The current stable Engine release is recorded in [`CHANGELOG.md`](../CHANGELOG.md). If you run a
tagged release/image, use the documentation from that same tag as the primary contract and use this
document's release table when planning an upgrade.

## Current unreleased source compatibility

The current source on this branch accepts exactly root Manifest format **0.3**:

```text
Engine supported root range: 0.3
```

### Section-version matrix

A section's `formatVersion` is optional. When omitted, Engine interprets the section using the
current format implemented by that reader. When explicitly present, it must be within the accepted
range below.

| Section / sub-format | Accepted version(s) | Current version | Notes |
| --- | ---: | ---: | --- |
| root Manifest | `0.3` | `0.3` | Root uses `MAJOR.MINOR`, not an integer. |
| `server` | `2` | `2` | Exact when explicitly declared. |
| `policy` | `2` | `2` | Exact when explicitly declared. |
| `credentials` | `4` | `4` | Current vocabulary includes OAuth 1.0a credential slots. |
| `authentication` | `2` | `2` | Current vocabulary includes OAuth 1.0a profiles. |
| `operations` | `1` | `1` | Exact when explicitly declared. |
| `agentSurface` | `4..5` | `5` | Version 5 adds operation-level agent output projection/pagination. |
| `tools` | `1` | `1` | Optional/derivable. |
| `search` | `1` | `1` | Optional/derivable. |
| search `builderVersion` | `1` | `1` | Unsupported builder version is ignored and the index is rebuilt. |
| transform program `transformVersion` | `1` | `1` | Applies to input/output transform programs. |
| compound binding `bindingVersion` | `1` | `1` | Other versions are refused. |
| JMESPath `languageVersion` | `1` | `1` | Evaluated only through the confined worker profile. |
| vector matrix MVMX | `1` | `1` | Unusable matrix degrades to lexical ranking rather than refusing the mount. |

The authoritative implementation is the reader/runtime, not this table. CI pins the same values
through reader/model tests; if this table and the executable disagree, the executable is the
authority and this document must be corrected.

## Important difference: `agentSurface` 4 vs 5

Engine deliberately accepts both versions 4 and 5.

Version 4 already uses the binding-level closed `outputProjection` union on a
`transformedHttp` binding. The old `outputProgram` spelling is not accepted.

Version 5 adds the **operation-level** `agentSurface.operations[*].outputProjection` used for
agent-facing response envelopes, response metadata and pagination.

Therefore:

- a version-4 section must not contain operation-level `outputProjection`;
- a version-4 transformed binding may contain its own binding-level `outputProjection`;
- a version-5 section may use both, at their distinct object locations.

For new manually authored Manifests, either omit the section `formatVersion` and follow the
current reference, or explicitly use `5`.

## Root format 0.2

The repository retains `schemas/manifest-0.2/` as a historical published schema snapshot.

The current Engine **does not serve root format 0.2**. Its runtime support range is exactly 0.3.
Do not infer runtime compatibility from the presence of a historical schema directory.

The current schema/reader conformance suite targets `schemas/manifest-0.3/`.

If you have a 0.2 artifact, migrate/re-export it to 0.3 before deploying it to the current Engine.

## How compatibility is checked

Use the Engine binary you intend to deploy:

```bash
dotnet mcpiler-engine.dll version
```

It prints the build identity and supported root Manifest range.

For a concrete file-mode bundle, run:

```bash
dotnet mcpiler-engine.dll inspect \
  --mount /check=/path/to/bundle \
  --file-store-root /tmp/mcpiler-check
```

Use the same authorization/runtime-state host settings the production deployment requires.
For HTTP, `inspect` runs the same Manifest loading, policy narrowing and host-side startup
authorization checks that determine whether `serve` can open the listener. An unstartable
configuration exits `78`, so CI must require exit code 0 rather than merely archive the report.

A successful JSON Schema validation alone is not a compatibility check.

## Machine-readable compatibility descriptor

Current Engine builds expose the independently versioned compatibility contract directly:

~~~bash
dotnet mcpiler-engine.dll compatibility
~~~

The command emits canonical JSON describing the supported root Manifest range, section-format
ranges and other versioned compatibility dimensions. Use this descriptor for automation and
cross-repository compatibility checks; do not infer compatibility from a moving branch, git SHA or
the human-readable table alone.

The human-readable matrix below remains useful for operators, while the descriptor is the
machine-readable authority shipped by the Engine build.

# Upgrade procedure for Engine

For a file-mode deployment:

1. read the target Engine release notes / `CHANGELOG.md` and compare the **section** matrix, not
   only the root format;
2. run the target binary's `version`;
3. run `inspect` against every production Manifest bundle with equivalent host settings;
4. resolve every refusal before rollout;
5. when a producer owns the artifact, re-export for the target Engine rather than changing only
   section-version numbers by hand;
6. verify runtime-state and file-store paths/permissions under the target image/user;
7. deploy the Engine version;
8. verify `/health/live` and `/health/ready`;
9. exercise at least one representative tool call per authentication/execution path you use.

Do not rely on an old process having served a Manifest as proof that a newer or older binary will
accept it.

For managed mode, validate the Engine/desired-generation pairing in a non-production deployment or
staged instance. A replacement generation is fail-safe after startup, but initial synchronization
has no previous generation to fall back to.

## Manifest migration procedure

When Engine reports `manifest/format-version-unsupported` or
`manifest/section-format-version-unsupported`:

### Studio/generated artifact

Prefer re-exporting with a producer that targets the Engine's supported contract. Generated fields,
hashes, section versions and derived sections should remain one producer's coherent output rather
than a collection of manual edits.

### Hand-authored artifact

Use [`authoring.md`](authoring.md) and the current [`manifest.md`](manifest.md) reference:

1. update the root version;
2. update only section shapes whose contract changed;
3. keep `formatVersion` omitted while editing unless you intentionally target a supported older
   section version;
4. run `inspect`;
5. if the bundle uses external section hashes/completeness, reseal it with producer/tooling that
   implements the documented sealing contract.

Do not change only a version number to make a refusal disappear. A version declaration is a claim
that the document follows that vocabulary.

## Pre-1.0 policy

While the Manifest root major version is 0, a minor root-version change may be breaking. Engine
does not promise to accept every earlier 0.x format and does not silently migrate one to another.

The refusal is intentional: a producer and runtime that disagree about a persisted execution
contract must fail visibly rather than guess.

Within root 0.3, section-version ranges are explicit. A section with an omitted `formatVersion`
uses the current interpretation; an explicitly declared older version is accepted only where the
reader has an explicit compatibility range.

## Derived sections and compatibility

`tools` and `search` are optional.

- absent `tools`: Engine derives the advertised tool set from surfaces;
- absent `search`: Engine derives the lexical index;
- unsupported search `builderVersion`: Engine warns and rebuilds the index.

This makes producer-specific derived data replaceable without weakening the persisted execution
contract.

Vectors are also optional, but for a different reason: they are an acceleration artifact. An
unusable matrix produces a vector diagnostic and lexical fallback; it does not make the underlying
Manifest unservable.

## Compatibility failures worth distinguishing

| Diagnostic | Meaning |
| --- | --- |
| `manifest/format-version-unsupported` | Root contract is outside the Engine-supported range. |
| `manifest/section-format-version-unsupported` | A section explicitly declares a version that reader does not support. |
| `binding/compound-binding-version-unsupported` | Compound sub-format version unsupported. |
| `binding/projection-version-unsupported` | JMESPath projection language version unsupported. |
| `search/builder-version-unsupported` | Search index builder differs; index is rebuilt rather than trusted. |
| `vectors/unreadable` | Vector binary layout is unusable; ranking falls back to lexical. |

The first four are persisted-contract incompatibilities that require changing the artifact or
runtime pairing. The latter two are degradations of optional derived/acceleration material.

## Release documentation rule

Every stable Engine release should record:

- Engine version/tag;
- supported Manifest root range;
- any changed section/sub-format version;
- additions/removals of stable diagnostic codes;
- any operator-visible migration requirement.

That information belongs in `CHANGELOG.md` / release notes even when the Manifest root version did
not change.
