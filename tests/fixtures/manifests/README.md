# Manifest fixtures

Hand-authored manifests used by `MCPiler.Engine.UnitTests`. Every fixture here is
readable input, not generated output: the format has to be authorable outside any
tooling, so the corpus is written the way an operator would write it.

`.gitattributes` disables end-of-line normalization for this whole tree. The
`sealed-bundle` digests are over the exact bytes on disk, and a checkout that
rewrote line endings would silently invalidate them.

## `defaults.json`

Every value the format treats as the meaning of an absent member, stated once. Byte-identical
to `tests/fixtures/manifests/defaults.json` in the Platform repository.

The producer decides what to omit and this reader decides what an omission means, in separate
repositories with no shared code. `SharedDefaultsTests` asserts the reader against this file by
parsing documents that omit the member, so what is pinned is the value an absence actually
produces rather than a constant that happens to sit nearby.

## Valid fixtures

Each directory holds a `manifest.json` and, where the fixture is a real bundle,
a `sections/` directory.

| fixture | what it pins |
| --- | --- |
| `minimal/` | the whole format reduced to what cannot be defaulted. Under 40 lines, asserted by test. |
| `multi-surface/` | two surfaces over one operation set, all three exposures, navigator settings, required scopes, a per-operation server URL, and every parameter location. |
| `sealed-bundle/` | five external sections with per-section digests and sizes plus a completeness seal over the index. |
| `refs/` | manifest-local `$ref`, including a self-referential component and a shared one used from several sites. |
| `compound/` | a three-step workflow with argument, step-response and constant mappings, plus output selection. |
| `transformed/` | input and output transformation programs carried verbatim. |
| `files/` | multipart upload with encoding, raw binary body, and a binary response declared through its media types. |
| `credentials/` | every credential scheme and every API-key location, all by reference. |
| `search/` | a pinned lexical index written by hand from the documented rules, so a drift in either derivation or the rules fails a test instead of quietly changing relevance. |
| `jmespath-profile-1/` | a complete transformed binding using the confined JMESPath profile-1 output projection and explicit projection limits. |
| `response-cache/` | a minimal cache-eligible GET with an authored per-operation response-cache TTL. |
| `response-projection-pagination/` | a minimal agent-facing output envelope with cursor pagination derived from a response header. |
| `two-origins/` | operations intentionally routed to more than one allowed upstream origin. |
| `compiled/` | producer-shaped output retained for Engine/Studio compatibility tests; not the recommended starting point for a hand-authored Manifest. |

### Authentication fixtures

`manifest-0.3/` contains complete manifests for the current executable authentication
vocabulary rather than fragments:

| fixture | what it pins |
| --- | --- |
| `static/` | a static authentication profile. |
| `oauth-client-credentials/` | OAuth 2 client credentials. |
| `oauth-authorization-code/` | OAuth 2 authorization code with PKCE/refresh state. |
| `exchange/` | token/session exchange. |
| `challenge-session/` | challenge/session authentication. |
| `oauth1-authorization/` | OAuth 1.0a including HMAC-SHA1, RSA-SHA1 and HMAC-SHA256 examples. |
| `request-signing-aws-sigv4/` | AWS Signature Version 4 request signing. |
| `request-signing-hmac/` | generic HMAC request signing. |
| `request-signing-jwt-hmac/` | JWT-HMAC request signing. |
| `request-signing-subsonic-md5/` | Subsonic-compatible MD5 signing. |
| `managed-provider/` | a dynamic profile whose credential value comes from the active managed generation. |

The user-facing catalogue in [`examples/README.md`](../../../examples/README.md) maps common
authoring goals to these test-pinned manifests.

## `archive/`

`archive/sealed-bundle.mcpiler-manifest` is the deterministic transport archive of
`sealed-bundle/`, byte-identical to `tests/fixtures/manifests/archive/` in the Platform
repository.

The generator that produces manifests packs archives too, and it cannot reference this
project, so the two packers are independent implementations of one specified byte layout.
This file is what reconciles them: each side asserts it produces exactly these bytes, so a
divergence fails on whichever side changed. It was accepted only after both packers produced
it independently and agreed.

Agreeing on bytes is not sufficient on its own, because two packers could agree on a pattern
that is not a loadable bundle. `ArchiveByteContractTests` therefore also unpacks this file and
loads the result as a sealed manifest.

## Hostile fixtures

`hostile/bundle/<case>/` holds cases that need real files on disk: path
containment, missing section files, digest and size disagreement, and a section
removed from a sealed index. Each carries an `expected.json` naming the single
diagnostic code the case must produce and why that refusal exists.

`hostile/document-cases.json` holds cases that are defects in the document
itself. They are stored as one file rather than one directory each because none
of them needs a filesystem, and keeping them together makes the refusal matrix
readable as a whole.

Three cases are generated in the test instead of stored here — the schema depth,
node-count and property-count bombs. Their point is size, and a literal fixture
of the required size would be unreadable and would not document anything.

## Adding a fixture

Both hostile sources are enumerated by the tests, so a new case is asserted the
moment it is added; there is no separate list to update. A new valid fixture
directory is likewise picked up and must load without errors.

`ManifestCorpus` classifies a directory as a bundle when it holds a `manifest.json`, and
`CorpusContainsTheDocumentedFixtures` asserts both the bundle list and the list of directories
that are not bundles. Adding either kind therefore requires recording the decision there. The
classification is positive rather than a list of excluded names so that a bundle whose root
went missing shows up as unaccounted material instead of quietly dropping out of the
valid-fixture theories.
