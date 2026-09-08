# Manifest fixtures

Hand-authored manifests used by `MCPiler.Engine.UnitTests`. Every fixture here is
readable input, not generated output: the format has to be authorable outside any
tooling, so the corpus is written the way an operator would write it.

`.gitattributes` disables end-of-line normalization for this whole tree. The
`sealed-bundle` digests are over the exact bytes on disk, and a checkout that
rewrote line endings would silently invalidate them.

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
