# Authoring a MCPiler Manifest by hand

This guide is the practical path from an empty directory to a Manifest that MCPiler Engine
can inspect and serve. If you are starting from the product question "I have a REST API; how do I
make it available to AI?", begin with [`getting-started.md`](getting-started.md). For complete
deployment/client scenarios use the [use-case cookbook](use-cases/README.md).

The normative format reference is [`manifest.md`](manifest.md); the published JSON Schemas are
under [`schemas/manifest-0.3/`](../schemas/manifest-0.3/), and executable feature examples are
catalogued in [`examples/README.md`](../examples/README.md).

The normal authoring loop is:

```text
write -> inspect -> fix diagnostics -> inspect -> serve
```

`inspect` uses the same Manifest loading, validation, policy narrowing and surface derivation
path as `serve`, and for HTTP it also applies the host-side startup authorization checks that can
make an otherwise valid Manifest unstartable. It opens no listener. A configuration that HTTP
`serve` would refuse for those checks exits `78` from `inspect` as well. Passing JSON Schema
validation is useful editor feedback; it is not sufficient to prove that a Manifest is servable
because cross-references, origin containment, credential/profile compatibility and other semantic
rules are enforced by the Engine reader/runtime.

## 1. Create the bundle directory

The host CLI mounts a **directory**, not an individual JSON file:

```text
my-api/
└── manifest.json
```

The "single-file" Manifest shape means that all sections are inline in that root
`manifest.json`. It is still mounted by naming the directory that contains the root file:

```bash
dotnet mcpiler-engine.dll inspect \
  --mount /example=./my-api \
  --file-store-root ./data
```

A successful inspection prints the surfaces and tools that would be served. Exit code `78`
means the host or Manifest was refused; the emitted diagnostic code identifies the rule that
failed.

## 2. Start with the four required sections

A minimal useful Manifest needs `server`, `policy`, `operations` and `agentSurface`:

```json
{
  "manifestFormatVersion": "0.3",
  "sections": {
    "server": {
      "inline": {
        "name": "Example API",
        "authenticationRequired": false
      }
    },
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

Save it as `my-api/manifest.json` and run `inspect` again. This example is also kept as the
tested fixture [`minimal/manifest.json`](../tests/fixtures/manifests/minimal/manifest.json).

The explicit `authenticationRequired: false` makes this a **local/demo** example that can be
inspected and served without configuring an OAuth issuer. The Manifest default is protected:
omitting this member means HTTP serving requires `--issuer` plus `--token-validation`. Prefer
the protected default for network-accessible deployments.

The four sections have separate responsibilities:

- `server` names the connector and optionally defines explicit MCP surfaces.
- `policy` declares the upstream base URL, origin perimeter and execution ceilings.
- `operations` describes the exact upstream HTTP contract.
- `agentSurface` defines the operations exposed to the agent and binds them to the HTTP
  contract.

Do not duplicate facts unnecessarily. Defaults are part of the Manifest format and are described
in [`manifest.md`](manifest.md).

### Keep the first hand-authored Manifest small

Several sections and members are deliberately derivable. For an ordinary connector, do not copy
them from a Studio-produced artifact unless you need to pin their exact content:

- omit explicit `server.surfaces` when one default surface exposing the declared operations is
  sufficient;
- omit `tools` to let Engine derive the advertised tool set from surface exposure;
- omit `search` to let Engine derive the lexical Navigator index;
- omit `vectors` unless you actually provide a compatible external embedding matrix;
- omit `generator` unless producer identity is useful for diagnostics;
- omit `provenance` unless your producer needs opaque traceability metadata;
- omit hashes and `completeness` while iterating unless your deployment requires a sealed bundle.

The [`compiled` fixture](../tests/fixtures/manifests/compiled/manifest.json) exists to pin
producer/runtime compatibility. It is intentionally not the template for a human-authored
Manifest.

## 3. Describe HTTP inputs and responses

Add path, query, header and cookie parameters to the corresponding operation. Request bodies and
responses use the bounded JSON Schema subset accepted by the Manifest reader.

For example:

```json
{
  "key": "GET /pets/{petId}",
  "method": "GET",
  "path": "/pets/{petId}",
  "parameters": [
    {
      "name": "petId",
      "in": "path",
      "required": true,
      "schema": { "type": "string" }
    },
    {
      "name": "include",
      "in": "query",
      "schema": { "type": "string" }
    }
  ],
  "responses": {
    "200": {
      "content": {
        "application/json": {
          "schema": { "type": "object" }
        }
      }
    }
  }
}
```

The binding in `agentSurface` references the operation by its `key`. A key must agree with the
operation's method and path; a plausible-looking key that disagrees is refused.

## 4. Define the agent-facing input

Engine can derive simple input schemas, but a hand-authored Manifest should state an explicit
agent-facing schema when the tool vocabulary differs from the upstream HTTP vocabulary:

```json
{
  "slug": "get-pet",
  "name": "Get pet",
  "inputSchema": {
    "type": "object",
    "required": ["petId"],
    "properties": {
      "petId": { "type": "string" }
    }
  },
  "binding": {
    "type": "http",
    "operation": "GET /pets/{petId}"
  }
}
```

Use a `transformedHttp` binding when agent arguments do not map directly to upstream parameter
names or when the upstream response needs to be transformed before it becomes the tool result.
See the tested [transformation example](../tests/fixtures/manifests/transformed/manifest.json).

## 5. Add credentials without embedding secrets

Declare secret references in the optional `credentials` section and reference their ids from
bindings. Prefer environment variables or files:

```json
{
  "credentials": {
    "inline": {
      "formatVersion": 4,
      "credentials": [
        {
          "id": "api-key",
          "scheme": "apiKey",
          "slot": "X-Api-Key",
          "location": "header",
          "value": { "fromEnv": "EXAMPLE_API_KEY" }
        }
      ]
    }
  }
}
```

and:

```json
{
  "binding": {
    "type": "http",
    "operation": "GET /pets",
    "credentialRef": ["api-key"]
  }
}
```

`inline` secret values are refused unless the operator explicitly enables
`--allow-inline-secrets`; they are not appropriate for a normal produced Manifest.

For dynamic authentication use an `authentication` profile and bind with
`authenticationRef`. Complete tested examples exist for OAuth 2 client credentials,
authorization-code/PKCE refresh, token/session exchange, challenge sessions, OAuth 1.0a and
the supported request-signing strategies; see the example catalogue.

### Upstream authentication is not MCP caller authorization

`credentials`, `authentication`, `credentialRef` and `authenticationRef` describe how
Engine authenticates **outbound** calls to the upstream API. They do not authenticate clients
calling the MCP endpoint.

Inbound MCP authorization is a separate deployment boundary. The Manifest's server/surface
settings state whether a served resource requires authorization and which scopes a surface
requires; the host's `--issuer` and `--token-validation introspection|jwks` settings configure
how caller bearer tokens are verified. Keep the two directions separate when debugging an
authentication refusal.

## 6. Inspect before serving

For a file-mode Manifest:

```bash
dotnet mcpiler-engine.dll inspect \
  --mount /example=./my-api \
  --file-store-root ./data
```

Then serve the same configuration:

```bash
dotnet mcpiler-engine.dll serve \
  --mount /example=./my-api \
  --file-store-root ./data
```

If a Manifest requires caller bearer authorization over HTTP, provide the corresponding host
issuer and token-validation configuration to both `inspect` and `serve`; HTTP inspection
deliberately applies the same host-side authorization startup refusals and exits `78` when the
configuration cannot serve. Stdio uses the local process boundary instead and does not require an
HTTP issuer merely because the Manifest is protected.

Use the diagnostic code, section and JSON pointer from a refusal. The complete stable diagnostic
catalogue is in [`manifest.md`](manifest.md#diagnostics).

## 7. Split a large Manifest into section files

A single-file Manifest and a directory bundle are the same logical format. To move a section out
of the root, replace its `inline` value with a relative `path`:

```text
my-api/
├── manifest.json
└── sections/
    ├── server.json
    ├── policy.json
    ├── operations.json
    └── agentSurface.json
```

Example root entry:

```json
{
  "sections": {
    "server": { "path": "sections/server.json" },
    "policy": { "path": "sections/policy.json" },
    "operations": { "path": "sections/operations.json" },
    "agentSurface": { "path": "sections/agentSurface.json" }
  }
}
```

Paths are bundle-relative and use `/`. Absolute paths, URIs, backslashes and parent traversal
are refused.

The tested [sealed bundle](../tests/fixtures/manifests/sealed-bundle/manifest.json) shows the
same shape with sizes, hashes and a completeness seal.

## 8. Integrity, sealing and transport archives

A hand-written Manifest does not need to be sealed unless the deployment requires it.
`--require-sealed` makes an absent completeness seal a startup refusal.

Engine's library contains the canonical sealing and `.mcpiler-manifest` archive implementation,
but the current standalone host CLI does **not** expose `seal`, `pack` or `unpack` commands
and file mode does not mount a `.mcpiler-manifest` archive directly. Do not infer such commands
or a direct archive mount from the format reference. Studio/generator tooling may produce these
artifacts, managed mode consumes archive deliveries, and third-party tooling can implement the
documented pack/unpack format.

Sealing is integrity metadata, not a signature. Anyone able to change both the bundle and its
digests can produce another internally consistent seal.

## 9. Response transformation

There are two different response-projection layers.

A binding-level projection changes the upstream response body before the agent-facing result is
built:

```json
{
  "type": "transformedHttp",
  "base": { "operation": "GET /search" },
  "outputProjection": {
    "kind": "jmespath",
    "languageVersion": 1,
    "expression": "results[*].{id: id, name: name}",
    "limits": {
      "maxExpressionBytes": 4096,
      "maxInputNodes": 100000,
      "maxInputDepth": 64,
      "maxResultNodes": 8192,
      "maxResultDepth": 32,
      "maxOutputBytes": 262144,
      "maxEvaluationMilliseconds": 10000
    }
  }
}
```

The operation-level `agentSurface.operations[*].outputProjection` builds an agent-facing envelope,
can map response metadata and can expose continuation information. These are distinct members even
though they share the name `outputProjection` at different object levels.

See the JMESPath, transform-program and response-projection/pagination examples in the catalogue.

## 10. Cache eligible read operations

Response caching is opt-in per agent operation:

```json
{
  "slug": "list-pets",
  "name": "List pets",
  "binding": { "type": "http", "operation": "GET /pets" },
  "responseCache": { "ttlSeconds": 300 }
}
```

The effective binding must be a cache-eligible GET. The host-level response-cache settings are
ceilings and may disable or narrow the authored policy. See the complete tested
[response-cache example](../tests/fixtures/manifests/response-cache/manifest.json).

## 11. Add pagination

An operation-level output projection can place the body under one field and derive the next call
from a response header, Link header or JSON body pointer. A simple cursor-header example is:

```json
{
  "outputProjection": {
    "bodyTarget": "/data",
    "pagination": {
      "target": "/pagination",
      "source": {
        "kind": "responseHeader",
        "name": "X-Next-Cursor",
        "scalarType": "string"
      },
      "nextArguments": [
        {
          "target": "/cursor",
          "from": { "kind": "extractedValue" },
          "as": "string"
        }
      ]
    }
  }
}
```

See the complete tested
[response-projection/pagination example](../tests/fixtures/manifests/response-projection-pagination/manifest.json)
for the associated input schema and upstream operation.

## 12. Files

File upload/download semantics are opt-in through binary schemas and the `x-mcp-file`
agent-facing extension. Start from the complete tested
[file example](../tests/fixtures/manifests/files/manifest.json) and read
[`file-handles.md`](file-handles.md) before deploying it.

## 13. Compound workflows

Use a `compound` binding to expose several already-declared agent operations as one tool.
Steps execute sequentially, can read arguments and previous step responses, and are bounded by
the compound policy. The complete tested
[compound example](../tests/fixtures/manifests/compound/manifest.json) covers argument mappings,
step-response mappings, constants and output selection.

## 14. Search and vectors

The lexical `search` section is optional and derivable. The binary `vectors` section is
optional, external-only and is an optimization: an invalid or unusable matrix degrades semantic
ranking rather than making the whole Manifest unservable.

The exact matrix binary layout is documented in
[`manifest.md#vectors`](manifest.md#vectors). A vector matrix is not ordinary JSON and cannot be
inlined into a single-file Manifest. The [vector example](../examples/vectors/README.md) includes
a complete bundle, a committed `vectors.bin` and a dependency-free generator that recreates its
bytes.

## 15. Multiple surfaces and Navigator

Define `server.surfaces` explicitly when the same Manifest needs different MCP views: for
example, a full surface and a read-only surface, or a small direct tool set with additional
operations reachable only through Navigator.

Each surface can independently mark an operation `direct`, `navigator` or `hidden`, can
require caller scopes, and can configure Navigator. Exposure is a routing/authorization decision;
presence in `agentSurface` or `search` does not grant reachability on a surface.

Start from the tested
[multi-surface example](../tests/fixtures/manifests/multi-surface/manifest.json).

## Example catalogue

Use [`examples/README.md`](../examples/README.md) to choose the smallest tested example for the
feature you need. The files it links are part of the Engine test corpus, so an example that stops
loading causes CI to fail.
