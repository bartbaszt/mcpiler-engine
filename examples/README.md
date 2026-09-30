# MCPiler Manifest examples

These examples are the recommended starting points for hand-authored Manifests. Most linked JSON
files live in the Engine fixture corpus instead of being duplicated here: CI loads them with the
real Manifest reader, so an example that stops being a valid/loadable Manifest fails the build.
Host-side serving requirements such as HTTP caller authorization are tested separately. The vector example
is kept here because it also needs a binary payload and a small generator.

For the product-level REST-to-MCP path, start with
[`docs/getting-started.md`](../docs/getting-started.md). For end-to-end deployment/client cases use
[`docs/use-cases/README.md`](../docs/use-cases/README.md). For Manifest mechanics use
[`docs/authoring.md`](../docs/authoring.md), and for the complete field-level contract use
[`docs/manifest.md`](../docs/manifest.md).

A concrete real-application example is
[`use-cases/trilium/`](use-cases/trilium/README.md): Trilium ETAPI remains unchanged while Engine
adds read-only and full MCP surfaces beside it.

| I want to… | Tested example |
| --- | --- |
| serve one simple REST GET | [minimal](../tests/fixtures/manifests/minimal/manifest.json) |
| use direct API keys/basic/header credentials | [credentials](../tests/fixtures/manifests/credentials/manifest.json) |
| use OAuth 2 client credentials | [OAuth 2 client credentials](../tests/fixtures/manifests/manifest-0.3/oauth-client-credentials/manifest.json) |
| use OAuth 2 authorization code + PKCE/refresh | [OAuth 2 authorization code](../tests/fixtures/manifests/manifest-0.3/oauth-authorization-code/manifest.json) |
| use OAuth 1.0a | [OAuth 1.0a](../tests/fixtures/manifests/manifest-0.3/oauth1-authorization/manifest.json) |
| use a managed provider secret | [managed provider](../tests/fixtures/manifests/manifest-0.3/managed-provider/manifest.json) |
| use token/session exchange | [token/session exchange](../tests/fixtures/manifests/manifest-0.3/exchange/manifest.json) |
| use challenge/session authentication | [challenge session](../tests/fixtures/manifests/manifest-0.3/challenge-session/manifest.json) |
| sign requests with AWS SigV4 | [AWS SigV4](../tests/fixtures/manifests/manifest-0.3/request-signing-aws-sigv4/manifest.json) |
| sign requests with generic HMAC | [HMAC signing](../tests/fixtures/manifests/manifest-0.3/request-signing-hmac/manifest.json) |
| sign requests with JWT HMAC | [JWT HMAC signing](../tests/fixtures/manifests/manifest-0.3/request-signing-jwt-hmac/manifest.json) |
| use Subsonic-style MD5 signing | [Subsonic MD5 signing](../tests/fixtures/manifests/manifest-0.3/request-signing-subsonic-md5/manifest.json) |
| rename/map request arguments and response fields | [transform programs](../tests/fixtures/manifests/transformed/manifest.json) |
| select/reshape a response with JMESPath | [JMESPath profile 1](../tests/fixtures/manifests/jmespath-profile-1/manifest.json) |
| cache an eligible GET response | [response cache](../tests/fixtures/manifests/response-cache/manifest.json) |
| expose response metadata and cursor pagination | [response projection + pagination](../tests/fixtures/manifests/response-projection-pagination/manifest.json) |
| combine several calls into one tool | [compound workflow](../tests/fixtures/manifests/compound/manifest.json) |
| upload/download binary files | [files](../tests/fixtures/manifests/files/manifest.json) |
| expose different tool sets on multiple surfaces | [multi-surface](../tests/fixtures/manifests/multi-surface/manifest.json) |
| use local JSON Schema `$ref` | [schema references](../tests/fixtures/manifests/refs/manifest.json) |
| author a lexical Navigator index | [search index](../tests/fixtures/manifests/search/manifest.json) |
| use more than one upstream origin | [two origins](../tests/fixtures/manifests/two-origins/manifest.json) |
| inspect an externally split and sealed bundle | [sealed bundle](../tests/fixtures/manifests/sealed-bundle/manifest.json) |
| add semantic vector ranking | [vectors](vectors/README.md) |

## Which example should I copy?

For a new hand-authored connector, copy **minimal** and add one feature at a time. The minimal
fixture explicitly sets `authenticationRequired: false` so the local tutorial can run without an
issuer; treat that as a demo posture, not as the production security default. For a remotely
reachable HTTP deployment, remove that opt-out (or set it to true) and configure caller
authorization.

Do not start from `compiled`: that fixture is deliberately producer-shaped and contains
provenance and explicit generated values that a human-authored Manifest normally does not need.

Authentication examples intentionally contain placeholder hosts and secret references. Replace
the public identifiers/URLs for your provider, and supply secrets through environment variables,
files, or managed provider values as appropriate. Do not replace those references with literal
production secrets.

The response-projection corpus under `tests/fixtures/response-projection/` and the response-cache
contract under `tests/fixtures/response-cache/` contain additional edge cases and refusal
examples. They are conformance corpora, not recommended copy-and-edit starting documents.
