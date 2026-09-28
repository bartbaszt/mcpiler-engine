# End-to-end use-case cookbook

This cookbook starts from real integration goals rather than from Manifest field names.

If you are new to MCPiler, read [getting-started.md](../getting-started.md) first. If you already
know the desired integration, choose the closest case below and then follow links to the tested
fixture/reference.

The normal loop for every case is:

~~~text
prove REST -> author Manifest -> inspect -> serve -> connect client -> test behavior
~~~

Do not skip the first or third step.

Unless a case explicitly says otherwise, remember two global rules:

1. HTTP mounts are protected by default. A local/demo case that intentionally needs no caller
   authorization must say `"authenticationRequired": false`; a protected HTTP case must pass the
   same `--issuer` / `--token-validation` settings to both `inspect` and `serve`.
2. `inspect` is an exit-code preflight, not merely a report. If a configuration fails one of
   the startup checks that `inspect` performs, it exits `78` while still printing derived
   surfaces/tools. Listener/socket binding itself is not checked because no listener is opened.

# Coverage map

| Area | Covered cases |
| --- | --- |
| Basic REST shapes | 1–4 |
| Static upstream auth | 5–8 |
| Dynamic/signing auth | 9–12 |
| Adapting REST for AI | 13–17 |
| Files/workflows/search | 18–24 |
| Self-hosting/deployment | 25–28 |
| AI clients | 29–33 |
| Platform/operations | 34–36 |
| Real application example | 37 |
| Production hardening and advanced runtime cases | 38–50 |

# 1. Public read-only REST endpoint

**Goal:** expose one GET endpoint as one MCP tool.

REST:

~~~text
GET https://api.example.com/status
~~~

Steps:

1. create a bundle directory with **manifest.json**;
2. set policy baseUrl to the API origin/base path;
3. declare **GET /status** in operations;
4. add one agent operation such as **get-status** with an HTTP binding;
5. run **inspect**;
6. run **serve**;
7. connect a client and ask a question that requires status.

Start from:
[minimal fixture](../../tests/fixtures/manifests/minimal/manifest.json).

Verify that the AI sees only the intended tool and Engine makes exactly one GET.

# 2. Path and query parameters

**Goal:** expose an endpoint such as:

~~~text
GET /customers/{customerId}/orders?limit=20&state=open
~~~

Steps:

1. declare customerId as a required path parameter;
2. declare limit/state as query parameters with useful schema bounds/enums;
3. give the agent operation an input schema with the same user-facing values;
4. bind directly when names already match;
5. inspect and call with multiple combinations;
6. verify URL encoding and omitted optional parameters upstream.

If the upstream names are poor for an AI, continue with case 13 instead of exposing them verbatim.

# 3. JSON POST/create operation

**Goal:** turn a normal JSON create endpoint into a write tool.

REST:

~~~text
POST /tickets
Content-Type: application/json
~~~

Steps:

1. describe the JSON requestBody in operations;
2. create an agent input schema containing only fields the model should choose;
3. mark annotations/risk as mutating and non-idempotent when appropriate;
4. bind to the POST operation;
5. inspect;
6. test against a non-production upstream first;
7. confirm exactly one ticket is created.

Use the body patterns in:
[compound fixture](../../tests/fixtures/manifests/compound/manifest.json).

Do not rely on the client's confirmation dialog to prevent duplicate writes. Correct idempotency semantics belong in the tool contract.

# 4. Full CRUD API

**Goal:** expose read, create, update and delete safely.

Steps:

1. model GET/list/get first;
2. add POST/create;
3. add PUT/PATCH update with accurate idempotency;
4. add DELETE last and mark destructive;
5. consider separate read-only and full-access surfaces;
6. test each REST side effect independently;
7. connect a client and check whether it surfaces confirmations for writes;
8. verify destructive tools are not accidentally visible on the read-only surface.

Use:
[multi-surface fixture](../../tests/fixtures/manifests/multi-surface/manifest.json).

# 5. Upstream API key in a header

**Goal:** REST uses X-Api-Key.

Steps:

1. declare a credential with scheme **apiKey**;
2. set slot to the real header name;
3. set location to header;
4. resolve value from an environment variable or file;
5. reference the credential from only the bindings that need it;
6. inspect with the secret present;
7. call the tool and verify upstream authentication.

Use:
[credential fixture](../../tests/fixtures/manifests/credentials/manifest.json).

# 6. Upstream bearer token

**Goal:** REST uses Authorization: Bearer TOKEN.

Steps:

1. declare a bearer credential;
2. set slot to Authorization;
3. store only the token value in the env/file source;
4. reference it from the relevant bindings;
5. inspect;
6. invoke and verify upstream receives a Bearer header.

Engine adds the Bearer scheme prefix itself.

This is the usual shape for self-hosted APIs such as modern Trilium ETAPI.

# 7. Upstream Basic authentication

**Goal:** REST requires username/password Basic auth.

Steps:

1. declare the username half with scheme basic / slot username;
2. declare the password half with scheme basic / slot password;
3. reference both from the same binding;
4. keep the password in a file/secret source;
5. inspect;
6. test a request.

Engine refuses an incomplete Basic pair rather than sending a malformed header.

Use:
[credential fixture](../../tests/fixtures/manifests/credentials/manifest.json).

# 8. API keys in query, cookie or custom header

**Goal:** integrate an older/vendor-specific API.

Steps:

1. choose scheme apiKey for query/cookie or header for a plain custom header;
2. set the exact destination slot;
3. resolve the secret from env/file;
4. reference it only from the operations requiring it;
5. inspect for destination collisions;
6. test redirects to ensure secrets do not leave the permitted origin.

Use:
[credential fixture](../../tests/fixtures/manifests/credentials/manifest.json).

# 9. OAuth 2 client credentials

**Goal:** Engine authenticates machine-to-machine and obtains access tokens itself.

Steps:

1. declare client-id/client-secret credentials;
2. declare an OAuth 2 client-credentials authentication profile;
3. configure token endpoint/origins/scopes required by that profile;
4. reference the profile with authenticationRef from the binding;
5. inspect with the secret available;
6. invoke twice and verify token caching/reuse semantics rather than minting unnecessarily;
7. test token expiry/refresh behavior.

Use:
[OAuth client-credentials fixture](../../tests/fixtures/manifests/manifest-0.3/oauth-client-credentials/manifest.json).

# 10. OAuth 2 authorization code + PKCE + refresh rotation

**Goal:** the upstream identity belongs to a user and refresh tokens rotate.

Steps:

1. model the authorization-code profile and slots;
2. provide the initial/provider credential material through the supported source;
3. configure durable runtime state before serving a mutable slot;
4. inspect with runtime-state root and key file;
5. complete the initial authorization/bootstrap flow required by your producer/deployment;
6. invoke until a refresh occurs;
7. verify the new refresh token is durably committed;
8. restart Engine and verify the rotated value survives.

Use:
[OAuth authorization-code fixture](../../tests/fixtures/manifests/manifest-0.3/oauth-authorization-code/manifest.json).

See [hosting.md](../hosting.md) for the runtime-state store.

# 11. OAuth 1.0a API

**Goal:** integrate a legacy OAuth 1 API without implementing signing in the application.

Steps:

1. choose the required signature method;
2. declare the exact required credential slots;
3. configure parameter transport;
4. bind through an oauth1-authorization profile;
5. inspect;
6. compare one signed request with the provider's canonical example;
7. verify nonce/timestamp behavior under retries.

Use:
[OAuth 1 fixture](../../tests/fixtures/manifests/manifest-0.3/oauth1-authorization/manifest.json).

# 12. Signed requests: AWS SigV4, HMAC, JWT-HMAC, Subsonic MD5

**Goal:** authenticate each outbound request by signature rather than bearer/API key.

Steps:

1. select the signer matching the provider;
2. declare only its required secret/key inputs;
3. declare the allowed signing/destination origins;
4. bind the profile to operations;
5. inspect;
6. test known canonical requests;
7. test redirect/destination behavior;
8. confirm signatures are recomputed for the actual outgoing hop.

Use one of:

- [AWS SigV4](../../tests/fixtures/manifests/manifest-0.3/request-signing-aws-sigv4/manifest.json)
- [generic HMAC](../../tests/fixtures/manifests/manifest-0.3/request-signing-hmac/manifest.json)
- [JWT HMAC](../../tests/fixtures/manifests/manifest-0.3/request-signing-jwt-hmac/manifest.json)
- [Subsonic MD5](../../tests/fixtures/manifests/manifest-0.3/request-signing-subsonic-md5/manifest.json)

# 13. REST argument names are bad for AI

**Goal:** upstream expects q, page_size and X-Api-Version, while the AI should see term and limit.

Steps:

1. describe the upstream operation exactly as it really exists;
2. define a clean agent input schema;
3. use transformedHttp;
4. copy term -> query/q;
5. copy limit -> query/page_size;
6. set implementation-only headers as constants;
7. inspect;
8. compare the final upstream request with the original REST contract.

Use:
[transformed fixture](../../tests/fixtures/manifests/transformed/manifest.json).

# 14. REST response is noisy or internal

**Goal:** the API returns 50 fields but the model needs 5.

Steps:

1. preserve the real upstream response schema;
2. decide whether a transform program or JMESPath is the simpler projection;
3. build a binding-level outputProjection;
4. explicitly bound output work and output bytes;
5. inspect;
6. invoke with typical and worst-case responses;
7. verify internal fields are absent from the tool result.

Use:
[transformed fixture](../../tests/fixtures/manifests/transformed/manifest.json).

# 15. Select/reshape JSON with JMESPath

**Goal:** declaratively extract a useful subset from JSON.

Steps:

1. choose transformedHttp;
2. set outputProjection kind jmespath;
3. set languageVersion 1;
4. provide all seven positive limits;
5. ensure limits fit under policy.jmesPathCeiling;
6. inspect so the confined validation path accepts the expression;
7. invoke;
8. verify projection failure does not fall back to raw upstream data.

Use:
[JMESPath fixture](../../tests/fixtures/manifests/jmespath-profile-1/manifest.json).

# 16. Paginated REST API

**Goal:** let the agent continue through cursor/header/body pagination without inventing parameters.

Steps:

1. model the current-page input;
2. describe the upstream response;
3. use operation-level outputProjection;
4. choose pagination source: response header, Link header or JSON pointer;
5. map the extracted next value into nextArguments;
6. ensure the target operation input schema accepts those arguments;
7. inspect;
8. call page one and verify the projected continuation;
9. call the continuation and verify page two.

Use:
[response projection + pagination fixture](../../tests/fixtures/manifests/response-projection-pagination/manifest.json).

# 17. Cache expensive read-only GETs

**Goal:** reduce repeated identical upstream reads.

Steps:

1. start with a correct GET/HEAD tool;
2. add responseCache.ttlSeconds;
3. configure host ceilings if defaults are not suitable;
4. inspect;
5. invoke twice under the same caller/authority;
6. verify the second request can use the cache;
7. repeat with a different authority/caller partition and verify isolation;
8. use the operator endpoint only if you intentionally configure its separate secret.

Use:
[response-cache fixture](../../tests/fixtures/manifests/response-cache/manifest.json).

# 18. Download a binary file

**Goal:** REST returns PDF/image/archive bytes.

Steps:

1. describe the binary media type and binary response schema;
2. set file policy bounds;
3. expose the operation as read-only;
4. run Engine with a writable file-store root;
5. invoke;
6. verify the MCP result contains a bounded file handle rather than unbounded inline bytes;
7. redeem the handle using the documented child transfer endpoint;
8. test expiry/authorization.

Use:
[file fixture](../../tests/fixtures/manifests/files/manifest.json)
and [file-handles.md](../file-handles.md).

# 19. Upload/replace a binary file

**Goal:** AI client supplies file content to a REST multipart/raw-body endpoint.

Steps:

1. describe multipart/form-data or raw binary requestBody;
2. mark the agent input property with the MCP file extension used by Engine;
3. restrict accepted media types when possible;
4. set upload size/magic policy;
5. inspect;
6. issue/upload a handle through the Engine file-transfer surface;
7. invoke the tool using that handle;
8. verify the correct upstream bytes and metadata.

Use:
[file fixture](../../tests/fixtures/manifests/files/manifest.json).

# 20. One user intent requires several REST calls

**Goal:** "place order" means create cart -> add item -> checkout.

Steps:

1. expose/test each primitive operation first;
2. create a compound agent operation;
3. map user arguments into step one;
4. map earlier response fields into later steps;
5. set workflow timeout/response bounds;
6. choose failFast behavior;
7. select only the final useful output;
8. inspect;
9. invoke and verify call order and side effects.

Use:
[compound fixture](../../tests/fixtures/manifests/compound/manifest.json).

# 21. Very large API: do not advertise hundreds of tools

**Goal:** make a 100+ operation REST API usable without flooding client context.

Steps:

1. choose a small set of direct high-value operations;
2. mark long-tail operations navigator instead of direct;
3. enable Navigator on the surface;
4. add useful operation names, summaries, aliases, keywords and example intents;
5. let Engine derive search unless you intentionally pin it;
6. inspect the direct tool set;
7. connect the target client;
8. test discovery queries for long-tail operations;
9. adjust metadata before increasing direct-tool count.

Use:
[search fixture](../../tests/fixtures/manifests/search/manifest.json)
and
[multi-surface fixture](../../tests/fixtures/manifests/multi-surface/manifest.json).

# 22. Read-only and full-access views of one API

**Goal:** one REST integration, two MCP audiences.

Steps:

1. define all agent operations once;
2. declare a read-only surface exposing only safe operations;
3. declare a full/default surface exposing writes as needed;
4. hide destructive operations from read-only;
5. optionally require scopes on one surface;
6. inspect both surface addresses;
7. test tool listing on each;
8. test that hidden operations cannot be invoked by name.

Use:
[multi-surface fixture](../../tests/fixtures/manifests/multi-surface/manifest.json).

# 23. API calls more than one upstream origin

**Goal:** one integration legitimately calls API and regional/object endpoints.

Steps:

1. set baseUrl;
2. declare every additional allowed origin explicitly;
3. use operation/server overrides only where required;
4. ensure credential/auth profiles permit only the required origins;
5. inspect;
6. invoke each origin;
7. test an undeclared origin and confirm refusal.

Use:
[two-origins fixture](../../tests/fixtures/manifests/two-origins/manifest.json).

# 24. Semantic ranking with vectors

**Goal:** improve Navigator ranking beyond lexical matching.

Steps:

1. make lexical search work first;
2. choose one embedding model;
3. generate one vector per served operation in lexical-index order;
4. build the MVMX v1 payload;
5. declare model/dimension/path/hash/bytes;
6. inspect;
7. call discovery with a query vector from the same model/dimension;
8. verify ranking;
9. corrupt or mismatch the matrix and verify safe lexical fallback.

Use:
[vector example](../../examples/vectors/README.md).

# 25. Self-hosted app on the same Docker network

**Goal:** REST stays private; Engine is the adapter.

Steps:

1. place Engine and the app on the same Docker network;
2. use the app's service DNS name in policy baseUrl;
3. inject the app token only into Engine;
4. mount the Manifest read-only;
5. mount /data writable for file handles/runtime state as needed;
6. run inspect before serve;
7. expose only Engine's MCP port;
8. test from a local MCP client.

Then choose cases 29–33 if a cloud/IDE client must connect.

# 26. Publish Engine behind an HTTPS reverse proxy

**Goal:** remote clients use https://mcp.example.com/app while Engine listens privately.

Steps:

1. run Engine on a private listen address;
2. proxy the exact public mount/surface path **without prefix stripping or path rewriting**; preserve the path Engine sees;
3. configure --trusted-proxy with only the proxy's actual source IP;
4. configure --allowed-host with the exact public host[:port] preserved by the proxy;
5. configure browser allowed origins only when needed;
6. keep health endpoints available to the orchestrator as appropriate;
7. test protected-resource metadata/auth;
8. test a complete MCP initialization and tool call through the proxy;
9. verify direct untrusted forwarded headers are ignored.

See:
[hosting.md](../hosting.md#proxy-deployments).

# 27. One Engine process for several self-hosted applications

**Goal:** expose /trilium, /homebox, /inventory from one listener.

Steps:

1. build one independent Manifest bundle per application;
2. give every app a unique mount prefix;
3. keep credentials separate by env/file names;
4. inspect all mounts together;
5. serve all mounts;
6. connect clients to the exact desired prefix;
7. test that tools/data do not cross mount boundaries;
8. monitor process-wide resource ceilings.

For stronger failure/security isolation, run separate Engine processes instead. Multi-mount is a
convenience, not a requirement.

# 28. Local MCP only: no HTTP listener

**Goal:** an IDE client launches Engine directly.

Steps:

1. narrow configuration to exactly one mount and one surface;
2. use --transport stdio;
3. configure the client command/args;
4. inject upstream secrets into the spawned process;
5. start a fresh client session;
6. list tools;
7. invoke one read and one allowed write;
8. verify stdout remains protocol-only.

See [clients.md](../clients.md) for Cursor and VS Code examples.

# 29. ChatGPT with a public HTTPS Engine

**Goal:** use an Engine surface as a ChatGPT custom MCP app.

Steps:

1. complete the REST/Manifest integration locally;
2. expose the Engine surface over HTTPS;
3. decide/configure MCP caller auth;
4. verify the endpoint from outside the private LAN;
5. follow the current ChatGPT custom-app/developer-mode setup;
6. enter the exact Engine surface URL;
7. authenticate if required;
8. scan/refresh tools;
9. test a read-only prompt;
10. test write operations only if the ChatGPT plan/workspace currently permits them.

Use the dated requirements in [clients.md](../clients.md), not an old screenshot/blog post.

# 30. ChatGPT with a private/on-premises Engine

**Goal:** use ChatGPT without making the private MCP server generally public.

Steps:

1. keep the REST app private;
2. keep Engine private;
3. verify Engine locally;
4. use OpenAI's current Secure MCP Tunnel path;
5. connect the custom app through that path;
6. scan tools;
7. test reads;
8. validate write permissions/confirmations before enabling mutating tools.

Do not expose the upstream REST service as the workaround.

# 31. Claude remote custom connector

**Goal:** connect Claude to an Engine HTTPS surface.

Steps:

1. finish and inspect the Manifest;
2. expose Engine through an address reachable from Anthropic infrastructure;
3. configure caller auth/OAuth if required;
4. add a custom remote/web connector in Claude;
5. enter the Engine URL;
6. connect/authorize;
7. enable the connector for a conversation;
8. test reads, then writes.

For a server that must remain local, use Claude Desktop's current local-extension mechanism rather
than assuming the remote connector originates from the desktop computer.

See [clients.md](../clients.md).

# 32. Cursor: local or remote

**Goal:** make REST-backed tools available to coding agents in Cursor.

Local:

1. configure Engine as a stdio server in Cursor MCP config;
2. pass absolute Manifest/data paths;
3. inherit/inject upstream secrets;
4. restart/reload the MCP server;
5. inspect tool list and invoke.

Remote:

1. serve Engine via Streamable HTTP;
2. add the URL to Cursor MCP config;
3. configure OAuth if the surface is protected;
4. test tool discovery;
5. check whether the session is local or a Cursor cloud-agent context before assuming private URLs
   are reachable.

See [clients.md](../clients.md).

# 33. VS Code / GitHub Copilot: local or remote

**Goal:** expose the API to VS Code agent chat.

Local:

1. add a stdio server to workspace/user MCP configuration;
2. point command/args at Engine;
3. keep secrets in VS Code inputs/env files/environment rather than source control;
4. start/enable the server;
5. enable its tools in chat;
6. test.

Remote:

1. add an HTTP server definition;
2. use the Engine surface URL;
3. configure OAuth/headers through supported VS Code mechanisms;
4. test from the actual Agent Host context you intend to use.

See [clients.md](../clients.md).

# 34. Managed mode with MCPiler Platform

**Goal:** the runtime remains Engine, but desired generations are delivered centrally.

Steps:

1. provision deployment identity/secret;
2. configure --mode managed and management endpoint;
3. configure file/runtime-state stores;
4. start Engine;
5. wait for bounded initial synchronization;
6. verify a desired generation activates before readiness/listener behavior is considered healthy;
7. publish a replacement generation;
8. verify atomic activation;
9. deliberately deliver an invalid candidate and verify the previous generation keeps serving;
10. test Platform outage and verify last active generation continues serving.

See [hosting.md](../hosting.md#managed-mode) and [architecture.md](../architecture.md).

# 35. Upgrade Engine without discovering incompatibility in production

**Goal:** move from one Engine release to another safely.

Steps:

1. read the target release's compatibility matrix;
2. compare section versions, not just root Manifest 0.3;
3. run the target binary's version;
4. run target inspect against every bundle with production-equivalent settings;
5. re-export producer-owned Manifests when required;
6. test runtime-state/file-store permissions with the target image;
7. deploy to staging;
8. verify health and representative auth/write/file paths;
9. deploy production;
10. keep the previous artifact available for rollback when the storage contract permits it.

See [compatibility.md](../compatibility.md).

# 36. CI gate for hand-authored Manifests

**Goal:** reject invalid Manifest changes before deployment.

Steps:

1. keep bundle directories in your deployment/config repository;
2. obtain the same Engine version used in production;
3. run inspect for each bundle in CI;
4. inject only synthetic/test secrets needed for reference resolution;
5. fail CI on non-zero exit;
6. optionally validate published JSON Schema for editor-quality feedback;
7. treat Engine inspect as the semantic authority;
8. run a small integration smoke test against a mock/staging REST API.

Pin Engine version in CI. A moving latest tag turns validation into a compatibility lottery.

# 37. Real self-hosted example: Trilium Notes ETAPI

**Goal:** connect AI tools to a self-hosted Trilium instance without modifying Trilium.

The current Trilium external API provides token-authenticated operations including note search,
note retrieval, note content, create/update/delete and export/import.

A complete MCPiler example is maintained in:
[examples/use-cases/trilium](../../examples/use-cases/trilium/README.md).

Recommended rollout:

1. create an ETAPI token in Trilium;
2. prove GET /etapi/app-info;
3. deploy the provided Manifest beside Trilium;
4. provide TRILIUM_ETAPI_TOKEN to Engine;
5. inspect;
6. serve /trilium;
7. connect a local client;
8. test search/get/content;
9. connect the desired remote client if needed;
10. only then enable/test the example's create/delete operations.

The example uses Bearer token syntax supported by current Trilium ETAPI.

# 38. Production read-only rollout before writes

**Goal:** reduce risk when introducing AI access to an existing production system.

Steps:

1. create a read-only surface;
2. expose list/search/get operations only;
3. deploy to a small client/user group;
4. review tool selection and result quality;
5. add idempotent writes;
6. add ordinary writes;
7. add destructive tools only to a separate/full surface;
8. require caller scopes when multiple authorization levels exist;
9. record expected side effects in integration tests.

This rollout pattern is often more important than adding every API feature immediately.

# 39. Per-caller scopes on an MCP endpoint

**Goal:** two MCP users may reach the same Engine, but one must not see privileged tools.

Steps:

1. configure inbound issuer/token validation on the host;
2. declare authenticationRequired on the server when appropriate;
3. define surfaces with requiredScopes;
4. place privileged operations only on the privileged surface;
5. expose separate resource URLs;
6. connect clients with tokens containing the intended audience/scopes;
7. verify tool listing;
8. verify direct invocation of an unauthorized/hidden tool does not bypass exposure.

Do not use upstream API credentials as a substitute for MCP caller authorization.

# 40. Diagnose "it works in REST but not in AI"

**Goal:** isolate the failing layer quickly.

Follow this order:

1. **REST:** reproduce the exact upstream call with curl/Postman from Engine's network;
2. **Manifest:** run inspect and resolve every diagnostic;
3. **Engine HTTP/stdio:** reconnect a simple MCP client and list tools;
4. **client networking:** determine whether the connection originates locally or from vendor cloud;
5. **caller auth:** distinguish client->Engine auth from Engine->REST auth;
6. **tool cache:** refresh/restart the client after Manifest changes;
7. **invocation:** compare model arguments with the declared input schema;
8. **upstream:** compare Engine's intended request shape with the REST contract;
9. **projection/files:** test response conversion separately;
10. **write side effect:** verify the upstream mutation, not merely the MCP success text.

Use [troubleshooting.md](../troubleshooting.md) for diagnostic-specific branches.

# 41. Token/session exchange authentication

**Goal:** the upstream requires exchanging one credential/token for a short-lived session/token before normal API calls.

Steps:

1. declare the source credentials used for the exchange;
2. declare a token-session-exchange authentication profile;
3. define the exchange endpoint, origins and extraction rules;
4. bind operations through authenticationRef;
5. inspect;
6. invoke a first call and verify one exchange occurs;
7. invoke subsequent calls and verify bounded reuse/caching behavior;
8. test expiry/failure and ensure the original credential is not leaked into tool output.

Use:
[token/session exchange fixture](../../tests/fixtures/manifests/manifest-0.3/exchange/manifest.json).

# 42. Challenge/session login flow

**Goal:** the API establishes a session only after a challenge/login sequence.

Steps:

1. model the required credentials;
2. declare a challenge-session authentication profile;
3. define the challenge/login request and extraction rules;
4. restrict the authentication origins;
5. inspect;
6. invoke a tool and verify session establishment;
7. invoke again and verify bounded session reuse;
8. test invalid/expired challenge behavior.

Use:
[challenge-session fixture](../../tests/fixtures/manifests/manifest-0.3/challenge-session/manifest.json).

# 43. Managed provider secret

**Goal:** Platform delivers a secret reference/value with the managed generation rather than the file-mode host resolving it.

Steps:

1. use managed mode;
2. declare the credential as fromProvider using the managed provider key;
3. reference it from the intended binding/profile;
4. publish the desired generation through the management channel;
5. let Engine perform initial synchronization;
6. verify the generation loads with the provider value;
7. rotate/change the provider value through the managed authority;
8. verify a new generation activates without putting the secret in the Manifest.

File mode intentionally refuses fromProvider. There is no standalone CLI flag to enable it.

Use:
[managed-provider fixture](../../tests/fixtures/manifests/manifest-0.3/managed-provider/manifest.json).

# 44. Plain text or HTML REST response

**Goal:** the upstream is REST/HTTP but does not return JSON.

Steps:

1. declare the real text media type in the operation response;
2. use a string schema;
3. expose the operation as a normal tool;
4. inspect;
5. invoke representative HTML/text content;
6. confirm size bounds are appropriate;
7. if the payload is too noisy for the model, add a supported projection only where the projection
   path accepts the media type/shape; otherwise change the upstream-facing operation/tool design.

The Trilium example includes note-content text/HTML response media types.

# 45. Redirecting REST API and secret containment

**Goal:** the API legitimately redirects, but credentials must not escape to an unrelated origin.

Steps:

1. declare the intended base/allowed origins;
2. configure a bounded redirect-hop limit;
3. attach credentials only to the bindings that need them;
4. inspect;
5. test an allowed same/permitted-origin redirect;
6. test a redirect to an undeclared origin;
7. verify Engine refuses/strips according to the documented containment rules rather than blindly
   forwarding sensitive headers.

This is a security test, not only a functional redirect test.

# 46. Slow or large upstream API

**Goal:** prevent one bad/slow endpoint from consuming the Engine indefinitely.

Steps:

1. measure normal upstream connect/request latency and response sizes;
2. set/narrow policy limits for connect timeout, request timeout and response bytes;
3. set a realistic concurrency bound;
4. inspect;
5. test typical load;
6. test an intentionally slow response;
7. test a response over the byte ceiling;
8. verify failures are bounded and do not destabilize unrelated mounts/tools.

Host configuration may narrow Manifest ceilings but must not widen them.

# 47. Browser-origin MCP client

**Goal:** a browser-based MCP client reaches Streamable HTTP without turning CORS/origin handling into a wildcard.

Steps:

1. identify the exact browser origin;
2. add one --allowed-origin value for that canonical origin;
3. do not add paths, queries, credentials or wildcards;
4. keep non-browser clients unchanged;
5. connect through the browser client;
6. test an unlisted Origin and confirm refusal;
7. test health/protected-resource discovery separately from served product routes.

See [hosting.md](../hosting.md#browser-origins).

# 48. Split and sealed production bundle

**Goal:** move from a hand-authored single file to an integrity-pinned multi-file artifact.

Steps:

1. split large sections into bundle-relative files;
2. replace inline entries with path entries;
3. run inspect;
4. produce hashes/byte sizes with tooling implementing the canonical sealing contract;
5. add completeness metadata;
6. inspect with --require-sealed;
7. deploy the entire bundle atomically;
8. modify one byte and verify the bundle is refused.

Remember: sealing is integrity metadata, not a cryptographic signature against an attacker who can
rewrite both content and hashes.

Use:
[sealed-bundle fixture](../../tests/fixtures/manifests/sealed-bundle/manifest.json).

# 49. Operate the response cache without exposing bodies

**Goal:** diagnose/clear cached read results in production.

Steps:

1. enable response caching on eligible operations;
2. configure a dedicated --response-cache-operator-secret-file;
3. use HTTPS remotely or genuine loopback HTTP;
4. query the operator observation endpoint for one mount;
5. inspect sanitized metadata rather than response bodies;
6. clear the mount or one operation when necessary;
7. verify an in-flight producer is not cancelled by clear;
8. keep the operator secret distinct from REST credentials, caller tokens and managed deployment
   secrets.

See [hosting.md](../hosting.md#response-cache-operator-channel).

# 50. Reuse local JSON Schema definitions with fragment refs

**Goal:** avoid duplicating a complex schema throughout one Manifest section.

Steps:

1. define the reusable schema/component in the supported local document location;
2. reference it with a local/fragment-only $ref supported by the Manifest contract;
3. keep the reference within the bundle/document boundary;
4. inspect;
5. test recursive/depth/node bounds where relevant;
6. verify no remote URL resolution is attempted.

Use:
[schema-reference fixture](../../tests/fixtures/manifests/refs/manifest.json).

# Selecting the closest recipe

| What you have | Start with |
| --- | --- |
| one public GET | 1 |
| normal JSON create/update | 3–4 |
| API key/token | 5–8 |
| OAuth/signature | 9–12 |
| ugly REST contract | 13–15 |
| pagination | 16 |
| repeated reads | 17 |
| binary API | 18–19 |
| multi-call workflow | 20 |
| huge API | 21 |
| different user access levels | 22 / 39 |
| several origins | 23 |
| semantic discovery | 24 |
| Docker self-hosting | 25 |
| public reverse proxy | 26 |
| several apps | 27 |
| local IDE | 28 / 32 / 33 |
| ChatGPT | 29–30 |
| Claude | 31 |
| managed Platform | 34 |
| upgrade/CI | 35–36 |
| Trilium | 37 |
| production safety rollout | 38 |
| debugging | 40 |
| exchange/challenge/managed secrets | 41–43 |
| text, redirects and operational bounds | 44–46 |
| browser Origin / sealed bundles / cache ops / schema refs | 47–50 |

# What is intentionally not duplicated here

This cookbook gives the operational sequence. It does not duplicate:

- every Manifest field: [manifest.md](../manifest.md);
- detailed authoring semantics: [authoring.md](../authoring.md);
- client UI/plan details: [clients.md](../clients.md);
- host option reference: [hosting.md](../hosting.md);
- failure branches: [troubleshooting.md](../troubleshooting.md);
- release/section matrices: [compatibility.md](../compatibility.md).

That separation keeps scenario docs readable while the reference documents remain authoritative.
