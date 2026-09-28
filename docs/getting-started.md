# Getting started: turn an existing REST API into MCP

MCPiler Engine is for the case where the useful backend already exists.

You have an application with a REST API. You want ChatGPT, Claude, Cursor, VS Code or another MCP
client to use selected operations from that API. You do **not** want to add an MCP SDK, MCP routes,
session handling, protocol negotiation, tool discovery, argument validation, credential plumbing,
file-transfer handling or MCP-specific error shapes to the application itself.

MCPiler keeps those concerns outside the application:

~~~text
                         existing REST/HTTP
AI / MCP client  --->  MCPiler Engine  --->  your application
      MCP               manifest.json         unchanged
~~~

The minimum deployment is:

1. choose the REST operations the AI should be allowed to use;
2. describe them in **manifest.json**;
3. run **inspect**;
4. run MCPiler Engine;
5. connect a compatible MCP client to the Engine endpoint.

Your application stays a REST application.

For field-by-field Manifest details use [manifest.md](manifest.md). For feature-oriented authoring
use [authoring.md](authoring.md). For complete scenarios use
[use-cases/README.md](use-cases/README.md). For client-specific connection steps use
[clients.md](clients.md). If you are still deciding between MCPiler and another gateway/framework,
read [alternatives.md](alternatives.md).

## Two common starting points

### I own the REST API

Before MCPiler:

~~~text
ChatGPT / Claude / IDE agent
        X
        |
        | no MCP interface
        |
my-product.example/api
        REST
~~~

With MCPiler:

~~~text
ChatGPT / Claude / IDE agent
             |
             | MCP
             v
     MCPiler Engine
             |
             | ordinary REST
             v
my-product.example/api
~~~

You do not have to change the application's controller/router layer.

### I self-host an application that already has a REST API

Typical topology:

~~~text
                    Docker / private network
               +------------------------------+
               |                              |
               |  MCPiler Engine  ----------> |  self-hosted application
               |       ^          REST        |  (Trilium, Homebox, ...)
               +-------|----------------------+
                       |
                    MCP / HTTPS
                       |
                  AI client
~~~

Engine can run beside the application. The upstream REST API does not need to be public; only
Engine needs to reach it.

Whether the **MCP endpoint** must be remotely reachable depends on the client. ChatGPT currently
connects to remote MCP servers and documents Secure MCP Tunnel for private/local servers. Cursor
and VS Code can also launch a local Engine process over stdio. See [clients.md](clients.md).

## What MCPiler solves

Given a Manifest, Engine owns the repetitive MCP/runtime work:

- MCP initialization, framing and protocol negotiation through the MCP SDK;
- tool discovery and tool definitions;
- conversion of MCP tool arguments into deterministic REST requests;
- path, query, header, cookie and body serialization;
- JSON and multipart request bodies;
- response bounds and structured results;
- API-key, Basic, bearer, OAuth, token-exchange, challenge/session and signing strategies;
- outbound origin containment and redirect handling;
- local stdio and remote Streamable HTTP transport;
- optional caller authorization for the MCP endpoint;
- pagination metadata;
- input/output transformations and JMESPath projections;
- response caching;
- binary upload/download through bounded file handles;
- multi-step compound tools;
- large-tool-set discovery through Navigator;
- multiple independent API mounts in one Engine process;
- diagnostics, preflight inspection, health checks and graceful shutdown.

Engine does not import OpenAPI, Postman or cURL descriptions at runtime. A human may author a
Manifest directly; producer tooling such as MCPiler Studio may generate one. Engine consumes the
resulting Manifest.

# Path A: I own the REST API

Assume the application already exposes:

~~~text
GET https://api.example.com/v1/projects/{projectId}
~~~

and you want the AI-facing operation:

~~~text
get-project(projectId)
~~~

## Step 1 — choose the first operation

Do not expose the entire API simply because it exists. Start with one read-only operation for
which you can answer:

- what should the tool be called?
- when should an AI use it?
- what arguments should the model control?
- is it read-only, mutating or destructive?
- which upstream identity should execute it?
- what part of the response is useful to the model?

## Step 2 — create the bundle

~~~text
my-api/
└── manifest.json
~~~

A minimal Manifest:

~~~json
{
  "manifestFormatVersion": "0.3",
  "sections": {
    "server": {
      "inline": {
        "name": "Example Projects",
        "authenticationRequired": false
      }
    },
    "policy": {
      "inline": { "baseUrl": "https://api.example.com/v1" }
    },
    "operations": {
      "inline": {
        "operations": [
          {
            "key": "GET /projects/{projectId}",
            "method": "GET",
            "path": "/projects/{projectId}",
            "parameters": [
              {
                "name": "projectId",
                "in": "path",
                "required": true,
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
        ]
      }
    },
    "agentSurface": {
      "inline": {
        "operations": [
          {
            "slug": "get-project",
            "name": "Get project",
            "summary": "Gets one project by identifier",
            "inputSchema": {
              "type": "object",
              "required": ["projectId"],
              "properties": {
                "projectId": { "type": "string" }
              }
            },
            "annotations": {
              "readOnly": true,
              "destructive": false,
              "idempotent": true,
              "openWorld": true
            },
            "binding": {
              "type": "http",
              "operation": "GET /projects/{projectId}"
            }
          }
        ]
      }
    }
  }
}
~~~

There is no MCP implementation code in the existing application.

This first Manifest is deliberately **open for a local demo**: `authenticationRequired: false`
is an explicit opt-out. The format default is the opposite — if the member is absent, the mount is
protected and HTTP `inspect`/`serve` require a configured `--issuer` and
`--token-validation`. Do not expose this demo-open surface to an untrusted network.

## Step 3 — preflight it

~~~bash
dotnet mcpiler-engine.dll inspect \
  --mount /projects=./my-api \
  --file-store-root ./data
~~~

**inspect** uses the same Manifest loading, semantic validation, policy narrowing and host-side
startup authorization checks as the corresponding HTTP **serve** configuration, but opens no
listener. If that exact HTTP configuration is unstartable, `inspect` returns exit code `78`
while still printing the derived surfaces/tools for diagnosis.

Do not replace this with "the JSON parses" or "the JSON Schema is green." Cross-section
references and security rules are reader/runtime rules.

## Step 4 — serve it

~~~bash
dotnet mcpiler-engine.dll serve \
  --mount /projects=./my-api \
  --file-store-root ./data \
  --listen http://127.0.0.1:8080
~~~

The default surface is now available at:

~~~text
http://localhost:8080/projects
~~~

That URL is an MCP Streamable HTTP endpoint, not another REST API for humans.

## Step 5 — connect a client

For a client that can reach localhost, use that URL or use Engine's stdio transport.

For a cloud-hosted AI client, **do not publish the demo-open configuration above**. Change the
Manifest to `"authenticationRequired": true` (or remove the explicit false), configure the
HTTP host with a real issuer and token-validation mode, and then expose that protected Engine
surface through HTTPS/reverse proxy/tunnel. For example, the serving configuration will also
contain settings of this form:

~~~bash
--issuer https://idp.example.com --token-validation jwks
~~~

where the issuer is your actual OAuth/OIDC authority. The resulting public resource might be:

~~~text
https://mcp.example.com/projects
~~~

Use [clients.md](clients.md) for ChatGPT, Claude, Cursor and VS Code instructions.

## Step 6 — test behavior, not only connectivity

Ask something that should require the tool:

~~~text
Show me project PRJ-123.
~~~

Verify:

1. the client discovers **get-project**;
2. it supplies projectId=PRJ-123;
3. Engine sends GET /v1/projects/PRJ-123 upstream;
4. the result is useful to the model;
5. no additional REST operation became reachable.

Then add the next operation.

# Path B: I self-host an application

Assume:

- the application runs at http://trilium:8080 inside a Docker network;
- its API requires a token;
- you want an MCP client to search/read notes.

## Step 1 — prove the REST API first

Test from the same network namespace in which Engine will run.

For Trilium:

~~~bash
curl http://trilium:8080/etapi/app-info \
  -H "Authorization: Bearer $TRILIUM_ETAPI_TOKEN"
~~~

If REST networking/authentication fails, fix that first. MCPiler cannot make an unreachable API
reachable.

## Step 2 — choose a narrow first surface

For a notes application, start with:

- search notes;
- get note metadata;
- read note content.

Do not start by exposing delete, backup, import and every administrative endpoint.

## Step 3 — model the upstream secret

The upstream token belongs to Engine's outbound request, not to the MCP caller-auth boundary.

~~~json
{
  "credentials": {
    "inline": {
      "credentials": [
        {
          "id": "trilium-token",
          "scheme": "bearer",
          "slot": "Authorization",
          "value": { "fromEnv": "TRILIUM_ETAPI_TOKEN" }
        }
      ]
    }
  }
}
~~~

A binding references it:

~~~json
{
  "binding": {
    "type": "http",
    "operation": "GET /notes",
    "credentialRef": ["trilium-token"]
  }
}
~~~

The bearer credential stores only the token value; Engine adds the Bearer scheme word when it
builds the upstream Authorization header.

A complete Trilium example is in
[examples/use-cases/trilium](../examples/use-cases/trilium/README.md).

## Step 4 — run Engine beside the application

A conceptual Compose fragment:

~~~yaml
services:
  app:
    image: your-existing-app

  mcpiler-engine:
    image: <Engine image matching the documentation/release you use>
    environment:
      TRILIUM_ETAPI_TOKEN: <inject from your secret source>
    volumes:
      - ./mcp/trilium:/manifests/trilium:ro
      - mcpiler-data:/data
    command:
      - serve
      - --mount
      - /trilium=/manifests/trilium
      - --file-store-root
      - /data
      - --issuer
      - https://idp.example.com
      - --token-validation
      - jwks
      - --listen
      - http://0.0.0.0:8080
~~~

The issuer above is a placeholder for the OAuth/OIDC authority that authenticates MCP callers;
use the same real issuer/validation settings you verified with `inspect`. The upstream REST port
can remain private to the Docker network.

Use a versioned Engine release and documentation/examples from the same tag. Root and section
Manifest versions are independent from the Engine product version; see
[compatibility.md](compatibility.md).

## Step 5 — decide how the client reaches Engine

Choose one:

- **local stdio** — best when the client can launch Engine itself;
- **local/private HTTP** — useful for clients on the same LAN/VPN;
- **public HTTPS** — normal remote-client deployment;
- **client-specific private tunnel** — for example ChatGPT Secure MCP Tunnel for a private Engine.

Do not make the upstream application's REST API public merely because the MCP client is remote.

## Step 6 — connect and test

Use [clients.md](clients.md), then try progressively:

~~~text
Find notes containing "MCP".
Get metadata for note <id>.
Show the content of note <id>.
~~~

Only after reads work should you expose create/update/delete.

# Is MCPiler the right adapter?

MCPiler Engine is a strong fit when the upstream behavior can be represented as bounded HTTP/REST
operations and the AI-facing capability should be MCP **tools**.

Typical good fits:

- JSON REST APIs;
- form/multipart APIs;
- binary upload/download APIs;
- APIs with path/query/header/cookie parameters;
- APIs protected by the credential/authentication strategies documented by Engine;
- APIs that need request/response reshaping before they become good AI tools;
- several APIs aggregated behind one MCP listener.

It is not currently the direct answer when your requirement fundamentally depends on:

- an upstream protocol other than the HTTP/REST shapes Engine supports;
- WebSocket/event-subscription semantics as the primary operation;
- an MCP server capability other than tools, such as resources/prompts/elicitation/MCP Apps;
- a browser UI with no usable REST API;
- arbitrary custom code execution inside the adapter;
- a client that supports neither Streamable HTTP nor stdio;
- an authentication protocol that cannot be expressed by the current credential/authentication
  vocabulary.

In those cases either extend Engine deliberately, put an appropriate adapter in front of the
upstream, or use a purpose-built MCP server. Do not force a protocol into a Manifest shape that
does not represent its real semantics.

# Understand the three authentication boundaries

A frequent integration mistake is treating every token as the same token.

~~~text
AI client
   |
   | (1) optional caller authorization
   v
MCPiler Engine
   |
   | (2) upstream application credential
   v
REST API

MCPiler Engine
   |
   +---- (3) optional deployment/local-state secrets
~~~

## 1. Who may call the MCP endpoint?

A protected HTTP surface uses host-side bearer validation against a configured issuer through JWKS
or introspection.

This is **AI client → Engine** authentication.

## 2. How does Engine authenticate to the REST API?

This is described by Manifest credentials/authentication:

- API key;
- Basic;
- bearer;
- OAuth 2;
- OAuth 1;
- token/session exchange;
- challenge/session;
- request signing.

This is **Engine → REST API** authentication.

## 3. Which secrets protect Engine-owned deployment state?

Examples include:

- runtime-state encryption key;
- managed deployment secret;
- optional response-cache operator secret.

Do not reuse one secret for unrelated trust boundaries.

# Choose the deployment topology

| Requirement | Recommended path |
| --- | --- |
| One local IDE/client | stdio |
| Several clients on the same LAN/VPN | Streamable HTTP on the private network |
| ChatGPT | remote Streamable HTTP endpoint or OpenAI's private-server tunnel path |
| Claude remote custom connector | remote endpoint reachable from Anthropic infrastructure |
| Cursor local development | stdio or localhost Streamable HTTP |
| VS Code local development | stdio or localhost Streamable HTTP |
| Several self-hosted applications | several mount prefixes or separate Engine processes |
| Public production service | HTTPS reverse proxy + caller authorization where required |
| Platform-managed deployment | managed mode |

Client requirements change faster than Engine. The dated, source-linked matrix is maintained in
[clients.md](clients.md).

# Design an AI-facing contract, not a REST mirror

A working translation can still be a poor AI interface.

For each operation:

- use a clear verb/noun name such as **search-notes** rather than an internal controller name;
- write a summary saying when the tool should be used;
- expose only arguments the model should control;
- hide implementation-only headers/version parameters behind a transform;
- mark read/write/destructive semantics accurately;
- project noisy responses down to useful fields;
- use compound operations when one user intent requires several REST calls;
- use Navigator for a large API instead of advertising hundreds of direct tools.

The Manifest is the boundary where the REST contract becomes an agent-facing contract without
changing the application.

# Roll out read/write progressively

A practical order is:

1. read-only GET/search;
2. idempotent writes;
3. non-idempotent create/update;
4. destructive operations;
5. compound workflows.

For write/destructive tools:

- set annotations/risk accurately;
- consider a separate read-only surface;
- use caller scopes when different MCP users need different access;
- test the exact upstream side effect;
- assume clients may add confirmation UX, but never make server correctness depend on that UX.

# What "AI compatible" means

A precise project statement is:

> MCPiler Engine turns selected operations of an existing REST API into MCP tools without
> requiring the application itself to implement an MCP server.

The resulting server can be used by MCP clients that support Engine's transport/capability set and
can reach/authenticate to the endpoint.

Engine currently exposes **tools**. It does not claim to expose every MCP capability family such
as resources, prompts, elicitation or MCP Apps.

# Definition of done

Before calling an integration complete:

- [ ] every intended bundle passes inspect;
- [ ] every exposed tool has a clear name and summary;
- [ ] read/write/destructive annotations are correct;
- [ ] production upstream credentials are referenced, not embedded as literals;
- [ ] the MCP caller-auth boundary is intentionally public or protected;
- [ ] only required upstream origins are allowed;
- [ ] representative reads succeed;
- [ ] representative writes perform exactly the intended side effect;
- [ ] noisy/large responses are bounded or projected;
- [ ] file operations are tested through real handles;
- [ ] the chosen client supports the selected transport and can reach it;
- [ ] remote endpoints use HTTPS;
- [ ] reverse-proxy trust names only real proxies;
- [ ] health/readiness is monitored where applicable;
- [ ] Engine/Manifest compatibility is checked before upgrades;
- [ ] operators know where the troubleshooting guide is.

# Next documents

- [Client compatibility and connection recipes](clients.md)
- [End-to-end use-case cookbook](use-cases/README.md)
- [Manual Manifest authoring](authoring.md)
- [Manifest reference](manifest.md)
- [Hosting](hosting.md)
- [Troubleshooting](troubleshooting.md)
- [Compatibility and upgrades](compatibility.md)
- [Security model](../SECURITY.md)
