# MCP client compatibility and connection recipes

This document answers the question after Engine is serving:

> Which MCP clients can use this endpoint, and how do I connect them?

Client products evolve independently of MCPiler Engine. The client-specific information below was
verified on **2026-09-26** against the vendors' current documentation. Re-check the linked upstream
documentation when UI labels, plan availability or authentication behavior matter to a deployment.

The stable Engine-side contract is documented separately in [hosting.md](hosting.md) and
[compatibility.md](compatibility.md).

# What MCPiler Engine exposes

The current Engine source uses the official .NET Model Context Protocol SDK packages
**ModelContextProtocol.AspNetCore 2.2.0** and **ModelContextProtocol.Core 2.2.0**.

## Protocol-revision behavior

The C# SDK 2.2.0 release explicitly adds hybrid Streamable HTTP serving so the
**2025-11-25** initialize/session protocol family and the **2026-07-28** stateless protocol revision
can share one endpoint. Engine configures the SDK with **StatefulForInitializeClients**: clients
using the initialize-era flow get the stateful session behavior Engine needs, while modern
2026-07-28 requests can use the SDK's stateless path.

The SDK 2.x line also documents backward compatibility with older initialize-era clients. Engine
does not implement a second home-grown negotiation layer; the SDK owns framing/negotiation and
Engine receives the negotiated protocol revision when it renders tool definitions/results.

Practical rule:

- do not pin a client to a revision newer than the Engine's pinned SDK supports;
- normal clients that negotiate/fallback should use the highest mutually supported path;
- use the C# SDK release notes as the wire-revision authority for the exact package version pinned
  by the Engine release.

Current SDK release reference:
https://github.com/modelcontextprotocol/csharp-sdk/releases/tag/v2.2.0

Engine exposes:

- MCP **tools**;
- Streamable HTTP for network clients;
- stdio for local process-spawned clients;
- negotiated protocol revision through the SDK;
- structured tool output when supported by the negotiated client revision;
- tool annotations such as read-only/destructive/idempotent/open-world hints;
- stateful HTTP sessions for clients that initialize a session.

Engine does **not** currently claim support for these server capability families:

- resources;
- prompts;
- elicitation;
- sampling;
- MCP Apps / interactive UI.

A client can therefore be compatible with Engine even when it supports many MCP features Engine
does not expose. The relevant question is whether it can consume MCP **tools** over Streamable HTTP
or stdio.

Engine does not expose a legacy SSE-only server transport. A client that supports only the
superseded SSE transport is not an Engine client until it also supports Streamable HTTP or stdio.

# Generic compatibility matrix

| Client capability | Engine |
| --- | --- |
| MCP tools | yes |
| Streamable HTTP | yes |
| stdio | yes |
| legacy SSE-only server | no |
| remote HTTPS | yes |
| localhost/private HTTP | yes when the client itself can reach it |
| caller bearer authorization | yes, as a resource-server boundary configured on the host |
| anonymous/public MCP surface | yes |
| several surfaces | yes over HTTP |
| several mounted APIs | yes over HTTP |
| stdio with several surfaces | no; stdio must resolve to exactly one surface |
| resources/prompts/apps | not currently exposed |

# Endpoint shape

For:

~~~bash
--mount /trilium=/manifests/trilium
~~~

the default surface is reachable at:

~~~text
https://mcp.example.com/trilium
~~~

If the Manifest declares another surface named **read-only**, its explicit address is:

~~~text
https://mcp.example.com/trilium/read-only
~~~

Use the exact resource URL configured for that surface. Do not append a guessed **/mcp** suffix.

For protected HTTP surfaces, a reverse proxy must preserve the public path that Engine receives.
Prefix stripping or path rewriting such as public `/mcp/trilium` -> Engine `/trilium` is not
compatible with exact audience/resource binding: Engine would authorize
`https://host/trilium`, not the public `https://host/mcp/trilium`. Engine currently has no
trusted external-path-prefix setting that can reconstruct such a public path.

# Local vs remote clients

## Local/process client

A local client can launch:

~~~bash
dotnet mcpiler-engine.dll serve \
  --mount /local=/path/to/manifest-directory \
  --file-store-root /path/to/data \
  --transport stdio
~~~

No HTTP listener exists. The OS process boundary authorizes the local caller. The configuration
must resolve to exactly one mount and one surface.

Good fits include Cursor, VS Code and other clients that accept a stdio command.

## Network client

A network client connects to a Streamable HTTP address:

~~~text
https://mcp.example.com/trilium
~~~

This is the normal path for ChatGPT, Claude remote custom connectors and remote configurations in
Cursor/VS Code.

# Authentication compatibility

There are two independent auth problems.

## Upstream REST authentication

Manifest **credentials** and **authentication** configure Engine -> REST API.

This does not require an MCP-client auth feature. The client can call an open Engine surface while
Engine authenticates upstream with an API key, OAuth, Basic, bearer or request signature.

## MCP caller authentication

A protected Engine surface is a resource server. The host validates bearer tokens against one
configured issuer using JWKS or token introspection.

Engine is **not** the authorization server and does not mint user tokens. The client/user must
authenticate with the configured issuer and present a suitable bearer token.

Therefore:

- a private local deployment may intentionally use an open Engine surface with tightly scoped
  upstream credentials;
- a shared/public Engine endpoint should normally have an explicit caller-authorization design;
- choose a client that can complete the issuer/OAuth flow required by the deployment.

### Audience/resource binding

For every protected HTTP surface, the caller token must also name the **exact public MCP surface
URL** as its audience/resource. Engine compares the audience byte-for-byte with the canonical
resource assembled from the request scheme, host and raw surface path.

For example, these are distinct token audiences:

```text
https://mcp.example.com/trilium
https://mcp.example.com/trilium/read-only
https://mcp.example.com/trilium/full
```

Correct scopes do not compensate for the wrong audience. A token carrying `trilium.write` for
`https://mcp.example.com/trilium` is still not a token for
`https://mcp.example.com/trilium/full`.

When configuring a client/issuer flow, make sure it can request/obtain a token for the exact
resource URL the MCP client connects to. Prefer the RFC 9728 protected-resource metadata Engine
publishes for that addressed surface when the client supports discovery.

See [hosting.md](hosting.md#caller-token-audience-is-the-exact-mcp-surface-resource) for the full
canonicalization rules and reverse-proxy implications.

# ChatGPT

Upstream documentation:
[Developer mode and MCP apps in ChatGPT](https://help.openai.com/en/articles/12584461-developer-mode-and-mcp-apps-in-chatgpt).

Verified 2026-09-26:

- ChatGPT connects to **remote MCP servers**, not directly to local stdio servers;
- OpenAI documents **Secure MCP Tunnel** for private network, on-premises or developer-machine MCP
  servers when you do not want to expose the server publicly;
- full MCP including write/modify actions is currently available to Business and Enterprise/Edu;
- Pro can currently connect custom MCP with read/fetch permissions in developer mode, while full
  MCP is not a Pro capability;
- custom MCP app setup is currently a web experience;
- search/fetch tools are no longer mandatory for a connected MCP server;
- changed tool definitions may require a client-side refresh/rescan and workspace approval.

Use the OpenAI page above as the authority for current plan and UI details.

## ChatGPT: remote public/HTTPS Engine

1. Serve Engine through HTTPS, for example **https://mcp.example.com/trilium**.
2. Verify the address is reachable from outside your LAN unless you use the private tunnel path.
3. If the surface requires caller authorization, ensure the issuer is usable by the ChatGPT app
   connection flow.
4. Enable developer/custom-app functionality permitted by the plan/workspace.
5. Create a custom MCP app/connector and enter the Engine endpoint.
6. Configure the requested authentication mechanism.
7. Scan/refresh tools.
8. Create/save the app.
9. Start a new chat, select or mention the app, and test a read-only tool first.
10. Only then test write/destructive tools and client confirmation behavior.

## ChatGPT: private/self-hosted Engine

1. Keep Engine and the REST application on the private network.
2. Serve the Engine MCP surface locally/private as normal.
3. Use the current OpenAI Secure MCP Tunnel path documented by OpenAI.
4. Connect the custom app through that path.
5. Test discovery and one read-only invocation.
6. Add write tools only after the tunnel and authorization boundary are stable.

ChatGPT does not directly consume Engine's stdio mode.

# Claude

Upstream documentation:
[Get started with custom connectors using remote MCP](https://support.claude.com/en/articles/11175166-get-started-with-custom-connectors-using-remote-mcp)
and
[When to use desktop and web connectors](https://support.claude.com/en/articles/11725091-when-to-use-desktop-and-web-connectors).

Verified 2026-09-26:

- remote custom MCP connectors are available on Claude, Cowork and Claude Desktop across Free,
  Pro, Max, Team and Enterprise; Anthropic currently limits Free to one custom connector;
- remote custom-connector traffic originates from Anthropic's cloud infrastructure, even when the
  user runs Claude Desktop;
- a remote connector therefore needs to be reachable from Anthropic infrastructure; private
  deployments require the network and firewall path documented by Anthropic;
- local MCP servers in Claude Desktop use a **different mechanism** from remote custom connectors;
  current Anthropic guidance prefers desktop extensions for local integrations.

## Claude: remote Engine

1. Expose the Engine surface at HTTPS.
2. Ensure Anthropic's cloud infrastructure can reach it.
3. Configure caller auth if required.
4. In Claude open the current custom-connector UI.
5. Add a custom web/remote connector.
6. Enter the Engine URL.
7. Supply OAuth client details when the caller-auth design requires them.
8. Connect/authorize the connector.
9. Enable it for a conversation.
10. Test a narrow read operation, then writes.

For Team/Enterprise, organization owners control registration of custom connectors before members
connect to them.

## Claude: local/private application

Choose either:

- run Engine remotely/reachably and use Claude's remote connector path; or
- package/run Engine through Claude Desktop's current local-extension mechanism.

The second path can use Engine stdio, but client-side extension packaging/configuration is outside
this repository. Follow current Anthropic desktop-extension documentation instead of copying old
manual Claude Desktop snippets from third-party guides.

# Cursor

Upstream documentation:
[Cursor MCP documentation](https://cursor.com/docs/mcp).

Verified 2026-09-26, Cursor supports stdio, Streamable HTTP, legacy SSE and OAuth for remote
servers. Engine maps to stdio and Streamable HTTP.

## Cursor: local stdio

A project-level **.cursor/mcp.json** can contain:

~~~json
{
  "mcpServers": {
    "my-api": {
      "type": "stdio",
      "command": "dotnet",
      "args": [
        "/absolute/path/mcpiler-engine.dll",
        "serve",
        "--mount",
        "/local=/absolute/path/my-api",
        "--file-store-root",
        "/absolute/path/mcpiler-data",
        "--transport",
        "stdio"
      ],
      "env": {
        "MY_API_TOKEN": "<inject or inherit MY_API_TOKEN>"
      }
    }
  }
}
~~~

Use absolute paths unless you intentionally rely on Cursor's workspace interpolation.

Constraints:

- Engine must resolve to one mount and one surface;
- normal logging must not write protocol frames to stdout;
- Engine already routes stdio operator progress separately.

## Cursor: remote Streamable HTTP

~~~json
{
  "mcpServers": {
    "my-api": {
      "url": "https://mcp.example.com/my-api"
    }
  }
}
~~~

Use Cursor's OAuth/static-auth support when the Engine surface is protected. Prefer environment
interpolation for secret client configuration rather than hardcoding values.

# VS Code / GitHub Copilot

Upstream documentation:
[Add and manage MCP servers in VS Code](https://code.visualstudio.com/docs/agent-customization/mcp-servers)
and
[MCP configuration reference](https://code.visualstudio.com/docs/agents/reference/mcp-configuration).

Verified 2026-09-26, VS Code supports stdio, Streamable HTTP, legacy SSE fallback and OAuth for
HTTP servers.

## VS Code: local stdio

A workspace **.vscode/mcp.json**:

~~~json
{
  "servers": {
    "my-api": {
      "type": "stdio",
      "command": "dotnet",
      "args": [
        "/absolute/path/mcpiler-engine.dll",
        "serve",
        "--mount",
        "/local=/absolute/path/my-api",
        "--file-store-root",
        "/absolute/path/mcpiler-data",
        "--transport",
        "stdio"
      ],
      "env": {
        "MY_API_TOKEN": "<inject or inherit MY_API_TOKEN>"
      }
    }
  }
}
~~~

VS Code also has a portable MCP configuration format where appropriate.

## VS Code: remote Streamable HTTP

~~~json
{
  "servers": {
    "my-api": {
      "type": "http",
      "url": "https://mcp.example.com/my-api"
    }
  }
}
~~~

VS Code can attach headers/OAuth configuration to HTTP server definitions. Follow its current
secret-input guidance rather than committing bearer tokens into the workspace file.

# Generic MCP client

For an unknown client, check in this order:

1. Does it support MCP **tools**?
2. Does it support **Streamable HTTP** or **stdio**?
3. If remote HTTP, does the connection originate from the user's device or the vendor's cloud?
4. Can that origin reach the Engine endpoint?
5. Does it support the caller-auth mechanism required by the Engine surface?
6. Does it implement normal MCP initialize/session behavior?
7. Does it honor tool input schemas and annotations?
8. If structured output matters, does its negotiated revision consume it?
9. Does it impose a tool-count/context limit that suggests Navigator?
10. Does it add approval rules for write/destructive tools?

If 1 and 2 are yes, transport compatibility is plausible. The remaining questions decide
deployment, authentication and UX compatibility.

# Practical client matrix

| Client | Engine stdio | Engine Streamable HTTP | Remote connection origin | Typical use |
| --- | --- | --- | --- | --- |
| ChatGPT custom MCP app | no | yes | OpenAI infrastructure / documented tunnel path | remote HTTPS tools |
| Claude remote custom connector | not through remote-connector mechanism | yes | Anthropic infrastructure | remote HTTPS tools |
| Claude Desktop local extension | local mechanism | client/extension-dependent | local machine | private/local tools |
| Cursor | yes | yes | local app for normal config; cloud-agent behavior can differ | development + remote tools |
| VS Code / Copilot | yes | yes | depends on local vs Agent Host context | development + remote tools |
| generic MCP client | client-dependent | client-dependent | client-dependent | use checklist above |

# Large tool sets

Client tool-loading behavior differs. Prefer:

1. a small set of high-value direct tools;
2. Navigator for the long tail;
3. useful aliases/keywords/example intents;
4. testing the actual client with the intended direct-tool count.

Do not assume every client handles hundreds of simultaneously advertised tools equally well.

# Tool changes after deployment

Engine tool definitions belong to the active generation. A new generation changes definitions for
new requests.

Clients can still cache or approve a snapshot. For example, ChatGPT currently documents explicit
refresh/rescan behavior for changed custom-app actions.

When testing a Manifest update, distinguish:

~~~text
Engine still serves old generation
vs
Engine serves new generation but client still displays cached tools
~~~

Run **inspect** and reconnect/restart/refresh the client before diagnosing a client cache as an
Engine problem.

# Security notes for every client

- connect only trusted MCP servers;
- keep upstream REST secrets in Engine rather than duplicating them into client config;
- do not confuse client-to-Engine bearer tokens with Engine-to-REST tokens;
- prefer read-only surfaces where possible;
- keep destructive/admin operations hidden unless required;
- expose Engine rather than the private REST API when the remote client only needs MCP;
- trust forwarded headers only from configured reverse proxies;
- test prompt-injection-sensitive write workflows before broad access.

# Compatibility verification checklist

For every client you claim to support, record:

- [ ] client/product name;
- [ ] verification date;
- [ ] transport;
- [ ] exact Engine URL or stdio command;
- [ ] where the network connection originates;
- [ ] caller-auth mechanism;
- [ ] read/write restrictions imposed by plan/client;
- [ ] tool refresh/reconnect procedure;
- [ ] one tested read prompt;
- [ ] one tested write prompt when applicable;
- [ ] known unsupported Engine/MCP capabilities.

For Engine/Manifest compatibility use [compatibility.md](compatibility.md). For scenario recipes use
[use-cases/README.md](use-cases/README.md).
