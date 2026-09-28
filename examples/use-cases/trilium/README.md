# Trilium Notes ETAPI example

This is a concrete self-hosting example: Trilium remains an ordinary REST application and MCPiler
Engine supplies the MCP tool surface beside it.

The example was checked against the current Trilium ETAPI documentation on **2026-09-26**:

- [ETAPI reference](https://docs.triliumnotes.org/rest-api/etapi/)
- [ETAPI user guide](https://docs.triliumnotes.org/user-guide/advanced-usage/etapi)

Trilium documents token authentication through the Authorization header and supports the
**Bearer TOKEN** form in current releases.

# What this example exposes

The Manifest declares two MCP surfaces.

## Default / read-only surface

At mount **/trilium**:

- search-notes
- get-note
- get-note-content
- requires caller scope **trilium.read**

Create/delete remain hidden.

## Full surface

At **/trilium/full**:

- search-notes
- get-note
- get-note-content
- create-note
- delete-note
- requires caller scopes **trilium.read** and **trilium.write**

The mount is explicitly protected with `authenticationRequired: true`. The two paths therefore
do **not** rely on URL secrecy: a token that has only `trilium.read` cannot use the full surface.
Use an OAuth/OIDC issuer you control for MCP callers. The Trilium ETAPI token remains a separate
Engine-to-Trilium credential.

# Network topology

The example assumes Docker/service DNS:

~~~text
MCP client
    |
    | MCP
    v
MCPiler Engine
    |
    | HTTP REST + Bearer token
    v
http://trilium:8080/etapi
~~~

Change policy.baseUrl when your Trilium service uses another name/port.

# 1. Create an ETAPI token

Use Trilium's current ETAPI settings/documentation to create a token.

Keep only the token value in the environment:

~~~bash
export TRILIUM_ETAPI_TOKEN='<token>'
~~~

Do not include the word Bearer. MCPiler's bearer credential scheme adds it to the upstream
Authorization header.

# 2. Prove REST connectivity

From the Engine network or container environment:

~~~bash
curl http://trilium:8080/etapi/app-info \
  -H "Authorization: Bearer $TRILIUM_ETAPI_TOKEN"
~~~

Do not continue until this succeeds.

# 3. Configure MCP caller authorization

The example is protected by design. Point Engine at a real OAuth/OIDC issuer that can issue bearer
tokens for the **exact MCP resource URL** being called and carrying the required scopes.

For a public deployment such as `https://mcp.example.com`, the relevant resources are:

```text
default/read-only via bare mount:
  aud = https://mcp.example.com/trilium
  scopes include trilium.read

explicit default-surface address:
  aud = https://mcp.example.com/trilium/read-only
  scopes include trilium.read

full surface:
  aud = https://mcp.example.com/trilium/full
  scopes include trilium.read trilium.write
```

These audiences are not interchangeable. In particular, adding `trilium.write` to a token whose
audience is `https://mcp.example.com/trilium` does not authorize
`https://mcp.example.com/trilium/full`.

Configure the issuer/client authorization flow so it can obtain a token for the exact MCP resource
the client connects to. Engine's protected-resource metadata publishes that addressed resource and
the configured authorization server.

For an issuer that publishes a `jwks_uri`:

~~~bash
export MCPILER_CALLER_ISSUER='https://idp.example.com'
~~~

Replace that placeholder with your actual issuer. If your issuer does not publish the endpoint you
need, use the corresponding explicit `--jwks-uri` or introspection settings documented in
[hosting.md](../../../docs/hosting.md).

# 4. Inspect the exact serving configuration

~~~bash
dotnet mcpiler-engine.dll inspect \
  --mount /trilium=./examples/use-cases/trilium \
  --file-store-root ./data \
  --issuer "$MCPILER_CALLER_ISSUER" \
  --token-validation jwks
~~~

`inspect` must exit 0 before deployment. A missing issuer, unusable issuer endpoint or other
startup refusal exits 78 while still printing the derived surfaces/tools for diagnosis.

The Manifest itself is [manifest.json](manifest.json).

# 5. Serve it

~~~bash
dotnet mcpiler-engine.dll serve \
  --mount /trilium=./examples/use-cases/trilium \
  --file-store-root ./data \
  --issuer "$MCPILER_CALLER_ISSUER" \
  --token-validation jwks \
  --listen http://0.0.0.0:8081
~~~

Addresses:

~~~text
read-only/default: http://localhost:8081/trilium
full:              http://localhost:8081/trilium/full
~~~

# 6. Test locally first

Connect a local MCP client and try:

~~~text
Find Trilium notes containing "MCP".
~~~

Then use an id from the result:

~~~text
Get metadata for note <noteId>.
Show the content of note <noteId>.
~~~

For the default surface, use a caller token whose audience is the exact address you call
(`http://localhost:8081/trilium` in this local HTTP example) and which contains `trilium.read`.

A token for that audience must still be refused at **/trilium/full**, even if it also carries
`trilium.write`, because `/trilium/full` is a different protected resource.

Only after those checks work, connect to **/trilium/full** with a caller token whose audience is
exactly `http://localhost:8081/trilium/full` and which contains both `trilium.read` and
`trilium.write`, then test:

~~~text
Create a text note called "MCPiler test" under parent <parentNoteId> with content "Created through MCP".
~~~

Do not test delete against valuable notes.

# 7. Connect ChatGPT, Claude or an IDE client

Use [docs/clients.md](../../../docs/clients.md).

Important topology difference:

- Cursor/VS Code can run a local Engine over stdio;
- ChatGPT uses a remote MCP path (or OpenAI's documented private-server tunnel);
- Claude remote custom connectors connect from Anthropic infrastructure.

You normally expose/tunnel the **Engine MCP endpoint**, not Trilium's private ETAPI port.

# Docker Compose pattern

This is intentionally a pattern rather than a pinned Trilium deployment definition:

~~~yaml
services:
  trilium:
    image: <your Trilium image>
    networks: [notes]

  mcpiler-engine:
    image: <Engine image matching the release documentation you use>
    environment:
      TRILIUM_ETAPI_TOKEN: <inject from secret management>
    volumes:
      - ./examples/use-cases/trilium:/manifests/trilium:ro
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
    networks: [notes]

networks:
  notes:

volumes:
  mcpiler-data:
~~~

Replace the issuer placeholder with the same real MCP-caller authority used by `inspect`.
If the remote AI client needs the service, publish Engine through your HTTPS reverse proxy or
supported tunnel. Trilium itself can remain reachable only on the Docker/private network.

# Why only these ETAPI operations?

Trilium exposes many more operations, including revisions, attachments, exports/imports, branch
management and backup actions.

The example intentionally starts with a narrow useful contract. Extend it using the same process:

1. prove the ETAPI call directly;
2. add the operations entry;
3. add a well-named agent operation;
4. set read/write/destructive semantics;
5. add it to only the surfaces that should expose it;
6. run inspect;
7. test against non-critical data.

For binary export/import, use MCPiler's file-handle patterns from
[the file fixture](../../../tests/fixtures/manifests/files/manifest.json).

# Security notes

- the ETAPI token is an upstream credential; it is not MCP caller authorization;
- the default example surface is read-only but is still powerful enough to disclose notes;
- the MCP caller must authenticate through the configured issuer; the Trilium ETAPI token does not authorize MCP callers;
- the read-only surface requires `trilium.read`; the full surface additionally requires `trilium.write`;
- every caller token must also carry the byte-exact audience of the addressed surface; scopes never substitute for audience binding;
- for stronger tenant/process isolation, use separate mounts/deployments rather than relying only on scopes;
- keep backup/admin operations out of the AI surface unless they are a deliberate requirement.

See [SECURITY.md](../../../SECURITY.md) and
[hosting.md](../../../docs/hosting.md).
