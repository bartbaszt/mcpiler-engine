# MCPiler Engine documentation

Choose the document by the question you are trying to answer.

# I am evaluating MCPiler

Start with:

1. [Getting started](getting-started.md) — what MCPiler solves and the two golden paths: product
   author and self-hoster.
2. [Alternatives and competitive positioning](alternatives.md) — why MCPiler exists, how its
   artifact/runtime model differs, and when AnythingMCP or another project is a better fit.
3. [Client compatibility](clients.md) — whether your AI/MCP client can connect.
4. [End-to-end cookbook](use-cases/README.md) — fifty representative integration scenarios.

If those answer the use case, continue into the reference material only when needed.

# I own a REST API

Read in this order:

1. [Getting started](getting-started.md)
2. [Use-case cookbook](use-cases/README.md)
3. [Manual Manifest authoring](authoring.md)
4. [Manifest reference](manifest.md)

Core idea:

~~~text
AI client -> MCPiler Engine -> your existing REST API
~~~

Your application does not need an MCP SDK when the desired capability can be represented by the
Engine Manifest/runtime contract.

# I self-host an application

Read:

1. [Getting started — self-hosting path](getting-started.md)
2. [Trilium real-world example](../examples/use-cases/trilium/README.md)
3. [Client compatibility](clients.md)
4. [Hosting](hosting.md)
5. [Troubleshooting](troubleshooting.md)
6. [Keycloak setup](authorization/keycloak.md) or [authentik setup](authorization/authentik.md) when Engine
   validates caller tokens against an external issuer (documented guidance; provider compatibility stays
   unverified until the smoke harness passes against a real provider)

The usual deployment keeps the application's REST endpoint private and exposes/tunnels only the
Engine MCP endpoint.

# I need to connect an AI/MCP client

Use [Client compatibility and connection recipes](clients.md).

It covers:

- Engine's MCP capability/transport set;
- local stdio vs remote Streamable HTTP;
- ChatGPT;
- Claude;
- Cursor;
- VS Code / GitHub Copilot;
- generic-client decision checklist;
- caller authorization vs upstream REST authentication;
- tool refresh/caching considerations.

Client-specific information is dated because those products change independently of Engine.

# I am writing a Manifest

Use:

1. [Manual authoring](authoring.md)
2. [Feature examples](../examples/README.md)
3. [Manifest reference](manifest.md)
4. [Published JSON Schemas](../schemas/manifest-0.3/README.md)

The recommended loop is:

~~~text
write -> inspect -> fix diagnostics -> inspect -> serve
~~~

# I am deploying Engine

Use:

- [Hosting](hosting.md) — CLI, file/managed mode, HTTP/stdio, auth, proxy, health, container and
  supply-chain behavior;
- [Compatibility](compatibility.md) — Engine/root/section versions and upgrades;
- [Licensing](licensing.md) — redistribution and third-party terms;
- [Security policy](../SECURITY.md) — vulnerability/reporting boundary.

# I am debugging an integration

Start with [Troubleshooting](troubleshooting.md).

Then use:

- [Manifest diagnostics](manifest.md#diagnostics);
- [Client compatibility](clients.md) for network and client-origin problems;
- [Compatibility](compatibility.md) for version refusals;
- [File handles](file-handles.md) for binary transfer/storage;
- [Architecture](architecture.md) when you need to understand generation/auth/state boundaries.

# I am extending Engine itself

Read:

1. [Architecture](architecture.md)
2. [Manifest reference](manifest.md)
3. [Compatibility](compatibility.md)
4. [Contributing](../CONTRIBUTING.md)
5. [Security](../SECURITY.md)

Architecture tests enforce the repository's key library/host, binding-seam, runtime-state and
public-repository boundaries.

# Reference map

| Document | Purpose |
| --- | --- |
| [getting-started.md](getting-started.md) | product-level onboarding, REST-to-MCP golden paths |
| [alternatives.md](alternatives.md) | competitive positioning, alternatives and decision guidance |
| [clients.md](clients.md) | MCP client compatibility and connection recipes |
| [use-cases/README.md](use-cases/README.md) | fifty end-to-end scenarios |
| [authoring.md](authoring.md) | hand-authoring workflow |
| [manifest.md](manifest.md) | normative persisted-contract/reference documentation |
| [hosting.md](hosting.md) | operator and deployment reference |
| [authorization/keycloak.md](authorization/keycloak.md) | documented Keycloak issuer/client/audience setup; compatibility unverified until the smoke harness passes |
| [authorization/authentik.md](authorization/authentik.md) | documented authentik issuer/client/audience setup and its explicit audience limitations; compatibility unverified |
| [troubleshooting.md](troubleshooting.md) | symptom-driven operator guide |
| [compatibility.md](compatibility.md) | release/root/section/sub-format compatibility |
| [architecture.md](architecture.md) | runtime architecture and trust boundaries |
| [file-handles.md](file-handles.md) | binary file-handle/storage/transfer contract |
| [licensing.md](licensing.md) | Engine and third-party licensing/redistribution |

Repository-root documents:

| Document | Purpose |
| --- | --- |
| [README.md](../README.md) | project landing page |
| [SECURITY.md](../SECURITY.md) | security support/reporting policy |
| [CONTRIBUTING.md](../CONTRIBUTING.md) | contribution and quality gates |
| [CHANGELOG.md](../CHANGELOG.md) | stable release history and release compatibility |
| [TRADEMARKS.md](../TRADEMARKS.md) | naming/trademark policy |
| [THIRD-PARTY-NOTICES.md](../THIRD-PARTY-NOTICES.md) | generated runtime dependency inventory |
