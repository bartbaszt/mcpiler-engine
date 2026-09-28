# Changelog

All stable MCPiler Engine releases are recorded here. The Engine version is independent of
the MCPiler Platform version and of the Manifest format version.

## v0.1.0

- Git range: repository start..v0.1.0
- Manifest format: 0.3
- Section formats at this tag: server 2, policy 1, credentials 3, authentication 1, operations 1, agentSurface 3, tools 1, search 1.
- Diagnostic codes: initial public diagnostic-code catalog; there is no prior stable Engine baseline.
- First stable Engine release with standalone MCP serving, authorization, managed deployment synchronization, file transfer, health/readiness, and runtime-owned mutable authentication state.

The unreleased `main` branch may support newer section formats while retaining root format 0.3.
Use [`docs/compatibility.md`](docs/compatibility.md) and documentation from the deployed tag when
planning an upgrade.
