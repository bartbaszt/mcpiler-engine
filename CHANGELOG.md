# Changelog

## v0.2.0

- Git range: v0.1.0..0c59273c34dcf9cce5c301824106107ec2c4d657
- Manifest format: 0.3
- Diagnostic codes: agent/projection-header-name-invalid,agent/projection-header-sensitive agent/projection-mapping-incomplete,agent/projection-mapping-invalid agent/projection-output-schema-invalid,agent/projection-pointer-invalid agent/projection-shape-invalid,agent/projection-target-not-http agent/projection-target-overlap,agent/projection-target-unknown agent/projection-target-unreachable,agent/projection-unknown-member agent/projection-unknown-value,agent/projection-url-source-required agent/response-cache-policy-invalid,binding/projection-invalid binding/projection-limit-out-of-range,binding/projection-version-unsupported
- Stable Engine release prepared from the reviewed source range above.

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
