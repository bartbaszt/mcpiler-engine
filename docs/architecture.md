# MCPiler Engine architecture

This document explains the runtime architecture and the boundaries the repository treats as
part of its design contract. For deployment configuration see [`hosting.md`](hosting.md); for
the persisted input contract see [`manifest.md`](manifest.md).

## Design goals

Engine is built around a small set of rules:

- the Manifest is the complete portable runtime contract;
- Engine can build and serve from a standalone checkout and deployment;
- the library decides **what** a Manifest means and what may execute;
- the host decides **how** that already-decided runtime is reached;
- a request is executed against one immutable generation from admission through completion;
- invalid configuration and invalid Manifest state fail closed before serving;
- optional accelerators may degrade, but security boundaries do not;
- secrets are resolved as late as possible and are never copied into diagnostics.

Architecture tests under `tests/MCPiler.Engine.ArchitectureTests/` enforce the most important
boundaries so they cannot silently drift with a refactor.

## Production projects

The repository has two production projects.

### `MCPiler.Engine`

The library owns product semantics:

- Manifest loading, section readers, canonicalization and validation;
- policy narrowing and outbound containment;
- tool/search derivation and Navigator behavior;
- request compilation and HTTP serialization;
- upstream authentication and request signing;
- response bounds, file handles, transformations, projections and caching;
- compound execution;
- protocol-neutral runtime values exposed through the `MCPiler.Engine.Runtime` seam.

The library does not own the web listener, command-line parsing or process lifecycle.

### `MCPiler.Engine.Host`

The executable owns deployment adapters:

- CLI binding;
- HTTP and stdio transports;
- MCP SDK translation;
- bearer-token validation at the inbound resource-server boundary;
- health/readiness and shutdown drain;
- managed synchronization transport;
- generation admission and activation;
- the confined JMESPath worker process.

The host is deliberately prevented from reaching directly into Manifest model, validation,
execution or search namespaces. It consumes the library's runtime seam instead. A Manifest
decision implemented only in the host would behave differently through another transport and
would therefore violate the split.

The projection-worker directory is the narrow exception to the host's no-child-process rule:
untrusted JMESPath evaluation is intentionally placed in a separate killable process.

## Manifest load pipeline

A file-mode mount begins with a directory containing `manifest.json`.

```text
bundle directory
      |
      v
DirectoryManifestSource
      |
      v
ManifestLoader
  - root format
  - section index
  - external payload hashes/sizes
      |
      v
section readers
  - closed member vocabularies
  - section format versions
      |
      v
policy narrowing
      |
      v
cross-section validation
      |
      v
derivation
  - default surface
  - tools
  - lexical search index
      |
      v
MountedManifest
```

`ManifestReader` is the end-to-end authority for whether a bundle represents a valid Manifest.
Published JSON Schemas are editor/interchange aids; they intentionally do not replace reader
validation.

The four required logical sections are `server`, `policy`, `operations` and
`agentSurface`. Credentials, authentication, tools, search, vectors and provenance are optional
for different reasons documented in the Manifest reference.

## The binding seam

Once a binding has been parsed, exactly one component is allowed to decide what it executes:
`ManifestBindingDispatcher`.

Consumers ask that dispatcher for:

- the effective HTTP operation;
- destination override;
- credential references;
- authentication profile;
- input transform program;
- output projection.

This prevents validation, capability gates and execution from independently pattern-matching the
binding and reaching different answers. A transformed binding, for example, always inherits the
HTTP execution identity and authentication scope of its base through this one seam.

The rule is enforced by `BindingSeamGuardTests`.

## Runtime construction

A successfully loaded mount is not yet a running request pipeline. Engine builds an execution
graph for the complete mount set. It contains the bounded HTTP transport, credential resolution,
authentication services, request compiler, response handling, file store integration and other
per-generation runtime state.

Startup is atomic at the process level: all configured file-mode mounts must load and the required
stores must open before the listener serves anything.

Important durable-state boundaries are:

| State | Lifetime | Durable? |
| --- | --- | --- |
| Manifest generation | deployment/generation | supplied externally; Engine does not rewrite file-mode Manifest state |
| access-token/session caches | generation/process | no |
| response cache | generation/process | no |
| file handles and their content | bounded handle lifetime | yes, under `--file-store-root` |
| declared runtime-owned mutable auth slot | across restarts | yes, encrypted under `--runtime-state-root` |
| managed provider secrets | generation | no |
| tool definitions/search derivations | generation | no |

The runtime-state store is not a general credential database. Its writer is structurally confined
to the mutable-slot port and the supported rotating slot implementation.

## Immutable generations

The host serves an `EngineGeneration`: one immutable mount set plus the execution graph and
derived MCP definitions belonging to it.

`EngineGenerationManager` is the only component that may replace the active generation.

```text
build complete candidate
        |
        v
EngineGenerationManager.Activate
        |
        +---- atomic pointer swap ----> new admissions
        |
        +---- retire old generation --> existing leases drain --> dispose
```

Every admitted request owns one generation lease. A request that started on generation N continues
using N even if N+1 activates while it runs. New admissions use N+1. A request therefore cannot
resolve a route from one generation and execute against another.

A refused candidate is never installed.

Generation-owned caches and memoized tool definitions die with their generation, preventing state
derived from an old Manifest from leaking into a replacement.

## File mode and managed mode

The generation model is shared by both deployment modes.

### File mode

File mode loads the local `--mount` directories before the listener opens. The desired state is
fixed for the process lifetime; changing files on disk does not hot-reload a running process.

### Managed mode

Managed mode has no local mounts. `ManagedSyncWorker` performs a bounded initial synchronization
with the configured management endpoint. The listener opens only after a complete generation has
been received, loaded and activated.

After startup the worker long-polls for complete desired generations:

```text
Platform delivery
      |
      v
archive extraction
      |
      v
ManagedGenerationLoader
      |
      v
full Manifest/runtime validation
      |
      +-- refused --> report sanitized diagnostic; keep current generation
      |
      v
EngineGeneration candidate
      |
      v
atomic activation
```

A management outage after activation does not stop the active generation. Engine continues serving
the last complete generation while synchronization retries with bounded backoff.

Runtime-owned secret rotations are committed locally before managed reconciliation is attempted.
A failed reconciliation remains operationally separate from the already-committed local rotation.

## Request path

At a high level, an MCP invocation follows this path:

```text
transport admission
      |
      v
generation lease
      |
      v
mount + surface resolution
      |
      v
exposure / caller-authorization gate
      |
      v
tool invocation
      |
      v
binding resolution
      |
      +-- compound --> bounded sequential step execution
      |
      v
input transform (optional)
      |
      v
request compilation
      |
      v
upstream authentication / signing
      |
      v
outbound containment + HTTP send
      |
      v
bounded response read / file-handle admission
      |
      v
binding-level body projection (optional)
      |
      v
agent output projection / pagination (optional)
      |
      v
MCP result
```

The exact ordering matters. Authentication is applied to the request that is actually sent;
response size bounds are applied before unbounded materialization; projection never grants a route
or credential that the binding did not already possess.

## Outbound containment

The Manifest defines the intended upstream perimeter. Engine enforces it rather than trusting a
URL that happens to appear during execution.

The runtime checks:

- policy base and allowed origins;
- per-operation destination overrides;
- authentication-profile origin restrictions;
- redirects and redirect-hop bounds;
- connect/request timeouts;
- upstream response-size limits.

Credential application is coupled to the reviewed execution destination. A redirect or override
cannot silently carry a secret to an origin outside the declared perimeter.

## Inbound authorization

Caller authorization is a host boundary, separate from upstream API authentication.

A surface may require bearer authorization and scopes. The host configures the trusted issuer and
one validation mode:

- RFC 7662 introspection; or
- JWKS-backed token validation.

The process refuses a protected mount when no usable issuer/validation configuration exists.
Authentication profiles inside the Manifest do not configure this inbound boundary.

## Projection isolation

Transform programs are a bounded Engine grammar.

JMESPath is treated differently because it is an expression evaluator. The serving process does
not evaluate an expression directly. `ProjectionWorkerHost` starts one short-lived child process
per evaluation under explicit concurrency, queue, time and memory/address-space bounds.

The worker receives prepared bounded JSON plus the expression, returns one classified result, and
is reaped before its worker slot is reused. If the parent cannot confirm that a child is gone, the
slot is deliberately not returned to the pool.

A declared projection failure never falls back to the raw upstream body.

## Response cache

The response cache is generation-local and opt-in per eligible operation. Cache identity includes
the execution authority needed to prevent one caller/authentication context from receiving another
context's response.

The host can narrow body, retained-byte, entry and TTL ceilings. Setting a ceiling to zero disables
the cache. The optional operator channel can inspect or clear completed entries but cannot mutate a
Manifest or cancel the producer of an in-flight entry.

## Files

Binary values cross the MCP boundary as Engine file handles rather than unbounded inline payloads.

The file store is opened at startup, is required to live outside declared served-content roots,
and uses bounded admission plus metadata records. The detailed storage and HTTP redemption
contract is in [`file-handles.md`](file-handles.md).

## Failure model

Engine distinguishes three broad classes:

1. **startup refusal** — configuration, Manifest or required storage is invalid; listener does not
   open;
2. **candidate refusal** — a managed replacement is invalid; active generation continues serving;
3. **request failure** — one invocation fails inside an already-valid generation.

Optional search-vector acceleration is an explicit exception: an unusable vector matrix degrades
to lexical ranking rather than refusing the Manifest.

Diagnostics are designed to carry codes and bounded non-secret context. Secret values must not
appear in startup or invocation diagnostics.

## Architectural change checklist

A change that introduces a new capability should answer:

1. Is this persisted contract or runtime behavior? If persisted, does the Manifest version need to
   change?
2. Does the decision belong in the library or is it only transport/hosting adaptation?
3. Does it add another interpretation of binding shape instead of extending the dispatcher?
4. Does it create state that survives a generation or process, and if so why?
5. Can it widen the outbound perimeter or secret scope?
6. Can it make one request observe two generations?
7. Can hostile input make it allocate, recurse, wait or spawn without a bound?
8. What stable diagnostic identifies refusal?
9. Which architecture/conformance test makes the new rule executable?

If those questions cannot be answered, the architecture is not yet specified enough to merge the
capability.
