# CI and release runners

Engine's private-repository GitHub-hosted Actions jobs can be blocked when the account's
included Actions minutes or spending limit is exhausted. The CI, history-scanning,
stable-release, and stable-release-resume workflows therefore target the dedicated
`[self-hosted, Linux, X64, mcpiler-engine-release]` label. This keeps the existing
Actions-only release state machine, permission boundaries, immutable candidates,
signatures, provenance, and mandatory GitHub Release bookkeeping.

Before triggering a release, an operator must independently verify that at least
one *online* runner with this exact label belongs to the Engine repository. A
Docker endpoint alone is not a GitHub Actions runner. The runner must provide:

- Linux x86-64, bash, Git, Python 3, curl, a working Docker daemon with Buildx,
  and enough available disk, RAM and Docker storage for .NET 10 and two-platform builds.
- A working `gh` CLI for release creation and resume, plus network access to
  GitHub, the .NET SDK distribution, and GHCR.
- Permission to run Docker builds and containers, install Buildx/QEMU helpers,
  and download pinned GitHub Actions dependencies. `actions/setup-dotnet` installs
  the SDK specified by `global.json` during source verification.
- Exclusive, appropriately isolated execution of Engine jobs. In particular,
  code from pull requests originating in forks is excluded from the persistent
  self-hosted CI and history-scan jobs.

The `linux/amd64` smoke executes natively. The `linux/arm64` smoke uses
`docker/setup-qemu-action` to execute the **ARM64 image under emulation** on the
x86-64 runner; this is runtime validation, but does not replace native ARM64
hardware performance testing. `eng/verify-container.sh --platform linux/arm64`
selects the requested image platform explicitly. The published index must still
contain exactly `linux/amd64` and `linux/arm64`.

The runner registration procedure, credentials, host location, and capacity
information are outside this future-public repository. Release entry points
remain the dedicated `Release patch`, `Release minor`, and `Release major`
workflows on `main`; failed post-Git publication is repaired with
`Resume stable release`. No workflow transfers source or SBOM through Actions
artifact storage.
