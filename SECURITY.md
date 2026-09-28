# Security Policy

MCPiler Engine is a network-facing runtime that can hold API credentials, validate caller tokens,
make outbound requests and persist bounded file/authentication state. Security reports are handled
privately.

## Supported versions

Security fixes target the latest stable Engine release line.

At the time of this document the stable line is `0.1.x`; the current stable release is listed in
[`CHANGELOG.md`](CHANGELOG.md) and on the repository Releases page.

| Version | Security support |
| --- | --- |
| latest stable minor line | supported |
| older stable minor lines | not guaranteed; upgrade to the latest stable line |
| unreleased `main` / development commits | development only; not a supported production baseline |

The Manifest format is versioned independently of Engine. A security fix in Engine does not imply
a Manifest format change, and a Manifest format change does not imply that an older Engine remains
security-supported. See [`docs/compatibility.md`](docs/compatibility.md).

## Reporting a vulnerability

**Do not open a public GitHub issue, discussion or pull request for a vulnerability before it has
been triaged privately.**

Private reporting paths:

1. When this repository is public and GitHub shows **Security → Advisories → Report a
   vulnerability**, use that Private Vulnerability Reporting form.
2. **Guaranteed fallback:** email **security@bbasztura.eu** with a subject beginning
   `[MCPiler Engine security]`.

The email fallback remains valid even when GitHub Private Vulnerability Reporting is enabled, so a
reporter is never required to open a public issue merely because the GitHub form is unavailable.
GitHub currently makes repository Private Vulnerability Reporting a public-repository feature, so
this fallback is also the explicit path while the Engine repository itself is private.

Do not send secrets merely to prove impact. A report should contain the minimum information needed
to reproduce and understand the boundary failure.

## What to include

A useful report contains:

- affected Engine version/commit;
- deployment mode (`file` or `managed`);
- affected transport (`http` or `stdio`);
- minimal redacted Manifest or fixture;
- exact non-secret host settings needed to reproduce;
- stable diagnostic/error codes, if any;
- reproduction steps and expected/observed behavior;
- security impact and the boundary crossed;
- whether the issue requires authentication or a particular Manifest capability;
- OS/container architecture when relevant.

For crashes or resource-exhaustion reports, include the smallest input that demonstrates the
behavior and the bound that failed to contain it.

## Never include

Do not include real:

- API keys;
- bearer/access tokens;
- refresh tokens;
- OAuth client secrets;
- request-signing secrets/private keys;
- deployment secrets;
- runtime-state encryption keys;
- contents of secret files;
- production user data.

Use synthetic values and redacted URLs unless the real hostname is essential to explain an origin
or redirect problem.

## Security-relevant areas

Examples of issues that should be reported privately include:

- credential or token disclosure;
- secret material appearing in diagnostics, logs, MCP results or cache observations;
- outbound origin/redirect containment bypass;
- a credential being sent to an undeclared destination;
- caller authorization or scope bypass;
- cross-mount, cross-surface, cross-caller or cross-generation data disclosure;
- file-handle authorization/path traversal or store escape;
- response-cache isolation failure;
- Manifest/archive path traversal;
- signature/authentication canonicalization defects that change the authenticated request;
- unsafe deserialization or unbounded hostile-input behavior;
- JMESPath worker confinement/limit bypass;
- runtime-state confidentiality, integrity or rollback defects;
- managed-generation authenticity/authorization failures;
- supply-chain or official-image integrity problems.

Ordinary malformed-Manifest refusals, expected lexical fallback for unusable vectors and documented
configuration errors are not vulnerabilities by themselves.

## Security model to check first

Before reporting a suspected bypass, compare the behavior with the documented boundary:

- [Architecture](docs/architecture.md) — trust and runtime boundaries;
- [Manifest](docs/manifest.md) — persisted contract and diagnostics;
- [Hosting](docs/hosting.md) — inbound authorization, proxy and deployment boundaries;
- [File handles](docs/file-handles.md) — file-store/redemption contract;
- [Troubleshooting](docs/troubleshooting.md) — expected refusal and degradation behavior.

A behavior that contradicts one of those contracts is especially useful to call out explicitly.

## Coordinated handling

The maintainer will triage the report privately and decide whether the issue is:

- a security defect;
- an ordinary correctness bug;
- documented behavior;
- outside Engine's trust boundary.

No fixed response or disclosure SLA is promised by this repository.

Please avoid public disclosure while a credible vulnerability is being investigated and a fix is
being prepared. After a fix is available, the maintainer may publish a GitHub Security Advisory,
release notes and upgrade guidance appropriate to the impact.

## Fixes

Security fixes should normally:

1. add a regression test that demonstrates the crossed boundary;
2. preserve fail-closed behavior;
3. add or retain a stable non-secret diagnostic when refusal is operator-visible;
4. update affected documentation;
5. ship in a stable Engine release when production users need the fix.

If a vulnerability changes the persisted Manifest contract, the compatibility impact must also be
documented in [`docs/compatibility.md`](docs/compatibility.md).
