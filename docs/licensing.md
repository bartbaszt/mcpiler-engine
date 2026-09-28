# Licensing and redistribution

MCPiler Engine itself is licensed under the Apache License, Version 2.0. The complete
licence text is in [`LICENSE`](../LICENSE), and the project attribution notice is in
[`NOTICE`](../NOTICE).

This document is an operational summary for users, redistributors and integrators. It does
not replace the licence texts that apply to Engine or to third-party software.

## MCPiler Engine

Apache-2.0 permits commercial and non-commercial use, modification and redistribution in
source and object form, subject to its conditions. In particular, a redistribution must
preserve the Apache-2.0 licence and applicable notices, and modified files must carry
prominent notices that they were changed. Apache-2.0 also contains a contributor patent
grant and its own warranty and liability terms.

The Apache licence does not grant rights to MCPiler names or branding. The separate
[`TRADEMARKS.md`](../TRADEMARKS.md) policy explains permitted descriptive use and the
rules for forks, derivative distributions and competing products.

## Third-party software

Engine is distributed with third-party runtime dependencies. The generated
[`THIRD-PARTY-NOTICES.md`](../THIRD-PARTY-NOTICES.md) records the exact runtime dependency
graph, package versions and the licence classification reviewed by this repository. The
inventory is regenerated and checked by `eng/check-licenses.sh`; a dependency or version
change that does not match the reviewed policy fails that gate.

Most current runtime dependencies use permissive licences such as Apache-2.0 or MIT.
Those licences remain the licences of their respective projects; Engine's Apache-2.0
licence does not replace them.

### JSON-Everything official binary releases

The current Engine runtime graph includes the following official NuGet binary releases from
the JSON-Everything project:

- `JsonSchema.Net 9.4.0`
- `JsonPointer.Net 7.0.2`
- `Json.More.Net 3.0.1`

Their source project publishes an [MIT licence](https://github.com/json-everything/json-everything/blob/master/LICENSE).
The upstream project also publishes an
[`OSMFEULA.txt`](https://github.com/json-everything/json-everything/blob/master/OSMFEULA.txt)
agreement for its official binary releases. The agreement describes an Open Source Maintenance
Fee arrangement for some revenue-generating users of those official binaries, while explicitly
distinguishing that arrangement from the MIT licence of the source code and from binaries
independently compiled from source.

Because MCPiler Engine's official builds currently consume the official NuGet binaries, users
and redistributors of an official Engine build should review the upstream JSON-Everything
binary terms for their own use case. MCPiler does not waive, replace or reinterpret those
upstream terms.

The value `MCPILER-APPROVED-OSMFEULA` in
[`THIRD-PARTY-NOTICES.md`](../THIRD-PARTY-NOTICES.md) is an internal Engine licence-policy
classification used by the deterministic dependency gate. It is not an SPDX licence
identifier and is not itself the upstream agreement.

Upstream source and binary terms can change independently of Engine. The package versions
recorded in `THIRD-PARTY-NOTICES.md` are therefore the authoritative description of which
versions an Engine release contains; consult the corresponding upstream package/source
materials for the actual terms applicable to those versions.

## Official container images

Stable images are published as `ghcr.io/bartbaszt/mcpiler-engine:vA.B.C`. The Engine image
carries the following Engine redistribution material under
`/licenses/mcpiler-engine/`:

- `LICENSE`
- `NOTICE`
- `THIRD-PARTY-NOTICES.md`

The inherited .NET runtime licence and third-party notices remain under
`/usr/share/dotnet/`.

The generated third-party inventory identifies the runtime packages in the Engine image, but
it should not be read as replacing the licence or agreement text supplied by an upstream
project.

## Common scenarios

| Scenario | Engine terms | Additional consideration |
| --- | --- | --- |
| Run an unmodified Engine build internally | Apache-2.0 | Review third-party runtime terms, including the JSON-Everything binary terms where applicable. |
| Use Engine commercially | Permitted by Apache-2.0 | Commercial use does not remove third-party obligations; review the terms of bundled dependencies. |
| Redistribute an unmodified Engine build/image | Permitted by Apache-2.0 subject to its redistribution conditions | Preserve Engine licence/notices and satisfy the terms and notices of bundled third-party software. |
| Publish a modified Engine build | Permitted by Apache-2.0 subject to its redistribution conditions | Mark modified files as required by Apache-2.0, preserve applicable notices, and follow the trademark policy for naming. |
| Fork the source | Permitted by Apache-2.0 | The MCPiler name and logo are not licensed by Apache-2.0; see `TRADEMARKS.md`. |
| Independently build a third-party dependency from its source | Governed by that dependency's source licence | This can differ from terms attached by an upstream project specifically to its official binary release. |

## Contributions

Contributions to MCPiler Engine are submitted under the repository's Apache-2.0 terms unless
explicitly stated otherwise. The project also requires Developer Certificate of Origin sign-off
as described in [`CONTRIBUTING.md`](../CONTRIBUTING.md).

## Licence questions

When determining obligations for a particular deployment or redistribution, use the actual
licence and upstream agreement texts rather than this summary. Questions about use of MCPiler
marks can be directed to the maintainer as described in `TRADEMARKS.md`.
