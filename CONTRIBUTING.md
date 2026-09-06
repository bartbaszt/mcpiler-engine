# Contributing to MCPiler Engine

Thank you for your interest. This document explains the licensing terms your contribution
is made under and the practical rules for changes.

## Licence and sign-off

MCPiler Engine is licensed under the Apache License, Version 2.0. Contributions are
accepted under the same licence, as provided by section 5 of that licence. There is no
Contributor License Agreement.

Every commit MUST carry a Developer Certificate of Origin sign-off:

```bash
git commit -s -m "your message"
```

This appends a line of the form:

```text
Signed-off-by: Your Name <your.email@example.com>
```

The name and address must be real and must match your commit author identity. CI rejects
pull requests containing commits without a valid sign-off.

### Developer Certificate of Origin 1.1

```text
Developer Certificate of Origin
Version 1.1

Copyright (C) 2004, 2006 The Linux Foundation and its contributors.

Everyone is permitted to copy and distribute verbatim copies of this
license document, but changing it is not allowed.


Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is covered under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part
    by me, under the same open source license (unless I am
    permitted to submit under a different license), as indicated
    in the file; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified
    it.

(d) I understand and agree that this project and the contribution
    are public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed consistent with
    this project or the open source license(s) involved.
```

## Scope rules

Engine is the runtime half of MCPiler. Please do not propose changes that:

- parse or interpret a source API description format (OpenAPI, Postman, cURL);
- add a YAML parser, an OpenAPI library, an ORM, or a UI framework to the dependency graph;
- introduce a dependency on any MCPiler control plane at runtime;
- add a network dependency that a fully offline deployment could not satisfy.

Those concerns belong to MCPiler Studio, which produces the manifest Engine consumes.

## Dependency policy

New dependencies must be licensed MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause or ISC, and
must be justified. Engine's dependency graph is intentionally small.

## Quality gates

```bash
dotnet build MCPiler.Engine.slnx -c Release
bash eng/verify-source.sh
```

Warnings are errors. Behavior changes require tests. Changes to request compilation,
serialization, credential application or manifest parsing require golden or
characterization tests, not only unit assertions.

## Reporting security issues

Do not open a public issue for a security problem. Contact the maintainer privately.
