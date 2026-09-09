# Request-compilation corpus

This directory is the contract that pins what a compiled HTTP request looks like.

```
operations/    an operations section per scenario, the input
cases/         the expected request, the output
divergences.json   deliberate, declared exceptions to parity
```

## How it works

A case file is a plain text rendering of one compiled request:

```
METHOD POST
URL https://api.example.com/multipart
H Content-Type: multipart/form-data
BODY 2d2d...
```

Headers are sorted by name, each value on its own line, and the body is lowercase hex so a byte
difference is visible rather than inferred. `BODY` is omitted when there is none.

`RequestCompilationGoldenTests` loads an operations section from `operations/`, compiles a request
from it with a fixed set of arguments and a fixed multipart boundary, renders it in the shape above,
and compares it to the matching file in `cases/`.

## Why the sections are generated and not authored

The same corpus is replayed by a second, independent implementation of request compilation. That is
the point of it: a request compiler is only correct relative to a contract, and a contract with one
implementation is indistinguishable from whatever that implementation happens to do.

The sections in `operations/` are produced by the manifest compiler that produces real manifests, not
written by hand. A hand-authored section would prove that this compiler agrees with the person who
wrote the fixture. A generated one proves it agrees with the manifests it will actually be given.

Do not edit a file in `operations/` or `cases/` to make a test pass. Both are regenerated from their
producers, and a change to either is a change to observable behavior.

## divergences.json

```json
{ "cases": [ { "case": "...", "behavior": "...", "reason": "..." } ] }
```

A case named here is exempt from byte parity and must be asserted directly instead. A case is a parity
case or a divergence, never both, and `GoldenCorpusTests` enforces that.

The list is empty while the two implementations are meant to agree exactly. It exists so that the
first deliberate improvement here has a place to be declared, instead of arriving as a failing parity
test that somebody is tempted to delete.
