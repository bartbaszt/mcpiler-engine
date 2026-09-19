# File handles

An upstream response is not always text. A report endpoint answers with a PDF, an export
endpoint with a ZIP, a rendering endpoint with a PNG. Engine does not put those bytes in an
MCP result: it writes them down, issues a handle, and returns the handle.

This document is the whole contract of that store - where it puts things, what the names
mean, how long a handle lives, what happens when a write fails halfway, and what the scan
verdict on a record does and does not claim. It is written for an operator deciding where
to point the root and for a reviewer deciding whether the failure behaviour is acceptable.

It also defines the HTTP transfer surface that turns a handle into an out-of-band file
capability. The routes are children of an MCP surface, not separate MCP resources:

- `POST {surface}/files/upload` streams bytes into the Engine file store and returns an opaque
  handle/capability in the JSON response;
- `GET {surface}/files/{capability}` redeems that capability and streams the stored bytes back.

The upload response contains the `handle`, sanitized `fileName`, `mediaType`, and byte `length`.
Treat the handle as opaque: do not derive scope or storage information from its characters, and do
not put file bytes in an MCP tool message. Upload and download bytes travel over these HTTP routes.

Both routes inherit the parent surface's authorization contract in `file` and `managed` mode. Each
request needs a bearer token when the parent mount is protected; the token audience is the exact
canonical parent resource, required scopes come from the parent surface, and an unauthenticated
request receives a protected-resource metadata challenge for the parent. The child URL is never an
alternate audience. A capability is scoped to the parent resource and is authorized again on every
download; unknown, expired, or cross-scope capabilities are refused without returning bytes.

Successful downloads preserve the stored media type and exact bytes, set
`X-Content-Type-Options: nosniff`, and set `Content-Disposition: attachment`.

- Implementation: `src/MCPiler.Engine/Execution/Files/FileHandleStore.cs`
- Options and the reference type: `src/MCPiler.Engine/Execution/FileHandleStoreOptions.cs`,
  `src/MCPiler.Engine/Execution/FileHandleReference.cs`

## Contents

1. [HTTP transfer contract](#http-transfer-contract)
2. [The root](#the-root)
3. [Names](#names)
4. [What a record holds](#what-a-record-holds)
5. [Write order and what a failure leaves](#write-order-and-what-a-failure-leaves)
6. [Lifetime and expiry](#lifetime-and-expiry)
7. [Removal and the sweep](#removal-and-the-sweep)
8. [Refusals](#refusals)
9. [Scan verdicts](#scan-verdicts)
10. [What the store is not](#what-the-store-is-not)

## HTTP transfer contract

### Upload

Send the file bytes as the request body. The optional `fileName` query value is retained as
sanitized metadata; the `Content-Type` header supplies the declared media type. The request must
carry the parent surface's bearer token when that mount is protected:

```http
POST /api/petstore/files/upload?fileName=report.pdf HTTP/1.1
Authorization: Bearer <parent-resource-token>
Content-Type: application/pdf

<file bytes>
```

The successful JSON response is a handle, not the file content:

```json
{
  "handle": "<opaque-capability>",
  "fileName": "report.pdf",
  "mediaType": "application/pdf",
  "length": 1234
}
```

Pass the opaque `handle` to an operation that expects a file reference or retain it for a later
download. It is not a filename, a storage path, or a bearer token.

### Download

Redeem the handle beneath the same parent surface with a bearer token for that parent resource:

```http
GET /api/petstore/files/<opaque-capability> HTTP/1.1
Authorization: Bearer <parent-resource-token>
```

The response body is the exact stored byte sequence. `Content-Type` is the stored media type,
`Content-Length` is the stored length, `X-Content-Type-Options` is `nosniff`, and
`Content-Disposition` is `attachment`.

### Parent-resource authorization

`/files/upload` and `/files/{capability}` inherit the parent MCP surface's protected-resource
identity. This means the same canonical parent resource controls:

1. the token audience;
2. the required scopes;
3. the `401` `resource_metadata` challenge; and
4. the authorization context used to issue or redeem the capability.

The child URL is not independently discoverable or authorizable. File and managed mode use this
same contract. In managed mode, the parent is the surface admitted for the current request; an
activation that happens while authorization or streaming is in progress cannot move that request to
another generation.

## The root

One directory holds everything. It is configured, not derived, and it is checked when the
store is constructed rather than on first use - a root that cannot be used is a deployment
mistake, and discovering it during the first execution that happens to produce a file would
report it as an execution failure instead.

Three conditions are verified, and each one refuses separately:

| Condition | Why |
|---|---|
| The directory exists | A store that created its own root would happily invent one at a typo'd path and look healthy. |
| The directory is writable | Verified by writing and deleting a probe file, because permission models differ per platform and per privilege level and asking the filesystem is more reliable than reasoning about it. |
| The directory does not overlap a directory the process serves | Checked in both directions. A store inside a served root publishes every payload; a served root inside the store publishes the store. |

The root is normalized before any of this, and every path the store later resolves is
normalized and required to sit under it. Containment is checked after normalization, never
before: `a/./b/../b` and `a/b` are the same location, and a check that ran first would be
comparing text rather than places.

## Names

Storage names are generated from 32 bytes of entropy and rendered as lower-case hex. They
are never derived from a filename the upstream declared.

That single decision removes an entire category of question. A declared name may contain a
traversal sequence, a path separator belonging to some other platform, a drive letter, a
reserved device name, a control character or a trailing dot - and none of it matters,
because the path the store writes to was built from entropy before the declared name was
ever looked at.

The declared name is still kept, as a record field, so a client can be told what the
upstream called the payload. It is sanitized for that purpose alone: everything up to the
last separator is dropped, control characters are removed, trailing dots and spaces are
trimmed, and an empty result becomes `download`. Sanitizing it makes echoing it safe. It is
not what makes the path safe; nothing about the path depends on it.

Unguessability matters because a handle identifier is a capability. Two files in one store
belong to different executions and, later, to different callers, and an identifier that
could be enumerated would let one read the other's payload by counting.

## What a record holds

Beside each content file sits a JSON record under the same identifier. It carries eight
fields plus two verdicts:

| Field | Meaning |
|---|---|
| `id` | The handle. Also the storage name. |
| `fileName` | The sanitized declared name, for echoing. |
| `mediaType` | The declared media type. |
| `length` | Byte length as written. |
| `contentHash` | SHA-256 over the content, lower-case hex. |
| `storagePointer` | The content file's name within the root. |
| `scope` | The execution the handle belongs to. |
| `expiresAtUtc` | When the handle stops resolving, or absent when it does not expire. |
| `scanVerdict` | What a scanner said, or that none ran. See below. |
| `signatureVerdict` | Whether the leading bytes agree with the declared media type. |

The record is the index. Every read starts from it, which is what makes content without a
record unreachable rather than merely untidy.

## Write order and what a failure leaves

A filesystem offers ordering and nothing else. There is no transaction, so the ordering is
the safety argument.

Admission writes **content first, then the record**. Removal deletes **the record first,
then the content**. Both orders exist for the same reason: at every point where the process
can stop, the state that remains must be one the store can honour.

| Interruption | What remains | Is it a problem |
|---|---|---|
| After content, before the record | Content with no record | No. Nothing can reach it - every read starts from a record - and the sweep reclaims it. |
| After the record, before content is deleted | A record whose content is gone | Yes, and this is why removal deletes the record first: this state is never produced. |
| After the record is deleted, before content is | Content with no record | No. Same as the first row. |

The invariant, stated once: **there is never a record whose content is absent.** A handle a
caller holds either resolves or is reported as gone. It never half-resolves.

Orphan content is permitted, reclaimable and unreachable. That is a deliberate trade: the
alternative would be a two-phase protocol on a filesystem that does not offer one.

## Lifetime and expiry

A handle's lifetime comes from the governing file policy. The record stores the resulting
instant, not the duration, so the deadline does not move when the policy is edited or when
the process restarts.

Expiry is enforced **on every read**, not only by the sweep. This matters more than it
looks: a sweep is a background pass, it may be disabled, delayed, or simply not have run
yet, and an expiry enforced only there would mean the actual lifetime of a handle is
whenever the sweep next happened to look. Reading an expired handle reports expiry - a
distinct outcome from not-found, because "it existed and its time ran out" and "there was
never such a handle" call for different responses from a caller.

A lifetime of zero or less means the handle does not expire at all. That is a real
configuration and not a degenerate one: a deployment whose payloads are consumed
immediately and whose root is a container-local scratch directory has nothing to gain from
a timer.

## Removal and the sweep

Removal deletes the record and the content together, and it is auditable: every issue,
redemption, expiry, removal and reclamation is offered to an audit sink when one is
configured.

The sweep is the reclaim path, and it handles four cases:

- a record whose lifetime has passed - removed;
- a record whose content is absent - removed, because the invariant says this should not
  exist and leaving it would make a handle that reports available and then fails;
- a record that cannot be parsed - removed, for the same reason;
- content with no record, older than the grace period - removed.

The grace period exists because content is written before its record, so orphan content is
the normal appearance of an admission still in progress. A sweep with no grace would race
the writer and delete a payload the caller is about to be handed.

## Refusals

The store refuses a payload rather than storing it when:

- it exceeds the configured size ceiling, which is enforced **while streaming**, not after
  buffering - a ceiling checked after the fact spends exactly the memory it exists to
  protect;
- its leading bytes contradict the declared media type and the policy rejects that;
- a configured scanner reports it as infected;
- a resolved path would fall outside the root.

Every one of these is a classified execution failure, not an exception escaping the
execution path. The distinction is visible to a caller: a refusal arrives as a result that
names the file runtime as the cause, alongside the response status and headers that were
already observed, rather than as a transport fault that discards them.

## Scan verdicts

A verdict records what a scanner said. With no scanner configured, the record says
**`NotScanned`**.

This is the point of the field. Recording `Clean` when nothing scanned conflates "a scanner
looked and found nothing" with "nobody looked", and the two claims are not
interchangeable - the first is evidence and the second is its absence. A deployment that
later wants to prove its payloads were scanned can distinguish them; a store that wrote
`Clean` by default would have destroyed that ability at the moment it was needed.

The signature verdict is separate and deliberately so. Comparing leading bytes against a
declared media type is a cheap structural check with three outcomes - agrees, contradicts,
nothing to say - and it is not a scan. Folding it into the scan verdict would let a
content-type check masquerade as evidence about content safety.

## What the store is not

It is not a database. There is no relational schema, no query surface and no index beyond
the records themselves; a handle is looked up by identifier and by nothing else.

It is not a transfer surface. Issuing a handle and redeeming one over a wire are separate
concerns, and this store does only the first. Per-request authorization and cross-scope
rejection belong to whatever exposes handles to a client, and are not implemented here.

It is not a cache. Nothing here is derived from anything else, so nothing can go stale
against an authority. The content is the authority for as long as the handle lives.
