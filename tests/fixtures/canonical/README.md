# Canonical JSON byte contract fixtures

These fixtures pin the exact bytes of the canonical JSON representation used whenever a
manifest is sealed, hashed or compared.

## Why this directory exists in two repositories

The MCPiler Platform and the MCPiler Engine each implement the canonical writer
independently: Engine must build from a standalone checkout and can never reference
Platform code. Two independent implementations of a byte contract silently drift, and the
drift is only observable as a hash mismatch on a customer's manifest long after the fact.

The same fixture set therefore lives in both repositories and both test suites assert
against the same expected digests. If either implementation changes behavior, one of the two
suites fails immediately.

`expected-canonical.json` was generated from the Platform writer, which is the byte
authority because its digests already exist in production data.

## Files

| File | Meaning |
| --- | --- |
| `NN-name.input.json` | Authored input. Formatting, member order and indentation are deliberately non-canonical. |
| `NN-name.canonical.json` | The exact canonical output. Single line, no trailing newline. |
| `expected-canonical.json` | Canonical byte count and SHA-256 hex digest per input fixture. |

`.gitattributes` disables end-of-line normalization for this directory. The canonical files
contain no newline at all, but a future fixture might, and a CRLF conversion would silently
change every digest.

## What each fixture proves

| Fixture | Property under test |
| --- | --- |
| `01-member-order` | Member sorting at every depth, including the empty member name, digits, case sensitivity, underscore, a non-ASCII name, a non-BMP name and a private-use name. |
| `02-numbers` | Lexical preservation of numeric tokens: `1.0`, `1.50`, `1e3`, `1E+2`, `-0`, `0.010`, and an integer beyond IEEE-754 exact range. |
| `03-strings-and-escapes` | String escaping, including HTML-sensitive characters, control characters, `U+007F`, `U+2028`/`U+2029`, surrogate pairs, and the fact that a precomposed and a combining sequence are distinct. |
| `04-structure` | Empty object, empty array, `null`, booleans, and the rule that array order is semantic and is never sorted. |
| `05-deep-nesting` | 64 levels of alternating object and array nesting, well inside the depth limit of 1000. |
| `06-manifest-shaped` | A realistic manifest root with inline and external sections, a schema component space, and a `provenance` object. |

## Two deliberate divergences from RFC 8785

`01-member-order` proves the first and `02-numbers` and `03-strings-and-escapes` prove the
second.

1. **Member ordering is UTF-16 code-unit ordinal**, which is what RFC 8785 specifies. Note
   that this is *not* UTF-8 byte order: in `01-member-order` the non-BMP emoji name sorts
   before the private-use `U+E000` name, because the leading surrogate `U+D83D` is below
   `U+E000` in UTF-16 while the emoji's UTF-8 bytes are above `U+E000`'s. Any implementation
   that sorts by UTF-8 bytes will fail this fixture.
2. **Numbers keep their original token and non-ASCII characters are escaped.** RFC 8785
   requires ES6 number formatting and minimal escaping. MCPiler preserves the lexical number
   token because manifest schemas carry upstream numeric bounds whose exact spelling must
   survive a round trip, and it escapes non-ASCII because the existing MCPiler canonical
   writer has always done so and byte agreement with already-sealed documents is a hard
   requirement.

Do not "fix" either divergence toward strict RFC 8785 without a new decision record: doing
so changes the digest of every manifest and of every already-pinned Platform document.

## Regenerating

Do not regenerate to make a failing test pass. A digest change means the canonical
representation changed, which is a format-version-level change per ADR-0053 §8. Change the
decision record first.
