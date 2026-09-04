# WWWAuthenticateTools

Parser and Builder classes for dealing with the WWW-Authenticate HTTP header.

This is the C# port of a planned cross-language library (C#/Python/TypeScript)
for parsing and generating `WWW-Authenticate`, `Proxy-Authenticate`,
`Authorization`, and `Proxy-Authorization` header values, per RFC 9110
§11.6.1 and §11.3. The library works purely at the string level — no
dependency on any HTTP framework.

## 🗂️ Project Layout

- `billpg.WWWAuthenticateTools/` — the library itself. Target framework is
  `netstandard2.0` for broad compatibility.
- `billpg.WWWAuthenticateToolsTests/` — MSTest unit tests. Per project
  convention, test assemblies are named `billpg.(project)Tests`.
- `billpg.WWWAuthenticateTools/billpg.WWWAuthenticateTools.slnx` — the
  solution file, referencing both projects.

## 🚀 Getting Started

```bash
dotnet build billpg.WWWAuthenticateTools/billpg.WWWAuthenticateTools.slnx
dotnet test billpg.WWWAuthenticateTools/billpg.WWWAuthenticateTools.slnx
```

## 📦 API Overview

The data model is immutable throughout: `Challenge` (one `auth-scheme` plus
either a `token68` or an ordered list of name/value params) and `AuthHeaders`
(an ordered collection of `Challenge`).

Build headers with the fluent builder — each call returns a new instance, and
`WithParam`/`WithToken68` apply to whichever scheme was added most recently:

```csharp
var auth = new AuthHeaders()
    .WithScheme("HashBack")
    .WithParam("version", "RFC12345")
    .WithScheme("Basic")
    .WithParam("realm", "example");
```

Generate header text from a model:

```csharp
auth.ToSingleHeaderValue();      // "HashBack version=RFC12345, Basic realm=example"
auth.ToHeaderLines();            // one string per challenge
```

Parse raw header values back into a model. The entry point takes one string
per actual header line received (not a single pre-joined string), since
WWW-Authenticate is one of the header fields that can't always be safely
combined by comma-joining multiple instances:

```csharp
var parsed = ParseHeader.Parse(["Basic realm=example"], strict: true);
```

## ⚠️ Exceptions

Every exception carries a stable string `Code`, which is the cross-language
contract other ports of this library will also use (message text is not):

- `AuthHeaderException` — abstract base.
- `AuthHeaderParseException` — malformed input during parsing; also carries
  `HeaderLineIndex` and `CharacterPosition`.
- `AuthHeaderBuilderException` — invalid use of the fluent builder.

The documented codes live in `AuthHeaderErrorCodes`: `no_current_scheme`,
`duplicate_param`, `token68_param_conflict`, `invalid_token68`,
`invalid_auth_param`, `unterminated_quoted_string`, `unexpected_comma`.

## 🚧 Status

Implemented: the data model, immutable fluent builder, exception taxonomy,
generator, and a **strict-mode** parser for RFC-conformant input.

Not yet implemented:
- Lenient-mode parsing (the `strict: false` documented deviations for
  real-world-but-spec-violating input) — currently behaves identically to
  strict mode.
- The shared `auth-header-test-vectors` submodule repo.
- Python and TypeScript ports.

## 🎯 Design Notes

- Params are kept in an ordered list, not a dictionary, so round-tripping
  preserves the original order even though lookups are logically
  case-insensitive by name.
- The builder does not re-validate RFC token grammar (that's the parser's
  job for untrusted input) — it only enforces structural invariants: a
  scheme must exist before `WithParam`/`WithToken68`, param names must be
  unique per challenge, and `WithParam`/`WithToken68` are mutually exclusive
  on the same challenge.
- Parsing a challenge's second word (right after the scheme) is ambiguous
  between a `token68` and the first `auth-param` — e.g. `Bearer abc123==`
  vs `Digest realm=example`. The parser resolves this the same way for
  every subsequent comma-separated item too: an auth-param is always
  `token BWS "=" BWS value`, so anything that isn't genuinely shaped that
  way (including a token68's own trailing `==` padding, which isn't a real
  `name=value` split) is treated as a new challenge or a token68 instead.
