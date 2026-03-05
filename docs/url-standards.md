# URL Standards

## The Two Standards

There are two URL standards:

### RFC 3986 (2005, IETF)

[RFC 3986 — Uniform Resource Identifier (URI): Generic Syntax](https://www.rfc-editor.org/rfc/rfc3986)
superseded the earlier RFC 2396 (1998) and remains the *de jure* standard
referenced by most protocol specifications, HTTP RFCs, and server-side software.

- **Defines a formal grammar** for valid URIs.  Input that does not match the
  grammar is invalid; the RFC does not define what a parser should do with it.
- **Used by**: server-side frameworks, Java's `java.net.URI`, Go's `net/url`,
  Rust's `http::Uri`, API specifications, protocol RFCs.
- **Normalization**: SHOULD lowercase scheme (§3.1), SHOULD uppercase hex digits
  in percent-encoding (§6.2.2.1).  Dot-segment resolution (§5.2.4) is required
  only during relative reference resolution — not during parsing of absolute
  URIs.

### WHATWG URL Standard (living document, 2012–present)

[WHATWG URL Standard](https://url.spec.whatwg.org/)

RFC 3986 did not define error recovery for invalid input, leading to divergent
behavior across implementations — especially browsers, each of which developed
its own quirks.  The WHATWG URL Standard standardizes results for invalid URL
handling as well, defining precise behavior for every possible input string.

- **Superset of RFC 3986**: every RFC-3986-valid HTTP/HTTPS URL is accepted by
  WHATWG with the same parsed result.  WHATWG additionally defines error recovery
  for invalid input — what RFC 3986 leaves as undefined behavior.
- **Used by**: all browsers (Chrome, Firefox, Safari, Edge), Rust's `url` crate,
  reqwest, Python's `urllib.parse` (partially), Node.js's `new URL()`.
- **Covers**: relative URL resolution, IDNA via Unicode UTS46, precise
  percent-encode sets per component, IPv4/IPv6 parsing and serialization,
  backslash-as-slash for "special" schemes, tab/newline stripping,
  forbidden host code point rejection.
- **Official test suite**: [web-platform-tests/wpt/url/](https://github.com/web-platform-tests/wpt/tree/master/url),
  with the canonical test data in
  [`urltestdata.json`](https://github.com/web-platform-tests/wpt/blob/master/url/resources/urltestdata.json)
  (984 test cases as of February 2026).  The test data does not distinguish
  which inputs are RFC-3986-valid; it only specifies expected WHATWG parser
  output.

### Relationship between the two

RFC 3986 defines a formal grammar for valid URIs.  WHATWG is a strict superset:
it accepts every RFC-3986-valid URL and additionally defines deterministic
behavior for invalid input that the RFC leaves undefined.  For valid input, both
standards produce the same parsed result.

## WinHTTP's URL Parser

[`WinHttpCrackUrl`](https://learn.microsoft.com/en-us/windows/win32/api/winhttp/nf-winhttp-winhttpcrackurl)
splits URLs into components.  In practice, WinHTTP implements RFC 3986 for valid
URLs — all well-formed HTTP/HTTPS URIs are parsed correctly, producing the same
components as both the RFC and WHATWG standards.

Where WinHTTP differs is in error handling.  For invalid input, WinHTTP's
behavior diverges from both RFC 3986 (which leaves it undefined) and WHATWG
(which defines specific error recovery).  WinHTTP tends to be **more
permissive** than either standard, accepting many forms of invalid input without
erroring.  As Microsoft's own documentation states: "WinHttpCrackUrl does not
check the validity or format of a URL before attempting to crack it."

| Operation | RFC 3986 | WHATWG | WinHTTP |
|-----------|----------|-------|---------|
| Splitting (scheme, host, port, path, query, fragment) | ✅ | ✅ | ✅ |
| Scheme lowercasing | SHOULD (§3.1) | ✅ | ✅ (case-insensitive matching) |
| Dot-segment resolution (`/a/../b` → `/b`) | Only for relative resolution (§5.2.4) | ✅ (always) | ❌ returns `/a/../b` |
| `%2e` / `%2E` treated as `.` for dot-segments | ❌ | ✅ | ❌ |
| Host validation (reject forbidden chars) | ✅ (§3.2.2) | ✅ | ❌ accepts anything |
| Port validation (reject >65535, negative) | ✅ (§3.2.3) | ✅ | Partial |
| Percent-encoding normalization | SHOULD (§6.2.2.1) | ✅ (component-aware) | ❌ |
| Tab/newline stripping | ❌ (invalid) | ✅ (strip silently) | ❌ (rejects) |
| Backslash as slash (special schemes) | ❌ (invalid) | ✅ | ❌ (rejects) |
| Relative URL resolution | ✅ (§5) | ✅ | ❌ |
| IDNA (internationalized domains) | Defers to RFC 3490 | ✅ (UTS46) | ❌ |
| NUL byte handling | N/A | Encodes as `%00` | Truncates (C-string) |
| Userinfo extraction for HTTP | Preserved | Preserved | Stripped silently |

### WinHTTP-specific quirks

These behaviors match neither standard:

- Accepts `[www.google.com]` as a host (both standards say brackets are only for
  IPv6 addresses).
- Accepts C0 control characters (U+0000–U+001F) literally in hostnames.
- Silently strips userinfo (`user:pass@`) from HTTP/HTTPS URLs.
- Truncates at NUL byte (C-string semantics).

## Percent-Encoding

### The non-idempotency problem

Percent-encoding is **intentionally non-idempotent** by design.  A `%2F` in a
URL path is a *literal encoded slash* — semantically different from `/`, which is
a path separator:

```
/api/v1/a%2Fb        ← 3 segments: "api", "v1", "a/b"
/api/v1/a/b          ← 4 segments: "api", "v1", "a", "b"
```

If a parser decoded `%2F` to `/` and then re-encoded, the URL would change from
3 segments to 4 — the meaning is destroyed.  This is why the WHATWG standard
**never** decodes-then-re-encodes URL components.  It only encodes *raw* unsafe
bytes while preserving existing `%XX` sequences.

### WHATWG percent-encode sets

The WHATWG standard defines component-specific sets of bytes that must be
percent-encoded (§1.3).  Each set is a superset of the C0 control percent-encode
set (bytes 0x00–0x1F and >0x7E):

| Encode set | Additional bytes encoded | Used for |
|------------|------------------------|----------|
| **C0 control** | (base set) | Opaque paths |
| **Fragment** | SPACE `"` `<` `>` `` ` `` | Fragment |
| **Query** | SPACE `"` `#` `<` `>` | Query (non-special schemes) |
| **Special-query** | Query set + `'` | Query (http, https, etc.) |
| **Path** | Query set + `?` `^` `` ` `` `{` `}` | Path |
| **Userinfo** | Path set + `/` `:` `;` `=` `@` `[` `\` `]` `|` | Username, password |

**Key property**: none of these sets (as used by the URL parser) include `%`
itself.  This means existing `%XX` sequences pass through untouched — there is
no double-encoding.  The WHATWG spec explicitly notes:

> "Of the possible values for the percentEncodeSet argument only two end up
> encoding U+0025 (%) and thus give round-trippable data: component
> percent-encode set and application/x-www-form-urlencoded percent-encode set.
> The other values — which happen to be used by the URL parser — leave U+0025 (%)
> untouched."

## WHATWG Test Suite vs WinHTTP

The WHATWG
[`urltestdata.json`](https://github.com/web-platform-tests/wpt/blob/master/url/resources/urltestdata.json)
contains 984 test cases.  Filtering to absolute `http://` and `https://` URLs
without base URL resolution yields 263 applicable test cases.

Every RFC-3986-valid URL in the test suite is correctly parsed by WinHTTP.  The
divergences are entirely in how each handles **invalid or edge-case input**:

### WinHTTP is more accepting than WHATWG (145 cases)

These are URLs that WHATWG **rejects** but WinHTTP **accepts**.  WinHTTP's
permissiveness here extends into territory that both RFC 3986 and WHATWG consider
invalid.

| Category | Count | Examples |
|----------|-------|---------|
| Forbidden host code points (literal C0 controls) | 34 | `http://a\x01b/` |
| Forbidden host code points (percent-encoded, decoded by WHATWG before host validation) | 32 | `http://ho%00st/`, `http://ho%20st/` |
| IPv4 overflow, octal, trailing dot | 16 | `https://256.0.0.1/`, `http://1.2.3.08` |
| Numeric-suffix hosts (WHATWG tries IPv4 parse, fails) | 12 | `http://foo.1.2.3.4`, `http://foo.09` |
| Brackets around non-IPv6 host | 10 | `http://[www.google.com]/` |
| Degenerate URLs (empty host, `?`-only, `#`-only, `///`) | 8 | `http://?`, `http://#`, `https:///` |
| Invalid IDNA / punycode | 7 | `http://a.b.c.xn--pokxncvks` |
| Raw forbidden chars in host | 7 | `http://a<b`, `http://a>b`, `http://a b/` |
| Missing host after credentials | 5 | `http://user:pass@/`, `http://@/www.example.com` |
| Unicode / replacement char in host | 5 | `https://💩.123/`, `https://\uFFFD` |
| Other (port-with-no-host, soft hyphen) | 9 | `http://@:www.example.com`, `https://%C2%AD/` |

### WinHTTP is more restrictive than WHATWG (28 cases)

These are URLs that WHATWG **accepts** (as error recovery for invalid input) but
WinHTTP **rejects** or **misparses**.

| Category | Count | Fixable? | Examples |
|----------|-------|----------|---------|
| Dot-segment resolution not performed | 15 | ✅ post-process | `/foo/bar/../ton` → should be `/foo/ton` |
| `%2e` / `%2E` not treated as dot-segment | 5 | ✅ pre-process | `/foo/%2e` → should be `/foo/` |
| Scheme-only URLs (no `//`) | 4 | ⚠ heuristic | `http:example.com/` → should resolve |
| Tab/newline not stripped | 2 | ✅ pre-process | `h\tt\np://host/` → should be `http://host/` |
| Backslash not normalized to slash | 1 | ✅ pre-process | `http:\\host\path` → should be `http://host/path` |
| NUL byte truncation | 1 | ❌ C-API limit | `https://x/\0y` → should be `https://x/%00y` |

23 of 28 cases are formally fixable with pre/post-processing around WinHTTP.
4 require heuristics (scheme-only URLs are arguably relative URL resolution,
which is out of scope for an HTTP client).  1 is a fundamental C-API limitation.
