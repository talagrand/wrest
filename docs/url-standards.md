# URL Standards

## The Two Standards

There are two URL standards. In this document, **RFC** is used as a shorthand
meaning the standard set by RFC 3986 and RFC 3987 together, in contrast to **WHATWG**.

### RFC 3986 and RFC 3987 (IETF)

[RFC 3986 — Uniform Resource Identifier (URI): Generic Syntax](https://www.rfc-editor.org/rfc/rfc3986)
The *de jure* standard referenced by most protocol specifications, HTTP RFCs,
and server-side software.

[RFC 3987 — Internationalized Resource Identifiers (IRIs)](https://www.rfc-editor.org/rfc/rfc3987)
extends that model to Unicode and defines how IRIs map to ASCII URIs. It does
not select an IDNA policy for Unicode domain names.

- **Defines a formal grammar** for valid URIs and IRIs.  Input that does not
  match the grammar is invalid; the RFCs do not define what a parser should do
  with it.
- **Used by**: server-side frameworks, Java's `java.net.URI`, Go's `net/url`,
  Rust's `http::Uri`, API specifications, protocol RFCs.
- **Normalization**: SHOULD lowercase scheme (§3.1), SHOULD uppercase hex digits
  in percent-encoding (§6.2.2.1).  Dot-segment resolution (§5.2.4) is required
  only during relative reference resolution — not during parsing of absolute
  URIs.

### WHATWG URL Standard (living document, 2012–present)

[WHATWG URL Standard](https://url.spec.whatwg.org/)

RFC does not define error recovery for invalid input, leading to divergent
behavior across implementations — especially browsers, each of which developed
its own quirks.  The WHATWG URL Standard standardizes results for invalid URL
handling as well, defining precise behavior for every possible input string.

- **Recovery and special-host processing**: WHATWG accepts many strings that
  are invalid under RFC, but can reject or reinterpret some RFC-valid
  registered names.
- **Used by**: all browsers (Chrome, Firefox, Safari, Edge), Rust's `url` crate,
  reqwest, Python's `urllib.parse` (partially), Node.js's `new URL()`.
- **Covers**: relative URL resolution, IDNA via Unicode UTS #46, precise
  percent-encode sets per component, legacy IPv4 parsing and serialization,
  backslash-as-slash for "special" schemes, tab/newline stripping,
  forbidden host code point rejection.
- **Official test suite**: [web-platform-tests/wpt/url/](https://github.com/web-platform-tests/wpt/tree/master/url),
  with the canonical test data in
  [`urltestdata.json`](https://github.com/web-platform-tests/wpt/blob/master/url/resources/urltestdata.json).
  The test data does not distinguish which inputs are RFC-valid; it specifies
  only the expected WHATWG result.

### Relationship Between the Two

RFC defines valid URI/IRI syntax and is a common basis for protocol,
server-side, and other non-browser URL handling. WHATWG builds on the same
component model with additional browser-oriented recovery, canonicalization,
and special-host policy.

Most ordinary well-formed HTTP(S) URLs have the same component meaning in both
models. Interoperable software generally stays within this shared subset.
Differences concentrate in malformed browser input, legacy numeric host
syntax, and a small set of registered names affected by WHATWG's special-host
policy.

## Semantic Differences and Impact

| Operation | RFC | WHATWG | Impact |
|-----------|-----|--------|--------|
| Splitting scheme, authority, path, query, and fragment | Defined by grammar | Defined by parser states | Shared legal forms generally produce the same components |
| Invalid-input recovery | Not defined | Defined for every input | Input accepted by `url::Url` can be rejected by an RFC parser |
| Scheme lowercasing | Recommended (§3.1) | Required | Serialization can differ without changing identity |
| Dot-segment resolution (`/a/../b` → `/b`) | During relative resolution (§5.2.4) | Also during special-URL parsing | Absolute paths can serialize differently |
| `%2e` / `%2E` treated as a dot segment | Not during parsing | Yes for special URLs | Resource paths can differ |
| Registered-name validation | Allows unreserved characters, sub-delimiters, and percent-encoded octets | Percent-decodes before special-host validation | An RFC-valid host can be rejected after decoding |
| Numeric hosts | Dotted-decimal IPv4 or registered name | Legacy decimal, octal, hexadecimal, and shortened IPv4 | The same spelling can select a domain or an IP address |
| Port validation | Syntax permits digits; meaning is scheme-specific | Rejects values above 65535 and removes defaults | Acceptance and serialization can differ |
| Tab/newline stripping | Invalid | Stripped silently | Visually different input can become the same URL |
| Backslash as slash | Invalid | Applied to special schemes | `http:\\host\path` becomes an HTTP URL only under WHATWG |
| Relative URL resolution | Defined (§5) | Defined by the browser algorithm | Shared cases align; recovery cases can differ |
| Unicode domains | RFC 3987 plus a separate IDNA policy | Nontransitional UTS #46 | Different IDNA generations can select different domains |
| Empty query or fragment | Present-but-empty differs from absent | Same distinction | `?` clears an inherited query; absence inherits it |

### Where Differences Are Observable

- **Destination identity**: unusual IDNA or numeric-host spellings can be
  interpreted differently.
- **Resource identity**: dot-segment and percent-encoding behavior can change
  the request path.
- **Acceptance**: browser-oriented code may accept input that a strict RFC
  parser rejects.
- **Serialization**: case, default ports, and empty components can differ even
  when two URLs refer to the same resource.

Most software encounters conventional hostnames for which these policies
agree. The differences matter primarily for browser recovery cases, legacy
spellings, or inputs deliberately constructed around edge syntax. RFC leaves
IDNA policy to the implementation, while WHATWG specifies nontransitional
UTS #46.

Legacy numeric hosts are another narrow difference. WHATWG interprets
`192.0x00A80001` as `192.168.0.1`; an RFC parser can retain it as a registered
name. WHATWG rejects invalid numeric-looking hosts such as `256.0.0.1` rather
than treating them as registered names.

## WHATWG Test Suite vs RFC

Wrest checks the WHATWG `urltestdata.json` corpus to ensure equivalent behavior
where the RFC and WHATWG models overlap. Cases that depend on WHATWG recovery
or special-host policy are not treated as RFC conformance failures.

The underlying `fluent-uri` and ICU libraries provide RFC 3986/3987 and
UTS #46 conformance respectively. Wrest's focused tests cover the policy and
integration behavior it adds around those libraries.

## Wrest Implementation

Wrest uses:

1. [`fluent-uri`](https://docs.rs/fluent-uri) for RFC parsing, component
   validation, and reference resolution;
2. Windows system ICU for nontransitional UTS #46 processing of Unicode
   registered names; and
3. WinHTTP for transport after the URL has been separated into host, port,
   path, and query.

Wrest deliberately implements the established RFC model used by protocol and
server-side software rather than WHATWG's additional browser recovery. For
the conventional HTTP(S) forms shared by both models, component and request
behavior align. Wrest preserves existing percent escapes in path, query, and
fragment components and distinguishes empty query and fragment components from
absent ones. Registered-name host escapes are decoded and checked against
`fluent-uri`'s rules before Wrest rebuilds the URL.

Unicode domains are converted lazily with system ICU. If ICU is unavailable,
Unicode domain parsing returns `ParseError::IdnaError`. ASCII registered names
bypass ICU, including `xn--` spellings that WHATWG would validate as A-labels.

Wrest sanitizes userinfo during parsing: accessors expose decoded credentials,
and serialized URLs omit them. Request construction converts the credentials
into `Authorization: Basic`. Reqwest reaches the same request behavior but
retains encoded userinfo in `url::Url` until it builds the request.

The native URL type accepts only `http` and `https` because WinHTTP is the
transport.

### Platform API Choices

`WinHttpCrackUrl` is not used for parsing because it does not validate URL
syntax, resolve references, or perform IDNA processing. Its encoding flags
also either decode existing escapes or escape the percent sign again.

Wrest does not fall back to Win32 `IdnToAscii`: it maps `faß.de` to `fass.de`,
while UTS #46 maps it to `xn--fa-hia.de`. Those are different destinations.
