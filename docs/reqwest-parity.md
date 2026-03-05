# wrest ↔ reqwest 0.13 Parity

Exhaustive API-by-API comparison of reqwest 0.13 (all features enabled)
vs wrest, covering both capabilities and gaps.
Each row is a single public API item. Status meanings:

- ✅ — implemented and functional
- 🔇 — accepted as a no-op (behind `noop-compat`)
- 🔒 — cannot implement (WinHTTP / platform limitation)
- 💤 — not yet implemented (feasible, future work)
- N/A — not applicable to wrest (concept doesn't exist)

---

## Public Re-exports & Free Functions

| Item | reqwest | wrest | Status | Notes |
|------|---------|-------|--------|-------|
| `Client` | ✓ | ✓ | ✅ | |
| `ClientBuilder` | ✓ | ✓ | ✅ | |
| `Request` | ✓ | ✓ | ✅ | |
| `RequestBuilder` | ✓ | ✓ | ✅ | |
| `Response` | ✓ | ✓ | ✅ | |
| `Body` | ✓ | ✓ | ✅ | |
| `Error` / `Result` | ✓ | ✓ | ✅ | |
| `Url` | ✓ | ✓ | ✅ | reqwest re-exports `url::Url`; wrest provides its own `Url` type backed by `WinHttpCrackUrl`. For WHATWG/RFC 3986 error recovery differences, see **Url Methods** section  |
| `Method` | ✓ | ✓ | ✅ | |
| `StatusCode` | ✓ | ✓ | ✅ | |
| `Version` (http) | ✓ | ✓ | ✅ | |
| `HeaderMap` / `header` module | ✓ | ✓ | ✅ | |
| `IntoUrl` trait | ✓ | ✓ | ✅ | |
| `ParseError` | — | ✓ | ✅ | reqwest does not re-export `url::ParseError`; wrest provides it on the native backend and the reqwest passthrough so `wrest::ParseError` always works |
| `Proxy` | ✓ | ✓ | ✅ | |
| `NoProxy` | ✓ | ✓ | ✅ | |
| `get()` free function | ✓ | ✓ | ✅ | |
| `Upgraded` | ✓ | — | 💤 | |
| `ResponseBuilderExt` trait | ✓ | — | 💤 | |
| `Certificate` | ✓ | — | 🔒 | WinHTTP uses OS cert store |
| `Identity` | ✓ | — | 🔒 | WinHTTP uses OS cert store |

## Public Modules

| Module | reqwest | wrest | Status | Notes |
|--------|---------|-------|--------|-------|
| `redirect` | ✓ | ✓ | ✅ | `Policy::custom()` missing — WinHTTP handles redirects |
| `proxy` | ✓ | ✓ | ✅ | |
| `header` | ✓ | ✓ | ✅ | re-export of `http::header` |
| `blocking` | ✓ | — | 💤 | async only |
| `cookie` | ✓ | — | 💤 | |
| `dns` | ✓ | — | 🔒 | WinHTTP manages DNS |
| `multipart` | ✓ | — | 💤 | |
| `tls` | ✓ | — | 🔒 | WinHTTP always uses SChannel |
| `retry` | ✓ | ✓ | ✅ | |

## Traits & Impls

| Item | reqwest | wrest | Status | Notes |
|------|---------|-------|--------|-------|
| `impl Service<Request> for Client` | ✓ | — | 💤 | Tower integration |
| `impl Service<Request> for &Client` | ✓ | — | 💤 | Tower integration |
| `impl From<Response> for Body` | ✓ | ✓ | ✅ | |
| `impl From<http::Response<T>> for Response` | ✓ | — | 💤 | Requires plumbing a pre-built body through `chunk()` |
| `impl From<Response> for http::Response<Body>` | ✓ | ✓ | ✅ | |
| `impl TryFrom<http::Request<T>> for Request` | ✓ | ✓ | ✅ | |
| `impl TryFrom<Request> for http::Request<Body>` | ✓ | ✓ | ✅ | |
| `impl http_body::Body for Body` | ✓ | — | 🔒 | wrest uses WinHTTP streaming, not `http-body` trait |
| `impl ResponseBuilderExt for http::response::Builder` | ✓ | — | 💤 | |
| `impl IntoProxy for S: IntoUrl` | ✓ | — | 💤 | |
| `UnixSocketProvider` trait | ✓ | — | 🔒 | `#[cfg(unix)]` in reqwest; Windows has AF_UNIX since 1803 but WinHTTP does not expose it |
| `WindowsNamedPipeProvider` trait | ✓ | — | 🔒 | Windows named pipes; not exposed via WinHTTP |

---

## `ClientBuilder` Methods

### Timeouts

| Method | reqwest | wrest | Status | Notes |
|--------|---------|-------|--------|-------|
| `timeout()` | ✓ | ✓ | ✅ | |
| `connect_timeout()` | ✓ | ✓ | ✅ | Default **60 s** (WinHTTP); reqwest default is **None** |
| `read_timeout()` | ✓ | ✓ | ✅ | wrest maps to WinHTTP receive timeout |
| `send_timeout()` | — | ✓ | ✅ | wrest extension (not in reqwest) |

### Identity & Headers

| Method | reqwest | wrest | Status | Notes |
|--------|---------|-------|--------|-------|
| `user_agent()` | ✓ | ✓ | ✅ | |
| `default_headers()` | ✓ | ✓ | ✅ | |

### Connection

| Method | reqwest | wrest | Status | Notes |
|--------|---------|-------|--------|-------|
| `connection_verbose()` | ✓ | ✓ | ✅ | |
| `pool_idle_timeout()` | ✓ | — | 🔇 | |
| `pool_max_idle_per_host()` | ✓ | — | 🔇 | |
| `tcp_nodelay()` | ✓ | — | 🔇 | |
| `tcp_keepalive()` | ✓ | — | 🔇 | |
| `tcp_keepalive_interval()` | ✓ | — | 🔇 | |
| `tcp_keepalive_retries()` | ✓ | — | 🔇 | |
| `local_address()` | ✓ | — | 🔒 | WinHTTP manages binding |
| `interface()` | ✓ | — | 🔒 | WinHTTP manages binding |
| `max_connections_per_host()` | — | ✓ | ✅ | wrest extension via WinHTTP |

### Redirect

| Method | reqwest | wrest | Status | Notes |
|--------|---------|-------|--------|-------|
| `redirect()` | ✓ | ✓ | ✅ | `Policy::limited()` and `Policy::none()` only |
| `referer()` | ✓ | — | 💤 | |

### Proxy

| Method | reqwest | wrest | Status | Notes |
|--------|---------|-------|--------|-------|
| `proxy()` | ✓ | ✓ | ✅ | |
| `no_proxy()` | ✓ | ✓ | ✅ | |

### TLS

| Method | reqwest | wrest | Status | Notes |
|--------|---------|-------|--------|-------|
| `tls_danger_accept_invalid_certs()` / `danger_accept_invalid_certs()` | ✓ | ✓ | ✅ | |
| `tls_danger_accept_invalid_hostnames()` / `danger_accept_invalid_hostnames()` | ✓ | — | 🔒 | SChannel validates hostnames |
| `tls_version_min()` / `min_tls_version()` | ✓ | — | 🔒 | SChannel manages negotiation |
| `tls_version_max()` / `max_tls_version()` | ✓ | — | 🔒 | SChannel manages negotiation |
| `tls_sni()` | ✓ | — | 🔇 | SNI always enabled |
| `tls_info()` | ✓ | — | 💤 | |
| `tls_certs_merge()` / `add_root_certificate()` | ✓ | — | 🔒 | OS cert store |
| `tls_certs_only()` | ✓ | — | 🔒 | OS cert store |
| `tls_crls_only()` | ✓ | — | 🔒 | rustls only |
| `add_crl()` | ✓ | — | 🔒 | rustls only |
| `add_crls()` | ✓ | — | 🔒 | rustls only |
| `tls_backend_native()` / `use_native_tls()` | ✓ | ✓ | 🔇 | always SChannel |
| `tls_backend_rustls()` / `use_rustls_tls()` | ✓ | — | N/A | always SChannel |
| `tls_backend_preconfigured()` / `use_preconfigured_tls()` | ✓ | — | N/A | always SChannel |
| `identity()` | ✓ | — | 🔒 | client certs via OS store, not exposed |

### HTTP Version Preference

| Method | reqwest | wrest | Status | Notes |
|--------|---------|-------|--------|-------|
| `http1_only()` | ✓ | ✓ | ✅ | functional — disables HTTP/2 flag |
| `http2_prior_knowledge()` | ✓ | — | 🔇 | |
| `http3_prior_knowledge()` | ✓ | — | 💤 | requires explicit `WINHTTP_PROTOCOL_FLAG_HTTP3`; not enabled to avoid QUIC/UDP timeout regressions |

### HTTP/1 Tuning

| Method | reqwest | wrest | Status | Notes |
|--------|---------|-------|--------|-------|
| `http09_responses()` | ✓ | — | 🔇 | |
| `http1_title_case_headers()` | ✓ | — | 🔇 | |
| `http1_allow_obsolete_multiline_headers_in_responses()` | ✓ | — | 🔇 | |
| `http1_ignore_invalid_headers_in_responses()` | ✓ | — | 🔇 | |
| `http1_allow_spaces_after_header_name_in_responses()` | ✓ | — | 🔇 | |

### HTTP/2 Tuning

| Method | reqwest | wrest | Status | Notes |
|--------|---------|-------|--------|-------|
| `http2_initial_stream_window_size()` | ✓ | — | 🔇 | |
| `http2_initial_connection_window_size()` | ✓ | — | 🔇 | |
| `http2_adaptive_window()` | ✓ | — | 🔇 | |
| `http2_max_frame_size()` | ✓ | — | 🔇 | |
| `http2_max_header_list_size()` | ✓ | — | 🔇 | |
| `http2_keep_alive_interval()` | ✓ | — | 🔇 | |
| `http2_keep_alive_timeout()` | ✓ | — | 🔇 | |
| `http2_keep_alive_while_idle()` | ✓ | — | 🔇 | |

### HTTP/3 Tuning (`http3` + `reqwest_unstable`)

| Method | reqwest | wrest | Status | Notes |
|--------|---------|-------|--------|-------|
| `http3_max_idle_timeout()` | ✓ | — | 🔒 | HTTP/3 not enabled; requires explicit `WINHTTP_PROTOCOL_FLAG_HTTP3` opt-in |
| `http3_stream_receive_window()` | ✓ | — | 🔒 | " |
| `http3_conn_receive_window()` | ✓ | — | 🔒 | " |
| `http3_send_window()` | ✓ | — | 🔒 | " |
| `http3_congestion_bbr()` | ✓ | — | 🔒 | " |
| `http3_max_field_section_size()` | ✓ | — | 🔒 | " |
| `http3_send_grease()` | ✓ | — | 🔒 | " |
| `tls_early_data()` | ✓ | — | 🔒 | " |

### Cookie

| Method | reqwest | wrest | Status | Notes |
|--------|---------|-------|--------|-------|
| `cookie_store()` | ✓ | — | 💤 | |
| `cookie_provider()` | ✓ | — | 💤 | |

### Decompression

| Method | reqwest | wrest | Status | Notes |
|--------|---------|-------|--------|-------|
| `gzip()` | ✓ | — | 🔇 | WinHTTP decompresses automatically |
| `brotli()` | ✓ | — | 🔇 | WinHTTP only does gzip/deflate |
| `deflate()` | ✓ | — | 🔇 | WinHTTP decompresses automatically |
| `zstd()` | ✓ | — | 🔇 | WinHTTP only does gzip/deflate |

### DNS

| Method | reqwest | wrest | Status | Notes |
|--------|---------|-------|--------|-------|
| `dns_resolver()` | ✓ | — | 🔒 | WinHTTP manages DNS |
| `resolve()` | ✓ | — | 🔒 | " |
| `resolve_to_addrs()` | ✓ | — | 🔒 | " |
| `no_hickory_dns()` | ✓ | — | 🔇 | wrest doesn't bundle a DNS resolver |

### Other ClientBuilder

| Method | reqwest | wrest | Status | Notes |
|--------|---------|-------|--------|-------|
| `https_only()` | ✓ | ✓ | ✅ | rejects `http://` URLs at send time |
| `connector_layer()` | ✓ | — | 🔒 | Tower connector layers not applicable |
| `retry()` | ✓ | ✓ | ✅ | |

---

## `Client` Methods

| Method | reqwest | wrest | Status | Notes |
|--------|---------|-------|--------|-------|
| `new()` | ✓ (panics) | ✓ (panics) | ✅ | behind `panicking-compat` in wrest |
| `builder()` | ✓ | ✓ | ✅ | |
| `get()` | ✓ | ✓ | ✅ | |
| `post()` | ✓ | ✓ | ✅ | |
| `put()` | ✓ | ✓ | ✅ | |
| `patch()` | ✓ | ✓ | ✅ | |
| `delete()` | ✓ | ✓ | ✅ | |
| `head()` | ✓ | ✓ | ✅ | |
| `request()` | ✓ | ✓ | ✅ | |
| `execute()` | ✓ | ✓ | ✅ | |

---

## `Request` Methods

| Method | reqwest | wrest | Status | Notes |
|--------|---------|-------|--------|-------|
| `new()` | ✓ | ✓ | ✅ | |
| `method()` | ✓ | ✓ | ✅ | |
| `method_mut()` | ✓ | ✓ | ✅ | |
| `url()` | ✓ | ✓ | ✅ | |
| `url_mut()` | ✓ | ✓ | ✅ | |
| `headers()` | ✓ | ✓ | ✅ | |
| `headers_mut()` | ✓ | ✓ | ✅ | |
| `body()` | ✓ | ✓ | ✅ | |
| `body_mut()` | ✓ | ✓ | ✅ | |
| `timeout()` | ✓ | ✓ | ✅ | |
| `timeout_mut()` | ✓ | ✓ | ✅ | |
| `version()` | ✓ | ✓ | ✅ | |
| `version_mut()` | ✓ | ✓ | ✅ | |
| `try_clone()` | ✓ | ✓ | ✅ | |

---

## `RequestBuilder` Methods

| Method | reqwest | wrest | Status | Notes |
|--------|---------|-------|--------|-------|
| `from_parts()` | ✓ | ✓ | ✅ | |
| `header()` | ✓ | ✓ | ✅ | |
| `headers()` | ✓ | ✓ | ✅ | |
| `basic_auth()` | ✓ | ✓ | ✅ | |
| `bearer_auth()` | ✓ | ✓ | ✅ | |
| `body()` | ✓ | ✓ | ✅ | |
| `timeout()` | ✓ | ✓ | ✅ | |
| `query()` | ✓ | ✓ | ✅ | behind `query` feature |
| `form()` | ✓ | ✓ | ✅ | behind `form` feature; uses `serde_json` → `form_urlencoded` bridge (reqwest uses `serde_urlencoded`). Nested objects produce a JSON string in wrest vs error in reqwest. |
| `json()` | ✓ | ✓ | ✅ | behind `json` feature |
| `version()` | ✓ | — | 🔇 | |
| `multipart()` | ✓ | — | 💤 | |
| `build()` | ✓ | ✓ | ✅ | |
| `build_split()` | ✓ | ✓ | ✅ | |
| `send()` | ✓ | ✓ | ✅ | |
| `try_clone()` | ✓ | ✓ | ✅ | |

---

## `Response` Methods

| Method | reqwest | wrest | Status | Notes |
|--------|---------|-------|--------|-------|
| `status()` | ✓ | ✓ | ✅ | |
| `version()` | ✓ | ✓ | ✅ | |
| `url()` | ✓ | ✓ | ✅ | |
| `headers()` | ✓ | ✓ | ✅ | |
| `headers_mut()` | ✓ | ✓ | ✅ | |
| `extensions()` | ✓ | ✓ | ✅ | |
| `extensions_mut()` | ✓ | ✓ | ✅ | |
| `content_length()` | ✓ | ✓ | ✅ | Returns **compressed** (wire) size; reqwest returns **decompressed** size via `hyper::Body::size_hint()`. Identical for uncompressed responses. |
| `text()` | ✓ | ✓ | ✅ | Decodes using `Content-Type` charset; supports all 39 WHATWG encodings (35 natively via `MultiByteToWideChar`, 3 via ICU, 1 via lookup table). Three rare encodings (ISO-8859-10 (Latin-6 / Nordic), ISO-8859-14 (Latin-8 / Celtic), EUC-JP (Extended Unix Code for Japanese)) fall back to ICU via `icu.dll` and require Windows 10 1903+. |
| `text_with_charset()` | ✓ | ✓ | ✅ | Caller-specified fallback charset; same 39-encoding support as `text()` |
| `json()` | ✓ | ✓ | ✅ | behind `json` feature |
| `bytes()` | ✓ | ✓ | ✅ | |
| `chunk()` | ✓ | ✓ | ✅ | |
| `bytes_stream()` | ✓ | ✓ | ✅ | |
| `error_for_status()` | ✓ | ✓ | ✅ | |
| `error_for_status_ref()` | ✓ | ✓ | ✅ | |
| `remote_addr()` | ✓ | — | 🔇 | no-op: always `None` |
| `cookies()` | ✓ | — | 💤 | |
| `upgrade()` | ✓ | — | 💤 | |

---

## `Body` Methods

| Method | reqwest | wrest | Status | Notes |
|--------|---------|-------|--------|-------|
| `as_bytes()` | ✓ | ✓ | ✅ | |
| `wrap_stream()` | ✓ | ✓ | ✅ | |
| `try_clone()` | ✓ | ✓ | ✅ | |
| `content_length()` | ✓ | — | 💤 | |
| `From<Bytes>` | ✓ | ✓ | ✅ | zero-copy |
| `From<&'static [u8]>` | ✓ | ✓ | ✅ | zero-copy |
| `From<Vec<u8>>` | ✓ | ✓ | ✅ | |
| `From<String>` | ✓ | ✓ | ✅ | |
| `From<&'static str>` | ✓ | ✓ | ✅ | |
| `From<tokio::fs::File>` | ✓ | — | 💤 | |
| `From<Response>` | ✓ | ✓ | ✅ | pipe response as body of another request |

---

## `Url` Methods

wrest provides its own `Url` type backed by `WinHttpCrackUrl`, not
`url::Url`.  For valid RFC 3986 URLs, both produce identical results.
For invalid input, behavior is ambiguous: the native backend uses
WinHTTP's error handling, while the reqwest passthrough uses WHATWG
(via the `url` crate).  See [docs/url-standards.md](url-standards.md)
for a detailed comparison.

The intentional API subset is documented here.  Missing methods
are feasible future work unless noted otherwise.

### Type-level differences

| Item | reqwest (`url::Url`) | wrest (`Url`) | Notes |
|------|---------------------|---------------|-------|
| Error type of `parse()` / `FromStr` | `url::ParseError` | `wrest::ParseError` | Variant names mirror `url::ParseError` (`EmptyHost`, `IdnaError`, `InvalidPort`, …, `Overflow`) plus wrest-specific `InvalidUrl` and `UnsupportedScheme`. Display strings match exactly for shared variants. Most url-mirrored variants are never produced by WinHTTP; `InvalidUrl` is the catch-all |
| Scheme restriction | Any | `http` / `https` only | WinHTTP limitation |
| IDNA (international domains) | Punycode-encoded | Passed through as-is | No `idna` crate |

### Accessor methods

| Method | reqwest | wrest | Status | Notes |
|--------|---------|-------|--------|-------|
| `as_str()` | ✓ | ✓ | ✅ | |
| `scheme()` | ✓ | ✓ | ✅ | |
| `host_str()` | ✓ | ✓ | ✅ | |
| `host()` | ✓ (`Host` enum) | — | 💤 | |
| `port()` | ✓ | ✓ | ✅ | |
| `port_or_known_default()` | ✓ | ✓ | ✅ | |
| `path()` | ✓ | ✓ | ✅ | |
| `query()` | ✓ | ✓ | ✅ | |
| `fragment()` | ✓ | ✓ | ✅ | |
| `username()` | ✓ | ✓ | ✅ | |
| `password()` | ✓ | ✓ | ✅ | |
| `domain()` | ✓ | ✓ | ✅ | `None` for IP-address hosts |
| `has_host()` | ✓ | ✓ | ✅ | always `true` for HTTP(S) |
| `has_authority()` | ✓ | ✓ | ✅ | always `true` for HTTP(S) |
| `cannot_be_a_base()` | ✓ | ✓ | ✅ | always `false` for HTTP(S) |
| `origin()` | ✓ | — | 💤 | |

### Parsing & navigation

| Method | reqwest | wrest | Status | Notes |
|--------|---------|-------|--------|-------|
| `parse()` | ✓ | ✓ | ✅ | Error type is `wrest::ParseError` (mirrors `url::ParseError` variants + `UnsupportedScheme`) |
| `join()` | ✓ | ✓ | ✅ | |
| `make_relative()` | ✓ | — | 💤 | |
| `path_segments()` | ✓ | ✓ | ✅ | |
| `query_pairs()` | ✓ | — | 💤 | |
| `socket_addrs()` | ✓ | — | 🔒 | Would require DNS resolution |

### Mutation

| Method | reqwest | wrest | Status | Notes |
|--------|---------|-------|--------|-------|
| `set_scheme()` | ✓ | — | 💤 | |
| `set_host()` | ✓ | — | 💤 | |
| `set_port()` | ✓ | — | 💤 | |
| `set_path()` | ✓ | — | 💤 | |
| `set_query()` | ✓ | — | 💤 | |
| `set_fragment()` | ✓ | — | 💤 | |
| `set_username()` | ✓ | — | 💤 | |
| `set_password()` | ✓ | — | 💤 | |
| `query_pairs_mut()` | ✓ | — | 💤 | |

### Trait impls

| Trait | reqwest | wrest | Status | Notes |
|-------|---------|-------|--------|-------|
| `Display` | ✓ | ✓ | ✅ | |
| `Debug` | ✓ | ✓ | ✅ | Format mirrors `url::Url`'s derived Debug |
| `Clone`, `Eq`, `Hash` | ✓ | ✓ | ✅ | |
| `Ord`, `PartialOrd` | ✓ | ✓ | ✅ | |
| `FromStr` | ✓ | ✓ | ✅ | Err = `ParseError` |
| `AsRef<str>` | ✓ | ✓ | ✅ | |
| `Serialize` / `Deserialize` | ✓ (via `url`) | ✓ (`json` feature) | ✅ | Different feature gate |
| `From<Url> for String` | ✓ | ✓ | ✅ | |

---

## `Error` Methods

| Method | reqwest | wrest | Status | Notes |
|--------|---------|-------|--------|-------|
| `is_builder()` | ✓ | ✓ | ✅ | |
| `is_connect()` | ✓ | ✓ | ✅ | |
| `is_timeout()` | ✓ | ✓ | ✅ | |
| `is_status()` | ✓ | ✓ | ✅ | |
| `is_request()` | ✓ | ✓ | ✅ | |
| `is_body()` | ✓ | ✓ | ✅ | |
| `is_redirect()` | ✓ | ✓ | ✅ | |
| `is_decode()` | ✓ | ✓ | ✅ | |
| `is_upgrade()` | ✓ | — | 🔇 | |
| `status()` | ✓ | ✓ | ✅ | |
| `url()` | ✓ | ✓ | ✅ | |
| `url_mut()` | ✓ | ✓ | ✅ | |
| `without_url()` | ✓ | ✓ | ✅ | |
| `with_url()` | ✓ | ✓ | ✅ | |

---

## `Proxy` Methods

| Method | reqwest | wrest | Status | Notes |
|--------|---------|-------|--------|-------|
| `all()` | ✓ | ✓ | ✅ | |
| `http()` | ✓ | ✓ | ✅ | |
| `https()` | ✓ | ✓ | ✅ | |
| `basic_auth()` | ✓ | ✓ | ✅ | |
| `no_proxy()` | ✓ | — | 🔇 | |
| `custom()` | ✓ | — | 💤 | per-URL proxy selection via closure |
| `custom_http_auth()` | ✓ | — | 💤 | |
| `headers()` | ✓ | — | 💤 | custom headers on proxy requests |
| SOCKS5 proxy (`socks5://`) | ✓ | — | 🔒 | WinHTTP only supports HTTP CONNECT proxies |

## `NoProxy` Methods

| Method | reqwest | wrest | Status | Notes |
|--------|---------|-------|--------|-------|
| `from_string()` | ✓ | ✓ | ✅ | |
| `from_env()` | ✓ | ✓ | ✅ | |

---

## `redirect::Policy` Methods

| Method | reqwest | wrest | Status | Notes |
|--------|---------|-------|--------|-------|
| `limited()` | ✓ | ✓ | ✅ | |
| `none()` | ✓ | ✓ | ✅ | |
| `default()` | ✓ | ✓ | ✅ | |
| `custom()` | ✓ | — | 🔒 | WinHTTP handles redirects internally |

---

## `tls` Module Types (reqwest only)

| Type | Status | Notes |
|------|--------|-------|
| `Certificate` — `from_pem()`, `from_der()`, `from_pem_bundle()` | 🔒 | OS cert store |
| `Identity` — `from_pkcs12_der()`, `from_pkcs8_pem()`, `from_pem()` | 🔒 | OS cert store |
| `Version` — `TLS_1_0`, `TLS_1_1`, `TLS_1_2`, `TLS_1_3` | 🔒 | SChannel negotiates |
| `TlsInfo` — `peer_certificate()` | 💤 | |
| `CertificateRevocationList` — `from_pem()`, `from_der()` | 🔒 | rustls only concept |

## `dns` Module Types (reqwest only)

| Type | Status | Notes |
|------|--------|-------|
| `Resolve` trait | 🔒 | WinHTTP manages DNS |
| `Name` | 🔒 | " |

## `cookie` Module Types (reqwest only)

| Type | Status | Notes |
|------|--------|-------|
| `Jar` | 💤 | |
| `CookieStore` trait | 💤 | |
| `Cookie` (response iterator item) | 💤 | |

## `multipart` Module Types (reqwest only)

| Type | Status | Notes |
|------|--------|-------|
| `Form` | 💤 | |
| `Part` | 💤 | |

## `retry` Module

### Free Functions

| Function | reqwest | wrest | Status | Notes |
|----------|---------|-------|--------|-------|
| `for_host()` | ✓ | ✓ | ✅ | |
| `never()` | ✓ | ✓ | ✅ | |

### `Builder` Methods

| Method | reqwest | wrest | Status | Notes |
|--------|---------|-------|--------|-------|
| `scoped()` | ✓ | ✓ | ✅ | sealed; callers are meant to use `for_host()` |
| `no_budget()` | ✓ | ✓ | ✅ | |
| `max_extra_load()` | ✓ | ✓ | ✅ | |
| `max_retries_per_request()` | ✓ | ✓ | ✅ | |
| `classify_fn()` | ✓ | ✓ | ✅ | |
| `classify()` | ✓ | — | N/A | sealed trait / unusable; use `classify_fn()` instead |

### `ReqRep` Methods (received by `classify_fn` closures)

| Method | reqwest | wrest | Status | Notes |
|--------|---------|-------|--------|-------|
| `method()` | ✓ | ✓ | ✅ | |
| `uri()` | ✓ | ✓ | ✅ | |
| `status()` | ✓ | ✓ | ✅ | |
| `error()` | ✓ | ✓ | ✅ | |
| `retryable()` | ✓ | ✓ | ✅ | |
| `success()` | ✓ | ✓ | ✅ | |

### `Action` Enum (returned from `classify_fn` closures)

| Variant | reqwest | wrest | Status | Notes |
|---------|---------|-------|--------|-------|
| `Success` | ✓ | ✓ | ✅ | |
| `Retryable` | ✓ | ✓ | ✅ | |

---

## Summary Counts

| Status | Count |
|--------|-------|
| ✅ Implemented | 166 |
| 🔇 No-op (`noop-compat`) | 32 |
| 🔒 Cannot implement (WinHTTP limitation) | 39 |
| 💤 Not yet implemented | 41 |
| N/A | 3 |
