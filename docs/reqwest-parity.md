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
| `Url` | ✓ | ✓ | ✅ | |
| `Method` | ✓ | ✓ | ✅ | |
| `StatusCode` | ✓ | ✓ | ✅ | |
| `Version` (http) | ✓ | ✓ | ✅ | |
| `HeaderMap` / `header` module | ✓ | ✓ | ✅ | |
| `IntoUrl` trait | ✓ | ✓ | ✅ | |
| `Proxy` | ✓ | ✓ | ✅ | |
| `NoProxy` | ✓ | ✓ | ✅ | |
| `get()` free function | ✓ | ✓ | ✅ | |
| `Upgraded` | ✓ | — | 💤 | HTTP upgrades not implemented |
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
| `cookie` | ✓ | — | 💤 | not implemented |
| `dns` | ✓ | — | 🔒 | WinHTTP manages DNS |
| `multipart` | ✓ | — | 💤 | not implemented |
| `tls` | ✓ | — | 🔒 | WinHTTP always uses SChannel |
| `retry` | ✓ | — | 💤 | new in 0.13, not implemented |

## Traits & Impls

| Item | reqwest | wrest | Status | Notes |
|------|---------|-------|--------|-------|
| `impl Service<Request> for Client` | ✓ | — | 💤 | Tower integration |
| `impl Service<Request> for &Client` | ✓ | — | 💤 | Tower integration |
| `impl From<Response> for Body` | ✓ | — | 💤 | pipe response as body of another request |
| `impl From<http::Response<T>> for Response` | ✓ | — | 💤 | |
| `impl From<Response> for http::Response<Body>` | ✓ | — | 💤 | |
| `impl TryFrom<http::Request<T>> for Request` | ✓ | — | 💤 | |
| `impl TryFrom<Request> for http::Request<Body>` | ✓ | — | 💤 | |

---

## `ClientBuilder` Methods

### Timeouts

| Method | reqwest | wrest | Status | Notes |
|--------|---------|-------|--------|-------|
| `timeout()` | ✓ | ✓ | ✅ | |
| `connect_timeout()` | ✓ | ✓ | ✅ | |
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
| `pool_idle_timeout()` | ✓ | — | 🔇 | no-op under `noop-compat` |
| `pool_max_idle_per_host()` | ✓ | — | 🔇 | no-op under `noop-compat` |
| `tcp_nodelay()` | ✓ | — | 🔇 | no-op under `noop-compat` |
| `tcp_keepalive()` | ✓ | — | 🔇 | no-op under `noop-compat` |
| `tcp_keepalive_interval()` | ✓ | — | 🔇 | no-op under `noop-compat` |
| `tcp_keepalive_retries()` | ✓ | — | 🔇 | no-op under `noop-compat` |
| `local_address()` | ✓ | — | 🔒 | WinHTTP manages binding |
| `interface()` | ✓ | — | 🔒 | WinHTTP manages binding |
| `max_connections_per_host()` | — | ✓ | ✅ | wrest extension via WinHTTP |

### Redirect

| Method | reqwest | wrest | Status | Notes |
|--------|---------|-------|--------|-------|
| `redirect()` | ✓ | ✓ | ✅ | `Policy::limited()` and `Policy::none()` only |
| `referer()` | ✓ | — | 💤 | not implemented |

### Proxy

| Method | reqwest | wrest | Status | Notes |
|--------|---------|-------|--------|-------|
| `proxy()` | ✓ | ✓ | ✅ | |
| `no_proxy()` | ✓ | ✓ | ✅ | |

### TLS

| Method | reqwest | wrest | Status | Notes |
|--------|---------|-------|--------|-------|
| `danger_accept_invalid_certs()` | ✓ | ✓ | ✅ | functional |
| `tls_danger_accept_invalid_certs()` | ✓ | — | 💤 | reqwest 0.13 renamed; wrest has the old name |
| `tls_danger_accept_invalid_hostnames()` / `danger_accept_invalid_hostnames()` | ✓ | — | 🔒 | SChannel validates hostnames |
| `tls_version_min()` / `min_tls_version()` | ✓ | — | 🔒 | SChannel manages negotiation |
| `tls_version_max()` / `max_tls_version()` | ✓ | — | 🔒 | SChannel manages negotiation |
| `tls_sni()` | ✓ | — | 🔇 | no-op under `noop-compat`; SNI always enabled |
| `tls_info()` | ✓ | — | 💤 | no `TlsInfo` extension |
| `tls_certs_merge()` / `add_root_certificate()` | ✓ | — | 🔒 | OS cert store |
| `tls_certs_only()` | ✓ | — | 🔒 | OS cert store |
| `tls_crls_only()` | ✓ | — | 🔒 | rustls only |
| `add_crl()` | ✓ | — | 🔒 | rustls only |
| `add_crls()` | ✓ | — | 🔒 | rustls only |
| `tls_backend_native()` / `use_native_tls()` | ✓ | — | 🔇 | no-op under `noop-compat`; always SChannel |
| `tls_backend_rustls()` / `use_rustls_tls()` | ✓ | — | N/A | always SChannel |
| `tls_backend_preconfigured()` / `use_preconfigured_tls()` | ✓ | — | N/A | always SChannel |
| `identity()` | ✓ | — | 🔒 | client certs via OS store, not exposed |

### HTTP Version Preference

| Method | reqwest | wrest | Status | Notes |
|--------|---------|-------|--------|-------|
| `http1_only()` | ✓ | ✓ | ✅ | functional — disables HTTP/2 flag |
| `http2_prior_knowledge()` | ✓ | — | 🔇 | no-op under `noop-compat` |
| `http3_prior_knowledge()` | ✓ | — | 💤 | requires explicit `WINHTTP_PROTOCOL_FLAG_HTTP3`; not enabled to avoid QUIC/UDP timeout regressions |

### HTTP/1 Tuning

| Method | reqwest | wrest | Status | Notes |
|--------|---------|-------|--------|-------|
| `http09_responses()` | ✓ | — | 🔇 | no-op under `noop-compat` |
| `http1_title_case_headers()` | ✓ | — | 🔇 | no-op under `noop-compat` |
| `http1_allow_obsolete_multiline_headers_in_responses()` | ✓ | — | 🔇 | no-op under `noop-compat` |
| `http1_ignore_invalid_headers_in_responses()` | ✓ | — | 🔇 | no-op under `noop-compat` |
| `http1_allow_spaces_after_header_name_in_responses()` | ✓ | — | 🔇 | no-op under `noop-compat` |

### HTTP/2 Tuning

| Method | reqwest | wrest | Status | Notes |
|--------|---------|-------|--------|-------|
| `http2_initial_stream_window_size()` | ✓ | — | 🔇 | no-op under `noop-compat` |
| `http2_initial_connection_window_size()` | ✓ | — | 🔇 | no-op under `noop-compat` |
| `http2_adaptive_window()` | ✓ | — | 🔇 | no-op under `noop-compat` |
| `http2_max_frame_size()` | ✓ | — | 🔇 | no-op under `noop-compat` |
| `http2_max_header_list_size()` | ✓ | — | 🔇 | no-op under `noop-compat` |
| `http2_keep_alive_interval()` | ✓ | — | 🔇 | no-op under `noop-compat` |
| `http2_keep_alive_timeout()` | ✓ | — | 🔇 | no-op under `noop-compat` |
| `http2_keep_alive_while_idle()` | ✓ | — | 🔇 | no-op under `noop-compat` |

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
| `cookie_store()` | ✓ | — | 💤 | not implemented |
| `cookie_provider()` | ✓ | — | 💤 | not implemented |

### Decompression

| Method | reqwest | wrest | Status | Notes |
|--------|---------|-------|--------|-------|
| `gzip()` | ✓ | — | 🔇 | no-op; WinHTTP decompresses automatically |
| `brotli()` | ✓ | — | 🔇 | no-op; WinHTTP only does gzip/deflate |
| `deflate()` | ✓ | — | 🔇 | no-op; WinHTTP decompresses automatically |
| `zstd()` | ✓ | — | 🔇 | no-op; WinHTTP only does gzip/deflate |

### DNS

| Method | reqwest | wrest | Status | Notes |
|--------|---------|-------|--------|-------|
| `dns_resolver()` | ✓ | — | 🔒 | WinHTTP manages DNS |
| `resolve()` | ✓ | — | 🔒 | " |
| `resolve_to_addrs()` | ✓ | — | 🔒 | " |
| `no_hickory_dns()` / `no_trust_dns()` | ✓ | — | 🔇 | no-op under `noop-compat`; wrest doesn't bundle a DNS resolver |

### Other ClientBuilder

| Method | reqwest | wrest | Status | Notes |
|--------|---------|-------|--------|-------|
| `https_only()` | ✓ | — | 💤 | not implemented |
| `connector_layer()` | ✓ | — | 🔒 | Tower connector layers not applicable |
| `retry()` | ✓ | — | 💤 | new in 0.13, not implemented |

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
| `form()` | ✓ | ✓ | ✅ | behind `form` feature |
| `json()` | ✓ | ✓ | ✅ | behind `json` feature |
| `version()` | ✓ | — | 🔇 | no-op under `noop-compat` |
| `multipart()` | ✓ | — | 💤 | multipart module not implemented |
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
| `content_length()` | ✓ | ✓ | ✅ | |
| `text()` | ✓ | ✓ | ✅ | Decodes using `Content-Type` charset; supports all 39 WHATWG encodings (35 natively via `MultiByteToWideChar`, 3 via ICU, 1 via lookup table). Three rare encodings (ISO-8859-10 (Latin-6 / Nordic), ISO-8859-14 (Latin-8 / Celtic), EUC-JP (Extended Unix Code for Japanese)) fall back to ICU via `icu.dll` and require Windows 10 1903+. |
| `text_with_charset()` | ✓ | ✓ | ✅ | Caller-specified fallback charset; same 39-encoding support as `text()` |
| `json()` | ✓ | ✓ | ✅ | behind `json` feature |
| `bytes()` | ✓ | ✓ | ✅ | |
| `chunk()` | ✓ | ✓ | ✅ | |
| `bytes_stream()` | ✓ | ✓ | ✅ | |
| `error_for_status()` | ✓ | ✓ | ✅ | |
| `error_for_status_ref()` | ✓ | ✓ | ✅ | |
| `remote_addr()` | ✓ | — | 🔇 | no-op (always `None`) under `noop-compat` |
| `cookies()` | ✓ | — | 💤 | cookie module not implemented |
| `upgrade()` | ✓ | — | 💤 | HTTP upgrades not implemented |

---

## `Body` Methods

| Method | reqwest | wrest | Status | Notes |
|--------|---------|-------|--------|-------|
| `as_bytes()` | ✓ | ✓ | ✅ | |
| `wrap_stream()` | ✓ | ✓ | ✅ | |
| `try_clone()` | ✓ | ✓ | ✅ | |

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
| `is_upgrade()` | ✓ | — | 🔇 | no-op under `noop-compat` |
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
| `no_proxy()` | ✓ | — | 🔇 | no-op under `noop-compat` |
| `custom_http_auth()` | ✓ | — | 💤 | not implemented |
| SOCKS5 proxy (`socks5://`) | ✓ | — | 🔒 | WinHTTP only supports HTTP CONNECT proxies |

## `NoProxy` Methods

| Method | reqwest | wrest | Status | Notes |
|--------|---------|-------|--------|-------|
| `from_string()` | ✓ | ✓ | ✅ | |
| `from_env()` | ✓ | — | 💤 | not implemented |

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
| `TlsInfo` — `peer_certificate()` | 💤 | not exposed |
| `CertificateRevocationList` — `from_pem()`, `from_der()` | 🔒 | rustls only concept |

## `dns` Module Types (reqwest only)

| Type | Status | Notes |
|------|--------|-------|
| `Resolve` trait | 🔒 | WinHTTP manages DNS |
| `Name` | 🔒 | " |

## `cookie` Module Types (reqwest only)

| Type | Status | Notes |
|------|--------|-------|
| `Jar` | 💤 | not implemented |
| `CookieStore` trait | 💤 | " |
| `Cookie` (response iterator item) | 💤 | " |

## `multipart` Module Types (reqwest only)

| Type | Status | Notes |
|------|--------|-------|
| `Form` | 💤 | not implemented |
| `Part` | 💤 | " |

## `retry` Module Types (reqwest 0.13 only)

| Type | Status | Notes |
|------|--------|-------|
| `Builder` — `for_host()`, `scoped()`, `no_budget()`, `max_extra_load()`, `max_retries_per_request()`, `classify()`, `classify_fn()` | 💤 | not implemented |
| `classify::Classify` trait | 💤 | " |
| `classify::ReqRep` | 💤 | " |
| `classify::Action` (`Success`, `Retryable`) | 💤 | " |
| `scope::Scope` trait | 💤 | " |

---

## Summary Counts

| Status | Count |
|--------|-------|
| ✅ Implemented | ~76 |
| 🔇 No-op (`noop-compat`) | ~31 |
| 🔒 Cannot implement (WinHTTP limitation) | ~15 |
| 💤 Not yet implemented | ~35 |
| N/A | ~2 |
