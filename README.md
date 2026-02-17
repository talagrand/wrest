<table><tr><td><img src="https://raw.githubusercontent.com/talagrand/wrest/main/docs/wrest.png" alt="wrest"></td><td>

# wrest

**Windows-native async HTTP client with a reqwest-compatible API.**

[![CI](https://github.com/talagrand/wrest/workflows/CI/badge.svg)](https://github.com/talagrand/wrest/actions)
[![codecov](https://codecov.io/gh/talagrand/wrest/graph/badge.svg)](https://codecov.io/gh/talagrand/wrest)
[![Crates.io](https://img.shields.io/crates/v/wrest.svg)](https://crates.io/crates/wrest)
[![Documentation](https://docs.rs/wrest/badge.svg)](https://docs.rs/wrest)

</td></tr></table>

wrest is a drop-in replacement for the **async** API of
[`reqwest`](https://docs.rs/reqwest) that uses the operating system's built-in
HTTP stack
([WinHTTP](https://learn.microsoft.com/en-us/windows/win32/winhttp/about-winhttp))
instead of bundling its own and does not depend on the
[`tokio`](https://docs.rs/tokio) executor. TLS, proxy resolution,
authentication, content-encoding, and more are all handled by Windows.

## Why

[`reqwest`](https://docs.rs/reqwest) is a battle-tested cross-platform HTTP client
built on top of [`tokio`](https://docs.rs/tokio). wrest takes a different approach:
instead of linking a TLS library and driving sockets from user space, it delegates the
**entire HTTP stack** to the OS, acting as a thin ergonomic API surface on top
of OS primitives.

| | reqwest | wrest |
|-|---------|-------|
| **HTTP stack** | [hyper](https://docs.rs/hyper) (user-space) | [WinHTTP](https://learn.microsoft.com/en-us/windows/win32/winhttp/about-winhttp) (OS-provided) |
| **TLS** | User-space or SChannel | SChannel -- always the OS certificate store |
| **Proxy** | Env vars + limited OS proxy settings | Env vars + All OS proxy settings |
| **Async runtime** | Requires [`tokio`](https://docs.rs/tokio) | Executor-agnostic -- any runtime or `block_on` |
| **Binary size** | hyper, h2, ... | Thin FFI layer over a system DLL |

If your application only targets Windows and you want the platform's native
networking -- the same stack used by Windows itself -- `wrest` lets you do
that without giving up the ergonomic `reqwest` API your code already uses.
You can also switch between the two in cross-platform codebases.

## Quick start

```rust,ignore
// The API is intentionally identical to reqwest.
use wrest::Client;

let client = Client::builder()
    .timeout(std::time::Duration::from_secs(30))
    .build()?;

let body = client
    .get("https://httpbin.org/get")
    .header("x-custom", "value")
    .send()
    .await?
    .text()
    .await?;

println!("{body}");
```

## Features

| Feature | Default | Description |
|---------|---------|-------------|
| `noop-compat` | No | Enables ~31 no-op reqwest stubs (connection pool, TCP options, compression toggles, HTTP/1 & HTTP/2 tuning, TLS backend selection, DNS resolver selection, etc.) so reqwest-targeting code compiles without changes |
| `json` | No | `RequestBuilder::json()` and `Response::json()` (adds `serde`, `serde_json`) |
| `form` | No | `RequestBuilder::form()` (adds `serde`, `form_urlencoded`) |
| `query` | No | `RequestBuilder::query()` (adds `serde`, `form_urlencoded`) |
| `tracing` | No | Emit diagnostics via the [`tracing`](https://docs.rs/tracing) crate — request lifecycle, proxy resolution, charset decoding, and more |
| `panicking-compat` | No | `Client::new()` and `impl Default for Client` (these panic on failure -- prefer `Client::builder().build()`) |

## Executor-agnostic

wrest returns standard `Future`s with no hidden dependency on
[`tokio`](https://docs.rs/tokio),
[`async-std`](https://docs.rs/async-std), or any other runtime. Use it with
whichever executor you prefer:

```rust,ignore
// tokio
tokio::runtime::Runtime::new()?.block_on(do_request());

// futures
futures::executor::block_on(do_request());

// smol
smol::block_on(do_request());
```

## What works

The core `reqwest` workflow is fully supported:

- `Client` / `ClientBuilder` -- timeouts, default headers, redirect policy,
  user agent, `danger_accept_invalid_certs`, proxy configuration
- `RequestBuilder` -- `get`, `post`, `put`, `patch`, `delete`, `head`,
  `request`; `.header()`, `.headers()`, `.body()`, `.json()`, `.form()`,
  `.query()`, `.basic_auth()`, `.bearer_auth()`, `.timeout()`
- `Request` -- inspect/modify before sending; `try_clone()`
- `Response` -- `status()`, `headers()`, `url()`, `version()`,
  `content_length()`, `text()`, `text_with_charset()`, `json()`,
  `bytes()`, `bytes_stream()`, `chunk()`, `error_for_status()`,
  `remote_addr()`, `extensions()`
- `Error` -- `is_builder()`, `is_connect()`, `is_timeout()`,
  `is_redirect()`, `is_status()`, `is_body()`, `is_decode()`,
  `is_request()`, `status()`, `url()`, `without_url()`
- URL userinfo (`http://user:pass@host/`) -> automatic `Authorization: Basic` header
- `wrest::get()` free function matching `reqwest::get()`
- Streaming request body via `Body::wrap_stream()` (chunked transfer encoding)
- Streaming response body via `chunk()` / `bytes_stream()`
- Redirect following with configurable limits
- `ClientBuilder::http1_only()`, `max_connections_per_host()`,
  `connection_verbose()` (requires `tracing`)

## What doesn't

wrest is **Windows only**. It will not compile on Linux, macOS, or other
platforms.

The table below compares wrest against reqwest (all features enabled).
Because WinHTTP is the HTTP stack, some reqwest APIs cannot be meaningfully
implemented and others haven't been added yet.

| Feature | Status | Notes |
|---------|--------|-------|
| Synchronous (blocking) API | ❌ | async only |
| Cookie jar / store | ❌ | not implemented |
| Multipart uploads | ❌ | not implemented |
| Retry policies | ❌ | not implemented |
| HTTP upgrades / WebSocket | ❌ | not implemented |
| `https_only()`, `referer()` | ❌ | not implemented |
| Custom DNS resolvers | ❌ | WinHTTP manages DNS internally |
| TLS configuration (custom certs, client identity, CRL, version pinning) | ❌ | WinHTTP uses SChannel and the OS certificate store. `danger_accept_invalid_certs()` **is** implemented. |
| HTTP/3 | ❌ | disabled to avoid QUIC/UDP timeout regressions |
| Local address / interface binding | ❌ | WinHTTP manages binding |
| Tower middleware | ❌ | not applicable |
| Custom redirect policy | ❌ | WinHTTP handles redirects internally |
| SOCKS proxies | ❌ | WinHTTP only supports HTTP CONNECT proxies |
| Brotli / zstd decompression | ❌ | WinHTTP only decompresses gzip and deflate |

Several reqwest builder methods that have no effect under WinHTTP (connection-pool
tuning, TCP options, compression toggles, HTTP/1 & HTTP/2 tuning, TLS backend
selection, DNS resolver selection) are available as silent no-ops under the
`noop-compat` feature. Keep it disabled for compile-time detection of unsupported
API usage.

## Behavioral differences from reqwest

Because the HTTP stack is WinHTTP rather than hyper, some behaviors
diverge from reqwest by necessity. These are also documented on a per-API basis.
If you find undocumented deviations, please file an issue!

- **Redirect policy:** Only `redirect::Policy::limited()` and
  `redirect::Policy::none()` are supported. `Policy::custom()` is not
  available because WinHTTP handles redirects internally.
- **Decompression:** Content-encoding decompression (gzip, deflate) is
  always-on; WinHTTP does not expose per-algorithm toggles. The `gzip()`,
  `brotli()`, `deflate()`, `zstd()` builders are no-ops.
- **Proxy:** SOCKS proxies (`socks4://`, `socks5://`) are rejected.
  WinHTTP only supports HTTP CONNECT proxies.
- **`remote_addr()`** always returns `None`; **`version()`** on
  `RequestBuilder` is a no-op. These are unconditional (not gated behind
  `noop-compat`).
- **Charset decoding:** `text()` supports all 39 WHATWG-mandated
  encodings.  35 are decoded natively (Win32 `MultiByteToWideChar` or
  pure Rust for UTF-8/UTF-16/x-user-defined).  Three rare encodings
  — ISO-8859-10 (Latin-6 / Nordic), ISO-8859-14 (Latin-8 / Celtic),
  and EUC-JP (Extended Unix Code for Japanese) — are absent from the
  Win32 NLS subsystem and are decoded via the system-bundled `icu.dll`
  on Windows 10 1903+; on older builds they will return a decode error.
  ISO-8859-16 (Latin-10 / South-Eastern European) is decoded via a
  compile-time Rust lookup table.

## Minimum supported Rust version

Rust 1.90.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT License](LICENSE-MIT) at your option.
