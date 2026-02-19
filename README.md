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

If your application targets Windows and you want the platform's native
networking -- the same stack used by Windows itself -- `wrest` lets you do
that without giving up the ergonomic `reqwest` API your code already uses.

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

## Cross-platform & A/B testing

On **non-Windows** platforms (Linux, macOS, etc.) wrest is a thin
passthrough to [`reqwest`](https://docs.rs/reqwest) -- every call
forwards directly, so the same code compiles everywhere.

To force the reqwest path **on Windows** -- for example, to A/B test
against the native WinHTTP path -- enable the `always-reqwest`
feature:

```toml
wrest = { version = "0.5", features = ["always-reqwest"] }
```

Feature flags like `json`, `gzip`, `stream`, etc. forward to the
corresponding reqwest features automatically. Use
`default-features = false` to strip wrest and reqwest to their bare
minimum, then re-add only what you need.

## Features

| Feature | Default | Description |
|---------|---------|-------------|
| `charset` | **Yes** | Improved text decoding. Native path has all 39 WHATWG encodings built-in (three rare ones -- ISO-8859-10 (Latin-6 / Nordic), ISO-8859-14 (Latin-8 / Celtic), EUC-JP (Extended Unix Code for Japanese) -- need Windows 10 1903+); forwards to `reqwest/charset` on the reqwest path |
| `http2` | **Yes** | HTTP/2 support. WinHTTP negotiates via ALPN automatically; forwards to `reqwest/http2` |
| `default-tls` | **Yes** | TLS via the OS stack (SChannel). Always-on natively; forwards to `reqwest/default-tls` |
| `native-tls` | No | Explicit OS-native TLS selection. No-op natively (SChannel is always used); forwards to `reqwest/native-tls` |
| `system-proxy` | **Yes** | Automatic system proxy detection. WinHTTP uses WPAD/PAC natively; forwards to `reqwest/system-proxy` |
| `json` | No | `RequestBuilder::json()` and `Response::json()` (adds `serde`, `serde_json`) |
| `form` | No | `RequestBuilder::form()` (adds `serde`, `form_urlencoded`) |
| `query` | No | `RequestBuilder::query()` (adds `serde`, `form_urlencoded`) |
| `gzip` | No | `ClientBuilder::gzip()` no-op toggle (WinHTTP always decompresses gzip); forwards to `reqwest/gzip` |
| `deflate` | No | `ClientBuilder::deflate()` no-op toggle; forwards to `reqwest/deflate` |
| `brotli` | No | `ClientBuilder::brotli()` no-op toggle; forwards to `reqwest/brotli` |
| `zstd` | No | `ClientBuilder::zstd()` no-op toggle; forwards to `reqwest/zstd` |
| `stream` | No | `Stream`-based body support. Always available natively; forwards to `reqwest/stream` |
| **`tracing`** | No | Emit diagnostics via the [`tracing`](https://docs.rs/tracing) crate -- request lifecycle, proxy resolution, charset decoding, and more |
| **`noop-compat`** | No | Enables ~31 no-op reqwest stubs (connection pool, TCP options, HTTP/2 tuning, TLS backend selection, etc.) so reqwest-targeting code compiles without changes. Compression toggles require both this and the respective feature |
| **`panicking-compat`** | No | `Client::new()` and `impl Default for Client` (these panic on failure -- prefer `Client::builder().build()`) |
| **`always-reqwest`** | No | Forces the [`reqwest`](https://docs.rs/reqwest) path even on Windows -- see [Cross-platform & A/B testing](#cross-platform--ab-testing) |

**Bold** feature names are unique to wrest (not present in reqwest).

## Limitations

wrest covers the core reqwest API surface (~75 methods). A few reqwest
features are not available because WinHTTP handles them internally or
they haven't been added yet:

- **No blocking API** -- async only
- **No cookies, multipart, retry, or WebSocket** -- not yet implemented
- **No custom DNS or TLS configuration** -- WinHTTP uses SChannel and
  the OS certificate store (`danger_accept_invalid_certs` *is* supported)
- **No SOCKS proxies** -- WinHTTP only supports HTTP CONNECT
- **Redirects** -- `Policy::limited()` and `Policy::none()` only;
  `Policy::custom()` is not available
- **Decompression** -- gzip/deflate always-on; brotli/zstd not available
  natively
- **`remote_addr()`** always returns `None`
- **Charset decoding** -- three rare encodings (ISO-8859-10 (Latin-6 /
  Nordic), ISO-8859-14 (Latin-8 / Celtic), EUC-JP (Extended Unix Code
  for Japanese)) require Windows 10 1903+ (`icu.dll`)

~31 additional reqwest builder stubs (pool tuning, TCP options, HTTP/2
knobs, etc.) are available as silent no-ops under the `noop-compat`
feature.

For a full API-by-API comparison, see [docs/reqwest-parity.md](docs/reqwest-parity.md).

## Minimum supported Rust version

Rust 1.90.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT License](LICENSE-MIT) at your option.
