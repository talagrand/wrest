# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/), and this project adheres to Semantic Versioning.

## 0.5.7

### Fixed
- Secret redaction: `Debug` output for `Url` and `Proxy` (and `Error`, transitively) now redacts the URL password and proxy Basic-auth password. `Display` already omitted them where provided.
- URL parsing: `winhttp_crack_url` previously used fixed-size buffers for URL parts - these are now preserved in full.
- 32-bit soundness: Return failure instead of wrapping if returned bodies would overflow `usize`.
- 32-bit soundness: Return failure instead of silently truncating oversized inputs.
- Retry budget: the slot-advance loop is now capped at the bucket count, so a long suspend (sleep, debugger, etc.) can no longer cause huge numbers of zero-bucket iterations on the next request.
- DLL-host safety: closed path where a panic during `HANDLE_CLOSING` callback bookkeeping could be swallowed and leave `WinHttpRequestHandle::drop` hanging in `wait_closed_and_idle`.
- Cross-origin redirects no longer forward `Authorization`, `Cookie`, `Cookie2`, `Proxy-Authorization`, `Proxy-Authenticate`, or `WWW-Authenticate` headers to the new origin. WinHTTP forwards these unchanged by default and documents that stripping them is the application's responsibility (Security Considerations item 16).
- An `https://` -> `http://` redirect now returns `Error::is_redirect() == true` instead of silently surfacing the 3xx response. The Err shape matches what reqwest produces under `https_only(true)`, but wrest applies it unconditionally: WinHTTP defaults to blocking the downgrade and wrest preserves that default, so the new shape is always what callers see (reqwest's default *follows* https->http silently).
- URL path traversal: `Url::join()` now treats `%2e` / `%2E` as `.` when collapsing dot-segments, so an attacker-controlled relative reference like `%2e%2e/secret` can no longer escape a trusted base.

### Changed
- CI - Reliability: swap `httpbin.org` for a locally-hosted version for reliability (doesn't affect local testing)
- Enabled clippy's `cast_possible_truncation`, `cast_possible_wrap`, `cast_sign_loss`, and `arithmetic_side_effects` lints (warn) to guard against integer-overflow and 32-bit soundness regressions.

## 0.5.6

### Fixed
- DLL-host safety: replaced `futures-timer` with a Win32-threadpool-backed `Delay` so the library no longer leaves a parked helper thread behind when a host process calls `FreeLibrary` on wrest. `futures-timer` remains as a dev-dependency for examples.
- DLL-host safety: WinHTTP request handles now drain in-flight callbacks during `Drop`, so an OS callback can no longer fire into unmapped code after a host drops the response and unloads the library. `WinHttpRequestHandle::drop` blocks until both `WINHTTP_CALLBACK_STATUS_HANDLE_CLOSING` has been delivered and no other callback is active for the handle.
- Callback hygiene: `CompletionSignal::signal` releases sender mutex before completing the channel; previously a theoretical custom inline-polling waker could have re-entered `signal` and deadlocked on the same mutex.
- Callback safety: `winhttp_callback` and `timer_callback` FFI-exposed callbacks are now defensively protected against Rust panics flowing through to the calling OS thread.
- Callback safety: WinHTTP callback now null/length-checks `lpv_info` before dereferencing avoiding hanging long awaiters when processing  `REQUEST_ERROR` and `SECURE_FAILURE`.
- Status-code parsing: reject WinHTTP status codes that don't fit in `u16` instead of letting a bare `as u16` cast silently truncate (e.g. `0x100C8` masquerading as a successful `200 OK`).
- Header dedup: `.json()` / `.form()` now override (rather than duplicate) a `Content-Type` from `Client::default_headers`.

### Changed
- Release - Supply chain: SHA-pin all actions in the release workflow. Minimize default permissions with per-job-scoped writes.
- Release - Actions: Switch to `actions-rust-lang/setup-rust-toolchain` to support SHA-pinning and remove `rust-cache` dependency, enable warnings by default and enable PR problem-matchers
- Dependabot - Group minor/patch updates for both cargo and github-actions into single PRs; review major version bumps independently.
- CI - Add timeouts and cancel superseded PRs.
- CI - Add macOS coverage.
- CI - MSRV does not bound dev-dependencies (cargo test -> cargo check)
- CI - Code coverage switches to OIDC publish
- CI - Add workflow lint (actionlint) to guard matrix/needs references, action input shapes, and GitHub expression syntax.
- CI - Add `typos` for spell-check in code, docs, and public API names. Allow-list lives in `_typos.toml`.
- Release - Miscellaneous resiliency fixes

## 0.5.5

### Fixed
- Fixed `WinHttpCrackUrl` double-encoding. Existing percent-encoded sequences (e.g., `%3d`, `%2f`) are preserved as-is. Previously, `ICU_ESCAPE` would re-encode them (`%3d` → `%253d`), causing 403 errors from servers that validate URL tokens.

### Added
- Added URL parsing conformance test (`tests/url_parse.rs`) that fetches the WHATWG URL parsing test suite and validates all applicable cases. RFC-clean URLs must match exactly; error-recovery divergences between WinHTTP and WHATWG are tracked.
- Added `docs/url-standards.md` documenting the relationship between RFC 3986, the WHATWG URL Standard, and WinHTTP's URL parser.

## 0.5.4

### Added
- Added `whirl` example: a tiny curl-like CLI demonstrating streaming downloads with progress display.
- Added `Url::domain()`, `Url::has_host()`, `Url::has_authority()`, `Url::cannot_be_a_base()`, and `Url::path_segments()` trivial accessor methods matching `url::Url`.
- Added `ClientBuilder::https_only()` — rejects `http://` URLs at send time when enabled.

### Changed
- Consolidated examples from 7 to 4, removing `simple_get`, `concurrent`, and `streaming` (all subsumed by `whirl` and remaining examples).
- `ClientBuilder::tls_danger_accept_invalid_certs()` alias for `danger_accept_invalid_certs()` to match reqwest 0.13.
- Removed `ClientBuilder::no_trust_dns()` (removed in reqwest 0.12); use `no_hickory_dns()` instead. Breakage should be acceptable since we are tracking reqwest 0.13.
- Wrest errors now use `source` chain so callers that do source chain traversal in `reqwest` see the same Error "shape". `Error::source()` now always returns `Some` for non-status errors.
- Performance: `Error` object size is now pointer-sized and errors are not greedily stringified.
- Release workflow switched to OIDC trusted publishing for crates.io (no more `CRATES_IO_TOKEN` secret).

### Fixed
- Fixed `WinHttpSetCredentials` return value being silently discarded; proxy auth failures now propagate as errors instead of producing 407 responses.
- Hardened charset extraction from headers to prevent false positives from substrings like `x=charset=wrong`.
- Fixed `Url::from_http_uri` to match `Url::parse` handling for default ports (80/443) - they should not be marked as explicit.
- Hardened handling of URLs with a `@` in the userinfo itself - always favor the *last* `@`.

## 0.5.3

### Added
- Added reqwest-style retry support on the native backend via `ClientBuilder::retry()` and the new `retry` module.
- Added runtime helpers (`Runtime`, `runtime()`, and `block_on()`) to provide a small executor abstraction for callers.
- Added additional `http` conversion support (request/response interop) to better match reqwest APIs.
- Added parity-focused integration coverage for retry and reqwest-aligned behaviors.

### Changed
- Refined parity behavior and public surface alignment with reqwest (including export/type polish and non-reqwest extras cleanup).
- Updated CI and pipeline configuration for feature-matrix coverage and deprecation cleanup.

### Fixed
- Improved code coverage and test consistency.

## 0.5.2

### Added
- Added reqwest forwarding mode to support cross-platform usage and A/B testing.

### Changed
- Improved reqwest API parity for URL/debug behavior and error surface expectations.

### Fixed
- Fixed error display parity and source-chain/classification behavior.
- Fixed streaming-body error classification alignment.
- Fixed UTF-16 and URL-path coverage edge cases.
- Fixed CI feature-gating/dependency issues.

### Documentation
- General documentation improvements.

## 0.5.1

### Changed
- Updated dependencies and tightened minimal-version accuracy.

### Fixed
- Fixed docs.rs build failure.

### CI
- Enforced minimal dependency versions in CI.
- Improved cargo-audit CI performance.

## 0.5.0

### Added
- Initial public release of `wrest`.
- Windows-native async HTTP client backed by WinHTTP.
- Reqwest-compatible core API (`Client`, `RequestBuilder`, `Response`, error model, and key feature flags).

