# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/), and this project adheres to Semantic Versioning.

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

