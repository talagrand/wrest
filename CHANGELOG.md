# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/), and this project adheres to Semantic Versioning.

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

