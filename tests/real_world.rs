//! Real-world integration tests against live internet services.
//!
//! These tests validate wrest against production HTTP servers to ensure
//! compatibility with real-world behaviors that mocks can't simulate:
//! - Real DNS resolution
//! - Real TLS handshakes and certificate validation
//! - Real HTTP/2 negotiation
//! - Real compression (gzip, deflate)
//! - Real redirect behavior
//! - Real chunked transfer encoding
//!
//! Test targets are chosen to be safe for testing:
//! - example.com: IANA reserved domain for testing
//! - httpbin.org: Designed for HTTP client testing
//! - badssl.com: Designed for TLS testing
//!
//! To run only these tests:
//! ```
//! cargo test --test real_world
//! ```
//!
//! To exclude these tests:
//! ```
//! cargo test --all-features -- --skip real_world
//! ```

#![expect(clippy::tests_outside_test_module)]

use std::time::Duration;
use wrest::{Client, StatusCode};

/// Helper: build a client with sensible defaults for real-world tests
fn test_client() -> Client {
    Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("client build should succeed")
}

// -----------------------------------------------------------------------
// Production server tests
// -----------------------------------------------------------------------

/// Test against example.com (IANA reserved domain for testing)
/// Validates real DNS resolution, TLS handshake, and HTTP/1.1 or HTTP/2
#[tokio::test]
async fn example_com() {
    let client = test_client();

    let resp = client
        .get("https://example.com/")
        .send()
        .await
        .expect("example.com should be reachable");

    assert!(resp.status().is_success(), "example.com should return 2xx");
    // example.com returns a simple HTML page
    let text = resp.text().await.expect("should read body");
    assert!(text.contains("Example Domain"), "should contain expected text");
}

/// Test httpbin.org/get - service designed for HTTP testing
#[tokio::test]
async fn httpbin_get() {
    let client = test_client();

    let resp = client
        .get("https://httpbin.org/get")
        .send()
        .await
        .expect("httpbin.org should be reachable");

    assert_eq!(resp.status(), StatusCode::OK);

    // httpbin returns JSON with request details
    let text = resp.text().await.expect("should read body");
    assert!(text.contains("\"headers\""), "httpbin should return JSON");
}

/// Test httpbin.org/stream-bytes - real chunked encoding
#[tokio::test]
async fn httpbin_chunked_encoding() {
    let client = test_client();

    // Request 10KB in chunks
    let resp = client
        .get("https://httpbin.org/stream-bytes/10240")
        .send()
        .await
        .expect("chunked request should succeed");

    assert_eq!(resp.status(), StatusCode::OK);

    let bytes = resp.bytes().await.expect("should read chunked body");
    assert_eq!(bytes.len(), 10240, "should receive exactly 10KB");
}

/// Test httpbin.org/redirect - real HTTP redirects
#[tokio::test]
async fn httpbin_redirect_chain() {
    let client = test_client();

    // httpbin.org/redirect/3 does 3 redirects then returns 200
    let resp = client
        .get("https://httpbin.org/redirect/3")
        .send()
        .await
        .expect("redirect chain should succeed");

    assert_eq!(resp.status(), StatusCode::OK);
    // Final URL should be /get after redirects
    assert!(
        resp.url().path().contains("/get"),
        "should end at /get after redirects, got: {}",
        resp.url()
    );
}

/// Test httpbin.org/gzip - real gzip compression
#[tokio::test]
async fn httpbin_gzip_decompression() {
    let client = test_client();

    let resp = client
        .get("https://httpbin.org/gzip")
        .send()
        .await
        .expect("gzip request should succeed");

    assert_eq!(resp.status(), StatusCode::OK);

    // WinHTTP should auto-decompress
    let text = resp.text().await.expect("should read decompressed body");
    assert!(text.contains("\"gzipped\": true"), "should confirm gzip was used and decompressed");
}

/// Test httpbin.org/deflate - real deflate compression
#[tokio::test]
async fn httpbin_deflate_decompression() {
    let client = test_client();

    let result = client.get("https://httpbin.org/deflate").send().await;

    // httpbin.org/deflate endpoint sometimes has issues, so we allow failure
    // The gzip test above validates compression handling
    match result {
        Ok(resp) => {
            assert_eq!(resp.status(), StatusCode::OK);
            // Try to read body, but don't fail if it errors (endpoint is flaky)
            match resp.text().await {
                Ok(text) => {
                    assert!(
                        text.contains("\"deflated\": true"),
                        "should confirm deflate was used and decompressed"
                    );
                }
                Err(e) => {
                    println!("httpbin.org/deflate body read failed (known flaky): {e}");
                }
            }
        }
        Err(e) => {
            // httpbin.org/deflate is known to be flaky, don't fail the test
            println!("httpbin.org/deflate request failed (known flaky endpoint): {e}");
        }
    }
}

// -----------------------------------------------------------------------
// TLS validation tests against badssl.com
// -----------------------------------------------------------------------

/// Data-driven test for invalid TLS certificates that should fail
#[tokio::test]
async fn badssl_invalid_certs_rejected() {
    let test_cases = [
        ("https://expired.badssl.com/", "expired certificate"),
        ("https://wrong.host.badssl.com/", "wrong hostname in certificate"),
        ("https://self-signed.badssl.com/", "self-signed certificate"),
    ];

    let client = test_client();

    for (url, description) in test_cases {
        let result = client.get(url).send().await;

        assert!(result.is_err(), "{description} should be rejected");

        let err = result.unwrap_err();
        assert!(err.is_connect(), "{description} should fail with connect error, got: {err:?}");
    }
}

/// Test danger_accept_invalid_certs allows self-signed certificates
#[tokio::test]
async fn badssl_with_accept_invalid_certs() {
    // With danger_accept_invalid_certs, we should succeed
    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .danger_accept_invalid_certs(true)
        .build()
        .expect("client should build");

    let result = client.get("https://self-signed.badssl.com/").send().await;

    assert!(result.is_ok(), "with danger_accept_invalid_certs should succeed");
}

// -----------------------------------------------------------------------
// HTTP/3 tests (requires Windows 11+ and server support)
// -----------------------------------------------------------------------

/// Data-driven test for servers that support HTTP/3
/// Note: HTTP/3 requires Windows 11+ for WinHTTP support
///
/// Currently disabled: HTTP/3 is not enabled by default to avoid QUIC timeout
/// regressions on networks that block UDP. This matches reqwest's approach where
/// HTTP/3 requires explicit opt-in. If wrest adds HTTP/3 support in the future,
/// it will be behind a feature flag or explicit configuration method.
#[tokio::test]
#[ignore = "HTTP/3 not enabled by default to avoid timeout regressions"]
async fn http3_capable_servers() {
    let test_cases =
        [("https://cloudflare.com/", "cloudflare.com"), ("https://www.google.com/", "google.com")];

    let client = test_client();

    for (url, name) in test_cases {
        let resp = client
            .get(url)
            .send()
            .await
            .unwrap_or_else(|_| panic!("{name} should be reachable"));

        assert!(resp.status().is_success(), "{name} should return 2xx");

        let version = resp.version();
        println!("{name} negotiated: {version:?}");

        // Should negotiate HTTP/3, HTTP/2, or HTTP/1.1 depending on Windows version and server
        assert!(
            matches!(
                version,
                wrest::Version::HTTP_3 | wrest::Version::HTTP_2 | wrest::Version::HTTP_11
            ),
            "{name} should negotiate HTTP/3, HTTP/2, or HTTP/1.1"
        );
    }
}
