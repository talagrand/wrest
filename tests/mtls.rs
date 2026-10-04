//! Tests against a TLS server that asks for a client certificate.
//!
//! `.github/actions/start-mtls` starts the server on [`OPTIONAL`] and
//! [`REQUIRED`].  To reproduce locally on Windows, run
//! `go run .github/ci-tools/mtls-server`.

#![cfg(native_winhttp)]
#![expect(clippy::tests_outside_test_module)]

use std::time::Duration;
use wrest::{Client, StatusCode};

/// Where the server asks for a client certificate but does not require one.
const OPTIONAL: &str = "127.0.0.1:18443";

/// Where it requires one.
const REQUIRED: &str = "127.0.0.1:18444";

/// The server's base URL, or `None` when these tests should skip.
///
/// Skipping is for developers without the server running.  When
/// `start-mtls` has run it sets `WREST_MTLS`, and then an unreachable server
/// is a failure instead, so a started-but-broken server cannot turn into a
/// silently green build.
fn mtls_url(server: &str) -> Option<String> {
    match std::net::TcpStream::connect(server) {
        Ok(_) => Some(format!("https://{server}")),
        Err(e) if std::env::var_os("WREST_MTLS").is_some() => {
            panic!("start-mtls ran but {server} is unreachable ({e})")
        }
        Err(_) => {
            eprintln!("skipping: no mTLS server on {server}");
            None
        }
    }
}

/// A client with no cert identity
fn certless_client() -> Client {
    Client::builder()
        .timeout(Duration::from_secs(10))
        // The server certificate is self-signed and generated per run.
        .tls_danger_accept_invalid_certs(true)
        .build()
        .expect("client should build")
}

/// WinHTTP answers a certificate request with "no certificate" rather than
/// returning `ERROR_WINHTTP_CLIENT_AUTH_CERT_NEEDED` without sending the
/// request, so the server's response is reachable.
#[tokio::test]
async fn an_optional_client_certificate_request_is_answered() {
    let Some(url) = mtls_url(OPTIONAL) else {
        return;
    };

    let response = certless_client()
        .get(format!("{url}/client-cert"))
        .send()
        .await
        .expect("a certificate request must be answered, not fail the request");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.text().await.expect("body should read").trim(), "none");
}

/// Answering cert required with no cert must fail
#[tokio::test]
async fn a_required_client_certificate_still_fails() {
    let Some(url) = mtls_url(REQUIRED) else {
        return;
    };

    let err = certless_client()
        .get(format!("{url}/client-cert"))
        .send()
        .await
        .expect_err("a server requiring a certificate must reject us");

    assert!(err.is_connect(), "expected a connect failure, got: {err:?}");
}
