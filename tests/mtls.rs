//! Tests against a TLS server that asks for a client certificate.
//!
//! Run locally with `cargo test --test mtls`; each test creates its own
//! throwaway TLS certificate and loopback listener.
//!
//! The `client-cert` tests additionally need a certificate in
//! `CurrentUser\MY`.  `.github/ci-tools/setup-test-certs.ps1` installs one
//! and reports its thumbprint in `WREST_MTLS_THUMBPRINT`; without it they
//! skip.

#![cfg(native_winhttp)]
#![expect(clippy::tests_outside_test_module)]

use std::{sync::Arc, time::Duration};

use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
    PKCS_ECDSA_P256_SHA256,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    task::JoinHandle,
};
use tokio_rustls::{
    TlsAcceptor,
    rustls::{
        RootCertStore, ServerConfig,
        pki_types::{CertificateDer, PrivatePkcs8KeyDer},
        server::{WebPkiClientVerifier, danger::ClientCertVerifier},
    },
};
#[cfg(feature = "client-cert")]
use tokio_rustls::rustls::{
    DigitallySignedStruct, DistinguishedName, Error as TlsError, SignatureScheme,
    client::danger::HandshakeSignatureValid,
    crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature},
    pki_types::UnixTime,
    server::danger::ClientCertVerified,
};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};
use wrest::{Client, StatusCode};
#[cfg(feature = "client-cert")]
use wrest::tls::{Identity, StoreLocation};

struct TestServer {
    url: String,
    task: JoinHandle<()>,
}

enum ClientCert {
    Optional,
    Required,
    /// Accept whatever the client presents and report its thumbprint.
    #[cfg(feature = "client-cert")]
    AcceptAny,
}

enum Handshakes {
    Direct,
    RedirectRetry,
}

impl TestServer {
    fn run(client_cert: ClientCert, test: impl AsyncFnOnce(&TestServer)) {
        Self::run_with_handshakes(client_cert, Handshakes::Direct, test);
    }

    fn run_with_retry(client_cert: ClientCert, test: impl AsyncFnOnce(&TestServer)) {
        Self::run_with_handshakes(client_cert, Handshakes::RedirectRetry, test);
    }

    fn run_with_handshakes(
        client_cert: ClientCert,
        handshakes: Handshakes,
        test: impl AsyncFnOnce(&TestServer),
    ) {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build mTLS test runtime")
            .block_on(async {
                let mut server = Self::start(client_cert, handshakes).await;
                test(&server).await;
                tokio::time::timeout(Duration::from_secs(10), &mut server.task)
                    .await
                    .expect("mTLS server timed out")
                    .expect("mTLS server task failed");
            });
    }

    async fn start(client_cert: ClientCert, handshakes: Handshakes) -> Self {
        let mut params =
            CertificateParams::new(vec!["127.0.0.1".to_owned()]).expect("test server SAN");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature, KeyUsagePurpose::KeyCertSign];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("generate test server key");
        let cert = params
            .self_signed(&key)
            .expect("sign test server certificate");

        let mut roots = RootCertStore::empty();
        roots.add(cert.der().clone()).expect("add test CA");
        let verifier: Arc<dyn ClientCertVerifier> = match client_cert {
            ClientCert::Optional => WebPkiClientVerifier::builder(Arc::new(roots))
                .allow_unauthenticated()
                .build()
                .expect("build client cert verifier"),
            ClientCert::Required => WebPkiClientVerifier::builder(Arc::new(roots))
                .build()
                .expect("build client cert verifier"),
            // A store certificate has no trust path to the per-run CA, so
            // the assertion is which certificate arrived, not its chain.
            #[cfg(feature = "client-cert")]
            ClientCert::AcceptAny => Arc::new(AcceptAnyClientCert(Arc::clone(
                CryptoProvider::get_default().expect("a default rustls crypto provider"),
            ))),
        };
        let config = ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(
                vec![cert.der().clone()],
                PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
            )
            .expect("build TLS server config");

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mTLS loopback listener");
        let url = format!(
            "https://{}/client-cert",
            listener.local_addr().expect("mTLS listener address")
        );
        let task = tokio::spawn(async move {
            let acceptor = TlsAcceptor::from(Arc::new(config));
            let (socket, _) = listener.accept().await.expect("accept mTLS connection");
            let handshake = acceptor.accept(socket).await;
            let handshake = if matches!(handshakes, Handshakes::RedirectRetry) {
                handshake.expect_err("first handshake must need client cert context");
                let (socket, _) = listener
                    .accept()
                    .await
                    .expect("accept retried HTTPS connection");
                acceptor.accept(socket).await
            } else {
                handshake
            };
            if matches!(client_cert, ClientCert::Required) {
                let err = handshake.expect_err("server must reject a missing client certificate");
                assert!(
                    matches!(
                        err.get_ref().and_then(|source| source.downcast_ref()),
                        Some(tokio_rustls::rustls::Error::NoCertificatesPresented)
                    ),
                    "expected a missing client certificate, got: {err:?}"
                );
                return;
            }

            let mut tls = handshake.expect("accept optional client cert handshake");
            let body = match tls.get_ref().1.peer_certificates() {
                Some([end_entity, ..]) => peer_label(end_entity),
                _ => "none".to_owned(),
            };
            let mut request = Vec::new();
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                let mut buf = [0; 1024];
                let n = tls.read(&mut buf).await.expect("read HTTPS request");
                assert!(n > 0, "client closed before sending HTTP headers");
                request.extend_from_slice(&buf[..n]);
                assert!(request.len() <= 8192, "HTTP request headers too large");
            }
            assert!(
                request.starts_with(b"GET /client-cert HTTP/1."),
                "unexpected request: {}",
                String::from_utf8_lossy(&request)
            );
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            tls.write_all(response.as_bytes())
                .await
                .expect("write HTTPS response");
            tls.shutdown().await.expect("finish HTTPS response");
        });
        Self { url, task }
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn redirect_server(destination: &str) -> MockServer {
    let redirect = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/redirect"))
        .respond_with(ResponseTemplate::new(302).insert_header("Location", destination))
        .mount(&redirect)
        .await;
    redirect
}

async fn assert_one_redirect(redirect: &MockServer) {
    let requests = redirect
        .received_requests()
        .await
        .expect("recorded HTTP redirect requests");
    assert_eq!(requests.len(), 1, "the original HTTP request must not be replayed");
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

fn certless_client_no_retry() -> Client {
    Client::builder()
        .timeout(Duration::from_secs(10))
        .tls_danger_accept_invalid_certs(true)
        // Isolate the WinHTTP handle retry from the client's outer retry.
        .retry(wrest::retry::never())
        .build()
        .expect("client should build")
}

/// WinHTTP answers a certificate request with "no certificate" rather than
/// returning `ERROR_WINHTTP_CLIENT_AUTH_CERT_NEEDED` without sending the
/// request, so the server's response is reachable.
#[test]
fn an_optional_client_certificate_request_is_answered() {
    TestServer::run(ClientCert::Optional, async |server| {
        let response = certless_client()
            .get(server.url.as_str())
            .send()
            .await
            .expect("a certificate request must be answered, not fail the request");

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.text().await.expect("body should read").trim(), "none");
    });
}

/// Answering cert required with no cert must fail
#[test]
fn a_required_client_certificate_still_fails() {
    TestServer::run(ClientCert::Required, async |server| {
        let err = certless_client()
            .get(server.url.as_str())
            .send()
            .await
            .expect_err("a server requiring a certificate must reject us");

        assert!(err.is_connect(), "expected a connect failure, got: {err:?}");
    });
}

#[test]
fn an_http_redirect_to_optional_client_certificate_is_answered() {
    TestServer::run_with_retry(ClientCert::Optional, async |server| {
        let redirect = redirect_server(&server.url).await;

        let response = certless_client()
            .get(format!("{}/redirect", redirect.uri()))
            .send()
            .await
            .expect("the redirect should reach the HTTPS server");

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.url().as_str(), server.url);
        assert_eq!(response.text().await.expect("body should read"), "none");
        assert_one_redirect(&redirect).await;
    });
}

#[test]
fn an_http_redirect_to_required_client_certificate_still_fails() {
    TestServer::run_with_retry(ClientCert::Required, async |server| {
        let redirect = redirect_server(&server.url).await;

        let err = certless_client_no_retry()
            .get(format!("{}/redirect", redirect.uri()))
            .send()
            .await
            .expect_err("the HTTPS server must reject a missing client certificate");

        assert!(err.is_connect(), "expected a connect failure, got: {err:?}");
        assert_one_redirect(&redirect).await;
    });
}

/// Label the certificate the server received: its SHA-1 thumbprint, the
/// form `Identity::from_windows_store()` selects by.
#[cfg(feature = "client-cert")]
fn peer_label(cert: &CertificateDer<'_>) -> String {
    let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA1_FOR_LEGACY_USE_ONLY, cert);
    hex_encode(digest.as_ref())
}

#[cfg(not(feature = "client-cert"))]
fn peer_label(_cert: &CertificateDer<'_>) -> String {
    "present".to_owned()
}

/// Accepts any client certificate: a certificate from the Windows store has
/// no trust path to the per-run CA, and the assertion is which certificate
/// SChannel presented.
#[cfg(feature = "client-cert")]
#[derive(Debug)]
struct AcceptAnyClientCert(Arc<CryptoProvider>);

#[cfg(feature = "client-cert")]
impl ClientCertVerifier for AcceptAnyClientCert {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, TlsError> {
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls12_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls13_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// Parse 40 hex characters into a SHA-1 thumbprint.  Windows reports
/// thumbprints in uppercase; accept either case.
#[cfg(feature = "client-cert")]
fn parse_thumbprint(hex: &str) -> Option<[u8; 20]> {
    let hex = hex.trim();
    if hex.len() != 40 {
        return None;
    }
    let (pairs, remainder) = hex.as_bytes().as_chunks::<2>();
    debug_assert!(remainder.is_empty(), "40 is even");

    let mut out = [0u8; 20];
    for (slot, pair) in out.iter_mut().zip(pairs) {
        let pair = std::str::from_utf8(pair).ok()?;
        *slot = u8::from_str_radix(pair, 16).ok()?;
    }
    Some(out)
}

#[cfg(feature = "client-cert")]
fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len().saturating_mul(2)), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

/// The thumbprint CI installed in `CurrentUser\MY`, or `None` to skip.
#[cfg(feature = "client-cert")]
fn ci_thumbprint() -> Option<[u8; 20]> {
    let hex = std::env::var("WREST_MTLS_THUMBPRINT").ok()?;
    let parsed = parse_thumbprint(&hex)
        .unwrap_or_else(|| panic!("WREST_MTLS_THUMBPRINT is not 40 hex chars: {hex:?}"));
    Some(parsed)
}

/// The server reports the thumbprint it received, so this asserts SChannel
/// presented *our* certificate.
#[cfg(feature = "client-cert")]
#[test]
fn client_certificate_is_presented_to_the_server() {
    let Some(thumbprint) = ci_thumbprint() else {
        eprintln!("skipping: WREST_MTLS_THUMBPRINT not set");
        return;
    };

    TestServer::run(ClientCert::AcceptAny, async |server| {
        let identity = Identity::from_windows_store(StoreLocation::CurrentUser, "MY", &thumbprint)
            .expect("CI installs this certificate in CurrentUser\\MY");
        let response = Client::builder()
            .timeout(Duration::from_secs(10))
            .tls_danger_accept_invalid_certs(true)
            .identity(identity)
            .build()
            .expect("client with identity should build")
            .get(server.url.as_str())
            .send()
            .await
            .expect("mutual-TLS handshake should succeed");

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.text().await.expect("body should read").trim(),
            hex_encode(&thumbprint),
            "server saw a different certificate than the one configured"
        );
    });
}

/// The certificate CI installs must appear in the listing, and the
/// listing's thumbprint must be the one the environment reports.
#[cfg(feature = "client-cert")]
#[test]
fn ci_certificate_appears_in_the_listing() {
    let Some(thumbprint) = ci_thumbprint() else {
        eprintln!("skipping: WREST_MTLS_THUMBPRINT not set");
        return;
    };

    let certs = wrest::tls::list_client_certificates(StoreLocation::CurrentUser, "MY")
        .expect("CurrentUser\\MY should open");
    let found = certs
        .iter()
        .find(|c| c.thumbprint == thumbprint)
        .unwrap_or_else(|| {
            let seen: Vec<_> = certs.iter().map(|c| c.thumbprint_hex()).collect();
            panic!("installed certificate is missing from the listing; saw {seen:?}")
        });

    assert!(found.subject.contains("wrest-test-client"), "unexpected subject: {}", found.subject);
    assert!(found.not_after > std::time::SystemTime::now(), "listed an expired certificate");
}
