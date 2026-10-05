//! Tests against a TLS server that asks for a client certificate.
//!
//! Run locally with `cargo test --test mtls`; each test creates its own
//! throwaway TLS certificate and loopback listener.

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
        RootCertStore, ServerConfig, pki_types::PrivatePkcs8KeyDer, server::WebPkiClientVerifier,
    },
};
use wrest::{Client, StatusCode};

struct TestServer {
    url: String,
    task: JoinHandle<()>,
}

enum ClientCert {
    Optional,
    Required,
}

impl TestServer {
    fn run(client_cert: ClientCert, test: impl AsyncFnOnce(&TestServer)) {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build mTLS test runtime")
            .block_on(async {
                let mut server = Self::start(client_cert).await;
                test(&server).await;
                tokio::time::timeout(Duration::from_secs(10), &mut server.task)
                    .await
                    .expect("mTLS server timed out")
                    .expect("mTLS server task failed");
            });
    }

    async fn start(client_cert: ClientCert) -> Self {
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
        let verifier = WebPkiClientVerifier::builder(Arc::new(roots));
        let verifier = match client_cert {
            ClientCert::Optional => verifier.allow_unauthenticated(),
            ClientCert::Required => verifier,
        };
        let config = ServerConfig::builder()
            .with_client_cert_verifier(verifier.build().expect("build client cert verifier"))
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
            let body = if tls
                .get_ref()
                .1
                .peer_certificates()
                .is_some_and(|certs| !certs.is_empty())
            {
                "present"
            } else {
                "none"
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
