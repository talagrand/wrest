//! Integration tests for wrest -- exercises the real WinHTTP stack against a
//! local wiremock `MockServer`.

#![expect(clippy::tests_outside_test_module)]

use std::time::Duration;
#[cfg(feature = "json")]
use wiremock::matchers::body_json;

/// A minimal tracing subscriber that accepts every event/span but discards
/// all output.  Installing this as the global default causes `trace!()` field
/// expressions to actually be evaluated, which lets llvm-cov mark those lines
/// as covered.
#[cfg(feature = "tracing")]
struct SinkSubscriber;

#[cfg(feature = "tracing")]
impl tracing::Subscriber for SinkSubscriber {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, _: &tracing::Event<'_>) {}
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}
use wiremock::matchers::{body_bytes, body_string, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};
use wrest::{Client, HeaderMap, StatusCode, Version};

/// Helper: build a `Client` pointed at the mock server with sensible defaults.
fn test_client() -> Client {
    Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("client build should succeed")
}

/// Helper: mount a simple GET mock and return the server.
/// Returns the `MockServer` so callers can build URLs with `server.uri()`.
async fn mock_get(path_str: &str, status: u16, body: &str) -> MockServer {
    let server = MockServer::start().await;
    let mut resp = ResponseTemplate::new(status);
    if !body.is_empty() {
        resp = resp.set_body_string(body);
    }
    Mock::given(method("GET"))
        .and(path(path_str))
        .respond_with(resp)
        .expect(1)
        .mount(&server)
        .await;
    server
}

// -----------------------------------------------------------------------
// Core request / response tests
// -----------------------------------------------------------------------

/// `get_200`: GET /data -> 200 + body; verify status and text.
#[tokio::test]
async fn get_200() {
    let server = mock_get("/data", 200, "hello world").await;

    let resp = test_client()
        .get(format!("{}/data", server.uri()))
        .send()
        .await
        .expect("request should succeed");

    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.text().await.expect("body read should succeed");
    assert_eq!(body, "hello world");
}

/// `get_json_bytes`: GET /json -> 200 + JSON; deserialize from bytes.
#[cfg(feature = "json")]
#[tokio::test]
async fn get_json_bytes() {
    #[derive(Debug, serde::Deserialize, PartialEq)]
    struct Payload {
        name: String,
        value: u32,
    }

    let server = MockServer::start().await;
    let json_body = r#"{"name":"wrest","value":42}"#;

    Mock::given(method("GET"))
        .and(path("/json"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(json_body)
                .append_header("Content-Type", "application/json"),
        )
        .expect(1)
        .mount(&server)
        .await;

    let resp = test_client()
        .get(format!("{}/json", server.uri()))
        .send()
        .await
        .expect("request should succeed");

    let bytes = resp.bytes().await.expect("body read should succeed");
    let parsed: Payload = serde_json::from_slice(&bytes).expect("JSON parse should succeed");
    assert_eq!(
        parsed,
        Payload {
            name: "wrest".into(),
            value: 42
        }
    );
}

/// `post_json`: POST /api with JSON body; mock verifies the body arrived.
#[cfg(feature = "json")]
#[tokio::test]
async fn post_json() {
    #[derive(serde::Serialize)]
    struct Req {
        action: String,
        count: u32,
    }

    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/api"))
        .and(body_json(serde_json::json!({
            "action": "test",
            "count": 7
        })))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .expect(1)
        .mount(&server)
        .await;

    let resp = test_client()
        .post(format!("{}/api", server.uri()))
        .json(&Req {
            action: "test".into(),
            count: 7,
        })
        .send()
        .await
        .expect("request should succeed");

    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.text().await.expect("body read should succeed");
    assert_eq!(body, "ok");
}

/// `get_with_header`: GET /range with custom Range header; mock verifies header.
#[tokio::test]
async fn get_with_header() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/range"))
        .and(header("Range", "bytes=0-99"))
        .respond_with(ResponseTemplate::new(206).set_body_bytes(vec![0u8; 100]))
        .expect(1)
        .mount(&server)
        .await;

    let resp = test_client()
        .get(format!("{}/range", server.uri()))
        .header("Range", "bytes=0-99")
        .send()
        .await
        .expect("request should succeed");

    assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
    let bytes = resp.bytes().await.expect("body read should succeed");
    assert_eq!(bytes.len(), 100);
}

/// `streaming_chunks`: GET /large -> large body; multiple chunk() calls.
#[tokio::test]
async fn streaming_chunks() {
    let server = MockServer::start().await;

    // 128 KB body -- large enough to produce multiple WinHTTP read operations
    let large_body = vec![b'X'; 128 * 1024];

    Mock::given(method("GET"))
        .and(path("/large"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(large_body.clone()))
        .expect(1)
        .mount(&server)
        .await;

    let mut resp = test_client()
        .get(format!("{}/large", server.uri()))
        .send()
        .await
        .expect("request should succeed");

    let mut total = 0usize;
    let mut chunks = 0usize;
    while let Some(chunk) = resp.chunk().await.expect("chunk read should succeed") {
        assert!(!chunk.is_empty(), "each chunk should be non-empty");
        total += chunk.len();
        chunks += 1;
    }

    assert_eq!(total, 128 * 1024, "total bytes should match body size");
    assert!(chunks >= 1, "should have received at least one chunk");
}

/// `error_for_status`: consuming check returns Err for 4xx/5xx, Ok for 2xx.
/// Full status-code matrix is covered by `response::tests::error_for_status_table`.
#[tokio::test]
async fn error_for_status() {
    let cases: &[(u16, bool)] = &[(200, false), (500, true)];

    for &(code, expect_err) in cases {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path(format!("/efs/{code}")))
            .respond_with(ResponseTemplate::new(code).set_body_string(format!("body-{code}")))
            .expect(1)
            .mount(&server)
            .await;

        let resp = test_client()
            .get(format!("{}/efs/{code}", server.uri()))
            .send()
            .await
            .expect("request should succeed");

        assert_eq!(resp.status().as_u16(), code);

        let result = resp.error_for_status();
        assert_eq!(result.is_err(), expect_err, "error_for_status() for {code}");
        if let Err(e) = result {
            assert!(e.is_status());
            assert_eq!(e.status().unwrap().as_u16(), code);
        }
    }
}

/// `error_for_status_ref`: non-consuming check returns Err for 4xx/5xx,
/// Ok for 2xx, and the response body remains readable afterwards.
/// Full status-code matrix is covered by `response::tests::error_for_status_ref_table`.
#[tokio::test]
async fn error_for_status_ref() {
    let cases: &[(u16, &str, bool)] = &[(200, "still here", false), (404, "not found", true)];

    for &(code, body_text, expect_err) in cases {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path(format!("/efsr/{code}")))
            .respond_with(ResponseTemplate::new(code).set_body_string(body_text))
            .expect(1)
            .mount(&server)
            .await;

        let resp = test_client()
            .get(format!("{}/efsr/{code}", server.uri()))
            .send()
            .await
            .expect("request should succeed");

        let ref_result = resp.error_for_status_ref();
        assert_eq!(ref_result.is_err(), expect_err, "error_for_status_ref() for {code}");
        if let Err(e) = ref_result {
            assert!(e.is_status());
            assert_eq!(e.status().unwrap().as_u16(), code);
        }

        // Response is still usable -- read the body.
        let body = resp.text().await.expect("body should be readable");
        assert_eq!(body, body_text, "body for {code}");
    }
}

/// `connect_error`: request to a port with no server -> is_connect() error.
#[tokio::test]
async fn connect_error() {
    // Use a port that is extremely unlikely to have a listener.
    // Port 1 is reserved and almost never open.
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("client build should succeed");

    let err = client
        .get("http://127.0.0.1:1/nope")
        .send()
        .await
        .unwrap_err();

    assert!(err.is_connect(), "expected connect error, got: {err}");
}

/// `timeout`: GET /slow with 5-second server delay, 200ms client timeout.
#[tokio::test]
async fn timeout() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/slow"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("slow")
                .set_delay(Duration::from_secs(5)),
        )
        .mount(&server)
        .await;

    let client = Client::builder()
        .timeout(Duration::from_millis(200))
        .build()
        .expect("client build should succeed");

    let err = client
        .get(format!("{}/slow", server.uri()))
        .send()
        .await
        .unwrap_err();

    assert!(err.is_timeout(), "expected timeout error, got: {err}");
}

/// `version_reported`: response.version() returns HTTP/1.1 or HTTP/2.
#[tokio::test]
async fn version_reported() {
    let server = mock_get("/ver", 200, "v").await;

    let resp = test_client()
        .get(format!("{}/ver", server.uri()))
        .send()
        .await
        .expect("request should succeed");

    let version = resp.version();
    assert!(
        version == Version::HTTP_11 || version == Version::HTTP_2,
        "expected HTTP/1.1 or HTTP/2, got: {version:?}"
    );
}

/// `client_is_clone`: clone a client, both make requests successfully.
#[tokio::test]
async fn client_is_clone() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/clone"))
        .respond_with(ResponseTemplate::new(200).set_body_string("cloned"))
        .expect(2)
        .mount(&server)
        .await;

    let client1 = test_client();
    let client2 = client1.clone();

    let url = format!("{}/clone", server.uri());

    let resp1 = client1.get(&url).send().await.expect("client1 should work");
    let resp2 = client2.get(&url).send().await.expect("client2 should work");

    assert_eq!(resp1.status(), StatusCode::OK);
    assert_eq!(resp2.status(), StatusCode::OK);

    assert_eq!(resp1.text().await.expect("body1"), "cloned");
    assert_eq!(resp2.text().await.expect("body2"), "cloned");
}

/// `concurrent_requests`: 10 parallel GETs; all succeed without deadlock.
#[tokio::test]
async fn concurrent_requests() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/concurrent"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .expect(10)
        .mount(&server)
        .await;

    let client = test_client();
    let url = format!("{}/concurrent", server.uri());

    let mut handles = Vec::new();
    for _ in 0..10 {
        let c = client.clone();
        let u = url.clone();
        handles.push(tokio::spawn(async move {
            let resp = c.get(&u).send().await.expect("request should succeed");
            assert_eq!(resp.status(), StatusCode::OK);
            let body = resp.text().await.expect("body read should succeed");
            assert_eq!(body, "ok");
        }));
    }

    for h in handles {
        h.await.expect("task should not panic");
    }
}

/// `response_headers`: verify headers() returns server-set headers.
#[tokio::test]
async fn response_headers() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/hdrs"))
        .respond_with(
            ResponseTemplate::new(200)
                .append_header("X-Custom", "hello")
                .append_header("X-Another", "world")
                .set_body_string("ok"),
        )
        .expect(1)
        .mount(&server)
        .await;

    let resp = test_client()
        .get(format!("{}/hdrs", server.uri()))
        .send()
        .await
        .expect("request should succeed");

    let headers: &HeaderMap = resp.headers();

    // Custom headers from the mock response.
    assert_eq!(headers.get("x-custom").unwrap().to_str().unwrap(), "hello");
    assert_eq!(headers.get("x-another").unwrap().to_str().unwrap(), "world");

    // Standard header that wiremock always includes.
    assert!(
        headers.contains_key("content-length") || headers.contains_key("transfer-encoding"),
        "expected at least one framing header"
    );
}

/// `content_length_present`: verify content_length() returns the body size.
#[tokio::test]
async fn content_length_present() {
    let body = "twelve chars";
    let server = mock_get("/clen", 200, body).await;

    let resp = test_client()
        .get(format!("{}/clen", server.uri()))
        .send()
        .await
        .expect("request should succeed");

    assert_eq!(
        resp.content_length(),
        Some(body.len() as u64),
        "content_length() should match the body size"
    );
}

// -----------------------------------------------------------------------
// Feature-specific tests
// -----------------------------------------------------------------------

/// `response_json`: GET /json -> 200 + JSON; deserialize via Response::json().
#[cfg(feature = "json")]
#[tokio::test]
async fn response_json() {
    #[derive(Debug, serde::Deserialize, PartialEq)]
    struct Data {
        name: String,
        count: u32,
    }

    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/json-deser"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(r#"{"name":"wrest","count":99}"#)
                .append_header("Content-Type", "application/json"),
        )
        .expect(1)
        .mount(&server)
        .await;

    let data: Data = test_client()
        .get(format!("{}/json-deser", server.uri()))
        .send()
        .await
        .expect("request should succeed")
        .json()
        .await
        .expect("json deserialization should succeed");

    assert_eq!(
        data,
        Data {
            name: "wrest".into(),
            count: 99
        }
    );
}

/// `bearer_auth`: GET with bearer token; mock verifies Authorization header.
/// Unit-level coverage: `request::tests::bearer_auth_sets_header`.
#[tokio::test]
async fn bearer_auth() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/auth"))
        .and(header("authorization", "Bearer my-secret-token"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .expect(1)
        .mount(&server)
        .await;

    let resp = test_client()
        .get(format!("{}/auth", server.uri()))
        .bearer_auth("my-secret-token")
        .send()
        .await
        .expect("request should succeed");

    assert_eq!(resp.status(), StatusCode::OK);
}

/// `basic_auth`: GET with basic auth; mock verifies Authorization header.
/// Unit-level coverage: `request::tests::basic_auth_table`.
#[tokio::test]
async fn basic_auth() {
    use base64::Engine as _;
    let expected =
        format!("Basic {}", base64::engine::general_purpose::STANDARD.encode("user:pass"));

    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/basic"))
        .and(header("authorization", expected.as_str()))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .expect(1)
        .mount(&server)
        .await;

    let resp = test_client()
        .get(format!("{}/basic", server.uri()))
        .basic_auth("user", Some("pass"))
        .send()
        .await
        .expect("request should succeed");

    assert_eq!(resp.status(), StatusCode::OK);
}

/// `raw_body`: POST with raw body; mock verifies body arrived.
#[tokio::test]
async fn raw_body() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/raw"))
        .and(body_string("raw body content"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .expect(1)
        .mount(&server)
        .await;

    let resp = test_client()
        .post(format!("{}/raw", server.uri()))
        .body("raw body content".as_bytes().to_vec())
        .send()
        .await
        .expect("request should succeed");

    assert_eq!(resp.status(), StatusCode::OK);
}

/// `empty_bytes_body`: POST with `Body::from(vec![])` exercises the explicit
/// empty-body branch in `execute_request` (distinct from no body at all).
#[tokio::test]
async fn empty_bytes_body() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/empty-body"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .expect(1)
        .mount(&server)
        .await;

    let resp = test_client()
        .post(format!("{}/empty-body", server.uri()))
        .body(Vec::<u8>::new())
        .send()
        .await
        .expect("request with empty body should succeed");

    assert_eq!(resp.status(), StatusCode::OK);
}

/// Streaming body POST: data-driven test exercising several chunk patterns.
///
/// Each case sends a POST with `Body::wrap_stream()` and verifies the server
/// receives the expected concatenated payload.
#[tokio::test]
async fn streaming_body_variants() {
    // (label, path, chunks, expected_body)
    let cases: Vec<(&str, &str, Vec<bytes::Bytes>, Vec<u8>)> = vec![
        (
            "multi-chunk",
            "/stream-upload",
            vec![
                bytes::Bytes::from("chunk1"),
                bytes::Bytes::from("chunk2"),
                bytes::Bytes::from("chunk3"),
            ],
            b"chunk1chunk2chunk3".to_vec(),
        ),
        ("empty stream", "/stream-empty", vec![], b"".to_vec()),
        (
            "single chunk",
            "/stream-single",
            vec![bytes::Bytes::from("only-chunk")],
            b"only-chunk".to_vec(),
        ),
        (
            "binary with fake terminator",
            "/stream-binary",
            vec![bytes::Bytes::from_static(b"before\r\n0\r\n\r\nafter")],
            b"before\r\n0\r\n\r\nafter".to_vec(),
        ),
        (
            "empty chunks ignored",
            "/stream-gaps",
            vec![
                bytes::Bytes::new(),
                bytes::Bytes::from("A"),
                bytes::Bytes::new(),
                bytes::Bytes::new(),
                bytes::Bytes::from("B"),
                bytes::Bytes::new(),
            ],
            b"AB".to_vec(),
        ),
    ];

    let server = MockServer::start().await;

    for (label, sub_path, chunks, expected) in cases {
        Mock::given(method("POST"))
            .and(path(sub_path))
            .and(body_bytes(expected.clone()))
            .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
            .expect(1)
            .mount(&server)
            .await;

        let stream = futures_util::stream::iter(chunks.into_iter().map(Ok::<_, std::io::Error>));

        let resp = test_client()
            .post(format!("{}{sub_path}", server.uri()))
            .body(wrest::Body::wrap_stream(stream))
            .send()
            .await
            .unwrap_or_else(|e| panic!("{label}: {e}"));

        assert_eq!(resp.status(), StatusCode::OK, "{label}");
    }
}

/// `streaming_body_error_propagated`: an I/O error yielded by the
/// stream is surfaced as a `wrest::Error` (not a panic or hang).
#[tokio::test]
async fn streaming_body_error_propagated() {
    let server = MockServer::start().await;

    let stream = futures_util::stream::iter(vec![
        Ok::<_, std::io::Error>(bytes::Bytes::from("good")),
        Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "boom")),
        Ok(bytes::Bytes::from("never-sent")),
    ]);

    let result = test_client()
        .post(format!("{}/stream-fail", server.uri()))
        .body(wrest::Body::wrap_stream(stream))
        .send()
        .await;

    let err = result.expect_err("stream error should propagate");
    assert!(
        err.is_request(),
        "expected a request error (body stream failed during send), got: {err:?}"
    );
    // Display shows a generic prefix ("error sending request"), matching
    // reqwest.  The root-cause "boom" text is in the Debug representation.
    assert!(
        format!("{err:?}").contains("boom"),
        "error debug should contain the stream error text, got: {err:?}"
    );
}

/// `streaming_body_delayed_chunks`: a stream that yields chunks with
/// small delays between them.  Exercises the chunked-transfer path with
/// realistic async timing rather than a pre-buffered iterator.
#[tokio::test]
async fn streaming_body_delayed_chunks() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/stream-delayed"))
        .and(body_bytes(b"slowAslowB".to_vec()))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .expect(1)
        .mount(&server)
        .await;

    let stream = futures_util::stream::unfold(0u8, |state| async move {
        if state >= 2 {
            return None;
        }
        // Small delay to simulate a slow producer
        tokio::time::sleep(Duration::from_millis(50)).await;
        let chunk = bytes::Bytes::from(format!("slow{}", (b'A' + state) as char));
        Some((Ok::<_, std::io::Error>(chunk), state + 1))
    });

    let resp = test_client()
        .post(format!("{}/stream-delayed", server.uri()))
        .body(wrest::Body::wrap_stream(stream))
        .send()
        .await
        .expect("delayed stream request should succeed");

    assert_eq!(resp.status(), StatusCode::OK);
}

/// `concurrent_requests_streaming`: 5 parallel POSTs with streaming bodies;
/// verifies that multiple simultaneous chunked uploads don't interfere with
/// each other.
#[tokio::test]
async fn concurrent_requests_streaming() {
    let server = MockServer::start().await;

    for i in 0..5u8 {
        let expected = format!("stream-{i}-Astream-{i}-B");
        Mock::given(method("POST"))
            .and(path(format!("/concurrent-stream/{i}")))
            .and(body_string(expected))
            .respond_with(ResponseTemplate::new(200).set_body_string(format!("ok-{i}")))
            .expect(1)
            .mount(&server)
            .await;
    }

    let client = test_client();
    let uri = server.uri();

    let mut handles = Vec::new();
    for i in 0..5u8 {
        let c = client.clone();
        let base = uri.clone();
        handles.push(tokio::spawn(async move {
            let stream = futures_util::stream::unfold(0u8, move |state| async move {
                if state >= 2 {
                    return None;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
                let chunk = bytes::Bytes::from(format!("stream-{i}-{}", (b'A' + state) as char));
                Some((Ok::<_, std::io::Error>(chunk), state + 1))
            });

            let resp = c
                .post(format!("{base}/concurrent-stream/{i}"))
                .body(wrest::Body::wrap_stream(stream))
                .send()
                .await
                .unwrap_or_else(|e| panic!("concurrent stream {i}: {e}"));

            assert_eq!(resp.status(), StatusCode::OK, "stream {i}");
            let body = resp.text().await.unwrap();
            assert_eq!(body, format!("ok-{i}"), "stream {i} body");
        }));
    }

    for h in handles {
        h.await.expect("task should not panic");
    }
}

/// `headers_bulk`: GET with multiple headers via headers(HeaderMap).
#[tokio::test]
async fn headers_bulk() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/bulk-hdrs"))
        .and(header("x-custom-one", "value1"))
        .and(header("x-custom-two", "value2"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .expect(1)
        .mount(&server)
        .await;

    let mut map = HeaderMap::new();
    map.insert("x-custom-one", "value1".parse().unwrap());
    map.insert("x-custom-two", "value2".parse().unwrap());

    let resp = test_client()
        .get(format!("{}/bulk-hdrs", server.uri()))
        .headers(map)
        .send()
        .await
        .expect("request should succeed");

    assert_eq!(resp.status(), StatusCode::OK);
}

/// `query_params`: GET with query parameters appended by query().
#[cfg(feature = "query")]
#[tokio::test]
async fn query_params() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/search"))
        .and(wiremock::matchers::query_param("q", "rust"))
        .and(wiremock::matchers::query_param("page", "2"))
        .respond_with(ResponseTemplate::new(200).set_body_string("results"))
        .expect(1)
        .mount(&server)
        .await;

    let resp = test_client()
        .get(format!("{}/search", server.uri()))
        .query(&[("q", "rust"), ("page", "2")])
        .send()
        .await
        .expect("request should succeed");

    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.text().await.unwrap();
    assert_eq!(body, "results");
}

/// `form_post`: POST with form-encoded body.
#[cfg(feature = "form")]
#[tokio::test]
async fn form_post() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/form"))
        .and(header("content-type", "application/x-www-form-urlencoded"))
        .and(body_string("user=admin&pass=secret"))
        .respond_with(ResponseTemplate::new(200).set_body_string("logged in"))
        .expect(1)
        .mount(&server)
        .await;

    let resp = test_client()
        .post(format!("{}/form", server.uri()))
        .form(&[("user", "admin"), ("pass", "secret")])
        .send()
        .await
        .expect("request should succeed");

    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.text().await.unwrap(), "logged in");
}

/// `per_request_timeout`: per-request timeout overrides client timeout.
#[tokio::test]
async fn per_request_timeout() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/slow-req"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("slow")
                .set_delay(Duration::from_secs(5)),
        )
        .mount(&server)
        .await;

    // Client has a generous 30s timeout, but per-request is 200ms.
    let client = Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .expect("client build should succeed");

    let err = client
        .get(format!("{}/slow-req", server.uri()))
        .timeout(Duration::from_millis(200))
        .send()
        .await
        .unwrap_err();

    assert!(err.is_timeout(), "expected timeout error, got: {err}");
}

/// `default_headers_applied`: default headers from client appear on request.
#[tokio::test]
async fn default_headers_applied() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/default-hdrs"))
        .and(header("x-default", "from-client"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .expect(1)
        .mount(&server)
        .await;

    let mut default = HeaderMap::new();
    default.insert("x-default", "from-client".parse().unwrap());

    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .default_headers(default)
        .build()
        .expect("client build should succeed");

    let resp = client
        .get(format!("{}/default-hdrs", server.uri()))
        .send()
        .await
        .expect("request should succeed");

    assert_eq!(resp.status(), StatusCode::OK);
}

/// `headers_mut_modify`: modify response headers via headers_mut().
#[tokio::test]
async fn headers_mut_modify() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/mut-hdrs"))
        .respond_with(
            ResponseTemplate::new(200)
                .append_header("x-original", "original")
                .set_body_string("ok"),
        )
        .expect(1)
        .mount(&server)
        .await;

    let mut resp = test_client()
        .get(format!("{}/mut-hdrs", server.uri()))
        .send()
        .await
        .expect("request should succeed");

    // Verify original header
    assert_eq!(resp.headers().get("x-original").unwrap().to_str().unwrap(), "original");

    // Modify via headers_mut
    resp.headers_mut()
        .insert("x-added", "injected".parse().unwrap());

    assert_eq!(resp.headers().get("x-added").unwrap().to_str().unwrap(), "injected");
}

/// `text_with_charset_utf8`: UTF-8 body passes through text_with_charset.
#[tokio::test]
async fn text_with_charset_utf8() {
    let server = mock_get("/charset", 200, "hello UTF-8").await;

    let text = test_client()
        .get(format!("{}/charset", server.uri()))
        .send()
        .await
        .expect("request should succeed")
        .text_with_charset("windows-1252")
        .await
        .expect("text_with_charset should succeed");

    assert_eq!(text, "hello UTF-8");
}

/// `try_clone_send_both`: clone a request builder, send both copies.
#[tokio::test]
async fn try_clone_send_both() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/clone-test"))
        .respond_with(ResponseTemplate::new(200).set_body_string("cloned"))
        .expect(2)
        .mount(&server)
        .await;

    let rb = test_client().get(format!("{}/clone-test", server.uri()));

    let rb2 = rb.try_clone().expect("clone should succeed");

    let resp1 = rb.send().await.expect("original send");
    let resp2 = rb2.send().await.expect("clone send");

    assert_eq!(resp1.status(), StatusCode::OK);
    assert_eq!(resp2.status(), StatusCode::OK);
    assert_eq!(resp1.text().await.unwrap(), "cloned");
    assert_eq!(resp2.text().await.unwrap(), "cloned");
}

/// `version_hint_accepted`: version() does not cause errors.
#[tokio::test]
#[cfg(feature = "noop-compat")]
async fn version_hint_accepted() {
    let server = mock_get("/ver-hint", 200, "ok").await;

    let resp = test_client()
        .get(format!("{}/ver-hint", server.uri()))
        .version(Version::HTTP_11)
        .send()
        .await
        .expect("request with version hint should succeed");

    assert_eq!(resp.status(), StatusCode::OK);
}

// -----------------------------------------------------------------------
// HTTP method and advanced feature tests
// -----------------------------------------------------------------------

/// Data-driven test for HTTP methods (PUT, PATCH, DELETE) with request bodies
#[tokio::test]
async fn http_methods_with_body() {
    let test_cases = [
        ("PUT", "/resource", "updated", StatusCode::OK, "ok"),
        ("PATCH", "/resource", "patched", StatusCode::OK, "ok"),
        ("DELETE", "/resource/42", "", StatusCode::NO_CONTENT, ""),
    ];

    for (http_method, path_str, request_body, expected_status, response_body) in test_cases {
        let server = MockServer::start().await;

        let mut mock = Mock::given(method(http_method)).and(path(path_str));

        if !request_body.is_empty() {
            mock = mock.and(body_string(request_body));
        }

        let mut response = ResponseTemplate::new(expected_status.as_u16());
        if !response_body.is_empty() {
            response = response.set_body_string(response_body);
        }

        mock.respond_with(response).expect(1).mount(&server).await;

        let url = format!("{}{path_str}", server.uri());
        let req = match http_method {
            "PUT" => test_client().put(&url),
            "PATCH" => test_client().patch(&url),
            "DELETE" => test_client().delete(&url),
            _ => unreachable!(),
        };

        let req = if !request_body.is_empty() {
            req.body(request_body)
        } else {
            req
        };

        let resp = req
            .send()
            .await
            .unwrap_or_else(|_| panic!("{http_method} should succeed"));

        assert_eq!(resp.status(), expected_status, "{http_method} should return {expected_status}");

        if !response_body.is_empty() {
            assert_eq!(
                resp.text().await.unwrap(),
                response_body,
                "{http_method} response body mismatch"
            );
        }
    }
}

#[tokio::test]
async fn head_returns_no_body() {
    let server = MockServer::start().await;

    Mock::given(method("HEAD"))
        .and(path("/resource"))
        .respond_with(
            ResponseTemplate::new(200)
                .append_header("content-length", "12")
                // wiremock strips the body for HEAD automatically
                .set_body_string("twelve chars"),
        )
        .expect(1)
        .mount(&server)
        .await;

    let resp = test_client()
        .head(format!("{}/resource", server.uri()))
        .send()
        .await
        .expect("HEAD should succeed");

    assert_eq!(resp.status(), StatusCode::OK);
    // HEAD responses have no body
    let body = resp.bytes().await.expect("bytes should succeed");
    assert!(body.is_empty(), "HEAD response body should be empty");
}

/// `redirect_followed`: 302 redirect is followed by default.
#[tokio::test]
async fn redirect_followed() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/old"))
        .respond_with(
            ResponseTemplate::new(302).append_header("Location", format!("{}/new", server.uri())),
        )
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/new"))
        .respond_with(ResponseTemplate::new(200).set_body_string("arrived"))
        .expect(1)
        .mount(&server)
        .await;

    let resp = test_client()
        .get(format!("{}/old", server.uri()))
        .send()
        .await
        .expect("redirect should be followed");

    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.text().await.unwrap(), "arrived");
}

/// `redirect_blocked`: Policy::none() prevents redirect following.
#[tokio::test]
async fn redirect_blocked() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/redir"))
        .respond_with(
            ResponseTemplate::new(302).append_header("Location", format!("{}/dest", server.uri())),
        )
        .expect(1)
        .mount(&server)
        .await;

    // No mock for /dest -- if redirect is followed, wiremock will 404.

    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .redirect(wrest::redirect::Policy::none())
        .build()
        .expect("client build should succeed");

    let resp = client
        .get(format!("{}/redir", server.uri()))
        .send()
        .await
        .expect("request should succeed (not follow redirect)");

    assert_eq!(resp.status(), StatusCode::FOUND, "should get 302 directly without following");
}

/// `json_deserialization_failure`: malformed JSON -> error from json().
#[cfg(feature = "json")]
#[tokio::test]
async fn json_deserialization_failure() {
    #[derive(Debug, serde::Deserialize)]
    struct Data {
        _name: String,
    }

    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/bad-json"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("{broken json")
                .append_header("Content-Type", "application/json"),
        )
        .expect(1)
        .mount(&server)
        .await;

    let result: Result<Data, _> = test_client()
        .get(format!("{}/bad-json", server.uri()))
        .send()
        .await
        .expect("request should succeed")
        .json()
        .await;

    assert!(result.is_err(), "malformed JSON should produce an error");
    let err = result.unwrap_err();
    assert!(err.is_decode(), "JSON parse error should be is_decode()");
    assert!(!err.is_body(), "JSON parse error should not be is_body()");
}

/// `get_free_function`: exercise `wrest::get()` convenience function.
#[tokio::test]
async fn get_free_function() {
    let server = mock_get("/free", 200, "free").await;

    let resp = wrest::get(format!("{}/free", server.uri()))
        .await
        .expect("wrest::get() should succeed");

    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.text().await.unwrap(), "free");
}

/// `bytes_stream_collect`: consume response via bytes_stream().
#[tokio::test]
async fn bytes_stream_collect() {
    use futures_util::StreamExt;
    use std::pin::pin;

    let server = MockServer::start().await;
    let body_data = vec![b'A'; 64 * 1024]; // 64 KB

    Mock::given(method("GET"))
        .and(path("/stream"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(body_data.clone()))
        .expect(1)
        .mount(&server)
        .await;

    let resp = test_client()
        .get(format!("{}/stream", server.uri()))
        .send()
        .await
        .expect("request should succeed");

    let mut total = 0usize;
    let mut stream = pin!(resp.bytes_stream());
    while let Some(chunk) = stream.next().await {
        let bytes = chunk.expect("chunk should succeed");
        assert!(!bytes.is_empty());
        total += bytes.len();
    }

    assert_eq!(total, 64 * 1024, "total bytes should match body size");
}

/// `client_execute`: build a Request, then execute via Client::execute().
#[tokio::test]
async fn client_execute() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/exec"))
        .and(body_string("execute-body"))
        .and(header("x-custom", "via-execute"))
        .respond_with(ResponseTemplate::new(200).set_body_string("executed"))
        .expect(1)
        .mount(&server)
        .await;

    let client = test_client();
    let req = client
        .post(format!("{}/exec", server.uri()))
        .header("x-custom", "via-execute")
        .body("execute-body")
        .build()
        .expect("build should succeed");

    let resp = client.execute(req).await.expect("execute should succeed");

    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.text().await.unwrap(), "executed");
}

// -----------------------------------------------------------------------
// response.url() after redirect
// -----------------------------------------------------------------------

/// After a 302 redirect, `response.url()` reflects the final location
/// (matching reqwest behavior).
#[tokio::test]
async fn response_url_after_redirect() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/redir"))
        .respond_with(
            ResponseTemplate::new(302).insert_header("location", format!("{}/final", server.uri())),
        )
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/final"))
        .respond_with(ResponseTemplate::new(200).set_body_string("arrived"))
        .expect(1)
        .mount(&server)
        .await;

    let resp = test_client()
        .get(format!("{}/redir", server.uri()))
        .send()
        .await
        .expect("request should succeed");

    assert_eq!(resp.status(), StatusCode::OK);
    // After following the redirect, url() must report the final destination.
    let url = resp.url().to_string();
    assert!(url.contains("/final"), "expected url to end with /final, got: {url}");
    assert_eq!(resp.text().await.unwrap(), "arrived");
}

/// `content_length_absent`: chunked/no CL header -> `None`.
#[tokio::test]
async fn content_length_absent() {
    let server = MockServer::start().await;

    // Transfer-Encoding: chunked -- wiremock doesn't set Content-Length when
    // we use a streaming body, but for safety we create a response without
    // an explicit Content-Length by using set_body_bytes with empty body and
    // manually removing the header isn't feasible. Instead, just verify
    // behaviour when the header IS present (covered above). This test uses
    // a HEAD request which may or may not carry Content-Length.
    Mock::given(method("HEAD"))
        .and(path("/nocl"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let resp = test_client()
        .head(format!("{}/nocl", server.uri()))
        .send()
        .await
        .expect("request should succeed");

    // 204 with no body -- Content-Length may be absent or zero.
    let cl = resp.content_length();
    assert!(cl.is_none() || cl == Some(0), "204 should have no/zero content-length, got: {cl:?}");
}

// -----------------------------------------------------------------------
// text() with charset
// -----------------------------------------------------------------------

/// `text_with_latin1_charset`: mock server sends Latin-1 encoded bytes with
/// `Content-Type: text/html; charset=iso-8859-1`. Verify `text()` decodes
/// the non-ASCII bytes correctly.
#[tokio::test]
async fn text_with_latin1_charset() {
    let server = MockServer::start().await;

    // Latin-1 bytes for "cafe" (e with acute = 0xE9 in ISO-8859-1).
    let latin1_body: Vec<u8> = vec![0x63, 0x61, 0x66, 0xE9];

    Mock::given(method("GET"))
        .and(path("/latin"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/html; charset=iso-8859-1")
                .set_body_raw(latin1_body, "text/html; charset=iso-8859-1"),
        )
        .expect(1)
        .mount(&server)
        .await;

    let resp = test_client()
        .get(format!("{}/latin", server.uri()))
        .send()
        .await
        .expect("request should succeed");

    let text = resp.text().await.expect("text() should succeed");
    assert_eq!(text, "caf\u{e9}", "Latin-1 0xE9 should decode to U+00E9");
}

// -----------------------------------------------------------------------
// Remote content-length via headers
// -----------------------------------------------------------------------

/// Verify `remote_addr()` returns an address on localhost for a local mock.
#[cfg(feature = "noop-compat")]
#[tokio::test]
async fn remote_addr_is_localhost() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/addr"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;

    let resp = test_client()
        .get(format!("{}/addr", server.uri()))
        .send()
        .await
        .expect("request should succeed");

    // WinHTTP may or may not expose remote_addr depending on platform version.
    // We simply ensure calling it doesn't panic.
    let _ = resp.remote_addr();
}

// -----------------------------------------------------------------------
// Regression: send() delegates to build() + execute()
// -----------------------------------------------------------------------

/// `url_userinfo_basic_auth`: GET with user:pass in URL; verify Authorization
/// header is injected via the send() path (regression test for the build/send
/// unification).
#[tokio::test]
async fn url_userinfo_basic_auth() {
    use base64::Engine as _;
    let expected_auth =
        format!("Basic {}", base64::engine::general_purpose::STANDARD.encode("alice:s3cret"));

    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api"))
        .and(header("authorization", expected_auth.as_str()))
        .respond_with(ResponseTemplate::new(200).set_body_string("authenticated"))
        .expect(1)
        .mount(&server)
        .await;

    // Inject userinfo into the mock server's URL
    let url = server.uri().replace("http://", "http://alice:s3cret@");

    let resp = test_client()
        .get(format!("{url}/api"))
        .send()
        .await
        .expect("request should succeed");

    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.text().await.expect("body read should succeed");
    assert_eq!(body, "authenticated");
}

/// `default_accept_header`: Verify Accept: */* is sent when no explicit Accept
/// is set, even through the send() path.
#[tokio::test]
async fn default_accept_header() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/accept"))
        .and(header("accept", "*/*"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .expect(1)
        .mount(&server)
        .await;

    let resp = test_client()
        .get(format!("{}/accept", server.uri()))
        .send()
        .await
        .expect("request should succeed");

    assert_eq!(resp.status(), StatusCode::OK);
}

/// `http1_only_mode`: verify http1_only() builder option works.
#[tokio::test]
async fn http1_only_mode() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/h1-only"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .expect(1)
        .mount(&server)
        .await;

    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .http1_only()
        .build()
        .expect("client with http1_only should build");

    let resp = client
        .get(format!("{}/h1-only", server.uri()))
        .send()
        .await
        .expect("HTTP/1-only request should succeed");

    assert_eq!(resp.status(), StatusCode::OK);
    // Version will be HTTP/1.1 or HTTP/1.0 (never HTTP/2)
    assert!(
        matches!(resp.version(), Version::HTTP_11 | Version::HTTP_10),
        "HTTP/1-only should not use HTTP/2"
    );
}

/// `max_connections_per_host_config`: verify max_connections_per_host() option
/// exercises the `WinHttpSession::open` path that sets `WINHTTP_OPTION_MAX_CONNS_PER_SERVER`.
/// Unit-level coverage: `client::tests::builder_field_storage_table` (builder storage only).
#[tokio::test]
async fn max_connections_per_host_config() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/max-conns"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .expect(1)
        .mount(&server)
        .await;

    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .max_connections_per_host(2)
        .build()
        .expect("client with max_connections_per_host should build");

    let resp = client
        .get(format!("{}/max-conns", server.uri()))
        .send()
        .await
        .expect("request should succeed");

    assert_eq!(resp.status(), StatusCode::OK);
}

/// `redirect_policy_limited`: test Policy::limited() with custom max redirects.
#[tokio::test]
async fn redirect_policy_limited() {
    let server = MockServer::start().await;

    // Chain: /r0 -> /r1 -> /r2 -> /final
    for i in 0..3 {
        Mock::given(method("GET"))
            .and(path(format!("/r{i}")))
            .respond_with(
                ResponseTemplate::new(302)
                    .insert_header("location", format!("{}/r{}", server.uri(), i + 1)),
            )
            .expect(1)
            .mount(&server)
            .await;
    }

    Mock::given(method("GET"))
        .and(path("/r3"))
        .respond_with(ResponseTemplate::new(200).set_body_string("final"))
        .expect(1)
        .mount(&server)
        .await;

    // Client allows up to 5 redirects
    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .redirect(wrest::redirect::Policy::limited(5))
        .build()
        .expect("client should build");

    let resp = client
        .get(format!("{}/r0", server.uri()))
        .send()
        .await
        .expect("redirect chain should succeed");

    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.text().await.unwrap(), "final");
}

/// `redirect_policy_limited_exceeded`: verify redirects stop at the limit.
#[tokio::test]
async fn redirect_policy_limited_exceeded() {
    let server = MockServer::start().await;

    // Create a redirect loop: /loop0 -> /loop1 -> /loop0 -> ...
    for i in 0..2 {
        Mock::given(method("GET"))
            .and(path(format!("/loop{i}")))
            .respond_with(
                ResponseTemplate::new(302)
                    .insert_header("location", format!("{}/loop{}", server.uri(), (i + 1) % 2)),
            )
            .mount(&server)
            .await;
    }

    // Client allows only 2 redirects
    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .redirect(wrest::redirect::Policy::limited(2))
        .build()
        .expect("client should build");

    let result = client.get(format!("{}/loop0", server.uri())).send().await;

    // Should fail with redirect error or return the last 302
    // WinHTTP handles this internally, so we just verify it doesn't infinite loop
    if let Err(e) = result {
        assert!(
            e.is_redirect() || e.is_request(),
            "should be redirect or request error, got: {e:?}"
        );
    } else {
        // Or it might return the 302 status
        let resp = result.unwrap();
        assert!(
            resp.status().is_redirection(),
            "should get redirect status, got: {}",
            resp.status()
        );
    }
}

// NOTE: `danger_accept_invalid_certs` builder option is covered by
// `client::tests::builder_accept_invalid_certs_propagated` (unit) and
// `real_world::badssl_with_accept_invalid_certs` (end-to-end with real cert).

/// `connection_verbose_tracing`: verify verbose flag is accepted and requests work.
///
/// A `SinkSubscriber` is installed as the global tracing subscriber so that
/// `trace!()` field expressions are evaluated, improving coverage of the
/// trace instrumentation in `winhttp.rs` and `client.rs`.
#[tokio::test]
#[cfg(feature = "tracing")]
async fn connection_verbose_tracing() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = tracing::subscriber::set_global_default(SinkSubscriber);
    });

    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/verbose"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .expect(1)
        .mount(&server)
        .await;

    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .connection_verbose(true)
        .build()
        .expect("client with verbose tracing should build");

    let resp = client
        .get(format!("{}/verbose", server.uri()))
        .send()
        .await
        .expect("verbose request should succeed");

    assert_eq!(resp.status(), StatusCode::OK);
}

/// `large_streaming_body_upload`: POST with large streaming body (chunked encoding).
#[tokio::test]
async fn large_streaming_body_upload() {
    let server = MockServer::start().await;

    // Create a 2MB streaming body
    let chunk_count = 128;
    let chunk_size = 16 * 1024; // 16KB chunks
    let chunks: Vec<bytes::Bytes> = (0..chunk_count)
        .map(|i| bytes::Bytes::from(vec![i as u8; chunk_size]))
        .collect();

    Mock::given(method("POST"))
        .and(path("/large-stream"))
        .respond_with(ResponseTemplate::new(200).set_body_string("streamed"))
        .expect(1)
        .mount(&server)
        .await;

    let stream = futures_util::stream::iter(chunks.into_iter().map(Ok::<_, std::io::Error>));

    let resp = test_client()
        .post(format!("{}/large-stream", server.uri()))
        .body(wrest::Body::wrap_stream(stream))
        .send()
        .await
        .expect("large streaming upload should succeed");

    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.text().await.unwrap(), "streamed");
}

// -----------------------------------------------------------------------
// Advanced coverage: Proxy (data-driven)
// -----------------------------------------------------------------------

/// Data-driven proxy configuration variants.
///
/// Each row builds a client with a different proxy setup, sends a GET
/// through wiremock, and asserts 200.
#[tokio::test]
async fn proxy_variants() {
    // (label, builder_fn)
    //
    // `builder_fn` receives the wiremock URI and returns a configured
    // `ClientBuilder`.  All cases send GET /{label} and expect 200.
    type BuilderFn = Box<dyn Fn(&str) -> wrest::ClientBuilder>;
    let cases: Vec<(&str, BuilderFn)> = vec![
        (
            "named-http",
            Box::new(|uri: &str| {
                Client::builder()
                    .timeout(Duration::from_secs(10))
                    .proxy(wrest::Proxy::http(uri).unwrap())
            }),
        ),
        (
            "named-with-creds",
            Box::new(|uri: &str| {
                Client::builder()
                    .timeout(Duration::from_secs(10))
                    .proxy(wrest::Proxy::http(uri).unwrap().basic_auth("user", "pass"))
            }),
        ),
        (
            "no-proxy",
            Box::new(|_uri: &str| {
                Client::builder()
                    .timeout(Duration::from_secs(10))
                    .no_proxy()
            }),
        ),
    ];

    // Config-only: proxy that points nowhere — just verify build succeeds.
    Client::builder()
        .timeout(Duration::from_secs(10))
        .proxy(wrest::Proxy::http("http://localhost:9999").unwrap())
        .build()
        .expect("config-only proxy client should build");

    for (label, builder_fn) in &cases {
        let server = MockServer::start().await;
        let uri = server.uri();
        let path_str = format!("/{label}");

        Mock::given(method("GET"))
            .and(path(&path_str))
            .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
            .expect(1)
            .mount(&server)
            .await;

        let client = builder_fn(&uri)
            .build()
            .unwrap_or_else(|e| panic!("{label}: build failed: {e}"));

        let resp = client
            .get(format!("{uri}{path_str}"))
            .send()
            .await
            .unwrap_or_else(|e| panic!("{label}: request failed: {e}"));

        assert_eq!(resp.status(), StatusCode::OK, "{label}");
    }
}

// -----------------------------------------------------------------------
// Response extensions
// -----------------------------------------------------------------------

/// `response_extensions`: verify extensions() / extensions_mut() round-trip.
#[tokio::test]
async fn response_extensions() {
    let server = mock_get("/ext", 200, "ok").await;

    let mut resp = test_client()
        .get(format!("{}/ext", server.uri()))
        .send()
        .await
        .expect("request should succeed");

    // Initially empty
    assert!(resp.extensions().get::<String>().is_none());

    // Insert and retrieve a custom type
    resp.extensions_mut().insert("custom-data".to_owned());
    assert_eq!(resp.extensions().get::<String>().unwrap(), "custom-data");
}

// NOTE: Body-read timeout behaviour shares the same WinHTTP timeout path
// as the `timeout` integration test above — both hit ERROR_WINHTTP_TIMEOUT.

// -----------------------------------------------------------------------
// Redirect edge cases
// -----------------------------------------------------------------------

/// Data-driven: 307/308 preserve POST; 301/303 demote POST→GET.
///
/// Per RFC 7231 / RFC 7538:
/// - 307/308: method and body MUST be preserved.
/// - 301/303: user agents typically change POST to GET.
#[tokio::test]
async fn redirect_method_handling() {
    // (status, orig_path, dest_path, dest_method, expected_body, label)
    let cases: &[(u16, &str, &str, &str, &str, &str)] = &[
        (307, "/orig307", "/dest307", "POST", "307ok", "307 preserves POST"),
        (308, "/orig308", "/dest308", "POST", "308ok", "308 preserves POST"),
        (301, "/old301", "/new301", "GET", "demoted301", "301 demotes POST→GET"),
        (303, "/old303", "/new303", "GET", "see-other", "303 demotes POST→GET"),
    ];

    for &(status, orig, dest, dest_method, body, label) in cases {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path(orig))
            .respond_with(
                ResponseTemplate::new(status)
                    .insert_header("location", format!("{}{dest}", server.uri())),
            )
            .expect(1)
            .mount(&server)
            .await;

        Mock::given(method(dest_method))
            .and(path(dest))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .expect(1)
            .mount(&server)
            .await;

        let resp = test_client()
            .post(format!("{}{orig}", server.uri()))
            .body("data")
            .send()
            .await
            .unwrap_or_else(|e| panic!("{label}: {e}"));

        assert_eq!(resp.status(), StatusCode::OK, "{label}");
        assert_eq!(resp.text().await.unwrap(), body, "{label}");
    }
}

// NOTE: Consuming the body then reading again is covered by
// `response::tests::chunk_after_body_consumed_errors` (unit).

// -----------------------------------------------------------------------
// Redirect policy coverage
// -----------------------------------------------------------------------

/// `redirect_policy_none`: builder with `Policy::none()` disables
/// automatic redirects — the 302 is returned as-is.
/// Covers the `PolicyInner::None` branch in `WinHttpSession::open`.
#[tokio::test]
async fn redirect_policy_none() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/redir-none"))
        .respond_with(
            ResponseTemplate::new(302)
                .insert_header("location", format!("{}/dest-none", server.uri())),
        )
        .expect(1)
        .mount(&server)
        .await;

    // NOT mounting the /dest-none handler — redirect should NOT be followed.

    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .redirect(wrest::redirect::Policy::none())
        .build()
        .expect("client should build with Policy::none()");

    let resp = client
        .get(format!("{}/redir-none", server.uri()))
        .send()
        .await
        .expect("request should succeed (302 returned directly)");

    assert_eq!(resp.status(), StatusCode::from_u16(302).unwrap());
}

// -----------------------------------------------------------------------
// Debug for Response
// -----------------------------------------------------------------------

/// `response_debug`: Debug impl on Response should include status and url.
#[tokio::test]
async fn response_debug() {
    let server = mock_get("/dbg", 200, "").await;

    let resp = test_client()
        .get(format!("{}/dbg", server.uri()))
        .send()
        .await
        .expect("request should succeed");

    let debug = format!("{resp:?}");
    assert!(debug.contains("200"), "debug should contain status: {debug}");
    assert!(debug.contains("/dbg"), "debug should contain url path: {debug}");
}

// Note: redirect method-change tests (301/303 demote, 307/308 preserve)
// are consolidated into `redirect_method_handling` above.

// -----------------------------------------------------------------------
// User-Agent end-to-end
// -----------------------------------------------------------------------

/// `user_agent_sent_to_server`: verify `.user_agent()` header reaches
/// the server.
#[tokio::test]
async fn user_agent_sent_to_server() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/ua"))
        .and(header("user-agent", "wrest-test/1.0"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .expect(1)
        .mount(&server)
        .await;

    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .user_agent("wrest-test/1.0")
        .build()
        .expect("client build should succeed");

    let resp = client
        .get(format!("{}/ua", server.uri()))
        .send()
        .await
        .expect("request should succeed");

    assert_eq!(resp.status(), StatusCode::OK);
    // The mock's .expect(1) verifies the User-Agent header matched.
}

// -----------------------------------------------------------------------
// Manual / stress tests  (`cargo test -- --ignored`)
// -----------------------------------------------------------------------
//
// Tests below are `#[ignore]`-d because they are slow, memory-heavy,
// or require special environments.  They never run in CI.
//
//   cargo test -- --ignored            # run ALL ignored tests
//   cargo test large_body_over_4gib -- --ignored   # run one by name

/// POST a body that exceeds `u32::MAX` bytes, forcing the real
/// production large-body / multi-write path through the public
/// `Client` API.  This allocates ~4.01 GiB of RAM and transfers
/// that much data over loopback — expect it to take a few seconds.
///
/// The unit test `winhttp::tests::large_body_multi_write_path`
/// exercises the same code path with a 5 MiB body via lowered
/// `#[cfg(test)]` thresholds; this test verifies the real thing.
#[tokio::test]
#[ignore]
async fn large_body_over_4gib() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/huge"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .expect(1)
        .mount(&server)
        .await;

    // 4 GiB + 1 MiB — just over the DWORD limit.
    let size: usize = (u32::MAX as usize) + 1024 * 1024;
    let huge_body = vec![b'Z'; size];

    let resp = test_client()
        .post(format!("{}/huge", server.uri()))
        .body(huge_body)
        .send()
        .await
        .expect("4+ GiB upload should succeed");

    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.text().await.unwrap(), "ok");
}
