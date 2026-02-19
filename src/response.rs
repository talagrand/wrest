//! HTTP response.
//!
//! [`Response`] wraps a received HTTP response. Read the body via
//! [`chunk()`](Response::chunk), [`text()`](Response::text), or
//! [`bytes()`](Response::bytes).

use crate::client::Client;
use crate::error::Error;
use crate::url::Url;
use crate::winhttp::{self, RawResponse};
use bytes::{Bytes, BytesMut};
use futures_util::future::Either;
use http::{Extensions, HeaderMap, StatusCode, Version};
#[cfg(feature = "noop-compat")]
use std::net::SocketAddr;
use std::pin::pin;
use std::time::Instant;

/// An HTTP response.
///
/// Created by [`RequestBuilder::send()`](crate::RequestBuilder::send).
/// The response headers are already received; the body can be read
/// incrementally via [`chunk()`](Self::chunk), or consumed entirely
/// via [`text()`](Self::text) or [`bytes()`](Self::bytes).
pub struct Response {
    status: StatusCode,
    version: Version,
    url: Url,
    headers: HeaderMap,
    extensions: Extensions,
    raw: Option<RawResponse>,
    /// Absolute deadline for the entire request (headers + body), or `None`
    /// if no total timeout was configured.
    deadline: Option<Instant>,
    /// Keeps the WinHTTP session handle alive for the duration of body reads.
    /// Without this, dropping the `Client` (and thus `ClientInner`) while a
    /// `Response` is still streaming would close the session handle, which
    /// invalidates the child request handle and causes `OPERATION_CANCELLED`.
    _client: Client,
}

impl std::fmt::Debug for Response {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Response")
            .field("status", &self.status)
            .field("version", &self.version)
            .field("url", &self.url)
            .finish()
    }
}

impl Response {
    /// Construct a `Response` from internal raw response data.
    pub(crate) fn from_raw(raw: RawResponse, deadline: Option<Instant>, client: Client) -> Self {
        debug!(
            status = raw.status.as_u16(),
            version = ?raw.version,
            url = %raw.url,
            "response received",
        );
        Self {
            status: raw.status,
            version: raw.version,
            url: raw.url.clone(),
            headers: raw.headers.clone(),
            extensions: Extensions::default(),
            raw: Some(raw),
            deadline,
            _client: client,
        }
    }

    /// Returns the HTTP status code.
    pub fn status(&self) -> StatusCode {
        self.status
    }

    /// Returns the HTTP version actually negotiated by WinHTTP
    /// (e.g., `HTTP/1.1`, `HTTP/2`).
    ///
    /// This is queried from `WINHTTP_OPTION_HTTP_PROTOCOL_USED` after
    /// headers are received, so it reflects the real protocol used on
    /// the wire.
    pub fn version(&self) -> Version {
        self.version
    }

    /// Returns the final URL of this response.
    ///
    /// If the request was redirected, this returns the URL of the final
    /// destination (matching `reqwest::Response::url()` behavior).
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// Returns the response headers.
    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    /// Returns a mutable reference to the response headers.
    pub fn headers_mut(&mut self) -> &mut HeaderMap {
        &mut self.headers
    }

    /// Returns the response extensions.
    ///
    /// Extensions are a type map of additional data attached to the
    /// response.  Use [`extensions_mut()`](Self::extensions_mut) to insert
    /// custom metadata.
    ///
    /// # Deviation from reqwest
    ///
    /// In reqwest, hyper populates extensions with internal connection
    /// metadata (e.g. `HttpInfo` for `remote_addr()`).
    /// In wrest, extensions start empty because WinHTTP does not expose
    /// equivalent typed data.  User-inserted extensions work identically.
    pub fn extensions(&self) -> &Extensions {
        &self.extensions
    }

    /// Returns a mutable reference to the response extensions.
    pub fn extensions_mut(&mut self) -> &mut Extensions {
        &mut self.extensions
    }

    /// Returns the content length from the `Content-Length` header, if present.
    ///
    /// # Deviation from reqwest
    ///
    /// reqwest returns the **decoded** (decompressed) body size via
    /// `hyper::Body::size_hint()`.  wrest reads the `Content-Length` header
    /// directly, which reports the **compressed** (wire) size when the server
    /// uses `Content-Encoding: gzip` or `deflate`.  WinHTTP decompresses the
    /// body transparently but does not update the header, and there is no API
    /// to query the decompressed size without reading the entire body.
    ///
    /// For uncompressed responses the values are identical.
    pub fn content_length(&self) -> Option<u64> {
        self.headers
            .get(http::header::CONTENT_LENGTH)?
            .to_str()
            .ok()?
            .parse()
            .ok()
    }

    /// Check the status code and return an error if it indicates a
    /// client or server error (4xx or 5xx).
    ///
    /// Consumes and returns `self` on success (2xx/3xx), or returns
    /// an `Error` with `is_status() == true` on failure.
    pub fn error_for_status(self) -> Result<Response, Error> {
        let status = self.status;
        if status.is_client_error() || status.is_server_error() {
            Err(Error::status_error(status, self.url))
        } else {
            Ok(self)
        }
    }

    /// Check the status code without consuming the response.
    ///
    /// Returns a reference to `self` on success (2xx/3xx), or an `Error`
    /// with `is_status() == true` on failure. Unlike
    /// [`error_for_status()`](Self::error_for_status), the response can
    /// still be used after this call.
    pub fn error_for_status_ref(&self) -> Result<&Response, Error> {
        let status = self.status;
        if status.is_client_error() || status.is_server_error() {
            Err(Error::status_error(status, self.url.clone()))
        } else {
            Ok(self)
        }
    }

    /// Read the next chunk of the response body.
    ///
    /// Returns `Ok(Some(bytes))` for each chunk, and `Ok(None)` at EOF.
    /// Each chunk is zero-copy -- WinHTTP writes directly into the returned buffer.
    ///
    /// If a total timeout was configured on the [`Client`](crate::Client),
    /// each chunk read is raced against the remaining deadline.
    pub async fn chunk(&mut self) -> Result<Option<Bytes>, Error> {
        // The read result, or `None` if a timeout expired.
        //
        // The borrow of `self.raw` is scoped to this block so that after
        // it ends, `self.raw.take()` can close the WinHTTP handle.  This
        // is critical on timeout: closing the handle cancels any in-flight
        // async operation and prevents late callbacks from misrouting
        // through the shared `CompletionSignal`.
        let outcome: Option<Option<Bytes>> = {
            let raw = self
                .raw
                .as_ref()
                .ok_or_else(|| Error::body("response body already consumed"))?;

            let read_future = winhttp::read_chunk(&raw.state, &raw.request_handle, &raw.url);

            if let Some(deadline) = self.deadline {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    None // timed out
                } else {
                    let delay = futures_timer::Delay::new(remaining);
                    let read_future = pin!(read_future);
                    let delay = pin!(delay);
                    match futures_util::future::select(read_future, delay).await {
                        Either::Left((result, _)) => Some(result?),
                        Either::Right(((), _)) => None, // timed out
                    }
                }
            } else {
                Some(read_future.await?)
            }
        }; // `raw` borrow released here

        match outcome {
            Some(result) => {
                if result.is_none() {
                    // EOF -- proactively release the WinHTTP request handle
                    // rather than waiting for `Response` to be dropped.
                    self.raw.take();
                }
                Ok(result)
            }
            None => {
                // Timeout expired.  Close the WinHTTP handle to cancel any
                // in-flight async I/O.  Without this, a late callback from
                // the cancelled operation could misroute through the shared
                // CompletionSignal if chunk() were called again on this
                // response.
                self.raw.take();
                Err(Error::timeout("total request timeout elapsed during body read")
                    .with_url(self.url.clone()))
            }
        }
    }

    /// Read the entire response body as a string.
    ///
    /// If the `Content-Type` header contains a `charset` parameter, that
    /// encoding is used; otherwise UTF-8 is assumed.
    ///
    /// UTF-8 takes a fast pure-Rust path. All other charsets are decoded
    /// via Win32 `MultiByteToWideChar` following the WHATWG Encoding
    /// Standard label mapping.
    ///
    /// # Memory
    ///
    /// The entire body is buffered in memory. For arbitrarily large
    /// responses, use [`bytes_stream()`](Self::bytes_stream) instead.
    ///
    /// # Deviation from reqwest
    ///
    /// reqwest uses the `encoding_rs` crate for charset decoding.
    /// wrest uses Win32 `MultiByteToWideChar` (plus ICU and a lookup
    /// table for four edge cases) to support all 39 WHATWG encodings.
    /// Three rare charsets -- ISO-8859-10 (Latin-6 / Nordic),
    /// ISO-8859-14 (Latin-8 / Celtic), and EUC-JP (Extended Unix Code
    /// for Japanese) -- require `icu.dll` and are available only on
    /// Windows 10 1903+; on older builds they will return a decode error.
    pub async fn text(self) -> Result<String, Error> {
        self.text_with_charset("utf-8").await
    }

    /// Read the entire response body, decoding with the given charset.
    ///
    /// The `Content-Type` charset takes priority; `default_encoding` is
    /// used only when the header does not specify one.
    ///
    /// UTF-8 takes a fast pure-Rust path. All other charsets are decoded
    /// via Win32 `MultiByteToWideChar` following the WHATWG Encoding
    /// Standard label mapping.
    ///
    /// # Memory
    ///
    /// The entire body is buffered in memory. For arbitrarily large
    /// responses, use [`bytes_stream()`](Self::bytes_stream) instead.
    ///
    /// # Deviation from reqwest
    ///
    /// reqwest uses the `encoding_rs` crate for charset decoding.
    /// wrest uses Win32 `MultiByteToWideChar` instead (see
    /// [`text()`](Self::text)).
    pub async fn text_with_charset(mut self, default_encoding: &str) -> Result<String, Error> {
        let charset = crate::encoding::extract_charset_from_content_type(&self.headers)
            .unwrap_or_else(|| default_encoding.to_owned());
        trace!(charset = charset, "decoding response body");
        let data = self.collect_body().await?;
        crate::encoding::decode_body(&data, &charset)
    }

    /// Deserialize the response body as JSON.
    ///
    /// Reads the full body, then deserializes with `serde_json`.
    ///
    /// # Memory
    ///
    /// The entire body is buffered in memory. For arbitrarily large
    /// responses, use [`bytes_stream()`](Self::bytes_stream) instead.
    ///
    /// Requires the `json` feature.
    #[cfg(feature = "json")]
    pub async fn json<T: serde::de::DeserializeOwned>(mut self) -> Result<T, Error> {
        let data = self.collect_body().await?;
        serde_json::from_slice(&data)
            .map_err(|e| Error::decode("JSON deserialization failed").with_source(e))
    }

    /// Read the entire response body as raw bytes.
    ///
    /// # Memory
    ///
    /// The entire body is buffered in memory. For arbitrarily large
    /// responses, use [`bytes_stream()`](Self::bytes_stream) instead.
    pub async fn bytes(mut self) -> Result<Bytes, Error> {
        self.collect_body().await
    }

    /// Convert the response into a `Stream` of `Bytes` chunks.
    ///
    /// Each item in the stream is a chunk from the response body.
    /// This is useful for processing large responses without buffering
    /// the entire body in memory.
    pub fn bytes_stream(self) -> impl futures_core::Stream<Item = Result<Bytes, Error>> {
        futures_util::stream::unfold(Some(self), |state| async move {
            let mut resp = state?;
            match resp.chunk().await {
                Ok(Some(bytes)) => Some((Ok(bytes), Some(resp))),
                Ok(None) => None,
                Err(e) => Some((Err(e), None)), // yield error, then end stream
            }
        })
    }

    /// Returns the remote socket address of the server.
    ///
    /// # No-op -- reqwest compatibility
    ///
    /// WinHTTP does not expose the remote socket address.  Always
    /// returns `None`.  Requires the `noop-compat` feature.
    #[cfg(feature = "noop-compat")]
    pub fn remote_addr(&self) -> Option<SocketAddr> {
        None
    }

    /// Collect all chunks into a single `Bytes`.
    ///
    /// No size limit is enforced -- matching reqwest, which also collects
    /// the full body into memory.  Callers processing arbitrarily large
    /// responses should use [`bytes_stream()`](Self::bytes_stream) instead.
    async fn collect_body(&mut self) -> Result<Bytes, Error> {
        let mut parts: Vec<Bytes> = Vec::new();
        let mut total_len = 0usize;

        while let Some(chunk) = self.chunk().await? {
            total_len += chunk.len();
            parts.push(chunk);
        }

        // Drop the raw response (closes the request handle)
        self.raw.take();

        // Destructure via iterator -- control flow encodes the invariant,
        // no .expect() needed.
        let mut iter = parts.into_iter();
        let Some(first) = iter.next() else {
            // No chunks received.
            return Ok(Bytes::new());
        };
        if iter.len() == 0 {
            // Single chunk -- return directly (zero-copy).
            return Ok(first);
        }

        // Multiple chunks -- concatenate into a single Bytes
        let mut buf = BytesMut::with_capacity(total_len);
        buf.extend_from_slice(&first);
        for part in iter {
            buf.extend_from_slice(&part);
        }
        Ok(buf.freeze())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a synthetic `Response` for unit tests.
    /// Uses a real `Client` (requiring WinHTTP) but no server I/O.
    fn synthetic(status: StatusCode, headers: HeaderMap) -> Response {
        let client = Client::builder().build().expect("client");
        let url: Url = "https://test.example.com/path".parse().unwrap();
        Response {
            status,
            version: Version::HTTP_11,
            url,
            headers,
            extensions: Extensions::default(),
            raw: None,
            deadline: None,
            _client: client,
        }
    }

    // -- content_length (data-driven) --

    #[test]
    fn content_length_table() {
        let cases: &[(Option<&str>, Option<u64>, &str)] = &[
            (Some("42"), Some(42), "valid"),
            (Some("0"), Some(0), "zero"),
            (None, None, "absent"),
            (Some("not-a-number"), None, "non-numeric"),
            (Some(""), None, "empty string"),
            (Some("999999999999"), Some(999999999999), "large value"),
        ];

        for &(header_val, expected, desc) in cases {
            let mut headers = HeaderMap::new();
            if let Some(v) = header_val {
                headers.insert(http::header::CONTENT_LENGTH, v.parse().unwrap());
            }
            let resp = synthetic(StatusCode::OK, headers);
            assert_eq!(resp.content_length(), expected, "{desc}");
        }
    }

    // -- error_for_status (data-driven) --

    #[test]
    fn error_for_status_table() {
        let cases: &[(u16, bool, &str)] = &[
            (200, true, "200 OK"),
            (204, true, "204 No Content"),
            (301, true, "301 redirect"),
            (400, false, "400 client error"),
            (404, false, "404 not found"),
            (500, false, "500 server error"),
            (503, false, "503 unavailable"),
        ];

        for &(code, expect_ok, desc) in cases {
            let status = StatusCode::from_u16(code).unwrap();
            let resp = synthetic(status, HeaderMap::new());
            let result = resp.error_for_status();
            if expect_ok {
                assert!(result.is_ok(), "{desc}: should be Ok");
            } else {
                let err = result.unwrap_err();
                assert!(err.is_status(), "{desc}: should be is_status()");
                assert_eq!(err.status(), Some(status), "{desc}: status code");
            }
        }
    }

    // -- error_for_status_ref (data-driven) --

    #[test]
    fn error_for_status_ref_table() {
        let cases: &[(u16, bool, &str)] = &[
            (200, true, "200 OK"),
            (301, true, "301 redirect"),
            (404, false, "404 not found"),
            (500, false, "500 server error"),
        ];

        for &(code, expect_ok, desc) in cases {
            let status = StatusCode::from_u16(code).unwrap();
            let resp = synthetic(status, HeaderMap::new());
            let result = resp.error_for_status_ref();
            if expect_ok {
                let r = result.expect("{desc}: should be Ok");
                assert_eq!(r.status(), status, "{desc}: status through ref");
            } else {
                let err = result.unwrap_err();
                assert!(err.is_status(), "{desc}: should be is_status()");
                assert_eq!(err.status(), Some(status), "{desc}: status code");
            }
        }
    }

    // -- error_for_status preserves URL --

    #[test]
    fn error_for_status_preserves_url() {
        let resp = synthetic(StatusCode::NOT_FOUND, HeaderMap::new());
        let err = resp.error_for_status().unwrap_err();
        assert_eq!(err.url().map(|u| u.as_str()), Some("https://test.example.com/path"));
    }

    // -- body-already-consumed error --

    #[tokio::test]
    async fn chunk_after_body_consumed_errors() {
        let mut resp = synthetic(StatusCode::OK, HeaderMap::new());
        // raw is None → body already consumed → should error.
        let result = resp.chunk().await;
        assert!(result.is_err(), "chunk() on consumed body should error");
        let err = result.unwrap_err();
        assert!(err.is_body(), "should be is_body()");
    }

    // -- Debug impl --

    #[test]
    fn debug_includes_status_and_url() {
        let resp = synthetic(StatusCode::NOT_FOUND, HeaderMap::new());
        let dbg = format!("{resp:?}");
        assert!(dbg.contains("404"), "Debug should include status code");
        assert!(dbg.contains("test.example.com"), "Debug should include URL");
    }

    // -- remote_addr (noop-compat) --

    #[test]
    #[cfg(feature = "noop-compat")]
    fn remote_addr_returns_none() {
        let resp = synthetic(StatusCode::OK, HeaderMap::new());
        assert!(resp.remote_addr().is_none());
    }

    // -- accessors --

    #[test]
    fn accessors_return_constructed_values() {
        let mut headers = HeaderMap::new();
        headers.insert("x-custom", "test-value".parse().unwrap());
        let resp = synthetic(StatusCode::OK, headers);
        assert_eq!(resp.version(), Version::HTTP_11);
        assert_eq!(resp.url().as_str(), "https://test.example.com/path");
        assert_eq!(resp.headers().get("x-custom").unwrap(), "test-value");
    }
}
