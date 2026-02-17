//! Request body type.
//!
//! [`Body`] wraps request data. It can be created from in-memory types
//! (`String`, `Vec<u8>`, `Bytes`, etc.) or from an async stream via
//! [`Body::wrap_stream()`], matching the
//! [`reqwest::Body`](https://docs.rs/reqwest/latest/reqwest/struct.Body.html)
//! API surface.

use bytes::Bytes;
use std::pin::Pin;

/// Boxed stream type used for streaming request bodies.
pub(crate) type BoxStream = Pin<
    Box<
        dyn futures_core::Stream<Item = Result<Bytes, Box<dyn std::error::Error + Send + Sync>>>
            + Send,
    >,
>;

/// A request body.
///
/// Can be created from `String`, `&str`, `Vec<u8>`, `&[u8]`, or `Bytes`
/// (in-memory), or from an async stream via [`wrap_stream()`](Self::wrap_stream).
///
/// # Example
///
/// ```rust,no_run
/// use wrest::Body;
///
/// // In-memory
/// let body: Body = "hello".into();
/// let body: Body = b"bytes".to_vec().into();
///
/// // From a stream
/// let stream = futures_util::stream::iter(vec![
///     Ok::<_, std::io::Error>(bytes::Bytes::from("chunk1")),
///     Ok(bytes::Bytes::from("chunk2")),
/// ]);
/// let body = Body::wrap_stream(stream);
/// ```
pub struct Body {
    inner: BodyInner,
}

pub(crate) enum BodyInner {
    /// In-memory body bytes.
    Bytes(Vec<u8>),
    /// Streaming body -- sent incrementally via chunked transfer encoding.
    Stream(BoxStream),
}

impl std::fmt::Debug for Body {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.inner {
            BodyInner::Bytes(v) => f
                .debug_struct("Body")
                .field("kind", &"bytes")
                .field("length", &v.len())
                .finish(),
            BodyInner::Stream(_) => f.debug_struct("Body").field("kind", &"stream").finish(),
        }
    }
}

impl Body {
    /// View the body contents as a byte slice.
    ///
    /// Returns `None` for streaming bodies (created via
    /// [`wrap_stream()`](Self::wrap_stream)).
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match &self.inner {
            BodyInner::Bytes(v) => Some(v),
            BodyInner::Stream(_) => None,
        }
    }

    /// Wrap an async stream as a request body.
    ///
    /// The stream is sent incrementally to the server using HTTP chunked
    /// transfer encoding.  Each chunk is forwarded to WinHTTP as it
    /// arrives from the stream, so the entire body does not need to fit
    /// in memory.
    ///
    /// Matches [`reqwest::Body::wrap_stream()`](https://docs.rs/reqwest/latest/reqwest/struct.Body.html#method.wrap_stream).
    pub fn wrap_stream<S, O, E>(stream: S) -> Body
    where
        S: futures_core::Stream<Item = Result<O, E>> + Send + 'static,
        O: Into<Bytes> + 'static,
        E: Into<Box<dyn std::error::Error + Send + Sync>> + 'static,
    {
        use futures_util::StreamExt;
        let mapped = stream.map(|result| result.map(|o| o.into()).map_err(|e| e.into()));
        Body {
            inner: BodyInner::Stream(Box::pin(mapped)),
        }
    }

    /// Try to clone this body.
    ///
    /// Returns `None` for streaming bodies (created via
    /// [`wrap_stream()`](Self::wrap_stream)), since streams cannot be
    /// replayed.
    pub fn try_clone(&self) -> Option<Body> {
        match &self.inner {
            BodyInner::Bytes(v) => Some(Body {
                inner: BodyInner::Bytes(v.clone()),
            }),
            BodyInner::Stream(_) => None,
        }
    }

    /// Decompose the body into its inner representation.
    pub(crate) fn into_inner(self) -> BodyInner {
        self.inner
    }

    /// Consume the body and collect it into bytes.
    ///
    /// For in-memory bodies this is zero-cost. For streaming bodies
    /// this reads the entire stream into memory.
    #[cfg(test)]
    pub(crate) async fn into_bytes(self) -> Result<Vec<u8>, crate::Error> {
        match self.inner {
            BodyInner::Bytes(v) => Ok(v),
            BodyInner::Stream(mut stream) => {
                use futures_util::StreamExt;
                let mut buf = Vec::new();
                while let Some(chunk) = stream.next().await {
                    let bytes =
                        chunk.map_err(|e| crate::Error::body(format!("stream body error: {e}")))?;
                    buf.extend_from_slice(&bytes);
                }
                Ok(buf)
            }
        }
    }
}

impl From<Vec<u8>> for Body {
    fn from(v: Vec<u8>) -> Self {
        Self {
            inner: BodyInner::Bytes(v),
        }
    }
}

impl From<&'static [u8]> for Body {
    fn from(s: &'static [u8]) -> Self {
        Self {
            inner: BodyInner::Bytes(s.to_vec()),
        }
    }
}

impl From<String> for Body {
    fn from(s: String) -> Self {
        Self {
            inner: BodyInner::Bytes(s.into_bytes()),
        }
    }
}

impl From<&'static str> for Body {
    fn from(s: &'static str) -> Self {
        Self {
            inner: BodyInner::Bytes(s.as_bytes().to_vec()),
        }
    }
}

impl From<Bytes> for Body {
    fn from(b: Bytes) -> Self {
        Self {
            inner: BodyInner::Bytes(b.to_vec()),
        }
    }
}

impl Default for Body {
    /// Create an empty body.
    ///
    /// Matches [`reqwest::Body::default()`](https://docs.rs/reqwest/latest/reqwest/struct.Body.html#impl-Default-for-Body).
    fn default() -> Self {
        Self {
            inner: BodyInner::Bytes(Vec::new()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn body_from_conversions() {
        // (label, constructor, expected_bytes)
        let cases: Vec<(&str, Body, &[u8])> = vec![
            ("Vec<u8>", Body::from(vec![1, 2, 3]), &[1, 2, 3]),
            ("&[u8]", Body::from(&b"hello"[..]), b"hello"),
            ("String", Body::from("hello".to_owned()), b"hello"),
            ("&str", Body::from("hello"), b"hello"),
            ("Bytes", Body::from(Bytes::from_static(b"hello")), b"hello"),
            ("default", Body::default(), b""),
        ];

        for (label, body, expected) in &cases {
            assert_eq!(body.as_bytes().unwrap(), *expected, "Body::from({label})");
        }
    }

    #[test]
    fn body_try_clone_bytes() {
        let body = Body::from("test");
        let clone = body.try_clone().unwrap();
        assert_eq!(clone.as_bytes().unwrap(), b"test");
    }

    #[test]
    fn body_try_clone_stream_returns_none() {
        let stream =
            futures_util::stream::iter(vec![Ok::<_, std::io::Error>(Bytes::from("chunk"))]);
        let body = Body::wrap_stream(stream);
        assert!(body.try_clone().is_none());
    }

    #[test]
    fn body_stream_as_bytes_returns_none() {
        let stream =
            futures_util::stream::iter(vec![Ok::<_, std::io::Error>(Bytes::from("chunk"))]);
        let body = Body::wrap_stream(stream);
        assert!(body.as_bytes().is_none());
    }

    #[test]
    fn body_debug_bytes() {
        let body = Body::from("hi");
        let s = format!("{body:?}");
        assert!(s.contains("bytes"));
        assert!(s.contains("2")); // length
    }

    #[test]
    fn body_debug_stream() {
        let stream =
            futures_util::stream::iter(vec![Ok::<_, std::io::Error>(Bytes::from("chunk"))]);
        let body = Body::wrap_stream(stream);
        let s = format!("{body:?}");
        assert!(s.contains("stream"));
    }

    #[test]
    fn body_stream_into_bytes() {
        let stream = futures_util::stream::iter(vec![
            Ok::<_, std::io::Error>(Bytes::from("hello ")),
            Ok(Bytes::from("world")),
        ]);
        let body = Body::wrap_stream(stream);
        let bytes = futures_executor::block_on(body.into_bytes()).unwrap();
        assert_eq!(bytes, b"hello world");
    }

    #[test]
    fn body_stream_error_propagated() {
        let stream = futures_util::stream::iter(vec![
            Ok::<Bytes, std::io::Error>(Bytes::from("ok")),
            Err(std::io::Error::other("fail")),
        ]);
        let body = Body::wrap_stream(stream);
        let result = futures_executor::block_on(body.into_bytes());
        assert!(result.is_err());
    }
}
