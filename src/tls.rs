//! TLS configuration types.
//!
//! Shares a path with
//! [`reqwest::tls`](https://docs.rs/reqwest/latest/reqwest/tls/index.html),
//! which the reqwest passthrough re-exports directly.  On the native
//! backend it carries `Identity`, whose constructors are Windows-only by
//! nature: they reference a certificate in the system store rather than
//! taking exported key material.

// ---------------------------------------------------------------------------
// Client certificates (`client-cert` feature)
// ---------------------------------------------------------------------------

/// Which Windows system certificate store to search.
///
/// Requires the `client-cert` feature.
#[cfg(feature = "client-cert")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreLocation {
    /// The per-user store, as shown by `certmgr.msc`.
    CurrentUser,
    /// The machine-wide store, as shown by `certlm.msc`.
    LocalMachine,
}

#[cfg(feature = "client-cert")]
impl From<StoreLocation> for crate::abi::StoreLocation {
    fn from(location: StoreLocation) -> Self {
        match location {
            StoreLocation::CurrentUser => crate::abi::StoreLocation::CurrentUser,
            StoreLocation::LocalMachine => crate::abi::StoreLocation::LocalMachine,
        }
    }
}

/// A client certificate for mutual TLS, referenced in the Windows
/// certificate store.
///
/// Requires the `client-cert` feature.  Pass one to
/// [`ClientBuilder::identity()`](crate::ClientBuilder::identity).
///
/// # Deviation from reqwest
///
/// Same path as
/// [`reqwest::tls::Identity`](https://docs.rs/reqwest/latest/reqwest/tls/struct.Identity.html),
/// different type.  reqwest's constructors all take exportable key
/// material; this one references a certificate already in the store, so
/// no private key is ever exported and smartcard / TPM / PIV keys work.
/// The constructor set is therefore Windows-only -- on the passthrough
/// this is reqwest's type with reqwest's constructors.
///
/// Cheap to [`Clone`]: clones share the `CERT_CONTEXT` reference count.
///
/// # Lifetime
///
/// This refers to a certificate in the store; it does not own key
/// material.  The reference keeps the certificate *context* alive even
/// after the certificate is deleted from the store, but the private key is
/// resolved through its provider on every handshake.  A removed
/// certificate, a deleted key container, or an unplugged token therefore
/// fails at send time, not when the `Identity` was built.
#[cfg(feature = "client-cert")]
pub struct Identity {
    /// Owned reference to the certificate. Released on drop.
    ctx: *const windows_sys::Win32::Security::Cryptography::CERT_CONTEXT,
    /// SHA-1 thumbprint, when the identity was looked up by one. Only used
    /// for `Debug`; a thumbprint is public data, not a secret.
    sha1: Option<[u8; 20]>,
}

// SAFETY: a `CERT_CONTEXT` is an immutable, reference-counted crypt32
// object.  `CertDuplicateCertificateContext` / `CertFreeCertificateContext`
// adjust that count atomically, and wrest never mutates through the
// pointer -- it only hands it to WinHTTP, which takes its own duplicate.
#[cfg(feature = "client-cert")]
unsafe impl Send for Identity {}
// SAFETY: as above -- shared access is read-only.
#[cfg(feature = "client-cert")]
unsafe impl Sync for Identity {}

#[cfg(feature = "client-cert")]
impl Identity {
    /// Look up a certificate by SHA-1 thumbprint in a Windows system store.
    ///
    /// `store_name` is a Windows store name such as `"MY"` (the personal
    /// store, where client certificates normally live) or `"ROOT"`.
    ///
    /// `CERT_FIND_SHA1_HASH` is the only hash the store indexes, and the
    /// SHA-1 thumbprint is what `certmgr.msc`, `certutil` and PowerShell's
    /// `.Thumbprint` show.  It identifies a certificate here rather than
    /// authenticating one, so SHA-1's collision weakness does not apply.
    ///
    /// # Errors
    ///
    /// Returns an error if the store cannot be opened, or if it holds no
    /// certificate with that thumbprint.
    pub fn from_windows_store(
        location: StoreLocation,
        store_name: &str,
        sha1_thumbprint: &[u8; 20],
    ) -> Result<Self, crate::Error> {
        let ctx = crate::abi::find_cert_by_sha1(location.into(), store_name, sha1_thumbprint)?;
        Ok(Self {
            ctx,
            sha1: Some(*sha1_thumbprint),
        })
    }

    /// Adopt a `CERT_CONTEXT` obtained elsewhere -- for example from the
    /// [`schannel`](https://docs.rs/schannel) crate's `CertContext`, or
    /// from a certificate-selection dialog.
    ///
    /// This takes its own reference, so the caller keeps ownership of
    /// theirs and should release it as usual.
    ///
    /// # Safety
    ///
    /// `ctx` must point to a live `CERT_CONTEXT` that has not been freed.
    #[must_use]
    pub unsafe fn from_cert_context(ctx: *const std::ffi::c_void) -> Self {
        // SAFETY: delegated to this function's contract on `ctx`.
        let ctx = unsafe { crate::abi::duplicate_cert_context(ctx.cast()) };
        Self { ctx, sha1: None }
    }

    /// The raw context, for `WINHTTP_OPTION_CLIENT_CERT_CONTEXT`.
    /// Borrowed from `self`, which frees it on drop.
    pub(crate) fn as_ptr(&self) -> *const windows_sys::Win32::Security::Cryptography::CERT_CONTEXT {
        self.ctx
    }
}

#[cfg(feature = "client-cert")]
impl Clone for Identity {
    fn clone(&self) -> Self {
        // SAFETY: `self.ctx` is live for as long as `self` is.
        let ctx = unsafe { crate::abi::duplicate_cert_context(self.ctx) };
        Self {
            ctx,
            sha1: self.sha1,
        }
    }
}

#[cfg(feature = "client-cert")]
impl Drop for Identity {
    fn drop(&mut self) {
        // SAFETY: we own exactly one reference, taken in a constructor or
        // in `clone`, and this runs once.
        unsafe { crate::abi::free_cert_context(self.ctx) }
    }
}

#[cfg(feature = "client-cert")]
impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut s = f.debug_struct("Identity");
        match &self.sha1 {
            Some(sha1) => s.field("sha1", &crate::abi::hex_thumbprint(sha1)).finish(),
            None => s.finish_non_exhaustive(),
        }
    }
}

/// A certificate in a Windows store, as metadata only.
///
/// Returned by [`list_client_certificates()`]; holds no handle and
/// borrows nothing from the store.  Requires the `client-cert` feature.
#[cfg(feature = "client-cert")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateInfo {
    /// SHA-1 thumbprint, the key [`Identity::from_windows_store()`] takes.
    pub thumbprint: [u8; 20],
    /// Display name of the subject, empty if the certificate has none.
    pub subject: String,
    /// Display name of the issuer, empty if the certificate has none.
    pub issuer: String,
    /// Start of the validity window.
    pub not_before: std::time::SystemTime,
    /// End of the validity window.
    pub not_after: std::time::SystemTime,
}

#[cfg(feature = "client-cert")]
impl CertificateInfo {
    /// The thumbprint as lowercase hex, the form `certmgr.msc` shows.
    #[must_use]
    pub fn thumbprint_hex(&self) -> String {
        crate::abi::hex_thumbprint(&self.thumbprint)
    }
}

/// List the certificates in a Windows store that could be presented as a
/// client identity.
///
/// Requires the `client-cert` feature.  `store_name` is a Windows store
/// name such as `"MY"`, the personal store where client certificates
/// normally live.
///
/// Certificates with no associated private key, outside their validity
/// window, or without the client-authentication EKU cannot complete a
/// handshake and are not returned.
///
/// Selection is left to the caller:
///
/// ```rust,ignore
/// let certs = wrest::tls::list_client_certificates(StoreLocation::CurrentUser, "MY")?;
/// let chosen = certs.iter().find(|c| c.subject.contains("svc-payments"));
/// ```
///
/// # Hardware-backed keys
///
/// A key is detected from `CERT_KEY_PROV_INFO_PROP_ID`, not by
/// acquiring it, so this never reaches a smartcard or TPM and never
/// prompts for a PIN.  Whether the token is present and unlocked is
/// settled during the handshake.
///
/// # Errors
///
/// Returns an error if the store cannot be opened.
#[cfg(feature = "client-cert")]
pub fn list_client_certificates(
    location: StoreLocation,
    store_name: &str,
) -> Result<Vec<CertificateInfo>, crate::Error> {
    let raw = crate::abi::list_usable_certs(location.into(), store_name)?;
    Ok(raw
        .into_iter()
        .map(|c| CertificateInfo {
            thumbprint: c.sha1,
            subject: c.subject,
            issuer: c.issuer,
            not_before: filetime_to_system_time(c.not_before),
            not_after: filetime_to_system_time(c.not_after),
        })
        .collect())
}

/// Convert a `FILETIME` (100ns ticks since 1601-01-01) to a `SystemTime`.
///
/// Saturates rather than wrapping: a certificate with a nonsensical date
/// should not panic a listing.
#[cfg(feature = "client-cert")]
fn filetime_to_system_time(ft: windows_sys::Win32::Foundation::FILETIME) -> std::time::SystemTime {
    /// Seconds between the FILETIME epoch (1601) and the Unix epoch.
    const EPOCH_DELTA_SECS: u64 = 11_644_473_600;

    let ticks = (u64::from(ft.dwHighDateTime) << 32) | u64::from(ft.dwLowDateTime);
    let secs = ticks / 10_000_000;
    let nanos = u32::try_from((ticks % 10_000_000).saturating_mul(100)).unwrap_or(0);

    match secs.checked_sub(EPOCH_DELTA_SECS) {
        Some(unix_secs) => std::time::UNIX_EPOCH
            .checked_add(std::time::Duration::new(unix_secs, nanos))
            .unwrap_or(std::time::UNIX_EPOCH),
        // Before 1601 + delta, i.e. before the Unix epoch.
        None => std::time::UNIX_EPOCH
            .checked_sub(std::time::Duration::from_secs(EPOCH_DELTA_SECS.saturating_sub(secs)))
            .unwrap_or(std::time::UNIX_EPOCH),
    }
}

/// Per-request TLS configuration, resolved at `Client` build time.
#[derive(Clone, Debug, Default)]
pub(crate) struct TlsConfig {
    /// Whether to ignore certificate validation errors.
    pub accept_invalid_certs: bool,
    /// Client certificate for mutual TLS, if configured.
    #[cfg(feature = "client-cert")]
    pub identity: Option<Identity>,
}

#[cfg(all(test, feature = "client-cert"))]
mod identity_tests {
    use super::*;

    /// A self-signed certificate, used only to obtain a real
    /// `CERT_CONTEXT`.  Its private key is absent; nothing here
    /// completes a handshake.
    const TEST_DER: &[u8] = include_bytes!("../tests/fixtures/test-client-cert.der");

    /// Build an `Identity` from the fixture without touching any store.
    fn fixture_identity() -> Identity {
        let ctx = crate::abi::create_cert_context(TEST_DER).expect("fixture DER should parse");
        // `from_cert_context` takes its own reference, so release ours.
        let identity = unsafe { Identity::from_cert_context(ctx.cast()) };
        unsafe { crate::abi::free_cert_context(ctx) };
        identity
    }

    #[test]
    fn fixture_parses_as_a_certificate() {
        let ctx = crate::abi::create_cert_context(TEST_DER).expect("fixture DER should parse");
        assert!(!ctx.is_null());
        unsafe { crate::abi::free_cert_context(ctx) };

        assert!(
            crate::abi::create_cert_context(b"not a certificate").is_err(),
            "invalid DER should not yield a context"
        );
    }

    #[test]
    fn clones_outlive_each_other() {
        // Each clone holds its own reference, so dropping clones in any
        // order must leave the remaining ones usable.
        let identity = fixture_identity();
        let a = identity.clone();
        let b = a.clone();
        drop(a);
        assert!(!b.as_ptr().is_null(), "clone still valid after sibling dropped");
        drop(b);
        assert!(!identity.as_ptr().is_null(), "original outlives its clones");

        // Dropping the last reference must not double-free.
        drop(identity);
    }

    #[test]
    fn debug_reports_thumbprint_only_when_known() {
        // Adopted contexts have no thumbprint recorded.
        let adopted = format!("{:?}", fixture_identity());
        assert!(adopted.starts_with("Identity"), "got {adopted}");
        assert!(!adopted.contains("sha1"), "no thumbprint is known: {adopted}");

        // A store lookup records one; check the formatting directly since
        // the lookup itself needs an installed certificate.  The context
        // is duplicated so this `Identity` owns its own reference and
        // drops normally.
        let base = fixture_identity();
        let identity = Identity {
            ctx: unsafe { crate::abi::duplicate_cert_context(base.as_ptr()) },
            sha1: Some([0xab; 20]),
        };
        let shown = format!("{identity:?}");
        assert!(shown.contains("abab"), "thumbprint should be shown: {shown}");
    }

    #[test]
    fn listing_a_store_succeeds_and_is_self_consistent() {
        // CurrentUser\MY always exists; it may legitimately be empty on a
        // machine with no personal certificates.
        let certs = list_client_certificates(StoreLocation::CurrentUser, "MY")
            .expect("CurrentUser\\MY should open");

        for cert in &certs {
            assert!(
                cert.not_before <= cert.not_after,
                "validity window is inverted for {}",
                cert.thumbprint_hex()
            );
            assert_eq!(cert.thumbprint_hex().len(), 40);
            // Every listed certificate must be resolvable by the
            // thumbprint the listing reported.
            Identity::from_windows_store(StoreLocation::CurrentUser, "MY", &cert.thumbprint)
                .unwrap_or_else(|e| {
                    panic!("listed {} but could not load it: {e:?}", cert.thumbprint_hex())
                });
        }
    }

    #[test]
    fn listing_an_unknown_store_is_an_error() {
        let err = list_client_certificates(StoreLocation::CurrentUser, "NoSuchStore\\Invalid")
            .expect_err("an invalid store name should fail");
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn filetime_converts_around_the_unix_epoch() {
        use windows_sys::Win32::Foundation::FILETIME;

        // The Unix epoch expressed as a FILETIME.
        let ticks: u64 = 11_644_473_600 * 10_000_000;
        let epoch = FILETIME {
            dwLowDateTime: (ticks & 0xFFFF_FFFF) as u32,
            dwHighDateTime: (ticks >> 32) as u32,
        };
        assert_eq!(filetime_to_system_time(epoch), std::time::UNIX_EPOCH);

        // Zero is 1601, well before the Unix epoch, and must not panic.
        let zero = FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };
        assert!(filetime_to_system_time(zero) < std::time::UNIX_EPOCH);
    }

    #[test]
    fn missing_certificate_is_an_error_not_a_panic() {
        let err = Identity::from_windows_store(StoreLocation::CurrentUser, "MY", &[0u8; 20])
            .expect_err("all-zero thumbprint should not resolve");
        assert!(err.is_builder(), "a missing certificate is a builder error");
        // Detail is in the source chain (`Debug`), not `Display`.
        let detail = format!("{err:?}");
        assert!(detail.contains("no certificate"), "got {detail}");
    }

    /// Parse 40 hex characters into a thumbprint.
    fn parse_thumbprint(hex: &str) -> Option<[u8; 20]> {
        let hex = hex.trim();
        if hex.len() != 40 {
            return None;
        }
        let (pairs, _) = hex.as_bytes().as_chunks::<2>();
        let mut out = [0u8; 20];
        for (slot, pair) in out.iter_mut().zip(pairs) {
            *slot = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
        }
        Some(out)
    }

    /// What happens when the certificate an `Identity` names is deleted
    /// from the store before the request is sent.
    ///
    /// `Identity` holds a duplicated `CERT_CONTEXT`, so the context
    /// survives deletion; the private key is resolved through its provider
    /// during the handshake.  CI provides a disposable certificate so this
    /// cannot disturb the other tests, but not a server: the mTLS harness is
    /// per-test and in-process, so point `WREST_MTLS_URL` at one by hand.
    #[tokio::test]
    #[ignore = "destructive: consumes the disposable certificate, run via --ignored"]
    async fn identity_after_certificate_is_deleted() {
        let (Ok(url), Ok(raw)) =
            (std::env::var("WREST_MTLS_URL"), std::env::var("WREST_MTLS_DISPOSABLE_THUMBPRINT"))
        else {
            eprintln!("skipping: WREST_MTLS_URL / WREST_MTLS_DISPOSABLE_THUMBPRINT not set");
            return;
        };
        let thumbprint =
            parse_thumbprint(&raw).unwrap_or_else(|| panic!("bad thumbprint: {raw:?}"));

        let identity = Identity::from_windows_store(StoreLocation::CurrentUser, "MY", &thumbprint)
            .expect("CI installs the disposable certificate");

        crate::abi::delete_cert_by_sha1(crate::abi::StoreLocation::CurrentUser, "MY", &thumbprint)
            .expect("the disposable certificate should be deletable");

        // It is really gone from the store.
        let listed =
            list_client_certificates(StoreLocation::CurrentUser, "MY").expect("store should open");
        assert!(
            listed.iter().all(|c| c.thumbprint != thumbprint),
            "deleted certificate is still listed"
        );

        let client = crate::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .tls_danger_accept_invalid_certs(true)
            .identity(identity)
            .build()
            .expect("client should build from an Identity whose certificate is gone");

        // Either outcome is acceptable; the client must not hang or panic.
        match client.get(format!("{url}/client-cert")).send().await {
            Ok(resp) => {
                eprintln!(
                    "OBSERVED: handshake still succeeded after deletion, status {}",
                    resp.status()
                );
                assert_eq!(resp.status(), crate::StatusCode::OK);
            }
            Err(e) => {
                eprintln!("OBSERVED: handshake failed after deletion: {e:?}");
                assert!(e.is_connect(), "should be a connect-class failure, got {e:?}");
            }
        }
    }

    #[test]
    fn winhttp_accepts_the_client_cert_option() {
        // The buffer for WINHTTP_OPTION_CLIENT_CERT_CONTEXT is the
        // CERT_CONTEXT itself with sizeof(CERT_CONTEXT) as the length; a
        // wrong pointer or size fails here rather than at handshake time.
        let session = crate::winhttp::WinHttpSession::open(&crate::winhttp::SessionConfig {
            user_agent: String::new(),
            connect_timeout_ms: 10_000,
            send_timeout_ms: 0,
            read_timeout_ms: 0,
            verbose: false,
            max_connections_per_host: None,
            proxy: crate::proxy::ProxyAction::Automatic,
            redirect_policy: None,
            http1_only: false,
        })
        .expect("session should open");

        let connect = crate::abi::winhttp_connect(session.handle.0, "example.com", 443)
            .expect("connect handle should open");
        let request = crate::abi::winhttp_open_request(connect, "GET", "/", true)
            .expect("request handle should open");

        let identity = fixture_identity();
        let result = crate::abi::winhttp_set_client_cert(request, identity.as_ptr());

        crate::abi::close_winhttp_handle(request);
        crate::abi::close_winhttp_handle(connect);

        result.expect("WinHTTP should accept the client certificate context");
    }
}
