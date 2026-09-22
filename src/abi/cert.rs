//! Thin safe wrappers around the crypt32 certificate-store FFI.
//!
//! Only compiled with the `client-cert` feature.  Backs
//! [`crate::tls::Identity`]: opening a system store, finding a
//! certificate, and managing the `CERT_CONTEXT` reference count.  Nothing
//! here touches private key material -- SChannel does that.

use super::{last_win32_error, to_wide};
use crate::Error;
use windows_sys::Win32::Foundation::FILETIME;
use windows_sys::Win32::Security::Cryptography::{
    CERT_CONTEXT, CERT_FIND_HASH, CERT_KEY_PROV_INFO_PROP_ID, CERT_NAME_ISSUER_FLAG,
    CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_SHA1_HASH_PROP_ID, CERT_STORE_PROV_SYSTEM_W,
    CERT_STORE_READONLY_FLAG, CERT_SYSTEM_STORE_CURRENT_USER, CERT_SYSTEM_STORE_LOCAL_MACHINE,
    CRYPT_INTEGER_BLOB, CTL_USAGE, CertCloseStore, CertDuplicateCertificateContext,
    CertEnumCertificatesInStore, CertFindCertificateInStore, CertFreeCertificateContext,
    CertGetCertificateContextProperty, CertGetEnhancedKeyUsage, CertGetNameStringW, CertOpenStore,
    CertVerifyTimeValidity, HCERTSTORE, PKCS_7_ASN_ENCODING, X509_ASN_ENCODING,
    szOID_ANY_ENHANCED_KEY_USAGE, szOID_PKIX_KP_CLIENT_AUTH,
};

/// Which system store location to search.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StoreLocation {
    /// `CurrentUser` -- the per-user store (`certmgr.msc`).
    CurrentUser,
    /// `LocalMachine` -- the machine-wide store (`certlm.msc`).
    LocalMachine,
}

impl StoreLocation {
    const fn flag(self) -> u32 {
        match self {
            StoreLocation::CurrentUser => CERT_SYSTEM_STORE_CURRENT_USER,
            StoreLocation::LocalMachine => CERT_SYSTEM_STORE_LOCAL_MACHINE,
        }
    }
}

/// An open system certificate store, closed on drop.
///
/// Deliberately closed *without* `CERT_CLOSE_STORE_FORCE_FLAG`: WinHTTP
/// documents that force-closing the store a client certificate came from
/// can cause an access violation, since contexts handed to it outlive the
/// store handle.
struct CertStore(HCERTSTORE);

impl CertStore {
    /// Get the raw certificate store handle.
    fn raw(&self) -> HCERTSTORE {
        self.0
    }
}

impl Drop for CertStore {
    fn drop(&mut self) {
        // No force flag -- see the type docs.
        unsafe {
            let _ = CertCloseStore(self.0, 0);
        }
    }
}

/// Open a named system store, read-only -- `"MY"` (personal), `"ROOT"`.
fn open_store(location: StoreLocation, store_name: &str) -> Result<CertStore, Error> {
    open_store_with(location, store_name, CERT_STORE_READONLY_FLAG)
}

/// Open a named system store with the most access the caller is granted,
/// which deleting requires.
#[cfg(test)]
fn open_store_writable(location: StoreLocation, store_name: &str) -> Result<CertStore, Error> {
    use windows_sys::Win32::Security::Cryptography::CERT_STORE_MAXIMUM_ALLOWED_FLAG;

    open_store_with(location, store_name, CERT_STORE_MAXIMUM_ALLOWED_FLAG)
}

fn open_store_with(
    location: StoreLocation,
    store_name: &str,
    access: u32,
) -> Result<CertStore, Error> {
    let name_wide = to_wide(store_name);

    // SAFETY: `CERT_STORE_PROV_SYSTEM_W` selects the system-store
    // provider, for which `pvpara` is a wide store name.  `name_wide`
    // outlives the call.
    let handle = unsafe {
        CertOpenStore(
            CERT_STORE_PROV_SYSTEM_W,
            0,
            0,
            location.flag() | access,
            name_wide.as_ptr().cast(),
        )
    };
    if handle.is_null() {
        return Err(last_win32_error());
    }
    Ok(CertStore(handle))
}

/// Find a certificate by SHA-1 thumbprint in a named system store.
///
/// Returns a context the caller owns and must release with
/// [`free_cert_context`].
///
/// # Errors
///
/// Returns the Win32 error if the store cannot be opened, or a
/// not-found error if no certificate in it has that thumbprint.
pub(crate) fn find_cert_by_sha1(
    location: StoreLocation,
    store_name: &str,
    sha1: &[u8; 20],
) -> Result<*const CERT_CONTEXT, Error> {
    let store = open_store(location, store_name)?;
    find_in_open_store(&store, sha1).ok_or_else(|| {
        // CertFindCertificateInStore sets CRYPT_E_NOT_FOUND, which maps to
        // a confusing message; say what actually happened instead.
        Error::builder(format!(
            "no certificate with SHA-1 thumbprint {} in {location:?}\\{store_name}",
            hex_thumbprint(sha1),
        ))
    })
}

/// Find a certificate by thumbprint in an already-open store.
fn find_in_open_store(store: &CertStore, sha1: &[u8; 20]) -> Option<*const CERT_CONTEXT> {
    let mut hash = *sha1;
    let blob = CRYPT_INTEGER_BLOB {
        cbData: 20,
        pbData: hash.as_mut_ptr(),
    };

    // SAFETY: `CERT_FIND_HASH` takes a `CRYPT_HASH_BLOB` as `pvFindPara`;
    // `blob` (and the `hash` it points at) outlive the call.  A null
    // `pPrevCertContext` starts the search from the beginning.
    let found = unsafe {
        CertFindCertificateInStore(
            store.raw(),
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            0,
            CERT_FIND_HASH,
            std::ptr::from_ref(&blob).cast(),
            std::ptr::null(),
        )
    };

    // The found context is owned by the caller; the store closes without
    // the force flag, which leaves the context valid.
    (!found.is_null()).then(|| found.cast_const())
}

/// Metadata for one certificate, read without touching its private key.
pub(crate) struct RawCertificateInfo {
    pub sha1: [u8; 20],
    pub subject: String,
    pub issuer: String,
    pub not_before: FILETIME,
    pub not_after: FILETIME,
}

/// List certificates in a store that could be presented as a client
/// identity: a key is associated, the certificate is currently valid, and
/// it is usable for client authentication.
///
/// Key *association* is read from `CERT_KEY_PROV_INFO_PROP_ID` rather than
/// acquiring the key: acquiring reaches the provider, which on a smartcard
/// or TPM can be slow and can prompt for a PIN.  It proves a key is bound
/// to the certificate, not that the token is present and unlocked.
///
/// # Errors
///
/// Returns the Win32 error if the store cannot be opened.
pub(crate) fn list_usable_certs(
    location: StoreLocation,
    store_name: &str,
) -> Result<Vec<RawCertificateInfo>, Error> {
    let store = open_store(location, store_name)?;
    let mut out = Vec::new();

    // CertEnumCertificatesInStore frees the context passed as
    // pPrevCertContext and returns the next, so a full enumeration frees
    // nothing itself; it ends by returning null.
    let mut ctx: *const CERT_CONTEXT = std::ptr::null();
    loop {
        // SAFETY: `store` outlives the loop, and `ctx` is either null (to
        // start) or the context handed back by the previous call.
        ctx = unsafe { CertEnumCertificatesInStore(store.raw(), ctx).cast_const() };
        if ctx.is_null() {
            break;
        }

        if !has_associated_key(ctx) || !is_time_valid(ctx) || !allows_client_auth(ctx) {
            continue;
        }

        let (not_before, not_after) = unsafe {
            let info = (*ctx).pCertInfo;
            if info.is_null() {
                continue;
            }
            ((*info).NotBefore, (*info).NotAfter)
        };

        let Some(sha1) = cert_sha1(ctx) else { continue };

        out.push(RawCertificateInfo {
            sha1,
            subject: cert_name(ctx, 0),
            issuer: cert_name(ctx, CERT_NAME_ISSUER_FLAG),
            not_before,
            not_after,
        });
    }

    Ok(out)
}

/// Whether a private key is associated with the certificate, without
/// reaching the key's provider.
fn has_associated_key(ctx: *const CERT_CONTEXT) -> bool {
    let mut size = 0u32;
    unsafe {
        CertGetCertificateContextProperty(
            ctx,
            CERT_KEY_PROV_INFO_PROP_ID,
            std::ptr::null_mut(),
            &raw mut size,
        ) != 0
    }
}

/// Whether the certificate is valid at the current time.
fn is_time_valid(ctx: *const CERT_CONTEXT) -> bool {
    unsafe {
        let info = (*ctx).pCertInfo;
        !info.is_null() && CertVerifyTimeValidity(std::ptr::null(), info) == 0
    }
}

/// Whether the certificate may be used for client authentication.
///
/// RFC 5280 leaves a certificate with no EKU extension unconstrained, and
/// `anyExtendedKeyUsage` permits every purpose, so both count as allowed
/// alongside an explicit `clientAuth`.
fn allows_client_auth(ctx: *const CERT_CONTEXT) -> bool {
    let mut size = 0u32;
    let sized =
        unsafe { CertGetEnhancedKeyUsage(ctx, 0, std::ptr::null_mut(), &raw mut size) != 0 };
    if !sized || size == 0 {
        return false;
    }

    let mut buf = vec![0u8; size as usize];
    let usage = buf.as_mut_ptr().cast::<CTL_USAGE>();
    if unsafe { CertGetEnhancedKeyUsage(ctx, 0, usage, &raw mut size) } == 0 {
        return false;
    }

    unsafe {
        let count = (*usage).cUsageIdentifier;
        if count == 0 {
            // No EKU: valid for all uses.
            return true;
        }
        let oids = (*usage).rgpszUsageIdentifier;
        (0..count as usize).any(|i| {
            let oid = *oids.add(i);
            !oid.is_null()
                && (cstr_eq(oid, szOID_PKIX_KP_CLIENT_AUTH)
                    || cstr_eq(oid, szOID_ANY_ENHANCED_KEY_USAGE))
        })
    }
}

/// Compare two null-terminated ASCII C strings.
///
/// # Safety
///
/// Both pointers must be null-terminated and readable.
unsafe fn cstr_eq(a: windows_sys::core::PCSTR, b: windows_sys::core::PCSTR) -> bool {
    unsafe {
        let mut i = 0usize;
        loop {
            let (x, y) = (*a.add(i), *b.add(i));
            if x != y {
                return false;
            }
            if x == 0 {
                return true;
            }
            i = i.wrapping_add(1);
        }
    }
}

/// The certificate's SHA-1 thumbprint, as the store records it.
fn cert_sha1(ctx: *const CERT_CONTEXT) -> Option<[u8; 20]> {
    let mut sha1 = [0u8; 20];
    let mut size = 20u32;
    let ok = unsafe {
        CertGetCertificateContextProperty(
            ctx,
            CERT_SHA1_HASH_PROP_ID,
            sha1.as_mut_ptr().cast(),
            &raw mut size,
        ) != 0
    };
    (ok && size == 20).then_some(sha1)
}

/// A display name for the certificate; empty when it has none.
fn cert_name(ctx: *const CERT_CONTEXT, flags: u32) -> String {
    let len = unsafe {
        CertGetNameStringW(
            ctx,
            CERT_NAME_SIMPLE_DISPLAY_TYPE,
            flags,
            std::ptr::null(),
            std::ptr::null_mut(),
            0,
        )
    };
    if len <= 1 {
        return String::new();
    }

    let mut buf = vec![0u16; len as usize];
    let written = unsafe {
        CertGetNameStringW(
            ctx,
            CERT_NAME_SIMPLE_DISPLAY_TYPE,
            flags,
            std::ptr::null(),
            buf.as_mut_ptr(),
            len,
        )
    };
    if written == 0 {
        return String::new();
    }

    // Drop the trailing null before converting.
    String::from_utf16_lossy(&buf[..written.saturating_sub(1) as usize])
}

/// Increment the reference count on a certificate context.
///
/// # Safety
///
/// `ctx` must be a valid `CERT_CONTEXT` pointer.
pub(crate) unsafe fn duplicate_cert_context(ctx: *const CERT_CONTEXT) -> *const CERT_CONTEXT {
    // SAFETY: delegated to the caller's contract on `ctx`.  The returned
    // pointer is a new reference the caller owns.
    unsafe { CertDuplicateCertificateContext(ctx).cast_const() }
}

/// Release a reference taken by [`find_cert_by_sha1`] or
/// [`duplicate_cert_context`].
///
/// # Safety
///
/// `ctx` must be a valid `CERT_CONTEXT` pointer that has not already been
/// freed.
pub(crate) unsafe fn free_cert_context(ctx: *const CERT_CONTEXT) {
    unsafe {
        let _ = CertFreeCertificateContext(ctx);
    }
}

/// Build a standalone certificate context from DER bytes.
///
/// Only used by tests, to obtain a real `CERT_CONTEXT` without installing
/// one in the runner's store.
///
/// # Errors
///
/// Returns the Win32 error if `der` is not a well-formed certificate.
#[cfg(test)]
pub(crate) fn create_cert_context(der: &[u8]) -> Result<*const CERT_CONTEXT, Error> {
    let len = u32::try_from(der.len()).map_err(|_| Error::builder("certificate too large"))?;
    // SAFETY: `der`/`len` describe the same buffer, which outlives the
    // call; crypt32 copies what it needs into the returned context.
    let ctx = unsafe {
        windows_sys::Win32::Security::Cryptography::CertCreateCertificateContext(
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            der.as_ptr(),
            len,
        )
    };
    if ctx.is_null() {
        return Err(last_win32_error());
    }
    Ok(ctx.cast_const())
}

/// Delete a certificate from a store by SHA-1 thumbprint.
///
/// Only used by tests, to remove a certificate out from under a live
/// [`crate::tls::Identity`].
///
/// # Errors
///
/// Returns the Win32 error if the store cannot be opened for writing, or
/// if no certificate has that thumbprint.
#[cfg(test)]
pub(crate) fn delete_cert_by_sha1(
    location: StoreLocation,
    store_name: &str,
    sha1: &[u8; 20],
) -> Result<(), Error> {
    use windows_sys::Win32::Security::Cryptography::CertDeleteCertificateFromStore;

    let store = open_store_writable(location, store_name)?;
    let found = find_in_open_store(&store, sha1).ok_or_else(|| {
        Error::builder(format!(
            "no certificate with SHA-1 thumbprint {} to delete",
            hex_thumbprint(sha1)
        ))
    })?;

    // SAFETY: `found` is a live context from this store.  The call frees
    // it whether or not it succeeds, so it must not be freed again.
    let ok = unsafe { CertDeleteCertificateFromStore(found) != 0 };
    if ok { Ok(()) } else { Err(last_win32_error()) }
}

/// Lowercase hex, for error messages and `Debug`.
pub(crate) fn hex_thumbprint(sha1: &[u8; 20]) -> String {
    use std::fmt::Write as _;
    sha1.iter().fold(String::with_capacity(40), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_thumbprint_formats_lowercase_fixed_width() {
        let mut sha1 = [0u8; 20];
        sha1[0] = 0x0a;
        sha1[19] = 0xff;
        let hex = hex_thumbprint(&sha1);
        assert_eq!(hex.len(), 40, "SHA-1 is always 40 hex chars");
        assert!(hex.starts_with("0a"), "leading zero must be kept: {hex}");
        assert!(hex.ends_with("ff"), "got {hex}");
    }

    #[test]
    fn missing_thumbprint_is_a_clear_error() {
        // An all-zero thumbprint will not be in anyone's store.  The
        // store itself must open, so this fails in the find, not the open.
        let err = find_cert_by_sha1(StoreLocation::CurrentUser, "MY", &[0u8; 20])
            .expect_err("all-zero thumbprint should not match");
        assert!(err.is_builder(), "a missing certificate is a builder error");
        // `Display` is the error kind alone; the detail lives in the
        // source chain, which `Debug` prints.
        let detail = format!("{err:?}");
        assert!(
            detail.contains("no certificate with SHA-1 thumbprint"),
            "expected a not-found detail, got: {detail}"
        );
    }

    #[test]
    fn unknown_store_name_surfaces_win32_error() {
        let err = find_cert_by_sha1(StoreLocation::CurrentUser, "NoSuchStore\\Invalid", &[0u8; 20])
            .expect_err("an invalid store name should fail");
        // Either the open fails or the find does; both must be errors,
        // and neither may panic.
        assert!(!err.to_string().is_empty());
    }
}
