//! Shared utility functions.
//!
//! Small helpers used across multiple modules. Nothing in this module is
//! WinHTTP-specific or Win32-specific -- these are general-purpose building
//! blocks. Win32 FFI wrappers live in [`abi`](crate::abi).

use crate::{Error, error::ContextError};

// ---------------------------------------------------------------------------
// Wide-string helpers
// ---------------------------------------------------------------------------

/// Convert a wide-string pointer to a Rust `String`.
///
/// When `char_count` is `Some`, it is the number of readable `u16` elements
/// and one optional trailing NUL is removed. When it is `None`, `ptr` is read
/// through its first NUL. Uses [`String::from_utf16`] so malformed UTF-16 is
/// surfaced as an error.
///
/// # Safety
///
/// For `Some(char_count)`, `ptr` must be valid for at least `char_count`
/// elements. For `None`, it must point to a NUL-terminated string. A null
/// pointer returns an empty string.
pub(crate) unsafe fn wide_to_string(
    ptr: *const u16,
    char_count: Option<usize>,
) -> Result<String, Error> {
    let slice = unsafe { wide_slice(ptr, char_count) };
    String::from_utf16(slice)
        .map_err(|_| Error::request("WinHTTP returned invalid UTF-16 in callback string"))
}

/// Convert a wide-string pointer to a Rust `String` using lossy decoding.
///
/// `char_count` has the same counted-versus-NUL-terminated meaning as in
/// [`wide_to_string`].
///
/// # Safety
///
/// The same pointer validity requirements as [`wide_to_string`] apply.
#[cfg_attr(all(not(feature = "tracing"), not(test)), expect(dead_code))]
pub(crate) unsafe fn wide_to_string_lossy(ptr: *const u16, char_count: Option<usize>) -> String {
    String::from_utf16_lossy(unsafe { wide_slice(ptr, char_count) })
}

/// Return the UTF-16 contents selected by `char_count`, without a terminator.
///
/// # Safety
///
/// The caller must uphold the pointer contract documented by [`wide_to_string`].
unsafe fn wide_slice<'a>(ptr: *const u16, char_count: Option<usize>) -> &'a [u16] {
    if ptr.is_null() {
        return &[];
    }

    let char_count = match char_count {
        Some(char_count) => char_count,
        None => unsafe { libc::wcslen(ptr) },
    };
    let slice = unsafe { std::slice::from_raw_parts(ptr, char_count) };
    slice.strip_suffix(&[0]).unwrap_or(slice)
}

// ---------------------------------------------------------------------------
// Environment helpers
// ---------------------------------------------------------------------------

/// Read an environment variable, returning `None` for empty or unset values.
pub(crate) fn read_env_var(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

// ---------------------------------------------------------------------------
// UTF-16 helpers
// ---------------------------------------------------------------------------

/// Convert a `&[u16]` buffer to a `String`, returning a [`Error::decode`]
/// on invalid UTF-16.
///
/// `context` describes the conversion path (e.g. `"UTF-16LE"`,
/// `"ICU produced invalid UTF-16"`) and is preserved in the error's
/// source chain via [`ContextError`](crate::error::ContextError).
pub(crate) fn string_from_utf16(buf: &[u16], context: &'static str) -> Result<String, Error> {
    String::from_utf16(buf).map_err(|e| Error::decode(ContextError::new(context, e)))
}

// ---------------------------------------------------------------------------
// Mutex helpers
// ---------------------------------------------------------------------------

/// Lock a [`Mutex`], recovering from poison.
///
/// If the mutex was poisoned (a prior panic occurred while the lock was
/// held), logs a warning, clears the poison flag, and returns the guard
/// anyway.
///
/// # When this is safe
///
/// All `Mutex`es in this crate protect simple `Option<T>` slots whose only
/// operations are `.take()` / `.replace()`.  There is no multi-field
/// invariant that a panicking thread could leave half-updated, so the
/// data behind the lock is always in a valid state.
pub(crate) fn lock_or_clear<T>(mutex: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => {
            warn!(
                "Mutex poisoned (prior panic while lock held); \
                 recovering -- protected data is a simple Option<T> slot"
            );
            mutex.clear_poison();
            poisoned.into_inner()
        }
    }
}

// ---------------------------------------------------------------------------
// Latin-1 header-value helpers
// ---------------------------------------------------------------------------

/// Widen raw header-value bytes into a `String` using Latin-1 (ISO 8859-1)
/// identity mapping: byte N becomes U+00NN.
///
/// HTTP header values are opaque octets (RFC 9110 §5.5), but
/// `RequestBuilder` stores them as `(String, String)` pairs so they can
/// be cloned, compared, and logged without carrying raw byte buffers.
/// Latin-1 is the natural encoding for this because every byte 0x00-0xFF
/// maps one-to-one to a Unicode code point, making the round-trip through
/// [`narrow_latin1`] perfectly lossless.
pub(crate) fn widen_latin1(bytes: &[u8]) -> String {
    bytes.iter().map(|&b| b as char).collect()
}

/// Narrow a Latin-1-widened string back into raw bytes.
///
/// This is the inverse of [`widen_latin1`]: each `char` is truncated to
/// its low byte.  Every char is guaranteed to be ≤ U+00FF because
/// `widen_latin1` only produces code points in that range.
pub(crate) fn narrow_latin1(s: &str) -> Vec<u8> {
    s.chars()
        .map(|ch| {
            debug_assert!(ch as u32 <= 0xFF, "narrow_latin1 called on non-Latin-1 char");
            ch as u8
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wide_string_decoders() {
        let hello = [b'H' as u16, b'e' as u16, b'l' as u16, b'l' as u16, b'o' as u16];
        let ok_with_null_and_suffix = [b'O' as u16, b'K' as u16, 0, b'X' as u16];
        let invalid_counted = [0xD800];
        let invalid_null_terminated = [0xD800, 0];

        // (label, data, optional character count, expected)
        let cases: &[(&str, *const u16, Option<usize>, &str)] = &[
            ("null_ptr_counted", std::ptr::null(), Some(10), ""),
            ("null_ptr_terminated", std::ptr::null(), None, ""),
            ("zero_count", hello.as_ptr(), Some(0), ""),
            ("counted_utf16", hello.as_ptr(), Some(5), "Hello"),
            ("counted_trailing_null", ok_with_null_and_suffix.as_ptr(), Some(3), "OK"),
            ("null_terminated_stops_at_first_null", ok_with_null_and_suffix.as_ptr(), None, "OK"),
        ];

        for &(label, ptr, char_count, expected) in cases {
            let strict = unsafe { wide_to_string(ptr, char_count) }
                .unwrap_or_else(|error| panic!("{label}: {error}"));
            assert_eq!(strict, expected, "strict: {label}");

            let lossy = unsafe { wide_to_string_lossy(ptr, char_count) };
            assert_eq!(lossy, expected, "lossy: {label}");
        }

        for (label, ptr, char_count) in [
            ("counted", invalid_counted.as_ptr(), Some(invalid_counted.len())),
            ("null_terminated", invalid_null_terminated.as_ptr(), None),
        ] {
            let strict = unsafe { wide_to_string(ptr, char_count) };
            assert!(strict.is_err(), "strict {label}: unpaired surrogate must fail");
            let lossy = unsafe { wide_to_string_lossy(ptr, char_count) };
            assert_eq!(lossy, "\u{FFFD}", "lossy {label}: unpaired surrogate is replaced");
        }
    }

    // -- read_env_var --

    #[test]
    fn read_env_var_unset() {
        assert!(read_env_var("wrest_TEST_NONEXISTENT_VAR_12345").is_none());
    }

    #[test]
    fn lock_or_clear_recovers_from_poison() {
        use std::sync::{Arc, Mutex};

        let mutex = Arc::new(Mutex::new(42_i32));
        let m2 = Arc::clone(&mutex);

        // Poison the mutex by panicking while holding the lock.
        let _ = std::thread::spawn(move || {
            let _guard = m2.lock().unwrap();
            panic!("intentional panic to poison mutex");
        })
        .join();

        // The mutex is now poisoned.
        assert!(mutex.lock().is_err(), "mutex should be poisoned");

        // Install a no-op subscriber so the `warn!()` inside
        // `lock_or_clear` actually evaluates (improves coverage).
        #[cfg(feature = "tracing")]
        let _guard = ::tracing::subscriber::set_default(crate::tracing::SinkSubscriber);

        // lock_or_clear recovers and returns a valid guard.
        let guard = lock_or_clear(&mutex);
        assert_eq!(*guard, 42);
        drop(guard);

        // After recovery, the poison flag is cleared.
        assert!(mutex.lock().is_ok(), "poison should be cleared");
    }
}
