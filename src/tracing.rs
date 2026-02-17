//! Internal tracing shims.
//!
//! When the `tracing` feature is enabled these macros forward directly to
//! [`tracing`].  When disabled they expand to nothing, so call-sites never
//! need `#[cfg]` annotations.

// Only one side of each cfg pair is active at a time.
#![allow(unused_macros)]

// ---- feature = "tracing" ----

#[cfg(feature = "tracing")]
macro_rules! trace {
    ($($tt:tt)*) => { tracing::trace!($($tt)*) }
}

#[cfg(feature = "tracing")]
macro_rules! debug {
    ($($tt:tt)*) => { tracing::debug!($($tt)*) }
}

#[cfg(feature = "tracing")]
macro_rules! warn {
    ($($tt:tt)*) => { tracing::warn!($($tt)*) }
}

// ---- not(feature = "tracing") ----

#[cfg(not(feature = "tracing"))]
macro_rules! trace {
    ($($tt:tt)*) => {};
}

#[cfg(not(feature = "tracing"))]
macro_rules! debug {
    ($($tt:tt)*) => {};
}

#[cfg(not(feature = "tracing"))]
macro_rules! warn {
    ($($tt:tt)*) => {};
}
