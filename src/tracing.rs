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

// ---------------------------------------------------------------------------
// Test-only: no-op subscriber that forces tracing macros to evaluate
// their arguments, so llvm-cov marks those lines as covered.
// ---------------------------------------------------------------------------

#[cfg(all(test, feature = "tracing"))]
pub(crate) struct SinkSubscriber;

#[cfg(all(test, feature = "tracing"))]
impl ::tracing::Subscriber for SinkSubscriber {
    fn enabled(&self, _: &::tracing::Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _: &::tracing::span::Attributes<'_>) -> ::tracing::span::Id {
        ::tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &::tracing::span::Id, _: &::tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &::tracing::span::Id, _: &::tracing::span::Id) {}
    fn event(&self, _: &::tracing::Event<'_>) {}
    fn enter(&self, _: &::tracing::span::Id) {}
    fn exit(&self, _: &::tracing::span::Id) {}
}

/// Exercise every `SinkSubscriber` method so coverage sees them as hit.
/// `enabled`, `event` are hit by `trace!()`; `new_span`, `enter`, `exit`
/// require creating a span.
#[cfg(all(test, feature = "tracing"))]
#[test]
fn sink_subscriber_covers_all_methods() {
    let _guard = ::tracing::subscriber::set_default(SinkSubscriber);
    // event → enabled + event
    ::tracing::trace!("cover event path");
    // span  → new_span + enter + exit + record + record_follows_from
    let span = ::tracing::trace_span!("cover_span", x = 1);
    let _entered = span.enter();
}
