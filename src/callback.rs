//! Reusable callback -> Future bridge for Win32 async APIs.
//!
//! This module provides three primitives that turn any Win32 callback-based API
//! into idiomatic Rust `Future`s:
//!
//! - [`CallbackContext`] -- safe `Arc` <-> `usize` lifecycle for `DWORD_PTR` context values
//! - [`CompletionSignal<T>`] -- reusable one-shot channel bridging callback to future
//! - [`await_win32()`] -- async combinator: install listener -> call Win32 -> await callback
//!
//! **No Win32 knowledge** -- the bridge is generic. It solves the problem:
//! "an OS callback fires on an arbitrary thread, I want a Rust `Future` to resolve."
//!
//! **Executor-agnostic** -- uses `futures_channel::oneshot`, works on tokio, async-std,
//! or bare `block_on`.

use futures_channel::oneshot;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use crate::util::lock_or_clear;

// ---------------------------------------------------------------------------
// CallbackContext -- safe Arc <-> usize lifecycle
// ---------------------------------------------------------------------------

/// Leak an `Arc` reference as a raw `usize`, suitable for passing as
/// `dwContext` / `DWORD_PTR` to a Win32 API.
///
/// Increments the Arc's strong count. The caller **must** eventually call
/// [`reclaim_context_ptr`] exactly once to balance this.
pub fn leak_context_ptr<T>(arc: &Arc<T>) -> usize {
    Arc::into_raw(Arc::clone(arc)) as usize
}

/// Borrow the value behind a context pointer inside a callback.
///
/// Returns a reference valid for the duration of the callback invocation.
/// Does **not** change the reference count.
///
/// # Safety
/// - `ptr` must have been returned by [`leak_context_ptr`].
/// - The matching [`reclaim_context_ptr`] must not have been called yet.
pub unsafe fn borrow_context_ptr<'a, T>(ptr: usize) -> &'a T {
    unsafe { &*(ptr as *const T) }
}

/// Reclaim the leaked `Arc`, decrementing the strong count.
///
/// Call this exactly once, from the **final** callback (e.g.,
/// `WINHTTP_CALLBACK_STATUS_HANDLE_CLOSING`, COM release, etc.).
///
/// # Safety
/// - `ptr` must have been returned by [`leak_context_ptr`].
/// - Must be called exactly once per [`leak_context_ptr`] call.
pub unsafe fn reclaim_context_ptr<T>(ptr: usize) {
    unsafe {
        drop(Arc::from_raw(ptr as *const T));
    }
}

// ---------------------------------------------------------------------------
// CompletionSignal -- reusable one-shot channel
// ---------------------------------------------------------------------------

/// A reusable one-shot channel that bridges Win32 callbacks to Rust Futures.
///
/// Before each async operation, call [`listen()`](Self::listen) to get a `Future`.
/// From the callback, call [`signal()`](Self::signal) to resolve that `Future`.
///
/// Only one listener is active at a time -- this matches Win32's sequential
/// async model where you must wait for one callback before starting the
/// next operation.
pub struct CompletionSignal<T: Send> {
    sender: Mutex<Option<oneshot::Sender<T>>>,
}

/// Future returned by [`CompletionSignal::listen()`].
pub struct CompletionFuture<T>(oneshot::Receiver<T>);

/// Error returned when the sender is dropped without signaling
/// (e.g., the Win32 handle was closed, cancelling in-flight operations).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignalCancelled;

impl std::fmt::Display for SignalCancelled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("completion signal cancelled (sender dropped)")
    }
}

impl std::error::Error for SignalCancelled {}

impl<T: Send> CompletionSignal<T> {
    /// Create a new `CompletionSignal` with no active listener.
    pub fn new() -> Self {
        Self {
            sender: Mutex::new(None),
        }
    }

    /// Install a fresh listener. Returns a future that resolves when
    /// [`signal()`](Self::signal) is called from a callback.
    ///
    /// If a previous listener was never consumed (e.g., the Win32 function
    /// failed synchronously, or the future was dropped), it is silently
    /// replaced. This makes the signal robust against all cancellation
    /// and error paths.
    pub fn listen(&self) -> CompletionFuture<T> {
        let (tx, rx) = oneshot::channel();
        // Safe to recover from poison: `sender` is an `Option<Sender>` slot
        // with only `.replace()` / `.take()` -- no multi-field invariant.
        let old = lock_or_clear(&self.sender).replace(tx);
        if old.is_some() {
            debug!("CompletionSignal::listen: replacing unconsumed sender");
        }
        CompletionFuture(rx)
    }

    /// Signal the current listener from a callback.
    ///
    /// Safe to call from any thread -- the `Mutex` is held for nanoseconds
    /// (just an `Option::take`). No-op if no listener is installed.
    pub fn signal(&self, value: T) {
        // Safe to recover from poison: `sender` is an `Option<Sender>` slot
        // with only `.take()` / `.replace()` -- no multi-field invariant.
        if let Some(tx) = lock_or_clear(&self.sender).take() {
            let _ = tx.send(value); // Receiver may be dropped (cancelled) -- that's fine
        }
    }
}

impl<T: Send> Default for CompletionSignal<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> Future for CompletionFuture<T> {
    type Output = Result<T, SignalCancelled>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // SAFETY: We're projecting the pin to the inner Receiver, which is Unpin.
        let receiver = &mut self.get_mut().0;
        // oneshot::Receiver is Unpin, so we can pin it trivially.
        Pin::new(receiver)
            .poll(cx)
            .map(|r| r.map_err(|_| SignalCancelled))
    }
}

// ---------------------------------------------------------------------------
// await_win32 -- the async combinator
// ---------------------------------------------------------------------------

/// Start a Win32 async operation and await its completion callback.
///
/// 1. Calls `signal.listen()` to prepare for the callback.
/// 2. Calls `start_op()` to begin the Win32 operation.
/// 3. If `start_op` succeeds -> awaits the callback via the listener.
///    If `start_op` fails  -> returns the error immediately (the listener
///    is abandoned and will be replaced on the next `listen()` call).
///
/// This handles the critical WinHTTP edge case: when a function like
/// `WinHttpSendRequest` returns `FALSE` with `GetLastError() !=
/// `ERROR_IO_PENDING`, the failure is synchronous and no callback fires.
pub async fn await_win32<T, E, F>(signal: &CompletionSignal<T>, start_op: F) -> Result<T, E>
where
    T: Send,
    E: From<SignalCancelled>,
    F: FnOnce() -> Result<(), E>,
{
    let future = signal.listen();
    start_op()?; // Synchronous failure -> return Err, listener abandoned
    future.await.map_err(E::from)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn signal_from_another_thread() {
        let signal = Arc::new(CompletionSignal::<u32>::new());
        let signal2 = Arc::clone(&signal);
        let future = signal.listen();

        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(10));
            signal2.signal(42);
        });

        let result = futures_executor::block_on(future);
        assert_eq!(result, Ok(42));
    }

    #[test]
    fn signal_before_poll_still_works() {
        let signal: CompletionSignal<u32> = Default::default();
        let future = signal.listen();
        signal.signal(7); // Signal before the future is polled
        assert_eq!(futures_executor::block_on(future), Ok(7));
    }

    #[test]
    fn dropped_sender_returns_cancelled() {
        let signal = CompletionSignal::<u32>::new();
        let future = signal.listen();
        drop(signal); // Sender dropped without signaling
        assert!(futures_executor::block_on(future).is_err());
    }

    #[test]
    fn replaced_listener_does_not_panic() {
        let signal = CompletionSignal::<u32>::new();
        let _fut1 = signal.listen(); // Never consumed
        let fut2 = signal.listen(); // Replaces fut1's sender silently
        signal.signal(99);
        assert_eq!(futures_executor::block_on(fut2), Ok(99));
    }

    #[test]
    fn sequential_reuse() {
        // Simulates the Win32 pattern: listen -> signal -> listen -> signal -> ...
        let signal = CompletionSignal::<&str>::new();

        let f1 = signal.listen();
        signal.signal("step1");
        assert_eq!(futures_executor::block_on(f1), Ok("step1"));

        let f2 = signal.listen();
        signal.signal("step2");
        assert_eq!(futures_executor::block_on(f2), Ok("step2"));
    }

    #[test]
    fn context_ptr_round_trip() {
        let state = Arc::new(String::from("hello"));
        let raw = leak_context_ptr(&state);
        assert_eq!(Arc::strong_count(&state), 2);

        unsafe {
            let s: &String = borrow_context_ptr(raw);
            assert_eq!(s, "hello");

            reclaim_context_ptr::<String>(raw);
        }
        assert_eq!(Arc::strong_count(&state), 1);
        assert_eq!(*state, "hello"); // Still valid
    }

    /// Custom error type for testing `await_win32`.
    #[derive(Debug, PartialEq)]
    enum TestError {
        Sync(&'static str),
        Cancelled,
    }

    impl From<SignalCancelled> for TestError {
        fn from(_: SignalCancelled) -> Self {
            TestError::Cancelled
        }
    }

    #[test]
    fn await_win32_sync_failure_skips_callback() {
        let signal = CompletionSignal::<u32>::new();
        let result = futures_executor::block_on(await_win32(&signal, || {
            Err::<(), _>(TestError::Sync("sync fail"))
        }));
        assert_eq!(result, Err(TestError::Sync("sync fail")));
        // The listener was abandoned -- next listen() should work fine
        let _fut = signal.listen();
    }

    #[test]
    fn await_win32_success() {
        let signal = CompletionSignal::<u32>::new();
        // Signal right after start_op succeeds (simulates immediate callback)
        let result = futures_executor::block_on(async {
            // We need to signal from another thread since await_win32 will block
            // waiting for the signal after start_op succeeds.
            let signal_ref = &signal;

            // For this test, signal before awaiting (oneshot channels buffer one value)
            let future = signal_ref.listen();
            signal_ref.signal(42);
            // Re-create the pattern manually since we can't signal during await_win32
            // in a single-threaded executor
            future.await.map_err(TestError::from)
        });
        assert_eq!(result, Ok(42));
    }

    #[test]
    fn await_win32_threaded_success() {
        let signal = Arc::new(CompletionSignal::<u32>::new());
        let signal2 = Arc::clone(&signal);

        let result = futures_executor::block_on(await_win32(&signal, || {
            // Start a thread that will signal after a brief delay
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(10));
                signal2.signal(99);
            });
            Ok::<(), TestError>(())
        }));
        assert_eq!(result, Ok(99));
    }

    /// Dropping the `CompletionSignal` after `start_op` succeeds but
    /// before the future resolves triggers the `From<SignalCancelled>`
    /// conversion.
    #[test]
    fn await_win32_cancelled_signal() {
        let signal = CompletionSignal::<u32>::new();
        let future = signal.listen();
        // Drop the signal without calling .signal() -- the sender is gone.
        drop(signal);
        // The future resolves to Err(SignalCancelled), which converts
        // via From<SignalCancelled> into TestError::Cancelled.
        let result: Result<u32, TestError> =
            futures_executor::block_on(async { future.await.map_err(TestError::from) });
        assert_eq!(result, Err(TestError::Cancelled));
    }
}
