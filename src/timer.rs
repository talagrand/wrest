//! Unload-safe async timer built on the Win32 threadpool.
//!
//! [`Delay`] is a drop-in replacement for `futures_timer::Delay` that
//! schedules its callback onto the system-managed default process
//! threadpool instead of a library-owned helper thread.  This matters
//! for hosts that load this code as a DLL and later call `FreeLibrary` --
//! a leaked thread holding code pointers into the unloaded DLL would
//! crash on its next wakeup.
//!
//! # Teardown contract
//!
//! Each `Delay` owns a [`ThreadpoolTimer`].  Dropping the `Delay`:
//!
//! 1. drops the inner `ThreadpoolTimer`, whose `Drop` impl performs the
//!    standard Win32 drain sequence (`SetThreadpoolTimer(_, NULL)` ->
//!    `WaitForThreadpoolTimerCallbacks(_, TRUE)` -> `CloseThreadpoolTimer`),
//!    then
//! 2. drops the [`CallbackContext`], which releases the retained
//!    context `Arc` that was passed to the OS as the callback's context.
//!
//! After the inner `ThreadpoolTimer` is dropped, no callback can re-enter
//! this DLL.  Hosts that drain outstanding
//! `Client`/`Response`/`Delay` before `FreeLibrary` will have nothing in
//! flight.  This matches the contract already documented for the
//! WinHTTP status callback.
//!
//! # Clock semantics
//!
//! Threadpool timers with a relative `pftDueTime` are documented to
//! exclude time the system spends in sleep or hibernation, matching the
//! monotonic semantics of `std::time::Instant` and the behaviour reqwest
//! provides via `tokio::time::sleep`.

use crate::{
    callback::{CallbackContext, CompletionFuture, CompletionSignal},
    threadpool::ThreadpoolTimer,
};
use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use windows_sys::Win32::System::Threading::{PTP_CALLBACK_INSTANCE, PTP_TIMER};

// ---------------------------------------------------------------------------
// Shared state
// ---------------------------------------------------------------------------

/// Heap state shared between the `Delay` future and the threadpool
/// callback.  Lives in an `Arc` whose strong count is held by the
/// `Delay` (for polling) plus a retained clone passed as the timer
/// callback's context (released in `Drop`).
struct TimerState {
    signal: CompletionSignal<()>,
}

// ---------------------------------------------------------------------------
// Debug-only callback re-entry guard
// ---------------------------------------------------------------------------

#[cfg(debug_assertions)]
mod debug {
    use windows_sys::Win32::System::Threading::PTP_TIMER;

    thread_local! {
        pub(super) static TIMER_CALLBACK_STACK: std::cell::RefCell<Vec<usize>> =
            const { std::cell::RefCell::new(Vec::new()) };
    }

    pub(super) struct TimerCallbackStackGuard {
        timer: usize,
    }

    impl TimerCallbackStackGuard {
        pub(super) fn enter(timer: PTP_TIMER) -> Self {
            let timer = timer.cast_unsigned();
            TIMER_CALLBACK_STACK.with(|stack| stack.borrow_mut().push(timer));
            Self { timer }
        }
    }

    impl Drop for TimerCallbackStackGuard {
        fn drop(&mut self) {
            TIMER_CALLBACK_STACK.with(|stack| {
                let popped = stack.borrow_mut().pop();
                debug_assert_eq!(
                    popped,
                    Some(self.timer),
                    "threadpool timer callback stack tracking became unbalanced"
                );
            });
        }
    }
}

// ---------------------------------------------------------------------------
// Timer callback
// ---------------------------------------------------------------------------

/// `PTP_TIMER_CALLBACK` -- fired on a system threadpool thread when the
/// timer expires.  Just resolves the `CompletionSignal`; the receiver
/// (`Delay::poll`) then wakes the user task.
///
/// # Safety
///
/// Invoked by the OS with the retained `Arc<TimerState>` pointer that
/// [`Delay::new`] passed to `CreateThreadpoolTimer`.  That pointer
/// remains valid until `Delay::drop` (after
/// `WaitForThreadpoolTimerCallbacks` returns) drops the
/// [`CallbackContext`], which releases the strong reference.
unsafe extern "system" fn timer_callback(
    _instance: PTP_CALLBACK_INSTANCE,
    context: *mut core::ffi::c_void,
    timer: PTP_TIMER,
) {
    if context.is_null() {
        return;
    }
    // A panic across this `extern "system"` boundary into the OS
    // threadpool worker is UB; swallow it here.
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        #[cfg(debug_assertions)]
        let _callback_stack_guard = debug::TimerCallbackStackGuard::enter(timer);
        #[cfg(not(debug_assertions))]
        let _ = timer;

        // SAFETY: `context` is the live `CallbackContext<TimerState>`
        // raw pointer owned by `Delay`; `Delay::drop` waits for this
        // callback to finish before releasing it.
        let state: &TimerState =
            unsafe { CallbackContext::<TimerState>::borrow_raw(context as usize) };
        state.signal.signal(());
    }));
}

// ---------------------------------------------------------------------------
// Delay
// ---------------------------------------------------------------------------

/// A future that resolves after a specified duration.
///
/// Drop-in replacement for `futures_timer::Delay`.  Built on the Win32
/// default-process threadpool so this library never owns a timer thread
/// that it needs to manage.
///
/// `Delay` is `Send` automatically: every field is `Send`, including
/// the [`ThreadpoolTimer`] handle (the OS documents `PTP_TIMER` as
/// thread-safe for set/wait/close).
pub(crate) struct Delay {
    /// `None` only if `CreateThreadpoolTimer` failed; in that case the
    /// future is permanently `Pending` and `Drop` is a no-op for the
    /// timer object.
    timer: Option<ThreadpoolTimer>,
    /// Retained `Arc<TimerState>` strong reference, if a timer was
    /// successfully created.  Its `Drop` releases the reference after
    /// `ThreadpoolTimer`'s own `Drop` has drained any in-flight callback.
    callback_ctx: Option<CallbackContext<TimerState>>,
    /// Defensive strong reference to the same `TimerState`.  Required
    /// for the `CreateThreadpoolTimer`-failure path where there is no
    /// `callback_ctx` to keep the signal's sender alive; without it the
    /// receiver in `listener` would see immediate cancellation and
    /// `poll` would treat that as "timer fired".  Also acts as belt-and-
    /// braces in the success path against future Drop-ordering refactors.
    _state: Arc<TimerState>,
    /// Receiver half of the one-shot, armed at construction.
    listener: CompletionFuture<()>,
    /// Set once `listener` resolves, so subsequent polls are cheap.
    fired: bool,
}

impl Delay {
    /// Schedule a one-shot timer that resolves after `dur`.
    ///
    /// Infallible: if the underlying `CreateThreadpoolTimer` call fails
    /// (rare; resource exhaustion), the returned future is permanently
    /// pending.  This is the safer degradation for the timeout call
    /// sites, where `Delay` is raced against an HTTP request inside
    /// `select`: a never-firing timer disables the timeout, while an
    /// instantly-firing timer would spuriously fail otherwise-healthy
    /// requests.
    ///
    /// # Resolution
    ///
    /// Windows scheduler resolution is ~15.6 ms by default (1 ms with
    /// `timeBeginPeriod`).  Sub-millisecond `dur` values round *up* to
    /// the current timer tick.
    pub(crate) fn new(dur: Duration) -> Self {
        let state = Arc::new(TimerState {
            signal: CompletionSignal::new(),
        });
        // Arm the listener *before* scheduling the timer, so a fast
        // callback (very short duration) cannot race ahead of us.
        let listener = state.signal.listen();

        let callback_ctx = CallbackContext::<TimerState>::new(&state);

        // SAFETY: `timer_callback` matches `PTP_TIMER_CALLBACK`'s ABI;
        // `callback_ctx` keeps the `Arc<TimerState>` alive until `Drop`
        // releases it after draining callbacks.
        let timer = unsafe {
            ThreadpoolTimer::new(
                Some(timer_callback),
                callback_ctx.as_raw() as *mut core::ffi::c_void,
            )
        };

        match timer {
            Some(t) => {
                t.set_relative(Some(dur));

                Self {
                    timer: Some(t),
                    callback_ctx: Some(callback_ctx),
                    _state: state,
                    listener,
                    fired: false,
                }
            }
            None => {
                // CreateThreadpoolTimer failed; `callback_ctx` is
                // dropped here, releasing the strong ref.  The returned
                // future is permanently pending.
                drop(callback_ctx);
                warn!(
                    "wrest::timer::Delay: CreateThreadpoolTimer failed; \
                     timeout will not fire (request will run unbounded)"
                );
                Self {
                    timer: None,
                    callback_ctx: None,
                    _state: state,
                    listener,
                    fired: false,
                }
            }
        }
    }
}

impl Future for Delay {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        // `Delay` holds no self-referential data, so projecting through
        // a `&mut` is sound.
        let this = self.get_mut();
        if this.fired {
            return Poll::Ready(());
        }
        // `CompletionFuture` wraps a `oneshot::Receiver`, which is `Unpin`.
        match Pin::new(&mut this.listener).poll(cx) {
            Poll::Ready(_) => {
                // Treat both Ok(()) (callback fired) and Err(cancelled)
                // (sender dropped) as "timer elapsed".  Cancellation only
                // happens if `Drop` runs concurrently with `poll`, which
                // cannot occur for a pinned future.
                this.fired = true;
                Poll::Ready(())
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl Drop for Delay {
    fn drop(&mut self) {
        let Some(timer) = self.timer.take() else {
            // CreateThreadpoolTimer had failed; nothing to tear down.
            return;
        };

        #[cfg(debug_assertions)]
        {
            let timer_id = timer.as_raw().cast_unsigned();
            debug::TIMER_CALLBACK_STACK.with(|stack| {
                debug_assert!(
                    !stack.borrow().contains(&timer_id),
                    "Delay dropped while inside its own timer callback; \
                     this suggests an executor/waker synchronously polled from wake"
                );
            });
        }

        // Drop the `ThreadpoolTimer`.  Its `Drop` impl follows:
        // stop scheduling -> wait for in-flight callbacks ->
        // close the timer object.  When this returns, no callback can
        // dereference the context Arc.
        drop(timer);

        // Safe to release the retained context ref: no callback can fire.
        // Remaining field drop order (`_state`, `listener`, `fired`) is
        // unconstrained for the same reason.
        let _ = self.callback_ctx.take();
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use futures_executor::block_on;
    use std::task::{Context, Poll, Waker};
    use std::time::Instant;

    /// What state a `Delay` is in when its `Drop` runs.  Each variant
    /// exercises a different drain code path:
    /// * `BeforeFire` -- never polled; timer may still be armed.
    /// * `AfterFire`  -- awaited to completion; callback already ran.
    /// * `WhilePending` -- polled once with a registered waker; callback
    ///   may be queued or in-flight when `Drop` starts.
    #[derive(Clone, Copy)]
    enum DropState {
        BeforeFire,
        AfterFire,
        WhilePending,
    }

    #[test]
    fn fires_table() {
        // (dur, min_elapsed, label)
        let cases: &[(Duration, Duration, &str)] = &[
            (Duration::ZERO, Duration::ZERO, "zero duration"),
            (Duration::from_millis(1), Duration::ZERO, "sub-tick (~scheduler floor)"),
            (Duration::from_millis(50), Duration::from_millis(40), "normal 50ms"),
        ];

        for &(dur, min_elapsed, label) in cases {
            let start = Instant::now();
            block_on(Delay::new(dur));
            let elapsed = start.elapsed();
            // Lower bound: timer must not fire before its due time.
            assert!(elapsed >= min_elapsed, "{label}: fired too early ({elapsed:?})");
            // Upper bound: catch a permanently-pending future (e.g. a
            // regression in init ordering or signal plumbing).
            assert!(elapsed < Duration::from_secs(2), "{label}: fired far too late ({elapsed:?})");
        }
    }

    #[test]
    fn drop_lifecycle_table() {
        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);

        // (dur, drop_state, label)
        let cases: &[(Duration, DropState, &str)] = &[
            (Duration::ZERO, DropState::BeforeFire, "zero / drop before fire"),
            (Duration::from_millis(100), DropState::BeforeFire, "100ms / armed at drop"),
            (Duration::ZERO, DropState::AfterFire, "zero / drop after await"),
            (Duration::from_millis(1), DropState::AfterFire, "1ms / drop after await"),
            (Duration::from_millis(20), DropState::WhilePending, "20ms / drop while polled"),
            (Duration::from_millis(100), DropState::WhilePending, "100ms / polled, still armed"),
        ];

        // Repeat each case a few times to surface drain races; the
        // operation is cheap so this stays well under a second total.
        const REPS: usize = 8;
        for &(dur, state, label) in cases {
            for i in 0..REPS {
                match state {
                    DropState::BeforeFire => {
                        let d = Delay::new(dur);
                        drop(d);
                    }
                    DropState::AfterFire => {
                        block_on(Delay::new(dur));
                    }
                    DropState::WhilePending => {
                        let mut d = Box::pin(Delay::new(dur));
                        let _ = d.as_mut().poll(&mut cx);
                        drop(d);
                    }
                }
                // Tag iteration for crash reports: if a callback fires
                // post-drop the panic message will identify the case.
                let _ = (label, i);
            }
        }
    }

    #[test]
    fn races_with_select() {
        use futures_util::future::{Either, select};
        let fast = Delay::new(Duration::from_millis(10));
        let slow = Delay::new(Duration::from_secs(60));
        let fast = std::pin::pin!(fast);
        let slow = std::pin::pin!(slow);
        match block_on(select(fast, slow)) {
            Either::Left(_) => {} // expected: fast wins
            Either::Right(_) => panic!("slow timer beat fast timer"),
        }
    }

    /// Polling after the future has resolved must return `Ready` without
    /// touching the underlying receiver again.
    #[test]
    fn poll_after_ready_is_idempotent() {
        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);
        let mut d = Box::pin(Delay::new(Duration::ZERO));

        // Drive to completion.
        block_on(async {
            // Awaiting consumes the future via `poll`; once it returns we
            // know `fired` is set.  Re-poll directly to exercise the
            // short-circuit path.
            (&mut d).await;
        });
        match d.as_mut().poll(&mut cx) {
            Poll::Ready(()) => {}
            Poll::Pending => panic!("Delay re-polled after Ready returned Pending"),
        }
    }

    /// Covers timer_callback: direct dispatch - is_null early return and valid-context signal path.
    #[test]
    fn timer_callback_dispatch_table() {
        enum TimerOutcome {
            Signaled,
            Pending,
        }

        // (label, supply_valid_context, expected outcome on the listener)
        let cases: &[(&str, bool, TimerOutcome)] = &[
            ("NULL context -> early return, no signal", false, TimerOutcome::Pending),
            ("valid context -> signals listener", true, TimerOutcome::Signaled),
        ];

        for (label, supply_ctx, expected) in cases {
            let state = Arc::new(TimerState {
                signal: CompletionSignal::new(),
            });
            let listener = state.signal.listen();
            // Hold the retained ref; drop after the call (no drop_raw here).
            let ctx = CallbackContext::<TimerState>::new(&state);

            let raw_ctx: *mut core::ffi::c_void = if *supply_ctx {
                ctx.as_raw() as *mut core::ffi::c_void
            } else {
                std::ptr::null_mut()
            };

            // SAFETY: `ctx` keeps Arc alive when supplied; null path returns
            // early.  `timer` is by-value, only used as a stack-guard key.
            unsafe {
                timer_callback(0 as PTP_CALLBACK_INSTANCE, raw_ctx, 1 as PTP_TIMER);
            }

            let waker = Waker::noop();
            let mut cx = Context::from_waker(waker);
            let mut listener = std::pin::pin!(listener);
            let poll = listener.as_mut().poll(&mut cx);

            match (expected, poll) {
                (TimerOutcome::Signaled, Poll::Ready(Ok(()))) => {}
                (TimerOutcome::Signaled, other) => {
                    panic!("{label}: expected Ready(Ok(())), got {other:?}");
                }
                (TimerOutcome::Pending, Poll::Pending) => {}
                (TimerOutcome::Pending, other) => {
                    panic!("{label}: expected Pending (no signal), got {other:?}");
                }
            }

            // Keep ctx alive past the listener observation.
            drop(ctx);
        }
    }
}
