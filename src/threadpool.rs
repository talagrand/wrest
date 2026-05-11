//! Win32 threadpool timer wrapper.
//!
//! The only consumer is [`crate::timer`].  Timers run on the
//! system-managed default process threadpool, so no library-owned
//! thread can survive a `FreeLibrary` call.
//!
//! # RAII contract
//!
//! [`ThreadpoolTimer`] is an owned handle; `Drop` performs the full
//! DLL-safe teardown in this order:
//!
//! 1. `SetThreadpoolTimer(_, NULL, 0, 0)` -- stop scheduling new callbacks
//! 2. `WaitForThreadpoolTimerCallbacks(_, TRUE)` -- cancel + wait
//! 3. `CloseThreadpoolTimer(_)` -- release the object

use windows_sys::Win32::{
    Foundation::FILETIME,
    System::Threading::{
        CloseThreadpoolTimer, CreateThreadpoolTimer, PTP_TIMER, PTP_TIMER_CALLBACK,
        SetThreadpoolTimer, WaitForThreadpoolTimerCallbacks,
    },
};

/// Owned Win32 threadpool timer.
///
/// Constructed only via [`ThreadpoolTimer::new`]; closed (after drain)
/// only via `Drop`.  Not `Clone`/`Copy`, so any `&ThreadpoolTimer` is
/// proof of a live, unique handle and double-close is structurally
/// impossible.
pub(crate) struct ThreadpoolTimer {
    handle: PTP_TIMER,
}

// SAFETY: `PTP_TIMER` is an opaque OS handle; Win32 documents
// `SetThreadpoolTimer`, `WaitForThreadpoolTimerCallbacks`, and
// `CloseThreadpoolTimer` as callable from any thread on the same
// handle.  No interior mutability is exposed at the Rust level.
unsafe impl Send for ThreadpoolTimer {}
unsafe impl Sync for ThreadpoolTimer {}

impl ThreadpoolTimer {
    /// `CreateThreadpoolTimer` -- allocate a timer on the default pool.
    /// Returns `None` on allocation failure; callers should treat that
    /// as "timer disabled" (see [`crate::timer::Delay`]).
    ///
    /// # Safety
    ///
    /// `callback` must be a valid `PTP_TIMER_CALLBACK`.  `context` must
    /// stay dereferenceable until this `ThreadpoolTimer` is dropped;
    /// `Drop` waits for the last callback to return before releasing
    /// the handle.
    pub(crate) unsafe fn new(
        callback: PTP_TIMER_CALLBACK,
        context: *mut core::ffi::c_void,
    ) -> Option<Self> {
        // SAFETY: caller upholds `callback` / `context` validity.
        let h = unsafe { CreateThreadpoolTimer(callback, context, std::ptr::null()) };
        if h == 0 as PTP_TIMER {
            None
        } else {
            Some(Self { handle: h })
        }
    }

    /// `SetThreadpoolTimer` -- arm (`Some`) or stop (`None`) the timer.
    ///
    /// `due_in_ticks` is a non-negative duration in 100-ns units; the
    /// wrapper negates it because `SetThreadpoolTimer` reads a negative
    /// `FILETIME` as a relative due time.
    pub(crate) fn set_relative(&self, due_in_ticks: Option<i64>) {
        match due_in_ticks {
            Some(ticks) => {
                // Negative => relative time, in 100-ns units.
                let neg = -ticks;
                let ft = FILETIME {
                    dwLowDateTime: neg as u32,
                    dwHighDateTime: (neg >> 32) as u32,
                };
                // SAFETY: `self.handle` is live (closed only in `Drop`).
                unsafe { SetThreadpoolTimer(self.handle, &raw const ft, 0, 0) };
            }
            None => {
                // SAFETY: `self.handle` is live; null `pftDueTime`
                // stops further callbacks being queued.
                unsafe { SetThreadpoolTimer(self.handle, std::ptr::null(), 0, 0) };
            }
        }
    }

    /// Raw `PTP_TIMER` handle for diagnostics only.  Do **not** close.
    #[cfg(debug_assertions)]
    pub(crate) fn as_raw(&self) -> PTP_TIMER {
        self.handle
    }
}

impl Drop for ThreadpoolTimer {
    fn drop(&mut self) {
        // DLL-safe teardown: stop scheduling, drain in-flight, close.
        // Must not run from inside this timer's own callback (the wait
        // would deadlock); a `debug_assert!` in `crate::timer::Delay`
        // enforces this at the only construction site.
        self.set_relative(None);
        // SAFETY: handle owned exclusively (no Clone/Copy); scheduling
        // stopped above; wait blocks until any in-flight callback
        // returns; close releases the object.
        unsafe {
            WaitForThreadpoolTimerCallbacks(self.handle, 1);
            CloseThreadpoolTimer(self.handle);
        }
    }
}
