//! Retry requests.
//!
//! A [`Client`](crate::Client) can automatically retry requests when a
//! response is classified as retryable.  The [`Builder`] configures what
//! to retry, with sensible defaults including a retry budget to prevent
//! retry storms.
//!
//! # Defaults
//!
//! The default retry behavior (applied when no explicit policy is set)
//! retries only connection-reset errors — the WinHTTP equivalent of
//! HTTP/2 GOAWAY / REFUSED\_STREAM — where the server signals it did
//! not process the request.  Max 2 retries per request, no budget
//! (connection resets are inherently rare).
//!
//! # Scoped
//!
//! A retry policy is scoped — it only applies to requests matching the
//! scope (typically a single host).  Since all policies include a budget
//! by default, applying retries to *all* requests would unfairly share
//! the budget across unrelated hosts.
//!
//! # Classifiers
//!
//! A retry policy needs a classifier that decides whether a given
//! request/response pair should be retried.  Knowledge of the server's
//! semantics is required to build safe classifiers — **do not retry**
//! if the server cannot handle the same request twice or if it causes
//! side effects.

use std::sync::Arc;
use std::time::Duration;

use budget::Budget;

pub(crate) use classify::Action;
use classify::ReqRep;

type ClassifyFn = Arc<dyn for<'a> Fn(ReqRep<'a>) -> Action + Send + Sync>;
type ScopeFn = Arc<dyn Fn(&crate::Url, &http::Method) -> bool + Send + Sync>;

// ===== Public free functions ==========================================

/// Create a retry builder scoped to a specific host.
pub fn for_host<S>(host: S) -> Builder
where
    S: for<'a> PartialEq<&'a str> + Send + Sync + 'static,
{
    scoped(move |url: &crate::Url, _| host == url.host_str().unwrap_or(""))
}

/// Create a retry policy that will never retry any request.
///
/// Useful for disabling the `Client`'s default behaviour of retrying
/// connection resets.
pub fn never() -> Builder {
    scoped(|_, _| false).no_budget()
}

fn scoped<F>(func: F) -> Builder
where
    F: Fn(&crate::Url, &http::Method) -> bool + Send + Sync + 'static,
{
    Builder::scoped(func)
}

// ===== Builder ========================================================

/// Builder to configure retries.
///
/// Construct with [`for_host()`].
pub struct Builder {
    budget: Option<f32>,
    classify: Option<ClassifyFn>,
    max_retries_per_request: u32,
    scope: Option<ScopeFn>,
}

impl Builder {
    /// Create a scoped retry policy.
    pub(crate) fn scoped(
        scope: impl Fn(&crate::Url, &http::Method) -> bool + Send + Sync + 'static,
    ) -> Self {
        Self {
            budget: Some(0.2),
            classify: None,
            max_retries_per_request: 2,
            scope: Some(Arc::new(scope)),
        }
    }

    /// Disable the retry budget.
    ///
    /// **Not recommended.** Disabling the budget makes the system more
    /// susceptible to retry storms.
    #[must_use]
    pub fn no_budget(mut self) -> Self {
        self.budget = None;
        self
    }

    /// Set the maximum extra load the budget will allow, as a fraction.
    ///
    /// For example, `0.2` allows 20% extra requests from retries.
    ///
    /// # Panics
    ///
    /// Panics if `extra_percent` is less than `0.0` or greater than
    /// `1000.0`.
    #[must_use]
    pub fn max_extra_load(mut self, extra_percent: f32) -> Self {
        assert!(extra_percent >= 0.0);
        assert!(extra_percent <= 1000.0);
        self.budget = Some(extra_percent);
        self
    }

    /// Set the maximum retries per individual request.
    ///
    /// Even when the budget has remaining capacity, a single request
    /// will not be retried more than `max` times.
    ///
    /// Default: 2.
    #[must_use]
    pub fn max_retries_per_request(mut self, max: u32) -> Self {
        self.max_retries_per_request = max;
        self
    }

    /// Provide a closure classifier to decide whether a request should
    /// be retried.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # fn with_builder(builder: wrest::retry::Builder) -> wrest::retry::Builder {
    /// builder.classify_fn(|req_rep| {
    ///     // Retry idempotent GETs that received a transient 503.
    ///     if req_rep.method() == http::Method::GET
    ///         && req_rep.status() == Some(http::StatusCode::SERVICE_UNAVAILABLE)
    ///     {
    ///         return req_rep.retryable();
    ///     }
    ///     req_rep.success()
    /// })
    /// # }
    /// ```
    #[must_use]
    pub fn classify_fn<F>(mut self, func: F) -> Self
    where
        F: Fn(ReqRep<'_>) -> Action + Send + Sync + 'static,
    {
        self.classify = Some(Arc::new(func));
        self
    }

    pub(crate) fn default() -> Builder {
        Self {
            // Unscoped protocol NACKs don't need a budget (they are rare)
            budget: None,
            classify: Some(Arc::new(|rr| {
                if rr.is_protocol_nack() {
                    Action::Retryable
                } else {
                    Action::Success
                }
            })),
            max_retries_per_request: 2,
            scope: None,
        }
    }

    pub(crate) fn into_policy(self) -> Policy {
        let budget = self
            .budget
            .map(|p| Arc::new(Budget::new(Duration::from_secs(10), 10, p)));
        Policy {
            budget,
            classify: self.classify,
            max_retries_per_request: self.max_retries_per_request,
            scope: self.scope,
        }
    }
}

impl std::fmt::Debug for Builder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Builder")
            .field("budget", &self.budget)
            .field("max_retries_per_request", &self.max_retries_per_request)
            .finish()
    }
}

// ===== Policy (internal) =============================================

/// The resolved retry policy stored in the client.
#[derive(Clone)]
pub(crate) struct Policy {
    budget: Option<Arc<Budget>>,
    classify: Option<ClassifyFn>,
    max_retries_per_request: u32,
    scope: Option<ScopeFn>,
}

impl Policy {
    /// Classify whether a request result should be retried.
    pub(crate) fn classify_result(
        &self,
        url: &crate::Url,
        method: &http::Method,
        result: &Result<crate::Response, crate::Error>,
    ) -> Action {
        // Check scope first — if the request isn't in scope, don't retry.
        if let Some(ref scope) = self.scope
            && !scope(url, method)
        {
            return Action::Success;
        }

        let Some(ref classify) = self.classify else {
            return Action::Success;
        };

        // If we can't represent the URL as an http::Uri, we can't
        // meaningfully classify — don't retry.
        let Ok(rr) = ReqRep::new(url, method, result) else {
            return Action::Success;
        };

        classify(rr)
    }

    /// Deposit a success token into the budget.
    pub(crate) fn deposit(&self) {
        if let Some(ref budget) = self.budget {
            budget.deposit();
        }
    }

    /// Try to withdraw a retry token from the budget.
    pub(crate) fn can_withdraw(&self) -> bool {
        self.budget.as_ref().is_none_or(|b| b.withdraw())
    }

    /// Maximum retries for a single request.
    pub(crate) fn max_retries(&self) -> u32 {
        self.max_retries_per_request
    }
}

impl std::fmt::Debug for Policy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Policy")
            .field("budget", &self.budget)
            .field("max_retries_per_request", &self.max_retries_per_request)
            .finish()
    }
}

// ===== Budget =========================================================

mod budget {
    //! Sliding-window token-bucket retry budget.
    //!
    //! Implements the same algorithm as tower's [`TpsBudget`], a
    //! sliding-window token bucket originally inspired by
    //! [Finagle's `RetryBudget`][finagle].
    //!
    //! ## Algorithm
    //!
    //! The TTL window is divided into 10 fixed-duration slots.  Each slot
    //! accumulates a running balance via `deposit_amount` and
    //! `-withdraw_amount`.  A withdrawal succeeds when
    //! `sum_of_all_slots + writer + reserve >= withdraw_amount`.
    //!
    //! `deposit_amount` and `withdraw_amount` are scaled from
    //! `retry_percent`:
    //!
    //! | `retry_percent` | `deposit` | `withdraw` | Meaning |
    //! |---|---|---|---|
    //! | `0.0`  | 0    | 1   | Deposits give nothing; only reserve is usable |
    //! | `<= 1.0` (e.g. 0.2) | 1 | `(1/p)` (e.g. 5) | 5 deposits needed per retry |
    //! | `> 1.0` (e.g. 2.5) | 1000 | `(1000/p)` (e.g. 400) | High-precision ratio |
    //!
    //! `reserve = min_per_sec * ttl_secs * withdraw_amount`, providing a
    //! baseline number of retries even with zero deposits.
    //!
    //! [`TpsBudget`]: https://docs.rs/tower/0.4/tower/retry/budget/struct.TpsBudget.html
    //! [finagle]: https://twitter.github.io/finagle/guide/Clients.html#retries

    use std::sync::Mutex;
    use std::time::{Duration, Instant};

    pub(super) struct Budget {
        state: Mutex<BudgetState>,
        /// Pre-computed reserve added to every `sum()` call.
        reserve: isize,
        /// Ring of per-slot balances.
        slots: usize,
        /// Duration of each slot.
        slot_duration: Duration,
        /// Tokens added per `deposit()` call.
        pub(super) deposit_amount: isize,
        /// Tokens removed per `withdraw()` call.
        pub(super) withdraw_amount: isize,
    }

    struct BudgetState {
        /// Ring of per-slot balances (single signed value combining
        /// deposits and withdrawals).
        buckets: Vec<isize>,
        /// Uncommitted balance for the current slot.
        writer: isize,
        /// Index of the current generation.
        gen_index: usize,
        /// Timestamp of the current generation.
        gen_time: Instant,
    }

    impl Budget {
        /// Create a new budget.
        ///
        /// - `ttl` -- how long a single deposit remains valid (1..=60 s).
        /// - `min_per_sec` -- baseline retries per second of `ttl`,
        ///   independent of deposits.
        /// - `retry_percent` -- fraction of deposits that may be retried
        ///   (0.0..=1000.0).
        pub(super) fn new(ttl: Duration, min_per_sec: u32, retry_percent: f32) -> Self {
            assert!(ttl >= Duration::from_secs(1));
            assert!(ttl <= Duration::from_secs(60));
            assert!(retry_percent >= 0.0);
            assert!(retry_percent <= 1000.0);

            let (deposit_amount, withdraw_amount) = if retry_percent == 0.0 {
                (0isize, 1isize)
            } else if retry_percent <= 1.0 {
                (1, (1.0 / retry_percent) as isize)
            } else {
                (1000, (1000.0 / retry_percent) as isize)
            };

            let reserve = (min_per_sec as isize)
                .saturating_mul(ttl.as_secs() as isize)
                .saturating_mul(withdraw_amount);

            let num_slots: usize = 10;
            let slot_duration = ttl / num_slots as u32;

            Budget {
                state: Mutex::new(BudgetState {
                    buckets: vec![0isize; num_slots],
                    writer: 0,
                    gen_index: 0,
                    gen_time: Instant::now(),
                }),
                reserve,
                slots: num_slots,
                slot_duration,
                deposit_amount,
                withdraw_amount,
            }
        }

        pub(super) fn deposit(&self) {
            let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            self.advance(&mut state);
            state.writer += self.deposit_amount;
        }

        pub(super) fn withdraw(&self) -> bool {
            let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            self.advance(&mut state);

            let sum = self.sum(&state);
            if sum >= self.withdraw_amount {
                state.writer -= self.withdraw_amount;
                true
            } else {
                false
            }
        }

        /// Running balance: writer + all slots + reserve.
        fn sum(&self, state: &BudgetState) -> isize {
            let windowed: isize = state.buckets.iter().copied().fold(0, isize::saturating_add);
            state
                .writer
                .saturating_add(windowed)
                .saturating_add(self.reserve)
        }

        fn advance(&self, state: &mut BudgetState) {
            let now = Instant::now();
            let elapsed = now.duration_since(state.gen_time);

            if elapsed < self.slot_duration {
                return;
            }

            // Commit the writer into the current slot.
            let committed = std::mem::take(&mut state.writer);
            state.buckets[state.gen_index] = committed;

            // Clear elapsed slots.
            let mut remaining = elapsed;
            let mut idx = (state.gen_index + 1) % self.slots;
            while remaining > self.slot_duration {
                state.buckets[idx] = 0;
                remaining -= self.slot_duration;
                idx = (idx + 1) % self.slots;
            }

            state.gen_index = idx;
            state.gen_time = now;
        }
    }

    impl std::fmt::Debug for Budget {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("Budget")
                .field("deposit_amount", &self.deposit_amount)
                .field("withdraw_amount", &self.withdraw_amount)
                .field("reserve", &self.reserve)
                .finish()
        }
    }
}

// ===== Classification =================================================

mod classify {
    /// A request/response pair for classification.
    ///
    /// Received by closures passed to [`super::Builder::classify_fn()`].  Helper
    /// methods expose the request metadata and response outcome; call
    /// [`retryable()`](ReqRep::retryable) or
    /// [`success()`](ReqRep::success) to produce the final [`Action`].
    #[derive(Debug)]
    pub struct ReqRep<'a> {
        uri: http::Uri,
        method: &'a http::Method,
        result: Result<http::StatusCode, &'a crate::Error>,
    }

    impl<'a> ReqRep<'a> {
        pub(super) fn new(
            url: &crate::Url,
            method: &'a http::Method,
            result: &'a Result<crate::Response, crate::Error>,
        ) -> Result<Self, http::Error> {
            Ok(Self {
                uri: url.to_http_uri()?,
                method,
                result: match result {
                    Ok(resp) => Ok(resp.status()),
                    Err(e) => Err(e),
                },
            })
        }

        /// The request method.
        pub fn method(&self) -> &http::Method {
            self.method
        }

        /// The request URI.
        pub fn uri(&self) -> &http::Uri {
            &self.uri
        }

        /// The response status code, if the request succeeded.
        pub fn status(&self) -> Option<http::StatusCode> {
            self.result.ok()
        }

        /// The error, if the request failed.
        pub fn error(&self) -> Option<&(dyn std::error::Error + 'static)> {
            self.result.as_ref().err().map(|e| &**e as _)
        }

        /// Mark this result as retryable.
        pub fn retryable(self) -> Action {
            Action::Retryable
        }

        /// Mark this result as a success (do not retry).
        pub fn success(self) -> Action {
            Action::Success
        }

        pub(super) fn is_protocol_nack(&self) -> bool {
            self.result
                .as_ref()
                .err()
                .map(|e| e.is_connection_reset())
                .unwrap_or(false)
        }
    }

    /// The outcome of retry classification.
    #[must_use]
    #[derive(Debug, PartialEq)]
    pub enum Action {
        /// Do not retry — the request succeeded or is not retryable.
        Success,
        /// The request should be retried.
        Retryable,
    }
}

// ===== Tests ==========================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -- Budget scaling (data-driven) --

    #[test]
    fn budget_scaling_table() {
        // Each case: (retry_percent, expected_deposit, expected_withdraw, desc)
        let cases: &[(f32, isize, isize, &str)] = &[
            (0.0, 0, 1, "zero percent: deposit=0, withdraw=1"),
            (0.2, 1, 5, "20%: 5 deposits per retry"),
            (0.5, 1, 2, "50%: 2 deposits per retry"),
            (1.0, 1, 1, "100%: 1:1 ratio"),
            (2.5, 1000, 400, "250%: high-precision scaling"),
            (10.0, 1000, 100, "1000%: high-precision scaling"),
        ];

        for &(pct, exp_deposit, exp_withdraw, desc) in cases {
            let b = Budget::new(Duration::from_secs(10), 0, pct);
            assert_eq!(b.deposit_amount, exp_deposit, "{desc}: deposit_amount");
            assert_eq!(b.withdraw_amount, exp_withdraw, "{desc}: withdraw_amount");
        }
    }

    // -- Budget reserve (data-driven) --

    #[test]
    fn budget_reserve_table() {
        // Each case: (min_per_sec, ttl_secs, retry_percent,
        //             num_deposits, expected_withdrawals, desc)
        let cases: &[(u32, u64, f32, u32, u32, &str)] = &[
            // reserve = 5*10*5 = 250 → 50 withdrawals; 10 deposits add
            // 10 tokens → 2 more @ cost 5 each.
            (5, 10, 0.2, 10, 52, "standard budget with deposits"),
            // reserve = 0; 5 deposits @ 1:1 ratio → 5 withdrawals.
            (0, 10, 1.0, 5, 5, "no reserve, 1:1 deposits"),
            // reserve = 3*10*1 = 30; 0 deposits → 30 withdrawals.
            (3, 10, 0.0, 0, 30, "reserve only, zero percent"),
            // reserve = 0, no deposits → 0 withdrawals.
            (0, 10, 0.5, 0, 0, "no reserve, no deposits"),
        ];

        for &(min_per_sec, ttl, pct, deposits, expected, desc) in cases {
            let budget = Budget::new(Duration::from_secs(ttl), min_per_sec, pct);
            for _ in 0..deposits {
                budget.deposit();
            }
            let mut count = 0u32;
            while budget.withdraw() {
                count += 1;
                if count > 10_000 {
                    break;
                }
            }
            assert_eq!(count, expected, "{desc}");
        }
    }

    // -- Scope matching (data-driven) --

    #[test]
    fn scope_table() {
        let policy = for_host("example.com".to_string()).into_policy();
        let scope = policy.scope.as_ref().expect("for_host should set a scope");

        let cases: &[(&str, bool, &str)] = &[
            ("https://example.com/test", true, "exact host match"),
            ("https://example.com/a/b/c", true, "deep path on matching host"),
            ("https://other.com/test", false, "different host"),
            ("https://sub.example.com/", false, "subdomain is not exact match"),
            ("http://example.com/", true, "http scheme, same host"),
        ];

        for &(url_str, expected, desc) in cases {
            let url: crate::Url = url_str.parse().unwrap();
            assert_eq!(scope(&url, &http::Method::GET), expected, "{desc}");
        }
    }

    // -- Max retries (data-driven) --

    #[test]
    fn max_retries_table() {
        let cases: &[(u32, &str)] = &[
            (0, "zero means no retries"),
            (1, "one retry"),
            (2, "default value"),
            (5, "custom higher value"),
            (100, "large value"),
        ];

        for &(max, desc) in cases {
            let policy = for_host("x")
                .max_retries_per_request(max)
                .no_budget()
                .into_policy();
            assert_eq!(policy.max_retries(), max, "{desc}");
        }
    }

    // -- Classification (data-driven) --

    #[test]
    fn classify_result_table() {
        // Build a policy scoped to example.com that retries 503s.
        let policy_503 = for_host("example.com".to_string())
            .no_budget()
            .classify_fn(|rr| {
                if rr.status() == Some(http::StatusCode::SERVICE_UNAVAILABLE) {
                    rr.retryable()
                } else {
                    rr.success()
                }
            })
            .into_policy();

        // Policy from never() — should never retry anything.
        let policy_never = never().into_policy();

        // Default policy (protocol NACKs only, unscoped).
        let policy_default = Builder::default().into_policy();

        // Policy with a matching scope but no classify function.
        let policy_no_classify = for_host("example.com".to_string())
            .no_budget()
            .into_policy();

        type RequestResult = Result<crate::Response, crate::Error>;

        let err: RequestResult = Err(crate::Error::builder("test"));

        // A synthetic connection-reset error to exercise the default classifier's
        // Retryable branch.
        let conn_reset_err: RequestResult = Err(crate::Error::request("connection reset")
            .with_source(std::io::Error::from(std::io::ErrorKind::ConnectionReset)));

        let resp_503: RequestResult = Ok(crate::Response::synthetic(
            http::StatusCode::SERVICE_UNAVAILABLE,
            "https://example.com/api",
        ));

        // (policy, url, result, expected_action, desc)
        let cases: &[(&Policy, &str, &RequestResult, Action, &str)] = &[
            (
                &policy_503,
                "https://example.com/api",
                &resp_503,
                Action::Retryable,
                "503-policy: 503 response IS retryable",
            ),
            (
                &policy_503,
                "https://example.com/api",
                &err,
                Action::Success,
                "503-policy: error is not a 503",
            ),
            (
                &policy_503,
                "https://other.com/api",
                &err,
                Action::Success,
                "503-policy: out of scope",
            ),
            (&policy_never, "https://example.com/", &err, Action::Success, "never: always success"),
            (
                &policy_default,
                "https://example.com/",
                &err,
                Action::Success,
                "default: builder error is not a connection reset",
            ),
            (
                &policy_default,
                "https://example.com/",
                &conn_reset_err,
                Action::Retryable,
                "default: connection reset IS retryable",
            ),
            (
                &policy_no_classify,
                "https://example.com/",
                &err,
                Action::Success,
                "no-classify: scope matches but no classify fn → success",
            ),
        ];

        for (policy, url_str, result, expected, desc) in cases {
            let url: crate::Url = url_str.parse().unwrap();
            let action = policy.classify_result(&url, &http::Method::GET, result);
            assert_eq!(action, *expected, "{desc}");
        }
    }

    /// Depositing, sleeping past multiple slots, then withdrawing exercises
    /// the `while remaining > self.slot_duration` loop in `Budget::advance()`.
    #[test]
    fn budget_multi_slot_advance() {
        // ttl=1s → slot_duration=100ms, 10 slots.
        // Deposit, then sleep >2 slots so advance() clears multiple buckets.
        let budget = Budget::new(Duration::from_secs(1), 0, 1.0);

        // Deposit several tokens into the current slot.
        for _ in 0..5 {
            budget.deposit();
        }

        // Sleep 350ms — crosses at least 3 slot boundaries.
        std::thread::sleep(Duration::from_millis(350));

        // The next operation triggers advance(), which must iterate
        // through the elapsed slots clearing them.
        budget.deposit();

        // We should still be able to withdraw: the 5 earlier deposits
        // were committed to a slot (not cleared, they're behind the
        // cursor), plus the fresh deposit.
        let mut count = 0u32;
        while budget.withdraw() {
            count += 1;
            if count > 100 {
                break;
            }
        }
        assert!(count >= 1, "expected at least 1 withdrawal after multi-slot advance, got {count}");
    }

    // -- Debug formatting (data-driven) --

    #[test]
    fn debug_table() {
        let cases: &[(&dyn std::fmt::Debug, &str, &str)] = &[
            (&for_host("example.com"), "Builder", "Builder debug"),
            (&Action::Success, "Success", "Action::Success"),
            (&Action::Retryable, "Retryable", "Action::Retryable"),
            (&Builder::default().into_policy(), "Policy", "Policy debug"),
            (&Budget::new(Duration::from_secs(10), 5, 0.2), "Budget", "Budget debug"),
        ];

        for &(val, needle, desc) in cases {
            let s = format!("{val:?}");
            assert!(s.contains(needle), "{desc}: expected {needle:?} in {s:?}");
        }
    }

    // -- ReqRep accessor coverage --

    #[test]
    fn classify_fn_exercises_accessors() {
        // Build a policy that calls every ReqRep accessor to ensure
        // coverage of method(), uri(), status(), error().
        let policy = for_host("example.com".to_string())
            .no_budget()
            .classify_fn(|rr| {
                let _method = rr.method();
                let _uri = rr.uri();
                let _status = rr.status();
                let _err = rr.error();
                rr.retryable()
            })
            .into_policy();

        let url: crate::Url = "https://example.com/api".parse().unwrap();
        let result: Result<crate::Response, crate::Error> = Err(crate::Error::builder("test"));
        assert_eq!(policy.classify_result(&url, &http::Method::POST, &result), Action::Retryable,);
    }

    // -- Remaining standalone tests --

    #[test]
    fn no_budget() {
        let policy = for_host("x").no_budget().into_policy();
        for _ in 0..100 {
            assert!(policy.can_withdraw());
        }
    }

    #[test]
    fn max_extra_load() {
        // retry_percent=0.5 → deposit=1, withdraw=2
        // reserve = 10*10*2 = 200 → 100 withdrawals
        // 20 deposits → 20 tokens → 10 more withdrawals
        let policy = for_host("x").max_extra_load(0.5).into_policy();
        for _ in 0..20 {
            policy.deposit();
        }
        let mut count = 0;
        while policy.can_withdraw() {
            count += 1;
            if count > 200 {
                break;
            }
        }
        assert_eq!(count, 110, "expected 110 withdrawals, got {count}");
    }

    #[test]
    #[should_panic]
    fn max_extra_load_panics_on_negative() {
        let _ = for_host("x").max_extra_load(-1.0);
    }
}
