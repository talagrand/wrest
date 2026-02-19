//! Redirect policy.
//!
//! Provides a [`Policy`](crate::redirect::Policy) type that controls how the client handles
//! HTTP redirects, matching the
//! [`reqwest::redirect::Policy`](https://docs.rs/reqwest/latest/reqwest/redirect/struct.Policy.html)
//! API surface.

/// A redirect policy.
///
/// Controls the behaviour of HTTP redirects. WinHTTP handles redirects
/// automatically; this type configures its redirect limit.
///
/// # Example
///
/// ```rust,ignore
/// use wrest::redirect;
///
/// let client = wrest::Client::builder()
///     .redirect(redirect::Policy::limited(5))
///     .build()?;
/// ```
#[derive(Debug, Clone)]
pub struct Policy {
    pub(crate) inner: PolicyInner,
}

#[derive(Debug, Clone)]
pub(crate) enum PolicyInner {
    /// Follow redirects (up to a maximum count).
    Limited(u32),
    /// Never follow redirects.
    None,
}

impl Policy {
    /// Follow redirects up to a maximum count.
    ///
    /// The default policy is `limited(10)`, matching reqwest.
    pub fn limited(max: usize) -> Self {
        // Saturate to u32::MAX rather than silently truncating.
        // In practice values above a few hundred are meaningless.
        let clamped = u32::try_from(max).unwrap_or(u32::MAX);
        Self {
            inner: PolicyInner::Limited(clamped),
        }
    }

    /// Never follow redirects.
    pub fn none() -> Self {
        Self {
            inner: PolicyInner::None,
        }
    }
}

impl Default for Policy {
    /// Create the default redirect policy (follow up to 10 redirects).
    ///
    /// This is what reqwest uses by default.
    fn default() -> Self {
        Self::limited(10)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_construction() {
        // (label, policy, expected_inner_match)
        type TestCase<'a> = (&'a str, Policy, fn(&PolicyInner) -> bool);
        let cases: Vec<TestCase<'_>> = vec![
            ("limited(5)", Policy::limited(5), |p| matches!(p, PolicyInner::Limited(5))),
            ("none", Policy::none(), |p| matches!(p, PolicyInner::None)),
            ("default", Policy::default(), |p| matches!(p, PolicyInner::Limited(10))),
            ("limited(0)", Policy::limited(0), |p| matches!(p, PolicyInner::Limited(0))),
            ("limited(usize::MAX) saturates", Policy::limited(usize::MAX), |p| {
                matches!(p, PolicyInner::Limited(u32::MAX))
            }),
        ];

        for (label, policy, check) in &cases {
            assert!(check(&policy.inner), "Policy::{label}: unexpected inner");
        }
    }

    #[test]
    fn policy_clone() {
        let p = Policy::limited(3);
        let p2 = p.clone();
        assert!(matches!(p.inner, PolicyInner::Limited(3)));
        assert!(matches!(p2.inner, PolicyInner::Limited(3)));
    }

    #[test]
    fn policy_debug() {
        let p = Policy::none();
        let s = format!("{p:?}");
        assert!(s.contains("None"));
    }
}
