//! Thin newtype that redacts a secret from `Debug` output.
//!
//! Wrapping a field in `Redacted<T>` causes it to be redacted from
//! `format!("{:?}", _)`, `dbg!`, and structured-tracing `?value`
//! formatters. The inner value is reachable only through
//! [`Redacted::expose`], which reads as a deliberate audit point at
//! every call site.

/// Wrapper that hides `T` from `Debug` output.
///
/// `PartialEq`, `Eq`, `Hash`, and `Clone` are derived and delegate to
/// the inner `T`, so a `Redacted<String>` participates in any
/// `#[derive]` on the containing struct without special casing.
#[derive(Clone, PartialEq, Eq, Hash)]
pub(crate) struct Redacted<T>(T);

impl<T> Redacted<T> {
    /// Wrap a secret value.
    pub(crate) fn new(value: T) -> Self {
        Self(value)
    }

    /// Borrow the inner secret. The name reads as a deliberate audit
    /// point at every call site (mirrors `secrecy::ExposeSecret`).
    pub(crate) fn expose(&self) -> &T {
        &self.0
    }
}

impl<T> std::fmt::Debug for Redacted<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("\"<redacted>\"")
    }
}

// No `Display` impl by design: secrets must not format via `{}`.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_output_table() {
        // Verifies Redacted's Debug is leak-proof through every wrapping
        // pattern actually used in this crate (bare, Option, tuple) and
        // that the Some/None shape of the Option is preserved -- that
        // shape is the reason we wrap the value rather than the Option.
        //
        // (label, formatted, expected_exact, must_not_contain)
        type TestCase<'a> = (&'a str, String, &'a str, &'a str);
        let cases: Vec<TestCase<'_>> = vec![
            (
                "bare",
                format!("{:?}", Redacted::new(String::from("s3cret"))),
                "\"<redacted>\"",
                "s3cret",
            ),
            (
                "Some(Redacted)",
                format!("{:?}", Some(Redacted::new(String::from("p@55w0rd")))),
                "Some(\"<redacted>\")",
                "p@55w0rd",
            ),
            (
                "None",
                format!("{:?}", None::<Redacted<String>>),
                "None",
                // No secret to leak; assert the placeholder doesn't
                // accidentally show up where there is no value.
                "<redacted>",
            ),
            (
                "tuple (username, password)",
                format!("{:?}", ("alice".to_owned(), Redacted::new(String::from("hunter2"))),),
                "(\"alice\", \"<redacted>\")",
                "hunter2",
            ),
        ];

        for (label, formatted, expected, forbidden) in &cases {
            assert_eq!(formatted, expected, "{label}: unexpected Debug output");
            assert!(
                !formatted.contains(forbidden),
                "{label}: leaked forbidden substring {forbidden:?} in {formatted}"
            );
        }
    }

    #[test]
    fn debug_inside_struct_propagates_via_derive() {
        // Confirms a containing struct can `#[derive(Debug)]` and
        // still be leak-proof for the wrapped field.
        #[derive(Debug)]
        #[expect(
            dead_code,
            reason = "fields only read via the derived Debug under test"
        )]
        struct Creds {
            user: String,
            pass: Redacted<String>,
        }
        let c = Creds {
            user: "alice".into(),
            pass: Redacted::new("s3cret".into()),
        };
        let s = format!("{c:?}");
        assert!(!s.contains("s3cret"), "leak via derived Debug: {s}");
        assert!(s.contains("alice"), "username should remain visible: {s}");
        assert!(s.contains("<redacted>"));
    }

    #[test]
    fn expose_returns_inner() {
        let r = Redacted::new(42_u32);
        assert_eq!(*r.expose(), 42);
    }

    #[test]
    fn equality_and_clone_delegate_to_inner() {
        let a = Redacted::new("x".to_owned());
        let b = a.clone();
        assert_eq!(a, b);
        let c = Redacted::new("y".to_owned());
        assert_ne!(a, c);
    }

    #[test]
    fn hash_delegates_to_inner() {
        use std::collections::HashSet;
        let mut set: HashSet<Redacted<String>> = HashSet::new();
        set.insert(Redacted::new("a".into()));
        set.insert(Redacted::new("a".into()));
        set.insert(Redacted::new("b".into()));
        assert_eq!(set.len(), 2, "Hash must delegate to inner");
    }
}
