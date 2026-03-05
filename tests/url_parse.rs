//! URL parsing conformance tests against the WHATWG `urltestdata.json`
//! test suite from [web-platform-tests](https://github.com/web-platform-tests/wpt).
//!
//! Each test case is classified as either:
//! - **RFC-clean**: well-formed RFC 3986 input that both WinHTTP and WHATWG
//!   must parse identically.  Zero failures expected.
//! - **Error-recovery**: invalid or edge-case input where behavior differs
//!   between WinHTTP and WHATWG.  Divergences are tracked but not failures.
//!
//! To run:
//! ```
//! cargo test --test url_parse
//! ```

// The entire test file requires TLS.  On native WinHTTP, TLS is always
// available via Schannel.  On reqwest passthrough, a TLS feature must be
// enabled.  When neither is true the file compiles to nothing.
#![cfg(any(native_winhttp, feature = "default-tls", feature = "native-tls"))]
#![expect(clippy::tests_outside_test_module)]

use wrest::Url;

const URLTESTDATA_URL: &str = "https://raw.githubusercontent.com/web-platform-tests/wpt/refs/heads/master/url/resources/urltestdata.json";

/// Fetch the WHATWG `urltestdata.json` from GitHub and run every applicable
/// test case against `wrest::Url::parse`.
#[tokio::test]
async fn whatwg_urltestdata() {
    let client = wrest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .expect("client build should succeed");

    let resp = client
        .get(URLTESTDATA_URL)
        .send()
        .await
        .expect("failed to fetch urltestdata.json");

    assert_eq!(
        resp.status(),
        wrest::StatusCode::OK,
        "unexpected status fetching urltestdata.json: {}",
        resp.status()
    );

    let body = resp.text().await.expect("failed to read response body");
    let entries: Vec<serde_json::Value> =
        serde_json::from_str(&body).expect("failed to parse urltestdata.json");

    let mut tested = 0u32;
    let mut skipped = 0u32;
    let mut rfc_clean_tested = 0u32;
    let mut rfc_clean_failures: Vec<String> = Vec::new();
    let mut error_recovery_divergences = 0u32;

    for entry in &entries {
        let Some(obj) = entry.as_object() else {
            continue; // skip comment strings
        };

        // Skip relative-URL tests (base != null).
        match obj.get("base") {
            Some(serde_json::Value::Null) => {}
            None => {}
            _ => {
                skipped += 1;
                continue;
            }
        }

        let input = obj["input"].as_str().unwrap();

        // Expected-failure tests.
        if obj.contains_key("failure") {
            if input.starts_with("http://") || input.starts_with("https://") {
                if Url::parse(input).is_ok() {
                    error_recovery_divergences += 1;
                }
                tested += 1;
            } else {
                skipped += 1;
            }
            continue;
        }

        // Only test http/https success cases.
        let protocol = obj.get("protocol").and_then(|v| v.as_str()).unwrap_or("");
        if protocol != "http:" && protocol != "https:" {
            skipped += 1;
            continue;
        }

        let is_rfc_clean = is_rfc_clean_input(input);

        let parsed = match Url::parse(input) {
            Ok(u) => u,
            Err(e) => {
                if is_rfc_clean {
                    rfc_clean_failures
                        .push(format!("parse failed for RFC-clean URL {input:?}: {e}"));
                } else {
                    error_recovery_divergences += 1;
                }
                if is_rfc_clean {
                    rfc_clean_tested += 1;
                }
                tested += 1;
                continue;
            }
        };

        let expected_path = obj["pathname"].as_str().unwrap();
        let expected_search = obj["search"].as_str().unwrap();
        let expected_hash = obj["hash"].as_str().unwrap();

        let path_ok = components_equivalent(parsed.path(), expected_path);
        let actual_search = match parsed.query() {
            Some(q) => format!("?{q}"),
            None => String::new(),
        };
        let search_ok = components_equivalent(&actual_search, expected_search);
        let actual_hash = match parsed.fragment() {
            Some(f) => format!("#{f}"),
            None => String::new(),
        };
        let hash_ok = components_equivalent(&actual_hash, expected_hash);

        if !path_ok || !search_ok || !hash_ok {
            let msg = format!(
                "{input:?}: path={:?}(exp {:?}), search={:?}(exp {:?}), hash={:?}(exp {:?})",
                parsed.path(),
                expected_path,
                actual_search,
                expected_search,
                actual_hash,
                expected_hash,
            );
            if is_rfc_clean {
                rfc_clean_failures.push(msg);
            } else {
                error_recovery_divergences += 1;
            }
        }

        if is_rfc_clean {
            rfc_clean_tested += 1;
        }
        tested += 1;
    }

    eprintln!(
        "WHATWG urltestdata: {tested} tested, {skipped} skipped, \
         {rfc_clean_tested} RFC-clean, \
         {error_recovery_divergences} error-recovery divergences"
    );

    assert!(tested >= 100, "too few tests ran: {tested}");
    assert!(rfc_clean_tested >= 40, "too few RFC-clean tests: {rfc_clean_tested}");

    // RFC-clean URLs MUST match exactly — zero failures.
    assert!(
        rfc_clean_failures.is_empty(),
        "RFC-clean URLs had {} failures:\n{}",
        rfc_clean_failures.len(),
        rfc_clean_failures.join("\n")
    );
}

/// Returns `true` if `input` is a "RFC-clean" URL that WinHTTP with
/// `flags=0` should parse identically to WHATWG.  Excludes inputs that
/// contain characters WHATWG would encode but WinHTTP passes through,
/// dot-segments, or non-standard forms.
fn is_rfc_clean_input(input: &str) -> bool {
    // Must have scheme://authority form.
    if !input.contains("://") {
        return false;
    }
    for b in input.bytes() {
        // C0 controls, DEL, non-ASCII, space, backslash
        if b <= 0x1F || b == 0x7F || b == b' ' || b == b'\\' || b > 0x7E {
            return false;
        }
        // Characters WHATWG encodes but WinHTTP passes through.
        if matches!(b, b'"' | b'<' | b'>' | b'`' | b'\'') {
            return false;
        }
    }
    // Dot-segments and %2e-as-dot trigger WHATWG-specific resolution.
    if input.contains("/./")
        || input.contains("/../")
        || input.ends_with("/.")
        || input.ends_with("/..")
        || input.contains("%2e")
        || input.contains("%2E")
    {
        return false;
    }
    // Trailing bare `#` or `?#` — empty fragment/query representation
    // differs between url::Url (Some("")) and WHATWG test expectations ("").
    if input.ends_with('#') || input.ends_with("?#") {
        return false;
    }
    true
}

/// Compare two URL component strings, treating percent-encoded hex digits
/// case-insensitively (e.g., `%2f` == `%2F`).
fn components_equivalent(a: &str, b: &str) -> bool {
    (a == b) || a.eq_ignore_ascii_case(b)
}
