fn main() {
    // Emit a single cfg flag so the rest of the crate can write
    // `#[cfg(native_winhttp)]` instead of the verbose
    // `#[cfg(all(windows, not(feature = "always-reqwest")))]`.
    let is_windows = std::env::var("CARGO_CFG_WINDOWS").is_ok();
    let always_reqwest = std::env::var("CARGO_FEATURE_ALWAYS_REQWEST").is_ok();

    if is_windows && !always_reqwest {
        println!("cargo:rustc-cfg=native_winhttp");
    }
}
