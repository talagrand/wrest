// Native WinHTTP backend

/// A lightweight executor handle.
///
/// On the native backend this is a zero-sized wrapper around
/// [`futures::executor::block_on`]; on the reqwest backend it is
/// [`tokio::runtime::Runtime`]. Use [`runtime()`] to construct one.
#[cfg(native_winhttp)]
#[derive(Debug)]
pub struct Runtime;

#[cfg(native_winhttp)]
impl Runtime {
    /// Run a future to completion on this runtime.
    pub fn block_on<F: std::future::Future<Output = T>, T>(&self, f: F) -> T {
        futures_executor::block_on(f)
    }
}

/// On the reqwest backend, `Runtime` is [`tokio::runtime::Runtime`] directly.
#[cfg(not(native_winhttp))]
pub type Runtime = tokio::runtime::Runtime;

/// Create a new [`Runtime`] (native backend -- infallible).
#[cfg(native_winhttp)]
pub fn runtime() -> std::io::Result<Runtime> {
    Ok(Runtime)
}

/// Create a new [`Runtime`] (reqwest backend -- wraps a single-threaded tokio runtime).
///
/// # Errors
///
/// Returns [`std::io::Error`] if the tokio runtime cannot be created.
#[cfg(not(native_winhttp))]
pub fn runtime() -> std::io::Result<Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
}

/// Create a [`Runtime`] and run `f` to completion on it.
///
/// # Errors
///
/// Returns [`std::io::Error`] if the runtime cannot be created
/// (reqwest backend only).
pub fn block_on<F: std::future::Future<Output = T>, T>(f: F) -> std::io::Result<T> {
    let rt = runtime()?;
    Ok(rt.block_on(f))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_lifecycle() {
        // runtime() creates successfully
        let rt = runtime().expect("runtime() should succeed");

        // Debug impl works
        let s = format!("{rt:?}");
        assert!(!s.is_empty(), "Debug output should not be empty");

        // block_on via the runtime object
        let val = rt.block_on(async { 7 + 3 });
        assert_eq!(val, 10);

        // reuse for multiple futures
        let a = rt.block_on(async { 1 });
        let b = rt.block_on(async { 2 });
        let c = rt.block_on(async { 3 });
        assert_eq!(a + b + c, 6);

        // free-standing block_on
        let val = block_on(async { 42 }).expect("runtime creation should succeed");
        assert_eq!(val, 42);
    }
}
