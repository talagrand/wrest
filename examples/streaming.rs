//! Streaming download with progress reporting.
//!
//! Downloads a file using `Response::chunk()` to read the body
//! incrementally, printing byte-count progress along the way.
//!
//! Uses a public test file from httpbin.org.
//!
//! Showcases:
//! - `Response::content_length()` -- read the expected size
//! - `Response::chunk()` -- incremental body consumption
//! - Building a `Vec<u8>` from streamed chunks
//! - `ClientBuilder::connect_timeout()` / `timeout()`
//!
//! Run with:
//! ```text
//! cargo run --example streaming
//! ```

use std::time::{Duration, Instant};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = wrest::Client::builder()
        .timeout(Duration::from_secs(60))
        .connect_timeout(Duration::from_secs(10))
        .build()?;

    // httpbin's /bytes/{n} endpoint generates n random bytes.
    let size = 512 * 1024; // 512 KB
    let url = format!("https://httpbin.org/bytes/{size}");

    println!("=== Streaming download: {size} bytes from httpbin.org ===\n");

    let start = Instant::now();

    let mut resp = client.get(&url).send().await?.error_for_status()?;

    let expected = resp.content_length();
    println!("  Content-Length: {expected:?}");
    println!("  Status:         {}", resp.status());
    println!("  Version:        {:?}", resp.version());
    println!();

    // Read the body chunk-by-chunk.
    let mut downloaded = 0u64;
    let mut body = Vec::new();
    let mut chunk_count = 0u32;

    while let Some(chunk) = resp.chunk().await? {
        chunk_count += 1;
        downloaded += chunk.len() as u64;
        body.extend_from_slice(&chunk);

        // Print progress every chunk.
        if let Some(total) = expected {
            let pct = (downloaded as f64 / total as f64) * 100.0;
            print!(
                "\r  Chunk {chunk_count:>3}: +{:>6} bytes  ({downloaded:>8} / {total} -- {pct:5.1}%)",
                chunk.len()
            );
        } else {
            print!(
                "\r  Chunk {chunk_count:>3}: +{:>6} bytes  ({downloaded:>8} total)",
                chunk.len()
            );
        }
    }

    let elapsed = start.elapsed();
    println!("\n");
    println!("  Download complete!");
    println!("  Total bytes:  {downloaded}");
    println!("  Chunks:       {chunk_count}");
    println!("  Elapsed:      {elapsed:.2?}");

    if elapsed.as_millis() > 0 {
        let kbps = (downloaded as f64 / 1024.0) / elapsed.as_secs_f64();
        println!("  Throughput:   {kbps:.1} KB/s");
    }

    // Verify we got what we expected.
    if let Some(total) = expected {
        assert_eq!(
            downloaded, total,
            "Downloaded size mismatch: got {downloaded}, expected {total}"
        );
        println!("  [ok] Size matches Content-Length");
    }

    println!("\nDone!");
    Ok(())
}
