//! Concurrent requests with async fan-out.
//!
//! Fires multiple GET requests in parallel using `futures_util::future::join_all`
//! and collects the results.  Demonstrates that `wrest::Client` is cheaply
//! cloneable and safe to share across concurrent tasks.
//!
//! Showcases:
//! - `Client::clone()` (shared WinHTTP session handle)
//! - `query()` -- add query parameters
//! - `futures_util::future::join_all` for async fan-out
//! - Measuring wall-clock time for concurrent vs sequential
//!
//! Run with:
//! ```text
//! cargo run --example concurrent --features json,query
//! ```

use serde::Deserialize;
use std::time::{Duration, Instant};

/// A comment from JSONPlaceholder.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Comment {
    #[expect(dead_code)]
    post_id: u32,
    #[expect(dead_code)]
    id: u32,
    name: String,
    #[expect(dead_code)]
    email: String,
    #[expect(dead_code)]
    body: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = wrest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()?;

    let post_ids: Vec<u32> = (1..=10).collect();

    // ---------------------------------------------------------------
    // 1. Sequential -- one request at a time
    // ---------------------------------------------------------------
    println!("=== 1. Sequential: fetch comments for posts 1-10 ===\n");

    let start = Instant::now();
    let mut total_comments = 0u32;

    for &post_id in &post_ids {
        let comments: Vec<Comment> = client
            .get("https://jsonplaceholder.typicode.com/comments")
            .query(&[("postId", post_id)])
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        total_comments += comments.len() as u32;
        println!(
            "  Post {post_id:>2}: {} comments (first: {:?})",
            comments.len(),
            comments.first().map(|c| &c.name)
        );
    }

    let sequential_ms = start.elapsed().as_millis();
    println!("\n  Total: {total_comments} comments in {sequential_ms} ms\n");

    // ---------------------------------------------------------------
    // 2. Concurrent -- all requests in flight at once
    // ---------------------------------------------------------------
    println!("=== 2. Concurrent: same requests, all at once ===\n");

    let start = Instant::now();

    // Build a Vec of futures. Each one captures a clone of the client.
    let futures: Vec<_> = post_ids
        .iter()
        .map(|&post_id| {
            let c = client.clone();
            async move {
                let comments: Vec<Comment> = c
                    .get("https://jsonplaceholder.typicode.com/comments")
                    .query(&[("postId", post_id)])
                    .send()
                    .await?
                    .error_for_status()?
                    .json()
                    .await?;
                Ok::<(u32, Vec<Comment>), wrest::Error>((post_id, comments))
            }
        })
        .collect();

    let results = futures_util::future::join_all(futures).await;

    let mut total_comments = 0u32;
    for result in &results {
        match result {
            Ok((post_id, comments)) => {
                total_comments += comments.len() as u32;
                println!(
                    "  Post {post_id:>2}: {} comments (first: {:?})",
                    comments.len(),
                    comments.first().map(|c| &c.name)
                );
            }
            Err(e) => println!("  Error: {e}"),
        }
    }

    let concurrent_ms = start.elapsed().as_millis();
    println!("\n  Total: {total_comments} comments in {concurrent_ms} ms");

    if sequential_ms > 0 {
        let speedup = sequential_ms as f64 / concurrent_ms.max(1) as f64;
        println!("  Speedup: {speedup:.1}x vs sequential\n");
    }

    println!("Done!");
    Ok(())
}
