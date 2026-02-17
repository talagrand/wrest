//! Live Hacker News ticker.
//!
//! First fetches and displays the current top 10 stories, then polls for
//! newly posted items and prints comments and stories as they appear in
//! real time. Runs for 60 seconds then exits.
//!
//! Showcases:
//! - Concurrent fan-out with `futures_util::future::join_all`
//! - `Response::json()` with `#[serde(default)]` for optional fields
//! - Polling loop with `futures_timer::Delay`
//! - Filtering and formatting live data
//! - Graceful timeout with a wall-clock deadline
//!
//! API docs: <https://github.com/HackerNews/API>
//!
//! Run with:
//! ```text
//! cargo run --example hn_live --features json
//! ```

use serde::Deserialize;
use std::time::{Duration, Instant};

const API_BASE: &str = "https://hacker-news.firebaseio.com/v0";
const POLL_INTERVAL: Duration = Duration::from_secs(5);
const RUN_DURATION: Duration = Duration::from_secs(60);
/// How many items to fetch per batch (avoid hammering the API on first run).
const MAX_BATCH: u64 = 20;

/// A Hacker News item (story, comment, job, poll, etc.).
///
/// Most fields are optional -- a comment has no `title` or `url`, a job has
/// no `descendants`, etc.
#[derive(Debug, Deserialize)]
struct Item {
    #[expect(dead_code)]
    id: u64,
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    score: Option<u32>,
    #[serde(default)]
    by: Option<String>,
    #[serde(default)]
    text: Option<String>,
    #[serde(default)]
    parent: Option<u64>,
    #[serde(default)]
    descendants: Option<u32>,
    #[serde(rename = "type", default)]
    item_type: Option<String>,
}

/// Fetch a single item by ID.
async fn fetch_item(client: &wrest::Client, id: u64) -> wrest::Result<Item> {
    client
        .get(format!("{API_BASE}/item/{id}.json"))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await
}

/// Strip HTML tags for a rough plain-text preview.
fn strip_html(html: &str) -> String {
    let mut out = String::with_capacity(html.len());
    let mut in_tag = false;
    for ch in html.chars() {
        match ch {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ if !in_tag => out.push(ch),
            _ => {}
        }
    }
    // Decode common HTML entities.
    out.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#x27;", "'")
        .replace("&#x2F;", "/")
}

/// Truncate a string to `max` chars, appending "…" if it was longer.
fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_owned()
    } else {
        let mut t: String = s.chars().take(max).collect();
        t.push('…');
        t
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = wrest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()?;

    // ===============================================================
    // Part 1: Current top 10 stories
    // ===============================================================
    println!("=== Top stories on Hacker News ===\n");

    let start = Instant::now();

    let all_ids: Vec<u64> = client
        .get(format!("{API_BASE}/topstories.json"))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    let count = all_ids.len().min(10);
    let top_ids = all_ids.get(..count).unwrap_or(&all_ids);
    println!("  {} total stories, fetching top {count}...\n", all_ids.len());

    // Fan out -- fetch all 10 concurrently.
    let futures: Vec<_> = top_ids
        .iter()
        .map(|&id| {
            let c = client.clone();
            async move { fetch_item(&c, id).await }
        })
        .collect();

    let items = futures_util::future::join_all(futures).await;

    for (i, result) in items.into_iter().enumerate() {
        match result {
            Ok(item) => {
                let title = item.title.as_deref().unwrap_or("(no title)");
                let by = item.by.as_deref().unwrap_or("?");
                let score = item.score.unwrap_or(0);
                let comments = item.descendants.unwrap_or(0);
                let url = item.url.as_deref().unwrap_or("(self post)");
                println!("  {:>2}. {title}", i + 1);
                println!("      {score} pts by {by} | {comments} comments");
                println!("      {url}");
            }
            Err(e) => println!("  {:>2}. Error: {e}", i + 1),
        }
    }

    println!("\n  Fetched in {} ms\n", start.elapsed().as_millis());

    // ===============================================================
    // Part 2: Live ticker -- new comments AND stories as they appear
    // ===============================================================

    // Seed the cursor at the current max item ID.
    let mut cursor: u64 = client
        .get(format!("{API_BASE}/maxitem.json"))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    println!(
        "=== 🔴 Live ticker (starting at item {cursor}, running for {}s) ===\n",
        RUN_DURATION.as_secs()
    );

    let deadline = Instant::now() + RUN_DURATION;
    let mut new_comments = 0u32;
    let mut new_stories = 0u32;

    loop {
        if Instant::now() >= deadline {
            break;
        }

        // Wait before polling.
        futures_timer::Delay::new(POLL_INTERVAL).await;

        // Check for new items.
        let new_max: u64 = client
            .get(format!("{API_BASE}/maxitem.json"))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        if new_max <= cursor {
            continue;
        }

        // Clamp to MAX_BATCH so we don't fire hundreds of requests.
        let start = if new_max - cursor > MAX_BATCH {
            new_max - MAX_BATCH
        } else {
            cursor + 1
        };

        let ids: Vec<u64> = (start..=new_max).collect();

        // Brief pause so Firebase can finish writing item fields.
        futures_timer::Delay::new(Duration::from_secs(2)).await;

        // Fetch all new items concurrently.
        let futures: Vec<_> = ids
            .iter()
            .map(|&id| {
                let c = client.clone();
                async move { fetch_item(&c, id).await }
            })
            .collect();

        let results = futures_util::future::join_all(futures).await;

        for result in results {
            let item = match result {
                Ok(item) => item,
                Err(_) => continue, // Deleted or unavailable item.
            };

            match item.item_type.as_deref() {
                Some("comment") => {
                    let by = item.by.as_deref().unwrap_or("?");
                    let text = item.text.as_deref().map(strip_html).unwrap_or_default();
                    let preview = truncate(&text, 120);
                    let parent = item.parent.unwrap_or(0);

                    new_comments += 1;
                    println!("  💬 {by} (on item {parent}):");
                    println!("     {preview}\n");
                }
                Some("story") | Some("job") => {
                    // Skip items that Firebase hasn't fully written yet.
                    let Some(title) = item.title.as_deref() else {
                        continue;
                    };
                    let by = item.by.as_deref().unwrap_or("?");
                    let url = item.url.as_deref().unwrap_or("(self post)");

                    new_stories += 1;
                    println!("  📰 NEW: {title}");
                    println!("     by {by} | {url}\n");
                }
                _ => {} // polls, pollopts, etc. -- skip
            }
        }

        cursor = new_max;
    }

    println!("---");
    println!(
        "Done! Saw {new_comments} comments and {new_stories} stories in {}s.",
        RUN_DURATION.as_secs()
    );
    Ok(())
}
