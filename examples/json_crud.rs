//! Full CRUD operations with JSON bodies.
//!
//! Demonstrates POST / PUT / PATCH / DELETE against the public
//! **JSONPlaceholder** API (<https://jsonplaceholder.typicode.com>).
//!
//! JSONPlaceholder accepts writes and returns realistic responses, but
//! nothing is actually persisted -- perfect for exercising HTTP verbs.
//!
//! Showcases:
//! - `RequestBuilder::json()` -- serialize a struct into a JSON body
//! - `Response::json::<T>()` -- deserialize the response
//! - `Client::post()`, `put()`, `patch()`, `delete()`
//! - `Response::status()` / `error_for_status()`
//! - Custom per-request headers
//!
//! Run with:
//! ```text
//! cargo run --example json_crud --features json
//! ```

use serde::{Deserialize, Serialize};
use std::time::Duration;

/// A post resource (both request and response).
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Post {
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<u32>,
    user_id: u32,
    title: String,
    body: String,
}

/// The JSONPlaceholder response for DELETE (empty JSON `{}`).
#[derive(Debug, Deserialize)]
struct Empty {}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = wrest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()?;

    let base = "https://jsonplaceholder.typicode.com/posts";

    // ---------------------------------------------------------------
    // 1. CREATE -- POST /posts
    // ---------------------------------------------------------------
    println!("=== 1. POST (create) ===\n");

    let new_post = Post {
        id: None,
        user_id: 42,
        title: "Hello from wrest".into(),
        body: "This post was created by the wrest json_crud example.".into(),
    };

    let created: Post = client
        .post(base)
        .json(&new_post)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    println!("Created: {created:#?}");
    println!("  -> Server assigned id = {:?}\n", created.id);

    // ---------------------------------------------------------------
    // 2. READ -- GET /posts/{id}
    // ---------------------------------------------------------------
    println!("=== 2. GET (read) ===\n");

    let fetched: Post = client
        .get(format!("{base}/1"))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    println!("Fetched: {fetched:#?}\n");

    // ---------------------------------------------------------------
    // 3. UPDATE (full) -- PUT /posts/{id}
    // ---------------------------------------------------------------
    println!("=== 3. PUT (full update) ===\n");

    let updated_post = Post {
        id: Some(1),
        user_id: 1,
        title: "Updated title via PUT".into(),
        body: "Completely replaced body.".into(),
    };

    let resp = client
        .put(format!("{base}/1"))
        .header("X-Custom-Header", "wrest-example")
        .json(&updated_post)
        .send()
        .await?
        .error_for_status()?;

    println!("PUT status: {}", resp.status());
    let updated: Post = resp.json().await?;
    println!("Updated: {updated:#?}\n");

    // ---------------------------------------------------------------
    // 4. UPDATE (partial) -- PATCH /posts/{id}
    // ---------------------------------------------------------------
    println!("=== 4. PATCH (partial update) ===\n");

    // Only send the fields we want to change.
    #[derive(Serialize)]
    struct PatchBody {
        title: String,
    }

    let patch = PatchBody {
        title: "Patched title only".into(),
    };

    let resp = client
        .patch(format!("{base}/1"))
        .json(&patch)
        .send()
        .await?
        .error_for_status()?;

    println!("PATCH status: {}", resp.status());
    let patched: Post = resp.json().await?;
    println!("Patched: {patched:#?}\n");

    // ---------------------------------------------------------------
    // 5. DELETE -- DELETE /posts/{id}
    // ---------------------------------------------------------------
    println!("=== 5. DELETE ===\n");

    let resp = client
        .delete(format!("{base}/1"))
        .send()
        .await?
        .error_for_status()?;

    println!("DELETE status: {} (expect 200)", resp.status());
    let _empty: Empty = resp.json().await?;
    println!("Response body: {{}}\n");

    println!("Done -- all CRUD operations succeeded!");
    Ok(())
}
