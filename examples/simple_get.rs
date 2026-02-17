//! Simple GET requests demonstrating core wrest features.
//!
//! Hits the public **JSONPlaceholder** API (<https://jsonplaceholder.typicode.com>)
//! to show:
//!
//! - basic GET -> `text()`
//! - GET -> typed `json::<T>()`
//! - `error_for_status()`
//! - response metadata (status, headers, content-length)
//!
//! Run with:
//! ```text
//! cargo run --example simple_get --features json
//! ```

use serde::Deserialize;
use std::time::Duration;

/// A single todo item from JSONPlaceholder.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[expect(dead_code)]
struct Todo {
    user_id: u32,
    id: u32,
    title: String,
    completed: bool,
}

/// A post from JSONPlaceholder.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Post {
    user_id: u32,
    id: u32,
    title: String,
    #[expect(dead_code)]
    body: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // ---------------------------------------------------------------
    // 1. One-shot GET with the free function -- returns raw text
    // ---------------------------------------------------------------
    println!("=== 1. wrest::get() -> text() ===\n");

    let text = wrest::get("https://jsonplaceholder.typicode.com/todos/1")
        .await?
        .text()
        .await?;
    println!("{text}\n");

    // ---------------------------------------------------------------
    // 2. Build a reusable Client, GET a typed JSON response
    // ---------------------------------------------------------------
    println!("=== 2. Client::get() -> json::<Todo>() ===\n");

    let client = wrest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()?;

    let todo: Todo = client
        .get("https://jsonplaceholder.typicode.com/todos/7")
        .send()
        .await?
        .json()
        .await?;
    println!("{todo:#?}\n");

    // ---------------------------------------------------------------
    // 3. Response metadata -- status, headers, content-length
    // ---------------------------------------------------------------
    println!("=== 3. Response metadata ===\n");

    let resp = client
        .get("https://jsonplaceholder.typicode.com/posts/1")
        .send()
        .await?;

    println!("Status:         {}", resp.status());
    println!("Version:        {:?}", resp.version());
    println!("Content-Length: {:?}", resp.content_length());
    println!("Content-Type:   {:?}", resp.headers().get("content-type"));
    println!();

    let post: Post = resp.json().await?;
    println!("Post #{}: {}\n", post.id, post.title);

    // ---------------------------------------------------------------
    // 4. error_for_status() -- turn 4xx/5xx into Err
    // ---------------------------------------------------------------
    println!("=== 4. error_for_status() on 404 ===\n");

    let result = client
        .get("https://jsonplaceholder.typicode.com/posts/99999")
        .send()
        .await?
        .error_for_status();

    match result {
        Ok(_) => println!("Unexpected success!"),
        Err(e) => {
            println!("Got expected error: {e}");
            println!("  is_status(): {}", e.is_status());
            println!("  status():    {:?}", e.status());
        }
    }
    println!();

    // ---------------------------------------------------------------
    // 5. Fetch a list of posts (first 5)
    // ---------------------------------------------------------------
    println!("=== 5. GET a list of Posts ===\n");

    let posts: Vec<Post> = client
        .get("https://jsonplaceholder.typicode.com/posts")
        .send()
        .await?
        .json()
        .await?;

    for post in posts.iter().take(5) {
        println!("  [{}] (user {}) {}", post.id, post.user_id, post.title);
    }
    println!("  ... and {} more\n", posts.len() - 5);

    println!("Done!");
    Ok(())
}
