//! Query the GitHub public REST API.
//!
//! No authentication required -- uses unauthenticated endpoints that are
//! rate-limited to 60 requests/hour per IP.
//!
//! Showcases:
//! - `ClientBuilder::default_headers()` -- set `Accept` and `User-Agent`
//! - `RequestBuilder::query()` -- add typed query parameters
//! - `Response::headers()` -- read rate-limit and pagination headers
//! - Typed JSON deserialization of real-world API responses
//! - Error handling for rate-limiting (HTTP 403)
//!
//! Run with:
//! ```text
//! cargo run --example github_api --features json,query
//! ```

use serde::Deserialize;
use std::time::Duration;
use wrest::header;

/// A GitHub repository (subset of fields).
#[derive(Debug, Deserialize)]
struct Repo {
    full_name: String,
    description: Option<String>,
    stargazers_count: u32,
    language: Option<String>,
    html_url: String,
}

/// A GitHub user (subset of fields).
#[derive(Debug, Deserialize)]
struct User {
    login: String,
    id: u64,
    html_url: String,
    #[serde(rename = "type")]
    user_type: String,
    public_repos: Option<u32>,
}

/// GitHub search response wrapper.
#[derive(Debug, Deserialize)]
struct SearchResult<T> {
    total_count: u32,
    items: Vec<T>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Build a client with default headers required by GitHub.
    let mut default_headers = wrest::header::HeaderMap::new();
    default_headers.insert(header::ACCEPT, "application/vnd.github+json".parse()?);
    // GitHub requires a User-Agent header.
    default_headers.insert(header::USER_AGENT, "wrest-example/0.1".parse()?);
    // Opt into the latest API version.
    default_headers
        .insert("X-GitHub-Api-Version".parse::<header::HeaderName>()?, "2022-11-28".parse()?);

    let client = wrest::Client::builder()
        .timeout(Duration::from_secs(30))
        .default_headers(default_headers)
        .build()?;

    // ---------------------------------------------------------------
    // 1. Look up a specific user
    // ---------------------------------------------------------------
    println!("=== 1. GET /users/{{login}} ===\n");

    let user: User = client
        .get("https://api.github.com/users/talagrand")
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    println!("  Login:        {}", user.login);
    println!("  ID:           {}", user.id);
    println!("  Type:         {}", user.user_type);
    println!("  Public repos: {:?}", user.public_repos);
    println!("  Profile:      {}\n", user.html_url);

    // ---------------------------------------------------------------
    // 2. Search repositories -- top Rust projects by stars
    // ---------------------------------------------------------------
    println!("=== 2. Search repos: top Rust projects by stars ===\n");

    let resp = client
        .get("https://api.github.com/search/repositories")
        .query(&[("q", "language:rust"), ("sort", "stars"), ("order", "desc"), ("per_page", "10")])
        .send()
        .await?;

    // Show rate-limit headers before consuming the body.
    println!("  Rate limit:     {:?}", resp.headers().get("x-ratelimit-limit"));
    println!("  Rate remaining: {:?}", resp.headers().get("x-ratelimit-remaining"));
    println!();

    let resp = resp.error_for_status()?;
    let search: SearchResult<Repo> = resp.json().await?;

    println!("  Found {} repos, showing top {}:\n", search.total_count, search.items.len());

    for (i, repo) in search.items.iter().enumerate() {
        println!(
            "  {:>2}. {} ⭐ {} -- {}",
            i + 1,
            repo.full_name,
            repo.stargazers_count,
            repo.description.as_deref().unwrap_or("(no description)")
        );
        println!("      lang: {:?}  url: {}", repo.language, repo.html_url);
    }
    println!();

    // ---------------------------------------------------------------
    // 3. List public repos for an org (paginated, first page)
    // ---------------------------------------------------------------
    println!("=== 3. List repos for an org (first page) ===\n");

    let resp = client
        .get("https://api.github.com/orgs/rust-lang/repos")
        .query(&[("per_page", "5"), ("sort", "pushed")])
        .send()
        .await?
        .error_for_status()?;

    let repos: Vec<Repo> = resp.json().await?;

    for repo in &repos {
        println!(
            "  {} -- ⭐ {} -- {}",
            repo.full_name,
            repo.stargazers_count,
            repo.description.as_deref().unwrap_or("(no description)")
        );
    }
    println!();

    // ---------------------------------------------------------------
    // 4. Handle rate limiting gracefully
    // ---------------------------------------------------------------
    println!("=== 4. Rate-limit awareness ===\n");

    let resp = client
        .get("https://api.github.com/rate_limit")
        .send()
        .await?
        .error_for_status()?;

    let text = resp.text().await?;
    // Just show the first few lines (it's a big JSON blob).
    for line in text.lines().take(10) {
        println!("  {line}");
    }
    println!("  ...\n");

    println!("Done!");
    Ok(())
}
