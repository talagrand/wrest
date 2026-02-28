//! **whirl** — a tiny curl-like CLI built on wrest (wrest + curl = whirl).
//!
//! Supports the most popular curl features:
//!
//! - HTTP methods (`-X`)
//! - Custom headers (`-H`)
//! - Request body (`-d` / `--data`)
//! - Output to file (`-o`)
//! - Verbose mode (`-v`)
//! - Silent mode (`-s`)
//! - Head-only (`-I`)
//!
//! Run with:
//! ```text
//! cargo run --example whirl -- https://httpbin.org/get
//! cargo run --example whirl -- -X POST -H "Content-Type: application/json" -d '{"hello":"world"}' https://httpbin.org/post
//! cargo run --example whirl -- -o page.html https://example.com
//! cargo run --example whirl -- -I https://httpbin.org/get
//! ```

use clap::Parser;
use std::io::Write;
use std::time::{Duration, Instant};

/// A tiny curl-like HTTP client powered by wrest
#[derive(Parser, Debug)]
#[command(
    name = "whirl",
    about = "whirl — a tiny curl-like HTTP client powered by wrest"
)]
struct Args {
    /// URL to request
    url: String,

    /// HTTP method (GET, POST, PUT, PATCH, DELETE, HEAD)
    #[arg(short = 'X', long = "request", default_value = "GET")]
    method: String,

    /// Add a header (can be repeated: -H "Key: Value")
    #[arg(short = 'H', long = "header")]
    headers: Vec<String>,

    /// Request body (string)
    #[arg(short = 'd', long = "data")]
    data: Option<String>,

    /// Read request body from file
    #[arg(long = "data-binary")]
    data_binary: Option<String>,

    /// Write output to file instead of stdout
    #[arg(short = 'o', long = "output")]
    output: Option<String>,

    /// Accepted for curl compatibility (wrest follows redirects by default)
    #[arg(short = 'L', long = "location")]
    follow_redirects: bool,

    /// Show response headers and status (verbose)
    #[arg(short = 'v', long = "verbose")]
    verbose: bool,

    /// Silent mode — no progress or error messages
    #[arg(short = 's', long = "silent")]
    silent: bool,

    /// Fetch headers only (HEAD request)
    #[arg(short = 'I', long = "head")]
    head_only: bool,

    /// Maximum time in seconds for the entire request
    #[arg(short = 'm', long = "max-time")]
    max_time: Option<u64>,

    /// User-Agent string
    #[arg(short = 'A', long = "user-agent")]
    user_agent: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    if args.follow_redirects {
        eprintln!("whirl: -L is a no-op (wrest follows redirects by default)");
    }

    // -I implies HEAD method
    let method_str = if args.head_only { "HEAD" } else { &args.method };

    let method: http::Method = method_str
        .parse()
        .map_err(|_| format!("Unknown HTTP method: {method_str}"))?;

    // Build client
    let mut builder = wrest::Client::builder();

    if let Some(secs) = args.max_time {
        builder = builder.timeout(Duration::from_secs(secs));
    }

    if let Some(ref ua) = args.user_agent {
        builder = builder.user_agent(ua);
    }

    let client = builder.build()?;

    // Build request
    let mut req = client.request(method, &args.url);

    // Parse and add headers
    for h in &args.headers {
        let (key, value) = h
            .split_once(':')
            .ok_or_else(|| format!("Invalid header (expected 'Key: Value'): {h}"))?;
        req = req.header(key.trim(), value.trim());
    }

    // Add body
    if let Some(ref data) = args.data {
        req = req.body(data.clone());
    } else if let Some(ref path) = args.data_binary {
        let path = path.strip_prefix('@').unwrap_or(path);
        let body = std::fs::read(path)?;
        req = req.body(body);
    }

    // Send
    let mut resp = req.send().await?;

    // Capture metadata before consuming the response body.
    let status = resp.status();
    let headers = resp.headers().clone();
    let version = resp.version();

    if args.head_only {
        // -I: just print headers to stdout
        println!("{version:?} {status}");
        for (name, value) in &headers {
            println!("{name}: {}", value.to_str().unwrap_or("<binary>"));
        }
        return Ok(());
    }

    // Print status + headers in verbose mode before the body.
    if args.verbose {
        let stderr = std::io::stderr();
        let mut err = stderr.lock();
        writeln!(err, "{version:?} {status}")?;
        for (name, value) in &headers {
            writeln!(err, "{name}: {}", value.to_str().unwrap_or("<binary>"))?;
        }
        writeln!(err)?;
        err.flush()?;
    }

    // Output
    if let Some(ref path) = args.output {
        // Stream chunks directly to disk — keeps memory usage constant
        // regardless of response size.
        let mut file = std::fs::File::create(path)?;
        let total = resp.content_length();
        let mut downloaded: u64 = 0;
        let start = Instant::now();
        let show_progress = !args.silent;

        while let Some(chunk) = resp.chunk().await? {
            file.write_all(&chunk)?;
            downloaded += chunk.len() as u64;

            if show_progress {
                print_progress(downloaded, total, start.elapsed());
            }
        }

        file.flush()?;

        if show_progress {
            // Clear the progress line and print final summary.
            let elapsed = start.elapsed();
            eprintln!(
                "\r{:>70}\r  Downloaded {downloaded} bytes to {path} in {elapsed:.1?}",
                "" // overwrite the progress line
            );
        }
    } else {
        // Buffer to stdout (fine for text/API responses).
        let body = resp.bytes().await?;
        let text = String::from_utf8_lossy(&body);
        print!("{text}");
    }

    // Exit with non-zero on HTTP error status (like curl --fail)
    if !status.is_success() && !status.is_informational() && !status.is_redirection() {
        if !args.silent {
            eprintln!("Request failed with status: {status}");
        }
        std::process::exit(22); // curl uses 22 for HTTP errors
    }

    Ok(())
}

/// Print a curl-style progress line to stderr, padded to avoid artifacts.
fn print_progress(downloaded: u64, total: Option<u64>, elapsed: Duration) {
    let secs = elapsed.as_secs_f64();
    let speed = if secs > 0.0 {
        downloaded as f64 / secs
    } else {
        0.0
    };

    let speed_str = format_bytes(speed);

    let line = if let Some(total) = total {
        let pct = if total > 0 {
            (downloaded as f64 / total as f64) * 100.0
        } else {
            100.0
        };
        format!(
            "  {:>5.1}%  {}  /  {}   {}/s",
            pct,
            format_bytes(downloaded as f64),
            format_bytes(total as f64),
            speed_str,
        )
    } else {
        format!("  {}   {}/s", format_bytes(downloaded as f64), speed_str,)
    };

    // Pad to 70 chars so shorter lines overwrite longer previous ones.
    eprint!("\r{line:<70}");
}

/// Format a byte count as a human-readable string (IEC binary prefixes).
fn format_bytes(bytes: f64) -> String {
    const KIB: f64 = 1024.0;
    const MIB: f64 = 1024.0 * 1024.0;
    const GIB: f64 = 1024.0 * 1024.0 * 1024.0;

    if bytes >= GIB {
        format!("{:.1} GiB", bytes / GIB)
    } else if bytes >= MIB {
        format!("{:.1} MiB", bytes / MIB)
    } else if bytes >= KIB {
        format!("{:.1} KiB", bytes / KIB)
    } else {
        format!("{bytes:.0} B")
    }
}
