//! Async HTTP example using the Tokio multi-threaded runtime.
//!
//! The futures produced by `winhttp` are runtime-agnostic and `Send`, so they
//! work with Tokio's multi-threaded scheduler -- including `tokio::spawn`.
//!
//! # Running
//!
//! ```sh
//! cargo run -p example-tokio
//! ```

use std::sync::Arc;
use winhttp::Client;

#[tokio::main]
async fn main() {
    println!("=== WinHTTP + Tokio (multi-thread) Example ===\n");

    let client = Arc::new(Client::new().expect("Failed to create client"));

    // ── Sequential requests ─────────────────────────────────────────
    println!("--- Async GET ---");
    let resp = client
        .async_get("https://httpbin.org/get")
        .await
        .expect("GET failed");
    println!("Status: {} {}", resp.status, resp.status_text);
    println!("Body: {} bytes\n", resp.body.len());

    println!("--- Async POST ---");
    let resp = client
        .async_post("https://httpbin.org/post", b"hello from tokio".to_vec())
        .await
        .expect("POST failed");
    println!("Status: {}", resp.status);
    println!(
        "Payload echoed: {}\n",
        resp.text().contains("hello from tokio")
    );

    // ── Builder with custom headers ─────────────────────────────────
    println!("--- Async builder ---");
    let resp = client
        .request("PUT", "https://httpbin.org/put")
        .header("Content-Type", "application/json")
        .header("X-Runtime", "tokio")
        .body(br#"{"runtime":"tokio"}"#)
        .send_async()
        .await
        .expect("Builder request failed");
    println!("Status: {}", resp.status);
    println!("Header echoed: {}\n", resp.text().contains("X-Runtime"));

    // ── Concurrent requests via tokio::spawn ────────────────────────
    println!("--- Concurrent spawned tasks ---");

    let urls = [
        "https://httpbin.org/get?n=1",
        "https://httpbin.org/get?n=2",
        "https://httpbin.org/get?n=3",
    ];

    let mut handles = Vec::new();
    for url in urls {
        let c = Arc::clone(&client);
        let url = url.to_string();
        handles.push(tokio::spawn(async move {
            let resp = c.async_get(&url).await.expect("GET failed");
            (url, resp.status, resp.body.len())
        }));
    }

    for handle in handles {
        let (url, status, len) = handle.await.expect("task panicked");
        println!("  {url}: {status} ({len} bytes)");
    }

    println!("\n=== Done ===");
}
