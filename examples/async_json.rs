//! Async HTTP with JSON request and response bodies.
//!
//! This example demonstrates both the `async` and `json` features together.
//! It fetches structured data from an API, deserializes responses into Rust
//! types, and posts typed JSON payloads using [`Body::json`] — all
//! asynchronously.
//!
//! # Running
//!
//! ```sh
//! cargo run --example async_json --features "async json"
//! ```

use serde::{Deserialize, Serialize};
use winhttp::{Body, Client};

/// The top-level response from httpbin.org/get.
#[derive(Debug, Deserialize)]
struct HttpBinGet {
    origin: String,
    url: String,
    headers: HttpBinHeaders,
}

/// The "headers" object echoed back by httpbin.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct HttpBinHeaders {
    host: String,
    #[serde(rename = "User-Agent")]
    user_agent: Option<String>,
}

/// The top-level response from httpbin.org/post.
#[derive(Debug, Deserialize)]
struct HttpBinPost {
    url: String,
    json: Option<serde_json::Value>,
}

/// The response from httpbin.org/ip.
#[derive(Debug, Deserialize)]
struct IpResponse {
    origin: String,
}

/// A typed request payload.
#[derive(Serialize)]
struct Greeting {
    action: String,
    name: String,
}

fn main() {
    println!("=== Async + JSON Example ===\n");

    pollster::block_on(async {
        let client = Client::builder()
            .base_url("https://httpbin.org")
            .user_agent("winhttp-async-json-example/0.1")
            .build()
            .expect("Failed to create client");

        // ── 1. GET and deserialize into a typed struct ────────────────
        println!("--- GET /get → HttpBinGet ---");
        let resp = client.async_get("/get").await.expect("GET failed");

        let data: HttpBinGet = resp.json().expect("Failed to parse JSON");
        println!("  Origin:     {}", data.origin);
        println!("  URL:        {}", data.url);
        println!("  Host:       {}", data.headers.host);
        println!(
            "  User-Agent: {}",
            data.headers.user_agent.as_deref().unwrap_or("(none)")
        );

        // ── 2. POST a typed struct as JSON using Body::json ───────────
        println!("\n--- POST /post (Body::json) → HttpBinPost ---");
        let payload = Greeting {
            action: "greet".into(),
            name: "winhttp".into(),
        };
        let resp = client
            .async_post("/post", Body::json(&payload).expect("serialize"))
            .await
            .expect("POST failed");

        let data: HttpBinPost = resp.json().expect("Failed to parse JSON");
        println!("  URL:  {}", data.url);
        println!("  JSON: {}", data.json.unwrap_or_default());

        // ── 3. Builder pattern with Body::json ────────────────────────
        println!("\n--- PUT /put (builder + Body::json) ---");
        let resp = client
            .request("PUT", "/put")
            .body(
                Body::json(&serde_json::json!({
                    "updated": true,
                    "version": 2
                }))
                .expect("serialize"),
            )
            .send_async()
            .await
            .expect("PUT failed");

        let echo: HttpBinPost = resp.json().expect("Failed to parse JSON");
        println!("  URL:  {}", echo.url);
        println!("  JSON: {}", echo.json.unwrap_or_default());

        // ── 4. Quick IP lookup ────────────────────────────────────────
        println!("\n--- GET /ip → IpResponse ---");
        let resp = client.async_get("/ip").await.expect("GET failed");

        let ip: IpResponse = resp.json().expect("Failed to parse JSON");
        println!("  Your IP: {}", ip.origin);

        // ── 5. Handle a missing or unexpected shape gracefully ─────────
        println!("\n--- Handling a parse error ---");
        let resp = client.async_get("/html").await.expect("GET failed");

        let result: Result<HttpBinGet, _> = resp.json();
        match result {
            Ok(data) => println!("  Parsed: {data:?}"),
            Err(e) => println!("  Expected parse error: {e}"),
        }
    });

    println!("\n=== Done ===");
}
