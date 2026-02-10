//! High-level Client helpers example.
//!
//! Demonstrates the ergonomic `Client` API with `get`, `post`, `put`,
//! `delete`, `patch`, `head`, and the builder pattern.
//!
//! # Running
//!
//! ```sh
//! cargo run --example client_helpers --features async
//! ```

use winhttp::Client;

fn main() {
    println!("=== WinHTTP Client Helpers Example ===\n");

    // ── 1. One-shot helpers (zero setup) ────────────────────────────
    println!("--- One-shot GET ---");
    let resp = winhttp::get("https://httpbin.org/get").expect("GET failed");
    println!("Status: {} {}", resp.status, resp.status_text);
    println!(
        "Body ({} bytes): {}\n",
        resp.body.len(),
        &resp.text()[..80.min(resp.text().len())]
    );

    // ── 2. Reusable client ──────────────────────────────────────────
    let client = Client::new().expect("Failed to create client");

    println!("--- GET ---");
    let resp = client
        .get("https://httpbin.org/get?lang=rust")
        .expect("GET failed");
    println!("Status: {}, Success: {}", resp.status, resp.is_success());

    println!("\n--- POST ---");
    let resp = client
        .post("https://httpbin.org/post", b"Hello from winhttp!")
        .expect("POST failed");
    println!("Status: {}", resp.status);
    println!(
        "Body contains payload: {}",
        resp.text().contains("Hello from winhttp!")
    );

    println!("\n--- PUT ---");
    let resp = client
        .put("https://httpbin.org/put", b"Updated content")
        .expect("PUT failed");
    println!("Status: {}", resp.status);

    println!("\n--- DELETE ---");
    let resp = client
        .delete("https://httpbin.org/delete")
        .expect("DELETE failed");
    println!("Status: {}", resp.status);

    println!("\n--- PATCH ---");
    let resp = client
        .patch("https://httpbin.org/patch", b"patched!")
        .expect("PATCH failed");
    println!("Status: {}", resp.status);

    println!("\n--- HEAD ---");
    let resp = client.head("https://httpbin.org/get").expect("HEAD failed");
    println!(
        "Status: {}, Body empty: {}",
        resp.status,
        resp.body.is_empty()
    );

    // ── 3. Builder pattern ──────────────────────────────────────────
    println!("\n--- Builder pattern ---");
    let resp = client
        .request("POST", "https://httpbin.org/post")
        .header("Content-Type", "application/json")
        .header("X-Custom-Header", "winhttp-rocks")
        .body(b"{\"greeting\":\"hello\"}")
        .send()
        .expect("Builder request failed");
    println!("Status: {}", resp.status);
    println!(
        "Custom header echoed: {}",
        resp.text().contains("X-Custom-Header")
    );

    // ── 4. Custom config ────────────────────────────────────────────
    println!("\n--- Custom config (builder) ---");
    let client = Client::builder()
        .user_agent("my-app/2.0")
        .connect_timeout_ms(10_000)
        .send_timeout_ms(5_000)
        .receive_timeout_ms(15_000)
        .build()
        .expect("Failed to create client");
    let resp = client
        .get("https://httpbin.org/user-agent")
        .expect("GET failed");
    println!("User-Agent echo: {}", resp.text().trim());

    // ── 5. Error status codes ───────────────────────────────────────
    println!("\n--- Status code checks ---");
    let resp = client
        .get("https://httpbin.org/status/404")
        .expect("Request failed");
    println!("404 is_client_error: {}", resp.is_client_error());

    let resp = client
        .get("https://httpbin.org/status/500")
        .expect("Request failed");
    println!("500 is_server_error: {}", resp.is_server_error());

    // ── 6. Async helpers (requires `async` feature) ─────────────────
    #[cfg(feature = "async")]
    {
        println!("\n--- Async helpers ---");
        pollster::block_on(async {
            let client = Client::new().expect("Failed to create client");

            let resp = client
                .async_get("https://httpbin.org/get")
                .await
                .expect("Async GET failed");
            println!("Async GET: {} ({})", resp.status, resp.body.len());

            let resp = client
                .async_post("https://httpbin.org/post", b"async payload".to_vec())
                .await
                .expect("Async POST failed");
            println!("Async POST: {} ({})", resp.status, resp.body.len());

            // Async builder
            let resp = client
                .request("PUT", "https://httpbin.org/put")
                .header("Content-Type", "text/plain")
                .body(b"async builder body")
                .send_async()
                .await
                .expect("Async builder failed");
            println!("Async builder PUT: {}", resp.status);
        });
    }

    println!("\n=== Done ===");
}
