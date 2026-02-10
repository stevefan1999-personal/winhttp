//! Async HTTP example using the smol runtime.
//!
//! The futures produced by `winhttp` are runtime-agnostic, so they work
//! seamlessly with smol — no adapters required.
//!
//! # Running
//!
//! ```sh
//! cargo run -p example-smol
//! ```

use winhttp::Client;

fn main() {
    println!("=== WinHTTP + smol Example ===\n");

    smol::block_on(async {
        let client = Client::new().expect("Failed to create client");

        // ── GET ─────────────────────────────────────────────────────
        println!("--- Async GET ---");
        let resp = client
            .async_get("https://httpbin.org/get")
            .await
            .expect("GET failed");
        println!("Status: {} {}", resp.status, resp.status_text);
        println!("Body: {} bytes\n", resp.body.len());

        // ── POST ────────────────────────────────────────────────────
        println!("--- Async POST ---");
        let resp = client
            .async_post("https://httpbin.org/post", b"hello from smol".to_vec())
            .await
            .expect("POST failed");
        println!("Status: {}", resp.status);
        println!(
            "Payload echoed: {}\n",
            resp.text().contains("hello from smol")
        );

        // ── Builder with custom headers ─────────────────────────────
        println!("--- Async builder ---");
        let resp = client
            .request("PUT", "https://httpbin.org/put")
            .header("Content-Type", "application/json")
            .header("X-Runtime", "smol")
            .body(br#"{"runtime":"smol"}"#)
            .send_async()
            .await
            .expect("Builder request failed");
        println!("Status: {}", resp.status);
        println!("Header echoed: {}\n", resp.text().contains("X-Runtime"));

        println!("=== Done ===");
    });
}
