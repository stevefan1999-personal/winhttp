//! Async HTTP GET example using WinHTTP.
//!
//! This example demonstrates runtime-agnostic async HTTP requests.
//! It uses `pollster::block_on` as a minimal executor, but the futures
//! produced by this library work with **any** async runtime:
//!
//! - `pollster::block_on(future)`
//! - `futures::executor::block_on(future)`
//! - `smol::block_on(future)`
//! - `tokio::runtime::Runtime::new().unwrap().block_on(future)`
//! - `async_std::task::block_on(future)`
//!
//! # Running
//!
//! ```sh
//! cargo run --example async_get --features async
//! ```

use winhttp::{Session, SessionConfig};

fn main() {
    println!("=== WinHTTP Async GET Example ===\n");

    // Any block_on works — the futures are runtime-agnostic.
    pollster::block_on(async {
        // 1. Create an async session (sets WINHTTP_FLAG_ASYNC).
        let session = Session::new_async().expect("Failed to create async session");

        // 2. Connect to the server.
        let connection = session
            .connect("httpbin.org", 443)
            .expect("Failed to connect");

        // 3. Build the request.
        let request = connection
            .request("GET", "/get")
            .secure()
            .header("User-Agent", "winhttp-rs-async-example/0.1")
            .header("Accept", "application/json")
            .build()
            .expect("Failed to build request");

        // 4. Convert to async and send.
        let async_request = request
            .into_async()
            .expect("Failed to create async request");
        let response = async_request.send().await.expect("Failed to send request");

        println!("Response headers received!");

        // 5. Read the full body.
        let body = response.read_all().await.expect("Failed to read body");
        let body_str = String::from_utf8_lossy(&body);
        println!("Response ({} bytes):\n{}", body.len(), body_str);
    });

    println!("\n=== Multiple Requests Example ===\n");

    pollster::block_on(async {
        let session = Session::new_async().expect("Failed to create async session");
        let connection = session
            .connect("httpbin.org", 443)
            .expect("Failed to connect");

        // Sequential async requests on the same connection.
        for path in ["/get", "/status/200", "/headers"] {
            let request = connection
                .request("GET", path)
                .secure()
                .build()
                .expect("Failed to build request");

            let async_req = request.into_async().expect("into_async failed");
            let response = async_req.send().await.expect("send failed");
            let body = response.read_all().await.expect("read_all failed");

            println!("{}: {} bytes", path, body.len());
        }
    });

    println!("\n=== Custom Config Example ===\n");

    pollster::block_on(async {
        let config = SessionConfig {
            user_agent: "my-custom-agent/2.0".to_string(),
            connect_timeout_ms: 10_000,
            send_timeout_ms: 5_000,
            receive_timeout_ms: 15_000,
        };
        let session = Session::with_config_async(config).expect("Failed to create session");
        let connection = session
            .connect("httpbin.org", 443)
            .expect("Failed to connect");

        let request = connection
            .request("GET", "/user-agent")
            .secure()
            .build()
            .expect("Failed to build request");

        let async_req = request.into_async().expect("into_async failed");
        let response = async_req.send().await.expect("send failed");
        let body = response.read_all().await.expect("read_all failed");

        println!("User-Agent echo:\n{}", String::from_utf8_lossy(&body));
    });
}
