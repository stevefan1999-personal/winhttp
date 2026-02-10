//! WebSocket echo example.
//!
//! Demonstrates both synchronous and asynchronous WebSocket communication
//! using the `websocket` feature. Connects to a public echo server, sends
//! messages, and prints the echoed responses.
//!
//! # Running
//!
//! ```sh
//! cargo run --example websocket --features websocket
//! ```

use winhttp::*;

fn main() {
    println!("=== WinHTTP WebSocket Example ===\n");

    // ── 1. Synchronous WebSocket ──────────────────────────────────────
    println!("--- Sync WebSocket ---");

    let session = Session::new().expect("Failed to create session");
    let connection = session
        .connect("echo.websocket.org", 443)
        .expect("Failed to connect");

    // Build an HTTP request that will be upgraded to WebSocket.
    let request = connection
        .request("GET", "/.ws")
        .secure()
        .header("Upgrade", "websocket")
        .header("Connection", "Upgrade")
        .header("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
        .header("Sec-WebSocket-Version", "13")
        .build()
        .expect("Failed to build request");

    request.send().expect("Failed to send");
    request.receive_response().expect("Failed to receive");

    // Upgrade the HTTP connection to a WebSocket.
    let ws = WebSocket::from_upgrade(request).expect("Failed to upgrade");
    println!("  WebSocket connected!");

    // Send a text message and receive the echo.
    ws.send_text("Hello from winhttp!").expect("Failed to send");
    let mut buf = vec![0u8; 4096];
    let (len, _buffer_type) = ws.receive(&mut buf).expect("Failed to receive");
    let echo = String::from_utf8_lossy(&buf[..len]);
    println!("  Sent:     \"Hello from winhttp!\"");
    println!("  Received: \"{echo}\"");

    // Send a binary message and receive the echo.
    let binary_data = vec![0xDE, 0xAD, 0xBE, 0xEF];
    ws.send_binary(&binary_data).expect("Failed to send binary");
    let (len, _buffer_type) = ws.receive(&mut buf).expect("Failed to receive binary");
    println!("  Binary sent:     {:?}", binary_data);
    println!("  Binary received: {:?}", &buf[..len]);

    // Close gracefully.
    ws.close_normal("done").expect("Failed to close");
    println!("  Connection closed.\n");

    // ── 2. Async WebSocket (requires both `websocket` and `async`) ────
    #[cfg(feature = "async")]
    {
        println!("--- Async WebSocket ---");

        pollster::block_on(async {
            let session = Session::new_async().expect("Failed to create async session");
            let connection = session
                .connect("echo.websocket.org", 443)
                .expect("Failed to connect");

            let request = connection
                .request("GET", "/.ws")
                .secure()
                .header("Upgrade", "websocket")
                .header("Connection", "Upgrade")
                .header("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
                .header("Sec-WebSocket-Version", "13")
                .build()
                .expect("Failed to build request");

            let async_request = request
                .into_async()
                .expect("Failed to create async request");
            let response = async_request.send().await.expect("Failed to send");

            // Upgrade to async WebSocket.
            let ws = AsyncWebSocket::from_response(response).expect("Failed to upgrade");
            println!("  Async WebSocket connected!");

            // Send and receive a text message.
            ws.send_text("Async hello!").await.expect("Failed to send");
            let msg = ws.receive().await.expect("Failed to receive");
            match msg {
                WebSocketMessage::Text(text) => {
                    println!("  Sent:     \"Async hello!\"");
                    println!("  Received: \"{text}\"");
                }
                other => println!("  Unexpected: {other:?}"),
            }

            // Use the Stream API for multiple messages.
            println!("\n  Stream API:");

            // We already consumed ws, so connect fresh for stream demo.
        });

        // Stream demo with a fresh connection.
        pollster::block_on(async {
            let session = Session::new_async().expect("Failed to create async session");
            let connection = session
                .connect("echo.websocket.org", 443)
                .expect("Failed to connect");

            let request = connection
                .request("GET", "/.ws")
                .secure()
                .header("Upgrade", "websocket")
                .header("Connection", "Upgrade")
                .header("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
                .header("Sec-WebSocket-Version", "13")
                .build()
                .expect("Failed to build request");

            let async_request = request
                .into_async()
                .expect("Failed to create async request");
            let response = async_request.send().await.expect("Failed to send");
            let ws = AsyncWebSocket::from_response(response).expect("Failed to upgrade");

            // Send several messages, then read them back.
            for i in 1..=3 {
                ws.send_text(&format!("Message #{i}"))
                    .await
                    .expect("Failed to send");
            }

            for _ in 0..3 {
                let msg = ws.receive().await.expect("Failed to receive");
                if let WebSocketMessage::Text(text) = msg {
                    println!("  Stream: {text}");
                }
            }

            // Graceful close.
            ws.close(1000, "done").await.expect("Failed to close");
            println!("  Async connection closed.");
        });
    }

    println!("\n=== Done ===");
}
