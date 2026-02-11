//! WebSocket echo example.
//!
//! Demonstrates both synchronous and asynchronous WebSocket communication
//! using the `websocket` feature. Connects to a public echo server, sends
//! messages, and prints the echoed responses.
//!
//! The echo server is a third-party service and may be temporarily
//! unavailable. The example prints a message and exits cleanly if it
//! cannot connect.
//!
//! # Running
//!
//! ```sh
//! cargo run --example websocket --features websocket
//! ```

use winhttp::*;

const ECHO_HOST: &str = "echo.websocket.org";
const ECHO_PORT: u16 = 443;
const ECHO_PATH: &str = "/.ws";

/// Try to create a sync WebSocket connection.
fn try_connect_sync() -> windows::core::Result<WebSocket> {
    let session = Session::new()?;
    let connection = session.connect(ECHO_HOST, ECHO_PORT)?;

    let request = connection.request("GET", ECHO_PATH).secure().build()?;

    // Tell WinHTTP to perform the WebSocket upgrade handshake.
    request.set_option(WINHTTP_OPTION_UPGRADE_TO_WEB_SOCKET, &[])?;

    request.send()?;
    request.receive_response()?;

    WebSocket::from_upgrade(request)
}

/// Drain a potential welcome message from the echo server.
fn drain_welcome(ws: &WebSocket) {
    let mut buf = vec![0u8; 4096];
    let _ = ws.receive(&mut buf);
}

/// Try to create an async WebSocket connection.
#[cfg(feature = "async")]
async fn try_connect_async() -> windows::core::Result<AsyncWebSocket> {
    let session = Session::new_async()?;
    let connection = session.connect(ECHO_HOST, ECHO_PORT)?;

    let request = connection.request("GET", ECHO_PATH).secure().build()?;

    request.set_option(WINHTTP_OPTION_UPGRADE_TO_WEB_SOCKET, &[])?;

    let async_request = request.into_async()?;
    let response = async_request.send().await?;

    AsyncWebSocket::from_response(response)
}

fn main() {
    println!("=== WinHTTP WebSocket Example ===\n");

    // ── 1. Synchronous WebSocket ──────────────────────────────────────
    println!("--- Sync WebSocket ---");

    let ws = match try_connect_sync() {
        Ok(ws) => ws,
        Err(e) => {
            println!("  Echo server ({ECHO_HOST}) is unreachable: {e}\n");
            println!("=== Done ===");
            return;
        }
    };
    println!("  WebSocket connected!");

    // The echo server may send a welcome message — drain it.
    drain_welcome(&ws);

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
            let ws = match try_connect_async().await {
                Ok(ws) => ws,
                Err(e) => {
                    println!("  Echo server ({ECHO_HOST}) is unreachable: {e}");
                    return;
                }
            };
            println!("  Async WebSocket connected!");

            // The echo server may send a welcome message — drain it.
            let _ = ws.receive().await;

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

            // Send several messages, then read them back.
            println!("\n  Multiple messages:");
            for i in 1..=3 {
                ws.send_text(&format!("Message #{i}"))
                    .await
                    .expect("Failed to send");
            }

            for _ in 0..3 {
                let msg = ws.receive().await.expect("Failed to receive");
                if let WebSocketMessage::Text(text) = msg {
                    println!("    {text}");
                }
            }

            // Graceful close.
            ws.close(1000, "done").await.expect("Failed to close");
            println!("  Async connection closed.");
        });
    }

    println!("\n=== Done ===");
}
