#![cfg(feature = "websocket")]
//! WebSocket integration tests against real echo servers
//!
//! Tests both synchronous and asynchronous WebSocket operations
//! using the public Postman WebSocket echo service.
//!
//! These tests require network access. If the echo server is unreachable
//! the tests skip gracefully instead of failing.

use winhttp::*;

#[cfg(feature = "async")]
use futures_core::Stream;

const ECHO_HOST: &str = "echo.websocket.org";
const ECHO_PORT: u16 = 443;
const ECHO_PATH: &str = "/.ws";

/// Session config with short timeouts so tests don't hang.
fn test_session_config() -> SessionConfig {
    SessionConfig {
        connect_timeout_ms: 10_000,
        send_timeout_ms: 10_000,
        receive_timeout_ms: 10_000,
        ..SessionConfig::default()
    }
}

/// Try to create a sync WebSocket connection. Returns `None` if the echo
/// server is unreachable (DNS failure, timeout, upgrade rejected, etc.).
fn try_create_sync_websocket() -> Option<WebSocket> {
    let session = Session::with_config(test_session_config()).ok()?;
    let connection = session.connect(ECHO_HOST, ECHO_PORT).ok()?;

    let request = connection.request("GET", ECHO_PATH).secure().build().ok()?;

    request
        .set_option(WINHTTP_OPTION_UPGRADE_TO_WEB_SOCKET, &[])
        .ok()?;

    request.send().ok()?;
    request.receive_response().ok()?;

    let ws = WebSocket::from_upgrade(request).ok()?;

    // Drain potential welcome message
    let mut drain_buf = vec![0u8; 4096];
    let _ = ws.receive(&mut drain_buf);

    Some(ws)
}

/// Macro that skips the test when the echo server is unreachable.
macro_rules! require_sync_ws {
    () => {
        match try_create_sync_websocket() {
            Some(ws) => ws,
            None => {
                eprintln!("SKIPPED: WebSocket echo server ({ECHO_HOST}) is unreachable");
                return;
            }
        }
    };
}

/// Try to create an async WebSocket connection. Returns `None` if the echo
/// server is unreachable.
#[cfg(feature = "async")]
async fn try_create_async_websocket() -> Option<AsyncWebSocket> {
    let session = Session::with_config_async(test_session_config()).ok()?;
    let connection = session.connect(ECHO_HOST, ECHO_PORT).ok()?;

    let request = connection.request("GET", ECHO_PATH).secure().build().ok()?;

    request
        .set_option(WINHTTP_OPTION_UPGRADE_TO_WEB_SOCKET, &[])
        .ok()?;

    let async_req = request.into_async().ok()?;
    let response = async_req.send().await.ok()?;

    let ws = AsyncWebSocket::from_response(response).ok()?;

    // Drain potential welcome message
    let _ = ws.receive().await;

    Some(ws)
}

/// Macro that skips an async test when the echo server is unreachable.
macro_rules! require_async_ws {
    () => {
        match try_create_async_websocket().await {
            Some(ws) => ws,
            None => {
                eprintln!("SKIPPED: WebSocket echo server ({ECHO_HOST}) is unreachable");
                return;
            }
        }
    };
}

/// Helper to poll a WebSocket stream for the next message
#[cfg(feature = "async")]
async fn stream_next(
    stream: &mut std::pin::Pin<&mut WebSocketStream>,
) -> Option<windows::core::Result<WebSocketMessage>> {
    std::future::poll_fn(|cx| stream.as_mut().poll_next(cx)).await
}

// Synchronous WebSocket Tests

#[test]
fn test_sync_ws_text_echo() {
    let ws = require_sync_ws!();

    // Send text message
    let message = "Hello WinHTTP!";
    ws.send_text(message).expect("send text message");

    // Receive echo
    let mut buf = vec![0u8; 4096];
    let (bytes_read, buffer_type) = ws.receive(&mut buf).expect("receive message");
    let received = std::str::from_utf8(&buf[..bytes_read]).expect("decode utf8");

    // Verify echo matches
    assert_eq!(received, message);
    assert_eq!(buffer_type, WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE);

    ws.close_normal("test complete").expect("close connection");
}

#[test]
fn test_sync_ws_binary_echo() {
    let ws = require_sync_ws!();

    // Send binary message
    let data = vec![0xDE, 0xAD, 0xBE, 0xEF];
    ws.send_binary(&data).expect("send binary message");

    // Receive echo
    let mut buf = vec![0u8; 4096];
    let (bytes_read, buffer_type) = ws.receive(&mut buf).expect("receive message");
    let received = &buf[..bytes_read];

    // Verify echo matches
    assert_eq!(received, &data[..]);
    assert_eq!(buffer_type, WINHTTP_WEB_SOCKET_BINARY_MESSAGE_BUFFER_TYPE);

    ws.close_normal("test complete").expect("close connection");
}

#[test]
fn test_sync_ws_multiple_messages() {
    let ws = require_sync_ws!();

    let messages = ["First message", "Second message", "Third message"];

    for message in &messages {
        // Send message
        ws.send_text(message).expect("send text message");

        // Receive echo
        let mut buf = vec![0u8; 4096];
        let (bytes_read, _) = ws.receive(&mut buf).expect("receive message");
        let received = std::str::from_utf8(&buf[..bytes_read]).expect("decode utf8");

        // Verify echo matches
        assert_eq!(received, *message);
    }

    ws.close_normal("test complete").expect("close connection");
}

#[test]
fn test_sync_ws_typed_send_receive() {
    let ws = require_sync_ws!();

    // Send using typed API
    let message = "Typed message test";
    ws.send_typed(message.as_bytes(), WebSocketBufferType::Utf8Message)
        .expect("send typed message");

    // Receive using typed API
    let mut buf = vec![0u8; 4096];
    let (bytes_read, buffer_type) = ws.receive_typed(&mut buf).expect("receive typed message");
    let received = std::str::from_utf8(&buf[..bytes_read]).expect("decode utf8");

    // Verify echo matches
    assert_eq!(received, message);
    assert_eq!(buffer_type, WebSocketBufferType::Utf8Message);

    ws.close_normal("test complete").expect("close connection");
}

#[test]
fn test_sync_ws_close() {
    let ws = require_sync_ws!();

    // Send a message
    let message = "Final message";
    ws.send_text(message).expect("send text message");

    // Receive echo
    let mut buf = vec![0u8; 4096];
    let (bytes_read, _) = ws.receive(&mut buf).expect("receive message");
    let received = std::str::from_utf8(&buf[..bytes_read]).expect("decode utf8");
    assert_eq!(received, message);

    // Close with explicit status code and reason
    ws.close(1000, "done").expect("close connection");
}

#[test]
fn test_sync_ws_empty_text_message() {
    let ws = require_sync_ws!();

    // WinHTTP does not support sending zero-length WebSocket messages.
    // Verify that the call fails gracefully rather than panicking.
    let result = ws.send_text("");
    assert!(
        result.is_err(),
        "WinHTTP should reject empty WebSocket messages"
    );

    ws.close_normal("test complete").expect("close connection");
}

#[test]
fn test_sync_ws_unicode_text() {
    let ws = require_sync_ws!();

    // Send Unicode text message
    let message = "Hello ä¸–ç•Œ ðŸŒ Ù…Ø±Ø\u{AD}Ø¨Ø§";
    ws.send_text(message).expect("send unicode text message");

    // Receive echo
    let mut buf = vec![0u8; 4096];
    let (bytes_read, _) = ws.receive(&mut buf).expect("receive message");
    let received = std::str::from_utf8(&buf[..bytes_read]).expect("decode utf8");

    // Verify Unicode echo matches
    assert_eq!(received, message);

    ws.close_normal("test complete").expect("close connection");
}

#[test]
fn test_sync_ws_large_binary() {
    let ws = require_sync_ws!();

    // Send large binary message (8KB)
    let data: Vec<u8> = (0..8192).map(|i| (i % 256) as u8).collect();
    ws.send_binary(&data).expect("send large binary message");

    // Receive echo — the server may fragment the response, so accumulate
    // until we get a complete MESSAGE (not FRAGMENT) buffer type.
    let mut received = Vec::new();
    let mut buf = vec![0u8; 16384];
    loop {
        let (bytes_read, buffer_type) = ws.receive(&mut buf).expect("receive message");
        received.extend_from_slice(&buf[..bytes_read]);
        if buffer_type == WINHTTP_WEB_SOCKET_BINARY_MESSAGE_BUFFER_TYPE {
            break;
        }
    }

    // Verify large binary echo matches
    assert_eq!(received.len(), data.len());
    assert_eq!(received, data);

    ws.close_normal("test complete").expect("close connection");
}

// Asynchronous WebSocket Tests

#[test]
#[cfg(all(target_os = "windows", feature = "async"))]
fn test_async_ws_text_echo() {
    pollster::block_on(async {
        let ws = require_async_ws!();

        // Send text message
        let message = "Async Hello!";
        ws.send_text(message).await.expect("send text message");

        // Receive echo
        let received_msg = ws.receive().await.expect("receive message");

        // Verify echo matches
        match received_msg {
            WebSocketMessage::Text(text) => {
                assert_eq!(text, message);
            }
            _ => panic!("Expected text message"),
        }

        ws.close(1000, "test complete")
            .await
            .expect("close connection");
    });
}

#[test]
#[cfg(all(target_os = "windows", feature = "async"))]
fn test_async_ws_binary_echo() {
    pollster::block_on(async {
        let ws = require_async_ws!();

        // Send binary message
        let data = vec![1, 2, 3, 4, 5];
        ws.send_binary(&data).await.expect("send binary message");

        // Receive echo
        let received_msg = ws.receive().await.expect("receive message");

        // Verify echo matches
        match received_msg {
            WebSocketMessage::Binary(received_data) => {
                assert_eq!(received_data, data);
            }
            _ => panic!("Expected binary message"),
        }

        ws.close(1000, "test complete")
            .await
            .expect("close connection");
    });
}

#[test]
#[cfg(all(target_os = "windows", feature = "async"))]
fn test_async_ws_multiple_roundtrips() {
    pollster::block_on(async {
        let ws = require_async_ws!();

        let messages = [
            "First async message",
            "Second async message",
            "Third async message",
            "Fourth async message",
            "Fifth async message",
        ];

        for message in &messages {
            // Send message
            ws.send_text(message).await.expect("send text message");

            // Receive echo
            let received_msg = ws.receive().await.expect("receive message");

            // Verify echo matches
            match received_msg {
                WebSocketMessage::Text(text) => {
                    assert_eq!(text, *message);
                }
                _ => panic!("Expected text message"),
            }
        }

        ws.close(1000, "test complete")
            .await
            .expect("close connection");
    });
}

#[test]
#[cfg(all(target_os = "windows", feature = "async"))]
fn test_async_ws_close_handshake() {
    pollster::block_on(async {
        let ws = require_async_ws!();

        // Send a message
        let message = "Goodbye message";
        ws.send_text(message).await.expect("send text message");

        // Receive echo
        let received_msg = ws.receive().await.expect("receive message");
        match received_msg {
            WebSocketMessage::Text(text) => {
                assert_eq!(text, message);
            }
            _ => panic!("Expected text message"),
        }

        // Close with explicit status and reason
        ws.close(1000, "goodbye").await.expect("close connection");
    });
}

#[test]
#[cfg(all(target_os = "windows", feature = "async"))]
fn test_async_ws_stream_api() {
    pollster::block_on(async {
        let ws = require_async_ws!();

        // Send a message before converting to stream
        let message = "stream test";
        ws.send_text(message).await.expect("send text message");

        // Convert to stream
        let stream = ws.into_stream();
        let mut pinned = std::pin::pin!(stream);

        // Poll the stream for the echo
        let msg = stream_next(&mut pinned).await;

        match msg {
            Some(Ok(WebSocketMessage::Text(text))) => {
                assert_eq!(text, message);
            }
            Some(Ok(_)) => panic!("Expected text message"),
            Some(Err(e)) => panic!("Stream error: {:?}", e),
            None => panic!("Stream ended unexpectedly"),
        }
    });
}

#[test]
#[cfg(all(target_os = "windows", feature = "async"))]
fn test_async_ws_large_message() {
    pollster::block_on(async {
        let ws = require_async_ws!();

        // Send large text message (10KB)
        let message: String = "x".repeat(10240);
        ws.send_text(&message)
            .await
            .expect("send large text message");

        // Receive echo
        let received_msg = ws.receive().await.expect("receive message");

        // Verify large message echo
        match received_msg {
            WebSocketMessage::Text(text) => {
                assert_eq!(text.len(), message.len());
                assert_eq!(text, message);
            }
            _ => panic!("Expected text message"),
        }

        ws.close(1000, "test complete")
            .await
            .expect("close connection");
    });
}

#[test]
#[cfg(all(target_os = "windows", feature = "async"))]
fn test_async_ws_empty_text_message() {
    pollster::block_on(async {
        let ws = require_async_ws!();

        // WinHTTP does not support sending zero-length WebSocket messages.
        // Verify that the call fails gracefully rather than panicking.
        let result = ws.send_text("").await;
        assert!(
            result.is_err(),
            "WinHTTP should reject empty WebSocket messages"
        );

        ws.close(1000, "test complete")
            .await
            .expect("close connection");
    });
}

#[test]
#[cfg(all(target_os = "windows", feature = "async"))]
fn test_async_ws_unicode_text() {
    pollster::block_on(async {
        let ws = require_async_ws!();

        // Send Unicode text message
        let message = "Async ä½ å¥½ ðŸš€ ÐŸÑ€Ð¸Ð²ÐµÑ‚";
        ws.send_text(message)
            .await
            .expect("send unicode text message");

        // Receive echo
        let received_msg = ws.receive().await.expect("receive message");

        // Verify Unicode echo matches
        match received_msg {
            WebSocketMessage::Text(text) => {
                assert_eq!(text, message);
            }
            _ => panic!("Expected text message"),
        }

        ws.close(1000, "test complete")
            .await
            .expect("close connection");
    });
}

#[test]
#[cfg(all(target_os = "windows", feature = "async"))]
fn test_async_ws_raw_send_api() {
    use windows::Win32::Networking::WinHttp::WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE;

    pollster::block_on(async {
        let ws = require_async_ws!();

        // Use the raw send() API with explicit buffer type
        let message = "raw send API test";
        ws.send(
            message.as_bytes(),
            WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE,
        )
        .await
        .expect("send with raw API");

        let received_msg = ws.receive().await.expect("receive message");

        match received_msg {
            WebSocketMessage::Text(text) => {
                assert_eq!(text, message);
            }
            _ => panic!("Expected text message from raw send"),
        }

        ws.close(1000, "test complete")
            .await
            .expect("close connection");
    });
}

#[test]
#[cfg(all(target_os = "windows", feature = "async"))]
fn test_async_ws_large_binary() {
    pollster::block_on(async {
        let ws = require_async_ws!();

        // Send large binary message (8KB, same as sync test)
        let data: Vec<u8> = (0..8192).map(|i| (i % 256) as u8).collect();
        ws.send_binary(&data)
            .await
            .expect("send large binary message");

        let received_msg = ws.receive().await.expect("receive message");

        match received_msg {
            WebSocketMessage::Binary(received_data) => {
                assert_eq!(received_data.len(), data.len());
                assert_eq!(received_data, data);
            }
            _ => panic!("Expected binary message"),
        }

        ws.close(1000, "test complete")
            .await
            .expect("close connection");
    });
}

#[test]
#[cfg(all(target_os = "windows", feature = "async"))]
fn test_async_ws_mixed_text_and_binary() {
    pollster::block_on(async {
        let ws = require_async_ws!();

        // Send text, then binary, then text â€” verify each echoes correctly
        let text1 = "first text message";
        ws.send_text(text1).await.expect("send text 1");
        match ws.receive().await.expect("receive text 1") {
            WebSocketMessage::Text(t) => assert_eq!(t, text1),
            _ => panic!("Expected text message 1"),
        }

        let binary = vec![0xCA, 0xFE, 0xBA, 0xBE];
        ws.send_binary(&binary).await.expect("send binary");
        match ws.receive().await.expect("receive binary") {
            WebSocketMessage::Binary(b) => assert_eq!(b, binary),
            _ => panic!("Expected binary message"),
        }

        let text2 = "second text message";
        ws.send_text(text2).await.expect("send text 2");
        match ws.receive().await.expect("receive text 2") {
            WebSocketMessage::Text(t) => assert_eq!(t, text2),
            _ => panic!("Expected text message 2"),
        }

        ws.close(1000, "test complete")
            .await
            .expect("close connection");
    });
}

#[test]
#[cfg(all(target_os = "windows", feature = "async"))]
fn test_async_ws_rapid_fire_messages() {
    pollster::block_on(async {
        let ws = require_async_ws!();

        // Send 10 messages rapidly and verify all echoes match
        let count = 10;
        for i in 0..count {
            let msg = format!("rapid message #{i}");
            ws.send_text(&msg).await.expect("send rapid message");

            let received = ws.receive().await.expect("receive rapid echo");
            match received {
                WebSocketMessage::Text(text) => {
                    assert_eq!(text, msg, "Mismatch at message #{i}");
                }
                _ => panic!("Expected text message at #{i}"),
            }
        }

        ws.close(1000, "test complete")
            .await
            .expect("close connection");
    });
}

#[test]
#[cfg(all(target_os = "windows", feature = "async"))]
fn test_async_ws_stream_multiple_messages() {
    pollster::block_on(async {
        let ws = require_async_ws!();

        // Send 3 messages before converting to stream
        let messages = ["stream msg 1", "stream msg 2", "stream msg 3"];
        for msg in &messages {
            ws.send_text(msg).await.expect("send message for stream");
        }

        // Convert to stream and poll all 3 messages
        let stream = ws.into_stream();
        let mut pinned = std::pin::pin!(stream);

        for expected in &messages {
            let msg = stream_next(&mut pinned).await;
            match msg {
                Some(Ok(WebSocketMessage::Text(text))) => {
                    assert_eq!(text, *expected);
                }
                Some(Ok(_)) => panic!("Expected text message"),
                Some(Err(e)) => panic!("Stream error: {:?}", e),
                None => panic!("Stream ended unexpectedly"),
            }
        }
    });
}

#[test]
#[cfg(all(target_os = "windows", feature = "async"))]
fn test_async_ws_stream_binary() {
    pollster::block_on(async {
        let ws = require_async_ws!();

        // Send binary data
        let data = vec![1, 2, 3, 4, 5, 6, 7, 8];
        ws.send_binary(&data).await.expect("send binary for stream");

        // Convert to stream and receive
        let stream = ws.into_stream();
        let mut pinned = std::pin::pin!(stream);

        let msg = stream_next(&mut pinned).await;
        match msg {
            Some(Ok(WebSocketMessage::Binary(received))) => {
                assert_eq!(received, data);
            }
            Some(Ok(_)) => panic!("Expected binary message"),
            Some(Err(e)) => panic!("Stream error: {:?}", e),
            None => panic!("Stream ended unexpectedly"),
        }
    });
}

#[test]
#[cfg(all(target_os = "windows", feature = "async"))]
fn test_async_ws_sequential_connections() {
    pollster::block_on(async {
        // Test that we can create, use, and close multiple connections sequentially
        for i in 0..3 {
            let ws = match try_create_async_websocket().await {
                Some(ws) => ws,
                None => {
                    eprintln!("SKIPPED: WebSocket echo server ({ECHO_HOST}) is unreachable");
                    return;
                }
            };

            let msg = format!("connection #{i}");
            ws.send_text(&msg).await.expect("send text");

            let received = ws.receive().await.expect("receive echo");
            match received {
                WebSocketMessage::Text(text) => assert_eq!(text, msg),
                _ => panic!("Expected text message"),
            }

            ws.close(1000, "done").await.expect("close connection");
        }
    });
}

#[test]
#[cfg(all(target_os = "windows", feature = "async"))]
fn test_async_ws_close_with_custom_reason() {
    pollster::block_on(async {
        let ws = require_async_ws!();

        // Send a message to confirm connection is alive
        ws.send_text("alive check").await.expect("send text");
        let _ = ws.receive().await.expect("receive echo");

        // Close with a longer, descriptive reason
        ws.close(
            1000,
            "client finished all work and is shutting down gracefully",
        )
        .await
        .expect("close with custom reason");
    });
}

#[test]
#[cfg(all(target_os = "windows", feature = "async"))]
fn test_async_ws_binary_patterns() {
    pollster::block_on(async {
        let ws = require_async_ws!();

        // All zeros
        let zeros = vec![0u8; 256];
        ws.send_binary(&zeros).await.expect("send zeros");
        match ws.receive().await.expect("receive zeros") {
            WebSocketMessage::Binary(b) => assert_eq!(b, zeros),
            _ => panic!("Expected binary"),
        }

        // All 0xFF
        let ones = vec![0xFFu8; 256];
        ws.send_binary(&ones).await.expect("send 0xFF");
        match ws.receive().await.expect("receive 0xFF") {
            WebSocketMessage::Binary(b) => assert_eq!(b, ones),
            _ => panic!("Expected binary"),
        }

        // Sequential bytes 0..255
        let sequential: Vec<u8> = (0..=255).collect();
        ws.send_binary(&sequential).await.expect("send sequential");
        match ws.receive().await.expect("receive sequential") {
            WebSocketMessage::Binary(b) => assert_eq!(b, sequential),
            _ => panic!("Expected binary"),
        }

        ws.close(1000, "test complete").await.expect("close");
    });
}
