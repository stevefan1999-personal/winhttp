//! Demonstrates WinHTTP ergonomic helpers and features.
//!
//! This example shows how to use the new convenience methods for:
//! - Getting status codes and headers
//! - Sending POST requests with body
//! - Enabling HTTP/2
//! - Automatic decompression
//! - Session-level configuration

use winhttp::*;

fn main() {
    println!("=== WinHTTP Feature Demo ===\n");

    // Configure session with modern TLS
    let session = Session::new().expect("Failed to create session");
    session
        .set_secure_protocols(WINHTTP_FLAG_SECURE_PROTOCOL_MODERN)
        .expect("Failed to set TLS protocols");
    session
        .enable_http_protocol(WINHTTP_PROTOCOL_FLAG_HTTP2)
        .expect("Failed to enable HTTP/2");
    session
        .set_decompression(WINHTTP_DECOMPRESSION_FLAG_ALL)
        .expect("Failed to enable decompression");

    println!("Session configured: TLS 1.2+, HTTP/2, auto-decompression\n");

    // --- Demo 1: Simple GET with status helpers ---
    println!("--- Demo 1: GET request with status helpers ---");
    let connection = session
        .connect("httpbin.org", 443)
        .expect("Failed to connect");

    let request = connection
        .request("GET", "/get")
        .secure()
        .build()
        .expect("Failed to build request");

    request.send().expect("Failed to send");
    request.receive_response().expect("Failed to receive");

    let status = request.status_code().expect("Failed to get status code");
    let text = request.status_text().expect("Failed to get status text");
    let ct = request.content_type().expect("Failed to get content type");
    let cl = request
        .content_length()
        .expect("Failed to get content length");

    println!("  Status: {status} {text}");
    println!("  Content-Type: {ct}");
    println!("  Content-Length: {cl:?}");

    // Check HTTP protocol used
    match request.http_protocol_used() {
        Ok(p) if p & WINHTTP_PROTOCOL_FLAG_HTTP2 != 0 => println!("  Protocol: HTTP/2"),
        Ok(p) if p & WINHTTP_PROTOCOL_FLAG_HTTP3 != 0 => println!("  Protocol: HTTP/3"),
        Ok(_) => println!("  Protocol: HTTP/1.1"),
        Err(e) => println!("  Protocol: unknown ({e})"),
    }

    let body = request.read_all().expect("Failed to read body");
    println!("  Body length: {} bytes\n", body.len());

    // --- Demo 2: POST with body ---
    println!("--- Demo 2: POST request with body ---");
    let request = connection
        .request("POST", "/post")
        .secure()
        .header("Content-Type", "application/json")
        .build()
        .expect("Failed to build request");

    let json_body = br#"{"message": "Hello from winhttp-rs!", "features": ["HTTP/2", "decompression", "ergonomic API"]}"#;
    request
        .send_with_body(json_body)
        .expect("Failed to send with body");
    request.receive_response().expect("Failed to receive");

    let status = request.status_code().expect("Failed to get status code");
    println!("  Status: {status}");

    let body = request.read_all().expect("Failed to read body");
    let body_str = String::from_utf8_lossy(&body);
    if body_str.contains("Hello from winhttp-rs!") {
        println!("  Server echoed our message back!");
    }
    println!("  Response: {} bytes\n", body.len());

    // --- Demo 3: Decompression ---
    println!("--- Demo 3: Gzip decompression ---");
    let request = connection
        .request("GET", "/gzip")
        .secure()
        .build()
        .expect("Failed to build request");

    // Decompression already set at session level, but can also set per-request:
    request
        .set_decompression(WINHTTP_DECOMPRESSION_FLAG_ALL)
        .expect("Failed to set decompression");

    request.send().expect("Failed to send");
    request.receive_response().expect("Failed to receive");

    let status = request.status_code().expect("Failed to get status code");
    let body = request.read_all().expect("Failed to read body");
    let body_str = String::from_utf8_lossy(&body);
    let is_gzipped = body_str.contains("\"gzipped\": true");
    println!("  Status: {status}");
    println!("  Gzip verified: {is_gzipped}");
    println!("  Decompressed body: {} bytes\n", body.len());

    // --- Demo 4: Redirect policy ---
    println!("--- Demo 4: Redirect control ---");
    let request = connection
        .request("GET", "/redirect/1")
        .secure()
        .build()
        .expect("Failed to build request");

    request
        .set_redirect_policy(WINHTTP_OPTION_REDIRECT_POLICY_NEVER)
        .expect("Failed to set redirect policy");

    request.send().expect("Failed to send");
    request.receive_response().expect("Failed to receive");

    let status = request.status_code().expect("Failed to get status code");
    println!("  Redirect suppressed: status = {status} (expected 302)\n");

    // --- Demo 5: Raw headers ---
    println!("--- Demo 5: Raw response headers ---");
    let request = connection
        .request("GET", "/response-headers?X-Custom=winhttp-rs")
        .secure()
        .build()
        .expect("Failed to build request");

    request.send().expect("Failed to send");
    request.receive_response().expect("Failed to receive");

    let raw = request.raw_headers().expect("Failed to get raw headers");
    // Print first few lines
    for line in raw.lines().take(5) {
        println!("  {line}");
    }
    println!("  ... ({} total chars)\n", raw.len());

    println!("=== All demos complete! ===");
}
