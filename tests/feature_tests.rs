//! Integration tests for WinHTTP ergonomic helpers and new features.

use winhttp::*;

#[test]

fn test_status_code_and_text() {
    let session = Session::new().expect("Failed to create session");
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
    assert_eq!(status, 200);

    let text = request.status_text().expect("Failed to get status text");
    assert_eq!(text, "OK");
}

#[test]

fn test_content_type_and_length() {
    let session = Session::new().expect("Failed to create session");
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

    let ct = request.content_type().expect("Failed to get content type");
    assert!(
        ct.contains("application/json"),
        "Expected JSON content type, got: {ct}"
    );

    // Content-Length may or may not be present depending on server
    let _cl = request
        .content_length()
        .expect("Failed to query content length");
}

#[test]

fn test_raw_headers() {
    let session = Session::new().expect("Failed to create session");
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

    let headers = request.raw_headers().expect("Failed to get raw headers");
    assert!(
        headers.contains("HTTP/"),
        "Expected HTTP version in raw headers"
    );
    assert!(
        headers.contains("Content-Type"),
        "Expected Content-Type in raw headers"
    );
}

#[test]

fn test_send_with_body() {
    let session = Session::new().expect("Failed to create session");
    let connection = session
        .connect("httpbin.org", 443)
        .expect("Failed to connect");

    let request = connection
        .request("POST", "/post")
        .secure()
        .header("Content-Type", "application/json")
        .build()
        .expect("Failed to build request");

    let body = br#"{"hello": "world"}"#;
    request
        .send_with_body(body)
        .expect("Failed to send with body");
    request.receive_response().expect("Failed to receive");

    let status = request.status_code().expect("Failed to get status code");
    assert_eq!(status, 200);

    let response_body = request.read_all().expect("Failed to read body");
    let response_str = String::from_utf8_lossy(&response_body);
    assert!(
        response_str.contains("hello"),
        "Response should echo the body"
    );
}

#[test]

fn test_enable_http2() {
    let session = Session::new().expect("Failed to create session");
    let connection = session
        .connect("httpbin.org", 443)
        .expect("Failed to connect");

    let request = connection
        .request("GET", "/get")
        .secure()
        .build()
        .expect("Failed to build request");

    // Enable HTTP/2 — this should succeed on modern Windows
    let result = request.enable_http2();
    assert!(result.is_ok(), "enable_http2 should succeed");

    request.send().expect("Failed to send");
    request.receive_response().expect("Failed to receive");

    let status = request.status_code().expect("Failed to get status code");
    assert_eq!(status, 200);

    // Check if HTTP/2 was actually used (may not be, depending on server/OS)
    let _protocol = request.http_protocol_used();
}

#[test]

fn test_set_decompression() {
    let session = Session::new().expect("Failed to create session");
    let connection = session
        .connect("httpbin.org", 443)
        .expect("Failed to connect");

    let request = connection
        .request("GET", "/gzip")
        .secure()
        .build()
        .expect("Failed to build request");

    request
        .set_decompression(WINHTTP_DECOMPRESSION_FLAG_ALL)
        .expect("Failed to enable decompression");

    request.send().expect("Failed to send");
    request.receive_response().expect("Failed to receive");

    let status = request.status_code().expect("Failed to get status code");
    assert_eq!(status, 200);
}

#[test]

fn test_disable_redirects() {
    let session = Session::new().expect("Failed to create session");
    let connection = session
        .connect("httpbin.org", 443)
        .expect("Failed to connect");

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

    // Should get a 302 redirect status, not follow it
    let status = request.status_code().expect("Failed to get status code");
    assert!(
        status == 302 || status == 301,
        "Expected redirect status, got: {status}"
    );
}

#[test]

fn test_session_set_secure_protocols() {
    let session = Session::new().expect("Failed to create session");

    // Set to modern TLS only
    let result = session.set_secure_protocols(WINHTTP_FLAG_SECURE_PROTOCOL_MODERN);
    assert!(result.is_ok(), "set_secure_protocols should succeed");

    // Verify we can still make a request
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
    assert_eq!(status, 200);
}

#[test]

fn test_session_set_option_query_option() {
    let session = Session::new().expect("Failed to create session");

    // Set max connections per server
    session
        .set_max_connections_per_server(4)
        .expect("Failed to set max connections");
}

#[test]

fn test_session_enable_http_protocol() {
    let session = Session::new().expect("Failed to create session");

    let result = session.enable_http_protocol(WINHTTP_PROTOCOL_FLAG_HTTP2);
    assert!(result.is_ok(), "enable_http_protocol should succeed");
}

#[test]

fn test_session_decompression() {
    let session = Session::new().expect("Failed to create session");

    let result = session.set_decompression(WINHTTP_DECOMPRESSION_FLAG_ALL);
    assert!(result.is_ok(), "set_decompression should succeed");
}

#[test]

fn test_reset_auto_proxy() {
    let session = Session::new().expect("Failed to create session");
    // reset_auto_proxy on the session should work or fail gracefully
    let result = session.reset_auto_proxy(WINHTTP_RESET_ALL);
    // Just verify it doesn't panic — may return error on some machines
    let _ = result;
}
