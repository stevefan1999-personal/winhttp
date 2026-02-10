//! Integration tests for WinHTTP library
//!
//! These tests verify the complete request/response cycle

use winhttp::*;

#[test]

fn test_simple_http_get() {
    let session = Session::new().expect("Failed to create session");
    let connection = session
        .connect("httpbin.org", 80)
        .expect("Failed to connect");

    let request = connection
        .request("GET", "/get")
        .build()
        .expect("Failed to build request");

    request.send().expect("Failed to send");
    request.receive_response().expect("Failed to receive");

    let body = request.read_all().expect("Failed to read body");
    assert!(!body.is_empty(), "Response should not be empty");

    let body_str = String::from_utf8_lossy(&body);
    assert!(
        body_str.contains("httpbin"),
        "Response should contain 'httpbin'"
    );
}

#[test]

fn test_https_get() {
    let session = Session::new().expect("Failed to create session");
    let connection = session
        .connect("httpbin.org", 443)
        .expect("Failed to connect");

    let request = connection
        .request("GET", "/get")
        .secure()
        .header("User-Agent", "winhttp-rs-integration-test")
        .build()
        .expect("Failed to build request");

    request.send().expect("Failed to send");
    request.receive_response().expect("Failed to receive");

    let body = request.read_all().expect("Failed to read body");
    let body_str = String::from_utf8_lossy(&body);
    assert!(
        body_str.contains("winhttp-rs-integration-test"),
        "Response should contain custom user agent"
    );
}

#[test]

fn test_custom_headers() {
    let session = Session::new().expect("Failed to create session");
    let connection = session
        .connect("httpbin.org", 443)
        .expect("Failed to connect");

    let request = connection
        .request("GET", "/headers")
        .secure()
        .header("X-Custom-Header", "test-value-123")
        .header("X-Another-Header", "another-value")
        .build()
        .expect("Failed to build request");

    request.send().expect("Failed to send");
    request.receive_response().expect("Failed to receive");

    let body = request.read_all().expect("Failed to read body");
    let body_str = String::from_utf8_lossy(&body);
    assert!(
        body_str.contains("X-Custom-Header"),
        "Response should echo custom header"
    );
    assert!(
        body_str.contains("test-value-123"),
        "Response should echo header value"
    );
}

#[test]

fn test_session_reuse() {
    let session = Session::new().expect("Failed to create session");

    let connection1 = session
        .connect("httpbin.org", 443)
        .expect("Failed to connect #1");
    let request1 = connection1
        .request("GET", "/get")
        .secure()
        .build()
        .expect("Failed to build #1");
    request1.send().expect("Failed to send #1");
    request1.receive_response().expect("Failed to receive #1");
    let _ = request1.read_all().expect("Failed to read #1");

    let connection2 = session
        .connect("httpbin.org", 443)
        .expect("Failed to connect #2");
    let request2 = connection2
        .request("GET", "/status/200")
        .secure()
        .build()
        .expect("Failed to build #2");
    request2.send().expect("Failed to send #2");
    request2.receive_response().expect("Failed to receive #2");
}

#[test]

fn test_connection_reuse() {
    let session = Session::new().expect("Failed to create session");
    let connection = session
        .connect("httpbin.org", 443)
        .expect("Failed to connect");

    let request1 = connection
        .request("GET", "/get")
        .secure()
        .build()
        .expect("Failed to build #1");
    request1.send().expect("Failed to send #1");
    request1.receive_response().expect("Failed to receive #1");
    let _ = request1.read_all().expect("Failed to read #1");

    let request2 = connection
        .request("GET", "/status/200")
        .secure()
        .build()
        .expect("Failed to build #2");
    request2.send().expect("Failed to send #2");
    request2.receive_response().expect("Failed to receive #2");
}

#[test]
#[cfg(not(target_os = "windows"))]
fn test_non_windows_compilation() {
    assert!(true, "Library should compile on non-Windows platforms");
}
