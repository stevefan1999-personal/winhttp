//! Real-world HTTP integration tests against popular HTTP testing services.
//!
//! Tests the high-level `Client` API against httpbin.org, jsonplaceholder.typicode.com,
//! and postman-echo.com to verify end-to-end correctness.

use winhttp::*;

#[cfg(feature = "json")]
use serde::Deserialize;

// JSON model structs

#[cfg(feature = "json")]
#[derive(Debug, Deserialize)]
struct Post {
    #[serde(rename = "userId")]
    user_id: u32,
    id: u32,
    title: String,
    body: String,
}

#[cfg(feature = "json")]
#[derive(Debug, Deserialize)]
struct User {
    name: String,
    email: String,
}

// A) JSON deserialization tests

#[test]
#[cfg(feature = "json")]
fn test_json_deserialize_post() {
    let client = Client::new().expect("create client");
    let resp = client
        .get("https://jsonplaceholder.typicode.com/posts/1")
        .expect("GET posts/1");

    assert!(resp.is_success());

    let post: Post = resp.json().expect("deserialize Post");
    assert_eq!(post.id, 1);
    assert_eq!(post.user_id, 1);
    assert!(!post.title.is_empty());
    assert!(!post.body.is_empty());
}

#[test]
#[cfg(feature = "json")]
fn test_json_deserialize_user() {
    let client = Client::new().expect("create client");
    let resp = client
        .get("https://jsonplaceholder.typicode.com/users/1")
        .expect("GET users/1");

    assert!(resp.is_success());

    let user: User = resp.json().expect("deserialize User");
    assert!(!user.name.is_empty());
    assert!(user.email.contains('@'));
}

#[test]
#[cfg(feature = "json")]
fn test_json_value_parsing() {
    let client = Client::new().expect("create client");
    let resp = client
        .get("https://httpbin.org/get")
        .expect("GET httpbin/get");

    assert!(resp.is_success());

    let value: serde_json::Value = resp.json().expect("deserialize Value");
    assert!(
        value.get("url").is_some(),
        "response should contain 'url' field"
    );
    assert!(
        value["url"]
            .as_str()
            .expect("url is string")
            .contains("httpbin")
    );
}

// B) Response header tests

#[test]
fn test_response_headers_httpbin() {
    let client = Client::new().expect("create client");
    let resp = client
        .get("https://httpbin.org/response-headers?Content-Type=application/json")
        .expect("GET response-headers");

    assert!(resp.is_success());
    assert!(
        resp.headers.contains("Content-Type"),
        "headers should contain Content-Type: {:?}",
        resp.headers
    );
}

#[test]
fn test_response_headers_postman_echo() {
    let client = Client::new().expect("create client");
    let resp = client
        .get("https://postman-echo.com/response-headers?foo=bar")
        .expect("GET postman-echo response-headers");

    assert!(resp.is_success());
    // Postman Echo returns the custom headers in the response
    assert!(
        resp.headers.contains("foo"),
        "headers should contain 'foo': {:?}",
        resp.headers
    );
}

// C) Redirect tests

#[test]
fn test_redirect_relative() {
    let client = Client::new().expect("create client");
    let resp = client
        .get("https://httpbin.org/redirect/2")
        .expect("GET redirect/2");

    // WinHTTP follows redirects by default
    assert_eq!(resp.status, 200);
    assert!(resp.is_success());
}

#[test]
fn test_redirect_absolute() {
    let client = Client::new().expect("create client");
    // Use redirect-to with an explicit HTTPS target to test absolute URL
    // redirect following. httpbin's /absolute-redirect may emit http://
    // Location headers, which WinHTTP's default policy rightly blocks.
    let resp = client
        .get("https://httpbin.org/redirect-to?url=https%3A%2F%2Fhttpbin.org%2Fget&status_code=301")
        .expect("GET absolute redirect");

    assert_eq!(resp.status, 200);
    assert!(resp.is_success());
}

#[test]
fn test_redirect_to_url() {
    let client = Client::new().expect("create client");
    let resp = client
        .get("https://httpbin.org/redirect-to?url=https%3A%2F%2Fhttpbin.org%2Fget")
        .expect("GET redirect-to");

    assert_eq!(resp.status, 200);
    assert!(resp.text().contains("httpbin"));
}

// D) Request body echo tests (postman-echo)

#[test]
fn test_postman_echo_post() {
    let client = Client::new().expect("create client");
    let resp = client
        .post("https://postman-echo.com/post", b"test123")
        .expect("POST postman-echo");

    assert!(resp.is_success());
    assert!(
        resp.text().contains("test123"),
        "response should echo body: {}",
        resp.text()
    );
}

#[test]
fn test_postman_echo_put() {
    let client = Client::new().expect("create client");
    let resp = client
        .put("https://postman-echo.com/put", b"update")
        .expect("PUT postman-echo");

    assert!(resp.is_success());
    assert!(
        resp.text().contains("update"),
        "response should echo body: {}",
        resp.text()
    );
}

#[test]
fn test_postman_echo_patch() {
    let client = Client::new().expect("create client");
    let resp = client
        .patch("https://postman-echo.com/patch", b"patched")
        .expect("PATCH postman-echo");

    assert!(resp.is_success());
    assert!(
        resp.text().contains("patched"),
        "response should echo body: {}",
        resp.text()
    );
}

// E) Query parameter tests

#[test]
fn test_query_params_httpbin() {
    let client = Client::new().expect("create client");
    let resp = client
        .get("https://httpbin.org/get?key1=value1&key2=value2")
        .expect("GET with query params");

    assert!(resp.is_success());
    let body = resp.text();
    assert!(body.contains("key1"), "body should contain key1");
    assert!(body.contains("value1"), "body should contain value1");
    assert!(body.contains("key2"), "body should contain key2");
    assert!(body.contains("value2"), "body should contain value2");
}

#[test]
fn test_query_params_postman_echo() {
    let client = Client::new().expect("create client");
    let resp = client
        .get("https://postman-echo.com/get?foo=bar&baz=qux")
        .expect("GET postman-echo with query params");

    assert!(resp.is_success());
    let body = resp.text();
    assert!(body.contains("foo"), "body should contain foo");
    assert!(body.contains("bar"), "body should contain bar");
    assert!(body.contains("baz"), "body should contain baz");
    assert!(body.contains("qux"), "body should contain qux");
}

// F) Status code tests

#[test]
fn test_status_201_created() {
    let client = Client::new().expect("create client");
    let resp = client
        .get("https://httpbin.org/status/201")
        .expect("GET status/201");

    assert_eq!(resp.status, 201);
    assert!(resp.is_success());
}

#[test]
fn test_status_418_teapot() {
    let client = Client::new().expect("create client");
    let resp = client
        .get("https://httpbin.org/status/418")
        .expect("GET status/418");

    assert_eq!(resp.status, 418);
    assert!(resp.is_client_error());
}

// G) Response body format tests

#[test]
fn test_gzip_response() {
    let client = Client::new().expect("create client");
    // WinHTTP does not decompress by default â€” enable it on the session.
    client
        .session()
        .set_decompression(WINHTTP_DECOMPRESSION_FLAG_ALL)
        .expect("enable decompression");

    let resp = client.get("https://httpbin.org/gzip").expect("GET gzip");

    assert!(resp.is_success());
    assert!(
        resp.text().contains("gzipped"),
        "response should contain 'gzipped': {}",
        resp.text()
    );
}

#[test]
fn test_bytes_response() {
    let client = Client::new().expect("create client");
    let resp = client
        .get("https://httpbin.org/bytes/1024")
        .expect("GET bytes/1024");

    assert!(resp.is_success());
    assert_eq!(
        resp.body.len(),
        1024,
        "body should be exactly 1024 bytes, got {}",
        resp.body.len()
    );
}

#[test]
fn test_utf8_response() {
    let client = Client::new().expect("create client");
    let resp = client
        .get("https://httpbin.org/encoding/utf8")
        .expect("GET encoding/utf8");

    assert!(resp.is_success());
    assert!(!resp.body.is_empty(), "body should not be empty");
    // Verify it's valid UTF-8
    let text = std::str::from_utf8(&resp.body);
    assert!(text.is_ok(), "body should be valid UTF-8");
}

// H) JSON POST to jsonplaceholder

#[test]
#[cfg(feature = "json")]
fn test_json_post_jsonplaceholder() {
    let client = Client::new().expect("create client");
    let resp = client
        .request("POST", "https://jsonplaceholder.typicode.com/posts")
        .header("Content-Type", "application/json")
        .body(br#"{"title":"winhttp test","body":"integration","userId":1}"#)
        .send()
        .expect("POST jsonplaceholder");

    // jsonplaceholder returns 201 for created resources
    assert_eq!(resp.status, 201);

    let value: serde_json::Value = resp.json().expect("deserialize response");
    assert!(value.get("id").is_some(), "response should contain 'id'");
    assert_eq!(value["title"], "winhttp test");
}

// I) Multiple services in one test (client reuse)

#[test]
fn test_client_reuse_across_hosts() {
    let client = Client::new().expect("create client");

    // Request 1: httpbin
    let resp1 = client.get("https://httpbin.org/get").expect("GET httpbin");
    assert!(resp1.is_success());

    // Request 2: jsonplaceholder
    let resp2 = client
        .get("https://jsonplaceholder.typicode.com/posts/1")
        .expect("GET jsonplaceholder");
    assert!(resp2.is_success());

    // Request 3: postman-echo
    let resp3 = client
        .get("https://postman-echo.com/get")
        .expect("GET postman-echo");
    assert!(resp3.is_success());
}

// J) Content-Type header on POST

#[test]
fn test_post_with_content_type() {
    let client = Client::new().expect("create client");
    let resp = client
        .request("POST", "https://httpbin.org/post")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(b"field1=value1&field2=value2")
        .send()
        .expect("POST with content-type");

    assert!(resp.is_success());
    let text = resp.text();
    assert!(text.contains("field1"), "should contain field1");
    assert!(text.contains("value1"), "should contain value1");
}

// K) Async integration tests

#[test]
#[cfg(all(target_os = "windows", feature = "async", feature = "json"))]
fn test_async_json_deserialize_post() {
    pollster::block_on(async {
        let client = Client::new().expect("create client");
        let resp = client
            .async_get("https://jsonplaceholder.typicode.com/posts/1")
            .await
            .expect("async GET posts/1");

        assert!(resp.is_success());

        let post: Post = resp.json().expect("deserialize Post");
        assert_eq!(post.id, 1);
        assert!(!post.title.is_empty());
    });
}

#[test]
#[cfg(all(target_os = "windows", feature = "async"))]
fn test_async_postman_echo_post() {
    pollster::block_on(async {
        let client = Client::new().expect("create client");
        let resp = client
            .async_post("https://postman-echo.com/post", b"async-body-123".to_vec())
            .await
            .expect("async POST postman-echo");

        assert!(resp.is_success());
        assert!(
            resp.text().contains("async-body-123"),
            "response should echo body"
        );
    });
}

#[test]
#[cfg(all(target_os = "windows", feature = "async"))]
fn test_async_redirect_follow() {
    pollster::block_on(async {
        let client = Client::new().expect("create client");
        let resp = client
            .async_get("https://httpbin.org/redirect/1")
            .await
            .expect("async GET redirect/1");

        assert_eq!(resp.status, 200);
        assert!(resp.is_success());
    });
}

#[test]
#[cfg(all(target_os = "windows", feature = "async"))]
fn test_async_bytes_response() {
    pollster::block_on(async {
        let client = Client::new().expect("create client");
        let resp = client
            .async_get("https://httpbin.org/bytes/512")
            .await
            .expect("async GET bytes/512");

        assert!(resp.is_success());
        assert_eq!(
            resp.body.len(),
            512,
            "body should be exactly 512 bytes, got {}",
            resp.body.len()
        );
    });
}

#[test]
#[cfg(all(target_os = "windows", feature = "async"))]
fn test_async_client_reuse_across_hosts() {
    pollster::block_on(async {
        let client = Client::new().expect("create client");

        let resp1 = client
            .async_get("https://httpbin.org/get")
            .await
            .expect("async GET httpbin");
        assert!(resp1.is_success());

        let resp2 = client
            .async_get("https://jsonplaceholder.typicode.com/posts/1")
            .await
            .expect("async GET jsonplaceholder");
        assert!(resp2.is_success());
    });
}
