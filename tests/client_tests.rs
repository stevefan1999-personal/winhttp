//! Integration tests for the high-level Client helpers (get/post/put/delete/patch/head).

use winhttp::*;

// Sync helpers

#[test]

fn test_client_get() {
    let client = Client::new().expect("Failed to create client");
    let resp = client
        .get("https://httpbin.org/get")
        .expect("GET request failed");

    assert_eq!(resp.status, 200);
    assert!(resp.is_success());
    assert!(!resp.body.is_empty());
    assert!(resp.text().contains("httpbin"));
}

#[test]

fn test_client_post() {
    let client = Client::new().expect("Failed to create client");
    let body = b"hello world";
    let resp = client
        .post("https://httpbin.org/post", body)
        .expect("POST request failed");

    assert_eq!(resp.status, 200);
    assert!(resp.text().contains("hello world"));
}

#[test]

fn test_client_put() {
    let client = Client::new().expect("Failed to create client");
    let body = b"updated data";
    let resp = client
        .put("https://httpbin.org/put", body)
        .expect("PUT request failed");

    assert_eq!(resp.status, 200);
    assert!(resp.text().contains("updated data"));
}

#[test]

fn test_client_delete() {
    let client = Client::new().expect("Failed to create client");
    let resp = client
        .delete("https://httpbin.org/delete")
        .expect("DELETE request failed");

    assert_eq!(resp.status, 200);
}

#[test]

fn test_client_patch() {
    let client = Client::new().expect("Failed to create client");
    let body = b"patched data";
    let resp = client
        .patch("https://httpbin.org/patch", body)
        .expect("PATCH request failed");

    assert_eq!(resp.status, 200);
    assert!(resp.text().contains("patched data"));
}

#[test]

fn test_client_head() {
    let client = Client::new().expect("Failed to create client");
    let resp = client
        .head("https://httpbin.org/get")
        .expect("HEAD request failed");

    assert_eq!(resp.status, 200);
    assert!(resp.body.is_empty(), "HEAD response should have no body");
    assert!(
        !resp.headers.is_empty(),
        "HEAD response should have headers"
    );
}

#[test]

fn test_client_request_builder() {
    let client = Client::new().expect("Failed to create client");
    let resp = client
        .request("POST", "https://httpbin.org/post")
        .header("Content-Type", "application/json")
        .header("X-Custom", "test-value")
        .body(b"{\"key\":\"value\"}")
        .send()
        .expect("Builder request failed");

    assert_eq!(resp.status, 200);
    let text = resp.text();
    assert!(text.contains("application/json"));
    assert!(text.contains("X-Custom"));
}

#[test]

fn test_client_get_with_query_string() {
    let client = Client::new().expect("Failed to create client");
    let resp = client
        .get("https://httpbin.org/get?foo=bar&baz=123")
        .expect("GET with query string failed");

    assert_eq!(resp.status, 200);
    let text = resp.text();
    assert!(text.contains("foo"));
    assert!(text.contains("bar"));
}

#[test]

fn test_client_status_codes() {
    let client = Client::new().expect("Failed to create client");

    let resp = client
        .get("https://httpbin.org/status/404")
        .expect("404 request failed");
    assert_eq!(resp.status, 404);
    assert!(resp.is_client_error());

    let resp = client
        .get("https://httpbin.org/status/500")
        .expect("500 request failed");
    assert_eq!(resp.status, 500);
    assert!(resp.is_server_error());
}

// Module-level one-shot helpers

#[test]

fn test_oneshot_get() {
    let resp = winhttp::get("https://httpbin.org/get").expect("One-shot GET failed");
    assert!(resp.is_success());
    assert!(!resp.body.is_empty());
}

#[test]

fn test_oneshot_post() {
    let resp =
        winhttp::post("https://httpbin.org/post", b"oneshot body").expect("One-shot POST failed");
    assert!(resp.is_success());
    assert!(resp.text().contains("oneshot body"));
}

// Async helpers

#[test]
#[cfg(all(target_os = "windows", feature = "async"))]
fn test_client_async_get() {
    pollster::block_on(async {
        let client = Client::new().expect("Failed to create client");
        let resp = client
            .async_get("https://httpbin.org/get")
            .await
            .expect("Async GET failed");

        assert_eq!(resp.status, 200);
        assert!(resp.is_success());
        assert!(!resp.body.is_empty());
    });
}

#[test]
#[cfg(all(target_os = "windows", feature = "async"))]
fn test_client_async_post() {
    pollster::block_on(async {
        let client = Client::new().expect("Failed to create client");
        let resp = client
            .async_post("https://httpbin.org/post", b"async body".to_vec())
            .await
            .expect("Async POST failed");

        assert_eq!(resp.status, 200);
        assert!(resp.text().contains("async body"));
    });
}

#[test]
#[cfg(all(target_os = "windows", feature = "async"))]
fn test_client_async_put() {
    pollster::block_on(async {
        let client = Client::new().expect("Failed to create client");
        let resp = client
            .async_put("https://httpbin.org/put", b"async put".to_vec())
            .await
            .expect("Async PUT failed");

        assert_eq!(resp.status, 200);
        assert!(!resp.body.is_empty(), "PUT response should have a body");
    });
}

#[test]
#[cfg(all(target_os = "windows", feature = "async"))]
fn test_client_async_delete() {
    pollster::block_on(async {
        let client = Client::new().expect("Failed to create client");
        let resp = client
            .async_delete("https://httpbin.org/delete")
            .await
            .expect("Async DELETE failed");

        assert_eq!(resp.status, 200);
    });
}

#[test]
#[cfg(all(target_os = "windows", feature = "async"))]
fn test_client_async_head() {
    pollster::block_on(async {
        let client = Client::new().expect("Failed to create client");
        let resp = client
            .async_head("https://httpbin.org/get")
            .await
            .expect("Async HEAD failed");

        assert_eq!(resp.status, 200);
        assert!(resp.body.is_empty());
    });
}

#[test]
#[cfg(all(target_os = "windows", feature = "async"))]
fn test_client_async_request_builder() {
    pollster::block_on(async {
        let client = Client::new().expect("Failed to create client");
        let resp = client
            .request("POST", "https://httpbin.org/post")
            .header("Content-Type", "application/json")
            .body(b"{\"async\":true}")
            .send_async()
            .await
            .expect("Async builder request failed");

        assert_eq!(resp.status, 200);
        assert!(resp.text().contains("application/json"));
    });
}
