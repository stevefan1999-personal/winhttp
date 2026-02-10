//! Integration tests for the async WinHTTP API across multiple runtimes.
//!
//! Each runtime module (pollster, smol, tokio) runs the same set of tests to
//! prove the futures are truly runtime-agnostic.

#[cfg(all(target_os = "windows", feature = "async"))]
mod async_tests {
    use winhttp::*;

    /// Stamps out the full test suite under a given runtime executor.
    macro_rules! define_runtime_tests {
        ($mod_name:ident, $block_on:expr) => {
            mod $mod_name {
                use super::*;

                /// Run a future with the selected executor.
                fn run<F: std::future::Future>(f: F) -> F::Output {
                    ($block_on)(f)
                }

                #[test]
                fn simple_https_get() {
                    run(async {
                        let session = Session::new_async().expect("Failed to create async session");
                        let connection = session
                            .connect("httpbin.org", 443)
                            .expect("Failed to connect");

                        let request = connection
                            .request("GET", "/get")
                            .secure()
                            .header("User-Agent", "winhttp-rs-async-test")
                            .build()
                            .expect("Failed to build request");

                        let async_req = request.into_async().expect("into_async failed");
                        let response = async_req.send().await.expect("send failed");
                        let body = response.read_all().await.expect("read_all failed");

                        let body_str = String::from_utf8_lossy(&body);
                        assert!(!body.is_empty(), "Response body should not be empty");
                        assert!(
                            body_str.contains("httpbin"),
                            "Response should contain 'httpbin'"
                        );
                    });
                }

                #[test]
                fn custom_headers() {
                    run(async {
                        let session = Session::new_async().expect("Failed to create async session");
                        let connection = session
                            .connect("httpbin.org", 443)
                            .expect("Failed to connect");

                        let request = connection
                            .request("GET", "/headers")
                            .secure()
                            .header("X-Async-Test", "crossfire-channel")
                            .build()
                            .expect("Failed to build request");

                        let async_req = request.into_async().expect("into_async failed");
                        let response = async_req.send().await.expect("send failed");
                        let body = response.read_all().await.expect("read_all failed");

                        let body_str = String::from_utf8_lossy(&body);
                        assert!(
                            body_str.contains("X-Async-Test"),
                            "Response should echo custom header"
                        );
                        assert!(
                            body_str.contains("crossfire-channel"),
                            "Response should echo header value"
                        );
                    });
                }

                #[test]
                fn session_reuse() {
                    run(async {
                        let session = Session::new_async().expect("Failed to create async session");

                        // First request
                        let conn1 = session
                            .connect("httpbin.org", 443)
                            .expect("Failed to connect #1");
                        let req1 = conn1
                            .request("GET", "/get")
                            .secure()
                            .build()
                            .expect("Failed to build #1");
                        let async_req1 = req1.into_async().expect("into_async #1 failed");
                        let resp1 = async_req1.send().await.expect("send #1 failed");
                        let _ = resp1.read_all().await.expect("read_all #1 failed");

                        // Second request on the same session
                        let conn2 = session
                            .connect("httpbin.org", 443)
                            .expect("Failed to connect #2");
                        let req2 = conn2
                            .request("GET", "/status/200")
                            .secure()
                            .build()
                            .expect("Failed to build #2");
                        let async_req2 = req2.into_async().expect("into_async #2 failed");
                        let _resp2 = async_req2.send().await.expect("send #2 failed");
                    });
                }

                #[test]
                fn connection_reuse() {
                    run(async {
                        let session = Session::new_async().expect("Failed to create async session");
                        let connection = session
                            .connect("httpbin.org", 443)
                            .expect("Failed to connect");

                        for path in ["/get", "/status/200"] {
                            let request = connection
                                .request("GET", path)
                                .secure()
                                .build()
                                .expect("Failed to build request");

                            let async_req = request.into_async().expect("into_async failed");
                            let response = async_req.send().await.expect("send failed");
                            let _ = response.read_all().await.expect("read_all failed");
                        }
                    });
                }

                #[test]
                fn response_access_request() {
                    run(async {
                        let session = Session::new_async().expect("Failed to create async session");
                        let connection = session
                            .connect("httpbin.org", 443)
                            .expect("Failed to connect");

                        let request = connection
                            .request("GET", "/get")
                            .secure()
                            .build()
                            .expect("Failed to build request");

                        let async_req = request.into_async().expect("into_async failed");
                        let response = async_req.send().await.expect("send failed");

                        let _req_ref = response.request();
                        let body = response.read_all().await.expect("read_all failed");
                        assert!(!body.is_empty());
                    });
                }

                #[test]
                fn with_custom_config() {
                    run(async {
                        let config = SessionConfig {
                            user_agent: "async-custom-agent/1.0".to_string(),
                            connect_timeout_ms: 15_000,
                            send_timeout_ms: 10_000,
                            receive_timeout_ms: 20_000,
                        };

                        let session = Session::with_config_async(config)
                            .expect("Failed to create async session");
                        let connection = session
                            .connect("httpbin.org", 443)
                            .expect("Failed to connect");

                        let request = connection
                            .request("GET", "/get")
                            .secure()
                            .header("X-Config-Test", "custom-config-works")
                            .build()
                            .expect("Failed to build request");

                        let async_req = request.into_async().expect("into_async failed");
                        let response = async_req.send().await.expect("send failed");
                        let body = response.read_all().await.expect("read_all failed");

                        let body_str = String::from_utf8_lossy(&body);
                        assert!(
                            body_str.contains("X-Config-Test"),
                            "Response should contain custom header"
                        );
                        assert_eq!(session.config().connect_timeout_ms, 15_000);
                        assert_eq!(session.config().send_timeout_ms, 10_000);
                    });
                }

                #[test]
                fn client_async_get() {
                    run(async {
                        let client = Client::new().expect("Failed to create client");
                        let resp = client
                            .async_get("https://httpbin.org/get")
                            .await
                            .expect("async_get failed");

                        assert!(resp.is_success(), "Expected 2xx status");
                        assert!(!resp.body.is_empty(), "Body should not be empty");
                        assert!(
                            resp.text().contains("httpbin"),
                            "Body should contain 'httpbin'"
                        );
                    });
                }
            }
        };
    }

    // ── Runtime: pollster (minimal, runtime-agnostic proof) ────────────────
    define_runtime_tests!(pollster, ::pollster::block_on);

    // ── Runtime: smol (lightweight async runtime) ──────────────────────────
    define_runtime_tests!(smol, ::smol::block_on);

    // ── Runtime: tokio (industry-standard async runtime) ───────────────────
    define_runtime_tests!(tokio, |f| {
        ::tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("Failed to build tokio runtime")
            .block_on(f)
    });
}
