//! Integration tests for Phase 3 features: type-safe flags, certificate info,
//! connection info, request times, request stats, and async helpers.

use winhttp::*;

#[test]
fn test_auth_scheme_flags() {
    let basic = AuthScheme::BASIC;
    let ntlm = AuthScheme::NTLM;
    let combined = basic | ntlm;

    assert!(combined.contains(AuthScheme::BASIC));
    assert!(combined.contains(AuthScheme::NTLM));
    assert!(!combined.contains(AuthScheme::DIGEST));
    assert!(!combined.is_empty());
    assert_eq!(combined.bits(), basic.bits() | ntlm.bits());
}

#[test]
fn test_auth_target_flags() {
    let server = AuthTarget::SERVER;
    let proxy = AuthTarget::PROXY;
    // SERVER = 0x00000000, so server.is_empty() is TRUE.
    assert!(server.is_empty()); // SERVER = 0
    assert!(!proxy.is_empty());
}

#[test]
fn test_security_flags() {
    let ignore_all = SecurityFlags::IGNORE_ALL;
    assert!(ignore_all.contains(SecurityFlags::IGNORE_CERT_CN_INVALID));
    assert!(ignore_all.contains(SecurityFlags::IGNORE_CERT_DATE_INVALID));
    assert!(ignore_all.contains(SecurityFlags::IGNORE_UNKNOWN_CA));
    assert!(ignore_all.contains(SecurityFlags::IGNORE_CERT_WRONG_USAGE));
}

#[test]
fn test_decompression_flags() {
    let all = DecompressionFlags::ALL;
    assert!(all.contains(DecompressionFlags::GZIP));
    assert!(all.contains(DecompressionFlags::DEFLATE));

    let gzip_only = DecompressionFlags::GZIP;
    assert!(gzip_only.contains(DecompressionFlags::GZIP));
    assert!(!gzip_only.contains(DecompressionFlags::DEFLATE));
}

#[test]
fn test_http_protocol_flags() {
    let both = HttpProtocol::HTTP2_AND_HTTP3;
    assert!(both.contains(HttpProtocol::HTTP2));
    assert!(both.contains(HttpProtocol::HTTP3));
}

#[test]
fn test_secure_protocol_flags() {
    let modern = SecureProtocol::MODERN;
    assert!(modern.contains(SecureProtocol::TLS1_2));
    assert!(modern.contains(SecureProtocol::TLS1_3));
    assert!(!modern.contains(SecureProtocol::SSL2));
    assert!(!modern.contains(SecureProtocol::SSL3));
    assert!(!modern.contains(SecureProtocol::TLS1_0));
}

#[test]
fn test_disable_flags() {
    let flags = DisableFlags::COOKIES | DisableFlags::REDIRECTS;
    assert!(flags.contains(DisableFlags::COOKIES));
    assert!(flags.contains(DisableFlags::REDIRECTS));
    assert!(!flags.contains(DisableFlags::AUTHENTICATION));
    assert!(!flags.contains(DisableFlags::KEEP_ALIVE));
}

#[test]
fn test_redirect_policy_enum() {
    assert_eq!(
        u32::from(RedirectPolicy::Always),
        WINHTTP_OPTION_REDIRECT_POLICY_ALWAYS
    );
    assert_eq!(
        u32::from(RedirectPolicy::Never),
        WINHTTP_OPTION_REDIRECT_POLICY_NEVER
    );
    assert_eq!(
        u32::from(RedirectPolicy::DisallowHttpsToHttp),
        WINHTTP_OPTION_REDIRECT_POLICY_DISALLOW_HTTPS_TO_HTTP
    );
}

#[test]
fn test_autologon_policy_enum() {
    assert_eq!(
        u32::from(AutologonPolicy::Low),
        WINHTTP_AUTOLOGON_SECURITY_LEVEL_LOW
    );
    assert_eq!(
        u32::from(AutologonPolicy::Medium),
        WINHTTP_AUTOLOGON_SECURITY_LEVEL_MEDIUM
    );
    assert_eq!(
        u32::from(AutologonPolicy::High),
        WINHTTP_AUTOLOGON_SECURITY_LEVEL_HIGH
    );
}

#[test]
fn test_flag_from_u32() {
    let flags = SecurityFlags::from(0xFFFFFFFF);
    assert!(flags.contains(SecurityFlags::IGNORE_ALL));

    let raw: u32 = SecurityFlags::IGNORE_CERT_CN_INVALID.into();
    assert_eq!(raw, SECURITY_FLAG_IGNORE_CERT_CN_INVALID);
}

#[test]
fn test_flag_bitwise_not() {
    let all = DecompressionFlags::ALL;
    let not_all = !all;
    assert_ne!(all.bits(), not_all.bits());
}

#[test]
fn test_flag_bitor_assign() {
    let mut flags = DecompressionFlags::GZIP;
    flags |= DecompressionFlags::DEFLATE;
    assert!(flags.contains(DecompressionFlags::GZIP));
    assert!(flags.contains(DecompressionFlags::DEFLATE));
}

#[test]
fn test_flag_bitand() {
    let all = SecurityFlags::IGNORE_ALL;
    let cn = SecurityFlags::IGNORE_CERT_CN_INVALID;
    let result = all & cn;
    assert_eq!(result.bits(), cn.bits());
}

#[test]
fn test_flag_debug_format() {
    let flags = DecompressionFlags::GZIP;
    let debug = format!("{:?}", flags);
    assert!(
        debug.contains("GZIP"),
        "Debug output should contain GZIP: {debug}"
    );
}

#[test]
fn test_set_credentials_typed() {
    let session = Session::new().expect("session");
    let connection = session.connect("httpbin.org", 443).expect("connect");
    let request = connection
        .request("GET", "/get")
        .secure()
        .build()
        .expect("build");

    // Should succeed (even though we haven't sent yet)
    let result =
        request.set_credentials_typed(AuthTarget::SERVER, AuthScheme::BASIC, "user", "pass");
    // Just verify it doesn't panic; may fail since we haven't queried auth schemes yet
    let _ = result;
}

#[test]
fn test_set_decompression_typed() {
    let session = Session::new().expect("Failed to create session");
    let connection = session
        .connect("httpbin.org", 443)
        .expect("Failed to connect");
    let request = connection
        .request("GET", "/gzip")
        .secure()
        .build()
        .expect("Failed to build");

    request
        .set_decompression_typed(DecompressionFlags::ALL)
        .expect("Failed to set decompression");

    request.send().expect("Failed to send");
    request.receive_response().expect("Failed to receive");
    assert_eq!(request.status_code().expect("status code"), 200);
}

#[test]
fn test_set_redirect_policy_typed() {
    let session = Session::new().expect("Failed to create session");
    let connection = session
        .connect("httpbin.org", 443)
        .expect("Failed to connect");
    let request = connection
        .request("GET", "/redirect/1")
        .secure()
        .build()
        .expect("Failed to build");

    request
        .set_redirect_policy_typed(RedirectPolicy::Never)
        .expect("Failed to set redirect policy");

    request.send().expect("Failed to send");
    request.receive_response().expect("Failed to receive");
    let status = request.status_code().expect("status code");
    assert!(
        status == 301 || status == 302,
        "Expected redirect status, got: {status}"
    );
}

#[test]
fn test_enable_http_protocol_typed() {
    let session = Session::new().expect("Failed to create session");
    let connection = session
        .connect("httpbin.org", 443)
        .expect("Failed to connect");
    let request = connection
        .request("GET", "/get")
        .secure()
        .build()
        .expect("Failed to build");

    request
        .enable_http_protocol(HttpProtocol::HTTP2)
        .expect("Failed to enable HTTP/2");

    request.send().expect("Failed to send");
    request.receive_response().expect("Failed to receive");
    assert_eq!(request.status_code().expect("status code"), 200);
}

#[test]
fn test_set_security_flags_typed() {
    let session = Session::new().expect("Failed to create session");
    let connection = session
        .connect("httpbin.org", 443)
        .expect("Failed to connect");
    let request = connection
        .request("GET", "/get")
        .secure()
        .build()
        .expect("Failed to build");

    // This should succeed (though we're already ignoring cert errors on a valid cert)
    request
        .set_security_flags_typed(SecurityFlags::IGNORE_ALL)
        .expect("Failed to set security flags");

    request.send().expect("Failed to send");
    request.receive_response().expect("Failed to receive");
    assert_eq!(request.status_code().expect("status code"), 200);
}

#[test]
fn test_disable_feature_typed() {
    let session = Session::new().expect("Failed to create session");
    let connection = session
        .connect("httpbin.org", 443)
        .expect("Failed to connect");
    let request = connection
        .request("GET", "/cookies/set?test=value")
        .secure()
        .build()
        .expect("Failed to build");

    request
        .disable_feature_typed(DisableFlags::COOKIES)
        .expect("Failed to disable cookies");
    request
        .set_redirect_policy_typed(RedirectPolicy::Never)
        .expect("Failed to set redirect policy");

    request.send().expect("Failed to send");
    request.receive_response().expect("Failed to receive");
    // Just verify it doesn't crash
    let _ = request.status_code();
}

#[test]
fn test_session_set_secure_protocols_typed() {
    let session = Session::new().expect("Failed to create session");
    session
        .set_secure_protocols_typed(SecureProtocol::MODERN)
        .expect("Failed to set secure protocols");

    let connection = session
        .connect("httpbin.org", 443)
        .expect("Failed to connect");
    let request = connection
        .request("GET", "/get")
        .secure()
        .build()
        .expect("Failed to build");
    request.send().expect("Failed to send");
    request.receive_response().expect("Failed to receive");
    assert_eq!(request.status_code().expect("status code"), 200);
}

#[test]
fn test_session_set_decompression_typed() {
    let session = Session::new().expect("Failed to create session");
    session
        .set_decompression_typed(DecompressionFlags::ALL)
        .expect("Failed to set decompression");
}

#[test]
fn test_session_enable_http_protocol_typed() {
    let session = Session::new().expect("Failed to create session");
    session
        .enable_http_protocol_typed(HttpProtocol::HTTP2)
        .expect("Failed to enable HTTP/2");
}

#[test]
fn test_certificate_info() {
    let session = Session::new().expect("Failed to create session");
    let connection = session
        .connect("httpbin.org", 443)
        .expect("Failed to connect");
    let request = connection
        .request("GET", "/get")
        .secure()
        .build()
        .expect("Failed to build");

    request.send().expect("Failed to send");
    request.receive_response().expect("Failed to receive");

    let cert_info = request
        .certificate_info()
        .expect("Failed to query cert info");
    // httpbin.org has a valid cert, so info should be present
    if let Some(info) = cert_info {
        assert!(!info.subject.is_empty(), "Subject should not be empty");
        assert!(!info.issuer.is_empty(), "Issuer should not be empty");
        assert!(info.key_size > 0, "Key size should be positive");
        println!(
            "Certificate: subject={}, issuer={}, expiry={}, key_size={}",
            info.subject, info.issuer, info.expiry, info.key_size
        );
    }
}

#[test]
fn test_connection_info() {
    let session = Session::new().expect("Failed to create session");
    let connection = session
        .connect("httpbin.org", 443)
        .expect("Failed to connect");
    let request = connection
        .request("GET", "/get")
        .secure()
        .build()
        .expect("Failed to build");

    request.send().expect("Failed to send");
    request.receive_response().expect("Failed to receive");

    let conn_info = request
        .connection_info()
        .expect("Failed to query connection info");
    if let Some(info) = conn_info {
        // Local address should have a non-zero port
        assert_ne!(info.local.port(), 0, "Local port should not be 0");
        // Remote address should be port 443
        assert_eq!(info.remote.port(), 443, "Remote port should be 443");
        println!("Connection: local={}, remote={}", info.local, info.remote);
    }
}

#[test]
fn test_request_times() {
    let session = Session::new().expect("Failed to create session");
    let connection = session
        .connect("httpbin.org", 443)
        .expect("Failed to connect");
    let request = connection
        .request("GET", "/get")
        .secure()
        .build()
        .expect("Failed to build");

    request.send().expect("Failed to send");
    request.receive_response().expect("Failed to receive");

    // request_times() may not be supported on all Windows versions
    match request.request_times() {
        Ok(times) => {
            println!(
                "Times: dns_start={}, dns_end={}, connect_start={}, connect_end={}, send_start={}, send_end={}",
                times.dns_start,
                times.dns_end,
                times.connect_start,
                times.connect_end,
                times.send_start,
                times.send_end
            );
        }
        Err(e) => {
            println!(
                "request_times() not supported (this is OK on some systems): {}",
                e
            );
        }
    }
}

#[test]
fn test_request_stats() {
    let session = Session::new().expect("Failed to create session");
    let connection = session
        .connect("httpbin.org", 443)
        .expect("Failed to connect");
    let request = connection
        .request("GET", "/get")
        .secure()
        .build()
        .expect("Failed to build");

    request.send().expect("Failed to send");
    request.receive_response().expect("Failed to receive");
    let _ = request.read_all().expect("Failed to read body");

    // request_stats() may not be supported on all Windows versions
    match request.request_stats() {
        Ok(stats) => {
            // Just verify we got stats; actual values may vary by implementation
            println!(
                "Stats: connections_opened={}, bytes_sent={}, bytes_received={}, redirects={}",
                stats.connections_opened, stats.bytes_sent, stats.bytes_received, stats.redirects
            );
            // Note: On some systems these may be 0; we just verify the API works
        }
        Err(e) => {
            println!(
                "request_stats() not supported (this is OK on some systems): {}",
                e
            );
        }
    }
}

#[cfg(feature = "async")]
#[test]
fn test_async_response_helpers() {
    // This test verifies that AsyncResponse convenience methods work correctly
    pollster::block_on(async {
        let session = Session::with_config_async(Default::default()).expect("session");
        let connection = session.connect("httpbin.org", 443).expect("connect");
        let request = connection
            .request("GET", "/get")
            .secure()
            .build()
            .expect("build");
        let async_req = request.into_async().expect("into_async");
        let response = async_req.send().await.expect("send");

        let status = response.status_code().expect("status code");
        assert_eq!(status, 200);

        let status_text = response.status_text().expect("status text");
        assert_eq!(status_text, "OK");

        let content_type = response.content_type().expect("content type");
        assert!(content_type.contains("application/json"));

        let headers = response.raw_headers().expect("raw headers");
        assert!(headers.contains("HTTP/"));

        let body = response.read_all().await.expect("read body");
        assert!(!body.is_empty());
    });
}

#[cfg(feature = "async")]
#[test]
fn test_async_response_certificate_info() {
    pollster::block_on(async {
        let session = Session::with_config_async(Default::default()).expect("session");
        let connection = session.connect("httpbin.org", 443).expect("connect");
        let request = connection
            .request("GET", "/get")
            .secure()
            .build()
            .expect("build");
        let async_req = request.into_async().expect("into_async");
        let response = async_req.send().await.expect("send");

        let cert = response.certificate_info().expect("cert info query");
        if let Some(info) = cert {
            assert!(!info.subject.is_empty());
            assert!(!info.issuer.is_empty());
        }

        let _ = response.read_all().await;
    });
}

#[cfg(feature = "async")]
#[test]
fn test_async_response_connection_info() {
    pollster::block_on(async {
        let session = Session::with_config_async(Default::default()).expect("session");
        let connection = session.connect("httpbin.org", 443).expect("connect");
        let request = connection
            .request("GET", "/get")
            .secure()
            .build()
            .expect("build");
        let async_req = request.into_async().expect("into_async");
        let response = async_req.send().await.expect("send");

        let conn = response.connection_info().expect("connection info query");
        if let Some(info) = conn {
            assert_eq!(info.remote.port(), 443);
        }

        let _ = response.read_all().await;
    });
}
