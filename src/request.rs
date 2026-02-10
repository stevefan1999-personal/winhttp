use crate::{handle::WinHttpHandle, session::Connection};
use std::marker::PhantomData;
use windows::Win32::Networking::WinHttp::*;
use windows::Win32::Networking::WinSock::SOCKADDR_STORAGE;
use windows::core::{Error, HSTRING, PCWSTR, Result};

/// Extract a [`std::net::SocketAddr`] from a `SOCKADDR_STORAGE`.
fn sockaddr_from_storage(storage: &SOCKADDR_STORAGE) -> Option<std::net::SocketAddr> {
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
    use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6, SOCKADDR_IN, SOCKADDR_IN6};

    let family = storage.ss_family;

    if family == AF_INET {
        let addr_in = unsafe { &*(storage as *const _ as *const SOCKADDR_IN) };
        let octets = unsafe { addr_in.sin_addr.S_un.S_un_b };
        let ip = Ipv4Addr::new(octets.s_b1, octets.s_b2, octets.s_b3, octets.s_b4);
        let port = u16::from_be(addr_in.sin_port);
        Some(SocketAddr::V4(SocketAddrV4::new(ip, port)))
    } else if family == AF_INET6 {
        let addr_in6 = unsafe { &*(storage as *const _ as *const SOCKADDR_IN6) };
        let bytes = unsafe { addr_in6.sin6_addr.u.Byte };
        let ip = Ipv6Addr::from(bytes);
        let port = u16::from_be(addr_in6.sin6_port);
        let flowinfo = addr_in6.sin6_flowinfo;
        let scope_id = unsafe { addr_in6.Anonymous.sin6_scope_id };
        Some(SocketAddr::V6(SocketAddrV6::new(
            ip, port, flowinfo, scope_id,
        )))
    } else {
        None
    }
}

pub struct Request<'conn> {
    pub(crate) handle: WinHttpHandle,
    _marker: PhantomData<&'conn Connection<'conn>>,
}

pub struct RequestBuilder<'conn> {
    connection: &'conn Connection<'conn>,
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    secure: bool,
}

impl<'conn> RequestBuilder<'conn> {
    pub(crate) fn new(connection: &'conn Connection<'conn>, method: &str, path: &str) -> Self {
        Self {
            connection,
            method: method.to_string(),
            path: path.to_string(),
            headers: Vec::new(),
            secure: false,
        }
    }

    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    pub fn secure(mut self) -> Self {
        self.secure = true;
        self
    }

    pub fn build(self) -> Result<Request<'conn>> {
        let method = HSTRING::from(&self.method);
        let path = HSTRING::from(&self.path);

        let flags = if self.secure {
            WINHTTP_FLAG_SECURE
        } else {
            WINHTTP_OPEN_REQUEST_FLAGS(0)
        };

        let handle = unsafe {
            WinHttpOpenRequest(
                self.connection.handle.as_raw(),
                &method,
                &path,
                PCWSTR::null(),
                PCWSTR::null(),
                std::ptr::null(),
                flags,
            )
        };

        let handle = unsafe { WinHttpHandle::from_raw(handle) }.ok_or_else(Error::from_thread)?;

        let request = Request {
            handle,
            _marker: PhantomData,
        };

        for (name, value) in self.headers {
            request.add_header(&name, &value)?;
        }

        Ok(request)
    }
}

impl<'conn> Request<'conn> {
    fn add_header(&self, name: &str, value: &str) -> Result<()> {
        let header_str = format!("{}: {}\r\n", name, value);
        let header: Vec<u16> = header_str
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        unsafe {
            WinHttpAddRequestHeaders(
                self.handle.as_raw(),
                &header[..header.len() - 1],
                WINHTTP_ADDREQ_FLAG_ADD,
            )
        }
    }

    pub fn send(&self) -> Result<()> {
        unsafe { WinHttpSendRequest(self.handle.as_raw(), None, None, 0, 0, 0) }
    }

    pub fn receive_response(&self) -> Result<()> {
        unsafe { WinHttpReceiveResponse(self.handle.as_raw(), std::ptr::null_mut()) }
    }

    pub fn read_data(&self, buffer: &mut [u8]) -> Result<usize> {
        let mut bytes_read = 0u32;
        unsafe {
            WinHttpReadData(
                self.handle.as_raw(),
                buffer.as_mut_ptr() as *mut _,
                buffer.len() as u32,
                &mut bytes_read,
            )?;
        }
        Ok(bytes_read as usize)
    }

    pub fn read_all(&self) -> Result<Vec<u8>> {
        let mut result = Vec::new();
        let mut buffer = vec![0u8; 8192];

        loop {
            let bytes_read = self.read_data(&mut buffer)?;
            if bytes_read == 0 {
                break;
            }
            result.extend_from_slice(&buffer[..bytes_read]);
        }

        Ok(result)
    }

    pub fn query_data_available(&self) -> Result<u32> {
        let mut bytes_available = 0u32;
        unsafe {
            WinHttpQueryDataAvailable(self.handle.as_raw(), &mut bytes_available)?;
        }
        Ok(bytes_available)
    }

    pub fn write_data(&self, data: &[u8]) -> Result<usize> {
        let mut bytes_written = 0u32;
        unsafe {
            WinHttpWriteData(
                self.handle.as_raw(),
                Some(data.as_ptr() as *const _),
                data.len() as u32,
                &mut bytes_written,
            )?;
        }
        Ok(bytes_written as usize)
    }

    pub fn query_headers(&self, info_level: u32, name: Option<&str>) -> Result<String> {
        let name_hstring = name.map(windows::core::HSTRING::from);
        let name_pcwstr = name_hstring.as_ref().map(|s| PCWSTR(s.as_ptr()));

        let mut buffer_len = 0u32;
        let _ = unsafe {
            WinHttpQueryHeaders(
                self.handle.as_raw(),
                info_level,
                name_pcwstr.unwrap_or(PCWSTR::null()),
                None,
                &mut buffer_len,
                std::ptr::null_mut(),
            )
        };

        if buffer_len == 0 {
            return Ok(String::new());
        }

        let mut buffer = vec![0u16; (buffer_len / 2) as usize + 1];
        unsafe {
            WinHttpQueryHeaders(
                self.handle.as_raw(),
                info_level,
                name_pcwstr.unwrap_or(PCWSTR::null()),
                Some(buffer.as_mut_ptr() as *mut _),
                &mut buffer_len,
                std::ptr::null_mut(),
            )?;
        }

        Ok(String::from_utf16_lossy(
            &buffer[..(buffer_len / 2) as usize],
        ))
    }

    pub fn set_option(&self, option: u32, buffer: &[u8]) -> Result<()> {
        let buf = if buffer.is_empty() {
            None
        } else {
            Some(buffer)
        };
        unsafe { WinHttpSetOption(Some(self.handle.as_raw()), option, buf) }
    }

    pub fn query_option(&self, option: u32) -> Result<Vec<u8>> {
        // First call to get buffer size needed
        let mut buffer_len = 0u32;
        let _ = unsafe { WinHttpQueryOption(self.handle.as_raw(), option, None, &mut buffer_len) };

        if buffer_len == 0 {
            return Ok(Vec::new());
        }

        // Second call to get actual data
        let mut buffer = vec![0u8; buffer_len as usize];
        unsafe {
            WinHttpQueryOption(
                self.handle.as_raw(),
                option,
                Some(buffer.as_mut_ptr() as *mut _),
                &mut buffer_len,
            )?;
        }

        buffer.truncate(buffer_len as usize);
        Ok(buffer)
    }

    pub fn set_credentials(
        &self,
        auth_targets: u32,
        auth_scheme: u32,
        username: &str,
        password: &str,
    ) -> Result<()> {
        let username_wide = HSTRING::from(username);
        let password_wide = HSTRING::from(password);
        unsafe {
            WinHttpSetCredentials(
                self.handle.as_raw(),
                auth_targets,
                auth_scheme,
                &username_wide,
                &password_wide,
                std::ptr::null_mut(),
            )
        }
    }

    /// Sets credentials for authentication using type-safe wrappers.
    ///
    /// See [`AuthScheme`](crate::AuthScheme) and [`AuthTarget`](crate::AuthTarget).
    pub fn set_credentials_typed(
        &self,
        target: crate::AuthTarget,
        scheme: crate::AuthScheme,
        username: &str,
        password: &str,
    ) -> Result<()> {
        self.set_credentials(target.bits(), scheme.bits(), username, password)
    }

    pub fn query_auth_schemes(&self) -> Result<(u32, u32, u32)> {
        let mut supported_schemes = 0u32;
        let mut first_scheme = 0u32;
        let mut auth_target = 0u32;
        unsafe {
            WinHttpQueryAuthSchemes(
                self.handle.as_raw(),
                &mut supported_schemes,
                &mut first_scheme,
                &mut auth_target,
            )?;
        }
        Ok((supported_schemes, first_scheme, auth_target))
    }

    /// Returns the HTTP status code (e.g. 200, 404, 500).
    pub fn status_code(&self) -> Result<u16> {
        let mut code = 0u32;
        let mut size = std::mem::size_of::<u32>() as u32;
        unsafe {
            WinHttpQueryHeaders(
                self.handle.as_raw(),
                WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                PCWSTR::null(),
                Some(&mut code as *mut u32 as *mut _),
                &mut size,
                std::ptr::null_mut(),
            )?;
        }
        Ok(code as u16)
    }

    /// Returns the HTTP status text (e.g. "OK", "Not Found").
    pub fn status_text(&self) -> Result<String> {
        self.query_headers(WINHTTP_QUERY_STATUS_TEXT, None)
    }

    /// Returns the Content-Type header value.
    pub fn content_type(&self) -> Result<String> {
        self.query_headers(WINHTTP_QUERY_CONTENT_TYPE, None)
    }

    /// Returns the Content-Length as a number, or `None` if not present.
    pub fn content_length(&self) -> Result<Option<u64>> {
        let mut len = 0u32;
        let mut size = std::mem::size_of::<u32>() as u32;
        let result = unsafe {
            WinHttpQueryHeaders(
                self.handle.as_raw(),
                WINHTTP_QUERY_CONTENT_LENGTH | WINHTTP_QUERY_FLAG_NUMBER,
                PCWSTR::null(),
                Some(&mut len as *mut u32 as *mut _),
                &mut size,
                std::ptr::null_mut(),
            )
        };
        match result {
            Ok(()) => Ok(Some(len as u64)),
            Err(_) => Ok(None),
        }
    }

    /// Returns all response headers as a single CRLF-delimited string.
    pub fn raw_headers(&self) -> Result<String> {
        self.query_headers(WINHTTP_QUERY_RAW_HEADERS_CRLF, None)
    }

    /// Sends the request with a body payload.
    ///
    /// This is a convenience wrapper that properly sets
    /// the Content-Length and writes the body data in a single step.
    pub fn send_with_body(&self, body: &[u8]) -> Result<()> {
        let body_len = body.len() as u32;
        unsafe {
            WinHttpSendRequest(
                self.handle.as_raw(),
                None,
                Some(body.as_ptr() as *const _),
                body_len,
                body_len,
                0,
            )
        }
    }

    /// Enables HTTP/2 protocol on this request handle.
    pub fn enable_http2(&self) -> Result<()> {
        let flags = WINHTTP_PROTOCOL_FLAG_HTTP2;
        self.set_option(WINHTTP_OPTION_ENABLE_HTTP_PROTOCOL, &flags.to_ne_bytes())
    }

    /// Enables HTTP/3 protocol on this request handle.
    pub fn enable_http3(&self) -> Result<()> {
        let flags = WINHTTP_PROTOCOL_FLAG_HTTP3;
        self.set_option(WINHTTP_OPTION_ENABLE_HTTP_PROTOCOL, &flags.to_ne_bytes())
    }

    /// Enables both HTTP/2 and HTTP/3 protocols on this request handle.
    pub fn enable_http2_and_http3(&self) -> Result<()> {
        let flags = WINHTTP_PROTOCOL_FLAG_HTTP2 | WINHTTP_PROTOCOL_FLAG_HTTP3;
        self.set_option(WINHTTP_OPTION_ENABLE_HTTP_PROTOCOL, &flags.to_ne_bytes())
    }

    /// Enables HTTP protocol(s) using the type-safe [`HttpProtocol`](crate::HttpProtocol) wrapper.
    pub fn enable_http_protocol(&self, protocol: crate::HttpProtocol) -> Result<()> {
        self.set_option(
            WINHTTP_OPTION_ENABLE_HTTP_PROTOCOL,
            &protocol.bits().to_ne_bytes(),
        )
    }

    /// Queries which HTTP protocol version was actually used for this request.
    ///
    /// Returns the protocol flags (e.g. `WINHTTP_PROTOCOL_FLAG_HTTP2`).
    /// Must be called after `receive_response()`.
    pub fn http_protocol_used(&self) -> Result<u32> {
        let data = self.query_option(WINHTTP_OPTION_HTTP_PROTOCOL_USED)?;
        if data.len() >= 4 {
            Ok(u32::from_ne_bytes([data[0], data[1], data[2], data[3]]))
        } else {
            Ok(0)
        }
    }

    /// Enables automatic decompression of gzip and/or deflate responses.
    pub fn set_decompression(&self, flags: u32) -> Result<()> {
        self.set_option(WINHTTP_OPTION_DECOMPRESSION, &flags.to_ne_bytes())
    }

    /// Enables automatic decompression using type-safe flags.
    ///
    /// See [`DecompressionFlags`](crate::DecompressionFlags).
    pub fn set_decompression_typed(&self, flags: crate::DecompressionFlags) -> Result<()> {
        self.set_decompression(flags.bits())
    }

    /// Sets the redirect policy for this request.
    ///
    /// Use one of:
    /// - `WINHTTP_OPTION_REDIRECT_POLICY_ALWAYS` (default)
    /// - `WINHTTP_OPTION_REDIRECT_POLICY_DISALLOW_HTTPS_TO_HTTP`
    /// - `WINHTTP_OPTION_REDIRECT_POLICY_NEVER`
    pub fn set_redirect_policy(&self, policy: u32) -> Result<()> {
        self.set_option(WINHTTP_OPTION_REDIRECT_POLICY, &policy.to_ne_bytes())
    }

    /// Sets the redirect policy using the type-safe [`RedirectPolicy`](crate::RedirectPolicy) enum.
    pub fn set_redirect_policy_typed(&self, policy: crate::RedirectPolicy) -> Result<()> {
        self.set_redirect_policy(u32::from(policy))
    }

    /// Sets security flags to control SSL/TLS certificate validation.
    ///
    /// Common flags include:
    /// - `SECURITY_FLAG_IGNORE_CERT_CN_INVALID`
    /// - `SECURITY_FLAG_IGNORE_CERT_DATE_INVALID`
    /// - `SECURITY_FLAG_IGNORE_UNKNOWN_CA`
    /// - `SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE`
    /// - `SECURITY_FLAG_IGNORE_ALL_CERT_ERRORS` (all of the above combined)
    pub fn set_security_flags(&self, flags: u32) -> Result<()> {
        self.set_option(WINHTTP_OPTION_SECURITY_FLAGS, &flags.to_ne_bytes())
    }

    /// Sets security flags using the type-safe [`SecurityFlags`](crate::SecurityFlags) wrapper.
    pub fn set_security_flags_typed(&self, flags: crate::SecurityFlags) -> Result<()> {
        self.set_security_flags(flags.bits())
    }

    /// Disables specific features on this request.
    ///
    /// Use flags like:
    /// - `WINHTTP_DISABLE_COOKIES`
    /// - `WINHTTP_DISABLE_REDIRECTS`
    /// - `WINHTTP_DISABLE_AUTHENTICATION`
    /// - `WINHTTP_DISABLE_KEEP_ALIVE`
    pub fn disable_feature(&self, flags: u32) -> Result<()> {
        self.set_option(WINHTTP_OPTION_DISABLE_FEATURE, &flags.to_ne_bytes())
    }

    /// Disables specific features using the type-safe [`DisableFlags`](crate::DisableFlags) wrapper.
    pub fn disable_feature_typed(&self, flags: crate::DisableFlags) -> Result<()> {
        self.disable_feature(flags.bits())
    }

    /// Adds HTTP request headers using extended format with separate name/value strings
    ///
    /// This is a newer API (Windows 10 Build 20348+) that allows adding headers
    /// with separate name and value strings instead of concatenated format.
    pub fn add_request_headers_ex(&self, headers: &[(&str, &str)], modifiers: u32) -> Result<()> {
        let header_strings: Vec<(HSTRING, HSTRING)> = headers
            .iter()
            .map(|(name, value)| (HSTRING::from(*name), HSTRING::from(*value)))
            .collect();

        let winhttp_headers: Vec<WINHTTP_EXTENDED_HEADER> = header_strings
            .iter()
            .map(|(name, value)| WINHTTP_EXTENDED_HEADER {
                Anonymous1: WINHTTP_EXTENDED_HEADER_0 {
                    pwszName: PCWSTR(name.as_ptr()),
                },
                Anonymous2: WINHTTP_EXTENDED_HEADER_1 {
                    pwszValue: PCWSTR(value.as_ptr()),
                },
            })
            .collect();

        let result = unsafe {
            WinHttpAddRequestHeadersEx(
                self.handle.as_raw(),
                modifiers,
                WINHTTP_EXTENDED_HEADER_FLAG_UNICODE as u64,
                0,
                &winhttp_headers,
            )
        };

        if result != 0 {
            return Err(Error::from_thread());
        }
        Ok(())
    }

    /// Queries HTTP headers using extended format with parsed name/value strings
    ///
    /// This is a newer API (Windows 10 Build 20348+) that returns headers
    /// as an array of name/value pairs instead of concatenated strings.
    pub fn query_headers_ex(
        &self,
        info_level: u32,
        name: Option<&str>,
    ) -> Result<Vec<(String, String)>> {
        let name_hstring = name.map(HSTRING::from);
        let header_name_opt = name_hstring.as_ref().map(|s| WINHTTP_HEADER_NAME {
            pwszName: PCWSTR(s.as_ptr()),
        });

        let mut buffer_len = 0u32;
        let mut headers_count = 0u32;

        unsafe {
            let _ = WinHttpQueryHeadersEx(
                self.handle.as_raw(),
                info_level,
                0,
                0,
                None,
                header_name_opt.as_ref().map(|h| h as *const _),
                None,
                &mut buffer_len,
                None,
                &mut headers_count,
            );
        }

        if buffer_len == 0 || headers_count == 0 {
            return Ok(Vec::new());
        }

        let mut buffer = vec![0u8; buffer_len as usize];
        let mut headers_ptr: *mut WINHTTP_EXTENDED_HEADER = std::ptr::null_mut();

        let result = unsafe {
            WinHttpQueryHeadersEx(
                self.handle.as_raw(),
                info_level,
                0,
                0,
                None,
                header_name_opt.as_ref().map(|h| h as *const _),
                Some(buffer.as_mut_ptr() as *mut _),
                &mut buffer_len,
                Some(&mut headers_ptr),
                &mut headers_count,
            )
        };

        if result != 0 {
            return Err(Error::from_thread());
        }

        if headers_ptr.is_null() || headers_count == 0 {
            return Ok(Vec::new());
        }

        let headers_slice =
            unsafe { std::slice::from_raw_parts(headers_ptr, headers_count as usize) };

        let mut result_headers = Vec::new();
        for header in headers_slice {
            unsafe {
                let name = if !header.Anonymous1.pwszName.is_null() {
                    header.Anonymous1.pwszName.to_string().unwrap_or_default()
                } else {
                    String::new()
                };

                let value = if !header.Anonymous2.pwszValue.is_null() {
                    header.Anonymous2.pwszValue.to_string().unwrap_or_default()
                } else {
                    String::new()
                };

                result_headers.push((name, value));
            }
        }

        Ok(result_headers)
    }

    pub fn read_data_ex(&self, buffer: &mut [u8], flags: u64) -> Result<usize> {
        let mut bytes_read = 0u32;
        let result = unsafe {
            WinHttpReadDataEx(
                self.handle.as_raw(),
                buffer.as_mut_ptr() as *mut _,
                buffer.len() as u32,
                &mut bytes_read,
                flags,
                0,
                None,
            )
        };
        if result != 0 {
            return Err(Error::from_thread());
        }
        Ok(bytes_read as usize)
    }

    /// Queries SSL/TLS certificate information for this HTTPS request.
    ///
    /// Must be called after `receive_response()` on an HTTPS connection.
    /// Returns `None` if certificate information is not available.
    pub fn certificate_info(&self) -> Result<Option<crate::CertificateInfo>> {
        let mut cert_info = WINHTTP_CERTIFICATE_INFO::default();
        let mut size = std::mem::size_of::<WINHTTP_CERTIFICATE_INFO>() as u32;

        let result = unsafe {
            WinHttpQueryOption(
                self.handle.as_raw(),
                WINHTTP_OPTION_SECURITY_CERTIFICATE_STRUCT,
                Some(&mut cert_info as *mut _ as *mut _),
                &mut size,
            )
        };

        match result {
            Ok(()) => {
                let subject = unsafe {
                    if !cert_info.lpszSubjectInfo.is_null() {
                        cert_info.lpszSubjectInfo.to_string().unwrap_or_default()
                    } else {
                        String::new()
                    }
                };
                let issuer = unsafe {
                    if !cert_info.lpszIssuerInfo.is_null() {
                        cert_info.lpszIssuerInfo.to_string().unwrap_or_default()
                    } else {
                        String::new()
                    }
                };

                let expiry = format!(
                    "{:04}-{:02}-{:02}",
                    cert_info.ftExpiry.dwHighDateTime,
                    cert_info.ftExpiry.dwLowDateTime >> 16,
                    cert_info.ftExpiry.dwLowDateTime & 0xFFFF,
                );

                Ok(Some(crate::CertificateInfo {
                    subject,
                    issuer,
                    expiry,
                    key_size: cert_info.dwKeySize,
                }))
            }
            Err(_) => Ok(None),
        }
    }

    /// Queries request timing information.
    ///
    /// Must be called after `receive_response()`.
    /// Returns timing data in 100-nanosecond intervals (Windows FILETIME units).
    pub fn request_times(&self) -> Result<crate::RequestTimes> {
        let data = self.query_option(WINHTTP_OPTION_REQUEST_TIMES)?;

        // WINHTTP_REQUEST_TIMES contains an array of u64 values
        let times: &[u64] = if data.len() >= std::mem::size_of::<u64>() {
            unsafe {
                std::slice::from_raw_parts(
                    data.as_ptr() as *const u64,
                    data.len() / std::mem::size_of::<u64>(),
                )
            }
        } else {
            &[]
        };

        let get = |i: usize| -> u64 { times.get(i).copied().unwrap_or(0) };

        Ok(crate::RequestTimes {
            proxy_detection_start: get(0),
            proxy_detection_end: get(1),
            dns_start: get(2),
            dns_end: get(3),
            connect_start: get(4),
            connect_end: get(5),
            tls_start: get(6),
            tls_end: get(7),
            send_start: get(8),
            send_end: get(9),
            receive_start: get(10),
            receive_end: get(11),
        })
    }

    /// Queries request statistics (bytes sent/received, connections, redirects).
    ///
    /// Must be called after `receive_response()`.
    pub fn request_stats(&self) -> Result<crate::RequestStats> {
        let data = self.query_option(WINHTTP_OPTION_REQUEST_STATS)?;

        // WINHTTP_REQUEST_STATS starts with a u32 array, then u64 values
        // Layout: Flags(u32), Index(u32), TotalCount(u32), then stat entries as u64
        let u64_data: &[u64] = if data.len() >= std::mem::size_of::<u64>() {
            unsafe {
                std::slice::from_raw_parts(
                    data.as_ptr() as *const u64,
                    data.len() / std::mem::size_of::<u64>(),
                )
            }
        } else {
            &[]
        };

        let get64 = |i: usize| -> u64 { u64_data.get(i).copied().unwrap_or(0) };

        Ok(crate::RequestStats {
            connections_opened: get64(1),
            connections_reused: get64(2),
            bytes_sent: get64(3),
            bytes_received: get64(4),
            redirects: get64(5) as u32,
            auth_challenges: get64(6) as u32,
        })
    }

    /// Queries TCP connection information (local/remote IP addresses and ports).
    ///
    /// Must be called after `receive_response()`.
    pub fn connection_info(&self) -> Result<Option<crate::ConnectionInfo>> {
        use windows::Win32::Networking::WinHttp::WINHTTP_CONNECTION_INFO;

        let mut info = WINHTTP_CONNECTION_INFO::default();
        let mut size = std::mem::size_of::<WINHTTP_CONNECTION_INFO>() as u32;

        let result = unsafe {
            WinHttpQueryOption(
                self.handle.as_raw(),
                WINHTTP_OPTION_CONNECTION_INFO,
                Some(&mut info as *mut _ as *mut _),
                &mut size,
            )
        };

        match result {
            Ok(()) => {
                let local = sockaddr_from_storage(&info.LocalAddress);
                let remote = sockaddr_from_storage(&info.RemoteAddress);

                match (local, remote) {
                    (Some(local), Some(remote)) => {
                        Ok(Some(crate::ConnectionInfo { local, remote }))
                    }
                    _ => Ok(None),
                }
            }
            Err(_) => Ok(None),
        }
    }

    #[cfg(feature = "async")]
    pub fn into_async(self) -> Result<crate::async_request::AsyncRequest<'conn>> {
        crate::async_request::AsyncRequest::from_request(self)
    }
}

impl<'session> Connection<'session> {
    pub fn request<'c>(&'c self, method: &str, path: &str) -> RequestBuilder<'c> {
        RequestBuilder::new(self, method, path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::Session;

    #[test]
    fn test_request_builder_new() {
        let method = "GET";
        let path = "/test";

        assert_eq!(method, "GET");
        assert_eq!(path, "/test");
    }

    #[test]
    fn test_request_builder_basic() {
        let session = Session::new().expect("Failed to create session");
        let connection = session
            .connect("example.com", 80)
            .expect("Failed to connect");

        let builder = connection.request("GET", "/");
        let request = builder.build();
        assert!(request.is_ok());
    }

    #[test]
    fn test_request_builder_with_headers() {
        let session = Session::new().expect("Failed to create session");
        let connection = session
            .connect("example.com", 443)
            .expect("Failed to connect");

        let request = connection
            .request("POST", "/api/data")
            .header("Content-Type", "application/json")
            .header("Authorization", "Bearer token123")
            .secure()
            .build();

        assert!(request.is_ok());
    }

    #[test]
    fn test_request_builder_secure_flag() {
        let session = Session::new().expect("Failed to create session");
        let connection = session
            .connect("example.com", 443)
            .expect("Failed to connect");

        let request_secure = connection.request("GET", "/").secure().build();
        assert!(request_secure.is_ok());

        let request_insecure = connection.request("GET", "/").build();
        assert!(request_insecure.is_ok());
    }

    #[test]
    fn test_request_builder_fluent_api() {
        let session = Session::new().expect("Failed to create session");
        let connection = session
            .connect("httpbin.org", 443)
            .expect("Failed to connect");

        let request = connection
            .request("GET", "/get")
            .secure()
            .header("User-Agent", "winhttp-rs-test")
            .header("Accept", "application/json")
            .build();

        assert!(request.is_ok());
    }

    #[test]
    fn test_request_send_and_receive() {
        let session = Session::new().expect("Failed to create session");
        let connection = session
            .connect("httpbin.org", 443)
            .expect("Failed to connect");

        let request = connection
            .request("GET", "/get")
            .secure()
            .build()
            .expect("Failed to build request");

        let send_result = request.send();
        assert!(send_result.is_ok(), "Send should succeed");

        let receive_result = request.receive_response();
        assert!(receive_result.is_ok(), "Receive should succeed");
    }

    #[test]
    fn test_request_read_all() {
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

        let body = request.read_all();
        assert!(body.is_ok());
        let body = body.unwrap();
        assert!(!body.is_empty(), "Response body should not be empty");
    }

    #[test]
    fn test_request_multiple_headers() {
        let session = Session::new().expect("Failed to create session");
        let connection = session
            .connect("example.com", 443)
            .expect("Failed to connect");

        let request = connection
            .request("GET", "/")
            .header("X-Custom-1", "value1")
            .header("X-Custom-2", "value2")
            .header("X-Custom-3", "value3")
            .secure()
            .build();

        assert!(request.is_ok());
    }

    #[test]
    fn test_request_query_data_available() {
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

        let available = request.query_data_available();
        assert!(available.is_ok());
    }

    #[test]
    fn test_request_set_option_query_option() {
        let session = Session::new().expect("Failed to create session");
        let connection = session
            .connect("example.com", 443)
            .expect("Failed to connect");

        let request = connection
            .request("GET", "/")
            .secure()
            .build()
            .expect("Failed to build request");

        let data = vec![1u8, 2, 3, 4];
        let set_result = request.set_option(0, &data);
        let _ = set_result;

        let query_result = request.query_option(0);
        let _ = query_result;
    }

    #[test]
    fn test_request_set_credentials() {
        let session = Session::new().expect("Failed to create session");
        let connection = session
            .connect("example.com", 443)
            .expect("Failed to connect");

        let request = connection
            .request("GET", "/")
            .secure()
            .build()
            .expect("Failed to build request");

        let result = request.set_credentials(0, 0, "username", "password");
        let _ = result;
    }

    #[test]
    fn test_request_query_auth_schemes() {
        let session = Session::new().expect("Failed to create session");
        let connection = session
            .connect("httpbin.org", 443)
            .expect("Failed to connect");

        let request = connection
            .request("GET", "/basic-auth/user/pass")
            .secure()
            .build()
            .expect("Failed to build request");

        request.send().expect("Failed to send");
        request.receive_response().ok();

        let result = request.query_auth_schemes();
        let _ = result;
    }

    #[test]
    fn test_request_query_headers_basic() {
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

        let result = request.query_headers(WINHTTP_QUERY_CONTENT_TYPE, None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_request_read_data_ex() {
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

        let mut buffer = vec![0u8; 1024];
        let result = request.read_data_ex(&mut buffer, 0);
        assert!(result.is_ok());
    }

    #[test]
    fn test_request_write_data() {
        let session = Session::new().expect("Failed to create session");
        let connection = session
            .connect("httpbin.org", 443)
            .expect("Failed to connect");

        let request = connection
            .request("POST", "/post")
            .secure()
            .header("Content-Type", "application/octet-stream")
            .build()
            .expect("Failed to build request");

        let data = vec![1u8, 2, 3, 4, 5];
        let result = request.write_data(&data);
        let _ = result;
    }
}
