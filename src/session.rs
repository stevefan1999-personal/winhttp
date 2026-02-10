use crate::handle::WinHttpHandle;
use crate::proxy::{
    AutoProxyOptions, ProxyInfo, ProxyResolver, ProxySettingsEx, ProxySettingsVersion,
    free_winhttp_pwstr,
};
use std::marker::PhantomData;
use std::sync::Arc;
use windows::Win32::Networking::WinHttp::*;
use windows::core::{Error, GUID, HSTRING, PCWSTR, Result};

#[derive(Debug, Clone)]
pub struct SessionConfig {
    pub user_agent: String,
    pub connect_timeout_ms: u32,
    pub send_timeout_ms: u32,
    pub receive_timeout_ms: u32,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            user_agent: "winhttp-rs/0.1.0".to_string(),
            connect_timeout_ms: 60_000,
            send_timeout_ms: 30_000,
            receive_timeout_ms: 30_000,
        }
    }
}

pub struct Session {
    handle: WinHttpHandle,
    config: Arc<SessionConfig>,
}

impl Session {
    pub fn new() -> Result<Self> {
        Self::with_config(SessionConfig::default())
    }

    pub fn with_config(config: SessionConfig) -> Result<Self> {
        Self::with_config_and_flags(config, 0)
    }

    #[cfg(feature = "async")]
    pub fn new_async() -> Result<Self> {
        Self::with_config_async(SessionConfig::default())
    }

    #[cfg(feature = "async")]
    pub fn with_config_async(config: SessionConfig) -> Result<Self> {
        Self::with_config_and_flags(config, WINHTTP_FLAG_ASYNC)
    }

    fn with_config_and_flags(config: SessionConfig, flags: u32) -> Result<Self> {
        let user_agent = HSTRING::from(&config.user_agent);

        let handle = unsafe {
            WinHttpOpen(
                &user_agent,
                WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                PCWSTR::null(),
                PCWSTR::null(),
                flags,
            )
        };

        let handle = unsafe { WinHttpHandle::from_raw(handle) }.ok_or_else(Error::from_thread)?;

        let session = Self {
            handle,
            config: Arc::new(config),
        };

        session.set_timeouts()?;

        Ok(session)
    }

    fn set_timeouts(&self) -> Result<()> {
        unsafe {
            WinHttpSetTimeouts(
                self.handle.as_raw(),
                0,
                self.config.connect_timeout_ms as i32,
                self.config.send_timeout_ms as i32,
                self.config.receive_timeout_ms as i32,
            )
        }
    }

    pub fn connect<'s>(&'s self, server: &str, port: u16) -> Result<Connection<'s>> {
        let server_name = HSTRING::from(server);

        let handle = unsafe { WinHttpConnect(self.handle.as_raw(), &server_name, port, 0) };

        let handle = unsafe { WinHttpHandle::from_raw(handle) }.ok_or_else(Error::from_thread)?;

        Ok(Connection {
            handle,
            _marker: PhantomData,
        })
    }

    pub fn config(&self) -> &SessionConfig {
        &self.config
    }

    pub fn query_connection_group(
        &self,
        connection_guid: Option<&GUID>,
    ) -> Result<ConnectionGroupResult> {
        let mut result_ptr: *mut WINHTTP_QUERY_CONNECTION_GROUP_RESULT = std::ptr::null_mut();
        let guid_ptr = connection_guid.map(|g| g as *const _);

        let error_code = unsafe {
            WinHttpQueryConnectionGroup(
                self.handle.as_raw(),
                guid_ptr,
                0, // ullflags
                &mut result_ptr,
            )
        };

        if error_code != 0 {
            return Err(Error::from_thread());
        }

        Ok(ConnectionGroupResult { ptr: result_ptr })
    }

    /// Gets proxy information for a specified URL
    ///
    /// Calls `WinHttpGetProxyForUrl` to retrieve proxy settings for a specific URL
    /// based on auto-proxy options.
    pub fn get_proxy_for_url(&self, url: &str, options: &AutoProxyOptions) -> Result<ProxyInfo> {
        let url_hstring = HSTRING::from(url);

        let auto_config_url_hstring = options.auto_config_url.as_ref().map(HSTRING::from);
        let auto_config_url_pcwstr = auto_config_url_hstring
            .as_ref()
            .map(|s| PCWSTR(s.as_ptr()))
            .unwrap_or(PCWSTR::null());

        let mut flags = 0u32;
        if options.auto_detect {
            flags |= WINHTTP_AUTOPROXY_AUTO_DETECT;
        }
        if options.auto_config_url.is_some() {
            flags |= WINHTTP_AUTOPROXY_CONFIG_URL;
        }
        if options.auto_logon_if_challenged {
            flags |= 0x00000100; // WINHTTP_AUTOPROXY_AUTO_LOGON_IF_CHALLENGED
        }

        let mut winhttp_options = WINHTTP_AUTOPROXY_OPTIONS {
            dwFlags: flags,
            dwAutoDetectFlags: WINHTTP_AUTO_DETECT_TYPE_DHCP | WINHTTP_AUTO_DETECT_TYPE_DNS_A,
            lpszAutoConfigUrl: auto_config_url_pcwstr,
            lpvReserved: std::ptr::null_mut(),
            dwReserved: 0,
            fAutoLogonIfChallenged: options.auto_logon_if_challenged.into(),
        };

        let mut proxy_info = WINHTTP_PROXY_INFO::default();

        unsafe {
            WinHttpGetProxyForUrl(
                self.handle.as_raw(),
                &url_hstring,
                &mut winhttp_options as *mut _,
                &mut proxy_info,
            )?;

            let proxy = if !proxy_info.lpszProxy.is_null() {
                let s = proxy_info.lpszProxy.to_string().ok();
                free_winhttp_pwstr(proxy_info.lpszProxy);
                s
            } else {
                None
            };

            let proxy_bypass = if !proxy_info.lpszProxyBypass.is_null() {
                let s = proxy_info.lpszProxyBypass.to_string().ok();
                free_winhttp_pwstr(proxy_info.lpszProxyBypass);
                s
            } else {
                None
            };

            Ok(ProxyInfo {
                access_type: proxy_info.dwAccessType,
                proxy,
                proxy_bypass,
            })
        }
    }

    /// Creates a proxy resolver handle for asynchronous proxy resolution
    ///
    /// Calls `WinHttpCreateProxyResolver` to create a resolver handle.
    ///
    /// **Note:** The session must have been opened with the async flag
    /// (e.g. via [`Session::new_async`] or [`Session::with_config_async`]).
    /// Using a synchronous session will return
    /// `ERROR_WINHTTP_INCORRECT_HANDLE_TYPE`.
    pub fn create_proxy_resolver(&self) -> Result<ProxyResolver> {
        use windows::Win32::Foundation::WIN32_ERROR;

        let mut resolver_handle = std::ptr::null_mut();

        unsafe {
            let result = WinHttpCreateProxyResolver(self.handle.as_raw(), &mut resolver_handle);
            if result != 0 {
                return Err(Error::from(WIN32_ERROR(result)));
            }

            let handle = WinHttpHandle::from_raw(resolver_handle).ok_or_else(Error::from_thread)?;

            Ok(ProxyResolver::from_handle(handle))
        }
    }

    /// Gets extended proxy settings
    ///
    /// Calls `WinHttpGetProxySettingsEx` to retrieve extended proxy configuration.
    /// This is a newer API that provides more detailed proxy settings.
    ///
    /// **Note:** The session must have been opened with the async flag
    /// (e.g. via [`Session::new_async`] or [`Session::with_config_async`]).
    /// The call returns asynchronously via `ERROR_IO_PENDING` on success.
    pub fn get_proxy_settings_ex(&self, version: ProxySettingsVersion) -> Result<ProxySettingsEx> {
        use windows::Win32::Foundation::{ERROR_IO_PENDING, WIN32_ERROR};

        let settings_version: WINHTTP_PROXY_SETTINGS_TYPE = version.into();
        let settings_ptr: *mut WINHTTP_PROXY_SETTINGS_EX = std::ptr::null_mut();

        unsafe {
            let result =
                WinHttpGetProxySettingsEx(self.handle.as_raw(), settings_version, None, None);
            if result != ERROR_IO_PENDING.0 {
                return Err(Error::from(WIN32_ERROR(result)));
            }

            Ok(ProxySettingsEx::new(settings_ptr, version))
        }
    }

    /// Sets an option on the session handle.
    pub fn set_option(&self, option: u32, buffer: &[u8]) -> Result<()> {
        let buf = if buffer.is_empty() {
            None
        } else {
            Some(buffer)
        };
        unsafe { WinHttpSetOption(Some(self.handle.as_raw()), option, buf) }
    }

    /// Queries an option on the session handle.
    pub fn query_option(&self, option: u32) -> Result<Vec<u8>> {
        let mut buffer_len = 0u32;
        let _ = unsafe { WinHttpQueryOption(self.handle.as_raw(), option, None, &mut buffer_len) };

        if buffer_len == 0 {
            return Ok(Vec::new());
        }

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

    /// Sets the allowed secure protocols for this session.
    ///
    /// Use flags like:
    /// - `WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2`
    /// - `WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3`
    /// - `WINHTTP_FLAG_SECURE_PROTOCOL_MODERN` (TLS 1.2 + 1.3)
    /// - `WINHTTP_FLAG_SECURE_PROTOCOL_ALL` (all protocols)
    pub fn set_secure_protocols(&self, flags: u32) -> Result<()> {
        self.set_option(WINHTTP_OPTION_SECURE_PROTOCOLS, &flags.to_ne_bytes())
    }

    /// Sets secure protocols using the type-safe [`SecureProtocol`](crate::SecureProtocol) wrapper.
    pub fn set_secure_protocols_typed(&self, flags: crate::SecureProtocol) -> Result<()> {
        self.set_secure_protocols(flags.bits())
    }

    /// Enables or disables WinHTTP tracing for debugging.
    pub fn enable_tracing(&self, enable: bool) -> Result<()> {
        let value: u32 = if enable { 1 } else { 0 };
        self.set_option(WINHTTP_OPTION_ENABLETRACING, &value.to_ne_bytes())
    }

    /// Sets the maximum number of connections per server for this session.
    pub fn set_max_connections_per_server(&self, max: u32) -> Result<()> {
        self.set_option(WINHTTP_OPTION_MAX_CONNS_PER_SERVER, &max.to_ne_bytes())
    }

    /// Enables automatic decompression for all requests in this session.
    pub fn set_decompression(&self, flags: u32) -> Result<()> {
        self.set_option(WINHTTP_OPTION_DECOMPRESSION, &flags.to_ne_bytes())
    }

    /// Enables decompression using the type-safe [`DecompressionFlags`](crate::DecompressionFlags) wrapper.
    pub fn set_decompression_typed(&self, flags: crate::DecompressionFlags) -> Result<()> {
        self.set_decompression(flags.bits())
    }

    /// Enables HTTP/2 and/or HTTP/3 for all requests in this session.
    pub fn enable_http_protocol(&self, flags: u32) -> Result<()> {
        self.set_option(WINHTTP_OPTION_ENABLE_HTTP_PROTOCOL, &flags.to_ne_bytes())
    }

    /// Enables HTTP protocol(s) using the type-safe [`HttpProtocol`](crate::HttpProtocol) wrapper.
    pub fn enable_http_protocol_typed(&self, protocol: crate::HttpProtocol) -> Result<()> {
        self.enable_http_protocol(protocol.bits())
    }

    /// Resets the auto-proxy subsystem for this session.
    ///
    /// Calls `WinHttpResetAutoProxy` to reset auto-proxy caching, or to force
    /// a re-download of the PAC script.
    ///
    /// The `flags` parameter controls what is reset:
    /// - `WINHTTP_RESET_STATE` (0x00000001) — Reset auto-proxy state
    /// - `WINHTTP_RESET_SWPAD_CURRENT_NETWORK` (0x00000002) — Reset WPAD for current network
    /// - `WINHTTP_RESET_SWPAD_ALL` (0x00000004) — Reset WPAD for all networks
    /// - `WINHTTP_RESET_SCRIPT_CACHE` (0x00000008) — Reset script cache
    /// - `WINHTTP_RESET_ALL` (0x0000FFFF) — Reset everything
    /// - `WINHTTP_RESET_NOTIFY_NETWORK_CHANGED` (0x00010000) — Notify network changed
    /// - `WINHTTP_RESET_OUT_OF_PROC` (0x00020000) — Perform out of process
    pub fn reset_auto_proxy(&self, flags: u32) -> Result<u32> {
        unsafe {
            let result = WinHttpResetAutoProxy(self.handle.as_raw(), flags);
            Ok(result)
        }
    }
}

impl Default for Session {
    fn default() -> Self {
        Self::new().expect("Failed to create default session")
    }
}

pub struct Connection<'session> {
    pub(crate) handle: WinHttpHandle,
    _marker: PhantomData<&'session Session>,
}

pub struct ConnectionGroupResult {
    ptr: *mut WINHTTP_QUERY_CONNECTION_GROUP_RESULT,
}

impl ConnectionGroupResult {
    pub fn as_raw(&self) -> *const WINHTTP_QUERY_CONNECTION_GROUP_RESULT {
        self.ptr
    }
}

impl Drop for ConnectionGroupResult {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            unsafe {
                WinHttpFreeQueryConnectionGroupResult(self.ptr);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_config_default() {
        let config = SessionConfig::default();
        assert_eq!(config.user_agent, "winhttp-rs/0.1.0");
        assert_eq!(config.connect_timeout_ms, 60_000);
        assert_eq!(config.send_timeout_ms, 30_000);
        assert_eq!(config.receive_timeout_ms, 30_000);
    }

    #[test]
    fn test_session_config_custom() {
        let config = SessionConfig {
            user_agent: "custom-agent/1.0".to_string(),
            connect_timeout_ms: 10_000,
            send_timeout_ms: 5_000,
            receive_timeout_ms: 15_000,
        };
        assert_eq!(config.user_agent, "custom-agent/1.0");
        assert_eq!(config.connect_timeout_ms, 10_000);
    }

    #[test]
    fn test_session_config_clone() {
        let config1 = SessionConfig::default();
        let config2 = config1.clone();
        assert_eq!(config1.user_agent, config2.user_agent);
        assert_eq!(config1.connect_timeout_ms, config2.connect_timeout_ms);
    }

    #[test]
    fn test_session_creation() {
        let session = Session::new();
        assert!(
            session.is_ok(),
            "Session creation should succeed on Windows"
        );

        let session = session.unwrap();
        assert_eq!(session.config().user_agent, "winhttp-rs/0.1.0");
    }

    #[test]
    fn test_session_with_custom_config() {
        let config = SessionConfig {
            user_agent: "test-agent/2.0".to_string(),
            connect_timeout_ms: 5_000,
            send_timeout_ms: 3_000,
            receive_timeout_ms: 10_000,
        };

        let session = Session::with_config(config.clone());
        assert!(session.is_ok());

        let session = session.unwrap();
        assert_eq!(session.config().user_agent, "test-agent/2.0");
        assert_eq!(session.config().connect_timeout_ms, 5_000);
    }

    #[test]
    fn test_session_connect() {
        let session = Session::new().expect("Failed to create session");

        let connection = session.connect("example.com", 80);
        assert!(connection.is_ok(), "Connection should succeed");
    }
}
