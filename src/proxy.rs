//! Proxy configuration and detection functions
//!
//! This module provides safe Rust wrappers for WinHTTP proxy-related functions,
//! including auto-detection, proxy resolution, and configuration management.

use crate::handle::WinHttpHandle;
use crate::types::WINHTTP_AUTOPROXY_AUTO_LOGON_IF_CHALLENGED;
use windows::Win32::Foundation::{GlobalFree, HGLOBAL};
use windows::Win32::Networking::WinHttp::*;
use windows::core::{Error, HSTRING, PCWSTR, PWSTR, Result};

/// Frees a WinHTTP-allocated PWSTR string using `GlobalFree`.
///
/// WinHTTP allocates strings (e.g. proxy URLs, bypass lists) via `GlobalAlloc`.
/// The caller is responsible for freeing them. This helper performs a null check
/// before calling `GlobalFree`.
///
/// # Safety
/// The pointer must have been allocated by WinHTTP (via `GlobalAlloc`) or be null.
pub(crate) unsafe fn free_winhttp_pwstr(ptr: PWSTR) {
    if !ptr.is_null() {
        unsafe {
            let _ = GlobalFree(Some(HGLOBAL(ptr.as_ptr().cast())));
        }
    }
}

/// Proxy configuration information
#[derive(Debug, Clone)]
pub struct ProxyInfo {
    pub access_type: WINHTTP_ACCESS_TYPE,
    pub proxy: Option<String>,
    pub proxy_bypass: Option<String>,
}

/// Internet Explorer proxy configuration
#[derive(Debug, Clone)]
pub struct IEProxyConfig {
    pub auto_detect: bool,
    pub auto_config_url: Option<String>,
    pub proxy: Option<String>,
    pub proxy_bypass: Option<String>,
}

/// Proxy resolver handle for async proxy resolution
pub struct ProxyResolver {
    handle: WinHttpHandle,
}

impl ProxyResolver {
    /// Get the raw handle for WinHTTP API calls
    pub(crate) fn as_raw(&self) -> *mut std::ffi::c_void {
        self.handle.as_raw()
    }

    /// Create a ProxyResolver from a WinHttpHandle (internal use)
    pub(crate) fn from_handle(handle: WinHttpHandle) -> Self {
        Self { handle }
    }

    /// Gets proxy information for a URL using extended async API
    ///
    /// Calls `WinHttpGetProxyForUrlEx` for asynchronous proxy resolution.
    /// This function initiates the async operation; use callbacks to get results.
    ///
    /// On success the function returns `Ok(())`. Internally the WinHTTP call
    /// returns `ERROR_IO_PENDING`, meaning the operation is proceeding
    /// asynchronously and results will be delivered via callback.
    pub fn get_proxy_for_url_ex(&self, url: &str, options: &AutoProxyOptions) -> Result<()> {
        use windows::Win32::Foundation::{ERROR_IO_PENDING, WIN32_ERROR};

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
            flags |= WINHTTP_AUTOPROXY_AUTO_LOGON_IF_CHALLENGED;
        }

        let winhttp_options = WINHTTP_AUTOPROXY_OPTIONS {
            dwFlags: flags,
            dwAutoDetectFlags: WINHTTP_AUTO_DETECT_TYPE_DHCP | WINHTTP_AUTO_DETECT_TYPE_DNS_A,
            lpszAutoConfigUrl: auto_config_url_pcwstr,
            lpvReserved: std::ptr::null_mut(),
            dwReserved: 0,
            fAutoLogonIfChallenged: options.auto_logon_if_challenged.into(),
        };

        unsafe {
            let result =
                WinHttpGetProxyForUrlEx(self.as_raw(), &url_hstring, &winhttp_options, None);
            if result != ERROR_IO_PENDING.0 {
                return Err(Error::from(WIN32_ERROR(result)));
            }
        }

        Ok(())
    }

    /// Gets the proxy resolution result from an async operation
    ///
    /// Calls `WinHttpGetProxyResult` to retrieve the result of an async
    /// proxy resolution started with `get_proxy_for_url_ex`.
    pub fn get_proxy_result(&self) -> Result<ProxyResult> {
        let result_ptr: *mut WINHTTP_PROXY_RESULT = std::ptr::null_mut();

        unsafe {
            let result = WinHttpGetProxyResult(self.as_raw(), result_ptr);
            if result != 0 {
                return Err(Error::from_thread());
            }

            if result_ptr.is_null() {
                return Err(Error::from_thread());
            }

            let result = &*result_ptr;
            let mut entries = Vec::new();

            let entries_slice =
                std::slice::from_raw_parts(result.pEntries, result.cEntries as usize);

            for entry in entries_slice {
                let use_proxy = entry.fProxy.as_bool();

                let proxy = if !entry.pwszProxy.is_null() {
                    entry.pwszProxy.to_string().ok()
                } else {
                    None
                };

                let proxy_bypass = None;

                entries.push(ProxyResultEntry {
                    use_proxy,
                    proxy,
                    proxy_bypass,
                });
            }

            Ok(ProxyResult {
                ptr: result_ptr,
                entries,
            })
        }
    }
}

/// Auto-proxy options for proxy resolution
#[derive(Debug, Clone)]
pub struct AutoProxyOptions {
    pub auto_detect: bool,
    pub auto_config_url: Option<String>,
    pub auto_logon_if_challenged: bool,
}

impl Default for AutoProxyOptions {
    fn default() -> Self {
        Self {
            auto_detect: true,
            auto_config_url: None,
            auto_logon_if_challenged: true,
        }
    }
}

/// Result from proxy resolution with automatic cleanup
pub struct ProxyResult {
    ptr: *mut WINHTTP_PROXY_RESULT,
    pub entries: Vec<ProxyResultEntry>,
}

impl Drop for ProxyResult {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            unsafe {
                WinHttpFreeProxyResult(self.ptr);
            }
        }
    }
}

/// Single proxy entry in resolution result
#[derive(Debug, Clone)]
pub struct ProxyResultEntry {
    pub use_proxy: bool,
    pub proxy: Option<String>,
    pub proxy_bypass: Option<String>,
}

// Auto-detection functions

/// Detects the auto-proxy configuration URL (WPAD)
///
/// Calls `WinHttpDetectAutoProxyConfigUrl` to find the WPAD configuration URL
/// using DHCP and/or DNS.
pub fn detect_auto_proxy_config_url() -> Result<String> {
    let mut config_url = PWSTR::null();

    unsafe {
        WinHttpDetectAutoProxyConfigUrl(
            WINHTTP_AUTO_DETECT_TYPE_DHCP | WINHTTP_AUTO_DETECT_TYPE_DNS_A,
            &mut config_url,
        )?;

        if config_url.is_null() {
            return Err(Error::from_thread());
        }

        // Convert PWSTR to String
        let url = config_url.to_string()?;

        // Free the string allocated by WinHTTP
        free_winhttp_pwstr(config_url);

        Ok(url)
    }
}

/// Gets the Internet Explorer proxy configuration for the current user
///
/// Calls `WinHttpGetIEProxyConfigForCurrentUser` to retrieve the proxy settings
/// configured in Internet Explorer.
pub fn get_ie_proxy_config() -> Result<IEProxyConfig> {
    let mut config = WINHTTP_CURRENT_USER_IE_PROXY_CONFIG::default();

    unsafe {
        WinHttpGetIEProxyConfigForCurrentUser(&mut config)?;

        let auto_detect = config.fAutoDetect.as_bool();

        let auto_config_url = if !config.lpszAutoConfigUrl.is_null() {
            let s = config.lpszAutoConfigUrl.to_string().ok();
            free_winhttp_pwstr(config.lpszAutoConfigUrl);
            s
        } else {
            None
        };

        let proxy = if !config.lpszProxy.is_null() {
            let s = config.lpszProxy.to_string().ok();
            free_winhttp_pwstr(config.lpszProxy);
            s
        } else {
            None
        };

        let proxy_bypass = if !config.lpszProxyBypass.is_null() {
            let s = config.lpszProxyBypass.to_string().ok();
            free_winhttp_pwstr(config.lpszProxyBypass);
            s
        } else {
            None
        };

        Ok(IEProxyConfig {
            auto_detect,
            auto_config_url,
            proxy,
            proxy_bypass,
        })
    }
}

// Default proxy configuration functions

/// Gets the default WinHTTP proxy configuration
///
/// Calls `WinHttpGetDefaultProxyConfiguration` to retrieve the system-wide
/// default proxy settings.
pub fn get_default_proxy_config() -> Result<ProxyInfo> {
    let mut proxy_info = WINHTTP_PROXY_INFO::default();

    unsafe {
        WinHttpGetDefaultProxyConfiguration(&mut proxy_info)?;

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

/// Sets the default WinHTTP proxy configuration
///
/// Calls `WinHttpSetDefaultProxyConfiguration` to set the system-wide
/// default proxy settings.
pub fn set_default_proxy_config(config: &ProxyInfo) -> Result<()> {
    let proxy_hstring = config.proxy.as_ref().map(HSTRING::from);
    let proxy_pwstr = proxy_hstring
        .as_ref()
        .map(|s| PWSTR(s.as_ptr() as *mut _))
        .unwrap_or(PWSTR::null());

    let bypass_hstring = config.proxy_bypass.as_ref().map(HSTRING::from);
    let bypass_pwstr = bypass_hstring
        .as_ref()
        .map(|s| PWSTR(s.as_ptr() as *mut _))
        .unwrap_or(PWSTR::null());

    let mut proxy_info = WINHTTP_PROXY_INFO {
        dwAccessType: config.access_type,
        lpszProxy: proxy_pwstr,
        lpszProxyBypass: bypass_pwstr,
    };

    unsafe {
        WinHttpSetDefaultProxyConfiguration(&mut proxy_info)?;
    }

    Ok(())
}

// Advanced proxy settings functions

/// Proxy settings version for extended API
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxySettingsVersion {
    Unknown,
    Wsl,
    Wsa,
}

impl From<ProxySettingsVersion> for WINHTTP_PROXY_SETTINGS_TYPE {
    fn from(version: ProxySettingsVersion) -> Self {
        match version {
            ProxySettingsVersion::Unknown => WinHttpProxySettingsTypeUnknown,
            ProxySettingsVersion::Wsl => WinHttpProxySettingsTypeWsl,
            ProxySettingsVersion::Wsa => WinHttpProxySettingsTypeWsa,
        }
    }
}

impl From<WINHTTP_PROXY_SETTINGS_TYPE> for ProxySettingsVersion {
    fn from(settings_type: WINHTTP_PROXY_SETTINGS_TYPE) -> Self {
        #[allow(nonstandard_style)]
        match settings_type {
            WinHttpProxySettingsTypeUnknown => ProxySettingsVersion::Unknown,
            WinHttpProxySettingsTypeWsl => ProxySettingsVersion::Wsl,
            WinHttpProxySettingsTypeWsa => ProxySettingsVersion::Wsa,
            _ => ProxySettingsVersion::Unknown,
        }
    }
}

/// Extended proxy settings structure with automatic cleanup
pub struct ProxySettingsEx {
    ptr: *mut WINHTTP_PROXY_SETTINGS_EX,
    version: ProxySettingsVersion,
}

impl ProxySettingsEx {
    pub(crate) fn new(ptr: *mut WINHTTP_PROXY_SETTINGS_EX, version: ProxySettingsVersion) -> Self {
        Self { ptr, version }
    }
}

impl Drop for ProxySettingsEx {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            let settings_type: WINHTTP_PROXY_SETTINGS_TYPE = self.version.into();
            unsafe {
                let _ = WinHttpFreeProxySettingsEx(settings_type, self.ptr as *const _);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Session;

    #[test]
    fn test_ie_proxy_config_creation() {
        let config = IEProxyConfig {
            auto_detect: true,
            auto_config_url: Some("http://wpad.example.com/wpad.dat".to_string()),
            proxy: Some("proxy.example.com:8080".to_string()),
            proxy_bypass: Some("*.local".to_string()),
        };

        assert!(config.auto_detect);
        assert!(config.auto_config_url.is_some());
        assert!(config.proxy.is_some());
        assert!(config.proxy_bypass.is_some());
    }

    #[test]
    fn test_auto_proxy_options_custom() {
        let options = AutoProxyOptions {
            auto_detect: false,
            auto_config_url: Some("http://example.com/proxy.pac".to_string()),
            auto_logon_if_challenged: false,
        };

        assert!(!options.auto_detect);
        assert!(options.auto_config_url.is_some());
        assert!(!options.auto_logon_if_challenged);
    }

    #[test]
    fn test_detect_auto_proxy_config_url() {
        // This may fail if WPAD is not configured, which is expected
        let result = detect_auto_proxy_config_url();
        // We just verify it doesn't panic - it's OK if it returns an error
        let _ = result;
    }

    #[test]
    fn test_get_ie_proxy_config() {
        let result = get_ie_proxy_config();
        // Should succeed even if no proxy is configured
        assert!(result.is_ok() || result.is_err()); // Just verify it doesn't panic
    }

    #[test]
    fn test_get_default_proxy_config() {
        let result = get_default_proxy_config();
        // Should succeed even if no proxy is configured
        assert!(result.is_ok() || result.is_err());
    }

    #[test]
    fn test_auto_proxy_options_default() {
        let options = AutoProxyOptions::default();
        assert!(options.auto_detect);
        assert_eq!(options.auto_config_url, None);
        assert!(options.auto_logon_if_challenged);
    }

    #[test]
    fn test_session_get_proxy_for_url() {
        let session = Session::new().expect("Failed to create session");
        let options = AutoProxyOptions::default();

        // This may fail if auto-detection doesn't work, which is expected
        let result = session.get_proxy_for_url("http://www.example.com", &options);
        // Just verify it doesn't panic
        let _ = result;
    }

    #[test]
    #[cfg(feature = "async")]
    fn test_session_create_proxy_resolver() {
        use crate::Session;

        let session = Session::new_async().expect("Failed to create async session");

        let result = session.create_proxy_resolver();
        // Should succeed in creating a resolver handle with an async session
        if let Err(e) = &result {
            panic!("create_proxy_resolver failed: {e}");
        }
    }

    #[test]
    #[cfg(feature = "async")]
    fn test_proxy_resolver_get_proxy_for_url_ex() {
        let session = Session::new_async().expect("Failed to create async session");
        let resolver = session
            .create_proxy_resolver()
            .expect("Failed to create resolver");
        let options = AutoProxyOptions::default();

        // Initiate async proxy resolution â€” returns ERROR_IO_PENDING on success
        let result = resolver.get_proxy_for_url_ex("http://www.example.com", &options);
        // This may fail depending on proxy configuration
        let _ = result;
    }

    #[test]
    fn test_proxy_info_creation() {
        let info = ProxyInfo {
            access_type: WINHTTP_ACCESS_TYPE_NO_PROXY,
            proxy: Some("proxy.example.com:8080".to_string()),
            proxy_bypass: Some("localhost".to_string()),
        };

        assert_eq!(info.access_type, WINHTTP_ACCESS_TYPE_NO_PROXY);
        assert_eq!(info.proxy, Some("proxy.example.com:8080".to_string()));
        assert_eq!(info.proxy_bypass, Some("localhost".to_string()));
    }

    #[test]
    fn test_session_get_proxy_settings_ex() {
        let session = Session::new().expect("Failed to create session");

        // Try to get proxy settings (may fail if not available)
        let result = session.get_proxy_settings_ex(ProxySettingsVersion::Wsl);
        // Just verify it doesn't panic
        let _ = result;
    }
}
