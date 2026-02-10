use windows::Win32::Foundation::SYSTEMTIME;
use windows::Win32::Networking::WinHttp::*;
use windows::core::{Error, HSTRING, PWSTR, Result};

#[derive(Debug, Clone)]
pub struct UrlComponents {
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub path: String,
    pub extra_info: String,
}

pub fn crack_url(url: &str) -> Result<UrlComponents> {
    let url_wide: Vec<u16> = url.encode_utf16().chain(std::iter::once(0)).collect();

    let mut scheme_buf = vec![0u16; 256];
    let mut host_buf = vec![0u16; 256];
    let mut path_buf = vec![0u16; 2048];
    let mut extra_buf = vec![0u16; 2048];

    let mut components = URL_COMPONENTS {
        dwStructSize: std::mem::size_of::<URL_COMPONENTS>() as u32,
        lpszScheme: PWSTR(scheme_buf.as_mut_ptr()),
        dwSchemeLength: scheme_buf.len() as u32,
        nScheme: Default::default(),
        lpszHostName: PWSTR(host_buf.as_mut_ptr()),
        dwHostNameLength: host_buf.len() as u32,
        nPort: 0,
        lpszUserName: PWSTR::null(),
        dwUserNameLength: 0,
        lpszPassword: PWSTR::null(),
        dwPasswordLength: 0,
        lpszUrlPath: PWSTR(path_buf.as_mut_ptr()),
        dwUrlPathLength: path_buf.len() as u32,
        lpszExtraInfo: PWSTR(extra_buf.as_mut_ptr()),
        dwExtraInfoLength: extra_buf.len() as u32,
    };

    unsafe {
        WinHttpCrackUrl(&url_wide, 0, &mut components)?;
    }

    let scheme = String::from_utf16_lossy(&scheme_buf[..components.dwSchemeLength as usize]);
    let host = String::from_utf16_lossy(&host_buf[..components.dwHostNameLength as usize]);
    let path = String::from_utf16_lossy(&path_buf[..components.dwUrlPathLength as usize]);
    let extra_info = String::from_utf16_lossy(&extra_buf[..components.dwExtraInfoLength as usize]);

    Ok(UrlComponents {
        scheme,
        host,
        port: components.nPort,
        path,
        extra_info,
    })
}

pub fn create_url(components: &UrlComponents) -> Result<String> {
    let scheme: Vec<u16> = components
        .scheme
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let host: Vec<u16> = components
        .host
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let path: Vec<u16> = components
        .path
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let extra: Vec<u16> = components
        .extra_info
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    let url_components = URL_COMPONENTS {
        dwStructSize: std::mem::size_of::<URL_COMPONENTS>() as u32,
        lpszScheme: PWSTR(scheme.as_ptr() as *mut _),
        dwSchemeLength: (scheme.len() - 1) as u32,
        nScheme: Default::default(),
        lpszHostName: PWSTR(host.as_ptr() as *mut _),
        dwHostNameLength: (host.len() - 1) as u32,
        nPort: components.port,
        lpszUserName: PWSTR::null(),
        dwUserNameLength: 0,
        lpszPassword: PWSTR::null(),
        dwPasswordLength: 0,
        lpszUrlPath: PWSTR(path.as_ptr() as *mut _),
        dwUrlPathLength: (path.len() - 1) as u32,
        lpszExtraInfo: PWSTR(extra.as_ptr() as *mut _),
        dwExtraInfoLength: (extra.len() - 1) as u32,
    };

    let mut url_len = 0u32;
    unsafe {
        let _ = WinHttpCreateUrl(
            &url_components,
            WIN_HTTP_CREATE_URL_FLAGS(0),
            None,
            &mut url_len,
        );

        if url_len == 0 {
            return Err(Error::from_thread());
        }

        let mut url_buf = vec![0u16; url_len as usize + 1];
        WinHttpCreateUrl(
            &url_components,
            WIN_HTTP_CREATE_URL_FLAGS(0),
            Some(PWSTR(url_buf.as_mut_ptr())),
            &mut url_len,
        )?;

        Ok(String::from_utf16_lossy(&url_buf[..url_len as usize]))
    }
}

pub fn check_platform() -> Result<()> {
    unsafe { WinHttpCheckPlatform() }
}

/// Converts a SYSTEMTIME to HTTP time format string (RFC 1123)
pub fn time_from_system_time(system_time: &SYSTEMTIME) -> Result<String> {
    let mut time_buf = [0u16; 62];
    unsafe {
        WinHttpTimeFromSystemTime(system_time as *const _, &mut time_buf)?;
    }

    // Find the null terminator
    let len = time_buf.iter().position(|&c| c == 0).unwrap_or(62);
    Ok(String::from_utf16_lossy(&time_buf[..len]))
}

/// Converts an HTTP time format string (RFC 1123) to SYSTEMTIME
pub fn time_to_system_time(time_str: &str) -> Result<SYSTEMTIME> {
    let time_wide = HSTRING::from(time_str);
    let mut system_time = SYSTEMTIME::default();

    unsafe {
        WinHttpTimeToSystemTime(&time_wide, &mut system_time)?;
    }

    Ok(system_time)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crack_url_http() {
        let result = crack_url("http://example.com:8080/path?query=value");
        assert!(result.is_ok());

        let components = result.unwrap();
        assert_eq!(components.scheme, "http");
        assert_eq!(components.host, "example.com");
        assert_eq!(components.port, 8080);
        assert!(components.path.contains("/path"));
    }

    #[test]
    fn test_crack_url_https() {
        let result = crack_url("https://secure.example.com/api/v1");
        assert!(result.is_ok());

        let components = result.unwrap();
        assert_eq!(components.scheme, "https");
        assert_eq!(components.host, "secure.example.com");
        assert_eq!(components.port, 443);
    }

    #[test]
    fn test_create_url() {
        let components = UrlComponents {
            scheme: "https".to_string(),
            host: "example.com".to_string(),
            port: 443,
            path: "/test".to_string(),
            extra_info: "?foo=bar".to_string(),
        };

        let result = create_url(&components);
        assert!(result.is_ok());

        let url = result.unwrap();
        assert!(url.contains("https"));
        assert!(url.contains("example.com"));
    }

    #[test]
    fn test_check_platform() {
        let result = check_platform();
        assert!(result.is_ok(), "Platform check should succeed on Windows");
    }
}
