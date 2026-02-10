//! Re-exports of all WinHTTP constants, types, flags, and enumerations.
//!
//! This module makes the full WinHTTP API surface available without requiring
//! users to depend on the `windows` crate directly. Constants are grouped
//! by category for discoverability.
//!
//! ## Type-safe flag types
//!
//! In addition to raw `u32` constants, this module provides type-safe wrappers
//! for commonly used flag groups:
//!
//! - [`AuthScheme`] â€” Authentication schemes (Basic, Digest, NTLM, Negotiate, Passport)
//! - [`AuthTarget`] â€” Authentication targets (Server, Proxy)
//! - [`SecurityFlags`] â€” SSL/TLS certificate validation flags
//! - [`DecompressionFlags`] â€” Response decompression (gzip, deflate)
//! - [`RedirectPolicy`] â€” Redirect behavior control
//! - [`HttpProtocol`] â€” HTTP protocol version flags (HTTP/2, HTTP/3)
//! - [`SecureProtocol`] â€” TLS protocol version flags
//! - [`DisableFlags`] â€” Feature disable flags (cookies, redirects, auth, keep-alive)
//!
//! All flag types implement bitwise OR (`|`, `|=`) and AND (`&`, `&=`) and
//! convert to/from `u32` via [`From`]/[`Into`].

// Re-export the underlying `windows` crate so users can access raw types when
// needed (e.g. `HSTRING`, `PCWSTR`, `Error`, `Result`).
pub use windows::Win32::Foundation::SYSTEMTIME;
pub use windows::core::{Error as WinError, HSTRING, PCWSTR, Result as WinResult};

pub use windows::Win32::Networking::WinHttp::{
    // Structures
    HTTP_VERSION_INFO,
    // Security flag constants (for WINHTTP_OPTION_SECURITY_FLAGS)
    SECURITY_FLAG_IGNORE_CERT_CN_INVALID,
    SECURITY_FLAG_IGNORE_CERT_DATE_INVALID,
    SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE,
    SECURITY_FLAG_IGNORE_UNKNOWN_CA,

    URL_COMPONENTS,
    // Create URL flags
    WIN_HTTP_CREATE_URL_FLAGS,
    // Access type constants
    WINHTTP_ACCESS_TYPE,
    WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
    WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
    WINHTTP_ACCESS_TYPE_NAMED_PROXY,
    WINHTTP_ACCESS_TYPE_NO_PROXY,

    // Add request header flags (WINHTTP_ADDREQ_FLAG_*)
    WINHTTP_ADDREQ_FLAG_ADD,
    WINHTTP_ADDREQ_FLAG_ADD_IF_NEW,
    WINHTTP_ADDREQ_FLAG_COALESCE,
    WINHTTP_ADDREQ_FLAG_COALESCE_WITH_COMMA,
    WINHTTP_ADDREQ_FLAG_COALESCE_WITH_SEMICOLON,
    WINHTTP_ADDREQ_FLAG_REPLACE,

    WINHTTP_ASYNC_RESULT,
    // Authentication scheme constants
    WINHTTP_AUTH_SCHEME_BASIC,
    WINHTTP_AUTH_SCHEME_DIGEST,
    WINHTTP_AUTH_SCHEME_NEGOTIATE,
    WINHTTP_AUTH_SCHEME_NTLM,
    WINHTTP_AUTH_SCHEME_PASSPORT,

    // Authentication target constants
    WINHTTP_AUTH_TARGET_PROXY,
    WINHTTP_AUTH_TARGET_SERVER,

    WINHTTP_AUTO_DETECT_TYPE_DHCP,
    WINHTTP_AUTO_DETECT_TYPE_DNS_A,

    // Autologon policy constants (for WINHTTP_OPTION_AUTOLOGON_POLICY)
    WINHTTP_AUTOLOGON_SECURITY_LEVEL_HIGH,
    WINHTTP_AUTOLOGON_SECURITY_LEVEL_LOW,
    WINHTTP_AUTOLOGON_SECURITY_LEVEL_MEDIUM,

    // Auto-proxy constants
    WINHTTP_AUTOPROXY_AUTO_DETECT,
    WINHTTP_AUTOPROXY_CONFIG_URL,
    WINHTTP_AUTOPROXY_OPTIONS,
    // Callback notification flag constants (WINHTTP_CALLBACK_FLAG_*)
    WINHTTP_CALLBACK_FLAG_ALL_NOTIFICATIONS,
    WINHTTP_CALLBACK_FLAG_DATA_AVAILABLE,
    WINHTTP_CALLBACK_FLAG_GETPROXYFORURL_COMPLETE,
    WINHTTP_CALLBACK_FLAG_HEADERS_AVAILABLE,
    WINHTTP_CALLBACK_FLAG_INTERMEDIATE_RESPONSE,
    WINHTTP_CALLBACK_FLAG_READ_COMPLETE,
    WINHTTP_CALLBACK_FLAG_REDIRECT,
    WINHTTP_CALLBACK_FLAG_REQUEST_ERROR,
    WINHTTP_CALLBACK_FLAG_SECURE_FAILURE,
    WINHTTP_CALLBACK_FLAG_SENDREQUEST_COMPLETE,
    WINHTTP_CALLBACK_FLAG_WRITE_COMPLETE,

    // Callback status constants (WINHTTP_CALLBACK_STATUS_*)
    WINHTTP_CALLBACK_STATUS_CLOSE_COMPLETE,
    WINHTTP_CALLBACK_STATUS_CLOSING_CONNECTION,
    WINHTTP_CALLBACK_STATUS_CONNECTED_TO_SERVER,
    WINHTTP_CALLBACK_STATUS_CONNECTING_TO_SERVER,
    WINHTTP_CALLBACK_STATUS_CONNECTION_CLOSED,
    WINHTTP_CALLBACK_STATUS_DATA_AVAILABLE,
    // Secure failure flag constants (sub-flags of WINHTTP_CALLBACK_STATUS_SECURE_FAILURE)
    WINHTTP_CALLBACK_STATUS_FLAG_CERT_CN_INVALID,
    WINHTTP_CALLBACK_STATUS_FLAG_CERT_DATE_INVALID,
    WINHTTP_CALLBACK_STATUS_FLAG_CERT_REV_FAILED,
    WINHTTP_CALLBACK_STATUS_FLAG_CERT_REVOKED,
    WINHTTP_CALLBACK_STATUS_FLAG_INVALID_CA,
    WINHTTP_CALLBACK_STATUS_FLAG_INVALID_CERT,
    WINHTTP_CALLBACK_STATUS_FLAG_SECURITY_CHANNEL_ERROR,

    WINHTTP_CALLBACK_STATUS_GETPROXYFORURL_COMPLETE,
    WINHTTP_CALLBACK_STATUS_HANDLE_CLOSING,
    WINHTTP_CALLBACK_STATUS_HANDLE_CREATED,
    WINHTTP_CALLBACK_STATUS_HEADERS_AVAILABLE,
    WINHTTP_CALLBACK_STATUS_INTERMEDIATE_RESPONSE,
    WINHTTP_CALLBACK_STATUS_NAME_RESOLVED,
    WINHTTP_CALLBACK_STATUS_READ_COMPLETE,
    WINHTTP_CALLBACK_STATUS_RECEIVING_RESPONSE,
    WINHTTP_CALLBACK_STATUS_REDIRECT,
    WINHTTP_CALLBACK_STATUS_REQUEST_ERROR,
    WINHTTP_CALLBACK_STATUS_REQUEST_SENT,
    WINHTTP_CALLBACK_STATUS_RESOLVING_NAME,
    WINHTTP_CALLBACK_STATUS_RESPONSE_RECEIVED,
    WINHTTP_CALLBACK_STATUS_SECURE_FAILURE,
    WINHTTP_CALLBACK_STATUS_SENDING_REQUEST,
    WINHTTP_CALLBACK_STATUS_SENDREQUEST_COMPLETE,
    WINHTTP_CALLBACK_STATUS_SHUTDOWN_COMPLETE,
    WINHTTP_CALLBACK_STATUS_WRITE_COMPLETE,

    WINHTTP_CERTIFICATE_INFO,
    WINHTTP_CONNECTION_GROUP,
    WINHTTP_CURRENT_USER_IE_PROXY_CONFIG,
    // Decompression flags (for WINHTTP_OPTION_DECOMPRESSION)
    WINHTTP_DECOMPRESSION_FLAG_DEFLATE,
    WINHTTP_DECOMPRESSION_FLAG_GZIP,

    // Disable feature flags (for WINHTTP_OPTION_DISABLE_FEATURE)
    WINHTTP_DISABLE_AUTHENTICATION,
    WINHTTP_DISABLE_COOKIES,
    WINHTTP_DISABLE_KEEP_ALIVE,
    WINHTTP_DISABLE_REDIRECTS,

    WINHTTP_EXTENDED_HEADER,
    // Extended header flags
    WINHTTP_EXTENDED_HEADER_FLAG_UNICODE,

    // Request flags (WINHTTP_OPEN_REQUEST_FLAGS / WINHTTP_FLAG_*)
    WINHTTP_FLAG_ASYNC,
    WINHTTP_FLAG_ESCAPE_PERCENT,
    WINHTTP_FLAG_NULL_CODEPAGE,
    WINHTTP_FLAG_SECURE,
    WINHTTP_FLAG_SECURE_DEFAULTS,
    // Secure protocol flags (for WINHTTP_OPTION_SECURE_PROTOCOLS)
    WINHTTP_FLAG_SECURE_PROTOCOL_SSL2,
    WINHTTP_FLAG_SECURE_PROTOCOL_SSL3,
    WINHTTP_FLAG_SECURE_PROTOCOL_TLS1,
    WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_1,
    WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2,
    WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3,

    WINHTTP_HEADER_NAME,
    WINHTTP_HOST_CONNECTION_GROUP,
    WINHTTP_MATCH_CONNECTION_GUID,
    WINHTTP_OPEN_REQUEST_FLAGS,

    // Option constants (WINHTTP_OPTION_*)
    WINHTTP_OPTION_ASSURED_NON_BLOCKING_CALLBACKS,
    WINHTTP_OPTION_AUTOLOGON_POLICY,
    WINHTTP_OPTION_BACKGROUND_CONNECTIONS,
    WINHTTP_OPTION_CALLBACK,
    WINHTTP_OPTION_CLIENT_CERT_CONTEXT,
    WINHTTP_OPTION_CLIENT_CERT_ISSUER_LIST,
    WINHTTP_OPTION_CODEPAGE,
    WINHTTP_OPTION_CONFIGURE_PASSPORT_AUTH,
    WINHTTP_OPTION_CONNECT_RETRIES,
    WINHTTP_OPTION_CONNECT_TIMEOUT,
    WINHTTP_OPTION_CONNECTION_GUID,
    WINHTTP_OPTION_CONNECTION_INFO,
    WINHTTP_OPTION_CONNECTION_STATS_V0,
    WINHTTP_OPTION_CONNECTION_STATS_V1,
    WINHTTP_OPTION_CONTEXT_VALUE,
    WINHTTP_OPTION_DECOMPRESSION,
    WINHTTP_OPTION_DISABLE_CERT_CHAIN_BUILDING,
    WINHTTP_OPTION_DISABLE_FEATURE,
    WINHTTP_OPTION_DISABLE_GLOBAL_POOLING,
    WINHTTP_OPTION_DISABLE_PROXY_AUTH_SCHEMES,
    WINHTTP_OPTION_DISABLE_SECURE_PROTOCOL_FALLBACK,
    WINHTTP_OPTION_DISABLE_STREAM_QUEUE,
    WINHTTP_OPTION_ENABLE_FEATURE,
    WINHTTP_OPTION_ENABLE_HTTP_PROTOCOL,
    WINHTTP_OPTION_ENABLE_HTTP2_PLUS_CLIENT_CERT,
    WINHTTP_OPTION_ENABLETRACING,
    WINHTTP_OPTION_ENCODE_EXTRA,
    WINHTTP_OPTION_EXPIRE_CONNECTION,
    WINHTTP_OPTION_EXTENDED_ERROR,
    WINHTTP_OPTION_FIRST_AVAILABLE_CONNECTION,
    WINHTTP_OPTION_GLOBAL_PROXY_CREDS,
    WINHTTP_OPTION_GLOBAL_SERVER_CREDS,
    WINHTTP_OPTION_HANDLE_TYPE,
    WINHTTP_OPTION_HTTP_PROTOCOL_REQUIRED,
    WINHTTP_OPTION_HTTP_PROTOCOL_USED,
    WINHTTP_OPTION_HTTP_VERSION,
    WINHTTP_OPTION_HTTP2_KEEPALIVE,
    WINHTTP_OPTION_HTTP2_PLUS_TRANSFER_ENCODING,
    WINHTTP_OPTION_HTTP2_RECEIVE_WINDOW,
    WINHTTP_OPTION_IGNORE_CERT_REVOCATION_OFFLINE,
    WINHTTP_OPTION_IPV6_FAST_FALLBACK,
    WINHTTP_OPTION_IS_PROXY_CONNECT_RESPONSE,
    WINHTTP_OPTION_MATCH_CONNECTION_GUID,
    WINHTTP_OPTION_MAX_CONNS_PER_1_0_SERVER,
    WINHTTP_OPTION_MAX_CONNS_PER_SERVER,
    WINHTTP_OPTION_MAX_HTTP_AUTOMATIC_REDIRECTS,
    WINHTTP_OPTION_MAX_HTTP_STATUS_CONTINUE,
    WINHTTP_OPTION_MAX_RESPONSE_DRAIN_SIZE,
    WINHTTP_OPTION_MAX_RESPONSE_HEADER_SIZE,
    WINHTTP_OPTION_PARENT_HANDLE,
    WINHTTP_OPTION_PASSPORT_COBRANDING_TEXT,
    WINHTTP_OPTION_PASSPORT_COBRANDING_URL,
    WINHTTP_OPTION_PASSPORT_RETURN_URL,
    WINHTTP_OPTION_PASSPORT_SIGN_OUT,
    WINHTTP_OPTION_PASSWORD,
    WINHTTP_OPTION_PROXY,
    WINHTTP_OPTION_PROXY_PASSWORD,
    WINHTTP_OPTION_PROXY_SPN_USED,
    WINHTTP_OPTION_PROXY_USERNAME,
    WINHTTP_OPTION_READ_BUFFER_SIZE,
    WINHTTP_OPTION_RECEIVE_PROXY_CONNECT_RESPONSE,
    WINHTTP_OPTION_RECEIVE_RESPONSE_TIMEOUT,
    WINHTTP_OPTION_RECEIVE_TIMEOUT,
    WINHTTP_OPTION_REDIRECT_POLICY,
    // Redirect policy constants (for WINHTTP_OPTION_REDIRECT_POLICY)
    WINHTTP_OPTION_REDIRECT_POLICY_ALWAYS,
    WINHTTP_OPTION_REDIRECT_POLICY_DISALLOW_HTTPS_TO_HTTP,
    WINHTTP_OPTION_REDIRECT_POLICY_NEVER,

    WINHTTP_OPTION_REJECT_USERPWD_IN_URL,
    WINHTTP_OPTION_REQUEST_PRIORITY,
    WINHTTP_OPTION_REQUEST_STATS,
    WINHTTP_OPTION_REQUEST_TIMES,
    WINHTTP_OPTION_RESOLUTION_HOSTNAME,
    WINHTTP_OPTION_RESOLVE_TIMEOUT,
    WINHTTP_OPTION_SECURE_PROTOCOLS,
    WINHTTP_OPTION_SECURITY_CERTIFICATE_STRUCT,
    WINHTTP_OPTION_SECURITY_FLAGS,
    WINHTTP_OPTION_SECURITY_INFO,
    WINHTTP_OPTION_SEND_TIMEOUT,
    WINHTTP_OPTION_SERVER_CERT_CONTEXT,
    WINHTTP_OPTION_UPGRADE_TO_WEB_SOCKET,
    WINHTTP_OPTION_URL,
    WINHTTP_OPTION_USE_GLOBAL_SERVER_CREDENTIALS,
    WINHTTP_OPTION_USERNAME,
    WINHTTP_OPTION_WRITE_BUFFER_SIZE,

    // HTTP protocol flags (for WINHTTP_OPTION_ENABLE_HTTP_PROTOCOL)
    WINHTTP_PROTOCOL_FLAG_HTTP2,
    WINHTTP_PROTOCOL_FLAG_HTTP3,

    WINHTTP_PROXY_INFO,
    WINHTTP_PROXY_RESULT,
    WINHTTP_PROXY_RESULT_ENTRY,
    WINHTTP_PROXY_SETTINGS_EX,
    WINHTTP_PROXY_SETTINGS_PARAM,
    // Enumerations
    WINHTTP_PROXY_SETTINGS_TYPE,
    // Query header info level constants (WINHTTP_QUERY_*)
    WINHTTP_QUERY_ACCEPT,
    WINHTTP_QUERY_ACCEPT_CHARSET,
    WINHTTP_QUERY_ACCEPT_ENCODING,
    WINHTTP_QUERY_ACCEPT_LANGUAGE,
    WINHTTP_QUERY_ACCEPT_RANGES,
    WINHTTP_QUERY_AGE,
    WINHTTP_QUERY_ALLOW,
    WINHTTP_QUERY_AUTHENTICATION_INFO,
    WINHTTP_QUERY_AUTHORIZATION,
    WINHTTP_QUERY_CACHE_CONTROL,
    WINHTTP_QUERY_CONNECTION,
    WINHTTP_QUERY_CONNECTION_GROUP_RESULT,
    WINHTTP_QUERY_CONTENT_BASE,
    WINHTTP_QUERY_CONTENT_DESCRIPTION,
    WINHTTP_QUERY_CONTENT_DISPOSITION,
    WINHTTP_QUERY_CONTENT_ENCODING,
    WINHTTP_QUERY_CONTENT_ID,
    WINHTTP_QUERY_CONTENT_LANGUAGE,
    WINHTTP_QUERY_CONTENT_LENGTH,
    WINHTTP_QUERY_CONTENT_LOCATION,
    WINHTTP_QUERY_CONTENT_MD5,
    WINHTTP_QUERY_CONTENT_RANGE,
    WINHTTP_QUERY_CONTENT_TRANSFER_ENCODING,
    WINHTTP_QUERY_CONTENT_TYPE,
    WINHTTP_QUERY_COOKIE,
    WINHTTP_QUERY_COST,
    WINHTTP_QUERY_CUSTOM,
    WINHTTP_QUERY_DATE,
    WINHTTP_QUERY_DERIVED_FROM,
    WINHTTP_QUERY_ETAG,
    WINHTTP_QUERY_EXPECT,
    WINHTTP_QUERY_EXPIRES,
    // Query modifier flags
    WINHTTP_QUERY_FLAG_NUMBER,
    WINHTTP_QUERY_FLAG_REQUEST_HEADERS,
    WINHTTP_QUERY_FLAG_SYSTEMTIME,

    WINHTTP_QUERY_FORWARDED,
    WINHTTP_QUERY_FROM,
    WINHTTP_QUERY_HOST,
    WINHTTP_QUERY_IF_MATCH,
    WINHTTP_QUERY_IF_MODIFIED_SINCE,
    WINHTTP_QUERY_IF_NONE_MATCH,
    WINHTTP_QUERY_IF_RANGE,
    WINHTTP_QUERY_IF_UNMODIFIED_SINCE,
    WINHTTP_QUERY_LAST_MODIFIED,
    WINHTTP_QUERY_LINK,
    WINHTTP_QUERY_LOCATION,
    WINHTTP_QUERY_MAX,
    WINHTTP_QUERY_MAX_FORWARDS,
    WINHTTP_QUERY_MESSAGE_ID,
    WINHTTP_QUERY_MIME_VERSION,
    WINHTTP_QUERY_ORIG_URI,
    WINHTTP_QUERY_PRAGMA,
    WINHTTP_QUERY_PROXY_AUTHENTICATE,
    WINHTTP_QUERY_PROXY_AUTHORIZATION,
    WINHTTP_QUERY_PROXY_CONNECTION,
    WINHTTP_QUERY_PROXY_SUPPORT,
    WINHTTP_QUERY_PUBLIC,
    WINHTTP_QUERY_RANGE,
    WINHTTP_QUERY_RAW_HEADERS,
    WINHTTP_QUERY_RAW_HEADERS_CRLF,
    WINHTTP_QUERY_REFERER,
    WINHTTP_QUERY_REFRESH,
    WINHTTP_QUERY_REQUEST_METHOD,
    WINHTTP_QUERY_RETRY_AFTER,
    WINHTTP_QUERY_SERVER,
    WINHTTP_QUERY_SET_COOKIE,
    WINHTTP_QUERY_STATUS_CODE,
    WINHTTP_QUERY_STATUS_TEXT,
    WINHTTP_QUERY_TITLE,
    WINHTTP_QUERY_TRANSFER_ENCODING,
    WINHTTP_QUERY_UNLESS_MODIFIED_SINCE,
    WINHTTP_QUERY_UPGRADE,
    WINHTTP_QUERY_URI,
    WINHTTP_QUERY_USER_AGENT,
    WINHTTP_QUERY_VARY,
    WINHTTP_QUERY_VERSION,
    WINHTTP_QUERY_VIA,
    WINHTTP_QUERY_WARNING,
    WINHTTP_QUERY_WWW_AUTHENTICATE,

    WINHTTP_REQUEST_STAT_ENTRY,
    WINHTTP_REQUEST_STATS,
    WINHTTP_REQUEST_TIME_ENTRY,
    WINHTTP_REQUEST_TIMES,
    WINHTTP_STATUS_CALLBACK,

    // WebSocket close status constants
    WINHTTP_WEB_SOCKET_ABORTED_CLOSE_STATUS,
    WINHTTP_WEB_SOCKET_ASYNC_RESULT,
    // WebSocket buffer types
    WINHTTP_WEB_SOCKET_BINARY_FRAGMENT_BUFFER_TYPE,
    WINHTTP_WEB_SOCKET_BINARY_MESSAGE_BUFFER_TYPE,
    WINHTTP_WEB_SOCKET_BUFFER_TYPE,
    WINHTTP_WEB_SOCKET_CLOSE_BUFFER_TYPE,
    // WebSocket operation types
    WINHTTP_WEB_SOCKET_CLOSE_OPERATION,
    WINHTTP_WEB_SOCKET_CLOSE_STATUS,
    WINHTTP_WEB_SOCKET_EMPTY_CLOSE_STATUS,
    WINHTTP_WEB_SOCKET_ENDPOINT_TERMINATED_CLOSE_STATUS,
    WINHTTP_WEB_SOCKET_INVALID_DATA_TYPE_CLOSE_STATUS,
    WINHTTP_WEB_SOCKET_INVALID_PAYLOAD_CLOSE_STATUS,
    WINHTTP_WEB_SOCKET_MESSAGE_TOO_BIG_CLOSE_STATUS,
    WINHTTP_WEB_SOCKET_OPERATION,
    WINHTTP_WEB_SOCKET_POLICY_VIOLATION_CLOSE_STATUS,
    WINHTTP_WEB_SOCKET_PROTOCOL_ERROR_CLOSE_STATUS,
    WINHTTP_WEB_SOCKET_RECEIVE_OPERATION,
    WINHTTP_WEB_SOCKET_SEND_OPERATION,
    WINHTTP_WEB_SOCKET_SERVER_ERROR_CLOSE_STATUS,
    WINHTTP_WEB_SOCKET_SHUTDOWN_OPERATION,

    WINHTTP_WEB_SOCKET_STATUS,

    WINHTTP_WEB_SOCKET_SUCCESS_CLOSE_STATUS,
    WINHTTP_WEB_SOCKET_UNSUPPORTED_EXTENSIONS_CLOSE_STATUS,

    WINHTTP_WEB_SOCKET_UTF8_FRAGMENT_BUFFER_TYPE,
    WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE,

    // Proxy settings type enum variants
    WinHttpProxySettingsTypeUnknown,
    WinHttpProxySettingsTypeWsa,

    WinHttpProxySettingsTypeWsl,
};

// Composite constants not individually available in the `windows` crate.
// These match the values from the WinHTTP C headers.

/// Combination of all secure protocol flags (SSL 2.0 through TLS 1.3).
pub const WINHTTP_FLAG_SECURE_PROTOCOL_ALL: u32 = WINHTTP_FLAG_SECURE_PROTOCOL_SSL2
    | WINHTTP_FLAG_SECURE_PROTOCOL_SSL3
    | WINHTTP_FLAG_SECURE_PROTOCOL_TLS1
    | WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_1
    | WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2
    | WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3;

/// Modern TLS only (TLS 1.2 + TLS 1.3). Recommended for most applications.
pub const WINHTTP_FLAG_SECURE_PROTOCOL_MODERN: u32 =
    WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2 | WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3;

/// Enable all decompression methods (gzip + deflate).
pub const WINHTTP_DECOMPRESSION_FLAG_ALL: u32 =
    WINHTTP_DECOMPRESSION_FLAG_GZIP | WINHTTP_DECOMPRESSION_FLAG_DEFLATE;

/// Auto-logon if challenged (used in WINHTTP_AUTOPROXY_OPTIONS flags).
pub const WINHTTP_AUTOPROXY_AUTO_LOGON_IF_CHALLENGED: u32 = 0x0000_0100;

/// Ignore all certificate errors (CN invalid + date invalid + unknown CA + wrong usage).
/// Use with extreme caution â€” disables SSL/TLS certificate verification.
pub const SECURITY_FLAG_IGNORE_ALL_CERT_ERRORS: u32 = SECURITY_FLAG_IGNORE_CERT_CN_INVALID
    | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID
    | SECURITY_FLAG_IGNORE_UNKNOWN_CA
    | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;

// WinHttpResetAutoProxy flags
pub const WINHTTP_RESET_STATE: u32 = 0x0000_0001;
pub const WINHTTP_RESET_SWPAD_CURRENT_NETWORK: u32 = 0x0000_0002;
pub const WINHTTP_RESET_SWPAD_ALL: u32 = 0x0000_0004;
pub const WINHTTP_RESET_SCRIPT_CACHE: u32 = 0x0000_0008;
pub const WINHTTP_RESET_ALL: u32 = 0x0000_FFFF;
pub const WINHTTP_RESET_NOTIFY_NETWORK_CHANGED: u32 = 0x0001_0000;
pub const WINHTTP_RESET_OUT_OF_PROC: u32 = 0x0002_0000;

// Type-safe flag wrappers

/// Macro to generate a bitflag-style newtype wrapping `u32`.
///
/// The generated type supports `|`, `|=`, `&`, `&=`, `!`, `==`, `Debug`,
/// `Clone`, `Copy`, `Default`, `Hash`, and converts to/from `u32`.
macro_rules! bitflags_u32 {
    (
        $(#[$outer:meta])*
        $vis:vis struct $Name:ident;

        $(
            $(#[$inner:meta])*
            const $FLAG:ident = $value:expr;
        )*
    ) => {
        $(#[$outer])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
        #[repr(transparent)]
        $vis struct $Name(pub u32);

        impl $Name {
            $(
                $(#[$inner])*
                pub const $FLAG: Self = Self($value);
            )*

            /// Returns `true` if no flags are set.
            #[inline]
            pub const fn is_empty(self) -> bool { self.0 == 0 }

            /// Returns `true` if all flags in `other` are set in `self`.
            #[inline]
            pub const fn contains(self, other: Self) -> bool {
                (self.0 & other.0) == other.0
            }

            /// Returns the raw `u32` value.
            #[inline]
            pub const fn bits(self) -> u32 { self.0 }
        }

        impl ::std::fmt::Debug for $Name {
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                let mut first = true;
                f.write_str(concat!(stringify!($Name), "("))?;
                $(
                    if self.contains(Self::$FLAG) && Self::$FLAG.0 != 0 {
                        if !first { f.write_str(" | ")?; }
                        f.write_str(stringify!($FLAG))?;
                        first = false;
                    }
                )*
                if first { write!(f, "0x{:08X}", self.0)?; }
                f.write_str(")")
            }
        }

        impl ::std::ops::BitOr for $Name {
            type Output = Self;
            #[inline]
            fn bitor(self, rhs: Self) -> Self { Self(self.0 | rhs.0) }
        }

        impl ::std::ops::BitOrAssign for $Name {
            #[inline]
            fn bitor_assign(&mut self, rhs: Self) { self.0 |= rhs.0; }
        }

        impl ::std::ops::BitAnd for $Name {
            type Output = Self;
            #[inline]
            fn bitand(self, rhs: Self) -> Self { Self(self.0 & rhs.0) }
        }

        impl ::std::ops::BitAndAssign for $Name {
            #[inline]
            fn bitand_assign(&mut self, rhs: Self) { self.0 &= rhs.0; }
        }

        impl ::std::ops::Not for $Name {
            type Output = Self;
            #[inline]
            fn not(self) -> Self { Self(!self.0) }
        }

        impl From<u32> for $Name {
            #[inline]
            fn from(val: u32) -> Self { Self(val) }
        }

        impl From<$Name> for u32 {
            #[inline]
            fn from(val: $Name) -> u32 { val.0 }
        }
    };
}

bitflags_u32! {
    /// Authentication scheme flags.
    ///
    /// Used with [`Request::set_credentials`](crate::Request::set_credentials)
    /// and [`Request::query_auth_schemes`](crate::Request::query_auth_schemes).
    pub struct AuthScheme;

    /// HTTP Basic authentication (base64 username:password).
    const BASIC = 0x0000_0001;
    /// HTTP Digest authentication (RFC 2617).
    const DIGEST = 0x0000_0008;
    /// NTLM authentication.
    const NTLM = 0x0000_0002;
    /// Negotiate (SPNEGO) authentication â€” selects between Kerberos and NTLM.
    const NEGOTIATE = 0x0000_0010;
    /// Microsoft Passport authentication.
    const PASSPORT = 0x0000_0004;
}

bitflags_u32! {
    /// Authentication target flags.
    ///
    /// Used with [`Request::set_credentials`](crate::Request::set_credentials).
    pub struct AuthTarget;

    /// Authenticate with the destination server.
    const SERVER = 0x0000_0000;
    /// Authenticate with the proxy server.
    const PROXY = 0x0000_0001;
}

bitflags_u32! {
    /// SSL/TLS certificate validation flags.
    ///
    /// Used with [`Request::set_security_flags`](crate::Request::set_security_flags).
    ///
    /// **Warning**: Ignoring certificate errors weakens security. Use with caution.
    pub struct SecurityFlags;

    /// Ignore certificate CN (Common Name) mismatch.
    const IGNORE_CERT_CN_INVALID = SECURITY_FLAG_IGNORE_CERT_CN_INVALID;
    /// Ignore expired or not-yet-valid certificates.
    const IGNORE_CERT_DATE_INVALID = SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
    /// Ignore unknown Certificate Authority.
    const IGNORE_UNKNOWN_CA = SECURITY_FLAG_IGNORE_UNKNOWN_CA;
    /// Ignore wrong certificate usage.
    const IGNORE_CERT_WRONG_USAGE = SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
    /// Ignore **all** certificate errors (combination of all above).
    const IGNORE_ALL = SECURITY_FLAG_IGNORE_CERT_CN_INVALID
        | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID
        | SECURITY_FLAG_IGNORE_UNKNOWN_CA
        | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
}

bitflags_u32! {
    /// Automatic response decompression flags.
    ///
    /// Used with [`Request::set_decompression`](crate::Request::set_decompression)
    /// and [`Session::set_decompression`](crate::Session::set_decompression).
    pub struct DecompressionFlags;

    /// Decompress gzip-encoded responses.
    const GZIP = WINHTTP_DECOMPRESSION_FLAG_GZIP;
    /// Decompress deflate-encoded responses.
    const DEFLATE = WINHTTP_DECOMPRESSION_FLAG_DEFLATE;
    /// Decompress both gzip and deflate responses.
    const ALL = WINHTTP_DECOMPRESSION_FLAG_GZIP | WINHTTP_DECOMPRESSION_FLAG_DEFLATE;
}

bitflags_u32! {
    /// HTTP/2 and HTTP/3 protocol flags.
    ///
    /// Used with [`Request::enable_http_protocol`](crate::Request::set_option)
    /// and [`Session::enable_http_protocol`](crate::Session::enable_http_protocol).
    pub struct HttpProtocol;

    /// Enable HTTP/2 protocol.
    const HTTP2 = WINHTTP_PROTOCOL_FLAG_HTTP2;
    /// Enable HTTP/3 protocol (QUIC).
    const HTTP3 = WINHTTP_PROTOCOL_FLAG_HTTP3;
    /// Enable both HTTP/2 and HTTP/3.
    const HTTP2_AND_HTTP3 = WINHTTP_PROTOCOL_FLAG_HTTP2 | WINHTTP_PROTOCOL_FLAG_HTTP3;
}

bitflags_u32! {
    /// TLS/SSL protocol version flags.
    ///
    /// Used with [`Session::set_secure_protocols`](crate::Session::set_secure_protocols).
    pub struct SecureProtocol;

    /// SSL 2.0 (deprecated, insecure).
    const SSL2 = WINHTTP_FLAG_SECURE_PROTOCOL_SSL2;
    /// SSL 3.0 (deprecated, insecure).
    const SSL3 = WINHTTP_FLAG_SECURE_PROTOCOL_SSL3;
    /// TLS 1.0 (deprecated).
    const TLS1_0 = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1;
    /// TLS 1.1 (deprecated).
    const TLS1_1 = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_1;
    /// TLS 1.2.
    const TLS1_2 = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2;
    /// TLS 1.3.
    const TLS1_3 = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3;
    /// Modern TLS only (TLS 1.2 + TLS 1.3). Recommended for most applications.
    const MODERN = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2 | WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3;
    /// All protocol versions (SSL 2.0 through TLS 1.3).
    const ALL = WINHTTP_FLAG_SECURE_PROTOCOL_SSL2
        | WINHTTP_FLAG_SECURE_PROTOCOL_SSL3
        | WINHTTP_FLAG_SECURE_PROTOCOL_TLS1
        | WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_1
        | WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2
        | WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3;
}

bitflags_u32! {
    /// Feature disable flags.
    ///
    /// Used with [`Request::disable_feature`](crate::Request::disable_feature).
    pub struct DisableFlags;

    /// Disable automatic cookie handling.
    const COOKIES = WINHTTP_DISABLE_COOKIES;
    /// Disable automatic redirect following.
    const REDIRECTS = WINHTTP_DISABLE_REDIRECTS;
    /// Disable automatic authentication.
    const AUTHENTICATION = WINHTTP_DISABLE_AUTHENTICATION;
    /// Disable HTTP keep-alive connections.
    const KEEP_ALIVE = WINHTTP_DISABLE_KEEP_ALIVE;
}

/// Redirect policy for HTTP requests.
///
/// Used with [`Request::set_redirect_policy`](crate::Request::set_redirect_policy).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum RedirectPolicy {
    /// Always follow redirects (default behavior).
    Always = WINHTTP_OPTION_REDIRECT_POLICY_ALWAYS,
    /// Follow redirects, but disallow HTTPS-to-HTTP downgrades.
    DisallowHttpsToHttp = WINHTTP_OPTION_REDIRECT_POLICY_DISALLOW_HTTPS_TO_HTTP,
    /// Never follow redirects.
    Never = WINHTTP_OPTION_REDIRECT_POLICY_NEVER,
}

impl From<RedirectPolicy> for u32 {
    #[inline]
    fn from(val: RedirectPolicy) -> u32 {
        val as u32
    }
}

/// Autologon security level for NTLM/Negotiate authentication.
///
/// Used with [`Request::set_option`](crate::Request::set_option) and
/// `WINHTTP_OPTION_AUTOLOGON_POLICY`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum AutologonPolicy {
    /// Send credentials to all servers.
    Low = WINHTTP_AUTOLOGON_SECURITY_LEVEL_LOW,
    /// Send credentials only to intranet servers (default).
    Medium = WINHTTP_AUTOLOGON_SECURITY_LEVEL_MEDIUM,
    /// Never automatically send credentials.
    High = WINHTTP_AUTOLOGON_SECURITY_LEVEL_HIGH,
}

impl From<AutologonPolicy> for u32 {
    #[inline]
    fn from(val: AutologonPolicy) -> u32 {
        val as u32
    }
}

// WebSocket types

#[cfg(feature = "websocket")]
/// WebSocket message buffer type.
///
/// Used with [`WebSocket::send_typed`](crate::WebSocket::send_typed) and
/// returned by [`WebSocket::receive_typed`](crate::WebSocket::receive_typed).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum WebSocketBufferType {
    /// Binary message (complete).
    BinaryMessage = 0, // WINHTTP_WEB_SOCKET_BINARY_MESSAGE_BUFFER_TYPE.0
    /// Binary fragment (partial message).
    BinaryFragment = 1, // WINHTTP_WEB_SOCKET_BINARY_FRAGMENT_BUFFER_TYPE.0
    /// UTF-8 text message (complete).
    Utf8Message = 2, // WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE.0
    /// UTF-8 text fragment (partial message).
    Utf8Fragment = 3, // WINHTTP_WEB_SOCKET_UTF8_FRAGMENT_BUFFER_TYPE.0
    /// Close frame.
    Close = 4, // WINHTTP_WEB_SOCKET_CLOSE_BUFFER_TYPE.0
}

#[cfg(feature = "websocket")]
impl From<WebSocketBufferType> for WINHTTP_WEB_SOCKET_BUFFER_TYPE {
    #[inline]
    fn from(val: WebSocketBufferType) -> Self {
        WINHTTP_WEB_SOCKET_BUFFER_TYPE(val as i32)
    }
}

#[cfg(feature = "websocket")]
impl TryFrom<WINHTTP_WEB_SOCKET_BUFFER_TYPE> for WebSocketBufferType {
    type Error = ();

    #[inline]
    fn try_from(val: WINHTTP_WEB_SOCKET_BUFFER_TYPE) -> Result<Self, Self::Error> {
        match val.0 {
            0 => Ok(WebSocketBufferType::BinaryMessage),
            1 => Ok(WebSocketBufferType::BinaryFragment),
            2 => Ok(WebSocketBufferType::Utf8Message),
            3 => Ok(WebSocketBufferType::Utf8Fragment),
            4 => Ok(WebSocketBufferType::Close),
            _ => Err(()),
        }
    }
}

#[cfg(feature = "websocket")]
/// WebSocket close status code.
///
/// Used with [`WebSocket::close_typed`](crate::WebSocket::close_typed) and
/// [`WebSocket::shutdown_typed`](crate::WebSocket::shutdown_typed).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum WebSocketCloseStatus {
    /// Normal closure (1000).
    Success = 1000,
    /// Endpoint going away (1001).
    EndpointTerminated = 1001,
    /// Protocol error (1002).
    ProtocolError = 1002,
    /// Unsupported data type (1003).
    InvalidDataType = 1003,
    /// No status code present (1005).
    Empty = 1005,
    /// Abnormal closure (1006).
    Aborted = 1006,
    /// Invalid payload data (1007).
    InvalidPayload = 1007,
    /// Policy violation (1008).
    PolicyViolation = 1008,
    /// Message too big (1009).
    MessageTooBig = 1009,
    /// Missing expected extension (1010).
    UnsupportedExtensions = 1010,
    /// Server encountered error (1011).
    ServerError = 1011,
}

#[cfg(feature = "websocket")]
impl From<WebSocketCloseStatus> for u16 {
    #[inline]
    fn from(val: WebSocketCloseStatus) -> u16 {
        val as u16
    }
}

#[cfg(feature = "websocket")]
impl TryFrom<u16> for WebSocketCloseStatus {
    type Error = ();

    #[inline]
    fn try_from(val: u16) -> Result<Self, Self::Error> {
        match val {
            1000 => Ok(WebSocketCloseStatus::Success),
            1001 => Ok(WebSocketCloseStatus::EndpointTerminated),
            1002 => Ok(WebSocketCloseStatus::ProtocolError),
            1003 => Ok(WebSocketCloseStatus::InvalidDataType),
            1005 => Ok(WebSocketCloseStatus::Empty),
            1006 => Ok(WebSocketCloseStatus::Aborted),
            1007 => Ok(WebSocketCloseStatus::InvalidPayload),
            1008 => Ok(WebSocketCloseStatus::PolicyViolation),
            1009 => Ok(WebSocketCloseStatus::MessageTooBig),
            1010 => Ok(WebSocketCloseStatus::UnsupportedExtensions),
            1011 => Ok(WebSocketCloseStatus::ServerError),
            _ => Err(()),
        }
    }
}

#[cfg(feature = "websocket")]
/// WebSocket operation type.
///
/// Reported in async WebSocket results.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum WebSocketOperation {
    /// Send operation.
    Send = 0, // WINHTTP_WEB_SOCKET_SEND_OPERATION.0
    /// Receive operation.
    Receive = 1, // WINHTTP_WEB_SOCKET_RECEIVE_OPERATION.0
    /// Close operation.
    Close = 2, // WINHTTP_WEB_SOCKET_CLOSE_OPERATION.0
    /// Shutdown operation.
    Shutdown = 3, // WINHTTP_WEB_SOCKET_SHUTDOWN_OPERATION.0
}

#[cfg(feature = "websocket")]
impl TryFrom<WINHTTP_WEB_SOCKET_OPERATION> for WebSocketOperation {
    type Error = ();

    #[inline]
    fn try_from(val: WINHTTP_WEB_SOCKET_OPERATION) -> Result<Self, Self::Error> {
        match val.0 {
            0 => Ok(WebSocketOperation::Send),
            1 => Ok(WebSocketOperation::Receive),
            2 => Ok(WebSocketOperation::Close),
            3 => Ok(WebSocketOperation::Shutdown),
            _ => Err(()),
        }
    }
}

// Certificate info wrapper

/// Parsed SSL/TLS certificate information.
///
/// Retrieved via [`Request::certificate_info`](crate::Request::certificate_info)
/// after a successful HTTPS response.
#[derive(Debug, Clone)]
pub struct CertificateInfo {
    /// Subject name (e.g. "CN=example.com").
    pub subject: String,
    /// Issuer name (e.g. "CN=Let's Encrypt Authority X3").
    pub issuer: String,
    /// Certificate expiration date as a formatted string.
    pub expiry: String,
    /// The key size in bits (e.g. 2048, 4096).
    pub key_size: u32,
}

// Request timing/stats wrappers

/// Performance timing information for an HTTP request.
///
/// Retrieved via [`Request::request_times`](crate::Request::request_times)
/// after a response has been received.
///
/// All times are in 100-nanosecond intervals (Windows FILETIME units).
#[derive(Debug, Clone, Default)]
pub struct RequestTimes {
    /// Time spent resolving the proxy.
    pub proxy_detection_start: u64,
    /// Time spent in proxy detection end.
    pub proxy_detection_end: u64,
    /// Time DNS resolution started.
    pub dns_start: u64,
    /// Time DNS resolution completed.
    pub dns_end: u64,
    /// Time the TCP connection started.
    pub connect_start: u64,
    /// Time the TCP connection completed.
    pub connect_end: u64,
    /// Time the TLS handshake started.
    pub tls_start: u64,
    /// Time the TLS handshake completed.
    pub tls_end: u64,
    /// Time the request send started.
    pub send_start: u64,
    /// Time the request send completed.
    pub send_end: u64,
    /// Time the first byte of the response was received.
    pub receive_start: u64,
    /// Time the last byte of the response was received.
    pub receive_end: u64,
}

/// Statistics for an HTTP request.
///
/// Retrieved via [`Request::request_stats`](crate::Request::request_stats)
/// after a response has been received.
#[derive(Debug, Clone, Default)]
pub struct RequestStats {
    /// Number of connections opened.
    pub connections_opened: u64,
    /// Number of connections reused.
    pub connections_reused: u64,
    /// Total bytes sent including headers.
    pub bytes_sent: u64,
    /// Total bytes received including headers.
    pub bytes_received: u64,
    /// Number of redirects followed.
    pub redirects: u32,
    /// Number of authentication challenges processed.
    pub auth_challenges: u32,
}

// Connection info wrapper

/// TCP connection information for an HTTP request.
///
/// Retrieved via [`Request::connection_info`](crate::Request::connection_info)
/// after a response has been received.
#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    /// Local socket address (IP + port).
    pub local: std::net::SocketAddr,
    /// Remote (server) socket address (IP + port).
    pub remote: std::net::SocketAddr,
}
