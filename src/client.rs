//! High-level HTTP client with ergonomic helpers.
//!
//! [`Client`] wraps a WinHTTP [`Session`] and provides one-liner methods for
//! common HTTP verbs (`get`, `post`, `put`, `delete`, `patch`, `head`).
//!
//! # Builder pattern
//!
//! ```no_run
//! use winhttp::Client;
//!
//! let client = Client::builder()
//!     .base_url("https://httpbin.org")
//!     .user_agent("my-app/1.0")
//!     .build()?;
//!
//! // Paths are joined to the base URL:
//! let resp = client.get("/get")?;
//!
//! // Absolute URLs bypass the base URL:
//! let resp = client.get("https://other.com/foo")?;
//! # Ok::<(), windows::core::Error>(())
//! ```
//!
//! # Quick start (no base URL)
//!
//! ```no_run
//! use winhttp::Client;
//!
//! let client = Client::new()?;
//! let resp = client.get("https://httpbin.org/get")?;
//! println!("{} {}", resp.status, String::from_utf8_lossy(&resp.body));
//! # Ok::<(), windows::core::Error>(())
//! ```
//!
//! # One-shot helpers
//!
//! For truly minimal usage, module-level functions create an ephemeral client:
//!
//! ```no_run
//! let resp = winhttp::get("https://httpbin.org/get")?;
//! # Ok::<(), windows::core::Error>(())
//! ```

use crate::session::{Session, SessionConfig};
use crate::url::{UrlComponents, crack_url};
use windows::core::Result;

// ---------------------------------------------------------------------------
// Body
// ---------------------------------------------------------------------------

/// A request body that can be raw bytes or serialized JSON.
///
/// Use the [`From`] impls to pass raw bytes, or [`Body::json`] to serialize a
/// value and automatically set the `Content-Type: application/json` header.
///
/// # Examples
///
/// ```
/// use winhttp::Body;
///
/// // Raw bytes — no Content-Type is set.
/// let body: Body = b"hello".as_slice().into();
/// let body: Body = vec![1, 2, 3].into();
/// let body: Body = "plain text".into();
/// ```
///
/// ```
/// # #[cfg(feature = "json")]
/// # fn demo() -> windows::core::Result<()> {
/// use winhttp::Body;
///
/// // JSON — Content-Type is set to application/json.
/// let body = Body::json(&serde_json::json!({"key": "value"}))?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct Body {
    bytes: Vec<u8>,
    content_type: Option<&'static str>,
}

impl Body {
    /// Serialize `value` as JSON and set `Content-Type: application/json`.
    ///
    /// Returns a `windows::core::Error` if serialization fails.
    ///
    /// Requires the `json` feature.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # #[cfg(feature = "json")]
    /// # fn demo() -> windows::core::Result<()> {
    /// use winhttp::{Body, Client};
    /// use serde::Serialize;
    ///
    /// #[derive(Serialize)]
    /// struct Payload { name: String }
    ///
    /// let client = Client::new()?;
    /// let resp = client.post("/users", Body::json(&Payload { name: "Ada".into() })?)?;
    /// # Ok(())
    /// # }
    /// ```
    #[cfg(feature = "json")]
    pub fn json<T: serde::Serialize>(value: &T) -> Result<Self> {
        let bytes = serde_json::to_vec(value).map_err(|err| {
            windows::core::Error::new(
                windows::Win32::Foundation::E_FAIL,
                format!("JSON serialization failed: {err}"),
            )
        })?;
        Ok(Self {
            bytes,
            content_type: Some("application/json"),
        })
    }

    /// Returns the raw bytes of this body.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the content type that should be set for this body, if any.
    #[must_use]
    pub fn content_type(&self) -> Option<&'static str> {
        self.content_type
    }
}

impl From<&[u8]> for Body {
    fn from(bytes: &[u8]) -> Self {
        Self {
            bytes: bytes.to_vec(),
            content_type: None,
        }
    }
}

impl<const N: usize> From<&[u8; N]> for Body {
    fn from(bytes: &[u8; N]) -> Self {
        Self {
            bytes: bytes.to_vec(),
            content_type: None,
        }
    }
}

impl From<Vec<u8>> for Body {
    fn from(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            content_type: None,
        }
    }
}

impl From<&str> for Body {
    fn from(s: &str) -> Self {
        Self {
            bytes: s.as_bytes().to_vec(),
            content_type: None,
        }
    }
}

impl From<String> for Body {
    fn from(s: String) -> Self {
        Self {
            bytes: s.into_bytes(),
            content_type: None,
        }
    }
}

/// Extract the implicit headers (e.g. `Content-Type`) from a [`Body`].
fn body_headers(body: &Body) -> Vec<(String, String)> {
    body.content_type
        .map(|ct| vec![("Content-Type".to_string(), ct.to_string())])
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Response
// ---------------------------------------------------------------------------

/// A high-level response returned by the [`Client`] helper methods.
#[derive(Debug, Clone)]
pub struct Response {
    /// HTTP status code (e.g. 200, 404, 500).
    pub status: u16,
    /// HTTP status text (e.g. "OK", "Not Found").
    pub status_text: String,
    /// All response headers as a single CRLF-delimited string.
    pub headers: String,
    /// The full response body bytes.
    pub body: Vec<u8>,
}

impl Response {
    /// Interpret the body as UTF-8 (lossy).
    #[must_use]
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    /// Returns `true` if the status code is 2xx.
    #[must_use]
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }

    /// Returns `true` if the status code is 3xx.
    #[must_use]
    pub fn is_redirect(&self) -> bool {
        (300..400).contains(&self.status)
    }

    /// Returns `true` if the status code is 4xx.
    #[must_use]
    pub fn is_client_error(&self) -> bool {
        (400..500).contains(&self.status)
    }

    /// Returns `true` if the status code is 5xx.
    #[must_use]
    pub fn is_server_error(&self) -> bool {
        (500..600).contains(&self.status)
    }

    /// Deserialize the response body as JSON.
    ///
    /// Requires the `json` feature.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # #[derive(serde::Deserialize)]
    /// # struct ApiResponse { url: String }
    /// let resp = winhttp::get("https://httpbin.org/get")?;
    /// let data: ApiResponse = resp.json()?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[cfg(feature = "json")]
    pub fn json<T: serde::de::DeserializeOwned>(
        &self,
    ) -> std::result::Result<T, serde_json::Error> {
        serde_json::from_slice(&self.body)
    }
}

// ---------------------------------------------------------------------------
// ClientBuilder
// ---------------------------------------------------------------------------

/// Builder for configuring and constructing a [`Client`].
///
/// Obtained via [`Client::builder`]. All fields have sensible defaults;
/// call [`build`](ClientBuilder::build) to create the client.
///
/// # Example
///
/// ```no_run
/// # use winhttp::Client;
/// let client = Client::builder()
///     .base_url("https://httpbin.org")
///     .user_agent("my-app/1.0")
///     .connect_timeout_ms(10_000)
///     .build()?;
/// # Ok::<(), windows::core::Error>(())
/// ```
pub struct ClientBuilder {
    base_url: Option<String>,
    user_agent: String,
    connect_timeout_ms: u32,
    send_timeout_ms: u32,
    receive_timeout_ms: u32,
}

impl ClientBuilder {
    /// Set a base URL that will be prepended to relative paths.
    ///
    /// When set, calls like `client.get("/users")` resolve to
    /// `{base_url}/users`. Absolute URLs (starting with `http://` or
    /// `https://`) bypass the base URL entirely.
    ///
    /// Trailing slashes on the base URL are trimmed automatically.
    #[must_use]
    pub fn base_url(mut self, url: impl Into<String>) -> Self {
        let mut url = url.into();
        // Trim trailing slashes so join logic is consistent.
        while url.ends_with('/') {
            url.pop();
        }
        self.base_url = Some(url);
        self
    }

    /// Set the `User-Agent` header string (default: `"winhttp-rs/0.1.0"`).
    #[must_use]
    pub fn user_agent(mut self, agent: impl Into<String>) -> Self {
        self.user_agent = agent.into();
        self
    }

    /// Set the connection timeout in milliseconds (default: 60 000).
    #[must_use]
    pub fn connect_timeout_ms(mut self, ms: u32) -> Self {
        self.connect_timeout_ms = ms;
        self
    }

    /// Set the send timeout in milliseconds (default: 30 000).
    #[must_use]
    pub fn send_timeout_ms(mut self, ms: u32) -> Self {
        self.send_timeout_ms = ms;
        self
    }

    /// Set the receive timeout in milliseconds (default: 30 000).
    #[must_use]
    pub fn receive_timeout_ms(mut self, ms: u32) -> Self {
        self.receive_timeout_ms = ms;
        self
    }

    /// Build the [`Client`].
    ///
    /// This creates the underlying WinHTTP session(s) and may fail if the
    /// platform does not support WinHTTP or if the base URL is invalid.
    pub fn build(self) -> Result<Client> {
        let base_components = match &self.base_url {
            Some(url) => Some(crack_url(url)?),
            None => None,
        };

        let config = SessionConfig {
            user_agent: self.user_agent,
            connect_timeout_ms: self.connect_timeout_ms,
            send_timeout_ms: self.send_timeout_ms,
            receive_timeout_ms: self.receive_timeout_ms,
        };

        let session = Session::with_config(config.clone())?;

        #[cfg(feature = "async")]
        let async_session = Session::with_config_async(config)?;

        Ok(Client {
            base_url: self.base_url,
            base_components,
            session,
            #[cfg(feature = "async")]
            async_session,
        })
    }
}

// ---------------------------------------------------------------------------
// RequestHelper
// ---------------------------------------------------------------------------

/// Builder for constructing a single request with custom headers and body.
///
/// Obtained via [`Client::request`]. Call [`send`](RequestHelper::send) (or
/// [`send_async`](RequestHelper::send_async) with the `async` feature) to
/// execute it.
///
/// # Example
///
/// ```no_run
/// # use winhttp::Client;
/// let client = Client::new()?;
/// let resp = client
///     .request("POST", "https://httpbin.org/post")
///     .header("Content-Type", "application/json")
///     .body(b"{\"key\":\"value\"}")
///     .send()?;
/// # Ok::<(), windows::core::Error>(())
/// ```
pub struct RequestHelper<'c> {
    client: &'c Client,
    method: String,
    url: String,
    headers: Vec<(String, String)>,
    body: Option<Body>,
}

impl RequestHelper<'_> {
    /// Add a header to this request.
    #[must_use]
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    /// Set the request body.
    ///
    /// Accepts anything that converts into a [`Body`]: `&[u8]`, `Vec<u8>`,
    /// `&str`, `String`, or a pre-built `Body` (e.g. from [`Body::json`]).
    ///
    /// If the body carries an implicit content type (such as `Body::json`),
    /// the corresponding `Content-Type` header is added automatically.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use winhttp::Client;
    /// let client = Client::new()?;
    ///
    /// // Raw bytes
    /// let resp = client.request("POST", "https://httpbin.org/post")
    ///     .body(b"raw bytes")
    ///     .send()?;
    /// # Ok::<(), windows::core::Error>(())
    /// ```
    ///
    /// ```no_run
    /// # #[cfg(feature = "json")]
    /// # fn demo() -> windows::core::Result<()> {
    /// # use winhttp::{Body, Client};
    /// # let client = Client::new()?;
    /// // JSON body (sets Content-Type automatically)
    /// let resp = client.request("POST", "https://httpbin.org/post")
    ///     .body(Body::json(&serde_json::json!({"key": "value"}))?)
    ///     .send()?;
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn body(mut self, data: impl Into<Body>) -> Self {
        self.body = Some(data.into());
        self
    }

    /// Execute the request synchronously and return the full [`Response`].
    pub fn send(self) -> Result<Response> {
        let (body_headers, body_bytes) = split_body(self.body);
        let mut all_headers = body_headers;
        all_headers.extend(self.headers);
        self.client
            .execute(&self.method, &self.url, &all_headers, body_bytes.as_deref())
    }

    /// Execute the request asynchronously and return the full [`Response`].
    ///
    /// This future is **runtime-agnostic** — it works with any executor
    /// (tokio, smol, pollster, etc.).
    #[cfg(feature = "async")]
    pub async fn send_async(self) -> Result<Response> {
        let (body_headers, body_bytes) = split_body(self.body);
        let mut all_headers = body_headers;
        all_headers.extend(self.headers);
        self.client
            .execute_async(&self.method, &self.url, &all_headers, body_bytes)
            .await
    }
}

/// Split a `Body` into its implicit headers and raw bytes.
fn split_body(body: Option<Body>) -> (Vec<(String, String)>, Option<Vec<u8>>) {
    match body {
        Some(body) => {
            let headers = body_headers(&body);
            (headers, Some(body.bytes))
        }
        None => (Vec::new(), None),
    }
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

/// A reusable HTTP client backed by a WinHTTP [`Session`].
///
/// Create one `Client` and reuse it across many requests to benefit from
/// connection pooling and shared configuration.
///
/// # Base URL
///
/// Use [`Client::builder`] to set a base URL. Relative paths passed to
/// request methods are joined to the base URL, while absolute URLs
/// (starting with `http://` or `https://`) are used as-is.
///
/// ```no_run
/// # use winhttp::Client;
/// let client = Client::builder()
///     .base_url("https://httpbin.org")
///     .build()?;
///
/// let resp = client.get("/get")?;          // → https://httpbin.org/get
/// let resp = client.get("https://x.com")?; // → https://x.com (absolute)
/// # Ok::<(), windows::core::Error>(())
/// ```
pub struct Client {
    base_url: Option<String>,
    base_components: Option<UrlComponents>,
    session: Session,
    #[cfg(feature = "async")]
    async_session: Session,
}

impl Client {
    /// Create a new `Client` with default settings and no base URL.
    ///
    /// Shorthand for `Client::builder().build()`.
    pub fn new() -> Result<Self> {
        Self::builder().build()
    }

    /// Return a [`ClientBuilder`] for full configuration.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use winhttp::Client;
    /// let client = Client::builder()
    ///     .base_url("https://api.example.com")
    ///     .user_agent("my-app/2.0")
    ///     .connect_timeout_ms(10_000)
    ///     .build()?;
    /// # Ok::<(), windows::core::Error>(())
    /// ```
    #[must_use]
    pub fn builder() -> ClientBuilder {
        ClientBuilder {
            base_url: None,
            user_agent: "winhttp-rs/0.1.0".to_string(),
            connect_timeout_ms: 60_000,
            send_timeout_ms: 30_000,
            receive_timeout_ms: 30_000,
        }
    }

    /// Access the underlying sync [`Session`].
    #[must_use]
    pub fn session(&self) -> &Session {
        &self.session
    }

    /// Access the underlying async [`Session`].
    #[cfg(feature = "async")]
    #[must_use]
    pub fn async_session(&self) -> &Session {
        &self.async_session
    }

    /// Return the base URL, if one was configured.
    #[must_use]
    pub fn base_url(&self) -> Option<&str> {
        self.base_url.as_deref()
    }

    /// Resolve a URL against the configured base URL, returning cracked
    /// [`UrlComponents`] ready for use by the execute methods.
    ///
    /// - Absolute URLs are cracked directly via [`crack_url`].
    /// - Relative paths are merged with the stored base components.
    /// - If no base URL is configured, the input is cracked as-is (will
    ///   fail if it is not a valid absolute URL).
    fn resolve_url(&self, url: &str) -> Result<UrlComponents> {
        // If crack_url succeeds the URL is already absolute — use it.
        if let Ok(components) = crack_url(url) {
            return Ok(components);
        }

        // Relative path — we need stored base components.
        let Some(base) = &self.base_components else {
            // No base URL configured; crack again to surface the original
            // WinHTTP error for the caller.
            return crack_url(url);
        };

        let mut components = base.clone();

        // Split the relative URL into path and query/fragment.
        let (path_part, extra_part) = match url.find(['?', '#']) {
            Some(i) => (&url[..i], &url[i..]),
            None => (url, ""),
        };

        if path_part.starts_with('/') {
            components.path = path_part.to_string();
        } else {
            let base_path = components.path.trim_end_matches('/');
            components.path = format!("{base_path}/{path_part}");
        }
        components.extra_info = extra_part.to_string();

        Ok(components)
    }

    /// Start building a request with a custom method and URL.
    ///
    /// Use this when you need to set headers or a body before sending.
    /// The `url` is resolved against the base URL (see [`Client`] docs).
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use winhttp::Client;
    /// let client = Client::builder()
    ///     .base_url("https://httpbin.org")
    ///     .build()?;
    /// let resp = client
    ///     .request("PATCH", "/patch")
    ///     .header("Content-Type", "application/json")
    ///     .body(b"{\"patched\":true}")
    ///     .send()?;
    /// # Ok::<(), windows::core::Error>(())
    /// ```
    #[must_use]
    pub fn request(&self, method: &str, url: &str) -> RequestHelper<'_> {
        RequestHelper {
            client: self,
            method: method.to_string(),
            url: url.to_string(),
            headers: Vec::new(),
            body: None,
        }
    }

    // -- Sync helpers -------------------------------------------------------

    /// Perform a synchronous `GET` request.
    ///
    /// The `url` is resolved against the base URL (see [`Client`] docs).
    pub fn get(&self, url: &str) -> Result<Response> {
        self.execute("GET", url, &[], None)
    }

    /// Perform a synchronous `POST` request with the given body.
    ///
    /// The body can be raw bytes (`&[u8]`, `Vec<u8>`, `&str`, `String`) or a
    /// [`Body::json`] value. See [`Body`] for details.
    ///
    /// The `url` is resolved against the base URL (see [`Client`] docs).
    pub fn post(&self, url: &str, body: impl Into<Body>) -> Result<Response> {
        let body = body.into();
        let headers = body_headers(&body);
        self.execute("POST", url, &headers, Some(&body.bytes))
    }

    /// Perform a synchronous `PUT` request with the given body.
    ///
    /// The body can be raw bytes or a [`Body::json`] value. See [`Body`].
    ///
    /// The `url` is resolved against the base URL (see [`Client`] docs).
    pub fn put(&self, url: &str, body: impl Into<Body>) -> Result<Response> {
        let body = body.into();
        let headers = body_headers(&body);
        self.execute("PUT", url, &headers, Some(&body.bytes))
    }

    /// Perform a synchronous `DELETE` request.
    ///
    /// The `url` is resolved against the base URL (see [`Client`] docs).
    pub fn delete(&self, url: &str) -> Result<Response> {
        self.execute("DELETE", url, &[], None)
    }

    /// Perform a synchronous `PATCH` request with the given body.
    ///
    /// The body can be raw bytes or a [`Body::json`] value. See [`Body`].
    ///
    /// The `url` is resolved against the base URL (see [`Client`] docs).
    pub fn patch(&self, url: &str, body: impl Into<Body>) -> Result<Response> {
        let body = body.into();
        let headers = body_headers(&body);
        self.execute("PATCH", url, &headers, Some(&body.bytes))
    }

    /// Perform a synchronous `HEAD` request.
    ///
    /// The returned `Response` will have an empty body since HEAD responses
    /// contain no body by definition.
    ///
    /// The `url` is resolved against the base URL (see [`Client`] docs).
    pub fn head(&self, url: &str) -> Result<Response> {
        self.execute_head(url)
    }

    // -- Async helpers ------------------------------------------------------

    /// Perform an async `GET` request.
    ///
    /// The `url` is resolved against the base URL (see [`Client`] docs).
    #[cfg(feature = "async")]
    pub async fn async_get(&self, url: &str) -> Result<Response> {
        self.execute_async("GET", url, &[], None).await
    }

    /// Perform an async `POST` request with the given body.
    ///
    /// The body can be raw bytes (`&[u8]`, `Vec<u8>`, `&str`, `String`) or a
    /// [`Body::json`] value. See [`Body`] for details.
    ///
    /// The `url` is resolved against the base URL (see [`Client`] docs).
    #[cfg(feature = "async")]
    pub async fn async_post(&self, url: &str, body: impl Into<Body>) -> Result<Response> {
        let body = body.into();
        let headers = body_headers(&body);
        self.execute_async("POST", url, &headers, Some(body.bytes))
            .await
    }

    /// Perform an async `PUT` request with the given body.
    ///
    /// The body can be raw bytes or a [`Body::json`] value. See [`Body`].
    ///
    /// The `url` is resolved against the base URL (see [`Client`] docs).
    #[cfg(feature = "async")]
    pub async fn async_put(&self, url: &str, body: impl Into<Body>) -> Result<Response> {
        let body = body.into();
        let headers = body_headers(&body);
        self.execute_async("PUT", url, &headers, Some(body.bytes))
            .await
    }

    /// Perform an async `DELETE` request.
    ///
    /// The `url` is resolved against the base URL (see [`Client`] docs).
    #[cfg(feature = "async")]
    pub async fn async_delete(&self, url: &str) -> Result<Response> {
        self.execute_async("DELETE", url, &[], None).await
    }

    /// Perform an async `PATCH` request with the given body.
    ///
    /// The body can be raw bytes or a [`Body::json`] value. See [`Body`].
    ///
    /// The `url` is resolved against the base URL (see [`Client`] docs).
    #[cfg(feature = "async")]
    pub async fn async_patch(&self, url: &str, body: impl Into<Body>) -> Result<Response> {
        let body = body.into();
        let headers = body_headers(&body);
        self.execute_async("PATCH", url, &headers, Some(body.bytes))
            .await
    }

    /// Perform an async `HEAD` request.
    ///
    /// The `url` is resolved against the base URL (see [`Client`] docs).
    #[cfg(feature = "async")]
    pub async fn async_head(&self, url: &str) -> Result<Response> {
        self.execute_async_head(url).await
    }

    // -- Internal -----------------------------------------------------------

    fn execute(
        &self,
        method: &str,
        url: &str,
        headers: &[(String, String)],
        body: Option<&[u8]>,
    ) -> Result<Response> {
        let components = self.resolve_url(url)?;
        let secure = components.scheme.eq_ignore_ascii_case("https");
        let path_and_query = if components.extra_info.is_empty() {
            components.path.clone()
        } else {
            format!("{}{}", components.path, components.extra_info)
        };

        let connection = self.session.connect(&components.host, components.port)?;

        let mut builder = connection.request(method, &path_and_query);
        if secure {
            builder = builder.secure();
        }
        for (name, value) in headers {
            builder = builder.header(name, value);
        }
        let request = builder.build()?;

        match body {
            Some(data) if !data.is_empty() => request.send_with_body(data)?,
            _ => request.send()?,
        }
        request.receive_response()?;

        let status = request.status_code()?;
        let status_text = request.status_text().unwrap_or_default();
        let resp_headers = request.raw_headers().unwrap_or_default();
        let resp_body = request.read_all()?;

        Ok(Response {
            status,
            status_text,
            headers: resp_headers,
            body: resp_body,
        })
    }

    fn execute_head(&self, url: &str) -> Result<Response> {
        let components = self.resolve_url(url)?;
        let secure = components.scheme.eq_ignore_ascii_case("https");
        let path_and_query = if components.extra_info.is_empty() {
            components.path.clone()
        } else {
            format!("{}{}", components.path, components.extra_info)
        };

        let connection = self.session.connect(&components.host, components.port)?;
        let mut builder = connection.request("HEAD", &path_and_query);
        if secure {
            builder = builder.secure();
        }
        let request = builder.build()?;
        request.send()?;
        request.receive_response()?;

        let status = request.status_code()?;
        let status_text = request.status_text().unwrap_or_default();
        let resp_headers = request.raw_headers().unwrap_or_default();

        Ok(Response {
            status,
            status_text,
            headers: resp_headers,
            body: Vec::new(),
        })
    }

    #[cfg(feature = "async")]
    async fn execute_async(
        &self,
        method: &str,
        url: &str,
        headers: &[(String, String)],
        body: Option<Vec<u8>>,
    ) -> Result<Response> {
        let components = self.resolve_url(url)?;
        let secure = components.scheme.eq_ignore_ascii_case("https");
        let path_and_query = if components.extra_info.is_empty() {
            components.path.clone()
        } else {
            format!("{}{}", components.path, components.extra_info)
        };

        let connection = self
            .async_session
            .connect(&components.host, components.port)?;

        let mut builder = connection.request(method, &path_and_query);
        if secure {
            builder = builder.secure();
        }
        for (name, value) in headers {
            builder = builder.header(name, value);
        }
        let request = builder.build()?;
        let async_request = request.into_async()?;

        let response = match body {
            Some(data) if !data.is_empty() => async_request.send_with_body(data).await?,
            _ => async_request.send().await?,
        };

        let status = response.status_code()?;
        let status_text = response.status_text().unwrap_or_default();
        let resp_headers = response.raw_headers().unwrap_or_default();
        let resp_body = response.read_all().await?;

        Ok(Response {
            status,
            status_text,
            headers: resp_headers,
            body: resp_body,
        })
    }

    #[cfg(feature = "async")]
    async fn execute_async_head(&self, url: &str) -> Result<Response> {
        let components = self.resolve_url(url)?;
        let secure = components.scheme.eq_ignore_ascii_case("https");
        let path_and_query = if components.extra_info.is_empty() {
            components.path.clone()
        } else {
            format!("{}{}", components.path, components.extra_info)
        };

        let connection = self
            .async_session
            .connect(&components.host, components.port)?;
        let mut builder = connection.request("HEAD", &path_and_query);
        if secure {
            builder = builder.secure();
        }
        let request = builder.build()?;
        let async_request = request.into_async()?;
        let response = async_request.send().await?;

        let status = response.status_code()?;
        let status_text = response.status_text().unwrap_or_default();
        let resp_headers = response.raw_headers().unwrap_or_default();

        Ok(Response {
            status,
            status_text,
            headers: resp_headers,
            body: Vec::new(),
        })
    }
}

// ---------------------------------------------------------------------------
// Module-level one-shot helpers
// ---------------------------------------------------------------------------

/// Perform a one-shot synchronous `GET` request.
///
/// Creates an ephemeral [`Client`] internally. For multiple requests, prefer
/// creating a [`Client`] and reusing it.
///
/// # Example
///
/// ```no_run
/// let resp = winhttp::get("https://httpbin.org/get")?;
/// assert!(resp.is_success());
/// println!("{}", resp.text());
/// # Ok::<(), windows::core::Error>(())
/// ```
pub fn get(url: &str) -> Result<Response> {
    Client::new()?.get(url)
}

/// Perform a one-shot synchronous `POST` request.
///
/// The body can be raw bytes (`&[u8]`, `Vec<u8>`, `&str`, `String`) or a
/// [`Body::json`] value.
///
/// # Example
///
/// ```no_run
/// let resp = winhttp::post("https://httpbin.org/post", b"hello".as_slice())?;
/// # Ok::<(), windows::core::Error>(())
/// ```
pub fn post(url: &str, body: impl Into<Body>) -> Result<Response> {
    Client::new()?.post(url, body)
}

/// Perform a one-shot synchronous `PUT` request.
pub fn put(url: &str, body: impl Into<Body>) -> Result<Response> {
    Client::new()?.put(url, body)
}

/// Perform a one-shot synchronous `DELETE` request.
pub fn delete(url: &str) -> Result<Response> {
    Client::new()?.delete(url)
}

/// Perform a one-shot synchronous `PATCH` request.
pub fn patch(url: &str, body: impl Into<Body>) -> Result<Response> {
    Client::new()?.patch(url, body)
}

/// Perform a one-shot synchronous `HEAD` request.
pub fn head(url: &str) -> Result<Response> {
    Client::new()?.head(url)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_response_status_checks() {
        let resp = Response {
            status: 200,
            status_text: "OK".to_string(),
            headers: String::new(),
            body: b"hello".to_vec(),
        };
        assert!(resp.is_success());
        assert!(!resp.is_redirect());
        assert!(!resp.is_client_error());
        assert!(!resp.is_server_error());
        assert_eq!(resp.text(), "hello");
    }

    #[test]
    fn test_response_redirect() {
        let resp = Response {
            status: 301,
            status_text: "Moved Permanently".to_string(),
            headers: String::new(),
            body: Vec::new(),
        };
        assert!(!resp.is_success());
        assert!(resp.is_redirect());
    }

    #[test]
    fn test_response_client_error() {
        let resp = Response {
            status: 404,
            status_text: "Not Found".to_string(),
            headers: String::new(),
            body: Vec::new(),
        };
        assert!(resp.is_client_error());
        assert!(!resp.is_server_error());
    }

    #[test]
    fn test_response_server_error() {
        let resp = Response {
            status: 500,
            status_text: "Internal Server Error".to_string(),
            headers: String::new(),
            body: Vec::new(),
        };
        assert!(resp.is_server_error());
        assert!(!resp.is_client_error());
    }

    #[test]
    fn test_client_creation() {
        let client = Client::new();
        assert!(client.is_ok());
    }

    #[test]
    fn test_client_with_builder() {
        let client = Client::builder()
            .user_agent("test-client/1.0")
            .connect_timeout_ms(5000)
            .send_timeout_ms(3000)
            .receive_timeout_ms(10_000)
            .build();
        assert!(client.is_ok());
    }

    #[test]
    fn test_client_with_base_url() {
        let client = Client::builder().base_url("https://httpbin.org").build();
        assert!(client.is_ok());
        let client = client.unwrap();
        assert_eq!(client.base_url(), Some("https://httpbin.org"));
    }

    #[test]
    fn test_client_base_url_trailing_slash_trimmed() {
        let client = Client::builder()
            .base_url("https://httpbin.org///")
            .build()
            .unwrap();
        assert_eq!(client.base_url(), Some("https://httpbin.org"));
    }

    #[test]
    fn test_resolve_url_absolute_bypasses_base() {
        let client = Client::builder()
            .base_url("https://base.example.com")
            .build()
            .unwrap();
        let resolved = client.resolve_url("https://other.com/foo").unwrap();
        assert_eq!(resolved.host, "other.com");
        assert_eq!(resolved.path, "/foo");
    }

    #[test]
    fn test_resolve_url_relative_path() {
        let client = Client::builder()
            .base_url("https://base.example.com")
            .build()
            .unwrap();
        let resolved = client.resolve_url("/api/users").unwrap();
        assert_eq!(resolved.host, "base.example.com");
        assert_eq!(resolved.path, "/api/users");
    }

    #[test]
    fn test_resolve_url_relative_no_slash() {
        let client = Client::builder()
            .base_url("https://base.example.com")
            .build()
            .unwrap();
        let resolved = client.resolve_url("api/users").unwrap();
        assert_eq!(resolved.host, "base.example.com");
        assert_eq!(resolved.path, "/api/users");
    }

    #[test]
    fn test_resolve_url_no_base() {
        let client = Client::new().unwrap();
        let resolved = client.resolve_url("https://example.com/test").unwrap();
        assert_eq!(resolved.host, "example.com");
        assert_eq!(resolved.path, "/test");
    }

    #[test]
    fn test_resolve_url_relative_with_query() {
        let client = Client::builder()
            .base_url("https://base.example.com")
            .build()
            .unwrap();
        let resolved = client.resolve_url("/search?q=hello&page=2").unwrap();
        assert_eq!(resolved.host, "base.example.com");
        assert_eq!(resolved.path, "/search");
        assert_eq!(resolved.extra_info, "?q=hello&page=2");
    }

    #[test]
    fn test_resolve_url_relative_fails_without_base() {
        let client = Client::new().unwrap();
        let result = client.resolve_url("/relative/path");
        assert!(
            result.is_err(),
            "relative path without base URL should fail"
        );
    }

    // -- Body tests ---------------------------------------------------------

    #[test]
    fn test_body_from_byte_slice() {
        let body: Body = b"hello".as_slice().into();
        assert_eq!(body.as_bytes(), b"hello");
        assert!(body.content_type().is_none());
    }

    #[test]
    fn test_body_from_vec() {
        let body: Body = vec![1, 2, 3].into();
        assert_eq!(body.as_bytes(), &[1, 2, 3]);
        assert!(body.content_type().is_none());
    }

    #[test]
    fn test_body_from_str() {
        let body: Body = "hello".into();
        assert_eq!(body.as_bytes(), b"hello");
        assert!(body.content_type().is_none());
    }

    #[test]
    fn test_body_from_string() {
        let body: Body = String::from("hello").into();
        assert_eq!(body.as_bytes(), b"hello");
        assert!(body.content_type().is_none());
    }

    #[test]
    fn test_body_headers_raw() {
        let body: Body = b"raw".as_slice().into();
        let headers = body_headers(&body);
        assert!(headers.is_empty());
    }

    #[cfg(feature = "json")]
    #[test]
    fn test_body_json() {
        use serde::Serialize;

        #[derive(Serialize)]
        struct Payload {
            key: String,
            count: u32,
        }

        let body = Body::json(&Payload {
            key: "hello".into(),
            count: 42,
        })
        .expect("serialization should succeed");

        assert_eq!(body.content_type(), Some("application/json"));

        let parsed: serde_json::Value =
            serde_json::from_slice(body.as_bytes()).expect("should be valid JSON");
        assert_eq!(parsed["key"], "hello");
        assert_eq!(parsed["count"], 42);
    }

    #[cfg(feature = "json")]
    #[test]
    fn test_body_json_headers() {
        let body = Body::json(&serde_json::json!({"a": 1})).expect("serialization should succeed");
        let headers = body_headers(&body);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Content-Type");
        assert_eq!(headers[0].1, "application/json");
    }

    #[cfg(feature = "json")]
    #[test]
    fn test_response_json() {
        use serde::Deserialize;

        #[derive(Deserialize)]
        struct Data {
            key: String,
            count: u32,
        }

        let resp = Response {
            status: 200,
            status_text: "OK".to_string(),
            headers: String::new(),
            body: br#"{"key":"hello","count":42}"#.to_vec(),
        };

        let data: Data = resp.json().expect("Failed to parse JSON");
        assert_eq!(data.key, "hello");
        assert_eq!(data.count, 42);
    }

    #[cfg(feature = "json")]
    #[test]
    fn test_response_json_error() {
        let resp = Response {
            status: 200,
            status_text: "OK".to_string(),
            headers: String::new(),
            body: b"not json".to_vec(),
        };

        let result: std::result::Result<serde_json::Value, _> = resp.json();
        assert!(result.is_err());
    }
}
