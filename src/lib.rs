//! # winhttp
//!
//! Safe, ergonomic Rust bindings for the Windows WinHTTP API.
//!
//! This crate provides both low-level access to WinHTTP functions and a
//! high-level [`Client`] with one-liner HTTP verb helpers. The async API is
//! **runtime-agnostic** — it works with any executor (tokio, smol, pollster,
//! `futures::executor`, etc.).
//!
//! ## Quick Start
//!
//! ### One-shot request
//!
//! ```no_run
//! let resp = winhttp::get("https://httpbin.org/get")?;
//! println!("{}", resp.text());
//! # Ok::<(), windows::core::Error>(())
//! ```
//!
//! ### Using the Client
//!
//! ```no_run
//! use winhttp::Client;
//!
//! // No base URL — pass full URLs:
//! let client = Client::new()?;
//! let resp = client.get("https://httpbin.org/get")?;
//! assert!(resp.is_success());
//!
//! // With base URL — pass paths:
//! let client = Client::builder()
//!     .base_url("https://httpbin.org")
//!     .build()?;
//!
//! let resp = client.get("/get")?;
//! assert!(resp.is_success());
//!
//! // POST with body
//! let resp = client.post("/post", b"hello")?;
//! println!("Status: {}", resp.status);
//!
//! // Builder pattern for custom headers
//! let resp = client
//!     .request("PUT", "/put")
//!     .header("Content-Type", "application/json")
//!     .body(b"{\"key\": \"value\"}")
//!     .send()?;
//! # Ok::<(), windows::core::Error>(())
//! ```
//!
//! ### Async (runtime-agnostic)
//!
//! Enable the `async` feature in your `Cargo.toml`:
//!
//! ```toml
//! [dependencies]
//! winhttp = { version = "0.1", features = ["async"] }
//! ```
//!
//! ```no_run
//! # #[cfg(feature = "async")]
//! # async fn demo() -> windows::core::Result<()> {
//! use winhttp::Client;
//!
//! let client = Client::builder()
//!     .base_url("https://httpbin.org")
//!     .build()?;
//! let resp = client.async_get("/get").await?;
//! println!("{}", resp.text());
//! # Ok(())
//! # }
//! ```
//!
//! ## Feature Flags
//!
//! | Feature | Default | Description |
//! |---------|---------|-------------|
//! | `async` | No | Enables async HTTP support via [`crossfire`](https://crates.io/crates/crossfire) channels. Runtime-agnostic. |
//! | `json`  | No | Adds `Response::json` for deserializing response bodies via `serde_json`. |
//! | `websocket` | No | Enables WebSocket support (`WebSocket`, `AsyncWebSocket`, typed helpers). |
//!
//! ## Architecture
//!
//! The crate is organized in layers:
//!
//! - **Low-level**: [`Session`], [`session::Connection`], [`Request`]
//!   — thin wrappers around WinHTTP handles with RAII cleanup.
//! - **Async bridge** (feature `async`): [`AsyncRequest`], [`AsyncResponse`] —
//!   WinHTTP callbacks are bridged to Rust [`Future`]s via
//!   [`crossfire`](https://crates.io/crates/crossfire) channels. No runtime assumed.
//! - **High-level**: [`Client`] — connection pooling, one-liner HTTP verbs,
//!   builder pattern, module-level convenience functions ([`get`], [`post`], etc.).
//! - **Types**: All WinHTTP constants, type-safe flag wrappers ([`AuthScheme`],
//!   [`SecurityFlags`], [`DecompressionFlags`], etc.), and info structs
//!   ([`CertificateInfo`], [`ConnectionInfo`], [`RequestTimes`], [`RequestStats`]).
//! - **Proxy**: Full proxy detection and configuration support via [`get_ie_proxy_config`],
//!   [`detect_auto_proxy_config_url`], [`Session::get_proxy_for_url`], etc.
//! - **WebSocket** (feature `websocket`): [`WebSocket`] with typed send/receive and close status helpers.
//!
//! ## Type-Safe Flags
//!
//! Methods accepting raw `u32` flags have `_typed()` variants that accept
//! strongly-typed wrappers:
//!
//! ```no_run
//! # use winhttp::*;
//! # fn demo() -> windows::core::Result<()> {
//! let session = Session::new()?;
//!
//! // Raw u32 API
//! session.set_secure_protocols(WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2 | WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3)?;
//!
//! // Type-safe API
//! session.set_secure_protocols_typed(SecureProtocol::MODERN)?;
//! # Ok(())
//! # }
//! ```

mod callback;
mod client;
mod handle;
mod proxy;
mod request;
mod session;
mod types;
mod url;
#[cfg(feature = "websocket")]
mod websocket;

#[cfg(feature = "async")]
mod async_request;

#[cfg(all(feature = "websocket", feature = "async"))]
mod async_websocket;

pub use callback::ProxyChangeNotification;
pub use client::{
    Body, Client, ClientBuilder, RequestHelper, Response, delete, get, head, patch, post, put,
};
pub use proxy::{
    AutoProxyOptions, IEProxyConfig, ProxyInfo, ProxyResolver, ProxyResult, ProxyResultEntry,
    ProxySettingsEx, ProxySettingsVersion, detect_auto_proxy_config_url, get_default_proxy_config,
    get_ie_proxy_config, set_default_proxy_config,
};
pub use request::{Request, RequestBuilder};
pub use session::{Connection, ConnectionGroupResult, Session, SessionConfig};
pub use url::{
    UrlComponents, check_platform, crack_url, create_url, time_from_system_time,
    time_to_system_time,
};
#[cfg(feature = "websocket")]
pub use websocket::WebSocket;

#[cfg(feature = "async")]
pub use async_request::{AsyncRequest, AsyncResponse, ReadAllFuture, SendFuture, WriteFuture};

#[cfg(all(feature = "websocket", feature = "async"))]
pub use async_websocket::{
    AsyncWebSocket, WebSocketMessage, WebSocketStream, WsCloseFuture, WsReceiveFuture, WsSendFuture,
};

pub use types::*;
