# winhttp

[![Crates.io](https://img.shields.io/crates/v/winhttp)](https://crates.io/crates/winhttp)
[![docs.rs](https://img.shields.io/docsrs/winhttp)](https://docs.rs/winhttp)
[![CI](https://img.shields.io/github/actions/workflow/status/stevefan1999-personal/winhttp/ci.yml?branch=master&label=CI)](https://github.com/stevefan1999-personal/winhttp/actions)
[![License: MIT](https://img.shields.io/crates/l/winhttp)](https://github.com/stevefan1999-personal/winhttp/blob/master/LICENSE)

Safe, ergonomic Rust bindings for the Windows WinHTTP API.

This crate lets you make HTTP requests on Windows without pulling in a large third-party HTTP stack. It talks directly to the operating system through WinHTTP, so your binaries stay small and you get automatic access to system proxy settings, TLS, and HTTP/2 for free.

Both synchronous and asynchronous requests are supported. The async API is runtime-agnostic, meaning it works with tokio, smol, pollster, or any other executor you prefer.

## Use case

Suppose you are building a Windows desktop tool that periodically checks an internal API for updates. You want something lightweight that respects corporate proxy settings out of the box and does not drag in OpenSSL or a bundled TLS library.

```rust
use winhttp::Client;

fn main() -> windows::core::Result<()> {
    // Create a reusable client with a base URL.
    let client = Client::builder()
        .base_url("https://api.example.com")
        .user_agent("update-checker/1.0")
        .connect_timeout_ms(10_000)
        .build()?;

    // Check for the latest version.
    let resp = client.get("/version/latest")?;

    if resp.is_success() {
        println!("Latest version: {}", resp.text());
    } else {
        eprintln!("Server returned status {}", resp.status);
    }

    // Post a usage report.
    let body = br#"{"event": "check", "os": "windows"}"#;
    let resp = client
        .request("POST", "/telemetry")
        .header("Content-Type", "application/json")
        .body(body)
        .send()?;

    println!("Telemetry status: {}", resp.status);
    Ok(())
}
```

If you only need a single one-off request, the module-level helpers make it even shorter:

```rust
let resp = winhttp::get("https://httpbin.org/get")?;
println!("{}", resp.text());
```

## Features

The library is organized in layers so you can choose the level of control you need.

**High-level client.** The `Client` type offers one-liner methods for GET, POST, PUT, DELETE, PATCH, and HEAD. It handles connection pooling, URL resolution against a configurable base URL, and a builder pattern for custom headers and bodies.

**Async support.** Enable the `async` feature to unlock `async_get`, `async_post`, and friends. These return standard `Future`s that work with any executor. There is no hidden runtime—just wire them up to whatever you already use.

```toml
[dependencies]
winhttp = { version = "0.1", features = ["async"] }
```

```rust
// Works with tokio, smol, pollster, or anything else.
let resp = client.async_get("/data").await?;
```

**JSON deserialization.** Enable the `json` feature to call `resp.json::<T>()` and get your response body deserialized through serde in one step.

**JSON request bodies.** The same `json` feature also provides `Body::json`, which serializes a struct into JSON and sets the `Content-Type` header automatically. Every method that accepts a body (`post`, `put`, `patch`, and the builder's `.body()`) takes `impl Into<Body>`, so you can pass raw bytes or a `Body::json` value interchangeably.

```toml
[dependencies]
winhttp = { version = "0.1", features = ["async", "json"] }
```

```rust
use serde::{Deserialize, Serialize};
use winhttp::{Body, Client};

#[derive(Serialize)]
struct CreateUser {
    name: String,
    email: String,
}

#[derive(Deserialize)]
struct User {
    id: u64,
    name: String,
}

fn create_user(client: &Client) -> windows::core::Result<()> {
    let payload = CreateUser {
        name: "Ada".into(),
        email: "ada@example.com".into(),
    };

    // Body::json serializes the struct and sets Content-Type for you.
    let resp = client.post("/users", Body::json(&payload)?)?;

    // Deserialize the response back into a different struct.
    let user: User = resp.json().expect("invalid JSON");
    println!("Created user #{}: {}", user.id, user.name);
    Ok(())
}
```

Raw bytes still work everywhere a `Body` is expected:

```rust
client.post("/raw", b"plain bytes")?;
client.post("/text", "string body")?;
```

**Low-level access.** The `Session`, `Connection`, and `Request` types are thin wrappers around the raw WinHTTP handles. They give you full control over protocol flags, TLS settings, decompression, redirect policies, and authentication schemes while still handling resource cleanup automatically.

**WebSocket.** Enable the `websocket` feature to get synchronous and asynchronous WebSocket support. The `WebSocket` type upgrades an HTTP connection and provides typed send and receive operations. With both `websocket` and `async` enabled, `AsyncWebSocket` adds future-based send/receive, graceful close, and a `futures_core::Stream` adapter for reading messages in a loop.

```toml
[dependencies]
winhttp = { version = "0.1", features = ["websocket"] }
```

```rust
use winhttp::*;

fn echo(session: &Session) -> windows::core::Result<()> {
    let conn = session.connect("echo.websocket.org", 443)?;

    let request = conn
        .request("GET", "/.ws")
        .secure()
        .build()?;

    // Tell WinHTTP to perform the WebSocket upgrade handshake.
    request.set_option(WINHTTP_OPTION_UPGRADE_TO_WEB_SOCKET, &[])?;

    request.send()?;
    request.receive_response()?;

    let ws = WebSocket::from_upgrade(request)?;
    ws.send_text("Hello!")?;

    let mut buf = vec![0u8; 4096];
    let (len, _) = ws.receive(&mut buf)?;
    println!("Echo: {}", String::from_utf8_lossy(&buf[..len]));

    ws.close_normal("done")?;
    Ok(())
}
```

**Proxy detection.** Built-in helpers read the system proxy configuration, detect auto-proxy URLs, and resolve proxies for specific URLs, matching the behavior that browsers and other Windows applications use.

**Type-safe flags.** Methods that accept raw `u32` flags also have `_typed()` variants that use strongly-typed wrappers like `AuthScheme`, `SecurityFlags`, `SecureProtocol`, and `DecompressionFlags`. This prevents mixing up unrelated flag values at compile time.

## Feature flags

| Feature     | Default | Description |
|-------------|---------|-------------|
| `async`     | No      | Enables async HTTP methods via crossfire channels. Runtime-agnostic. |
| `json`      | No      | Adds `Response::json` for deserializing and `Body::json` for serializing via serde. |
| `websocket` | No      | Enables `WebSocket` and `AsyncWebSocket` for upgrading HTTP connections to WebSocket. |

## Requirements

This crate only works on Windows. It requires Rust 1.85 or later.

## Examples

The repository includes several runnable examples.

```sh
# Synchronous low-level request
cargo run -p example-sync

# Async with tokio
cargo run -p example-tokio

# Async with smol
cargo run -p example-smol

# High-level client helpers
cargo run --example client_helpers --features async

# Feature demo (HTTP/2, decompression, redirects)
cargo run --example features

# Async GET with pollster
cargo run --example async_get --features async

# Async with JSON request/response bodies
cargo run --example async_json --features "async json"

# Sync + async WebSocket echo
cargo run --example websocket --features "websocket async"
```

## License

See the license file in the repository for details.
