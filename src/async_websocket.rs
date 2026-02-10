use crate::async_request::AsyncResponse;
use crate::handle::WinHttpHandle;
use crossfire::mpsc;
use parking_lot::Mutex;
use std::ffi::c_void;
use std::future::Future;
use std::mem::ManuallyDrop;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};
use windows::Win32::Foundation::WIN32_ERROR;
use windows::Win32::Networking::WinHttp::*;
use windows::core::{Error, Result};

/// Windows error code for an asynchronous operation that has been initiated
/// but not yet completed.
const ERROR_IO_PENDING_VALUE: u32 = 997;

#[derive(Debug)]
enum WsSendEvent {
    WriteComplete,
    Error(u32),
}

#[derive(Debug)]
enum WsRecvEvent {
    ReadComplete { bytes_read: u32, buffer_type: i32 },
    CloseComplete,
    Error(u32),
}

type SendSender = crossfire::MTx<mpsc::List<WsSendEvent>>;
type SendReceiver = crossfire::Rx<mpsc::List<WsSendEvent>>;
type RecvSender = crossfire::MTx<mpsc::List<WsRecvEvent>>;
type RecvReceiver = crossfire::Rx<mpsc::List<WsRecvEvent>>;

struct WebSocketContext {
    send_waker: Mutex<Option<Waker>>,
    recv_waker: Mutex<Option<Waker>>,
    send_sender: SendSender,
    recv_sender: RecvSender,
}

impl WebSocketContext {
    fn new(send_sender: SendSender, recv_sender: RecvSender) -> Pin<Arc<Self>> {
        Arc::pin(Self {
            send_waker: Mutex::new(None),
            recv_waker: Mutex::new(None),
            send_sender,
            recv_sender,
        })
    }

    fn wake_send(&self) {
        if let Some(waker) = self.send_waker.lock().take() {
            waker.wake();
        }
    }

    fn wake_recv(&self) {
        if let Some(waker) = self.recv_waker.lock().take() {
            waker.wake();
        }
    }

    fn set_send_waker(&self, waker: &Waker) {
        let mut guard = self.send_waker.lock();
        match guard.as_ref() {
            Some(existing) if existing.will_wake(waker) => {}
            _ => *guard = Some(waker.clone()),
        }
    }

    fn set_recv_waker(&self, waker: &Waker) {
        let mut guard = self.recv_waker.lock();
        match guard.as_ref() {
            Some(existing) if existing.will_wake(waker) => {}
            _ => *guard = Some(waker.clone()),
        }
    }
}

/// # Safety
///
/// This function is called by WinHTTP on its own thread pool. The `context`
/// parameter is a raw pointer to a pinned `WebSocketContext` whose lifetime is
/// guaranteed by the owning `AsyncWebSocket`.
unsafe extern "system" fn async_websocket_callback(
    _hinternet: *mut c_void,
    context: usize,
    status: u32,
    status_info: *mut c_void,
    _status_info_length: u32,
) {
    let Some(ctx) = (unsafe { (context as *const WebSocketContext).as_ref() }) else {
        return;
    };

    match status {
        WINHTTP_CALLBACK_STATUS_WRITE_COMPLETE => {
            let _ = ctx.send_sender.send(WsSendEvent::WriteComplete);
            ctx.wake_send();
        }
        WINHTTP_CALLBACK_STATUS_READ_COMPLETE => {
            if !status_info.is_null() {
                let ws_status = unsafe { &*(status_info as *const WINHTTP_WEB_SOCKET_STATUS) };
                let _ = ctx.recv_sender.send(WsRecvEvent::ReadComplete {
                    bytes_read: ws_status.dwBytesTransferred,
                    buffer_type: ws_status.eBufferType.0,
                });
            }
            ctx.wake_recv();
        }
        WINHTTP_CALLBACK_STATUS_CLOSE_COMPLETE => {
            let _ = ctx.recv_sender.send(WsRecvEvent::CloseComplete);
            ctx.wake_recv();
        }
        WINHTTP_CALLBACK_STATUS_SHUTDOWN_COMPLETE => {
            let _ = ctx.send_sender.send(WsSendEvent::WriteComplete);
            ctx.wake_send();
        }
        WINHTTP_CALLBACK_STATUS_REQUEST_ERROR => {
            if !status_info.is_null() {
                let ws_err = unsafe { &*(status_info as *const WINHTTP_WEB_SOCKET_ASYNC_RESULT) };
                let error_code = ws_err.AsyncResult.dwError;
                // Operation.0: 0 = Send, else = Receive/Close/Shutdown
                if ws_err.Operation.0 == 0 {
                    let _ = ctx.send_sender.send(WsSendEvent::Error(error_code));
                    ctx.wake_send();
                } else {
                    let _ = ctx.recv_sender.send(WsRecvEvent::Error(error_code));
                    ctx.wake_recv();
                }
            }
        }
        _ => {}
    }
}

/// A complete WebSocket message received from the server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WebSocketMessage {
    /// A complete UTF-8 text message.
    Text(String),
    /// A complete binary message.
    Binary(Vec<u8>),
    /// A close frame was received. The connection is being shut down.
    Close,
}

/// An async WebSocket connection built on top of WinHTTP's async machinery.
///
/// Two independent crossfire channels (send and receive) allow concurrent
/// `send` + `receive` operations without contention.
///
/// Created from an [`AsyncResponse`] whose HTTP 101 upgrade has completed.
pub struct AsyncWebSocket {
    handle: WinHttpHandle,
    context: Pin<Arc<WebSocketContext>>,
    send_receiver: SendReceiver,
    recv_receiver: RecvReceiver,
}

impl AsyncWebSocket {
    /// Upgrade an HTTP 101 response into an async WebSocket connection.
    ///
    /// Internally calls `WinHttpWebSocketCompleteUpgrade`, closes the
    /// original request handle, then installs a new callback and context
    /// on the WebSocket handle.
    pub fn from_response(response: AsyncResponse<'_>) -> Result<Self> {
        let request = response.into_request();

        // Prevent `Request`'s Drop from closing the handle â€” we need it for
        // the upgrade call and will close it ourselves afterward.
        let request = ManuallyDrop::new(request);
        let request_raw = request.handle.as_raw();

        let ws_raw = unsafe { WinHttpWebSocketCompleteUpgrade(request_raw, None) };
        if ws_raw.is_null() {
            return Err(Error::from_thread());
        }

        let handle = unsafe { WinHttpHandle::from_raw(ws_raw) }
            .expect("WinHttpWebSocketCompleteUpgrade returned non-null");

        // Create two independent channels.
        let (send_tx, send_rx) = mpsc::unbounded_blocking();
        let (recv_tx, recv_rx) = mpsc::unbounded_blocking();
        let context = WebSocketContext::new(send_tx, recv_tx);

        // Install our callback on the WebSocket handle.
        unsafe {
            WinHttpSetStatusCallback(
                handle.as_raw(),
                Some(async_websocket_callback),
                WINHTTP_CALLBACK_FLAG_ALL_NOTIFICATIONS,
                0,
            )
        };

        // Set the context pointer so the callback can reach our channels.
        let ctx_ptr: usize = &*context as *const WebSocketContext as usize;
        unsafe {
            WinHttpSetOption(
                Some(handle.as_raw()),
                WINHTTP_OPTION_CONTEXT_VALUE,
                Some(&ctx_ptr.to_ne_bytes()),
            )?;
        }

        // Now safe to close the original request handle.
        unsafe {
            let _ = WinHttpCloseHandle(request_raw);
        }

        Ok(Self {
            handle,
            context,
            send_receiver: send_rx,
            recv_receiver: recv_rx,
        })
    }

    /// Send raw data with the given buffer type.
    pub fn send(
        &self,
        data: &[u8],
        buffer_type: WINHTTP_WEB_SOCKET_BUFFER_TYPE,
    ) -> WsSendFuture<'_> {
        WsSendFuture {
            ws: self,
            data: data.to_vec(),
            buffer_type,
            initiated: false,
        }
    }

    /// Send a UTF-8 text message.
    pub fn send_text(&self, text: &str) -> WsSendFuture<'_> {
        self.send(text.as_bytes(), WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE)
    }

    /// Send a binary message.
    pub fn send_binary(&self, data: &[u8]) -> WsSendFuture<'_> {
        self.send(data, WINHTTP_WEB_SOCKET_BINARY_MESSAGE_BUFFER_TYPE)
    }

    /// Receive a single complete [`WebSocketMessage`].
    ///
    /// Fragments are reassembled automatically â€” the future resolves only
    /// when a complete text, binary, or close message has been collected.
    pub fn receive(&self) -> WsReceiveFuture<'_> {
        WsReceiveFuture {
            ws: self,
            buffer: vec![0u8; 8192],
            fragments: Vec::new(),
            is_text: None,
            initiated: false,
        }
    }

    /// Initiate a graceful close of the WebSocket connection.
    pub fn close(&self, status: u16, reason: &str) -> WsCloseFuture<'_> {
        WsCloseFuture {
            ws: self,
            status,
            reason: reason.as_bytes().to_vec(),
            initiated: false,
        }
    }

    // Stream adapter

    /// Consume the `AsyncWebSocket` and return a [`WebSocketStream`] that
    /// implements [`futures_core::Stream`].
    pub fn into_stream(self) -> WebSocketStream {
        WebSocketStream {
            ws: self,
            buffer: vec![0u8; 8192],
            fragments: Vec::new(),
            is_text: None,
            initiated: false,
            closed: false,
        }
    }
}

// WsSendFuture

/// Future returned by [`AsyncWebSocket::send`], [`send_text`](AsyncWebSocket::send_text),
/// and [`send_binary`](AsyncWebSocket::send_binary).
pub struct WsSendFuture<'ws> {
    ws: &'ws AsyncWebSocket,
    data: Vec<u8>,
    buffer_type: WINHTTP_WEB_SOCKET_BUFFER_TYPE,
    initiated: bool,
}

impl Future for WsSendFuture<'_> {
    type Output = Result<()>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;
        this.ws.context.set_send_waker(cx.waker());

        if !this.initiated {
            this.initiated = true;
            let status = unsafe {
                WinHttpWebSocketSend(this.ws.handle.as_raw(), this.buffer_type, Some(&this.data))
            };
            if status == 0 {
                // Synchronous completion (unusual on async sessions).
                return Poll::Ready(Ok(()));
            }
            if status != ERROR_IO_PENDING_VALUE {
                return Poll::Ready(Err(Error::from_thread()));
            }
            // ERROR_IO_PENDING â€” fall through to drain the channel.
        }

        match this.ws.send_receiver.try_recv() {
            Ok(WsSendEvent::WriteComplete) => Poll::Ready(Ok(())),
            Ok(WsSendEvent::Error(code)) => Poll::Ready(Err(Error::from(WIN32_ERROR(code)))),
            Err(crossfire::TryRecvError::Empty) => Poll::Pending,
            Err(crossfire::TryRecvError::Disconnected) => Poll::Ready(Err(Error::empty())),
        }
    }
}

// WsReceiveFuture

/// Future returned by [`AsyncWebSocket::receive`].
///
/// Automatically reassembles fragments into a single complete message.
pub struct WsReceiveFuture<'ws> {
    ws: &'ws AsyncWebSocket,
    buffer: Vec<u8>,
    fragments: Vec<u8>,
    is_text: Option<bool>,
    initiated: bool,
}

impl Future for WsReceiveFuture<'_> {
    type Output = Result<WebSocketMessage>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;
        this.ws.context.set_recv_waker(cx.waker());

        if !this.initiated {
            this.initiated = true;
            if let Err(e) = initiate_receive(&this.ws.handle, &mut this.buffer) {
                return Poll::Ready(Err(e));
            }
        }

        loop {
            match this.ws.recv_receiver.try_recv() {
                Ok(WsRecvEvent::ReadComplete {
                    bytes_read,
                    buffer_type,
                }) => {
                    let data = &this.buffer[..bytes_read as usize];
                    match buffer_type {
                        // BinaryFragment
                        1 => {
                            if this.is_text.is_none() {
                                this.is_text = Some(false);
                            }
                            this.fragments.extend_from_slice(data);
                            // Initiate another receive for the next fragment.
                            if let Err(e) = initiate_receive(&this.ws.handle, &mut this.buffer) {
                                return Poll::Ready(Err(e));
                            }
                            this.ws.context.set_recv_waker(cx.waker());
                            continue;
                        }
                        // Utf8Fragment
                        3 => {
                            if this.is_text.is_none() {
                                this.is_text = Some(true);
                            }
                            this.fragments.extend_from_slice(data);
                            if let Err(e) = initiate_receive(&this.ws.handle, &mut this.buffer) {
                                return Poll::Ready(Err(e));
                            }
                            this.ws.context.set_recv_waker(cx.waker());
                            continue;
                        }
                        // BinaryMessage (complete or final fragment)
                        0 => {
                            let mut full = std::mem::take(&mut this.fragments);
                            full.extend_from_slice(data);
                            return Poll::Ready(Ok(WebSocketMessage::Binary(full)));
                        }
                        // Utf8Message (complete or final fragment)
                        2 => {
                            let mut full = std::mem::take(&mut this.fragments);
                            full.extend_from_slice(data);
                            let text = String::from_utf8_lossy(&full).into_owned();
                            return Poll::Ready(Ok(WebSocketMessage::Text(text)));
                        }
                        // Close
                        4 => {
                            return Poll::Ready(Ok(WebSocketMessage::Close));
                        }
                        _ => {
                            // Unknown buffer type â€” treat as binary.
                            let mut full = std::mem::take(&mut this.fragments);
                            full.extend_from_slice(data);
                            return Poll::Ready(Ok(WebSocketMessage::Binary(full)));
                        }
                    }
                }
                Ok(WsRecvEvent::CloseComplete) => {
                    return Poll::Ready(Ok(WebSocketMessage::Close));
                }
                Ok(WsRecvEvent::Error(code)) => {
                    return Poll::Ready(Err(Error::from(WIN32_ERROR(code))));
                }
                Err(crossfire::TryRecvError::Empty) => return Poll::Pending,
                Err(crossfire::TryRecvError::Disconnected) => {
                    return Poll::Ready(Err(Error::empty()));
                }
            }
        }
    }
}

/// Kick off a single `WinHttpWebSocketReceive` call.
fn initiate_receive(handle: &WinHttpHandle, buffer: &mut [u8]) -> Result<()> {
    let mut bytes_read = 0u32;
    let mut buffer_type = WINHTTP_WEB_SOCKET_BUFFER_TYPE::default();

    let status = unsafe {
        WinHttpWebSocketReceive(
            handle.as_raw(),
            buffer.as_mut_ptr() as *mut _,
            buffer.len() as u32,
            &mut bytes_read,
            &mut buffer_type,
        )
    };

    if status != 0 && status != ERROR_IO_PENDING_VALUE {
        return Err(Error::from_thread());
    }
    Ok(())
}

// WsCloseFuture

/// Future returned by [`AsyncWebSocket::close`].
pub struct WsCloseFuture<'ws> {
    ws: &'ws AsyncWebSocket,
    status: u16,
    reason: Vec<u8>,
    initiated: bool,
}

impl Future for WsCloseFuture<'_> {
    type Output = Result<()>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;
        this.ws.context.set_recv_waker(cx.waker());

        if !this.initiated {
            this.initiated = true;
            let reason_ptr = if this.reason.is_empty() {
                None
            } else {
                Some(this.reason.as_ptr() as *const c_void)
            };
            let status = unsafe {
                WinHttpWebSocketClose(
                    this.ws.handle.as_raw(),
                    this.status,
                    reason_ptr,
                    this.reason.len() as u32,
                )
            };
            if status == 0 {
                return Poll::Ready(Ok(()));
            }
            if status != ERROR_IO_PENDING_VALUE {
                return Poll::Ready(Err(Error::from_thread()));
            }
        }

        loop {
            match this.ws.recv_receiver.try_recv() {
                Ok(WsRecvEvent::CloseComplete) => return Poll::Ready(Ok(())),
                Ok(WsRecvEvent::Error(code)) => {
                    return Poll::Ready(Err(Error::from(WIN32_ERROR(code))));
                }
                Ok(_) => continue,
                Err(crossfire::TryRecvError::Empty) => return Poll::Pending,
                Err(crossfire::TryRecvError::Disconnected) => {
                    return Poll::Ready(Err(Error::empty()));
                }
            }
        }
    }
}

// WebSocketStream â€” futures_core::Stream adapter

/// A [`futures_core::Stream`] of [`WebSocketMessage`]s.
///
/// Created by [`AsyncWebSocket::into_stream`]. Yields `Some(Ok(msg))` for
/// each received message and `None` when the connection is closed.
pub struct WebSocketStream {
    ws: AsyncWebSocket,
    buffer: Vec<u8>,
    fragments: Vec<u8>,
    is_text: Option<bool>,
    initiated: bool,
    closed: bool,
}

impl futures_core::Stream for WebSocketStream {
    type Item = Result<WebSocketMessage>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = &mut *self;

        if this.closed {
            return Poll::Ready(None);
        }

        this.ws.context.set_recv_waker(cx.waker());

        if !this.initiated {
            this.initiated = true;
            if let Err(e) = initiate_receive(&this.ws.handle, &mut this.buffer) {
                this.closed = true;
                return Poll::Ready(Some(Err(e)));
            }
        }

        loop {
            match this.ws.recv_receiver.try_recv() {
                Ok(WsRecvEvent::ReadComplete {
                    bytes_read,
                    buffer_type,
                }) => {
                    let data = &this.buffer[..bytes_read as usize];
                    match buffer_type {
                        // BinaryFragment
                        1 => {
                            if this.is_text.is_none() {
                                this.is_text = Some(false);
                            }
                            this.fragments.extend_from_slice(data);
                            if let Err(e) = initiate_receive(&this.ws.handle, &mut this.buffer) {
                                this.closed = true;
                                return Poll::Ready(Some(Err(e)));
                            }
                            this.ws.context.set_recv_waker(cx.waker());
                            continue;
                        }
                        // Utf8Fragment
                        3 => {
                            if this.is_text.is_none() {
                                this.is_text = Some(true);
                            }
                            this.fragments.extend_from_slice(data);
                            if let Err(e) = initiate_receive(&this.ws.handle, &mut this.buffer) {
                                this.closed = true;
                                return Poll::Ready(Some(Err(e)));
                            }
                            this.ws.context.set_recv_waker(cx.waker());
                            continue;
                        }
                        // BinaryMessage (complete or final fragment)
                        0 => {
                            let mut full = std::mem::take(&mut this.fragments);
                            full.extend_from_slice(data);
                            this.is_text = None;
                            // Initiate next receive for the stream.
                            this.initiated = false;
                            return Poll::Ready(Some(Ok(WebSocketMessage::Binary(full))));
                        }
                        // Utf8Message (complete or final fragment)
                        2 => {
                            let mut full = std::mem::take(&mut this.fragments);
                            full.extend_from_slice(data);
                            let text = String::from_utf8_lossy(&full).into_owned();
                            this.is_text = None;
                            this.initiated = false;
                            return Poll::Ready(Some(Ok(WebSocketMessage::Text(text))));
                        }
                        // Close
                        4 => {
                            this.closed = true;
                            return Poll::Ready(None);
                        }
                        _ => {
                            let mut full = std::mem::take(&mut this.fragments);
                            full.extend_from_slice(data);
                            this.is_text = None;
                            this.initiated = false;
                            return Poll::Ready(Some(Ok(WebSocketMessage::Binary(full))));
                        }
                    }
                }
                Ok(WsRecvEvent::CloseComplete) => {
                    this.closed = true;
                    return Poll::Ready(None);
                }
                Ok(WsRecvEvent::Error(code)) => {
                    this.closed = true;
                    return Poll::Ready(Some(Err(Error::from(WIN32_ERROR(code)))));
                }
                Err(crossfire::TryRecvError::Empty) => return Poll::Pending,
                Err(crossfire::TryRecvError::Disconnected) => {
                    this.closed = true;
                    return Poll::Ready(None);
                }
            }
        }
    }
}

// Unit tests

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn websocket_message_text_equality() {
        let msg = WebSocketMessage::Text("hello".to_string());
        assert_eq!(msg, WebSocketMessage::Text("hello".to_string()));
        assert_ne!(msg, WebSocketMessage::Text("world".to_string()));
    }

    #[test]
    fn websocket_message_binary_equality() {
        let msg = WebSocketMessage::Binary(vec![1, 2, 3]);
        assert_eq!(msg, WebSocketMessage::Binary(vec![1, 2, 3]));
        assert_ne!(msg, WebSocketMessage::Binary(vec![4, 5, 6]));
    }

    #[test]
    fn websocket_message_close() {
        let msg = WebSocketMessage::Close;
        assert_eq!(msg, WebSocketMessage::Close);
        assert_ne!(msg, WebSocketMessage::Text(String::new()));
    }

    #[test]
    fn websocket_message_debug_format() {
        let text = WebSocketMessage::Text("hi".to_string());
        let debug = format!("{text:?}");
        assert!(debug.contains("Text"));
        assert!(debug.contains("hi"));

        let binary = WebSocketMessage::Binary(vec![0xDE, 0xAD]);
        let debug = format!("{binary:?}");
        assert!(debug.contains("Binary"));

        let close = WebSocketMessage::Close;
        let debug = format!("{close:?}");
        assert!(debug.contains("Close"));
    }

    #[test]
    fn websocket_message_clone() {
        let original = WebSocketMessage::Text("test".to_string());
        let cloned = original.clone();
        assert_eq!(original, cloned);

        let original = WebSocketMessage::Binary(vec![1, 2, 3]);
        let cloned = original.clone();
        assert_eq!(original, cloned);
    }

    #[test]
    fn websocket_message_variants_are_distinct() {
        let text = WebSocketMessage::Text(String::new());
        let binary = WebSocketMessage::Binary(Vec::new());
        let close = WebSocketMessage::Close;

        assert_ne!(text, binary);
        assert_ne!(text, close);
        assert_ne!(binary, close);
    }
}
