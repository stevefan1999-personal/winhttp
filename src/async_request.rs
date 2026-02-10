use crate::request::Request;
use crossfire::mpsc;
use parking_lot::Mutex;
use std::ffi::c_void;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};
use windows::Win32::Foundation::WIN32_ERROR;
use windows::Win32::Networking::WinHttp::*;
use windows::core::{Error, Result};

/// Type aliases to hide crossfire's Flavor generics from the rest of the crate.
type EventSender = crossfire::MTx<mpsc::List<CallbackEvent>>;
type EventReceiver = crossfire::Rx<mpsc::List<CallbackEvent>>;

#[derive(Debug)]
pub enum CallbackEvent {
    SendRequestComplete,
    HeadersAvailable,
    DataAvailable(u32),
    ReadComplete(usize),
    WriteComplete(usize),
    RequestError(u32),
}

/// Shared context between the async future and the WinHTTP callback.
///
/// The `Waker` is protected by a [`parking_lot::Mutex`] to eliminate the
/// data race between the WinHTTP thread-pool callback (which calls `wake()`)
/// and the executor thread (which sets the waker in `poll()`).
struct AsyncContext {
    waker: Mutex<Option<Waker>>,
    sender: EventSender,
}

impl AsyncContext {
    fn new(sender: EventSender) -> Pin<Arc<Self>> {
        Arc::pin(Self {
            waker: Mutex::new(None),
            sender,
        })
    }

    fn wake(&self) {
        if let Some(waker) = self.waker.lock().take() {
            waker.wake();
        }
    }

    fn set_waker(&self, waker: &Waker) {
        let mut guard = self.waker.lock();
        match guard.as_ref() {
            Some(existing) if existing.will_wake(waker) => {}
            _ => *guard = Some(waker.clone()),
        }
    }

    fn send_event(&self, event: CallbackEvent) {
        let _ = self.sender.send(event);
    }
}

/// # Safety
///
/// This function is called by WinHTTP on its own thread pool. The `context`
/// parameter is a raw pointer to a pinned `AsyncContext` whose lifetime is
/// guaranteed by the owning `AsyncRequest`/`AsyncResponse`.
pub unsafe extern "system" fn async_status_callback(
    _hinternet: *mut c_void,
    context: usize,
    status: u32,
    status_info: *mut c_void,
    status_info_length: u32,
) {
    let Some(ctx) = (unsafe { (context as *const AsyncContext).as_ref() }) else {
        return;
    };

    let event = match status {
        WINHTTP_CALLBACK_STATUS_SENDREQUEST_COMPLETE => Some(CallbackEvent::SendRequestComplete),
        WINHTTP_CALLBACK_STATUS_HEADERS_AVAILABLE => Some(CallbackEvent::HeadersAvailable),
        WINHTTP_CALLBACK_STATUS_DATA_AVAILABLE => {
            if !status_info.is_null() {
                let bytes = unsafe { *(status_info as *const u32) };
                Some(CallbackEvent::DataAvailable(bytes))
            } else {
                None
            }
        }
        WINHTTP_CALLBACK_STATUS_READ_COMPLETE => {
            Some(CallbackEvent::ReadComplete(status_info_length as usize))
        }
        WINHTTP_CALLBACK_STATUS_WRITE_COMPLETE => {
            Some(CallbackEvent::WriteComplete(status_info_length as usize))
        }
        WINHTTP_CALLBACK_STATUS_REQUEST_ERROR => {
            if !status_info.is_null() {
                let result = unsafe { &*(status_info as *const WINHTTP_ASYNC_RESULT) };
                Some(CallbackEvent::RequestError(result.dwError))
            } else {
                None
            }
        }
        _ => None,
    };

    if let Some(event) = event {
        ctx.send_event(event);
        ctx.wake();
    }
}

pub struct AsyncRequest<'conn> {
    request: Request<'conn>,
    context: Pin<Arc<AsyncContext>>,
    receiver: EventReceiver,
}

impl<'conn> AsyncRequest<'conn> {
    pub fn from_request(request: Request<'conn>) -> Result<Self> {
        let (sender, receiver) = mpsc::unbounded_blocking();
        let context = AsyncContext::new(sender);

        unsafe {
            WinHttpSetStatusCallback(
                request.handle.as_raw(),
                Some(async_status_callback),
                WINHTTP_CALLBACK_FLAG_ALL_NOTIFICATIONS,
                0,
            )
        };

        // Set the context value on the handle so the callback receives a
        // pointer to our `AsyncContext`. Without this, `dwContext` in the
        // callback is 0 and all events are silently dropped.
        let ctx_ptr: usize = &*context as *const AsyncContext as usize;
        request.set_option(WINHTTP_OPTION_CONTEXT_VALUE, &ctx_ptr.to_ne_bytes())?;

        Ok(Self {
            request,
            context,
            receiver,
        })
    }

    /// Initiate the HTTP send and return a future that resolves to
    /// [`AsyncResponse`] once headers are available.
    ///
    /// This future is **runtime-agnostic** — it works with any executor
    /// (tokio, smol, async-std, pollster, `futures::executor`, etc.).
    pub fn send(self) -> SendFuture<'conn> {
        SendFuture {
            inner: Some(self),
            initiated: false,
            body: None,
        }
    }

    /// Initiate the HTTP send with a body payload and return a future that
    /// resolves to [`AsyncResponse`] once headers are available.
    ///
    /// This future is **runtime-agnostic**.
    pub fn send_with_body(self, body: Vec<u8>) -> SendFuture<'conn> {
        SendFuture {
            inner: Some(self),
            initiated: false,
            body: Some(body),
        }
    }
}

pub struct SendFuture<'conn> {
    inner: Option<AsyncRequest<'conn>>,
    initiated: bool,
    body: Option<Vec<u8>>,
}

impl<'conn> Future for SendFuture<'conn> {
    type Output = Result<AsyncResponse<'conn>>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;
        let request = this.inner.as_mut().unwrap();

        // Register the waker so the callback can wake us.
        request.context.set_waker(cx.waker());

        if !this.initiated {
            this.initiated = true;
            // SAFETY: Keep the body alive in `this.body` — WinHTTP reads
            // from the buffer asynchronously until SEND_REQUEST_COMPLETE.
            // Using `.take()` here would drop the buffer before WinHTTP
            // is done with it.
            let result = if let Some(body) = this.body.as_ref() {
                request.request.send_with_body(body)
            } else {
                request.request.send()
            };
            if let Err(e) = result {
                return Poll::Ready(Err(e));
            }
        }

        // Drain events from the channel.
        loop {
            match request.receiver.try_recv() {
                Ok(CallbackEvent::SendRequestComplete) => {
                    // Send completed — now ask WinHTTP for the response headers.
                    if let Err(e) = request.request.receive_response() {
                        return Poll::Ready(Err(e));
                    }
                    // Re-register waker and wait for HEADERS_AVAILABLE.
                    request.context.set_waker(cx.waker());
                }
                Ok(CallbackEvent::HeadersAvailable) => {
                    let async_request = this.inner.take().unwrap();
                    return Poll::Ready(Ok(AsyncResponse {
                        request: async_request.request,
                        context: async_request.context,
                        receiver: async_request.receiver,
                    }));
                }
                Ok(CallbackEvent::RequestError(code)) => {
                    return Poll::Ready(Err(Error::from(WIN32_ERROR(code))));
                }
                Ok(_) => {
                    // Unexpected event during send phase — skip and keep draining.
                    continue;
                }
                Err(crossfire::TryRecvError::Empty) => {
                    return Poll::Pending;
                }
                Err(crossfire::TryRecvError::Disconnected) => {
                    return Poll::Ready(Err(Error::empty()));
                }
            }
        }
    }
}

pub struct AsyncResponse<'conn> {
    request: Request<'conn>,
    context: Pin<Arc<AsyncContext>>,
    receiver: EventReceiver,
}

impl<'conn> AsyncResponse<'conn> {
    /// Read the entire response body asynchronously.
    ///
    /// Returns a future that collects all bytes. Runtime-agnostic.
    pub fn read_all(self) -> ReadAllFuture<'conn> {
        ReadAllFuture {
            response: Some(self),
            body: Vec::new(),
            buffer: vec![0u8; 8192],
            state: ReadState::QueryAvailable,
        }
    }

    /// Access the underlying request handle to query headers, status codes, etc.
    pub fn request(&self) -> &Request<'conn> {
        &self.request
    }

    /// Returns the HTTP status code (e.g. 200, 404, 500).
    ///
    /// Convenience wrapper around `self.request().status_code()`.
    pub fn status_code(&self) -> Result<u16> {
        self.request.status_code()
    }

    /// Returns the HTTP status text (e.g. "OK", "Not Found").
    pub fn status_text(&self) -> Result<String> {
        self.request.status_text()
    }

    /// Returns the Content-Type header value.
    pub fn content_type(&self) -> Result<String> {
        self.request.content_type()
    }

    /// Returns the Content-Length as a number, or `None` if not present.
    pub fn content_length(&self) -> Result<Option<u64>> {
        self.request.content_length()
    }

    /// Returns all response headers as a single CRLF-delimited string.
    pub fn raw_headers(&self) -> Result<String> {
        self.request.raw_headers()
    }

    /// Queries a specific header by info level and optional name.
    pub fn query_headers(&self, info_level: u32, name: Option<&str>) -> Result<String> {
        self.request.query_headers(info_level, name)
    }

    /// Queries which HTTP protocol version was actually used.
    pub fn http_protocol_used(&self) -> Result<u32> {
        self.request.http_protocol_used()
    }

    /// Queries SSL/TLS certificate information (HTTPS only).
    pub fn certificate_info(&self) -> Result<Option<crate::CertificateInfo>> {
        self.request.certificate_info()
    }

    /// Queries TCP connection information (local/remote IP and port).
    pub fn connection_info(&self) -> Result<Option<crate::ConnectionInfo>> {
        self.request.connection_info()
    }

    /// Consume the response and return the underlying [`Request`] handle.
    ///
    /// This is used by the async WebSocket upgrade path to extract the
    /// request handle needed for [`WinHttpWebSocketCompleteUpgrade`].
    #[cfg(feature = "websocket")]
    pub(crate) fn into_request(self) -> Request<'conn> {
        self.request
    }
}

enum ReadState {
    QueryAvailable,
    WaitingData,
    Reading,
}

pub struct ReadAllFuture<'conn> {
    response: Option<AsyncResponse<'conn>>,
    body: Vec<u8>,
    buffer: Vec<u8>,
    state: ReadState,
}

impl<'conn> Future for ReadAllFuture<'conn> {
    type Output = Result<Vec<u8>>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;
        let response = this.response.as_mut().unwrap();
        response.context.set_waker(cx.waker());

        loop {
            match this.state {
                ReadState::QueryAvailable => {
                    // Ask WinHTTP how many bytes are available.
                    // In async mode this returns immediately; the actual
                    // answer arrives via DATA_AVAILABLE callback.
                    match response.request.query_data_available() {
                        Ok(_) => {
                            this.state = ReadState::WaitingData;
                        }
                        Err(e) => return Poll::Ready(Err(e)),
                    }
                }
                ReadState::WaitingData => match response.receiver.try_recv() {
                    Ok(CallbackEvent::DataAvailable(0)) => {
                        let body = std::mem::take(&mut this.body);
                        return Poll::Ready(Ok(body));
                    }
                    Ok(CallbackEvent::DataAvailable(bytes)) => {
                        let read_len = (bytes as usize).min(this.buffer.len());
                        match response.request.read_data(&mut this.buffer[..read_len]) {
                            Ok(_) => {
                                this.state = ReadState::Reading;
                            }
                            Err(e) => return Poll::Ready(Err(e)),
                        }
                    }
                    Ok(CallbackEvent::RequestError(code)) => {
                        return Poll::Ready(Err(Error::from(WIN32_ERROR(code))));
                    }
                    Ok(_) => continue,
                    Err(crossfire::TryRecvError::Empty) => {
                        return Poll::Pending;
                    }
                    Err(crossfire::TryRecvError::Disconnected) => {
                        return Poll::Ready(Err(Error::empty()));
                    }
                },
                ReadState::Reading => match response.receiver.try_recv() {
                    Ok(CallbackEvent::ReadComplete(0)) => {
                        let body = std::mem::take(&mut this.body);
                        return Poll::Ready(Ok(body));
                    }
                    Ok(CallbackEvent::ReadComplete(bytes_read)) => {
                        this.body.extend_from_slice(&this.buffer[..bytes_read]);
                        this.state = ReadState::QueryAvailable;
                    }
                    Ok(CallbackEvent::RequestError(code)) => {
                        return Poll::Ready(Err(Error::from(WIN32_ERROR(code))));
                    }
                    Ok(_) => continue,
                    Err(crossfire::TryRecvError::Empty) => {
                        return Poll::Pending;
                    }
                    Err(crossfire::TryRecvError::Disconnected) => {
                        return Poll::Ready(Err(Error::empty()));
                    }
                },
            }
        }
    }
}

/// A future that writes data to an async request in chunks.
///
/// Created by [`AsyncRequest::write_stream`]. Each chunk is written via
/// `WinHttpWriteData` and the future waits for the `WRITE_COMPLETE` callback
/// before writing the next chunk.
///
/// This is useful for uploading large payloads without buffering the entire
/// body in memory.
pub struct WriteFuture<'conn> {
    request: Option<AsyncRequest<'conn>>,
    data: Vec<u8>,
    offset: usize,
    chunk_size: usize,
    initiated: bool,
    waiting_write: bool,
}

impl<'conn> AsyncRequest<'conn> {
    /// Send the request with headers indicating a known `total_len`, then
    /// asynchronously stream `data` in chunks of `chunk_size`.
    ///
    /// Returns a future that resolves to an [`AsyncResponse`] once the full
    /// body has been written and the response headers are available.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn demo(req: winhttp::AsyncRequest<'_>) -> windows::core::Result<()> {
    /// let body = vec![0u8; 1_000_000]; // 1 MB payload
    /// let response = req.write_stream(body, 65536).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn write_stream(self, data: Vec<u8>, chunk_size: usize) -> WriteFuture<'conn> {
        WriteFuture {
            request: Some(self),
            data,
            offset: 0,
            chunk_size: chunk_size.max(1),
            initiated: false,
            waiting_write: false,
        }
    }
}

impl<'conn> Future for WriteFuture<'conn> {
    type Output = Result<AsyncResponse<'conn>>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;
        let request = this.request.as_mut().unwrap();

        request.context.set_waker(cx.waker());

        // Step 1: Initiate the send with Content-Length but no body data.
        if !this.initiated {
            this.initiated = true;
            let total_len = this.data.len() as u32;
            let result = unsafe {
                windows::Win32::Networking::WinHttp::WinHttpSendRequest(
                    request.request.handle.as_raw(),
                    None,
                    None,
                    0,
                    total_len,
                    0,
                )
            };
            if let Err(e) = result {
                return Poll::Ready(Err(e));
            }
        }

        // Drain events
        loop {
            match request.receiver.try_recv() {
                Ok(CallbackEvent::SendRequestComplete) => {
                    // Headers sent. Start writing chunks.
                    if this.offset < this.data.len() {
                        let end = (this.offset + this.chunk_size).min(this.data.len());
                        let chunk = &this.data[this.offset..end];
                        match request.request.write_data(chunk) {
                            Ok(_) => {
                                this.waiting_write = true;
                            }
                            Err(e) => return Poll::Ready(Err(e)),
                        }
                    } else {
                        // Empty body — go straight to receiving response.
                        if let Err(e) = request.request.receive_response() {
                            return Poll::Ready(Err(e));
                        }
                    }
                    request.context.set_waker(cx.waker());
                }
                Ok(CallbackEvent::WriteComplete(bytes_written)) => {
                    this.waiting_write = false;
                    this.offset += bytes_written;

                    if this.offset < this.data.len() {
                        // More data to write.
                        let end = (this.offset + this.chunk_size).min(this.data.len());
                        let chunk = &this.data[this.offset..end];
                        match request.request.write_data(chunk) {
                            Ok(_) => {
                                this.waiting_write = true;
                            }
                            Err(e) => return Poll::Ready(Err(e)),
                        }
                    } else {
                        // All data written. Ask for response headers.
                        if let Err(e) = request.request.receive_response() {
                            return Poll::Ready(Err(e));
                        }
                    }
                    request.context.set_waker(cx.waker());
                }
                Ok(CallbackEvent::HeadersAvailable) => {
                    let async_request = this.request.take().unwrap();
                    return Poll::Ready(Ok(AsyncResponse {
                        request: async_request.request,
                        context: async_request.context,
                        receiver: async_request.receiver,
                    }));
                }
                Ok(CallbackEvent::RequestError(code)) => {
                    return Poll::Ready(Err(Error::from(WIN32_ERROR(code))));
                }
                Ok(_) => continue,
                Err(crossfire::TryRecvError::Empty) => {
                    return Poll::Pending;
                }
                Err(crossfire::TryRecvError::Disconnected) => {
                    return Poll::Ready(Err(Error::empty()));
                }
            }
        }
    }
}
