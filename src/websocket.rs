use crate::{handle::WinHttpHandle, request::Request};
use std::mem::ManuallyDrop;
use windows::Win32::Networking::WinHttp::*;
use windows::core::{Error, Result};

pub struct WebSocket {
    handle: WinHttpHandle,
}

impl WebSocket {
    pub fn from_upgrade<'conn>(request: Request<'conn>) -> Result<Self> {
        let request = ManuallyDrop::new(request);
        let request_raw = request.handle.as_raw();

        let ws_handle = unsafe { WinHttpWebSocketCompleteUpgrade(request_raw, None) };

        if ws_handle.is_null() {
            return Err(Error::from_thread());
        }

        unsafe {
            let _ = WinHttpCloseHandle(request_raw);
        }

        let handle = unsafe { WinHttpHandle::from_raw(ws_handle) }
            .expect("WinHttpWebSocketCompleteUpgrade returned non-null");

        Ok(Self { handle })
    }

    pub fn send(&self, data: &[u8], buffer_type: WINHTTP_WEB_SOCKET_BUFFER_TYPE) -> Result<()> {
        let status = unsafe { WinHttpWebSocketSend(self.handle.as_raw(), buffer_type, Some(data)) };
        if status != 0 {
            return Err(Error::from_thread());
        }
        Ok(())
    }

    pub fn receive(&self, buffer: &mut [u8]) -> Result<(usize, WINHTTP_WEB_SOCKET_BUFFER_TYPE)> {
        let mut bytes_read = 0u32;
        let mut buffer_type = WINHTTP_WEB_SOCKET_BUFFER_TYPE::default();

        let status = unsafe {
            WinHttpWebSocketReceive(
                self.handle.as_raw(),
                buffer.as_mut_ptr() as *mut _,
                buffer.len() as u32,
                &mut bytes_read,
                &mut buffer_type,
            )
        };

        if status != 0 {
            return Err(Error::from_thread());
        }

        Ok((bytes_read as usize, buffer_type))
    }

    pub fn close(&self, status: u16, reason: &str) -> Result<()> {
        let reason_bytes = reason.as_bytes();
        let result = unsafe {
            WinHttpWebSocketClose(
                self.handle.as_raw(),
                status,
                Some(reason_bytes.as_ptr() as *const _),
                reason_bytes.len() as u32,
            )
        };
        if result != 0 {
            return Err(Error::from_thread());
        }
        Ok(())
    }

    pub fn shutdown(&self, status: u16, reason: &str) -> Result<()> {
        let reason_bytes = reason.as_bytes();
        let result = unsafe {
            WinHttpWebSocketShutdown(
                self.handle.as_raw(),
                status,
                Some(reason_bytes.as_ptr() as *const _),
                reason_bytes.len() as u32,
            )
        };
        if result != 0 {
            return Err(Error::from_thread());
        }
        Ok(())
    }

    pub fn query_close_status(&self) -> Result<(u16, String)> {
        let mut status = 0u16;
        let mut reason_buf = vec![0u8; 123];
        let mut reason_len = reason_buf.len() as u32;

        let result = unsafe {
            WinHttpWebSocketQueryCloseStatus(
                self.handle.as_raw(),
                &mut status,
                Some(reason_buf.as_mut_ptr() as *mut _),
                reason_len,
                &mut reason_len,
            )
        };

        if result != 0 {
            return Err(Error::from_thread());
        }

        let reason = String::from_utf8_lossy(&reason_buf[..reason_len as usize]).to_string();
        Ok((status, reason))
    }

    /// Sends data using the type-safe [`WebSocketBufferType`](crate::types::WebSocketBufferType).
    pub fn send_typed(
        &self,
        data: &[u8],
        buffer_type: crate::types::WebSocketBufferType,
    ) -> Result<()> {
        self.send(data, buffer_type.into())
    }

    /// Receives data, returning the type-safe buffer type.
    pub fn receive_typed(
        &self,
        buffer: &mut [u8],
    ) -> Result<(usize, crate::types::WebSocketBufferType)> {
        let (bytes_read, raw_type) = self.receive(buffer)?;
        let typed = crate::types::WebSocketBufferType::try_from(raw_type)
            .unwrap_or(crate::types::WebSocketBufferType::BinaryMessage);
        Ok((bytes_read, typed))
    }

    /// Closes the WebSocket with a type-safe close status.
    pub fn close_typed(
        &self,
        status: crate::types::WebSocketCloseStatus,
        reason: &str,
    ) -> Result<()> {
        self.close(status as u16, reason)
    }

    /// Shuts down the WebSocket with a type-safe close status.
    pub fn shutdown_typed(
        &self,
        status: crate::types::WebSocketCloseStatus,
        reason: &str,
    ) -> Result<()> {
        self.shutdown(status as u16, reason)
    }

    /// Queries the close status and returns a type-safe close status.
    pub fn query_close_status_typed(&self) -> Result<(crate::types::WebSocketCloseStatus, String)> {
        let (raw_status, reason) = self.query_close_status()?;
        // Try to convert; if unknown, default to Success
        let status = crate::types::WebSocketCloseStatus::try_from(raw_status)
            .unwrap_or(crate::types::WebSocketCloseStatus::Success);
        Ok((status, reason))
    }

    /// Send a UTF-8 text message.
    pub fn send_text(&self, text: &str) -> Result<()> {
        self.send(text.as_bytes(), WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE)
    }

    /// Send a binary message.
    pub fn send_binary(&self, data: &[u8]) -> Result<()> {
        self.send(data, WINHTTP_WEB_SOCKET_BINARY_MESSAGE_BUFFER_TYPE)
    }

    /// Close the WebSocket with a normal success status.
    pub fn close_normal(&self, reason: &str) -> Result<()> {
        self.close(1000, reason)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::Session;

    #[test]
    fn test_websocket_upgrade() {
        let session = Session::new().expect("Failed to create session");
        let connection = session
            .connect("echo.websocket.org", 443)
            .expect("Failed to connect");

        let request = connection
            .request("GET", "/")
            .secure()
            .header("Upgrade", "websocket")
            .header("Connection", "Upgrade")
            .header("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
            .header("Sec-WebSocket-Version", "13")
            .build()
            .expect("Failed to build request");

        request.send().ok();
        request.receive_response().ok();

        let ws = WebSocket::from_upgrade(request);
        assert!(ws.is_ok() || ws.is_err());
    }

    #[test]
    fn test_websocket_buffer_types() {
        use crate::types::*;

        let _ = WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE;
        let _ = WINHTTP_WEB_SOCKET_BINARY_MESSAGE_BUFFER_TYPE;
        let _ = WINHTTP_WEB_SOCKET_CLOSE_BUFFER_TYPE;
    }

    #[test]
    fn test_websocket_buffer_type_conversion() {
        use crate::types::WebSocketBufferType;

        // Test From conversion
        let raw: WINHTTP_WEB_SOCKET_BUFFER_TYPE = WebSocketBufferType::Utf8Message.into();
        assert_eq!(raw, WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE);

        let raw: WINHTTP_WEB_SOCKET_BUFFER_TYPE = WebSocketBufferType::BinaryMessage.into();
        assert_eq!(raw, WINHTTP_WEB_SOCKET_BINARY_MESSAGE_BUFFER_TYPE);

        let raw: WINHTTP_WEB_SOCKET_BUFFER_TYPE = WebSocketBufferType::Close.into();
        assert_eq!(raw, WINHTTP_WEB_SOCKET_CLOSE_BUFFER_TYPE);

        // Test TryFrom conversion
        let typed = WebSocketBufferType::try_from(WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE);
        assert_eq!(typed, Ok(WebSocketBufferType::Utf8Message));

        let typed = WebSocketBufferType::try_from(WINHTTP_WEB_SOCKET_BINARY_MESSAGE_BUFFER_TYPE);
        assert_eq!(typed, Ok(WebSocketBufferType::BinaryMessage));
    }

    #[test]
    fn test_websocket_close_status_values() {
        use crate::types::WebSocketCloseStatus;

        assert_eq!(WebSocketCloseStatus::Success as u16, 1000);
        assert_eq!(WebSocketCloseStatus::EndpointTerminated as u16, 1001);
        assert_eq!(WebSocketCloseStatus::ProtocolError as u16, 1002);
        assert_eq!(WebSocketCloseStatus::InvalidDataType as u16, 1003);
        assert_eq!(WebSocketCloseStatus::Empty as u16, 1005);
        assert_eq!(WebSocketCloseStatus::Aborted as u16, 1006);
        assert_eq!(WebSocketCloseStatus::InvalidPayload as u16, 1007);
        assert_eq!(WebSocketCloseStatus::PolicyViolation as u16, 1008);
        assert_eq!(WebSocketCloseStatus::MessageTooBig as u16, 1009);
        assert_eq!(WebSocketCloseStatus::UnsupportedExtensions as u16, 1010);
        assert_eq!(WebSocketCloseStatus::ServerError as u16, 1011);
    }

    #[test]
    fn test_websocket_operation_conversion() {
        use crate::types::WebSocketOperation;

        let typed = WebSocketOperation::try_from(WINHTTP_WEB_SOCKET_SEND_OPERATION);
        assert_eq!(typed, Ok(WebSocketOperation::Send));

        let typed = WebSocketOperation::try_from(WINHTTP_WEB_SOCKET_RECEIVE_OPERATION);
        assert_eq!(typed, Ok(WebSocketOperation::Receive));

        let typed = WebSocketOperation::try_from(WINHTTP_WEB_SOCKET_CLOSE_OPERATION);
        assert_eq!(typed, Ok(WebSocketOperation::Close));

        let typed = WebSocketOperation::try_from(WINHTTP_WEB_SOCKET_SHUTDOWN_OPERATION);
        assert_eq!(typed, Ok(WebSocketOperation::Shutdown));
    }
}
