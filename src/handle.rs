//! Core RAII wrapper for HINTERNET handles
//!
//! This module provides the low-level handle wrapper that ensures
//! WinHTTP handles are properly closed when dropped.

use std::ptr::NonNull;
use windows::Win32::Networking::WinHttp::WinHttpCloseHandle;

/// Core RAII wrapper for HINTERNET handles
///
/// This type wraps a raw `*mut c_void` handle and ensures it's closed
/// via `WinHttpCloseHandle` when dropped. Uses `NonNull` for null-safety.
///
/// This type is private to the crate - public API uses typed wrappers
/// (Session, Connection, Request, WebSocket).
pub(crate) struct WinHttpHandle(NonNull<std::ffi::c_void>);

impl WinHttpHandle {
    /// Create from raw handle, checking for null
    ///
    /// Returns `None` if the handle is null, indicating an error.
    ///
    /// # Safety
    ///
    /// The caller must ensure the handle is valid and was returned
    /// by a WinHTTP function.
    pub(crate) unsafe fn from_raw(raw: *mut std::ffi::c_void) -> Option<Self> {
        NonNull::new(raw).map(Self)
    }

    /// Get raw pointer for passing to WinHTTP functions
    pub(crate) fn as_raw(&self) -> *mut std::ffi::c_void {
        self.0.as_ptr()
    }
}

impl Drop for WinHttpHandle {
    fn drop(&mut self) {
        unsafe {
            // Ignore errors in Drop - cleanup must not panic
            // Per Microsoft docs, WinHttpCloseHandle returns BOOL
            let _ = WinHttpCloseHandle(self.as_raw());
        }
    }
}

// WinHTTP handles are thread-safe per Microsoft documentation
// https://learn.microsoft.com/en-us/windows/win32/winhttp/winhttp-versions
unsafe impl Send for WinHttpHandle {}
unsafe impl Sync for WinHttpHandle {}
