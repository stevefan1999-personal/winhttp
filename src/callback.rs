//! Callback and asynchronous notification functions
//!
//! This module provides safe Rust wrappers for WinHTTP callback and async notification
//! functions, including status callbacks and proxy change notifications.

use crate::request::Request;
use std::ffi::c_void;
use windows::Win32::Networking::WinHttp::*;
use windows::core::{Error, Result};

// Status Callback

impl<'conn> Request<'conn> {
    /// Sets a status callback function for asynchronous operations
    ///
    /// Calls `WinHttpSetStatusCallback` to register a callback function that receives
    /// status information and notifications for asynchronous WinHTTP operations.
    ///
    /// # Arguments
    ///
    /// * `callback` - The callback function pointer to register
    /// * `notification_flags` - Flags specifying which notifications to receive
    ///
    /// # Returns
    ///
    /// The previous callback function pointer, or `WINHTTP_INVALID_STATUS_CALLBACK` if none was set.
    ///
    /// # Safety Notes
    ///
    /// - The callback function pointer must remain valid for the lifetime of the request handle
    /// - The callback must be thread-safe (`Send + Sync`) for multi-threaded use
    /// - Users must ensure the callback does not panic or unwind across FFI boundaries
    /// - The context pointer passed to notifications must outlive the request
    ///
    /// # Example Notification Flags
    ///
    /// - `WINHTTP_CALLBACK_FLAG_ALL_NOTIFICATIONS` - All notifications
    /// - `WINHTTP_CALLBACK_FLAG_SEND_REQUEST` - Send request notifications
    /// - `WINHTTP_CALLBACK_FLAG_READ_COMPLETE` - Read completion notifications
    /// - `WINHTTP_CALLBACK_FLAG_WRITE_COMPLETE` - Write completion notifications
    /// - `WINHTTP_CALLBACK_FLAG_STATUS_*` - Various status notifications
    pub fn set_status_callback(
        &self,
        callback: WINHTTP_STATUS_CALLBACK,
        notification_flags: u32,
    ) -> WINHTTP_STATUS_CALLBACK {
        unsafe {
            WinHttpSetStatusCallback(
                self.handle.as_raw(),
                callback,
                notification_flags,
                0, // dwReserved - must be 0
            )
        }
    }
}

// Proxy Change Notification

/// RAII wrapper for proxy change notification registration
///
/// Automatically unregisters the proxy change notification when dropped.
/// Provides safe management of proxy change callbacks registered via
/// `WinHttpRegisterProxyChangeNotification`.
///
/// # Safety Notes
///
/// - The callback function must remain valid for the lifetime of this struct
/// - The callback must be thread-safe (`Send + Sync`)
/// - The context pointer must outlive this registration
/// - Do not manually call `WinHttpUnregisterProxyChangeNotification` - the Drop impl handles it
pub struct ProxyChangeNotification {
    handle: *mut c_void,
}

impl ProxyChangeNotification {
    /// Registers a callback for proxy change notifications
    ///
    /// Calls `WinHttpRegisterProxyChangeNotification` to register a callback that will
    /// be invoked when proxy settings change on the system.
    ///
    /// # Arguments
    ///
    /// * `flags` - Flags controlling notification behavior (typically 0)
    /// * `callback` - The callback function to invoke on proxy changes
    /// * `context` - User-defined context pointer passed to the callback
    ///
    /// # Returns
    ///
    /// A `ProxyChangeNotification` wrapper that automatically unregisters on drop.
    ///
    /// # Errors
    ///
    /// Returns an error if registration fails.
    ///
    /// # Safety Notes
    ///
    /// - The callback must be a valid function pointer that remains valid until unregistration
    /// - The callback must be thread-safe and not panic
    /// - The context pointer must remain valid until the notification is unregistered (dropped)
    /// - The callback signature is: `fn(context: *const c_void, proxy_info: *const WINHTTP_PROXY_INFO)`
    ///
    /// # Example
    ///
    /// ```no_run
    /// use winhttp::ProxyChangeNotification;
    /// use std::ffi::c_void;
    ///
    /// unsafe extern "system" fn proxy_callback(
    ///     _flags: u64,
    ///     _context: *const c_void,
    /// ) {
    ///     // Handle proxy change notification
    /// }
    ///
    /// // Register callback (automatic cleanup on drop)
    /// // SAFETY: `std::ptr::null()` is a valid context pointer (no dereference expected).
    /// let notification = unsafe {
    ///     ProxyChangeNotification::register(
    ///         0,
    ///         Some(proxy_callback),
    ///         std::ptr::null()
    ///     )?
    /// };
    /// // Callback is active until `notification` is dropped
    /// # Ok::<(), windows::core::Error>(())
    /// ```
    ///
    /// # Safety
    ///
    /// - `context` must remain valid and point to allocated memory for the lifetime
    ///   of the returned `ProxyChangeNotification`, or be null.
    /// - `callback` must be a valid function pointer safe to call from any thread.
    pub unsafe fn register(
        flags: u64,
        callback: WINHTTP_PROXY_CHANGE_CALLBACK,
        context: *const c_void,
    ) -> Result<Self> {
        let mut handle = std::ptr::null_mut();

        let result = unsafe {
            WinHttpRegisterProxyChangeNotification(flags, callback, context, &mut handle)
        };

        if result != 0 {
            return Err(Error::from_thread());
        }

        Ok(Self { handle })
    }
}

impl Drop for ProxyChangeNotification {
    /// Automatically unregisters the proxy change notification
    ///
    /// Calls `WinHttpUnregisterProxyChangeNotification` to clean up the registration.
    /// Any errors during cleanup are silently ignored as per Rust Drop conventions.
    fn drop(&mut self) {
        unsafe {
            // Ignore errors in Drop - cleanup must not panic
            let _ = WinHttpUnregisterProxyChangeNotification(self.handle);
        }
    }
}

// ProxyChangeNotification uses system callbacks which must be thread-safe
unsafe impl Send for ProxyChangeNotification {}
unsafe impl Sync for ProxyChangeNotification {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proxy_change_notification_type_exists() {
        // Just verify the type compiles
        let _marker: Option<ProxyChangeNotification> = None;
    }
}
