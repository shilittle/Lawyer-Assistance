#![allow(unsafe_code)]

use std::{
    ops::{Deref, DerefMut},
    sync::atomic::{compiler_fence, Ordering},
};

/// Owns partially decrypted bytes and scrubs them on every early-return path.
pub(super) struct ZeroizingAccumulator(Vec<u8>);

impl ZeroizingAccumulator {
    pub(super) fn with_capacity(capacity: usize) -> Self {
        Self(Vec::with_capacity(capacity))
    }

    pub(super) fn extend_from_slice(&mut self, bytes: &[u8]) {
        self.0.extend_from_slice(bytes);
    }

    pub(super) fn into_inner(mut self) -> Vec<u8> {
        std::mem::take(&mut self.0)
    }
}

impl Deref for ZeroizingAccumulator {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for ZeroizingAccumulator {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Drop for ZeroizingAccumulator {
    fn drop(&mut self) {
        for byte in &mut self.0 {
            unsafe { std::ptr::write_volatile(byte, 0) };
        }
        compiler_fence(Ordering::SeqCst);
    }
}
