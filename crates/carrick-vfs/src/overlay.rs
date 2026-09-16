//! Back-compat re-export for the historical in-memory writable overlay.
//!
//! The implementation now lives in [`crate::fs_backend`] behind the
//! swappable `FsBackend` trait, but older code paths still refer to
//! `crate::overlay::WritableOverlay`.

pub use crate::fs_backend::{
    MemoryBackend as WritableOverlay, OverlayEntry, layered_directory_entries,
};
