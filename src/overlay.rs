// Historical home of the in-memory writable overlay. Kept around as
// a back-compat re-export so older code paths that say
// `crate::overlay::WritableOverlay` keep compiling, but the real
// implementation now lives in [`crate::fs_backend`] behind the
// swappable [`FsBackend`] trait. See `fs_backend.rs` for the trait,
// the in-memory backend (`MemoryBackend`), and the cap-std-backed
// host-fs backend (`HostFsBackend`).

pub use crate::fs_backend::{
    MemoryBackend as WritableOverlay, OverlayEntry, layered_directory_entries,
};
