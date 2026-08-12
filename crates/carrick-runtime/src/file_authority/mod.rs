//! One per-run mutable file authority.
//!
//! This module is developed only on the atomic cutover branch. Production
//! wiring must not merge until `ThreadResources.files`, every description
//! guard, the host-fork rejection, and process-local writable VFS state are
//! replaced in the same merge.

mod backing;
mod core;
mod ipc;
mod protocol;
mod transport;
mod types;

pub(crate) use core::FileAuthorityCore;
pub(crate) use ipc::IpcFileAuthority;
pub(crate) use transport::{DirectFileAuthority, FileAuthorityTransport};
pub(crate) use types::*;

#[cfg(test)]
mod tests;
