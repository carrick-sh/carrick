//! One per-run mutable file authority.
//!
//! Production owns exactly one helper-backed core for each dispatcher run.
//! During the vertical cutover, the root binding is live before any guest host
//! fork while syscall families continue to use legacy state only until their
//! complete authority slice replaces and deletes that state.

mod backing;
mod core;
mod epoll;
mod ipc;
mod protocol;
mod root;
mod stream;
mod transport;
mod types;

pub(crate) use core::FileAuthorityCore;
pub(crate) use ipc::IpcFileAuthority;
pub(crate) use root::FileAuthorityRun;
#[cfg(test)]
pub(crate) use transport::DirectFileAuthority;
pub(crate) use transport::FileAuthorityTransport;
pub(crate) use types::*;

#[cfg(test)]
mod tests;
