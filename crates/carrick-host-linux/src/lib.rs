//! carrick-host-linux: the Linux host-OS layer (sibling of carrick-host-bsd).
//!
//! Holds the Linux-specific, VMM-agnostic host glue: the native epoll
//! [`EventMultiplexer`](carrick_hal::event::EventMultiplexer) implementation
//! (`EpollMultiplexer`, the Linux counterpart of carrick-host-bsd's
//! `KqueueMultiplexer`) and the Linux `host_to_linux_errno` identity hook.
//!
//! All code is `cfg(target_os = "linux")`; on any other host this crate is
//! intentionally empty. It depends only on the trait crate `carrick-hal` (no
//! VMM-backend dependency) — the KVM backend (`carrick-vmm-kvm`) and this host
//! layer are integrated by `carrick-runtime` under the `platform-linux` feature.
#![cfg(target_os = "linux")]

pub mod epoll_mux;
pub mod errno;

pub use epoll_mux::EpollMultiplexer;
pub use errno::host_to_linux_errno;
