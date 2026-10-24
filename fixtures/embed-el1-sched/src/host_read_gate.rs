//! Test-harness handshake: the guest cannot write the socket until the host
//! observes the reader's production wait registration in the enrolled state.
use std::sync::atomic::AtomicU32;

#[repr(C)]
pub struct HostReadGate {
    pub reader_tid: AtomicU32,
    pub sleep_done: AtomicU32,
    pub enrolled: AtomicU32,
}
