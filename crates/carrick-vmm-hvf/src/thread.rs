//! Thread + futex coordination — re-exported from `carrick-thread`.
//!
//! All platform-agnostic types (`ThreadId`, `ThreadRegistry`, `FutexTable`,
//! `FutexWait`, `FutexWaitOutcome`, and the container-keyed runtime endpoint
//! registry live in `carrick-thread` so
//! the Linux/KVM backend can use them without depending on this crate.
//!
//! The Darwin-specific `(tid, state_char)` projection that `/proc` renders is
//! NOT here: it calls `host_proc::thread_run_state_char` (a Mach `thread_info`
//! syscall) and is consumed only by the kernel's `/proc` renderer, so it lives
//! in `carrick_kernel::container_thread_states` over the same carrick-thread
//! port registry. A copy here would put a second implementation on the macOS
//! lane and a carrick-vmm-* crate in the kernel's closure.
pub use carrick_thread::thread::*;
