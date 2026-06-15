//! Thread + futex coordination — re-exported from `carrick-thread`.
//!
//! All platform-agnostic types (`ThreadId`, `ThreadRegistry`, `FutexTable`,
//! `FutexWait`, `FutexWaitOutcome`, `set_current_registry`,
//! `current_thread_name`, `current_thread_ports`) live in `carrick-thread` so
//! the Linux/KVM backend can use them without depending on this crate.
//!
//! The Darwin-specific `thread_states` / `current_thread_states` functions are
//! defined here because they call `host_proc::thread_run_state_char`, which
//! issues a Mach `thread_info` syscall. Those cannot live in carrick-thread
//! (which is hypervisor-agnostic and must not import carrick-host).
pub use carrick_thread::thread::*;

/// Live `(tid, state_char)` for every thread of this process — the data
/// behind `/proc/<pid>/task/` and `/proc/<tid>/stat`. The state char is
/// read from the kernel via `thread_info` on each thread's recorded mach
/// port (`'S'` = WAITING, `'R'` = RUNNING, …); a thread whose port isn't
/// recorded yet reports `'R'`.
pub fn current_thread_states() -> Vec<(ThreadId, char)> {
    let ports = carrick_thread::thread::current_thread_ports();
    ports
        .into_iter()
        .map(|(tid, port)| {
            let state = if port != 0 {
                crate::host_proc::thread_run_state_char(port)
            } else {
                'R'
            };
            (tid, state)
        })
        .collect()
}
