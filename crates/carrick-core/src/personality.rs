//! Neutral operating system personality interface.

use carrick_guest_arch::ThreadPointerRegister;

/// An operating system personality contract for execution context and policy.
pub trait Personality: Send + Sync {
    /// Return the human-readable identifier of this personality.
    fn name(&self) -> &'static str;

    /// The architectural register this personality uses as the thread context / TLS base pointer.
    fn thread_pointer_register(&self) -> ThreadPointerRegister;

    /// The architectural register this personality uses for a specific thread, allowing
    /// personalities to configure thread pointer base registers per task/thread.
    fn thread_pointer_register_for_thread(&self, _thread_id: u64) -> ThreadPointerRegister {
        self.thread_pointer_register()
    }

    /// The architectural register this personality uses for a specific task.
    fn thread_pointer_register_for_task(&self, _task_id: u64) -> ThreadPointerRegister {
        self.thread_pointer_register()
    }
}
