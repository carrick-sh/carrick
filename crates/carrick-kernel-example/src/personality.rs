//! In-tree non-Linux test personality for VM-free scenario verification.

use carrick_core::Personality;
use carrick_guest_arch::ThreadPointerRegister;
use parking_lot::RwLock;
use std::collections::HashMap;

/// In-tree test personality with configurable thread base pointer register.
#[derive(Debug)]
pub struct ExamplePersonality {
    default_register: ThreadPointerRegister,
    thread_overrides: RwLock<HashMap<u64, ThreadPointerRegister>>,
    task_overrides: RwLock<HashMap<u64, ThreadPointerRegister>>,
}

impl ExamplePersonality {
    /// Create an instance using the architecture's non-standard thread pointer register:
    /// `GS` on x86_64, `x18` on AArch64.
    pub fn new() -> Self {
        #[cfg(target_arch = "x86_64")]
        let default_register = ThreadPointerRegister::GS;
        #[cfg(target_arch = "aarch64")]
        let default_register = ThreadPointerRegister::X18;
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        let default_register = ThreadPointerRegister::GS;

        Self {
            default_register,
            thread_overrides: RwLock::new(HashMap::new()),
            task_overrides: RwLock::new(HashMap::new()),
        }
    }

    /// Create an instance with an explicit default thread pointer register.
    pub fn with_default_register(default_register: ThreadPointerRegister) -> Self {
        Self {
            default_register,
            thread_overrides: RwLock::new(HashMap::new()),
            task_overrides: RwLock::new(HashMap::new()),
        }
    }

    /// Configure a thread-specific thread pointer register.
    pub fn configure_thread(&self, thread_id: u64, register: ThreadPointerRegister) {
        self.thread_overrides.write().insert(thread_id, register);
    }

    /// Configure a task-specific thread pointer register.
    pub fn configure_task(&self, task_id: u64, register: ThreadPointerRegister) {
        self.task_overrides.write().insert(task_id, register);
    }

    /// Create a shared MM authority for explicit address-space reservation,
    /// commit, and decommit primitives under this personality.
    pub fn create_mm_authority(
        &self,
        pt_manager: carrick_mmu_core::aarch64::PageTableManager,
        frame_pool_base: carrick_guest_arch::FrameGpa,
        frame_pool_total: usize,
    ) -> carrick_core::mm::RangeAuthority {
        carrick_core::mm::RangeAuthority::new(pt_manager, frame_pool_base, frame_pool_total)
    }
}

impl Default for ExamplePersonality {
    fn default() -> Self {
        Self::new()
    }
}

impl Personality for ExamplePersonality {
    fn name(&self) -> &'static str {
        "example"
    }

    fn thread_pointer_register(&self) -> ThreadPointerRegister {
        self.default_register
    }

    fn thread_pointer_register_for_thread(&self, thread_id: u64) -> ThreadPointerRegister {
        self.thread_overrides
            .read()
            .get(&thread_id)
            .copied()
            .unwrap_or(self.default_register)
    }

    fn thread_pointer_register_for_task(&self, task_id: u64) -> ThreadPointerRegister {
        self.task_overrides
            .read()
            .get(&task_id)
            .copied()
            .unwrap_or(self.default_register)
    }
}
