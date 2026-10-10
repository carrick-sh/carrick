//! Explicit per-frame policy avoids process-global aperture mutation in tests.
use carrick_el1::personality::dispatch::GuestDispatchFrame;
use carrick_el1_abi::TrapFrame;
use carrick_guest_arch::{
    CanonicalNr, NativeOrdinal, NativeReturnWord, SlotId, SyscallFrame, UserVa,
};
use carrick_guest_mem::ArmRingFirst;
use carrick_personality_linux::crossing::HostCrossingSet;

pub struct PolicyFrame<'a> {
    pub frame: &'a mut TrapFrame,
    pub policy: ArmRingFirst,
}
impl SyscallFrame for PolicyFrame<'_> {
    fn canonical_ordinal(&self) -> CanonicalNr {
        self.frame.canonical_ordinal()
    }
    fn argument(&self, index: usize) -> Option<u64> {
        self.frame.argument(index)
    }
    fn result(&self) -> NativeReturnWord {
        self.frame.result()
    }
    fn set_result(&mut self, result: NativeReturnWord) {
        self.frame.set_result(result);
    }
    fn slot(&self) -> Option<SlotId> {
        self.frame.slot()
    }
    fn user_sp(&self) -> Option<UserVa> {
        self.frame.user_sp()
    }
}
impl GuestDispatchFrame for PolicyFrame<'_> {
    fn native_number(&self) -> NativeOrdinal {
        self.frame.native_number()
    }
    fn crossing_set(&self) -> HostCrossingSet {
        HostCrossingSet::Aarch64
    }
    fn crossing_strict(&self, _: impl FnOnce() -> bool) -> bool {
        self.policy.is_strict()
    }
    fn arm_frame(&mut self) -> Option<&mut TrapFrame> {
        Some(self.frame)
    }
    fn arm_frame_ref(&self) -> Option<&TrapFrame> {
        Some(self.frame)
    }
    fn arm_scheduler(&self) -> bool {
        true
    }
    fn robust_publications(&self) -> Option<&core::sync::atomic::AtomicU64> {
        None
    }
}
