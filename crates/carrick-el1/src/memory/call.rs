//! Native adapters expose only the anonymous engine's call contract.
use carrick_guest_arch::{NativeReturnWord, UserVa};
use carrick_personality_linux::entry::{CanonicalCall, CanonicalOrdinal};
use carrick_sched_core::SlotId;

/// ISA-neutral memory call, including the originating continuation identity.
pub trait AnonymousCallView {
    fn canonical(&self) -> CanonicalOrdinal;
    fn arguments(&self) -> [u64; 6];
    fn return_address(&self) -> UserVa;
    fn slot(&self) -> Option<SlotId>;
    fn task_index(&self) -> usize {
        self.slot().map_or(usize::MAX, SlotId::index)
    }
    fn result(&self) -> NativeReturnWord;
    fn set_result(&mut self, result: NativeReturnWord);
}

/// A decoded native call whose result is copied back by the entry owner.
pub struct AnonymousCall {
    call: CanonicalCall,
    slot: SlotId,
    return_address: UserVa,
    result: NativeReturnWord,
}
impl AnonymousCall {
    pub fn slot(&self) -> SlotId {
        self.slot
    }
    pub fn new(call: CanonicalCall, slot: SlotId, return_address: UserVa) -> Self {
        Self {
            result: NativeReturnWord(call.args[0]),
            call,
            slot,
            return_address,
        }
    }
}
impl AnonymousCallView for AnonymousCall {
    fn canonical(&self) -> CanonicalOrdinal {
        self.call.canonical
    }
    fn arguments(&self) -> [u64; 6] {
        self.call.args
    }
    fn return_address(&self) -> UserVa {
        self.return_address
    }
    fn slot(&self) -> Option<SlotId> {
        Some(self.slot)
    }
    fn task_index(&self) -> usize {
        0
    }
    fn result(&self) -> NativeReturnWord {
        self.result
    }
    fn set_result(&mut self, result: NativeReturnWord) {
        self.result = result;
    }
}

impl AnonymousCallView for carrick_el1_abi::TrapFrame {
    fn canonical(&self) -> CanonicalOrdinal {
        CanonicalOrdinal::new(self.x[8])
    }
    fn arguments(&self) -> [u64; 6] {
        [
            self.x[0], self.x[1], self.x[2], self.x[3], self.x[4], self.x[5],
        ]
    }
    fn return_address(&self) -> UserVa {
        UserVa::new(self.elr)
    }
    fn slot(&self) -> Option<SlotId> {
        usize::try_from(self.slot).ok().and_then(SlotId::from_index)
    }
    fn result(&self) -> NativeReturnWord {
        NativeReturnWord(self.x[0])
    }
    fn set_result(&mut self, result: NativeReturnWord) {
        self.x[0] = result.0;
    }
}
