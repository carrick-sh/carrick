//! Linux robust-list and clear-TID progress retained by the neutral terminal owner.
use carrick_core::user_copy::{CopyOutcome, GuestCopyRequest, UserCopy};
use carrick_guest_arch::UserVa;

const WAITERS: u32 = 0x8000_0000;
const OWNER_DIED: u32 = 0x4000_0000;
const TID_MASK: u32 = 0x3fff_ffff;
const LIST_LIMIT: u32 = 2048;

#[derive(Clone, Copy)]
enum Phase {
    Head,
    Link,
    Load,
    Exchange(u32),
    Wake,
    Clear,
    ClearWake,
    Done,
}

/// A fault consumes only the current copy; a park preserves its phase and
/// successor link. Completed stores and wakes are never replayed.
pub struct ThreadCleanup {
    head: u64,
    tid: u32,
    clear: u64,
    phase: Phase,
    current: u64,
    next: u64,
    offset: i64,
    pending: u64,
    pending_pass: bool,
    remaining: u32,
    word: u64,
    refused: bool,
}
pub enum CleanupPoll {
    Wait(GuestCopyRequest),
    Wake(UserVa),
    Done,
}
impl ThreadCleanup {
    pub fn new(head: u64, tid: u32, clear: u64) -> Self {
        Self {
            head,
            tid,
            clear,
            phase: if head == 0 { Phase::Clear } else { Phase::Head },
            current: 0,
            next: 0,
            offset: 0,
            pending: 0,
            pending_pass: false,
            remaining: LIST_LIMIT,
            word: 0,
            refused: false,
        }
    }
    /// A backing refusal is the terminal fault of the exact parked access.
    pub fn refuse_copy(&mut self) {
        self.refused = true;
    }
    fn copy(&mut self, attempt: impl FnOnce() -> CopyOutcome) -> CopyOutcome {
        if core::mem::take(&mut self.refused) {
            CopyOutcome::Fault
        } else {
            attempt()
        }
    }
    fn pending_or_clear(&mut self) {
        if !self.pending_pass && self.pending & !1 != 0 {
            self.pending_pass = true;
            self.current = self.pending;
            self.phase = Phase::Load;
            self.word = (self.current & !1).wrapping_add_signed(self.offset);
        } else {
            self.phase = Phase::Clear;
        }
    }
    fn advance(&mut self) {
        if self.pending_pass {
            self.phase = Phase::Clear;
        } else {
            self.current = self.next;
            self.phase = Phase::Link;
        }
    }
    pub fn wake_completed(&mut self) {
        match self.phase {
            Phase::Wake => self.advance(),
            Phase::ClearWake => self.phase = Phase::Done,
            _ => {}
        }
    }
    pub fn poll(&mut self, copy: &mut impl UserCopy) -> CleanupPoll {
        loop {
            match self.phase {
                Phase::Head => {
                    let mut bytes = [0; 24];
                    let address = UserVa::new(self.head);
                    match self.copy(|| copy.copy_in(&mut bytes, address)) {
                        CopyOutcome::NotYet(wait) => return CleanupPoll::Wait(wait),
                        CopyOutcome::Fault => self.phase = Phase::Clear,
                        CopyOutcome::Done => {
                            self.current =
                                u64::from_ne_bytes(bytes[..8].try_into().unwrap_or([0; 8]));
                            self.offset =
                                i64::from_ne_bytes(bytes[8..16].try_into().unwrap_or([0; 8]));
                            self.pending =
                                u64::from_ne_bytes(bytes[16..].try_into().unwrap_or([0; 8]));
                            self.phase = Phase::Link;
                        }
                    }
                }
                Phase::Link => {
                    if self.current & !1 == self.head || self.remaining == 0 {
                        self.pending_or_clear();
                        continue;
                    }
                    let mut bytes = [0; 8];
                    let address = UserVa::new(self.current & !1);
                    match self.copy(|| copy.copy_in(&mut bytes, address)) {
                        CopyOutcome::NotYet(wait) => return CleanupPoll::Wait(wait),
                        CopyOutcome::Fault => self.pending_or_clear(),
                        CopyOutcome::Done => {
                            self.remaining -= 1;
                            self.next = u64::from_ne_bytes(bytes);
                            self.word = (self.current & !1).wrapping_add_signed(self.offset);
                            if self.current & !1 == self.pending & !1 {
                                self.advance();
                            } else {
                                self.phase = Phase::Load;
                            }
                        }
                    }
                }
                Phase::Load => {
                    // PI futex ownership belongs to the PI protocol, not the
                    // non-PI owner-death CAS. Never corrupt its word here.
                    if self.current & 1 != 0 {
                        self.advance();
                        continue;
                    }
                    let mut value = 0;
                    let address = UserVa::new(self.word);
                    match self.copy(|| copy.atomic_load_u32(address, &mut value)) {
                        CopyOutcome::NotYet(wait) => return CleanupPoll::Wait(wait),
                        CopyOutcome::Fault => self.advance(),
                        CopyOutcome::Done if value & TID_MASK != self.tid => self.advance(),
                        CopyOutcome::Done => self.phase = Phase::Exchange(value),
                    }
                }
                Phase::Exchange(expected) => {
                    let mut observed = 0;
                    let desired = (expected & WAITERS) | OWNER_DIED;
                    let address = UserVa::new(self.word);
                    match self.copy(|| {
                        copy.atomic_compare_exchange_u32(address, expected, desired, &mut observed)
                    }) {
                        CopyOutcome::NotYet(wait) => return CleanupPoll::Wait(wait),
                        CopyOutcome::Fault => self.advance(),
                        CopyOutcome::Done if observed == expected => {
                            if expected & WAITERS != 0 {
                                self.phase = Phase::Wake;
                            } else {
                                self.advance();
                            }
                        }
                        CopyOutcome::Done if observed & TID_MASK != self.tid => self.advance(),
                        CopyOutcome::Done => self.phase = Phase::Exchange(observed),
                    }
                }
                Phase::Wake => return CleanupPoll::Wake(UserVa::new(self.word)),
                Phase::Clear => {
                    if self.clear == 0 {
                        self.phase = Phase::Done;
                        continue;
                    }
                    let address = UserVa::new(self.clear);
                    match self.copy(|| copy.copy_out(address, &0_u32.to_ne_bytes())) {
                        CopyOutcome::NotYet(wait) => return CleanupPoll::Wait(wait),
                        CopyOutcome::Done | CopyOutcome::Fault => self.phase = Phase::ClearWake,
                    }
                }
                Phase::ClearWake => return CleanupPoll::Wake(UserVa::new(self.clear)),
                Phase::Done => return CleanupPoll::Done,
            }
        }
    }
}
