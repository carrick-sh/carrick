use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::arena::ArenaError;
use crate::domains::{HostPid, ProcessGeneration};

pub const PROCESS_RECORDS: usize = 4096;

/// Claim-sentinel: `host_pid == REGISTERING` while a record is being filled.
pub const REGISTERING: u32 = u32::MAX;

pub const FLAG_ALIVE: u32 = 1 << 0;
pub const FLAG_ORPHANED: u32 = 1 << 1;
pub const FLAG_DEAD: u32 = 1 << 2;
pub const FLAG_ADOPTED: u32 = 1 << 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum VirtualPtraceState {
    Untraced = 0,
    Running = 1,
    StopRequested = 2,
    StopReported = 3,
}

impl VirtualPtraceState {
    pub const fn raw(self) -> u32 {
        self as u32
    }
}

#[repr(C)]
pub struct ProcessSection {
    pub next_ns_pid: AtomicU32,
    pub init_host_pid: AtomicU32,
    pub init_host_pgid: AtomicU32,
    pub init_host_sid: AtomicU32,
    pub init_sig_handlers: AtomicU64,
    pub records: [ProcessRecord; PROCESS_RECORDS],
}

#[repr(C)]
pub struct ProcessRecord {
    pub host_pid: AtomicU32,
    pub generation: AtomicU32,
    pub ns_pid: AtomicU32,
    pub parent_host_pid: AtomicU32,
    pub subreaper_pid: AtomicU32,
    pub flags: AtomicU32,
    pub exec_generation: AtomicU32,
    pub pgid: AtomicU32,
    pub sid: AtomicU32,
    pub ctty: AtomicU32,
    pub run_state: AtomicU64,
    pub ptrace_stop_signal: AtomicU64,
    pub exit_status: AtomicU64,
    pub exit_ready: AtomicU32,
    pub ptrace_tracer_pid: AtomicU32,
    pub ptrace_state: AtomicU32,
    _pad: AtomicU32,
    pub guest_ns: AtomicU64,
}

/// Index + generation pair so a stale ref cannot touch a reused slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcessRecordRef {
    pub index: usize,
    pub generation: ProcessGeneration,
}

impl ProcessSection {
    /// Claim a free record, fill via the closure, and publish `host_pid` last.
    pub fn claim(
        &self,
        host_pid: Option<HostPid>,
        generation: ProcessGeneration,
        fill: impl FnOnce(&ProcessRecord),
    ) -> Result<ProcessRecordRef, ArenaError> {
        for (index, record) in self.records.iter().enumerate() {
            if record
                .host_pid
                .compare_exchange(0, REGISTERING, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
            {
                continue;
            }

            record.clear_body_for_claim();
            record.generation.store(generation.raw(), Ordering::Release);
            fill(record);
            if let Some(pid) = host_pid {
                record.host_pid.store(pid.raw(), Ordering::Release);
            }
            return Ok(ProcessRecordRef { index, generation });
        }
        Err(ArenaError::Exhausted {
            section: "processes",
            capacity: PROCESS_RECORDS,
        })
    }

    pub fn find(&self, host_pid: HostPid) -> Option<ProcessRecordRef> {
        let wanted = host_pid.raw();
        if wanted == 0 || wanted == REGISTERING {
            return None;
        }

        for (index, record) in self.records.iter().enumerate() {
            if record.host_pid.load(Ordering::Acquire) != wanted {
                continue;
            }
            let generation = record.generation.load(Ordering::Acquire);
            if generation != 0 {
                return Some(ProcessRecordRef {
                    index,
                    generation: ProcessGeneration::new(generation),
                });
            }
        }
        None
    }

    pub fn allocate_ns_pid(&self) -> u32 {
        self.next_ns_pid.fetch_add(1, Ordering::AcqRel)
    }

    pub fn publish_host_pid(&self, r: ProcessRecordRef, pid: HostPid) {
        if let Some(record) = self.record_for_ref(r) {
            record.host_pid.store(pid.raw(), Ordering::Release);
        }
    }

    pub fn release(&self, r: ProcessRecordRef) {
        if let Some(record) = self.record_for_ref(r) {
            record.clear_body_for_claim();
            record.generation.store(0, Ordering::Release);
            record.host_pid.store(0, Ordering::Release);
        }
    }

    fn record_for_ref(&self, r: ProcessRecordRef) -> Option<&ProcessRecord> {
        let record = self.records.get(r.index)?;
        let generation = record.generation.load(Ordering::Acquire);
        if generation == r.generation.raw() {
            Some(record)
        } else {
            None
        }
    }
}

impl ProcessRecord {
    fn clear_body_for_claim(&self) {
        self.ns_pid.store(0, Ordering::Relaxed);
        self.parent_host_pid.store(0, Ordering::Relaxed);
        self.subreaper_pid.store(0, Ordering::Relaxed);
        self.flags.store(0, Ordering::Relaxed);
        self.exec_generation.store(0, Ordering::Relaxed);
        self.pgid.store(0, Ordering::Relaxed);
        self.sid.store(0, Ordering::Relaxed);
        self.ctty.store(0, Ordering::Relaxed);
        self.run_state.store(0, Ordering::Relaxed);
        self.ptrace_stop_signal.store(0, Ordering::Relaxed);
        self.exit_status.store(0, Ordering::Relaxed);
        self.exit_ready.store(0, Ordering::Relaxed);
        self.ptrace_tracer_pid.store(0, Ordering::Relaxed);
        self.ptrace_state
            .store(VirtualPtraceState::Untraced.raw(), Ordering::Relaxed);
        self.guest_ns.store(0, Ordering::Relaxed);
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::arena::KernelArena;
    use crate::domains::HostPid;

    #[test]
    fn claim_fill_publish_find_release_round_trip() {
        let arena = KernelArena::create().unwrap();
        let s = &arena.layout().processes;
        let generation = arena.allocate_generation();
        let r = s
            .claim(Some(HostPid::new(500)), generation, |rec| {
                rec.ns_pid.store(2, Ordering::Relaxed);
                rec.parent_host_pid.store(1, Ordering::Relaxed);
                rec.flags.store(FLAG_ALIVE, Ordering::Relaxed);
            })
            .unwrap();
        let found = s.find(HostPid::new(500)).unwrap();
        assert_eq!(found.index, r.index);
        assert_eq!(found.generation, generation);
        s.release(found);
        assert!(s.find(HostPid::new(500)).is_none());
    }

    #[test]
    fn registering_records_are_invisible_to_find() {
        let arena = KernelArena::create().unwrap();
        let s = &arena.layout().processes;
        let generation = arena.allocate_generation();
        let r = s.claim(None, generation, |_| {}).unwrap();
        assert!(s.find(HostPid::new(REGISTERING)).is_none());
        s.publish_host_pid(r, HostPid::new(600));
        assert!(s.find(HostPid::new(600)).is_some());
    }

    #[test]
    fn ns_pids_are_monotonic_from_2() {
        let arena = KernelArena::create().unwrap();
        let s = &arena.layout().processes;
        assert_eq!(s.allocate_ns_pid(), 2);
        assert_eq!(s.allocate_ns_pid(), 3);
    }

    #[test]
    fn exhaustion_is_loud() {
        let arena = KernelArena::create().unwrap();
        let s = &arena.layout().processes;
        for i in 0..PROCESS_RECORDS {
            s.claim(
                Some(HostPid::new(1000 + i as u32)),
                arena.allocate_generation(),
                |_| {},
            )
            .unwrap();
        }
        assert!(matches!(
            s.claim(Some(HostPid::new(1)), arena.allocate_generation(), |_| {}),
            Err(ArenaError::Exhausted {
                section: "processes",
                capacity: PROCESS_RECORDS
            })
        ));
    }
}
