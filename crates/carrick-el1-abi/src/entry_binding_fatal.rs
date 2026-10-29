//! Terminal observation of an ARM entry-binding failure. This carries no
//! completion or scheduler authority; record fields are atomic observations.
use crate::{Claim, ExecutionBinding, RecordId, SlotId, ThreadIdentity, TrapFrame, ZoneTables};
use core::fmt;

/// Discriminator in x1 of the existing PANIC_SENTINEL / HVC #3 transport.
/// Rust panic source lines cannot collide with this full-width tag.
pub const ENTRY_BINDING_FATAL_TAG: u64 = 0x454e_5452_5942_494e;

pub const fn is_entry_binding_fatal(sentinel: u64, tag: u64) -> bool {
    sentinel == crate::PANIC_SENTINEL && tag == ENTRY_BINDING_FATAL_TAG
}

/// Compact discriminator carried in x2 at the existing terminal HVC.
/// Values are transport ABI; unknown values remain visible in diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u64)]
pub enum EntryBindingFatalReason {
    EntryBinding = 1,
    PhysicalCustody = 2,
    MissingNativeFrame = 3,
    RevisionCredit = 4,
    SignalNumber = 5,
    ProcessGraph = 6,
    HostRescheduleKick = 7,
    HostWorkForward = 8,
    CpuStackSlot = 9,
    ArchitectureFatal = 10,
    RunFailureReturned = 11,
    ResidencyLayout = 12,
    RootExitRefused = 13,
    ForkCustodyRefused = 14,
    AffinityTopologyMissing = 15,
    NamespaceIdentityRange = 16,
    NamespaceIdentityLost = 17,
    ExitCustodyLost = 18,
    ExitPublicationLost = 19,
    ExitReleaseLost = 20,
    RegistryEpochExhausted = 21,
    BirthPayloadMismatch = 22,
    ProcessGroupCollision = 23,
    ProcessGroupIndexLost = 24,
    SessionCollision = 25,
    SessionIndexLost = 26,
    AutoreapAccountingLost = 27,
}
impl EntryBindingFatalReason {
    pub const fn from_raw(raw: u64) -> Option<Self> {
        match raw {
            1 => Some(Self::EntryBinding),
            2 => Some(Self::PhysicalCustody),
            3 => Some(Self::MissingNativeFrame),
            4 => Some(Self::RevisionCredit),
            5 => Some(Self::SignalNumber),
            6 => Some(Self::ProcessGraph),
            7 => Some(Self::HostRescheduleKick),
            8 => Some(Self::HostWorkForward),
            9 => Some(Self::CpuStackSlot),
            10 => Some(Self::ArchitectureFatal),
            11 => Some(Self::RunFailureReturned),
            12 => Some(Self::ResidencyLayout),
            13 => Some(Self::RootExitRefused),
            14 => Some(Self::ForkCustodyRefused),
            15 => Some(Self::AffinityTopologyMissing),
            16 => Some(Self::NamespaceIdentityRange),
            17 => Some(Self::NamespaceIdentityLost),
            18 => Some(Self::ExitCustodyLost),
            19 => Some(Self::ExitPublicationLost),
            20 => Some(Self::ExitReleaseLost),
            21 => Some(Self::RegistryEpochExhausted),
            22 => Some(Self::BirthPayloadMismatch),
            23 => Some(Self::ProcessGroupCollision),
            24 => Some(Self::ProcessGroupIndexLost),
            25 => Some(Self::SessionCollision),
            26 => Some(Self::SessionIndexLost),
            27 => Some(Self::AutoreapAccountingLost),

            _ => None,
        }
    }
}

/// Two-register fatal payload. The caller's source coordinates occupy x3;
/// no pointers or aggregate stack records cross this diagnostic boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EntryBindingFatalDetail {
    pub reason: EntryBindingFatalReason,
    pub line: u32,
    pub column: u32,
}
impl EntryBindingFatalDetail {
    #[track_caller]
    pub fn at_caller(reason: EntryBindingFatalReason) -> Self {
        let caller = core::panic::Location::caller();
        Self {
            reason,
            line: caller.line(),
            column: caller.column(),
        }
    }
    pub const fn encode(self) -> [u64; 2] {
        [
            self.reason as u64,
            ((self.line as u64) << 32) | self.column as u64,
        ]
    }
    pub const fn decode(reason: u64, location: u64) -> Option<Self> {
        let Some(reason) = EntryBindingFatalReason::from_raw(reason) else {
            return None;
        };
        Some(Self {
            reason,
            line: (location >> 32) as u32,
            column: location as u32,
        })
    }
}
struct FatalDetail(Option<u64>, Option<u64>);
impl fmt::Display for FatalDetail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Some(raw) => match EntryBindingFatalReason::from_raw(raw) {
                Some(reason) => write!(f, "reason={reason:?} ")?,
                None => write!(f, "reason=unknown({raw:#x}) ")?,
            },
            None => f.write_str("reason=unavailable ")?,
        }
        match self.1 {
            Some(location) => write!(f, "at={}:{}", location >> 32, location as u32),
            None => f.write_str("at=unavailable"),
        }
    }
}

/// Live registers at the terminal HVC, distinct from the saved EL0 frame.
/// None means the VMM could not read the register, never an invented zero.
#[derive(Clone, Copy, Debug, Default)]
pub struct ArmEntryFatalRegisters {
    pub reason: Option<u64>,
    pub source_location: Option<u64>,
    pub pc: Option<u64>,
    pub lr: Option<u64>,
    pub fp: Option<u64>,
    pub sp_el0: Option<u64>,
    pub sp_el1: Option<u64>,
    pub esr_el1: Option<u64>,
    pub far_el1: Option<u64>,
    pub elr_el1: Option<u64>,
    pub spsr_el1: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArmEntryRecordSource {
    Current,
    Host,
}

/// Identity and custody observed without reading the record's UnsafeCell
/// context. A peer may request custody: preserve before/after observations.
#[derive(Clone, Copy, Debug)]
pub struct ArmEntryFatalRecord {
    pub id: RecordId,
    pub source: ArmEntryRecordSource,
    pub identity: ThreadIdentity,
    pub incarnation: u64,
    pub incarnation_after: u64,
    pub claim: Claim,
    pub claim_after: Claim,
}

/// Small host-side snapshot rendered into the existing fixed fatal record.
/// SP_EL0 is banked hardware state: TrapFrame itself has no saved SP field.
#[derive(Clone, Copy, Debug)]
pub struct ArmEntryBindingFatal {
    pub registers: ArmEntryFatalRegisters,
    pub slot: SlotId,
    pub frame_slot: u64,
    pub saved_lr: u64,
    pub saved_x: [u64; 4],
    pub saved_elr: u64,
    pub saved_spsr: u64,
    pub saved_esr: u64,
    pub saved_far: u64,
    pub loaded: ExecutionBinding,
    pub record: Option<ArmEntryFatalRecord>,
}

/// Selects terminal context before the carrier's single EL1 fatal sink.
/// Borrowing the observation avoids another large host-side snapshot copy.
pub enum ArmEl1FatalReport<'a> {
    Entry(&'a ArmEntryBindingFatal),
    EntryUnavailable(&'a ArmEntryFatalRegisters),
    Panic {
        sentinel: u64,
        elr_el1: u64,
        source_line: u64,
        source_column: u64,
        publication_detail: u64,
    },
}

impl fmt::Display for ArmEl1FatalReport<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Entry(diagnostic) => diagnostic.fmt(f),
            Self::EntryUnavailable(registers) => write!(
                f,
                "entry_binding retained_entry=unavailable {} registers={registers:?}",
                FatalDetail(registers.reason, registers.source_location)
            ),
            Self::Panic {
                sentinel,
                elr_el1,
                source_line,
                source_column,
                publication_detail,
            } => write!(
                f,
                "EL1 panic handler invoked: panic sentinel {sentinel:#x} at elr_el1={elr_el1:#x}; \
                 source_line={source_line} source_column={source_column} \
                 frame_grant_publication_detail={publication_detail}"
            ),
        }
    }
}

impl ArmEntryBindingFatal {
    /// Caller supplies the exact stopped CPU's vector frame and banked
    /// registers. Loaded and record identities are reported independently;
    /// failed authentication must not erase the evidence of a mismatch.
    pub fn capture(
        registers: ArmEntryFatalRegisters,
        frame: &TrapFrame,
        loaded: ExecutionBinding,
        zone: &ZoneTables,
        slot: SlotId,
    ) -> Self {
        let record = zone
            .slot(slot)
            .current()
            .map(|id| (id, ArmEntryRecordSource::Current))
            .or_else(|| {
                zone.slot(slot)
                    .host_record()
                    .map(|id| (id, ArmEntryRecordSource::Host))
            })
            .map(|(id, source)| {
                let record = zone.record(id);
                let incarnation = record.incarnation();
                let claim = record.claim();
                let identity = record.identity();
                ArmEntryFatalRecord {
                    id,
                    source,
                    identity,
                    incarnation,
                    claim,
                    claim_after: record.claim(),
                    incarnation_after: record.incarnation(),
                }
            });
        Self {
            registers,
            slot,
            frame_slot: frame.slot,
            saved_lr: frame.x[30],
            saved_x: [frame.x[0], frame.x[1], frame.x[2], frame.x[3]],
            saved_elr: frame.elr,
            saved_spsr: frame.spsr,
            saved_esr: frame.esr,
            saved_far: frame.far,
            loaded,
            record,
        }
    }
}
// Keep every custody field in the fixed 1024-byte sink. Flags are 0/1;
// long variants avoid Debug's whitespace, slot wrappers and boolean words.
// `host_req` is the complete host_requested flag, not omitted custody state.
struct CompactClaim(Claim);
impl fmt::Display for CompactClaim {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Claim::Transferring {
                seq,
                cancelled,
                host_requested,
            } => write!(
                f,
                "Transferring{{seq:{seq},cancelled:{},host_req:{}}}",
                u8::from(cancelled),
                u8::from(host_requested)
            ),
            Claim::Placing {
                incarnation,
                host_requested,
            } => write!(
                f,
                "Placing{{incarnation:{incarnation:#x},host_req:{}}}",
                u8::from(host_requested)
            ),
            Claim::OnCpuRequested { slot, seq } => {
                write!(f, "OnCpuRequested{{slot:{},seq:{seq}}}", slot.raw())
            }
            Claim::Free => f.write_str("Free"),
            Claim::Parked { seq } => write!(f, "Parked{{seq:{seq}}}"),
            Claim::Host { seq } => write!(f, "Host{{seq:{seq}}}"),
            Claim::Queued { slot, seq } => write!(f, "Queued{{slot:{},seq:{seq}}}", slot.raw()),
            Claim::OnCpu { slot, seq } => write!(f, "OnCpu{{slot:{},seq:{seq}}}", slot.raw()),
            Claim::Activating { incarnation } => {
                write!(f, "Activating{{incarnation:{incarnation:#x}}}")
            }
            Claim::Retiring { incarnation } => {
                write!(f, "Retiring{{incarnation:{incarnation:#x}}}")
            }
            Claim::FirstEntryHost { incarnation } => {
                write!(f, "FirstEntryHost{{incarnation:{incarnation:#x}}}")
            }
        }
    }
}
struct Register(Option<u64>);
impl fmt::Display for Register {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Some(value) => write!(f, "{value:#x}"),
            None => f.write_str("unavailable"),
        }
    }
}
impl fmt::Display for ArmEntryBindingFatal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let r = &self.registers;
        write!(
            f,
            "entry_binding cpu={} pc={} lr={} fp={} sp_el1={} esr_el1={} far_el1={} elr_el1={} spsr_el1={} sp_el0={} ",
            self.slot.raw(),
            Register(r.pc),
            Register(r.lr),
            Register(r.fp),
            Register(r.sp_el1),
            Register(r.esr_el1),
            Register(r.far_el1),
            Register(r.elr_el1),
            Register(r.spsr_el1),
            Register(r.sp_el0)
        )?;
        write!(
            f,
            "frame_slot={:#x} saved_lr={:#x} saved_x0={:#x} saved_x1={:#x} saved_x2={:#x} saved_x3={:#x} saved_elr={:#x} saved_spsr={:#x} saved_esr={:#x} saved_far={:#x} ",
            self.frame_slot,
            self.saved_lr,
            self.saved_x[0],
            self.saved_x[1],
            self.saved_x[2],
            self.saved_x[3],
            self.saved_elr,
            self.saved_spsr,
            self.saved_esr,
            self.saved_far
        )?;
        write!(
            f,
            "loaded_task={:#x} loaded_generation={:#x} loaded_mm={:#x} loaded_birth={:#x} ",
            self.loaded.task.raw(),
            self.loaded.generation.raw(),
            self.loaded.mm.raw(),
            self.loaded.thread_generation.raw()
        )?;
        write!(f, "{} ", FatalDetail(r.reason, r.source_location))?;
        match self.record {
            None => f.write_str("record=none"),
            Some(record) => write!(
                f,
                "record={} record_source={:?} task={:#x} generation={:#x} birth={:#x} mm={:#x} incarnation={:#x}->{:#x} custody={}->{}",
                record.id.raw(),
                record.source,
                record.identity.tid,
                record.identity.generation,
                record.identity.serial,
                record.identity.mm,
                record.incarnation,
                record.incarnation_after,
                CompactClaim(record.claim),
                CompactClaim(record.claim_after)
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::{boxed::Box, format};

    #[test]
    fn fatal_detail_round_trip_and_formatter() {
        for raw in 1..=27 {
            let reason = EntryBindingFatalReason::from_raw(raw).unwrap();
            for (line, column) in [(0, 0), (1646, 9), (u32::MAX, u32::MAX)] {
                let detail = EntryBindingFatalDetail {
                    reason,
                    line,
                    column,
                };
                let [r, l] = detail.encode();
                assert_eq!(EntryBindingFatalDetail::decode(r, l), Some(detail));
            }
        }
        assert_eq!(EntryBindingFatalDetail::decode(0, 0), None);
        assert_eq!(EntryBindingFatalDetail::decode(u64::MAX, 0), None);
        assert_eq!(
            format!("{}", FatalDetail(Some(3), Some((1646 << 32) | 9))),
            "reason=MissingNativeFrame at=1646:9"
        );
        assert_eq!(
            format!("{}", FatalDetail(Some(99), Some(0))),
            "reason=unknown(0x63) at=0:0"
        );
        assert_eq!(
            format!("{}", FatalDetail(None, None)),
            "reason=unavailable at=unavailable"
        );
        assert_eq!(
            format!("{}", FatalDetail(Some(3), None)),
            "reason=MissingNativeFrame at=unavailable"
        );
        assert_eq!(
            format!(
                "{}",
                CompactClaim(Claim::Transferring {
                    seq: 7,
                    cancelled: true,
                    host_requested: false
                })
            ),
            "Transferring{seq:7,cancelled:1,host_req:0}"
        );
        assert_eq!(
            format!(
                "{}",
                CompactClaim(Claim::Placing {
                    incarnation: 9,
                    host_requested: true
                })
            ),
            "Placing{incarnation:0x9,host_req:1}"
        );
        let line = line!() + 1;
        let detail = EntryBindingFatalDetail::at_caller(EntryBindingFatalReason::EntryBinding);
        assert_eq!(detail.line, line);
        let registers = ArmEntryFatalRegisters {
            reason: Some(3),
            source_location: Some((1646 << 32) | 9),
            ..Default::default()
        };
        let capture = ArmEntryBindingFatal::capture(
            registers,
            &crate::TrapFrame::default(),
            binding(),
            &zone(),
            crate::SlotId::new(0),
        );
        for text in [
            format!("{capture}"),
            format!("{}", ArmEl1FatalReport::EntryUnavailable(&registers)),
        ] {
            assert!(text.contains("reason=MissingNativeFrame at=1646:9"));
        }
    }

    fn zone() -> Box<crate::ZoneTables> {
        let mut storage = Box::<crate::ZoneTables>::new_uninit();
        // SAFETY: the typed allocation preserves ABI alignment; all-zero is
        // the scheduler's valid empty state. No large aggregate is on stack.
        unsafe {
            storage.as_mut_ptr().write_bytes(0, 1);
            storage.assume_init()
        }
    }

    fn binding() -> crate::ExecutionBinding {
        crate::ExecutionBinding {
            task: crate::EntryTaskKey::from_raw(41),
            generation: crate::SnapshotGeneration::from_raw(11),
            mm: crate::EntryMmKey::from_raw(7),
            thread_generation: crate::EntryThreadGeneration::from_raw(101),
        }
    }

    #[test]
    fn entry_binding_fatal_report_preserves_the_single_terminal_sink() {
        let registers = ArmEntryFatalRegisters::default();
        let unavailable = ArmEl1FatalReport::EntryUnavailable(&registers);
        assert!(format!("{unavailable}").contains("retained_entry=unavailable"));
        let ordinary = ArmEl1FatalReport::Panic {
            sentinel: crate::PANIC_SENTINEL,
            elr_el1: 0x266318,
            source_line: 12,
            source_column: 3,
            publication_detail: 4,
        };
        assert_eq!(
            format!("{ordinary}"),
            "EL1 panic handler invoked: panic sentinel 0xdeadcafedeadbeef at elr_el1=0x266318; source_line=12 source_column=3 frame_grant_publication_detail=4"
        );
        let zone = zone();
        let capture = ArmEntryBindingFatal::capture(
            registers,
            &crate::TrapFrame::default(),
            binding(),
            &zone,
            crate::SlotId::new(0),
        );
        assert_eq!(
            format!("{}", ArmEl1FatalReport::Entry(&capture)),
            format!("{capture}")
        );
    }

    #[test]
    fn entry_binding_fatal_capture_keeps_two_slot_identities_and_saved_registers() {
        let zone = zone();
        let slot = crate::SlotId::new(0);
        let peer = crate::SlotId::new(1);
        let identity = crate::ThreadIdentity {
            tid: 42,
            generation: 0,
            serial: 103,
            mm: 9,
            ..crate::ThreadIdentity::default()
        };
        let record = zone.current_or_new(slot, identity).unwrap();
        let peer_record = zone
            .current_or_new(
                peer,
                crate::ThreadIdentity {
                    tid: 99,
                    serial: 201,
                    mm: 10,
                    ..identity
                },
            )
            .unwrap();
        let mut frame = crate::TrapFrame::default();
        frame.x[..4].copy_from_slice(&[0x10, 0x11, 0x12, 0x13]);
        frame.x[30] = 0x1234;
        frame.elr = 0x266318;
        let registers = ArmEntryFatalRegisters {
            pc: Some(0xdead),
            lr: Some(0xbeef),
            sp_el0: Some(0x5678),
            ..Default::default()
        };
        let capture = ArmEntryBindingFatal::capture(registers, &frame, binding(), &zone, slot);
        let observed = capture.record.unwrap();
        assert_eq!(observed.id, record);
        assert_ne!(observed.id, peer_record);
        assert_eq!(observed.source, ArmEntryRecordSource::Host);
        assert_eq!(observed.identity, identity);
        assert_eq!(observed.claim, crate::Claim::Free);
        assert_eq!(observed.incarnation, zone.record(record).incarnation());
        assert_eq!(observed.incarnation_after, observed.incarnation);
        assert_eq!(capture.loaded, binding());
        assert_eq!(capture.saved_lr, 0x1234);
        assert_eq!(capture.saved_x, [0x10, 0x11, 0x12, 0x13]);
        let text = format!("{capture}");
        for field in [
            "pc=0xdead",
            "lr=0xbeef",
            "sp_el0=0x5678",
            "saved_lr=0x1234",
            "saved_elr=0x266318",
            "task=0x2a",
            "generation=0x0",
            "birth=0x67",
            "custody=Free",
        ] {
            assert!(text.contains(field), "missing {field}: {text}");
        }
        // Diagnostic observation neither acquires nor edits custody.
        assert_eq!(zone.record(record).identity(), identity);
        assert_eq!(zone.record(record).claim(), crate::Claim::Free);
        zone.drive(slot, 1);
        zone.publish_slot(slot, identity.mm, Some(0), 0b11);
        assert!(zone.occupancy.replace(
            carrick_sched_core::ExecutionSlot::zone(slot),
            0,
            identity.mm
        ));
        zone.requeue_preempted(slot, record);
        assert_eq!(zone.switch_in(slot), Some(record));
        let current = ArmEntryBindingFatal::capture(registers, &frame, binding(), &zone, slot);
        let observed = current.record.unwrap();
        assert_eq!(observed.source, ArmEntryRecordSource::Current);
        assert!(matches!(observed.claim, crate::Claim::OnCpu { slot: owner, .. } if owner == slot));
    }

    #[test]
    fn entry_binding_fatal_absence_and_register_read_failures_are_explicit() {
        let capture = ArmEntryBindingFatal::capture(
            ArmEntryFatalRegisters::default(),
            &crate::TrapFrame::default(),
            binding(),
            &zone(),
            crate::SlotId::new(0),
        );
        let text = format!("{capture}");
        assert!(capture.record.is_none());
        assert!(text.contains("record=none"));
        assert!(text.contains("esr_el1=unavailable"));
        assert!(text.contains("far_el1=unavailable"));
        assert!(text.contains("elr_el1=unavailable"));
        assert!(text.contains("spsr_el1=unavailable"));
        assert!(!is_entry_binding_fatal(crate::PANIC_SENTINEL, 0));
        assert!(!is_entry_binding_fatal(0, ENTRY_BINDING_FATAL_TAG));
        assert!(is_entry_binding_fatal(
            crate::PANIC_SENTINEL,
            ENTRY_BINDING_FATAL_TAG
        ));
    }

    #[test]
    fn entry_binding_fatal_maximum_width_fits_the_terminal_record() {
        let zone = zone();
        let slot = crate::SlotId::new(255);
        zone.current_or_new(
            slot,
            crate::ThreadIdentity {
                tid: u64::MAX,
                generation: u64::MAX,
                serial: u64::MAX,
                mm: u64::MAX,
                ..crate::ThreadIdentity::default()
            },
        )
        .unwrap();
        let mut frame = crate::TrapFrame {
            x: [u64::MAX; 31],
            elr: u64::MAX,
            spsr: u64::MAX,
            esr: u64::MAX,
            slot: u64::MAX,
            far: u64::MAX,
        };
        let registers = ArmEntryFatalRegisters {
            reason: Some(u64::MAX),
            source_location: Some(u64::MAX),
            pc: Some(u64::MAX),
            lr: Some(u64::MAX),
            fp: Some(u64::MAX),
            sp_el0: Some(u64::MAX),
            sp_el1: Some(u64::MAX),
            esr_el1: Some(u64::MAX),
            far_el1: Some(u64::MAX),
            elr_el1: Some(u64::MAX),
            spsr_el1: Some(u64::MAX),
        };
        let mut capture = ArmEntryBindingFatal::capture(
            registers,
            &frame,
            crate::ExecutionBinding {
                task: crate::EntryTaskKey::from_raw(u64::MAX),
                generation: crate::SnapshotGeneration::from_raw(u64::MAX),
                mm: crate::EntryMmKey::from_raw(u64::MAX),
                thread_generation: crate::EntryThreadGeneration::from_raw(u64::MAX),
            },
            &zone,
            slot,
        );
        let observed = capture.record.as_mut().unwrap();
        observed.incarnation = u64::MAX;
        observed.incarnation_after = u64::MAX;
        observed.id =
            crate::RecordId::from_raw(carrick_sched_core::ZONE_RECORDS as u32 - 1).unwrap();
        observed.source = ArmEntryRecordSource::Current;
        // Bound every custody variant with maximum-width fields, including
        // an unknown transport reason. Compact flags have equal width.
        for claim in [
            crate::Claim::Free,
            crate::Claim::Parked { seq: u32::MAX },
            crate::Claim::Host { seq: u32::MAX },
            crate::Claim::Queued {
                slot,
                seq: u32::MAX,
            },
            crate::Claim::OnCpu {
                slot,
                seq: u32::MAX,
            },
            crate::Claim::Activating {
                incarnation: u64::MAX,
            },
            crate::Claim::Retiring {
                incarnation: u64::MAX,
            },
            crate::Claim::FirstEntryHost {
                incarnation: u64::MAX,
            },
            crate::Claim::OnCpuRequested {
                slot,
                seq: u32::MAX,
            },
            crate::Claim::Transferring {
                seq: u32::MAX,
                cancelled: false,
                host_requested: false,
            },
            crate::Claim::Placing {
                incarnation: u64::MAX,
                host_requested: false,
            },
        ] {
            let observed = capture.record.as_mut().unwrap();
            observed.claim = claim;
            observed.claim_after = claim;
            let text = format!("{capture}");
            assert!(
                text.len() <= 1024,
                "fatal sink truncates {} bytes: {text}",
                text.len()
            );
        }
        // Distinguish saved entry state from the architectural exception state.
        frame.x[0] = 0;
        assert_eq!(frame.x[0], 0);
        assert_eq!(capture.saved_x[0], u64::MAX);
    }
}
