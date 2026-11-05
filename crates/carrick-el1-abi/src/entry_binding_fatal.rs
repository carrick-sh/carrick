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
    NativeServiceInvalid = 28,
    NativeServiceStale = 29,
    NativeServiceExhausted = 30,
    NativeServiceFault = 31,
    NativeServiceOwnerWait = 32,
    NativeServiceUnsupported = 33,
    NativeServiceGroupExit = 34,
    NativeServiceBusy = 35,
    NativeServiceQuarantined = 36,
    NativeServiceNoChild = 37,
    NativeServiceCapStale = 38,
    NativeServicePayloadStale = 39,
    NativeServiceMemberStale = 40,
    NativeServiceBirthStale = 41,
    NativeServiceMmStale = 42,
    NativeServiceBindStale = 43,
    NativeServicePublishStale = 44,
    NativeServiceNoticeStale = 45,
    NativeServiceParkStale = 46,
    NativeServiceSettleStale = 47,
    NativeServiceCompleteStale = 48,
    /// A switch-in found the slot's occupancy word naming the thread's
    /// address space while the live TTBR0 named another table (#1100: an
    /// exit to the host left the word behind and the host rewrote the
    /// root). Numbered to match the #1100 diagnostics stack, which defines
    /// 49..=59.
    SwitchInStaleRoot = 60,
    /// A vCPU's own running or newly allocated record was not queued: its
    /// claim was neither this slot's `OnCpu*` nor `Free` (#1100). Leaving it
    /// on no run queue would strand the thread.
    RequeueRefused = 61,
    /// Rolling back an unexposed physical inventory failed (#1642: once
    /// folded into `PhysicalCustody` with every native run failure).
    InventoryRollbackFailed = 62,
    /// An authenticated native run failure; the origin word names which.
    NativeRunFailure = 63,
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
            28 => Some(Self::NativeServiceInvalid),
            29 => Some(Self::NativeServiceStale),
            30 => Some(Self::NativeServiceExhausted),
            31 => Some(Self::NativeServiceFault),
            32 => Some(Self::NativeServiceOwnerWait),
            33 => Some(Self::NativeServiceUnsupported),
            34 => Some(Self::NativeServiceGroupExit),
            35 => Some(Self::NativeServiceBusy),
            36 => Some(Self::NativeServiceQuarantined),
            37 => Some(Self::NativeServiceNoChild),
            38 => Some(Self::NativeServiceCapStale),
            39 => Some(Self::NativeServicePayloadStale),
            40 => Some(Self::NativeServiceMemberStale),
            41 => Some(Self::NativeServiceBirthStale),
            42 => Some(Self::NativeServiceMmStale),
            43 => Some(Self::NativeServiceBindStale),
            44 => Some(Self::NativeServicePublishStale),
            45 => Some(Self::NativeServiceNoticeStale),
            46 => Some(Self::NativeServiceParkStale),
            47 => Some(Self::NativeServiceSettleStale),
            48 => Some(Self::NativeServiceCompleteStale),
            60 => Some(Self::SwitchInStaleRoot),
            61 => Some(Self::RequeueRefused),
            62 => Some(Self::InventoryRollbackFailed),
            63 => Some(Self::NativeRunFailure),
            _ => None,
        }
    }
}

/// Which `NativeInvariant` variant raised the fatal (origin word bits 0..8).
/// `Substrate` is a scheduler or ISA fatal raised without one, so one shared
/// reason code (`EntryBinding`) still says which layer refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum EntryBindingFatalOrigin {
    Substrate = 0,
    EntryBinding = 1,
    NativeService = 2,
    PhysicalCustody = 3,
    MissingNativeFrame = 4,
    RevisionCredit = 5,
    SignalNumber = 6,
    ProcessGraph = 7,
}
impl EntryBindingFatalOrigin {
    pub const fn from_raw(raw: u8) -> Option<Self> {
        match raw {
            0 => Some(Self::Substrate),
            1 => Some(Self::EntryBinding),
            2 => Some(Self::NativeService),
            3 => Some(Self::PhysicalCustody),
            4 => Some(Self::MissingNativeFrame),
            5 => Some(Self::RevisionCredit),
            6 => Some(Self::SignalNumber),
            7 => Some(Self::ProcessGraph),
            _ => None,
        }
    }
}

/// What failed: the transport reason, the raising variant and, for an
/// authenticated native run failure, its exact reason (origin bits 8..16).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EntryBindingFatalCause {
    pub reason: EntryBindingFatalReason,
    pub origin: EntryBindingFatalOrigin,
    pub run_failure: Option<carrick_core_abi::NativeRunFailureReason>,
}
impl EntryBindingFatalCause {
    /// A scheduler or ISA refusal that no `NativeInvariant` carried.
    pub const fn substrate(reason: EntryBindingFatalReason) -> Self {
        Self::invariant(EntryBindingFatalOrigin::Substrate, reason)
    }
    pub const fn invariant(
        origin: EntryBindingFatalOrigin,
        reason: EntryBindingFatalReason,
    ) -> Self {
        Self {
            reason,
            origin,
            run_failure: None,
        }
    }
    pub const fn native_run_failure(reason: carrick_core_abi::NativeRunFailureReason) -> Self {
        Self {
            reason: EntryBindingFatalReason::NativeRunFailure,
            origin: EntryBindingFatalOrigin::PhysicalCustody,
            run_failure: Some(reason),
        }
    }
    const fn origin_word(self) -> u64 {
        let run = match self.run_failure {
            Some(reason) => reason as u64,
            None => 0,
        };
        (self.origin as u64) | (run << 8)
    }
}

/// Bytes of `Location::file()` the transport keeps: a header byte, then up
/// to 63 trailing path bytes, so `crates/<crate>/src/<file>.rs` survives.
pub const FATAL_SOURCE_FILE_WORDS: usize = 8;
const FATAL_SOURCE_FILE_BYTES: usize = FATAL_SOURCE_FILE_WORDS * 8 - 1;
const FATAL_SOURCE_FILE_TRUNCATED: u8 = 0x80;

/// The caller's source file, carried by value in eight registers: the EL1
/// image's string pointer is meaningless to the host. Byte 0 holds the kept
/// length and a truncation flag; bytes 1.. the path's last bytes.
#[derive(Clone, Copy, Default, Eq, PartialEq)]
pub struct FatalSourceFile {
    words: [u64; FATAL_SOURCE_FILE_WORDS],
}
impl FatalSourceFile {
    pub fn from_path(path: &str) -> Self {
        let bytes = path.as_bytes();
        let kept = bytes.len().min(FATAL_SOURCE_FILE_BYTES);
        let mut header = kept as u8;
        if bytes.len() > kept {
            header |= FATAL_SOURCE_FILE_TRUNCATED;
        }
        let tail = bytes.get(bytes.len() - kept..).unwrap_or_default();
        let mut words = [0u64; FATAL_SOURCE_FILE_WORDS];
        for (index, byte) in core::iter::once(&header).chain(tail).enumerate() {
            if let Some(word) = words.get_mut(index / 8) {
                *word |= u64::from(*byte) << (8 * (index % 8));
            }
        }
        Self { words }
    }
    pub const fn from_words(words: [u64; FATAL_SOURCE_FILE_WORDS]) -> Self {
        Self { words }
    }
    pub const fn words(self) -> [u64; FATAL_SOURCE_FILE_WORDS] {
        self.words
    }
    fn byte(&self, index: usize) -> u8 {
        self.words
            .get(index / 8)
            .map_or(0, |word| (word >> (8 * (index % 8))) as u8)
    }
}
/// Printable ASCII only: a corrupt register must not inject a line break
/// into the single fatal line. Other bytes render as `?`.
impl fmt::Display for FatalSourceFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let header = self.byte(0);
        let kept = usize::from(header & !FATAL_SOURCE_FILE_TRUNCATED).min(FATAL_SOURCE_FILE_BYTES);
        if kept == 0 {
            return f.write_str("unknown");
        }
        if header & FATAL_SOURCE_FILE_TRUNCATED != 0 {
            f.write_str("...")?;
        }
        for index in 1..=kept {
            let byte = self.byte(index);
            let shown = if byte.is_ascii_graphic() { byte } else { b'?' };
            fmt::Write::write_char(f, char::from(shown))?;
        }
        Ok(())
    }
}
impl fmt::Debug for FatalSourceFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "\"{self}\"")
    }
}

/// Register payload of one fatal: reason in x2, the caller's line and column
/// in x3, origin in x4 and the caller's file in x5..x12. No pointers or
/// aggregate stack records cross this diagnostic boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EntryBindingFatalWords {
    pub reason: u64,
    pub location: u64,
    pub origin: u64,
    pub file: FatalSourceFile,
}

/// A fatal's cause and call site. Two call sites never print the same line.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EntryBindingFatalDetail {
    pub cause: EntryBindingFatalCause,
    pub line: u32,
    pub column: u32,
    pub file: FatalSourceFile,
}
impl EntryBindingFatalDetail {
    #[track_caller]
    pub fn at_caller(cause: EntryBindingFatalCause) -> Self {
        let caller = core::panic::Location::caller();
        Self {
            cause,
            line: caller.line(),
            column: caller.column(),
            file: FatalSourceFile::from_path(caller.file()),
        }
    }
    pub const fn encode(self) -> EntryBindingFatalWords {
        EntryBindingFatalWords {
            reason: self.cause.reason as u64,
            location: ((self.line as u64) << 32) | self.column as u64,
            origin: self.cause.origin_word(),
            file: self.file,
        }
    }
    pub const fn decode(words: EntryBindingFatalWords) -> Option<Self> {
        let Some(reason) = EntryBindingFatalReason::from_raw(words.reason) else {
            return None;
        };
        let Some(origin) = EntryBindingFatalOrigin::from_raw(words.origin as u8) else {
            return None;
        };
        if words.origin >> 16 != 0 {
            return None;
        }
        let run_failure = match (words.origin >> 8) as u8 {
            0 => None,
            raw => match carrick_core_abi::NativeRunFailureReason::from_raw(raw as u64) {
                Some(reason) => Some(reason),
                None => return None,
            },
        };
        Some(Self {
            cause: EntryBindingFatalCause {
                reason,
                origin,
                run_failure,
            },
            line: (words.location >> 32) as u32,
            column: words.location as u32,
            file: words.file,
        })
    }
}
/// The one renderer for both the EL1 register payload and the hosted
/// `invalid_completion` line, so both name the same fields.
impl fmt::Display for EntryBindingFatalDetail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let words = self.encode();
        FatalDetail {
            reason: Some(words.reason),
            origin: Some(words.origin),
            location: Some(words.location),
            file: Some(words.file),
        }
        .fmt(f)
    }
}
struct FatalDetail {
    reason: Option<u64>,
    origin: Option<u64>,
    location: Option<u64>,
    file: Option<FatalSourceFile>,
}
impl FatalDetail {
    fn of(registers: &ArmEntryFatalRegisters) -> Self {
        Self {
            reason: registers.reason,
            origin: registers.origin,
            location: registers.source_location,
            file: registers.source_file,
        }
    }
}
impl fmt::Display for FatalDetail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.reason {
            Some(raw) => match EntryBindingFatalReason::from_raw(raw) {
                Some(reason) => write!(f, "reason={reason:?} ")?,
                None => write!(f, "reason=unknown({raw:#x}) ")?,
            },
            None => f.write_str("reason=unavailable ")?,
        }
        match self.origin {
            Some(raw) => {
                match EntryBindingFatalOrigin::from_raw(raw as u8) {
                    Some(EntryBindingFatalOrigin::Substrate) => f.write_str("invariant=none")?,
                    Some(origin) => write!(f, "invariant={origin:?}")?,
                    None => write!(f, "invariant=unknown({:#x})", raw as u8)?,
                }
                match (raw >> 8) as u8 {
                    0 => {}
                    run => match carrick_core_abi::NativeRunFailureReason::from_raw(run as u64) {
                        Some(reason) => write!(f, "({reason:?})")?,
                        None => write!(f, "(unknown({run:#x}))")?,
                    },
                }
                f.write_str(" ")?;
            }
            None => f.write_str("invariant=unavailable ")?,
        }
        f.write_str("at=")?;
        match self.file {
            Some(file) => write!(f, "{file}:")?,
            None => f.write_str("unavailable:")?,
        }
        match self.location {
            Some(location) => write!(f, "{}:{}", location >> 32, location as u32),
            None => f.write_str("unavailable"),
        }
    }
}

/// Live registers at the terminal HVC, distinct from the saved EL0 frame.
/// None means the VMM could not read the register, never an invented zero.
#[derive(Clone, Copy, Debug, Default)]
pub struct ArmEntryFatalRegisters {
    pub reason: Option<u64>,
    pub source_location: Option<u64>,
    pub origin: Option<u64>,
    pub source_file: Option<FatalSourceFile>,
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
                FatalDetail::of(registers)
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
// Keep every custody field in the fixed 1536-byte sink
// (`carrick_fatal::MAX_MESSAGE_LEN`). Flags are 0/1;
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
        // Cause and call site lead: they name the refusing site (#1642),
        // and a clipped paste of the line still carries them.
        write!(
            f,
            "entry_binding {} cpu={} pc={} lr={} fp={} sp_el1={} esr_el1={} far_el1={} elr_el1={} spsr_el1={} sp_el0={} ",
            FatalDetail::of(r),
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

    const ORIGINS: [EntryBindingFatalOrigin; 8] = [
        EntryBindingFatalOrigin::Substrate,
        EntryBindingFatalOrigin::EntryBinding,
        EntryBindingFatalOrigin::NativeService,
        EntryBindingFatalOrigin::PhysicalCustody,
        EntryBindingFatalOrigin::MissingNativeFrame,
        EntryBindingFatalOrigin::RevisionCredit,
        EntryBindingFatalOrigin::SignalNumber,
        EntryBindingFatalOrigin::ProcessGraph,
    ];

    #[test]
    fn fatal_detail_round_trip_and_formatter() {
        let path = "crates/carrick-el1-linux/src/aarch64_process.rs";
        for raw in (1..=48).chain(60..=63) {
            let reason = EntryBindingFatalReason::from_raw(raw).unwrap();
            for origin in ORIGINS {
                for (line, column) in [(0, 0), (1646, 9), (u32::MAX, u32::MAX)] {
                    let detail = EntryBindingFatalDetail {
                        cause: EntryBindingFatalCause::invariant(origin, reason),
                        line,
                        column,
                        file: FatalSourceFile::from_path(path),
                    };
                    assert_eq!(
                        EntryBindingFatalDetail::decode(detail.encode()),
                        Some(detail)
                    );
                }
            }
        }
        for raw in 1..=12 {
            let run = carrick_core_abi::NativeRunFailureReason::from_raw(raw).unwrap();
            let detail = EntryBindingFatalDetail {
                cause: EntryBindingFatalCause::native_run_failure(run),
                line: 716,
                column: 13,
                file: FatalSourceFile::from_path(path),
            };
            assert_eq!(
                EntryBindingFatalDetail::decode(detail.encode()),
                Some(detail)
            );
        }
        let words = |reason, origin| EntryBindingFatalWords {
            reason,
            location: 0,
            origin,
            file: FatalSourceFile::default(),
        };
        assert_eq!(EntryBindingFatalDetail::decode(words(0, 0)), None);
        assert_eq!(EntryBindingFatalDetail::decode(words(u64::MAX, 0)), None);
        assert_eq!(EntryBindingFatalDetail::decode(words(1, 8)), None);
        assert_eq!(EntryBindingFatalDetail::decode(words(1, 99 << 8)), None);
        assert_eq!(EntryBindingFatalDetail::decode(words(1, 1 << 16)), None);
        let file = Some(FatalSourceFile::from_path("src/dispatch.rs"));
        assert_eq!(
            format!(
                "{}",
                FatalDetail {
                    reason: Some(3),
                    origin: Some(4),
                    location: Some((1646 << 32) | 9),
                    file,
                }
            ),
            "reason=MissingNativeFrame invariant=MissingNativeFrame at=src/dispatch.rs:1646:9"
        );
        assert_eq!(
            format!(
                "{}",
                FatalDetail {
                    reason: Some(63),
                    origin: Some(3 | (12 << 8)),
                    location: Some(0),
                    file,
                }
            ),
            "reason=NativeRunFailure invariant=PhysicalCustody(BornEnqueueRefused) at=src/dispatch.rs:0:0"
        );
        assert_eq!(
            format!(
                "{}",
                FatalDetail {
                    reason: Some(99),
                    origin: Some(0x9900 | 0x42),
                    location: Some(0),
                    file: Some(FatalSourceFile::default()),
                }
            ),
            "reason=unknown(0x63) invariant=unknown(0x42)(unknown(0x99)) at=unknown:0:0"
        );
        assert_eq!(
            format!(
                "{}",
                FatalDetail {
                    reason: None,
                    origin: None,
                    location: None,
                    file: None,
                }
            ),
            "reason=unavailable invariant=unavailable at=unavailable:unavailable"
        );
        assert_eq!(
            format!(
                "{}",
                FatalDetail {
                    reason: Some(1),
                    origin: Some(0),
                    location: None,
                    file: None,
                }
            ),
            "reason=EntryBinding invariant=none at=unavailable:unavailable"
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
        let detail = EntryBindingFatalDetail::at_caller(EntryBindingFatalCause::substrate(
            EntryBindingFatalReason::EntryBinding,
        ));
        assert_eq!(detail.line, line);
        assert_eq!(
            format!("{}", detail.file),
            "crates/carrick-el1-abi/src/entry_binding_fatal.rs"
        );
        let words = detail.encode();
        let registers = ArmEntryFatalRegisters {
            reason: Some(3),
            source_location: Some((1646 << 32) | 9),
            origin: Some(4),
            source_file: Some(words.file),
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
            assert!(text.contains(
                "reason=MissingNativeFrame invariant=MissingNativeFrame \
                 at=crates/carrick-el1-abi/src/entry_binding_fatal.rs:1646:9"
            ));
        }
    }

    /// #1642: a shared reason code from two call sites used to print the
    /// same `entry_binding` line. The site now distinguishes them, both in
    /// file and in line, and the raising layer is named.
    #[test]
    fn two_call_sites_render_two_fatal_lines() {
        #[track_caller]
        fn raise(cause: EntryBindingFatalCause) -> std::string::String {
            format!("{}", EntryBindingFatalDetail::at_caller(cause))
        }
        let reason = EntryBindingFatalReason::EntryBinding;
        let first = raise(EntryBindingFatalCause::invariant(
            EntryBindingFatalOrigin::EntryBinding,
            reason,
        ));
        let second = raise(EntryBindingFatalCause::invariant(
            EntryBindingFatalOrigin::EntryBinding,
            reason,
        ));
        let substrate = raise(EntryBindingFatalCause::substrate(reason));
        assert_ne!(first, second);
        assert!(first.starts_with("reason=EntryBinding invariant=EntryBinding at="));
        assert!(substrate.starts_with("reason=EntryBinding invariant=none at="));
        let long = FatalSourceFile::from_path(
            "crates/a-very-long-crate-name-for-truncation/src/deeply/nested/module/file.rs",
        );
        let shown = format!("{long}");
        assert!(shown.starts_with("..."), "{shown}");
        assert!(shown.ends_with("/nested/module/file.rs"), "{shown}");
        assert_eq!(shown.len(), 3 + FATAL_SOURCE_FILE_BYTES);
        let mut corrupt = FatalSourceFile::from_path("a\nb").words();
        corrupt[0] |= 0x7f;
        assert!(!format!("{}", FatalSourceFile::from_words(corrupt)).contains('\n'));
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
        assert!(zone.requeue_preempted(slot, record).is_queued());
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
            origin: Some(u64::MAX),
            source_file: Some(FatalSourceFile::from_path(
                "crates/a-crate-name-longer-than-the-transport/src/deeply/nested/module/file.rs",
            )),
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
            for reason in (1..=48).chain([60, 63, u64::MAX]) {
                capture.registers.reason = Some(reason);
                let text = format!("{capture}");
                assert!(
                    text.len() <= 1536,
                    "fatal sink truncates {} bytes: {text}",
                    text.len()
                );
            }
        }
        // Distinguish saved entry state from the architectural exception state.
        frame.x[0] = 0;
        assert_eq!(frame.x[0], 0);
        assert_eq!(capture.saved_x[0], u64::MAX);
    }
}
