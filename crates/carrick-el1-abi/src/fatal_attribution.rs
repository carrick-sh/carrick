//! Exact-check attribution for EL1 entry-binding fatals (#1100).
//!
//! The terminal `HVC #3` transport carries the fatal reason in x2 and the
//! caller's source coordinates in x3. Several fatals collapse many refusing
//! checks into one reason (`Stale` alone has ~25 sources in native process
//! admission), so x4..x12 carry a typed [`FatalAttribution`]: which check
//! refused, what it refused with, and the custody state it observed.
//!
//! Diagnostic observation only. Nothing here grants custody, retries or
//! changes a refusal: every field is copied from state the refusing code
//! already read, or read once more on the fatal path.
use crate::{Claim, Handback};
use core::fmt;

/// Number of words [`FatalAttribution`] occupies in the fatal transport.
pub const FATAL_ATTRIBUTION_WORDS: usize = 9;

/// The exact refusing check of a native process entry admission
/// (`with_process_entry` and the registry authenticators it runs).
/// Prefixes name the owner: `Record*` the home record, `Observed*` the
/// loaded binding against that record, `Group*`/`Fresh*` the process
/// lookup, `Rehome*`/`Register*` the registry member, `Issue*` the
/// first-execution issuer, `Auth*` `authenticate_registered`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum AdmissionCheck {
    /// The slot's refusal record did not name this refusal's error.
    Unrecorded = 0,
    RecordRoot = 1,
    RecordMm = 2,
    RecordRootGeneration = 3,
    RecordAllocate = 4,
    ObservedAddressContext = 10,
    /// Generation 0 and `admit_born_in_zone` refused: the record is not
    /// an unadopted birth held `OnCpu` on this slot with this identity.
    ObservedBornAdmission = 11,
    ObservedTid = 12,
    ObservedGeneration = 13,
    ObservedSerial = 14,
    ObservedMm = 15,
    ObservedInstalledSpace = 16,
    ObservedAddressMm = 17,
    ObservedRoot = 18,
    GroupVisiblePid = 20,
    GroupAddress = 21,
    FreshRoot = 22,
    RegisterRoot = 23,
    RehomeHostIdentity = 30,
    RehomeKey = 31,
    RehomeVisiblePid = 32,
    RehomeRecord = 33,
    /// `prepare_handoff` refused: the record's claim or identity no
    /// longer names this slot's execution.
    RehomeHandoff = 34,
    RehomeGroup = 35,
    RehomeTask = 36,
    RehomeResources = 37,
    /// The member's execution identity differs from the loaded binding.
    RehomeMemberIdentity = 38,
    RehomeProcessKeys = 39,
    RehomeThreadGeneration = 40,
    RehomeSignalRecordBusy = 41,
    RehomeKeyBusy = 42,
    RehomeMember = 43,
    RehomeAdoptedReceipt = 44,
    RehomeProcessKeysLost = 45,
    RehomeTaskLost = 46,
    RegisterKey = 50,
    RegisterVisiblePid = 51,
    RegisterMetadata = 52,
    RegisterRecord = 53,
    RegisterHandoff = 54,
    RegisterZoneRecord = 55,
    RegisterBornRecord = 56,
    RegisterBornIdentity = 57,
    RegisterBornMismatch = 58,
    RegisterHostThread = 59,
    RegisterGate = 60,
    RegisterGroup = 61,
    RegisterBusy = 62,
    RegisterProcessKeys = 63,
    RegisterHostIdentity = 64,
    RegisterTask = 65,
    RegisterAuthorizeGroup = 66,
    RegisterReleaseAdopted = 67,
    RegisterPage = 68,
    RegisterImported = 69,
    RegisterSpawnThread = 70,
    RegisterMember = 71,
    RegisterRetainControl = 72,
    RegisterPendingCustody = 73,
    RegisterTail = 74,
    AuthZone = 80,
    AuthKey = 81,
    IssueNotBorn = 82,
    IssueRecord = 83,
    IssueMember = 84,
    IssueMemberMismatch = 85,
    IssueTask = 86,
    IssueGraphMember = 87,
    /// `issue_native_first_execution` refused: not an unadopted native
    /// birth held exactly `OnCpu` on this slot.
    IssueClaim = 88,
    IssueRekey = 89,
    AuthMember = 90,
    AuthRuntime = 91,
    AuthRecord = 92,
    AuthHandoff = 93,
    AuthTask = 94,
    AuthResources = 95,
    AuthMemberControl = 96,
    AuthControlSlot = 97,
    AuthLeaderRecord = 98,
    AuthVisibleTid = 99,
    AuthCredentials = 100,
    EnterControlCustody = 101,
    ImportSignals = 110,
}

impl AdmissionCheck {
    pub const fn from_raw(raw: u16) -> Option<Self> {
        match raw {
            0 => Some(Self::Unrecorded),
            1 => Some(Self::RecordRoot),
            2 => Some(Self::RecordMm),
            3 => Some(Self::RecordRootGeneration),
            4 => Some(Self::RecordAllocate),
            10 => Some(Self::ObservedAddressContext),
            11 => Some(Self::ObservedBornAdmission),
            12 => Some(Self::ObservedTid),
            13 => Some(Self::ObservedGeneration),
            14 => Some(Self::ObservedSerial),
            15 => Some(Self::ObservedMm),
            16 => Some(Self::ObservedInstalledSpace),
            17 => Some(Self::ObservedAddressMm),
            18 => Some(Self::ObservedRoot),
            20 => Some(Self::GroupVisiblePid),
            21 => Some(Self::GroupAddress),
            22 => Some(Self::FreshRoot),
            23 => Some(Self::RegisterRoot),
            30 => Some(Self::RehomeHostIdentity),
            31 => Some(Self::RehomeKey),
            32 => Some(Self::RehomeVisiblePid),
            33 => Some(Self::RehomeRecord),
            34 => Some(Self::RehomeHandoff),
            35 => Some(Self::RehomeGroup),
            36 => Some(Self::RehomeTask),
            37 => Some(Self::RehomeResources),
            38 => Some(Self::RehomeMemberIdentity),
            39 => Some(Self::RehomeProcessKeys),
            40 => Some(Self::RehomeThreadGeneration),
            41 => Some(Self::RehomeSignalRecordBusy),
            42 => Some(Self::RehomeKeyBusy),
            43 => Some(Self::RehomeMember),
            44 => Some(Self::RehomeAdoptedReceipt),
            45 => Some(Self::RehomeProcessKeysLost),
            46 => Some(Self::RehomeTaskLost),
            50 => Some(Self::RegisterKey),
            51 => Some(Self::RegisterVisiblePid),
            52 => Some(Self::RegisterMetadata),
            53 => Some(Self::RegisterRecord),
            54 => Some(Self::RegisterHandoff),
            55 => Some(Self::RegisterZoneRecord),
            56 => Some(Self::RegisterBornRecord),
            57 => Some(Self::RegisterBornIdentity),
            58 => Some(Self::RegisterBornMismatch),
            59 => Some(Self::RegisterHostThread),
            60 => Some(Self::RegisterGate),
            61 => Some(Self::RegisterGroup),
            62 => Some(Self::RegisterBusy),
            63 => Some(Self::RegisterProcessKeys),
            64 => Some(Self::RegisterHostIdentity),
            65 => Some(Self::RegisterTask),
            66 => Some(Self::RegisterAuthorizeGroup),
            67 => Some(Self::RegisterReleaseAdopted),
            68 => Some(Self::RegisterPage),
            69 => Some(Self::RegisterImported),
            70 => Some(Self::RegisterSpawnThread),
            71 => Some(Self::RegisterMember),
            72 => Some(Self::RegisterRetainControl),
            73 => Some(Self::RegisterPendingCustody),
            74 => Some(Self::RegisterTail),
            80 => Some(Self::AuthZone),
            81 => Some(Self::AuthKey),
            82 => Some(Self::IssueNotBorn),
            83 => Some(Self::IssueRecord),
            84 => Some(Self::IssueMember),
            85 => Some(Self::IssueMemberMismatch),
            86 => Some(Self::IssueTask),
            87 => Some(Self::IssueGraphMember),
            88 => Some(Self::IssueClaim),
            89 => Some(Self::IssueRekey),
            90 => Some(Self::AuthMember),
            91 => Some(Self::AuthRuntime),
            92 => Some(Self::AuthRecord),
            93 => Some(Self::AuthHandoff),
            94 => Some(Self::AuthTask),
            95 => Some(Self::AuthResources),
            96 => Some(Self::AuthMemberControl),
            97 => Some(Self::AuthControlSlot),
            98 => Some(Self::AuthLeaderRecord),
            99 => Some(Self::AuthVisibleTid),
            100 => Some(Self::AuthCredentials),
            101 => Some(Self::EnterControlCustody),
            110 => Some(Self::ImportSignals),
            _ => None,
        }
    }
}

/// `NativeProcessError`, without payloads, as the refusal reported it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum AdmissionError {
    Invalid = 1,
    Stale = 2,
    Exhausted = 3,
    Fault = 4,
    OwnerWait = 5,
    ForkRefused = 6,
    Unsupported = 7,
    GroupExitCustody = 8,
    Busy = 9,
    Quarantined = 10,
    NoChild = 11,
}

impl AdmissionError {
    pub const fn from_raw(raw: u8) -> Option<Self> {
        match raw {
            1 => Some(Self::Invalid),
            2 => Some(Self::Stale),
            3 => Some(Self::Exhausted),
            4 => Some(Self::Fault),
            5 => Some(Self::OwnerWait),
            6 => Some(Self::ForkRefused),
            7 => Some(Self::Unsupported),
            8 => Some(Self::GroupExitCustody),
            9 => Some(Self::Busy),
            10 => Some(Self::Quarantined),
            11 => Some(Self::NoChild),
            _ => None,
        }
    }
}

/// The registry member for the loaded task id, read on the fatal path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum MemberIdentity {
    /// The registry lock was held elsewhere; not observed.
    Unobserved = 0,
    Absent = 1,
    /// `NativeThreadIdentity::Born`: generation not yet issued.
    Born = 2,
    /// `NativeThreadIdentity::Issued`.
    Issued = 3,
}

impl MemberIdentity {
    pub const fn from_raw(raw: u8) -> Option<Self> {
        match raw {
            0 => Some(Self::Unobserved),
            1 => Some(Self::Absent),
            2 => Some(Self::Born),
            3 => Some(Self::Issued),
            _ => None,
        }
    }
}

/// Which registry route `admit_entry_runtime` took before the refusal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum AdmissionPath {
    /// Refused before a route was chosen (record or observed address).
    Unrouted = 0,
    /// An existing member keyed by the loaded binding (`for_entry`).
    ForEntry = 1,
    /// An existing member re-keyed to this record (`rehome_entry`).
    Rehome = 2,
    /// A new member of a published group (`register_thread`).
    Register = 3,
    /// A fresh root process (`admit_fresh_root`).
    FreshRoot = 4,
}

impl AdmissionPath {
    pub const fn from_raw(raw: u8) -> Option<Self> {
        match raw {
            0 => Some(Self::Unrouted),
            1 => Some(Self::ForEntry),
            2 => Some(Self::Rehome),
            3 => Some(Self::Register),
            4 => Some(Self::FreshRoot),
            _ => None,
        }
    }
}

/// One address context's identity words: MM id, root incarnation, root.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AddressWords {
    pub mm: u32,
    pub generation: u32,
    pub root: u64,
}

impl AddressWords {
    const fn pack(this: Option<Self>) -> [u64; 2] {
        match this {
            Some(words) => [
                ((words.mm as u64) << 32) | words.generation as u64,
                words.root,
            ],
            None => [0, 0],
        }
    }
    fn unpack(present: bool, words: [u64; 2]) -> Option<Self> {
        present.then_some(Self {
            mm: (words[0] >> 32) as u32,
            generation: words[0] as u32,
            root: words[1],
        })
    }
}

impl fmt::Display for AddressWords {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}/{:#x}", self.mm, self.generation, self.root)
    }
}

struct OptionalAddress(Option<AddressWords>);
impl fmt::Display for OptionalAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Some(words) => words.fmt(f),
            None => f.write_str("none"),
        }
    }
}

/// Exact attribution of a refused native process admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdmissionAttribution {
    pub check: AdmissionCheck,
    pub error: AdmissionError,
    pub member: MemberIdentity,
    /// The generation the issued member is keyed under (0 when not issued).
    pub member_generation: u32,
    /// The loaded binding's generation (0 = unissued birth).
    pub binding_generation: u32,
    /// The slot's current (else host) record.
    pub record: Option<u16>,
    /// The record claim the refusing check itself read, when it read one;
    /// otherwise the claim read on the fatal path, before the host's own
    /// later read (`custody=` in the record).
    pub claim: Option<Claim>,
    /// Whether [`Self::claim`] is the refusing check's own read.
    pub claim_from_check: bool,
    /// Why a claimant requested this record (`OnCpu` -> `OnCpuRequested`).
    pub requested: Option<Handback>,
    pub cancelled: bool,
    pub unadopted_birth: bool,
    pub native_owner: bool,
    pub path: AdmissionPath,
    /// The address the record's parked context names (`mm/gen/root`).
    pub context: Option<AddressWords>,
    /// The thread group's registered address, when the route looked it up.
    pub group: Option<AddressWords>,
    /// `CurrentTask::root_generation()` on the fatal path.
    pub root_generation: Option<u32>,
    /// The live TTBR0 root address on the fatal path (0: not read).
    pub live_root: u64,
}

/// The EL1 side of `retire_mm`: which step refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum RetireStep {
    TerminalPhase = 1,
    MmMismatch = 2,
    SpaceMissing = 3,
    RetireRecord = 4,
    /// The host answered the `HVC #6` child-retire crossing with a
    /// refusal; [`RetireAttribution::host`] names its arm.
    CrossingRefused = 5,
    /// The crossing succeeded but the wire record held no reply for
    /// this execution.
    ReplyMissing = 6,
    ReplyStale = 7,
    ReplyInvalid = 8,
    LiveRoot = 9,
    IdleRoot = 10,
    ReservationMm = 11,
}

impl RetireStep {
    pub const fn from_raw(raw: u16) -> Option<Self> {
        match raw {
            1 => Some(Self::TerminalPhase),
            2 => Some(Self::MmMismatch),
            3 => Some(Self::SpaceMissing),
            4 => Some(Self::RetireRecord),
            5 => Some(Self::CrossingRefused),
            6 => Some(Self::ReplyMissing),
            7 => Some(Self::ReplyStale),
            8 => Some(Self::ReplyInvalid),
            9 => Some(Self::LiveRoot),
            10 => Some(Self::IdleRoot),
            11 => Some(Self::ReservationMm),
            _ => None,
        }
    }
}

/// The host `service_terminal_operation` arm that answered `DENIED`
/// (or `INVALID`) to a pending child retirement. Returned in x1 of
/// the reply; the status word in x0 is unchanged.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum TerminalRetireDenial {
    NoLiveVm = 1,
    CpuMismatch = 2,
    TerminalBinding = 3,
    AbiRegion = 4,
    StoppedRecords = 5,
    BadReservationMm = 6,
    MmQuarantined = 7,
    NoChildRoot = 8,
    NoRootGeneration = 9,
    RootMismatch = 10,
    RecordPointer = 11,
    StoppedZone = 12,
    NoWakeChannel = 13,
    SpaceIndex = 14,
    EditorStale = 15,
    /// Another editor holds the MM; detail = its active-editor word.
    EditorBusy = 16,
    CowSettle = 17,
    ExecPredecessor = 18,
    RetireChild = 19,
    ZoneTables = 20,
    Slot = 21,
    AcceptTerminal = 22,
}

impl TerminalRetireDenial {
    pub const fn from_raw(raw: u16) -> Option<Self> {
        match raw {
            1 => Some(Self::NoLiveVm),
            2 => Some(Self::CpuMismatch),
            3 => Some(Self::TerminalBinding),
            4 => Some(Self::AbiRegion),
            5 => Some(Self::StoppedRecords),
            6 => Some(Self::BadReservationMm),
            7 => Some(Self::MmQuarantined),
            8 => Some(Self::NoChildRoot),
            9 => Some(Self::NoRootGeneration),
            10 => Some(Self::RootMismatch),
            11 => Some(Self::RecordPointer),
            12 => Some(Self::StoppedZone),
            13 => Some(Self::NoWakeChannel),
            14 => Some(Self::SpaceIndex),
            15 => Some(Self::EditorStale),
            16 => Some(Self::EditorBusy),
            17 => Some(Self::CowSettle),
            18 => Some(Self::ExecPredecessor),
            19 => Some(Self::RetireChild),
            20 => Some(Self::ZoneTables),
            21 => Some(Self::Slot),
            22 => Some(Self::AcceptTerminal),
            _ => None,
        }
    }
}

/// The host's typed child-retire refusal, carried back in the reply.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TerminalRetireRefusal {
    pub arm: Option<TerminalRetireDenial>,
    pub detail: u64,
}

impl TerminalRetireRefusal {
    pub const fn new(arm: TerminalRetireDenial, detail: u64) -> Self {
        Self {
            arm: Some(arm),
            detail,
        }
    }
    /// The reply's x1/x2 words; x0 keeps the DENIED/INVALID status.
    pub const fn words(self) -> [u64; 2] {
        [
            match self.arm {
                Some(arm) => arm as u64,
                None => 0,
            },
            self.detail,
        ]
    }
    pub const fn from_words(words: [u64; 2]) -> Self {
        Self {
            arm: TerminalRetireDenial::from_raw(words[0] as u16),
            detail: words[1],
        }
    }
}

/// How the closing owner's `cancel_members` claims answered, per
/// `HostClaim` arm, for the close that preceded this retirement. The arms
/// are only counted; the claims are unchanged (#1100). Counts saturate at
/// 1023.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CancelTally {
    pub claimed: u16,
    pub el1_held: u16,
    pub deferred: u16,
    pub already_host: u16,
    pub stale: u16,
    /// Members whose record was no longer live, so no claim was made.
    pub not_live: u16,
}

impl CancelTally {
    const MAX: u16 = 0x3ff;
    pub fn bump(count: &mut u16) {
        *count = (*count + 1).min(Self::MAX);
    }
    pub const fn pack(self) -> u64 {
        (self.claimed as u64 & 0x3ff)
            | ((self.el1_held as u64 & 0x3ff) << 10)
            | ((self.deferred as u64 & 0x3ff) << 20)
            | ((self.already_host as u64 & 0x3ff) << 30)
            | ((self.stale as u64 & 0x3ff) << 40)
            | ((self.not_live as u64 & 0x3ff) << 50)
    }
    pub const fn unpack(word: u64) -> Self {
        Self {
            claimed: (word & 0x3ff) as u16,
            el1_held: ((word >> 10) & 0x3ff) as u16,
            deferred: ((word >> 20) & 0x3ff) as u16,
            already_host: ((word >> 30) & 0x3ff) as u16,
            stale: ((word >> 40) & 0x3ff) as u16,
            not_live: ((word >> 50) & 0x3ff) as u16,
        }
    }
}

/// Exact attribution of a refused child address-space retirement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetireAttribution {
    pub step: RetireStep,
    pub host: Option<TerminalRetireRefusal>,
    pub mm: u64,
    pub binding_generation: u32,
    pub slot: u8,
    /// The preceding `cancel_members` tally on this slot, if recorded.
    pub cancel: Option<CancelTally>,
}

/// The typed extra words of an entry-binding fatal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FatalAttribution {
    None,
    Admission(AdmissionAttribution),
    Retire(RetireAttribution),
    StaleRoot(StaleRootAttribution),
    /// A tag this host does not know; raw words stay visible.
    Unknown([u64; FATAL_ATTRIBUTION_WORDS]),
}

const TAG_ADMISSION: u64 = 1;
const TAG_RETIRE: u64 = 2;
const TAG_STALE_ROOT: u64 = 3;
const FLAG_CLAIM_AT_CHECK: u64 = 1;
const FLAG_CANCELLED: u64 = 2;
const FLAG_UNADOPTED: u64 = 4;
const FLAG_NATIVE_OWNER: u64 = 8;
const FLAG_RECORD: u64 = 16;
const FLAG_HOST_REPLY: u64 = 32;
const FLAG_CLAIM: u64 = 64;
const ADDR_CONTEXT: u64 = 1;
const ADDR_GROUP: u64 = 2;
const ADDR_ROOT_GENERATION: u64 = 4;

impl FatalAttribution {
    pub const fn encode(self) -> [u64; FATAL_ATTRIBUTION_WORDS] {
        match self {
            Self::None => [0; FATAL_ATTRIBUTION_WORDS],
            Self::Unknown(words) => words,
            Self::Admission(a) => {
                let flags = (if a.claim_from_check {
                    FLAG_CLAIM_AT_CHECK
                } else {
                    0
                }) | (if a.claim.is_some() { FLAG_CLAIM } else { 0 })
                    | (if a.cancelled { FLAG_CANCELLED } else { 0 })
                    | (if a.unadopted_birth { FLAG_UNADOPTED } else { 0 })
                    | (if a.native_owner { FLAG_NATIVE_OWNER } else { 0 })
                    | (if a.record.is_some() { FLAG_RECORD } else { 0 });
                let requested = match a.requested {
                    Some(kind) => kind as u64,
                    None => 0,
                };
                let record = match a.record {
                    Some(record) => record as u64,
                    None => 0,
                };
                [
                    (TAG_ADMISSION << 56)
                        | ((a.check as u64) << 32)
                        | ((a.error as u64) << 24)
                        | ((a.member as u64) << 16)
                        | (flags << 8)
                        | requested,
                    (record << 48)
                        | ((a.member_generation as u64 & 0xff_ffff) << 24)
                        | (a.binding_generation as u64 & 0xff_ffff),
                    match a.claim {
                        Some(claim) => claim.encode(),
                        None => 0,
                    },
                    ((match a.root_generation {
                        Some(generation) => generation as u64,
                        None => 0,
                    }) << 32)
                        | ((a.path as u64) << 8)
                        | (if a.context.is_some() { ADDR_CONTEXT } else { 0 })
                        | (if a.group.is_some() { ADDR_GROUP } else { 0 })
                        | (if a.root_generation.is_some() {
                            ADDR_ROOT_GENERATION
                        } else {
                            0
                        }),
                    AddressWords::pack(a.context)[0],
                    AddressWords::pack(a.context)[1],
                    AddressWords::pack(a.group)[0],
                    AddressWords::pack(a.group)[1],
                    a.live_root,
                ]
            }
            Self::Retire(r) => {
                let (flags, host) = match r.host {
                    Some(host) => (FLAG_HOST_REPLY, host.words()),
                    None => (0, [0, 0]),
                };
                [
                    (TAG_RETIRE << 56)
                        | ((r.step as u64) << 32)
                        | (flags << 24)
                        | ((r.slot as u64) << 16)
                        | (host[0] & 0xffff),
                    host[1],
                    r.mm,
                    r.binding_generation as u64,
                    match r.cancel {
                        Some(tally) => tally.pack() | (1 << 63),
                        None => 0,
                    },
                    0,
                    0,
                    0,
                    0,
                ]
            }
            Self::StaleRoot(r) => [
                (TAG_STALE_ROOT << 56) | ((r.slot as u64) << 48) | (r.space & 0xffff_ffff),
                r.live_ttbr0,
                r.expected_ttbr0,
                r.idle_ttbr0,
                r.last_idle_exit.0,
                r.recent[0].0,
                r.recent[1].0,
                r.recent[2].0,
                0,
            ],
        }
    }

    pub fn decode(words: [u64; FATAL_ATTRIBUTION_WORDS]) -> Self {
        let w0 = words[0];
        let unknown = Self::Unknown(words);
        match w0 >> 56 {
            0 if words == [0; FATAL_ATTRIBUTION_WORDS] => Self::None,
            TAG_ADMISSION => {
                let flags = (w0 >> 8) & 0xff;
                let address = words[3] & 0xff;
                let (Some(check), Some(error), Some(member), Some(path)) = (
                    AdmissionCheck::from_raw((w0 >> 32) as u16),
                    AdmissionError::from_raw((w0 >> 24) as u8),
                    MemberIdentity::from_raw((w0 >> 16) as u8),
                    AdmissionPath::from_raw((words[3] >> 8) as u8),
                ) else {
                    return unknown;
                };
                Self::Admission(AdmissionAttribution {
                    check,
                    error,
                    member,
                    member_generation: ((words[1] >> 24) & 0xff_ffff) as u32,
                    binding_generation: (words[1] & 0xff_ffff) as u32,
                    record: (flags & FLAG_RECORD != 0).then_some((words[1] >> 48) as u16),
                    claim: (flags & FLAG_CLAIM != 0).then(|| Claim::decode(words[2])),
                    claim_from_check: flags & FLAG_CLAIM_AT_CHECK != 0,
                    requested: Handback::from_raw((w0 & 0xff) as u32),
                    cancelled: flags & FLAG_CANCELLED != 0,
                    unadopted_birth: flags & FLAG_UNADOPTED != 0,
                    native_owner: flags & FLAG_NATIVE_OWNER != 0,
                    path,
                    context: AddressWords::unpack(
                        address & ADDR_CONTEXT != 0,
                        [words[4], words[5]],
                    ),
                    group: AddressWords::unpack(address & ADDR_GROUP != 0, [words[6], words[7]]),
                    root_generation: (address & ADDR_ROOT_GENERATION != 0)
                        .then_some((words[3] >> 32) as u32),
                    live_root: words[8],
                })
            }
            TAG_RETIRE => {
                let Some(step) = RetireStep::from_raw((w0 >> 32) as u16) else {
                    return unknown;
                };
                Self::Retire(RetireAttribution {
                    step,
                    host: ((w0 >> 24) & FLAG_HOST_REPLY != 0)
                        .then(|| TerminalRetireRefusal::from_words([w0 & 0xffff, words[1]])),
                    mm: words[2],
                    binding_generation: words[3] as u32,
                    slot: (w0 >> 16) as u8,
                    cancel: (words[4] >> 63 != 0).then(|| CancelTally::unpack(words[4])),
                })
            }
            TAG_STALE_ROOT => Self::StaleRoot(StaleRootAttribution {
                slot: (w0 >> 48) as u8,
                space: w0 & 0xffff_ffff,
                live_ttbr0: words[1],
                expected_ttbr0: words[2],
                idle_ttbr0: words[3],
                last_idle_exit: SlotEvent(words[4]),
                recent: [
                    SlotEvent(words[5]),
                    SlotEvent(words[6]),
                    SlotEvent(words[7]),
                ],
            }),
            _ => unknown,
        }
    }
}

impl fmt::Display for FatalAttribution {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => Ok(()),
            Self::Unknown(words) => write!(
                f,
                " attribution=unknown({:#x},{:#x},{:#x},{:#x},{:#x},{:#x},{:#x},{:#x},{:#x})",
                words[0],
                words[1],
                words[2],
                words[3],
                words[4],
                words[5],
                words[6],
                words[7],
                words[8]
            ),
            Self::Admission(a) => {
                write!(
                    f,
                    " check={:?} err={:?} member={:?}/{} bind_gen={} rec=",
                    a.check, a.error, a.member, a.member_generation, a.binding_generation
                )?;
                match a.record {
                    Some(record) => write!(f, "{record}")?,
                    None => f.write_str("none")?,
                }
                f.write_str(if a.claim_from_check {
                    " claim@check="
                } else {
                    " claim@fatal="
                })?;
                match a.claim {
                    Some(claim) => {
                        write!(f, "{}", crate::entry_binding_fatal::CompactClaim(claim))?
                    }
                    None => f.write_str("none")?,
                }
                f.write_str(" requested=")?;
                match a.requested {
                    Some(kind) => write!(f, "{kind:?}")?,
                    None => f.write_str("none")?,
                }
                write!(
                    f,
                    " cancel={} unadopt={} native={} path={:?} ctx={} grp={} ttbr={:#x} root_gen=",
                    u8::from(a.cancelled),
                    u8::from(a.unadopted_birth),
                    u8::from(a.native_owner),
                    a.path,
                    OptionalAddress(a.context),
                    OptionalAddress(a.group),
                    a.live_root,
                )?;
                match a.root_generation {
                    Some(generation) => write!(f, "{generation}"),
                    None => f.write_str("none"),
                }
            }
            Self::Retire(r) => {
                write!(
                    f,
                    " retire_step={:?} slot={} mm={:#x} bind_gen={} host=",
                    r.step, r.slot, r.mm, r.binding_generation
                )?;
                match r.host {
                    Some(host) => write!(f, "{:?} host_detail={:#x}", host.arm, host.detail)?,
                    None => f.write_str("none")?,
                }
                match r.cancel {
                    Some(t) => write!(
                        f,
                        " cancel=claimed:{}/held:{}/deferred:{}/host:{}/stale:{}/dead:{}",
                        t.claimed, t.el1_held, t.deferred, t.already_host, t.stale, t.not_live
                    ),
                    None => f.write_str(" cancel=unrecorded"),
                }
            }
            Self::StaleRoot(r) => write!(
                f,
                // The slot is the header's `cpu=`; the sink is 1024 bytes.
                " stale_root mm={} live={:#x} expected={:#x} idle={:#x} last={} \
                 trace=[{},{},{}]",
                r.space,
                r.live_ttbr0,
                r.expected_ttbr0,
                r.idle_ttbr0,
                r.last_idle_exit,
                r.recent[0],
                r.recent[1],
                r.recent[2]
            ),
        }
    }
}

/// The scheduler or dispatch arm that ended an EL1 entry with
/// `Action::Idle` (the `hvc #5` exit), recorded in the slot's trace (#1100
/// occupancy). Values are transport ABI.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum IdleProducer {
    /// No producer named itself on this entry.
    Unattributed = 0,
    /// `Sched::idle` saw host work (or an excluding affinity) while polling.
    IdleHostWork = 1,
    /// `Sched::idle` switched a thread in whose space could not install.
    IdleLoadNeedsHost = 2,
    /// `Sched::idle`: the run-queue head needs its executor.
    IdleHeadNeedsHost = 3,
    /// `run_ready` switched a thread in whose space could not install.
    RunReadyLoadNeedsHost = 4,
    /// `run_ready`: the run-queue head needs its executor.
    RunReadyHeadNeedsHost = 5,
    /// `enforce_affinity` parked the current thread off this CPU.
    EnforceAffinity = 6,
    /// `yield_queued` handed off and nothing loaded.
    YieldQueued = 7,
    /// IRQ slice end: the running thread parked, the head needs the host.
    InterruptParkPreempted = 8,
    /// IRQ slice end: the preempt's head could not install its space.
    InterruptPreemptFailed = 9,
    /// The host's idle entry found host work before polling.
    IdleEntryHostWork = 10,
    /// `leave_after_object_park`: host work after an object park.
    ObjectParkHostWork = 11,
    /// `native_service_idle`: the native service park (leaves the space).
    NativeServiceIdle = 12,
}

impl IdleProducer {
    pub const fn from_raw(raw: u8) -> Self {
        match raw {
            1 => Self::IdleHostWork,
            2 => Self::IdleLoadNeedsHost,
            3 => Self::IdleHeadNeedsHost,
            4 => Self::RunReadyLoadNeedsHost,
            5 => Self::RunReadyHeadNeedsHost,
            6 => Self::EnforceAffinity,
            7 => Self::YieldQueued,
            8 => Self::InterruptParkPreempted,
            9 => Self::InterruptPreemptFailed,
            10 => Self::IdleEntryHostWork,
            11 => Self::ObjectParkHostWork,
            12 => Self::NativeServiceIdle,
            _ => Self::Unattributed,
        }
    }
}

/// The dispatch route that turned a completion into `Action::Idle`, when
/// it was not the scheduler alone. Values are transport ABI (4 bits).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum IdleRoute {
    None = 0,
    /// `resolve_arm_process_route`: `CompletionRoute::Suspended`.
    CompletionSuspended = 1,
    /// `arm_signal_user_return`: `CompletionRoute::Suspended`.
    UserReturnSuspended = 2,
    /// Reserved (the generic process-call route; not recorded on ARM).
    ProcessRouteSuspended = 3,
    /// Declined-fault signal delivery: `CompletionRoute::Suspended`.
    DeclinedFaultSuspended = 4,
    /// The COW resolver's object park.
    CowObjectPark = 5,
}

impl IdleRoute {
    pub const fn from_raw(raw: u8) -> Self {
        match raw {
            1 => Self::CompletionSuspended,
            2 => Self::UserReturnSuspended,
            3 => Self::ProcessRouteSuspended,
            4 => Self::DeclinedFaultSuspended,
            5 => Self::CowObjectPark,
            _ => Self::None,
        }
    }
}

/// What one slot-trace event records (4 bits).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum SlotEventKind {
    Empty = 0,
    /// EL1 left for the host with `Action::Idle`.
    IdleExit = 1,
    /// The host started this vCPU's idle entry.
    IdleEntry = 2,
    /// Switch-in found the word already naming the space (no install).
    SwitchInKept = 3,
    /// Switch-in installed the space's roots.
    SwitchInInstalled = 4,
    /// `leave_space` moved the vCPU to the maintenance root.
    Left = 5,
}

impl SlotEventKind {
    pub const fn from_raw(raw: u8) -> Self {
        match raw {
            1 => Self::IdleExit,
            2 => Self::IdleEntry,
            3 => Self::SwitchInKept,
            4 => Self::SwitchInInstalled,
            5 => Self::Left,
            _ => Self::Empty,
        }
    }
}

/// One packed slot-trace event: what happened, the occupancy word's space
/// and the live TTBR0 at that moment. Diagnostics only (#1100).
///
/// Layout: kind 63..60, producer 59..52, route 51..48, `idle_root` 47,
/// space (low 15 bits) 46..32, live TTBR0 page number (`BADDR >> 12`,
/// low 32 bits) 31..0.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SlotEvent(pub u64);

impl SlotEvent {
    pub const EMPTY: Self = Self(0);

    /// `live_root` is the TTBR0 value; `idle_root` whether it was the
    /// maintenance root.
    pub const fn new(
        kind: SlotEventKind,
        producer: IdleProducer,
        route: IdleRoute,
        space: u64,
        live_root: u64,
        idle_root: bool,
    ) -> Self {
        Self(
            ((kind as u64 & 0xf) << 60)
                | ((producer as u64 & 0xff) << 52)
                | ((route as u64 & 0xf) << 48)
                | (if idle_root { 1 << 47 } else { 0 })
                | ((space & 0x7fff) << 32)
                | ((ttbr_baddr(live_root) >> 12) & 0xffff_ffff),
        )
    }
    pub const fn kind(self) -> SlotEventKind {
        SlotEventKind::from_raw((self.0 >> 60) as u8)
    }
    pub const fn producer(self) -> IdleProducer {
        IdleProducer::from_raw((self.0 >> 52) as u8)
    }
    pub const fn route(self) -> IdleRoute {
        IdleRoute::from_raw(((self.0 >> 48) & 0xf) as u8)
    }
    pub const fn idle_root(self) -> bool {
        self.0 & (1 << 47) != 0
    }
    pub const fn space(self) -> u64 {
        (self.0 >> 32) & 0x7fff
    }
    /// The live TTBR0's table address, page-aligned.
    pub const fn root_page(self) -> u64 {
        (self.0 & 0xffff_ffff) << 12
    }
}

/// The translation-table base address of a TTBR value: the ASID (63..48)
/// and CnP (bit 0) do not name a different table.
pub const fn ttbr_baddr(ttbr: u64) -> u64 {
    ttbr & 0x0000_ffff_ffff_fffe
}

/// Compact (the fatal sink is 1024 bytes): `exit:<producer>[/<route>]`,
/// `entry`, `kept`, `inst` or `left`, then `:mm<space>:` and the live root
/// page, or `idle` when it was the maintenance root.
impl fmt::Display for SlotEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind() {
            SlotEventKind::Empty => return f.write_str("-"),
            SlotEventKind::IdleExit => {
                write!(f, "exit:{:?}", self.producer())?;
                if !matches!(self.route(), IdleRoute::None) {
                    write!(f, "/{:?}", self.route())?;
                }
            }
            SlotEventKind::IdleEntry => f.write_str("entry")?,
            SlotEventKind::SwitchInKept => f.write_str("kept")?,
            SlotEventKind::SwitchInInstalled => f.write_str("inst")?,
            SlotEventKind::Left => f.write_str("left")?,
        }
        write!(f, ":mm{}:", self.space())?;
        if self.idle_root() {
            f.write_str("idle")
        } else {
            write!(f, "{:#x}", self.root_page())
        }
    }
}

/// A switch-in trusted the slot's occupancy word, which named the thread's
/// address space, while the vCPU's live TTBR0 was another table (#1100).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StaleRootAttribution {
    pub slot: u8,
    /// The space the occupancy word named (and the thread's); low 32 bits.
    pub space: u64,
    pub live_ttbr0: u64,
    /// The space's published TTBR0.
    pub expected_ttbr0: u64,
    /// The carrier's maintenance root, as EL1 reads it.
    pub idle_ttbr0: u64,
    /// The slot's most recent `IdleExit`, if still in its trace.
    pub last_idle_exit: SlotEvent,
    /// The slot's last trace events, oldest first.
    pub recent: [SlotEvent; 3],
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SlotId;

    #[test]
    fn admission_attribution_round_trips_every_field() {
        let attribution = FatalAttribution::Admission(AdmissionAttribution {
            check: AdmissionCheck::ObservedBornAdmission,
            error: AdmissionError::Stale,
            member: MemberIdentity::Born,
            member_generation: 0,
            binding_generation: 0,
            record: Some(3),
            claim: Some(Claim::OnCpuRequested {
                slot: SlotId::new(1),
                seq: 7,
            }),
            claim_from_check: true,
            requested: Some(Handback::Cancelled),
            cancelled: true,
            unadopted_birth: true,
            native_owner: true,
            path: AdmissionPath::Rehome,
            context: Some(AddressWords {
                mm: 2,
                generation: 1,
                root: 0x8000,
            }),
            group: None,
            root_generation: Some(1),
            live_root: 0x9000,
        });
        assert_eq!(FatalAttribution::decode(attribution.encode()), attribution);
        let text = alloc_free_render(&attribution);
        assert!(text.contains("check=ObservedBornAdmission err=Stale member=Born/0"));
        assert!(text.contains("claim@check=OnCpuRequested{slot:1,seq:7}"));
        assert!(text.contains("requested=Cancelled cancel=1 unadopt=1 native=1"));
        assert!(text.contains("path=Rehome ctx=2/1/0x8000 grp=none ttbr=0x9000 root_gen=1"));
    }

    #[test]
    fn retire_attribution_carries_the_host_arm_and_its_detail() {
        let attribution = FatalAttribution::Retire(RetireAttribution {
            step: RetireStep::CrossingRefused,
            host: Some(TerminalRetireRefusal::new(
                TerminalRetireDenial::EditorBusy,
                0x42,
            )),
            mm: 2,
            binding_generation: 1,
            slot: 3,
            cancel: Some(CancelTally {
                el1_held: 2,
                not_live: 1,
                ..CancelTally::default()
            }),
        });
        assert_eq!(FatalAttribution::decode(attribution.encode()), attribution);
        assert!(alloc_free_render(&attribution).contains(
            "retire_step=CrossingRefused slot=3 mm=0x2 bind_gen=1 host=Some(EditorBusy) host_detail=0x42 cancel=claimed:0/held:2/deferred:0/host:0/stale:0/dead:1"
        ));
        assert_eq!(
            FatalAttribution::decode([0; FATAL_ATTRIBUTION_WORDS]),
            FatalAttribution::None
        );
        assert!(matches!(
            FatalAttribution::decode([9 << 56, 0, 0, 0, 0, 0, 0, 0, 0]),
            FatalAttribution::Unknown(_)
        ));
    }

    #[test]
    fn stale_root_attribution_names_the_idle_producer_and_the_trace() {
        let idle = 0x2d_0010_0000;
        let attribution = FatalAttribution::StaleRoot(StaleRootAttribution {
            slot: 3,
            space: 2,
            live_ttbr0: idle,
            expected_ttbr0: (5 << 48) | 0x9a_0020_0000,
            idle_ttbr0: idle,
            last_idle_exit: SlotEvent::new(
                SlotEventKind::IdleExit,
                IdleProducer::IdleHeadNeedsHost,
                IdleRoute::CompletionSuspended,
                2,
                (5 << 48) | 0x9a_0020_0000,
                false,
            ),
            recent: [
                SlotEvent::new(
                    SlotEventKind::IdleExit,
                    IdleProducer::IdleHeadNeedsHost,
                    IdleRoute::CompletionSuspended,
                    2,
                    (5 << 48) | 0x9a_0020_0000,
                    false,
                ),
                SlotEvent::new(
                    SlotEventKind::IdleEntry,
                    IdleProducer::Unattributed,
                    IdleRoute::None,
                    2,
                    idle,
                    true,
                ),
                SlotEvent::new(
                    SlotEventKind::SwitchInKept,
                    IdleProducer::Unattributed,
                    IdleRoute::None,
                    2,
                    idle,
                    true,
                ),
            ],
        });
        assert_eq!(FatalAttribution::decode(attribution.encode()), attribution);
        let text = alloc_free_render(&attribution);
        assert!(text.contains(
            "stale_root mm=2 live=0x2d00100000 expected=0x5009a00200000 \
             idle=0x2d00100000 last=exit:IdleHeadNeedsHost/CompletionSuspended:mm2:0x9a00200000"
        ));
        assert!(text.contains(
            "trace=[exit:IdleHeadNeedsHost/CompletionSuspended:mm2:0x9a00200000,\
             entry:mm2:idle,kept:mm2:idle]"
        ));
    }

    /// A fixed buffer, as the carrier's no-alloc fatal sink.
    fn alloc_free_render(attribution: &FatalAttribution) -> heapless_text::Text {
        use core::fmt::Write;
        let mut text = heapless_text::Text::default();
        write!(text, "{attribution}").unwrap();
        text
    }

    mod heapless_text {
        pub struct Text {
            bytes: [u8; 512],
            len: usize,
        }
        impl Default for Text {
            fn default() -> Self {
                Self {
                    bytes: [0; 512],
                    len: 0,
                }
            }
        }
        impl Text {
            pub fn contains(&self, needle: &str) -> bool {
                core::str::from_utf8(&self.bytes[..self.len])
                    .unwrap()
                    .contains(needle)
            }
        }
        impl core::fmt::Write for Text {
            fn write_str(&mut self, s: &str) -> core::fmt::Result {
                let end = self.len + s.len();
                self.bytes
                    .get_mut(self.len..end)
                    .ok_or(core::fmt::Error)?
                    .copy_from_slice(s.as_bytes());
                self.len = end;
                Ok(())
            }
        }
    }
}
