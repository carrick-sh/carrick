//! Complete, process-wide Hypervisor.framework VM lifecycle history.
//!
//! DTrace and the event ring are intentionally not authorities for this history:
//! both can drop or overwrite records. The production VM probe wrapper mirrors
//! every lifecycle transition into this typed ledger before firing its scalar
//! USDT. HVPatch qualification can therefore prove one logical VM creation and
//! matching teardown independently of tracer delivery.

use std::io::{Read as _, Write as _};
use std::num::NonZeroU64;
use std::path::Path;
use std::ptr;
use std::sync::atomic::{AtomicPtr, Ordering};
use std::sync::{Mutex, OnceLock};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

const MAX_RECORDED_EVENTS: usize = 64;
const MAX_RECORDED_VIOLATIONS: usize = 64;
pub const VM_LIFECYCLE_ARTIFACT_MAX_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum VmLifecycleOperation {
    LogicalCreateAttempt = 0,
    CreateSuccess = 1,
    DestroyAttempt = 2,
    DestroySuccess = 3,
}

impl VmLifecycleOperation {
    pub const fn from_raw(raw: u32) -> Option<Self> {
        match raw {
            0 => Some(Self::LogicalCreateAttempt),
            1 => Some(Self::CreateSuccess),
            2 => Some(Self::DestroyAttempt),
            3 => Some(Self::DestroySuccess),
            _ => None,
        }
    }

    pub const fn raw(self) -> u32 {
        self as u32
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct VmSerial(NonZeroU64);

impl VmSerial {
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct VmLifecycleSequence(NonZeroU64);

impl VmLifecycleSequence {
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VmLifecycleEvent {
    pub sequence: VmLifecycleSequence,
    pub operation: VmLifecycleOperation,
    pub serial: VmSerial,
    pub admission: Option<i32>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VmRunTerminalOutcome {
    Completed {
        exit_code: i32,
        traps: u64,
        trap_limit_hit: bool,
    },
    RuntimeError,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VmRunTerminal {
    pub sequence: VmLifecycleSequence,
    pub outcome: VmRunTerminalOutcome,
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum VmLifecycleViolation {
    #[error("unknown VM lifecycle operation {operation}")]
    UnknownOperation { operation: u32 },
    #[error("VM lifecycle serial space is exhausted")]
    SerialExhausted,
    #[error("VM lifecycle sequence space is exhausted")]
    SequenceExhausted,
    #[error("VM create attempted while serial {serial:?} is pending")]
    CreateWhilePending { serial: VmSerial },
    #[error("VM create attempted while serial {serial:?} is active")]
    CreateWhileActive { serial: VmSerial },
    #[error("VM create succeeded without a pending logical attempt")]
    CreateSuccessWithoutAttempt,
    #[error("VM create admission changed from {expected} to {observed}")]
    CreateAdmissionChanged { expected: i32, observed: i32 },
    #[error("VM destroy attempted without an active VM")]
    DestroyWithoutActiveVm,
    #[error("VM destroy was attempted twice for serial {serial:?}")]
    DuplicateDestroyAttempt { serial: VmSerial },
    #[error("VM destroy succeeded without a matching attempt")]
    DestroySuccessWithoutAttempt,
    #[error("process-wide VM run terminal was published twice")]
    DuplicateRunTerminal,
    #[error("VM lifecycle event capacity was exceeded")]
    EventCapacityExceeded,
    #[error("VM lifecycle violation capacity was exceeded")]
    ViolationCapacityExceeded,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VmLifecycleSnapshot {
    pub events: Vec<VmLifecycleEvent>,
    pub violations: Vec<VmLifecycleViolation>,
    pub pending_create: Option<VmSerial>,
    pub active: Option<VmSerial>,
    pub destroy_pending: bool,
    pub terminal: Option<VmRunTerminal>,
}

#[derive(Clone, Copy, Debug)]
struct PendingCreate {
    serial: VmSerial,
    admission: i32,
}

#[derive(Debug)]
struct VmLifecycleState {
    next_serial: u64,
    next_sequence: u64,
    pending_create: Option<PendingCreate>,
    active: Option<VmSerial>,
    destroy_pending: bool,
    events: Vec<VmLifecycleEvent>,
    terminal: Option<VmRunTerminal>,
    violations: Vec<VmLifecycleViolation>,
}

impl Default for VmLifecycleState {
    fn default() -> Self {
        Self {
            next_serial: 1,
            next_sequence: 1,
            pending_create: None,
            active: None,
            destroy_pending: false,
            events: Vec::new(),
            terminal: None,
            violations: Vec::new(),
        }
    }
}

impl VmLifecycleState {
    fn allocate_serial(&mut self) -> Option<VmSerial> {
        let serial = NonZeroU64::new(self.next_serial).map(VmSerial);
        self.next_serial = self.next_serial.checked_add(1).unwrap_or(0);
        serial
    }

    fn record_violation(&mut self, violation: VmLifecycleViolation) {
        if self.violations.len() < MAX_RECORDED_VIOLATIONS.saturating_sub(1) {
            self.violations.push(violation);
        } else if self.violations.len() < MAX_RECORDED_VIOLATIONS {
            self.violations
                .push(VmLifecycleViolation::ViolationCapacityExceeded);
        }
    }

    fn append(
        &mut self,
        operation: VmLifecycleOperation,
        serial: VmSerial,
        admission: Option<i32>,
    ) {
        if self.events.len() >= MAX_RECORDED_EVENTS {
            self.record_violation(VmLifecycleViolation::EventCapacityExceeded);
            return;
        }
        let Some(sequence) = NonZeroU64::new(self.next_sequence).map(VmLifecycleSequence) else {
            self.record_violation(VmLifecycleViolation::SequenceExhausted);
            return;
        };
        let Some(next) = self.next_sequence.checked_add(1) else {
            self.next_sequence = 0;
            self.record_violation(VmLifecycleViolation::SequenceExhausted);
            return;
        };
        self.next_sequence = next;
        self.events.push(VmLifecycleEvent {
            sequence,
            operation,
            serial,
            admission,
        });
    }

    fn apply_raw(&mut self, raw: u32, admission: i32) {
        let Some(operation) = VmLifecycleOperation::from_raw(raw) else {
            self.record_violation(VmLifecycleViolation::UnknownOperation { operation: raw });
            return;
        };
        match operation {
            VmLifecycleOperation::LogicalCreateAttempt => {
                if let Some(pending) = self.pending_create {
                    self.record_violation(VmLifecycleViolation::CreateWhilePending {
                        serial: pending.serial,
                    });
                    return;
                }
                if let Some(serial) = self.active {
                    self.record_violation(VmLifecycleViolation::CreateWhileActive { serial });
                    return;
                }
                let Some(serial) = self.allocate_serial() else {
                    self.record_violation(VmLifecycleViolation::SerialExhausted);
                    return;
                };
                self.pending_create = Some(PendingCreate { serial, admission });
                self.append(operation, serial, Some(admission));
            }
            VmLifecycleOperation::CreateSuccess => {
                let Some(pending) = self.pending_create.take() else {
                    self.record_violation(VmLifecycleViolation::CreateSuccessWithoutAttempt);
                    return;
                };
                if pending.admission != admission {
                    self.record_violation(VmLifecycleViolation::CreateAdmissionChanged {
                        expected: pending.admission,
                        observed: admission,
                    });
                }
                self.active = Some(pending.serial);
                self.append(operation, pending.serial, Some(admission));
            }
            VmLifecycleOperation::DestroyAttempt => {
                let Some(serial) = self.active else {
                    self.record_violation(VmLifecycleViolation::DestroyWithoutActiveVm);
                    return;
                };
                if self.destroy_pending {
                    self.record_violation(VmLifecycleViolation::DuplicateDestroyAttempt { serial });
                    return;
                }
                self.destroy_pending = true;
                self.append(operation, serial, None);
            }
            VmLifecycleOperation::DestroySuccess => {
                let Some(serial) = self.active else {
                    self.record_violation(VmLifecycleViolation::DestroySuccessWithoutAttempt);
                    return;
                };
                if !self.destroy_pending {
                    self.record_violation(VmLifecycleViolation::DestroySuccessWithoutAttempt);
                    return;
                }
                self.destroy_pending = false;
                self.active = None;
                self.append(operation, serial, None);
            }
        }
    }

    fn record_terminal(&mut self, outcome: VmRunTerminalOutcome) {
        if self.terminal.is_some() {
            self.record_violation(VmLifecycleViolation::DuplicateRunTerminal);
            return;
        }
        let Some(sequence) = NonZeroU64::new(self.next_sequence).map(VmLifecycleSequence) else {
            self.record_violation(VmLifecycleViolation::SequenceExhausted);
            return;
        };
        let Some(next) = self.next_sequence.checked_add(1) else {
            self.next_sequence = 0;
            self.record_violation(VmLifecycleViolation::SequenceExhausted);
            return;
        };
        self.next_sequence = next;
        self.terminal = Some(VmRunTerminal { sequence, outcome });
    }

    fn snapshot(&self) -> VmLifecycleSnapshot {
        VmLifecycleSnapshot {
            events: self.events.clone(),
            violations: self.violations.clone(),
            pending_create: self.pending_create.map(|pending| pending.serial),
            active: self.active,
            destroy_pending: self.destroy_pending,
            terminal: self.terminal,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum VmLifecycleValidationError {
    #[error("VM lifecycle ledger contains {count} transition violation(s)")]
    RecordedViolations { count: usize },
    #[error("VM lifecycle ledger is incomplete at process terminal")]
    IncompleteState,
    #[error("one-VM lifecycle requires 4 events, observed {observed}")]
    EventCount { observed: usize },
    #[error("VM lifecycle event {index} has {observed:?}, expected {expected:?}")]
    Operation {
        index: usize,
        expected: VmLifecycleOperation,
        observed: VmLifecycleOperation,
    },
    #[error("VM lifecycle changed serial at event {index}")]
    SerialMismatch { index: usize },
    #[error("VM lifecycle sequence is discontinuous at event {index}")]
    SequenceMismatch { index: usize },
    #[error("VM lifecycle has no process-wide run terminal")]
    MissingRunTerminal,
    #[error("VM lifecycle run terminal sequence is not immediately after teardown")]
    TerminalSequenceMismatch,
}

pub fn validate_completed_single_vm(
    snapshot: &VmLifecycleSnapshot,
) -> Result<VmSerial, VmLifecycleValidationError> {
    if !snapshot.violations.is_empty() {
        return Err(VmLifecycleValidationError::RecordedViolations {
            count: snapshot.violations.len(),
        });
    }
    if snapshot.pending_create.is_some() || snapshot.active.is_some() || snapshot.destroy_pending {
        return Err(VmLifecycleValidationError::IncompleteState);
    }
    let expected = [
        VmLifecycleOperation::LogicalCreateAttempt,
        VmLifecycleOperation::CreateSuccess,
        VmLifecycleOperation::DestroyAttempt,
        VmLifecycleOperation::DestroySuccess,
    ];
    if snapshot.events.len() != expected.len() {
        return Err(VmLifecycleValidationError::EventCount {
            observed: snapshot.events.len(),
        });
    }
    let serial = snapshot.events[0].serial;
    for (index, (event, expected_operation)) in snapshot.events.iter().zip(expected).enumerate() {
        if event.operation != expected_operation {
            return Err(VmLifecycleValidationError::Operation {
                index,
                expected: expected_operation,
                observed: event.operation,
            });
        }
        if event.serial != serial {
            return Err(VmLifecycleValidationError::SerialMismatch { index });
        }
        let expected_sequence = u64::try_from(index).unwrap_or(u64::MAX).saturating_add(1);
        if event.sequence.get() != expected_sequence {
            return Err(VmLifecycleValidationError::SequenceMismatch { index });
        }
    }
    let terminal = snapshot
        .terminal
        .ok_or(VmLifecycleValidationError::MissingRunTerminal)?;
    if terminal.sequence.get() != 5 {
        return Err(VmLifecycleValidationError::TerminalSequenceMismatch);
    }
    Ok(serial)
}

#[derive(Debug, Default)]
pub struct VmLifecycleLedger {
    state: Mutex<VmLifecycleState>,
}

impl VmLifecycleLedger {
    pub fn record_raw(&self, operation: u32, admission: i32) {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .apply_raw(operation, admission);
    }

    pub fn record_terminal(&self, outcome: VmRunTerminalOutcome) {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .record_terminal(outcome);
    }

    pub fn snapshot(&self) -> VmLifecycleSnapshot {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .snapshot()
    }
}

#[derive(Debug, Default)]
struct ProcessLedgerSlot {
    current: AtomicPtr<VmLifecycleLedger>,
}

impl ProcessLedgerSlot {
    fn get(&self) -> &'static VmLifecycleLedger {
        let mut current = self.current.load(Ordering::Acquire);
        if current.is_null() {
            let candidate = Box::into_raw(Box::new(VmLifecycleLedger::default()));
            match self.current.compare_exchange(
                ptr::null_mut(),
                candidate,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => current = candidate,
                Err(installed) => {
                    // SAFETY: this candidate was never published and remains
                    // uniquely owned by this initialization attempt.
                    drop(unsafe { Box::from_raw(candidate) });
                    current = installed;
                }
            }
        }
        // SAFETY: installed ledgers are intentionally process-lifetime objects.
        // A fork child replaces (but never frees) the inherited pointer before
        // it can publish new events, so outstanding references cannot dangle.
        unsafe { &*current }
    }

    fn reset_after_fork_child(&self) {
        let replacement = Box::into_raw(Box::new(VmLifecycleLedger::default()));
        // Do not lock or free the inherited ledger: another vanished host thread
        // may have owned its mutex at fork. The child has one surviving thread,
        // and leaking the inherited allocation in that new process is bounded.
        self.current.store(replacement, Ordering::Release);
    }
}

fn process_ledger_slot() -> &'static ProcessLedgerSlot {
    static SLOT: ProcessLedgerSlot = ProcessLedgerSlot {
        current: AtomicPtr::new(ptr::null_mut()),
    };
    &SLOT
}

fn process_ledger() -> &'static VmLifecycleLedger {
    process_ledger_slot().get()
}

pub fn record_raw(operation: u32, admission: i32) {
    process_ledger().record_raw(operation, admission);
}

pub fn record_process_terminal(outcome: VmRunTerminalOutcome) {
    process_ledger().record_terminal(outcome);
}

pub fn process_snapshot() -> VmLifecycleSnapshot {
    process_ledger().snapshot()
}

pub fn reset_after_fork_child() {
    process_ledger_slot().reset_after_fork_child();
}

pub const VM_LIFECYCLE_ARTIFACT_SCHEMA: &str = "carrick.hvpatch-vm-lifecycle.v1";
pub const VM_LIFECYCLE_ARTIFACT_PATH_ENV: &str = "CARRICK_HVPATCH_VM_LEDGER_PATH";
pub const VM_LIFECYCLE_SOURCE_SHA256_ENV: &str = "CARRICK_SOURCE_SHA256";
static PROCESS_COMMAND_SHA256: OnceLock<String> = OnceLock::new();
const VM_LIFECYCLE_SCHEMA_DESCRIPTOR: &[u8] = b"carrick.hvpatch-vm-lifecycle.v1\0schema_sha256\0program_sha256\0run_id_sha256\0source_sha256\0binary_sha256\0command_sha256\0events(sequence,operation,serial,admission)\0terminal(sequence,kind,exit_code,traps,trap_limit_hit)";
// The validator authenticates the exact currently bundled ledger program, the
// same pattern used by Carrick's bundled DTrace profiles. `include_bytes!` is
// raw inclusion, so including this source file does not recursively expand it.
const VM_LIFECYCLE_PROGRAM_SOURCE: &[u8] = include_bytes!("vm_lifecycle.rs");

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ArtifactEventV1 {
    sequence: u64,
    operation: u32,
    serial: u64,
    admission: Option<i32>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ArtifactTerminalV1 {
    sequence: u64,
    kind: String,
    exit_code: i32,
    traps: u64,
    trap_limit_hit: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ArtifactPayloadV1 {
    schema: String,
    schema_sha256: String,
    program_sha256: String,
    run_id_sha256: String,
    source_sha256: String,
    binary_sha256: String,
    command_sha256: String,
    events: Vec<ArtifactEventV1>,
    terminal: ArtifactTerminalV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ArtifactEnvelopeV1 {
    payload: ArtifactPayloadV1,
    payload_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VmLifecycleArtifactSummary {
    pub serial: VmSerial,
    pub terminal: VmRunTerminalOutcome,
    pub program_sha256: String,
    pub run_id_sha256: String,
    pub source_sha256: String,
    pub binary_sha256: String,
    pub command_sha256: String,
    pub payload_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VmLifecycleArtifactExpectations {
    pub run_id_sha256: String,
    pub source_sha256: String,
    pub binary_sha256: String,
    pub command_sha256: String,
}

impl VmLifecycleArtifactExpectations {
    pub fn new(
        run_id: &[u8],
        source_sha256: String,
        binary_sha256: String,
        command_sha256: String,
    ) -> Result<Self, VmLifecycleArtifactError> {
        for (field, value) in [
            ("source_sha256", source_sha256.as_str()),
            ("binary_sha256", binary_sha256.as_str()),
            ("command_sha256", command_sha256.as_str()),
        ] {
            if !valid_sha256(value) {
                return Err(VmLifecycleArtifactError::InvalidSha256 { field });
            }
        }
        Ok(Self {
            run_id_sha256: sha256_hex(run_id),
            source_sha256,
            binary_sha256,
            command_sha256,
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum VmLifecycleArtifactError {
    #[error(transparent)]
    Validation(#[from] VmLifecycleValidationError),
    #[error("CARRICK_RUN_ID is required for VM lifecycle evidence")]
    MissingRunId,
    #[error("CARRICK_SOURCE_SHA256 is required for VM lifecycle evidence")]
    MissingSourceSha256,
    #[error("top-level command identity was not installed before VM lifecycle publication")]
    MissingCommandSha256,
    #[error("top-level command identity was installed twice with different values")]
    ConflictingCommandSha256,
    #[error("VM lifecycle artifact is {observed} bytes; maximum is {maximum}")]
    ArtifactTooLarge { observed: usize, maximum: usize },
    #[error("VM lifecycle artifact is not canonical JSON plus one newline")]
    NonCanonicalArtifact,
    #[error("VM lifecycle artifact provenance mismatch for {field}")]
    ProvenanceMismatch { field: &'static str },
    #[error("VM lifecycle artifact parent directory is not private to this uid")]
    InsecureParentDirectory,
    #[error("VM lifecycle artifact JSON is invalid: {0}")]
    Json(#[from] serde_json::Error),
    #[error("VM lifecycle artifact field {field} is not lowercase SHA-256")]
    InvalidSha256 { field: &'static str },
    #[error("VM lifecycle artifact schema mismatch")]
    SchemaMismatch,
    #[error("VM lifecycle artifact event {index} has unknown operation {operation}")]
    UnknownOperation { index: usize, operation: u32 },
    #[error("VM lifecycle artifact payload digest mismatch")]
    PayloadDigestMismatch,
    #[error("VM lifecycle artifact I/O failed during {operation}: {source}")]
    Io {
        operation: &'static str,
        #[source]
        source: std::io::Error,
    },
}

pub fn sha256_bytes(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

fn sha256_hex(bytes: &[u8]) -> String {
    sha256_bytes(bytes)
}

pub fn install_process_command_sha256(
    command_sha256: String,
) -> Result<(), VmLifecycleArtifactError> {
    if !valid_sha256(&command_sha256) {
        return Err(VmLifecycleArtifactError::InvalidSha256 {
            field: "command_sha256",
        });
    }
    if let Some(installed) = PROCESS_COMMAND_SHA256.get() {
        return if installed == &command_sha256 {
            Ok(())
        } else {
            Err(VmLifecycleArtifactError::ConflictingCommandSha256)
        };
    }
    PROCESS_COMMAND_SHA256
        .set(command_sha256)
        .map_err(|_| VmLifecycleArtifactError::ConflictingCommandSha256)
}

pub fn sha256_file(path: &Path) -> Result<String, VmLifecycleArtifactError> {
    let mut file = std::fs::File::open(path).map_err(|source| VmLifecycleArtifactError::Io {
        operation: "open file for hashing",
        source,
    })?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|source| VmLifecycleArtifactError::Io {
                operation: "read file for hashing",
                source,
            })?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    let mut encoded = String::with_capacity(64);
    for byte in digest.finalize() {
        use std::fmt::Write as _;
        let _ = write!(encoded, "{byte:02x}");
    }
    Ok(encoded)
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn artifact_payload(
    snapshot: &VmLifecycleSnapshot,
    run_id_sha256: String,
    source_sha256: String,
    binary_sha256: String,
    command_sha256: String,
) -> Result<ArtifactPayloadV1, VmLifecycleArtifactError> {
    let _serial = validate_completed_single_vm(snapshot)?;
    let terminal = snapshot
        .terminal
        .ok_or(VmLifecycleValidationError::MissingRunTerminal)?;
    let terminal = match terminal.outcome {
        VmRunTerminalOutcome::Completed {
            exit_code,
            traps,
            trap_limit_hit,
        } => ArtifactTerminalV1 {
            sequence: terminal.sequence.get(),
            kind: "completed".to_owned(),
            exit_code,
            traps,
            trap_limit_hit,
        },
        VmRunTerminalOutcome::RuntimeError => ArtifactTerminalV1 {
            sequence: terminal.sequence.get(),
            kind: "runtime-error".to_owned(),
            exit_code: 0,
            traps: 0,
            trap_limit_hit: false,
        },
    };
    Ok(ArtifactPayloadV1 {
        schema: VM_LIFECYCLE_ARTIFACT_SCHEMA.to_owned(),
        schema_sha256: sha256_hex(VM_LIFECYCLE_SCHEMA_DESCRIPTOR),
        program_sha256: sha256_hex(VM_LIFECYCLE_PROGRAM_SOURCE),
        run_id_sha256,
        source_sha256,
        binary_sha256,
        command_sha256,
        events: snapshot
            .events
            .iter()
            .map(|event| ArtifactEventV1 {
                sequence: event.sequence.get(),
                operation: event.operation.raw(),
                serial: event.serial.get(),
                admission: event.admission,
            })
            .collect(),
        terminal,
    })
}

pub fn render_completed_artifact(
    snapshot: &VmLifecycleSnapshot,
    run_id_sha256: String,
    source_sha256: String,
    binary_sha256: String,
    command_sha256: String,
) -> Result<Vec<u8>, VmLifecycleArtifactError> {
    for (field, value) in [
        ("run_id_sha256", run_id_sha256.as_str()),
        ("source_sha256", source_sha256.as_str()),
        ("binary_sha256", binary_sha256.as_str()),
        ("command_sha256", command_sha256.as_str()),
    ] {
        if !valid_sha256(value) {
            return Err(VmLifecycleArtifactError::InvalidSha256 { field });
        }
    }
    let payload = artifact_payload(
        snapshot,
        run_id_sha256,
        source_sha256,
        binary_sha256,
        command_sha256,
    )?;
    let payload_bytes = serde_json::to_vec(&payload)?;
    let envelope = ArtifactEnvelopeV1 {
        payload,
        payload_sha256: sha256_hex(&payload_bytes),
    };
    let mut bytes = serde_json::to_vec(&envelope)?;
    bytes.push(b'\n');
    Ok(bytes)
}

pub fn validate_artifact(
    bytes: &[u8],
) -> Result<VmLifecycleArtifactSummary, VmLifecycleArtifactError> {
    if bytes.len() > VM_LIFECYCLE_ARTIFACT_MAX_BYTES {
        return Err(VmLifecycleArtifactError::ArtifactTooLarge {
            observed: bytes.len(),
            maximum: VM_LIFECYCLE_ARTIFACT_MAX_BYTES,
        });
    }
    let envelope: ArtifactEnvelopeV1 = serde_json::from_slice(bytes)?;
    let mut canonical = serde_json::to_vec(&envelope)?;
    canonical.push(b'\n');
    if bytes != canonical {
        return Err(VmLifecycleArtifactError::NonCanonicalArtifact);
    }
    if envelope.payload.schema != VM_LIFECYCLE_ARTIFACT_SCHEMA
        || envelope.payload.schema_sha256 != sha256_hex(VM_LIFECYCLE_SCHEMA_DESCRIPTOR)
        || envelope.payload.program_sha256 != sha256_hex(VM_LIFECYCLE_PROGRAM_SOURCE)
    {
        return Err(VmLifecycleArtifactError::SchemaMismatch);
    }
    for (field, value) in [
        ("program_sha256", envelope.payload.program_sha256.as_str()),
        ("run_id_sha256", envelope.payload.run_id_sha256.as_str()),
        ("source_sha256", envelope.payload.source_sha256.as_str()),
        ("binary_sha256", envelope.payload.binary_sha256.as_str()),
        ("command_sha256", envelope.payload.command_sha256.as_str()),
        ("payload_sha256", envelope.payload_sha256.as_str()),
    ] {
        if !valid_sha256(value) {
            return Err(VmLifecycleArtifactError::InvalidSha256 { field });
        }
    }
    let payload_bytes = serde_json::to_vec(&envelope.payload)?;
    if sha256_hex(&payload_bytes) != envelope.payload_sha256 {
        return Err(VmLifecycleArtifactError::PayloadDigestMismatch);
    }
    let expected = [0_u32, 1, 2, 3];
    if envelope.payload.events.len() != expected.len() {
        return Err(VmLifecycleValidationError::EventCount {
            observed: envelope.payload.events.len(),
        }
        .into());
    }
    let serial = NonZeroU64::new(envelope.payload.events[0].serial)
        .map(VmSerial)
        .ok_or(VmLifecycleValidationError::SerialMismatch { index: 0 })?;
    for (index, (event, expected_operation)) in
        envelope.payload.events.iter().zip(expected).enumerate()
    {
        let expected_operation = VmLifecycleOperation::from_raw(expected_operation)
            .ok_or(VmLifecycleArtifactError::SchemaMismatch)?;
        let observed = VmLifecycleOperation::from_raw(event.operation).ok_or(
            VmLifecycleArtifactError::UnknownOperation {
                index,
                operation: event.operation,
            },
        )?;
        if observed != expected_operation {
            return Err(VmLifecycleValidationError::Operation {
                index,
                expected: expected_operation,
                observed,
            }
            .into());
        }
        if event.serial != serial.get() {
            return Err(VmLifecycleValidationError::SerialMismatch { index }.into());
        }
        if event.sequence != u64::try_from(index).unwrap_or(u64::MAX).saturating_add(1) {
            return Err(VmLifecycleValidationError::SequenceMismatch { index }.into());
        }
    }
    if envelope.payload.events[0].admission.is_none()
        || envelope.payload.events[1].admission != envelope.payload.events[0].admission
        || envelope.payload.events[2].admission.is_some()
        || envelope.payload.events[3].admission.is_some()
    {
        return Err(VmLifecycleArtifactError::SchemaMismatch);
    }
    if envelope.payload.terminal.sequence != 5 {
        return Err(VmLifecycleValidationError::TerminalSequenceMismatch.into());
    }
    let terminal = match envelope.payload.terminal.kind.as_str() {
        "completed" => VmRunTerminalOutcome::Completed {
            exit_code: envelope.payload.terminal.exit_code,
            traps: envelope.payload.terminal.traps,
            trap_limit_hit: envelope.payload.terminal.trap_limit_hit,
        },
        "runtime-error"
            if envelope.payload.terminal.exit_code == 0
                && envelope.payload.terminal.traps == 0
                && !envelope.payload.terminal.trap_limit_hit =>
        {
            VmRunTerminalOutcome::RuntimeError
        }
        _ => return Err(VmLifecycleArtifactError::SchemaMismatch),
    };
    Ok(VmLifecycleArtifactSummary {
        serial,
        terminal,
        program_sha256: envelope.payload.program_sha256,
        run_id_sha256: envelope.payload.run_id_sha256,
        source_sha256: envelope.payload.source_sha256,
        binary_sha256: envelope.payload.binary_sha256,
        command_sha256: envelope.payload.command_sha256,
        payload_sha256: envelope.payload_sha256,
    })
}

pub fn validate_authenticated_artifact(
    bytes: &[u8],
    expected: &VmLifecycleArtifactExpectations,
) -> Result<VmLifecycleArtifactSummary, VmLifecycleArtifactError> {
    let summary = validate_artifact(bytes)?;
    for (field, observed, expected) in [
        (
            "run_id_sha256",
            summary.run_id_sha256.as_str(),
            expected.run_id_sha256.as_str(),
        ),
        (
            "source_sha256",
            summary.source_sha256.as_str(),
            expected.source_sha256.as_str(),
        ),
        (
            "binary_sha256",
            summary.binary_sha256.as_str(),
            expected.binary_sha256.as_str(),
        ),
        (
            "command_sha256",
            summary.command_sha256.as_str(),
            expected.command_sha256.as_str(),
        ),
    ] {
        if observed != expected {
            return Err(VmLifecycleArtifactError::ProvenanceMismatch { field });
        }
    }
    Ok(summary)
}

fn publish_artifact_bytes(path: &Path, bytes: &[u8]) -> Result<(), VmLifecycleArtifactError> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let parent_metadata =
        std::fs::metadata(parent).map_err(|source| VmLifecycleArtifactError::Io {
            operation: "inspect artifact parent directory",
            source,
        })?;
    if !parent_metadata.is_dir() || parent_metadata.permissions().mode() & 0o022 != 0 {
        return Err(VmLifecycleArtifactError::InsecureParentDirectory);
    }

    let mut temporary = tempfile::Builder::new()
        .prefix(".carrick-hvpatch-vm-ledger.")
        .tempfile_in(parent)
        .map_err(|source| VmLifecycleArtifactError::Io {
            operation: "create random temporary artifact",
            source,
        })?;
    temporary
        .write_all(bytes)
        .and_then(|()| temporary.as_file().sync_all())
        .map_err(|source| VmLifecycleArtifactError::Io {
            operation: "write temporary artifact",
            source,
        })?;
    let published =
        temporary
            .persist_noclobber(path)
            .map_err(|error| VmLifecycleArtifactError::Io {
                operation: "publish no-clobber artifact",
                source: error.error,
            })?;
    let published_metadata =
        published
            .metadata()
            .map_err(|source| VmLifecycleArtifactError::Io {
                operation: "inspect published artifact",
                source,
            })?;
    let path_metadata = std::fs::metadata(path).map_err(|source| VmLifecycleArtifactError::Io {
        operation: "reopen published artifact",
        source,
    })?;
    if published_metadata.dev() != path_metadata.dev()
        || published_metadata.ino() != path_metadata.ino()
    {
        return Err(VmLifecycleArtifactError::Io {
            operation: "verify published artifact identity",
            source: std::io::Error::other("published path does not name written inode"),
        });
    }
    std::fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| VmLifecycleArtifactError::Io {
            operation: "sync artifact parent directory",
            source,
        })?;
    Ok(())
}

pub fn write_completed_process_artifact(
    path: &Path,
) -> Result<VmLifecycleArtifactSummary, VmLifecycleArtifactError> {
    use std::os::unix::ffi::OsStrExt as _;

    let run_id =
        std::env::var_os("CARRICK_RUN_ID").ok_or(VmLifecycleArtifactError::MissingRunId)?;
    let source_sha256 = std::env::var(VM_LIFECYCLE_SOURCE_SHA256_ENV)
        .map_err(|_| VmLifecycleArtifactError::MissingSourceSha256)?;
    let executable = std::env::current_exe().map_err(|source| VmLifecycleArtifactError::Io {
        operation: "resolve current executable",
        source,
    })?;
    let binary_sha256 = sha256_file(&executable)?;
    let command_sha256 = PROCESS_COMMAND_SHA256
        .get()
        .cloned()
        .ok_or(VmLifecycleArtifactError::MissingCommandSha256)?;
    let bytes = render_completed_artifact(
        &process_snapshot(),
        sha256_hex(run_id.as_os_str().as_bytes()),
        source_sha256,
        binary_sha256,
        command_sha256,
    )?;
    publish_artifact_bytes(path, &bytes)?;
    validate_artifact(&bytes)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    #[test]
    fn one_vm_lifecycle_keeps_one_serial_and_complete_sequence() {
        let ledger = VmLifecycleLedger::default();
        ledger.record_raw(0, 7);
        ledger.record_raw(1, 7);
        ledger.record_raw(2, -1);
        ledger.record_raw(3, -1);
        ledger.record_terminal(VmRunTerminalOutcome::Completed {
            exit_code: 0,
            traps: 42,
            trap_limit_hit: false,
        });

        let snapshot = ledger.snapshot();
        assert!(snapshot.violations.is_empty());
        assert_eq!(snapshot.events.len(), 4);
        assert_eq!(
            snapshot
                .events
                .iter()
                .map(|event| event.operation)
                .collect::<Vec<_>>(),
            vec![
                VmLifecycleOperation::LogicalCreateAttempt,
                VmLifecycleOperation::CreateSuccess,
                VmLifecycleOperation::DestroyAttempt,
                VmLifecycleOperation::DestroySuccess,
            ]
        );
        assert!(
            snapshot
                .events
                .windows(2)
                .all(|events| events[0].serial == events[1].serial)
        );
        assert!(snapshot.pending_create.is_none());
        assert!(snapshot.active.is_none());
        assert!(!snapshot.destroy_pending);
        assert!(matches!(
            snapshot.terminal,
            Some(VmRunTerminal {
                outcome: VmRunTerminalOutcome::Completed { exit_code: 0, .. },
                ..
            })
        ));
        assert_eq!(
            validate_completed_single_vm(&snapshot),
            Ok(snapshot.events[0].serial)
        );
    }

    #[test]
    fn versioned_artifact_round_trips_and_rejects_tampering() {
        let ledger = VmLifecycleLedger::default();
        ledger.record_raw(0, 7);
        ledger.record_raw(1, 7);
        ledger.record_raw(2, -1);
        ledger.record_raw(3, -1);
        ledger.record_terminal(VmRunTerminalOutcome::Completed {
            exit_code: 0,
            traps: 42,
            trap_limit_hit: false,
        });
        let digest = "00".repeat(32);
        let bytes = render_completed_artifact(
            &ledger.snapshot(),
            digest.clone(),
            digest.clone(),
            digest.clone(),
            digest,
        )
        .expect("render artifact");
        let summary = validate_artifact(&bytes).expect("validate artifact");
        assert_eq!(summary.serial.get(), 1);
        assert!(matches!(
            summary.terminal,
            VmRunTerminalOutcome::Completed {
                exit_code: 0,
                traps: 42,
                trap_limit_hit: false
            }
        ));

        let mut tampered: ArtifactEnvelopeV1 =
            serde_json::from_slice(&bytes).expect("parse artifact envelope");
        tampered.payload.events[0].serial = 9;
        let mut tampered = serde_json::to_vec(&tampered).expect("encode tampered artifact");
        tampered.push(b'\n');
        assert!(matches!(
            validate_artifact(&tampered),
            Err(VmLifecycleArtifactError::PayloadDigestMismatch)
        ));

        let mut unknown: serde_json::Value =
            serde_json::from_slice(&bytes).expect("parse artifact value");
        unknown["extra"] = serde_json::json!(true);
        let unknown = serde_json::to_vec(&unknown).expect("encode unknown field");
        assert!(matches!(
            validate_artifact(&unknown),
            Err(VmLifecycleArtifactError::Json(_))
        ));

        let expected = VmLifecycleArtifactExpectations {
            run_id_sha256: "00".repeat(32),
            source_sha256: "00".repeat(32),
            binary_sha256: "00".repeat(32),
            command_sha256: "00".repeat(32),
        };
        validate_authenticated_artifact(&bytes, &expected).expect("trusted provenance must match");
        let mut wrong_source = expected;
        wrong_source.source_sha256 = "11".repeat(32);
        assert!(matches!(
            validate_authenticated_artifact(&bytes, &wrong_source),
            Err(VmLifecycleArtifactError::ProvenanceMismatch {
                field: "source_sha256"
            })
        ));

        let mut whitespace = bytes.clone();
        whitespace.extend_from_slice(b" \n");
        assert!(matches!(
            validate_artifact(&whitespace),
            Err(VmLifecycleArtifactError::NonCanonicalArtifact)
        ));
        let mut trailing = bytes;
        trailing.extend_from_slice(b"garbage");
        assert!(matches!(
            validate_artifact(&trailing),
            Err(VmLifecycleArtifactError::Json(_))
        ));
        assert!(matches!(
            validate_artifact(&vec![b' '; VM_LIFECYCLE_ARTIFACT_MAX_BYTES + 1]),
            Err(VmLifecycleArtifactError::ArtifactTooLarge { .. })
        ));
    }

    #[test]
    fn malformed_transition_sequences_fail_closed_without_false_events() {
        let cases = [
            vec![(1, 0)],
            vec![(2, -1)],
            vec![(3, -1)],
            vec![(0, 1), (0, 1)],
            vec![(0, 1), (1, 2)],
            vec![(0, 1), (1, 1), (2, -1), (2, -1)],
            vec![(0, 1), (1, 1), (3, -1)],
            vec![(99, 0)],
        ];
        for operations in cases {
            let ledger = VmLifecycleLedger::default();
            for (operation, admission) in operations {
                ledger.record_raw(operation, admission);
            }
            let snapshot = ledger.snapshot();
            assert!(!snapshot.violations.is_empty());
            assert!(validate_completed_single_vm(&snapshot).is_err());
        }
    }

    #[test]
    fn missing_or_duplicate_terminal_fails_closed() {
        let ledger = VmLifecycleLedger::default();
        ledger.record_raw(0, 1);
        ledger.record_raw(1, 1);
        ledger.record_raw(2, -1);
        ledger.record_raw(3, -1);
        assert_eq!(
            validate_completed_single_vm(&ledger.snapshot()),
            Err(VmLifecycleValidationError::MissingRunTerminal)
        );
        ledger.record_terminal(VmRunTerminalOutcome::RuntimeError);
        ledger.record_terminal(VmRunTerminalOutcome::RuntimeError);
        assert!(matches!(
            validate_completed_single_vm(&ledger.snapshot()),
            Err(VmLifecycleValidationError::RecordedViolations { .. })
        ));
    }

    #[test]
    fn sequential_vm_lifecycles_never_reuse_a_serial() {
        let ledger = VmLifecycleLedger::default();
        for admission in [1, 2] {
            ledger.record_raw(0, admission);
            ledger.record_raw(1, admission);
            ledger.record_raw(2, -1);
            ledger.record_raw(3, -1);
        }
        let snapshot = ledger.snapshot();
        assert!(snapshot.violations.is_empty());
        let first = snapshot.events[0].serial;
        let second = snapshot.events[4].serial;
        assert_ne!(first, second);
        assert!(first.get() < second.get());
    }

    #[test]
    fn concurrent_snapshots_are_complete_prefixes() {
        let ledger = Arc::new(VmLifecycleLedger::default());
        let writer = Arc::clone(&ledger);
        let thread = std::thread::spawn(move || {
            for admission in 0..8 {
                writer.record_raw(0, admission);
                writer.record_raw(1, admission);
                writer.record_raw(2, -1);
                writer.record_raw(3, -1);
            }
        });
        while !thread.is_finished() {
            let snapshot = ledger.snapshot();
            assert!(
                snapshot
                    .events
                    .windows(2)
                    .all(|events| events[0].sequence.get() < events[1].sequence.get())
            );
        }
        assert!(thread.join().is_ok(), "VM lifecycle writer panicked");
        let snapshot = ledger.snapshot();
        assert!(snapshot.violations.is_empty());
        assert_eq!(snapshot.events.len(), 32);
    }

    #[test]
    fn production_ledger_capacity_is_bounded_and_fails_closed() {
        let ledger = VmLifecycleLedger::default();
        for admission in 0..100 {
            ledger.record_raw(0, admission);
            ledger.record_raw(1, admission);
            ledger.record_raw(2, -1);
            ledger.record_raw(3, -1);
        }
        let snapshot = ledger.snapshot();
        assert_eq!(snapshot.events.len(), MAX_RECORDED_EVENTS);
        assert_eq!(snapshot.violations.len(), MAX_RECORDED_VIOLATIONS);
        assert!(snapshot.violations.iter().any(|violation| matches!(
            violation,
            VmLifecycleViolation::EventCapacityExceeded
                | VmLifecycleViolation::ViolationCapacityExceeded
        )));
        assert!(validate_completed_single_vm(&snapshot).is_err());
    }

    #[test]
    fn artifact_publication_is_private_durable_and_no_clobber() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().expect("create private artifact directory");
        let path = directory.path().join("ledger.json");
        publish_artifact_bytes(&path, b"receipt\n").expect("publish artifact");
        assert_eq!(std::fs::read(&path).expect("read artifact"), b"receipt\n");
        assert!(publish_artifact_bytes(&path, b"replacement\n").is_err());
        assert_eq!(std::fs::read(&path).expect("reread artifact"), b"receipt\n");

        let insecure = directory.path().join("insecure");
        std::fs::create_dir(&insecure).expect("create insecure directory");
        std::fs::set_permissions(&insecure, std::fs::Permissions::from_mode(0o777))
            .expect("mark directory world writable");
        assert!(matches!(
            publish_artifact_bytes(&insecure.join("ledger.json"), b"receipt\n"),
            Err(VmLifecycleArtifactError::InsecureParentDirectory)
        ));
    }

    #[test]
    fn fork_child_reset_discards_inherited_history_and_restarts_identity() {
        let slot = ProcessLedgerSlot::default();
        slot.get().record_raw(0, 3);
        slot.get().record_raw(1, 3);
        slot.reset_after_fork_child();
        assert!(slot.get().snapshot().events.is_empty());
        slot.get().record_raw(0, 4);
        let snapshot = slot.get().snapshot();
        assert_eq!(snapshot.events[0].serial.get(), 1);
        assert_eq!(snapshot.events[0].sequence.get(), 1);
    }
}
