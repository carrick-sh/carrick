#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::FileExt;
use std::sync::OnceLock;

use super::cache::TranslationCache;
use super::emit::{
    BiasedBase, BiasedBaseCoordinate, BiasedExclusiveRecovery, DirectLink, EmittedBlock,
    PcMapEntry, RecoveryAction, RecoveryEntry,
};
use super::types::{CacheOffset, DsrError};

const MOV_WIDE_IMM16_MASK: u32 = 0x001f_ffe0;
const ARTIFACT_STORE_SIZE: u64 = 256 * 1024 * 1024;
static ARTIFACT_AUTHORITY: OnceLock<ArtifactAuthority> = OnceLock::new();

#[derive(Debug)]
pub(in crate::native_darwin) struct ArtifactAuthority {
    file: File,
    authority_nonce: [u8; 16],
}

impl ArtifactAuthority {
    fn create() -> Result<Self, DsrError> {
        let file = tempfile::tempfile().map_err(|error| DsrError::Host {
            operation: "create translation artifact spike authority",
            error,
        })?;
        file.set_len(ARTIFACT_STORE_SIZE)
            .map_err(|error| DsrError::Host {
                operation: "size translation artifact spike authority",
                error,
            })?;
        let mut authority_nonce = [0_u8; 16];
        getrandom::fill(&mut authority_nonce).map_err(|error| {
            DsrError::CachePolicy(format!("generate artifact authority nonce: {error}"))
        })?;
        file.write_all_at(&authority_nonce, 0)
            .map_err(|error| DsrError::Host {
                operation: "write translation artifact spike nonce",
                error,
            })?;
        Ok(Self {
            file,
            authority_nonce,
        })
    }

    #[cfg(test)]
    fn create_for_test() -> Result<Self, DsrError> {
        Self::create()
    }

    pub(in crate::native_darwin) fn snapshot(
        &self,
    ) -> Result<crate::native_exec_capsule::NativeReexecArtifactSpikeV1, DsrError> {
        let fd = self.file.as_raw_fd();
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if flags < 0 {
            return Err(DsrError::Host {
                operation: "read artifact authority fd flags",
                error: std::io::Error::last_os_error(),
            });
        }
        let mut identity = std::mem::MaybeUninit::<libc::stat>::uninit();
        if unsafe { libc::fstat(fd, identity.as_mut_ptr()) } != 0 {
            return Err(DsrError::Host {
                operation: "stat artifact authority",
                error: std::io::Error::last_os_error(),
            });
        }
        let identity = unsafe { identity.assume_init() };
        Ok(crate::native_exec_capsule::NativeReexecArtifactSpikeV1 {
            host_fd: fd,
            original_host_fd_flags: flags,
            host_device: identity.st_dev as u64,
            host_inode: identity.st_ino,
            host_size: identity.st_size as u64,
            authority_nonce: self.authority_nonce,
        })
    }

    #[cfg(test)]
    fn file(&self) -> &File {
        &self.file
    }
}

fn adopt(
    snapshot: &crate::native_exec_capsule::NativeReexecArtifactSpikeV1,
) -> Result<ArtifactAuthority, DsrError> {
    let mut identity = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(snapshot.host_fd, identity.as_mut_ptr()) } != 0 {
        return Err(DsrError::Host {
            operation: "stat inherited artifact authority",
            error: std::io::Error::last_os_error(),
        });
    }
    let identity = unsafe { identity.assume_init() };
    if identity.st_dev as u64 != snapshot.host_device
        || identity.st_ino != snapshot.host_inode
        || identity.st_size as u64 != snapshot.host_size
        || snapshot.host_size != ARTIFACT_STORE_SIZE
    {
        return Err(DsrError::CachePolicy(
            "inherited artifact authority identity mismatch".to_string(),
        ));
    }
    let file = unsafe { File::from_raw_fd(snapshot.host_fd) };
    let mut authority_nonce = [0_u8; 16];
    file.read_exact_at(&mut authority_nonce, 0)
        .map_err(|error| DsrError::Host {
            operation: "read inherited artifact authority nonce",
            error,
        })?;
    if authority_nonce != snapshot.authority_nonce {
        return Err(DsrError::CachePolicy(
            "inherited artifact authority nonce mismatch".to_string(),
        ));
    }
    if unsafe {
        libc::fcntl(
            file.as_raw_fd(),
            libc::F_SETFD,
            snapshot.original_host_fd_flags,
        )
    } != 0
    {
        return Err(DsrError::Host {
            operation: "restore inherited artifact authority fd flags",
            error: std::io::Error::last_os_error(),
        });
    }
    Ok(ArtifactAuthority {
        file,
        authority_nonce,
    })
}

pub(in crate::native_darwin) fn ensure_authority_if_enabled() -> Result<(), DsrError> {
    if std::env::var_os("CARRICK_DSR_ARTIFACT_SPIKE").as_deref() != Some(std::ffi::OsStr::new("1"))
        || ARTIFACT_AUTHORITY.get().is_some()
    {
        return Ok(());
    }
    let authority = ArtifactAuthority::create()?;
    ARTIFACT_AUTHORITY.set(authority).map_err(|_| {
        DsrError::CachePolicy("artifact authority initialized concurrently".to_string())
    })
}

pub(crate) fn authority_snapshot_if_enabled()
-> anyhow::Result<Option<crate::native_exec_capsule::NativeReexecArtifactSpikeV1>> {
    ensure_authority_if_enabled()
        .map_err(|error| anyhow::anyhow!("create artifact spike authority: {error}"))?;
    ARTIFACT_AUTHORITY
        .get()
        .map(ArtifactAuthority::snapshot)
        .transpose()
        .map_err(|error| anyhow::anyhow!("snapshot artifact spike authority: {error}"))
}

pub(crate) fn adopt_for_resume(
    snapshot: &crate::native_exec_capsule::NativeReexecArtifactSpikeV1,
) -> anyhow::Result<()> {
    let authority = adopt(snapshot)
        .map_err(|error| anyhow::anyhow!("adopt artifact spike authority: {error}"))?;
    ARTIFACT_AUTHORITY
        .set(authority)
        .map_err(|_| anyhow::anyhow!("artifact spike authority was already initialized"))
}

#[cfg(test)]
fn adopt_for_test(
    snapshot: &crate::native_exec_capsule::NativeReexecArtifactSpikeV1,
) -> Result<ArtifactAuthority, DsrError> {
    adopt(snapshot)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum GatewayKind {
    Syscall,
    Direct,
    Indirect,
    Sensitive,
    Unsupported,
    Signal,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum ProcessValue {
    Gateway(GatewayKind),
    GenerationAddress,
    GenerationExpected,
    HostBias,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ArtifactBindings {
    values: BTreeMap<ProcessValue, u64>,
}

impl ArtifactBindings {
    pub(super) fn from_values(
        values: impl IntoIterator<Item = (ProcessValue, u64)>,
    ) -> Result<Self, DsrError> {
        let mut result = BTreeMap::new();
        for (kind, value) in values {
            if result.insert(kind, value).is_some() {
                return Err(DsrError::CachePolicy(format!(
                    "duplicate artifact binding for {kind:?}"
                )));
            }
        }
        Ok(Self { values: result })
    }

    fn value(&self, kind: ProcessValue) -> Result<u64, DsrError> {
        self.values
            .get(&kind)
            .copied()
            .ok_or_else(|| DsrError::CachePolicy(format!("missing artifact binding for {kind:?}")))
    }

    fn bind(&mut self, kind: ProcessValue, value: u64) -> Result<(), DsrError> {
        if let Some(existing) = self.values.insert(kind, value)
            && existing != value
        {
            return Err(DsrError::CachePolicy(format!(
                "conflicting artifact binding for {kind:?}: 0x{existing:x} versus 0x{value:x}"
            )));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum MaterializedValue {
    Guest(u64),
    Process(ProcessValue, u64),
}

impl MaterializedValue {
    pub(super) const fn raw(self) -> u64 {
        match self {
            Self::Guest(value) | Self::Process(_, value) => value,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PendingRelocation {
    first_word: u32,
    register: u8,
    value: ProcessValue,
}

#[derive(Debug, Default)]
pub(super) struct ArtifactRecording {
    bindings: BTreeMap<ProcessValue, u64>,
    relocations: Vec<PendingRelocation>,
}

impl ArtifactRecording {
    pub(super) fn bind(&mut self, kind: ProcessValue, value: u64) -> Result<(), DsrError> {
        let mut bindings = ArtifactBindings {
            values: std::mem::take(&mut self.bindings),
        };
        let result = bindings.bind(kind, value);
        self.bindings = bindings.values;
        result
    }

    pub(super) fn record_mov_wide(
        &mut self,
        first_byte: CacheOffset,
        register: u32,
        value: MaterializedValue,
    ) -> Result<(), DsrError> {
        let MaterializedValue::Process(kind, raw) = value else {
            return Ok(());
        };
        self.bind(kind, raw)?;
        let first_word = first_byte.get().checked_div(4).ok_or_else(|| {
            DsrError::CachePolicy("artifact relocation offset overflow".to_string())
        })?;
        self.relocations.push(PendingRelocation {
            first_word,
            register: u8::try_from(register).map_err(|_| {
                DsrError::CachePolicy(format!(
                    "artifact MOV-wide register does not fit u8: {register}"
                ))
            })?,
            value: kind,
        });
        Ok(())
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "finishing a recording captures code and all replay metadata"
    )]
    pub(super) fn finish(
        self,
        words: Vec<u32>,
        map: Vec<PcMapEntry>,
        recovery: Vec<RecoveryEntry>,
        direct_links: Vec<DirectLink>,
        source_words: Vec<u32>,
    ) -> Result<ArtifactRecord, DsrError> {
        let bindings = ArtifactBindings {
            values: self.bindings,
        };
        let recorded_starts = self
            .relocations
            .iter()
            .map(|relocation| relocation.first_word)
            .collect::<BTreeSet<_>>();
        for first in 0..words.len().saturating_sub(3) {
            let sequence = &words[first..first + 4];
            let register = sequence[0] & 0x1f;
            let is_mov_wide = sequence.iter().enumerate().all(|(halfword, word)| {
                let expected = if halfword == 0 {
                    0xd280_0000
                } else {
                    0xf280_0000
                } | ((halfword as u32) << 21)
                    | register;
                (*word & !MOV_WIDE_IMM16_MASK) == expected
            });
            if !is_mov_wide {
                continue;
            }
            let materialized =
                sequence
                    .iter()
                    .enumerate()
                    .fold(0_u64, |value, (halfword, word)| {
                        value | (u64::from((word & MOV_WIDE_IMM16_MASK) >> 5) << (halfword * 16))
                    });
            let exact_process_value = bindings.values.values().any(|value| *value == materialized);
            let biased_literal = bindings
                .values
                .get(&ProcessValue::HostBias)
                .is_some_and(|bias| {
                    materialized >= *bias
                        && materialized.saturating_sub(*bias)
                            < super::super::address::BIASED_GUEST_LITERAL_TARGET_END
                });
            let first = u32::try_from(first).map_err(|_| {
                DsrError::CachePolicy("artifact MOV-wide index exceeds u32".to_string())
            })?;
            if (exact_process_value || biased_literal) && !recorded_starts.contains(&first) {
                return Err(DsrError::CachePolicy(format!(
                    "unrecorded process-derived MOV-wide value 0x{materialized:x} at word {first}"
                )));
            }
        }
        let relocations = self
            .relocations
            .into_iter()
            .map(|pending| {
                let first = usize::try_from(pending.first_word).map_err(|_| {
                    DsrError::CachePolicy("artifact relocation index overflow".to_string())
                })?;
                let slice = words.get(first..first.saturating_add(4)).ok_or_else(|| {
                    DsrError::CachePolicy(format!(
                        "recorded artifact relocation at word {first} is incomplete"
                    ))
                })?;
                Ok(ArtifactRelocation {
                    first_word: pending.first_word,
                    register: pending.register,
                    value: pending.value,
                    expected_opcode_mask: std::array::from_fn(|index| {
                        slice[index] & !MOV_WIDE_IMM16_MASK
                    }),
                })
            })
            .collect::<Result<Vec<_>, DsrError>>()?;
        let template = ArtifactTemplate::normalize(
            words,
            map,
            recovery,
            direct_links,
            source_words,
            relocations,
            &bindings,
        )?;
        Ok(ArtifactRecord { template, bindings })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ArtifactRecord {
    pub(super) template: ArtifactTemplate,
    pub(super) bindings: ArtifactBindings,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ArtifactRelocation {
    pub(super) first_word: u32,
    pub(super) register: u8,
    pub(super) value: ProcessValue,
    pub(super) expected_opcode_mask: [u32; 4],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PortableBiasedMemoryRecovery {
    scratch_registers: [u32; 4],
    scratch_count: u8,
    base_scratch: u32,
    base: BiasedBase,
    base_coordinate: BiasedBaseCoordinate,
    commit_base: bool,
    virtual_x18_scratch: Option<u32>,
    virtual_x28_scratch: Option<u32>,
    instruction_complete: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PortableRecoveryAction {
    Noop,
    RestoreGuestX17,
    RestoreGenerationGuardRegisters,
    RestoreGenerationGuard,
    RestoreIndirectRegisters,
    RestoreIndirectResolver,
    RestoreScratch {
        register: u32,
    },
    RestoreScratchInvalidBiasedLiteral {
        register: u32,
    },
    RestoreScratchCompleted {
        register: u32,
    },
    CommitVirtualizedAndRestoreScratch {
        register: u32,
        virtual_register: u32,
    },
    RestoreScratchAndContext {
        register: u32,
        context_register: u32,
    },
    RestoreScratchAndContextCompleted {
        register: u32,
        context_register: u32,
    },
    CommitVirtualizedAndRestoreScratchAndContext {
        register: u32,
        context_register: u32,
        virtual_register: u32,
    },
    RestoreDualVirtualReadOnly {
        x18_scratch: u32,
        x28_scratch: u32,
        context_scratch: u32,
    },
    RestoreDualVirtualReadOnlyCompleted {
        x18_scratch: u32,
        x28_scratch: u32,
        context_scratch: u32,
    },
    CommitDualVirtualAndRestore {
        x18_scratch: u32,
        x28_scratch: u32,
        context_scratch: u32,
        virtual_register: u32,
        virtual_scratch: u32,
    },
    RecoverBiasedMemory(PortableBiasedMemoryRecovery),
    RecoverBiasedExclusive(BiasedExclusiveRecovery),
}

impl PortableRecoveryAction {
    fn normalize(action: RecoveryAction, bindings: &ArtifactBindings) -> Result<Self, DsrError> {
        Ok(match action {
            RecoveryAction::Noop => Self::Noop,
            RecoveryAction::RestoreGuestX17 => Self::RestoreGuestX17,
            RecoveryAction::RestoreGenerationGuardRegisters => {
                Self::RestoreGenerationGuardRegisters
            }
            RecoveryAction::RestoreGenerationGuard => Self::RestoreGenerationGuard,
            RecoveryAction::RestoreIndirectRegisters => Self::RestoreIndirectRegisters,
            RecoveryAction::RestoreIndirectResolver => Self::RestoreIndirectResolver,
            RecoveryAction::RestoreScratch { register } => Self::RestoreScratch { register },
            RecoveryAction::RestoreScratchInvalidBiasedLiteral { register } => {
                Self::RestoreScratchInvalidBiasedLiteral { register }
            }
            RecoveryAction::RestoreScratchCompleted { register } => {
                Self::RestoreScratchCompleted { register }
            }
            RecoveryAction::CommitVirtualizedAndRestoreScratch {
                register,
                virtual_register,
            } => Self::CommitVirtualizedAndRestoreScratch {
                register,
                virtual_register,
            },
            RecoveryAction::RestoreScratchAndContext {
                register,
                context_register,
            } => Self::RestoreScratchAndContext {
                register,
                context_register,
            },
            RecoveryAction::RestoreScratchAndContextCompleted {
                register,
                context_register,
            } => Self::RestoreScratchAndContextCompleted {
                register,
                context_register,
            },
            RecoveryAction::CommitVirtualizedAndRestoreScratchAndContext {
                register,
                context_register,
                virtual_register,
            } => Self::CommitVirtualizedAndRestoreScratchAndContext {
                register,
                context_register,
                virtual_register,
            },
            RecoveryAction::RestoreDualVirtualReadOnly {
                x18_scratch,
                x28_scratch,
                context_scratch,
            } => Self::RestoreDualVirtualReadOnly {
                x18_scratch,
                x28_scratch,
                context_scratch,
            },
            RecoveryAction::RestoreDualVirtualReadOnlyCompleted {
                x18_scratch,
                x28_scratch,
                context_scratch,
            } => Self::RestoreDualVirtualReadOnlyCompleted {
                x18_scratch,
                x28_scratch,
                context_scratch,
            },
            RecoveryAction::CommitDualVirtualAndRestore {
                x18_scratch,
                x28_scratch,
                context_scratch,
                virtual_register,
                virtual_scratch,
            } => Self::CommitDualVirtualAndRestore {
                x18_scratch,
                x28_scratch,
                context_scratch,
                virtual_register,
                virtual_scratch,
            },
            RecoveryAction::RecoverBiasedMemory(recovery) => {
                let bound_bias = bindings.value(ProcessValue::HostBias)?;
                if recovery.host_bias.get() != bound_bias {
                    return Err(DsrError::CachePolicy(format!(
                        "biased recovery binding mismatch: recovery=0x{:x} binding=0x{bound_bias:x}",
                        recovery.host_bias.get()
                    )));
                }
                Self::RecoverBiasedMemory(PortableBiasedMemoryRecovery {
                    scratch_registers: recovery.scratch_registers,
                    scratch_count: recovery.scratch_count,
                    base_scratch: recovery.base_scratch,
                    base: recovery.base,
                    base_coordinate: recovery.base_coordinate,
                    commit_base: recovery.commit_base,
                    virtual_x18_scratch: recovery.virtual_x18_scratch,
                    virtual_x28_scratch: recovery.virtual_x28_scratch,
                    instruction_complete: recovery.instruction_complete,
                })
            }
            RecoveryAction::RecoverBiasedExclusive(recovery) => {
                Self::RecoverBiasedExclusive(recovery)
            }
        })
    }

    fn rebind(self, bindings: &ArtifactBindings) -> Result<RecoveryAction, DsrError> {
        Ok(match self {
            Self::Noop => RecoveryAction::Noop,
            Self::RestoreGuestX17 => RecoveryAction::RestoreGuestX17,
            Self::RestoreGenerationGuardRegisters => {
                RecoveryAction::RestoreGenerationGuardRegisters
            }
            Self::RestoreGenerationGuard => RecoveryAction::RestoreGenerationGuard,
            Self::RestoreIndirectRegisters => RecoveryAction::RestoreIndirectRegisters,
            Self::RestoreIndirectResolver => RecoveryAction::RestoreIndirectResolver,
            Self::RestoreScratch { register } => RecoveryAction::RestoreScratch { register },
            Self::RestoreScratchInvalidBiasedLiteral { register } => {
                RecoveryAction::RestoreScratchInvalidBiasedLiteral { register }
            }
            Self::RestoreScratchCompleted { register } => {
                RecoveryAction::RestoreScratchCompleted { register }
            }
            Self::CommitVirtualizedAndRestoreScratch {
                register,
                virtual_register,
            } => RecoveryAction::CommitVirtualizedAndRestoreScratch {
                register,
                virtual_register,
            },
            Self::RestoreScratchAndContext {
                register,
                context_register,
            } => RecoveryAction::RestoreScratchAndContext {
                register,
                context_register,
            },
            Self::RestoreScratchAndContextCompleted {
                register,
                context_register,
            } => RecoveryAction::RestoreScratchAndContextCompleted {
                register,
                context_register,
            },
            Self::CommitVirtualizedAndRestoreScratchAndContext {
                register,
                context_register,
                virtual_register,
            } => RecoveryAction::CommitVirtualizedAndRestoreScratchAndContext {
                register,
                context_register,
                virtual_register,
            },
            Self::RestoreDualVirtualReadOnly {
                x18_scratch,
                x28_scratch,
                context_scratch,
            } => RecoveryAction::RestoreDualVirtualReadOnly {
                x18_scratch,
                x28_scratch,
                context_scratch,
            },
            Self::RestoreDualVirtualReadOnlyCompleted {
                x18_scratch,
                x28_scratch,
                context_scratch,
            } => RecoveryAction::RestoreDualVirtualReadOnlyCompleted {
                x18_scratch,
                x28_scratch,
                context_scratch,
            },
            Self::CommitDualVirtualAndRestore {
                x18_scratch,
                x28_scratch,
                context_scratch,
                virtual_register,
                virtual_scratch,
            } => RecoveryAction::CommitDualVirtualAndRestore {
                x18_scratch,
                x28_scratch,
                context_scratch,
                virtual_register,
                virtual_scratch,
            },
            Self::RecoverBiasedMemory(recovery) => {
                let raw_bias = bindings.value(ProcessValue::HostBias)?;
                let host_bias =
                    super::super::address::NativeHostBias::new(raw_bias, 1).map_err(|error| {
                        DsrError::CachePolicy(format!(
                            "invalid artifact host-bias binding 0x{raw_bias:x}: {error}"
                        ))
                    })?;
                RecoveryAction::RecoverBiasedMemory(super::emit::BiasedMemoryRecovery {
                    scratch_registers: recovery.scratch_registers,
                    scratch_count: recovery.scratch_count,
                    base_scratch: recovery.base_scratch,
                    base: recovery.base,
                    base_coordinate: recovery.base_coordinate,
                    commit_base: recovery.commit_base,
                    virtual_x18_scratch: recovery.virtual_x18_scratch,
                    virtual_x28_scratch: recovery.virtual_x28_scratch,
                    host_bias,
                    instruction_complete: recovery.instruction_complete,
                })
            }
            Self::RecoverBiasedExclusive(recovery) => {
                RecoveryAction::RecoverBiasedExclusive(recovery)
            }
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PortableRecoveryEntry {
    cache: CacheOffset,
    action: PortableRecoveryAction,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ArtifactTemplate {
    words: Vec<u32>,
    map: Vec<PcMapEntry>,
    recovery: Vec<PortableRecoveryEntry>,
    direct_links: Vec<DirectLink>,
    relocations: Vec<ArtifactRelocation>,
    source_words: Vec<u32>,
}

impl ArtifactTemplate {
    #[allow(
        clippy::too_many_arguments,
        reason = "an artifact template owns code and all replay metadata"
    )]
    pub(super) fn normalize(
        mut words: Vec<u32>,
        map: Vec<PcMapEntry>,
        recovery: Vec<RecoveryEntry>,
        direct_links: Vec<DirectLink>,
        source_words: Vec<u32>,
        mut relocations: Vec<ArtifactRelocation>,
        bindings: &ArtifactBindings,
    ) -> Result<Self, DsrError> {
        relocations.sort_by_key(|relocation| relocation.first_word);
        let mut consumed = BTreeSet::new();
        for relocation in &relocations {
            if relocation.register > 30 {
                return Err(DsrError::CachePolicy(format!(
                    "artifact relocation uses invalid x{}",
                    relocation.register
                )));
            }
            let first = usize::try_from(relocation.first_word).map_err(|_| {
                DsrError::CachePolicy("artifact relocation index overflow".to_string())
            })?;
            let value = bindings.value(relocation.value)?;
            for halfword in 0..4_usize {
                let index = first.checked_add(halfword).ok_or_else(|| {
                    DsrError::CachePolicy("artifact relocation range overflow".to_string())
                })?;
                if !consumed.insert(index) {
                    return Err(DsrError::CachePolicy(format!(
                        "overlapping artifact relocation at word {index}"
                    )));
                }
                let word = words.get_mut(index).ok_or_else(|| {
                    DsrError::CachePolicy(format!(
                        "artifact relocation word {index} is out of bounds"
                    ))
                })?;
                let opcode = *word & !MOV_WIDE_IMM16_MASK;
                if opcode != relocation.expected_opcode_mask[halfword]
                    || (*word & 0x1f) != u32::from(relocation.register)
                {
                    return Err(DsrError::CachePolicy(format!(
                        "artifact relocation opcode mismatch at word {index}"
                    )));
                }
                let encoded = (*word & MOV_WIDE_IMM16_MASK) >> 5;
                let expected = ((value >> (halfword * 16)) & 0xffff) as u32;
                if encoded != expected {
                    return Err(DsrError::CachePolicy(format!(
                        "artifact relocation binding mismatch at word {index}"
                    )));
                }
                *word &= !MOV_WIDE_IMM16_MASK;
            }
        }
        let recovery = recovery
            .into_iter()
            .map(|entry| {
                Ok(PortableRecoveryEntry {
                    cache: entry.cache,
                    action: PortableRecoveryAction::normalize(entry.action, bindings)?,
                })
            })
            .collect::<Result<Vec<_>, DsrError>>()?;
        Ok(Self {
            words,
            map,
            recovery,
            direct_links,
            relocations,
            source_words,
        })
    }
}

pub(super) fn replay_artifact(
    cache: &mut TranslationCache,
    template: &ArtifactTemplate,
    bindings: &ArtifactBindings,
) -> Result<EmittedBlock, DsrError> {
    let mut words = template.words.clone();
    let mut consumed = BTreeSet::new();
    for relocation in &template.relocations {
        let first = usize::try_from(relocation.first_word).map_err(|_| {
            DsrError::CachePolicy("artifact replay relocation index overflow".to_string())
        })?;
        let value = bindings.value(relocation.value)?;
        for halfword in 0..4_usize {
            let index = first.checked_add(halfword).ok_or_else(|| {
                DsrError::CachePolicy("artifact replay relocation range overflow".to_string())
            })?;
            if !consumed.insert(index) {
                return Err(DsrError::CachePolicy(format!(
                    "overlapping artifact replay relocation at word {index}"
                )));
            }
            let word = words.get_mut(index).ok_or_else(|| {
                DsrError::CachePolicy(format!(
                    "artifact replay relocation word {index} is out of bounds"
                ))
            })?;
            if (*word & !MOV_WIDE_IMM16_MASK) != relocation.expected_opcode_mask[halfword]
                || (*word & MOV_WIDE_IMM16_MASK) != 0
                || (*word & 0x1f) != u32::from(relocation.register)
            {
                return Err(DsrError::CachePolicy(format!(
                    "artifact replay opcode mismatch at word {index}"
                )));
            }
            let immediate = ((value >> (halfword * 16)) & 0xffff) as u32;
            *word |= immediate << 5;
        }
    }
    let recovery = template
        .recovery
        .iter()
        .map(|entry| {
            Ok(RecoveryEntry {
                cache: entry.cache,
                action: entry.action.rebind(bindings)?,
            })
        })
        .collect::<Result<Vec<_>, DsrError>>()?;
    let code = cache.publish_words(&words)?;
    EmittedBlock::from_artifact_parts(
        code,
        template.map.clone(),
        template.direct_links.clone(),
        recovery,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native_darwin::address::NativeHostBias;
    use crate::native_darwin::dsr::cache::TranslationCache;
    use crate::native_darwin::dsr::emit::{
        BiasedBase, BiasedBaseCoordinate, BiasedMemoryRecovery, DirectLink, PcMapEntry,
        RecoveryAction, RecoveryEntry,
    };
    use crate::native_darwin::dsr::types::CacheOffset;
    use carrick_guest_mem::GuestVa;
    use std::os::fd::AsRawFd;

    const IMM16_MASK: u32 = 0x001f_ffe0;

    fn mov_wide(register: u8, value: u64) -> [u32; 4] {
        std::array::from_fn(|halfword| {
            let base = if halfword == 0 {
                0xd280_0000
            } else {
                0xf280_0000
            };
            let immediate = ((value >> (halfword * 16)) & 0xffff) as u32;
            base | ((halfword as u32) << 21) | (immediate << 5) | u32::from(register)
        })
    }

    fn emit_artifact_fixture(
        generation_address: u64,
        host_bias: u64,
    ) -> (ArtifactTemplate, ArtifactBindings) {
        let mut words = mov_wide(16, generation_address).to_vec();
        words.extend([0xd280_0540, 0xd65f_03c0]); // mov x0, #42; ret
        let relocation = ArtifactRelocation {
            first_word: 0,
            register: 16,
            value: ProcessValue::GenerationAddress,
            expected_opcode_mask: std::array::from_fn(|index| words[index] & !IMM16_MASK),
        };
        let bindings = ArtifactBindings::from_values([
            (ProcessValue::GenerationAddress, generation_address),
            (ProcessValue::HostBias, host_bias),
        ])
        .expect("unique fixture bindings");
        let bias = NativeHostBias::new(host_bias, 16 * 1024).expect("aligned fixture bias");
        let recovery = vec![RecoveryEntry {
            cache: CacheOffset::published(0),
            action: RecoveryAction::RecoverBiasedMemory(BiasedMemoryRecovery {
                scratch_registers: [16, 17, 0, 0],
                scratch_count: 2,
                base_scratch: 16,
                base: BiasedBase::Register(0),
                base_coordinate: BiasedBaseCoordinate::Guest,
                commit_base: false,
                virtual_x18_scratch: None,
                virtual_x28_scratch: None,
                host_bias: bias,
                instruction_complete: false,
            }),
        }];
        let template = ArtifactTemplate::normalize(
            words,
            vec![PcMapEntry {
                guest: GuestVa(0x4000),
                cache: CacheOffset::published(0),
            }],
            recovery,
            vec![DirectLink {
                slot: CacheOffset::published(20),
                target: GuestVa(0x5000),
            }],
            vec![0xd280_0540, 0xd65f_03c0],
            vec![relocation],
            &bindings,
        )
        .expect("normalize fixture");
        (template, bindings)
    }

    #[test]
    fn normalization_removes_every_process_value() {
        let (a, a_bindings) = emit_artifact_fixture(0x1000_0000, 0x2000_0000);
        let (b, b_bindings) = emit_artifact_fixture(0x3000_0000, 0x4000_0000);
        assert_eq!(a, b);
        assert_ne!(a_bindings, b_bindings);
    }

    #[test]
    fn replay_matches_fresh_metadata_and_guest_result() {
        let (template, bindings) = emit_artifact_fixture(0x1000_0000, 0x2000_0000);
        let mut fresh_cache = TranslationCache::new(16 * 1024).expect("fresh cache");
        let fresh = replay_artifact(&mut fresh_cache, &template, &bindings).expect("fresh replay");
        let mut replay_cache = TranslationCache::new(16 * 1024).expect("replay cache");
        let replay = replay_artifact(&mut replay_cache, &template, &bindings).expect("replay");

        assert_eq!(fresh.map().entries(), replay.map().entries());
        assert_eq!(fresh.recovery(), replay.recovery());
        assert_eq!(fresh.direct_links(), replay.direct_links());
        #[cfg(target_arch = "aarch64")]
        unsafe {
            let fresh_fn: unsafe extern "C" fn() -> u64 =
                std::mem::transmute(fresh.entry().host().raw());
            let replay_fn: unsafe extern "C" fn() -> u64 =
                std::mem::transmute(replay.entry().host().raw());
            assert_eq!(fresh_fn(), 42);
            assert_eq!(replay_fn(), 42);
        }
    }

    #[test]
    fn authority_snapshot_preserves_identity_and_nonce() {
        let authority = ArtifactAuthority::create_for_test().expect("authority");
        let snapshot = authority.snapshot().expect("snapshot");
        let adopted_fd = unsafe { libc::fcntl(snapshot.host_fd, libc::F_DUPFD_CLOEXEC, 0) };
        assert!(adopted_fd >= 0);
        let mut inherited = snapshot;
        inherited.host_fd = adopted_fd;
        let adopted = adopt_for_test(&inherited).expect("adopt matching authority");
        assert_eq!(
            adopted
                .snapshot()
                .expect("adopted snapshot")
                .authority_nonce,
            snapshot.authority_nonce
        );
        assert_ne!(adopted.file().as_raw_fd(), authority.file().as_raw_fd());
    }

    #[test]
    fn authority_rejects_substituted_fd() {
        let authority = ArtifactAuthority::create_for_test().expect("authority");
        let mut snapshot = authority.snapshot().expect("snapshot");
        snapshot.host_inode ^= 1;
        assert!(adopt_for_test(&snapshot).is_err());
    }
}
