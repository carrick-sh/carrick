//! # Guest Mapping Plan and Exec File Cache
//!
//! Address space layout planning for guest execution, cached private file
//! backings for execve rebuild, and initial VM creation with mapping plan.

#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

use super::*;
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GuestMappingPlan {
    /// The user-mode entry point (real `_start` of the loaded ELF, already
    /// rebased through any PIE bias). When `el0_trampoline_entry` is `None`
    /// this is also the vCPU's initial PC. When the trampoline is installed
    /// this becomes ELR_EL1 instead, and the vCPU starts at the trampoline.
    pub entry: u64,
    pub initial_stack_pointer: Option<u64>,
    /// Guest physical address of the EL0 entry trampoline page (a single
    /// `eret` instruction). When set, the trap engine starts the vCPU here
    /// in EL1h and uses `entry` as the post-`eret` PC in EL0t.
    pub el0_trampoline_entry: Option<u64>,
    /// Guest physical address to program into VBAR_EL1 so EL0 SVC traps are
    /// routed through the EL1 vector page (which forwards them via HVC).
    pub el1_vectors_base: Option<u64>,
    /// Guest physical address of the stage-1 identity page-table root.
    /// When set, the trap engine programs TTBR0_EL1 / TCR_EL1 / MAIR_EL1
    /// and enables stage-1 (`SCTLR_EL1.M=1`).
    pub stage1_page_tables_base: Option<u64>,
    /// Page-granular read-only guest-VA spans from non-writable ELF `PT_LOAD`
    /// segments. Stage-1 already enforces these for guest stores; HVF also
    /// seeds the shared syscall protection table from them so copyout-style
    /// syscalls return `EFAULT` for `.text`/`.rodata` destinations.
    pub ro_spans: Vec<carrick_mem::elf::RoSpan>,
    pub mappings: Vec<GuestMapping>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GuestMapping {
    /// Guest VIRTUAL address the region is mapped at (also the key for
    /// software syscall-path memory access). Equals `ipa_start` for every
    /// region except Rosetta's high-VA alias.
    pub guest_start: u64,
    /// Intermediate physical address actually handed to `hv_vm_map`. Identity
    /// (== `guest_start`) for all regions but the Rosetta window, which is
    /// aliased to a low IPA (see `crate::memory::ipa_for_va`).
    pub ipa_start: u64,
    pub mapped_size: u64,
    pub offset_in_mapping: u64,
    pub payload_size: u64,
    pub perms: SegmentPerms,
    /// Host backing is `MAP_SHARED` (kept shared across fork). Mirrors
    /// `MemoryRegion::shared`.
    pub shared: bool,
    #[serde(skip)]
    pub(crate) image: std::sync::Arc<Vec<u8>>,
    /// Optional immutable, fully-patched file artifact for a private RX
    /// mapping. Every exec creates a fresh MAP_PRIVATE host view; the artifact
    /// itself is cached and never mutated.
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[serde(skip)]
    pub(crate) private_file_backing: Option<ExecPrivateFileBacking>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Debug)]
pub(crate) struct ExecPrivateFileBacking {
    pub(crate) identity: u64,
    pub(crate) file: std::sync::Arc<std::fs::File>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl PartialEq for ExecPrivateFileBacking {
    fn eq(&self, other: &Self) -> bool {
        self.identity == other.identity
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl Eq for ExecPrivateFileBacking {}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct ExecPrivateFileKey {
    source_ptr: usize,
    source_len: usize,
    mapped_size: usize,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Debug)]
struct CachedExecPrivateFile {
    source: std::sync::Arc<Vec<u8>>,
    backing: ExecPrivateFileBacking,
    mapped_size: usize,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Debug, Default)]
struct ExecPrivateFileCache {
    entries: HashMap<ExecPrivateFileKey, CachedExecPrivateFile>,
    mapped_bytes: usize,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
const EXEC_PRIVATE_FILE_CACHE_CAPACITY: usize = 64;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
const EXEC_PRIVATE_FILE_CACHE_BYTES: usize = 256 * 1024 * 1024;

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn exec_private_file_cache_enabled() -> bool {
    std::env::var_os("CARRICK_HVPATCH_EXEC_PRIVATE_FILE_CACHE").as_deref()
        != Some(std::ffi::OsStr::new("0"))
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn exec_private_file_cache() -> &'static parking_lot::Mutex<ExecPrivateFileCache> {
    static CACHE: std::sync::OnceLock<parking_lot::Mutex<ExecPrivateFileCache>> =
        std::sync::OnceLock::new();
    CACHE.get_or_init(|| parking_lot::Mutex::new(ExecPrivateFileCache::default()))
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn create_exec_private_file_artifact(
    source: &[u8],
    mapped_size: usize,
) -> Result<std::fs::File, std::io::Error> {
    use std::os::unix::fs::{FileExt, OpenOptionsExt};

    if source.len() > mapped_size || mapped_size == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid hvpatch private executable artifact extent",
        ));
    }
    static NEXT_FILE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    let sequence = NEXT_FILE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        ".carrick-hvpatch-exec-{}-{sequence}",
        std::process::id()
    ));
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)?;
    if let Err(error) = std::fs::remove_file(&path) {
        drop(file);
        let _ = std::fs::remove_file(&path);
        return Err(error);
    }
    file.set_len(mapped_size as u64)?;
    file.write_all_at(source, 0)?;
    Ok(file)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn cached_exec_private_file_backing(
    source: std::sync::Arc<Vec<u8>>,
    mapped_size: usize,
) -> Result<ExecPrivateFileBacking, TrapError> {
    let key = ExecPrivateFileKey {
        source_ptr: std::sync::Arc::as_ptr(&source) as usize,
        source_len: source.len(),
        mapped_size,
    };
    if let Some(cached) = exec_private_file_cache()
        .lock()
        .entries
        .get(&key)
        .filter(|cached| std::sync::Arc::ptr_eq(&cached.source, &source))
    {
        return Ok(cached.backing.clone());
    }

    let file = create_exec_private_file_artifact(&source, mapped_size).map_err(|error| {
        TrapError::Hypervisor(format!(
            "create hvpatch private executable artifact (size={mapped_size}): {error}"
        ))
    })?;
    static NEXT_IDENTITY: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    let candidate = ExecPrivateFileBacking {
        identity: NEXT_IDENTITY.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        file: std::sync::Arc::new(file),
    };
    let mut cache = exec_private_file_cache().lock();
    if let Some(cached) = cache
        .entries
        .get(&key)
        .filter(|cached| std::sync::Arc::ptr_eq(&cached.source, &source))
    {
        return Ok(cached.backing.clone());
    }
    while cache.entries.len() >= EXEC_PRIVATE_FILE_CACHE_CAPACITY
        || cache.mapped_bytes.saturating_add(mapped_size) > EXEC_PRIVATE_FILE_CACHE_BYTES
    {
        let Some(victim) = cache.entries.keys().next().copied() else {
            break;
        };
        if let Some(removed) = cache.entries.remove(&victim) {
            cache.mapped_bytes = cache.mapped_bytes.saturating_sub(removed.mapped_size);
        }
    }
    if mapped_size <= EXEC_PRIVATE_FILE_CACHE_BYTES {
        cache.mapped_bytes = cache.mapped_bytes.saturating_add(mapped_size);
        cache.entries.insert(
            key,
            CachedExecPrivateFile {
                source,
                backing: candidate.clone(),
                mapped_size,
            },
        );
    }
    Ok(candidate)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn attach_exec_private_file_backings(
    plan: &mut GuestMappingPlan,
) -> Result<(), TrapError> {
    if !exec_private_file_cache_enabled() {
        return Ok(());
    }
    for mapping in &mut plan.mappings {
        let eligible = mapping.perms.execute
            && !mapping.perms.write
            && !mapping.shared
            && mapping.offset_in_mapping == 0
            && !mapping.image.is_empty()
            && mapping.image.len() <= mapping.mapped_size as usize
            && mapping.mapped_size as usize <= EXEC_PRIVATE_FILE_CACHE_BYTES;
        if !eligible {
            continue;
        }
        mapping.private_file_backing = Some(cached_exec_private_file_backing(
            std::sync::Arc::clone(&mapping.image),
            mapping.mapped_size as usize,
        )?);
    }
    Ok(())
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn lazy_exec_page_tables_enabled() -> bool {
    std::env::var_os("CARRICK_HVPATCH_LAZY_EXEC_PAGE_TABLES").as_deref()
        != Some(std::ffi::OsStr::new("0"))
}

impl GuestMappingPlan {
    pub fn from_address_space(address_space: &AddressSpace) -> Result<Self, TrapError> {
        // Default to sharing immutable ELF payloads between the loaded image and
        // mapping plan. The =0 hatch restores the pre-optimization copy so one
        // signed binary can perform a schedule-identical liveness bisection.
        let share_payload = std::env::var_os("CARRICK_HVPATCH_SHARE_EXEC_PAYLOAD").as_deref()
            != Some(std::ffi::OsStr::new("0"));
        let sparse_initial_stack = std::env::var_os("CARRICK_HVPATCH_SPARSE_EXEC_STACK").as_deref()
            != Some(std::ffi::OsStr::new("0"));
        let initial_stack_pointer = address_space.initial_stack_pointer();
        let mut mappings = Vec::with_capacity(address_space.regions().len());
        for region in address_space.regions() {
            let guest_start = align_down(region.start, HVF_PAGE_SIZE);
            // The IPA actually mapped — identity for everything except the
            // Rosetta high-VA window, which is aliased down to a low IPA.
            let ipa_start = align_down(crate::memory::ipa_for_va(region.start), HVF_PAGE_SIZE);
            // Back the FULL Rosetta window (2 MiB) so its page-table block has no
            // unbacked tail; other regions round their end up to a page.
            let guest_end = if crate::memory::is_rosetta_va(region.start) {
                crate::memory::LINUX_ROSETTA_VA_BASE + crate::memory::LINUX_ROSETTA_WINDOW_SIZE
            } else {
                align_up(region.end, HVF_PAGE_SIZE)?
            };
            let mapped_size =
                guest_end
                    .checked_sub(guest_start)
                    .ok_or(TrapError::MappingOverflow {
                        guest_start,
                        mapped_size: 0,
                    })?;
            let mapped_len = usize::try_from(mapped_size)
                .map_err(|_| TrapError::MappingTooLarge(mapped_size))?;
            let mut offset_in_mapping = region.start - guest_start;

            // Keep only the payload bytes, not a full zero-padded copy of the
            // (potentially 512 MiB) mapping. hv_vm_allocate hands back lazily
            // zero-filled, HVF-managed memory, so we write just the payload at
            // its offset and let untouched pages fault in on demand. Building
            // and writing the whole region here is what pinned ~2 GiB resident
            // per guest process for mappings the guest never touches.
            let _ = mapped_len;
            let is_initial_stack = sparse_initial_stack
                && region.start == crate::memory::LINUX_STACK_TOP - crate::memory::LINUX_STACK_SIZE
                && region.end == crate::memory::LINUX_STACK_TOP;
            let image = if is_initial_stack {
                let stack_pointer = initial_stack_pointer.ok_or_else(|| {
                    TrapError::Hypervisor(
                        "initial stack region has no initial stack pointer".to_owned(),
                    )
                })?;
                let payload_offset = align_down(
                    stack_pointer.checked_sub(region.start).ok_or_else(|| {
                        TrapError::Hypervisor(
                            "initial stack pointer lies below stack region".to_owned(),
                        )
                    })?,
                    HVF_PAGE_SIZE,
                );
                let (initialized_offset, initialized) = region.shared_initialized_bytes();
                let within_payload =
                    payload_offset
                        .checked_sub(initialized_offset)
                        .ok_or_else(|| {
                            TrapError::Hypervisor(
                                "initial stack payload precedes initialized window".to_owned(),
                            )
                        })?;
                let payload_offset_usize = usize::try_from(within_payload)
                    .map_err(|_| TrapError::MappingTooLarge(within_payload))?;
                let payload = initialized.get(payload_offset_usize..).ok_or_else(|| {
                    TrapError::Hypervisor("initial stack payload offset exceeds backing".to_owned())
                })?;
                offset_in_mapping = offset_in_mapping.checked_add(payload_offset).ok_or(
                    TrapError::MappingOverflow {
                        guest_start,
                        mapped_size,
                    },
                )?;
                if share_payload && within_payload == 0 {
                    initialized
                } else {
                    std::sync::Arc::new(payload.to_vec())
                }
            } else if share_payload {
                region.shared_bytes()
            } else {
                std::sync::Arc::new(region.bytes().to_vec())
            };

            mappings.push(GuestMapping {
                guest_start,
                ipa_start,
                mapped_size,
                offset_in_mapping,
                payload_size: image.len() as u64,
                perms: region.perms,
                shared: region.shared,
                image,
                #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
                private_file_backing: None,
            });
        }

        Ok(Self {
            entry: address_space.entry(),
            initial_stack_pointer: address_space.initial_stack_pointer(),
            el0_trampoline_entry: address_space.el0_trampoline_entry(),
            el1_vectors_base: address_space.el1_vectors_base(),
            stage1_page_tables_base: address_space.stage1_page_tables_base(),
            ro_spans: address_space.ro_spans().to_vec(),
            mappings,
        })
    }
}

impl HvfVmState {
    pub(crate) fn seed_readonly_spans_from_plan(&self, plan: &GuestMappingPlan) {
        for span in &plan.ro_spans {
            let Ok(len) = usize::try_from(span.len) else {
                continue;
            };
            self.protections.set_no_write(span.start, len, true);
        }
    }

    /// Boot a container root: create the carrier VM (first root) or reuse the
    /// live one (later roots), map the guest address space, and stage the
    /// root's first-instruction registers as data. No vCPU is created: every
    /// vCPU lives for its VM's whole life (EL1 plan 1a D2), so the root runs on
    /// a persistent executor's vCPU, which restores the staged state.
    pub(crate) fn new_with_plan(
        plan: &GuestMappingPlan,
    ) -> Result<(HvfVmState, crate::staged_cpu::StagedCpu), TrapError> {
        let mut pending_creation = None;
        let result = Self::new_with_plan_inner(plan, &mut pending_creation);
        finish_pending_vm_creation(pending_creation, result)
    }

    fn new_with_plan_inner(
        plan: &GuestMappingPlan,
        pending_creation: &mut Option<PendingCarrierVmCreation>,
    ) -> Result<(HvfVmState, crate::staged_cpu::StagedCpu), TrapError> {
        // Carrier reuse: when this carrier already owns a VM, a new container's
        // root boots INSIDE it. Its image is placed the way `execve_rebuild`
        // places a replacement image (global-frame stage-2 leases + rebased
        // stage-1 tables), so two live roots never collide on identity IPAs,
        // and the six carrier control mappings are shared, not re-mapped.
        //
        // The boot gate is held across the first root's `hv_vm_create`, so two
        // roots racing here cannot both create (HV_BUSY for the loser); a root
        // that finds the VM live but the bundle not yet published waits for
        // the first root's `take_persistent_executor_spec`.
        let boot_gate = carrier_root_boot_gate().lock();
        let carrier: Option<PersistentExecutorSpec> = if carrier_vm_live() {
            let mut cell = persistent_carrier_cell().lock();
            while cell.is_none() {
                if carrier_published()
                    .wait_for(&mut cell, CARRIER_PUBLISH_WAIT)
                    .timed_out()
                {
                    return Err(TrapError::Hypervisor(
                        "carrier VM is live but its executor bundle was never published".to_owned(),
                    ));
                }
            }
            match cell.as_ref() {
                Some(PersistentCarrierCellEntry::Published(spec)) => Some(spec.clone()),
                Some(PersistentCarrierCellEntry::CreateCleanup { .. }) => {
                    return Err(TrapError::Hypervisor(
                        "carrier VM creation cleanup is pending retry".to_owned(),
                    ));
                }
                None => unreachable!(),
            }
        } else {
            None
        };
        let mut global_plan = match &carrier {
            Some(spec) => {
                spec.carrier_mappings.audit()?;
                audit_plan_against_installed_carrier(plan, &spec.carrier_mappings)?;
                Some(prepare_global_exec_plan(plan, None)?)
            }
            None => None,
        };
        let (
            vm,
            _permit,
            syscall_transport,
            mailbox_slots,
            carrier_mappings,
            carrier_foreign_mm_transport,
        ) = match &carrier {
            Some(spec) => (
                // A VM rebuilt since publication supersedes the bundle's handle,
                // exactly as `from_persistent_executor_spec` reads it.
                rebuilt_vm_cell()
                    .lock()
                    .clone()
                    .unwrap_or_else(|| spec.vm.clone()),
                None,
                spec.syscall_transport,
                std::sync::Arc::clone(&spec.mailbox_slots),
                Some(std::sync::Arc::clone(&spec.carrier_mappings)),
                std::sync::Arc::clone(&spec.carrier_foreign_mm_transport),
            ),
            None => {
                let carrier_foreign_mm_transport =
                    std::sync::Arc::new(CarrierForeignMmTransport::new());
                let (syscall_transport, (vm, permit, creation)) =
                    prepare_initial_carrier_before_admission(
                        || {
                            HvfSyscallTransport::from_env()
                                .map_err(|error| TrapError::Hypervisor(error.to_string()))
                        },
                        || {
                            create_vm_with_admission(
                                VmCreateAdmission::Initial,
                                &carrier_foreign_mm_transport.custody,
                            )
                        },
                    )?;
                *pending_creation = Some(creation);
                (
                    vm,
                    permit,
                    syscall_transport,
                    std::sync::Arc::new(MailboxSlotAllocator::new()),
                    None,
                    carrier_foreign_mm_transport,
                )
            }
        };
        let vm = SetupVmGuard::new(vm, carrier.is_none());
        drop(boot_gate);

        #[cfg(not(test))]
        let custody = std::sync::Arc::clone(&carrier_foreign_mm_transport.custody);
        let mut state = HvfVmState {
            _vm: std::mem::ManuallyDrop::new(vm.into_inner()),
            carrier_foreign_mm_transport,
            task: HvfTaskState {
                #[cfg(not(test))]
                custody,
                mappings: TaskMappingIndex::new(),
                mm_root_slot: None,
                container_root: ContainerRootToken::next(),
                pending_exec_mm_root_slot: None,
                pending_exec_asid: None,
                pending_exec_predecessor_identity: None,
                pending_exec_stage2_cleanup: None,
                shared_process_mm: false,
                mm_access: MmAccessState::new(
                    carrick_aarch64::Stage1Authority::new(),
                    std::sync::Arc::new(MemoryProtections::default()),
                    std::sync::Arc::new(parking_lot::Mutex::new(HvpatchFrameInventory::default())),
                    std::sync::Arc::new(parking_lot::Mutex::new(CowArmedRanges::default())),
                    std::sync::Arc::new(parking_lot::Mutex::new(Vec::new())),
                ),
                last_exit_class: 0,
                last_fault_esr: 0,
                is_forked_child: false,
                forked_no_exec: false,
                last_syscall_nr: None,
                last_syscall_orig_x0: 0,
                live_vcpu: crate::vcpu_kick::LiveVcpuSlot::new(),
                persistent_vm_lifecycle: false,
                cow_authority: None,
                cow_identity: None,
                pending_fork_frame_receipts: Vec::new(),
                pending_process_aliases: Vec::new(),
                fail_next_begin_exec_inventory: false,
                cow_rollback_scratch: None,
                registration: None,
            },
            carrier_mappings,
            mailbox_slots,
            syscall_transport,
            executor_vcpu: None,
            cached_fork_alias_snapshot: parking_lot::Mutex::new(None),
            last_fork_host_mapping_allocations: std::sync::atomic::AtomicU64::new(0),
            last_fork_projection_rows_visited: std::sync::atomic::AtomicU64::new(0),
        };
        state.seed_readonly_spans_from_plan(plan);

        // Reuse lane: map the relocated image with owning stage-2 leases (the
        // exec placement); first-boot lane: the identity `map_region_raw`
        // placement. `plan` is rebound so the register programming below reads
        // the relocated stage-1 table root (guest VAs are unchanged).
        let plan: &GuestMappingPlan = match global_plan.as_mut() {
            Some(GlobalExecPlan {
                plan: relocated,
                stage2_leases,
            }) => {
                for mapping in relocated.mappings.iter().filter(|mapping| {
                    !is_sparse_hvpatch_mmap_mapping(mapping)
                        && !is_persistent_executor_carrier_guest_mapping(mapping)
                }) {
                    let key = (mapping.ipa_start, mapping.mapped_size);
                    let mut lease = stage2_leases.remove(&key).ok_or_else(|| {
                        TrapError::Hypervisor(format!(
                            "carrier root mapping IPA 0x{:x} size {} has no owning lease",
                            key.0, key.1
                        ))
                    })?;
                    let mut region = prepare_exec_region_raw_in(
                        &state.carrier_foreign_mm_transport.custody,
                        mapping,
                    )?;
                    let install = exec_stage2_install(mapping, &region, false);
                    let rc = unsafe {
                        inventory_hv_vm_map(
                            install.host.cast(),
                            install.ipa,
                            install.size,
                            install.perms,
                        )
                    };
                    if rc != 0 {
                        return Err(TrapError::Hypervisor(format!(
                            "map carrier root IPA 0x{:x} size {} failed: 0x{rc:x}",
                            install.ipa, install.size
                        )));
                    }
                    lease.mark_mapped();
                    publish_exec_region_host_owner_in(
                        &state.carrier_foreign_mm_transport.custody,
                        &mut region,
                        lease,
                        None,
                    )?;
                    if let Some(owner) = region.structural_owner.as_ref() {
                        state.mm_access.install_structural_mapping_authority(
                            None,
                            std::sync::Arc::clone(owner),
                        )?;
                    }
                    state.mappings.insert(region);
                }
                if !stage2_leases.is_empty() {
                    return Err(TrapError::Hypervisor(format!(
                        "carrier root left {} reserved stage-2 leases unmaterialized",
                        stage2_leases.len()
                    )));
                }
                relocated
            }
            None => {
                for mapping in plan
                    .mappings
                    .iter()
                    .filter(|mapping| !is_sparse_hvpatch_mmap_mapping(mapping))
                {
                    #[cfg(feature = "trace-hvf")]
                    eprintln!(
                        "MAP guest_start=0x{:x} mapped_size=0x{:x} payload_size=0x{:x} perms=r{}w{}x{}",
                        mapping.guest_start,
                        mapping.mapped_size,
                        mapping.payload_size,
                        if mapping.perms.read { '+' } else { '-' },
                        if mapping.perms.write { '+' } else { '-' },
                        if mapping.perms.execute { '+' } else { '-' },
                    );
                    let region = map_region_raw_in(
                        &state.carrier_foreign_mm_transport.custody,
                        mapping,
                        false,
                        true,
                    )?;
                    // The boot path owns structural tables just like relocated
                    // exec. Publish that ownership to the MM before any guest
                    // fault needs the executor-independent table resolver.
                    if let Some(owner) = region.structural_owner.as_ref() {
                        state.mm_access.install_structural_mapping_authority(
                            None,
                            std::sync::Arc::clone(owner),
                        )?;
                    }
                    state.mappings.insert(region);
                }
                plan
            }
        };
        if carrier.is_none() {
            let replayed = replayed_global_frame_owners_for_regions_in(
                &state.carrier_foreign_mm_transport.custody,
                state.mappings.iter(),
            );
            reconcile_global_frame_owners_after_replay_in(
                &state.carrier_foreign_mm_transport.custody,
                &replayed,
                false,
            )?;
        }

        // The root's first registers (EL0-entry trampoline, stage-1 MMU,
        // FP/SIMD and counter access, vectors, user stack) are programmed as
        // data from the relocated `plan`; see `StagedCpu::initial_root`.
        let staged = crate::staged_cpu::StagedCpu::initial_root(plan);
        if pending_creation.is_some() {
            commit_pending_creation_before_vcpu_handoff(pending_creation)?;
        }
        // Fill the vDSO vvar page so __kernel_clock_gettime can derive time from
        // CNTVCT_EL0 in userspace. After the creation commits: host writes are
        // admitted only against committed backing owners.
        state.populate_vdso_data_page();
        Ok((state, staged))
    }
}
