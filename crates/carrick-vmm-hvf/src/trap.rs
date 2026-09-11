//! # The HVF trap boundary
//!
//! This is the seam where a Linux guest's `svc #0` becomes a host Rust syscall
//! dispatch. carrick runs unmodified Linux ELF code as guest EL0 inside a single
//! Hypervisor.framework VM, with NO Linux kernel underneath it — when the guest
//! issues a syscall, control must cross all the way out to host userspace, get
//! serviced against Darwin primitives, and resume the guest as if a kernel had
//! handled it. This module owns that crossing in both directions.
//!
//! ## Theory of operation: the round trip of one syscall
//!
//! 1. **Guest `svc #0` (EL0).** The guest executes a normal AArch64 supervisor
//!    call. With `SCTLR_EL1.M=1` and our stage-1 identity tables installed, this
//!    is a synchronous exception from the lowest EL.
//! 2. **EL1 vector table (`VBAR_EL1`).** HVF does NOT exit to the host on a bare
//!    EL0 `svc`; it routes the exception to EL1, which is *still inside the VM*.
//!    `map_plan` programs `VBAR_EL1` to a guest-physical vector page (built by
//!    `crate::memory`) whose lower-EL-synchronous entry is a tiny trampoline. The
//!    trampoline runs at EL1 — this is carrick code executing in the guest, never
//!    the guest's own code.
//! 3. **`hvc #2` → EL2 VM-exit.** The vector trampoline issues a hypervisor call.
//!    THAT is what HVF surfaces to the host as an `EXCEPTION` exit from
//!    `hv_vcpu_run`. (Plain EL0 memory aborts HVF cannot satisfy — a stack
//!    overflow running SP off the mapped stack — surface directly as an
//!    `EXCEPTION` exit with `EC=0x20/0x24` instead; see
//!    [`is_aarch64_el0_abort_exception`].) The reason we trampoline through EL1
//!    rather than letting HVF trap the `svc` directly is that the EL1 stage
//!    gives us a place to do stage-1 TLB maintenance (`hvc #1`, see
//!    `HvfInner::run_el1_maintenance`) on a platform whose public HVF has no
//!    stage-2 TLBI.
//! 4. **Host decode.** `HvfInner::run_until_syscall` reads the exit info,
//!    confirms `EC=0x16` (our HVC) *and* that the underlying `ESR_EL1` is an
//!    `svc` (anything else — an ID-register read, a real fault — is handled or
//!    surfaced as [`TrapError::EL0Fault`]), then reads x0..x5/x8 into an
//!    [`Aarch64SyscallFrame`] and returns it to the runtime dispatcher.
//! 5. **Host dispatch + resume.** The dispatcher services the syscall against
//!    Darwin and calls `HvfInner::complete_syscall`, which writes the retval
//!    into x0. The next `hv_vcpu_run` resumes the trampoline's `eret`, dropping
//!    back to EL0 at the instruction after the `svc` (HVF latched that address in
//!    `ELR_EL1` when it took the exception).
//!
//! ## The load-bearing EL0/EL1 invariant
//!
//! The single most important distinction in this module is *whose code is the
//! vCPU running*. EL0 is genuine Linux guest userspace; EL1+ is always carrick's
//! trap trampoline. A PC (or register snapshot) captured at EL1 is a *carrick*
//! address and must NEVER be treated as a guest resume target — injecting a
//! signal frame at an EL1 PC overwrites an in-flight syscall and wedges the
//! thread. [`ExecLevel::from_pstate`] is the systematic classifier; every site
//! that captures a live vCPU PC for guest use must consult it. The kick path in
//! `HvfInner::run_until_syscall` is the sharp example: a cross-thread
//! `hv_vcpus_exit` can land while the vCPU is mid-trampoline at EL1, so it resumes
//! the vCPU to a clean EL0 boundary before reporting the kick (this fixed a real
//! SIGURG storm corrupting a futex waiter at `vectors_base+0x404`).
//!
//! ## The [`SyscallTrap`] contract
//!
//! The runtime loop drives the engine through one trait, [`SyscallTrap`]:
//! `next_syscall` (run until a trap; `Ok(None)` is a no-syscall kick exit),
//! `complete_syscall` (write the retval), process projection / `execve_into`
//! (address-space
//! lifecycle), and the signal pair `inject_signal` / `restore_from_sigframe`.
//! [`HvfTrapEngine`] is the real implementation; the runtime also has a
//! non-HVF `SplitView` adapter, which is why every method has a portable
//! default and a `#[cfg(not(macos+aarch64))]` stub returning
//! [`TrapError::UnsupportedPlatform`]. Errors are typed: most variants carry the
//! syndrome/ELR/FAR so the runtime can translate a guest fault into the right
//! Linux signal, and [`TrapError::SignalDeliveryFault`] specifically models
//! Linux's `force_sigsegv` (an unwritable signal stack kills the thread-group by
//! SIGSEGV rather than fatalling carrick).
//!
//! ## Address-space lifecycle: process projection, clone, execve
//!
//! HVPatch keeps process identity and address spaces inside one carrier. Guest
//! process/thread creation updates Carrick's kernel graph and stage-1 projection;
//! it never creates a host process:
//!
//! - **Process fork** shares stable global
//!   frames read-only across distinct per-mm stage-1 graphs and copies only the
//!   first writer's affected compound frame. Genuine guest `MAP_SHARED`
//!   mappings remain shared.
//! - **Thread clone** (`HvfInner::build_thread_spec` / `from_thread_spec`)
//!   keeps ONE process VM and gives each guest thread its own vCPU in it. The
//!   stage-2 mappings are VM-global, so a sibling only re-materialises local
//!   syscall-path metadata (UNOWNED, `memory: None`) and never frees the main
//!   engine's buffers. Because HVF caps concurrent vCPUs, sibling creation
//!   passes through an admission gate (`wait_for_vcpu_slot`); see the
//!   private `vcpu_gate` module for why a guest that out-threads the cap *blocks*
//!   rather than failing `clone` (Linux has no such cap, so failing would
//!   deadlock a join).
//! - **`execve(2)`** (`HvfInner::execve_into`) tears down and rebuilds the VM
//!   with a brand-new [`AddressSpace`] and resets the vCPU to
//!   "initial process startup" (zeroed GPRs, entry trampoline) rather than
//!   "resume mid-syscall". It has no successful return.
//!
//! ## Signals: synthesising kernel signal delivery in userspace
//!
//! `HvfInner::inject_signal` builds a Linux-shaped `CarrickSigframe` (siginfo +
//! ucontext + a full GPR/PC/SP/PSTATE/FPSIMD snapshot), pushes it onto SP_EL0
//! (or the SA_ONSTACK alt stack), points x30 at the restorer, sets x0..x2 to the
//! handler arguments, and redirects the resumed PC to the handler. On
//! `rt_sigreturn(2)`, `HvfInner::restore_from_sigframe` pops the frame and
//! restores the pre-signal state. Two non-obvious subtleties:
//!
//! - The authoritative pre-signal PSTATE source DIFFERS by injection path. At a
//!   syscall boundary the hardware latched EL0's PSTATE into `SPSR_EL1`; on a
//!   kick exit no exception was taken, so `SPSR_EL1` is stale and `CPSR` holds
//!   the live EL0 state. Reading the wrong one resumes the interrupted routine
//!   with stale NZCV — conditional branches go the wrong way — which was exactly
//!   Go's async-preemption (SIGURG) corruption.
//! - V0–V31 / FPSR / FPCR must round-trip across both signals *and* fork/clone,
//!   or a handler (or post-fork resume) that touches SIMD corrupts the
//!   interrupted thread's vector file. This collides with an `applevisor-sys`
//!   ABI bug: see `set_simd_fp_reg_v` — Apple's `hv_vcpu_set_simd_fp_reg` takes
//!   a 16-byte vector BY VALUE in a V register, but the stable binding mistypes
//!   it as `u128` (passed in a GP register pair), so the kernel reads garbage and
//!   silently zeroes the target register while returning `HV_SUCCESS`. We route
//!   every V-register *write* through a tiny C shim that gets the vector ABI
//!   right on stable Rust; reads are pointer-based and unaffected.
//!
//! ## Guest memory access from the syscall path
//!
//! The dispatcher reads/writes guest buffers through this engine's
//! [`GuestMemory`] impl. Because guest RAM is `MAP_SHARED` and another host
//! thread's vCPU can mutate it concurrently, host-side copies go byte-wise
//! `read_volatile`/`write_volatile` (`volatile_copy_from_guest`) to remove
//! language-level UB (it does NOT make the data race "correct" — the guest owns
//! its own synchronization). Writes from the syscall path are permission-checked
//! (a write into a read-only / carrick-owned mapping returns EFAULT, not a host
//! SIGBUS); carrick-internal writes (vdso, sigframe, bootstrap) use the unchecked
//! path deliberately. High-VA Rosetta aliases can overlap by VA, so region
//! lookup disambiguates by walking the guest's own stage-1 tables to the IPA the
//! guest actually uses (`HvfInner::translate_va`).
//!
//! ## Sharp edges / known limitations
//!
//! - **No stage-2 TLBI on public arm64 HVF.** Guest-visible `mprotect`/`munmap`
//!   semantics are implemented entirely in stage-1 (page-table edits + an EL1
//!   `tlbi` trampoline); the stage-2 mapping is left in place. This is why
//!   munmap'd arena backing is still physically mapped (only stage-1-invalidated)
//!   and why `HvfInner::zero_guest_backing` can scrub a reclaimed region the
//!   permission-checked writes would refuse.
//! - **Stage-2 perm escalation.** `hvf_perms` escalates writable data regions
//!   to `ReadWriteExec` to work around an HVF stage-2 quirk where RW-without-X
//!   mappings fail to translate EL0 data accesses. Guest-visible W^X is enforced
//!   in stage-1 instead.
//! - **Drop is intentionally a no-op.** See above; touching applevisor
//!   destructors post-fork panics.
//! - **`ptr::write`-based in-place replacement.** Rebuilding the engine
//!   (`replace_destroyed_hvf_inner`) and the post-fork/clone VM swaps use
//!   `mem::forget`/`ptr::write` to avoid running Drop on already-raw-destroyed
//!   handles. These are the single sanctioned no-drop replacement points; do not
//!   assign an `HvfInner`/vCPU/VM field normally after a raw teardown.

// The hub types live in the leaf crate carrick-guest-mem (A2); import them from
// there, not via `crate::dispatch`, so trap.rs has NO dependency on the
// dispatcher — the last edge blocking a future carrick-vmm-hvf crate (A3).
use crate::elf::SegmentPerms;
use crate::memory::AddressSpace;
use crate::syscall_mailbox::{
    HvfSyscallTransport, MailboxBinding, MailboxSlotAllocator, MailboxSlotId,
};
use carrick_aarch64::Aarch64VcpuSnapshot;
use carrick_guest_mem::{GuestVa, MemoryError};
use serde::Serialize;
use std::collections::HashMap;
use std::os::fd::AsRawFd;

use carrick_fatal::carrick_fatal;

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod sparse_materialization;

mod sysreg;
use sysreg::*;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod carrier_custody;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod global_frame;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) use global_frame::*;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod foreign_mm;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod frame_inventory;
mod memory_protection;
pub(crate) use self::memory_protection::*;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) use carrier_custody::*;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub use foreign_mm::HvpatchMmRootRetirementProof;
#[cfg(all(
    target_os = "macos",
    target_arch = "aarch64",
    feature = "foreign-cow-test-support"
))]
pub use foreign_mm::foreign_cow_test_support;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) use foreign_mm::*;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) use frame_inventory::*;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod task_mapping_index;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) use task_mapping_index::*;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod vcpu_admission;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod vcpu_gate;
pub use vcpu_admission::cooperative_release_atomic_permit;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) use vcpu_admission::*;
// The vvar clock calibration sources (a frequency-only EL0 read plus the
// CLOCK_UPTIME_RAW monotonic base). The raw counter pair remains exported for
// explicit divergence diagnostics, not production calibration. The
// Darwin-native backend's vvar stamper uses the identical frequency/uptime
// sources as `populate_vdso_data_page` below.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub use sysreg::{host_clock_uptime_ns, host_counter, host_counter_frequency};

// Process-wide PROT_NONE bookkeeping is a neutral-core abstraction shared with
// every other backend (KVM included) — see carrick_mem::protections. Both hold
// it as `Arc<MemoryProtections>` and clone it into each sibling vCPU thread.
use carrick_mem::protections::MemoryProtections;

// SyscallTrap/TrapError moved down into the carrick-hal leaf crate
// (the runtime↔engine contract is platform-agnostic). Re-export them here so
// existing `crate::trap::…` paths in carrick-vmm-hvf and carrick-runtime are
// unchanged. HvfTrapEngine below implements the trait from its new home.
use carrick_hal::aarch64::ExecLevel;
// The ESR exception-class decode surface (classifier fns + the SVC/HVC class
// consts) hoisted into carrick_hal::aarch64 must stay PUB-re-exported here:
// `carrick_runtime::trap` is this module on macOS, and external consumers (the
// trap_hvf integration test) import the classifiers through that path. A plain
// `use` made them private and broke `cargo test -p carrick-runtime`
// (E0603/E0432 in tests/trap_hvf.rs).
pub use carrick_hal::aarch64::{
    AARCH64_HVC_EXCEPTION_CLASS, AARCH64_SVC_EXCEPTION_CLASS, aarch64_exception_class,
    is_aarch64_hvc_exception, is_aarch64_hvc_fault, is_aarch64_hvc_maintenance,
    is_aarch64_svc_exception, is_aarch64_syscall_exception,
};
use carrick_hal::trap::{HostAliasBacking, HostAliasSharing};
pub use carrick_hal::trap::{RawSyscall, SyscallTrap, TrapError};

pub const HVF_PAGE_SIZE: u64 = 0x4000;
// Guest stage-1 uses a 4 KiB granule even though HVF maps stage-2 in 16 KiB
// chunks. Syscall memory copies must reselect the backing at this boundary.
const GUEST_STAGE1_PAGE_SIZE: u64 = 0x1000;
// ESR exception-class decode (svc/hvc/maintenance/syscall classifiers, the
// SVC/HVC class consts, and ExecLevel) live in the shared carrick_hal::aarch64
// module — imported above. This SHIFT is kept local only for the counter-trap
// TESTS that synthesize an ESR syndrome (cntfrq/cntvct/dczid), so it is test-only.
#[cfg(test)]
const AARCH64_EXCEPTION_CLASS_SHIFT: u64 = 26;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TrapBackend {
    HypervisorFramework,
}

#[cfg(test)]
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) mod foreign_mm_tests {
    pub(super) static FOREIGN_MM_TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
    pub(crate) use super::foreign_mm::tests::ExternalAliasStateRestore;
}

#[cfg(test)]
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) mod task_only_carrier_directory_tests;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct TrapCapabilities {
    pub backend: TrapBackend,
    pub available_on_this_host: bool,
    pub implemented: bool,
}

pub fn hvf_capabilities() -> TrapCapabilities {
    TrapCapabilities {
        backend: TrapBackend::HypervisorFramework,
        available_on_this_host: cfg!(all(target_os = "macos", target_arch = "aarch64")),
        implemented: cfg!(all(target_os = "macos", target_arch = "aarch64")),
    }
}

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
    image: std::sync::Arc<Vec<u8>>,
    /// Optional immutable, fully-patched file artifact for a private RX
    /// mapping. Every exec creates a fresh MAP_PRIVATE host view; the artifact
    /// itself is cached and never mutated.
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[serde(skip)]
    private_file_backing: Option<ExecPrivateFileBacking>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Debug)]
struct ExecPrivateFileBacking {
    identity: u64,
    file: std::sync::Arc<std::fs::File>,
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
fn cached_exec_private_file_backing(
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
fn attach_exec_private_file_backings(plan: &mut GuestMappingPlan) -> Result<(), TrapError> {
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
fn lazy_exec_page_tables_enabled() -> bool {
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

// The public HVF trap engine IS `Aarch64EngineCore<HvfAarch64Vmm>`: the shared
// `carrick-aarch64` scaffold parameterized over the thin HVF backend trait pair
// (`crate::hvf_aarch64_engine`). Every existing `crate::trap::HvfTrapEngine`
// reference (carrick-runtime's run loop, the integration tests) resolves through
// this alias unchanged. The trap loop / register walk / guest-memory gate /
// fork/execve/sibling sequencing / threaded lifecycle now live ONCE in
// carrick-aarch64; the HVF-specific atoms below feed it through the trait pair.
//
// The leak-until-exit Drop discipline (NEVER run applevisor's Vcpu /
// VirtualMachine destructors after a `fork(2)`, or they panic with "no VM or
// vCPU available") now lives per-half: `HvfAarch64Vcpu`'s `Drop` skips
// `ManuallyDrop::drop`, and `HvfVmState` holds the VM in a no-op `ManuallyDrop`.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub type HvfTrapEngine =
    carrick_aarch64::Aarch64EngineCore<crate::hvf_aarch64_engine::HvfAarch64Vmm>;

/// Bring up the HVF trap engine from a loaded image: create the VM + vCPU, map
/// the guest address space, and park the vCPU at the EL0-entry trampoline. The
/// runtime calls this instead of the old `HvfTrapEngine::new()` + `map_plan`.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub fn new_hvf_trap_engine(image: &AddressSpace) -> Result<HvfTrapEngine, TrapError> {
    crate::hvf_aarch64_engine::bring_up(image)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
const GPR_TABLE: [applevisor::vcpu::Reg; 31] = [
    applevisor::vcpu::Reg::X0,
    applevisor::vcpu::Reg::X1,
    applevisor::vcpu::Reg::X2,
    applevisor::vcpu::Reg::X3,
    applevisor::vcpu::Reg::X4,
    applevisor::vcpu::Reg::X5,
    applevisor::vcpu::Reg::X6,
    applevisor::vcpu::Reg::X7,
    applevisor::vcpu::Reg::X8,
    applevisor::vcpu::Reg::X9,
    applevisor::vcpu::Reg::X10,
    applevisor::vcpu::Reg::X11,
    applevisor::vcpu::Reg::X12,
    applevisor::vcpu::Reg::X13,
    applevisor::vcpu::Reg::X14,
    applevisor::vcpu::Reg::X15,
    applevisor::vcpu::Reg::X16,
    applevisor::vcpu::Reg::X17,
    applevisor::vcpu::Reg::X18,
    applevisor::vcpu::Reg::X19,
    applevisor::vcpu::Reg::X20,
    applevisor::vcpu::Reg::X21,
    applevisor::vcpu::Reg::X22,
    applevisor::vcpu::Reg::X23,
    applevisor::vcpu::Reg::X24,
    applevisor::vcpu::Reg::X25,
    applevisor::vcpu::Reg::X26,
    applevisor::vcpu::Reg::X27,
    applevisor::vcpu::Reg::X28,
    applevisor::vcpu::Reg::X29,
    applevisor::vcpu::Reg::X30,
];

/// Process-wide handoff for multithreaded fork: the forking thread (parent),
/// after rebuilding its VM, publishes a clone here so quiesced sibling threads
/// recreate their vCPUs in the same (new) process VM.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
type SharedVm = applevisor::vm::VirtualMachineInstance<applevisor::vm::GicDisabled>;

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn rebuilt_vm_cell() -> &'static parking_lot::Mutex<Option<SharedVm>> {
    static CELL: std::sync::OnceLock<parking_lot::Mutex<Option<SharedVm>>> =
        std::sync::OnceLock::new();
    CELL.get_or_init(|| parking_lot::Mutex::new(None))
}

/// Carrier-lifetime HVF VM authority: the ONE `hv_vm_create` per carrier plus
/// the five VM-global control mappings and the mailbox-slot allocator that
/// every container's executors share (`PersistentExecutorSpec`).
///
/// Published by the FIRST root bring-up (`HvfVmState::take_persistent_executor_spec`),
/// consumed by every LATER root bring-up (`HvfVmState::new_with_plan` builds
/// the new container's root inside this VM instead of calling `hv_vm_create`,
/// which would return `HV_BUSY`), and drained exactly once by
/// [`destroy_persistent_vm_at_carrier_exit`]. It is never drained at a
/// container's run terminal: containers come and go inside one VM. Readers
/// still consult [`rebuilt_vm_cell`] first, exactly as
/// `from_persistent_executor_spec` does, so a VM rebuilt after publication
/// supersedes the bundle's handle.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone)]
enum PersistentCarrierCellEntry {
    Published(PersistentExecutorSpec),
    CreateCleanup {
        custody: std::sync::Arc<CarrierVmCustody>,
        generation: CarrierVmGeneration,
        vcpu_id: Option<applevisor_sys::hv_vcpu_t>,
        raw_vm_destroyed: bool,
    },
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn persistent_carrier_cell() -> &'static parking_lot::Mutex<Option<PersistentCarrierCellEntry>> {
    static CELL: std::sync::OnceLock<parking_lot::Mutex<Option<PersistentCarrierCellEntry>>> =
        std::sync::OnceLock::new();
    CELL.get_or_init(|| parking_lot::Mutex::new(None))
}

/// Signalled by `take_persistent_executor_spec` when the first root publishes
/// the carrier bundle; paired with `persistent_carrier_cell`'s mutex.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn carrier_published() -> &'static parking_lot::Condvar {
    static PUBLISHED: parking_lot::Condvar = parking_lot::Condvar::new();
    &PUBLISHED
}

/// Whether this carrier has already retired the boot loader's eager mmap arena.
///
/// The retirement is a VM-wide `hv_vm_unmap` performed during a container's
/// root bring-up, so it must happen exactly once for the carrier's VM rather
/// than once per container: a second unmap would remove sparse arena pages a
/// sibling container has already faulted in. Carrier scope is the correct
/// scope here — the arena belongs to the VM, not to a Linux process — and is
/// cleared with the VM in `record_vm_released` so a rebuilt VM retires its own
/// fresh eager mapping.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn carrier_initial_arena_retired() -> &'static std::sync::atomic::AtomicBool {
    static RETIRED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    &RETIRED
}

/// Serializes the "does this carrier own a VM yet?" decision across roots
/// booting at the same time. Held across the FIRST root's `hv_vm_create`, so
/// a second root arriving mid-create observes `carrier_vm_live()` and waits
/// for the published bundle instead of issuing its own `hv_vm_create`
/// (which would return `HV_BUSY`).
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn carrier_root_boot_gate() -> &'static parking_lot::Mutex<()> {
    static GATE: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
    &GATE
}

/// Bound on how long a later root waits for the first root to publish the
/// carrier bundle (publication happens at that root's persistent-lane start,
/// before any guest instruction runs).
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
const CARRIER_PUBLISH_WAIT: std::time::Duration = std::time::Duration::from_secs(60);

/// Whether this carrier currently owns a live HVF VM. Set on the single create
/// funnel's success (`create_vm_with_admission`), cleared by
/// `record_vm_released` after a successful `hv_vm_destroy`.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
static CARRIER_VM_LIVE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// True while this carrier owns a live HVF VM.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub fn carrier_vm_live() -> bool {
    CARRIER_VM_LIVE.load(std::sync::atomic::Ordering::Acquire)
}

/// How guest-visible sharing maps onto the host and HVPatch's one VM.
///
/// `ForkSharedAnonymous` deliberately shares only the host backing and explicit
/// fork-child descriptor. It stays in the owning mm's IPA scope and does not
/// acquire shared-file futex identity. `GlobalShared` is the existing shared
/// aperture / MAP_SHARED-file behavior whose IPA is VM-global.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[allow(dead_code)] // Stage-2 mapping is compiled out by the host-test support feature.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum GuestMappingSharing {
    Private,
    ForkSharedAnonymous,
    GlobalShared,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl GuestMappingSharing {
    fn shares_across_fork(self) -> bool {
        self != Self::Private
    }

    fn uses_global_ipa(self) -> bool {
        self == Self::GlobalShared
    }

    fn has_shared_futex_identity(self) -> bool {
        self != Self::Private
    }
}

/// Process-global registry of dynamic alias mappings, so a vCPU can
/// re-establish one in ITS shared VM after fork dropped it.
///
/// Threads share ONE hv_vm, but `fork()` tears that VM down and rebuilds it from
/// ONLY the forking thread's per-thread `mappings` list (see `HvfInner::fork`).
/// A global-shared alias mapped by a SIBLING thread is therefore lost from the
/// rebuilt VM, and any later access stage-2-faults (the go-build telemetry
/// counter: a counter file `mmap(MAP_SHARED)`'d on one thread, read via LDAR on
/// another after `go` forks `compile`). arm64 HVF has no stage-2 TLB shootdown,
/// so we cannot push the map to siblings eagerly; instead each vCPU LAZILY
/// re-maps on the fault, keyed off this registry.
///
/// Every alias is registered for thread fallback. The sharing classification
/// decides whether its IPA is process-scoped or global and whether fork reuses
/// the backing; those decisions must not be inferred from host `MAP_SHARED`.
/// A high-VA alias's IPA window → host backing, registered PROCESS-GLOBALLY. Two
/// roles: (1) the stage-2 lazy on-fault re-map (a vCPU whose forked VM lost an
/// alias re-establishes it), and (2) the SYSCALL-PATH cross-thread fallback —
/// `mapping_for_range` consults this when a guest buffer lives in a high-VA alias
/// ANOTHER thread mapped (each `HvfInner.mappings` is per-thread; Go's heap arenas
/// are shared across goroutines, so a sibling-mapped arena was invisible to a
/// thread's syscall and EFAULTed). The VA→IPA half is already process-shared
/// (`translate_va` over the Arc-shared page tables); this supplies the IPA→host
/// half. Stores a NON-OWNING raw `host_addr` only (never an OwnedHostMapping), so
/// it never participates in Drop / double-free; the backing's lifetime stays with
/// the owning thread's `mappings` Vec and this entry is removed on `munmap`
/// (`unregister_alias`).
/// A unique monotonic token identifying a container root address space within
/// the carrier.
///
/// This distinguishes private alias ownership across independent containers
/// sharing the single VM carrier, without conflating ownership scope with
/// stage-1 page table root slot allocations. It identifies container instance
/// scope in the VMM layer; it is not a guest PID or a security boundary.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct ContainerRootToken(u64);

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl ContainerRootToken {
    /// The sentinel used by fixtures and by contexts that predate container
    /// minting. Minted tokens never take this value — see [`Self::next`].
    pub const ROOT: Self = Self(1);

    /// Mints a fresh, distinct token for a new container root.
    ///
    /// Starts ABOVE [`Self::ROOT`] deliberately: a minted token that aliased
    /// the sentinel would make the first container's private aliases match
    /// every ROOT-scoped alias again, which is the exact collision this type
    /// exists to remove.
    pub fn next() -> Self {
        static NEXT_ID: std::sync::atomic::AtomicU64 =
            std::sync::atomic::AtomicU64::new(ContainerRootToken::ROOT.0 + 1);
        Self(NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed))
    }

    pub fn from_raw(raw: u64) -> Self {
        Self(raw)
    }

    pub fn raw(self) -> u64 {
        self.0
    }
}

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct ContainerRootToken(u64);

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
impl ContainerRootToken {
    pub const ROOT: Self = Self(1);

    pub fn from_raw(raw: u64) -> Self {
        Self(raw)
    }

    pub fn raw(self) -> u64 {
        self.0
    }
}

// Futex-word keying for `MAP_SHARED` file mappings lives in
// `carrick_host::futex_key` (portable POSIX) so the native (DSR) backend
// derives its waiter keys with the SAME scheme on every host OS. Re-exported
// here because this trap layer is where the keys are consumed on HVF.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub use carrick_host::futex_key::{shared_file_key_base, shared_futex_waiter_key};

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn alias_registry() -> &'static parking_lot::Mutex<AliasRegistry> {
    static CELL: std::sync::OnceLock<parking_lot::Mutex<AliasRegistry>> =
        std::sync::OnceLock::new();
    CELL.get_or_init(|| parking_lot::Mutex::new(AliasRegistry::default()))
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
type GlobalFrameHostOwnerDirectory =
    parking_lot::Mutex<std::collections::BTreeMap<(u64, u64), GlobalFrameOwnerEntry>>;

#[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
fn global_frame_host_owners() -> &'static GlobalFrameHostOwnerDirectory {
    &legacy_test_carrier_vm_custody().global_frame_host_owners
}

#[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
fn legacy_test_carrier_vm_custody() -> &'static CarrierVmCustody {
    legacy_test_carrier_vm_custody_arc().as_ref()
}

#[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
fn legacy_test_carrier_vm_custody_arc() -> &'static std::sync::Arc<CarrierVmCustody> {
    static CELL: std::sync::OnceLock<std::sync::Arc<CarrierVmCustody>> = std::sync::OnceLock::new();
    CELL.get_or_init(|| std::sync::Arc::new(CarrierVmCustody::new_live_fixture()))
}

#[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
fn carrier_stage2_leases()
-> &'static parking_lot::Mutex<std::collections::BTreeMap<(u64, u64), CarrierStage2RecordIdentity>>
{
    &legacy_test_carrier_vm_custody_arc().carrier_stage2_records
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
/// Process-global count of live HVF vCPUs, managed via [`carrick_hal::VcpuCensus`].
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub fn vcpu_census() -> &'static carrick_hal::VcpuCensus {
    carrick_hal::vcpu_census::global()
}
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) static VCPU_CREATED_TOTAL: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
thread_local! {
    static THREAD_VCPU_CREATED_TOTAL: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn current_thread_vcpu_created_total() -> u64 {
    THREAD_VCPU_CREATED_TOTAL.get()
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn vcpu_created() {
    VCPU_CREATED_TOTAL.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    THREAD_VCPU_CREATED_TOTAL.set(THREAD_VCPU_CREATED_TOTAL.get().saturating_add(1));
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(super) fn global_vcpu_permits() -> &'static std::sync::Mutex<GlobalVcpuPermitState> {
    static PERMITS: std::sync::OnceLock<std::sync::Mutex<GlobalVcpuPermitState>> =
        std::sync::OnceLock::new();
    PERMITS.get_or_init(|| std::sync::Mutex::new(GlobalVcpuPermitState::default()))
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(super) fn permit_region() -> &'static PermitRegion {
    static REGION: std::sync::OnceLock<PermitRegion> = std::sync::OnceLock::new();
    REGION.get_or_init(PermitRegion::new_shared_global)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(super) fn vm_residency_region() -> &'static PermitRegion {
    static REGION: std::sync::OnceLock<PermitRegion> = std::sync::OnceLock::new();
    REGION.get_or_init(PermitRegion::new_shared_global_vm)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub fn destroy_persistent_vm_at_carrier_exit() -> Result<(), TrapError> {
    if !carrier_vm_live() {
        let terminal = persistent_carrier_cell().lock().take();
        let Some(entry) = terminal else {
            return Ok(());
        };
        if let PersistentCarrierCellEntry::CreateCleanup {
            custody,
            generation,
            mut vcpu_id,
            mut raw_vm_destroyed,
        } = entry
        {
            if let Err(error) = drive_pending_carrier_vm_cleanup(
                &custody,
                generation,
                &mut vcpu_id,
                &mut raw_vm_destroyed,
                "carrier create-cleanup retry",
            ) {
                *persistent_carrier_cell().lock() =
                    Some(PersistentCarrierCellEntry::CreateCleanup {
                        custody,
                        generation,
                        vcpu_id,
                        raw_vm_destroyed,
                    });
                return Err(error);
            }
            return Ok(());
        }
        let PersistentCarrierCellEntry::Published(carrier) = entry else {
            unreachable!()
        };
        let custody = std::sync::Arc::clone(&carrier.carrier_foreign_mm_transport.custody);
        if let Err(error) = finalize_carrier_exit_global_frame_owners_in(&custody) {
            *persistent_carrier_cell().lock() =
                Some(PersistentCarrierCellEntry::Published(carrier));
            return Err(error);
        }
        carrier
            .carrier_mappings
            .mark_vm_destroyed_after_custody_commit()?;
        drop(carrier);
        return Ok(());
    }
    let entry = persistent_carrier_cell().lock().take().ok_or_else(|| {
        TrapError::Hypervisor("carrier-exit live VM has no published carrier custody".to_owned())
    })?;
    let PersistentCarrierCellEntry::Published(carrier) = entry else {
        *persistent_carrier_cell().lock() = Some(entry);
        return Err(TrapError::Hypervisor(
            "carrier-exit live VM has only create-cleanup custody".to_owned(),
        ));
    };
    let custody = std::sync::Arc::clone(&carrier.carrier_foreign_mm_transport.custody);
    // Keep the published bundle recoverable until raw destroy succeeds. A
    // failed destroy leaves the exact VM live, so its publication must remain
    // reachable for retry rather than disappearing with a provisional take.
    if let Err(error) = destroy_vm_with_custody(&custody, "carrier-exit") {
        *persistent_carrier_cell().lock() = Some(PersistentCarrierCellEntry::Published(carrier));
        return Err(error);
    }
    // A successful raw destroy is the terminal authority for every exact VM
    // record. Pending pre-destroy unmap failures cannot veto that success.
    // Carrier exit has no replay successor, so every remaining logical owner
    // is retired after terminalization.
    if let Err(error) = finalize_carrier_exit_global_frame_owners_in(&custody) {
        *persistent_carrier_cell().lock() = Some(PersistentCarrierCellEntry::Published(carrier));
        return Err(error);
    }
    carrier
        .carrier_mappings
        .mark_vm_destroyed_after_custody_commit()?;
    drop(carrier);
    Ok(())
}

/// Whether the atomic slot-table admission permit is active; cached once.
///
/// The atomic permit is the DEFAULT: it is enabled UNLESS
/// `CARRICK_HVF_ATOMIC_PERMIT` is explicitly set to a falsey value
/// (`0`/`false`/`no`, case-insensitive), which selects the legacy flock
/// permit path (byte-for-byte unchanged) as a fallback. Unset → atomic on.
/// `=1` (or any other value) → atomic on.
/// Pure env → enabled mapping for [`atomic_permit_enabled`], factored out so it
/// can be unit-tested without touching the process-global `FLAG` cache or the
/// (unsafe, in edition 2024) `set_var`. Atomic is the default: enabled unless
/// the value is an explicit falsey token (`0`/`false`/`no`, case-insensitive).
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub fn atomic_permit_enabled() -> bool {
    use std::sync::atomic::{AtomicU8, Ordering};
    static FLAG: AtomicU8 = AtomicU8::new(0);
    match FLAG.load(Ordering::Relaxed) {
        1 => true,
        2 => false,
        _ => {
            let on = atomic_permit_enabled_from_env(
                std::env::var("CARRICK_HVF_ATOMIC_PERMIT").ok().as_deref(),
            );
            FLAG.store(if on { 1 } else { 2 }, Ordering::Relaxed);
            on
        }
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(super) fn admission_trace_enabled() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var_os("CARRICK_HVF_ADMISSION_TRACE").is_some())
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn create_vm_with_admission(
    admission: VmCreateAdmission,
    custody: &std::sync::Arc<CarrierVmCustody>,
) -> Result<
    (
        applevisor::vm::VirtualMachineInstance<applevisor::vm::GicDisabled>,
        Option<HeldPermitGuard>,
        PendingCarrierVmCreation,
    ),
    TrapError,
> {
    // Soft pre-throttle: acquire an admitted slot (bounded by GLOBAL_VCPU_CEILING)
    // BEFORE creating; held across HV_NO_RESOURCES retries below. The acquire is
    // bounded (ADMISSION_PERMIT_MAX_WAIT) — persistent exhaustion propagates as
    // a typed error instead of parking here forever.
    let permit = match admission.global_permit_budget() {
        Some(budget) => Some(HeldPermitGuard::new(acquire_admission_permit(budget)?)),
        None => None,
    };
    let generation = custody
        .begin_create()
        .map_err(|error| custody_transition_error("hv_vm_create", "begin_create", error))?;
    let create_result = {
        // Config is rebuilt per attempt inside the closure because
        // `with_config` consumes it, so an HV_NO_RESOURCES retry needs a
        // fresh one.
        crate::probes::vm_lifecycle(0, admission.probe_code());
        create_with_no_resources_backpressure("hv_vm_create", || {
            let config = fresh_vm_config()?;
            virtual_machine_with_private_signals_blocked(config)
        })
    };
    match create_result {
        Ok(vm) => {
            // Publish "this carrier owns a VM" the instant `hv_vm_create`
            // succeeds, which is what this flag has always DOCUMENTED ("set on
            // the single create funnel's success"). It used to be published by
            // `PendingCarrierVmCreation::commit`, far later in root setup, and
            // `carrier_root_boot_gate` is released as soon as the create
            // returns -- so a second root could take the gate, still read
            // `carrier_vm_live() == false`, and issue its own `hv_vm_create`.
            // HVF allows one VM per process, so that second create returned
            // HV_BUSY and the container failed to start: the concurrent
            // `conformance_container_gate` lane failed with alpha never
            // reaching its rendezvous. A rolled-back creation clears the flag
            // through `record_vm_released` once `hv_vm_destroy` succeeds, and
            // if that destroy fails the flag correctly stays set -- a VM does
            // still exist.
            CARRIER_VM_LIVE.store(true, std::sync::atomic::Ordering::Release);
            Ok((
                vm,
                permit,
                PendingCarrierVmCreation {
                    custody: std::sync::Arc::clone(custody),
                    generation,
                    probe_code: admission.probe_code(),
                    vcpu_id: None,
                    armed: true,
                },
            ))
        }
        Err(error) => {
            custody
                .abort_create(generation)
                .map_err(|abort| custody_transition_error("hv_vm_create", "abort_create", abort))?;
            drop(permit);
            Err(error)
        }
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn virtual_machine_with_private_signals_blocked(
    config: applevisor::vm::VirtualMachineConfig,
) -> applevisor::error::Result<applevisor::vm::VirtualMachineInstance<applevisor::vm::GicDisabled>>
{
    let _guard = crate::host_signal::block_hvf_private_thread_signals();
    applevisor::vm::VirtualMachine::with_config(config)
}

/// Enable EL0 direct reads of `CNTVCT_EL0`/`CNTFRQ_EL0` (`CNTKCTL_EL1.EL0VCTEN |
/// EL0PCTEN`) on a freshly-created vCPU. Must run on EVERY vCPU — initial,
/// per-thread and execve rebuild. If only some vCPUs have it, the others trap
/// CNTVCT and fall back to the host-`Instant` emulation, which is a DIFFERENT
/// clock basis (ns-since-process-start, not the hardware counter the vDSO
/// assumes). That skews the monotonic clock between Go's worker threads, so a
/// timer scheduled on one vCPU is checked against a wildly different time on
/// another and never fires — deadlocking `time.After`/timer tests with absurd
/// (e.g. "179h") waits. Best-effort.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn enable_el0_counter_access(vcpu_id: applevisor_sys::hv_vcpu_t) {
    const CNTKCTL_EL1: applevisor_sys::hv_sys_reg_t = applevisor_sys::hv_sys_reg_t::CNTKCTL_EL1;
    unsafe {
        let _ = applevisor_sys::hv_vcpu_set_sys_reg(vcpu_id, CNTKCTL_EL1, (1 << 1) | (1 << 0));
    }
}
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn vcpu_destroyed(vcpu_id: u64) {
    release_admission_permit_for_vcpu(vcpu_id);
    // A slot freed: wake a sibling thread blocked in the admission gate.
    vcpu_gate::notify();
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn audit_hvpatch_executor_boundary(
    state: &HvfVmState,
    mailbox: &MailboxBinding,
) -> Result<(), TrapError> {
    if state.reclaim_authority == ReclaimParkAuthority::Live {
        return Err(TrapError::Hypervisor(
            "HVF executor boundary retained live vCPU authority".to_owned(),
        ));
    }
    if !mailbox.is_released_for_executor_boundary() {
        return Err(TrapError::Hypervisor(
            "HVF executor boundary retained mailbox slot".to_owned(),
        ));
    }
    Ok(())
}

/// V0–V31 SIMD/FP registers, saved/restored across signal delivery alongside
/// the GPRs so a handler that uses SIMD (aarch64 `memcpy`/`memset`, the guest's
/// own handler body) cannot corrupt the interrupted thread's vector state.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) const SIMD_FP_TABLE: [applevisor::vcpu::SimdFpReg; 32] = {
    use applevisor_sys::hv_simd_fp_reg_t::*;
    [
        Q0, Q1, Q2, Q3, Q4, Q5, Q6, Q7, Q8, Q9, Q10, Q11, Q12, Q13, Q14, Q15, Q16, Q17, Q18, Q19,
        Q20, Q21, Q22, Q23, Q24, Q25, Q26, Q27, Q28, Q29, Q30, Q31,
    ]
};

/// Write a 128-bit value into a guest SIMD&FP (V) register.
///
/// Apple's `hv_simd_fp_uchar16_t` is `__attribute__((ext_vector_type(16)))
/// uint8_t` — a 16-byte SIMD vector, which AAPCS64 passes BY VALUE in a vector
/// (V) register. The `applevisor-sys` binding (without the nightly-only
/// `simd-nightly` feature) mistypes the by-value `set` parameter as `u128`,
/// which Rust passes in a general-purpose register PAIR (x2/x3). The kernel
/// then reads the value from a V register and gets unrelated bytes — in
/// practice zeroes — so `hv_vcpu_set_simd_fp_reg` silently corrupts the target
/// register while returning `HV_SUCCESS`. (`get` is unaffected: it is
/// pointer-based, so there is no register-class mismatch.)
///
/// This broke signal delivery: `restore_from_sigframe` could not restore the
/// interrupted thread's V registers, so any signal taken while the guest was
/// mid-SIMD (aarch64 `memmove`/`memequal`, FP math) resumed with zeroed vector
/// state. Under Go that surfaced as the async-preemption (SIGURG) corruption —
/// e.g. runtime `TestUserArena/largeScalar` comparing a buffer whose bytes are
/// intact but whose compare loop returns the wrong answer.
///
/// Passing a 16-byte vector by value across `extern "C"` from Rust needs the
/// nightly `simd_ffi` feature, so we route through a tiny C shim
/// (`carrick_shim.c`) that takes the 16 bytes by pointer and reconstructs the
/// `hv_simd_fp_uchar16_t` for the kernel call — C gets the vector ABI right on
/// stable. Returns the raw `hv_return_t` (0 = `HV_SUCCESS`).
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn set_simd_fp_reg_v(
    vcpu_id: u64,
    reg: applevisor_sys::hv_simd_fp_reg_t,
    value: u128,
) -> i32 {
    unsafe extern "C" {
        fn carrick_set_simd_fp_reg(vcpu: u64, reg: u32, bytes: *const u8) -> i32;
    }
    // u128 -> 16 little-endian bytes, matching the byte order `get_simd_fp_reg`
    // produces, so save/restore round-trips as identity.
    let bytes = value.to_le_bytes();
    unsafe { carrick_set_simd_fp_reg(vcpu_id, reg as u32, bytes.as_ptr()) }
}

/// Which privilege level a vCPU was executing at when carrick observed it. The
/// Full-speed diagnostic counters (the dtrace consumer perturbs the
/// SIGURG-vs-futex race away, so observe with cheap atomics instead). Dumped at
/// process teardown when built with the `debug-stats` feature (the USDT probe
/// fires always; only the stderr dump is gated).
pub static EL1_KICK_RESUMED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
pub static INJECT_AT_EL1: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
pub static KICK_PATH_INJECT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Whether to save/restore guest FP/SIMD across signal handlers (default on;
/// `CARRICK_NO_FPSIMD` disables it for differential measurement). Cached after
/// the first read so the signal hot path doesn't hit the environment.
pub fn fpsimd_save_enabled() -> bool {
    use std::sync::atomic::{AtomicU8, Ordering};
    static FLAG: AtomicU8 = AtomicU8::new(0);
    match FLAG.load(Ordering::Relaxed) {
        1 => true,
        2 => false,
        _ => {
            let on = std::env::var_os("CARRICK_NO_FPSIMD").is_none();
            FLAG.store(if on { 1 } else { 2 }, Ordering::Relaxed);
            on
        }
    }
}

pub fn dump_kick_stats() {
    use std::sync::atomic::Ordering;
    let (el1, inject, at_el1) = (
        EL1_KICK_RESUMED.load(Ordering::Relaxed),
        KICK_PATH_INJECT.load(Ordering::Relaxed),
        INJECT_AT_EL1.load(Ordering::Relaxed),
    );
    // Surface the cumulative totals through one cheap USDT fire at exit, so a
    // trace can read them without the per-event `kick-in-kernel` probe cost.
    crate::probes::kick_stats(el1, inject, at_el1);
    #[cfg(feature = "debug-stats")]
    eprintln!(
        "[kick_stats pid={}] el1_kick_resumed={el1} kick_path_inject={inject} inject_at_el1={at_el1}",
        unsafe { libc::getpid() },
    );
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReclaimParkAuthority {
    Live,
    InitialRunnerParked,
    VcpuParked,
    VmParked,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl ReclaimParkAuthority {
    fn mark_initial_runner_parked(&mut self) -> Result<(), TrapError> {
        if *self != Self::Live {
            return Err(TrapError::Hypervisor(
                "initial runner park attempted without live executor authority".to_owned(),
            ));
        }
        *self = Self::InitialRunnerParked;
        Ok(())
    }

    fn mark_vcpu_parked(&mut self) -> Result<(), TrapError> {
        if *self != Self::Live {
            return Err(TrapError::Hypervisor(
                "vCPU reclaim park attempted without live executor authority".to_owned(),
            ));
        }
        *self = Self::VcpuParked;
        Ok(())
    }

    fn mark_vm_parked(&mut self) -> Result<(), TrapError> {
        if *self != Self::VcpuParked {
            return Err(TrapError::Hypervisor(
                "VM reclaim park attempted without parked vCPU authority".to_owned(),
            ));
        }
        *self = Self::VmParked;
        Ok(())
    }

    fn destination_vcpu_is_live(self) -> Result<(), TrapError> {
        (self == Self::Live).then_some(()).ok_or_else(|| {
            TrapError::Hypervisor("destination executor vCPU is not live".to_owned())
        })
    }

    fn mark_live_after_recreate(&mut self) -> Result<(), TrapError> {
        if *self == Self::Live {
            return Err(TrapError::Hypervisor(
                "reclaim resume attempted to recreate a live destination vCPU".to_owned(),
            ));
        }
        *self = Self::Live;
        Ok(())
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) struct HvfVmState {
    _vm:
        std::mem::ManuallyDrop<applevisor::vm::VirtualMachineInstance<applevisor::vm::GicDisabled>>,
    pub(crate) task: HvfTaskState,
    carrier_foreign_mm_transport: std::sync::Arc<CarrierForeignMmTransport>,
    /// VM-global Carrick control mappings owned by the persistent carrier.
    /// This is executor-local authority: load/save swaps it with the worker,
    /// while a logical task binding always carries `None`.
    pub(crate) carrier_mappings: Option<std::sync::Arc<PersistentCarrierMappings>>,
    /// Executor-local lifecycle only. Task registers are owned exclusively by
    /// the Kernel's typed execution lease and never stashed in this backend.
    reclaim_authority: ReclaimParkAuthority,
    /// Carrick-owned logical mailbox slots shared by every vCPU in this VM.
    /// Slot identity is deliberately independent of opaque/recycled HVF ids.
    mailbox_slots: std::sync::Arc<MailboxSlotAllocator>,
    /// Internal diagnostic transport selection, parsed once before first entry
    /// and inherited by every sibling/rebuild. This is not public CLI policy.
    syscall_transport: HvfSyscallTransport,
    /// Raw worker-local vCPU identity used by teardown and exact kick audit.
    vcpu_id: applevisor_sys::hv_vcpu_t,
    /// Cloneable worker-local handle for `hv_vcpus_exit`.
    vcpu_handle: applevisor::vcpu::VcpuHandle,
    _vcpu_guard: Option<carrick_hal::VcpuLiveGuard>,
}

/// Every backend field whose authority follows a logical HVPatch task rather
/// than a Task4 worker. Keeping this as one value makes load/save a literal
/// swap: the carrier VM, reclaim/mailbox transport, and live vCPU identity stay
/// on the worker while MM mappings, stage-1, inventory, and per-thread COW
/// authority move with the binding.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) struct HvfTaskState {
    #[cfg(not(test))]
    custody: std::sync::Arc<CarrierVmCustody>,
    pub(crate) mappings: TaskMappingIndex,
    /// Per-mm stage-1 root-table slot. It contains page-table/control backing
    /// only; guest data frames live at stable global IPAs outside the slot.
    /// Ordinary VMM engines leave this unset.
    mm_root_slot: Option<(u64, u64)>,
    /// Monotonic token identifying the container root this task belongs to,
    /// used to scope private aliases across containers sharing the carrier.
    container_root: ContainerRootToken,
    pending_exec_mm_root_slot: Option<(u64, u64)>,
    pending_exec_asid: Option<u16>,
    pending_exec_predecessor_identity: Option<carrick_hal::ExecPredecessorIdentity>,
    pending_exec_stage2_cleanup: Option<PendingExecStage2Cleanup>,
    /// A distinct Linux process edge onto another process's live CLONE_VM MM.
    /// Exit/exec drops this projection without retiring shared stage-2 state.
    shared_process_mm: bool,
    /// Exact MM-owned access authority. This is the only movable MM state:
    /// sibling/CLONE_VM tasks clone this Arc, while copied forks allocate a
    /// distinct value.
    mm_access: std::sync::Arc<MmAccessState>,
    /// The exception class of the most recent vCPU exit. We need to remember
    /// whether the trap came in via EL0 `svc` (`EC = 0x15`) or the EL1 vector
    /// stub's `hvc` (`EC = 0x16`) so `complete_syscall` knows whether to
    /// advance PC past the HVC before resuming. Carried in the `VcpuSnapshot` so
    /// fork/clone/reclaim round-trip it.
    last_exit_class: u64,
    /// ESR_EL1 of the most recent EL0 synchronous fault. The arm64 kernel puts
    /// it in the signal frame's `esr_context`; Apple Rosetta's signal handler
    /// requires that record. Captured at fault detection, consumed by
    /// `inject_signal` when building a fault signal's ucontext. Only meaningful
    /// between fault-detect and the immediately following delivery, so it is
    /// reset to 0 across fork/clone/execve.
    last_fault_esr: u64,
    /// True iff this engine was produced by a `fork(2)` returning into a
    /// child. The runtime checks this when the guest exits and calls
    /// `_exit(2)` instead of running normal Rust drops — applevisor's
    /// Vcpu Drop unwraps `hv_vcpu_destroy` and panics in the
    /// post-fork child's HVF context (the new VM HVF tracks for the
    /// child got swapped in by `fork()`; ordering of `_vm` vs `vcpu`
    /// Drop trips a "no VM or vCPU available" assertion).
    is_forked_child: bool,
    /// Like `is_forked_child`, but RESET on execve: true only for a LIVE forked
    /// child that has not yet exec'd. Drives the `forked=` diagnostic probes
    /// (stale-stage2 reasoning); distinct from the sticky shutdown flag above,
    /// which must stay set across execve to keep the `_exit`-without-JSON path.
    forked_no_exec: bool,
    /// Process-wide guest ranges currently mapped `PROT_NONE`.
    /// Thread siblings share this metadata so syscall-path memory access checks
    /// observe `mprotect(PROT_NONE)` changes made by any guest thread.
    /// Lazily-built editor over the EL1 stage-1 page-table image, used to give
    /// `mprotect`/`PROT_NONE`/`munmap` guest-visible semantics. Built from the
    /// page-table region's host backing on first edit; reset to `None` on
    /// fork/execve (fresh tables). SHARED across sibling vCPU threads (one HVF
    /// VM ⇒ one set of stage-1 tables): the mutex serializes edits so the
    /// spare-table allocator stays consistent, and `sync_to_host` orders the
    /// descriptor stores so a concurrent sibling hardware walk stays safe
    /// without quiescing.
    /// The Linux syscall number (x8) and original arg0 (x0) of the most recent
    /// `svc` trap, captured before the dispatcher overwrites x0 with the retval.
    /// Used to restart an `EINTR`'d restartable syscall under SA_RESTART: the
    /// handler-injection path rewinds PC to the `svc` and restores this x0.
    last_syscall_nr: Option<u64>,
    last_syscall_orig_x0: u64,
    /// HvPatch owns one process-wide HVF VM across guest exec/fork lifecycle;
    /// ordinary VMM preserves the mature destroy/recreate behavior.
    persistent_vm_lifecycle: bool,
    /// HVPatch-only exact sparse-extent inventory. Sibling vCPUs share this
    /// ledger; VM/vCPU recreation reuses it and therefore emits no logical
    /// mapping events.
    /// Per-engine runtime authority. Sibling vCPUs bind their own Linux TID;
    /// the underlying mm/frame inventory remains shared.
    cow_authority: Option<std::sync::Arc<dyn carrick_hal::FrameCowAuthority>>,
    cow_identity: Option<carrick_hal::FrameCowIdentity>,
    pending_fork_frame_receipts: Vec<PendingForkFrameReceipt>,
    /// Child aliases withheld until fresh-vCPU register restoration succeeds.
    pending_process_aliases: Vec<AliasBacking>,
    /// Test-only diagnostic arm owned by this executor projection. It must not
    /// move into the shared MM access state or a sibling can consume it.
    fail_next_begin_exec_inventory: bool,
    /// Recycled buffer for the frame-COW rollback pre-image.
    ///
    /// `perform_frame_cow` snapshots the whole stage-1 manager before it edits,
    /// so a failed publication can restore the exact pre-transaction image. That
    /// snapshot is unchanged; only its allocation is reused. A fresh
    /// `PageTableManager::clone()` costs an `mmap` of 1.75 MiB, a zero-fill
    /// fault per page as the copy touches it, and a `munmap`/`madvise` on drop
    /// — measured at ~6 COW faults per guest fork+wait round trip, which put
    /// that whole host-VM churn on the COW path. Taken for the duration of one
    /// COW and returned on success; a rollback consumes it (it becomes the live
    /// manager) and the next COW allocates one again.
    cow_rollback_scratch: Option<crate::page_table::PageTableManager>,
    pub(crate) registration: Option<HvpatchTaskRegistration>,
    /// The executor vCPU this task is loaded on right now. Kick handles
    /// registered for the task follow this slot, so a kick reaches the vCPU
    /// the task currently occupies rather than the one it was first loaded on.
    live_vcpu: std::sync::Arc<crate::vcpu_kick::LiveVcpuSlot>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl std::ops::Deref for HvfTaskState {
    type Target = MmAccessState;

    fn deref(&self) -> &Self::Target {
        &self.mm_access
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
struct PendingExecStage2Cleanup {
    #[cfg(not(test))]
    custody: std::sync::Arc<CarrierVmCustody>,
    pub(crate) mappings: TaskMappingIndex,
    /// Physical candidates selected at exec publication, bound to the exact
    /// global-owner incarnation observed at that boundary.
    extents: std::collections::BTreeMap<(u64, usize), InventoryStage2OwnerIdentity>,
    /// Exact alias values visible from the predecessor MM when exec published
    /// its replacement. The root container scope can be reused by the
    /// successor, so a delayed cleanup may remove these values only—not every
    /// row that happens to carry the same broad scope later.
    predecessor_aliases: Vec<AliasBacking>,
    /// Shared backend reference authority rechecked immediately before recycle.
    frames: std::sync::Arc<parking_lot::Mutex<InventoryFrameRegistry>>,
    /// Semantic alias ownership of the address space replaced by exec.
    mm_root_slot: Option<(u64, u64)>,
    /// Exact predecessor MM authority retained independently of its frame
    /// inventory candidates. Present only when this exec owns retirement of
    /// the old MM; a shared projection leaves the authority with its sharer.
    mm_access: Option<std::sync::Arc<MmAccessState>>,
    /// Immutable exact Kernel identity captured before exec replaces the task.
    predecessor_identity: carrick_hal::ExecPredecessorIdentity,
    /// Never-reused predecessor MM identity from the matching COW binding.
    predecessor_mm: u64,
    shared_projection: bool,
    armed: bool,
}

// SAFETY: cleanup moves with the stopped logical task and is consumed only on
// a Task4 owner worker after save/detach. Its raw mapping pointers remain owned
// by the contained HvfMappedRegion backings until cleanup runs.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
unsafe impl Send for PendingExecStage2Cleanup {}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl PendingExecStage2Cleanup {
    fn retire(&mut self) -> Result<(), TrapError> {
        self.retire_with(&mut |event| {
            crate::probes::hvpatch_exec_predecessor_classification(event);
        })
    }

    fn retire_with(
        &mut self,
        publish: &mut dyn FnMut(
            carrick_observability::probes::HvpatchExecPredecessorClassification,
        ),
    ) -> Result<(), TrapError> {
        self.retire_with_cleanup_boundary(publish, &mut |_| {})
            .map(|_| ())
    }

    fn retire_with_root_proof(
        &mut self,
        expected_root_slot: (u64, u64),
    ) -> Result<HvpatchMmRootRetirementProof, TrapError> {
        if self.mm_root_slot != Some(expected_root_slot) {
            return Err(TrapError::Hypervisor(format!(
                "exec predecessor root retirement coordinates mismatch: expected=({:#x}, {:#x}) captured={:?}",
                expected_root_slot.0, expected_root_slot.1, self.mm_root_slot
            )));
        }
        self.retire_with_cleanup_boundary(
            &mut |event| crate::probes::hvpatch_exec_predecessor_classification(event),
            &mut |_| {},
        )?
        .ok_or_else(|| {
            TrapError::Hypervisor(
                "exec predecessor retirement produced no stage-1 root proof".to_owned(),
            )
        })
    }

    fn retire_with_cleanup_boundary(
        &mut self,
        publish: &mut dyn FnMut(
            carrick_observability::probes::HvpatchExecPredecessorClassification,
        ),
        after_exact_owner_retirement: &mut dyn FnMut(RetiredStage2Projection),
    ) -> Result<Option<HvpatchMmRootRetirementProof>, TrapError> {
        #[cfg(not(test))]
        let custody = std::sync::Arc::clone(&self.custody);
        #[cfg(not(test))]
        let custody = custody.as_ref();
        #[cfg(test)]
        let custody = legacy_test_carrier_vm_custody();
        let identity = self.predecessor_identity;
        let classification =
            carrick_observability::probes::HvpatchExecPredecessorClassification::new(
                carrick_observability::probes::HvpatchExecPredecessorClassificationPhase::CleanupConsumed,
                carrick_observability::probes::HvpatchExecPredecessorIdentity::new(
                    identity.task_serial,
                    identity.thread_serial,
                    identity.linux_pid,
                    identity.linux_tid,
                    self.predecessor_mm,
                    u32::from(identity.asid),
                )
                .map_err(|error| {
                    TrapError::Hypervisor(format!(
                        "construct deferred HVPatch exec predecessor identity: {error}"
                    ))
                })?,
                self.shared_projection,
            )
            .map_err(|error| {
                TrapError::Hypervisor(format!(
                    "construct deferred HVPatch exec predecessor classification: {error}"
                ))
            })?;
        if self.shared_projection {
            // A CLONE_VM process edge owns only unowned descriptors into the
            // parent's still-live MM. Exec drops that projection; it must not
            // unmap stage-2, retire aliases, or release parent backing.
            self.mappings.clear();
            self.armed = false;
            publish(classification);
            return Ok(None);
        }
        let mut retired_extents = Vec::new();
        for (&(ipa, size), &owner_identity) in &self.extents {
            let owner_generation = owner_identity.generation;
            let lease = (ipa, size as u64);
            if owner_generation == 0 && is_reusable_global_frame_extent(ipa, size as u64) {
                // A reusable extent is born with a registered owner generation.
                // Absence at selection is incomplete authority, never permission
                // for delayed cleanup to remove a later incarnation by bare key.
                continue;
            }
            if global_frame_host_owner_generation_in(custody, ipa, size as u64) != owner_generation
            {
                continue;
            }
            let mut exact_owner_retired = false;
            if HvfVmState::retire_stage2_candidate_if_unreferenced(&self.frames, lease, || {
                if owner_generation == 0 {
                    HvfVmState::retire_stage2_extent_from_mappings_in(
                        custody,
                        &mut self.mappings,
                        ipa,
                        size as u64,
                    )
                } else {
                    let outcome = retire_global_frame_host_owner_if_generation_in(
                        custody,
                        ipa,
                        size as u64,
                        owner_generation,
                    );
                    match outcome {
                        GlobalFrameRetirementOutcome::RetiredUnmapped { .. }
                        | GlobalFrameRetirementOutcome::TerminalizedByVmDestroy { .. } => {
                            exact_owner_retired = true;
                            Ok(())
                        }
                        GlobalFrameRetirementOutcome::DeferredActivePins { .. }
                        | GlobalFrameRetirementOutcome::RetryPending { .. } => Ok(()),
                        outcome => Err(TrapError::Hypervisor(format!(
                            "HVPatch exec predecessor owner generation drifted at IPA 0x{ipa:x} size {size}: {outcome:?}"
                        ))),
                    }
                }
            })? {
                let retired = RetiredStage2Projection {
                    physical_ipa: ipa,
                    physical_length: size as u64,
                    owner: owner_identity,
                };
                retired_extents.push(retired);
                if exact_owner_retired {
                    after_exact_owner_retirement(retired);
                }
            }
        }
        let mut root_proof = None;
        if let (Some(mm_access), Some(root_slot)) = (&self.mm_access, self.mm_root_slot) {
            let retired_root = mm_access.retire_mm_root_stage2_in(custody, root_slot)?;
            let (ipa, size) = retired_root.physical_extent;
            if !retired_extents.iter().any(|retired| {
                (retired.physical_ipa, retired.physical_length) == (ipa, size as u64)
            }) {
                retired_extents.push(RetiredStage2Projection {
                    physical_ipa: ipa,
                    physical_length: size as u64,
                    owner: retired_root.owner,
                });
            }
            root_proof = Some(retired_root.proof);
        }
        let (removed_aliases, preserved_aliases) = mutate_known_external_alias_state(
            |_, registry| {
                retired_projection_mutation_keys(
                    registry,
                    &retired_extents,
                    &self.predecessor_aliases,
                )
            },
            |replay, registry| {
                let cleanup =
                    remove_rows_for_retired_stage2_projections(replay, registry, &retired_extents);
                let mut removed = cleanup.removed_aliases;
                let mut preserved = cleanup.preserved_reused_aliases;
                for expected in &self.predecessor_aliases {
                    if let Some(current) =
                        registry.find_by_key(expected.start, expected.ipa, expected.ownership_scope)
                        && current != *expected
                    {
                        preserved.push(current);
                    }
                }
                removed.extend(registry.remove_exact_values_in_batch(&self.predecessor_aliases));
                (removed, preserved)
            },
        );
        for alias in removed_aliases {
            record_cow_alias_lifecycle(
                CowDiagnosticLifecycleKind::AliasRemoved,
                CowDiagnosticLifecycleSite::ExecRetirement,
                Some(custody),
                None,
                self.mm_root_slot,
                alias,
            );
        }
        for alias in preserved_aliases {
            record_cow_alias_lifecycle(
                CowDiagnosticLifecycleKind::AliasPreservedReused,
                CowDiagnosticLifecycleSite::ExecRetirement,
                Some(custody),
                None,
                self.mm_root_slot,
                alias,
            );
        }
        record_alias_revision(
            CowDiagnosticAliasRevisionSite::ExecPredecessorMutation,
            custody,
            None,
            0,
            alias_registry().lock().revision(),
        );
        let structural_retirements = self
            .mappings
            .iter()
            .filter_map(|mapping| {
                mapping
                    .structural_owner
                    .as_ref()
                    .map(|owner| *owner.retained.record_identity.lock())
            })
            .collect::<Vec<_>>();
        let mut retained_backings = Vec::new();
        for mapping in std::mem::take(&mut self.mappings).into_values() {
            if retired_extents
                .iter()
                .any(|retired| mapped_region_matches_retired_inventory_extent(&mapping, *retired))
            {
                drop(mapping);
            } else {
                retained_backings.push(mapping);
            }
        }
        std::mem::forget(retained_backings);
        retry_structural_backing_identities_in_using(
            custody,
            &structural_retirements,
            &mut unmap_global_frame_stage2_record,
            &mut release_retired_stage2_ipa,
        )?;
        self.armed = false;
        publish(classification);
        Ok(root_proof)
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl Drop for PendingExecStage2Cleanup {
    fn drop(&mut self) {
        if self.armed {
            if let Err(error) = self.retire() {
                carrick_fatal!(
                    "hvpatch::exec_commit",
                    "drop pending exec predecessor cleanup failed: {error}"
                );
            }
        }
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl std::ops::Deref for HvfVmState {
    type Target = HvfTaskState;

    fn deref(&self) -> &Self::Target {
        &self.task
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl std::ops::DerefMut for HvfVmState {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.task
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn swap_hvpatch_task_state(live: &mut HvfTaskState, parked: &mut HvfTaskState) {
    std::mem::swap(live, parked);
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Copy, Clone)]
pub(crate) struct HvfPageTableResolver<'a> {
    task: &'a HvfTaskState,
    manager_base: u64,
    primary_host: Option<*mut u8>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl<'a> carrick_mem::page_table::HostArenaResolver for HvfPageTableResolver<'a> {
    fn host_ptr_for_base(&self, base: u64) -> Option<*mut u8> {
        self.primary_host
            .filter(|_| base == self.manager_base)
            // Extension arenas are published as structural owners keyed by
            // exactly (base, 2 MiB): O(1). The mapping-row scan below is
            // O(rows) and made every page-table edit of a process with
            // thousands of mappings quadratic (pagetablegrow spent minutes
            // in `live_pt_debug_walk`); it stays only as the last resort.
            .or_else(|| {
                self.task.mm_access.structural_owner_host_ptr(
                    base,
                    carrick_mem::memory::LINUX_PAGE_TABLES_SIZE as usize,
                )
            })
            .or_else(|| {
                self.task
                    .host_ptr_for_ipa(base, carrick_mem::memory::LINUX_PAGE_TABLES_SIZE as usize)
            })
    }

    fn record_populated_prefix(&self, base: u64, prefix: usize) {
        self.task.record_stage1_populated_prefix(base, prefix);
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl HvfTaskState {
    pub(crate) fn custody(&self) -> &CarrierVmCustody {
        #[cfg(not(test))]
        {
            &self.custody
        }
        #[cfg(test)]
        {
            legacy_test_carrier_vm_custody()
        }
    }

    fn custody_arc(&self) -> std::sync::Arc<CarrierVmCustody> {
        #[cfg(not(test))]
        {
            std::sync::Arc::clone(&self.custody)
        }
        #[cfg(test)]
        {
            std::sync::Arc::clone(legacy_test_carrier_vm_custody_arc())
        }
    }

    pub(crate) fn mm_access_authority(&self) -> std::sync::Arc<MmAccessState> {
        std::sync::Arc::clone(&self.mm_access)
    }

    fn take_exec_predecessor_identity(
        &mut self,
        predecessor_cow_identity: carrick_hal::FrameCowIdentity,
    ) -> Result<carrick_hal::ExecPredecessorIdentity, TrapError> {
        let predecessor_identity =
            self.pending_exec_predecessor_identity
                .take()
                .ok_or_else(|| {
                    TrapError::Hypervisor(
                        "HVPatch exec predecessor cleanup lacks bound Kernel identity".to_owned(),
                    )
                })?;
        if let Some(registration) = self.registration.as_ref() {
            let registered = registration.expected_identity;
            if predecessor_identity.task_serial != registered.task_serial
                || predecessor_identity.linux_pid != registered.linux_pid
            {
                return Err(TrapError::Hypervisor(
                    "HVPatch exec predecessor Kernel/registration identity mismatch".to_owned(),
                ));
            }
            if registration.cow_identity != Some(predecessor_cow_identity) {
                return Err(TrapError::Hypervisor(
                    "HVPatch exec predecessor registration/COW identity mismatch".to_owned(),
                ));
            }
        }
        if predecessor_identity.linux_pid != predecessor_cow_identity.linux_pid
            || predecessor_identity.mm != predecessor_cow_identity.mm
            || predecessor_identity.asid != predecessor_cow_identity.asid
        {
            return Err(TrapError::Hypervisor(
                "HVPatch exec predecessor Kernel/COW identity mismatch".to_owned(),
            ));
        }
        Ok(predecessor_identity)
    }

    pub(crate) fn runtime_authorities_match(
        &self,
        mm_access: &std::sync::Arc<MmAccessState>,
        page_tables: &carrick_aarch64::Stage1Authority,
        protections: &std::sync::Arc<MemoryProtections>,
    ) -> bool {
        std::sync::Arc::ptr_eq(&self.mm_access, mm_access)
            && carrick_aarch64::Aarch64TaskRuntimeProjection {
                page_tables: page_tables.clone(),
                protections: std::sync::Arc::clone(protections),
                process_asid: None,
            }
            .shares_exact_mm_authority(&self.page_tables_authority(), &self.protections)
    }

    fn publish_pending_fork_frame_receipts_with(
        &mut self,
        publish: &mut dyn FnMut(carrick_observability::probes::HvpatchForkFrameShare),
    ) {
        // This task-local vector is the observation copy made by
        // `runtime_task_state`. The MM authority retains its original receipts
        // for exact retirement authentication, so draining here is publication
        // exactly once without discharging the Kernel obligation.
        if self.pending_fork_frame_receipts.is_empty() {
            return;
        }
        let authority = self.cow_authority.as_ref().unwrap_or_else(|| {
            carrick_fatal!(
                "hvpatch::cow_token",
                "pending fork-frame receipt has no COW authority"
            )
        });
        let identity = self.cow_identity.unwrap_or_else(|| {
            carrick_fatal!(
                "hvpatch::cow_token",
                "pending fork-frame receipt has no COW identity"
            )
        });
        for receipt in std::mem::take(&mut self.pending_fork_frame_receipts) {
            let length = carrick_hal::FrameLength::from_mapping_extent(
                std::num::NonZeroU64::new(receipt.length).unwrap_or_else(|| {
                    carrick_fatal!(
                        "hvpatch::fork_publication",
                        "pending fork-frame receipt has zero length"
                    )
                }),
            );
            match authority.mapping_is_live(
                receipt.child_mapping,
                receipt.frame,
                carrick_guest_mem::Gpa(receipt.ipa),
                length,
            ) {
                Ok(true) => {}
                Ok(false) => {
                    carrick_fatal!(
                        "hvpatch::fork_publication",
                        "fork-frame receipt child mapping {:?} is not live",
                        receipt.child_mapping
                    );
                }
                Err(error) => {
                    carrick_fatal!(
                        "hvpatch::cow_token",
                        "authenticate fork-frame receipt mapping {:?}: {error}",
                        receipt.child_mapping
                    );
                }
            }
            let event = carrick_observability::probes::HvpatchForkFrameShare::new(
                identity.linux_pid,
                identity.linux_tid,
                identity.mm,
                u32::from(identity.asid),
                receipt.kind,
                receipt.parent_mapping.raw(),
                receipt.child_mapping.raw(),
                receipt.frame.raw(),
                receipt.ipa,
                receipt.length,
            )
            .unwrap_or_else(|error| {
                carrick_fatal!(
                    "hvpatch::fork_publication",
                    "construct authenticated fork-frame receipt failed: {error}"
                )
            });
            publish(event);
        }
    }

    pub(crate) fn publish_pending_fork_frame_receipts(&mut self) {
        self.publish_pending_fork_frame_receipts_with(&mut |event| {
            crate::probes::hvpatch_fork_frame_share(event);
        });
    }

    pub(crate) fn bind_frame_cow(
        &mut self,
        authority: std::sync::Arc<dyn carrick_hal::FrameCowAuthority>,
        identity: carrick_hal::FrameCowIdentity,
    ) {
        self.cow_authority = Some(std::sync::Arc::clone(&authority));
        self.cow_identity = Some(identity);
        self.mm_access.bind_cow_runtime(MmCowRuntimeBinding {
            authority: std::sync::Arc::clone(&authority),
            identity,
            mm_root_slot: self.mm_root_slot,
            container_root: self.container_root,
            persistent_vm_lifecycle: self.persistent_vm_lifecycle,
        });
        self.publish_pending_fork_frame_receipts();
        if let Some(ref mut reg) = self.registration {
            reg.cow_authority = Some(authority);
            reg.cow_identity = Some(identity);
            reg.cow_authority_identity = None;
        }
    }

    pub(crate) fn physical_cow_source(
        &self,
        semantic_va: u64,
        ipa: u64,
    ) -> Option<PhysicalCowSource> {
        self.physical_cow_source_in(self.custody(), semantic_va, ipa)
    }

    fn report_physical_cow_source_refusal(
        &self,
        custody: &CarrierVmCustody,
        semantic_va: u64,
        ipa: u64,
    ) {
        if !cow_refusal_diagnostics_enabled() {
            return;
        }
        const PAGE_SIZE: u64 = 4 * 1024;
        const PA_MASK_4KIB: u64 = 0x0000_FFFF_FFFF_F000;
        const REPORT_ROW_LIMIT: usize = 16;

        let physical_ipa = align_down(ipa, CowArmedRanges::COMPOUND_SIZE);
        let physical_offset = ipa.saturating_sub(physical_ipa);
        let compound_va = semantic_va
            .checked_sub(physical_offset)
            .unwrap_or_else(|| align_down(semantic_va, CowArmedRanges::COMPOUND_SIZE));
        let compound_end = compound_va.saturating_add(CowArmedRanges::COMPOUND_SIZE);
        let custody_identity = custody as *const CarrierVmCustody as usize;
        let mm_access_identity = std::sync::Arc::as_ptr(&self.mm_access) as usize;
        let page_tables_authority = self.page_tables_authority();
        let page_tables_identity = page_tables_authority.authority_id() as usize;
        let page_table_host = self
            .mapping_for_range_in(
                custody,
                crate::memory::LINUX_PAGE_TABLES_BASE,
                carrick_mem::memory::LINUX_PAGE_TABLES_SIZE as usize,
            )
            .map(|mapping| mapping.host_addr);
        let (page_table_root, stage1_rows) = page_tables_authority
            .with_manager(|manager| {
                let mut rows = Vec::with_capacity(4);
                let mut va = compound_va;
                while va < compound_end {
                    let shadow = manager.debug_walk(va);
                    let live = page_table_host.and_then(|host| unsafe {
                        manager
                            .debug_walk_host(
                                self.page_table_resolver(manager.base(), Some(host)),
                                va,
                            )
                            .ok()
                    });
                    rows.push((
                        va,
                        manager.translate(va),
                        manager.translate_retained_output(va),
                        shadow,
                        live,
                    ));
                    va = va.saturating_add(PAGE_SIZE);
                }
                (Some(manager.base()), rows)
            })
            .unwrap_or((None, Vec::new()));
        eprintln!(
            "[COW-REFUSAL] input_va={semantic_va:#x} input_ipa={ipa:#x} compound_va={compound_va:#x} physical={physical_ipa:#x}+{:#x} custody={custody_identity:#x} mm_access={mm_access_identity:#x} page_tables={page_tables_identity:#x} root={page_table_root:#x?} mm_root_slot={:?} cow_identity={:?}",
            CowArmedRanges::COMPOUND_SIZE,
            self.mm_root_slot,
            self.cow_identity,
        );
        for (va, translated, retained, shadow, live) in stage1_rows {
            let live_leaf = live.map(|walk| walk[3]);
            let live_ipa = live_leaf.map(|leaf| leaf & PA_MASK_4KIB);
            eprintln!(
                "[COW-REFUSAL stage1] va={va:#x} translated={translated:#x?} retained={retained:#x?} shadow={shadow:x?} live={live:x?} live_leaf_ipa={live_ipa:#x?}",
            );
        }

        let owner_entry = custody
            .global_frame_host_owners
            .lock()
            .get(&(physical_ipa, CowArmedRanges::COMPOUND_SIZE))
            .cloned();
        match &owner_entry {
            Some(GlobalFrameOwnerEntry::Live(owner)) => eprintln!(
                "[COW-REFUSAL owner] state=live host={:#x} generation={} mapping_pins={} record={:?} stage2={:?}",
                owner.host_addr(),
                owner.generation(),
                owner.mapping.pin_count(),
                owner.record_identity,
                owner.snapshot(),
            ),
            Some(GlobalFrameOwnerEntry::RetirementPending {
                owner,
                error,
                in_flight,
            }) => eprintln!(
                "[COW-REFUSAL owner] state=retirement-pending host={:#x} generation={} mapping_pins={} in_flight={} error={:?} record={:?} stage2={:?}",
                owner.host_addr(),
                owner.generation(),
                owner.mapping.pin_count(),
                in_flight,
                error,
                owner.record_identity,
                owner.snapshot(),
            ),
            None => eprintln!(
                "[COW-REFUSAL owner] state=absent physical={physical_ipa:#x}+{:#x}",
                CowArmedRanges::COMPOUND_SIZE,
            ),
        }

        let (inventory_total, inventory_rows, inventory_identity, inventory_consistent) = {
            let inventory = self.frame_inventory.lock();
            let mut total = 0usize;
            let mut rows = Vec::new();
            let mut identity = None;
            let mut consistent = true;
            for (&logical_key, &extent) in inventory.extents.iter().filter(|(_, extent)| {
                (extent.stage2_base, extent.stage2_length)
                    == (physical_ipa, CowArmedRanges::COMPOUND_SIZE)
            }) {
                total = total.saturating_add(1);
                if extent.stage2_owner.generation == 0
                    || identity.is_some_and(|current| current != extent.stage2_owner)
                {
                    consistent = false;
                }
                identity.get_or_insert(extent.stage2_owner);
                if rows.len() < REPORT_ROW_LIMIT {
                    rows.push((logical_key, extent));
                }
            }
            (total, rows, identity, consistent)
        };
        let inventory_authorized = inventory_consistent
            && inventory_identity.is_some_and(|identity| {
                identity.generation != 0
                    && matches!(
                        &owner_entry,
                        Some(GlobalFrameOwnerEntry::Live(owner))
                            if owner.host_addr() == identity.host_addr
                                && owner.generation() == identity.generation
                    )
            });
        eprintln!(
            "[COW-REFUSAL inventory] exact_stage2_candidates={inventory_total} shown={} identity={inventory_identity:?} consistent={inventory_consistent} authorized={inventory_authorized}",
            inventory_rows.len(),
        );
        for (logical_key, extent) in inventory_rows {
            eprintln!(
                "[COW-REFUSAL inventory-row] logical={logical_key:#x?} frame={:?} mapping={:?} backing={:?} stage2=({:#x},{:#x}) owner={:?}",
                extent.frame,
                extent.mapping,
                extent.backing,
                extent.stage2_base,
                extent.stage2_length,
                extent.stage2_owner,
            );
        }

        let affine_translation_matches = |mapping_start: u64, mapping_ipa: u64| {
            if semantic_va < mapping_start {
                ipa.checked_add(mapping_start - semantic_va) == Some(mapping_ipa)
            } else {
                mapping_ipa.checked_add(semantic_va - mapping_start) == Some(ipa)
            }
        };
        let (mapping_total, mapping_rows) = {
            let mut total = 0usize;
            let mut rows = Vec::new();
            for mapping in self
                .mappings
                .iter()
                .rev()
                .filter(|mapping| mapping.start < compound_end && compound_va < mapping.end)
            {
                total = total.saturating_add(1);
                let physical_host_addr = mapped_region_physical_host_addr(mapping);
                let owner_matches = physical_host_addr.is_some_and(|host| {
                    mapping.owner_generation != 0
                        && global_frame_host_owner_identity_in(
                            custody,
                            mapping.physical_ipa,
                            mapping.physical_size as u64,
                        ) == Some((host as usize, mapping.owner_generation))
                });
                if rows.len() < REPORT_ROW_LIMIT {
                    rows.push((
                        mapping.start,
                        mapping.end,
                        mapping.ipa,
                        mapping.physical_ipa,
                        mapping.physical_size,
                        physical_host_addr.map_or(0, |host| host as usize),
                        mapping.owner_generation,
                        owner_matches,
                        mapping.guest_writable,
                        mapping.sharing,
                    ));
                }
            }
            (total, rows)
        };
        eprintln!(
            "[COW-REFUSAL semantic-mappings] total={mapping_total} shown={}",
            mapping_rows.len()
        );
        for (
            start,
            end,
            mapping_ipa,
            mapping_physical_ipa,
            physical_size,
            physical_host_addr,
            owner_generation,
            owner_matches,
            guest_writable,
            sharing,
        ) in mapping_rows
        {
            eprintln!(
                "[COW-REFUSAL semantic-mapping] va=({:#x},{:#x}) ipa={:#x} affine={} physical=({:#x},{:#x}) host={:#x} owner_generation={} owner_matches={} writable={} sharing={:?}",
                start,
                end,
                mapping_ipa,
                affine_translation_matches(start, mapping_ipa),
                mapping_physical_ipa,
                physical_size,
                physical_host_addr,
                owner_generation,
                owner_matches,
                guest_writable,
                sharing,
            );
        }
        let (alias_total, alias_rows) = {
            let mut total = 0usize;
            let mut rows = Vec::new();
            for alias in alias_registry()
                .lock()
                .process_visible_ordered(self.mm_root_slot, self.container_root)
                .into_iter()
                .rev()
                .filter(|alias| {
                    alias.start < compound_end
                        && compound_va < alias.start.saturating_add(alias.size as u64)
                })
            {
                total = total.saturating_add(1);
                if rows.len() < REPORT_ROW_LIMIT {
                    rows.push(alias);
                }
            }
            (total, rows)
        };
        eprintln!(
            "[COW-REFUSAL semantic-aliases] total={alias_total} shown={}",
            alias_rows.len()
        );
        for alias in alias_rows {
            let owner_matches = alias.owner_generation != 0
                && global_frame_host_owner_identity_in(
                    custody,
                    alias.physical_ipa,
                    alias.physical_size as u64,
                ) == Some((alias.physical_host_addr, alias.owner_generation));
            eprintln!(
                "[COW-REFUSAL semantic-alias] va=({:#x},{:#x}) ipa={:#x} affine={} physical=({:#x},{:#x}) host={:#x} owner_generation={} owner_matches={} writable={} sharing={:?} scope={:?}",
                alias.start,
                alias.start.saturating_add(alias.size as u64),
                alias.ipa,
                affine_translation_matches(alias.start, alias.ipa),
                alias.physical_ipa,
                alias.physical_size,
                alias.physical_host_addr,
                alias.owner_generation,
                owner_matches,
                alias.guest_writable,
                alias.sharing,
                alias.ownership_scope,
            );
        }

        let history = cow_diagnostic_history().lock().relevant(
            custody_identity,
            physical_ipa,
            Some(mm_access_identity),
            REPORT_ROW_LIMIT,
        );
        eprintln!("[COW-REFUSAL history] shown={}", history.len());
        for event in history {
            eprintln!("[COW-REFUSAL history-row] {event:?}");
        }
    }

    fn physical_cow_source_in(
        &self,
        custody: &CarrierVmCustody,
        semantic_va: u64,
        ipa: u64,
    ) -> Option<PhysicalCowSource> {
        let physical_ipa = align_down(ipa, CowArmedRanges::COMPOUND_SIZE);
        let physical_end = physical_ipa.checked_add(CowArmedRanges::COMPOUND_SIZE)?;
        let semantic_end = semantic_va.checked_add(CowArmedRanges::COMPOUND_SIZE)?;
        let affine_translation_matches = |mapping_start: u64, mapping_ipa: u64| {
            if semantic_va < mapping_start {
                ipa.checked_add(mapping_start - semantic_va) == Some(mapping_ipa)
            } else {
                mapping_ipa.checked_add(semantic_va - mapping_start) == Some(ipa)
            }
        };
        if let Some(alias) = alias_registry().lock().newest_matching_for_process(
            self.mm_root_slot,
            self.container_root,
            |alias| {
                alias_matches_process_scope(
                    alias.ownership_scope,
                    self.mm_root_slot,
                    self.container_root,
                ) && alias.start < semantic_end
                    && alias
                        .start
                        .checked_add(alias.size as u64)
                        .is_some_and(|alias_end| semantic_va < alias_end)
                    && affine_translation_matches(alias.start, alias.ipa)
                    && physical_ipa >= alias.physical_ipa
                    && physical_end
                        <= alias
                            .physical_ipa
                            .saturating_add(alias.physical_size as u64)
                    && if self.persistent_vm_lifecycle
                        && is_reusable_global_frame_extent(
                            alias.physical_ipa,
                            alias.physical_size as u64,
                        )
                    {
                        global_frame_host_owner_matches_in(
                            custody,
                            alias.physical_ipa,
                            alias.physical_size as u64,
                            alias.physical_host_addr,
                            alias.owner_generation,
                        )
                    } else {
                        alias_backing_is_live(alias.physical_host_addr)
                    }
            },
        ) {
            let offset = usize::try_from(physical_ipa - alias.physical_ipa).ok()?;
            if self.persistent_vm_lifecycle
                && is_reusable_global_frame_extent(alias.physical_ipa, alias.physical_size as u64)
            {
                if let Some(pin) = pin_exact_live_global_frame_owner_in(
                    custody,
                    alias.physical_ipa,
                    alias.physical_size as u64,
                    alias.physical_host_addr,
                    alias.owner_generation,
                ) {
                    return Some(PhysicalCowSource::pinned(pin, offset, physical_ipa));
                }
            } else {
                return Some(PhysicalCowSource::unpinned(
                    unsafe { (alias.physical_host_addr as *mut u8).add(offset) },
                    physical_ipa,
                ));
            }
        }
        let mapping = self
            .mappings
            .candidates_for_range(GuestVa(semantic_va), CowArmedRanges::COMPOUND_SIZE)
            .find(|mapping| {
                let physical_mapping_end = mapping
                    .physical_ipa
                    .checked_add(mapping.physical_size as u64);
                mapping.start < semantic_end
                    && semantic_va < mapping.end
                    && affine_translation_matches(mapping.start, mapping.ipa)
                    && physical_ipa >= mapping.physical_ipa
                    && physical_mapping_end.is_some_and(|limit| physical_end <= limit)
                    && (!self.persistent_vm_lifecycle
                        || !is_reusable_global_frame_extent(
                            mapping.physical_ipa,
                            mapping.physical_size as u64,
                        )
                        || global_frame_region_owner_matches_in(custody, mapping))
            });
        if let Some(mapping) = mapping
            && let Some(physical_host_addr) = mapped_region_physical_host_addr(mapping)
            && let Ok(offset) = usize::try_from(physical_ipa - mapping.physical_ipa)
        {
            if self.persistent_vm_lifecycle
                && is_reusable_global_frame_extent(
                    mapping.physical_ipa,
                    mapping.physical_size as u64,
                )
            {
                if let Some(pin) = pin_exact_live_global_frame_owner_in(
                    custody,
                    mapping.physical_ipa,
                    mapping.physical_size as u64,
                    physical_host_addr as usize,
                    mapping.owner_generation,
                ) {
                    return Some(PhysicalCowSource::pinned(pin, offset, physical_ipa));
                }
            } else {
                return Some(PhysicalCowSource::unpinned(
                    unsafe { physical_host_addr.add(offset) },
                    physical_ipa,
                ));
            }
        }
        // A newly activated sibling can have stale worker-local semantic rows
        // even though its live stage-1 tree and shared inventory already name
        // the current COW overlay. Authenticate that physical fact directly:
        // the extent, host address, and owner generation must all match exactly,
        // and the returned source retains both mapping and stage-2 pins.
        if self.persistent_vm_lifecycle
            && is_reusable_global_frame_extent(physical_ipa, CowArmedRanges::COMPOUND_SIZE)
        {
            let inventory_owner = {
                let inventory = self.frame_inventory.lock();
                let mut owner = None;
                let mut consistent = true;
                for extent in inventory.extents.values().filter(|extent| {
                    (extent.stage2_base, extent.stage2_length)
                        == (physical_ipa, CowArmedRanges::COMPOUND_SIZE)
                }) {
                    let candidate = extent.stage2_owner;
                    if candidate.generation == 0
                        || owner.is_some_and(|current| current != candidate)
                    {
                        consistent = false;
                        break;
                    }
                    owner = Some(candidate);
                }
                consistent.then_some(owner).flatten()
            };
            if let Some(owner) = inventory_owner
                && let Some(pin) = pin_exact_live_global_frame_owner_in(
                    custody,
                    physical_ipa,
                    CowArmedRanges::COMPOUND_SIZE,
                    owner.host_addr,
                    owner.generation,
                )
            {
                return Some(PhysicalCowSource::pinned(pin, 0, physical_ipa));
            }
        }
        self.report_physical_cow_source_refusal(custody, semantic_va, ipa);
        None
    }

    pub(crate) fn host_ptr_for_ipa(&self, ipa: u64, len: usize) -> Option<*mut u8> {
        let mapping = HvfVmState::mapping_for_ipa_range(&self.mappings, ipa, len.max(1))?;
        let offset = usize::try_from(ipa.saturating_sub(mapping.ipa)).ok()?;
        Some(unsafe { mapping.host_addr.add(offset) })
    }

    pub(crate) fn record_stage1_populated_prefix(&self, base: u64, prefix: usize) {
        if let Some(owner) = self
            .mm_access
            .structural_owners
            .read()
            .get(&(base, carrick_mem::memory::LINUX_PAGE_TABLES_SIZE as usize))
        {
            owner.record_populated_prefix(prefix);
        }
        if let Some(ref auth) = *self.mm_access.mm_root_stage2.lock() {
            if auth.root_slot.0 == base {
                auth.owner.record_populated_prefix(prefix);
            }
        }
    }

    pub(crate) fn page_table_resolver<'a>(
        &'a self,
        manager_base: u64,
        primary_host: Option<*mut u8>,
    ) -> HvfPageTableResolver<'a> {
        HvfPageTableResolver {
            task: self,
            manager_base,
            primary_host,
        }
    }

    pub(crate) fn publish_stage1_extension_arenas(
        &mut self,
        manager: &carrick_mem::page_table::PageTableManager,
    ) -> Result<(), TrapError> {
        let root_perms = self
            .mm_root_slot
            .and_then(|(root_base, _)| {
                self.mappings
                    .iter()
                    .find(|m| m.ipa == root_base)
                    .map(|m| m.perms)
            })
            .unwrap_or(applevisor::memory::MemPerms::ReadWrite);

        let published = self.mm_access.publish_stage1_extension_arenas(
            &self.custody_arc(),
            manager,
            root_perms,
        )?;
        self.mappings.extend(published);
        Ok(())
    }

    pub(crate) fn retire_stage1_extension_arenas(
        &mut self,
        manager: &mut carrick_mem::page_table::PageTableManager,
    ) -> Result<(), TrapError> {
        const TWO_MIB: u64 = 2 * 1024 * 1024;
        let custody = self.custody_arc();
        let retired_bases = manager.retire_extension_arenas();
        for base in retired_bases {
            HvfVmState::retire_stage2_extent_from_mappings_in(
                &custody,
                &mut self.mappings,
                base,
                TWO_MIB,
            )?;
            self.mappings.retain(|m| m.ipa != base);
        }
        Ok(())
    }

    fn translate_va_for_cow(&self, va: u64) -> Option<u64> {
        self.page_tables_authority()
            .with_manager(|m| m.translate(va))
            .flatten()
    }

    fn mapping_for_range_in(
        &self,
        custody: &CarrierVmCustody,
        address: u64,
        length: usize,
    ) -> Option<MappingView> {
        let address = strip_pointer_tag(address);
        let stage1_ipa = self.translate_va_for_cow(address);
        let region_is_live = |mapping: &HvfMappedRegion| {
            !self.persistent_vm_lifecycle
                || !is_reusable_global_frame_extent(
                    mapping.physical_ipa,
                    mapping.physical_size as u64,
                )
                || global_frame_region_owner_matches_in(custody, mapping)
        };
        let alias_is_live = |alias: &AliasBacking| {
            !self.persistent_vm_lifecycle
                || !is_reusable_global_frame_extent(alias.physical_ipa, alias.physical_size as u64)
                || global_frame_host_owner_matches_in(
                    custody,
                    alias.physical_ipa,
                    alias.physical_size as u64,
                    alias.physical_host_addr,
                    alias.owner_generation,
                )
        };
        if let Some(ipa) = stage1_ipa {
            if let Some(mapping) = self
                .mappings
                .candidates_for_range(GuestVa(address), length as u64)
                .find(|mapping| {
                    ipa >= mapping.ipa
                        && ipa < mapping.ipa.saturating_add(mapping.size as u64)
                        && mapping.contains_range(address, length)
                        && mapping.ipa.checked_add(address - mapping.start) == Some(ipa)
                        && region_is_live(mapping)
                })
            {
                return Some(mapping.view());
            }
            if let Some(alias) = alias_registry().lock().newest_containing_ipa(ipa, |alias| {
                // A fork peer can retain the same physical frame at a
                // different VA. Its live IPA is not a semantic mapping for
                // this MM: copy offsets and sparse-materialization bounds
                // must come from the requested VA's exact translation.
                alias_matches_process_scope(
                    alias.ownership_scope,
                    self.mm_root_slot,
                    self.container_root,
                ) && address >= alias.start
                    && address.checked_add(length as u64).is_some_and(|end| {
                        alias
                            .start
                            .checked_add(alias.size as u64)
                            .is_some_and(|limit| end <= limit)
                    })
                    && alias.ipa.checked_add(address - alias.start) == Some(ipa)
                    && ipa >= alias.ipa
                    && ipa < alias.ipa.saturating_add(alias.size as u64)
                    && alias_is_live(alias)
            }) {
                return Some(MappingView::from_alias(&alias));
            }
            return None;
        }
        // A dynamic-alias row is this task's CACHE of a process-wide registry
        // projection, and only the registry is edited by a sibling task's
        // partial `munmap`/`MAP_FIXED`: `unregister_alias_entries` splits the
        // registry entry and `split_local_rows_for_unmap` mirrors that onto the
        // unmapping task's own rows, so every OTHER task keeps a row that still
        // spans the retired page. Frame liveness cannot see that: the compound
        // stays owned as long as one neighbouring page still uses it, so the
        // stale row authenticated a PAGE the process had already unmapped. The
        // page's next incarnation then took the zero-allocation fast path of
        // `ensure_sparse_mmap_backing` and revalidated the retired leaf output
        // (a frame handed to someone else, or the page's previous bytes) —
        // the wide fault window makes multi-page rows, and with them this
        // shape, routine (go_types `s.allocCount != s.nelems`, the
        // `windowcoherence` cross-thread stress). Authenticate the row against
        // the registry at the page: the projection it caches must still exist
        // for this process scope with the same physical incarnation.
        let row_projection_is_current = |mapping: &HvfMappedRegion| {
            // Only the persistent (HVPatch) lifecycle publishes multi-page
            // rows into a process-scoped registry; the mature lane stamps no
            // owner generation and clears the registry at exec, so its rows
            // keep the frame-liveness contract above.
            if !mapping.is_dynamic_alias || !self.persistent_vm_lifecycle {
                return true;
            }
            let Some(end) = address.checked_add(length as u64) else {
                return false;
            };
            alias_registry()
                .lock()
                .newest_process_alias_containing_va(
                    address,
                    self.mm_root_slot,
                    self.container_root,
                    |alias| {
                        alias
                            .start
                            .checked_add(alias.size as u64)
                            .is_some_and(|limit| end <= limit)
                            && alias.physical_ipa == mapping.physical_ipa
                            && alias.physical_size == mapping.physical_size
                            && alias.owner_generation == mapping.owner_generation
                            && alias.ipa.checked_add(address - alias.start)
                                == mapping.ipa.checked_add(address - mapping.start)
                    },
                )
                .is_some()
        };
        if let Some(mapping) = self
            .mappings
            .candidates_for_range(GuestVa(address), length as u64)
            .find(|mapping| {
                mapping.contains_range(address, length)
                    && region_is_live(mapping)
                    && row_projection_is_current(mapping)
            })
        {
            return Some(mapping.view());
        }
        if !self.protections.range_no_access(address, length) {
            if let Some(alias) = alias_registry().lock().newest_process_alias_containing_va(
                address,
                self.mm_root_slot,
                self.container_root,
                |alias| {
                    address.checked_add(length as u64).is_some_and(|end| {
                        alias
                            .start
                            .checked_add(alias.size as u64)
                            .is_some_and(|limit| end <= limit)
                    }) && alias_is_live(alias)
                },
            ) {
                return Some(MappingView::from_alias(&alias));
            }
        }
        None
    }

    fn supersede_cow_receipts_for_cow(&self, va: u64, len: u64) {
        let Some(end) = va.checked_add(len) else {
            return;
        };
        let mut receipts = self.cow_deferred_publications.lock();
        let mut remaining = Vec::with_capacity(receipts.len());
        for receipt in receipts.drain(..) {
            let receipt_end = receipt.va.saturating_add(receipt.len as u64);
            if receipt_end <= va || receipt.va >= end {
                remaining.push(receipt);
                continue;
            }
            let overlap_start = receipt.va.max(va);
            let overlap_end = receipt_end.min(end);
            if receipt.va < overlap_start
                && let Ok(prefix) = usize::try_from(overlap_start - receipt.va)
            {
                remaining.push(PendingFrameCowPublication {
                    va: receipt.va,
                    len: prefix,
                    expected_ipa: receipt.expected_ipa,
                });
            }
            if overlap_end < receipt_end
                && let Ok(suffix) = usize::try_from(receipt_end - overlap_end)
                && let Some(expected_ipa) =
                    receipt.expected_ipa.checked_add(overlap_end - receipt.va)
            {
                remaining.push(PendingFrameCowPublication {
                    va: overlap_end,
                    len: suffix,
                    expected_ipa,
                });
            }
        }
        *receipts = remaining;
    }

    fn retire_stage2_extent_for_cow(
        &mut self,
        custody: &CarrierVmCustody,
        ipa: u64,
        length: u64,
    ) -> Result<(), TrapError> {
        HvfVmState::retire_stage2_extent_from_mappings_in(custody, &mut self.mappings, ipa, length)
    }

    fn neutral() -> Self {
        let page_tables = carrick_aarch64::Stage1Authority::new();
        let protections = std::sync::Arc::new(MemoryProtections::default());
        let frame_inventory =
            std::sync::Arc::new(parking_lot::Mutex::new(HvpatchFrameInventory::default()));
        let cow_armed = std::sync::Arc::new(parking_lot::Mutex::new(CowArmedRanges::default()));
        let cow_deferred_publications = std::sync::Arc::new(parking_lot::Mutex::new(Vec::new()));
        Self {
            #[cfg(not(test))]
            custody: std::sync::Arc::new(CarrierVmCustody::new()),
            mappings: TaskMappingIndex::new(),
            mm_root_slot: None,
            container_root: ContainerRootToken(0),
            pending_exec_mm_root_slot: None,
            pending_exec_asid: None,
            pending_exec_predecessor_identity: None,
            pending_exec_stage2_cleanup: None,
            shared_process_mm: false,
            mm_access: MmAccessState::new(
                page_tables,
                protections,
                frame_inventory,
                cow_armed,
                cow_deferred_publications,
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
        }
    }

    fn audit_neutral(&self) -> Result<(), TrapError> {
        let protections = self.protections.snapshot_all();
        let inventory = self.frame_inventory.ledger.lock();
        let frames = inventory.frames.lock();
        let neutral = self.mappings.is_empty()
            && self.mm_root_slot.is_none()
            && self.container_root == ContainerRootToken(0)
            && self.pending_exec_mm_root_slot.is_none()
            && self.pending_exec_asid.is_none()
            && self.pending_exec_stage2_cleanup.is_none()
            && self.last_exit_class == 0
            && self.last_fault_esr == 0
            && !self.is_forked_child
            && !self.forked_no_exec
            && protections.no_access.is_empty()
            && protections.unmapped.is_empty()
            && protections.no_write.is_empty()
            && protections.executable.is_empty()
            && protections.bus_fault.is_empty()
            && protections.mutable_shared_backing.is_empty()
            && self.page_tables_authority().is_none()
            && self.last_syscall_nr.is_none()
            && self.last_syscall_orig_x0 == 0
            && !self.persistent_vm_lifecycle
            && !inventory.initialized
            && inventory.extents.is_empty()
            && frames.shared.is_empty()
            && frames.references.is_empty()
            && frames.extent_references.is_empty()
            && frames.stage2_references.is_empty()
            && frames.authority_retained_stage2.is_empty()
            && inventory.alias_reservation.is_none()
            && inventory.alias_commit.is_none()
            && inventory.alias_staged.is_empty()
            && inventory.process_reservation.is_none()
            && inventory.process_commit.is_none()
            && inventory.retired_reservation.is_none()
            && inventory.replacement_reservation.is_none()
            && inventory.exec_commits.is_none()
            && inventory.retirement_reservation.is_none()
            && inventory.retirement_commit.is_none()
            && self.cow_authority.is_none()
            && self.cow_identity.is_none()
            && self.cow_armed.lock().ranges.is_empty()
            && self.cow_deferred_publications.lock().is_empty()
            && self.pending_fork_frame_receipts.is_empty()
            && self.pending_process_aliases.is_empty()
            && self.cow_rollback_scratch.is_none()
            && self.registration.is_none();
        drop(frames);
        drop(inventory);
        neutral.then_some(()).ok_or_else(|| {
            TrapError::Hypervisor("idle HVPatch worker retained task authority".to_owned())
        })
    }

    /// Whether an execve on this task retires the old mm's extents.
    ///
    /// A vfork / `CLONE_VM` child shares its mm with a live sharer that keeps
    /// every mapping, so its exec retires nothing: the replacement gets a fresh
    /// ledger and the old one stays whole. Callers must arm no retirement
    /// transaction in that case — a reservation filled with zero events is
    /// rejected by the Kernel authority, and the exec is already past its point
    /// of no return by the time the commit is applied.
    pub(crate) fn exec_retires_old_mm(&self) -> bool {
        !self.shared_process_mm
    }

    /// Extents this task's execve will retire from the old mm: none when a
    /// live sharer still owns it.
    pub(crate) fn exec_retired_extent_count(&self) -> usize {
        if self.exec_retires_old_mm() {
            self.frame_inventory.lock().extents.len()
        } else {
            0
        }
    }

    fn begin_exec_inventory(
        &mut self,
        retired: Option<carrick_hal::FrameInventoryReservation>,
        replacement: carrick_hal::FrameInventoryReservation,
    ) -> Result<(), TrapError> {
        if std::mem::take(&mut self.fail_next_begin_exec_inventory) {
            return Err(TrapError::Hypervisor(
                "injected HVPatch begin_exec_inventory failure".to_owned(),
            ));
        }
        if self.shared_process_mm {
            // The parent still owns this ledger. Exec starts a fresh backend
            // ledger for the replacement MM so it cannot remove the parent's
            // mappings. Nothing is retired, so `retired` is `None` here:
            // reserving a retirement would stage zero events against the fresh
            // ledger, and the Kernel authority rejects a zero-event commit.
            let frames = self.frame_inventory.lock().frames.clone();
            self.mm_access = MmAccessState::new(
                self.page_tables_authority(),
                std::sync::Arc::clone(&self.protections),
                std::sync::Arc::new(parking_lot::Mutex::new(HvpatchFrameInventory::with_frames(
                    frames,
                ))),
                std::sync::Arc::clone(&self.cow_armed),
                std::sync::Arc::clone(&self.cow_deferred_publications),
            );
        }
        self.frame_inventory
            .begin_exec_inventory(retired, replacement)
    }

    pub(crate) fn set_persistent_vm_lifecycle(&mut self, enabled: bool) {
        self.persistent_vm_lifecycle = enabled;
    }

    pub(crate) fn sparse_mmap_arena_enabled(&self) -> bool {
        self.persistent_vm_lifecycle
    }

    /// Retire the generic boot loader's hidden 32 GiB mmap backing after the
    /// runtime selects HVPatch, but before initial frame inventory publication.
    /// Mature VMM never enables the persistent lifecycle and keeps its existing
    /// eager identity mapping unchanged.
    ///
    /// **Once per carrier VM, not once per container.** The unmap below is
    /// `inventory_hv_vm_unmap` over the WHOLE arena extent, which is VM-wide
    /// state, while this runs during each container's root bring-up. With one
    /// VM per container that distinction did not exist. With a carrier VM
    /// shared by several containers it is the difference between retiring an
    /// eager mapping nobody is using yet and tearing out the sparse per-page
    /// backing a SIBLING container has already faulted in inside that same
    /// range — the sibling's next access then takes a level-1 translation
    /// fault on an address it was legitimately handed, and its guest dies of
    /// SIGSEGV within a few traps.
    ///
    /// The carrier's root boot gate serializes VM ownership and the first root
    /// publishes the carrier bundle before any guest instruction runs, so the
    /// first caller retires while no guest can yet hold sparse pages, and
    /// every later container skips it. Absence remains tolerated for the same
    /// reason it always was: a later container's plan omits the eager mapping.
    /// What is NOT tolerated is a second unmap.
    pub(crate) fn retire_initial_mmap_arena(&mut self) -> Result<(), TrapError> {
        if !self.persistent_vm_lifecycle {
            return Ok(());
        }
        if carrier_initial_arena_retired().swap(true, std::sync::atomic::Ordering::AcqRel) {
            return Ok(());
        }
        let Some(mapping) = self.mappings.get(&GuestVa(crate::memory::LINUX_MMAP_BASE)) else {
            return Ok(());
        };
        if mapping.end
            != crate::memory::LINUX_MMAP_BASE.saturating_add(crate::memory::mmap_arena_size())
            || mapping.physical_ipa != crate::memory::LINUX_MMAP_BASE
            || mapping.physical_size as u64 != crate::memory::mmap_arena_size()
            || mapping.is_dynamic_alias
            || mapping.stage2_lease.is_some()
            || mapping.host_mapping.is_none()
        {
            return Err(TrapError::Hypervisor(
                "HVPatch initial mmap arena backing has unexpected shape or ownership".to_owned(),
            ));
        }
        let rc = unsafe { inventory_hv_vm_unmap(mapping.physical_ipa, mapping.physical_size) };
        if rc != 0 {
            return Err(TrapError::Hypervisor(format!(
                "unmap HVPatch initial sparse mmap arena: 0x{rc:x}"
            )));
        }
        self.mappings.remove_range(
            GuestVa(crate::memory::LINUX_MMAP_BASE),
            crate::memory::mmap_arena_size() as usize,
        );
        Ok(())
    }
}

#[cfg(test)]
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn hvpatch_task_state_test_fixture(
    mm_slot: u64,
    mapping_start: u64,
    linux_tid: i32,
) -> HvfTaskState {
    let cow_authority: std::sync::Arc<dyn carrick_hal::FrameCowAuthority> =
        std::sync::Arc::new(task_only_carrier_directory_tests::TestCowAuthority);
    let page_tables = carrick_aarch64::Stage1Authority::new();
    let protections = std::sync::Arc::new(MemoryProtections::default());
    let frame_inventory =
        std::sync::Arc::new(parking_lot::Mutex::new(HvpatchFrameInventory::default()));
    let cow_armed = std::sync::Arc::new(parking_lot::Mutex::new(CowArmedRanges::default()));
    let cow_deferred_publications = std::sync::Arc::new(parking_lot::Mutex::new(Vec::new()));
    HvfTaskState {
        mappings: TaskMappingIndex::from_region(HvfMappedRegion {
            start: mapping_start,
            end: mapping_start + 0x1000,
            ipa: mapping_start + 0x10_0000,
            physical_ipa: mapping_start + 0x10_0000,
            host_addr: std::ptr::null_mut(),
            size: 0x1000,
            physical_size: 0x1000,
            perms: applevisor::memory::MemPerms::ReadWrite,
            memory: None,
            host_mapping: None,
            structural_owner: None,
            stage2_lease: None,
            is_dynamic_alias: false,
            sharing: GuestMappingSharing::Private,
            guest_writable: true,
            shared_key_base: 0,
            shared_key_offset: 0,
            owner_generation: mm_slot,
        }),
        mm_root_slot: Some((mm_slot << 20, 0x20_0000)),
        container_root: ContainerRootToken::from_raw(1),
        pending_exec_mm_root_slot: None,
        pending_exec_asid: None,
        pending_exec_predecessor_identity: None,
        pending_exec_stage2_cleanup: None,
        shared_process_mm: false,
        mm_access: MmAccessState::new(
            page_tables,
            protections,
            frame_inventory,
            cow_armed,
            cow_deferred_publications,
        ),
        last_exit_class: 0,
        last_fault_esr: 0,
        is_forked_child: false,
        forked_no_exec: false,
        last_syscall_nr: None,
        last_syscall_orig_x0: 0,
        live_vcpu: crate::vcpu_kick::LiveVcpuSlot::new(),
        persistent_vm_lifecycle: true,
        cow_authority: Some(cow_authority),
        cow_identity: Some(carrick_hal::FrameCowIdentity {
            linux_pid: 7,
            linux_tid,
            mm: mm_slot,
            asid: u16::try_from(mm_slot).unwrap(),
        }),
        pending_fork_frame_receipts: Vec::new(),
        pending_process_aliases: Vec::new(),
        fail_next_begin_exec_inventory: false,
        cow_rollback_scratch: None,
        registration: None,
    }
}

#[cfg(test)]
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct HvpatchTaskStateTestIdentity {
    mm_root_slot: Option<(u64, u64)>,
    first_mapping: u64,
    linux_tid: i32,
    page_tables: usize,
    frame_inventory: usize,
    cow_authority: usize,
    mm_access: usize,
}

#[cfg(test)]
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn hvpatch_task_state_test_identity(
    state: &HvfTaskState,
) -> HvpatchTaskStateTestIdentity {
    let authority = state
        .cow_authority
        .as_ref()
        .map(|authority| std::sync::Arc::as_ptr(authority) as *const () as usize)
        .unwrap_or_default();
    HvpatchTaskStateTestIdentity {
        mm_root_slot: state.mm_root_slot,
        first_mapping: state.mappings.first().map_or(0, |mapping| mapping.start),
        linux_tid: state.cow_identity.map_or(0, |identity| identity.linux_tid),
        page_tables: state.page_tables_authority().authority_id() as usize,
        frame_inventory: std::sync::Arc::as_ptr(&state.frame_inventory.ledger) as usize,
        cow_authority: authority,
        mm_access: std::sync::Arc::as_ptr(&state.mm_access) as usize,
    }
}

#[cfg(test)]
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn hvpatch_neutral_task_state_for_test() -> HvfTaskState {
    HvfTaskState::neutral()
}

#[cfg(test)]
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn audit_hvpatch_neutral_task_state_for_test(
    state: &HvfTaskState,
) -> Result<(), TrapError> {
    state.audit_neutral()
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn bind_exec_predecessor_identity_slot(
    pending: &mut Option<carrick_hal::ExecPredecessorIdentity>,
    identity: carrick_hal::ExecPredecessorIdentity,
) -> Result<(), TrapError> {
    if identity.task_serial == 0
        || identity.thread_serial == 0
        || identity.linux_pid <= 0
        || identity.linux_tid <= 0
        || identity.mm == 0
        || identity.asid == 0
    {
        return Err(TrapError::Hypervisor(
            "invalid exact HVPatch exec predecessor identity".to_owned(),
        ));
    }
    if pending.is_some() {
        return Err(TrapError::Hypervisor(
            "duplicate exact HVPatch exec predecessor identity".to_owned(),
        ));
    }
    *pending = Some(identity);
    Ok(())
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl HvfVmState {
    pub(crate) fn bind_deferred_anonymous_state(
        &mut self,
        state: std::sync::Arc<carrick_guest_mem::DeferredAnonymousState>,
    ) {
        let mm = carrick_hal::ForeignMmId::from_kernel_allocation(
            self.cow_identity
                .and_then(|identity| std::num::NonZeroU64::new(identity.mm))
                .unwrap_or_else(|| {
                    carrick_fatal!(
                        "hvpatch::deferred_materialization_binding",
                        "local HVF state has no nonzero COW MM identity while binding deferred-memory authority"
                    )
                }),
        );
        let mut binding = self.mm_access.deferred_anonymous.write();
        if let Some((bound_mm, bound_state)) = binding.as_ref()
            && (*bound_mm != mm || !std::sync::Arc::ptr_eq(bound_state, &state))
        {
            carrick_fatal!(
                "hvpatch::deferred_materialization_binding",
                "local HVF state already holds a different MM or deferred-memory authority"
            );
        }
        *binding = Some((mm, state));
    }

    pub(crate) fn deferred_anonymous_state(
        &self,
    ) -> Option<std::sync::Arc<carrick_guest_mem::DeferredAnonymousState>> {
        let mm = carrick_hal::ForeignMmId::from_kernel_allocation(std::num::NonZeroU64::new(
            self.cow_identity?.mm,
        )?);
        self.mm_access
            .deferred_anonymous
            .read()
            .as_ref()
            .filter(|(bound_mm, _)| *bound_mm == mm)
            .map(|(_, state)| std::sync::Arc::clone(state))
    }

    pub(crate) fn carrier_vm_custody(&self) -> std::sync::Arc<CarrierVmCustody> {
        std::sync::Arc::clone(&self.carrier_foreign_mm_transport.custody)
    }
    pub(crate) fn foreign_mm_endpoint(&self) -> carrick_hal::ForeignMmEndpoint {
        carrick_hal::ForeignMmEndpoint::for_carrier(self.carrier_foreign_mm_transport.clone())
    }

    pub(crate) fn bind_frame_cow(
        &mut self,
        authority: std::sync::Arc<dyn carrick_hal::FrameCowAuthority>,
        identity: carrick_hal::FrameCowIdentity,
    ) {
        self.task.bind_frame_cow(authority, identity);
        if let (Some(mm), Some(asid), Some((stage1_root, _))) = (
            std::num::NonZeroU64::new(identity.mm),
            std::num::NonZeroU16::new(identity.asid),
            self.task.mm_root_slot,
        ) {
            self.carrier_foreign_mm_transport.register_identity(
                carrick_hal::ForeignMmId::from_kernel_allocation(mm),
                CarrierForeignMmBinding {
                    asid: carrick_hal::ForeignAsid::from_kernel_allocation(asid),
                    stage1_root: carrick_guest_mem::Gpa(stage1_root),
                },
                &self.task.mm_access,
            );
        }
    }

    pub(crate) fn prepare_exec_address_space(
        &mut self,
        root_slot_base: u64,
        root_slot_size: u64,
        asid: u16,
    ) -> Result<(), TrapError> {
        if !root_slot_base.is_multiple_of(HVF_PAGE_SIZE) || root_slot_size == 0 || asid == 0 {
            return Err(TrapError::Hypervisor(
                "invalid exact HVPatch exec MM lease".to_owned(),
            ));
        }
        if self.pending_exec_mm_root_slot.is_some() || self.pending_exec_asid.is_some() {
            return Err(TrapError::Hypervisor(
                "duplicate exact HVPatch exec MM lease".to_owned(),
            ));
        }
        self.pending_exec_mm_root_slot = Some((root_slot_base, root_slot_size));
        self.pending_exec_asid = Some(asid);
        Ok(())
    }

    pub(crate) fn bind_exec_predecessor_identity(
        &mut self,
        identity: carrick_hal::ExecPredecessorIdentity,
    ) -> Result<(), TrapError> {
        bind_exec_predecessor_identity_slot(&mut self.pending_exec_predecessor_identity, identity)
    }

    /// See `carrick_hal::ThreadedEngine::mark_exec_predecessor_shared`. The
    /// flag drives `exec_retires_old_mm`, the fresh-ledger split in
    /// `begin_exec_inventory`, and `execve_rebuild`'s `shared_projection`;
    /// `execve_rebuild` clears it after capturing the projection.
    pub(crate) fn mark_exec_predecessor_shared(&mut self, shared: bool) {
        self.shared_process_mm = shared;
    }

    pub(crate) fn swap_persistent_executor_local(&mut self, other: &mut Self) {
        if !std::sync::Arc::ptr_eq(
            &self.carrier_foreign_mm_transport,
            &other.carrier_foreign_mm_transport,
        ) {
            carrick_fatal!(
                "hvpatch::executor_boundary",
                "swapping persistent executor-local state across mismatched carrier foreign MM transport instances"
            );
        }
        std::mem::swap(&mut self._vm, &mut other._vm);
        std::mem::swap(&mut self.carrier_mappings, &mut other.carrier_mappings);
        std::mem::swap(&mut self.reclaim_authority, &mut other.reclaim_authority);
        std::mem::swap(&mut self.mailbox_slots, &mut other.mailbox_slots);
        std::mem::swap(&mut self.syscall_transport, &mut other.syscall_transport);
        std::mem::swap(&mut self.vcpu_id, &mut other.vcpu_id);
        std::mem::swap(&mut self.vcpu_handle, &mut other.vcpu_handle);
    }
}

/// Thread/process exit must LEAK the per-thread host backings, never `munmap`
/// them. All sibling threads share ONE host address space, and the
/// process-global [`alias_registry`] holds NON-OWNING raw `host_addr`s into
/// these same buffers. A clone thread exiting (its `run_vcpu_until_exit` returns
/// → this `Drop` runs on its `HvfVmState`) that `munmap`'d a buffer it happens
/// to OWN — e.g. a `kind=SharedFile` `MAP_SHARED` semaphore alias it
/// `add_alias`'d — would yank that buffer out from under every sibling thread
/// AND leave a DANGLING registry entry that a later syscall (`read_futex_word`
/// on the process-shared semaphore) resolves to a dead pointer → a carrick HOST
/// SIGSEGV. That is the cpython multiprocessing FORKSERVER SyncManager crash:
/// the Manager's pool teardown exits a clone thread whose `self.mappings` owned
/// the live sem buffer. The kernel reclaims every mapping at process exit; the
/// fork/execve rebuilds already `mem::forget` `self.mappings` for exactly this
/// reason. (Restores the leak-until-exit discipline the pre-`Aarch64EngineCore`
/// refactor's no-op engine `Drop` provided — see the `unregister_alias` doc.)
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl Drop for HvfVmState {
    fn drop(&mut self) {
        std::mem::forget(std::mem::take(&mut self.mappings));
    }
}

/// Owns ONLY the three vCPU-touching associated functions the shared engine
/// reaches through the `Aarch64Vcpu` trait — the native-exit decode
/// (`run_to_exit`) and the snapshot/restore I/O — so they are free of
/// `HvfVmState` (they take the bare `applevisor` vCPU). The name is kept so the
/// new module's `HvfInner::snapshot_vcpu_from` / `restore_vcpu_into` /
/// `run_to_exit` paths resolve unchanged.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) struct HvfInner;

/// Overwrite `slot`'s VM in place WITHOUT running applevisor's `VirtualMachine`
/// Drop on the old (already raw-destroyed) handle — the single no-drop VM
/// replacement point (the fork/execve rebuilds). `mem::forget` the old (it was
/// `hv_vm_destroy`'d via the raw API; running its wrapper Drop now would panic).
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn replace_destroyed_vm(
    slot: &mut HvfVmState,
    new_vm: applevisor::vm::VirtualMachineInstance<applevisor::vm::GicDisabled>,
) {
    let old = std::mem::replace(&mut slot._vm, std::mem::ManuallyDrop::new(new_vm));
    std::mem::forget(std::mem::ManuallyDrop::into_inner(old));
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Debug)]
pub(crate) struct HvfMappedRegion {
    /// Guest VIRTUAL start (the syscall-path lookup key). Differs from `ipa`
    /// only for the Rosetta high-VA alias.
    start: u64,
    end: u64,
    /// IPA this region was `hv_vm_map`'d at — needed to re-map across fork(2).
    /// Identity (== `start`) for every region but the Rosetta window.
    ipa: u64,
    /// Exact HVF stage-2 extent. `ipa`/`size` are the live semantic projection;
    /// a partial 4 KiB Linux mapping can retain a 16 KiB physical owner whose
    /// base precedes that projection. Lifetime decisions must use this tuple.
    physical_ipa: u64,
    physical_size: usize,
    /// Which incarnation of the global-frame lease this row was published
    /// against — see [`GlobalFrameHostOwner::generation`].
    owner_generation: u64,
    /// Host VA of the buffer backing this guest-physical mapping. We
    /// record this explicitly so the fork(2) path can re-issue
    /// `hv_vm_map` in the child against the same (COW'd) host pages
    /// without going through `applevisor::Memory::new` (which would
    /// allocate a fresh buffer).
    host_addr: *mut u8,
    /// Size of the mapping in bytes (matches the size HVF was given).
    size: usize,
    /// Stage-2 permissions used to map the region. Same value that
    /// `hvf_perms` returned; the child rebuilds the mapping with these
    /// exact permissions.
    perms: applevisor::memory::MemPerms,
    /// `Memory` owns the host allocation and the hv_vm_unmap that
    /// fires on Drop. In a freshly-forked CHILD we replace this with
    /// `None` (after `mem::forget` on the inherited inner) — the host
    /// pages stay alive via COW; the unmap would target the parent's
    /// HVF context which no longer exists in the child.
    ///
    /// `#[allow(dead_code)]`: these are RAII ownership holders, kept alive for
    /// their `Drop` side effects (freeing host pages), not read. Every region
    /// is now built by `map_region_raw` with `memory: None` +
    /// `host_mapping: Some(..)`.
    #[allow(dead_code)]
    memory: Option<applevisor::memory::Memory>,
    #[allow(dead_code)]
    host_mapping: Option<crate::host_mapping::OwnedHostMapping>,
    #[allow(dead_code)]
    structural_owner: Option<std::sync::Arc<StructuralBackingOwner>>,
    /// Owning rollback/retirement handle for a fresh HVPatch stage-2 extent.
    /// Inherited mappings and dynamic aliases owned by the process-global
    /// host-owner registry carry `None`.
    stage2_lease: Option<GlobalFrameStage2Lease>,
    /// True only for a post-boot alias published through `add_alias`. Retired
    /// aliases deliberately remain in `mappings` to keep their host/stage-2
    /// owners alive, but the live alias registry decides whether they enter a
    /// fork child's address-space inventory.
    is_dynamic_alias: bool,
    /// Separates host/fork visibility from VM-global IPA and futex identity.
    /// Both shared variants keep one host backing across guest fork, while only
    /// `GlobalShared` participates in the historical global alias namespace.
    sharing: GuestMappingSharing,
    /// The guest's INTENDED writability (Linux PROT_WRITE), tracked separately
    /// from `perms` — alias regions force `perms` to RWX for the HVF stage-2
    /// translation quirk, so it cannot be used to detect a read-only mapping.
    /// The syscall write-path (`write_guest_bytes_checked`) rejects a write into
    /// a non-writable mapping with EFAULT instead of faulting the host (SIGBUS on
    /// a PROT_READ MAP_SHARED file alias) or corrupting a carrick-owned
    /// `write:false` region. (audit M1; probe `rosharedbus`)
    guest_writable: bool,
    shared_key_base: u64,
    shared_key_offset: u64,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl HvfMappedRegion {
    /// Whether this row still owns something whose `Drop` frees backing.
    ///
    /// A row holding any of these is a lifetime holder: dropping it releases
    /// host pages, a stage-2 lease or a structural owner. A row holding none
    /// of them is pure description -- which is NOT the same as "safe to
    /// forget"; see [`TaskMappingIndex::displace_overlapping`].
    #[cfg_attr(not(test), allow(dead_code))]
    fn holds_backing_handle(&self) -> bool {
        self.memory.is_some()
            || self.host_mapping.is_some()
            || self.structural_owner.is_some()
            || self.stage2_lease.is_some()
    }
}

/// A copyable projection of the scalar fields of an [`HvfMappedRegion`] that the
/// syscall-path accessors actually read (`start`/`end`/`ipa`/`host_addr`/`size`/
/// `guest_writable`/sharing). [`HvfInner::mapping_for_range`] returns this
/// by value instead of `&HvfMappedRegion` so a lookup that resolves through the
/// PROCESS-SHARED `alias_registry` fallback (a high-VA alias another thread
/// mapped, absent from THIS thread's per-thread `mappings`) can synthesize a view
/// with no borrow into `self.mappings`. The copy loops compute
/// `host_addr + (addr - start)`, so a synthetic view sets `start` to the alias VA
/// base and `host_addr` to its backing base — identical offset math to a real
/// region.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy)]
pub(crate) struct MappingView {
    start: u64,
    end: u64,
    ipa: u64,
    host_addr: *mut u8,
    guest_writable: bool,
    sharing: GuestMappingSharing,
    shared_key_base: u64,
    shared_key_offset: u64,
}

/// Snapshot of vCPU register state used for reclaim and executor rebinding.
///
/// The architectural register file lives in the ISA-neutral
/// [`Aarch64VcpuSnapshot`] `core` — the SAME type the shared engine and the KVM
/// lane trade in — so the HVF lane no longer duplicates those 21 fields. The
/// per-VMM HVF↔neutral mapping (CPSR ↔ `core.pstate` and the `*_EL1`
/// sysreg names ↔ their neutral aliases) lives in
/// `snapshot_vcpu_from`/`restore_vcpu*`; mailbox rebinding owns SP_EL1. The
/// TTBR1_EL1 (Rosetta x86-64 high-half
/// root) / ACTLR_EL1 (Rosetta EnTSO) / TPIDR*_EL0 (musl TLS, vDSO/rseq) capture
/// rationales are documented on the neutral fields.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Debug, Clone)]
pub(crate) struct VcpuSnapshot {
    /// The ISA-neutral architectural register file (GPRs, EL1 sysregs, V-regs, FP
    /// control) shared with the engine and the KVM lane.
    pub(crate) core: Aarch64VcpuSnapshot,
}

// Off macOS/aarch64 the HVF backend is cfg'd out entirely (no `applevisor`, no
// `HvfTrapEngine` alias, no register-access helpers), so there is no non-macOS
// `HvfInner` marker to carry — `HvfInner` exists ONLY on the macOS/HVF lane.

/// One mapping descriptor for a thread sibling: the guest-physical range,
/// the host VA backing it, its size, and the stage-2 perms. The sibling vCPU
/// lives in the same HVF VM as the parent, so the stage-2 entries are already
/// present; the descriptor only re-materialises local syscall-path metadata as
/// `HvfMappedRegion { memory: None }` (UNOWNED) so the sibling never
/// unmaps/frees buffers the main engine owns.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Debug, Clone)]
pub(crate) struct ThreadMappingDesc {
    start: u64,
    ipa: u64,
    end: u64,
    host_addr: *mut u8,
    size: usize,
    physical_ipa: u64,
    physical_host_addr: *mut u8,
    physical_size: usize,
    perms: applevisor::memory::MemPerms,
    is_dynamic_alias: bool,
    sharing: GuestMappingSharing,
    guest_writable: bool,
    shared_key_base: u64,
    shared_key_offset: u64,
    owner_generation: u64,
    structural_owner: Option<std::sync::Arc<StructuralBackingOwner>>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ForkMappingDisposition {
    /// Parent and child keep the same frame and the same writable permissions.
    SharedFrameWritable,
    /// Parent and child name the same private frame, with both stage-1 leaves
    /// armed read-only until one mm takes the write-permission COW fault.
    SharedFrameReadOnly,
    /// Carrick-owned stage-1 tables are per-mm mutable kernel state, so the
    /// child receives an independent table frame before publication.
    IndependentPageTables,
    /// Carrick-owned EL1 identity/mailbox state is never guest-accessible and
    /// must be writable before the exception vector can run.  Give the child a
    /// fresh per-mm frame before entry rather than depending on recovery from a
    /// current-EL write-permission fault.
    IndependentKernelState,
    /// `MADV_WIPEONFORK`: the child must see this guest mapping as fresh zero
    /// pages while the parent keeps its contents, so it cannot share the
    /// parent's frame even read-only. The child gets its own frame, seeded with
    /// the parent's bytes and then zeroed across exactly the wiped sub-ranges
    /// -- the frame can be wider than the semantic window and can carry other
    /// aliases' bytes, which must survive.
    IndependentGuestZeroed,
}

/// What the dispatcher's fork projection says about ONE VMM mapping's span.
///
/// `derive_fork_projection` turns the `madvise` fork policies into per-VMA
/// `ForkLeafDisposition`s and `ProcessForkRequest` carries them all the way
/// here, but the VMM used to derive every disposition from the mapping's own
/// properties and never read the plan -- so `MADV_DONTFORK`/`MADV_WIPEONFORK`
/// changed carrick's metadata while the child still inherited the pages.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Debug, Eq, PartialEq)]
enum ProjectedForkSpan {
    /// No omitted or zeroed range touches this mapping.
    Preserve,
    /// `MADV_DONTFORK` covers the WHOLE span: the child gets no mapping here.
    Omit,
    /// `MADV_WIPEONFORK` covers part or all of the span. Byte ranges are
    /// relative to the mapping's semantic start.
    Zero { wiped: Vec<(u64, u64)> },
    /// `MADV_DONTFORK` covers only PART of the span. A hole inside one physical
    /// mapping is not representable in a single descriptor, and silently
    /// preserving the range would hand the child memory the guest asked it not
    /// to inherit, so this fails closed instead.
    PartialOmit,
}

/// Intersect one VMM mapping's semantic span with the fork projection.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn projected_fork_span(
    ranges: &[carrick_hal::ForkProjectionRange],
    start: u64,
    end: u64,
) -> ProjectedForkSpan {
    if end <= start {
        return ProjectedForkSpan::Preserve;
    }
    let mut omitted: u64 = 0;
    let mut wiped: Vec<(u64, u64)> = Vec::new();
    for range in ranges {
        let range_end = range.va.saturating_add(range.len);
        let lo = range.va.max(start);
        let hi = range_end.min(end);
        if hi <= lo {
            continue;
        }
        match range.disposition {
            carrick_hal::ForkLeafDisposition::Omit => omitted = omitted.saturating_add(hi - lo),
            carrick_hal::ForkLeafDisposition::Zero => wiped.push((lo - start, hi - lo)),
            carrick_hal::ForkLeafDisposition::Preserve => {}
        }
    }
    if omitted > 0 {
        return if omitted == end - start {
            ProjectedForkSpan::Omit
        } else {
            ProjectedForkSpan::PartialOmit
        };
    }
    if wiped.is_empty() {
        ProjectedForkSpan::Preserve
    } else {
        ProjectedForkSpan::Zero { wiped }
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn fork_mapping_disposition(
    mapping: &ThreadMappingDesc,
    shares_mm: bool,
) -> ForkMappingDisposition {
    if mapping.sharing.shares_across_fork() {
        ForkMappingDisposition::SharedFrameWritable
    } else if mapping.start == crate::memory::LINUX_PAGE_TABLES_BASE {
        ForkMappingDisposition::IndependentPageTables
    } else if mapping.guest_writable && is_kernel_only_stage1_range(mapping.start, mapping.size) {
        ForkMappingDisposition::IndependentKernelState
    } else if shares_mm && !is_kernel_only_stage1_range(mapping.start, mapping.size) {
        ForkMappingDisposition::SharedFrameWritable
    } else {
        ForkMappingDisposition::SharedFrameReadOnly
    }
}

/// Apply the dispatcher's fork projection on top of the mapping's own
/// disposition.
///
/// The projection describes GUEST VMAs, so it may only redirect a mapping that
/// would otherwise be shared with the child. Carrick's own per-mm state (the
/// stage-1 tables and the EL1 control frame) keeps its disposition: those
/// ranges have no semantic VMA and must exist in every child.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn projected_fork_mapping_disposition(
    mapping: &ThreadMappingDesc,
    shares_mm: bool,
    ranges: &[carrick_hal::ForkProjectionRange],
) -> ForkMappingPlan {
    let base = fork_mapping_disposition(mapping, shares_mm);
    if !matches!(
        base,
        ForkMappingDisposition::SharedFrameWritable | ForkMappingDisposition::SharedFrameReadOnly
    ) {
        return ForkMappingPlan::preserved(base);
    }
    match projected_fork_span(ranges, mapping.start, mapping.end) {
        ProjectedForkSpan::Preserve => ForkMappingPlan::preserved(base),
        ProjectedForkSpan::Omit => ForkMappingPlan::Omit,
        ProjectedForkSpan::Zero { wiped } => ForkMappingPlan::Map {
            disposition: ForkMappingDisposition::IndependentGuestZeroed,
            wiped,
        },
        ProjectedForkSpan::PartialOmit => ForkMappingPlan::PartialOmit,
    }
}

/// What one VMM mapping becomes in the child once the fork projection has been
/// applied on top of the mapping's own disposition.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Debug, Eq, PartialEq)]
enum ForkMappingPlan {
    /// The child gets the mapping. `wiped` names the sub-ranges, relative to
    /// the mapping's semantic start, whose bytes must read as zero there.
    Map {
        disposition: ForkMappingDisposition,
        wiped: Vec<(u64, u64)>,
    },
    /// `MADV_DONTFORK` over the whole span: the child gets nothing here.
    Omit,
    /// `MADV_DONTFORK` over only part of the span, which one descriptor cannot
    /// express. See `ProjectedForkSpan::PartialOmit`.
    PartialOmit,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl ForkMappingPlan {
    fn preserved(disposition: ForkMappingDisposition) -> Self {
        Self::Map {
            disposition,
            wiped: Vec::new(),
        }
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn fork_frame_receipt_kind(
    disposition: ForkMappingDisposition,
    start: u64,
    size: usize,
) -> Option<carrick_observability::probes::HvpatchForkFrameKind> {
    use carrick_observability::probes::HvpatchForkFrameKind;

    match disposition {
        ForkMappingDisposition::SharedFrameWritable => Some(HvpatchForkFrameKind::Shared),
        ForkMappingDisposition::SharedFrameReadOnly
            if !is_kernel_only_stage1_range(start, size) =>
        {
            Some(HvpatchForkFrameKind::PrivateCow)
        }
        ForkMappingDisposition::SharedFrameReadOnly
        | ForkMappingDisposition::IndependentPageTables
        | ForkMappingDisposition::IndependentKernelState
        // A wiped mapping shares no frame with the parent, so there is no
        // fork-frame receipt to publish for it.
        | ForkMappingDisposition::IndependentGuestZeroed => None,
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn is_stage1_cow_write_fault(syndrome: u64) -> bool {
    const EXCEPTION_CLASS_MASK: u64 = 0x3f;
    const DATA_ABORT_LOWER_EL: u64 = 0x24;
    const WRITE_NOT_READ: u64 = 1 << 6;
    const FAULT_STATUS_MASK: u64 = 0x3f;
    let exception_class = (syndrome >> 26) & EXCEPTION_CLASS_MASK;
    let fault_status = syndrome & FAULT_STATUS_MASK;
    matches!(exception_class, DATA_ABORT_LOWER_EL | 0x25)
        && syndrome & WRITE_NOT_READ != 0
        && matches!(fault_status, 0x0d..=0x0f)
}

fn frame_cow_write_is_denied(
    protection_denied: bool,
    guest_writable: bool,
    intent: carrick_aarch64::vmm::FrameCowWriteIntent,
) -> bool {
    intent == carrick_aarch64::vmm::FrameCowWriteIntent::GuestVisible
        && (protection_denied || !guest_writable)
}

fn frame_cow_preserves_guest_protection(intent: carrick_aarch64::vmm::FrameCowWriteIntent) -> bool {
    intent != carrick_aarch64::vmm::FrameCowWriteIntent::GuestVisible
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FrameCowWriteRoute {
    Direct,
    CopyOnWrite,
    MaterializeRetired,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UnarmedPermissionFaultRoute {
    NotCow,
    RetryCommittedWinner,
    MissingArm,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn unarmed_permission_fault_route(
    private_writable_mapping: bool,
    write_denied: bool,
    any_arms: bool,
    live_leaf_is_writable: bool,
) -> UnarmedPermissionFaultRoute {
    if !private_writable_mapping || write_denied {
        UnarmedPermissionFaultRoute::NotCow
    } else if live_leaf_is_writable {
        UnarmedPermissionFaultRoute::RetryCommittedWinner
    } else if !any_arms {
        UnarmedPermissionFaultRoute::NotCow
    } else {
        UnarmedPermissionFaultRoute::MissingArm
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn frame_cow_write_route(
    intent: carrick_aarch64::vmm::FrameCowWriteIntent,
    armed: bool,
    retained_output_has_no_physical_source: bool,
    retained_output_source_is_shared: bool,
) -> FrameCowWriteRoute {
    // A maintenance write whose retained output names a frame OTHER mms still
    // reference must MATERIALIZE a private replacement, exactly like the
    // no-source case — never write through. The armed-set cannot make this
    // call: it is derived at fork from alias rows and is known-omissive
    // (`mtforkcorrupt`), and an unarmed Direct write through a shared frame
    // zeroed one process's live memory during another's mmap reuse (the
    // CPython forkserver interned-dict corruption). The frame inventory's
    // reference count is the authority that actually knows who shares.
    if intent == carrick_aarch64::vmm::FrameCowWriteIntent::BackingMaintenance
        && (retained_output_has_no_physical_source || retained_output_source_is_shared)
    {
        FrameCowWriteRoute::MaterializeRetired
    } else if armed {
        FrameCowWriteRoute::CopyOnWrite
    } else {
        FrameCowWriteRoute::Direct
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn next_frame_cow_write_probe(
    intent: carrick_aarch64::vmm::FrameCowWriteIntent,
    current: u64,
    end: u64,
    armed_span_end: Option<u64>,
    next_armed_start: Option<u64>,
) -> u64 {
    // A 16 KiB physical frame may carry four independently mapped Linux 4 KiB
    // pages. Backing maintenance runs while reused leaves are invalid, and
    // those four outputs can therefore name a mixture of live, shared, and
    // retired owners. Classify each Linux page.
    if intent == carrick_aarch64::vmm::FrameCowWriteIntent::BackingMaintenance {
        return align_down(current, 0x1000).saturating_add(0x1000).min(end);
    }
    // A guest-visible write advances by exactly what the armed COW
    // transaction resolved: the span itself (one 16 KiB compound for a fork
    // arm, one 4 KiB page for a private file view whose clean siblings must
    // keep tracking the file). An unarmed page advances to the end of its
    // compound, but never past the next armed range: a page privatized out
    // of a compound leaves its siblings armed, and stepping over them would
    // write straight into a shared frame or a file view.
    let next = match armed_span_end {
        Some(span_end) if span_end > current => span_end,
        _ => {
            let compound_end = align_down(current, CowArmedRanges::COMPOUND_SIZE)
                .saturating_add(CowArmedRanges::COMPOUND_SIZE);
            match next_armed_start {
                Some(start) if start > current => compound_end.min(start),
                _ => compound_end,
            }
        }
    };
    next.max(current.saturating_add(1)).min(end)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy, Debug)]
struct FrameCowTrigger {
    class: carrick_observability::probes::HvpatchFrameCowTriggerClass,
    syndrome: u64,
    far: u64,
    ttbr0: u64,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl ThreadMappingDesc {
    /// Project a live region into a `Send`-safe descriptor for a `ThreadSpec` (the
    /// sibling thread mirrors it as an UNOWNED `HvfMappedRegion`). Called by
    /// `HvfVmState::build_thread_spec` (the per-VMM `build_sibling_builder`).
    fn from_region(region: &HvfMappedRegion) -> Self {
        let semantic_offset =
            usize::try_from(region.ipa.saturating_sub(region.physical_ipa)).unwrap_or(0);
        let physical_host_addr =
            (region.host_addr as usize).saturating_sub(semantic_offset) as *mut u8;
        Self {
            start: region.start,
            ipa: region.ipa,
            end: region.end,
            host_addr: region.host_addr,
            size: semantic_extent_size(region.start, region.end),
            physical_ipa: region.physical_ipa,
            physical_host_addr,
            physical_size: region.physical_size,
            perms: region.perms,
            is_dynamic_alias: region.is_dynamic_alias,
            sharing: region.sharing,
            guest_writable: region.guest_writable,
            shared_key_base: region.shared_key_base,
            shared_key_offset: region.shared_key_offset,
            owner_generation: region.owner_generation,
            structural_owner: region.structural_owner.clone(),
        }
    }

    fn from_alias(alias: AliasBacking) -> Option<Self> {
        let perms = match alias.perms {
            0 => applevisor::memory::MemPerms::None,
            1 => applevisor::memory::MemPerms::Read,
            2 => applevisor::memory::MemPerms::Write,
            3 => applevisor::memory::MemPerms::ReadWrite,
            4 => applevisor::memory::MemPerms::Exec,
            5 => applevisor::memory::MemPerms::ReadExec,
            6 => applevisor::memory::MemPerms::WriteExec,
            7 => applevisor::memory::MemPerms::ReadWriteExec,
            _ => return None,
        };
        Some(Self {
            start: alias.start,
            ipa: alias.ipa,
            end: alias.start.saturating_add(alias.size as u64),
            host_addr: alias.host_addr as *mut u8,
            size: alias.size,
            physical_ipa: alias.physical_ipa,
            physical_host_addr: alias.physical_host_addr as *mut u8,
            physical_size: alias.physical_size,
            perms,
            is_dynamic_alias: true,
            sharing: alias.sharing,
            guest_writable: alias.guest_writable,
            shared_key_base: alias.shared_key_base,
            shared_key_offset: alias.shared_key_offset,
            owner_generation: alias.owner_generation,
            structural_owner: None,
        })
    }

    fn from_alias_with_structural_owner(alias: AliasBacking, sources: &[Self]) -> Option<Self> {
        let semantic_projection_is_exact = alias
            .ipa
            .checked_sub(alias.physical_ipa)
            .and_then(|offset| usize::try_from(offset).ok())
            .filter(|offset| {
                offset
                    .checked_add(alias.size)
                    .is_some_and(|end| end <= alias.physical_size)
                    && alias
                        .physical_host_addr
                        .checked_add(*offset)
                        .is_some_and(|host_addr| host_addr == alias.host_addr)
            })
            .is_some();
        let structural_owner = if semantic_projection_is_exact {
            sources
                .iter()
                .filter_map(|source| source.structural_owner.as_ref())
                .find(|owner| {
                    owner.ptr() as usize == alias.physical_host_addr
                        && owner.physical_ipa == alias.physical_ipa
                        && owner.physical_size == alias.physical_size
                        && owner.epoch().raw() == alias.owner_generation
                })
                .cloned()
        } else {
            None
        };
        let mut mapping = Self::from_alias(alias)?;
        mapping.structural_owner = structural_owner;
        Some(mapping)
    }

    fn into_shared_mm_task_mapping(self) -> HvpatchTaskMappingState {
        HvpatchTaskMappingState {
            start: self.start,
            ipa: self.ipa,
            physical_ipa: self.physical_ipa,
            end: self.end,
            host_addr: self.host_addr,
            physical_host_addr: self.physical_host_addr,
            size: self.size,
            physical_size: self.physical_size,
            perms: self.perms,
            guest_writable: self.guest_writable,
            host_mapping: None,
            structural_owner: self.structural_owner,
            is_dynamic_alias: self.is_dynamic_alias,
            sharing: self.sharing,
            shared_key_base: self.shared_key_base,
            shared_key_offset: self.shared_key_offset,
            owner_generation: self.owner_generation,
            // A CLONE_VM edge views rows its process already owns.
            global_frame_owner_role: GlobalFrameOwnerRole::Borrowed,
        }
    }

    fn into_unowned_region(self) -> HvfMappedRegion {
        HvfMappedRegion {
            start: self.start,
            ipa: self.ipa,
            physical_ipa: self.physical_ipa,
            end: self.end,
            host_addr: self.host_addr,
            size: self.physical_size,
            physical_size: self.physical_size,
            perms: self.perms,
            memory: None,
            host_mapping: None,
            structural_owner: self.structural_owner,
            stage2_lease: None,
            is_dynamic_alias: self.is_dynamic_alias,
            sharing: self.sharing,
            guest_writable: self.guest_writable,
            shared_key_base: self.shared_key_base,
            shared_key_offset: self.shared_key_offset,
            owner_generation: self.owner_generation,
        }
    }
}

/// A root booting inside a live carrier must carry the SAME control image the
/// carrier installed: identical geometry for all five fixed mappings, and
/// identical bytes for the three code pages (EL0 trampoline, EL1 vectors, EL1
/// maintenance). The mailbox arena and the carrier maintenance root are live
/// data, so only their geometry is compared. Divergence is a build/config
/// error, never something to paper over by remapping.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn audit_plan_against_installed_carrier(
    plan: &GuestMappingPlan,
    carrier: &PersistentCarrierMappings,
) -> Result<(), TrapError> {
    let code_pages = [
        carrick_mem::memory::LINUX_EL0_TRAMPOLINE_BASE,
        carrick_mem::memory::LINUX_EL1_VECTORS_BASE,
        carrick_mem::memory::LINUX_EL1_MAINT_BASE,
    ];
    let mut seen = 0_usize;
    for mapping in plan
        .mappings
        .iter()
        .filter(|mapping| is_persistent_executor_carrier_guest_mapping(mapping))
    {
        seen += 1;
        let installed = carrier
            .mappings
            .iter()
            .find(|installed| installed.start == mapping.guest_start)
            .ok_or_else(|| {
                TrapError::Hypervisor(format!(
                    "carrier has no control mapping at 0x{:x}",
                    mapping.guest_start
                ))
            })?;
        if installed.end.saturating_sub(installed.start) != mapping.mapped_size {
            return Err(TrapError::Hypervisor(format!(
                "carrier control mapping 0x{:x} size {} differs from plan size {}",
                mapping.guest_start,
                installed.end.saturating_sub(installed.start),
                mapping.mapped_size
            )));
        }
        if code_pages.contains(&mapping.guest_start) {
            let payload = usize::try_from(mapping.payload_size)
                .map_err(|_| TrapError::MappingTooLarge(mapping.payload_size))?;
            let offset = usize::try_from(mapping.offset_in_mapping)
                .map_err(|_| TrapError::MappingTooLarge(mapping.offset_in_mapping))?;
            let planned = mapping.image.get(offset..offset + payload).ok_or_else(|| {
                TrapError::Hypervisor(format!(
                    "carrier control image at 0x{:x} is shorter than its payload",
                    mapping.guest_start
                ))
            })?;
            let live = carrier
                .host_pointer(mapping.guest_start + mapping.offset_in_mapping, payload)
                .ok_or_else(|| {
                    TrapError::Hypervisor(format!(
                        "carrier control mapping 0x{:x} payload is not host-visible",
                        mapping.guest_start
                    ))
                })?;
            // SAFETY: `host_pointer` proved `[ptr, ptr+payload)` lies inside one
            // live carrier mapping; the code pages are immutable after install.
            let live = unsafe { std::slice::from_raw_parts(live.as_ptr(), payload) };
            if live != planned {
                return Err(TrapError::Hypervisor(format!(
                    "carrier control code at 0x{:x} differs from this image's bytes",
                    mapping.guest_start
                )));
            }
        }
    }
    if seen != 5 {
        return Err(TrapError::Hypervisor(format!(
            "root image carries {seen} carrier control mappings, expected 5"
        )));
    }
    Ok(())
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn is_persistent_executor_carrier_mapping(mapping: &HvfMappedRegion) -> bool {
    is_persistent_executor_carrier_address(mapping.start)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn is_persistent_executor_carrier_guest_mapping(mapping: &GuestMapping) -> bool {
    is_persistent_executor_carrier_address(mapping.guest_start)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn mapping_belongs_to_task_inventory(
    persistent_vm_lifecycle: bool,
    mapping: &HvfMappedRegion,
) -> bool {
    !persistent_vm_lifecycle || !is_persistent_executor_carrier_mapping(mapping)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn is_persistent_executor_carrier_address(address: u64) -> bool {
    matches!(
        address,
        carrick_mem::memory::LINUX_EL0_TRAMPOLINE_BASE
            | carrick_mem::memory::LINUX_EL1_VECTORS_BASE
            | carrick_mem::memory::LINUX_EL1_MAINT_BASE
            | carrick_mem::memory::LINUX_SYSCALL_MAILBOX_BASE
            | carrick_mem::memory::LINUX_CARRIER_MAINT_ROOT_BASE
    )
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn persistent_executor_carrier_mappings<'a>(
    mappings: impl IntoIterator<Item = &'a HvfMappedRegion>,
) -> Vec<ThreadMappingDesc> {
    mappings
        .into_iter()
        .filter(|mapping| is_persistent_executor_carrier_mapping(mapping))
        .map(ThreadMappingDesc::from_region)
        .collect()
}

/// Owning carrier-wide lifetime for the five fixed HVPatch control mappings.
/// Logical MM/task cleanup never sees these rows. The last factory/worker Arc
/// drops only after every worker vCPU has been joined and destroyed.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) struct PersistentCarrierMappings {
    pub(crate) mappings: TaskMappingIndex,
    custody: std::sync::Arc<CarrierVmCustody>,
    vm_destroyed_after_custody_commit: std::sync::atomic::AtomicBool,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl PersistentCarrierMappings {
    fn extract(
        task_mappings: &mut TaskMappingIndex,
        custody: std::sync::Arc<CarrierVmCustody>,
    ) -> Result<Self, TrapError> {
        let mut carrier = TaskMappingIndex::new();
        let mut task = TaskMappingIndex::new();
        for mapping in std::mem::take(task_mappings).into_values() {
            if is_persistent_executor_carrier_mapping(&mapping) {
                carrier.insert(mapping);
            } else {
                task.insert(mapping);
            }
        }
        *task_mappings = task;
        let authority = Self {
            mappings: carrier,
            custody,
            vm_destroyed_after_custody_commit: std::sync::atomic::AtomicBool::new(false),
        };
        authority.audit()?;
        if authority.mappings.len() != 5 {
            return Err(TrapError::Hypervisor(format!(
                "persistent executor carrier owns {} mappings, expected 5",
                authority.mappings.len()
            )));
        }
        Ok(authority)
    }

    fn mark_vm_destroyed_after_custody_commit(&self) -> Result<(), TrapError> {
        let committed = matches!(
            self.custody.state.lock().lifecycle,
            CarrierVmLifecycle::Vacant
        );
        if !committed {
            return Err(TrapError::Hypervisor(
                "persistent carrier mappings cannot retire before exact VM custody destroy commits"
                    .to_owned(),
            ));
        }
        self.vm_destroyed_after_custody_commit
            .store(true, std::sync::atomic::Ordering::Release);
        Ok(())
    }

    fn maintenance_root(&self) -> carrick_mem::memory::CarrierMaintenanceRoot {
        carrick_mem::memory::CarrierMaintenanceRoot(carrick_guest_mem::Gpa(
            carrick_mem::memory::LINUX_CARRIER_MAINT_ROOT_BASE,
        ))
    }

    fn host_pointer(&self, address: u64, length: usize) -> Option<std::ptr::NonNull<u8>> {
        let mapping = self.mappings.mapping_for_range(GuestVa(address), length)?;
        let offset = usize::try_from(address.checked_sub(mapping.start)?).ok()?;
        std::ptr::NonNull::new(unsafe { mapping.host_addr.add(offset) })
    }

    fn host_pointer_for_ipa(&self, ipa: u64, length: usize) -> Option<*mut u8> {
        let mapping = HvfVmState::mapping_for_ipa_range(&self.mappings, ipa, length.max(1))?;
        let offset = usize::try_from(ipa.checked_sub(mapping.ipa)?).ok()?;
        Some(unsafe { mapping.host_addr.add(offset) })
    }

    fn audit(&self) -> Result<(), TrapError> {
        let descriptors = persistent_executor_carrier_mappings(&self.mappings);
        audit_persistent_executor_carrier_mappings(&descriptors)
    }
}

// SAFETY: the owning mappings name VM-global MAP_SHARED host allocations. The
// carrier Arc is immutable after extraction; only its final Drop mutates the
// mapping owners, after all worker threads have joined.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
unsafe impl Send for PersistentCarrierMappings {}
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
unsafe impl Sync for PersistentCarrierMappings {}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl Drop for PersistentCarrierMappings {
    fn drop(&mut self) {
        let vm_destroyed = self
            .vm_destroyed_after_custody_commit
            .load(std::sync::atomic::Ordering::Acquire);
        for mut mapping in std::mem::take(&mut self.mappings).into_values() {
            if let Some(mut lease) = mapping.stage2_lease.take() {
                // Retire EXPLICITLY. Dropping a lease does not unmap stage-2 --
                // it only releases the IPA reservation and (in a debug build)
                // asserts the lease was not mapped. This is the carrier
                // authority's own terminal point, which is why the lease-less
                // branch below issues the same `hv_vm_unmap`; leaving the
                // leased branch to `drop` alone unmapped nothing while the
                // `OwnedHostMapping` below still released the backing, so the
                // guest kept a stage-2 route to freed host memory.
                if vm_destroyed {
                    lease.forget_backend_mapping();
                    drop(lease);
                } else {
                    lease.try_retire().unwrap_or_else(|error| {
                        carrick_fatal!(
                            "hvpatch::host_alias",
                            "retire persistent carrier stage-2 lease failed at IPA 0x{:x} size {}: {error}",
                            mapping.physical_ipa, mapping.physical_size
                        );
                    });
                }
            } else if !vm_destroyed {
                let rc =
                    unsafe { inventory_hv_vm_unmap(mapping.physical_ipa, mapping.physical_size) };
                if rc != 0 {
                    carrick_fatal!(
                        "hvpatch::mm_authority",
                        "retire persistent carrier stage-2 IPA 0x{:x} size {} failed: 0x{rc:x}",
                        mapping.physical_ipa,
                        mapping.physical_size
                    );
                }
            }
            // Stage-2 is gone before OwnedHostMapping releases the backing.
            drop(mapping);
        }
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn persistent_carrier_host_pointer(
    mappings: &[ThreadMappingDesc],
    address: u64,
    length: usize,
) -> Option<std::ptr::NonNull<u8>> {
    let end = address.checked_add(u64::try_from(length).ok()?)?;
    let mapping = mappings
        .iter()
        .find(|mapping| address >= mapping.start && end <= mapping.end)?;
    let offset = usize::try_from(address.checked_sub(mapping.start)?).ok()?;
    std::ptr::NonNull::new(unsafe { mapping.host_addr.add(offset) })
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn audit_persistent_executor_carrier_mappings(
    mappings: &[ThreadMappingDesc],
) -> Result<(), TrapError> {
    for (name, start, size) in [
        (
            "EL0 trampoline",
            carrick_mem::memory::LINUX_EL0_TRAMPOLINE_BASE,
            carrick_mem::memory::LINUX_EL0_TRAMPOLINE_SIZE,
        ),
        (
            "EL1 vectors",
            carrick_mem::memory::LINUX_EL1_VECTORS_BASE,
            carrick_mem::memory::LINUX_EL1_VECTORS_SIZE,
        ),
        (
            "EL1 maintenance",
            carrick_mem::memory::LINUX_EL1_MAINT_BASE,
            carrick_mem::memory::LINUX_EL1_MAINT_SIZE,
        ),
        (
            "syscall mailbox",
            carrick_mem::memory::LINUX_SYSCALL_MAILBOX_BASE,
            carrick_mem::memory::LINUX_SYSCALL_MAILBOX_ARENA_SIZE,
        ),
        (
            "carrier maintenance root",
            carrick_mem::memory::LINUX_CARRIER_MAINT_ROOT_BASE,
            carrick_mem::memory::LINUX_CARRIER_MAINT_ROOT_SIZE,
        ),
    ] {
        let size = usize::try_from(size).map_err(|_| {
            TrapError::Hypervisor(format!("persistent executor {name} extent is too large"))
        })?;
        if persistent_carrier_host_pointer(mappings, start, size).is_none() {
            return Err(TrapError::Hypervisor(format!(
                "persistent executor carrier {name} mapping is absent"
            )));
        }
    }
    Ok(())
}
/// Everything a freshly-spawned host thread needs to stand up its own vCPU
/// in the SHARED process VM and resume the cloned guest thread.
///
/// `vm` is a `vm.clone()` handle: the applevisor VM is Arc-refcounted, so
/// holding a clone keeps the single process VM alive and lets the new thread
/// call `vcpu_create()` against it (HVF requires vCPU create on the owning
/// thread). `mappings` are raw descriptors of the SAME host buffers the main
/// engine mapped; they are local syscall-path metadata only, because the
/// stage-2 entries live on the shared HVF VM, not on each vCPU.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone)]
pub struct ThreadSpec {
    vm: applevisor::vm::VirtualMachineInstance<applevisor::vm::GicDisabled>,
    mappings: Vec<ThreadMappingDesc>,
    /// Sibling threads retain the exact MM authority; no per-MM field is
    /// copied independently into an executor specification.
    mm_access: std::sync::Arc<MmAccessState>,
    carrier_foreign_mm_transport: std::sync::Arc<CarrierForeignMmTransport>,
    mailbox_slots: std::sync::Arc<MailboxSlotAllocator>,
    syscall_transport: HvfSyscallTransport,
    persistent_vm_lifecycle: bool,
    mm_root_slot: Option<(u64, u64)>,
    container_root: ContainerRootToken,
    cow_authority: Option<std::sync::Arc<dyn carrick_hal::FrameCowAuthority>>,
    cow_identity: Option<carrick_hal::FrameCowIdentity>,
}

/// Factory authority for one Task4 worker. It deliberately carries only the
/// carrier VM and executor-local mailbox transport configuration; no task MM,
/// stage-1 editor, mapping descriptor, frame inventory, or COW authority can be
/// retained by the factory or copied into an idle worker.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone)]
pub(crate) struct PersistentExecutorSpec {
    vm: applevisor::vm::VirtualMachineInstance<applevisor::vm::GicDisabled>,
    /// VM-global Carrick control mappings needed before any task projection is
    /// loaded: entry trampoline, EL1 vectors/scratch path, maintenance code,
    /// and the executor mailbox arena. The Arc is their exact carrier-wide
    /// stage-2/backing owner; task mappings, page tables, MM/root, inventory,
    /// and COW authority stay out of the factory.
    carrier_mappings: std::sync::Arc<PersistentCarrierMappings>,
    mailbox_slots: std::sync::Arc<MailboxSlotAllocator>,
    syscall_transport: HvfSyscallTransport,
    carrier_foreign_mm_transport: std::sync::Arc<CarrierForeignMmTransport>,
}

// SAFETY: PersistentCarrierMappings owns immutable VM-global MAP_SHARED
// buffers. Worker threads only resolve pointers while their Arc is live.
unsafe impl Send for PersistentExecutorSpec {}
unsafe impl Sync for PersistentExecutorSpec {}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
struct ProcessMappingDesc {
    start: u64,
    ipa: u64,
    end: u64,
    // Drop the stage-2 authority before the host owner on every implicit
    // prepare-error path. Named initializers make declaration order otherwise
    // invisible, but Rust field destruction follows this order.
    stage2_lease: Option<GlobalFrameStage2Lease>,
    host: ProcessMappingHost,
    size: usize,
    physical_ipa: u64,
    physical_host_addr: *mut u8,
    physical_size: usize,
    inventory_backing: InventoryBackingIdentity,
    perms: applevisor::memory::MemPerms,
    is_dynamic_alias: bool,
    sharing: GuestMappingSharing,
    guest_writable: bool,
    inherited_frame: Option<carrick_hal::FrameId>,
    shared_key_base: u64,
    shared_key_offset: u64,
    owner_generation: u64,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
enum ProcessMappingHost {
    Borrowed {
        pointer: *mut u8,
        structural_owner: Option<std::sync::Arc<StructuralBackingOwner>>,
    },
    Owned(crate::host_mapping::OwnedHostMapping),
    PooledRootSlot {
        handle: crate::frame_pool::PooledRootSlotHandle,
    },
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl ProcessMappingHost {
    #[allow(dead_code)]
    fn ptr(&self) -> *mut u8 {
        match self {
            Self::Borrowed { pointer, .. } => *pointer,
            Self::Owned(mapping) => mapping.as_ptr(),
            Self::PooledRootSlot { handle } => handle.as_mut_ptr(),
        }
    }

    #[allow(dead_code)]
    fn into_owned(self) -> Option<crate::host_mapping::OwnedHostMapping> {
        match self {
            Self::Borrowed { .. } | Self::PooledRootSlot { .. } => None,
            Self::Owned(mapping) => Some(mapping),
        }
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy, Debug)]
struct ProcessInventoryDesc {
    gpa: u64,
    length: u64,
    permissions: carrick_hal::MemPerms,
    inherited_frame: Option<carrick_hal::FrameId>,
    inherited_mapping: Option<carrick_hal::MappingId>,
    backing: InventoryBackingIdentity,
    stage2_lease: (u64, u64),
    stage2_owner: InventoryStage2OwnerIdentity,
    fork_frame_receipt_kind: Option<carrick_observability::probes::HvpatchForkFrameKind>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn process_mapping_needs_child_alias_authority(mapping: &ProcessMappingDesc) -> bool {
    mapping.is_dynamic_alias
        || (mapping.inherited_frame.is_some()
            && mapping.sharing == GuestMappingSharing::Private
            && !is_kernel_only_stage1_range(mapping.start, mapping.size))
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn authenticated_structural_owner_record_in(
    custody: &CarrierVmCustody,
    owner: &std::sync::Arc<StructuralBackingOwner>,
    physical_host_addr: *mut u8,
    physical_ipa: u64,
    physical_size: usize,
    perms: applevisor::memory::MemPerms,
    owner_generation: u64,
) -> Option<CarrierStage2RecordIdentity> {
    let owner_custody = owner.custody.upgrade()?;
    if !std::ptr::eq(owner_custody.as_ref(), custody)
        || owner.ptr() != physical_host_addr
        || owner.len() != physical_size
        || owner.physical_ipa != physical_ipa
        || owner.physical_size != physical_size
        || owner.epoch().raw() != owner_generation
        || owner
            .retained
            .owner_retired
            .load(std::sync::atomic::Ordering::Acquire)
    {
        return None;
    }
    let identity = *owner.retained.record_identity.lock();
    if custody
        .structural_backings
        .lock()
        .get(&identity.record_id)
        .is_none_or(|retained| !std::sync::Arc::ptr_eq(retained, &owner.retained))
    {
        return None;
    }
    let snapshot = custody.stage2_record_snapshot(identity.record_id)?;
    let logical_owner = CarrierLogicalOwner {
        id: owner_generation,
        generation: owner_generation,
    };
    (identity.vm_generation == snapshot.vm_generation
        && identity.logical_owner == Some(logical_owner)
        && custody.setup_generation() == Some(snapshot.vm_generation)
        && snapshot.ipa == physical_ipa
        && snapshot.len == physical_size
        && snapshot.host_addr == physical_host_addr as usize
        && snapshot.perms == u64::from(perms)
        && snapshot.logical_owner == Some(logical_owner)
        && snapshot.mapped
        && snapshot.backend_map_installed
        && !snapshot.retirement_requested
        && !snapshot.terminalized_by_vm_destroy)
        .then_some(identity)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn mapped_region_physical_host_addr(mapping: &HvfMappedRegion) -> Option<*mut u8> {
    let offset = usize::try_from(mapping.ipa.checked_sub(mapping.physical_ipa)?).ok()?;
    let semantic_size = usize::try_from(mapping.end.checked_sub(mapping.start)?).ok()?;
    offset
        .checked_add(semantic_size)
        .filter(|end| *end <= mapping.physical_size)?;
    (mapping.host_addr as usize)
        .checked_sub(offset)
        .map(|base| base as *mut u8)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn structural_fork_owner_identity_in(
    custody: &CarrierVmCustody,
    mapping: &ThreadMappingDesc,
) -> Option<InventoryStage2OwnerIdentity> {
    authenticated_structural_owner_record_in(
        custody,
        mapping.structural_owner.as_ref()?,
        mapping.physical_host_addr,
        mapping.physical_ipa,
        mapping.physical_size,
        mapping.perms,
        mapping.owner_generation,
    )?;
    Some(InventoryStage2OwnerIdentity {
        host_addr: mapping.physical_host_addr as usize,
        generation: mapping.owner_generation,
    })
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
/// The parent frame inventory grouped by the stage-2 extent an inherited
/// mapping is matched on.
///
/// `inherited_fork_inventory_extents_in` selects rows whose
/// `(stage2_base, stage2_length)` equals the mapping's physical extent, but it
/// found them by walking the WHOLE inventory. It is called once per source
/// mapping — twice, counting the overlay index — so a fork paid O(M * I).
/// Grouping once per fork turns each of those into a lookup.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
type ForkInventoryByStage2 =
    std::collections::BTreeMap<(u64, u64), Vec<((u64, u64), InventoryExtent)>>;

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn index_fork_inventory_by_stage2(
    inventory: &std::collections::BTreeMap<(u64, u64), InventoryExtent>,
) -> ForkInventoryByStage2 {
    let mut index = ForkInventoryByStage2::new();
    for (&key, &extent) in inventory {
        index
            .entry((extent.stage2_base, extent.stage2_length))
            .or_default()
            .push((key, extent));
    }
    index
}

/// [`inherited_fork_inventory_extents_in`] against a pre-grouped inventory.
/// The owner authentication is unchanged and still per-mapping; only the
/// search for candidate rows is indexed.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn inherited_fork_inventory_extents_indexed(
    custody: &CarrierVmCustody,
    mapping: &ThreadMappingDesc,
    index: &ForkInventoryByStage2,
) -> Vec<((u64, u64), InventoryExtent)> {
    let extent_key = (mapping.physical_ipa, mapping.physical_size as u64);
    let Some(candidates) = index.get(&extent_key) else {
        return Vec::new();
    };
    let expected_owner = (mapping.owner_generation != 0).then_some(InventoryStage2OwnerIdentity {
        host_addr: mapping.physical_host_addr as usize,
        generation: mapping.owner_generation,
    });
    let live_owner = if mapping.owner_generation == 0 {
        None
    } else if is_reusable_global_frame_extent(mapping.physical_ipa, mapping.physical_size as u64) {
        global_frame_host_owner_identity_in(
            custody,
            mapping.physical_ipa,
            mapping.physical_size as u64,
        )
        .map(|(host_addr, generation)| InventoryStage2OwnerIdentity {
            host_addr,
            generation,
        })
    } else {
        structural_fork_owner_identity_in(custody, mapping)
    };
    candidates
        .iter()
        .filter(|(_, extent)| {
            mapping.owner_generation == 0
                || (expected_owner == Some(extent.stage2_owner)
                    && live_owner == Some(extent.stage2_owner))
        })
        .copied()
        .collect()
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn thread_mapping_semantic_ipa_at(mapping: &ThreadMappingDesc, address: u64) -> Option<u64> {
    let offset = address.checked_sub(mapping.start)?;
    if offset >= mapping.size as u64 {
        return None;
    }
    mapping.ipa.checked_add(offset)
}

/// Fork-source mappings that own inherited inventory extents, indexed by the
/// translation they produce.
///
/// A mapping satisfies `thread_mapping_semantic_ipa_at(overlay, va) ==
/// Some(translated)` only if `overlay.ipa - overlay.start == translated - va`
/// and `va` lies inside it. The first half is independent of `va`, so it is an
/// index key; the second half stays an exact per-candidate check, so the
/// predicate is unchanged.
///
/// This exists because the previous shape asked the question by scanning EVERY
/// source mapping and, for each one, recomputing its inherited inventory
/// extents — a fresh `Vec` allocation and a full pass over the parent frame
/// inventory. Inside the per-mapping fork loop that is O(M^2 * I) for a
/// process with M mappings and an I-row inventory: measured 2026-08-30 at
/// 13.3% of carrier CPU in this function plus 8.6% in the O(1)
/// `thread_mapping_semantic_ipa_at` it calls, i.e. ~22% of a fork/exit storm
/// spent re-deriving facts that do not depend on the candidate at all. Fork is
/// the most horizontal path there is, so this cost compounds into every
/// workload that forks.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Debug, Default)]
struct ForkOverlayOwnerIndex {
    /// `(translation delta, mapping start) -> source mapping indexes`, for the
    /// mappings that own inherited inventory extents. The value is a list
    /// because two source mappings may legitimately share a start and a delta
    /// while differing in size; collapsing them to one index would let the
    /// surviving row be the candidate itself and silently answer "no owner".
    by_delta_and_start: std::collections::BTreeMap<(u64, u64), Vec<usize>>,
    /// Largest mapping size present per delta, so a query walks back only as
    /// far as a mapping could possibly reach.
    widest_by_delta: std::collections::BTreeMap<u64, u64>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl ForkOverlayOwnerIndex {
    /// Build once per fork. Each mapping's inherited-extent status is computed
    /// exactly ONCE here rather than once per (candidate, overlay) pair.
    fn build(
        custody: &CarrierVmCustody,
        mappings: &[ThreadMappingDesc],
        inventory: &ForkInventoryByStage2,
    ) -> Self {
        note_hot_path_rows(HotPathScan::ForkMappings, mappings.len());
        let mut index = Self::default();
        for (position, overlay) in mappings.iter().enumerate() {
            if inherited_fork_inventory_extents_indexed(custody, overlay, inventory).is_empty() {
                continue;
            }
            let delta = overlay.ipa.wrapping_sub(overlay.start);
            index
                .by_delta_and_start
                .entry((delta, overlay.start))
                .or_default()
                .push(position);
            let widest = index.widest_by_delta.entry(delta).or_insert(0);
            *widest = (*widest).max(overlay.size as u64);
        }
        index
    }

    /// True when some OTHER source mapping that owns inherited inventory
    /// extents also translates `va` to `translated`.
    fn has_overlay_owner(
        &self,
        mappings: &[ThreadMappingDesc],
        candidate_index: usize,
        va: u64,
        translated: u64,
    ) -> bool {
        let delta = translated.wrapping_sub(va);
        let Some(&widest) = self.widest_by_delta.get(&delta) else {
            return false;
        };
        // Only a mapping starting in `[va - widest, va]` can contain `va`, so
        // this is a bounded range walk rather than a pass over the bucket. The
        // delta alone is NOT selective enough: a process whose mappings sit at
        // a constant ipa-to-va offset puts every one of them in one bucket,
        // which is the common case and would restore the linear scan.
        let lower = va.saturating_sub(widest);
        let mut visited = 0usize;
        let mut found = false;
        'search: for (&(_, start), positions) in
            self.by_delta_and_start.range((delta, lower)..=(delta, va))
        {
            debug_assert!(start <= va);
            for &position in positions {
                visited += 1;
                if position != candidate_index
                    && thread_mapping_semantic_ipa_at(&mappings[position], va) == Some(translated)
                {
                    found = true;
                    break 'search;
                }
            }
        }
        note_hot_path_rows(HotPathScan::ForkMappings, visited);
        found
    }
}

#[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
fn inherited_fork_inventory_extents(
    mapping: &ThreadMappingDesc,
    inventory: &std::collections::BTreeMap<(u64, u64), InventoryExtent>,
) -> Vec<((u64, u64), InventoryExtent)> {
    inherited_fork_inventory_extents_indexed(
        legacy_test_carrier_vm_custody(),
        mapping,
        &index_fork_inventory_by_stage2(inventory),
    )
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn fork_translation_has_overlay_owner(
    index: &ForkTranslationOverlayIndex,
    mappings: &[ProcessMappingDesc],
    candidate_index: usize,
    va: u64,
    translated: u64,
) -> bool {
    index.has_overlay_owner(mappings, candidate_index, va, translated)
}

/// Overlay owners of one forking process's translations, indexed by the
/// translation they produce.
///
/// A row can satisfy the overlay predicate only if its `ipa - start` equals
/// `translated - va` and it starts within its own length of `va`, so those two
/// facts are the index and the exact containment test stays a per-candidate
/// check. Same construction as [`ForkOverlayOwnerIndex`], and for the same
/// reason: the previous shape asked the question by scanning every source
/// mapping AND the whole carrier-global alias registry, once per mapping, so a
/// process with M mappings in a carrier holding R alias rows paid O(M * (M + R))
/// per fork. Measured 20.1% of carrier CPU under a fork/exit storm even after
/// the call was made lazy.
///
/// The alias half admits exactly the scopes the original predicate did: the
/// scopes `alias_matches_process_scope` accepts, plus this container's root
/// regardless of `mm_root_slot`.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Debug, Default)]
struct ForkTranslationOverlayIndex {
    mappings_by_delta_and_start: std::collections::BTreeMap<(u64, u64), Vec<usize>>,
    mappings_widest_by_delta: std::collections::BTreeMap<u64, u64>,
    aliases_by_delta_and_start: std::collections::BTreeMap<(u64, u64), Vec<AliasBacking>>,
    aliases_widest_by_delta: std::collections::BTreeMap<u64, u64>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl ForkTranslationOverlayIndex {
    fn build(
        mappings: &[ProcessMappingDesc],
        mm_root_slot: Option<(u64, u64)>,
        container_root: ContainerRootToken,
    ) -> Self {
        let mut index = Self::default();
        for (position, overlay) in mappings.iter().enumerate() {
            let delta = overlay.ipa.wrapping_sub(overlay.start);
            index
                .mappings_by_delta_and_start
                .entry((delta, overlay.start))
                .or_default()
                .push(position);
            let widest = index.mappings_widest_by_delta.entry(delta).or_insert(0);
            *widest = (*widest).max(overlay.end.saturating_sub(overlay.start));
        }
        let registry = alias_registry().lock();
        let mut scopes: Vec<AliasOwnershipScope> =
            AliasRegistry::process_visible_scopes(mm_root_slot, container_root).to_vec();
        let container_scope = AliasOwnershipScope::ContainerRoot(container_root);
        if !scopes.contains(&container_scope) {
            scopes.push(container_scope);
        }
        for scope in scopes {
            let rows = registry.scope_rows(scope);
            note_alias_state_rows_scanned(rows.len());
            for (_, alias) in rows {
                let delta = alias.ipa.wrapping_sub(alias.start);
                index
                    .aliases_by_delta_and_start
                    .entry((delta, alias.start))
                    .or_default()
                    .push(*alias);
                let widest = index.aliases_widest_by_delta.entry(delta).or_insert(0);
                *widest = (*widest).max(alias.size as u64);
            }
        }
        index
    }

    fn has_overlay_owner(
        &self,
        mappings: &[ProcessMappingDesc],
        candidate_index: usize,
        va: u64,
        translated: u64,
    ) -> bool {
        let delta = translated.wrapping_sub(va);
        if let Some(&widest) = self.mappings_widest_by_delta.get(&delta) {
            let lower = va.saturating_sub(widest);
            for (_, positions) in self
                .mappings_by_delta_and_start
                .range((delta, lower)..=(delta, va))
            {
                for &position in positions {
                    let overlay = &mappings[position];
                    if position != candidate_index
                        && va >= overlay.start
                        && va < overlay.end
                        && overlay
                            .ipa
                            .checked_add(va - overlay.start)
                            .is_some_and(|ipa| ipa == translated)
                    {
                        return true;
                    }
                }
            }
        }
        let Some(&widest) = self.aliases_widest_by_delta.get(&delta) else {
            return false;
        };
        let lower = va.saturating_sub(widest);
        self.aliases_by_delta_and_start
            .range((delta, lower)..=(delta, va))
            .flat_map(|(_, aliases)| aliases)
            .any(|alias| {
                va >= alias.start
                    && va < alias.start.saturating_add(alias.size as u64)
                    && alias.ipa.checked_add(va.saturating_sub(alias.start)) == Some(translated)
            })
    }
}

/// The boot-time shared aperture is a physical stage-2 owner, not one dense
/// guest-visible mapping. Linux `MAP_SHARED` sub-allocations install sparse
/// stage-1 leaves anywhere inside it, so the aperture's first VA may be absent
/// even while later leaves are live. Fork copies the parent's stage-1 graph
/// separately; do not treat the missing *base* leaf as a corrupt child graph.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn fork_mapping_requires_base_translation(
    start: u64,
    size: usize,
    is_dynamic_alias: bool,
) -> bool {
    is_dynamic_alias
        || start != crate::memory::LINUX_SHARED_FILE_BASE
        || size != crate::memory::LINUX_SHARED_FILE_SIZE as usize
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy, Debug)]
struct PendingForkFrameReceipt {
    transaction: carrick_hal::KernelTransactionId,
    kind: carrick_observability::probes::HvpatchForkFrameKind,
    parent_mapping: carrick_hal::MappingId,
    child_mapping: carrick_hal::MappingId,
    frame: carrick_hal::FrameId,
    ipa: u64,
    length: u64,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn authenticate_pending_fork_receipts(
    receipts: &[PendingForkFrameReceipt],
    receipt: &carrick_hal::FrameInventoryApplyReceipt,
) -> bool {
    receipts.iter().enumerate().all(|(index, pending)| {
        pending.transaction == receipt.transaction()
            && receipt.authorizes(pending.child_mapping, pending.frame)
            && pending.length != 0
            && pending.parent_mapping != pending.child_mapping
            && !receipts[..index].iter().any(|prior| {
                prior.child_mapping == pending.child_mapping
                    || (prior.ipa, prior.length) == (pending.ipa, pending.length)
            })
    })
}

/// Why a retirement receipt did or did not authenticate, clause by clause.
///
/// The abort this feeds is unrecoverable, so it must name the failing clause: a
/// receipt that leaves the mm non-empty, one that covers a different number of
/// mappings, and one that omits a pending fork frame call for entirely different
/// fixes, and a bare "malformed" verdict cannot tell them apart.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy, Debug)]
struct PendingRetirementAudit {
    mm_empty_at_revision: bool,
    expected_non_empty: bool,
    cardinality_matches: bool,
    expected_authorized: bool,
    pending_authorized: bool,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl PendingRetirementAudit {
    const fn ok(self) -> bool {
        self.mm_empty_at_revision
            && self.expected_non_empty
            && self.cardinality_matches
            && self.expected_authorized
            && self.pending_authorized
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn authenticate_pending_retirement(
    expected: &[(carrick_hal::MappingId, carrick_hal::FrameId)],
    pending: &[PendingForkFrameReceipt],
    receipt: &carrick_hal::FrameInventoryRetirementReceipt,
) -> PendingRetirementAudit {
    PendingRetirementAudit {
        mm_empty_at_revision: receipt.mm_empty_at_revision(),
        expected_non_empty: !expected.is_empty(),
        cardinality_matches: expected.len() == receipt.mapping_set().len(),
        expected_authorized: expected
            .iter()
            .all(|&(mapping, frame)| receipt.authorizes(mapping, frame)),
        // Only OUTSTANDING inheritances. A pending receipt records an
        // obligation created at fork publication: "this child mapping holds a
        // frame inherited from the parent". It is discharged either here, by the
        // retirement unmapping that mapping with that frame, or EARLIER, when
        // the mapping was superseded — `stage_cow_inventory_split` pushes its
        // own `UnmapMapping` and `RetireFrame` for the old mapping and
        // `commit_cow_inventory_split` drops the extent, all inside that
        // transaction. Demanding that retirement account for an already-settled
        // obligation is a category error, and it failed every forked child that
        // wrote to an inherited page: the superseded mapping id is simply absent
        // from the retirement's set. A mapping still live in `expected` must
        // still retire under the frame it inherited.
        pending_authorized: pending
            .iter()
            .filter(|pending| {
                expected
                    .iter()
                    .any(|(mapping, _)| *mapping == pending.child_mapping)
            })
            .all(|pending| receipt.authorizes(pending.child_mapping, pending.frame)),
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PendingFrameCowPublication {
    va: u64,
    len: usize,
    expected_ipa: u64,
}

/// Name the stage-1 pool's own numbers on a sparse-mmap planning failure.
/// A bare `OutOfTables` cannot distinguish a legitimately huge address
/// space from a pool that was refused permission to sweep its reclaimable
/// tables (`cpython-compile` reported fifteen bare refusals at 1 MiB anonymous
/// maps); the child-clone and syscall edit paths already report this census.
fn sparse_mmap_stage1_error(
    manager: &carrick_mem::page_table::PageTableManager,
    span: &str,
    error: carrick_mem::page_table::PageTableError,
    source: bool,
) -> TrapError {
    let (in_use, free, capacity, arenas) = manager.pool_stats();
    let (multi_vcpu, exclusive, reclaim_pending) = manager.coalesce_policy();
    TrapError::Hypervisor(format!(
        "plan sparse HVPatch mmap {span} stage-1 output: {error:?} \
         (in_use={in_use} free={free} capacity={capacity} arenas={arenas} source={source} \
         multi_vcpu={multi_vcpu} exclusive={exclusive} reclaim_pending={reclaim_pending})"
    ))
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn next_deferred_cow_authentication_page(
    walk: [u64; 4],
    page: u64,
    end: u64,
    armed: &[carrick_aarch64::vmm::ForkCowRange],
) -> u64 {
    // Called only AFTER authenticating the live walk against the shadow and
    // exact expected output while retaining the page-table authority. A valid
    // block has one descriptor and linear outputs throughout its aligned span;
    // an L3 table still requires every leaf to be read. Invalid retained leaves
    // stay on the conservative page path. Never infer coverage from endpoints.
    const PAGE: u64 = 4096;
    let mut span = PAGE;
    for (level, descriptor) in walk.into_iter().enumerate() {
        if descriptor & 1 == 0 {
            break;
        }
        if descriptor & 3 == 1 {
            span = match level {
                1 => 1 << 30,
                2 => 1 << 21,
                _ => PAGE,
            };
            break;
        }
    }
    let mut next = (page & !(span - 1)).saturating_add(span).min(end);
    // AP_RO is authentic for an armed page even when PROT_WRITE was requested.
    // Stop at every arm boundary so an unarmed interior page cannot inherit
    // that exception. Overlapping arms merely cause extra authentication.
    for range in armed {
        let Some(range_end) = range.va.checked_add(range.len as u64) else {
            continue;
        };
        for boundary in [range.va, range_end] {
            if boundary > page && boundary < next {
                // The caller authenticates page starts; an unaligned arm
                // boundary first changes that classification on the next page.
                next = boundary.saturating_add(PAGE - 1) & !(PAGE - 1);
            }
        }
    }
    next.min(end)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn deferred_cow_leaf_authenticates(
    leaf: u64,
    translated: Option<u64>,
    expected_ipa: u64,
    expected_ap: u64,
    must_be_valid: bool,
    must_be_executable: bool,
) -> bool {
    const VALID: u64 = 1;
    const AP_MASK: u64 = 0b11 << 6;
    const NON_GLOBAL: u64 = 1 << 11;
    const UXN: u64 = 1 << 54;

    translated == Some(expected_ipa)
        && leaf & NON_GLOBAL != 0
        && (leaf & VALID != 0) == must_be_valid
        // In an invalid descriptor AP and UXN do not grant guest access and
        // are deliberately retained by `PtOp::Invalidate` along with the
        // output address. Once revalidated they are semantic and must match
        // the exact requested access, including execute permission.
        && (!must_be_valid || leaf & AP_MASK == expected_ap)
        && (!must_be_valid || (leaf & UXN == 0) == must_be_executable)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn process_mapping_needs_stage2_install(inherited_frame: Option<carrick_hal::FrameId>) -> bool {
    inherited_frame.is_none()
}

/// A fork child address space waiting for vCPU materialization on its owning
/// host thread. Private mappings initially retain the parent's FrameId/global
/// IPA and are read-only in each mm's independent stage-1 graph; the first
/// writer receives a new compound frame. A CLONE_VM child instead retains user
/// frames writable while keeping its stage-1 tables and EL1 control state
/// independent. Guest-shared mappings retain their existing IPA and frame
/// without entering private COW. Shared-anonymous aliases remain mm-scoped; only
/// shared-file mappings use the VM-global alias namespace.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub struct ProcessSpecPlan {
    mappings: Vec<ProcessMappingDesc>,
    inventory_mappings: Vec<ProcessInventoryDesc>,
    protections: std::sync::Arc<MemoryProtections>,
    mailbox_slots: std::sync::Arc<MailboxSlotAllocator>,
    syscall_transport: HvfSyscallTransport,
    persistent_vm_lifecycle: bool,
    mm_root_slot: (u64, u64),
    container_root: ContainerRootToken,
    frame_inventory: std::sync::Arc<parking_lot::Mutex<HvpatchFrameInventory>>,
    cow_armed: std::sync::Arc<parking_lot::Mutex<CowArmedRanges>>,
    carrier_foreign_mm_transport: std::sync::Arc<CarrierForeignMmTransport>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl ProcessSpecPlan {
    pub(crate) fn stage_with_reservation_factory(
        &mut self,
        mut reserve: impl FnMut(
            usize,
            usize,
            carrick_hal::FrameEventCapacity,
        ) -> Result<carrick_hal::FrameInventoryReservation, TrapError>,
    ) -> Result<(), TrapError> {
        let mapping_candidates = self.inventory_mappings.len();
        let frame_candidates = self
            .inventory_mappings
            .iter()
            .filter(|mapping| mapping.inherited_frame.is_none())
            .count();
        let capacity = carrick_hal::FrameEventCapacity::for_event_count(
            carrick_hal::MAX_FRAME_INVENTORY_EVENTS_PER_BATCH,
        )
        .map_err(|error| {
            TrapError::Hypervisor(format!(
                "invalid HVPatch child frame inventory capacity: {error}"
            ))
        })?;
        let reservation = reserve(frame_candidates, mapping_candidates, capacity)?;
        self.frame_inventory.lock().process_reservation = Some(reservation);
        Ok(())
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub struct ProcessSpec {
    vm: applevisor::vm::VirtualMachineInstance<applevisor::vm::GicDisabled>,
    mappings: Vec<ProcessMappingDesc>,
    inventory_mappings: Vec<ProcessInventoryDesc>,
    protections: std::sync::Arc<MemoryProtections>,
    mailbox_slots: std::sync::Arc<MailboxSlotAllocator>,
    syscall_transport: HvfSyscallTransport,
    persistent_vm_lifecycle: bool,
    mm_root_slot: (u64, u64),
    container_root: ContainerRootToken,
    frame_inventory: std::sync::Arc<parking_lot::Mutex<HvpatchFrameInventory>>,
    cow_armed: std::sync::Arc<parking_lot::Mutex<CowArmedRanges>>,
    carrier_foreign_mm_transport: std::sync::Arc<CarrierForeignMmTransport>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl ProcessSpec {
    pub(crate) fn new(
        vm: applevisor::vm::VirtualMachineInstance<applevisor::vm::GicDisabled>,
        plan: ProcessSpecPlan,
    ) -> Self {
        Self {
            vm,
            mappings: plan.mappings,
            inventory_mappings: plan.inventory_mappings,
            protections: plan.protections,
            mailbox_slots: plan.mailbox_slots,
            syscall_transport: plan.syscall_transport,
            persistent_vm_lifecycle: plan.persistent_vm_lifecycle,
            mm_root_slot: plan.mm_root_slot,
            container_root: plan.container_root,
            frame_inventory: plan.frame_inventory,
            cow_armed: plan.cow_armed,
            carrier_foreign_mm_transport: plan.carrier_foreign_mm_transport,
        }
    }

    pub(crate) fn into_plan(
        self,
    ) -> (
        applevisor::vm::VirtualMachineInstance<applevisor::vm::GicDisabled>,
        ProcessSpecPlan,
    ) {
        let plan = ProcessSpecPlan {
            mappings: self.mappings,
            inventory_mappings: self.inventory_mappings,
            protections: self.protections,
            mailbox_slots: self.mailbox_slots,
            syscall_transport: self.syscall_transport,
            persistent_vm_lifecycle: self.persistent_vm_lifecycle,
            mm_root_slot: self.mm_root_slot,
            container_root: self.container_root,
            frame_inventory: self.frame_inventory,
            cow_armed: self.cow_armed,
            carrier_foreign_mm_transport: self.carrier_foreign_mm_transport,
        };
        (self.vm, plan)
    }

    pub(crate) fn stage_with_reservation_factory(
        &mut self,
        reserve: impl FnMut(
            usize,
            usize,
            carrick_hal::FrameEventCapacity,
        ) -> Result<carrick_hal::FrameInventoryReservation, TrapError>,
    ) -> Result<(), TrapError> {
        let mut plan = ProcessSpecPlan {
            mappings: std::mem::take(&mut self.mappings),
            inventory_mappings: std::mem::take(&mut self.inventory_mappings),
            protections: std::sync::Arc::clone(&self.protections),
            mailbox_slots: std::sync::Arc::clone(&self.mailbox_slots),
            syscall_transport: self.syscall_transport,
            persistent_vm_lifecycle: self.persistent_vm_lifecycle,
            mm_root_slot: self.mm_root_slot,
            container_root: self.container_root,
            frame_inventory: std::sync::Arc::clone(&self.frame_inventory),
            cow_armed: std::sync::Arc::clone(&self.cow_armed),
            carrier_foreign_mm_transport: std::sync::Arc::clone(&self.carrier_foreign_mm_transport),
        };
        let result = plan.stage_with_reservation_factory(reserve);
        self.mappings = plan.mappings;
        self.inventory_mappings = plan.inventory_mappings;
        result
    }
}

/// Deferred HVPatch task backend state. Its variants deliberately contain no
/// vCPU, mailbox allocator/binding, vCPU handle/id, reclaim authority, or host
/// owner identity; those belong exclusively to a Task4 worker pthread.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub struct HvpatchTaskOnlyBackendState {
    registration: Option<HvpatchTaskRegistration>,
}

impl HvpatchTaskOnlyBackendState {
    pub(crate) fn register_foreign_mm(&mut self, task: &HvfTaskState) -> Result<(), TrapError> {
        self.registration
            .as_mut()
            .ok_or_else(|| TrapError::Hypervisor("retired HVPatch registration".to_owned()))?
            .register_foreign_mm(task)
    }

    pub(crate) fn unregister_foreign_mm(&mut self) {
        if let Some(registration) = self.registration.as_mut() {
            registration.unregister_foreign_mm();
        }
    }

    pub(crate) fn carrier_vm_custody(&self) -> Result<std::sync::Arc<CarrierVmCustody>, TrapError> {
        let registration = self
            .registration
            .as_ref()
            .ok_or_else(|| TrapError::Hypervisor("retired HVPatch registration".to_owned()))?;
        #[cfg(not(test))]
        {
            Ok(std::sync::Arc::clone(&registration.custody))
        }
        #[cfg(test)]
        {
            let _ = registration;
            Ok(std::sync::Arc::clone(legacy_test_carrier_vm_custody_arc()))
        }
    }

    pub(crate) fn take_registration(&mut self) -> Option<HvpatchTaskRegistration> {
        self.registration.take()
    }

    pub(crate) fn runtime_task_state(
        &self,
        page_tables: carrick_aarch64::Stage1Authority,
        protections: std::sync::Arc<MemoryProtections>,
    ) -> Result<HvfTaskState, TrapError> {
        self.registration
            .as_ref()
            .ok_or_else(|| TrapError::Hypervisor("retired HVPatch registration".to_owned()))?
            .runtime_task_state(page_tables, protections)
    }

    pub(crate) fn apply_inventory(
        &self,
        apply: impl FnOnce(
            carrick_hal::FrameInventoryCommit<()>,
        ) -> Result<carrick_hal::FrameInventoryApplyReceipt, TrapError>,
    ) -> Result<(), TrapError> {
        self.registration
            .as_ref()
            .ok_or_else(|| TrapError::Hypervisor("retired HVPatch registration".to_owned()))?
            .apply_inventory(apply)
    }

    pub(crate) fn shares_another_process_inventory(&self) -> bool {
        self.registration
            .as_ref()
            .is_some_and(|registration| registration.shares_another_process_inventory())
    }

    pub(crate) fn prepare_inventory_retirement(
        &self,
        commit: carrick_hal::FrameInventoryCommit<()>,
    ) -> Result<(), TrapError> {
        self.registration
            .as_ref()
            .ok_or_else(|| TrapError::Hypervisor("retired HVPatch registration".to_owned()))?
            .prepare_inventory_retirement(commit)
    }

    pub(crate) fn apply_inventory_retirement(
        &self,
        apply: impl FnOnce(
            carrick_hal::FrameInventoryCommit<()>,
        ) -> Result<carrick_hal::FrameInventoryRetirementReceipt, TrapError>,
    ) -> Result<(), TrapError> {
        self.registration
            .as_ref()
            .ok_or_else(|| TrapError::Hypervisor("retired HVPatch registration".to_owned()))?
            .apply_inventory_retirement(apply)
    }

    pub(crate) fn bind_child_kernel(
        &mut self,
        binding: HvpatchChildKernelBinding,
    ) -> Result<(), TrapError> {
        self.registration
            .as_mut()
            .ok_or_else(|| TrapError::Hypervisor("retired HVPatch registration".to_owned()))?
            .bind_child_kernel(binding)
    }

    pub(crate) fn activate(&self) -> Result<(), TrapError> {
        self.registration
            .as_ref()
            .ok_or_else(|| TrapError::Hypervisor("retired HVPatch registration".to_owned()))?
            .activate()
    }

    fn cleanup_exact(&mut self) {
        let Some(registration) = self.registration.take() else {
            return;
        };
        registration.cleanup().unwrap_or_else(|error| {
            carrick_fatal!(
                "hvpatch::task_backend_lifecycle",
                "exact deferred HVPatch task cleanup: {error}"
            );
        });
    }
}

impl Drop for HvpatchTaskOnlyBackendState {
    fn drop(&mut self) {
        self.cleanup_exact();
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct HvpatchCarrierTaskIdentity {
    pub task_serial: u64,
    pub thread_serial: u64,
    pub execution_generation: u64,
    pub linux_pid: i32,
    pub linux_tid: i32,
    pub asid: u16,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub use carrick_hal::HvpatchChildKernelToken as HvpatchChildKernelBinding;

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct HvpatchCarrierTaskStateKey {
    directory_instance: std::num::NonZeroU64,
    task_serial: u64,
    thread_serial: u64,
    execution_generation: u64,
    nonce: std::num::NonZeroU64,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[allow(dead_code)]
enum HvpatchCarrierTaskState {
    Sibling {
        vm: applevisor::vm::VirtualMachineInstance<applevisor::vm::GicDisabled>,
    },
    /// A distinct Linux process which retains an already-published MM.  The
    /// existing carrier-MM row owns the VM/stage-2 lifecycle; this edge owns no
    /// replacement carrier authority of its own.
    SharedProcess {
        vm: applevisor::vm::VirtualMachineInstance<applevisor::vm::GicDisabled>,
    },
    Process {
        vm: applevisor::vm::VirtualMachineInstance<applevisor::vm::GicDisabled>,
        stage2_leases: Vec<GlobalFrameStage2Lease>,
    },
    #[cfg(test)]
    Test {
        rollbacks: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        order: Option<std::sync::Arc<parking_lot::Mutex<Vec<&'static str>>>>,
    },
    #[cfg(test)]
    LeaseTest {
        stage2_leases: Vec<GlobalFrameStage2Lease>,
    },
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
enum HvpatchCarrierMmAuthority {
    Live {
        stage2_logical_leases: Vec<CarrierStage2LogicalLease>,
        custody: std::sync::Weak<CarrierVmCustody>,
        frames: std::sync::Arc<parking_lot::Mutex<InventoryFrameRegistry>>,
        _vm: applevisor::vm::VirtualMachineInstance<applevisor::vm::GicDisabled>,
    },
    #[cfg(test)]
    Test {
        order: std::sync::Arc<parking_lot::Mutex<Vec<&'static str>>>,
    },
    #[cfg(test)]
    LeaseTest {
        stage2_lease_keys: Vec<(u64, u64)>,
        frames: std::sync::Arc<parking_lot::Mutex<InventoryFrameRegistry>>,
    },
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CarrierStage2LogicalLease {
    key: (u64, u64),
    logical_owner: Option<CarrierLogicalOwner>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn carrier_stage2_logical_leases(
    custody: &CarrierVmCustody,
    identities: &[CarrierStage2RecordIdentity],
) -> Vec<CarrierStage2LogicalLease> {
    identities
        .iter()
        .filter_map(|identity| {
            custody
                .stage2_record_snapshot(identity.record_id)
                .map(|snapshot| CarrierStage2LogicalLease {
                    key: (snapshot.ipa, snapshot.len as u64),
                    logical_owner: identity.logical_owner,
                })
        })
        .collect()
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn request_carrier_stage2_record_retirements(
    stage2_logical_leases: &mut Vec<CarrierStage2LogicalLease>,
    custody: &std::sync::Weak<CarrierVmCustody>,
    frames: &std::sync::Arc<parking_lot::Mutex<InventoryFrameRegistry>>,
) {
    let Some(custody) = custody.upgrade() else {
        stage2_logical_leases.clear();
        return;
    };
    let mut frames = frames.lock();
    for logical_lease in std::mem::take(stage2_logical_leases) {
        let Some(identity) = custody
            .carrier_stage2_records
            .lock()
            .get(&logical_lease.key)
            .copied()
            .filter(|identity| identity.logical_owner == logical_lease.logical_owner)
        else {
            continue;
        };
        let Some(snapshot) = custody.stage2_record_snapshot(identity.record_id) else {
            continue;
        };
        let key = (snapshot.ipa, snapshot.len as u64);
        let authority_retained = frames.authority_retained_stage2.remove(&key);
        if frames.stage2_references.contains_key(&key) || authority_retained {
            // Another MM still names this physical lease, or the Kernel reported
            // a mapping outside the backend population. Consume the one-shot
            // handoff and leave the process-global carrier registry as owner;
            // a later exact retirement takes it through
            // `retire_stage2_extent_from_mappings`.
            continue;
        }
        let _ = custody.request_stage2_record_retirement(identity);
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl Drop for HvpatchCarrierMmAuthority {
    fn drop(&mut self) {
        match self {
            Self::Live {
                stage2_logical_leases,
                custody,
                frames,
                ..
            } => {
                request_carrier_stage2_record_retirements(stage2_logical_leases, custody, frames);
            }
            #[cfg(test)]
            Self::Test { order } => {
                order.lock().push("carrier");
            }
            #[cfg(test)]
            Self::LeaseTest {
                stage2_lease_keys,
                frames,
            } => {
                let custody = legacy_test_carrier_vm_custody_arc();
                let identities = stage2_lease_keys
                    .drain(..)
                    .filter_map(|key| custody.carrier_stage2_records.lock().get(&key).copied())
                    .collect::<Vec<_>>();
                let mut logical_leases = carrier_stage2_logical_leases(custody, &identities);
                request_carrier_stage2_record_retirements(
                    &mut logical_leases,
                    &std::sync::Arc::downgrade(custody),
                    frames,
                );
            }
        }
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
struct HvpatchCarrierTaskRow {
    _mm: Option<std::sync::Arc<HvpatchCarrierMmAuthority>>,
    #[cfg(test)]
    rollbacks: Option<std::sync::Arc<std::sync::atomic::AtomicUsize>>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn rollback_failed_directory_publication(
    task_mm: &std::sync::Arc<HvpatchTaskMmAuthority>,
    row: HvpatchCarrierTaskRow,
    carrier_mm: Option<std::sync::Arc<HvpatchCarrierMmAuthority>>,
) -> Result<
    (
        HvpatchCarrierTaskRow,
        Option<std::sync::Arc<HvpatchCarrierMmAuthority>>,
    ),
    TrapError,
> {
    #[cfg(test)]
    if let Some(rollbacks) = &row.rollbacks {
        rollbacks.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
    task_mm.rollback_unpublished_before_carrier_drop()?;
    Ok((row, carrier_mm))
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct HvpatchMmAuthorityKey {
    task_serial: u64,
    mm_root_slot: Option<(u64, u64)>,
    shared_kernel_mm: Option<u64>,
}

/// Who holds the reusable global-frame owner row a task mapping names.
///
/// Reusable global frames are shared by IPA across processes: a forked child
/// borrows the parent's private frames COW, a CLONE_VM sibling views every row
/// of its process, and an exec rebind re-describes the process's own live rows.
/// The `owner_generation` stamped on such a descriptor is ANOTHER authority's
/// live generation, so it is never permission to retire the row. Only the
/// preparation that registered a row may retire it when that preparation
/// unwinds; reading the stamped generation as ownership retired live parent
/// heap frames under a running process whenever a fork was abandoned after
/// `prepare` (the go `os/exec` crash after a load-induced `fork(2) = EAGAIN`).
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GlobalFrameOwnerRole {
    /// Not a reusable global frame, or its owner row belongs to another
    /// authority. Unwinding this task must leave the row alone.
    Borrowed,
    /// `prepare_task_only_plan` registered `owner_generation` for this task;
    /// unwinding the preparation retires exactly that generation.
    Registered,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[allow(dead_code)] // consumed by the worker-side binding load transaction in the next slice
struct HvpatchTaskMappingState {
    start: u64,
    ipa: u64,
    physical_ipa: u64,
    end: u64,
    host_addr: *mut u8,
    physical_host_addr: *mut u8,
    size: usize,
    physical_size: usize,
    perms: applevisor::memory::MemPerms,
    guest_writable: bool,
    host_mapping: Option<crate::host_mapping::OwnedHostMapping>,
    structural_owner: Option<std::sync::Arc<StructuralBackingOwner>>,
    is_dynamic_alias: bool,
    sharing: GuestMappingSharing,
    shared_key_base: u64,
    shared_key_offset: u64,
    owner_generation: u64,
    global_frame_owner_role: GlobalFrameOwnerRole,
}
unsafe impl Send for HvpatchTaskMappingState {}
// SAFETY: these pointers are immutable address metadata naming MM-owned host
// mappings. Access is authenticated through the stage-1/frame authority and
// synchronized by the worker transaction; the descriptor never dereferences
// them on its own.
unsafe impl Sync for HvpatchTaskMappingState {}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl HvpatchTaskMappingState {
    fn unowned_runtime_region(&self) -> HvfMappedRegion {
        HvfMappedRegion {
            start: self.start,
            ipa: self.ipa,
            physical_ipa: self.physical_ipa,
            end: self.end,
            host_addr: self.host_addr,
            size: self.physical_size,
            physical_size: self.physical_size,
            perms: self.perms,
            memory: None,
            host_mapping: None,
            structural_owner: self.structural_owner.clone(),
            stage2_lease: None,
            is_dynamic_alias: self.is_dynamic_alias,
            sharing: self.sharing,
            guest_writable: self.guest_writable,
            shared_key_base: self.shared_key_base,
            shared_key_offset: self.shared_key_offset,
            owner_generation: self.owner_generation,
        }
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Default)]
#[allow(dead_code)] // retained task authority; worker-side load consumes these fields
struct HvpatchPreparedTaskAuthority {
    custody: Option<std::sync::Arc<CarrierVmCustody>>,
    foreign_mm_transport: Option<std::sync::Arc<CarrierForeignMmTransport>>,
    mappings: Vec<HvpatchTaskMappingState>,
    mm_root_slot: Option<(u64, u64)>,
    /// Exact structural root record captured while this process mapping is
    /// published, before frame inventory selection can omit it.
    mm_root_stage2: Option<MmRootStage2Authority>,
    container_root: ContainerRootToken,
    /// Shared processes use the Kernel's exact MM identity to intern one MM
    /// projection even when the root parent has no task-only directory row.
    shared_kernel_mm: Option<u64>,
    inventory: HvpatchTaskInventoryAuthority,
    cow_authority: Option<std::sync::Arc<dyn carrick_hal::FrameCowAuthority>>,
    cow_identity: Option<carrick_hal::FrameCowIdentity>,
    cow_armed: Option<std::sync::Arc<parking_lot::Mutex<CowArmedRanges>>>,
    cow_deferred_publications:
        Option<std::sync::Arc<parking_lot::Mutex<Vec<PendingFrameCowPublication>>>>,
    /// Exact MM state inherited by a sibling or CLONE_VM process projection.
    ///
    /// This must move as one Arc rather than being reconstructed from its
    /// ledger/COW components: the Arc also owns the exact structural stage-2
    /// authority for the reusable stage-1 root slot.
    inherited_mm_access: Option<std::sync::Arc<MmAccessState>>,
    pending_receipts: Vec<PendingForkFrameReceipt>,
    pending_aliases: Vec<AliasBacking>,
    #[cfg(test)]
    drop_order: Option<std::sync::Arc<parking_lot::Mutex<Vec<&'static str>>>>,
    #[cfg(test)]
    abort_order: Option<std::sync::Arc<parking_lot::Mutex<Vec<&'static str>>>>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Default)]
#[allow(dead_code)] // publication/activation is consumed by the next runtime wiring slice
enum HvpatchTaskInventoryAuthority {
    #[default]
    Absent,
    SiblingShared {
        ledger: std::sync::Arc<parking_lot::Mutex<HvpatchFrameInventory>>,
    },
    SharedProcess {
        ledger: std::sync::Arc<parking_lot::Mutex<HvpatchFrameInventory>>,
    },
    ProcessPrepared {
        ledger: std::sync::Arc<parking_lot::Mutex<HvpatchFrameInventory>>,
        staged: Vec<((u64, u64), InventoryExtent)>,
        commit: Option<carrick_hal::FrameInventoryCommit<()>>,
        challenge: Option<carrick_hal::FrameInventoryReceiptChallenge>,
    },
    InventoryPublished {
        ledger: std::sync::Arc<parking_lot::Mutex<HvpatchFrameInventory>>,
        staged: Vec<((u64, u64), InventoryExtent)>,
        receipt: carrick_hal::FrameInventoryApplyReceipt,
    },
    Active {
        ledger: std::sync::Arc<parking_lot::Mutex<HvpatchFrameInventory>>,
        receipt: carrick_hal::FrameInventoryApplyReceipt,
        retirement: Option<HvpatchPreparedInventoryRetirement>,
    },
    Retired,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
struct HvpatchPreparedInventoryRetirement {
    commit: carrick_hal::FrameInventoryCommit<()>,
    challenge: carrick_hal::FrameInventoryReceiptChallenge,
    expected_mappings: Vec<(carrick_hal::MappingId, carrick_hal::FrameId)>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[allow(dead_code)] // transitions are exposed to the next publication wiring slice
impl HvpatchTaskInventoryAuthority {
    fn shared_runtime_ledger(
        &self,
    ) -> Option<std::sync::Arc<parking_lot::Mutex<HvpatchFrameInventory>>> {
        match self {
            Self::SiblingShared { ledger }
            | Self::SharedProcess { ledger }
            | Self::ProcessPrepared { ledger, .. }
            | Self::InventoryPublished { ledger, .. }
            | Self::Active { ledger, .. } => Some(std::sync::Arc::clone(ledger)),
            Self::Absent | Self::Retired => None,
        }
    }

    fn shared_frame_registry(
        &self,
    ) -> Option<std::sync::Arc<parking_lot::Mutex<InventoryFrameRegistry>>> {
        self.shared_runtime_ledger()
            .map(|ledger| std::sync::Arc::clone(&ledger.lock().frames))
    }

    fn apply_process_inventory(
        &mut self,
        apply: impl FnOnce(
            carrick_hal::FrameInventoryCommit<()>,
        ) -> Result<carrick_hal::FrameInventoryApplyReceipt, TrapError>,
        expected_mm: std::num::NonZeroU64,
    ) -> Result<(), TrapError> {
        let current = std::mem::replace(self, Self::Retired);
        match current {
            Self::ProcessPrepared {
                ledger,
                staged,
                mut commit,
                mut challenge,
            } => {
                if let (Some(commit), Some(challenge)) = (commit.take(), challenge.take()) {
                    match apply(commit) {
                        Ok(receipt) if challenge.authenticate_apply(&receipt, expected_mm) => {
                            *self = Self::InventoryPublished {
                                ledger,
                                staged,
                                receipt,
                            };
                            Ok(())
                        }
                        Ok(_) => {
                            carrick_fatal!(
                                "hvpatch::frame_inventory",
                                "Kernel returned a malformed successful HVPatch inventory receipt"
                            );
                        }
                        Err(_) => {
                            let mut inventory = ledger.lock();
                            HvfVmState::rollback_unpublished_mappings(&mut inventory, &staged)?;
                            Err(TrapError::Hypervisor(
                                "kernel rejected or mis-authenticated HVPatch inventory apply"
                                    .to_owned(),
                            ))
                        }
                    }
                } else {
                    *self = Self::ProcessPrepared {
                        ledger,
                        staged,
                        commit,
                        challenge,
                    };
                    Err(TrapError::Hypervisor(
                        "prepared HVPatch process inventory lost its commit".to_owned(),
                    ))
                }
            }
            other => {
                *self = other;
                Err(TrapError::Hypervisor(
                    "only a prepared process owner may publish HVPatch inventory".to_owned(),
                ))
            }
        }
    }

    fn activate(&mut self, pending_receipts: &[PendingForkFrameReceipt]) -> Result<(), TrapError> {
        let current = std::mem::replace(self, Self::Retired);
        match current {
            Self::SiblingShared { ledger } => {
                *self = Self::SiblingShared { ledger };
                Ok(())
            }
            Self::SharedProcess { ledger } => {
                *self = Self::SharedProcess { ledger };
                Ok(())
            }
            Self::Active {
                ledger,
                receipt,
                retirement,
            } => {
                *self = Self::Active {
                    ledger,
                    receipt,
                    retirement,
                };
                Ok(())
            }
            Self::InventoryPublished {
                ledger,
                staged,
                receipt,
            } => {
                if authenticate_pending_fork_receipts(pending_receipts, &receipt) {
                    *self = Self::Active {
                        ledger,
                        receipt,
                        retirement: None,
                    };
                    Ok(())
                } else {
                    *self = Self::InventoryPublished {
                        ledger,
                        staged,
                        receipt,
                    };
                    Err(TrapError::Hypervisor(
                        "HVPatch fork receipts failed inventory authentication".to_owned(),
                    ))
                }
            }
            other => {
                let phase = other.phase_name();
                *self = other;
                Err(TrapError::Hypervisor(format!(
                    "HVPatch inventory activation requires published inventory (phase={phase})"
                )))
            }
        }
    }

    fn prepare_retirement(
        &mut self,
        commit: carrick_hal::FrameInventoryCommit<()>,
    ) -> Result<(), TrapError> {
        match self {
            Self::Active {
                ledger, retirement, ..
            } if retirement.is_none() => {
                // ONE invariant: the commit must cover exactly what this mm
                // owned WHEN ITS RETIREMENT WAS STAGED.
                //
                // `stage_retirement` pushes an `UnmapMapping` per extent and
                // then clears `extents` in the same critical section, so on the
                // production path the live ledger is empty by construction and
                // the snapshot it recorded there is the only faithful statement
                // of that set. A caller that has not staged yet still has its
                // set in `extents`. Taking the snapshot also makes a duplicate
                // retirement fail closed instead of silently passing.
                let mut expected_mappings = {
                    let mut ledger = ledger.lock();
                    let staged = std::mem::take(&mut ledger.retirement_expected);
                    if staged.is_empty() {
                        ledger
                            .extents
                            .values()
                            .map(|extent| (extent.mapping, extent.frame))
                            .collect()
                    } else {
                        staged
                    }
                };
                expected_mappings.sort_unstable();
                expected_mappings.dedup();
                let mut committed_unmaps: Vec<_> = commit
                    .batch()
                    .events()
                    .iter()
                    .filter_map(|event| match *event {
                        carrick_hal::FrameInventoryEvent::UnmapMapping { mapping, .. } => {
                            Some(mapping)
                        }
                        _ => None,
                    })
                    .collect();
                committed_unmaps.sort_unstable();
                committed_unmaps.dedup();
                let expected_ids: Vec<_> = expected_mappings
                    .iter()
                    .map(|(mapping, _)| *mapping)
                    .collect();
                if expected_mappings.is_empty() || committed_unmaps != expected_ids {
                    // Name the exact disagreement. "does not cover" alone cannot
                    // distinguish an empty ledger from a commit that unmaps a
                    // different set, and those call for opposite fixes.
                    let ledger_only: Vec<_> = expected_ids
                        .iter()
                        .filter(|id| !committed_unmaps.contains(id))
                        .take(8)
                        .collect();
                    let commit_only: Vec<_> = committed_unmaps
                        .iter()
                        .filter(|id| !expected_ids.contains(id))
                        .take(8)
                        .collect();
                    return Err(TrapError::Hypervisor(format!(
                        "retirement commit does not cover exact current HVPatch MM ledger                          (ledger={} commit={} ledger_only={ledger_only:?} commit_only={commit_only:?})",
                        expected_ids.len(),
                        committed_unmaps.len(),
                    )));
                }
                let challenge = commit.receipt_challenge();
                *retirement = Some(HvpatchPreparedInventoryRetirement {
                    commit,
                    challenge,
                    expected_mappings,
                });
                Ok(())
            }
            // Name the phase. "duplicate or not active" covers six distinct
            // states that call for different fixes: `retired` means a second
            // retirement path reached the same authority, while `prepared` or
            // `inventory_published` means retirement raced ahead of activation.
            other => {
                let phase = other.phase_name();
                Err(TrapError::Hypervisor(format!(
                    "HVPatch inventory retirement is duplicate or not active (phase={phase})"
                )))
            }
        }
    }

    fn apply_retirement(
        &mut self,
        expected_mm: std::num::NonZeroU64,
        pending_receipts: &[PendingForkFrameReceipt],
        apply: impl FnOnce(
            carrick_hal::FrameInventoryCommit<()>,
        ) -> Result<carrick_hal::FrameInventoryRetirementReceipt, TrapError>,
    ) -> Result<(), TrapError> {
        let current = std::mem::replace(self, Self::Retired);
        match current {
            Self::Active {
                ledger,
                receipt,
                retirement: Some(retirement),
            } => match apply(retirement.commit) {
                Ok(retired) => {
                    let challenge = retirement
                        .challenge
                        .authenticate_retirement(&retired, expected_mm);
                    let revision_advanced = retired.revision() > receipt.revision();
                    let transaction_distinct = retired.transaction() != receipt.transaction();
                    let audit = authenticate_pending_retirement(
                        &retirement.expected_mappings,
                        pending_receipts,
                        &retired,
                    );
                    if challenge && revision_advanced && transaction_distinct && audit.ok() {
                        return Ok(());
                    }
                    // Abort is unrecoverable, so name the exact clause that
                    // rejected the receipt rather than only its verdict.
                    //
                    // A rejected pending fork receipt has two very different
                    // shapes: the child mapping is absent from the retirement
                    // entirely (a superseded mapping id), or it is present under
                    // a DIFFERENT frame (the child COW'd the inherited page).
                    // Print which, because they call for opposite fixes.
                    let unauthorized: Vec<String> = pending_receipts
                        .iter()
                        .filter(|pending| !retired.authorizes(pending.child_mapping, pending.frame))
                        .take(6)
                        .map(|pending| {
                            let retired_frame = retired
                                .mapping_set()
                                .iter()
                                .find(|(mapping, _)| *mapping == pending.child_mapping)
                                .map(|(_, frame)| *frame);
                            format!(
                                "{{child={:?} receipt_frame={:?} retirement_frame={retired_frame:?} \
                                 parent={:?} ipa={:#x} len={:#x} kind={:?}}}",
                                pending.child_mapping,
                                pending.frame,
                                pending.parent_mapping,
                                pending.ipa,
                                pending.length,
                                pending.kind,
                            )
                        })
                        .collect();
                    carrick_fatal!(
                        "hvpatch::frame_inventory",
                        "Kernel returned a malformed successful HVPatch retirement receipt\
                         (challenge={challenge} revision_advanced={revision_advanced} \
                         transaction_distinct={transaction_distinct} {audit:?} \
                         receipt_revision={} retired_revision={} expected_mappings={} \
                         receipt_mapping_set={} pending_receipts={} \
                         unauthorized={unauthorized:?})",
                        receipt.revision(),
                        retired.revision(),
                        retirement.expected_mappings.len(),
                        retired.mapping_set().len(),
                        pending_receipts.len(),
                    );
                }
                Err(error) => {
                    *self = Self::Active {
                        ledger,
                        receipt,
                        retirement: None,
                    };
                    Err(error)
                }
            },
            other => {
                *self = other;
                Err(TrapError::Hypervisor(
                    "HVPatch inventory retirement lacks an owned prepared commit".to_owned(),
                ))
            }
        }
    }

    fn rollback_unpublished(&mut self) -> Result<(), TrapError> {
        let current = std::mem::replace(self, Self::Retired);
        match current {
            Self::Absent
            | Self::SiblingShared { .. }
            | Self::SharedProcess { .. }
            | Self::Retired => Ok(()),
            Self::ProcessPrepared {
                ledger,
                staged,
                commit,
                challenge: _,
            } => {
                let mut inventory = ledger.lock();
                HvfVmState::rollback_unpublished_mappings(&mut inventory, &staged)?;
                drop(commit);
                Ok(())
            }
            Self::InventoryPublished { .. } | Self::Active { .. } => {
                let phase = current.phase_name();
                *self = current;
                Err(TrapError::Hypervisor(format!(
                    "published HVPatch inventory dropped before exact retirement (phase={phase})"
                )))
            }
        }
    }

    fn retire_exec_predecessor(&mut self) {
        let current = std::mem::replace(self, Self::Retired);
        if let Self::ProcessPrepared {
            ledger,
            staged,
            commit,
            challenge: _,
        } = current
        {
            if let Some(mut inventory) = ledger.try_lock() {
                let _ = HvfVmState::rollback_unpublished_mappings(&mut inventory, &staged);
            }
            drop(commit);
        }
    }

    /// Does this task merely SHARE another process's frame-inventory ledger?
    ///
    /// A vfork/`CLONE_VM` task is published `SharedProcess` (or `SiblingShared`)
    /// because its kernel mm belongs to another process. `activate` and
    /// `rollback_unpublished` already treat those phases as having nothing of
    /// their own to publish or roll back, and retirement is the same: the OWNER
    /// retires the ledger. Staging a retirement from a shared ledger would unmap
    /// the owner's live mappings.
    ///
    /// `Retired` and `Absent` are deliberately NOT folded in here. A second
    /// retirement of an OWNED ledger must keep being refused by
    /// `prepare_retirement`, not silently skipped.
    fn shares_another_process_inventory(&self) -> bool {
        matches!(
            self,
            Self::SiblingShared { .. } | Self::SharedProcess { .. }
        )
    }

    fn phase_name(&self) -> &'static str {
        match self {
            Self::Absent => "absent",
            Self::SiblingShared { .. } => "sibling_shared",
            Self::SharedProcess { .. } => "shared_process",
            Self::ProcessPrepared { .. } => "prepared",
            Self::InventoryPublished { .. } => "inventory_published",
            Self::Active { .. } => "active",
            Self::Retired => "retired",
        }
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HvpatchTaskMmHolder {
    Registration,
    RegistrationDrop,
    RegistrationCleanup,
    LiveExecutor,
    CarrierDirectory,
    DormantRetire,
    ExecRebind,
    FailpointRollback,
    #[cfg(test)]
    Test,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl std::fmt::Display for HvpatchTaskMmHolder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Registration => write!(f, "registration"),
            Self::RegistrationDrop => write!(f, "registration-drop"),
            Self::RegistrationCleanup => write!(f, "registration-cleanup"),
            Self::LiveExecutor => write!(f, "live-executor"),
            Self::CarrierDirectory => write!(f, "carrier-directory"),
            Self::DormantRetire => write!(f, "dormant-retire"),
            Self::ExecRebind => write!(f, "exec-rebind"),
            Self::FailpointRollback => write!(f, "failpoint-rollback"),
            #[cfg(test)]
            Self::Test => write!(f, "test"),
        }
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[allow(dead_code)] // retained MM authority; worker-side load consumes these fields
pub(crate) struct HvpatchTaskMmAuthority {
    mappings: Vec<HvpatchTaskMappingState>,
    foreign_mm_transport: Option<std::sync::Arc<CarrierForeignMmTransport>>,
    mm_root_slot: Option<(u64, u64)>,
    /// Publication-time root custody moves exactly once into the shared
    /// `MmAccessState` when the first executor activates this MM.
    mm_root_stage2: parking_lot::Mutex<Option<MmRootStage2Authority>>,
    container_root: ContainerRootToken,
    inventory: parking_lot::Mutex<HvpatchTaskInventoryAuthority>,
    kernel_mm: parking_lot::Mutex<Option<std::num::NonZeroU64>>,
    cow_armed: Option<std::sync::Arc<parking_lot::Mutex<CowArmedRanges>>>,
    cow_deferred_publications:
        Option<std::sync::Arc<parking_lot::Mutex<Vec<PendingFrameCowPublication>>>>,
    /// Lazily installed exact per-MM state. Repeated executor loads and
    /// CLONE_VM projections receive this same Arc.
    mm_access: parking_lot::Mutex<Option<std::sync::Arc<MmAccessState>>>,
    /// One-shot observation copy. Retirement keeps `pending_receipts` for its
    /// exact Kernel receipt challenge, but an executor reload must never
    /// republish an older fork mapping after COW or munmap supersedes it.
    pending_publication_receipts: parking_lot::Mutex<Vec<PendingForkFrameReceipt>>,
    /// Outstanding fork-inheritance obligations the retirement challenge must
    /// account for. They move with the inventory phase when an exec hands an
    /// `Active` authority to a live CLONE_VM sharer.
    pending_receipts: parking_lot::Mutex<Vec<PendingForkFrameReceipt>>,
    alias_receipts: parking_lot::Mutex<Vec<AliasPublicationReceipt>>,
    last_holder: parking_lot::Mutex<HvpatchTaskMmHolder>,
    #[cfg(test)]
    drop_order: Option<std::sync::Arc<parking_lot::Mutex<Vec<&'static str>>>>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[allow(dead_code)] // next publication slice invokes these exact MM transitions
impl HvpatchTaskMmAuthority {
    fn from_prepared(
        mut prepared: HvpatchPreparedTaskAuthority,
        alias_receipt: AliasPublicationReceipt,
    ) -> Self {
        let pending_receipts = std::mem::take(&mut prepared.pending_receipts);
        Self {
            mappings: std::mem::take(&mut prepared.mappings),
            foreign_mm_transport: prepared.foreign_mm_transport.take(),
            mm_root_slot: prepared.mm_root_slot,
            mm_root_stage2: parking_lot::Mutex::new(prepared.mm_root_stage2.take()),
            container_root: prepared.container_root,
            inventory: parking_lot::Mutex::new(std::mem::take(&mut prepared.inventory)),
            kernel_mm: parking_lot::Mutex::new(None),
            cow_armed: prepared.cow_armed.take(),
            cow_deferred_publications: prepared.cow_deferred_publications.take(),
            mm_access: parking_lot::Mutex::new(prepared.inherited_mm_access.take()),
            pending_publication_receipts: parking_lot::Mutex::new(pending_receipts.clone()),
            pending_receipts: parking_lot::Mutex::new(pending_receipts),
            alias_receipts: parking_lot::Mutex::new(vec![alias_receipt]),
            last_holder: parking_lot::Mutex::new(HvpatchTaskMmHolder::Registration),
            #[cfg(test)]
            drop_order: prepared.drop_order.take(),
        }
    }

    pub(crate) fn record_holder(&self, holder: HvpatchTaskMmHolder) {
        *self.last_holder.lock() = holder;
    }

    fn apply_inventory(
        &self,
        apply: impl FnOnce(
            carrick_hal::FrameInventoryCommit<()>,
        ) -> Result<carrick_hal::FrameInventoryApplyReceipt, TrapError>,
    ) -> Result<(), TrapError> {
        let mm = (*self.kernel_mm.lock()).ok_or_else(|| {
            TrapError::Hypervisor("HVPatch MM has no exact Kernel binding".to_owned())
        })?;
        self.inventory.lock().apply_process_inventory(apply, mm)
    }

    fn activate(&self) -> Result<(), TrapError> {
        self.inventory
            .lock()
            .activate(&self.pending_receipts.lock())
    }

    fn shares_another_process_inventory(&self) -> bool {
        self.inventory.lock().shares_another_process_inventory()
    }

    fn prepare_retirement(
        &self,
        commit: carrick_hal::FrameInventoryCommit<()>,
    ) -> Result<(), TrapError> {
        self.inventory.lock().prepare_retirement(commit)
    }

    fn apply_retirement(
        &self,
        apply: impl FnOnce(
            carrick_hal::FrameInventoryCommit<()>,
        ) -> Result<carrick_hal::FrameInventoryRetirementReceipt, TrapError>,
    ) -> Result<(), TrapError> {
        let mm = (*self.kernel_mm.lock()).ok_or_else(|| {
            TrapError::Hypervisor("HVPatch MM has no exact Kernel binding".to_owned())
        })?;
        let pending = self.pending_receipts.lock();
        self.inventory.lock().apply_retirement(mm, &pending, apply)
    }

    fn retire_exec_predecessor(&self) {
        self.inventory.lock().retire_exec_predecessor();
    }

    /// Is this authority the `Active` owner of a published inventory?
    fn owns_active_inventory(&self) -> bool {
        matches!(
            &*self.inventory.lock(),
            HvpatchTaskInventoryAuthority::Active { .. }
        )
    }

    /// Move this `Active` inventory -- the Kernel apply receipt and every
    /// outstanding fork-inheritance receipt -- to `sharer`, the CLONE_VM/vfork
    /// process that keeps the mm after the owner execs (`RetainOldMm`).
    ///
    /// The Kernel names the sharer as the mm's surviving owner, so the sharer's
    /// terminal path is where the exact retirement must be issued from; leaving
    /// the receipt on the exec'ing owner's authority either discards it (last
    /// holder, `retire_exec_predecessor`) or aborts the carrier when a sibling
    /// thread's registration drops it still `Active`. After the hand-off the
    /// owner's phase is `Retired`, so every remaining holder drops it inertly.
    fn hand_off_inventory_to_sharer(&self, sharer: &Self) -> Result<(), TrapError> {
        let mm = (*self.kernel_mm.lock()).ok_or_else(|| {
            TrapError::Hypervisor(
                "HVPatch exec predecessor hand-off has no exact Kernel binding".to_owned(),
            )
        })?;
        sharer.bind_kernel_mm(mm)?;
        let mut inventory = self.inventory.lock();
        let mut sharer_inventory = sharer.inventory.lock();
        let ledger = match &*inventory {
            HvpatchTaskInventoryAuthority::Active {
                ledger,
                retirement: None,
                ..
            } => std::sync::Arc::clone(ledger),
            other => {
                return Err(TrapError::Hypervisor(format!(
                    "HVPatch exec predecessor hand-off from phase={}",
                    other.phase_name()
                )));
            }
        };
        match &*sharer_inventory {
            HvpatchTaskInventoryAuthority::SharedProcess {
                ledger: sharer_ledger,
            } if std::sync::Arc::ptr_eq(sharer_ledger, &ledger) => {}
            other => {
                return Err(TrapError::Hypervisor(format!(
                    "HVPatch exec predecessor hand-off to sharer phase={} on a foreign ledger",
                    other.phase_name()
                )));
            }
        }
        *sharer_inventory =
            std::mem::replace(&mut *inventory, HvpatchTaskInventoryAuthority::Retired);
        sharer
            .pending_receipts
            .lock()
            .extend(self.pending_receipts.lock().drain(..));
        Ok(())
    }

    fn rollback_unpublished_before_carrier_drop(&self) -> Result<(), TrapError> {
        self.inventory.lock().rollback_unpublished()
    }

    fn bind_kernel_mm(&self, mm: std::num::NonZeroU64) -> Result<(), TrapError> {
        let mut bound = self.kernel_mm.lock();
        match *bound {
            None => {
                *bound = Some(mm);
                Ok(())
            }
            Some(existing) if existing == mm => Ok(()),
            Some(_) => Err(TrapError::Hypervisor(
                "HVPatch MM binding changed across sibling registrations".to_owned(),
            )),
        }
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl Drop for HvpatchTaskMmAuthority {
    fn drop(&mut self) {
        for receipt in self.alias_receipts.get_mut().drain(..).rev() {
            receipt.retire_exact();
        }
        let phase = self.inventory.get_mut().phase_name();
        let mm_root_slot = self.mm_root_slot;
        let kernel_mm = *self.kernel_mm.get_mut();
        let holder = *self.last_holder.get_mut();
        self.inventory
            .get_mut()
            .rollback_unpublished()
            .unwrap_or_else(|error| {
                carrick_fatal!(
                    "hvpatch::mm_authority",
                    "drop HVPatch MM authority \
                     (phase={phase} mm_root_slot={mm_root_slot:?} kernel_mm={kernel_mm:?} holder={holder}): {error}"
                );
            });
        #[cfg(test)]
        if let Some(order) = &self.drop_order {
            order.lock().push("task");
        }
        // `mappings` (and their host owners) drop only after the inventory is
        // retired. The registration removes the carrier MM first: zero-reference
        // stage-2 leases unmap there, while referenced leases stay parked in the
        // process-global carrier registry for the later exact retirement.
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl HvpatchPreparedTaskAuthority {
    /// COW arming and COW deferred publication are ONE authority: a task that
    /// can arm a COW range must also own the slot its deferred publications
    /// land in. Publication is the last boundary that can still reject a task
    /// cheaply — past it the child is live and a missing half aborts the
    /// carrier when a worker activates it.
    fn validate_cow_authority_pairing(&self) -> Result<(), TrapError> {
        match (
            self.cow_armed.is_some(),
            self.cow_deferred_publications.is_some(),
        ) {
            (true, true) | (false, false) => Ok(()),
            (true, false) => Err(TrapError::Hypervisor(
                "HVPatch prepared task authority armed COW without publication state".to_owned(),
            )),
            (false, true) => Err(TrapError::Hypervisor(
                "HVPatch prepared task authority holds COW publication state without arming"
                    .to_owned(),
            )),
        }
    }

    fn rollback_unpublished_inventory(&mut self) -> Result<(), TrapError> {
        // Pending aliases have never touched either global registry.  The
        // publication receipt owns exact preimages only after commit.
        self.inventory.rollback_unpublished()?;
        #[cfg(test)]
        if let Some(order) = &self.abort_order {
            order.lock().push("inventory");
        }
        Ok(())
    }

    fn abort(mut self) -> Result<(), TrapError> {
        self.rollback_unpublished_inventory()
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn abort_prepared_task_and_carrier(
    mut task: HvpatchPreparedTaskAuthority,
    state: HvpatchCarrierTaskState,
) -> Result<(), TrapError> {
    let custody = task.custody.as_ref().cloned();
    // The backend ledger must forget every unpublished mapping BEFORE the
    // carrier leases can return their IPAs to the allocator. Keep `task` alive
    // until after carrier teardown so its host mappings still back any installed
    // stage-2 entries while the leases unmap them.
    task.rollback_unpublished_inventory()
        .unwrap_or_else(|error| {
            carrick_fatal!(
                "hvpatch::frame_inventory",
                "rollback prepared HVPatch inventory before carrier teardown: {error}"
            );
        });
    let state_result = state.abort();
    let mut owner_rollback_error = None;
    if let Some(custody) = custody.as_ref() {
        for mapping in &task.mappings {
            // Retire only the owner rows THIS preparation registered. Borrowed
            // rows (a forked child's COW view of its parent's frames, a
            // CLONE_VM sibling's view of its process) stay live for their
            // owner; retiring them here unmapped a running parent's heap.
            if mapping.global_frame_owner_role == GlobalFrameOwnerRole::Registered {
                let outcome = retire_global_frame_host_owner_if_generation_in(
                    custody,
                    mapping.physical_ipa,
                    mapping.physical_size as u64,
                    mapping.owner_generation,
                );
                if !outcome.is_retired() {
                    owner_rollback_error = Some(TrapError::Hypervisor(format!(
                        "prepared task global owner rollback deferred: {outcome:?}"
                    )));
                }
            }
        }
    }
    drop(task);
    state_result?;
    if let Some(custody) = custody.as_ref()
        && let Err(error) = retry_structural_backing_retirements_in_using(
            custody,
            &mut unmap_global_frame_stage2_record,
            &mut release_retired_stage2_ipa,
        )
    {
        owner_rollback_error = Some(error);
    }
    if let Some(error) = owner_rollback_error {
        return Err(error);
    }
    Ok(())
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Default)]
struct AliasPublicationReceipt {
    versions: Vec<AliasPublicationVersionId>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct AliasPublicationVersionId {
    owner: HvpatchCarrierTaskStateKey,
    ordinal: u32,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[cfg_attr(test, derive(Clone, Debug, Eq, PartialEq))]
struct OwnedAliasVersion {
    id: AliasPublicationVersionId,
    value: AliasBacking,
    epoch: u64,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[cfg_attr(test, derive(Clone, Debug, Eq, PartialEq))]
struct AliasVersionChain {
    // The `(start, ipa, scope)` tuple is the map key; it is deliberately not
    // duplicated into the value, so the key and the row can never disagree.
    base: Option<AliasBacking>,
    versions: Vec<OwnedAliasVersion>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
type AliasVersionKey = (u64, u64, AliasOwnershipScope);

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn alias_version_key(alias: &AliasBacking) -> AliasVersionKey {
    (alias.start, alias.ipa, alias.ownership_scope)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[cfg_attr(test, derive(Clone, Debug, Eq, PartialEq))]
struct OwnedReplayVersion {
    id: AliasPublicationVersionId,
    value: ReplayMappingKey,
    epoch: u64,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[cfg_attr(test, derive(Clone, Debug, Eq, PartialEq))]
struct ReplayVersionChain {
    // `physical_ipa` is the map key; see `AliasVersionChain`.
    base: Vec<ReplayMappingKey>,
    versions: Vec<OwnedReplayVersion>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
/// Carrier-global alias/replay version state, keyed on every axis it is
/// looked up by.
///
/// These were `Vec`s scanned with `iter().position(..)` / `iter().find(..)`.
/// Because the containers are carrier-global but the lookups are per-process,
/// every guest process exit paid a scan proportional to every OTHER live
/// process — the O(N^2) exit path measured on 2026-08-30 (see
/// `retiring_one_owner_does_not_scan_foreign_alias_rows`). The version indexes
/// exist so `AliasPublicationReceipt::retire_exact` can find the chain owning
/// a version id without walking every chain's version list.
#[derive(Default)]
#[cfg_attr(test, derive(Clone, Debug, Eq, PartialEq))]
pub(crate) struct AliasVersionRegistry {
    aliases: std::collections::BTreeMap<AliasVersionKey, AliasVersionChain>,
    replays: std::collections::BTreeMap<u64, ReplayVersionChain>,
    alias_epochs: std::collections::BTreeMap<AliasVersionKey, u64>,
    replay_epochs: std::collections::BTreeMap<u64, u64>,
    alias_version_owner: std::collections::BTreeMap<AliasPublicationVersionId, AliasVersionKey>,
    replay_version_owner: std::collections::BTreeMap<AliasPublicationVersionId, u64>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn alias_version_registry() -> &'static parking_lot::Mutex<AliasVersionRegistry> {
    static CELL: std::sync::OnceLock<parking_lot::Mutex<AliasVersionRegistry>> =
        std::sync::OnceLock::new();
    CELL.get_or_init(|| parking_lot::Mutex::new(AliasVersionRegistry::default()))
}

/// Hot paths whose cost must be a function of the operation, not of the
/// carrier. Each variant owns one per-thread visited-row counter.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HotPathScan {
    /// Linear passes over the carrier-global alias registry, replay set and
    /// alias version chains.
    AliasState,
    /// Passes over one forking process's source mappings.
    ForkMappings,
    /// Rows one task's [`TaskMappingIndex`] offered to a lookup. The ordered
    /// views are meant to make this a function of the ANSWER -- the covering
    /// row and its neighbours -- not of the table, so a per-fault count that
    /// tracks the row population names a surviving full-table walk.
    ///
    /// Unlike the other two variants this is counted per ROW, not per pass:
    /// the index's queries are lazy ordered walks whose length is not known
    /// until the consumer stops pulling, so one thread-local `Cell` add per
    /// visited row is the price of knowing the walk length at all.
    TaskMappings,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
thread_local! {
    static ALIAS_STATE_ROWS_SCANNED: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    static FORK_MAPPING_ROWS_SCANNED: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    static TASK_MAPPING_ROWS_SCANNED: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// Account one linear pass over the CARRIER-GLOBAL alias / replay / version
/// state.
///
/// This exists so an algorithmic-complexity regression is a TEST FAILURE
/// rather than a timing observation. The alias registry, the replay set and
/// the alias version chains are carrier-global containers that hold rows
/// belonging to every live guest process, and a per-process operation that
/// scans them is O(all processes) — the `docs/identity-and-scope-domains.md`
/// scope-domain defect. Measured on 2026-08-30, that made guest process exit
/// cost 38.7 ms of globally serialized topology-lock hold with 1,000 children
/// live, decaying monotonically to 5.3 ms as they drained: an O(N^2) exit path
/// that `futexforkrequeue` could not reap inside its 40 s bound.
///
/// A wall-clock assertion for that shape is load-sensitive and would be
/// excluded from CI within a week. A visited-row count is deterministic, so
/// `retiring_one_owner_does_not_scan_foreign_alias_rows` can state the
/// complexity contract directly.
///
/// Cost is one thread-local add per PASS (never per row), so this is always
/// on: a counter nobody runs is a counter that lies. It is PER THREAD on
/// purpose — a process-global counter is polluted by every other guest thread
/// and by every concurrently running test, which made the first version of
/// `retiring_one_owner_does_not_scan_foreign_alias_rows` report 1,539 rows
/// under `cargo test`'s default parallelism and 513 in isolation for the same
/// work. Per-thread also attributes the cost to the executor that paid it.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn note_alias_state_rows_scanned(rows: usize) {
    note_hot_path_rows(HotPathScan::AliasState, rows);
}

/// Account one pass over a hot-path container. See [`HotPathScan`].
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn note_hot_path_rows(scan: HotPathScan, rows: usize) {
    let counter = match scan {
        HotPathScan::AliasState => &ALIAS_STATE_ROWS_SCANNED,
        HotPathScan::ForkMappings => &FORK_MAPPING_ROWS_SCANNED,
        HotPathScan::TaskMappings => &TASK_MAPPING_ROWS_SCANNED,
    };
    counter.with(|cell| cell.set(cell.get().saturating_add(rows as u64)));
}

/// Account one row a [`TaskMappingIndex`] ordered query offered its consumer.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[inline]
pub(crate) fn note_task_mapping_row_visited() {
    TASK_MAPPING_ROWS_SCANNED.with(|cell| cell.set(cell.get().saturating_add(1)));
}

/// Visited rows for one hot path on the CALLING thread, readable by shipped
/// code. Monotonic; callers difference two reads around the operation.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn hot_path_rows_scanned_live(scan: HotPathScan) -> u64 {
    match scan {
        HotPathScan::AliasState => ALIAS_STATE_ROWS_SCANNED.with(std::cell::Cell::get),
        HotPathScan::ForkMappings => FORK_MAPPING_ROWS_SCANNED.with(std::cell::Cell::get),
        HotPathScan::TaskMappings => TASK_MAPPING_ROWS_SCANNED.with(std::cell::Cell::get),
    }
}

/// Visited rows for one hot path on the CALLING thread. Monotonic; callers
/// compare two reads around the operation under test.
#[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn hot_path_rows_scanned(scan: HotPathScan) -> u64 {
    hot_path_rows_scanned_live(scan)
}

/// Total rows visited by linear passes over the carrier-global alias state.
/// Monotonic; callers compare two reads around the operation under test.
///
/// The COUNTER is unconditional so the shipped code path and the measured one
/// are the same instructions; only this reader is test-scoped, because the
/// value has no production consumer yet.
#[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn alias_state_rows_scanned() -> u64 {
    hot_path_rows_scanned(HotPathScan::AliasState)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn bump_version_epoch<K: Copy + Ord>(
    epochs: &mut std::collections::BTreeMap<K, u64>,
    key: K,
) -> Option<u64> {
    let epoch = epochs.entry(key).or_insert(0);
    *epoch = epoch.checked_add(1)?;
    Some(*epoch)
}

/// Every replay row whose leading physical IPA is `physical_ipa`.
///
/// `ReplayMappingKey` sorts on that IPA first, so this is a range query, not a
/// filter over the whole carrier-global set. The linear `filter` it replaces
/// ran once per affected key per mutation and was part of the O(N^2) exit
/// path.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn replay_rows_for_ipa(
    replay: &std::collections::BTreeSet<ReplayMappingKey>,
    physical_ipa: u64,
) -> Vec<ReplayMappingKey> {
    use std::ops::Bound;
    let start = Bound::Included((physical_ipa, usize::MIN, usize::MIN, u64::MIN, u64::MIN));
    let end = match physical_ipa.checked_add(1) {
        Some(next) => Bound::Excluded((next, usize::MIN, usize::MIN, u64::MIN, u64::MIN)),
        None => Bound::Unbounded,
    };
    replay.range((start, end)).copied().collect()
}

/// Re-base one alias version chain and report the version ids it orphaned.
///
/// Split out so the chain mutation and the version-index cleanup borrow
/// disjoint `AliasVersionRegistry` fields in sequence rather than at once.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn reset_alias_chain(
    chains: &mut std::collections::BTreeMap<AliasVersionKey, AliasVersionChain>,
    key: AliasVersionKey,
    base: Option<AliasBacking>,
) -> Vec<AliasPublicationVersionId> {
    match chains.get_mut(&key) {
        Some(chain) => {
            chain.base = base;
            chain.versions.drain(..).map(|version| version.id).collect()
        }
        None => Vec::new(),
    }
}

/// Replay-side counterpart of [`reset_alias_chain`].
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn reset_replay_chain(
    chains: &mut std::collections::BTreeMap<u64, ReplayVersionChain>,
    physical_ipa: u64,
    base: Vec<ReplayMappingKey>,
) -> Vec<AliasPublicationVersionId> {
    match chains.get_mut(&physical_ipa) {
        Some(chain) => {
            chain.base = base;
            chain.versions.drain(..).map(|version| version.id).collect()
        }
        None => Vec::new(),
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
/// Scoped fast path for the two per-COW-fault alias mutators. The general
/// `mutate_external_alias_state` CLONES the whole replay set and alias
/// registry and diffs them O(n^2) per mutation to discover the touched keys;
/// on fork-storm workloads that made every COW fault O(aliases) and
/// `futexforkrequeue` burned its whole 45s budget in the diff (sampled:
/// register_shared_alias walking the BTreeMap under perform_frame_cow).
/// The hot mutators KNOW their touched keys, so this bumps exactly those
/// epochs with the same lock order and the same chain-reset semantics.
fn scoped_alias_epoch_update(
    versions: &mut AliasVersionRegistry,
    alias_change: Option<(AliasVersionKey, Option<AliasBacking>)>,
    replay_ipas: &[u64],
    replay: &std::collections::BTreeSet<ReplayMappingKey>,
) {
    if let Some((key, after)) = alias_change {
        bump_version_epoch(&mut versions.alias_epochs, key).unwrap_or_else(|| {
            carrick_fatal!(
                "hvpatch::host_alias",
                "external alias mutation epoch exhausted"
            );
        });
        for id in reset_alias_chain(&mut versions.aliases, key, after) {
            versions.alias_version_owner.remove(&id);
        }
    }
    for physical_ipa in replay_ipas {
        bump_version_epoch(&mut versions.replay_epochs, *physical_ipa).unwrap_or_else(|| {
            carrick_fatal!(
                "hvpatch::host_alias",
                "external replay mutation epoch exhausted"
            );
        });
        let base = replay_rows_for_ipa(replay, *physical_ipa);
        for id in reset_replay_chain(&mut versions.replays, *physical_ipa, base) {
            versions.replay_version_owner.remove(&id);
        }
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
/// Drop every alias row a retiring guest process owns.
///
/// This is the process-exit counterpart of [`scoped_alias_epoch_update`]. Two
/// things made the previous shape O(live processes) per exit, and therefore
/// O(N^2) across an exiting process group:
///
/// - the generic [`mutate_external_alias_state`] path CLONED the whole replay
///   set and alias registry and re-derived the touched keys by diffing them,
///   even though the caller knows exactly which rows leave; and
/// - the registry was a flat carrier-global `Vec`, so even a single `retain`
///   pass visited every other live process's rows.
///
/// `alias_is_owned_by_process` selects exactly one [`AliasOwnershipScope`], and
/// the registry is now partitioned on that axis, so the owned rows leave as a
/// bucket removal. The only other rows a process may drop are `Global`
/// shared-file aliases, whose population is bounded by open files rather than
/// by live processes. Everything else is not visited at all.
///
/// Measured 2026-08-30: the single-pass version was 45.4% of all carrier user
/// CPU under a 1,000-child fork/exit storm.
fn retire_process_aliases(
    mm_root_slot: Option<(u64, u64)>,
    container_root: ContainerRootToken,
    global_keep: impl FnMut(&AliasBacking) -> bool,
) {
    // Same replay -> alias -> version lock order as receipt publication and
    // retirement, and as `mutate_external_alias_state`.
    let replay = replay_mappings().lock();
    let mut registry = alias_registry().lock();
    let mut versions = alias_version_registry().lock();
    retire_process_aliases_in(
        &mut registry,
        &replay,
        &mut versions,
        mm_root_slot,
        container_root,
        global_keep,
    );
}

/// The body of [`retire_process_aliases`], against explicitly supplied
/// authorities rather than the process-global ones.
///
/// Taking the three structures as parameters is what makes the complexity
/// contract testable: `retiring_one_owner_does_not_scan_foreign_alias_rows`
/// measures visited rows, and driving the carrier-global registry made that
/// measurement depend on whatever other tests happened to be running (observed
/// failing roughly one run in three). A per-process operation should not need
/// process-global state to be exercised, and now it does not.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn retire_process_aliases_in(
    registry: &mut AliasRegistry,
    replay: &std::collections::BTreeSet<ReplayMappingKey>,
    versions: &mut AliasVersionRegistry,
    mm_root_slot: Option<(u64, u64)>,
    container_root: ContainerRootToken,
    mut global_keep: impl FnMut(&AliasBacking) -> bool,
) {
    let owned_scope = AliasRegistry::owned_scope(mm_root_slot, container_root);
    let mut dropped_global_first = std::collections::BTreeMap::new();
    let mut dropped_global_order = Vec::new();
    let mut seen_global_keys = std::collections::BTreeSet::new();

    let removed_owned = registry.remove_scope(owned_scope);
    let removed_global = registry.retain_in_scope(AliasOwnershipScope::Global, |alias| {
        let key = alias_version_key(alias);
        let survives = global_keep(alias);
        if seen_global_keys.insert(key) && !survives {
            dropped_global_first.insert(key, *alias);
            dropped_global_order.push(key);
        }
        survives
    });
    note_alias_state_rows_scanned(removed_owned.len() + removed_global.len());

    // Affected keys, in first-seen order, with their effective row beforehand and afterwards.
    // Removing a whole scope leaves every key in it with no successor; the
    // `Global` half keeps the generic path's first-occurrence semantics for
    // duplicate keys exactly.
    let mut affected: Vec<(AliasVersionKey, Option<AliasBacking>)> = Vec::new();
    let mut seen_keys = std::collections::BTreeSet::new();
    for alias in &removed_owned {
        let key = alias_version_key(alias);
        if seen_keys.insert(key) {
            affected.push((key, None));
        }
    }
    for key in dropped_global_order {
        let before = dropped_global_first[&key];
        let after = registry.find_by_key(key.0, key.1, key.2);
        if after == Some(before) {
            continue;
        }
        affected.push((key, after));
    }
    let global_first_before = dropped_global_first;

    let mut affected_physical: Vec<u64> = Vec::new();
    let mut affected_physical_seen: std::collections::BTreeSet<u64> =
        std::collections::BTreeSet::new();
    for (key, after) in affected {
        let before_rows = if key.2 == owned_scope {
            removed_owned
                .iter()
                .find(|alias| alias_version_key(alias) == key)
                .copied()
        } else {
            global_first_before.get(&key).copied()
        };
        for alias in before_rows.into_iter().chain(after) {
            if affected_physical_seen.insert(alias.physical_ipa) {
                affected_physical.push(alias.physical_ipa);
            }
        }
        bump_version_epoch(&mut versions.alias_epochs, key).unwrap_or_else(|| {
            carrick_fatal!(
                "hvpatch::host_alias",
                "external alias mutation epoch exhausted"
            );
        });
        for id in reset_alias_chain(&mut versions.aliases, key, after) {
            versions.alias_version_owner.remove(&id);
        }
    }

    // A retirement never touches the replay set, so the generic path's
    // replay-side diff can only report the IPAs the alias changes already imply.
    for physical_ipa in affected_physical {
        bump_version_epoch(&mut versions.replay_epochs, physical_ipa).unwrap_or_else(|| {
            carrick_fatal!(
                "hvpatch::host_alias",
                "external replay mutation epoch exhausted"
            );
        });
        let base = replay_rows_for_ipa(replay, physical_ipa);
        for id in reset_replay_chain(&mut versions.replays, physical_ipa, base) {
            versions.replay_version_owner.remove(&id);
        }
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn mutate_external_alias_state<R>(
    mutate: impl FnOnce(&mut std::collections::BTreeSet<ReplayMappingKey>, &mut AliasRegistry) -> R,
) -> R {
    // All external writers use the same replay -> alias -> version lock order
    // as receipt publication/retirement. A mutation becomes the new effective
    // base and invalidates every older receipt version for the touched key.
    let mut replay = replay_mappings().lock();
    let mut registry = alias_registry().lock();
    let mut versions = alias_version_registry().lock();
    mutate_external_alias_state_in(&mut replay, &mut registry, &mut versions, mutate)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn mutate_external_alias_state_in<R>(
    replay: &mut std::collections::BTreeSet<ReplayMappingKey>,
    registry: &mut AliasRegistry,
    versions: &mut AliasVersionRegistry,
    mutate: impl FnOnce(&mut std::collections::BTreeSet<ReplayMappingKey>, &mut AliasRegistry) -> R,
) -> R {
    let replay_before = replay.clone();
    let registry_before = registry.clone();
    let result = mutate(replay, registry);

    // Index the FIRST alias per (start, ipa, scope) on each side once. The previous
    // shape rescanned the whole registry per key (two linear `find`s plus a
    // linear key dedup), which was O(aliases^2) per mutation and made every
    // process retirement in a 1000-process exit storm pay hundreds of
    // milliseconds inside this function. First-occurrence indexing preserves
    // the historical `find`-first semantics for duplicate keys exactly.
    note_alias_state_rows_scanned(registry_before.len() + registry.len());
    let mut before_by_key = std::collections::BTreeMap::new();
    for alias in registry_before.iter() {
        before_by_key
            .entry(alias_version_key(alias))
            .or_insert(*alias);
    }
    let mut after_by_key = std::collections::BTreeMap::new();
    for alias in registry.iter() {
        after_by_key
            .entry(alias_version_key(alias))
            .or_insert(*alias);
    }
    let mut alias_keys = Vec::new();
    let mut seen_alias_keys = std::collections::BTreeSet::new();
    note_alias_state_rows_scanned(registry_before.len() + registry.len());
    for alias in registry_before.iter().chain(registry.iter()) {
        let key = alias_version_key(alias);
        if seen_alias_keys.insert(key) {
            alias_keys.push(key);
        }
    }
    let mut affected_physical_ipas = Vec::new();
    let mut affected_physical_set = std::collections::BTreeSet::new();
    for key in alias_keys {
        let before = before_by_key.get(&key).copied();
        let after = after_by_key.get(&key).copied();
        if before == after {
            continue;
        }
        for alias in before.into_iter().chain(after) {
            if affected_physical_set.insert(alias.physical_ipa) {
                affected_physical_ipas.push(alias.physical_ipa);
            }
        }
        bump_version_epoch(&mut versions.alias_epochs, key).unwrap_or_else(|| {
            carrick_fatal!(
                "hvpatch::host_alias",
                "external alias mutation epoch exhausted"
            );
        });
        for id in reset_alias_chain(&mut versions.aliases, key, after) {
            versions.alias_version_owner.remove(&id);
        }
    }
    // Group both replay sides by physical IPA once, then compare per key.
    // The previous shape filtered BOTH whole sets per replay row (and did a
    // linear `contains` on the affected list), the replay half of the same
    // O(n^2) mutation cost. BTreeSet iteration is sorted, so the grouped
    // per-IPA vectors are byte-identical to the filtered ones.
    note_alias_state_rows_scanned(replay_before.len() + replay.len());
    let mut replay_before_by_ipa: std::collections::BTreeMap<u64, Vec<ReplayMappingKey>> =
        std::collections::BTreeMap::new();
    for row in replay_before.iter() {
        replay_before_by_ipa.entry(row.0).or_default().push(*row);
    }
    let mut replay_after_by_ipa: std::collections::BTreeMap<u64, Vec<ReplayMappingKey>> =
        std::collections::BTreeMap::new();
    for row in replay.iter() {
        replay_after_by_ipa.entry(row.0).or_default().push(*row);
    }
    for ipa in replay_before_by_ipa
        .keys()
        .chain(replay_after_by_ipa.keys())
        .copied()
        .collect::<std::collections::BTreeSet<_>>()
    {
        if !affected_physical_set.contains(&ipa)
            && replay_before_by_ipa.get(&ipa) != replay_after_by_ipa.get(&ipa)
        {
            affected_physical_set.insert(ipa);
            affected_physical_ipas.push(ipa);
        }
    }
    for physical_ipa in affected_physical_ipas {
        bump_version_epoch(&mut versions.replay_epochs, physical_ipa).unwrap_or_else(|| {
            carrick_fatal!(
                "hvpatch::host_alias",
                "external replay mutation epoch exhausted"
            );
        });
        let base = replay_rows_for_ipa(replay, physical_ipa);
        for id in reset_replay_chain(&mut versions.replays, physical_ipa, base) {
            versions.replay_version_owner.remove(&id);
        }
    }
    result
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn mutate_known_external_alias_state<R>(
    affected: impl FnOnce(
        &std::collections::BTreeSet<ReplayMappingKey>,
        &AliasRegistry,
    ) -> (Vec<AliasVersionKey>, Vec<u64>),
    mutate: impl FnOnce(&mut std::collections::BTreeSet<ReplayMappingKey>, &mut AliasRegistry) -> R,
) -> R {
    // Same lock order as receipt publication. Unlike the generic external
    // mutator, the caller identifies the bounded keys it can change, so no
    // carrier-wide registry/replay clone or diff is required on COW/exec.
    let mut replay = replay_mappings().lock();
    let mut registry = alias_registry().lock();
    let (alias_keys, replay_ipas) = affected(&replay, &registry);
    let alias_keys = alias_keys
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>();
    let replay_ipas = replay_ipas
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>();
    let alias_before = alias_keys
        .iter()
        .map(|&(start, ipa, scope)| ((start, ipa, scope), registry.find_by_key(start, ipa, scope)))
        .collect::<std::collections::BTreeMap<_, _>>();
    let replay_before = replay_ipas
        .iter()
        .map(|&ipa| (ipa, replay_rows_for_ipa(&replay, ipa)))
        .collect::<std::collections::BTreeMap<_, _>>();
    let result = mutate(&mut replay, &mut registry);
    let mut versions = alias_version_registry().lock();
    for &(start, ipa, scope) in &alias_keys {
        let key = (start, ipa, scope);
        let after = registry.find_by_key(start, ipa, scope);
        if alias_before.get(&key).copied().flatten() == after {
            continue;
        }
        bump_version_epoch(&mut versions.alias_epochs, key).unwrap_or_else(|| {
            carrick_fatal!(
                "hvpatch::host_alias",
                "external alias mutation epoch exhausted"
            );
        });
        for id in reset_alias_chain(&mut versions.aliases, key, after) {
            versions.alias_version_owner.remove(&id);
        }
    }
    for physical_ipa in replay_ipas {
        let after = replay_rows_for_ipa(&replay, physical_ipa);
        if replay_before.get(&physical_ipa) == Some(&after) {
            continue;
        }
        bump_version_epoch(&mut versions.replay_epochs, physical_ipa).unwrap_or_else(|| {
            carrick_fatal!(
                "hvpatch::host_alias",
                "external replay mutation epoch exhausted"
            );
        });
        for id in reset_replay_chain(&mut versions.replays, physical_ipa, after) {
            versions.replay_version_owner.remove(&id);
        }
    }
    result
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn retired_projection_mutation_keys(
    registry: &AliasRegistry,
    retired: &[RetiredStage2Projection],
    exact_aliases: &[AliasBacking],
) -> (Vec<AliasVersionKey>, Vec<u64>) {
    let mut alias_keys = exact_aliases
        .iter()
        .map(alias_version_key)
        .collect::<Vec<_>>();
    let mut replay_ipas = exact_aliases
        .iter()
        .map(|alias| alias.physical_ipa)
        .collect::<Vec<_>>();
    for retired in retired {
        if retired.owner.host_addr == 0
            || (retired.owner.generation == 0
                && is_reusable_global_frame_extent(retired.physical_ipa, retired.physical_length))
        {
            continue;
        }
        replay_ipas.push(retired.physical_ipa);
        alias_keys.extend(
            registry
                .physical_start_rows(retired.physical_ipa)
                .iter()
                .filter(|(_, alias)| {
                    (alias.physical_size as u64 == retired.physical_length)
                        && alias.physical_host_addr == retired.owner.host_addr
                        && alias.owner_generation == retired.owner.generation
                })
                .map(|(_, alias)| alias_version_key(alias)),
        );
    }
    (alias_keys, replay_ipas)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl AliasPublicationReceipt {
    fn commit(
        owner: HvpatchCarrierTaskStateKey,
        aliases: &[AliasBacking],
    ) -> Result<Self, TrapError> {
        let mut replay = replay_mappings().lock();
        let mut registry = alias_registry().lock();
        let mut versions = alias_version_registry().lock();
        // Keyed, not linear-scanned: publishing k aliases used to cost O(k^2)
        // here before it even reached the registry.
        let mut alias_increments = std::collections::BTreeMap::<AliasVersionKey, u64>::new();
        let mut replay_increments = std::collections::BTreeMap::<u64, u64>::new();
        for alias in aliases {
            let count = alias_increments
                .entry(alias_version_key(alias))
                .or_insert(0);
            *count = count.checked_add(1).unwrap_or(u64::MAX);
            let count = replay_increments.entry(alias.physical_ipa).or_insert(0);
            *count = count.checked_add(1).unwrap_or(u64::MAX);
        }
        let alias_exhausted = alias_increments.iter().any(|(key, count)| {
            let current = versions.alias_epochs.get(key).copied().unwrap_or(0);
            current.checked_add(*count).is_none()
        });
        let replay_exhausted = replay_increments.iter().any(|(ipa, count)| {
            let current = versions.replay_epochs.get(ipa).copied().unwrap_or(0);
            current.checked_add(*count).is_none()
        });
        if aliases.len() > u32::MAX as usize || alias_exhausted || replay_exhausted {
            return Err(TrapError::Hypervisor(
                "alias publication version identity exhausted".to_owned(),
            ));
        }
        let mut receipt = Self::default();
        for (ordinal, alias) in aliases.iter().enumerate() {
            let ordinal = u32::try_from(ordinal).map_err(|_| {
                TrapError::Hypervisor("alias publication ordinal exhausted".to_owned())
            })?;
            let id = AliasPublicationVersionId { owner, ordinal };
            let alias_key = alias_version_key(alias);
            let alias_epoch = bump_version_epoch(&mut versions.alias_epochs, alias_key)
                .ok_or_else(|| TrapError::Hypervisor("alias version epoch exhausted".to_owned()))?;
            let replay_epoch = bump_version_epoch(&mut versions.replay_epochs, alias.physical_ipa)
                .ok_or_else(|| {
                    TrapError::Hypervisor("replay version epoch exhausted".to_owned())
                })?;
            let alias_base = registry.find_by_key(alias.start, alias.ipa, alias.ownership_scope);
            let replay_base = replay_rows_for_ipa(&replay, alias.physical_ipa);
            versions
                .aliases
                .entry(alias_key)
                .or_insert_with(|| AliasVersionChain {
                    base: alias_base,
                    versions: Vec::new(),
                })
                .versions
                .push(OwnedAliasVersion {
                    id,
                    value: *alias,
                    epoch: alias_epoch,
                });
            versions.alias_version_owner.insert(id, alias_key);
            versions
                .replays
                .entry(alias.physical_ipa)
                .or_insert_with(|| ReplayVersionChain {
                    base: replay_base,
                    versions: Vec::new(),
                })
                .versions
                .push(OwnedReplayVersion {
                    id,
                    value: replay_mapping_key(*alias),
                    epoch: replay_epoch,
                });
            versions.replay_version_owner.insert(id, alias.physical_ipa);
            for row in replay_rows_for_ipa(&replay, alias.physical_ipa) {
                replay.remove(&row);
            }
            replay.insert(replay_mapping_key(*alias));
            let _ = registry.upsert_by_key(*alias);
            receipt.versions.push(id);
        }
        Ok(receipt)
    }

    fn retire_exact(self) {
        let mut replay = replay_mappings().lock();
        let mut registry = alias_registry().lock();
        let mut versions = alias_version_registry().lock();
        // Simulate exact-key mutations while walking the version chains, then
        // rebuild each affected scope once. Mutating the scope Vec for every
        // receipt row made retiring k aliases O(k * rows-in-mm).
        let mut pending_alias_values =
            std::collections::BTreeMap::<AliasVersionKey, Option<AliasBacking>>::new();
        let mut alias_mutations = Vec::<(AliasVersionKey, Option<AliasBacking>)>::new();
        for id in self.versions.into_iter().rev() {
            if let Some(chain_key) = versions.alias_version_owner.remove(&id) {
                let (start, ipa, scope) = chain_key;
                let chain = versions
                    .aliases
                    .get_mut(&chain_key)
                    .unwrap_or_else(|| {
                        carrick_fatal!(
                            "hvpatch::host_alias",
                            "missing alias version chain for owned receipt version: key={chain_key:?} id={id:?}"
                        );
                    });
                let version_index = chain
                    .versions
                    .iter()
                    .position(|version| version.id == id)
                    .unwrap_or_else(|| {
                        carrick_fatal!(
                            "hvpatch::host_alias",
                            "missing alias receipt version in chain: key={chain_key:?} id={id:?}"
                        );
                    });
                let was_top = version_index + 1 == chain.versions.len();
                let removed = chain.versions.remove(version_index);
                let base = chain.base;
                let previous = chain.versions.last().map(|version| version.value);
                let empty = chain.versions.is_empty();
                let current_epoch = versions.alias_epochs.get(&chain_key).copied();
                let current_value = pending_alias_values
                    .get(&chain_key)
                    .copied()
                    .unwrap_or_else(|| registry.find_by_key(start, ipa, scope));
                if was_top
                    && current_epoch == Some(removed.epoch)
                    && current_value == Some(removed.value)
                {
                    let mm_root_slot = match scope {
                        AliasOwnershipScope::MmRootSlot { base, size } => Some((base, size)),
                        AliasOwnershipScope::Global | AliasOwnershipScope::ContainerRoot(_) => None,
                    };
                    record_cow_alias_lifecycle(
                        CowDiagnosticLifecycleKind::AliasRemoved,
                        CowDiagnosticLifecycleSite::ReceiptRetirement,
                        None,
                        None,
                        mm_root_slot,
                        removed.value,
                    );
                    let replacement = previous.or(base);
                    pending_alias_values.insert(chain_key, replacement);
                    alias_mutations.push((chain_key, replacement));
                    if let Some(previous) = replacement {
                        record_cow_alias_lifecycle(
                            CowDiagnosticLifecycleKind::AliasPublished,
                            CowDiagnosticLifecycleSite::ReceiptRetirement,
                            None,
                            None,
                            mm_root_slot,
                            previous,
                        );
                    }
                    bump_version_epoch(&mut versions.alias_epochs, chain_key)
                        .unwrap_or_else(|| {
                            carrick_fatal!(
                                "hvpatch::host_alias",
                                "alias version epoch exhausted on receipt retirement: key={chain_key:?}"
                            );
                        });
                }
                if empty {
                    versions.aliases.remove(&chain_key);
                }
            }
            if let Some(physical_ipa) = versions.replay_version_owner.remove(&id) {
                let chain = versions
                    .replays
                    .get_mut(&physical_ipa)
                    .unwrap_or_else(|| {
                        carrick_fatal!(
                            "hvpatch::host_alias",
                            "missing replay version chain for owned receipt version: ipa={physical_ipa:#x} id={id:?}"
                        );
                    });
                let version_index = chain
                    .versions
                    .iter()
                    .position(|version| version.id == id)
                    .unwrap_or_else(|| {
                        carrick_fatal!(
                            "hvpatch::host_alias",
                            "missing replay receipt version in chain: ipa={physical_ipa:#x} id={id:?}"
                        );
                    });
                let was_top = version_index + 1 == chain.versions.len();
                let removed = chain.versions.remove(version_index);
                let base = chain.base.clone();
                let previous = chain.versions.last().map(|version| version.value);
                let empty = chain.versions.is_empty();
                let current_epoch = versions.replay_epochs.get(&physical_ipa).copied();
                let current = replay_rows_for_ipa(&replay, physical_ipa);
                if was_top && current_epoch == Some(removed.epoch) && current == vec![removed.value]
                {
                    for row in current {
                        replay.remove(&row);
                    }
                    if let Some(previous) = previous {
                        replay.insert(previous);
                    } else {
                        replay.extend(base);
                    }
                    bump_version_epoch(&mut versions.replay_epochs, physical_ipa)
                        .unwrap_or_else(|| {
                            carrick_fatal!(
                                "hvpatch::host_alias",
                                "replay version epoch exhausted on receipt retirement: ipa={physical_ipa:#x}"
                            );
                        });
                }
                if empty {
                    versions.replays.remove(&physical_ipa);
                }
            }
        }
        // Multiple receipt rows may version the same key. Keep only its final
        // simulated value, ordered by that key's last mutation so restored
        // rows receive the same relative insertion order as the old loop.
        let mut final_alias_mutations =
            std::collections::BTreeMap::<AliasVersionKey, (usize, Option<AliasBacking>)>::new();
        for (order, (key, replacement)) in alias_mutations.into_iter().enumerate() {
            final_alias_mutations.insert(key, (order, replacement));
        }
        let mut final_alias_mutations = final_alias_mutations
            .into_iter()
            .map(|(key, (order, replacement))| (order, key, replacement))
            .collect::<Vec<_>>();
        final_alias_mutations.sort_by_key(|(order, _, _)| *order);
        let final_alias_mutations = final_alias_mutations
            .into_iter()
            .map(|(_, key, replacement)| (key, replacement))
            .collect::<Vec<_>>();
        registry.replace_exact_keys_in_batch(&final_alias_mutations);
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub struct HvpatchCarrierTaskStateDirectory {
    instance: std::num::NonZeroU64,
    child_token_verifier: std::sync::Arc<carrick_hal::HvpatchChildTokenVerifier>,
    next: std::sync::atomic::AtomicU64,
    inner: parking_lot::Mutex<HvpatchCarrierTaskDirectoryInner>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Default)]
struct HvpatchCarrierTaskDirectoryInner {
    states: std::collections::BTreeMap<HvpatchCarrierTaskStateKey, HvpatchCarrierTaskRow>,
    carrier_mms: std::collections::BTreeMap<
        HvpatchMmAuthorityKey,
        std::sync::Weak<HvpatchCarrierMmAuthority>,
    >,
    task_mms:
        std::collections::BTreeMap<HvpatchMmAuthorityKey, std::sync::Weak<HvpatchTaskMmAuthority>>,
}

#[cfg(test)]
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl Default for HvpatchCarrierTaskStateDirectory {
    fn default() -> Self {
        static NEXT_DIRECTORY_INSTANCE: std::sync::atomic::AtomicU64 =
            std::sync::atomic::AtomicU64::new(1);
        let instance = NEXT_DIRECTORY_INSTANCE
            .fetch_update(
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Acquire,
                |current| current.checked_add(1),
            )
            .unwrap_or_else(|_| {
                carrick_fatal!(
                    "hvpatch::task_directory",
                    "HVPatch carrier directory identity exhausted"
                );
            });
        let instance = std::num::NonZeroU64::new(instance).unwrap_or_else(|| {
            carrick_fatal!(
                "hvpatch::task_directory",
                "zero HVPatch carrier directory identity"
            );
        });
        let (_, verifier) = carrick_hal::HvpatchChildTokenIssuer::new_pair();
        Self::new(instance, verifier)
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl HvpatchCarrierTaskStateDirectory {
    pub fn new(
        instance: std::num::NonZeroU64,
        child_token_verifier: std::sync::Arc<carrick_hal::HvpatchChildTokenVerifier>,
    ) -> Self {
        Self {
            instance,
            child_token_verifier,
            next: std::sync::atomic::AtomicU64::new(1),
            inner: parking_lot::Mutex::new(HvpatchCarrierTaskDirectoryInner::default()),
        }
    }

    pub(crate) fn rebind_exec_task_mm(
        &self,
        key: HvpatchCarrierTaskStateKey,
        new_mm_key: HvpatchMmAuthorityKey,
        task_mm: &std::sync::Arc<HvpatchTaskMmAuthority>,
        stage2_record_identities: Vec<CarrierStage2RecordIdentity>,
        custody: &std::sync::Arc<CarrierVmCustody>,
    ) -> Result<(), TrapError> {
        if key.directory_instance != self.instance {
            return Err(TrapError::Hypervisor(
                "cross-directory HVPatch carrier token rejected".to_owned(),
            ));
        }
        let frames = task_mm
            .inventory
            .lock()
            .shared_frame_registry()
            .ok_or_else(|| {
                TrapError::Hypervisor(
                    "exec replacement has no shared HVPatch frame registry".to_owned(),
                )
            })?;
        let mut inner = self.inner.lock();
        if inner
            .task_mms
            .get(&new_mm_key)
            .and_then(std::sync::Weak::upgrade)
            .is_some()
        {
            return Err(TrapError::Hypervisor(
                "duplicate HVPatch MM authority key for exec replacement".to_owned(),
            ));
        }
        let existing_carrier_mm = inner.states.get(&key).and_then(|row| row._mm.clone());
        let new_carrier_mm = match existing_carrier_mm.as_deref() {
            Some(HvpatchCarrierMmAuthority::Live { _vm, .. }) => {
                Some(std::sync::Arc::new(HvpatchCarrierMmAuthority::Live {
                    stage2_logical_leases: carrier_stage2_logical_leases(
                        custody,
                        &stage2_record_identities,
                    ),
                    custody: std::sync::Arc::downgrade(custody),
                    frames,
                    _vm: _vm.clone(),
                }))
            }
            #[cfg(test)]
            Some(HvpatchCarrierMmAuthority::Test { order }) => {
                Some(std::sync::Arc::new(HvpatchCarrierMmAuthority::Test {
                    order: std::sync::Arc::clone(order),
                }))
            }
            #[cfg(test)]
            Some(HvpatchCarrierMmAuthority::LeaseTest { .. }) => {
                return Err(TrapError::Hypervisor(
                    "test carrier lease authority cannot be exec-rebound".to_owned(),
                ));
            }
            None => None,
        };
        if let Some(carrier_mm) = new_carrier_mm {
            inner
                .carrier_mms
                .insert(new_mm_key, std::sync::Arc::downgrade(&carrier_mm));
            if let Some(row) = inner.states.get_mut(&key) {
                row._mm = Some(carrier_mm);
            }
        }
        inner
            .task_mms
            .insert(new_mm_key, std::sync::Arc::downgrade(task_mm));
        task_mm.record_holder(HvpatchTaskMmHolder::CarrierDirectory);
        Ok(())
    }

    /// The live CLONE_VM/vfork sharer authority interned for `mm` on the
    /// owner's `mm_root_slot`, if one is still registered. Sharers publish
    /// under `{task_serial: 0, mm_root_slot, shared_kernel_mm: Some(mm)}`
    /// (`shared_mm_projection`), distinct from the owner's
    /// `{0, mm_root_slot, None}` row.
    fn clone_vm_sharer_authority(
        &self,
        mm_root_slot: Option<(u64, u64)>,
        mm: std::num::NonZeroU64,
    ) -> Option<std::sync::Arc<HvpatchTaskMmAuthority>> {
        self.inner
            .lock()
            .task_mms
            .get(&HvpatchMmAuthorityKey {
                task_serial: 0,
                mm_root_slot,
                shared_kernel_mm: Some(mm.get()),
            })
            .and_then(std::sync::Weak::upgrade)
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) struct HvpatchTaskRegistration {
    directory: std::sync::Arc<HvpatchCarrierTaskStateDirectory>,
    key: HvpatchCarrierTaskStateKey,
    expected_identity: HvpatchCarrierTaskIdentity,
    foreign_mm_registration: Option<CarrierForeignMmRegistration>,
    task_mm: Option<std::sync::Arc<HvpatchTaskMmAuthority>>,
    cow_authority: Option<std::sync::Arc<dyn carrick_hal::FrameCowAuthority>>,
    cow_identity: Option<carrick_hal::FrameCowIdentity>,
    cow_authority_identity: Option<std::num::NonZeroU64>,
    child_token_verifier: std::sync::Arc<carrick_hal::HvpatchChildTokenVerifier>,
    #[cfg(not(test))]
    custody: std::sync::Arc<CarrierVmCustody>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl HvpatchTaskRegistration {
    fn register_foreign_mm(&mut self, task: &HvfTaskState) -> Result<(), TrapError> {
        if self.foreign_mm_registration.is_some() {
            return Err(TrapError::Hypervisor(
                "duplicate copied-child foreign-MM registration".to_owned(),
            ));
        }
        let task_mm = self
            .task_mm
            .as_ref()
            .ok_or_else(|| TrapError::Hypervisor("missing HVPatch task MM".to_owned()))?;
        let Some(transport) = task_mm.foreign_mm_transport.as_ref() else {
            return Ok(());
        };
        let identity = self.cow_identity.ok_or_else(|| {
            TrapError::Hypervisor("HVPatch task lacks live COW identity".to_owned())
        })?;
        let (stage1_root, _) = task.mm_root_slot.ok_or_else(|| {
            TrapError::Hypervisor("copied child lacks exact stage-1 root slot".to_owned())
        })?;
        let mm = std::num::NonZeroU64::new(identity.mm)
            .map(carrick_hal::ForeignMmId::from_kernel_allocation)
            .ok_or_else(|| TrapError::Hypervisor("copied child has zero MM identity".to_owned()))?;
        let asid = std::num::NonZeroU16::new(identity.asid)
            .map(carrick_hal::ForeignAsid::from_kernel_allocation)
            .ok_or_else(|| TrapError::Hypervisor("copied child has zero ASID".to_owned()))?;
        self.foreign_mm_registration = Some(transport.register_owned_identity(
            mm,
            CarrierForeignMmBinding {
                asid,
                stage1_root: carrick_guest_mem::Gpa(stage1_root),
            },
            &task.mm_access,
        ));
        Ok(())
    }

    fn unregister_foreign_mm(&mut self) {
        drop(self.foreign_mm_registration.take());
    }

    fn runtime_task_state(
        &self,
        page_tables: carrick_aarch64::Stage1Authority,
        protections: std::sync::Arc<MemoryProtections>,
    ) -> Result<HvfTaskState, TrapError> {
        let task_mm = self
            .task_mm
            .as_ref()
            .ok_or_else(|| TrapError::Hypervisor("missing HVPatch task MM".to_owned()))?;
        task_mm.record_holder(HvpatchTaskMmHolder::LiveExecutor);
        let inventory = task_mm.inventory.lock();
        let shared_process_mm = matches!(
            *inventory,
            HvpatchTaskInventoryAuthority::SharedProcess { .. }
        );
        let ledger = inventory
            .shared_runtime_ledger()
            .ok_or_else(|| TrapError::Hypervisor("inactive HVPatch task inventory".to_owned()))?;
        drop(inventory);
        let cow_authority = self.cow_authority.clone().ok_or_else(|| {
            TrapError::Hypervisor("HVPatch task lacks live COW authority".to_owned())
        })?;
        let cow_identity = self.cow_identity.ok_or_else(|| {
            TrapError::Hypervisor("HVPatch task lacks live COW identity".to_owned())
        })?;
        let cow_armed = task_mm.cow_armed.as_ref().cloned().ok_or_else(|| {
            TrapError::Hypervisor("HVPatch task lacks COW armed state".to_owned())
        })?;
        let cow_deferred_publications = task_mm
            .cow_deferred_publications
            .as_ref()
            .cloned()
            .ok_or_else(|| {
                TrapError::Hypervisor("HVPatch task lacks COW publication state".to_owned())
            })?;
        let mm_access = {
            let mut slot = task_mm.mm_access.lock();
            std::sync::Arc::clone(slot.get_or_insert_with(|| {
                let access = MmAccessState::new(
                    page_tables.clone(),
                    std::sync::Arc::clone(&protections),
                    std::sync::Arc::clone(&ledger),
                    std::sync::Arc::clone(&cow_armed),
                    std::sync::Arc::clone(&cow_deferred_publications),
                );
                if let Some(authority) = task_mm.mm_root_stage2.lock().take() {
                    access
                        .install_prepared_mm_root_stage2_authority(authority)
                        .unwrap_or_else(|error| {
                            carrick_fatal!(
                                "hvpatch::mm_authority",
                                "install published task-only root authority failed: {error}"
                            );
                        });
                }
                for mapping in &task_mm.mappings {
                    if let Some(owner) = &mapping.structural_owner {
                        access
                            .install_structural_mapping_authority(
                                task_mm.mm_root_slot,
                                std::sync::Arc::clone(owner),
                            )
                            .unwrap_or_else(|error| {
                                carrick_fatal!(
                                    "hvpatch::mm_authority",
                                    "install task-only structural MM authority failed: slot={:?} error={error}",
                                    task_mm.mm_root_slot
                                );
                            });
                    }
                }
                access
            }))
        };
        mm_access.bind_page_tables_authority(page_tables.clone());
        mm_access.bind_cow_runtime(MmCowRuntimeBinding {
            authority: std::sync::Arc::clone(&cow_authority),
            identity: cow_identity,
            mm_root_slot: task_mm.mm_root_slot,
            container_root: task_mm.container_root,
            persistent_vm_lifecycle: true,
        });
        Ok(HvfTaskState {
            #[cfg(not(test))]
            custody: std::sync::Arc::clone(&self.custody),
            mappings: task_mm
                .mappings
                .iter()
                .map(HvpatchTaskMappingState::unowned_runtime_region)
                .collect(),
            mm_root_slot: task_mm.mm_root_slot,
            container_root: task_mm.container_root,
            pending_exec_mm_root_slot: None,
            pending_exec_asid: None,
            pending_exec_predecessor_identity: None,
            pending_exec_stage2_cleanup: None,
            shared_process_mm,
            mm_access,
            last_exit_class: 0,
            last_fault_esr: 0,
            is_forked_child: false,
            forked_no_exec: false,
            last_syscall_nr: None,
            last_syscall_orig_x0: 0,
            live_vcpu: crate::vcpu_kick::LiveVcpuSlot::new(),
            persistent_vm_lifecycle: true,
            cow_authority: Some(cow_authority),
            cow_identity: Some(cow_identity),
            pending_fork_frame_receipts: std::mem::take(
                &mut *task_mm.pending_publication_receipts.lock(),
            ),
            pending_process_aliases: Vec::new(),
            fail_next_begin_exec_inventory: false,
            cow_rollback_scratch: None,
            registration: None,
        })
    }

    fn apply_inventory(
        &self,
        apply: impl FnOnce(
            carrick_hal::FrameInventoryCommit<()>,
        ) -> Result<carrick_hal::FrameInventoryApplyReceipt, TrapError>,
    ) -> Result<(), TrapError> {
        self.task_mm
            .as_ref()
            .ok_or_else(|| TrapError::Hypervisor("missing HVPatch task MM".to_owned()))?
            .apply_inventory(apply)
    }

    pub(crate) fn shares_another_process_inventory(&self) -> bool {
        self.task_mm
            .as_ref()
            .is_some_and(|task_mm| task_mm.shares_another_process_inventory())
    }

    pub(crate) fn prepare_inventory_retirement(
        &self,
        commit: carrick_hal::FrameInventoryCommit<()>,
    ) -> Result<(), TrapError> {
        self.task_mm
            .as_ref()
            .ok_or_else(|| TrapError::Hypervisor("missing HVPatch task MM".to_owned()))?
            .prepare_retirement(commit)
    }

    pub(crate) fn apply_inventory_retirement(
        &self,
        apply: impl FnOnce(
            carrick_hal::FrameInventoryCommit<()>,
        ) -> Result<carrick_hal::FrameInventoryRetirementReceipt, TrapError>,
    ) -> Result<(), TrapError> {
        self.task_mm
            .as_ref()
            .ok_or_else(|| TrapError::Hypervisor("missing HVPatch task MM".to_owned()))?
            .apply_retirement(apply)
    }

    fn bind_child_kernel(&mut self, binding: HvpatchChildKernelBinding) -> Result<(), TrapError> {
        let binding = self
            .child_token_verifier
            .verify_and_open(binding)
            .ok_or_else(|| {
                TrapError::Hypervisor(
                    "child Kernel token issuer does not match carrier verifier".to_owned(),
                )
            })?;
        let cow_identity = binding.cow_identity();
        if binding.task_serial() != self.key.task_serial
            || binding.thread_serial() != self.key.thread_serial
            || binding.execution_generation() != self.key.execution_generation
            || cow_identity.linux_pid != self.expected_identity.linux_pid
            || cow_identity.linux_tid != self.expected_identity.linux_tid
            || cow_identity.asid != self.expected_identity.asid
            || self.cow_authority.is_some()
            || self.cow_identity.is_some()
            || self.cow_authority_identity.is_some()
        {
            return Err(TrapError::Hypervisor(
                "duplicate or mismatched exact child Kernel binding".to_owned(),
            ));
        }
        let mm = std::num::NonZeroU64::new(cow_identity.mm).ok_or_else(|| {
            TrapError::Hypervisor("child Kernel token contains zero MM".to_owned())
        })?;
        self.task_mm
            .as_ref()
            .ok_or_else(|| TrapError::Hypervisor("missing HVPatch task MM".to_owned()))?
            .bind_kernel_mm(mm)?;
        self.cow_authority_identity = Some(binding.authority_identity());
        self.cow_identity = Some(cow_identity);
        self.cow_authority = Some(binding.into_cow_authority());
        Ok(())
    }

    fn bind_kernel_mm(&mut self, mm: std::num::NonZeroU64) -> Result<(), TrapError> {
        self.task_mm
            .as_ref()
            .ok_or_else(|| TrapError::Hypervisor("missing HVPatch task MM".to_owned()))?
            .bind_kernel_mm(mm)
    }

    fn rebind_exec_authority(
        &mut self,
        new_task_mm: std::sync::Arc<HvpatchTaskMmAuthority>,
        replacement_mm_root_slot: (u64, u64),
        stage2_record_identities: Vec<CarrierStage2RecordIdentity>,
        custody: &std::sync::Arc<CarrierVmCustody>,
        retain_shared_predecessor_authority: bool,
    ) -> Result<(), TrapError> {
        let new_mm_key = HvpatchMmAuthorityKey {
            task_serial: 0,
            mm_root_slot: Some(replacement_mm_root_slot),
            shared_kernel_mm: None,
        };
        self.directory.rebind_exec_task_mm(
            self.key,
            new_mm_key,
            &new_task_mm,
            stage2_record_identities,
            custody,
        )?;
        if let Some(old_task_mm) = self.task_mm.take() {
            old_task_mm.record_holder(HvpatchTaskMmHolder::ExecRebind);
            if retain_shared_predecessor_authority && old_task_mm.owns_active_inventory() {
                // The Kernel pinned `RetainOldMm`: a CLONE_VM/vfork process
                // keeps this mm, and its exit is where the exact retirement
                // will be issued. Move the `Active` receipt to that sharer now
                // (`vforkexecthread`). Whether the vfork-suspended leader's
                // registration has already dropped its Arc must not matter:
                // before this, a sole holder silently discarded the receipt
                // and a surviving sibling holder aborted the carrier at its
                // own cleanup (`holder=registration-cleanup`).
                let mm = (*old_task_mm.kernel_mm.lock()).ok_or_else(|| {
                    TrapError::Hypervisor(
                        "HVPatch exec retains a predecessor with no Kernel binding".to_owned(),
                    )
                })?;
                match self
                    .directory
                    .clone_vm_sharer_authority(old_task_mm.mm_root_slot, mm)
                {
                    Some(sharer) => old_task_mm.hand_off_inventory_to_sharer(&sharer)?,
                    None => {
                        // The sharer the Kernel counted at reservation time
                        // exited during the sibling drain and its registration
                        // is gone. Its exit was not the final mm edge (this
                        // task's lease still named the mm), so nobody retires
                        // these rows: say so rather than aborting a legitimate
                        // exec.
                        tracing::error!(
                            target: "carrick::hvpatch",
                            mm = mm.get(),
                            mm_root_slot = ?old_task_mm.mm_root_slot,
                            "exec retained a shared predecessor mm whose CLONE_VM sharer is \
                             gone; its frame-inventory rows are abandoned unretired"
                        );
                        old_task_mm.retire_exec_predecessor();
                    }
                }
            } else if retain_shared_predecessor_authority {
                // The predecessor is itself a projection of another process's
                // inventory (a vfork child exec'ing). That process owns the
                // retirement; only a LAST holder may retire the projection,
                // and `Arc::into_inner` answers that atomically.
                if let Some(sole) = std::sync::Arc::into_inner(old_task_mm) {
                    sole.retire_exec_predecessor();
                }
            } else {
                old_task_mm.retire_exec_predecessor();
            }
        }
        self.task_mm = Some(new_task_mm);
        Ok(())
    }

    pub(crate) fn retire_dormant_authority(&mut self) {
        if let Some(task_mm) = &self.task_mm {
            task_mm.record_holder(HvpatchTaskMmHolder::DormantRetire);
            task_mm.retire_exec_predecessor();
        }
    }

    fn activate(&self) -> Result<(), TrapError> {
        if self.cow_authority.is_none() || self.cow_identity.is_none() {
            return Err(TrapError::Hypervisor(
                "HVPatch child activation requires exact tid/kicker/COW authority".to_owned(),
            ));
        }
        self.task_mm
            .as_ref()
            .ok_or_else(|| TrapError::Hypervisor("missing HVPatch task MM".to_owned()))?
            .activate()
    }

    pub(crate) fn cleanup(mut self) -> Result<(), TrapError> {
        self.unregister_foreign_mm();
        // Removing the carrier row drops this binding's carrier-MM reference.
        // If it is the final MM binding, every stage-2 lease unmaps here, before
        // the final task-MM Arc below releases any host mapping owner.
        self.directory.retire(self.key)?;
        if let Some(task_mm) = self.task_mm.take() {
            task_mm.record_holder(HvpatchTaskMmHolder::RegistrationCleanup);
            // NOTE (history, re-verified 2026-09-01): this drop is where the
            // "published HVPatch inventory dropped before exact retirement"
            // abort fired for `execthreads` and for a `clone(CLONE_VM|SIGCHLD)`
            // child exiting under a live parent. The root cause was NOT here:
            // `reserve_exec_inner` retired the predecessor mm at RESERVATION
            // time, so an exec owner suspended in the sibling drain resumed
            // into a `Retiring` mm (fixed by preparing that retirement inside
            // `ExecMmReservation::commit`). Retiring the inventory from this
            // drop instead was measured to HANG 2 runs in 3 and is not the fix.
            //
            // The register-time MM key still splits an mm's owner
            // ({slot, None}) from its CLONE_VM/vfork sharer ({slot, Some(mm)}),
            // so a sharer registers a second carrier MM authority over the
            // same stage-2. That second authority is INERT by construction:
            // the `SharedProcess` arm mints it with no stage-2 leases (its
            // drop retires nothing) and a `SharedProcess` inventory rolls back
            // as `Ok(())`. Measured at HEAD: 1,800 CLONE_VM sharer lifecycles
            // (owner verifying a 64 MiB heap after, and concurrently with,
            // every sharer exit) plus the callee-saved-register check, zero
            // faults. A slot-only key that dedupes the sharer onto the owner
            // was tried twice and showed no measurable effect (its gate
            // destabilization was the stale kick-handle defect, see
            // `HvfTaskState::live_vcpu`); collapse the key only with a red
            // reproducer in hand.
            drop(task_mm);
        }
        Ok(())
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl Drop for HvpatchTaskRegistration {
    fn drop(&mut self) {
        if let Some(task_mm) = &self.task_mm {
            task_mm.record_holder(HvpatchTaskMmHolder::RegistrationDrop);
        }
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) struct HvpatchPreparedCarrierTaskState {
    identity: HvpatchCarrierTaskIdentity,
    state: Option<HvpatchCarrierTaskState>,
    task: Option<HvpatchPreparedTaskAuthority>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl HvpatchPreparedCarrierTaskState {
    fn new(
        identity: HvpatchCarrierTaskIdentity,
        state: HvpatchCarrierTaskState,
        task: HvpatchPreparedTaskAuthority,
    ) -> Self {
        Self {
            identity,
            state: Some(state),
            task: Some(task),
        }
    }

    pub(crate) fn sibling(
        identity: HvpatchCarrierTaskIdentity,
        spec: ThreadSpec,
    ) -> Result<Self, TrapError> {
        Self::shared_mm_projection(identity, None, spec)
    }

    pub(crate) fn shared_process(
        identity: HvpatchCarrierTaskIdentity,
        shared_kernel_mm: u64,
        spec: ThreadSpec,
    ) -> Result<Self, TrapError> {
        if shared_kernel_mm == 0 {
            return Err(TrapError::Hypervisor(
                "shared-process HVPatch MM identity is invalid".to_owned(),
            ));
        }
        Self::shared_mm_projection(identity, Some(shared_kernel_mm), spec)
    }

    fn shared_mm_projection(
        identity: HvpatchCarrierTaskIdentity,
        shared_kernel_mm: Option<u64>,
        spec: ThreadSpec,
    ) -> Result<Self, TrapError> {
        if !spec.persistent_vm_lifecycle {
            return Err(TrapError::Hypervisor(
                "task-only shared-MM projection requires persistent HVPatch VM".to_owned(),
            ));
        }
        let ThreadSpec {
            vm,
            mappings,
            mm_access,
            carrier_foreign_mm_transport,
            mailbox_slots: _,
            syscall_transport: _,
            persistent_vm_lifecycle: _,
            mm_root_slot,
            container_root,
            cow_authority: _,
            cow_identity: _,
        } = spec;
        let frame_inventory = mm_access.frame_inventory.shared_ledger();
        let cow_armed = std::sync::Arc::clone(&mm_access.cow_armed);
        let cow_deferred_publications = std::sync::Arc::clone(&mm_access.cow_deferred_publications);
        let mappings = mappings
            .into_iter()
            .map(ThreadMappingDesc::into_shared_mm_task_mapping)
            .collect();
        Ok(Self::new(
            identity,
            if shared_kernel_mm.is_some() {
                HvpatchCarrierTaskState::SharedProcess { vm }
            } else {
                HvpatchCarrierTaskState::Sibling { vm }
            },
            HvpatchPreparedTaskAuthority {
                custody: Some(std::sync::Arc::clone(&carrier_foreign_mm_transport.custody)),
                // The existing exact-MM owner already registered this shared
                // state. A CLONE_VM edge must not own or retire that row.
                foreign_mm_transport: None,
                mappings,
                mm_root_slot,
                container_root,
                shared_kernel_mm,
                inventory: if shared_kernel_mm.is_some() {
                    HvpatchTaskInventoryAuthority::SharedProcess {
                        ledger: frame_inventory,
                    }
                } else {
                    HvpatchTaskInventoryAuthority::SiblingShared {
                        ledger: frame_inventory,
                    }
                },
                cow_armed: Some(cow_armed),
                cow_deferred_publications: Some(cow_deferred_publications),
                inherited_mm_access: Some(mm_access),
                ..HvpatchPreparedTaskAuthority::default()
            },
        ))
    }

    pub(crate) fn process(
        identity: HvpatchCarrierTaskIdentity,
        spec: ProcessSpec,
    ) -> Result<Self, TrapError> {
        if !spec.persistent_vm_lifecycle {
            return Err(TrapError::Hypervisor(
                "task-only process requires persistent HVPatch VM".to_owned(),
            ));
        }
        let (state, task) = HvfVmState::prepare_task_only_process_spec(spec)?;
        Ok(Self::new(identity, state, task))
    }

    pub(crate) fn commit(
        mut self,
        directory: std::sync::Arc<HvpatchCarrierTaskStateDirectory>,
    ) -> Result<HvpatchTaskOnlyBackendState, TrapError> {
        let state = self.state.take().unwrap_or_else(|| {
            carrick_fatal!(
                "hvpatch::task_backend_commit",
                "carrier task state missing during prepared carrier commit: identity={:?}",
                self.identity
            );
        });
        let task = self.task.take().unwrap_or_else(|| {
            carrick_fatal!(
                "hvpatch::task_backend_commit",
                "prepared task authority missing during prepared carrier commit: identity={:?}",
                self.identity
            );
        });
        directory.publish(self.identity, state, task)
    }

    pub(crate) fn abort(mut self) -> Result<(), TrapError> {
        if let Some(state) = self.state.take() {
            let task = self.task.take().unwrap_or_else(|| {
                carrick_fatal!(
                    "hvpatch::task_backend_lifecycle",
                    "prepared task authority missing during prepared carrier abort: identity={:?}",
                    self.identity
                );
            });
            abort_prepared_task_and_carrier(task, state)?;
        }
        Ok(())
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl Drop for HvpatchPreparedCarrierTaskState {
    fn drop(&mut self) {
        if let Some(state) = self.state.take() {
            let task = self.task.take().unwrap_or_else(|| {
                carrick_fatal!(
                    "hvpatch::task_backend_lifecycle",
                    "prepared task authority missing during prepared carrier drop: identity={:?}",
                    self.identity
                );
            });
            abort_prepared_task_and_carrier(task, state).unwrap_or_else(|error| {
                carrick_fatal!(
                    "hvpatch::task_backend_lifecycle",
                    "abort deferred HVPatch task/carrier state during drop failed: identity={:?} error={error}",
                    self.identity
                );
            });
        }
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl HvpatchCarrierTaskStateDirectory {
    fn publish(
        self: &std::sync::Arc<Self>,
        identity: HvpatchCarrierTaskIdentity,
        state: HvpatchCarrierTaskState,
        task: HvpatchPreparedTaskAuthority,
    ) -> Result<HvpatchTaskOnlyBackendState, TrapError> {
        self.publish_inner(identity, state, task, 0)
    }

    fn publish_inner(
        self: &std::sync::Arc<Self>,
        identity: HvpatchCarrierTaskIdentity,
        state: HvpatchCarrierTaskState,
        task: HvpatchPreparedTaskAuthority,
        failpoint: u8,
    ) -> Result<HvpatchTaskOnlyBackendState, TrapError> {
        #[cfg(not(test))]
        let custody = match task.custody.as_ref() {
            Some(custody) => std::sync::Arc::clone(custody),
            None => {
                abort_prepared_task_and_carrier(task, state)?;
                return Err(TrapError::Hypervisor(
                    "prepared HVPatch task has no carrier VM custody".to_owned(),
                ));
            }
        };
        if identity.task_serial == 0
            || identity.thread_serial == 0
            || identity.execution_generation == 0
        {
            abort_prepared_task_and_carrier(task, state)?;
            return Err(TrapError::Hypervisor(
                "deferred HVPatch task identity contains zero".to_owned(),
            ));
        }
        if let Err(error) = task.validate_cow_authority_pairing() {
            abort_prepared_task_and_carrier(task, state)?;
            return Err(error);
        }
        let carrier_frames = match &state {
            #[cfg(test)]
            HvpatchCarrierTaskState::Test { .. } => None,
            _ => match task.inventory.shared_frame_registry() {
                Some(frames) => Some(frames),
                None => {
                    abort_prepared_task_and_carrier(task, state)?;
                    return Err(TrapError::Hypervisor(
                        "prepared HVPatch task has no shared frame registry".to_owned(),
                    ));
                }
            },
        };
        let nonce = match self.next.fetch_update(
            std::sync::atomic::Ordering::AcqRel,
            std::sync::atomic::Ordering::Acquire,
            |current| current.checked_add(1),
        ) {
            Ok(nonce) => nonce,
            Err(_) => {
                abort_prepared_task_and_carrier(task, state)?;
                return Err(TrapError::Hypervisor(
                    "carrier task-state key exhausted".to_owned(),
                ));
            }
        };
        let Some(nonce) = std::num::NonZeroU64::new(nonce) else {
            abort_prepared_task_and_carrier(task, state)?;
            return Err(TrapError::Hypervisor(
                "carrier task-state key exhausted".to_owned(),
            ));
        };
        let key = HvpatchCarrierTaskStateKey {
            directory_instance: self.instance,
            task_serial: identity.task_serial,
            thread_serial: identity.thread_serial,
            execution_generation: identity.execution_generation,
            nonce,
        };
        let mut inner = self.inner.lock();
        if inner.states.keys().any(|key| {
            (key.task_serial, key.thread_serial, key.execution_generation)
                == (
                    identity.task_serial,
                    identity.thread_serial,
                    identity.execution_generation,
                )
        }) {
            drop(inner);
            abort_prepared_task_and_carrier(task, state)?;
            return Err(TrapError::Hypervisor(
                "duplicate exact carrier task-state publication".to_owned(),
            ));
        }
        let alias_receipt = match AliasPublicationReceipt::commit(key, &task.pending_aliases) {
            Ok(receipt) => receipt,
            Err(error) => {
                drop(inner);
                abort_prepared_task_and_carrier(task, state)?;
                return Err(error);
            }
        };
        if failpoint == 1 {
            alias_receipt.retire_exact();
            drop(inner);
            abort_prepared_task_and_carrier(task, state)?;
            return Err(TrapError::Hypervisor(
                "injected carrier task-state failure after alias commit".to_owned(),
            ));
        }
        let mm_key = HvpatchMmAuthorityKey {
            // A concrete root slot is the exact MM identity and is shared by
            // every thread binding. Root/no-slot tasks fall back to the task
            // serial so unrelated roots never alias one MM authority.
            task_serial: if task.shared_kernel_mm.is_some() {
                0
            } else {
                task.mm_root_slot.map_or(identity.task_serial, |_| 0)
            },
            mm_root_slot: task.mm_root_slot,
            shared_kernel_mm: task.shared_kernel_mm,
        };
        let process_owner = matches!(
            task.inventory,
            HvpatchTaskInventoryAuthority::ProcessPrepared { .. }
        );
        let existing_carrier_mm = inner
            .carrier_mms
            .get(&mm_key)
            .and_then(std::sync::Weak::upgrade);
        let existing_task_mm = inner
            .task_mms
            .get(&mm_key)
            .and_then(std::sync::Weak::upgrade);
        if process_owner && (existing_carrier_mm.is_some() || existing_task_mm.is_some()) {
            alias_receipt.retire_exact();
            drop(inner);
            abort_prepared_task_and_carrier(task, state)?;
            return Err(TrapError::Hypervisor(
                "duplicate process owner for exact HVPatch MM".to_owned(),
            ));
        }
        if task.cow_authority.is_some() || task.cow_identity.is_some() {
            alias_receipt.retire_exact();
            drop(inner);
            abort_prepared_task_and_carrier(task, state)?;
            return Err(TrapError::Hypervisor(
                "prepared HVPatch child retained parent COW authority".to_owned(),
            ));
        }
        let carrier_custody = task.custody.as_ref().cloned().ok_or_else(|| {
            TrapError::Hypervisor("prepared HVPatch task has no carrier custody".to_owned())
        })?;
        let (carrier_mm, test_rollbacks): (
            Option<std::sync::Arc<HvpatchCarrierMmAuthority>>,
            Option<std::sync::Arc<std::sync::atomic::AtomicUsize>>,
        ) = match state {
            HvpatchCarrierTaskState::Sibling { vm } => (
                existing_carrier_mm.or_else(|| {
                    Some(std::sync::Arc::new(HvpatchCarrierMmAuthority::Live {
                        _vm: vm,
                        stage2_logical_leases: Vec::new(),
                        custody: std::sync::Arc::downgrade(&carrier_custody),
                        frames: std::sync::Arc::clone(
                            carrier_frames.as_ref().unwrap_or_else(|| {
                                carrick_fatal!(
                                    "hvpatch::frame_inventory",
                                    "carrier frame inventory missing when constructing live carrier MM authority for sibling task: identity={:?}",
                                    identity
                                );
                            }),
                        ),
                    }))
                }),
                None,
            ),
            HvpatchCarrierTaskState::SharedProcess { vm } => (
                existing_carrier_mm.or_else(|| {
                    Some(std::sync::Arc::new(HvpatchCarrierMmAuthority::Live {
                        _vm: vm,
                        stage2_logical_leases: Vec::new(),
                        custody: std::sync::Arc::downgrade(&carrier_custody),
                        frames: std::sync::Arc::clone(
                            carrier_frames.as_ref().unwrap_or_else(|| {
                                carrick_fatal!(
                                    "hvpatch::frame_inventory",
                                    "carrier frame inventory missing when constructing live carrier MM authority for shared-process task: identity={:?}",
                                    identity
                                );
                            }),
                        ),
                    }))
                }),
                None,
            ),
            HvpatchCarrierTaskState::Process {
                vm,
                mut stage2_leases,
            } => {
                let owner_hosts =
                    match collect_carrier_stage2_owner_hosts(task.mappings.iter().map(|mapping| {
                        (
                            (mapping.physical_ipa, mapping.physical_size as u64),
                            mapping.physical_host_addr as usize,
                        )
                    })) {
                        Ok(owners) => owners,
                        Err(error) => {
                            abort_prepared_task_and_carrier(
                                task,
                                HvpatchCarrierTaskState::Process { vm, stage2_leases },
                            )?;
                            return Err(error);
                        }
                    };
                let stage2_record_identities = match register_carrier_stage2_leases(
                    &carrier_custody,
                    &mut stage2_leases,
                    &owner_hosts,
                ) {
                    Ok(keys) => keys,
                    Err(error) => {
                        abort_prepared_task_and_carrier(
                            task,
                            HvpatchCarrierTaskState::Process { vm, stage2_leases },
                        )?;
                        return Err(error);
                    }
                };
                (
                    Some(std::sync::Arc::new(HvpatchCarrierMmAuthority::Live {
                        _vm: vm,
                        stage2_logical_leases: carrier_stage2_logical_leases(
                            &carrier_custody,
                            &stage2_record_identities,
                        ),
                        custody: std::sync::Arc::downgrade(&carrier_custody),
                        frames: std::sync::Arc::clone(
                            carrier_frames.as_ref().unwrap_or_else(|| {
                                carrick_fatal!(
                                    "hvpatch::frame_inventory",
                                    "carrier frame inventory missing when constructing live carrier MM authority for process task: identity={:?}",
                                    identity
                                );
                            }),
                        ),
                    })),
                    None,
                )
            }
            #[cfg(test)]
            HvpatchCarrierTaskState::LeaseTest { mut stage2_leases } => {
                let owner_hosts =
                    match collect_carrier_stage2_owner_hosts(task.mappings.iter().map(|mapping| {
                        (
                            (mapping.physical_ipa, mapping.physical_size as u64),
                            mapping.physical_host_addr as usize,
                        )
                    })) {
                        Ok(owners) => owners,
                        Err(error) => {
                            abort_prepared_task_and_carrier(
                                task,
                                HvpatchCarrierTaskState::LeaseTest { stage2_leases },
                            )?;
                            return Err(error);
                        }
                    };
                let stage2_record_identities = match register_carrier_stage2_leases(
                    &carrier_custody,
                    &mut stage2_leases,
                    &owner_hosts,
                ) {
                    Ok(keys) => keys,
                    Err(error) => {
                        abort_prepared_task_and_carrier(
                            task,
                            HvpatchCarrierTaskState::LeaseTest { stage2_leases },
                        )?;
                        return Err(error);
                    }
                };
                (
                    Some(std::sync::Arc::new(HvpatchCarrierMmAuthority::LeaseTest {
                        stage2_lease_keys: stage2_record_identities
                            .iter()
                            .filter_map(|identity| {
                                carrier_custody
                                    .stage2_record_snapshot(identity.record_id)
                                    .map(|snapshot| (snapshot.ipa, snapshot.len as u64))
                            })
                            .collect(),
                        frames: std::sync::Arc::clone(
                            carrier_frames
                                .as_ref()
                                .unwrap_or_else(|| std::process::abort()),
                        ),
                    })),
                    None,
                )
            }
            #[cfg(test)]
            HvpatchCarrierTaskState::Test { rollbacks, order } => (
                existing_carrier_mm.or_else(|| {
                    order
                        .map(|order| std::sync::Arc::new(HvpatchCarrierMmAuthority::Test { order }))
                }),
                Some(rollbacks),
            ),
        };
        #[cfg(not(test))]
        let _ = &test_rollbacks;
        let mut task = task;
        task.pending_aliases.clear();
        let task_mm = if let Some(existing) = existing_task_mm {
            task.abort()?;
            existing.alias_receipts.lock().push(alias_receipt);
            existing
        } else {
            std::sync::Arc::new(HvpatchTaskMmAuthority::from_prepared(task, alias_receipt))
        };
        if inner
            .states
            .insert(
                key,
                HvpatchCarrierTaskRow {
                    _mm: carrier_mm.clone(),
                    #[cfg(test)]
                    rollbacks: test_rollbacks,
                },
            )
            .is_some()
        {
            carrick_fatal!(
                "hvpatch::task_backend_lifecycle",
                "duplicate carrier task registration during publication: key={key:?}"
            );
        }
        if failpoint == 2 {
            let row = inner.states.remove(&key).unwrap_or_else(|| {
                carrick_fatal!(
                    "hvpatch::task_backend_lifecycle",
                    "carrier task state row missing immediately after insertion during failpoint rollback: key={key:?}"
                );
            });
            drop(inner);
            let (row, carrier_mm) = rollback_failed_directory_publication(
                &task_mm, row, carrier_mm,
            )
            .unwrap_or_else(|error| {
                carrick_fatal!(
                    "hvpatch::task_backend_lifecycle",
                    "rollback failed HVPatch directory publication: {error}"
                );
            });
            drop(row);
            drop(carrier_mm);
            task_mm.record_holder(HvpatchTaskMmHolder::FailpointRollback);
            drop(task_mm);
            return Err(TrapError::Hypervisor(
                "injected carrier task-state failure after directory publication".to_owned(),
            ));
        }
        if let Some(carrier_mm) = carrier_mm {
            inner
                .carrier_mms
                .insert(mm_key, std::sync::Arc::downgrade(&carrier_mm));
        }
        inner
            .task_mms
            .insert(mm_key, std::sync::Arc::downgrade(&task_mm));
        drop(inner);
        Ok(HvpatchTaskOnlyBackendState {
            registration: Some(HvpatchTaskRegistration {
                directory: std::sync::Arc::clone(self),
                key,
                expected_identity: identity,
                foreign_mm_registration: None,
                task_mm: Some(task_mm),
                cow_authority: None,
                cow_identity: None,
                cow_authority_identity: None,
                child_token_verifier: std::sync::Arc::clone(&self.child_token_verifier),
                #[cfg(not(test))]
                custody,
            }),
        })
    }

    pub(crate) fn retire(&self, key: HvpatchCarrierTaskStateKey) -> Result<(), TrapError> {
        if key.directory_instance != self.instance {
            return Err(TrapError::Hypervisor(
                "cross-directory HVPatch carrier token rejected".to_owned(),
            ));
        }
        let row = self.inner.lock().states.remove(&key).ok_or_else(|| {
            TrapError::Hypervisor("missing exact carrier task-state retirement".to_owned())
        })?;
        #[cfg(test)]
        if let Some(rollbacks) = &row.rollbacks {
            rollbacks.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
        drop(row);
        Ok(())
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl HvpatchCarrierTaskState {
    fn abort(self) -> Result<(), TrapError> {
        match self {
            Self::Sibling { .. } | Self::SharedProcess { .. } => Ok(()),
            Self::Process {
                mut stage2_leases, ..
            } => {
                for lease in &mut stage2_leases {
                    lease.try_retire()?;
                }
                Ok(())
            }
            #[cfg(test)]
            Self::LeaseTest { mut stage2_leases } => {
                for lease in &mut stage2_leases {
                    lease.try_retire()?;
                }
                Ok(())
            }
            #[cfg(test)]
            Self::Test { rollbacks, order } => {
                rollbacks.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                if let Some(order) = order {
                    order.lock().push("carrier");
                }
                Ok(())
            }
        }
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
struct GlobalExecPlan {
    plan: GuestMappingPlan,
    stage2_leases: std::collections::BTreeMap<(u64, u64), GlobalFrameStage2Lease>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ExecStage2Install {
    ipa: u64,
    size: usize,
    host: *mut u8,
    perms: u64,
    replay_registered: bool,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ExecLeaseFingerprint {
    pub(crate) base: u64,
    pub(crate) length: u64,
    pub(crate) mapped: bool,
    pub(crate) active: bool,
    pub(crate) release_ipa: bool,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl From<&GlobalFrameStage2Lease> for ExecLeaseFingerprint {
    fn from(lease: &GlobalFrameStage2Lease) -> Self {
        Self {
            base: lease.base,
            length: lease.length,
            mapped: lease.mapped,
            active: lease.active,
            release_ipa: lease.release_ipa,
        }
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Debug, Eq, PartialEq)]
struct ExecOwnerFingerprint {
    key: (u64, u64),
    host: usize,
    host_len: usize,
    perms: u64,
    lease: ExecLeaseFingerprint,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ExecBackendExtentFingerprint {
    key: (u64, u64),
    frame: carrick_hal::FrameId,
    mapping: carrick_hal::MappingId,
    backing: InventoryBackingIdentity,
    stage2_base: u64,
    stage2_length: u64,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Debug, Eq, PartialEq)]
struct ExecMappingFingerprint {
    start: u64,
    ipa: u64,
    physical_ipa: u64,
    end: u64,
    host: usize,
    size: usize,
    physical_size: usize,
    perms: u64,
    has_memory: bool,
    host_owner: Option<(usize, usize)>,
    stage2_lease: Option<ExecLeaseFingerprint>,
    is_dynamic_alias: bool,
    sharing: GuestMappingSharing,
    guest_writable: bool,
    shared_key_base: u64,
    shared_key_offset: u64,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Debug, Eq, PartialEq)]
struct ExecAllocatorFingerprint {
    next: u64,
    free: Vec<(u64, u64)>,
    live: Vec<(u64, u64)>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Debug, Eq, PartialEq)]
struct ExecAuthorityFingerprint {
    owners: Vec<ExecOwnerFingerprint>,
    inventory_initialized: bool,
    backend_extents: Vec<ExecBackendExtentFingerprint>,
    frame_references: Vec<(carrick_hal::FrameId, usize)>,
    extent_references: Vec<((carrick_hal::FrameId, u64, u64), usize)>,
    stage2_references: Vec<((u64, u64), usize)>,
    authority_retained_stage2: Vec<(u64, u64)>,
    mappings: Vec<ExecMappingFingerprint>,
    allocator: ExecAllocatorFingerprint,
    replay_mappings: Vec<ReplayMappingKey>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn verify_exec_authority_rollback(
    before: &ExecAuthorityFingerprint,
    after: &ExecAuthorityFingerprint,
) -> Result<(), TrapError> {
    if before == after {
        Ok(())
    } else {
        Err(TrapError::Hypervisor(
            "HVPatch exec stage-2 rollback changed published authority".to_owned(),
        ))
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl ExecStage2Install {
    fn replay_key(&self) -> Option<ReplayMappingKey> {
        self.replay_registered
            .then_some((self.ipa, self.size, self.host as usize, self.perms, 0))
    }

    #[cfg(test)]
    fn key(&self) -> (u64, u64) {
        (self.ipa, self.size as u64)
    }

    #[cfg(test)]
    fn for_test(ipa: u64, size: usize) -> Self {
        Self {
            ipa,
            size,
            host: std::ptr::null_mut(),
            perms: 0,
            replay_registered: false,
        }
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn switch_exec_stage2_transaction(
    old: &[ExecStage2Install],
    new: &[ExecStage2Install],
    fail_after_maps: Option<usize>,
    mut unmap: impl FnMut(&ExecStage2Install) -> Result<(), TrapError>,
    mut map: impl FnMut(&ExecStage2Install) -> Result<(), TrapError>,
) -> Result<(), TrapError> {
    for (old_unmapped, extent) in old.iter().enumerate() {
        if let Err(error) = unmap(extent) {
            for restore in &old[..old_unmapped] {
                map(restore).unwrap_or_else(|rollback| {
                    carrick_fatal!(
                        "hvpatch::exec_commit",
                        "restore HVPatch exec predecessor after unmap failure: {rollback}"
                    );
                });
            }
            return Err(error);
        }
    }

    let rollback =
        |mapped: usize,
         unmap: &mut dyn FnMut(&ExecStage2Install) -> Result<(), TrapError>,
         map: &mut dyn FnMut(&ExecStage2Install) -> Result<(), TrapError>| {
            for replacement in new[..mapped].iter().rev() {
                unmap(replacement).unwrap_or_else(|error| {
                    carrick_fatal!(
                        "hvpatch::exec_commit",
                        "rollback HVPatch exec replacement stage-2 mapping: {error}"
                    );
                });
            }
            for predecessor in old {
                map(predecessor).unwrap_or_else(|error| {
                    carrick_fatal!(
                        "hvpatch::exec_commit",
                        "restore HVPatch exec predecessor stage-2 mapping: {error}"
                    );
                });
            }
        };

    for (new_mapped, extent) in new.iter().enumerate() {
        if fail_after_maps == Some(new_mapped) {
            rollback(new_mapped, &mut unmap, &mut map);
            return Err(TrapError::Hypervisor(format!(
                "injected HVPatch exec stage-2 map failure after {new_mapped} maps"
            )));
        }
        if let Err(error) = map(extent) {
            rollback(new_mapped, &mut unmap, &mut map);
            return Err(error);
        }
    }
    Ok(())
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn exec_stage2_fail_after_maps() -> Option<usize> {
    std::env::var("CARRICK_HVPATCH_EXEC_FAIL_AFTER_MAPS")
        .ok()
        .and_then(|value| value.parse().ok())
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn global_frame_exec_lease_order(mappings: &[GuestMapping], table_index: usize) -> Vec<usize> {
    let mut order: Vec<usize> = (0..mappings.len())
        .filter(|&index| {
            !is_sparse_hvpatch_mmap_mapping(&mappings[index])
                && !is_persistent_executor_carrier_guest_mapping(&mappings[index])
        })
        .collect();
    order.sort_by_key(|&index| {
        (
            u8::from(index != table_index),
            std::cmp::Reverse(mappings[index].mapped_size),
            mappings[index].guest_start,
            index,
        )
    });
    order
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn prepare_global_exec_plan(
    plan: &GuestMappingPlan,
    mm_root_slot: Option<(u64, u64)>,
) -> Result<GlobalExecPlan, TrapError> {
    let old_root = plan.stage1_page_tables_base.ok_or_else(|| {
        TrapError::Hypervisor("hvpatch exec image has no stage-1 tables".to_owned())
    })?;
    let table_index = plan
        .mappings
        .iter()
        .position(|mapping| mapping.guest_start == old_root)
        .ok_or_else(|| {
            TrapError::Hypervisor("hvpatch exec page-table mapping absent".to_owned())
        })?;
    let mut global = plan.clone();
    let mut stage2_leases = std::collections::BTreeMap::new();
    let mut page_tables = crate::page_table::PageTableManager::new(
        global.mappings[table_index].image.as_ref().clone(),
        old_root,
    );
    const TWO_MIB: u64 = 2 * 1024 * 1024;
    let mut order = global_frame_exec_lease_order(&global.mappings, table_index);
    if mm_root_slot.is_none() {
        // The root's table is allocator-owned after its first exec, unlike a
        // child's fixed root-slot table. Preserve scarce large holes by giving
        // the largest root mappings first choice before reserving the table.
        order.sort_by_key(|&index| {
            (
                std::cmp::Reverse(global.mappings[index].mapped_size),
                global.mappings[index].guest_start,
                index,
            )
        });
    }
    for index in order {
        let mapping = &mut global.mappings[index];
        let lease = if let Some((root_slot_base, root_slot_size)) = mm_root_slot
            && index == table_index
        {
            if mapping.mapped_size > root_slot_size {
                return Err(TrapError::Hypervisor(format!(
                    "hvpatch stage-1 root needs {} bytes, slot has {root_slot_size}",
                    mapping.mapped_size
                )));
            }
            let lease = GlobalFrameStage2Lease::fixed(root_slot_base, mapping.mapped_size);
            if lease
                .base
                .checked_add(mapping.mapped_size)
                .is_none_or(|end| end > root_slot_base.saturating_add(root_slot_size))
            {
                return Err(TrapError::Hypervisor(format!(
                    "hvpatch stage-1 root mapping escapes slot 0x{root_slot_base:x}..0x{:x}",
                    root_slot_base.saturating_add(root_slot_size)
                )));
            }
            lease
        } else {
            let alignment =
                if mapping.guest_start.is_multiple_of(TWO_MIB) && mapping.mapped_size >= TWO_MIB {
                    TWO_MIB
                } else {
                    HVF_PAGE_SIZE
                };
            GlobalFrameStage2Lease::reserve(mapping.mapped_size, alignment)?
        };
        let ipa = lease.base;
        mapping.ipa_start = ipa;
        if stage2_leases
            .insert((ipa, mapping.mapped_size), lease)
            .is_some()
        {
            return Err(TrapError::Hypervisor(format!(
                "duplicate HVPatch exec stage-2 lease IPA 0x{ipa:x} size {}",
                mapping.mapped_size
            )));
        }
    }
    let root = global.mappings[table_index].ipa_start;
    page_tables.rebase(root, None).map_err(|error| {
        TrapError::Hypervisor(format!("rebase HVPatch exec page tables: {error:?}"))
    })?;
    for mapping in global
        .mappings
        .iter()
        .filter(|mapping| !is_sparse_hvpatch_mmap_mapping(mapping))
    {
        let remap = if (crate::memory::LINUX_KERNEL_REGION_BASE
            ..crate::memory::LINUX_KERNEL_REGION_BASE + TWO_MIB)
            .contains(&mapping.guest_start)
        {
            page_tables.map_kernel_aliased(
                mapping.guest_start,
                mapping.ipa_start,
                mapping.mapped_size,
                None,
            )
        } else {
            page_tables.map_aliased(
                mapping.guest_start,
                mapping.ipa_start,
                mapping.mapped_size,
                mapping.perms.write,
                None,
            )
        };
        remap.map_err(|error| {
            TrapError::Hypervisor(format!(
                "plan global-frame HVPatch exec VA 0x{:x}: {error:?}",
                mapping.guest_start
            ))
        })?;
    }
    page_tables
        .set_prot_none(
            crate::memory::LINUX_MMAP_BASE,
            crate::memory::mmap_arena_size() as usize,
            None,
        )
        .map_err(|error| {
            TrapError::Hypervisor(format!("reserve sparse HVPatch mmap arena: {error:?}"))
        })?;
    reapply_global_exec_readonly_spans(&mut page_tables, &global.ro_spans)?;
    for mapping in &global.mappings {
        let expected = (!is_sparse_hvpatch_mmap_mapping(mapping)).then_some(mapping.ipa_start);
        if page_tables.translate(mapping.guest_start) != expected {
            return Err(TrapError::Hypervisor(format!(
                "hvpatch exec translation mismatch for VA 0x{:x}: expected={expected:x?}",
                mapping.guest_start,
            )));
        }
    }
    carrick_aarch64::engine::reserve_hvpatch_process_apertures(&mut page_tables).map_err(
        |error| {
            TrapError::Hypervisor(format!(
                "reserve hvpatch exec root-slot/global-frame apertures: {error:?}"
            ))
        },
    )?;
    let table_bytes = page_tables.into_bytes();
    {
        let table = &mut global.mappings[table_index];
        if table.ipa_start != root || table_bytes.len() > table.mapped_size as usize {
            return Err(TrapError::Hypervisor(
                "hvpatch exec page-table root-slot layout mismatch".to_owned(),
            ));
        }
        table.image = table_bytes.into();
        table.payload_size = table.image.len() as u64;
    }
    global.stage1_page_tables_base = Some(root);
    Ok(GlobalExecPlan {
        plan: global,
        stage2_leases,
    })
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn is_sparse_hvpatch_mmap_mapping(mapping: &GuestMapping) -> bool {
    mapping.guest_start == crate::memory::LINUX_MMAP_BASE
        && mapping.mapped_size == crate::memory::mmap_arena_size()
        && !mapping.shared
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn next_vdso_rng_generation() -> u64 {
    // A host PID distinguished the historical one-guest-process-per-host-process
    // VMM fork path, but HVPatch materializes many Linux processes inside one
    // Carrick host process. A process-local monotonic generation distinguishes
    // every such child; the vDSO uses it only as a reseed epoch, not as entropy.
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn reapply_global_exec_readonly_spans(
    page_tables: &mut crate::page_table::PageTableManager,
    ro_spans: &[carrick_mem::elf::RoSpan],
) -> Result<(), TrapError> {
    for span in ro_spans {
        let len = usize::try_from(span.len).map_err(|_| {
            TrapError::Hypervisor(format!(
                "HVPatch exec read-only span at 0x{:x} is too large: {}",
                span.start, span.len
            ))
        })?;
        page_tables
            .set_readonly(span.start, len, span.exec, None)
            .map_err(|error| {
                TrapError::Hypervisor(format!(
                    "restore HVPatch exec read-only span at 0x{:x}: {error:?}",
                    span.start
                ))
            })?;
    }
    Ok(())
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
struct GlobalFrameOwnerRollback {
    custody: std::sync::Arc<CarrierVmCustody>,
    keys: Vec<(u64, u64)>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl GlobalFrameOwnerRollback {
    fn new(custody: std::sync::Arc<CarrierVmCustody>) -> Self {
        Self {
            custody,
            keys: Vec::new(),
        }
    }

    fn record(&mut self, key: (u64, u64)) {
        self.keys.push(key);
    }

    fn commit(mut self) {
        self.keys.clear();
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl Drop for GlobalFrameOwnerRollback {
    fn drop(&mut self) {
        for &(ipa, length) in self.keys.iter().rev() {
            let outcome = retire_global_frame_host_owner_in(&self.custody, ipa, length);
            if matches!(outcome, GlobalFrameRetirementOutcome::NotFound { .. }) {
                carrick_fatal!(
                    "hvpatch::frame_inventory",
                    "rollback lost global frame owner IPA 0x{ipa:x} size {length}"
                );
            }
        }
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
unsafe impl Send for ProcessSpec {}

// SAFETY: `ThreadSpec` carries raw `*mut u8` host pointers (inside the
// mapping descriptors). Those pointers name buffers that are valid for the
// entire host process address space — they outlive every guest thread and
// are never reallocated for the life of the VM. The seeded register snapshot
// rides the engine's `Aarch64SiblingSpec`, NOT here (the engine restores it
// onto the sibling vCPU). The applevisor VM handle is itself `Send` (Arc-backed).
// Moving the spec to another thread to materialise a vCPU there is exactly
// the supported HVF pattern (create the vCPU on its owning thread), so the
// raw pointers crossing the thread boundary is sound.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
unsafe impl Send for ThreadSpec {}

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
pub struct ThreadSpec;

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum PersistentExecutorInvariantRegister {
    VbarEl1,
    SctlrEl1,
    MairEl1,
    CpacrEl1,
    CntkctlEl1,
    TpidrEl1,
    SpEl1,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
const PERSISTENT_EXECUTOR_CONFIGURED_REGISTERS: [PersistentExecutorInvariantRegister; 6] = [
    PersistentExecutorInvariantRegister::VbarEl1,
    PersistentExecutorInvariantRegister::SctlrEl1,
    PersistentExecutorInvariantRegister::MairEl1,
    PersistentExecutorInvariantRegister::CpacrEl1,
    PersistentExecutorInvariantRegister::CntkctlEl1,
    PersistentExecutorInvariantRegister::TpidrEl1,
];

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
const PERSISTENT_EXECUTOR_INVARIANT_REGISTERS: [PersistentExecutorInvariantRegister; 7] = [
    PersistentExecutorInvariantRegister::VbarEl1,
    PersistentExecutorInvariantRegister::SctlrEl1,
    PersistentExecutorInvariantRegister::MairEl1,
    PersistentExecutorInvariantRegister::CpacrEl1,
    PersistentExecutorInvariantRegister::CntkctlEl1,
    PersistentExecutorInvariantRegister::TpidrEl1,
    PersistentExecutorInvariantRegister::SpEl1,
];

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn persistent_executor_invariant_value(
    register: PersistentExecutorInvariantRegister,
    mailbox_sp: u64,
) -> u64 {
    use carrick_hal::GuestArch as _;

    let boot = <HvfTrapEngine as carrick_hal::ThreadedEngine>::Arch::bootstrap_sysregs();
    match register {
        PersistentExecutorInvariantRegister::VbarEl1 => carrick_mem::memory::LINUX_EL1_VECTORS_BASE,
        PersistentExecutorInvariantRegister::SctlrEl1 => boot.sctlr_el1,
        PersistentExecutorInvariantRegister::MairEl1 => boot.mair_el1,
        PersistentExecutorInvariantRegister::CpacrEl1 => boot.cpacr_el1,
        PersistentExecutorInvariantRegister::CntkctlEl1 => (1 << 1) | (1 << 0),
        // The EL1 vector uses TPIDR_EL1 only as transient executor-local x16
        // scratch. A newly published worker must not inherit task residue.
        PersistentExecutorInvariantRegister::TpidrEl1 => 0,
        PersistentExecutorInvariantRegister::SpEl1 => mailbox_sp,
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn configure_persistent_executor_invariant_registers(
    mut write: impl FnMut(PersistentExecutorInvariantRegister, u64) -> Result<(), TrapError>,
) -> Result<(), TrapError> {
    for register in PERSISTENT_EXECUTOR_CONFIGURED_REGISTERS {
        write(register, persistent_executor_invariant_value(register, 0))?;
    }
    Ok(())
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn restore_persistent_executor_invariant_registers(
    mut write: impl FnMut(PersistentExecutorInvariantRegister, u64) -> Result<(), TrapError>,
    mailbox_sp: u64,
) -> Result<(), TrapError> {
    for register in PERSISTENT_EXECUTOR_INVARIANT_REGISTERS {
        write(
            register,
            persistent_executor_invariant_value(register, mailbox_sp),
        )?;
    }
    Ok(())
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn audit_persistent_executor_invariant_registers(
    mut read: impl FnMut(PersistentExecutorInvariantRegister) -> Result<u64, TrapError>,
    mailbox_sp: u64,
) -> Result<(), TrapError> {
    for register in PERSISTENT_EXECUTOR_INVARIANT_REGISTERS {
        let actual = read(register)?;
        let expected = persistent_executor_invariant_value(register, mailbox_sp);
        if actual != expected {
            return Err(TrapError::Hypervisor(format!(
                "persistent executor invariant {register:?} mismatch: {actual:#x}/{expected:#x}"
            )));
        }
    }
    Ok(())
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl HvfVmState {
    fn configure_executor_invariants(vcpu: &applevisor::vcpu::Vcpu) -> Result<(), TrapError> {
        use applevisor::prelude::SysReg;

        configure_persistent_executor_invariant_registers(|register, value| {
            let register = match register {
                PersistentExecutorInvariantRegister::VbarEl1 => SysReg::VBAR_EL1,
                PersistentExecutorInvariantRegister::SctlrEl1 => SysReg::SCTLR_EL1,
                PersistentExecutorInvariantRegister::MairEl1 => SysReg::MAIR_EL1,
                PersistentExecutorInvariantRegister::CpacrEl1 => SysReg::CPACR_EL1,
                PersistentExecutorInvariantRegister::CntkctlEl1 => SysReg::CNTKCTL_EL1,
                PersistentExecutorInvariantRegister::TpidrEl1 => SysReg::TPIDR_EL1,
                PersistentExecutorInvariantRegister::SpEl1 => {
                    unreachable!("SP_EL1 is mailbox-owned")
                }
            };
            vcpu.set_sys_reg(register, value).map_err(hvf_error)
        })
    }

    fn audit_executor_invariants(
        vcpu: &applevisor::vcpu::Vcpu,
        mailbox_sp: u64,
    ) -> Result<(), TrapError> {
        use applevisor::prelude::SysReg;

        audit_persistent_executor_invariant_registers(
            |register| {
                let register = match register {
                    PersistentExecutorInvariantRegister::VbarEl1 => SysReg::VBAR_EL1,
                    PersistentExecutorInvariantRegister::SctlrEl1 => SysReg::SCTLR_EL1,
                    PersistentExecutorInvariantRegister::MairEl1 => SysReg::MAIR_EL1,
                    PersistentExecutorInvariantRegister::CpacrEl1 => SysReg::CPACR_EL1,
                    PersistentExecutorInvariantRegister::CntkctlEl1 => SysReg::CNTKCTL_EL1,
                    PersistentExecutorInvariantRegister::TpidrEl1 => SysReg::TPIDR_EL1,
                    PersistentExecutorInvariantRegister::SpEl1 => SysReg::SP_EL1,
                };
                vcpu.get_sys_reg(register).map_err(hvf_error)
            },
            mailbox_sp,
        )
    }

    fn exec_authority_fingerprint(&self) -> ExecAuthorityFingerprint {
        let inventory = self.frame_inventory.lock();
        let backend_extents = inventory
            .extents
            .iter()
            .map(|(&key, extent)| ExecBackendExtentFingerprint {
                key,
                frame: extent.frame,
                mapping: extent.mapping,
                backing: extent.backing,
                stage2_base: extent.stage2_base,
                stage2_length: extent.stage2_length,
            })
            .collect();
        let inventory_initialized = inventory.initialized;
        let frames = inventory.frames.lock();
        let frame_references = frames
            .references
            .iter()
            .map(|(&key, &value)| (key, value))
            .collect();
        let extent_references = frames
            .extent_references
            .iter()
            .map(|(&key, &value)| (key, value))
            .collect();
        let stage2_references = frames
            .stage2_references
            .iter()
            .map(|(&key, &value)| (key, value))
            .collect();
        let authority_retained_stage2 = frames.authority_retained_stage2.iter().copied().collect();
        drop(frames);
        drop(inventory);
        let owners = self
            .custody()
            .global_frame_host_owners
            .lock()
            .iter()
            .map(|(&key, entry)| {
                let owner = entry.owner();
                ExecOwnerFingerprint {
                    key,
                    host: owner.host_addr(),
                    host_len: owner.len(),
                    perms: owner.perms(),
                    lease: owner.lease_fingerprint().unwrap_or(ExecLeaseFingerprint {
                        base: key.0,
                        length: key.1,
                        mapped: false,
                        active: false,
                        release_ipa: false,
                    }),
                }
            })
            .collect();
        let mappings = self
            .mappings
            .iter()
            .map(|mapping| ExecMappingFingerprint {
                start: mapping.start,
                ipa: mapping.ipa,
                physical_ipa: mapping.physical_ipa,
                end: mapping.end,
                host: mapping.host_addr as usize,
                size: mapping.size,
                physical_size: mapping.physical_size,
                perms: u64::from(mapping.perms),
                has_memory: mapping.memory.is_some(),
                host_owner: mapping
                    .host_mapping
                    .as_ref()
                    .map(|owner| (owner.as_ptr() as usize, owner.len())),
                stage2_lease: mapping.stage2_lease.as_ref().map(Into::into),
                is_dynamic_alias: mapping.is_dynamic_alias,
                sharing: mapping.sharing,
                guest_writable: mapping.guest_writable,
                shared_key_base: mapping.shared_key_base,
                shared_key_offset: mapping.shared_key_offset,
            })
            .collect();
        let allocator = global_frame_ipa_allocator().lock();
        let allocator = ExecAllocatorFingerprint {
            next: allocator.next,
            free: allocator.free.clone(),
            live: allocator
                .live
                .iter()
                .map(|(&key, &value)| (key, value))
                .collect(),
        };
        let replay_mappings = replay_mappings().lock().iter().copied().collect();
        ExecAuthorityFingerprint {
            owners,
            inventory_initialized,
            backend_extents,
            frame_references,
            extent_references,
            stage2_references,
            authority_retained_stage2,
            mappings,
            allocator,
            replay_mappings,
        }
    }

    fn retire_stage2_extent(&mut self, ipa: u64, length: u64) -> Result<(), TrapError> {
        #[cfg(not(test))]
        {
            let custody = std::sync::Arc::clone(&self.custody);
            Self::retire_stage2_extent_from_mappings_in(&custody, &mut self.mappings, ipa, length)
        }
        #[cfg(test)]
        {
            Self::retire_stage2_extent_from_mappings_in(
                legacy_test_carrier_vm_custody(),
                &mut self.mappings,
                ipa,
                length,
            )
        }
    }

    fn retire_stage2_extent_from_mappings_in(
        custody: &CarrierVmCustody,
        mappings: &mut TaskMappingIndex,
        ipa: u64,
        length: u64,
    ) -> Result<(), TrapError> {
        let outcome = retire_global_frame_host_owner_in(custody, ipa, length);
        if outcome.is_retired()
            || matches!(
                outcome,
                GlobalFrameRetirementOutcome::DeferredActivePins { .. }
                    | GlobalFrameRetirementOutcome::RetryPending { .. }
            )
        {
            return Ok(());
        }
        if let Some((row, owner)) = mappings.take_structural_owner(ipa, length) {
            let Some(mapping) = mappings.row(row) else {
                unreachable!("structural claim named a row that is not in the index")
            };
            let identity = authenticated_structural_owner_record_in(
                custody,
                &owner,
                mapped_region_physical_host_addr(mapping).unwrap_or(std::ptr::null_mut()),
                mapping.physical_ipa,
                mapping.physical_size,
                mapping.perms,
                mapping.owner_generation,
            );
            let Some(identity) = identity
                .filter(|_| mapping.physical_ipa == ipa && mapping.physical_size as u64 == length)
            else {
                mappings.restore_structural_owner(row, owner);
                return Err(TrapError::Hypervisor(format!(
                    "structural retirement owner for IPA 0x{ipa:x} size {length} is not the exact current custody owner"
                )));
            };
            // Process retirement is the authoritative lifetime boundary for
            // this structural stage-2 extent.  MM-access projections retain
            // owner Arcs so foreign reads can authenticate live semantic
            // mappings, but those metadata references must not postpone the
            // root-slot unmap after the Kernel has retired the MM and returned
            // its fixed slot for reuse.
            owner
                .retained
                .owner_retired
                .store(true, std::sync::atomic::Ordering::Release);
            let retirement = retry_structural_backing_identities_in_using(
                custody,
                &[identity],
                &mut unmap_global_frame_stage2_record,
                &mut release_retired_stage2_ipa,
            );
            if let Err(error) = retirement {
                mappings.restore_structural_owner(row, owner);
                return Err(error);
            }
            if custody.stage2_record_snapshot(identity.record_id).is_some() {
                mappings.restore_structural_owner(row, owner);
                return Err(TrapError::Hypervisor(format!(
                    "structural retirement owner for IPA 0x{ipa:x} size {length} did not reach terminal retirement"
                )));
            }
            drop(owner);
            return Ok(());
        }
        if let Some(lease) = mappings.take_stage2_lease(ipa, length) {
            drop(lease);
            return Ok(());
        }
        // A forked process parks its fresh kernel-state leases on the carrier,
        // not on a mapping row. Without this the fallback below released an IPA
        // whose lease was still live, and the lease's `Drop` then released it
        // again.
        if let Some(identity) = take_carrier_stage2_record(custody, ipa, length) {
            retire_carrier_stage2_record_at_safe_point(custody, identity)?;
            return Ok(());
        }
        if is_reusable_global_frame_extent(ipa, length)
            && !global_frame_ipa_allocator().lock().is_live(ipa, length)
        {
            return Ok(());
        }
        if custody.is_pooled_ipa(ipa) {
            return Ok(());
        }
        let size = usize::try_from(length).map_err(|_| TrapError::MappingTooLarge(length))?;
        let rc = unsafe { inventory_hv_vm_unmap(ipa, size) };
        if rc != 0 {
            return Err(TrapError::Hypervisor(format!(
                "retire HVPatch stage-2 extent IPA 0x{ipa:x} size {size} failed: 0x{rc:x}"
            )));
        }
        release_retired_stage2_ipa(ipa, length)?;
        Ok(())
    }

    fn retire_unowned_stage2_extent_from_mappings_in(
        custody: &CarrierVmCustody,
        mappings: &mut TaskMappingIndex,
        ipa: u64,
        length: u64,
        host_addr: usize,
    ) -> Result<(), TrapError> {
        if let Some(live) = global_frame_host_owner_identity_in(custody, ipa, length) {
            return Err(TrapError::Hypervisor(format!(
                "unowned stage-2 retirement {ipa:#x}/{length:#x} found live global owner {live:?}"
            )));
        }
        if let Some(lease) = mappings.take_exact_unowned_stage2_lease(ipa, length, host_addr) {
            drop(lease);
            return Ok(());
        }
        if let Some(identity) = take_carrier_stage2_record_if_owner(custody, ipa, length, host_addr)
        {
            retire_carrier_stage2_record_at_safe_point(custody, identity)?;
            return Ok(());
        }
        if is_reusable_global_frame_extent(ipa, length) {
            return Err(TrapError::Hypervisor(format!(
                "unowned reusable stage-2 retirement {ipa:#x}/{length:#x} lost exact mapped local/carrier owner 0x{host_addr:x}"
            )));
        }
        let size = usize::try_from(length).map_err(|_| TrapError::MappingTooLarge(length))?;
        let rc = unsafe { inventory_hv_vm_unmap(ipa, size) };
        if rc != 0 {
            return Err(TrapError::Hypervisor(format!(
                "retire unowned HVPatch stage-2 extent IPA 0x{ipa:x} size {size} failed: 0x{rc:x}"
            )));
        }
        Ok(())
    }

    #[cfg(test)]
    fn retire_stage2_extent_from_mappings(
        mappings: &mut TaskMappingIndex,
        ipa: u64,
        length: u64,
    ) -> Result<(), TrapError> {
        Self::retire_stage2_extent_from_mappings_in(
            legacy_test_carrier_vm_custody(),
            mappings,
            ipa,
            length,
        )
    }

    #[cfg(test)]
    fn retire_unowned_stage2_extent_from_mappings(
        mappings: &mut TaskMappingIndex,
        ipa: u64,
        length: u64,
        host_addr: usize,
    ) -> Result<(), TrapError> {
        Self::retire_unowned_stage2_extent_from_mappings_in(
            legacy_test_carrier_vm_custody(),
            mappings,
            ipa,
            length,
            host_addr,
        )
    }

    fn inventory_generation(raw: u64) -> carrick_hal::MappingGeneration {
        let Some(raw) = std::num::NonZeroU64::new(raw) else {
            carrick_fatal!(
                "hvpatch::frame_inventory",
                "attempted to construct MappingGeneration from zero raw counter"
            );
        };
        carrick_hal::MappingGeneration::from_backend_counter(raw)
    }

    fn private_backing_identity() -> InventoryBackingIdentity {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        let serial = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if serial == 0 {
            carrick_fatal!(
                "hvpatch::frame_inventory",
                "HVPatch private backing identity exhausted"
            );
        }
        InventoryBackingIdentity::Private(serial)
    }

    fn private_file_view_backing_identity() -> InventoryBackingIdentity {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        let serial = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if serial == 0 {
            carrick_fatal!(
                "hvpatch::frame_inventory",
                "HVPatch private file-view backing identity exhausted"
            );
        }
        InventoryBackingIdentity::PrivateFileView(serial)
    }

    fn shared_anon_backing_identity() -> InventoryBackingIdentity {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        let serial = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if serial == 0 {
            carrick_fatal!(
                "hvpatch::frame_inventory",
                "HVPatch shared-anonymous backing identity exhausted"
            );
        }
        InventoryBackingIdentity::SharedAnon(serial)
    }

    fn region_permissions(region: &HvfMappedRegion) -> carrick_hal::MemPerms {
        let raw = u64::from(region.perms);
        carrick_hal::MemPerms {
            read: raw & 1 != 0,
            write: raw & 2 != 0,
            exec: raw & 4 != 0,
        }
    }

    fn reservation_error(error: carrick_hal::FrameInventoryReservationError) -> TrapError {
        TrapError::Hypervisor(format!("HVPatch frame inventory staging failed: {error}"))
    }

    fn push_exact_mapping_events(
        reservation: &mut carrick_hal::FrameInventoryReservation,
        frame: carrick_hal::FrameId,
        gpa: u64,
        length: u64,
        permissions: carrick_hal::MemPerms,
    ) -> Result<carrick_hal::MappingId, TrapError> {
        let mapping = reservation
            .claim_mapping()
            .map_err(Self::reservation_error)?;
        let length = std::num::NonZeroU64::new(length).ok_or_else(|| {
            TrapError::Hypervisor("HVPatch inventory received an empty mapping extent".to_owned())
        })?;
        let transaction = reservation.transaction();
        reservation
            .push(carrick_hal::FrameInventoryEvent::PrepareMapping {
                transaction,
                frame,
                mapping,
                generation: Self::inventory_generation(1),
                gpa: carrick_guest_mem::Gpa(gpa),
                length: carrick_hal::FrameLength::from_mapping_extent(length),
                permissions,
            })
            .map_err(Self::reservation_error)?;
        reservation
            .push(carrick_hal::FrameInventoryEvent::PublishMapping {
                transaction,
                mapping,
                generation: Self::inventory_generation(1),
            })
            .map_err(Self::reservation_error)?;
        Ok(mapping)
    }

    fn cow_inventory_split_shape(
        inventory: &HvpatchFrameInventory,
        compound_gpa: u64,
        retain_compound: bool,
        authority_mapping_count: impl Fn(carrick_hal::FrameId) -> Result<Option<usize>, TrapError>,
    ) -> Result<CowInventorySplitShape, TrapError> {
        let compound_end = compound_gpa
            .checked_add(CowArmedRanges::COMPOUND_SIZE)
            .ok_or_else(|| TrapError::Hypervisor("HVPatch COW compound overflow".to_owned()))?;
        let (&old_key, &old) = inventory
            .extents
            .iter()
            .find(|((base, length), _)| {
                compound_gpa >= *base && compound_end <= base.saturating_add(*length)
            })
            .ok_or_else(|| {
                TrapError::Hypervisor(format!(
                    "HVPatch COW compound IPA 0x{compound_gpa:x} has no exact inventory coverage"
                ))
            })?;
        let old_end = old_key.0.checked_add(old_key.1).ok_or_else(|| {
            TrapError::Hypervisor("HVPatch old inventory extent overflow".to_owned())
        })?;
        let mut fragments = Vec::with_capacity(2);
        if old_key.0 < compound_gpa {
            fragments.push((old_key.0, compound_gpa - old_key.0));
        }
        if retain_compound {
            fragments.push((compound_gpa, CowArmedRanges::COMPOUND_SIZE));
        }
        if compound_end < old_end {
            fragments.push((compound_end, old_end - compound_end));
        }
        let global_references = inventory
            .frames
            .lock()
            .references
            .get(&old.frame)
            .copied()
            .ok_or_else(|| {
                TrapError::Hypervisor(format!(
                    "HVPatch COW frame {:?} lacks backend references",
                    old.frame
                ))
            })?;
        let authoritative_references = authority_mapping_count(old.frame)?;
        let backend_frame_references_complete = authoritative_references == Some(global_references);
        let retire_old_frame =
            global_references == 1 && fragments.is_empty() && authoritative_references == Some(1);
        Ok(CowInventorySplitShape {
            old_key,
            old,
            fragments,
            retirement: CowInventoryRetirementDecision {
                retire_old_frame,
                backend_frame_references_complete,
            },
        })
    }

    /// Plan which mappings, frames and stage-2 leases a munmap retires.
    ///
    /// `authority_mapping_count` reports the authority's VM-WIDE live-mapping
    /// count for a frame. It is not redundant with the backend reference
    /// counts consulted below: `inventory.extents` is per-mm, the authority's
    /// count spans every mm, and `RetireFrame` is rejected unless the frame
    /// reaches zero mappings there. Retiring on the per-mm population alone
    /// aborts the carrier the moment a second Linux process maps the same
    /// frame, which is precisely what a forking guest does.
    fn inventory_lease_retirement_shape(
        inventory: &HvpatchFrameInventory,
        leases: &std::collections::BTreeSet<(u64, u64)>,
        authority_mapping_count: &dyn Fn(carrick_hal::FrameId) -> Result<Option<usize>, TrapError>,
    ) -> Result<InventoryLeaseRetirement, TrapError> {
        let mappings: Vec<_> = inventory
            .extents
            .iter()
            .filter(|(_, extent)| leases.contains(&(extent.stage2_base, extent.stage2_length)))
            .map(|(&key, &extent)| (key, extent))
            .collect();
        let mut removed_frames = std::collections::BTreeMap::new();
        let mut removed_leases = std::collections::BTreeMap::new();
        for (_, extent) in &mappings {
            *removed_frames.entry(extent.frame).or_insert(0usize) += 1;
            *removed_leases
                .entry((extent.stage2_base, extent.stage2_length))
                .or_insert(0usize) += 1;
        }
        let registry = inventory.frames.lock();
        let mut frames = std::collections::BTreeSet::new();
        let mut complete_frames = std::collections::BTreeSet::new();
        for (&frame, &removed) in &removed_frames {
            let live = registry.references.get(&frame).copied().ok_or_else(|| {
                TrapError::Hypervisor(format!(
                    "HVPatch alias retirement frame {frame:?} has no backend reference"
                ))
            })?;
            if removed > live {
                return Err(TrapError::Hypervisor(format!(
                    "HVPatch alias retirement frame {frame:?} reference underflow"
                )));
            }
            let authoritative = authority_mapping_count(frame)?;
            if authoritative == Some(live) {
                complete_frames.insert(frame);
            }
            // Both populations must agree. `removed == live` says this mm
            // dropped the last backend reference it knows about; the authority
            // count says no OTHER mm still maps the frame. Requiring both can
            // only decline a retirement, never invent one, and a frame left
            // live is reclaimed by a later unmap where a wrong retirement
            // aborts the whole carrier.
            if removed == live && authoritative == Some(removed) {
                frames.insert(frame);
            }
        }
        let mut stage2_leases = std::collections::BTreeSet::new();
        let mut stage2_population_complete = std::collections::BTreeMap::new();
        for (&lease, &removed) in &removed_leases {
            let live = registry
                .stage2_references
                .get(&lease)
                .copied()
                .ok_or_else(|| {
                    TrapError::Hypervisor(format!(
                        "HVPatch alias retirement stage-2 lease {lease:?} has no backend reference"
                    ))
                })?;
            if removed > live {
                return Err(TrapError::Hypervisor(format!(
                    "HVPatch alias retirement stage-2 lease {lease:?} reference underflow"
                )));
            }
            let all_frame_populations_complete = mappings
                .iter()
                .filter(|(_, extent)| (extent.stage2_base, extent.stage2_length) == lease)
                .all(|(_, extent)| complete_frames.contains(&extent.frame));
            stage2_population_complete.insert(lease, all_frame_populations_complete);
            if removed == live && all_frame_populations_complete {
                stage2_leases.insert(lease);
            }
        }
        Ok(InventoryLeaseRetirement {
            mappings,
            frames,
            stage2_leases,
            stage2_population_complete,
        })
    }

    fn stage_inventory_lease_retirement(
        reservation: &mut carrick_hal::FrameInventoryReservation,
        retirement: &InventoryLeaseRetirement,
    ) -> Result<(), TrapError> {
        let transaction = reservation.transaction();
        for (_, extent) in &retirement.mappings {
            reservation
                .push(carrick_hal::FrameInventoryEvent::UnmapMapping {
                    transaction,
                    mapping: extent.mapping,
                    generation: Self::inventory_generation(2),
                })
                .map_err(Self::reservation_error)?;
        }
        for &frame in &retirement.frames {
            reservation
                .push(carrick_hal::FrameInventoryEvent::RetireFrame {
                    transaction,
                    frame,
                    generation: Self::inventory_generation(2),
                })
                .map_err(Self::reservation_error)?;
        }
        Ok(())
    }

    fn commit_inventory_lease_retirement(
        inventory: &mut HvpatchFrameInventory,
        retirement: &InventoryLeaseRetirement,
    ) -> Result<(), TrapError> {
        let mut removed = Vec::with_capacity(retirement.mappings.len());
        for &(key, expected) in &retirement.mappings {
            let actual = inventory.extents.remove(&key).ok_or_else(|| {
                TrapError::Hypervisor(format!(
                    "HVPatch alias retirement mapping {key:?} disappeared"
                ))
            })?;
            if actual.mapping != expected.mapping || actual.frame != expected.frame {
                return Err(TrapError::Hypervisor(format!(
                    "HVPatch alias retirement mapping {key:?} identity drifted"
                )));
            }
            removed.push((key, actual));
        }
        let mut registry = inventory.frames.lock();
        for (key, extent) in removed {
            decrement_inventory_reference(&mut registry.references, extent.frame)?;
            decrement_inventory_reference(
                &mut registry.extent_references,
                (extent.frame, key.0, key.1),
            )?;
            decrement_inventory_reference(
                &mut registry.stage2_references,
                (extent.stage2_base, extent.stage2_length),
            )?;
            if retirement.frames.contains(&extent.frame)
                && matches!(extent.backing, InventoryBackingIdentity::SharedFile { .. })
            {
                registry.shared.remove(&extent.backing);
            }
        }
        for frame in &retirement.frames {
            if registry.references.contains_key(frame) {
                return Err(TrapError::Hypervisor(format!(
                    "HVPatch retired alias frame {frame:?} retains backend references"
                )));
            }
        }
        for lease in &retirement.stage2_leases {
            if registry.stage2_references.contains_key(lease) {
                return Err(TrapError::Hypervisor(format!(
                    "HVPatch retired stage-2 lease {lease:?} retains backend references"
                )));
            }
        }
        for (&lease, &population_complete) in &retirement.stage2_population_complete {
            reconcile_carrier_stage2_authority_retention(&mut registry, lease, population_complete);
        }
        Ok(())
    }

    fn stage_cow_inventory_split(
        reservation: &mut carrick_hal::FrameInventoryReservation,
        old_key: (u64, u64),
        old: InventoryExtent,
        fragment_shapes: &[(u64, u64)],
        retirement: CowInventoryRetirementDecision,
        replacement: CowInventoryReplacementStage,
    ) -> Result<CowInventorySplit, TrapError> {
        let transaction = reservation.transaction();
        reservation
            .push(carrick_hal::FrameInventoryEvent::UnmapMapping {
                transaction,
                mapping: old.mapping,
                generation: Self::inventory_generation(2),
            })
            .map_err(Self::reservation_error)?;
        let permissions = carrick_hal::MemPerms {
            read: true,
            write: true,
            exec: true,
        };
        let mut fragments = Vec::with_capacity(fragment_shapes.len());
        for &(gpa, length) in fragment_shapes {
            let mapping =
                Self::push_exact_mapping_events(reservation, old.frame, gpa, length, permissions)?;
            fragments.push(CowInventoryFragment {
                gpa,
                length,
                mapping,
            });
        }
        let (new_frame, new_mapping) = if let Some(existing) = replacement.existing {
            if existing.frame == old.frame
                || existing.stage2_base != replacement.gpa
                || existing.stage2_length != CowArmedRanges::COMPOUND_SIZE
                || existing.stage2_owner != replacement.stage2_owner
                || existing.backing != replacement.backing
            {
                return Err(TrapError::Hypervisor(
                    "HVPatch COW reuse identity mismatch".to_owned(),
                ));
            }
            (existing.frame, existing.mapping)
        } else {
            let frame = reservation.claim_frame().map_err(Self::reservation_error)?;
            let mapping = Self::push_exact_mapping_events(
                reservation,
                frame,
                replacement.gpa,
                CowArmedRanges::COMPOUND_SIZE,
                permissions,
            )?;
            (frame, mapping)
        };
        if retirement.retire_old_frame {
            reservation
                .push(carrick_hal::FrameInventoryEvent::RetireFrame {
                    transaction,
                    frame: old.frame,
                    generation: Self::inventory_generation(2),
                })
                .map_err(Self::reservation_error)?;
        }
        Ok(CowInventorySplit {
            replacement_is_existing: replacement.existing.is_some(),
            old_key,
            old,
            fragments,
            new_key: (replacement.gpa, CowArmedRanges::COMPOUND_SIZE),
            new_extent: InventoryExtent {
                frame: new_frame,
                mapping: new_mapping,
                backing: replacement.backing,
                stage2_base: replacement.gpa,
                stage2_length: CowArmedRanges::COMPOUND_SIZE,
                stage2_owner: replacement.stage2_owner,
            },
            retirement,
        })
    }

    fn commit_cow_inventory_split(
        inventory: &mut HvpatchFrameInventory,
        split: &CowInventorySplit,
        retire_stage2: impl FnOnce() -> Result<(), TrapError>,
    ) -> Result<bool, TrapError> {
        if split.replacement_is_existing {
            if split.new_extent.frame == split.old.frame
                || inventory.extents.get(&split.new_key) != Some(&split.new_extent)
            {
                return Err(TrapError::Hypervisor(
                    "HVPatch COW reuse destination drifted".to_owned(),
                ));
            }
        } else if let Some(existing) = inventory.extents.get(&split.new_key) {
            let stage2_references = inventory
                .frames
                .lock()
                .stage2_references
                .get(&(existing.stage2_base, existing.stage2_length))
                .copied();
            return Err(TrapError::Hypervisor(format!(
                "HVPatch COW new inventory extent collided before backend mutation: \
                 new_key={:?} existing={existing:?} existing_stage2_references={stage2_references:?} \
                 old_key={:?} fragments={:?}",
                split.new_key, split.old_key, split.fragments,
            )));
        }
        let removed = inventory.extents.remove(&split.old_key).ok_or_else(|| {
            TrapError::Hypervisor("HVPatch COW old inventory mapping disappeared".to_owned())
        })?;
        if removed.mapping != split.old.mapping || removed.frame != split.old.frame {
            return Err(TrapError::Hypervisor(
                "HVPatch COW old inventory identity drifted".to_owned(),
            ));
        }
        let mut frames = inventory.frames.lock();
        decrement_inventory_reference(&mut frames.references, split.old.frame)?;
        decrement_inventory_reference(
            &mut frames.extent_references,
            (split.old.frame, split.old_key.0, split.old_key.1),
        )?;
        decrement_inventory_reference(
            &mut frames.stage2_references,
            (split.old.stage2_base, split.old.stage2_length),
        )?;
        for fragment in &split.fragments {
            increment_inventory_reference(&mut frames.references, split.old.frame)?;
            increment_inventory_reference(
                &mut frames.extent_references,
                (split.old.frame, fragment.gpa, fragment.length),
            )?;
            increment_inventory_reference(
                &mut frames.stage2_references,
                (split.old.stage2_base, split.old.stage2_length),
            )?;
            inventory.extents.insert(
                (fragment.gpa, fragment.length),
                InventoryExtent {
                    frame: split.old.frame,
                    mapping: fragment.mapping,
                    backing: split.old.backing,
                    stage2_base: split.old.stage2_base,
                    stage2_length: split.old.stage2_length,
                    stage2_owner: split.old.stage2_owner,
                },
            );
        }
        if !split.replacement_is_existing {
            increment_inventory_reference(&mut frames.references, split.new_extent.frame)?;
            increment_inventory_reference(
                &mut frames.extent_references,
                (split.new_extent.frame, split.new_key.0, split.new_key.1),
            )?;
            increment_inventory_reference(
                &mut frames.stage2_references,
                (split.new_extent.stage2_base, split.new_extent.stage2_length),
            )?;
        }
        if split.retirement.retire_old_frame && frames.references.contains_key(&split.old.frame) {
            return Err(TrapError::Hypervisor(
                "HVPatch COW retired old frame retains backend mappings".to_owned(),
            ));
        }
        reconcile_carrier_stage2_authority_retention(
            &mut frames,
            (split.old.stage2_base, split.old.stage2_length),
            split.retirement.backend_frame_references_complete,
        );
        let retire_old_stage2 = split.retirement.backend_frame_references_complete
            && !frames
                .stage2_references
                .contains_key(&(split.old.stage2_base, split.old.stage2_length));
        if retire_old_stage2 {
            // `stage_mapping` publishes a sibling reference while holding this
            // same registry lock. Keep it through physical-owner removal and
            // allocator release so the old zero-reference decision cannot go
            // stale before another COW reserves the recycled IPA.
            retire_stage2()?;
        }
        drop(frames);
        if !split.replacement_is_existing
            && inventory
                .extents
                .insert(split.new_key, split.new_extent)
                .is_some()
        {
            return Err(TrapError::Hypervisor(
                "HVPatch COW new inventory extent collided".to_owned(),
            ));
        }
        Ok(retire_old_stage2)
    }

    fn retire_stage2_candidate_if_unreferenced(
        frames: &std::sync::Arc<parking_lot::Mutex<InventoryFrameRegistry>>,
        candidate: (u64, u64),
        retire: impl FnOnce() -> Result<(), TrapError>,
    ) -> Result<bool, TrapError> {
        let registry = frames.lock();
        if registry.stage2_references.contains_key(&candidate) {
            return Ok(false);
        }
        retire()?;
        drop(registry);
        Ok(true)
    }

    fn stage_mapping_in(
        custody: &CarrierVmCustody,
        inventory: &mut HvpatchFrameInventory,
        reservation: &mut carrick_hal::FrameInventoryReservation,
        stage: InventoryMappingStage,
    ) -> Result<InventoryExtent, TrapError> {
        #[cfg(test)]
        if STAGE2_AUDIT_STATE.with(|s| {
            let mut state = s.borrow_mut();
            let count = state.stage_mapping_count;
            state.stage_mapping_count += 1;
            if state.fail_stage_mapping {
                state.fail_stage_mapping = false;
                true
            } else if state.fail_stage_mapping_on_row == Some(count) {
                state.fail_stage_mapping_on_row = None;
                true
            } else {
                false
            }
        }) {
            return Err(TrapError::Hypervisor(
                "injected stage_mapping failure".to_owned(),
            ));
        }
        let InventoryMappingStage {
            gpa,
            length,
            permissions,
            backing,
            inherited_frame,
            stage2_lease,
            stage2_owner,
        } = stage;
        if inventory.extents.contains_key(&(gpa, length)) {
            return Err(TrapError::Hypervisor(format!(
                "HVPatch inventory extent IPA 0x{gpa:x} size {length} is duplicated"
            )));
        }
        let transaction = reservation.transaction();
        let mapping = reservation
            .claim_mapping()
            .map_err(Self::reservation_error)?;
        let frame = if let Some(frame) = inherited_frame {
            frame
        } else if matches!(backing, InventoryBackingIdentity::SharedFile { .. }) {
            let existing = inventory.frames.lock().shared.get(&backing).copied();
            match existing {
                Some(frame) => frame,
                None => reservation.claim_frame().map_err(Self::reservation_error)?,
            }
        } else {
            reservation.claim_frame().map_err(Self::reservation_error)?
        };
        let Some(length_value) = std::num::NonZeroU64::new(length) else {
            return Err(TrapError::Hypervisor(
                "HVPatch inventory received an empty mapping extent".to_owned(),
            ));
        };
        let length_typed = carrick_hal::FrameLength::from_mapping_extent(length_value);
        reservation
            .push(carrick_hal::FrameInventoryEvent::PrepareMapping {
                transaction,
                frame,
                mapping,
                generation: Self::inventory_generation(1),
                gpa: carrick_guest_mem::Gpa(gpa),
                length: length_typed,
                permissions,
            })
            .map_err(Self::reservation_error)?;
        reservation
            .push(carrick_hal::FrameInventoryEvent::PublishMapping {
                transaction,
                mapping,
                generation: Self::inventory_generation(1),
            })
            .map_err(Self::reservation_error)?;
        let mut frames = inventory.frames.lock();
        let frame_references = frames
            .references
            .get(&frame)
            .copied()
            .unwrap_or_default()
            .checked_add(1)
            .ok_or_else(|| {
                TrapError::Hypervisor(format!(
                    "HVPatch frame {frame:?} backend reference count exhausted"
                ))
            })?;
        let extent_key = (frame, gpa, length);
        let extent_references = frames
            .extent_references
            .get(&extent_key)
            .copied()
            .unwrap_or_default()
            .checked_add(1)
            .ok_or_else(|| {
                TrapError::Hypervisor(format!(
                    "HVPatch physical extent {extent_key:?} reference count exhausted"
                ))
            })?;
        let stage2_lease = stage2_lease.unwrap_or((gpa, length));
        if is_reusable_global_frame_extent(stage2_lease.0, stage2_lease.1) {
            match global_frame_host_owner_identity_in(custody, stage2_lease.0, stage2_lease.1) {
                Some(live)
                    if stage2_owner.generation != 0
                        && live == (stage2_owner.host_addr, stage2_owner.generation) => {}
                Some(live) => {
                    return Err(TrapError::Hypervisor(format!(
                        "HVPatch inventory stage-2 owner is not live: lease={stage2_lease:?} owner={stage2_owner:?} live={live:?}"
                    )));
                }
                None if stage2_owner.generation == 0 => {}
                None => {
                    return Err(TrapError::Hypervisor(format!(
                        "HVPatch inventory stage-2 owner is not live: lease={stage2_lease:?} owner={stage2_owner:?} live=None"
                    )));
                }
            }
        }
        let stage2_references = frames
            .stage2_references
            .get(&stage2_lease)
            .copied()
            .unwrap_or_default()
            .checked_add(1)
            .ok_or_else(|| {
                TrapError::Hypervisor(format!(
                    "HVPatch stage-2 lease {stage2_lease:?} reference count exhausted"
                ))
            })?;
        // Owner authentication and every fallible count calculation complete
        // before the shared registry is mutated. A rejected publication has no
        // InventoryExtent for rollback to discover, so partial insertion here
        // would manufacture phantom frame authority permanently.
        frames.references.insert(frame, frame_references);
        frames
            .extent_references
            .insert(extent_key, extent_references);
        frames
            .stage2_references
            .insert(stage2_lease, stage2_references);
        if matches!(backing, InventoryBackingIdentity::SharedFile { .. }) {
            // From this point the frame is REUSABLE by the next installer of
            // the same file (the `existing` lookup above), and a reuser's batch
            // names it without reserving it. The authority accepts that only
            // once this frame is published, so whoever stages a fresh shared
            // frame must publish it before releasing the topology lock the
            // staging ran under (`vcpu_loop` alias-install arm). Publishing
            // after the release let a reuser publish first and aborted the
            // carrier with `UnreservedFrame` (2026-09-08).
            frames.shared.entry(backing).or_insert(frame);
        }
        drop(frames);
        let extent = InventoryExtent {
            frame,
            mapping,
            backing,
            stage2_base: stage2_lease.0,
            stage2_length: stage2_lease.1,
            stage2_owner,
        };
        inventory.extents.insert((gpa, length), extent);
        Ok(extent)
    }

    #[cfg(test)]
    fn stage_mapping(
        inventory: &mut HvpatchFrameInventory,
        reservation: &mut carrick_hal::FrameInventoryReservation,
        stage: InventoryMappingStage,
    ) -> Result<InventoryExtent, TrapError> {
        Self::stage_mapping_in(
            legacy_test_carrier_vm_custody(),
            inventory,
            reservation,
            stage,
        )
    }

    pub(crate) fn rollback_unpublished_mappings(
        inventory: &mut HvpatchFrameInventory,
        mappings: &[((u64, u64), InventoryExtent)],
    ) -> Result<(), TrapError> {
        let mut registry = inventory.frames.lock();
        for &(key, expected) in mappings.iter().rev() {
            let actual = inventory.extents.remove(&key).ok_or_else(|| {
                TrapError::Hypervisor(format!("HVPatch unpublished mapping rollback lost {key:?}"))
            })?;
            if actual.mapping != expected.mapping || actual.frame != expected.frame {
                return Err(TrapError::Hypervisor(format!(
                    "HVPatch unpublished mapping rollback identity drifted at {key:?}"
                )));
            }
            decrement_inventory_reference(&mut registry.references, actual.frame)?;
            decrement_inventory_reference(
                &mut registry.extent_references,
                (actual.frame, key.0, key.1),
            )?;
            decrement_inventory_reference(
                &mut registry.stage2_references,
                (actual.stage2_base, actual.stage2_length),
            )?;
            if matches!(actual.backing, InventoryBackingIdentity::SharedFile { .. })
                && !registry.references.contains_key(&actual.frame)
            {
                registry.shared.remove(&actual.backing);
            }
        }
        Ok(())
    }

    fn stage_retirement(
        inventory: &mut HvpatchFrameInventory,
        reservation: &mut carrick_hal::FrameInventoryReservation,
        authority: &dyn carrick_hal::FrameCowAuthority,
    ) -> Result<std::collections::BTreeSet<(u64, u64)>, TrapError> {
        let mut candidate_extents = Vec::with_capacity(inventory.extents.len());
        for (&(gpa, mapping_length), extent) in &inventory.extents {
            let non_zero_len = std::num::NonZeroU64::new(mapping_length).ok_or_else(|| {
                TrapError::Hypervisor(format!(
                    "HVPatch retirement contains empty extent at IPA 0x{gpa:x}"
                ))
            })?;
            candidate_extents.push((
                extent.mapping,
                extent.frame,
                carrick_guest_mem::Gpa(gpa),
                carrick_hal::FrameLength::from_mapping_extent(non_zero_len),
            ));
        }

        let mut local_frame_references =
            std::collections::BTreeMap::<carrick_hal::FrameId, usize>::new();
        for extent in inventory.extents.values() {
            let local = local_frame_references.entry(extent.frame).or_default();
            *local = local.checked_add(1).ok_or_else(|| {
                TrapError::Hypervisor(format!(
                    "HVPatch frame {:?} local retirement count exhausted",
                    extent.frame
                ))
            })?;
        }
        let candidate_frames: Vec<carrick_hal::FrameId> =
            local_frame_references.keys().copied().collect();

        let (extent_liveness, frame_counts) = authority
            .retirement_batch_query(&candidate_extents, &candidate_frames)
            .map_err(|error| {
                TrapError::Hypervisor(format!(
                    "query process-terminal frame inventory retirement batch: {error}"
                ))
            })?;

        for (i, &exact_live) in extent_liveness.iter().enumerate() {
            if !exact_live {
                return Err(TrapError::Hypervisor(format!(
                    "HVPatch process retirement mapping {:?} is not exact-live for retiring mm",
                    candidate_extents[i].0
                )));
            }
        }

        let authoritative_counts: std::collections::BTreeMap<carrick_hal::FrameId, Option<usize>> =
            candidate_frames.into_iter().zip(frame_counts).collect();

        let transaction = reservation.transaction();
        for extent in inventory.extents.values() {
            reservation
                .push(carrick_hal::FrameInventoryEvent::UnmapMapping {
                    transaction,
                    mapping: extent.mapping,
                    generation: Self::inventory_generation(2),
                })
                .map_err(Self::reservation_error)?;
        }
        let mut local_stage2_references = std::collections::BTreeMap::new();
        for extent in inventory.extents.values() {
            *local_stage2_references
                .entry((extent.stage2_base, extent.stage2_length))
                .or_insert(0usize) += 1;
        }

        let mut frames = inventory.frames.lock();
        let mut retired = std::collections::BTreeSet::new();
        let mut complete_frames = std::collections::BTreeSet::new();
        for (&frame, &local) in &local_frame_references {
            let global = frames.references.get(&frame).copied().ok_or_else(|| {
                TrapError::Hypervisor(format!("HVPatch frame {frame:?} has no backend reference"))
            })?;
            if global < local {
                return Err(TrapError::Hypervisor(format!(
                    "HVPatch frame {frame:?} backend reference count underflow"
                )));
            }
            let authoritative = authoritative_counts.get(&frame).copied().flatten();
            if authoritative == Some(global) {
                complete_frames.insert(frame);
            }
            // `frames.references` is backend bookkeeping; `RetireFrame` is a
            // claim about the kernel authority's VM-wide mapping population.
            // A sibling mm can therefore keep the frame live even when this
            // retirement removes every backend reference visible here. Require
            // exact agreement before emitting the irreversible frame event.
            if global == local && authoritative == Some(local) {
                retired.insert(frame);
            }
        }
        for (&(gpa, length), extent) in &inventory.extents {
            let key = (extent.frame, gpa, length);
            let references = frames.extent_references.get(&key).copied().ok_or_else(|| {
                TrapError::Hypervisor(format!(
                    "HVPatch physical extent {key:?} has no backend reference"
                ))
            })?;
            if references == 0 {
                return Err(TrapError::Hypervisor(format!(
                    "HVPatch physical extent {key:?} reference count underflow"
                )));
            }
        }
        let mut incomplete_stage2_leases = std::collections::BTreeSet::new();
        for extent in inventory.extents.values() {
            if !complete_frames.contains(&extent.frame) {
                incomplete_stage2_leases.insert((extent.stage2_base, extent.stage2_length));
            }
        }
        let mut retired_stage2 = std::collections::BTreeSet::new();
        let mut stage2_population_complete = std::collections::BTreeMap::new();
        for (&lease, &local) in &local_stage2_references {
            let global = frames
                .stage2_references
                .get(&lease)
                .copied()
                .ok_or_else(|| {
                    TrapError::Hypervisor(format!(
                        "HVPatch stage-2 lease {lease:?} has no backend reference"
                    ))
                })?;
            if global < local {
                return Err(TrapError::Hypervisor(format!(
                    "HVPatch stage-2 lease {lease:?} reference count underflow"
                )));
            }
            let all_frame_populations_complete = !incomplete_stage2_leases.contains(&lease);
            stage2_population_complete.insert(lease, all_frame_populations_complete);
            if global == local && all_frame_populations_complete {
                retired_stage2.insert(lease);
            }
        }
        for &frame in &retired {
            reservation
                .push(carrick_hal::FrameInventoryEvent::RetireFrame {
                    transaction,
                    frame,
                    generation: Self::inventory_generation(2),
                })
                .map_err(Self::reservation_error)?;
        }

        for (&frame, &local) in &local_frame_references {
            let remaining = frames.references[&frame] - local;
            if remaining == 0 {
                frames.references.remove(&frame);
            } else {
                frames.references.insert(frame, remaining);
            }
        }
        for (&(gpa, length), extent) in &inventory.extents {
            let key = (extent.frame, gpa, length);
            let remaining = frames.extent_references[&key] - 1;
            if remaining == 0 {
                frames.extent_references.remove(&key);
            } else {
                frames.extent_references.insert(key, remaining);
            }
            if retired.contains(&extent.frame)
                && matches!(extent.backing, InventoryBackingIdentity::SharedFile { .. })
            {
                frames.shared.remove(&extent.backing);
            }
        }
        for (&lease, &local) in &local_stage2_references {
            let remaining = frames.stage2_references[&lease] - local;
            if remaining == 0 {
                frames.stage2_references.remove(&lease);
            } else {
                frames.stage2_references.insert(lease, remaining);
            }
        }
        for (&lease, &population_complete) in &stage2_population_complete {
            reconcile_carrier_stage2_authority_retention(&mut frames, lease, population_complete);
        }
        drop(frames);
        // Record what this mm owned BEFORE dropping it, so the authority can
        // still authenticate the commit against the exact set it retires.
        let mut expected: Vec<_> = inventory
            .extents
            .values()
            .map(|extent| (extent.mapping, extent.frame))
            .collect();
        expected.sort_unstable();
        expected.dedup();
        inventory.retirement_expected = expected;
        inventory.extents.clear();
        Ok(retired_stage2)
    }

    pub(crate) fn frame_inventory_extent_count(&self) -> usize {
        let inventory = self.frame_inventory.lock();
        if inventory.initialized {
            inventory.extents.len()
        } else {
            self.mappings
                .iter()
                .filter(|mapping| {
                    mapping_belongs_to_task_inventory(self.persistent_vm_lifecycle, mapping)
                })
                .count()
        }
    }

    pub(crate) fn inventory_initial_mappings(
        &mut self,
        mut reservation: carrick_hal::FrameInventoryReservation,
    ) -> Result<carrick_hal::FrameInventoryCommit<()>, TrapError> {
        let mut inventory = self.frame_inventory.lock();
        if !inventory.extents.is_empty() {
            return Ok(reservation.commit(()));
        }
        for region in &self.mappings {
            if !mapping_belongs_to_task_inventory(self.persistent_vm_lifecycle, region) {
                continue;
            }
            let stage2_owner = mapped_region_stage2_owner_identity(region).ok_or_else(|| {
                TrapError::Hypervisor(format!(
                    "HVPatch initial inventory region IPA 0x{:x} has invalid physical owner offset",
                    region.physical_ipa
                ))
            })?;
            Self::stage_mapping_in(
                self.custody(),
                &mut inventory,
                &mut reservation,
                InventoryMappingStage {
                    gpa: region.physical_ipa,
                    length: region.physical_size as u64,
                    permissions: Self::region_permissions(region),
                    backing: Self::private_backing_identity(),
                    inherited_frame: None,
                    stage2_lease: None,
                    stage2_owner,
                },
            )?;
        }
        inventory.initialized = true;
        Ok(reservation.commit(()))
    }

    pub(crate) fn begin_alias_inventory(
        &mut self,
        reservation: carrick_hal::FrameInventoryReservation,
    ) -> Result<(), TrapError> {
        self.frame_inventory.begin_alias_inventory(reservation)
    }

    pub(crate) fn take_alias_inventory(&mut self) -> Option<carrick_hal::FrameInventoryCommit<()>> {
        let mut inventory = self.frame_inventory.lock();
        // Handing the commit off makes the staged extents the authority's
        // business, so they are no longer this transaction's to roll back.
        tracing::trace!(
            staged = inventory.alias_staged.len(),
            commit = inventory.alias_commit.is_some(),
            "hvpatch alias take"
        );
        inventory.alias_staged.clear();
        inventory.alias_commit.take()
    }

    pub(crate) fn abandon_alias_inventory(&mut self) -> bool {
        self.frame_inventory.cancel_alias_inventory()
    }

    pub(crate) fn begin_exec_inventory(
        &mut self,
        retired: Option<carrick_hal::FrameInventoryReservation>,
        replacement: carrick_hal::FrameInventoryReservation,
    ) -> Result<(), TrapError> {
        self.task.begin_exec_inventory(retired, replacement)
    }

    pub(crate) fn inject_next_begin_exec_inventory_failure(&mut self) {
        self.task.fail_next_begin_exec_inventory = true;
    }

    pub(crate) fn frame_inventory_exec_extent_counts(
        &self,
        new_image: &crate::memory::AddressSpace,
    ) -> (usize, usize) {
        let replacement = GuestMappingPlan::from_address_space(new_image)
            .map(|plan| {
                plan.mappings
                    .iter()
                    .filter(|mapping| !is_sparse_hvpatch_mmap_mapping(mapping))
                    .count()
            })
            .unwrap_or(0);
        (self.exec_retired_extent_count(), replacement)
    }

    pub(crate) fn take_exec_inventory(&mut self) -> Option<carrick_hal::ExecInventoryCommits> {
        self.frame_inventory.lock().exec_commits.take()
    }

    pub(crate) fn begin_process_inventory(
        &mut self,
        reservation: carrick_hal::FrameInventoryReservation,
    ) -> Result<(), TrapError> {
        self.frame_inventory.begin_process_inventory(reservation)
    }

    pub(crate) fn cancel_process_inventory(&mut self) -> bool {
        self.frame_inventory.cancel_process_inventory()
    }

    pub(crate) fn take_process_inventory(
        &mut self,
    ) -> Option<carrick_hal::FrameInventoryCommit<()>> {
        self.frame_inventory.lock().process_commit.take()
    }

    pub(crate) fn commit_process_materialization(&mut self) -> Result<(), TrapError> {
        if self.frame_inventory.lock().process_commit.is_none() {
            return Err(TrapError::Hypervisor(
                "HVPatch process materialization has no inventory commit".to_owned(),
            ));
        }
        // Register only after the fresh vCPU register restore succeeds. Until
        // this point the aliases remain an owned, unpublished vector.
        for alias in std::mem::take(&mut self.pending_process_aliases) {
            register_shared_alias(alias);
            record_cow_alias_lifecycle(
                CowDiagnosticLifecycleKind::AliasPublished,
                CowDiagnosticLifecycleSite::ProcessMaterialization,
                Some(self.custody()),
                self.cow_identity,
                self.mm_root_slot,
                alias,
            );
        }
        Ok(())
    }

    pub(crate) fn refresh_fork_process_state(
        &mut self,
        flush_stage1: &mut dyn FnMut() -> Result<(), TrapError>,
    ) -> Result<(), TrapError> {
        let custody = std::sync::Arc::clone(&self.carrier_foreign_mm_transport.custody);
        self.task
            .refresh_fork_process_state_in(&custody, flush_stage1)
    }

    pub(crate) fn abort_process_materialization(&mut self) -> Result<(), TrapError> {
        self.pending_process_aliases.clear();
        self.pending_fork_frame_receipts.clear();
        {
            let mut inventory = self.frame_inventory.lock();
            let staged: Vec<_> = inventory
                .extents
                .iter()
                .map(|(&key, &extent)| (key, extent))
                .collect();
            Self::rollback_unpublished_mappings(&mut inventory, &staged)?;
            drop(inventory.process_commit.take());
        }
        // Fresh per-mm mappings own their stage-2 leases; inherited mappings
        // are non-owning. Dropping this vector therefore unmaps/releases only
        // unpublished child-local extents.
        drop(std::mem::take(&mut self.mappings));
        self.mm_root_slot = None;
        Ok(())
    }

    pub(crate) fn begin_retirement_inventory(
        &mut self,
        reservation: carrick_hal::FrameInventoryReservation,
    ) -> Result<(), TrapError> {
        let mut inventory = self.frame_inventory.lock();
        if inventory.retirement_reservation.is_some() {
            return Err(TrapError::Hypervisor(
                "overlapping HVPatch retirement inventory transaction".to_owned(),
            ));
        }
        inventory.retirement_reservation = Some(reservation);
        Ok(())
    }

    pub(crate) fn take_retirement_inventory(
        &mut self,
    ) -> Option<carrick_hal::FrameInventoryCommit<()>> {
        self.frame_inventory.lock().retirement_commit.take()
    }

    pub(crate) fn page_tables_snapshot(&self) -> Option<crate::page_table::PageTableManager> {
        self.page_tables_authority().snapshot_image()
    }

    pub(crate) fn bind_stage1_page_tables(
        &mut self,
        page_tables: carrick_aarch64::Stage1Authority,
    ) {
        page_tables.emit_bind_probe();
        tracing::debug!(
            target: "carrick::stage1_arena",
            authority = page_tables.authority_id() as usize,
            present = page_tables.is_present(),
            has_source = page_tables.has_source(),
            arenas = page_tables.pool_stats().map_or(0, |s| s.3),
            "bind stage-1 page tables"
        );
        self.mm_access.bind_page_tables_authority(page_tables);
    }

    pub(crate) fn task_runtime_authorities_match(
        &self,
        mm_access: &std::sync::Arc<MmAccessState>,
        page_tables: &carrick_aarch64::Stage1Authority,
        protections: &std::sync::Arc<MemoryProtections>,
    ) -> bool {
        self.task
            .runtime_authorities_match(mm_access, page_tables, protections)
    }

    pub(crate) fn task_mm_access_authority(&self) -> std::sync::Arc<MmAccessState> {
        self.task.mm_access_authority()
    }

    pub(crate) fn task_protections_authority(&self) -> std::sync::Arc<MemoryProtections> {
        std::sync::Arc::clone(&self.protections)
    }

    /// Tell `manager` whether THIS thread's edit is exclusive, before an
    /// HVPatch mapping publication that locks `self.page_tables` directly.
    ///
    /// `Aarch64EngineCore::pt_edit_locked` pushes the same answer for every
    /// edit that goes through the engine, but the HVPatch publications below
    /// take the lock themselves and would otherwise allocate spare sub-tables
    /// under whatever marker the PREVIOUS editor happened to leave behind.
    /// The marker gates `alloc_table`'s last-resort reclaim sweep, so a stale
    /// `false` turns a recoverable pool into `OutOfTables` -> guest `ENOMEM`:
    /// cpython `concurrent_futures` raised `MemoryError` out of a 16 KiB
    /// anonymous `mmap` whose own syscall dispatch DID hold exclusivity.
    ///
    /// Only exclusivity is refreshed. `multi_vcpu` gates the EAGER coalescing
    /// scan, which is a throughput decision this path must not silently flip
    /// (enabling it cost `go-net_http` 50 s -> over 200 s).
    fn refresh_stage1_exclusivity(manager: &mut crate::page_table::PageTableManager) {
        manager.set_stage1_exclusive(
            carrick_hal::stage1_exclusive::current_thread_edits_exclusively(),
        );
    }

    /// Complete pre-transaction image of `manager`, taken into the recycled
    /// buffer when one is available.
    ///
    /// This is byte-for-byte what `manager.clone()` produced before; the only
    /// change is that a returned buffer is refilled in place instead of asking
    /// the allocator for another 1.75 MiB region. See `cow_rollback_scratch`.
    fn rollback_pre_image(
        scratch: &mut Option<crate::page_table::PageTableManager>,
        manager: &crate::page_table::PageTableManager,
    ) -> crate::page_table::PageTableManager {
        match scratch.take() {
            Some(mut reused) => {
                reused.clone_from(manager);
                reused
            }
            None => manager.clone(),
        }
    }

    pub(crate) fn retire_process_mappings(&mut self) -> Result<(), TrapError> {
        Self::retire_task_state_process_mappings(&mut self.task)
    }

    pub(crate) fn retire_task_state_process_mappings(
        task: &mut HvfTaskState,
    ) -> Result<(), TrapError> {
        Self::retire_task_state_process_mappings_inner(task, None).map(|_| ())
    }

    pub(crate) fn retire_task_state_process_mappings_with_root_proof(
        task: &mut HvfTaskState,
        expected_root_slot: (u64, u64),
    ) -> Result<HvpatchMmRootRetirementProof, TrapError> {
        Self::retire_task_state_process_mappings_inner(task, Some(expected_root_slot))?.ok_or_else(
            || {
                TrapError::Hypervisor(
                    "HVPatch process retirement produced no stage-1 root proof".to_owned(),
                )
            },
        )
    }

    fn retire_task_state_process_mappings_inner(
        task: &mut HvfTaskState,
        expected_root_slot: Option<(u64, u64)>,
    ) -> Result<Option<HvpatchMmRootRetirementProof>, TrapError> {
        /// Answer "which mapping rows contain `[ipa, ipa + length)`" for terminal
        /// retirement without re-walking every row per inventory extent.
        ///
        /// Process-terminal retirement asks that question once per inventory
        /// extent. Written directly as `task.mappings.iter().filter(..)` it is
        /// O(extents x rows): a CPython `test_compile` guest retires with 33,471
        /// inventory extents against 33,478 mapping rows, so one executor spins
        /// through ~1.1e9 row visits inside
        /// [`HvfVmState::retire_task_state_process_mappings_inner`] while its
        /// Linux task is already a zombie. That is the shape the always-on
        /// process-graph liveness sink reports as "1 container job(s) unpublished
        /// with 0 live task(s), 1 live thread(s) and 0 runnable row(s) for
        /// 2000ms" (`carrick run` rc 125): nothing is deadlocked, the settlement
        /// that publishes the container job is simply still queued behind a
        /// quadratic sweep.
        ///
        /// [`TaskMappingIndex::by_ipa`] cannot serve this query. It orders the
        /// SEMANTIC `ipa`/`size` projection, while every lifetime decision here
        /// must use the exact `physical_ipa`/`physical_size` tuple — a partial
        /// 4 KiB Linux mapping can retain a 16 KiB physical owner whose base
        /// precedes its semantic view. This index is therefore built once per
        /// retirement, from a single pass over the rows, and covers displaced
        /// rows as well as live ones because the scan it replaces did.
        struct PhysicalExtentIndex<'rows> {
            /// Rows ascending by `physical_ipa`.
            rows: Vec<&'rows HvfMappedRegion>,
            /// `rows[i].physical_ipa`, kept apart for the binary search.
            starts: Vec<u64>,
            /// `max(physical end of rows[0..=i])`. Non-decreasing, so a descending
            /// walk stops at the first index whose prefix maximum can no longer
            /// reach the query end: no earlier row reaches further either.
            prefix_max_end: Vec<u64>,
        }

        impl<'rows> PhysicalExtentIndex<'rows> {
            fn build(rows: impl Iterator<Item = &'rows HvfMappedRegion>) -> Self {
                let mut rows: Vec<&'rows HvfMappedRegion> = rows.collect();
                rows.sort_unstable_by_key(|row| row.physical_ipa);
                let starts = rows.iter().map(|row| row.physical_ipa).collect::<Vec<_>>();
                let mut prefix_max_end = Vec::with_capacity(rows.len());
                let mut running = 0u64;
                for row in &rows {
                    running = running.max(Self::physical_end(row));
                    prefix_max_end.push(running);
                }
                Self {
                    rows,
                    starts,
                    prefix_max_end,
                }
            }

            fn physical_end(row: &HvfMappedRegion) -> u64 {
                row.physical_ipa.saturating_add(row.physical_size as u64)
            }

            /// Every row whose exact stage-2 physical extent contains
            /// `[ipa, ipa + length)`, in no particular order — both consumers ask
            /// `any`/`iter().any`, so order carries no meaning here.
            fn containing(
                &self,
                ipa: u64,
                length: u64,
            ) -> impl Iterator<Item = &'rows HvfMappedRegion> {
                let end = ipa.checked_add(length);
                let upper = self.starts.partition_point(|start| *start <= ipa);
                let prefix_max_end = &self.prefix_max_end;
                let rows = &self.rows;
                (0..upper)
                    .rev()
                    .take_while(move |&position| {
                        end.is_some_and(|end| prefix_max_end[position] >= end)
                    })
                    .map(move |position| rows[position])
                    .filter(move |row| end.is_some_and(|end| end <= Self::physical_end(row)))
            }
        }

        #[cfg(not(test))]
        let custody = std::sync::Arc::clone(&task.custody);
        #[cfg(not(test))]
        let custody = custody.as_ref();
        #[cfg(test)]
        let custody = legacy_test_carrier_vm_custody();
        // Mature VMM processes own a private VM and retain the historical
        // teardown path; only the persistent single-VM HVPatch lane publishes
        // per-process frame-inventory retirement.
        if !task.persistent_vm_lifecycle {
            return Ok(None);
        }
        let authority = task.cow_authority.as_ref().cloned().ok_or_else(|| {
            TrapError::Hypervisor(
                "HVPatch process retirement has no frame inventory authority".to_owned(),
            )
        })?;
        // The runtime holds the process-wide HVPatch topology lock across this
        // method. Stage the backend inventory retirement BEFORE recycling any
        // physical extent. The old order sampled `stage2_references`, dropped
        // that lock, recycled the IPA, and only later removed this mm's
        // references. A sibling publication in that window could retain the
        // old extent after its global owner was gone; the allocator then handed
        // the IPA to a COW transaction whose per-mm inventory still contained
        // that key (`HVPatch COW new inventory extent collided`).
        let ledger = std::sync::Arc::clone(&task.frame_inventory.ledger);
        let (candidates, frames, retirement_commit, stage2_owners) = {
            let mut inventory = ledger.lock();
            if inventory.extents.is_empty() {
                if task.mappings.is_empty() {
                    return Ok(None);
                }
                return Err(TrapError::Hypervisor(
                    "HVPatch process retirement has mappings without frame inventory authority"
                        .to_owned(),
                ));
            }
            if inventory.retirement_reservation.is_none() {
                return Err(TrapError::Hypervisor(
                    "HVPatch retirement began without frame inventory reservation".to_owned(),
                ));
            }

            // Validate every physical candidate extent in inventory before
            // performing any logical mutation. The inventory records the
            // owner identity that was live at publication; `task.mappings`
            // deliberately retains historical rows and therefore cannot be
            // used to reconstruct one generation at terminal retirement.
            //
            // One pass builds the physical-extent index the per-extent
            // containment queries below read; see `PhysicalExtentIndex` for
            // why the direct per-extent scan is the exit residual.
            let mapping_extents = PhysicalExtentIndex::build(task.mappings.iter());
            let mut stage2_owners = std::collections::BTreeMap::new();
            for (&(_gpa, mapping_length), extent) in &inventory.extents {
                if mapping_length == 0 {
                    return Err(TrapError::Hypervisor(
                        "HVPatch process retirement inventory has zero-length mapping".to_owned(),
                    ));
                }
                let ipa = extent.stage2_base;
                let length = extent.stage2_length;
                let _size =
                    usize::try_from(length).map_err(|_| TrapError::MappingTooLarge(length))?;
                let lease = (ipa, length);
                if let Some(previous) = stage2_owners.insert(lease, extent.stage2_owner)
                    && previous != extent.stage2_owner
                {
                    return Err(TrapError::Hypervisor(format!(
                        "HVPatch process retirement lease {lease:?} has conflicting inventory owner identities {previous:?} and {:?}",
                        extent.stage2_owner
                    )));
                }
                let matching_rows: Vec<_> = mapping_extents
                    .containing(ipa, length)
                    .filter_map(|mapping| {
                        mapped_region_stage2_owner_identity(mapping).map(|identity| {
                            (
                                identity,
                                mapping
                                    .stage2_lease
                                    .as_ref()
                                    .map(|lease| (lease.key(), lease.active, lease.mapped)),
                                mapping.is_dynamic_alias,
                            )
                        })
                    })
                    .collect();
                if is_reusable_global_frame_extent(ipa, length) {
                    let live_owner = global_frame_host_owner_identity_in(custody, ipa, length);
                    if extent.stage2_owner.generation == 0 {
                        if live_owner.is_some() {
                            return Err(TrapError::Hypervisor(format!(
                                "HVPatch process retirement unowned lease {lease:?} unexpectedly has live global owner {live_owner:?}"
                            )));
                        }
                        let local_lease = matching_rows.iter().any(|(identity, local, _)| {
                            *identity == extent.stage2_owner
                                && local.is_some_and(|((key_base, key_len), active, mapped)| {
                                    key_base <= ipa
                                        && ipa
                                            .checked_add(length)
                                            .is_some_and(|end| end <= key_base + key_len)
                                        && active
                                        && mapped
                                })
                        });
                        let carrier_lease = carrier_stage2_lease_owner_matches(
                            custody,
                            ipa,
                            length,
                            extent.stage2_owner.host_addr,
                        );
                        // Generation-zero extents have no global owner identity to
                        // authenticate. They therefore still require an exact
                        // live task or carrier lease. Nonzero extents are different:
                        // the inventory captured their complete host/generation
                        // identity at publication and the global-owner comparison
                        // below authenticates it directly. A detached task-only
                        // reload may legitimately omit a duplicate runtime-created
                        // mapping row while retaining that inventory authority.
                        if !local_lease && !carrier_lease {
                            return Err(TrapError::Hypervisor(format!(
                                "HVPatch process retirement reusable unowned lease {lease:?} has no exact local or carrier lease"
                            )));
                        }
                    } else {
                        match live_owner {
                            Some(live)
                                if live
                                    == (
                                        extent.stage2_owner.host_addr,
                                        extent.stage2_owner.generation,
                                    ) => {}
                            Some((live_host, live_generation))
                                if live_generation == extent.stage2_owner.generation =>
                            {
                                return Err(TrapError::Hypervisor(format!(
                                    "HVPatch process retirement owner pointer drifted for lease {lease:?}: inventory={:?} live=({live_host}, {live_generation})",
                                    extent.stage2_owner
                                )));
                            }
                            // A different live generation is a successor owner.
                            // This stale mm may retire its logical inventory but
                            // must leave the successor's physical lease untouched.
                            Some(_) => {}
                            None => {
                                return Err(TrapError::Hypervisor(format!(
                                    "HVPatch process retirement owned lease {lease:?} expected inventory owner {:?} but the owner is absent",
                                    extent.stage2_owner
                                )));
                            }
                        }
                    }
                } else {
                    let local_lease = matching_rows.iter().any(|(identity, local, _)| {
                        *identity == extent.stage2_owner
                            && local.is_some_and(|((key_base, key_len), active, mapped)| {
                                key_base <= ipa
                                    && ipa
                                        .checked_add(length)
                                        .is_some_and(|end| end <= key_base + key_len)
                                    && active
                                    && mapped
                            })
                    }) || mapping_extents.containing(ipa, length).any(|m| {
                        extent.stage2_owner.generation == 0
                            || m.owner_generation == extent.stage2_owner.generation
                            || m.structural_owner.as_ref().is_some_and(|owner| {
                                owner.epoch().raw() == extent.stage2_owner.generation
                            })
                    });
                    let carrier_lease = carrier_stage2_lease_owner_matches(
                        custody,
                        ipa,
                        length,
                        extent.stage2_owner.host_addr,
                    );
                    if !local_lease
                        && !carrier_lease
                        && take_carrier_stage2_record(custody, ipa, length).is_none()
                    {
                        return Err(TrapError::Hypervisor(format!(
                            "HVPatch process retirement structural lease {lease:?} has no exact local, structural, or carrier lease"
                        )));
                    }
                }
            }

            let frames = std::sync::Arc::clone(&inventory.frames);
            let mut reservation = inventory.retirement_reservation.take().unwrap_or_else(|| {
                carrick_fatal!(
                    "hvpatch::frame_inventory",
                    "validated HVPatch retirement reservation disappeared before candidate staging"
                );
            });
            let diagnostic_extents = if cow_refusal_diagnostics_enabled() {
                inventory
                    .extents
                    .iter()
                    .map(|(&key, &extent)| (key, extent))
                    .collect::<Vec<_>>()
            } else {
                Vec::new()
            };
            let candidates =
                Self::stage_retirement(&mut inventory, &mut reservation, authority.as_ref())?;
            for (key, extent) in diagnostic_extents {
                record_cow_inventory_lifecycle(
                    CowDiagnosticLifecycleKind::InventoryRemoved,
                    CowDiagnosticLifecycleSite::ProcessRetirement,
                    custody,
                    task.cow_identity,
                    task.mm_root_slot,
                    0,
                    0,
                    key,
                    extent,
                );
            }
            (candidates, frames, reservation.commit(()), stage2_owners)
        };

        // `stage_mapping` increments the same registry while holding this exact
        // lock. Recheck each stale candidate and keep the lock through owner
        // removal/allocator release: publication either wins first and keeps
        // the extent live, or retirement wins first and no later publication
        // can inherit the recycled owner.
        let mut extents = std::collections::BTreeSet::new();
        let mut superseded_owners = std::collections::BTreeMap::new();
        for &(ipa, length) in &candidates {
            let size = usize::try_from(length).map_err(|_| TrapError::MappingTooLarge(length))?;
            let lease = (ipa, length);
            let owner = stage2_owners.get(&lease).copied().ok_or_else(|| {
                TrapError::Hypervisor(format!(
                    "HVPatch process retirement candidate {lease:?} lost inventory owner identity"
                ))
            })?;
            if is_reusable_global_frame_extent(ipa, length) {
                let live_owner = global_frame_host_owner_identity_in(custody, ipa, length);
                if owner.generation == 0 {
                    if live_owner.is_some() {
                        return Err(TrapError::Hypervisor(format!(
                            "HVPatch process retirement unowned candidate {lease:?} unexpectedly has live global owner {live_owner:?}"
                        )));
                    }
                    if Self::retire_stage2_candidate_if_unreferenced(&frames, lease, || {
                        Self::retire_unowned_stage2_extent_from_mappings_in(
                            custody,
                            &mut task.mappings,
                            ipa,
                            length,
                            owner.host_addr,
                        )
                    })? {
                        extents.insert((ipa, size));
                    }
                } else if live_owner == Some((owner.host_addr, owner.generation)) {
                    if Self::retire_stage2_candidate_if_unreferenced(&frames, lease, || {
                        let outcome = retire_global_frame_host_owner_if_generation_in(
                            custody,
                            ipa,
                            length,
                            owner.generation,
                        );
                        match outcome {
                            GlobalFrameRetirementOutcome::RetiredUnmapped { .. }
                            | GlobalFrameRetirementOutcome::TerminalizedByVmDestroy { .. }
                            | GlobalFrameRetirementOutcome::DeferredActivePins { .. }
                            | GlobalFrameRetirementOutcome::RetryPending { .. } => Ok(()),
                            outcome => Err(TrapError::Hypervisor(format!(
                                "HVPatch process retirement owner identity drifted for lease {lease:?}: {outcome:?}"
                            ))),
                        }
                    })? {
                        extents.insert((ipa, size));
                    }
                } else if let Some((live_host, live_generation)) = live_owner {
                    if live_generation == owner.generation {
                        return Err(TrapError::Hypervisor(format!(
                            "HVPatch process retirement candidate owner pointer drifted for lease {lease:?}: inventory={owner:?} live=({live_host}, {live_generation})"
                        )));
                    }
                    // Stale cleanup: a successor owner is live; leave it untouched.
                    superseded_owners.insert(lease, owner);
                } else {
                    return Err(TrapError::Hypervisor(format!(
                        "HVPatch process retirement owned candidate {lease:?} expected inventory owner {owner:?} but the owner is absent"
                    )));
                }
            } else {
                if Self::retire_stage2_candidate_if_unreferenced(&frames, lease, || {
                    Self::retire_stage2_extent_from_mappings_in(
                        custody,
                        &mut task.mappings,
                        ipa,
                        length,
                    )
                })? {
                    extents.insert((ipa, size));
                }
            }
        }
        let retired_root = expected_root_slot
            .map(|root_slot| task.mm_access.retire_mm_root_stage2_in(custody, root_slot))
            .transpose()?;
        if let Some(root) = &retired_root {
            extents.insert(root.physical_extent);
        }
        let retiring_aliases = if cow_refusal_diagnostics_enabled() {
            alias_registry()
                .lock()
                .process_visible_ordered(task.mm_root_slot, task.container_root)
        } else {
            Vec::new()
        };
        retire_process_aliases(task.mm_root_slot, task.container_root, |alias| {
            let key = (alias.physical_ipa, alias.physical_size as u64);
            let retired_exact_owner = superseded_owners.get(&key).is_some_and(|owner| {
                owner.host_addr == alias.physical_host_addr
                    && owner.generation == alias.owner_generation
            });
            !extents.contains(&(alias.physical_ipa, alias.physical_size)) && !retired_exact_owner
        });
        record_alias_unmap_lifecycle(
            CowDiagnosticLifecycleSite::ProcessRetirement,
            custody,
            task.cow_identity,
            task.mm_root_slot,
            task.container_root,
            &retiring_aliases,
        );

        // A retained shared extent still points at its original host allocation.
        // Reclaim only exact extents removed above and preserve the remaining
        // backing until the single VM is finally destroyed.
        let mut retained_backings = Vec::new();
        for mapping in std::mem::take(&mut task.mappings) {
            if extents.contains(&(mapping.physical_ipa, mapping.physical_size)) {
                drop(mapping);
            } else {
                retained_backings.push(mapping);
            }
        }
        std::mem::forget(retained_backings);
        task.mm_root_slot = None;

        ledger.lock().retirement_commit = Some(retirement_commit);
        Ok(retired_root.map(|root| root.proof))
    }

    pub(crate) fn retire_task_state_mm_root_only(
        task: &mut HvfTaskState,
        expected_root_slot: (u64, u64),
    ) -> Result<HvpatchMmRootRetirementProof, TrapError> {
        #[cfg(not(test))]
        let custody = std::sync::Arc::clone(&task.custody);
        #[cfg(not(test))]
        let custody = custody.as_ref();
        #[cfg(test)]
        let custody = legacy_test_carrier_vm_custody();
        if !task.persistent_vm_lifecycle {
            return Err(TrapError::Hypervisor(
                "stage-1 root-only retirement requires persistent HVPatch lifecycle".to_owned(),
            ));
        }
        let retired = task
            .mm_access
            .retire_mm_root_stage2_in(custody, expected_root_slot)?;
        task.mm_root_slot = None;
        Ok(retired.proof)
    }

    pub(crate) fn take_task_state_retirement_inventory(
        task: &mut HvfTaskState,
    ) -> Option<carrick_hal::FrameInventoryCommit<()>> {
        task.frame_inventory.lock().retirement_commit.take()
    }

    pub(crate) fn retire_task_state_exec_predecessor(
        task: &mut HvfTaskState,
    ) -> Result<(), TrapError> {
        let mut cleanup = task.pending_exec_stage2_cleanup.take().ok_or_else(|| {
            TrapError::Hypervisor(
                "detached exec successor lost predecessor stage-2 cleanup authority".to_owned(),
            )
        })?;
        cleanup.retire()
    }

    pub(crate) fn retire_task_state_exec_predecessor_with_root_proof(
        task: &mut HvfTaskState,
        expected_root_slot: (u64, u64),
    ) -> Result<HvpatchMmRootRetirementProof, TrapError> {
        let mut cleanup = task.pending_exec_stage2_cleanup.take().ok_or_else(|| {
            TrapError::Hypervisor(
                "detached exec successor lost predecessor stage-2 cleanup authority".to_owned(),
            )
        })?;
        cleanup.retire_with_root_proof(expected_root_slot)
    }

    pub(crate) fn retire_task_state_dormant_authority(
        task: &mut HvfTaskState,
    ) -> Result<(), TrapError> {
        if let Some(reg) = &mut task.registration {
            reg.retire_dormant_authority();
        }
        Ok(())
    }

    fn seed_readonly_spans_from_plan(&self, plan: &GuestMappingPlan) {
        for span in &plan.ro_spans {
            let Ok(len) = usize::try_from(span.len) else {
                continue;
            };
            self.protections.set_no_write(span.start, len, true);
        }
    }

    /// Create the VM + the (one) vCPU, map the guest address space, program the
    /// initial vCPU sysregs/trampoline, and return the `(state_without_vcpu,
    /// vcpu)` pair the shared engine owns separately. Consolidates the old
    /// `HvfTrapEngine::new_platform` + `map_plan` + the initial-PC/SPSR/SCTLR/
    /// TTBR/CPACR/CNTKCTL/VBAR/SP/vdso setup into one constructor.
    pub(crate) fn new_with_plan(
        plan: &GuestMappingPlan,
    ) -> Result<(HvfVmState, applevisor::vcpu::Vcpu, MailboxBinding), TrapError> {
        let mut pending_creation = None;
        let result = Self::new_with_plan_inner(plan, &mut pending_creation);
        finish_pending_vm_creation(pending_creation, result)
    }

    fn new_with_plan_inner(
        plan: &GuestMappingPlan,
        pending_creation: &mut Option<PendingCarrierVmCreation>,
    ) -> Result<(HvfVmState, applevisor::vcpu::Vcpu, MailboxBinding), TrapError> {
        use applevisor::prelude::*;

        // Carrier reuse: when this carrier already owns a VM, a new container's
        // root boots INSIDE it. Its image is placed the way `execve_rebuild`
        // places a replacement image (global-frame stage-2 leases + rebased
        // stage-1 tables), so two live roots never collide on identity IPAs,
        // and the five carrier control mappings are shared, not re-mapped.
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
            permit,
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
        let vcpu = SetupVcpuGuard::new(
            if carrier.is_some() {
                // Existing-VM vCPU: admitted by the in-process scheduler, like a
                // thread sibling (see `create_vcpu`).
                create_vcpu(&vm)?
            } else {
                create_vcpu_with_permit(&vm, permit)?
            },
            if carrier.is_some() {
                SetupVcpuCleanup::LocalRaii
            } else {
                SetupVcpuCleanup::PendingRaw
            },
        );
        if let Some(creation) = pending_creation.as_mut() {
            creation.record_vcpu(vcpu.id());
        }
        enable_el0_counter_access(vcpu.id());

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
            reclaim_authority: ReclaimParkAuthority::Live,
            mailbox_slots,
            syscall_transport,
            vcpu_id: vcpu.id(),
            vcpu_handle: vcpu.get_handle(),
            _vcpu_guard: Some(vcpu_census().created()),
        };
        state.publish_live_vcpu();
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
                    let install = exec_stage2_install(mapping, &region);
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

        // Start PC: if an EL0 entry trampoline is installed, the vCPU begins
        // at the trampoline page (in EL1h) and executes the single `eret`
        // there to drop into EL0t at the real user entry. Otherwise the vCPU
        // starts directly at the user entry (used by the existing EL1-only
        // unit tests).
        let initial_pc = plan.el0_trampoline_entry.unwrap_or(plan.entry);
        vcpu.set_reg(Reg::PC, initial_pc).map_err(hvf_error)?;
        // M[3:0]=0b0101 = EL1h (AArch64 EL1 using SP_EL1) + DAIF masked.
        // HVF reset CPSR is also EL1h; we set it explicitly so a re-entry
        // after a syscall trap doesn't depend on whatever HVF left in place.
        // The vCPU stays at EL1h until the trampoline `eret` swaps PSTATE
        // for the SPSR_EL1 value programmed below.
        const AARCH64_PSTATE_EL1H_DAIF_MASKED: u64 = 0x3c5;
        vcpu.set_reg(Reg::CPSR, AARCH64_PSTATE_EL1H_DAIF_MASKED)
            .map_err(hvf_error)?;
        // When using the trampoline, stage SPSR_EL1 with "AArch64 EL0t, DAIF
        // masked" (M[3:0]=0b0000) and ELR_EL1 with the user-mode entry. The
        // `eret` at the trampoline page then transitions to EL0t with
        // PC=plan.entry, which is the state Linux user code expects so the
        // first `svc #0` raises a "lower EL using AArch64" synchronous
        // exception that HVF surfaces to the host.
        if let Some(_trampoline) = plan.el0_trampoline_entry {
            const AARCH64_PSTATE_EL0T_DAIF_MASKED: u64 = 0x3c0;
            vcpu.set_sys_reg(SysReg::SPSR_EL1, AARCH64_PSTATE_EL0T_DAIF_MASKED)
                .map_err(hvf_error)?;
            vcpu.set_sys_reg(SysReg::ELR_EL1, plan.entry)
                .map_err(hvf_error)?;
        }
        // Disable stage-1 MMU translation for the EL0/EL1 guest. Without this,
        // the vCPU's reset value of SCTLR_EL1 has .M=1, which makes every
        // instruction fetch translate through page tables we never built, and
        // the first fetch faults with FSC=Translation fault, level 3. With
        // .M=0 the guest sees stage-2 mappings directly. Bits C/I (caches) are
        // also cleared since we have no maintenance ops yet.
        // SCTLR_EL1 layout:
        //   bit  0 = M  (MMU enable)        — 0: stage-1 MMU off, identity
        //   bit  2 = C  (D-cache enable)    — 1: data accesses cacheable
        //   bit 12 = I  (I-cache enable)    — 1: instruction fetches cacheable
        //   bits 22..21 = SED/UCT etc. (default 0 is fine)
        //   bits 28..23 = RES1 (reserved-as-one); HVF accepts 0 for them.
        // We keep M=0 (no page tables) but set C=1 and I=1 so the memory we
        // use is treated as cacheable Normal memory. ARMv8-A defines
        // exclusive load/store on non-cacheable memory as UNPREDICTABLE,
        // and Apple HVF appears to abort externally rather than treat it as
        // implementation-defined; musl's `ldaxr` on first mutex acquire
        // depends on this.
        // If a stage-1 page-table region is installed, program TTBR0_EL1,
        // TCR_EL1 and MAIR_EL1 to point at our identity-mapping tables,
        // and set SCTLR_EL1.M = 1 so EL0/EL1 data accesses go through
        // the Normal-cacheable mapping. ARMv8-A treats data accesses as
        // Device-nGnRnE memory whenever stage-1 is disabled, and
        // `ldaxr`/`stlxr` on Device memory abort externally — which is
        // exactly the wall musl's pthread_mutex_lock hits otherwise.
        // C=1, I=1 (caches); UCI=1 (bit 26: EL0 cache-maintenance ops DC CVAU/
        // CIVAC/CVAC, IC IVAU — glibc __clear_cache), UCT=1 (bit 15: EL0 read of
        // CTR_EL0 — glibc 2.41 reads cache line sizes at startup; without this
        // the MRS traps to EL1 and crashed CPython), DZE=1 (bit 14: EL0 DC ZVA +
        // DCZID_EL0 read — glibc memset). Matches Linux's SCTLR_EL1 for EL0.
        // Shared bootstrap SCTLR (via GuestArch; canonical rationale in
        // carrick_mem::arch_sysregs) carries M=1 (stage-1 on); HVF enables M
        // only when stage-1 tables exist (below), so start from the value with
        // M cleared and OR M back in there. HVF leaves SPAN(23) CLEAR and
        // forces PSTATE.PAN=1 (FEAT_PAN3) — SPAN is KVM glue, NOT part of the
        // shared value.
        use carrick_hal::GuestArch as _;
        let boot = <HvfTrapEngine as carrick_hal::ThreadedEngine>::Arch::bootstrap_sysregs();
        let mut sctlr_el1: u64 = boot.sctlr_el1 & !1;
        // Stage-1 MMU is on by default. The identity tables use AP=00 for
        // kernel pages (trampoline/vectors/PT) and AP=01+PXN=1 for user
        // pages, which is required on Apple Silicon because HVF starts
        // vCPUs with PSTATE.PAN=1 and FEAT_PAN3 turns any EL1 fetch from
        // an AP[1]=1 page into a permission fault. See
        // `stage1_identity_page_tables` in src/memory.rs.
        if let Some(pt_base) = plan.stage1_page_tables_base {
            // MAIR_EL1 slot 0 = Normal memory, Inner & Outer Write-Back
            // Cacheable, RW-allocate (0xFF). Slot 1..7 stay 0 (Device-
            // nGnRnE), unused for now.
            vcpu.set_sys_reg(SysReg::MAIR_EL1, boot.mair_el1)
                .map_err(hvf_error)?;
            // TCR_EL1: TTBR0 (lower half) and TTBR1 (upper half) BOTH active.
            //   T0SZ = T1SZ = 16 (48-bit VA each half) — wide enough for
            //              Rosetta's fixed ET_EXEC load base at 2^47 AND the
            //              x86-64 high-half (negative) addresses it maps into.
            //   IRGN0/1 = 0b11, ORGN0/1 = 0b11, SH0/1 = 0b11 (Inner WB, Inner
            //              Shareable) for both halves; TG0 = 0b00 (4K),
            //              TG1 = 0b10 (4K — note TG1's encoding differs!).
            //   EPD1 = 0 (TTBR1 walks ENABLED). TTBR1 shares the TTBR0 page-
            //              table root: a walk indexes VA[47:0] regardless of
            //              which TTBR selected it, and carrick's lower-half
            //              mappings + the upper-half alias projections occupy
            //              disjoint L0 slots.
            //   IPS = 0b010 (40-bit IPA, max for M-series HVF — output stays
            //              <=40 bits; high VAs are mapped down to a low IPA).
            //   TBI0/TBI1 = 1: the MMU ignores the top byte on translation —
            //              Rosetta tags pointers in the top byte and asserts
            //              unless hardware ignores it (pairs with the 16-bit
            //              software tag strip in mapping_for_range / mmap).
            // boot.tcr_el1 is the shared bootstrap value via GuestArch
            // (canonical rationale in carrick_mem::arch_sysregs).
            vcpu.set_sys_reg(SysReg::TCR_EL1, boot.tcr_el1)
                .map_err(hvf_error)?;
            vcpu.set_sys_reg(SysReg::TTBR0_EL1, pt_base)
                .map_err(hvf_error)?;
            // TTBR1 shares the same root (see the TCR comment above).
            vcpu.set_sys_reg(SysReg::TTBR1_EL1, pt_base)
                .map_err(hvf_error)?;
            // Enable stage-1 MMU (M=1) on top of the C=1, I=1 flags above.
            sctlr_el1 |= 1;
        }
        vcpu.set_sys_reg(SysReg::SCTLR_EL1, sctlr_el1)
            .map_err(hvf_error)?;
        // Enable FP/SIMD for the guest. Without this, CPACR_EL1.FPEN defaults
        // to "trap at EL0", and musl's `memset` (which uses NEON `dup`/`stp`
        // instructions) faults on its very first call — the trap is misrouted
        // through our EL1 vector as if it were an SVC, the dispatcher sees
        // garbage syscall numbers, and the guest spins forever. FPEN=0b11
        // turns the trap off; the bottom two bits of each TRC* field are kept
        // at zero (trace unsupported, no SME).
        // boot.cpacr_el1 (FPEN=0b11, no FP/SIMD trap at EL0) is shared.
        vcpu.set_sys_reg(SysReg::CPACR_EL1, boot.cpacr_el1)
            .map_err(hvf_error)?;
        // Allow EL0 to read the virtual (EL0VCTEN, bit 1) and physical
        // (EL0PCTEN, bit 0) counters directly without trapping to EL1. This is
        // the foundation for the vDSO fast clock path: `__kernel_clock_gettime`
        // reads CNTVCT_EL0 in userspace, so it must NOT vmexit. The
        // emulate_el0_sys64_read path stays as a fallback for any guest whose
        // read still traps. Harmless for guests that don't read the counter.
        const CNTKCTL_EL1_EL0_COUNTER_ACCESS: u64 = (1 << 1) | (1 << 0);
        vcpu.set_sys_reg(SysReg::CNTKCTL_EL1, CNTKCTL_EL1_EL0_COUNTER_ACCESS)
            .map_err(hvf_error)?;
        // Route lower-EL synchronous exceptions (EL0 `svc #0`) through our
        // vector page. Without this, VBAR_EL1 defaults to 0 (or whatever
        // HVF leaves it at) and the SVC fetch faults on an unmapped page.
        if let Some(vectors_base) = plan.el1_vectors_base {
            vcpu.set_sys_reg(SysReg::VBAR_EL1, vectors_base)
                .map_err(hvf_error)?;
        }
        if let Some(stack_pointer) = plan.initial_stack_pointer {
            // SP_EL0 is the Linux userspace stack. SP_EL1 is reserved for the
            // per-vCPU syscall mailbox and is bound after mappings are live.
            vcpu.set_sys_reg(SysReg::SP_EL0, stack_pointer)
                .map_err(hvf_error)?;
        }
        // Fill the vDSO vvar page so __kernel_clock_gettime can derive time from
        // CNTVCT_EL0 in userspace. Best-effort: if the page isn't mapped (a load
        // path without with_vdso) just skip — the guest falls back to syscalls.
        state.populate_vdso_data_page();
        let mailbox = match &carrier {
            // Shared arena, shared allocator: the slot is unique across every
            // container's vCPUs in this VM.
            Some(spec) => Self::allocate_persistent_mailbox_for_vcpu(spec, &vcpu)?,
            None => state.allocate_mailbox_for_vcpu(&vcpu)?,
        };
        if pending_creation.is_some() {
            commit_pending_creation_before_vcpu_handoff(pending_creation)?;
        }
        Ok((state, vcpu.into_inner(), mailbox))
    }
}

/// Volatile copy out of guest-shared memory. Guest RAM is MAP_SHARED and the
/// guest vCPU can mutate it concurrently on another host thread; a plain
/// (non-volatile) read racing that write is UB in Rust's memory model (the
/// optimizer may assume the bytes are stable and tear/hoist/elide the read).
/// `read_volatile` forbids that. This does NOT make the data race semantically
/// correct — the guest owns its own synchronization — it only removes the
/// language-level UB on the host side.
///
/// Word-accelerated: the guest (`src`) side is read with aligned word-sized
/// `read_volatile` (with byte-volatile head/tail around the unaligned edges),
/// which preserves the UB guarantee while doing ~`size_of::<usize>()`× fewer
/// guest accesses than a byte loop — this copy is on every guest→host transfer
/// (sockets, pipes, file reads) and the byte loop was a measured hot spot
/// (~33µs of a 59µs loopback `sendto`). The private host `dst` is not shared,
/// so it uses plain unaligned writes.
///
/// SAFETY: `src` must be valid for reads of `len` bytes and `dst` valid for
/// writes of `len` bytes; the two regions must not overlap.
mod guest_memory;
pub(crate) use guest_memory::*;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl HvfVmState {
    /// The process-wide PROT_NONE bookkeeping (the engine's EFAULT gate).
    pub(crate) fn protections_ref(&self) -> &MemoryProtections {
        &self.protections
    }

    /// A `Send`/`Sync` kick handle for THIS thread's live vCPU. The engine's
    /// `ThreadedEngine::kick_handle` routes through the Vmm, which does not hold
    /// the vCPU, so HVF stashes the handle on every vCPU create (see the
    /// `vcpu_handle` field) and hands it out here.
    pub(crate) fn vcpu_kick_handle(&self) -> crate::vcpu_kick::VcpuKickHandle {
        crate::vcpu_kick::VcpuKickHandle::following(std::sync::Arc::clone(&self.task.live_vcpu))
    }

    /// Name this backend's live vCPU as the one the attached task occupies.
    /// Called on every attach and whenever the vCPU is recreated underneath a
    /// loaded task, so registered kick handles keep following the task.
    pub(crate) fn publish_live_vcpu(&self) {
        self.task.live_vcpu.publish(self.vcpu_handle.clone());
    }

    /// The task is leaving this vCPU; a kick registered for it now has nothing
    /// in `hv_vcpu_run` to interrupt until the next attach republishes.
    pub(crate) fn clear_live_vcpu(&self) {
        self.task.live_vcpu.clear();
    }

    /// Live private semantic mappings that a process fork must arm read-only in
    /// both stage-1 graphs. This includes a currently-read-only or PROT_NONE
    /// mapping: a later mprotect-to-write must still take frame COW rather than
    /// silently sharing the parent's frame. The alias registry supplies mappings
    /// installed by sibling vCPUs and filters retired lifetime-owner rows.
    pub(crate) fn fork_cow_ranges(&self) -> Vec<carrick_aarch64::vmm::ForkCowRange> {
        let aliases = alias_registry()
            .lock()
            .process_visible_ordered(self.mm_root_slot, self.container_root);
        let alias_index = process_alias_index(&aliases, self.mm_root_slot, self.container_root);
        let mut ranges: Vec<_> = self
            .mappings
            .iter()
            .filter(|mapping| {
                mapping.sharing == GuestMappingSharing::Private
                    && mapping.start != crate::memory::LINUX_PAGE_TABLES_BASE
                    && !is_kernel_only_stage1_range(
                        mapping.start,
                        semantic_extent_size(mapping.start, mapping.end),
                    )
                    && mapping_is_current_for_process_fork_indexed(mapping, &alias_index)
            })
            .map(|mapping| carrick_aarch64::vmm::ForkCowRange {
                va: mapping.start,
                len: semantic_extent_size(mapping.start, mapping.end),
                executable: u64::from(mapping.perms) & 4 != 0,
                kernel_only: is_kernel_only_stage1_range(
                    mapping.start,
                    semantic_extent_size(mapping.start, mapping.end),
                ),
                granule: carrick_aarch64::vmm::CowGranule::Compound,
            })
            .collect();
        let local_aliases = current_process_alias_keys(
            &self.mappings,
            &aliases,
            self.mm_root_slot,
            self.container_root,
        );
        ranges.extend(
            missing_process_aliases(
                &local_aliases,
                &aliases,
                self.mm_root_slot,
                self.container_root,
            )
            .into_iter()
            .filter(|mapping| {
                mapping.sharing == GuestMappingSharing::Private
                    && !is_kernel_only_stage1_range(mapping.start, mapping.size)
            })
            .map(|mapping| carrick_aarch64::vmm::ForkCowRange {
                va: mapping.start,
                len: mapping.size,
                executable: mapping.perms & 4 != 0,
                kernel_only: is_kernel_only_stage1_range(mapping.start, mapping.size),
                granule: carrick_aarch64::vmm::CowGranule::Compound,
            }),
        );
        ranges.sort_by_key(|range| (range.va, range.len));
        ranges.dedup_by_key(|range| (range.va, range.len));
        ranges
    }

    pub(crate) fn arm_frame_cow_ranges(&mut self, ranges: &[carrick_aarch64::vmm::ForkCowRange]) {
        if let Some(debug_va) = fork_debug_va()
            && let Some(range) = ranges
                .iter()
                .find(|range| debug_va >= range.va && debug_va < range.va + range.len as u64)
        {
            eprintln!(
                "[ARMDBG parent pid={:?} mm={:?} slot={:x?}] arm covers watch: va={:#x} len={:#x}",
                self.cow_identity.map(|identity| identity.linux_pid),
                self.cow_identity.map(|identity| identity.mm),
                self.mm_root_slot,
                range.va,
                range.len,
            );
        }
        self.cow_armed.lock().arm(ranges);
    }

    pub(crate) fn frame_cow_arm_snapshot(&self) -> Vec<carrick_aarch64::vmm::ForkCowRange> {
        self.cow_armed.lock().snapshot()
    }

    pub(crate) fn restore_frame_cow_arm_snapshot(
        &mut self,
        snapshot: Vec<carrick_aarch64::vmm::ForkCowRange>,
    ) {
        self.cow_armed.lock().restore(snapshot);
    }

    pub(crate) fn armed_frame_cow_ranges(
        &self,
        va: u64,
        len: usize,
    ) -> Vec<carrick_aarch64::vmm::ForkCowRange> {
        self.cow_armed.lock().overlapping(va, len)
    }

    pub(crate) fn publish_private_repoint(
        &mut self,
        va: u64,
        overlay_ipa: u64,
        len: usize,
    ) -> Result<(), TrapError> {
        let overlay_end = overlay_ipa.checked_add(len as u64).ok_or_else(|| {
            TrapError::Hypervisor("private repoint semantic IPA overflow".to_owned())
        })?;
        let (
            mapping_ipa,
            physical_ipa,
            mapping_host,
            physical_size,
            perms,
            mapping_owner_generation,
        ) = self
            .mappings
            .iter()
            .rev()
            .find(|mapping| {
                overlay_ipa >= mapping.ipa
                    && mapping
                        .ipa
                        .checked_add(mapping.size as u64)
                        .is_some_and(|end| overlay_end <= end)
            })
            .map(|mapping| {
                (
                    mapping.ipa,
                    mapping.physical_ipa,
                    mapping.host_addr as usize,
                    mapping.physical_size,
                    mapping.perms,
                    mapping
                        .structural_owner
                        .as_ref()
                        .map(|owner| owner.epoch().raw())
                        .unwrap_or(mapping.owner_generation),
                )
            })
            .ok_or_else(|| {
                TrapError::Hypervisor(format!(
                    "private repoint IPA 0x{overlay_ipa:x} size {len} has no physical owner"
                ))
            })?;
        let semantic_offset = overlay_ipa.checked_sub(physical_ipa).ok_or_else(|| {
            TrapError::Hypervisor("private repoint precedes its physical extent".to_owned())
        })?;
        let physical_host_addr = mapping_host
            .checked_sub(mapping_ipa.checked_sub(physical_ipa).ok_or_else(|| {
                TrapError::Hypervisor(
                    "private repoint mapping precedes its physical extent".to_owned(),
                )
            })? as usize)
            .ok_or_else(|| {
                TrapError::Hypervisor("private repoint physical host underflow".to_owned())
            })?;
        let host_addr = physical_host_addr
            .checked_add(semantic_offset as usize)
            .ok_or_else(|| {
                TrapError::Hypervisor("private repoint semantic host overflow".to_owned())
            })?;
        let inventory_backing = self
            .frame_inventory
            .lock()
            .extents
            .get(&(physical_ipa, physical_size as u64))
            .map(|extent| extent.backing)
            .or_else(|| (!self.persistent_vm_lifecycle).then(Self::private_backing_identity))
            .ok_or_else(|| {
                TrapError::Hypervisor(format!(
                    "private repoint physical IPA 0x{:x} size {} lacks frame inventory",
                    physical_ipa, physical_size
                ))
            })?;
        let owner_generation =
            if is_reusable_global_frame_extent(physical_ipa, physical_size as u64) {
                global_frame_host_owner_generation_in(
                    self.custody(),
                    physical_ipa,
                    physical_size as u64,
                )
            } else {
                mapping_owner_generation
            };
        let sharing = GuestMappingSharing::Private;
        register_shared_alias(AliasBacking {
            start: va,
            ipa: overlay_ipa,
            host_addr,
            size: len,
            physical_ipa,
            physical_host_addr,
            physical_size,
            perms: u64::from(perms),
            guest_writable: true,
            sharing,
            ownership_scope: alias_ownership_scope(sharing, self.mm_root_slot, self.container_root),
            inventory_backing,
            shared_key_base: 0,
            shared_key_offset: 0,
            owner_generation,
        });
        Ok(())
    }

    pub(crate) fn apply_exec_inventory(
        &mut self,
        replacement_mm: u64,
        apply: &mut dyn FnMut(
            carrick_hal::FrameInventoryCommit<()>,
        )
            -> Result<carrick_hal::FrameInventoryApplyReceipt, TrapError>,
    ) -> Result<bool, TrapError> {
        let Some(ref mut reg) = self.registration else {
            return Ok(false);
        };
        let mm = std::num::NonZeroU64::new(replacement_mm).ok_or_else(|| {
            TrapError::Hypervisor("zero replacement MM for HVPatch exec".to_owned())
        })?;
        reg.bind_kernel_mm(mm)?;
        reg.apply_inventory(apply)?;
        Ok(true)
    }

    pub(crate) fn activate_exec_inventory(&mut self) -> Result<(), TrapError> {
        let Some(ref mut reg) = self.registration else {
            return Ok(());
        };
        reg.activate()
    }

    /// Whether the frame backing `ipa` is referenced by MORE than one extent in
    /// the shared backend registry — i.e., some other mm (a fork parent or
    /// child) still lives on it. The registry `Arc` is shared across every
    /// engine in the carrier and its counts drive retirement, so it is the
    /// authority for "shared", where the per-engine armed-set is only a
    /// derived (and known-omissive) approximation.
    /// Whether this mm may write DIRECTLY through the frame its retained
    /// stage-1 output names. Two ways to lose that right:
    ///
    /// - This mm's inventory holds NO extent covering the IPA at all: the leaf
    ///   is stale — it survived a retirement/replacement of the mapping it
    ///   belonged to — and whatever lives behind that IPA now belongs to
    ///   someone else. The forkserver worker's scrub had exactly this shape
    ///   (606 own extents, none covering the retained IPA) and its Direct
    ///   write zeroed the SERVER's live interned-dict granule.
    /// - An extent exists but the backend registry counts more than one
    ///   reference on its frame: a fork peer still lives on it, and a direct
    ///   write would be visible through the other mm.
    ///
    /// In both cases the maintenance write must MATERIALIZE a private zeroed
    /// replacement instead. The registry `Arc` is shared carrier-wide and its
    /// counts drive retirement, so it is the authority; the per-engine
    /// armed-set is a derived, known-omissive approximation
    /// (`mtforkcorrupt`).
    fn retained_output_lacks_exclusive_claim(&self, ipa: u64) -> bool {
        // Only REUSABLE global-frame IPAs carry claims at all. Boot and
        // identity regions (the heap, the low arena's fixed backing, page
        // tables) are per-mm by construction and never enter the extent map;
        // treating their absence as a lost claim routed every brk-heap scrub
        // into materialization and broke `ltp-brk02`/`ltp-tgkill01` outright.
        if !is_reusable_global_frame_extent(ipa, 1) {
            return false;
        }
        let inventory = self.frame_inventory.lock();
        let extent = inventory
            .extents
            .iter()
            .find(|(key, _)| key.0 <= ipa && ipa < key.0.saturating_add(key.1))
            .map(|(_, extent)| *extent);
        let Some(extent) = extent else {
            return true;
        };
        // DELIBERATE sharing is not a lost claim. A `SharedAnon`/`SharedFile`
        // backing is MAP_SHARED semantics: every mapper must keep seeing the
        // same bytes, and materializing a private replacement under it breaks
        // exactly what the guest asked for (measured: multiprocessing's
        // Barrier hung when a shared semaphore page was privatized here).
        // Only a PRIVATE backing observed by more than one mm is fork-COW
        // sharing that a maintenance write must not write through.
        //
        // A private FILE VIEW never carries an exclusive claim: its host
        // bytes are the file's page cache, so a direct maintenance write
        // would either fail (the view is `PROT_READ`) or, worse, be the file.
        // The maintenance write must materialize the page privately, exactly
        // like a guest write to a clean page.
        match extent.backing {
            InventoryBackingIdentity::PrivateFileView(_) => return true,
            InventoryBackingIdentity::Private(_) => {}
            InventoryBackingIdentity::SharedAnon(_)
            | InventoryBackingIdentity::SharedFile { .. } => return false,
        }
        inventory
            .frames
            .lock()
            .references
            .get(&extent.frame)
            .copied()
            .unwrap_or(0)
            > 1
    }

    pub(crate) const DEFAULT_FAULT_WINDOW_BYTES: u64 = 64 * 1024;

    fn fault_window_bytes() -> u64 {
        static WINDOW: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
        *WINDOW.get_or_init(|| {
            std::env::var("CARRICK_FAULT_WINDOW_BYTES")
                .ok()
                .and_then(|val| val.parse::<u64>().ok())
                .filter(|&w| w >= 4096 && w.is_power_of_two())
                .unwrap_or(Self::DEFAULT_FAULT_WINDOW_BYTES)
        })
    }

    /// Materialize private zero backing for the exact accessible pieces of the
    /// sparse HVPatch mmap arena. One VMA hole becomes one host mapping, one
    /// stage-2 lease, and one inventory frame; there is no shared source frame
    /// and therefore no shared-zero COW authority.
    ///
    /// This is the first-touch fault service, so it is where the mapping-index
    /// census is taken: the row populations both lookup structures hold, the
    /// rows their walks visited for THIS fault, and the nanoseconds it cost.
    /// `docs/perf-results/2026-09-08-mapping-index-measurement.md` closed the
    /// full-table walk it could see by wall time alone and had to leave the
    /// residual super-linearity unnamed, because no probe reported a scan
    /// count. This is that probe.
    pub(crate) fn ensure_sparse_mmap_backing(
        &mut self,
        va: u64,
        len: usize,
        flush_stage1: &mut dyn FnMut() -> Result<(), TrapError>,
    ) -> Result<(), TrapError> {
        let Some(started) = carrick_observability::probes::hvpatch_mapping_index_begin(
            self.mappings.live_len() as u64,
            self.mappings.shadowed_len() as u64,
        ) else {
            return self.ensure_sparse_mmap_backing_censused(va, len, flush_stage1);
        };
        let mapping_rows_before = hot_path_rows_scanned_live(HotPathScan::TaskMappings);
        let alias_rows_before = hot_path_rows_scanned_live(HotPathScan::AliasState);
        let outcome = self.ensure_sparse_mmap_backing_censused(va, len, flush_stage1);
        let nanos = u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX);
        let (alias_rows, widest_va) = {
            let registry = alias_registry().lock();
            (registry.len() as u64, registry.widest_va_window())
        };
        carrick_observability::probes::hvpatch_mapping_index_fault(
            carrick_observability::probes::HvpatchMappingIndexCensus::new(
                va,
                self.mappings.live_len() as u64,
                self.mappings.shadowed_len() as u64,
                hot_path_rows_scanned_live(HotPathScan::TaskMappings)
                    .wrapping_sub(mapping_rows_before),
                alias_rows,
                hot_path_rows_scanned_live(HotPathScan::AliasState).wrapping_sub(alias_rows_before),
                widest_va,
                nanos,
            ),
        );
        outcome
    }

    fn ensure_sparse_mmap_backing_censused(
        &mut self,
        va: u64,
        len: usize,
        flush_stage1: &mut dyn FnMut() -> Result<(), TrapError>,
    ) -> Result<(), TrapError> {
        const PAGE_SIZE: u64 = 4 * 1024;
        if !self.persistent_vm_lifecycle || len == 0 {
            return Ok(());
        }
        let arena_start = crate::memory::LINUX_MMAP_BASE;
        let arena_end = arena_start
            .checked_add(crate::memory::mmap_arena_size())
            .ok_or_else(|| TrapError::Hypervisor("HVPatch mmap arena overflow".to_owned()))?;
        let requested_end = va
            .checked_add(len as u64)
            .ok_or_else(|| TrapError::Hypervisor("sparse mmap range overflow".to_owned()))?;
        let in_low_arena = va >= arena_start && requested_end <= arena_end;
        let in_high_va = crate::memory::is_high_va(va) && requested_end <= (1u64 << 48);
        if !in_low_arena && !in_high_va {
            return Ok(());
        }
        if let Some(state) = self.deferred_anonymous_state()
            && let Some(transition) =
                state.begin_private_file_materialization(carrick_guest_mem::GuestVa(va))
        {
            let start = transition.start().raw();
            let materialized = self.materialize_private_file_backing(
                start,
                transition.len(),
                transition.fd(),
                transition.file_offset(),
                transition.source(),
                flush_stage1,
            )?;
            if !materialized {
                return Err(TrapError::Hypervisor(format!(
                    "deferred private file view at VA 0x{start:x} refused first-touch publication"
                )));
            }
            transition.commit();
            return Ok(());
        }
        let mut current = align_down(va, PAGE_SIZE);
        let end = align_up(requested_end, PAGE_SIZE)?;

        // Zero-allocation fast path: if the requested range is already backed
        // by a live mapping, return immediately.
        if let Some(mapping) = self.mapping_for_range(current, 1) {
            if mapping.end >= end {
                return Ok(());
            }
        }

        // Anonymous private fault window (Step 1 + Step 2):
        // Widen the fault window up to W bytes (default 64 KiB) within the pristine hole:
        // window_end = min(hole_end, align_up(va + 1, W), vma_end, next_2mb_boundary)
        const COMPOUND: u64 = CowArmedRanges::COMPOUND_SIZE;
        const TWO_MIB: u64 = 2 * 1024 * 1024;
        if len == PAGE_SIZE as usize && current < end {
            let pristine = self.deferred_anonymous_state().and_then(|state| {
                state
                    .snapshot()
                    .pristine
                    .into_iter()
                    .find(|r| r.start.raw() <= current && current < r.end.raw())
                    .map(|r| (r.start.raw(), r.end.raw()))
            });
            if let Some((p_start, p_end)) = pristine {
                let w = Self::fault_window_bytes();
                if w < COMPOUND {
                    // Hatch CARRICK_FAULT_WINDOW_BYTES=4096: single-page fallback.
                    let has_local = self
                        .mappings
                        .iter()
                        .any(|m| m.start < end && m.end > current);
                    let has_alias = alias_registry().lock().has_live_process_alias_overlapping(
                        current,
                        end,
                        self.mm_root_slot,
                        self.container_root,
                    );
                    if !has_local && !has_alias {
                        self.materialize_sparse_mmap_extent(
                            current,
                            end,
                            SparseExtentBacking::Anon,
                            flush_stage1,
                            Some(current..end),
                        )?;
                        return Ok(());
                    }
                } else {
                    let range_end_limit = if in_high_va { 1u64 << 48 } else { arena_end };
                    let range_start_limit = if in_high_va {
                        crate::memory::LINUX_HIGH_VA_THRESHOLD
                    } else {
                        arena_start
                    };
                    let w_end = align_up(current.saturating_add(1), w)?;
                    let next_2mb = align_down(current, TWO_MIB).saturating_add(TWO_MIB);
                    let vma_end = p_end;
                    let mut window_end = vma_end.min(next_2mb).min(w_end).min(range_end_limit);
                    window_end = window_end.max(end);

                    // Sorted by construction (`TaskMappingIndex`), so this
                    // neighbour question is an ordered range query. The
                    // earlier `partition_point` attempt was wrong because the
                    // VECTOR was unsorted and a binary search missed live
                    // mappings, letting a window materialize over them (Go
                    // heap corruption, 2026-09-07); the invariant now holds at
                    // every publication site, and displaced rows are searched
                    // too.
                    let next_local = self.mappings.first_start_between(
                        GuestVa(current),
                        GuestVa(window_end),
                        |_| true,
                    );
                    let next_alias = alias_registry()
                        .lock()
                        .first_matching_process_alias_start_between(
                            current,
                            window_end,
                            self.mm_root_slot,
                            self.container_root,
                            |alias| alias_backing_is_live(alias.physical_host_addr),
                        );
                    window_end = next_local
                        .into_iter()
                        .chain(next_alias)
                        .min()
                        .unwrap_or(window_end);

                    let compound_start = align_down(current, COMPOUND);
                    let window_start = if compound_start >= p_start
                        && compound_start >= range_start_limit
                        && !alias_registry().lock().has_live_process_alias_overlapping(
                            compound_start,
                            current,
                            self.mm_root_slot,
                            self.container_root,
                        ) {
                        let lower_has_local = self
                            .mappings
                            .any_lower_row_reaches(GuestVa(current), compound_start);
                        if !lower_has_local {
                            compound_start
                        } else {
                            current
                        }
                    } else {
                        current
                    };

                    if window_start < window_end && window_start <= current && end <= window_end {
                        let mut chunk_start = window_start;
                        while chunk_start < window_end {
                            let chunk_limit = if chunk_start.is_multiple_of(COMPOUND) {
                                chunk_start.saturating_add(COMPOUND).min(window_end)
                            } else {
                                align_up(chunk_start.saturating_add(1), COMPOUND)?.min(window_end)
                            };
                            let materialized_end = self.materialize_sparse_mmap_extent(
                                chunk_start,
                                chunk_limit,
                                SparseExtentBacking::Anon,
                                flush_stage1,
                                Some(current..end),
                            )?;
                            if materialized_end <= chunk_start {
                                break;
                            }
                            chunk_start = materialized_end;
                        }
                        return Ok(());
                    }
                }
            }
        }

        while current < end {
            if let Some(mapping) = self.mapping_for_range(current, 1) {
                let next = mapping.end.min(end);
                if next <= current {
                    return Err(TrapError::Hypervisor(format!(
                        "sparse mmap live mapping made no progress at VA 0x{current:x}: view VA 0x{:x}..0x{:x}, view IPA 0x{:x}, live IPA {:?}, mm root {:?}",
                        mapping.start,
                        mapping.end,
                        mapping.ipa,
                        self.translate_va(current),
                        self.mm_root_slot,
                    )));
                }
                current = next;
                continue;
            }

            // Preserve already-materialized neighbours. The topology lock in
            // the materializer rechecks this shape before publication.
            let next_local =
                self.mappings
                    .first_start_between(GuestVa(current), GuestVa(end), |_| true);
            let next_alias = alias_registry()
                .lock()
                .first_matching_process_alias_start_between(
                    current,
                    end,
                    self.mm_root_slot,
                    self.container_root,
                    |alias| alias_backing_is_live(alias.physical_host_addr),
                );
            let hole_end = next_local
                .into_iter()
                .chain(next_alias)
                .min()
                .unwrap_or(end);
            current = self.materialize_sparse_mmap_extent(
                current,
                hole_end,
                SparseExtentBacking::Anon,
                flush_stage1,
                None,
            )?;
        }
        Ok(())
    }

    /// Materialize a file view for a guest `MAP_PRIVATE` mapping in the sparse
    /// arena. Immutable lower artifacts use Darwin `MAP_PRIVATE`; mutable files
    /// require a writable `MAP_SHARED` host view so clean pages track later file
    /// writes. Carrick arms 4 KiB frame COW before guest access, keeping every
    /// guest and foreign store private to the exact MM.
    ///
    /// Returns `Ok(false)` when the request cannot take this shape and the
    /// dispatcher must fall back to its eager snapshot: ranges outside the
    /// sparse arena, a VA/offset pair that is not congruent modulo the 16 KiB
    /// host page, an offset at/after EOF, or a range that is not entirely a
    /// hole. A mutable read-only host fd is also refused by Darwin because the
    /// coherent host view needs write authority.
    pub(crate) fn materialize_private_file_backing(
        &mut self,
        va: u64,
        len: usize,
        fd: std::os::fd::BorrowedFd<'_>,
        offset: u64,
        source: carrick_guest_mem::PrivateFileSource,
        flush_stage1: &mut dyn FnMut() -> Result<(), TrapError>,
    ) -> Result<bool, TrapError> {
        const PAGE_SIZE: u64 = 4 * 1024;
        if !self.persistent_vm_lifecycle || len == 0 {
            return Ok(false);
        }
        let arena_start = crate::memory::LINUX_MMAP_BASE;
        let arena_end = arena_start
            .checked_add(crate::memory::mmap_arena_size())
            .ok_or_else(|| TrapError::Hypervisor("HVPatch mmap arena overflow".to_owned()))?;
        let end = va
            .checked_add(len as u64)
            .ok_or_else(|| TrapError::Hypervisor("private file view range overflow".to_owned()))?;
        let in_low_arena = va >= arena_start && end <= arena_end;
        let in_high_va = crate::memory::is_high_va(va) && end <= (1u64 << 48);
        // A private mapping may be moved into the shared aperture. Its VA
        // does not decide ownership: the live alias/mapping checks below still
        // refuse shared or non-dynamic backing before any retirement.
        let eligible_range =
            in_low_arena || in_high_va || crate::memory::va_in_shared_aperture(va, len as u64);
        if !eligible_range
            || !va.is_multiple_of(PAGE_SIZE)
            || !end.is_multiple_of(PAGE_SIZE)
            || !offset.is_multiple_of(PAGE_SIZE)
        {
            return Ok(false);
        }
        let file_len = {
            let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
            // SAFETY: `fstat` writes a `libc::stat` into the provided buffer.
            let rc = unsafe { libc::fstat(fd.as_raw_fd(), stat.as_mut_ptr()) };
            if rc != 0 {
                return Ok(false);
            }
            // SAFETY: `fstat` succeeded and initialized the buffer.
            let stat = unsafe { stat.assume_init() };
            u64::try_from(stat.st_size).unwrap_or(0)
        };
        if offset >= file_len {
            return Ok(false);
        }
        let view_len = (file_len - offset).min(end - va);
        let view_end = va + view_len;
        let file_pages_end = align_up(view_end, PAGE_SIZE).unwrap_or(end).min(end);

        // Holes vs overlapping existing mappings:
        // A plain MAP_PRIVATE file mmap lands in a hole. A MAP_FIXED over an
        // existing private mapping (such as the ELF loader's PROT_NONE reservation)
        // retires the old backing for the range so it takes the lazy view too.
        // If any overlapping mapping or process-scoped alias is non-private or
        // non-dynamic (e.g. shared memory), refuse the lowering so dispatcher falls back.
        let overlapping_aliases = alias_registry().lock().overlapping_process_aliases(
            va,
            len,
            self.mm_root_slot,
            self.container_root,
        );
        let has_non_retirable_alias = overlapping_aliases.iter().any(|(_, alias)| {
            alias.sharing != GuestMappingSharing::Private
                || !alias_backing_is_live(alias.physical_host_addr)
        });
        if has_non_retirable_alias {
            return Ok(false);
        }

        let has_non_retirable_mapping = self.mappings.iter().any(|m| {
            m.start < end
                && m.end > va
                && global_frame_region_owner_matches_in(self.custody(), m)
                && (!m.is_dynamic_alias || m.sharing != GuestMappingSharing::Private)
        });
        if has_non_retirable_mapping {
            return Ok(false);
        }

        let mut current = va;
        while current < end {
            let hole_end = if current < file_pages_end {
                file_pages_end
            } else {
                end
            };
            let backing = if current < file_pages_end {
                SparseExtentBacking::FileView {
                    fd,
                    offset: offset + (current - va),
                    source,
                }
            } else {
                SparseExtentBacking::Anon
            };
            let next = self.materialize_sparse_mmap_extent_inner(
                current,
                hole_end,
                backing,
                flush_stage1,
                None,
                true,
            )?;
            if next <= current {
                return Err(TrapError::Hypervisor(format!(
                    "private file view materialization made no progress at VA 0x{current:x}"
                )));
            }
            current = next;
        }
        Ok(true)
    }

    fn materialize_sparse_mmap_extent(
        &mut self,
        start: u64,
        end: u64,
        backing: SparseExtentBacking<'_>,
        flush_stage1: &mut dyn FnMut() -> Result<(), TrapError>,
        receipt_range: Option<std::ops::Range<u64>>,
    ) -> Result<u64, TrapError> {
        self.materialize_sparse_mmap_extent_inner(
            start,
            end,
            backing,
            flush_stage1,
            receipt_range,
            false,
        )
    }

    fn materialize_sparse_mmap_extent_inner(
        &mut self,
        start: u64,
        end: u64,
        backing: SparseExtentBacking<'_>,
        flush_stage1: &mut dyn FnMut() -> Result<(), TrapError>,
        receipt_range: Option<std::ops::Range<u64>>,
        replacing: bool,
    ) -> Result<u64, TrapError> {
        const PAGE_SIZE: u64 = 4 * 1024;

        if start >= end || !start.is_multiple_of(PAGE_SIZE) || !end.is_multiple_of(PAGE_SIZE) {
            return Err(TrapError::Hypervisor(format!(
                "invalid sparse mmap materialization 0x{start:x}..0x{end:x}"
            )));
        }
        let identity = self.cow_identity.ok_or_else(|| {
            TrapError::Hypervisor("HVPatch sparse mmap has no bound mm identity".to_owned())
        })?;
        let publication = sparse_materialization::PublicationContext::for_local(
            std::sync::Arc::clone(&self.mm_access),
            self.carrier_vm_custody(),
            identity,
        )?;
        let _topology = crate::fork_quiesce::acquire_topology_lock(
            carrick_observability::probes::HvpatchTopologyOperation::AliasMap,
            identity.linux_pid,
            identity.linux_tid,
        );
        let end = if replacing {
            // Eligibility was screened before exact-MM quiescence. Recheck
            // under topology exclusion before bypassing the hole checks: a
            // sibling must not turn a private replacement into a shared unmap.
            let len = usize::try_from(end - start)
                .map_err(|_| TrapError::MappingTooLarge(end - start))?;
            let aliases = alias_registry().lock().overlapping_process_aliases(
                start,
                len,
                self.mm_root_slot,
                self.container_root,
            );
            let forbidden_alias = aliases.iter().any(|(_, alias)| {
                alias.sharing != GuestMappingSharing::Private
                    || !alias_backing_is_live(alias.physical_host_addr)
            });
            let forbidden_mapping = self.mappings.iter().any(|mapping| {
                mapping.start < end
                    && mapping.end > start
                    && global_frame_region_owner_matches_in(self.custody(), mapping)
                    && (!mapping.is_dynamic_alias
                        || mapping.sharing != GuestMappingSharing::Private)
            });
            if forbidden_alias || forbidden_mapping {
                return Err(TrapError::Hypervisor(
                    "private-file replacement eligibility changed before quiescence".to_owned(),
                ));
            }
            end
        } else {
            if let Some(mapping) = self.mapping_for_range(start, 1) {
                // An aperture identity row is a boot lookup fallback, not proof
                // that a private file view raced this publication. The caller has
                // already refused live shared aliases; process-scoped frame owners
                // below remain authoritative even after an old overlay is retired.
                let replaces_boot_identity =
                    matches!(backing, SparseExtentBacking::FileView { .. })
                        && crate::memory::va_in_shared_aperture(start, end - start)
                        && mapping.is_shared_aperture_identity();
                if !replaces_boot_identity {
                    return Ok(mapping.end.min(end));
                }
            }

            // Another vCPU in this mm can publish the physical alias while its
            // stage-1 receipt is deliberately still invalid.  Such an alias is
            // invisible to `mapping_for_range` on this sibling until the later
            // protection commit, so authenticate the process-shared physical owner
            // directly before allocating a second overlapping frame.
            let live_alias_end = alias_registry()
                .lock()
                .newest_process_alias_containing_va(
                    start,
                    self.mm_root_slot,
                    self.container_root,
                    |alias| {
                        global_frame_host_owner_matches_in(
                            self.custody(),
                            alias.physical_ipa,
                            alias.physical_size as u64,
                            alias.physical_host_addr,
                            alias.owner_generation,
                        )
                    },
                )
                .map(|alias| alias.start.saturating_add(alias.size as u64));
            if let Some(alias_end) = live_alias_end {
                return Ok(alias_end.min(end));
            }

            // The caller found this hole before quiescing. Recompute its upper
            // boundary under the topology lock so a sibling publication between
            // those two points cannot be overlapped.
            // Ordered range query (see the window arm above): this bound decides
            // whether the new extent overlaps a live mapping, so it must still see
            // every row -- including displaced ones -- that the exact live global
            // owner still backs.
            let custody = self.custody();
            let next_local =
                self.mappings
                    .first_start_between(GuestVa(start), GuestVa(end), |mapping| {
                        global_frame_region_owner_matches_in(custody, mapping)
                    });
            let next_alias = alias_registry()
                .lock()
                .first_matching_process_alias_start_between(
                    start,
                    end,
                    self.mm_root_slot,
                    self.container_root,
                    |alias| {
                        global_frame_host_owner_matches_in(
                            self.custody(),
                            alias.physical_ipa,
                            alias.physical_size as u64,
                            alias.physical_host_addr,
                            alias.owner_generation,
                        )
                    },
                );
            next_local
                .into_iter()
                .chain(next_alias)
                .min()
                .unwrap_or(end)
        };

        let semantic_len =
            usize::try_from(end - start).map_err(|_| TrapError::MappingTooLarge(end - start))?;
        let deferred_state = self.deferred_anonymous_state();
        let deferred_transition = deferred_state
            .as_ref()
            .map(|state| {
                state.begin_materialization(carrick_guest_mem::GuestVa(start), semantic_len)
            })
            .transpose()
            .map_err(|error| {
                TrapError::Hypervisor(format!("anonymous materialization range: {error}"))
            })?;

        let mut retirement = if replacing {
            Some(self.prepare_process_alias_retirement(start, semantic_len)?)
        } else {
            None
        };
        let published = sparse_materialization::publish_replacing(
            &publication,
            start,
            end,
            backing,
            flush_stage1,
            &mut || {
                if let Some(retirement) = retirement.take() {
                    // New descriptors and inventory are committed, but the new
                    // alias is not registered yet. Retire only the old rows.
                    // All ordinary allocation failures preceded this boundary.
                    self.commit_process_alias_retirement(start, semantic_len, retirement)
                        .unwrap_or_else(|error| {
                            carrick_fatal!(
                                "hvpatch::host_alias",
                                "committed private-file retirement failed: start=0x{start:x} len=0x{semantic_len:x} error={error}"
                            );
                        });
                }
            },
        )?;
        let page_granular_arm = published.page_granular_arm;
        let semantic_ipa = published.region.ipa;
        for ext in published.extension_regions {
            self.mappings.insert(ext);
        }
        self.mappings.insert(published.region);
        if page_granular_arm {
            // Every page of the view starts clean: the first guest (or host
            // syscall) write to a page must move THAT page, and only that
            // page, off the page-cache view. The anonymous beyond-EOF tail of
            // this extent is armed the same way so the extent is uniform.
            self.cow_armed
                .lock()
                .arm(&[carrick_aarch64::vmm::ForkCowRange {
                    va: start,
                    len: semantic_len,
                    executable: false,
                    kernel_only: false,
                    granule: carrick_aarch64::vmm::CowGranule::Page,
                }]);
        }
        let (receipt_va, receipt_len, receipt_ipa) = if let Some(range) = receipt_range {
            let r_start = start.max(range.start);
            let r_end = end.min(range.end);
            if r_start < r_end {
                let r_len = usize::try_from(r_end - r_start)
                    .map_err(|_| TrapError::MappingTooLarge(r_end - r_start))?;
                let r_ipa = semantic_ipa.checked_add(r_start - start).ok_or_else(|| {
                    TrapError::Hypervisor("sparse mmap receipt IPA overflow".to_owned())
                })?;
                (r_start, r_len, r_ipa)
            } else {
                (start, 0, semantic_ipa)
            }
        } else {
            (start, semantic_len, semantic_ipa)
        };
        if receipt_len > 0 {
            self.supersede_cow_receipts("sparse-mmap-extent", receipt_va, receipt_len as u64);
            self.cow_deferred_publications
                .lock()
                .push(PendingFrameCowPublication {
                    va: receipt_va,
                    len: receipt_len,
                    expected_ipa: receipt_ipa,
                });
        }
        if let Some(transition) = deferred_transition {
            transition.commit();
        }
        Ok(end)
    }

    /// Void every pending deferred-COW receipt naming `[va, va+len)`.
    ///
    /// A receipt is a promise about ONE `(VA -> IPA)` publication, redeemed by
    /// the `protect_range` that completes it. The moment a later transaction
    /// repoints those leaves the promise is void: authenticating it compares
    /// the live translation against an owner that has been DELIBERATELY
    /// replaced, and `observe_frame_cow_protection` then fails a publication
    /// that is in fact correct — which the dispatcher can only lower to a
    /// guest `ENOMEM`. That is how CPython's thread stacks came back
    /// MAP_FAILED ("Can't start 20 threads, only 4 threads started"): a
    /// sparse-mmap extent's receipt was falsified by a frame COW running
    /// between its publication and its protection commit.
    ///
    /// Every stage-1 repointer calls this before publishing its own receipt.
    /// No authentication coverage is lost: each repointer verifies its own
    /// leaves inline and leaves a receipt for the state that actually
    /// survives. A receipt only partly covered is split, never widened.
    fn supersede_cow_receipts(&self, site: &'static str, va: u64, len: u64) {
        let Some(end) = va.checked_add(len) else {
            return;
        };
        let mut receipts = self.cow_deferred_publications.lock();
        if receipts.is_empty() {
            return;
        }
        let mut remaining = Vec::with_capacity(receipts.len());
        for receipt in receipts.drain(..) {
            let receipt_end = receipt.va.saturating_add(receipt.len as u64);
            if receipt_end <= va || receipt.va >= end {
                remaining.push(receipt);
                continue;
            }
            tracing::debug!(
                target: "carrick::cow",
                site,
                repoint = format_args!("{va:#x}+{len:#x}"),
                receipt = format_args!("{:#x}+{:#x}", receipt.va, receipt.len),
                expected_ipa = format_args!("{:#x}", receipt.expected_ipa),
                "superseding deferred COW receipt",
            );
            let overlap_start = receipt.va.max(va);
            let overlap_end = receipt_end.min(end);
            if receipt.va < overlap_start
                && let Ok(prefix) = usize::try_from(overlap_start - receipt.va)
            {
                remaining.push(PendingFrameCowPublication {
                    va: receipt.va,
                    len: prefix,
                    expected_ipa: receipt.expected_ipa,
                });
            }
            if overlap_end < receipt_end
                && let Ok(suffix) = usize::try_from(receipt_end - overlap_end)
                && let Some(expected_ipa) =
                    receipt.expected_ipa.checked_add(overlap_end - receipt.va)
            {
                remaining.push(PendingFrameCowPublication {
                    va: overlap_end,
                    len: suffix,
                    expected_ipa,
                });
            }
        }
        *receipts = remaining;
    }

    /// Replace an invalid stage-1 output whose exact stage-2 lease was retired
    /// by `munmap` with a fresh zero frame before low-arena same-VA reuse.
    ///
    /// `munmap` deliberately preserves the descriptor output address while
    /// clearing VALID. That is useful while a partially unmapped compound still
    /// owns its physical lease, but a *full* semantic unmap now retires that
    /// lease exactly. A later anonymous mmap may reuse the same low VA without
    /// going through `add_alias`; merely setting VALID would resurrect an IPA
    /// that no longer exists in stage-2. Materialize a new global frame and
    /// repoint the still-invalid leaves transactionally. The later
    /// `protect_range` publication authenticates the deferred PTE receipts.
    fn materialize_retired_reuse(
        &mut self,
        va: u64,
        requested_end: u64,
        flush_stage1: &mut dyn FnMut() -> Result<(), TrapError>,
    ) -> Result<Option<u64>, TrapError> {
        const PAGE_SIZE: u64 = 4 * 1024;
        const PA_MASK_4KIB: u64 = 0x0000_FFFF_FFFF_F000;
        const VALID: u64 = 1;
        const AP_MASK: u64 = 0b11 << 6;
        const AP_USER_RO: u64 = 0b11 << 6;
        const NON_GLOBAL: u64 = 1 << 11;

        if !self.persistent_vm_lifecycle {
            return Ok(None);
        }
        let page_va = align_down(va, PAGE_SIZE);
        let retained_ipa = self
            .page_tables_authority()
            .with_manager(|manager| manager.translate_retained_output(page_va))
            .flatten();
        let Some(retained_ipa) = retained_ipa else {
            return Ok(None);
        };
        if self.physical_cow_source(page_va, retained_ipa).is_some()
            && !self.retained_output_lacks_exclusive_claim(retained_ipa)
        {
            return Ok(None);
        }
        if !self.protections.range_unmapped(page_va, 1) {
            return Err(TrapError::Hypervisor(format!(
                "HVPatch live VA 0x{page_va:x} names retired stage-2 IPA 0x{retained_ipa:x}"
            )));
        }

        let identity = self.cow_identity.ok_or_else(|| {
            TrapError::Hypervisor("HVPatch retained reuse has no bound mm identity".to_owned())
        })?;
        let authority = self.cow_authority.clone().ok_or_else(|| {
            TrapError::Hypervisor("HVPatch retained reuse has no inventory authority".to_owned())
        })?;
        let _quiesce = authority.quiesce().map_err(|error| {
            TrapError::Hypervisor(format!("quiesce HVPatch retained reuse: {error}"))
        })?;
        let _topology = crate::fork_quiesce::acquire_topology_lock(
            carrick_observability::probes::HvpatchTopologyOperation::AliasMap,
            identity.linux_pid,
            identity.linux_tid,
        );

        // Another sibling may have repaired the leaf while this thread waited.
        let retained_ipa = self
            .page_tables_authority()
            .with_manager(|manager| manager.translate_retained_output(page_va))
            .flatten();
        let Some(retained_ipa) = retained_ipa else {
            return Ok(None);
        };
        if self.physical_cow_source(page_va, retained_ipa).is_some()
            && !self.retained_output_lacks_exclusive_claim(retained_ipa)
        {
            // A live PRIVATE source means a sibling repaired the leaf; nothing
            // to materialize. A live SHARED source is the case this exists
            // for: the mm must get its own zeroed replacement rather than
            // writing through (corruption) or reading through (disclosure)
            // the other mm's frame.
            return Ok(None);
        }

        let compound_va = align_down(page_va, CowArmedRanges::COMPOUND_SIZE);
        let compound_end = compound_va
            .checked_add(CowArmedRanges::COMPOUND_SIZE)
            .ok_or_else(|| {
                TrapError::Hypervisor("HVPatch retained reuse compound overflow".to_owned())
            })?;
        // Extend past the trigger page only across pages in EXACTLY its state.
        //
        // The predicate above (a retained stage-1 output naming no live
        // physical source) selected `page_va` alone; the rest of the compound
        // was taken on trust. That is wrong, because a page whose backing was
        // published moments earlier by `materialize_sparse_mmap_extent` is
        // indistinguishable from a retired one AT THE LEAF: sparse
        // materialization deliberately leaves its stage-1 receipts invalid
        // until the protection commit. Repointing such a page replaces a live
        // physical owner and falsifies the `PendingFrameCowPublication` that
        // names it, so the `protect_range` that follows in the same guest
        // `mmap` fails to authenticate its own receipt and the guest gets
        // MAP_FAILED — with, before this, no explanation anywhere. That is the
        // shape that broke every CPython `dlopen` of a DSO whose PROT_NONE
        // reservation started one page into a 16 KiB compound.
        //
        // Authenticate each page against the live translation and the exact
        // current owner instead, and stop at the first page that already has
        // one. Splitting a compound across frames is already supported — the
        // repoint covers exactly `[page_va, span_end)`.
        let mut span_end = requested_end.min(compound_end);
        let mut probe = page_va.saturating_add(PAGE_SIZE);
        while probe < span_end {
            let retained = self
                .page_tables_authority()
                .with_manager(|manager| manager.translate_retained_output(probe))
                .flatten();
            let needs_materialization = retained.is_some_and(|ipa| {
                self.physical_cow_source(probe, ipa).is_none()
                    || self.retained_output_lacks_exclusive_claim(ipa)
            }) && self.protections.range_unmapped(probe, 1);
            if !needs_materialization {
                span_end = probe;
                break;
            }
            probe = probe.saturating_add(PAGE_SIZE);
        }
        let span_len = usize::try_from(span_end.checked_sub(page_va).ok_or_else(|| {
            TrapError::Hypervisor("HVPatch retained reuse span underflow".to_owned())
        })?)
        .map_err(|_| TrapError::MappingTooLarge(span_end.saturating_sub(page_va)))?;
        if span_len == 0 {
            return Ok(None);
        }
        let physical_offset = page_va.checked_sub(compound_va).ok_or_else(|| {
            TrapError::Hypervisor("HVPatch retained reuse offset underflow".to_owned())
        })?;
        let page_table_host = self
            .mapping_for_range(
                crate::memory::LINUX_PAGE_TABLES_BASE,
                carrick_mem::memory::LINUX_PAGE_TABLES_SIZE as usize,
            )
            .map(|mapping| mapping.host_addr)
            .ok_or_else(|| {
                TrapError::Hypervisor("HVPatch retained reuse has no page-table backing".to_owned())
            })?;

        let mut reservation = authority.reserve(1, 1, 2).map_err(|error| {
            TrapError::Hypervisor(format!("reserve HVPatch retained reuse inventory: {error}"))
        })?;
        let backing = Self::private_backing_identity();
        let new_host = crate::host_mapping::OwnedHostMapping::map_shared_anon(
            CowArmedRanges::COMPOUND_SIZE as usize,
            crate::host_mapping::HostMappingKind::FrameCow,
        )
        .map_err(|error| {
            TrapError::Hypervisor(format!("allocate HVPatch retained reuse backing: {error}"))
        })?;
        let new_host_ptr = new_host.as_ptr();
        let mut new_lease = GlobalFrameStage2Lease::reserve(
            CowArmedRanges::COMPOUND_SIZE,
            CowArmedRanges::COMPOUND_SIZE,
        )?;
        let new_physical_ipa = new_lease.base;
        let new_ipa = new_physical_ipa
            .checked_add(physical_offset)
            .ok_or_else(|| TrapError::Hypervisor("retained reuse IPA overflow".to_owned()))?;
        let stage2_perms = applevisor::memory::MemPerms::ReadWriteExec;
        let map_result = unsafe {
            inventory_hv_vm_map(
                new_host_ptr.cast(),
                new_physical_ipa,
                CowArmedRanges::COMPOUND_SIZE as usize,
                u64::from(stage2_perms),
            )
        };
        if map_result != 0 {
            return Err(TrapError::Hypervisor(format!(
                "map retained reuse IPA 0x{new_physical_ipa:x}: 0x{map_result:x}"
            )));
        }
        new_lease.mark_mapped();
        let custody = self.carrier_vm_custody();
        let owner_generation = register_global_frame_host_owner_in(
            &custody,
            new_lease,
            new_host,
            u64::from(stage2_perms),
        )?;
        let mut owner_rollback = GlobalFrameOwnerRollback::new(custody);
        owner_rollback.record((new_physical_ipa, CowArmedRanges::COMPOUND_SIZE));

        let inventory_mapping = {
            let mut inventory = self.frame_inventory.lock();
            Self::stage_mapping_in(
                self.custody(),
                &mut inventory,
                &mut reservation,
                InventoryMappingStage {
                    gpa: new_physical_ipa,
                    length: CowArmedRanges::COMPOUND_SIZE,
                    permissions: carrick_hal::MemPerms {
                        read: true,
                        write: true,
                        exec: true,
                    },
                    backing,
                    inherited_frame: None,
                    stage2_lease: Some((new_physical_ipa, CowArmedRanges::COMPOUND_SIZE)),
                    stage2_owner: InventoryStage2OwnerIdentity {
                        host_addr: new_host_ptr as usize,
                        generation: owner_generation,
                    },
                },
            )?
        };
        let inventory_entry = (
            (new_physical_ipa, CowArmedRanges::COMPOUND_SIZE),
            inventory_mapping,
        );

        // Journal this transaction's descriptor pre-images rather than
        // cloning the whole 1.75 MiB table region (see `begin_undo`).
        let publication = {
            let page_tables_authority = self.page_tables_authority();
            page_tables_authority
                .edit(
                    || {
                        Err(TrapError::Hypervisor(
                            "HVPatch retained reuse page tables are absent".to_owned(),
                        ))
                    },
                    |editor| -> Result<(), TrapError> {
                        editor.begin_undo();
                        Self::refresh_stage1_exclusivity(editor.manager);
                        editor
                            .repoint_preserving_attributes(page_va, new_ipa, span_len as u64)
                            .map_err(|error| {
                                TrapError::Hypervisor(format!(
                                    "repoint HVPatch retained reuse leaves: {error:?}"
                                ))
                            })?;
                        // `PtOp::Invalidate` intentionally preserves AP. A retired overlay
                        // may therefore carry invalid+RW attributes, while the deferred
                        // PROT_NONE publication is required to authenticate invalid+RO.
                        // Normalize the unpublished leaves to fork-RO/nG now; a later RW
                        // protect changes AP while preserving the exact fresh IPA.
                        editor
                            .set_fork_readonly(page_va, span_len)
                            .map_err(|error| {
                                TrapError::Hypervisor(format!(
                                    "restrict HVPatch retained reuse leaves: {error:?}"
                                ))
                            })?;
                        self.publish_stage1_extension_arenas(editor.manager)?;
                        let page_table_resolver =
                            self.page_table_resolver(editor.base(), Some(page_table_host));
                        unsafe { editor.sync_to_host(page_table_resolver) }.map_err(|e| {
                            TrapError::Hypervisor(format!("retained reuse sync_to_host failed: {e:?}"))
                        })?;
                        let mut current = page_va;
                        while current < span_end {
                            let expected_ipa = new_ipa.checked_add(current - page_va).ok_or_else(|| {
                                TrapError::Hypervisor("retained reuse leaf IPA overflow".to_owned())
                            })?;
                            let shadow = editor.debug_walk(current);
                            let live = unsafe { editor.debug_walk_host(page_table_resolver, current) }
                                .map_err(|e| {
                                    TrapError::Hypervisor(format!(
                                        "retained reuse debug_walk_host failed: {e:?}"
                                    ))
                                })?;
                            if shadow != live {
                                return Err(TrapError::Hypervisor(format!(
                                    "HVPatch retained reuse shadow/live mismatch at VA 0x{current:x}"
                                )));
                            }
                            let leaf = live[3];
                            if leaf & VALID != 0
                                || leaf & PA_MASK_4KIB != expected_ipa & PA_MASK_4KIB
                                || leaf & AP_MASK != AP_USER_RO
                                || leaf & NON_GLOBAL == 0
                            {
                                return Err(TrapError::Hypervisor(format!(
                                    "HVPatch retained reuse leaf authentication failed at VA 0x{current:x}: leaf=0x{leaf:x} expected_ipa=0x{expected_ipa:x}"
                                )));
                            }
                            current = current.saturating_add(PAGE_SIZE);
                        }
                        Ok::<(), TrapError>(())
                    },
                )
        };
        if let Err(error) = publication {
            let _ = self.page_tables_authority().edit(
                || Err(()),
                |editor| {
                    let manager_base = editor.base();
                    let page_table_resolver = |base: u64| {
                        (base == manager_base)
                            .then_some(page_table_host)
                            .or_else(|| {
                                self.host_ptr(
                                    base,
                                    carrick_mem::memory::LINUX_PAGE_TABLES_SIZE as usize,
                                )
                            })
                    };
                    // SAFETY: the COW quiesce and topology guards remain held.
                    unsafe { editor.rollback_undo(page_table_resolver) };
                    Ok::<(), ()>(())
                },
            );
            if let Err(flush_error) = flush_stage1() {
                carrick_fatal!(
                    "hvpatch::mm_authority",
                    "retained reuse rollback TLBI failed: {flush_error}"
                );
            }
            Self::rollback_unpublished_mappings(
                &mut self.frame_inventory.lock(),
                &[inventory_entry],
            )?;
            return Err(error);
        }
        // Publication succeeded: the journalled pre-images are no longer needed.
        let _ = self.page_tables_authority().edit(
            || Err(()),
            |editor| {
                editor.commit_undo();
                Ok::<(), ()>(())
            },
        );
        if let Err(error) = flush_stage1() {
            carrick_fatal!(
                "hvpatch::mm_authority",
                "retained reuse stage-1 TLBI failed: {error}"
            );
        }
        if let Err(error) = authority.apply(reservation.commit(())) {
            carrick_fatal!(
                "hvpatch::frame_inventory",
                "retained reuse inventory commit failed: {error}"
            );
        }
        owner_rollback.commit();

        match authority.mapping_is_live(
            inventory_mapping.mapping,
            inventory_mapping.frame,
            carrick_guest_mem::Gpa(new_physical_ipa),
            carrick_hal::FrameLength::from_mapping_extent(
                std::num::NonZeroU64::new(CowArmedRanges::COMPOUND_SIZE).unwrap_or_else(|| {
                    carrick_fatal!(
                        "hvpatch::frame_inventory",
                        "retained reuse compound extent is zero"
                    );
                }),
            ),
        ) {
            Ok(true) => {}
            Ok(false) => {
                carrick_fatal!(
                    "hvpatch::cow_token",
                    "retained reuse mapping absent after commit"
                );
            }
            Err(error) => {
                carrick_fatal!(
                    "hvpatch::cow_token",
                    "authenticate retained reuse mapping: {error}"
                );
            }
        }

        let semantic_host = unsafe { new_host_ptr.add(physical_offset as usize) };
        let sharing = GuestMappingSharing::Private;
        register_shared_alias(AliasBacking {
            start: page_va,
            ipa: new_ipa,
            host_addr: semantic_host as usize,
            size: span_len,
            physical_ipa: new_physical_ipa,
            physical_host_addr: new_host_ptr as usize,
            physical_size: CowArmedRanges::COMPOUND_SIZE as usize,
            perms: u64::from(stage2_perms),
            guest_writable: true,
            sharing,
            ownership_scope: alias_ownership_scope(sharing, self.mm_root_slot, self.container_root),
            inventory_backing: backing,
            shared_key_base: 0,
            shared_key_offset: 0,
            owner_generation,
        });
        self.mappings.insert(HvfMappedRegion {
            start: page_va,
            ipa: new_ipa,
            physical_ipa: new_physical_ipa,
            end: span_end,
            host_addr: semantic_host,
            size: CowArmedRanges::COMPOUND_SIZE as usize,
            physical_size: CowArmedRanges::COMPOUND_SIZE as usize,
            perms: stage2_perms,
            memory: None,
            host_mapping: None,
            structural_owner: None,
            stage2_lease: None,
            is_dynamic_alias: true,
            sharing,
            guest_writable: true,
            shared_key_base: 0,
            shared_key_offset: 0,
            owner_generation,
        });
        self.supersede_cow_receipts("retained-reuse", page_va, span_len as u64);
        let mut pending = self.cow_deferred_publications.lock();
        let mut current = page_va;
        while current < span_end {
            pending.push(PendingFrameCowPublication {
                va: current,
                len: PAGE_SIZE as usize,
                expected_ipa: new_ipa + (current - page_va),
            });
            current = current.saturating_add(PAGE_SIZE);
        }
        // This fresh frame is private to the reusing mm. A semantic arm can
        // outlive the retired physical lease (or be reintroduced by a later
        // fork from a broad arena descriptor), but carrying that arm into the
        // following `protect_range(PROT_WRITE)` would immediately force the
        // newly published leaves back to RO and fail their deferred receipt.
        if let Some(debug_va) = fork_debug_va()
            && debug_va >= page_va
            && debug_va < page_va.saturating_add(span_len as u64)
        {
            eprintln!(
                "[DISARMDBG retained-reuse pid={:?} mm={:?}] span=({page_va:#x},{span_len:#x})",
                self.cow_identity.map(|identity| identity.linux_pid),
                self.cow_identity.map(|identity| identity.mm),
            );
        }
        self.cow_armed.lock().disarm(CowArmedSpan {
            va: page_va,
            len: span_len,
            executable: false,
            kernel_only: false,
        });
        Ok(Some(span_end))
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl HvfTaskState {
    pub(crate) fn publish_shared_repoint(
        &mut self,
        va: u64,
        target_ipa: u64,
        len: usize,
    ) -> Result<(), TrapError> {
        let target_end = target_ipa.checked_add(len as u64).ok_or_else(|| {
            TrapError::Hypervisor("shared repoint target IPA overflow".to_owned())
        })?;

        let (
            physical_ipa,
            physical_size,
            physical_host_addr,
            perms,
            mapping_owner_generation,
            shared_key_base,
            shared_key_offset,
            alias_inventory_backing,
        ) = if let Some(mapping) = self.mappings.iter().rev().find(|mapping| {
            let mapping_end = mapping.ipa.checked_add(mapping.size as u64);
            let phys_end = mapping
                .physical_ipa
                .checked_add(mapping.physical_size as u64);
            ((target_ipa >= mapping.ipa && mapping_end.is_some_and(|limit| target_end <= limit))
                || (target_ipa >= mapping.physical_ipa
                    && phys_end.is_some_and(|limit| target_end <= limit)))
                && (!self.persistent_vm_lifecycle
                    || !is_reusable_global_frame_extent(
                        mapping.physical_ipa,
                        mapping.physical_size as u64,
                    )
                    || global_frame_region_owner_matches_in(self.custody(), mapping))
        }) {
            let physical_ipa = mapping.physical_ipa;
            let physical_size = mapping.physical_size;
            let mapping_ipa = mapping.ipa;
            let mapping_host = mapping.host_addr as usize;
            let physical_offset = mapping_ipa.checked_sub(physical_ipa).ok_or_else(|| {
                TrapError::Hypervisor(
                    "shared repoint mapping precedes its physical extent".to_owned(),
                )
            })? as usize;
            let physical_host_addr =
                mapping_host.checked_sub(physical_offset).ok_or_else(|| {
                    TrapError::Hypervisor("shared repoint physical host underflow".to_owned())
                })?;
            let owner_gen = mapping
                .structural_owner
                .as_ref()
                .map(|owner| owner.epoch().raw())
                .unwrap_or(mapping.owner_generation);
            (
                physical_ipa,
                physical_size,
                physical_host_addr,
                mapping.perms,
                owner_gen,
                mapping.shared_key_base,
                mapping.shared_key_offset,
                None,
            )
        } else {
            let alias = alias_registry()
                .lock()
                .newest_matching_for_process(self.mm_root_slot, self.container_root, |alias| {
                    let alias_end = alias.ipa.checked_add(alias.size as u64);
                    let phys_end = alias.physical_ipa.checked_add(alias.physical_size as u64);
                    ((target_ipa >= alias.ipa
                        && alias_end.is_some_and(|limit| target_end <= limit))
                        || (target_ipa >= alias.physical_ipa
                            && phys_end.is_some_and(|limit| target_end <= limit)))
                        && alias_matches_process_scope(
                            alias.ownership_scope,
                            self.mm_root_slot,
                            self.container_root,
                        )
                        && (!self.persistent_vm_lifecycle
                            || !is_reusable_global_frame_extent(
                                alias.physical_ipa,
                                alias.physical_size as u64,
                            )
                            || global_frame_host_owner_matches_in(
                                self.custody(),
                                alias.physical_ipa,
                                alias.physical_size as u64,
                                alias.physical_host_addr,
                                alias.owner_generation,
                            ))
                })
                .ok_or_else(|| {
                    TrapError::Hypervisor(format!(
                        "shared repoint IPA 0x{target_ipa:x} size {len} has no physical owner"
                    ))
                })?;
            let perms = match alias.perms {
                0 => applevisor::memory::MemPerms::None,
                1 => applevisor::memory::MemPerms::Read,
                2 => applevisor::memory::MemPerms::Write,
                3 => applevisor::memory::MemPerms::ReadWrite,
                4 => applevisor::memory::MemPerms::Exec,
                5 => applevisor::memory::MemPerms::ReadExec,
                6 => applevisor::memory::MemPerms::WriteExec,
                7 => applevisor::memory::MemPerms::ReadWriteExec,
                _ => applevisor::memory::MemPerms::ReadWrite,
            };
            (
                alias.physical_ipa,
                alias.physical_size,
                alias.physical_host_addr,
                perms,
                alias.owner_generation,
                alias.shared_key_base,
                alias.shared_key_offset,
                Some(alias.inventory_backing),
            )
        };

        let semantic_offset = target_ipa.checked_sub(physical_ipa).ok_or_else(|| {
            TrapError::Hypervisor("shared repoint precedes its physical extent".to_owned())
        })?;
        let host_addr = physical_host_addr
            .checked_add(semantic_offset as usize)
            .ok_or_else(|| {
                TrapError::Hypervisor("shared repoint semantic host overflow".to_owned())
            })?;

        let inventory_backing = alias_inventory_backing
            .or_else(|| {
                let registry = alias_registry().lock();
                registry
                    .physical_start_rows(physical_ipa)
                    .iter()
                    .find(|(_, alias)| alias.physical_size == physical_size)
                    .map(|(_, alias)| alias.inventory_backing)
                    .or_else(|| {
                        registry
                            .physical_start_rows(physical_ipa)
                            .first()
                            .map(|(_, alias)| alias.inventory_backing)
                    })
            })
            .or_else(|| {
                self.frame_inventory
                    .lock()
                    .extents
                    .get(&(physical_ipa, physical_size as u64))
                    .map(|extent| extent.backing)
            })
            .or_else(|| (!self.persistent_vm_lifecycle).then(HvfVmState::private_backing_identity))
            .ok_or_else(|| {
                TrapError::Hypervisor(format!(
                    "shared repoint physical IPA 0x{:x} size {} lacks frame inventory",
                    physical_ipa, physical_size
                ))
            })?;

        let owner_generation =
            if is_reusable_global_frame_extent(physical_ipa, physical_size as u64) {
                global_frame_host_owner_generation_in(
                    self.custody(),
                    physical_ipa,
                    physical_size as u64,
                )
            } else {
                mapping_owner_generation
            };

        self.page_tables_authority().edit(
            || {
                Err(TrapError::Hypervisor(
                    "repoint shared leaf stage-1 tables are absent".to_owned(),
                ))
            },
            |tables| {
                tables
                    .map_aliased(va, target_ipa, len as u64, true)
                    .map_err(|e| {
                        TrapError::Hypervisor(format!("repoint shared leaf pt edit: {e:?}"))
                    })
            },
        )?;

        let shared_key_offset = shared_key_offset.saturating_add(semantic_offset);
        let sharing = GuestMappingSharing::GlobalShared;
        register_shared_alias(AliasBacking {
            start: va,
            ipa: target_ipa,
            host_addr,
            size: len,
            physical_ipa,
            physical_host_addr,
            physical_size,
            perms: u64::from(perms),
            guest_writable: true,
            sharing,
            ownership_scope: alias_ownership_scope(sharing, self.mm_root_slot, self.container_root),
            inventory_backing,
            shared_key_base,
            shared_key_offset,
            owner_generation,
        });
        self.mappings.insert(HvfMappedRegion {
            start: va,
            ipa: target_ipa,
            physical_ipa,
            end: va.saturating_add(len as u64),
            host_addr: host_addr as *mut u8,
            size: len,
            physical_size,
            perms,
            memory: None,
            host_mapping: None,
            structural_owner: None,
            stage2_lease: None,
            is_dynamic_alias: true,
            sharing,
            guest_writable: true,
            shared_key_base,
            shared_key_offset,
            owner_generation,
        });
        Ok(())
    }

    /// Walk the guest's live stage-1 page tables to resolve `va`→IPA (the output
    /// address carrick `hv_vm_map`'d). `None` if unmapped. Used to disambiguate
    /// overlapping high-VA alias regions in `mapping_for_range[_mut]`.
    pub(crate) fn translate_va(&self, va: u64) -> Option<u64> {
        self.page_tables_authority()
            .with_manager(|manager| manager.translate(va))
            .flatten()
    }

    fn live_stage1_names_writable_private_mapping(
        &self,
        custody: &CarrierVmCustody,
        fault_va: u64,
        mapping: MappingView,
    ) -> Result<bool, TrapError> {
        const VALID_PAGE: u64 = 0b11;
        const NON_GLOBAL: u64 = 1 << 11;
        const AP_MASK: u64 = 0b11 << 6;
        const AP_USER_RW: u64 = 0b01 << 6;
        const PA_MASK_4KIB: u64 = 0x0000_FFFF_FFFF_F000;
        const PAGE_SIZE: u64 = 4 * 1024;

        let page_va = align_down(fault_va, PAGE_SIZE);
        let expected_ipa = mapping
            .ipa
            .checked_add(page_va.checked_sub(mapping.start).ok_or_else(|| {
                TrapError::Hypervisor("HVPatch winner PTE precedes mapping start".to_owned())
            })?)
            .ok_or_else(|| TrapError::Hypervisor("HVPatch winner PTE IPA overflow".to_owned()))?;
        let page_table_host = self
            .mapping_for_range_in(
                custody,
                crate::memory::LINUX_PAGE_TABLES_BASE,
                carrick_mem::memory::LINUX_PAGE_TABLES_SIZE as usize,
            )
            .map(|mapping| mapping.host_addr)
            .ok_or_else(|| {
                TrapError::Hypervisor("HVPatch winner PTE page-table backing is absent".to_owned())
            })?;
        let page_tables_authority = self.page_tables_authority();
        page_tables_authority
            .with_manager(|manager| -> Result<bool, TrapError> {
                let shadow = manager.debug_walk(page_va);
                let page_table_resolver =
                    self.page_table_resolver(manager.base(), Some(page_table_host));
                let live = unsafe { manager.debug_walk_host(page_table_resolver, page_va) }
                    .map_err(|e| {
                        TrapError::Hypervisor(format!(
                            "HVPatch winner PTE debug_walk_host failed: {e:?}"
                        ))
                    })?;
                if shadow != live {
                    return Err(TrapError::Hypervisor(format!(
                        "HVPatch winner PTE shadow/live mismatch at VA 0x{page_va:x}: shadow={shadow:x?} live={live:x?}"
                    )));
                }
                let leaf = live[3];
                Ok(leaf & VALID_PAGE == VALID_PAGE
                    && leaf & NON_GLOBAL != 0
                    && leaf & AP_MASK == AP_USER_RW
                    && leaf & PA_MASK_4KIB == expected_ipa & PA_MASK_4KIB)
            })
            .ok_or_else(|| {
                TrapError::Hypervisor("HVPatch winner PTE manager is absent".to_owned())
            })?
    }

    /// Called only under the COW quiesce and topology guards. Use the complete
    /// physical alias bucket, not only live leaves: even a retained invalid
    /// projection or a foreign/stale alias conservatively prevents reuse.
    fn private_cow_lane_candidate(
        &self,
        custody: &CarrierVmCustody,
        authority: &dyn carrick_hal::FrameCowAuthority,
        span: CowArmedSpan,
        source_ipa: u64,
        offset: u64,
    ) -> Option<(PhysicalCowSource, InventoryExtent)> {
        if span.len != 0x1000 || span.kernel_only || span.va % 0x1000 != 0 {
            return None;
        }
        let scope = AliasRegistry::owned_scope(self.mm_root_slot, self.container_root);
        let base = align_down(span.va, CowArmedRanges::COMPOUND_SIZE);
        for lane in 0..4 {
            let neighbor = base + lane * 0x1000;
            if neighbor == span.va {
                continue;
            }
            let Some(ipa) = self.translate_va_for_cow(neighbor) else {
                continue;
            };
            let key = (
                align_down(ipa, CowArmedRanges::COMPOUND_SIZE),
                CowArmedRanges::COMPOUND_SIZE,
            );
            if key.0 == source_ipa {
                continue;
            }
            let extent = {
                let inventory = self.frame_inventory.lock();
                let Some(extent) = inventory.extents.get(&key).copied() else {
                    continue;
                };
                let frames = inventory.frames.lock();
                if frames.references.get(&extent.frame) != Some(&1)
                    || frames.extent_references.get(&(extent.frame, key.0, key.1)) != Some(&1)
                    || frames.stage2_references.get(&key) != Some(&1)
                {
                    continue;
                }
                extent
            };
            let aliases: Vec<_> = alias_registry()
                .lock()
                .by_physical_start
                .get(&key.0)
                .into_iter()
                .flatten()
                .map(|(_, alias)| *alias)
                .collect();
            if !cow_lane_is_unpublished(key, extent, scope, offset, &aliases) {
                continue;
            }
            let length =
                carrick_hal::FrameLength::from_mapping_extent(std::num::NonZeroU64::new(key.1)?);
            if authority.frame_mapping_count(extent.frame).ok() != Some(Some(1))
                || authority
                    .mapping_is_live(
                        extent.mapping,
                        extent.frame,
                        carrick_guest_mem::Gpa(key.0),
                        length,
                    )
                    .ok()
                    != Some(true)
            {
                continue;
            }
            let Some(pin) = pin_exact_live_global_frame_owner_in(
                custody,
                key.0,
                key.1,
                extent.stage2_owner.host_addr,
                extent.stage2_owner.generation,
            ) else {
                continue;
            };
            return Some((PhysicalCowSource::pinned(pin, 0, key.0), extent));
        }
        None
    }

    fn perform_frame_cow(
        &mut self,
        custody: &std::sync::Arc<CarrierVmCustody>,
        fault_va: u64,
        intent: carrick_aarch64::vmm::FrameCowWriteIntent,
        trigger: FrameCowTrigger,
        flush_stage1: &mut dyn FnMut() -> Result<(), TrapError>,
    ) -> Result<bool, TrapError> {
        let identity = self.cow_identity.ok_or_else(|| {
            TrapError::Hypervisor("HVPatch frame COW has no bound mm identity".to_owned())
        })?;
        let authority = self.cow_authority.clone().ok_or_else(|| {
            TrapError::Hypervisor("HVPatch frame COW has no inventory authority".to_owned())
        })?;
        // Lock order matches every runtime page-table editor: pause sibling
        // walkers first, then serialize shared HVF stage-2/alias topology.
        let _quiesce = authority.quiesce().map_err(|error| {
            TrapError::Hypervisor(format!("quiesce HVPatch frame COW: {error}"))
        })?;
        let _topology = crate::fork_quiesce::acquire_topology_lock(
            carrick_observability::probes::HvpatchTopologyOperation::FrameCow,
            identity.linux_pid,
            identity.linux_tid,
        );

        // Another vCPU of this mm may have won while we waited for topology.
        // Take only what the fault path needs. This used to CLONE the whole
        // armed-range vector on EVERY COW fault — a heap allocation and copy
        // proportional to the mm's armed range count — to serve one boolean
        // and two diagnostics. A fork arms every private writable range, so
        // the clone grew with the very thing the faults are resolving.
        let (span, armed_is_empty, armed_len) = {
            let cow_armed = self.cow_armed.lock();
            (
                cow_armed.span_for(fault_va),
                cow_armed.ranges.is_empty(),
                cow_armed.ranges.len(),
            )
        };
        let Some(span) = span else {
            let mapping = self.mapping_for_range_in(custody, fault_va, 1);
            let write_denied = self.protections.range_write_denied(fault_va, 1);
            let private_writable_mapping = mapping.is_some_and(|mapping| {
                mapping.guest_writable && mapping.sharing == GuestMappingSharing::Private
            });
            let live_leaf_is_writable = match mapping {
                Some(mapping) if private_writable_mapping && !write_denied => {
                    self.live_stage1_names_writable_private_mapping(custody, fault_va, mapping)?
                }
                _ => false,
            };
            if let Some(debug_va) = fork_debug_va()
                && align_down(fault_va, 4 * 1024) == align_down(debug_va, 4 * 1024)
            {
                eprintln!(
                    "[COWDBG pid={} tid={}] UNARMED fault va={fault_va:#x} mm={:?} \
                     mapping={:?} write_denied={write_denied} \
                     private_writable={private_writable_mapping} \
                     live_leaf_writable={live_leaf_is_writable} armed_count={}",
                    identity.linux_pid,
                    identity.linux_tid,
                    identity.mm,
                    mapping.map(|m| (m.start, m.end, m.ipa, m.guest_writable, m.sharing)),
                    armed_len,
                );
            }
            match unarmed_permission_fault_route(
                private_writable_mapping,
                write_denied,
                !armed_is_empty,
                live_leaf_is_writable,
            ) {
                UnarmedPermissionFaultRoute::NotCow => return Ok(false),
                UnarmedPermissionFaultRoute::RetryCommittedWinner => {
                    // The exact live descriptor is already writable and names
                    // the current private mapping: a sibling won this COW while
                    // this vCPU was parking. Flush the losing vCPU's stale RO
                    // translation and retry the faulting instruction.
                    flush_stage1()?;
                    return Ok(true);
                }
                UnarmedPermissionFaultRoute::MissingArm => {
                    let mapping_shape = mapping.map(|mapping| {
                        (
                            mapping.start,
                            mapping.end,
                            mapping.ipa,
                            mapping.guest_writable,
                            mapping.sharing,
                        )
                    });
                    return Err(TrapError::Hypervisor(format!(
                        "HVPatch private writable permission fault at VA 0x{fault_va:x} has no COW arm; mapping={mapping_shape:?} write_denied={write_denied} armed={:?}",
                        // Only the fatal path pays to materialize the list.
                        self.cow_armed.lock().ranges
                    )));
                }
            }
        };
        // COW allocation is physical at the 16 KiB host compound, but guest
        // access authority is semantic at the exact fault byte. A compound can
        // cross the current `brk`, mprotect, or partial-unmap edge; rejecting
        // the whole span incorrectly SIGSEGVs a writable byte merely because an
        // adjacent page is denied. Internal backing maintenance is distinct:
        // mmap must zero a reclaimed, currently-unmapped page BEFORE publishing
        // its fresh VMA permission. It still splits/repoints the frame, while
        // the page-table publication below deliberately preserves the denied
        // descriptor until mmap's later `protect_range` commit.
        let source_guest_writable = self
            .mapping_for_range_in(custody, fault_va, 1)
            .ok_or_else(|| {
                TrapError::Hypervisor(format!(
                    "HVPatch COW VA 0x{fault_va:x} has no semantic mapping authority"
                ))
            })?
            .guest_writable;
        if frame_cow_write_is_denied(
            self.protections.range_write_denied(fault_va, 1),
            source_guest_writable,
            intent,
        ) {
            return Ok(false);
        }
        // `span.va` can name the host-granule prefix of a semantic fragment
        // whose first live Linux leaf begins at `fault_va` (Task 1 deliberately
        // keeps semantic and physical extents separate). A guest fault proves
        // that the exact byte translated; backing maintenance may intentionally
        // start from an invalid munmap descriptor, so the mapping-metadata
        // fallback is authoritative for that pre-publication transaction.
        let old_fault_ipa = self.translate_va_for_cow(fault_va).or_else(|| {
            let mapping = self.mapping_for_range_in(custody, fault_va, 1)?;
            mapping
                .ipa
                .checked_add(fault_va.checked_sub(mapping.start)?)
        });
        if let Some(debug_va) = fork_debug_va()
            && align_down(fault_va, 4 * 1024) == align_down(debug_va, 4 * 1024)
        {
            eprintln!(
                "[COWDBG pid={} tid={}] ARMED fault va={fault_va:#x} mm={:?} span=({:#x},{:#x}) old_fault_ipa={old_fault_ipa:?}",
                identity.linux_pid, identity.linux_tid, identity.mm, span.va, span.len,
            );
        }
        let semantic_offset = fault_va.checked_sub(span.va).ok_or_else(|| {
            TrapError::Hypervisor("HVPatch COW fault precedes its armed span".to_owned())
        })?;
        let old_ipa = old_fault_ipa
            .and_then(|ipa| ipa.checked_sub(semantic_offset))
            .ok_or_else(|| {
                TrapError::Hypervisor(format!(
                    "HVPatch COW VA 0x{:x} (fault 0x{fault_va:x}) has no stage-1 or mapping translation",
                    span.va
                ))
            })?;
        let old_source = self
            .physical_cow_source_in(custody, span.va, old_ipa)
            .ok_or_else(|| {
            TrapError::Hypervisor(format!(
                "HVPatch COW VA 0x{:x} IPA 0x{old_ipa:x} has no matching 16 KiB physical backing",
                span.va
            ))
        })?;
        let old_host = old_source.host_addr();
        let old_physical_ipa = old_source.physical_ipa();
        // The semantic span sits at `old_offset` WITHIN its 16 KiB compound.
        // The COW replacement must preserve that intra-compound offset: the
        // 2026-08-23 wedge2 change flattened `new_ipa`/`semantic_host` to the
        // compound base, which COWs the WRONG PAGE for every span whose
        // offset is nonzero — forkcow's child then reads unrelated bytes and
        // SIGSEGVs (bisect-convicted, red 3/3 at that commit, green 3/3 at
        // its parent).
        let old_offset = old_ipa.checked_sub(old_physical_ipa).ok_or_else(|| {
            TrapError::Hypervisor("HVPatch COW physical offset underflow".to_owned())
        })?;
        let retention_aliases = authenticated_cow_retention_aliases_in(
            custody,
            self.mm_root_slot,
            self.container_root,
            old_physical_ipa,
        );
        let retain_old_compound = {
            let page_tables_authority = self.page_tables_authority();
            let retain = page_tables_authority.with_manager(|manager| {
                cow_source_has_retained_projection(
                    span,
                    old_ipa,
                    old_physical_ipa,
                    &retention_aliases,
                    |va| manager.translate_retained_output(va),
                )
            });
            match retain {
                Some(retain) => retain,
                None => {
                    page_tables_authority.emit_absent_probe(1);
                    return Err(TrapError::Hypervisor(
                        "HVPatch COW page-table manager is absent".to_owned(),
                    ));
                }
            }
        };
        let CowInventorySplitShape {
            old_key: old_inventory_key,
            old: old_inventory_extent,
            fragments: fragment_shapes,
            retirement,
        } = {
            let inventory = self.frame_inventory.lock();
            HvfVmState::cow_inventory_split_shape(
                &inventory,
                old_physical_ipa,
                retain_old_compound,
                |frame| {
                    authority.frame_mapping_count(frame).map_err(|error| {
                        TrapError::Hypervisor(format!("query COW frame mapping count: {error}"))
                    })
                },
            )?
        };
        let old_frame = old_inventory_extent.frame;
        // Resolve every authority needed for stage-1 publication before the
        // first physical/staged-inventory mutation.  A fork-time response can
        // run while the engine's mapping metadata is being rebuilt; failing
        // here must leave no staged MappingId for terminal retirement to see.
        let page_table_host = self
            .mapping_for_range_in(
                custody,
                crate::memory::LINUX_PAGE_TABLES_BASE,
                carrick_mem::memory::LINUX_PAGE_TABLES_SIZE as usize,
            )
            .map(|mapping| mapping.host_addr)
            .ok_or_else(|| {
                TrapError::Hypervisor("HVPatch COW page-table backing is absent".to_owned())
            })?;

        let receipt_va = align_down(fault_va, 4 * 1024);
        let trigger_event = carrick_observability::probes::HvpatchFrameCowTrigger::new(
            trigger.class,
            identity.linux_pid,
            identity.linux_tid,
            identity.mm,
            u32::from(identity.asid),
            receipt_va,
            trigger.syndrome,
            trigger.far,
            trigger.ttbr0,
        )
        .unwrap_or_else(|error| {
            carrick_fatal!(
                "hvpatch::cow_token",
                "construct HVPatch frame-COW trigger: {error}"
            );
        });
        crate::probes::hvpatch_frame_cow_trigger(trigger_event);

        let reused_destination = if matches!(
            old_inventory_extent.backing,
            InventoryBackingIdentity::PrivateFileView(_)
        ) && intent
            == carrick_aarch64::vmm::FrameCowWriteIntent::GuestVisible
        {
            self.private_cow_lane_candidate(
                custody,
                authority.as_ref(),
                span,
                old_physical_ipa,
                old_offset,
            )
        } else {
            None
        };
        let reused_extent = reused_destination.as_ref().map(|(_, extent)| *extent);
        let fresh_destination = reused_extent.is_none();
        // Reserve every kernel identity/event slot before physical mutation.
        let mapping_candidates = fragment_shapes
            .len()
            .saturating_add(usize::from(fresh_destination));
        let event_count = 1usize
            .saturating_add(mapping_candidates.saturating_mul(2))
            .saturating_add(usize::from(retirement.retire_old_frame));
        let mut reservation = authority
            .reserve(
                usize::from(fresh_destination),
                mapping_candidates,
                event_count,
            )
            .map_err(|error| {
                TrapError::Hypervisor(format!("reserve frame COW inventory: {error}"))
            })?;
        let stage2_perms = applevisor::memory::MemPerms::ReadWriteExec;
        let pooled = if fresh_destination {
            custody.frame_pool().and_then(|p| p.allocate_compound())
        } else {
            None
        };
        let (new_host_ptr, new_physical_ipa, owner_generation) =
            if let Some((destination, extent)) = &reused_destination {
                // No published alias names this lane. Only the newly touched Linux
                // page is refreshed; previously written neighbors are never copied.
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        old_host.add(old_offset as usize),
                        destination.host_addr().add(old_offset as usize),
                        span.len,
                    );
                    crate::probes::hvpatch_frame_cow_copy(
                        old_frame.raw(),
                        old_ipa,
                        std::slice::from_raw_parts(old_host.add(old_offset as usize), span.len),
                        std::slice::from_raw_parts(
                            destination.host_addr().add(old_offset as usize),
                            span.len,
                        ),
                    );
                }
                drop(old_source);
                (
                    destination.host_addr(),
                    destination.physical_ipa(),
                    extent.stage2_owner.generation,
                )
            } else if let Some(handle) = pooled {
                let host_ptr = handle.as_mut_ptr();
                let physical_ipa = handle.ipa();
                carrick_observability::probes::hvpatch_frame_pool_hit(0, physical_ipa);
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        old_host,
                        host_ptr,
                        CowArmedRanges::COMPOUND_SIZE as usize,
                    );
                }
                let source = unsafe {
                    std::slice::from_raw_parts(
                        old_host.cast_const(),
                        CowArmedRanges::COMPOUND_SIZE as usize,
                    )
                };
                let destination = unsafe {
                    std::slice::from_raw_parts(
                        host_ptr.cast_const(),
                        CowArmedRanges::COMPOUND_SIZE as usize,
                    )
                };
                crate::probes::hvpatch_frame_cow_copy(
                    old_frame.raw(),
                    old_physical_ipa,
                    source,
                    destination,
                );
                drop(old_source);
                let owner_generation = register_pooled_global_frame_host_owner_in(
                    custody,
                    handle,
                    u64::from(stage2_perms),
                )?;
                (host_ptr, physical_ipa, owner_generation)
            } else {
                carrick_observability::probes::hvpatch_frame_pool_miss(0, 0);
                let new_host = crate::host_mapping::OwnedHostMapping::map_shared_anon(
                    CowArmedRanges::COMPOUND_SIZE as usize,
                    crate::host_mapping::HostMappingKind::FrameCow,
                )
                .map_err(|error| {
                    TrapError::Hypervisor(format!("allocate frame COW backing: {error}"))
                })?;
                let new_host_ptr = new_host.as_ptr();
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        old_host,
                        new_host_ptr,
                        CowArmedRanges::COMPOUND_SIZE as usize,
                    );
                }
                let source = unsafe {
                    std::slice::from_raw_parts(
                        old_host.cast_const(),
                        CowArmedRanges::COMPOUND_SIZE as usize,
                    )
                };
                let destination = unsafe {
                    std::slice::from_raw_parts(
                        new_host_ptr.cast_const(),
                        CowArmedRanges::COMPOUND_SIZE as usize,
                    )
                };
                crate::probes::hvpatch_frame_cow_copy(
                    old_frame.raw(),
                    old_physical_ipa,
                    source,
                    destination,
                );
                drop(old_source);
                let mut new_lease = GlobalFrameStage2Lease::reserve(
                    CowArmedRanges::COMPOUND_SIZE,
                    CowArmedRanges::COMPOUND_SIZE,
                )?;
                let new_physical_ipa = new_lease.base;
                let map_result = unsafe {
                    inventory_hv_vm_map(
                        new_host_ptr.cast(),
                        new_physical_ipa,
                        CowArmedRanges::COMPOUND_SIZE as usize,
                        u64::from(stage2_perms),
                    )
                };
                if map_result != 0 {
                    return Err(TrapError::Hypervisor(format!(
                        "map frame COW IPA 0x{new_physical_ipa:x}: 0x{map_result:x}"
                    )));
                }
                new_lease.mark_mapped();
                let owner_generation = register_global_frame_host_owner_in(
                    custody,
                    new_lease,
                    new_host,
                    u64::from(stage2_perms),
                )?;
                (new_host_ptr, new_physical_ipa, owner_generation)
            };
        let new_ipa = new_physical_ipa
            .checked_add(old_offset)
            .ok_or_else(|| TrapError::Hypervisor("HVPatch COW semantic IPA overflow".to_owned()))?;

        let backing = reused_extent.map_or_else(HvfVmState::private_backing_identity, |extent| {
            extent.backing
        });
        let split = match HvfVmState::stage_cow_inventory_split(
            &mut reservation,
            old_inventory_key,
            old_inventory_extent,
            &fragment_shapes,
            retirement,
            CowInventoryReplacementStage {
                existing: reused_extent,
                gpa: new_physical_ipa,
                backing,
                stage2_owner: InventoryStage2OwnerIdentity {
                    host_addr: new_host_ptr as usize,
                    generation: owner_generation,
                },
            },
        ) {
            Ok(split) => split,
            Err(error) => {
                if fresh_destination {
                    let _ = retire_global_frame_host_owner_in(
                        custody,
                        new_physical_ipa,
                        CowArmedRanges::COMPOUND_SIZE,
                    );
                }
                return Err(error);
            }
        };
        let new_frame = split.new_extent.frame;
        let new_mapping = split.new_extent.mapping;
        const PAGE_SIZE: u64 = 4 * 1024;
        let receipt_intent = match intent {
            carrick_aarch64::vmm::FrameCowWriteIntent::GuestVisible => {
                carrick_observability::probes::HvpatchFrameCowIntent::GuestVisible
            }
            carrick_aarch64::vmm::FrameCowWriteIntent::BackingMaintenance => {
                carrick_observability::probes::HvpatchFrameCowIntent::BackingMaintenance
            }
            carrick_aarch64::vmm::FrameCowWriteIntent::PrivilegedInternal => {
                carrick_observability::probes::HvpatchFrameCowIntent::PrivilegedInternal
            }
        };
        let emit_cow = |phase| {
            let event = carrick_observability::probes::HvpatchFrameCow::new(
                phase,
                receipt_intent,
                identity.linux_pid,
                identity.linux_tid,
                identity.mm,
                u32::from(identity.asid),
                receipt_va,
                old_frame.raw(),
                new_frame.raw(),
                old_physical_ipa,
                new_physical_ipa,
            )
            .unwrap_or_else(|error| {
                carrick_fatal!(
                    "hvpatch::cow_token",
                    "construct HVPatch frame-COW receipt: {error}"
                );
            });
            crate::probes::hvpatch_frame_cow(event);
        };
        emit_cow(carrick_observability::probes::HvpatchFrameCowPhase::Stage2Mapped);
        // Journal this transaction's descriptor pre-images rather than
        // cloning the whole 1.75 MiB table region (see `begin_undo`).
        let mut preserved_protection_receipt = None;
        let page_table_result = {
            const PA_MASK_4KIB: u64 = 0x0000_FFFF_FFFF_F000;
            const AP_MASK: u64 = 0b11 << 6;
            const AP_USER_RW: u64 = 0b01 << 6;
            const VALID: u64 = 1;
            const TYPE_TABLE_OR_PAGE: u64 = 0b11;
            const NON_GLOBAL: u64 = 1 << 11;
            let page_tables_authority = self.page_tables_authority();
            page_tables_authority
                .edit(
                    || {
                        page_tables_authority.emit_absent_probe(2);
                        Err(TrapError::Hypervisor(
                            "HVPatch COW page-table manager is absent".to_owned(),
                        ))
                    },
                    |manager| -> Result<(), TrapError> {
                        // The transaction can fail after one or more descriptors were
                        // written to both the manager shadow and live backing, so it needs
                        // a rollback log; the manager's `dirty` list is not one, because
                        // `sync_to_host` drains the NEW edits. `begin_undo` journals the
                        // pre-image of every descriptor this transaction writes.
                        manager.begin_undo();
                        // The leaf authentication below needs the AP bits each page held
                        // BEFORE this transaction, which it used to read by walking a full
                        // cloned pre-image. The span is a single 16 KiB compound, so
                        // capturing just those bits is exact and costs a handful of walks
                        // instead of a 1.75 MiB copy.
                        let mut pre_edit_ap: std::collections::BTreeMap<u64, u64> =
                            std::collections::BTreeMap::new();
                        {
                            let span_end = span.va.saturating_add(span.len as u64);
                            let mut probe_va = span.va & !(PAGE_SIZE - 1);
                            while probe_va < span_end {
                                pre_edit_ap.insert(probe_va, manager.debug_walk(probe_va)[3] & AP_MASK);
                                probe_va = probe_va.saturating_add(PAGE_SIZE);
                            }
                        }
                        HvfVmState::refresh_stage1_exclusivity(manager.manager);
                        if span.kernel_only {
                            manager
                                .map_kernel_aliased(span.va, new_ipa, span.len as u64)
                                .map_err(|error| {
                                    TrapError::Hypervisor(format!(
                                        "publish kernel-only HVPatch COW stage-1 leaf: {error:?}"
                                    ))
                                })?;
                        } else {
                            manager
                                .repoint_preserving_attributes(span.va, new_ipa, span.len as u64)
                                .map_err(|error| {
                                    TrapError::Hypervisor(format!(
                                        "repoint HVPatch COW stage-1 compound: {error:?}"
                                    ))
                                })?;
                            let span_end = span.va.saturating_add(span.len as u64);
                            let mut page_va = span.va & !(PAGE_SIZE - 1);
                            while page_va < span_end {
                                if source_guest_writable && !self.protections.range_write_denied(page_va, 1) {
                                    manager
                                        .set_writable_preserving_attributes(page_va, PAGE_SIZE as usize)
                                        .map_err(|error| {
                                            TrapError::Hypervisor(format!(
                                                "grant HVPatch COW semantic page write: {error:?}"
                                            ))
                                        })?;
                                }
                                page_va = page_va.saturating_add(PAGE_SIZE);
                            }
                        }
                        self.publish_stage1_extension_arenas(manager.manager)?;
                        let page_table_resolver =
                            self.page_table_resolver(manager.base(), Some(page_table_host));
                        unsafe { manager.sync_to_host(page_table_resolver) }.map_err(|e| {
                            TrapError::Hypervisor(format!("HVPatch COW sync_to_host failed: {e:?}"))
                        })?;

                        // A semantic fork result is not structural proof.  Before the
                        // stage-1 TLBI publishes this transaction, authenticate the exact
                        // descriptors the hardware walker will consume: the manager shadow
                        // and live backing must agree, every 4 KiB leaf in this 16 KiB COW
                        // compound must name the new global frame IPA, and its AP bits must
                        // match the EL1-only/user regime.  Fail closed while the old armed
                        // leaf is still live on any mismatch.
                        let span_end = span.va.saturating_add(span.len as u64);
                        let mut page_va = span.va & !(PAGE_SIZE - 1);
                        while page_va < span_end {
                            let expected_ipa = new_ipa.checked_add(page_va - span.va).ok_or_else(|| {
                                TrapError::Hypervisor("HVPatch COW leaf IPA overflow".to_owned())
                            })?;
                            let shadow = manager.debug_walk(page_va);
                            let live = unsafe {
                                manager.debug_walk_host(page_table_resolver, page_va)
                            }
                            .map_err(|e| {
                                TrapError::Hypervisor(format!(
                                    "HVPatch COW debug_walk_host failed: {e:?}"
                                ))
                            })?;
                            if shadow != live {
                                return Err(TrapError::Hypervisor(format!(
                                    "HVPatch COW shadow/live mismatch at VA 0x{page_va:x}"
                                )));
                            }
                            let leaf = live[3];
                            let page_is_valid = leaf & VALID != 0;
                            let expected_ap = if span.kernel_only {
                                0
                            } else if source_guest_writable
                                && !self.protections.range_write_denied(page_va, 1)
                            {
                                AP_USER_RW
                            } else {
                                pre_edit_ap.get(&page_va).copied().ok_or_else(|| {
                                    TrapError::Hypervisor(format!(
                                        "HVPatch COW pre-edit AP bits are absent for VA 0x{page_va:x}"
                                    ))
                                })?
                            };
                            if leaf & PA_MASK_4KIB != expected_ipa & PA_MASK_4KIB
                                || (page_is_valid
                                    && (leaf & 0b11 != TYPE_TABLE_OR_PAGE
                                        || leaf & AP_MASK != expected_ap
                                        || (!span.kernel_only && leaf & NON_GLOBAL == 0)))
                            {
                                return Err(TrapError::Hypervisor(format!(
                                    "HVPatch COW stage-1 leaf authentication failed at VA 0x{page_va:x}: leaf=0x{leaf:x} expected_ipa=0x{expected_ipa:x} expected_ap=0x{expected_ap:x}"
                                )));
                            }
                            if page_va == receipt_va && frame_cow_preserves_guest_protection(intent) {
                                preserved_protection_receipt =
                                    Some((page_va, leaf, expected_ipa, leaf & AP_MASK));
                            } else if page_va == receipt_va {
                                crate::probes::pt_alias_receipt(page_va, leaf, expected_ipa, expected_ap, 2);
                            }
                            // Reuse the durable descriptor-walk probe so a signed live
                            // capture can bind the COW receipt to the exact published PTE.
                            crate::probes::pt_alias_walk(page_va, live, 1 << 3);
                            page_va = page_va.saturating_add(PAGE_SIZE);
                        }
                        Ok(())
                    },
                )
        };
        if let Err(error) = page_table_result {
            let _ = self.page_tables_authority().edit(
                || Err(()),
                |manager| {
                    let manager_base = manager.base();
                    let page_table_resolver = |base: u64| {
                        (base == manager_base)
                            .then_some(page_table_host)
                            .or_else(|| {
                                self.host_ptr_for_ipa(
                                    base,
                                    carrick_mem::memory::LINUX_PAGE_TABLES_SIZE as usize,
                                )
                            })
                    };
                    // SAFETY: the COW quiesce and topology guards remain held;
                    // no vCPU can walk or edit this mm while the journalled
                    // pre-images are replayed into its live backing.
                    unsafe { manager.rollback_undo(page_table_resolver) };
                    Ok::<(), ()>(())
                },
            );
            if let Err(flush_error) = flush_stage1() {
                carrick_fatal!(
                    "hvpatch::mm_authority",
                    "HVPatch COW rollback stage-1 TLBI failed: {flush_error}"
                );
            }
            if fresh_destination {
                let _ = retire_global_frame_host_owner_in(
                    custody,
                    new_physical_ipa,
                    CowArmedRanges::COMPOUND_SIZE,
                );
            }
            return Err(error);
        }
        // Publication succeeded: the journalled pre-images are no longer needed.
        let _ = self.page_tables_authority().edit(
            || Err(()),
            |manager| {
                manager.commit_undo();
                Ok::<(), ()>(())
            },
        );
        if let Err(error) = flush_stage1() {
            carrick_fatal!(
                "hvpatch::mm_authority",
                "HVPatch COW stage-1 TLBI failed: {error}"
            );
        }
        emit_cow(carrick_observability::probes::HvpatchFrameCowPhase::Stage1Published);
        if let Err(error) = authority.apply(reservation.commit(())) {
            carrick_fatal!(
                "hvpatch::frame_inventory",
                "HVPatch COW inventory commit failed: {error}"
            );
        }
        let inventory_ledger = std::sync::Arc::clone(&self.frame_inventory.ledger);
        let retired_old_stage2 = {
            let mut inventory = inventory_ledger.lock();
            HvfVmState::commit_cow_inventory_split(&mut inventory, &split, || {
                self.retire_stage2_extent_for_cow(
                    custody,
                    split.old.stage2_base,
                    split.old.stage2_length,
                )
            })
            .unwrap_or_else(|error| {
                carrick_fatal!(
                    "hvpatch::frame_inventory",
                    "commit HVPatch backend COW inventory after kernel commit: {error}"
                );
            })
        };
        record_cow_inventory_lifecycle(
            CowDiagnosticLifecycleKind::InventoryRemoved,
            CowDiagnosticLifecycleSite::CowCommit,
            custody,
            self.cow_identity,
            self.mm_root_slot,
            span.va,
            span.len as u64,
            split.old_key,
            split.old,
        );
        for fragment in &split.fragments {
            record_cow_inventory_lifecycle(
                CowDiagnosticLifecycleKind::InventoryPublished,
                CowDiagnosticLifecycleSite::CowCommit,
                custody,
                self.cow_identity,
                self.mm_root_slot,
                span.va,
                span.len as u64,
                (fragment.gpa, fragment.length),
                InventoryExtent {
                    frame: split.old.frame,
                    mapping: fragment.mapping,
                    backing: split.old.backing,
                    stage2_base: split.old.stage2_base,
                    stage2_length: split.old.stage2_length,
                    stage2_owner: split.old.stage2_owner,
                },
            );
        }
        if fresh_destination {
            record_cow_inventory_lifecycle(
                CowDiagnosticLifecycleKind::InventoryPublished,
                CowDiagnosticLifecycleSite::CowCommit,
                custody,
                self.cow_identity,
                self.mm_root_slot,
                span.va,
                span.len as u64,
                split.new_key,
                split.new_extent,
            );
        }
        if retired_old_stage2 {
            {
                // Exact physical-owner selection plus a single rebuild of
                // each affected scope. This runs on every COW fault, so it
                // must not clone/diff or retain-scan carrier-global state.
                let retired = [RetiredStage2Projection::from(split.old)];
                let cleanup = mutate_known_external_alias_state(
                    |_, registry| retired_projection_mutation_keys(registry, &retired, &[]),
                    |replay, registry| {
                        remove_rows_for_retired_stage2_projections(replay, registry, &retired)
                    },
                );
                for alias in &cleanup.preserved_reused_aliases {
                    record_cow_alias_lifecycle(
                        CowDiagnosticLifecycleKind::AliasPreservedReused,
                        CowDiagnosticLifecycleSite::CowCommit,
                        Some(custody),
                        self.cow_identity,
                        self.mm_root_slot,
                        *alias,
                    );
                }
                for alias in &cleanup.removed_aliases {
                    record_cow_alias_lifecycle(
                        CowDiagnosticLifecycleKind::AliasRemoved,
                        CowDiagnosticLifecycleSite::CowCommit,
                        Some(custody),
                        self.cow_identity,
                        self.mm_root_slot,
                        *alias,
                    );
                }
            }
            self.mappings.retain(|mapping| {
                !mapped_region_matches_retired_inventory_extent(mapping, split.old.into())
            });
        }
        let Some(cow_extent) = std::num::NonZeroU64::new(CowArmedRanges::COMPOUND_SIZE) else {
            carrick_fatal!(
                "hvpatch::frame_inventory",
                "HVPatch COW compound extent is zero"
            );
        };
        let cow_length = carrick_hal::FrameLength::from_mapping_extent(cow_extent);
        match authority.mapping_is_live(
            new_mapping,
            new_frame,
            carrick_guest_mem::Gpa(new_physical_ipa),
            cow_length,
        ) {
            Ok(true) => {}
            Ok(false) => {
                carrick_fatal!(
                    "hvpatch::cow_token",
                    "authenticated HVPatch COW mapping {new_mapping:?} was absent immediately after commit"
                );
            }
            Err(error) => {
                carrick_fatal!(
                    "hvpatch::cow_token",
                    "authenticate HVPatch COW mapping {new_mapping:?}: {error}"
                );
            }
        }
        emit_cow(carrick_observability::probes::HvpatchFrameCowPhase::Committed);
        // The repoint above replaced this span's stage-1 output. Any receipt
        // still naming the PREVIOUS owner for these VAs — typically the
        // sparse-mmap extent published moments earlier in the very same guest
        // `mmap`, whose leaves are deliberately invalid until the protection
        // commit — is now a false promise, and would fail the authentication
        // that completes this mapping.
        self.supersede_cow_receipts_for_cow(span.va, span.len as u64);
        if let Some((va, leaf, expected_ipa, expected_ap)) = preserved_protection_receipt {
            crate::probes::pt_alias_receipt(va, leaf, expected_ipa, expected_ap, 3);
            if intent == carrick_aarch64::vmm::FrameCowWriteIntent::BackingMaintenance {
                self.cow_deferred_publications
                    .lock()
                    .push(PendingFrameCowPublication {
                        va,
                        len: PAGE_SIZE as usize,
                        expected_ipa,
                    });
            }
        }

        let semantic_host = unsafe { new_host_ptr.add(old_offset as usize) };
        let alias = AliasBacking {
            start: span.va,
            ipa: new_ipa,
            host_addr: semantic_host as usize,
            size: span.len,
            physical_ipa: new_physical_ipa,
            physical_host_addr: new_host_ptr as usize,
            physical_size: CowArmedRanges::COMPOUND_SIZE as usize,
            perms: u64::from(stage2_perms),
            guest_writable: source_guest_writable,
            sharing: GuestMappingSharing::Private,
            ownership_scope: alias_ownership_scope(
                GuestMappingSharing::Private,
                self.mm_root_slot,
                self.container_root,
            ),
            inventory_backing: backing,
            shared_key_base: 0,
            shared_key_offset: 0,
            owner_generation,
        };
        register_shared_alias(alias);
        record_cow_alias_lifecycle(
            CowDiagnosticLifecycleKind::AliasPublished,
            CowDiagnosticLifecycleSite::CowCommit,
            Some(custody),
            self.cow_identity,
            self.mm_root_slot,
            alias,
        );
        record_alias_revision(
            CowDiagnosticAliasRevisionSite::CowPublication,
            custody,
            self.cow_identity,
            new_physical_ipa,
            alias_registry().lock().revision(),
        );
        self.mappings.insert(HvfMappedRegion {
            start: span.va,
            ipa: new_ipa,
            physical_ipa: new_physical_ipa,
            end: span.va.saturating_add(span.len as u64),
            host_addr: semantic_host,
            size: CowArmedRanges::COMPOUND_SIZE as usize,
            physical_size: CowArmedRanges::COMPOUND_SIZE as usize,
            perms: stage2_perms,
            memory: None,
            host_mapping: None,
            structural_owner: None,
            stage2_lease: None,
            is_dynamic_alias: true,
            sharing: GuestMappingSharing::Private,
            guest_writable: source_guest_writable,
            shared_key_base: 0,
            shared_key_offset: 0,
            owner_generation,
        });
        record_cow_diagnostic_event(CowDiagnosticEvent::ReplacementCommitted {
            custody: custody.as_ref() as *const CarrierVmCustody as usize,
            linux_pid: identity.linux_pid,
            mm: identity.mm,
            semantic_va: span.va,
            old_physical_ipa,
            new_physical_ipa,
            new_host_addr: new_host_ptr as usize,
            new_owner_generation: owner_generation,
            new_frame: new_frame.raw(),
            new_mapping: new_mapping.raw(),
            retired_old_stage2,
        });
        if let Some(debug_va) = fork_debug_va()
            && debug_va >= span.va
            && debug_va < span.va.saturating_add(span.len as u64)
        {
            eprintln!(
                "[DISARMDBG split pid={:?} mm={:?}] span=({:#x},{:#x}) new_ipa={new_ipa:#x}",
                self.cow_identity.map(|identity| identity.linux_pid),
                self.cow_identity.map(|identity| identity.mm),
                span.va,
                span.len,
            );
        }
        self.cow_armed.lock().disarm(span);
        Ok(true)
    }

    fn refresh_fork_process_state_in(
        &mut self,
        custody: &std::sync::Arc<CarrierVmCustody>,
        flush_stage1: &mut dyn FnMut() -> Result<(), TrapError>,
    ) -> Result<(), TrapError> {
        let generation_address =
            crate::vdso::LINUX_VVAR_BASE + crate::vdso::VVAR_OFF_RNG_GENERATION as u64;
        if self.cow_armed.lock().span_for(generation_address).is_none() {
            return Err(TrapError::Hypervisor(
                "HVPatch child vvar generation has no COW arm".to_owned(),
            ));
        }
        if !self.perform_frame_cow(
            custody,
            generation_address,
            carrick_aarch64::vmm::FrameCowWriteIntent::PrivilegedInternal,
            FrameCowTrigger {
                class:
                    carrick_observability::probes::HvpatchFrameCowTriggerClass::PrivilegedInternal,
                syndrome: 0,
                far: generation_address,
                ttbr0: 0,
            },
            flush_stage1,
        )? {
            return Err(TrapError::Hypervisor(
                "HVPatch child vvar generation COW was not resolved".to_owned(),
            ));
        }
        let mapping = self
            .mapping_for_range_in(custody, generation_address, core::mem::size_of::<u64>())
            .ok_or_else(|| {
                TrapError::Hypervisor(
                    "HVPatch child vvar generation has no semantic mapping authority after COW"
                        .to_owned(),
                )
            })?;
        let offset = usize::try_from(generation_address - mapping.start).map_err(|_| {
            TrapError::Hypervisor("HVPatch child vvar generation offset overflow".to_owned())
        })?;
        let generation = next_vdso_rng_generation().to_le_bytes();
        unsafe {
            std::ptr::copy_nonoverlapping(
                generation.as_ptr(),
                mapping.host_addr.add(offset),
                generation.len(),
            );
        }
        Ok(())
    }
}

/// Does `zero_guest_backing` REPLACE an eligible reused private anonymous
/// range with fresh kernel zero pages (`mmap MAP_FIXED|MAP_ANON`) instead of
/// memsetting the old backing end to end?
///
/// **DEFAULT ON.** `CARRICK_DSR_ZERO_REMAP=0` is the exact escape hatch
/// (mirroring commit 52342762), preserving the immovable zeroed-anon guarantee
/// while touching nothing.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn zero_anonymous_remap_enabled() -> bool {
    #[cfg(not(test))]
    {
        static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        *ENABLED.get_or_init(|| {
            std::env::var_os("CARRICK_DSR_ZERO_REMAP").as_deref() != Some(std::ffi::OsStr::new("0"))
        })
    }
    #[cfg(test)]
    {
        std::env::var_os("CARRICK_DSR_ZERO_REMAP").as_deref() != Some(std::ffi::OsStr::new("0"))
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) struct ScrubRun {
    pub(crate) host_start: *mut u8,
    pub(crate) len: usize,
    pub(crate) eligible: bool,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl ScrubRun {
    pub(crate) fn flush(self) {
        const HOST_PAGE: usize = 16384;
        let ScrubRun {
            host_start,
            len,
            eligible,
        } = self;
        if len == 0 {
            return;
        }
        let aligned_len = if eligible && (host_start as usize) % HOST_PAGE == 0 {
            len & !(HOST_PAGE - 1)
        } else {
            0
        };
        let mut remapped = false;
        if aligned_len > 0 {
            let mapped = unsafe {
                libc::mmap(
                    host_start as *mut libc::c_void,
                    aligned_len,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_ANON | libc::MAP_PRIVATE | libc::MAP_FIXED,
                    -1,
                    0,
                )
            };
            if mapped == host_start as *mut libc::c_void {
                remapped = true;
                let tail_len = len - aligned_len;
                if tail_len > 0 {
                    unsafe {
                        core::ptr::write_bytes(host_start.add(aligned_len), 0u8, tail_len);
                    }
                }
            } else if mapped != libc::MAP_FAILED {
                unsafe {
                    libc::munmap(mapped, aligned_len);
                }
            }
        }
        if !remapped {
            unsafe {
                core::ptr::write_bytes(host_start, 0u8, len);
            }
        }
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl HvfVmState {
    pub(crate) fn page_table_resolver<'a>(
        &'a self,
        manager_base: u64,
        primary_host: Option<*mut u8>,
    ) -> HvfPageTableResolver<'a> {
        self.task.page_table_resolver(manager_base, primary_host)
    }

    pub(crate) fn record_stage1_populated_prefix(&mut self, base: u64, prefix: usize) {
        self.task.record_stage1_populated_prefix(base, prefix);
    }

    pub(crate) fn publish_stage1_extension_arenas(
        &mut self,
        manager: &carrick_mem::page_table::PageTableManager,
    ) -> Result<(), TrapError> {
        self.task.publish_stage1_extension_arenas(manager)
    }

    pub(crate) fn retire_stage1_extension_arenas(
        &mut self,
        manager: &mut carrick_mem::page_table::PageTableManager,
    ) -> Result<(), TrapError> {
        self.task.retire_stage1_extension_arenas(manager)
    }

    pub(crate) fn resolve_frame_cow_fault(
        &mut self,
        syndrome: u64,
        far: u64,
        ttbr0: u64,
        flush_stage1: &mut dyn FnMut() -> Result<(), TrapError>,
    ) -> Result<carrick_hal::CowFaultResolution, TrapError> {
        if is_stage1_cow_write_fault(syndrome) {
            let fault_va = strip_pointer_tag(far);
            let custody = std::sync::Arc::clone(&self.carrier_foreign_mm_transport.custody);
            let resolved = self.task.perform_frame_cow(
                &custody,
                fault_va,
                carrick_aarch64::vmm::FrameCowWriteIntent::GuestVisible,
                FrameCowTrigger {
                    class: carrick_observability::probes::HvpatchFrameCowTriggerClass::Stage1PermissionFault,
                    syndrome,
                    far: fault_va,
                    ttbr0,
                },
                flush_stage1,
            )?;
            if !resolved {
                return Ok(carrick_hal::CowFaultResolution::NotCow);
            }
            // The refault livelock detector keys on this live post-resolution
            // translation: a fork loop legitimately re-COWs the same VA to a
            // FRESH frame every iteration (fork re-arms the span, the wait loop
            // rewrites the same stack slot), so (FAR, ESR) alone cannot prove
            // the resolver made no progress.
            return Ok(carrick_hal::CowFaultResolution::Resolved {
                translation: self.translate_va(fault_va),
            });
        }

        // Anonymous first touch belongs to the runtime resident-fault plan,
        // which owns exact page permissions, residency and rollback authority.
        Ok(carrick_hal::CowFaultResolution::NotCow)
    }

    pub(crate) fn ensure_frame_cow_write(
        &mut self,
        va: u64,
        len: usize,
        intent: carrick_aarch64::vmm::FrameCowWriteIntent,
        flush_stage1: &mut dyn FnMut() -> Result<(), TrapError>,
    ) -> Result<(), TrapError> {
        if len == 0 {
            return Ok(());
        }
        let start = strip_pointer_tag(va);
        let end = start
            .checked_add(len as u64)
            .ok_or_else(|| TrapError::Hypervisor("HVPatch COW write range overflow".to_owned()))?;
        let mut current = start;
        let mut stalled: Option<(u64, u32)> = None;
        while current < end {
            let (armed_span_end, next_armed_start) = {
                let cow_armed = self.cow_armed.lock();
                (
                    cow_armed
                        .span_for(current)
                        .map(|span| span.va.saturating_add(span.len as u64)),
                    cow_armed.next_armed_start_after(current),
                )
            };
            let armed = armed_span_end.is_some();
            let (retained_output_has_no_physical_source, retained_output_source_is_shared) =
                if intent == carrick_aarch64::vmm::FrameCowWriteIntent::BackingMaintenance
                    && self.persistent_vm_lifecycle
                {
                    match self
                        .page_tables_authority()
                        .with_manager(|manager| manager.translate_retained_output(current))
                        .flatten()
                    {
                        Some(ipa) => {
                            // The retired-reuse materializer serves UNMAPPED
                            // VAs whose leaf retained a dead output. A LIVE VA
                            // in that state (a brk-heap page whose fork-COW
                            // lease retired underneath it) is not its case —
                            // the materializer refuses it by design, and
                            // routing it there turned every brk SHRINK over
                            // such a page into a refusal (ltp-brk02). A live
                            // VA's scrub resolves through its live backing.
                            let unmapped = self.protections.range_unmapped(current, 1);
                            let no_source =
                                unmapped && self.physical_cow_source(current, ipa).is_none();
                            let shared = unmapped
                                && !no_source
                                && self.retained_output_lacks_exclusive_claim(ipa);
                            (no_source, shared)
                        }
                        None => (false, false),
                    }
                } else {
                    (false, false)
                };
            let route = frame_cow_write_route(
                intent,
                armed,
                retained_output_has_no_physical_source,
                retained_output_source_is_shared,
            );
            if let Some(debug_va) = fork_debug_va()
                && current <= debug_va
                && debug_va < end.min(current.saturating_add(CowArmedRanges::COMPOUND_SIZE))
            {
                // Co-ownership audit for the watched VA: which physical frame
                // would a Direct write land in, and does any OTHER mm scope
                // still name that frame? A Direct GuestVisible write into a
                // frame another live mm reads is the fork-child stack-smash
                // corruption shape.
                let translation = self.translate_va(debug_va);
                let mapping = self.mapping_for_range(debug_va, 1).map(|mapping| {
                    (
                        mapping.start,
                        mapping.ipa,
                        mapping.host_addr as usize,
                        mapping.sharing,
                    )
                });
                let target_ipa =
                    mapping.map(|(start, ipa, _, _)| ipa.wrapping_add(debug_va - start));
                let co_owners: Vec<_> = target_ipa
                    .map(|ipa| {
                        alias_registry()
                            .lock()
                            .iter()
                            .filter(|alias| {
                                let base = alias.physical_ipa;
                                let end = base.saturating_add(alias.physical_size as u64);
                                ipa >= base
                                    && ipa < end
                                    && alias.ownership_scope
                                        != alias_ownership_scope(
                                            GuestMappingSharing::Private,
                                            self.mm_root_slot,
                                            self.container_root,
                                        )
                            })
                            .map(|alias| (alias.start, alias.physical_ipa, alias.ownership_scope))
                            .collect()
                    })
                    .unwrap_or_default();
                eprintln!(
                    "[ROUTEDBG pid={:?} mm={:?} slot={:x?}] va={current:#x} intent={intent:?} \
                     armed={armed} armed_len={} \
                     no_source={retained_output_has_no_physical_source} \
                     shared={retained_output_source_is_shared} route={route:?} \
                     translation={translation:x?} mapping={mapping:x?} co_owners={co_owners:x?}",
                    self.cow_identity.map(|identity| identity.linux_pid),
                    self.cow_identity.map(|identity| identity.mm),
                    self.mm_root_slot,
                    self.cow_armed.lock().ranges.len(),
                );
            }
            match route {
                FrameCowWriteRoute::MaterializeRetired => {
                    if let Some(materialized_end) =
                        self.materialize_retired_reuse(current, end, flush_stage1)?
                    {
                        current = materialized_end;
                    }
                    // The materializer rechecks after acquiring quiesce. If a
                    // sibling repaired the leaf first, restart this chunk and
                    // route against the now-current stage-1/physical state.
                    // FAIL CLOSED if the restart makes no progress: a None
                    // return with UNCHANGED routing inputs re-enters this arm
                    // forever — a silent 100% CPU livelock that also starves
                    // this executor's InvalidateAsid servicing and parks every
                    // peer in consume_invalidation_acks (seen live on
                    // futexforkrequeue; core ffr-livelock-76407). Two repeats
                    // are already impossible if the recheck story holds; 16
                    // allows genuine sibling races to win first.
                    match &mut stalled {
                        Some((va, count)) if *va == current => {
                            *count += 1;
                            if *count >= 16 {
                                return Err(TrapError::Hypervisor(format!(
                                    "HVPatch retained-reuse materialization made no progress                                      at 0x{current:x} after {count} restarts                                      (intent={intent:?} armed={armed}                                      no_source={retained_output_has_no_physical_source}                                      shared={retained_output_source_is_shared}) —                                      COW routing livelock"
                                )));
                            }
                        }
                        _ => stalled = Some((current, 1)),
                    }
                    continue;
                }
                FrameCowWriteRoute::CopyOnWrite => {
                    let class = match intent {
                        carrick_aarch64::vmm::FrameCowWriteIntent::GuestVisible => {
                            carrick_observability::probes::HvpatchFrameCowTriggerClass::SyscallGuestWrite
                        }
                        carrick_aarch64::vmm::FrameCowWriteIntent::BackingMaintenance => {
                            carrick_observability::probes::HvpatchFrameCowTriggerClass::BackingMaintenance
                        }
                        carrick_aarch64::vmm::FrameCowWriteIntent::PrivilegedInternal => {
                            carrick_observability::probes::HvpatchFrameCowTriggerClass::PrivilegedInternal
                        }
                    };
                    let custody = std::sync::Arc::clone(&self.carrier_foreign_mm_transport.custody);
                    if !self.task.perform_frame_cow(
                        &custody,
                        current,
                        intent,
                        FrameCowTrigger {
                            class,
                            syndrome: 0,
                            far: current,
                            ttbr0: 0,
                        },
                        flush_stage1,
                    )? {
                        return Err(TrapError::Hypervisor(format!(
                            "HVPatch COW write at 0x{current:x} remained armed"
                        )));
                    }
                }
                FrameCowWriteRoute::Direct => {}
            }
            current =
                next_frame_cow_write_probe(intent, current, end, armed_span_end, next_armed_start);
        }
        Ok(())
    }

    pub(crate) fn observe_frame_cow_protection(
        &mut self,
        va: u64,
        len: usize,
        prot: u64,
    ) -> Result<(), TrapError> {
        const PAGE_SIZE: u64 = 4 * 1024;
        const AP_USER_RW: u64 = 0b01 << 6;
        const AP_USER_RO: u64 = 0b11 << 6;

        if len == 0 {
            return Ok(());
        }
        let end = va.checked_add(len as u64).ok_or_else(|| {
            TrapError::Hypervisor("deferred COW protection range overflow".to_owned())
        })?;
        let pending: Vec<_> = self
            .cow_deferred_publications
            .lock()
            .iter()
            .copied()
            .filter(|receipt| {
                receipt
                    .va
                    .checked_add(receipt.len as u64)
                    .is_some_and(|receipt_end| receipt.va < end && receipt_end > va)
            })
            .collect();
        if pending.is_empty() {
            return Ok(());
        }

        let page_table_host = self
            .mapping_for_range(
                crate::memory::LINUX_PAGE_TABLES_BASE,
                carrick_mem::memory::LINUX_PAGE_TABLES_SIZE as usize,
            )
            .map(|mapping| mapping.host_addr)
            .ok_or_else(|| {
                TrapError::Hypervisor(
                    "deferred COW protection has no page-table backing".to_owned(),
                )
            })?;
        let prot_flags = carrick_abi::LinuxProtFlags::from_bits_truncate(prot);
        let (expected_ap, phase, must_be_valid) =
            if prot_flags.contains(carrick_abi::LinuxProtFlags::WRITE) {
                (AP_USER_RW, 4, true)
            } else if prot_flags
                .intersects(carrick_abi::LinuxProtFlags::READ | carrick_abi::LinuxProtFlags::EXEC)
            {
                (AP_USER_RO, 5, true)
            } else {
                (AP_USER_RO, 6, false)
            };

        // `protect_range` re-downgrades every armed span to read-only after
        // granting PROT_WRITE (fork COW arms and the page-granular arms a
        // lowered MAP_PRIVATE file view carries), so a page inside an armed
        // range is authentic at `AP_USER_RO` even when the guest asked for
        // write access. Snapshot the arms before taking the page-table lock:
        // the two locks are never nested the other way round.
        let armed = if expected_ap == AP_USER_RW {
            self.cow_armed.lock().overlapping(va, len)
        } else {
            Vec::new()
        };
        let armed_covers = |page: u64| {
            armed.iter().any(|range| {
                range
                    .va
                    .checked_add(range.len as u64)
                    .is_some_and(|range_end| page >= range.va && page < range_end)
            })
        };

        let page_tables_authority = self.page_tables_authority();
        let authenticated = page_tables_authority
            .with_manager(|manager| -> Result<Vec<PendingFrameCowPublication>, TrapError> {
                let page_table_resolver =
                    self.page_table_resolver(manager.base(), Some(page_table_host));
                let mut authenticated = Vec::with_capacity(pending.len());
                for receipt in pending {
                    let receipt_end = receipt.va.checked_add(receipt.len as u64).ok_or_else(|| {
                        TrapError::Hypervisor("deferred COW receipt range overflow".to_owned())
                    })?;
                    let overlap_start = receipt.va.max(va);
                    let overlap_end = receipt_end.min(end);
                    if !overlap_start.is_multiple_of(PAGE_SIZE)
                        || !overlap_end.is_multiple_of(PAGE_SIZE)
                    {
                        return Err(TrapError::Hypervisor(format!(
                            "deferred COW receipt/protection is not page aligned: receipt=0x{:x}..0x{receipt_end:x} protection=0x{va:x}..0x{end:x}",
                            receipt.va
                        )));
                    }
                    let mut page = overlap_start;
                    let mut first_leaf = None;
                    while page < overlap_end {
                        let expected_ipa = receipt
                            .expected_ipa
                            .checked_add(page - receipt.va)
                            .ok_or_else(|| {
                                TrapError::Hypervisor(
                                    "deferred COW receipt IPA range overflow".to_owned(),
                                )
                            })?;
                        let shadow = manager.debug_walk(page);
                        let live = unsafe { manager.debug_walk_host(page_table_resolver, page) }
                            .map_err(|e| {
                                TrapError::Hypervisor(format!(
                                    "deferred COW debug_walk_host failed: {e:?}"
                                ))
                            })?;
                        let leaf = carrick_mem::page_table::terminal_descriptor(live);
                        let translated = if must_be_valid {
                            manager.translate(page)
                        } else {
                            manager.translate_retained_output(page)
                        };
                        let expected_ap = if armed_covers(page) {
                            AP_USER_RO
                        } else {
                            expected_ap
                        };
                        if shadow != live
                            || !deferred_cow_leaf_authenticates(
                                leaf,
                                translated,
                                expected_ipa,
                                expected_ap,
                                must_be_valid,
                                prot_flags.contains(carrick_abi::LinuxProtFlags::EXEC),
                            )
                        {
                            return Err(TrapError::Hypervisor(format!(
                                "deferred COW protection authentication failed at VA 0x{page:x}: leaf=0x{leaf:x} translated={translated:x?} expected_ipa=0x{expected_ipa:x} expected_ap=0x{expected_ap:x} valid={must_be_valid} receipt=0x{:x}+0x{:x}",
                                receipt.va, receipt.len
                            )));
                        }
                        first_leaf.get_or_insert((page, leaf, expected_ipa));
                        page = next_deferred_cow_authentication_page(live, page, overlap_end, &armed);
                    }
                    if let Some((page, leaf, expected_ipa)) = first_leaf {
                        crate::probes::pt_alias_receipt(page, leaf, expected_ipa, expected_ap, phase);
                    }
                    authenticated.push(receipt);
                }
                Ok(authenticated)
            })
            .ok_or_else(|| {
                TrapError::Hypervisor("deferred COW protection has no page-table manager".to_owned())
            })??;

        let mut receipts = self.cow_deferred_publications.lock();
        let mut remaining = Vec::with_capacity(receipts.len());
        for receipt in receipts.drain(..) {
            if !authenticated.contains(&receipt) {
                remaining.push(receipt);
                continue;
            }
            let receipt_end = receipt.va.saturating_add(receipt.len as u64);
            let overlap_start = receipt.va.max(va);
            let overlap_end = receipt_end.min(end);
            if receipt.va < overlap_start {
                remaining.push(PendingFrameCowPublication {
                    va: receipt.va,
                    len: usize::try_from(overlap_start - receipt.va).unwrap_or_else(|_| {
                        carrick_fatal!(
                            "hvpatch::cow_token",
                            "invalid leading span length in COW publication"
                        );
                    }),
                    expected_ipa: receipt.expected_ipa,
                });
            }
            if overlap_end < receipt_end {
                remaining.push(PendingFrameCowPublication {
                    va: overlap_end,
                    len: usize::try_from(receipt_end - overlap_end).unwrap_or_else(|_| {
                        carrick_fatal!(
                            "hvpatch::cow_token",
                            "invalid trailing span length in COW publication"
                        );
                    }),
                    expected_ipa: receipt
                        .expected_ipa
                        .checked_add(overlap_end - receipt.va)
                        .unwrap_or_else(|| {
                            carrick_fatal!(
                                "hvpatch::cow_token",
                                "expected IPA overflow for trailing COW publication"
                            );
                        }),
                });
            }
        }
        *receipts = remaining;
        Ok(())
    }

    /// Create a fresh vCPU bound to this VM (the boot/clone/fork/reclaim
    /// vcpu_create; admission is the bounded scheduler's job, NOT this path).
    pub(crate) fn add_vcpu(
        &mut self,
    ) -> Result<(applevisor::vcpu::Vcpu, MailboxBinding), TrapError> {
        let vcpu = create_vcpu(&self._vm)?;
        enable_el0_counter_access(vcpu.id());
        self.vcpu_id = vcpu.id();
        self.vcpu_handle = vcpu.get_handle();
        self._vcpu_guard = Some(vcpu_census().created());
        self.publish_live_vcpu();
        let mailbox = self.allocate_mailbox_for_vcpu(&vcpu)?;
        Ok((vcpu, mailbox))
    }

    fn mailbox_host_pointer(
        &self,
        slot: MailboxSlotId,
    ) -> Result<std::ptr::NonNull<carrick_aarch64::mailbox::Aarch64SyscallMailbox>, TrapError> {
        let address = slot.guest_address();
        let size = carrick_aarch64::mailbox::AARCH64_SYSCALL_MAILBOX_SIZE as usize;
        let pointer = self
            .translate_va(address)
            .and_then(|ipa| {
                Self::mailbox_mapping_for_range(&self.mappings, address, ipa, size).map(|mapping| {
                    let offset =
                        usize::try_from(address.saturating_sub(mapping.start)).unwrap_or_default();
                    unsafe { mapping.host_addr.add(offset) }
                })
            })
            // A persistent-VM exec deliberately drops the software page-table
            // manager until the first real edit. The mailbox lives in a static
            // boot mapping whose guest-VA extent is unambiguous, so resolve that
            // mapping directly instead of paying a 1.8 MiB table clone solely to
            // recover the root-slot/global-frame IPA during publication.
            .or_else(|| {
                let mapping = self.mapping_for_range(address, size)?;
                let offset = usize::try_from(address.checked_sub(mapping.start)?).ok()?;
                Some(unsafe { mapping.host_addr.add(offset) })
            })
            .or_else(|| {
                self.carrier_mappings
                    .as_ref()?
                    .host_pointer(address, size)
                    .map(std::ptr::NonNull::as_ptr)
            })
            .ok_or_else(|| {
                TrapError::Hypervisor(format!(
                    "AArch64 syscall mailbox slot {} at {address:#x} is not mapped",
                    slot.raw()
                ))
            })?;
        std::ptr::NonNull::new(pointer.cast()).ok_or_else(|| {
            TrapError::Hypervisor(format!(
                "AArch64 syscall mailbox slot {} resolved to a null host pointer",
                slot.raw()
            ))
        })
    }

    fn allocate_mailbox_for_vcpu(
        &self,
        vcpu: &applevisor::vcpu::Vcpu,
    ) -> Result<MailboxBinding, TrapError> {
        use applevisor::prelude::SysReg;

        let lease = self
            .mailbox_slots
            .allocate()
            .map_err(|error| TrapError::Hypervisor(error.to_string()))?;
        let address = lease.id().guest_address();
        let pointer = self.mailbox_host_pointer(lease.id())?;
        // SAFETY: `mailbox_host_pointer` resolved the complete fixed slot from
        // this VM's process-lifetime mapping, and the lease uniquely owns it.
        let binding = unsafe { MailboxBinding::new(lease, pointer, self.syscall_transport) };
        vcpu.set_sys_reg(SysReg::SP_EL1, address)
            .map_err(hvf_error)?;
        Ok(binding)
    }

    pub(crate) fn relocate_mailbox_after_cow(
        &self,
        binding: &mut MailboxBinding,
    ) -> Result<(), TrapError> {
        let pointer = self.mailbox_host_pointer(binding.slot())?;
        // SAFETY: the live stage-1 walk resolves the complete replacement
        // backing for this binding's uniquely leased slot. The COW copied the
        // prior header before the guest published its request into that backing,
        // so relocation must not reset or regenerate any protocol field.
        unsafe { binding.relocate_after_cow(pointer) };
        let diagnostics = binding.diagnostics();
        if diagnostics.generation != binding.generation() {
            return Err(TrapError::Hypervisor(format!(
                "AArch64 mailbox COW relocation changed generation: binding={} backing={}",
                binding.generation(),
                diagnostics.generation
            )));
        }
        Ok(())
    }

    pub(crate) fn enrich_mailbox_run_error(
        &self,
        binding: &MailboxBinding,
        error: TrapError,
    ) -> TrapError {
        let TrapError::Hypervisor(message) = error else {
            return error;
        };
        if !message.contains("without a published mailbox request") {
            return TrapError::Hypervisor(message);
        }
        let slot = binding.slot();
        let address = slot.guest_address();
        let translated_ipa = self.translate_va(address);
        let live = self.mailbox_host_pointer(slot).ok();
        let live_diagnostics = live.map(|pointer| {
            // SAFETY: `mailbox_host_pointer` authenticated a complete live slot,
            // and the vCPU is stopped at the HVC that produced `error`.
            unsafe { MailboxBinding::diagnostics_at(pointer) }
        });
        TrapError::Hypervisor(format!(
            "{message}; mailbox_route={{slot={}, va={address:#x}, translated_ipa={translated_ipa:?}, binding_host={:#x}, live_host={:?}, live={live_diagnostics:?}}}",
            slot.raw(),
            binding.host_address(),
            live.map(|pointer| pointer.as_ptr() as usize),
        ))
    }

    fn release_mailbox_for_reclaim(&self, binding: &mut MailboxBinding) -> Result<(), TrapError> {
        binding.release_for_reclaim().map_err(|error| {
            TrapError::Hypervisor(format!("park AArch64 syscall mailbox: {error}"))
        })
    }

    fn reacquire_mailbox_after_vcpu_create(
        &self,
        vcpu: &applevisor::vcpu::Vcpu,
        binding: &mut MailboxBinding,
        continuation: Option<carrick_hal::threaded::Aarch64SyscallContinuationV1>,
    ) -> Result<(), TrapError> {
        use applevisor::prelude::SysReg;

        let lease = self
            .mailbox_slots
            .allocate()
            .map_err(|error| TrapError::Hypervisor(error.to_string()))?;
        let address = lease.id().guest_address();
        let pointer = self.mailbox_host_pointer(lease.id())?;
        // SAFETY: the allocator lease uniquely owns the complete fixed slot.
        unsafe { binding.reacquire_after_reclaim(lease, pointer, continuation) }.map_err(
            |error| TrapError::Hypervisor(format!("resume AArch64 syscall mailbox: {error}")),
        )?;
        vcpu.set_sys_reg(SysReg::SP_EL1, address).map_err(hvf_error)
    }

    /// Host pointer backing `[gpa, gpa+len)`, or `None` if unmapped. The
    /// engine's `GuestMemory` copies through this; HVF resolves it via the same
    /// per-thread mapping walk (with the stage-1-IPA disambiguation) the
    /// syscall path uses.
    /// Map host memory at a stage-2 IPA (`hv_vm_map`). The STAGE-1 path stays in
    /// the engine; this is the backend stage-2 op only.
    pub(crate) fn map_stage2(
        &mut self,
        ipa: u64,
        host: *mut u8,
        len: u64,
        perms: carrick_hal::MemPerms,
    ) -> Result<(), TrapError> {
        let perms_raw: u64 = u64::from(hvf_mem_perms(perms));
        let r = unsafe {
            inventory_hv_vm_map(host as *mut std::ffi::c_void, ipa, len as usize, perms_raw)
        };
        if r != 0 {
            return Err(TrapError::Hypervisor(format!(
                "hv_vm_map(ipa=0x{ipa:x}, size={len}) failed: 0x{r:x}"
            )));
        }
        Ok(())
    }

    /// The HVF-only lazy high-VA alias re-map: a forked child rebuilt its VM
    /// from only the forking thread's mappings, dropping a global-shared alias a
    /// sibling thread mapped; re-`hv_vm_map` the registered host backing into
    /// THIS VM so the faulting instruction re-executes cleanly. Returns true iff
    /// it remapped. (The engine's `next_syscall` already runs the bounded in-loop
    /// remap; this is the `handle_memory_exit` hook surface — kept for the trait,
    /// driven on the rare path the in-loop remap doesn't cover.)
    pub(crate) fn try_lazy_alias_remap(&mut self, gpa: u64, va: u64) -> bool {
        let backing = if gpa != 0 {
            lookup_shared_alias(gpa)
        } else {
            lookup_shared_alias_by_va(va, 1, self.mm_root_slot, self.container_root)
        };
        let Some(b) = backing else {
            return false;
        };
        // SAFETY: `host_addr` is a live MAP_SHARED mmap registered by
        // `add_alias`. Replay succeeds only when HVF confirms the installation;
        // an arbitrary nonzero result is never evidence that a racing mapper won.
        let rc = unsafe { inventory_hv_vm_map_replay(b) };
        crate::probes::hv_vm_map_alias(
            va,
            b.physical_ipa,
            b.physical_size as u64,
            rc as i32,
            self.forked_no_exec as i32,
        );
        rc == 0
    }

    /// Back a dynamic `mmap` (`DispatchOutcome::MapHostAlias`) with host
    /// memory: `hv_vm_map` the host backing at the alias IPA, register the
    /// alias process-globally, and add the per-thread region — returning the
    /// `(gpa = ipa, writable)` the engine then threads into the SHARED stage-1
    /// `map_aliased`. RWX so a JIT (Rosetta) can write+execute it; the guest may
    /// `mprotect` afterwards.
    ///
    /// `backing` selects the host object, and the sharing it carries is the
    /// VMA's own: a deferred `mprotect` commit must preserve MAP_SHARED across
    /// host fork rather than silently substituting private COW backing. A
    /// `MAP_PRIVATE` file backing is refused outright: a Darwin `MAP_PRIVATE`
    /// file view is a map-time snapshot, so it cannot honour the Linux clause
    /// that clean private pages track later writes (`mmapprivatefiletrack`);
    /// that shape is served only by the sparse-arena page-cache view plus
    /// carrick-owned page COW (`materialize_private_file_backing`).
    pub(crate) fn add_alias(
        &mut self,
        va: u64,
        ipa: u64,
        len: u64,
        payload: &[u8],
        backing: HostAliasBacking,
    ) -> Result<(u64, bool), TrapError> {
        let sharing = match &backing {
            HostAliasBacking::File {
                sharing: HostAliasSharing::Shared,
                ..
            } => GuestMappingSharing::GlobalShared,
            HostAliasBacking::Anonymous {
                sharing: HostAliasSharing::Shared,
            } => GuestMappingSharing::ForkSharedAnonymous,
            HostAliasBacking::File {
                sharing: HostAliasSharing::Private,
                ..
            }
            | HostAliasBacking::Anonymous {
                sharing: HostAliasSharing::Private,
            } => GuestMappingSharing::Private,
        };
        let inventory_backing = match &backing {
            HostAliasBacking::File {
                fd,
                offset,
                sharing: HostAliasSharing::Shared,
                ..
            } => {
                let mut stat: libc::stat = unsafe { std::mem::zeroed() };
                if unsafe { libc::fstat(fd.as_raw_fd(), &mut stat) } != 0 {
                    return Err(TrapError::Hypervisor(format!(
                        "identify HVPatch shared-file frame: {}",
                        std::io::Error::last_os_error()
                    )));
                }
                let offset = u64::try_from(*offset).map_err(|_| {
                    TrapError::Hypervisor(
                        "HVPatch shared-file frame has negative offset".to_owned(),
                    )
                })?;
                InventoryBackingIdentity::SharedFile {
                    device: stat.st_dev as u64,
                    inode: stat.st_ino as u64,
                    offset,
                    length: len,
                }
            }
            HostAliasBacking::Anonymous {
                sharing: HostAliasSharing::Shared,
            } => Self::shared_anon_backing_identity(),
            // A private file mapping is a private frame: its host object is a
            // per-mapping COW view of the file, never shared with another alias.
            HostAliasBacking::File {
                sharing: HostAliasSharing::Private,
                ..
            }
            | HostAliasBacking::Anonymous {
                sharing: HostAliasSharing::Private,
            } => Self::private_backing_identity(),
        };
        // Mature VMM/root uses the IPA the dispatcher allocated from the global
        // alias arena. An in-process hvpatch mm relocates non-global aliases into
        // its mm scope; the returned GPA is authoritative for stage-1, while
        // dispatcher VMA metadata remains keyed by VA and needs no IPA.
        // hv_vm_map requires a 16 KiB-granular size; round the HOST mapping up
        // to the HVF granule. The stage-1 `map_aliased` (the engine, on the exact
        // `len`) below still maps only the guest's page-aligned request, so a
        // sub-16 KiB mmap never maps extra 4 KiB guest pages into a neighbouring
        // region's page-table entries (which would redirect that region's
        // fetches/reads to the wrong IPA — the amd64 Rosetta JIT undefined-
        // instruction bug).
        let hvf_len = align_up(len, HVF_PAGE_SIZE)?;
        let guest_size = usize::try_from(len).map_err(|_| TrapError::MappingTooLarge(len))?;
        let requested_physical_size =
            usize::try_from(hvf_len).map_err(|_| TrapError::MappingTooLarge(len))?;
        let guest_end = va.checked_add(len).ok_or(TrapError::MappingOverflow {
            guest_start: va,
            mapped_size: len,
        })?;
        // A shared file's host page is mapped at the guest's actual prot
        // (map_shared_file), so a PROT_READ file alias has a read-only host
        // backing. Track the guest-intended writability so the syscall
        // write-path returns EFAULT instead of SIGBUS-ing the host. Anon and
        // private-file aliases are RW-backed (a private file view is a COW
        // copy, so host PROT_WRITE never reaches the file).
        let alias_guest_writable = match &backing {
            HostAliasBacking::File {
                host_prot,
                sharing: HostAliasSharing::Shared,
                ..
            } => *host_prot & libc::PROT_WRITE != 0,
            HostAliasBacking::File {
                sharing: HostAliasSharing::Private,
                ..
            }
            | HostAliasBacking::Anonymous { .. } => true,
        };
        let (shared_key_base, shared_key_offset) = match &backing {
            HostAliasBacking::File {
                fd,
                offset,
                sharing: HostAliasSharing::Shared,
                ..
            } => (
                shared_file_key_base(fd.as_raw_fd()),
                u64::try_from(*offset).unwrap_or_default(),
            ),
            HostAliasBacking::File {
                sharing: HostAliasSharing::Private,
                ..
            }
            | HostAliasBacking::Anonymous { .. } => (0, 0),
        };
        let host_mapping = match &backing {
            // Live MAP_SHARED file: back the guest region with the file's page
            // cache directly, so writes are coherent with other openers and
            // survive fork. The dispatcher handed us a dup'd fd it owns; mmap
            // takes its own reference, so the dup closes with `backing`.
            HostAliasBacking::File {
                fd,
                offset,
                host_prot,
                sharing: HostAliasSharing::Shared,
            } => crate::host_mapping::OwnedHostMapping::map_shared_file(
                fd.as_raw_fd(),
                *offset,
                requested_physical_size,
                *host_prot,
            )
            .map_err(|e| {
                TrapError::Hypervisor(format!(
                    "alias MAP_SHARED file (fd={} off={offset} size={requested_physical_size} prot={host_prot}) failed: {e}",
                    fd.as_raw_fd()
                ))
            })?,
            // MAP_PRIVATE file: refuse. A Darwin `MAP_PRIVATE` file view is a
            // snapshot of the file at mmap time (measured by
            // `overlay_shared_file_view_tracks_later_file_writes`), so it
            // cannot give Linux's clean-page-tracks-`write(2)` semantics; the
            // contract says a backend that cannot honour `Private` for a file
            // MUST refuse rather than silently map a snapshot. Arena-resident
            // MAP_PRIVATE file mappings take the page-granular
            // `materialize_private_file_backing` lane instead; no dispatcher
            // site produces this shape for a high-VA alias.
            HostAliasBacking::File {
                fd,
                offset,
                sharing: HostAliasSharing::Private,
                ..
            } => {
                return Err(TrapError::Hypervisor(format!(
                    "alias MAP_PRIVATE file (fd={} off={offset} size={requested_physical_size}) unsupported: a Darwin MAP_PRIVATE file view is a snapshot",
                    fd.as_raw_fd()
                )));
            }
            HostAliasBacking::Anonymous { .. } => {
                crate::host_mapping::OwnedHostMapping::map_shared_anon(
                    requested_physical_size,
                    if sharing.shares_across_fork() {
                        crate::host_mapping::HostMappingKind::SharedAnon
                    } else {
                        crate::host_mapping::HostMappingKind::PrivateAnon
                    },
                )
                .map_err(|e| {
                    TrapError::Hypervisor(format!(
                        "alias mmap (size={requested_physical_size}) failed: {e}"
                    ))
                })?
            }
        };
        // The host mapping holds its own reference to the file; the
        // dispatcher's dup is closed here, on every path below, by drop.
        let seed_payload = !backing.is_file();
        drop(backing);
        let host = host_mapping.as_ptr();
        let physical_size = host_mapping.len();
        // Seed the anon content (a file mapping is already backed by the file's
        // pages; an anon mapping is zeroed and takes the dispatcher's payload).
        if seed_payload && !payload.is_empty() {
            let n = payload.len().min(guest_size);
            unsafe { std::ptr::copy_nonoverlapping(payload.as_ptr(), host, n) };
        }
        // Alias mappings keep permissive stage-2 rights; guest-visible
        // protections are enforced in stage-1 and adjusted by mprotect.
        let perms = hvf_perms(SegmentPerms {
            read: true,
            write: true,
            execute: true,
        });
        // Reserve the global-frame lease on a 2 MiB boundary, NOT the 16 KiB
        // COW compound granule. The dispatcher hands this path a 2 MiB-aligned
        // alias VA, so a 2 MiB-aligned output keeps VA and IPA congruent and
        // lets the stage-1 editor express the mapping as 1 GiB/2 MiB block
        // leaves. A 16 KiB-aligned base breaks that congruence, and since no
        // block leaf can then be expressed ANYWHERE the whole alias falls to
        // 4 KiB pages — one fresh L3 table per 2 MiB, which exhausts the
        // 440-page spare pool at ~850 MiB and fails the build (CPython's
        // `test_mmap` LargeMmapTests hung there). The sparse-arena sibling
        // reserves on `TWO_MIB` for exactly this reason.
        const TWO_MIB: u64 = 2 * 1024 * 1024;
        let mut global_lease = if self.persistent_vm_lifecycle {
            Some(GlobalFrameStage2Lease::reserve(hvf_len, TWO_MIB)?)
        } else {
            None
        };
        let ipa = global_lease.as_ref().map_or(ipa, |lease| lease.base);
        let r = unsafe { inventory_hv_vm_map(host.cast(), ipa, physical_size, u64::from(perms)) };
        crate::probes::hv_vm_map_alias(
            va,
            ipa,
            physical_size as u64,
            r as i32,
            self.forked_no_exec as i32,
        );
        if r != 0 {
            return Err(TrapError::Hypervisor(format!(
                "hv_vm_map alias va=0x{va:x} ipa=0x{ipa:x} size={physical_size} failed: 0x{r:x}"
            )));
        }
        if let Some(lease) = global_lease.as_mut() {
            lease.mark_mapped();
        }
        let (host_mapping, owner_generation) = if self.persistent_vm_lifecycle {
            let custody = self.carrier_vm_custody();
            let owner_generation = register_global_frame_host_owner_in(
                &custody,
                global_lease.take().ok_or_else(|| {
                    TrapError::Hypervisor("HVPatch alias lost its global IPA lease".to_owned())
                })?,
                host_mapping,
                u64::from(perms),
            )?;
            (None, owner_generation)
        } else {
            (Some(host_mapping), 0)
        };
        // Register EVERY alias (MAP_SHARED file AND private anon — Go's high-VA
        // heap arenas) process-globally in `alias_registry`. Two consumers: the
        // stage-2 lazy on-fault re-map (a forked VM that lost the alias), and the
        // SYSCALL-PATH cross-thread fallback in `mapping_for_range` (a sibling
        // thread whose per-thread `mappings` never saw this alias — the
        // "read/wait: bad address" EFAULT). The index is non-owning (raw
        // host_addr) and removed on munmap. guest_writable is carried so a
        // PROT_READ file alias still EFAULTs a syscall write via the fallback
        // instead of SIGBUS-ing the host.
        register_shared_alias(AliasBacking {
            start: va,
            ipa,
            host_addr: host as usize,
            size: guest_size,
            physical_ipa: ipa,
            physical_host_addr: host as usize,
            physical_size,
            perms: u64::from(perms),
            guest_writable: alias_guest_writable,
            sharing,
            ownership_scope: alias_ownership_scope(sharing, self.mm_root_slot, self.container_root),
            inventory_backing,
            shared_key_base,
            shared_key_offset,
            owner_generation,
        });
        self.mappings.insert(HvfMappedRegion {
            start: va,
            ipa,
            physical_ipa: ipa,
            end: guest_end,
            host_addr: host,
            size: physical_size,
            physical_size,
            perms,
            memory: None,
            host_mapping,
            structural_owner: None,
            stage2_lease: None,
            is_dynamic_alias: true,
            sharing,
            guest_writable: alias_guest_writable,
            shared_key_base,
            shared_key_offset,
            owner_generation,
        });
        if self.persistent_vm_lifecycle {
            let mut inventory = self.frame_inventory.lock();
            let mut reservation = inventory.alias_reservation.take().unwrap_or_else(|| {
                carrick_fatal!(
                    "hvpatch::frame_inventory",
                    "HVPatch alias mapped without frame inventory reservation"
                );
            });
            match Self::stage_mapping_in(
                self.custody(),
                &mut inventory,
                &mut reservation,
                InventoryMappingStage {
                    gpa: ipa,
                    length: physical_size as u64,
                    permissions: carrick_hal::MemPerms {
                        read: true,
                        write: true,
                        exec: true,
                    },
                    backing: inventory_backing,
                    inherited_frame: None,
                    stage2_lease: None,
                    stage2_owner: InventoryStage2OwnerIdentity {
                        host_addr: host as usize,
                        generation: owner_generation,
                    },
                },
            ) {
                Ok(extent) => {
                    tracing::trace!(
                        mapping = ?extent.mapping,
                        frame = ?extent.frame,
                        gpa = format_args!("{ipa:#x}"),
                        "hvpatch alias stage"
                    );
                    inventory
                        .alias_staged
                        .push(((ipa, physical_size as u64), extent));
                }
                Err(error) => {
                    carrick_fatal!(
                        "hvpatch::frame_inventory",
                        "stage inventory after HVPatch alias map: {error}"
                    );
                }
            }
            inventory.alias_commit = Some(reservation.commit(()));
        }
        Ok((ipa, alias_guest_writable))
    }

    fn emulate_el0_sys64_read_inner(
        vcpu: &mut applevisor::vcpu::Vcpu,
        esr: u64,
    ) -> Result<bool, TrapError> {
        use applevisor::prelude::*;

        // EL0 read of a feature-ID register (the CRn==0, Op0==3, Op1==0 space).
        // The Linux kernel emulates these for userspace; Apple Rosetta reads
        // ID_AA64MMFR1_EL1 (and friends) at startup, and without this the MRS
        // takes a fatal undef. Return the real vCPU value. (The Op1==3 timer /
        // CTR_EL0 / DCZID_EL0 reads handled below are a separate space.)
        let op0 = (esr >> 20) & 0x3;
        let op1 = (esr >> 14) & 0x7;
        let crn = (esr >> 10) & 0xf;
        let crm = (esr >> 1) & 0xf;
        let op2 = (esr >> 17) & 0x7;
        let direction_read = esr & 1 == 1;
        if direction_read && op0 == 3 && op1 == 0 && crn == 0 {
            let rt_id = ((esr >> 5) & 0x1f) as usize;
            let enc = (op0 << 14) | (op1 << 11) | (crn << 7) | (crm << 3) | op2;
            let id_reg = match enc {
                0xc000 => Some(SysReg::MIDR_EL1),
                0xc020 => Some(SysReg::ID_AA64PFR0_EL1),
                0xc021 => Some(SysReg::ID_AA64PFR1_EL1),
                0xc028 => Some(SysReg::ID_AA64DFR0_EL1),
                0xc029 => Some(SysReg::ID_AA64DFR1_EL1),
                0xc030 => Some(SysReg::ID_AA64ISAR0_EL1),
                0xc031 => Some(SysReg::ID_AA64ISAR1_EL1),
                0xc038 => Some(SysReg::ID_AA64MMFR0_EL1),
                0xc039 => Some(SysReg::ID_AA64MMFR1_EL1),
                0xc03a => Some(SysReg::ID_AA64MMFR2_EL1),
                // Any other CRn==0/Op0==3/Op1==0 slot reads-as-zero (RES0),
                // matching the architectural default for unallocated ID regs.
                _ => None,
            };
            let value = match id_reg {
                Some(reg) => vcpu.get_sys_reg(reg).map_err(hvf_error)?,
                None => 0,
            };
            if let Some(target) = GPR_TABLE.get(rt_id) {
                vcpu.set_reg(*target, value).map_err(hvf_error)?;
            }
            let elr = vcpu.get_sys_reg(SysReg::ELR_EL1).map_err(hvf_error)?;
            vcpu.set_sys_reg(SysReg::ELR_EL1, elr.wrapping_add(4))
                .map_err(hvf_error)?;
            return Ok(true);
        }

        let Some((rt, reg)) = decode_el0_sys64_read(esr) else {
            return Ok(false);
        };
        let value = match reg {
            El0SysRegRead::CntfrqEl0 => AARCH64_GUEST_COUNTER_HZ,
            El0SysRegRead::CntvctEl0 => guest_counter_ticks(),
            // Fallback if a guest's CTR_EL0/DCZID_EL0 read still traps despite
            // SCTLR_EL1.UCT/DZE (e.g. a forked child before its sysregs are
            // re-applied). Return the real host cache geometry.
            El0SysRegRead::CtrEl0 => host_ctr_dczid().0,
            El0SysRegRead::DczidEl0 => host_ctr_dczid().1,
        };
        if let Some(target) = GPR_TABLE.get(rt as usize) {
            vcpu.set_reg(*target, value).map_err(hvf_error)?;
        }
        let elr = vcpu.get_sys_reg(SysReg::ELR_EL1).map_err(hvf_error)?;
        vcpu.set_sys_reg(SysReg::ELR_EL1, elr.wrapping_add(4))
            .map_err(hvf_error)?;
        Ok(true)
    }

    /// True if `[address, address+length)` overlaps any PROT_NONE range. Used
    /// to fault syscall-path accesses to a guest PROT_NONE buffer (EFAULT).
    pub(crate) fn range_no_access(&self, address: u64, length: usize) -> bool {
        self.protections.range_no_access(address, length)
    }

    /// Write the vDSO vvar data page: the counter frequency and the
    /// monotonic→realtime offset, so `__kernel_clock_gettime` can convert
    /// CNTVCT_EL0 to a timespec entirely in userspace. The guest reads the same
    /// counter we calibrate against (CNTKCTL_EL1.EL0VCTEN), so the rate is exact;
    /// monotonic durations depend only on the frequency. Best-effort: silently
    /// skips if the vvar page isn't mapped.
    ///
    /// Stamp a fresh process-local epoch into the vvar RNG generation (P2).
    /// Re-stamping each forked child ensures the generation never matches the
    /// state snapshot inherited from its parent, forcing the userspace
    /// getrandom blob to reseed rather than reuse the parent's keystream.
    fn stamp_rng_generation(&mut self) -> Result<(), MemoryError> {
        let generation = next_vdso_rng_generation();
        self.write_guest_bytes(
            crate::vdso::LINUX_VVAR_BASE + crate::vdso::VVAR_OFF_RNG_GENERATION as u64,
            &generation.to_le_bytes(),
        )
    }

    fn populate_vdso_data_page(&mut self) {
        // Independent of the clock data (getrandom needs no calibrated counter),
        // so stamp it first and unconditionally.
        let _ = self.stamp_rng_generation();
        let freq = host_counter_frequency();
        if freq == 0 {
            return;
        }
        // The vDSO computes the guest's CLOCK_REALTIME as
        //   realtime_ns = guest_CNTVCT/freq + realtime_off.
        // So `realtime_off` MUST be `unix_ns - guest_CNTVCT/freq` measured on
        // the SAME clock the guest's CNTVCT_EL0 actually exposes.
        //
        // Crucially, the guest's CNTVCT does NOT equal the raw `cntvct_el0` MRS
        // that carrick reads in `host_counter()`: the bare hardware counter
        // keeps ticking across system SUSPEND (it is BOOTTIME-like), whereas
        // HVF gives the guest a virtual counter aligned to macOS
        // CLOCK_UPTIME_RAW (which EXCLUDES suspend) — empirically the guest's
        // CNTVCT/freq matches CLOCK_UPTIME_RAW to the millisecond, while the
        // raw MRS runs HOURS ahead after a laptop has slept (hv_vcpu's
        // vtimer_offset reports 0, so the gap is invisible through that API).
        // Calibrating `mono_ns` off the raw MRS therefore skewed guest
        // CLOCK_REALTIME by the accumulated suspend time → every absolute
        // FUTEX_WAIT_BITSET|FUTEX_CLOCK_REALTIME deadline (glibc sem_timedwait /
        // pthread condvar timeouts, i.e. multiprocessing SemLock/Condition)
        // computed as already-past → instant spurious ETIMEDOUT.
        //
        // Reading CLOCK_UPTIME_RAW here matches the guest's counter base, so
        // realtime_off is exact. CLOCK_MONOTONIC is unaffected (durations
        // cancel any constant base), but its absolute value now also agrees
        // with carrick's syscall-path monotonic (`monotonic_duration`, also
        // CLOCK_UPTIME_RAW) — the vDSO and syscall fast/slow paths are coherent.
        let mono_ns = host_clock_uptime_ns();
        let unix_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        let realtime_off = unix_ns.wrapping_sub(mono_ns);
        // Publish the SAME offset to the shared store so the trapping
        // clock_gettime(CLOCK_REALTIME) syscall computes uptime + realtime_off
        // identically to the vDSO fast path (which adds VVAR_OFF_REALTIME_OFF_NS
        // to the guest CNTVCT) — keeping the two paths coherent (clock_gettime04).
        crate::vdso::set_realtime_off_ns(realtime_off);

        let base = crate::vdso::LINUX_VVAR_BASE;
        let _ = self.write_guest_bytes(
            base + crate::vdso::VVAR_OFF_FREQ as u64,
            &freq.to_le_bytes(),
        );
        let _ = self.write_guest_bytes(
            base + crate::vdso::VVAR_OFF_REALTIME_OFF_NS as u64,
            &realtime_off.to_le_bytes(),
        );
        // seq stays 0 (even = stable); these aren't updated after boot.
    }

    /// Mark `[address, address+len)` PROT_NONE (`no_access=true`) or clear it.
    /// Clearing performs interval subtraction so an mprotect/mmap that re-enables
    /// part of a PROT_NONE region leaves only the still-protected remainder.
    pub(crate) fn set_no_access(&mut self, address: u64, len: usize, no_access: bool) {
        self.protections.set_no_access(address, len, no_access);
    }

    /// Mirror a partial `munmap`'s registry split onto this engine's LOCAL
    /// mapping rows.
    ///
    /// `unregister_alias_entries` splits an overlapped registry entry into its
    /// surviving head/tail fragments, but the engine's own row kept the
    /// ORIGINAL extent. `mapping_is_current_for_process_fork_indexed` then
    /// matched that row against the registry index by exact identity
    /// `(start, ipa, host_addr, semantic size)` — and a fragment never equals
    /// the whole — so fork DROPPED the row from its COW ranges. The child's
    /// cloned stage-1 kept a WRITABLE leaf onto the parent's frame, no COW
    /// fault ever fired, and the child's frees scribbled pymalloc free-list
    /// links over the parent's live objects (`cpython-threading`'s
    /// `free(): invalid pointer`, reducer
    /// `docs/perf-results/2026-08-17-closure-post-libuv/reducers/cpython-fork-shutdown-parent-segv.py`).
    /// An identity test was standing in for a liveness question; keeping the
    /// two representations in step restores the invariant at its source
    /// instead of teaching the consumer to guess.
    ///
    /// Ownership: `HvfMappedRegion` owns its backing handles and is not
    /// `Clone`, so the surviving HEAD keeps them and a tail fragment carries
    /// `None`. Both fragments retain the same `physical_ipa`/`physical_size`,
    /// which is what stage-2 retirement keys on, so they are still retired
    /// together. A row the unmap covers ENTIRELY is left untouched: the
    /// registry drops such an entry outright, and excluding a dead row from
    /// fork is correct.
    fn split_local_rows_for_unmap(&mut self, va: u64, len: usize) {
        self.mappings.split_local_rows_for_unmap(va, len);
    }

    pub(crate) fn unregister_process_alias(
        &mut self,
        va: u64,
        len: usize,
    ) -> Result<(), TrapError> {
        // An unmap is a stage-1 repointer that publishes NO receipt of its own,
        // so it has to void the promises naming the range it is tearing down —
        // the contract `supersede_cow_receipts` states for every repointer.
        // Without this a receipt outlives the leaves it describes, and the next
        // mapping over that VA authenticates it against an absent translation:
        // `deferred COW protection authentication failed ... leaf=0x0
        // translated=None`, which the dispatcher can only lower to a guest
        // `ENOMEM`. Seen as `go-net` dying with "fatal error: runtime: cannot
        // allocate memory" on a 256 KiB arena mmap whose fifth page still held
        // a one-page receipt from a freed mapping.
        if !self.persistent_vm_lifecycle {
            self.supersede_cow_receipts("process-alias-unmap", va, len as u64);
            if let Some(debug_va) = fork_debug_va()
                && debug_va >= va
                && debug_va < va.saturating_add(len as u64)
            {
                eprintln!(
                    "[DISARMDBG alias-unmap-legacy pid={:?}] va={va:#x} len={len:#x}",
                    self.cow_identity.map(|identity| identity.linux_pid),
                );
            }
            self.cow_armed.lock().disarm(CowArmedSpan {
                va,
                len,
                executable: false,
                kernel_only: false,
            });
            let _ = unregister_alias(va, len, self.mm_root_slot, self.container_root);
            self.split_local_rows_for_unmap(va, len);
            return Ok(());
        }
        let identity = self.cow_identity.ok_or_else(|| {
            TrapError::Hypervisor("HVPatch alias retirement has no mm identity".to_owned())
        })?;
        // `GuestMemory::unmap_range` is reached only from the mmap-family
        // syscall set, whose runtime dispatch already owns the process-wide
        // page-table pause across invalidate + TLBI + this backend retirement.
        // Acquiring the same non-reentrant pause here deadlocks the coordinator
        // against itself as soon as the mm has a sibling vCPU.
        let _topology = crate::fork_quiesce::acquire_topology_lock(
            carrick_observability::probes::HvpatchTopologyOperation::AliasUnmap,
            identity.linux_pid,
            identity.linux_tid,
        );

        let prepared = self.prepare_process_alias_retirement(va, len)?;
        self.commit_process_alias_retirement(va, len, prepared)
    }

    /// Prepare while the caller holds topology exclusion. Dropping this value
    /// leaves aliases, COW state, receipts and inventory unchanged.
    fn prepare_process_alias_retirement(
        &self,
        va: u64,
        len: usize,
    ) -> Result<PreparedProcessAliasRetirement, TrapError> {
        let authority = self.cow_authority.as_ref().ok_or_else(|| {
            TrapError::Hypervisor("HVPatch alias retirement has no inventory authority".to_owned())
        })?;
        let (planned_leases, registry_before, diagnostic_before) = {
            let registry = alias_registry().lock();
            let (planned_leases, registry_before) = registry.plan_unregister_process_alias(
                va,
                len,
                self.mm_root_slot,
                self.container_root,
            );
            let diagnostic_before = if cow_refusal_diagnostics_enabled() {
                registry.process_visible_ordered(self.mm_root_slot, self.container_root)
            } else {
                Vec::new()
            };
            (planned_leases, registry_before, diagnostic_before)
        };
        let disarm_spans = retired_alias_disarm_spans(
            &registry_before,
            va,
            len,
            self.mm_root_slot,
            self.container_root,
            &planned_leases,
        );
        let inventory = if planned_leases.is_empty() {
            None
        } else {
            let retirement = {
                let inventory = self.frame_inventory.lock();
                Self::inventory_lease_retirement_shape(&inventory, &planned_leases, &|frame| {
                    authority.frame_mapping_count(frame).map_err(|error| {
                        TrapError::Hypervisor(format!(
                            "query alias-retirement frame mapping count: {error}"
                        ))
                    })
                })?
            };
            if retirement.mappings.is_empty() {
                None
            } else {
                let event_count = retirement
                    .mappings
                    .len()
                    .saturating_add(retirement.frames.len());
                let mut reservation = authority.reserve(0, 0, event_count).map_err(|error| {
                    TrapError::Hypervisor(format!(
                        "reserve HVPatch alias retirement inventory: {error}"
                    ))
                })?;
                Self::stage_inventory_lease_retirement(&mut reservation, &retirement)?;
                Some((retirement, reservation))
            }
        };
        Ok(PreparedProcessAliasRetirement {
            planned_leases,
            diagnostic_before,
            disarm_spans,
            inventory,
        })
    }

    /// Consume a retirement under the same topology exclusion as preparation.
    fn commit_process_alias_retirement(
        &mut self,
        va: u64,
        len: usize,
        prepared: PreparedProcessAliasRetirement,
    ) -> Result<(), TrapError> {
        let authority = self.cow_authority.as_ref().ok_or_else(|| {
            TrapError::Hypervisor("HVPatch alias retirement has no inventory authority".to_owned())
        })?;
        let identity = self.cow_identity.ok_or_else(|| {
            TrapError::Hypervisor("HVPatch alias retirement has no mm identity".to_owned())
        })?;
        let custody = self.carrier_vm_custody();
        let PreparedProcessAliasRetirement {
            planned_leases,
            diagnostic_before,
            disarm_spans,
            inventory,
        } = prepared;
        self.supersede_cow_receipts("process-alias-unmap", va, len as u64);
        let actual_leases = unregister_alias(va, len, self.mm_root_slot, self.container_root);
        if actual_leases != planned_leases {
            carrick_fatal!(
                "hvpatch::host_alias",
                "HVPatch alias registry changed under topology lock: planned={planned_leases:?} actual={actual_leases:?}"
            );
        }
        record_alias_unmap_lifecycle(
            CowDiagnosticLifecycleSite::AliasUnmap,
            &custody,
            Some(identity),
            self.mm_root_slot,
            self.container_root,
            &diagnostic_before,
        );
        let Some((retirement, reservation)) = inventory else {
            self.split_local_rows_for_unmap(va, len);
            // A surviving fragment of a compound still needs its COW arm.
            // The planner emits spans only for leases it actually retires.
            let mut armed = self.cow_armed.lock();
            for span in disarm_spans {
                armed.disarm(span);
            }
            return Ok(());
        };
        if let Err(error) = authority.apply(reservation.commit(())) {
            // Name the retirement, not just the id that failed. This abort used
            // to print one MappingId and nothing else, which cannot distinguish
            // a double-retire from a mapping the authority never saw, and gives
            // no way to tell WHICH extent named it — `inventory.extents` is
            // keyed by `(gpa, length)`, so an extent has no lifetime tie to the
            // mapping it names and an orphan is invisible from the id alone.
            let inventory = self.frame_inventory.lock();
            let retiring: std::collections::BTreeSet<_> = retirement
                .mappings
                .iter()
                .map(|(_, extent)| extent.mapping)
                .collect();
            let naming: Vec<_> = inventory
                .extents
                .iter()
                .filter(|(_, extent)| retiring.contains(&extent.mapping))
                .map(|(&key, extent)| (key, extent.mapping, extent.frame, extent.backing))
                .collect();
            carrick_fatal!(
                "hvpatch::frame_inventory",
                "apply HVPatch alias retirement inventory: {error}\n  \
                 va={va:#x} len={len:#x} retiring={:?}\n  frames={:?} leases={:?}\n  \
                 every extent naming those mappings: {naming:?}\n  \
                 live extents={} planned_leases={planned_leases:?}",
                retirement.mappings,
                retirement.frames,
                retirement.stage2_leases,
                inventory.extents.len(),
            );
        }
        {
            let mut inventory = self.frame_inventory.lock();
            Self::commit_inventory_lease_retirement(&mut inventory, &retirement).unwrap_or_else(
                |error| {
                    carrick_fatal!(
                        "hvpatch::frame_inventory",
                        "commit HVPatch alias retirement backend ledger: {error}"
                    )
                },
            );
        }
        for &(logical_key, extent) in &retirement.mappings {
            record_cow_inventory_lifecycle(
                CowDiagnosticLifecycleKind::InventoryRemoved,
                CowDiagnosticLifecycleSite::AliasUnmap,
                &custody,
                Some(identity),
                self.mm_root_slot,
                va,
                len as u64,
                logical_key,
                extent,
            );
        }
        for &(ipa, length) in &retirement.stage2_leases {
            let retired = retirement
                .mappings
                .iter()
                .filter_map(|(_, extent)| {
                    ((extent.stage2_base, extent.stage2_length) == (ipa, length))
                        .then_some(RetiredStage2Projection::from(*extent))
                })
                .try_fold(None, |selected, candidate| match selected {
                    Some(selected) if selected != candidate => Err(TrapError::Hypervisor(format!(
                        "HVPatch alias retirement IPA 0x{ipa:x} size {length} has conflicting owner identities"
                    ))),
                    Some(selected) => Ok(Some(selected)),
                    None => Ok(Some(candidate)),
                })?
                .ok_or_else(|| {
                    TrapError::Hypervisor(format!(
                        "HVPatch alias retirement IPA 0x{ipa:x} size {length} has no exact inventory owner"
                    ))
            })?;
            self.retire_stage2_extent(ipa, length)?;
            let retired = [retired];
            let cleanup = mutate_known_external_alias_state(
                |_, registry| retired_projection_mutation_keys(registry, &retired, &[]),
                |replay, registry| {
                    remove_rows_for_retired_stage2_projections(replay, registry, &retired)
                },
            );
            for alias in cleanup.removed_aliases {
                record_cow_alias_lifecycle(
                    CowDiagnosticLifecycleKind::AliasRemoved,
                    CowDiagnosticLifecycleSite::AliasUnmap,
                    Some(&custody),
                    Some(identity),
                    self.mm_root_slot,
                    alias,
                );
            }
            for alias in cleanup.preserved_reused_aliases {
                record_cow_alias_lifecycle(
                    CowDiagnosticLifecycleKind::AliasPreservedReused,
                    CowDiagnosticLifecycleSite::AliasUnmap,
                    Some(&custody),
                    Some(identity),
                    self.mm_root_slot,
                    alias,
                );
            }
            self.mappings.retain(|mapping| {
                !mapped_region_matches_retired_inventory_extent(mapping, retired[0])
            });
        }
        self.split_local_rows_for_unmap(va, len);
        let mut armed = self.cow_armed.lock();
        for span in disarm_spans {
            armed.disarm(span);
        }
        Ok(())
    }

    /// Resolve a guest VA range to a [`MappingView`] (host pointer + bounds +
    /// writability). THE single chokepoint every syscall-path memory accessor
    /// (read/write_guest_bytes, host_ptr_for_read/write, validate_guest_write_range,
    /// zero_guest_backing) routes through.
    ///
    /// Fast path: THIS thread's per-thread `mappings`. Cross-thread FALLBACK: when
    /// that misses for a high-VA address, the VA→IPA half is already process-shared
    /// (`translate_va` walks the Arc-shared page tables, which `map_aliased` edits
    /// for EVERY thread's alias), so resolve IPA→host from the process-shared
    /// `alias_registry` — fixing a syscall buffer that lives in a high-VA alias
    /// (Go heap arena) ANOTHER goroutine mmap'd, invisible to this thread's list
    /// (the "read/wait: bad address" EFAULT). Both `_range` and `_range_mut`
    /// resolve identically — no accessor mutates the region itself.
    pub(crate) fn mapping_for_range(&self, address: u64, length: usize) -> Option<MappingView> {
        let custody = self.carrier_vm_custody();
        self.task.mapping_for_range_in(&custody, address, length)
    }

    pub(crate) fn mapping_for_range_mut(
        &mut self,
        address: u64,
        length: usize,
    ) -> Option<MappingView> {
        self.mapping_for_range(address, length)
    }

    /// The address the per-chunk region lookup + offset should use for a syscall
    /// buffer at guest VA `chunk_va`. Identity for everything but a
    /// `repoint_private` overlay: a MAP_FIXED|MAP_PRIVATE carved over a
    /// shared-aperture VA repoints the stage-1 leaf to a per-process overlay IPA
    /// (608 GiB), but registers NO region keyed at the original VA — the only
    /// region with the overlay backing is keyed at the overlay IPA. So a syscall
    /// copy must look up (and offset) by that translated IPA, or it resolves to
    /// the STALE shared-aperture region the VA still covers (the repoint_private
    /// syscall-buffer bug). High-VA aliases are NOT redirected here: their region
    /// is keyed at the VA and `mapping_for_range` already disambiguates
    /// overlapping aliases via `translate_va` internally (VA-relative offset). For
    /// every other (identity) VA this returns `chunk_va` unchanged — no walk.
    pub(crate) fn syscall_buffer_lookup_addr(&self, chunk_va: u64, chunk_len: usize) -> u64 {
        if !crate::memory::needs_stage1_translation(chunk_va, chunk_len as u64) {
            return chunk_va;
        }
        self.translate_va(chunk_va).unwrap_or(chunk_va)
    }

    /// True if `ipa` falls in `region`'s `hv_vm_map`'d IPA window.
    pub(crate) fn region_owns_ipa(region: &HvfMappedRegion, ipa: u64) -> bool {
        ipa >= region.ipa && ipa < region.ipa + region.size as u64
    }

    #[cfg(test)]
    pub(crate) fn mapping_index_for_range(
        mappings: &[HvfMappedRegion],
        address: u64,
        length: usize,
        stage1_ipa: Option<u64>,
    ) -> Option<usize> {
        // Prefer the region selected by the authoritative stage-1 output when
        // overlapping semantic descriptors exist, then fall back newest-first
        // for test fixtures without a live page-table walk.
        if let Some(ipa) = stage1_ipa
            && let Some((idx, _)) = mappings.iter().enumerate().rev().find(|(_, mapping)| {
                Self::region_owns_ipa(mapping, ipa) && mapping.contains_range(address, length)
            })
        {
            return Some(idx);
        }
        mappings
            .iter()
            .enumerate()
            .rev()
            .find(|(_, mapping)| mapping.contains_range(address, length))
            .map(|(idx, _)| idx)
    }

    /// Resolve a raw stage-2 IPA without treating it as a guest virtual
    /// address. Global-frame aliases deliberately have `start != ipa`; using
    /// the VA lookup here could select no mapping (or an unrelated mapping at
    /// the same VA) when editing a non-identity backing.
    pub(crate) fn mapping_for_ipa_range(
        mappings: &TaskMappingIndex,
        ipa: u64,
        length: usize,
    ) -> Option<MappingView> {
        let length = u64::try_from(length).ok()?;
        ipa.checked_add(length)?;
        mappings
            .candidates_for_ipa_range(ipa, length)
            .next()
            .map(HvfMappedRegion::view)
    }

    /// Resolve one mailbox route without losing its semantic VA identity.
    ///
    /// A raw IPA is not a sufficient key in the persistent VM: the reusable
    /// allocator can give a retired dynamic row's physical IPA to a later
    /// process-local kernel-state mapping while that stale row remains in one
    /// vCPU's metadata solely to retain its host owner. Require the same row to
    /// cover the mailbox VA *and* express the live VA-to-IPA translation.
    fn mailbox_mapping_for_range(
        mappings: &TaskMappingIndex,
        semantic_va: u64,
        ipa: u64,
        length: usize,
    ) -> Option<MappingView> {
        let semantic_end = semantic_va.checked_add(u64::try_from(length).ok()?)?;
        mappings
            .candidates_for_range(GuestVa(semantic_va), length as u64)
            .find(|mapping| {
                semantic_va >= mapping.start
                    && semantic_end <= mapping.end
                    && mapping
                        .ipa
                        .checked_add(semantic_va.saturating_sub(mapping.start))
                        == Some(ipa)
            })
            .map(HvfMappedRegion::view)
    }

    /// Resolve a raw IPA only through the exact currently-owned generation.
    /// A retired dynamic row can keep the same IPA and raw host pointer after
    /// the reusable allocator hands that IPA to another frame; mapped-address
    /// liveness or IPA equality alone would then select stale memory.
    pub(crate) fn mapping_for_live_ipa_range(
        &self,
        semantic_va: u64,
        ipa: u64,
        length: usize,
    ) -> Option<MappingView> {
        let length = u64::try_from(length).ok()?;
        let end = ipa.checked_add(length)?;
        let semantic_end = semantic_va.checked_add(length)?;
        if let Some(mapping) = self.mappings.iter().rev().find(|mapping| {
            let mapping_end = mapping.ipa.checked_add(mapping.size as u64);
            semantic_va >= mapping.start
                && semantic_end <= mapping.end
                && mapping
                    .ipa
                    .checked_add(semantic_va.saturating_sub(mapping.start))
                    == Some(ipa)
                && ipa >= mapping.ipa
                && mapping_end.is_some_and(|limit| end <= limit)
                && (!self.persistent_vm_lifecycle
                    || !is_reusable_global_frame_extent(
                        mapping.physical_ipa,
                        mapping.physical_size as u64,
                    )
                    || global_frame_region_owner_matches_in(self.custody(), mapping))
        }) {
            return Some(mapping.view());
        }
        alias_registry()
            .lock()
            .newest_process_alias_containing_va(
                semantic_va,
                self.mm_root_slot,
                self.container_root,
                |alias| {
                    let alias_end = alias.ipa.checked_add(alias.size as u64);
                    semantic_end <= alias.start.saturating_add(alias.size as u64)
                        && alias
                            .ipa
                            .checked_add(semantic_va.saturating_sub(alias.start))
                            == Some(ipa)
                        && ipa >= alias.ipa
                        && alias_end.is_some_and(|limit| end <= limit)
                        && (!self.persistent_vm_lifecycle
                            || !is_reusable_global_frame_extent(
                                alias.physical_ipa,
                                alias.physical_size as u64,
                            )
                            || global_frame_host_owner_matches_in(
                                self.custody(),
                                alias.physical_ipa,
                                alias.physical_size as u64,
                                alias.physical_host_addr,
                                alias.owner_generation,
                            ))
                },
            )
            .map(|alias| MappingView::from_alias(&alias))
    }

    pub(crate) fn guest_range_is_writable(&self, address: u64, length: usize) -> bool {
        !self.range_no_access(address, length)
            && self
                .validate_guest_write_range_with_pristine(address, length, true, true)
                .is_ok()
    }

    /// M:N reclaim — BLOCK side. Snapshot this vCPU and DESTROY it (freeing one
    /// HVF concurrent-vCPU slot) so another guest thread can run while this one
    /// parks in the futex wait. The SAME thread recreates it via
    /// [`reclaim_resume`](Self::reclaim_resume) on wake. Unlike the fork
    /// path this does NOT publish mappings or rebuild the VM — the VM is unchanged;
    /// only the per-thread vCPU is recycled. Task state is returned through the
    /// typed engine boundary; this backend retains only executor lifecycle.
    ///
    /// WIRED via the HVF engine override `ThreadedEngine::save_guest_state`
    /// (`hvf_aarch64_engine.rs:536`), which passes the engine's separately-owned
    /// `&mut vcpu` through to this destroy-in-place reclaim; the wake side is
    /// `rebind_to_slot` (`hvf_aarch64_engine.rs:557`) → [`reclaim_resume`].
    /// This is the multi-threaded blocked-wait park (vCPU-only; the VM stays
    /// alive) that `park_vcpu_for_blocking_wait` routes to.
    pub(crate) fn reclaim_park(
        &mut self,
        vcpu: &mut applevisor::vcpu::Vcpu,
        mailbox: &mut MailboxBinding,
    ) -> Result<(), TrapError> {
        // Raw destroy — only the owning thread may, and applevisor's Drop would
        // panic on the post-destroy handle.
        let vcpu_id = vcpu.id();
        let rc = unsafe { applevisor_sys::hv_vcpu_destroy(vcpu_id) };
        if rc == 0 {
            self._vcpu_guard = None;
            vcpu_destroyed(vcpu_id);
        }
        if rc != 0 {
            return Err(TrapError::Hypervisor(format!(
                "reclaim_park: hv_vcpu_destroy rc={rc:#x}"
            )));
        }
        self.reclaim_authority.mark_vcpu_parked()?;
        self.release_mailbox_for_reclaim(mailbox)?;
        Ok(())
    }

    /// Owner-thread zero-instruction handoff. The initial mailbox must still be
    /// idle; validate before destroying the vCPU so an incompatible protocol
    /// state fails without partially relinquishing hardware authority.
    pub(crate) fn initial_runner_park(
        &mut self,
        vcpu: &mut applevisor::vcpu::Vcpu,
        mailbox: &mut MailboxBinding,
    ) -> Result<(), TrapError> {
        let diagnostics = mailbox.diagnostics();
        if diagnostics.state != carrick_aarch64::mailbox::MailboxState::Idle.raw() {
            return Err(TrapError::Hypervisor(format!(
                "initial runner mailbox is not idle: diagnostics={diagnostics:?}"
            )));
        }
        let vcpu_id = vcpu.id();
        let rc = unsafe { applevisor_sys::hv_vcpu_destroy(vcpu_id) };
        if rc == 0 {
            self._vcpu_guard = None;
            vcpu_destroyed(vcpu_id);
        }
        if rc != 0 {
            return Err(TrapError::Hypervisor(format!(
                "initial_runner_park: hv_vcpu_destroy rc={rc:#x}"
            )));
        }
        self.reclaim_authority.mark_initial_runner_parked()?;
        mailbox
            .release_idle_for_initial_handoff()
            .map_err(|error| TrapError::Hypervisor(format!("release initial mailbox: {error}")))
    }

    pub(crate) fn initial_runner_resume(
        &mut self,
        vcpu: &mut applevisor::vcpu::Vcpu,
        mailbox: &mut MailboxBinding,
    ) -> Result<(), TrapError> {
        if self.reclaim_authority != ReclaimParkAuthority::InitialRunnerParked {
            return Err(TrapError::Hypervisor(
                "initial_runner_resume: no idle initial-runner authority".to_owned(),
            ));
        }
        let new_vcpu = create_vcpu(&self._vm)?;
        enable_el0_counter_access(new_vcpu.id());
        Self::configure_executor_invariants(&new_vcpu)?;
        self.vcpu_id = new_vcpu.id();
        self.vcpu_handle = new_vcpu.get_handle();
        self._vcpu_guard = Some(vcpu_census().created());
        self.publish_live_vcpu();
        std::mem::forget(std::mem::replace(vcpu, new_vcpu));
        self.reacquire_mailbox_after_vcpu_create(vcpu, mailbox, None)?;
        self.reclaim_authority.mark_live_after_recreate()
    }

    /// M:N reclaim — WAKE side. Recreate this executor's vCPU in the EXISTING VM
    /// when it was locally parked. A live destination executor is retained as-is;
    /// the caller overlays only Kernel-owned typed task state. The CALLER must hold
    /// `fork_quiesce::topology_lock` so `vcpu_create` cannot race a concurrent
    /// fork's `hv_vm_destroy`/`create`. Writes the recreated vCPU back through
    /// `vcpu` via `std::mem::replace` + `forget` of the old (already-destroyed)
    /// handle (no applevisor Drop).
    ///
    /// WIRED — see [`reclaim_park`](Self::reclaim_park): reached via the HVF
    /// engine override `ThreadedEngine::rebind_to_slot`
    /// (`hvf_aarch64_engine.rs:557`), which passes the `&mut vcpu` this
    /// destroy/recreate-in-place reclaim needs.
    pub(crate) fn reclaim_resume(
        &mut self,
        vcpu: &mut applevisor::vcpu::Vcpu,
        mailbox: &mut MailboxBinding,
        continuation: Option<carrick_hal::threaded::Aarch64SyscallContinuationV1>,
    ) -> Result<(), TrapError> {
        if self.reclaim_authority.destination_vcpu_is_live().is_ok() {
            if let Some(continuation) = continuation {
                mailbox
                    .import_task_continuation(continuation)
                    .map_err(|error| {
                        TrapError::Hypervisor(format!(
                            "restore task continuation into live destination mailbox: {error}"
                        ))
                    })?;
            }
            return Ok(());
        }
        if self.reclaim_authority != ReclaimParkAuthority::VcpuParked {
            return Err(TrapError::Hypervisor(
                "reclaim_resume: executor requires whole-VM recreation".to_owned(),
            ));
        }
        let continuation = continuation.ok_or_else(|| {
            TrapError::Hypervisor(
                "reclaim_resume: parked syscall has no typed continuation authority".to_owned(),
            )
        })?;
        let new_vcpu = create_vcpu(&self._vm)?;
        enable_el0_counter_access(new_vcpu.id());
        Self::configure_executor_invariants(&new_vcpu)?;
        self.vcpu_id = new_vcpu.id();
        self.vcpu_handle = new_vcpu.get_handle();
        self._vcpu_guard = Some(vcpu_census().created());
        self.publish_live_vcpu();
        // Replace the destroyed handle WITHOUT running applevisor's panicky Drop on
        // the (already hv_vcpu_destroy'd) old one — mirror the fork rebuild.
        std::mem::forget(std::mem::replace(vcpu, new_vcpu));
        self.reacquire_mailbox_after_vcpu_create(vcpu, mailbox, Some(continuation))?;
        self.reclaim_authority.mark_live_after_recreate()?;
        Ok(())
    }

    /// Single-threaded process shared-futex park. Unlike `reclaim_park`, this
    /// destroys the whole VM, not just the vCPU, so a large process-fork fanout
    /// parked in `FUTEX_WAIT` does not keep one HVF VM alive per waiter.
    pub(crate) fn shared_wait_park(
        &mut self,
        vcpu: &mut applevisor::vcpu::Vcpu,
        mailbox: &mut MailboxBinding,
    ) -> Result<(), TrapError> {
        let vcpu_id = vcpu.id();
        let vcpu_rc = unsafe { applevisor_sys::hv_vcpu_destroy(vcpu_id) };
        if vcpu_rc == 0 {
            self._vcpu_guard = None;
            vcpu_destroyed(vcpu_id);
        }
        if vcpu_rc != 0 {
            return Err(TrapError::Hypervisor(format!(
                "shared_wait_park: hv_vcpu_destroy rc={vcpu_rc:#x}"
            )));
        }
        self.reclaim_authority.mark_vcpu_parked()?;
        self.release_mailbox_for_reclaim(mailbox)?;
        destroy_vm_with_custody(
            &self.carrier_foreign_mm_transport.custody,
            "shared_wait_park",
        )?;
        self.reclaim_authority.mark_vm_parked()?;
        Ok(())
    }

    /// MT whole-VM lease — VM-only release by the LAST parker of a
    /// multi-threaded process. Its own vCPU was ALREADY destroyed by
    /// [`Self::reclaim_park`] (its executor lifecycle is recorded in
    /// `reclaim_authority`), and every
    /// sibling's registry "parked" mark is set only AFTER its own
    /// `reclaim_park` destroy — so when the runtime's re-check passes, zero
    /// vCPUs are live and the bare `hv_vm_destroy` succeeds. Any nonzero rc
    /// (e.g. HV_BUSY from a vCPU in a teardown window the registry no longer
    /// tracks, like a thread mid-exit) is a clean error: the VM was NOT
    /// destroyed, and the caller must NOT set the vm-released flag — the park
    /// stays vCPU-only and the wake side stays `reclaim_resume`.
    pub(crate) fn release_vm_after_reclaim_park(&mut self) -> Result<(), TrapError> {
        if self.reclaim_authority != ReclaimParkAuthority::VcpuParked {
            return Err(TrapError::Hypervisor(
                "release_vm_after_reclaim_park: no parked vCPU authority (reclaim_park did not run)"
                    .into(),
            ));
        }
        destroy_vm_with_custody(
            &self.carrier_foreign_mm_transport.custody,
            "release_vm_after_reclaim_park",
        )?;
        self.reclaim_authority.mark_vm_parked()?;
        Ok(())
    }

    /// Resume a process parked by [`Self::shared_wait_park`]: create a fresh VM
    /// and vCPU, re-map this process's existing host backings, then restore the
    /// saved guest registers.
    ///
    /// `replay_alias_union` (the MT whole-VM lease first-waker rebuild): also
    /// re-map every live process-global [`alias_registry`] entry this thread's
    /// per-thread `mappings` lacks. Threads share ONE VM but `mappings` is
    /// per-thread, so a high-VA alias a STILL-PARKED sibling mapped would
    /// otherwise be missing from the rebuilt stage-2 (the same shape the fork
    /// rebuild repairs with its quiesced-sibling union). Safe because every
    /// parked sibling holds its `OwnedHostMapping`s alive while parked, and no
    /// guest thread of this process runs during the rebuild (the caller holds
    /// the topology lock; claim-false wakers rebind behind it) — so no
    /// interleaving `munmap` can invalidate an entry mid-replay. Entries are
    /// NOT pushed into `self.mappings` (ownership stays with the mapping
    /// thread; a later rebuild re-reads the registry, which reflects any
    /// munmap since). Single-threaded resumes pass `false` — their own
    /// `mappings` list is complete by construction, and a forked child must
    /// NOT re-establish inherited parent/sibling aliases the fork rebuild
    /// deliberately dropped. The bounded lazy on-fault re-map in `run_to_exit`
    /// remains the backstop either way.
    pub(crate) fn shared_wait_resume(
        &mut self,
        vcpu: &mut applevisor::vcpu::Vcpu,
        mailbox: &mut MailboxBinding,
        replay_alias_union: bool,
        continuation: Option<carrick_hal::threaded::Aarch64SyscallContinuationV1>,
    ) -> Result<(), TrapError> {
        let mut pending_creation = None;
        let result = self.shared_wait_resume_inner(
            vcpu,
            mailbox,
            replay_alias_union,
            continuation,
            &mut pending_creation,
        );
        finish_pending_vm_creation(pending_creation, result)
    }

    fn shared_wait_resume_inner(
        &mut self,
        vcpu: &mut applevisor::vcpu::Vcpu,
        mailbox: &mut MailboxBinding,
        replay_alias_union: bool,
        continuation: Option<carrick_hal::threaded::Aarch64SyscallContinuationV1>,
        pending_creation: &mut Option<PendingCarrierVmCreation>,
    ) -> Result<(), TrapError> {
        if self.reclaim_authority != ReclaimParkAuthority::VmParked {
            return Err(TrapError::Hypervisor(
                "shared_wait_resume: no parked VM executor authority".to_owned(),
            ));
        }
        let continuation = continuation.ok_or_else(|| {
            TrapError::Hypervisor(
                "shared_wait_resume: parked syscall has no typed continuation authority".to_owned(),
            )
        })?;
        let (new_vm, permit, creation) = create_vm_with_admission(
            VmCreateAdmission::SharedWaitResume,
            &self.carrier_foreign_mm_transport.custody,
        )?;
        let new_vm = SetupVmGuard::new(new_vm, true);
        *pending_creation = Some(creation);
        let new_vcpu = SetupVcpuGuard::new(
            create_vcpu_with_permit(&new_vm, permit)?,
            SetupVcpuCleanup::PendingRaw,
        );
        let creation = pending_creation.as_mut().ok_or_else(|| {
            TrapError::Hypervisor("shared-wait creation transaction disappeared".to_owned())
        })?;
        creation.record_vcpu(new_vcpu.id());
        enable_el0_counter_access(new_vcpu.id());
        Self::configure_executor_invariants(&new_vcpu)?;
        // Snapshot the registry's CURRENT membership before the replay: an
        // alias another thread `munmap`'d while we were parked was removed
        // from the registry (`unregister_alias`) but may still sit in this
        // thread's per-thread `mappings` list — re-REGISTERING it below would
        // resurrect a dead index entry that a later syscall/fault could
        // resolve to a freed backing. Registration is creation-complete
        // (every `add_alias` registers; removal happens only on munmap /
        // execve-clear), so absence here means "gone on purpose".
        let registered_aliases = alias_registry()
            .lock()
            .process_visible_ordered(self.mm_root_slot, self.container_root);
        let mut mapped_extents = std::collections::HashSet::new();
        let mut replayed_global_owners = Vec::new();
        for mapping in &self.mappings {
            // Skip a sibling-munmap'd stale high-VA entry ENTIRELY (absence
            // from the registry = gone on purpose, mirroring the union loop
            // below): hv_vm_map'ing it would map a freed host VA
            // (ChildMapFailed → wake fatal) or squat a dead IPA a later mmap
            // collides with.
            let live_alias = mapping
                .is_dynamic_alias
                .then(|| {
                    registered_aliases.iter().find(|alias| {
                        alias_matches_process_scope(
                            alias.ownership_scope,
                            self.mm_root_slot,
                            self.container_root,
                        ) && alias.start == mapping.start
                            && alias.ipa == mapping.ipa
                            && alias.host_addr == mapping.host_addr as usize
                            && alias.size == semantic_extent_size(mapping.start, mapping.end)
                    })
                })
                .flatten();
            if mapping.is_dynamic_alias && live_alias.is_none() {
                continue;
            }
            let (host_addr, ipa, size, perms, owner_generation) = live_alias.map_or(
                (
                    mapping.host_addr,
                    mapping.ipa,
                    mapping.size,
                    u64::from(mapping.perms),
                    mapping.owner_generation,
                ),
                |alias| {
                    (
                        alias.physical_host_addr as *mut u8,
                        alias.physical_ipa,
                        alias.physical_size,
                        alias.perms,
                        alias.owner_generation,
                    )
                },
            );
            if is_reusable_global_frame_extent(ipa, size as u64)
                && !global_frame_owner_is_replayable_in(
                    &self.carrier_foreign_mm_transport.custody,
                    ipa,
                    size as u64,
                    host_addr as usize,
                    owner_generation,
                )
            {
                continue;
            }
            if !mapped_extents.insert((ipa, size)) {
                continue;
            }
            let r = unsafe { inventory_hv_vm_map(host_addr.cast(), ipa, size, perms) };
            if r != 0 {
                return Err(TrapError::ChildMapFailed {
                    host_addr: host_addr as u64,
                    guest_start: ipa,
                    size,
                    code: r as u32,
                });
            }
            replayed_global_owners.push(GlobalFrameReplayExtent {
                ipa,
                length: size as u64,
                host_addr: host_addr as usize,
                perms,
            });
        }

        if replay_alias_union || self.mappings.iter().any(|mapping| mapping.is_dynamic_alias) {
            // Copy the entries out so the registry mutex isn't held across the
            // hv_vm_map syscalls (`AliasBacking` is `Copy`).
            for b in registered_aliases {
                if !alias_matches_process_scope(
                    b.ownership_scope,
                    self.mm_root_slot,
                    self.container_root,
                ) || !mapped_extents.insert((b.physical_ipa, b.physical_size))
                    || !alias_backing_is_live(b.host_addr)
                {
                    continue;
                }
                if is_reusable_global_frame_extent(b.physical_ipa, b.physical_size as u64)
                    && !global_frame_owner_is_replayable_in(
                        &self.carrier_foreign_mm_transport.custody,
                        b.physical_ipa,
                        b.physical_size as u64,
                        b.physical_host_addr,
                        b.owner_generation,
                    )
                {
                    continue;
                }
                let r = unsafe {
                    inventory_hv_vm_map(
                        b.physical_host_addr as *mut std::ffi::c_void,
                        b.physical_ipa,
                        b.physical_size,
                        b.perms,
                    )
                };
                if r != 0 {
                    return Err(TrapError::ChildMapFailed {
                        host_addr: b.host_addr as u64,
                        guest_start: b.physical_ipa,
                        size: b.physical_size,
                        code: r as u32,
                    });
                }
                replayed_global_owners.push(GlobalFrameReplayExtent {
                    ipa: b.physical_ipa,
                    length: b.physical_size as u64,
                    host_addr: b.physical_host_addr,
                    perms: b.perms,
                });
            }
        }

        reconcile_global_frame_owners_after_replay_in(
            &self.carrier_foreign_mm_transport.custody,
            &replayed_global_owners,
            false,
        )?;

        self.reacquire_mailbox_after_vcpu_create(&new_vcpu, mailbox, Some(continuation))?;
        self.reclaim_authority.mark_live_after_recreate()?;
        commit_pending_creation_before_vcpu_handoff(pending_creation)?;
        self.vcpu_id = new_vcpu.id();
        self.vcpu_handle = new_vcpu.get_handle();
        self.publish_live_vcpu();
        std::mem::forget(std::mem::replace(vcpu, new_vcpu.into_inner()));
        replace_destroyed_vm(self, new_vm.into_inner());
        Ok(())
    }

    /// A guest thread is exiting: destroy ITS OWN vCPU (only the owning thread
    /// may) so the slot is freed in the process-global VM. Without this, the
    /// no-op `Drop` leaks the vCPU live forever, and a later fork's
    /// `hv_vm_destroy` trips over the accumulated dead-thread vCPUs (HV_BUSY).
    /// Raw `hv_vcpu_destroy`, not applevisor's panicky wrapper.
    pub(crate) fn destroy_vcpu_on_thread_exit(&mut self, vcpu: &mut applevisor::vcpu::Vcpu) {
        let vcpu_id = vcpu.id();
        let rc = unsafe { applevisor_sys::hv_vcpu_destroy(vcpu_id) };
        if rc == 0 {
            self._vcpu_guard = None;
            vcpu_destroyed(vcpu_id);
        }
    }

    pub(crate) fn take_persistent_executor_spec(
        &mut self,
    ) -> Result<PersistentExecutorSpec, TrapError> {
        if let Some(carrier_mappings) = self.carrier_mappings.as_ref() {
            // A later container's root was built INSIDE the carrier VM
            // (`new_with_plan` reuse lane) and already shares the carrier's
            // control-mapping authority: hand back the carrier's own bundle.
            // Any other holder (a worker) is still refused as before.
            let cell = persistent_carrier_cell().lock();
            return match cell.as_ref() {
                Some(PersistentCarrierCellEntry::Published(spec))
                    if std::sync::Arc::ptr_eq(&spec.carrier_mappings, carrier_mappings) =>
                {
                    Ok(spec.clone())
                }
                _ => Err(TrapError::Hypervisor(
                    "persistent executor carrier authority was already extracted".to_owned(),
                )),
            };
        }
        let custody = std::sync::Arc::clone(&self.carrier_foreign_mm_transport.custody);
        let carrier_mappings = std::sync::Arc::new(PersistentCarrierMappings::extract(
            &mut self.mappings,
            custody,
        )?);
        let spec = PersistentExecutorSpec {
            vm: (*self._vm).clone(),
            carrier_mappings,
            mailbox_slots: std::sync::Arc::clone(&self.mailbox_slots),
            syscall_transport: self.syscall_transport,
            carrier_foreign_mm_transport: std::sync::Arc::clone(&self.carrier_foreign_mm_transport),
        };
        // First root of this carrier: publish the VM-global bundle for every
        // later container's root bring-up and wake any root parked on it. The
        // boot gate in `new_with_plan` guarantees only ONE first root exists,
        // so the cell is empty here; the guard is defensive.
        {
            let mut cell = persistent_carrier_cell().lock();
            if cell.is_none() {
                *cell = Some(PersistentCarrierCellEntry::Published(spec.clone()));
            }
        }
        carrier_published().notify_all();
        Ok(spec)
    }

    fn allocate_persistent_mailbox_for_vcpu(
        spec: &PersistentExecutorSpec,
        vcpu: &applevisor::vcpu::Vcpu,
    ) -> Result<MailboxBinding, TrapError> {
        use applevisor::prelude::SysReg;

        let lease = spec
            .mailbox_slots
            .allocate()
            .map_err(|error| TrapError::Hypervisor(error.to_string()))?;
        let address = lease.id().guest_address();
        let pointer = spec
            .carrier_mappings
            .host_pointer(
                address,
                carrick_aarch64::mailbox::AARCH64_SYSCALL_MAILBOX_SIZE as usize,
            )
            .ok_or_else(|| {
                TrapError::Hypervisor(format!(
                    "persistent executor syscall mailbox slot {} at {address:#x} is not mapped",
                    lease.id().raw()
                ))
            })?
            .cast::<carrick_aarch64::mailbox::Aarch64SyscallMailbox>();
        // SAFETY: the carrier projection was validated to contain the complete
        // fixed mailbox arena, and the lease uniquely owns this slot.
        let binding = unsafe { MailboxBinding::new(lease, pointer, spec.syscall_transport) };
        vcpu.set_sys_reg(SysReg::SP_EL1, address)
            .map_err(hvf_error)?;
        Ok(binding)
    }

    pub(crate) fn from_persistent_executor_spec(
        spec: &PersistentExecutorSpec,
    ) -> Result<(HvfVmState, applevisor::vcpu::Vcpu, MailboxBinding), TrapError> {
        spec.carrier_mappings.audit()?;
        let vm = rebuilt_vm_cell()
            .lock()
            .clone()
            .unwrap_or_else(|| spec.vm.clone());
        let vcpu = create_vcpu(&vm)?;
        enable_el0_counter_access(vcpu.id());
        let state = HvfVmState {
            _vm: std::mem::ManuallyDrop::new(vm),
            carrier_foreign_mm_transport: std::sync::Arc::clone(&spec.carrier_foreign_mm_transport),
            task: HvfTaskState::neutral(),
            carrier_mappings: Some(std::sync::Arc::clone(&spec.carrier_mappings)),
            reclaim_authority: ReclaimParkAuthority::Live,
            mailbox_slots: std::sync::Arc::clone(&spec.mailbox_slots),
            syscall_transport: spec.syscall_transport,
            vcpu_id: vcpu.id(),
            vcpu_handle: vcpu.get_handle(),
            _vcpu_guard: Some(vcpu_census().created()),
        };
        state.publish_live_vcpu();
        Self::configure_executor_invariants(&vcpu)?;
        let mailbox = Self::allocate_persistent_mailbox_for_vcpu(spec, &vcpu)?;
        Self::audit_executor_invariants(&vcpu, mailbox.slot().guest_address())?;
        state.task.audit_neutral()?;
        Ok((state, vcpu, mailbox))
    }

    pub(crate) fn audit_persistent_executor_idle(&self) -> Result<(), TrapError> {
        self.task.audit_neutral()?;
        self.carrier_mappings
            .as_ref()
            .ok_or_else(|| {
                TrapError::Hypervisor(
                    "persistent executor lost carrier mapping authority".to_owned(),
                )
            })?
            .audit()?;
        // Maintenance failures remain recorded on the exact Pending owner and
        // re-arm the custody-local request bit. They must not kill an otherwise
        // clean persistent worker; the next executor-idle boundary retries.
        let _remaining = retry_pending_global_frame_retirements_at_idle_in_using(
            &self.carrier_foreign_mm_transport.custody,
            &mut unmap_global_frame_stage2_record,
        );
        Ok(())
    }

    pub(crate) fn carrier_maintenance_root(
        &self,
    ) -> Result<carrick_mem::memory::CarrierMaintenanceRoot, TrapError> {
        let carrier = self.carrier_mappings.as_ref().ok_or_else(|| {
            TrapError::Hypervisor("persistent executor lost carrier mapping authority".to_owned())
        })?;
        Ok(carrier.maintenance_root())
    }

    pub(crate) fn audit_persistent_worker_vcpu_boundary(
        &self,
        vcpu: &applevisor::vcpu::Vcpu,
        mailbox: &MailboxBinding,
    ) -> Result<(), TrapError> {
        self.audit_persistent_executor_idle()?;
        if self.reclaim_authority != ReclaimParkAuthority::Live {
            return Err(TrapError::Hypervisor(
                "persistent worker lost its live owner-thread vCPU authority".to_owned(),
            ));
        }
        if mailbox.is_released_for_executor_boundary() {
            return Err(TrapError::Hypervisor(
                "persistent worker released its executor-local mailbox".to_owned(),
            ));
        }
        if mailbox
            .export_task_continuation()
            .map_err(|error| {
                TrapError::Hypervisor(format!("audit persistent worker mailbox boundary: {error}"))
            })?
            .is_some()
        {
            return Err(TrapError::Hypervisor(
                "persistent worker retained a task syscall continuation".to_owned(),
            ));
        }
        use applevisor::prelude::SysReg;
        let sp_el1 = vcpu.get_sys_reg(SysReg::SP_EL1).map_err(hvf_error)?;
        if sp_el1 != mailbox.slot().guest_address() {
            return Err(TrapError::Hypervisor(format!(
                "persistent worker mailbox SP_EL1 drifted: {sp_el1:#x}/{:#x}",
                mailbox.slot().guest_address()
            )));
        }
        Ok(())
    }

    pub(crate) fn restore_persistent_worker_vcpu_boundary(
        &self,
        vcpu: &applevisor::vcpu::Vcpu,
        mailbox: &MailboxBinding,
    ) -> Result<(), TrapError> {
        use applevisor::prelude::SysReg;

        restore_persistent_executor_invariant_registers(
            |register, value| {
                let register = match register {
                    PersistentExecutorInvariantRegister::VbarEl1 => SysReg::VBAR_EL1,
                    PersistentExecutorInvariantRegister::SctlrEl1 => SysReg::SCTLR_EL1,
                    PersistentExecutorInvariantRegister::MairEl1 => SysReg::MAIR_EL1,
                    PersistentExecutorInvariantRegister::CpacrEl1 => SysReg::CPACR_EL1,
                    PersistentExecutorInvariantRegister::CntkctlEl1 => SysReg::CNTKCTL_EL1,
                    PersistentExecutorInvariantRegister::TpidrEl1 => SysReg::TPIDR_EL1,
                    PersistentExecutorInvariantRegister::SpEl1 => SysReg::SP_EL1,
                };
                vcpu.set_sys_reg(register, value).map_err(hvf_error)
            },
            mailbox.slot().guest_address(),
        )?;
        Self::audit_executor_invariants(vcpu, mailbox.slot().guest_address())
    }

    /// Build a [`ThreadSpec`] for a thread-creating `clone(CLONE_THREAD)`: clone the
    /// SHARED VM handle (Arc-refcounted, so the new thread can `vcpu_create` against
    /// it) + the SHARED protections/page-table Arcs + a COPY of the mapping
    /// descriptors (the new thread's vCPU sees the same guest memory; the stage-2
    /// entries are VM-global). Does NOT snapshot the vCPU — the engine carries the
    /// seeded register snapshot in its own `Aarch64SiblingSpec` and restores it onto
    /// the sibling vCPU via `restore_thread_start` after `from_thread_spec`.
    pub(crate) fn build_thread_spec(&self) -> Result<ThreadSpec, TrapError> {
        let mappings: Vec<ThreadMappingDesc> = self
            .mappings
            .iter()
            .map(ThreadMappingDesc::from_region)
            .collect();
        Ok(ThreadSpec {
            vm: (*self._vm).clone(),
            mappings,
            mm_access: std::sync::Arc::clone(&self.mm_access),
            carrier_foreign_mm_transport: std::sync::Arc::clone(&self.carrier_foreign_mm_transport),
            mailbox_slots: std::sync::Arc::clone(&self.mailbox_slots),
            syscall_transport: self.syscall_transport,
            persistent_vm_lifecycle: self.persistent_vm_lifecycle,
            mm_root_slot: self.mm_root_slot,
            container_root: self.container_root,
            cow_authority: self.cow_authority.clone(),
            cow_identity: self.cow_identity,
        })
    }

    /// Stand up a thread sibling on the current host thread from a [`ThreadSpec`]:
    /// create a new vCPU in the shared VM and mirror the inherited (UNOWNED)
    /// mapping metadata. Returns the `(state, vcpu)` pair; the engine restores the
    /// seeded register snapshot. MUST be called on the host thread that will own
    /// the vCPU (HVF requires vCPU create+run+destroy on one thread).
    pub(crate) fn from_thread_spec(
        spec: ThreadSpec,
    ) -> Result<(HvfVmState, applevisor::vcpu::Vcpu, MailboxBinding), TrapError> {
        let ThreadSpec {
            vm,
            mappings,
            mm_access,
            carrier_foreign_mm_transport,
            mailbox_slots,
            syscall_transport,
            persistent_vm_lifecycle,
            mm_root_slot,
            container_root,
            cow_authority,
            cow_identity,
        } = spec;

        // The spec captured `vm` at clone time. If a fork rebuilt the VM since
        // then (the spec's `vm` was destroyed), create the vCPU in the CURRENT
        // VM that the fork published instead — otherwise vcpu_create hits
        // HV_BUSY on a torn-down VM. Between forks the published cell holds the
        // live VM; with no fork yet it's empty and the spec's `vm` is current.
        // The caller holds `fork_quiesce::topology_lock()`, so this read can't
        // race a fork's republish.
        let vm = rebuilt_vm_cell().lock().clone().unwrap_or(vm);
        let vcpu = create_vcpu(&vm)?;
        enable_el0_counter_access(vcpu.id());

        #[cfg(not(test))]
        let custody = std::sync::Arc::clone(&carrier_foreign_mm_transport.custody);
        let mut state = HvfVmState {
            _vm: std::mem::ManuallyDrop::new(vm),
            carrier_foreign_mm_transport,
            task: HvfTaskState {
                #[cfg(not(test))]
                custody,
                mappings: TaskMappingIndex::new(),
                mm_root_slot,
                container_root,
                pending_exec_mm_root_slot: None,
                pending_exec_asid: None,
                pending_exec_predecessor_identity: None,
                pending_exec_stage2_cleanup: None,
                shared_process_mm: false,
                mm_access,
                last_exit_class: 0,
                last_fault_esr: 0,
                is_forked_child: false,
                forked_no_exec: false,
                last_syscall_nr: None,
                last_syscall_orig_x0: 0,
                live_vcpu: crate::vcpu_kick::LiveVcpuSlot::new(),
                persistent_vm_lifecycle,
                cow_authority,
                cow_identity,
                pending_fork_frame_receipts: Vec::new(),
                pending_process_aliases: Vec::new(),
                fail_next_begin_exec_inventory: false,
                cow_rollback_scratch: None,
                registration: None,
            },
            carrier_mappings: None,
            reclaim_authority: ReclaimParkAuthority::Live,
            mailbox_slots,
            syscall_transport,
            vcpu_id: vcpu.id(),
            vcpu_handle: vcpu.get_handle(),
            _vcpu_guard: Some(vcpu_census().created()),
        };
        state.publish_live_vcpu();

        for mapping in mappings {
            // `hv_vm_map` is VM-global on Hypervisor.framework. The new vCPU is
            // created in the parent's VM clone, so the parent mappings are
            // already visible here; reissuing them for every sibling is at best
            // an already-mapped no-op and at worst map-table churn while other
            // vCPUs are running. Keep only local metadata used by syscall-path
            // guest-memory accessors.
            state.mappings.insert(mapping.into_unowned_region());
        }

        let mailbox = state.allocate_mailbox_for_vcpu(&vcpu)?;
        Ok((state, vcpu, mailbox))
    }

    pub(crate) fn build_process_spec(
        &self,
        request: carrick_hal::ProcessForkRequest,
        page_tables: &mut crate::page_table::PageTableManager,
        cow_ranges: &[carrick_aarch64::vmm::ForkCowRange],
    ) -> Result<ProcessSpec, TrapError> {
        let plan = self.task.build_process_plan(
            request,
            page_tables,
            cow_ranges,
            std::sync::Arc::clone(&self.mailbox_slots),
            self.syscall_transport,
            std::sync::Arc::clone(&self.carrier_foreign_mm_transport),
        )?;
        Ok(ProcessSpec::new((*self._vm).clone(), plan))
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl HvfTaskState {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn build_process_plan(
        &self,
        request: carrick_hal::ProcessForkRequest,
        page_tables: &mut crate::page_table::PageTableManager,
        cow_ranges: &[carrick_aarch64::vmm::ForkCowRange],
        mailbox_slots: std::sync::Arc<MailboxSlotAllocator>,
        syscall_transport: HvfSyscallTransport,
        carrier_foreign_mm_transport: std::sync::Arc<CarrierForeignMmTransport>,
    ) -> Result<ProcessSpecPlan, TrapError> {
        use carrick_observability::probes::{
            HvpatchForkProcessSpecStage, HvpatchForkProcessSpecStagePhase,
        };

        let child_tid_raw = request.child_tid.raw();
        let forking_tid_raw = request.forking_tid.raw();
        let emit_stage = move |phase: HvpatchForkProcessSpecStagePhase,
                               started: std::time::Instant,
                               units: u64| {
            let elapsed_ns = started.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64;
            crate::probes::hvpatch_fork_process_spec_stage(HvpatchForkProcessSpecStage::new(
                phase,
                child_tid_raw,
                forking_tid_raw,
                elapsed_ns,
                units,
            ));
        };

        crate::probes::hvpatch_fork_snapshot_begin(child_tid_raw, forking_tid_raw);
        let stage_started = std::time::Instant::now();
        const STAGE2_PAGE: u64 = 16 * 1024;
        let root_slot_end = request
            .root_slot_base
            .checked_add(request.root_slot_size)
            .ok_or_else(|| {
                TrapError::Hypervisor("hvpatch child stage-1 root slot overflow".to_owned())
            })?;
        let mut cursor = request.root_slot_base;
        let (alias_revision_begin, aliases) = {
            let registry = alias_registry().lock();
            (
                registry.revision(),
                registry.process_visible_ordered(self.mm_root_slot, self.container_root),
            )
        };
        record_alias_revision(
            CowDiagnosticAliasRevisionSite::ForkSnapshotBegin,
            &carrier_foreign_mm_transport.custody,
            self.cow_identity,
            0,
            alias_revision_begin,
        );
        let alias_index = process_alias_index(&aliases, self.mm_root_slot, self.container_root);
        let mut seen_dynamic_aliases = std::collections::HashSet::new();
        let mut source_mappings: Vec<ThreadMappingDesc> = self
            .mappings
            .iter()
            .filter_map(|mapping| {
                if !mapping.is_dynamic_alias {
                    return Some(ThreadMappingDesc::from_region(mapping));
                }
                let key = (
                    mapping.start,
                    mapping.ipa,
                    mapping.host_addr as usize,
                    semantic_extent_size(mapping.start, mapping.end),
                    mapping.owner_generation,
                );
                if !seen_dynamic_aliases.insert(key) {
                    return None;
                }
                let alias = alias_index.get(&key).copied()?;
                let source = ThreadMappingDesc::from_region(mapping);
                ThreadMappingDesc::from_alias_with_structural_owner(
                    alias,
                    std::slice::from_ref(&source),
                )
            })
            .collect();
        // Fork-union audit: `CARRICK_FORK_DEBUG_VA=<hex guest VA>` reports every
        // LOCAL mapping row covering that VA and whether the alias index kept
        // it. The `[FORKDBG] mapping` block further down only prints rows that
        // already SURVIVED this filter, so a row dropped here — the child then
        // inherits a writable stage-1 leaf onto the parent's frame with nothing
        // arming COW — was previously invisible.
        if let Some(debug_va) = fork_debug_va() {
            let window_lo = debug_va.saturating_sub(0x20_0000);
            let window_hi = debug_va.saturating_add(0x20_0000);
            for alias in aliases.iter().filter(|alias| {
                alias.start < window_hi && alias.start.saturating_add(alias.size as u64) > window_lo
            }) {
                eprintln!(
                    "[UNIONDBG pid={:?}] alias [{:#x}+{:#x}) ipa={:#x} host={:#x} \
                     phys=({:#x}+{:#x}) scope={:?} in_scope={} sharing={:?} writable={} \
                     covers_va={}",
                    self.cow_identity.map(|identity| identity.linux_pid),
                    alias.start,
                    alias.size,
                    alias.ipa,
                    alias.host_addr,
                    alias.physical_ipa,
                    alias.physical_size,
                    alias.ownership_scope,
                    alias_matches_process_scope(
                        alias.ownership_scope,
                        self.mm_root_slot,
                        self.container_root,
                    ),
                    alias.sharing,
                    alias.guest_writable,
                    alias.start <= debug_va
                        && debug_va < alias.start.saturating_add(alias.size as u64),
                );
            }
            for mapping in self
                .mappings
                .iter()
                .filter(|mapping| mapping.start < window_hi && mapping.end > window_lo)
            {
                let kept = mapping_is_current_for_process_fork_indexed(mapping, &alias_index);
                eprintln!(
                    "[UNIONDBG pid={:?}] local row [{:#x},{:#x}) ipa={:#x} host={:p} \
                     size={:#x} sem={:#x} dyn={} sharing={:?} guest_writable={} kept={} \
                     covers_va={}",
                    self.cow_identity.map(|identity| identity.linux_pid),
                    mapping.start,
                    mapping.end,
                    mapping.ipa,
                    mapping.host_addr,
                    mapping.size,
                    semantic_extent_size(mapping.start, mapping.end),
                    mapping.is_dynamic_alias,
                    mapping.sharing,
                    mapping.guest_writable,
                    kept,
                    mapping.start <= debug_va && debug_va < mapping.end,
                );
            }
            let armed = cow_ranges;
            let covering: Vec<_> = armed
                .iter()
                .filter(|range| {
                    range.va <= debug_va && debug_va < range.va.saturating_add(range.len as u64)
                })
                .map(|range| (range.va, range.len))
                .collect();
            eprintln!(
                "[UNIONDBG pid={:?}] fork_cow_ranges covering {debug_va:#x}: {covering:x?} \
                 (total {} ranges)",
                self.cow_identity.map(|identity| identity.linux_pid),
                armed.len(),
            );
        }
        let local_regions = source_mappings.len() as u64;
        // A structural boot mapping can physically contain a narrower semantic
        // alias at the same IPA (the private-overlay aperture is the canonical
        // case). Only an exact current local descriptor suppresses a registry
        // row; keying every local descriptor by IPA hid MAP_FIXED private
        // ownership from fork even though stage-1 already selected it.
        let local_aliases: std::collections::HashSet<ProcessAliasKey> = source_mappings
            .iter()
            .map(thread_mapping_process_alias_key)
            .collect();
        let missing = missing_process_aliases(
            &local_aliases,
            &aliases,
            self.mm_root_slot,
            self.container_root,
        );
        let candidate_regions = missing.len() as u64;
        let mut added_regions = 0_u64;
        let mut added_bytes = 0_u64;
        let mut private_added_regions = 0_u64;
        let mut shared_added_regions = 0_u64;
        let mut largest_added_bytes = 0_u64;
        for alias in missing {
            // The registry is the authoritative live-alias inventory. Scope by
            // mm root-slot scope above and require its retained host owner to be live, but
            // do not require a valid stage-1 leaf: a live PROT_NONE alias is
            // intentionally invalid in stage-1 and still must survive fork.
            if alias_backing_is_live(alias.host_addr)
                && let Some(mapping) =
                    ThreadMappingDesc::from_alias_with_structural_owner(alias, &source_mappings)
            {
                added_regions = added_regions.saturating_add(1);
                added_bytes = added_bytes.saturating_add(mapping.size as u64);
                largest_added_bytes = largest_added_bytes.max(mapping.size as u64);
                if mapping.sharing.shares_across_fork() {
                    shared_added_regions = shared_added_regions.saturating_add(1);
                } else {
                    private_added_regions = private_added_regions.saturating_add(1);
                }
                source_mappings.push(mapping);
            }
        }
        emit_stage(
            HvpatchForkProcessSpecStagePhase::AliasUnion,
            stage_started,
            source_mappings.len() as u64,
        );

        let stage_started = std::time::Instant::now();
        let mut mappings = Vec::with_capacity(source_mappings.len());
        let parent_inventory = self.frame_inventory.lock().extents.clone();
        let mut inventory_mappings = Vec::with_capacity(parent_inventory.len());
        let mut inherited_inventory_ids = std::collections::BTreeSet::new();

        // Put the stage-1 backing at the root slot promised by TTBR. Guest
        // frames retain their stable global IPAs and never enter this slot.
        let mut order: Vec<usize> = (0..source_mappings.len()).collect();
        order.sort_by_key(|&index| {
            u8::from(source_mappings[index].start != crate::memory::LINUX_PAGE_TABLES_BASE)
        });
        // Built once for the whole fork; the per-mapping loop below only
        // queries it. See `ForkOverlayOwnerIndex`.
        // Grouped once for the whole fork and shared by the overlay index and
        // the per-mapping inheritance test below.
        let parent_inventory_by_stage2 = index_fork_inventory_by_stage2(&parent_inventory);
        let overlay_owner_index = ForkOverlayOwnerIndex::build(
            &carrier_foreign_mm_transport.custody,
            &source_mappings,
            &parent_inventory_by_stage2,
        );
        let projection_ranges = std::sync::Arc::clone(request.projection_plan());
        let parent_extension_bases = self
            .page_tables_authority()
            .with_manager(|pt| pt.extension_arena_bases())
            .unwrap_or_default();
        for index in order {
            let mapping = &source_mappings[index];
            if parent_extension_bases.contains(&mapping.start) {
                // Parent extension page-table arenas are Carrick stage-1 backing, not guest VMAs;
                // child extension arenas are allocated and installed into stage-2 below.
                continue;
            }
            let (disposition, wiped_subranges) = match projected_fork_mapping_disposition(
                mapping,
                request.shares_mm(),
                &projection_ranges,
            ) {
                // `MADV_DONTFORK`: the child gets no mapping, no stage-1 leaf
                // and no inventory row here, which is what makes its `mincore`
                // answer ENOMEM the way Linux's does.
                ForkMappingPlan::Omit => continue,
                ForkMappingPlan::Map { disposition, wiped } => (disposition, wiped),
                ForkMappingPlan::PartialOmit => {
                    return Err(TrapError::Hypervisor(format!(
                        "hvpatch fork: MADV_DONTFORK covers only part of the physical mapping \
                         at VA 0x{:x}..0x{:x}; a hole inside one mapping is not representable, \
                         and inheriting it would hand the child memory the guest excluded",
                        mapping.start, mapping.end,
                    )));
                }
            };
            if matches!(
                disposition,
                ForkMappingDisposition::SharedFrameWritable
                    | ForkMappingDisposition::SharedFrameReadOnly
            ) {
                let inherited = inherited_fork_inventory_extents_indexed(
                    &carrier_foreign_mm_transport.custody,
                    mapping,
                    &parent_inventory_by_stage2,
                );
                // Fork lineage debug: CARRICK_FORK_DEBUG_VA=<hex guest VA>
                // prints, for the mapping covering that VA, every inherited
                // extent and — crucially — a mapping DROPPED for having none.
                // Added while hunting a deterministic zeroed 16 KiB granule in
                // a forkserver worker; the drop below is silent by design and
                // was otherwise unobservable.
                if let Some(debug_va) = fork_debug_va()
                    && mapping.start <= debug_va
                    && debug_va < mapping.end
                {
                    eprintln!(
                        "[FORKDBG] mapping [{:#x},{:#x}) ipa={:#x} phys_ipa={:#x} size={:#x} \
                         sharing={:?} dyn={} extents={} phys_host={:p}",
                        mapping.start,
                        mapping.end,
                        mapping.ipa,
                        mapping.physical_ipa,
                        mapping.size,
                        mapping.sharing,
                        mapping.is_dynamic_alias,
                        inherited.len(),
                        mapping.physical_host_addr,
                    );
                    for ((gpa, length), extent) in &inherited {
                        eprintln!(
                            "[FORKDBG]   extent gpa={gpa:#x}+{length:#x} mapping={:?} frame={:?} \
                             backing={:?} lease=({:#x},{:#x})",
                            extent.mapping,
                            extent.frame,
                            extent.backing,
                            extent.stage2_base,
                            extent.stage2_length,
                        );
                    }
                    if inherited.is_empty() {
                        eprintln!(
                            "[FORKDBG]   DROPPED: no inventory extents; child will have NO backing here"
                        );
                    }
                    // Peek the PARENT frame's bytes for the debug granule: if
                    // they are already zero here, the parent reads its data
                    // through some OTHER backing than the frame the child will
                    // inherit — the divergence predates the fork.
                    let frame_offset =
                        (debug_va - mapping.start) + (mapping.ipa - mapping.physical_ipa);
                    let peek = mapping
                        .physical_host_addr
                        .wrapping_add(frame_offset as usize);
                    // SAFETY: debug-only read inside the mapping's live host
                    // backing, bounds-checked against physical_size just below.
                    if (frame_offset as usize) + 16 <= mapping.physical_size {
                        let bytes = unsafe { std::slice::from_raw_parts(peek.cast_const(), 16) };
                        eprintln!(
                            "[FORKDBG]   parent frame bytes @host+{frame_offset:#x}: {bytes:02x?}"
                        );
                    }
                    // The decisive comparison: where does the PARENT's live
                    // stage-1 actually point for this VA, versus where the
                    // inventory says the frame is? A mismatch proves the
                    // divergence the child will inherit.
                    let expected_ipa = mapping.physical_ipa + frame_offset;
                    let walk = self
                        .page_tables_authority()
                        .with_manager(|manager| manager.debug_walk(debug_va));
                    if let Some(w) = walk {
                        let leaf_pa = w[3] & 0x0000_FFFF_FFFF_F000;
                        eprintln!(
                            "[FORKDBG]   parent stage-1 leaf for {debug_va:#x}: {:#x} -> pa {leaf_pa:#x} \
                             (inventory expects {expected_ipa:#x}) {}",
                            w[3],
                            if leaf_pa == expected_ipa & !0xfff {
                                "AGREES"
                            } else {
                                "DIVERGED"
                            },
                        );
                    }
                }
                // A coarse per-vCPU host-owner row may outlive its exact
                // per-mm mapping coverage after every compound in that stage-2
                // lease was repointed. It is no longer a fork source.
                let Some((_, parent_extent)) = inherited.first().copied() else {
                    let live_translation = page_tables
                        .translate(mapping.start)
                        .or_else(|| page_tables.translate_retained_output(mapping.start));
                    if let Some(translated) = live_translation {
                        let physical_ipa = align_down(translated, CowArmedRanges::COMPOUND_SIZE);
                        let owner = global_frame_host_owner_identity_in(
                            &carrier_foreign_mm_transport.custody,
                            physical_ipa,
                            CowArmedRanges::COMPOUND_SIZE,
                        );
                        record_cow_diagnostic_event(CowDiagnosticEvent::Lifecycle {
                            kind: CowDiagnosticLifecycleKind::ForkOmitted,
                            site: CowDiagnosticLifecycleSite::ForkPlan,
                            custody: carrier_foreign_mm_transport.custody.as_ref()
                                as *const CarrierVmCustody
                                as usize,
                            linux_pid: self.cow_identity.map_or(0, |identity| identity.linux_pid),
                            mm: self.cow_identity.map_or(0, |identity| identity.mm),
                            mm_root_slot_base: self.mm_root_slot.map_or(0, |slot| slot.0),
                            semantic_va: mapping.start,
                            semantic_length: mapping.size as u64,
                            logical_gpa: mapping.physical_ipa,
                            logical_length: mapping.physical_size as u64,
                            physical_ipa,
                            physical_length: CowArmedRanges::COMPOUND_SIZE,
                            owner_host_addr: owner.map_or(0, |identity| identity.0),
                            owner_generation: owner.map_or(0, |identity| identity.1),
                            frame: 0,
                            mapping: 0,
                        });
                    }
                    let candidate_translation =
                        thread_mapping_semantic_ipa_at(mapping, mapping.start);
                    let authenticated_overlay = live_translation.is_some_and(|translated| {
                        overlay_owner_index.has_overlay_owner(
                            &source_mappings,
                            index,
                            mapping.start,
                            translated,
                        )
                    });
                    let candidate_matches_live = live_translation == candidate_translation;
                    if fork_mapping_requires_base_translation(
                        mapping.start,
                        mapping.size,
                        mapping.is_dynamic_alias,
                    ) && live_translation.is_some()
                        && (candidate_matches_live || !authenticated_overlay)
                    {
                        if let Some(translated) = live_translation {
                            self.report_physical_cow_source_refusal(
                                &carrier_foreign_mm_transport.custody,
                                mapping.start,
                                translated,
                            );
                        }
                        let alias_revision_refusal = alias_registry().lock().revision();
                        record_alias_revision(
                            CowDiagnosticAliasRevisionSite::ForkSnapshotEnd,
                            &carrier_foreign_mm_transport.custody,
                            self.cow_identity,
                            live_translation
                                .map(|ipa| align_down(ipa, CowArmedRanges::COMPOUND_SIZE))
                                .unwrap_or(0),
                            alias_revision_refusal,
                        );
                        return Err(TrapError::Hypervisor(format!(
                            "hvpatch live fork mapping VA 0x{:x} IPA 0x{:x} has no authenticated inherited inventory extent; live_translation={live_translation:#x?} candidate_translation={candidate_translation:#x?} candidate_matches_live={candidate_matches_live} authenticated_overlay={authenticated_overlay} alias_revision_begin={alias_revision_begin} alias_revision_refusal={alias_revision_refusal}",
                            mapping.start, mapping.physical_ipa,
                        )));
                    }
                    continue;
                };
                let raw = u64::from(mapping.perms);
                let fork_frame_receipt_kind =
                    fork_frame_receipt_kind(disposition, mapping.start, mapping.size);
                for ((gpa, length), extent) in &inherited {
                    let selected = inherited_inventory_ids.insert(extent.mapping);
                    record_cow_inventory_lifecycle(
                        if selected {
                            CowDiagnosticLifecycleKind::ForkSelected
                        } else {
                            CowDiagnosticLifecycleKind::ForkDeduplicated
                        },
                        CowDiagnosticLifecycleSite::ForkPlan,
                        &carrier_foreign_mm_transport.custody,
                        self.cow_identity,
                        self.mm_root_slot,
                        mapping.start,
                        mapping.size as u64,
                        (*gpa, *length),
                        *extent,
                    );
                    if selected {
                        inventory_mappings.push(ProcessInventoryDesc {
                            gpa: *gpa,
                            length: *length,
                            permissions: carrick_hal::MemPerms {
                                read: raw & 1 != 0,
                                write: raw & 2 != 0,
                                exec: raw & 4 != 0,
                            },
                            inherited_frame: Some(extent.frame),
                            inherited_mapping: Some(extent.mapping),
                            backing: extent.backing,
                            stage2_lease: (extent.stage2_base, extent.stage2_length),
                            stage2_owner: extent.stage2_owner,
                            fork_frame_receipt_kind,
                        });
                    }
                }
                mappings.push(ProcessMappingDesc {
                    start: mapping.start,
                    ipa: mapping.ipa,
                    end: mapping.end,
                    host: ProcessMappingHost::Borrowed {
                        pointer: mapping.physical_host_addr,
                        structural_owner: mapping.structural_owner.clone(),
                    },
                    size: mapping.size,
                    physical_ipa: mapping.physical_ipa,
                    physical_host_addr: mapping.physical_host_addr,
                    physical_size: mapping.physical_size,
                    inventory_backing: parent_extent.backing,
                    perms: mapping.perms,
                    is_dynamic_alias: mapping.is_dynamic_alias,
                    sharing: mapping.sharing,
                    guest_writable: mapping.guest_writable,
                    shared_key_base: mapping.shared_key_base,
                    shared_key_offset: mapping.shared_key_offset,
                    inherited_frame: Some(parent_extent.frame),
                    stage2_lease: None,
                    owner_generation: mapping.owner_generation,
                });
                continue;
            }

            const TWO_MIB: u64 = 2 * 1024 * 1024;
            let (physical_ipa, stage2_lease) = match disposition {
                ForkMappingDisposition::IndependentPageTables => {
                    let packing_alignment = if mapping.start.is_multiple_of(TWO_MIB)
                        && (mapping.physical_size as u64) >= TWO_MIB
                    {
                        TWO_MIB
                    } else {
                        STAGE2_PAGE
                    };
                    cursor = align_up(cursor, packing_alignment)?;
                    let physical_ipa = cursor;
                    cursor = cursor
                        .checked_add(mapping.physical_size as u64)
                        .ok_or_else(|| {
                            TrapError::Hypervisor(
                                "hvpatch child page-table root overflow".to_owned(),
                            )
                        })?;
                    if cursor > root_slot_end {
                        return Err(TrapError::Hypervisor(format!(
                            "hvpatch child page tables need more than {}-byte root slot",
                            request.root_slot_size
                        )));
                    }
                    (
                        physical_ipa,
                        Some(GlobalFrameStage2Lease::fixed(
                            physical_ipa,
                            mapping.physical_size as u64,
                        )),
                    )
                }
                ForkMappingDisposition::IndependentKernelState
                | ForkMappingDisposition::IndependentGuestZeroed => {
                    let lease = GlobalFrameStage2Lease::reserve(
                        mapping.physical_size as u64,
                        CowArmedRanges::COMPOUND_SIZE,
                    )?;
                    let physical_ipa = lease.base;
                    (physical_ipa, Some(lease))
                }
                ForkMappingDisposition::SharedFrameWritable
                | ForkMappingDisposition::SharedFrameReadOnly => {
                    return Err(TrapError::Hypervisor(
                        "shared fork mapping escaped inherited-frame branch".to_owned(),
                    ));
                }
            };
            // Per-mm page tables and EL1 control state are the only fresh fork
            // frames.  Both are Carrick kernel state, not the guest-private
            // mappings governed by permission-fault COW.
            let host_kind = match disposition {
                ForkMappingDisposition::IndependentPageTables => {
                    crate::host_mapping::HostMappingKind::PrivateAnon
                }
                ForkMappingDisposition::IndependentKernelState => {
                    crate::host_mapping::HostMappingKind::PerMmKernelState
                }
                ForkMappingDisposition::IndependentGuestZeroed => {
                    crate::host_mapping::HostMappingKind::PrivateAnon
                }
                ForkMappingDisposition::SharedFrameWritable
                | ForkMappingDisposition::SharedFrameReadOnly => {
                    return Err(TrapError::Hypervisor(
                        "shared fork mapping escaped inherited-frame branch".to_owned(),
                    ));
                }
            };
            let host = if disposition == ForkMappingDisposition::IndependentPageTables
                && mapping.physical_size == crate::frame_pool::ROOT_SLOT_SIZE
            {
                if let Some(pool) = carrier_foreign_mm_transport.custody.root_slot_pool() {
                    if let Some(handle) = pool.allocate_slot_at(physical_ipa) {
                        ProcessMappingHost::PooledRootSlot { handle }
                    } else {
                        let owned = crate::host_mapping::OwnedHostMapping::map_shared_anon(
                            mapping.physical_size,
                            host_kind,
                        )
                        .map_err(|error| {
                            TrapError::Hypervisor(format!(
                                "allocate HVPatch child per-mm kernel backing: {error}"
                            ))
                        })?;
                        ProcessMappingHost::Owned(owned)
                    }
                } else {
                    let owned = crate::host_mapping::OwnedHostMapping::map_shared_anon(
                        mapping.physical_size,
                        host_kind,
                    )
                    .map_err(|error| {
                        TrapError::Hypervisor(format!(
                            "allocate HVPatch child per-mm kernel backing: {error}"
                        ))
                    })?;
                    ProcessMappingHost::Owned(owned)
                }
            } else {
                let owned = crate::host_mapping::OwnedHostMapping::map_shared_anon(
                    mapping.physical_size,
                    host_kind,
                )
                .map_err(|error| {
                    TrapError::Hypervisor(format!(
                        "allocate HVPatch child per-mm kernel backing: {error}"
                    ))
                })?;
                ProcessMappingHost::Owned(owned)
            };
            if disposition == ForkMappingDisposition::IndependentGuestZeroed {
                // Seed with the parent's frame, THEN zero the wiped window.
                // `physical_size` can exceed the semantic span, and the extra
                // bytes belong to other aliases of the same frame -- copying
                // first is what keeps them intact while `MADV_WIPEONFORK`
                // still gives the child zeroes exactly where it asked.
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        mapping.physical_host_addr,
                        host.ptr(),
                        mapping.physical_size,
                    );
                }
                let window = mapping
                    .ipa
                    .checked_sub(mapping.physical_ipa)
                    .ok_or_else(|| {
                        TrapError::Hypervisor(format!(
                            "HVPatch wiped alias IPA 0x{:x} precedes physical IPA 0x{:x}",
                            mapping.ipa, mapping.physical_ipa
                        ))
                    })?;
                for (offset, len) in &wiped_subranges {
                    let frame_offset = window.checked_add(*offset).and_then(|start| {
                        usize::try_from(start).ok().filter(|start| {
                            usize::try_from(*len)
                                .ok()
                                .and_then(|len| start.checked_add(len))
                                .is_some_and(|end| end <= mapping.physical_size)
                        })
                    });
                    let (Some(frame_offset), Ok(len)) = (frame_offset, usize::try_from(*len))
                    else {
                        return Err(TrapError::Hypervisor(format!(
                            "HVPatch MADV_WIPEONFORK range +0x{offset:x}+0x{len:x} escapes the \
                             frame at VA 0x{:x} (physical size 0x{:x})",
                            mapping.start, mapping.physical_size
                        )));
                    };
                    // SAFETY: bounds-checked against `physical_size` above, and
                    // `host` is this child's freshly allocated frame.
                    unsafe {
                        std::ptr::write_bytes(host.ptr().add(frame_offset), 0, len);
                    }
                }
            }
            if disposition == ForkMappingDisposition::IndependentKernelState {
                // Preserve the fork boundary's coherent control-state image;
                // child identity/mailbox rebinding mutates this independent
                // frame before entry.  This is a bounded Carrick-kernel copy,
                // never a guest private whole-mapping snapshot.
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        mapping.physical_host_addr,
                        host.ptr(),
                        mapping.physical_size,
                    );
                }
            }
            let semantic_physical_offset = mapping
                .ipa
                .checked_sub(mapping.physical_ipa)
                .ok_or_else(|| {
                    TrapError::Hypervisor(format!(
                        "HVPatch alias IPA 0x{:x} precedes physical IPA 0x{:x}",
                        mapping.ipa, mapping.physical_ipa
                    ))
                })?;
            let ipa = physical_ipa
                .checked_add(semantic_physical_offset)
                .ok_or_else(|| {
                    TrapError::Hypervisor("hvpatch child alias IPA overflow".to_owned())
                })?;
            let mapped = if (crate::memory::LINUX_KERNEL_REGION_BASE
                ..crate::memory::LINUX_KERNEL_REGION_BASE + TWO_MIB)
                .contains(&mapping.start)
            {
                page_tables.map_kernel_aliased(
                    mapping.start,
                    ipa,
                    mapping.end.saturating_sub(mapping.start),
                    None,
                )
            } else {
                page_tables.map_aliased(
                    mapping.start,
                    ipa,
                    mapping.end.saturating_sub(mapping.start),
                    mapping.guest_writable,
                    None,
                )
            };
            mapped.map_err(|error| {
                // Name the pool's own numbers, exactly as `pt_edit_locked` does
                // for the syscall path. "OutOfTables" alone cannot distinguish a
                // legitimately huge address space from a pool the child clone was
                // refused permission to sweep.
                let (in_use, free, capacity, arenas) = page_tables.pool_stats();
                let (multi_vcpu, exclusive, reclaim_policy) = page_tables.coalesce_policy();
                let source = self.page_tables_authority().has_source();
                TrapError::Hypervisor(format!(
                    "map hvpatch child VA 0x{:x} to global/root-slot IPA 0x{ipa:x}: {error:?} \
                     (in_use={in_use} free={free} capacity={capacity} arenas={arenas} source={source} \
                     multi_vcpu={multi_vcpu} exclusive={exclusive} reclaim_pending={reclaim_policy})",
                    mapping.start
                ))
            })?;
            let physical_host_addr = host.ptr();
            let inventory_backing = HvfVmState::private_backing_identity();
            mappings.push(ProcessMappingDesc {
                start: mapping.start,
                ipa,
                end: mapping.end,
                host,
                size: mapping.size,
                physical_ipa,
                physical_host_addr,
                physical_size: mapping.physical_size,
                inventory_backing,
                perms: mapping.perms,
                is_dynamic_alias: mapping.is_dynamic_alias,
                sharing: GuestMappingSharing::Private,
                guest_writable: mapping.guest_writable,
                shared_key_base: mapping.shared_key_base,
                shared_key_offset: mapping.shared_key_offset,
                inherited_frame: None,
                stage2_lease,
                owner_generation: 0,
            });
            inventory_mappings.push(ProcessInventoryDesc {
                gpa: physical_ipa,
                length: mapping.physical_size as u64,
                permissions: {
                    let raw = u64::from(mapping.perms);
                    carrick_hal::MemPerms {
                        read: raw & 1 != 0,
                        write: raw & 2 != 0,
                        exec: raw & 4 != 0,
                    }
                },
                inherited_frame: None,
                inherited_mapping: None,
                backing: inventory_backing,
                stage2_lease: (physical_ipa, mapping.physical_size as u64),
                stage2_owner: InventoryStage2OwnerIdentity {
                    host_addr: physical_host_addr as usize,
                    generation: 0,
                },
                fork_frame_receipt_kind: None,
            });
        }
        emit_stage(
            HvpatchForkProcessSpecStagePhase::FramePlan,
            stage_started,
            cursor.saturating_sub(request.root_slot_base),
        );

        let stage_started = std::time::Instant::now();
        let mut child_pte_receipts = Vec::new();
        // Copied out so the memoizing closures below borrow neither `self`.
        let fork_mm_root_slot = self.mm_root_slot;
        let fork_container_root = self.container_root;
        // Built once for the whole fork; see `ForkTranslationOverlayIndex`.
        let overlay_index =
            ForkTranslationOverlayIndex::build(&mappings, fork_mm_root_slot, fork_container_root);
        for (index, mapping) in mappings.iter().enumerate() {
            let Some(translated) = page_tables
                .translate(mapping.start)
                .or_else(|| page_tables.translate_retained_output(mapping.start))
            else {
                // A live PROT_NONE reservation or post-munmap physical owner
                // intentionally has no valid stage-1 translation. It still
                // belongs in the child's physical/frame inventory and COW-arm
                // registry so a later mprotect/remap cannot expose the parent's
                // frame, but there is no live PTE to authenticate at fork.
                if self.protections.range_no_access(mapping.start, 1)
                    || mapping.is_dynamic_alias
                    || !fork_mapping_requires_base_translation(
                        mapping.start,
                        mapping.size,
                        mapping.is_dynamic_alias,
                    )
                {
                    continue;
                }
                return Err(TrapError::Hypervisor(format!(
                    "hvpatch child stage-1 has no translation for VA 0x{:x}",
                    mapping.start
                )));
            };
            // A completed COW is an overlay on the original physical extent:
            // the old extent must remain in the child inventory for its
            // unaffected leaves, while the newer 16 KiB descriptor owns this
            // particular VA.  Validate against the last applicable overlay,
            // matching the reverse-order syscall-memory lookup authority.
            // Thread-local descriptor vectors and the process alias registry
            // can contribute COW overlays in different orders. The shared
            // stage-1 graph is authoritative, so authenticate its translation
            // against any other exact overlay owner rather than assuming the
            // winning overlay was appended after this descriptor.
            // Answer the overlay question at most ONCE per mapping, and only
            // when a cheaper condition has already failed.
            // `fork_translation_has_overlay_owner` walks every source mapping
            // AND the whole alias registry, so evaluating it eagerly for every
            // mapping made fork O(M * (M + R)) — 14.4% of carrier CPU under a
            // fork/exit storm. Both consumers below reach it only in the
            // uncommon case, so most mappings never pay for it at all.
            let mut overlay_matches: Option<bool> = None;
            if translated != mapping.ipa
                && !*overlay_matches.get_or_insert_with(|| {
                    fork_translation_has_overlay_owner(
                        &overlay_index,
                        &mappings,
                        index,
                        mapping.start,
                        translated,
                    )
                })
            {
                return Err(TrapError::Hypervisor(format!(
                    "hvpatch child stage-1 VA 0x{:x} resolves to IPA 0x{translated:x}, expected 0x{:x}",
                    mapping.start, mapping.ipa
                )));
            }
            if mapping.inherited_frame.is_some()
                && mapping.sharing == GuestMappingSharing::Private
                && !is_kernel_only_stage1_range(mapping.start, mapping.size)
                && !*overlay_matches.get_or_insert_with(|| {
                    fork_translation_has_overlay_owner(
                        &overlay_index,
                        &mappings,
                        index,
                        mapping.start,
                        translated,
                    )
                })
            {
                const VALID: u64 = 1;
                const NON_GLOBAL: u64 = 1 << 11;
                const AP_MASK: u64 = 0b11 << 6;
                const AP_USER_RW: u64 = 0b01 << 6;
                const AP_USER_RO: u64 = 0b11 << 6;
                let leaf = carrick_mem::page_table::terminal_descriptor(
                    page_tables.debug_walk(mapping.start),
                );
                if leaf & VALID != 0 {
                    let expected_ap = if request.shares_mm() {
                        // The descriptor can cover mixed ELF permissions; a
                        // shared-mm child keeps the exact cloned leaf rather
                        // than deriving AP from the coarse physical owner.
                        leaf & AP_MASK
                    } else if mapping.guest_writable && mapping.sharing.shares_across_fork() {
                        AP_USER_RW
                    } else {
                        AP_USER_RO
                    };
                    // CLONE_VM deliberately preserves the parent's exact
                    // user translation, including its global attribute: both
                    // ASIDs name the same frame until the child exits or execs.
                    let expected_non_global = !request.shares_mm();
                    if leaf & AP_MASK != expected_ap
                        || (expected_non_global && leaf & NON_GLOBAL == 0)
                    {
                        return Err(TrapError::Hypervisor(format!(
                            "hvpatch child inherited stage-1 AP mismatch at VA 0x{:x}: leaf=0x{leaf:x} expected_ap=0x{expected_ap:x} expected_non_global={expected_non_global}",
                            mapping.start,
                        )));
                    }
                    child_pte_receipts.push((
                        mapping.start,
                        mapping.ipa,
                        expected_ap,
                        expected_non_global,
                    ));
                }
            }
        }
        emit_stage(
            HvpatchForkProcessSpecStagePhase::Validation,
            stage_started,
            mappings.len() as u64,
        );

        let stage_started = std::time::Instant::now();
        // Borrow the table image; do NOT clone it. The region is
        // `LINUX_PAGE_TABLES_SIZE` = 1.75 MiB, and this runs once per fork, so
        // the clone was 1.75 MiB of allocation plus memcpy on top of the copy
        // into the child's backing below — roughly 238 MiB of pointless copying
        // across the 68 forks of a cold `go build`.
        const TWO_MIB: usize = 2 * 1024 * 1024;
        let child_extension_bases = page_tables.extension_arena_bases();
        for base in &child_extension_bases {
            let (host, physical_host_addr) =
                if let Some(pool) = carrier_foreign_mm_transport.custody.root_slot_pool() {
                    if let Some(handle) = pool.allocate_slot_at(*base) {
                        let ptr = handle.as_mut_ptr();
                        (ProcessMappingHost::PooledRootSlot { handle }, ptr)
                    } else {
                        let owned = crate::host_mapping::OwnedHostMapping::map_shared_anon(
                            TWO_MIB,
                            crate::host_mapping::HostMappingKind::PerMmKernelState,
                        )
                        .map_err(|error| {
                            TrapError::Hypervisor(format!(
                                "allocate HVPatch child extension page-table backing: {error}"
                            ))
                        })?;
                        let ptr = owned.as_ptr();
                        (ProcessMappingHost::Owned(owned), ptr)
                    }
                } else {
                    let owned = crate::host_mapping::OwnedHostMapping::map_shared_anon(
                        TWO_MIB,
                        crate::host_mapping::HostMappingKind::PerMmKernelState,
                    )
                    .map_err(|error| {
                        TrapError::Hypervisor(format!(
                            "allocate HVPatch child extension page-table backing: {error}"
                        ))
                    })?;
                    let ptr = owned.as_ptr();
                    (ProcessMappingHost::Owned(owned), ptr)
                };
            let inventory_backing = HvfVmState::private_backing_identity();
            let stage2_lease = Some(GlobalFrameStage2Lease::fixed(*base, TWO_MIB as u64));
            mappings.push(ProcessMappingDesc {
                start: *base,
                ipa: *base,
                end: *base + TWO_MIB as u64,
                host,
                size: TWO_MIB,
                physical_ipa: *base,
                physical_host_addr,
                physical_size: TWO_MIB,
                inventory_backing,
                perms: applevisor::memory::MemPerms::ReadWrite,
                is_dynamic_alias: false,
                sharing: GuestMappingSharing::Private,
                guest_writable: true,
                shared_key_base: 0,
                shared_key_offset: 0,
                inherited_frame: None,
                stage2_lease,
                owner_generation: 0,
            });
        }

        let table = mappings
            .iter_mut()
            .find(|mapping| mapping.start == crate::memory::LINUX_PAGE_TABLES_BASE)
            .ok_or_else(|| {
                TrapError::Hypervisor("hvpatch child page-table mapping absent".to_owned())
            })?;
        if table.ipa != request.root_slot_base {
            return Err(TrapError::Hypervisor(
                "hvpatch child page-table root-slot layout mismatch".to_owned(),
            ));
        }

        let page_table_resolver = |base: u64| -> Option<*mut u8> {
            mappings
                .iter()
                .find(|m| m.ipa == base)
                .map(|m| m.physical_host_addr)
        };
        unsafe { page_tables.restore_quiesced_snapshot_to_host(page_table_resolver) };
        let copied_bytes = page_tables.copied_bytes();
        for mapping in &mappings {
            if let ProcessMappingHost::PooledRootSlot { ref handle } = mapping.host {
                handle.record_populated_prefix(copied_bytes as usize);
            }
        }

        for (va, expected_ipa, expected_ap, expected_non_global) in child_pte_receipts {
            let shadow = page_tables.debug_walk(va);
            let live =
                unsafe { page_tables.debug_walk_host(page_table_resolver, va) }.map_err(|e| {
                    TrapError::Hypervisor(format!(
                        "child live stage-1 debug_walk_host failed: {e:?}"
                    ))
                })?;
            let live_leaf = carrick_mem::page_table::terminal_descriptor(live);
            if shadow != live
                // An unmodified CLONE_VM graph may retain an L1/L2 block: its
                // descriptor carries the block base, while `expected_ipa`
                // includes the VA's offset inside that block. `shadow == live`
                // plus the earlier software translation receipt authenticates
                // the exact address without falsely applying an L3 mask.
                || (!request.shares_mm()
                    && live_leaf & 0x0000_FFFF_FFFF_F000
                        != expected_ipa & 0x0000_FFFF_FFFF_F000)
                || live_leaf & (0b11 << 6) != expected_ap
                || (expected_non_global && live_leaf & (1 << 11) == 0)
            {
                return Err(TrapError::Hypervisor(format!(
                    "hvpatch child live stage-1 receipt mismatch at VA 0x{va:x}: shadow={shadow:x?} live={live:x?} expected_ipa=0x{expected_ipa:x} expected_ap=0x{expected_ap:x} expected_non_global={expected_non_global}"
                )));
            }
            crate::probes::pt_alias_receipt(va, live_leaf, expected_ipa, expected_ap, 1);
        }
        let table_bytes_len = page_tables.copied_bytes();
        emit_stage(
            HvpatchForkProcessSpecStagePhase::TablePublish,
            stage_started,
            table_bytes_len,
        );

        let alias_revision_end = alias_registry().lock().revision();
        record_alias_revision(
            CowDiagnosticAliasRevisionSite::ForkSnapshotEnd,
            &carrier_foreign_mm_transport.custody,
            self.cow_identity,
            0,
            alias_revision_end,
        );
        crate::probes::hvpatch_fork_snapshot_end(
            request.child_tid.raw(),
            local_regions,
            candidate_regions,
            added_regions,
            added_bytes,
        );
        crate::probes::hvpatch_fork_snapshot_shape(
            request.child_tid.raw(),
            private_added_regions,
            shared_added_regions,
            largest_added_bytes,
            cursor.saturating_sub(request.root_slot_base),
        );

        let stage_started = std::time::Instant::now();
        let protections = std::sync::Arc::new(MemoryProtections::from_snapshot(
            self.protections.snapshot_all(),
        ));
        emit_stage(
            HvpatchForkProcessSpecStagePhase::BackendProtections,
            stage_started,
            0,
        );

        let stage_started = std::time::Instant::now();
        let frame_inventory = {
            let mut parent_inventory = self.frame_inventory.lock();
            let reservation = parent_inventory.process_reservation.take();
            let mut child =
                HvpatchFrameInventory::with_frames(std::sync::Arc::clone(&parent_inventory.frames));
            child.process_reservation = reservation;
            std::sync::Arc::new(parking_lot::Mutex::new(child))
        };
        let mut child_cow_armed = self.cow_armed.lock().clone();
        child_cow_armed.arm(cow_ranges);
        if let Some(debug_va) = fork_debug_va() {
            let covered = child_cow_armed
                .ranges
                .iter()
                .any(|range| debug_va >= range.va && debug_va < range.va + range.len as u64);
            eprintln!(
                "[ARMDBG child-build parent_pid={:?} parent_mm={:?} child_slot={:x} \
                 ranges={} watch_covered={covered}]",
                self.cow_identity.map(|identity| identity.linux_pid),
                self.cow_identity.map(|identity| identity.mm),
                request.root_slot_base,
                child_cow_armed.ranges.len(),
            );
        }
        let plan = ProcessSpecPlan {
            mappings,
            inventory_mappings,
            protections,
            mailbox_slots,
            syscall_transport,
            persistent_vm_lifecycle: self.persistent_vm_lifecycle,
            mm_root_slot: (request.root_slot_base, request.root_slot_size),
            container_root: self.container_root,
            frame_inventory,
            cow_armed: std::sync::Arc::new(parking_lot::Mutex::new(child_cow_armed)),
            carrier_foreign_mm_transport,
        };
        emit_stage(
            HvpatchForkProcessSpecStagePhase::BackendSpecFinalize,
            stage_started,
            0,
        );
        Ok(plan)
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl HvfVmState {
    fn prepare_task_only_process_spec(
        spec: ProcessSpec,
    ) -> Result<(HvpatchCarrierTaskState, HvpatchPreparedTaskAuthority), TrapError> {
        let (vm, plan) = spec.into_plan();
        let (stage2_leases, prepared_task) = Self::prepare_task_only_plan(plan)?;
        Ok((
            HvpatchCarrierTaskState::Process { vm, stage2_leases },
            prepared_task,
        ))
    }

    #[cfg(test)]
    fn prepare_task_only_plan_for_test(
        plan: ProcessSpecPlan,
    ) -> Result<(HvpatchCarrierTaskState, HvpatchPreparedTaskAuthority), TrapError> {
        let (stage2_leases, prepared_task) = Self::prepare_task_only_plan(plan)?;
        Ok((
            HvpatchCarrierTaskState::LeaseTest { stage2_leases },
            prepared_task,
        ))
    }

    fn prepare_task_only_plan(
        plan: ProcessSpecPlan,
    ) -> Result<(Vec<GlobalFrameStage2Lease>, HvpatchPreparedTaskAuthority), TrapError> {
        let mut mapped = Vec::with_capacity(plan.mappings.len());
        let mut stage2_leases = Vec::with_capacity(plan.mappings.len());
        let mut structural_owners = std::collections::BTreeMap::new();
        let mut structural_identities = Vec::new();
        let mut registered_global_owners = Vec::new();
        let inventory_mappings = plan.inventory_mappings;
        let mut pending_aliases = Vec::new();
        let mut pending_receipts = Vec::new();
        let mut mm_root_stage2 = None;
        for mut mapping in plan.mappings {
            let semantic_physical_offset = mapping
                .ipa
                .checked_sub(mapping.physical_ipa)
                .and_then(|offset| usize::try_from(offset).ok())
                .filter(|offset| {
                    offset
                        .checked_add(mapping.size)
                        .is_some_and(|end| end <= mapping.physical_size)
                })
                .ok_or_else(|| {
                    TrapError::Hypervisor(format!(
                        "task-only child alias IPA 0x{:x} escapes physical IPA 0x{:x}",
                        mapping.ipa, mapping.physical_ipa
                    ))
                })?;
            let host_addr = mapping
                .physical_host_addr
                .wrapping_add(semantic_physical_offset);
            let needs_child_alias_authority = process_mapping_needs_child_alias_authority(&mapping);
            if matches!(mapping.host, ProcessMappingHost::PooledRootSlot { .. }) {
                if let Some(lease) = mapping.stage2_lease.as_mut() {
                    lease.mark_pre_mapped();
                }
            } else if process_mapping_needs_stage2_install(mapping.inherited_frame) {
                let rc = unsafe {
                    inventory_hv_vm_map(
                        mapping.physical_host_addr.cast(),
                        mapping.physical_ipa,
                        mapping.physical_size,
                        u64::from(mapping.perms),
                    )
                };
                if rc != 0 {
                    drop(mapping.stage2_lease.take());
                    drop(mapped);
                    report_stage2_map_refusal(
                        &plan.carrier_foreign_mm_transport.custody,
                        mapping.physical_host_addr as usize,
                        mapping.physical_ipa,
                        mapping.physical_size,
                        u64::from(mapping.perms),
                        rc as u32,
                    );
                    let error = TrapError::ChildMapFailed {
                        host_addr: mapping.physical_host_addr as u64,
                        guest_start: mapping.physical_ipa,
                        size: mapping.physical_size,
                        code: rc as u32,
                    };
                    drop(mm_root_stage2.take());
                    if let Err(rollback_error) = rollback_partial_process_stage2_authorities(
                        &plan.carrier_foreign_mm_transport.custody,
                        &mut stage2_leases,
                        &registered_global_owners,
                        &structural_identities,
                        structural_owners,
                    ) {
                        fail_stop_partial_process_stage2_rollback(
                            "task-only mapping composition",
                            &TrapError::Hypervisor(format!(
                                "{error}; exact rollback failed: {rollback_error}"
                            )),
                        );
                    }
                    return Err(error);
                }
                if let Some(lease) = mapping.stage2_lease.as_mut() {
                    lease.mark_mapped();
                }
            }
            let (host_mapping, structural_owner, stage2_lease, owner_generation, owner_role) =
                if is_reusable_global_frame_extent(
                    mapping.physical_ipa,
                    mapping.physical_size as u64,
                ) {
                    match (mapping.stage2_lease.take(), mapping.host) {
                        (Some(lease), ProcessMappingHost::Owned(host_mapping)) => {
                            let owner_generation = register_global_frame_host_owner_in(
                                &plan.carrier_foreign_mm_transport.custody,
                                lease,
                                host_mapping,
                                u64::from(mapping.perms),
                            )?;
                            registered_global_owners.push((
                                mapping.physical_ipa,
                                mapping.physical_size as u64,
                                owner_generation,
                            ));
                            (
                                None,
                                None,
                                None,
                                owner_generation,
                                GlobalFrameOwnerRole::Registered,
                            )
                        }
                        (None, ProcessMappingHost::Borrowed { .. }) => {
                            // A COW/shared reference to a frame whose owner row
                            // another process registered (a forked child's view
                            // of its parent's private frames). The parent's live
                            // generation is preserved for authentication only;
                            // unwinding this preparation must never retire it.
                            (
                                None,
                                None,
                                None,
                                mapping.owner_generation,
                                GlobalFrameOwnerRole::Borrowed,
                            )
                        }
                        (Some(_), ProcessMappingHost::Borrowed { .. }) => {
                            return Err(TrapError::Hypervisor(format!(
                                "HVPatch reusable global-frame mapping at IPA ({:#x}, {:#x}) has stage-2 lease without owned host backing",
                                mapping.physical_ipa, mapping.physical_size
                            )));
                        }
                        (None, ProcessMappingHost::Owned(_)) => {
                            return Err(TrapError::Hypervisor(format!(
                                "HVPatch reusable global-frame mapping at IPA ({:#x}, {:#x}) has owned host backing without stage-2 lease",
                                mapping.physical_ipa, mapping.physical_size
                            )));
                        }
                        (_, ProcessMappingHost::PooledRootSlot { .. }) => {
                            return Err(TrapError::Hypervisor(format!(
                                "HVPatch reusable global-frame mapping at IPA ({:#x}, {:#x}) cannot have pooled root backing",
                                mapping.physical_ipa, mapping.physical_size
                            )));
                        }
                    }
                } else {
                    match mapping.host {
                        ProcessMappingHost::Owned(host) => {
                            let epoch = next_structural_epoch()?;
                            let lease = mapping.stage2_lease.take().ok_or_else(|| {
                                TrapError::Hypervisor(format!(
                                    "structural mapping at IPA 0x{:x} missing stage-2 lease",
                                    mapping.physical_ipa
                                ))
                            })?;
                            let owner = StructuralBackingOwner::new_in(
                                &plan.carrier_foreign_mm_transport.custody,
                                host,
                                lease,
                                u64::from(mapping.perms),
                                epoch,
                                mapping.physical_ipa,
                                mapping.physical_size,
                            )?;
                            let owner_generation = epoch.raw();
                            structural_identities.push(owner.record_identity());
                            structural_owners.insert(
                                (mapping.physical_ipa, mapping.physical_size),
                                std::sync::Arc::clone(&owner),
                            );
                            (
                                None,
                                Some(owner),
                                None,
                                owner_generation,
                                GlobalFrameOwnerRole::Borrowed,
                            )
                        }
                        ProcessMappingHost::PooledRootSlot { handle } => {
                            let epoch = next_structural_epoch()?;
                            let lease = mapping.stage2_lease.take().ok_or_else(|| {
                                TrapError::Hypervisor(format!(
                                    "structural mapping at IPA 0x{:x} missing stage-2 lease",
                                    mapping.physical_ipa
                                ))
                            })?;
                            let owner = StructuralBackingOwner::new_pooled_root_in(
                                &plan.carrier_foreign_mm_transport.custody,
                                handle,
                                lease,
                                u64::from(mapping.perms),
                                epoch,
                                mapping.physical_ipa,
                                mapping.physical_size,
                            )?;
                            let owner_generation = epoch.raw();
                            structural_identities.push(owner.record_identity());
                            structural_owners.insert(
                                (mapping.physical_ipa, mapping.physical_size),
                                std::sync::Arc::clone(&owner),
                            );
                            (
                                None,
                                Some(owner),
                                None,
                                owner_generation,
                                GlobalFrameOwnerRole::Borrowed,
                            )
                        }
                        ProcessMappingHost::Borrowed {
                            pointer,
                            structural_owner,
                        } => {
                            let structural_owner = structural_owner.ok_or_else(|| {
                                TrapError::Hypervisor(format!(
                                    "borrowed structural mapping at IPA 0x{:x} lost its owner",
                                    mapping.physical_ipa
                                ))
                            })?;
                            if structural_owner.ptr() != pointer
                                || structural_owner.physical_ipa != mapping.physical_ipa
                                || structural_owner.physical_size != mapping.physical_size
                                || structural_owner.epoch().raw() != mapping.owner_generation
                            {
                                return Err(TrapError::Hypervisor(format!(
                                    "borrowed structural mapping at IPA 0x{:x} mismatches its exact owner",
                                    mapping.physical_ipa
                                )));
                            }
                            structural_owners.insert(
                                (mapping.physical_ipa, mapping.physical_size),
                                std::sync::Arc::clone(&structural_owner),
                            );
                            (
                                None,
                                Some(structural_owner),
                                mapping.stage2_lease,
                                mapping.owner_generation,
                                GlobalFrameOwnerRole::Borrowed,
                            )
                        }
                    }
                };
            if needs_child_alias_authority {
                let alias = AliasBacking {
                    start: mapping.start,
                    ipa: mapping.ipa,
                    host_addr: host_addr as usize,
                    size: mapping.size,
                    physical_ipa: mapping.physical_ipa,
                    physical_host_addr: mapping.physical_host_addr as usize,
                    physical_size: mapping.physical_size,
                    perms: u64::from(mapping.perms),
                    guest_writable: mapping.guest_writable,
                    sharing: mapping.sharing,
                    ownership_scope: alias_ownership_scope(
                        mapping.sharing,
                        None,
                        plan.container_root,
                    ),
                    inventory_backing: mapping.inventory_backing,
                    shared_key_base: mapping.shared_key_base,
                    shared_key_offset: mapping.shared_key_offset,
                    owner_generation,
                };
                pending_aliases.push(if mapping.sharing.uses_global_ipa() {
                    alias
                } else {
                    rebind_inherited_alias_to_process(alias, plan.mm_root_slot)
                });
            }
            if let Some(lease) = stage2_lease {
                stage2_leases.push(lease);
            }
            if mapping.physical_ipa == plan.mm_root_slot.0 {
                let owner = structural_owner.as_ref().cloned().ok_or_else(|| {
                    TrapError::Hypervisor(
                        "task-only stage-1 root mapping has no structural owner".to_owned(),
                    )
                })?;
                let candidate = MmRootStage2Authority::new(plan.mm_root_slot, owner)?;
                if mm_root_stage2.replace(candidate).is_some() {
                    return Err(TrapError::Hypervisor(
                        "task-only process published duplicate stage-1 root mappings".to_owned(),
                    ));
                }
            }
            mapped.push(HvpatchTaskMappingState {
                start: mapping.start,
                ipa: mapping.ipa,
                physical_ipa: mapping.physical_ipa,
                end: mapping.end,
                host_addr,
                physical_host_addr: mapping.physical_host_addr,
                size: mapping.physical_size,
                physical_size: mapping.physical_size,
                perms: mapping.perms,
                guest_writable: mapping.guest_writable,
                host_mapping,
                structural_owner,
                is_dynamic_alias: mapping.is_dynamic_alias,
                sharing: mapping.sharing,
                shared_key_base: mapping.shared_key_base,
                shared_key_offset: mapping.shared_key_offset,
                owner_generation,
                global_frame_owner_role: owner_role,
            });
        }
        let mut process_reservation = plan
            .frame_inventory
            .lock()
            .process_reservation
            .take()
            .ok_or_else(|| {
                TrapError::Hypervisor(
                    "task-only child has no frame inventory reservation".to_owned(),
                )
            })?;
        let process_transaction = process_reservation.transaction();
        let mut staged_inventory_mappings = Vec::with_capacity(inventory_mappings.len());
        let process_commit;
        {
            let mut inventory = plan.frame_inventory.lock();
            for mapping in inventory_mappings {
                let stage2_owner = if is_reusable_global_frame_extent(mapping.gpa, mapping.length) {
                    let generation = global_frame_host_owner_generation_in(
                        &plan.carrier_foreign_mm_transport.custody,
                        mapping.gpa,
                        mapping.length,
                    );
                    InventoryStage2OwnerIdentity {
                        host_addr: mapping.stage2_owner.host_addr,
                        // If registered in `global_frame_host_owners()` above, use the authoritative
                        // freshly registered owner generation. If generation is 0, this mapping represents
                        // an unowned extent whose generation was already recorded on the descriptor
                        // during preparation rather than a registration failure (which fails fast with Err).
                        generation: if generation != 0 {
                            generation
                        } else {
                            mapping.stage2_owner.generation
                        },
                    }
                } else if let Ok(size) = usize::try_from(mapping.length)
                    && let Some(owner) = structural_owners.get(&(mapping.gpa, size))
                {
                    InventoryStage2OwnerIdentity {
                        host_addr: owner.ptr() as usize,
                        generation: owner.epoch().raw(),
                    }
                } else {
                    mapping.stage2_owner
                };
                let staged = match Self::stage_mapping_in(
                    &plan.carrier_foreign_mm_transport.custody,
                    &mut inventory,
                    &mut process_reservation,
                    InventoryMappingStage {
                        gpa: mapping.gpa,
                        length: mapping.length,
                        permissions: mapping.permissions,
                        backing: mapping.backing,
                        inherited_frame: mapping.inherited_frame,
                        stage2_lease: Some(mapping.stage2_lease),
                        stage2_owner,
                    },
                ) {
                    Ok(staged) => staged,
                    Err(error) => {
                        Self::rollback_unpublished_mappings(
                            &mut inventory,
                            &staged_inventory_mappings,
                        )
                        .unwrap_or_else(|rollback_error| {
                            carrick_fatal!(
                                "hvpatch::frame_inventory",
                                "rollback task-only child inventory: {rollback_error}"
                            )
                        });
                        drop(inventory);
                        drop(mapped);
                        drop(mm_root_stage2.take());
                        let stage2_rollback_error = rollback_partial_process_stage2_authorities(
                            &plan.carrier_foreign_mm_transport.custody,
                            &mut stage2_leases,
                            &registered_global_owners,
                            &structural_identities,
                            structural_owners,
                        )
                        .err();
                        if let Some(rollback_error) = stage2_rollback_error {
                            fail_stop_partial_process_stage2_rollback(
                                "task-only inventory composition",
                                &TrapError::Hypervisor(format!(
                                    "{error}; exact rollback failed: {rollback_error}"
                                )),
                            );
                        }
                        return Err(error);
                    }
                };
                record_cow_inventory_lifecycle(
                    CowDiagnosticLifecycleKind::InventoryPublished,
                    CowDiagnosticLifecycleSite::ForkMaterialization,
                    &plan.carrier_foreign_mm_transport.custody,
                    None,
                    Some(plan.mm_root_slot),
                    0,
                    0,
                    (mapping.gpa, mapping.length),
                    staged,
                );
                staged_inventory_mappings.push(((mapping.gpa, mapping.length), staged));
                if let (Some(parent_mapping), Some(frame), Some(kind)) = (
                    mapping.inherited_mapping,
                    mapping.inherited_frame,
                    mapping.fork_frame_receipt_kind,
                ) {
                    pending_receipts.push(PendingForkFrameReceipt {
                        transaction: process_transaction,
                        kind,
                        parent_mapping,
                        child_mapping: staged.mapping,
                        frame,
                        ipa: mapping.gpa,
                        length: mapping.length,
                    });
                }
            }
            inventory.initialized = true;
            process_commit = process_reservation.commit(());
        }
        let process_challenge = process_commit.receipt_challenge();
        Ok((
            stage2_leases,
            HvpatchPreparedTaskAuthority {
                custody: Some(std::sync::Arc::clone(
                    &plan.carrier_foreign_mm_transport.custody,
                )),
                foreign_mm_transport: Some(std::sync::Arc::clone(
                    &plan.carrier_foreign_mm_transport,
                )),
                mappings: mapped,
                mm_root_slot: Some(plan.mm_root_slot),
                mm_root_stage2,
                container_root: plan.container_root,
                inventory: HvpatchTaskInventoryAuthority::ProcessPrepared {
                    ledger: plan.frame_inventory,
                    staged: staged_inventory_mappings,
                    commit: Some(process_commit),
                    challenge: Some(process_challenge),
                },
                cow_armed: Some(plan.cow_armed),
                // A freshly materialized process has no deferred COW
                // publication yet, but it must own the slot they land in:
                // `from_process_spec` gives the live state the same fresh
                // vector, and arming without one is not a task authority.
                cow_deferred_publications: Some(std::sync::Arc::new(parking_lot::Mutex::new(
                    Vec::new(),
                ))),
                pending_receipts,
                pending_aliases,
                ..HvpatchPreparedTaskAuthority::default()
            },
        ))
    }

    pub(crate) fn from_process_spec(
        spec: ProcessSpec,
    ) -> Result<(HvfVmState, applevisor::vcpu::Vcpu, MailboxBinding), TrapError> {
        let (vm, plan) = spec.into_plan();
        let vcpu = create_vcpu(&vm)?;
        enable_el0_counter_access(vcpu.id());
        let mut mapped = TaskMappingIndex::new();
        let mut structural_owners = std::collections::BTreeMap::new();
        let mut structural_identities = Vec::new();
        let mut registered_global_owners = Vec::new();
        let inventory_mappings = plan.inventory_mappings;
        let mut aliases_to_publish = Vec::new();
        let mut pending_fork_frame_receipts = Vec::new();
        for mut mapping in plan.mappings {
            let semantic_physical_offset = mapping
                .ipa
                .checked_sub(mapping.physical_ipa)
                .and_then(|offset| usize::try_from(offset).ok())
                .filter(|offset| {
                    offset
                        .checked_add(mapping.size)
                        .is_some_and(|end| end <= mapping.physical_size)
                })
                .ok_or_else(|| {
                    TrapError::Hypervisor(format!(
                        "HVPatch semantic alias IPA 0x{:x} size {} escapes physical IPA 0x{:x} size {}",
                        mapping.ipa, mapping.size, mapping.physical_ipa, mapping.physical_size
                    ))
                })?;
            let host_addr = mapping
                .physical_host_addr
                .wrapping_add(semantic_physical_offset);
            let needs_child_alias_authority = process_mapping_needs_child_alias_authority(&mapping);
            if matches!(mapping.host, ProcessMappingHost::PooledRootSlot { .. }) {
                if let Some(lease) = mapping.stage2_lease.as_mut() {
                    lease.mark_pre_mapped();
                }
            } else if process_mapping_needs_stage2_install(mapping.inherited_frame) {
                let rc = unsafe {
                    inventory_hv_vm_map(
                        mapping.physical_host_addr.cast(),
                        mapping.physical_ipa,
                        mapping.physical_size,
                        u64::from(mapping.perms),
                    )
                };
                if rc != 0 {
                    report_stage2_map_refusal(
                        &plan.carrier_foreign_mm_transport.custody,
                        mapping.physical_host_addr as usize,
                        mapping.physical_ipa,
                        mapping.physical_size,
                        u64::from(mapping.perms),
                        rc as u32,
                    );
                    let error = TrapError::ChildMapFailed {
                        host_addr: mapping.physical_host_addr as u64,
                        guest_start: mapping.physical_ipa,
                        size: mapping.physical_size,
                        code: rc as u32,
                    };
                    drop(mapping.stage2_lease.take());
                    let mut prior_stage2_leases = mapped
                        .iter_mut()
                        .filter_map(|mapping| mapping.stage2_lease.take())
                        .collect::<Vec<_>>();
                    drop(mapped);
                    if let Err(rollback_error) = rollback_partial_process_stage2_authorities(
                        &plan.carrier_foreign_mm_transport.custody,
                        &mut prior_stage2_leases,
                        &registered_global_owners,
                        &structural_identities,
                        structural_owners,
                    ) {
                        fail_stop_partial_process_stage2_rollback(
                            "full-VM mapping composition",
                            &TrapError::Hypervisor(format!(
                                "{error}; exact rollback failed: {rollback_error}"
                            )),
                        );
                    }
                    return Err(error);
                }
                if let Some(lease) = mapping.stage2_lease.as_mut() {
                    lease.mark_mapped();
                }
            }
            let (host_mapping, structural_owner, stage2_lease, owner_generation) =
                if is_reusable_global_frame_extent(
                    mapping.physical_ipa,
                    mapping.physical_size as u64,
                ) {
                    match (mapping.stage2_lease.take(), mapping.host) {
                        (Some(lease), ProcessMappingHost::Owned(host_mapping)) => {
                            let owner_generation = register_global_frame_host_owner_in(
                                &plan.carrier_foreign_mm_transport.custody,
                                lease,
                                host_mapping,
                                u64::from(mapping.perms),
                            )?;
                            registered_global_owners.push((
                                mapping.physical_ipa,
                                mapping.physical_size as u64,
                                owner_generation,
                            ));
                            (None, None, None, owner_generation)
                        }
                        (None, ProcessMappingHost::Borrowed { .. }) => {
                            // An unowned reference to an already-registered global frame owner.
                            // The owner_generation stamped on the mapping is preserved.
                            (None, None, None, mapping.owner_generation)
                        }
                        (Some(_), ProcessMappingHost::Borrowed { .. }) => {
                            return Err(TrapError::Hypervisor(format!(
                                "HVPatch reusable global-frame mapping at IPA ({:#x}, {:#x}) has stage-2 lease without owned host backing",
                                mapping.physical_ipa, mapping.physical_size
                            )));
                        }
                        (None, ProcessMappingHost::Owned(_)) => {
                            return Err(TrapError::Hypervisor(format!(
                                "HVPatch reusable global-frame mapping at IPA ({:#x}, {:#x}) has owned host backing without stage-2 lease",
                                mapping.physical_ipa, mapping.physical_size
                            )));
                        }
                        (_, ProcessMappingHost::PooledRootSlot { .. }) => {
                            return Err(TrapError::Hypervisor(format!(
                                "HVPatch reusable global-frame mapping at IPA ({:#x}, {:#x}) cannot have pooled root backing",
                                mapping.physical_ipa, mapping.physical_size
                            )));
                        }
                    }
                } else {
                    match mapping.host {
                        ProcessMappingHost::Owned(host) => {
                            let epoch = next_structural_epoch()?;
                            let lease = mapping.stage2_lease.take().ok_or_else(|| {
                                TrapError::Hypervisor(format!(
                                    "structural mapping at IPA 0x{:x} missing stage-2 lease",
                                    mapping.physical_ipa
                                ))
                            })?;
                            let owner = StructuralBackingOwner::new_in(
                                &plan.carrier_foreign_mm_transport.custody,
                                host,
                                lease,
                                u64::from(mapping.perms),
                                epoch,
                                mapping.physical_ipa,
                                mapping.physical_size,
                            )?;
                            let owner_generation = epoch.raw();
                            structural_identities.push(owner.record_identity());
                            structural_owners.insert(
                                (mapping.physical_ipa, mapping.physical_size),
                                std::sync::Arc::clone(&owner),
                            );
                            (None, Some(owner), None, owner_generation)
                        }
                        ProcessMappingHost::PooledRootSlot { handle } => {
                            let epoch = next_structural_epoch()?;
                            let lease = mapping.stage2_lease.take().ok_or_else(|| {
                                TrapError::Hypervisor(format!(
                                    "structural mapping at IPA 0x{:x} missing stage-2 lease",
                                    mapping.physical_ipa
                                ))
                            })?;
                            let owner = StructuralBackingOwner::new_pooled_root_in(
                                &plan.carrier_foreign_mm_transport.custody,
                                handle,
                                lease,
                                u64::from(mapping.perms),
                                epoch,
                                mapping.physical_ipa,
                                mapping.physical_size,
                            )?;
                            let owner_generation = epoch.raw();
                            structural_identities.push(owner.record_identity());
                            structural_owners.insert(
                                (mapping.physical_ipa, mapping.physical_size),
                                std::sync::Arc::clone(&owner),
                            );
                            (None, Some(owner), None, owner_generation)
                        }
                        ProcessMappingHost::Borrowed {
                            pointer,
                            structural_owner,
                        } => {
                            let structural_owner = structural_owner.ok_or_else(|| {
                                TrapError::Hypervisor(format!(
                                    "borrowed structural mapping at IPA 0x{:x} lost its owner",
                                    mapping.physical_ipa
                                ))
                            })?;
                            if structural_owner.ptr() != pointer
                                || structural_owner.physical_ipa != mapping.physical_ipa
                                || structural_owner.physical_size != mapping.physical_size
                                || structural_owner.epoch().raw() != mapping.owner_generation
                            {
                                return Err(TrapError::Hypervisor(format!(
                                    "borrowed structural mapping at IPA 0x{:x} mismatches its exact owner",
                                    mapping.physical_ipa
                                )));
                            }
                            structural_owners.insert(
                                (mapping.physical_ipa, mapping.physical_size),
                                std::sync::Arc::clone(&structural_owner),
                            );
                            (
                                None,
                                Some(structural_owner),
                                mapping.stage2_lease,
                                mapping.owner_generation,
                            )
                        }
                    }
                };
            if needs_child_alias_authority {
                let alias = AliasBacking {
                    start: mapping.start,
                    ipa: mapping.ipa,
                    host_addr: host_addr as usize,
                    size: mapping.size,
                    physical_ipa: mapping.physical_ipa,
                    physical_host_addr: mapping.physical_host_addr as usize,
                    physical_size: mapping.physical_size,
                    perms: u64::from(mapping.perms),
                    guest_writable: mapping.guest_writable,
                    sharing: mapping.sharing,
                    ownership_scope: alias_ownership_scope(
                        mapping.sharing,
                        None,
                        plan.container_root,
                    ),
                    inventory_backing: mapping.inventory_backing,
                    shared_key_base: mapping.shared_key_base,
                    shared_key_offset: mapping.shared_key_offset,
                    owner_generation,
                };
                aliases_to_publish.push(if mapping.sharing.uses_global_ipa() {
                    alias
                } else {
                    rebind_inherited_alias_to_process(alias, plan.mm_root_slot)
                });
            }
            mapped.insert(HvfMappedRegion {
                start: mapping.start,
                ipa: mapping.ipa,
                physical_ipa: mapping.physical_ipa,
                end: mapping.end,
                host_addr,
                size: mapping.physical_size,
                physical_size: mapping.physical_size,
                perms: mapping.perms,
                guest_writable: mapping.guest_writable,
                memory: None,
                host_mapping,
                structural_owner,
                stage2_lease,
                is_dynamic_alias: mapping.is_dynamic_alias,
                sharing: mapping.sharing,
                shared_key_base: mapping.shared_key_base,
                shared_key_offset: mapping.shared_key_offset,
                owner_generation,
            });
        }
        let mut process_reservation = plan
            .frame_inventory
            .lock()
            .process_reservation
            .take()
            .ok_or_else(|| {
                TrapError::Hypervisor(
                    "HVPatch child materialized without frame inventory reservation".to_owned(),
                )
            })?;
        let process_transaction = process_reservation.transaction();
        let mm_access = MmAccessState::new(
            carrick_aarch64::Stage1Authority::new(),
            plan.protections,
            plan.frame_inventory,
            plan.cow_armed,
            std::sync::Arc::new(parking_lot::Mutex::new(Vec::new())),
        );
        for mapping in &mapped {
            if let Some(owner) = &mapping.structural_owner {
                mm_access.install_structural_mapping_authority(
                    Some(plan.mm_root_slot),
                    std::sync::Arc::clone(owner),
                )?;
            }
        }
        #[cfg(not(test))]
        let custody = std::sync::Arc::clone(&plan.carrier_foreign_mm_transport.custody);
        let mut state = HvfVmState {
            _vm: std::mem::ManuallyDrop::new(vm),
            carrier_foreign_mm_transport: std::sync::Arc::clone(&plan.carrier_foreign_mm_transport),
            task: HvfTaskState {
                #[cfg(not(test))]
                custody,
                mappings: mapped,
                mm_root_slot: Some(plan.mm_root_slot),
                container_root: plan.container_root,
                pending_exec_mm_root_slot: None,
                pending_exec_asid: None,
                pending_exec_predecessor_identity: None,
                pending_exec_stage2_cleanup: None,
                shared_process_mm: false,
                // A copied process receives a fresh MM authority rather than
                // retaining the parent's Arc.
                mm_access,
                last_exit_class: 0,
                last_fault_esr: 0,
                is_forked_child: false,
                forked_no_exec: false,
                last_syscall_nr: None,
                last_syscall_orig_x0: 0,
                live_vcpu: crate::vcpu_kick::LiveVcpuSlot::new(),
                persistent_vm_lifecycle: plan.persistent_vm_lifecycle,
                cow_authority: None,
                cow_identity: None,
                pending_fork_frame_receipts: Vec::new(),
                pending_process_aliases: aliases_to_publish,
                fail_next_begin_exec_inventory: false,
                cow_rollback_scratch: None,
                registration: None,
            },
            carrier_mappings: None,
            reclaim_authority: ReclaimParkAuthority::Live,
            mailbox_slots: plan.mailbox_slots,
            syscall_transport: plan.syscall_transport,
            vcpu_id: vcpu.id(),
            vcpu_handle: vcpu.get_handle(),
            _vcpu_guard: Some(vcpu_census().created()),
        };
        state.publish_live_vcpu();
        let mailbox = match state.allocate_mailbox_for_vcpu(&vcpu) {
            Ok(mailbox) => mailbox,
            Err(error) => {
                // `HvfVmState::drop` intentionally leaks live process mappings.
                // Materialization has not committed, so explicitly drop the
                // fresh RAII leases and host owners instead.
                drop(std::mem::take(&mut state.mappings));
                return Err(error);
            }
        };
        {
            let mut inventory = state.frame_inventory.lock();
            let mut staged_mappings = Vec::with_capacity(inventory_mappings.len());
            for mapping in inventory_mappings {
                let stage2_owner = if is_reusable_global_frame_extent(mapping.gpa, mapping.length) {
                    let generation = global_frame_host_owner_generation_in(
                        &plan.carrier_foreign_mm_transport.custody,
                        mapping.gpa,
                        mapping.length,
                    );
                    InventoryStage2OwnerIdentity {
                        host_addr: mapping.stage2_owner.host_addr,
                        // If registered in `global_frame_host_owners()` above, use the authoritative
                        // freshly registered owner generation. If generation is 0, this mapping represents
                        // an unowned extent whose generation was already recorded on the descriptor
                        // during preparation rather than a registration failure (which fails fast with Err).
                        generation: if generation != 0 {
                            generation
                        } else {
                            mapping.stage2_owner.generation
                        },
                    }
                } else if let Ok(size) = usize::try_from(mapping.length)
                    && let Some(owner) = structural_owners.get(&(mapping.gpa, size))
                {
                    InventoryStage2OwnerIdentity {
                        host_addr: owner.ptr() as usize,
                        generation: owner.epoch().raw(),
                    }
                } else {
                    mapping.stage2_owner
                };
                let staged = match Self::stage_mapping_in(
                    &plan.carrier_foreign_mm_transport.custody,
                    &mut inventory,
                    &mut process_reservation,
                    InventoryMappingStage {
                        gpa: mapping.gpa,
                        length: mapping.length,
                        permissions: mapping.permissions,
                        backing: mapping.backing,
                        inherited_frame: mapping.inherited_frame,
                        stage2_lease: Some(mapping.stage2_lease),
                        stage2_owner,
                    },
                ) {
                    Ok(staged) => staged,
                    Err(error) => {
                        Self::rollback_unpublished_mappings(&mut inventory, &staged_mappings)
                            .unwrap_or_else(|rollback_error| {
                                carrick_fatal!(
                                    "hvpatch::frame_inventory",
                                    "rollback HVPatch child inventory staging: {rollback_error}"
                                )
                            });
                        drop(inventory);
                        for mapping in &state.mappings {
                            if is_reusable_global_frame_extent(
                                mapping.physical_ipa,
                                mapping.physical_size as u64,
                            ) {
                                plan.carrier_foreign_mm_transport
                                    .custody
                                    .global_frame_host_owners
                                    .lock()
                                    .remove(&(mapping.physical_ipa, mapping.physical_size as u64));
                            }
                        }
                        drop(std::mem::take(&mut state.mappings));
                        return Err(error);
                    }
                };
                record_cow_inventory_lifecycle(
                    CowDiagnosticLifecycleKind::InventoryPublished,
                    CowDiagnosticLifecycleSite::ForkMaterialization,
                    &plan.carrier_foreign_mm_transport.custody,
                    None,
                    Some(plan.mm_root_slot),
                    0,
                    0,
                    (mapping.gpa, mapping.length),
                    staged,
                );
                staged_mappings.push(((mapping.gpa, mapping.length), staged));
                if let (Some(parent_mapping), Some(frame), Some(kind)) = (
                    mapping.inherited_mapping,
                    mapping.inherited_frame,
                    mapping.fork_frame_receipt_kind,
                ) {
                    pending_fork_frame_receipts.push(PendingForkFrameReceipt {
                        transaction: process_transaction,
                        kind,
                        parent_mapping,
                        child_mapping: staged.mapping,
                        frame,
                        ipa: mapping.gpa,
                        length: mapping.length,
                    });
                }
            }
            inventory.initialized = true;
            inventory.process_commit = Some(process_reservation.commit(()));
        }
        state.pending_fork_frame_receipts = pending_fork_frame_receipts;
        Ok((state, vcpu, mailbox))
    }

    fn global_frame_exec_plan(&self, plan: &GuestMappingPlan) -> Result<GlobalExecPlan, TrapError> {
        prepare_global_exec_plan(plan, self.pending_exec_mm_root_slot.or(self.mm_root_slot))
    }

    /// `execve(2)` image replacement. Ordinary VMM tears down and rebuilds the
    /// VM; hvpatch retains its one process-wide VM and replaces only stage-2
    /// mappings plus vCPU architectural state. Clears the alias registry and
    /// preserves `is_forked_child`.
    pub(crate) fn execve_rebuild(
        &mut self,
        vcpu: &mut applevisor::vcpu::Vcpu,
        mailbox: &mut MailboxBinding,
        plan: &GuestMappingPlan,
    ) -> Result<(), TrapError> {
        let mut pending_creation = None;
        let result = self.execve_rebuild_inner(vcpu, mailbox, plan, &mut pending_creation);
        finish_pending_vm_creation(pending_creation, result)
    }

    fn execve_rebuild_inner(
        &mut self,
        vcpu: &mut applevisor::vcpu::Vcpu,
        mailbox: &mut MailboxBinding,
        plan: &GuestMappingPlan,
        pending_creation: &mut Option<PendingCarrierVmCreation>,
    ) -> Result<(), TrapError> {
        use applevisor::prelude::*;
        let custody = self.carrier_vm_custody();
        let predecessor_mm_root_slot = self.mm_root_slot;
        let replacement_mm_root_slot = if self.persistent_vm_lifecycle {
            self.pending_exec_mm_root_slot.ok_or_else(|| {
                TrapError::Hypervisor(
                    "HVPatch exec began without a fresh root-slot lease".to_owned(),
                )
            })?
        } else {
            self.mm_root_slot.unwrap_or((0, 0))
        };
        let replacement_asid = if self.persistent_vm_lifecycle {
            self.pending_exec_asid.ok_or_else(|| {
                TrapError::Hypervisor("HVPatch exec began without a fresh ASID lease".to_owned())
            })?
        } else {
            0
        };
        let mut inventory_reservations = if self.persistent_vm_lifecycle {
            let mut inventory = self.frame_inventory.lock();
            // The replacement transaction is mandatory. The retirement one is
            // absent exactly when the old mm stays owned by a live sharer, so
            // its absence here is the armed contract, not a missing reservation.
            let replacement = inventory.replacement_reservation.take().ok_or_else(|| {
                TrapError::Hypervisor(
                    "HVPatch exec began without replacement-mm inventory reservation".to_owned(),
                )
            })?;
            Some((inventory.retired_reservation.take(), replacement))
        } else {
            None
        };
        let frame_plan_started = std::time::Instant::now();
        let GlobalExecPlan {
            plan: mut global_plan,
            mut stage2_leases,
        } = self.global_frame_exec_plan(plan)?;
        self.pending_exec_mm_root_slot = None;
        self.pending_exec_asid = None;
        let frame_plan_elapsed_ns = frame_plan_started
            .elapsed()
            .as_nanos()
            .min(u128::from(u64::MAX)) as u64;
        let replacement_mapping_count = global_plan
            .mappings
            .iter()
            .filter(|mapping| {
                !is_sparse_hvpatch_mmap_mapping(mapping)
                    && !is_persistent_executor_carrier_guest_mapping(mapping)
            })
            .count() as u64;
        let replacement_mapped_bytes = global_plan
            .mappings
            .iter()
            .filter(|mapping| {
                !is_sparse_hvpatch_mmap_mapping(mapping)
                    && !is_persistent_executor_carrier_guest_mapping(mapping)
            })
            .map(|mapping| mapping.mapped_size)
            .sum::<u64>();
        crate::probes::hvpatch_exec_replace_stage(
            carrick_observability::probes::HvpatchExecReplaceStage::new(
                carrick_observability::probes::HvpatchExecReplaceStagePhase::FramePlan,
                frame_plan_elapsed_ns,
                replacement_mapping_count,
                replacement_mapped_bytes,
            ),
        );
        let private_file_artifacts_started = std::time::Instant::now();
        if self.persistent_vm_lifecycle {
            attach_exec_private_file_backings(&mut global_plan)?;
        }
        let private_file_artifacts_elapsed_ns = private_file_artifacts_started
            .elapsed()
            .as_nanos()
            .min(u128::from(u64::MAX)) as u64;
        let plan = &global_plan;
        let map_backings_started = std::time::Instant::now();
        let mut prepared_exec_regions = Vec::new();
        if self.persistent_vm_lifecycle {
            for mapping in plan.mappings.iter().filter(|mapping| {
                !is_sparse_hvpatch_mmap_mapping(mapping)
                    && !is_persistent_executor_carrier_guest_mapping(mapping)
            }) {
                let key = (mapping.ipa_start, mapping.mapped_size);
                let lease = stage2_leases.remove(&key).ok_or_else(|| {
                    TrapError::Hypervisor(format!(
                        "HVPatch exec mapping IPA 0x{:x} size {} has no owning lease",
                        key.0, key.1
                    ))
                })?;
                let region = prepare_exec_region_raw_in(&custody, mapping)?;
                prepared_exec_regions.push((region, lease));
            }
            if !stage2_leases.is_empty() {
                return Err(TrapError::Hypervisor(format!(
                    "HVPatch exec left {} reserved stage-2 leases unmaterialized",
                    stage2_leases.len()
                )));
            }
        }
        let emit_replace_stage =
            |phase: carrick_observability::probes::HvpatchExecReplaceStagePhase,
             started: std::time::Instant| {
                let elapsed_ns = started.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64;
                crate::probes::hvpatch_exec_replace_stage(
                    carrick_observability::probes::HvpatchExecReplaceStage::new(
                        phase,
                        elapsed_ns,
                        replacement_mapping_count,
                        replacement_mapped_bytes,
                    ),
                );
            };
        crate::probes::hvpatch_exec_replace_stage(
            carrick_observability::probes::HvpatchExecReplaceStage::new(
                carrick_observability::probes::HvpatchExecReplaceStagePhase::PrivateFileArtifacts,
                private_file_artifacts_elapsed_ns,
                replacement_mapping_count,
                replacement_mapped_bytes,
            ),
        );
        // Preserve `is_forked_child` across execve. A process that descended from
        // the original `carrick run` invocation should keep using the
        // `_exit`-without-JSON shutdown path even after it execve's into a
        // different image; otherwise every forked + execve'd descendant prints its
        // own JSON report to stdout (interleaved with the parent's), making the
        // user-visible output unreadable.
        let was_forked_child = self.is_forked_child;
        let shared_projection = self.shared_process_mm;
        let address_space_teardown_started = std::time::Instant::now();
        let mut pending_exec_vcpu = None;
        let mut pending_exec_vm = None;
        let retired_physical_extents = if self.persistent_vm_lifecycle {
            // The vCPU is stopped at the execve syscall exit and every sibling
            // has already retired. Build the complete predecessor/replacement
            // edge sets before touching stage-2. The switch helper restores the
            // exact predecessor on every ordinary failure, so backend inventory,
            // owners and mapping rows remain unchanged until this succeeds.
            let authority = self.cow_authority.as_ref().cloned().ok_or_else(|| {
                TrapError::Hypervisor(
                    "HVPatch exec retirement has no frame inventory authority".to_owned(),
                )
            })?;
            let extents =
                final_exec_physical_extents(&self.frame_inventory.lock(), authority.as_ref())?;
            let replacement = plan
                .mappings
                .iter()
                .filter(|mapping| {
                    !is_sparse_hvpatch_mmap_mapping(mapping)
                        && !is_persistent_executor_carrier_guest_mapping(mapping)
                })
                .zip(prepared_exec_regions.iter())
                .map(|(mapping, (region, _))| exec_stage2_install(mapping, region))
                .collect::<Vec<_>>();
            let authority_before = self.exec_authority_fingerprint();
            let switch_result = switch_exec_stage2_transaction(
                &[],
                &replacement,
                exec_stage2_fail_after_maps(),
                |extent| {
                    crate::probes::hvpatch_exec_stage2(
                        carrick_observability::probes::HvpatchExecStage2::new(
                            carrick_observability::probes::HvpatchExecStage2Phase::UnmapBegin,
                            extent.ipa,
                            extent.size as u64,
                            u64::MAX,
                            0,
                        ),
                    );
                    let rc = unsafe { inventory_hv_vm_unmap(extent.ipa, extent.size) };
                    crate::probes::hvpatch_exec_stage2(
                        carrick_observability::probes::HvpatchExecStage2::new(
                            carrick_observability::probes::HvpatchExecStage2Phase::UnmapEnd,
                            extent.ipa,
                            extent.size as u64,
                            u64::MAX,
                            if rc == 0 { 0 } else { -1 },
                        ),
                    );
                    if rc == 0 {
                        Ok(())
                    } else {
                        Err(TrapError::Hypervisor(format!(
                            "unmap HVPatch exec predecessor IPA 0x{:x} size {} failed: 0x{rc:x}",
                            extent.ipa, extent.size
                        )))
                    }
                },
                |extent| {
                    crate::probes::hvpatch_exec_stage2(
                        carrick_observability::probes::HvpatchExecStage2::new(
                            carrick_observability::probes::HvpatchExecStage2Phase::MapBegin,
                            extent.ipa,
                            extent.size as u64,
                            u64::MAX,
                            0,
                        ),
                    );
                    let rc = unsafe {
                        inventory_hv_vm_map(
                            extent.host.cast(),
                            extent.ipa,
                            extent.size,
                            extent.perms,
                        )
                    };
                    if rc == 0
                        && let Some(replay_key) = extent.replay_key()
                    {
                        mutate_external_alias_state(|replay, _| {
                            replay.insert(replay_key);
                        });
                    }
                    crate::probes::hvpatch_exec_stage2(
                        carrick_observability::probes::HvpatchExecStage2::new(
                            carrick_observability::probes::HvpatchExecStage2Phase::MapEnd,
                            extent.ipa,
                            extent.size as u64,
                            u64::MAX,
                            rc as i32,
                        ),
                    );
                    if rc == 0 {
                        Ok(())
                    } else {
                        Err(TrapError::Hypervisor(format!(
                            "map HVPatch exec replacement IPA 0x{:x} size {} failed: 0x{rc:x}",
                            extent.ipa, extent.size
                        )))
                    }
                },
            );
            if let Err(error) = switch_result {
                let authority_after = self.exec_authority_fingerprint();
                if let Err(rollback_error) =
                    verify_exec_authority_rollback(&authority_before, &authority_after)
                {
                    carrick_fatal!("hvpatch::exec_commit", "{rollback_error}");
                }
                return Err(error);
            }
            for (_, lease) in &mut prepared_exec_regions {
                lease.mark_mapped();
            }
            if let Some((Some(retired), _)) = inventory_reservations.as_mut() {
                let authority = self.cow_authority.as_ref().cloned().ok_or_else(|| {
                    TrapError::Hypervisor(
                        "HVPatch exec retirement has no frame inventory authority".to_owned(),
                    )
                })?;
                let mut inventory = self.frame_inventory.lock();
                let diagnostic_extents = if cow_refusal_diagnostics_enabled() {
                    inventory
                        .extents
                        .iter()
                        .map(|(&key, &extent)| (key, extent))
                        .collect::<Vec<_>>()
                } else {
                    Vec::new()
                };
                if let Err(error) =
                    Self::stage_retirement(&mut inventory, retired, authority.as_ref())
                {
                    carrick_fatal!(
                        "hvpatch::frame_inventory",
                        "stage inventory after HVPatch exec unmap: {error}"
                    );
                }
                for (key, extent) in diagnostic_extents {
                    record_cow_inventory_lifecycle(
                        CowDiagnosticLifecycleKind::InventoryRemoved,
                        CowDiagnosticLifecycleSite::ExecRetirement,
                        &self.carrier_foreign_mm_transport.custody,
                        self.cow_identity,
                        self.mm_root_slot,
                        0,
                        0,
                        key,
                        extent,
                    );
                }
            }
            extents
        } else {
            // Mature VMM behavior: tear down the current HVF VM and rebuild it.
            let inherited_vcpu_id = vcpu.id();
            let vcpu_destroy_rc = unsafe { applevisor_sys::hv_vcpu_destroy(inherited_vcpu_id) };
            if vcpu_destroy_rc == 0 {
                self._vcpu_guard = None;
                vcpu_destroyed(inherited_vcpu_id);
            }
            destroy_vm_with_custody(&self.carrier_foreign_mm_transport.custody, "execve_rebuild")?;

            let (new_vm, permit, creation) = create_vm_with_admission(
                VmCreateAdmission::ExecveRebuild,
                &self.carrier_foreign_mm_transport.custody,
            )?;
            let new_vm = SetupVmGuard::new(new_vm, true);
            *pending_creation = Some(creation);
            reconcile_global_frame_owners_after_replay_in(
                &self.carrier_foreign_mm_transport.custody,
                &[],
                true,
            )?;
            let new_vcpu = SetupVcpuGuard::new(
                create_vcpu_with_permit(&new_vm, permit)?,
                SetupVcpuCleanup::PendingRaw,
            );
            let creation = pending_creation.as_mut().ok_or_else(|| {
                TrapError::Hypervisor("exec creation transaction disappeared".to_owned())
            })?;
            creation.record_vcpu(new_vcpu.id());
            enable_el0_counter_access(new_vcpu.id());
            pending_exec_vcpu = Some(new_vcpu);
            pending_exec_vm = Some(new_vm);
            std::collections::BTreeSet::new()
        };
        emit_replace_stage(
            carrick_observability::probes::HvpatchExecReplaceStagePhase::AddressSpaceTeardown,
            address_space_teardown_started,
        );
        // Retain aliases still backed by another live mm. Mature VMM destroyed
        // the whole VM; persistent HVPatch removes only physical extents whose
        // final logical references retired above.
        let alias_cleanup_started = std::time::Instant::now();
        if !self.persistent_vm_lifecycle {
            clear_alias_registry();
        }
        emit_replace_stage(
            carrick_observability::probes::HvpatchExecReplaceStagePhase::AliasCleanup,
            alias_cleanup_started,
        );
        let drop_backings_started = std::time::Instant::now();
        if self.persistent_vm_lifecycle {
            let predecessor_cow_identity = self.cow_identity.ok_or_else(|| {
                TrapError::Hypervisor(
                    "HVPatch exec predecessor cleanup lacks exact COW identity".to_owned(),
                )
            })?;
            let predecessor_identity =
                self.take_exec_predecessor_identity(predecessor_cow_identity)?;
            let predecessor_classification =
                carrick_observability::probes::HvpatchExecPredecessorClassification::new(
                    carrick_observability::probes::HvpatchExecPredecessorClassificationPhase::BackendCaptured,
                    carrick_observability::probes::HvpatchExecPredecessorIdentity::new(
                        predecessor_identity.task_serial,
                        predecessor_identity.thread_serial,
                        predecessor_identity.linux_pid,
                        predecessor_identity.linux_tid,
                        predecessor_cow_identity.mm,
                        u32::from(predecessor_identity.asid),
                    )
                    .map_err(|error| {
                        TrapError::Hypervisor(format!(
                            "construct backend HVPatch exec predecessor identity: {error}"
                        ))
                    })?,
                    shared_projection,
                )
                .map_err(|error| {
                    TrapError::Hypervisor(format!(
                        "construct backend HVPatch exec predecessor classification: {error}"
                    ))
                })?;
            let predecessor_aliases = alias_registry()
                .lock()
                .process_visible_ordered(predecessor_mm_root_slot, self.container_root)
                .into_iter()
                .filter(|alias| {
                    alias_is_owned_by_process(
                        alias.ownership_scope,
                        predecessor_mm_root_slot,
                        self.container_root,
                    )
                })
                .collect::<Vec<_>>();
            let predecessor_mappings = std::mem::take(&mut self.mappings);
            let predecessor_mm_access = if shared_projection {
                None
            } else {
                Some(std::sync::Arc::clone(&self.mm_access))
            };
            let predecessor_frames = std::sync::Arc::clone(&self.frame_inventory.lock().frames);
            let predecessor_extents = retired_physical_extents
                .iter()
                .map(|&(ipa, size)| {
                    let owner = global_frame_host_owner_identity_in(&custody, ipa, size as u64)
                        .map(|(host_addr, generation)| InventoryStage2OwnerIdentity {
                            host_addr,
                            generation,
                        })
                        .or_else(|| {
                            predecessor_mappings
                                .iter()
                                .find(|mapping| {
                                    (mapping.physical_ipa, mapping.physical_size) == (ipa, size)
                                })
                                .and_then(mapped_region_stage2_owner_identity)
                        })
                        .ok_or_else(|| {
                            TrapError::Hypervisor(format!(
                                "HVPatch exec predecessor extent IPA 0x{ipa:x} size {size} has no exact owner identity"
                            ))
                        })?;
                    Ok(((ipa, size), owner))
                })
                .collect::<std::result::Result<
                    std::collections::BTreeMap<_, _>,
                    TrapError,
                >>()?;
            if self
                .pending_exec_stage2_cleanup
                .replace(PendingExecStage2Cleanup {
                    #[cfg(not(test))]
                    custody: std::sync::Arc::clone(&custody),
                    mappings: predecessor_mappings,
                    extents: predecessor_extents,
                    predecessor_aliases,
                    frames: predecessor_frames,
                    mm_root_slot: predecessor_mm_root_slot,
                    mm_access: predecessor_mm_access,
                    predecessor_identity,
                    predecessor_mm: predecessor_cow_identity.mm,
                    shared_projection,
                    armed: true,
                })
                .is_some()
            {
                carrick_fatal!(
                    "hvpatch::exec_commit",
                    "overlapping detached exec predecessor cleanup"
                );
            }
            crate::probes::hvpatch_exec_predecessor_classification(predecessor_classification);
        } else {
            // Preserve mature VMM's historical leak-until-process-exit discipline:
            // the old VM was raw-destroyed and sibling/alias projections may still
            // carry non-owning pointers into these backings.
            std::mem::forget(std::mem::take(&mut self.mappings));
        }
        emit_replace_stage(
            carrick_observability::probes::HvpatchExecReplaceStagePhase::DropBackings,
            drop_backings_started,
        );
        let page_tables_started = std::time::Instant::now();
        self.reclaim_authority = ReclaimParkAuthority::Live;
        self.last_exit_class = 0;
        self.last_fault_esr = 0;
        self.is_forked_child = was_forked_child;
        self.forked_no_exec = false; // execve gives a fresh VM: no longer a live forked-no-exec child
        self.shared_process_mm = false;
        self.pending_fork_frame_receipts.clear();
        self.pending_process_aliases.clear();
        // The shared AArch64 engine already builds this editor lazily from the
        // live page-table backing on its first real edit. Keeping an eager
        // manager here cloned the complete 1.8 MiB root-slot table on every exec,
        // even for short-lived compiler children that never mmap/mprotect.
        // Mailbox publication resolves its static boot mapping directly; an
        // in-process fork below explicitly materializes the manager on demand.
        // The =0 hatch restores the eager clone for schedule-identical ABBA.
        if self.persistent_vm_lifecycle {
            self.mm_root_slot = Some(replacement_mm_root_slot);
        }
        let exec_page_tables = if lazy_exec_page_tables_enabled() {
            None
        } else {
            self.mm_root_slot.and_then(|_| {
                let root = plan.stage1_page_tables_base?;
                let table = plan
                    .mappings
                    .iter()
                    .find(|mapping| mapping.guest_start == crate::memory::LINUX_PAGE_TABLES_BASE)?;
                Some(crate::page_table::PageTableManager::new(
                    table.image.as_ref().clone(),
                    root,
                ))
            })
        };
        // Exec replaces the exact MM authority as one unit. Old protections,
        // stage-1 state, and COW metadata cannot survive independently.
        let protections = std::sync::Arc::new(MemoryProtections::default());
        let cow_armed = std::sync::Arc::new(parking_lot::Mutex::new(CowArmedRanges::default()));
        let cow_deferred_publications = std::sync::Arc::new(parking_lot::Mutex::new(Vec::new()));
        self.mm_access = MmAccessState::new(
            carrick_aarch64::Stage1Authority::new_with_manager(exec_page_tables),
            protections,
            self.frame_inventory.shared_ledger(),
            cow_armed,
            cow_deferred_publications,
        );
        self.seed_readonly_spans_from_plan(plan);
        // Mature one-process VMM exec gets a fresh VM-local allocator. A
        // persistent HVPatch worker must retain its executor-local allocator
        // on the owner pthread; `allocate_mailbox_for_vcpu` below gives the
        // replacement task a fresh slot from that same bounded arena.
        if !self.persistent_vm_lifecycle {
            self.mailbox_slots = std::sync::Arc::new(MailboxSlotAllocator::new());
        }
        self.last_syscall_nr = None;
        self.last_syscall_orig_x0 = 0;
        emit_replace_stage(
            carrick_observability::probes::HvpatchExecReplaceStagePhase::PageTables,
            page_tables_started,
        );

        // Stage-2 is already switched transactionally on HVPatch. Publish its
        // host owners only after predecessor retirement can no longer roll
        // back. Mature VMM still maps through the historical helper here.
        if self.persistent_vm_lifecycle {
            for (mut region, lease) in prepared_exec_regions.drain(..) {
                publish_exec_region_host_owner_in(
                    &custody,
                    &mut region,
                    lease,
                    Some(replacement_mm_root_slot),
                )
                .unwrap_or_else(|error| {
                    carrick_fatal!(
                        "hvpatch::frame_inventory",
                        "publish HVPatch exec global-frame owner: {error}"
                    )
                });
                if let Some(owner) = region.structural_owner.as_ref() {
                    self.mm_access
                        .install_structural_mapping_authority(
                            Some(replacement_mm_root_slot),
                            std::sync::Arc::clone(owner),
                        )
                        .unwrap_or_else(|error| {
                            carrick_fatal!(
                                "hvpatch::mm_authority",
                                "install exec structural MM authority: {error}"
                            )
                        });
                }
                self.mappings.insert(region);
            }
        } else {
            for mapping in &plan.mappings {
                self.mappings
                    .insert(map_region_raw_in(&custody, mapping, false, false)?);
            }
            let replayed =
                replayed_global_frame_owners_for_regions_in(&custody, self.mappings.iter());
            reconcile_global_frame_owners_after_replay_in(&custody, &replayed, false)?;
        }
        if let Some((retired, mut replacement)) = inventory_reservations.take() {
            let staged_inventory_mappings = {
                let mut inventory = self.frame_inventory.lock();
                let mut staged_mappings = Vec::with_capacity(self.mappings.len());
                for region in &self.mappings {
                    let stage2_owner = mapped_region_stage2_owner_identity(region)
                        .unwrap_or_else(|| {
                            carrick_fatal!(
                                "hvpatch::frame_inventory",
                                "HVPatch exec inventory region IPA 0x{:x} has invalid physical owner offset",
                                region.physical_ipa
                            )
                        });
                    let staged = match Self::stage_mapping_in(
                        &custody,
                        &mut inventory,
                        &mut replacement,
                        InventoryMappingStage {
                            gpa: region.physical_ipa,
                            length: region.physical_size as u64,
                            permissions: Self::region_permissions(region),
                            backing: Self::private_backing_identity(),
                            inherited_frame: None,
                            stage2_lease: None,
                            stage2_owner,
                        },
                    ) {
                        Ok(staged) => staged,
                        Err(error) => {
                            carrick_fatal!(
                                "hvpatch::frame_inventory",
                                "stage inventory after HVPatch exec map: {error}"
                            );
                        }
                    };
                    staged_mappings
                        .push(((region.physical_ipa, region.physical_size as u64), staged));
                }
                staged_mappings
            };
            let replacement_commit = replacement.commit(());
            let retired_commit = retired.map(|retired| retired.commit(()));
            let fallback_replacement_commit = if self.registration.is_some() {
                let replacement_challenge = replacement_commit.receipt_challenge();
                let owner_hosts =
                    collect_carrier_stage2_owner_hosts(self.mappings.iter().map(|mapping| {
                        let owner =
                            mapped_region_stage2_owner_identity(mapping).unwrap_or_else(|| {
                                carrick_fatal!(
                                    "hvpatch::frame_inventory",
                                    "exec carrier lease has invalid physical host offset"
                                )
                            });
                        (
                            (mapping.physical_ipa, mapping.physical_size as u64),
                            owner.host_addr,
                        )
                    }))
                    .unwrap_or_else(|error| {
                        carrick_fatal!(
                            "hvpatch::frame_inventory",
                            "collect exec carrier lease owners: {error}"
                        )
                    });
                let mut stage2_leases = Vec::new();
                for region in &mut self.mappings {
                    if let Some(stage2_lease) = region.stage2_lease.take() {
                        stage2_leases.push(stage2_lease);
                    }
                }
                let stage2_lease_keys =
                    register_carrier_stage2_leases(&custody, &mut stage2_leases, &owner_hosts)
                        .unwrap_or_else(|error| {
                            // Replacement inventory already names every candidate.
                            // Fail-stop before unwinding can drop their leases or host
                            // backings out from under that published authority.
                            carrick_fatal!(
                                "hvpatch::frame_inventory",
                                "register carrier stage2 lease for exec: {error}"
                            )
                        });
                let mapped_task_mappings: Vec<HvpatchTaskMappingState> = self
                    .mappings
                    .iter()
                    .map(|mapping| HvpatchTaskMappingState {
                        start: mapping.start,
                        ipa: mapping.ipa,
                        physical_ipa: mapping.physical_ipa,
                        end: mapping.end,
                        host_addr: mapping.host_addr,
                        physical_host_addr: mapping.host_addr,
                        size: mapping.size,
                        physical_size: mapping.physical_size,
                        perms: mapping.perms,
                        guest_writable: mapping.guest_writable,
                        host_mapping: None,
                        structural_owner: mapping.structural_owner.clone(),
                        is_dynamic_alias: mapping.is_dynamic_alias,
                        sharing: mapping.sharing,
                        shared_key_base: mapping.shared_key_base,
                        shared_key_offset: mapping.shared_key_offset,
                        owner_generation: mapping.owner_generation,
                        // Exec re-describes rows this process's live authority
                        // already owns; the replacement never registers them.
                        global_frame_owner_role: GlobalFrameOwnerRole::Borrowed,
                    })
                    .collect();

                let new_authority = HvpatchTaskInventoryAuthority::ProcessPrepared {
                    ledger: std::sync::Arc::clone(&self.frame_inventory.ledger),
                    staged: staged_inventory_mappings,
                    commit: Some(replacement_commit),
                    challenge: Some(replacement_challenge),
                };

                let new_task_mm = std::sync::Arc::new(HvpatchTaskMmAuthority {
                    mappings: mapped_task_mappings,
                    foreign_mm_transport: Some(std::sync::Arc::clone(
                        &self.carrier_foreign_mm_transport,
                    )),
                    mm_root_slot: Some(replacement_mm_root_slot),
                    mm_root_stage2: parking_lot::Mutex::new(None),
                    container_root: self.container_root,
                    inventory: parking_lot::Mutex::new(new_authority),
                    kernel_mm: parking_lot::Mutex::new(None),
                    cow_armed: Some(std::sync::Arc::clone(&self.cow_armed)),
                    cow_deferred_publications: Some(std::sync::Arc::clone(
                        &self.cow_deferred_publications,
                    )),
                    mm_access: parking_lot::Mutex::new(Some(std::sync::Arc::clone(
                        &self.mm_access,
                    ))),
                    pending_publication_receipts: parking_lot::Mutex::new(Vec::new()),
                    pending_receipts: parking_lot::Mutex::new(Vec::new()),
                    alias_receipts: parking_lot::Mutex::new(Vec::new()),
                    last_holder: parking_lot::Mutex::new(HvpatchTaskMmHolder::ExecRebind),
                    #[cfg(test)]
                    drop_order: None,
                });

                let Some(ref mut reg) = self.registration else {
                    carrick_fatal!(
                        "hvpatch::task_backend_lifecycle",
                        "missing registration for HVPatch exec rebind"
                    );
                };
                if let Err(error) = reg.rebind_exec_authority(
                    new_task_mm,
                    replacement_mm_root_slot,
                    stage2_lease_keys,
                    &custody,
                    shared_projection,
                ) {
                    carrick_fatal!(
                        "hvpatch::task_backend_lifecycle",
                        "rebind HVPatch exec MM authority: {error}"
                    );
                }
                None
            } else {
                Some(replacement_commit)
            };
            self.frame_inventory.lock().exec_commits =
                Some((retired_commit, fallback_replacement_commit));
        }
        emit_replace_stage(
            carrick_observability::probes::HvpatchExecReplaceStagePhase::MapBackings,
            map_backings_started,
        );

        // Initial vCPU state — same sequence as `new_with_plan`. Zero the GPRs
        // first: Linux's execve contract says the new program starts with all
        // registers clear except for SP and PC. Without this, musl's _start in the
        // new image inherits the previous process's x8 which can decode as a bogus
        // syscall number on the first svc.
        let active_vcpu = pending_exec_vcpu.as_deref().unwrap_or(vcpu);
        let post_publication = (|| -> std::result::Result<MailboxBinding, TrapError> {
            let registers_started = std::time::Instant::now();
            for reg in GPR_TABLE {
                active_vcpu.set_reg(reg, 0).map_err(hvf_error)?;
            }

            let initial_pc = plan.el0_trampoline_entry.unwrap_or(plan.entry);
            active_vcpu
                .set_reg(Reg::PC, initial_pc)
                .map_err(hvf_error)?;
            const AARCH64_PSTATE_EL1H_DAIF_MASKED: u64 = 0x3c5;
            active_vcpu
                .set_reg(Reg::CPSR, AARCH64_PSTATE_EL1H_DAIF_MASKED)
                .map_err(hvf_error)?;
            if let Some(_trampoline) = plan.el0_trampoline_entry {
                const AARCH64_PSTATE_EL0T_DAIF_MASKED: u64 = 0x3c0;
                active_vcpu
                    .set_sys_reg(SysReg::SPSR_EL1, AARCH64_PSTATE_EL0T_DAIF_MASKED)
                    .map_err(hvf_error)?;
                active_vcpu
                    .set_sys_reg(SysReg::ELR_EL1, plan.entry)
                    .map_err(hvf_error)?;
            }
            // C=1, I=1, UCI=1 (bit 26), UCT=1 (bit 15), DZE=1 (bit 14) — EL0 cache-
            // maintenance ops + CTR_EL0/DCZID_EL0 reads + DC ZVA, matching Linux.
            // See the matching comment at the initial-bringup site; glibc 2.41 reads
            // CTR_EL0 at startup, which traps to EL1 (fatal) without UCT.
            // Shared bootstrap SCTLR (via GuestArch; canonical rationale in
            // carrick_mem::arch_sysregs) carries M=1 (stage-1 on); HVF enables M
            // only when stage-1 tables exist (below), so start from the value with
            // M cleared and OR M back in there. HVF leaves SPAN(23) CLEAR and
            // forces PSTATE.PAN=1 (FEAT_PAN3) — SPAN is KVM glue, NOT part of the
            // shared value.
            use carrick_hal::GuestArch as _;
            let boot = <HvfTrapEngine as carrick_hal::ThreadedEngine>::Arch::bootstrap_sysregs();
            let mut sctlr_el1: u64 = boot.sctlr_el1 & !1;
            if let Some(pt_base) = plan.stage1_page_tables_base {
                active_vcpu
                    .set_sys_reg(SysReg::MAIR_EL1, boot.mair_el1)
                    .map_err(hvf_error)?;
                // 48-bit VA, TTBR0 + TTBR1 both active sharing one root. MUST stay
                // identical to the canonical TCR comment/value in new_with_plan.
                // boot.tcr_el1 is the shared bootstrap value via GuestArch
                // (canonical rationale in carrick_mem::arch_sysregs).
                active_vcpu
                    .set_sys_reg(SysReg::TCR_EL1, boot.tcr_el1)
                    .map_err(hvf_error)?;
                let ttbr = pt_base | (u64::from(replacement_asid) << 48);
                active_vcpu
                    .set_sys_reg(SysReg::TTBR0_EL1, ttbr)
                    .map_err(hvf_error)?;
                // TTBR1 shares the same root (see the TCR comment above).
                active_vcpu
                    .set_sys_reg(SysReg::TTBR1_EL1, ttbr)
                    .map_err(hvf_error)?;
                sctlr_el1 |= 1;
            }
            active_vcpu
                .set_sys_reg(SysReg::SCTLR_EL1, sctlr_el1)
                .map_err(hvf_error)?;
            // boot.cpacr_el1 (FPEN=0b11, no FP/SIMD trap at EL0) is shared.
            active_vcpu
                .set_sys_reg(SysReg::CPACR_EL1, boot.cpacr_el1)
                .map_err(hvf_error)?;
            if let Some(vectors_base) = plan.el1_vectors_base {
                active_vcpu
                    .set_sys_reg(SysReg::VBAR_EL1, vectors_base)
                    .map_err(hvf_error)?;
            }
            if let Some(stack_pointer) = plan.initial_stack_pointer {
                active_vcpu
                    .set_sys_reg(SysReg::SP_EL0, stack_pointer)
                    .map_err(hvf_error)?;
            }
            // execve resets TPIDR_EL0 — the new image's musl init will call
            // set_thread_area to initialise it.
            active_vcpu
                .set_sys_reg(SysReg::TPIDR_EL0, 0)
                .map_err(hvf_error)?;

            // Verify post-execve sysreg state through dtrace. If stage-1 isn't on or
            // TTBR0 doesn't point at the new tables, the new process will fault on the
            // first LDAXR.
            let actual_sctlr = active_vcpu.get_sys_reg(SysReg::SCTLR_EL1).unwrap_or(0);
            let actual_ttbr0 = active_vcpu.get_sys_reg(SysReg::TTBR0_EL1).unwrap_or(0);
            let actual_mair = active_vcpu.get_sys_reg(SysReg::MAIR_EL1).unwrap_or(0);
            emit_replace_stage(
                carrick_observability::probes::HvpatchExecReplaceStagePhase::Registers,
                registers_started,
            );
            crate::probes::execve_sysregs(actual_sctlr, actual_ttbr0, actual_mair);
            self.populate_vdso_data_page();
            self.allocate_mailbox_for_vcpu(active_vcpu)
        })();
        let mailbox_started = std::time::Instant::now();
        *mailbox = post_publication.unwrap_or_else(|error| {
            // Backend inventory and non-owning mapping rows already name these
            // frames. Returning would let `owner_rollback` retire their leases
            // while leaving those authorities published, so the only sound
            // outcome after this indeterminate boundary is process fail-stop.
            carrick_fatal!(
                "hvpatch::exec_commit",
                "HVPatch exec post-publication register/mailbox failure: {error}"
            );
        });
        emit_replace_stage(
            carrick_observability::probes::HvpatchExecReplaceStagePhase::Mailbox,
            mailbox_started,
        );
        if let Some(new_vcpu) = pending_exec_vcpu {
            let new_vm = pending_exec_vm.take().ok_or_else(|| {
                TrapError::Hypervisor(
                    "exec VM disappeared before committed vCPU handoff".to_owned(),
                )
            })?;
            commit_pending_creation_before_vcpu_handoff(pending_creation)?;
            self._vcpu_guard = Some(vcpu_census().created());
            self.vcpu_id = new_vcpu.id();
            self.vcpu_handle = new_vcpu.get_handle();
            self.publish_live_vcpu();
            std::mem::forget(std::mem::replace(vcpu, new_vcpu.into_inner()));
            replace_destroyed_vm(self, new_vm.into_inner());
        }
        Ok(())
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl HvfInner {
    /// Snapshot every register the trap engine ever writes, reading from the
    /// passed `vcpu`. Gated like the signal path on `fpsimd_save_enabled()`. The
    /// shared engine's `Aarch64Vcpu::snapshot` calls this; `last_exit_class` is
    /// owned by the engine, so the snapshot carries 0 for it.
    pub(crate) fn snapshot_vcpu_from(
        vcpu: &applevisor::vcpu::Vcpu,
    ) -> Result<VcpuSnapshot, TrapError> {
        use applevisor::prelude::*;
        let mut gprs = [0u64; 31];
        for (i, reg) in GPR_TABLE.iter().enumerate() {
            gprs[i] = vcpu.get_reg(*reg).map_err(hvf_error)?;
        }
        // V0-V31 + FPSR/FPCR (audit M2): preserved across fork/clone so the
        // vector file survives the vCPU rebuild. Gated like the signal path.
        let mut vregs = [0u128; 32];
        let (mut fpsr, mut fpcr) = (0u32, 0u32);
        if fpsimd_save_enabled() {
            for (i, reg) in SIMD_FP_TABLE.iter().enumerate() {
                vregs[i] = vcpu.get_simd_fp_reg(*reg).map_err(hvf_error)?;
            }
            fpsr = vcpu.get_reg(Reg::FPSR).map_err(hvf_error)? as u32;
            fpcr = vcpu.get_reg(Reg::FPCR).map_err(hvf_error)? as u32;
        }
        let sp_el0 = vcpu.get_sys_reg(SysReg::SP_EL0).map_err(hvf_error)?;
        let sp_el1 = vcpu.get_sys_reg(SysReg::SP_EL1).map_err(hvf_error)?;
        Ok(VcpuSnapshot {
            core: Aarch64VcpuSnapshot {
                gprs,
                pc: vcpu.get_reg(Reg::PC).map_err(hvf_error)?,
                pstate: vcpu.get_reg(Reg::CPSR).map_err(hvf_error)?,
                sp_el0,
                // SP_EL1 is the per-vCPU syscall-mailbox address. Rebuild paths
                // refresh it from the binding after restoring this snapshot.
                sp_el1,
                elr_el1: vcpu.get_sys_reg(SysReg::ELR_EL1).map_err(hvf_error)?,
                spsr_el1: vcpu.get_sys_reg(SysReg::SPSR_EL1).map_err(hvf_error)?,
                ttbr0: vcpu.get_sys_reg(SysReg::TTBR0_EL1).map_err(hvf_error)?,
                ttbr1: vcpu.get_sys_reg(SysReg::TTBR1_EL1).map_err(hvf_error)?,
                tcr: vcpu.get_sys_reg(SysReg::TCR_EL1).map_err(hvf_error)?,
                sctlr: vcpu.get_sys_reg(SysReg::SCTLR_EL1).map_err(hvf_error)?,
                mair: vcpu.get_sys_reg(SysReg::MAIR_EL1).map_err(hvf_error)?,
                vbar: vcpu.get_sys_reg(SysReg::VBAR_EL1).map_err(hvf_error)?,
                cpacr: vcpu.get_sys_reg(SysReg::CPACR_EL1).map_err(hvf_error)?,
                cntkctl_el1: vcpu.get_sys_reg(SysReg::CNTKCTL_EL1).map_err(hvf_error)?,
                tpidr_el0: vcpu.get_sys_reg(SysReg::TPIDR_EL0).map_err(hvf_error)?,
                tpidrro_el0: vcpu.get_sys_reg(SysReg::TPIDRRO_EL0).map_err(hvf_error)?,
                tpidr_el1: vcpu.get_sys_reg(SysReg::TPIDR_EL1).map_err(hvf_error)?,
                contextidr_el1: vcpu
                    .get_sys_reg(SysReg::CONTEXTIDR_EL1)
                    .map_err(hvf_error)?,
                actlr_el1: vcpu.get_sys_reg(SysReg::ACTLR_EL1).map_err(hvf_error)?,
                vregs,
                fpsr,
                fpcr,
            },
        })
    }

    /// Restore `snap` onto the passed `vcpu` for reclaim/executor rebinding.
    pub(crate) fn restore_vcpu_into(
        vcpu: &mut applevisor::vcpu::Vcpu,
        snap: &VcpuSnapshot,
    ) -> Result<(), TrapError> {
        use applevisor::prelude::*;
        for (reg, value) in GPR_TABLE.iter().zip(snap.core.gprs.iter()) {
            vcpu.set_reg(*reg, *value).map_err(hvf_error)?;
        }
        vcpu.set_reg(Reg::PC, snap.core.pc).map_err(hvf_error)?;
        vcpu.set_reg(Reg::CPSR, snap.core.pstate)
            .map_err(hvf_error)?;
        vcpu.set_sys_reg(SysReg::SP_EL0, snap.core.sp_el0)
            .map_err(hvf_error)?;
        // Order matters: program TCR/MAIR/TTBR0 before flipping SCTLR.M.
        vcpu.set_sys_reg(SysReg::MAIR_EL1, snap.core.mair)
            .map_err(hvf_error)?;
        vcpu.set_sys_reg(SysReg::TCR_EL1, snap.core.tcr)
            .map_err(hvf_error)?;
        vcpu.set_sys_reg(SysReg::TTBR0_EL1, snap.core.ttbr0)
            .map_err(hvf_error)?;
        // TTBR1 (upper-half, x86-64 high half under Rosetta) and ACTLR (EnTSO)
        // are part of the guest's live state; the captured TCR enables TTBR1, so
        // restoring TTBR0 alone would leave TTBR1 walking from base 0 and lose
        // hardware TSO — both required for the post-fork/clone guest to run.
        vcpu.set_sys_reg(SysReg::TTBR1_EL1, snap.core.ttbr1)
            .map_err(hvf_error)?;
        vcpu.set_sys_reg(SysReg::ACTLR_EL1, snap.core.actlr_el1)
            .map_err(hvf_error)?;
        vcpu.set_sys_reg(SysReg::CPACR_EL1, snap.core.cpacr)
            .map_err(hvf_error)?;
        vcpu.set_sys_reg(SysReg::CNTKCTL_EL1, snap.core.cntkctl_el1)
            .map_err(hvf_error)?;
        vcpu.set_sys_reg(SysReg::VBAR_EL1, snap.core.vbar)
            .map_err(hvf_error)?;
        vcpu.set_sys_reg(SysReg::SPSR_EL1, snap.core.spsr_el1)
            .map_err(hvf_error)?;
        vcpu.set_sys_reg(SysReg::ELR_EL1, snap.core.elr_el1)
            .map_err(hvf_error)?;
        vcpu.set_sys_reg(SysReg::TPIDR_EL0, snap.core.tpidr_el0)
            .map_err(hvf_error)?;
        // TPIDRRO_EL0 (guest-readable thread ptr), TPIDR_EL1 (the shim's x16
        // scratch) and CONTEXTIDR_EL1 (carrick's fast-`gettid` tid stamp) are all
        // zeroed by hv_vcpu_create, so a rebuilt vCPU (fork/clone or a
        // destroy/recreate reclaim) must restore each. CONTEXTIDR_EL1 is the one
        // that is guest-VISIBLE through `gettid`: miss it and the EL1 handler
        // reads 0 and degrades to a host round trip for the rest of the thread's
        // life. (The tid lived in TPIDR_EL1 before it was moved here to free that
        // register as the scratch; restoring only TPIDR_EL1 preserved a value that
        // means nothing across a park and dropped the one that does.)
        vcpu.set_sys_reg(SysReg::TPIDRRO_EL0, snap.core.tpidrro_el0)
            .map_err(hvf_error)?;
        vcpu.set_sys_reg(SysReg::TPIDR_EL1, snap.core.tpidr_el1)
            .map_err(hvf_error)?;
        vcpu.set_sys_reg(SysReg::CONTEXTIDR_EL1, snap.core.contextidr_el1)
            .map_err(hvf_error)?;
        // Apply SCTLR last so the MMU enable lands with the new tables.
        vcpu.set_sys_reg(SysReg::SCTLR_EL1, snap.core.sctlr)
            .map_err(hvf_error)?;
        // Restore V0-V31 + FPSR/FPCR via the C shim (NOT applevisor's
        // set_simd_fp_reg, which zeroes via the wrong register class). (audit M2)
        if fpsimd_save_enabled() {
            let vcpu_id = vcpu.id();
            for (i, reg) in SIMD_FP_TABLE.iter().enumerate() {
                let rc = set_simd_fp_reg_v(vcpu_id, *reg, snap.core.vregs[i]);
                if rc != 0 {
                    return Err(TrapError::Hypervisor(format!(
                        "fork restore set_simd_fp_reg(q{i}) failed: rc={rc:#x}"
                    )));
                }
            }
            vcpu.set_reg(Reg::FPSR, u64::from(snap.core.fpsr))
                .map_err(hvf_error)?;
            vcpu.set_reg(Reg::FPCR, u64::from(snap.core.fpcr))
                .map_err(hvf_error)?;
        }
        Ok(())
    }

    /// Seed a BRAND-NEW sibling vCPU (a `clone(CLONE_THREAD)` thread) so it enters
    /// EL0 at the child's resume PC. Unlike [`restore_vcpu_into`] (used by fork,
    /// whose vCPU had already done the boot trampoline `eret` into EL0 and merely
    /// resumes), a freshly created vCPU has never transitioned to EL0. We therefore
    /// start it at the EL0 trampoline page (in EL1h) with `SPSR_EL1=EL0t` and
    /// `ELR_EL1=snap.core.pc`, so the trampoline's single `eret` drops the vCPU into EL0
    /// at exactly the post-clone instruction — mirroring `map_plan`'s initial-boot
    /// sequence but with thread-private PC/SP/TLS. (The engine's `restore_thread_start`
    /// routes here for HVF; `last_exit_class` is engine-owned and not restored here.)
    pub(crate) fn restore_vcpu_thread_start_into(
        vcpu: &mut applevisor::vcpu::Vcpu,
        snap: &VcpuSnapshot,
    ) -> Result<(), TrapError> {
        use applevisor::prelude::*;
        for (reg, value) in GPR_TABLE.iter().zip(snap.core.gprs.iter()) {
            vcpu.set_reg(*reg, *value).map_err(hvf_error)?;
        }
        // Start at the EL0 trampoline page in EL1h; the trampoline `eret`s into EL0t
        // at ELR_EL1 with SPSR_EL1's PSTATE.
        const AARCH64_PSTATE_EL1H_DAIF_MASKED: u64 = 0x3c5;
        const AARCH64_PSTATE_EL0T_DAIF_MASKED: u64 = 0x3c0;
        vcpu.set_reg(Reg::PC, crate::memory::LINUX_EL0_TRAMPOLINE_BASE)
            .map_err(hvf_error)?;
        vcpu.set_reg(Reg::CPSR, AARCH64_PSTATE_EL1H_DAIF_MASKED)
            .map_err(hvf_error)?;
        vcpu.set_sys_reg(SysReg::SPSR_EL1, AARCH64_PSTATE_EL0T_DAIF_MASKED)
            .map_err(hvf_error)?;
        // The child's EL0 resume PC (snap.core.pc == parent ELR_EL1 == post-svc).
        vcpu.set_sys_reg(SysReg::ELR_EL1, snap.core.pc)
            .map_err(hvf_error)?;
        vcpu.set_sys_reg(SysReg::SP_EL0, snap.core.sp_el0)
            .map_err(hvf_error)?;
        // Same translation regime as the parent (shared address space).
        vcpu.set_sys_reg(SysReg::MAIR_EL1, snap.core.mair)
            .map_err(hvf_error)?;
        vcpu.set_sys_reg(SysReg::TCR_EL1, snap.core.tcr)
            .map_err(hvf_error)?;
        vcpu.set_sys_reg(SysReg::TTBR0_EL1, snap.core.ttbr0)
            .map_err(hvf_error)?;
        // TTBR1 (upper-half, x86-64 high half under Rosetta) and ACTLR (EnTSO) are
        // part of the guest's live state; the captured TCR enables TTBR1, so restoring
        // TTBR0 alone would leave TTBR1 walking from base 0 and lose hardware TSO —
        // both required for the post-clone guest to run.
        vcpu.set_sys_reg(SysReg::TTBR1_EL1, snap.core.ttbr1)
            .map_err(hvf_error)?;
        vcpu.set_sys_reg(SysReg::ACTLR_EL1, snap.core.actlr_el1)
            .map_err(hvf_error)?;
        vcpu.set_sys_reg(SysReg::CPACR_EL1, snap.core.cpacr)
            .map_err(hvf_error)?;
        vcpu.set_sys_reg(SysReg::CNTKCTL_EL1, snap.core.cntkctl_el1)
            .map_err(hvf_error)?;
        vcpu.set_sys_reg(SysReg::VBAR_EL1, snap.core.vbar)
            .map_err(hvf_error)?;
        vcpu.set_sys_reg(SysReg::TPIDR_EL0, snap.core.tpidr_el0)
            .map_err(hvf_error)?;
        // CONTEXTIDR_EL1 is deliberately LEFT ZERO here: a new thread must not
        // inherit the parent's tid stamp. Zero is the fail-safe — the EL1
        // `gettid` handler's degrade branch traps to the host and returns the
        // correct tid — whereas a stale parent tid would be returned silently
        // and WRONG if the caller's re-stamp ever failed to run.
        // SP_EL1 was already set to this sibling's mailbox by materialization.
        // The trampoline does not touch it before `eret` enters EL0.
        // Enable the MMU last, identically to the parent.
        vcpu.set_sys_reg(SysReg::SCTLR_EL1, snap.core.sctlr)
            .map_err(hvf_error)?;
        // A new fork/clone vCPU starts with zeroed SIMD/FP state. Preserve the
        // captured V0-V31 + FPSR/FPCR just as the ordinary restore path does;
        // otherwise a raw clone loses live vector state in the child.
        if fpsimd_save_enabled() {
            let vcpu_id = vcpu.id();
            for (i, reg) in SIMD_FP_TABLE.iter().enumerate() {
                let rc = set_simd_fp_reg_v(vcpu_id, *reg, snap.core.vregs[i]);
                if rc != 0 {
                    return Err(TrapError::Hypervisor(format!(
                        "thread-start restore set_simd_fp_reg(q{i}) failed: rc={rc:#x}"
                    )));
                }
            }
            vcpu.set_reg(Reg::FPSR, u64::from(snap.core.fpsr))
                .map_err(hvf_error)?;
            vcpu.set_reg(Reg::FPCR, u64::from(snap.core.fpcr))
                .map_err(hvf_error)?;
        }
        Ok(())
    }

    /// Run the passed `vcpu` to its next exit, decoding HVF's native trap surface
    /// into the neutral [`carrick_aarch64::Aarch64Exit`]. The old
    /// `run_until_syscall` exit decode, returning `Aarch64Exit` instead of an
    /// `Option<Aarch64SyscallFrame>` — the shared engine owns the
    /// pending-syscall/SA_RESTART state, the guest-CPU accounting and the
    /// EL1-maintenance loop, so this surfaces
    /// `Syscall`/`EL0Fault`/`MaintenanceDone`/`Kicked`, keeps the internal
    /// kick-swallow + the bounded in-loop lazy alias re-map, and services the
    /// sys64 MRS read inline (a loop `continue`).
    pub(crate) fn run_to_exit(
        vcpu: &mut applevisor::vcpu::Vcpu,
        mailbox: &mut MailboxBinding,
    ) -> Result<carrick_aarch64::Aarch64Exit, TrapError> {
        use applevisor::prelude::*;
        use carrick_aarch64::Aarch64Exit;

        // Lifecycle marker: the first entry here is the moment the guest first
        // runs — i.e. INITIAL boot/setup is done. Fired once per process; since
        // carrick forks via no-exec `libc::fork`, a forked child inherits the
        // parent's already-completed Once and does NOT re-fire this.
        static FIRST_RUN: std::sync::Once = std::sync::Once::new();
        FIRST_RUN.call_once(|| crate::probes::lifecycle(crate::probes::phase::FIRST_VCPU_RUN));

        // Bounds lazy re-mapping of dropped aliases so a
        // genuinely-unmappable backing still terminates instead of spinning.
        let mut alias_remap_limiter = AliasRemapLimiter::default();
        loop {
            // The engine accounts the guest CPU time via `guest_cpu::timed_run`
            // around its `vcpu.run()` call, so do NOT double-account here.
            vcpu.run().map_err(hvf_error)?;
            let exit = vcpu.get_exit_info();
            if exit.reason == ExitReason::CANCELED {
                // A cross-thread `hv_vcpus_exit` (crate::vcpu_kick) forced this
                // vCPU out of the guest so a pending signal can be delivered.
                //
                // But the kick can land while the vCPU is still inside carrick's
                // EL1 trap trampoline — a guest EL0 `svc`/fault is mid-flight,
                // between the vector entry (VBAR_EL1 = vectors_base, e.g. the
                // sync-from-EL0 entry at +0x400) and the HVC that traps out to
                // the host. PC there is an EL1 trampoline address, NOT a guest
                // userspace PC. Reporting that as a deliverable kick overwrites
                // the in-flight exception and wedges the thread — reproduced as a
                // SIGURG storm corrupting a futex waiter (pc=vectors_base+0x404).
                //
                // Resume until the guest is back at EL0 so the trampoline
                // completes its HVC and the real syscall is serviced; the
                // pending signal is then delivered at that clean EL0 boundary.
                let cpsr = vcpu.get_reg(Reg::CPSR).map_err(hvf_error)?;
                if !ExecLevel::from_pstate(cpsr).is_guest() {
                    EL1_KICK_RESUMED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    crate::probes::kick_in_kernel(
                        vcpu.get_reg(Reg::PC).unwrap_or(0),
                        ((cpsr >> 2) & 0b11) as u32,
                    );
                    continue;
                }
                return Ok(Aarch64Exit::Kicked);
            }
            // A direct EL0 abort on a high-VA alias address that THIS vCPU's
            // shared VM is missing: a `fork()` rebuilt the shared VM from only the
            // forking thread's mappings, dropping an alias mapped by
            // a sibling thread (the go-build telemetry counter). arm64 HVF has no
            // stage-2 TLB shootdown, so re-running alone never fixes it — but the
            // host backing is a MAP_SHARED mmap still live at the registered host
            // address, so re-`hv_vm_map`'ing it into THIS (shared) VM restores the
            // stage-2 entry for every thread, and the instruction re-executes
            // cleanly. Only registered aliases are touched, so a genuine bad
            // access to unregistered memory still faults. Bounded as a backstop.
            // (Kept INSIDE run_to_exit, NOT surfaced as Aarch64Exit::Memory — the
            // in-loop remap is the safe, behavior-identical choice.)
            if exit.reason == ExitReason::EXCEPTION
                && is_aarch64_el0_abort_exception(exit.exception.syndrome)
                && crate::memory::is_high_va(exit.exception.virtual_address)
            {
                let backing = if exit.exception.physical_address != 0 {
                    lookup_shared_alias(exit.exception.physical_address)
                } else {
                    lookup_live_alias_by_va_any_scope(exit.exception.virtual_address, 1)
                };
                if let Some(b) = backing
                    && alias_remap_limiter.allow(b.physical_ipa)
                {
                    // SAFETY: `host_addr` is a live MAP_SHARED mmap registered
                    // by add_alias. Only rc=0 proves replay installation.
                    let rc = unsafe { inventory_hv_vm_map_replay(b) };
                    crate::probes::hv_vm_map_alias(
                        exit.exception.virtual_address,
                        b.physical_ipa,
                        b.physical_size as u64,
                        rc as i32,
                        0,
                    );
                    if rc != 0 {
                        return Err(TrapError::Hypervisor(format!(
                            "lazy alias replay hv_vm_map(ipa=0x{:x}, size={}) failed: 0x{rc:x}",
                            b.physical_ipa, b.physical_size
                        )));
                    }
                    // Diagnostic-only alias-remap counter+dump, gated behind
                    // `debug-stats` (no other consumer reads the counter).
                    #[cfg(feature = "debug-stats")]
                    {
                        let n =
                            ALIAS_REMAP_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        if n.is_multiple_of(256) {
                            eprintln!("ALIAS_REMAP n={n} ipa=0x{:x}", b.physical_ipa);
                        }
                    }
                    continue;
                }
            }
            if exit.reason != ExitReason::EXCEPTION {
                // WFI/halt or any non-EXCEPTION non-CANCELED exit that today
                // errored: keep erroring.
                return Err(TrapError::UnexpectedExit {
                    reason: format!("{:?}", exit.reason),
                });
            }

            let exception = exit.exception;
            // A guest EL0 memory abort HVF couldn't satisfy (e.g. a stack overflow
            // that ran SP off the mapped stack) surfaces DIRECTLY as an EXCEPTION
            // exit with EC=0x20/0x24, NOT through our EL1 vector's HVC. Surface it
            // as a DIRECT EL0Fault so the runtime delivers the right Linux signal
            // (SIGSEGV) instead of fataling. ELR_EL1/FAR_EL1 are STALE here (the
            // guest's EL1 vector never ran), so build the fault from HVF's
            // authoritative PC (Reg::PC) + VA (exception.virtual_address).
            if is_aarch64_el0_abort_exception(exception.syndrome) {
                let true_pc = vcpu.get_reg(Reg::PC).unwrap_or(0);
                let far = exception.virtual_address;
                let x16 = vcpu.get_reg(Reg::X16).unwrap_or(0);
                let x17 = vcpu.get_reg(Reg::X17).unwrap_or(0);
                let x29 = vcpu.get_reg(Reg::X29).unwrap_or(0);
                let x30 = vcpu.get_reg(Reg::LR).unwrap_or(0);
                let sp = vcpu.get_sys_reg(SysReg::SP_EL0).unwrap_or(0);
                crate::probes::vcpu_fault(exception.syndrome, true_pc, far, x30, sp, unsafe {
                    libc::getpid()
                });
                return Ok(Aarch64Exit::EL0Fault {
                    syndrome: exception.syndrome,
                    elr: true_pc,
                    far,
                    x16,
                    x17,
                    x29,
                    x30,
                    sp,
                    from_el0_direct: true,
                });
            }
            // Fail loud on the EL1 vector's `hvc #3` (current-EL synchronous slot):
            // carrick's guest took a synchronous exception WHILE AT EL1, which only
            // happens when a guest resume left PSTATE at EL1 (e.g. a signal handler
            // entered with SPSR_EL1=EL1h, whose PXN instruction fetch aborts). The
            // bare-`eret` vectors used to spin on this forever at 100 % CPU with no
            // host exit; the `hvc #3` trap surfaces it here. ESR_EL1/ELR_EL1/FAR_EL1
            // still hold the ORIGINAL EL1 fault (the `hvc` left them untouched), so
            // report them verbatim. This is a carrick bug, not a guest fault — do
            // not deliver it to the guest as a signal; terminate loudly.
            if is_aarch64_hvc_fault(exception.syndrome) {
                let esr_el1 = vcpu.get_sys_reg(SysReg::ESR_EL1).unwrap_or(0);
                let elr_el1 = vcpu.get_sys_reg(SysReg::ELR_EL1).unwrap_or(0);
                let far_el1 = vcpu.get_sys_reg(SysReg::FAR_EL1).unwrap_or(0);
                let spsr_el1 = vcpu.get_sys_reg(SysReg::SPSR_EL1).unwrap_or(0);
                if is_stage1_cow_write_fault(esr_el1) {
                    vcpu.set_reg(Reg::PC, elr_el1).map_err(hvf_error)?;
                    vcpu.set_reg(Reg::CPSR, spsr_el1).map_err(hvf_error)?;
                    return Ok(Aarch64Exit::Stage1CowFault {
                        syndrome: esr_el1,
                        far: far_el1,
                    });
                }
                let ec = (esr_el1 >> 26) & 0x3f;
                let mailbox_diagnostics = mailbox.diagnostics();
                eprintln!(
                    "FAIL-LOUD pid={pid}: guest executed at EL1 and faulted \
                     (current-EL sync vector) — carrick state corruption (a guest \
                     resume left PSTATE at EL1, commonly a signal handler entered \
                     with SPSR_EL1=EL1h). Was a silent 100% CPU spin before the \
                     hvc #3 vector trap. esr_el1={esr_el1:#x} ec={ec:#x} \
                     elr_el1={elr_el1:#x} far_el1={far_el1:#x} spsr_el1={spsr_el1:#x} \
                     mailbox={mailbox_diagnostics:?}",
                    pid = unsafe { libc::getpid() },
                );
                return Err(TrapError::GuestAtEl1 {
                    esr_el1,
                    elr_el1,
                    far_el1,
                    spsr_el1,
                });
            }
            if !is_aarch64_syscall_exception(exception.syndrome) {
                return Err(TrapError::UnexpectedException {
                    syndrome: exception.syndrome,
                    virtual_address: exception.virtual_address,
                    physical_address: exception.physical_address,
                });
            }
            // EC=0x16 (HVC) only means our EL1 vector trampoline fired — it catches
            // ALL lower-EL synchronous exceptions, not just SVCs. Look at ESR_EL1
            // to see what actually trapped to EL1; if it's not an SVC, either
            // emulate it (sys64 MRS read → re-run) or surface it as an EL0Fault.
            if is_aarch64_hvc_exception(exception.syndrome) {
                // The maintenance HVC (`hvc #1`) is consumed by the engine's
                // EL1-maintenance loop; if it ever reaches here, report it so the
                // engine's loop can match on it.
                if is_aarch64_hvc_maintenance(exception.syndrome) {
                    return Ok(Aarch64Exit::MaintenanceDone);
                }
                let underlying = vcpu.get_sys_reg(SysReg::ESR_EL1).map_err(hvf_error)?;
                if !is_aarch64_svc_exception(underlying) {
                    if HvfVmState::emulate_el0_sys64_read_inner(vcpu, underlying)? {
                        // Serviced (ELR_EL1 advanced, target GPR written) — re-run.
                        continue;
                    }
                    let elr = vcpu.get_sys_reg(SysReg::ELR_EL1).unwrap_or(0);
                    let far = vcpu.get_sys_reg(SysReg::FAR_EL1).unwrap_or(0);
                    let x16 = vcpu.get_reg(Reg::X16).unwrap_or(0);
                    let x17 = vcpu.get_reg(Reg::X17).unwrap_or(0);
                    let x29 = vcpu.get_reg(Reg::X29).unwrap_or(0);
                    let x30 = vcpu.get_reg(Reg::LR).unwrap_or(0);
                    let sp = vcpu.get_sys_reg(SysReg::SP_EL0).unwrap_or(0);
                    crate::probes::vcpu_fault(underlying, elr, far, x30, sp, unsafe {
                        libc::getpid()
                    });
                    // HVC-trampoline path: the guest EL1 vector latched
                    // ELR_EL1/FAR_EL1, so they are authoritative.
                    return Ok(Aarch64Exit::EL0Fault {
                        syndrome: underlying,
                        elr,
                        far,
                        x16,
                        x17,
                        x29,
                        x30,
                        sp,
                        from_el0_direct: false,
                    });
                }
            }
            // A genuine guest EL0 `svc`. HVC2 from the mailbox vector consumes
            // the release-published frame without any register/sysreg API reads.
            // The diagnostic legacy mode still validates that publication, then
            // deliberately reads the live registers for an apples-to-apples
            // transport comparison. A direct SVC exit (no EL1 HVC vehicle) keeps
            // the historical register decode as a defensive compatibility path.
            let mut register_reads = 0u32;
            let mut sysreg_reads = 0u32;
            let mut legacy_decode = || {
                sysreg_reads += 1;
                let resume_pc = vcpu.get_sys_reg(SysReg::ELR_EL1).map_err(|error| {
                    crate::syscall_mailbox::MailboxConsumeError::Legacy(error.to_string())
                })?;
                let frame = carrick_hal::read_aarch64_syscall_frame(|r| {
                    register_reads += 1;
                    hvf_get_reg(vcpu, r)
                })
                .map_err(|error| {
                    crate::syscall_mailbox::MailboxConsumeError::Legacy(error.to_string())
                })?;
                sysreg_reads += 1;
                let spsr = vcpu.get_sys_reg(SysReg::SPSR_EL1).unwrap_or(0);
                register_reads += 1;
                let fp = vcpu.get_reg(Reg::X29).unwrap_or(0);
                register_reads += 1;
                let lr = vcpu.get_reg(Reg::LR).unwrap_or(0);
                sysreg_reads += 1;
                let sp = vcpu.get_sys_reg(SysReg::SP_EL0).unwrap_or(0);
                sysreg_reads += 1;
                let esr = vcpu.get_sys_reg(SysReg::ESR_EL1).unwrap_or(0);
                Ok(crate::syscall_mailbox::MailboxRequest {
                    native_nr: frame.x8,
                    frame,
                    resume_pc,
                    spsr,
                    fp,
                    lr,
                    sp,
                    esr,
                })
            };
            let request = if is_aarch64_hvc_exception(exception.syndrome) {
                mailbox.decode_request(legacy_decode)
            } else {
                legacy_decode()
            }
            .map_err(|error| {
                let pc = vcpu.get_reg(Reg::PC).unwrap_or(0);
                let sp_el1 = vcpu.get_sys_reg(SysReg::SP_EL1).unwrap_or(0);
                let binding_address = mailbox.slot().guest_address();
                let diagnostics = mailbox.diagnostics();
                TrapError::Hypervisor(format!(
                    "{error}; vcpu_pc={pc:#x}; sp_el1={sp_el1:#x}; binding_address={binding_address:#x}; mailbox={diagnostics:?}"
                ))
            })?;
            crate::probes::hvf_syscall_transport(
                mailbox.transport().raw(),
                0,
                register_reads,
                sysreg_reads,
                0,
            );
            let frame = request.frame;
            let resume_pc = request.resume_pc;
            // vcpu_trap probe parity: guest PC at the trap (= ELR_EL1) + the live
            // FP/SP/LR so a DTrace consumer can walk the guest call chain. The
            // stack-region bases require the per-thread mapping list (on
            // HvfVmState, not reachable here), so report zero bases.
            crate::probes::vcpu_trap(&crate::compat::GuestRegs {
                pc: resume_pc,
                sp: request.sp,
                fp: request.fp,
                lr: request.lr,
                x8: frame.x8,
                x0: frame.x0,
                stack_guest_base: 0,
                stack_host_base: 0,
                stack_guest_end: 0,
            });
            return Ok(Aarch64Exit::Syscall { frame, resume_pc });
        }
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl HvfMappedRegion {
    /// Whether `[address, address+length)` lies wholly within this region's
    /// VA span `[start, end)`. Delegates the whole-range containment+bounds math
    /// to the neutral [`carrick_guest_mem::region::GuestMemoryRegion::contains_range`]
    /// so the bounds test can't drift across backends. HVF keeps its RICHER
    /// region SELECTION (newest-first + stage-1-IPA preference, chunked per page,
    /// `translate_va` for high-VA aliases — see `mapping_index_for_range`) as its
    /// own glue; only this per-region bounds primitive is shared. The projected
    /// region keys on `start`/`end` (NOT `size`: a 16 KiB host-rounded `end` can
    /// over-claim, and the copy loops compute `host_addr + (addr - start)`).
    fn contains_range(&self, address: u64, length: usize) -> bool {
        carrick_guest_mem::region::GuestMemoryRegion {
            base: self.start,
            len: (self.end - self.start) as usize,
            host_addr: self.host_addr,
        }
        .contains_range(address, length)
    }

    fn view(&self) -> MappingView {
        MappingView {
            start: self.start,
            end: self.end,
            ipa: self.ipa,
            host_addr: self.host_addr,
            guest_writable: self.guest_writable,
            sharing: self.sharing,
            shared_key_base: self.shared_key_base,
            shared_key_offset: self.shared_key_offset,
        }
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl MappingView {
    fn is_shared_aperture_identity(&self) -> bool {
        self.ipa == self.start
            && self.sharing == GuestMappingSharing::GlobalShared
            && self.end > self.start
            && crate::memory::va_in_shared_aperture(self.start, self.end - self.start)
    }

    /// Synthesize a view from a process-shared `alias_registry` entry (the
    /// cross-thread fallback). The alias is a contiguous VA→IPA→host window, so
    /// the VA base + backing base reproduce the same `host_addr + (addr - start)`
    /// offset math a real region uses.
    fn from_alias(b: &AliasBacking) -> Self {
        MappingView {
            start: b.start,
            end: b.start.saturating_add(b.size as u64),
            ipa: b.ipa,
            host_addr: b.host_addr as *mut u8,
            guest_writable: b.guest_writable,
            sharing: b.sharing,
            shared_key_base: b.shared_key_base,
            shared_key_offset: b.shared_key_offset,
        }
    }

    fn shared_futex_location_for_ipa(
        &self,
        backing_gpa: u64,
    ) -> Option<carrick_guest_mem::SharedFutexLocation> {
        if !self.sharing.has_shared_futex_identity() {
            return None;
        }
        let offset = usize::try_from(backing_gpa.checked_sub(self.ipa)?).ok()?;
        if offset.checked_add(std::mem::size_of::<u32>())?
            > self.end.checked_sub(self.start)? as usize
        {
            return None;
        }
        let word = carrick_guest_mem::HostVa(unsafe { self.host_addr.add(offset) } as usize);
        let waiter_key = if self.shared_key_base == 0 {
            word.raw()
        } else {
            let file_offset = self.shared_key_offset.saturating_add(offset as u64);
            shared_futex_waiter_key(self.shared_key_base, file_offset)
        };
        Some(carrick_guest_mem::SharedFutexLocation::Direct { word, waiter_key })
    }
}

/// True for a memory abort taken from a LOWER exception level (EL0 guest code):
/// instruction abort (`EC = 0x20`) or data abort (`EC = 0x24`). HVF normally
/// funnels guest EL0 faults through our EL1 vector trampoline (an HVC), but a
/// fault HVF itself can't satisfy (e.g. a stack overflow whose SP ran off the
/// mapped guest stack) surfaces DIRECTLY as an EXCEPTION exit with this EC. It
/// must be delivered to the guest as SIGSEGV (faulthandler._stack_overflow,
/// Go's sigpanic), not treated as a fatal "unexpected exception".
pub fn is_aarch64_el0_abort_exception(syndrome: u64) -> bool {
    matches!(aarch64_exception_class(syndrome), 0x20 | 0x24)
}

pub(crate) fn align_down(value: u64, alignment: u64) -> u64 {
    value / alignment * alignment
}

fn align_up(value: u64, alignment: u64) -> Result<u64, TrapError> {
    if alignment == 0 {
        return Err(TrapError::Hypervisor(
            "cannot align a guest mapping to zero bytes".to_owned(),
        ));
    }
    let remainder = value % alignment;
    if remainder == 0 {
        Ok(value)
    } else {
        value
            .checked_add(alignment - remainder)
            .ok_or(TrapError::MappingOverflow {
                guest_start: value,
                mapped_size: alignment,
            })
    }
}

#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Stage2BackendEvent {
    Map {
        ipa: u64,
        size: usize,
        host: usize,
        perms: u64,
    },
    Unmap {
        ipa: u64,
        size: usize,
    },
    UnmapAttemptFailed {
        ipa: u64,
        size: usize,
    },
}

#[cfg(test)]
#[derive(Default)]
struct Stage2TestAuditState {
    enabled: bool,
    fail_sparse_publication_after_sync: bool,
    fail_next_map: bool,
    fail_map_on_call: Option<usize>,
    map_call_count: usize,
    fail_next_unmap: bool,
    fail_stage_mapping: bool,
    fail_stage_mapping_on_row: Option<usize>,
    stage_mapping_count: usize,
    mapped_extents: std::collections::BTreeSet<(u64, usize)>,
    events: Vec<Stage2BackendEvent>,
}

#[cfg(test)]
thread_local! {
    static STAGE2_AUDIT_STATE: std::cell::RefCell<Stage2TestAuditState> =
        std::cell::RefCell::new(Stage2TestAuditState::default());
}

#[cfg(test)]
pub(crate) struct ScopedStage2MapTestStub;

#[cfg(test)]
impl ScopedStage2MapTestStub {
    pub(crate) fn enable() -> Self {
        STAGE2_AUDIT_STATE.with(|s| {
            let mut state = s.borrow_mut();
            state.enabled = true;
            state.fail_sparse_publication_after_sync = false;
            state.fail_next_map = false;
            state.fail_map_on_call = None;
            state.map_call_count = 0;
            state.fail_next_unmap = false;
            state.fail_stage_mapping = false;
            state.fail_stage_mapping_on_row = None;
            state.stage_mapping_count = 0;
            state.mapped_extents.clear();
            state.events.clear();
        });
        Self
    }

    pub(crate) fn set_fail_next_map(&self, fail: bool) {
        STAGE2_AUDIT_STATE.with(|s| s.borrow_mut().fail_next_map = fail);
    }

    pub(crate) fn set_fail_map_on_call(&self, call: Option<usize>) {
        STAGE2_AUDIT_STATE.with(|s| {
            let mut state = s.borrow_mut();
            state.fail_map_on_call = call;
            state.map_call_count = 0;
        });
    }

    pub(crate) fn set_fail_next_unmap(&self, fail: bool) {
        STAGE2_AUDIT_STATE.with(|s| s.borrow_mut().fail_next_unmap = fail);
    }

    #[allow(dead_code)]
    pub(crate) fn set_fail_stage_mapping(&self, fail: bool) {
        STAGE2_AUDIT_STATE.with(|s| s.borrow_mut().fail_stage_mapping = fail);
    }

    pub(crate) fn set_fail_stage_mapping_on_row(&self, row: Option<usize>) {
        STAGE2_AUDIT_STATE.with(|s| {
            let mut state = s.borrow_mut();
            state.fail_stage_mapping_on_row = row;
            state.stage_mapping_count = 0;
        });
    }

    pub(crate) fn is_mapped(ipa: u64, size: usize) -> bool {
        STAGE2_AUDIT_STATE.with(|s| s.borrow().mapped_extents.contains(&(ipa, size)))
    }

    pub(crate) fn events() -> Vec<Stage2BackendEvent> {
        STAGE2_AUDIT_STATE.with(|s| s.borrow().events.clone())
    }

    pub(crate) fn mapped_count() -> usize {
        STAGE2_AUDIT_STATE.with(|s| s.borrow().mapped_extents.len())
    }

    #[allow(dead_code)]
    pub(crate) fn clear_events() {
        STAGE2_AUDIT_STATE.with(|s| s.borrow_mut().events.clear());
    }
}

#[cfg(test)]
impl Drop for ScopedStage2MapTestStub {
    fn drop(&mut self) {
        STAGE2_AUDIT_STATE.with(|s| {
            let mut state = s.borrow_mut();
            state.enabled = false;
            state.fail_next_map = false;
            state.fail_map_on_call = None;
            state.map_call_count = 0;
            state.fail_next_unmap = false;
            state.fail_stage_mapping = false;
            state.fail_stage_mapping_on_row = None;
            state.stage_mapping_count = 0;
            state.mapped_extents.clear();
            state.events.clear();
        });
    }
}

#[cfg(test)]
#[test]
#[ignore = "negative control: scripts/test-signed.sh runs it on an UNENTITLED copy of this executable"]
fn unsigned_executable_maps_hv_denied_to_entitlement() {
    let outcome = applevisor::vm::VirtualMachine::with_config(
        applevisor::vm::VirtualMachineConfig::default(),
    );
    match outcome {
        Err(err)
            if err.to_string().contains("0xfae94007") || err.to_string().contains("HV_DENIED") => {}
        Err(other) => {
            panic!("expected HV_DENIED from an unentitled executable, got: {other:?}")
        }
        Ok(_) => panic!(
            "an unentitled executable created a VM: this process IS entitled, \
             so the negative control proves nothing"
        ),
    }
}

/// Sole raw Hypervisor.framework stage-2 map boundary. Inventory-aware callers
/// own logical publication; VM/vCPU replay calls this only to reinstall the
/// same physical extent and must still treat every nonzero result as failure.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) unsafe fn inventory_hv_vm_map(
    host: *mut std::ffi::c_void,
    ipa: u64,
    size: usize,
    permissions: u64,
) -> applevisor_sys::hv_return_t {
    #[cfg(test)]
    if STAGE2_AUDIT_STATE.with(|s| s.borrow().enabled) {
        let should_fail = STAGE2_AUDIT_STATE.with(|s| {
            let mut state = s.borrow_mut();
            state.map_call_count = state.map_call_count.saturating_add(1);
            if state.fail_next_map {
                state.fail_next_map = false;
                true
            } else if state.fail_map_on_call == Some(state.map_call_count) {
                state.fail_map_on_call = None;
                true
            } else if !state.mapped_extents.insert((ipa, size)) {
                true
            } else {
                state.events.push(Stage2BackendEvent::Map {
                    ipa,
                    size,
                    host: host as usize,
                    perms: permissions,
                });
                false
            }
        });
        if should_fail {
            return 0xfae9_4005u32 as applevisor_sys::hv_return_t;
        }
        return 0;
    }
    let result = unsafe { applevisor_sys::hv_vm_map(host, ipa, size, permissions) };
    if result == 0 {
        emit_global_frame_stage2(
            carrick_observability::probes::HvpatchGlobalFrameStage2Phase::Mapped,
            ipa,
            size,
            host as u64,
            permissions,
        );
    }
    result
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn emit_global_frame_stage2(
    phase: carrick_observability::probes::HvpatchGlobalFrameStage2Phase,
    ipa: u64,
    size: usize,
    host_addr: u64,
    permissions: u64,
) {
    let event = carrick_observability::probes::HvpatchGlobalFrameStage2::new(
        phase,
        ipa,
        size as u64,
        host_addr,
        permissions,
    )
    .unwrap_or_else(|error| {
        carrick_fatal!(
            "hvpatch::frame_inventory",
            "construct global-frame stage-2 receipt: {error}"
        );
    });
    crate::probes::hvpatch_global_frame_stage2(event);
}

/// Serialize lazy replay and make a sibling that lost the race observe the
/// exact already-installed extent as success without accepting arbitrary HVF
/// errors. The marker is cleared on unmap and every VM destruction.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
unsafe fn inventory_hv_vm_map_replay(backing: AliasBacking) -> applevisor_sys::hv_return_t {
    let key = replay_mapping_key(backing);
    mutate_external_alias_state(|installed, _| {
        if installed.contains(&key) {
            return 0;
        }
        let result = unsafe {
            inventory_hv_vm_map(
                backing.physical_host_addr as *mut std::ffi::c_void,
                backing.physical_ipa,
                backing.physical_size,
                backing.perms,
            )
        };
        if result == 0 {
            installed.insert(key);
        }
        result
    })
}

/// Sole raw Hypervisor.framework stage-2 unmap boundary.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
unsafe fn inventory_hv_vm_unmap(ipa: u64, size: usize) -> applevisor_sys::hv_return_t {
    #[cfg(test)]
    if STAGE2_AUDIT_STATE.with(|s| s.borrow().enabled) {
        let should_fail = STAGE2_AUDIT_STATE.with(|s| {
            let mut state = s.borrow_mut();
            if state.fail_next_unmap {
                state.fail_next_unmap = false;
                state
                    .events
                    .push(Stage2BackendEvent::UnmapAttemptFailed { ipa, size });
                true
            } else {
                false
            }
        });
        if should_fail {
            return 0xfae9_4001u32 as applevisor_sys::hv_return_t;
        }
        forget_replay_extent(ipa, size);
        STAGE2_AUDIT_STATE.with(|s| {
            let mut state = s.borrow_mut();
            state.mapped_extents.remove(&(ipa, size));
            state.events.push(Stage2BackendEvent::Unmap { ipa, size });
        });
        return 0;
    }
    let result = unsafe { applevisor_sys::hv_vm_unmap(ipa, size) };
    if result == 0 {
        forget_replay_extent(ipa, size);
        emit_global_frame_stage2(
            carrick_observability::probes::HvpatchGlobalFrameStage2Phase::Unmapped,
            ipa,
            size,
            0,
            0,
        );
    }
    result
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) unsafe fn inventory_hv_vm_destroy() -> applevisor_sys::hv_return_t {
    let result = unsafe { applevisor_sys::hv_vm_destroy() };
    if result == 0 {
        clear_replay_mappings();
    }
    result
}

#[cfg(test)]
#[test]
fn raw_hvf_stage2_calls_are_inventory_gated() {
    let source = include_str!("trap.rs");
    assert_eq!(
        source
            .matches(concat!("applevisor_sys::hv_vm_", "map("))
            .count(),
        1,
        "raw hv_vm_map must appear only in inventory_hv_vm_map"
    );
    assert_eq!(
        source
            .matches(concat!("applevisor_sys::hv_vm_", "unmap("))
            .count(),
        1,
        "raw hv_vm_unmap must appear only in inventory_hv_vm_unmap"
    );
    assert_eq!(
        source
            .matches(concat!("inventory_hv_vm_map_replay", "(b)"))
            .count(),
        2,
        "both lazy replay paths must use exact serialized replay"
    );
}

#[cfg(test)]
#[test]
fn raw_vm_destroy_is_custody_transaction_gated() {
    let source = concat!(
        include_str!("trap.rs"),
        include_str!("trap/carrier_custody.rs")
    );
    assert_eq!(
        source
            .matches(concat!("applevisor_sys::hv_vm_", "destroy()"))
            .count(),
        1,
        "the inventory boundary must remain the sole raw hv_vm_destroy caller"
    );
    assert_eq!(
        source
            .matches(concat!("inventory_hv_vm_", "destroy()"))
            .count(),
        2,
        "inventory_hv_vm_destroy must appear only in its definition and the custody wrapper"
    );
}

#[cfg(test)]
#[test]
fn reclaim_park_authority_contains_no_task_snapshot() {
    let mut authority = ReclaimParkAuthority::Live;
    authority.mark_vcpu_parked().unwrap();
    assert_eq!(authority, ReclaimParkAuthority::VcpuParked);
    assert!(authority.destination_vcpu_is_live().is_err());
    authority.mark_live_after_recreate().unwrap();
    assert_eq!(authority, ReclaimParkAuthority::Live);
    assert!(authority.destination_vcpu_is_live().is_ok());
}

#[cfg(test)]
#[test]
fn carrier_exit_without_a_vm_is_a_recorded_no_op() {
    use carrick_observability::vm_lifecycle::{VmLifecycleOperation, process_snapshot};
    fn destroy_events() -> usize {
        process_snapshot()
            .events
            .iter()
            .filter(|event| {
                matches!(
                    event.operation,
                    VmLifecycleOperation::DestroyAttempt | VmLifecycleOperation::DestroySuccess
                )
            })
            .count()
    }
    // An unsigned test executable can never create a VM (HV_DENIED), so this
    // process has no live carrier VM: carrier exit must destroy nothing and
    // must NOT append DestroyAttempt/DestroySuccess to the lifecycle ledger.
    // Only destroy-class events are counted: a sibling test in this binary may
    // record a failed LogicalCreateAttempt concurrently.
    let before = destroy_events();
    assert!(!carrier_vm_live());
    destroy_persistent_vm_at_carrier_exit().expect("no VM: nothing to destroy");
    assert_eq!(
        destroy_events(),
        before,
        "carrier exit without a VM must not record destroy events"
    );
}

fn prepare_exec_region_raw_in(
    custody: &CarrierVmCustody,
    mapping: &GuestMapping,
) -> Result<HvfMappedRegion, TrapError> {
    let requested_size = usize::try_from(mapping.mapped_size)
        .map_err(|_| TrapError::MappingTooLarge(mapping.mapped_size))?;
    let backing_started = std::time::Instant::now();
    let (host, size, host_mapping) = map_exclusive_region(mapping, requested_size)?;
    let elapsed_ns = backing_started
        .elapsed()
        .as_nanos()
        .min(u128::from(u64::MAX)) as u64;
    crate::probes::hvpatch_exec_backing(carrick_observability::probes::HvpatchExecBacking::new(
        if mapping.private_file_backing.is_some() {
            carrick_observability::probes::HvpatchExecBackingPhase::PrivateFileMapped
        } else {
            carrick_observability::probes::HvpatchExecBackingPhase::Materialized
        },
        mapping.guest_start,
        mapping.ipa_start,
        mapping.mapped_size,
        elapsed_ns,
    ));
    let end =
        mapping
            .guest_start
            .checked_add(mapping.mapped_size)
            .ok_or(TrapError::MappingOverflow {
                guest_start: mapping.guest_start,
                mapped_size: mapping.mapped_size,
            })?;
    Ok(HvfMappedRegion {
        start: mapping.guest_start,
        ipa: mapping.ipa_start,
        physical_ipa: mapping.ipa_start,
        end,
        host_addr: host,
        size,
        physical_size: size,
        perms: hvf_perms(mapping.perms),
        memory: None,
        host_mapping: Some(host_mapping),
        structural_owner: None,
        stage2_lease: None,
        is_dynamic_alias: false,
        sharing: if mapping.shared {
            GuestMappingSharing::GlobalShared
        } else {
            GuestMappingSharing::Private
        },
        guest_writable: mapping.perms.write,
        shared_key_base: 0,
        shared_key_offset: 0,
        owner_generation: global_frame_host_owner_generation_in(
            custody,
            mapping.ipa_start,
            size as u64,
        ),
    })
}

#[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
fn prepare_exec_region_raw(mapping: &GuestMapping) -> Result<HvfMappedRegion, TrapError> {
    prepare_exec_region_raw_in(legacy_test_carrier_vm_custody(), mapping)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn exec_stage2_install(mapping: &GuestMapping, region: &HvfMappedRegion) -> ExecStage2Install {
    ExecStage2Install {
        ipa: mapping.ipa_start,
        size: region.physical_size,
        host: region.host_addr,
        perms: u64::from(region.perms),
        replay_registered: false,
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn map_region_raw_in(
    custody: &std::sync::Arc<CarrierVmCustody>,
    mapping: &GuestMapping,
    emit_exec_backing_census: bool,
    retain_structural_owner: bool,
) -> Result<HvfMappedRegion, TrapError> {
    map_region_raw_in_using_epoch_allocator(
        custody,
        mapping,
        emit_exec_backing_census,
        retain_structural_owner,
        next_structural_epoch,
    )
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn map_region_raw_in_using_epoch_allocator(
    custody: &std::sync::Arc<CarrierVmCustody>,
    mapping: &GuestMapping,
    emit_exec_backing_census: bool,
    retain_structural_owner: bool,
    allocate_epoch: impl FnOnce() -> Result<StructuralEpoch, TrapError>,
) -> Result<HvfMappedRegion, TrapError> {
    let size = usize::try_from(mapping.mapped_size)
        .map_err(|_| TrapError::MappingTooLarge(mapping.mapped_size))?;
    let end =
        mapping
            .guest_start
            .checked_add(mapping.mapped_size)
            .ok_or(TrapError::MappingOverflow {
                guest_start: mapping.guest_start,
                mapped_size: mapping.mapped_size,
            })?;
    let retain_structural_owner =
        retain_structural_owner && !is_persistent_executor_carrier_guest_mapping(mapping);
    // Mint every fallible structural identity before stage-2 publication. If
    // this fails, dropping the not-yet-mapped host backing is sufficient
    // rollback; no HVF mapping or custody record exists yet.
    let structural_epoch = retain_structural_owner.then(allocate_epoch).transpose()?;
    // MAP_SHARED, not MAP_PRIVATE: a MAP_PRIVATE anon page mapped into the
    // guest via hv_vm_map desyncs from the host buffer — the guest's own store
    // and a later guest load observe different memory (the "PROT_REA" wild-PC
    // crash: a dynamic binary's GOT slot that ld.so resolved reads back stale).
    // MAP_SHARED anon is HVF-coherent (same as `map_shared_file`). The cost:
    // fork(2) no longer COW-isolates these pages. HVPatch isolates them with
    // per-mm stage-1 COW; the legacy VMM fork path separately clones only its
    // page-table/control backing.
    // The aperture region is host-MAP_SHARED so it stays shared across fork(2)
    // (never snapshotted); all other regions are private guest RAM.
    let backing_started = std::time::Instant::now();
    let (host, size, host_mapping) = map_exclusive_region(mapping, size)?;
    if emit_exec_backing_census {
        let elapsed_ns = backing_started
            .elapsed()
            .as_nanos()
            .min(u128::from(u64::MAX)) as u64;
        crate::probes::hvpatch_exec_backing(
            carrick_observability::probes::HvpatchExecBacking::new(
                if mapping.private_file_backing.is_some() {
                    carrick_observability::probes::HvpatchExecBackingPhase::PrivateFileMapped
                } else {
                    carrick_observability::probes::HvpatchExecBackingPhase::Materialized
                },
                mapping.guest_start,
                mapping.ipa_start,
                mapping.mapped_size,
                elapsed_ns,
            ),
        );
    }
    let perms = hvf_perms(mapping.perms);
    let perms_raw: u64 = u64::from(perms);
    // Map at the IPA (identity for all but the Rosetta alias); the guest's
    // stage-1 page tables translate the VIRTUAL `guest_start` to this IPA.
    if emit_exec_backing_census {
        crate::probes::hvpatch_exec_stage2(carrick_observability::probes::HvpatchExecStage2::new(
            carrick_observability::probes::HvpatchExecStage2Phase::MapBegin,
            mapping.ipa_start,
            size as u64,
            mapping.guest_start,
            0,
        ));
    }
    let r = unsafe {
        inventory_hv_vm_map(
            host.cast::<std::ffi::c_void>(),
            mapping.ipa_start,
            size,
            perms_raw,
        )
    };
    if emit_exec_backing_census {
        crate::probes::hvpatch_exec_stage2(carrick_observability::probes::HvpatchExecStage2::new(
            carrick_observability::probes::HvpatchExecStage2Phase::MapEnd,
            mapping.ipa_start,
            size as u64,
            mapping.guest_start,
            r as i32,
        ));
    }
    if r != 0 {
        return Err(TrapError::Hypervisor(format!(
            "hv_vm_map(ipa=0x{:x}, va=0x{:x}, size={size}) failed: 0x{r:x}",
            mapping.ipa_start, mapping.guest_start
        )));
    }
    let sharing = if mapping.shared {
        GuestMappingSharing::GlobalShared
    } else {
        GuestMappingSharing::Private
    };
    let mut region = HvfMappedRegion {
        start: mapping.guest_start,
        ipa: mapping.ipa_start,
        physical_ipa: mapping.ipa_start,
        end,
        host_addr: host,
        size,
        physical_size: size,
        perms,
        memory: None,
        host_mapping: Some(host_mapping),
        structural_owner: None,
        stage2_lease: None,
        is_dynamic_alias: false,
        // Private guest RAM (data/bss/heap/stack/MAP_PRIVATE): HVPatch fork
        // shares the global frame read-only until the writer COWs it.
        sharing,
        // Boot regions carry their true guest write-intent (image=RX, page
        // tables=RO -> not writable; heap/stack/data=RW -> writable).
        guest_writable: mapping.perms.write,
        shared_key_base: 0,
        shared_key_offset: 0,
        owner_generation: global_frame_host_owner_generation_in(
            custody,
            mapping.ipa_start,
            size as u64,
        ),
    };
    if retain_structural_owner {
        let host_mapping = region.host_mapping.take().ok_or_else(|| {
            TrapError::Hypervisor(format!(
                "initial fixed mapping at IPA 0x{:x} has no host owner",
                region.physical_ipa
            ))
        })?;
        let epoch = structural_epoch.ok_or_else(|| {
            TrapError::Hypervisor(format!(
                "initial fixed mapping at IPA 0x{:x} has no structural epoch",
                region.physical_ipa
            ))
        })?;
        let mut lease =
            GlobalFrameStage2Lease::fixed(region.physical_ipa, region.physical_size as u64);
        lease.mark_mapped();
        let owner = StructuralBackingOwner::new_in(
            custody,
            host_mapping,
            lease,
            u64::from(region.perms),
            epoch,
            region.physical_ipa,
            region.physical_size,
        )?;
        region.owner_generation = epoch.raw();
        region.structural_owner = Some(owner);
    }
    Ok(region)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn map_exclusive_region(
    mapping: &GuestMapping,
    size: usize,
) -> Result<(*mut u8, usize, crate::host_mapping::OwnedHostMapping), TrapError> {
    if let Some(backing) = &mapping.private_file_backing {
        let host_mapping = crate::host_mapping::OwnedHostMapping::map_private_file(
            backing.file.as_raw_fd(),
            0,
            size,
        )
        .map_err(|error| {
            TrapError::Hypervisor(format!(
                "mmap private executable artifact (size={size}) failed: {error}"
            ))
        })?;
        return Ok((host_mapping.as_ptr(), host_mapping.len(), host_mapping));
    }
    let kind = if mapping.shared {
        crate::host_mapping::HostMappingKind::SharedAnon
    } else {
        crate::host_mapping::HostMappingKind::PrivateAnon
    };
    let host_mapping =
        crate::host_mapping::OwnedHostMapping::map_shared_anon(size, kind).map_err(|error| {
            TrapError::Hypervisor(format!("mmap guest region (size={size}) failed: {error}"))
        })?;
    let host = host_mapping.as_ptr();
    let size = host_mapping.len();
    // Copy the payload prefix into the freshly-zeroed region; the rest stays
    // zero (lazy). offset_in_mapping + image.len() <= mapped_size is guaranteed
    // by GuestMappingPlan::from_address_space.
    if !mapping.image.is_empty() {
        let off = usize::try_from(mapping.offset_in_mapping)
            .map_err(|_| TrapError::MappingTooLarge(mapping.offset_in_mapping))?;
        unsafe {
            std::ptr::copy_nonoverlapping(
                mapping.image.as_ptr(),
                host.add(off),
                mapping.image.len(),
            );
        }
    }
    Ok((host, size, host_mapping))
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn hvf_perms(perms: SegmentPerms) -> applevisor::memory::MemPerms {
    use applevisor::memory::MemPerms;

    // HVF stage-2 quirk on macOS 26 (Tahoe) / Apple Silicon: a stage-2
    // mapping created with `HV_MEMORY_READ | HV_MEMORY_WRITE` (no
    // `HV_MEMORY_EXEC`) fails to translate EL0 data accesses — the guest
    // takes a stage-2 translation fault (DFSC=0x05, "translation fault
    // level 1") even though the IPA falls inside the mapping and the
    // host-side `Memory::read`/`Memory::write` accessors succeed. The
    // ARM stage-2 attribute model has no per-EL data-access bit, so the
    // fault is HVF-specific behaviour rather than ARMv8 architectural.
    //
    // Empirically, escalating the stage-2 permission to
    // `ReadWriteExec` makes the fault go away. The guest still uses
    // stage-1 (`SCTLR_EL1.M=0` in the bootstrap), so the stage-2 X bit
    // is the only thing that controls instruction fetch from the
    // region; the guest is already executing without stage-1 enforcement
    // and the host process is single-tenant, so granting stage-2 X on
    // data/stack regions does not add a meaningful new attack surface.
    //
    // The escalation is gated on the original perms still being some
    // form of `Write` so we don't accidentally upgrade a `Read`-only or
    // `Exec`-only mapping: those translate fine as-is. This keeps the
    // workaround narrow.
    let escalated_perms = SegmentPerms {
        read: perms.read,
        write: perms.write,
        execute: perms.execute || perms.write,
    };

    match (
        escalated_perms.read,
        escalated_perms.write,
        escalated_perms.execute,
    ) {
        (false, false, false) => MemPerms::None,
        (true, false, false) => MemPerms::Read,
        (false, true, false) => MemPerms::Write,
        (false, false, true) => MemPerms::Exec,
        (true, true, false) => MemPerms::ReadWrite,
        (true, false, true) => MemPerms::ReadExec,
        (false, true, true) => MemPerms::WriteExec,
        (true, true, true) => MemPerms::ReadWriteExec,
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn hvf_error(error: applevisor::error::HypervisorError) -> TrapError {
    TrapError::Hypervisor(error.to_string())
}

/// Convert a neutral [`carrick_hal::MemPerms`] to the applevisor stage-2
/// `MemPerms` for [`HvfVmState::map_stage2`]. A DIRECT mapping (no RWX
/// escalation): that escalation is the `hvf_perms(SegmentPerms)` boot/alias path;
/// the engine's `map_stage2` callers pass the perms they want verbatim.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn hvf_mem_perms(perms: carrick_hal::MemPerms) -> applevisor::memory::MemPerms {
    use applevisor::memory::MemPerms;
    match (perms.read, perms.write, perms.exec) {
        (false, false, false) => MemPerms::None,
        (true, false, false) => MemPerms::Read,
        (false, true, false) => MemPerms::Write,
        (false, false, true) => MemPerms::Exec,
        (true, true, false) => MemPerms::ReadWrite,
        (true, false, true) => MemPerms::ReadExec,
        (false, true, true) => MemPerms::WriteExec,
        (true, true, true) => MemPerms::ReadWriteExec,
    }
}

/// The HVF concurrent-vCPU budget for the bounded M:N scheduler the engine
/// installs via `GuestVmBackend::vcpu_budget`: physical host cores, capped by
/// HVF's usable per-VM vCPU ceiling. Reclaim recycles vCPUs so >budget guest
/// threads run instead of hanging. macOS/HVF-only: `vcpu_gate` (and the whole HVF
/// backend) is cfg'd out off the HVF lane, and the only caller (the new module's
/// `GuestVmBackend::vcpu_budget`) is macOS-only too.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn hvf_vcpu_budget() -> usize {
    vcpu_gate::budget().max(1)
}

// NOTE: the thread-sibling register seeding (`seed_child_snapshot`) now lives
// ONCE in the shared engine (`carrick_aarch64::seed_sibling_snapshot`), which the
// engine's `build_sibling_spec` applies before `materialize_sibling`. HVF's
// `from_thread_spec` only stands up the vCPU + mirrors the mapping metadata; the
// engine restores the seeded snapshot onto it.

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[cfg(test)]
pub(crate) mod frame_inventory_backend_tests {
    pub(crate) static NEXT_TEST_PHYSICAL_IPA: std::sync::atomic::AtomicU64 =
        std::sync::atomic::AtomicU64::new(0x0000_00a1_0000_0000);

    pub(crate) fn global_frame_allocator_test_lock() -> &'static parking_lot::Mutex<()> {
        static LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
        &LOCK
    }
}

#[cfg(test)]
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) mod thread_sibling_tests;

// ---------------------------------------------------------------------------
// carrick-hal trait impls: RegAccess + ThreadedEngine
//
// These are forwarding impls only.  Every method delegates to an existing
// HvfTrapEngine / HvfInner method verbatim.  No behaviour is changed.
//
// The HAL Reg/SysReg enums were designed for KVM's register naming; we map
// each variant to the equivalent applevisor register below.
//
// HypervisorError does not carry a POSIX errno.  We map any HVF error to
// EIO (5) — a generic I/O error the caller can distinguish from EINVAL/ENOSYS.
// ---------------------------------------------------------------------------

/// Convert an applevisor error to a HAL OsError, using EIO as the errno.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[inline]
pub(crate) fn hvf_os_error(_e: applevisor::error::HypervisorError) -> carrick_hal::OsError {
    carrick_hal::OsError::from_raw(libc::EIO)
}

/// Map a HAL [`carrick_hal::Reg`] to the corresponding applevisor value and
/// read it from `vcpu`.  On non-HVF targets returns ENOSYS (never called).
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn hvf_get_reg(
    vcpu: &applevisor::vcpu::Vcpu,
    r: carrick_hal::Reg,
) -> Result<u64, carrick_hal::OsError> {
    // `applevisor::prelude::*` brings `Reg`/`SysReg`; we locally shadow the
    // HAL types only inside the `match r` arm patterns.
    use applevisor::prelude::*;
    let hal_r = r;
    match hal_r {
        carrick_hal::Reg::X(n) => match GPR_TABLE.get(n as usize) {
            Some(&reg) => vcpu.get_reg(reg).map_err(hvf_os_error),
            None => Err(carrick_hal::OsError::from_raw(libc::EINVAL)),
        },
        carrick_hal::Reg::Sp => vcpu.get_sys_reg(SysReg::SP_EL0).map_err(hvf_os_error),
        carrick_hal::Reg::Pc => vcpu.get_reg(Reg::PC).map_err(hvf_os_error),
        carrick_hal::Reg::Pstate => vcpu.get_reg(Reg::CPSR).map_err(hvf_os_error),
        carrick_hal::Reg::SpEl1 => vcpu.get_sys_reg(SysReg::SP_EL1).map_err(hvf_os_error),
        carrick_hal::Reg::ElrEl1 => vcpu.get_sys_reg(SysReg::ELR_EL1).map_err(hvf_os_error),
        carrick_hal::Reg::SpsrEl1 => vcpu.get_sys_reg(SysReg::SPSR_EL1).map_err(hvf_os_error),
        _ => Err(carrick_hal::OsError::from_raw(libc::EINVAL)),
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn hvf_set_reg(
    vcpu: &applevisor::vcpu::Vcpu,
    r: carrick_hal::Reg,
    v: u64,
) -> Result<(), carrick_hal::OsError> {
    use applevisor::prelude::*;
    let hal_r = r;
    match hal_r {
        carrick_hal::Reg::X(n) => match GPR_TABLE.get(n as usize) {
            Some(&reg) => vcpu.set_reg(reg, v).map_err(hvf_os_error),
            None => Err(carrick_hal::OsError::from_raw(libc::EINVAL)),
        },
        carrick_hal::Reg::Sp => vcpu.set_sys_reg(SysReg::SP_EL0, v).map_err(hvf_os_error),
        carrick_hal::Reg::Pc => vcpu.set_reg(Reg::PC, v).map_err(hvf_os_error),
        carrick_hal::Reg::Pstate => vcpu.set_reg(Reg::CPSR, v).map_err(hvf_os_error),
        carrick_hal::Reg::SpEl1 => vcpu.set_sys_reg(SysReg::SP_EL1, v).map_err(hvf_os_error),
        carrick_hal::Reg::ElrEl1 => vcpu.set_sys_reg(SysReg::ELR_EL1, v).map_err(hvf_os_error),
        carrick_hal::Reg::SpsrEl1 => vcpu.set_sys_reg(SysReg::SPSR_EL1, v).map_err(hvf_os_error),
        _ => Err(carrick_hal::OsError::from_raw(libc::EINVAL)),
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn hvf_get_sys_reg(
    vcpu: &applevisor::vcpu::Vcpu,
    r: carrick_hal::SysReg,
) -> Result<u64, carrick_hal::OsError> {
    use applevisor::prelude::*;
    let hvf_reg = match r {
        carrick_hal::SysReg::Sctlr => SysReg::SCTLR_EL1,
        carrick_hal::SysReg::Ttbr0 => SysReg::TTBR0_EL1,
        carrick_hal::SysReg::Ttbr1 => SysReg::TTBR1_EL1,
        carrick_hal::SysReg::Tcr => SysReg::TCR_EL1,
        carrick_hal::SysReg::Mair => SysReg::MAIR_EL1,
        carrick_hal::SysReg::Vbar => SysReg::VBAR_EL1,
        carrick_hal::SysReg::Cpacr => SysReg::CPACR_EL1,
        carrick_hal::SysReg::TpidrEl0 => SysReg::TPIDR_EL0,
        // x86_64 FsBase/GsBase are a disjoint ISA view; never on the macOS/HVF lane.
        _ => return Err(carrick_hal::OsError::from_raw(libc::EINVAL)),
    };
    vcpu.get_sys_reg(hvf_reg).map_err(hvf_os_error)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn hvf_set_sys_reg(
    vcpu: &applevisor::vcpu::Vcpu,
    r: carrick_hal::SysReg,
    v: u64,
) -> Result<(), carrick_hal::OsError> {
    use applevisor::prelude::*;
    let hvf_reg = match r {
        carrick_hal::SysReg::Sctlr => SysReg::SCTLR_EL1,
        carrick_hal::SysReg::Ttbr0 => SysReg::TTBR0_EL1,
        carrick_hal::SysReg::Ttbr1 => SysReg::TTBR1_EL1,
        carrick_hal::SysReg::Tcr => SysReg::TCR_EL1,
        carrick_hal::SysReg::Mair => SysReg::MAIR_EL1,
        carrick_hal::SysReg::Vbar => SysReg::VBAR_EL1,
        carrick_hal::SysReg::Cpacr => SysReg::CPACR_EL1,
        carrick_hal::SysReg::TpidrEl0 => SysReg::TPIDR_EL0,
        // x86_64 FsBase/GsBase are a disjoint ISA view; never on the macOS/HVF lane.
        _ => return Err(carrick_hal::OsError::from_raw(libc::EINVAL)),
    };
    vcpu.set_sys_reg(hvf_reg, v).map_err(hvf_os_error)
}

#[cfg(test)]
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod tag_strip_tests {
    use super::*;

    #[test]
    fn logical_hvpatch_processes_receive_distinct_vdso_rng_generations() {
        let parent = next_vdso_rng_generation();
        let child = next_vdso_rng_generation();

        assert_ne!(parent, 0);
        assert_ne!(child, 0);
        assert_ne!(parent, child);
    }

    static EXEC_PAYLOAD_ENV_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

    #[test]
    fn guest_mapping_plan_shares_address_space_payload() {
        let _env_guard = EXEC_PAYLOAD_ENV_LOCK.lock();
        let perms = carrick_mem::elf::SegmentPerms {
            read: true,
            write: false,
            execute: true,
        };
        let image = carrick_mem::memory::AddressSpace::from_segments(
            0x1_0000,
            [(0x1_0000, perms, vec![0xaa; 0x4000], 0x4000)],
        )
        .expect("one valid region");

        let plan = GuestMappingPlan::from_address_space(&image).expect("mapping plan");
        let cloned_plan = plan.clone();

        assert_eq!(
            plan.mappings[0].image.as_ptr(),
            image.regions()[0].bytes().as_ptr(),
            "mapping-plan construction must not copy immutable image bytes"
        );
        assert_eq!(
            cloned_plan.mappings[0].image.as_ptr(),
            plan.mappings[0].image.as_ptr(),
            "mapping-plan clones must share immutable image bytes"
        );
    }

    #[test]
    fn global_exec_readonly_spans_preserve_rebased_ipa() {
        let va = 0x20_0000;
        let ipa = 0x5000_0000;
        let mut tables = carrick_mem::page_table::PageTableManager::new(
            carrick_mem::memory::stage1_identity_page_tables(),
            carrick_mem::memory::LINUX_PAGE_TABLES_BASE,
        );
        tables
            .map_aliased(va, ipa, 0x20_000, true, None)
            .expect("rebase merged writable load region");

        reapply_global_exec_readonly_spans(
            &mut tables,
            &[carrick_mem::elf::RoSpan {
                start: va + 0x4000,
                len: 0x2000,
                exec: false,
            }],
        )
        .expect("restore PT_LOAD protection");

        assert_eq!(tables.translate(va + 0x4000), Some(ipa + 0x4000));
        assert!(
            !tables
                .set_readonly(va + 0x4000, 0x1000, false, None)
                .expect("span is already read-only")
                .changed,
            "reapplying the same read-only protection must be a no-op"
        );
        assert!(
            !tables
                .set_rw(va + 0x3000, 0x1000, true, None)
                .expect("prefix remains writable")
                .changed,
            "the page before the span must retain the merged mapping's RWX attributes"
        );
        assert!(
            !tables
                .set_rw(va + 0x6000, 0x1000, true, None)
                .expect("suffix remains writable")
                .changed,
            "the page after the span must retain the merged mapping's RWX attributes"
        );
    }

    #[test]
    fn guest_mapping_plan_payload_sharing_hatch_restores_deep_copy() {
        let _env_guard = EXEC_PAYLOAD_ENV_LOCK.lock();
        let prior = std::env::var_os("CARRICK_HVPATCH_SHARE_EXEC_PAYLOAD");
        // SAFETY: no other test reads or writes this diagnostic-only variable.
        unsafe { std::env::set_var("CARRICK_HVPATCH_SHARE_EXEC_PAYLOAD", "0") };

        let perms = carrick_mem::elf::SegmentPerms {
            read: true,
            write: false,
            execute: true,
        };
        let image = carrick_mem::memory::AddressSpace::from_segments(
            0x1_0000,
            [(0x1_0000, perms, vec![0xaa; 0x4000], 0x4000)],
        )
        .expect("one valid region");
        let plan = GuestMappingPlan::from_address_space(&image).expect("mapping plan");

        match prior {
            Some(value) => {
                // SAFETY: restores the value this test replaced.
                unsafe { std::env::set_var("CARRICK_HVPATCH_SHARE_EXEC_PAYLOAD", value) };
            }
            None => {
                // SAFETY: restores the absence this test replaced.
                unsafe { std::env::remove_var("CARRICK_HVPATCH_SHARE_EXEC_PAYLOAD") };
            }
        }

        assert_ne!(
            plan.mappings[0].image.as_ptr(),
            image.regions()[0].bytes().as_ptr(),
            "the =0 bisection hatch must restore the pre-optimization payload copy"
        );
        assert_eq!(
            plan.mappings[0].image.as_slice(),
            image.regions()[0].bytes()
        );
    }

    #[test]
    fn guest_mapping_plan_keeps_full_stack_extent_but_only_initialized_tail_payload() {
        let image = carrick_mem::memory::AddressSpace::from_regions(0x1_0000, Vec::new())
            .expect("empty image")
            .with_linux_initial_stack([b"tool".as_slice()], [b"KEY=value".as_slice()])
            .expect("initial stack");
        let plan = GuestMappingPlan::from_address_space(&image).expect("mapping plan");
        let stack_start =
            carrick_mem::memory::LINUX_STACK_TOP - carrick_mem::memory::LINUX_STACK_SIZE;
        let mapping = plan
            .mappings
            .iter()
            .find(|mapping| mapping.guest_start == stack_start)
            .expect("stack mapping");

        assert_eq!(
            mapping.mapped_size,
            carrick_mem::memory::LINUX_STACK_SIZE,
            "Linux stack growth must retain the full RLIMIT_STACK extent"
        );
        assert!(mapping.offset_in_mapping > 7 * 1024 * 1024);
        assert!(mapping.image.len() < 64 * 1024);
        assert_eq!(
            mapping.offset_in_mapping + mapping.image.len() as u64,
            mapping.mapped_size,
            "the sparse payload must cover the initialized tail through stack top"
        );
        let source = image
            .regions()
            .iter()
            .find(|region| region.start == stack_start)
            .expect("source stack");
        assert_eq!(
            mapping.image.as_slice(),
            &source.bytes()[mapping.offset_in_mapping as usize..]
        );
    }

    #[test]
    fn private_exec_file_artifact_reuses_bytes_but_each_mapping_is_cow() {
        use std::os::fd::AsRawFd;

        let source = std::sync::Arc::new(vec![0xA5; super::HVF_PAGE_SIZE as usize]);
        let first = super::cached_exec_private_file_backing(
            std::sync::Arc::clone(&source),
            super::HVF_PAGE_SIZE as usize,
        )
        .expect("cache private executable artifact");
        let second = super::cached_exec_private_file_backing(
            std::sync::Arc::clone(&source),
            super::HVF_PAGE_SIZE as usize,
        )
        .expect("reuse private executable artifact");
        assert_eq!(
            first, second,
            "the same immutable payload must reuse one artifact"
        );

        let mapped = crate::host_mapping::OwnedHostMapping::map_private_file(
            first.file.as_raw_fd(),
            0,
            super::HVF_PAGE_SIZE as usize,
        )
        .expect("map private executable artifact");
        unsafe { mapped.as_ptr().write_volatile(0x5A) };
        assert_eq!(unsafe { mapped.as_ptr().read_volatile() }, 0x5A);

        let fresh = crate::host_mapping::OwnedHostMapping::map_private_file(
            second.file.as_raw_fd(),
            0,
            super::HVF_PAGE_SIZE as usize,
        )
        .expect("map fresh private executable artifact");
        assert_eq!(
            unsafe { fresh.as_ptr().read_volatile() },
            0xA5,
            "one exec's COW write must not contaminate the cached artifact"
        );
    }

    #[test]
    fn strips_top_16_bits() {
        // Rosetta's RWX ExecutableHeap hint, and an x86-64 high-half address.
        assert_eq!(
            strip_pointer_tag(0xffff_fff7_ff70_0000),
            0x0000_fff7_ff70_0000
        );
        assert_eq!(
            strip_pointer_tag(0xffff_ffff_fff3_a000),
            0x0000_ffff_fff3_a000
        );
        // Native (top-byte-zero) pointers are untouched.
        assert_eq!(
            strip_pointer_tag(0x0000_0001_2345_6000),
            0x0000_0001_2345_6000
        );
    }
}
