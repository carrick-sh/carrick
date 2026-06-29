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
//! `complete_syscall` (write the retval), `fork` / `execve_into` (address-space
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
//! ## Address-space lifecycle: fork, clone, execve
//!
//! There is no guest kernel to copy a page table, so process/thread creation is
//! done by *rebuilding HVF state around the host's own fork/threads*:
//!
//! - **`fork(2)`** (`HvfInner::fork`) is a real `libc::fork`. macOS HVF state is
//!   not fork-safe, so the parent tears down its vCPU+VM via the *raw* API
//!   BEFORE forking (a live VM at fork time leaves the child unable to
//!   `hv_vm_create`); both sides then rebuild a fresh VM and re-`hv_vm_map` the
//!   same host buffers. Guest RAM is host-`MAP_SHARED` (required for HVF
//!   coherence), so `fork(2)` does NOT COW-isolate it — the parent therefore
//!   takes an explicit private snapshot of each PRIVATE region pre-fork (while
//!   the vCPU is suspended, hence race-free) via `clone_region_for_child`, and
//!   the child maps those copies. Genuine guest `MAP_SHARED` file mappings are
//!   deliberately *not* snapshotted (POSIX: they stay shared across fork).
//! - **Thread clone** (`HvfInner::build_thread_spec` / `from_thread_spec`)
//!   keeps ONE process VM and gives each guest thread its own vCPU in it. The
//!   stage-2 mappings are VM-global, so a sibling only re-materialises local
//!   syscall-path metadata (UNOWNED, `memory: None`) and never frees the main
//!   engine's buffers. Because HVF caps concurrent vCPUs, sibling creation
//!   passes through an admission gate (`wait_for_vcpu_slot`); see the
//!   private `vcpu_gate` module for why a guest that out-threads the cap *blocks*
//!   rather than failing `clone` (Linux has no such cap, so failing would
//!   deadlock a join). A *multithreaded* fork additionally quiesces siblings,
//!   destroys their vCPUs so the forker can `hv_vm_destroy`, then republishes the
//!   rebuilt VM for them to recreate vCPUs in (`release_vcpu_for_fork` /
//!   `publish_vm_for_siblings` / `rebuild_vcpu_after_fork`).
//! - **`execve(2)`** (`HvfInner::execve_into`) tears down and rebuilds the VM
//!   like fork, but installs a brand-new [`AddressSpace`] and resets the vCPU to
//!   "initial process startup" (zeroed GPRs, entry trampoline) rather than
//!   "resume mid-syscall". It has no successful return.
//!
//! All three paths bypass `applevisor`'s `Drop`: once a single `fork(2)` has run,
//! applevisor's internal handle bookkeeping no longer matches HVF, and its
//! destructors panic ("no VM or vCPU available"). `HvfInner` is held in a
//! [`std::mem::ManuallyDrop`] and the host pages leak until process exit — which
//! is fine, the process is exiting anyway, and the kernel reclaims the VM.
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
use carrick_aarch64::Aarch64VcpuSnapshot;
use carrick_guest_mem::MemoryError;
use serde::Serialize;

mod sysreg;
use sysreg::*;

// Process-wide PROT_NONE bookkeeping is a neutral-core abstraction shared with
// every other backend (KVM included) — see carrick_mem::protections. Both hold
// it as `Arc<MemoryProtections>` and clone it into each sibling vCPU thread.
use carrick_mem::protections::MemoryProtections;

// SyscallTrap/TrapError/ForkOutcome moved down into the carrick-hal leaf crate
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
pub use carrick_hal::trap::{ForkOutcome, RawSyscall, SyscallTrap, TrapError};

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
    image: Vec<u8>,
}

impl GuestMappingPlan {
    pub fn from_address_space(address_space: &AddressSpace) -> Result<Self, TrapError> {
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
            let offset_in_mapping = region.start - guest_start;

            // Keep only the payload bytes, not a full zero-padded copy of the
            // (potentially 512 MiB) mapping. hv_vm_allocate hands back lazily
            // zero-filled, HVF-managed memory, so we write just the payload at
            // its offset and let untouched pages fault in on demand. Building
            // and writing the whole region here is what pinned ~2 GiB resident
            // per guest process for mappings the guest never touches.
            let _ = mapped_len;
            let image = region.bytes().to_vec();

            mappings.push(GuestMapping {
                guest_start,
                ipa_start,
                mapped_size,
                offset_in_mapping,
                payload_size: region.bytes().len() as u64,
                perms: region.perms,
                shared: region.shared,
                image,
            });
        }

        Ok(Self {
            entry: address_space.entry(),
            initial_stack_pointer: address_space.initial_stack_pointer(),
            el0_trampoline_entry: address_space.el0_trampoline_entry(),
            el1_vectors_base: address_space.el1_vectors_base(),
            stage1_page_tables_base: address_space.stage1_page_tables_base(),
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

/// Process-global registry of dynamic MAP_SHARED-file alias mappings, so a vCPU
/// can re-establish one in ITS shared VM after fork dropped it.
///
/// Threads share ONE hv_vm, but `fork()` tears that VM down and rebuilds it from
/// ONLY the forking thread's per-thread `mappings` list (see `HvfInner::fork`).
/// A `guest_shared` alias mapped by a SIBLING thread is therefore lost from the
/// rebuilt VM, and any later access stage-2-faults (the go-build telemetry
/// counter: a counter file `mmap(MAP_SHARED)`'d on one thread, read via LDAR on
/// another after `go` forks `compile`). arm64 HVF has no stage-2 TLB shootdown,
/// so we cannot push the map to siblings eagerly; instead each vCPU LAZILY
/// re-maps on the fault, keyed off this registry.
///
/// Only `guest_shared` (MAP_SHARED-file) aliases are registered: their host
/// backing is a `MAP_SHARED` mmap that stays valid across fork and threads, so
/// re-`hv_vm_map`'ing the SAME host address is coherent. Private/anon aliases
/// are per-thread-snapshotted by the fork path and must NOT be re-shared here.
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
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy)]
struct AliasBacking {
    /// Guest VIRTUAL start of the alias (the syscall-path region key).
    start: u64,
    ipa: u64,
    host_addr: usize,
    size: usize,
    perms: u64,
    /// Whether the guest may WRITE the alias (a PROT_READ MAP_SHARED file alias
    /// must EFAULT a syscall write, not SIGBUS the host through the raw pointer).
    guest_writable: bool,
    /// True for a genuine guest `MAP_SHARED` FILE alias (cross-process coherent).
    /// Gates `shared_futex_host_addr`: only a guest_shared alias is a valid
    /// cross-process futex word — an anon arena alias resolved via the same index
    /// must NOT be treated as one.
    guest_shared: bool,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn alias_registry() -> &'static parking_lot::Mutex<Vec<AliasBacking>> {
    static CELL: std::sync::OnceLock<parking_lot::Mutex<Vec<AliasBacking>>> =
        std::sync::OnceLock::new();
    CELL.get_or_init(|| parking_lot::Mutex::new(Vec::new()))
}

/// Diagnostic: lazy-alias re-map count (the `debug-stats` feature logs every 256th).
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub static ALIAS_REMAP_COUNT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Record an alias (any `map_host_alias` region — file OR private anon) so the
/// stage-2 lazy remap and the syscall-path cross-thread fallback can resolve it
/// from any thread. Idempotent per IPA: a re-register (e.g. a forked child
/// overwriting the inherited PARENT host_addr with its private snapshot pointer)
/// replaces the entry.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn register_shared_alias(b: AliasBacking) {
    let mut reg = alias_registry().lock();
    if let Some(e) = reg.iter_mut().find(|e| e.ipa == b.ipa) {
        *e = b;
    } else {
        reg.push(b);
    }
}

/// Find the registered alias whose `hv_vm_map`'d IPA window contains `ipa`.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn lookup_shared_alias(ipa: u64) -> Option<AliasBacking> {
    alias_registry()
        .lock()
        .iter()
        .find(|e| ipa >= e.ipa && ipa < e.ipa.saturating_add(e.size as u64))
        .copied()
}

/// Find the registered alias whose guest-VA window FULLY contains `[va, va+len)`.
/// The cross-thread fallback's IPA key (`translate_va`) reads this thread's
/// software stage-1 model, which can lack a freshly-`MAP_FIXED`-committed high-VA
/// arena page that a sibling vCPU installed — even though `add_alias` already
/// registered the backing here, keyed by guest VA. The VA key resolves it.
///
/// Two safety rules make this never resolve to the WRONG backing (the failure the
/// `mapping_index_for_range` doc warns about):
/// - **Whole range in ONE entry**: a buffer straddling two aliases returns `None`
///   (→ EFAULT), never a partial backing.
/// - **Newest-first** (`.rev()`): a Go arena page is covered by BOTH the PROT_NONE
///   reservation entry AND the later `MAP_FIXED` commit; the commit is registered
///   last, and `add_alias`/`map_aliased` register the IPA they install into stage-1
///   in the same order — so the newest entry is exactly the backing the guest's own
///   page tables use.
///
/// The caller gates on `!range_no_access` so a still-PROT_NONE reservation page
/// (uncommitted) EFAULTs even though the reservation entry would contain its VA.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn lookup_shared_alias_by_va(va: u64, len: usize) -> Option<AliasBacking> {
    let end = va.saturating_add(len as u64);
    alias_registry()
        .lock()
        .iter()
        .rev()
        .find(|e| va >= e.start && end <= e.start.saturating_add(e.size as u64))
        .copied()
}

/// Drop the index entry for any alias whose guest-VA window overlaps
/// `[va, va+len)` — called on a guest `munmap` of a high-VA alias (the only point
/// the backing is actually freed), BEFORE the stage-1 invalidate, so a stale
/// `host_addr` is never resolved after the OwnedHostMapping unmaps it. A thread
/// exit LEAKS the backing (HvfTrapEngine::Drop is a no-op), so no unregister is
/// needed there. Keyed on the VA `start` because `munmap` supplies a VA.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn unregister_alias(va: u64, len: usize) {
    let end = va.saturating_add(len as u64);
    alias_registry()
        .lock()
        .retain(|e| e.start.saturating_add(e.size as u64) <= va || e.start >= end);
}

/// Bounds lazy alias remaps per backing IPA, not per guest-run interval.
///
/// Go's pprof mapping test can touch many distinct MAP_SHARED file aliases
/// before issuing another syscall; a small global cap turns the ninth valid
/// alias into SIGSEGV. Repeated faults on the same backing still terminate.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Default)]
struct AliasRemapLimiter {
    attempts_by_ipa: std::collections::HashMap<u64, u32>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl AliasRemapLimiter {
    const MAX_ATTEMPTS_PER_IPA: u32 = 8;

    fn allow(&mut self, ipa: u64) -> bool {
        let attempts = self.attempts_by_ipa.entry(ipa).or_default();
        if *attempts >= Self::MAX_ATTEMPTS_PER_IPA {
            return false;
        }
        *attempts += 1;
        true
    }
}

/// A sibling vCPU's mapping, published during a fork quiesce so the forking
/// thread can re-map the UNION of every sibling's regions into the rebuilt
/// PARENT VM — not just its own. Threads share ONE `hv_vm`, but `fork()` rebuilds
/// it from only the forking thread's `mappings`; a per-thread alias a SIBLING
/// established (e.g. a Go heap-arena chunk mmap'd at high-VA on that thread) is
/// otherwise dropped from the rebuilt VM and the parent translation-faults on it
/// (DC ZVA on a missing stage-2 entry — the concurrent-os/exec crash).
///
/// `host_addr`/`perms` are stored as `usize`/`u64` (not the raw pointer / MemPerms)
/// so the registry is `Send` across the publishing siblings and the consuming
/// forker. Safe because publication happens in `release_vcpu_for_fork`, after
/// which the sibling PARKS (holding its `OwnedHostMapping` alive) until the fork
/// completes — so the forker always re-maps a live backing (no use-after-free).
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy)]
struct SiblingForkMapping {
    start: u64,
    ipa: u64,
    end: u64,
    host_addr: usize,
    size: usize,
    perms: u64,
    guest_shared: bool,
    guest_writable: bool,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn sibling_fork_mappings() -> &'static parking_lot::Mutex<Vec<SiblingForkMapping>> {
    static CELL: std::sync::OnceLock<parking_lot::Mutex<Vec<SiblingForkMapping>>> =
        std::sync::OnceLock::new();
    CELL.get_or_init(|| parking_lot::Mutex::new(Vec::new()))
}

/// Drop all published sibling mappings. Called by the forker at quiesce start
/// (before kicking siblings) so each fork round starts from a clean set.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub fn clear_sibling_fork_mappings() {
    sibling_fork_mappings().lock().clear();
}

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
pub fn clear_sibling_fork_mappings() {}

/// Publish a quiescing sibling's regions so the forker re-maps them into the
/// rebuilt parent VM.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn publish_sibling_fork_mappings(regions: &[HvfMappedRegion]) {
    let mut reg = sibling_fork_mappings().lock();
    reg.reserve(regions.len());
    for m in regions {
        reg.push(SiblingForkMapping {
            start: m.start,
            ipa: m.ipa,
            end: m.end,
            host_addr: m.host_addr as usize,
            size: m.size,
            perms: u64::from(m.perms),
            guest_shared: m.guest_shared,
            guest_writable: m.guest_writable,
        });
    }
}

/// Process-global count of live HVF vCPUs (created minus destroyed). Pure
/// diagnostic: reported in the fork__quiesce phase-2 probe so a `carrick trace`
/// shows exactly how many vCPUs are alive when the forker calls hv_vm_destroy.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub static VCPU_LIVE: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(0);

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn vcpu_created() {
    VCPU_LIVE.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
}

/// vCPU admission gate for sibling guest threads.
///
/// Hypervisor.framework caps the number of vCPUs that may exist CONCURRENTLY in
/// a VM (`hv_vm_get_max_vcpu_count`, 64 on this class of host). carrick gives
/// every guest thread its own vCPU for its whole lifetime, so a guest that runs
/// more concurrent threads than the cap (CPython's `test_queue.test_many_threads`
/// spawns 50 producers + 50 consumers = 100) makes `hv_vcpu_create` return
/// HV_NO_RESOURCES (0xfae94005). Before this gate the clone() syscall had ALREADY
/// reported the new tid as success to the guest, so the thread that failed to get
/// a vCPU silently never ran — and any join on it deadlocked (→ 150s TIMEOUT).
///
/// Linux has no such cap: those 100 threads just run. To preserve that observable
/// behavior we DON'T fail clone; instead the sibling host-thread BLOCKS here until
/// a vCPU slot frees (another guest thread exits and destroys its vCPU). The guest
/// thread is created eagerly (clone succeeds, matching Linux); it simply may not
/// get scheduled onto a real vCPU until the live count drops below budget. Threads
/// that decouple through a queue (producers exit → free slots → queued consumers
/// admitted) therefore complete instead of deadlocking.
///
/// Only SIBLING-thread creation goes through the gate. The initial boot vCPU and
/// fork/execve REBUILDs must never block: a fork releases its vCPUs (count drops)
/// before rebuilding, and blocking a rebuild behind the gate it just emptied would
/// be a self-deadlock — those paths call `vcpu_create` directly.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod vcpu_gate {
    use std::sync::{Condvar, OnceLock};

    /// Slots we keep in reserve below the raw HVF cap so a multithreaded fork can
    /// always rebuild its quiesced siblings' vCPUs (each sibling releases then
    /// recreates one) and the forker has headroom, even while the gate is full.
    const RESERVE: i64 = 4;

    static BUDGET: OnceLock<i64> = OnceLock::new();
    static GATE_CV: Condvar = Condvar::new();

    /// HVF concurrent-vCPU budget for SIBLING threads (cap − reserve). Queried
    /// once; if the query fails we fall back to a conservative 60. The
    /// `Aarch64Vmm::vcpu_budget()` the bounded scheduler installs.
    ///
    /// NOTE: the old blocking `acquire()` admission gate is RETIRED — the bounded
    /// carrick-hal scheduler (installed for `vcpu_budget()`) does admission in the
    /// shared spawn path, and HVF's `wait_for_vcpu_slot` is now a no-op. `notify`
    /// is still poked on every vCPU destroy in case a future waiter parks on the
    /// condvar.
    pub(crate) fn budget() -> i64 {
        *BUDGET.get_or_init(|| {
            let mut max: u32 = 0;
            let rc = unsafe { applevisor_sys::hv_vm_get_max_vcpu_count(&mut max) };
            let cap = if rc == 0 && max > 0 { max as i64 } else { 64 };
            (cap - RESERVE).max(1)
        })
    }

    /// A vCPU was destroyed; wake any thread parked on the gate condvar.
    pub fn notify() {
        GATE_CV.notify_all();
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
/// per-thread, fork/execve rebuild. If only some vCPUs have it, the others trap
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
fn vcpu_destroyed() {
    VCPU_LIVE.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    // A slot freed: wake a sibling thread blocked in the admission gate.
    vcpu_gate::notify();
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
thread_local! {
    /// Per-sibling vCPU snapshot held between `release_vcpu_for_fork` and
    /// `rebuild_vcpu_after_fork` (both run on the same thread, around the fork
    /// quiesce park).
    static FORK_VCPU_SNAPSHOT: std::cell::RefCell<Option<VcpuSnapshot>> =
        const { std::cell::RefCell::new(None) };

}

/// Clear the published fork VM (child path; the child is single-threaded).
pub fn clear_rebuilt_vm_for_fork() {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        *rebuilt_vm_cell().lock() = None;
    }
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

/// Guest mmap-arena high-water mark (the dispatcher's `mmap_next`), published by
/// `handle_fork` just before forking. `clone_region_for_child` reads it to bound
/// the per-fork resident-page `mincore` scan of the 32 GiB arena window to the
/// used prefix `[LINUX_MMAP_BASE, this)` instead of scanning all 2M pages — the
/// dominant per-fork cost (a `mincore` over the full window measured ~470 ms).
/// `u64::MAX` (the default) means "unknown, scan the full region" so non-fork
/// callers and tests keep the original, always-correct behaviour.
pub static GUEST_ARENA_HIGH_WATER: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(u64::MAX);

/// Publish the arena high-water for the next fork's snapshot scan. Called by
/// `handle_fork` with `SyscallDispatcher::mmap_arena_high_water()`.
pub fn set_guest_arena_high_water(addr: u64) {
    GUEST_ARENA_HIGH_WATER.store(addr, std::sync::atomic::Ordering::SeqCst);
}

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

/// The HVF VM half: the live `applevisor` VM + the per-thread mapping list +
/// the process-shared PROT_NONE / page-table state, plus the fork/reclaim
/// bookkeeping. The `vcpu` lives separately in `HvfAarch64Vcpu` (the shared
/// engine owns it), so the trap loop, register walk, fork/execve/sibling
/// SEQUENCING and threaded lifecycle live ONCE in `carrick-aarch64`; the
/// methods here take the vCPU as a parameter when they touch it.
///
/// The VM is held in a no-op `ManuallyDrop` — exactly the old
/// `ManuallyDrop<HvfInner>` discipline, now per-half: once a single `fork(2)`
/// has run inside the trap loop, applevisor's `VirtualMachine` destructor no
/// longer matches HVF and panics ("no VM or vCPU available"). The process is
/// exiting either way; the kernel reclaims the VM.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) struct HvfVmState {
    _vm:
        std::mem::ManuallyDrop<applevisor::vm::VirtualMachineInstance<applevisor::vm::GicDisabled>>,
    mappings: Vec<HvfMappedRegion>,
    /// Per-thread snapshot stashed by the M:N reclaim between `reclaim_park`
    /// (snapshot + destroy this vCPU at a block point) and `reclaim_resume`
    /// (recreate + restore on wake). The SAME host thread saves then restores, so
    /// a plain field is safe and avoids serializing `VcpuSnapshot` through bytes.
    reclaim_snapshot: Option<VcpuSnapshot>,
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
    protections: std::sync::Arc<MemoryProtections>,
    /// Lazily-built editor over the EL1 stage-1 page-table image, used to give
    /// `mprotect`/`PROT_NONE`/`munmap` guest-visible semantics. Built from the
    /// page-table region's host backing on first edit; reset to `None` on
    /// fork/execve (fresh tables). SHARED across sibling vCPU threads (one HVF
    /// VM ⇒ one set of stage-1 tables): the mutex serializes edits so the
    /// spare-table allocator stays consistent, and `sync_to_host` orders the
    /// descriptor stores so a concurrent sibling hardware walk stays safe
    /// without quiescing.
    page_tables: std::sync::Arc<parking_lot::Mutex<Option<crate::page_table::PageTableManager>>>,
    /// The Linux syscall number (x8) and original arg0 (x0) of the most recent
    /// `svc` trap, captured before the dispatcher overwrites x0 with the retval.
    /// Used to restart an `EINTR`'d restartable syscall under SA_RESTART: the
    /// handler-injection path rewinds PC to the `svc` and restores this x0.
    last_syscall_nr: Option<u64>,
    last_syscall_orig_x0: u64,
    /// The id of THIS thread's live vCPU, tracked because the shared engine's
    /// `freeze_ram_for_fork` hook (`fork_prepare_and_teardown`) does NOT receive
    /// the vCPU — yet the parent must `hv_vcpu_destroy` its vCPU BEFORE
    /// `hv_vm_destroy` (and before `libc::fork`, or the child can't
    /// `hv_vm_create`). Updated on every vCPU (re)create (boot/clone/fork/exec/
    /// reclaim). NOT the applevisor wrapper — that lives in `HvfAarch64Vcpu`; this
    /// is only the raw id for the pre-fork teardown.
    vcpu_id: applevisor_sys::hv_vcpu_t,
    /// A `Send`/`Sync`-able kick handle for THIS thread's live vCPU (a `Weak` to
    /// the vCPU's liveness guard, so a kick after destroy is a safe no-op). The
    /// engine's `ThreadedEngine::kick_handle` routes through `self.vm` (NOT the
    /// vCPU), so HVF — whose kick mechanism is the vCPU's `hv_vcpus_exit` handle —
    /// stashes the handle here, refreshed on every vCPU (re)create.
    vcpu_handle: applevisor::vcpu::VcpuHandle,
    /// The vfork (`CLONE_VM`) flag for the NEXT fork: the child SHARES the
    /// parent's guest RAM instead of snapshotting private regions. Set by the
    /// engine's `set_vfork_share`, read by `fork_prepare_and_teardown`.
    vfork_share: bool,
    /// Fork descriptor stash, captured by `fork_prepare_and_teardown` (the
    /// pre-`libc::fork` half) and consumed by `fork_rebuild` (the post-fork
    /// half). The parent re-maps `mapping_descs` (its own buffers); the child
    /// re-maps `child_descs` (the private snapshots / shared originals). Only
    /// populated between the two halves of a single fork.
    fork_mapping_descs: Vec<ForkMappingDesc>,
    fork_child_descs: Vec<ForkMappingDesc>,
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
    /// True for a genuine guest `MAP_SHARED` file mapping (`map_shared_file`).
    /// Guest memory is host-`MAP_SHARED` for HVF coherence, so fork(2) does
    /// NOT COW-isolate it; the `fork` path takes an explicit private snapshot
    /// of every region EXCEPT these — a guest `MAP_SHARED` file mapping must
    /// stay shared across guest fork (POSIX), so parent and child keep mapping
    /// the SAME host buffer. (LTP's test framework relies on this: the test
    /// runs in a forked child that writes pass/fail counts to a `MAP_SHARED`
    /// results file the parent then reads.)
    guest_shared: bool,
    /// The guest's INTENDED writability (Linux PROT_WRITE), tracked separately
    /// from `perms` — alias regions force `perms` to RWX for the HVF stage-2
    /// translation quirk, so it cannot be used to detect a read-only mapping.
    /// The syscall write-path (`write_guest_bytes_checked`) rejects a write into
    /// a non-writable mapping with EFAULT instead of faulting the host (SIGBUS on
    /// a PROT_READ MAP_SHARED file alias) or corrupting a carrick-owned
    /// `write:false` region. (audit M1; probe `rosharedbus`)
    guest_writable: bool,
}

/// A copyable projection of the scalar fields of an [`HvfMappedRegion`] that the
/// syscall-path accessors actually read (`start`/`end`/`ipa`/`host_addr`/`size`/
/// `guest_writable`/`guest_shared`). [`HvfInner::mapping_for_range`] returns this
/// by value instead of `&HvfMappedRegion` so a lookup that resolves through the
/// PROCESS-SHARED `alias_registry` fallback (a high-VA alias another thread
/// mapped, absent from THIS thread's per-thread `mappings`) can synthesize a view
/// with no borrow into `self.mappings`. The copy loops compute
/// `host_addr + (addr - start)`, so a synthetic view sets `start` to the alias VA
/// base and `host_addr` to its backing base — identical offset math to a real
/// region.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy)]
struct MappingView {
    start: u64,
    end: u64,
    ipa: u64,
    host_addr: *mut u8,
    guest_writable: bool,
    guest_shared: bool,
}

/// Snapshot of vCPU register state captured before fork(2). The child restores
/// from this after rebuilding the HVF context so it resumes exactly where the
/// parent left off (post-clone syscall).
///
/// The architectural register file lives in the ISA-neutral
/// [`Aarch64VcpuSnapshot`] `core` — the SAME type the shared engine and the KVM
/// lane trade in — so the HVF lane no longer duplicates those 21 fields. The
/// only thing HVF carries on top is the backend-owned `last_exit_class` (the
/// trap class latched at the exit the snapshot was taken on), which the neutral
/// type deliberately does NOT model. This is the "neutral core + backend extra"
/// shape: the per-VMM HVF↔neutral mapping (CPSR ↔ `core.pstate`, the `*_EL1`
/// sysreg names ↔ their neutral aliases, and HVF seeding SP_EL1 from
/// `core.sp_el0` since it captures no separate SP_EL1) lives in
/// `snapshot_vcpu_from`/`restore_vcpu*`. The TTBR1_EL1 (Rosetta x86-64 high-half
/// root) / ACTLR_EL1 (Rosetta EnTSO) / TPIDR*_EL0 (musl TLS, vDSO/rseq) capture
/// rationales are documented on the neutral fields.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Debug, Clone)]
pub(crate) struct VcpuSnapshot {
    /// The ISA-neutral architectural register file (GPRs, EL1 sysregs, V-regs, FP
    /// control) shared with the engine and the KVM lane.
    pub(crate) core: Aarch64VcpuSnapshot,
    /// Backend-only: the HVF trap class latched at the exit this snapshot was
    /// taken on. Engine-owned and intentionally absent from the neutral snapshot;
    /// restored onto the rebuilt vCPU's `last_exit_class` so a reclaim/fork
    /// resumes with the correct exit-class context.
    pub(crate) last_exit_class: u64,
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
#[derive(Debug, Clone, Copy)]
struct ThreadMappingDesc {
    start: u64,
    ipa: u64,
    end: u64,
    host_addr: *mut u8,
    size: usize,
    perms: applevisor::memory::MemPerms,
    guest_shared: bool,
    guest_writable: bool,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl ThreadMappingDesc {
    /// Project a live region into a `Send`-safe descriptor for a `ThreadSpec` (the
    /// sibling thread mirrors it as an UNOWNED `HvfMappedRegion`). Called by
    /// `HvfVmState::build_thread_spec` (the per-VMM `build_sibling_builder`).
    fn from_region(region: &HvfMappedRegion) -> Self {
        Self {
            start: region.start,
            ipa: region.ipa,
            end: region.end,
            host_addr: region.host_addr,
            size: region.size,
            perms: region.perms,
            guest_shared: region.guest_shared,
            guest_writable: region.guest_writable,
        }
    }

    fn into_unowned_region(self) -> HvfMappedRegion {
        HvfMappedRegion {
            start: self.start,
            ipa: self.ipa,
            end: self.end,
            host_addr: self.host_addr,
            size: self.size,
            perms: self.perms,
            memory: None,
            host_mapping: None,
            guest_shared: self.guest_shared,
            guest_writable: self.guest_writable,
        }
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
struct ForkMappingDesc {
    start: u64,
    ipa: u64,
    end: u64,
    host: ForkMappingHost,
    size: usize,
    perms: applevisor::memory::MemPerms,
    guest_shared: bool,
    guest_writable: bool,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
enum ForkMappingHost {
    Borrowed(*mut u8),
    Owned(crate::host_mapping::OwnedHostMapping),
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl ForkMappingHost {
    fn ptr(&self) -> *mut u8 {
        match self {
            ForkMappingHost::Borrowed(ptr) => *ptr,
            ForkMappingHost::Owned(mapping) => mapping.as_ptr(),
        }
    }

    fn into_owned(self) -> Option<crate::host_mapping::OwnedHostMapping> {
        match self {
            ForkMappingHost::Borrowed(_) => None,
            ForkMappingHost::Owned(mapping) => Some(mapping),
        }
    }
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
pub struct ThreadSpec {
    vm: applevisor::vm::VirtualMachineInstance<applevisor::vm::GicDisabled>,
    mappings: Vec<ThreadMappingDesc>,
    protections: std::sync::Arc<MemoryProtections>,
    /// Shared stage-1 page-table editor (one VM ⇒ one set of tables; siblings
    /// share this so concurrent edits serialize through its mutex).
    page_tables: std::sync::Arc<parking_lot::Mutex<Option<crate::page_table::PageTableManager>>>,
}

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
impl HvfVmState {
    /// Create the VM + the (one) vCPU, map the guest address space, program the
    /// initial vCPU sysregs/trampoline, and return the `(state_without_vcpu,
    /// vcpu)` pair the shared engine owns separately. Consolidates the old
    /// `HvfTrapEngine::new_platform` + `map_plan` + the initial-PC/SPSR/SCTLR/
    /// TTBR/CPACR/CNTKCTL/VBAR/SP/vdso setup into one constructor.
    pub(crate) fn new_with_plan(
        plan: &GuestMappingPlan,
    ) -> Result<(HvfVmState, applevisor::vcpu::Vcpu), TrapError> {
        use applevisor::prelude::*;

        let max_ipa = VirtualMachineConfig::get_max_ipa_size().map_err(hvf_error)?;
        let mut config = VirtualMachineConfig::new();
        config.set_ipa_size(max_ipa).map_err(hvf_error)?;
        let vm = virtual_machine_with_private_signals_blocked(config).map_err(hvf_error)?;
        let vcpu = vm.vcpu_create().map_err(hvf_error)?;
        vcpu_created();
        enable_el0_counter_access(vcpu.id());

        let mut state = HvfVmState {
            _vm: std::mem::ManuallyDrop::new(vm),
            mappings: Vec::new(),
            reclaim_snapshot: None,
            last_exit_class: 0,
            last_fault_esr: 0,
            is_forked_child: false,
            forked_no_exec: false,
            protections: std::sync::Arc::new(MemoryProtections::default()),
            page_tables: std::sync::Arc::new(parking_lot::Mutex::new(None)),
            last_syscall_nr: None,
            last_syscall_orig_x0: 0,
            vcpu_id: vcpu.id(),
            vcpu_handle: vcpu.get_handle(),
            vfork_share: false,
            fork_mapping_descs: Vec::new(),
            fork_child_descs: Vec::new(),
        };

        for mapping in &plan.mappings {
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
            let region = map_region_raw(mapping)?;
            state.mappings.push(region);
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
            // Running at EL1h, so seed both SP_EL1 (current SP) and SP_EL0
            // (in case anything ever drops back to EL0).
            vcpu.set_sys_reg(SysReg::SP_EL1, stack_pointer)
                .map_err(hvf_error)?;
            vcpu.set_sys_reg(SysReg::SP_EL0, stack_pointer)
                .map_err(hvf_error)?;
        }
        // Fill the vDSO vvar page so __kernel_clock_gettime can derive time from
        // CNTVCT_EL0 in userspace. Best-effort: if the page isn't mapped (a load
        // path without with_vdso) just skip — the guest falls back to syscalls.
        state.populate_vdso_data_page();
        Ok((state, vcpu))
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
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[inline]
unsafe fn volatile_copy_from_guest(src: *const u8, dst: *mut u8, len: usize) {
    const W: usize = core::mem::size_of::<usize>();
    let mut i = 0usize;
    unsafe {
        // Head: byte-volatile until the guest pointer is word-aligned.
        while i < len && !(src.add(i) as usize).is_multiple_of(W) {
            dst.add(i).write(src.add(i).read_volatile());
            i += 1;
        }
        // Bulk: aligned word-volatile reads from guest, unaligned plain writes
        // to the private host buffer.
        while i + W <= len {
            let word = (src.add(i) as *const usize).read_volatile();
            (dst.add(i) as *mut usize).write_unaligned(word);
            i += W;
        }
        // Tail.
        while i < len {
            dst.add(i).write(src.add(i).read_volatile());
            i += 1;
        }
    }
}

/// Volatile copy INTO guest-shared memory. See [`volatile_copy_from_guest`] for
/// why volatile is required and the word-acceleration rationale. Here the guest
/// (`dst`) side takes aligned word-sized `write_volatile`; the private host
/// `src` uses plain unaligned reads.
///
/// SAFETY: `src` must be valid for reads of `len` bytes and `dst` valid for
/// writes of `len` bytes; the two regions must not overlap.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[inline]
unsafe fn volatile_copy_to_guest(src: *const u8, dst: *mut u8, len: usize) {
    const W: usize = core::mem::size_of::<usize>();
    let mut i = 0usize;
    unsafe {
        // Head: byte-volatile until the guest pointer is word-aligned.
        while i < len && !(dst.add(i) as usize).is_multiple_of(W) {
            dst.add(i).write_volatile(src.add(i).read());
            i += 1;
        }
        // Bulk: unaligned plain reads from the private host buffer, aligned
        // word-volatile writes to guest.
        while i + W <= len {
            let word = (src.add(i) as *const usize).read_unaligned();
            (dst.add(i) as *mut usize).write_volatile(word);
            i += W;
        }
        // Tail.
        while i < len {
            dst.add(i).write_volatile(src.add(i).read());
            i += 1;
        }
    }
}

#[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
mod volatile_copy_tests {
    use super::{volatile_copy_from_guest, volatile_copy_to_guest};

    // Exercise every src/dst alignment combo and a spread of lengths (crossing
    // the word boundary and the head/bulk/tail seams), comparing against the
    // obvious byte copy and asserting no overrun past `len`.
    const LENS: &[usize] = &[0, 1, 7, 8, 9, 15, 16, 17, 31, 63, 64, 65, 255, 256];

    #[test]
    fn from_guest_matches_reference() {
        let src: Vec<u8> = (0..512u32)
            .map(|i| (i.wrapping_mul(31).wrapping_add(7)) as u8)
            .collect();
        for &len in LENS {
            for s in 0..8usize {
                for d in 0..8usize {
                    if s + len > src.len() {
                        continue;
                    }
                    let mut dst = vec![0xCDu8; d + len + 1];
                    unsafe {
                        volatile_copy_from_guest(src.as_ptr().add(s), dst.as_mut_ptr().add(d), len);
                    }
                    assert_eq!(&dst[d..d + len], &src[s..s + len], "len={len} s={s} d={d}");
                    assert_eq!(dst[d + len], 0xCD, "overrun len={len} d={d}");
                }
            }
        }
    }

    #[test]
    fn to_guest_matches_reference() {
        let src: Vec<u8> = (0..512u32)
            .map(|i| (i.wrapping_mul(17).wrapping_add(3)) as u8)
            .collect();
        for &len in LENS {
            for s in 0..8usize {
                for d in 0..8usize {
                    if s + len > src.len() {
                        continue;
                    }
                    let mut dst = vec![0xABu8; d + len + 1];
                    unsafe {
                        volatile_copy_to_guest(src.as_ptr().add(s), dst.as_mut_ptr().add(d), len);
                    }
                    assert_eq!(&dst[d..d + len], &src[s..s + len], "len={len} s={s} d={d}");
                    assert_eq!(dst[d + len], 0xAB, "overrun len={len} d={d}");
                }
            }
        }
    }
}

/// Strip a 16-bit pointer tag (bits 63:48) from a guest virtual address.
/// Apple Rosetta tags pointers in the top 16 bits (a 48-bit `TaggedPointer`
/// value space, broader than the 8-bit hardware TBI), so syscall-path region
/// lookups must mask the tag to resolve a tagged pointer to its 48-bit backing
/// mapping. Pairs with TCR_EL1.TBI0/TBI1 (hardware ignores the top byte for the
/// guest's own accesses) and the mmap-hint strip in dispatch/mem.rs. A no-op
/// for native (top-byte-zero) guests.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[inline]
fn strip_pointer_tag(address: u64) -> u64 {
    address & 0x0000_FFFF_FFFF_FFFF
}

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
        crate::vcpu_kick::VcpuKickHandle::new(self.vcpu_handle.clone())
    }

    /// Set the vfork (`CLONE_VM`) flag for the NEXT fork.
    pub(crate) fn set_vfork_share(&mut self, share_vm: bool) {
        self.vfork_share = share_vm;
    }

    /// Create a fresh vCPU bound to this VM (the boot/clone/fork/reclaim
    /// vcpu_create; admission is the bounded scheduler's job, NOT this path).
    pub(crate) fn add_vcpu(&mut self) -> Result<applevisor::vcpu::Vcpu, TrapError> {
        let vcpu = self._vm.vcpu_create().map_err(hvf_error)?;
        vcpu_created();
        enable_el0_counter_access(vcpu.id());
        self.vcpu_id = vcpu.id();
        self.vcpu_handle = vcpu.get_handle();
        Ok(vcpu)
    }

    /// Host pointer backing `[gpa, gpa+len)`, or `None` if unmapped. The
    /// engine's `GuestMemory` copies through this; HVF resolves it via the same
    /// per-thread mapping walk (with the stage-1-IPA disambiguation) the
    /// syscall path uses.
    pub(crate) fn host_ptr(&self, gpa: u64, len: usize) -> Option<*mut u8> {
        let mapping = self.mapping_for_range(gpa, len.max(1))?;
        let offset = (gpa.wrapping_sub(mapping.start)) as usize;
        Some(unsafe { mapping.host_addr.add(offset) })
    }

    /// Copy `bytes` into guest physical memory at `gpa` (raw GPA, no PROT_NONE
    /// gate, no permission check — the engine's run-elf / page-table seed path).
    pub(crate) fn write_gpa(&self, gpa: u64, bytes: &[u8]) -> Result<(), MemoryError> {
        let Some(mapping) = self.mapping_for_range(gpa, bytes.len().max(1)) else {
            return Err(MemoryError::OutOfBounds {
                address: gpa,
                length: bytes.len(),
            });
        };
        let offset = (gpa.wrapping_sub(mapping.start)) as usize;
        unsafe {
            volatile_copy_to_guest(bytes.as_ptr(), mapping.host_addr.add(offset), bytes.len());
        }
        Ok(())
    }

    /// Read `len` bytes of live guest memory at guest-physical `gpa` (no VA
    /// translation, no PROT_NONE gate).
    pub(crate) fn read_gpa(&self, gpa: u64, len: usize) -> Result<Vec<u8>, MemoryError> {
        let Some(mapping) = self.mapping_for_range(gpa, len.max(1)) else {
            return Err(MemoryError::OutOfBounds {
                address: gpa,
                length: len,
            });
        };
        let offset = (gpa.wrapping_sub(mapping.start)) as usize;
        let mut out = vec![0u8; len];
        unsafe {
            volatile_copy_from_guest(mapping.host_addr.add(offset), out.as_mut_ptr(), len);
        }
        Ok(out)
    }

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
            applevisor_sys::hv_vm_map(host as *mut std::ffi::c_void, ipa, len as usize, perms_raw)
        };
        if r != 0 {
            return Err(TrapError::Hypervisor(format!(
                "hv_vm_map(ipa=0x{ipa:x}, size={len}) failed: 0x{r:x}"
            )));
        }
        Ok(())
    }

    /// The HVF-only lazy high-VA alias re-map: a forked child rebuilt its VM
    /// from only the forking thread's mappings, dropping a `guest_shared` alias a
    /// sibling thread mapped; re-`hv_vm_map` the registered host backing into
    /// THIS VM so the faulting instruction re-executes cleanly. Returns true iff
    /// it remapped. (The engine's `next_syscall` already runs the bounded in-loop
    /// remap; this is the `handle_memory_exit` hook surface — kept for the trait,
    /// driven on the rare path the in-loop remap doesn't cover.)
    pub(crate) fn try_lazy_alias_remap(&mut self, gpa: u64, va: u64) -> bool {
        let fault_ipa = if gpa != 0 {
            gpa
        } else {
            va.wrapping_sub(crate::memory::LINUX_HIGH_VA_THRESHOLD)
                .wrapping_add(crate::memory::LINUX_ALIAS_IPA_BASE)
        };
        let Some(b) = lookup_shared_alias(fault_ipa) else {
            return false;
        };
        // SAFETY: `host_addr` is a live MAP_SHARED mmap registered by
        // `add_alias`; re-mapping the same host range to the same IPA in this VM
        // is idempotent (a nonzero rc — already mapped by a racing sibling — is
        // fine).
        let _ = unsafe {
            applevisor_sys::hv_vm_map(b.host_addr as *mut std::ffi::c_void, b.ipa, b.size, b.perms)
        };
        crate::probes::hv_vm_map_alias(va, b.ipa, b.size as u64, 0, self.forked_no_exec as i32);
        true
    }

    /// Back a dynamic high-VA `mmap` (`DispatchOutcome::MapHostAlias`): allocate
    /// the low alias IPA, `hv_vm_map` the host file/anon backing there, register
    /// the alias process-globally, and add the per-thread region — returning the
    /// `(gpa = ipa, writable)` the engine then threads into the SHARED stage-1
    /// `map_aliased`. RWX so a JIT (Rosetta) can write+execute it; the guest may
    /// `mprotect` afterwards.
    ///
    /// Mirrors the old `map_host_alias`, with the IPA derived HERE (the dispatcher
    /// no longer supplies it through the shared `map_host_alias` seam): the same
    /// `crate::memory::alloc_alias_ipa` the dispatcher used.
    pub(crate) fn add_alias(
        &mut self,
        va: u64,
        ipa: u64,
        len: u64,
        payload: &[u8],
        file: Option<(libc::c_int, libc::off_t, libc::c_int)>,
    ) -> Result<(u64, bool), TrapError> {
        // Use the IPA the DISPATCHER already allocated from the global alias arena
        // (`crate::memory::alloc_alias_ipa`) and passed through `MapHostAlias` — do
        // NOT re-allocate here (that double-consumed the arena and desynced the
        // dispatcher's VA→IPA bookkeeping, the dynamic-loader fault). The returned
        // gpa IS this ipa (HVF's stage-2 maps the host at the IPA, identity gpa==ipa).
        // hv_vm_map requires a 16 KiB-granular size; round the HOST mapping up
        // to the HVF granule. The stage-1 `map_aliased` (the engine, on the exact
        // `len`) below still maps only the guest's page-aligned request, so a
        // sub-16 KiB mmap never maps extra 4 KiB guest pages into a neighbouring
        // region's page-table entries (which would redirect that region's
        // fetches/reads to the wrong IPA — the amd64 Rosetta JIT undefined-
        // instruction bug).
        let hvf_len = align_up(len, HVF_PAGE_SIZE)?;
        let size = usize::try_from(hvf_len).map_err(|_| TrapError::MappingTooLarge(len))?;
        // The host page is mapped at the guest's actual prot (map_shared_file),
        // so a PROT_READ file alias has a read-only host backing. Track the
        // guest-intended writability so the syscall write-path returns EFAULT
        // instead of SIGBUS-ing the host. Anon aliases are RW-backed.
        let alias_guest_writable = match file {
            Some((_, _, prot)) => prot & libc::PROT_WRITE != 0,
            None => true,
        };
        let host_mapping = match file {
            // Live MAP_SHARED file: back the guest region with the file's page
            // cache directly, so writes are coherent with other openers and
            // survive fork. The dispatcher handed us a dup'd fd it owns; mmap
            // takes its own reference, so close the dup once mapped.
            Some((fd, offset, prot)) => {
                let m = crate::host_mapping::OwnedHostMapping::map_shared_file(fd, offset, size, prot)
                    .map_err(|e| {
                        unsafe { libc::close(fd) };
                        TrapError::Hypervisor(format!(
                            "alias MAP_SHARED file (fd={fd} off={offset} size={size} prot={prot}) failed: {e}"
                        ))
                    })?;
                unsafe { libc::close(fd) };
                m
            }
            None => crate::host_mapping::OwnedHostMapping::map_shared_anon(
                size,
                crate::host_mapping::HostMappingKind::PrivateAnon,
            )
            .map_err(|e| TrapError::Hypervisor(format!("alias mmap (size={size}) failed: {e}")))?,
        };
        let host = host_mapping.as_ptr();
        let size = host_mapping.len();
        // Seed the file content (empty for anon — the anon mapping is zeroed; a
        // live MAP_SHARED file mapping is already backed by the page cache).
        if file.is_none() && !payload.is_empty() {
            let n = payload.len().min(size);
            unsafe { std::ptr::copy_nonoverlapping(payload.as_ptr(), host, n) };
        }
        // Alias mappings keep permissive stage-2 rights; guest-visible
        // protections are enforced in stage-1 and adjusted by mprotect.
        let perms = hvf_perms(SegmentPerms {
            read: true,
            write: true,
            execute: true,
        });
        let r = unsafe { applevisor_sys::hv_vm_map(host.cast(), ipa, size, u64::from(perms)) };
        crate::probes::hv_vm_map_alias(va, ipa, size as u64, r as i32, self.forked_no_exec as i32);
        if r != 0 {
            return Err(TrapError::Hypervisor(format!(
                "hv_vm_map alias va=0x{va:x} ipa=0x{ipa:x} size={size} failed: 0x{r:x}"
            )));
        }
        let guest_shared = host_mapping.guest_shared();
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
            size,
            perms: u64::from(perms),
            guest_writable: alias_guest_writable,
            guest_shared,
        });
        self.mappings.push(HvfMappedRegion {
            start: va,
            ipa,
            end: va + size as u64,
            host_addr: host,
            size,
            perms,
            memory: None,
            host_mapping: Some(host_mapping),
            guest_shared,
            guest_writable: alias_guest_writable,
        });
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
    fn range_no_access(&self, address: u64, length: usize) -> bool {
        self.protections.range_no_access(address, length)
    }

    pub(crate) fn read_guest_bytes(
        &self,
        address: u64,
        length: usize,
    ) -> Result<Vec<u8>, MemoryError> {
        let mut bytes = vec![0u8; length];
        self.read_guest_bytes_into(address, &mut bytes)?;
        Ok(bytes)
    }

    /// No-alloc core of [`Self::read_guest_bytes`]: `volatile`-copy `dst.len()` bytes
    /// of guest memory at `address` straight into `dst`. Same checks, chunked
    /// mapping walk, and trace probes as the allocating form.
    pub(crate) fn read_guest_bytes_into(
        &self,
        address: u64,
        dst: &mut [u8],
    ) -> Result<(), MemoryError> {
        let length = dst.len();
        // PROT_NONE gated once in the default `GuestMemory::read_bytes`/`read_into`.
        let mut copied = 0usize;
        while copied < length {
            let (chunk_address, chunk_len) = Self::guest_copy_chunk(address, copied, length)?;
            // For a `repoint_private` overlay VA the region+offset are keyed on the
            // translated overlay IPA, not the VA (see `syscall_buffer_lookup_addr`).
            // Identity otherwise — no walk. PROT_NONE was already gated on the VA.
            let lookup_address = self.syscall_buffer_lookup_addr(chunk_address, chunk_len);
            let (mapping_start, mapping_end, mapping_ipa, host_addr) = {
                let Some(mapping) = self.mapping_for_range(lookup_address, chunk_len) else {
                    return Err(MemoryError::OutOfBounds { address, length });
                };
                (mapping.start, mapping.end, mapping.ipa, mapping.host_addr)
            };
            self.emit_guest_mem_copy_decision(
                crate::probes::guest_mem_dir::READ_GUEST,
                chunk_address,
                chunk_len,
                mapping_start,
                mapping_end,
                mapping_ipa,
            );
            // Read directly out of the host buffer. Works for both
            // applevisor-owned mappings (the parent case) and raw mappings
            // we re-created in a forked child via hv_vm_map.
            let chunk_offset = (lookup_address - mapping_start) as usize;
            unsafe {
                volatile_copy_from_guest(
                    host_addr.add(chunk_offset),
                    dst.as_mut_ptr().add(copied),
                    chunk_len,
                );
            }
            copied += chunk_len;
        }
        crate::probes::guest_mem_bytes(
            crate::probes::guest_mem_dir::READ_GUEST,
            strip_pointer_tag(address),
            dst,
        );
        Ok(())
    }

    /// Host VA of `address` iff it lives in a host-`MAP_SHARED` guest region
    /// (the boot-mapped shared aperture; shared across carrick processes via
    /// the inherited MAP_SHARED backing). Used to back a cross-process futex
    /// with the public `os_sync_wait_on_address` API (see `crate::ulock`).
    pub(crate) fn shared_futex_host_addr(&self, address: u64) -> Option<usize> {
        // Fast path: the region is in THIS thread's mapping list.
        if let Some(mapping) = self.mapping_for_range(address, 4) {
            if !mapping.guest_shared {
                return None; // present but private/anon — not a cross-process futex
            }
            let offset = (address - mapping.start) as usize;
            return Some(unsafe { mapping.host_addr.add(offset) } as usize);
        }
        // Slow path: a fork rebuild replayed only the forking thread's mappings,
        // so a MAP_SHARED-file alias mapped by another thread is absent from THIS
        // thread's list — yet the guest CPU still reaches it via the lazy on-fault
        // re-map keyed off the process-global alias registry. Recover the host
        // backing from that same registry so a dispatcher-side futex-word read in
        // a forked child doesn't spuriously EFAULT (→ glibc futex_fatal_error /
        // SIGABRT, seen in CPython multiprocessing SyncManager teardown waiting on
        // a shared semaphore). High-VA aliases sit at the deterministic
        // ipa = va - HIGH_VA_THRESHOLD + ALIAS_IPA_BASE (the exact mapping the
        // fault handler inverts).
        if address >= crate::memory::LINUX_HIGH_VA_THRESHOLD {
            let ipa = address
                .wrapping_sub(crate::memory::LINUX_HIGH_VA_THRESHOLD)
                .wrapping_add(crate::memory::LINUX_ALIAS_IPA_BASE);
            if let Some(b) = lookup_shared_alias(ipa) {
                let offset = (ipa - b.ipa) as usize;
                return Some(b.host_addr + offset);
            }
        }
        None
    }

    pub(crate) fn write_guest_bytes(
        &mut self,
        address: u64,
        bytes: &[u8],
    ) -> Result<(), MemoryError> {
        let length = bytes.len();
        // PROT_NONE gated once in the default `GuestMemory::write_bytes`.
        self.validate_guest_write_range(address, length, false)?;
        let mut copied = 0usize;
        while copied < length {
            let (chunk_address, chunk_len) = Self::guest_copy_chunk(address, copied, length)?;
            // See `read_guest_bytes_into`: a `repoint_private` overlay VA resolves
            // its region+offset via the translated overlay IPA, so a syscall write
            // lands in the PRIVATE overlay backing the guest reads, not the shared
            // aperture. Identity otherwise; PROT_NONE already gated on the VA.
            let lookup_address = self.syscall_buffer_lookup_addr(chunk_address, chunk_len);
            let (mapping_start, mapping_end, mapping_ipa, host_addr) = {
                let Some(mapping) = self.mapping_for_range_mut(lookup_address, chunk_len) else {
                    return Err(MemoryError::OutOfBounds { address, length });
                };
                (mapping.start, mapping.end, mapping.ipa, mapping.host_addr)
            };
            self.emit_guest_mem_copy_decision(
                crate::probes::guest_mem_dir::WRITE_GUEST,
                chunk_address,
                chunk_len,
                mapping_start,
                mapping_end,
                mapping_ipa,
            );
            let chunk_offset = (lookup_address - mapping_start) as usize;
            unsafe {
                volatile_copy_to_guest(
                    bytes.as_ptr().add(copied),
                    host_addr.add(chunk_offset),
                    chunk_len,
                );
            }
            copied += chunk_len;
        }
        crate::probes::guest_mem_bytes(
            crate::probes::guest_mem_dir::WRITE_GUEST,
            strip_pointer_tag(address),
            bytes,
        );
        Ok(())
    }

    /// Host pointer for a contiguous guest range (zero-copy send source), or
    /// `None` if the whole range isn't within one mapped region. Mirrors
    /// `read_guest_bytes`'s address handling (raw no-access guard, tag strip)
    /// but returns the backing pointer instead of copying. See
    /// `GuestMemory::host_ptr_for_read`.
    pub(crate) fn host_ptr_for_read(&self, address: u64, length: usize) -> Option<*const u8> {
        if length == 0 || self.range_no_access(address, length) {
            return None;
        }
        let stripped = strip_pointer_tag(address);
        // `repoint_private` overlay VAs look up + offset via the translated overlay
        // IPA (see `syscall_buffer_lookup_addr`); identity otherwise (no walk).
        let lookup = self.syscall_buffer_lookup_addr(stripped, length);
        let mapping = self.mapping_for_range(lookup, length)?;
        let offset = (lookup - mapping.start) as usize;
        Some(unsafe { mapping.host_addr.add(offset) } as *const u8)
    }

    /// Host pointer for a contiguous guest range as a zero-copy recv DESTINATION,
    /// or `None` if the range isn't one mapped region OR isn't guest-writable.
    /// The guest-writable requirement mirrors `write_guest_bytes_checked`: a
    /// guest read-only mapping must EFAULT via the checked copy path, not be
    /// written by the kernel through a raw host pointer. See
    /// `GuestMemory::host_ptr_for_write`.
    pub(crate) fn host_ptr_for_write(&mut self, address: u64, length: usize) -> Option<*mut u8> {
        if length == 0 || self.range_no_access(address, length) {
            return None;
        }
        let stripped = strip_pointer_tag(address);
        if self
            .validate_guest_write_range(stripped, length, true)
            .is_err()
        {
            return None;
        }
        // `repoint_private` overlay VAs look up + offset via the translated overlay
        // IPA (see `syscall_buffer_lookup_addr`); identity otherwise (no walk).
        let lookup = self.syscall_buffer_lookup_addr(stripped, length);
        let mapping = self.mapping_for_range(lookup, length)?;
        let offset = (lookup - mapping.start) as usize;
        Some(unsafe { mapping.host_addr.add(offset) })
    }

    /// Zero the PHYSICAL backing of `[address, address+length)`, bypassing BOTH
    /// the `range_no_access` and the writability checks (see
    /// `GuestMemory::zero_backing`). Used to scrub a reused anon region whose
    /// stale content must never reach the guest: a region just reclaimed from
    /// `munmap` (stage-1-invalidated → `range_no_access`) or mapped `PROT_NONE`
    /// has no write permission, so `write_guest_bytes`/`_checked` deliberately
    /// fault and cannot scrub it. The arena backing is always mapped (munmap only
    /// stage-1-invalidates; arm64 HVF has no stage-2 flush), so the lookup
    /// succeeds for the reclaimed region.
    pub(crate) fn zero_guest_backing(
        &mut self,
        address: u64,
        length: usize,
    ) -> Result<(), MemoryError> {
        let Some(mapping) = self.mapping_for_range_mut(address, length) else {
            return Err(MemoryError::OutOfBounds { address, length });
        };
        let offset = (address - mapping.start) as usize;
        unsafe {
            core::ptr::write_bytes(mapping.host_addr.add(offset), 0u8, length);
        }
        Ok(())
    }

    /// Permission-respecting write used by the SYSCALL path
    /// (`GuestMemory::write_bytes`): a write into a non-writable mapping returns
    /// EFAULT (`MemoryError::OutOfBounds`) instead of either faulting the host
    /// (SIGBUS on a genuinely read-only `MAP_SHARED` file alias) or silently
    /// corrupting a carrick-owned region (the EL1 page tables / vector table are
    /// registered `write:false`). Carrick-internal writes (vdso vvar, sigframe,
    /// bootstrap) deliberately use the unchecked `write_guest_bytes`.
    /// (audit M1; probe `rosharedbus`)
    pub(crate) fn write_guest_bytes_checked(
        &mut self,
        address: u64,
        bytes: &[u8],
    ) -> Result<(), MemoryError> {
        let length = bytes.len();
        // PROT_NONE gated once in the default `GuestMemory::write_bytes`.
        self.validate_guest_write_range(address, length, true)?;
        let mut copied = 0usize;
        while copied < length {
            let (chunk_address, chunk_len) = Self::guest_copy_chunk(address, copied, length)?;
            // `repoint_private` overlay VAs resolve region+offset via the translated
            // overlay IPA (see `syscall_buffer_lookup_addr`); identity otherwise.
            let lookup_address = self.syscall_buffer_lookup_addr(chunk_address, chunk_len);
            let (mapping_start, mapping_end, mapping_ipa, host_addr) = {
                let Some(mapping) = self.mapping_for_range_mut(lookup_address, chunk_len) else {
                    return Err(MemoryError::OutOfBounds { address, length });
                };
                (mapping.start, mapping.end, mapping.ipa, mapping.host_addr)
            };
            self.emit_guest_mem_copy_decision(
                crate::probes::guest_mem_dir::WRITE_GUEST_CHECKED,
                chunk_address,
                chunk_len,
                mapping_start,
                mapping_end,
                mapping_ipa,
            );
            let chunk_offset = (lookup_address - mapping_start) as usize;
            unsafe {
                volatile_copy_to_guest(
                    bytes.as_ptr().add(copied),
                    host_addr.add(chunk_offset),
                    chunk_len,
                );
            }
            copied += chunk_len;
        }
        crate::probes::guest_mem_bytes(
            crate::probes::guest_mem_dir::WRITE_GUEST_CHECKED,
            strip_pointer_tag(address),
            bytes,
        );
        Ok(())
    }

    fn validate_guest_write_range(
        &self,
        address: u64,
        length: usize,
        require_guest_writable: bool,
    ) -> Result<(), MemoryError> {
        let mut checked = 0usize;
        while checked < length {
            let (chunk_address, chunk_len) = Self::guest_copy_chunk(address, checked, length)?;
            // The writability check follows the same region a `repoint_private`
            // overlay VA's copy will hit (the translated overlay IPA), so the
            // overlay's guest_writable flag — not the stale shared region's — gates.
            let lookup_address = self.syscall_buffer_lookup_addr(chunk_address, chunk_len);
            let Some(mapping) = self.mapping_for_range(lookup_address, chunk_len) else {
                return Err(MemoryError::OutOfBounds { address, length });
            };
            if require_guest_writable && !mapping.guest_writable {
                return Err(MemoryError::OutOfBounds { address, length });
            }
            checked += chunk_len;
        }
        Ok(())
    }

    pub(crate) fn guest_copy_chunk(
        address: u64,
        offset: usize,
        total_length: usize,
    ) -> Result<(u64, usize), MemoryError> {
        let offset_u64 = u64::try_from(offset).map_err(|_| MemoryError::OutOfBounds {
            address,
            length: total_length,
        })?;
        let raw_chunk_address =
            address
                .checked_add(offset_u64)
                .ok_or(MemoryError::OutOfBounds {
                    address,
                    length: total_length,
                })?;
        let chunk_address = strip_pointer_tag(raw_chunk_address);
        let remaining = total_length - offset;
        let page_remaining =
            (GUEST_STAGE1_PAGE_SIZE - (chunk_address & (GUEST_STAGE1_PAGE_SIZE - 1))) as usize;
        Ok((chunk_address, remaining.min(page_remaining)))
    }

    fn emit_guest_mem_copy_decision(
        &self,
        direction: u32,
        address: u64,
        length: usize,
        mapping_start: u64,
        mapping_end: u64,
        mapping_ipa: u64,
    ) {
        let stage1_ipa = crate::memory::is_high_va(address)
            .then(|| self.translate_va(address))
            .flatten();
        crate::probes::guest_mem_copy(
            direction,
            address,
            length,
            stage1_ipa,
            mapping_start,
            mapping_end,
            mapping_ipa,
        );
        self.emit_guest_mem_points(direction, address, length, mapping_start, mapping_ipa);
    }

    fn emit_guest_mem_points(
        &self,
        direction: u32,
        address: u64,
        length: usize,
        mapping_start: u64,
        mapping_ipa: u64,
    ) {
        for point in crate::probes::guest_mem_probe_points(address, length)
            .into_iter()
            .flatten()
        {
            let stage1_ipa = crate::memory::is_high_va(point)
                .then(|| self.translate_va(point))
                .flatten();
            crate::probes::guest_mem_point(
                direction,
                point,
                stage1_ipa,
                mapping_start,
                mapping_ipa,
            );
        }
    }

    /// Write the vDSO vvar data page: the counter frequency and the
    /// monotonic→realtime offset, so `__kernel_clock_gettime` can convert
    /// CNTVCT_EL0 to a timespec entirely in userspace. The guest reads the same
    /// counter we calibrate against (CNTKCTL_EL1.EL0VCTEN), so the rate is exact;
    /// monotonic durations depend only on the frequency. Best-effort: silently
    /// skips if the vvar page isn't mapped.
    /// Stamp this process's host PID into the vvar RNG generation (P2). It is
    /// unique per process; re-stamped for a forked child in
    /// `fork_rebuild` so the child's generation never matches the
    /// snapshot it COW-inherited from its parent — forcing the userspace
    /// getrandom blob to reseed instead of reusing the parent's keystream.
    fn stamp_rng_generation(&mut self) {
        let pid = unsafe { libc::getpid() } as u64;
        let _ = self.write_guest_bytes(
            crate::vdso::LINUX_VVAR_BASE + crate::vdso::VVAR_OFF_RNG_GENERATION as u64,
            &pid.to_le_bytes(),
        );
    }

    fn populate_vdso_data_page(&mut self) {
        // Independent of the clock data (getrandom needs no calibrated counter),
        // so stamp it first and unconditionally.
        self.stamp_rng_generation();
        let (_, freq) = host_counter();
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
    fn mapping_for_range(&self, address: u64, length: usize) -> Option<MappingView> {
        let address = strip_pointer_tag(address);
        let stage1_ipa = crate::memory::is_high_va(address)
            .then(|| self.translate_va(address))
            .flatten();
        if let Some(idx) =
            Self::mapping_index_for_range(&self.mappings, address, length, stage1_ipa)
        {
            return Some(self.mappings[idx].view());
        }
        // Cross-thread fallback (high-VA aliases only — low-VA regions are all
        // boot-mapped into every thread's list). Key on the guest's OWN stage-1
        // IPA so an overlapping MAP_FIXED alias resolves to the backing the guest
        // actually sees.
        if let Some(ipa) = stage1_ipa {
            if let Some(b) = lookup_shared_alias(ipa) {
                return Some(MappingView::from_alias(&b));
            }
        }
        // VA-keyed fallback for when the IPA key is unavailable. `translate_va`
        // reads THIS thread's software stage-1 model, which can lack a high-VA
        // arena page a sibling vCPU freshly MAP_FIXED-committed (Go reserves its
        // heap arena PROT_NONE, then MAP_FIXEDs RW sub-regions; a goroutine on
        // another vCPU then reads/writes a buffer there). `add_alias` already
        // registered that backing keyed by guest VA, so resolve it by VA. Gate on
        // `!range_no_access` so a still-PROT_NONE reservation page EFAULTs as it
        // must; `lookup_shared_alias_by_va` requires the whole range in one entry
        // and picks newest-first, so it never resolves a partial or stale backing.
        // This closes the intermittent Go "read/write: bad address" EFAULT.
        if !self.range_no_access(address, length) {
            if let Some(b) = lookup_shared_alias_by_va(address, length) {
                return Some(MappingView::from_alias(&b));
            }
        }
        None
    }

    fn mapping_for_range_mut(&mut self, address: u64, length: usize) -> Option<MappingView> {
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
    fn syscall_buffer_lookup_addr(&self, chunk_va: u64, chunk_len: usize) -> u64 {
        if !crate::memory::needs_stage1_translation(chunk_va, chunk_len as u64) {
            return chunk_va;
        }
        self.translate_va(chunk_va).unwrap_or(chunk_va)
    }

    /// True if `ipa` falls in `region`'s `hv_vm_map`'d IPA window.
    fn region_owns_ipa(region: &HvfMappedRegion, ipa: u64) -> bool {
        ipa >= region.ipa && ipa < region.ipa + region.size as u64
    }

    pub(crate) fn mapping_index_for_range(
        mappings: &[HvfMappedRegion],
        address: u64,
        length: usize,
        stage1_ipa: Option<u64>,
    ) -> Option<usize> {
        // For a high-VA Rosetta alias, prefer the region whose `hv_vm_map`'d IPA
        // window owns the guest's OWN stage-1 translation of `address`. Alias
        // regions can overlap by VA -- a 16 KiB host-rounded `end` over-claims its
        // neighbour, and a MAP_FIXED overlay leaves its predecessor in place -- so
        // a pure VA-range match (even newest-first) can pick a region the guest's
        // page tables do NOT use, sending a syscall buffer copy to the wrong
        // backing. Matching on stage-1 IPA picks exactly what the guest sees.
        if let Some(ipa) = stage1_ipa
            && let Some((idx, _)) =
                mappings.iter().enumerate().rev().find(|(_, m)| {
                    Self::region_owns_ipa(m, ipa) && m.contains_range(address, length)
                })
        {
            return Some(idx);
        }
        // Search NEWEST-first: a MAP_FIXED mmap overlaying an earlier mapping
        // pushes a new region without removing the old one, and the guest's
        // stage-1 points to the last mapping.
        mappings
            .iter()
            .enumerate()
            .rev()
            .find(|(_, mapping)| mapping.contains_range(address, length))
            .map(|(idx, _)| idx)
    }

    /// Walk the guest's live stage-1 page tables to resolve `va`→IPA (the output
    /// address carrick `hv_vm_map`'d). `None` if unmapped. Used to disambiguate
    /// overlapping high-VA alias regions in `mapping_for_range[_mut]`.
    fn translate_va(&self, va: u64) -> Option<u64> {
        self.page_tables.lock().as_ref()?.translate(va)
    }

    pub(crate) fn guest_range_is_writable(&self, address: u64, length: usize) -> bool {
        self.mapping_for_range(address, length).is_some() && !self.range_no_access(address, length)
    }

    /// M:N reclaim — BLOCK side. Snapshot this vCPU and DESTROY it (freeing one
    /// HVF concurrent-vCPU slot) so another guest thread can run while this one
    /// parks in the futex wait. The SAME thread recreates it via
    /// [`reclaim_resume`](Self::reclaim_resume) on wake. Unlike the fork
    /// path this does NOT publish mappings or rebuild the VM — the VM is unchanged;
    /// only the per-thread vCPU is recycled. (No `FORK_VCPU_SNAPSHOT` / no
    /// `rebuilt_vm_cell`: the snapshot is stashed in `self.reclaim_snapshot`, and
    /// recreate uses the existing `self._vm`.)
    ///
    /// NOT YET WIRED: the shared engine's `ThreadedEngine::save_guest_state` /
    /// `rebind_to_slot` route through the `&self` / `&mut self.vm` `Aarch64Vmm`
    /// reclaim hooks, which CANNOT reach the engine's separately-owned vCPU — so
    /// they surface an error for HVF (see the `save_guest_state` impl in
    /// `hvf_aarch64_engine.rs`). The DESTROY-IN-PLACE reclaim these methods
    /// implement needs `&mut vcpu`, so they wait on a future engine override that
    /// passes the vCPU through. Kept here as the ready reclaim surface.
    #[allow(dead_code)]
    pub(crate) fn reclaim_park(
        &mut self,
        vcpu: &mut applevisor::vcpu::Vcpu,
    ) -> Result<(), TrapError> {
        let snap = HvfInner::snapshot_vcpu_from(vcpu)?;
        self.reclaim_snapshot = Some(snap);
        // Raw destroy — only the owning thread may, and applevisor's Drop would
        // panic on the post-destroy handle.
        let rc = unsafe { applevisor_sys::hv_vcpu_destroy(vcpu.id()) };
        vcpu_destroyed();
        if rc != 0 {
            return Err(TrapError::Hypervisor(format!(
                "reclaim_park: hv_vcpu_destroy rc={rc:#x}"
            )));
        }
        Ok(())
    }

    /// M:N reclaim — WAKE side. Recreate this thread's vCPU in the EXISTING VM (no
    /// fork rebuild) and restore the parked register state (incl. TPIDR_EL0/
    /// TPIDRRO_EL0/TPIDR_EL1 and the V-regs). The CALLER must hold
    /// `fork_quiesce::topology_lock` so `vcpu_create` cannot race a concurrent
    /// fork's `hv_vm_destroy`/`create`. Writes the recreated vCPU back through
    /// `vcpu` via `std::mem::replace` + `forget` of the old (already-destroyed)
    /// handle (no applevisor Drop).
    ///
    /// NOT YET WIRED — see [`reclaim_park`](Self::reclaim_park): the engine's
    /// reclaim hooks can't reach the vCPU, so this destroy/recreate-in-place
    /// reclaim waits on a future engine override.
    #[allow(dead_code)]
    pub(crate) fn reclaim_resume(
        &mut self,
        vcpu: &mut applevisor::vcpu::Vcpu,
    ) -> Result<(), TrapError> {
        let snap = self
            .reclaim_snapshot
            .take()
            .ok_or_else(|| TrapError::Hypervisor("reclaim_resume: no parked snapshot".into()))?;
        let new_vcpu = self._vm.vcpu_create().map_err(hvf_error)?;
        vcpu_created();
        enable_el0_counter_access(new_vcpu.id());
        self.vcpu_id = new_vcpu.id();
        self.vcpu_handle = new_vcpu.get_handle();
        // Replace the destroyed handle WITHOUT running applevisor's panicky Drop on
        // the (already hv_vcpu_destroy'd) old one — mirror the fork rebuild.
        std::mem::forget(std::mem::replace(vcpu, new_vcpu));
        HvfInner::restore_vcpu_into(vcpu, &snap)?;
        self.last_exit_class = snap.last_exit_class;
        Ok(())
    }

    /// Multithreaded fork — sibling side, step 1. Snapshot this vCPU and destroy
    /// it (raw `hv_vcpu_destroy`; only the owning thread may) so the forking
    /// thread can `hv_vm_destroy` before `libc::fork` (which fails HV_BUSY while
    /// any vCPU is alive). The wrapper is left stale until `rebuild_vcpu_after_fork`.
    pub(crate) fn release_vcpu_for_fork(
        &mut self,
        vcpu: &mut applevisor::vcpu::Vcpu,
    ) -> Result<(), TrapError> {
        // Publish this sibling's regions so the forking thread re-maps them into
        // the rebuilt parent VM (the rebuild otherwise replays only the forker's
        // own mappings, dropping this thread's per-thread aliases). We then park
        // (caller: release_and_park_vcpu_for_fork) holding our OwnedHostMappings
        // alive, so the forker re-maps live backings.
        publish_sibling_fork_mappings(&self.mappings);
        let snap = HvfInner::snapshot_vcpu_from(vcpu)?;
        FORK_VCPU_SNAPSHOT.with(|s| *s.borrow_mut() = Some(snap));
        let rc = unsafe { applevisor_sys::hv_vcpu_destroy(vcpu.id()) };
        vcpu_destroyed();
        // phase 3: a nonzero rc means this sibling FAILED to destroy its own
        // vCPU, so it stays live and the forker's hv_vm_destroy hits HV_BUSY.
        crate::probes::fork_quiesce(3, rc as i64, vcpu.id() as i64, unsafe { libc::getpid() });
        Ok(())
    }

    /// Multithreaded fork — forking thread (parent), after rebuilding its VM.
    /// Publish a clone of the new process VM so quiesced siblings can recreate
    /// their vCPUs in it.
    pub(crate) fn publish_vm_for_siblings(&self) {
        *rebuilt_vm_cell().lock() = Some((*self._vm).clone());
    }

    /// Multithreaded fork — sibling side, step 2 (after the parent published the
    /// rebuilt VM and released the quiesce). Recreate this vCPU in the new VM
    /// and restore the pre-fork register state. Mappings are VM-global (the
    /// parent remapped them into the shared VM), so nothing to re-map here.
    pub(crate) fn rebuild_vcpu_after_fork(
        &mut self,
        vcpu: &mut applevisor::vcpu::Vcpu,
    ) -> Result<(), TrapError> {
        let snap = FORK_VCPU_SNAPSHOT
            .with(|s| s.borrow_mut().take())
            .ok_or_else(|| TrapError::Hypervisor("no fork vCPU snapshot for rebuild".into()))?;
        // Post-fork: recreate in the parent's rebuilt VM (published). On a
        // quiesce ABORT (timeout — no fork happened), nothing was published and
        // the existing VM is still live, so recreate the vCPU in it.
        let new_vm = rebuilt_vm_cell()
            .lock()
            .clone()
            .unwrap_or_else(|| (*self._vm).clone());
        let new_vcpu = new_vm.vcpu_create().map_err(hvf_error)?;
        vcpu_created();
        enable_el0_counter_access(new_vcpu.id());
        self.vcpu_id = new_vcpu.id();
        self.vcpu_handle = new_vcpu.get_handle();
        // Replace _vm and vcpu WITHOUT running applevisor's panicky Drop on the
        // old (already-destroyed) handles — mirror the fork/thread-sibling
        // leak-until-exit discipline.
        std::mem::forget(std::mem::replace(vcpu, new_vcpu));
        replace_destroyed_vm(self, new_vm);
        HvfInner::restore_vcpu_into(vcpu, &snap)?;
        self.last_exit_class = snap.last_exit_class;
        Ok(())
    }

    /// A guest thread is exiting: destroy ITS OWN vCPU (only the owning thread
    /// may) so the slot is freed in the process-global VM. Without this, the
    /// no-op `Drop` leaks the vCPU live forever, and a later fork's
    /// `hv_vm_destroy` trips over the accumulated dead-thread vCPUs (HV_BUSY).
    /// Raw `hv_vcpu_destroy`, not applevisor's panicky wrapper.
    pub(crate) fn destroy_vcpu_on_thread_exit(&mut self, vcpu: &mut applevisor::vcpu::Vcpu) {
        let _ = unsafe { applevisor_sys::hv_vcpu_destroy(vcpu.id()) };
        vcpu_destroyed();
    }

    /// Multithreaded fork — PRE-`libc::fork` half (the forking thread, single
    /// process). Snapshot every PRIVATE region into a child-private copy (guest
    /// RAM is host-MAP_SHARED, so fork doesn't isolate it), capture the mapping
    /// descriptors, and tear down the HVF VM via the raw API (a live VM at fork
    /// time makes the child's `hv_vm_create` fail). Both sides then rebuild from
    /// the stashed descriptors in `fork_rebuild`. Does NOT call `libc::fork` (the
    /// shared engine does that) and does NOT snapshot the vCPU registers (the
    /// engine snapshots separately and passes them into `fork_rebuild`).
    pub(crate) fn fork_prepare_and_teardown(&mut self) -> Result<(), TrapError> {
        // Probe parity with the old monolithic fork: the engine snapshots the
        // vCPU (PC/ELR/CPSR) just before this; report the pre-fork marker. The
        // vCPU registers are no longer read here (the engine owns the snapshot),
        // so fire the marker with zeros — the engine's snapshot carries the
        // authoritative values the old `fork_pre` reported.
        crate::probes::fork_pre(0, 0, 0);

        // vfork (CLONE_VM): before libc::fork, mark each WRITABLE guest region
        // VM_INHERIT_SHARE so the fork SHARES its pages with the child (XNU
        // vm_map_fork_share — child references the SAME vm_object, no shadow/copy,
        // both is_shared; the parent is NOT made COW). This gives a CLONE_VFORK
        // child true write-visibility into the SUSPENDED parent (clone05) while
        // keeping the SAME physical pages, so the child's re-hv_vm_map binds the
        // same PAs — unlike a fresh MAP_SHARED copy (smashed the vfork-exec stack)
        // or a mach_vm_remap COW (HVF rejects). `guest_writable` is the exact
        // discriminator: it is false for every carrick-internal region (trampolines,
        // vectors, page tables, identity page, vvar, sigreturn) and read-only guest
        // text, so the share never touches the trap machinery; the page-table region
        // additionally stays a private clone (child branch below). minherit covers
        // the WHOLE region (offset 0, full len) — a sub-range would clip the map
        // entry and shadow on the first fork. The parent restores VM_INHERIT_COPY
        // after the fork (fork_rebuild) so later PLAIN forks stay cheap COW.
        if self.vfork_share {
            for m in &self.mappings {
                let is_pt = m.start == crate::memory::LINUX_PAGE_TABLES_BASE;
                if m.guest_writable && !m.guest_shared && !is_pt {
                    set_region_fork_inheritance(m.host_addr, m.size, VM_INHERIT_SHARE);
                }
            }
        }

        let mapping_descs: Vec<ForkMappingDesc> = self
            .mappings
            .iter()
            .map(|m| ForkMappingDesc {
                start: m.start,
                ipa: m.ipa,
                end: m.end,
                host: ForkMappingHost::Borrowed(m.host_addr),
                size: m.size,
                perms: m.perms,
                guest_shared: m.guest_shared,
                guest_writable: m.guest_writable,
            })
            .collect();

        let share_vm = self.vfork_share;
        let mut child_descs: Vec<ForkMappingDesc> = Vec::with_capacity(mapping_descs.len());
        for desc in &mapping_descs {
            // vfork (CLONE_VM): the child shares the parent's address space until it
            // execs/exits, while the parent vCPU stays SUSPENDED. carrick forks a
            // real host process, and bulk guest RAM is host-MAP_PRIVATE, so the
            // child's COW view is ISOLATED — which is exactly right for the common
            // vfork-FOR-EXEC case (Go, posix_spawn, the shell): the child's pre-exec
            // trampoline writes COW away, leaving the suspended parent's stack/canary
            // intact, and execve rebuilds the child fresh. (The STRICT vfork-write
            // corner — a CLONE_VFORK child that mutates a shared global the parent
            // then reads WITHOUT exec'ing, i.e. LTP clone05 — is a known gap: making
            // those writes shared requires promoting the writable regions to
            // MAP_SHARED, which corrupts the live stack the child's exec trampoline
            // writes and regresses every vfork-exec. The isolation here is the
            // correct trade for real workloads.)
            //
            // The stage-1 page-table BACKING stays a PRIVATE clone even for vfork:
            // the child's cloned PageTableManager assumes a private backing, and a
            // COW/shared PT desyncs the guest VA->PA walk under HVF (breaks
            // cross-process futex/tst_checkpoint + clone05). Tiny region, ~free.
            let is_page_table_region = desc.start == crate::memory::LINUX_PAGE_TABLES_BASE;
            let child_host = if (share_vm && !is_page_table_region) || desc.guest_shared {
                ForkMappingHost::Borrowed(desc.host.ptr()) // shared mapping: child maps the SAME buffer
            } else if is_page_table_region {
                ForkMappingHost::Owned(clone_region_for_child(
                    desc.host.ptr(),
                    desc.size,
                    desc.start,
                )?)
            } else {
                // Bulk private guest RAM (data/bss/heap/stack/mmap arena) is
                // host-MAP_PRIVATE, so libc::fork already COW-isolates it: the
                // child re-maps its OWN COW view of the same VA, skipping the
                // eager mincore+copy snapshot (the dominant per-fork cost — the
                // epoll-ltp ~50x win).
                ForkMappingHost::Borrowed(desc.host.ptr())
            };
            child_descs.push(ForkMappingDesc {
                start: desc.start,
                ipa: desc.ipa,
                end: desc.end,
                host: child_host,
                size: desc.size,
                perms: desc.perms,
                guest_shared: desc.guest_shared,
                guest_writable: desc.guest_writable,
            });
        }

        // Tear down the parent's HVF context BEFORE the engine forks. macOS's
        // HVF kernel state is not fork-safe: if a VM exists in the parent at
        // fork(2) time, the child inherits a "resource is busy" state that
        // prevents `hv_vm_create` from succeeding. Both processes then rebuild a
        // fresh VM from the stashed descriptors in `fork_rebuild`. The engine's
        // `freeze_ram_for_fork` hook does NOT pass the vCPU, so we destroy by the
        // tracked `vcpu_id` (the stale `HvfAarch64Vcpu` wrapper is replaced in
        // `fork_rebuild`, which DOES hold `&mut vcpu`).
        let vcpu_destroy_rc = unsafe { applevisor_sys::hv_vcpu_destroy(self.vcpu_id) };
        vcpu_destroyed();
        let vm_destroy_rc = unsafe { applevisor_sys::hv_vm_destroy() };
        if std::env::var_os("CARRICK_FORK_DEBUG").is_some() {
            eprintln!(
                "[FORKDBG pid={}] teardown vcpu_id={:#x} vcpu_destroy_rc={:#x} vm_destroy_rc={:#x} live={} share_vm={}",
                unsafe { libc::getpid() },
                self.vcpu_id,
                vcpu_destroy_rc,
                vm_destroy_rc,
                VCPU_LIVE.load(std::sync::atomic::Ordering::SeqCst),
                share_vm,
            );
        }
        // phase 2: a nonzero rc means a vCPU was still live at teardown — the
        // HV_BUSY root cause (the rebuilt VM is then corrupt and sibling
        // vcpu_create fails). Traceable via `carrick trace` fork__quiesce.
        crate::probes::fork_quiesce(
            2,
            vm_destroy_rc as i64,
            VCPU_LIVE.load(std::sync::atomic::Ordering::SeqCst),
            unsafe { libc::getpid() },
        );

        self.fork_mapping_descs = mapping_descs;
        self.fork_child_descs = child_descs;
        Ok(())
    }

    /// Multithreaded fork — POST-`libc::fork` half. Build a fresh VM + vCPU,
    /// re-`hv_vm_map` the right buffers (the CHILD uses the private snapshots; the
    /// PARENT re-maps its own + the union of every quiesced sibling's regions),
    /// restore the engine-supplied register `snap` onto the NEW vCPU, and
    /// re-stamp the vvar RNG generation (child). `is_child` keys the parent-vs-
    /// child inheritance EXACTLY as the old monolithic `fork`.
    pub(crate) fn fork_rebuild(
        &mut self,
        vcpu: &mut applevisor::vcpu::Vcpu,
        snap: &VcpuSnapshot,
        is_child: bool,
    ) -> Result<(), TrapError> {
        use applevisor::prelude::*;

        // Take the descriptors stashed in `fork_prepare_and_teardown`. The parent
        // re-maps its own buffers (`mapping_descs`); the child re-maps the private
        // snapshots / shared originals (`child_descs`). The unused set drops here.
        let mapping_descs = std::mem::take(&mut self.fork_mapping_descs);
        let child_descs = std::mem::take(&mut self.fork_child_descs);

        // Build a fresh VM + vCPU. Both processes have just had their HVF state
        // torn down (parent did it pre-fork; child inherited the now-empty state
        // via fork). Each side independently re-registers the inherited host
        // buffers via raw `hv_vm_map`.
        let max_ipa = VirtualMachineConfig::get_max_ipa_size().map_err(hvf_error)?;
        if std::env::var_os("CARRICK_FORK_DEBUG").is_some() {
            eprintln!(
                "[FORKDBG pid={}] fork_rebuild is_child={} max_ipa={:#x} (pre-create)",
                unsafe { libc::getpid() },
                is_child,
                max_ipa,
            );
        }
        let mut config = VirtualMachineConfig::new();
        config.set_ipa_size(max_ipa).map_err(hvf_error)?;
        let new_vm = virtual_machine_with_private_signals_blocked(config).map_err(hvf_error)?;
        let new_vcpu = new_vm.vcpu_create().map_err(hvf_error)?;
        vcpu_created();
        enable_el0_counter_access(new_vcpu.id());
        if std::env::var_os("CARRICK_FORK_DEBUG").is_some() {
            eprintln!(
                "[FORKDBG pid={}] fork_rebuild is_child={} new_vcpu_id={:#x} n_descs={}",
                unsafe { libc::getpid() },
                is_child,
                new_vcpu.id(),
                if is_child {
                    child_descs.len()
                } else {
                    mapping_descs.len()
                },
            );
        }
        self.vcpu_id = new_vcpu.id();
        self.vcpu_handle = new_vcpu.get_handle();

        // Swap the new VM + vCPU into place WITHOUT running applevisor's Drop on
        // the old (raw-destroyed) handles. `is_forked_child` is true only in the
        // child process; the parent kept its pre-fork host process identity.
        std::mem::forget(std::mem::replace(vcpu, new_vcpu));
        replace_destroyed_vm(self, new_vm);

        // In the parent, keep the exact shared protection table siblings already
        // use; otherwise post-fork mmap/mprotect changes split across two Arcs and
        // one thread can see a valid Go heap futex as PROT_NONE. The child is
        // single-threaded after fork, so it gets a private copy of the parent's
        // ranges at the fork point.
        self.protections = if is_child {
            std::sync::Arc::new(MemoryProtections::from_ranges(self.protections.snapshot()))
        } else {
            std::sync::Arc::clone(&self.protections)
        };
        // The stage-1 page-table manager must survive fork EXACTLY like
        // protections. The PARENT's tables and their host backing are unchanged
        // by fork, so it keeps the SAME shared manager — a fresh manager would
        // rebuild from the (live) backing with `next_free` reset to the first
        // spare, then re-hand-out table pages already in use, writing L3 entries
        // over a live L2 table (proven: the cross-test TestUserArenaNew SIGSEGV,
        // an L2 slot holding `USER_PAGE_FLAGS | <arena PA>`). The CHILD gets a
        // private backing copy, so it needs its OWN manager — but a CLONE of the
        // parent's state, not a reset, so its bump cursor matches that backing.
        self.page_tables = if is_child {
            let cloned = self.page_tables.lock().clone();
            std::sync::Arc::new(parking_lot::Mutex::new(cloned))
        } else {
            std::sync::Arc::clone(&self.page_tables)
        };
        // CRITICAL: LEAK the old mapping Vec (do NOT drop it). Each old
        // `HvfMappedRegion` owns an `OwnedHostMapping` whose Drop `munmap`s the host
        // backing — and the `mapping_descs` we re-`hv_vm_map` below carry BORROWED
        // raw pointers INTO those exact buffers. Dropping the old Vec here would
        // munmap them out from under the re-map, so `hv_vm_map` faults (HV_ERROR).
        // This matches the original monolithic `fork`, which swapped the whole
        // `HvfInner` via `ptr::write` + `mem::forget` and so never ran Drop on the
        // old mappings (the leak-until-exit / ManuallyDrop discipline; the kernel
        // reclaims the pages at process exit). The CHILD remaps its own private
        // snapshots (`child_descs`), which are MOVED into the rebuilt mappings below,
        // so the parent's borrowed originals it inherited via COW are likewise kept
        // alive by this leak.
        std::mem::forget(std::mem::replace(
            &mut self.mappings,
            Vec::with_capacity(mapping_descs.len()),
        ));
        self.reclaim_snapshot = None;
        self.last_exit_class = snap.last_exit_class;
        self.last_fault_esr = 0;
        self.is_forked_child = is_child;
        self.forked_no_exec = is_child;
        self.last_syscall_nr = None;
        self.last_syscall_orig_x0 = 0;

        // Re-map each region using raw hv_vm_map. The PARENT re-maps its original
        // buffers; the CHILD maps the pre-fork private snapshots for PRIVATE
        // regions and the shared originals for guest-MAP_SHARED ones.
        let descs = if is_child { child_descs } else { mapping_descs };
        for desc in descs {
            let host_addr = desc.host.ptr();
            let perms_raw: u64 = u64::from(desc.perms);
            let r = unsafe {
                applevisor_sys::hv_vm_map(
                    host_addr as *mut std::ffi::c_void,
                    desc.ipa,
                    desc.size,
                    perms_raw,
                )
            };
            if r != 0 {
                return Err(TrapError::ChildMapFailed {
                    host_addr: host_addr as u64,
                    guest_start: desc.ipa,
                    size: desc.size,
                    code: r as u32,
                });
            }
            // Re-register every high-VA alias into the process-shared index with
            // THIS rebuild's host_addr. Critical for the CHILD: the index is
            // COW-inherited from the parent pointing at the PARENT's backings, but
            // a PRIVATE alias was just re-snapshotted to a NEW child buffer
            // (child_descs / clone_region_for_child) — without this overwrite a
            // child syscall would read/write the parent's backing (cross-process
            // corruption) instead of its own copy. For the parent it's idempotent
            // (same host_addr). Low-VA boot regions are not aliases (every thread
            // has them) and are never in the index.
            if crate::memory::is_high_va(desc.start) {
                register_shared_alias(AliasBacking {
                    start: desc.start,
                    ipa: desc.ipa,
                    host_addr: host_addr as usize,
                    size: desc.size,
                    perms: perms_raw,
                    guest_writable: desc.guest_writable,
                    guest_shared: desc.guest_shared,
                });
            }
            self.mappings.push(HvfMappedRegion {
                start: desc.start,
                ipa: desc.ipa,
                end: desc.end,
                host_addr,
                size: desc.size,
                perms: desc.perms,
                guest_writable: desc.guest_writable,
                // No Memory object — the host buffer is either an inherited
                // shared mapping or a snapshot copy. Drop runs no HVF call for
                // this mapping; the engine's VM tear-down releases all stage-2
                // entries in one shot.
                memory: None,
                host_mapping: desc.host.into_owned(),
                guest_shared: desc.guest_shared,
            });
        }

        // PARENT post-vfork: restore VM_INHERIT_COPY on the regions we shared for
        // this vfork (set VM_INHERIT_SHARE in fork_prepare_and_teardown), so a LATER
        // plain fork of this parent gets cheap COW isolation again rather than
        // silently sharing its address space. The vfork child execs/exits, so it
        // keeps the inherited SHARE attribute harmlessly (a no-op once it detaches).
        if !is_child && self.vfork_share {
            for m in &self.mappings {
                let is_pt = m.start == crate::memory::LINUX_PAGE_TABLES_BASE;
                if m.guest_writable && !m.guest_shared && !is_pt {
                    set_region_fork_inheritance(m.host_addr, m.size, VM_INHERIT_COPY);
                }
            }
        }

        // PARENT only: re-map the UNION of all quiesced siblings' regions that
        // the forking thread's `mapping_descs` lacked. Threads share one VM but
        // this rebuild replays only the forker's mappings, so a per-thread alias
        // a SIBLING established (e.g. a Go heap-arena chunk at high-VA) is missing
        // from the rebuilt stage-2 — the parent then DC-ZVA-faults on it
        // (translation fault, mapped_here=false). The shared stage-1 page tables
        // (kept by Arc above) already carry the VA->IPA entry; only the stage-2
        // `hv_vm_map` is absent, so re-map each sibling region by IPA (deduped
        // against what we just mapped; alias IPAs are process-global + unique).
        // The backing is alive: every publisher PARKED in
        // release_and_park_vcpu_for_fork after publishing and stays parked until
        // we end the quiesce, holding its OwnedHostMapping. The region is UNOWNED
        // here (memory/host_mapping = None) so the parent never frees a buffer the
        // sibling owns. The CHILD is single-threaded post-fork (uses child_descs),
        // so it must NOT inherit sibling aliases — hence parent only.
        if !is_child {
            let mut mapped_ipas: std::collections::HashSet<u64> =
                self.mappings.iter().map(|m| m.ipa).collect();
            let siblings = sibling_fork_mappings().lock().clone();
            for sm in siblings {
                if !mapped_ipas.insert(sm.ipa) {
                    continue;
                }
                let r = unsafe {
                    applevisor_sys::hv_vm_map(
                        sm.host_addr as *mut std::ffi::c_void,
                        sm.ipa,
                        sm.size,
                        sm.perms,
                    )
                };
                if r != 0 {
                    return Err(TrapError::ChildMapFailed {
                        host_addr: sm.host_addr as u64,
                        guest_start: sm.ipa,
                        size: sm.size,
                        code: r as u32,
                    });
                }
                self.mappings.push(HvfMappedRegion {
                    start: sm.start,
                    ipa: sm.ipa,
                    end: sm.end,
                    host_addr: sm.host_addr as *mut u8,
                    size: sm.size,
                    perms: applevisor::memory::MemPerms::from(sm.perms),
                    guest_writable: sm.guest_writable,
                    memory: None,
                    host_mapping: None,
                    guest_shared: sm.guest_shared,
                });
            }
        }

        // Restore vCPU register state from the engine's pre-fork snapshot. Both
        // parent and child resume inside the same `clone` syscall site; the
        // dispatcher then writes the appropriate retval into X0 (child pid for
        // parent, 0 for child).
        HvfInner::restore_vcpu_into(vcpu, snap)?;
        self.last_exit_class = snap.last_exit_class;
        let post_pid = if is_child {
            0
        } else {
            unsafe { libc::getpid() }
        };
        crate::probes::fork_post(post_pid, snap.core.pc, snap.core.elr_el1);
        if is_child {
            // The child has a new pid, but its inherited USDT DOF is registered
            // with the kernel under the PARENT's pid. Re-register so DTrace's
            // `carrick*` provider matches this child too — otherwise forked guest
            // processes (apt's http method, dpkg-deb's tar subprocess) are
            // invisible to `carrick trace`.
            let _ = crate::probes::register_dtrace_probes();
            // P2 getrandom fork-safety: re-stamp the vvar RNG generation with the
            // child's new PID. `self` is now the child's rebuilt engine — its vvar
            // mapping points at the child's freshly re-mapped snapshot buffer, and
            // the vCPU was just recreated (clean stage-2 TLB) — so this write IS
            // visible to the child's guest reads. The child's distinct generation
            // forces the userspace getrandom blob to reseed instead of reusing the
            // parent's keystream (gated by conformance-probes/getrandomvdsofork).
            self.stamp_rng_generation();
        }
        Ok(())
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
            protections: std::sync::Arc::clone(&self.protections),
            page_tables: std::sync::Arc::clone(&self.page_tables),
        })
    }

    /// Stand up a thread sibling on the current host thread from a [`ThreadSpec`]:
    /// create a new vCPU in the shared VM and mirror the inherited (UNOWNED)
    /// mapping metadata. Returns the `(state, vcpu)` pair; the engine restores the
    /// seeded register snapshot. MUST be called on the host thread that will own
    /// the vCPU (HVF requires vCPU create+run+destroy on one thread).
    pub(crate) fn from_thread_spec(
        spec: ThreadSpec,
    ) -> Result<(HvfVmState, applevisor::vcpu::Vcpu), TrapError> {
        let ThreadSpec {
            vm,
            mappings,
            protections,
            page_tables,
        } = spec;

        // The spec captured `vm` at clone time. If a fork rebuilt the VM since
        // then (the spec's `vm` was destroyed), create the vCPU in the CURRENT
        // VM that the fork published instead — otherwise vcpu_create hits
        // HV_BUSY on a torn-down VM. Between forks the published cell holds the
        // live VM; with no fork yet it's empty and the spec's `vm` is current.
        // The caller holds `fork_quiesce::topology_lock()`, so this read can't
        // race a fork's republish.
        let vm = rebuilt_vm_cell().lock().clone().unwrap_or(vm);
        let vcpu = vm.vcpu_create().map_err(hvf_error)?;
        vcpu_created();
        enable_el0_counter_access(vcpu.id());

        let mut state = HvfVmState {
            _vm: std::mem::ManuallyDrop::new(vm),
            mappings: Vec::with_capacity(mappings.len()),
            reclaim_snapshot: None,
            last_exit_class: 0,
            last_fault_esr: 0,
            is_forked_child: false,
            forked_no_exec: false,
            protections,
            page_tables,
            last_syscall_nr: None,
            last_syscall_orig_x0: 0,
            vcpu_id: vcpu.id(),
            vcpu_handle: vcpu.get_handle(),
            vfork_share: false,
            fork_mapping_descs: Vec::new(),
            fork_child_descs: Vec::new(),
        };

        for mapping in mappings {
            // `hv_vm_map` is VM-global on Hypervisor.framework. The new vCPU is
            // created in the parent's VM clone, so the parent mappings are
            // already visible here; reissuing them for every sibling is at best
            // an already-mapped no-op and at worst map-table churn while other
            // vCPUs are running. Keep only local metadata used by syscall-path
            // guest-memory accessors.
            state.mappings.push(mapping.into_unowned_region());
        }

        Ok((state, vcpu))
    }

    /// `execve(2)` image replacement: tear down + rebuild the VM around the new
    /// image, reset the vCPU to "initial process startup" (zeroed GPRs, EL0
    /// trampoline). Clears the alias registry. Preserves `is_forked_child`.
    pub(crate) fn execve_rebuild(
        &mut self,
        vcpu: &mut applevisor::vcpu::Vcpu,
        plan: &GuestMappingPlan,
    ) -> Result<(), TrapError> {
        use applevisor::prelude::*;

        // execve replaces the WHOLE address space: drop every process-shared alias
        // index entry so a stale pre-exec high-VA `host_addr` can never be resolved
        // by a syscall in the new image. (execve already killed sibling threads, so
        // no other thread is mid-lookup against these entries.)
        alias_registry().lock().clear();

        // Tear down the current HVF VM. Same dance as fork(): destroy vCPU then VM
        // via raw API (applevisor's Drop is bypassed).
        let inherited_vcpu_id = vcpu.id();
        let _ = unsafe { applevisor_sys::hv_vcpu_destroy(inherited_vcpu_id) };
        vcpu_destroyed();
        let _ = unsafe { applevisor_sys::hv_vm_destroy() };

        // Create a fresh VM + vCPU.
        let max_ipa = VirtualMachineConfig::get_max_ipa_size().map_err(hvf_error)?;
        let mut config = VirtualMachineConfig::new();
        config.set_ipa_size(max_ipa).map_err(hvf_error)?;
        let new_vm = virtual_machine_with_private_signals_blocked(config).map_err(hvf_error)?;
        let new_vcpu = new_vm.vcpu_create().map_err(hvf_error)?;
        vcpu_created();
        enable_el0_counter_access(new_vcpu.id());
        self.vcpu_id = new_vcpu.id();
        self.vcpu_handle = new_vcpu.get_handle();

        // Preserve `is_forked_child` across execve. A process that descended from
        // the original `carrick run` invocation should keep using the
        // `_exit`-without-JSON shutdown path even after it execve's into a
        // different image; otherwise every forked + execve'd descendant prints its
        // own JSON report to stdout (interleaved with the parent's), making the
        // user-visible output unreadable.
        let was_forked_child = self.is_forked_child;
        // Swap the new VM + vCPU into place WITHOUT running Drop on the old.
        std::mem::forget(std::mem::replace(vcpu, new_vcpu));
        replace_destroyed_vm(self, new_vm);
        // LEAK the old image's mappings (do NOT drop): the old VM was just
        // raw-`hv_vm_destroy`'d, and the original monolithic `execve_into` swapped
        // the whole `HvfInner` via `ptr::write`/`mem::forget` and so never ran Drop
        // on the old mappings (the leak-until-exit discipline; the kernel reclaims
        // at process exit). Dropping here would `munmap` the old `OwnedHostMapping`s
        // — harmless for the now-unmapped image, but we keep the exact discipline so
        // no stale alias-registry/sibling reference can dangle.
        std::mem::forget(std::mem::take(&mut self.mappings));
        self.reclaim_snapshot = None;
        self.last_exit_class = 0;
        self.last_fault_esr = 0;
        self.is_forked_child = was_forked_child;
        self.forked_no_exec = false; // execve gives a fresh VM: no longer a live forked-no-exec child
        // execve replaces the address space; any prior PROT_NONE ranges are gone.
        self.protections = std::sync::Arc::new(MemoryProtections::default());
        self.page_tables = std::sync::Arc::new(parking_lot::Mutex::new(None));
        self.last_syscall_nr = None;
        self.last_syscall_orig_x0 = 0;

        // Apply the new mapping plan via the shared raw-mmap helper.
        for mapping in &plan.mappings {
            self.mappings.push(map_region_raw(mapping)?);
        }

        // Initial vCPU state — same sequence as `new_with_plan`. Zero the GPRs
        // first: Linux's execve contract says the new program starts with all
        // registers clear except for SP and PC. Without this, musl's _start in the
        // new image inherits the previous process's x8 which can decode as a bogus
        // syscall number on the first svc.
        for reg in GPR_TABLE {
            vcpu.set_reg(reg, 0).map_err(hvf_error)?;
        }

        let initial_pc = plan.el0_trampoline_entry.unwrap_or(plan.entry);
        vcpu.set_reg(Reg::PC, initial_pc).map_err(hvf_error)?;
        const AARCH64_PSTATE_EL1H_DAIF_MASKED: u64 = 0x3c5;
        vcpu.set_reg(Reg::CPSR, AARCH64_PSTATE_EL1H_DAIF_MASKED)
            .map_err(hvf_error)?;
        if let Some(_trampoline) = plan.el0_trampoline_entry {
            const AARCH64_PSTATE_EL0T_DAIF_MASKED: u64 = 0x3c0;
            vcpu.set_sys_reg(SysReg::SPSR_EL1, AARCH64_PSTATE_EL0T_DAIF_MASKED)
                .map_err(hvf_error)?;
            vcpu.set_sys_reg(SysReg::ELR_EL1, plan.entry)
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
            vcpu.set_sys_reg(SysReg::MAIR_EL1, boot.mair_el1)
                .map_err(hvf_error)?;
            // 48-bit VA, TTBR0 + TTBR1 both active sharing one root. MUST stay
            // identical to the canonical TCR comment/value in new_with_plan.
            // boot.tcr_el1 is the shared bootstrap value via GuestArch
            // (canonical rationale in carrick_mem::arch_sysregs).
            vcpu.set_sys_reg(SysReg::TCR_EL1, boot.tcr_el1)
                .map_err(hvf_error)?;
            vcpu.set_sys_reg(SysReg::TTBR0_EL1, pt_base)
                .map_err(hvf_error)?;
            // TTBR1 shares the same root (see the TCR comment above).
            vcpu.set_sys_reg(SysReg::TTBR1_EL1, pt_base)
                .map_err(hvf_error)?;
            sctlr_el1 |= 1;
        }
        vcpu.set_sys_reg(SysReg::SCTLR_EL1, sctlr_el1)
            .map_err(hvf_error)?;
        // boot.cpacr_el1 (FPEN=0b11, no FP/SIMD trap at EL0) is shared.
        vcpu.set_sys_reg(SysReg::CPACR_EL1, boot.cpacr_el1)
            .map_err(hvf_error)?;
        if let Some(vectors_base) = plan.el1_vectors_base {
            vcpu.set_sys_reg(SysReg::VBAR_EL1, vectors_base)
                .map_err(hvf_error)?;
        }
        if let Some(stack_pointer) = plan.initial_stack_pointer {
            vcpu.set_sys_reg(SysReg::SP_EL1, stack_pointer)
                .map_err(hvf_error)?;
            vcpu.set_sys_reg(SysReg::SP_EL0, stack_pointer)
                .map_err(hvf_error)?;
        }
        // execve resets TPIDR_EL0 — the new image's musl init will call
        // set_thread_area to initialise it.
        vcpu.set_sys_reg(SysReg::TPIDR_EL0, 0).map_err(hvf_error)?;

        // Verify post-execve sysreg state through dtrace. If stage-1 isn't on or
        // TTBR0 doesn't point at the new tables, the new process will fault on the
        // first LDAXR.
        let actual_sctlr = vcpu.get_sys_reg(SysReg::SCTLR_EL1).unwrap_or(0);
        let actual_ttbr0 = vcpu.get_sys_reg(SysReg::TTBR0_EL1).unwrap_or(0);
        let actual_mair = vcpu.get_sys_reg(SysReg::MAIR_EL1).unwrap_or(0);
        crate::probes::execve_sysregs(actual_sctlr, actual_ttbr0, actual_mair);
        self.populate_vdso_data_page();
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
        Ok(VcpuSnapshot {
            core: Aarch64VcpuSnapshot {
                gprs,
                pc: vcpu.get_reg(Reg::PC).map_err(hvf_error)?,
                pstate: vcpu.get_reg(Reg::CPSR).map_err(hvf_error)?,
                sp_el0,
                // HVF captures no separate SP_EL1 (its EL1 trampoline never pushes a
                // kernel stack); mirror sp_el0 so the neutral round-trip is total —
                // `restore_vcpu*` seeds SP_EL1 from `core.sp_el0`, not this field.
                sp_el1: sp_el0,
                elr_el1: vcpu.get_sys_reg(SysReg::ELR_EL1).map_err(hvf_error)?,
                spsr_el1: vcpu.get_sys_reg(SysReg::SPSR_EL1).map_err(hvf_error)?,
                ttbr0: vcpu.get_sys_reg(SysReg::TTBR0_EL1).map_err(hvf_error)?,
                ttbr1: vcpu.get_sys_reg(SysReg::TTBR1_EL1).map_err(hvf_error)?,
                tcr: vcpu.get_sys_reg(SysReg::TCR_EL1).map_err(hvf_error)?,
                sctlr: vcpu.get_sys_reg(SysReg::SCTLR_EL1).map_err(hvf_error)?,
                mair: vcpu.get_sys_reg(SysReg::MAIR_EL1).map_err(hvf_error)?,
                vbar: vcpu.get_sys_reg(SysReg::VBAR_EL1).map_err(hvf_error)?,
                cpacr: vcpu.get_sys_reg(SysReg::CPACR_EL1).map_err(hvf_error)?,
                tpidr_el0: vcpu.get_sys_reg(SysReg::TPIDR_EL0).map_err(hvf_error)?,
                tpidrro_el0: vcpu.get_sys_reg(SysReg::TPIDRRO_EL0).map_err(hvf_error)?,
                tpidr_el1: vcpu.get_sys_reg(SysReg::TPIDR_EL1).map_err(hvf_error)?,
                actlr_el1: vcpu.get_sys_reg(SysReg::ACTLR_EL1).map_err(hvf_error)?,
                vregs,
                fpsr,
                fpcr,
            },
            // The engine owns last_exit_class; the snapshot carries 0 for it.
            last_exit_class: 0,
        })
    }

    /// Restore `snap` onto the passed `vcpu` (the fork/clone/reclaim rebuild +
    /// the engine's `Aarch64Vcpu::restore`). The old `restore_vcpu` body.
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
        vcpu.set_sys_reg(SysReg::VBAR_EL1, snap.core.vbar)
            .map_err(hvf_error)?;
        vcpu.set_sys_reg(SysReg::SPSR_EL1, snap.core.spsr_el1)
            .map_err(hvf_error)?;
        vcpu.set_sys_reg(SysReg::ELR_EL1, snap.core.elr_el1)
            .map_err(hvf_error)?;
        vcpu.set_sys_reg(SysReg::TPIDR_EL0, snap.core.tpidr_el0)
            .map_err(hvf_error)?;
        // TPIDRRO_EL0 (guest-readable thread ptr) + TPIDR_EL1 (carrick's fast-gettid
        // tid stamp) are zeroed by hv_vcpu_create, so a rebuilt vCPU (fork/clone or
        // a destroy/recreate reclaim) must restore both.
        vcpu.set_sys_reg(SysReg::TPIDRRO_EL0, snap.core.tpidrro_el0)
            .map_err(hvf_error)?;
        vcpu.set_sys_reg(SysReg::TPIDR_EL1, snap.core.tpidr_el1)
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
        vcpu.set_sys_reg(SysReg::VBAR_EL1, snap.core.vbar)
            .map_err(hvf_error)?;
        vcpu.set_sys_reg(SysReg::TPIDR_EL0, snap.core.tpidr_el0)
            .map_err(hvf_error)?;
        // SP_EL1 for the brief EL1h trampoline window. The trampoline only executes
        // one `eret` and touches no stack, but give it a sane value (the child's EL0
        // stack works; the trampoline never pushes).
        vcpu.set_sys_reg(SysReg::SP_EL1, snap.core.sp_el0)
            .map_err(hvf_error)?;
        // Enable the MMU last, identically to the parent.
        vcpu.set_sys_reg(SysReg::SCTLR_EL1, snap.core.sctlr)
            .map_err(hvf_error)?;
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
    ) -> Result<carrick_aarch64::Aarch64Exit, TrapError> {
        use applevisor::prelude::*;
        use carrick_aarch64::Aarch64Exit;

        // Lifecycle marker: the first entry here is the moment the guest first
        // runs — i.e. INITIAL boot/setup is done. Fired once per process; since
        // carrick forks via no-exec `libc::fork`, a forked child inherits the
        // parent's already-completed Once and does NOT re-fire this.
        static FIRST_RUN: std::sync::Once = std::sync::Once::new();
        FIRST_RUN.call_once(|| crate::probes::lifecycle(crate::probes::phase::FIRST_VCPU_RUN));

        // Bounds lazy re-mapping of dropped guest_shared aliases so a
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
            // forking thread's mappings, dropping a `guest_shared` alias mapped by
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
                let fault_ipa = if exit.exception.physical_address != 0 {
                    exit.exception.physical_address
                } else {
                    // Aliases are placed at va = HIGH_VA_THRESHOLD + (ipa - BASE).
                    exit.exception
                        .virtual_address
                        .wrapping_sub(crate::memory::LINUX_HIGH_VA_THRESHOLD)
                        .wrapping_add(crate::memory::LINUX_ALIAS_IPA_BASE)
                };
                if let Some(b) = lookup_shared_alias(fault_ipa)
                    && alias_remap_limiter.allow(b.ipa)
                {
                    // SAFETY: `host_addr` is a live MAP_SHARED mmap (the alias
                    // backing) registered by add_alias; re-mapping the same host
                    // range to the same IPA in this VM is idempotent. A nonzero rc
                    // (e.g. already mapped by a racing sibling) is fine — re-run
                    // and re-walk regardless.
                    let _ = unsafe {
                        applevisor_sys::hv_vm_map(
                            b.host_addr as *mut std::ffi::c_void,
                            b.ipa,
                            b.size,
                            b.perms,
                        )
                    };
                    crate::probes::hv_vm_map_alias(
                        exit.exception.virtual_address,
                        b.ipa,
                        b.size as u64,
                        0,
                        0,
                    );
                    // Diagnostic-only alias-remap counter+dump, gated behind
                    // `debug-stats` (no other consumer reads the counter).
                    #[cfg(feature = "debug-stats")]
                    {
                        let n =
                            ALIAS_REMAP_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        if n.is_multiple_of(256) {
                            eprintln!("ALIAS_REMAP n={n} ipa=0x{:x}", b.ipa);
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
                let ec = (esr_el1 >> 26) & 0x3f;
                eprintln!(
                    "FAIL-LOUD pid={pid}: guest executed at EL1 and faulted \
                     (current-EL sync vector) — carrick state corruption (a guest \
                     resume left PSTATE at EL1, commonly a signal handler entered \
                     with SPSR_EL1=EL1h). Was a silent 100% CPU spin before the \
                     hvc #3 vector trap. esr_el1={esr_el1:#x} ec={ec:#x} \
                     elr_el1={elr_el1:#x} far_el1={far_el1:#x} spsr_el1={spsr_el1:#x}",
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
                    // Decoded fault diagnostics for `carrick trace`
                    // (vcpu-fault-regs) as SCALARS — the faulting instruction word
                    // + the base register a load/store dereferenced and its value.
                    {
                        let insn = 0u64;
                        let rn = ((insn >> 5) & 0x1f) as u32;
                        let xrn = GPR_TABLE
                            .get(rn as usize)
                            .and_then(|r| vcpu.get_reg(*r).ok())
                            .unwrap_or(0);
                        crate::probes::vcpu_fault_regs(underlying, elr, far, insn, rn, xrn);
                    }
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
            // A genuine guest EL0 `svc`. Read the syscall frame; the engine owns
            // the pending-syscall/SA_RESTART state (it sets last_syscall_nr/orig_x0
            // from the frame). resume_pc = ELR_EL1 (= svc+4), which the EL1
            // vector's `eret` consumes.
            let resume_pc = vcpu.get_sys_reg(SysReg::ELR_EL1).unwrap_or(0);
            let frame = carrick_hal::read_aarch64_syscall_frame(|r| hvf_get_reg(vcpu, r))
                .map_err(|e| TrapError::Hypervisor(e.to_string()))?;
            // vcpu_trap probe parity: guest PC at the trap (= ELR_EL1) + the live
            // FP/SP/LR so a DTrace consumer can walk the guest call chain. The
            // stack-region bases require the per-thread mapping list (on
            // HvfVmState, not reachable here), so report zero bases.
            let lr = vcpu.get_reg(Reg::LR).unwrap_or(0);
            let fp = vcpu.get_reg(Reg::X29).unwrap_or(0);
            let sp = vcpu.get_sys_reg(SysReg::SP_EL0).unwrap_or(0);
            crate::probes::vcpu_trap(&crate::compat::GuestRegs {
                pc: resume_pc,
                sp,
                fp,
                lr,
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
            guest_shared: self.guest_shared,
        }
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl MappingView {
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
            // Preserve guest_shared so a MAP_SHARED-file alias resolved via this
            // fallback is still recognized as a cross-process futex word by
            // shared_futex_host_addr (an anon arena alias must NOT be).
            guest_shared: b.guest_shared,
        }
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

fn align_down(value: u64, alignment: u64) -> u64 {
    value / alignment * alignment
}

fn align_up(value: u64, alignment: u64) -> Result<u64, TrapError> {
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

/// Back one guest region with a raw `mmap(MAP_ANON)` buffer + `hv_vm_map`,
/// returning an UNOWNED [`HvfMappedRegion`] (`memory: None`).
///
/// We deliberately do NOT use applevisor's `Memory` (`vm.memory_create`), whose
/// `alloc_zeroed(Layout::from_size_align(size, 16 KiB))` produces a VM mapping
/// that macOS `fork(2)` is ~8x more expensive to COW than a clean anonymous
/// `mmap` — even though neither is resident (both ~6 MiB RSS). For carrick's
/// ~640 MiB of guest windows this was the dominant per-fork cost: 640 MiB
/// fork+wait measured 9.6 ms (applevisor) vs 1.1 ms (raw mmap). See
/// `examples/fork_alloc_bench.rs`. The host pages leak only at process exit,
/// matching the existing `ManuallyDrop<HvfInner>` discipline (applevisor
/// `Memory` Drop never ran either) and the `map_shared_file` raw path.
/// Allocate a fresh `MAP_SHARED` anon buffer and copy `src`'s RESIDENT pages
/// into it. Used by `HvfInner::fork` to take a private snapshot of guest-
/// PRIVATE memory: guest RAM is host-`MAP_SHARED` for HVF coherence (see
/// `map_region_raw`), so `fork(2)` does NOT COW-isolate it — without an
/// explicit copy a forked child and its parent would share, and corrupt, the
/// macOS `vm_inherit.h`: parent + child share the SAME pages across `fork(2)`.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
const VM_INHERIT_SHARE: libc::c_int = 0;
/// macOS `vm_inherit.h`: child gets a COW copy across `fork(2)` (the default).
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
const VM_INHERIT_COPY: libc::c_int = 1;

/// Set a guest region's per-process `fork(2)` inheritance via macOS `minherit(2)`.
///
/// `VM_INHERIT_SHARE` makes the WHOLE region's pages SHARED across a later
/// `libc::fork` (XNU `vm_map_fork_share`: the child references the SAME
/// `vm_object` — no shadow, no copy — and both entries are `is_shared`; the
/// parent is NOT converted to copy-on-write, unlike FreeBSD/NetBSD UVM). This is
/// how a vfork/CLONE_VM child gets true write-visibility into the SUSPENDED
/// parent (LTP clone05) while keeping the same physical pages, so the child's
/// re-`hv_vm_map` binds the same PAs. `VM_INHERIT_COPY` restores cheap COW
/// isolation for subsequent plain forks.
///
/// MUST be applied to a WHOLE mmap region (offset 0, full len): `minherit` on a
/// sub-range clips the `vm_map_entry`, so the first fork shadows the sub-entry
/// (`vo_size > entry_size`) instead of sharing. carrick's per-region mmaps make
/// the whole-region call natural. Best-effort: a failure degrades to COW (the
/// vfork child just won't see the parent's writes), never a crash.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn set_region_fork_inheritance(host_addr: *mut u8, size: usize, inherit: libc::c_int) {
    unsafe extern "C" {
        fn minherit(
            addr: *mut libc::c_void,
            len: libc::size_t,
            inherit: libc::c_int,
        ) -> libc::c_int;
    }
    let rc = unsafe { minherit(host_addr.cast(), size, inherit) };
    if rc != 0 && std::env::var_os("CARRICK_FORK_DEBUG").is_some() {
        eprintln!(
            "[FORKDBG pid={}] minherit(host={host_addr:p}, size={size}, inherit={inherit}) failed: {}",
            unsafe { libc::getpid() },
            std::io::Error::last_os_error()
        );
    }
}

/// same pages. Called pre-fork while the guest vCPU is suspended (atomic, no
/// race). Only resident pages are copied (mincore-gated) so the snapshot is
/// sparse; on mincore failure we fall back to a full copy (correct, slower).
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn clone_region_for_child(
    src: *mut u8,
    size: usize,
    guest_start: u64,
) -> Result<crate::host_mapping::OwnedHostMapping, TrapError> {
    let dst = crate::host_mapping::OwnedHostMapping::map_shared_anon(
        size,
        crate::host_mapping::HostMappingKind::ChildPrivateSnapshot,
    )
    .map_err(|error| {
        TrapError::Hypervisor(format!(
            "fork child-snapshot mmap (size={size}) failed: {error}"
        ))
    })?;
    let dst_ptr = dst.as_ptr();
    let page = {
        let p = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        if p <= 0 { 16 * 1024 } else { p as usize }
    };
    // Bound the residency scan to the region's used prefix. The 32 GiB mmap
    // arena is mapped once but the guest only bump-allocates a sliver from its
    // base; `mincore` over the full window walks all ~2M pages (~470 ms/fork —
    // the dominant cost of any subprocess-spawning guest). The dispatcher's
    // arena high-water (published into GUEST_ARENA_HIGH_WATER by handle_fork)
    // says the guest has only touched `[LINUX_MMAP_BASE, hw)`; pages past it are
    // untouched in the parent too, so the child's freshly-zeroed snapshot needs
    // no copy there. Other regions (heap, stack, trampolines) keep the full
    // scan. `u64::MAX` default ⇒ full scan (non-fork callers / tests).
    let scan_size = if guest_start == crate::memory::LINUX_MMAP_BASE {
        let hw = GUEST_ARENA_HIGH_WATER.load(std::sync::atomic::Ordering::SeqCst);
        hw.saturating_sub(guest_start)
            .try_into()
            .unwrap_or(size)
            .min(size)
    } else {
        size
    };
    if scan_size == 0 {
        return Ok(dst); // nothing resident to copy; dst stays lazily zero
    }
    let n_pages = scan_size.div_ceil(page);
    let mut resident = vec![0u8; n_pages];
    let rc = unsafe {
        libc::mincore(
            src as *mut libc::c_void,
            scan_size,
            resident.as_mut_ptr() as *mut libc::c_char,
        )
    };
    if rc != 0 {
        unsafe { std::ptr::copy_nonoverlapping(src, dst_ptr, size) };
        return Ok(dst);
    }
    for (i, &flag) in resident.iter().enumerate() {
        if flag & 1 != 0 {
            let off = i * page;
            let len = page.min(size - off);
            unsafe { std::ptr::copy_nonoverlapping(src.add(off), dst_ptr.add(off), len) };
        }
    }
    Ok(dst)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn map_region_raw(mapping: &GuestMapping) -> Result<HvfMappedRegion, TrapError> {
    let size = usize::try_from(mapping.mapped_size)
        .map_err(|_| TrapError::MappingTooLarge(mapping.mapped_size))?;
    // MAP_SHARED, not MAP_PRIVATE: a MAP_PRIVATE anon page mapped into the
    // guest via hv_vm_map desyncs from the host buffer — the guest's own store
    // and a later guest load observe different memory (the "PROT_REA" wild-PC
    // crash: a dynamic binary's GOT slot that ld.so resolved reads back stale).
    // MAP_SHARED anon is HVF-coherent (same as `map_shared_file`). The cost:
    // fork(2) no longer COW-isolates these pages, so `HvfInner::fork` takes an
    // explicit private snapshot for the child (see `clone_region_for_child`).
    // The aperture region is host-MAP_SHARED so it stays shared across fork(2)
    // (never snapshotted); all other regions are private guest RAM.
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
    let perms = hvf_perms(mapping.perms);
    let perms_raw: u64 = u64::from(perms);
    // Map at the IPA (identity for all but the Rosetta alias); the guest's
    // stage-1 page tables translate the VIRTUAL `guest_start` to this IPA.
    let r = unsafe {
        applevisor_sys::hv_vm_map(
            host.cast::<std::ffi::c_void>(),
            mapping.ipa_start,
            size,
            perms_raw,
        )
    };
    if r != 0 {
        return Err(TrapError::Hypervisor(format!(
            "hv_vm_map(ipa=0x{:x}, va=0x{:x}, size={size}) failed: 0x{r:x}",
            mapping.ipa_start, mapping.guest_start
        )));
    }
    let end =
        mapping
            .guest_start
            .checked_add(mapping.mapped_size)
            .ok_or(TrapError::MappingOverflow {
                guest_start: mapping.guest_start,
                mapped_size: mapping.mapped_size,
            })?;
    let guest_shared = host_mapping.guest_shared();
    Ok(HvfMappedRegion {
        start: mapping.guest_start,
        ipa: mapping.ipa_start,
        end,
        host_addr: host,
        size,
        perms,
        memory: None,
        host_mapping: Some(host_mapping),
        // Private guest RAM (data/bss/heap/stack/MAP_PRIVATE): fork snapshots it.
        guest_shared,
        // Boot regions carry their true guest write-intent (image=RX, page
        // tables=RO -> not writable; heap/stack/data=RW -> writable).
        guest_writable: mapping.perms.write,
    })
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

/// The HVF concurrent-vCPU budget (cap − fork-rebuild reserve) for the bounded
/// M:N scheduler the engine installs via `GuestVmBackend::vcpu_budget`. Same value
/// the retired `vcpu_gate` enforced; reclaim recycles vCPUs so >cap guest threads
/// run instead of hanging. macOS/HVF-only: `vcpu_gate` (and the whole HVF backend)
/// is cfg'd out off the HVF lane, and the only caller (the new module's
/// `GuestVmBackend::vcpu_budget`) is macOS-only too.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn hvf_vcpu_budget() -> usize {
    vcpu_gate::budget().max(1) as usize
}

// NOTE: the thread-sibling register seeding (`seed_child_snapshot`) now lives
// ONCE in the shared engine (`carrick_aarch64::seed_sibling_snapshot`), which the
// engine's `build_sibling_spec` applies before `materialize_sibling`. HVF's
// `from_thread_spec` only stands up the vCPU + mirrors the mapping metadata; the
// engine restores the seeded snapshot onto it.

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[cfg(test)]
mod alias_remap_limiter_tests {
    use super::*;

    #[test]
    fn caps_repeated_faults_on_one_alias_backing() {
        let mut limiter = AliasRemapLimiter::default();
        let ipa = crate::memory::LINUX_ALIAS_IPA_BASE + 0x20_0000;

        for _ in 0..AliasRemapLimiter::MAX_ATTEMPTS_PER_IPA {
            assert!(limiter.allow(ipa));
        }
        assert!(!limiter.allow(ipa));
    }

    #[test]
    fn permits_many_distinct_alias_backings() {
        let mut limiter = AliasRemapLimiter::default();

        for i in 0..64 {
            let ipa = crate::memory::LINUX_ALIAS_IPA_BASE + i * 0x20_0000;
            assert!(
                limiter.allow(ipa),
                "alias backing {i} should not hit a global cap"
            );
        }
    }

    #[test]
    fn exhausted_alias_does_not_block_a_different_alias() {
        let mut limiter = AliasRemapLimiter::default();
        let first = crate::memory::LINUX_ALIAS_IPA_BASE;
        let second = first + 0x20_0000;

        for _ in 0..AliasRemapLimiter::MAX_ATTEMPTS_PER_IPA {
            assert!(limiter.allow(first));
        }

        assert!(!limiter.allow(first));
        assert!(limiter.allow(second));
        assert!(!limiter.allow(first));
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[cfg(test)]
mod memory_protection_tests {
    use super::*;

    #[test]
    fn exec_level_classifies_el0_as_guest_el1_as_kernel() {
        // PSTATE M[3:0]: EL0t=0b0000, EL1t=0b0100, EL1h=0b0101.
        assert_eq!(ExecLevel::from_pstate(0b0000), ExecLevel::Guest);
        assert!(ExecLevel::from_pstate(0b0000).is_guest());
        // EL0t with DAIF/nzcv bits set high is still EL0 (only M[3:2] matter).
        assert_eq!(ExecLevel::from_pstate(0x6000_0000), ExecLevel::Guest);
        assert_eq!(ExecLevel::from_pstate(0b0100), ExecLevel::Kernel); // EL1t
        assert_eq!(ExecLevel::from_pstate(0b0101), ExecLevel::Kernel); // EL1h
        assert!(!ExecLevel::from_pstate(0b0101).is_guest());
    }

    #[test]
    fn cloned_protection_metadata_shares_updates_across_thread_engines() {
        let protections = std::sync::Arc::new(MemoryProtections::default());
        let sibling = std::sync::Arc::clone(&protections);

        protections.set_no_access(0x4000, 0x2000, true);
        assert!(sibling.range_no_access(0x4fff, 1));

        sibling.set_no_access(0x5000, 0x1000, false);
        assert!(protections.range_no_access(0x4000, 1));
        assert!(protections.range_no_access(0x4fff, 1));
        assert!(!protections.range_no_access(0x5000, 1));
        assert!(!protections.range_no_access(0x6000 - 1, 1));
    }

    #[test]
    fn protection_ranges_are_sorted_coalesced_and_split_on_clear() {
        let protections = MemoryProtections::default();

        protections.set_no_access(0x3000, 0x1000, true);
        protections.set_no_access(0x1000, 0x1000, true);
        protections.set_no_access(0x2000, 0x1000, true);

        assert_eq!(protections.snapshot(), vec![(0x1000, 0x4000)]);
        assert!(protections.range_no_access(0x1800, 1));
        assert!(protections.range_no_access(0x3fff, 1));
        assert!(!protections.range_no_access(0x4000, 1));

        protections.set_no_access(0x2000, 0x800, false);

        assert_eq!(
            protections.snapshot(),
            vec![(0x1000, 0x2000), (0x2800, 0x4000)]
        );
        assert!(!protections.range_no_access(0x2000, 0x800));
        assert!(protections.range_no_access(0x2800, 1));
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[cfg(test)]
mod thread_sibling_tests {
    use super::*;

    // NOTE: the thread-sibling register SEEDING tests (child_resumes_at_post_
    // syscall_pc_with_x0_zero / child_uses_clone_stack_and_tls /
    // child_keeps_parent_tls_when_clone_tls_is_zero / child_copies_all_other_
    // gprs_and_sysregs) moved with `seed_child_snapshot` into the shared engine:
    // they live ONCE in `carrick_aarch64`'s `seed_applies_thread_entry_deltas`
    // (over the neutral `Aarch64VcpuSnapshot`). HVF no longer owns the seeding, so
    // it no longer owns those assertions.

    #[test]
    fn decodes_el0_counter_register_traps() {
        let cntfrq = (AARCH64_SYS64_EXCEPTION_CLASS << AARCH64_EXCEPTION_CLASS_SHIFT)
            | AARCH64_SYS64_ISS_SYS_CNTFRQ
            | (1 << AARCH64_SYS64_ISS_RT_SHIFT);
        let cntvct = (AARCH64_SYS64_EXCEPTION_CLASS << AARCH64_EXCEPTION_CLASS_SHIFT)
            | AARCH64_SYS64_ISS_SYS_CNTVCT
            | (2 << AARCH64_SYS64_ISS_RT_SHIFT);

        assert_eq!(
            decode_el0_sys64_read(cntfrq),
            Some((1, El0SysRegRead::CntfrqEl0))
        );
        assert_eq!(
            decode_el0_sys64_read(cntvct),
            Some((2, El0SysRegRead::CntvctEl0))
        );
        // CTR_EL0 / DCZID_EL0 — the cache-geometry reads glibc 2.41 does at
        // startup. The faulting `mrs x1, ctr_el0` observed from python:3.12-slim
        // was ESR_EL1=0x6232c021 (EC=0x18, Rt=1): decode it directly.
        assert_eq!(
            decode_el0_sys64_read(0x6232c021),
            Some((1, El0SysRegRead::CtrEl0))
        );
        let dczid = (AARCH64_SYS64_EXCEPTION_CLASS << AARCH64_EXCEPTION_CLASS_SHIFT)
            | AARCH64_SYS64_ISS_SYS_DCZID
            | (3 << AARCH64_SYS64_ISS_RT_SHIFT);
        assert_eq!(
            decode_el0_sys64_read(dczid),
            Some((3, El0SysRegRead::DczidEl0))
        );
        assert_eq!(decode_el0_sys64_read(0), None);
    }

    #[test]
    fn thread_mapping_descriptor_preserves_shared_mapping_metadata() {
        // `into_unowned_region` (the surviving half of the old `ThreadMappingDesc`
        // round-trip; `from_region` moved to the engine's sibling-builder seam)
        // must re-materialise the syscall-path metadata UNOWNED (memory/host_mapping
        // = None) so a sibling never frees the main engine's buffers.
        let desc = ThreadMappingDesc {
            start: 0x1000,
            ipa: 0x1000,
            end: 0x5000,
            host_addr: 0x7000usize as *mut u8,
            size: 0x4000,
            perms: applevisor::memory::MemPerms::ReadWrite,
            guest_shared: true,
            guest_writable: true,
        };

        let copied = desc.into_unowned_region();

        assert_eq!(copied.start, 0x1000);
        assert_eq!(copied.end, 0x5000);
        assert_eq!(copied.host_addr, 0x7000usize as *mut u8);
        assert_eq!(copied.size, 0x4000);
        assert_eq!(copied.perms, applevisor::memory::MemPerms::ReadWrite);
        assert!(copied.memory.is_none());
        assert!(copied.host_mapping.is_none());
        assert!(copied.guest_shared);
    }

    fn mapped_region(start: u64, end: u64, ipa: u64) -> HvfMappedRegion {
        HvfMappedRegion {
            start,
            ipa,
            end,
            host_addr: std::ptr::null_mut(),
            size: usize::try_from(end - start).unwrap(),
            perms: applevisor::memory::MemPerms::ReadWrite,
            memory: None,
            host_mapping: None,
            guest_shared: false,
            guest_writable: true,
        }
    }

    #[derive(Debug, Clone, Copy)]
    struct FakeStageSegment {
        va_start: u64,
        va_end: u64,
        ipa_start: u64,
    }

    impl FakeStageSegment {
        fn new(va_start: u64, va_end: u64, ipa_start: u64) -> Self {
            Self {
                va_start,
                va_end,
                ipa_start,
            }
        }

        fn translate(self, va: u64) -> Option<u64> {
            (va >= self.va_start && va < self.va_end)
                .then_some(self.ipa_start + (va - self.va_start))
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct FakeCopyChunk {
        mapping_idx: usize,
        len: usize,
        mapping_offset: usize,
    }

    struct FakeStageCopyHarness {
        mappings: Vec<HvfMappedRegion>,
        backing: Vec<Vec<u8>>,
        stage: Vec<FakeStageSegment>,
    }

    impl FakeStageCopyHarness {
        fn new(mappings: Vec<HvfMappedRegion>, stage: Vec<FakeStageSegment>) -> Self {
            let backing = mappings
                .iter()
                .map(|mapping| vec![0; mapping.size])
                .collect();
            Self {
                mappings,
                backing,
                stage,
            }
        }

        fn read(&self, address: u64, length: usize) -> Result<Vec<u8>, MemoryError> {
            let plan = self.plan(address, length)?;
            let mut bytes = vec![0; length];
            let mut copied = 0usize;
            for chunk in plan {
                let src = &self.backing[chunk.mapping_idx]
                    [chunk.mapping_offset..chunk.mapping_offset + chunk.len];
                bytes[copied..copied + chunk.len].copy_from_slice(src);
                copied += chunk.len;
            }
            Ok(bytes)
        }

        fn write(
            &mut self,
            address: u64,
            bytes: &[u8],
            require_guest_writable: bool,
        ) -> Result<(), MemoryError> {
            let plan = self.plan(address, bytes.len())?;
            if require_guest_writable
                && plan
                    .iter()
                    .any(|chunk| !self.mappings[chunk.mapping_idx].guest_writable)
            {
                return Err(MemoryError::OutOfBounds {
                    address,
                    length: bytes.len(),
                });
            }

            let mut copied = 0usize;
            for chunk in plan {
                let dst = &mut self.backing[chunk.mapping_idx]
                    [chunk.mapping_offset..chunk.mapping_offset + chunk.len];
                dst.copy_from_slice(&bytes[copied..copied + chunk.len]);
                copied += chunk.len;
            }
            Ok(())
        }

        fn mapping_bytes(&self, idx: usize) -> &[u8] {
            &self.backing[idx]
        }

        fn plan(&self, address: u64, length: usize) -> Result<Vec<FakeCopyChunk>, MemoryError> {
            let mut copied = 0usize;
            let mut plan = Vec::new();
            while copied < length {
                let (chunk_address, chunk_len) =
                    HvfVmState::guest_copy_chunk(address, copied, length)?;
                let stage1_ipa = crate::memory::is_high_va(chunk_address)
                    .then(|| self.translate(chunk_address))
                    .flatten();
                let mapping_idx = HvfVmState::mapping_index_for_range(
                    &self.mappings,
                    chunk_address,
                    chunk_len,
                    stage1_ipa,
                )
                .ok_or(MemoryError::OutOfBounds { address, length })?;
                let mapping_offset =
                    usize::try_from(chunk_address - self.mappings[mapping_idx].start).unwrap();
                plan.push(FakeCopyChunk {
                    mapping_idx,
                    len: chunk_len,
                    mapping_offset,
                });
                copied += chunk_len;
            }
            Ok(plan)
        }

        fn translate(&self, va: u64) -> Option<u64> {
            let va = strip_pointer_tag(va);
            self.stage.iter().find_map(|segment| segment.translate(va))
        }
    }

    #[test]
    fn high_va_mapping_lookup_prefers_stage1_ipa_owner_over_newer_va_overlap() {
        let b_start = crate::memory::LINUX_HIGH_VA_THRESHOLD + 0x3000;
        let b_ipa = crate::memory::LINUX_ALIAS_IPA_BASE + 0x20_0000;
        let mappings = vec![
            mapped_region(b_start, b_start + 0x4000, b_ipa),
            // Newer region A over-claims into B's VA range because the host
            // mapping size was rounded to 16 KiB. The guest stage-1 walk still
            // says B owns b_start+0x1000, so B must win.
            mapped_region(
                crate::memory::LINUX_HIGH_VA_THRESHOLD,
                crate::memory::LINUX_HIGH_VA_THRESHOLD + 0x4000,
                crate::memory::LINUX_ALIAS_IPA_BASE,
            ),
        ];

        let idx = HvfVmState::mapping_index_for_range(
            &mappings,
            b_start + 0x1000,
            8,
            Some(b_ipa + 0x1000),
        );

        assert_eq!(idx, Some(0));
    }

    #[test]
    fn guest_copy_chunks_reselect_stage1_owner_across_alias_boundary() {
        let old_start = crate::memory::LINUX_HIGH_VA_THRESHOLD;
        let old_ipa = crate::memory::LINUX_ALIAS_IPA_BASE;
        let new_start = old_start + 0x3000;
        let new_ipa = old_ipa + 0x20_0000;
        let mappings = vec![
            mapped_region(old_start, old_start + 0x9000, old_ipa),
            mapped_region(new_start, new_start + 0x6000, new_ipa),
        ];
        let address = old_start + 0x2f50;
        let length = 0x5000usize;

        // The old single-region path would select the owner for the range's
        // start and use it for bytes after new_start, even though stage-1 has
        // already repointed that tail to the newer alias.
        assert_eq!(
            HvfVmState::mapping_index_for_range(
                &mappings,
                address,
                length,
                Some(old_ipa + (address - old_start)),
            ),
            Some(0),
        );

        let mut offset = 0usize;
        let mut owners = Vec::new();
        while offset < length {
            let (chunk_address, chunk_len) =
                HvfVmState::guest_copy_chunk(address, offset, length).unwrap();
            let stage1_ipa = if chunk_address < new_start {
                old_ipa + (chunk_address - old_start)
            } else {
                new_ipa + (chunk_address - new_start)
            };
            let idx = HvfVmState::mapping_index_for_range(
                &mappings,
                chunk_address,
                chunk_len,
                Some(stage1_ipa),
            )
            .unwrap();
            if owners.last() != Some(&idx) {
                owners.push(idx);
            }
            offset += chunk_len;
        }

        assert_eq!(owners, vec![0, 1]);
    }

    #[test]
    fn fake_stage1_copy_writes_tail_to_live_owner_backing() {
        let old_start = crate::memory::LINUX_HIGH_VA_THRESHOLD;
        let old_ipa = crate::memory::LINUX_ALIAS_IPA_BASE;
        let new_start = old_start + 0x3000;
        let new_ipa = old_ipa + 0x20_0000;
        let mut harness = FakeStageCopyHarness::new(
            vec![
                mapped_region(old_start, old_start + 0x9000, old_ipa),
                mapped_region(new_start, new_start + 0x6000, new_ipa),
            ],
            vec![
                FakeStageSegment::new(old_start, new_start, old_ipa),
                FakeStageSegment::new(new_start, new_start + 0x6000, new_ipa),
            ],
        );
        let address = old_start + 0x2f50;
        let length = 0x2400usize;
        let boundary_prefix = usize::try_from(new_start - address).unwrap();
        let source: Vec<u8> = (0..length).map(|idx| (idx % 251) as u8).collect();

        harness.write(address, &source, false).unwrap();

        assert_eq!(harness.read(address, length).unwrap(), source);
        assert_eq!(
            &harness.mapping_bytes(0)[0x2f50..0x3000],
            &source[..boundary_prefix]
        );
        assert!(
            harness.mapping_bytes(0)[0x3000..0x5350]
                .iter()
                .all(|byte| *byte == 0)
        );
        assert_eq!(
            &harness.mapping_bytes(1)[..length - boundary_prefix],
            &source[boundary_prefix..]
        );
    }

    #[test]
    fn fake_stage1_checked_write_rejects_readonly_tail_without_partial_write() {
        let old_start = crate::memory::LINUX_HIGH_VA_THRESHOLD;
        let old_ipa = crate::memory::LINUX_ALIAS_IPA_BASE;
        let new_start = old_start + 0x3000;
        let new_ipa = old_ipa + 0x20_0000;
        let mut new_region = mapped_region(new_start, new_start + 0x6000, new_ipa);
        new_region.guest_writable = false;
        let mut harness = FakeStageCopyHarness::new(
            vec![
                mapped_region(old_start, old_start + 0x9000, old_ipa),
                new_region,
            ],
            vec![
                FakeStageSegment::new(old_start, new_start, old_ipa),
                FakeStageSegment::new(new_start, new_start + 0x6000, new_ipa),
            ],
        );
        let address = old_start + 0x2f50;
        let source = vec![0xa5; 0x2400];

        assert!(harness.write(address, &source, true).is_err());
        assert!(harness.mapping_bytes(0).iter().all(|byte| *byte == 0));
        assert!(harness.mapping_bytes(1).iter().all(|byte| *byte == 0));
    }

    #[test]
    fn mapping_lookup_falls_back_to_newest_overlap_without_stage1_ipa() {
        let start = crate::memory::LINUX_HIGH_VA_THRESHOLD;
        let old = mapped_region(start, start + 0x4000, crate::memory::LINUX_ALIAS_IPA_BASE);
        let new = mapped_region(
            start,
            start + 0x4000,
            crate::memory::LINUX_ALIAS_IPA_BASE + 0x20_0000,
        );
        let mappings = vec![old, new];

        let idx = HvfVmState::mapping_index_for_range(&mappings, start + 0x1000, 8, None);

        assert_eq!(idx, Some(1));
    }
}

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
        carrick_hal::Reg::X(n) if (n as usize) < GPR_TABLE.len() => {
            vcpu.get_reg(GPR_TABLE[n as usize]).map_err(hvf_os_error)
        }
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
        carrick_hal::Reg::X(n) if (n as usize) < GPR_TABLE.len() => {
            vcpu.set_reg(GPR_TABLE[n as usize], v).map_err(hvf_os_error)
        }
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

#[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
mod tag_strip_tests {
    use super::strip_pointer_tag;

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
