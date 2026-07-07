//! The thin per-VMM backend trait pair (`Aarch64Vmm` + `Aarch64Vcpu`) and the
//! small value types they trade in (`Aarch64Exit`, `Aarch64VcpuSnapshot`,
//! `ForkRamStrategy`).
//!
//! This is the Axis-1 (aarch64 host/VMM) seam, mirroring `carrick-x86`'s
//! [`crate`]-level `X86Vmm`/`X86Vcpu` pair. Everything that is *genuinely*
//! per-VMM on aarch64 (HVF's `applevisor` trap surface vs KVM's MMIO-sentinel
//! trap surface) is named here, and `carrick-aarch64`'s engine scaffold is
//! written ONCE over this pair (Stage 2+). The trait surface is reverse-
//! engineered from the HVF ∩ KVM intersection: the genuinely-irreducible body is
//! [`Aarch64Vcpu::run`] (each backend decodes its native trap surface into
//! [`Aarch64Exit`]); the genuinely-per-VMM divergence is on [`Aarch64Vmm`]
//! (fork VM rebuild, execve remap, sibling spawn, stage-2 mapping, the HVF-only
//! lazy-alias re-map as the [`Aarch64Vmm::handle_memory_exit`] hook).
//!
//! Stage 1 defines this surface only — NOTHING implements it yet (no backend is
//! migrated). It must compile standalone.

use std::sync::Arc;

use carrick_guest_mem::protections::MemoryProtections;
use carrick_guest_mem::{Aarch64SyscallFrame, GuestVa, MemoryError, SharedFutexLocation};
use carrick_hal::{
    GuestEntryRegs, GuestVmBackend, MemPerms, Reg, SlotId, SysReg, TrapError, VcpuKick,
    VcpuRegistry,
};
use carrick_mem::memory::AddressSpace;

/// COW-inherit vs eager full-RAM copy at `fork(2)`. Re-exported from
/// [`carrick_hal`] (the single canonical definition, shared with the x86 lane) so
/// existing `crate::vmm::ForkRamStrategy` references keep resolving.
pub use carrick_hal::ForkRamStrategy;

/// The shared exit shape. Lifted from HVF's `applevisor` `ExitReason`+`ESR.EC`
/// decode ∪ KVM's `VcpuExit::MmioWrite{gpa}`/`Kicked`/`Halt`. Backends decode
/// their native exit into THIS.
///
/// `resume_pc` rides [`Aarch64Exit::Syscall`] so the ENGINE owns the
/// pending-syscall state (the §2.1 contract). On aarch64 it is the post-`svc`
/// `ELR_EL1` the EL1 vector's `eret` consumes — so `complete_syscall` sets X0
/// only and never re-advances PC.
#[derive(Debug, Clone)]
pub enum Aarch64Exit {
    /// A guest EL0 `svc #0`. `frame` carries x0..x5 + x8 (already read via the
    /// shared `read_aarch64_syscall_frame`); `resume_pc` is `ELR_EL1` (= svc+4).
    /// HVF: surfaced when the EL1-vector vehicle is an EXCEPTION with
    /// EC==SVC/HVC-syscall. KVM: `MmioWrite{gpa == SENTINEL_GPA}`.
    Syscall {
        frame: Aarch64SyscallFrame,
        resume_pc: u64,
    },

    /// An EL0 SYNCHRONOUS fault (data/instruction abort, alignment, undef, debug)
    /// the engine lowers to `TrapError::EL0Fault` then to `GuestFault`. Carries
    /// the raw architectural state both backends already build `el0_fault()`
    /// from. `from_el0_direct` is the ONE trap-surface bit: HVF gets a DIRECT
    /// EXCEPTION exit (authoritative PC=ELR, VA=FAR) => `true`; KVM steers the
    /// abort to the guest VBAR and catches it at the fault sentinel, latching
    /// `ELR_EL1`/`FAR_EL1` => `false`. (Matches
    /// `carrick_hal::TrapError::EL0Fault::from_el0_direct`.)
    EL0Fault {
        /// `ESR_EL1`.
        syndrome: u64,
        /// `ELR_EL1` (or authoritative exit PC).
        elr: u64,
        /// `FAR_EL1` (or authoritative exit VA).
        far: u64,
        x16: u64,
        x17: u64,
        x29: u64,
        x30: u64,
        sp: u64,
        from_el0_direct: bool,
    },

    /// An EL0 `MRS` of an emulated ID/timer/cache register that trapped (Rosetta
    /// x86-on-arm + HVF). The engine's shared `emulate_el0_sys64_read` services
    /// it and re-enters; backends whose config never traps `MRS` never surface
    /// this (cf. x86's `FpDoorbell` / `Memory` defaults).
    Sys64Read {
        /// `ESR_EL1` (op0/op1/CRn/CRm/op2 decode).
        esr: u64,
    },

    /// The EL1 stage-1 TLBI maintenance trampoline finished
    /// (`run_el1_maintenance`). HVF: `hvc #1`. KVM:
    /// `MmioWrite{gpa == MAINT_SENTINEL_GPA}`. The shared maintenance loop
    /// matches on THIS instead of each backend matching its native vehicle.
    MaintenanceDone,

    /// WFI/halt with no syscall pending: the engine returns `Ok(None)`, the loop
    /// runs signal delivery and resumes.
    Halt,

    /// Cross-thread kick (HVF `hv_vcpus_exit` -> `ExitReason::CANCELED`; KVM
    /// signal -> `KVM_RUN` EINTR). The shared loop checks: if PC is in the
    /// carrick EL1 vector, swallow + re-enter; else report `Ok(None)`.
    Kicked,

    /// A backend memory exit a sparse/alias backend can resolve and retry. HVF
    /// uses this for the lazy high-VA alias re-map on a forked child's missing
    /// stage-2 entry; KVM never surfaces it (siblings share one VM). Mirrors
    /// `X86Exit::Memory{gpa}` + [`Aarch64Vmm::handle_memory_exit`] (default
    /// `Ok(false)`).
    Memory { gpa: u64, va: u64 },
}

/// Snapshot of a vCPU's full architectural register file (GPRs + stage-1 MMU
/// sysregs + V-regs + FP control), taken on the parent before `fork(2)`/`clone`/
/// `execve` and restored onto the child's rebuilt vCPU.
///
/// Promoted from `carrick-vmm-kvm/src/fork.rs::VcpuSnapshot` so HVF and KVM share
/// ONE snapshot format; the only per-VMM marshalling is
/// [`Aarch64Vcpu::snapshot`]/[`Aarch64Vcpu::restore`]. This is the FP-carrying
/// shape — `vregs`/`fpsr`/`fpcr` are real fields (a zero-stubbed FP form silently
/// corrupts a guest's NEON/FP state across fork/clone/execve and signal
/// save/restore). `.fpsr` holds FPSR and `.fpcr` holds FPCR (do NOT swap).
#[derive(Debug, Clone)]
pub struct Aarch64VcpuSnapshot {
    /// X0..X30 (the general-purpose register file).
    pub gprs: [u64; 31],
    pub pc: u64,
    pub pstate: u64,
    /// `user_pt_regs.sp` == SP_EL0 (the EL0/user stack pointer).
    pub sp_el0: u64,
    pub sp_el1: u64,
    pub elr_el1: u64,
    pub spsr_el1: u64,
    pub ttbr0: u64,
    pub ttbr1: u64,
    pub tcr: u64,
    pub sctlr: u64,
    pub mair: u64,
    pub vbar: u64,
    pub cpacr: u64,
    /// TPIDR_EL0 — the EL0 thread pointer (libc TLS base).
    pub tpidr_el0: u64,
    /// TPIDRRO_EL0 — the read-only EL0 thread pointer. `hv_vcpu_create` zeroes it
    /// and the guest can only READ it (EL1 writes it), so a fork/clone/reclaim must
    /// restore it — vDSO cpu-id / rseq read it. KVM does not use it (left 0).
    pub tpidrro_el0: u64,
    /// TPIDR_EL1 — carrick's per-vCPU scratch. HVF's syscall shim uses it only
    /// transiently to preserve x16 while checking ESR_EL1; the fast `gettid`
    /// path stores the guest tid in CONTEXTIDR_EL1 instead. (On KVM TPIDR_EL1
    /// backs the syscall-frame `saved_x9` stash; the snapshot carries it so a
    /// reclaim/fork round-trips that too.)
    pub tpidr_el1: u64,
    /// ACTLR_EL1 — incl. EnTSO (Rosetta `prctl(PR_SET_MEM_MODEL, TSO)`). Restored
    /// across fork/clone/reclaim so a rebuilt vCPU keeps hardware x86 TSO. KVM has
    /// no such bit (left 0).
    pub actlr_el1: u64,
    /// V0..V31 (the full 128-bit NEON/FP register file).
    pub vregs: [u128; 32],
    /// FPSR.
    pub fpsr: u32,
    /// FPCR.
    pub fpcr: u32,
}

/// Per-vCPU register/run surface. The ONLY thing genuinely per-VMM on the vCPU
/// side. HVF wraps `applevisor::Vcpu`; KVM wraps its `KvmVcpu` (which already
/// provides every method body). Supersedes the bare
/// [`carrick_hal::HvVcpu`] — it adds snapshot/restore, V-regs, FP control, and
/// fault-register reads. The genuinely-per-VMM marshalling lives here and
/// NOWHERE in the shared engine.
pub trait Aarch64Vcpu {
    // ── GPR / sysreg access ──
    fn get_reg(&self, r: Reg) -> Result<u64, TrapError>;
    fn set_reg(&mut self, r: Reg, v: u64) -> Result<(), TrapError>;
    fn get_sys_reg(&self, r: SysReg) -> Result<u64, TrapError>;
    fn set_sys_reg(&mut self, r: SysReg, v: u64) -> Result<(), TrapError>;

    // ── V-regs + FP control (aarch64 V0..V31 are full 128b) ──
    fn get_vreg(&self, n: u32) -> Result<u128, TrapError>;
    fn set_vreg(&mut self, n: u32, v: u128) -> Result<(), TrapError>;
    fn get_fpcr(&self) -> Result<u64, TrapError>;
    fn set_fpcr(&mut self, v: u64) -> Result<(), TrapError>;
    fn get_fpsr(&self) -> Result<u64, TrapError>;
    fn set_fpsr(&mut self, v: u64) -> Result<(), TrapError>;
    // NOTE: the applevisor `set_simd_fp_reg_v` C-shim (the u128-by-value ABI-bug
    // workaround) lives in the HVF impl of `set_vreg` ONLY; KVM calls its native
    // setter. This is exactly x86's "the backend provides the fix (if any)".

    // ── fault-register reads (for Aarch64Exit::EL0Fault capture) ──
    fn get_esr_el1(&self) -> Result<u64, TrapError>;
    fn get_far_el1(&self) -> Result<u64, TrapError>;

    // ── snapshot / restore (the VALUE is ISA-neutral; the I/O is per-VMM) ──
    fn snapshot(&self) -> Result<Aarch64VcpuSnapshot, TrapError>;
    fn restore(&mut self, snap: &Aarch64VcpuSnapshot) -> Result<(), TrapError>;

    /// Restore `snap` onto a FRESHLY-CREATED sibling vCPU (a `clone(CLONE_THREAD)`
    /// thread). DEFAULT: a plain [`Self::restore`] (KVM — its restore sets PC/PSTATE
    /// directly and a fresh KVM vCPU enters EL0 via its own MMIO vehicle). HVF
    /// OVERRIDES: a brand-new HVF vCPU has never transitioned to EL0, so it must
    /// start at the EL0 trampoline (in EL1h) with `SPSR_EL1=EL0t` and
    /// `ELR_EL1=snap.pc`, so the trampoline's single `eret` drops it into EL0 at the
    /// post-clone instruction — distinct from a `restore` that just resumes.
    fn restore_thread_start(&mut self, snap: &Aarch64VcpuSnapshot) -> Result<(), TrapError> {
        self.restore(snap)
    }

    /// The guest's real x9 at the trapped `svc`, IFF this backend's trap vehicle
    /// clobbered it. The EL1 sentinel vector clobbers x9 (the sentinel-store
    /// scratch) after stashing the guest's live x9 in a scratch sysreg (KVM:
    /// `TPIDR_EL1`, free at EL0). The shared `complete_syscall` restores it on every
    /// syscall return. The Linux aarch64 syscall ABI preserves x1..x30, and musl
    /// holds a live x9 across `brk(2)` (`__expand_heap` → `str x10,[x9,#920]`), so
    /// without this the guest faults on the sentinel GPA.
    ///
    /// `Some(x9)` ⟹ the vehicle clobbered x9; `complete_syscall` writes it back.
    /// DEFAULT `Ok(None)` ⟹ the vehicle leaves x9 live in the register file
    /// (HVF's `hvc #2` clobbers NO GPR), so `complete_syscall` must NOT touch it —
    /// a blanket `set_reg(X9, 0)` here would DESTROY the guest's live x9 (musl's
    /// malloc-context pointer) and fault it on the next `str x10,[x9,#920]`.
    fn get_saved_x9(&self) -> Result<Option<u64>, TrapError> {
        Ok(None)
    }

    /// Stamp the guest-visible thread id into the per-thread scratch sysreg the
    /// EL1-vector `gettid` fast path reads, so `gettid(2)` is serviced at EL1
    /// without a host trap. DEFAULT `Ok(())` (no-op) ⟹ this backend has no
    /// in-guest `gettid` fast path and the dispatcher services `gettid` on the
    /// host trap. Genuinely per-VMM: HVF stamps `TPIDR_EL1` (its `hvc` vehicle
    /// leaves that sysreg free); KVM CANNOT — its sentinel vehicle already uses
    /// `TPIDR_EL1` as the live-x9 stash (see [`Self::get_saved_x9`]), so it keeps
    /// the no-op and traps `gettid` to the host.
    fn stamp_guest_thread_id(&self, tid: u64) -> Result<(), TrapError> {
        let _ = tid;
        Ok(())
    }

    /// Run until the next exit, decoding the backend's native trap surface into
    /// [`Aarch64Exit`]. HVF: `hv_vcpu_run` + `get_exit_info()` => EXCEPTION+ESR.EC
    /// decode (svc / abort / sys64 MRS / maint-hvc) + CANCELED => `Kicked`. KVM:
    /// `KVM_RUN` => `MmioWrite{SENTINEL => Syscall, FAULT_SENTINEL => EL0Fault,
    /// MAINT_SENTINEL => MaintenanceDone}` + EINTR => `Kicked`. `resume_pc` filled
    /// at decode time; the ENGINE owns the pending-syscall state (§2.1).
    fn run(&mut self) -> Result<Aarch64Exit, TrapError>;

    /// Force this vCPU out of `run()` from another thread (HVF `hv_vcpus_exit`;
    /// KVM `pthread_kill(SIGRTMIN)`).
    fn kick(&self) -> Result<(), TrapError>;

    /// Set the hardware TSO (total-store-order) memory model. HVF sets
    /// `ACTLR_EL1.EnTSO` for Rosetta; KVM keeps the no-op default. Carried
    /// separately from [`Self::set_memory_model`] so a backend that needs both a
    /// guest-prctl entrypoint and a direct bring-up entrypoint has each.
    fn set_hardware_tso(&mut self, _tso: bool) -> Result<(), TrapError> {
        Ok(())
    }

    /// `prctl(PR_SET_MEM_MODEL, TSO)`: HVF sets `ACTLR_EL1.EnTSO` for Rosetta; KVM
    /// keeps the no-op default (matches `SyscallTrap::set_memory_model`).
    fn set_memory_model(&mut self, _tso: bool) -> Result<(), TrapError> {
        Ok(())
    }
}

/// VM-level memory + lifecycle. One per guest process. This is where the
/// GENUINELY-backend-specific divergence lives: fork VM rebuild, execve remap,
/// sibling spawn, host memory windows + stage-2 mapping, and the HVF-only
/// lazy-alias re-map (as the optional [`Self::handle_memory_exit`] hook). Mirrors
/// `carrick-x86`'s `X86Vmm`.
pub trait Aarch64Vmm: Sized + GuestVmBackend {
    type Vcpu: Aarch64Vcpu;

    /// The per-backend vCPU-kick handle (`KvmKickHandle` / `HvfKickHandle`).
    type KickHandle: VcpuKick + 'static;

    /// The `Send` payload `build_sibling_builder` hands a freshly spawned host
    /// thread; `materialize_sibling` turns it into a fresh `(Self, Self::Vcpu)`
    /// pair on the SAME VM (`clone(CLONE_THREAD)`) without re-registering memory.
    type SiblingBuilder: Send;

    // ── memory windows + stage-2 (the hv_vm_map / KVM-slot seam) ──
    //
    // NOTE: `host_ptr` / `host_ptr_mut` / `write_gpa` are inherited from the shared
    // [`GuestVmBackend`] supertrait (ISA-neutral, signature-identical with x86).

    /// Map host memory at a stage-2 IPA. The STAGE-1 path (page-table edit) is
    /// the shared engine's job; this is only the backend stage-2 op: HVF
    /// `hv_vm_map`; KVM `KVM_SET_USER_MEMORY_REGION`. Used by the shared
    /// `map_host_alias`.
    fn map_stage2(
        &mut self,
        ipa: u64,
        host: *mut u8,
        len: u64,
        perms: MemPerms,
    ) -> Result<(), TrapError>;

    /// Resolve a backend memory exit. HVF overrides for the lazy high-VA alias
    /// re-map (lookup_shared_alias + `hv_vm_map` on a forked child's missing
    /// stage-2 entry — the one HVF-only cluster). KVM keeps the default
    /// `Ok(false)`: siblings share one VM, fork relies on Linux COW, no analogue.
    /// Mirrors `X86Vmm::handle_memory_exit`.
    fn handle_memory_exit(&mut self, _gpa: u64, _va: u64) -> Result<bool, TrapError> {
        Ok(false)
    }

    // ── guest-memory access (the GuestMemory backing seam) ──
    //
    // The PROT_NONE EFAULT gate is keyed on the guest VA and lives in the engine's
    // default `read_bytes`/`write_bytes` (via [`Self::protections`]); the backend
    // hooks below do the BACKING access only, on the stage-1-TRANSLATED IPA, so a
    // `repoint_private` overlay / high-VA alias resolves to the page the guest's
    // OWN EL0 accesses hit rather than the stale shared aperture the VA still
    // covers. For an identity VA `ipa == va`. (HVF: discrete per-region windows;
    // KVM: `GuestRam::safe_access_translated_raw`.)

    /// Read live guest memory at guest-PHYSICAL `gpa` (no VA translation, no
    /// PROT_NONE gate). The shared run-elf / page-table seed paths read raw GPAs
    /// (e.g. the live stage-1 page-table region, an `execve` path string).
    fn read_gpa(&self, gpa: u64, len: usize) -> Result<Vec<u8>, TrapError>;

    /// The PROT_NONE set the engine's default `read_bytes`/`write_bytes` gate on
    /// (keyed on the guest VA). `Some(..)` so the gate fires; the backend owns the
    /// set (KVM in `GuestRam`, shared across siblings) so a sibling thread's
    /// `mprotect(PROT_NONE)` is observed here.
    fn protections(&self) -> Option<&MemoryProtections>;

    /// Backing READ of `[va, va+len)` whose stage-1 translation is `ipa`. The
    /// engine already ran the PROT_NONE gate (on `va`); this does the IPA-translated
    /// single-region backing copy. NULL-guard + single-window bounds live in the
    /// backend.
    fn translated_read(&self, va: u64, ipa: u64, len: usize) -> Result<Vec<u8>, MemoryError>;

    /// Backing WRITE of `bytes` to `[va, va+len)` whose stage-1 translation is
    /// `ipa`. Symmetric to [`Self::translated_read`].
    fn translated_write(&mut self, va: u64, ipa: u64, bytes: &[u8]) -> Result<(), MemoryError>;

    /// Record/clear a PROT_NONE range (the HOST-SIDE EFAULT bookkeeping). The
    /// COMPLEMENTARY guest-side enforcement (so the guest's OWN EL0 access faults)
    /// is the engine's stage-1 `protect_range`/`unmap_range` (page-table edit +
    /// TLBI). Keyed on the guest VA.
    fn set_no_access(&mut self, address: u64, len: usize, no_access: bool);

    /// Scrub the physical backing of `[address, address+len)`, BYPASSING the
    /// PROT_NONE check — clears a reused/`munmap`'d region whose stale bytes must
    /// never resurface after a later `mprotect` makes it readable.
    fn zero_backing(&mut self, address: u64, len: usize) -> Result<(), MemoryError>;

    /// Host wait address plus Linux-visible waiter-count key for a guest futex
    /// word IFF it lives in a `MAP_SHARED` region. `None` for private/COW words,
    /// which stay in-process via the parking-lot `FutexTable`.
    fn shared_futex_location(&self, _guest_addr: GuestVa) -> Option<SharedFutexLocation> {
        None
    }

    /// Back a dynamic high-VA mmap (`DispatchOutcome::MapHostAlias`): mmap the host
    /// file/anon backing and register a fresh stage-2 alias slot, returning the
    /// `(gpa, writable)` the engine then threads into the SHARED stage-1
    /// `map_aliased` edit. KVM derives the alias GPA from the VA inside its <1 TiB
    /// arena; HVF maps at a low alias IPA. The STAGE-1 path stays in the engine.
    fn add_alias(
        &mut self,
        va: u64,
        ipa: u64,
        len: u64,
        payload: &[u8],
        file: Option<(libc::c_int, libc::off_t, libc::c_int)>,
    ) -> Result<(u64, bool), TrapError>;

    /// Called by the engine's `unmap_range`/`unmap_alias_range` BEFORE the stage-1
    /// invalidate, so a backend with a process-shared alias index (HVF's
    /// `alias_registry`) can drop the entry for a high-VA alias whose backing is
    /// about to be freed — a stale `host_addr` must never resolve after the
    /// `OwnedHostMapping` unmaps it. KVM has no such index; default no-op.
    fn on_unmap(&mut self, _va: u64, _len: usize) {}

    /// Whether the engine saves/restores guest FP/SIMD across signal delivery (the
    /// `InjectParams::fpsimd_enabled` flag for inject + restore). HVF gates this on
    /// `CARRICK_NO_FPSIMD` (differential measurement); KVM keeps the default `true`.
    fn fpsimd_enabled(&self) -> bool {
        true
    }

    /// Backing-only fixed-size READ into `dst` whose stage-1 translation is `ipa`,
    /// the no-alloc hot path (`read_u32`/`read_u64`/struct headers). Default:
    /// allocate via [`Self::translated_read`] + copy. HVF overrides to
    /// `volatile`-copy straight into `dst`.
    fn translated_read_into(&self, va: u64, ipa: u64, dst: &mut [u8]) -> Result<(), MemoryError> {
        let bytes = self.translated_read(va, ipa, dst.len())?;
        dst.copy_from_slice(&bytes);
        Ok(())
    }

    /// Backing WRITE that bypasses the guest-visible WRITE permission (a
    /// carrick-INTERNAL frame the guest must receive even into a guest-read-only
    /// mapping: vdso vvar, the signal frame, bootstrap). The host page is writable;
    /// only the guest-visible permission is bypassed. Default: the permission-checked
    /// [`Self::translated_write`] (KVM models no per-mapping write-permission split).
    /// HVF overrides to its unchecked writer.
    fn translated_write_unchecked(
        &mut self,
        va: u64,
        ipa: u64,
        bytes: &[u8],
    ) -> Result<(), MemoryError> {
        self.translated_write(va, ipa, bytes)
    }

    /// Whether every byte of `[va, va+len)` is currently guest-WRITABLE (signal
    /// delivery uses this to detect an unwritable SA_ONSTACK alt-stack → Linux
    /// `force_sigsegv`). Default `true` (KVM models no per-mapping write-permission
    /// flag); HVF checks its per-region `guest_writable` + PROT_NONE set.
    fn guest_range_is_writable(&self, _va: u64, _len: usize) -> bool {
        true
    }

    /// Host pointer for a CONTIGUOUS guest range usable for zero-copy host I/O,
    /// valid IFF the whole `[va, va+len)` is one mapped region (and, for writes,
    /// guest-writable). `None` ⇒ the caller falls back to `read_bytes`/`write_bytes`.
    /// Default `None` (KVM uses the identity copy path); HVF resolves its region.
    fn host_ptr_for_read(&self, _va: u64, _len: usize) -> Option<*const u8> {
        None
    }
    fn host_ptr_for_write(&mut self, _va: u64, _len: usize) -> Option<*mut u8> {
        None
    }

    // ── vCPU lifecycle ──

    /// Create a fresh vCPU bound to this VM.
    fn add_vcpu(&mut self) -> Result<Self::Vcpu, TrapError>;

    // ── fork (skeleton shared; this is the per-VMM rebuild mechanism) ──
    //
    // NOTE: `fork_ram_strategy` is inherited from the shared [`GuestVmBackend`]
    // supertrait (ISA-neutral POLICY, signature-identical with x86).

    /// Freeze the guest RAM segment on the PARENT before `libc::fork`, so an
    /// `EagerCopy` backend's child can rebuild from a coherent image. Only invoked
    /// by the shared `fork()` when [`carrick_hal::GuestVmBackend::fork_ram_strategy`] is `EagerCopy`
    /// (HVF, whose windows are `MAP_SHARED`); the `Cow` default (KVM) is a no-op.
    /// Mirrors the x86 `freeze_ram`.
    fn freeze_ram_for_fork(&mut self) -> Result<(), TrapError> {
        Ok(())
    }

    /// Child-side rebuild after `libc::fork()`: KVM rebuilds a fresh `KvmVm` over
    /// the COW host mmaps; HVF rebuilds a fresh `applevisor` VM and re-`hv_vm_map`s
    /// each region. This hook owns the whole child-side register re-seat (restore
    /// `snapshot`, set x0=0, restore the real x9 = `saved_x9`, advance the child PC
    /// past the EL1-vector sentinel store / HVC, re-calibrate the vDSO clock), since
    /// the PC-advance distance and the post-MMIO replay are per-trap-vehicle. The
    /// shared `fork()` then sets the engine's `is_forked_child` flag, clears the
    /// pending/tracking state, and clones the page-table editor. (The x86
    /// `rebuild_child_after_fork` analogue, plus the aarch64 x9/sentinel carry.)
    fn rebuild_child_after_fork(
        &mut self,
        vcpu: &mut Self::Vcpu,
        snapshot: &Aarch64VcpuSnapshot,
        saved_x9: u64,
    ) -> Result<(), TrapError>;

    /// Parent-side rebuild after `libc::fork()`. KVM keeps its live VM untouched —
    /// default no-op. HVF MUST tear its VM down BEFORE `libc::fork` (a live VM at
    /// fork time makes the child's `hv_vm_create` fail), so BOTH sides rebuild a
    /// fresh `applevisor` VM and re-`hv_vm_map` their buffers; this is the PARENT's
    /// half (the child's is [`Self::rebuild_child_after_fork`]). The shared `fork()`
    /// calls this on the parent branch with the same pre-fork `snapshot`/`saved_x9`.
    /// `share_vm` is the vfork flag (`CLONE_VM`): the child shares the parent's RAM.
    fn rebuild_parent_after_fork(
        &mut self,
        _vcpu: &mut Self::Vcpu,
        _snapshot: &Aarch64VcpuSnapshot,
        _saved_x9: u64,
    ) -> Result<(), TrapError> {
        Ok(())
    }

    /// Set the vfork (`CLONE_VM`) flag for the NEXT fork: the child shares the
    /// parent's guest RAM instead of snapshotting private regions. The shared
    /// `fork_vfork` sets this, runs the normal `fork()`, and the backend's
    /// `freeze_ram_for_fork`/rebuild hooks read it. KVM ignores it (default no-op).
    fn set_vfork_share(&mut self, _share_vm: bool) {}

    /// `execve(2)` image replacement. KVM remaps slots in place on the live VM;
    /// HVF rebuilds the VM. The shared `execve_into` calls this then reprograms
    /// sysregs (shared `program_sysregs`) + clears pending state.
    fn execve_rebuild(
        &mut self,
        vcpu: &mut Self::Vcpu,
        new_image: &AddressSpace,
    ) -> Result<(), TrapError>;

    // NOTE: `process_exit_cleanup` is inherited from the shared [`GuestVmBackend`]
    // supertrait (ISA-neutral hook, signature-identical with x86).

    // ── threaded sibling lifecycle (the generic ThreadedEngine drives these) ──

    /// A kick handle for the current vCPU thread (the engine's `kick_handle`).
    fn kick_handle(&self) -> Self::KickHandle;

    // NOTE: `wait_for_vcpu_slot` / `vcpu_budget` / `reclaims` are inherited from the
    // shared [`GuestVmBackend`] supertrait (ISA-neutral, signature-identical with
    // x86).

    /// Save THIS thread's full guest CPU state before releasing its vCPU slot at a
    /// block point (M:N reclaim), passing the engine-owned `vcpu`. KVM aarch64 does
    /// not reclaim (default no-op error). HVF DESTROYS the vCPU here (snapshot then
    /// raw `hv_vcpu_destroy`) and stashes the snapshot internally; the returned
    /// snapshot is unused for HVF (it round-trips through its own field). The engine
    /// passes `&mut self.vcpu` so a destroy-in-place backend can recycle it.
    fn save_guest_state(
        &mut self,
        _vcpu: &mut Self::Vcpu,
    ) -> Result<Aarch64VcpuSnapshot, TrapError> {
        Err(TrapError::Hypervisor(
            "aarch64 backend does not reclaim (save_guest_state)".into(),
        ))
    }

    /// Save state for a process-shared futex wait. Defaults to the generic
    /// vCPU-only reclaim; HVF overrides this for single-threaded process waits
    /// so it can tear down the whole VM while the process is parked.
    fn save_shared_wait_state(
        &mut self,
        vcpu: &mut Self::Vcpu,
    ) -> Result<Aarch64VcpuSnapshot, TrapError> {
        self.save_guest_state(vcpu)
    }

    /// Re-bind to `slot`'s vCPU after a block (M:N reclaim wake), passing the
    /// engine-owned `vcpu`. HVF RECREATES the vCPU in its existing VM and restores
    /// the parked state, writing the new vCPU back through `vcpu`. KVM no-op.
    fn rebind_to_slot(
        &mut self,
        slot: SlotId,
        snapshot: &Aarch64VcpuSnapshot,
        vcpu: &mut Self::Vcpu,
    ) -> Result<(), TrapError> {
        let _ = (slot, snapshot, vcpu);
        Ok(())
    }

    /// Restore state saved by [`Self::save_shared_wait_state`].
    fn rebind_shared_wait_state(
        &mut self,
        slot: SlotId,
        snapshot: &Aarch64VcpuSnapshot,
        vcpu: &mut Self::Vcpu,
    ) -> Result<(), TrapError> {
        self.rebind_to_slot(slot, snapshot, vcpu)
    }

    /// Build the `Send` payload a `clone(CLONE_THREAD)` sibling needs to add its
    /// own vCPU on the SAME VM (shared VM handle + window descriptors + a
    /// live-vcpu ticket). KVM `build_sibling_spec` (ignores `vcpu`); HVF publishes
    /// its VM + clones the mapping list and needs `vcpu` to snapshot the parent.
    /// `entry` carries the new thread's `clone` deltas (return value / child stack /
    /// TLS).
    fn build_sibling_builder(
        &self,
        vcpu: &Self::Vcpu,
        entry: GuestEntryRegs,
    ) -> Result<Self::SiblingBuilder, TrapError>;

    /// On the sibling thread, turn the builder into a fresh `(VM, vCPU)` on the
    /// SAME VM. KVM `materialize_sibling`; the engine restores the seeded snapshot
    /// and SHARES the protections/page_tables Arc.
    fn materialize_sibling(builder: Self::SiblingBuilder) -> Result<(Self, Self::Vcpu), TrapError>;

    /// Set SP_EL0 on a vfork child given an explicit `child_stack`, through
    /// `&self` (the shared loop holds only `&engine`).
    fn set_guest_sp(&self, vcpu: &Self::Vcpu, sp: u64) -> Result<(), TrapError>;

    /// A FRESH kick registry for the CHILD of a guest `fork(2)` (only the calling
    /// thread survived `libc::fork`). KVM `fresh_fork_kicker`.
    fn fresh_fork_kicker(&self) -> Arc<dyn VcpuRegistry>;

    // ── multithreaded-fork sibling lifecycle (HVF-only; KVM defaults no-op) ──
    //
    // A MULTITHREADED guest fork on HVF must quiesce sibling vCPUs, destroy them
    // so the forker can `hv_vm_destroy` before `libc::fork`, then republish the
    // rebuilt VM for them to recreate vCPUs in. KVM siblings share ONE VM and rely
    // on Linux COW, so none of this is needed (defaults).

    /// Whether this backend's M:N reclaim DESTROYS the vCPU (so its kick handle goes
    /// dead and the runtime must unregister it from the registry before the block
    /// and re-register on wake). `true` for HVF (raw `hv_vcpu_destroy` does not drop
    /// applevisor's liveness Weak); `false` (default) for pool-swap backends.
    fn reclaim_refreshes_kicker(&self) -> bool {
        false
    }

    /// Multithreaded fork — sibling side, step 1: snapshot + destroy THIS vCPU
    /// (raw destroy; only the owning thread may) and publish this thread's regions
    /// so the forker can re-map them into the rebuilt parent VM. KVM no-op.
    fn release_vcpu_for_fork(&mut self, _vcpu: &mut Self::Vcpu) -> Result<(), TrapError> {
        Ok(())
    }

    /// Multithreaded fork — forker, after rebuilding its VM: publish a clone of the
    /// new process VM so quiesced siblings recreate their vCPUs in it. KVM no-op.
    fn publish_vm_for_siblings(&self) -> Result<(), TrapError> {
        Ok(())
    }

    /// Multithreaded fork — sibling side, step 2: recreate this vCPU in the
    /// forker's republished VM and restore the pre-fork register state. KVM no-op.
    fn rebuild_vcpu_after_fork(&mut self, _vcpu: &mut Self::Vcpu) -> Result<(), TrapError> {
        Ok(())
    }

    /// A guest thread is exiting: destroy its vCPU (freeing an HVF concurrent-vCPU
    /// slot). KVM no-op (vCPU drops with the engine).
    fn destroy_vcpu_on_thread_exit(&mut self, _vcpu: &mut Self::Vcpu) {}
}
