//! The thin per-VMM backend trait pair (`X86Vmm` + `X86Vcpu`) and the small
//! value types they trade in (`X86Exit`, `MsrInstall`, `ForkRamStrategy`,
//! `WindowPlan`, `X86Reg`, `X86Seg`).
//!
//! This is the Axis-2 (VMM-backend) seam: everything that is *genuinely*
//! per-VMM is named here, and `carrick-x86`'s engine scaffold is written ONCE
//! over this pair (Stage 2+). The trait surface is reverse-engineered from the
//! KVM ∩ bhyve intersection and the two bhyve outliers are quarantined as the
//! two enum returns [`MsrInstall::NeedsRing0Blob`] and `X86Vcpu::get_fp() ==
//! None`, so removing any one backend would not simplify the trait.
//!
//! Stage 1 defines this surface only — NOTHING implements it yet (no backend is
//! migrated). It must compile standalone.

use std::sync::Arc;

use carrick_guest_mem::{MemoryError, X8664SyscallFrame};
use carrick_hal::{TrapError, VcpuKick, VcpuRegistry};

use crate::bringup_fns::{self, BringupLayout, X86VcpuSnapshot};

/// The shared x86 register view the engine reads/writes through the backend. The
/// union of KVM's `kvm_regs` named fields, bhyve's `vm_reg_name` ordinals, and
/// NVMM's `NvmmX64State.gprs[]` array — every backend marshals these to/from its
/// native register struct.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum X86Reg {
    Rax,
    Rbx,
    Rcx,
    Rdx,
    Rsi,
    Rdi,
    Rbp,
    Rsp,
    R8,
    R9,
    R10,
    R11,
    R12,
    R13,
    R14,
    R15,
    Rip,
    Rflags,
    Cr0,
    Cr2,
    Cr3,
    Cr4,
    Efer,
}

/// The x86 segment registers the long-mode bring-up programs. Each backend
/// realizes `set_segment` via `kvm_segment`/`kvm_sregs` (KVM), `vm_set_desc`
/// ordinals (bhyve), or the `NvmmX64StateSeg` array (NVMM).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum X86Seg {
    Cs,
    Ds,
    Es,
    Fs,
    Gs,
    Ss,
    Tr,
    Ldtr,
    Gdtr,
    Idtr,
}

/// The shared exit shape. Lifted from bhyve's private `X86Exit` ∪ KVM's
/// `VcpuExit::IoOut`/`Halt`/`Kicked`. Backends decode their native exit into
/// THIS.
///
/// `resume_pc` is the next-RIP to continue at after a syscall doorbell:
///   - auto-advancing VMMs (NVMM `io.npc`) fill it directly;
///   - KVM fills it from the native current RIP (observed as the trampoline
///     `out` address on Linux/KVM; KVM completes the PIO step on re-entry);
///   - bhyve computes it = `exit.rip + exit.inst_length` at decode time (its
///     native `VmExit` carries `rip` + `inst_length` separately; the
///     `inst_length` is consumed HERE, not retained by the backend).
///
/// STATEFUL OBLIGATION (the §2.1 contract): collapsing bhyve's old
/// `PendingInout { rip, inst_length }` into one `resume_pc` moves the "which
/// doorbell is pending" bookkeeping INTO the engine. The backend's `run()` is
/// stateless w.r.t. the pending syscall: it returns `Syscall { frame, resume_pc
/// }` and the engine — not the backend — holds the pending-completion state
/// until `complete_syscall` writes the return value and resumes at `resume_pc`.
#[derive(Debug, Clone)]
pub enum X86Exit {
    /// The SYSCALL doorbell (`out %al, $SYSCALL_DOORBELL_PORT`). `frame` is the
    /// decoded syscall frame; `resume_pc` is where to resume after completion.
    Syscall {
        frame: X8664SyscallFrame,
        resume_pc: u64,
    },
    /// `HLT` (requires the per-backend halt-exit capability).
    Halt,
    /// A spurious re-entry / cross-thread kick: no syscall pending. The threaded
    /// loop re-checks signals/futex/quiesce and re-enters.
    Kicked,
    /// The FP-stub completion doorbell (`out %al, $FP_STUB_DOORBELL_PORT`) fired:
    /// the ring-3 FXSAVE/FXRSTOR stub finished. Only a no-FP-getter backend
    /// (`get_fp() == None`) ever surfaces this, and only while
    /// [`crate::bringup::run_fp_stub`] is driving the stub.
    FpDoorbell,
    /// Backend-specific memory exit. Most VMMs never surface this to the shared
    /// engine; sparse backends can ask their VMM half to realize the missing GPA
    /// and then re-enter the guest.
    Memory { gpa: u64 },
    /// A synchronous guest fault -> the runtime delivers it as
    /// [`carrick_hal::TrapError::GuestFault`]. `fault_addr` is the Linux
    /// `siginfo.si_addr` value already resolved by the backend (CR2 for #PF,
    /// RIP for #UD/#DE, NULL for #GP); `error_code` is the x86 error code.
    Fault {
        kind: X86FaultKind,
        fault_addr: u64,
        error_code: u64,
    },
}

/// The class of an [`X86Exit::Fault`]. Maps to the Linux `(signum, si_code)` the
/// runtime delivers via [`carrick_hal::TrapError::GuestFault`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum X86FaultKind {
    /// Page fault (#PF) → SIGSEGV.
    PageFault,
    /// Divide error (#DE) -> SIGFPE/FPE_INTDIV.
    DivideError,
    /// Invalid opcode (#UD) -> SIGILL/ILL_ILLOPN.
    InvalidOpcode,
    /// General protection (#GP) -> SIGSEGV/SI_KERNEL.
    GeneralProtection,
    /// Alignment check (#AC) -> SIGBUS/BUS_ADRALN.
    AlignmentCheck,
    /// Any other fatal guest exception.
    Other,
}

/// What a VMM gives up to wrap an MSR write of LSTAR/STAR/SFMASK. The shared
/// bring-up branches on this ONCE instead of every backend re-deciding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MsrInstall {
    /// `KVM_SET_MSRS` / NVMM `setstate(MSRS)` — bring-up calls `set_syscall_msrs`
    /// and the MSRs are live immediately.
    Direct,
    /// FreeBSD libvmmapi has no MSR ioctl — the bring-up must splice the
    /// ring-0 [`crate::bringup::msr_init_blob`] (a WRMSR-then-iretq stub) into
    /// the guest and run it once to install the MSRs.
    NeedsRing0Blob,
}

/// COW-inherit vs eager full-RAM copy at `fork(2)`. POLICY only: the shared
/// `fork_x86` reads this to decide *whether* to freeze; the `EagerCopy`
/// MECHANISM (frozen-RAM memcpy, fresh named child VM) stays in the backend,
/// exposed as `freeze_ram`/`rebuild_child_vm` that `fork_x86` *calls* but does
/// not own (§2.5b).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForkRamStrategy {
    /// KVM `MAP_PRIVATE` / NVMM host-fork COW: the child inherits RAM for free,
    /// nothing is copied.
    Cow,
    /// bhyve kernel-owned non-COW RAM: the parent freezes the whole segment into
    /// a host buffer pre-fork and the child rebuilds a fresh named VM from it.
    EagerCopy,
}

/// One region of the guest address space the bring-up wants mapped: a `va`/`gpa`
/// pair of `len` bytes with `perms`. The ordered list is the *union* of both
/// backends' needs (§2.5a): KVM reads it as N per-region slots; bhyve reads
/// `max(gpa + len)` + the base-0 contiguity assumption and folds it into ONE
/// sysmem segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WindowRegion {
    pub va: u64,
    pub gpa: u64,
    pub len: u64,
    pub read: bool,
    pub write: bool,
    pub exec: bool,
    /// User-accessible (ring 3) vs kernel-only.
    pub user: bool,
    /// Whether the source guest region requires shared host backing across
    /// fork. Used for the boot-mapped shared aperture.
    pub shared: bool,
}

/// The ordered region list the bring-up hands every backend. The PML4
/// region-walk that produces it is shared; the slot-vs-segment *realization*
/// (`X86Vmm::setup_memory`) is the per-backend seam.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WindowPlan {
    pub regions: Vec<WindowRegion>,
}

/// Capacity of the PML4 table region in bytes (448 pages × 4 KiB = 1.75 MiB).
/// Shared with `carrick_mem::memory::LINUX_PAGE_TABLES_SIZE` so the `pml4_tables`
/// budget matches the aarch64 lane. The bring-up reserves a supervisor-only
/// window of this size for the page tables at `BringupLayout::pml4_base`.
pub const X86_PML4_CAPACITY: u64 = carrick_mem::memory::LINUX_PAGE_TABLES_SIZE;

impl WindowPlan {
    /// The minimum contiguous `[0, max_gpa)` size a single-segment backend
    /// (bhyve) needs to cover every planned region. Returns 0 for an empty plan.
    pub fn max_gpa_end(&self) -> u64 {
        self.regions
            .iter()
            .map(|r| r.gpa.saturating_add(r.len))
            .max()
            .unwrap_or(0)
    }
}

/// VM-level memory + lifecycle. One per guest process. See §2.1/§2.5 for the
/// honest semantic seams hiding behind `setup_memory`, `fork_ram_strategy`,
/// `freeze_ram`/`rebuild_child_vm`.
///
/// The trait also carries the threaded-lifecycle surface
/// (`build_sibling_builder` / `materialize_sibling` / `kick_handle` /
/// `fresh_fork_kicker` / `set_guest_sp`) the generic engine's `ThreadedEngine`
/// impl drives — these are the per-backend "spawn a sibling vCPU on the same VM"
/// and "kick a vCPU thread" mechanisms, which differ per VMM.
pub trait X86Vmm: Sized {
    type Vcpu: X86Vcpu;

    /// The per-backend vCPU-kick handle (`KvmKickHandle` / `BhyveKickHandle`).
    /// Surfaces as `X86EngineCore<V>::KickHandle`.
    type KickHandle: VcpuKick + 'static;

    /// The `Send` payload `build_sibling_builder` hands to a freshly spawned host
    /// thread; `materialize_sibling` turns it into a fresh `(Self, Self::Vcpu)`
    /// pair on the SAME VM (clone(CLONE_THREAD)) without re-registering memory.
    type SiblingBuilder: Send;

    /// Consume the SHARED [`WindowPlan`]; the backend owns the slot-vs-segment
    /// decision (§2.5a).
    fn setup_memory(&mut self, plan: &WindowPlan) -> Result<(), TrapError>;

    /// Copy `bytes` into guest physical memory at `gpa`.
    fn write_gpa(&self, gpa: u64, bytes: &[u8]) -> Result<(), TrapError>;

    /// The host pointer backing `[gpa, gpa + len)`, or `None` if unmapped. The
    /// engine's `GuestMemory` impl copies through this.
    fn host_ptr(&self, gpa: u64, len: usize) -> Option<*mut u8>;

    /// Mutable variant of [`Self::host_ptr`]. Backends with sparse/lazy backing
    /// may materialize the requested range before returning the host pointer.
    fn host_ptr_mut(&mut self, gpa: u64, len: usize) -> Option<*mut u8> {
        self.host_ptr(gpa, len)
    }

    /// Whether `va` lies in a guest memory RESERVATION that is not yet committed
    /// (a lazily-backed `mmap`/`brk` page the guest has never touched). On a
    /// demand-paged backend (bhyve), such a page has no `host_ptr` until first
    /// access, but a READ of it must yield zeros — the kernel's lazy zero-fill
    /// for anonymous memory — NOT EFAULT (e.g. `write(fd, calloc'd buf, n)`,
    /// where glibc/Rust `alloc_zeroed` returns untouched `MAP_ANONYMOUS` pages).
    /// Backends whose host mmap is itself lazily backed (KVM's `MAP_NORESERVE`)
    /// never hit this — a `None` `host_ptr` there is a genuine fault — so the
    /// default is `false`.
    fn is_guest_reserved(&self, _va: u64) -> bool {
        false
    }

    /// Change the guest-visible protection for a VA range. Backends with real
    /// page tables override this; simple bring-up backends can keep the default.
    fn protect_range(&mut self, _address: u64, _len: usize, _prot: u64) -> Result<(), MemoryError> {
        Ok(())
    }

    /// Make a VA range non-present for `munmap`. Backends with page tables can
    /// override this when unmap differs from `PROT_NONE`; otherwise clearing
    /// present bits through `protect_range(..., PROT_NONE)` is the x86 default.
    fn unmap_range(&mut self, address: u64, len: usize) -> Result<(), MemoryError> {
        self.protect_range(address, len, 0)
    }

    /// Demand-commit a single page for a not-present (`#PF` MAPERR) fault at
    /// `fault_addr`. Returns `Ok(true)` if the backend had LAZILY RESERVED this
    /// VA (e.g. a guest PROT_NONE mmap the backend chose not to back eagerly) and
    /// has now committed the page — the engine then flushes the TLB and re-runs
    /// the faulting instruction (the `#PF` did not advance RIP). Returns
    /// `Ok(false)` if the VA is not a known reservation, leaving the engine to
    /// raise a genuine guest fault (SIGSEGV).
    ///
    /// Default: `Ok(false)`. KVM/NVMM back guest RAM with a `MAP_NORESERVE` host
    /// mapping, so the host kernel demand-pages and there is nothing to commit;
    /// only bhyve — whose sysmem is a fixed pool with no host demand-paging —
    /// overrides this.
    fn demand_commit(&mut self, _fault_addr: u64) -> Result<bool, MemoryError> {
        Ok(false)
    }

    /// Tear down an alias VA range. Backends may reclaim alias-specific table
    /// storage; the default invalidates the leaves like an ordinary unmap.
    fn unmap_alias_range(&mut self, address: u64, len: usize) -> Result<(), MemoryError> {
        self.unmap_range(address, len)
    }

    /// Back a dynamic high-VA mapping and install the VA→GPA page-table path.
    /// Backends that can receive `DispatchOutcome::MapHostAlias` override this.
    fn map_host_alias(
        &mut self,
        va: u64,
        ipa: u64,
        len: u64,
        payload: &[u8],
        file: Option<(libc::c_int, libc::off_t, libc::c_int)>,
    ) -> Result<(), TrapError> {
        let _ = (ipa, payload, file);
        Err(TrapError::Hypervisor(format!(
            "carrick-x86: map_host_alias not implemented for this backend (va=0x{va:x} len=0x{len:x})"
        )))
    }

    /// Handle a backend memory exit. Return `true` when the VMM resolved the
    /// missing backing and the engine should retry the same guest instruction.
    fn handle_memory_exit(&mut self, _gpa: u64) -> Result<bool, TrapError> {
        Ok(false)
    }

    /// Translate a guest VA to its GPA by walking the live page tables, or
    /// `None` if no leaf maps it. Used by the engine's `GuestMemory` raw
    /// read/write path to resolve a `repoint_private` overlay VA (whose stage-1
    /// leaf points at the per-process overlay GPA, NOT the stale shared-aperture
    /// GPA the identity lookup would use) — see
    /// [`carrick_mem::memory::needs_stage1_translation`]. The default returns
    /// `None`, which makes the engine fall back to its identity fast path (the
    /// correct behaviour for any backend without an overlay).
    fn translate_va(&self, _va: u64) -> Option<u64> {
        None
    }

    /// Repoint guest VA `[va, va+len)` at the per-process PRIVATE overlay
    /// aperture GPA `overlay_gpa` (identity GPA==VA, boot-mapped), seeding the
    /// overlay backing with `content` FIRST (while `va` still translates to the
    /// stale shared-aperture GPA, so no torn read during the flip). Backs a guest
    /// `mmap(MAP_FIXED|MAP_PRIVATE|MAP_ANON)` over a shared-aperture VA: carrick's
    /// shared aperture is host-`MAP_SHARED`, so a write through `va` would leak a
    /// guest's "private" stores to every other mapper and across fork — the
    /// overlay is `MAP_SHARED`-free (fork-snapshotted), so the repointed VA's
    /// stores stay private. The backend seeds `host_ptr(overlay_gpa)`, then edits
    /// the live PML4 leaf to point `va` at `overlay_gpa` (a 4 KiB-precise
    /// `map_aliased`); the engine flushes the TLB afterwards. The default returns
    /// a clear error (NOT a silent no-op) so a backend without the overlay wired
    /// up surfaces the gap instead of leaking.
    fn repoint_private(
        &mut self,
        va: u64,
        _overlay_gpa: u64,
        _len: usize,
        _content: &[u8],
    ) -> Result<(), MemoryError> {
        Err(MemoryError::HostMap(format!(
            "carrick-x86: repoint_private not implemented for this backend (va=0x{va:x})"
        )))
    }

    /// Back and map a guest `mmap(MAP_FIXED|MAP_PRIVATE|MAP_ANON)` at an
    /// arbitrary VA that has NO existing page-table leaf or memory slot (a
    /// MAP_FIXED outside the eager mmap arena / image regions — e.g. a loader
    /// placing its interpreter at a high identity VA). The backend allocates a
    /// fresh identity GPA slot (GPA==VA) backed by zeroed anonymous host memory
    /// and installs the VA→GPA leaf so the guest's own EL0 access has real
    /// backing instead of faulting. `writable` controls the leaf R/W bit. The
    /// engine flushes the TLB afterwards. The default returns a clear error so a
    /// backend without this path surfaces the gap (the guest write would
    /// otherwise SIGSEGV on an unbacked VA).
    fn back_fixed_anon(
        &mut self,
        va: u64,
        _len: usize,
        _writable: bool,
    ) -> Result<(), MemoryError> {
        Err(MemoryError::HostMap(format!(
            "carrick-x86: back_fixed_anon not implemented for this backend (va=0x{va:x})"
        )))
    }

    /// Create a fresh vCPU bound to this VM.
    fn add_vcpu(&mut self) -> Result<Self::Vcpu, TrapError>;

    /// The guest TSC frequency in Hz, if the backend can report it directly
    /// (KVM `KVM_GET_TSC_KHZ`). `None` (the default) makes the shared vDSO
    /// calibration fall back to timing the host TSC — see
    /// [`crate::vdso::populate_vdso_vvar`].
    fn tsc_hz(&self) -> Option<u64> {
        None
    }

    /// POLICY: whether `fork(2)` can inherit RAM via COW or must eagerly copy
    /// the whole segment (§2.5b).
    fn fork_ram_strategy(&self) -> ForkRamStrategy;

    /// `EagerCopy` mechanism (no-op / unreachable for `Cow` backends): snapshot
    /// the full segment into a host buffer pre-fork. Returns the frozen RAM the
    /// child rebuilds.
    fn freeze_ram(&self) -> Result<Vec<u8>, TrapError> {
        Ok(Vec::new())
    }

    /// `EagerCopy` mechanism: create a fresh named child VM and restore `frozen`
    /// into it (bhyve); `Cow` backends never call this.
    fn rebuild_child_vm(&mut self, _frozen: &[u8]) -> Result<(), TrapError> {
        Ok(())
    }

    /// Child-side VM/vCPU rebuild after the host `fork(2)`. The default preserves
    /// the original eager-copy seam (bhyve swaps the vCPU through its shared
    /// handle inside `rebuild_child_vm`); KVM overrides this because inherited
    /// vCPU fds are not usable in the child and the engine's separate vCPU field
    /// must be replaced explicitly.
    fn rebuild_child_after_fork(
        &mut self,
        _vcpu: &mut Self::Vcpu,
        frozen: &[u8],
    ) -> Result<(), TrapError> {
        self.rebuild_child_vm(frozen)
    }

    /// Restore a generic x86 vCPU snapshot onto a backend vCPU. The default
    /// uses the shared trait-level register writers; backends with stricter
    /// ioctl grouping requirements can override while keeping the x86 snapshot
    /// format shared.
    fn restore_vcpu(
        &self,
        vcpu: &mut Self::Vcpu,
        layout: BringupLayout,
        snapshot: &X86VcpuSnapshot,
    ) -> Result<(), TrapError> {
        bringup_fns::restore(vcpu, layout, snapshot)
    }

    /// Replace the live guest image with `new_image` (`execve(2)`). The default
    /// is NYI — KVM/NVMM Phase-2 hello never execve. A backend that supports
    /// execve (bhyve) rebuilds a fresh VM from `new_image` and re-points its live
    /// vCPU; the generic engine's `execve_into` calls this then clears the
    /// pending-syscall state. (§2.5c sibling: a HOOK on the backend, not a fixed
    /// engine policy, because the rebuild is backend mechanism.)
    fn execve_rebuild(
        &mut self,
        _vcpu: &mut Self::Vcpu,
        _new_image: &carrick_mem::memory::AddressSpace,
    ) -> Result<(), TrapError> {
        Err(TrapError::Hypervisor(
            "carrick-x86: execve_rebuild not implemented for this backend".into(),
        ))
    }

    /// Tear down per-process VM resources on a guest process `_exit` (§2.5c). A
    /// HOOK, not `Drop` — the forked child `_exit`s skipping Rust Drops. Default
    /// no-op (KVM `MAP_PRIVATE` / NVMM host-fork RAM is reclaimed by the OS on
    /// `_exit`); bhyve overrides it to `vm_destroy` its `/dev/vmm` node (skipping
    /// a vfork-shared/borrowed VM the parent still owns). The run loop's
    /// child-exit path calls the engine's `process_exit_cleanup`, which delegates
    /// here.
    fn process_exit_cleanup(&mut self) {}

    // ── Threaded-lifecycle surface (the generic ThreadedEngine drives these) ──

    /// A kick handle for the current vCPU thread (the engine's `kick_handle`).
    fn kick_handle(&self) -> Self::KickHandle;

    /// Backend admission gate before a new vCPU thread runs (HVF's concurrent-
    /// vCPU cap; a no-op on KVM/bhyve).
    fn wait_for_vcpu_slot() {}

    /// Live concurrent-vCPU budget N for the M:N admission scheduler. `usize::MAX`
    /// = no carrick-side cap (KVM); bhyve returns `hw.vmm.maxcpu`.
    fn vcpu_budget() -> usize {
        usize::MAX
    }

    /// Whether this backend RECLAIMS a thread's vCPU slot on block (M:N reclaim).
    /// `false` (default) = Phase-1 lifetime-binding (KVM); bhyve returns `true`.
    fn reclaims(&self) -> bool {
        false
    }

    /// Save THIS thread's full guest CPU state (GPRs + RSP/RFLAGS + FS/GS base +
    /// FP/AVX) before releasing its vCPU slot at a block point.
    fn save_guest_state(&self) -> Vec<u8> {
        Vec::new()
    }

    /// Re-bind to `slot`'s vCPU and restore `state` into it after a block.
    fn rebind_to_slot(&mut self, slot: carrick_hal::SlotId, state: &[u8]) -> Result<(), TrapError> {
        let _ = (slot, state);
        Ok(())
    }

    /// Build the `Send` payload a `clone(CLONE_THREAD)` sibling thread needs to
    /// add its own vCPU on the SAME VM (shared VM handle + window descriptors +
    /// a reserved live-vcpu slot, etc.).
    fn build_sibling_builder(&self) -> Result<Self::SiblingBuilder, TrapError>;

    /// On the sibling thread, turn the builder into a fresh `(VM-handle, vCPU)`
    /// pair on the SAME VM. The vCPU is returned UNPROGRAMMED; the engine
    /// restores the seeded snapshot onto it.
    fn materialize_sibling(builder: Self::SiblingBuilder) -> Result<(Self, Self::Vcpu), TrapError>;

    /// Set the guest user stack pointer (RSP) on a vfork child given an explicit
    /// `child_stack`, through `&self` (the shared loop holds only `&engine`).
    fn set_guest_sp(&self, vcpu: &Self::Vcpu, sp: u64) -> Result<(), TrapError>;

    /// A FRESH vCPU-kick registry for the CHILD side of a guest `fork(2)`
    /// (`libc::fork` replicates only the calling thread — the child drops the
    /// parent's kicker).
    fn fresh_fork_kicker(&self) -> Arc<dyn VcpuRegistry>;
}

/// Length of the x86 XSAVE area carried by [`X86Vcpu::get_xsave`] for
/// `XCR0 = x87|SSE|AVX`: the 512-byte legacy FXSAVE region, a 64-byte XSAVE
/// header (`xstate_bv` @ 512, `xcomp_bv` @ 520), and the 256-byte AVX `YMM_Hi`
/// component (16 × 16 bytes) at the standard-format offset 576. (We never enable
/// AVX-512, so no larger components follow.)
pub const XSAVE_LEN: usize = 832;

/// Byte offset of the AVX `YMM_Hi` component within the standard XSAVE area.
pub const XSAVE_AVX_OFFSET: usize = 576;

/// Pad a 512-byte FXSAVE area into an [`XSAVE_LEN`] XSAVE area that advertises
/// ONLY x87+SSE (no AVX): the legacy region verbatim, `xstate_bv = 0b11`, the
/// AVX component zeroed. Used as the default `get_xsave` for backends that never
/// enable AVX (their guests never touch YMM, so the upper halves are always 0).
pub fn fxsave_to_xsave(fx: [u8; 512]) -> [u8; XSAVE_LEN] {
    let mut xs = [0u8; XSAVE_LEN];
    xs[..512].copy_from_slice(&fx);
    xs[512] = 0x03; // xstate_bv low byte: x87(0) | SSE(1)
    xs
}

/// Per-vCPU register/run surface. The ONLY thing genuinely per-VMM.
pub trait X86Vcpu {
    /// Read a GPR / control register (`Rax..R15`/`Rip`/`Rsp`/`Rflags`/
    /// `Cr0..4`/`Efer`/`Cr2`).
    fn get_gpr(&self, reg: X86Reg) -> Result<u64, TrapError>;

    /// Write a GPR / control register.
    fn set_gpr(&mut self, reg: X86Reg, v: u64) -> Result<(), TrapError>;

    /// Batched register read: fill `out[i]` with `regs[i]`'s value. The default
    /// loops over [`Self::get_gpr`] (one ioctl per register); a backend with a
    /// whole-register-file read (bhyve `VM_GET_REGISTER_SET`, NVMM one
    /// `getstate`, KVM one `KVM_GET_REGS`) overrides this to satisfy the whole
    /// slice from ONE ioctl. `out` must be at least `regs.len()` long. Used on
    /// the hot syscall-completion path (`complete_sysret`) to fetch
    /// `RCX`/`R11` together.
    fn get_gprs(&self, regs: &[X86Reg], out: &mut [u64]) -> Result<(), TrapError> {
        for (slot, reg) in out.iter_mut().zip(regs) {
            *slot = self.get_gpr(*reg)?;
        }
        Ok(())
    }

    /// Batched register write: apply each `(reg, value)`. The default loops over
    /// [`Self::set_gpr`] (one ioctl per register); a whole-register-file backend
    /// (bhyve `VM_SET_REGISTER_SET`, NVMM one `setstate`) overrides this to commit
    /// the slice in ONE ioctl. Writes are applied in order. Used on the hot
    /// syscall-completion path (`complete_sysret`) to write `RAX`+`RIP`
    /// together.
    fn set_gprs(&mut self, writes: &[(X86Reg, u64)]) -> Result<(), TrapError> {
        for (reg, v) in writes {
            self.set_gpr(*reg, *v)?;
        }
        Ok(())
    }

    /// Read a guest MSR. Optional: the default reports "unsupported", which the
    /// shared vDSO calibration ([`crate::vdso::populate_vdso_vvar`]) treats as
    /// "fall back to the host TSC". A backend overrides this to read the guest
    /// `IA32_TSC` precisely (KVM `KVM_GET_MSRS`, etc.) when its guest runs with a
    /// non-zero TSC offset.
    fn read_msr(&self, index: u32) -> Result<u64, TrapError> {
        Err(TrapError::Hypervisor(format!(
            "read_msr({index:#x}) not implemented for this backend"
        )))
    }

    /// Complete a syscall that must resume through the shared SYSRET
    /// trampoline. Returns the guest user `(RCX, RFLAGS)` values that the engine
    /// should expose while the live RIP is parked in the trampoline.
    ///
    /// The default preserves the original per-register sequence. Backends with
    /// whole-register-file APIs may override this to batch reads/writes without
    /// moving the RCX/R11 read point.
    fn complete_sysret(
        &mut self,
        layout: BringupLayout,
        return_value: i64,
        resume_pc: u64,
    ) -> Result<(u64, u64), TrapError> {
        // Fetch the user RCX (return address) and R11 (saved RFLAGS) together —
        // one ioctl on a whole-register-file backend — AT completion time (the
        // safe read point, NOT the doorbell-time snapshot). RAX/RIP are
        // independent of RCX/R11 and the guest is paused, so reading first lets
        // the two writes also batch into one ioctl below.
        // Fetch the user RCX (return address) and R11 (saved RFLAGS) together —
        // one ioctl on a whole-register-file backend — AT completion time (the
        // safe read point, NOT the doorbell-time snapshot). RAX/RIP are
        // independent of RCX/R11 and the guest is paused, so reading first lets
        // the two writes also batch into one ioctl below.
        let mut user = [0u64; 2];
        self.get_gprs(&[X86Reg::Rcx, X86Reg::R11], &mut user)?;
        let user_pc = user[0];
        let user_rflags = user[1] | 0x2;
        self.prepare_sysret_resume(layout)?;
        // Write the syscall return value (RAX) and the resume RIP together.
        self.set_gprs(&[(X86Reg::Rax, return_value as u64), (X86Reg::Rip, resume_pc)])?;
        Ok((user_pc, user_rflags))
    }

    /// Prepare backend-hidden segment state for resuming inside the shared
    /// syscall trampoline. Backends whose SYSCALL exit already preserves kernel
    /// CS/SS can keep the default; KVM must reprogram the hidden descriptors
    /// explicitly before re-entering the `out; sysretq` stub.
    fn prepare_sysret_resume(&mut self, _layout: BringupLayout) -> Result<(), TrapError> {
        Ok(())
    }

    /// Program a segment/system descriptor (`base`/`limit`/access-rights).
    fn set_segment(&mut self, seg: X86Seg, base: u64, limit: u32, ar: u32)
    -> Result<(), TrapError>;

    /// The `SegmentBaseRegs` mechanism (arch_prctl FS/GS base): KVM/NVMM via the
    /// segment struct, bhyve via `vm_get/set_desc(FS/GS.base)`.
    fn get_fs_base(&self) -> Result<u64, TrapError>;
    fn set_fs_base(&mut self, v: u64) -> Result<(), TrapError>;
    fn get_gs_base(&self) -> Result<u64, TrapError>;
    fn set_gs_base(&mut self, v: u64) -> Result<(), TrapError>;

    /// Install the SYSCALL MSRs. Returns whether they took effect directly
    /// ([`MsrInstall::Direct`]) or the bring-up must run the ring-0 blob
    /// ([`MsrInstall::NeedsRing0Blob`], bhyve).
    fn set_syscall_msrs(
        &mut self,
        lstar: u64,
        star: u64,
        sfmask: u64,
    ) -> Result<MsrInstall, TrapError>;

    /// `None` = "no FP getter, drive the ring-3 FXSAVE stub"
    /// ([`crate::bringup::run_fp_stub`]); `Some(fx)` = native 512-byte fxsave
    /// area (KVM `KVM_GET_FPU`, NVMM `STATE_FPU`).
    fn get_fp(&self) -> Result<Option<[u8; 512]>, TrapError>;

    /// Apply a 512-byte fxsave area. `Ok(true)` = applied natively; `Ok(false)`
    /// = "no native FP setter, the caller must drive the ring-3 FXRSTOR stub".
    fn set_fp(&mut self, fx: &[u8; 512]) -> Result<bool, TrapError>;

    /// The full XSAVE area ([`XSAVE_LEN`]) — the legacy FXSAVE region PLUS the
    /// AVX `YMM_Hi` component — for fork/clone/execve snapshots and signal
    /// save/restore. The FXSAVE-only [`X86Vcpu::get_fp`] drops the YMM upper halves, which
    /// silently corrupts a guest's AVX state across those boundaries (Go's
    /// runtime uses AVX memmove once `CR4.OSXSAVE` is set). The DEFAULT pads
    /// [`X86Vcpu::get_fp`]'s FXSAVE into a no-AVX XSAVE; a backend that enables AVX
    /// (CR4.OSXSAVE + XCR0) MUST override this with a real XSAVE getter.
    fn get_xsave(&self) -> Result<Option<[u8; XSAVE_LEN]>, TrapError> {
        Ok(self.get_fp()?.map(fxsave_to_xsave))
    }

    /// Apply a full XSAVE area. The DEFAULT extracts the FXSAVE prefix and calls
    /// [`X86Vcpu::set_fp`] (dropping AVX — correct for a backend that never enables it);
    /// an AVX-enabled backend MUST override with a real XSAVE setter.
    fn set_xsave(&mut self, xs: &[u8; XSAVE_LEN]) -> Result<bool, TrapError> {
        let mut fx = [0u8; 512];
        fx.copy_from_slice(&xs[..512]);
        self.set_fp(&fx)
    }

    /// Run the vCPU until the next exit and decode it into [`X86Exit`]. The
    /// backend fills `resume_pc` at decode time; the ENGINE owns the
    /// pending-syscall state (§2.1).
    fn run(&mut self) -> Result<X86Exit, TrapError>;

    /// Enable the HALT exit capability (`KVM_CAP`/`vm_set_capability`); a no-op
    /// where halt already exits.
    fn enable_halt_exit(&mut self) -> Result<(), TrapError>;
}
