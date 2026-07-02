//! The KVM x86_64 backend on the shared `carrick-x86` scaffold (portability S4).
//!
//! `KvmVmm` (+ `impl X86Vcpu for KvmVcpu`) is the thin per-VMM trait pair the
//! generic [`carrick_x86::X86EngineCore`] is parameterized over. It replaces the
//! hand-rolled `KvmX86TrapEngine`: the trap loop, register walk, guest-memory
//! access, snapshot triple, long-mode bring-up, and run-elf loop all now live
//! ONCE in `carrick-x86`; this module supplies only the KVM-specific
//! marshalling.
//!
//! KVM answers the three quirk seams `Direct` / `Some` / `Cow`:
//!   - `set_syscall_msrs` → `MsrInstall::Direct` (`KVM_SET_MSRS`).
//!   - `get_fp` → `Some` (`KVM_GET_FPU` 512-byte fxsave area, native).
//!   - `fork_ram_strategy` → `Cow` (`MAP_PRIVATE` — KVM never freezes RAM).
//!
//! ## Whole-`kvm_sregs` read-modify-write
//!
//! KVM has no per-register x86 ioctl: control regs + EFER + every segment
//! descriptor live in one `kvm_sregs`, GPRs/RIP/RFLAGS in one `kvm_regs`, FP in
//! one `kvm_fpu`. Each `X86Vcpu` setter therefore reads the whole struct,
//! mutates the one field, and writes it back. The "all control regs + 64-bit CS
//! in one `KVM_SET_SREGS`" validation invariant (paging-on-without-64-bit-CS →
//! EINVAL) is preserved because the snapshot/restore path writes the full
//! `kvm_sregs` it captured; the per-field setters used during bring-up touch
//! only off-hot-path regs after long mode is already established.
//!
//! ## KERNEL_GS_BASE
//!
//! `gs.base` is the active GS base (what `arch_prctl(ARCH_SET_GS)` programs and
//! the sigframe carries). `KERNEL_GS_BASE` (the SWAPGS shadow) is not used by
//! the ring-3-only guest, so `get/set_gs_base` operate on `sregs.gs.base`.

use std::sync::{Arc, Mutex, RwLock};

use carrick_abi::LinuxProtFlags;
use carrick_guest_mem::{Gpa, GuestVa, HostVa, MemoryError};
use carrick_hal::{GuestVmBackend, TrapError};
use carrick_mem::memory::AddressSpace;
use carrick_mem::pml4::{Pml4Manager, walk_descriptors};
use carrick_x86::{
    BringupLayout, FAULT_DOORBELL_PORT, FaultDoorbellRecord, ForkRamStrategy, MsrInstall,
    WindowPlan, X86_FAULT_RECORD_U32_WORDS, X86EngineCore, X86Exit, X86Reg, X86Seg, X86Vcpu,
    X86VcpuSnapshot, X86Vmm, fault_exit_from_record, snapshot as x86_snapshot,
};
use kvm_bindings::{Msrs, kvm_dtable, kvm_msr_entry, kvm_segment};

use crate::guest_setup::{GuestRam, WindowDesc};
use crate::guest_setup_x86::{X86_GDT_BASE, X86_PML4_BASE, X86_TRAMPOLINE_BASE};
use crate::kvm::{KvmVcpu, KvmVm, SharedVmHandle, VcpuLiveTicket};
use crate::kvm_kicker::{KvmKickHandle, KvmKicker};

/// The KVM x86 kernel-window GPA layout (the §2.5a/`BringupLayout` per-backend
/// choice). KVM places the trampoline/GDT/PML4 in a low 256 MiB window so CR3
/// stays below the host's 36-bit physical-address ceiling.
pub const KVM_X86_LAYOUT: BringupLayout = BringupLayout {
    trampoline_base: X86_TRAMPOLINE_BASE,
    gdt_base: X86_GDT_BASE,
    pml4_base: X86_PML4_BASE,
};

// ─── KvmVmm ──────────────────────────────────────────────────────────────────

/// The KVM `X86Vmm`: a `KvmVm` plus the `GuestRam` window table backing it. One
/// per guest process. The generic engine drives memory through `host_ptr`,
/// lifecycle through `add_vcpu` / the sibling hooks.
pub struct KvmVmm {
    vm: KvmVm,
    ram: GuestRam,
    page_tables: Arc<Mutex<Pml4Manager>>,
    /// The `vm`-side half of the x86 M:N block-recycle reclaim — a clone of the
    /// engine's live-vCPU shared slot + the shared recycle pool. Bound to a
    /// specific [`KvmVcpu`] via [`Self::bind_reclaim`] at every point the engine
    /// pairs this `KvmVmm` with a vCPU (bring-up, sibling, fork-child, execve), so
    /// `save_guest_state`/`rebind_to_slot` — which only receive `&mut self.vm` —
    /// can reach and swap the live vCPU underneath the engine's separate `vcpu`
    /// field. `None` only in the transient window before the first bind.
    reclaim: Option<crate::kvm::KvmReclaimHandle>,
    /// `vfork(2)` (`CLONE_VM|CLONE_VFORK`) shared shadows, armed by
    /// `prepare_vfork_share` PRE-`libc::fork` and consumed once: the CHILD reads
    /// them in `rebuild_child_after_fork_vfork` (registers its slots over them);
    /// the PARENT reconciles + frees them in `finish_vfork_parent` on resume.
    /// `Some` only inside one vfork window; `None` otherwise.
    vfork_shadows: Option<crate::guest_setup::VforkShadows>,
    /// The guest mmap-arena high-water published by the runtime just before a
    /// `vfork(2)` (`set_vfork_arena_high_water`). Bounds `prepare_vfork_shadows`'
    /// residency scan to the used arena prefix. `u64::MAX` ⇒ no bound (full scan).
    vfork_arena_high_water: u64,
}

impl KvmVmm {
    /// Bind this `KvmVmm`'s reclaim handle to `vcpu` — the engine's live vCPU on
    /// this thread. Called at every point the engine (re)pairs the vmm with a
    /// vCPU (initial bring-up, clone sibling, fork-child rebuild, execve). The
    /// handle shares `vcpu`'s [`Arc<KvmVcpuSlot>`], so a later block-recycle swaps
    /// the same live vCPU the engine runs.
    fn bind_reclaim(&mut self, vcpu: &KvmVcpu) {
        self.reclaim = Some(vcpu.reclaim_handle(self.vm.vm_handle()));
    }

    /// Adopt a freshly-rebuilt child VM/vCPU (ordinary fork or vfork-share): swap
    /// in the new VM, repoint the engine's vCPU, mark this process's single vCPU
    /// live, give the child its own page-table manager (the parent's is now a
    /// separate process), and re-bind the reclaim handle to the new VM + vCPU.
    fn adopt_child_vm(&mut self, vcpu: &mut KvmVcpu, new_vm: KvmVm, new_vcpu: KvmVcpu) {
        self.vm = new_vm;
        *vcpu = new_vcpu;
        crate::kvm::VCPU_LIVE.store(1, std::sync::atomic::Ordering::SeqCst);
        let page_tables = self
            .page_tables
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        self.page_tables = Arc::new(Mutex::new(page_tables));
        // Re-bind reclaim to the child's fresh VM + vCPU (new shared slot + a new
        // vcpu pool on the rebuilt VM).
        self.bind_reclaim(vcpu);
    }

    /// Build a sibling `KvmVmm` over the shared VM handle + window descriptors (a
    /// `clone(CLONE_THREAD)` sibling shares every slot — no re-registration).
    fn from_sibling(
        handle: SharedVmHandle,
        windows: Arc<RwLock<Vec<WindowDesc>>>,
        protections: Arc<carrick_mem::protections::MemoryProtections>,
        page_tables: Arc<Mutex<Pml4Manager>>,
    ) -> Self {
        let vm = KvmVm::from_shared_vm(handle);
        let ram = GuestRam::from_shared_windows(windows, protections);
        Self {
            vm,
            ram,
            page_tables,
            reclaim: None,
            vfork_shadows: None,
            vfork_arena_high_water: u64::MAX,
        }
    }

    fn edit_page_tables(
        &mut self,
        address: u64,
        len: usize,
        edit: impl FnOnce(&mut Pml4Manager) -> Result<bool, carrick_mem::pml4::Pml4Error>,
    ) -> Result<(), MemoryError> {
        let pt_host = self
            .ram
            .host_ptr(X86_PML4_BASE, carrick_x86::X86_PML4_CAPACITY as usize)
            .ok_or_else(|| MemoryError::HostMap("kvm-x86: PML4 backing not mapped".into()))?;
        let mut page_tables = self.page_tables.lock().unwrap_or_else(|e| e.into_inner());
        let changed = edit(&mut page_tables).map_err(|_| MemoryError::OutOfBounds {
            address,
            length: len,
        })?;
        if changed {
            let bytes = page_tables.bytes();
            // SAFETY: `pt_host` backs the full PML4 table region in the live guest;
            // `bytes` is the manager's table image for exactly that arena.
            unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), pt_host, bytes.len()) };
        }
        Ok(())
    }
}

/// The `Send` payload a sibling thread materializes into a fresh vCPU on the SAME
/// VM. Mirrors the old `X8664SiblingSpec` minus the snapshot (the engine carries
/// the seeded snapshot in `X86SiblingSpec`).
pub struct KvmSiblingBuilder {
    vm: SharedVmHandle,
    windows: Arc<RwLock<Vec<WindowDesc>>>,
    protections: Arc<carrick_mem::protections::MemoryProtections>,
    page_tables: Arc<Mutex<Pml4Manager>>,
    ticket: VcpuLiveTicket,
}

impl GuestVmBackend for KvmVmm {
    fn write_gpa(&self, gpa: u64, bytes: &[u8]) -> Result<(), TrapError> {
        // GuestRam::write_gpa takes &mut self; the bring-up holds &mut, but the
        // trait is &self. The window host pointers are stable, so copy directly
        // through host_ptr.
        let host = self.ram.host_ptr(gpa, bytes.len()).ok_or_else(|| {
            TrapError::Hypervisor(format!("kvm-x86: write_gpa 0x{gpa:x} unmapped"))
        })?;
        // SAFETY: host_ptr proved [host, host+len) is within a live window.
        unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), host, bytes.len()) };
        Ok(())
    }

    fn host_ptr(&self, gpa: u64, len: usize) -> Option<*mut u8> {
        self.ram.host_ptr(gpa, len)
    }

    fn fork_ram_strategy(&self) -> ForkRamStrategy {
        // KVM: MAP_PRIVATE windows inherit via COW; nothing is frozen/copied.
        ForkRamStrategy::Cow
    }

    fn process_exit_cleanup(&mut self) {
        crate::kvm::print_kvm_stats_once("process-exit");
    }

    fn wait_for_vcpu_slot() {
        // Admission is enforced by the carrick-hal VcpuScheduler installed for
        // `vcpu_budget()` (a bounded HostCondvarScheduler since the budget is
        // finite); this backend hook stays a no-op.
    }

    fn vcpu_budget() -> usize {
        // KVM_CAP_MAX_VCPUS is the hard per-VM cap; a guest thread beyond it would
        // EINVAL KVM_CREATE_VCPU. Bound the live admitted set to (cap - reserve)
        // so total created vcpu ids stay ≤ cap (the exit+block recycle reuses ids
        // within that bound). The reserve mirrors bhyve/HVF: headroom for the
        // boot vCPU + a fork-rebuild in flight. A query failure falls back to a
        // safe constant well under the typical ~512 cap.
        //
        // CARRICK_KVM_BUDGET overrides it (testing): the real cap is ~512, far
        // above any practical thread count, so force a low budget to exercise the
        // block-recycle reclaim with a small barrier.
        if let Some(n) = std::env::var("CARRICK_KVM_BUDGET")
            .ok()
            .and_then(|v| v.trim().parse::<usize>().ok())
            .filter(|n| *n >= 1)
        {
            return n;
        }
        kvm_max_vcpus().saturating_sub(VCPU_BUDGET_RESERVE).max(1)
    }

    fn reclaims(&self) -> bool {
        // KVM reclaims so a guest with MORE concurrent threads than the budget can
        // run: a blocking thread parks its vCPU into the recycle pool and another
        // thread pops it (pool-swap / block-recycle).
        true
    }
}

impl X86Vmm for KvmVmm {
    type Vcpu = KvmVcpu;
    type KickHandle = KvmKickHandle;
    type SiblingBuilder = KvmSiblingBuilder;

    /// KVM can report the guest TSC frequency directly, so the shared vDSO
    /// calibration uses it instead of timing the host TSC.
    fn tsc_hz(&self) -> Option<u64> {
        self.vm.x86_tsc_hz()
    }

    fn setup_memory(&mut self, _plan: &WindowPlan) -> Result<(), TrapError> {
        // KVM realizes the plan as N MAP_NORESERVE slots; that registration is
        // done by `bring_up` (it builds the `GuestRam` window table + registers
        // every window as a KVM slot, capped 64 MiB each — §2.5a KVM column).
        // This hook is a no-op for KVM because `bring_up` constructs an already-
        // memory-mapped `KvmVmm`; it exists for backends that defer memory setup.
        Ok(())
    }

    /// Resolve a futex word's GPA to the host address of its `MAP_SHARED`
    /// backing, but only when it lies in a fork-coherent shared window (the boot
    /// aperture or a runtime file-backed alias — both `WindowKind::Shared`). The
    /// `GuestRam` already tracks this for the aarch64 lane; expose it on the x86
    /// `X86Vmm` seam so the shared engine routes the cross-process futex through
    /// the bare-`SYS_futex` shared path (`ltpcheckpoint` reverse direction).
    fn shared_futex_host_addr(&self, gpa: Gpa, len: usize) -> Option<HostVa> {
        self.ram.shared_futex_host_addr(gpa.raw(), len).map(HostVa)
    }

    fn protect_range(&mut self, address: u64, len: usize, prot: u64) -> Result<(), MemoryError> {
        let prot = LinuxProtFlags::from_bits_truncate(prot);
        let exec = prot.contains(LinuxProtFlags::EXEC);
        self.edit_page_tables(address, len, |mgr| {
            if prot.is_empty() {
                mgr.set_prot_none(address, len)
            } else if prot.contains(LinuxProtFlags::WRITE) {
                mgr.set_rw(address, len, exec)
            } else {
                mgr.set_readonly(address, len, exec)
            }
        })
    }

    fn unmap_range(&mut self, address: u64, len: usize) -> Result<(), MemoryError> {
        self.edit_page_tables(address, len, |mgr| mgr.set_prot_none(address, len))
    }

    fn unmap_alias_range(&mut self, address: u64, len: usize) -> Result<(), MemoryError> {
        self.unmap_range(address, len)
    }

    fn map_host_alias(
        &mut self,
        va: GuestVa,
        ipa: Gpa,
        len: u64,
        payload: &[u8],
        file: Option<(libc::c_int, libc::off_t, libc::c_int)>,
    ) -> Result<(), TrapError> {
        use crate::guest_setup::AliasBacking;
        use carrick_mem::memory::{LINUX_ALIAS_IPA_BASE, LINUX_ALIAS_IPA_SIZE};

        let (va, ipa) = (va.raw(), ipa.raw());

        let alias_end = ipa.checked_add(len).ok_or_else(|| {
            TrapError::Hypervisor(format!("KVM x86 alias 0x{ipa:x}+{len} overflows"))
        })?;
        let alias_limit = LINUX_ALIAS_IPA_BASE + LINUX_ALIAS_IPA_SIZE;
        if ipa < LINUX_ALIAS_IPA_BASE || alias_end > alias_limit {
            return Err(TrapError::Hypervisor(format!(
                "KVM x86 map_host_alias: dispatcher IPA 0x{ipa:x}..0x{alias_end:x} \
                 outside alias GPA arena 0x{LINUX_ALIAS_IPA_BASE:x}..0x{alias_limit:x}"
            )));
        }
        let gpa = ipa;
        let writable = match file {
            Some((_, _, prot)) => prot & libc::PROT_WRITE != 0,
            None => true,
        };
        let backing = match file {
            Some((fd, offset, prot)) => AliasBacking::File { fd, offset, prot },
            None => AliasBacking::Anon { payload },
        };
        let pt_host = self
            .ram
            .host_ptr(X86_PML4_BASE, carrick_x86::X86_PML4_CAPACITY as usize)
            .ok_or_else(|| TrapError::Hypervisor("kvm-x86: PML4 backing not mapped".into()))?;
        self.ram
            .add_alias(&mut self.vm, va, gpa, len, backing)
            .map_err(|e| TrapError::Hypervisor(e.to_string()))?;
        let mut page_tables = self.page_tables.lock().unwrap_or_else(|e| e.into_inner());
        page_tables
            // exec=true: KVM is eager — the leaf's NX is (re)applied by the
            // backend `protect_range` → `set_rw`/`set_readonly` per the mmap prot,
            // so the alias leaf itself stays executable (prior behaviour).
            .map_aliased(GuestVa(va), Gpa(gpa), len, writable, true)
            .map_err(|e| TrapError::Hypervisor(format!("kvm-x86: PML4 map_aliased: {e:?}")))?;
        let bytes = page_tables.bytes();
        // SAFETY: `pt_host` backs the full PML4 table region in the live guest;
        // `bytes` has exactly that arena's size and stays valid for this copy.
        unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), pt_host, bytes.len()) };
        Ok(())
    }

    fn translate_va(&self, va: u64) -> Option<u64> {
        self.page_tables
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .translate(va)
    }

    fn repoint_private(
        &mut self,
        va: u64,
        overlay_gpa: u64,
        len: usize,
        content: &[u8],
    ) -> Result<(), MemoryError> {
        // The overlay aperture (608 GiB) is identity GPA==VA and boot-mapped as a
        // normal KVM slot, so `host_ptr(overlay_gpa)` resolves its private (NOT
        // MAP_SHARED) backing. Seed `content` into that backing FIRST — while `va`
        // still maps to the stale shared-aperture GPA, so no torn read through
        // `va` during the flip.
        let dst = self
            .ram
            .host_ptr(overlay_gpa, len.max(1))
            .ok_or(MemoryError::OutOfBounds {
                address: overlay_gpa,
                length: len,
            })?;
        if !content.is_empty() {
            let n = content.len().min(len);
            // SAFETY: `host_ptr` proved `[overlay_gpa, overlay_gpa+len)` lies wholly
            // within the overlay slot's backing, so `dst[..n]` (n <= len) is valid
            // and writable; `content[..n]` is a distinct, valid source slice.
            unsafe { std::ptr::copy_nonoverlapping(content.as_ptr(), dst, n) };
        }
        // Repoint the live PML4 leaf for `va` at the overlay GPA (`map_aliased`
        // splits any covering 2 MiB block to a 4 KiB leaf so a single page is
        // repointed without disturbing neighbours), then copy the table image back
        // over the live PML4 backing. The engine reloads CR3 afterwards.
        let len_u64 = u64::try_from(len).map_err(|_| MemoryError::OutOfBounds {
            address: va,
            length: len,
        })?;
        self.edit_page_tables(va, len, |mgr| {
            mgr.map_aliased(GuestVa(va), Gpa(overlay_gpa), len_u64, true, true)
                .map(|()| true)
        })
    }

    fn back_fixed_anon(&mut self, va: u64, len: usize, writable: bool) -> Result<(), MemoryError> {
        use crate::guest_setup::AliasBacking;

        // Back a MAP_FIXED|MAP_PRIVATE|MAP_ANON at an arbitrary VA that the PML4
        // does not yet map (outside the eager arena/image). Allocate a fresh
        // identity-GPA slot (GPA==VA) backed by zeroed anon host memory, then
        // install the VA→GPA leaf so the guest's own access has real backing.
        let len_u64 = u64::try_from(len).map_err(|_| MemoryError::OutOfBounds {
            address: va,
            length: len,
        })?;
        self.ram
            .add_alias(
                &mut self.vm,
                va,
                va,
                len_u64,
                AliasBacking::Anon { payload: &[] },
            )
            .map_err(|e| {
                MemoryError::HostMap(format!("kvm-x86: back_fixed_anon add_alias: {e}"))
            })?;
        self.edit_page_tables(va, len, |mgr| {
            // exec=true: `back_fixed_anon` only seeds the leaf; the caller's
            // `protect_range`/`set_rw` re-applies the prot (incl. NX) for KVM.
            mgr.map_aliased(GuestVa(va), Gpa(va), len_u64, writable, true)
                .map(|()| true)
        })
    }

    fn add_vcpu(&mut self) -> Result<Self::Vcpu, TrapError> {
        use carrick_hal::HvVm as _;
        self.vm
            .add_vcpu()
            .map_err(|e| TrapError::Hypervisor(e.to_string()))
    }

    fn rebuild_child_after_fork(
        &mut self,
        vcpu: &mut Self::Vcpu,
        _frozen: &[u8],
    ) -> Result<(), TrapError> {
        let (new_vm, new_vcpu) = self
            .ram
            .rebuild_vm_for_child()
            .map_err(|e| TrapError::Hypervisor(e.to_string()))?;
        self.adopt_child_vm(vcpu, new_vm, new_vcpu);
        Ok(())
    }

    fn set_vfork_arena_high_water(&mut self, high_water: u64) {
        self.vfork_arena_high_water = high_water;
    }

    fn prepare_vfork_share(&mut self) -> Result<bool, TrapError> {
        // vfork (CLONE_VM): allocate shared shadows of every MAP_PRIVATE window so
        // the child can share the parent's address space across libc::fork (which
        // would otherwise COW them private). Stash them for the post-fork halves.
        let shadows = self
            .ram
            .prepare_vfork_shadows(self.vfork_arena_high_water)
            .map_err(|e| TrapError::Hypervisor(e.to_string()))?;
        // No shadows (e.g. an all-shared layout) → nothing to share; degrade to a
        // plain fork so the runtime doesn't wrongly run the parent-reconcile path.
        if shadows.is_empty() {
            return Ok(false);
        }
        self.vfork_shadows = Some(shadows);
        Ok(true)
    }

    fn rebuild_child_after_fork_vfork(
        &mut self,
        vcpu: &mut Self::Vcpu,
        _frozen: &[u8],
    ) -> Result<(), TrapError> {
        // Register the child's slots over the parent's shared shadows so the
        // child's guest writes are visible to the suspended parent (CLONE_VM).
        let shadows = self.vfork_shadows.take().ok_or_else(|| {
            TrapError::Hypervisor("kvm-x86: vfork child rebuild without armed shadows".into())
        })?;
        let (new_vm, new_vcpu) = self
            .ram
            .rebuild_vm_for_child_vfork(&shadows)
            .map_err(|e| TrapError::Hypervisor(e.to_string()))?;
        // The CHILD must NOT free the shadows — they belong to the parent's
        // mapping and the parent munmaps them on resume. `VforkShadows` has NO
        // `Drop`, so simply dropping this handle here releases nothing (the child
        // detaches on execve → a fresh VM, or on `_exit` → process death).
        drop(shadows);
        self.adopt_child_vm(vcpu, new_vm, new_vcpu);
        Ok(())
    }

    fn finish_vfork_parent(&mut self) {
        // The child has execve'd/_exited, so the shared window is quiescent. Copy
        // the child's shared writes back into the parent's private windows and
        // release the shadows. No-op if nothing was armed (degrade path).
        if let Some(shadows) = self.vfork_shadows.take() {
            self.ram.finish_vfork_parent(shadows);
        }
    }

    fn restore_vcpu(
        &self,
        vcpu: &mut Self::Vcpu,
        layout: BringupLayout,
        snapshot: &X86VcpuSnapshot,
    ) -> Result<(), TrapError> {
        let (rcx_walk, rdx_walk, rsp_walk, fs_walk) = {
            let page_tables = self.page_tables.lock().unwrap_or_else(|e| e.into_inner());
            (
                walk_descriptors(page_tables.bytes(), layout.pml4_base, snapshot.gprs[2]),
                walk_descriptors(page_tables.bytes(), layout.pml4_base, snapshot.gprs[3]),
                walk_descriptors(page_tables.bytes(), layout.pml4_base, snapshot.rsp),
                walk_descriptors(page_tables.bytes(), layout.pml4_base, snapshot.fs_base),
            )
        };
        restore_kvm_vcpu(
            vcpu, layout, snapshot, rcx_walk, rdx_walk, rsp_walk, fs_walk,
        )
    }

    fn execve_rebuild(
        &mut self,
        vcpu: &mut Self::Vcpu,
        new_image: &AddressSpace,
    ) -> Result<(), TrapError> {
        let (new_vm, new_ram, new_page_tables, new_vcpu) = build_kvm_x86_guest(new_image)?;
        vcpu.close_on_drop();
        *vcpu = new_vcpu;
        self.vm = new_vm;
        self.ram = new_ram;
        self.page_tables = new_page_tables;
        // Re-bind reclaim to the replacement image's fresh VM + vCPU.
        self.bind_reclaim(vcpu);
        Ok(())
    }

    fn kick_handle(&self) -> Self::KickHandle {
        KvmKickHandle::for_current_thread()
    }

    fn save_guest_state(&self) -> Vec<u8> {
        // Snapshot the blocking thread's full guest CPU state (16 GPRs + RIP/RSP/
        // RFLAGS + CR0/3/4 + EFER + FS/GS base + the full XSAVE incl AVX YMM) via
        // the shared X86 snapshot, SERIALIZE it into the returned bytes (round-
        // tripped to `rebind_to_slot` on the SAME thread), then PARK this thread's
        // vCPU into the recycle pool so another admitted thread can pop+reuse its
        // finite vcpu id. Serializing keeps this `&self` (no interior-mutable stash
        // needed). On any failure return empty — `rebind_to_slot` then errors out
        // (a reclaim failure is fatal to the thread, never silent corruption).
        let Some(reclaim) = self.reclaim.as_ref() else {
            return Vec::new();
        };
        // Capture the snapshot through a transient view over the live shared slot
        // (the vCPU is parked at the ring-0 LSTAR-stub syscall boundary — CPL 0 —
        // so the native KVM_GET_XSAVE captures clean FP/AVX state).
        let bytes = match reclaim.with_vcpu(|vcpu| x86_snapshot(vcpu)) {
            Ok(s) => serialize_x86_snapshot(&s),
            Err(_) => return Vec::new(),
        };
        // Park the vCPU AFTER the snapshot read (which needs the live fd): move the
        // fd into the recycle pool and leave the shared slot empty for the no-vCPU
        // host wait.
        reclaim.park_current();
        bytes
    }

    fn rebind_to_slot(
        &mut self,
        _slot: carrick_hal::SlotId,
        state: &[u8],
    ) -> Result<(), TrapError> {
        // Re-acquire a vCPU for the woken thread and restore its saved state. The
        // scheduler `slot` is admission bookkeeping; KVM maps it to whatever
        // pooled/fresh vcpu id `install_recycled` returns (like HVF/bhyve, the
        // slot value itself is not the KVM vcpu id).
        let Some(snap) = deserialize_x86_snapshot(state) else {
            return Err(TrapError::Hypervisor(
                "kvm reclaim rebind: missing/short snapshot".into(),
            ));
        };
        // Pop a recycled (or fresh) vCPU and INSTALL it into the engine's shared
        // slot, so the engine's separate `vcpu` field now drives it. `reclaim` is a
        // `&self.reclaim` borrow; `install_recycled` is `&self`, and the later
        // `restore_vcpu` is also `&self` — overlapping SHARED borrows, both legal.
        let reclaim = self
            .reclaim
            .as_ref()
            .ok_or_else(|| TrapError::Hypervisor("kvm reclaim rebind: unbound".into()))?;
        reclaim
            .install_recycled()
            .map_err(|e| TrapError::Hypervisor(e.to_string()))?;
        // Restore the saved register file onto the freshly-installed vCPU through a
        // transient view over the now-live shared slot, reusing the production KVM
        // restore (full sregs/regs/xsave/MSRs + the page-table walks that feed the
        // resume-state record). `with_vcpu` returns the closure's result.
        reclaim.with_vcpu(|vcpu| self.restore_vcpu(vcpu, KVM_X86_LAYOUT, &snap))
    }

    fn build_sibling_builder(&self) -> Result<Self::SiblingBuilder, TrapError> {
        Ok(KvmSiblingBuilder {
            vm: self.vm.vm_handle(),
            windows: self.ram.window_descriptors(),
            protections: self.ram.shared_protections(),
            page_tables: Arc::clone(&self.page_tables),
            // Reserve the sibling's VCPU_LIVE slot now (closes the execve-drain
            // blind window); consumed at materialization.
            ticket: VcpuLiveTicket::acquire(),
        })
    }

    fn materialize_sibling(builder: Self::SiblingBuilder) -> Result<(Self, Self::Vcpu), TrapError> {
        let mut vmm = Self::from_sibling(
            builder.vm,
            builder.windows,
            builder.protections,
            builder.page_tables,
        );
        let vcpu = vmm
            .vm
            .add_sibling_vcpu()
            .map_err(|e| TrapError::Hypervisor(e.to_string()))?;
        // Bind reclaim to this sibling's fresh vCPU (its own shared slot).
        vmm.bind_reclaim(&vcpu);
        // Transfer the reserved VCPU_LIVE slot to the vcpu before the (fallible)
        // restore the engine runs next.
        builder.ticket.consume();
        Ok((vmm, vcpu))
    }

    fn set_guest_sp(&self, vcpu: &Self::Vcpu, sp: u64) -> Result<(), TrapError> {
        // &self read-modify-write of RSP (KVM_SET_REGS is &self on VcpuFd).
        crate::kvm::record_kvm_stat(crate::kvm::KvmStat::GetRegs);
        let mut regs = vcpu
            .fd()
            .get_regs()
            .map_err(|e| TrapError::Hypervisor(format!("KVM_GET_REGS(set_rsp): {e}")))?;
        regs.rsp = sp;
        crate::kvm::record_kvm_stat(crate::kvm::KvmStat::SetRegs);
        vcpu.fd()
            .set_regs(&regs)
            .map_err(|e| TrapError::Hypervisor(format!("KVM_SET_REGS(rsp): {e}")))
    }

    fn fresh_fork_kicker(&self) -> Arc<dyn carrick_hal::VcpuRegistry> {
        Arc::new(KvmKicker::new())
    }
}

// ─── impl X86Vcpu for KvmVcpu ────────────────────────────────────────────────

/// Map an `X86Seg` to the KVM bring-up selector (KVM uses the hidden `kvm_segment`
/// directly and does not re-load from the GDT, but a consistent selector keeps
/// the descriptor self-describing). CS=0x23, SS/DS/ES=0x1B, others 0.
fn seg_selector(seg: X86Seg) -> u16 {
    match seg {
        X86Seg::Cs => 0x23,
        X86Seg::Ss | X86Seg::Ds | X86Seg::Es => 0x1B,
        _ => 0,
    }
}

/// Unpack a packed long-mode access-rights word (see `carrick_x86`'s `seg_ar`)
/// into the `kvm_segment` bit-fields.
fn ar_to_kvm_segment(base: u64, limit: u32, ar: u32, selector: u16) -> kvm_segment {
    kvm_segment {
        base,
        limit,
        selector,
        type_: (ar & 0xF) as u8,
        s: ((ar >> 4) & 1) as u8,
        dpl: ((ar >> 5) & 3) as u8,
        present: ((ar >> 7) & 1) as u8,
        avl: ((ar >> 12) & 1) as u8,
        l: ((ar >> 13) & 1) as u8,
        db: ((ar >> 14) & 1) as u8,
        g: ((ar >> 15) & 1) as u8,
        unusable: ((ar >> 16) & 1) as u8,
        ..Default::default()
    }
}

fn restore_kvm_vcpu(
    vcpu: &mut KvmVcpu,
    layout: BringupLayout,
    s: &X86VcpuSnapshot,
    rcx_walk: [u64; 4],
    rdx_walk: [u64; 4],
    rsp_walk: [u64; 4],
    fs_walk: [u64; 4],
) -> Result<(), TrapError> {
    use carrick_hal::guest_arch::GuestArch as _;
    use carrick_hal::x8664_arch::X8664GuestArch;

    let boot = X8664GuestArch::bootstrap_sysregs();
    let segs = carrick_x86::long_mode_segment_state();
    let kernel_cs = ((boot.star >> 32) & 0xFFFF) as u16;
    let kernel_ss = kernel_cs.wrapping_add(8);
    let user_base = ((boot.star >> 48) & 0xFFFF) as u16;
    let user_ss = user_base.wrapping_add(8);
    let user_cs = user_base.wrapping_add(16);
    let at_sysret = s.rip == layout.trampoline_base + 2;
    let (cs_ar, cs_selector, ss_ar, ss_selector) = if at_sysret {
        (segs.kernel_cs_ar, kernel_cs, segs.kernel_data_ar, kernel_ss)
    } else {
        (segs.cs_ar, user_cs, segs.data_ar, user_ss)
    };
    let mut sregs = vcpu
        .fd()
        .get_sregs()
        .map_err(|e| TrapError::Hypervisor(format!("KVM_GET_SREGS(restore): {e}")))?;
    sregs.cr0 = s.cr0;
    sregs.cr2 = 0;
    sregs.cr3 = s.cr3;
    sregs.cr4 = s.cr4;
    sregs.efer = s.efer;
    sregs.cs = ar_to_kvm_segment(0, 0xFFFF_FFFF, cs_ar, cs_selector);
    let data = |base| ar_to_kvm_segment(base, 0xFFFF_FFFF, segs.data_ar, 0);
    sregs.ss = ar_to_kvm_segment(0, 0xFFFF_FFFF, ss_ar, ss_selector);
    sregs.ds = ar_to_kvm_segment(0, 0xFFFF_FFFF, segs.data_ar, user_ss);
    sregs.es = ar_to_kvm_segment(0, 0xFFFF_FFFF, segs.data_ar, user_ss);
    sregs.fs = data(s.fs_base);
    sregs.gs = data(s.gs_base);
    let fault_slot = vcpu.x86_fault_slot();
    sregs.tr = ar_to_kvm_segment(
        carrick_x86::fault_slot_gpa(carrick_x86::fault_tss_base(layout), fault_slot)?,
        carrick_x86::fault::X86_TSS64_LIMIT,
        segs.tr_ar,
        seg_selector(X86Seg::Tr),
    );
    sregs.ldt = ar_to_kvm_segment(0, 0, segs.ldtr_ar, seg_selector(X86Seg::Ldtr));
    sregs.gdt = kvm_dtable {
        base: layout.gdt_base,
        limit: segs.gdt_limit as u16,
        ..Default::default()
    };
    sregs.idt = kvm_dtable {
        base: carrick_x86::fault_slot_gpa(carrick_x86::fault_idt_base(layout), fault_slot)?,
        limit: (carrick_x86::fault::X86_IDT_BYTES - 1) as u16,
        ..Default::default()
    };
    vcpu.fd()
        .set_sregs(&sregs)
        .map_err(|e| TrapError::Hypervisor(format!("KVM_SET_SREGS(restore): {e}")))?;

    let mut regs = vcpu
        .fd()
        .get_regs()
        .map_err(|e| TrapError::Hypervisor(format!("KVM_GET_REGS(restore): {e}")))?;
    regs.rax = s.gprs[0];
    regs.rbx = s.gprs[1];
    regs.rcx = s.gprs[2];
    regs.rdx = s.gprs[3];
    regs.rsi = s.gprs[4];
    regs.rdi = s.gprs[5];
    regs.rbp = s.gprs[6];
    regs.rsp = s.rsp;
    regs.r8 = s.gprs[8];
    regs.r9 = s.gprs[9];
    regs.r10 = s.gprs[10];
    regs.r11 = s.gprs[11];
    regs.r12 = s.gprs[12];
    regs.r13 = s.gprs[13];
    regs.r14 = s.gprs[14];
    regs.r15 = s.gprs[15];
    regs.rip = s.rip;
    regs.rflags = s.rflags;
    vcpu.fd()
        .set_regs(&regs)
        .map_err(|e| TrapError::Hypervisor(format!("KVM_SET_REGS(restore): {e}")))?;

    if let Some(xs) = &s.xsave {
        let _ = vcpu.set_xsave(xs)?;
    }
    vcpu.set_syscall_msrs(layout.trampoline_base, boot.star, boot.sfmask)?;
    vcpu.record_x86_restore_state(crate::kvm::KvmX86RestoreState {
        rip: s.rip,
        rsp: s.rsp,
        rflags: s.rflags,
        rax: s.gprs[0],
        rcx: s.gprs[2],
        rdx: s.gprs[3],
        rdi: s.gprs[5],
        r8: s.gprs[8],
        r11: s.gprs[11],
        fs_base: s.fs_base,
        gs_base: s.gs_base,
        cr0: s.cr0,
        cr3: s.cr3,
        cr4: s.cr4,
        efer: s.efer,
        rcx_walk,
        rdx_walk,
        rsp_walk,
        fs_walk,
    });
    Ok(())
}

impl KvmVcpu {
    fn collect_x86_fault_record(&mut self, first_data: &[u8]) -> Result<X86Exit, TrapError> {
        use carrick_hal::{HvVcpu, VcpuExit};

        let mut words = Vec::with_capacity(X86_FAULT_RECORD_U32_WORDS);
        words.push(fault_out_word(first_data)?);
        while words.len() < X86_FAULT_RECORD_U32_WORDS {
            match <Self as HvVcpu>::run(self).map_err(|e| TrapError::Hypervisor(e.to_string()))? {
                VcpuExit::IoOut { port, data } if port == FAULT_DOORBELL_PORT => {
                    words.push(fault_out_word(&data)?);
                }
                VcpuExit::Kicked => continue,
                other => {
                    return Err(TrapError::Hypervisor(format!(
                        "kvm-x86: fault doorbell record interrupted by {}",
                        vcpu_exit_name(&other)
                    )));
                }
            }
        }

        let record = FaultDoorbellRecord::from_u32_words(&words)?;
        if std::env::var_os("CARRICK_TRACE_X86_FAULTS").is_some() {
            eprintln!("[KVM-X86-FAULT] {record:?}");
        }
        fault_exit_from_record(self, record, "kvm-x86")
    }
}

fn fault_out_word(data: &[u8]) -> Result<u32, TrapError> {
    let bytes: [u8; 4] = data.try_into().map_err(|_| {
        TrapError::Hypervisor(format!(
            "kvm-x86: fault doorbell OUT expected 4 bytes, got {}",
            data.len()
        ))
    })?;
    Ok(u32::from_le_bytes(bytes))
}

fn vcpu_exit_name(exit: &carrick_hal::VcpuExit) -> &'static str {
    match exit {
        carrick_hal::VcpuExit::MmioWrite { .. } => "MMIO write",
        carrick_hal::VcpuExit::Exception { .. } => "exception",
        carrick_hal::VcpuExit::Kicked => "kick",
        carrick_hal::VcpuExit::Halt => "halt",
        carrick_hal::VcpuExit::IoOut { .. } => "I/O out",
    }
}

impl X86Vcpu for KvmVcpu {
    fn read_msr(&self, index: u32) -> Result<u64, TrapError> {
        let mut msrs = Msrs::from_entries(&[kvm_msr_entry {
            index,
            ..Default::default()
        }])
        .map_err(|e| TrapError::Hypervisor(format!("Msrs::from_entries({index:#x}): {e}")))?;
        if self
            .fd()
            .get_msrs(&mut msrs)
            .map_err(|e| TrapError::Hypervisor(format!("KVM_GET_MSRS({index:#x}): {e}")))?
            != 1
        {
            return Err(TrapError::Hypervisor(format!(
                "KVM_GET_MSRS({index:#x}) returned no entry"
            )));
        }
        msrs.as_slice()
            .first()
            .map(|entry| entry.data)
            .ok_or_else(|| TrapError::Hypervisor(format!("KVM_GET_MSRS({index:#x}) empty")))
    }

    fn get_gpr(&self, reg: X86Reg) -> Result<u64, TrapError> {
        // GPRs/RIP/RSP/RFLAGS via KVM_GET_REGS; control regs/EFER via KVM_GET_SREGS.
        Ok(match reg {
            X86Reg::Cr0 | X86Reg::Cr2 | X86Reg::Cr3 | X86Reg::Cr4 | X86Reg::Efer => {
                crate::kvm::record_kvm_stat(crate::kvm::KvmStat::GetSregs);
                let s = self
                    .fd()
                    .get_sregs()
                    .map_err(|e| TrapError::Hypervisor(format!("KVM_GET_SREGS: {e}")))?;
                match reg {
                    X86Reg::Cr0 => s.cr0,
                    X86Reg::Cr2 => s.cr2,
                    X86Reg::Cr3 => s.cr3,
                    X86Reg::Cr4 => s.cr4,
                    X86Reg::Efer => s.efer,
                    _ => unreachable!(),
                }
            }
            _ => {
                crate::kvm::record_kvm_stat(crate::kvm::KvmStat::GetRegs);
                let r = self
                    .fd()
                    .get_regs()
                    .map_err(|e| TrapError::Hypervisor(format!("KVM_GET_REGS: {e}")))?;
                match reg {
                    X86Reg::Rax => r.rax,
                    X86Reg::Rbx => r.rbx,
                    X86Reg::Rcx => r.rcx,
                    X86Reg::Rdx => r.rdx,
                    X86Reg::Rsi => r.rsi,
                    X86Reg::Rdi => r.rdi,
                    X86Reg::Rbp => r.rbp,
                    X86Reg::Rsp => r.rsp,
                    X86Reg::R8 => r.r8,
                    X86Reg::R9 => r.r9,
                    X86Reg::R10 => r.r10,
                    X86Reg::R11 => r.r11,
                    X86Reg::R12 => r.r12,
                    X86Reg::R13 => r.r13,
                    X86Reg::R14 => r.r14,
                    X86Reg::R15 => r.r15,
                    X86Reg::Rip => r.rip,
                    X86Reg::Rflags => r.rflags,
                    _ => unreachable!(),
                }
            }
        })
    }

    fn prepare_sysret_resume(&mut self, _layout: BringupLayout) -> Result<(), TrapError> {
        use carrick_hal::guest_arch::GuestArch as _;
        use carrick_hal::x8664_arch::X8664GuestArch;

        let boot = X8664GuestArch::bootstrap_sysregs();
        let segs = carrick_x86::long_mode_segment_state();
        let kernel_cs = ((boot.star >> 32) & 0xFFFF) as u16;
        let kernel_ss = kernel_cs.wrapping_add(8);
        let want_cs = ar_to_kvm_segment(0, 0xFFFF_FFFF, segs.kernel_cs_ar, kernel_cs);
        let want_ss = ar_to_kvm_segment(0, 0xFFFF_FFFF, segs.kernel_data_ar, kernel_ss);

        // Read sregs from the mmap'd kvm_run.s.regs (the kernel synced it out on
        // the doorbell exit; kvm_valid_regs requests SREGS too) instead of a
        // KVM_GET_SREGS ioctl. Read-only mirror — kernel sregs stay authoritative.
        let mut sregs = if self.sync_regs_usable() {
            self.fd().sync_regs().sregs
        } else {
            crate::kvm::record_kvm_stat(crate::kvm::KvmStat::GetSregs);
            self.fd()
                .get_sregs()
                .map_err(|e| TrapError::Hypervisor(format!("KVM_GET_SREGS(sysret): {e}")))?
        };
        // A guest SYSCALL already loaded kernel CS/SS — selector AND the fixed
        // hidden descriptor (base 0, 4 GiB limit, kernel AR) — from STAR, so the
        // reprogram is normally a no-op. Skip the KVM_SET_SREGS when CS/SS already
        // match; only the first sysret after a fresh/forked vCPU needs the write.
        if sregs.cs == want_cs && sregs.ss == want_ss {
            return Ok(());
        }
        sregs.cs = want_cs;
        sregs.ss = want_ss;
        crate::kvm::record_kvm_stat(crate::kvm::KvmStat::SetSregs);
        self.fd()
            .set_sregs(&sregs)
            .map_err(|e| TrapError::Hypervisor(format!("KVM_SET_SREGS(sysret): {e}")))
    }

    fn set_gpr(&mut self, reg: X86Reg, v: u64) -> Result<(), TrapError> {
        match reg {
            X86Reg::Cr0 | X86Reg::Cr2 | X86Reg::Cr3 | X86Reg::Cr4 | X86Reg::Efer => {
                crate::kvm::record_kvm_stat(crate::kvm::KvmStat::GetSregs);
                let mut s = self
                    .fd()
                    .get_sregs()
                    .map_err(|e| TrapError::Hypervisor(format!("KVM_GET_SREGS: {e}")))?;
                match reg {
                    X86Reg::Cr0 => s.cr0 = v,
                    X86Reg::Cr2 => s.cr2 = v,
                    X86Reg::Cr3 => s.cr3 = v,
                    X86Reg::Cr4 => s.cr4 = v,
                    X86Reg::Efer => s.efer = v,
                    _ => unreachable!(),
                }
                crate::kvm::record_kvm_stat(crate::kvm::KvmStat::SetSregs);
                self.fd()
                    .set_sregs(&s)
                    .map_err(|e| TrapError::Hypervisor(format!("KVM_SET_SREGS: {e}")))
            }
            _ => {
                crate::kvm::record_kvm_stat(crate::kvm::KvmStat::GetRegs);
                let mut r = self
                    .fd()
                    .get_regs()
                    .map_err(|e| TrapError::Hypervisor(format!("KVM_GET_REGS: {e}")))?;
                match reg {
                    X86Reg::Rax => r.rax = v,
                    X86Reg::Rbx => r.rbx = v,
                    X86Reg::Rcx => r.rcx = v,
                    X86Reg::Rdx => r.rdx = v,
                    X86Reg::Rsi => r.rsi = v,
                    X86Reg::Rdi => r.rdi = v,
                    X86Reg::Rbp => r.rbp = v,
                    X86Reg::Rsp => r.rsp = v,
                    X86Reg::R8 => r.r8 = v,
                    X86Reg::R9 => r.r9 = v,
                    X86Reg::R10 => r.r10 = v,
                    X86Reg::R11 => r.r11 = v,
                    X86Reg::R12 => r.r12 = v,
                    X86Reg::R13 => r.r13 = v,
                    X86Reg::R14 => r.r14 = v,
                    X86Reg::R15 => r.r15 = v,
                    X86Reg::Rip => r.rip = v,
                    X86Reg::Rflags => r.rflags = v,
                    _ => unreachable!(),
                }
                crate::kvm::record_kvm_stat(crate::kvm::KvmStat::SetRegs);
                self.fd()
                    .set_regs(&r)
                    .map_err(|e| TrapError::Hypervisor(format!("KVM_SET_REGS: {e}")))
            }
        }
    }

    fn complete_sysret(
        &mut self,
        layout: BringupLayout,
        return_value: i64,
        resume_pc: u64,
    ) -> Result<(u64, u64), TrapError> {
        // Read the whole GPR snapshot ONCE (RCX/R11 for the parked user PC/RFLAGS,
        // and as the base for the RAX/RIP writes), then flush it in ONE
        // KVM_SET_REGS. With KVM_CAP_SYNC_REGS the snapshot is the mmap'd
        // kvm_run.s.regs the kernel synced out on the doorbell exit — no
        // KVM_GET_REGS at all. The snapshot is a READ-ONLY mirror (we never set
        // kvm_dirty_regs), so the kernel registers stay authoritative and every
        // other accessor (get_gpr/set_gpr) is unaffected. RAX/RIP are independent
        // of RCX/R11, so reading first preserves their values.
        let mut regs = if self.sync_regs_usable() {
            self.fd().sync_regs().regs
        } else {
            crate::kvm::record_kvm_stat(crate::kvm::KvmStat::GetRegs);
            self.fd()
                .get_regs()
                .map_err(|e| TrapError::Hypervisor(format!("KVM_GET_REGS(sysret): {e}")))?
        };
        let user_pc = regs.rcx;
        let user_rflags = regs.r11 | 0x2;
        self.prepare_sysret_resume(layout)?;
        regs.rax = return_value as u64;
        // RIP fix-up for the M:N reclaim resume:
        //
        // The syscall trampoline is `out %al,$0xC5 ; sysretq`; `resume_pc` is the
        // OUT address (trampoline_base). On the NORMAL path the vCPU is still
        // parked at that KVM_EXIT_IO with a pending PIO completion, so the NEXT
        // KVM_RUN advances RIP past the 2-byte OUT (to the sysretq) before
        // executing — landing the guest on the SYSRET. The reclaim path swaps in a
        // freshly-installed vCPU whose pending PIO was FLUSHED at acquisition
        // (`create_vcpu_on_shared_vm`), so KVM has NOTHING to auto-advance: setting
        // RIP=resume_pc would re-execute the OUT, re-trap the doorbell with RAX
        // clobbered to the syscall's return value, and the guest would re-issue the
        // SAME syscall with a bogus number (read/EBADF) — glibc's "futex facility
        // returned an unexpected error code". `sync_regs_usable()` is false exactly
        // for that un-run installed vCPU, so step the RIP past the OUT ourselves.
        let stale_reclaim = !self.sync_regs_usable();
        regs.rip = if stale_reclaim && resume_pc == layout.trampoline_base {
            const SYSCALL_DOORBELL_OUT_LEN: u64 = 2; // `E6 C5` = out %al,$0xC5
            resume_pc + SYSCALL_DOORBELL_OUT_LEN
        } else {
            resume_pc
        };
        crate::kvm::record_kvm_stat(crate::kvm::KvmStat::SetRegs);
        self.fd()
            .set_regs(&regs)
            .map_err(|e| TrapError::Hypervisor(format!("KVM_SET_REGS(sysret): {e}")))?;
        Ok((user_pc, user_rflags))
    }

    fn set_segment(
        &mut self,
        seg: X86Seg,
        base: u64,
        limit: u32,
        ar: u32,
    ) -> Result<(), TrapError> {
        crate::kvm::record_kvm_stat(crate::kvm::KvmStat::GetSregs);
        let mut s = self
            .fd()
            .get_sregs()
            .map_err(|e| TrapError::Hypervisor(format!("KVM_GET_SREGS(seg): {e}")))?;
        match seg {
            X86Seg::Gdtr => {
                s.gdt = kvm_dtable {
                    base,
                    limit: limit as u16,
                    ..Default::default()
                };
            }
            X86Seg::Idtr => {
                s.idt = kvm_dtable {
                    base,
                    limit: limit as u16,
                    ..Default::default()
                };
            }
            _ => {
                let kseg = ar_to_kvm_segment(base, limit, ar, seg_selector(seg));
                match seg {
                    X86Seg::Cs => s.cs = kseg,
                    X86Seg::Ds => s.ds = kseg,
                    X86Seg::Es => s.es = kseg,
                    X86Seg::Fs => s.fs = kseg,
                    X86Seg::Gs => s.gs = kseg,
                    X86Seg::Ss => s.ss = kseg,
                    X86Seg::Tr => s.tr = kseg,
                    X86Seg::Ldtr => s.ldt = kseg,
                    X86Seg::Gdtr | X86Seg::Idtr => unreachable!(),
                }
            }
        }
        crate::kvm::record_kvm_stat(crate::kvm::KvmStat::SetSregs);
        self.fd()
            .set_sregs(&s)
            .map_err(|e| TrapError::Hypervisor(format!("KVM_SET_SREGS(seg): {e}")))
    }

    fn get_fs_base(&self) -> Result<u64, TrapError> {
        crate::kvm::record_kvm_stat(crate::kvm::KvmStat::GetSregs);
        let s = self
            .fd()
            .get_sregs()
            .map_err(|e| TrapError::Hypervisor(format!("KVM_GET_SREGS(fs): {e}")))?;
        Ok(s.fs.base)
    }

    fn set_fs_base(&mut self, v: u64) -> Result<(), TrapError> {
        crate::kvm::record_kvm_stat(crate::kvm::KvmStat::GetSregs);
        let mut s = self
            .fd()
            .get_sregs()
            .map_err(|e| TrapError::Hypervisor(format!("KVM_GET_SREGS(fs): {e}")))?;
        s.fs.base = v;
        crate::kvm::record_kvm_stat(crate::kvm::KvmStat::SetSregs);
        self.fd()
            .set_sregs(&s)
            .map_err(|e| TrapError::Hypervisor(format!("KVM_SET_SREGS(fs.base): {e}")))
    }

    fn get_gs_base(&self) -> Result<u64, TrapError> {
        crate::kvm::record_kvm_stat(crate::kvm::KvmStat::GetSregs);
        let s = self
            .fd()
            .get_sregs()
            .map_err(|e| TrapError::Hypervisor(format!("KVM_GET_SREGS(gs): {e}")))?;
        Ok(s.gs.base)
    }

    fn set_gs_base(&mut self, v: u64) -> Result<(), TrapError> {
        crate::kvm::record_kvm_stat(crate::kvm::KvmStat::GetSregs);
        let mut s = self
            .fd()
            .get_sregs()
            .map_err(|e| TrapError::Hypervisor(format!("KVM_GET_SREGS(gs): {e}")))?;
        s.gs.base = v;
        crate::kvm::record_kvm_stat(crate::kvm::KvmStat::SetSregs);
        self.fd()
            .set_sregs(&s)
            .map_err(|e| TrapError::Hypervisor(format!("KVM_SET_SREGS(gs.base): {e}")))
    }

    fn set_syscall_msrs(
        &mut self,
        lstar: u64,
        star: u64,
        sfmask: u64,
    ) -> Result<MsrInstall, TrapError> {
        // KVM exposes the SYSCALL MSRs directly via KVM_SET_MSRS — Direct.
        let msrs = Msrs::from_entries(&[
            kvm_msr_entry {
                index: 0xc000_0081,
                data: star,
                ..Default::default()
            }, // STAR
            kvm_msr_entry {
                index: 0xc000_0082,
                data: lstar,
                ..Default::default()
            }, // LSTAR
            kvm_msr_entry {
                index: 0xc000_0084,
                data: sfmask,
                ..Default::default()
            }, // SFMASK
        ])
        .map_err(|e| TrapError::Hypervisor(format!("kvm-x86: Msrs::from_entries: {e}")))?;
        crate::kvm::record_kvm_stat(crate::kvm::KvmStat::SetMsrs);
        let n = self
            .fd()
            .set_msrs(&msrs)
            .map_err(|e| TrapError::Hypervisor(format!("kvm-x86: KVM_SET_MSRS: {e}")))?;
        if n != 3 {
            return Err(TrapError::Hypervisor(format!(
                "kvm-x86: KVM_SET_MSRS wrote {n}/3 (partial)"
            )));
        }
        Ok(MsrInstall::Direct)
    }

    fn get_fp(&self) -> Result<Option<[u8; 512]>, TrapError> {
        // KVM_GET_FPU yields the native 512-byte fxsave area. The `kvm_fpu`
        // struct's first 512 bytes ARE the legacy fxsave region (fpr/xmm/mxcsr/
        // control words at the architectural offsets), so we serialize it.
        crate::kvm::record_kvm_stat(crate::kvm::KvmStat::GetFpu);
        let fpu = self
            .fd()
            .get_fpu()
            .map_err(|e| TrapError::Hypervisor(format!("KVM_GET_FPU: {e}")))?;
        Ok(Some(kvm_fpu_to_fxsave(&fpu)))
    }

    fn set_fp(&mut self, fx: &[u8; 512]) -> Result<bool, TrapError> {
        crate::kvm::record_kvm_stat(crate::kvm::KvmStat::GetFpu);
        let mut fpu = self
            .fd()
            .get_fpu()
            .map_err(|e| TrapError::Hypervisor(format!("KVM_GET_FPU(set): {e}")))?;
        fxsave_into_kvm_fpu(fx, &mut fpu);
        crate::kvm::record_kvm_stat(crate::kvm::KvmStat::SetFpu);
        self.fd()
            .set_fpu(&fpu)
            .map_err(|e| TrapError::Hypervisor(format!("KVM_SET_FPU: {e}")))?;
        Ok(true)
    }

    fn get_xsave(&self) -> Result<Option<[u8; carrick_x86::XSAVE_LEN]>, TrapError> {
        // KVM_GET_XSAVE yields the standard-format XSAVE area (legacy FXSAVE +
        // 64-byte header + AVX YMM_Hi at offset 576). Copy our XSAVE_LEN-byte
        // prefix out of the 4 KiB `kvm_xsave` region — this is what preserves a
        // guest's AVX upper halves across fork/clone/execve and signals (the
        // FXSAVE-only get_fp drops them, corrupting AVX state).
        let xsave = self
            .fd()
            .get_xsave()
            .map_err(|e| TrapError::Hypervisor(format!("KVM_GET_XSAVE: {e}")))?;
        let mut out = [0u8; carrick_x86::XSAVE_LEN];
        for (i, chunk) in out.chunks_mut(4).enumerate() {
            chunk.copy_from_slice(&xsave.region[i].to_ne_bytes());
        }
        Ok(Some(out))
    }

    fn set_xsave(&mut self, xs: &[u8; carrick_x86::XSAVE_LEN]) -> Result<bool, TrapError> {
        // Read-modify-write: preserve any `kvm_xsave` bytes beyond our window
        // (none with XCR0 = x87|SSE|AVX), overwrite the standard prefix.
        let mut xsave = self
            .fd()
            .get_xsave()
            .map_err(|e| TrapError::Hypervisor(format!("KVM_GET_XSAVE(set): {e}")))?;
        for (i, chunk) in xs.chunks(4).enumerate() {
            xsave.region[i] = u32::from_ne_bytes(chunk.try_into().unwrap_or([0u8; 4]));
        }
        // SAFETY: `xsave` is a fully-initialized kvm_xsave whose standard-format
        // region we populated from a valid XSAVE image; KVM validates xstate_bv.
        unsafe {
            self.fd()
                .set_xsave(&xsave)
                .map_err(|e| TrapError::Hypervisor(format!("KVM_SET_XSAVE: {e}")))?;
        }
        Ok(true)
    }

    fn run(&mut self) -> Result<X86Exit, TrapError> {
        use carrick_hal::{HvVcpu, VcpuExit};

        match <Self as HvVcpu>::run(self).map_err(|e| TrapError::Hypervisor(e.to_string()))? {
            // SYSCALL doorbell: OUT 0xC5 → KVM_EXIT_IO. KVM reports the native
            // current RIP (observed as the OUT address on Linux/KVM); it
            // completes the PIO step when userspace re-enters. The shared x86
            // engine treats either trampoline address as syscall-return state.
            VcpuExit::IoOut { port, .. } if port == carrick_hal::SYSCALL_DOORBELL_PORT => {
                // With KVM_CAP_SYNC_REGS the kernel already mirrored the GPRs into
                // kvm_run.s.regs on this exit (kvm_valid_regs was set before the
                // run), so read the frame from the mmap page — no KVM_GET_REGS.
                let regs = if self.sync_regs_usable() {
                    self.fd().sync_regs().regs
                } else {
                    crate::kvm::record_kvm_stat(crate::kvm::KvmStat::GetRegs);
                    self.fd().get_regs().map_err(|e| {
                        TrapError::Hypervisor(format!("KVM_GET_REGS(doorbell): {e}"))
                    })?
                };
                let frame = carrick_guest_mem::X8664SyscallFrame {
                    rax: regs.rax,
                    rdi: regs.rdi,
                    rsi: regs.rsi,
                    rdx: regs.rdx,
                    r10: regs.r10,
                    r8: regs.r8,
                    r9: regs.r9,
                };
                Ok(X86Exit::Syscall {
                    frame,
                    resume_pc: regs.rip,
                })
            }
            VcpuExit::IoOut { port, data } if port == FAULT_DOORBELL_PORT => {
                self.collect_x86_fault_record(&data)
            }
            VcpuExit::IoOut { port, .. } => {
                let mut msg = format!("kvm-x86: unexpected OUT to port 0x{port:04X}");
                self.append_debug_state(&mut msg);
                Err(TrapError::Hypervisor(msg))
            }
            VcpuExit::Halt => Ok(X86Exit::Halt),
            VcpuExit::Kicked => Ok(X86Exit::Kicked),
            VcpuExit::MmioWrite { gpa, .. } => Err(TrapError::Hypervisor(format!(
                "kvm-x86: unexpected MMIO write to gpa=0x{gpa:x} (ring-3 fault / PML4 gap)"
            ))),
            VcpuExit::Exception { syndrome, far } => Err(TrapError::Hypervisor(format!(
                "kvm-x86: unexpected Exception syndrome=0x{syndrome:x} far=0x{far:x}"
            ))),
        }
    }

    fn enable_halt_exit(&mut self) -> Result<(), TrapError> {
        // KVM exits on HLT by default (KVM_EXIT_HLT); no capability to enable.
        Ok(())
    }
}

// ─── M:N reclaim helpers (budget query + snapshot (de)serialization) ─────────

/// Headroom subtracted from KVM_CAP_MAX_VCPUS for the admission budget: the boot
/// vCPU plus a fork-rebuild's fresh vcpu that can momentarily coexist with the
/// recycled set (mirrors the bhyve/HVF reserve idea). Keeps total created vcpu
/// ids safely under the hard cap.
const VCPU_BUDGET_RESERVE: usize = 16;

/// Fallback budget when KVM_CAP_MAX_VCPUS can't be queried — comfortably under
/// the typical ~512 cap and large enough not to over-serialize realistic guests.
const VCPU_BUDGET_FALLBACK: usize = 240;

/// Query KVM_CAP_MAX_VCPUS (the per-VM hard cap). Opens a throwaway `/dev/kvm`
/// handle (the cap is global, not per-VM, so any handle reports it) and reads the
/// integer extension; on any failure returns [`VCPU_BUDGET_FALLBACK`].
fn kvm_max_vcpus() -> usize {
    match kvm_ioctls::Kvm::new() {
        Ok(kvm) => {
            let n = kvm.check_extension_int(kvm_ioctls::Cap::MaxVcpus);
            if n > 0 {
                n as usize
            } else {
                VCPU_BUDGET_FALLBACK
            }
        }
        Err(_) => VCPU_BUDGET_FALLBACK,
    }
}

/// Wire format of an [`X86VcpuSnapshot`] for the reclaim save→rebind round-trip
/// (same host thread, so endianness/layout are trivially consistent): the 16
/// GPRs + RIP/RSP/RFLAGS + CR0/3/4 + EFER + FS/GS base as little-endian u64s,
/// then a 1-byte XSAVE-present flag, then (if present) the XSAVE_LEN bytes.
const SNAP_SCALARS: usize = 16 + 3 + 4 + 2; // gprs + rip/rsp/rflags + cr0/3/4/efer + fs/gs
const SNAP_HEADER_LEN: usize = SNAP_SCALARS * 8 + 1;

fn serialize_x86_snapshot(s: &X86VcpuSnapshot) -> Vec<u8> {
    let mut buf = Vec::with_capacity(SNAP_HEADER_LEN + carrick_x86::XSAVE_LEN);
    for g in &s.gprs {
        buf.extend_from_slice(&g.to_le_bytes());
    }
    for v in [
        s.rip, s.rsp, s.rflags, s.cr0, s.cr3, s.cr4, s.efer, s.fs_base, s.gs_base,
    ] {
        buf.extend_from_slice(&v.to_le_bytes());
    }
    match &s.xsave {
        Some(xs) => {
            buf.push(1);
            buf.extend_from_slice(xs);
        }
        None => buf.push(0),
    }
    buf
}

fn deserialize_x86_snapshot(state: &[u8]) -> Option<X86VcpuSnapshot> {
    if state.len() < SNAP_HEADER_LEN {
        return None;
    }
    let rd = |i: usize| -> u64 {
        let off = i * 8;
        u64::from_le_bytes(state[off..off + 8].try_into().unwrap_or([0u8; 8]))
    };
    let mut gprs = [0u64; 16];
    for (i, g) in gprs.iter_mut().enumerate() {
        *g = rd(i);
    }
    let xsave = if state[SNAP_SCALARS * 8] == 1 {
        let start = SNAP_HEADER_LEN;
        let end = start + carrick_x86::XSAVE_LEN;
        if state.len() < end {
            return None;
        }
        let mut xs = [0u8; carrick_x86::XSAVE_LEN];
        xs.copy_from_slice(&state[start..end]);
        Some(xs)
    } else {
        None
    };
    Some(X86VcpuSnapshot {
        gprs,
        rip: rd(16),
        rsp: rd(17),
        rflags: rd(18),
        cr0: rd(19),
        cr3: rd(20),
        cr4: rd(21),
        efer: rd(22),
        fs_base: rd(23),
        gs_base: rd(24),
        xsave,
    })
}

/// Serialize a `kvm_fpu` into the 512-byte legacy fxsave layout (Intel SDM
/// vol. 1 §10.5.1): control words +0, st_space (x87) +32, xmm_space +160,
/// mxcsr +24.
fn kvm_fpu_to_fxsave(fpu: &kvm_bindings::kvm_fpu) -> [u8; 512] {
    let mut fx = [0u8; 512];
    fx[0] = (fpu.fcw & 0xFF) as u8;
    fx[1] = (fpu.fcw >> 8) as u8;
    fx[2] = (fpu.fsw & 0xFF) as u8;
    fx[3] = (fpu.fsw >> 8) as u8;
    fx[4] = fpu.ftwx;
    fx[5] = 0; // reserved
    fx[6] = (fpu.last_opcode & 0xFF) as u8;
    fx[7] = (fpu.last_opcode >> 8) as u8;
    fx[8..16].copy_from_slice(&fpu.last_ip.to_le_bytes());
    fx[16..24].copy_from_slice(&fpu.last_dp.to_le_bytes());
    fx[24..28].copy_from_slice(&fpu.mxcsr.to_le_bytes());
    // st_space: 8 × 16 bytes at +32 (KVM stores [u32; 32] = 128 bytes).
    for (i, w) in fpu.fpr.iter().enumerate() {
        let off = 32 + i * 16;
        fx[off..off + 16].copy_from_slice(&w[..16.min(w.len())]);
    }
    // xmm_space: 16 × 16 bytes at +160.
    for (i, w) in fpu.xmm.iter().enumerate() {
        let off = 160 + i * 16;
        fx[off..off + 16].copy_from_slice(&w[..16.min(w.len())]);
    }
    fx
}

/// Inverse of [`kvm_fpu_to_fxsave`]: load a 512-byte fxsave image into `fpu`.
fn fxsave_into_kvm_fpu(fx: &[u8; 512], fpu: &mut kvm_bindings::kvm_fpu) {
    fpu.fcw = u16::from_le_bytes([fx[0], fx[1]]);
    fpu.fsw = u16::from_le_bytes([fx[2], fx[3]]);
    fpu.ftwx = fx[4];
    fpu.last_opcode = u16::from_le_bytes([fx[6], fx[7]]);
    fpu.last_ip = u64::from_le_bytes(fx[8..16].try_into().unwrap_or_default());
    fpu.last_dp = u64::from_le_bytes(fx[16..24].try_into().unwrap_or_default());
    fpu.mxcsr = u32::from_le_bytes(fx[24..28].try_into().unwrap_or_default());
    for (i, w) in fpu.fpr.iter_mut().enumerate() {
        let off = 32 + i * 16;
        let n = w.len().min(16);
        w[..n].copy_from_slice(&fx[off..off + n]);
    }
    for (i, w) in fpu.xmm.iter_mut().enumerate() {
        let off = 160 + i * 16;
        let n = w.len().min(16);
        w[..n].copy_from_slice(&fx[off..off + n]);
    }
}

// ─── bring_up ────────────────────────────────────────────────────────────────

/// Bring up a KVM x86 guest for `image` and wrap it in the generic
/// [`X86EngineCore`]. Builds the `GuestRam` window table (N MAP_NORESERVE slots),
/// writes the trampoline/GDT/PML4 images, creates the vCPU, and programs long
/// mode via the shared [`carrick_x86::program_longmode_entry`].
pub fn bring_up(image: &AddressSpace) -> Result<X86EngineCore<KvmVmm>, TrapError> {
    let (vm, ram, page_tables, vcpu) = build_kvm_x86_guest(image)?;
    let mut vmm = KvmVmm {
        vm,
        ram,
        page_tables,
        reclaim: None,
        vfork_shadows: None,
        vfork_arena_high_water: u64::MAX,
    };
    // Bind the reclaim handle to the boot vCPU so a later block-recycle can swap
    // the live vCPU underneath the engine's separate `vcpu` field.
    vmm.bind_reclaim(&vcpu);
    Ok(X86EngineCore::from_parts(vmm, vcpu, KVM_X86_LAYOUT))
}

/// The freshly-built KVM x86 guest parts: the VM, its `GuestRam` window table,
/// the shared PML4 manager, and the boot vCPU. `bring_up` destructures these
/// into a `KvmVmm` + engine.
type BuiltKvmX86Guest = (KvmVm, GuestRam, Arc<Mutex<Pml4Manager>>, KvmVcpu);

fn build_kvm_x86_guest(image: &AddressSpace) -> Result<BuiltKvmX86Guest, TrapError> {
    use carrick_hal::HvVm as _;

    // 1. Lay out guest RAM (identity GPA = VA; N capped MAP_NORESERVE windows).
    let mut ram =
        GuestRam::build_for_image_x86(image).map_err(|e| TrapError::Hypervisor(e.to_string()))?;

    // 2. Create the VM + register every window as a KVM slot.
    let mut vm = KvmVm::create_empty().map_err(|e| TrapError::Hypervisor(e.to_string()))?;
    for (gpa, host, len) in ram.windows_for_kvm() {
        vm.map_memory(gpa, host, len, carrick_hal::MemPerms::ReadWriteExec)
            .map_err(|e| TrapError::Hypervisor(e.to_string()))?;
    }

    // 3. Write the bring-up byte images (trampoline + GDT + PML4) into RAM.
    //    The plan/PML4 are built via the shared region-walk.
    let plan = carrick_x86::plan_windows(image, KVM_X86_LAYOUT)?;
    let pml4_bytes = carrick_x86::build_pml4(&plan, KVM_X86_LAYOUT)?;
    let page_tables = Arc::new(Mutex::new(Pml4Manager::new(
        pml4_bytes.clone(),
        X86_PML4_BASE,
    )));
    write_bringup_images_via_ram(&mut ram, &pml4_bytes)?;

    // 4. Create the vCPU and program long mode (CR/EFER/segs/GDTR/MSRs).
    let vcpu = vm
        .add_vcpu()
        .map_err(|e| TrapError::Hypervisor(e.to_string()))?;
    let rsp = image
        .initial_stack_pointer()
        .unwrap_or(carrick_mem::memory::LINUX_STACK_TOP);
    let mut vcpu = vcpu;
    let _install =
        carrick_x86::program_longmode_entry(&mut vcpu, KVM_X86_LAYOUT, image.entry(), rsp)?;
    // KVM is MsrInstall::Direct — the SYSCALL MSRs are already live; no ring-0 blob.
    // The vDSO clock page is calibrated by the shared engine (`from_parts` calls
    // `carrick_x86::vdso::populate_vdso_vvar`), so there is no KVM-private copy.

    Ok((vm, ram, page_tables, vcpu))
}

/// Write the trampoline/GDT/PML4 byte images into `ram` directly (the bring-up
/// holds `&mut GuestRam`, so it uses `GuestRam::write_gpa` rather than the
/// `&self` `GuestVmBackend::write_gpa` hook).
fn write_bringup_images_via_ram(ram: &mut GuestRam, pml4_bytes: &[u8]) -> Result<(), TrapError> {
    use carrick_hal::guest_arch::GuestArch as _;
    use carrick_hal::x8664_arch::X8664GuestArch;

    ram.write_gpa(
        X86_TRAMPOLINE_BASE,
        &X8664GuestArch::entry_trampoline_bytes(),
    )
    .map_err(|e| TrapError::Hypervisor(e.to_string()))?;
    let boot = X8664GuestArch::bootstrap_sysregs();
    let gdt_bytes: Vec<u8> = boot.gdt.iter().flat_map(|e| e.to_le_bytes()).collect();
    ram.write_gpa(X86_GDT_BASE, &gdt_bytes)
        .map_err(|e| TrapError::Hypervisor(e.to_string()))?;
    ram.write_gpa(X86_PML4_BASE, pml4_bytes)
        .map_err(|e| TrapError::Hypervisor(e.to_string()))?;
    carrick_x86::write_fault_tables_with(KVM_X86_LAYOUT, |gpa, bytes| {
        ram.write_gpa(gpa, bytes)
            .map_err(|e| TrapError::Hypervisor(e.to_string()))
    })?;
    Ok(())
}
