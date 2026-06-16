//! The NVMM x86_64 backend on the shared `carrick-x86` scaffold (portability S5).
//!
//! `NvmmVmm` (+ `impl X86Vcpu for NvmmX86Vcpu`) is the thin per-VMM trait pair the
//! generic [`carrick_x86::X86EngineCore`] is parameterized over — mirroring
//! `carrick-vmm-kvm`'s `kvm_x86_engine`, NOT copied from carrick-vmm-bhyve. The trap
//! loop, register walk, guest-memory access, snapshot triple, long-mode
//! bring-up, and run-elf loop all live ONCE in `carrick-x86`; this supplies only
//! the NVMM-specific marshalling.
//!
//! NVMM answers the three quirk seams with its BEST mechanism (the doctrine):
//!   - `set_syscall_msrs` → [`MsrInstall::Direct`] (`setstate(STATE_MSRS)` writes
//!     EFER/STAR/LSTAR/SFMASK directly — NO ring-0 WRMSR blob).
//!   - `get_fp` → `Some` (`getstate(STATE_FPU)` ↔ `struct fxsave fpu`, native —
//!     NO FXSAVE stub).
//!   - `fork_ram_strategy` → [`ForkRamStrategy::EagerCopy`] (NVMM's hypervisor
//!     writes race host COW snapshots; fork children rebuild a fresh machine
//!     from a pre-fork private-RAM snapshot).
//!
//! The IO doorbell exit returns `io.npc` (the next-PC; the kernel does NOT
//! advance RIP — proven in M0), so `run()` fills `resume_pc = exit.io.npc`.

use std::sync::Arc;

use carrick_hal::TrapError;
use carrick_mem::memory::AddressSpace;
use carrick_x86::{
    BringupLayout, FAULT_DOORBELL_PORT, ForkRamStrategy, MsrInstall, WindowPlan, WindowRegion,
    X86EngineCore, X86Exit, X86Reg, X86Seg, X86Vcpu, X86Vmm,
};

use crate::nvmm::{
    self, Fxsave, NVMM_PROT_EXEC, NVMM_PROT_READ, NVMM_PROT_WRITE, NVMM_VCPU_EXIT_HALTED,
    NVMM_VCPU_EXIT_IO, NVMM_VCPU_EXIT_MEMORY, NVMM_VCPU_EXIT_NONE, NVMM_X64_CR_CR0,
    NVMM_X64_CR_CR2, NVMM_X64_CR_CR3, NVMM_X64_CR_CR4, NVMM_X64_GPR_R8, NVMM_X64_GPR_R9,
    NVMM_X64_GPR_R10, NVMM_X64_GPR_R11, NVMM_X64_GPR_R12, NVMM_X64_GPR_R13, NVMM_X64_GPR_R14,
    NVMM_X64_GPR_R15, NVMM_X64_GPR_RAX, NVMM_X64_GPR_RBP, NVMM_X64_GPR_RBX, NVMM_X64_GPR_RCX,
    NVMM_X64_GPR_RDI, NVMM_X64_GPR_RDX, NVMM_X64_GPR_RFLAGS, NVMM_X64_GPR_RIP, NVMM_X64_GPR_RSI,
    NVMM_X64_GPR_RSP, NVMM_X64_MSR_EFER, NVMM_X64_MSR_LSTAR, NVMM_X64_MSR_SFMASK,
    NVMM_X64_MSR_STAR, NVMM_X64_SEG_CS, NVMM_X64_SEG_DS, NVMM_X64_SEG_ES, NVMM_X64_SEG_FS,
    NVMM_X64_SEG_GDT, NVMM_X64_SEG_GS, NVMM_X64_SEG_IDT, NVMM_X64_SEG_LDT, NVMM_X64_SEG_SS,
    NVMM_X64_SEG_TR, NVMM_X64_STATE_CRS, NVMM_X64_STATE_FPU, NVMM_X64_STATE_GPRS,
    NVMM_X64_STATE_MSRS, NVMM_X64_STATE_SEGS, NvmmMachine, NvmmRamBacking, NvmmVcpu,
    NvmmX64StateSeg,
};
use crate::nvmm_kicker::{NvmmKickHandle, NvmmKicker};

/// The NVMM x86 kernel-window GPA layout (trampoline/GDT/PML4). Placed at 256
/// MiB — identity-mapped (VA==GPA, compact, under NVMM's `max_ram`) and ABOVE the
/// static binary's low load addresses (a non-PIE ET_EXEC loads at ~2 MiB), so it
/// never collides with an image region (mirrors KVM's `X86_KERNEL_WINDOW_BASE`).
pub const NVMM_X86_LAYOUT: BringupLayout = BringupLayout {
    trampoline_base: 0x1000_0000,
    gdt_base: 0x1000_1000,
    pml4_base: 0x1000_2000,
};

/// Chunk size for sparse NVMM backing. The logical x86 page tables cover the
/// full guest arena, but the NetBSD eager-GPA debug module faults every mapped
/// GPA page, so large windows are realized lazily in bounded chunks.
const SPARSE_WINDOW_CHUNK_LEN: u64 = 64 * 1024 * 1024;
const X86_2M: u64 = 2 * 1024 * 1024;
const X86_1G: u64 = 1024 * 1024 * 1024;

fn map_err(e: nvmm::NvmmError) -> TrapError {
    TrapError::Hypervisor(e.to_string())
}

// ─── NvmmVmm ─────────────────────────────────────────────────────────────────

/// One mapped guest-RAM region. NVMM's `max_ram` ceiling (128 GiB on VM 201) is
/// far below carrick's guest VA layout (heap 256 GiB, mmap 384 GiB, stack ~1
/// TiB), and `nvmm_gpa_map` ABORTS on an out-of-ceiling GPA, so — exactly like
/// bhyve — we assign each region a COMPACT low GPA from a bump cursor and let the
/// PML4 decouple the guest VA from it. The engine queries guest memory by VA
/// (`GuestMemory::read_bytes(va)`), so we record + resolve by `va` and only use
/// `gpa` for `gpa_map`. (Kernel-window regions are identity: `va == gpa`.)
struct Region {
    va: u64,
    gpa: u64,
    hva: *mut u8,
    len: usize,
    prot: libc::c_int,
    backing: NvmmRamBacking,
}

/// The NVMM `X86Vmm`: an `NvmmMachine` plus the VA-keyed host-HVA region table
/// the engine reads/writes guest memory through (NVMM is the N-mapping model —
/// `hva_map` + `gpa_map` per region — not bhyve's single segment).
pub struct NvmmVmm {
    mach: NvmmMachine,
    windows: Vec<WindowRegion>,
    regions: Vec<Region>,
    page_tables: Option<carrick_mem::pml4::Pml4Manager>,
}

impl NvmmVmm {
    /// Find the host pointer for guest-VA `[va, va+len)` within a region.
    fn resolve(&self, va: u64, len: usize) -> Option<*mut u8> {
        resolve_region(&self.regions, va, len)
    }

    fn map_window_chunk(&mut self, chunk: WindowRegion) -> Result<(), TrapError> {
        if chunk.len == 0 || self.resolve(chunk.va, 1).is_some() {
            return Ok(());
        }
        let len = usize::try_from(chunk.len)
            .map_err(|_| TrapError::Hypervisor("nvmm-x86: chunk length overflows usize".into()))?;
        let mut prot = 0;
        if chunk.read {
            prot |= NVMM_PROT_READ;
        }
        if chunk.write {
            prot |= NVMM_PROT_WRITE;
        }
        if chunk.exec {
            prot |= NVMM_PROT_EXEC;
        }
        let backing = if chunk.shared {
            NvmmRamBacking::Shared
        } else {
            NvmmRamBacking::Private
        };
        let hva = self
            .mach
            .map_guest_ram_with_backing(chunk.gpa, len, prot, backing)
            .map_err(map_err)?;
        self.regions.push(Region {
            va: chunk.va,
            gpa: chunk.gpa,
            hva,
            len,
            prot,
            backing,
        });
        if std::env::var_os("CARRICK_TRACE_X86_FAULTS").is_some() {
            eprintln!(
                "[NVMM-X86-MAP] va=0x{:x} gpa=0x{:x} len=0x{:x}",
                chunk.va, chunk.gpa, chunk.len
            );
        }
        Ok(())
    }

    fn map_window_chunk_for_gpa(&mut self, gpa: u64) -> Result<bool, TrapError> {
        let Some(chunk) = sparse_chunk_for_gpa(&self.windows, gpa) else {
            return Ok(false);
        };
        self.map_window_chunk(chunk)?;
        Ok(true)
    }
}

fn resolve_region(regions: &[Region], va: u64, len: usize) -> Option<*mut u8> {
    for r in regions {
        if va >= r.va && va + len as u64 <= r.va + r.len as u64 {
            // SAFETY: bounds proven above; offset stays within the region.
            return Some(unsafe { r.hva.add((va - r.va) as usize) });
        }
    }
    None
}

fn fault_record_hva(regions: &[Region]) -> Result<*mut u8, TrapError> {
    let record_va =
        carrick_x86::fault_slot_gpa(carrick_x86::fault_record_base(NVMM_X86_LAYOUT), 0)?;
    resolve_region(
        regions,
        record_va,
        carrick_x86::X86_FAULT_MEMORY_RECORD_BYTES,
    )
    .ok_or_else(|| {
        TrapError::Hypervisor(format!(
            "nvmm-x86: fault record page va=0x{record_va:x} unmapped"
        ))
    })
}

fn sparse_chunk_for_gpa(windows: &[WindowRegion], gpa: u64) -> Option<WindowRegion> {
    let window = windows
        .iter()
        .copied()
        .find(|r| gpa >= r.gpa && gpa < r.gpa.saturating_add(r.len))?;
    let offset = gpa.checked_sub(window.gpa)?;
    let chunk_offset = (offset / SPARSE_WINDOW_CHUNK_LEN) * SPARSE_WINDOW_CHUNK_LEN;
    let remaining = window.len.checked_sub(chunk_offset)?;
    let len = remaining.min(SPARSE_WINDOW_CHUNK_LEN);
    Some(WindowRegion {
        va: window.va + chunk_offset,
        gpa: window.gpa + chunk_offset,
        len,
        ..window
    })
}

fn compact_region_alignment(region: WindowRegion) -> u64 {
    if region.va.is_multiple_of(X86_1G) && region.len >= X86_1G {
        X86_1G
    } else if region.va.is_multiple_of(X86_2M) && region.len >= X86_2M {
        X86_2M
    } else {
        0x1000
    }
}

impl X86Vmm for NvmmVmm {
    type Vcpu = NvmmX86Vcpu;
    type KickHandle = NvmmKickHandle;
    type SiblingBuilder = ();

    /// Realize the plan as N compact-GPA regions. The plan's `gpa` is the
    /// (already compact) GPA the PML4 maps `va` to; `hva_map`+`gpa_map` backs it
    /// and we record `va → hva` for the engine's by-VA accesses.
    fn setup_memory(&mut self, plan: &WindowPlan) -> Result<(), TrapError> {
        self.windows = plan.regions.clone();
        for r in &plan.regions {
            if let Some(chunk) = sparse_chunk_for_gpa(&[*r], r.gpa) {
                self.map_window_chunk(chunk)?;
            }
        }
        Ok(())
    }

    fn write_gpa(&self, va: u64, bytes: &[u8]) -> Result<(), TrapError> {
        // Called with a guest VA (image region start) or an identity-mapped
        // kernel-window GPA (== its VA). Resolve uniformly by VA.
        let host = self.resolve(va, bytes.len()).ok_or_else(|| {
            TrapError::Hypervisor(format!("nvmm-x86: write_gpa va 0x{va:x} unmapped"))
        })?;
        // SAFETY: resolve proved [host, host+len) is within a live region.
        unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), host, bytes.len()) };
        Ok(())
    }

    fn host_ptr(&self, va: u64, len: usize) -> Option<*mut u8> {
        self.resolve(va, len)
    }

    fn handle_memory_exit(&mut self, gpa: u64) -> Result<bool, TrapError> {
        self.map_window_chunk_for_gpa(gpa)
    }

    fn map_host_alias(
        &mut self,
        va: u64,
        ipa: u64,
        len: u64,
        payload: &[u8],
        file: Option<(libc::c_int, libc::off_t, libc::c_int)>,
    ) -> Result<(), TrapError> {
        use carrick_mem::memory::{LINUX_ALIAS_IPA_BASE, LINUX_ALIAS_IPA_SIZE};

        let aligned_len = len
            .next_multiple_of(0x1000)
            .try_into()
            .map_err(|_| TrapError::Hypervisor("nvmm-x86: alias length overflows usize".into()))?;
        let alias_end = ipa.checked_add(aligned_len as u64).ok_or_else(|| {
            TrapError::Hypervisor(format!("nvmm-x86 alias 0x{ipa:x}+{aligned_len} overflows"))
        })?;
        let alias_limit = LINUX_ALIAS_IPA_BASE + LINUX_ALIAS_IPA_SIZE;
        if ipa < LINUX_ALIAS_IPA_BASE || alias_end > alias_limit {
            return Err(TrapError::Hypervisor(format!(
                "nvmm-x86 map_host_alias: dispatcher IPA 0x{ipa:x}..0x{alias_end:x} \
                 outside alias GPA arena 0x{LINUX_ALIAS_IPA_BASE:x}..0x{alias_limit:x}"
            )));
        }
        let pt_host = self
            .resolve(
                NVMM_X86_LAYOUT.pml4_base,
                carrick_x86::X86_PML4_CAPACITY as usize,
            )
            .ok_or_else(|| TrapError::Hypervisor("nvmm-x86: PML4 backing not mapped".into()))?;
        let (hva, prot, backing, writable) = match file {
            Some((fd, offset, host_prot)) => {
                let h = unsafe {
                    libc::mmap(
                        std::ptr::null_mut(),
                        aligned_len,
                        host_prot,
                        libc::MAP_SHARED,
                        fd,
                        offset,
                    )
                };
                unsafe {
                    libc::close(fd);
                }
                if h == libc::MAP_FAILED {
                    return Err(TrapError::Hypervisor(format!(
                        "nvmm-x86: alias MAP_SHARED file fd={fd} off={offset} size={aligned_len} prot={host_prot} failed"
                    )));
                }
                let mut prot = 0;
                if host_prot & libc::PROT_READ != 0 {
                    prot |= NVMM_PROT_READ;
                }
                if host_prot & libc::PROT_WRITE != 0 {
                    prot |= NVMM_PROT_WRITE;
                }
                if host_prot & libc::PROT_EXEC != 0 {
                    prot |= NVMM_PROT_EXEC;
                }
                (
                    h.cast::<u8>(),
                    prot,
                    NvmmRamBacking::Shared,
                    host_prot & libc::PROT_WRITE != 0,
                )
            }
            None => {
                let prot = NVMM_PROT_READ | NVMM_PROT_WRITE | NVMM_PROT_EXEC;
                let hva = self
                    .mach
                    .map_guest_ram_with_backing(ipa, aligned_len, prot, NvmmRamBacking::Private)
                    .map_err(map_err)?;
                if !payload.is_empty() {
                    let n = payload.len().min(aligned_len);
                    unsafe { std::ptr::copy_nonoverlapping(payload.as_ptr(), hva, n) };
                }
                (hva, prot, NvmmRamBacking::Private, true)
            }
        };
        if file.is_some()
            && let Err(e) = self
                .mach
                .map_existing_host_ram(hva, ipa, aligned_len, prot)
                .map_err(map_err)
        {
            unsafe {
                libc::munmap(hva.cast::<libc::c_void>(), aligned_len);
            }
            return Err(e);
        }
        self.regions.push(Region {
            va,
            gpa: ipa,
            hva,
            len: aligned_len,
            prot,
            backing,
        });
        let page_tables = self
            .page_tables
            .as_mut()
            .ok_or_else(|| TrapError::Hypervisor("nvmm-x86: page tables not initialized".into()))?;
        page_tables
            .map_aliased(va, ipa, len, writable)
            .map_err(|e| TrapError::Hypervisor(format!("nvmm-x86: PML4 map_aliased: {e:?}")))?;
        let bytes = page_tables.bytes();
        unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), pt_host, bytes.len()) };
        Ok(())
    }

    fn add_vcpu(&mut self) -> Result<Self::Vcpu, TrapError> {
        let fault_record_hva = fault_record_hva(&self.regions)?;
        let vcpu = self.mach.create_vcpu(0).map_err(map_err)?;
        NvmmX86Vcpu::new(vcpu, fault_record_hva)
    }

    fn fork_ram_strategy(&self) -> ForkRamStrategy {
        // NVMM vCPU writes land through the hypervisor's registered HVA view,
        // not ordinary host stores that participate cleanly in process COW. The
        // parent can run ahead after host fork and mutate pages before the child
        // rematerializes its machine, so freeze private windows before fork.
        ForkRamStrategy::EagerCopy
    }

    fn freeze_ram(&self) -> Result<Vec<u8>, TrapError> {
        let total = self
            .regions
            .iter()
            .filter(|r| r.backing == NvmmRamBacking::Private)
            .map(|r| r.len)
            .sum();
        let mut frozen = Vec::with_capacity(total);
        for region in &self.regions {
            if region.backing != NvmmRamBacking::Private {
                continue;
            }
            // SAFETY: `region.hva` spans `region.len` bytes for the live
            // private window; the parent vCPU is suspended at the syscall trap.
            let bytes = unsafe { std::slice::from_raw_parts(region.hva, region.len) };
            frozen.extend_from_slice(bytes);
        }
        Ok(frozen)
    }

    fn rebuild_child_after_fork(
        &mut self,
        vcpu: &mut Self::Vcpu,
        frozen: &[u8],
    ) -> Result<(), TrapError> {
        // CHILD side of a guest fork(2). Private windows are rebuilt from the
        // pre-fork frozen buffer; shared file-backed windows are re-registered
        // with the fresh machine. NetBSD's inherited NVMM machine and vCPU
        // kernel objects are not usable from the child. Also, dropping them in
        // the child would destroy the parent's machine, so disarm them before
        // any fallible rebuild work.
        self.mach.disarm_destroy();
        vcpu.disarm_destroy();

        let mut child_mach = NvmmMachine::create().map_err(map_err)?;
        let mut child_regions = Vec::with_capacity(self.regions.len());
        let mut frozen_cursor = 0usize;
        for region in &self.regions {
            let child_hva = match region.backing {
                NvmmRamBacking::Private => {
                    let end = frozen_cursor.checked_add(region.len).ok_or_else(|| {
                        TrapError::Hypervisor("nvmm-x86: frozen RAM cursor overflow".into())
                    })?;
                    let Some(src) = frozen.get(frozen_cursor..end) else {
                        return Err(TrapError::Hypervisor(format!(
                            "nvmm-x86: frozen RAM too short for private region va=0x{:x}",
                            region.va
                        )));
                    };
                    let dst = child_mach
                        .map_guest_ram_with_backing(
                            region.gpa,
                            region.len,
                            region.prot,
                            NvmmRamBacking::Private,
                        )
                        .map_err(map_err)?;
                    // SAFETY: `src` and `dst` both span `region.len`; the
                    // child mapping is fresh and disjoint.
                    unsafe { std::ptr::copy_nonoverlapping(src.as_ptr(), dst, region.len) };
                    frozen_cursor = end;
                    dst
                }
                NvmmRamBacking::Shared => {
                    child_mach
                        .map_existing_host_ram(region.hva, region.gpa, region.len, region.prot)
                        .map_err(map_err)?;
                    region.hva
                }
            };
            child_regions.push(Region {
                va: region.va,
                gpa: region.gpa,
                hva: child_hva,
                len: region.len,
                prot: region.prot,
                backing: region.backing,
            });
        }
        if frozen_cursor != frozen.len() {
            return Err(TrapError::Hypervisor(format!(
                "nvmm-x86: unused frozen RAM bytes: {}",
                frozen.len() - frozen_cursor
            )));
        }
        let fault_record_hva = fault_record_hva(&child_regions)?;
        let child_vcpu = NvmmX86Vcpu::new(
            child_mach.create_vcpu(0).map_err(map_err)?,
            fault_record_hva,
        )?;

        self.mach = child_mach;
        self.regions = child_regions;
        *vcpu = child_vcpu;
        Ok(())
    }

    fn kick_handle(&self) -> Self::KickHandle {
        NvmmKickHandle::for_current_thread()
    }

    fn build_sibling_builder(&self) -> Result<Self::SiblingBuilder, TrapError> {
        // M2: sibling vCPUs on the shared NVMM machine (clone(CLONE_THREAD)).
        Err(TrapError::Hypervisor(
            "nvmm-x86: sibling vCPUs are M2 (not in M1 hello)".into(),
        ))
    }

    fn materialize_sibling(_builder: ()) -> Result<(Self, Self::Vcpu), TrapError> {
        Err(TrapError::Hypervisor(
            "nvmm-x86: sibling vCPUs are M2 (not in M1 hello)".into(),
        ))
    }

    fn set_guest_sp(&self, _vcpu: &Self::Vcpu, _sp: u64) -> Result<(), TrapError> {
        Err(TrapError::Hypervisor(
            "nvmm-x86: set_guest_sp is M2 (vfork; not in M1 hello)".into(),
        ))
    }

    fn fresh_fork_kicker(&self) -> Arc<dyn carrick_hal::VcpuRegistry> {
        Arc::new(NvmmKicker::new())
    }

    fn process_exit_cleanup(&mut self) {
        self.mach.destroy_in_place();
    }

    fn execve_rebuild(
        &mut self,
        vcpu: &mut Self::Vcpu,
        new_image: &AddressSpace,
    ) -> Result<(), TrapError> {
        // Replace the live image (execve). Build the fresh NVMM machine/vCPU
        // first so a bring-up error leaves the old image running, matching Linux
        // execve failure semantics. On success, destroy the old vCPU before the
        // old machine, then publish the fresh machine/regions.
        let (new_vmm, new_vcpu) = bring_up_parts(new_image)?;
        let NvmmVmm {
            mach: new_mach,
            windows: new_windows,
            regions: new_regions,
            page_tables: new_page_tables,
        } = new_vmm;

        *vcpu = new_vcpu;
        let mut old_mach = std::mem::replace(&mut self.mach, new_mach);
        old_mach.destroy_in_place();
        self.windows = new_windows;
        self.regions = new_regions;
        self.page_tables = new_page_tables;
        Ok(())
    }
}

// SAFETY: NvmmVmm holds the libnvmm machine handle + raw HVA pointers valid in
// every thread of the process (threads share the address space). Mirrors the
// KVM/bhyve backends' `Send` over their VM handle.
unsafe impl Send for NvmmVmm {}

// ─── impl X86Vcpu for NvmmX86Vcpu ────────────────────────────────────────────

/// NVMM's x86 vCPU handle plus the HVA of slot-0's memory-backed fault record.
/// The low-level [`NvmmVcpu`] stays a VMM-neutral FFI wrapper; this type carries
/// only the x86 backend state needed to decode NVMM's payload-less IO exits.
pub struct NvmmX86Vcpu {
    inner: NvmmVcpu,
    fault_record_hva: *mut u8,
}

impl NvmmX86Vcpu {
    fn new(mut inner: NvmmVcpu, fault_record_hva: *mut u8) -> Result<Self, TrapError> {
        let mut st = inner.get_state(NVMM_X64_STATE_FPU).map_err(map_err)?;
        st.fpu = Fxsave::default();
        inner.set_state(&st, NVMM_X64_STATE_FPU).map_err(map_err)?;
        Ok(Self {
            inner,
            fault_record_hva,
        })
    }

    fn disarm_destroy(&mut self) {
        self.inner.disarm_destroy();
    }

    fn read_fault_record(&self) -> Result<carrick_x86::FaultDoorbellRecord, TrapError> {
        // SAFETY: `fault_record_hva` points at a live mapped page for this vCPU
        // slot. The guest fault stub writes the packed record before ringing
        // the doorbell, and the vCPU is stopped while we read it.
        let bytes = unsafe {
            std::slice::from_raw_parts(
                self.fault_record_hva,
                carrick_x86::X86_FAULT_MEMORY_RECORD_BYTES,
            )
        };
        carrick_x86::FaultMemoryRecord::from_bytes(bytes)?.to_doorbell_record()
    }
}

/// Pack an `X86Seg` (long-mode `base`/`limit`/packed-`ar`) into an
/// `NvmmX64StateSeg`.
///
/// The shared `carrick_x86::seg_ar` emits the **VMX** access-rights layout
/// (Intel SDM vol.3 §24.4.1): type[0:3], s[4], dpl[5:6], p[7], avl[12], l[13],
/// db[14], g[15]. NVMM's `attrib` is a **contiguous bitfield** (confirmed on-box
/// + grounding doc): type[0:3], s[4], dpl[5:6], p[7], avl[8], l[9], def[10],
/// g[11]. The low byte (type/s/dpl/p) is identical; the high flags move, so we
/// repack avl/l/db(def)/g into NVMM's positions. (Getting this wrong leaves CS
/// without its 64-bit `l` bit → the guest never runs long-mode ring-3 → spin.)
fn seg_to_nvmm(selector: u16, base: u64, limit: u32, ar: u32) -> NvmmX64StateSeg {
    let bit = |n: u32| (ar >> n) & 1;
    let attrib = (ar & 0xFF) as u16            // type/s/dpl/p (identical low byte)
        | (bit(12) << 8) as u16                // AVL: VMX 12 → NVMM 8
        | (bit(13) << 9) as u16                // L  : VMX 13 → NVMM 9
        | (bit(14) << 10) as u16               // D/B (def): VMX 14 → NVMM 10
        | (bit(15) << 11) as u16; // G  : VMX 15 → NVMM 11
    NvmmX64StateSeg {
        selector,
        attrib,
        limit,
        base,
    }
}

/// Where an [`X86Reg`] lives in `NvmmX64State`: a `(sub-area flag, array,
/// index)` tuple. CR0..4 → `crs[]`, EFER → `msrs[]`, everything else → `gprs[]`.
/// The arrays are all `[u64]`, so get/set is one uniform indexed access.
enum RegLoc {
    Cr(usize),
    Efer,
    Gpr(usize),
}

fn reg_loc(reg: X86Reg) -> RegLoc {
    use X86Reg::*;
    match reg {
        Cr0 => RegLoc::Cr(NVMM_X64_CR_CR0),
        Cr2 => RegLoc::Cr(NVMM_X64_CR_CR2),
        Cr3 => RegLoc::Cr(NVMM_X64_CR_CR3),
        Cr4 => RegLoc::Cr(NVMM_X64_CR_CR4),
        Efer => RegLoc::Efer,
        Rax => RegLoc::Gpr(NVMM_X64_GPR_RAX),
        Rbx => RegLoc::Gpr(NVMM_X64_GPR_RBX),
        Rcx => RegLoc::Gpr(NVMM_X64_GPR_RCX),
        Rdx => RegLoc::Gpr(NVMM_X64_GPR_RDX),
        Rsi => RegLoc::Gpr(NVMM_X64_GPR_RSI),
        Rdi => RegLoc::Gpr(NVMM_X64_GPR_RDI),
        Rbp => RegLoc::Gpr(NVMM_X64_GPR_RBP),
        Rsp => RegLoc::Gpr(NVMM_X64_GPR_RSP),
        R8 => RegLoc::Gpr(NVMM_X64_GPR_R8),
        R9 => RegLoc::Gpr(NVMM_X64_GPR_R9),
        R10 => RegLoc::Gpr(NVMM_X64_GPR_R10),
        R11 => RegLoc::Gpr(NVMM_X64_GPR_R11),
        R12 => RegLoc::Gpr(NVMM_X64_GPR_R12),
        R13 => RegLoc::Gpr(NVMM_X64_GPR_R13),
        R14 => RegLoc::Gpr(NVMM_X64_GPR_R14),
        R15 => RegLoc::Gpr(NVMM_X64_GPR_R15),
        Rip => RegLoc::Gpr(NVMM_X64_GPR_RIP),
        Rflags => RegLoc::Gpr(NVMM_X64_GPR_RFLAGS),
    }
}

/// The `NvmmX64State.segs[]` index for an [`X86Seg`].
fn seg_index(seg: X86Seg) -> usize {
    match seg {
        X86Seg::Cs => NVMM_X64_SEG_CS,
        X86Seg::Ds => NVMM_X64_SEG_DS,
        X86Seg::Es => NVMM_X64_SEG_ES,
        X86Seg::Fs => NVMM_X64_SEG_FS,
        X86Seg::Gs => NVMM_X64_SEG_GS,
        X86Seg::Ss => NVMM_X64_SEG_SS,
        X86Seg::Tr => NVMM_X64_SEG_TR,
        X86Seg::Ldtr => NVMM_X64_SEG_LDT,
        X86Seg::Gdtr => NVMM_X64_SEG_GDT,
        X86Seg::Idtr => NVMM_X64_SEG_IDT,
    }
}

impl NvmmVcpu {
    /// Read-modify-write the `segs[idx].base` field (FS/GS base programming).
    fn set_seg_base(&mut self, idx: usize, v: u64) -> Result<(), TrapError> {
        let mut st = self.get_state(NVMM_X64_STATE_SEGS).map_err(map_err)?;
        st.segs[idx].base = v;
        self.set_state(&st, NVMM_X64_STATE_SEGS).map_err(map_err)
    }
}

impl X86Vcpu for NvmmX86Vcpu {
    fn get_gpr(&self, reg: X86Reg) -> Result<u64, TrapError> {
        // get_state is `&self` (FFI-handle pattern). One fetch of all three
        // sub-areas; pick the field per `reg_loc`.
        let st = self
            .inner
            .get_state(NVMM_X64_STATE_CRS | NVMM_X64_STATE_MSRS | NVMM_X64_STATE_GPRS)
            .map_err(map_err)?;
        Ok(match reg_loc(reg) {
            RegLoc::Cr(i) => st.crs[i],
            RegLoc::Efer => st.msrs[NVMM_X64_MSR_EFER],
            RegLoc::Gpr(i) => st.gprs[i],
        })
    }

    fn set_gpr(&mut self, reg: X86Reg, v: u64) -> Result<(), TrapError> {
        // Get-then-set only the touched sub-area (NVMM setstate pushes just the
        // requested flags).
        let flag = match reg_loc(reg) {
            RegLoc::Cr(_) => NVMM_X64_STATE_CRS,
            RegLoc::Efer => NVMM_X64_STATE_MSRS,
            RegLoc::Gpr(_) => NVMM_X64_STATE_GPRS,
        };
        let mut st = self.inner.get_state(flag).map_err(map_err)?;
        match reg_loc(reg) {
            RegLoc::Cr(i) => st.crs[i] = v,
            RegLoc::Efer => st.msrs[NVMM_X64_MSR_EFER] = v,
            RegLoc::Gpr(i) => st.gprs[i] = v,
        }
        self.inner.set_state(&st, flag).map_err(map_err)
    }

    fn set_segment(
        &mut self,
        seg: X86Seg,
        base: u64,
        limit: u32,
        ar: u32,
    ) -> Result<(), TrapError> {
        let mut st = self.inner.get_state(NVMM_X64_STATE_SEGS).map_err(map_err)?;
        // Selector is cosmetic in long mode (hidden base/limit/ar drive it);
        // keep CS=0x23, SS/DS/ES=0x1B self-describing, others 0.
        let sel = match seg {
            X86Seg::Cs => 0x23,
            X86Seg::Ss | X86Seg::Ds | X86Seg::Es => 0x1B,
            _ => 0,
        };
        st.segs[seg_index(seg)] = seg_to_nvmm(sel, base, limit, ar);
        self.inner
            .set_state(&st, NVMM_X64_STATE_SEGS)
            .map_err(map_err)
    }

    fn get_fs_base(&self) -> Result<u64, TrapError> {
        Ok(self
            .inner
            .get_state(NVMM_X64_STATE_SEGS)
            .map_err(map_err)?
            .segs[NVMM_X64_SEG_FS]
            .base)
    }

    fn set_fs_base(&mut self, v: u64) -> Result<(), TrapError> {
        self.inner.set_seg_base(NVMM_X64_SEG_FS, v)
    }

    fn get_gs_base(&self) -> Result<u64, TrapError> {
        Ok(self
            .inner
            .get_state(NVMM_X64_STATE_SEGS)
            .map_err(map_err)?
            .segs[NVMM_X64_SEG_GS]
            .base)
    }

    fn set_gs_base(&mut self, v: u64) -> Result<(), TrapError> {
        self.inner.set_seg_base(NVMM_X64_SEG_GS, v)
    }

    fn set_syscall_msrs(
        &mut self,
        lstar: u64,
        star: u64,
        sfmask: u64,
    ) -> Result<MsrInstall, TrapError> {
        // Direct MSR install: setstate(STATE_MSRS) writes STAR/LSTAR/SFMASK
        // (EFER is set separately). NO ring-0 WRMSR blob.
        let mut st = self.inner.get_state(NVMM_X64_STATE_MSRS).map_err(map_err)?;
        st.msrs[NVMM_X64_MSR_STAR] = star;
        st.msrs[NVMM_X64_MSR_LSTAR] = lstar;
        st.msrs[NVMM_X64_MSR_SFMASK] = sfmask;
        self.inner
            .set_state(&st, NVMM_X64_STATE_MSRS)
            .map_err(map_err)?;
        Ok(MsrInstall::Direct)
    }

    fn get_fp(&self) -> Result<Option<[u8; 512]>, TrapError> {
        // Native FP: getstate(STATE_FPU) ↔ struct fxsave (512 bytes). NO stub.
        let st = self.inner.get_state(NVMM_X64_STATE_FPU).map_err(map_err)?;
        Ok(Some(st.fpu.bytes))
    }

    fn set_fp(&mut self, fx: &[u8; 512]) -> Result<bool, TrapError> {
        let mut st = self.inner.get_state(NVMM_X64_STATE_FPU).map_err(map_err)?;
        st.fpu.bytes = *fx;
        self.inner
            .set_state(&st, NVMM_X64_STATE_FPU)
            .map_err(map_err)?;
        Ok(true)
    }

    fn run(&mut self) -> Result<X86Exit, TrapError> {
        // Bound the consecutive host-internal (NONE) re-entries so a wedged guest
        // surfaces as an error instead of spinning the (nested) host forever.
        let mut spurious = 0u32;
        loop {
            let exit = self.inner.run_until_exit().map_err(map_err)?;
            match exit.reason {
                NVMM_VCPU_EXIT_NONE => {
                    spurious += 1;
                    if spurious > 1_000_000 {
                        return Err(TrapError::Hypervisor(
                            "nvmm-x86: >1e6 consecutive NONE exits (wedged guest?)".into(),
                        ));
                    }
                    continue; // host-internal exit; resume
                }
                NVMM_VCPU_EXIT_MEMORY => {
                    let mem = exit.mem();
                    if std::env::var_os("CARRICK_TRACE_X86_FAULTS").is_some() {
                        eprintln!(
                            "[NVMM-X86-MEM] gpa=0x{:x} prot=0x{:x} inst_len={}",
                            mem.gpa, mem.prot, mem.inst_len
                        );
                    }
                    return Ok(X86Exit::Memory { gpa: mem.gpa });
                }
                NVMM_VCPU_EXIT_IO => {
                    let io = exit.io();
                    if io.port == FAULT_DOORBELL_PORT {
                        let record = self.read_fault_record()?;
                        if std::env::var_os("CARRICK_TRACE_X86_FAULTS").is_some() {
                            eprintln!("[NVMM-X86-FAULT] {record:?}");
                            if let Some(fx) = self.get_fp()? {
                                let fcw = u16::from_le_bytes([fx[0], fx[1]]);
                                let fsw = u16::from_le_bytes([fx[2], fx[3]]);
                                let mxcsr = u32::from_le_bytes([fx[24], fx[25], fx[26], fx[27]]);
                                eprintln!(
                                    "[NVMM-X86-FPU] fcw=0x{fcw:04x} fsw=0x{fsw:04x} mxcsr=0x{mxcsr:08x}"
                                );
                            }
                        }
                        return carrick_x86::fault_exit_from_record(self, record, "nvmm-x86");
                    }
                    if io.port != carrick_hal::SYSCALL_DOORBELL_PORT {
                        return Err(TrapError::Hypervisor(format!(
                            "nvmm-x86: unexpected OUT to port 0x{:04X}",
                            io.port
                        )));
                    }
                    // The IO exit hands back io.npc (the next-PC; the kernel does
                    // NOT advance RIP — proven in M0). Resume there directly.
                    let st = self.inner.get_state(NVMM_X64_STATE_GPRS).map_err(map_err)?;
                    let frame = carrick_guest_mem::X8664SyscallFrame {
                        rax: st.gprs[NVMM_X64_GPR_RAX],
                        rdi: st.gprs[NVMM_X64_GPR_RDI],
                        rsi: st.gprs[NVMM_X64_GPR_RSI],
                        rdx: st.gprs[NVMM_X64_GPR_RDX],
                        r10: st.gprs[NVMM_X64_GPR_R10],
                        r8: st.gprs[NVMM_X64_GPR_R8],
                        r9: st.gprs[NVMM_X64_GPR_R9],
                    };
                    return Ok(X86Exit::Syscall {
                        frame,
                        resume_pc: io.npc,
                    });
                }
                NVMM_VCPU_EXIT_HALTED => return Ok(X86Exit::Halt),
                other => {
                    // Enrich with RIP (and the raw union head) so a long-mode /
                    // ring-3-entry fault is diagnosable (spec risk #2).
                    let rip = self
                        .inner
                        .get_state(NVMM_X64_STATE_GPRS)
                        .map(|s| s.gprs[NVMM_X64_GPR_RIP])
                        .unwrap_or(0);
                    return Err(TrapError::Hypervisor(format!(
                        "nvmm-x86: unexpected exit reason 0x{other:x} at rip=0x{rip:x} \
                         u={:02x?}",
                        exit.u
                    )));
                }
            }
        }
    }

    fn enable_halt_exit(&mut self) -> Result<(), TrapError> {
        // NVMM exits on HLT (NVMM_VCPU_EXIT_HALTED) by default.
        Ok(())
    }
}

/// Where the compact-GPA bump cursor for high VAs starts (512 MiB) — above the
/// kernel window (256 MiB base + its PML4 1.75 MiB capacity) AND above the static
/// image's low load region, so compact runtime GPAs never collide with either.
const COMPACT_GPA_BASE: u64 = 0x2000_0000;

/// Rewrite the shared (identity GPA=VA) [`WindowPlan`] into one with COMPACT
/// GPAs for NVMM: kernel-window regions (trampoline/GDT/PML4, already low) stay
/// identity; every other region (high image/heap/mmap/stack VAs) is reassigned a
/// GPA from a bump cursor so it fits under NVMM's `max_ram` ceiling. The `va`
/// field is preserved, so `build_pml4` maps each guest VA → its compact GPA.
fn compact_plan(plan: &WindowPlan, layout: BringupLayout) -> WindowPlan {
    let mut cursor = COMPACT_GPA_BASE;
    let mut regions = Vec::with_capacity(plan.regions.len());
    for r in &plan.regions {
        let len = r.len.next_multiple_of(0x1000);
        let is_kernel = r.gpa == layout.trampoline_base
            || r.gpa == layout.gdt_base
            || r.gpa == layout.pml4_base;
        let gpa = if is_kernel {
            r.gpa // identity (already compact + low)
        } else {
            let g = cursor.next_multiple_of(compact_region_alignment(*r));
            cursor = g + len;
            g
        };
        regions.push(WindowRegion { gpa, len, ..*r });
    }
    WindowPlan { regions }
}

// ─── bring_up ────────────────────────────────────────────────────────────────

/// Bring up an NVMM x86 guest for `image` and wrap it in the generic
/// [`X86EngineCore`]. Assigns compact GPAs (NVMM's `max_ram` ceiling +
/// abort-on-overflow `gpa_map`), mmap+hva_map+gpa_map's every region, writes the
/// ELF bytes + the trampoline/GDT/PML4 images, creates the vCPU, and programs
/// long mode via the shared [`carrick_x86::program_longmode_entry`].
fn bring_up_parts(image: &AddressSpace) -> Result<(NvmmVmm, NvmmX86Vcpu), TrapError> {
    nvmm::init().map_err(map_err)?;
    let mach = NvmmMachine::create().map_err(map_err)?;
    let mut vmm = NvmmVmm {
        mach,
        windows: Vec::new(),
        regions: Vec::new(),
        page_tables: None,
    };

    // 1. Shared region walk (identity), then remap to compact GPAs + map them.
    let plan = compact_plan(
        &carrick_x86::plan_windows(image, NVMM_X86_LAYOUT)?,
        NVMM_X86_LAYOUT,
    );
    vmm.setup_memory(&plan)?;

    // 2. Copy each ELF/runtime region's bytes into the mapped guest RAM (by VA).
    for region in image.regions() {
        if region.end <= carrick_mem::memory::LINUX_NULL_GUARD_END {
            continue;
        }
        let bytes = region.bytes();
        if !bytes.is_empty() {
            vmm.write_gpa(region.start, bytes)?;
        }
    }

    // 3. Write the bring-up byte images (trampoline + GDT + PML4). The PML4 maps
    //    each guest VA → its compact GPA; CR3 = the (compact, low) pml4_base.
    let pml4_bytes = carrick_x86::build_pml4(&plan, NVMM_X86_LAYOUT)?;
    let page_tables = carrick_mem::pml4::Pml4Manager::new(pml4_bytes, NVMM_X86_LAYOUT.pml4_base);
    carrick_x86::write_bringup_images(&vmm, NVMM_X86_LAYOUT, page_tables.bytes())?;
    vmm.page_tables = Some(page_tables);
    carrick_x86::write_memory_record_fault_tables(&vmm, NVMM_X86_LAYOUT)?;

    // 4. Create the vCPU and program long mode (CR/EFER/segs/GDTR/MSRs).
    let mut vcpu = vmm.add_vcpu()?;
    let rsp = image
        .initial_stack_pointer()
        .unwrap_or(carrick_mem::memory::LINUX_STACK_TOP);
    // NVMM is MsrInstall::Direct — the SYSCALL MSRs are live; no ring-0 blob.
    let _install =
        carrick_x86::program_longmode_entry(&mut vcpu, NVMM_X86_LAYOUT, image.entry(), rsp)?;

    // 5. Ring-3 entry. `program_longmode_entry` programs a DIRECT ring-3 entry
    //    (CS DPL3 + RIP=user entry). NVMM/VT-x will NOT vm-enter directly into a
    //    ring-3 CS via setstate (spec risk #2 — confirmed on VM 201: every state
    //    field is correct, yet the first nvmm_vcpu_run never reaches the doorbell).
    //    So override to enter in ring-0 at a 1-instruction `iretq` stub that pops
    //    a pre-built ring-3 frame — the canonical CPL0→CPL3 transition VT-x always
    //    accepts. (bhyve needed an analogous ring-0 init blob for VT-x reasons.)
    install_iretq_ring3_entry(&vmm, &mut vcpu, image.entry(), rsp)?;

    Ok((vmm, vcpu))
}

pub fn bring_up(image: &AddressSpace) -> Result<X86EngineCore<NvmmVmm>, TrapError> {
    let (vmm, vcpu) = bring_up_parts(image)?;
    Ok(X86EngineCore::from_parts(vmm, vcpu, NVMM_X86_LAYOUT))
}

/// Offsets within the (exec, supervisor) trampoline page reused for the ring-3
/// entry stub: the `iretq` instruction and the 5-qword `iretq` frame. Both are
/// host-written at bring-up (so the page's guest RO/exec perms don't matter), and
/// the guest only fetches the stub + pops the frame.
const IRETQ_STUB_OFF: u64 = 0x100;
const IRETQ_FRAME_OFF: u64 = 0x800;

/// Program a ring-0 → ring-3 `iretq` entry (the spec-risk-#2 fallback). Writes a
/// one-byte-opcode `iretq` stub + a ring-3 `iretq` frame into the trampoline
/// page, then overrides CS=ring-0/RIP=stub/RSP=frame so the first `nvmm_vcpu_run`
/// vm-enters in ring-0 and `iretq`s into the user entry.
fn install_iretq_ring3_entry(
    vmm: &NvmmVmm,
    vcpu: &mut NvmmX86Vcpu,
    user_entry: u64,
    user_rsp: u64,
) -> Result<(), TrapError> {
    let stub_gpa = NVMM_X86_LAYOUT.trampoline_base + IRETQ_STUB_OFF;
    let frame_gpa = NVMM_X86_LAYOUT.trampoline_base + IRETQ_FRAME_OFF;

    // `iretq` = 48 CF. Pops RIP, CS, RFLAGS, RSP, SS (low→high).
    vmm.write_gpa(stub_gpa, &[0x48, 0xCF])?;
    // Ring-3 iretq frame: user CS=0x23 (GDT[4] uCS64), user SS=0x1B
    // (GDT[3] uSS), RFLAGS=0x2 (reserved bit only).
    let mut frame = [0u8; 40];
    frame[0..8].copy_from_slice(&user_entry.to_le_bytes());
    frame[8..16].copy_from_slice(&0x23u64.to_le_bytes());
    frame[16..24].copy_from_slice(&0x2u64.to_le_bytes());
    frame[24..32].copy_from_slice(&user_rsp.to_le_bytes());
    frame[32..40].copy_from_slice(&0x1Bu64.to_le_bytes());
    vmm.write_gpa(frame_gpa, &frame)?;

    // Enter in ring-0: CS=GDT[1] kCS64 sel 0x08 (DPL0, L=1, exec/read, g=1),
    // SS=GDT[2] kSS sel 0x10, at the stub, RSP = the frame. The VMX-packed
    // access-rights (the shared `seg_ar` layout): ring-0 CS64 type=0xB|S|P|L|G,
    // ring-0 SS type=3|S|P|D/B|G. The selector must be the ring-0 (RPL0)
    // selector, so write the segs directly (the generic set_segment hardcodes the
    // ring-3 selectors).
    let cs0_ar = 0xB | (1 << 4) | (1 << 7) | (1 << 13) | (1 << 15);
    let ss0_ar = 0x3 | (1 << 4) | (1 << 7) | (1 << 14) | (1 << 15);
    let mut st = vcpu.inner.get_state(NVMM_X64_STATE_SEGS).map_err(map_err)?;
    st.segs[NVMM_X64_SEG_CS] = seg_to_nvmm(0x08, 0, 0xFFFF_FFFF, cs0_ar);
    st.segs[NVMM_X64_SEG_SS] = seg_to_nvmm(0x10, 0, 0xFFFF_FFFF, ss0_ar);
    vcpu.inner
        .set_state(&st, NVMM_X64_STATE_SEGS)
        .map_err(map_err)?;
    vcpu.set_gpr(X86Reg::Rip, stub_gpa)?;
    vcpu.set_gpr(X86Reg::Rsp, frame_gpa)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use carrick_mem::memory::{LINUX_HEAP_BASE, LINUX_HEAP_SIZE, LINUX_MMAP_BASE, mmap_arena_size};

    #[test]
    fn compact_plan_preserves_full_mmap_arena_length() {
        let plan = WindowPlan {
            regions: vec![WindowRegion {
                va: LINUX_MMAP_BASE,
                gpa: LINUX_MMAP_BASE,
                len: mmap_arena_size(),
                read: true,
                write: true,
                exec: false,
                user: true,
                shared: false,
            }],
        };

        let compact = compact_plan(&plan, NVMM_X86_LAYOUT);
        let region = compact
            .regions
            .iter()
            .find(|region| region.va == LINUX_MMAP_BASE)
            .expect("compacted mmap region");

        assert_eq!(region.gpa % (1 << 30), 0);
        assert_eq!(region.len, mmap_arena_size());
    }

    #[test]
    fn compact_large_windows_stay_within_pml4_table_budget() {
        let plan = WindowPlan {
            regions: vec![
                WindowRegion {
                    va: 0x400000,
                    gpa: 0x400000,
                    len: 0xccc000,
                    read: true,
                    write: false,
                    exec: true,
                    user: true,
                    shared: false,
                },
                WindowRegion {
                    va: LINUX_HEAP_BASE,
                    gpa: LINUX_HEAP_BASE,
                    len: LINUX_HEAP_SIZE,
                    read: true,
                    write: true,
                    exec: false,
                    user: true,
                    shared: false,
                },
                WindowRegion {
                    va: LINUX_MMAP_BASE,
                    gpa: LINUX_MMAP_BASE,
                    len: mmap_arena_size(),
                    read: true,
                    write: true,
                    exec: false,
                    user: true,
                    shared: false,
                },
            ],
        };
        let compact = compact_plan(&plan, NVMM_X86_LAYOUT);

        carrick_x86::build_pml4(&compact, NVMM_X86_LAYOUT)
            .expect("large compact windows should retain large-page mappings");
    }

    #[test]
    fn sparse_chunk_for_gpa_selects_fault_chunk_inside_large_window() {
        let plan = WindowPlan {
            regions: vec![WindowRegion {
                va: LINUX_MMAP_BASE,
                gpa: COMPACT_GPA_BASE,
                len: mmap_arena_size(),
                read: true,
                write: true,
                exec: false,
                user: true,
                shared: false,
            }],
        };
        let fault_offset = 0x4496_0000;
        let chunk = sparse_chunk_for_gpa(&plan.regions, COMPACT_GPA_BASE + fault_offset)
            .expect("fault GPA should resolve to sparse mmap chunk");

        assert_eq!(chunk.gpa, COMPACT_GPA_BASE + 0x4400_0000);
        assert_eq!(chunk.va, LINUX_MMAP_BASE + 0x4400_0000);
        assert_eq!(chunk.len, SPARSE_WINDOW_CHUNK_LEN);
    }
}
