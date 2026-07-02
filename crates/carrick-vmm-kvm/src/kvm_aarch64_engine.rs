//! The KVM aarch64 backend on the shared `carrick-aarch64` scaffold (Stage 2).
//!
//! `KvmAarch64Vmm` (+ `impl Aarch64Vcpu for KvmVcpu`) is the thin per-VMM trait
//! pair the generic [`carrick_aarch64::Aarch64EngineCore`] is parameterized over.
//! It replaces the hand-rolled `KvmTrapEngine`: the trap loop, register walk,
//! guest-memory access, stage-1 page-table edits, snapshot/restore pair, fork
//! sequencing, and the threaded lifecycle all now live ONCE in `carrick-aarch64`;
//! this module supplies only the KVM-specific marshalling.
//!
//! KVM answers the aarch64 quirk seams the same way it does on x86:
//!   - `fork_ram_strategy` → `Cow` (`MAP_PRIVATE` windows inherit via Linux COW —
//!     correct POSIX fork divergence for free; HVF's `MAP_SHARED` windows must
//!     `EagerCopy`).
//!   - `handle_memory_exit` → the default `Ok(false)` (siblings share ONE VM; no
//!     HVF-style lazy high-VA alias re-map).
//!   - `set_hardware_tso`/`set_memory_model` → the no-op defaults (no Rosetta-on-arm
//!     `ACTLR_EL1.EnTSO` on KVM).
//!
//! The trap surface is the MMIO-sentinel vehicle: the EL1 vector's sentinel store
//! faults out as `KVM_EXIT_MMIO { gpa }`, and [`KvmVcpu`]'s `run()` decode maps
//! `gpa == SENTINEL_GPA` → `Syscall`, `FAULT_SENTINEL_GPA` → `EL0Fault`,
//! `MAINT_SENTINEL_GPA` → `MaintenanceDone`, and `KVM_RUN` EINTR → `Kicked`.

use std::sync::{Arc, RwLock};

use carrick_aarch64::{
    Aarch64EngineCore, Aarch64Exit, Aarch64Vcpu, Aarch64VcpuSnapshot, Aarch64Vmm, ForkRamStrategy,
};
use carrick_guest_mem::protections::MemoryProtections;
use carrick_guest_mem::zero_range_chunked;
use carrick_guest_mem::{GuestVa, HostVa, MemoryError};
use carrick_hal::{
    GuestEntryRegs, GuestVmBackend, HvVcpu, HvVm, MemPerms, OsError, Reg, SysReg, TrapError,
    VcpuExit, VcpuRegistry,
};
use carrick_mem::memory::AddressSpace;

use crate::guest_setup::{
    BroughtUp, FAULT_SENTINEL_GPA, GuestRam, MAINT_SENTINEL_GPA, SENTINEL_GPA, WindowDesc,
    bring_up as ram_bring_up, populate_vdso_vvar, program_sysregs,
};
use crate::kvm::{KvmVcpu, KvmVm, SharedVmHandle, VcpuLiveTicket};
use crate::kvm_kicker::{KvmKickHandle, KvmKicker};

/// The public engine type: the KVM aarch64 lane IS `Aarch64EngineCore<KvmAarch64Vmm>`.
/// The thin `KvmTrapEngine` newtype (in `trap_engine.rs`) wraps this so the
/// existing run-elf loop's method set is unchanged.
pub type KvmAarch64Engine = Aarch64EngineCore<KvmAarch64Vmm>;

/// Bring up the guest from a freestanding ELF image and return an engine parked
/// at the EL1 trampoline (the first `next_syscall` runs into EL0). Mirrors the
/// x86 lane's `bring_up` → `X86EngineCore::from_parts`.
pub fn bring_up(image: &AddressSpace) -> Result<KvmAarch64Engine, TrapError> {
    let BroughtUp {
        vm,
        vcpu,
        ram,
        entry: _,
    } = ram_bring_up(image).map_err(|e| TrapError::Hypervisor(e.to_string()))?;
    let vmm = KvmAarch64Vmm { vm, ram };
    Ok(Aarch64EngineCore::from_parts(vmm, vcpu))
}

// ─── impl Aarch64Vcpu for KvmVcpu ────────────────────────────────────────────

/// Gated (CARRICK_MEM_DEBUG) diagnostic for a failed syscall-path guest access:
/// prints the address, length, and the calling thread's window view so a
/// cross-thread translation miss (a stale per-sibling `GuestRam` snapshot) is
/// visible. No-op unless the env var is set, so it never costs the hot path.
fn mem_debug(op: &str, ram: &GuestRam, address: u64, length: usize) {
    if std::env::var_os("CARRICK_MEM_DEBUG").is_some() {
        let tid = unsafe { libc::syscall(libc::SYS_gettid) };
        eprintln!(
            "[MEMDBG tid={tid} {op} FAIL] {}",
            ram.debug_access(address, length)
        );
    }
}

fn os_to_trap(e: OsError) -> TrapError {
    TrapError::Hypervisor(e.to_string())
}

impl Aarch64Vcpu for KvmVcpu {
    fn get_reg(&self, r: Reg) -> Result<u64, TrapError> {
        <Self as HvVcpu>::reg(self, r).map_err(os_to_trap)
    }
    fn set_reg(&mut self, r: Reg, v: u64) -> Result<(), TrapError> {
        <Self as HvVcpu>::set_reg(self, r, v).map_err(os_to_trap)
    }
    fn get_sys_reg(&self, r: SysReg) -> Result<u64, TrapError> {
        KvmVcpu::get_sys_reg(self, r).map_err(os_to_trap)
    }
    fn set_sys_reg(&mut self, r: SysReg, v: u64) -> Result<(), TrapError> {
        <Self as HvVcpu>::set_sys_reg(self, r, v).map_err(os_to_trap)
    }

    fn get_vreg(&self, n: u32) -> Result<u128, TrapError> {
        KvmVcpu::get_vreg(self, n).map_err(os_to_trap)
    }
    fn set_vreg(&mut self, n: u32, v: u128) -> Result<(), TrapError> {
        KvmVcpu::set_vreg(self, n, v).map_err(os_to_trap)
    }
    fn get_fpcr(&self) -> Result<u64, TrapError> {
        KvmVcpu::get_fpcr(self).map(u64::from).map_err(os_to_trap)
    }
    fn set_fpcr(&mut self, v: u64) -> Result<(), TrapError> {
        KvmVcpu::set_fpcr(self, v as u32).map_err(os_to_trap)
    }
    fn get_fpsr(&self) -> Result<u64, TrapError> {
        KvmVcpu::get_fpsr(self).map(u64::from).map_err(os_to_trap)
    }
    fn set_fpsr(&mut self, v: u64) -> Result<(), TrapError> {
        KvmVcpu::set_fpsr(self, v as u32).map_err(os_to_trap)
    }

    fn get_esr_el1(&self) -> Result<u64, TrapError> {
        KvmVcpu::get_esr_el1(self).map_err(os_to_trap)
    }
    fn get_far_el1(&self) -> Result<u64, TrapError> {
        KvmVcpu::get_far_el1(self).map_err(os_to_trap)
    }

    fn snapshot(&self) -> Result<Aarch64VcpuSnapshot, TrapError> {
        KvmVcpu::snapshot(self).map_err(os_to_trap)
    }
    fn restore(&mut self, snap: &Aarch64VcpuSnapshot) -> Result<(), TrapError> {
        KvmVcpu::restore(self, snap).map_err(os_to_trap)
    }

    fn get_saved_x9(&self) -> Result<Option<u64>, TrapError> {
        // The EL1 sentinel vector stashed the guest's live x9 in TPIDR_EL1 (the
        // sentinel store clobbers x9). The shared `complete_syscall` reads it back
        // from here to restore x9 on every syscall return (the Linux aarch64 ABI
        // preserves x1..x30; musl's `__expand_heap` holds its malloc-context
        // pointer in x9 across `brk(2)`). On KVM TPIDR_EL1 is free for this. `Some`
        // ⟹ the vehicle clobbered x9, so `complete_syscall` writes it back.
        KvmVcpu::get_tpidr_el1(self).map(Some).map_err(os_to_trap)
    }

    fn run(&mut self) -> Result<Aarch64Exit, TrapError> {
        // Decode the native KVM trap surface (`VcpuExit`) into the neutral
        // `Aarch64Exit` the shared engine matches on. Lifted from the old
        // `KvmTrapEngine::next_syscall` exit match (byte-identical semantics).
        match <Self as HvVcpu>::run(self).map_err(os_to_trap)? {
            VcpuExit::MmioWrite { gpa, .. } if gpa == SENTINEL_GPA => {
                // The EL0 `svc` re-entered EL1 and hit the sentinel store. The
                // hardware already set ELR_EL1 = (svc addr + 4) on the exception,
                // and the EL1 vector's own `eret` (after the sentinel store)
                // consumes it — so the engine does NOT touch the PC; it just reads
                // the syscall frame. `resume_pc` rides ELR_EL1 for the §2.1 state.
                let frame =
                    carrick_hal::read_aarch64_syscall_frame(|r| <Self as HvVcpu>::reg(self, r))
                        .map_err(os_to_trap)?;
                let resume_pc = <Self as HvVcpu>::reg(self, Reg::ElrEl1).map_err(os_to_trap)?;
                Ok(Aarch64Exit::Syscall { frame, resume_pc })
            }
            VcpuExit::MmioWrite { gpa, .. } if gpa == FAULT_SENTINEL_GPA => {
                // An EL0 SYNCHRONOUS FAULT (data/instruction abort, alignment)
                // vectored into the EL1 sentinel slot, which read ESR.EC, saw it
                // was not an `svc`, and stored to FAULT_SENTINEL_GPA. (A bare EL0
                // abort is NOT a KVM_RUN exit — KVM steers it to the guest's own
                // VBAR_EL1 — so this is the ONLY way it reaches the host.) Capture
                // the still-pristine EL0 fault state (the vector clobbered only x9)
                // and surface EL0Fault; the shared loop's fault path maps ESR.EC ->
                // SIGSEGV/SIGBUS and injects the handler (or terminates).
                // `from_el0_direct = false`: the EL1 vector latched ELR_EL1, and
                // inject_signal redirects ELR_EL1 (the syscall-path mechanism)
                // which the vector's `eret` then consumes — exactly like a syscall
                // return.
                let syndrome = KvmVcpu::get_esr_el1(self).map_err(os_to_trap)?;
                let far = KvmVcpu::get_far_el1(self).map_err(os_to_trap)?;
                let g = |r: Reg| <Self as HvVcpu>::reg(self, r).map_err(os_to_trap);
                Ok(Aarch64Exit::EL0Fault {
                    syndrome,
                    elr: g(Reg::ElrEl1)?,
                    far,
                    x16: g(Reg::X(16))?,
                    x17: g(Reg::X(17))?,
                    x29: g(Reg::X(29))?,
                    x30: g(Reg::X(30))?,
                    sp: g(Reg::Sp)?,
                    from_el0_direct: false,
                })
            }
            VcpuExit::MmioWrite { gpa, .. } if gpa == MAINT_SENTINEL_GPA => {
                // The EL1 stage-1 maintenance trampoline finished its
                // `dsb sy; tlbi vmalle1is; dsb sy; isb` and stored to
                // MAINT_SENTINEL_GPA — the KVM completion vehicle (in place of HVF's
                // `hvc #1`). The shared `run_el1_maintenance` loop matches on this.
                Ok(Aarch64Exit::MaintenanceDone)
            }
            VcpuExit::MmioWrite { gpa, data, len } => {
                let pc = <Self as HvVcpu>::reg(self, Reg::Pc).unwrap_or(0);
                let elr = <Self as HvVcpu>::reg(self, Reg::ElrEl1).unwrap_or(0);
                let g = |n: u32| <Self as HvVcpu>::reg(self, Reg::X(n)).unwrap_or(0);
                Err(TrapError::UnexpectedExit {
                    reason: format!(
                        "MMIO at non-sentinel gpa=0x{gpa:x} data=0x{data:x} len={len} \
                         pc=0x{pc:x} elr=0x{elr:x} x0=0x{:x} x1=0x{:x} x8=0x{:x} sp=0x{:x}",
                        g(0),
                        g(1),
                        g(8),
                        <Self as HvVcpu>::reg(self, Reg::Sp).unwrap_or(0),
                    ),
                })
            }
            // A WFI/halt with no pending syscall.
            VcpuExit::Halt => Ok(Aarch64Exit::Halt),
            VcpuExit::Kicked => Ok(Aarch64Exit::Kicked),
            VcpuExit::Exception { syndrome, far } => Err(TrapError::UnexpectedException {
                syndrome,
                virtual_address: far,
                physical_address: far,
            }),
            // IoOut: the x86-KVM doorbell — never occurs on aarch64 KVM.
            VcpuExit::IoOut { port, .. } => Err(TrapError::UnexpectedExit {
                reason: format!("unexpected IoOut on port=0x{port:04x} (aarch64 KVM path)"),
            }),
        }
    }

    fn kick(&self) -> Result<(), TrapError> {
        <Self as HvVcpu>::kick(self).map_err(os_to_trap)
    }
    // set_hardware_tso / set_memory_model keep the no-op trait defaults: KVM has
    // no Rosetta-on-arm ACTLR_EL1.EnTSO entrypoint.
}

// ─── KvmAarch64Vmm ───────────────────────────────────────────────────────────

/// The KVM aarch64 `Aarch64Vmm`: a `KvmVm` plus the `GuestRam` window table
/// backing it. One per guest process. The shared engine drives memory through
/// the translated-access / page-table hooks and lifecycle through `add_vcpu` /
/// the sibling+fork hooks.
pub struct KvmAarch64Vmm {
    /// The live VM. Held (not `_`-prefixed) because `fork` swaps in a freshly
    /// rebuilt VM on the child side; the field's host-mmap-backed slots must stay
    /// alive for the new vCPU to run.
    vm: KvmVm,
    ram: GuestRam,
}

impl GuestVmBackend for KvmAarch64Vmm {
    fn host_ptr(&self, gpa: u64, len: usize) -> Option<*mut u8> {
        self.ram.host_ptr(gpa, len)
    }

    fn write_gpa(&self, gpa: u64, bytes: &[u8]) -> Result<(), TrapError> {
        let host = self.ram.host_ptr(gpa, bytes.len()).ok_or_else(|| {
            TrapError::Hypervisor(format!("kvm-aarch64: write_gpa 0x{gpa:x} unmapped"))
        })?;
        // SAFETY: host_ptr proved [host, host+len) is within a live window.
        unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), host, bytes.len()) };
        Ok(())
    }

    fn fork_ram_strategy(&self) -> ForkRamStrategy {
        // KVM: MAP_PRIVATE windows inherit via COW; nothing is frozen/copied.
        ForkRamStrategy::Cow
    }

    fn wait_for_vcpu_slot() {
        // NO-OP for KVM: there is no Apple-HVF-style concurrent-vCPU cap (HVF
        // limits ~64 concurrent vCPUs; KVM has no such admission gate), so a
        // sibling never has to wait for a slot before KVM_CREATE_VCPU.
    }
}

impl Aarch64Vmm for KvmAarch64Vmm {
    type Vcpu = KvmVcpu;
    type KickHandle = KvmKickHandle;
    type SiblingBuilder = KvmAarch64SiblingBuilder;

    // ── memory windows + stage-2 ──

    fn map_stage2(
        &mut self,
        ipa: u64,
        host: *mut u8,
        len: u64,
        perms: MemPerms,
    ) -> Result<(), TrapError> {
        self.vm
            .map_memory(ipa, host, len as usize, perms)
            .map_err(os_to_trap)
    }

    // ── guest-memory access (the GuestMemory backing seam) ──

    fn read_gpa(&self, gpa: u64, len: usize) -> Result<Vec<u8>, TrapError> {
        self.ram.read(gpa, len).map_err(os_to_trap)
    }

    fn translated_read(&self, va: u64, ipa: u64, length: usize) -> Result<Vec<u8>, MemoryError> {
        // PROT_NONE was gated on the guest VA in the engine's default
        // `read_bytes`; here we do the IPA-translated single-region lookup so a
        // `repoint_private` overlay / high-VA alias resolves to the page the
        // guest's OWN EL0 accesses hit — NOT the stale shared-aperture backing the
        // VA still covers. Identity VAs: ipa==va (skips the walk). The copy stays
        // glue.
        let host = self
            .ram
            .safe_access_translated_raw(va, ipa, length)
            .map_err(|e| {
                mem_debug("read", &self.ram, ipa, length);
                e.map_to_memory_error(va, length)
            })?;
        let mut out = vec![0u8; length];
        // SAFETY: `safe_access` proved [va, va+length) ⊆ one window, so `host`
        // points at `length` readable bytes of that window's backing.
        unsafe {
            std::ptr::copy_nonoverlapping(host, out.as_mut_ptr(), length);
        }
        Ok(out)
    }

    fn translated_write(&mut self, va: u64, ipa: u64, bytes: &[u8]) -> Result<(), MemoryError> {
        let length = bytes.len();
        // PROT_NONE gated on the guest VA in the engine's default `write_bytes`;
        // backing lookup on the translated IPA (see `translated_read`). For a
        // `repoint_private` overlay the syscall write lands in the PRIVATE overlay
        // backing the guest reads, not the shared aperture.
        let host = self
            .ram
            .safe_access_translated_raw(va, ipa, length)
            .map_err(|e| {
                mem_debug("write", &self.ram, ipa, length);
                e.map_to_memory_error(va, length)
            })?;
        // SAFETY: `safe_access` proved [va, va+length) ⊆ one window, so `host`
        // points at `length` writable bytes of that window's backing.
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), host, length);
        }
        Ok(())
    }

    fn protections(&self) -> Option<&MemoryProtections> {
        // The PROT_NONE set the shared default `read_bytes`/`write_bytes` gate on
        // (keyed on the guest VA). KVM's per-window set lives in `GuestRam`; the
        // engine reads it through here so a sibling thread's `mprotect` is seen.
        Some(self.ram.protections_ref())
    }

    fn set_no_access(&mut self, address: u64, len: usize, no_access: bool) {
        self.ram.set_no_access(address, len, no_access);
    }

    fn zero_backing(&mut self, address: u64, len: usize) -> Result<(), MemoryError> {
        // Streamed in fixed chunks (no `len`-sized temp); `write_gpa` bypasses the
        // writability gate, which scrubbing a reused PROT_NONE / unmapped region needs.
        zero_range_chunked(address, len, |addr, bytes| {
            self.ram
                .write_gpa(addr, bytes)
                .map_err(|_| MemoryError::OutOfBounds {
                    address: addr,
                    length: bytes.len(),
                })
        })
    }

    fn shared_futex_host_addr(&self, guest_addr: GuestVa) -> Option<HostVa> {
        self.ram
            .shared_futex_host_addr(guest_addr.raw(), 4)
            .map(HostVa)
    }

    fn add_alias(
        &mut self,
        va: u64,
        ipa: u64,
        len: u64,
        payload: &[u8],
        file: Option<(libc::c_int, libc::off_t, libc::c_int)>,
    ) -> Result<(u64, bool), TrapError> {
        use crate::guest_setup::{AliasBacking, KVM_ALIAS_GPA_BASE, KVM_ALIAS_GPA_SIZE};
        use carrick_mem::memory::LINUX_HIGH_VA_THRESHOLD;
        // KVM IGNORES the dispatcher's `ipa` (HVF-shaped: a low IPA at 96 GiB that
        // sits INSIDE KVM's single low-window slot, so it can't be a fresh slot).
        let _ = ipa;
        // Derive the alias GPA deterministically from the guest VA, inside the free
        // <1 TiB arena (the 40-bit nested-KVM IPA limit). The dispatcher's alias
        // VAs span [1 TiB, 1 TiB + 64 GiB), so the offset always lands in-arena; a
        // guest-FIXED VA outside that span (e.g. Rosetta amd64 mapping at 128 TiB)
        // is not yet supported on KVM — fail clearly rather than corrupt memory.
        let off = va
            .checked_sub(LINUX_HIGH_VA_THRESHOLD)
            .filter(|&o| o < KVM_ALIAS_GPA_SIZE)
            .ok_or_else(|| {
                TrapError::Hypervisor(format!(
                    "KVM map_host_alias: VA 0x{va:x} outside the alias arena \
                     [1 TiB, 1 TiB+64 GiB) — guest-fixed high-VA / Rosetta unsupported on KVM"
                ))
            })?;
        let gpa = KVM_ALIAS_GPA_BASE + off;
        let writable = match file {
            Some((_, _, prot)) => prot & libc::PROT_WRITE != 0,
            None => true,
        };
        let backing = match file {
            Some((fd, offset, prot)) => AliasBacking::File { fd, offset, prot },
            None => AliasBacking::Anon { payload },
        };
        // mmap the host backing + register a live KVM slot at `gpa`, tracked in
        // GuestRam keyed by `va` (so the syscall read/write path resolves it).
        self.ram
            .add_alias(&mut self.vm, va, gpa, len, backing)
            .map_err(os_to_trap)?;
        Ok((gpa, writable))
    }

    // ── vCPU lifecycle ──

    fn add_vcpu(&mut self) -> Result<Self::Vcpu, TrapError> {
        self.vm.add_vcpu().map_err(os_to_trap)
    }

    fn rebuild_child_after_fork(
        &mut self,
        vcpu: &mut Self::Vcpu,
        snapshot: &Aarch64VcpuSnapshot,
        saved_x9: u64,
    ) -> Result<(), TrapError> {
        // Approach A — lean on Linux COW. KVM's VM/vCPU fds are per-process and are
        // NOT usefully inherited across `libc::fork`, so the CHILD rebuilds a
        // brand-new KvmVm over the COW-inherited host mmaps while the PARENT keeps
        // its live VM. Because the guest RAM windows are MAP_PRIVATE|MAP_ANONYMOUS
        // (except the MAP_SHARED aperture), Linux COW gives correct POSIX fork
        // divergence for free — no `mincore` snapshot and no per-region clone
        // (unlike HVF, whose RAM is MAP_SHARED).
        let (new_vm, mut new_vcpu) = self.ram.rebuild_vm_for_child().map_err(os_to_trap)?;

        // Restore the parent's register file onto the child's fresh vCPU, then set
        // x0 = 0 (the child's fork(2) return value). The child resumes inside the
        // same trapped clone/fork syscall, just like the parent.
        KvmVcpu::restore(&mut new_vcpu, snapshot).map_err(os_to_trap)?;
        // Disambiguate `set_reg`: `KvmVcpu` now has both `HvVcpu::set_reg` and the
        // new `Aarch64Vcpu::set_reg` in scope. Use the native `HvVcpu` path (these
        // are KVM-internal register writes during the child rebuild).
        HvVcpu::set_reg(&mut new_vcpu, Reg::X(0), 0).map_err(os_to_trap)?;
        // Restore the child's real x9. The snapshot captured the vector-clobbered
        // SENTINEL_GPA (the EL1 vector stashed the real x9 in TPIDR_EL1, which the
        // snapshot does not carry). The Linux syscall ABI preserves x1..x30 across
        // the clone/fork svc, so the child must resume with the parent's pre-svc x9.
        // The child resumes straight at the eret and never runs `complete_syscall`
        // (which is what restores x9 in the parent on syscall return), so without
        // this it would resume holding x9 = SENTINEL_GPA and fault on a `str
        // x10,[x9,#920]` (musl's `brk`-via-`__expand_heap`).
        HvVcpu::set_reg(&mut new_vcpu, Reg::X(9), saved_x9).map_err(os_to_trap)?;

        // CRITICAL: advance the child PC past the EL1 vector's sentinel store.
        //
        // At the trap, the vCPU is suspended ON the `str x8,[x9]` sentinel store
        // (snapshot.pc points AT it). On the PARENT's ORIGINAL vCPU, KVM remembers the
        // MMIO is being completed and auto-advances PC by 4 on the next KVM_RUN, so
        // it resumes at the vector's `eret`. The CHILD's vCPU is BRAND-NEW with no
        // pending-MMIO state, so a plain restore would RE-EXECUTE the sentinel store
        // → another MMIO exit → re-trap the SAME (clone) frame → fork bomb. We
        // replicate KVM's post-MMIO advance ourselves: PC = snapshot.pc + 4 lands on
        // the vector's `eret`, which loads PC←ELR_EL1 (= the guest svc+4) and
        // PSTATE←SPSR_EL1 (= EL0t), dropping the child back into EL0 just past its
        // clone — exactly where the parent resumes.
        const SENTINEL_STR_WIDTH: u64 = 4; // one A64 instruction (the sentinel `str x8,[x9]`)
        HvVcpu::set_reg(
            &mut new_vcpu,
            Reg::Pc,
            snapshot.pc.wrapping_add(SENTINEL_STR_WIDTH),
        )
        .map_err(os_to_trap)?;

        // Swap the rebuilt VM/vCPU in. The old (inherited, now-useless) KvmVm/
        // KvmVcpu drop here, closing their stale fds. `ram` is unchanged — the host
        // mmaps it tracks are exactly the COW-inherited pages the new slots point at.
        self.vm = new_vm;
        *vcpu = new_vcpu;
        // The child inherited the PARENT's VCPU_LIVE value (plain static, copied by
        // libc::fork) — including siblings' vCPUs that do NOT exist in this process
        // (fork replicates only the calling thread, and the KVM fork quiesce parks
        // siblings WITHOUT releasing their vCPUs). The child owns exactly ONE vCPU.
        // Re-stamp the truth, or a child that later goes multithreaded and execve's
        // would wait on phantom siblings in `terminate_siblings_for_exec` and ride
        // out the bounded timeout on every exec.
        crate::kvm::VCPU_LIVE.store(1, std::sync::atomic::Ordering::SeqCst);
        // Re-calibrate the vDSO clock against the CHILD's counter: the child runs on
        // a brand-new KvmVm, so its guest counter basis differs from the parent's,
        // and the COW-inherited vvar's realtime_off no longer matches. (CNTKCTL is
        // set on the child's vCPU via the shared add_vcpu create path.)
        let _ = populate_vdso_vvar(vcpu, &mut self.ram);
        Ok(())
    }

    fn execve_rebuild(
        &mut self,
        vcpu: &mut Self::Vcpu,
        new_image: &AddressSpace,
    ) -> Result<(), TrapError> {
        // In-place image replacement on the LIVE VM (no teardown, unlike HVF which
        // rebuilds the VM). Mirrors the HVF structure: build the new layout up
        // front, remap the slots, reprogram the registers.
        //
        // 1. Build the new image's guest RAM (fresh host mmaps + image segments +
        //    the EL0 trampoline / stage-1 identity tables / EL1 sentinel vector)
        //    FIRST, so any image/window error surfaces BEFORE we tear down the live
        //    slots (Linux execve semantics: on failure the caller keeps running its
        //    old image). `build_for_image` refuses any window that would back the
        //    unmapped SENTINEL_GPA, so the sentinel hole stays a stage-2 MMIO fault.
        let new_ram = GuestRam::build_for_image(new_image).map_err(os_to_trap)?;

        // 2. Unregister EVERY currently-registered KVM memory slot on the LIVE VM
        //    (`KVM_SET_USER_MEMORY_REGION` with memory_size = 0). Slot ids are dense
        //    from 0 (the shared allocator never recycles and failures are fatal), so
        //    `0..slot_count()` is the complete live set — including any alias slot a
        //    SIBLING thread registered post-spawn, which this engine's
        //    `ram.window_count()` would UNDERCOUNT (the sibling's window lives only
        //    in its own GuestRam view). Linux execve destroys all threads' mappings;
        //    a stale alias slot would collide with a re-issued id after the counter
        //    resets below.
        let old_slot_count = self.vm.slot_count();
        for slot in 0..old_slot_count {
            self.vm.unmap_memory_slot(slot).map_err(os_to_trap)?;
        }
        // Reset the slot allocator so the new windows re-register from slot 0 (same
        // ids/order a fresh VM would use), then publish them on the LIVE VM. The
        // SENTINEL_GPA hole stays unmapped.
        self.vm.reset_slot_counter();
        for (base, host, len) in new_ram.windows_for_kvm() {
            self.vm
                .map_memory(base, host, len, MemPerms::ReadWriteExec)
                .map_err(os_to_trap)?;
        }

        // 3. Swap in the new RAM. The OLD GuestRam drops here, `munmap`ing its host
        //    windows — safe because their KVM slots were just deleted, so no live
        //    vCPU references them. `no_access` is dropped with it: execve replaces
        //    the address space, so any prior PROT_NONE ranges are gone.
        self.ram = new_ram;

        // 4. Reprogram the system + core registers for the new image (MAIR=0xFF,
        //    TCR bootstrap, TTBR0/1 = LINUX_PAGE_TABLES_BASE, SCTLR, CPACR,
        //    VBAR = LINUX_EL1_VECTORS_BASE, TPIDR_EL0 = 0, PSTATE/SPSR/ELR/PC + SP
        //    from the new image's entry/initial stack). Reuses the SAME builder
        //    bring-up uses, so the sysreg values cannot drift between the two paths.
        program_sysregs(vcpu, new_image).map_err(os_to_trap)?;
        // Re-calibrate the vDSO clock for the new image's vvar (same vCPU, so
        // CNTKCTL is still set; best-effort like bring_up).
        let _ = populate_vdso_vvar(vcpu, &mut self.ram);

        // 5. Zero x0..x30. Linux's execve contract starts the new program with all
        //    GPRs clear (except SP/PC, set by `program_sysregs`). Without this the
        //    new image's _start inherits the old image's x8, which can decode as a
        //    bogus syscall number on its first `svc`. (`program_sysregs`
        //    deliberately leaves the GPRs to us — it sets only SP/PC/PSTATE.)
        for n in 0..=30u32 {
            HvVcpu::set_reg(vcpu, Reg::X(n), 0).map_err(os_to_trap)?;
        }
        Ok(())
    }

    // ── threaded sibling lifecycle ──

    fn kick_handle(&self) -> Self::KickHandle {
        // Built on (and returning) the CURRENT vCPU thread's pthread id, so a
        // cross-thread `pthread_kill(tid, SIGRTMIN)` forces this vCPU out of
        // KVM_RUN. (The shared loop calls this on the owning vCPU thread.)
        KvmKickHandle::for_current_thread()
    }

    fn save_guest_state(
        &mut self,
        _vcpu: &mut Self::Vcpu,
    ) -> Result<Aarch64VcpuSnapshot, TrapError> {
        // KVM aarch64 does NOT reclaim (`reclaims()` is the default `false`), so
        // the M:N save/rebind round-trip is never exercised on this path. Surface a
        // clear error rather than silently corrupting state if it ever is.
        Err(TrapError::Hypervisor(
            "kvm-aarch64: save_guest_state called but this backend does not reclaim".into(),
        ))
    }

    fn build_sibling_builder(
        &self,
        // KVM's sibling shares the parent VM (Arc handle) + window descriptors, so it
        // needs neither the parent vCPU (it does not snapshot here — the engine seeds
        // the neutral snapshot) nor the `clone` deltas. Both ignored.
        _vcpu: &Self::Vcpu,
        _entry: GuestEntryRegs,
    ) -> Result<Self::SiblingBuilder, TrapError> {
        // Snapshot the parent vCPU is the engine's job (it owns the vcpu); here we
        // only need the SAME VM (Arc<VmFd>) + the parent's window descriptors so the
        // sibling vCPU runs in the SAME address space on the SAME VM. The engine
        // seeds the snapshot for the new thread and carries it in its own
        // `Aarch64SiblingSpec`.
        Ok(KvmAarch64SiblingBuilder {
            vm: self.vm.vm_handle(),
            windows: self.ram.window_descriptors(),
            protections: self.ram.shared_protections(),
            // Reserve the sibling's VCPU_LIVE slot NOW — this runs while the parent
            // is suspended at the trapped clone, BEFORE the guest can race ahead
            // into execve, closing the materialization blind window (9/60
            // multithreaded-execv iterations EFAULT'd without it).
            ticket: VcpuLiveTicket::acquire(),
        })
    }

    fn materialize_sibling(builder: Self::SiblingBuilder) -> Result<(Self, Self::Vcpu), TrapError> {
        // Create a NEW vCPU on the SAME VM (siblings share all slots — no
        // re-registration, unlike the fork child which rebuilds a fresh VM).
        let vm = KvmVm::from_shared_vm(builder.vm);
        let vcpu = vm.add_sibling_vcpu().map_err(os_to_trap)?;
        // The vcpu now exists: transfer the spec's reserved VCPU_LIVE slot to it
        // (KvmVcpu::drop owns the decrement from here on). Consume BEFORE the
        // engine's (fallible) restore — if restore fails, the dropped vcpu does the
        // single decrement; consuming later would double-count the error path
        // (ticket Drop + vcpu Drop).
        builder.ticket.consume();
        // A NON-OWNING view over the parent's host windows: the sibling reads/writes
        // syscall buffers through the SAME backing but NEVER munmaps it (the owning
        // parent frees it at process exit). It SHARES the parent's PROT_NONE
        // bookkeeping so cross-thread mprotect is coherent.
        let ram = GuestRam::from_shared_windows(builder.windows, Arc::clone(&builder.protections));
        Ok((Self { vm, ram }, vcpu))
    }

    fn set_guest_sp(&self, vcpu: &Self::Vcpu, sp: u64) -> Result<(), TrapError> {
        // SP_EL0 is `Reg::Sp` (the EL0/user stack), NOT a sysreg. `&self` write via
        // the shared (`&self`) KVM_SET_ONE_REG path.
        vcpu.set_reg_shared(Reg::Sp, sp).map_err(os_to_trap)
    }

    fn fresh_fork_kicker(&self) -> Arc<dyn VcpuRegistry> {
        // CHILD side of a guest fork: libc::fork replicated only the calling thread,
        // so the child drops the parent's kicker and starts over with an empty one
        // (no phantom siblings). The child rebuilds its private-futex backend via
        // the PlatformFutexFactory in the run loop.
        Arc::new(KvmKicker::new())
    }

    // process_exit_cleanup / handle_memory_exit / rebind_to_slot keep their trait
    // defaults: KVM's RAM is released by the OS on `_exit`, siblings share one VM
    // (no lazy-alias re-map), and this backend does not reclaim.
}

/// The `Send` payload `build_sibling_builder` hands to a freshly spawned host
/// thread, which `materialize_sibling` turns into a sibling `(VM, vCPU)` pair on
/// the SAME VM. It carries a SHARED handle to the parent's VM (`Arc<VmFd>`) plus
/// the parent's window descriptors so the new vCPU runs in the SAME guest address
/// space on the SAME VM. Unlike the `fork` child, NO new VM is built and NO memory
/// is re-registered — the sibling shares every slot by construction. The seeded
/// register snapshot lives in the engine's `Aarch64SiblingSpec`, NOT here.
pub struct KvmAarch64SiblingBuilder {
    /// Shared handle to the SAME VM the parent runs on — the `VmFd` AND the shared
    /// vcpu-id allocator, so the sibling's `KVM_CREATE_VCPU` draws a UNIQUE id (1,
    /// 2, 3, …) instead of colliding with the main vCPU's id 0.
    vm: SharedVmHandle,
    /// `Send`-safe descriptors of the parent's host windows (raw `*mut u8` carried
    /// as `usize`; same VA in the sibling thread — no fork). The sibling builds a
    /// NON-OWNING `GuestRam` view over these.
    windows: Arc<RwLock<Vec<WindowDesc>>>,
    /// The parent's PROT_NONE bookkeeping, SHARED (Arc clone) so the sibling's
    /// syscall-path access checks observe the parent's (and every sibling's)
    /// `mprotect(PROT_NONE)`. Carried into the sibling's `GuestRam`.
    protections: Arc<MemoryProtections>,
    /// The sibling's reserved `VCPU_LIVE` slot, acquired HERE (synchronously with
    /// the trapped clone) so the execve drain can see the sibling before its host
    /// thread constructs a vCPU. Consumed at materialization; dropped-unmaterialized
    /// releases it.
    ticket: VcpuLiveTicket,
}

// SAFETY: the builder carries the shared `VmFd` handle (Send + Sync), the
// `Send`-safe window descriptors (raw pointers as usize, valid in every thread),
// the `Arc<MemoryProtections>` (Send + Sync), and the VCPU_LIVE ticket. Moving it
// to the spawned sibling thread is sound. Mirrors `unsafe impl Send for
// KvmSiblingSpec`.
unsafe impl Send for KvmAarch64SiblingBuilder {}
