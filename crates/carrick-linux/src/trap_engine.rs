//! KvmTrapEngine: drives a `KvmVcpu` to implement the `carrick-hal`
//! `SyscallTrap` contract. `next_syscall` runs KVM_RUN until the EL1 vector's
//! sentinel store surfaces as `VcpuExit::MmioWrite { gpa: SENTINEL_GPA, .. }`,
//! reads x0..x5,x8 into an `Aarch64SyscallFrame`, and returns it.
use carrick_abi::LinuxSiginfo;
use carrick_guest_mem::{Aarch64SyscallFrame, GuestMemory, MemoryError};
use carrick_hal::{ForkOutcome, HvVcpu, HvVm, MemPerms, Reg, SyscallTrap, TrapError, VcpuExit};
use carrick_mem::memory::AddressSpace;

use crate::guest_setup::{BroughtUp, GuestRam, SENTINEL_GPA, bring_up, program_sysregs};
use crate::kvm::{KvmVcpu, KvmVm};

pub struct KvmTrapEngine {
    /// The live VM. Held (not `_`-prefixed) because `fork` swaps in a freshly
    /// rebuilt VM on the child side; the field's host-mmap-backed slots must
    /// stay alive for the new vCPU to run.
    vm: KvmVm,
    vcpu: KvmVcpu,
    ram: GuestRam,
    /// Set `true` on the child side of a guest `fork(2)`. Preserved across a
    /// later `execve` (Task 4) so exit-reporting can distinguish a forked child;
    /// mirrors the HVF backend's `is_forked_child`. Default `false`.
    is_forked_child: bool,
}

impl KvmTrapEngine {
    /// Bring up the guest from a freestanding ELF image and return an engine
    /// parked at the EL1 trampoline (first `next_syscall` runs into EL0).
    pub fn new(image: &AddressSpace) -> Result<Self, TrapError> {
        let BroughtUp {
            vm,
            vcpu,
            ram,
            entry: _,
        } = bring_up(image).map_err(|e| TrapError::Hypervisor(e.to_string()))?;
        Ok(Self {
            vm,
            vcpu,
            ram,
            is_forked_child: false,
        })
    }

    /// Read `len` bytes of live guest memory at guest-physical `gpa` (e.g. a
    /// `write(2)` buffer the guest passed). Backed by the same host RAM the
    /// vCPU sees, so guest writes are visible.
    pub fn read_guest(&self, gpa: u64, len: usize) -> Result<Vec<u8>, TrapError> {
        self.ram
            .read(gpa, len)
            .map_err(|e| TrapError::Hypervisor(e.to_string()))
    }
}

// NOTE: KvmTrapEngine implements the `carrick-hal` SyscallTrap contract; the
// MVP drives it from `crate::run_elf`, reading the trapped write(2) buffer out
// of the live guest RAM via `read_guest`. Pairing it with the full
// carrick-runtime dispatcher (SplitView @ runtime.rs:3701) is the full-Linux-
// backend spec's job — that path needs ~200 macOS-isms ported off the dispatch
// layer first (see run_elf.rs).

/// `GuestMemory` over the KVM guest RAM. The guest is **identity-mapped** (the
/// stage-1 tables map VA == IPA, and the single KVM memory slot maps IPA == GPA
/// at host-mmap offset), so a syscall's guest *virtual* pointer is numerically
/// the same as its guest-physical address and indexes straight into the host
/// backing. The real dispatcher reads/writes its syscall buffers through this.
///
/// `read_bytes`/`write_bytes` move syscall buffers; `set_no_access`/
/// `zero_backing` implement the HOST-SIDE PROT_NONE check (a bad syscall
/// buffer faults with EFAULT). The trait's default no-op bodies stand for the
/// GUEST-fault methods (`protect_range`/`unmap_range`/`unmap_alias_range`/
/// `repoint_private`) and the zero-copy / `shared_futex_host_addr` hooks
/// (`None`): making the guest's own EL0 access fault needs stage-1 edits + a
/// SIGSEGV the engine can't yet inject (Phase D).
impl GuestMemory for KvmTrapEngine {
    fn read_bytes(&self, address: u64, length: usize) -> Result<Vec<u8>, MemoryError> {
        // A syscall buffer overlapping a PROT_NONE range faults with EFAULT,
        // even though the host backing is accessible (C2 host-side check).
        if self.ram.range_no_access(address, length) {
            return Err(MemoryError::OutOfBounds { address, length });
        }
        self.ram
            .read(address, length)
            .map_err(|_| MemoryError::OutOfBounds { address, length })
    }

    fn write_bytes(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
        if self.ram.range_no_access(address, bytes.len()) {
            return Err(MemoryError::OutOfBounds {
                address,
                length: bytes.len(),
            });
        }
        self.ram
            .write_gpa(address, bytes)
            .map_err(|_| MemoryError::OutOfBounds {
                address,
                length: bytes.len(),
            })
    }

    /// Record/clear a PROT_NONE range so syscall buffers there fault (EFAULT).
    /// HOST-SIDE only — the guest's own EL0 accesses still hit the accessible
    /// backing (making those fault needs stage-1 edits + signal injection,
    /// Phase D), so `protect_range`/`unmap_range` keep their no-op defaults.
    fn set_no_access(&mut self, address: u64, len: usize, no_access: bool) {
        self.ram.set_no_access(address, len, no_access);
    }

    /// Scrub the physical backing of `[address, address+len)`, BYPASSING the
    /// PROT_NONE check — used to clear a reused/`munmap`'d region whose stale
    /// bytes must never resurface after a later `mprotect` makes it readable.
    fn zero_backing(&mut self, address: u64, len: usize) -> Result<(), MemoryError> {
        let zeros = vec![0u8; len];
        self.ram
            .write_gpa(address, &zeros)
            .map_err(|_| MemoryError::OutOfBounds {
                address,
                length: len,
            })
    }
}

impl SyscallTrap for KvmTrapEngine {
    fn next_syscall(&mut self) -> Result<Option<Aarch64SyscallFrame>, TrapError> {
        // One KVM_RUN per call; the outer run loop calls `next_syscall`
        // repeatedly. Classify the exit and return.
        match self
            .vcpu
            .run()
            .map_err(|e| TrapError::Hypervisor(e.to_string()))?
        {
            VcpuExit::MmioWrite { gpa, .. } if gpa == SENTINEL_GPA => {
                // The EL0 `svc` re-entered EL1 and hit the sentinel store.
                // The hardware already set ELR_EL1 = (svc addr + 4) on the
                // exception, and the EL1 vector's own `eret` (after the
                // sentinel store) consumes it — so we do NOT touch the PC
                // here; we just read the syscall frame.
                Ok(Some(self.read_frame()?))
            }
            VcpuExit::MmioWrite { gpa, data, len } => Err(TrapError::UnexpectedExit {
                reason: format!("MMIO at non-sentinel gpa=0x{gpa:x} data=0x{data:x} len={len}"),
            }),
            // A bare kick or halt with no pending syscall: the contract is to
            // return `None` so the run loop can run signal delivery and resume.
            VcpuExit::Halt | VcpuExit::Kicked => Ok(None),
            VcpuExit::Exception { syndrome, far } => Err(TrapError::UnexpectedException {
                syndrome,
                virtual_address: far,
                physical_address: far,
            }),
        }
    }

    fn current_pc(&self) -> Result<u64, TrapError> {
        self.vcpu
            .reg(Reg::Pc)
            .map_err(|e| TrapError::Hypervisor(e.to_string()))
    }

    fn complete_syscall(&mut self, return_value: i64) -> Result<(), TrapError> {
        // Write the syscall result into x0. The guest resume PC is already
        // correct: ELR_EL1 (= svc+4) was latched by the exception and is
        // restored by the EL1 vector's `eret`. We must NOT advance it again,
        // or the instruction after the `svc` would be skipped.
        self.vcpu
            .set_reg(Reg::X(0), return_value as u64)
            .map_err(|e| TrapError::Hypervisor(e.to_string()))
    }

    fn fork(&mut self) -> Result<ForkOutcome, TrapError> {
        // Approach A — lean on Linux COW. KVM's VM/vCPU fds are per-process and
        // are NOT usefully inherited across `libc::fork` (the inherited fds point
        // at the parent's kernel VM), so the CHILD rebuilds a brand-new KvmVm
        // over the COW-inherited host mmaps while the PARENT keeps its live VM.
        //
        // Because the guest RAM windows are MAP_PRIVATE|MAP_ANONYMOUS (except the
        // MAP_SHARED aperture), Linux COW gives correct POSIX fork divergence for
        // free — no `mincore` snapshot and no per-region clone (unlike HVF, whose
        // RAM is MAP_SHARED). The HVF-only lifecycle hooks
        // (publish_vm_for_siblings / rebuild_vcpu_after_fork /
        // release_vcpu_for_fork) stay default no-ops on KVM.

        // 1. Snapshot the parent vCPU register file BEFORE forking, so both sides
        //    resume inside the same trapped syscall site. (Taken while the vCPU is
        //    suspended at the syscall trap — atomic, race-free.)
        let snap = self
            .vcpu
            .snapshot()
            .map_err(|e| TrapError::Hypervisor(e.to_string()))?;

        // 2. Real host fork.
        //
        // SAFETY: the carrick-linux thin-shim run loop spawns no threads, so the
        // process is SINGLE-THREADED at this point.  That is the load-bearing
        // invariant: because no other thread exists, no other thread can be
        // holding the malloc lock (or any other process-global lock) at fork
        // time, so the child inherits a consistent allocator state and may
        // safely allocate during `rebuild_vm_for_child`.
        //
        // NOTE (Task 7): the threaded-capstone run loop breaks this invariant —
        // when `KvmForkCoordinator::fork_from_threaded_context` is implemented,
        // this path will need re-examination (quiesce-all-threads protocol or
        // async-signal-safe-only child path).
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            return Err(TrapError::ForkFailed(
                std::io::Error::last_os_error().to_string(),
            ));
        }

        if pid > 0 {
            // 3. PARENT: the live VM is untouched (its KVM fds are still valid;
            //    its private RAM is unchanged by the child's COW writes). Return
            //    the child pid so the runtime writes it into the guest's x0.
            return Ok(ForkOutcome::Parent { child_pid: pid });
        }

        // 4. CHILD: build a brand-new KvmVm over the COW-inherited host mmaps:
        //    open /dev/kvm -> KVM_CREATE_VM -> re-register every window in the
        //    SAME order/GPA/slot id (the SENTINEL_GPA hole stays unmapped) ->
        //    KVM_CREATE_VCPU. PRIVATE windows are the Linux-COW copies; the
        //    MAP_SHARED aperture re-registers the SAME inherited host pages.
        let (new_vm, mut new_vcpu) = self
            .ram
            .rebuild_vm_for_child()
            .map_err(|e| TrapError::Hypervisor(e.to_string()))?;

        // Restore the parent's register file onto the child's fresh vCPU, then
        // set x0 = 0 (the child's fork(2) return value). The child resumes inside
        // the same trapped clone/fork syscall, just like the parent.
        new_vcpu
            .restore(&snap)
            .map_err(|e| TrapError::Hypervisor(e.to_string()))?;
        new_vcpu
            .set_reg(Reg::X(0), 0)
            .map_err(|e| TrapError::Hypervisor(e.to_string()))?;

        // CRITICAL: advance the child PC past the EL1 vector's sentinel store.
        //
        // At the trap, the vCPU is suspended ON the `str x8,[x9]` sentinel store
        // (snap.pc points AT it). On the PARENT's ORIGINAL vCPU, KVM remembers the
        // MMIO is being completed and auto-advances PC by 4 on the next KVM_RUN,
        // so it resumes at the vector's `eret`. The CHILD's vCPU is BRAND-NEW with
        // no pending-MMIO state, so a plain restore would RE-EXECUTE the sentinel
        // store → another MMIO exit → re-trap the SAME (clone) frame → fork bomb.
        // We replicate KVM's post-MMIO advance ourselves: PC = snap.pc + 4 lands
        // on the vector's `eret`, which loads PC←ELR_EL1 (= the guest svc+4) and
        // PSTATE←SPSR_EL1 (= EL0t), dropping the child back into EL0 just past its
        // clone — exactly where the parent resumes.
        const SENTINEL_STR_WIDTH: u64 = 4; // one A64 instruction (the sentinel `str x8,[x9]`)
        new_vcpu
            .set_reg(Reg::Pc, snap.pc.wrapping_add(SENTINEL_STR_WIDTH))
            .map_err(|e| TrapError::Hypervisor(e.to_string()))?;

        // Swap the rebuilt VM/vCPU into `self`. The old (inherited, now-useless)
        // KvmVm/KvmVcpu drop here, closing their stale fds. `ram` is unchanged —
        // the host mmaps it tracks are exactly the COW-inherited pages the new
        // slots point at.
        self.vm = new_vm;
        self.vcpu = new_vcpu;
        self.is_forked_child = true;
        Ok(ForkOutcome::Child)
    }

    fn is_forked_child(&self) -> bool {
        self.is_forked_child
    }

    fn execve_into(&mut self, new_image: &AddressSpace) -> Result<(), TrapError> {
        // In-place image replacement on the LIVE VM (no teardown, unlike HVF
        // which rebuilds the VM). Mirrors the HVF structure
        // (carrick-hvf/src/trap.rs:3764-3913): build the new layout up front,
        // remap the slots, reprogram the registers, preserve is_forked_child.
        //
        // 1. Build the new image's guest RAM (fresh host mmaps + image segments +
        //    the EL0 trampoline / stage-1 identity tables / EL1 sentinel vector)
        //    FIRST, so any image/window error surfaces BEFORE we tear down the
        //    live slots (Linux execve semantics: on failure the caller keeps
        //    running its old image). `build_for_image` refuses any window that
        //    would back the unmapped SENTINEL_GPA (the guard in `add_window` is
        //    not weakened), so the sentinel hole stays a stage-2 MMIO fault.
        let new_ram = GuestRam::build_for_image(new_image)
            .map_err(|e| TrapError::Hypervisor(e.to_string()))?;

        // 2. Unregister EVERY currently-registered KVM memory slot on the LIVE VM
        //    (`KVM_SET_USER_MEMORY_REGION` with memory_size = 0). The old slots
        //    were registered from slot 0 in window order, so slot ids are
        //    `0..old window_count`.
        let old_slot_count = self.ram.window_count() as u32;
        for slot in 0..old_slot_count {
            self.vm
                .unmap_memory_slot(slot)
                .map_err(|e| TrapError::Hypervisor(e.to_string()))?;
        }
        // Reset the slot allocator so the new windows re-register from slot 0
        // (same ids/order a fresh VM would use), then publish them on the LIVE
        // VM. The SENTINEL_GPA hole stays unmapped.
        self.vm.reset_slot_counter();
        for (base, host, len) in new_ram.windows_for_kvm() {
            self.vm
                .map_memory(base, host, len, MemPerms::ReadWriteExec)
                .map_err(|e| TrapError::Hypervisor(e.to_string()))?;
        }

        // 3. Swap in the new RAM. The OLD GuestRam drops here, `munmap`ing its
        //    host windows — safe because their KVM slots were just deleted, so no
        //    live vCPU references them. `no_access` is dropped with it: execve
        //    replaces the address space, so any prior PROT_NONE ranges are gone
        //    (the new image starts with none until it mmaps them).
        self.ram = new_ram;

        // 4. Reprogram the system + core registers for the new image (MAIR=0xFF,
        //    TCR bootstrap, TTBR0/1 = LINUX_PAGE_TABLES_BASE, SCTLR, CPACR,
        //    VBAR = LINUX_EL1_VECTORS_BASE, TPIDR_EL0 = 0, PSTATE/SPSR/ELR/PC +
        //    SP from the new image's entry/initial stack). Reuses the SAME
        //    builder bring-up uses, so the sysreg values cannot drift between
        //    the two paths.
        program_sysregs(&mut self.vcpu, new_image)
            .map_err(|e| TrapError::Hypervisor(e.to_string()))?;

        // 5. Zero x0..x30. Linux's execve contract starts the new program with
        //    all GPRs clear (except SP/PC, set by `program_sysregs`). Without
        //    this the new image's _start inherits the old image's x8, which can
        //    decode as a bogus syscall number on its first `svc`. (`program_sysregs`
        //    deliberately leaves the GPRs to us — it sets only SP/PC/PSTATE.)
        for n in 0..=30u32 {
            self.vcpu
                .set_reg(Reg::X(n), 0)
                .map_err(|e| TrapError::Hypervisor(e.to_string()))?;
        }

        // 6. PRESERVE is_forked_child across execve (Task 2 flag): a descendant
        //    of a forked child keeps the `_exit`-without-report shutdown path
        //    even after it execve's into a different image (mirrors HVF
        //    trap.rs:3795). The flag is a plain field on `self`, untouched by
        //    the remap above — so this is a no-op assertion of intent, kept
        //    explicit for the contract.
        // (self.is_forked_child is intentionally left unchanged.)

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn inject_signal(
        &mut self,
        _signum: i32,
        _handler: u64,
        _sa_restorer: u64,
        _pending_syscall_retval: Option<i64>,
        _interrupted_pc: Option<u64>,
        _altstack: Option<(u64, u64)>,
        _saved_sigmask: u64,
        _fault_siginfo: Option<(i32, u64)>,
        _queued_siginfo: Option<LinuxSiginfo>,
        _restart_syscall: bool,
    ) -> Result<(), TrapError> {
        Err(TrapError::UnsupportedPlatform)
    }

    fn restore_from_sigframe(&mut self) -> Result<u64, TrapError> {
        Err(TrapError::UnsupportedPlatform)
    }
}

impl KvmTrapEngine {
    fn read_frame(&self) -> Result<Aarch64SyscallFrame, TrapError> {
        let g = |n: u32| {
            self.vcpu
                .reg(Reg::X(n))
                .map_err(|e| TrapError::Hypervisor(e.to_string()))
        };
        Ok(Aarch64SyscallFrame {
            x0: g(0)?,
            x1: g(1)?,
            x2: g(2)?,
            x3: g(3)?,
            x4: g(4)?,
            x5: g(5)?,
            x8: g(8)?,
        })
    }
}

#[cfg(test)]
mod execve_tests {
    //! `execve_into` unit tests. These build a REAL `KvmTrapEngine` (needing
    //! `/dev/kvm`) and assert the post-execve vCPU state directly — no full guest
    //! run. They therefore execute only where `/dev/kvm` is present (the lima L2
    //! lane / a native aarch64 Linux host); on a host without KVM they SKIP (the
    //! crate itself is `cfg(target_os = "linux")`, so macOS never compiles them).
    use super::*;
    use carrick_hal::SysReg;
    use carrick_mem::memory::{AddressSpace, LINUX_EL1_VECTORS_BASE, LINUX_PAGE_TABLES_BASE};

    // Two freestanding static aarch64 ELFs committed under fixtures/: the
    // fork-wait4 driver (initial image) and the exit0 execve target (new image).
    // Both are valid ELFs `AddressSpace::load_elf_bytes` can parse.
    const INITIAL_ELF: &[u8] = include_bytes!("../fixtures/fork-wait4/fork-wait4");
    const TARGET_ELF: &[u8] = include_bytes!("../fixtures/exec-target-exit0/exec-target-exit0");

    /// True when `/dev/kvm` is usable; tests SKIP (return early) otherwise so the
    /// suite is green on KVM-less hosts.
    fn kvm_available() -> bool {
        std::path::Path::new("/dev/kvm").exists()
    }

    fn engine_for(bytes: &[u8]) -> KvmTrapEngine {
        let image = AddressSpace::load_elf_bytes(bytes).expect("load test ELF");
        KvmTrapEngine::new(&image).expect("bring up test engine")
    }

    /// After `execve_into`, the stage-1 MMU sysregs point at the canonical
    /// carrick page-table / vector bases and MAIR is the Normal-WB value — i.e.
    /// the new image is correctly re-bootstrapped on the LIVE vCPU.
    #[test]
    fn execve_into_reprograms_sysregs() {
        if !kvm_available() {
            eprintln!("SKIP execve_into_reprograms_sysregs: no /dev/kvm");
            return;
        }
        let mut engine = engine_for(INITIAL_ELF);
        let new_image = AddressSpace::load_elf_bytes(TARGET_ELF).expect("load target ELF");
        engine.execve_into(&new_image).expect("execve_into");

        let v = &engine.vcpu;
        assert_eq!(
            v.get_sys_reg(SysReg::Ttbr0).unwrap(),
            LINUX_PAGE_TABLES_BASE,
            "TTBR0 must point at the stage-1 identity tables"
        );
        assert_eq!(
            v.get_sys_reg(SysReg::Ttbr1).unwrap(),
            LINUX_PAGE_TABLES_BASE,
            "TTBR1 shares the stage-1 root"
        );
        assert_eq!(
            v.get_sys_reg(SysReg::Vbar).unwrap(),
            LINUX_EL1_VECTORS_BASE,
            "VBAR must point at the sentinel EL1 vectors"
        );
        assert_eq!(
            v.get_sys_reg(SysReg::Mair).unwrap(),
            0xFF,
            "MAIR slot 0 = Normal Inner/Outer WB"
        );
        // Stage-1 on (SCTLR_EL1.M = bit 0).
        assert_eq!(
            v.get_sys_reg(SysReg::Sctlr).unwrap() & 1,
            1,
            "SCTLR_EL1.M must be set (stage-1 MMU on)"
        );
        // execve resets the EL0 thread pointer.
        assert_eq!(
            v.get_sys_reg(SysReg::TpidrEl0).unwrap(),
            0,
            "TPIDR_EL0 must be reset to 0 across execve"
        );
    }

    /// Linux execve starts the new program with x0..x30 clear. Dirty every GPR
    /// before execve and assert they are all zero afterwards.
    #[test]
    fn execve_into_clears_gprs() {
        if !kvm_available() {
            eprintln!("SKIP execve_into_clears_gprs: no /dev/kvm");
            return;
        }
        let mut engine = engine_for(INITIAL_ELF);
        // Dirty all GPRs to a non-zero pattern.
        for n in 0..=30u32 {
            engine
                .vcpu
                .set_reg(Reg::X(n), 0xDEAD_0000 | u64::from(n))
                .unwrap();
        }
        let new_image = AddressSpace::load_elf_bytes(TARGET_ELF).expect("load target ELF");
        engine.execve_into(&new_image).expect("execve_into");
        for n in 0..=30u32 {
            assert_eq!(
                engine.vcpu.reg(Reg::X(n)).unwrap(),
                0,
                "x{n} must be cleared by execve"
            );
        }
    }

    /// `is_forked_child` must survive execve (a forked-then-execve'd descendant
    /// keeps the `_exit`-without-report shutdown path).
    #[test]
    fn execve_into_preserves_is_forked_child() {
        if !kvm_available() {
            eprintln!("SKIP execve_into_preserves_is_forked_child: no /dev/kvm");
            return;
        }
        let new_image = AddressSpace::load_elf_bytes(TARGET_ELF).expect("load target ELF");

        // Case A: a NON-forked engine stays non-forked across execve.
        let mut e0 = engine_for(INITIAL_ELF);
        assert!(!e0.is_forked_child());
        e0.execve_into(&new_image)
            .expect("execve_into (non-forked)");
        assert!(
            !e0.is_forked_child(),
            "execve must not spuriously set is_forked_child"
        );

        // Case B: a forked engine stays forked across execve.
        let mut e1 = engine_for(INITIAL_ELF);
        e1.is_forked_child = true;
        e1.execve_into(&new_image).expect("execve_into (forked)");
        assert!(
            e1.is_forked_child(),
            "execve must preserve is_forked_child = true"
        );
    }

    /// PC after execve is the EL0 trampoline base (the vCPU restarts in EL1h and
    /// `eret`s into the new image's entry), and ELR_EL1 holds the new entry.
    #[test]
    fn execve_into_repositions_pc_to_new_entry() {
        if !kvm_available() {
            eprintln!("SKIP execve_into_repositions_pc_to_new_entry: no /dev/kvm");
            return;
        }
        use carrick_mem::memory::LINUX_EL0_TRAMPOLINE_BASE;
        let mut engine = engine_for(INITIAL_ELF);
        let new_image = AddressSpace::load_elf_bytes(TARGET_ELF).expect("load target ELF");
        let new_entry = new_image.entry();
        engine.execve_into(&new_image).expect("execve_into");
        assert_eq!(
            engine.vcpu.reg(Reg::Pc).unwrap(),
            LINUX_EL0_TRAMPOLINE_BASE,
            "PC must be the EL0 trampoline so the eret drops to EL0 at the new entry"
        );
        assert_eq!(
            engine.vcpu.reg(Reg::ElrEl1).unwrap(),
            new_entry,
            "ELR_EL1 must hold the new image's entry"
        );
    }
}
