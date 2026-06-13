//! `KvmX86TrapEngine` — the x86_64 KVM `SyscallTrap` + `GuestMemory` impl.
//!
//! Structural analogue of the aarch64 `KvmTrapEngine`, but dispatching on
//! `VcpuExit::IoOut(0xC5, ..)` (the `KVM_EXIT_IO` INOUT doorbell) instead of
//! `VcpuExit::MmioWrite`.  A ring-3 `SYSCALL` instruction enters the LSTAR stub
//! (`out %al, $0xC5` + `sysretq`), which surfaces as `KVM_EXIT_IO` on port 0xC5.
//!
//! # Resume discipline
//!
//! KVM auto-advances RIP past a completed INOUT on `KVM_EXIT_IO` (KVM API §4.35:
//! "KVM advances the instruction pointer").  `complete_syscall` therefore only
//! writes RAX — no RIP fixup needed (unlike the aarch64 MMIO-sentinel path, which
//! has no equivalent auto-advance and relies on the EL1 vector's own `eret`).
//!
//! # Syscall number contract
//!
//! `next_syscall` returns **canonical** (aarch64/asm-generic) numbers for
//! `SyscallRemap::Direct` entries.  For `SyscallRemap::Native` (e.g. `arch_prctl`)
//! and `SyscallRemap::Unknown` the raw x86_64 number is returned untranslated;
//! the M2 run-elf loop answers -ENOSYS for unknowns.
//!
//! # Sources
//! - x86_64 syscall ABI: syscall(2) man7.org "Architecture calling conventions"
//! - KVM API §4.35 "KVM_EXIT_IO"
//! - kvm-ioctls 0.22.1 `VcpuExit::IoOut(port, data_slice)`
//! - arch_prctl(2) man7.org `ARCH_SET_FS = 0x1002`

use std::sync::Arc;

use carrick_guest_mem::{GuestMemory, MemoryError, X8664SyscallFrame};
use carrick_hal::{
    OsError, RawSyscall, Reg, SysReg, SyscallTrap, TrapError, VcpuExit,
    guest_arch::{GuestArch as _, SyscallRemap, SyscallTable as _},
    x8664_arch::{X8664GuestArch, X8664SyscallTable},
};
use carrick_mem::memory::AddressSpace;

use crate::guest_setup::GuestRam;
use crate::guest_setup_x86::BroughtUpX86;
use crate::kvm::{KvmVcpu, KvmVm};
use crate::kvm_kicker::{KvmKickHandle, KvmKicker};

// ─── Doorbell port ────────────────────────────────────────────────────────────

/// The `OUT` port the LSTAR stub uses as the SYSCALL doorbell.
///
/// Matches the immediate in `X8664GuestArch::entry_trampoline_bytes()`:
/// `0xE6 0xC5` = `OUT imm8($0xC5), %al`.  Source: AMD64 ISA / OSDev "OUT".
pub const SYSCALL_DOORBELL_PORT: u16 = 0xC5;

/// Canonical (asm-generic/aarch64) `clone` number. Used to detect the one
/// syscall whose x86-64 raw arg order differs from the dispatcher's. The swap is
/// keyed on 220 PRECISELY so it never touches clone3 (canonical 435), which
/// reads its parameters from a guest `clone_args` struct (no positional args to
/// swap). Source: `clone(2)` man-page "C library/kernel differences".
const CANONICAL_CLONE: u64 = 220;

// x86-64 fork(2)/vfork(2) syscall numbers and the canonical Linux clone(2) flag
// values they desugar to. x86-64 HAS SYS_fork/SYS_vfork (asm-generic/aarch64 do
// NOT — they implement fork via clone), so musl's fork()/vfork() issue these
// directly. Translate them to canonical clone(220) + flags so the ISA-neutral
// dispatcher routes them to engine.fork()/fork_vfork() (the SAME path aarch64's
// clone(SIGCHLD) takes). Without this, raw 57/58 fall through Unknown and
// collide with canonical close(57)/… → silent misdispatch. Flag values:
// clone(2) man-page (exit-signal = low byte; CLONE_VM=0x100, CLONE_VFORK=0x4000);
// SIGCHLD=17 (signal(7)).
const X86_NR_FORK: u64 = 57;
const X86_NR_VFORK: u64 = 58;
const LINUX_SIGCHLD: u64 = 17;
const LINUX_CLONE_VM: u64 = 0x0000_0100;
const LINUX_CLONE_VFORK: u64 = 0x0000_4000;

// ─── KvmX86TrapEngine ────────────────────────────────────────────────────────

/// The KVM x86_64 syscall trap engine.
///
/// Drives a single vCPU over the INOUT doorbell vehicle.  Phase 2 M0–M2:
/// single-threaded, no fork/execve/signals (those return typed errors per
/// spec N1–N2).
pub struct KvmX86TrapEngine {
    vm: KvmVm,
    vcpu: KvmVcpu,
    ram: GuestRam,
    /// Set `true` on the child side of a guest `fork(2)` (mirrors aarch64
    /// `KvmTrapEngine::is_forked_child`). Steers the exit-reporting path.
    is_forked_child: bool,
}

impl KvmX86TrapEngine {
    /// Create a trap engine from the result of `bring_up_x86_kvm`.
    pub fn new(image: &AddressSpace) -> Result<Self, TrapError> {
        let brought_up = crate::guest_setup_x86::bring_up_x86_kvm(image)
            .map_err(|e| TrapError::Hypervisor(e.to_string()))?;
        Ok(Self::from_brought_up(brought_up))
    }

    /// Build from a fully brought-up `BroughtUpX86` (avoids re-running bring-up).
    pub fn from_brought_up(bux: BroughtUpX86) -> Self {
        Self {
            vm: bux.vm,
            vcpu: bux.vcpu,
            ram: bux.ram,
            is_forked_child: false,
        }
    }

    /// Resolve guest VA to a host pointer through the GuestRam window table.
    ///
    /// Returns `(host_ptr, bytes_available_in_window)` or `None` if the VA
    /// does not fall within any mapped window.
    fn va_to_host(&self, va: u64, len: usize) -> Option<(*mut u8, usize)> {
        // GuestRam::host_ptr gives us the base host pointer for `gpa`.
        // On the x86 path GPA == VA (identity mapping), so pass va directly.
        let host = self.ram.host_ptr(va, len)?;
        Some((host, len))
    }
}

// ─── arch_prctl FS/GS base (the carrick-hal shared policy calls these) ───────

impl carrick_hal::x8664_arch::SegmentBaseRegs for KvmX86TrapEngine {
    fn seg_set_fs_base(&mut self, addr: u64) -> Result<(), TrapError> {
        let mut sregs = self
            .vcpu
            .fd()
            .get_sregs()
            .map_err(|e| TrapError::Hypervisor(format!("KVM_GET_SREGS(set_fs): {e}")))?;
        sregs.fs.base = addr;
        self.vcpu
            .fd()
            .set_sregs(&sregs)
            .map_err(|e| TrapError::Hypervisor(format!("KVM_SET_SREGS(fs.base): {e}")))
    }

    fn seg_get_fs_base(&self) -> Result<u64, TrapError> {
        let sregs = self
            .vcpu
            .fd()
            .get_sregs()
            .map_err(|e| TrapError::Hypervisor(format!("KVM_GET_SREGS(get_fs): {e}")))?;
        Ok(sregs.fs.base)
    }

    fn seg_set_gs_base(&mut self, addr: u64) -> Result<(), TrapError> {
        let mut sregs = self
            .vcpu
            .fd()
            .get_sregs()
            .map_err(|e| TrapError::Hypervisor(format!("KVM_GET_SREGS(set_gs): {e}")))?;
        sregs.gs.base = addr;
        self.vcpu
            .fd()
            .set_sregs(&sregs)
            .map_err(|e| TrapError::Hypervisor(format!("KVM_SET_SREGS(gs.base): {e}")))
    }

    fn seg_get_gs_base(&self) -> Result<u64, TrapError> {
        let sregs = self
            .vcpu
            .fd()
            .get_sregs()
            .map_err(|e| TrapError::Hypervisor(format!("KVM_GET_SREGS(get_gs): {e}")))?;
        Ok(sregs.gs.base)
    }
}

// ─── GuestMemory ─────────────────────────────────────────────────────────────

impl GuestMemory for KvmX86TrapEngine {
    /// Read `length` bytes from guest VA `address` via the host mmap window.
    fn read_bytes(&self, address: u64, length: usize) -> Result<Vec<u8>, MemoryError> {
        let (host, _avail) = self
            .va_to_host(address, length)
            .ok_or(MemoryError::OutOfBounds { address, length })?;
        let mut out = vec![0u8; length];
        // SAFETY: `va_to_host` verified [host, host+length) is within a live
        // GuestRam window; the destination slice is disjoint.
        unsafe { std::ptr::copy_nonoverlapping(host, out.as_mut_ptr(), length) };
        Ok(out)
    }

    /// Write `bytes` into guest VA `address` via the host mmap window.
    fn write_bytes(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
        let length = bytes.len();
        let (host, _avail) = self
            .va_to_host(address, length)
            .ok_or(MemoryError::OutOfBounds { address, length })?;
        // SAFETY: `va_to_host` verified [host, host+length) is within a live
        // GuestRam window; the source slice is disjoint.
        unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), host, length) };
        Ok(())
    }
}

// ─── SyscallTrap ─────────────────────────────────────────────────────────────

impl SyscallTrap for KvmX86TrapEngine {
    fn next_syscall(&mut self) -> Result<Option<RawSyscall>, TrapError> {
        use carrick_hal::HvVcpu as _;

        loop {
            match self
                .vcpu
                .run()
                .map_err(|e| TrapError::Hypervisor(e.to_string()))?
            {
                // ── SYSCALL doorbell: OUT 0xC5 ────────────────────────────────
                //
                // The LSTAR stub executed `out %al, $0xC5`, KVM surfaced it as
                // `KVM_EXIT_IO` on port 0xC5.  KVM has already auto-advanced RIP
                // past the `out` instruction (KVM API §4.35), so complete_syscall
                // need only write RAX.
                //
                // Read the full GPR frame via `KVM_GET_REGS`.  The `kvm_regs`
                // struct on x86_64 has named fields: rax, rbx, rcx, rdx, rsi,
                // rdi, rsp, rbp, r8..r15, rip, rflags.
                // Source: kvm-bindings 0.12.1 `kvm_regs` on x86_64.
                VcpuExit::IoOut { port, .. } if port == SYSCALL_DOORBELL_PORT => {
                    let regs = self
                        .vcpu
                        .fd()
                        .get_regs()
                        .map_err(|e| TrapError::Hypervisor(format!("KVM_GET_REGS: {e}")))?;

                    // x86_64 Linux syscall ABI (syscall(2) man7.org):
                    //   number = rax
                    //   arg0   = rdi, arg1 = rsi, arg2 = rdx
                    //   arg3   = r10 (NOT rcx — SYSCALL clobbers rcx with RIP)
                    //   arg4   = r8,  arg5 = r9
                    let frame = X8664SyscallFrame {
                        rax: regs.rax,
                        rdi: regs.rdi,
                        rsi: regs.rsi,
                        rdx: regs.rdx,
                        r10: regs.r10,
                        r8: regs.r8,
                        r9: regs.r9,
                    };

                    let (x86_number, args) = X8664GuestArch::decode_syscall(&frame);

                    // Remap x86_64 number → canonical (aarch64/asm-generic).
                    // Direct(c)  → canonical number (runtime dispatch).
                    // Native     → raw x86_64 number (arch_prctl etc.).
                    // Unknown    → raw x86_64 number (-ENOSYS in the loop).
                    let canonical = match X8664SyscallTable::remap(x86_number) {
                        SyscallRemap::Direct(c) => c,
                        SyscallRemap::Native | SyscallRemap::Unknown => x86_number,
                    };

                    // arch_prctl(SET/GET FS/GS) is x86-ISA-specific and needs
                    // KVM_GET/SET_SREGS — an engine-only op the ISA-neutral
                    // SyscallDispatcher cannot perform (and raw x86 158 would
                    // misroute to canonical getgroups=158). Service it HERE via the
                    // SHARED carrick-hal policy (identical for bhyve) and re-enter
                    // the guest, so the dispatcher never sees it. (musl's first
                    // syscall is arch_prctl(ARCH_SET_FS, tls); without this the FS
                    // base stays 0, the first TLS access faults, and KVM_RUN returns
                    // KVM_EXIT_INTERNAL_ERROR.)
                    if x86_number == carrick_hal::x8664_arch::ARCH_PRCTL_X86_NR {
                        let ret =
                            carrick_hal::x8664_arch::service_arch_prctl(self, args[0], args[1])?;
                        self.complete_syscall(ret)?;
                        continue;
                    }

                    // x86-64 fork(57)/vfork(58): desugar to canonical clone(220)
                    // + flags so the shared dispatcher routes them to
                    // engine.fork()/fork_vfork(). (Raw 57/58 Unknown-collide with
                    // canonical close(57)/… → silent misdispatch.)
                    if x86_number == X86_NR_FORK {
                        return Ok(Some(RawSyscall {
                            number: CANONICAL_CLONE,
                            args: [LINUX_SIGCHLD, 0, 0, 0, 0, 0],
                        }));
                    }
                    if x86_number == X86_NR_VFORK {
                        return Ok(Some(RawSyscall {
                            number: CANONICAL_CLONE,
                            args: [
                                LINUX_CLONE_VM | LINUX_CLONE_VFORK | LINUX_SIGCHLD,
                                0,
                                0,
                                0,
                                0,
                                0,
                            ],
                        }));
                    }

                    // x86-64 raw clone(2) arg order is
                    // (flags, stack, parent_tid, child_tid, tls); the shared
                    // dispatcher binds the asm-generic order
                    // (flags, stack, parent_tid, tls, child_tid). Swap args[3]<->
                    // args[4] for canonical clone so the ISA-neutral clone handler
                    // reads tls/child_tid correctly. clone3 (435) passes a struct
                    // → no swap (the CANONICAL_CLONE guard keys on 220).
                    let mut args = args;
                    if canonical == CANONICAL_CLONE {
                        args.swap(3, 4);
                    }

                    return Ok(Some(RawSyscall {
                        number: canonical,
                        args,
                    }));
                }

                // ── Other IoOut ports ─────────────────────────────────────────
                VcpuExit::IoOut { port, .. } => {
                    return Err(TrapError::Hypervisor(format!(
                        "kvm-x86: unexpected OUT to port 0x{port:04X} \
                         (only doorbell 0x{SYSCALL_DOORBELL_PORT:04X} is handled)"
                    )));
                }

                // ── HLT: the guest executed a `hlt` — clean stop ─────────────
                VcpuExit::Halt => return Ok(None),

                // ── Kicked: EINTR from KVM_RUN (cross-thread signal) ──────────
                // Re-enter the guest; no pending syscall.
                VcpuExit::Kicked => continue,

                // ── MMIO write: PML4 misconfiguration or ring-3 fault ─────────
                // With an empty IDT a #GP/#PF/#UD cannot be delivered → triple
                // fault → KVM_EXIT_SHUTDOWN (surfaced as Halt above).  A spurious
                // MMIO write is a diagnostic aid.
                VcpuExit::MmioWrite { gpa, .. } => {
                    return Err(TrapError::Hypervisor(format!(
                        "kvm-x86: unexpected MMIO write to gpa=0x{gpa:x} \
                         (ring-3 fault or PML4 gap; check CR3 / page tables)"
                    )));
                }

                // ── Any other exit ────────────────────────────────────────────
                VcpuExit::Exception { syndrome, far } => {
                    return Err(TrapError::Hypervisor(format!(
                        "kvm-x86: unexpected Exception syndrome=0x{syndrome:x} far=0x{far:x}"
                    )));
                }
            }
        }
    }

    fn current_pc(&self) -> Result<u64, TrapError> {
        // Read RIP via KVM_GET_REGS.
        self.vcpu
            .fd()
            .get_regs()
            .map(|r| r.rip)
            .map_err(|e| TrapError::Hypervisor(format!("KVM_GET_REGS(current_pc): {e}")))
    }

    fn complete_syscall(&mut self, return_value: i64) -> Result<(), TrapError> {
        // Write RAX = return value.  KVM already auto-advanced RIP past the OUT
        // (KVM API §4.35), so no RIP fixup is needed.
        // Source: kvm-ioctls VcpuFd::set_regs; x86_64 syscall ABI (syscall(2)).
        let mut regs = self
            .vcpu
            .fd()
            .get_regs()
            .map_err(|e| TrapError::Hypervisor(format!("KVM_GET_REGS(complete): {e}")))?;
        regs.rax = return_value as u64;
        self.vcpu
            .fd()
            .set_regs(&regs)
            .map_err(|e| TrapError::Hypervisor(format!("KVM_SET_REGS(rax): {e}")))?;
        Ok(())
    }

    fn is_forked_child(&self) -> bool {
        self.is_forked_child
    }

    // ── M3c: real fork; execve_into + signals still deferred (M3d) ────────────

    fn fork(&mut self) -> Result<carrick_hal::ForkOutcome, TrapError> {
        use crate::guest_setup_x86::{restore_x86, seed_entry_snapshot_x86, snapshot_x86};

        // Snapshot the parent vCPU BEFORE forking (suspended at the trap — atomic).
        let snap = snapshot_x86(&self.vcpu).map_err(|e| TrapError::Hypervisor(e.to_string()))?;

        // Real host fork. The carrick-linux run loop quiesces other threads
        // around a guest fork (fork_quiesce); the calling thread is the only
        // active one here.
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            return Err(TrapError::ForkFailed(
                std::io::Error::last_os_error().to_string(),
            ));
        }
        if pid > 0 {
            // PARENT: live VM untouched; report child pid (loop writes it to RAX).
            return Ok(carrick_hal::ForkOutcome::Parent { child_pid: pid });
        }

        // CHILD: rebuild a fresh KvmVm over the COW-inherited host mmaps (the
        // PML4/GDT/trampoline windows came along COW), then restore the parent
        // register file seeded as a fork child (rax=0, rip=SYSRETQ, inherit
        // stack+tls). No page-table manager to clone (x86 static identity PML4);
        // no sentinel/PC fixup. restore_x86 re-applies the SYSCALL MSRs.
        let (new_vm, new_vcpu) = self
            .ram
            .rebuild_vm_for_child()
            .map_err(|e| TrapError::Hypervisor(e.to_string()))?;
        let child_snap = seed_entry_snapshot_x86(&snap, carrick_hal::GuestEntryRegs::default());
        restore_x86(&new_vcpu, &child_snap).map_err(|e| TrapError::Hypervisor(e.to_string()))?;
        self.vm = new_vm;
        self.vcpu = new_vcpu;
        // Re-stamp the live-vcpu counter: libc::fork copied the parent's static
        // VCPU_LIVE (incl. phantom siblings absent post-fork). The child owns
        // exactly one vCPU. Mirrors aarch64 trap_engine.rs.
        crate::kvm::VCPU_LIVE.store(1, std::sync::atomic::Ordering::SeqCst);
        self.is_forked_child = true;
        Ok(carrick_hal::ForkOutcome::Child)
    }

    fn execve_into(&mut self, _new_image: &AddressSpace) -> Result<(), TrapError> {
        Err(TrapError::Hypervisor(
            "kvm-x86: execve_into is not implemented in Phase 2 (M3+; spec N1)".into(),
        ))
    }

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
        _queued_siginfo: Option<carrick_abi::LinuxSiginfo>,
        _restart_syscall: bool,
    ) -> Result<(), TrapError> {
        Err(TrapError::Hypervisor(
            "kvm-x86: inject_signal is not implemented in Phase 2 (M3+; spec N2)".into(),
        ))
    }

    fn restore_from_sigframe(&mut self) -> Result<u64, TrapError> {
        Err(TrapError::Hypervisor(
            "kvm-x86: restore_from_sigframe is not implemented in Phase 2 (M3+; spec N2)".into(),
        ))
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

// ─── RegAccess (x86_64 via KVM_GET/SET_REGS/SREGS/FPU) ───────────────────────
//
// The aarch64 KvmVcpu::reg/set_reg are non-aarch64 Err stubs (kvm.rs:790); x86
// goes straight through the VcpuFd. get/set_reg read-modify-write the full
// kvm_regs (KVM has no per-GPR ioctl on x86) — fine off the syscall hot path
// (only the clone/sigframe paths read these). The aarch64 Reg/SysReg variants
// are a disjoint ISA view and never reach this engine (-> EINVAL).
impl carrick_hal::RegAccess for KvmX86TrapEngine {
    fn get_reg(&self, r: Reg) -> Result<u64, OsError> {
        let regs = self
            .vcpu
            .fd()
            .get_regs()
            .map_err(|_| OsError::from_raw(libc::EIO))?;
        Ok(match r {
            Reg::Rax => regs.rax,
            Reg::Rbx => regs.rbx,
            Reg::Rcx => regs.rcx,
            Reg::Rdx => regs.rdx,
            Reg::Rsi => regs.rsi,
            Reg::Rdi => regs.rdi,
            Reg::Rbp => regs.rbp,
            Reg::Rsp => regs.rsp,
            Reg::R8 => regs.r8,
            Reg::R9 => regs.r9,
            Reg::R10 => regs.r10,
            Reg::R11 => regs.r11,
            Reg::R12 => regs.r12,
            Reg::R13 => regs.r13,
            Reg::R14 => regs.r14,
            Reg::R15 => regs.r15,
            Reg::Rip => regs.rip,
            Reg::Rflags => regs.rflags,
            _ => return Err(OsError::from_raw(libc::EINVAL)),
        })
    }

    fn set_reg(&mut self, r: Reg, v: u64) -> Result<(), OsError> {
        let mut regs = self
            .vcpu
            .fd()
            .get_regs()
            .map_err(|_| OsError::from_raw(libc::EIO))?;
        match r {
            Reg::Rax => regs.rax = v,
            Reg::Rbx => regs.rbx = v,
            Reg::Rcx => regs.rcx = v,
            Reg::Rdx => regs.rdx = v,
            Reg::Rsi => regs.rsi = v,
            Reg::Rdi => regs.rdi = v,
            Reg::Rbp => regs.rbp = v,
            Reg::Rsp => regs.rsp = v,
            Reg::R8 => regs.r8 = v,
            Reg::R9 => regs.r9 = v,
            Reg::R10 => regs.r10 = v,
            Reg::R11 => regs.r11 = v,
            Reg::R12 => regs.r12 = v,
            Reg::R13 => regs.r13 = v,
            Reg::R14 => regs.r14 = v,
            Reg::R15 => regs.r15 = v,
            Reg::Rip => regs.rip = v,
            Reg::Rflags => regs.rflags = v,
            _ => return Err(OsError::from_raw(libc::EINVAL)),
        }
        self.vcpu
            .fd()
            .set_regs(&regs)
            .map_err(|_| OsError::from_raw(libc::EIO))
    }

    fn get_sys_reg(&self, r: SysReg) -> Result<u64, OsError> {
        let sregs = self
            .vcpu
            .fd()
            .get_sregs()
            .map_err(|_| OsError::from_raw(libc::EIO))?;
        Ok(match r {
            SysReg::FsBase => sregs.fs.base,
            SysReg::GsBase => sregs.gs.base,
            _ => return Err(OsError::from_raw(libc::EINVAL)),
        })
    }

    fn set_sys_reg(&mut self, r: SysReg, v: u64) -> Result<(), OsError> {
        let mut sregs = self
            .vcpu
            .fd()
            .get_sregs()
            .map_err(|_| OsError::from_raw(libc::EIO))?;
        match r {
            SysReg::FsBase => sregs.fs.base = v,
            SysReg::GsBase => sregs.gs.base = v,
            _ => return Err(OsError::from_raw(libc::EINVAL)),
        }
        self.vcpu
            .fd()
            .set_sregs(&sregs)
            .map_err(|_| OsError::from_raw(libc::EIO))
    }

    fn get_vreg(&self, n: u32) -> Result<u128, OsError> {
        if n >= 16 {
            return Err(OsError::from_raw(libc::EINVAL));
        }
        let fpu = self
            .vcpu
            .fd()
            .get_fpu()
            .map_err(|_| OsError::from_raw(libc::EIO))?;
        Ok(u128::from_le_bytes(fpu.xmm[n as usize]))
    }

    fn set_vreg(&mut self, n: u32, v: u128) -> Result<(), OsError> {
        if n >= 16 {
            return Err(OsError::from_raw(libc::EINVAL));
        }
        let mut fpu = self
            .vcpu
            .fd()
            .get_fpu()
            .map_err(|_| OsError::from_raw(libc::EIO))?;
        fpu.xmm[n as usize] = v.to_le_bytes();
        self.vcpu
            .fd()
            .set_fpu(&fpu)
            .map_err(|_| OsError::from_raw(libc::EIO))
    }

    fn get_fpcr(&self) -> Result<u64, OsError> {
        // x86 has no FPCR; MXCSR is the nearest control word. The x86 sigframe
        // (M3d) builds fpregs from KVM_GET_FPU directly and does not consult this.
        let fpu = self
            .vcpu
            .fd()
            .get_fpu()
            .map_err(|_| OsError::from_raw(libc::EIO))?;
        Ok(u64::from(fpu.mxcsr))
    }

    fn set_fpcr(&mut self, v: u64) -> Result<(), OsError> {
        let mut fpu = self
            .vcpu
            .fd()
            .get_fpu()
            .map_err(|_| OsError::from_raw(libc::EIO))?;
        fpu.mxcsr = v as u32;
        self.vcpu
            .fd()
            .set_fpu(&fpu)
            .map_err(|_| OsError::from_raw(libc::EIO))
    }

    fn get_fpsr(&self) -> Result<u64, OsError> {
        // No distinct x86 status word in this model (unused on the x86 sigframe path).
        Ok(0)
    }

    fn set_fpsr(&mut self, _v: u64) -> Result<(), OsError> {
        Ok(())
    }
}

// SAFETY: `KvmX86TrapEngine` holds a `KvmVm` (`Arc<VmFd>` + `Option<Kvm>` — `File`s,
// `Send + Sync`), a `KvmVcpu` (`VcpuFd` — `Send + Sync` in kvm-ioctls), and a
// `GuestRam` whose only non-`Send` members are the window mmaps' raw `*mut u8`.
// Those host pointers are valid in EVERY thread of the process (threads share the
// address space) and the KVM fds are usable from any thread, so moving the engine
// to its owning sibling/vCPU thread is sound. Mirrors `unsafe impl Send for
// KvmTrapEngine` (trap_engine.rs).
unsafe impl Send for KvmX86TrapEngine {}

/// The `Send` payload `build_sibling_spec` hands to a freshly spawned host
/// thread, which `materialize_sibling` turns into a sibling engine on the SAME
/// VM (no new VM, no re-registration — siblings share every slot). x86
/// counterpart of aarch64 `KvmSiblingSpec`, minus the page-table manager (x86
/// uses a static identity PML4 — nothing to share). Auto-`Send`: `SharedVmHandle`
/// is `Arc`-backed, `WindowDesc.host` is a `usize`, the snapshot is POD, and
/// `VcpuLiveTicket`/`Arc<MemoryProtections>` are `Send`.
pub struct X8664SiblingSpec {
    vm: crate::kvm::SharedVmHandle,
    windows: Vec<crate::guest_setup::WindowDesc>,
    snapshot: crate::guest_setup_x86::X8664VcpuSnapshot,
    protections: std::sync::Arc<carrick_mem::protections::MemoryProtections>,
    ticket: crate::kvm::VcpuLiveTicket,
}

// ─── ThreadedEngine (minimal — single-threaded M3a/M3b) ──────────────────────
//
// Puts x86 on the canonical run_vcpu_until_exit loop. clone(CLONE_THREAD) sibling
// vCPUs are M3c (build/materialize_sibling = typed-error stubs); fork/execve_into/
// inject_signal/restore_from_sigframe keep their SyscallTrap stubs (M3c/M3d).
impl carrick_hal::ThreadedEngine for KvmX86TrapEngine {
    type Arch = X8664GuestArch;
    type KickHandle = KvmKickHandle;
    type SiblingSpec = X8664SiblingSpec;

    fn kick_handle(&self) -> Self::KickHandle {
        KvmKickHandle::for_current_thread()
    }

    fn wait_for_vcpu_slot() {
        // No-op: KVM has no Apple-HVF concurrent-vCPU admission cap.
    }

    fn build_sibling_spec(
        &self,
        entry: carrick_hal::GuestEntryRegs,
    ) -> Result<Self::SiblingSpec, TrapError> {
        use crate::guest_setup_x86::{seed_entry_snapshot_x86, snapshot_x86};
        // Snapshot the parent (suspended at the trapped clone — atomic), seed it
        // for the new thread (rax=0, rsp=stack, fs.base=tls, rip=SYSRETQ), and
        // carry SHARED handles so the sibling runs in the SAME VM/address space.
        let parent = snapshot_x86(&self.vcpu).map_err(|e| TrapError::Hypervisor(e.to_string()))?;
        let snapshot = seed_entry_snapshot_x86(&parent, entry);
        Ok(X8664SiblingSpec {
            vm: self.vm.vm_handle(),
            windows: self.ram.window_descriptors(),
            snapshot,
            protections: self.ram.shared_protections(),
            // Reserve the sibling's VCPU_LIVE slot NOW (parent suspended at the
            // trapped clone) — closes the execve-drain blind window. Consumed at
            // materialization; dropped-unmaterialized releases it.
            ticket: crate::kvm::VcpuLiveTicket::acquire(),
        })
    }

    fn materialize_sibling(spec: Self::SiblingSpec) -> Result<Self, TrapError>
    where
        Self: Sized,
    {
        use crate::guest_setup_x86::restore_x86;
        // New vCPU on the SAME VM (siblings share all slots). The unique vcpu id
        // is drawn from the shared allocator in SharedVmHandle.
        let vm = KvmVm::from_shared_vm(spec.vm);
        let vcpu = vm
            .add_sibling_vcpu()
            .map_err(|e| TrapError::Hypervisor(e.to_string()))?;
        // Transfer the reserved VCPU_LIVE slot to the vcpu BEFORE the fallible
        // restore (so a restore error decrements exactly once via the vcpu Drop).
        spec.ticket.consume();
        restore_x86(&vcpu, &spec.snapshot).map_err(|e| TrapError::Hypervisor(e.to_string()))?;
        // Non-owning view over the parent's host windows (shares the same backing
        // + PROT_NONE bookkeeping; never munmaps — the parent owns it).
        let ram =
            GuestRam::from_shared_windows(&spec.windows, std::sync::Arc::clone(&spec.protections));
        Ok(Self {
            vm,
            vcpu,
            ram,
            is_forked_child: false,
        })
    }

    fn program_counter(&self) -> Result<u64, TrapError> {
        self.current_pc()
    }

    fn set_guest_sp_el0(&self, sp: u64) -> Result<(), TrapError> {
        // x86 "SP_EL0" analogue is RSP. &self read-modify-write of the GPR set.
        let mut regs = self
            .vcpu
            .fd()
            .get_regs()
            .map_err(|e| TrapError::Hypervisor(format!("KVM_GET_REGS(set_rsp): {e}")))?;
        regs.rsp = sp;
        self.vcpu
            .fd()
            .set_regs(&regs)
            .map_err(|e| TrapError::Hypervisor(format!("KVM_SET_REGS(rsp): {e}")))
    }

    fn set_guest_thread_id(&self, _tid: u64) -> Result<(), TrapError> {
        // No in-guest gettid fast path on KVM (no syscall shim); the dispatcher
        // services gettid. Mirrors the HVF/aarch64 no-shim path.
        Ok(())
    }

    fn fresh_fork_kicker(&self) -> Arc<dyn carrick_hal::VcpuRegistry> {
        Arc::new(KvmKicker::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify the doorbell port constant matches the LSTAR trampoline bytes.
    ///
    /// `entry_trampoline_bytes()` = `[0xE6, 0xC5, 0x48, 0x0F, 0x07]`:
    ///   `0xE6` = `OUT imm8, %al` opcode
    ///   `0xC5` = port immediate (must equal `SYSCALL_DOORBELL_PORT`)
    /// Source: AMD64 Architecture Programmer's Manual Vol. 3 / OSDev "OUT".
    #[test]
    fn doorbell_port_matches_trampoline() {
        let trampoline = X8664GuestArch::entry_trampoline_bytes();
        assert_eq!(trampoline[0], 0xE6, "OUT opcode must be 0xE6");
        assert_eq!(
            trampoline[1], SYSCALL_DOORBELL_PORT as u8,
            "trampoline port byte must match SYSCALL_DOORBELL_PORT"
        );
    }

    /// Verify the x86_64 syscall frame field layout.
    ///
    /// x86_64 Linux syscall ABI (syscall(2) man7.org):
    ///   number: rax; args: rdi, rsi, rdx, r10, r8, r9
    ///   return: rax; SYSCALL clobbers rcx (return RIP) and r11 (return RFLAGS)
    ///   The 4th argument is r10 (NOT rcx — rcx is clobbered by SYSCALL).
    #[test]
    fn x86_syscall_frame_layout() {
        let frame = X8664SyscallFrame {
            rax: 1,
            rdi: 2,
            rsi: 3,
            rdx: 4,
            r10: 5,
            r8: 6,
            r9: 7,
        };
        assert_eq!(frame.rax, 1);
        assert_eq!(frame.rdi, 2);
        assert_eq!(
            frame.r10, 5,
            "4th arg is r10, not rcx (SYSCALL clobbers rcx)"
        );
    }
}
