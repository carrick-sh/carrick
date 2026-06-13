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

use carrick_guest_mem::{GuestMemory, MemoryError, X8664SyscallFrame};
use carrick_hal::{
    RawSyscall, SyscallTrap, TrapError, VcpuExit,
    guest_arch::{GuestArch as _, SyscallRemap, SyscallTable as _},
    x8664_arch::{X8664GuestArch, X8664SyscallTable},
};
use carrick_mem::memory::AddressSpace;

use crate::guest_setup::GuestRam;
use crate::guest_setup_x86::BroughtUpX86;
use crate::kvm::{KvmVcpu, KvmVm};

// ─── Doorbell port ────────────────────────────────────────────────────────────

/// The `OUT` port the LSTAR stub uses as the SYSCALL doorbell.
///
/// Matches the immediate in `X8664GuestArch::entry_trampoline_bytes()`:
/// `0xE6 0xC5` = `OUT imm8($0xC5), %al`.  Source: AMD64 ISA / OSDev "OUT".
pub const SYSCALL_DOORBELL_PORT: u16 = 0xC5;

// ─── KvmX86TrapEngine ────────────────────────────────────────────────────────

/// The KVM x86_64 syscall trap engine.
///
/// Drives a single vCPU over the INOUT doorbell vehicle.  Phase 2 M0–M2:
/// single-threaded, no fork/execve/signals (those return typed errors per
/// spec N1–N2).
pub struct KvmX86TrapEngine {
    _vm: KvmVm,
    vcpu: KvmVcpu,
    ram: GuestRam,
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
            _vm: bux.vm,
            vcpu: bux.vcpu,
            ram: bux.ram,
        }
    }

    /// Set `FS.base` via `KVM_SET_SREGS` — the `arch_prctl(ARCH_SET_FS)` handler.
    ///
    /// In long-mode, FS.base is a 64-bit base address for the FS segment used by
    /// musl as the TLS pointer.  KVM exposes it directly through `sregs.fs.base`
    /// (unlike bhyve, which requires `vm_set_desc` for segment hidden state).
    ///
    /// Source: arch_prctl(2) man7.org `ARCH_SET_FS = 0x1002`; kvm-ioctls `get_sregs`.
    pub fn set_fs_base(&mut self, addr: u64) -> Result<i64, TrapError> {
        let mut sregs = self
            .vcpu
            .fd()
            .get_sregs()
            .map_err(|e| TrapError::Hypervisor(format!("KVM_GET_SREGS(set_fs): {e}")))?;
        sregs.fs.base = addr;
        self.vcpu
            .fd()
            .set_sregs(&sregs)
            .map_err(|e| TrapError::Hypervisor(format!("KVM_SET_SREGS(fs.base): {e}")))?;
        Ok(0)
    }

    /// Get the current `FS.base` value — used by `arch_prctl(ARCH_GET_FS)`.
    pub fn get_fs_base(&self) -> Result<u64, TrapError> {
        let sregs = self
            .vcpu
            .fd()
            .get_sregs()
            .map_err(|e| TrapError::Hypervisor(format!("KVM_GET_SREGS(get_fs): {e}")))?;
        Ok(sregs.fs.base)
    }

    /// Raw `VcpuFd` accessor for in-crate helpers (arch_prctl GS path in
    /// `run_elf_x86.rs`).  `pub(crate)` keeps the encapsulation at the crate
    /// boundary.
    pub(crate) fn vcpu_fd(&self) -> &kvm_ioctls::VcpuFd {
        self.vcpu.fd()
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

    // ── Phase 2 deferred (spec N1–N2) ────────────────────────────────────────

    fn fork(&mut self) -> Result<carrick_hal::ForkOutcome, TrapError> {
        Err(TrapError::Hypervisor(
            "kvm-x86: fork is not implemented in Phase 2 (M3+; spec N1)".into(),
        ))
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
