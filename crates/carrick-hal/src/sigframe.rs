//! Carrier machine adapter for the shared pure ARM Linux rt-frame codec.
//!
//! Snapshot/guest-memory/register operations stay here. Public encoding and
//! complete validation live in carrick_personality_linux::signal::arm, shared
//! with the dormant EL1 SignalBackend. The engine supplies the authoritative
//! PSTATE, restart x0, fault ESR and trampoline; no codec reads a machine.

use carrick_guest_arch::UserVa;
use carrick_guest_mem::CurrentMmMemory;
use carrick_guest_mem::MemoryError;
use carrick_personality_linux::signal::arm;
use carrick_signal_core::{SignalSet, policy::SigBlockMask};
use zerocopy::IntoBytes;

use crate::{Reg, RegAccess, TrapError};

/// All inputs to [`build_sigframe`]: the 10 `inject_signal` arguments plus the
/// engine-supplied values that are NOT reachable through `RegAccess`/`CurrentMmMemory`.
pub struct InjectParams {
    pub signum: i32,
    pub handler: u64,
    pub sa_restorer: u64,
    pub pending_syscall_retval: Option<i64>,
    pub interrupted_pc: Option<u64>,
    pub altstack: Option<(u64, u64)>,
    pub saved_sigmask: u64,
    pub fault_siginfo: Option<(i32, u64)>,
    pub queued_siginfo: Option<carrick_abi::LinuxSiginfo>,
    pub restart_syscall: bool,
    // engine-supplied (backend-private knowledge the shared builder must not recompute):
    /// `= mcontext.pstate`: the interrupted code's PSTATE. CPSR on the kick
    /// path, SPSR_EL1 on the syscall path on HVF; KVM always uses SPSR_EL1. The
    /// ENGINE decides which source is authoritative.
    pub pstate_source: u64,
    /// `= self.last_syscall_orig_x0` (SA_RESTART path): the syscall's original
    /// arg0, restored so a restarted syscall re-executes with real arguments.
    pub orig_x0: u64,
    /// `= self.last_fault_esr`: the fault ESR recorded in the esr_context.
    pub fault_esr: u64,
    /// Whether to save/restore the FPSIMD context (`fpsimd_save_enabled()` on HVF).
    pub fpsimd_enabled: bool,
    /// The backend's fixed sigreturn trampoline base, used as the handler's LR
    /// when the sigaction registered no explicit `sa_restorer`
    /// (`crate::memory::LINUX_SIGRETURN_TRAMPOLINE_BASE` on HVF).
    pub sigreturn_trampoline_base: u64,
}

/// The values the inject wrapper needs after [`build_sigframe`] to fire its
/// USDT probes.
pub struct SigframeInject {
    pub new_sp: u64,
    pub saved_pc: u64,
}

/// The values the restore wrapper needs after [`restore_sigframe`].
pub struct SigframeRestore {
    pub sigmask: u64,
    pub saved_pc: u64,
    pub frame_sp: u64,
    /// Architecture diagnostic tag (zero for the public ARM frame).
    pub magic: u64,
}

fn signal_frame_memory_error_code(error: &MemoryError) -> i32 {
    match error {
        MemoryError::OutOfBounds { .. } => 1,
        MemoryError::Unsupported => 2,
        MemoryError::HostMap(_) => 3,
        MemoryError::MetadataAllocation => 4,
        MemoryError::OwnerWait(_) => 5,
        MemoryError::Supply(_) => 6,
        MemoryError::Physical(_) => 7,
        MemoryError::ReadSuspended(_) => 8,
        MemoryError::OwnerRetired(_) => 9,
    }
}

/// Build a public ARM frame for `p.signum`, write it to the guest's user
/// stack, and redirect the vCPU to the handler. Preserves the pre-signal
/// register state in the frame so [`restore_sigframe`] recovers it on
/// `rt_sigreturn`. Returns the new SP and the frame's saved PC for the caller's
/// telemetry. See `SyscallTrap::inject_signal` for the full per-field contract.
pub fn build_sigframe<E: RegAccess + CurrentMmMemory>(
    engine: &mut E,
    p: InjectParams,
) -> Result<SigframeInject, TrapError> {
    let mut mcontext = carrick_abi::LinuxSignalContext::empty();
    for i in 0..31 {
        mcontext.regs[i] = engine.get_reg(Reg::X(i as u32))?;
    }
    // x0 was just overwritten by `complete_syscall` with the
    // syscall's retval. Snapshot that value (not the pre-syscall
    // arg0) so the handler-return path resumes with the right
    // retval visible.
    //
    // SA_RESTART (restart_syscall): the interrupted syscall returned EINTR
    // and its handler is restartable. Restore the ORIGINAL arg0 instead so
    // that, after rt_sigreturn rewinds PC to the `svc` (below), the guest
    // re-executes the syscall with its real arguments (x8=sysno is
    // untouched by complete_syscall; x1..x5 were never clobbered).
    if p.restart_syscall {
        mcontext.regs[0] = p.orig_x0;
    } else if let Some(retval) = p.pending_syscall_retval {
        mcontext.regs[0] = retval as u64;
    }
    // Resume address after the handler returns. On a syscall-boundary
    // injection the backend set ELR_EL1 to the instruction after the `svc`; on
    // a kick (CANCELED) exit there was no exception, so ELR_EL1 is stale and
    // the caller passes the live guest PC instead.
    mcontext.pc = match p.interrupted_pc {
        Some(pc) => pc,
        None => engine.get_reg(Reg::ElrEl1)?,
    };
    // SA_RESTART: rewind PC by one instruction (4 bytes) so it points back
    // at the `svc` rather than the instruction after it. After the handler
    // returns via rt_sigreturn the guest re-executes the syscall (the
    // kernel's ERESTARTSYS). Only valid on the syscall-boundary path
    // (caller guarantees restart_syscall ⇒ interrupted_pc is None).
    if p.restart_syscall {
        mcontext.pc = mcontext.pc.wrapping_sub(4);
    }
    mcontext.sp = engine.get_reg(Reg::Sp)?;
    // Snapshot the interrupted code's PSTATE (incl. NZCV condition flags),
    // restored verbatim by rt_sigreturn → eret. The correct source differs
    // by injection path:
    //   * syscall-boundary (interrupted_pc == None): the guest `svc` took a
    //     synchronous exception to EL1, so the hardware latched the EL0
    //     PSTATE into SPSR_EL1. CPSR now reads the EL1 trampoline's state.
    //     SPSR_EL1 is authoritative.
    //   * kick (interrupted_pc == Some): a cross-thread hv_vcpus_exit forced
    //     a CANCELED exit while the guest was live at EL0 — NO exception was
    //     taken, so SPSR_EL1 is stale (it holds whatever the *previous*
    //     syscall latched). The live EL0 PSTATE is in CPSR. Reading SPSR_EL1
    //     here resumes the preempted routine with stale NZCV — conditional
    //     branches go the wrong way (memory intact, computation wrong),
    //     which is exactly Go's async-preemption (SIGURG) corruption.
    //
    // The engine pre-selected the authoritative source into `pstate_source`.
    // Publish only user-modifiable Linux signal PSTATE. Execution interrupt
    // masks and privilege fields cannot become guest-owned resume authority.
    mcontext.pstate = p.pstate_source & carrick_abi::AARCH64_EL0_USER_PSTATE_MASK;

    // A queued siginfo (rt_sigqueueinfo / sigqueue) wins over synthesis: it
    // carries the caller's si_value payload and the kernel-set si_code
    // (SI_QUEUE etc.). A synchronous fault carries the kernel-style
    // si_code (SEGV_MAPERR/SEGV_ACCERR/BUS_ADRALN) and si_addr=faulting
    // address so a handler (Go's sigpanic) sees the real cause.
    // Otherwise it's a SI_USER-shaped delivery (tkill/sysmon preempt).
    let mut siginfo = match (p.queued_siginfo, p.fault_siginfo) {
        (Some(q), _) => q,
        (None, Some((si_code, si_addr))) => {
            let mut s = carrick_abi::LinuxSiginfo::empty();
            s.si_code = si_code;
            s.si_addr = si_addr;
            s
        }
        (None, None) => {
            let mut s = carrick_abi::LinuxSiginfo::empty();
            s.si_code = carrick_abi::LINUX_SI_USER;
            s
        }
    };
    // The kernel re-stamps si_signo to the actually-delivered signum even
    // when a queued siginfo carried a stale field.
    siginfo.si_signo = p.signum;
    if let Some((_, si_addr)) = p.fault_siginfo {
        mcontext.fault_address = si_addr;
    }
    let fpsimd = read_fpsimd(engine, p.fpsimd_enabled)?;
    let stack = match p.altstack {
        Some((ss_sp, ss_size)) => carrick_abi::LinuxSignalStack {
            ss_sp,
            ss_size,
            ss_flags: carrick_abi::LINUX_SS_ONSTACK as i32,
            _pad0: 0,
        },
        None => carrick_abi::LinuxSignalStack::empty(),
    };
    let frame = arm::encode(
        mcontext,
        stack,
        SigBlockMask::blocking_all_of(SignalSet::from_bits(p.saved_sigmask)),
        siginfo,
        fpsimd,
        p.fault_siginfo.map(|_| p.fault_esr),
    )
    .map_err(|_| TrapError::SignalDeliveryFault)?;

    // Reserve space on the target stack, rounded down to 16-byte alignment
    // (AArch64 stack alignment requirement at function-call boundaries).
    // For SA_ONSTACK the frame is pushed from the TOP of the alt stack
    // (ss_sp + ss_size); otherwise from the interrupted SP_EL0. The alt
    // stack is what lets a handler run when the main stack is unusable
    // (LTP sigaltstack01 deliberately exercises that).
    let frame_bytes = frame.as_bytes();
    let new_sp = signal_frame_stack_pointer(mcontext.sp, p.altstack, frame_bytes.len())?;
    // A prepared lazy leaf is not yet a valid stage-1 translation. The
    // backend authenticates Linux write intent and commits first touch before
    // the ordinary whole-range host-buffer check below.
    engine
        .prepare_host_write(new_sp, frame_bytes.len())
        .map_err(|error| {
            carrick_observability::probes::hvpatch_signal_frame_step(
                1,
                new_sp,
                frame_bytes.len() as u64,
                signal_frame_memory_error_code(&error),
            );
            TrapError::SignalDeliveryFault
        })?;
    if !engine.guest_range_is_writable(new_sp, frame_bytes.len()) {
        carrick_observability::probes::hvpatch_signal_frame_step(
            2,
            new_sp,
            frame_bytes.len() as u64,
            1,
        );
        // Any unwritable signal stack is Linux force_sigsegv territory. This
        // check also prevents the unchecked frame write below from modifying
        // runtime-owned executable mappings when a guest forges SP_EL0.
        return Err(TrapError::SignalDeliveryFault);
    }

    // Write the frame into guest memory at the new SP. An unwritable/
    // unmapped stack is Linux force_sigsegv territory: terminate the
    // thread-group by SIGSEGV rather than crashing carrick.
    engine
        .write_bytes_unchecked(new_sp, frame_bytes)
        .map_err(|error| {
            carrick_observability::probes::hvpatch_signal_frame_step(
                3,
                new_sp,
                frame_bytes.len() as u64,
                signal_frame_memory_error_code(&error),
            );
            TrapError::SignalDeliveryFault
        })?;

    // Adjust SP_EL0 to point past the freshly-written frame.
    engine.set_reg(Reg::Sp, new_sp)?;

    // First handler argument is the signum.
    engine.set_reg(Reg::X(0), p.signum as u64)?;
    // x1/x2 carry siginfo* / ucontext* on SA_SIGINFO. Handlers may inspect
    // or mutate the saved PC/SP before rt_sigreturn, so keep the embedded
    // Linux-shaped context authoritative.
    let siginfo_addr = new_sp;
    let ucontext_addr = new_sp + arm::UCONTEXT_OFFSET as u64;
    engine.set_reg(Reg::X(1), siginfo_addr)?;
    engine.set_reg(Reg::X(2), ucontext_addr)?;
    engine.set_reg(Reg::X(29), new_sp + arm::FRAME_RECORD_OFFSET as u64)?;

    // LR = the restorer the handler `ret`s to, which must invoke
    // `rt_sigreturn(2)`. musl/x86-style libcs pass an explicit
    // `sa_restorer`; glibc on aarch64 passes 0 and relies on the kernel's
    // VDSO sigreturn trampoline (the aarch64 kernel ABI has no
    // sa_restorer). Use Carrick's fixed executable user trampoline rather
    // than writing code into the guest signal stack: stack-resident code is
    // vulnerable to I-cache coherency and frame-clobber timing at Go's
    // SIGURG preemption rate.
    let restorer = if p.sa_restorer != 0 {
        p.sa_restorer
    } else {
        p.sigreturn_trampoline_base
    };
    engine.set_reg(Reg::X(30), restorer)?;

    // Redirect to the handler entry. On a syscall-boundary injection the
    // guest is mid-`eret` from the EL1 vector, so the resume PC is ELR_EL1
    // (previously "instruction after the SVC"); we steal it for the handler
    // and mcontext.pc holds the original until rt_sigreturn. On a kick
    // (CANCELED) injection there is no pending eret — the vCPU resumes
    // directly at Reg::PC — so redirect PC instead and leave ELR_EL1 alone.
    // Either way the handler later returns via the rt_sigreturn `svc`, whose
    // completion restores ELR_EL1 = saved_pc and erets to it.
    if p.interrupted_pc.is_some() {
        engine.set_reg(Reg::Pc, p.handler)?;
    } else {
        engine.set_reg(Reg::ElrEl1, p.handler)?;
    }

    // Preserve the SPSR_EL1 we snapshotted — we want to return to
    // EL0t with the same DAIF state, and the EL1 vector path
    // already set SPSR_EL1 to "EL0t, DAIF masked" when entering
    // this trap. Nothing to write here; SPSR_EL1 is already
    // correct for "return to EL0t".

    let saved_pc = mcontext.pc;
    Ok(SigframeInject { new_sp, saved_pc })
}

/// Snapshot machine FP state; the pure codec owns its wire encoding.
fn read_fpsimd<E: RegAccess>(
    engine: &E,
    enabled: bool,
) -> Result<Option<carrick_abi::LinuxFpsimdContext>, TrapError> {
    if !enabled {
        return Ok(None);
    }
    let mut fp = carrick_abi::LinuxFpsimdContext::empty();
    let mut vregs = [0u128; 32];
    for (i, slot) in vregs.iter_mut().enumerate() {
        *slot = engine.get_vreg(i as u32)?;
    }
    fp.vregs = vregs;
    fp.fpsr = engine.get_fpsr()? as u32;
    fp.fpcr = engine.get_fpcr()? as u32;
    Ok(Some(fp))
}

/// Pop the public ARM frame at SP_EL0 (placed there by [`build_sigframe`]) and
/// restore the pre-signal register state. Called when the guest invokes
/// `rt_sigreturn(2)`. Returns the restored sigmask plus the values the caller's
/// `signal_restore` probe needs. Does NOT advance PC the way `complete_syscall`
/// does — the restored PC IS the next PC.
pub fn restore_sigframe<E: RegAccess + CurrentMmMemory>(
    engine: &mut E,
    fpsimd_enabled: bool,
) -> Result<SigframeRestore, TrapError> {
    let sp = engine.get_reg(Reg::Sp)?;
    let bytes = engine
        .read_bytes(sp, arm::PUBLIC_FRAME_LEN)
        .map_err(|_| TrapError::SignalDeliveryFault)?;
    let resume = arm::decode(&bytes, UserVa::new(sp), fpsimd_enabled)
        .map_err(|_| TrapError::SignalDeliveryFault)?;
    // All public records and resume fields are validated before the first
    // machine write. Malformed frames cannot publish a partial context.
    for (i, value) in resume.regs.iter().enumerate() {
        engine.set_reg(Reg::X(i as u32), *value)?;
    }
    if fpsimd_enabled && let Some(fp) = resume.fpsimd {
        let vregs = fp.vregs;
        for (i, value) in vregs.iter().enumerate() {
            engine.set_vreg(i as u32, *value)?;
        }
        engine.set_fpsr(u64::from(fp.fpsr))?;
        engine.set_fpcr(u64::from(fp.fpcr))?;
    }
    let saved_pc = resume.pc.raw();
    engine.set_reg(Reg::ElrEl1, saved_pc)?;
    engine.set_reg(Reg::Sp, resume.sp.raw())?;
    engine.set_reg(Reg::SpsrEl1, resume.pstate)?;
    Ok(SigframeRestore {
        sigmask: resume.mask.signals().bits(),
        saved_pc,
        frame_sp: sp,
        magic: 0,
    })
}

/// Compute the (16-byte-aligned) guest SP at which to push a signal frame of
/// `frame_len` bytes, honoring an SA_ONSTACK alt stack. Pure arithmetic over
/// `saved_sp` / `altstack` / `frame_len`.
pub fn signal_frame_stack_pointer(
    saved_sp: u64,
    altstack: Option<(u64, u64)>,
    frame_len: usize,
) -> Result<u64, TrapError> {
    arm::stack_pointer(
        UserVa::new(saved_sp),
        altstack.map(|(sp, size)| (UserVa::new(sp), size)),
        frame_len,
    )
    .map(UserVa::raw)
    .map_err(|error| match error {
        arm::FrameError::StackOverflow => {
            TrapError::Hypervisor("signal alt stack top overflowed".to_string())
        }
        arm::FrameError::StackUnderflow => {
            TrapError::Hypervisor("sigframe push underflowed stack".to_string())
        }
        _ => TrapError::SignalDeliveryFault,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signal_frame_stack_pointer_uses_checked_altstack_bounds() {
        let sp = signal_frame_stack_pointer(0x8000, Some((0x4000, 0x2000)), 0x123).unwrap();
        assert_eq!(sp & 15, 0);
        assert!(sp >= 0x4000);
        assert!(sp < 0x6000);

        let err = signal_frame_stack_pointer(0x8000, Some((u64::MAX - 8, 16)), 0x100).unwrap_err();
        assert!(
            err.to_string().contains("alt stack top overflowed"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn nested_altstack_frame_continues_down_from_current_sp() {
        // alt stack [0x4000, 0x6000). A first (outer) delivery while NOT on the
        // alt stack (saved_sp outside the range) pushes from the TOP.
        let outer = signal_frame_stack_pointer(0x8000, Some((0x4000, 0x2000)), 0x100).unwrap();
        assert!((0x4000..0x6000).contains(&outer));

        // A NESTED delivery while ALREADY on the alt stack (saved_sp inside the
        // range, simulating the outer handler's live SP) must push BELOW that
        // SP — not reset to the top, which would clobber the outer frame
        // (glibc "stack smashing detected"). This is the SA_NODEFER re-entry
        // / faulthandler chain=True case.
        let nested = signal_frame_stack_pointer(outer, Some((0x4000, 0x2000)), 0x100).unwrap();
        assert!(
            nested < outer,
            "nested {nested:#x} must be below outer {outer:#x}"
        );
        assert!(
            nested >= 0x4000,
            "nested {nested:#x} underflowed the alt stack"
        );
        assert_eq!(nested & 15, 0);

        // saved_sp exactly at the alt-stack base is treated as NOT on the stack
        // (the kernel's on_sig_stack uses sp > base), so it resets to the top.
        let at_base = signal_frame_stack_pointer(0x4000, Some((0x4000, 0x2000)), 0x100).unwrap();
        assert!((0x4000..0x6000).contains(&at_base));
        assert_eq!(at_base, outer);
    }
}
