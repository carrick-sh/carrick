//! Shared, platform-agnostic aarch64 `rt_sigframe` builder/restorer.
//!
//! This is the single source of truth for how carrick constructs the Linux
//! `CarrickSigframe` it pushes onto the guest's user stack when delivering a
//! signal, and how it recovers the pre-signal register state on
//! `rt_sigreturn(2)`. The signal-frame layout is load-bearing ABI: a guest
//! handler (glibc, musl, Go's sigpanic, CPython faulthandler, Apple Rosetta's
//! x86 trampoline) reads/writes these exact bytes, so the logic here must stay
//! identical across backends.
//!
//! It is written once over the [`crate::RegAccess`] + [`carrick_guest_mem::GuestMemory`]
//! traits so every backend (HVF on macOS, KVM on Linux) reuses it byte-for-byte.
//! The single combined `E: RegAccess + GuestMemory` bound matches reality: a
//! trap engine impls BOTH traits on the SAME type, and every access here is
//! sequential, so one `&mut E` supplies both register and memory access without
//! aliasing.
//!
//! The engine supplies four values the shared builder must not recompute
//! ([`InjectParams::pstate_source`], `orig_x0`, `fault_esr`, `fpsimd_enabled`)
//! plus the backend's sigreturn trampoline base — see [`InjectParams`].

use carrick_guest_mem::GuestMemory;
use zerocopy::{FromBytes, IntoBytes};

use crate::{Reg, RegAccess, TrapError};

/// All inputs to [`build_sigframe`]: the 10 `inject_signal` arguments plus the
/// engine-supplied values that are NOT reachable through `RegAccess`/`GuestMemory`.
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
    /// `= frame.saved_spsr`: the interrupted code's PSTATE. CPSR on the kick
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
    pub magic: u64,
}

/// Build a `CarrickSigframe` for `p.signum`, write it to the guest's user
/// stack, and redirect the vCPU to the handler. Preserves the pre-signal
/// register state in the frame so [`restore_sigframe`] recovers it on
/// `rt_sigreturn`. Returns the new SP and the frame's saved PC for the caller's
/// telemetry. See `SyscallTrap::inject_signal` for the full per-field contract.
pub fn build_sigframe<E: RegAccess + GuestMemory>(
    engine: &mut E,
    p: InjectParams,
) -> Result<SigframeInject, TrapError> {
    let mut frame = carrick_abi::CarrickSigframe::empty();
    frame.signum = p.signum as u32;
    for i in 0..31 {
        frame.saved_x[i] = engine.get_reg(Reg::X(i as u32))?;
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
        frame.saved_x[0] = p.orig_x0;
    } else if let Some(retval) = p.pending_syscall_retval {
        frame.saved_x[0] = retval as u64;
    }
    // Resume address after the handler returns. On a syscall-boundary
    // injection the backend set ELR_EL1 to the instruction after the `svc`; on
    // a kick (CANCELED) exit there was no exception, so ELR_EL1 is stale and
    // the caller passes the live guest PC instead.
    frame.saved_pc = match p.interrupted_pc {
        Some(pc) => pc,
        None => engine.get_reg(Reg::ElrEl1)?,
    };
    // SA_RESTART: rewind PC by one instruction (4 bytes) so it points back
    // at the `svc` rather than the instruction after it. After the handler
    // returns via rt_sigreturn the guest re-executes the syscall (the
    // kernel's ERESTARTSYS). Only valid on the syscall-boundary path
    // (caller guarantees restart_syscall ⇒ interrupted_pc is None).
    if p.restart_syscall {
        frame.saved_pc = frame.saved_pc.wrapping_sub(4);
    }
    frame.saved_sp = engine.get_reg(Reg::Sp)?;
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
    frame.saved_spsr = p.pstate_source;

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
    frame.siginfo = siginfo;

    let mut mcontext = carrick_abi::LinuxSignalContext::empty();
    mcontext.regs = frame.saved_x;
    mcontext.sp = frame.saved_sp;
    mcontext.pc = frame.saved_pc;
    mcontext.pstate = frame.saved_spsr;
    // The arm64 kernel records the faulting VA in sigcontext.fault_address for
    // a synchronous memory fault (SIGSEGV/SIGBUS). Linux fault handlers read it
    // there, NOT from siginfo.si_addr — Go's `sigctxt.fault()` returns
    // `c.regs().fault_address`, and the `addr=0x..` in its crash report comes
    // from it. Leaving it 0 made every guest SIGSEGV look like a nil deref.
    // Mirror si_addr (= the faulting VA) here; non-fault signals leave it 0.
    if let Some((_, si_addr)) = p.fault_siginfo {
        mcontext.fault_address = si_addr;
    }
    // Save V0–V31 + FPSR/FPCR as a Linux fpsimd_context at the start of
    // sigcontext.__reserved, so the handler can't leak SIMD state into the
    // interrupted thread (aarch64 memcpy/memset use V registers) and so a
    // handler inspecting the ucontext sees real FP state.
    save_fpsimd(engine, &mut mcontext, p.fpsimd_enabled)?;
    // For a synchronous fault, the arm64 kernel also records an esr_context
    // (the fault ESR) in __reserved after the fpsimd record. Apple Rosetta's
    // signal handler requires it. The zero-filled tail is the terminating
    // null record.
    if p.fault_siginfo.is_some() {
        const ESR_MAGIC: u32 = 0x4553_5201; // 'ESR\x01'
        let off = if p.fpsimd_enabled {
            core::mem::size_of::<carrick_abi::LinuxFpsimdContext>()
        } else {
            0
        };
        if off + 16 <= mcontext.__reserved.len() {
            mcontext.__reserved[off..off + 4].copy_from_slice(&ESR_MAGIC.to_le_bytes());
            mcontext.__reserved[off + 4..off + 8].copy_from_slice(&16u32.to_le_bytes());
            mcontext.__reserved[off + 8..off + 16].copy_from_slice(&p.fault_esr.to_le_bytes());
        }
    }
    let mut ucontext = carrick_abi::LinuxUcontext::empty();
    ucontext.uc_sigmask = p.saved_sigmask;
    ucontext.uc_mcontext = mcontext;
    // When delivering on the alternate signal stack (SA_ONSTACK), the
    // ucontext's uc_stack describes that stack with SS_ONSTACK set, so a
    // handler querying sigaltstack(NULL, &old) sees it's running on it.
    if let Some((ss_sp, ss_size)) = p.altstack {
        ucontext.uc_stack = carrick_abi::LinuxSignalStack {
            ss_sp,
            ss_flags: carrick_abi::LINUX_SS_ONSTACK as i32,
            _pad0: 0,
            ss_size,
        };
    }
    frame.ucontext = ucontext;

    // Reserve space on the target stack, rounded down to 16-byte alignment
    // (AArch64 stack alignment requirement at function-call boundaries).
    // For SA_ONSTACK the frame is pushed from the TOP of the alt stack
    // (ss_sp + ss_size); otherwise from the interrupted SP_EL0. The alt
    // stack is what lets a handler run when the main stack is unusable
    // (LTP sigaltstack01 deliberately exercises that).
    let frame_bytes = frame.as_bytes();
    let new_sp = signal_frame_stack_pointer(frame.saved_sp, p.altstack, frame_bytes.len())?;
    if p.altstack.is_some() && !engine.guest_range_is_writable(new_sp, frame_bytes.len()) {
        // Unwritable alt stack: Linux force_sigsegv -> terminate the
        // thread-group by SIGSEGV, not a fatal carrick error.
        return Err(TrapError::SignalDeliveryFault);
    }

    // Write the frame into guest memory at the new SP. An unwritable/
    // unmapped stack is Linux force_sigsegv territory: terminate the
    // thread-group by SIGSEGV rather than crashing carrick.
    engine
        .write_bytes_unchecked(new_sp, frame_bytes)
        .map_err(|_| TrapError::SignalDeliveryFault)?;

    // Adjust SP_EL0 to point past the freshly-written frame.
    engine.set_reg(Reg::Sp, new_sp)?;

    // First handler argument is the signum.
    engine.set_reg(Reg::X(0), p.signum as u64)?;
    // x1/x2 carry siginfo* / ucontext* on SA_SIGINFO. Handlers may inspect
    // or mutate the saved PC/SP before rt_sigreturn, so keep the embedded
    // Linux-shaped context authoritative.
    let siginfo_addr = new_sp + core::mem::offset_of!(carrick_abi::CarrickSigframe, siginfo) as u64;
    let ucontext_addr =
        new_sp + core::mem::offset_of!(carrick_abi::CarrickSigframe, ucontext) as u64;
    engine.set_reg(Reg::X(1), siginfo_addr)?;
    engine.set_reg(Reg::X(2), ucontext_addr)?;

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
    // and frame.saved_pc holds the original until rt_sigreturn. On a kick
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

    let saved_pc = frame.saved_pc;
    Ok(SigframeInject { new_sp, saved_pc })
}

/// Snapshot the guest V0–V31 + FPSR/FPCR into the Linux `fpsimd_context`
/// at the start of `mcontext.__reserved`. Mirrors what the arm64 kernel
/// writes at signal entry (`preserve_fpsimd_context`).
fn save_fpsimd<E: RegAccess>(
    engine: &E,
    mcontext: &mut carrick_abi::LinuxSignalContext,
    enabled: bool,
) -> Result<(), TrapError> {
    if !enabled {
        return Ok(());
    }
    let mut fp = carrick_abi::LinuxFpsimdContext::empty();
    let mut vregs = [0u128; 32];
    for (i, slot) in vregs.iter_mut().enumerate() {
        *slot = engine.get_vreg(i as u32)?;
    }
    fp.vregs = vregs;
    fp.fpsr = engine.get_fpsr()? as u32;
    fp.fpcr = engine.get_fpcr()? as u32;
    let bytes = fp.as_bytes();
    mcontext.__reserved[..bytes.len()].copy_from_slice(bytes);
    Ok(())
}

/// Restore V0–V31 + FPSR/FPCR from the `fpsimd_context` saved in
/// `mcontext.__reserved`. A missing/!FPSIMD_MAGIC record is left alone
/// (vector registers keep their current values rather than taking garbage).
fn restore_fpsimd<E: RegAccess>(
    engine: &mut E,
    mcontext: &carrick_abi::LinuxSignalContext,
    enabled: bool,
) -> Result<(), TrapError> {
    if !enabled {
        return Ok(());
    }
    let reserved = mcontext.__reserved;
    let size = core::mem::size_of::<carrick_abi::LinuxFpsimdContext>();
    let Ok(fp) = carrick_abi::LinuxFpsimdContext::read_from_bytes(&reserved[..size]) else {
        return Ok(());
    };
    if fp.magic != carrick_abi::LINUX_FPSIMD_MAGIC {
        return Ok(());
    }
    let vregs = fp.vregs;
    for (i, v) in vregs.iter().enumerate() {
        // RegAccess::set_vreg routes through the backend's correct vector-set
        // path (on HVF the `set_simd_fp_reg_v` C shim, NOT applevisor's
        // by-value setter which silently zeroes the register).
        engine.set_vreg(i as u32, *v)?;
    }
    let (fpsr, fpcr) = (fp.fpsr, fp.fpcr);
    engine.set_fpsr(u64::from(fpsr))?;
    engine.set_fpcr(u64::from(fpcr))?;
    Ok(())
}

/// Pop the `CarrickSigframe` at SP_EL0 (placed there by [`build_sigframe`]) and
/// restore the pre-signal register state. Called when the guest invokes
/// `rt_sigreturn(2)`. Returns the restored sigmask plus the values the caller's
/// `signal_restore` probe needs. Does NOT advance PC the way `complete_syscall`
/// does — the restored PC IS the next PC.
pub fn restore_sigframe<E: RegAccess + GuestMemory>(
    engine: &mut E,
    fpsimd_enabled: bool,
) -> Result<SigframeRestore, TrapError> {
    let sp = engine.get_reg(Reg::Sp)?;
    let frame_size = core::mem::size_of::<carrick_abi::CarrickSigframe>();
    // rt_sigreturn restores from the rt_sigframe the handler is returning
    // through, which the AArch64 kernel ABI places at SP (siginfo@0,
    // ucontext next). For a native guest this is carrick's own frame, with
    // the private magic intact. Apple Rosetta runs the x86 handler out of
    // carrick's frame, then rebuilds a FRESH, standard rt_sigframe at a new
    // SP and rt_sigreturns through THAT — it carries a valid AArch64
    // ucontext but NOT carrick's private magic (and the original frame is
    // overwritten). Either way the authoritative resume state is
    // ucontext.uc_mcontext at SP, exactly as the Linux kernel restores it;
    // we no longer require the private magic, which cannot survive Rosetta.
    let bytes = engine
        .read_bytes(sp, frame_size)
        .map_err(|e| TrapError::Hypervisor(format!("sigframe read failed: {e}")))?;
    let frame = carrick_abi::CarrickSigframe::read_from_bytes(&bytes)
        .map_err(|_| TrapError::Hypervisor("sigframe decode failed".to_string()))?;
    let magic = frame.magic;

    // `frame` is `#[repr(C, packed)]` so we cannot borrow individual
    // fields. Copy out the Linux ucontext first; SA_SIGINFO handlers may
    // mutate it before invoking rt_sigreturn.
    let ucontext = frame.ucontext;
    let restored_sigmask = ucontext.uc_sigmask;
    let mcontext = ucontext.uc_mcontext;
    // Linux validates the regs before applying them (`valid_user_regs`); the
    // load-bearing invariant is that the resume PSTATE targets EL0. A bogus
    // SP (rt_sigreturn called outside a handler, or a corrupt frame) would
    // yield a non-EL0 / garbage PSTATE — refuse rather than wedge the vCPU.
    // This replaces the private-magic gate, which Rosetta's reconstructed
    // frame legitimately lacks.
    let resume_pstate = mcontext.pstate;
    if resume_pstate & 0b1111 != 0 {
        return Err(TrapError::Hypervisor(format!(
            "rt_sigreturn: frame at SP_EL0=0x{sp:x} has non-EL0 PSTATE 0x{resume_pstate:x} (magic 0x{magic:x})"
        )));
    }
    let saved_x = mcontext.regs;
    for (i, value) in saved_x.iter().enumerate() {
        engine.set_reg(Reg::X(i as u32), *value)?;
    }
    // Restore V0–V31 + FPSR/FPCR from the fpsimd_context the matching
    // build_sigframe stored (a handler may have mutated it). Skip silently if
    // the record's magic is absent (older/foreign frame) — never restore
    // garbage over the vector registers.
    restore_fpsimd(engine, &mcontext, fpsimd_enabled)?;
    let saved_pc = mcontext.pc;
    let saved_sp = mcontext.sp;
    let saved_spsr = mcontext.pstate;
    engine.set_reg(Reg::ElrEl1, saved_pc)?;
    engine.set_reg(Reg::Sp, saved_sp)?;
    engine.set_reg(Reg::SpsrEl1, saved_spsr)?;
    Ok(SigframeRestore {
        sigmask: restored_sigmask,
        saved_pc,
        frame_sp: sp,
        magic,
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
    let frame_len = u64::try_from(frame_len)
        .map_err(|_| TrapError::Hypervisor("sigframe length does not fit u64".to_string()))?;
    let aligned_len = frame_len
        .checked_add(15)
        .map(|len| len & !15u64)
        .ok_or_else(|| TrapError::Hypervisor("sigframe length overflowed".to_string()))?;
    let stack_base = match altstack {
        Some((ss_sp, ss_size)) => {
            let top = ss_sp.checked_add(ss_size).ok_or_else(|| {
                TrapError::Hypervisor("signal alt stack top overflowed".to_string())
            })?;
            // If the interrupted code is ALREADY running on the alternate
            // signal stack, a nested SA_ONSTACK delivery must continue DOWN
            // from the current SP — not reset to the top, which would push the
            // new frame on top of the live parent handler's frame and clobber
            // it (glibc's `*** stack smashing detected ***`). This is exactly
            // the kernel's `on_sig_stack()` check. CPython faulthandler's
            // SA_NODEFER|SA_ONSTACK handler re-enters itself via chain=True, so
            // the second frame lands here.
            if saved_sp > ss_sp && saved_sp <= top {
                saved_sp
            } else {
                top
            }
        }
        None => saved_sp,
    };
    stack_base
        .checked_sub(aligned_len)
        .map(|sp| sp & !15u64)
        .ok_or_else(|| TrapError::Hypervisor("sigframe push underflowed stack".to_string()))
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
