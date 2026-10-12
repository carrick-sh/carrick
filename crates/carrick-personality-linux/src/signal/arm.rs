//! Pure AArch64 Linux rt-frame codec for the admitted FPSIMD/ESR ABI.
//!
//! Authority: sigreturn(2), the public arm64 SVE ABI documentation (signal
//! handling/return), and Dave Martin's Arm presentation, Linux Plumbers 2017,
//! slides 10-12. No machine access: callers supply a snapshot or an admitted
//! byte extent and publish only a successfully decoded context.
//!
//! SVE/SME and out-of-line extra_context state are not admitted by this lane.
//! Such records are refused rather than ignored or followed into guest memory.

use carrick_guest_arch::UserVa;
use carrick_signal_core::{SignalSet, policy::SigBlockMask};
use carrick_syscall_abi::{
    AARCH64_EL0_USER_PSTATE_MASK, LINUX_AARCH64_ESR_MAGIC, LINUX_FPSIMD_MAGIC, LinuxFpsimdContext,
    LinuxSiginfo, LinuxSignalContext, LinuxSignalStack, LinuxUcontext,
};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

/// Public Linux rt_sigframe prefix. There is no Carrick authentication trailer.
#[repr(C, packed)]
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
pub struct RtSigframe {
    pub siginfo: LinuxSiginfo,
    pub ucontext: LinuxUcontext,
}

/// The public frame followed by an ordinary AAPCS64 FP/LR unwind record.
#[repr(C, packed)]
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
pub struct SignalFrame {
    pub rt: RtSigframe,
    pub frame_record: [u64; 2],
}

pub const PUBLIC_FRAME_LEN: usize = core::mem::size_of::<RtSigframe>();
pub const FRAME_RECORD_OFFSET: usize = core::mem::offset_of!(SignalFrame, frame_record);
pub const UCONTEXT_OFFSET: usize = core::mem::offset_of!(RtSigframe, ucontext);
const FP_LEN: usize = core::mem::size_of::<LinuxFpsimdContext>();

const _: () = assert!(UCONTEXT_OFFSET == 128 && PUBLIC_FRAME_LEN.is_multiple_of(16));

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameError {
    InvalidContext,
    InvalidRecord,
    UnsupportedRecord,
    Truncated,
    StackOverflow,
    StackUnderflow,
}

/// Validated restore data. Obtaining this value never changes caller state.
pub struct ResumeContext {
    pub regs: [u64; 31],
    pub pc: UserVa,
    pub sp: UserVa,
    pub pstate: u64,
    pub mask: SigBlockMask,
    pub stack: LinuxSignalStack,
    pub fpsimd: Option<LinuxFpsimdContext>,
}

fn validate_pstate(pstate: u64) -> Result<(), FrameError> {
    if pstate & !AARCH64_EL0_USER_PSTATE_MASK != 0 {
        return Err(FrameError::InvalidContext);
    }
    Ok(())
}

fn validate_context(context: &LinuxSignalContext) -> Result<(), FrameError> {
    validate_pstate(context.pstate)?;
    if context.sp & 15 != 0 || context.pc & 3 != 0 {
        return Err(FrameError::InvalidContext);
    }
    Ok(())
}

/// Encode the public context, optional admitted extension records, and FP/LR.
/// The caller resolves restart state and selects the authoritative PSTATE.
pub fn encode(
    mut context: LinuxSignalContext,
    stack: LinuxSignalStack,
    mask: SigBlockMask,
    siginfo: LinuxSiginfo,
    fpsimd: Option<LinuxFpsimdContext>,
    esr: Option<u64>,
) -> Result<SignalFrame, FrameError> {
    // Fault delivery preserves the interrupted PC/SP, including a bad
    // alignment that the handler needs to inspect or repair. Only decode
    // admits those fields as resume authority.
    validate_pstate(context.pstate)?;
    context.__reserved.fill(0);
    let mut offset = 0;
    if let Some(fp) = fpsimd {
        if fp.magic != LINUX_FPSIMD_MAGIC || fp.size as usize != FP_LEN {
            return Err(FrameError::InvalidRecord);
        }
        context.__reserved[..FP_LEN].copy_from_slice(fp.as_bytes());
        offset = FP_LEN;
    }
    if let Some(esr) = esr {
        context.__reserved[offset..offset + 4]
            .copy_from_slice(&LINUX_AARCH64_ESR_MAGIC.to_le_bytes());
        context.__reserved[offset + 4..offset + 8].copy_from_slice(&16_u32.to_le_bytes());
        context.__reserved[offset + 8..offset + 16].copy_from_slice(&esr.to_le_bytes());
    }
    let frame_record = [context.regs[29], context.regs[30]];
    let mut ucontext = LinuxUcontext::empty();
    ucontext.uc_mcontext = context;
    ucontext.uc_stack = stack;
    ucontext.uc_sigmask = mask.signals().bits();
    Ok(SignalFrame {
        rt: RtSigframe { siginfo, ucontext },
        frame_record,
    })
}

/// Decode only the public frame from the caller's admitted extent. Trailing
/// private data is neither read nor required. All extension records are walked
/// before returning any resume authority; the 4 KiB reserved area is the bound.
pub fn decode(
    bytes: &[u8],
    frame_sp: UserVa,
    require_fpsimd: bool,
) -> Result<ResumeContext, FrameError> {
    if frame_sp.raw() & 15 != 0 {
        return Err(FrameError::InvalidContext);
    }
    let bytes = bytes.get(..PUBLIC_FRAME_LEN).ok_or(FrameError::Truncated)?;
    let frame = RtSigframe::read_from_bytes(bytes).map_err(|_| FrameError::Truncated)?;
    let context = frame.ucontext.uc_mcontext;
    validate_context(&context)?;
    let fpsimd = decode_records(&context.__reserved, require_fpsimd)?;
    Ok(ResumeContext {
        regs: context.regs,
        pc: UserVa::new(context.pc),
        sp: UserVa::new(context.sp),
        pstate: context.pstate,
        mask: SigBlockMask::blocking_all_of(SignalSet::from_bits(frame.ucontext.uc_sigmask)),
        stack: frame.ucontext.uc_stack,
        fpsimd,
    })
}

fn decode_records(
    records: &[u8],
    require_fpsimd: bool,
) -> Result<Option<LinuxFpsimdContext>, FrameError> {
    let mut offset = 0;
    let mut fpsimd = None;
    let mut saw_esr = false;
    loop {
        let header = records
            .get(offset..offset + 8)
            .ok_or(FrameError::Truncated)?;
        let magic = u32::from_le_bytes(header[..4].try_into().map_err(|_| FrameError::Truncated)?);
        let size =
            u32::from_le_bytes(header[4..].try_into().map_err(|_| FrameError::Truncated)?) as usize;
        if magic == 0 && size == 0 {
            if require_fpsimd && fpsimd.is_none() {
                return Err(FrameError::InvalidRecord);
            }
            return Ok(fpsimd);
        }
        if magic == 0 || size < 16 || size & 15 != 0 {
            return Err(FrameError::InvalidRecord);
        }
        let end = offset.checked_add(size).ok_or(FrameError::Truncated)?;
        let record = records.get(offset..end).ok_or(FrameError::Truncated)?;
        match magic {
            LINUX_FPSIMD_MAGIC if fpsimd.is_none() && size == FP_LEN => {
                fpsimd = Some(
                    LinuxFpsimdContext::read_from_bytes(record)
                        .map_err(|_| FrameError::InvalidRecord)?,
                );
            }
            LINUX_AARCH64_ESR_MAGIC if !saw_esr && size == 16 => saw_esr = true,
            LINUX_FPSIMD_MAGIC | LINUX_AARCH64_ESR_MAGIC => return Err(FrameError::InvalidRecord),
            _ => return Err(FrameError::UnsupportedRecord),
        }
        offset = end;
    }
}

/// Select the current or alternate stack and push a 16-byte-aligned extent.
/// A nested SA_ONSTACK delivery keeps growing down from the interrupted SP.
pub fn stack_pointer(
    saved_sp: UserVa,
    altstack: Option<(UserVa, u64)>,
    frame_len: usize,
) -> Result<UserVa, FrameError> {
    let frame_len = u64::try_from(frame_len).map_err(|_| FrameError::StackOverflow)?;
    let aligned_len = frame_len.checked_add(15).ok_or(FrameError::StackOverflow)? & !15;
    let saved_sp = saved_sp.raw();
    let stack_base = match altstack {
        Some((ss_sp, ss_size)) => {
            let ss_sp = ss_sp.raw();
            let top = ss_sp
                .checked_add(ss_size)
                .ok_or(FrameError::StackOverflow)?;
            if saved_sp > ss_sp && saved_sp <= top {
                saved_sp
            } else {
                top
            }
        }
        None => saved_sp,
    };
    Ok(UserVa::new(
        stack_base
            .checked_sub(aligned_len)
            .ok_or(FrameError::StackUnderflow)?
            & !15,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid() -> SignalFrame {
        let mut context = LinuxSignalContext::empty();
        context.pc = 0x10000;
        context.sp = 0x20000;
        encode(
            context,
            LinuxSignalStack::empty(),
            SigBlockMask::blocking_all_of(SignalSet::EMPTY),
            LinuxSiginfo::empty(),
            Some(LinuxFpsimdContext::empty()),
            None,
        )
        .unwrap()
    }

    #[test]
    fn public_prefix_alone_is_sufficient_and_truncation_is_refused() {
        let frame = valid();
        let bytes = frame.rt.as_bytes();
        assert_eq!(bytes.len(), 128 + core::mem::size_of::<LinuxUcontext>());
        assert!(decode(bytes, UserVa::new(0x40000), true).is_ok());
        assert!(decode(&bytes[..bytes.len() - 1], UserVa::new(0x40000), true).is_err());
        assert!(decode(bytes, UserVa::new(0x40008), true).is_err());
    }

    #[test]
    fn every_record_length_is_bounded_and_aligned() {
        for size in [0_u32, 8, 15, 17, 527, 529, 4096, u32::MAX] {
            let mut frame = valid();
            frame.rt.ucontext.uc_mcontext.__reserved[4..8].copy_from_slice(&size.to_le_bytes());
            assert!(decode(frame.rt.as_bytes(), UserVa::new(0x40000), true).is_err());
        }
    }

    #[test]
    fn duplicate_esr_and_unadmitted_extensions_are_refused() {
        for magic in [
            LINUX_AARCH64_ESR_MAGIC,
            0x4558_5401,
            0x5356_4501,
            0xdead_beef,
        ] {
            let mut frame = valid();
            let records = &mut frame.rt.ucontext.uc_mcontext.__reserved;
            records[528..532].copy_from_slice(&LINUX_AARCH64_ESR_MAGIC.to_le_bytes());
            records[532..536].copy_from_slice(&16_u32.to_le_bytes());
            records[544..548].copy_from_slice(&magic.to_le_bytes());
            records[548..552].copy_from_slice(&16_u32.to_le_bytes());
            assert!(decode(frame.rt.as_bytes(), UserVa::new(0x40000), true).is_err());
        }
    }

    #[test]
    fn termination_at_the_extent_boundary_is_walked() {
        // A record can end at the bound, but a terminator must still fit.
        let mut records = [0; 16];
        records[..4].copy_from_slice(&LINUX_AARCH64_ESR_MAGIC.to_le_bytes());
        records[4..8].copy_from_slice(&16_u32.to_le_bytes());
        assert!(decode_records(&records, false).is_err());
        let mut with_terminator = [0; 24];
        with_terminator[..16].copy_from_slice(&records);
        assert!(decode_records(&with_terminator, false).is_ok());
    }
}
