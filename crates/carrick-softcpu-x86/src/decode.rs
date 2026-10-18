//! x86_64 instruction decoder and classifier for `carrick-softcpu-x86`.

use iced_x86::{
    Code, Decoder, DecoderOptions, FlowControl, Instruction, Mnemonic, OpKind, Register,
};

/// Sub-classification of control-flow terminators.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CflowKind {
    DirectJump { target: u64 },
    IndirectJump,
    ConditionalBranch { target: u64, fallthrough: u64 },
    DirectCall { target: u64, return_va: u64 },
    IndirectCall { return_va: u64 },
    Return { pop_bytes: u16 },
}

/// Privileged and sensitive instructions classified as block exits (§3.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SensitiveOp {
    Iretq,
    Sysret,
    Swapgs,
    Wrmsr,
    Rdmsr,
    MovFromCr { cr: u8, gpr: usize },
    MovToCr { cr: u8, gpr: usize },
    Xsetbv,
    Lgdt,
    Lidt,
    Ltr,
    Invlpg,
    OutImm { port: u8, size: u8 },
    OutDx { size: u8 },
    InImm { port: u8, size: u8 },
    InDx { size: u8 },
    Cli,
    Sti,
    Hlt,
    Clac,
    Stac,
    Cpuid,
    Rdtsc,
    Rdtscp,
    Xgetbv,
    Rdpkru,
    Wrpkru,
    Rdssp { reg: usize, is_64: bool },
    Fxsave,
    Fxrstor,
    Xsave,
    Xsaveopt,
    Xsavec,
    Xrstor,
}

impl SensitiveOp {
    /// Returns `true` if executing this instruction at `CPL == 3` must raise `#GP(0)`.
    #[must_use]
    pub const fn is_privileged(self) -> bool {
        !matches!(
            self,
            Self::Cpuid
                | Self::Rdtsc
                | Self::Rdtscp
                | Self::Xgetbv
                | Self::Rdpkru
                | Self::Wrpkru
                | Self::Rdssp { .. }
                | Self::Fxsave
                | Self::Fxrstor
                | Self::Xsave
                | Self::Xsaveopt
                | Self::Xsavec
                | Self::Xrstor
        )
    }
}

/// Top-level classification of a decoded x86_64 instruction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InsnClass {
    Body,
    Syscall,
    ControlFlow(CflowKind),
    Sensitive(SensitiveOp),
    InvalidOpcode,
}

/// One decoded x86_64 instruction and its block-planning metadata.
#[derive(Clone, Debug)]
pub struct DecodedInsn {
    pub va: u64,
    pub len: usize,
    pub class: InsnClass,
    pub raw: Instruction,
    pub rip_relative_target: Option<u64>,
    pub fs_relative: bool,
    pub gs_relative: bool,
}

/// Map an `iced_x86::Register` to its 0..16 architectural GPR index.
#[must_use]
pub const fn gpr_index(reg: Register) -> Option<usize> {
    match reg {
        Register::AL | Register::AH | Register::AX | Register::EAX | Register::RAX => Some(0),
        Register::CL | Register::CH | Register::CX | Register::ECX | Register::RCX => Some(1),
        Register::DL | Register::DH | Register::DX | Register::EDX | Register::RDX => Some(2),
        Register::BL | Register::BH | Register::BX | Register::EBX | Register::RBX => Some(3),
        Register::SPL | Register::SP | Register::ESP | Register::RSP => Some(4),
        Register::BPL | Register::BP | Register::EBP | Register::RBP => Some(5),
        Register::SIL | Register::SI | Register::ESI | Register::RSI => Some(6),
        Register::DIL | Register::DI | Register::EDI | Register::RDI => Some(7),
        Register::R8L | Register::R8W | Register::R8D | Register::R8 => Some(8),
        Register::R9L | Register::R9W | Register::R9D | Register::R9 => Some(9),
        Register::R10L | Register::R10W | Register::R10D | Register::R10 => Some(10),
        Register::R11L | Register::R11W | Register::R11D | Register::R11 => Some(11),
        Register::R12L | Register::R12W | Register::R12D | Register::R12 => Some(12),
        Register::R13L | Register::R13W | Register::R13D | Register::R13 => Some(13),
        Register::R14L | Register::R14W | Register::R14D | Register::R14 => Some(14),
        Register::R15L | Register::R15W | Register::R15D | Register::R15 => Some(15),
        _ => None,
    }
}

const fn cr_number(reg: Register) -> Option<u8> {
    match reg {
        Register::CR0 => Some(0),
        Register::CR2 => Some(2),
        Register::CR3 => Some(3),
        Register::CR4 => Some(4),
        Register::CR8 => Some(8),
        _ => None,
    }
}

/// Detect `rdsspd r32` (`F3 0F 1E C8..CF`) and `rdsspq r64` (`F3 48/49 0F 1E C8..CF`).
fn decode_rdssp(bytes: &[u8]) -> Option<(usize, SensitiveOp)> {
    if bytes.first().copied() != Some(0xF3) {
        return None;
    }
    let (rex, idx) = match bytes.get(1).copied()? {
        b if (0x40..=0x4F).contains(&b) => (b, 2usize),
        _ => (0u8, 1usize),
    };
    if bytes.get(idx).copied()? != 0x0F || bytes.get(idx + 1).copied()? != 0x1E {
        return None;
    }
    let modrm = bytes.get(idx + 2).copied()?;
    if !(0xC8..=0xCF).contains(&modrm) {
        return None;
    }
    let reg = ((modrm & 0x07) as usize) | (if (rex & 0x01) != 0 { 8 } else { 0 });
    Some((
        idx + 3,
        SensitiveOp::Rdssp {
            reg,
            is_64: (rex & 0x08) != 0,
        },
    ))
}

/// Decode and classify one x86_64 instruction at `va` from `bytes` (up to 15 bytes).
#[must_use]
pub fn classify(bytes: &[u8], va: u64) -> Option<DecodedInsn> {
    if bytes.is_empty() {
        return None;
    }
    if let Some((len, rdssp_op)) = decode_rdssp(bytes) {
        return Some(DecodedInsn {
            va,
            len,
            class: InsnClass::Sensitive(rdssp_op),
            raw: Instruction::default(),
            rip_relative_target: None,
            fs_relative: false,
            gs_relative: false,
        });
    }

    let insn = Decoder::with_ip(64, bytes, va, DecoderOptions::NONE).decode();
    let (len, seg) = (insn.len().max(1), insn.segment_prefix());
    if insn.is_invalid() {
        return Some(DecodedInsn {
            va,
            len,
            class: InsnClass::InvalidOpcode,
            raw: insn,
            rip_relative_target: None,
            fs_relative: false,
            gs_relative: false,
        });
    }

    let next_va = va.wrapping_add(len as u64);
    let rip_relative_target = (0..insn.op_count())
        .any(|i| insn.op_kind(i) == OpKind::Memory && insn.is_ip_rel_memory_operand())
        .then(|| insn.ip_rel_memory_address());

    Some(DecodedInsn {
        va,
        len,
        class: classify_insn(&insn, next_va),
        raw: insn,
        rip_relative_target,
        fs_relative: seg == Register::FS,
        gs_relative: seg == Register::GS,
    })
}

fn classify_insn(insn: &Instruction, next_va: u64) -> InsnClass {
    let simple = match insn.mnemonic() {
        Mnemonic::Syscall => return InsnClass::Syscall,
        Mnemonic::Ud0 | Mnemonic::Ud1 | Mnemonic::Ud2 => return InsnClass::InvalidOpcode,
        Mnemonic::Iretq | Mnemonic::Iretd | Mnemonic::Iret => Some(SensitiveOp::Iretq),
        Mnemonic::Sysretq | Mnemonic::Sysret => Some(SensitiveOp::Sysret),
        Mnemonic::Swapgs => Some(SensitiveOp::Swapgs),
        Mnemonic::Wrmsr => Some(SensitiveOp::Wrmsr),
        Mnemonic::Rdmsr => Some(SensitiveOp::Rdmsr),
        Mnemonic::Xsetbv => Some(SensitiveOp::Xsetbv),
        Mnemonic::Lgdt => Some(SensitiveOp::Lgdt),
        Mnemonic::Lidt => Some(SensitiveOp::Lidt),
        Mnemonic::Ltr => Some(SensitiveOp::Ltr),
        Mnemonic::Invlpg => Some(SensitiveOp::Invlpg),
        Mnemonic::Cli => Some(SensitiveOp::Cli),
        Mnemonic::Sti => Some(SensitiveOp::Sti),
        Mnemonic::Hlt => Some(SensitiveOp::Hlt),
        Mnemonic::Clac => Some(SensitiveOp::Clac),
        Mnemonic::Stac => Some(SensitiveOp::Stac),
        Mnemonic::Cpuid => Some(SensitiveOp::Cpuid),
        Mnemonic::Rdtsc => Some(SensitiveOp::Rdtsc),
        Mnemonic::Rdtscp => Some(SensitiveOp::Rdtscp),
        Mnemonic::Xgetbv => Some(SensitiveOp::Xgetbv),
        Mnemonic::Rdpkru => Some(SensitiveOp::Rdpkru),
        Mnemonic::Wrpkru => Some(SensitiveOp::Wrpkru),
        Mnemonic::Fxsave | Mnemonic::Fxsave64 => Some(SensitiveOp::Fxsave),
        Mnemonic::Fxrstor | Mnemonic::Fxrstor64 => Some(SensitiveOp::Fxrstor),
        Mnemonic::Xsave | Mnemonic::Xsave64 => Some(SensitiveOp::Xsave),
        Mnemonic::Xsaveopt | Mnemonic::Xsaveopt64 => Some(SensitiveOp::Xsaveopt),
        Mnemonic::Xsavec | Mnemonic::Xsavec64 => Some(SensitiveOp::Xsavec),
        Mnemonic::Xrstor | Mnemonic::Xrstor64 => Some(SensitiveOp::Xrstor),
        _ => None,
    };
    if let Some(op) = simple {
        return InsnClass::Sensitive(op);
    }

    match insn.mnemonic() {
        Mnemonic::Out | Mnemonic::In => {
            let (is_out, size) = match insn.code() {
                Code::Out_imm8_AL | Code::Out_DX_AL => (true, 1),
                Code::Out_imm8_AX | Code::Out_DX_AX => (true, 2),
                Code::Out_imm8_EAX | Code::Out_DX_EAX => (true, 4),
                Code::In_AL_imm8 | Code::In_AL_DX => (false, 1),
                Code::In_AX_imm8 | Code::In_AX_DX => (false, 2),
                Code::In_EAX_imm8 | Code::In_EAX_DX => (false, 4),
                _ => return InsnClass::InvalidOpcode,
            };
            let is_imm =
                insn.op0_kind() == OpKind::Immediate8 || insn.op1_kind() == OpKind::Immediate8;
            let op = match (is_out, is_imm) {
                (true, true) => SensitiveOp::OutImm {
                    port: insn.immediate8(),
                    size,
                },
                (true, false) => SensitiveOp::OutDx { size },
                (false, true) => SensitiveOp::InImm {
                    port: insn.immediate8(),
                    size,
                },
                (false, false) => SensitiveOp::InDx { size },
            };
            return InsnClass::Sensitive(op);
        }
        Mnemonic::Mov => {
            let (k0, k1, r0, r1) = (
                insn.op0_kind(),
                insn.op1_kind(),
                insn.op0_register(),
                insn.op1_register(),
            );
            if k0 == OpKind::Register && k1 == OpKind::Register {
                if let (Some(gpr), Some(cr)) = (gpr_index(r0), cr_number(r1)) {
                    return InsnClass::Sensitive(SensitiveOp::MovFromCr { cr, gpr });
                }
                if let (Some(cr), Some(gpr)) = (cr_number(r0), gpr_index(r1)) {
                    return InsnClass::Sensitive(SensitiveOp::MovToCr { cr, gpr });
                }
                if r0.is_segment_register() || r1.is_segment_register() || r0.is_dr() || r1.is_dr()
                {
                    return InsnClass::InvalidOpcode;
                }
            } else if (k0 == OpKind::Register && r0.is_segment_register())
                || (k1 == OpKind::Register && r1.is_segment_register())
            {
                return InsnClass::InvalidOpcode;
            }
        }
        Mnemonic::Rdfsbase
        | Mnemonic::Rdgsbase
        | Mnemonic::Wrfsbase
        | Mnemonic::Wrgsbase
        | Mnemonic::Sgdt
        | Mnemonic::Sidt
        | Mnemonic::Sldt
        | Mnemonic::Lldt
        | Mnemonic::Str
        | Mnemonic::Verr
        | Mnemonic::Verw
        | Mnemonic::Smsw
        | Mnemonic::Lmsw
        | Mnemonic::Invd
        | Mnemonic::Wbinvd
        | Mnemonic::Clts => return InsnClass::InvalidOpcode,
        _ => {}
    }

    let target = insn.near_branch_target();
    match insn.flow_control() {
        FlowControl::Next => InsnClass::Body,
        FlowControl::UnconditionalBranch if insn.is_jmp_short_or_near() => {
            InsnClass::ControlFlow(CflowKind::DirectJump { target })
        }
        FlowControl::IndirectBranch if insn.is_jmp_near_indirect() => {
            InsnClass::ControlFlow(CflowKind::IndirectJump)
        }
        FlowControl::ConditionalBranch
            if insn.is_jcc_short_or_near()
                || insn.is_jcx_short()
                || insn.is_loop()
                || insn.is_loopcc() =>
        {
            InsnClass::ControlFlow(CflowKind::ConditionalBranch {
                target,
                fallthrough: next_va,
            })
        }
        FlowControl::Call if insn.is_call_near() => InsnClass::ControlFlow(CflowKind::DirectCall {
            target,
            return_va: next_va,
        }),
        FlowControl::IndirectCall if insn.is_call_near_indirect() => {
            InsnClass::ControlFlow(CflowKind::IndirectCall { return_va: next_va })
        }
        FlowControl::Return => match insn.code() {
            Code::Retnq | Code::Retnd => InsnClass::ControlFlow(CflowKind::Return { pop_bytes: 0 }),
            Code::Retnq_imm16 | Code::Retnd_imm16 => InsnClass::ControlFlow(CflowKind::Return {
                pop_bytes: insn.immediate16(),
            }),
            _ => InsnClass::InvalidOpcode,
        },
        _ => InsnClass::InvalidOpcode,
    }
}
