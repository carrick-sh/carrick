//! Variable-length x86_64 instruction classification for the DSR block
//! planner.
//!
//! `classify` decodes ONE instruction at a guest VA and answers the only
//! questions the planner asks: how long is it, does it copy through
//! verbatim, is it sensitive (and which kind), does it end the block
//! (control flow), or is it undecodable/privileged (typed, fail-closed).
//! The AArch64 lane answers the same questions over fixed 4-byte words in
//! `carrick-dsr-aarch64`'s `decode::classify`; the per-ISA IRs stay private
//! to each arch crate by design.

use iced_x86::{
    Code, Decoder, DecoderOptions, FlowControl, Instruction, InstructionInfoFactory, Register,
};

/// The x86_64 sensitive-instruction catalog (design-doc fixed set). Each is
/// an instruction the translator must REWRITE rather than copy: it either
/// enters the kernel, reads virtualized time/identity, or touches the
/// guest-TLS segment bases the host also depends on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X86SensitiveKind {
    /// `syscall` — the Linux 64-bit syscall gate.
    Syscall,
    /// `int 0x80` — the legacy 32-bit-ABI syscall gate (some static
    /// binaries still use it).
    Int80,
    /// `rdtsc` / `rdtscp` — virtualized like the AArch64 CNTVCT reads.
    Rdtsc { with_processor_id: bool },
    /// `cpuid` — identity/feature virtualization.
    Cpuid,
    /// `rdfsbase`/`wrfsbase`/`rdgsbase`/`wrgsbase` — direct segment-base
    /// access (FSGSBASE); interacts with `arch_prctl` TLS emulation.
    SegmentBase { write: bool, gs: bool },
    /// A gs-prefixed memory access. `fs:` accesses copy through (the gateway
    /// installs the guest fs base for the whole translated run — see
    /// `gateway_x86_64.S`), but 64-bit Linux userspace leaves `%gs` to
    /// niche uses the lane has no virtualization story for yet, so they
    /// stay a typed sensitive exit (fail-closed at emit).
    SegmentPrefixed { gs: bool },
}

/// One classified instruction. `len` is the decoded byte length — the
/// planner's stride (x86 is variable-length; there is no `pc + 4`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X86Classified {
    pub len: u8,
    pub class: X86InstClass,
    /// Whether the instruction touches SSE/AVX (xmm/ymm/zmm), x87 (st), or
    /// MMX (mm) register state. The block planner ORs this across a block so
    /// the gateway can SKIP the `fxsave`/`fxrstor` of the 512-byte FPU area
    /// around blocks that never touch it (the common case in integer-heavy
    /// code). Conservative: any FPU/vector register use — read or write,
    /// explicit or implicit — sets it, so skipping is only ever done when the
    /// block provably leaves FPU/vector state untouched.
    pub uses_fpu: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X86InstClass {
    /// Copies through verbatim (includes `lock`-prefixed RMWs: x86 has no
    /// exclusive monitors, so atomics need no fusion apparatus).
    Copy,
    /// Must be rewritten at a typed boundary.
    Sensitive(X86SensitiveKind),
    /// Ends the basic block (branch/call/ret/jcc); the M2 plan IR will
    /// carry targets/kinds — the classifier only marks the boundary.
    ControlFlow,
    /// Decodable but not translatable (privileged/system instructions);
    /// fail-closed at plan time.
    Unsupported,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum X86DecodeError {
    #[error("x86 DSR could not decode instruction bytes at guest VA 0x{va:x}")]
    Undecodable { va: u64 },
    #[error("x86 DSR needs more bytes at guest VA 0x{va:x} (had {available})")]
    Truncated { va: u64, available: usize },
}

/// Classify the single instruction starting at `bytes[0]`, which the caller
/// asserts sits at guest VA `va` (used for RIP-relative correctness in the
/// eventual plan IR and for error reporting today). `bytes` may extend past
/// the instruction; at least the full instruction must be present (x86 max
/// is 15 bytes).
pub fn classify(bytes: &[u8], va: u64) -> Result<X86Classified, X86DecodeError> {
    if bytes.is_empty() {
        return Err(X86DecodeError::Truncated { va, available: 0 });
    }
    let mut decoder = Decoder::with_ip(64, bytes, va, DecoderOptions::NONE);
    let inst: Instruction = decoder.decode();
    if inst.is_invalid() {
        // iced reports truncation as invalid too; distinguish so the block
        // planner can re-fetch across a page boundary instead of failing.
        return if bytes.len() < 15 {
            Err(X86DecodeError::Truncated {
                va,
                available: bytes.len(),
            })
        } else {
            Err(X86DecodeError::Undecodable { va })
        };
    }
    let len = inst.len() as u8;
    let class = classify_decoded(&inst);
    let uses_fpu = instruction_uses_fpu(&inst);
    Ok(X86Classified {
        len,
        class,
        uses_fpu,
    })
}

/// Whether the instruction reads or writes any SSE/AVX (xmm/ymm/zmm), x87
/// (st), MMX (mm), or the SSE control/status word — including IMPLICIT uses
/// (e.g. x87 ops that reference `st` implicitly). Uses `InstructionInfoFactory`
/// so nothing FPU/vector escapes detection; the cost is paid once per block at
/// translation time (cached thereafter).
fn instruction_uses_fpu(inst: &Instruction) -> bool {
    // Instructions that touch the SSE control/status word or the whole FPU
    // area WITHOUT naming a vector register operand — they still mutate state
    // inside the fxsave image, so a block containing one must not skip the
    // save/restore.
    if matches!(
        inst.code(),
        Code::Ldmxcsr_m32
            | Code::Stmxcsr_m32
            | Code::VEX_Vldmxcsr_m32
            | Code::VEX_Vstmxcsr_m32
            | Code::Fxsave_m512byte
            | Code::Fxsave64_m512byte
            | Code::Fxrstor_m512byte
            | Code::Fxrstor64_m512byte
    ) {
        return true;
    }
    let mut info = InstructionInfoFactory::new();
    info.info(inst).used_registers().iter().any(|used| {
        let r = used.register();
        r.is_xmm() || r.is_ymm() || r.is_zmm() || r.is_st() || r.is_mm()
    })
}

fn classify_decoded(inst: &Instruction) -> X86InstClass {
    match inst.code() {
        Code::Syscall => return X86InstClass::Sensitive(X86SensitiveKind::Syscall),
        Code::Int_imm8 if inst.immediate8() == 0x80 => {
            return X86InstClass::Sensitive(X86SensitiveKind::Int80);
        }
        Code::Rdtsc => {
            return X86InstClass::Sensitive(X86SensitiveKind::Rdtsc {
                with_processor_id: false,
            });
        }
        Code::Rdtscp => {
            return X86InstClass::Sensitive(X86SensitiveKind::Rdtsc {
                with_processor_id: true,
            });
        }
        Code::Cpuid => return X86InstClass::Sensitive(X86SensitiveKind::Cpuid),
        Code::Rdfsbase_r32 | Code::Rdfsbase_r64 => {
            return X86InstClass::Sensitive(X86SensitiveKind::SegmentBase {
                write: false,
                gs: false,
            });
        }
        Code::Rdgsbase_r32 | Code::Rdgsbase_r64 => {
            return X86InstClass::Sensitive(X86SensitiveKind::SegmentBase {
                write: false,
                gs: true,
            });
        }
        Code::Wrfsbase_r32 | Code::Wrfsbase_r64 => {
            return X86InstClass::Sensitive(X86SensitiveKind::SegmentBase {
                write: true,
                gs: false,
            });
        }
        Code::Wrgsbase_r32 | Code::Wrgsbase_r64 => {
            return X86InstClass::Sensitive(X86SensitiveKind::SegmentBase {
                write: true,
                gs: true,
            });
        }
        _ => {}
    }
    // Segment-prefixed memory access. `fs:` (the guest-TLS surface) copies
    // through: the gateway swaps the real fs base to the guest's for the
    // whole translated run, so the copied access resolves against guest TLS
    // with zero rewriting. `gs:` stays fail-closed (checked before control
    // flow so a `jmp gs:[...]` oddity lands Sensitive, not ControlFlow).
    if inst.segment_prefix() == Register::GS {
        return X86InstClass::Sensitive(X86SensitiveKind::SegmentPrefixed { gs: true });
    }
    match inst.flow_control() {
        FlowControl::Next => {}
        FlowControl::UnconditionalBranch
        | FlowControl::IndirectBranch
        | FlowControl::ConditionalBranch
        | FlowControl::Return
        | FlowControl::Call
        | FlowControl::IndirectCall => return X86InstClass::ControlFlow,
        // int3/into/ud2/iret/xabort and every `Exception`-class or
        // interrupt flow: not translatable guest fast-path material.
        FlowControl::Interrupt | FlowControl::Exception | FlowControl::XbeginXabortXend => {
            return X86InstClass::Unsupported;
        }
    }
    if inst.is_privileged() {
        return X86InstClass::Unsupported;
    }
    X86InstClass::Copy
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one(bytes: &[u8]) -> X86Classified {
        classify(bytes, 0x40_0000).expect("classify")
    }

    #[test]
    fn syscall_gate_is_sensitive() {
        let c = one(&[0x0f, 0x05]);
        assert_eq!(c.len, 2);
        assert_eq!(c.class, X86InstClass::Sensitive(X86SensitiveKind::Syscall));
    }

    #[test]
    fn legacy_int80_gate_is_sensitive_and_other_ints_are_not_syscalls() {
        let c = one(&[0xcd, 0x80]);
        assert_eq!(c.class, X86InstClass::Sensitive(X86SensitiveKind::Int80));
        // int 0x3f is NOT a syscall gate — must not classify as Int80.
        let other = one(&[0xcd, 0x3f]);
        assert_ne!(
            other.class,
            X86InstClass::Sensitive(X86SensitiveKind::Int80)
        );
    }

    #[test]
    fn time_and_identity_reads_are_sensitive() {
        assert_eq!(
            one(&[0x0f, 0x31]).class,
            X86InstClass::Sensitive(X86SensitiveKind::Rdtsc {
                with_processor_id: false
            })
        );
        assert_eq!(
            one(&[0x0f, 0x01, 0xf9]).class,
            X86InstClass::Sensitive(X86SensitiveKind::Rdtsc {
                with_processor_id: true
            })
        );
        assert_eq!(
            one(&[0x0f, 0xa2]).class,
            X86InstClass::Sensitive(X86SensitiveKind::Cpuid)
        );
    }

    #[test]
    fn fsgsbase_instructions_are_sensitive() {
        // f3 48 0f ae c0    rdfsbase rax
        assert_eq!(
            one(&[0xf3, 0x48, 0x0f, 0xae, 0xc0]).class,
            X86InstClass::Sensitive(X86SensitiveKind::SegmentBase {
                write: false,
                gs: false
            })
        );
        // f3 48 0f ae d0    wrfsbase rax  (0f ae group: ModRM /2)
        assert_eq!(
            one(&[0xf3, 0x48, 0x0f, 0xae, 0xd0]).class,
            X86InstClass::Sensitive(X86SensitiveKind::SegmentBase {
                write: true,
                gs: false
            })
        );
        // f3 48 0f ae d8    wrgsbase rax  (ModRM /3)
        assert_eq!(
            one(&[0xf3, 0x48, 0x0f, 0xae, 0xd8]).class,
            X86InstClass::Sensitive(X86SensitiveKind::SegmentBase {
                write: true,
                gs: true
            })
        );
    }

    #[test]
    fn fs_prefixed_tls_access_copies_through_but_gs_stays_sensitive() {
        // 64 48 8b 04 25 28 00 00 00    mov rax, fs:[0x28]  (glibc canary read)
        // Copy-safe: the gateway installs the guest fs base for the whole
        // translated run, so the copied access hits guest TLS directly.
        let c = one(&[0x64, 0x48, 0x8b, 0x04, 0x25, 0x28, 0x00, 0x00, 0x00]);
        assert_eq!(c.len, 9);
        assert_eq!(c.class, X86InstClass::Copy);
        // 65 48 8b 04 25 28 00 00 00    mov rax, gs:[0x28] — no gs story yet.
        let g = one(&[0x65, 0x48, 0x8b, 0x04, 0x25, 0x28, 0x00, 0x00, 0x00]);
        assert_eq!(
            g.class,
            X86InstClass::Sensitive(X86SensitiveKind::SegmentPrefixed { gs: true })
        );
    }

    #[test]
    fn fpu_use_is_detected_for_the_gateway_save_skip() {
        // Integer ops: no FPU.
        assert!(!one(&[0x48, 0x89, 0xd8]).uses_fpu); // mov rax, rbx
        assert!(!one(&[0x48, 0x01, 0xd8]).uses_fpu); // add rax, rbx
        assert!(!one(&[0x90]).uses_fpu); // nop
        // SSE: movss xmm0, xmm1 (f3 0f 10 c1) touches xmm.
        assert!(one(&[0xf3, 0x0f, 0x10, 0xc1]).uses_fpu);
        // SSE2 packed: paddd xmm0, xmm1 (66 0f fe c1).
        assert!(one(&[0x66, 0x0f, 0xfe, 0xc1]).uses_fpu);
        // x87: fld st(0) implicitly (d9 c0) touches st.
        assert!(one(&[0xd9, 0xc0]).uses_fpu);
        // ldmxcsr [rax] (0f ae 10) touches the SSE control word with no xmm
        // operand — still must be flagged.
        assert!(one(&[0x0f, 0xae, 0x10]).uses_fpu);
    }

    #[test]
    fn plain_and_lock_prefixed_instructions_copy_through() {
        // 48 89 d8    mov rax, rbx
        assert_eq!(one(&[0x48, 0x89, 0xd8]).class, X86InstClass::Copy);
        // f0 48 0f c1 07    lock xadd [rdi], rax — atomics need NO fusion on x86.
        assert_eq!(
            one(&[0xf0, 0x48, 0x0f, 0xc1, 0x07]).class,
            X86InstClass::Copy
        );
        // Variable length is reported, not assumed: 48 b8 imm64 is 10 bytes.
        let c = one(&[0x48, 0xb8, 1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(c.len, 10);
        assert_eq!(c.class, X86InstClass::Copy);
    }

    #[test]
    fn control_flow_ends_blocks() {
        assert_eq!(one(&[0xc3]).class, X86InstClass::ControlFlow); // ret
        assert_eq!(one(&[0xeb, 0x02]).class, X86InstClass::ControlFlow); // jmp +2
        assert_eq!(one(&[0x74, 0x02]).class, X86InstClass::ControlFlow); // je +2
        assert_eq!(one(&[0xff, 0xd0]).class, X86InstClass::ControlFlow); // call rax
    }

    #[test]
    fn privileged_and_trap_instructions_fail_closed() {
        assert_eq!(one(&[0xf4]).class, X86InstClass::Unsupported); // hlt
        assert_eq!(one(&[0x0f, 0x0b]).class, X86InstClass::Unsupported); // ud2
        assert_eq!(one(&[0xcc]).class, X86InstClass::Unsupported); // int3
    }

    #[test]
    fn truncation_and_garbage_are_distinct_typed_errors() {
        // A lone REX prefix cannot decode — with few bytes it's Truncated
        // (the planner may re-fetch across a page boundary).
        assert!(matches!(
            classify(&[0x48], 0x1000),
            Err(X86DecodeError::Truncated { available: 1, .. })
        ));
        assert!(matches!(
            classify(&[], 0x1000),
            Err(X86DecodeError::Truncated { available: 0, .. })
        ));
    }
}
