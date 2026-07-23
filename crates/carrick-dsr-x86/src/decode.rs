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
    Code, CpuidFeature, Decoder, DecoderOptions, FlowControl, Instruction, InstructionInfoFactory,
    OpKind, Register,
};

/// Which long-mode XRSTOR encoding the guest used. The distinction affects
/// the legacy x87 instruction/data-pointer representation; neither form is
/// ever executed directly by the host.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X86XstateRestoreKind {
    Xrstor,
    Xrstor64,
}

/// Which user XSAVE-family encoding the guest used. Plain versus REX.W
/// affects the x87 pointer representation; compacted forms affect component
/// destinations. None of these opcodes is ever executed against guest memory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X86XstateSaveKind {
    Xsave,
    Xsave64,
    Xsaveopt,
    Xsaveopt64,
    Xsavec,
    Xsavec64,
}

impl X86XstateSaveKind {
    pub const fn is_64(self) -> bool {
        matches!(self, Self::Xsave64 | Self::Xsaveopt64 | Self::Xsavec64)
    }

    pub const fn is_compacted(self) -> bool {
        matches!(self, Self::Xsavec | Self::Xsavec64)
    }
}

/// Which 512-byte FXSAVE-family user-state transfer was decoded. These forms
/// have a distinct 16-byte alignment contract and never transfer AVX or newer
/// xstate components.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X86FxStateKind {
    Fxsave,
    Fxsave64,
    Fxrstor,
    Fxrstor64,
}

impl X86FxStateKind {
    pub const fn is_64(self) -> bool {
        matches!(self, Self::Fxsave64 | Self::Fxrstor64)
    }

    pub const fn is_save(self) -> bool {
        matches!(self, Self::Fxsave | Self::Fxsave64)
    }
}

/// Exact iced long-mode legacy x87 environment/state memory forms. The width
/// is part of the kind so the checked service never infers a 14/28 or 94/108
/// layout from host mode or executes a guest opcode to discover it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X86LegacyX87Kind {
    Fldenv14,
    Fldenv28,
    Fnstenv14,
    Fstenv14,
    Fnstenv28,
    Fstenv28,
    Frstor94,
    Frstor108,
    Fnsave94,
    Fsave94,
    Fnsave108,
    Fsave108,
}

impl X86LegacyX87Kind {
    pub const fn waits(self) -> bool {
        matches!(
            self,
            Self::Fldenv14
                | Self::Fldenv28
                | Self::Fstenv14
                | Self::Fstenv28
                | Self::Frstor94
                | Self::Frstor108
                | Self::Fsave94
                | Self::Fsave108
        )
    }

    pub const fn is_save(self) -> bool {
        matches!(
            self,
            Self::Fnstenv14
                | Self::Fstenv14
                | Self::Fnstenv28
                | Self::Fstenv28
                | Self::Fnsave94
                | Self::Fsave94
                | Self::Fnsave108
                | Self::Fsave108
        )
    }

    pub const fn includes_registers(self) -> bool {
        matches!(
            self,
            Self::Frstor94
                | Self::Frstor108
                | Self::Fnsave94
                | Self::Fsave94
                | Self::Fnsave108
                | Self::Fsave108
        )
    }

    pub const fn environment_len(self) -> usize {
        match self {
            Self::Fldenv14
            | Self::Fnstenv14
            | Self::Fstenv14
            | Self::Frstor94
            | Self::Fnsave94
            | Self::Fsave94 => 14,
            Self::Fldenv28
            | Self::Fnstenv28
            | Self::Fstenv28
            | Self::Frstor108
            | Self::Fnsave108
            | Self::Fsave108 => 28,
        }
    }
}

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
    /// `rdpkru`/`wrpkru` — virtualized because applying guest key-0 rights to
    /// the user-mode gateway would revoke its context and host-stack access.
    ProtectionKey { write: bool },
    /// `xgetbv` — masks the virtualized PKRU component from guest XCR0.
    ExtendedControl,
    /// User XSAVE/XSAVEOPT/XSAVEC forms — written through checked guest-memory
    /// copies from the authoritative snapshot, never by executing guest bytes.
    XstateSave(X86XstateSaveKind),
    /// `xrstor`/`xrstor64` — restored through checked guest-memory reads into
    /// the authoritative snapshot, never by executing guest bytes.
    XstateRestore(X86XstateRestoreKind),
    /// FXSAVE/FXSAVE64/FXRSTOR/FXRSTOR64 — checked 512-byte user-state transfer.
    FxState(X86FxStateKind),
    /// Legacy x87 environment/state transfer in its exact iced operand width.
    LegacyX87(X86LegacyX87Kind),
    /// Standalone FWAIT. It services the virtual pending x87 exception state
    /// without ever consulting or applying the host thread's physical x87 state.
    X87Wait,
    /// `rdsspd`/`rdsspq` with virtual CET shadow stacks disabled. Architecturally
    /// these preserve the destination and flags; they still exit so host CET
    /// state can never leak into the guest.
    ReadShadowStackPointer,
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
    // Iced's used-register list intentionally omits x87 environment/control
    // effects that have no ST operand (FLDCW, FNINIT, FRSTOR, ...). Its CPUID
    // metadata gives a complete fail-closed family boundary for those legacy
    // instructions. MMX catches registerless EMMS; FEMMS and WAIT need explicit
    // treatment because their feature tags are not uniformly FPU/MMX.
    if inst.cpuid_features().iter().any(|feature| {
        matches!(
            feature,
            CpuidFeature::FPU
                | CpuidFeature::FPU287
                | CpuidFeature::FPU287XL_ONLY
                | CpuidFeature::FPU387
                | CpuidFeature::FPU387SL_ONLY
                | CpuidFeature::MMX
        )
    }) || matches!(inst.code(), Code::Femms | Code::Wait)
    {
        return true;
    }

    // Instructions that touch control/status or whole extended-state areas
    // WITHOUT naming a vector register operand still require the gateway's
    // complete XSAVE/XRSTOR switch. RDPKRU/WRPKRU are sensitive-emulated and
    // therefore never reach this copy-through predicate.
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
            | Code::Xsave_mem
            | Code::Xsave64_mem
            | Code::Xrstor_mem
            | Code::Xrstor64_mem
            | Code::Xsaveopt_mem
            | Code::Xsaveopt64_mem
            | Code::Xsavec_mem
            | Code::Xsavec64_mem
            | Code::Xsaves_mem
            | Code::Xsaves64_mem
            | Code::Xrstors_mem
            | Code::Xrstors64_mem
            | Code::VEX_Ldtilecfg_m512
            | Code::VEX_Tilerelease
            | Code::VEX_Sttilecfg_m512
    ) {
        return true;
    }
    let mut info = InstructionInfoFactory::new();
    info.info(inst).used_registers().iter().any(|used| {
        let r = used.register();
        r.is_xmm()
            || r.is_ymm()
            || r.is_zmm()
            || r.is_k()
            || r.is_tmm()
            || r.is_bnd()
            || r.is_st()
            || r.is_mm()
    })
}

fn classify_decoded(inst: &Instruction) -> X86InstClass {
    // Carrick's virtual CET state is always disabled. RDSSP is architecturally
    // a destination- and flag-preserving compatibility no-op in that state,
    // but it must still exit so a host-enabled shadow stack can never leak.
    if matches!(inst.code(), Code::Rdsspd_r32 | Code::Rdsspq_r64) {
        return X86InstClass::Sensitive(X86SensitiveKind::ReadShadowStackPointer);
    }

    // These families carry constrained XSAVE components that Carrick does not
    // yet validate on sigreturn. Native CPUID/XGETBV mask them; fail closed for
    // raw instructions too rather than letting a guest bypass that contract.
    if inst.cpuid_features().iter().any(|feature| {
        matches!(
            feature,
            CpuidFeature::MPX
                | CpuidFeature::CET_SS
                | CpuidFeature::AMX_BF16
                | CpuidFeature::AMX_TILE
                | CpuidFeature::AMX_INT8
                | CpuidFeature::AMX_FP16
                | CpuidFeature::AMX_COMPLEX
        )
    }) {
        return X86InstClass::Unsupported;
    }

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
        Code::Rdpkru => {
            return X86InstClass::Sensitive(X86SensitiveKind::ProtectionKey { write: false });
        }
        Code::Wrpkru => {
            return X86InstClass::Sensitive(X86SensitiveKind::ProtectionKey { write: true });
        }
        Code::Xgetbv => return X86InstClass::Sensitive(X86SensitiveKind::ExtendedControl),
        Code::Fxsave_m512byte => {
            return X86InstClass::Sensitive(X86SensitiveKind::FxState(X86FxStateKind::Fxsave));
        }
        Code::Fxsave64_m512byte => {
            return X86InstClass::Sensitive(X86SensitiveKind::FxState(X86FxStateKind::Fxsave64));
        }
        Code::Fxrstor_m512byte => {
            return X86InstClass::Sensitive(X86SensitiveKind::FxState(X86FxStateKind::Fxrstor));
        }
        Code::Fxrstor64_m512byte => {
            return X86InstClass::Sensitive(X86SensitiveKind::FxState(X86FxStateKind::Fxrstor64));
        }
        Code::Fldenv_m14byte => {
            return X86InstClass::Sensitive(X86SensitiveKind::LegacyX87(
                X86LegacyX87Kind::Fldenv14,
            ));
        }
        Code::Fldenv_m28byte => {
            return X86InstClass::Sensitive(X86SensitiveKind::LegacyX87(
                X86LegacyX87Kind::Fldenv28,
            ));
        }
        Code::Fnstenv_m14byte => {
            return X86InstClass::Sensitive(X86SensitiveKind::LegacyX87(
                X86LegacyX87Kind::Fnstenv14,
            ));
        }
        Code::Fstenv_m14byte => {
            return X86InstClass::Sensitive(X86SensitiveKind::LegacyX87(
                X86LegacyX87Kind::Fstenv14,
            ));
        }
        Code::Fnstenv_m28byte => {
            return X86InstClass::Sensitive(X86SensitiveKind::LegacyX87(
                X86LegacyX87Kind::Fnstenv28,
            ));
        }
        Code::Fstenv_m28byte => {
            return X86InstClass::Sensitive(X86SensitiveKind::LegacyX87(
                X86LegacyX87Kind::Fstenv28,
            ));
        }
        Code::Frstor_m94byte => {
            return X86InstClass::Sensitive(X86SensitiveKind::LegacyX87(
                X86LegacyX87Kind::Frstor94,
            ));
        }
        Code::Frstor_m108byte => {
            return X86InstClass::Sensitive(X86SensitiveKind::LegacyX87(
                X86LegacyX87Kind::Frstor108,
            ));
        }
        Code::Fnsave_m94byte => {
            return X86InstClass::Sensitive(X86SensitiveKind::LegacyX87(
                X86LegacyX87Kind::Fnsave94,
            ));
        }
        Code::Fsave_m94byte => {
            return X86InstClass::Sensitive(X86SensitiveKind::LegacyX87(X86LegacyX87Kind::Fsave94));
        }
        Code::Fnsave_m108byte => {
            return X86InstClass::Sensitive(X86SensitiveKind::LegacyX87(
                X86LegacyX87Kind::Fnsave108,
            ));
        }
        Code::Fsave_m108byte => {
            return X86InstClass::Sensitive(X86SensitiveKind::LegacyX87(
                X86LegacyX87Kind::Fsave108,
            ));
        }
        Code::Wait => return X86InstClass::Sensitive(X86SensitiveKind::X87Wait),
        Code::Xsave_mem => {
            return X86InstClass::Sensitive(X86SensitiveKind::XstateSave(X86XstateSaveKind::Xsave));
        }
        Code::Xsave64_mem => {
            return X86InstClass::Sensitive(X86SensitiveKind::XstateSave(
                X86XstateSaveKind::Xsave64,
            ));
        }
        Code::Xsaveopt_mem => {
            return X86InstClass::Sensitive(X86SensitiveKind::XstateSave(
                X86XstateSaveKind::Xsaveopt,
            ));
        }
        Code::Xsaveopt64_mem => {
            return X86InstClass::Sensitive(X86SensitiveKind::XstateSave(
                X86XstateSaveKind::Xsaveopt64,
            ));
        }
        Code::Xsavec_mem => {
            return X86InstClass::Sensitive(X86SensitiveKind::XstateSave(
                X86XstateSaveKind::Xsavec,
            ));
        }
        Code::Xsavec64_mem => {
            return X86InstClass::Sensitive(X86SensitiveKind::XstateSave(
                X86XstateSaveKind::Xsavec64,
            ));
        }
        // XSAVES can transfer supervisor/XSS state. It stays unsupported; the
        // checked emulation surface is deliberately limited to user state.
        Code::Xsaves_mem | Code::Xsaves64_mem => return X86InstClass::Unsupported,
        Code::Xrstor_mem => {
            return X86InstClass::Sensitive(X86SensitiveKind::XstateRestore(
                X86XstateRestoreKind::Xrstor,
            ));
        }
        Code::Xrstor64_mem => {
            return X86InstClass::Sensitive(X86SensitiveKind::XstateRestore(
                X86XstateRestoreKind::Xrstor64,
            ));
        }
        // XRSTORS can restore supervisor/CET/PKRU state. It stays unsupported;
        // the safe emulation surface is deliberately limited to user XRSTOR.
        Code::Xrstors_mem | Code::Xrstors64_mem => return X86InstClass::Unsupported,
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
        // Copied x87 memory instructions must publish an exact FDP. This
        // native lane has no guest GS-base virtualization; reject the form
        // while planning rather than execute it and expose a stale FDP at the
        // next FXSAVE/signal boundary. Non-x87 GS accesses retain their typed
        // sensitive boundary.
        let copied_x87_memory = inst.op_count() != 0
            && (0..inst.op_count()).any(|operand| inst.op_kind(operand) == OpKind::Memory)
            && inst.cpuid_features().iter().any(|feature| {
                matches!(
                    feature,
                    CpuidFeature::FPU
                        | CpuidFeature::FPU287
                        | CpuidFeature::FPU287XL_ONLY
                        | CpuidFeature::FPU387
                        | CpuidFeature::FPU387SL_ONLY
                )
            });
        return if copied_x87_memory {
            X86InstClass::Unsupported
        } else {
            X86InstClass::Sensitive(X86SensitiveKind::SegmentPrefixed { gs: true })
        };
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
    fn protection_key_register_access_is_sensitive_and_supervisor_xrstor_fails_closed() {
        assert_eq!(
            one(&[0x0f, 0x01, 0xee]).class,
            X86InstClass::Sensitive(X86SensitiveKind::ProtectionKey { write: false })
        );
        assert_eq!(
            one(&[0x0f, 0x01, 0xef]).class,
            X86InstClass::Sensitive(X86SensitiveKind::ProtectionKey { write: true })
        );
        assert_eq!(
            one(&[0x0f, 0x01, 0xd0]).class,
            X86InstClass::Sensitive(X86SensitiveKind::ExtendedControl)
        );
        // 0f c7 /3: XRSTORS [rax]. Supervisor-state restoration remains out
        // of the user-only checked emulation surface.
        assert_eq!(one(&[0x0f, 0xc7, 0x18]).class, X86InstClass::Unsupported);
    }

    #[test]
    fn all_user_xsave_forms_are_typed_sensitive_and_xsaves_fails_closed() {
        for (bytes, kind) in [
            (
                &[0x0f, 0xae, 0x64, 0x24, 0x40][..],
                X86XstateSaveKind::Xsave,
            ),
            (
                &[0x48, 0x0f, 0xae, 0x64, 0x24, 0x40][..],
                X86XstateSaveKind::Xsave64,
            ),
            (
                &[0x0f, 0xae, 0x74, 0x24, 0x40][..],
                X86XstateSaveKind::Xsaveopt,
            ),
            (
                &[0x48, 0x0f, 0xae, 0x74, 0x24, 0x40][..],
                X86XstateSaveKind::Xsaveopt64,
            ),
            (
                &[0x0f, 0xc7, 0x64, 0x24, 0x40][..],
                X86XstateSaveKind::Xsavec,
            ),
            (
                &[0x48, 0x0f, 0xc7, 0x64, 0x24, 0x40][..],
                X86XstateSaveKind::Xsavec64,
            ),
        ] {
            let classified = one(bytes);
            assert_eq!(
                classified.class,
                X86InstClass::Sensitive(X86SensitiveKind::XstateSave(kind))
            );
            assert!(classified.uses_fpu);
        }
        for bytes in [
            &[0x0f, 0xc7, 0x6c, 0x24, 0x40][..],
            &[0x48, 0x0f, 0xc7, 0x6c, 0x24, 0x40][..],
        ] {
            assert_eq!(one(bytes).class, X86InstClass::Unsupported);
        }
    }

    #[test]
    fn exact_rsp_xrstor_encodings_are_typed_sensitive_exits() {
        let xrstor = one(&[0x0f, 0xae, 0x6c, 0x24, 0x40]);
        assert_eq!(xrstor.len, 5);
        assert_eq!(
            xrstor.class,
            X86InstClass::Sensitive(X86SensitiveKind::XstateRestore(
                X86XstateRestoreKind::Xrstor
            ))
        );

        let xrstor64 = one(&[0x48, 0x0f, 0xae, 0x6c, 0x24, 0x40]);
        assert_eq!(xrstor64.len, 6);
        assert_eq!(
            xrstor64.class,
            X86InstClass::Sensitive(X86SensitiveKind::XstateRestore(
                X86XstateRestoreKind::Xrstor64
            ))
        );
    }

    #[test]
    fn rdssp_is_sensitive_but_cet_mutators_remain_unsupported() {
        for bytes in [
            &[0xf3, 0x0f, 0x1e, 0xc8][..],
            &[0xf3, 0x48, 0x0f, 0x1e, 0xc8][..],
        ] {
            assert_eq!(
                one(bytes).class,
                X86InstClass::Sensitive(X86SensitiveKind::ReadShadowStackPointer)
            );
        }
        for bytes in [
            &[0xf3, 0x48, 0x0f, 0xae, 0xe8][..], // incsspq rax
            &[0xf3, 0x0f, 0x01, 0x28][..],       // rstorssp [rax]
            &[0xf3, 0x0f, 0x01, 0xea][..],       // saveprevssp
            &[0x48, 0x0f, 0x38, 0xf6, 0x00][..], // wrssq [rax],rax
        ] {
            assert_eq!(one(bytes).class, X86InstClass::Unsupported);
        }
    }

    #[test]
    fn all_fxsave_and_legacy_x87_state_forms_are_typed_sensitive() {
        for bytes in [
            &[0x0f, 0xae, 0x00][..],
            &[0x48, 0x0f, 0xae, 0x00][..],
            &[0x0f, 0xae, 0x08][..],
            &[0x48, 0x0f, 0xae, 0x08][..],
            &[0xd9, 0x20][..],
            &[0x66, 0xd9, 0x20][..],
            &[0xd9, 0x30][..],
            &[0x9b, 0xd9, 0x30][..],
            &[0x66, 0xd9, 0x30][..],
            &[0x9b, 0x66, 0xd9, 0x30][..],
            &[0xdd, 0x20][..],
            &[0x66, 0xdd, 0x20][..],
            &[0xdd, 0x30][..],
            &[0x9b, 0xdd, 0x30][..],
            &[0x66, 0xdd, 0x30][..],
            &[0x9b, 0x66, 0xdd, 0x30][..],
            &[0x9b][..],
        ] {
            let classified = one(bytes);
            assert!(
                matches!(classified.class, X86InstClass::Sensitive(_)),
                "{bytes:02x?} decoded as {:?}",
                classified.class
            );
            assert!(classified.uses_fpu);
        }
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
        // EVEX vmovdqu64 zmm6,[r11+1] from the exact GnuTLS corruption path.
        assert!(one(&[0x62, 0xd1, 0xfd, 0x48, 0x6f, 0xb3, 0x01, 0x00, 0x00, 0x00]).uses_fpu);
        // Opmask-only operations are xstate users even without xmm/ymm/zmm.
        assert!(one(&[0xc4, 0xe1, 0xf5, 0x47, 0xc9]).uses_fpu); // kxord k1,k1,k1
        assert!(one(&[0xc4, 0xe1, 0xf8, 0x98, 0xdb]).uses_fpu); // kortestq k3,k3
        assert!(one(&[0xc4, 0x61, 0xfb, 0x93, 0xd9]).uses_fpu); // kmovq r11,k1
        // Whole-register effects may be implicit in instruction metadata.
        assert!(one(&[0xc5, 0xf8, 0x77]).uses_fpu); // vzeroupper
        assert!(one(&[0xc4, 0xe2, 0x7b, 0x49, 0xc0]).uses_fpu); // tilezero tmm0
        // AMX configuration/release changes tile xstate without a TMM operand.
        let ldtilecfg = one(&[0xc4, 0xe2, 0x78, 0x49, 0x00]);
        assert!(ldtilecfg.uses_fpu);
        assert_eq!(ldtilecfg.class, X86InstClass::Unsupported);
        let tilerelease = one(&[0xc4, 0xe2, 0x78, 0x49, 0xc0]);
        assert!(tilerelease.uses_fpu);
        assert_eq!(tilerelease.class, X86InstClass::Unsupported);
        assert!(one(&[0xc4, 0xe2, 0x79, 0x49, 0x00]).uses_fpu); // sttilecfg [rax]
        // x87: fld st(0) implicitly (d9 c0) touches st.
        assert!(one(&[0xd9, 0xc0]).uses_fpu);
        // x87 environment/control families have no explicit ST/MM operand but
        // still read or mutate the authoritative guest xstate.
        assert!(one(&[0xd9, 0x28]).uses_fpu); // fldcw [rax]
        assert!(one(&[0xd9, 0x38]).uses_fpu); // fnstcw [rax]
        assert!(one(&[0xd9, 0x20]).uses_fpu); // fldenv [rax]
        assert!(one(&[0xd9, 0x30]).uses_fpu); // fnstenv [rax]
        assert!(one(&[0xdd, 0x20]).uses_fpu); // frstor [rax]
        assert!(one(&[0xdd, 0x30]).uses_fpu); // fnsave [rax]
        assert!(one(&[0xdb, 0xe3]).uses_fpu); // fninit
        assert!(one(&[0xdb, 0xe2]).uses_fpu); // fnclex
        assert!(one(&[0x0f, 0x77]).uses_fpu); // emms
        assert!(one(&[0x9b]).uses_fpu); // fwait
        // Copy-through state-control instructions with no vector operand must
        // still switch the full extended state. PKRU accesses are instead
        // sensitive-emulated and XRSTOR exits to checked emulation.
        assert!(one(&[0x0f, 0xae, 0x10]).uses_fpu); // ldmxcsr [rax]
        assert!(one(&[0x0f, 0xae, 0x20]).uses_fpu); // xsave [rax]
        assert!(one(&[0x0f, 0xae, 0x28]).uses_fpu); // xrstor [rax]
        assert!(!one(&[0x0f, 0x01, 0xee]).uses_fpu); // rdpkru
        assert!(!one(&[0x0f, 0x01, 0xef]).uses_fpu); // wrpkru
    }

    #[test]
    fn every_iced_x87_and_mmx_feature_code_requires_xstate() {
        let mut covered = 0usize;
        for code in Code::values() {
            if !code.cpuid_features().iter().any(|feature| {
                matches!(
                    feature,
                    CpuidFeature::FPU
                        | CpuidFeature::FPU287
                        | CpuidFeature::FPU287XL_ONLY
                        | CpuidFeature::FPU387
                        | CpuidFeature::FPU387SL_ONLY
                        | CpuidFeature::MMX
                )
            }) {
                continue;
            }
            let mut instruction = Instruction::default();
            instruction.set_code(code);
            assert!(
                instruction_uses_fpu(&instruction),
                "{code:?} escaped the xstate classifier"
            );
            covered += 1;
        }
        assert!(covered > 100, "iced x87/MMX catalog unexpectedly small");
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
