//! Minimal x86_64 block emitter: copy-through + typed exit branches.
//!
//! For a translated block, the Copy-class instructions are emitted VERBATIM
//! and the terminator is replaced by an indirect branch to the matching
//! gateway exit stub — `jmp *disp(%r15)` where `disp` is the stub's address
//! offset in the [`X86DsrContext`](crate::gateway::X86DsrContext) (r15 is the
//! context pointer during translated execution). The indirect-through-context
//! form is used because the JIT region and the gateway `.text` can be more
//! than 2 GiB apart (a `rel32` branch cannot reach) and it clobbers no guest
//! register.
//!
//! Scope (vertical slice): only `Syscall` terminators emit real code; the
//! control-flow/sensitive/unsupported cases are typed errors until their
//! lowerings land. Copy-through assumes NO RIP-relative operands in the
//! block — a guest that reaches data via `movabs` (absolute) is safe; general
//! RIP-relative fixup (recomputing `disp32` against the cache VA) is the next
//! emitter rung.

use crate::block::{X86Block, X86Exit};
use crate::gateway::{CTX_EXIT_INDIRECT_ADDR, CTX_EXIT_SYSCALL_ADDR};

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum EmitError {
    #[error("x86 emit: source block bytes ({got}) shorter than the copy-through region ({need})")]
    ShortSource { need: usize, got: usize },
    #[error("x86 emit: terminator {0} is not lowered yet")]
    Unsupported(&'static str),
}

/// The `jmp *disp32(%r15)` encoding for an exit stub whose address lives at
/// `disp` bytes into the context: REX.B (0x41) + FF /4 + ModRM(mod=10,
/// reg=100, rm=111=r15) + disp32 (little-endian).
fn jmp_indirect_r15(disp: i32) -> [u8; 7] {
    let d = disp.to_le_bytes();
    [0x41, 0xFF, 0xA7, d[0], d[1], d[2], d[3]]
}

/// Emit the translated bytes for `block`. `source` is the guest bytes for
/// `[block.start, block.end)`. Returns the JIT-ready byte sequence: the
/// caller copies it through the JIT region's RW alias and sets the context's
/// `entry` to the corresponding exec VA.
pub fn emit_block(source: &[u8], block: &X86Block) -> Result<Vec<u8>, EmitError> {
    match block.exit {
        X86Exit::Syscall { va, .. } => {
            // Copy-through region: everything from the block start up to (not
            // including) the syscall instruction, which the exit branch
            // replaces.
            let copy_len = (va - block.start) as usize;
            if source.len() < copy_len {
                return Err(EmitError::ShortSource {
                    need: copy_len,
                    got: source.len(),
                });
            }
            let mut out = Vec::with_capacity(copy_len + 7);
            out.extend_from_slice(&source[..copy_len]);
            out.extend_from_slice(&jmp_indirect_r15(CTX_EXIT_SYSCALL_ADDR));
            Ok(out)
        }
        X86Exit::ControlFlow { va, .. } => {
            // Copy the straight-line body up to (not including) the branch,
            // then exit to Rust, which resolves the target from the captured
            // guest state (see `cflow::resolve`). The branch itself is not
            // executed on the host — its semantics are applied in Rust.
            let copy_len = (va - block.start) as usize;
            if source.len() < copy_len {
                return Err(EmitError::ShortSource {
                    need: copy_len,
                    got: source.len(),
                });
            }
            let mut out = Vec::with_capacity(copy_len + 7);
            out.extend_from_slice(&source[..copy_len]);
            out.extend_from_slice(&jmp_indirect_r15(CTX_EXIT_INDIRECT_ADDR));
            Ok(out)
        }
        X86Exit::Sensitive { .. } => Err(EmitError::Unsupported("sensitive")),
        X86Exit::Unsupported { .. } => Err(EmitError::Unsupported("unsupported-instruction")),
        X86Exit::Continue { .. } => Err(EmitError::Unsupported("continue")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::plan_block;

    #[test]
    fn syscall_block_copies_body_then_branches() {
        const BASE: u64 = 0x40_0000;
        // mov eax,60 (b8 3c 00 00 00); syscall (0f 05)
        static IMG: &[u8] = &[0xb8, 0x3c, 0x00, 0x00, 0x00, 0x0f, 0x05];
        let reader = |va: u64| {
            let off = (va - BASE) as usize;
            IMG.get(off..).map(|s| s.to_vec()).unwrap_or_default()
        };
        let block = plan_block(BASE, 256, 4096, reader).expect("plan");
        let out = emit_block(IMG, &block).expect("emit");
        // 5 body bytes + 7-byte indirect jmp; the syscall (0f 05) is dropped.
        assert_eq!(&out[..5], &IMG[..5]);
        assert_eq!(out.len(), 5 + 7);
        assert_eq!(out[5], 0x41, "REX.B prefix of the exit jmp");
        assert_eq!(out[6], 0xFF, "jmp near indirect opcode");
    }

    #[test]
    fn control_flow_lowers_to_the_indirect_exit() {
        const BASE: u64 = 0x40_0000;
        // nop (90); jmp +0 (eb 00) — one copy byte, then the branch exit.
        static IMG: &[u8] = &[0x90, 0xeb, 0x00];
        let reader = |va: u64| {
            let off = (va - BASE) as usize;
            IMG.get(off..).map(|s| s.to_vec()).unwrap_or_default()
        };
        let block = plan_block(BASE, 256, 4096, reader).expect("plan");
        let out = emit_block(IMG, &block).expect("emit");
        // 1 copied body byte (the nop) + the 7-byte indirect exit; the branch
        // (eb 00) is dropped — Rust resolves the target.
        assert_eq!(&out[..1], &[0x90]);
        assert_eq!(out.len(), 1 + 7);
        assert_eq!(out[1], 0x41, "REX.B prefix of the exit jmp");
    }
}
