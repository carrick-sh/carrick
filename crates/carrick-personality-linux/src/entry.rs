//! Linux decoding and dispatch at the shared native-entry seam.
pub use crate::abi::entry::{CanonicalCall, CanonicalOrdinal, SyscallResult};
pub use carrick_core_abi::ExecutionBinding;
use carrick_guest_arch::{
    GuestIsa, NativeAbi, NativeEntrySnapshot, NativeOrdinal, UserVa, X86Register, X86Registers,
};

pub const SYS_SET_ROBUST_LIST: usize = 99;
pub const EINVAL: i64 = -22;

/// Decode the Linux x86_64 syscall ABI from a native register snapshot.
pub fn decode_x86_64(native: u64, mut args: [u64; 6], stack: u64) -> CanonicalCall {
    // clone's fourth and fifth native arguments are reversed relative to
    // the canonical asm-generic order.
    if native == 56 {
        args.swap(3, 4);
    }
    let canonical = carrick_syscall_abi::syscall_x86_64::canonical_x86_64(
        carrick_syscall_abi::NativeNr(native),
    )
    .map_or(u64::MAX, carrick_syscall_abi::CanonicalNr::raw);
    CanonicalCall {
        isa: GuestIsa::X86_64,
        canonical: CanonicalOrdinal::new(canonical),
        native: NativeOrdinal::new(native),
        args,
        stack: UserVa::new(stack),
    }
}

/// Decode Linux registers from the full native snapshot, refusing an ISA or
/// entry-profile mismatch before dispatch or any family effect.
pub fn decode_x86_snapshot<F: X86Registers>(
    snapshot: NativeEntrySnapshot<'_, F>,
) -> Option<CanonicalCall> {
    if snapshot.isa != GuestIsa::X86_64 || snapshot.abi != NativeAbi::X86_64Syscall {
        return None;
    }
    let frame = snapshot.frame;
    Some(decode_x86_64(
        frame.read(X86Register::Rax),
        [
            frame.read(X86Register::Rdi),
            frame.read(X86Register::Rsi),
            frame.read(X86Register::Rdx),
            frame.read(X86Register::R10),
            frame.read(X86Register::R8),
            frame.read(X86Register::R9),
        ],
        frame.read(X86Register::Rsp),
    ))
}

/// The native ARM adapter extracts x8 and supplies Linux's six ABI register
/// arguments. The ordinal is interpreted here, never by the hardware trait.
pub fn decode_aarch64(native: u64, args: [u64; 6], stack: u64) -> CanonicalCall {
    CanonicalCall {
        isa: GuestIsa::Aarch64,
        canonical: CanonicalOrdinal::new(native),
        native: NativeOrdinal::new(native),
        args,
        stack: UserVa::new(stack),
    }
}
/// AArch64 Linux vDSO wire identity: preserve the process half and replace
/// the thread's visible tid only when that native vDSO binding is present.
pub const fn aarch64_child_vdso_identity(parent: u64, visible_tid: u32) -> u64 {
    if parent == 0 {
        0
    } else {
        (parent & !0xffff_ffff) | visible_tid as u64
    }
}

#[cfg(test)]
mod decode_tests {
    use super::decode_x86_64;

    #[test]
    fn ordinary_x86_file_call_uses_canonical_family_ordinal() {
        let call = decode_x86_64(0, [7, 0x1000, 8, 0, 0, 0], 0x8000);
        assert_eq!(call.canonical.raw(), 63); // read, served by the shared IPC/file family
        assert_eq!(call.args, [7, 0x1000, 8, 0, 0, 0]);
        assert_eq!(call.native.raw(), 0);
    }
}
