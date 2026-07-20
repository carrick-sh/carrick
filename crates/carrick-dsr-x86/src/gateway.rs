//! The x86_64 guest register snapshot, the `repr(C)` gateway context, and the
//! safe wrapper over the assembled `gateway_x86_64.S` trampoline.
//!
//! Execution model (block-at-a-time, mirrors the AArch64 lane):
//! Rust fills a [`X86DsrContext`] with the guest register snapshot and the
//! `entry` cache VA of one translated block, then calls
//! [`enter_translated`]. The trampoline saves the host's callee-saved
//! registers into the context, loads the guest state, pins **`%r15` as the
//! context pointer**, and jumps to `entry`. The block runs to its terminator
//! and branches to an exit stub, which saves the guest state back into the
//! snapshot and `ret`s — returning, on the SAME host frame, straight to the
//! caller of [`enter_translated`] with the exit status. Guest `%r15` is
//! virtualized (kept in the snapshot, never loaded into the live r15) because
//! r15 holds the context pointer throughout translated execution.

/// Guest register file. GPR order is the x86 encoding order
/// (rax=0, rcx=1, rdx=2, rbx=3, rsp=4, rbp=5, rsi=6, rdi=7, r8..r15=8..15), so
/// the gateway asm indexes it as `[r15 + SNAP_GPR + reg*8]`. `fxsave` is a
/// 16-aligned 512-byte area for `fxsave`/`fxrstor` (SSE + x87 state).
#[repr(C, align(16))]
#[derive(Clone, Copy, Debug)]
pub struct X86UcontextSnapshot {
    pub gpr: [u64; 16],
    pub rip: u64,
    pub rflags: u64,
    pub fxsave: [u8; 512],
}

/// Register-file index constants (into [`X86UcontextSnapshot::gpr`]).
pub mod reg {
    pub const RAX: usize = 0;
    pub const RCX: usize = 1;
    pub const RDX: usize = 2;
    pub const RBX: usize = 3;
    pub const RSP: usize = 4;
    pub const RBP: usize = 5;
    pub const RSI: usize = 6;
    pub const RDI: usize = 7;
    pub const R8: usize = 8;
    pub const R9: usize = 9;
    pub const R10: usize = 10;
    pub const R11: usize = 11;
    pub const R12: usize = 12;
    pub const R13: usize = 13;
    pub const R14: usize = 14;
    pub const R15: usize = 15;
}

impl X86UcontextSnapshot {
    /// A snapshot with Linux's initial register/FPU state. A caller sets `rip`,
    /// `gpr[RSP]`, and argument registers before entry.
    pub fn new() -> Self {
        // The gateway `fxrstor`s this area on entry, so it must hold a VALID
        // initial FXSAVE image, not zeros: a zeroed image sets `FCW=0` and
        // `MXCSR=0`, which UNMASKS every x87/SSE exception and picks
        // round-to-nearest-with-wrong-flags — a guest's first FP/SSE op would
        // then trap or misbehave. Linux hands a fresh process `FCW=0x037F`
        // (all exceptions masked, 64-bit precision, round-to-nearest) and
        // `MXCSR=0x1F80` (all SSE exceptions masked). FXSAVE layout: FCW at
        // byte 0, MXCSR at byte 24.
        let mut fxsave = [0u8; 512];
        fxsave[0..2].copy_from_slice(&0x037Fu16.to_le_bytes());
        fxsave[24..28].copy_from_slice(&0x0000_1F80u32.to_le_bytes());
        Self {
            gpr: [0; 16],
            rip: 0,
            // EFLAGS bit 1 is always set; everything else clear (IF is not
            // meaningful at CPL 3 and the guest never observes it).
            rflags: 0x0000_0000_0000_0002,
            fxsave,
        }
    }
}

impl Default for X86UcontextSnapshot {
    fn default() -> Self {
        Self::new()
    }
}

/// The exit status the gateway returns (also the discriminant the caller
/// switches on). Distinct stubs write distinct values; `Signal` is written by
/// the fault shim (M2-runtime).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum X86ExitStatus {
    /// A `syscall`/`int 0x80` terminator: `snapshot.rip` is the resume VA.
    Syscall = 1,
    /// A control-flow/indirect terminator: `snapshot.rip` is the next VA.
    Indirect = 3,
    /// A sensitive (rdtsc/cpuid/fsgsbase/…) terminator.
    Sensitive = 6,
    /// A host signal (guest fault) captured by the trap shim.
    Signal = 4,
    /// An asynchronous host kick requesting a return to the run loop.
    Kicked = 7,
}

impl X86ExitStatus {
    pub fn from_raw(value: i32) -> Option<Self> {
        match value {
            1 => Some(Self::Syscall),
            3 => Some(Self::Indirect),
            6 => Some(Self::Sensitive),
            4 => Some(Self::Signal),
            7 => Some(Self::Kicked),
            _ => None,
        }
    }
}

/// Raw x86_64 syscall ordinals eligible for the immutable identity fast path.
/// These are native x86 UAPI numbers read from live `%rax`, not Carrick's
/// canonical asm-generic syscall numbers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum X86IdentitySyscall {
    GetPid = 39,
    GetTid = 186,
}

impl X86IdentitySyscall {
    pub const fn raw(self) -> u32 {
        self as u32
    }

    pub const fn from_static_x86_ordinal(raw: u32) -> Option<Self> {
        match raw {
            39 => Some(Self::GetPid),
            186 => Some(Self::GetTid),
            _ => None,
        }
    }
}

/// Per-thread identity values consumed directly by emitted code. This is a
/// JIT/assembly wire structure; construction remains typed on the Rust side.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct X86IdentityStamp {
    /// Host VA of an aligned `AtomicU32`: 1 enables, 0 forces dispatch.
    pub live_gate: u64,
    pub pid: u64,
    pub tid: u64,
}

impl X86IdentityStamp {
    pub const fn live(live_gate: u64, pid: u32, tid: u32) -> Self {
        Self {
            live_gate,
            pid: pid as u64,
            tid: tid as u64,
        }
    }
}

/// The gateway context. `#[repr(C, align(16))]` with a fixed field order; the
/// `gateway_x86_64.S` `.equ` offsets mirror the `offset_of!` asserts below.
#[repr(C, align(16))]
#[derive(Clone, Copy, Debug)]
pub struct X86DsrContext {
    pub snapshot: X86UcontextSnapshot,
    /// Host `rsp` at trampoline entry (points at the return address into the
    /// Rust caller). The exit stub restores this and `ret`s through it.
    pub host_rsp: u64,
    /// Host callee-saved registers saved at entry: rbx, rbp, r12, r13, r14,
    /// r15 (SysV requires the callee preserve these across the call).
    pub host_callee: [u64; 6],
    /// Cache VA of the translated block to jump to on entry.
    pub entry: u64,
    /// Resume/next guest VA, pre-filled per block; the exit stub copies it to
    /// `snapshot.rip`.
    pub exit_resume: u64,
    pub exit_status: i32,
    pub exit_pad: u32,
    /// Absolute addresses of the exit stubs, filled by [`enter_translated`]
    /// from the assembled symbols. Emitted code branches to a terminator via
    /// `jmp *disp(%r15)` (see [`CTX_EXIT_SYSCALL_ADDR`] etc.): the JIT region
    /// and the gateway `.text` can be more than 2 GiB apart, so a `rel32`
    /// branch cannot reach — an indirect jump through the context does, and
    /// clobbers no guest register (r15 is the context pointer).
    pub exit_syscall_addr: u64,
    pub exit_indirect_addr: u64,
    pub exit_sensitive_addr: u64,
    /// Spill slot for the emitter's RIP-relative rewrite: emitted code saves
    /// one guest GPR here (`mov [r15+CTX_SCRATCH], reg`), materializes the
    /// absolute guest VA in it, runs the re-encoded instruction, and restores
    /// the GPR — all `mov`s, so guest rflags survive. Never read by Rust or
    /// the gateway asm; live only within one rewritten instruction sequence.
    pub scratch: u64,
    /// Second spill slot, used when one rewritten instruction needs two
    /// scratch GPRs (a RIP-relative operand AND a virtualized-r15 rename in
    /// the same instruction). Same lifetime rules as `scratch`.
    pub scratch2: u64,
    /// The guest's `%fs` segment base (its Linux thread pointer, set via
    /// `arch_prctl(ARCH_SET_FS)` / `wrfsbase` servicing). When nonzero, the
    /// gateway installs it with `wrfsbase` on entry — making plain
    /// `fs:`-prefixed guest TLS accesses copy-through-safe — and restores
    /// [`host_fsbase`](Self::host_fsbase) on exit. Zero means "guest has no
    /// TLS yet": no swap happens (zero is never a real Linux thread pointer).
    pub guest_fsbase: u64,
    /// Where the gateway parks the host's `%fs` base across a translated run
    /// (written by the enter trampoline via `rdfsbase`, read back by the exit
    /// stubs). Only meaningful while `guest_fsbase != 0`.
    pub host_fsbase: u64,
    /// Where the host-OS seam's signal shim records a guest fault before
    /// redirecting to the signal exit stub (see `carrick_dsr::fault`). Only
    /// meaningful when the gateway returns [`X86ExitStatus::Signal`]; note
    /// `snapshot.rip` holds the per-block `exit_resume` then, NOT the fault
    /// point — [`FaultRecord::host_rip`](carrick_dsr::fault::FaultRecord)
    /// is authoritative.
    pub fault: carrick_dsr::fault::FaultRecord,
    /// Whether the enter/exit trampoline should `fxrstor`/`fxsave` the guest
    /// FPU/vector state (the 512-byte `snapshot.fxsave` area) around this
    /// block. Set per block from [`X86Block::uses_fpu`](crate::block::X86Block):
    /// integer-only blocks (the majority) leave it 0 and skip the save/restore
    /// entirely. Correctness across a non-saving block is preserved because the
    /// `snapshot.fxsave` area still holds the last FPU-using block's guest
    /// state, which the next FPU-using block's `fxrstor` reloads. Nonzero =
    /// save/restore.
    pub save_fpu: u32,
    pub save_fpu_pad: u32,
    /// A CHAIN-MISS flag, set nonzero by a chainable branch's COLD stub (see
    /// `emit::emit_block_linked`). When nonzero after an `Indirect` exit the
    /// run loop is at a chain miss — `snapshot.rip` holds the already-resolved
    /// successor guest VA, so the loop just continues there (and its
    /// `pending`-edge registry patches the missed slot when that VA is
    /// translated). Zero on a genuine indirect branch (`jmp/call r/m`), which
    /// the loop resolves from the snapshot instead. The driver clears it before
    /// every enter. The stub records the patch-site ADDRESS here (not just a
    /// bare 1) so the value is also usable for diagnostics or a future
    /// direct-patch path; the run loop currently consults only its
    /// nonzero-ness.
    pub chain_patch_site: u64,
    /// Namespace identity stamped at each chainable Rust→JIT entry, plus a
    /// live gate that closes when seccomp must observe these syscalls.
    pub identity: X86IdentityStamp,
}

/// Byte offset of [`X86DsrContext::exit_resume`] — the guest VA the exit stub
/// copies to `snapshot.rip`. Emitted exits SELF-SET this (so a chained-into
/// block does not depend on the driver pre-setting it).
pub const CTX_EXIT_RESUME: i32 = 720;
/// Byte offset of [`X86DsrContext::exit_syscall_addr`] for `jmp *disp(%r15)`.
pub const CTX_EXIT_SYSCALL_ADDR: i32 = 736;
/// Byte offset of [`X86DsrContext::exit_indirect_addr`].
pub const CTX_EXIT_INDIRECT_ADDR: i32 = 744;
/// Byte offset of [`X86DsrContext::exit_sensitive_addr`].
pub const CTX_EXIT_SENSITIVE_ADDR: i32 = 752;
/// Byte offset of [`X86DsrContext::scratch`] for the emitter's RIP-relative
/// rewrite spill (`mov [r15+CTX_SCRATCH], reg` / restore).
pub const CTX_SCRATCH: i32 = 760;
/// Byte offset of [`X86DsrContext::scratch2`] (second rewrite spill).
pub const CTX_SCRATCH2: i32 = 768;
/// Byte offset of [`X86DsrContext::guest_fsbase`] (mirrored in the `.S`).
pub const CTX_GUEST_FSBASE: i32 = 776;
/// Byte offset of [`X86DsrContext::host_fsbase`] (mirrored in the `.S`).
pub const CTX_HOST_FSBASE: i32 = 784;
/// Byte offset of [`X86DsrContext::save_fpu`] (mirrored in the `.S`): the
/// per-block flag gating the FPU save/restore.
pub const CTX_SAVE_FPU: i32 = 816;
/// Byte offset of [`X86DsrContext::chain_patch_site`] — a chainable branch's
/// cold stub writes the patch-site address here.
pub const CTX_CHAIN_PATCH: i32 = 824;
/// Byte offsets of the x86 identity fast-path wire fields.
pub const CTX_IDENTITY_LIVE_GATE: i32 = 832;
pub const CTX_IDENTITY_PID: i32 = 840;
pub const CTX_IDENTITY_TID: i32 = 848;
/// Byte offset of the virtualized guest `%r15` slot inside the snapshot
/// (`gpr[15]`): the emitter's r15-rename loads/stores it directly.
pub const SNAP_GUEST_R15: i32 = 120;
/// Byte offset of [`X86DsrContext::fault`] — handed to the host-OS seam's
/// signal shim, which writes the record through `r15 + CTX_FAULT_RECORD`.
pub const CTX_FAULT_RECORD: u32 = 792;
/// Byte offset of [`X86DsrContext::entry`] (unused by emitted code — the
/// trampoline reads it — but asserted for parity with the `.S`).
pub const CTX_ENTRY: i32 = 712;

impl X86DsrContext {
    pub fn new(snapshot: X86UcontextSnapshot, entry: u64, exit_resume: u64) -> Self {
        Self {
            snapshot,
            host_rsp: 0,
            host_callee: [0; 6],
            entry,
            exit_resume,
            exit_status: 0,
            exit_pad: 0,
            exit_syscall_addr: 0,
            exit_indirect_addr: 0,
            exit_sensitive_addr: 0,
            scratch: 0,
            scratch2: 0,
            guest_fsbase: 0,
            host_fsbase: 0,
            fault: carrick_dsr::fault::FaultRecord::new(),
            // Default: save/restore the FPU area (the always-correct behavior).
            // The runtime driver sets it per block from `X86Block::uses_fpu`;
            // in-crate tests keep the conservative default.
            save_fpu: 1,
            save_fpu_pad: 0,
            chain_patch_site: 0,
            identity: X86IdentityStamp::default(),
        }
    }
}

// The C gateway indexes these by byte offset; keep them in lockstep with
// gateway_x86_64.S (the `.equ` block). A drift here is a compile error.
const _: () = assert!(std::mem::offset_of!(X86UcontextSnapshot, gpr) == 0);
const _: () = assert!(std::mem::offset_of!(X86UcontextSnapshot, rip) == 128);
const _: () = assert!(std::mem::offset_of!(X86UcontextSnapshot, rflags) == 136);
const _: () = assert!(std::mem::offset_of!(X86UcontextSnapshot, fxsave) == 144);
const _: () = assert!(std::mem::size_of::<X86UcontextSnapshot>() == 656);
const _: () = assert!(std::mem::offset_of!(X86DsrContext, snapshot) == 0);
const _: () = assert!(std::mem::offset_of!(X86DsrContext, host_rsp) == 656);
const _: () = assert!(std::mem::offset_of!(X86DsrContext, host_callee) == 664);
const _: () = assert!(std::mem::offset_of!(X86DsrContext, entry) == 712);
const _: () = assert!(std::mem::offset_of!(X86DsrContext, exit_resume) == 720);
const _: () = assert!(std::mem::offset_of!(X86DsrContext, exit_status) == 728);
const _: () = assert!(std::mem::offset_of!(X86DsrContext, exit_syscall_addr) == 736);
const _: () = assert!(std::mem::offset_of!(X86DsrContext, exit_indirect_addr) == 744);
const _: () = assert!(std::mem::offset_of!(X86DsrContext, exit_sensitive_addr) == 752);
const _: () = assert!(std::mem::offset_of!(X86DsrContext, scratch) == 760);
const _: () = assert!(std::mem::offset_of!(X86DsrContext, scratch) as i32 == CTX_SCRATCH);
const _: () = assert!(std::mem::offset_of!(X86DsrContext, scratch2) as i32 == CTX_SCRATCH2);
const _: () = assert!(std::mem::offset_of!(X86DsrContext, guest_fsbase) as i32 == CTX_GUEST_FSBASE);
const _: () = assert!(std::mem::offset_of!(X86DsrContext, host_fsbase) as i32 == CTX_HOST_FSBASE);
const _: () = assert!(
    std::mem::offset_of!(X86UcontextSnapshot, gpr) + 15 * 8 == SNAP_GUEST_R15 as usize,
    "the emitter's r15 rename addresses gpr[15] directly"
);
const _: () = assert!(std::mem::offset_of!(X86DsrContext, fault) as u32 == CTX_FAULT_RECORD);
const _: () = assert!(std::mem::offset_of!(X86DsrContext, save_fpu) as i32 == CTX_SAVE_FPU);
const _: () =
    assert!(std::mem::offset_of!(X86DsrContext, chain_patch_site) as i32 == CTX_CHAIN_PATCH);
const _: () = assert!(
    std::mem::offset_of!(X86DsrContext, identity)
        + std::mem::offset_of!(X86IdentityStamp, live_gate)
        == CTX_IDENTITY_LIVE_GATE as usize
);
const _: () = assert!(
    std::mem::offset_of!(X86DsrContext, identity) + std::mem::offset_of!(X86IdentityStamp, pid)
        == CTX_IDENTITY_PID as usize
);
const _: () = assert!(
    std::mem::offset_of!(X86DsrContext, identity) + std::mem::offset_of!(X86IdentityStamp, tid)
        == CTX_IDENTITY_TID as usize
);
const _: () = assert!(std::mem::offset_of!(X86DsrContext, exit_resume) as i32 == CTX_EXIT_RESUME);
const _: () =
    assert!(std::mem::offset_of!(X86DsrContext, exit_syscall_addr) as i32 == CTX_EXIT_SYSCALL_ADDR);
const _: () = assert!(std::mem::offset_of!(X86DsrContext, entry) as i32 == CTX_ENTRY);

/// Whether this CPU exposes the FSGSBASE instructions
/// (`rdfsbase`/`wrfsbase`), which the gateway's fs-base swap uses (CPUID
/// leaf 7 subleaf 0, EBX bit 0). The kernel must also have enabled
/// CR4.FSGSBASE — FreeBSD does so whenever the CPU has it — and the
/// execution tests prove the pair end-to-end. A runtime without this must
/// refuse guests that set a TLS base rather than approximate.
#[cfg(target_arch = "x86_64")]
pub fn fsgsbase_supported() -> bool {
    // cpuid is unprivileged; leaf 7 exists on every x86_64 CPU new enough to
    // run this code (the intrinsic is safe on x86_64 targets).
    let leaf7 = core::arch::x86_64::__cpuid_count(7, 0);
    leaf7.ebx & 1 != 0
}

#[cfg(not(target_arch = "x86_64"))]
pub fn fsgsbase_supported() -> bool {
    false
}

// The assembled gateway is the ONE target boundary in this crate. build.rs
// assembles gateway_x86_64.S on target_arch = "x86_64" (any OS — the asm is
// SysV-ABI-portable). Everything that enters translated execution lives here.
#[cfg(target_arch = "x86_64")]
mod native_gateway {
    use super::X86DsrContext;

    unsafe extern "C" {
        fn carrick_dsr_x86_enter_raw(context: *mut X86DsrContext) -> i32;
        fn carrick_dsr_x86_exit_syscall();
        fn carrick_dsr_x86_exit_indirect();
        fn carrick_dsr_x86_exit_sensitive();
        fn carrick_dsr_x86_exit_signal();
        fn carrick_dsr_x86_exit_kicked();
    }

    /// Absolute address of the signal exit stub — what the host-OS seam's
    /// fault shim installs as the redirected RIP after recording a guest
    /// fault (paired with [`super::CTX_FAULT_RECORD`]).
    pub fn signal_stub_addr() -> u64 {
        carrick_dsr_x86_exit_signal as *const () as u64
    }

    /// Absolute address of the asynchronous host-kick exit stub.
    pub fn kick_stub_addr() -> u64 {
        carrick_dsr_x86_exit_kicked as *const () as u64
    }

    /// Absolute addresses of the three exit stubs. Emitted code branches to
    /// one via `jmp *disp(%r15)` where `disp` is the matching
    /// `CTX_EXIT_*_ADDR` offset.
    pub fn exit_stub_addresses() -> (u64, u64, u64) {
        (
            carrick_dsr_x86_exit_syscall as *const () as u64,
            carrick_dsr_x86_exit_indirect as *const () as u64,
            carrick_dsr_x86_exit_sensitive as *const () as u64,
        )
    }

    /// Enter the translated block described by `context`. Returns the raw
    /// exit status (decode with [`super::X86ExitStatus::from_raw`]). On
    /// return, `context.snapshot` holds the updated guest state.
    ///
    /// # Safety
    /// `context.entry` must be a valid, executable cache VA holding a
    /// translated block that ends in one of the gateway's exit stubs, and
    /// `context.snapshot.gpr[RSP]` must point at a valid guest stack. The
    /// caller must keep the JIT region mapped for the duration.
    pub unsafe fn enter_translated(context: &mut X86DsrContext) -> i32 {
        let (syscall, indirect, sensitive) = exit_stub_addresses();
        context.exit_syscall_addr = syscall;
        context.exit_indirect_addr = indirect;
        context.exit_sensitive_addr = sensitive;
        // SAFETY: forwarded to the caller's contract above; the trampoline
        // saves/restores all host callee-saved state around the guest run.
        unsafe { carrick_dsr_x86_enter_raw(context as *mut X86DsrContext) }
    }
}

#[cfg(target_arch = "x86_64")]
pub use native_gateway::{enter_translated, exit_stub_addresses, kick_stub_addr, signal_stub_addr};

/// Off-x86 fail-closed complement: the gateway only exists on x86_64. This
/// keeps the crate compiling (and unit-testable) on other host arches, where
/// translated x86 execution is meaningless.
#[cfg(not(target_arch = "x86_64"))]
pub unsafe fn enter_translated(_context: &mut X86DsrContext) -> i32 {
    -1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_snapshot_seeds_linux_fpu_control_words() {
        // A fresh snapshot's fxsave image must carry Linux's initial FP control
        // state, since the gateway fxrstors it before the guest's first FP/SSE
        // op. FCW at byte 0 = 0x037F; MXCSR at byte 24 = 0x1F80.
        let s = X86UcontextSnapshot::new();
        assert_eq!(
            u16::from_le_bytes([s.fxsave[0], s.fxsave[1]]),
            0x037F,
            "FCW"
        );
        assert_eq!(
            u32::from_le_bytes([s.fxsave[24], s.fxsave[25], s.fxsave[26], s.fxsave[27]]),
            0x1F80,
            "MXCSR"
        );
        // The rest of the image (FSW, tag word, ST/XMM regs) stays zeroed.
        assert!(s.fxsave[28..].iter().all(|&b| b == 0));
    }
}
