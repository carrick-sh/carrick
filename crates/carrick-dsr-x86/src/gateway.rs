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
/// the gateway asm indexes it as `[r15 + SNAP_GPR + reg*8]`. `xsave` is a
/// 64-aligned standard-format XSAVE area large enough for current x86_64
/// extended state (including AVX-512 and AMX when enabled in XCR0).
pub const XSAVE_AREA_LEN: usize = 16 * 1024;

#[repr(C, align(64))]
#[derive(Clone, Copy, Debug)]
pub struct X86UcontextSnapshot {
    pub gpr: [u64; 16],
    pub rip: u64,
    pub rflags: u64,
    xsave_align_pad: [u8; 48],
    pub xsave: [u8; XSAVE_AREA_LEN],
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
        // XRSTOR requires a valid standard-format image. Linux starts x87/SSE
        // in non-trapping defaults; AVX and newer components remain in their
        // architectural initial state because XSTATE_BV names only x87/SSE.
        // Standard XSAVE layout keeps the legacy FCW/MXCSR fields at 0/24 and
        // XSTATE_BV at byte 512.
        let mut xsave = [0u8; XSAVE_AREA_LEN];
        xsave[0..2].copy_from_slice(&0x037Fu16.to_le_bytes());
        xsave[24..28].copy_from_slice(&0x0000_1F80u32.to_le_bytes());
        xsave[512..520].copy_from_slice(&0x3u64.to_le_bytes());
        Self {
            gpr: [0; 16],
            rip: 0,
            // EFLAGS bit 1 is always set; everything else clear (IF is not
            // meaningful at CPL 3 and the guest never observes it).
            rflags: 0x0000_0000_0000_0002,
            xsave_align_pad: [0; 48],
            xsave,
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

/// The gateway context has a fixed, 64-byte-aligned field order; the
/// `gateway_x86_64.S` `.equ` offsets mirror the `offset_of!` asserts below.
#[repr(C, align(64))]
#[derive(Clone, Copy, Debug)]
pub struct X86DsrContext {
    pub snapshot: X86UcontextSnapshot,
    /// Complete host extended state saved before installing guest state. This
    /// includes process-affecting components such as PKRU, not just registers
    /// covered by the SysV calling convention. XSAVE initializes every byte
    /// XRSTOR may consume; `MaybeUninit` avoids pointlessly clearing 16 KiB on
    /// every short gateway round trip.
    pub host_xsave: [std::mem::MaybeUninit<u8>; XSAVE_AREA_LEN],
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
    /// Whether the enter/exit trampoline should save/restore the guest and
    /// host XSAVE areas around this block. Set per block from
    /// [`X86Block::uses_fpu`](crate::block::X86Block); integer-only blocks skip
    /// the extended-state work. Nonzero = save/restore.
    pub save_fpu: u32,
    /// Nonzero when the host supports XSAVEOPT for sparse, incremental guest
    /// state saves; zero selects baseline XSAVE.
    pub use_xsaveopt: u32,
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
pub const CTX_EXIT_RESUME: i32 = 33_024;
/// Byte offset of [`X86DsrContext::exit_syscall_addr`] for `jmp *disp(%r15)`.
pub const CTX_EXIT_SYSCALL_ADDR: i32 = 33_040;
/// Byte offset of [`X86DsrContext::exit_indirect_addr`].
pub const CTX_EXIT_INDIRECT_ADDR: i32 = 33_048;
/// Byte offset of [`X86DsrContext::exit_sensitive_addr`].
pub const CTX_EXIT_SENSITIVE_ADDR: i32 = 33_056;
/// Byte offset of [`X86DsrContext::scratch`] for the emitter's RIP-relative
/// rewrite spill (`mov [r15+CTX_SCRATCH], reg` / restore).
pub const CTX_SCRATCH: i32 = 33_064;
/// Byte offset of [`X86DsrContext::scratch2`] (second rewrite spill).
pub const CTX_SCRATCH2: i32 = 33_072;
/// Byte offset of [`X86DsrContext::guest_fsbase`] (mirrored in the `.S`).
pub const CTX_GUEST_FSBASE: i32 = 33_080;
/// Byte offset of [`X86DsrContext::host_fsbase`] (mirrored in the `.S`).
pub const CTX_HOST_FSBASE: i32 = 33_088;
/// Byte offset of [`X86DsrContext::save_fpu`] (mirrored in the `.S`): the
/// per-block flag gating the FPU save/restore.
pub const CTX_SAVE_FPU: i32 = 33_120;
/// Byte offset of [`X86DsrContext::chain_patch_site`] — a chainable branch's
/// cold stub writes the patch-site address here.
pub const CTX_CHAIN_PATCH: i32 = 33_128;
/// Byte offsets of the x86 identity fast-path wire fields.
pub const CTX_IDENTITY_LIVE_GATE: i32 = 33_136;
pub const CTX_IDENTITY_PID: i32 = 33_144;
pub const CTX_IDENTITY_TID: i32 = 33_152;
/// Byte offset of the virtualized guest `%r15` slot inside the snapshot
/// (`gpr[15]`): the emitter's r15-rename loads/stores it directly.
pub const SNAP_GUEST_R15: i32 = 120;
/// Byte offset of [`X86DsrContext::fault`] — handed to the host-OS seam's
/// signal shim, which writes the record through `r15 + CTX_FAULT_RECORD`.
pub const CTX_FAULT_RECORD: u32 = 33_096;
/// Byte offset of [`X86DsrContext::entry`] (unused by emitted code — the
/// trampoline reads it — but asserted for parity with the `.S`).
pub const CTX_ENTRY: i32 = 33_016;

#[cfg(target_arch = "x86_64")]
fn host_supports_xsaveopt() -> u32 {
    static SUPPORTED: std::sync::OnceLock<u32> = std::sync::OnceLock::new();
    *SUPPORTED.get_or_init(|| std::arch::x86_64::__cpuid_count(0x0d, 1).eax & 1)
}

#[cfg(not(target_arch = "x86_64"))]
fn host_supports_xsaveopt() -> u32 {
    0
}

impl X86DsrContext {
    pub fn new(snapshot: X86UcontextSnapshot, entry: u64, exit_resume: u64) -> Self {
        let mut host_xsave = [std::mem::MaybeUninit::uninit(); XSAVE_AREA_LEN];
        // XSAVE need not overwrite reserved header bytes, while XRSTOR requires
        // them to be zero. Enabled component payloads are written by XSAVE.
        host_xsave[512..576].fill(std::mem::MaybeUninit::new(0));
        Self {
            snapshot,
            host_xsave,
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
            use_xsaveopt: host_supports_xsaveopt(),
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
const _: () = assert!(std::mem::offset_of!(X86UcontextSnapshot, xsave) == 192);
const _: () = assert!(std::mem::size_of::<X86UcontextSnapshot>() == 16_576);
const _: () = assert!(std::mem::offset_of!(X86DsrContext, snapshot) == 0);
const _: () = assert!(std::mem::offset_of!(X86DsrContext, host_xsave) == 16_576);
const _: () = assert!(std::mem::offset_of!(X86DsrContext, host_rsp) == 32_960);
const _: () = assert!(std::mem::offset_of!(X86DsrContext, host_callee) == 32_968);
const _: () = assert!(std::mem::offset_of!(X86DsrContext, entry) == 33_016);
const _: () = assert!(std::mem::offset_of!(X86DsrContext, exit_resume) == 33_024);
const _: () = assert!(std::mem::offset_of!(X86DsrContext, exit_status) == 33_032);
const _: () = assert!(std::mem::offset_of!(X86DsrContext, exit_syscall_addr) == 33_040);
const _: () = assert!(std::mem::offset_of!(X86DsrContext, exit_indirect_addr) == 33_048);
const _: () = assert!(std::mem::offset_of!(X86DsrContext, exit_sensitive_addr) == 33_056);
const _: () = assert!(std::mem::offset_of!(X86DsrContext, scratch) == 33_064);
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
const _: () = assert!(std::mem::offset_of!(X86DsrContext, use_xsaveopt) == 33_124);
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
    use super::{X86DsrContext, XSAVE_AREA_LEN};

    fn host_xsave_fits_snapshot() -> bool {
        static FITS: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        *FITS.get_or_init(|| {
            let features = std::arch::x86_64::__cpuid(1).ecx;
            let xsave_enabled = features & ((1 << 26) | (1 << 27)) == ((1 << 26) | (1 << 27));
            xsave_enabled
                && std::arch::x86_64::__cpuid_count(0x0d, 0).ebx as usize <= XSAVE_AREA_LEN
        })
    }

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
        if !host_xsave_fits_snapshot() {
            return -1;
        }
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
        // A fresh standard XSAVE image carries Linux's initial FP control
        // state. FCW at byte 0 = 0x037F; MXCSR at byte 24 = 0x1F80; XSTATE_BV
        // names the initialized x87/SSE legacy components.
        let s = X86UcontextSnapshot::new();
        assert_eq!(u16::from_le_bytes([s.xsave[0], s.xsave[1]]), 0x037F, "FCW");
        assert_eq!(
            u32::from_le_bytes([s.xsave[24], s.xsave[25], s.xsave[26], s.xsave[27]]),
            0x1F80,
            "MXCSR"
        );
        assert_eq!(
            u64::from_le_bytes(s.xsave[512..520].try_into().unwrap()),
            0x3,
            "XSTATE_BV"
        );
        assert!(s.xsave[28..512].iter().all(|&byte| byte == 0));
        assert!(s.xsave[520..].iter().all(|&byte| byte == 0));
    }
}
