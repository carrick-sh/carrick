//! Pure x86 ISA byte-emitters + the FP-stub *driving* logic, hoisted out of
//! the bhyve backend so every no-MSR-ioctl / no-FP-getter VMM reuses them
//! instead of re-deriving the encodings.
//!
//! These are gated behind the two backend quirk enums:
//!   - [`msr_init_blob`] is run only when `X86Vcpu::set_syscall_msrs` returns
//!     [`crate::MsrInstall::NeedsRing0Blob`] (bhyve: libvmmapi has no MSR ioctl).
//!   - [`fp_stub_bytes`] + [`run_fp_stub`] are used only when
//!     `X86Vcpu::get_fp()` returns `None` (bhyve on FreeBSD 15.1: no FP getter).
//!
//! Stage-1 status: these are the **canonical copies** in `carrick-x86`. They are
//! byte-for-byte equivalent to bhyve's `guest_setup_x86::{msr_init_blob,
//! fp_stub_bytes}` and `trap_engine::run_fp_stub`, but the bhyve copies are left
//! in place (Stage 4 deletes them and re-points bhyve at these). Nothing
//! consumes these yet.

use crate::vmm::{X86Exit, X86Reg, X86Vcpu};
use carrick_hal::TrapError;

// ─── MSR numbers (AMD64 SYSCALL MSRs) ────────────────────────────────────────
//
// Source: AMD64 APM vol. 2 §3.1.7 (SYSCALL/SYSRET MSRs); these are the same
// numbers KVM's `KVM_SET_MSRS` and NVMM's `setstate(MSRS)` accept.

/// `MSR_STAR` (0xC000_0081): SYSCALL/SYSRET CS/SS selectors.
const MSR_STAR: u32 = 0xC000_0081;
/// `MSR_LSTAR` (0xC000_0082): 64-bit SYSCALL entry RIP.
const MSR_LSTAR: u32 = 0xC000_0082;
/// `MSR_SF_MASK` (0xC000_0084): RFLAGS bits cleared on SYSCALL.
const MSR_SF_MASK: u32 = 0xC000_0084;

// ─── Ring-3 selectors (the iretq frame the MSR-init blob builds) ─────────────
//
// GDT order: null[0x00] / kCS[0x08] / kSS[0x10] / uSS[0x18] / uCS[0x20]. The
// RPL=3 user selectors are 0x20|3 = 0x23 (CS) and 0x18|3 = 0x1B (SS).

/// User CS selector (RPL=3): GDT[4]=0x20 | 3.
const USER_CS64_SEL: u64 = 0x23;
/// User SS selector (RPL=3): GDT[3]=0x18 | 3.
const USER_SS_SEL: u64 = 0x1B;

/// Emit the ring-0 MSR-init blob: a WRMSR sequence for LSTAR/STAR/SFMASK
/// followed by an `iretq` that drops to ring 3 at `user_rip`/`user_rsp`.
///
/// Used by backends whose `set_syscall_msrs` returns
/// [`crate::MsrInstall::NeedsRing0Blob`] (FreeBSD libvmmapi exposes no MSR
/// ioctl). The blob is spliced into the guest at a scratch GPA, run once, and
/// the `iretq` hands control to the real entry point with the SYSCALL MSRs live.
///
/// `clear_rax` emits `xor eax, eax` before the `iretq` so a `clone(2)` child
/// sees `rax = 0`.
///
/// Encodings (Intel SDM vol. 2 / AMD64 APM):
/// ```text
///   mov ecx, msr   B9 id
///   mov eax, lo    B8 id
///   mov edx, hi    BA id
///   wrmsr          0F 30
///   push imm32     68 id         ; small selectors / flags (sign-extends)
///   mov rax, imm64 48 B8 iq      ; large VAs (rip/rsp)
///   push rax       50
///   xor eax, eax   31 C0         ; iff clear_rax
///   iretq          48 CF
/// ```
pub fn msr_init_blob(
    lstar: u64,
    star: u64,
    sfmask: u64,
    user_rip: u64,
    user_rsp: u64,
    user_rflags: u64,
    clear_rax: bool,
) -> Vec<u8> {
    let mut b = Vec::with_capacity(128);

    // Helper: emit WRMSR(msr, val). All three SYSCALL MSRs fit in EDX:EAX.
    let mut wrmsr = |msr: u32, val: u64| {
        let lo = (val & 0xFFFF_FFFF) as u32;
        let hi = (val >> 32) as u32;
        // mov ecx, msr_num  (B9 id)
        b.push(0xB9);
        b.extend_from_slice(&msr.to_le_bytes());
        // mov eax, lo       (B8 id)
        b.push(0xB8);
        b.extend_from_slice(&lo.to_le_bytes());
        // mov edx, hi       (BA id)
        b.push(0xBA);
        b.extend_from_slice(&hi.to_le_bytes());
        // wrmsr             (0F 30)
        b.push(0x0F);
        b.push(0x30);
    };

    wrmsr(MSR_LSTAR, lstar);
    wrmsr(MSR_STAR, star);
    wrmsr(MSR_SF_MASK, sfmask);

    // Build iretq frame. push imm32 sign-extends; push rax from imm64 for large
    // values (user_rip and user_rsp can exceed 0x7FFF_FFFF).
    let push_u64 = |b: &mut Vec<u8>, val: u64| {
        // mov rax, imm64  (REX.W B8 + 8-byte imm)
        b.push(0x48);
        b.push(0xB8);
        b.extend_from_slice(&val.to_le_bytes());
        // push rax  (50)
        b.push(0x50);
    };

    // SS (selector, small — push imm32 sign-extends to 0x0000_0000_0000_001B)
    b.push(0x68); // push imm32
    b.extend_from_slice(&(USER_SS_SEL as u32).to_le_bytes());

    // RSP (large VA — use mov+push)
    push_u64(&mut b, user_rsp);

    // RFLAGS (small — push imm32)
    b.push(0x68);
    b.extend_from_slice(&(user_rflags as u32).to_le_bytes());

    // CS (selector, small)
    b.push(0x68);
    b.extend_from_slice(&(USER_CS64_SEL as u32).to_le_bytes());

    // RIP (large VA — use mov+push)
    push_u64(&mut b, user_rip);

    // Optionally zero RAX (xor eax, eax = 31 C0).
    if clear_rax {
        b.push(0x31);
        b.push(0xC0);
    }

    // iretq  (REX.W CF)
    b.push(0x48);
    b.push(0xCF);

    b
}

/// SP3.2 FXSAVE/FXRSTOR ring-3 stub bytes (16 bytes, two 8-byte slots).
///
/// Used by backends whose `get_fp()` returns `None` (libvmmapi exposes no FP
/// getter): the engine reads/writes the live vCPU FP by redirecting RIP to one
/// of these stubs (with `RDI = scratch GPA`) and running until the FP doorbell
/// (`out %al, $FP_STUB_DOORBELL_PORT`). FXSAVE is non-destructive; FXRSTOR loads
/// FP only — so after the stub the vCPU is byte-identical ([`run_fp_stub`]
/// restores the saved RIP/RAX/RDI/RFLAGS).
///
/// Encodings (AMD64 APM vol. 3 / Intel SDM vol. 2A "FXSAVE"/"FXRSTOR"):
/// ```text
///   fxsave  (%rdi)    0F AE 07     ; capture FP into [rdi]=scratch  (slot +0)
///   fxrstor (%rdi)    0F AE 0F     ; load FP from [rdi]=scratch     (slot +8)
///   out %al,$0xC6     E6 C6        ; FP doorbell (FP_STUB_DOORBELL_PORT)
///   jmp .             EB FE        ; park (never reached: host restores RIP)
/// ```
/// `fxsave_stub` at +0, `fxrstor_stub` at +8 (each padded to 8 bytes).
pub fn fp_stub_bytes() -> [u8; 16] {
    let mut b = [0u8; 16];
    // fxsave (%rdi); out %al,$0xC6; jmp .
    b[0..7].copy_from_slice(&[0x0F, 0xAE, 0x07, 0xE6, 0xC6, 0xEB, 0xFE]);
    // fxrstor (%rdi); out %al,$0xC6; jmp .
    b[8..15].copy_from_slice(&[0x0F, 0xAE, 0x0F, 0xE6, 0xC6, 0xEB, 0xFE]);
    b
}

/// Drive one FP-stub (FXSAVE or FXRSTOR) to completion on a vCPU whose backend
/// has no native FP getter/setter.
///
/// This is the §2.5d hoist: the ~40-line "save regs → redirect RIP to the stub
/// GPA → run until the FP doorbell → restore regs" procedure that bhyve's
/// `trap_engine::run_fp_stub` performs, lifted into `carrick-x86` so the next
/// no-FP-getter backend reuses it. It calls ONLY [`X86Vcpu`] trait methods (no
/// backend FFI): the backend supplies just the `stub_gpa` (which stub) and
/// `scratch_gpa` (the 512-byte fxsave area), via its [`crate::X86Vmm`].
///
/// The stub at `stub_gpa` must end with `out %al, $FP_STUB_DOORBELL_PORT`, which
/// the backend's [`X86Vcpu::run`] decodes into [`X86Exit::FpDoorbell`].
pub fn run_fp_stub<C: X86Vcpu>(
    vcpu: &mut C,
    stub_gpa: u64,
    scratch_gpa: u64,
) -> Result<(), TrapError> {
    let saved_rip = vcpu.get_gpr(X86Reg::Rip)?;
    let saved_rax = vcpu.get_gpr(X86Reg::Rax)?;
    let saved_rdi = vcpu.get_gpr(X86Reg::Rdi)?;
    let saved_rflags = vcpu.get_gpr(X86Reg::Rflags)?;

    vcpu.set_gpr(X86Reg::Rdi, scratch_gpa)?;
    vcpu.set_gpr(X86Reg::Rax, 0)?; // `out %al` source byte
    vcpu.set_gpr(X86Reg::Rip, stub_gpa)?;

    loop {
        match vcpu.run()? {
            X86Exit::FpDoorbell => break,
            // Spurious VT-x re-entry / cross-thread kick — re-run the stub.
            X86Exit::Kicked => continue,
            other => {
                return Err(TrapError::Hypervisor(format!(
                    "run_fp_stub: unexpected exit {other:?} (stub did not reach the FP doorbell)"
                )));
            }
        }
    }

    // Restore the four touched regs (the RIP override cancels the backend's
    // auto-advance past the `out`).
    vcpu.set_gpr(X86Reg::Rip, saved_rip)?;
    vcpu.set_gpr(X86Reg::Rax, saved_rax)?;
    vcpu.set_gpr(X86Reg::Rdi, saved_rdi)?;
    vcpu.set_gpr(X86Reg::Rflags, saved_rflags)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn msr_init_blob_is_nonempty_and_ends_with_iretq() {
        let blob = msr_init_blob(
            0x1000,
            0x0013_0008_0000_0000,
            0x4700,
            0x40_0000,
            0x7fff_0000,
            0x2,
            false,
        );
        assert!(!blob.is_empty());
        assert!(blob.len() <= 128, "blob must fit the scratch slot");
        // ends with `iretq` = 48 CF
        let n = blob.len();
        assert_eq!(&blob[n - 2..], &[0x48, 0xCF], "blob must end with iretq");
        // first WRMSR targets MSR_LSTAR (mov ecx, imm32 = B9 + le32)
        assert_eq!(blob[0], 0xB9, "first op is `mov ecx, imm32`");
        assert_eq!(
            &blob[1..5],
            &MSR_LSTAR.to_le_bytes(),
            "first WRMSR targets MSR_LSTAR"
        );
    }

    #[test]
    fn msr_init_blob_clear_rax_emits_xor_before_iretq() {
        let with = msr_init_blob(0, 0, 0, 0x1000, 0x2000, 0x2, true);
        let without = msr_init_blob(0, 0, 0, 0x1000, 0x2000, 0x2, false);
        // `with` has the extra `xor eax, eax` (31 C0) just before `iretq`.
        assert_eq!(with.len(), without.len() + 2);
        let n = with.len();
        assert_eq!(
            &with[n - 4..n - 2],
            &[0x31, 0xC0],
            "xor eax,eax precedes iretq"
        );
    }

    #[test]
    fn fp_stub_bytes_encode_fxsave_and_fxrstor() {
        let s = fp_stub_bytes();
        // fxsave (%rdi) = 0F AE 07, then the FP doorbell out %al,$0xC6 = E6 C6.
        assert_eq!(&s[0..5], &[0x0F, 0xAE, 0x07, 0xE6, 0xC6]);
        // fxrstor (%rdi) = 0F AE 0F at +8, then the same doorbell.
        assert_eq!(&s[8..13], &[0x0F, 0xAE, 0x0F, 0xE6, 0xC6]);
    }
}
