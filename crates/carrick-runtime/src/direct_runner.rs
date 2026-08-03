//! Wire tier D's directly-executed guests to the real syscall dispatcher.
//!
//! Tier D (`carrick_native_darwin::direct`) runs guest code natively and sends
//! every patched `svc` to a handler. This module is what that handler calls:
//! the same [`SyscallDispatcher`] the translated lane uses, so the two tiers
//! differ only in how guest code REACHES a syscall, never in what a syscall
//! means. One dispatcher is the point — a second implementation would give
//! every future conformance result two answers to reconcile.
//!
//! # Guest VA is host VA
//!
//! The guest executes in carrick's own address space, so a pointer it hands to
//! a syscall is already a valid host pointer. [`IdentityMemory`] is therefore a
//! near-empty `GuestMemory`: no translation table, no guest-physical mapping,
//! no alias window. That is the structural simplification direct execution
//! buys, and it is why this file is short.

use carrick_abi::{CanonicalNr, LinuxGuestAbi, NativeNr};
use carrick_guest_mem::{GuestMemory, MemoryError};
use carrick_native_darwin::direct::GuestContext;

use crate::dispatch::{DispatchOutcome, SyscallDispatcher, SyscallRequest};

/// Guest memory for a directly-executed image: guest addresses ARE host
/// addresses.
///
/// Accesses are bounds-checked against the window the runner was built with,
/// so a guest pointer that escapes it surfaces as `EFAULT` rather than as a
/// segfault inside carrick.
#[derive(Debug, Clone, Copy)]
pub struct IdentityMemory {
    base: u64,
    len: u64,
}

impl IdentityMemory {
    pub fn new(base: u64, len: u64) -> Self {
        Self { base, len }
    }

    fn resolve(&self, address: u64, length: usize) -> Result<*mut u8, MemoryError> {
        let end = address
            .checked_add(length as u64)
            .ok_or(MemoryError::OutOfBounds { address, length })?;
        if address < self.base || end > self.base.saturating_add(self.len) {
            return Err(MemoryError::OutOfBounds { address, length });
        }
        Ok(address as usize as *mut u8)
    }
}

impl GuestMemory for IdentityMemory {
    fn read_bytes_raw(&self, address: u64, length: usize) -> Result<Vec<u8>, MemoryError> {
        let src = self.resolve(address, length)?;
        let mut out = vec![0_u8; length];
        // SAFETY: `resolve` proved the range lies inside the runner's window,
        // and the guest is parked in the handler while this runs.
        unsafe { std::ptr::copy_nonoverlapping(src, out.as_mut_ptr(), length) };
        Ok(out)
    }

    fn write_bytes_raw(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
        let dst = self.resolve(address, bytes.len())?;
        // SAFETY: as above.
        unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), dst, bytes.len()) };
        Ok(())
    }
}

/// Why a directly-executed guest stopped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DirectRunOutcome {
    Exited {
        code: i32,
    },
    /// The dispatcher produced an outcome tier D does not implement yet
    /// (blocking waits, fork, execve, signal delivery). Named rather than
    /// approximated: the translated lane's loop services these, and tier D has
    /// to grow the same handling before it can claim them.
    Unsupported {
        syscall: u64,
        outcome: String,
    },
}

/// A directly-executed guest plus the dispatcher that serves it.
pub struct DirectRunner {
    dispatcher: SyscallDispatcher,
    memory: IdentityMemory,
    outcome: Option<DirectRunOutcome>,
    syscalls: u64,
}

impl DirectRunner {
    pub fn new(dispatcher: SyscallDispatcher, memory: IdentityMemory) -> Self {
        Self {
            dispatcher,
            memory,
            outcome: None,
            syscalls: 0,
        }
    }

    pub fn outcome(&self) -> Option<&DirectRunOutcome> {
        self.outcome.as_ref()
    }
    pub fn syscalls(&self) -> u64 {
        self.syscalls
    }
    pub fn dispatcher(&self) -> &SyscallDispatcher {
        &self.dispatcher
    }

    /// Service one syscall from a tier-D island; returns the guest's x0.
    fn service(&mut self, ctx: &GuestContext) -> i64 {
        self.syscalls += 1;
        let number = ctx.syscall_nr();
        let request = SyscallRequest::from_raw(carrick_hal::RawSyscall {
            number: CanonicalNr(number),
            args: ctx.args(),
            // aarch64 guest on an aarch64 host: the canonical numbering IS the
            // guest's own, so there is nothing to normalize.
            guest_abi: LinuxGuestAbi::Aarch64,
            native_number: NativeNr(number),
        });
        let reporter = crate::compat::CompatReporter::default();
        match self
            .dispatcher
            .dispatch(request, &mut self.memory, &reporter)
        {
            Ok(DispatchOutcome::Returned { value }) => value,
            Ok(DispatchOutcome::Errno { errno }) => errno.guest_retval(),
            Ok(DispatchOutcome::Exit { code }) => {
                self.outcome = Some(DirectRunOutcome::Exited { code });
                0
            }
            Ok(other) => {
                self.outcome = Some(DirectRunOutcome::Unsupported {
                    syscall: number,
                    outcome: format!("{other:?}"),
                });
                crate::linux_abi::LINUX_ENOSYS.guest_retval()
            }
            Err(error) => {
                self.outcome = Some(DirectRunOutcome::Unsupported {
                    syscall: number,
                    outcome: error.to_string(),
                });
                crate::linux_abi::LINUX_ENOSYS.guest_retval()
            }
        }
    }
}

thread_local! {
    /// The runner serving the guest executing on THIS thread.
    ///
    /// A directly-executed guest runs on the host thread that entered it, so
    /// "which runner" is exactly a per-thread question - and it stays correct
    /// when tier D grows threads.
    static ACTIVE: std::cell::Cell<*mut DirectRunner> =
        const { std::cell::Cell::new(std::ptr::null_mut()) };
}

/// The handler a tier-D image is built with.
extern "C" fn dispatch_from_island(ctx: *mut GuestContext) {
    let runner = ACTIVE.with(std::cell::Cell::get);
    if runner.is_null() || ctx.is_null() {
        return;
    }
    // SAFETY: `with_runner` installs this runner for exactly the window in
    // which the guest can call back, and the island owns `ctx` for this call.
    let (runner, ctx) = unsafe { (&mut *runner, &mut *ctx) };
    let value = runner.service(ctx);
    ctx.set_return(value);
}

/// Build a tier-D image with this so its syscalls reach the real dispatcher.
pub fn island_handler() -> extern "C" fn(*mut GuestContext) {
    dispatch_from_island
}

/// Install `runner` for the current thread while `body` runs the guest.
///
/// # Safety
/// `body` must enter an image built with [`island_handler`].
pub unsafe fn with_runner<R>(runner: &mut DirectRunner, body: impl FnOnce() -> R) -> R {
    let previous = ACTIVE.with(|slot| slot.replace(std::ptr::from_mut(runner)));
    let result = body();
    ACTIVE.with(|slot| slot.set(previous));
    result
}

#[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
mod tests {
    use super::*;
    use carrick_native_darwin::direct::DirectImage;

    const NR_WRITE: u32 = 64;
    const SVC_0: u32 = 0xd400_0001;

    const fn movz(rd: u32, imm16: u32, shift: u32) -> u32 {
        0xd280_0000 | ((shift / 16) << 21) | (imm16 << 5) | rd
    }
    const fn movk(rd: u32, imm16: u32, shift: u32) -> u32 {
        0xf280_0000 | ((shift / 16) << 21) | (imm16 << 5) | rd
    }
    const fn mov_reg(rd: u32, rm: u32) -> u32 {
        0xaa00_03e0 | (rm << 16) | rd
    }
    const fn str_pre_sp(rt: u32) -> u32 {
        0xf800_0c00 | ((0x1f0_u32 & 0x1ff) << 12) | (31 << 5) | rt
    }
    const fn mov_from_sp(rd: u32) -> u32 {
        0x9100_0000 | (31 << 5) | rd
    }
    /// `add sp, sp, #16`
    const ADD_SP_16: u32 = 0x9100_0000 | (16 << 10) | (31 << 5) | 31;

    /// `write(1, "hi\n", 3)`, then return to the host with SP BALANCED.
    ///
    /// The pop is load-bearing. A real guest never returns to Rust — it leaves
    /// through `exit` — so an unbalanced SP is harmless there. A fixture that
    /// returns via `ret` hands Rust a stack pointer 16 bytes low, and Rust then
    /// unwinds through garbage: the failure surfaces later as a branch to a
    /// stack address (EXC_BAD_ACCESS with PC on the stack), and whether it
    /// fires at all depends on what the caller does next. That fixture bug,
    /// not tier D, is what blocked this bridge.
    fn write_fixture() -> Vec<u8> {
        elf_with_code(&[
            mov_reg(20, 30),      // stash the incoming link register
            movz(9, 0x6968, 0),   // 'h','i'
            movk(9, 0x000a, 16),  // '\n'
            str_pre_sp(9),        // bytes onto the guest stack (SP -= 16)
            mov_from_sp(1),       // x1 = buf
            movz(0, 1, 0),        // x0 = fd 1
            movz(2, 3, 0),        // x2 = len
            movz(8, NR_WRITE, 0), // x8 = __NR_write
            SVC_0,
            ADD_SP_16,       // give the borrowed slot back
            mov_reg(30, 20), // restore the host's link register
            0xd65f_03c0,     // ret
        ])
    }

    /// The "one dispatcher" claim, made concrete: bytes travel from guest code
    /// executing natively on the host CPU, through a patched `svc`, into the
    /// same `SyscallDispatcher` the translated lane uses.
    #[test]
    fn guest_write_reaches_the_real_dispatcher() {
        let image = DirectImage::load(&write_fixture(), island_handler())
            .expect("load")
            .expect("eligible");
        assert_eq!(image.svc_sites(), 1);
        let mut runner =
            DirectRunner::new(SyscallDispatcher::new(), IdentityMemory::new(0, u64::MAX));
        let entry = image.entry();
        // SAFETY: the image is patched and built with `island_handler`.
        unsafe { with_runner(&mut runner, || image.enter(entry)) };

        assert_eq!(runner.syscalls(), 1, "exactly one syscall was serviced");
        assert_eq!(
            runner.dispatcher().stdout(),
            b"hi\n",
            "the guest's own write(2) reached the real dispatcher"
        );
    }

    /// Minimal ET_DYN wrapper with a section header table, which tier D's
    /// eligibility scan requires (it walks SHF_EXECINSTR sections).
    fn elf_with_code(code: &[u32]) -> Vec<u8> {
        let code_bytes: Vec<u8> = code.iter().flat_map(|w| w.to_le_bytes()).collect();
        let entry: u64 = 0x1000;
        let mut elf = vec![0_u8; 0x40 + 56];
        elf[..4].copy_from_slice(b"\x7fELF");
        elf[4] = 2;
        elf[5] = 1;
        elf[6] = 1;
        elf[0x10..0x12].copy_from_slice(&3_u16.to_le_bytes());
        elf[0x12..0x14].copy_from_slice(&183_u16.to_le_bytes());
        elf[0x18..0x20].copy_from_slice(&entry.to_le_bytes());
        elf[0x20..0x28].copy_from_slice(&0x40_u64.to_le_bytes());
        elf[0x36..0x38].copy_from_slice(&56_u16.to_le_bytes());
        elf[0x38..0x3a].copy_from_slice(&1_u16.to_le_bytes());
        let ph = 0x40;
        elf[ph..ph + 4].copy_from_slice(&1_u32.to_le_bytes());
        elf[ph + 4..ph + 8].copy_from_slice(&5_u32.to_le_bytes());
        elf[ph + 0x08..ph + 0x10].copy_from_slice(&entry.to_le_bytes());
        elf[ph + 0x10..ph + 0x18].copy_from_slice(&entry.to_le_bytes());
        elf[ph + 0x20..ph + 0x28].copy_from_slice(&(code_bytes.len() as u64).to_le_bytes());
        elf[ph + 0x28..ph + 0x30].copy_from_slice(&(code_bytes.len() as u64).to_le_bytes());
        elf.resize(entry as usize, 0);
        elf.extend_from_slice(&code_bytes);
        let shoff = elf.len();
        let mut shdrs = vec![0_u8; 64 * 2];
        let text = 64;
        shdrs[text + 0x04..text + 0x08].copy_from_slice(&1_u32.to_le_bytes());
        shdrs[text + 0x08..text + 0x10].copy_from_slice(&0x6_u64.to_le_bytes());
        shdrs[text + 0x10..text + 0x18].copy_from_slice(&entry.to_le_bytes());
        shdrs[text + 0x18..text + 0x20].copy_from_slice(&entry.to_le_bytes());
        shdrs[text + 0x20..text + 0x28].copy_from_slice(&(code_bytes.len() as u64).to_le_bytes());
        elf.extend_from_slice(&shdrs);
        elf[0x28..0x30].copy_from_slice(&(shoff as u64).to_le_bytes());
        elf[0x3a..0x3c].copy_from_slice(&64_u16.to_le_bytes());
        elf[0x3c..0x3e].copy_from_slice(&2_u16.to_le_bytes());
        elf
    }
}
