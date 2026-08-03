//! Wire tier D's directly-executed guests to the real syscall dispatcher.
//!
//! Tier D (`carrick_native_darwin::direct`) runs guest code natively and sends
//! every patched `svc` to a handler. This module is what that handler calls:
//! the same `SyscallDispatcher` the translated lane uses, so the two tiers
//! differ only in how guest code REACHES a syscall, never in what a syscall
//! means. One dispatcher is the point — a second implementation would give
//! every future conformance result two answers to reconcile.
//!
//! # Guest VA is host VA
//!
//! The guest executes in carrick's own address space, so a pointer it hands to
//! a syscall is already a valid host pointer. `IdentityMemory` is therefore a
//! near-empty `GuestMemory`: no translation table, no guest-physical mapping,
//! no alias window. That is the structural simplification direct execution
//! buys, and it is why this file is short.
//!
//! # How a run ends: the guest-leave contract
//!
//! A tier-D guest leaves through the handler, never by returning to Rust with
//! its own stack discipline (the full contract lives in
//! `carrick_native_darwin::direct`). Concretely for this runner: any dispatch
//! outcome that ends or suspends the run — `Exit`, and every outcome tier D
//! does not implement yet (`Execve`, `Fork`, signal delivery, blocking waits)
//! — makes the handler request a leave. The island's leave leg then returns
//! control to `DirectLoadGroup::enter`'s caller with the guest's complete state
//! parked in its context, and `DirectRunner::outcome` names why the run
//! stopped. The guest is never resumed past such a syscall with a fabricated
//! errno.

use carrick_abi::{CanonicalNr, LinuxGuestAbi, NativeNr};
use carrick_guest_mem::{GuestMemory, MemoryError};
use carrick_native_darwin::direct::{DirectLoadGroup, GuestContext};

use crate::dispatch::{DispatchOutcome, SyscallDispatcher, SyscallRequest};

/// Apple Silicon's host page size. On the identity tier this IS the guest's
/// page size (`AT_PAGESZ`, brk/mmap granularity): guest mappings are host
/// mappings, so nothing smaller is protectable or mappable.
const HOST_PAGE_SIZE: u64 = 16 * 1024;

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

/// The exec stack for a directly-executed guest: a host allocation holding
/// the argc/argv/envp/auxv image execve(2) would build, with `sp()` ready for
/// [`carrick_native_darwin::direct::DirectLoadGroup::enter_on_stack`].
///
/// Guest VA is host VA on this tier, so the pointers serialized into the
/// arrays are the allocation's own addresses — nothing to relocate. The
/// serializer and the auxv builder are carrick-mem's, shared with the VMM
/// lanes: one implementation of the exec-stack ABI, not a second drifting
/// copy. The vDSO is NOT advertised (`AT_SYSINFO_EHDR` absent) because tier D
/// does not map one; libc falls back to real syscalls, which the islands
/// service.
pub struct DirectStack {
    base: *mut u8,
    len: usize,
    sp: u64,
    auxv_image: Vec<u8>,
}

// SAFETY: the mapping is owned solely by this value and unmapped in `Drop`.
unsafe impl Send for DirectStack {}

impl DirectStack {
    /// Linux's default `RLIMIT_STACK`.
    pub const SIZE: usize = 8 * 1024 * 1024;

    /// Build the stack for `main_elf` mapped at `main_bias` (the load group's
    /// `main().bias()`).
    ///
    /// `interpreter_base` is the interpreter's load bias when the image is
    /// dynamic — it becomes `AT_BASE`, which ld.so requires to find itself; a
    /// missing `AT_BASE` on a dynamic target and a bogus one on a static
    /// target are both real, shipped bug shapes, so the caller states it
    /// explicitly.
    pub fn build(
        main_elf: &[u8],
        main_bias: u64,
        interpreter_base: Option<u64>,
        argv: &[Vec<u8>],
        envp: &[Vec<u8>],
    ) -> std::io::Result<Self> {
        use goblin::elf::header::EM_AARCH64;
        let plan = carrick_mem::elf::plan_elf_load_bytes_for(main_elf, EM_AARCH64)
            .map_err(std::io::Error::other)?
            .with_load_bias(main_bias);
        let mut auxv = carrick_mem::memory::linux_auxv_from_load_plan_with_vdso(
            &plan,
            interpreter_base,
            false,
        );
        // AT_PAGESZ must be the HOST page size on the identity tier: guest
        // mappings ARE host mappings, so every size/alignment libc derives
        // from it must be host-granular. The default 4096 made glibc round
        // its RELRO bounds to 4 KiB and the host mprotect EINVALed — ld.so
        // itself reported "cannot apply additional memory protection after
        // relocation" and exited 127.
        for entry in &mut auxv {
            if entry.a_type == carrick_abi::LINUX_AT_PAGESZ {
                *entry =
                    carrick_abi::LinuxAuxvEntry::new(carrick_abi::LINUX_AT_PAGESZ, HOST_PAGE_SIZE);
            }
        }
        let len = Self::SIZE;
        // SAFETY: fresh anonymous host mapping; the kernel picks the address.
        let base = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            )
        };
        if base == libc::MAP_FAILED {
            return Err(std::io::Error::last_os_error());
        }
        let base = base.cast::<u8>();
        let stack_top = base as u64 + len as u64;
        let (region, sp, auxv_image) = carrick_mem::memory::build_linux_initial_stack(
            argv.to_vec(),
            envp.to_vec(),
            &auxv,
            None,
            stack_top,
            len as u64,
        )
        .map_err(|error| {
            // SAFETY: undo the mapping this constructor owns before failing.
            unsafe { libc::munmap(base.cast(), len) };
            std::io::Error::other(error)
        })?;
        // Everything the serializer initialized sits at or above the SP
        // offset (strings at the top, pointer arrays at SP); the pages below
        // are the guest's to grow into and stay untouched zero-fill.
        let initialized = (sp - region.start) as usize;
        // SAFETY: `region` spans exactly [base, base+len); copying its
        // initialized tail into the live mapping at the same offsets.
        unsafe {
            std::ptr::copy_nonoverlapping(
                region.bytes()[initialized..].as_ptr(),
                base.add(initialized),
                region.bytes().len() - initialized,
            );
        }
        Ok(Self {
            base,
            len,
            sp,
            auxv_image,
        })
    }

    /// The initial guest SP: 16-aligned, pointing at argc.
    pub fn sp(&self) -> u64 {
        self.sp
    }

    /// The exact auxv byte image on the stack (`/proc/self/auxv`'s content).
    pub fn auxv_image(&self) -> &[u8] {
        &self.auxv_image
    }
}

impl Drop for DirectStack {
    fn drop(&mut self) {
        // SAFETY: this value owns the mapping.
        unsafe { libc::munmap(self.base.cast(), self.len) };
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
    /// approximated: the guest LEAVES through the island's leave leg with its
    /// full state parked in the context — never resumed with a fabricated
    /// errno — and the translated lane's loop shows what tier D has to grow
    /// before it can claim these outcomes.
    Unsupported {
        syscall: u64,
        outcome: String,
    },
}

/// What the island should do when the handler returns.
enum ServiceVerdict {
    /// Write `x0` and resume the guest at the instruction after the `svc`.
    Resume(i64),
    /// Leave guest execution: the run's outcome is recorded and the guest's
    /// state stays parked in the context (guest-leave contract).
    Leave,
}

/// The identity tier's program break: a lazily created host reservation the
/// guest's `brk(2)` grows into.
///
/// Linux puts the initial break after the main image's bss; the VALUE is
/// unobservable to a correct guest (it only uses what `brk` returns), so the
/// identity tier reserves an arbitrary host range instead. Growth commits
/// pages (`mprotect` RW over untouched reservation = zero-fill on first
/// touch); shrink REPLACES the released pages with a fresh `PROT_NONE`
/// mapping so a later regrowth re-delivers zeros — the anonymous-memory
/// guarantee is immovable.
struct IdentityBrk {
    base: u64,
    current: u64,
}

impl IdentityBrk {
    /// 1 GiB of reserved (PROT_NONE, uncommitted) break headroom.
    const RESERVE: usize = 1 << 30;
}

/// A directly-executed guest plus the dispatcher that serves it.
pub struct DirectRunner {
    dispatcher: SyscallDispatcher,
    memory: IdentityMemory,
    outcome: Option<DirectRunOutcome>,
    syscalls: u64,
    brk: Option<IdentityBrk>,
}

impl Drop for DirectRunner {
    fn drop(&mut self) {
        if let Some(brk) = &self.brk {
            // SAFETY: this runner owns the reservation.
            unsafe { libc::munmap(brk.base as usize as *mut libc::c_void, IdentityBrk::RESERVE) };
        }
    }
}

impl DirectRunner {
    pub fn new(dispatcher: SyscallDispatcher, memory: IdentityMemory) -> Self {
        Self {
            dispatcher,
            memory,
            outcome: None,
            syscalls: 0,
            brk: None,
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

    /// Identity lowering of the guest's MEMORY-MODEL syscalls.
    ///
    /// On tier D, guest VA IS host VA, so the only correct service for mmap
    /// and friends is the host's own primitive: the shared dispatcher's
    /// memory subsystem models a boot-mapped guest arena (the VMM lanes'
    /// world) and hands out guest VAs with NO host mapping behind them.
    /// Proven by fault: real ld.so's first malloc received `0x6000000010`
    /// from the arena and its memset SIGBUSed (lldb: `str q0, [x0]`,
    /// x0=0x6000000010, x8 still 222). This is not a second dispatcher —
    /// it is the tier's memory model, exactly as the HostAlias plumbing is
    /// the VMM lanes'; every non-memory syscall still goes to the one
    /// shared dispatcher.
    ///
    /// Fails closed, never approximates:
    /// - `PROT_EXEC` content the scan+patch window pipeline cannot prove —
    ///   `MAP_FIXED` exec mmaps, anonymous exec mmaps, `mprotect(PROT_EXEC)`
    ///   outside a patched tier-D mapping — LEAVES named;
    /// - `MAP_SHARED` file mmap -> LEAVES named (a private copy would break
    ///   the sharing contract);
    /// - `mremap` -> LEAVES named until implemented identity-style.
    fn service_identity_memory(&mut self, ctx: &GuestContext) -> Option<ServiceVerdict> {
        use carrick_abi::{LinuxMmapFlags, LinuxProtFlags};
        let number = ctx.syscall_nr();
        let [a0, a1, a2, a3, a4, a5] = ctx.args();
        let unsupported = |this: &mut Self, what: &str| {
            this.outcome = Some(DirectRunOutcome::Unsupported {
                syscall: number,
                outcome: what.to_string(),
            });
            Some(ServiceVerdict::Leave)
        };
        match number {
            // mmap(addr, len, prot, flags, fd, off)
            222 => {
                let prot = LinuxProtFlags::from_bits_truncate(a2);
                let flags = LinuxMmapFlags::from_bits_truncate(a3);
                if !flags.contains(LinuxMmapFlags::ANONYMOUS) {
                    if flags.contains(LinuxMmapFlags::SHARED) {
                        return unsupported(self, "MAP_SHARED file mmap on tier D");
                    }
                    if a5 % HOST_PAGE_SIZE != 0 {
                        // The identity tier's page size IS the host's
                        // (`AT_PAGESZ` says so), so a file offset must be
                        // host-page aligned to be mappable at all.
                        return Some(ServiceVerdict::Resume(
                            crate::host_to_linux_errno(libc::EINVAL).guest_retval(),
                        ));
                    }
                    if prot.contains(LinuxProtFlags::EXEC) {
                        return Some(self.service_exec_file_mmap(a0, flags, a4, a5, a1));
                    }
                    return Some(self.service_data_file_mmap(a0, a1, prot, flags, a4, a5));
                }
                if prot.contains(LinuxProtFlags::EXEC) {
                    // Fresh anonymous pages have no content to patch; a
                    // guest that wants executable memory must publish it
                    // through a PROT_EXEC flip (or is an RWX-without-flip
                    // JIT, which is tier T's by design).
                    return unsupported(
                        self,
                        "anonymous mmap(PROT_EXEC) on tier D (RWX-without-flip is tier T's)",
                    );
                }
                let mut host_flags = libc::MAP_ANON;
                host_flags |= if flags.contains(LinuxMmapFlags::SHARED) {
                    libc::MAP_SHARED
                } else {
                    libc::MAP_PRIVATE
                };
                if flags.contains(LinuxMmapFlags::FIXED) {
                    host_flags |= libc::MAP_FIXED;
                }
                // SAFETY: identity tier — the guest's address space IS this
                // process's, so a host mmap is the exact semantic.
                let mapped = unsafe {
                    libc::mmap(
                        a0 as usize as *mut libc::c_void,
                        a1 as usize,
                        host_prot(prot),
                        host_flags,
                        -1,
                        a5 as i64 as libc::off_t,
                    )
                };
                Some(if mapped == libc::MAP_FAILED {
                    host_errno_verdict()
                } else {
                    // A MAP_FIXED anon punch into a tier-D mapping (ld.so's
                    // bss tail over a window) voids patched coverage there.
                    if flags.contains(LinuxMmapFlags::FIXED)
                        && let Some(group) = active_group()
                    {
                        group.note_plain_replacement(mapped as u64, a1);
                    }
                    ServiceVerdict::Resume(mapped as i64)
                })
            }
            // munmap(addr, len)
            215 => {
                // A hole in a tier-D mapping is no longer patched text;
                // whatever lands there later must not inherit coverage.
                if let Some(group) = active_group() {
                    group.note_plain_replacement(a0, a1);
                }
                // SAFETY: as above; the guest unmaps within its own space.
                let rc = unsafe { libc::munmap(a0 as usize as *mut libc::c_void, a1 as usize) };
                Some(if rc == 0 {
                    ServiceVerdict::Resume(0)
                } else {
                    host_errno_verdict()
                })
            }
            // mprotect(addr, len, prot)
            226 => {
                let prot = LinuxProtFlags::from_bits_truncate(a2);
                if prot.contains(LinuxProtFlags::EXEC) {
                    // Inside a patched tier-D mapping the pages are ALREADY
                    // executable and their text was patched at map time, so
                    // the flip adds nothing — approving it keeps
                    // W^X-disciplined guests alive (ld.so re-mprotects
                    // libc's text R|X after relocation for BTI hardening).
                    // Anywhere else the bytes are unpatched: fail closed.
                    if active_group().is_some_and(|group| group.covers_patched_executable(a0, a1)) {
                        return Some(ServiceVerdict::Resume(0));
                    }
                    return unsupported(
                        self,
                        "mprotect(PROT_EXEC) outside a patched tier-D mapping",
                    );
                }
                let target = host_prot(prot);
                // SAFETY: as above.
                let rc = unsafe {
                    libc::mprotect(a0 as usize as *mut libc::c_void, a1 as usize, target)
                };
                if rc != 0 {
                    // Darwin refuses EVERY mprotect on MAP_JIT pages —
                    // probed EACCES for any target protection, armed or not
                    // — and ld.so's segment-hole `mprotect(PROT_NONE)` lands
                    // exactly there. When the range is still original window
                    // pages, lower the protection change to a
                    // preserve-and-replace; anything else keeps the host's
                    // verdict.
                    let errno = std::io::Error::last_os_error().raw_os_error();
                    if errno == Some(libc::EACCES)
                        && active_group()
                            .is_some_and(|group| group.covers_patched_executable(a0, a1))
                    {
                        return Some(self.replace_jit_pages_with_protection(a0, a1, target));
                    }
                    return Some(host_errno_verdict());
                }
                // A writability flip over patched text means the guest may
                // rewrite it: void its coverage so a later EXEC flip cannot
                // bless stale patches.
                if prot.contains(LinuxProtFlags::WRITE)
                    && let Some(group) = active_group()
                {
                    group.note_plain_replacement(a0, a1);
                }
                Some(ServiceVerdict::Resume(0))
            }
            // brk(addr) — the FIRST syscall real ld.so makes.
            214 => Some(self.service_identity_brk(a0)),
            // mremap: the dispatcher's arena answer is poison on the identity
            // tier (an address with no host mapping), so fail closed with the
            // gap NAMED instead of falling through.
            216 => unsupported(self, "mremap on tier D (identity mremap not built yet)"),
            _ => None,
        }
    }

    /// `mmap(PROT_EXEC, fd)`: guest-created executable memory, serviced
    /// through the load group's scan+patch window pipeline (roadmap Phase 1
    /// item 5 — this is how ld.so maps libc.so.6's text). The file content
    /// comes through the dispatcher's own fd table, so whatever backend the
    /// file lives on (VFS overlay, host dir, synthetic) feeds the same
    /// pipeline. Refusals LEAVE named — tier T owns what the scan cannot
    /// prove.
    fn service_exec_file_mmap(
        &mut self,
        addr: u64,
        flags: carrick_abi::LinuxMmapFlags,
        fd: u64,
        offset: u64,
        len: u64,
    ) -> ServiceVerdict {
        let leave = |this: &mut Self, what: String| -> ServiceVerdict {
            this.outcome = Some(DirectRunOutcome::Unsupported {
                syscall: 222,
                outcome: what,
            });
            ServiceVerdict::Leave
        };
        let fixed = flags.contains(carrick_abi::LinuxMmapFlags::FIXED);
        // The group reference is derived from a thread-local pointer and
        // names memory separate from `self`, so it is held across the
        // `&mut self` file read below without aliasing.
        let Some(group) = active_group() else {
            return leave(
                self,
                "mmap(PROT_EXEC, fd) with no tier-D load group installed".to_string(),
            );
        };
        let file = match self.read_guest_file_all(fd) {
            Ok(file) => file,
            Err(retval) => return ServiceVerdict::Resume(retval),
        };
        let Ok(len_usize) = usize::try_from(len) else {
            return ServiceVerdict::Resume(crate::host_to_linux_errno(libc::EINVAL).guest_retval());
        };
        let result = if fixed {
            // The guest reserved this address; a MAP_FIXED exec segment must
            // land exactly there (plain-anon text + a separate island arena).
            group.map_fixed_exec_file_window(&file, offset, addr, len_usize)
        } else {
            group.map_exec_file_window(&file, offset, len_usize)
        };
        match result {
            Ok(Ok(base)) => ServiceVerdict::Resume(base as i64),
            Ok(Err(reason)) => leave(
                self,
                format!("mmap(PROT_EXEC, fd): tier D window scan refused: {reason}"),
            ),
            Err(error) => leave(self, format!("mmap(PROT_EXEC, fd): {error}")),
        }
    }

    /// A PRIVATE file-backed data mapping (ld.so's `MAP_FIXED` data
    /// segments, read-only header windows): fresh anonymous pages plus a
    /// dispatcher read of the file window. MAP_PRIVATE means writes never
    /// reach the file and later file changes need not appear, so the copy IS
    /// the semantic; bytes past EOF stay zero, mmap's own rule. Content is
    /// read BEFORE any address-space mutation so an fd error fails the mmap
    /// without having clobbered guest pages.
    fn service_data_file_mmap(
        &mut self,
        addr: u64,
        len: u64,
        prot: carrick_abi::LinuxProtFlags,
        flags: carrick_abi::LinuxMmapFlags,
        fd: u64,
        offset: u64,
    ) -> ServiceVerdict {
        let Ok(len_usize) = usize::try_from(len) else {
            return ServiceVerdict::Resume(crate::host_to_linux_errno(libc::EINVAL).guest_retval());
        };
        let bytes = match self.read_guest_file(fd, offset, len_usize) {
            Ok(bytes) => bytes,
            Err(retval) => return ServiceVerdict::Resume(retval),
        };
        let mut host_flags = libc::MAP_ANON | libc::MAP_PRIVATE;
        if flags.contains(carrick_abi::LinuxMmapFlags::FIXED) {
            host_flags |= libc::MAP_FIXED;
        }
        // SAFETY: identity tier; a MAP_FIXED target is the guest replacing
        // its own pages (ld.so mapping data over its text reservation).
        let mapped = unsafe {
            libc::mmap(
                addr as usize as *mut libc::c_void,
                len_usize,
                libc::PROT_READ | libc::PROT_WRITE,
                host_flags,
                -1,
                0,
            )
        };
        if mapped == libc::MAP_FAILED {
            return host_errno_verdict();
        }
        if flags.contains(carrick_abi::LinuxMmapFlags::FIXED)
            && let Some(group) = active_group()
        {
            group.note_plain_replacement(mapped as u64, len);
        }
        // SAFETY: `bytes.len() == len_usize` and the mapping was just
        // created RW at `mapped`.
        unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), mapped.cast::<u8>(), len_usize) };
        let final_prot = host_prot(prot);
        if final_prot != (libc::PROT_READ | libc::PROT_WRITE) {
            // SAFETY: narrowing the mapping just created to the guest's prot.
            let rc = unsafe { libc::mprotect(mapped, len_usize, final_prot) };
            if rc != 0 {
                return host_errno_verdict();
            }
        }
        ServiceVerdict::Resume(mapped as i64)
    }

    /// Change the protection of tier-D window pages by REPLACING them:
    /// Darwin's `mprotect` refuses MAP_JIT pages outright (probed: EACCES
    /// for every target protection), so the only way to honor a guest
    /// protection change inside a window is to swap the pages for plain
    /// ones. Contents are preserved — stash the (readable) JIT bytes, map
    /// plain anon RW in place, copy back, then apply the requested
    /// protection — so the guest-visible mprotect guarantee holds even
    /// through a PROT_NONE round trip. The replaced range loses
    /// patched-executable coverage: plain pages cannot execute, and a later
    /// PROT_EXEC flip on them fails closed by the containment rule.
    ///
    /// The caller guarantees the range is still original window pages
    /// (`covers_patched_executable`), which is what makes the stash read
    /// safe: original MAP_JIT pages are always readable (no mprotect ever
    /// succeeded on them, and they were created R+W+X).
    fn replace_jit_pages_with_protection(
        &mut self,
        addr: u64,
        len: u64,
        target: i32,
    ) -> ServiceVerdict {
        let Ok(len_usize) = usize::try_from(len) else {
            return ServiceVerdict::Resume(crate::host_to_linux_errno(libc::EINVAL).guest_retval());
        };
        let mut stash = vec![0_u8; len_usize];
        // SAFETY: the caller proved the range lies in original (readable)
        // window pages, and the guest is parked in the handler.
        unsafe {
            std::ptr::copy_nonoverlapping(
                addr as usize as *const u8,
                stash.as_mut_ptr(),
                len_usize,
            );
        }
        // SAFETY: replacing the guest's own window pages in place.
        let mapped = unsafe {
            libc::mmap(
                addr as usize as *mut libc::c_void,
                len_usize,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANON | libc::MAP_FIXED,
                -1,
                0,
            )
        };
        if mapped == libc::MAP_FAILED {
            return host_errno_verdict();
        }
        if let Some(group) = active_group() {
            group.note_plain_replacement(addr, len);
        }
        // SAFETY: fresh RW pages at `addr`, sized `len_usize`.
        unsafe { std::ptr::copy_nonoverlapping(stash.as_ptr(), mapped.cast::<u8>(), len_usize) };
        if target != (libc::PROT_READ | libc::PROT_WRITE) {
            // SAFETY: plain pages now; any non-EXEC protection is honored.
            let rc = unsafe { libc::mprotect(mapped, len_usize, target) };
            if rc != 0 {
                return host_errno_verdict();
            }
        }
        ServiceVerdict::Resume(0)
    }

    /// Dispatch a runner-synthesized syscall (`fstat`/`pread64` for the mmap
    /// file services) through the one shared dispatcher — the same fd
    /// semantics every guest read gets. Errno outcomes come back as the
    /// guest retval to fail the surrounding mmap with; any non-value outcome
    /// is EIO (these numbers cannot fork or exit).
    fn dispatch_synthesized(&mut self, number: u64, args: [u64; 6]) -> Result<i64, i64> {
        let request = SyscallRequest::from_raw(carrick_hal::RawSyscall {
            number: CanonicalNr(number),
            args,
            guest_abi: LinuxGuestAbi::Aarch64,
            native_number: NativeNr(number),
        });
        let reporter = crate::compat::CompatReporter::default();
        match self
            .dispatcher
            .dispatch(request, &mut self.memory, &reporter)
        {
            Ok(DispatchOutcome::Returned { value }) => Ok(value),
            Ok(DispatchOutcome::Errno { errno }) => Err(errno.guest_retval()),
            _ => Err(crate::host_to_linux_errno(libc::EIO).guest_retval()),
        }
    }

    /// The byte length of the guest file behind `fd`, via `fstat(2)`.
    fn guest_file_len(&mut self, fd: u64) -> Result<u64, i64> {
        use zerocopy::FromBytes as _;
        let mut stat_bytes = [0_u8; core::mem::size_of::<carrick_abi::LinuxStat>()];
        let addr = stat_bytes.as_mut_ptr() as u64;
        // fstat(fd, statbuf); the dispatcher writes the guest's aarch64
        // `struct stat` through the identity memory into our buffer.
        self.dispatch_synthesized(80, [fd, addr, 0, 0, 0, 0])?;
        let stat = carrick_abi::LinuxStat::read_from_bytes(&stat_bytes)
            .map_err(|_| crate::host_to_linux_errno(libc::EIO).guest_retval())?;
        Ok(stat.st_size.max(0) as u64)
    }

    /// Read `[offset, offset + len)` of the guest file behind `fd` via
    /// `pread64(2)` — offset-neutral, so the guest's own file position is
    /// undisturbed. A short read leaves the tail zeroed (mmap's
    /// beyond-EOF semantic).
    fn read_guest_file(&mut self, fd: u64, offset: u64, len: usize) -> Result<Vec<u8>, i64> {
        let mut out = vec![0_u8; len];
        let mut done = 0_usize;
        while done < len {
            let addr = out.as_mut_ptr() as u64 + done as u64;
            let n = self.dispatch_synthesized(
                67,
                [fd, addr, (len - done) as u64, offset + done as u64, 0, 0],
            )?;
            if n <= 0 {
                break;
            }
            done += n as usize;
        }
        Ok(out)
    }

    /// The whole guest file behind `fd`: `fstat` for the length, `pread64`
    /// for the bytes. The exec-window pipeline needs the full file because
    /// the section headers that place the code live at its end.
    fn read_guest_file_all(&mut self, fd: u64) -> Result<Vec<u8>, i64> {
        let len = self.guest_file_len(fd)?;
        let len = usize::try_from(len)
            .map_err(|_| crate::host_to_linux_errno(libc::EINVAL).guest_retval())?;
        self.read_guest_file(fd, 0, len)
    }

    /// `brk(2)`, identity-style (see [`IdentityBrk`]). Linux semantics: on
    /// any failure or out-of-range request, return the CURRENT break —
    /// `brk` never errnos.
    fn service_identity_brk(&mut self, addr: u64) -> ServiceVerdict {
        const PAGE: u64 = HOST_PAGE_SIZE;
        if self.brk.is_none() {
            // SAFETY: fresh PROT_NONE reservation, kernel-chosen address.
            let base = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    IdentityBrk::RESERVE,
                    libc::PROT_NONE,
                    libc::MAP_PRIVATE | libc::MAP_ANON,
                    -1,
                    0,
                )
            };
            if base == libc::MAP_FAILED {
                // No break exists and none can: park the run with the reason
                // named rather than inventing an address.
                self.outcome = Some(DirectRunOutcome::Unsupported {
                    syscall: 214,
                    outcome: "brk reservation failed".to_string(),
                });
                return ServiceVerdict::Leave;
            }
            let base = base as u64;
            self.brk = Some(IdentityBrk {
                base,
                current: base,
            });
        }
        let Some(brk) = self.brk.as_mut() else {
            // Populated just above; this arm keeps the no-panic gate total.
            // "No change" is brk's own failure semantic, and with no break
            // the current break is 0.
            return ServiceVerdict::Resume(0);
        };
        let (lo, hi) = (brk.base, brk.base + IdentityBrk::RESERVE as u64);
        if addr < lo || addr > hi {
            return ServiceVerdict::Resume(brk.current as i64);
        }
        let committed = (brk.current - lo).next_multiple_of(PAGE);
        let wanted = (addr - lo).next_multiple_of(PAGE);
        if wanted > committed {
            // SAFETY: committing untouched reservation pages; zero-fill on
            // first touch preserves the anonymous-memory guarantee.
            let rc = unsafe {
                libc::mprotect(
                    (lo + committed) as usize as *mut libc::c_void,
                    (wanted - committed) as usize,
                    libc::PROT_READ | libc::PROT_WRITE,
                )
            };
            if rc != 0 {
                return ServiceVerdict::Resume(brk.current as i64);
            }
        } else if wanted < committed {
            // SAFETY: replacing released break pages with a fresh PROT_NONE
            // mapping so a later regrowth re-delivers ZEROS.
            let remapped = unsafe {
                libc::mmap(
                    (lo + wanted) as usize as *mut libc::c_void,
                    (committed - wanted) as usize,
                    libc::PROT_NONE,
                    libc::MAP_PRIVATE | libc::MAP_ANON | libc::MAP_FIXED,
                    -1,
                    0,
                )
            };
            if remapped == libc::MAP_FAILED {
                return ServiceVerdict::Resume(brk.current as i64);
            }
        }
        brk.current = addr;
        ServiceVerdict::Resume(addr as i64)
    }

    /// Service one syscall from a tier-D island.
    fn service(&mut self, ctx: &GuestContext) -> ServiceVerdict {
        self.syscalls += 1;
        let number = ctx.syscall_nr();
        if let Some(verdict) = self.service_identity_memory(ctx) {
            return verdict;
        }
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
            Ok(DispatchOutcome::Returned { value }) => ServiceVerdict::Resume(value),
            Ok(DispatchOutcome::Errno { errno }) => ServiceVerdict::Resume(errno.guest_retval()),
            Ok(DispatchOutcome::Exit { code }) => {
                self.outcome = Some(DirectRunOutcome::Exited { code });
                ServiceVerdict::Leave
            }
            // A thread-creating clone is the roadmap Phase 1 item 4 boundary:
            // tier D's TLS/x18/context slots are per-LOAD-GROUP, coherent for
            // a single-threaded guest but NOT per-thread. Spawning a second
            // guest thread here would have both threads read one TLS base —
            // incoherent by construction — so tier D fails CLOSED with the
            // boundary named rather than run an unsound thread. Single-
            // threaded guests (dash, cpython's own `-c`) never reach this.
            Ok(DispatchOutcome::CloneThread { .. }) => {
                self.outcome = Some(DirectRunOutcome::Unsupported {
                    syscall: number,
                    outcome: "thread-creating clone: tier D slots are per-load-group, \
                              not per-thread (roadmap Phase 1 item 4)"
                        .to_string(),
                });
                ServiceVerdict::Leave
            }
            Ok(other) => {
                self.outcome = Some(DirectRunOutcome::Unsupported {
                    syscall: number,
                    outcome: format!("{other:?}"),
                });
                ServiceVerdict::Leave
            }
            Err(error) => {
                self.outcome = Some(DirectRunOutcome::Unsupported {
                    syscall: number,
                    outcome: error.to_string(),
                });
                ServiceVerdict::Leave
            }
        }
    }
}

/// Lower a guest protection to the host's non-executable bits. EXEC never
/// reaches here: every EXEC path is routed to the scan+patch pipeline or
/// fails closed before protection is applied.
fn host_prot(prot: carrick_abi::LinuxProtFlags) -> i32 {
    use carrick_abi::LinuxProtFlags;
    let mut host = 0;
    if prot.contains(LinuxProtFlags::READ) {
        host |= libc::PROT_READ;
    }
    if prot.contains(LinuxProtFlags::WRITE) {
        host |= libc::PROT_WRITE;
    }
    host
}

/// Resume the guest with the host's errno, translated to Linux's.
fn host_errno_verdict() -> ServiceVerdict {
    let host = std::io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(libc::EINVAL);
    ServiceVerdict::Resume(crate::host_to_linux_errno(host).guest_retval())
}

thread_local! {
    /// The runner serving the guest executing on THIS thread.
    ///
    /// A directly-executed guest runs on the host thread that entered it, so
    /// "which runner" is exactly a per-thread question - and it stays correct
    /// when tier D grows threads.
    static ACTIVE: std::cell::Cell<*mut DirectRunner> =
        const { std::cell::Cell::new(std::ptr::null_mut()) };
    /// The load group of that guest, installed alongside the runner: the
    /// identity memory services need it for the mmap(PROT_EXEC) window
    /// pipeline and the mprotect(PROT_EXEC) containment rule.
    static ACTIVE_GROUP: std::cell::Cell<*const DirectLoadGroup> =
        const { std::cell::Cell::new(std::ptr::null()) };
}

/// The load group installed for the guest on this thread, if any.
fn active_group<'a>() -> Option<&'a DirectLoadGroup> {
    let group = ACTIVE_GROUP.with(std::cell::Cell::get);
    // SAFETY: `with_runner` installs the pointer for exactly the window in
    // which the guest can call back and clears it before returning, and the
    // reference is only used inside handler-called services within that
    // window.
    unsafe { group.as_ref() }
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
    match runner.service(ctx) {
        ServiceVerdict::Resume(value) => ctx.set_return(value),
        // The guest's own state at the syscall stays parked in the context —
        // no fabricated return value — and the island's leave leg returns
        // control to `enter`'s caller (guest-leave contract).
        ServiceVerdict::Leave => ctx.request_leave(),
    }
}

/// Build a tier-D image with this so its syscalls reach the real dispatcher.
pub fn island_handler() -> extern "C" fn(*mut GuestContext) {
    dispatch_from_island
}

/// Install `runner` and `group` for the current thread while `body` runs the
/// guest.
///
/// # Safety
/// `body` must enter an image (or runtime window) of `group`, built with
/// [`island_handler`].
pub unsafe fn with_runner<R>(
    runner: &mut DirectRunner,
    group: &DirectLoadGroup,
    body: impl FnOnce() -> R,
) -> R {
    let previous_runner = ACTIVE.with(|slot| slot.replace(std::ptr::from_mut(runner)));
    let previous_group = ACTIVE_GROUP.with(|slot| slot.replace(std::ptr::from_ref(group)));
    let result = body();
    ACTIVE.with(|slot| slot.set(previous_runner));
    ACTIVE_GROUP.with(|slot| slot.set(previous_group));
    result
}

#[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
mod tests {
    use super::*;
    use carrick_native_darwin::direct::DirectLoadGroup;

    /// The STRETCH gate: real CPython 3.12 running `print(1)` end to end on
    /// tier D. `python3.12` is a real, PIE, dynamically linked interpreter
    /// from the debian-based `python:3.12-slim` image; its real ld.so maps
    /// libc, libm, and the 6.6 MB `libpython3.12.so` through the exec-mmap
    /// window pipeline (both the whole-span and MAP_FIXED strategies), and
    /// CPython's full C runtime initializes, imports the frozen `encodings`
    /// codec from the staged stdlib, evaluates `print(1)`, and exits 0 with
    /// `1\n` on stdout — all through the one dispatcher, single-threaded.
    ///
    /// Runs from a rootfs staged on disk under `target/tierd-live/pyroot`
    /// (skips loudly when absent). Staging, from the cached OCI layers:
    /// `bin/python3.12` + `lib/libpython3.12.so.1.0` into `usr/local/{bin,
    /// lib}`, the interpreter/libc/libm into `lib`, `lib64`, `usr/lib` (the
    /// default search path, since `$ORIGIN` RUNPATH cannot resolve without a
    /// real `/proc/self/exe`), and the full `python3.12` stdlib under
    /// `usr/local/lib`.
    #[test]
    fn real_cpython_prints_through_tier_d() {
        let root = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../target/tierd-live/pyroot"
        );
        let (Ok(py), Ok(ld)) = (
            std::fs::read(format!("{root}/usr/local/bin/python3.12")),
            std::fs::read(format!("{root}/lib/ld-linux-aarch64.so.1")),
        ) else {
            eprintln!("skipping: no python rootfs under target/tierd-live/pyroot (see test doc)");
            return;
        };
        let group =
            DirectLoadGroup::load_with_interpreter(&py, |_| Ok(ld.clone()), island_handler())
                .expect("load")
                .expect("python and its ld.so are tier-D eligible");
        let interp = group.interpreter().expect("interpreter mapped");
        let stack = DirectStack::build(
            &py,
            group.main().bias(),
            Some(interp.bias()),
            &[
                b"python3".to_vec(),
                b"-I".to_vec(),
                b"-S".to_vec(),
                b"-c".to_vec(),
                b"print(1)".to_vec(),
            ],
            &[b"PYTHONHOME=/usr/local".to_vec()],
        )
        .expect("stack builds");
        let mut dispatcher = SyscallDispatcher::new();
        dispatcher.set_fs_backend(Box::new(
            crate::fs_backend::HostFsBackend::from_existing_dir(
                cap_std::fs::Dir::open_ambient_dir(root, cap_std::ambient_authority())
                    .expect("open python rootfs"),
            ),
        ));
        let mut runner = DirectRunner::new(dispatcher, IdentityMemory::new(0, u64::MAX));
        let entry = group.entry_pc();
        let sp = stack.sp();
        // SAFETY: patched images built with `island_handler`; the guest
        // leaves through its exit.
        unsafe { with_runner(&mut runner, &group, || group.enter_on_stack(entry, sp)) };
        assert_eq!(
            runner.outcome(),
            Some(&DirectRunOutcome::Exited { code: 0 }),
            "CPython evaluated print(1) and exited 0 on tier D (syscalls: {}; \
             stdout: {:?}; stderr: {:?})",
            runner.syscalls(),
            String::from_utf8_lossy(&runner.dispatcher().stdout()),
            String::from_utf8_lossy(&runner.dispatcher().stderr()),
        );
        assert_eq!(
            runner.dispatcher().stdout(),
            b"1\n",
            "print(1) reached stdout through the one dispatcher"
        );
    }

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
        let group = DirectLoadGroup::load(&write_fixture(), island_handler())
            .expect("load")
            .expect("eligible");
        assert_eq!(group.main().svc_sites(), 1);
        let mut runner =
            DirectRunner::new(SyscallDispatcher::new(), IdentityMemory::new(0, u64::MAX));
        let entry = group.main().entry();
        // SAFETY: the image is patched and built with `island_handler`.
        unsafe { with_runner(&mut runner, &group, || group.enter(entry)) };

        assert_eq!(runner.syscalls(), 1, "exactly one syscall was serviced");
        assert_eq!(
            runner.dispatcher().stdout(),
            b"hi\n",
            "the guest's own write(2) reached the real dispatcher"
        );
    }

    /// The guest-leave contract, enforced at the syscall that ends the run:
    /// `exit(2)` must LEAVE through the handler, not merely be recorded while
    /// the guest keeps executing whatever bytes follow the `svc`. The poison
    /// write after the exit would be serviced by a runner without an exit
    /// path, so the assertions below are red against exactly that defect.
    #[test]
    fn exit_leaves_through_the_handler_instead_of_running_past_it() {
        const NR_EXIT: u32 = 93;
        let elf = elf_with_code(&[
            mov_reg(20, 30), // stash the incoming link register
            movz(0, 7, 0),   // exit code 7
            movz(8, NR_EXIT, 0),
            SVC_0,
            // POISON: everything from here on must never execute. A runner
            // without a real exit path resumes the guest here and services
            // this write, which is the observable difference.
            movz(9, 0x4141, 0), // "AA"
            str_pre_sp(9),
            mov_from_sp(1),
            movz(0, 1, 0),
            movz(2, 2, 0),
            movz(8, NR_WRITE, 0),
            SVC_0,
            ADD_SP_16,
            mov_reg(30, 20),
            0xd65f_03c0, // ret — reached only when the exit path is broken
        ]);
        let group = DirectLoadGroup::load(&elf, island_handler())
            .expect("load")
            .expect("eligible");
        let mut runner =
            DirectRunner::new(SyscallDispatcher::new(), IdentityMemory::new(0, u64::MAX));
        let entry = group.main().entry();
        // SAFETY: the image is patched and built with `island_handler`.
        unsafe { with_runner(&mut runner, &group, || group.enter(entry)) };

        assert_eq!(
            runner.outcome(),
            Some(&DirectRunOutcome::Exited { code: 7 }),
            "the exit was recorded"
        );
        assert_eq!(
            runner.syscalls(),
            1,
            "the guest left AT the exit; the poison write never reached the dispatcher"
        );
        assert_eq!(
            runner.dispatcher().stdout(),
            b"",
            "no poison bytes: the guest did not run past its own exit"
        );
    }

    /// `execve(2)` is the syscall the roadmap names as needing a real exit:
    /// the dispatcher resolves path/argv/envp and hands back an `Execve`
    /// outcome the RUNNER must act on, which tier D cannot yet — so the guest
    /// must leave through the handler with its full state parked in the
    /// context, not resume with a fabricated errno.
    #[test]
    fn execve_leaves_through_the_handler_with_the_guest_parked_at_the_syscall() {
        const NR_EXECVE: u32 = 221;
        const NR_EXIT: u32 = 93;
        let elf = elf_with_code(&[
            mov_reg(20, 30),
            movz(9, 0x782f, 0), // "/x" + NUL padding
            str_pre_sp(9),
            mov_from_sp(0), // x0 = pathname
            str_pre_sp(31), // NULL terminator word (str xzr)
            mov_from_sp(1), // x1 = argv (empty, NULL-terminated)
            mov_reg(2, 1),  // x2 = envp = same empty array
            movz(8, NR_EXECVE, 0),
            SVC_0,
            // POISON: a broken exit path resumes here and this exit(9)
            // overwrites the recorded outcome, which the assertion catches.
            movz(0, 9, 0),
            movz(8, NR_EXIT, 0),
            SVC_0,
            ADD_SP_16,
            ADD_SP_16,
            mov_reg(30, 20),
            0xd65f_03c0, // ret
        ]);
        let group = DirectLoadGroup::load(&elf, island_handler())
            .expect("load")
            .expect("eligible");
        let mut runner =
            DirectRunner::new(SyscallDispatcher::new(), IdentityMemory::new(0, u64::MAX));
        let entry = group.main().entry();
        // SAFETY: the image is patched and built with `island_handler`.
        unsafe { with_runner(&mut runner, &group, || group.enter(entry)) };

        assert!(
            matches!(
                runner.outcome(),
                Some(&DirectRunOutcome::Unsupported {
                    syscall: 221,
                    ref outcome
                }) if outcome.contains("Execve")
            ),
            "the run stopped AT the execve with the outcome named: {:?}",
            runner.outcome()
        );
        assert_eq!(
            runner.syscalls(),
            1,
            "the guest left AT the execve; the poison exit never ran"
        );
    }

    /// The tier-D exec stack: a REAL Linux process begins with argc/argv/
    /// envp/auxv on its stack, and the guest must find them through nothing
    /// but SP. The fixture reads argc from `[sp]` and `argv[0]` from
    /// `[sp+8]`, writes the first bytes of `argv[0]` to stdout, and exits
    /// with argc as its code — so a wrong layout fails loudly on three
    /// independent axes. The Rust side additionally walks the built stack
    /// past envp into the auxv and checks the interpreter contract values
    /// (`AT_PHDR`/`AT_ENTRY`; `AT_BASE` belongs to the interpreter chain).
    #[test]
    fn exec_stack_hands_argv_envp_auxv_to_the_guest() {
        const NR_EXIT: u32 = 93;
        let elf = elf_with_code(&[
            ldr_sp_imm(20, 0), // x20 = argc
            ldr_sp_imm(1, 8),  // x1 = argv[0] (the string's stack address)
            movz(0, 1, 0),     // fd 1
            movz(2, 5, 0),     // len 5: "hello"
            movz(8, NR_WRITE, 0),
            SVC_0,
            mov_reg(0, 20), // exit(argc)
            movz(8, NR_EXIT, 0),
            SVC_0,
        ]);
        let group = DirectLoadGroup::load(&elf, island_handler())
            .expect("load")
            .expect("eligible");
        let stack = DirectStack::build(
            &elf,
            group.main().bias(),
            None,
            &[b"hello-stack".to_vec(), b"arg1".to_vec()],
            &[b"PATH=/usr/bin".to_vec()],
        )
        .expect("stack builds");

        // Rust-side walk BEFORE entering: sp -> argc, argv[..], NULL,
        // envp[..], NULL, auxv pairs. This proves the auxv contract without
        // trusting the guest.
        // SAFETY: the stack was just built in host memory; reading it back.
        let word = |offset_words: u64| -> u64 {
            unsafe { *((stack.sp() + offset_words * 8) as *const u64) }
        };
        assert_eq!(word(0), 2, "argc");
        let argv0 = word(1);
        // SAFETY: argv[0] points into the same stack allocation.
        let argv0_bytes = unsafe { std::slice::from_raw_parts(argv0 as *const u8, 12) };
        assert_eq!(&argv0_bytes[..11], b"hello-stack");
        assert_eq!(word(3), 0, "argv NULL terminator");
        let envp0 = word(4);
        // SAFETY: envp[0] points into the same stack allocation.
        let envp0_bytes = unsafe { std::slice::from_raw_parts(envp0 as *const u8, 13) };
        assert_eq!(envp0_bytes, b"PATH=/usr/bin");
        assert_eq!(word(5), 0, "envp NULL terminator");
        let mut auxv = std::collections::HashMap::new();
        let mut cursor = 6;
        loop {
            let (a_type, a_val) = (word(cursor), word(cursor + 1));
            if a_type == carrick_abi::LINUX_AT_NULL {
                break;
            }
            auxv.insert(a_type, a_val);
            cursor += 2;
        }
        assert_eq!(
            auxv.get(&carrick_abi::LINUX_AT_ENTRY),
            Some(&group.main().entry()),
            "AT_ENTRY is the main image's BIASED entry"
        );
        let phdr = auxv
            .get(&carrick_abi::LINUX_AT_PHDR)
            .expect("AT_PHDR present");
        assert!(
            *phdr > group.main().bias(),
            "AT_PHDR is a runtime address inside the mapped image"
        );
        assert!(
            !auxv.contains_key(&carrick_abi::LINUX_AT_BASE),
            "no interpreter, no AT_BASE (a bogus AT_BASE was a real bug)"
        );
        assert!(
            auxv.contains_key(&carrick_abi::LINUX_AT_RANDOM),
            "AT_RANDOM present (glibc stack canary init reads it)"
        );

        // Now the guest's own view.
        let mut runner =
            DirectRunner::new(SyscallDispatcher::new(), IdentityMemory::new(0, u64::MAX));
        let entry = group.main().entry();
        let sp = stack.sp();
        // SAFETY: the image is patched and built with `island_handler`; the
        // guest leaves through its exit.
        unsafe { with_runner(&mut runner, &group, || group.enter_on_stack(entry, sp)) };
        assert_eq!(
            runner.outcome(),
            Some(&DirectRunOutcome::Exited { code: 2 }),
            "the guest read argc == 2 through its own SP"
        );
        assert_eq!(
            runner.dispatcher().stdout(),
            b"hello",
            "the guest wrote argv[0]'s bytes read via the stack"
        );
    }

    /// The interpreter chain, end to end on synthetic images: the main image
    /// declares `PT_INTERP`, the loader maps the resolved interpreter as a
    /// SECOND image in the same load group, entry goes to the INTERPRETER,
    /// and the interpreter finds the main image the only way the real ld.so
    /// can — by walking the stack past argv and envp into the auxv and
    /// branching to `AT_ENTRY`. The main image then exits through the
    /// handler. A wrong stack layout, a missing/wrong `AT_ENTRY` or
    /// `AT_BASE`, or entry at the wrong image all fail this test loudly (the
    /// interpreter exits 99 if the auxv has no `AT_ENTRY`).
    #[test]
    fn interpreter_chain_reaches_the_main_image_through_the_auxv() {
        const NR_EXIT: u32 = 93;
        // The "interpreter": skip argc/argv/envp, scan the auxv for AT_ENTRY
        // (a_type 9), `br` to its value; exit(99) at AT_NULL. Word indices in
        // the comments; branch offsets are (target - here) * 4.
        let interp_code: Vec<u32> = vec![
            ldr_sp_imm(1, 0),          //  0: x1 = argc
            add_imm(2, 31, 8),         //  1: x2 = &argv[0]
            add_lsl3(2, 2, 1),         //  2: x2 += argc * 8
            add_imm(2, 2, 8),          //  3: skip argv's NULL
            ldr_post8(3, 2),           //  4: x3 = *x2++, an envp entry
            cbnz_rel(3, -4),           //  5: while x3 != 0 goto 4
            ldr_post8(3, 2),           //  6: a_type
            ldr_post8(4, 2),           //  7: a_val
            cmp_imm(3, 9),             //  8: AT_ENTRY?
            b_eq_rel((14 - 9) * 4),    //  9: -> the br at 14
            cbnz_rel(3, (6 - 10) * 4), // 10: not AT_NULL: next pair
            movz(0, 99, 0),            // 11: AT_NULL, no AT_ENTRY
            movz(8, NR_EXIT, 0),       // 12
            SVC_0,                     // 13
            br_reg(4),                 // 14: hand control to the main image
        ];
        // The main image writes through the dispatcher and exits 42 — proof
        // it ran AFTER the interpreter handoff, with the stack intact.
        let main_code: Vec<u32> = vec![
            movz(9, 0x7964, 0),  // 'd','y'
            movk(9, 0x0a6e, 16), // 'n','\n'
            str_pre_sp(9),
            mov_from_sp(1),
            movz(0, 1, 0),
            movz(2, 4, 0),
            movz(8, NR_WRITE, 0),
            SVC_0,
            movz(0, 42, 0),
            movz(8, NR_EXIT, 0),
            SVC_0,
        ];
        let main_elf = elf_with_code_and_interp(&main_code, Some(b"/lib/fake-ld.so.1"));
        let interp_elf = elf_with_code(&interp_code);
        let group = DirectLoadGroup::load_with_interpreter(
            &main_elf,
            |path| {
                assert_eq!(path, "/lib/fake-ld.so.1", "the PT_INTERP path is resolved");
                Ok(interp_elf.clone())
            },
            island_handler(),
        )
        .expect("load")
        .expect("eligible");
        let interp = group.interpreter().expect("the interpreter was mapped");
        assert_ne!(
            interp.base(),
            group.main().base(),
            "two images, two mappings, one load group"
        );
        assert_eq!(
            group.entry_pc(),
            interp.entry(),
            "process entry is the INTERPRETER's entry"
        );

        let stack = DirectStack::build(
            &main_elf,
            group.main().bias(),
            Some(interp.bias()),
            &[b"dyn-fixture".to_vec()],
            &[],
        )
        .expect("stack builds");
        // Rust-side: AT_BASE is the interpreter's load bias — ld.so requires
        // it to find itself (a missing AT_BASE was a real carrick bug).
        // Layout for argc=1, no envp: argc(0) argv0(1) NULL(2) NULL(3) auxv(4..).
        // SAFETY: reading back the stack allocation just built.
        let word = |offset_words: u64| -> u64 {
            unsafe { *((stack.sp() + offset_words * 8) as *const u64) }
        };
        let mut auxv = std::collections::HashMap::new();
        let mut cursor = 4;
        loop {
            let (a_type, a_val) = (word(cursor), word(cursor + 1));
            if a_type == carrick_abi::LINUX_AT_NULL {
                break;
            }
            auxv.insert(a_type, a_val);
            cursor += 2;
        }
        assert_eq!(
            auxv.get(&carrick_abi::LINUX_AT_BASE),
            Some(&interp.bias()),
            "AT_BASE is the interpreter's load bias"
        );
        assert_eq!(
            auxv.get(&carrick_abi::LINUX_AT_ENTRY),
            Some(&group.main().entry()),
            "AT_ENTRY is the MAIN image's biased entry, reachable from the interpreter"
        );

        let mut runner =
            DirectRunner::new(SyscallDispatcher::new(), IdentityMemory::new(0, u64::MAX));
        let entry = group.entry_pc();
        let sp = stack.sp();
        // SAFETY: both images are patched and built with `island_handler`;
        // the guest leaves through its exit.
        unsafe { with_runner(&mut runner, &group, || group.enter_on_stack(entry, sp)) };
        assert_eq!(
            runner.outcome(),
            Some(&DirectRunOutcome::Exited { code: 42 }),
            "the MAIN image ran and exited through the handler (99 = interpreter \
             found no AT_ENTRY; anything else = the chain broke earlier)"
        );
        assert_eq!(
            runner.dispatcher().stdout(),
            b"dyn\n",
            "the main image's write went through the dispatcher after the handoff"
        );
    }

    /// Milestone: a REAL dynamically linked binary on tier D. The fixture is
    /// cross-compiled with the host's aarch64-linux-gnu toolchain
    /// (`-nostdlib -pie` with an explicit `--dynamic-linker`), and the
    /// interpreter is the toolchain sysroot's REAL glibc ld.so — real
    /// relocation processing, real TLS setup, real syscalls through the real
    /// dispatcher, veneered tpidr/x18 and patched `svc` throughout. The run
    /// must end with the MAIN image's exit(42) leaving through the handler.
    ///
    /// Skips (loudly) when the cross toolchain is not installed; on the
    /// canonical dev host it runs (`brew install aarch64-unknown-linux-gnu`).
    #[test]
    fn real_glibc_ld_so_runs_a_dynamic_binary_on_tier_d() {
        let probe = std::process::Command::new("aarch64-linux-gnu-gcc")
            .arg("-print-sysroot")
            .output();
        let Ok(output) = probe else {
            eprintln!("skipping: aarch64-linux-gnu-gcc not on PATH");
            return;
        };
        assert!(output.status.success(), "-print-sysroot failed");
        let sysroot = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let ld_path = format!("{sysroot}/lib/ld-linux-aarch64.so.1");
        let ld_bytes = std::fs::read(&ld_path).expect("sysroot ships ld.so");

        let dir = tempfile::tempdir().expect("tempdir");
        let src = dir.path().join("dyn.c");
        std::fs::write(
            &src,
            r#"
__attribute__((naked)) void _start(void) {
    __asm__ volatile(
        "mov x0, #42\n"
        "mov x8, #93\n"
        "svc #0\n");
}
"#,
        )
        .expect("write fixture source");
        let out = dir.path().join("dyn");
        let compile = std::process::Command::new("aarch64-linux-gnu-gcc")
            .args(["-nostdlib", "-pie", "-fpic", "-o"])
            .arg(&out)
            .arg(&src)
            .arg("-Wl,--dynamic-linker=/lib/ld-linux-aarch64.so.1")
            .output()
            .expect("cross gcc runs");
        assert!(
            compile.status.success(),
            "fixture compile failed: {}",
            String::from_utf8_lossy(&compile.stderr)
        );
        let main_elf = std::fs::read(&out).expect("read fixture");

        let group = DirectLoadGroup::load_with_interpreter(
            &main_elf,
            |path| {
                assert_eq!(path, "/lib/ld-linux-aarch64.so.1");
                Ok(ld_bytes.clone())
            },
            island_handler(),
        )
        .expect("load")
        .expect("real ld.so and the fixture are both tier-D eligible");
        let interp = group.interpreter().expect("interpreter mapped");
        let stack = DirectStack::build(
            &main_elf,
            group.main().bias(),
            Some(interp.bias()),
            &[b"dyn-real".to_vec()],
            &[],
        )
        .expect("stack builds");

        let mut runner =
            DirectRunner::new(SyscallDispatcher::new(), IdentityMemory::new(0, u64::MAX));
        let entry = group.entry_pc();
        let sp = stack.sp();
        // SAFETY: both images are patched and built with `island_handler`;
        // the guest leaves through its exit.
        unsafe { with_runner(&mut runner, &group, || group.enter_on_stack(entry, sp)) };
        assert_eq!(
            runner.outcome(),
            Some(&DirectRunOutcome::Exited { code: 42 }),
            "real ld.so ran to the main image, which exited through the \
             handler (syscalls serviced: {}; guest stdout: {:?}; guest \
             stderr: {:?})",
            runner.syscalls(),
            String::from_utf8_lossy(&runner.dispatcher().stdout()),
            String::from_utf8_lossy(&runner.dispatcher().stderr()),
        );
        assert_ne!(
            group.guest_tls(),
            0,
            "real ld.so initialized TLS through the veneers into the \
             LOAD-GROUP slot (glibc's TLS_INIT_TP is an `msr tpidr_el0`)"
        );
    }

    /// The former `/bin/dash` frontier, now CROSSED: a real libc-linked
    /// binary (`DT_NEEDED libc.so.6`). ld.so runs, finds the real libc.so.6
    /// through the dispatcher's VFS, maps its text with `mmap(PROT_EXEC,
    /// fd)` — the scan+patch window boundary, roadmap Phase 1 item 5 — maps
    /// its data segments `MAP_FIXED` over the reservation (guest-fd reads
    /// through the one fd table), relocates, runs glibc's full startup, and
    /// the program's `main` returns 41 out through the handler.
    ///
    /// Until item 5 landed, this test pinned the fail-closed stop at the
    /// named `mmap(PROT_EXEC, fd)` gap; its history is the red-first proof.
    #[test]
    fn dt_needed_binary_runs_through_the_exec_mmap_boundary() {
        let probe = std::process::Command::new("aarch64-linux-gnu-gcc")
            .arg("-print-sysroot")
            .output();
        let Ok(output) = probe else {
            eprintln!("skipping: aarch64-linux-gnu-gcc not on PATH");
            return;
        };
        assert!(output.status.success(), "-print-sysroot failed");
        let sysroot = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let ld_bytes =
            std::fs::read(format!("{sysroot}/lib/ld-linux-aarch64.so.1")).expect("ld.so");

        let dir = tempfile::tempdir().expect("tempdir");
        let src = dir.path().join("hello.c");
        std::fs::write(&src, "int main(void) { return 41; }\n").expect("write");
        let out = dir.path().join("hello");
        // -pie -fpie explicitly: this toolchain's default is ET_EXEC at
        // 0x400000, which tier D refuses by physics (the __PAGEZERO wall).
        let compile = std::process::Command::new("aarch64-linux-gnu-gcc")
            .args(["-pie", "-fpie", "-o"])
            .arg(&out)
            .arg(&src)
            .output()
            .expect("cross gcc runs");
        assert!(
            compile.status.success(),
            "compile failed: {}",
            String::from_utf8_lossy(&compile.stderr)
        );
        let main_elf = std::fs::read(&out).expect("read fixture");

        let group = DirectLoadGroup::load_with_interpreter(
            &main_elf,
            |_| Ok(ld_bytes.clone()),
            island_handler(),
        )
        .expect("load")
        .expect("eligible");
        let interp = group.interpreter().expect("interpreter mapped");
        let stack = DirectStack::build(
            &main_elf,
            group.main().bias(),
            Some(interp.bias()),
            &[b"hello-libc".to_vec()],
            &[],
        )
        .expect("stack builds");

        // A rootfs whose /lib64 holds the sysroot's REAL libc.so.6 — /lib64
        // because that is this toolchain's system search path, read from
        // ld.so's own `LD_DEBUG=libs` trace through the dispatcher — so the
        // search SUCCEEDS through the VFS and the run reaches the file mmap
        // itself instead of dying on the lookup.
        use crate::fs_backend::FsBackend as _;
        let libc_bytes = std::fs::read(format!("{sysroot}/lib/libc.so.6")).expect("sysroot libc");
        let scratch = tempfile::tempdir().expect("scratch rootfs");
        let dir = cap_std::fs::Dir::open_ambient_dir(scratch.path(), cap_std::ambient_authority())
            .expect("open scratch");
        let backend = crate::fs_backend::HostFsBackend::from_existing_dir(dir);
        backend.make_dir("/lib64").expect("mkdir /lib64");
        backend
            .set_file_contents("/lib64/libc.so.6", libc_bytes)
            .expect("place libc");
        let mut dispatcher = SyscallDispatcher::new();
        dispatcher.set_fs_backend(Box::new(backend));
        let mut runner = DirectRunner::new(dispatcher, IdentityMemory::new(0, u64::MAX));
        let entry = group.entry_pc();
        let sp = stack.sp();
        // SAFETY: patched images built with `island_handler`; the guest
        // leaves through its exit.
        unsafe { with_runner(&mut runner, &group, || group.enter_on_stack(entry, sp)) };
        assert_eq!(
            runner.outcome(),
            Some(&DirectRunOutcome::Exited { code: 41 }),
            "real ld.so mapped libc through the exec-mmap window and main \
             returned 41 (syscalls: {}; stderr: {:?})",
            runner.syscalls(),
            String::from_utf8_lossy(&runner.dispatcher().stderr()),
        );
    }

    /// THE GATE: `/bin/dash -c 'echo hi'` end to end on tier D — a real,
    /// stripped, PIE `/bin/dash` from a debian arm64 image, its real
    /// ld-linux-aarch64.so.1 as the interpreter, its real libc.so.6 found
    /// through the dispatcher's VFS and mapped through the exec-mmap window
    /// pipeline. `echo` is a dash builtin, so the whole run is one process:
    /// ld.so relocation, glibc startup, dash's parser, the builtin's
    /// write(2), and exit(0) through the handler.
    ///
    /// Binary sources (loud skip when absent): extracted from the cached
    /// debian OCI layer into `target/tierd-live` —
    /// `cd target/tierd-live && tar -xzf ~/.carrick/blobs/sha256/<debian
    /// stable layer digest> usr/bin/dash usr/lib/aarch64-linux-gnu/libc.so.6
    /// usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1`.
    #[test]
    fn real_dash_echoes_through_tier_d() {
        let live = concat!(env!("CARGO_MANIFEST_DIR"), "/../../target/tierd-live");
        let read = |name: &str| std::fs::read(format!("{live}/{name}"));
        let (Ok(dash_elf), Ok(ld_bytes), Ok(libc_bytes)) = (
            read("usr/bin/dash"),
            read("usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1"),
            read("usr/lib/aarch64-linux-gnu/libc.so.6"),
        ) else {
            eprintln!("skipping: no debian binaries under target/tierd-live (see test doc)");
            return;
        };

        let group = DirectLoadGroup::load_with_interpreter(
            &dash_elf,
            |path| {
                assert_eq!(path, "/lib/ld-linux-aarch64.so.1");
                Ok(ld_bytes.clone())
            },
            island_handler(),
        )
        .expect("load")
        .expect("dash and its ld.so are tier-D eligible");
        let interp = group.interpreter().expect("interpreter mapped");
        let stack = DirectStack::build(
            &dash_elf,
            group.main().bias(),
            Some(interp.bias()),
            &[b"dash".to_vec(), b"-c".to_vec(), b"echo hi".to_vec()],
            &[b"PATH=/usr/bin:/bin".to_vec()],
        )
        .expect("stack builds");

        // A rootfs carrying libc at every stop of debian ld.so's built-in
        // search list, so the lookup succeeds wherever this ld looks.
        use crate::fs_backend::FsBackend as _;
        let scratch = tempfile::tempdir().expect("scratch rootfs");
        let dir = cap_std::fs::Dir::open_ambient_dir(scratch.path(), cap_std::ambient_authority())
            .expect("open scratch");
        let backend = crate::fs_backend::HostFsBackend::from_existing_dir(dir);
        for parent in [
            "/lib",
            "/lib/aarch64-linux-gnu",
            "/lib64",
            "/usr",
            "/usr/lib",
        ] {
            backend.make_dir(parent).expect("mkdir");
        }
        for path in [
            "/lib/aarch64-linux-gnu/libc.so.6",
            "/lib64/libc.so.6",
            "/lib/libc.so.6",
        ] {
            backend
                .set_file_contents(path, libc_bytes.clone())
                .expect("place libc");
        }
        let mut dispatcher = SyscallDispatcher::new();
        dispatcher.set_fs_backend(Box::new(backend));
        let mut runner = DirectRunner::new(dispatcher, IdentityMemory::new(0, u64::MAX));
        let entry = group.entry_pc();
        let sp = stack.sp();
        // SAFETY: patched images built with `island_handler`; the guest
        // leaves through its exit.
        unsafe { with_runner(&mut runner, &group, || group.enter_on_stack(entry, sp)) };
        assert_eq!(
            runner.outcome(),
            Some(&DirectRunOutcome::Exited { code: 0 }),
            "dash -c 'echo hi' ran end to end on tier D (syscalls: {}; \
             stdout: {:?}; stderr: {:?})",
            runner.syscalls(),
            String::from_utf8_lossy(&runner.dispatcher().stdout()),
            String::from_utf8_lossy(&runner.dispatcher().stderr()),
        );
        assert_eq!(
            runner.dispatcher().stdout(),
            b"hi\n",
            "the builtin echo's bytes came through the one dispatcher"
        );
    }

    /// A thread-creating `clone(2)` LEAVES named at the item-4 boundary:
    /// tier D's TLS/x18/context slots are per-load-group, not per-thread, so
    /// spawning a second guest thread would be unsound. A single-threaded
    /// guest never reaches this; a `pthread_create`-shaped clone
    /// (`CLONE_VM|CLONE_THREAD|CLONE_SIGHAND`) must fail closed, not run.
    #[test]
    fn thread_creating_clone_leaves_at_the_per_thread_boundary() {
        const NR_CLONE: u32 = 220;
        const NR_EXIT: u32 = 93;
        // flags = CLONE_VM|CLONE_THREAD|CLONE_SIGHAND|CLONE_FS|CLONE_FILES,
        // the pthread shape the dispatcher classifies as CloneThread.
        const FLAGS: u32 = 0x100 | 0x1_0000 | 0x800 | 0x200 | 0x400;
        let elf = elf_with_code(&[
            mov_reg(20, 30),
            movz(0, FLAGS & 0xffff, 0),
            movk(0, FLAGS >> 16, 16), // x0 = flags
            movz(1, 0x1000, 0),       // x1 = a nonzero child stack
            movz(2, 0, 0),
            movz(3, 0, 0),
            movz(4, 0, 0),
            movz(8, NR_CLONE, 0),
            SVC_0,
            // POISON: a runner that ran an unsound thread would resume here.
            movz(0, 5, 0),
            movz(8, NR_EXIT, 0),
            SVC_0,
        ]);
        let group = DirectLoadGroup::load(&elf, island_handler())
            .expect("load")
            .expect("eligible");
        let mut runner =
            DirectRunner::new(SyscallDispatcher::new(), IdentityMemory::new(0, u64::MAX));
        let entry = group.main().entry();
        // SAFETY: patched image built with `island_handler`.
        unsafe { with_runner(&mut runner, &group, || group.enter(entry)) };
        assert!(
            matches!(
                runner.outcome(),
                Some(&DirectRunOutcome::Unsupported { syscall: 220, ref outcome })
                    if outcome.contains("per-thread") && outcome.contains("item 4")
            ),
            "the thread clone left AT the per-thread boundary, named: {:?}",
            runner.outcome()
        );
        assert_eq!(
            runner.syscalls(),
            1,
            "the guest left AT the clone; the poison exit never ran"
        );
    }

    /// `ldr xt, [sp, #imm]`
    const fn ldr_sp_imm(rt: u32, byte_offset: u32) -> u32 {
        0xf940_0000 | ((byte_offset / 8) << 10) | (31 << 5) | rt
    }
    /// `add xd, xn, #imm` (rn = 31 reads SP)
    const fn add_imm(rd: u32, rn: u32, imm12: u32) -> u32 {
        0x9100_0000 | (imm12 << 10) | (rn << 5) | rd
    }
    /// `add xd, xn, xm, lsl #3`
    const fn add_lsl3(rd: u32, rn: u32, rm: u32) -> u32 {
        0x8b00_0000 | (rm << 16) | (3 << 10) | (rn << 5) | rd
    }
    /// `ldr xt, [xn], #8`
    const fn ldr_post8(rt: u32, rn: u32) -> u32 {
        0xf840_0400 | (8 << 12) | (rn << 5) | rt
    }
    /// `cbnz xt, <pc + offset>`
    const fn cbnz_rel(rt: u32, offset: i32) -> u32 {
        0xb500_0000 | (((offset as u32 >> 2) & 0x7ffff) << 5) | rt
    }
    /// `cmp xn, #imm` (SUBS XZR)
    const fn cmp_imm(rn: u32, imm12: u32) -> u32 {
        0xf100_0000 | (imm12 << 10) | (rn << 5) | 31
    }
    /// `b.eq <pc + offset>`
    const fn b_eq_rel(offset: i32) -> u32 {
        0x5400_0000 | (((offset as u32 >> 2) & 0x7ffff) << 5)
    }
    /// `br xn`
    const fn br_reg(rn: u32) -> u32 {
        0xd61f_0000 | (rn << 5)
    }

    /// Minimal ET_DYN wrapper with a section header table, which tier D's
    /// eligibility scan requires (it walks SHF_EXECINSTR sections).
    ///
    /// Real-binary shape where it matters for the exec stack: the FIRST
    /// `PT_LOAD` covers the ELF header and program headers at vaddr 0 (every
    /// real toolchain binary does this), which is what lets the load planner
    /// derive `AT_PHDR` — a fixture whose phdrs sit outside every segment
    /// would rightly get no `AT_PHDR` at all.
    fn elf_with_code(code: &[u32]) -> Vec<u8> {
        elf_with_code_and_interp(code, None)
    }

    /// As [`elf_with_code`], plus an optional `PT_INTERP` naming the given
    /// interpreter path — the shape of every real dynamically linked binary.
    fn elf_with_code_and_interp(code: &[u32], interp: Option<&[u8]>) -> Vec<u8> {
        let code_bytes: Vec<u8> = code.iter().flat_map(|w| w.to_le_bytes()).collect();
        let entry: u64 = 0x1000;
        let phnum: u64 = if interp.is_some() { 3 } else { 2 };
        let headers_len: u64 = 0x40 + phnum * 56;
        let mut elf = vec![0_u8; headers_len as usize];
        elf[..4].copy_from_slice(b"\x7fELF");
        elf[4] = 2;
        elf[5] = 1;
        elf[6] = 1;
        elf[0x10..0x12].copy_from_slice(&3_u16.to_le_bytes());
        elf[0x12..0x14].copy_from_slice(&183_u16.to_le_bytes());
        elf[0x18..0x20].copy_from_slice(&entry.to_le_bytes());
        elf[0x20..0x28].copy_from_slice(&0x40_u64.to_le_bytes());
        elf[0x36..0x38].copy_from_slice(&56_u16.to_le_bytes());
        elf[0x38..0x3a].copy_from_slice(&(phnum as u16).to_le_bytes());
        // PT_LOAD [0]: the headers, read-only at vaddr 0.
        let ph = 0x40;
        elf[ph..ph + 4].copy_from_slice(&1_u32.to_le_bytes());
        elf[ph + 4..ph + 8].copy_from_slice(&4_u32.to_le_bytes()); // PF_R
        elf[ph + 0x20..ph + 0x28].copy_from_slice(&headers_len.to_le_bytes());
        elf[ph + 0x28..ph + 0x30].copy_from_slice(&headers_len.to_le_bytes());
        // PT_LOAD [1]: the code.
        let ph = 0x40 + 56;
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
        // PT_INTERP [2]: path bytes appended past the section headers
        // (nothing after them reads by offset), NUL-terminated.
        if let Some(path) = interp {
            let interp_off = elf.len();
            elf.extend_from_slice(path);
            elf.push(0);
            let ph = 0x40 + 2 * 56;
            elf[ph..ph + 4].copy_from_slice(&3_u32.to_le_bytes());
            elf[ph + 0x08..ph + 0x10].copy_from_slice(&(interp_off as u64).to_le_bytes());
            elf[ph + 0x20..ph + 0x28].copy_from_slice(&((path.len() + 1) as u64).to_le_bytes());
        }
        elf
    }
}
