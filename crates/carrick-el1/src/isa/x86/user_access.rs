//! CPL0 user access against the live CR3, with a task-local #PF fixup.

use super::ArchError;
use carrick_el1_abi::CurrentTask;
use carrick_guest_arch::{Access, CopyProgress, FrameGpa, GuestLen, RootGpa, UserRange, UserVa};
use core::num::NonZeroU64;
use core::ptr::NonNull;
use core::sync::atomic::Ordering;

/// A CPL0-only fixture syscall that exercises this shared kernel module.
pub const USER_ACCESS_WITNESS: u64 = 0xffff_ffff_ffff_ff10;

const PRESENT: u64 = 1;
const WRITABLE: u64 = 1 << 1;
const USER: u64 = 1 << 2;
const LARGE: u64 = 1 << 7;
const TABLE_ADDR: u64 = 0x000f_ffff_ffff_f000;
const TABLE_DIRECT_VA: u64 = 0xffff_ffff_9000_0000;
const USER_CEILING: u64 = 0x0000_8000_0000_0000;

/// A user operand must be wholly within the canonical lower half. The
/// checked end also excludes wraparound into the supervisor address space.
const fn lower_half_range(address: u64, len: u64) -> bool {
    address < USER_CEILING
        && match address.checked_add(len) {
            Some(end) => end <= USER_CEILING,
            None => false,
        }
}

// Compile-time range cases also run for the freestanding image, whose x86
// module cannot be loaded by the host-only carrick-el1 unit-test target.
const _: () = {
    assert!(lower_half_range(0, 0));
    assert!(lower_half_range(USER_CEILING - 8, 8));
    assert!(!lower_half_range(USER_CEILING - 4, 8));
    assert!(!lower_half_range(USER_CEILING, 0));
    assert!(!lower_half_range(0xffff_ffff_8000_0000, 8));
    assert!(!lower_half_range(u64::MAX - 3, 8));
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransferDirection {
    FromUser,
    ToUser,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct MmKey(NonZeroU64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TaskGeneration(NonZeroU64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ThreadGeneration(NonZeroU64);

/// An exact running task's bounded CPL0 transfer. The owner, root and offset
/// stay attached across chunks; a reschedule to another MM cannot reuse it.
pub struct UserTransfer {
    owner: NonNull<CurrentTask>,
    task_generation: TaskGeneration,
    thread_generation: ThreadGeneration,
    mm: MmKey,
    root: RootGpa,
    user: UserVa,
    kernel: NonNull<u8>,
    total: GuestLen,
    completed: GuestLen,
    direction: TransferDirection,
}

fn live_root() -> RootGpa {
    let mut cr3: u64;
    // SAFETY: CPL0 reads the current address-space root; the PCID bits are
    // stripped before constructing the typed physical root address.
    unsafe { core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nostack, nomem)) };
    // The mask guarantees page alignment.
    RootGpa::page_aligned(FrameGpa::new(cr3 & TABLE_ADDR)).unwrap_or_else(|| {
        // SAFETY: a non-page-aligned masked CR3 is an impossible kernel state.
        unsafe { core::arch::asm!("ud2", options(noreturn)) }
    })
}

fn current_task(owner: &CurrentTask) -> bool {
    let current: u64;
    // SAFETY: SWAPGS selected the executing CPU's retained CpuBinding before
    // this kernel path. Offset 24 is its published task pointer.
    unsafe {
        core::arch::asm!("mov {}, qword ptr gs:[24]", out(reg) current,
            options(nostack, readonly, preserves_flags));
    }
    current == owner as *const CurrentTask as u64
}

impl UserTransfer {
    /// Admit a transfer from the currently executing task. The kernel buffer
    /// is a retained supervisor allocation of `total` bytes.
    ///
    /// # Safety
    /// `owner` and `kernel` must remain live until the final chunk or drop;
    /// `kernel` permits reads/writes for `total` bytes and does not alias the
    /// user range. A caller must not move this transfer to another CPU.
    pub unsafe fn new(
        owner: &CurrentTask,
        user: UserVa,
        kernel: NonNull<u8>,
        total: GuestLen,
        direction: TransferDirection,
    ) -> Result<Self, ArchError> {
        if !current_task(owner) || !lower_half_range(user.raw(), total.raw()) {
            return Err(ArchError::Unbound);
        }
        let task_generation = NonZeroU64::new(owner.execution.generation.load(Ordering::Acquire))
            .map(TaskGeneration)
            .ok_or(ArchError::Unbound)?;
        let mm = NonZeroU64::new(owner.mm.key.load(Ordering::Acquire))
            .map(MmKey)
            .ok_or(ArchError::Unbound)?;
        let thread_generation = NonZeroU64::new(owner.mm.thread_generation.load(Ordering::Acquire))
            .map(ThreadGeneration)
            .ok_or(ArchError::Unbound)?;
        Ok(Self {
            owner: NonNull::from(owner),
            task_generation,
            thread_generation,
            mm,
            root: live_root(),
            user,
            kernel,
            total,
            completed: GuestLen::new(0),
            direction,
        })
    }

    /// Copy at most `limit` bytes, stopping at this user page's boundary.
    /// The returned remaining length belongs to the whole transfer.
    pub fn advance(&mut self, limit: GuestLen) -> Result<CopyProgress, ArchError> {
        // SAFETY: the constructor requires owner retention through the
        // transfer, and the current-task check runs before any user access.
        let owner = unsafe { self.owner.as_ref() };
        if !current_task(owner)
            || owner.execution.generation.load(Ordering::Acquire) != self.task_generation.0.get()
            || owner.mm.key.load(Ordering::Acquire) != self.mm.0.get()
            || owner.mm.thread_generation.load(Ordering::Acquire) != self.thread_generation.0.get()
            || live_root() != self.root
        {
            return Err(ArchError::Unbound);
        }
        let remaining = self.total.raw() - self.completed.raw();
        let address = self.user.raw() + self.completed.raw();
        let page_remaining = 4096 - (address & 4095);
        let chunk = remaining.min(limit.raw()).min(page_remaining);
        if chunk == 0 {
            return Ok(CopyProgress {
                completed: GuestLen::new(0),
                remaining: GuestLen::new(remaining),
            });
        }
        let offset = usize::try_from(self.completed.raw()).map_err(|_| ArchError::Unbound)?;
        let len = usize::try_from(chunk).map_err(|_| ArchError::Unbound)?;
        // SAFETY: constructor retains a kernel buffer of `total` bytes;
        // offset+chunk is within that bound. `copy` validates the live user
        // permission chain and guards the actual instruction against #PF.
        let kernel = unsafe { self.kernel.as_ptr().add(offset) };
        let ok = unsafe {
            match self.direction {
                TransferDirection::FromUser => {
                    copy(owner, kernel, address as *const u8, len, address, false)
                }
                TransferDirection::ToUser => copy(
                    owner,
                    address as *mut u8,
                    kernel.cast_const(),
                    len,
                    address,
                    true,
                ),
            }
        };
        if !ok {
            return Err(ArchError::Unbound);
        }
        self.completed = GuestLen::new(self.completed.raw() + chunk);
        Ok(CopyProgress {
            completed: GuestLen::new(chunk),
            remaining: GuestLen::new(remaining - chunk),
        })
    }
}

/// Number of initial bytes whose live stage-1 walk grants the requested user
/// access. A later unmap is still caught by the guarded load/copy.
pub fn accessible_bytes(address: u64, len: usize, write: bool) -> usize {
    if len == 0 || !lower_half_range(address, len as u64) {
        return 0;
    }
    let mut root: u64;
    // SAFETY: CPL0 can read CR3; the image owner keeps the live page-table
    // frames supervisor mapped while the current task is executing.
    unsafe { core::arch::asm!("mov {}, cr3", out(reg) root, options(nostack, nomem)) };
    let root = root & TABLE_ADDR;
    let mut done = 0_usize;
    while done < len {
        let Some(va) = address.checked_add(done as u64) else {
            break;
        };
        if !page_allows(root, va, write) {
            break;
        }
        let page_remaining = 4096 - (va as usize & 4095);
        done += core::cmp::min(len - done, page_remaining);
    }
    done
}

/// Validate the live user permission prefix for the exact current task.
pub fn validate(
    owner: &CurrentTask,
    range: UserRange,
    access: Access,
) -> Result<GuestLen, ArchError> {
    if !current_task(owner) {
        return Err(ArchError::Unbound);
    }
    let len = usize::try_from(range.len().raw()).map_err(|_| ArchError::Unbound)?;
    let write = match access {
        Access::Read => false,
        Access::Write => true,
        Access::Execute => return Err(ArchError::Unbound),
    };
    Ok(GuestLen::new(
        accessible_bytes(range.start().raw(), len, write) as u64,
    ))
}

fn page_allows(root: u64, va: u64, write: bool) -> bool {
    let mut table = root;
    for (level, shift) in [39, 30, 21, 12].into_iter().enumerate() {
        let index = (va >> shift) & 511;
        // SAFETY: authenticated live CR3 and every present next-level entry
        // point at retained, supervisor-mapped page-table frames. This read
        // observes the current hardware permission chain, not a cached VMA.
        let desc = unsafe {
            core::ptr::read_volatile((TABLE_DIRECT_VA + table + index * 8) as *const u64)
        };
        if desc & (PRESENT | USER) != (PRESENT | USER) || (write && desc & WRITABLE == 0) {
            return false;
        }
        if level == 0 && desc & LARGE != 0 {
            return false;
        }
        if level == 3 || (level == 1 || level == 2) && desc & LARGE != 0 {
            return true;
        }
        table = desc & TABLE_ADDR;
    }
    false
}

/// Read one Linux user word. A fault is a typed absence, never a zero word.
pub fn read_u64(task: &CurrentTask, address: u64) -> Option<u64> {
    if !current_task(task) || accessible_bytes(address, 8, false) != 8 {
        return None;
    }
    guarded_read_u64(task, address)
}

fn guarded_read_u64(task: &CurrentTask, address: u64) -> Option<u64> {
    let fixup = &task.linux.fixup_pc as *const _ as *const u64;
    let mut value = 0_u64;
    let mut ok = 1_u64;
    // SAFETY: CPL0 owns the current task and its fixup slot. The CPL0 #PF
    // gate resumes only at label 2; CR4.SMAP gates STAC/CLAC on this CPU.
    // The range check excludes supervisor VA; carrick_mmu_core x86
    // descriptor_txn::check_leaf_privilege_matches_range must forbid any
    // supervisor leaf in the lower half during concurrent publication.
    unsafe {
        core::arch::asm!(
            "mov {tmp}, cr4", "bt {tmp}, 21", "jnc 9f", "stac", "9:",
            "lea {tmp}, [rip + 2f]", "mov [{fixup}], {tmp}",
            "mov {value}, [{address}]",
            "mov qword ptr [{fixup}], 0",
            "mov {tmp}, cr4", "bt {tmp}, 21", "jnc 8f", "clac", "8:",
            "jmp 3f",
            "2:",
            "mov qword ptr [{fixup}], 0",
            "mov {tmp}, cr4", "bt {tmp}, 21", "jnc 7f", "clac", "7:",
            "mov {ok}, 0", "mov {value}, 0",
            "3:",
            tmp = out(reg) _, fixup = in(reg) fixup, address = in(reg) address,
            value = inout(reg) value, ok = inout(reg) ok,
            options(nostack)
        );
    }
    (ok != 0).then_some(value)
}

/// Read a 32-bit user word as one x86 memory operation.
pub fn read_u32(task: &CurrentTask, address: u64) -> Option<u32> {
    if !current_task(task) || accessible_bytes(address, 4, false) != 4 {
        return None;
    }
    let fixup = &task.linux.fixup_pc as *const _ as *const u64;
    let mut value = 0_u64;
    let mut ok = 1_u64;
    // SAFETY: the guarded load and #PF fixup follow the same task-local
    // protocol as read_u64; the e-register load zero extends to 64 bits.
    // Concurrent leaf publication depends on
    // descriptor_txn::check_leaf_privilege_matches_range (see read_u64).
    unsafe {
        core::arch::asm!(
            "mov {tmp}, cr4", "bt {tmp}, 21", "jnc 9f", "stac", "9:",
            "lea {tmp}, [rip + 2f]", "mov [{fixup}], {tmp}",
            "mov {value:e}, [{address}]",
            "mov qword ptr [{fixup}], 0",
            "mov {tmp}, cr4", "bt {tmp}, 21", "jnc 8f", "clac", "8:",
            "jmp 3f",
            "2:",
            "mov qword ptr [{fixup}], 0",
            "mov {tmp}, cr4", "bt {tmp}, 21", "jnc 7f", "clac", "7:",
            "mov {ok}, 0", "mov {value}, 0",
            "3:",
            tmp = out(reg) _, fixup = in(reg) fixup, address = in(reg) address,
            value = inout(reg) value, ok = inout(reg) ok,
            options(nostack)
        );
    }
    (ok != 0).then_some(value as u32)
}

/// Copy with exactly one user operand; partial bytes on a fault are ignored by
/// the caller's false result, as on ARM. `src` and `dst` must permit pointer
/// arithmetic for `len` bytes; the user side may be unmapped.
///
/// # Safety
/// The kernel side must be valid, retained, and disjoint from the user side.
/// The task's #PF gate must be installed on this CPL0 CPU.
pub unsafe fn copy(
    task: &CurrentTask,
    dst: *mut u8,
    src: *const u8,
    len: usize,
    user_address: u64,
    user_write: bool,
) -> bool {
    if !current_task(task) || accessible_bytes(user_address, len, user_write) != len {
        return false;
    }
    // SAFETY: the caller supplied valid kernel memory and the task-local
    // #PF fixup is installed; the preflight narrows the normal access path.
    unsafe { guarded_copy(task, dst, src, len) }
}

unsafe fn guarded_copy(task: &CurrentTask, dst: *mut u8, src: *const u8, len: usize) -> bool {
    let fixup = &task.linux.fixup_pc as *const _ as *const u64;
    let mut ok = 1_u64;
    // SAFETY: REP MOVSB is guarded by the task-local fixup, and the caller
    // supplies a valid kernel operand. DF is cleared for the forward copy.
    // The caller's lower-half check relies on
    // descriptor_txn::check_leaf_privilege_matches_range for concurrent maps.
    unsafe {
        core::arch::asm!(
            "mov {tmp}, cr4", "bt {tmp}, 21", "jnc 9f", "stac", "9:",
            "lea {tmp}, [rip + 2f]", "mov [{fixup}], {tmp}",
            "cld", "rep movsb",
            "mov qword ptr [{fixup}], 0",
            "mov {tmp}, cr4", "bt {tmp}, 21", "jnc 8f", "clac", "8:",
            "jmp 3f",
            "2:",
            "mov qword ptr [{fixup}], 0",
            "mov {tmp}, cr4", "bt {tmp}, 21", "jnc 7f", "clac", "7:",
            "mov {ok}, 0",
            "3:",
            tmp = out(reg) _, fixup = in(reg) fixup,
            inout("rdi") dst => _, inout("rsi") src => _, inout("rcx") len => _,
            ok = inout(reg) ok,
            options(nostack)
        );
    }
    ok != 0
}

/// The fixture returns Linux EFAULT on a failed read/copy and the exact word
/// on success. The address is from the test's CPL3 register frame.
pub fn witness(task: &CurrentTask, address: u64, mode: u64) -> u64 {
    use carrick_guest_arch::{Access, MmuBackend, UserRange};
    let mut backend = super::X86Backend;
    match mode {
        0 => backend
            .read_user_word(task, UserVa::new(address), GuestLen::new(8))
            .unwrap_or((-14_i64) as u64),
        1 => {
            let mut word = 0_u64;
            // SAFETY: `word` is a live kernel destination, and the supplied
            // user address is guarded by the task's #PF recovery gate.
            let ok = unsafe {
                crate::substrate::file::copy_from_user_guarded(
                    task,
                    (&raw mut word).cast(),
                    address as *const u8,
                    8,
                )
            };
            if ok { word } else { (-14_i64) as u64 }
        }
        2 => {
            let word = 0x51ab_cdef_1234_5678_u64;
            // SAFETY: `word` is a live kernel source, and the user write is
            // guarded by the task's #PF recovery gate.
            let ok = unsafe {
                crate::substrate::file::copy_to_user_guarded(
                    task,
                    address as *mut u8,
                    (&raw const word).cast(),
                    8,
                )
            };
            if ok { 0 } else { (-14_i64) as u64 }
        }
        3 => backend
            .read_user_word(task, UserVa::new(address), GuestLen::new(4))
            .unwrap_or((-14_i64) as u64),
        4 | 5 => UserRange::checked(UserVa::new(address), GuestLen::new(16))
            .and_then(|range| {
                backend
                    .validate_user_access(
                        task,
                        range,
                        if mode == 4 {
                            Access::Read
                        } else {
                            Access::Write
                        },
                    )
                    .ok()
            })
            .map_or(0, GuestLen::raw),
        6 => guarded_read_u64(task, address).unwrap_or((-14_i64) as u64),
        7 => {
            let mut word = 0_u64;
            // SAFETY: fixture deliberately bypasses preflight to exercise
            // the #PF fixup; the kernel destination is a live stack word.
            let ok = unsafe { guarded_copy(task, (&raw mut word).cast(), address as *const u8, 8) };
            if ok { word } else { (-14_i64) as u64 }
        }
        8 => {
            use carrick_guest_arch::{GuestLen, MmuBackend};
            let mut word = 0_u64;
            // SAFETY: the fixture's task and stack word remain live through
            // both synchronous chunks on this exact CPL0 CPU.
            let Ok(mut transfer) = (unsafe {
                UserTransfer::new(
                    task,
                    UserVa::new(address),
                    NonNull::from(&mut word).cast(),
                    GuestLen::new(8),
                    TransferDirection::FromUser,
                )
            }) else {
                return (-14_i64) as u64;
            };
            let mut backend = super::X86Backend;
            let first = backend.copy_user_chunk(&mut transfer, GuestLen::new(4));
            let second = backend.copy_user_chunk(&mut transfer, GuestLen::new(4));
            match (first, second) {
                (Ok(a), Ok(b))
                    if a.completed.raw() == 4
                        && a.remaining.raw() == 4
                        && b.completed.raw() == 4
                        && b.remaining.raw() == 0 =>
                {
                    word
                }
                _ => (-14_i64) as u64,
            }
        }
        9 => {
            use carrick_guest_arch::{GuestLen, MmuBackend};
            let mut word = 0x6ace_b00c_1234_5678_u64;
            // SAFETY: the fixture retains this source word and task through
            // both synchronous chunks on the same execution lane.
            let Ok(mut transfer) = (unsafe {
                UserTransfer::new(
                    task,
                    UserVa::new(address),
                    NonNull::from(&mut word).cast(),
                    GuestLen::new(8),
                    TransferDirection::ToUser,
                )
            }) else {
                return (-14_i64) as u64;
            };
            let mut backend = super::X86Backend;
            let first = backend.copy_user_chunk(&mut transfer, GuestLen::new(4));
            let second = backend.copy_user_chunk(&mut transfer, GuestLen::new(4));
            match (first, second) {
                (Ok(a), Ok(b))
                    if a.completed.raw() == 4
                        && a.remaining.raw() == 4
                        && b.completed.raw() == 4
                        && b.remaining.raw() == 0 =>
                {
                    0
                }
                _ => (-14_i64) as u64,
            }
        }
        10 | 14 => {
            use carrick_guest_arch::{GuestLen, MmuBackend};
            let mut word = 0_u64;
            // SAFETY: the fixture retains its task and destination word while
            // it perturbs the MM key and restores it before returning.
            let Ok(mut transfer) = (unsafe {
                UserTransfer::new(
                    task,
                    UserVa::new(address),
                    NonNull::from(&mut word).cast(),
                    GuestLen::new(8),
                    TransferDirection::FromUser,
                )
            }) else {
                return (-14_i64) as u64;
            };
            let changed = if mode == 10 {
                &task.mm.key
            } else {
                &task.mm.thread_generation
            };
            let old = changed.load(Ordering::Acquire);
            changed.store(old.wrapping_add(1), Ordering::Release);
            let refused = super::X86Backend
                .copy_user_chunk(&mut transfer, GuestLen::new(8))
                .is_err();
            changed.store(old, Ordering::Release);
            if refused && word == 0 {
                0
            } else {
                (-14_i64) as u64
            }
        }
        11 => match backend.read_user_word(task, UserVa::new(address), GuestLen::new(8)) {
            Err(ArchError::Unbound) => 0,
            _ => (-14_i64) as u64,
        },
        12 => match backend.read_user_word(task, UserVa::new(address), GuestLen::new(3)) {
            Err(ArchError::InvalidWidth) => 0,
            _ => (-14_i64) as u64,
        },
        13 => {
            let stranger = CurrentTask::new();
            let Some(range) = UserRange::checked(UserVa::new(address), GuestLen::new(16)) else {
                return (-14_i64) as u64;
            };
            match backend.validate_user_access(&stranger, range, Access::Read) {
                Err(ArchError::Unbound) => 0,
                _ => (-14_i64) as u64,
            }
        }
        _ => (-22_i64) as u64,
    }
}
