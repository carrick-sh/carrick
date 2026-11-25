//! The one door to a host size change of a guest file (#1338 A1).
//!
//! A shared file window maps a host file's own pages into a carrier: a host
//! `mmap(MAP_SHARED)` of the file that the carrier keeps for the run. A host
//! shrink of that inode pulls pages out from under the guest's live leaves
//! (on KVM the next touch past the new end hangs the run). Until a shrink
//! revokes those leaves first (#1338 A3), a shrink of a windowed inode is
//! refused: a counted `ENOSYS`, before the host applies it.
//!
//! The fence keys on the **object the change is applied to**, never on a
//! path looked up beside it: every host size change of a guest file is made
//! through this module on the descriptor it mutates ([`admit_resize`],
//! [`open_truncating`], [`admit_discard`]), and the check `fstat`s
//! that same descriptor. No second lookup can name a different inode, and a
//! bind mount, a hard link, a rename or a `/proc/self/fd` reopen all reach
//! the same `(st_dev, st_ino)`.
//!
//! A change is a typed token: [`Resize`] and [`Discard`] are minted only by
//! the admissions, and a resize is applied only by the door itself. [`admit_write`]
//! and non-windowed checks hold `WINDOWED.read()`, while [`admit_resize`] upgrades
//! to `WINDOWED.write()` when `fd` names a windowed (or unstatable) inode in a
//! non-empty registry (serializing concurrent resizes, [`record`], and in-flight
//! [`admit_write`] regular-file writes). Normal host opens run unlocked; only the
//! non-Linux empty-registry fallback and Linux's single-FD `EMFILE` empty-registry
//! fallback hold `WINDOWED.read()` across the fallback `open(flags)` after `owned`
//! verified an unwindowed regular file so [`record`] cannot intervene.
//!
//! The registry is process-wide: a window slot is a host mapping of this
//! process, so any shrink this process applies to the inode breaks it,
//! whichever run asked. It holds no descriptor: a recorded inode is kept
//! alive by the window's own host mapping, and its birth time tells a
//! reused `(st_dev, st_ino)` apart. An inode stays recorded as long as its
//! window slot stays, for the run (the interim trade-off of A1), so the
//! registry is bounded by the window slots.

use std::collections::HashMap;
#[cfg(any(target_os = "linux", test))]
use std::os::fd::FromRawFd;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd, RawFd};
use std::sync::LazyLock;

use parking_lot::{RwLock, RwLockReadGuard, RwLockWriteGuard};

use crate::vfs::InodeIdentity;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct WindowEntry {
    birth: Birth,
    refs: usize,
}

/// Process-wide live pin keeping an inode registered in the shrink fence
/// while at least one carrier retains a shared window slot for it (#1338 A1,
/// #2975 P0 2). Holds no host descriptor; drops the entry when the last
/// carrier reference drops.
#[derive(Debug)]
pub struct WindowRegistration {
    identity: InodeIdentity,
}

impl WindowRegistration {
    pub fn identity(&self) -> InodeIdentity {
        self.identity
    }
}

impl Drop for WindowRegistration {
    fn drop(&mut self) {
        let mut registry = WINDOWED.write();
        if let std::collections::hash_map::Entry::Occupied(mut entry) =
            registry.entry(self.identity)
        {
            if entry.get().refs <= 1 {
                entry.remove();
            } else {
                entry.get_mut().refs -= 1;
            }
        }
    }
}

/// Each windowed inode, with its birth time when the host reports one and
/// active reference count. No descriptor is kept: the window's own host
/// mapping keeps the inode alive while it is recorded, and the birth time
/// tells a reused `(st_dev, st_ino)` from the recorded inode.
type Registry = HashMap<InodeIdentity, WindowEntry>;

static WINDOWED: LazyLock<RwLock<Registry>> = LazyLock::new(|| RwLock::new(HashMap::new()));

std::thread_local! {
    /// Changes this thread's door refused, so a caller can tell the door's
    /// `ENOSYS` from a layer's own ([`fenced_during`]).
    static REFUSED: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// Run `f`, and report whether the door refused a change on this thread
/// while it ran: its `ENOSYS` is then the call's answer, never a layer's
/// "not supported here" (a mount's `ENOSYS` falls through to the rootfs).
pub fn fenced_during<R>(f: impl FnOnce() -> R) -> (R, bool) {
    let before = REFUSED.with(std::cell::Cell::get);
    let result = f();
    (result, REFUSED.with(std::cell::Cell::get) != before)
}

fn refused() -> Fenced {
    REFUSED.with(|count| count.set(count.get().wrapping_add(1)));
    Fenced
}

/// A host size change of a file.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Change {
    /// Set the file's size to this many bytes (`ftruncate`, `O_TRUNC`).
    Resize(u64),
    /// Discard bytes without moving the end of the file (a hole punch, a
    /// range collapse, a whole-file rewrite): refused whenever a window
    /// maps the file.
    Discard,
}

/// Why the door refused a change: a window maps the file and the change
/// would shrink it or discard its bytes (or its identity could not be read
/// while a window exists). The caller answers `ENOSYS`, a counted refusal,
/// and applies nothing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Fenced;

impl Fenced {
    /// The host errno a fenced change answers: a counted `ENOSYS`.
    pub const ERRNO: libc::c_int = libc::ENOSYS;
}

#[allow(dead_code)]
enum RegistryGuard<'a> {
    Read(RwLockReadGuard<'a, Registry>),
    Write(RwLockWriteGuard<'a, Registry>),
}

/// An admitted resize of one descriptor's file to one length. Only
/// [`admit_resize`] mints one: it holds `WINDOWED.write()` when `fd` names a
/// windowed (or unstatable) inode in a non-empty registry (so no concurrent
/// resize, [`record`], or regular-file write can interleave between the EOF
/// check and `ftruncate(2)`), or `WINDOWED.read()` otherwise. The door applies it itself
/// ([`Resize::apply`]): the admitted length on the admitted descriptor,
/// nothing else.
#[must_use = "an admitted resize does nothing until it is applied"]
pub struct Resize<'a> {
    _registry: RegistryGuard<'a>,
    fd: BorrowedFd<'a>,
    len: libc::off_t,
}

/// Guard holding the window-registry read lock across a regular-file host
/// write (`pwrite`/`write`/`writev`), so concurrent [`admit_resize`] on a
/// windowed inode (`WINDOWED.write()`) cannot sample an older EOF before the
/// write extends the file and `ftruncate(2)` back down afterward (#2975 P0 1).
#[must_use = "write guard must stay live until the host write finishes"]
pub struct WriteGuard {
    _registry: RwLockReadGuard<'static, Registry>,
}

/// Hold the window-registry read lock across a regular-file host write on
/// `fd`. Shared write guards do not contend with one another, while
/// `WINDOWED.write()` writers ([`admit_resize`] on a windowed inode and
/// [`record`]) serialize cleanly with in-flight writes.
pub fn admit_write(_fd: BorrowedFd<'_>) -> WriteGuard {
    #[cfg(any(test, feature = "test-support"))]
    test_resize_hook::signal_before_write_lock();
    let guard = WriteGuard {
        _registry: WINDOWED.read(),
    };
    #[cfg(any(test, feature = "test-support"))]
    test_resize_hook::signal_after_write_lock();
    guard
}

#[cfg(any(test, feature = "test-support"))]
pub mod test_resize_hook {
    use std::cell::RefCell;
    use std::sync::mpsc;

    struct Hook {
        entered: mpsc::SyncSender<()>,
        proceed: mpsc::Receiver<()>,
    }

    static TEST_WINDOW_LOCK: std::sync::LazyLock<parking_lot::Mutex<()>> =
        std::sync::LazyLock::new(|| parking_lot::Mutex::new(()));

    thread_local! {
        static BEFORE_FTRUNCATE: RefCell<Option<Hook>> = const { RefCell::new(None) };
        static BEFORE_WRITE_ALL: RefCell<Option<Hook>> = const { RefCell::new(None) };
        static BEFORE_WRITE_LOCK: RefCell<Option<mpsc::SyncSender<()>>> = const { RefCell::new(None) };
        static AFTER_WRITE_LOCK: RefCell<Option<mpsc::SyncSender<()>>> = const { RefCell::new(None) };
        static BEFORE_RESIZE_LOCK: RefCell<Option<mpsc::SyncSender<()>>> = const { RefCell::new(None) };
        static AFTER_RESIZE_LOCK: RefCell<Option<mpsc::SyncSender<()>>> = const { RefCell::new(None) };
    }

    /// Serialize parallel tests that register process-wide `WINDOWED` entries or
    /// pause while holding `WINDOWED` locks so `RwLock` write-preference cannot
    /// deadlock a pause-hook test against a concurrent writer.
    pub fn lock_window_tests() -> parking_lot::MutexGuard<'static, ()> {
        TEST_WINDOW_LOCK.lock()
    }

    pub fn install(entered: mpsc::SyncSender<()>, proceed: mpsc::Receiver<()>) {
        BEFORE_FTRUNCATE.with(|slot| *slot.borrow_mut() = Some(Hook { entered, proceed }));
    }

    pub fn install_write(entered: mpsc::SyncSender<()>, proceed: mpsc::Receiver<()>) {
        BEFORE_WRITE_ALL.with(|slot| *slot.borrow_mut() = Some(Hook { entered, proceed }));
    }

    pub fn install_write_lock_signals(before: mpsc::SyncSender<()>, after: mpsc::SyncSender<()>) {
        BEFORE_WRITE_LOCK.with(|slot| *slot.borrow_mut() = Some(before));
        AFTER_WRITE_LOCK.with(|slot| *slot.borrow_mut() = Some(after));
    }

    pub fn install_resize_lock_signals(before: mpsc::SyncSender<()>, after: mpsc::SyncSender<()>) {
        BEFORE_RESIZE_LOCK.with(|slot| *slot.borrow_mut() = Some(before));
        AFTER_RESIZE_LOCK.with(|slot| *slot.borrow_mut() = Some(after));
    }

    pub fn window_read_lock_held() -> bool {
        super::WINDOWED.try_write().is_none()
    }

    pub fn window_write_lock_held() -> bool {
        super::WINDOWED.try_read().is_none()
    }

    pub(super) fn signal_before_write_lock() {
        if let Some(tx) = BEFORE_WRITE_LOCK.with(|slot| slot.borrow_mut().take()) {
            let _ = tx.send(());
        }
    }

    pub(super) fn signal_after_write_lock() {
        if let Some(tx) = AFTER_WRITE_LOCK.with(|slot| slot.borrow_mut().take()) {
            let _ = tx.send(());
        }
    }

    pub(super) fn signal_before_resize_lock() {
        if let Some(tx) = BEFORE_RESIZE_LOCK.with(|slot| slot.borrow_mut().take()) {
            let _ = tx.send(());
        }
    }

    pub(super) fn signal_after_resize_lock() {
        if let Some(tx) = AFTER_RESIZE_LOCK.with(|slot| slot.borrow_mut().take()) {
            let _ = tx.send(());
        }
    }

    pub(super) fn pause_before_ftruncate() {
        let hook = BEFORE_FTRUNCATE.with(|slot| slot.borrow_mut().take());
        if let Some(hook) = hook {
            let _ = hook.entered.send(());
            let _ = hook.proceed.recv();
        }
    }

    pub(crate) fn pause_before_write_all() {
        let hook = BEFORE_WRITE_ALL.with(|slot| slot.borrow_mut().take());
        if let Some(hook) = hook {
            let _ = hook.entered.send(());
            let _ = hook.proceed.recv();
        }
    }
}

impl Resize<'_> {
    /// `ftruncate(2)` of the admitted descriptor to the admitted length:
    /// the host call's errno on failure.
    pub fn apply(self) -> Result<(), libc::c_int> {
        #[cfg(any(test, feature = "test-support"))]
        test_resize_hook::pause_before_ftruncate();
        // SAFETY: a plain host call on the admitted, borrowed descriptor.
        if unsafe { libc::ftruncate(self.fd.as_raw_fd(), self.len) } == 0 {
            Ok(())
        } else {
            Err(last_errno())
        }
    }
}

/// An admitted discard of one descriptor's bytes (a hole punch, a range
/// collapse). Only [`admit_discard`] mints one; like [`Resize`] it holds the
/// registry's read lock until it is applied.
#[must_use = "an admitted discard does nothing until it is applied"]
pub struct Discard<'a> {
    _registry: RwLockReadGuard<'a, Registry>,
    fd: BorrowedFd<'a>,
}

impl Discard<'_> {
    /// Apply the admitted discard with `apply` on the admitted descriptor.
    pub fn apply<R>(self, apply: impl FnOnce(BorrowedFd<'_>) -> R) -> R {
        apply(self.fd)
    }
}

/// Admit a resize of the file `fd` names to `len` bytes: `Err(EFBIG)` for a
/// length the host cannot represent, `Err(`[`Fenced::ERRNO`]`)` when
/// fenced. Serializes concurrent resizes on any windowed inode under
/// `WINDOWED.write()` across the EOF check and `ftruncate` (#2975 P0 1).
pub fn admit_resize(fd: BorrowedFd<'_>, len: u64) -> Result<Resize<'_>, libc::c_int> {
    let off = libc::off_t::try_from(len).map_err(|_| libc::EFBIG)?;
    let registry = WINDOWED.read();
    if !registry.is_empty() && is_windowed_or_unstatable(&registry, fd.as_raw_fd()) {
        drop(registry);
        #[cfg(any(test, feature = "test-support"))]
        test_resize_hook::signal_before_resize_lock();
        let registry = WINDOWED.write();
        #[cfg(any(test, feature = "test-support"))]
        test_resize_hook::signal_after_resize_lock();
        check(&registry, fd.as_raw_fd(), Change::Resize(len)).map_err(|Fenced| Fenced::ERRNO)?;
        return Ok(Resize {
            _registry: RegistryGuard::Write(registry),
            fd,
            len: off,
        });
    }
    Ok(Resize {
        _registry: RegistryGuard::Read(registry),
        fd,
        len: off,
    })
}

/// Admit a discard of the file `fd` names, or [`Fenced`].
pub fn admit_discard(fd: BorrowedFd<'_>) -> Result<Discard<'_>, Fenced> {
    let registry = WINDOWED.read();
    check(&registry, fd.as_raw_fd(), Change::Discard)?;
    Ok(Discard {
        _registry: registry,
        fd,
    })
}

/// `ftruncate(2)` of a guest file through the door: [`admit_resize`], then
/// [`Resize::apply`]. The host errno on failure ([`Fenced::ERRNO`] when
/// fenced).
pub fn resize(fd: BorrowedFd<'_>, len: u64) -> Result<(), libc::c_int> {
    admit_resize(fd, len)?.apply()
}

/// An `open(2)` of a guest file through the door. `open` is the host open
/// with the flags to use. Without `O_TRUNC`, or on `O_CREAT | O_EXCL` (which
/// atomically creates a fresh unmapped inode), it runs once with `flags` as
/// given. For non-`O_EXCL` `O_CREAT | O_RDONLY | O_TRUNC`, it first tries
/// `O_EXCL` atomically so creating a fresh `0444` file succeeds without
/// leaving an un-truncated orphan on write-permission checks; existing files
/// and other modes open without `O_TRUNC`, admit the truncation against the
/// exact descriptor returned, and apply it: `Err(`[`Fenced::ERRNO`]`)` (and the
/// descriptor closed) when fenced.
pub fn open_truncating(
    flags: libc::c_int,
    mut open: impl FnMut(libc::c_int) -> Result<OwnedFd, libc::c_int>,
) -> Result<OwnedFd, libc::c_int> {
    open_truncating_with(flags, &mut open, reopen_writable_self_fd)
}

fn open_truncating_with(
    flags: libc::c_int,
    mut open: impl FnMut(libc::c_int) -> Result<OwnedFd, libc::c_int>,
    reopen_writable: impl FnOnce(BorrowedFd<'_>, libc::c_int) -> Result<OwnedFd, libc::c_int>,
) -> Result<OwnedFd, libc::c_int> {
    if flags & libc::O_TRUNC == 0 {
        // An ordinary open changes no size: the door is not involved.
        return open(flags);
    }
    // `O_CREAT | O_EXCL` atomically creates a brand-new inode (or fails EEXIST),
    // which no existing carrier window can map; passing `O_TRUNC` straight to
    // the host preserves `O_CREAT | O_EXCL | O_RDONLY | O_TRUNC` on mode `0444`.
    if flags & libc::O_CREAT != 0 && flags & libc::O_EXCL != 0 {
        return open(flags);
    }
    // Host opens run with no lock held (they may block on a FIFO or slow FS).
    let owned = if flags & libc::O_CREAT != 0 && flags & libc::O_ACCMODE == libc::O_RDONLY {
        // Atomic `O_EXCL` attempt creates a fresh `0444` inode truncated in one
        // step; if the path already exists (`EEXIST`), reopen the existing
        // target with `!(O_CREAT | O_TRUNC)` so an `EACCES` permission check
        // never leaves a newly created `0444` file behind (Codex r29 P0 #2).
        let mut retried = false;
        loop {
            match open(flags | libc::O_EXCL) {
                Ok(fd) => return Ok(fd),
                Err(libc::EEXIST) => match open(flags & !(libc::O_CREAT | libc::O_TRUNC)) {
                    Ok(fd) => break fd,
                    Err(libc::ENOENT) if !retried => {
                        retried = true;
                        continue;
                    }
                    Err(libc::ENOENT) if flags & libc::O_NOFOLLOW == 0 => {
                        // A symlink exists at the pathname (`O_EXCL` returned
                        // `EEXIST`) while its target is missing (`!(O_CREAT|O_TRUNC)`
                        // returned `ENOENT` even on retry): follow the dangling
                        // final symlink to create the missing target, matching
                        // Linux `open(2)` (`#2975` r31 P0 #3).
                        return open(flags);
                    }
                    Err(err) => return Err(err),
                },
                Err(err) => return Err(err),
            }
        }
    } else {
        open(flags & !libc::O_TRUNC)?
    };
    let Some(stat) = fstat(owned.as_raw_fd()) else {
        return Err(last_errno());
    };
    if stat.st_mode & libc::S_IFMT != libc::S_IFREG {
        return Ok(owned);
    }
    if flags & libc::O_ACCMODE != libc::O_RDONLY {
        admit_resize(owned.as_fd(), 0)?.apply()?;
        return Ok(owned);
    }
    #[cfg(target_os = "linux")]
    {
        // `O_RDONLY | O_TRUNC` (Linux truncates when the caller may write, open(2)):
        // open a writable handle via `/proc/self/fd` BEFORE acquiring `WINDOWED`,
        // then admit and truncate under the door while returning the caller's
        // `O_RDONLY` descriptor intact (#2975 P0 4). When the process has only
        // one free host descriptor (`EMFILE` on the second open), inspect `owned`
        // under `WINDOWED.read()`: fence windowed targets (`ENOSYS`), fall back
        // to single-FD `open(flags)` only when `registry.is_empty()` under that
        // read guard (so `record` cannot insert a window across `drop(owned)`
        // and a pathname rename), and otherwise return `Err(libc::EMFILE)`
        // without issuing an unchecked pathname `O_TRUNC` (#2975 r31 P0 #1).
        match reopen_writable(owned.as_fd(), flags) {
            Ok(writable) => {
                admit_resize(writable.as_fd(), 0)?.apply()?;
                Ok(owned)
            }
            Err(libc::EMFILE) => {
                let registry = WINDOWED.read();
                check(&registry, owned.as_raw_fd(), Change::Resize(0))
                    .map_err(|Fenced| Fenced::ERRNO)?;
                if registry.is_empty() {
                    drop(owned);
                    return open(flags);
                }
                Err(libc::EMFILE)
            }
            Err(err) => Err(err),
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let registry = WINDOWED.read();
        if registry.is_empty() {
            drop(owned);
            return open(flags);
        }
        drop(registry);
        match reopen_writable(owned.as_fd(), flags) {
            Ok(writable) => {
                admit_resize(writable.as_fd(), 0)?.apply()?;
                Ok(owned)
            }
            Err(err) => {
                if err == Fenced::ERRNO {
                    let _ = refused();
                }
                Err(err)
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn reopen_writable_self_fd(
    owned: BorrowedFd<'_>,
    flags: libc::c_int,
) -> Result<OwnedFd, libc::c_int> {
    let path = std::ffi::CString::new(format!("/proc/self/fd/{}", owned.as_raw_fd()))
        .map_err(|_| libc::EINVAL)?;
    let wr_flags = libc::O_WRONLY | libc::O_CLOEXEC | (flags & libc::O_NONBLOCK);
    // SAFETY: a NUL-terminated `/proc/self/fd` path naming a descriptor this function borrows.
    let fd = unsafe { libc::open(path.as_ptr(), wr_flags) };
    if fd < 0 {
        return Err(last_errno());
    }
    // SAFETY: `open` returned a fresh descriptor this function now owns.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// No window exists on a host without one (#2972): refuse rather than open
/// untruncated.
#[cfg(not(target_os = "linux"))]
fn reopen_writable_self_fd(
    _owned: BorrowedFd<'_>,
    _flags: libc::c_int,
) -> Result<OwnedFd, libc::c_int> {
    Err(Fenced::ERRNO)
}

/// Return the `(device, inode)` identity of `fd` without pinning it.
pub fn identity(fd: BorrowedFd<'_>) -> Option<InodeIdentity> {
    fstat(fd.as_raw_fd()).map(|stat| identity_of(&stat))
}

/// Record the host file `fd` names as mapped by a shared file window,
/// returning a reference-counted registration that clears the fence when the
/// final carrier drops it (#1338 A1, #2975 P0 2). `None` when its identity
/// cannot be read: the caller must not window it.
pub fn record(fd: BorrowedFd<'_>) -> Option<WindowRegistration> {
    let stat = fstat(fd.as_raw_fd())?;
    let identity = identity_of(&stat);
    let birth = birth(fd.as_raw_fd(), &stat);
    let mut registry = WINDOWED.write();
    match registry.entry(identity) {
        std::collections::hash_map::Entry::Occupied(mut entry) => {
            entry.get_mut().birth = birth;
            entry.get_mut().refs += 1;
        }
        std::collections::hash_map::Entry::Vacant(slot) => {
            slot.insert(WindowEntry { birth, refs: 1 });
        }
    }
    Some(WindowRegistration { identity })
}

/// Whether a window of this process maps `identity`.
pub fn maps(identity: InodeIdentity) -> bool {
    WINDOWED.read().contains_key(&identity)
}

/// Whether any window of this process was recorded.
pub fn any_window() -> bool {
    !WINDOWED.read().is_empty()
}

fn is_windowed_or_unstatable(registry: &Registry, fd: RawFd) -> bool {
    let Some(stat) = fstat(fd) else {
        return true;
    };
    matches!(
        registry.get(&identity_of(&stat)),
        Some(recorded) if recorded.birth == birth(fd, &stat)
    )
}

fn check(registry: &Registry, fd: RawFd, change: Change) -> Result<(), Fenced> {
    if registry.is_empty() {
        return Ok(());
    }
    let Some(stat) = fstat(fd) else {
        return Err(refused());
    };
    match registry.get(&identity_of(&stat)) {
        // A reused `(st_dev, st_ino)` is another inode: not windowed.
        Some(recorded) if recorded.birth == birth(fd, &stat) => {}
        _ => return Ok(()),
    }
    match change {
        Change::Resize(new_len) if u64::try_from(stat.st_size).is_ok_and(|now| new_len >= now) => {
            Ok(())
        }
        _ => Err(refused()),
    }
}

/// An inode's birth time, when the host reports one.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Birth(Option<(i64, i64)>);

#[cfg(target_os = "linux")]
fn birth(fd: RawFd, _stat: &libc::stat) -> Birth {
    let mut statx = std::mem::MaybeUninit::<libc::statx>::uninit();
    // SAFETY: `statx` of the descriptor itself (an empty path with
    // `AT_EMPTY_PATH`) writes the whole record on success.
    let rc = unsafe {
        libc::statx(
            fd,
            c"".as_ptr(),
            libc::AT_EMPTY_PATH,
            libc::STATX_BTIME,
            statx.as_mut_ptr(),
        )
    };
    if rc != 0 {
        return Birth(None);
    }
    // SAFETY: initialized by the successful call above.
    let statx = unsafe { statx.assume_init() };
    if statx.stx_mask & libc::STATX_BTIME == 0 {
        return Birth(None);
    }
    Birth(Some((
        statx.stx_btime.tv_sec,
        i64::from(statx.stx_btime.tv_nsec),
    )))
}

#[cfg(any(target_os = "macos", target_os = "freebsd"))]
fn birth(_fd: RawFd, stat: &libc::stat) -> Birth {
    Birth(Some((
        stat.st_birthtime as i64,
        stat.st_birthtime_nsec as i64,
    )))
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "freebsd")))]
fn birth(_fd: RawFd, _stat: &libc::stat) -> Birth {
    Birth(None)
}

fn identity_of(stat: &libc::stat) -> InodeIdentity {
    InodeIdentity::new(stat.st_dev as u64, stat.st_ino as u64)
}

fn fstat(fd: RawFd) -> Option<libc::stat> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: `fstat` writes the whole record on success.
    if unsafe { libc::fstat(fd, stat.as_mut_ptr()) } != 0 {
        return None;
    }
    // SAFETY: initialized by the successful call above.
    Some(unsafe { stat.assume_init() })
}

fn last_errno() -> libc::c_int {
    std::io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(libc::EIO)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd;

    struct TestRegistryMutex;
    impl TestRegistryMutex {
        fn lock(&self) -> parking_lot::MutexGuard<'static, ()> {
            test_resize_hook::lock_window_tests()
        }
    }
    static TEST_REGISTRY_MUTEX: TestRegistryMutex = TestRegistryMutex;

    fn file(len: u64) -> (tempfile::TempDir, std::path::PathBuf, std::fs::File) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f");
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .unwrap();
        file.set_len(len).unwrap();
        (dir, path, file)
    }

    fn size(path: &std::path::Path) -> u64 {
        std::fs::metadata(path).unwrap().len()
    }

    fn host_open(path: &std::path::Path, flags: libc::c_int) -> Result<OwnedFd, libc::c_int> {
        let cpath = std::ffi::CString::new(path.to_str().unwrap()).unwrap();
        // SAFETY: a NUL-terminated path; a fresh descriptor is owned below.
        let fd = unsafe { libc::open(cpath.as_ptr(), flags | libc::O_CLOEXEC, 0o644) };
        if fd < 0 {
            Err(last_errno())
        } else {
            // SAFETY: `open` returned a fresh descriptor.
            Ok(unsafe { OwnedFd::from_raw_fd(fd) })
        }
    }

    fn open_path(path: &std::path::Path, flags: libc::c_int) -> Result<OwnedFd, libc::c_int> {
        open_truncating(flags, |flags| host_open(path, flags))
    }

    #[test]
    fn a_window_fences_every_shrink_of_its_inode_by_the_object_mutated() {
        let _guard = TEST_REGISTRY_MUTEX.lock();
        let (_dir, path, windowed) = file(8192);
        let (_other_dir, other_path, other) = file(8192);
        let _reg = record(windowed.as_fd()).unwrap();
        let identity = _reg.identity();
        assert!(maps(identity));
        assert!(any_window());

        // A resize: a shrink is refused and applies nothing; a growth and
        // the same size are admitted. Another inode shrinks as before.
        assert_eq!(resize(windowed.as_fd(), 4096), Err(Fenced::ERRNO));
        assert_eq!(size(&path), 8192);
        assert_eq!(resize(windowed.as_fd(), 8192), Ok(()));
        assert_eq!(resize(windowed.as_fd(), 12288), Ok(()));
        assert_eq!(size(&path), 12288);
        assert_eq!(resize(other.as_fd(), 0), Ok(()));
        assert_eq!(size(&other_path), 0);
        assert_eq!(resize(other.as_fd(), u64::MAX), Err(libc::EFBIG));

        // O_TRUNC by name, through a second name (a hard link) and through
        // the descriptor's own /proc link: each opened object is the
        // windowed inode, so each is refused before anything is truncated.
        let link = path.with_file_name("link");
        std::fs::hard_link(&path, &link).unwrap();
        for name in [&path, &link] {
            for access in [libc::O_RDWR, libc::O_WRONLY, libc::O_RDONLY] {
                assert_eq!(
                    open_path(name, access | libc::O_TRUNC).err(),
                    Some(Fenced::ERRNO)
                );
            }
        }
        #[cfg(target_os = "linux")]
        {
            let proc = std::path::PathBuf::from(format!("/proc/self/fd/{}", windowed.as_raw_fd()));
            assert_eq!(
                open_path(&proc, libc::O_RDWR | libc::O_TRUNC).err(),
                Some(Fenced::ERRNO)
            );
        }
        assert_eq!(size(&path), 12288);
        // Without O_TRUNC the open is served.
        assert!(open_path(&path, libc::O_RDWR).is_ok());

        // O_TRUNC of another inode truncates it, whatever the access mode.
        std::fs::write(&other_path, b"bytes").unwrap();
        assert!(open_path(&other_path, libc::O_WRONLY | libc::O_TRUNC).is_ok());
        assert_eq!(size(&other_path), 0);
        #[cfg(target_os = "linux")]
        {
            std::fs::write(&other_path, b"bytes").unwrap();
            assert!(open_path(&other_path, libc::O_RDONLY | libc::O_TRUNC).is_ok());
            assert_eq!(size(&other_path), 0);
        }

        // A discard (hole punch, collapse) is refused whatever the size;
        // another inode's is admitted.
        assert!(admit_discard(windowed.as_fd()).is_err());
        assert!(admit_discard(other.as_fd()).is_ok());
    }

    /// Early review P0 1 (#2975): no open runs under the registry's lock,
    /// so a host open that blocks (a FIFO, a slow mount) never holds back
    /// a window being recorded, and so never wedges every other change.
    #[test]
    fn no_host_open_runs_under_the_registry_lock() {
        let _guard = TEST_REGISTRY_MUTEX.lock();
        let (_dir, path, _file) = file(4096);
        for flags in [libc::O_RDWR, libc::O_RDWR | libc::O_TRUNC] {
            let opened = open_truncating(flags, |flags| {
                assert!(
                    WINDOWED.try_write().is_some(),
                    "the registry is locked across the open ({flags:#x})"
                );
                host_open(&path, flags)
            });
            assert!(opened.is_ok());
        }
        #[cfg(target_os = "linux")]
        {
            std::fs::write(&path, b"abcdef").unwrap();
            let opened = open_truncating_with(
                libc::O_RDONLY | libc::O_TRUNC,
                |flags| {
                    assert!(
                        WINDOWED.try_write().is_some(),
                        "the registry is locked across initial O_RDONLY|O_TRUNC open"
                    );
                    host_open(&path, flags)
                },
                |fd, flags| {
                    assert!(
                        WINDOWED.try_write().is_some(),
                        "the registry is locked across /proc/self/fd reopen (#2975 P0 4)"
                    );
                    reopen_writable_self_fd(fd, flags)
                },
            )
            .unwrap();
            assert_eq!(size(&path), 0);
            // Returned fd remains read-only (O_RDONLY): write must fail EBADF.
            let rc = unsafe { libc::write(opened.as_raw_fd(), c"x".as_ptr().cast(), 1) };
            assert_eq!(rc, -1);
            assert_eq!(last_errno(), libc::EBADF);
        }
    }

    #[test]
    fn excl_rdonly_trunc_creates_mode_0444_atomically() {
        let _guard = TEST_REGISTRY_MUTEX.lock();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("readonly_excl");
        let cpath = std::ffi::CString::new(path.to_str().unwrap()).unwrap();
        let flags = libc::O_CREAT | libc::O_EXCL | libc::O_RDONLY | libc::O_TRUNC;
        let mut calls = 0usize;
        let opened = open_truncating(flags, |open_flags| {
            calls += 1;
            let fd = unsafe { libc::open(cpath.as_ptr(), open_flags | libc::O_CLOEXEC, 0o444) };
            if fd < 0 {
                Err(last_errno())
            } else {
                Ok(unsafe { OwnedFd::from_raw_fd(fd) })
            }
        });
        assert!(
            opened.is_ok(),
            "O_CREAT|O_EXCL|O_RDONLY|O_TRUNC 0444 failed: {opened:?}"
        );
        assert_eq!(calls, 1);
        assert_eq!(size(&path), 0);
    }

    #[test]
    fn non_excl_rdonly_trunc_creates_mode_0444_atomically_and_checks_existing() {
        let _guard = TEST_REGISTRY_MUTEX.lock();
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("non_excl_0444");
        let c_missing = std::ffi::CString::new(missing.to_str().unwrap()).unwrap();
        let flags = libc::O_CREAT | libc::O_RDONLY | libc::O_TRUNC;
        let opened = open_truncating(flags, |open_flags| {
            let fd = unsafe { libc::open(c_missing.as_ptr(), open_flags | libc::O_CLOEXEC, 0o444) };
            if fd < 0 {
                Err(last_errno())
            } else {
                Ok(unsafe { OwnedFd::from_raw_fd(fd) })
            }
        });
        assert!(
            opened.is_ok(),
            "O_CREAT|O_RDONLY|O_TRUNC on missing 0444 file must succeed without leaking created file: {opened:?}"
        );
        drop(opened);
        assert_eq!(size(&missing), 0);
        // Reopening existing 0444 file without O_EXCL must refuse with EACCES.
        let reopen_ro = open_truncating(flags, |open_flags| {
            let fd = unsafe { libc::open(c_missing.as_ptr(), open_flags | libc::O_CLOEXEC, 0o444) };
            if fd < 0 {
                Err(last_errno())
            } else {
                Ok(unsafe { OwnedFd::from_raw_fd(fd) })
            }
        });
        if unsafe { libc::geteuid() } != 0 {
            assert_eq!(reopen_ro.err(), Some(libc::EACCES));
        } else {
            assert!(reopen_ro.is_ok());
        }
    }

    #[test]
    fn concurrent_windowed_resizes_are_serialized() {
        let _guard = TEST_REGISTRY_MUTEX.lock();
        let (_dir, path, windowed) = file(4096);
        let second = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        let _reg = record(windowed.as_fd()).unwrap();
        let tok = admit_resize(windowed.as_fd(), 8192).unwrap();
        assert!(
            WINDOWED.try_read().is_none(),
            "admitted resize of a windowed inode must exclude competing resizes until applied"
        );
        tok.apply().unwrap();
        assert_eq!(size(&path), 8192);
        drop(_reg);

        // Concurrent 8 KiB vs 12 KiB growths across independent fds never shrink 12 KiB -> 8 KiB.
        for _ in 0..64 {
            second.set_len(4096).unwrap();
            let pin = record(windowed.as_fd()).unwrap();
            let barrier = std::sync::Barrier::new(2);
            let (r8, r12) = std::thread::scope(|s| {
                let b1 = &barrier;
                let h1 = s.spawn(|| {
                    b1.wait();
                    resize(windowed.as_fd(), 8192)
                });
                barrier.wait();
                let r12 = resize(second.as_fd(), 12288);
                (h1.join().unwrap(), r12)
            });
            assert_eq!(r12, Ok(()));
            assert_eq!(size(&path), 12288);
            assert!(matches!(r8, Ok(()) | Err(Fenced::ERRNO)));
            drop(pin);
        }
    }

    #[test]
    fn admitted_write_blocks_windowed_admit_resize() {
        let _guard = TEST_REGISTRY_MUTEX.lock();
        let (_dir, _path, windowed) = file(4096);
        let _reg = record(windowed.as_fd()).unwrap();
        let write_guard = admit_write(windowed.as_fd());
        let (before_tx, before_rx) = std::sync::mpsc::sync_channel(1);
        let (after_tx, after_rx) = std::sync::mpsc::sync_channel(1);
        std::thread::scope(|s| {
            let h = s.spawn(|| {
                test_resize_hook::install_resize_lock_signals(before_tx, after_tx);
                resize(windowed.as_fd(), 8192)
            });
            before_rx.recv().unwrap();
            assert!(
                test_resize_hook::window_read_lock_held(),
                "in-flight admit_write must hold WINDOWED read lock"
            );
            assert!(
                after_rx.try_recv().is_err(),
                "admit_resize on windowed file must not acquire WINDOWED write lock until admit_write drops"
            );
            drop(write_guard);
            after_rx.recv().unwrap();
            assert_eq!(h.join().unwrap(), Ok(()));
        });
    }

    #[test]
    fn window_registration_refcounts_and_unregisters_on_final_drop() {
        let _guard = TEST_REGISTRY_MUTEX.lock();
        let (_dir, path, windowed) = file(8192);
        let reg1 = record(windowed.as_fd()).unwrap();
        let id = reg1.identity();
        let reg2 = record(windowed.as_fd()).unwrap();
        assert_eq!(reg2.identity(), id);
        assert!(maps(id));
        assert_eq!(resize(windowed.as_fd(), 0), Err(Fenced::ERRNO));
        drop(reg1);
        assert!(maps(id), "second reference must keep shrink fence active");
        assert_eq!(resize(windowed.as_fd(), 0), Err(Fenced::ERRNO));
        drop(reg2);
        assert!(!maps(id), "final drop must remove inode from registry");
        assert!(!any_window());
        assert_eq!(resize(windowed.as_fd(), 0), Ok(()));
        assert_eq!(size(&path), 0);
    }

    /// Early review P0 2 (#2975): the registry holds no host descriptor
    /// (its value is a [`Birth`]), so a reused `(st_dev, st_ino)` must not
    /// be taken for the windowed inode.
    #[test]
    fn a_recorded_window_holds_no_descriptor_and_names_only_its_inode() {
        let _guard = TEST_REGISTRY_MUTEX.lock();
        let (_dir, path, windowed) = file(8192);
        let _reg = record(windowed.as_fd()).unwrap();
        let identity = _reg.identity();
        assert!(maps(identity));
        // Same (st_dev, st_ino), another birth: the inode was reused.
        WINDOWED
            .write()
            .insert(
                identity,
                WindowEntry {
                    birth: Birth(Some((0, 0))),
                    refs: 1,
                },
            )
            .unwrap();
        if birth(windowed.as_raw_fd(), &fstat(windowed.as_raw_fd()).unwrap()) != Birth(None) {
            assert_eq!(resize(windowed.as_fd(), 0), Ok(()));
            assert_eq!(size(&path), 0);
        }
    }

    /// Codex r31 P0 3 (#2975): `O_CREAT | O_RDONLY | O_TRUNC` (without `O_EXCL`
    /// or `O_NOFOLLOW`) through a dangling final symlink must follow the symlink
    /// and create the missing target, just like Linux `open(2)`.
    #[test]
    fn creat_rdonly_trunc_through_dangling_symlink_creates_target() {
        let _guard = TEST_REGISTRY_MUTEX.lock();
        let dir = tempfile::tempdir().unwrap();
        for (idx, mode) in [0o644u32, 0o444u32].into_iter().enumerate() {
            let target = dir.path().join(format!("missing_target_{idx}"));
            let link = dir.path().join(format!("dangling_link_{idx}"));
            std::os::unix::fs::symlink(&target, &link).unwrap();
            let clink = std::ffi::CString::new(link.to_str().unwrap()).unwrap();
            let flags = libc::O_CREAT | libc::O_RDONLY | libc::O_TRUNC;
            let opened = open_truncating(flags, |open_flags| {
                let fd = unsafe {
                    libc::open(
                        clink.as_ptr(),
                        open_flags | libc::O_CLOEXEC,
                        mode as libc::c_uint,
                    )
                };
                if fd < 0 {
                    Err(last_errno())
                } else {
                    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
                }
            });
            assert!(
                opened.is_ok(),
                "O_CREAT|O_RDONLY|O_TRUNC through dangling symlink failed (mode {mode:#o}): {opened:?}"
            );
            assert_eq!(size(&target), 0);
        }
    }

    /// Host tests that temporarily tighten process-wide `RLIMIT_NOFILE`.
    /// Must run with `RUST_TEST_THREADS=1` (as `just test` and
    /// `just test-touched` do for `serial_host` modules) so sibling tests do
    /// not observe transient `EMFILE`.
    #[cfg(target_os = "linux")]
    mod serial_host {
        use super::*;

        struct OneFreeFdGuard {
            saved: libc::rlimit,
        }

        impl OneFreeFdGuard {
            fn arm() -> Self {
                let mut saved: libc::rlimit = unsafe { core::mem::zeroed() };
                assert_eq!(
                    unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut saved) },
                    0
                );
                let probe = unsafe { libc::dup(0) };
                assert!(probe >= 0, "probe dup(0): {}", last_errno());
                unsafe { libc::close(probe) };
                let guard = Self { saved };
                let tight = libc::rlimit {
                    rlim_cur: (probe as libc::rlim_t) + 1,
                    rlim_max: saved.rlim_max,
                };
                assert_eq!(
                    unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &tight) },
                    0,
                    "setrlimit to {} failed: {}",
                    tight.rlim_cur,
                    last_errno()
                );
                let first = unsafe { libc::dup(0) };
                assert_eq!(first, probe, "expected slot {probe} free");
                let second = unsafe { libc::dup(0) };
                assert_eq!(second, -1);
                assert_eq!(last_errno(), libc::EMFILE);
                unsafe { libc::close(first) };
                guard
            }
        }

        impl Drop for OneFreeFdGuard {
            fn drop(&mut self) {
                unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &self.saved) };
            }
        }

        /// Codex r30 P0 3 (#2975): with only one host FD free, opening an
        /// existing unwindowed file with `O_RDONLY | O_TRUNC` (with or without
        /// `O_CREAT`) must not fail `EMFILE` on the Linux `/proc/self/fd` reopen.
        #[test]
        fn existing_rdonly_trunc_succeeds_with_one_free_host_fd_when_unwindowed() {
            let _guard = TEST_REGISTRY_MUTEX.lock();
            let dir = tempfile::tempdir().unwrap();
            let path_plain = dir.path().join("existing_plain");
            let path_creat = dir.path().join("existing_creat");
            let path_sibling = dir.path().join("existing_with_other_windowed");
            std::fs::write(&path_plain, b"existing-plain-bytes").unwrap();
            std::fs::write(&path_creat, b"existing-creat-bytes").unwrap();
            std::fs::write(&path_sibling, b"existing-sibling-bytes").unwrap();
            let (_win_dir, win_path, win_file) = file(4096);
            let c_plain = std::ffi::CString::new(path_plain.to_str().unwrap()).unwrap();
            let c_creat = std::ffi::CString::new(path_creat.to_str().unwrap()).unwrap();
            let c_sibling = std::ffi::CString::new(path_sibling.to_str().unwrap()).unwrap();
            let c_win = std::ffi::CString::new(win_path.to_str().unwrap()).unwrap();
            let opener = |cpath: &std::ffi::CStr, flags: libc::c_int| {
                let fd = unsafe { libc::open(cpath.as_ptr(), flags | libc::O_CLOEXEC, 0o644) };
                if fd < 0 {
                    Err(last_errno())
                } else {
                    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
                }
            };

            {
                let _one_fd = OneFreeFdGuard::arm();
                let opened =
                    open_truncating(libc::O_RDONLY | libc::O_TRUNC, |f| opener(&c_plain, f))
                        .expect(
                            "O_RDONLY|O_TRUNC on existing file must succeed with 1 free host FD",
                        );
                let wr = unsafe { libc::write(opened.as_raw_fd(), c"x".as_ptr().cast(), 1) };
                assert_eq!(wr, -1);
                assert_eq!(last_errno(), libc::EBADF);
            }
            assert_eq!(size(&path_plain), 0);

            {
                let _one_fd = OneFreeFdGuard::arm();
                let opened = open_truncating(libc::O_CREAT | libc::O_RDONLY | libc::O_TRUNC, |f| {
                    opener(&c_creat, f)
                })
                .expect(
                    "O_CREAT|O_RDONLY|O_TRUNC on existing file must succeed with 1 free host FD",
                );
                drop(opened);
            }
            assert_eq!(size(&path_creat), 0);

            // When a window is already recorded in this process, the single-FD
            // fallback is unsafe because dropping `owned` and reopening by path
            // could race with rename onto a windowed inode (#2975 r31 P0 #1):
            // an unwindowed file fails cleanly `EMFILE` without truncating, while
            // the windowed file still fences `ENOSYS`.
            let _pin = record(win_file.as_fd()).unwrap();
            {
                let _one_fd = OneFreeFdGuard::arm();
                let err =
                    open_truncating(libc::O_RDONLY | libc::O_TRUNC, |f| opener(&c_sibling, f))
                        .expect_err("unwindowed file under 1 free FD with active registry must fail EMFILE rather than issue unchecked pathname O_TRUNC");
                assert_eq!(err, libc::EMFILE);
            }
            assert_eq!(size(&path_sibling), b"existing-sibling-bytes".len() as u64);
            {
                let _one_fd = OneFreeFdGuard::arm();
                let err = open_truncating(libc::O_RDONLY | libc::O_TRUNC, |f| opener(&c_win, f))
                    .expect_err("windowed existing file must still fence under 1 free host FD");
                assert_eq!(err, Fenced::ERRNO);
            }
            assert_eq!(size(&win_path), 4096);
        }

        /// Codex r31 P0 1 (#2975): under one free host FD when a window exists
        /// in the process, replacing the target pathname with a link to the
        /// windowed inode between the initial open and fallback MUST NOT truncate
        /// the windowed inode.
        #[test]
        fn existing_rdonly_trunc_does_not_truncate_windowed_target_when_path_replaced_under_one_free_fd()
         {
            let _guard = TEST_REGISTRY_MUTEX.lock();
            let dir = tempfile::tempdir().unwrap();
            let win_path = dir.path().join("windowed");
            let win_link = dir.path().join("win_hardlink");
            let target_path = dir.path().join("target");
            std::fs::write(&win_path, vec![b'W'; 4096]).unwrap();
            std::fs::hard_link(&win_path, &win_link).unwrap();
            std::fs::write(&target_path, b"plain-initial").unwrap();
            let win_file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&win_path)
                .unwrap();
            let _pin = record(win_file.as_fd()).unwrap();
            let ctarget = std::ffi::CString::new(target_path.to_str().unwrap()).unwrap();

            let mut calls = 0usize;
            {
                let _one_fd = OneFreeFdGuard::arm();
                let res = open_truncating(libc::O_RDONLY | libc::O_TRUNC, |open_flags| {
                    calls += 1;
                    let fd = unsafe {
                        libc::open(ctarget.as_ptr(), open_flags | libc::O_CLOEXEC, 0o644)
                    };
                    if fd < 0 {
                        return Err(last_errno());
                    }
                    if calls == 1 {
                        std::fs::rename(&win_link, &target_path).unwrap();
                    }
                    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
                });
                assert!(
                    matches!(res, Err(libc::EMFILE) | Err(Fenced::ERRNO)),
                    "1-FD fallback must refuse rather than truncate swapped windowed inode: {res:?}"
                );
            }
            assert_eq!(
                calls, 1,
                "must not issue unchecked O_TRUNC reopen when registry is non-empty"
            );
            assert_eq!(
                std::fs::read(&win_path).unwrap(),
                vec![b'W'; 4096],
                "windowed inode bytes and size must survive concurrent pathname replacement"
            );
        }
    }
}
