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
//! through this module on the descriptor it mutates ([`ftruncate`],
//! [`open_truncating`], [`admit`] for a discard), and the check `fstat`s
//! that same descriptor. No second lookup can name a different inode, and a
//! bind mount, a hard link, a rename or a `/proc/self/fd` reopen all reach
//! the same `(st_dev, st_ino)`.
//!
//! The registry's read lock is held from the check until the change is
//! applied ([`SizeChange`] borrows it), and [`record`] takes the write lock,
//! so a window recorded concurrently can never slip between the check and
//! the change.
//!
//! The registry is process-wide: a window slot is a host mapping of this
//! process, so any shrink this process applies to the inode breaks it,
//! whichever run asked. Each recorded inode is pinned by a duplicated
//! descriptor, so its identity is never reused while it is recorded. An
//! inode stays recorded for the rest of the process, as its window slot
//! stays for the run: the interim trade-off of A1.

use std::collections::HashMap;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::sync::LazyLock;

use parking_lot::{RwLock, RwLockReadGuard};

use crate::vfs::InodeIdentity;

type Registry = HashMap<InodeIdentity, OwnedFd>;

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
pub enum Change {
    /// Set the file's size to this many bytes (`ftruncate`, `O_TRUNC`).
    Resize(u64),
    /// Discard bytes without moving the end of the file (a hole punch, a
    /// range collapse, a whole-file rewrite): refused whenever a window
    /// maps the file.
    Discard,
}

/// A window maps the file and the change would shrink it or discard its
/// bytes (or its identity could not be read while a window exists). The
/// caller answers `ENOSYS`, a counted refusal, and applies nothing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Fenced;

/// An admitted change of one descriptor's file. Only [`admit`] mints one,
/// and it holds the registry's read lock, so no window can be recorded for
/// the file until the change has been applied.
pub struct SizeChange<'a> {
    _registry: RwLockReadGuard<'a, Registry>,
    fd: BorrowedFd<'a>,
}

impl SizeChange<'_> {
    /// Apply the admitted change with `apply` on the admitted descriptor.
    pub fn apply<R>(self, apply: impl FnOnce(BorrowedFd<'_>) -> R) -> R {
        apply(self.fd)
    }
}

/// Admit `change` of the file `fd` names, or [`Fenced`].
pub fn admit(fd: BorrowedFd<'_>, change: Change) -> Result<SizeChange<'_>, Fenced> {
    let registry = WINDOWED.read();
    check(&registry, fd.as_raw_fd(), change)?;
    Ok(SizeChange {
        _registry: registry,
        fd,
    })
}

/// `ftruncate(2)` of a guest file through the door: `-1` with `errno`
/// `ENOSYS` when [`Fenced`], else the host call's own result.
pub fn ftruncate(fd: RawFd, len: libc::off_t) -> libc::c_int {
    let Ok(new_len) = u64::try_from(len) else {
        set_errno(libc::EINVAL);
        return -1;
    };
    // SAFETY: the caller's descriptor stays open for this call.
    let fd = unsafe { BorrowedFd::borrow_raw(fd) };
    match admit(fd, Change::Resize(new_len)) {
        // SAFETY: a plain host call on the admitted descriptor.
        Ok(change) => change.apply(|fd| unsafe { libc::ftruncate(fd.as_raw_fd(), len) }),
        Err(Fenced) => {
            set_errno(libc::ENOSYS);
            -1
        }
    }
}

/// An `open(2)` of a guest file through the door. `open` is the host open
/// with the flags to use. Without `O_TRUNC`, or with no window anywhere, it
/// runs once with `flags` as given. Otherwise it runs without `O_TRUNC`,
/// and the truncation is admitted against the descriptor it returned, the
/// exact object, then applied to it: `-1` with `errno` `ENOSYS` (and the
/// descriptor closed) when [`Fenced`]. As `O_TRUNC` does, only a regular
/// file is truncated.
pub fn open_truncating(flags: libc::c_int, open: impl FnOnce(libc::c_int) -> RawFd) -> RawFd {
    match open_truncating_with(flags, |flags| {
        let fd = open(flags);
        if fd < 0 { Err(last_errno()) } else { Ok(fd) }
    }) {
        Ok(fd) => fd,
        Err(errno) => {
            set_errno(errno);
            -1
        }
    }
}

/// [`open_truncating`] for a host open that answers its errno: `Err(ENOSYS)`
/// when [`Fenced`].
pub fn open_truncating_with(
    flags: libc::c_int,
    open: impl FnOnce(libc::c_int) -> Result<RawFd, libc::c_int>,
) -> Result<RawFd, libc::c_int> {
    let fd = open_truncating_raw(flags, |flags| match open(flags) {
        Ok(fd) => fd,
        Err(errno) => {
            set_errno(errno);
            -1
        }
    });
    if fd < 0 { Err(last_errno()) } else { Ok(fd) }
}

fn open_truncating_raw(flags: libc::c_int, open: impl FnOnce(libc::c_int) -> RawFd) -> RawFd {
    let registry = WINDOWED.read();
    if flags & libc::O_TRUNC == 0 || registry.is_empty() {
        return open(flags);
    }
    let fd = open(flags & !libc::O_TRUNC);
    if fd < 0 {
        return fd;
    }
    // SAFETY: `open` returned a fresh descriptor this function now owns.
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    if check(&registry, fd, Change::Resize(0)).is_err() {
        drop(owned);
        set_errno(libc::ENOSYS);
        return -1;
    }
    let Some(stat) = fstat(fd) else {
        return owned.into_raw_fd();
    };
    if stat.st_mode & libc::S_IFMT != libc::S_IFREG {
        return owned.into_raw_fd();
    }
    if flags & libc::O_ACCMODE != libc::O_RDONLY {
        // SAFETY: a plain host call on the descriptor this function owns.
        if unsafe { libc::ftruncate(fd, 0) } != 0 {
            let errno = last_errno();
            drop(owned);
            set_errno(errno);
            return -1;
        }
        return owned.into_raw_fd();
    }
    reopen_truncating(owned, flags)
}

/// `O_RDONLY | O_TRUNC` (Linux truncates when the caller may write, open(2)):
/// reopen the exact object through its descriptor with the caller's flags.
#[cfg(target_os = "linux")]
fn reopen_truncating(owned: OwnedFd, flags: libc::c_int) -> RawFd {
    let Ok(path) = std::ffi::CString::new(format!("/proc/self/fd/{}", owned.as_raw_fd())) else {
        set_errno(libc::EINVAL);
        return -1;
    };
    // The object exists now: creation flags no longer apply, and the
    // descriptor link is followed by design.
    let flags = flags & !(libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW);
    // SAFETY: a NUL-terminated path naming a descriptor this function owns.
    let fd = unsafe { libc::open(path.as_ptr(), flags) };
    let errno = last_errno();
    drop(owned);
    if fd < 0 {
        set_errno(errno);
    }
    fd
}

/// No window exists on a host without one (#2972): refuse rather than open
/// untruncated.
#[cfg(not(target_os = "linux"))]
fn reopen_truncating(owned: OwnedFd, _flags: libc::c_int) -> RawFd {
    drop(owned);
    set_errno(libc::ENOSYS);
    -1
}

/// Record the host file `fd` names as mapped by a shared file window,
/// before the window's source is retained. `None` (nothing recorded) when
/// its identity cannot be read or the descriptor cannot be pinned: the
/// caller must not window it.
pub fn record(fd: BorrowedFd<'_>) -> Option<InodeIdentity> {
    let stat = fstat(fd.as_raw_fd())?;
    let identity = identity_of(&stat);
    let mut registry = WINDOWED.write();
    if let std::collections::hash_map::Entry::Vacant(entry) = registry.entry(identity) {
        entry.insert(fd.try_clone_to_owned().ok()?);
    }
    Some(identity)
}

/// Whether a window of this process maps `identity`.
pub fn maps(identity: InodeIdentity) -> bool {
    WINDOWED.read().contains_key(&identity)
}

/// Whether any window of this process was recorded.
pub fn any_window() -> bool {
    !WINDOWED.read().is_empty()
}

fn check(registry: &Registry, fd: RawFd, change: Change) -> Result<(), Fenced> {
    if registry.is_empty() {
        return Ok(());
    }
    let Some(stat) = fstat(fd) else {
        return Err(refused());
    };
    if !registry.contains_key(&identity_of(&stat)) {
        return Ok(());
    }
    match change {
        Change::Resize(new_len) if u64::try_from(stat.st_size).is_ok_and(|now| new_len >= now) => {
            Ok(())
        }
        _ => Err(refused()),
    }
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

fn set_errno(errno: libc::c_int) {
    carrick_portable::set_errno(errno);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd;

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

    fn open_path(path: &std::path::Path, flags: libc::c_int) -> RawFd {
        let cpath = std::ffi::CString::new(path.to_str().unwrap()).unwrap();
        open_truncating(flags, |flags| unsafe {
            libc::open(cpath.as_ptr(), flags | libc::O_CLOEXEC, 0o644)
        })
    }

    #[test]
    fn a_window_fences_every_shrink_of_its_inode_by_the_object_mutated() {
        let (_dir, path, windowed) = file(8192);
        let (_other_dir, other_path, other) = file(8192);
        let identity = record(windowed.as_fd()).unwrap();
        assert!(maps(identity));
        assert!(any_window());

        // ftruncate: a shrink is refused and applies nothing; a growth and
        // the same size are admitted. Another inode shrinks as before.
        assert_eq!(ftruncate(windowed.as_raw_fd(), 4096), -1);
        assert_eq!(last_errno(), libc::ENOSYS);
        assert_eq!(size(&path), 8192);
        assert_eq!(ftruncate(windowed.as_raw_fd(), 8192), 0);
        assert_eq!(ftruncate(windowed.as_raw_fd(), 12288), 0);
        assert_eq!(size(&path), 12288);
        assert_eq!(ftruncate(other.as_raw_fd(), 0), 0);
        assert_eq!(size(&other_path), 0);

        // O_TRUNC by name, through a second name (a hard link) and through
        // the descriptor's own /proc link: each opened object is the
        // windowed inode, so each is refused before anything is truncated.
        let link = path.with_file_name("link");
        std::fs::hard_link(&path, &link).unwrap();
        for name in [&path, &link] {
            for access in [libc::O_RDWR, libc::O_WRONLY, libc::O_RDONLY] {
                assert_eq!(open_path(name, access | libc::O_TRUNC), -1);
                assert_eq!(last_errno(), libc::ENOSYS);
            }
        }
        #[cfg(target_os = "linux")]
        {
            let proc = std::path::PathBuf::from(format!("/proc/self/fd/{}", windowed.as_raw_fd()));
            assert_eq!(open_path(&proc, libc::O_RDWR | libc::O_TRUNC), -1);
        }
        assert_eq!(size(&path), 12288);
        // Without O_TRUNC the open is served.
        let fd = open_path(&path, libc::O_RDWR);
        assert!(fd >= 0);
        unsafe { libc::close(fd) };

        // O_TRUNC of another inode truncates it, whatever the access mode.
        std::fs::write(&other_path, b"bytes").unwrap();
        let fd = open_path(&other_path, libc::O_WRONLY | libc::O_TRUNC);
        assert!(fd >= 0);
        unsafe { libc::close(fd) };
        assert_eq!(size(&other_path), 0);
        #[cfg(target_os = "linux")]
        {
            std::fs::write(&other_path, b"bytes").unwrap();
            let fd = open_path(&other_path, libc::O_RDONLY | libc::O_TRUNC);
            assert!(fd >= 0);
            unsafe { libc::close(fd) };
            assert_eq!(size(&other_path), 0);
        }

        // A discard (hole punch, collapse, rewrite) is refused whatever the
        // size; another inode's is admitted.
        assert!(admit(windowed.as_fd(), Change::Discard).is_err());
        assert!(admit(other.as_fd(), Change::Discard).is_ok());
    }
}
