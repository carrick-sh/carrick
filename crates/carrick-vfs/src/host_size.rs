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
//! the admissions, and a resize is applied only by the door itself. The
//! registry's read lock is held from the check until the change is applied
//! (the token borrows it), and [`record`] takes the write lock, so a window
//! recorded concurrently can never slip between the check and the change.
//! No lock is held across a host open: an `O_TRUNC` open runs without
//! `O_TRUNC`, and only its truncation is admitted and applied under the
//! lock.
//!
//! The registry is process-wide: a window slot is a host mapping of this
//! process, so any shrink this process applies to the inode breaks it,
//! whichever run asked. It holds no descriptor: a recorded inode is kept
//! alive by the window's own host mapping, and its birth time tells a
//! reused `(st_dev, st_ino)` apart. An inode stays recorded as long as its
//! window slot stays, for the run (the interim trade-off of A1), so the
//! registry is bounded by the window slots.

use std::collections::HashMap;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::sync::LazyLock;

use parking_lot::{RwLock, RwLockReadGuard};

use crate::vfs::InodeIdentity;

/// Each windowed inode, with its birth time when the host reports one. No
/// descriptor is kept: the window's own host mapping keeps the inode alive
/// while it is recorded, and the birth time tells a reused `(st_dev, st_ino)`
/// from the recorded inode, so the registry costs no host descriptor and is
/// bounded by the window slots that exist.
type Registry = HashMap<InodeIdentity, Birth>;

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

/// An admitted resize of one descriptor's file to one length. Only
/// [`admit_resize`] mints one, and it holds the registry's read lock, so no
/// window can be recorded for the file until the resize has been applied.
/// The door applies it itself ([`Resize::apply`]): the admitted length on
/// the admitted descriptor, nothing else.
#[must_use = "an admitted resize does nothing until it is applied"]
pub struct Resize<'a> {
    _registry: RwLockReadGuard<'a, Registry>,
    fd: BorrowedFd<'a>,
    len: libc::off_t,
}

impl Resize<'_> {
    /// `ftruncate(2)` of the admitted descriptor to the admitted length:
    /// the host call's errno on failure.
    pub fn apply(self) -> Result<(), libc::c_int> {
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
/// fenced.
pub fn admit_resize(fd: BorrowedFd<'_>, len: u64) -> Result<Resize<'_>, libc::c_int> {
    let off = libc::off_t::try_from(len).map_err(|_| libc::EFBIG)?;
    let registry = WINDOWED.read();
    check(&registry, fd.as_raw_fd(), Change::Resize(len)).map_err(|Fenced| Fenced::ERRNO)?;
    Ok(Resize {
        _registry: registry,
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
/// with the flags to use. Without `O_TRUNC`, or with no window anywhere, it
/// runs once with `flags` as given. Otherwise it runs without `O_TRUNC`,
/// and the truncation is admitted against the descriptor it returned, the
/// exact object, then applied to it: `Err(`[`Fenced::ERRNO`]`)` (and the
/// descriptor closed) when fenced. As `O_TRUNC` does, only a regular file
/// is truncated.
pub fn open_truncating(
    flags: libc::c_int,
    open: impl FnOnce(libc::c_int) -> Result<OwnedFd, libc::c_int>,
) -> Result<OwnedFd, libc::c_int> {
    if flags & libc::O_TRUNC == 0 {
        // An ordinary open changes no size: the door is not involved.
        return open(flags);
    }
    // The host open runs with no lock held (it may block, a FIFO or a slow
    // mount): only the truncation, admitted against the object it returned,
    // runs under the registry's read lock.
    let owned = open(flags & !libc::O_TRUNC)?;
    let Some(stat) = fstat(owned.as_raw_fd()) else {
        return Err(last_errno());
    };
    if stat.st_mode & libc::S_IFMT != libc::S_IFREG {
        return Ok(owned);
    }
    let registry = WINDOWED.read();
    check(&registry, owned.as_raw_fd(), Change::Resize(0)).map_err(|Fenced| Fenced::ERRNO)?;
    if flags & libc::O_ACCMODE != libc::O_RDONLY {
        // SAFETY: a plain host call on the descriptor this function owns.
        if unsafe { libc::ftruncate(owned.as_raw_fd(), 0) } != 0 {
            return Err(last_errno());
        }
        return Ok(owned);
    }
    reopen_truncating(owned, flags)
}

/// `O_RDONLY | O_TRUNC` (Linux truncates when the caller may write, open(2)):
/// reopen the exact object through its descriptor with the caller's flags.
#[cfg(target_os = "linux")]
fn reopen_truncating(owned: OwnedFd, flags: libc::c_int) -> Result<OwnedFd, libc::c_int> {
    let path = std::ffi::CString::new(format!("/proc/self/fd/{}", owned.as_raw_fd()))
        .map_err(|_| libc::EINVAL)?;
    // The object exists now: creation flags no longer apply, and the
    // descriptor link is followed by design.
    let flags = flags & !(libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW);
    // SAFETY: a NUL-terminated path naming a descriptor this function owns.
    let fd = unsafe { libc::open(path.as_ptr(), flags) };
    if fd < 0 {
        return Err(last_errno());
    }
    drop(owned);
    // SAFETY: `open` returned a fresh descriptor this function now owns.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// No window exists on a host without one (#2972): refuse rather than open
/// untruncated.
#[cfg(not(target_os = "linux"))]
fn reopen_truncating(owned: OwnedFd, _flags: libc::c_int) -> Result<OwnedFd, libc::c_int> {
    drop(owned);
    Err(Fenced::ERRNO)
}

/// Record the host file `fd` names as mapped by a shared file window,
/// before the window's source is retained. `None` (nothing recorded) when
/// its identity cannot be read: the caller must not window it.
/// Return the `(device, inode)` identity of `fd` without pinning it.
pub fn identity(fd: BorrowedFd<'_>) -> Option<InodeIdentity> {
    fstat(fd.as_raw_fd()).map(|stat| identity_of(&stat))
}

pub fn record(fd: BorrowedFd<'_>) -> Option<InodeIdentity> {
    let stat = fstat(fd.as_raw_fd())?;
    let identity = identity_of(&stat);
    let birth = birth(fd.as_raw_fd(), &stat);
    WINDOWED.write().insert(identity, birth);
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
    match registry.get(&identity_of(&stat)) {
        // A reused `(st_dev, st_ino)` is another inode: not windowed.
        Some(&recorded) if recorded == birth(fd, &stat) => {}
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
        let (_dir, path, windowed) = file(8192);
        let (_other_dir, other_path, other) = file(8192);
        let identity = record(windowed.as_fd()).unwrap();
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
        let (_dir, path, _file) = file(4096);
        for flags in [libc::O_RDWR, libc::O_RDWR | libc::O_TRUNC] {
            let opened = open_truncating(flags, |flags| {
                // A writer can take the lock while the open runs (bounded:
                // another test's read lock is held only for a check).
                let taken = WINDOWED
                    .try_write_for(std::time::Duration::from_secs(10))
                    .is_some();
                assert!(taken, "the registry is locked across the open ({flags:#x})");
                host_open(&path, flags)
            });
            assert!(opened.is_ok());
        }
    }

    /// Early review P0 2 (#2975): the registry holds no host descriptor
    /// (its value is a [`Birth`]), so a reused `(st_dev, st_ino)` must not
    /// be taken for the windowed inode.
    #[test]
    fn a_recorded_window_holds_no_descriptor_and_names_only_its_inode() {
        let (_dir, path, windowed) = file(8192);
        let identity = record(windowed.as_fd()).unwrap();
        assert!(maps(identity));
        // Same (st_dev, st_ino), another birth: the inode was reused.
        WINDOWED
            .write()
            .insert(identity, Birth(Some((0, 0))))
            .unwrap();
        if birth(windowed.as_raw_fd(), &fstat(windowed.as_raw_fd()).unwrap()) != Birth(None) {
            assert_eq!(resize(windowed.as_fd(), 0), Ok(()));
            assert_eq!(size(&path), 0);
        }
        WINDOWED.write().remove(&identity);
    }
}
