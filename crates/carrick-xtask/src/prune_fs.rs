//! Descriptor-relative filesystem operations; display paths never authorize I/O.
use std::ffi::{CStr, CString, OsStr, OsString};
use std::fs::{File, Metadata};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::MetadataExt;
use std::path::Path;

fn name(value: &OsStr) -> io::Result<CString> {
    if value.as_bytes().contains(&b'/') || value.is_empty() {
        return Err(io::Error::other("not a single directory entry"));
    }
    CString::new(value.as_bytes()).map_err(io::Error::other)
}

pub(super) fn root(path: &Path) -> io::Result<File> {
    let path = CString::new(path.as_os_str().as_bytes()).map_err(io::Error::other)?;
    // SAFETY: a valid C pathname; ownership of a successful descriptor transfers below.
    owned(unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    })
}

fn owned(fd: libc::c_int) -> io::Result<File> {
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        // SAFETY: the successful open returned a new owned descriptor.
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}

pub(super) fn open(parent: &File, entry: &OsStr, directory: bool) -> io::Result<File> {
    let entry = name(entry)?;
    let flags = libc::O_RDONLY
        | libc::O_NOFOLLOW
        | libc::O_CLOEXEC
        | libc::O_NONBLOCK
        | if directory { libc::O_DIRECTORY } else { 0 };
    // SAFETY: parent remains owned and the single-component C name is valid.
    owned(unsafe { libc::openat(parent.as_raw_fd(), entry.as_ptr(), flags) })
}

pub(super) fn mkdir(parent: &File, entry: &OsStr) -> io::Result<()> {
    let entry = name(entry)?;
    // SAFETY: valid owned directory and C name; 0700 prevents access by other users.
    if unsafe { libc::mkdirat(parent.as_raw_fd(), entry.as_ptr(), 0o700) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

pub(super) fn lock(parent: &File) -> io::Result<File> {
    let entry = c".cargo-lock";
    // SAFETY: native Cargo lock opened relative to the retained profile directory.
    owned(unsafe {
        libc::openat(
            parent.as_raw_fd(),
            entry.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o666,
        )
    })
}

pub(super) fn same(parent: &File, entry: &OsStr, expected: &Metadata) -> io::Result<bool> {
    let entry = name(entry)?;
    let mut result = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: result is writable; fstatat does not follow a replaced symlink.
    if unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            entry.as_ptr(),
            result.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful fstatat initialized the structure.
    let result = unsafe { result.assume_init() };
    Ok(result.st_dev as u64 == expected.dev()
        && result.st_ino as u64 == expected.ino()
        && result.st_mode as u32 & libc::S_IFMT as u32 == expected.mode() & libc::S_IFMT as u32)
}

pub(super) fn rename(from: &File, entry: &OsStr, to: &File, destination: &OsStr) -> io::Result<()> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let entry = name(entry)?;
        let destination = name(destination)?;
        // SAFETY: both directories are retained and both names are single components.
        // Staging must never overwrite an unexpected destination entry.
        #[cfg(target_os = "linux")]
        let result = unsafe {
            libc::renameat2(
                from.as_raw_fd(),
                entry.as_ptr(),
                to.as_raw_fd(),
                destination.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        };
        #[cfg(target_os = "macos")]
        let result = unsafe {
            libc::renameatx_np(
                from.as_raw_fd(),
                entry.as_ptr(),
                to.as_raw_fd(),
                destination.as_ptr(),
                libc::RENAME_EXCL,
            )
        };
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (from, entry, to, destination);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "no-clobber descriptor staging is supported on Linux and macOS",
        ))
    }
}

pub(super) fn unlink(parent: &File, entry: &OsStr, directory: bool) -> io::Result<()> {
    let entry = name(entry)?;
    // SAFETY: unlinkat never follows a final symlink; directory removal is empty-only.
    if unsafe {
        libc::unlinkat(
            parent.as_raw_fd(),
            entry.as_ptr(),
            if directory { libc::AT_REMOVEDIR } else { 0 },
        )
    } == 0
    {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

struct Stream(*mut libc::DIR);
impl Drop for Stream {
    fn drop(&mut self) {
        // SAFETY: fdopendir transferred a unique directory stream to this owner.
        unsafe {
            libc::closedir(self.0);
        }
    }
}

fn clear_errno() {
    // SAFETY: these libc accessors address this thread's errno slot.
    #[cfg(target_os = "linux")]
    unsafe {
        *libc::__errno_location() = 0;
    }
    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    unsafe {
        *libc::__error() = 0;
    }
    #[cfg(target_os = "netbsd")]
    unsafe {
        *libc::__errno() = 0;
    }
}

pub(super) fn entries(directory: &File) -> io::Result<Vec<OsString>> {
    // A fresh open description avoids sharing readdir offsets with the anchor.
    let fd = open(directory, OsStr::new("."), true)?.into_raw_fd();
    // SAFETY: fd is a new owned directory descriptor.
    let stream = unsafe { libc::fdopendir(fd) };
    if stream.is_null() {
        let error = io::Error::last_os_error();
        // SAFETY: fdopendir failed without consuming the descriptor.
        unsafe {
            libc::close(fd);
        }
        return Err(error);
    }
    let stream = Stream(stream);
    let mut result = Vec::new();
    loop {
        clear_errno();
        // SAFETY: the stream is live and accessed only by this thread.
        let entry = unsafe { libc::readdir(stream.0) };
        if entry.is_null() {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(0) {
                return Err(error);
            }
            break;
        }
        // SAFETY: readdir supplied a terminated name valid until the next call.
        let bytes = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if bytes != b"." && bytes != b".." {
            result.push(OsString::from_vec(bytes.to_vec()));
        }
    }
    result.sort();
    Ok(result)
}
