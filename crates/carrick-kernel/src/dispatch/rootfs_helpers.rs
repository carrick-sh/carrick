//! Rootfs, path, dirent, and access check helpers.

pub(crate) use std::path::{Component, Path};
use zerocopy::IntoBytes;

pub(crate) use carrick_abi::{
    LINUX_DIRENT64_HEADER_SIZE, LINUX_DT_CHR, LINUX_DT_DIR, LINUX_DT_FIFO, LINUX_DT_LNK,
    LINUX_DT_REG, LINUX_DT_SOCK, LINUX_E2BIG, LINUX_EACCES, LINUX_EFAULT, LINUX_ENAMETOOLONG,
    LINUX_S_IFCHR, LINUX_S_IFDIR, LINUX_S_IFIFO, LINUX_S_IFLNK, LINUX_S_IFREG, LINUX_S_IFSOCK,
    LinuxDirent64Header,
};
use carrick_guest_mem::CurrentMmMemory;

use crate::linux_abi::LinuxErrno;
use carrick_vfs::rootfs::{RootFsDirEntry, RootFsEntryKind, RootFsMetadata};

use super::DispatchOutcome;

pub(crate) const MAX_GUEST_PATH: usize = 4096;
/// Linux bounds one `execve(2)` argument or environment string, including its
/// terminating NUL, to 32 guest pages. This uses Linux's fixed guest page size,
/// not the host page size (16 KiB on the reference macOS host).
const MAX_EXEC_STRING_BYTES: usize = 32 * crate::linux_abi::LINUX_PAGE_SIZE as usize;

/// Linux `NLMSG_ALIGNTO` — netlink messages and attributes are 4-byte aligned.
pub(crate) const NLMSG_ALIGNTO: usize = 4;

/// Decode the major number from a raw Linux `dev_t` (the glibc `gnu_dev_major`
/// encoding documented in makedev(3)): the major occupies bits 8..20 and 32..64,
/// the minor bits 0..8 and 20..64 (interleaved so a 32-bit dev_t stays
/// compatible). `stat`/`mknod` carry the raw `dev_t` verbatim; only `statx`
/// reports the split fields, so the decode lives here. Clean-room from the man
/// page, not glibc source.
pub(super) fn linux_dev_major(dev: u64) -> u32 {
    (((dev >> 8) & 0xfff) | ((dev >> 32) & !0xfff)) as u32
}

/// Decode the minor number from a raw Linux `dev_t` (see `linux_dev_major`).
pub(super) fn linux_dev_minor(dev: u64) -> u32 {
    ((dev & 0xff) | ((dev >> 12) & !0xff)) as u32
}

pub(super) fn linux_mode(metadata: &RootFsMetadata) -> u32 {
    let kind = match metadata.kind {
        RootFsEntryKind::File => LINUX_S_IFREG,
        RootFsEntryKind::Directory => LINUX_S_IFDIR,
        RootFsEntryKind::Symlink => LINUX_S_IFLNK,
        RootFsEntryKind::CharDevice => LINUX_S_IFCHR,
        RootFsEntryKind::Fifo => LINUX_S_IFIFO,
        RootFsEntryKind::Socket => LINUX_S_IFSOCK,
    };
    kind | (metadata.mode & 0o7777)
}

pub(super) fn access_metadata(metadata: &RootFsMetadata, mode: u64) -> DispatchOutcome {
    // carrick runs the guest as uid 0 (root), and the overlay/host backend is
    // writable (read-only rootfs files copy up on write). Root bypasses DAC
    // read/write checks entirely, so R_OK and W_OK always succeed for an
    // existing path — previously W_OK returned EACCES unconditionally, which
    // made dpkg refuse /var/lib/dpkg ("required read/write access") even
    // though writes actually work. For execute, root still requires at least
    // one x bit on a regular file.
    if carrick_abi::LinuxAccessMode::from_bits_truncate(mode)
        .contains(carrick_abi::LinuxAccessMode::X_OK)
        && metadata.kind == RootFsEntryKind::File
        && metadata.mode & 0o111 == 0
    {
        return DispatchOutcome::Errno {
            errno: LINUX_EACCES,
        };
    }
    DispatchOutcome::Returned { value: 0 }
}

/// POSIX discretionary access control (DAC) check. `uid`/`gid` are the
/// CALLER's ids to test against (real ids for `access(2)`, effective for
/// `faccessat(AT_EACCESS)` / `open(2)`); `file_*` describe the target.
/// `mask` is `R_OK|W_OK|X_OK` (`F_OK`=0 always passes — existence is the
/// caller's concern). Returns `Ok(())` if permitted, `Err(EACCES)` otherwise.
///
/// Root (uid 0) bypasses read/write; for execute it still requires at least
/// one execute bit on a regular file (dirs are always searchable for root).
/// Non-root selects exactly ONE triplet — owner if `uid` matches the file
/// owner, else group if `gid` matches, else other — matching the kernel
/// (owner perms apply even when more restrictive than group/other).
pub(super) fn dac_check(
    uid: carrick_abi::NsUid,
    gid: carrick_abi::NsGid,
    file_uid: carrick_abi::NsUid,
    file_gid: carrick_abi::NsGid,
    file_mode: u32,
    is_dir: bool,
    mask: u64,
) -> Result<(), LinuxErrno> {
    let access_mode = carrick_abi::LinuxAccessMode::from_bits_truncate(mask);
    let need = (if access_mode.contains(carrick_abi::LinuxAccessMode::R_OK) {
        4
    } else {
        0
    }) | (if access_mode.contains(carrick_abi::LinuxAccessMode::W_OK) {
        2
    } else {
        0
    }) | (if access_mode.contains(carrick_abi::LinuxAccessMode::X_OK) {
        1
    } else {
        0
    });
    if need == 0 {
        return Ok(());
    }
    if uid.is_root() {
        if need & 1 != 0 && !is_dir && file_mode & 0o111 == 0 {
            return Err(LINUX_EACCES);
        }
        return Ok(());
    }
    let triplet = if uid == file_uid {
        (file_mode >> 6) & 7
    } else if gid == file_gid {
        (file_mode >> 3) & 7
    } else {
        file_mode & 7
    };
    if triplet & need == need {
        Ok(())
    } else {
        Err(LINUX_EACCES)
    }
}

pub(super) fn synthetic_readonly_access(mode: u64) -> DispatchOutcome {
    synthetic_readonly_access_with_errno(mode, LINUX_EACCES)
}

pub(super) fn synthetic_readonly_access_with_errno(
    mode: u64,
    write_errno: LinuxErrno,
) -> DispatchOutcome {
    if carrick_abi::LinuxAccessMode::from_bits_truncate(mode)
        .contains(carrick_abi::LinuxAccessMode::W_OK)
    {
        DispatchOutcome::Errno { errno: write_errno }
    } else {
        DispatchOutcome::Returned { value: 0 }
    }
}

pub(super) fn blocks_512(size: usize) -> i64 {
    if size == 0 {
        0
    } else {
        size.div_ceil(512) as i64
    }
}

pub(super) fn dirent64_record(entry: &RootFsDirEntry, next_offset: usize) -> Vec<u8> {
    // `entry.name` is in the VFS layer's reversible escape form; decode back to
    // the opaque directory-entry BYTES so an undecodable filename round-trips
    // through getdents (Linux d_name is raw bytes, not UTF-8). Valid-UTF-8
    // names decode to themselves.
    let name_bytes = carrick_vfs::pathcodec::decode_to_bytes(&entry.name);
    let name = name_bytes.as_slice();
    let record_len = align_to(LINUX_DIRENT64_HEADER_SIZE + name.len() + 1, 8);
    let header = LinuxDirent64Header {
        // Real host inode when known, so scandir's DirEntry.inode() matches a
        // later stat()'s st_ino; else a stable path-hash (in-memory/synthetic).
        d_ino: if entry.ino != 0 {
            entry.ino
        } else {
            inode_for_path(&entry.metadata.path)
        },
        d_off: next_offset as i64,
        d_reclen: record_len as u16,
        d_type: linux_dirent_type(entry.metadata.kind),
    };

    let mut out = vec![0; record_len];
    out[..LINUX_DIRENT64_HEADER_SIZE].copy_from_slice(header.as_bytes());
    out[LINUX_DIRENT64_HEADER_SIZE..LINUX_DIRENT64_HEADER_SIZE + name.len()].copy_from_slice(name);
    out
}

pub(super) fn linux_dirent_type(kind: RootFsEntryKind) -> u8 {
    match kind {
        RootFsEntryKind::File => LINUX_DT_REG,
        RootFsEntryKind::Directory => LINUX_DT_DIR,
        RootFsEntryKind::Symlink => LINUX_DT_LNK,
        RootFsEntryKind::CharDevice => LINUX_DT_CHR,
        RootFsEntryKind::Fifo => LINUX_DT_FIFO,
        RootFsEntryKind::Socket => LINUX_DT_SOCK,
    }
}

pub(super) fn align_to(value: usize, alignment: usize) -> usize {
    value.div_ceil(alignment) * alignment
}

pub(super) fn inode_for_path(path: &Path) -> u64 {
    // Inode numbers must reflect file *identity*, not the textual path used to
    // reach the file. stat("/a/b") and stat(".") from inside /a/b must agree,
    // or TOCTOU identity checks abort — dpkg-preconfigure stats a directory,
    // chdirs in, re-stats ".", and bails with "directory … changed before
    // chdir, expected ino=X, actual ino=Y". Normalise the path lexically
    // (collapse ".", "..", and "//") before hashing so every spelling of one
    // path maps to one inode. `normalize` returns None for paths that escape
    // the root ("/.."); fall back to the raw bytes there so we never panic.
    // Hash the RAW path bytes so an undecodable filename gets a stable,
    // distinct inode — to_string_lossy would collapse different undecodable
    // spellings to the same U+FFFD soup. The path may arrive in EITHER form:
    // the VFS layer's reversible escape (`&str`-derived, e.g. a synthetic
    // stat) OR already-raw bytes (a `normalize`-decoded PathBuf from getdents).
    // Canonicalise to raw bytes first so both spellings of one file agree.
    use std::os::unix::ffi::OsStrExt;
    let os_bytes = path.as_os_str().as_bytes();
    let decoded_owned;
    let canon_bytes: &[u8] = match std::str::from_utf8(os_bytes) {
        Ok(s) if carrick_vfs::pathcodec::has_escaped_bytes(s) => {
            decoded_owned = carrick_vfs::pathcodec::decode_to_bytes(s);
            &decoded_owned
        }
        _ => os_bytes,
    };
    let normalized =
        carrick_vfs::fs_backend::normalize_raw(Path::new(std::ffi::OsStr::from_bytes(canon_bytes)));
    let key_os = normalized
        .as_ref()
        .map(|p| p.as_os_str().as_bytes())
        .unwrap_or(canon_bytes);
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in key_os {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash.max(1)
}

pub(super) fn join_rootfs_path(base: &str, path: &str) -> String {
    let mut parts = Vec::new();
    for component in Path::new(base)
        .components()
        .chain(Path::new(path).components())
    {
        match component {
            Component::Prefix(_) => {}
            Component::RootDir => parts.clear(),
            Component::CurDir => {}
            Component::ParentDir => {
                parts.pop();
            }
            Component::Normal(name) => parts.push(name.to_string_lossy().into_owned()),
        }
    }
    if parts.is_empty() {
        "/".to_owned()
    } else {
        format!("/{}", parts.join("/"))
    }
}

pub(super) fn display_rootfs_path(path: &Path) -> String {
    // Idempotent: callers pass either a relative (normalised) path or an
    // already-absolute one. Strip leading slashes and prepend exactly one so
    // we never produce a double leading slash (getcwd returned "//tmp/...").
    let s = path.to_string_lossy();
    let trimmed = s.trim_start_matches('/');
    if trimmed.is_empty() {
        "/".to_owned()
    } else {
        format!("/{trimmed}")
    }
}

/// Read a NULL-terminated array of guest VA pointers, dereferencing each to a
/// C string as RAW BYTES — for `argv` / `envp` in `execve(2)`, which Linux
/// treats as opaque byte strings (NOT UTF-8). See [`read_guest_c_string_bytes`].
pub(super) fn read_guest_string_array_bytes(
    memory: &impl CurrentMmMemory,
    array_addr: u64,
) -> Result<Vec<Vec<u8>>, LinuxErrno> {
    if array_addr == 0 {
        return Ok(Vec::new());
    }
    const MAX_ENTRIES: usize = 4096;
    let mut out = Vec::new();
    for index in 0..MAX_ENTRIES {
        let slot_addr = array_addr
            .checked_add((index as u64) * 8)
            .ok_or(LINUX_E2BIG)?;
        let bytes = memory.read_bytes(slot_addr, 8).map_err(|_| LINUX_EFAULT)?;
        let ptr = u64::from_le_bytes(bytes.try_into().map_err(|_| LINUX_EFAULT)?);
        if ptr == 0 {
            return Ok(out);
        }
        out.push(read_guest_exec_string_bytes(memory, ptr)?);
    }
    Err(LINUX_E2BIG)
}

pub(super) fn validate_exec_vector_size(
    argv: &[Vec<u8>],
    env: &[Vec<u8>],
) -> Result<(), LinuxErrno> {
    let pointer_bytes = argv
        .len()
        .checked_add(env.len())
        .and_then(|count| count.checked_add(2))
        .and_then(|count| count.checked_mul(std::mem::size_of::<u64>()))
        .ok_or(LINUX_E2BIG)?;
    let total = argv
        .iter()
        .chain(env)
        .try_fold(pointer_bytes, |total, item| {
            item.len()
                .checked_add(1)
                .and_then(|item_len| total.checked_add(item_len))
        })
        .ok_or(LINUX_E2BIG)?;
    if total > crate::linux_abi::LINUX_ARG_MAX {
        return Err(LINUX_E2BIG);
    }
    Ok(())
}

#[cfg(test)]
mod exec_vector_tests {
    use super::*;

    fn one_string_array(payload_len: usize) -> crate::dispatch::LinearMemory {
        const BASE: u64 = 0x1000;
        const STRING_OFFSET: usize = 0x100;
        let string_address = BASE + STRING_OFFSET as u64;
        let mut bytes = vec![0_u8; STRING_OFFSET + payload_len + 1];
        bytes[..8].copy_from_slice(&string_address.to_le_bytes());
        bytes[STRING_OFFSET..STRING_OFFSET + payload_len].fill(b'x');
        crate::dispatch::LinearMemory::new(BASE, bytes)
    }

    #[test]
    fn exec_argument_string_can_exceed_path_max() {
        const BASE: u64 = 0x1000;
        let memory = one_string_array(MAX_GUEST_PATH);

        let argv = read_guest_string_array_bytes(&memory, BASE).expect("read long exec argument");

        assert_eq!(argv, vec![vec![b'x'; MAX_GUEST_PATH]]);
    }

    #[test]
    fn exec_string_limit_includes_terminating_nul_and_returns_e2big() {
        const BASE: u64 = 0x1000;
        let largest = one_string_array(MAX_EXEC_STRING_BYTES - 1);
        assert_eq!(
            read_guest_string_array_bytes(&largest, BASE).expect("read largest Linux exec string")
                [0]
            .len(),
            MAX_EXEC_STRING_BYTES - 1
        );

        let oversized = one_string_array(MAX_EXEC_STRING_BYTES);
        assert_eq!(
            read_guest_string_array_bytes(&oversized, BASE),
            Err(LINUX_E2BIG)
        );
    }

    #[test]
    fn path_limit_and_unmapped_exec_string_errors_are_preserved() {
        const BASE: u64 = 0x1000;
        let path = one_string_array(MAX_GUEST_PATH);
        assert_eq!(
            read_guest_c_string_bytes(&path, BASE + 0x100),
            Err(LINUX_ENAMETOOLONG)
        );

        let mut pointer_only = vec![0_u8; 16];
        pointer_only[..8].copy_from_slice(&0x9000_u64.to_le_bytes());
        let unmapped = crate::dispatch::LinearMemory::new(BASE, pointer_only);
        assert_eq!(
            read_guest_string_array_bytes(&unmapped, BASE),
            Err(LINUX_EFAULT)
        );
    }

    #[test]
    fn exec_vector_rejects_payload_beyond_linux_arg_max() {
        let allowed = vec![vec![b'x'; crate::linux_abi::LINUX_ARG_MAX - 32]];
        assert!(validate_exec_vector_size(&allowed, &[]).is_ok());

        let oversized = vec![vec![b'x'; crate::linux_abi::LINUX_ARG_MAX]];
        assert_eq!(validate_exec_vector_size(&oversized, &[]), Err(LINUX_E2BIG));
    }
}

/// Adapter from the VFS-trait [`Metadata`](carrick_vfs::Metadata) back to
/// [`RootFsMetadata`] for the dispatcher's existing stat/statx
/// writers, which still take the rootfs-shaped struct. Used by every
/// dispatcher fs syscall that's been migrated to consult
/// `RootFsVfs::lookup`.
pub(super) fn vfs_md_to_rootfs_md(path: &str, md: &carrick_vfs::Metadata) -> RootFsMetadata {
    RootFsMetadata {
        path: Path::new(path).to_path_buf(),
        kind: match md.kind {
            carrick_vfs::EntryKind::File => RootFsEntryKind::File,
            carrick_vfs::EntryKind::Directory => RootFsEntryKind::Directory,
            carrick_vfs::EntryKind::Symlink => RootFsEntryKind::Symlink,
            carrick_vfs::EntryKind::CharDevice => RootFsEntryKind::CharDevice,
            carrick_vfs::EntryKind::Fifo => RootFsEntryKind::Fifo,
            carrick_vfs::EntryKind::Socket => RootFsEntryKind::Socket,
        },
        mode: md.mode,
        size: md.size as usize,
    }
}

pub mod linux_errno {
    pub use crate::linux_abi::{
        LINUX_E2BIG as E2BIG, LINUX_EACCES as EACCES, LINUX_EADDRINUSE as EADDRINUSE,
        LINUX_EADDRNOTAVAIL as EADDRNOTAVAIL, LINUX_EAFNOSUPPORT as EAFNOSUPPORT,
        LINUX_EAGAIN as EAGAIN, LINUX_EALREADY as EALREADY, LINUX_EBADF as EBADF,
        LINUX_EBADMSG as EBADMSG, LINUX_EBUSY as EBUSY, LINUX_ECANCELED as ECANCELED,
        LINUX_ECHILD as ECHILD, LINUX_ECONNABORTED as ECONNABORTED,
        LINUX_ECONNREFUSED as ECONNREFUSED, LINUX_ECONNRESET as ECONNRESET,
        LINUX_EDEADLK as EDEADLK, LINUX_EDESTADDRREQ as EDESTADDRREQ, LINUX_EDOM as EDOM,
        LINUX_EDQUOT as EDQUOT, LINUX_EEXIST as EEXIST, LINUX_EFAULT as EFAULT,
        LINUX_EFBIG as EFBIG, LINUX_EHOSTDOWN as EHOSTDOWN, LINUX_EHOSTUNREACH as EHOSTUNREACH,
        LINUX_EIDRM as EIDRM, LINUX_EILSEQ as EILSEQ, LINUX_EINPROGRESS as EINPROGRESS,
        LINUX_EINTR as EINTR, LINUX_EINVAL as EINVAL, LINUX_EIO as EIO, LINUX_EISCONN as EISCONN,
        LINUX_EISDIR as EISDIR, LINUX_ELOOP as ELOOP, LINUX_EMFILE as EMFILE,
        LINUX_EMLINK as EMLINK, LINUX_EMSGSIZE as EMSGSIZE, LINUX_ENAMETOOLONG as ENAMETOOLONG,
        LINUX_ENETDOWN as ENETDOWN, LINUX_ENETRESET as ENETRESET, LINUX_ENETUNREACH as ENETUNREACH,
        LINUX_ENFILE as ENFILE, LINUX_ENOBUFS as ENOBUFS, LINUX_ENODEV as ENODEV,
        LINUX_ENOENT as ENOENT, LINUX_ENOEXEC as ENOEXEC, LINUX_ENOLCK as ENOLCK,
        LINUX_ENOLINK as ENOLINK, LINUX_ENOMEM as ENOMEM, LINUX_ENOMSG as ENOMSG,
        LINUX_ENOPROTOOPT as ENOPROTOOPT, LINUX_ENOSPC as ENOSPC, LINUX_ENOSYS as ENOSYS,
        LINUX_ENOTBLK as ENOTBLK, LINUX_ENOTCONN as ENOTCONN, LINUX_ENOTDIR as ENOTDIR,
        LINUX_ENOTEMPTY as ENOTEMPTY, LINUX_ENOTSOCK as ENOTSOCK, LINUX_ENOTTY as ENOTTY,
        LINUX_ENXIO as ENXIO, LINUX_EOPNOTSUPP as EOPNOTSUPP, LINUX_EOVERFLOW as EOVERFLOW,
        LINUX_EPERM as EPERM, LINUX_EPFNOSUPPORT as EPFNOSUPPORT, LINUX_EPIPE as EPIPE,
        LINUX_EPROTONOSUPPORT as EPROTONOSUPPORT, LINUX_EPROTOTYPE as EPROTOTYPE,
        LINUX_ERANGE as ERANGE, LINUX_EREMOTE as EREMOTE, LINUX_EROFS as EROFS,
        LINUX_ESHUTDOWN as ESHUTDOWN, LINUX_ESOCKTNOSUPPORT as ESOCKTNOSUPPORT,
        LINUX_ESPIPE as ESPIPE, LINUX_ESRCH as ESRCH, LINUX_ESTALE as ESTALE,
        LINUX_ETIMEDOUT as ETIMEDOUT, LINUX_ETOOMANYREFS as ETOOMANYREFS, LINUX_ETXTBSY as ETXTBSY,
        LINUX_EUCLEAN as EUCLEAN, LINUX_EXDEV as EXDEV,
    };
}

/// Read a NUL-terminated C string from guest memory as RAW BYTES. Linux paths/
/// argv/env are OPAQUE byte strings, not UTF-8 — e.g. CPython's regrtest sets a
/// non-UTF-8 `PYTHONREGRTEST_UNICODE_GUARD` env var, which made an execve EINVAL
/// when carrick required UTF-8. The execve argv/env path keeps these bytes
/// verbatim; callers needing a Rust `String` (fs path lookup) use the wrapper.
pub(super) fn read_guest_c_string_bytes(
    memory: &impl CurrentMmMemory,
    address: u64,
) -> Result<Vec<u8>, LinuxErrno> {
    read_guest_c_string_bytes_bounded(memory, address, MAX_GUEST_PATH, LINUX_ENAMETOOLONG)
}

fn read_guest_exec_string_bytes(
    memory: &impl CurrentMmMemory,
    address: u64,
) -> Result<Vec<u8>, LinuxErrno> {
    read_guest_c_string_bytes_bounded(memory, address, MAX_EXEC_STRING_BYTES, LINUX_E2BIG)
}

fn read_guest_c_string_bytes_bounded(
    memory: &impl CurrentMmMemory,
    address: u64,
    max_bytes_including_nul: usize,
    too_long: LinuxErrno,
) -> Result<Vec<u8>, LinuxErrno> {
    const CHUNK: usize = 256;
    let mut bytes = Vec::new();
    let mut offset = 0usize;
    let mut stack_chunk = [0u8; CHUNK];
    while offset < max_bytes_including_nul {
        let current_address = address.checked_add(offset as u64).ok_or(too_long)?;
        let to_read = CHUNK.min(max_bytes_including_nul - offset);
        let read_len = if memory
            .read_into(current_address, &mut stack_chunk[..to_read])
            .is_ok()
        {
            to_read
        } else if to_read > 1
            && memory
                .read_into(current_address, &mut stack_chunk[..1])
                .is_ok()
        {
            1
        } else {
            return Err(LINUX_EFAULT);
        };
        let slice = &stack_chunk[..read_len];
        if let Some(nul) = slice.iter().position(|&byte| byte == 0) {
            bytes.extend_from_slice(&slice[..nul]);
            return Ok(bytes);
        }
        offset += read_len;
        bytes.extend_from_slice(slice);
    }
    Err(too_long)
}

/// As [`read_guest_c_string_bytes`], carried into a Rust `String` for the paths
/// carrick resolves against its String/Path-based fs layer. Linux paths are
/// opaque BYTES; rather than reject a non-UTF-8 path with EINVAL, undecodable
/// bytes are carried through the `&str` layer with a reversible escape
/// (`carrick_vfs::pathcodec`) — valid UTF-8 is byte-for-byte unchanged (fast path),
/// and the escape is decoded back to the raw bytes at the guest-facing read-back
/// boundaries (getdents/readlink/getcwd). The encoded form also doubles as the
/// durable host representation, since APFS rejects a raw non-UTF-8 name (EILSEQ).
/// argv/env use the bytes form and never reach here.
pub(super) fn read_guest_c_string(
    memory: &impl CurrentMmMemory,
    address: u64,
) -> Result<String, LinuxErrno> {
    const CHUNK: usize = 256;
    let mut stack_chunk = [0u8; CHUNK];
    if memory.read_into(address, &mut stack_chunk).is_ok() {
        if let Some(nul) = stack_chunk.iter().position(|&byte| byte == 0) {
            return Ok(carrick_vfs::pathcodec::encode_bytes(&stack_chunk[..nul]));
        }
    }
    Ok(carrick_vfs::pathcodec::encode_bytes(
        &read_guest_c_string_bytes(memory, address)?,
    ))
}
