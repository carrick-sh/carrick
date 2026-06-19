//! Digest-keyed `clonefile(2)` cache for extracted OCI rootfs layers.
//!
//! `carrick run <image>` used to byte-copy the entire layer stack into a fresh
//! per-run scratch on every invocation (see `HostFsBackend::extract_layers`).
//! OCI layers are content-addressed and immutable, so the COMPOSED extraction
//! of a given layer stack is identical across runs. We extract it ONCE into a
//! digest-keyed cache directory on the scratch volume, then seed each run's
//! scratch via APFS `clonefile(2)` — an O(1) copy-on-write clone instead of an
//! O(rootfs-size) byte copy. The "parent-most" extraction cost is paid once and
//! amortized across every subsequent run.
//!
//! `clonefile` preserves modes, symlinks, and xattrs (so the guest file-mode
//! `user.carrick.*` xattrs survive the clone), and the clone is copy-on-write,
//! so the guest freely mutates its scratch without disturbing the cache.
//!
//! Everything degrades cleanly: any failure (a cross-volume or non-APFS
//! scratch, a `clonefile` ENOTSUP, an extraction error) returns `Ok(false)` so
//! the caller falls back to a direct byte-copy extraction into the scratch.
//!
//! The cache directory carries no `.carrick.lock`, so the scratch sweeper
//! (`fs_backend::sweep_orphans`, which only reaps lock-bearing dirs) leaves it
//! alone — it is intentionally persistent.

#[cfg(any(target_os = "linux", target_os = "freebsd"))]
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

/// Name of the persistent cache directory, placed beside the per-run scratch
/// dirs under the scratch root (same volume, which `clonefile` requires).
const CACHE_DIR: &str = ".carrick-layer-cache";

/// Try to seed `scratch` (an existing, empty per-run dir) from the clonefile
/// cache for `layer_paths`. Returns `Ok(true)` when the scratch was populated
/// via the cache, `Ok(false)` when the cache is unusable and the caller should
/// extract directly. Never partially populates the scratch on the `false` path.
pub fn try_seed_scratch(layer_paths: &[PathBuf], scratch: &Path) -> std::io::Result<bool> {
    if layer_paths.is_empty() {
        return Ok(false);
    }
    // The per-run scratch is a TempDir created directly under the scratch root,
    // so its parent IS the scratch root. The cache lives beside it (same volume).
    let Some(scratch_root) = scratch.parent() else {
        return Ok(false);
    };
    let cache_root = scratch_root.join(CACHE_DIR);
    let entry = cache_root.join(stack_key(layer_paths)?);

    if !entry.exists() && !build_cache_entry(layer_paths, &cache_root, &entry)? {
        return Ok(false);
    }
    clone_children_into(&entry, scratch)
}

/// Linux-only: compose the per-run rootfs as an overlayfs mount instead of a
/// byte-copy. `lowerdir` = the digest-keyed cached extraction (read-only, shared
/// across runs, NEVER copied); `upperdir`/`workdir` = fresh per-run dirs under
/// `scratch`; the merged view is mounted at `scratch/merged`. Returns
/// `Ok(Some(merged))` to hand the caller the mountpoint (it opens the cap-std
/// `Dir` there and unmounts on Drop), `Ok(None)` to fall back to clone/copy.
#[cfg(target_os = "linux")]
pub fn overlay_seed_scratch(
    layer_paths: &[PathBuf],
    scratch: &Path,
) -> std::io::Result<Option<PathBuf>> {
    if layer_paths.is_empty() {
        return Ok(None);
    }
    let Some(scratch_root) = scratch.parent() else {
        return Ok(None);
    };
    let cache_root = scratch_root.join(CACHE_DIR);
    let entry = cache_root.join(stack_key(layer_paths)?);
    if !entry.exists() && !build_cache_entry(layer_paths, &cache_root, &entry)? {
        return Ok(None);
    }
    let upper = scratch.join("upper");
    let work = scratch.join("work");
    let merged = scratch.join("merged");
    for d in [&upper, &work, &merged] {
        std::fs::create_dir_all(d)?;
    }
    if mount_overlay(&entry, &upper, &work, &merged).is_err() {
        // Leave the scratch empty so the clone/copy fallback can seed it.
        let _ = std::fs::remove_dir_all(&merged);
        let _ = std::fs::remove_dir_all(&work);
        let _ = std::fs::remove_dir_all(&upper);
        return Ok(None);
    }
    Ok(Some(merged))
}

/// `mount(2)` an overlayfs at `merged` (lower RO, upper+work writable). The
/// `userxattr` option makes whiteouts/opaque markers use `user.overlay.*` xattrs
/// (settable from an unprivileged user namespace) rather than `trusted.*`
/// (CAP_SYS_ADMIN-only) or 0:0 char-device whiteouts (CAP_MKNOD-only) — so it
/// works for an unprivileged-container guest. The lower extraction already has
/// OCI whiteouts applied, so the overlay only ever adds the guest's own writes.
#[cfg(target_os = "linux")]
fn mount_overlay(lower: &Path, upper: &Path, work: &Path, merged: &Path) -> std::io::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let mut data: Vec<u8> = Vec::new();
    data.extend_from_slice(b"lowerdir=");
    data.extend_from_slice(lower.as_os_str().as_bytes());
    data.extend_from_slice(b",upperdir=");
    data.extend_from_slice(upper.as_os_str().as_bytes());
    data.extend_from_slice(b",workdir=");
    data.extend_from_slice(work.as_os_str().as_bytes());
    data.extend_from_slice(b",userxattr\0");
    let target = std::ffi::CString::new(merged.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::other("NUL in overlay mountpoint"))?;
    // SAFETY: all args are valid NUL-terminated C strings (`data` ends in NUL);
    // the kernel copies them in. A failed mount returns -1 / errno, no UB.
    let rc = unsafe {
        libc::mount(
            c"overlay".as_ptr(),
            target.as_ptr(),
            c"overlay".as_ptr(),
            0,
            data.as_ptr() as *const libc::c_void,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Stable cache key for an ordered layer stack: SHA-256 over each layer's
/// (file name, byte length). The blob file names are already content digests;
/// folding in the length is belt-and-suspenders against a truncated blob.
fn stack_key(layer_paths: &[PathBuf]) -> std::io::Result<String> {
    let mut hasher = Sha256::new();
    for path in layer_paths {
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let len = std::fs::metadata(path)?.len();
        hasher.update(name.as_bytes());
        hasher.update(b"\0");
        hasher.update(len.to_le_bytes());
        hasher.update(b"\0");
    }
    Ok(format!("{:x}", hasher.finalize()))
}

/// Extract `layer_paths` into a temp sibling under `cache_root`, then
/// atomically rename it to `entry`. Returns `Ok(true)` if `entry` now holds a
/// complete extraction (built by us or, on a lost rename race, by a concurrent
/// run), `Ok(false)` if the cache couldn't be built (caller falls back).
fn build_cache_entry(
    layer_paths: &[PathBuf],
    cache_root: &Path,
    entry: &Path,
) -> std::io::Result<bool> {
    if std::fs::create_dir_all(cache_root).is_err() {
        return Ok(false);
    }
    let building = cache_root.join(format!(
        ".building-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    if std::fs::create_dir_all(&building).is_err() {
        return Ok(false);
    }
    let extracted = (|| {
        let dir = cap_std::fs::Dir::open_ambient_dir(&building, cap_std::ambient_authority())
            .map_err(|e| e.to_string())?;
        crate::rootfs::extract_layer_paths_to_dir(layer_paths, &dir).map_err(|e| e.to_string())
    })();
    if extracted.is_err() {
        let _ = std::fs::remove_dir_all(&building);
        return Ok(false);
    }
    match std::fs::rename(&building, entry) {
        Ok(()) => Ok(true),
        // A concurrent run published the same key first; use theirs.
        Err(_) if entry.exists() => {
            let _ = std::fs::remove_dir_all(&building);
            Ok(true)
        }
        Err(_) => {
            let _ = std::fs::remove_dir_all(&building);
            Ok(false)
        }
    }
}

/// `clonefile(2)` every top-level child of `entry` into `scratch` (which exists
/// but is empty save its lockfile). We clone children rather than `entry`
/// itself because `clonefile` requires the destination path not to exist.
/// Returns `Ok(false)` (after removing anything we cloned) if any clone fails,
/// so the caller can fall back to a clean direct extraction.
fn clone_children_into(entry: &Path, scratch: &Path) -> std::io::Result<bool> {
    // Cheap up-front viability check: clonefile only works within one volume.
    if same_device(entry, scratch) != Some(true) {
        return Ok(false);
    }
    let mut cloned: Vec<PathBuf> = Vec::new();
    // Hardlink identity map (Linux replicate path only): the cache tree can
    // contain hardlinked files (the extractor reproduces tar hardlinks), and a
    // naive per-file copy would break them into independent inodes. Track
    // (dev,ino) of the first occurrence so later siblings `link(2)` to it,
    // preserving link identity AND space. macOS `clonefile` recurses a whole
    // subtree in one syscall and needs no such bookkeeping.
    #[cfg(any(target_os = "linux", target_os = "freebsd"))]
    let mut links: HashMap<(u64, u64), PathBuf> = HashMap::new();
    // `entry` is a cache dir built solely by our own OCI-layer extraction; each
    // child name is validated `Normal` below before being joined onto scratch.
    // (Generic web path-traversal rule misfires on this fs code.)
    let children = std::fs::read_dir(entry)?; // nosemgrep
    for child in children {
        let child = child?;
        let name = child.file_name();
        // Defense in depth: a cache entry is built only by our own extraction,
        // but never let a surprising name escape the scratch dir. read_dir
        // yields single components; reject anything that isn't a plain
        // `Normal` path component (no separators, no `.`/`..`).
        if std::path::Path::new(&name).components().count() != 1
            || !matches!(
                std::path::Path::new(&name).components().next(),
                Some(std::path::Component::Normal(_))
            )
        {
            return Ok(false);
        }
        let src = child.path();
        let dst = scratch.join(&name);
        #[cfg(any(target_os = "linux", target_os = "freebsd"))]
        let replicated = replicate_tree(&src, &dst, &mut links);
        #[cfg(target_os = "macos")]
        let replicated = clonefile(&src, &dst);
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "freebsd")))]
        let replicated: std::io::Result<()> =
            Err(std::io::Error::from(std::io::ErrorKind::Unsupported));
        if replicated.is_err() {
            // Roll back any partial clones so the scratch is empty for the
            // caller's fallback extraction.
            for p in &cloned {
                let _ = remove_path(p);
            }
            return Ok(false);
        }
        cloned.push(dst);
    }
    Ok(true)
}

/// Faithfully replicate the cache-entry subtree `src` to `dst` (which must not
/// yet exist), preferring an `FICLONE` reflink for file data and falling back to
/// a byte copy when the scratch filesystem has no reflink support. This is what
/// makes the digest-keyed layer cache effective on **Linux**: instead of a full
/// OCI-tar re-extraction on every `--fs host` run (gzip-decompress + cap-std
/// per-component re-walk for every file), each run seeds its fresh scratch from
/// the once-extracted cache — O(1) on btrfs/XFS/bcachefs/ZFS-bclone (reflink),
/// and a fast metadata-preserving copy everywhere else (ext4, restricted ZFS).
///
/// Preserves exactly what the extractor (`rootfs::apply_tar_to_dir`) set: dir
/// and file permission bits, symlink targets (verbatim, never followed),
/// hardlink identity within the tree, and every `user.*` xattr (carrick stores
/// the guest mode/uid/gid/socket state there). The extractor writes no uid/gid
/// (single carrick uid) and no other xattr namespaces, so neither does this.
#[cfg(any(target_os = "linux", target_os = "freebsd"))]
fn replicate_tree(
    src: &Path,
    dst: &Path,
    links: &mut HashMap<(u64, u64), PathBuf>,
) -> std::io::Result<()> {
    use std::os::unix::fs::MetadataExt as _;
    use std::os::unix::fs::PermissionsExt as _;

    let md = std::fs::symlink_metadata(src)?;
    let ft = md.file_type();

    // `src` is always inside our own digest-keyed cache (built solely by our OCI
    // extraction) and `dst` is inside the scratch under a top-level child whose
    // name `clone_children_into` already validated as a single `Normal`
    // component; the recursion descends only through that trusted tree. The
    // generic web path-traversal rule misfires on this local fs replication.
    if ft.is_symlink() {
        let target = std::fs::read_link(src)?; // nosemgrep
        std::os::unix::fs::symlink(&target, dst)?; // nosemgrep
        // lsetxattr on the link itself (symlinks rarely carry xattrs, but be
        // faithful). Mode of a symlink is ignored by Linux, so skip set_perm.
        copy_user_xattrs(src, dst);
        return Ok(());
    }

    if ft.is_dir() {
        std::fs::create_dir(dst)?; // nosemgrep
        let entries = std::fs::read_dir(src)?; // nosemgrep
        for child in entries {
            let child = child?;
            replicate_tree(&child.path(), &dst.join(child.file_name()), links)?; // nosemgrep
        }
        // Copy xattrs while the dir is still writable, THEN apply its mode last:
        // a read/search-denied mode (e.g. 0500/0000, possible in odd images) must
        // not lock us out while we still need to create children or set xattrs
        // (a non-root run cannot setxattr on a write-denied inode).
        copy_user_xattrs(src, dst);
        std::fs::set_permissions(dst, std::fs::Permissions::from_mode(md.mode()))?;
        return Ok(());
    }

    // Regular file. A hardlinked file (nlink > 1) seen before re-links to the
    // first occurrence (shares its inode, mode, and xattrs).
    if md.nlink() > 1 {
        let key = (md.dev(), md.ino());
        if let Some(first) = links.get(&key) {
            std::fs::hard_link(first, dst)?;
            return Ok(());
        }
        links.insert(key, dst.to_path_buf());
    }
    reflink_or_copy_file(src, dst)?;
    // xattrs before the (possibly read-only) mode — see the dir branch above.
    copy_user_xattrs(src, dst);
    std::fs::set_permissions(dst, std::fs::Permissions::from_mode(md.mode()))?;
    Ok(())
}

/// Copy file *data* from `src` to `dst` via an `FICLONE` reflink (O(1),
/// copy-on-write, on btrfs/XFS/bcachefs/ZFS-bclone), falling back to a byte copy
/// when the kernel/filesystem rejects the clone (EOPNOTSUPP/EXDEV/EPERM — e.g.
/// ext4, or a container that blocks the ioctl). Mode and xattrs are applied by
/// the caller, so only the bytes matter here.
#[cfg(any(target_os = "linux", target_os = "freebsd"))]
fn reflink_or_copy_file(src: &Path, dst: &Path) -> std::io::Result<()> {
    let s = std::fs::File::open(src)?; // nosemgrep
    {
        let d = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(dst)?;
        // Linux: try an FICLONE reflink first (whole-file COW on btrfs/XFS/ZFS).
        // FreeBSD has no FICLONE — its COW comes from copy_file_range below (ZFS
        // block_cloning).
        #[cfg(target_os = "linux")]
        {
            use std::os::fd::AsRawFd as _;
            // FICLONE = _IOW(0x94, 9, int): clone the whole src file into dst.
            const FICLONE: libc::c_ulong = 0x4004_9409;
            // SAFETY: both fds are open and valid; FICLONE takes the source fd as
            // its (by-value int) argument and only reads from it.
            let rc = unsafe { libc::ioctl(d.as_raw_fd(), FICLONE, s.as_raw_fd()) };
            if rc == 0 {
                return Ok(());
            }
        }
        // FICLONE requires CAP_SYS_RAWIO — denied in unprivileged containers,
        // where it returns EPERM — and isn't supported on every fs. copy_file_range(2)
        // needs no capability and still reflinks/COWs on btrfs/XFS/bcachefs and ZFS
        // with block_cloning (Linux AND FreeBSD; an efficient in-kernel copy
        // otherwise), so try it before falling back to a userspace byte copy.
        if copy_file_range_whole(&s, &d).is_ok() {
            return Ok(());
        }
    }
    // Reflink unavailable on this volume — `std::fs::copy` overwrites the empty
    // file the failed clone left behind (it create/truncates the destination).
    std::fs::copy(src, dst)?; // nosemgrep
    Ok(())
}

/// Copy the whole file `s` -> `d` via `copy_file_range(2)`: a reflink/COW where
/// the filesystem supports it (incl. unprivileged ZFS block_cloning, where
/// `FICLONE` is denied) and an efficient in-kernel copy otherwise. `d` was just
/// create/truncated, so both fds sit at offset 0; NULL offsets let the kernel
/// advance them. Shared by the Linux and FreeBSD seed paths (FreeBSD has no
/// `FICLONE`, so this is its sole COW primitive via ZFS block_cloning).
#[cfg(any(target_os = "linux", target_os = "freebsd"))]
fn copy_file_range_whole(s: &std::fs::File, d: &std::fs::File) -> std::io::Result<()> {
    use std::os::fd::AsRawFd as _;
    let mut remaining = s.metadata()?.len();
    while remaining > 0 {
        // SAFETY: both fds are open/valid; NULL in/out offsets advance the file
        // positions; len is clamped to what is left.
        let n = unsafe {
            libc::copy_file_range(
                s.as_raw_fd(),
                std::ptr::null_mut(),
                d.as_raw_fd(),
                std::ptr::null_mut(),
                remaining as usize,
                0,
            )
        };
        if n < 0 {
            return Err(std::io::Error::last_os_error());
        }
        if n == 0 {
            break; // short of EOF with no progress — let the caller byte-copy.
        }
        remaining -= n as u64;
    }
    if remaining != 0 {
        return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
    }
    Ok(())
}

/// Copy every `user.*` extended attribute from `src` to `dst` (the symlink/file
/// itself — the `l*xattr` variants never follow links). carrick's guest
/// mode/uid/gid/socket state lives under `user.carrick.*`; preserving it keeps a
/// cache-seeded scratch identical to a freshly extracted one. Best-effort: any
/// individual list/get/set failure is skipped (a missing or unsettable attr is
/// not worth failing the whole O(1) seed over).
#[cfg(target_os = "linux")]
fn copy_user_xattrs(src: &Path, dst: &Path) {
    use std::os::unix::ffi::OsStrExt as _;
    let Ok(csrc) = std::ffi::CString::new(src.as_os_str().as_bytes()) else {
        return;
    };
    let Ok(cdst) = std::ffi::CString::new(dst.as_os_str().as_bytes()) else {
        return;
    };
    // Enumerate the names (llistxattr: NUL-separated names; the symlink itself).
    let mut name_buf = vec![0u8; 1024];
    let len = loop {
        // SAFETY: csrc is a valid C string; name_buf is a valid writable buffer
        // of the passed length. llistxattr returns the byte length or -1/errno.
        let rc = unsafe {
            libc::llistxattr(
                csrc.as_ptr(),
                name_buf.as_mut_ptr() as *mut libc::c_char,
                name_buf.len(),
            )
        };
        if rc >= 0 {
            break rc as usize;
        }
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ERANGE) {
            // Buffer too small — grow and retry (size query then re-list).
            let need =
                unsafe { libc::llistxattr(csrc.as_ptr(), std::ptr::null_mut::<libc::c_char>(), 0) };
            if need <= 0 {
                return;
            }
            name_buf = vec![0u8; need as usize];
            continue;
        }
        return; // ENOTSUP / ENODATA / etc. — nothing to copy.
    };

    for raw in name_buf[..len].split(|&b| b == 0) {
        if raw.is_empty() || !raw.starts_with(b"user.") {
            continue;
        }
        let Ok(cname) = std::ffi::CString::new(raw) else {
            continue;
        };
        // Value: size query, then read.
        // SAFETY: csrc/cname are valid C strings; a null value pointer with
        // size 0 asks the kernel for the attribute's length.
        let vlen = unsafe {
            libc::lgetxattr(
                csrc.as_ptr(),
                cname.as_ptr(),
                std::ptr::null_mut::<libc::c_void>(),
                0,
            )
        };
        if vlen < 0 {
            continue;
        }
        let mut val = vec![0u8; vlen as usize];
        let got = unsafe {
            libc::lgetxattr(
                csrc.as_ptr(),
                cname.as_ptr(),
                val.as_mut_ptr() as *mut libc::c_void,
                val.len(),
            )
        };
        if got < 0 {
            continue;
        }
        val.truncate(got as usize);
        // SAFETY: cdst/cname are valid C strings; val is a valid buffer of the
        // passed length. Best-effort — ignore the result.
        unsafe {
            libc::lsetxattr(
                cdst.as_ptr(),
                cname.as_ptr(),
                val.as_ptr() as *const libc::c_void,
                val.len(),
                0,
            );
        }
    }
}

/// FreeBSD counterpart of the Linux [`copy_user_xattrs`]: copy every
/// USER-namespace extended attribute (carrick's `carrick.*` guest
/// mode/uid/gid/socket state) from `src` to `dst` via the `extattr_*_link` API
/// (operates on the link itself; never follows). FreeBSD's extattr list is
/// length-prefixed (`[u8 len][name]…`) and the namespace is implicit, so names
/// carry no `user.` prefix. Best-effort — individual failures are skipped.
#[cfg(target_os = "freebsd")]
fn copy_user_xattrs(src: &Path, dst: &Path) {
    use std::os::unix::ffi::OsStrExt as _;
    let Ok(csrc) = std::ffi::CString::new(src.as_os_str().as_bytes()) else {
        return;
    };
    let Ok(cdst) = std::ffi::CString::new(dst.as_os_str().as_bytes()) else {
        return;
    };
    let ns = libc::EXTATTR_NAMESPACE_USER as libc::c_int;
    // SAFETY: csrc is a valid C string; a null buffer with size 0 queries the
    // total length of the (length-prefixed) attribute-name list.
    let need = unsafe { libc::extattr_list_link(csrc.as_ptr(), ns, std::ptr::null_mut(), 0) };
    if need <= 0 {
        return; // no user attrs, or ENOTSUP/error.
    }
    let mut buf = vec![0u8; need as usize];
    // SAFETY: csrc valid; buf is a writable buffer of the passed length.
    let got = unsafe {
        libc::extattr_list_link(
            csrc.as_ptr(),
            ns,
            buf.as_mut_ptr() as *mut libc::c_void,
            buf.len(),
        )
    };
    if got <= 0 {
        return;
    }
    let buf = &buf[..got as usize];
    let mut i = 0usize;
    while i < buf.len() {
        let nlen = buf[i] as usize; // 1-byte length prefix
        i += 1;
        if nlen == 0 || i + nlen > buf.len() {
            break;
        }
        let name = &buf[i..i + nlen];
        i += nlen;
        let Ok(cname) = std::ffi::CString::new(name) else {
            continue;
        };
        // SAFETY: csrc/cname valid; null value buffer with size 0 queries length.
        let vlen = unsafe {
            libc::extattr_get_link(csrc.as_ptr(), ns, cname.as_ptr(), std::ptr::null_mut(), 0)
        };
        if vlen < 0 {
            continue;
        }
        let mut val = vec![0u8; vlen as usize];
        // SAFETY: csrc/cname valid; val is a writable buffer of the passed length.
        let vgot = unsafe {
            libc::extattr_get_link(
                csrc.as_ptr(),
                ns,
                cname.as_ptr(),
                val.as_mut_ptr() as *mut libc::c_void,
                val.len(),
            )
        };
        if vgot < 0 {
            continue;
        }
        val.truncate(vgot as usize);
        // SAFETY: cdst/cname valid; val is a buffer of the passed length.
        unsafe {
            libc::extattr_set_link(
                cdst.as_ptr(),
                ns,
                cname.as_ptr(),
                val.as_ptr() as *const libc::c_void,
                val.len(),
            );
        }
    }
}

/// Whether two paths live on the same device (a precondition for `clonefile`).
fn same_device(a: &Path, b: &Path) -> Option<bool> {
    use std::os::unix::fs::MetadataExt as _;
    let da = std::fs::metadata(a).ok()?.dev();
    let db = std::fs::metadata(b).ok()?.dev();
    Some(da == db)
}

/// `CLONE_NOFOLLOW` (`sys/clonefile.h`): clone a symlink SOURCE as a symlink
/// rather than following it. Without it, `clonefile(flags=0)` on a top-level
/// symlink child — e.g. merged-/usr's `bin -> usr/bin` — FOLLOWS the link and
/// clones the target directory, materialising `/bin` as a real directory in the
/// scratch. That breaks the guest's merged-/usr view: `base-files`' preinst
/// aborts ("/bin is a directory, but should be a symbolic link"), so `apt
/// full-upgrade` fails. NOFOLLOW is a no-op for directory sources (they clone
/// recursively with their inner symlinks preserved either way).
#[cfg(target_os = "macos")]
const CLONE_NOFOLLOW: u32 = 0x0001;

/// macOS: COW-clone the whole subtree `src` into `dst` in one `clonefile(2)`
/// syscall (APFS). The single-syscall recursive clone is strictly faster than a
/// per-file walk, so macOS keeps using it; Linux (no APFS) uses [`replicate_tree`]
/// (FICLONE reflink, else a fast metadata-preserving copy) instead.
#[cfg(target_os = "macos")]
fn clonefile(src: &Path, dst: &Path) -> std::io::Result<()> {
    use std::ffi::CString;
    let csrc = CString::new(src.as_os_str().as_encoded_bytes())
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    let cdst = CString::new(dst.as_os_str().as_encoded_bytes())
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    // SAFETY: both pointers are valid NUL-terminated C strings. CLONE_NOFOLLOW
    // clones a symlink child as a symlink instead of following it (see above).
    let rc = unsafe { libc::clonefile(csrc.as_ptr(), cdst.as_ptr(), CLONE_NOFOLLOW) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

fn remove_path(p: &Path) -> std::io::Result<()> {
    match std::fs::symlink_metadata(p) {
        Ok(m) if m.is_dir() => std::fs::remove_dir_all(p),
        Ok(_) => std::fs::remove_file(p),
        Err(_) => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stack_key_is_stable_and_order_sensitive() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("sha256-aaaa");
        let b = dir.path().join("sha256-bbbb");
        std::fs::write(&a, b"layer-a").unwrap();
        std::fs::write(&b, b"layer-bb").unwrap();

        let k_ab = stack_key(&[a.clone(), b.clone()]).unwrap();
        let k_ab2 = stack_key(&[a.clone(), b.clone()]).unwrap();
        let k_ba = stack_key(&[b.clone(), a.clone()]).unwrap();
        assert_eq!(k_ab, k_ab2, "same stack hashes identically");
        assert_ne!(k_ab, k_ba, "layer order changes the key");
        assert_eq!(k_ab.len(), 64, "hex sha256");
    }

    #[test]
    fn empty_layers_declines_cache() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!try_seed_scratch(&[], dir.path()).unwrap());
    }

    #[test]
    fn same_device_true_within_one_dir() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a");
        let b = dir.path().join("b");
        std::fs::create_dir(&a).unwrap();
        std::fs::create_dir(&b).unwrap();
        assert_eq!(same_device(&a, &b), Some(true));
    }

    #[test]
    fn clone_children_preserves_top_level_symlink() {
        // Regression: merged-/usr ships `bin -> usr/bin` as a SYMLINK. Seeding
        // the scratch with clonefile(flags=0) FOLLOWED it and materialised /bin
        // as a directory, so base-files' preinst aborted ("/bin is a directory,
        // but should be a symbolic link") and `apt full-upgrade` failed. The
        // clone must reproduce the symlink verbatim.
        let tmp = tempfile::tempdir().unwrap();
        let entry = tmp.path().join("entry");
        let scratch = tmp.path().join("scratch");
        std::fs::create_dir(&entry).unwrap();
        std::fs::create_dir(&scratch).unwrap();
        std::fs::create_dir(entry.join("usrbin")).unwrap();
        std::fs::write(entry.join("usrbin/a"), b"a").unwrap();
        std::os::unix::fs::symlink("usrbin", entry.join("bin")).unwrap();

        if !clone_children_into(&entry, &scratch).unwrap() {
            // clonefile unsupported on this temp volume — nothing to assert.
            eprintln!("skip: clonefile unavailable on the temp volume");
            return;
        }
        let meta = std::fs::symlink_metadata(scratch.join("bin")).unwrap();
        assert!(
            meta.file_type().is_symlink(),
            "scratch/bin must stay a symlink (got {:?}); merged-/usr would break",
            meta.file_type()
        );
        assert_eq!(
            std::fs::read_link(scratch.join("bin")).unwrap(),
            std::path::Path::new("usrbin")
        );
    }

    /// Linux reflink-or-copy seed (`replicate_tree` via `clone_children_into`)
    /// must reproduce the cache tree faithfully: nested dirs + files with their
    /// permission bits, a verbatim symlink, the `user.carrick.*` mode xattr, and
    /// hardlink identity. This is the property that lets the digest-keyed cache
    /// replace a full tar re-extraction on every Linux `--fs host` run.
    #[cfg(target_os = "linux")]
    #[test]
    fn replicate_tree_preserves_modes_symlinks_xattrs_hardlinks() {
        use std::os::unix::ffi::OsStrExt as _;
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink};

        let set_user_xattr = |p: &Path, name: &str, val: &[u8]| -> bool {
            let cp = std::ffi::CString::new(p.as_os_str().as_bytes()).unwrap();
            let cn = std::ffi::CString::new(name).unwrap();
            // SAFETY: valid C strings + a valid value buffer of the given length.
            unsafe {
                libc::lsetxattr(
                    cp.as_ptr(),
                    cn.as_ptr(),
                    val.as_ptr() as *const libc::c_void,
                    val.len(),
                    0,
                ) == 0
            }
        };
        let get_user_xattr = |p: &Path, name: &str| -> Option<Vec<u8>> {
            let cp = std::ffi::CString::new(p.as_os_str().as_bytes()).unwrap();
            let cn = std::ffi::CString::new(name).unwrap();
            let mut buf = vec![0u8; 256];
            // SAFETY: valid C strings + a writable buffer of the given length.
            let n = unsafe {
                libc::lgetxattr(
                    cp.as_ptr(),
                    cn.as_ptr(),
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                )
            };
            if n < 0 {
                return None;
            }
            buf.truncate(n as usize);
            Some(buf)
        };

        let tmp = tempfile::tempdir().unwrap();
        let entry = tmp.path().join("entry");
        let scratch = tmp.path().join("scratch");
        std::fs::create_dir(&entry).unwrap();
        std::fs::create_dir(&scratch).unwrap();

        // Nested dir (mode 0750) holding a file (mode 0640, content).
        std::fs::create_dir(entry.join("dir")).unwrap();
        std::fs::write(entry.join("dir/file.txt"), b"hello-carrick").unwrap();
        std::fs::set_permissions(
            entry.join("dir/file.txt"),
            std::fs::Permissions::from_mode(0o640),
        )
        .unwrap();
        std::fs::set_permissions(entry.join("dir"), std::fs::Permissions::from_mode(0o750))
            .unwrap();
        // Top-level symlink (merged-/usr style).
        symlink("dir", entry.join("link")).unwrap();
        // A file carrying the guest mode xattr.
        std::fs::write(entry.join("oddmode"), b"x").unwrap();
        let xattr_ok = set_user_xattr(&entry.join("oddmode"), "user.carrick.mode", b"0600");
        // A hardlink pair (same inode).
        std::fs::write(entry.join("h1"), b"shared").unwrap();
        std::fs::hard_link(entry.join("h1"), entry.join("h2")).unwrap();

        assert!(
            clone_children_into(&entry, &scratch).unwrap(),
            "linux reflink-or-copy seed must succeed (it never declines like the old clonefile stub)"
        );

        // Content + permission bits.
        assert_eq!(
            std::fs::read(scratch.join("dir/file.txt")).unwrap(),
            b"hello-carrick"
        );
        assert_eq!(
            std::fs::symlink_metadata(scratch.join("dir/file.txt"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o640
        );
        assert_eq!(
            std::fs::symlink_metadata(scratch.join("dir"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o750
        );
        // Symlink reproduced verbatim (never followed).
        let lm = std::fs::symlink_metadata(scratch.join("link")).unwrap();
        assert!(
            lm.file_type().is_symlink(),
            "scratch/link must stay a symlink"
        );
        assert_eq!(
            std::fs::read_link(scratch.join("link")).unwrap(),
            std::path::Path::new("dir")
        );
        // Guest mode xattr preserved (only assert when the temp fs supports it).
        if xattr_ok {
            assert_eq!(
                get_user_xattr(&scratch.join("oddmode"), "user.carrick.mode").as_deref(),
                Some(&b"0600"[..]),
                "user.carrick.mode xattr must survive the seed"
            );
        }
        // Hardlink identity preserved (same inode, shared content).
        let i1 = std::fs::symlink_metadata(scratch.join("h1")).unwrap().ino();
        let i2 = std::fs::symlink_metadata(scratch.join("h2")).unwrap().ino();
        assert_eq!(
            i1, i2,
            "hardlinked files must share one inode in the scratch"
        );
        assert_eq!(std::fs::read(scratch.join("h1")).unwrap(), b"shared");
    }
}
