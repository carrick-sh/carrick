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

use std::ffi::CString;
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
        if clonefile(&src, &dst).is_err() {
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

/// Whether two paths live on the same device (a precondition for `clonefile`).
fn same_device(a: &Path, b: &Path) -> Option<bool> {
    use std::os::unix::fs::MetadataExt as _;
    let da = std::fs::metadata(a).ok()?.dev();
    let db = std::fs::metadata(b).ok()?.dev();
    Some(da == db)
}

fn clonefile(src: &Path, dst: &Path) -> std::io::Result<()> {
    let csrc = CString::new(src.as_os_str().as_encoded_bytes())
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    let cdst = CString::new(dst.as_os_str().as_encoded_bytes())
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    // SAFETY: both pointers are valid NUL-terminated C strings; flags=0 is the
    // documented default (recursive COW clone, follow nothing special).
    let rc = unsafe { libc::clonefile(csrc.as_ptr(), cdst.as_ptr(), 0) };
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
}
