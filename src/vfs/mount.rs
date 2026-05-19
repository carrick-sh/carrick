//! Mount table for the unified VFS.
//!
//! [`VfsMounts`] holds a list of `(mount_point, Box<dyn Vfs>)` pairs
//! and routes path lookups to the longest-prefix-matching mount.
//! Prefix matching is on path-component boundaries, so `/proc-foo`
//! does NOT route to a mount at `/proc` — only `/proc` itself and
//! `/proc/...` do.
//!
//! For step 1 of the VFS migration the mount table is exercised by
//! its own unit tests but is not yet consulted by the dispatcher.
//! Step 2 (DevVfs) is the first real user.

use std::path::{Component, Path, PathBuf};

use super::Vfs;

/// Routing table from absolute paths to mounts. Maintained in
/// descending-prefix-length order so the first prefix-match in a
/// linear walk is always the longest. New mounts are inserted with
/// [`mount`](Self::mount), which preserves the invariant.
pub struct VfsMounts {
    entries: Vec<MountEntry>,
}

struct MountEntry {
    point: PathBuf,
    vfs: Box<dyn Vfs>,
}

impl Default for VfsMounts {
    fn default() -> Self {
        Self::new()
    }
}

impl VfsMounts {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Register a mount at `point`. `point` must be an absolute path
    /// (start with `/`). Re-mounting an existing point replaces it.
    pub fn mount(&mut self, point: impl Into<PathBuf>, vfs: Box<dyn Vfs>) {
        let point = canonicalise_mount_point(point.into());
        self.entries.retain(|e| e.point != point);
        self.entries.push(MountEntry { point, vfs });
        // Sort descending by component count so longest-prefix-wins
        // is a simple linear walk. Ties broken alphabetically for
        // determinism (matters for the readdir-shadowing logic later).
        self.entries.sort_by(|a, b| {
            let len_cmp = component_count(&b.point).cmp(&component_count(&a.point));
            len_cmp.then_with(|| a.point.cmp(&b.point))
        });
    }

    /// True iff a mount is registered at exactly `point`.
    pub fn has_mount_at(&self, point: &Path) -> bool {
        let p = canonicalise_mount_point(point.to_path_buf());
        self.entries.iter().any(|e| e.point == p)
    }

    /// Resolve `path` to the mount that owns it. Returns the full
    /// absolute path back to the caller — most mounts (proc, sys)
    /// know their own mount point and already accept absolute paths,
    /// so stripping the prefix would just churn allocations.
    pub fn resolve(&self, path: &str) -> Option<MountRef<'_>> {
        let path = canonicalise_path(path)?;
        let idx = self
            .entries
            .iter()
            .position(|e| path_starts_with_mount(&path, &e.point))?;
        Some(MountRef {
            vfs: self.entries[idx].vfs.as_ref(),
            full_path: path,
        })
    }

    /// Mutable variant of [`resolve`](Self::resolve) for ops that need
    /// to write into the mount.
    pub fn resolve_mut(&mut self, path: &str) -> Option<MountRefMut<'_>> {
        let path = canonicalise_path(path)?;
        let idx = self
            .entries
            .iter()
            .position(|e| path_starts_with_mount(&path, &e.point))?;
        Some(MountRefMut {
            vfs: self.entries[idx].vfs.as_mut(),
            full_path: path,
        })
    }

    /// Resolve `path` and return the mount-relative tail in addition
    /// to the full path. Useful for backends (rootfs, dev) that prefer
    /// to work with the relative path. For a mount at `/dev` and
    /// `path = /dev/null`, returns `relative = "null"`. Mount root
    /// returns `relative = ""`.
    pub fn resolve_relative(&self, path: &str) -> Option<MountRefRelative<'_>> {
        let r = self.resolve(path)?;
        // SAFETY: `path_starts_with_mount` returned true, so the
        // mount path is a component-aligned prefix.
        let mount_point = &self
            .entries
            .iter()
            .find(|e| path_starts_with_mount(&r.full_path, &e.point))?
            .point;
        let relative = strip_mount_prefix(&r.full_path, mount_point);
        Some(MountRefRelative {
            vfs: r.vfs,
            full_path: r.full_path.clone(),
            relative,
        })
    }

    /// Iterate registered mount points, longest-prefix-first.
    pub fn mount_points(&self) -> impl Iterator<Item = &Path> {
        self.entries.iter().map(|e| e.point.as_path())
    }

    /// Number of mounts.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

pub struct MountRef<'a> {
    pub vfs: &'a dyn Vfs,
    pub full_path: String,
}

pub struct MountRefMut<'a> {
    pub vfs: &'a mut dyn Vfs,
    pub full_path: String,
}

pub struct MountRefRelative<'a> {
    pub vfs: &'a dyn Vfs,
    pub full_path: String,
    pub relative: String,
}

// --- internal helpers --------------------------------------------------

fn canonicalise_mount_point(p: PathBuf) -> PathBuf {
    // Strip trailing slashes (except for the root). `Path` already
    // ignores them on component iteration, but normalising the stored
    // value makes `has_mount_at` comparisons obviously correct.
    let s = p.to_string_lossy();
    if s == "/" {
        return PathBuf::from("/");
    }
    let trimmed = s.trim_end_matches('/');
    PathBuf::from(trimmed)
}

fn canonicalise_path(path: &str) -> Option<String> {
    if path.is_empty() {
        return None;
    }
    if !path.starts_with('/') {
        return None;
    }
    // Resolve `.` and `..` components, reject any `..` that escapes /.
    let mut out: Vec<&str> = Vec::new();
    for comp in Path::new(path).components() {
        match comp {
            Component::RootDir => {}
            Component::CurDir => {}
            Component::ParentDir => {
                if out.pop().is_none() {
                    return None;
                }
            }
            Component::Normal(n) => out.push(n.to_str()?),
            Component::Prefix(_) => return None,
        }
    }
    if out.is_empty() {
        Some("/".to_string())
    } else {
        let mut s = String::with_capacity(path.len());
        for c in &out {
            s.push('/');
            s.push_str(c);
        }
        Some(s)
    }
}

fn path_starts_with_mount(path: &str, mount: &Path) -> bool {
    let mount_str = mount.to_string_lossy();
    if mount_str == "/" {
        return true;
    }
    if !path.starts_with(mount_str.as_ref()) {
        return false;
    }
    // Component boundary: the next byte must be `/` or end-of-string.
    let after = &path[mount_str.len()..];
    after.is_empty() || after.starts_with('/')
}

fn strip_mount_prefix(path: &str, mount: &Path) -> String {
    let mount_str = mount.to_string_lossy();
    if mount_str == "/" {
        return path.trim_start_matches('/').to_string();
    }
    let tail = &path[mount_str.len()..];
    tail.trim_start_matches('/').to_string()
}

fn component_count(p: &Path) -> usize {
    p.components()
        .filter(|c| matches!(c, Component::Normal(_)))
        .count()
}

// --- tests -------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vfs::{EntryKind, Metadata, VfsError};

    /// Trivial Vfs that reports a single fixed file at its mount root.
    /// Useful for asserting "this is the mount that resolved the path".
    struct TaggedVfs {
        tag: &'static str,
    }

    impl Vfs for TaggedVfs {
        fn lookup(&self, _path: &str) -> Result<Metadata, VfsError> {
            Ok(Metadata {
                kind: EntryKind::File,
                mode: 0o644,
                size: self.tag.len() as u64,
                uid: 0,
                gid: 0,
                mtime_secs: 0,
                mtime_nanos: 0,
            })
        }

        fn name(&self) -> &'static str {
            self.tag
        }
    }

    fn mount(tag: &'static str) -> Box<dyn Vfs> {
        Box::new(TaggedVfs { tag })
    }

    #[test]
    fn empty_mounts_resolves_nothing() {
        let m = VfsMounts::new();
        assert!(m.resolve("/").is_none());
        assert!(m.resolve("/anything").is_none());
        assert!(m.is_empty());
        assert_eq!(m.len(), 0);
    }

    #[test]
    fn root_mount_catches_everything() {
        let mut m = VfsMounts::new();
        m.mount("/", mount("root"));
        assert_eq!(m.resolve("/").unwrap().vfs.name(), "root");
        assert_eq!(m.resolve("/etc/hosts").unwrap().vfs.name(), "root");
        assert_eq!(m.resolve("/proc/cpuinfo").unwrap().vfs.name(), "root");
    }

    #[test]
    fn longest_prefix_wins() {
        let mut m = VfsMounts::new();
        m.mount("/", mount("root"));
        m.mount("/proc", mount("proc"));
        m.mount("/proc/net", mount("procnet"));
        assert_eq!(m.resolve("/etc/hosts").unwrap().vfs.name(), "root");
        assert_eq!(m.resolve("/proc/cpuinfo").unwrap().vfs.name(), "proc");
        assert_eq!(m.resolve("/proc/net/if_inet6").unwrap().vfs.name(), "procnet");
        // The mount root itself routes to that mount, not its parent.
        assert_eq!(m.resolve("/proc").unwrap().vfs.name(), "proc");
        assert_eq!(m.resolve("/proc/net").unwrap().vfs.name(), "procnet");
    }

    #[test]
    fn insertion_order_does_not_affect_resolution() {
        let mut m = VfsMounts::new();
        // Reverse-order insertion of the previous test.
        m.mount("/proc/net", mount("procnet"));
        m.mount("/proc", mount("proc"));
        m.mount("/", mount("root"));
        assert_eq!(m.resolve("/etc/hosts").unwrap().vfs.name(), "root");
        assert_eq!(m.resolve("/proc/cpuinfo").unwrap().vfs.name(), "proc");
        assert_eq!(m.resolve("/proc/net/if_inet6").unwrap().vfs.name(), "procnet");
    }

    #[test]
    fn prefix_match_respects_component_boundary() {
        let mut m = VfsMounts::new();
        m.mount("/", mount("root"));
        m.mount("/proc", mount("proc"));
        // "/procfs" is NOT in the /proc mount — different component.
        assert_eq!(m.resolve("/procfs").unwrap().vfs.name(), "root");
        assert_eq!(m.resolve("/proc-extras/foo").unwrap().vfs.name(), "root");
    }

    #[test]
    fn re_mounting_replaces_in_place() {
        let mut m = VfsMounts::new();
        m.mount("/proc", mount("proc-v1"));
        assert_eq!(m.resolve("/proc/x").unwrap().vfs.name(), "proc-v1");
        m.mount("/proc", mount("proc-v2"));
        assert_eq!(m.resolve("/proc/x").unwrap().vfs.name(), "proc-v2");
        assert_eq!(m.len(), 1);
    }

    #[test]
    fn trailing_slash_on_mount_point_normalised() {
        let mut m = VfsMounts::new();
        m.mount("/proc/", mount("proc"));
        assert!(m.has_mount_at(Path::new("/proc")));
        assert_eq!(m.resolve("/proc").unwrap().vfs.name(), "proc");
        assert_eq!(m.resolve("/proc/").unwrap().vfs.name(), "proc");
    }

    #[test]
    fn dot_and_dotdot_in_path_are_canonicalised() {
        let mut m = VfsMounts::new();
        m.mount("/proc", mount("proc"));
        m.mount("/", mount("root"));
        assert_eq!(m.resolve("/proc/./cpuinfo").unwrap().vfs.name(), "proc");
        assert_eq!(m.resolve("/proc/net/../cpuinfo").unwrap().vfs.name(), "proc");
        // .. that escapes the root is rejected.
        assert!(m.resolve("/../etc").is_none());
        assert!(m.resolve("/a/../../etc").is_none());
    }

    #[test]
    fn relative_paths_are_rejected() {
        let mut m = VfsMounts::new();
        m.mount("/", mount("root"));
        assert!(m.resolve("etc/hosts").is_none());
        assert!(m.resolve("").is_none());
    }

    #[test]
    fn resolve_relative_strips_mount_prefix() {
        let mut m = VfsMounts::new();
        m.mount("/dev", mount("dev"));
        m.mount("/", mount("root"));
        let r = m.resolve_relative("/dev/null").unwrap();
        assert_eq!(r.vfs.name(), "dev");
        assert_eq!(r.full_path, "/dev/null");
        assert_eq!(r.relative, "null");

        let r = m.resolve_relative("/dev").unwrap();
        assert_eq!(r.relative, "");

        let r = m.resolve_relative("/etc/hosts").unwrap();
        assert_eq!(r.vfs.name(), "root");
        assert_eq!(r.relative, "etc/hosts");
    }

    #[test]
    fn mount_points_iter_returns_longest_first() {
        let mut m = VfsMounts::new();
        m.mount("/", mount("root"));
        m.mount("/proc/net", mount("procnet"));
        m.mount("/proc", mount("proc"));
        m.mount("/dev", mount("dev"));
        let pts: Vec<_> = m
            .mount_points()
            .map(|p| p.to_string_lossy().into_owned())
            .collect();
        assert_eq!(pts.first().map(String::as_str), Some("/proc/net"));
        // The single-component mounts come next in alphabetical order
        // (deterministic tie-break), then root.
        assert_eq!(pts.last().map(String::as_str), Some("/"));
    }
}
