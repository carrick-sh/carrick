//! A ring task's Linux `fs_struct` values: its working directory and root.
//!
//! The ring task row owns them, beside its credentials and umask (#1392).
//! Fork copies the row; the threads of one process share the row, which is
//! exactly `CLONE_FS` (the ring serves no process clone that shares an
//! `fs_struct`). Every crossing that resolves a path carries these values,
//! with the caller's credentials, as an [`AccessContext`]: the carrier
//! resolves against them in a transient scope and keeps nothing.
//!
//! Paths are spelled as the host VFS spells them: absolute, normalized, with
//! symlinks resolved, and with an undecodable byte in the VFS's reversible
//! escape form. The ring hands them back verbatim, so no codec lives here.
extern crate alloc;

use alloc::vec::Vec;
use carrick_core_abi::host_file::{ACCESS_MAX_PATH_BYTES, AccessContext, AccessIds};
use carrick_syscall_abi::LinuxErrno;

use crate::identity::TaskCredentials;

/// An absolute host-VFS path spelling held by a task row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskPath(Vec<u8>);

impl TaskPath {
    /// `/`.
    pub fn root_directory() -> Self {
        Self(alloc::vec![b'/'])
    }

    /// An absolute spelling of at most `PATH_MAX` bytes, or `None`.
    pub fn new(bytes: &[u8]) -> Option<Self> {
        (bytes.first() == Some(&b'/')
            && bytes.len() <= ACCESS_MAX_PATH_BYTES
            && !bytes.contains(&0))
        .then(|| Self(bytes.to_vec()))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// The working directory and root of one ring process.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskFs {
    pub cwd: TaskPath,
    /// `None` until this process or an ancestor called `chroot`.
    pub root: Option<TaskPath>,
}

impl Default for TaskFs {
    fn default() -> Self {
        Self {
            cwd: TaskPath::root_directory(),
            root: None,
        }
    }
}

/// What the escape form of the host VFS reserves: the UTF-8 encodings of
/// `U+EE00..=U+EEFF` begin with these two bytes.
fn has_escaped_byte(path: &[u8]) -> bool {
    path.windows(2)
        .any(|pair| pair[0] == 0xEE && (0xB8..=0xBB).contains(&pair[1]))
}

/// What `getcwd(2)` reports for `cwd` under `root`, the one rule both the
/// host task and a ring task use.
///
/// Carrick does not re-root path resolution, so the global cwd is reported
/// verbatim except in one case: a cwd that is a strict ancestor of the root
/// (`chroot` into a subdirectory without `chdir`, CVE-2018-1000001) is
/// unreachable, and is `ENOENT`. A cwd at or inside the root is reported
/// relative to it.
pub fn visible_cwd(cwd: &[u8], root: Option<&[u8]>) -> Result<Vec<u8>, LinuxErrno> {
    let Some(root) = root.filter(|root| *root != b"/") else {
        return Ok(cwd.to_vec());
    };
    if cwd == root {
        return Ok(alloc::vec![b'/']);
    }
    if let Some(rel) = cwd
        .strip_prefix(root)
        .and_then(|rest| rest.strip_prefix(b"/"))
    {
        let mut visible = alloc::vec![b'/'];
        visible.extend_from_slice(rel);
        return Ok(visible);
    }
    let ancestor = cwd == b"/"
        || root
            .strip_prefix(cwd)
            .is_some_and(|rest| rest.first() == Some(&b'/'));
    if ancestor {
        return Err(carrick_syscall_abi::LINUX_ENOENT);
    }
    Ok(cwd.to_vec())
}

/// The file-access capabilities the carrier grants exactly when `fsuid` is 0
/// and never otherwise: `CAP_DAC_OVERRIDE` (read, write and search bypass,
/// capabilities(7)) and `CAP_FOWNER` (owner checks).
const CARRIER_FSUID0_CAPS: u64 =
    (1 << carrick_syscall_abi::CAP_DAC_OVERRIDE) | (1 << carrick_syscall_abi::CAP_FOWNER);
/// Every file capability the carrier's id-based checks could imply.
/// `CAP_DAC_READ_SEARCH` adds nothing over `CAP_DAC_OVERRIDE` for any
/// operation that crosses (its extra reach, `open_by_handle_at` and
/// `linkat(AT_EMPTY_PATH)`, never does), so with fsuid 0 it is don't-care;
/// Docker's default set (`0xa80425fb`) omits it.
const CARRIER_FILE_CAPS: u64 =
    CARRIER_FSUID0_CAPS | (1 << carrick_syscall_abi::CAP_DAC_READ_SEARCH);

/// Whether the carrier's "fsuid 0 overrides DAC" model is exactly this
/// caller's authority: fsuid 0 with `CAP_DAC_OVERRIDE` and `CAP_FOWNER`
/// effective, or a nonzero fsuid with none of the file capabilities. Any
/// other caller (a root that dropped one of them, a non-root that holds
/// one) is left unrouted rather than checked with the wrong privileges.
pub fn carrier_models_file_caps(credentials: &TaskCredentials) -> bool {
    let held = credentials.cap_effective.bits();
    if credentials.fsuid.is_root() {
        held & CARRIER_FSUID0_CAPS == CARRIER_FSUID0_CAPS
    } else {
        held & CARRIER_FILE_CAPS == 0
    }
}

impl TaskFs {
    /// `getcwd(2)` of this context: the visible spelling, without its NUL.
    /// `None` when the cwd holds an escaped undecodable byte, which only the
    /// host VFS codec can decode: that call is left unrouted, never guessed.
    pub fn getcwd(&self) -> Option<Result<Vec<u8>, LinuxErrno>> {
        if has_escaped_byte(self.cwd.as_bytes()) {
            return None;
        }
        Some(visible_cwd(
            self.cwd.as_bytes(),
            self.root.as_ref().map(TaskPath::as_bytes),
        ))
    }

    /// Append this context and the caller's credentials and umask, as one
    /// [`AccessContext`], to `out`.
    pub fn encode_access(
        &self,
        credentials: &TaskCredentials,
        umask: u32,
        out: &mut Vec<u8>,
    ) -> Result<(), LinuxErrno> {
        // The context carries ids, not capabilities: only a caller whose
        // capabilities the carrier's id-based checks reproduce crosses.
        if !carrier_models_file_caps(credentials) {
            return Err(carrick_syscall_abi::LINUX_ENOSYS);
        }
        let ids = AccessIds {
            ruid: credentials.ruid.raw(),
            euid: credentials.euid.raw(),
            suid: credentials.suid.raw(),
            fsuid: credentials.fsuid.raw(),
            rgid: credentials.rgid.raw(),
            egid: credentials.egid.raw(),
            sgid: credentials.sgid.raw(),
            fsgid: credentials.fsgid.raw(),
        };
        let mut groups = Vec::new();
        groups
            .try_reserve_exact(credentials.groups.len())
            .map_err(|_| carrick_syscall_abi::LINUX_ENOMEM)?;
        groups.extend(credentials.groups.iter().map(|group| group.raw()));
        AccessContext::encode_into(
            out,
            ids,
            umask & 0o777,
            credentials.groups_installed.then_some(groups.as_slice()),
            self.cwd.as_bytes(),
            self.root.as_ref().map(TaskPath::as_bytes),
        )
        // A context past one record's bounds (more than
        // `ACCESS_MAX_GROUPS` groups) is left unrouted, never guessed.
        .map_err(|_| carrick_syscall_abi::LINUX_ENOSYS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn visible_cwd_reports_the_global_cwd_except_above_the_root() {
        assert_eq!(visible_cwd(b"/tmp", None).unwrap(), b"/tmp");
        assert_eq!(visible_cwd(b"/tmp", Some(b"/")).unwrap(), b"/tmp");
        assert_eq!(visible_cwd(b"/jail", Some(b"/jail")).unwrap(), b"/");
        assert_eq!(visible_cwd(b"/jail/a/b", Some(b"/jail")).unwrap(), b"/a/b");
        assert_eq!(
            visible_cwd(b"/", Some(b"/jail")),
            Err(carrick_syscall_abi::LINUX_ENOENT)
        );
        assert_eq!(
            visible_cwd(b"/srv", Some(b"/srv/jail")),
            Err(carrick_syscall_abi::LINUX_ENOENT)
        );
        // A sibling that only shares a prefix is neither inside nor above.
        assert_eq!(
            visible_cwd(b"/jailbreak", Some(b"/jail")).unwrap(),
            b"/jailbreak"
        );
        assert_eq!(visible_cwd(b"/etc", Some(b"/jail")).unwrap(), b"/etc");
    }

    #[test]
    fn getcwd_leaves_an_escaped_cwd_unrouted() {
        let fs = TaskFs {
            cwd: TaskPath::new("/tmp/\u{ee41}".as_bytes()).unwrap(),
            root: None,
        };
        assert_eq!(fs.getcwd(), None);
        assert_eq!(TaskFs::default().getcwd(), Some(Ok(alloc::vec![b'/'])));
    }

    #[test]
    fn task_paths_are_absolute_and_bounded() {
        assert!(TaskPath::new(b"rel").is_none());
        assert!(TaskPath::new(b"").is_none());
        assert!(TaskPath::new(b"/a\0b").is_none());
        assert!(TaskPath::new(&alloc::vec![b'/'; ACCESS_MAX_PATH_BYTES + 1]).is_none());
    }

    /// Review #1409 (1): a uid-0 caller that dropped `CAP_DAC_OVERRIDE`
    /// must not be checked as a DAC-overriding root by the carrier, and a
    /// non-root caller holding it must not be checked without it: both are
    /// left unrouted (counted ENOSYS), so no file is opened at all.
    #[test]
    fn access_is_refused_when_capabilities_disagree_with_fsuid() {
        let fs = TaskFs::default();
        let mut out = Vec::new();
        let mut dropped = TaskCredentials::ROOT;
        dropped
            .cap_effective
            .remove(carrick_syscall_abi::LinuxCapabilitySet::CAP_DAC_OVERRIDE);
        assert_eq!(
            fs.encode_access(&dropped, 0o022, &mut out),
            Err(carrick_syscall_abi::LINUX_ENOSYS)
        );
        let mut privileged = TaskCredentials::ROOT;
        privileged.fsuid = crate::identity::TaskUid::new(1000);
        assert_eq!(
            fs.encode_access(&privileged, 0o022, &mut out),
            Err(carrick_syscall_abi::LINUX_ENOSYS)
        );
        assert!(out.is_empty(), "nothing was encoded for a refused caller");
        // Docker's default capability set (no CAP_DAC_READ_SEARCH) crosses
        // as root; so does a root missing only CAP_DAC_READ_SEARCH.
        let mut docker = TaskCredentials::ROOT;
        docker.cap_effective =
            carrick_syscall_abi::LinuxCapabilitySet::from_bits_retain(0xa804_25fb);
        assert!(fs.encode_access(&docker, 0o022, &mut out).is_ok());
        let mut no_fowner = TaskCredentials::ROOT;
        no_fowner
            .cap_effective
            .remove(carrick_syscall_abi::LinuxCapabilitySet::CAP_FOWNER);
        assert_eq!(
            fs.encode_access(&no_fowner, 0o022, &mut Vec::new()),
            Err(carrick_syscall_abi::LINUX_ENOSYS)
        );
        let mut read_search = TaskCredentials::ROOT;
        read_search.fsuid = crate::identity::TaskUid::new(1000);
        read_search.cap_effective = carrick_syscall_abi::LinuxCapabilitySet::CAP_DAC_READ_SEARCH;
        assert_eq!(
            fs.encode_access(&read_search, 0o022, &mut Vec::new()),
            Err(carrick_syscall_abi::LINUX_ENOSYS),
            "a non-root holding any file capability is not modelled"
        );
        // Root with every file capability, and a non-root with none, cross.
        assert!(
            fs.encode_access(&TaskCredentials::ROOT, 0o022, &mut out)
                .is_ok()
        );
        privileged.cap_effective = carrick_syscall_abi::LinuxCapabilitySet::empty();
        assert!(fs.encode_access(&privileged, 0o022, &mut out).is_ok());
    }

    #[test]
    fn encoded_access_carries_the_callers_own_values() {
        let mut credentials = TaskCredentials::ROOT;
        credentials.fsuid = crate::identity::TaskUid::new(1000);
        credentials.cap_effective = carrick_syscall_abi::LinuxCapabilitySet::empty();
        credentials.groups = alloc::vec![crate::identity::TaskGid::new(7)];
        credentials.groups_installed = true;
        let fs = TaskFs {
            cwd: TaskPath::new(b"/tmp/sub").unwrap(),
            root: None,
        };
        let mut bytes = Vec::new();
        fs.encode_access(&credentials, 0o7077, &mut bytes).unwrap();
        let (context, rest) = AccessContext::decode(&bytes).unwrap();
        assert_eq!(context.ids.fsuid, 1000);
        assert_eq!(context.umask, 0o077);
        assert_eq!(context.cwd, b"/tmp/sub");
        assert_eq!(context.groups().unwrap().collect::<Vec<_>>(), [7]);
        assert!(rest.is_empty());
        // `setgroups(0, NULL)`: an installed empty list, not launch groups.
        credentials.groups.clear();
        let mut bytes = Vec::new();
        fs.encode_access(&credentials, 0o022, &mut bytes).unwrap();
        let (context, _) = AccessContext::decode(&bytes).unwrap();
        assert_eq!(context.groups().map(|groups| groups.len()), Some(0));
        let mut bytes = Vec::new();
        fs.encode_access(&TaskCredentials::ROOT, 0o022, &mut bytes)
            .unwrap();
        let (context, _) = AccessContext::decode(&bytes).unwrap();
        assert!(context.groups().is_none(), "the launch identity's groups");
    }
}
