//! The Linux new mount API: `open_tree(2)`, `move_mount(2)`, `fsopen(2)`,
//! `fsconfig(2)`, `fsmount(2)`, `fspick(2)` and `mount_setattr(2)`.
//!
//! # Contract: the Docker oracle, not bare-metal Linux
//!
//! carrick's guest models a `docker run` container (see
//! [`crate::namespace::process::CapabilitySet::docker_default`]): the whole
//! family is gated on CAP_SYS_ADMIN exactly as Docker's default cap/seccomp
//! profile gates it, so a default-caps guest sees EPERM from every entry
//! point BEFORE any argument validation — byte-identical to the oracle
//! (`docker run alpine` gives `fsopen(NULL, bad_flags)` → EPERM, not
//! EINVAL/EFAULT, and LTP's `tst_fd.c` prints `TCONF: Skipping fsopen:
//! EPERM (1)`). Bare Linux would allow unprivileged non-CLONE `open_tree`;
//! the container contract does not, and the container is carrick's oracle.
//!
//! # With CAP_SYS_ADMIN (e.g. after `unshare(CLONE_NEWUSER)`)
//!
//! Argument validation, error ordering and the `fsconfig` staging state
//! machine follow the empirical `--cap-add SYS_ADMIN` oracle transcripts
//! (captured 2026-08-18, LinuxKit 7.0.12 arm64; see the probe matrix in the
//! unit tests below and `conformance-probes/src/bin/newmountapi.rs`):
//!
//!   * `fsopen`: flags checked before the fstype string is read
//!     (`fsopen(NULL, 0x10)` → EINVAL, `fsopen(NULL, 0)` → EFAULT); an
//!     unknown fstype → ENODEV. carrick's known-fs list is the same list
//!     `/proc/filesystems` advertises (self-consistency is the honest
//!     choice: carrick has no ext2 driver, so `fsopen("ext2", 0)` is ENODEV
//!     here where a real kernel with ext2 gives a context).
//!   * `fsconfig` ordering: `fd < 0` → EINVAL; unknown cmd → EOPNOTSUPP
//!     (yes, even on a closed fd); per-cmd key/value/aux shape → EINVAL;
//!     THEN the fd lookup → EBADF; a non-fscontext fd → EINVAL; state
//!     violations → EBUSY.
//!   * `fsmount`: flags and attr_flags are validated before the fd
//!     (`fsmount(-1, 0x100, 0)` → EINVAL, `fsmount(-1, 0, 0)` → EBADF), a
//!     context that has not been created → EINVAL.
//!   * `fspick`: flags before path (`fspick(AT_FDCWD, missing, 0x100)` →
//!     EINVAL), a path that is not the root of a mount → EINVAL.
//!   * `move_mount`: flags → source resolution (empty path without
//!     F_EMPTY_PATH → ENOENT) → target resolution → the move itself; a
//!     non-mount-root source → EINVAL; source `/` → ELOOP.
//!   * `mount_setattr`: flags → size (<32 → EINVAL) → copy-in (EFAULT /
//!     E2BIG on nonzero tail, `copy_struct_from_user` semantics) → attr-bit
//!     validation → and a fully-zero attr is a NO-OP that succeeds WITHOUT
//!     resolving the path (`mount_setattr(AT_FDCWD, missing, 0, {0}, 32)`
//!     → 0 on the oracle).
//!
//! # Honest deferrals (documented divergence, never fabricated success)
//!
//! carrick's VFS has no superblock lifecycle and no mount re-anchoring, so
//! the operations with guest-visible mount-table effects return EOPNOTSUPP
//! at exactly the step Linux would perform the effect:
//! `FSCONFIG_CMD_CREATE`/`CMD_RECONFIGURE`, an otherwise-valid `move_mount`
//! of a real mount, and a non-no-op `mount_setattr`. Consequently `fsmount`
//! can only ever see an un-created context (EINVAL), which is Linux's own
//! answer for that state. Two smaller divergences: staged `fsconfig` keys
//! are not validated against per-filesystem parameter tables (Linux's tmpfs
//! rejects an unknown key at SET_STRING time with EINVAL; carrick stages
//! it — rejection would have surfaced at the deferred CMD_CREATE), and
//! `read(2)` on a context fd (the kernel's error-log channel) is EINVAL.
//!
//! `open_tree` without OPEN_TREE_CLONE is semantically an `O_PATH` open of
//! the subtree root and lowers to carrick's existing open machinery (real
//! dirfd behaviour — fstat/openat-dirfd/readlink all agree). With
//! OPEN_TREE_CLONE the fd additionally represents a detached copy on Linux;
//! carrick has no mount topology to detach from, so the clone degrades to
//! the same O_PATH view (indistinguishable until a mount op mutates the
//! source tree, which carrick cannot express) and any later `move_mount` of
//! it lands in the EINVAL/EOPNOTSUPP paths above.

use super::*;
use crate::linux_abi::{
    FsconfigCmd, LINUX_AT_EMPTY_PATH, LINUX_AT_NO_AUTOMOUNT, LINUX_AT_RECURSIVE,
    LINUX_AT_SYMLINK_NOFOLLOW, LINUX_EBUSY, LINUX_ELOOP, LINUX_ENODEV, LINUX_EOPNOTSUPP,
    LINUX_EPERM, LINUX_FSMOUNT_CLOEXEC, LINUX_FSMOUNT_VALID_ATTRS, LINUX_FSOPEN_CLOEXEC,
    LINUX_FSPICK_EMPTY_PATH, LINUX_FSPICK_VALID_FLAGS, LINUX_MOUNT_ATTR_SIZE_VER0,
    LINUX_MOUNT_SETATTR_VALID_ATTRS, LINUX_MOVE_MOUNT_F_EMPTY_PATH, LINUX_MOVE_MOUNT_T_EMPTY_PATH,
    LINUX_MOVE_MOUNT_VALID_FLAGS, LINUX_OPEN_TREE_CLOEXEC, LINUX_OPEN_TREE_CLONE,
    LINUX_OPEN_TREE_VALID_FLAGS,
};

syscall_table! {
    /// Per-module routing for the new mount API. Chained from
    /// `resolve_handler` in `dispatch/mod.rs`. The numbers are the unified
    /// post-424 syscall space (identical on aarch64 and x86_64).
    pub(crate) fn dispatch_mount_api;
    428 => open_tree,
    429 => move_mount,
    430 => fsopen,
    431 => fsconfig,
    432 => fsmount,
    433 => fspick,
    442 => mount_setattr,
}

/// Filesystem types `fsopen(2)` recognises — kept in lockstep with the
/// `/proc/filesystems` the guest sees (`vfs::proc::synthetic_proc_filesystems`;
/// a unit test below pins the two together). Anything else is ENODEV.
const SUPPORTED_FS_TYPES: &[&str] = &["tmpfs", "proc", "sysfs", "overlay"];

/// What an fs context was opened FOR (fsopen → create a new superblock,
/// fspick → reconfigure an existing mount). Drives the EBUSY matrix for the
/// CMD_* commands: the oracle gives EBUSY for CMD_RECONFIGURE on a fresh
/// fsopen context and for CMD_CREATE on an fspick context.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FsContextPurpose {
    /// `fsopen(2)`: staging parameters toward FSCONFIG_CMD_CREATE.
    NewSuperblock,
    /// `fspick(2)`: staging parameters toward FSCONFIG_CMD_RECONFIGURE.
    Reconfigure,
}

/// One staged `fsconfig(2)` parameter. carrick stages rather than
/// interprets: the deferred CMD_CREATE/CMD_RECONFIGURE is where Linux would
/// consume these.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum StagedParam {
    /// FSCONFIG_SET_FLAG: a bare key ("ro").
    Flag(String),
    /// FSCONFIG_SET_STRING: key=value.
    String { key: String, value: String },
    /// FSCONFIG_SET_BINARY: key + payload length (payload bytes are not
    /// retained — no deferred consumer exists to read them).
    Binary { key: String, len: u64 },
    /// FSCONFIG_SET_PATH / SET_PATH_EMPTY: key + path (+ the aux dirfd).
    Path {
        key: String,
        path: String,
        dirfd: i32,
    },
    /// FSCONFIG_SET_FD: key + the supplied fd number.
    Fd { key: String, fd: i32 },
}

/// The staged-configuration state behind an [`OpenDescription::FsContext`].
/// Shared via `Arc` so `dup(2)`ed descriptors mutate one context (Linux
/// semantics). The phase machine is intentionally two-armed: carrick can
/// never reach "created" (CMD_CREATE is deferred), so the reachable states
/// are exactly `purpose × staging`.
#[derive(Debug)]
pub(crate) struct FsContextState {
    /// Filesystem type (fsopen) — `None` for an fspick context, which
    /// reconfigures whatever is mounted at `picked_path`.
    #[allow(dead_code)] // read by the (deferred) CMD_CREATE and by tests
    pub(crate) fs_type: Option<String>,
    /// The mount root an fspick context was opened against.
    #[allow(dead_code)] // read by future statfs/notification surfaces
    pub(crate) picked_path: Option<String>,
    pub(crate) purpose: FsContextPurpose,
    pub(crate) staged: Vec<StagedParam>,
}

impl FsContextState {
    pub(crate) fn new_superblock(fs_type: &str) -> Self {
        Self {
            fs_type: Some(fs_type.to_owned()),
            picked_path: None,
            purpose: FsContextPurpose::NewSuperblock,
            staged: Vec::new(),
        }
    }

    pub(crate) fn reconfigure(path: &str) -> Self {
        Self {
            fs_type: None,
            picked_path: Some(path.to_owned()),
            purpose: FsContextPurpose::Reconfigure,
            staged: Vec::new(),
        }
    }

    /// Apply one staged SET_* parameter.
    pub(crate) fn stage(&mut self, param: StagedParam) {
        self.staged.push(param);
    }

    /// Apply a CMD_* command per the oracle's EBUSY matrix, deferring the
    /// operation Linux would actually perform:
    ///   * CMD_CREATE/CMD_CREATE_EXCL on a `NewSuperblock` context is where
    ///     the superblock would be created → EOPNOTSUPP (deferred);
    ///     on a `Reconfigure` context → EBUSY (oracle `rctx_create`).
    ///   * CMD_RECONFIGURE on a `Reconfigure` context is where the remount
    ///     would apply → EOPNOTSUPP (deferred); on a fresh `NewSuperblock`
    ///     context → EBUSY (oracle `ctx2_reconfigure_uncreated`).
    pub(crate) fn apply_cmd(&self, cmd: FsconfigCmd) -> LinuxErrno {
        match (cmd, self.purpose) {
            (
                FsconfigCmd::CmdCreate | FsconfigCmd::CmdCreateExcl,
                FsContextPurpose::NewSuperblock,
            ) => LINUX_EOPNOTSUPP,
            (
                FsconfigCmd::CmdCreate | FsconfigCmd::CmdCreateExcl,
                FsContextPurpose::Reconfigure,
            ) => LINUX_EBUSY,
            (FsconfigCmd::CmdReconfigure, FsContextPurpose::Reconfigure) => LINUX_EOPNOTSUPP,
            (FsconfigCmd::CmdReconfigure, FsContextPurpose::NewSuperblock) => LINUX_EBUSY,
            // SET_* never reaches apply_cmd.
            _ => LINUX_EINVAL,
        }
    }
}

/// Per-command argument-shape validation for `fsconfig(2)` (fsconfig(2) man
/// page; EINVAL on violation). `key`/`value` are "is the pointer non-NULL";
/// this runs BEFORE the fd lookup (oracle: a closed fd with a bad shape
/// would be EINVAL, with a good shape EBADF).
fn fsconfig_shape_ok(cmd: FsconfigCmd, key: bool, value: bool, aux: i64) -> bool {
    match cmd {
        FsconfigCmd::SetFlag => key && !value && aux == 0,
        FsconfigCmd::SetString => key && value && aux == 0,
        FsconfigCmd::SetBinary => key && value && aux > 0,
        FsconfigCmd::SetPath | FsconfigCmd::SetPathEmpty => key && value,
        FsconfigCmd::SetFd => key && !value && aux >= 0,
        FsconfigCmd::CmdCreate | FsconfigCmd::CmdReconfigure | FsconfigCmd::CmdCreateExcl => {
            !key && !value && aux == 0
        }
    }
}

impl SyscallDispatcher {
    /// The Docker-container capability gate every entry point of the family
    /// shares: no CAP_SYS_ADMIN → EPERM before any argument validation
    /// (matching Docker's default profile, which EPERMs the whole family
    /// regardless of arguments).
    ///
    /// Reads the CALLING TASK's effective set through the shared
    /// [`super::creds::has_effective_capability`] helper rather than the
    /// process-global namespace store: under HVPatch one carrier hosts many
    /// Linux processes, so "which caps" is a property of `cx.kernel`'s task,
    /// not of the host process (`docs/identity-and-scope-domains.md`). A guest
    /// that setuid'd away from root has dropped the capability and must get
    /// EPERM even though a sibling task still holds it.
    fn mount_api_permitted(&self, kernel: &crate::kernel::KernelContext) -> bool {
        super::creds::has_effective_capability(kernel, crate::namespace::process::CAP_SYS_ADMIN)
    }

    /// True iff `path` is the root of a mount in carrick's model: the rootfs
    /// root itself, or a registered VFS mount point (/proc, /sys, /dev, …).
    fn is_mount_root(&self, path: &str) -> bool {
        if path == "/" {
            return true;
        }
        self.fs.vfs_mounts.has_mount_at(std::path::Path::new(path))
    }

    /// Resolve a (dirfd, path, empty-path-allowed) triple to an absolute,
    /// existing guest path, with the family's shared error shapes: an empty
    /// path without the respective *_EMPTY_PATH flag → ENOENT; with it, the
    /// dirfd itself is the object (AT_FDCWD → the cwd).
    fn mount_api_resolve(
        &self,
        dirfd: u64,
        path: &str,
        empty_ok: bool,
    ) -> Result<String, LinuxErrno> {
        let resolved = if path.is_empty() {
            if !empty_ok {
                return Err(LINUX_ENOENT);
            }
            self.openat2_anchor_for_dirfd(dirfd)?
        } else {
            self.resolve_at_path(dirfd, path)?
        };
        // The object must exist (ENOENT), whatever kind it is.
        self.layered_metadata(&resolved).map_err(|_| LINUX_ENOENT)?;
        Ok(resolved)
    }

    define_syscall! {
        /// fsopen(fs_name, flags) — open a filesystem context for creating a
        /// new superblock. Validation order per the oracle: flags → fs_name
        /// copy (EFAULT) → known-fs check (ENODEV). Success is an
        /// `FsContext` anon fd staging toward the (deferred) CMD_CREATE.
        fn fsopen(this, cx, fs_name: GuestPtr, flags: u64) {
            if !this.mount_api_permitted(cx.kernel) {
                return Ok(DispatchOutcome::errno(LINUX_EPERM));
            }
            if flags & !LINUX_FSOPEN_CLOEXEC != 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let name = match read_guest_c_string(&*cx.memory, fs_name.0) {
                Ok(s) => s,
                Err(errno) => return Ok(DispatchOutcome::errno(errno)),
            };
            if !SUPPORTED_FS_TYPES.contains(&name.as_str()) {
                return Ok(DispatchOutcome::errno(LINUX_ENODEV));
            }
            let description = OpenDescription::FsContext {
                base: OpenDescriptionBase::new(0),
                state: Arc::new(Mutex::new(FsContextState::new_superblock(&name))),
            };
            let fd_flags = if flags & LINUX_FSOPEN_CLOEXEC != 0 {
                crate::linux_abi::LINUX_FD_CLOEXEC
            } else {
                0
            };
            Ok(this.install_fd(description, fd_flags))
        }

        /// fsconfig(fd, cmd, key, value, aux) — stage a parameter into (or
        /// issue a command against) a filesystem context. Error ordering is
        /// the oracle's exactly; see the module doc.
        fn fsconfig(this, cx, fd: Fd, cmd: u64, key: GuestPtr, value: GuestPtr, aux: u64) {
            if !this.mount_api_permitted(cx.kernel) {
                return Ok(DispatchOutcome::errno(LINUX_EPERM));
            }
            // (1) A negative fd is EINVAL — before the command switch
            //     (oracle: fsconfig(-1, 100, …) is EINVAL, not EOPNOTSUPP).
            if fd.0 < 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            // (2) Unknown command → EOPNOTSUPP — before the fd lookup
            //     (oracle: fsconfig(closed_fd, 100, …) is EOPNOTSUPP).
            let Some(cmd) = FsconfigCmd::from_raw(cmd) else {
                return Ok(DispatchOutcome::errno(LINUX_EOPNOTSUPP));
            };
            // (3) Per-command pointer/aux shape → EINVAL.
            let aux = aux as i64;
            if !fsconfig_shape_ok(cmd, key.0 != 0, value.0 != 0, aux) {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            // (4) Copy the strings in (EFAULT on a bad pointer).
            let key_str = if key.0 != 0 {
                match read_guest_c_string(&*cx.memory, key.0) {
                    Ok(s) => Some(s),
                    Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                }
            } else {
                None
            };
            let value_str = match cmd {
                FsconfigCmd::SetString | FsconfigCmd::SetPath | FsconfigCmd::SetPathEmpty => {
                    match read_guest_c_string(&*cx.memory, value.0) {
                        Ok(s) => Some(s),
                        Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                    }
                }
                _ => None,
            };
            // (5) The fd lookup (EBADF), then the fscontext check (EINVAL).
            // A bare stdio fd (0/1/2, not reopened) has no open_files entry
            // but IS a valid non-fscontext fd → EINVAL, not EBADF (same
            // stdio-fd trap the dirfdnotdir probe pinned for fstatat).
            let Some(open_file) = this.open_file(fd.0) else {
                return Ok(DispatchOutcome::errno(if this.fd_is_valid(fd.0) {
                    LINUX_EINVAL
                } else {
                    LINUX_EBADF
                }));
            };
            let description = open_file.description.read();
            let OpenDescription::FsContext { state, .. } = &*description else {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            };
            let mut state = state.lock();
            // (6) Stage or command.
            match cmd {
                FsconfigCmd::SetFlag => {
                    state.stage(StagedParam::Flag(key_str.unwrap_or_default()));
                }
                FsconfigCmd::SetString => {
                    state.stage(StagedParam::String {
                        key: key_str.unwrap_or_default(),
                        value: value_str.unwrap_or_default(),
                    });
                }
                FsconfigCmd::SetBinary => {
                    // Payload readability check only (EFAULT), then stage the
                    // length — nothing deferred ever consumes the bytes.
                    if (*cx.memory).read_bytes(value.0, aux as usize).is_err() {
                        return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                    }
                    state.stage(StagedParam::Binary {
                        key: key_str.unwrap_or_default(),
                        len: aux as u64,
                    });
                }
                FsconfigCmd::SetPath | FsconfigCmd::SetPathEmpty => {
                    state.stage(StagedParam::Path {
                        key: key_str.unwrap_or_default(),
                        path: value_str.unwrap_or_default(),
                        dirfd: aux as i32,
                    });
                }
                FsconfigCmd::SetFd => {
                    if !this.fd_is_valid(aux as i32) {
                        return Ok(DispatchOutcome::errno(LINUX_EBADF));
                    }
                    state.stage(StagedParam::Fd {
                        key: key_str.unwrap_or_default(),
                        fd: aux as i32,
                    });
                }
                FsconfigCmd::CmdCreate
                | FsconfigCmd::CmdReconfigure
                | FsconfigCmd::CmdCreateExcl => {
                    return Ok(DispatchOutcome::errno(state.apply_cmd(cmd)));
                }
            }
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        /// fsmount(fd, flags, attr_flags) — turn a CREATED context into a
        /// detached mount fd. Ordering per the oracle: flags → attr_flags →
        /// fd (EBADF) → fscontext (EINVAL) → created? (EINVAL). carrick
        /// contexts never reach "created" (CMD_CREATE is deferred), so the
        /// terminal answer for a real context is Linux's own not-yet-created
        /// EINVAL — success is unreachable, never fabricated.
        fn fsmount(this, cx, fd: Fd, flags: u64, attr_flags: u64) {
            if !this.mount_api_permitted(cx.kernel) {
                return Ok(DispatchOutcome::errno(LINUX_EPERM));
            }
            if flags & !LINUX_FSMOUNT_CLOEXEC != 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            if attr_flags & !LINUX_FSMOUNT_VALID_ATTRS != 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            // A bare stdio fd is valid-but-not-fscontext → EINVAL (see
            // fsconfig's step 5).
            let Some(open_file) = this.open_file(fd.0) else {
                return Ok(DispatchOutcome::errno(if this.fd_is_valid(fd.0) {
                    LINUX_EINVAL
                } else {
                    LINUX_EBADF
                }));
            };
            let description = open_file.description.read();
            if !matches!(&*description, OpenDescription::FsContext { .. }) {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            // A carrick context is never in the created state (module doc).
            Ok(DispatchOutcome::errno(LINUX_EINVAL))
        }

        /// fspick(dirfd, path, flags) — open a filesystem context targeting
        /// an EXISTING mount for reconfiguration. Ordering per the oracle:
        /// flags → path copy (EFAULT) → resolution (ENOENT) → must be a
        /// mount root (EINVAL).
        fn fspick(this, cx, dirfd: u64, path: GuestPtr, flags: u64) {
            if !this.mount_api_permitted(cx.kernel) {
                return Ok(DispatchOutcome::errno(LINUX_EPERM));
            }
            if flags & !LINUX_FSPICK_VALID_FLAGS != 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let path = match read_guest_c_string(&*cx.memory, path.0) {
                Ok(s) => s,
                Err(errno) => return Ok(DispatchOutcome::errno(errno)),
            };
            let resolved = match this.mount_api_resolve(
                dirfd,
                &path,
                flags & LINUX_FSPICK_EMPTY_PATH != 0,
            ) {
                Ok(p) => p,
                Err(errno) => return Ok(DispatchOutcome::errno(errno)),
            };
            if !this.is_mount_root(&resolved) {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let description = OpenDescription::FsContext {
                base: OpenDescriptionBase::new(0),
                state: Arc::new(Mutex::new(FsContextState::reconfigure(&resolved))),
            };
            let fd_flags = if flags & crate::linux_abi::LINUX_FSPICK_CLOEXEC != 0 {
                crate::linux_abi::LINUX_FD_CLOEXEC
            } else {
                0
            };
            Ok(this.install_fd(description, fd_flags))
        }

        /// open_tree(dirfd, path, flags) — an O_PATH-style handle on a
        /// subtree. Ordering per the oracle: flags (incl. AT_RECURSIVE
        /// requiring OPEN_TREE_CLONE) → path (empty without AT_EMPTY_PATH →
        /// ENOENT; bad dirfd → EBADF; missing → ENOENT). Lowered onto the
        /// existing open machinery as an O_PATH open, which is exactly the
        /// non-CLONE semantics; the CLONE degradation is in the module doc.
        fn open_tree(this, cx, dirfd: u64, path: GuestPtr, flags: u64) {
            if !this.mount_api_permitted(cx.kernel) {
                return Ok(DispatchOutcome::errno(LINUX_EPERM));
            }
            if flags & !LINUX_OPEN_TREE_VALID_FLAGS != 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            if flags & LINUX_AT_RECURSIVE != 0 && flags & LINUX_OPEN_TREE_CLONE == 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let path = match read_guest_c_string(&*cx.memory, path.0) {
                Ok(s) => s,
                Err(errno) => return Ok(DispatchOutcome::errno(errno)),
            };
            let resolved = match this.mount_api_resolve(
                dirfd,
                &path,
                flags & LINUX_AT_EMPTY_PATH != 0,
            ) {
                Ok(p) => p,
                Err(errno) => return Ok(DispatchOutcome::errno(errno)),
            };
            let mut open_flags = crate::linux_abi::LINUX_O_PATH;
            if flags & LINUX_AT_SYMLINK_NOFOLLOW != 0 {
                open_flags |= crate::linux_abi::LINUX_O_NOFOLLOW;
            }
            if flags & LINUX_OPEN_TREE_CLOEXEC != 0 {
                open_flags |= crate::linux_abi::LINUX_O_CLOEXEC;
            }
            let _ = LINUX_AT_NO_AUTOMOUNT; // accepted, no automounts to inhibit
            this.open_at_path_string(
                cx.kernel,
                cx.thread.as_ref().map(|thread| thread.registry),
                crate::linux_abi::LINUX_AT_FDCWD,
                &resolved,
                open_flags,
                0,
                cx.reporter,
            )
        }

        /// move_mount(from_dirfd, from_path, to_dirfd, to_path, flags).
        /// Ordering per the oracle: flags → source resolution → target
        /// resolution → the move. A source that is not a mount root →
        /// EINVAL; the root itself → ELOOP; a real carrick mount root →
        /// EOPNOTSUPP (re-anchoring a VFS mount is deferred — the move IS
        /// the guest-visible effect and is never fabricated).
        fn move_mount(this, cx, from_dirfd: u64, from_path: GuestPtr, to_dirfd: u64, to_path: GuestPtr, flags: u64) {
            if !this.mount_api_permitted(cx.kernel) {
                return Ok(DispatchOutcome::errno(LINUX_EPERM));
            }
            if flags & !LINUX_MOVE_MOUNT_VALID_FLAGS != 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let from_path = match read_guest_c_string(&*cx.memory, from_path.0) {
                Ok(s) => s,
                Err(errno) => return Ok(DispatchOutcome::errno(errno)),
            };
            let from = match this.mount_api_resolve(
                from_dirfd,
                &from_path,
                flags & LINUX_MOVE_MOUNT_F_EMPTY_PATH != 0,
            ) {
                Ok(p) => p,
                Err(errno) => return Ok(DispatchOutcome::errno(errno)),
            };
            let to_path = match read_guest_c_string(&*cx.memory, to_path.0) {
                Ok(s) => s,
                Err(errno) => return Ok(DispatchOutcome::errno(errno)),
            };
            if let Err(errno) = this.mount_api_resolve(
                to_dirfd,
                &to_path,
                flags & LINUX_MOVE_MOUNT_T_EMPTY_PATH != 0,
            ) {
                return Ok(DispatchOutcome::errno(errno));
            }
            if !this.is_mount_root(&from) {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            if from == "/" {
                // Moving the root of the namespace under itself (oracle: ELOOP).
                return Ok(DispatchOutcome::errno(LINUX_ELOOP));
            }
            // A real mount root: the move itself is deferred (module doc).
            Ok(DispatchOutcome::errno(LINUX_EOPNOTSUPP))
        }

        /// mount_setattr(dirfd, path, flags, uattr, usize). Ordering per the
        /// oracle: flags → size → copy-in (EFAULT / E2BIG tail) → attr-bit
        /// validation → NO-OP short-circuit (a fully-zero attr succeeds
        /// without resolving the path) → path resolution → the (deferred)
        /// application.
        fn mount_setattr(this, cx, dirfd: u64, path: GuestPtr, flags: u64, uattr: GuestPtr, size: u64) {
            if !this.mount_api_permitted(cx.kernel) {
                return Ok(DispatchOutcome::errno(LINUX_EPERM));
            }
            const VALID_FLAGS: u64 = LINUX_AT_EMPTY_PATH
                | LINUX_AT_RECURSIVE
                | LINUX_AT_SYMLINK_NOFOLLOW
                | LINUX_AT_NO_AUTOMOUNT;
            if flags & !VALID_FLAGS != 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            if size < LINUX_MOUNT_ATTR_SIZE_VER0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            // copy_struct_from_user: the known 32 bytes must be readable
            // (EFAULT); any tail must be readable AND zero (EFAULT/E2BIG) —
            // same contract as openat2's open_how.
            let attr = match (*cx.memory).read_bytes(uattr.0, LINUX_MOUNT_ATTR_SIZE_VER0 as usize) {
                Ok(b) => b,
                Err(_) => return Ok(DispatchOutcome::errno(LINUX_EFAULT)),
            };
            if size > LINUX_MOUNT_ATTR_SIZE_VER0 {
                let tail_len = (size - LINUX_MOUNT_ATTR_SIZE_VER0) as usize;
                match (*cx.memory).read_bytes(uattr.0 + LINUX_MOUNT_ATTR_SIZE_VER0, tail_len) {
                    Ok(tail) => {
                        if tail.iter().any(|&b| b != 0) {
                            return Ok(DispatchOutcome::errno(crate::linux_abi::LINUX_E2BIG));
                        }
                    }
                    Err(_) => return Ok(DispatchOutcome::errno(LINUX_EFAULT)),
                }
            }
            let word = |i: usize| {
                let mut b = [0u8; 8];
                b.copy_from_slice(&attr[i * 8..i * 8 + 8]);
                u64::from_le_bytes(b)
            };
            let (attr_set, attr_clr, propagation, userns_fd) =
                (word(0), word(1), word(2), word(3));
            if attr_set & !LINUX_MOUNT_SETATTR_VALID_ATTRS != 0
                || attr_clr & !LINUX_MOUNT_SETATTR_VALID_ATTRS != 0
            {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            // A fully-zero attr is a no-op that succeeds WITHOUT path
            // resolution (oracle: mount_setattr(AT_FDCWD, missing, 0, {0},
            // 32) → 0).
            if attr_set == 0 && attr_clr == 0 && propagation == 0 && userns_fd == 0 {
                return Ok(DispatchOutcome::Returned { value: 0 });
            }
            let path = match read_guest_c_string(&*cx.memory, path.0) {
                Ok(s) => s,
                Err(errno) => return Ok(DispatchOutcome::errno(errno)),
            };
            if let Err(errno) = this.mount_api_resolve(
                dirfd,
                &path,
                flags & LINUX_AT_EMPTY_PATH != 0,
            ) {
                return Ok(DispatchOutcome::errno(errno));
            }
            // Applying real attribute changes to a mount is deferred
            // (module doc): carrick's mounts carry no per-mount attr state,
            // and claiming to have changed them would be fabricated success.
            Ok(DispatchOutcome::errno(LINUX_EOPNOTSUPP))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// fsopen's ENODEV list must be exactly what the guest's
    /// /proc/filesystems advertises — the two surfaces answering "which
    /// filesystems exist" may never drift apart.
    #[test]
    fn supported_fs_types_match_proc_filesystems() {
        let proc_list =
            String::from_utf8_lossy(crate::vfs::proc::synthetic_proc_filesystems()).to_string();
        let proc_names: Vec<&str> = proc_list
            .lines()
            .filter_map(|l| l.split('\t').next_back())
            .collect();
        for fs in SUPPORTED_FS_TYPES {
            assert!(
                proc_names.contains(fs),
                "{fs} not advertised in /proc/filesystems"
            );
        }
        for name in &proc_names {
            assert!(
                SUPPORTED_FS_TYPES.contains(name),
                "/proc/filesystems advertises {name} but fsopen would ENODEV it"
            );
        }
    }

    // --- fsconfig shape matrix (oracle transcripts 2026-08-18) ---

    #[test]
    fn shape_set_flag_requires_bare_key() {
        assert!(fsconfig_shape_ok(FsconfigCmd::SetFlag, true, false, 0));
        // fsconfig_nullkey_regfd → EINVAL
        assert!(!fsconfig_shape_ok(FsconfigCmd::SetFlag, false, false, 0));
        // fsconfig_setflag_badvalue_regfd → EINVAL
        assert!(!fsconfig_shape_ok(FsconfigCmd::SetFlag, true, true, 0));
        // fsconfig_setflag_badaux_regfd → EINVAL
        assert!(!fsconfig_shape_ok(FsconfigCmd::SetFlag, true, false, 1));
    }

    #[test]
    fn shape_set_string_requires_key_and_value() {
        assert!(fsconfig_shape_ok(FsconfigCmd::SetString, true, true, 0));
        // fsconfig_setstring_nullvalue_regfd → EINVAL
        assert!(!fsconfig_shape_ok(FsconfigCmd::SetString, true, false, 0));
        assert!(!fsconfig_shape_ok(FsconfigCmd::SetString, true, true, 1));
    }

    #[test]
    fn shape_set_binary_requires_positive_aux() {
        assert!(fsconfig_shape_ok(FsconfigCmd::SetBinary, true, true, 16));
        // ctx_setbinary_nullvalue → EINVAL
        assert!(!fsconfig_shape_ok(FsconfigCmd::SetBinary, true, false, 1));
        assert!(!fsconfig_shape_ok(FsconfigCmd::SetBinary, true, true, 0));
    }

    #[test]
    fn shape_set_fd_rejects_negative_aux() {
        assert!(fsconfig_shape_ok(FsconfigCmd::SetFd, true, false, 5));
        // ctx_setfd_badaux (aux = -1) → EINVAL
        assert!(!fsconfig_shape_ok(FsconfigCmd::SetFd, true, false, -1));
        assert!(!fsconfig_shape_ok(FsconfigCmd::SetFd, true, true, 5));
    }

    #[test]
    fn shape_commands_take_no_arguments() {
        for cmd in [
            FsconfigCmd::CmdCreate,
            FsconfigCmd::CmdReconfigure,
            FsconfigCmd::CmdCreateExcl,
        ] {
            assert!(fsconfig_shape_ok(cmd, false, false, 0));
            assert!(!fsconfig_shape_ok(cmd, true, false, 0));
            assert!(!fsconfig_shape_ok(cmd, false, true, 0));
            assert!(!fsconfig_shape_ok(cmd, false, false, 1));
        }
    }

    // --- context state machine (oracle: ctx_*/rctx_* rows) ---

    #[test]
    fn new_superblock_context_stages_then_defers_create() {
        let mut st = FsContextState::new_superblock("tmpfs");
        assert_eq!(st.fs_type.as_deref(), Some("tmpfs"));
        assert_eq!(st.picked_path, None);
        st.stage(StagedParam::Flag("ro".into()));
        st.stage(StagedParam::String {
            key: "mode".into(),
            value: "0700".into(),
        });
        assert_eq!(st.staged.len(), 2);
        // ctx_create: the superblock creation itself is carrick's deferral.
        assert_eq!(st.apply_cmd(FsconfigCmd::CmdCreate), LINUX_EOPNOTSUPP);
        // ctx2_reconfigure_uncreated → EBUSY.
        assert_eq!(st.apply_cmd(FsconfigCmd::CmdReconfigure), LINUX_EBUSY);
    }

    #[test]
    fn reconfigure_context_defers_reconfigure_and_refuses_create() {
        let st = FsContextState::reconfigure("/proc");
        // rctx_create → EBUSY.
        assert_eq!(st.apply_cmd(FsconfigCmd::CmdCreate), LINUX_EBUSY);
        assert_eq!(st.apply_cmd(FsconfigCmd::CmdCreateExcl), LINUX_EBUSY);
        // rctx_reconfigure is where Linux applies the remount — deferred.
        assert_eq!(st.apply_cmd(FsconfigCmd::CmdReconfigure), LINUX_EOPNOTSUPP);
    }

    #[test]
    fn fsconfig_cmd_round_trips_known_range_and_rejects_unknown() {
        for raw in 0..=8u64 {
            assert!(FsconfigCmd::from_raw(raw).is_some());
        }
        assert!(FsconfigCmd::from_raw(9).is_none());
        assert!(FsconfigCmd::from_raw(100).is_none());
    }
}
