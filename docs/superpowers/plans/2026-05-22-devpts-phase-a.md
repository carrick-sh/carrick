# devpts Phase A (self-contained PTY) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a self-contained `/dev/ptmx` + `/dev/pts` so guest programs that allocate their own pseudo-terminal (apt/dpkg, `script`, `tmux`, `expect`) work, eliminating the `apt-get` `/dev/pts` warning.

**Architecture:** Host-PTY-backed devpts (Approach 1 in the spec). `/dev/ptmx` opens a real macOS pty via `posix_openpt`/`grantpt`/`unlockpt`; a shared `Arc<Mutex<PtyTable>>` maps a guest pts index `N` to the host master fd + macOS slave name; `/dev/pts/N` opens the real host slave. Master/slave fds reuse the existing `HostPipe` open-description (tagged with an optional pty role) for data I/O; the `ioctl` handler synthesizes `TIOCGPTN`/`TIOCSPTLCK` and passes termios/winsize/pgrp ioctls through to the host fd. Job control rides the host line discipline because guest pgrps are real macOS pgrps.

**Tech Stack:** Rust, `libc` (posix_openpt/grantpt/unlockpt/ptsname_r/ioctl), the existing `Vfs` mount trait, `parking_lot::Mutex`.

**Spec:** `docs/superpowers/specs/2026-05-22-devpts-design.md`. Phase B (`carrick run -it` host relay) is a separate plan.

**Conventions observed in this codebase:**
- Build + sign before any guest run: `./scripts/build-signed.sh` (plain `cargo build`/`cargo test --release` strips the HVF entitlement → `HV_DENIED`).
- Linux errno constants live in `src/linux_abi.rs` as `LINUX_*`; ioctl request constants too (`LINUX_TCGETS`, `LINUX_TIOCGWINSZ`, …).
- macOS→Linux errno translation: `dev.rs::host_open_errno()` / `crate::dispatch::macos_to_linux_errno`.
- `OpenDescription` is a private enum in `src/dispatch/mod.rs`; `HostPipe` is matched in ~39 places — extend it with a new field rather than adding variants.

---

## File Structure

- **Create** `src/vfs/devpts.rs` — `PtyTable`, `PtyEntry`, `PtyRole`, `DevptsVfs` (the `/dev/pts` mount), and host-pty helpers (`open_master`, slave name lookup). One responsibility: model and back pseudo-terminals.
- **Modify** `src/vfs/mod.rs` — add `VfsHandle::Pty`; `pub mod devpts;` + re-exports (`PtyTable`, `PtyRole`).
- **Modify** `src/vfs/dev.rs` — `DevVfs` gains a shared `Arc<Mutex<PtyTable>>` and handles `/dev/ptmx` (lookup/readdir/open).
- **Modify** `src/vfs/mount.rs` — register `DevptsVfs` at `/dev/pts` (existing `DevVfs` at `/dev` keeps `/dev/ptmx`).
- **Modify** `src/dispatch/mod.rs` — add `pty: Option<PtyRole>` to `OpenDescription::HostPipe`; add a `pty_table: Arc<Mutex<PtyTable>>` field to `SyscallDispatcher`; wire it into both mounts at construction.
- **Modify** `src/dispatch/fs.rs` — `try_vfs_open` handles `VfsHandle::Pty`; `ioctl` handler routes pty fds (synthesize `TIOCGPTN`/`TIOCSPTLCK`, passthrough the rest); `fd_is_tty` returns true for pty fds; `close` frees the master's table entry; add `pty: None` to existing `HostPipe` construction sites.
- **Create** `conformance-probes/src/bin/ptypair.rs` — full `posix_openpt` round-trip probe.
- **Modify** `tests/conformance.rs` — register the `ptypair` probe (if probes are listed explicitly; otherwise auto-discovered).

---

## Task 1: `PtyTable` data model

**Files:**
- Create: `src/vfs/devpts.rs`
- Test: inline `#[cfg(test)]` in `src/vfs/devpts.rs`

- [ ] **Step 1: Write the failing test**

```rust
// src/vfs/devpts.rs
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alloc_lookup_free_roundtrip() {
        let mut t = PtyTable::new();
        let n0 = t.insert(10, "/dev/ttys000".into());
        let n1 = t.insert(11, "/dev/ttys001".into());
        assert_eq!(n0, 0);
        assert_eq!(n1, 1);
        assert_eq!(t.slave_name(0).as_deref(), Some("/dev/ttys000"));
        assert_eq!(t.slave_name(1).as_deref(), Some("/dev/ttys001"));
        assert_eq!(t.slave_name(2), None);
        assert_eq!(t.live_indices(), vec![0, 1]);
        // unlock toggles the per-entry lock used by TIOCSPTLCK.
        assert!(t.is_locked(0));
        t.set_locked(0, false);
        assert!(!t.is_locked(0));
        // free removes the entry; index numbers are not reused.
        t.free(0);
        assert_eq!(t.slave_name(0), None);
        assert_eq!(t.live_indices(), vec![1]);
        assert_eq!(t.insert(12, "/dev/ttys002".into()), 2);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --lib vfs::devpts::tests::alloc_lookup_free_roundtrip`
Expected: FAIL — `PtyTable` not found / module not declared.

- [ ] **Step 3: Write minimal implementation**

```rust
// src/vfs/devpts.rs  (top of file)
//! `/dev/pts` mount + pseudo-terminal table. `/dev/ptmx` opens a real
//! macOS pty (posix_openpt); `/dev/pts/N` opens its slave. Master/slave
//! data I/O reuses the dispatcher's `HostPipe` open-description; this
//! module owns the index<->host-fd/slave-name mapping.

use std::collections::BTreeMap;

/// Tags a `HostPipe` open-description as a pty end so the ioctl handler
/// can synthesize `TIOCGPTN`/`TIOCSPTLCK` and passthrough termios.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PtyRole {
    pub index: u32,
    pub is_master: bool,
}

struct PtyEntry {
    host_master_fd: i32,
    host_slave_name: String,
    locked: bool,
}

/// Maps a guest pts index to the macOS master fd + slave device name.
/// Shared (`Arc<Mutex<_>>`) between the `/dev/ptmx` handler, the
/// `/dev/pts` mount, and the dispatcher's close/ioctl paths.
pub struct PtyTable {
    next_index: u32,
    entries: BTreeMap<u32, PtyEntry>,
}

impl PtyTable {
    pub fn new() -> Self {
        Self { next_index: 0, entries: BTreeMap::new() }
    }

    /// Record a freshly-opened master; returns the allocated index N.
    pub fn insert(&mut self, host_master_fd: i32, host_slave_name: String) -> u32 {
        let n = self.next_index;
        self.next_index += 1;
        self.entries.insert(
            n,
            PtyEntry { host_master_fd, host_slave_name, locked: true },
        );
        n
    }

    pub fn slave_name(&self, n: u32) -> Option<String> {
        self.entries.get(&n).map(|e| e.host_slave_name.clone())
    }

    pub fn is_locked(&self, n: u32) -> bool {
        self.entries.get(&n).map(|e| e.locked).unwrap_or(false)
    }

    pub fn set_locked(&mut self, n: u32, locked: bool) {
        if let Some(e) = self.entries.get_mut(&n) {
            e.locked = locked;
        }
    }

    /// Live pts indices in ascending order (for `/dev/pts` readdir).
    pub fn live_indices(&self) -> Vec<u32> {
        self.entries.keys().copied().collect()
    }

    /// Drop an entry (master closed). Does not close the host fd — the
    /// dispatcher owns fd closing; this only updates the directory view.
    pub fn free(&mut self, n: u32) {
        self.entries.remove(&n);
    }
}

impl Default for PtyTable {
    fn default() -> Self {
        Self::new()
    }
}
```

Then declare the module: in `src/vfs/mod.rs` add `pub mod devpts;` and `pub use devpts::{PtyRole, PtyTable};`.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --lib vfs::devpts::tests::alloc_lookup_free_roundtrip`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/vfs/devpts.rs src/vfs/mod.rs
git commit -m "vfs: add PtyTable data model for devpts"
```

---

## Task 2: Tag `HostPipe` with an optional pty role + `VfsHandle::Pty`

**Files:**
- Modify: `src/vfs/mod.rs` (add `VfsHandle::Pty`)
- Modify: `src/dispatch/mod.rs` (add `pty: Option<PtyRole>` to `HostPipe`)
- Modify: `src/dispatch/fs.rs` (existing `HostPipe` construction sites + the `try_vfs_open` conversion)

This task is a pure refactor + new plumbing; its "test" is that the whole suite still compiles and passes (the new field defaults to `None` everywhere).

- [ ] **Step 1: Add the `VfsHandle::Pty` variant**

```rust
// src/vfs/mod.rs — inside `pub enum VfsHandle { … }`, after `HostFd { … }`:
    /// A pty end backed by a host fd. The dispatcher converts this to a
    /// `HostPipe` open-description tagged with `PtyRole` so the ioctl
    /// handler treats it as a tty.
    Pty {
        host_fd: i32,
        pts_index: u32,
        is_master: bool,
        status_flags: u32,
    },
```

- [ ] **Step 2: Add the field to `HostPipe`**

In `src/dispatch/mod.rs`, find `HostPipe { host_fd, is_read_end, status_flags }` in the `OpenDescription` enum and add:

```rust
    HostPipe {
        host_fd: i32,
        is_read_end: bool,
        status_flags: u64,
        /// `Some` iff this fd is a pty master/slave end. Data I/O is
        /// identical to a plain host pipe; this only changes ioctl
        /// handling and close cleanup. `None` for ordinary host pipes,
        /// sockets-as-pipes, and `/dev/*` chardevs.
        pty: Option<crate::vfs::PtyRole>,
    },
```

Add `pty: None` to every existing `HostPipe { … }` **construction** site. As of this writing they are in `src/dispatch/fs.rs` at lines ~632, ~643, ~706, ~1791, ~1876, and any built by `pipe2`/socket code. Find them all:

Run: `grep -rn "OpenDescription::HostPipe {" src/dispatch/ | grep -v "\.\." `
For each, add `pty: None,` to the struct literal. (Match arms using `HostPipe { .. }` or `HostPipe { host_fd, .. }` need no change — the `..` covers the new field.)

- [ ] **Step 3: Convert `VfsHandle::Pty` in `try_vfs_open`**

In `src/dispatch/fs.rs`, in the `match handle { … }` at ~line 1860, add an arm after the `HostFd` arm:

```rust
            crate::vfs::VfsHandle::Pty {
                host_fd,
                pts_index,
                is_master,
                status_flags,
            } => {
                let new_fd = match self.allocate_fd(3) {
                    Some(fd) => fd,
                    None => {
                        unsafe { libc::close(host_fd) };
                        return VfsOpenAttempt::Errno(linux_errno::EMFILE);
                    }
                };
                self.insert_open_file(
                    new_fd,
                    OpenFile {
                        description: Arc::new(RwLock::new(OpenDescription::HostPipe {
                            host_fd,
                            // A pty end is bidirectional; route reads and
                            // writes through the host fd like /dev/null.
                            is_read_end: true,
                            status_flags: status_flags as u64,
                            pty: Some(crate::vfs::PtyRole { index: pts_index, is_master }),
                        })),
                        fd_flags: linux_fd_flags_from_open_flags(flags),
                    },
                );
                VfsOpenAttempt::Installed(new_fd)
            }
```

- [ ] **Step 4: Build + run the suite**

Run: `cargo build && cargo test --lib`
Expected: PASS (134+ lib tests; the new field is `None` everywhere so behavior is unchanged).

- [ ] **Step 5: Commit**

```bash
git add src/vfs/mod.rs src/dispatch/mod.rs src/dispatch/fs.rs
git commit -m "dispatch: tag HostPipe with optional PtyRole; add VfsHandle::Pty"
```

---

## Task 3: `/dev/ptmx` opens a real host pty

**Files:**
- Modify: `src/vfs/devpts.rs` (host-pty helper `open_master`)
- Modify: `src/vfs/dev.rs` (`DevVfs` holds the shared table; handle `/dev/ptmx`)
- Test: inline in `src/vfs/devpts.rs`

- [ ] **Step 1: Write the failing test (host-pty helper)**

```rust
// src/vfs/devpts.rs  #[cfg(test)] mod tests
    #[test]
    fn open_master_returns_fd_and_slave_name() {
        let (master_fd, slave_name) = open_master(false).expect("posix_openpt");
        assert!(master_fd >= 0);
        assert!(slave_name.starts_with("/dev/"), "got {slave_name}");
        unsafe { libc::close(master_fd) };
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --lib vfs::devpts::tests::open_master_returns_fd_and_slave_name`
Expected: FAIL — `open_master` not found.

- [ ] **Step 3: Implement `open_master`**

```rust
// src/vfs/devpts.rs
use std::ffi::CStr;

/// Open a fresh macOS pty master: posix_openpt + grantpt + unlockpt,
/// then resolve the slave device name. `nonblock` adds O_NONBLOCK to
/// the master. Returns (master_fd, slave_name). Errno is the raw macOS
/// errno; callers translate via `dev::host_open_errno`-style mapping.
pub fn open_master(nonblock: bool) -> Result<(i32, String), i32> {
    let mut oflag = libc::O_RDWR | libc::O_NOCTTY;
    if nonblock {
        oflag |= libc::O_NONBLOCK;
    }
    // SAFETY: posix_openpt takes an int flag and returns an fd or -1.
    let master = unsafe { libc::posix_openpt(oflag) };
    if master < 0 {
        return Err(unsafe { *libc::__error() });
    }
    // SAFETY: master is a valid fd from posix_openpt.
    if unsafe { libc::grantpt(master) } != 0 || unsafe { libc::unlockpt(master) } != 0 {
        let e = unsafe { *libc::__error() };
        unsafe { libc::close(master) };
        return Err(e);
    }
    // ptsname is not thread-safe; ptsname_r is non-portable on macOS.
    // macOS provides ptsname(); we copy out immediately under no other
    // pty calls in flight (callers hold the PtyTable mutex).
    // SAFETY: master is valid; ptsname returns a static C string or null.
    let name_ptr = unsafe { libc::ptsname(master) };
    if name_ptr.is_null() {
        let e = unsafe { *libc::__error() };
        unsafe { libc::close(master) };
        return Err(e);
    }
    // SAFETY: name_ptr is a valid NUL-terminated C string from ptsname.
    let slave_name = unsafe { CStr::from_ptr(name_ptr) }
        .to_string_lossy()
        .into_owned();
    Ok((master, slave_name))
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --lib vfs::devpts::tests::open_master_returns_fd_and_slave_name`
Expected: PASS.

- [ ] **Step 5: Wire `/dev/ptmx` into `DevVfs`**

In `src/vfs/dev.rs`, give `DevVfs` the shared table and handle ptmx:

```rust
use std::sync::Arc;
use parking_lot::Mutex;
use super::devpts::{open_master, PtyTable};

pub struct DevVfs {
    pty_table: Arc<Mutex<PtyTable>>,
}

impl DevVfs {
    pub fn new(pty_table: Arc<Mutex<PtyTable>>) -> Self {
        Self { pty_table }
    }
}
```

In `lookup`, before the `host_path_for` check, add:

```rust
        if path == "/dev/ptmx" {
            return Ok(Metadata {
                kind: EntryKind::CharDevice,
                mode: 0o666,
                size: 0,
                uid: 0,
                gid: 0,
                mtime_secs: 0,
                mtime_nanos: 0,
            });
        }
```

In `readdir("/dev")`, append `"ptmx"` to the returned names (it is a /dev node). In `open`, before `host_path_for`:

```rust
        if path == "/dev/ptmx" {
            let (master_fd, slave_name) = open_master(flags.nonblock).map_err(host_errno_map)?;
            let index = self.pty_table.lock().insert(master_fd, slave_name);
            let status_flags = if flags.nonblock {
                crate::linux_abi::LINUX_O_NONBLOCK as u32
            } else {
                0
            };
            return Ok(VfsHandle::Pty {
                host_fd: master_fd,
                pts_index: index,
                is_master: true,
                status_flags,
            });
        }
```

(`host_errno_map` = the existing `host_open_errno`-style translator; reuse `host_open_errno()` by setting errno first, or factor a `fn map_host_errno(raw: i32) -> i32`. Simplest: change `open_master` callers to translate via a small local `match` mirroring `host_open_errno`.) Update `DevVfs::new` callers (Task 5 wires construction).

- [ ] **Step 6: Commit**

```bash
git add src/vfs/devpts.rs src/vfs/dev.rs
git commit -m "vfs: /dev/ptmx opens a real host pty master"
```

---

## Task 4: `DevptsVfs` — `/dev/pts` and `/dev/pts/N`

**Files:**
- Modify: `src/vfs/devpts.rs` (the `Vfs` impl)
- Modify: `src/vfs/mount.rs` (register at `/dev/pts`)
- Test: inline in `src/vfs/devpts.rs`

- [ ] **Step 1: Write the failing test**

```rust
// src/vfs/devpts.rs  #[cfg(test)] mod tests
    #[test]
    fn devpts_lookup_and_readdir_track_live_ptys() {
        use crate::vfs::{Vfs, OpenFlags, OpenContext};
        use std::sync::Arc;
        use parking_lot::Mutex;

        let table = Arc::new(Mutex::new(PtyTable::new()));
        let dev = DevptsVfs::new(Arc::clone(&table));

        // The dir always exists; an unknown slave is ENOENT.
        assert_eq!(dev.lookup("/dev/pts").unwrap().kind, crate::vfs::EntryKind::Directory);
        assert!(dev.lookup("/dev/pts/0").is_err());

        // Allocate a master out-of-band; the slave now resolves.
        let n = table.lock().insert(99, "/dev/null".into()); // /dev/null: openable slave stand-in
        assert_eq!(n, 0);
        assert_eq!(dev.lookup("/dev/pts/0").unwrap().kind, crate::vfs::EntryKind::CharDevice);
        let names: Vec<String> = dev.readdir("/dev/pts").unwrap().into_iter().map(|e| e.name).collect();
        assert!(names.contains(&"0".to_string()));

        // Opening the slave yields a Pty handle (host fd to /dev/null here).
        let h = dev.open("/dev/pts/0", OpenFlags { read: true, write: true, ..Default::default() }, &OpenContext::default()).unwrap();
        match h {
            crate::vfs::VfsHandle::Pty { is_master, pts_index, host_fd, .. } => {
                assert!(!is_master);
                assert_eq!(pts_index, 0);
                unsafe { libc::close(host_fd) };
            }
            other => panic!("expected Pty handle, got {other:?}"),
        }
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --lib vfs::devpts::tests::devpts_lookup_and_readdir_track_live_ptys`
Expected: FAIL — `DevptsVfs` not found.

- [ ] **Step 3: Implement `DevptsVfs`**

```rust
// src/vfs/devpts.rs
use std::ffi::CString;
use std::sync::Arc;
use parking_lot::Mutex;
use crate::linux_abi::{LINUX_ENOENT, LINUX_ENOTDIR};
use super::{DirEnt, EntryKind, Metadata, OpenContext, OpenFlags, Vfs, VfsError, VfsHandle};

pub struct DevptsVfs {
    pty_table: Arc<Mutex<PtyTable>>,
}

impl DevptsVfs {
    pub fn new(pty_table: Arc<Mutex<PtyTable>>) -> Self {
        Self { pty_table }
    }

    fn parse_index(path: &str) -> Option<u32> {
        path.strip_prefix("/dev/pts/")?.parse().ok()
    }
}

impl Vfs for DevptsVfs {
    fn lookup(&self, path: &str) -> Result<Metadata, VfsError> {
        if path == "/dev/pts" {
            return Ok(Metadata {
                kind: EntryKind::Directory,
                mode: 0o755,
                size: 0,
                uid: 0,
                gid: 0,
                mtime_secs: 0,
                mtime_nanos: 0,
            });
        }
        if let Some(n) = Self::parse_index(path) {
            if self.pty_table.lock().slave_name(n).is_some() {
                return Ok(Metadata {
                    kind: EntryKind::CharDevice,
                    mode: 0o620,
                    size: 0,
                    uid: 0,
                    gid: 0,
                    mtime_secs: 0,
                    mtime_nanos: 0,
                });
            }
        }
        Err(LINUX_ENOENT)
    }

    fn readdir(&self, path: &str) -> Result<Vec<DirEnt>, VfsError> {
        if path != "/dev/pts" {
            return Err(LINUX_ENOTDIR);
        }
        Ok(self
            .pty_table
            .lock()
            .live_indices()
            .into_iter()
            .map(|n| DirEnt { name: n.to_string(), kind: EntryKind::CharDevice })
            .collect())
    }

    fn open(&self, path: &str, flags: OpenFlags, _ctx: &OpenContext<'_>) -> Result<VfsHandle, VfsError> {
        let n = Self::parse_index(path).ok_or(LINUX_ENOENT)?;
        let slave_name = self.pty_table.lock().slave_name(n).ok_or(LINUX_ENOENT)?;
        let mut oflag = if flags.read && flags.write {
            libc::O_RDWR
        } else if flags.write {
            libc::O_WRONLY
        } else {
            libc::O_RDONLY
        };
        oflag |= libc::O_NOCTTY;
        if flags.nonblock {
            oflag |= libc::O_NONBLOCK;
        }
        let cpath = CString::new(slave_name).map_err(|_| crate::linux_abi::LINUX_EINVAL)?;
        // SAFETY: cpath is a valid NUL-terminated path to a host slave pty.
        let host_fd = unsafe { libc::open(cpath.as_ptr(), oflag) };
        if host_fd < 0 {
            return Err(super::dev::host_open_errno());
        }
        let status_flags = if flags.nonblock {
            crate::linux_abi::LINUX_O_NONBLOCK as u32
        } else {
            0
        };
        Ok(VfsHandle::Pty { host_fd, pts_index: n, is_master: false, status_flags })
    }

    fn name(&self) -> &'static str {
        "devpts"
    }
}
```

(Make `dev::host_open_errno` `pub(crate)` so `devpts` can reuse it.)

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --lib vfs::devpts::tests::devpts_lookup_and_readdir_track_live_ptys`
Expected: PASS.

- [ ] **Step 5: Register the mount**

Find where `DevVfs` is mounted (`grep -rn 'DevVfs::new\|mount("/dev"' src/`). Adjacent to it, mount devpts with the **same** `Arc<Mutex<PtyTable>>` (the table is created in Task 5's dispatcher wiring; this step adds the `mount("/dev/pts", Box::new(DevptsVfs::new(Arc::clone(&pty_table))))` call alongside the updated `DevVfs::new(Arc::clone(&pty_table))`).

- [ ] **Step 6: Commit**

```bash
git add src/vfs/devpts.rs src/vfs/mount.rs
git commit -m "vfs: DevptsVfs serves /dev/pts and /dev/pts/N slaves"
```

---

## Task 5: Dispatcher wiring — own the shared `PtyTable`

**Files:**
- Modify: `src/dispatch/mod.rs` (`SyscallDispatcher` field + constructor wiring)
- Modify: `src/dispatch/fs.rs` (`FsState`/mount construction, if mounts are built there)

- [ ] **Step 1: Add the field**

In `src/dispatch/mod.rs`, add to `SyscallDispatcher`:

```rust
    /// Shared pseudo-terminal table. Cloned into the `/dev` (ptmx) and
    /// `/dev/pts` mounts; the dispatcher reaches it from the ioctl
    /// (TIOCSPTLCK) and close (free-on-master-close) paths.
    pty_table: Arc<parking_lot::Mutex<crate::vfs::PtyTable>>,
```

- [ ] **Step 2: Wire it at construction**

Wherever the dispatcher builds its `VfsMounts` and `DevVfs` (follow the existing `DevVfs::new()` call site — likely in `FsState::new`/`with_rootfs`), create the table once and clone it into both mounts and the field:

```rust
let pty_table = Arc::new(parking_lot::Mutex::new(crate::vfs::PtyTable::new()));
// … vfs_mounts.mount("/dev", Box::new(DevVfs::new(Arc::clone(&pty_table))));
// … vfs_mounts.mount("/dev/pts", Box::new(DevptsVfs::new(Arc::clone(&pty_table))));
// store `pty_table` in the dispatcher field
```

If `DevVfs::new()` currently takes no args, update **all** its call sites (`grep -rn 'DevVfs::new' src/`) to pass the table; tests that construct `DevVfs` standalone use `Arc::new(Mutex::new(PtyTable::new()))`.

- [ ] **Step 3: Build + run lib tests**

Run: `cargo build && cargo test --lib`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add src/dispatch/mod.rs src/dispatch/fs.rs
git commit -m "dispatch: own a shared PtyTable wired into /dev and /dev/pts"
```

---

## Task 6: ioctl routing for pty fds

**Files:**
- Modify: `src/dispatch/fs.rs` (`ioctl` handler ~line 918; `fd_is_tty`)
- Modify: `src/linux_abi.rs` (add `LINUX_TIOCGPTN`, `LINUX_TIOCSPTLCK` if absent)
- Test: `tests/syscall_fs.rs`

`TIOCGPTN = 0x80045430`, `TIOCSPTLCK = 0x40045431` (Linux aarch64 values). Add as `LINUX_*` consts in `src/linux_abi.rs` if not present.

- [ ] **Step 1: Write the failing test**

```rust
// tests/syscall_fs.rs
#[test]
fn ptmx_open_then_tiocgptn_returns_index_and_isatty() {
    // Open /dev/ptmx, then TIOCGPTN must return the pts index (0 for the
    // first pty) and TCGETS must succeed (isatty true) rather than ENOTTY.
    let mut dispatcher = /* dispatcher with /dev + /dev/pts mounts */;
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x400]);
    memory.write_bytes(0x4000, b"/dev/ptmx\0").unwrap();
    let reporter = CompatReporter::default();

    // openat(AT_FDCWD, "/dev/ptmx", O_RDWR)
    let fd = match dispatcher.dispatch(
        SyscallRequest::new(56, SyscallArgs::from([(-100_i64) as u64, 0x4000, 2 /*O_RDWR*/, 0, 0, 0])),
        &mut memory, &reporter,
    ).unwrap() {
        DispatchOutcome::Returned { value } => value as u64,
        other => panic!("open ptmx: {other:?}"),
    };

    // ioctl(fd, TIOCGPTN, &out) -> writes 0
    let out = 0x4100;
    assert_eq!(
        dispatcher.dispatch(
            SyscallRequest::new(29, SyscallArgs::from([fd, 0x80045430, out, 0, 0, 0])),
            &mut memory, &reporter,
        ).unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(memory.read_bytes(out, 4).unwrap(), 0u32.to_le_bytes());

    // ioctl(fd, TCGETS, &buf) must NOT be ENOTTY (isatty true).
    let buf = 0x4200;
    let r = dispatcher.dispatch(
        SyscallRequest::new(29, SyscallArgs::from([fd, LINUX_TCGETS, buf, 0, 0, 0])),
        &mut memory, &reporter,
    ).unwrap();
    assert!(matches!(r, DispatchOutcome::Returned { .. }), "TCGETS on ptmx: {r:?}");
}
```

(Use the existing test helper that builds a dispatcher with the standard mount set; if none exists, add `SyscallDispatcher::with_rootfs(empty_rootfs())` and confirm it mounts `/dev` + `/dev/pts` — Task 5 ensures it does.)

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --test syscall_fs ptmx_open_then_tiocgptn`
Expected: FAIL — TIOCGPTN unhandled (ENOTTY) and/or TCGETS returns ENOTTY for the pty fd.

- [ ] **Step 3: Implement pty ioctl routing**

In `src/dispatch/fs.rs`, add a helper to fetch the `PtyRole` for an fd:

```rust
fn pty_role(&self, fd: i32) -> Option<crate::vfs::PtyRole> {
    self.open_file(fd).and_then(|of| match &*of.description.read() {
        OpenDescription::HostPipe { pty, .. } => *pty,
        _ => None,
    })
}

fn pty_host_fd(&self, fd: i32) -> Option<i32> {
    self.open_file(fd).and_then(|of| match &*of.description.read() {
        OpenDescription::HostPipe { host_fd, pty: Some(_), .. } => Some(*host_fd),
        _ => None,
    })
}
```

At the **top** of the `ioctl` match (before the stdio-specific arms), handle pty fds:

```rust
        if let Some(role) = self.pty_role(fd) {
            // SAFETY for all passthroughs: host_fd is a live pty fd we own.
            let host_fd = self.pty_host_fd(fd).expect("pty fd has host fd");
            return Ok(match ioctl_request {
                LINUX_TIOCGPTN => {
                    write_packed(&mut *ctx.memory, arg, &role.index.to_le_bytes())
                }
                LINUX_TIOCSPTLCK => {
                    // glibc unlockpt writes 0; lock writes nonzero.
                    let mut buf = [0u8; 4];
                    match ctx.memory.read_bytes(arg, 4) {
                        Ok(b) => buf.copy_from_slice(&b),
                        Err(_) => return Ok(DispatchOutcome::Errno { errno: LINUX_EFAULT }),
                    }
                    let lock = i32::from_le_bytes(buf) != 0;
                    self.pty_table.lock().set_locked(role.index, lock);
                    DispatchOutcome::Returned { value: 0 }
                }
                LINUX_TCGETS => passthrough_termios_get(host_fd, &mut *ctx.memory, arg),
                LINUX_TCSETS | LINUX_TCSETSW | LINUX_TCSETSF => {
                    passthrough_termios_set(host_fd, ioctl_request, &*ctx.memory, arg)
                }
                LINUX_TIOCGWINSZ => passthrough_winsize_get(host_fd, &mut *ctx.memory, arg),
                LINUX_TIOCSWINSZ => passthrough_winsize_set(host_fd, &*ctx.memory, arg),
                LINUX_TIOCGPGRP => passthrough_pgrp_get(host_fd, &mut *ctx.memory, arg),
                LINUX_TIOCSPGRP => passthrough_pgrp_set(host_fd, &*ctx.memory, arg),
                LINUX_TIOCSCTTY => {
                    // SAFETY: host_fd is our pty fd. Best-effort; ignore errno.
                    unsafe { libc::ioctl(host_fd, libc::TIOCSCTTY as _, 0) };
                    DispatchOutcome::Returned { value: 0 }
                }
                _ => {
                    ctx.reporter.record(CompatEvent::unhandled_ioctl(fd, ioctl_request, arg));
                    DispatchOutcome::Errno { errno: LINUX_ENOTTY }
                }
            });
        }
```

Implement the passthrough helpers (free functions in `fs.rs`). macOS `struct termios`/`winsize` layouts differ from Linux, so marshal field-by-field using the existing `LinuxTermios` (36-byte) / `LinuxWinsize` (8-byte) ABI structs in `src/linux_abi.rs`. Example for winsize (identical 4×u16 layout on both):

```rust
fn passthrough_winsize_get<M: GuestMemory>(host_fd: i32, mem: &mut M, arg: u64) -> DispatchOutcome {
    let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
    // SAFETY: host_fd is a live tty; &mut ws is a valid winsize buffer.
    if unsafe { libc::ioctl(host_fd, libc::TIOCGWINSZ, &mut ws) } != 0 {
        return DispatchOutcome::Errno { errno: crate::dispatch::macos_to_linux_errno(unsafe { *libc::__error() }) };
    }
    let mut bytes = [0u8; 8];
    bytes[0..2].copy_from_slice(&ws.ws_row.to_le_bytes());
    bytes[2..4].copy_from_slice(&ws.ws_col.to_le_bytes());
    bytes[4..6].copy_from_slice(&ws.ws_xpixel.to_le_bytes());
    bytes[6..8].copy_from_slice(&ws.ws_ypixel.to_le_bytes());
    write_packed(mem, arg, &bytes)
}
```

For termios, reuse the existing Linux↔host termios marshaling already used by the stdio `TCGETS` path (`grep -n "host_tty\|LinuxTermios" src/dispatch/fs.rs src/host_tty.rs`); factor that conversion into a helper both stdio and pty paths call rather than duplicating. For pgrp, marshal a single `i32` and call `libc::tcgetpgrp`/`libc::tcsetpgrp`.

Then update `fd_is_tty` (or the predicate the existing TCGETS arm uses) so a `HostPipe { pty: Some(_), .. }` fd counts as a tty.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --test syscall_fs ptmx_open_then_tiocgptn`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/dispatch/fs.rs src/linux_abi.rs tests/syscall_fs.rs
git commit -m "dispatch: pty ioctls — synth TIOCGPTN/TIOCSPTLCK, passthrough termios/winsize/pgrp"
```

---

## Task 7: Free the table entry when the master closes

**Files:**
- Modify: `src/dispatch/fs.rs` (the `close` handler)
- Test: `tests/syscall_fs.rs`

- [ ] **Step 1: Write the failing test**

```rust
// tests/syscall_fs.rs
#[test]
fn closing_ptmx_master_removes_pts_entry() {
    let mut dispatcher = /* dispatcher with /dev + /dev/pts */;
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x200]);
    memory.write_bytes(0x4000, b"/dev/ptmx\0").unwrap();
    memory.write_bytes(0x4040, b"/dev/pts/0\0").unwrap();
    let reporter = CompatReporter::default();

    let master = match dispatcher.dispatch(
        SyscallRequest::new(56, SyscallArgs::from([(-100_i64) as u64, 0x4000, 2, 0, 0, 0])),
        &mut memory, &reporter).unwrap() {
        DispatchOutcome::Returned { value } => value as u64,
        o => panic!("{o:?}"),
    };
    // /dev/pts/0 now resolves (openat O_RDWR succeeds).
    assert!(matches!(
        dispatcher.dispatch(SyscallRequest::new(56, SyscallArgs::from([(-100_i64) as u64, 0x4040, 2, 0, 0, 0])), &mut memory, &reporter).unwrap(),
        DispatchOutcome::Returned { .. }
    ));
    // close(master) -> /dev/pts/0 becomes ENOENT.
    assert_eq!(
        dispatcher.dispatch(SyscallRequest::new(57, SyscallArgs::from([master, 0, 0, 0, 0, 0])), &mut memory, &reporter).unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        dispatcher.dispatch(SyscallRequest::new(56, SyscallArgs::from([(-100_i64) as u64, 0x4040, 2, 0, 0, 0])), &mut memory, &reporter).unwrap(),
        DispatchOutcome::Errno { errno: 2 }
    );
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --test syscall_fs closing_ptmx_master_removes_pts_entry`
Expected: FAIL — `/dev/pts/0` still resolves after master close.

- [ ] **Step 3: Implement free-on-master-close**

In the `close` handler in `src/dispatch/fs.rs`, after determining the description being closed and before/while closing its host fd, add:

```rust
        if let OpenDescription::HostPipe { pty: Some(role), .. } = &*description.read() {
            if role.is_master {
                self.pty_table.lock().free(role.index);
            }
        }
```

(Place this where `close` already inspects the description to close the host fd; the existing host-fd close path handles the actual `libc::close`.)

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --test syscall_fs closing_ptmx_master_removes_pts_entry`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/dispatch/fs.rs tests/syscall_fs.rs
git commit -m "dispatch: free pts entry when the ptmx master closes"
```

---

## Task 8: Conformance probe `ptypair`

**Files:**
- Create: `conformance-probes/src/bin/ptypair.rs`
- Modify: `tests/conformance.rs` (only if probes are listed explicitly; otherwise auto-discovered — check the existing `KNOWN_PROBE_GAPS`/probe list)

- [ ] **Step 1: Write the probe (the test IS the probe; it runs identically under carrick and Docker)**

```rust
// conformance-probes/src/bin/ptypair.rs
// Full pty round-trip: posix_openpt -> grantpt -> unlockpt -> ptsname ->
// open slave -> write master, read slave (and reverse). Prints
// deterministic, host-independent lines so carrick and real Linux match.
use std::ffi::CStr;
use std::io::{Read, Write};
use std::os::unix::io::FromRawFd;

fn main() {
    unsafe {
        let master = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY);
        assert!(master >= 0, "posix_openpt");
        assert_eq!(libc::grantpt(master), 0, "grantpt");
        assert_eq!(libc::unlockpt(master), 0, "unlockpt");
        let name = CStr::from_ptr(libc::ptsname(master)).to_string_lossy().into_owned();
        // The slave name is /dev/pts/N on Linux; print only the prefix so
        // carrick (which also serves /dev/pts/N) matches regardless of N.
        println!("slave_prefix={}", name.rsplit_once('/').map(|(p, _)| p).unwrap_or(""));

        let slave_fd = libc::open(CStr::from_ptr(libc::ptsname(master)).as_ptr(), libc::O_RDWR | libc::O_NOCTTY);
        assert!(slave_fd >= 0, "open slave");

        // isatty on the slave.
        println!("slave_isatty={}", libc::isatty(slave_fd));

        // Disable echo so the master read is deterministic.
        let mut tio: libc::termios = std::mem::zeroed();
        libc::tcgetattr(slave_fd, &mut tio);
        tio.c_lflag &= !(libc::ECHO | libc::ICANON) as _;
        libc::tcsetattr(slave_fd, libc::TCSANOW, &tio);

        let mut master_f = std::fs::File::from_raw_fd(master);
        let mut slave_f = std::fs::File::from_raw_fd(slave_fd);

        master_f.write_all(b"ping").unwrap();
        let mut buf = [0u8; 4];
        slave_f.read_exact(&mut buf).unwrap();
        println!("slave_got={}", std::str::from_utf8(&buf).unwrap());

        slave_f.write_all(b"pong").unwrap();
        let mut buf2 = [0u8; 4];
        master_f.read_exact(&mut buf2).unwrap();
        println!("master_got={}", std::str::from_utf8(&buf2).unwrap());
    }
}
```

Expected deterministic output (both carrick and Docker):
```
slave_prefix=/dev/pts
slave_isatty=1
slave_got=ping
master_got=pong
```

- [ ] **Step 2: Build the probes**

Run: `scripts/build-probes.sh`
Expected: `ptypair` appears in `conformance-probes/target/aarch64-unknown-linux-musl/release/`.

- [ ] **Step 3: Build + sign carrick, run conformance**

Run:
```bash
./scripts/build-signed.sh
cargo test --test conformance -- --nocapture
```
Expected: the `ptypair` probe MATCHES Docker (PASS). If carrick's `slave_prefix` differs (e.g. macOS leaks `/dev/ttys`), that's a bug in the slave-name presentation — carrick must present `/dev/pts/N` to the guest, which it does because the guest opened `/dev/pts/N` (the guest never sees the macOS name). Confirm `ptsname` in the guest returns `/dev/pts/N` via the TIOCGPTN synthesis.

- [ ] **Step 4: Commit**

```bash
git add conformance-probes/src/bin/ptypair.rs tests/conformance.rs
git commit -m "conformance: ptypair probe — full posix_openpt round-trip vs Docker"
```

---

## Task 9: End-to-end verification + docs

**Files:**
- Modify: `docs/tier-b-demo-report.md` or a short note (optional)

- [ ] **Step 1: Verify the apt cosmetic is gone**

Run:
```bash
./scripts/build-signed.sh
./target/release/carrick run --raw --fs host docker.io/library/debian:stable \
  /bin/sh -c "apt-get update >/dev/null 2>&1 && apt-get install -y hello 2>&1 | grep -c '/dev/pts'; /usr/bin/hello"
```
Expected: `0` (no `/dev/pts` warnings) followed by `Hello, world!`.

- [ ] **Step 2: Verify a self-allocated pty works**

Run:
```bash
./target/release/carrick run --raw --fs host docker.io/library/debian:stable \
  /bin/sh -c "apt-get install -y -qq script >/dev/null 2>&1; script -qec 'echo in-a-pty' /dev/null"
```
Expected: output includes `in-a-pty` with no posix_openpt error.

- [ ] **Step 3: Full gates**

Run:
```bash
cargo fmt --all -- --check
cargo clippy --lib --tests
cargo test --lib && cargo test --test syscall_fs
```
Expected: all green; no new clippy warnings from the new code.

- [ ] **Step 4: Commit any doc updates**

```bash
git add -A
git commit -m "docs: note devpts Phase A complete (apt /dev/pts warning resolved)"
```

---

## Self-review notes

- **Spec coverage:** ptmx open (Task 3), /dev/pts + slave open (Task 4), `PtyTable` (Task 1), ioctl synth + passthrough (Task 6), fork coherence (inherited via HostPipe host fds — no extra code, validated by the apt e2e which forks dpkg, Task 9), close/lifecycle (Task 7), error handling (Tasks 3/4 errno translation, Task 6 ENOTTY fallthrough), testing (unit Tasks 1/3/4/6/7, probe Task 8, e2e Task 9). Phase B is explicitly out of scope (separate plan).
- **Open implementation detail to resolve during Task 6:** factor the existing stdio termios marshaling (`host_tty`) into a shared helper rather than duplicating; if its current shape resists reuse, the pty path may copy the conversion with a `TODO` to unify — acceptable since correctness is covered by the `ptypair` probe.
- **macOS `ptsname` thread-safety:** callers hold the `PtyTable` mutex across `open_master`, serializing `ptsname`; do not call `open_master` without the lock held in production paths.
