//! Linux namespace emulation (UID/GID + PID), implementing
//! `docs/namespaces-design.md` so `carrick run` presents the same namespace
//! view a container gets under `docker run` (uid 0 inside, pid 1 for the init,
//! `/proc/self/uid_map` readable, etc.).
//!
//! This module is split into:
//! - [`user`]: the user (UID/GID) namespace value object — the write-once
//!   `uid_map`/`gid_map` parser/validator, the setgroups gate, and the
//!   inside↔outside id translation (`user_namespaces(7)`).
//! - [`pid`]: the PID namespace translation table + the shared-memory member
//!   table backing it across fork (`pid_namespaces(7)`).
//!
//! The pure logic here is exercised by unit tests (`cargo test -p
//! carrick-runtime namespace::`) so it can iterate without the signed HVF build.

pub mod pid;
pub mod process;
pub mod user;

/// A namespace identity. Doubles as the inode-like number rendered in the
/// `/proc/[pid]/ns/{user,pid}` magic symlinks (`kind:[NsId]`), so it must be
/// stable for the lifetime of the namespace. Allocated from a monotonic
/// counter; never recycled (gaps are harmless — see design §8).
pub type NsId = u32;

/// The initial (host) user namespace every guest starts in. Identity-mapped
/// (`0 0 4294967295`), matching observed default `docker run` and carrick's
/// existing "guest is root" behavior (design §1.2, §4.2).
pub const INITIAL_USER_NS: NsId = 1;

/// The initial (host) PID namespace. Level 0, identity map (`ns_pid ==
/// host_pid`), so non-namespaced runs and `run-elf` are unchanged (design §5.2).
pub const INITIAL_PID_NS: NsId = 1;

/// The first namespace id handed out for a *freshly created* namespace
/// (`unshare`/`clone(CLONE_NEW*)`/launch placement). Ids 1 are reserved for the
/// initial namespaces above.
pub const FIRST_DYNAMIC_NS: NsId = 2;

/// The overflow uid/gid an unmapped id appears as inside a user namespace —
/// `nobody`/`nogroup` (`user_namespaces(7)`, observed and documented as 65534).
pub const OVERFLOW_ID: u32 = 65534;
