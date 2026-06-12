//! Backend-agnostic readiness multiplexer (kqueue on macOS ↔ epoll on Linux).
//!
//! Defined here so `carrick-bsd`'s `KqueueMultiplexer` and the future Linux
//! `EpollMultiplexer` share one contract. The contract is informed by the
//! runtime's actual epoll dependencies: EVFILT_VNODE/inotify, EVFILT_EXCEPT/
//! NOTE_OOB → EPOLLPRI, edge-vs-level, EV_EOF/error, NOTE_EXITSTATUS.

use crate::error::OsError;
use std::os::fd::RawFd;
use std::time::Duration;

/// IO readiness the caller wants (`EPOLLIN`/`EPOLLOUT`/`EPOLLPRI`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Interest {
    pub read: bool,
    pub write: bool,
    /// Out-of-band / priority data (`EPOLLPRI` ↔ `EVFILT_EXCEPT`/`NOTE_OOB`).
    pub oob: bool,
}

impl Interest {
    /// Helper to check if read/write/oob is requested.
    pub fn contains(&self, other: Self) -> bool {
        (self.read || !other.read) && (self.write || !other.write) && (self.oob || !other.oob)
    }

    pub const READ: Self = Self {
        read: true,
        write: false,
        oob: false,
    };
    pub const WRITE: Self = Self {
        read: false,
        write: true,
        oob: false,
    };
    pub const OOB: Self = Self {
        read: false,
        write: false,
        oob: true,
    };
}

/// Edge- vs level-triggered delivery (`EPOLLET` ↔ `EV_CLEAR`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TriggerMode {
    Edge,
    Level,
}

/// Filesystem-event mask (`EVFILT_VNODE` ↔ inotify).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct VnodeEvents {
    pub delete: bool,
    pub write: bool,
    pub extend: bool,
    pub attrib: bool,
    pub link: bool,
    pub rename: bool,
    pub revoke: bool,
}

impl VnodeEvents {
    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "dragonfly",
        target_os = "openbsd",
        target_os = "netbsd"
    ))]
    pub fn to_note(&self) -> u32 {
        let mut note = 0;
        if self.delete {
            note |= libc::NOTE_DELETE;
        }
        if self.write {
            note |= libc::NOTE_WRITE;
        }
        if self.extend {
            note |= libc::NOTE_EXTEND;
        }
        if self.attrib {
            note |= libc::NOTE_ATTRIB;
        }
        if self.link {
            note |= libc::NOTE_LINK;
        }
        if self.rename {
            note |= libc::NOTE_RENAME;
        }
        if self.revoke {
            note |= libc::NOTE_REVOKE;
        }
        note
    }
}

/// What the caller learns about a token's readiness.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Readiness {
    pub read: bool,
    pub write: bool,
    pub oob: bool,
}

impl std::ops::BitOrAssign for Readiness {
    fn bitor_assign(&mut self, rhs: Self) {
        self.read |= rhs.read;
        self.write |= rhs.write;
        self.oob |= rhs.oob;
    }
}

impl Readiness {
    pub fn empty() -> Self {
        Self::default()
    }

    pub const READ: Self = Self {
        read: true,
        write: false,
        oob: false,
    };
    pub const WRITE: Self = Self {
        read: false,
        write: true,
        oob: false,
    };
    pub const OOB: Self = Self {
        read: false,
        write: false,
        oob: true,
    };
}

/// One ready event returned by [`EventMultiplexer::wait`].
#[derive(Debug, Clone, Copy)]
pub struct PollEvent {
    pub token: u64,
    pub readiness: Readiness,
    /// `EV_EOF`/fflags → `EPOLLERR`.
    pub error: Option<i32>,
    /// → `EPOLLHUP`.
    pub eof: bool,
    /// `NOTE_EXITSTATUS`.
    pub exit_status: Option<i32>,
}

pub trait EventMultiplexer: Send {
    fn register_io(
        &mut self,
        fd: RawFd,
        token: u64,
        interest: Interest,
        mode: TriggerMode,
    ) -> Result<(), OsError>;
    fn register_vnode(&mut self, fd: RawFd, token: u64, mask: VnodeEvents) -> Result<(), OsError>;
    fn watch_process_exit(&mut self, pid: i32, token: u64) -> Result<(), OsError>;
    fn register_user(&mut self, ident: u64) -> Result<(), OsError>;
    fn trigger_user(&self, ident: u64) -> Result<(), OsError>;
    fn register_timer(
        &mut self,
        token: u64,
        interval: Duration,
        oneshot: bool,
    ) -> Result<(), OsError>;
    fn deregister(&mut self, fd: RawFd) -> Result<(), OsError>;
    fn wait(
        &mut self,
        out: &mut Vec<PollEvent>,
        timeout: Option<Duration>,
    ) -> Result<usize, OsError>;
    /// The pollable fd readable when any registered event is ready (kqueue fd on
    /// BSD, epoll fd on Linux).
    fn poll_fd(&self) -> RawFd;
}
