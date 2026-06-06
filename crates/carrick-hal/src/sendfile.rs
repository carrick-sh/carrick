//! File→socket zero-copy fast path. The general sendfile case already falls
//! back to a portable userspace copy in the runtime; only this fast path needs
//! a per-OS abstraction (macOS 6-arg vs FreeBSD 7-arg `sendfile`).

use crate::error::OsError;
use std::os::fd::RawFd;

pub trait Sendfile {
    fn file_to_socket(
        &self,
        file: RawFd,
        sock: RawFd,
        offset: i64,
        count: usize,
    ) -> Result<usize, OsError>;
}
