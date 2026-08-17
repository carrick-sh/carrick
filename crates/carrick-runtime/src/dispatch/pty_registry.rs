//! Where each live pty's MASTER end can be found, without the file table.
//!
//! # Why this exists
//!
//! Darwin destroys whatever is still queued in a pty the moment its last slave
//! fd closes; Linux hands the data over and only then reports EOF. Measured on
//! macOS 27: write 1024 bytes to a slave, do not read the master, `close` the
//! slave — the master reads `0` and the bytes are gone. Carrick therefore has
//! to rescue the queued bytes from the master BEFORE letting the slave's close
//! reach the host.
//!
//! That rescue runs inside the close path, which is exactly where the master
//! cannot be looked up the obvious way: reading the file table from
//! `close_open_file_and_free_pty` hangs (`tty_pty` hung even in a variant whose
//! rescue immediately did nothing, so the LOOKUP is what deadlocks, not the
//! draining). Hence this registry — populated when the master is opened, so the
//! close path only has to consult a `HashMap`.
//!
//! # Scope
//!
//! CARRIER-WIDE, keyed by the pts index. A pty is a host kernel object shared
//! by whichever logical Linux processes hold its ends, so the host's own scope
//! is the right one — the same reasoning as `dispatch::net::reuseport`. Entries
//! are removed when the master closes, because a stale one would name a host fd
//! the kernel has since handed to something else.

use crate::kernel::FileDescriptionId;
use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};

/// pts index -> (master host fd, master open-description id).
static MASTERS: LazyLock<Mutex<HashMap<u32, (i32, FileDescriptionId)>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn lock() -> std::sync::MutexGuard<'static, HashMap<u32, (i32, FileDescriptionId)>> {
    MASTERS.lock().unwrap_or_else(|e| e.into_inner())
}

/// Record a pty master as it is opened.
pub(crate) fn register_master(index: u32, host_fd: i32, description: FileDescriptionId) {
    lock().insert(index, (host_fd, description));
}

/// Forget a pty master as it closes. A stale entry would name a host fd the
/// kernel has since reused.
pub(crate) fn unregister_master(index: u32) {
    lock().remove(&index);
}

/// The master end of pty `index`, if one is open.
pub(crate) fn master(index: u32) -> Option<(i32, FileDescriptionId)> {
    lock().get(&index).copied()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The registry must answer only for ptys that actually have a master open,
    /// and must forget one as soon as it closes — a stale entry names a host fd
    /// the kernel is free to have reused for something unrelated.
    #[test]
    fn a_master_is_findable_only_while_it_is_open() {
        let id = crate::kernel::ObjectIdRegistry::default()
            .file_description_id()
            .expect("a description id");
        assert!(master(4242).is_none());
        register_master(4242, 31, id);
        assert_eq!(master(4242), Some((31, id)));
        unregister_master(4242);
        assert!(master(4242).is_none());
    }
}
