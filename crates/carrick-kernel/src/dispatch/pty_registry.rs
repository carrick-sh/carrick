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

use crate::kernel::FileDescription;
use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex, Weak};

type MasterEntry = (i32, Weak<FileDescription>);
type MasterMap = HashMap<u32, MasterEntry>;

/// pts index -> (master host fd, weak reference to master open-description).
static MASTERS: LazyLock<Mutex<MasterMap>> = LazyLock::new(|| Mutex::new(HashMap::new()));

fn lock() -> std::sync::MutexGuard<'static, MasterMap> {
    MASTERS.lock().unwrap_or_else(|e| e.into_inner())
}

/// Record a pty master as it is opened.
pub(crate) fn register_master(index: u32, host_fd: i32, description: &Arc<FileDescription>) {
    lock().insert(index, (host_fd, Arc::downgrade(description)));
}

/// Forget a pty master as it closes. A stale entry would name a host fd the
/// kernel has since reused.
pub(crate) fn unregister_master(index: u32) {
    lock().remove(&index);
}

/// The master end of pty `index`, if one is open.
pub(crate) fn master(index: u32) -> Option<(i32, Arc<FileDescription>)> {
    lock()
        .get(&index)
        .and_then(|(host_fd, weak)| weak.upgrade().map(|desc| (*host_fd, desc)))
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
        let desc = Arc::new(FileDescription::regular(id));
        assert!(master(4242).is_none());
        register_master(4242, 31, &desc);
        assert_eq!(master(4242).map(|(fd, d)| (fd, d.id())), Some((31, id)));
        unregister_master(4242);
        assert!(master(4242).is_none());
    }

    #[test]
    fn a_dropped_master_description_is_not_findable() {
        let id = crate::kernel::ObjectIdRegistry::default()
            .file_description_id()
            .expect("a description id");
        let desc = Arc::new(FileDescription::regular(id));
        register_master(4243, 31, &desc);
        assert!(master(4243).is_some());
        drop(desc);
        assert!(master(4243).is_none());
        unregister_master(4243);
    }
}
