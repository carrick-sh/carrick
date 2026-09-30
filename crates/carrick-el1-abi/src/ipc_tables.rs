//! Which shared descriptor table ([`crate::ipc::IpcFdCore`]) belongs to which
//! host file table: the map EL1 consults to serve a task's IPC descriptors.
//!
//! The key is the host's `FileTableId` that every task record already
//! carries ([`crate::CurrentTask::file_table`], `ThreadIdentity::file_table`),
//! so a thread EL1 switches in — possibly of another process — resolves its
//! own table with no extra per-switch publication. A file table with no
//! entry is not served (EL1 forwards): publication is the host's admission
//! of a complete descriptor namespace, withdrawal its revocation.
//!
//! Concurrency: one host writer at a time (`writer` lock word), lock-free
//! EL1 readers. Each entry is a sequence lock: the writer makes `seq` odd,
//! writes the fields, then makes it even (Release); a reader that sees an
//! odd or changed `seq` treats the entry as absent (fail closed: forward).
//! A torn read cannot misroute a call either way: the returned
//! [`RawTableId`] is authenticated by the fd core (authority, index,
//! generation) on every use.

use crate::ipc::RawTableId;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

/// Map entries (open addressing).
pub const IPC_TABLE_MAP_ENTRIES: usize = 1024;
/// Probe length bound: lookups visit at most this many entries.
pub const IPC_TABLE_MAP_PROBES: usize = 16;
const EMPTY: u64 = 0;
const TOMBSTONE: u64 = u64::MAX;

#[repr(C, align(64))]
#[derive(Debug, Default)]
pub struct IpcTableMapEntry {
    seq: AtomicU64,
    file_table: AtomicU64,
    authority: AtomicU64,
    index: AtomicU64,
    generation: AtomicU64,
}

#[repr(C, align(64))]
#[derive(Debug)]
pub struct IpcTableMap {
    writer: AtomicU32,
    /// Nonzero once the carrier mapped the IPC window into stage-2: before
    /// that, touching the window would fault into the host, so EL1 checks
    /// this word (in always-mapped EL1 region memory) first.
    window: AtomicU32,
    _reserved: [u32; 14],
    entries: [IpcTableMapEntry; IPC_TABLE_MAP_ENTRIES],
}

/// Why a publication was refused (nothing changed).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IpcTableMapError {
    /// File table id 0 and `u64::MAX` are reserved.
    InvalidKey,
    /// No free entry within the probe bound: the table stays unpublished
    /// (its calls forward), never misrouted.
    Full,
}

fn home(file_table: u64) -> usize {
    (file_table.wrapping_mul(0x9E37_79B9_7F4A_7C15) >> 32) as usize % IPC_TABLE_MAP_ENTRIES
}

impl IpcTableMap {
    /// Host: the IPC window is mapped for EL1 (after stage-2 installation).
    pub fn publish_window(&self) {
        self.window.store(1, Ordering::Release);
    }

    /// Whether EL1 may touch the IPC window at all.
    pub fn window_published(&self) -> bool {
        self.window.load(Ordering::Acquire) != 0
    }

    fn probe(file_table: u64) -> impl Iterator<Item = usize> {
        let start = home(file_table);
        (0..IPC_TABLE_MAP_PROBES).map(move |i| (start + i) % IPC_TABLE_MAP_ENTRIES)
    }

    fn lock(&self) -> WriterGuard<'_> {
        while self
            .writer
            .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        WriterGuard(&self.writer)
    }

    fn store(entry: &IpcTableMapEntry, file_table: u64, table: RawTableId) {
        let seq = entry.seq.load(Ordering::Relaxed);
        entry.seq.store(seq.wrapping_add(1), Ordering::Relaxed);
        core::sync::atomic::fence(Ordering::Release);
        entry.authority.store(table.authority, Ordering::Relaxed);
        entry.index.store(table.index, Ordering::Relaxed);
        entry.generation.store(table.generation, Ordering::Relaxed);
        entry.file_table.store(file_table, Ordering::Relaxed);
        entry.seq.store(seq.wrapping_add(2), Ordering::Release);
    }

    /// Host: publish (or replace) `file_table`'s shared table.
    pub fn publish(&self, file_table: u64, table: RawTableId) -> Result<(), IpcTableMapError> {
        if file_table == EMPTY || file_table == TOMBSTONE {
            return Err(IpcTableMapError::InvalidKey);
        }
        let _writer = self.lock();
        let mut free = None;
        for i in Self::probe(file_table) {
            let key = self.entries[i].file_table.load(Ordering::Relaxed);
            if key == file_table {
                Self::store(&self.entries[i], file_table, table);
                return Ok(());
            }
            if free.is_none() && (key == EMPTY || key == TOMBSTONE) {
                free = Some(i);
            }
            if key == EMPTY {
                break;
            }
        }
        let i = free.ok_or(IpcTableMapError::Full)?;
        Self::store(&self.entries[i], file_table, table);
        Ok(())
    }

    /// Host: withdraw `file_table` (its calls forward from now on).
    pub fn withdraw(&self, file_table: u64) {
        let _writer = self.lock();
        for i in Self::probe(file_table) {
            let entry = &self.entries[i];
            let key = entry.file_table.load(Ordering::Relaxed);
            if key == file_table {
                Self::store(entry, TOMBSTONE, RawTableId::default());
                return;
            }
            if key == EMPTY {
                return;
            }
        }
    }

    /// EL1 or host: the table published for `file_table`, if any. At most
    /// [`IPC_TABLE_MAP_PROBES`] entries are read.
    pub fn lookup(&self, file_table: u64) -> Option<RawTableId> {
        if file_table == EMPTY || file_table == TOMBSTONE {
            return None;
        }
        for i in Self::probe(file_table) {
            let entry = &self.entries[i];
            let seq = entry.seq.load(Ordering::Acquire);
            let key = entry.file_table.load(Ordering::Relaxed);
            let table = RawTableId {
                authority: entry.authority.load(Ordering::Relaxed),
                index: entry.index.load(Ordering::Relaxed),
                generation: entry.generation.load(Ordering::Relaxed),
            };
            core::sync::atomic::fence(Ordering::Acquire);
            if seq & 1 != 0 || entry.seq.load(Ordering::Relaxed) != seq {
                // Mid-update: absent now; the caller forwards.
                return None;
            }
            if key == file_table {
                return Some(table);
            }
            if key == EMPTY {
                return None;
            }
        }
        None
    }
}

struct WriterGuard<'a>(&'a AtomicU32);
impl Drop for WriterGuard<'_> {
    fn drop(&mut self) {
        self.0.store(0, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    extern crate std;
    use super::*;
    use std::boxed::Box;

    fn map() -> Box<IpcTableMap> {
        let layout = std::alloc::Layout::new::<IpcTableMap>();
        // SAFETY: all-zero is the empty map.
        unsafe { Box::from_raw(std::alloc::alloc_zeroed(layout).cast()) }
    }
    fn raw(n: u64) -> RawTableId {
        RawTableId {
            authority: 7,
            index: n,
            generation: n + 100,
        }
    }

    #[test]
    fn el1_ipc_table_map_publishes_replaces_and_withdraws() {
        let m = map();
        assert_eq!(m.lookup(5), None, "unpublished: fail closed");
        m.publish(5, raw(1)).unwrap();
        m.publish(6, raw(2)).unwrap();
        assert_eq!(m.lookup(5), Some(raw(1)));
        m.publish(5, raw(3)).unwrap();
        assert_eq!(m.lookup(5), Some(raw(3)), "fork/unshare republishes");
        m.withdraw(5);
        assert_eq!(m.lookup(5), None);
        assert_eq!(m.lookup(6), Some(raw(2)), "tombstones keep probing");
        assert_eq!(m.publish(0, raw(1)), Err(IpcTableMapError::InvalidKey));
        assert_eq!(m.lookup(0), None);
    }

    #[test]
    fn el1_ipc_table_map_bounds_probes_and_refuses_when_full() {
        let m = map();
        // Keys that all share one home slot.
        let keys: std::vec::Vec<u64> = (1..u64::MAX)
            .filter(|k| home(*k) == home(1))
            .take(IPC_TABLE_MAP_PROBES + 1)
            .collect();
        for (n, k) in keys[..IPC_TABLE_MAP_PROBES].iter().enumerate() {
            m.publish(*k, raw(n as u64)).unwrap();
        }
        let last = keys[IPC_TABLE_MAP_PROBES];
        assert_eq!(m.publish(last, raw(99)), Err(IpcTableMapError::Full));
        assert_eq!(m.lookup(last), None, "refused tables forward");
        for (n, k) in keys[..IPC_TABLE_MAP_PROBES].iter().enumerate() {
            assert_eq!(m.lookup(*k), Some(raw(n as u64)));
        }
    }

    #[test]
    fn el1_ipc_window_attach_fails_closed_until_published() {
        let m = map();
        assert!(
            !m.window_published(),
            "zeroed EL1 region: never touch the window"
        );
        m.publish_window();
        assert!(m.window_published());
        let dir_len = crate::ipc::IPC_DIRECTORY_BYTES;
        let pool_len = crate::EL1_IPC_POOL_SPAN as usize;
        let dir = unsafe {
            std::alloc::alloc_zeroed(std::alloc::Layout::from_size_align(dir_len, 4096).unwrap())
        } as usize;
        let pool = 0x1000_0000_usize; // never dereferenced by these checks
        // SAFETY: only validation and a header read of zeroed memory.
        unsafe {
            assert!(crate::IpcWindow::new(dir, dir_len, pool, pool_len - 1).is_none());
            assert!(crate::IpcWindow::new(dir, dir_len - 1, pool, pool_len).is_none());
            assert!(crate::IpcWindow::new(0, dir_len, pool, pool_len).is_none());
            let window = crate::IpcWindow::new(dir, dir_len, pool, pool_len).unwrap();
            assert_eq!(
                window.attach().err(),
                Some(crate::ipc::IpcError::BadRegion),
                "an unpublished directory never attaches"
            );
        }
    }

    #[test]
    fn el1_ipc_table_map_readers_never_see_torn_entries() {
        let m: &'static IpcTableMap = Box::leak(map());
        let stop = std::sync::atomic::AtomicBool::new(false);
        std::thread::scope(|s| {
            s.spawn(|| {
                for n in 0..20_000u64 {
                    m.publish(9, raw(n)).unwrap();
                }
                stop.store(true, Ordering::Release);
            });
            while !stop.load(Ordering::Acquire) {
                if let Some(t) = m.lookup(9) {
                    assert_eq!(t.generation, t.index + 100, "torn entry {t:?}");
                }
            }
        });
    }
}
