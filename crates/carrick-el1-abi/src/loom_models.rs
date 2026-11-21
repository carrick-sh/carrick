#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

extern crate std;

use core::sync::atomic::Ordering;
use loom::sync::Arc;
use loom::sync::atomic::{AtomicU64, fence};
use loom::thread;

use crate::{InotifyNameCache, NameCacheAtomic};
use carrick_core_abi::{SeqAtomic, SeqLockAtomic};

#[repr(transparent)]
#[derive(Debug, Default)]
pub(crate) struct LoomNameCacheAtomic(AtomicU64);

impl SeqAtomic for LoomNameCacheAtomic {
    #[inline]
    fn load(&self, order: Ordering) -> u64 {
        self.0.load(order)
    }

    #[inline]
    fn store(&self, val: u64, order: Ordering) {
        self.0.store(val, order);
    }

    #[inline]
    fn release_fence() {
        fence(Ordering::Release);
    }

    #[inline]
    fn acquire_fence() {
        fence(Ordering::Acquire);
    }

    #[inline]
    fn spin_loop() {
        thread::yield_now();
    }
}

impl SeqLockAtomic for LoomNameCacheAtomic {
    #[inline]
    fn compare_exchange(
        &self,
        current: u64,
        new: u64,
        success: Ordering,
        failure: Ordering,
    ) -> Result<u64, u64> {
        self.0.compare_exchange(current, new, success, failure)
    }
}

impl NameCacheAtomic for LoomNameCacheAtomic {
    #[inline]
    fn fetch_add(&self, val: u64, order: Ordering) -> u64 {
        self.0.fetch_add(val, order)
    }
}

fn check_with_preemptions(preemptions: usize, f: impl Fn() + Sync + Send + 'static) {
    let mut builder = loom::model::Builder::new();
    builder.preemption_bound = Some(preemptions);
    builder.check(f);
}

#[test]
fn loom_invalidate_all_and_refill_never_returns_other_paths_handle() {
    check_with_preemptions(2, || {
        let cache = Arc::new(InotifyNameCache::<LoomNameCacheAtomic, 1, 2>::with_default_entries());
        let file_table = 42_u64;
        let cwd_gen = cache.cwd_generation();
        let forced_hash = 0xdead_beef_cafe_babe_u64;
        let path_a = *b"aaaaaaaaxxxxxxxx";
        let path_b = *b"bbbbbbbbxxxxxxxx";
        let handle_a = 11_u32;
        let handle_b = 22_u32;

        cache.insert(file_table, cwd_gen, &path_a, forced_hash, handle_a);

        let writer_cache = Arc::clone(&cache);
        let writer = thread::spawn(move || {
            writer_cache.invalidate_all();
            writer_cache.insert(file_table, cwd_gen, &path_b, forced_hash, handle_b);
        });

        let got = cache.lookup(file_table, &path_a, forced_hash);
        assert!(
            matches!(got, None | Some(11)),
            "lookup for path_a returned another path's handle across invalidate_all+insert: {got:?}"
        );

        writer.join().unwrap();
        assert_eq!(cache.lookup(file_table, &path_a, forced_hash), None);
        assert_eq!(
            cache.lookup(file_table, &path_b, forced_hash),
            Some(handle_b)
        );
    });
}

#[test]
fn loom_invalidate_file_and_refill_never_returns_other_paths_handle() {
    check_with_preemptions(2, || {
        let cache = Arc::new(InotifyNameCache::<LoomNameCacheAtomic, 1, 2>::with_default_entries());
        let file_table = 42_u64;
        let cwd_gen = cache.cwd_generation();
        let forced_hash = 0xdead_beef_cafe_babe_u64;
        let path_a = *b"aaaaaaaaxxxxxxxx";
        let path_b = *b"bbbbbbbbxxxxxxxx";
        let handle_a = 11_u32;
        let handle_b = 22_u32;

        cache.insert(file_table, cwd_gen, &path_a, forced_hash, handle_a);

        let writer_cache = Arc::clone(&cache);
        let writer = thread::spawn(move || {
            writer_cache.invalidate_file(handle_a);
            writer_cache.insert(file_table, cwd_gen, &path_b, forced_hash, handle_b);
        });

        let got = cache.lookup(file_table, &path_a, forced_hash);
        assert!(
            matches!(got, None | Some(11)),
            "lookup for path_a returned another path's handle across invalidate_file+insert: {got:?}"
        );

        writer.join().unwrap();
        assert_eq!(cache.lookup(file_table, &path_a, forced_hash), None);
        assert_eq!(
            cache.lookup(file_table, &path_b, forced_hash),
            Some(handle_b)
        );
    });
}

#[test]
fn loom_direct_eviction_overwrite_never_returns_wrong_handle() {
    check_with_preemptions(2, || {
        let cache = Arc::new(InotifyNameCache::<LoomNameCacheAtomic, 1, 2>::with_default_entries());
        let file_table = 42_u64;
        let cwd_gen = cache.cwd_generation();
        let forced_hash = 0xdead_beef_cafe_babe_u64;
        let path_a = *b"aaaaaaaaxxxxxxxx";
        let path_b = *b"bbbbbbbbxxxxxxxx";
        let handle_a = 11_u32;
        let handle_b = 22_u32;

        cache.insert(file_table, cwd_gen, &path_a, forced_hash, handle_a);

        let writer_cache = Arc::clone(&cache);
        let writer = thread::spawn(move || {
            writer_cache.insert(file_table, cwd_gen, &path_b, forced_hash, handle_b);
        });

        let got_a = cache.lookup(file_table, &path_a, forced_hash);
        assert!(
            matches!(got_a, None | Some(11)),
            "lookup for path_a returned wrong handle during eviction overwrite: {got_a:?}"
        );
        let got_b = cache.lookup(file_table, &path_b, forced_hash);
        assert!(
            matches!(got_b, None | Some(22)),
            "lookup for path_b returned wrong handle during eviction overwrite: {got_b:?}"
        );

        writer.join().unwrap();
        assert_eq!(cache.lookup(file_table, &path_a, forced_hash), None);
        assert_eq!(
            cache.lookup(file_table, &path_b, forced_hash),
            Some(handle_b)
        );
    });
}

#[test]
fn loom_concurrent_insert_and_invalidate_release_the_entry_and_stay_linearizable() {
    check_with_preemptions(2, || {
        let cache = Arc::new(InotifyNameCache::<LoomNameCacheAtomic, 1, 2>::with_default_entries());
        let file_table = 42_u64;
        let cwd_gen = cache.cwd_generation();
        let path_a = *b"aaaaaaaaxxxxxxxx";
        let hash_a = crate::hash_path(&path_a);
        let handle_a = 11_u32;

        let writer_cache = Arc::clone(&cache);
        let writer = thread::spawn(move || {
            writer_cache.insert(file_table, cwd_gen, &path_a, hash_a, handle_a);
        });

        let invalidator_cache = Arc::clone(&cache);
        let invalidator = thread::spawn(move || {
            invalidator_cache.invalidate_file(handle_a);
        });

        writer.join().unwrap();
        invalidator.join().unwrap();

        // Both writers released the entry: it is even (readable) and
        // claimable again.
        assert!(cache.entries[0].seq.read_begin().is_some());
        assert!(cache.entries[0].seq.try_write().is_some());
        let final_lookup = cache.lookup(file_table, &path_a, hash_a);
        assert!(matches!(final_lookup, None | Some(11)));
    });
}

/// A refused-call writer lapped by the ring (#2690): writer A claims logical
/// record 0 and stalls while writer B publishes records 1 and 2, and record 2
/// lands on A's row. Whatever the interleaving, a row the reader accepts as
/// record `i` holds exactly the words published as record `i`.
#[test]
fn loom_lapped_refused_call_writer_never_leaves_an_accepted_torn_row() {
    use crate::{REFUSED_CALL_WORDS, publish_refused_call_row, read_refused_call_row};

    type Row = [LoomNameCacheAtomic; REFUSED_CALL_WORDS];
    struct Ring {
        rows: [Row; 2],
        next: LoomNameCacheAtomic,
    }
    fn record(tag: u64) -> [u64; REFUSED_CALL_WORDS - 1] {
        core::array::from_fn(|word| tag << 8 | word as u64)
    }

    check_with_preemptions(3, || {
        let ring = Arc::new(Ring {
            rows: Default::default(),
            next: LoomNameCacheAtomic::default(),
        });
        let stalled = Arc::clone(&ring);
        let a = thread::spawn(move || {
            [
                publish_refused_call_row(&stalled.rows, &stalled.next, record(0xa))
                    .map(|index| (index, record(0xa))),
            ]
        });
        let lapping = Arc::clone(&ring);
        let b = thread::spawn(move || {
            [0xb1, 0xb2].map(|tag| {
                publish_refused_call_row(&lapping.rows, &lapping.next, record(tag))
                    .map(|index| (index, record(tag)))
            })
        });
        let published: std::vec::Vec<(u64, [u64; REFUSED_CALL_WORDS - 1])> = a
            .join()
            .unwrap()
            .into_iter()
            .chain(b.join().unwrap())
            .flatten()
            .collect();
        let next = ring.next.load(Ordering::Acquire);
        assert_eq!(next, 3);
        for index in next - 2..next {
            let Some(words) = read_refused_call_row(&ring.rows, index) else {
                continue;
            };
            let expected = published
                .iter()
                .find(|(published, _)| *published == index)
                .map(|(_, words)| *words);
            assert_eq!(
                Some(words),
                expected,
                "row accepted as record {index} holds another record's words"
            );
        }
    });
}
