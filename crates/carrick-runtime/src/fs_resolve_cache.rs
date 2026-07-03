//! Fork-coherent cache for `resolve_at_path` — the guest-path → canonical
//! host-side path resolution.
//!
//! Under `--fs host`, resolving a guest path re-walks it on the host (cap-std
//! containment / `validate_parents_fast`), which costs one-to-many host
//! `openat`s PER resolve. A syscall-bound workload that hammers the SAME stable
//! path — e.g. LTP `tst_fuzzy_sync` tests doing `inotify_add_watch` in a
//! 158k-iteration loop — pays that walk every iteration. This cache turns the
//! repeat resolves into hash lookups.
//!
//! ## Coherence across carrick's real-process forks
//!
//! carrick services guest `clone(2)` by forking the HOST process, so an
//! in-process map is NOT fork-coherent: a sibling that renames/creates/deletes
//! a directory would leave every other process's cache serving a stale resolve.
//! We fix that with a **generation counter in a `MAP_SHARED` page** (the same
//! trick as the alias-IPA allocator): every structural fs mutation — in ANY
//! process — bumps the one shared word, and a cache entry is valid only while
//! its stamped generation still equals the current shared generation. A stale
//! entry re-resolves. Content writes do NOT bump it (they can't change a path's
//! resolution); only structural changes (mkdir/rmdir/rename/symlink/link/
//! unlink/mknod/create) do.

use std::collections::HashMap;
use std::sync::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};

/// The one `MAP_SHARED` generation word, shared with every host-forked
/// descendant so a mutation in any process invalidates every process's cache.
fn generation_word() -> &'static AtomicU64 {
    static CELL: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    let addr = *CELL.get_or_init(|| {
        // SAFETY: a fresh anonymous shared page owned for the process lifetime.
        let p = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                4096,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_ANON | libc::MAP_SHARED,
                -1,
                0,
            )
        };
        if p == libc::MAP_FAILED {
            // mmap failing at boot means the host is already OOM; fall back to a
            // leaked process-local atomic (cross-fork coherence lost, but the
            // run is failing anyway).
            return Box::into_raw(Box::new(AtomicU64::new(1))) as usize;
        }
        // SAFETY: `p` is a writable 4 KiB page; an AtomicU64 fits at its start.
        // Start at 1 so a freshly-stamped entry (gen 1) is valid until the first
        // mutation; 0 is reserved as "never stamped".
        unsafe { (*(p as *mut AtomicU64)).store(1, Ordering::SeqCst) };
        p as usize
    });
    // SAFETY: `addr` is a live AtomicU64 valid for the whole process; MAP_SHARED
    // makes it the SAME physical word in every host-forked descendant.
    unsafe { &*(addr as *const AtomicU64) }
}

/// Force the shared generation word into existence in the ROOT process, BEFORE
/// any guest `fork`, so every descendant inherits the one `MAP_SHARED` word (a
/// child that first touched it after forking would map its own private page).
pub fn init() {
    let _ = generation_word();
}

/// Current fs-structure generation. A cache entry stamped with this value is
/// valid until the next structural mutation.
pub fn current_generation() -> u64 {
    generation_word().load(Ordering::SeqCst)
}

/// Invalidate every process's resolve cache by bumping the shared generation.
/// Call from every structural fs mutation (mkdir/rmdir/rename/symlink/link/
/// unlink/mknod/create), NOT from content writes.
pub fn bump_generation() {
    generation_word().fetch_add(1, Ordering::SeqCst);
}

/// Per-process resolve cache, validated against the shared generation. The map
/// itself is fork-copied like the rest of the address space; the shared
/// generation is what makes stale copies re-resolve.
pub struct ResolveCache {
    map: RwLock<HashMap<String, (String, u64)>>,
}

/// Bound the map so a path-diverse workload can't grow it without limit; the
/// hot case (a loop on one path) stays tiny well under this.
const MAX_ENTRIES: usize = 8192;

impl Default for ResolveCache {
    fn default() -> Self {
        Self::new()
    }
}

impl ResolveCache {
    pub fn new() -> Self {
        Self {
            map: RwLock::new(HashMap::new()),
        }
    }

    /// The cached resolution for `key`, or `None` if absent or STALE — its
    /// stamped generation no longer matches `current` (the caller passes the
    /// live [`current_generation`], read at the get, so a mutation between an
    /// entry's birth and this lookup invalidates it).
    pub fn get(&self, key: &str, current: u64) -> Option<String> {
        let guard = self.map.read().ok()?;
        match guard.get(key) {
            Some((abs, stamped)) if *stamped == current => Some(abs.clone()),
            _ => None,
        }
    }

    /// Cache `key` -> `abs`, stamped with `gen_at_lookup` — the generation
    /// sampled BEFORE the resolve read any fs state. If a structural mutation
    /// bumped the shared generation DURING the resolve (a sibling racing this
    /// lookup), `gen_at_lookup` is already behind and the entry is born stale,
    /// so a racing pre-mutation resolution is never served. (Seqlock-style: the
    /// mutation side bumps AFTER it completes; the reader stamps the value it
    /// saw at entry.)
    pub fn put(&self, key: String, abs: String, gen_at_lookup: u64) {
        let stamped = gen_at_lookup;
        if let Ok(mut guard) = self.map.write() {
            if guard.len() >= MAX_ENTRIES && !guard.contains_key(&key) {
                // Cheapest bound: drop everything rather than track LRU. The hot
                // loops re-warm instantly; only a pathologically path-diverse
                // workload ever trips this.
                guard.clear();
            }
            guard.insert(key, (abs, stamped));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hit_is_served_until_the_generation_moves_on() {
        let c = ResolveCache::new();
        c.put("/tmp/x/file".into(), "/tmp/x/file".into(), 5);
        // Same generation -> hit.
        assert_eq!(c.get("/tmp/x/file", 5).as_deref(), Some("/tmp/x/file"));
        // A structural mutation advanced the generation -> stale -> miss.
        assert_eq!(c.get("/tmp/x/file", 6), None);
        // Re-populating at the new generation -> hit again.
        c.put("/tmp/x/file".into(), "/tmp/x/file".into(), 6);
        assert_eq!(c.get("/tmp/x/file", 6).as_deref(), Some("/tmp/x/file"));
    }

    #[test]
    fn a_mutation_racing_the_lookup_births_a_stale_entry() {
        // The reader sampled generation 5 at entry; a sibling's structural
        // mutation advanced it to 6 DURING the resolve; the reader stores with
        // its stale sample. A get at the current generation (6) must miss, so
        // the racing pre-mutation resolution is never served.
        let c = ResolveCache::new();
        c.put("/raced".into(), "/raced".into(), 5);
        assert_eq!(c.get("/raced", 6), None);
    }

    #[test]
    fn absent_key_misses() {
        let c = ResolveCache::new();
        assert_eq!(c.get("/never/put", 1), None);
    }

    #[test]
    fn shared_generation_advances_monotonically() {
        // Robust under parallel tests: fetch_add is monotonic even if other
        // tests bump concurrently.
        let a = current_generation();
        bump_generation();
        assert!(current_generation() > a);
    }
}
