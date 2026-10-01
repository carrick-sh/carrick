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
//! In lanes that fork the HOST process, an
//! in-process map is NOT fork-coherent: a sibling that renames/creates/deletes
//! a directory would leave every other process's cache serving a stale resolve.
//! We fix that with a **generation counter in a `MAP_SHARED` page** (the same
//! trick as the alias-IPA allocator): every structural fs mutation — in ANY
//! process within the backing cohort — bumps its shared word, and a cache entry is valid only while
//! its stamped generation still equals the current shared generation. A stale
//! entry re-resolves. Content writes do NOT bump it (they can't change a path's
//! resolution); only structural changes (mkdir/rmdir/rename/symlink/link/
//! unlink/mknod/create) do.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

use parking_lot::RwLock;

/// Index of the path-resolution generation within the shared page.
const PATH_GENERATION_SLOT: usize = 0;
/// Index of the directory-topology generation within the shared page. Kept in
/// the SAME page as the path generation so one `mmap` serves both and both are
/// equally fork-shared.
const DIR_GENERATION_SLOT: usize = 1;
/// Index of the sandbox-root MARKER generation within the shared page — see
/// [`FsCacheCoherence::current_marker_generation`].
const MARKER_GENERATION_SLOT: usize = 2;
/// Index of the guest-METADATA generation within the shared page — see
/// [`FsCacheCoherence::current_meta_generation`].
const META_GENERATION_SLOT: usize = 3;
/// Number of generation words in the shared page.
const GENERATION_SLOTS: usize = 4;

/// Generation authority for one admitted backing-filesystem cohort.
/// Anonymous MAP_SHARED words survive host fork, but not host self-reexec.
/// Reexec admission deliberately creates a fresh cohort, preserving the
/// previous anonymous-mapping boundary; no mapping is transported in the capsule.
pub struct FsCacheCoherence {
    words: std::ptr::NonNull<AtomicU64>,
    local_path_bumps: AtomicU64,
}

// SAFETY: the mapping is owned until Drop and is accessed only through atomics.
unsafe impl Send for FsCacheCoherence {}
// SAFETY: concurrent access to shared words and local counters is atomic.
unsafe impl Sync for FsCacheCoherence {}

impl Default for FsCacheCoherence {
    fn default() -> Self {
        // SAFETY: request a new writable anonymous shared mapping, owned by
        // this authority and inherited by real host-fork descendants.
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
            // A private fallback would silently destroy cross-fork coherence.
            std::alloc::handle_alloc_error(
                std::alloc::Layout::new::<[AtomicU64; GENERATION_SLOTS]>(),
            );
        }
        let words =
            std::ptr::NonNull::new(p.cast::<AtomicU64>()).unwrap_or_else(|| std::process::abort());
        for slot in 0..GENERATION_SLOTS {
            // SAFETY: four aligned AtomicU64s fit in the owned writable mapping.
            unsafe {
                words.as_ptr().add(slot).write(AtomicU64::new(1));
            }
        }
        ensure_atfork_installed();
        Self {
            words,
            local_path_bumps: AtomicU64::new(0),
        }
    }
}

impl Drop for FsCacheCoherence {
    fn drop(&mut self) {
        // SAFETY: the last owner releases this process's mapping only. Forked
        // descendants retain their own virtual mapping of the shared backing.
        unsafe {
            libc::munmap(self.words.as_ptr().cast(), 4096);
        }
    }
}

impl FsCacheCoherence {
    fn generation_word_at(&self, slot: usize) -> &AtomicU64 {
        debug_assert!(slot < GENERATION_SLOTS);
        // SAFETY: slot is one of the four module constants; mapping lives as
        // long as this authority and references cannot outlive it.
        unsafe { &*self.words.as_ptr().add(slot) }
    }
    fn generation_word(&self) -> &AtomicU64 {
        self.generation_word_at(PATH_GENERATION_SLOT)
    }
    pub(crate) fn local_path_bump_count(&self) -> u64 {
        self.local_path_bumps.load(Ordering::SeqCst)
    }
    #[cfg(test)]
    pub(crate) fn simulate_sibling_path_bump(&self) {
        self.generation_word().fetch_add(1, Ordering::SeqCst);
    }
    /// Current fs-structure generation. A cache entry stamped with this value is
    /// valid until the next structural mutation.
    pub fn current_generation(&self) -> u64 {
        self.generation_word().load(Ordering::SeqCst)
    }

    /// Invalidate every process's resolve cache by bumping the shared generation.
    /// Call from every structural fs mutation (mkdir/rmdir/rename/symlink/link/
    /// unlink/mknod/create), NOT from content writes.
    pub fn bump_generation(&self) {
        self.generation_word().fetch_add(1, Ordering::SeqCst);
        self.local_path_bumps.fetch_add(1, Ordering::SeqCst);
    }

    /// Current DIRECTORY-TOPOLOGY generation — the one the kernel's directory
    /// cache stamps its open dirfds with.
    ///
    /// This is deliberately a SECOND, much slower-moving counter than
    /// [`FsCacheCoherence::current_generation`]. A cached dirfd names an *inode*, so it is only
    /// invalidated by an operation that can change which inode an existing
    /// directory PATH names: a rename or exchange involving a directory, and a
    /// directory removal. Creating a file, writing one, unlinking one, or creating
    /// a new directory cannot — a new name cannot re-point an existing one.
    ///
    /// That distinction is what makes a directory cache viable on a build
    /// workload. A cold `go build` performs thousands of file creations and
    /// unlinks, every one of which bumps the path generation and so flushes the
    /// resolve cache; almost none of them touch directory topology, so the dirfds
    /// survive and the walk they replace is never repaid.
    pub fn current_dir_generation(&self) -> u64 {
        self.generation_word_at(DIR_GENERATION_SLOT)
            .load(Ordering::SeqCst)
    }

    /// Invalidate every process's directory cache. Call ONLY from an operation
    /// that can re-point an existing directory path — rename/exchange where either
    /// side is a directory, and directory removal (including a whiteout that hides
    /// one). See [`FsCacheCoherence::current_dir_generation`] for why the set is this narrow.
    ///
    /// Returns the generation this call established. A caller that knows EXACTLY
    /// which of its own cached entries the mutation invalidated can re-stamp the
    /// survivors with this value (see
    /// `HostFsBackend::evict_dir_cache_subtree_restamping`) instead of paying the
    /// global invalidation it just imposed on every other process. Using the
    /// returned value rather than a fresh `current_dir_generation()` read is what
    /// makes that sound: if a SIBLING process bumps in between, the survivors stay
    /// stamped at the older value and are correctly invalidated on their next read.
    pub fn bump_dir_generation(&self) -> u64 {
        self.generation_word_at(DIR_GENERATION_SLOT)
            .fetch_add(1, Ordering::SeqCst)
            + 1
    }

    /// Current sandbox-root MARKER generation — the one the host backend's
    /// "no FIFO / marker node / metadata xattr / whiteout / symlink anywhere in
    /// the upper" answers are stamped with.
    ///
    /// A third, near-static counter. Those answers are read from durable root
    /// xattrs that only ever go absent → present, and only a marker STAMP
    /// (`stamp_root_marker`) can change one; a file creation or unlink cannot.
    /// Keying the absent readings on [`FsCacheCoherence::current_generation`] instead made every
    /// structural mutation invalidate all five, so a create/unlink loop re-read
    /// the root xattr (`openat`+`fgetxattr`+`close`) several times per guest
    /// syscall — 3 of the 12 host opens behind one guest `unlink`.
    pub fn current_marker_generation(&self) -> u64 {
        self.generation_word_at(MARKER_GENERATION_SLOT)
            .load(Ordering::SeqCst)
    }

    /// Invalidate every process's absent-marker readings. Call ONLY after a root
    /// marker xattr has been stamped present (the stamp first, then the bump, so
    /// a reader that sampled the old generation before the stamp is born stale).
    pub fn bump_marker_generation(&self) {
        self.generation_word_at(MARKER_GENERATION_SLOT)
            .fetch_add(1, Ordering::SeqCst);
    }

    /// Current guest-METADATA generation — the one the host backend's stat cache
    /// stamps each entry with.
    ///
    /// A cached `RealStat` carries fields the host inode cannot answer: the guest
    /// mode override, owner uid/gid, and the AF_UNIX-socket marker, all read from
    /// carrick's own `user.carrick.*` xattrs. Their ONLY writers are carrick's
    /// own metadata helpers, and every one bumps this word after writing. So an
    /// entry stamped with the current value still holds those fields even when
    /// the inode's ctime/mtime/size moved — a directory gaining or losing a
    /// child, a file being appended — and revalidation can serve it with just the
    /// fresh volatile fields instead of refilling (a second `fstatat` plus an
    /// `openat`+`flistxattr`+`close` xattr pass). A create/unlink loop used to pay
    /// that refill for the parent directory on every iteration.
    pub fn current_meta_generation(&self) -> u64 {
        self.generation_word_at(META_GENERATION_SLOT)
            .load(Ordering::SeqCst)
    }

    /// Invalidate every process's cached guest-metadata readings. Call from every
    /// writer of a `user.carrick.*` metadata xattr (mode/uid/gid/socket/rdev), set
    /// OR remove, AFTER the write lands — a reader that stamped the old generation
    /// before the write then revalidates through a refill.
    pub fn bump_meta_generation(&self) {
        self.generation_word_at(META_GENERATION_SLOT)
            .fetch_add(1, Ordering::SeqCst);
    }
}

/// Process-local generation counter. Incremented whenever this process is
/// created via a host fork (`pthread_atfork` child callback, or explicit hook in
/// `carrier::reset_after_fork_child` and `reinit_after_fork`).
/// Used by in-process caches to detect fork without issuing `libc::getpid()`.
static PROCESS_GENERATION: AtomicU64 = AtomicU64::new(1);

static ATFORK_INIT: std::sync::Once = std::sync::Once::new();

fn ensure_atfork_installed() {
    ATFORK_INIT.call_once(|| {
        extern "C" fn atfork_child() {
            bump_process_generation();
        }
        unsafe {
            libc::pthread_atfork(None, None, Some(atfork_child));
        }
    });
}

/// Current process generation. Validated by caches to detect fork without `libc::getpid()`.
pub fn current_process_generation() -> u64 {
    ensure_atfork_installed();
    PROCESS_GENERATION.load(Ordering::Relaxed)
}

/// Advance the process generation after a host fork.
pub fn bump_process_generation() {
    PROCESS_GENERATION.fetch_add(1, Ordering::Relaxed);
}

/// Install process-fork detection. Cohort words are allocated eagerly by
/// FsCacheCoherence construction, so no process-global mapping is needed.
pub fn init() {
    ensure_atfork_installed();
}

/// Per-process resolve cache, validated against the shared generation. The map
/// itself is fork-copied like the rest of the address space; the shared
/// generation is what makes stale copies re-resolve.
pub struct ResolveCache {
    pub coherence: std::sync::Arc<FsCacheCoherence>,
    map: RwLock<HashMap<String, (String, u64)>>,
}

/// Bound the map so a path-diverse workload can't grow it without limit; the
/// hot case (a loop on one path) stays tiny well under this.
const MAX_ENTRIES: usize = 8192;

impl Default for ResolveCache {
    fn default() -> Self {
        Self::new(std::sync::Arc::default())
    }
}

impl ResolveCache {
    pub fn new(coherence: std::sync::Arc<FsCacheCoherence>) -> Self {
        Self {
            coherence,
            map: RwLock::new(HashMap::new()),
        }
    }

    /// The cached resolution for `key`, or `None` if absent or STALE — its
    /// stamped generation no longer matches `current` (the caller passes the
    /// live [`FsCacheCoherence::current_generation`], read at the get, so a mutation between an
    /// entry's birth and this lookup invalidates it).
    pub fn get(&self, key: &str, current: u64) -> Option<String> {
        let guard = self.map.read();
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
        let mut guard = self.map.write();
        if guard.len() >= MAX_ENTRIES && !guard.contains_key(&key) {
            // Cheapest bound: drop everything rather than track LRU. The hot
            // loops re-warm instantly; only a pathologically path-diverse
            // workload ever trips this.
            guard.clear();
        }
        guard.insert(key, (abs, stamped));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hit_is_served_until_the_generation_moves_on() {
        let c = ResolveCache::new(std::sync::Arc::default());
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
        let c = ResolveCache::new(std::sync::Arc::default());
        c.put("/raced".into(), "/raced".into(), 5);
        assert_eq!(c.get("/raced", 6), None);
    }

    #[test]
    fn absent_key_misses() {
        let c = ResolveCache::new(std::sync::Arc::default());
        assert_eq!(c.get("/never/put", 1), None);
    }

    #[test]
    fn shared_generation_advances_monotonically() {
        let cohort = FsCacheCoherence::default();
        // Robust under parallel tests: fetch_add is monotonic even if other
        // tests bump concurrently.
        let a = cohort.current_generation();
        cohort.bump_generation();
        assert!(cohort.current_generation() > a);
    }

    #[test]
    fn dir_generation_advances_monotonically() {
        let cohort = FsCacheCoherence::default();
        let a = cohort.current_dir_generation();
        cohort.bump_dir_generation();
        assert!(cohort.current_dir_generation() > a);
    }

    #[test]
    fn path_and_dir_generations_are_independent_words() {
        let cohort = FsCacheCoherence::default();
        // The whole point of the second counter: a file create/unlink storm
        // must NOT flush the directory cache. Bumping the path generation
        // leaves the dir generation exactly where it was.
        //
        // Only the dir side is asserted stable — another test bumping the path
        // generation concurrently is harmless, but a concurrent
        // `bump_dir_generation` would be a real aliasing bug, and this test
        // would catch it.
        let dir_before = cohort.current_dir_generation();
        cohort.bump_generation();
        cohort.bump_generation();
        assert_eq!(cohort.current_dir_generation(), dir_before);
    }
}
