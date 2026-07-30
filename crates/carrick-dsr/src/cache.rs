//! Translation-cache and publication machinery shared by every native lane.
//!
//! Moved from `carrick-runtime/src/native_darwin/dsr/cache.rs` as part of the
//! staged native-backend extraction (see
//! docs/superpowers/specs/2026-07-17-native-backend-portability-seams-design.md).
//! Host-OS specifics (MAP_JIT, per-thread W^X toggles, icache maintenance)
//! are routed through the [`NativeHostJit`] seam; guest-ISA specifics (the
//! AArch64 `B` encoding for direct links) stay with the runtime's arch layer,
//! which hands this module fully encoded words via
//! [`TranslationCache::patch_code_word`].

use std::collections::BTreeMap;
use std::ops::Range;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use carrick_guest_mem::{GuestVa, HostVa};
use parking_lot::{Condvar, Mutex, RwLock};

use crate::host::{JitRegion, NativeHostJit};
use crate::ids::{CacheOffset, CacheVa, CodeGeneration};

/// Typed cache errors. The runtime maps these 1:1 back onto its `DsrError`
/// counterparts (`CachePolicy`, `CacheCapacity`, `GenerationChanged`, `Host`)
/// with identical display strings, so `?` sites there are unchanged.
#[derive(Debug, thiserror::Error)]
pub enum CacheError {
    #[error("DSR cache policy error: {0}")]
    Policy(String),
    #[error(
        "DSR translation cache exhausted: requested={requested} used={used} capacity={capacity}"
    )]
    Capacity {
        requested: usize,
        used: usize,
        capacity: usize,
    },
    #[error(
        "DSR executable page 0x{page:x} changed generation: expected {expected:?}, observed {observed:?}"
    )]
    GenerationChanged {
        page: u64,
        expected: u64,
        observed: u64,
    },
    #[error("DSR host operation {operation} failed: {error}")]
    Host {
        operation: &'static str,
        error: std::io::Error,
    },
}

pub struct PageGenerationTable {
    page_size: u64,
    next: AtomicU64,
    pages: RwLock<BTreeMap<GuestVa, Arc<AtomicU64>>>,
}

#[derive(Clone)]
pub struct PageGenerationObservation {
    page: GuestVa,
    expected: CodeGeneration,
    current: Arc<AtomicU64>,
}

impl PageGenerationObservation {
    pub const fn page(&self) -> GuestVa {
        self.page
    }

    pub const fn expected(&self) -> CodeGeneration {
        self.expected
    }

    pub fn current(&self) -> CodeGeneration {
        CodeGeneration::claimed(self.current.load(Ordering::Acquire))
    }

    pub fn current_atomic(&self) -> &AtomicU64 {
        &self.current
    }
}

impl PageGenerationTable {
    pub fn new(page_size: u64) -> Result<Self, CacheError> {
        if page_size == 0 || !page_size.is_power_of_two() {
            return Err(CacheError::Policy(format!(
                "DSR generation page size must be a nonzero power of two, got {page_size}"
            )));
        }
        Ok(Self {
            page_size,
            next: AtomicU64::new(CodeGeneration::INITIAL.get()),
            pages: RwLock::new(BTreeMap::new()),
        })
    }

    pub fn note_guest_code_write(
        &self,
        range: Range<GuestVa>,
    ) -> Result<CodeGeneration, CacheError> {
        if range.start.raw() >= range.end.raw() {
            return Err(CacheError::Policy(format!(
                "DSR code mutation range is empty or reversed: 0x{:x}..0x{:x}",
                range.start.raw(),
                range.end.raw()
            )));
        }
        let generation = self
            .next
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current.checked_add(1)
            })
            .map(|previous| CodeGeneration::claimed(previous + 1))
            .map_err(|_| CacheError::Policy("DSR code generation overflow".to_string()))?;
        let page_mask = self.page_size - 1;
        let mut page = range.start.raw() & !page_mask;
        let last = range.end.raw().saturating_sub(1) & !page_mask;
        let mut pages = self.pages.write();
        loop {
            pages
                .entry(GuestVa(page))
                .or_insert_with(|| Arc::new(AtomicU64::new(CodeGeneration::INITIAL.get())))
                .store(generation.get(), Ordering::Release);
            if page == last {
                break;
            }
            page = page.checked_add(self.page_size).ok_or_else(|| {
                CacheError::Policy("DSR generation page range overflow".to_string())
            })?;
        }
        Ok(generation)
    }

    pub fn invalidate_page(
        &self,
        page: GuestVa,
        generation: CodeGeneration,
    ) -> Result<(), CacheError> {
        let page = GuestVa(page.raw() & !(self.page_size - 1));
        let observed = self.generation_for_pc(page)?;
        if observed != generation {
            return Err(CacheError::GenerationChanged {
                page: page.raw(),
                expected: generation.get(),
                observed: observed.get(),
            });
        }
        Ok(())
    }

    pub fn generation_for_pc(&self, pc: GuestVa) -> Result<CodeGeneration, CacheError> {
        let page = GuestVa(pc.raw() & !(self.page_size - 1));
        Ok(self
            .pages
            .read()
            .get(&page)
            .map(|generation| CodeGeneration::claimed(generation.load(Ordering::Acquire)))
            .unwrap_or(CodeGeneration::INITIAL))
    }

    pub fn observe(&self, pc: GuestVa) -> Result<PageGenerationObservation, CacheError> {
        let page = GuestVa(pc.raw() & !(self.page_size - 1));
        let mut pages = crate::probes::acquire_with_synchronization_reason(
            crate::probes::DsrSynchronizationKind::GenerationTableWrite,
            || self.pages.write(),
        );
        let current = pages
            .entry(page)
            .or_insert_with(|| Arc::new(AtomicU64::new(CodeGeneration::INITIAL.get())))
            .clone();
        let expected = CodeGeneration::claimed(current.load(Ordering::Acquire));
        Ok(PageGenerationObservation {
            page,
            expected,
            current,
        })
    }

    pub fn is_current(&self, pc: GuestVa, generation: CodeGeneration) -> Result<bool, CacheError> {
        Ok(self.generation_for_pc(pc)? == generation)
    }

    pub fn fork_view(&self) -> Self {
        let pages = self
            .pages
            .read()
            .iter()
            .map(|(page, generation)| {
                (
                    *page,
                    Arc::new(AtomicU64::new(generation.load(Ordering::Acquire))),
                )
            })
            .collect();
        Self {
            page_size: self.page_size,
            next: AtomicU64::new(self.next.load(Ordering::Acquire)),
            pages: RwLock::new(pages),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LinkSite {
    pub source: CacheVa,
    pub slot: CacheOffset,
}

#[derive(Default)]
pub struct PageBlockDependencies {
    blocks: BTreeMap<GuestVa, Vec<(GuestVa, CodeGeneration)>>,
}

#[derive(Clone, Copy)]
enum PublicationState {
    Building,
    Published(CacheVa),
}

/// Fired on the duplicate-publication wait path of
/// [`ConcurrentPublicationIndex::get_or_publish_observed`]. The runtime's
/// caller turns these into its USDT translation-subphase probes; this crate
/// stays probe-free.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PublicationWaitEvent {
    WaitBegin,
    WaitEnd,
}

#[derive(Default)]
pub struct ConcurrentPublicationIndex {
    state: Mutex<BTreeMap<(GuestVa, CodeGeneration), PublicationState>>,
    changed: Condvar,
    builders: AtomicU64,
}

impl ConcurrentPublicationIndex {
    pub fn get_or_publish(
        &self,
        key: (GuestVa, CodeGeneration),
        build: impl FnOnce() -> CacheVa,
    ) -> CacheVa {
        self.get_or_publish_with_wait_hooks(key, build, || {}, || {})
    }

    /// Like [`Self::get_or_publish`], but reports duplicate-wait begin/end to
    /// `wait_observer` so the caller can account the blocked time (the
    /// runtime fires its `DsrTranslationSubphase::DuplicateWait` probes from
    /// the observer).
    pub fn get_or_publish_observed(
        &self,
        key: (GuestVa, CodeGeneration),
        build: impl FnOnce() -> CacheVa,
        wait_observer: &dyn Fn(PublicationWaitEvent),
    ) -> CacheVa {
        self.get_or_publish_with_wait_hooks(
            key,
            build,
            || wait_observer(PublicationWaitEvent::WaitBegin),
            || wait_observer(PublicationWaitEvent::WaitEnd),
        )
    }

    fn get_or_publish_with_wait_hooks(
        &self,
        key: (GuestVa, CodeGeneration),
        build: impl FnOnce() -> CacheVa,
        mut wait_begin: impl FnMut(),
        mut wait_end: impl FnMut(),
    ) -> CacheVa {
        let mut state = self.state.lock();
        loop {
            match state.get(&key).copied() {
                Some(PublicationState::Published(entry)) => return entry,
                Some(PublicationState::Building) => {
                    wait_begin();
                    self.changed.wait(&mut state);
                    wait_end();
                }
                None => {
                    state.insert(key, PublicationState::Building);
                    break;
                }
            }
        }
        drop(state);
        self.builders.fetch_add(1, Ordering::Relaxed);
        let entry = build();
        let mut state = self.state.lock();
        state.insert(key, PublicationState::Published(entry));
        self.changed.notify_all();
        entry
    }

    pub fn after_fork_child(&self) {
        self.state
            .lock()
            .retain(|_, state| matches!(state, PublicationState::Published(_)));
        self.changed.notify_all();
    }

    pub fn reset_for_exec(&self) {
        self.state.lock().clear();
        self.changed.notify_all();
    }

    // `test-hooks` + pub (not crate-private `cfg(test)`): the runtime's
    // native test module reads this cross-crate — see `crate::test_hooks`.
    #[cfg(any(test, feature = "test-hooks"))]
    pub fn published_count(&self) -> usize {
        self.state
            .lock()
            .values()
            .filter(|state| matches!(state, PublicationState::Published(_)))
            .count()
    }

    #[cfg(test)]
    pub(crate) fn builder_count(&self) -> u64 {
        self.builders.load(Ordering::Relaxed)
    }
}

impl PageBlockDependencies {
    pub fn page_count(&self) -> usize {
        self.blocks.len()
    }

    pub fn record(&mut self, page: GuestVa, block: GuestVa, generation: CodeGeneration) {
        let blocks = self.blocks.entry(page).or_default();
        if !blocks.contains(&(block, generation)) {
            blocks.push((block, generation));
        }
    }

    pub fn invalidate_page(
        &mut self,
        page: GuestVa,
        current: CodeGeneration,
    ) -> Vec<(GuestVa, CodeGeneration)> {
        let Some(blocks) = self.blocks.get_mut(&page) else {
            return Vec::new();
        };
        let mut stale = Vec::new();
        blocks.retain(|dependency| {
            if dependency.1 == current {
                true
            } else {
                stale.push(*dependency);
                false
            }
        });
        stale
    }

    #[cfg(test)]
    pub(crate) fn contains(
        &self,
        page: GuestVa,
        block: GuestVa,
        generation: CodeGeneration,
    ) -> bool {
        self.blocks
            .get(&page)
            .is_some_and(|blocks| blocks.contains(&(block, generation)))
    }
}

pub struct PublishedCode {
    entry: CacheVa,
    len: usize,
}

impl PublishedCode {
    pub const fn entry(&self) -> CacheVa {
        self.entry
    }

    pub const fn len(&self) -> usize {
        self.len
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

pub struct TranslationCache {
    host: &'static dyn NativeHostJit,
    region: JitRegion,
    cursor: usize,
    /// `true` for a cache built by [`Self::new`], which mapped `region`
    /// itself and must unmap it on `Drop`. `false` for one built by
    /// [`Self::from_region`], which BORROWS an already-mapped region owned
    /// by some other, longer-lived reservation (e.g. one private slice of a
    /// process-wide code cache the caller carves into several
    /// independently-cursored regions) -- unmapping `region` on drop there
    /// would tear down memory a sibling still owns.
    owns_mapping: bool,
}

// SAFETY: the mapping is process-wide and contains no thread-affine pointer
// provenance, and `host` is a `'static` reference to a stateless
// `NativeHostJit` implementation (per the trait contract every method is safe
// to call from any thread; thread-write windows are per-thread hardware or
// no-op state, never state on this struct). Every mutation, including the
// thread-local write-enable window, is serialized by
// `ProcessTranslator::state`; published instructions are immutable except for
// aligned atomic direct-link patches under that same lock.
unsafe impl Send for TranslationCache {}

// SAFETY: `ProcessTranslator::state` is a `RwLock<ProcessState>`, so any
// `&TranslationCache` obtained through it (via a read guard) can be held
// concurrently by multiple threads, but NEVER at the same time as a `&mut
// TranslationCache` (a write guard) -- the RwLock enforces reader/writer
// mutual exclusion with the necessary acquire/release synchronization. The
// `&self` accessors this type exposes (`used_bytes`, `capacity_bytes`,
// `host_range`, `contains_host_pc`) only read `host`/`region` (fixed at
// construction, never mutated afterward) and `cursor` (mutated only by
// `&mut self` methods, i.e. only under the write lock). The one other
// `&self` method, `after_fork_child`, writes NO `self` field -- it only
// repairs the CALLING thread's per-thread write-protection state through the
// stateless host implementation (`NativeHostJit` contract: implementations
// hold no shared mutable state; write windows are per-thread) -- so it
// cannot race another thread on this struct's memory. So concurrent
// `&self` reads across threads never race a writer, and never race each
// other (plain reads of the same memory are data-race-free). A second
// consumer, x86's `TranslationCache::from_region` caches, are not behind an
// RwLock; their soundness rests on exclusive per-thread ownership (one
// thread owns each slice, enforced by the platform's thread architecture).
// Direct-link patches into the JIT buffer's *contents* (as opposed to these
// struct fields) still go through `AtomicU32` stores with `Release` ordering
// plus an icache flush, unchanged by this impl and only ever issued under the
// same write lock.
unsafe impl Sync for TranslationCache {}

impl TranslationCache {
    pub fn new(
        requested_capacity: usize,
        host: &'static dyn NativeHostJit,
    ) -> Result<Self, CacheError> {
        if requested_capacity == 0 {
            return Err(CacheError::Policy(
                "translation cache capacity must be nonzero".to_string(),
            ));
        }
        host.supported()
            .map_err(|reason| CacheError::Policy(reason.to_string()))?;
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        if page_size <= 0 {
            return Err(CacheError::Host {
                operation: "query host page size",
                error: std::io::Error::last_os_error(),
            });
        }
        let page_size = page_size as usize;
        let capacity = requested_capacity
            .checked_add(page_size - 1)
            .map(|value| value & !(page_size - 1))
            .ok_or_else(|| CacheError::Policy("translation cache size overflow".to_string()))?;
        let region = host
            .map_code_cache(capacity)
            .map_err(|error| CacheError::Host {
                operation: "allocate MAP_JIT translation cache",
                error,
            })?;
        host.end_thread_write();
        Ok(Self {
            host,
            region,
            cursor: 0,
            owns_mapping: true,
        })
    }

    /// Build a translation cache over a region that is ALREADY mapped and
    /// owned elsewhere -- skips [`NativeHostJit::map_code_cache`] entirely
    /// (no page-rounding, no fresh allocation) and starts empty (`cursor =
    /// 0`). A new sibling to [`Self::new`], not a replacement: existing
    /// callers of `new` are completely unaffected.
    ///
    /// This is the seam a lane whose guest threads do NOT yet share one
    /// cache uses to get typed capacity/publish machinery per thread without
    /// asking the host to map a fresh region per thread: carve one big
    /// reservation into per-thread slices with [`JitRegion::sub_region`] and
    /// wrap each slice in its own `TranslationCache::from_region`. Because
    /// `region` is borrowed, NOT owned, dropping the returned cache never
    /// unmaps it -- the caller that produced `region` keeps sole unmap
    /// responsibility for the reservation it carved it from.
    pub fn from_region(region: JitRegion, host: &'static dyn NativeHostJit) -> Self {
        host.end_thread_write();
        Self {
            host,
            region,
            cursor: 0,
            owns_mapping: false,
        }
    }

    pub fn reset_after_fork_for_exec(&mut self) {
        // The sole surviving child thread inherits the code-cache mapping and
        // no cache writer can be live across the quiesced fork. Reuse the
        // mapping instead of asking the host to map again in the fork child.
        self.host.end_thread_write();
        self.cursor = 0;
    }

    pub fn begin_write(&mut self, len: usize) -> Result<CacheWriter<'_>, CacheError> {
        if len == 0 || !len.is_multiple_of(std::mem::size_of::<u32>()) {
            return Err(CacheError::Policy(format!(
                "translation cache write length must be a nonzero instruction multiple, got {len}"
            )));
        }
        let end = self
            .cursor
            .checked_add(len)
            .ok_or_else(|| CacheError::Policy("translation cache cursor overflow".to_string()))?;
        if end > self.region.capacity {
            return Err(CacheError::Capacity {
                requested: len,
                used: self.cursor,
                capacity: self.region.capacity,
            });
        }
        let start = self.cursor;
        self.host.begin_thread_write();
        Ok(CacheWriter {
            cache: self,
            start,
            len,
            written: 0,
            write_enabled: true,
        })
    }

    pub fn publish_words(&mut self, words: &[u32]) -> Result<PublishedCode, CacheError> {
        let len = words
            .len()
            .checked_mul(std::mem::size_of::<u32>())
            .ok_or_else(|| CacheError::Policy("artifact replay length overflow".to_string()))?;
        let mut writer = self.begin_write(len)?;
        writer.write_words(words)?;
        writer.publish()
    }

    /// Repair the per-thread code-cache protection state inherited by the
    /// sole surviving thread after `fork(2)`.  Quiescence guarantees no
    /// writer is live at the fork instant, so the child always starts
    /// executable-only.
    pub fn after_fork_child(&self) {
        self.host.end_thread_write();
    }

    pub fn contains_host_pc(&self, pc: HostVa) -> bool {
        let start = self.region.exec_base.as_ptr() as usize;
        let end = start.saturating_add(self.cursor);
        (start..end).contains(&pc.raw())
    }

    pub fn host_range(&self) -> Range<usize> {
        let start = self.region.exec_base.as_ptr() as usize;
        start..start.saturating_add(self.region.capacity)
    }

    pub const fn used_bytes(&self) -> usize {
        self.cursor
    }

    pub const fn capacity_bytes(&self) -> usize {
        self.region.capacity
    }

    /// Patch one already-published instruction word at a direct-link site.
    ///
    /// Guest-ISA-neutral: the caller (the runtime's arch layer) encodes the
    /// word -- e.g. an AArch64 `B` for a direct link -- and this method only
    /// checks alignment, performs the aligned atomic `Release` store through
    /// the write alias, and flushes the icache at the EXEC address, in that
    /// order (matching the pre-extraction Darwin behavior).
    pub fn patch_code_word(&mut self, site: LinkSite, word: u32) -> Result<(), CacheError> {
        let source = site
            .source
            .host()
            .raw()
            .checked_add(site.slot.get() as usize)
            .ok_or_else(|| CacheError::Policy("direct-link source overflow".to_string()))?;
        if !source.is_multiple_of(4) {
            return Err(CacheError::Policy(format!(
                "direct-link source is not instruction aligned: 0x{source:x}"
            )));
        }
        let destination = self
            .region
            .write_ptr_for(source as *mut u8)
            .ok_or_else(|| {
                CacheError::Policy(format!(
                    "direct-link site is outside the translation cache: 0x{source:x}"
                ))
            })?;
        self.host.begin_thread_write();
        // SAFETY: `destination` is 4-aligned (checked above) and inside the
        // write alias of the mapped region (checked by `write_ptr_for`).
        let instruction = unsafe { &*(destination as *const AtomicU32) };
        instruction.store(word, Ordering::Release);
        self.host.flush_icache(source as *const u8, 4);
        self.host.end_thread_write();
        Ok(())
    }

    /// Test-support patch of an arbitrary published word (compiled
    /// unconditionally so the runtime's `#[cfg(test)]` consumers can reach it
    /// across the crate boundary).
    pub fn patch_word_for_test(
        &mut self,
        instruction: CacheVa,
        word: u32,
    ) -> Result<(), CacheError> {
        let address = instruction.host().raw();
        if !address.is_multiple_of(4) || !self.contains_host_pc(HostVa(address)) {
            return Err(CacheError::Policy(format!(
                "test patch address is outside published cache: 0x{address:x}"
            )));
        }
        let destination = self
            .region
            .write_ptr_for(address as *mut u8)
            .ok_or_else(|| {
                CacheError::Policy(format!(
                    "test patch address is outside published cache: 0x{address:x}"
                ))
            })?;
        self.host.begin_thread_write();
        // SAFETY: `destination` is 4-aligned (checked above) and inside the
        // write alias of the mapped region (checked by `write_ptr_for`).
        let instruction = unsafe { &*(destination as *const AtomicU32) };
        instruction.store(word, Ordering::Release);
        self.host.flush_icache(address as *const u8, 4);
        self.host.end_thread_write();
        Ok(())
    }
}

impl Drop for TranslationCache {
    fn drop(&mut self) {
        self.host.end_thread_write();
        if !self.owns_mapping {
            // Built via `from_region`: `self.region` is a borrowed slice of
            // someone else's longer-lived reservation. That owner (not this
            // cache) is responsible for unmapping it, on its own schedule --
            // typically well after this cache has been dropped and its slice
            // recycled for a new occupant.
            return;
        }
        // SAFETY: dropping the cache is the single teardown point; the
        // runtime guarantees no thread still executes from or holds pointers
        // into the region (the `NativeHostJit::unmap` contract).
        unsafe { self.host.unmap(&self.region) };
    }
}

pub struct CacheWriter<'a> {
    cache: &'a mut TranslationCache,
    start: usize,
    len: usize,
    written: usize,
    write_enabled: bool,
}

impl CacheWriter<'_> {
    /// The reservation's EXEC entry address, known BEFORE the words are
    /// written. A trampoline whose last word is a `b` to a known target must
    /// encode a displacement from its own address, so it needs this before it
    /// can build the words it is about to write.
    pub fn entry(&self) -> CacheVa {
        // SAFETY: `start` is inside the mapped region (reserved by
        // `begin_write`).
        let ptr = unsafe { self.cache.region.exec_base.as_ptr().add(self.start) };
        CacheVa::published(HostVa(ptr as usize))
    }

    /// Test-support alias of [`Self::entry`] (compiled unconditionally so the
    /// runtime's `#[cfg(test)]` consumers can reach it across the crate
    /// boundary).
    pub fn entry_for_test(&self) -> CacheVa {
        self.entry()
    }

    pub fn write_words(&mut self, words: &[u32]) -> Result<(), CacheError> {
        let byte_len = words
            .len()
            .checked_mul(std::mem::size_of::<u32>())
            .ok_or_else(|| CacheError::Policy("emitted code size overflow".to_string()))?;
        if byte_len != self.len {
            return Err(CacheError::Policy(format!(
                "emitted code length mismatch: reserved={} emitted={byte_len}",
                self.len
            )));
        }
        // SAFETY: `start` is inside the mapped region (reserved by
        // `begin_write`), so the exec-side pointer is in-bounds.
        let exec_ptr = unsafe { self.cache.region.exec_base.as_ptr().add(self.start) };
        let destination = self
            .cache
            .region
            .write_ptr_for(exec_ptr)
            .ok_or_else(|| {
                CacheError::Policy("cache write destination is outside the region".to_string())
            })?
            .cast::<u32>();
        // SAFETY: `begin_write` reserved `len` bytes at `start` inside the
        // region, `byte_len == len`, and the write alias is writable for this
        // thread (per-thread write window opened by `begin_write`).
        unsafe { std::ptr::copy_nonoverlapping(words.as_ptr(), destination, words.len()) };
        self.written = byte_len;
        Ok(())
    }

    pub fn publish(mut self) -> Result<PublishedCode, CacheError> {
        if self.written != self.len {
            return Err(CacheError::Policy(format!(
                "cannot publish incomplete code: reserved={} written={}",
                self.len, self.written
            )));
        }
        // SAFETY: `start` is inside the mapped region (reserved by
        // `begin_write`).
        let entry_ptr = unsafe { self.cache.region.exec_base.as_ptr().add(self.start) };
        self.cache.host.flush_icache(entry_ptr.cast(), self.len);
        self.cache.host.end_thread_write();
        self.write_enabled = false;
        self.cache.cursor += self.len;
        Ok(PublishedCode {
            entry: CacheVa::published(HostVa(entry_ptr as usize)),
            len: self.len,
        })
    }
}

impl Drop for CacheWriter<'_> {
    fn drop(&mut self) {
        if self.write_enabled {
            self.cache.host.end_thread_write();
        }
    }
}

#[cfg(test)]
pub(crate) mod test_host {
    //! A working [`NativeHostJit`] for this crate's own tests.

    use std::ptr::NonNull;

    use crate::host::{ForkChildJit, JitRegion, NativeHostJit};

    pub(crate) struct TestHostJit;

    pub(crate) static TEST_HOST: TestHostJit = TestHostJit;

    // Mirror of the runtime's transitional `DarwinHostJit`
    // (`carrick-runtime/src/native_darwin/darwin_jit.rs`): one MAP_JIT RWX
    // mapping with the per-thread `pthread_jit_write_protect_np` toggle.
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    impl NativeHostJit for TestHostJit {
        fn supported(&self) -> Result<(), &'static str> {
            if unsafe { libc::pthread_jit_write_protect_supported_np() } == 0 {
                return Err("pthread JIT write protection is unavailable");
            }
            Ok(())
        }

        fn map_code_cache(&self, capacity: usize) -> std::io::Result<JitRegion> {
            let mapped = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    capacity,
                    libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                    libc::MAP_PRIVATE | libc::MAP_ANON | libc::MAP_JIT,
                    -1,
                    0,
                )
            };
            if mapped == libc::MAP_FAILED {
                return Err(std::io::Error::last_os_error());
            }
            let base = NonNull::new(mapped.cast::<u8>())
                .ok_or_else(|| std::io::Error::other("MAP_JIT returned a null mapping"))?;
            Ok(JitRegion {
                exec_base: base,
                write_base: base,
                capacity,
            })
        }

        unsafe fn unmap(&self, region: &JitRegion) {
            let _ = unsafe { libc::munmap(region.exec_base.as_ptr().cast(), region.capacity) };
        }

        fn begin_thread_write(&self) {
            unsafe { libc::pthread_jit_write_protect_np(0) };
        }

        fn end_thread_write(&self) {
            unsafe { libc::pthread_jit_write_protect_np(1) };
        }

        fn flush_icache(&self, exec_ptr: *const u8, len: usize) {
            unsafe extern "C" {
                fn sys_icache_invalidate(start: *mut core::ffi::c_void, len: usize);
            }
            unsafe { sys_icache_invalidate(exec_ptr as *mut core::ffi::c_void, len) };
        }

        fn remap_for_fork_child(&self, _prior: &JitRegion) -> std::io::Result<ForkChildJit> {
            // Mirror of `DarwinHostJit`: MAP_JIT is MAP_PRIVATE, so the
            // inherited mapping is already the child's own CoW copy.
            Ok(ForkChildJit::Inherited)
        }
    }

    // Non-Darwin test hosts: a plain READ|WRITE private anonymous mapping with
    // write_base == exec_base. Thread write windows are no-ops (the mapping is
    // always writable) and `flush_icache` is a no-op -- fine on x86_64
    // (coherent I-cache; `core::arch` has no icache op there), and this crate's
    // tests never execute cache bytes on any host (nothing here transmutes a
    // cache address to a function pointer; a lane that must EXECUTE supplies
    // its own real `NativeHostJit`, e.g. `carrick_native_netbsd::NetbsdHostJit`).
    //
    // Deliberately NOT `PROT_EXEC`: a W|X anonymous mapping is not something
    // any real carrick host lane asks for -- Darwin uses MAP_JIT and the two
    // BSD lanes use a `shm_open` dual RX/RW map -- and hosts that enforce W^X
    // REFUSE it outright. NetBSD/aarch64 with PaX MPROTECT
    // (`security.pax.mprotect.{enabled,global}=1`, the GENERIC64 default)
    // fails this `mmap` with EACCES and pins `maxprot` at map time, so even a
    // later `mprotect` to RX cannot recover -- which took down six of this
    // crate's tests on that host while the production NetBSD lane's real
    // dual-mapped JIT passed. Asking only for the protection the double
    // actually uses is both honest and portable; if a test ever does execute
    // cache bytes it now faults loudly on every host rather than working on
    // some and being unbuildable on others.
    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    impl NativeHostJit for TestHostJit {
        fn supported(&self) -> Result<(), &'static str> {
            Ok(())
        }

        fn map_code_cache(&self, capacity: usize) -> std::io::Result<JitRegion> {
            let mapped = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    capacity,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANON,
                    -1,
                    0,
                )
            };
            if mapped == libc::MAP_FAILED {
                return Err(std::io::Error::last_os_error());
            }
            let base = NonNull::new(mapped.cast::<u8>())
                .ok_or_else(|| std::io::Error::other("mmap returned a null mapping"))?;
            Ok(JitRegion {
                exec_base: base,
                write_base: base,
                capacity,
            })
        }

        unsafe fn unmap(&self, region: &JitRegion) {
            let _ = unsafe { libc::munmap(region.exec_base.as_ptr().cast(), region.capacity) };
        }

        fn begin_thread_write(&self) {}

        fn end_thread_write(&self) {}

        fn flush_icache(&self, _exec_ptr: *const u8, _len: usize) {}

        fn remap_for_fork_child(&self, _prior: &JitRegion) -> std::io::Result<ForkChildJit> {
            // MAP_PRIVATE anonymous mapping: the inherited pages are
            // already this child's own CoW copy, same reasoning as Darwin's
            // MAP_JIT arm above.
            Ok(ForkChildJit::Inherited)
        }
    }
}

#[cfg(test)]
mod generation_tests {
    use std::ops::Range;

    use carrick_guest_mem::GuestVa;
    use proptest::prelude::*;

    use super::PageGenerationTable;
    use super::test_host::TEST_HOST;
    use crate::ids::CodeGeneration;

    const PAGE_SIZE: u64 = 0x4000;
    const PAGE: GuestVa = GuestVa(0x20_000);

    #[test]
    fn translation_cache_exhaustion_is_typed() {
        let mut cache =
            super::TranslationCache::new(16 * 1024, &TEST_HOST).expect("translation cache");
        let error = match cache.begin_write(cache.capacity_bytes() + 4) {
            Ok(_) => panic!("oversized reservation succeeded"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            super::CacheError::Capacity {
                requested,
                used: 0,
                capacity
            } if requested == capacity + 4
        ));
    }

    #[test]
    fn translation_cache_test_patch_replaces_a_published_word() {
        let mut cache =
            super::TranslationCache::new(16 * 1024, &TEST_HOST).expect("translation cache");
        let mut writer = cache.begin_write(4).expect("reserve test word");
        writer.write_words(&[0xd503_201f]).expect("write nop");
        let published = writer.publish().expect("publish nop");

        cache
            .patch_word_for_test(published.entry(), 0xd420_0000)
            .expect("patch published word");

        assert_eq!(
            unsafe { *(published.entry().host().raw() as *const u32) },
            0xd420_0000
        );
    }

    #[derive(Clone, Copy, Debug)]
    enum Operation {
        Write(u8),
        ProtectExecutable,
        Translate,
        Execute,
        ForkView,
        Unmap,
    }

    fn operation_strategy() -> impl Strategy<Value = Operation> {
        prop_oneof![
            any::<u8>().prop_map(Operation::Write),
            Just(Operation::ProtectExecutable),
            Just(Operation::Translate),
            Just(Operation::Execute),
            Just(Operation::ForkView),
            Just(Operation::Unmap),
        ]
    }

    proptest! {
        #[test]
        fn dsr_generation_never_executes_stale_published_bytes(
            operations in prop::collection::vec(operation_strategy(), 1..128)
        ) {
            let generations = PageGenerationTable::new(PAGE_SIZE).expect("generation table");
            let mut current_value = None;
            let mut published = None;

            for operation in operations {
                match operation {
                    Operation::Write(value) => {
                        current_value = Some(value);
                        generations.note_guest_code_write(page_range()).expect("note write");
                    }
                    Operation::ProtectExecutable => {
                        generations.note_guest_code_write(page_range()).expect("note protection transition");
                    }
                    Operation::Translate => {
                        if let Some(value) = current_value {
                            let generation = generations.generation_for_pc(PAGE).expect("page generation");
                            published = Some((generation, value));
                        }
                    }
                    Operation::Execute => {
                        if let Some((generation, value)) = published
                            && generations.is_current(PAGE, generation).expect("current generation")
                        {
                            prop_assert_eq!(Some(value), current_value);
                        }
                    }
                    Operation::ForkView => {
                        let child = generations.fork_view();
                        prop_assert_eq!(
                            child.generation_for_pc(PAGE).expect("child generation"),
                            generations.generation_for_pc(PAGE).expect("parent generation"),
                        );
                    }
                    Operation::Unmap => {
                        current_value = None;
                        let generation = generations.note_guest_code_write(page_range()).expect("note unmap");
                        generations.invalidate_page(PAGE, generation).expect("invalidate page");
                    }
                }
            }
        }
    }

    #[test]
    fn dsr_generation_observation_tracks_page_mutations_at_stable_address() {
        let generations = PageGenerationTable::new(PAGE_SIZE).expect("generation table");
        let observation = generations.observe(PAGE).expect("observe page");
        assert_eq!(observation.expected(), CodeGeneration::INITIAL);
        assert_eq!(observation.current(), CodeGeneration::INITIAL);

        let changed = generations
            .note_guest_code_write(page_range())
            .expect("note write");
        assert_eq!(observation.current(), changed);
        assert_ne!(observation.current(), observation.expected());
    }

    #[test]
    fn dsr_generation_reverse_dependencies_retire_only_stale_page_blocks() {
        let mut dependencies = super::PageBlockDependencies::default();
        let first = GuestVa(PAGE.raw() + 0x100);
        let second = GuestVa(PAGE.raw() + 0x200);
        let other_page = GuestVa(PAGE.raw() + PAGE_SIZE);
        dependencies.record(PAGE, first, CodeGeneration::INITIAL);
        dependencies.record(PAGE, second, CodeGeneration::claimed(1));
        dependencies.record(other_page, other_page, CodeGeneration::INITIAL);

        assert_eq!(
            dependencies.invalidate_page(PAGE, CodeGeneration::claimed(1)),
            vec![(first, CodeGeneration::INITIAL)]
        );
        assert!(dependencies.contains(PAGE, second, CodeGeneration::claimed(1)));
        assert!(dependencies.contains(other_page, other_page, CodeGeneration::INITIAL));
    }

    #[test]
    fn dsr_concurrency_duplicate_publication_has_one_winner() {
        use std::sync::{Arc, Barrier};

        let publications = Arc::new(super::ConcurrentPublicationIndex::default());
        let barrier = Arc::new(Barrier::new(2));
        let key = (PAGE, CodeGeneration::INITIAL);
        let winner_entry = crate::ids::CacheVa::published(carrick_guest_mem::HostVa(0x1000));
        let mut threads = Vec::new();
        for _ in 0..2 {
            let publications = Arc::clone(&publications);
            let barrier = Arc::clone(&barrier);
            threads.push(std::thread::spawn(move || {
                publications.get_or_publish(key, || {
                    barrier.wait();
                    winner_entry
                })
            }));
        }
        barrier.wait();
        let results = threads
            .into_iter()
            .map(|thread| thread.join().expect("publication thread"))
            .collect::<Vec<_>>();
        assert_eq!(results, vec![winner_entry, winner_entry]);
        assert_eq!(publications.published_count(), 1);
        assert_eq!(publications.builder_count(), 1);
    }

    #[test]
    fn dsr_observed_publication_preserves_the_winner() {
        let publications = super::ConcurrentPublicationIndex::default();
        let key = (PAGE, CodeGeneration::INITIAL);
        let entry = crate::ids::CacheVa::published(carrick_guest_mem::HostVa(0x1800));
        let no_op = |_event: super::PublicationWaitEvent| {};

        assert_eq!(
            publications.get_or_publish_observed(key, || entry, &no_op),
            entry
        );
        assert_eq!(
            publications.get_or_publish_observed(
                key,
                || crate::ids::CacheVa::published(carrick_guest_mem::HostVa(0x2800)),
                &no_op
            ),
            entry
        );
        assert_eq!(publications.builder_count(), 1);
    }

    #[test]
    fn dsr_concurrency_waiter_cannot_observe_partial_publication() {
        use std::sync::{Arc, Barrier, mpsc};

        let publications = Arc::new(super::ConcurrentPublicationIndex::default());
        let allocated = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        let key = (PAGE, CodeGeneration::INITIAL);
        let entry = crate::ids::CacheVa::published(carrick_guest_mem::HostVa(0x3000));
        let builder = {
            let publications = Arc::clone(&publications);
            let allocated = Arc::clone(&allocated);
            let release = Arc::clone(&release);
            std::thread::spawn(move || {
                publications.get_or_publish(key, || {
                    allocated.wait();
                    release.wait();
                    entry
                })
            })
        };
        allocated.wait();
        let (sent, received) = mpsc::channel();
        let waiter = {
            let publications = Arc::clone(&publications);
            std::thread::spawn(move || {
                let observed = publications.get_or_publish(key, || entry);
                sent.send(observed).expect("send publication result");
            })
        };
        assert!(
            matches!(
                received.recv_timeout(std::time::Duration::from_millis(20)),
                Err(mpsc::RecvTimeoutError::Timeout)
            ),
            "waiter observed a candidate before publication"
        );
        release.wait();
        assert_eq!(
            received
                .recv_timeout(std::time::Duration::from_secs(1))
                .expect("published result"),
            entry
        );
        assert_eq!(builder.join().expect("join publication builder"), entry);
        waiter.join().expect("join publication waiter");
    }

    #[test]
    fn dsr_concurrency_fork_child_discards_in_progress_publication() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::{Arc, Barrier};

        let publications = Arc::new(super::ConcurrentPublicationIndex::default());
        let ready = Arc::new(Barrier::new(2));
        let release = Arc::new(AtomicBool::new(false));
        let key = (PAGE, CodeGeneration::INITIAL);
        let builder = {
            let publications = Arc::clone(&publications);
            let ready = Arc::clone(&ready);
            let release = Arc::clone(&release);
            std::thread::spawn(move || {
                publications.get_or_publish(key, || {
                    ready.wait();
                    while !release.load(Ordering::Acquire) {
                        std::hint::spin_loop();
                    }
                    crate::ids::CacheVa::published(carrick_guest_mem::HostVa(0x1000))
                })
            })
        };
        ready.wait();

        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork publication child");
        if pid == 0 {
            publications.after_fork_child();
            let entry = publications.get_or_publish(key, || {
                crate::ids::CacheVa::published(carrick_guest_mem::HostVa(0x2000))
            });
            unsafe { libc::_exit(i32::from(entry.host().raw() != 0x2000)) };
        }
        release.store(true, Ordering::Release);
        builder.join().expect("join parent publication builder");
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFEXITED(status), "child status 0x{status:x}");
        assert_eq!(libc::WEXITSTATUS(status), 0);
    }

    #[test]
    fn dsr_concurrency_exec_reset_discards_published_index() {
        let publications = super::ConcurrentPublicationIndex::default();
        let key = (PAGE, CodeGeneration::INITIAL);
        let first = publications.get_or_publish(key, || {
            crate::ids::CacheVa::published(carrick_guest_mem::HostVa(0x1000))
        });
        publications.reset_for_exec();
        let second = publications.get_or_publish(key, || {
            crate::ids::CacheVa::published(carrick_guest_mem::HostVa(0x2000))
        });
        assert_ne!(first, second);
        assert_eq!(publications.builder_count(), 2);
    }

    fn page_range() -> Range<GuestVa> {
        PAGE..GuestVa(PAGE.raw() + PAGE_SIZE)
    }
}

#[cfg(test)]
mod from_region_tests {
    //! `TranslationCache::from_region` / `JitRegion::sub_region`: the seam a
    //! lane whose guest threads each carve a private slice out of ONE big
    //! process-wide reservation (the x86 native lane's per-thread JIT cache)
    //! uses to get the same typed capacity/publish machinery `Self::new`
    //! gives a process-wide cache, without asking the host to map a fresh
    //! region per slice. `Self::new`'s own construction path (used
    //! unconditionally by the aarch64 lane) is untouched by any of this --
    //! these tests are the aarch64-non-regression pin for that claim.

    use super::test_host::TEST_HOST;
    use crate::host::NativeHostJit;

    const SLICE_LEN: usize = 4096;
    const SLICE_COUNT: usize = 3;

    #[test]
    fn from_region_reports_the_slice_capacity_not_the_parent_region() {
        let region = TEST_HOST
            .map_code_cache(SLICE_LEN * SLICE_COUNT)
            .expect("map process-wide region");
        let slice = region.sub_region(SLICE_LEN, SLICE_LEN).expect("slice 1");
        let cache = super::TranslationCache::from_region(slice, &TEST_HOST);

        assert_eq!(cache.capacity_bytes(), SLICE_LEN);
        assert_eq!(cache.used_bytes(), 0);

        // The cache never mapped anything itself and does not own `region`;
        // dropping it here must not unmap the parent's memory (proven below,
        // in `from_region_drop_never_unmaps_the_borrowed_region`).
        drop(cache);
        unsafe { TEST_HOST.unmap(&region) };
    }

    #[test]
    fn from_region_writes_land_at_the_slices_own_offset() {
        let region = TEST_HOST
            .map_code_cache(SLICE_LEN * SLICE_COUNT)
            .expect("map process-wide region");
        let slice1 = region.sub_region(SLICE_LEN, SLICE_LEN).expect("slice 1");
        let mut cache1 = super::TranslationCache::from_region(slice1, &TEST_HOST);

        let published = cache1
            .publish_words(&[0xd503_201f])
            .expect("publish one word into slice 1");
        let expected_entry = region.exec_base.as_ptr() as usize + SLICE_LEN;
        assert_eq!(published.entry().host().raw(), expected_entry);
        assert_eq!(cache1.used_bytes(), 4);

        drop(cache1);
        unsafe { TEST_HOST.unmap(&region) };
    }

    #[test]
    fn from_region_drop_never_unmaps_the_borrowed_region() {
        let region = TEST_HOST
            .map_code_cache(SLICE_LEN * SLICE_COUNT)
            .expect("map process-wide region");
        let slice0 = region.sub_region(0, SLICE_LEN).expect("slice 0");
        let mut cache0 = super::TranslationCache::from_region(slice0, &TEST_HOST);
        let published = cache0
            .publish_words(&[0x1234_5678, 0x9abc_def0])
            .expect("publish two words into slice 0");
        let entry_addr = published.entry().host().raw();

        // Dropping a `from_region` cache must be a no-op on the underlying
        // mapping -- a live sibling slice (or a future occupant of this same
        // slice, recycled from a free-list the way the x86 native lane
        // reuses JIT slices across guest threads) must still see valid,
        // readable memory afterward.
        drop(cache0);

        let survived = unsafe { std::slice::from_raw_parts(entry_addr as *const u32, 2) };
        assert_eq!(
            survived,
            &[0x1234_5678, 0x9abc_def0],
            "the published bytes must survive the from_region cache's Drop"
        );

        // And a FRESH cache over the very same slice must still get a valid,
        // writable region -- proof the memory was never unmapped out from
        // under it.
        let slice0_again = region.sub_region(0, SLICE_LEN).expect("re-slice slot 0");
        let mut reused = super::TranslationCache::from_region(slice0_again, &TEST_HOST);
        reused
            .publish_words(&[0x1111_1111])
            .expect("publish into the recycled slice");

        unsafe { TEST_HOST.unmap(&region) };
    }

    #[test]
    fn sub_region_rejects_a_range_that_does_not_fit() {
        let region = TEST_HOST
            .map_code_cache(SLICE_LEN * SLICE_COUNT)
            .expect("map process-wide region");

        assert!(region.sub_region(SLICE_LEN * SLICE_COUNT, 1).is_none());
        assert!(region.sub_region(1, SLICE_LEN * SLICE_COUNT).is_none());
        assert!(region.sub_region(usize::MAX, 1).is_none());
        assert!(
            region
                .sub_region(SLICE_LEN * (SLICE_COUNT - 1), SLICE_LEN)
                .is_some(),
            "the last slice exactly fills the remaining capacity"
        );

        unsafe { TEST_HOST.unmap(&region) };
    }
}
