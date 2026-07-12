#![allow(dead_code)] // Cache publication is wired into block emission in Task 4.

use std::collections::BTreeMap;
use std::ops::Range;
use std::ptr::NonNull;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use carrick_guest_mem::{GuestVa, HostVa};
use parking_lot::{Condvar, Mutex, RwLock};

use super::types::{CacheOffset, CacheVa, CodeGeneration, DsrError};

pub(in crate::native_darwin) struct PageGenerationTable {
    page_size: u64,
    next: AtomicU64,
    pages: RwLock<BTreeMap<GuestVa, Arc<AtomicU64>>>,
}

#[derive(Clone)]
pub(in crate::native_darwin) struct PageGenerationObservation {
    page: GuestVa,
    expected: CodeGeneration,
    current: Arc<AtomicU64>,
}

impl PageGenerationObservation {
    pub(super) const fn page(&self) -> GuestVa {
        self.page
    }

    pub(super) const fn expected(&self) -> CodeGeneration {
        self.expected
    }

    pub(super) fn current(&self) -> CodeGeneration {
        CodeGeneration::claimed(self.current.load(Ordering::Acquire))
    }

    pub(super) fn current_atomic(&self) -> &AtomicU64 {
        &self.current
    }
}

impl PageGenerationTable {
    pub(in crate::native_darwin) fn new(page_size: u64) -> Result<Self, DsrError> {
        if page_size == 0 || !page_size.is_power_of_two() {
            return Err(DsrError::CachePolicy(format!(
                "DSR generation page size must be a nonzero power of two, got {page_size}"
            )));
        }
        Ok(Self {
            page_size,
            next: AtomicU64::new(CodeGeneration::INITIAL.get()),
            pages: RwLock::new(BTreeMap::new()),
        })
    }

    pub(in crate::native_darwin) fn note_guest_code_write(
        &self,
        range: Range<GuestVa>,
    ) -> Result<CodeGeneration, DsrError> {
        if range.start.raw() >= range.end.raw() {
            return Err(DsrError::CachePolicy(format!(
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
            .map_err(|_| DsrError::CachePolicy("DSR code generation overflow".to_string()))?;
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
                DsrError::CachePolicy("DSR generation page range overflow".to_string())
            })?;
        }
        Ok(generation)
    }

    pub(in crate::native_darwin) fn invalidate_page(
        &self,
        page: GuestVa,
        generation: CodeGeneration,
    ) -> Result<(), DsrError> {
        let page = GuestVa(page.raw() & !(self.page_size - 1));
        let observed = self.generation_for_pc(page)?;
        if observed != generation {
            return Err(DsrError::GenerationChanged {
                page: page.raw(),
                expected: generation.get(),
                observed: observed.get(),
            });
        }
        Ok(())
    }

    pub(in crate::native_darwin) fn generation_for_pc(
        &self,
        pc: GuestVa,
    ) -> Result<CodeGeneration, DsrError> {
        let page = GuestVa(pc.raw() & !(self.page_size - 1));
        Ok(self
            .pages
            .read()
            .get(&page)
            .map(|generation| CodeGeneration::claimed(generation.load(Ordering::Acquire)))
            .unwrap_or(CodeGeneration::INITIAL))
    }

    pub(in crate::native_darwin) fn observe(
        &self,
        pc: GuestVa,
    ) -> Result<PageGenerationObservation, DsrError> {
        let page = GuestVa(pc.raw() & !(self.page_size - 1));
        let current = self
            .pages
            .write()
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

    pub(in crate::native_darwin) fn is_current(
        &self,
        pc: GuestVa,
        generation: CodeGeneration,
    ) -> Result<bool, DsrError> {
        Ok(self.generation_for_pc(pc)? == generation)
    }

    pub(in crate::native_darwin) fn fork_view(&self) -> Self {
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
pub(super) struct LinkSite {
    pub(super) source: CacheVa,
    pub(super) slot: CacheOffset,
}

#[derive(Default)]
pub(super) struct PageBlockDependencies {
    blocks: BTreeMap<GuestVa, Vec<(GuestVa, CodeGeneration)>>,
}

#[derive(Clone, Copy)]
enum PublicationState {
    Building,
    Published(CacheVa),
}

#[derive(Default)]
pub(super) struct ConcurrentPublicationIndex {
    state: Mutex<BTreeMap<(GuestVa, CodeGeneration), PublicationState>>,
    changed: Condvar,
    builders: AtomicU64,
}

impl ConcurrentPublicationIndex {
    pub(super) fn get_or_publish(
        &self,
        key: (GuestVa, CodeGeneration),
        build: impl FnOnce() -> CacheVa,
    ) -> CacheVa {
        let mut state = self.state.lock();
        loop {
            match state.get(&key).copied() {
                Some(PublicationState::Published(entry)) => return entry,
                Some(PublicationState::Building) => {
                    self.changed.wait(&mut state);
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

    pub(super) fn after_fork_child(&self) {
        self.state
            .lock()
            .retain(|_, state| matches!(state, PublicationState::Published(_)));
        self.changed.notify_all();
    }

    pub(super) fn reset_for_exec(&self) {
        self.state.lock().clear();
        self.changed.notify_all();
    }

    #[cfg(test)]
    pub(super) fn published_count(&self) -> usize {
        self.state
            .lock()
            .values()
            .filter(|state| matches!(state, PublicationState::Published(_)))
            .count()
    }

    #[cfg(test)]
    pub(super) fn builder_count(&self) -> u64 {
        self.builders.load(Ordering::Relaxed)
    }
}

impl PageBlockDependencies {
    pub(super) fn page_count(&self) -> usize {
        self.blocks.len()
    }

    pub(super) fn record(&mut self, page: GuestVa, block: GuestVa, generation: CodeGeneration) {
        let blocks = self.blocks.entry(page).or_default();
        if !blocks.contains(&(block, generation)) {
            blocks.push((block, generation));
        }
    }

    pub(super) fn invalidate_page(
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
    pub(super) fn contains(
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

pub(super) struct PublishedCode {
    entry: CacheVa,
    len: usize,
}

impl PublishedCode {
    pub(super) const fn entry(&self) -> CacheVa {
        self.entry
    }

    pub(super) const fn len(&self) -> usize {
        self.len
    }
}

pub(super) struct TranslationCache {
    base: NonNull<u8>,
    capacity: usize,
    cursor: usize,
}

// SAFETY: the mapping is process-wide and contains no thread-affine pointer
// provenance. Every mutation, including the thread-local MAP_JIT write-enable
// window, is serialized by `ProcessTranslator::state`; published instructions
// are immutable except for aligned atomic direct-link patches under that same
// lock.
unsafe impl Send for TranslationCache {}

impl TranslationCache {
    pub(in crate::native_darwin) fn new(requested_capacity: usize) -> Result<Self, DsrError> {
        if requested_capacity == 0 {
            return Err(DsrError::CachePolicy(
                "translation cache capacity must be nonzero".to_string(),
            ));
        }
        if unsafe { libc::pthread_jit_write_protect_supported_np() } == 0 {
            return Err(DsrError::CachePolicy(
                "pthread JIT write protection is unavailable".to_string(),
            ));
        }
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        if page_size <= 0 {
            return Err(DsrError::Host {
                operation: "query host page size",
                error: std::io::Error::last_os_error(),
            });
        }
        let page_size = page_size as usize;
        let capacity = requested_capacity
            .checked_add(page_size - 1)
            .map(|value| value & !(page_size - 1))
            .ok_or_else(|| DsrError::CachePolicy("translation cache size overflow".to_string()))?;
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
            return Err(DsrError::Host {
                operation: "allocate MAP_JIT translation cache",
                error: std::io::Error::last_os_error(),
            });
        }
        let base = NonNull::new(mapped.cast::<u8>())
            .ok_or_else(|| DsrError::CachePolicy("MAP_JIT returned a null mapping".to_string()))?;
        unsafe { libc::pthread_jit_write_protect_np(1) };
        Ok(Self {
            base,
            capacity,
            cursor: 0,
        })
    }

    pub(super) fn reset_after_fork_for_exec(&mut self) {
        // The sole surviving child thread inherits the MAP_JIT mapping and no
        // cache writer can be live across the quiesced fork. Reuse the mapping
        // instead of calling MAP_JIT/libdispatch again in the fork child.
        unsafe { libc::pthread_jit_write_protect_np(1) };
        self.cursor = 0;
    }

    pub(super) fn begin_write(&mut self, len: usize) -> Result<CacheWriter<'_>, DsrError> {
        if len == 0 || !len.is_multiple_of(std::mem::size_of::<u32>()) {
            return Err(DsrError::CachePolicy(format!(
                "translation cache write length must be a nonzero instruction multiple, got {len}"
            )));
        }
        let end = self.cursor.checked_add(len).ok_or_else(|| {
            DsrError::CachePolicy("translation cache cursor overflow".to_string())
        })?;
        if end > self.capacity {
            return Err(DsrError::CacheCapacity {
                requested: len,
                used: self.cursor,
                capacity: self.capacity,
            });
        }
        let start = self.cursor;
        unsafe { libc::pthread_jit_write_protect_np(0) };
        Ok(CacheWriter {
            cache: self,
            start,
            len,
            written: 0,
            write_enabled: true,
        })
    }

    /// Repair the per-thread MAP_JIT protection bit inherited by the sole
    /// surviving thread after `fork(2)`.  Quiescence guarantees no writer is
    /// live at the fork instant, so the child always starts executable-only.
    pub(super) fn after_fork_child(&self) {
        unsafe { libc::pthread_jit_write_protect_np(1) };
    }

    pub(super) fn contains_host_pc(&self, pc: HostVa) -> bool {
        let start = self.base.as_ptr() as usize;
        let end = start.saturating_add(self.cursor);
        (start..end).contains(&pc.raw())
    }

    pub(super) fn host_range(&self) -> Range<usize> {
        let start = self.base.as_ptr() as usize;
        start..start.saturating_add(self.capacity)
    }

    pub(super) const fn used_bytes(&self) -> usize {
        self.cursor
    }

    pub(super) const fn capacity_bytes(&self) -> usize {
        self.capacity
    }

    pub(super) fn patch_direct_branch(
        &mut self,
        site: LinkSite,
        target: CacheVa,
    ) -> Result<(), DsrError> {
        let source = site
            .source
            .host()
            .raw()
            .checked_add(site.slot.get() as usize)
            .ok_or_else(|| DsrError::CachePolicy("direct-link source overflow".to_string()))?;
        if !source.is_multiple_of(4) {
            return Err(DsrError::CachePolicy(format!(
                "direct-link source is not instruction aligned: 0x{source:x}"
            )));
        }
        let displacement = (target.host().raw() as i128) - (source as i128);
        if displacement % 4 != 0 {
            return Err(DsrError::CachePolicy(format!(
                "direct-link displacement is not instruction aligned: {displacement}"
            )));
        }
        let words = displacement / 4;
        if !(-(1_i128 << 25)..(1_i128 << 25)).contains(&words) {
            return Err(DsrError::CachePolicy(format!(
                "direct-link target is outside AArch64 B range: {displacement} bytes"
            )));
        }
        let word = 0x1400_0000 | ((words as i64 as u32) & 0x03ff_ffff);
        unsafe { libc::pthread_jit_write_protect_np(0) };
        let instruction = unsafe { &*(source as *const AtomicU32) };
        instruction.store(word, Ordering::Release);
        unsafe { super::super::carrick_native_clear_icache(source as *mut _, 4) };
        unsafe { libc::pthread_jit_write_protect_np(1) };
        Ok(())
    }
}

impl Drop for TranslationCache {
    fn drop(&mut self) {
        unsafe { libc::pthread_jit_write_protect_np(1) };
        let _ = unsafe { libc::munmap(self.base.as_ptr().cast(), self.capacity) };
    }
}

pub(super) struct CacheWriter<'a> {
    cache: &'a mut TranslationCache,
    start: usize,
    len: usize,
    written: usize,
    write_enabled: bool,
}

impl CacheWriter<'_> {
    #[cfg(test)]
    pub(super) fn entry_for_test(&self) -> CacheVa {
        let ptr = unsafe { self.cache.base.as_ptr().add(self.start) };
        CacheVa::published(HostVa(ptr as usize))
    }

    pub(super) fn write_words(&mut self, words: &[u32]) -> Result<(), DsrError> {
        let byte_len = words
            .len()
            .checked_mul(std::mem::size_of::<u32>())
            .ok_or_else(|| DsrError::CachePolicy("emitted code size overflow".to_string()))?;
        if byte_len != self.len {
            return Err(DsrError::CachePolicy(format!(
                "emitted code length mismatch: reserved={} emitted={byte_len}",
                self.len
            )));
        }
        let destination = unsafe { self.cache.base.as_ptr().add(self.start).cast::<u32>() };
        unsafe { std::ptr::copy_nonoverlapping(words.as_ptr(), destination, words.len()) };
        self.written = byte_len;
        Ok(())
    }

    pub(super) fn publish(mut self) -> Result<PublishedCode, DsrError> {
        if self.written != self.len {
            return Err(DsrError::CachePolicy(format!(
                "cannot publish incomplete code: reserved={} written={}",
                self.len, self.written
            )));
        }
        let entry_ptr = unsafe { self.cache.base.as_ptr().add(self.start) };
        unsafe { super::super::carrick_native_clear_icache(entry_ptr.cast(), self.len) };
        unsafe { libc::pthread_jit_write_protect_np(1) };
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
            unsafe { libc::pthread_jit_write_protect_np(1) };
        }
    }
}

#[cfg(test)]
mod generation_tests {
    use std::ops::Range;

    use carrick_guest_mem::GuestVa;
    use proptest::prelude::*;

    use super::super::types::CodeGeneration;
    use super::PageGenerationTable;

    const PAGE_SIZE: u64 = 0x4000;
    const PAGE: GuestVa = GuestVa(0x20_000);

    #[test]
    fn translation_cache_exhaustion_is_typed() {
        let mut cache = super::TranslationCache::new(16 * 1024).expect("translation cache");
        let error = match cache.begin_write(cache.capacity_bytes() + 4) {
            Ok(_) => panic!("oversized reservation succeeded"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            super::super::types::DsrError::CacheCapacity {
                requested,
                used: 0,
                capacity
            } if requested == capacity + 4
        ));
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
        let winner_entry = super::CacheVa::published(carrick_guest_mem::HostVa(0x1000));
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
    fn dsr_concurrency_waiter_cannot_observe_partial_publication() {
        use std::sync::{Arc, Barrier, mpsc};

        let publications = Arc::new(super::ConcurrentPublicationIndex::default());
        let allocated = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        let key = (PAGE, CodeGeneration::INITIAL);
        let entry = super::CacheVa::published(carrick_guest_mem::HostVa(0x3000));
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
                    super::CacheVa::published(carrick_guest_mem::HostVa(0x1000))
                })
            })
        };
        ready.wait();

        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork publication child");
        if pid == 0 {
            publications.after_fork_child();
            let entry = publications.get_or_publish(key, || {
                super::CacheVa::published(carrick_guest_mem::HostVa(0x2000))
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
            super::CacheVa::published(carrick_guest_mem::HostVa(0x1000))
        });
        publications.reset_for_exec();
        let second = publications.get_or_publish(key, || {
            super::CacheVa::published(carrick_guest_mem::HostVa(0x2000))
        });
        assert_ne!(first, second);
        assert_eq!(publications.builder_count(), 2);
    }

    fn page_range() -> Range<GuestVa> {
        PAGE..GuestVa(PAGE.raw() + PAGE_SIZE)
    }
}
