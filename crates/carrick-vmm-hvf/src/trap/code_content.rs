//! Physical-backing content dependencies for translation setup.
//!
//! These witnesses detect participating host writes. They are NOT permission
//! to execute translated code: guest stores, mapping changes, alias admission
//! and link publication require separate authority. Active
//! participating-host-write users now drain before write admission completes.
//! A page identity is never revived after a write or backing retirement.
use parking_lot::{Condvar, Mutex};
use std::{
    collections::BTreeMap,
    ops::{Deref, RangeInclusive},
    sync::{
        Arc, OnceLock, Weak,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};

const PAGE_SHIFT: usize = 12;

#[derive(Debug, Default)]
struct Registry {
    pages: Mutex<BTreeMap<usize, Weak<ContentPage>>>,
}

/// A never-revived dependency. Entry and revocation use the same
/// publish-before-check handshake as the kernel's execution census.
#[derive(Debug)]
struct ContentPage {
    valid: AtomicBool,
    running: AtomicUsize,
    drain: Mutex<()>,
    idle: Condvar,
}
impl ContentPage {
    fn new() -> Self {
        Self {
            valid: AtomicBool::new(true),
            running: AtomicUsize::new(0),
            drain: Mutex::new(()),
            idle: Condvar::new(),
        }
    }
    fn leave(&self) {
        let before = self.running.fetch_sub(1, Ordering::SeqCst);
        if before == 0 {
            carrick_fatal::carrick_fatal!(
                "hvf::code_content",
                "unbalanced instruction content scope"
            );
        }
        // Warm exits need no lock. If revocation follows this check, its
        // SeqCst running check sees zero; otherwise we wake its locked wait.
        if before == 1 && !self.valid.load(Ordering::SeqCst) {
            let _drain = self.drain.lock();
            self.idle.notify_all();
        }
    }
    fn wait_idle(&self) {
        let mut drain = self.drain.lock();
        while self.running.load(Ordering::SeqCst) != 0 {
            self.idle.wait(&mut drain);
        }
    }
}
impl Registry {
    /// The common no-execution path visits the range once. If an affected
    /// page is running, release the registry before parking, then resume
    /// strictly after that page. No unrelated dependency is revoked/drained,
    /// and no per-write scratch allocation or polling is needed.
    fn revoke(&self, range: RangeInclusive<usize>) -> usize {
        let mut start = *range.start();
        let end = *range.end();
        let mut visits = 0;
        loop {
            let pending = {
                let pages = self.pages.lock();
                let mut pending = None;
                for (&page, dependency) in pages.range(start..=end) {
                    visits += 1;
                    if let Some(dependency) = dependency.upgrade() {
                        dependency.valid.store(false, Ordering::SeqCst);
                        if dependency.running.load(Ordering::SeqCst) != 0 {
                            pending = Some((page, Some(dependency)));
                            break;
                        }
                    } else {
                        pending = Some((page, None));
                        break;
                    }
                }
                pending
            };
            let Some((page, dependency)) = pending else {
                break;
            };
            if let Some(dependency) = dependency {
                dependency.wait_idle();
                // A last observer may have dropped while this writer held
                // the final strong reference. Drop it under the registry lock
                // so concurrent observer cleanup cannot miss the final owner.
                let mut pages = self.pages.lock();
                if Arc::strong_count(&dependency) == 1
                    && pages
                        .get(&page)
                        .is_some_and(|current| current.as_ptr() == Arc::as_ptr(&dependency))
                {
                    pages.remove(&page);
                }
                drop(dependency);
            } else {
                let mut pages = self.pages.lock();
                if pages
                    .get(&page)
                    .is_some_and(|current| current.strong_count() == 0)
                {
                    pages.remove(&page);
                }
            }
            if page == end {
                break;
            }
            start = page + 1;
        }
        visits
    }
}

#[derive(Debug)]
pub(crate) struct CodeContent {
    len: usize,
    writers: AtomicUsize,
    observed: AtomicBool,
    registry: OnceLock<Arc<Registry>>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ContentError {
    OutOfBounds,
    WriteInProgress,
    Changed,
    AlreadyExecuting,
}

impl CodeContent {
    pub(crate) fn new(len: usize) -> Self {
        Self {
            len,
            writers: AtomicUsize::new(0),
            observed: AtomicBool::new(false),
            registry: OnceLock::new(),
        }
    }

    fn pages(&self, offset: usize, len: usize) -> Result<RangeInclusive<usize>, ContentError> {
        let end = offset.checked_add(len).ok_or(ContentError::OutOfBounds)?;
        if len == 0 || end > self.len {
            return Err(ContentError::OutOfBounds);
        }
        Ok((offset >> PAGE_SHIFT)..=((end - 1) >> PAGE_SHIFT))
    }

    // Translation publication is deliberately not exposed by this witness.
    pub(crate) fn observe(
        &self,
        offset: usize,
        len: usize,
    ) -> Result<ContentObservation, ContentError> {
        let range = self.pages(offset, len)?;
        let registry = self.registry.get_or_init(|| Arc::new(Registry::default()));
        let mut pages = registry.pages.lock();
        // Paired with writer admission: either a new observer sees the writer,
        // or that writer sees the initialized registry before changing bytes.
        self.observed.store(true, Ordering::SeqCst);
        if self.writers.load(Ordering::SeqCst) != 0 {
            return Err(ContentError::WriteInProgress);
        }
        let dependencies = range
            .map(|page| {
                let existing = pages.get(&page).and_then(Weak::upgrade);
                let valid = match existing {
                    Some(valid) if valid.valid.load(Ordering::Acquire) => valid,
                    _ => {
                        let valid = Arc::new(ContentPage::new());
                        pages.insert(page, Arc::downgrade(&valid));
                        valid
                    }
                };
                (page, valid)
            })
            .collect();
        drop(pages);
        let observation = ContentObservation {
            registry: Arc::clone(registry),
            dependencies,
            executing: 0,
        };
        if self.writers.load(Ordering::SeqCst) != 0 || !observation.is_current() {
            return Err(ContentError::WriteInProgress);
        }
        Ok(observation)
    }

    pub(crate) fn begin_write(
        &self,
        offset: usize,
        len: usize,
    ) -> Result<ContentWrite<&Self>, ContentError> {
        ContentWrite::new(self, offset, len)
    }
}

impl Drop for CodeContent {
    fn drop(&mut self) {
        if let Some(registry) = self.registry.get() {
            registry.revoke(0..=usize::MAX);
        }
    }
}

#[derive(Debug)]
pub(crate) struct ContentObservation {
    registry: Arc<Registry>,
    dependencies: Vec<(usize, Arc<ContentPage>)>,
    executing: usize,
}

impl ContentObservation {
    /// Participating host writers cannot finish admission until this scope
    /// ends. This covers content only: it does not authorize executable entry
    /// or prove absence of guest hardware stores and writable aliases.
    pub(crate) fn begin_execution(&mut self) -> Result<(), ContentError> {
        if self.executing != 0 {
            return Err(ContentError::AlreadyExecuting);
        }
        for (_, page) in &self.dependencies {
            page.running
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_add(1))
                .unwrap_or_else(|_| {
                    carrick_fatal::carrick_fatal!(
                        "hvf::code_content",
                        "instruction content count exhausted"
                    )
                });
            self.executing += 1;
            if !page.valid.load(Ordering::SeqCst) {
                self.finish_execution();
                return Err(ContentError::Changed);
            }
        }
        Ok(())
    }
    pub(crate) fn finish_execution(&mut self) {
        let count = std::mem::take(&mut self.executing);
        for (_, page) in &self.dependencies[..count] {
            page.leave();
        }
    }

    pub(crate) fn is_current(&self) -> bool {
        self.dependencies
            .iter()
            .all(|(_, valid)| valid.valid.load(Ordering::Acquire))
    }
}

impl Drop for ContentObservation {
    fn drop(&mut self) {
        self.finish_execution();
        let mut pages = self.registry.pages.lock();
        for (page, valid) in self.dependencies.drain(..) {
            if Arc::strong_count(&valid) == 1
                && pages
                    .get(&page)
                    .is_some_and(|current| current.as_ptr() == Arc::as_ptr(&valid))
            {
                pages.remove(&page);
            }
            drop(valid);
        }
    }
}

/// The owner is either a lexical borrow or retained physical backing. Both
/// close writer admission on drop without allocating another writer object.
#[derive(Debug)]
pub(crate) struct ContentWrite<O: Deref<Target = CodeContent>> {
    content: O,
    #[cfg(test)]
    visited_pages: usize,
}
impl<O: Deref<Target = CodeContent>> ContentWrite<O> {
    pub(crate) fn new(content: O, offset: usize, len: usize) -> Result<Self, ContentError> {
        let range = content.pages(offset, len)?;
        content
            .writers
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |count| {
                count.checked_add(1)
            })
            .unwrap_or_else(|_| {
                carrick_fatal::carrick_fatal!("hvf::code_content", "content writer count exhausted")
            });
        #[cfg(test)]
        let mut visited_pages = 0;
        if content.observed.load(Ordering::SeqCst) {
            let registry = content.registry.get().unwrap_or_else(|| {
                carrick_fatal::carrick_fatal!(
                    "hvf::code_content",
                    "observed content lacks registry"
                )
            });
            let visits = registry.revoke(range);
            #[cfg(test)]
            {
                visited_pages = visits;
            }
            #[cfg(not(test))]
            let _ = visits;
        }
        Ok(ContentWrite {
            content,
            #[cfg(test)]
            visited_pages,
        })
    }
    #[cfg(test)]
    pub(crate) fn visited_pages(&self) -> usize {
        self.visited_pages
    }
}
impl<O: Deref<Target = CodeContent>> Drop for ContentWrite<O> {
    fn drop(&mut self) {
        self.content.writers.fetch_sub(1, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overlapping_writes_prevent_observation_until_both_finish() {
        let content = CodeContent::new(8192);
        let old = content.observe(0, 4).unwrap();
        let untouched = content.observe(4096, 4).unwrap();
        let first = content.begin_write(0, 4).unwrap();
        let second = content.begin_write(2, 4).unwrap();
        assert!(!old.is_current());
        assert!(untouched.is_current());
        assert_eq!(
            content.observe(0, 4).unwrap_err(),
            ContentError::WriteInProgress
        );
        drop(first);
        assert_eq!(
            content.observe(0, 4).unwrap_err(),
            ContentError::WriteInProgress
        );
        drop(second);
        let fresh = content.observe(0, 4).unwrap();
        assert!(fresh.is_current());
        assert!(!old.is_current());
        drop(old);
        assert!(fresh.is_current());
    }

    #[test]
    fn cold_writer_prevents_first_observer_and_dropped_observers_leave_no_history() {
        let content = CodeContent::new(1024 * 4096);
        let writer = content.begin_write(0, 4).unwrap();
        assert_eq!(writer.visited_pages(), 0);
        assert!(content.registry.get().is_none());
        assert_eq!(
            content.observe(0, 4).unwrap_err(),
            ContentError::WriteInProgress
        );
        drop(writer);
        for page in 0..1024 {
            let observation = content.observe(page * 4096, 4).unwrap();
            assert!(observation.is_current());
            drop(observation);
        }
        assert!(content.registry.get().unwrap().pages.lock().is_empty());
    }

    #[test]
    fn simultaneous_final_observers_leave_no_history() {
        let content = CodeContent::new(4096);
        for _ in 0..64 {
            let first = content.observe(0, 4).unwrap();
            let second = content.observe(0, 4).unwrap();
            let start = std::sync::Barrier::new(2);
            std::thread::scope(|scope| {
                scope.spawn(|| {
                    start.wait();
                    drop(first);
                });
                scope.spawn(|| {
                    start.wait();
                    drop(second);
                });
            });
            assert!(content.registry.get().unwrap().pages.lock().is_empty());
        }
    }

    #[test]
    fn racing_first_observation_cannot_survive_an_admitted_write() {
        use std::sync::{Barrier, mpsc};
        use std::time::Duration;
        for _ in 0..64 {
            let content = CodeContent::new(4096);
            let start = Barrier::new(2);
            let (admitted_tx, admitted_rx) = mpsc::channel();
            let (finish_tx, finish_rx) = mpsc::channel();
            let observation = std::thread::scope(|scope| {
                let content_ref = &content;
                let start_ref = &start;
                scope.spawn(move || {
                    start_ref.wait();
                    let writer = content_ref.begin_write(0, 4).unwrap();
                    admitted_tx.send(()).unwrap();
                    finish_rx.recv_timeout(Duration::from_secs(5)).unwrap();
                    drop(writer);
                });
                start.wait();
                let observation = content.observe(0, 4);
                admitted_rx.recv_timeout(Duration::from_secs(5)).unwrap();
                finish_tx.send(()).unwrap();
                observation
            });
            match observation {
                Ok(observation) => assert!(!observation.is_current()),
                Err(error) => assert_eq!(error, ContentError::WriteInProgress),
            }
            assert!(content.observe(0, 4).unwrap().is_current());
        }
    }

    #[test]
    fn retirement_and_equal_offsets_in_another_owner_do_not_revive_dependencies() {
        let first = CodeContent::new(4096);
        let second = CodeContent::new(4096);
        let a = first.observe(0, 4).unwrap();
        let b = second.observe(0, 4).unwrap();
        drop(first);
        assert!(!a.is_current());
        assert!(b.is_current());
        let replacement = CodeContent::new(4096);
        assert!(replacement.observe(0, 4).unwrap().is_current());
        assert!(!a.is_current());
    }

    #[test]
    fn partial_page_crossings_and_invalid_ranges() {
        let content = CodeContent::new(3 * 4096);
        let a = content.observe(0, 4).unwrap();
        let b = content.observe(4096, 4).unwrap();
        let c = content.observe(8192, 4).unwrap();
        for (offset, len) in [(0, 0), (usize::MAX, 2), (3 * 4096, 1)] {
            assert_eq!(
                content.begin_write(offset, len).unwrap_err(),
                ContentError::OutOfBounds
            );
            assert!(a.is_current());
        }
        let write = content.begin_write(4095, 2).unwrap();
        assert_eq!(write.visited_pages(), 2);
        assert!(!a.is_current());
        assert!(!b.is_current());
        assert!(c.is_current());
    }
    #[test]
    fn native_code_content_invalidation_contract() {
        use carrick_conformance_contract::{
            Completeness, ContractId, ContractObservation, ContractRegistry, ExecutionLayer,
            SemanticAssertion, WorkMetric, WorkSnapshot, evaluate,
        };
        use sha2::{Digest, Sha256};
        let mut observations = Vec::new();
        for scale in [1u64, 8, 32, 128] {
            let content = CodeContent::new(129 * 4096);
            let unrelated: Vec<_> = (1..129)
                .map(|page| content.observe(page * 4096, 4).unwrap())
                .collect();
            let mut stale = Vec::new();
            let mut visits = 0;
            for _ in 0..scale {
                let dependent = content.observe(0, 4).unwrap();
                assert!(dependent.is_current());
                let write = content.begin_write(0, 4).unwrap();
                visits += write.visited_pages() as u64;
                assert!(!dependent.is_current());
                assert!(unrelated.iter().all(ContentObservation::is_current));
                drop(write);
                stale.push(dependent);
            }
            assert_eq!(visits, scale, "the invalidation instrument must fire");
            assert!(stale.iter().all(|dep| !dep.is_current()));
            let mut work = WorkSnapshot::new();
            work.insert(WorkMetric::NativeCodeInvalidationPages, visits)
                .unwrap();
            observations.push(ContractObservation {
                contract_id: ContractId::new("kernel.mm.native-code-content").unwrap(),
                layer: ExecutionLayer::VmFree,
                implementation_revision: format!(
                    "sha256:{:x}",
                    Sha256::digest(include_bytes!("code_content.rs"))
                ),
                fixture_identity: "unit:native-code-content".into(),
                scale,
                semantic_assertions: vec![SemanticAssertion::pass(
                    "affected_pages_revoke_without_touching_unrelated_dependencies",
                )],
                work: Some(work),
                timing: None,
                completeness: Completeness::Complete,
            });
        }
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap();
        let registry = ContractRegistry::load(root).unwrap();
        println!(
            "native_code_content_observations {}",
            serde_json::to_string(&observations).unwrap()
        );
        evaluate(
            registry.require("kernel.mm.native-code-content").unwrap(),
            &observations,
        )
        .unwrap();
    }
}

#[cfg(test)]
mod execution_tests {
    use super::*;
    use std::{sync::mpsc, thread, time::Duration};

    #[test]
    fn native_code_drain_waits_for_active_content_before_writer_admission() {
        let content = Arc::new(CodeContent::new(8192));
        let mut observation = content.observe(0, 4).unwrap();
        observation.begin_execution().unwrap();
        let (started_tx, started_rx) = mpsc::channel();
        let (admitted_tx, admitted_rx) = mpsc::channel();
        let writer_content = Arc::clone(&content);
        let writer = thread::spawn(move || {
            started_tx.send(()).unwrap();
            let _writer = writer_content.begin_write(0, 4).unwrap();
            admitted_tx.send(()).unwrap();
        });
        started_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        let premature = admitted_rx.recv_timeout(Duration::from_millis(50)).is_ok();
        observation.finish_execution();
        if !premature {
            admitted_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        }
        writer.join().unwrap();
        assert!(
            !premature,
            "writer was admitted while captured instructions were active"
        );
        assert!(!observation.is_current());
        assert!(observation.begin_execution().is_err());
    }
    #[test]
    fn native_code_drain_last_active_observer_releases_registry_entry() {
        let registry = Arc::new(Registry::default());
        let dependency = Arc::new(ContentPage::new());
        registry.pages.lock().insert(0, Arc::downgrade(&dependency));
        let mut observation = ContentObservation {
            registry: Arc::clone(&registry),
            dependencies: vec![(0, dependency.clone())],
            executing: 0,
        };
        observation.begin_execution().unwrap();
        // This retained writer-side reference has the same lifetime as the
        // pending drain's reference. Drop must account for it when cleaning up.
        drop(observation);
        assert!(registry.pages.lock().contains_key(&0));
        drop(dependency);
        // A subsequent real invalidation must sweep the dead selected entry.
        registry.revoke(0..=0);
        assert!(
            registry.pages.lock().is_empty(),
            "dead dependency retained after final active scope"
        );
    }
    #[test]
    fn native_code_drain_partial_entry_rolls_back_and_unrelated_scope_stays_live() {
        let content = CodeContent::new(3 * 4096);
        let mut combined = content.observe(0, 8192).unwrap();
        let mut unrelated = content.observe(8192, 4).unwrap();
        unrelated.begin_execution().unwrap();
        drop(content.begin_write(4096, 4).unwrap());
        assert_eq!(combined.begin_execution(), Err(ContentError::Changed));
        assert!(
            combined
                .dependencies
                .iter()
                .all(|(_, p)| p.running.load(Ordering::SeqCst) == 0)
        );
        // A stale preparation and an unrelated active page cannot hold this
        // writer hostage. No timed wait or polling is needed on this path.
        drop(content.begin_write(0, 4).unwrap());
        assert!(unrelated.is_current());
        unrelated.finish_execution();
    }

    #[test]
    fn native_code_drain_entry_write_race_leaves_no_active_count() {
        use std::sync::Barrier;
        for _ in 0..64 {
            let content = CodeContent::new(4096);
            let mut observation = content.observe(0, 4).unwrap();
            let start = Barrier::new(2);
            thread::scope(|threads| {
                let writer = threads.spawn(|| {
                    start.wait();
                    drop(content.begin_write(0, 4).unwrap());
                });
                start.wait();
                if observation.begin_execution().is_ok() {
                    observation.finish_execution();
                }
                writer.join().unwrap();
            });
            assert!(!observation.is_current());
            assert_eq!(observation.executing, 0);
            assert_eq!(
                observation.dependencies[0].1.running.load(Ordering::SeqCst),
                0
            );
        }
    }
    #[test]
    fn native_code_drain_waits_for_last_reader_and_cleans_pending_reference() {
        let content = Arc::new(CodeContent::new(8192));
        let mut first = content.observe(0, 4).unwrap();
        let mut second = content.observe(0, 4).unwrap();
        let mut unrelated = content.observe(4096, 4).unwrap();
        first.begin_execution().unwrap();
        second.begin_execution().unwrap();
        unrelated.begin_execution().unwrap();
        let (start_tx, start_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();
        let writer_content = Arc::clone(&content);
        let writer = thread::spawn(move || {
            start_tx.send(()).unwrap();
            drop(writer_content.begin_write(0, 4).unwrap());
            done_tx.send(()).unwrap();
        });
        start_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        let mut premature = done_rx.recv_timeout(Duration::from_millis(50)).is_ok();
        drop(first);
        premature |= done_rx.recv_timeout(Duration::from_millis(50)).is_ok();
        drop(second);
        if !premature {
            done_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        }
        writer.join().unwrap();
        assert!(!premature, "writer bypassed a remaining active observation");
        assert!(unrelated.is_current());
        assert!(
            !content
                .registry
                .get()
                .unwrap()
                .pages
                .lock()
                .contains_key(&0)
        );
        unrelated.finish_execution();
    }
}
