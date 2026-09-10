//! Exact-MM pristine anonymous backing state. Callers authenticate MM identity
//! and permissions; absence of a translation never grants zero-read authority.
use crate::GuestVa;
use parking_lot::{Mutex, MutexGuard};
use std::ops::Range;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::sync::Arc;

use carrick_fatal::carrick_fatal;

const PAGE: u64 = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DeferredAnonymousError {
    #[error("deferred anonymous range is empty, unaligned, or overflows")]
    InvalidRange,
    #[error("could not retain private file view fd: errno {0}")]
    DuplicateFile(i32),
    #[error("could not read deferred private file view: errno {0}")]
    ReadFile(i32),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeferredAnonymousSnapshot {
    pub pristine: Vec<Range<GuestVa>>,
    pub zero_read_resident: Vec<Range<GuestVa>>,
    pub private_file: Vec<DeferredPrivateFileSnapshot>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeferredPrivateFileSnapshot {
    pub range: Range<GuestVa>,
    pub file_offset: u64,
    pub source: crate::PrivateFileSource,
}

#[derive(Debug, Default, Clone)]
struct State {
    pristine: Vec<Range<u64>>,
    resident: Vec<Range<u64>>,
}

#[derive(Debug, Clone)]
struct DeferredPrivateFileView {
    range: Range<u64>,
    file: Arc<OwnedFd>,
    file_offset: u64,
    source: crate::PrivateFileSource,
}

#[derive(Debug, Default, Clone)]
struct FileState {
    views: Vec<DeferredPrivateFileView>,
}

/// Share only within one MM; use `fork_private` for a copied MM. Never hold
/// this lock while acquiring quiesce or calling back into runtime authorities.
#[derive(Debug, Default)]
pub struct DeferredAnonymousState {
    state: Mutex<State>,
    files: Mutex<FileState>,
}

fn extent(start: GuestVa, len: usize) -> Result<Range<u64>, DeferredAnonymousError> {
    let end = start
        .raw()
        .checked_add(u64::try_from(len).map_err(|_| DeferredAnonymousError::InvalidRange)?)
        .ok_or(DeferredAnonymousError::InvalidRange)?;
    if len == 0 || !start.raw().is_multiple_of(PAGE) || !end.is_multiple_of(PAGE) {
        return Err(DeferredAnonymousError::InvalidRange);
    }
    Ok(start.raw()..end)
}

fn remove(ranges: &mut Vec<Range<u64>>, cut: &Range<u64>) {
    let mut next = Vec::with_capacity(ranges.len() + 1);
    for old in ranges.drain(..) {
        if old.end <= cut.start || old.start >= cut.end {
            next.push(old);
        } else {
            if old.start < cut.start {
                next.push(old.start..cut.start);
            }
            if old.end > cut.end {
                next.push(cut.end..old.end);
            }
        }
    }
    *ranges = next;
}

fn insert(ranges: &mut Vec<Range<u64>>, mut added: Range<u64>) {
    let first = ranges.partition_point(|r| r.end < added.start);
    let mut last = first;
    while last < ranges.len() && ranges[last].start <= added.end {
        added.start = added.start.min(ranges[last].start);
        added.end = added.end.max(ranges[last].end);
        last += 1;
    }
    ranges.splice(first..last, [added]);
}

fn copy_file_view(
    view: &DeferredPrivateFileView,
    start: GuestVa,
    dst: &mut [u8],
) -> Result<(), DeferredAnonymousError> {
    let len = u64::try_from(dst.len()).map_err(|_| DeferredAnonymousError::InvalidRange)?;
    let end = start
        .raw()
        .checked_add(len)
        .ok_or(DeferredAnonymousError::InvalidRange)?;
    if start.raw() < view.range.start || end > view.range.end {
        return Err(DeferredAnonymousError::InvalidRange);
    }
    let file_offset = view
        .file_offset
        .checked_add(start.raw() - view.range.start)
        .ok_or(DeferredAnonymousError::InvalidRange)?;
    dst.fill(0);
    let mut copied = 0usize;
    while copied < dst.len() {
        let copied_offset =
            u64::try_from(copied).map_err(|_| DeferredAnonymousError::InvalidRange)?;
        let offset = file_offset
            .checked_add(copied_offset)
            .and_then(|value| libc::off_t::try_from(value).ok())
            .ok_or(DeferredAnonymousError::InvalidRange)?;
        let read = unsafe {
            libc::pread(
                view.file.as_raw_fd(),
                dst[copied..].as_mut_ptr().cast(),
                dst.len() - copied,
                offset,
            )
        };
        if read < 0 {
            return Err(DeferredAnonymousError::ReadFile(
                std::io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(libc::EIO),
            ));
        }
        if read == 0 {
            break;
        }
        copied = copied
            .checked_add(usize::try_from(read).map_err(|_| DeferredAnonymousError::InvalidRange)?)
            .ok_or(DeferredAnonymousError::InvalidRange)?;
    }
    Ok(())
}

impl DeferredAnonymousState {
    pub fn new() -> Self {
        Self::default()
    }
    /// Caller must prove this is newly reserved, pristine private anonymous memory.
    pub fn reserve_fresh(&self, start: GuestVa, len: usize) -> Result<(), DeferredAnonymousError> {
        let range = extent(start, len)?;
        let mut state = self.state.lock();
        remove(&mut state.resident, &range);
        insert(&mut state.pristine, range);
        Ok(())
    }
    pub fn retire(&self, start: GuestVa, len: usize) -> Result<(), DeferredAnonymousError> {
        let range = extent(start, len)?;
        let mut state = self.state.lock();
        remove(&mut state.pristine, &range);
        remove(&mut state.resident, &range);
        drop(state);
        let mut files = self.files.lock();
        let mut retained = Vec::with_capacity(files.views.len() + 1);
        for view in files.views.drain(..) {
            if view.range.end <= range.start || view.range.start >= range.end {
                retained.push(view);
                continue;
            }
            if view.range.start < range.start {
                let mut left = view.clone();
                left.range.end = range.start;
                retained.push(left);
            }
            if view.range.end > range.end {
                let mut right = view;
                right.file_offset = right
                    .file_offset
                    .saturating_add(range.end.saturating_sub(right.range.start));
                right.range.start = range.end;
                retained.push(right);
            }
        }
        retained.sort_by_key(|view| view.range.start);
        files.views = retained;
        Ok(())
    }

    /// Retain an exact private file-view recipe without publishing backing.
    /// The duplicated descriptor is mapping-owned and therefore survives a
    /// guest close; copied MMs share that immutable open-file reference.
    pub fn reserve_private_file(
        &self,
        start: GuestVa,
        len: usize,
        fd: BorrowedFd<'_>,
        file_offset: u64,
        source: crate::PrivateFileSource,
    ) -> Result<(), DeferredAnonymousError> {
        let range = extent(start, len)?;
        let duplicated = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
        if duplicated < 0 {
            return Err(DeferredAnonymousError::DuplicateFile(
                std::io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(libc::EIO),
            ));
        }
        let file = Arc::new(unsafe { OwnedFd::from_raw_fd(duplicated) });
        let mut files = self.files.lock();
        if files
            .views
            .iter()
            .any(|view| view.range.start < range.end && range.start < view.range.end)
        {
            return Err(DeferredAnonymousError::InvalidRange);
        }
        files.views.push(DeferredPrivateFileView {
            range,
            file,
            file_offset,
            source,
        });
        files.views.sort_by_key(|view| view.range.start);
        Ok(())
    }

    /// Copy a page-local syscall read directly from the retained file recipe.
    /// This preserves zero-copy mmap while giving kernel copyin the same bytes
    /// a guest first touch would materialize. Short reads zero-fill the page
    /// tail, matching a private mapping's partial-EOF page.
    pub fn copy_pristine_file(
        &self,
        start: GuestVa,
        dst: &mut [u8],
    ) -> Result<bool, DeferredAnonymousError> {
        if dst.is_empty() {
            return Ok(true);
        }
        let end = start
            .raw()
            .checked_add(dst.len() as u64)
            .ok_or(DeferredAnonymousError::InvalidRange)?;
        let files = self.files.lock();
        let Some(view) = files
            .views
            .iter()
            .find(|view| view.range.start <= start.raw() && end <= view.range.end)
        else {
            return Ok(false);
        };
        copy_file_view(view, start, dst)?;
        Ok(true)
    }

    /// Lock the exact file recipe covering `address` through backing
    /// publication. Callers already own MM mutation exclusion.
    pub fn begin_private_file_materialization(
        &self,
        address: GuestVa,
    ) -> Option<DeferredPrivateFileTransition<'_>> {
        let files = self.files.lock();
        let index = files
            .views
            .iter()
            .position(|view| view.range.start <= address.raw() && address.raw() < view.range.end)?;
        let view = files.views[index].clone();
        Some(DeferredPrivateFileTransition { files, index, view })
    }
    /// Clear logical read residency without changing pristine provenance.
    pub fn clear_zero_read_residency(
        &self,
        start: GuestVa,
        len: usize,
    ) -> Result<(), DeferredAnonymousError> {
        let range = extent(start, len)?;
        remove(&mut self.state.lock().resident, &range);
        Ok(())
    }
    /// Caller checks logical read permission before entering. Refusal leaves dst unchanged.
    pub fn copy_pristine_zero(
        &self,
        start: GuestVa,
        dst: &mut [u8],
    ) -> Result<bool, DeferredAnonymousError> {
        if dst.is_empty() {
            return Ok(true);
        }
        let start = start.raw();
        let len = u64::try_from(dst.len()).map_err(|_| DeferredAnonymousError::InvalidRange)?;
        let end = start
            .checked_add(len)
            .ok_or(DeferredAnonymousError::InvalidRange)?;
        let page = start & !(PAGE - 1);
        let page_end = page
            .checked_add(PAGE)
            .ok_or(DeferredAnonymousError::InvalidRange)?;
        if end > page_end {
            return Err(DeferredAnonymousError::InvalidRange);
        }
        let mut state = self.state.lock();
        let index = state.pristine.partition_point(|r| r.end <= start);
        if !state
            .pristine
            .get(index)
            .is_some_and(|r| r.start <= start && end <= r.end)
        {
            return Ok(false);
        }
        dst.fill(0);
        insert(&mut state.resident, page..page_end);
        Ok(true)
    }
    /// Check pristine provenance without materializing or marking pages resident.
    /// Callers separately authenticate the MM and logical access permission.
    pub fn covers_pristine(&self, start: GuestVa, len: usize) -> bool {
        let Ok(len) = u64::try_from(len) else {
            return false;
        };
        let Some(end) = start.raw().checked_add(len).filter(|_| len != 0) else {
            return false;
        };
        let state = self.state.lock();
        let index = state.pristine.partition_point(|r| r.end <= start.raw());
        state
            .pristine
            .get(index)
            .is_some_and(|r| r.start <= start.raw() && end <= r.end)
    }
    /// Enumerate all materialized (non-pristine) subranges within `[start, start + len)`.
    ///
    /// Any subrange that is NOT covered by `state.pristine` has had physical backing
    /// populated / written to, and contains actual data for core dump capture.
    pub fn materialized_subranges(&self, start: GuestVa, len: usize) -> Vec<Range<GuestVa>> {
        let Ok(len_u64) = u64::try_from(len) else {
            return Vec::new();
        };
        if len == 0 {
            return Vec::new();
        }
        let Some(req_end) = start.raw().checked_add(len_u64) else {
            return Vec::new();
        };
        let req_start = start.raw();

        let state = self.state.lock();
        let mut materialized = Vec::new();
        let mut cursor = req_start;

        let first_idx = state.pristine.partition_point(|r| r.end <= req_start);
        for p in &state.pristine[first_idx..] {
            if p.start >= req_end {
                break;
            }
            if p.start > cursor {
                let gap_end = p.start.min(req_end);
                materialized.push(GuestVa(cursor)..GuestVa(gap_end));
            }
            cursor = cursor.max(p.end);
            if cursor >= req_end {
                break;
            }
        }
        if cursor < req_end {
            materialized.push(GuestVa(cursor)..GuestVa(req_end));
        }

        materialized
    }
    /// Check whether one retained private-file recipe covers the range.
    /// Callers separately authenticate the exact MM and access permission.
    pub fn covers_private_file(&self, start: GuestVa, len: usize) -> bool {
        let Ok(len) = u64::try_from(len) else {
            return false;
        };
        let Some(end) = start.raw().checked_add(len).filter(|_| len != 0) else {
            return false;
        };
        self.files
            .lock()
            .views
            .iter()
            .any(|view| view.range.start <= start.raw() && end <= view.range.end)
    }
    pub fn snapshot(&self) -> DeferredAnonymousSnapshot {
        let state = self.state.lock();
        DeferredAnonymousSnapshot {
            pristine: state
                .pristine
                .iter()
                .map(|r| GuestVa(r.start)..GuestVa(r.end))
                .collect(),
            zero_read_resident: state
                .resident
                .iter()
                .map(|r| GuestVa(r.start)..GuestVa(r.end))
                .collect(),
            private_file: self
                .files
                .lock()
                .views
                .iter()
                .map(|view| DeferredPrivateFileSnapshot {
                    range: GuestVa(view.range.start)..GuestVa(view.range.end),
                    file_offset: view.file_offset,
                    source: view.source,
                })
                .collect(),
        }
    }
    pub fn fork_private(&self) -> Self {
        Self {
            state: Mutex::new(self.state.lock().clone()),
            files: Mutex::new(self.files.lock().clone()),
        }
    }
    /// Acquire only AFTER caller quiescence/exclusion. On failure, prove complete
    /// rollback or fail-stop BEFORE dropping the guard: drop restores no backend state.
    pub fn begin_materialization(
        &self,
        start: GuestVa,
        len: usize,
    ) -> Result<DeferredAnonymousTransition<'_>, DeferredAnonymousError> {
        Ok(DeferredAnonymousTransition {
            state: self.state.lock(),
            range: extent(start, len)?,
        })
    }
}

#[must_use]
pub struct DeferredPrivateFileTransition<'a> {
    files: MutexGuard<'a, FileState>,
    index: usize,
    view: DeferredPrivateFileView,
}

impl DeferredPrivateFileTransition<'_> {
    pub fn start(&self) -> GuestVa {
        GuestVa(self.view.range.start)
    }

    pub fn len(&self) -> usize {
        usize::try_from(self.view.range.end - self.view.range.start).unwrap_or_else(|_| {
            carrick_fatal!(
                "guest_mem::deferred_anonymous",
                "deferred private file view byte length exceeded host address space limits: start={:#x} end={:#x}",
                self.view.range.start,
                self.view.range.end
            );
        })
    }

    pub fn is_empty(&self) -> bool {
        self.view.range.is_empty()
    }

    pub fn file_offset(&self) -> u64 {
        self.view.file_offset
    }

    pub fn source(&self) -> crate::PrivateFileSource {
        self.view.source
    }

    pub fn fd(&self) -> BorrowedFd<'_> {
        self.view.file.as_fd()
    }

    /// Seed a private page from the retained live file view while this exact
    /// recipe is locked against retirement or a competing publication.
    pub fn copy_pristine(
        &self,
        start: GuestVa,
        dst: &mut [u8],
    ) -> Result<(), DeferredAnonymousError> {
        copy_file_view(&self.view, start, dst)
    }

    /// Commit publication of only one subrange, retaining the untouched
    /// pieces with their original file offsets.
    pub fn commit_range(
        mut self,
        start: GuestVa,
        len: usize,
    ) -> Result<(), DeferredAnonymousError> {
        let published = extent(start, len)?;
        if published.start < self.view.range.start || published.end > self.view.range.end {
            return Err(DeferredAnonymousError::InvalidRange);
        }
        if self.files.views.get(self.index).is_none_or(|current| {
            current.range != self.view.range
                || current.file_offset != self.view.file_offset
                || !Arc::ptr_eq(&current.file, &self.view.file)
        }) {
            carrick_fatal!(
                "guest_mem::deferred_anonymous",
                "deferred private file view mutated or displaced under lock during commit_range: index={} start={:#x} end={:#x} offset={:#x}",
                self.index,
                self.view.range.start,
                self.view.range.end,
                self.view.file_offset
            );
        }
        let mut retained = Vec::with_capacity(2);
        if self.view.range.start < published.start {
            let mut left = self.view.clone();
            left.range.end = published.start;
            retained.push(left);
        }
        if self.view.range.end > published.end {
            let mut right = self.view;
            right.file_offset = right
                .file_offset
                .checked_add(published.end - right.range.start)
                .ok_or(DeferredAnonymousError::InvalidRange)?;
            right.range.start = published.end;
            retained.push(right);
        }
        self.files.views.splice(self.index..=self.index, retained);
        Ok(())
    }

    pub fn commit(mut self) {
        if self.files.views.get(self.index).is_none_or(|current| {
            current.range != self.view.range
                || current.file_offset != self.view.file_offset
                || !Arc::ptr_eq(&current.file, &self.view.file)
        }) {
            carrick_fatal!(
                "guest_mem::deferred_anonymous",
                "deferred private file view mutated or displaced under lock during commit: index={} start={:#x} end={:#x} offset={:#x}",
                self.index,
                self.view.range.start,
                self.view.range.end,
                self.view.file_offset
            );
        }
        self.files.views.remove(self.index);
    }
}

#[must_use]
pub struct DeferredAnonymousTransition<'a> {
    state: MutexGuard<'a, State>,
    range: Range<u64>,
}
impl DeferredAnonymousTransition<'_> {
    /// Call only after successful publication. Logical zero-read residency remains.
    pub fn commit(mut self) {
        remove(&mut self.state.pristine, &self.range);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    #[test]
    fn pristine_validation_is_nonmutating_and_rejects_holes_and_overflow() {
        let state = DeferredAnonymousState::new();
        state.reserve_fresh(GuestVa(0x1000), 0x3000).unwrap();
        let before = state.snapshot();
        assert!(state.covers_pristine(GuestVa(0x1fff), 2));
        assert!(state.covers_pristine(GuestVa(0x1000), 0x3000));
        assert!(!state.covers_pristine(GuestVa(0xfff), 2));
        assert!(!state.covers_pristine(GuestVa(0x3fff), 2));
        assert!(!state.covers_pristine(GuestVa(u64::MAX), 2));
        assert!(!state.covers_pristine(GuestVa(0x1000), 0));
        assert_eq!(state.snapshot(), before);
        state
            .begin_materialization(GuestVa(0x2000), 4096)
            .unwrap()
            .commit();
        assert!(!state.covers_pristine(GuestVa(0x1fff), 0x1002));
        assert!(state.covers_pristine(GuestVa(0x3001), 2));
        state.retire(GuestVa(0x3000), 4096).unwrap();
        assert!(!state.covers_pristine(GuestVa(0x3001), 2));
        assert!(state.snapshot().zero_read_resident.is_empty());
    }

    #[test]
    fn exact_zero_reads_and_lifecycle() {
        let state = DeferredAnonymousState::new();
        state.reserve_fresh(GuestVa(0x1000), 0x2000).unwrap();
        state.reserve_fresh(GuestVa(0x3000), 0x1000).unwrap();
        assert_eq!(
            state.snapshot().pristine,
            vec![GuestVa(0x1000)..GuestVa(0x4000)]
        );
        let mut bytes = [9; 4];
        assert!(
            state
                .copy_pristine_zero(GuestVa(0x1ffc), &mut bytes)
                .unwrap()
        );
        assert_eq!(bytes, [0; 4]);
        assert_eq!(
            state.snapshot().zero_read_resident,
            vec![GuestVa(0x1000)..GuestVa(0x2000)]
        );
        assert!(
            state
                .copy_pristine_zero(GuestVa(0x1ffe), &mut bytes)
                .is_err()
        );
        state.retire(GuestVa(0x2000), 0x1000).unwrap();
        bytes.fill(7);
        assert!(
            !state
                .copy_pristine_zero(GuestVa(0x2000), &mut bytes)
                .unwrap()
        );
        assert_eq!(bytes, [7; 4]);
        state.reserve_fresh(GuestVa(0x1000), 0x1000).unwrap();
        assert!(state.snapshot().zero_read_resident.is_empty());
        assert!(state.reserve_fresh(GuestVa(u64::MAX - 4095), 4096).is_err());
        assert!(state.retire(GuestVa(1), 4096).is_err());
        assert!(state.retire(GuestVa(0), 0).is_err());
    }
    #[test]
    fn transition_commit_failure_and_fork_isolation() {
        let state = DeferredAnonymousState::new();
        state.reserve_fresh(GuestVa(0x1000), 0x3000).unwrap();
        let child = state.fork_private();
        let before = state.snapshot();
        drop(state.begin_materialization(GuestVa(0x2000), 4096).unwrap());
        assert_eq!(state.snapshot(), before);
        state
            .begin_materialization(GuestVa(0x2000), 4096)
            .unwrap()
            .commit();
        assert_eq!(
            state.snapshot().pristine,
            vec![
                GuestVa(0x1000)..GuestVa(0x2000),
                GuestVa(0x3000)..GuestVa(0x4000)
            ]
        );
        assert_eq!(child.snapshot(), before);
    }
    #[test]
    fn zero_read_residency_has_an_independent_lifecycle() {
        let state = DeferredAnonymousState::new();
        state.reserve_fresh(GuestVa(0x1000), 8192).unwrap();
        assert!(
            state
                .copy_pristine_zero(GuestVa(0x1000), &mut [1; 4])
                .unwrap()
        );
        state
            .begin_materialization(GuestVa(0x1000), 4096)
            .unwrap()
            .commit();
        assert_eq!(
            state.snapshot().zero_read_resident,
            vec![GuestVa(0x1000)..GuestVa(0x2000)]
        );
        state
            .clear_zero_read_residency(GuestVa(0x1000), 8192)
            .unwrap();
        assert!(state.snapshot().zero_read_resident.is_empty());
        assert_eq!(
            state.snapshot().pristine,
            vec![GuestVa(0x2000)..GuestVa(0x3000)]
        );
        assert!(
            state
                .copy_pristine_zero(GuestVa(0x2000), &mut [1; 4])
                .unwrap()
        );
        state.retire(GuestVa(0x2000), 4096).unwrap();
        assert!(state.snapshot().zero_read_resident.is_empty());
        assert!(state.snapshot().pristine.is_empty());
    }

    #[test]
    fn rolled_back_materializer_orders_before_zero_reader() {
        let state = std::sync::Arc::new(DeferredAnonymousState::new());
        state.reserve_fresh(GuestVa(0x1000), 4096).unwrap();
        let guard = state.begin_materialization(GuestVa(0x1000), 4096).unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let child = state.clone();
        let reader = std::thread::spawn(move || {
            assert!(child.state.try_lock().is_none());
            tx.send(()).unwrap();
            let mut bytes = [5; 4];
            (
                child
                    .copy_pristine_zero(GuestVa(0x1000), &mut bytes)
                    .unwrap(),
                bytes,
            )
        });
        rx.recv().unwrap();
        drop(guard); // No backend publication occurred: clean failure.
        assert_eq!(reader.join().unwrap(), (true, [0; 4]));
    }

    #[test]
    fn committed_materializer_orders_before_reader() {
        let state = std::sync::Arc::new(DeferredAnonymousState::new());
        state.reserve_fresh(GuestVa(0x1000), 4096).unwrap();
        let guard = state.begin_materialization(GuestVa(0x1000), 4096).unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let child = state.clone();
        let reader = std::thread::spawn(move || {
            assert!(child.state.try_lock().is_none());
            tx.send(()).unwrap();
            let mut bytes = [5; 4];
            (
                child
                    .copy_pristine_zero(GuestVa(0x1000), &mut bytes)
                    .unwrap(),
                bytes,
            )
        });
        rx.recv().unwrap();
        guard.commit();
        assert_eq!(reader.join().unwrap(), (false, [5; 4]));
    }

    #[test]
    fn deferred_file_recipe_survives_close_forks_and_trims_offsets() {
        let path = std::env::temp_dir().join(format!(
            "carrick-deferred-file-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        let bytes: Vec<u8> = (0..0x3000)
            .map(|index| (index / 0x1000) as u8 + 1)
            .collect();
        file.write_all(&bytes).unwrap();

        let state = DeferredAnonymousState::new();
        state
            .reserve_private_file(
                GuestVa(0x1000),
                0x3000,
                file.as_fd(),
                0,
                crate::PrivateFileSource::ImmutableLower,
            )
            .unwrap();
        let child = state.fork_private();
        drop(file);
        std::fs::remove_file(path).unwrap();

        let mut copied = [0; 8];
        assert!(
            state
                .copy_pristine_file(GuestVa(0x2000), &mut copied)
                .unwrap()
        );
        assert_eq!(copied, [2; 8], "the mapping-owned dup survives guest close");

        state.retire(GuestVa(0x2000), 0x1000).unwrap();
        assert_eq!(
            state.snapshot().private_file,
            vec![
                DeferredPrivateFileSnapshot {
                    range: GuestVa(0x1000)..GuestVa(0x2000),
                    file_offset: 0,
                    source: crate::PrivateFileSource::ImmutableLower,
                },
                DeferredPrivateFileSnapshot {
                    range: GuestVa(0x3000)..GuestVa(0x4000),
                    file_offset: 0x2000,
                    source: crate::PrivateFileSource::ImmutableLower,
                },
            ]
        );
        assert_eq!(
            child.snapshot().private_file,
            vec![DeferredPrivateFileSnapshot {
                range: GuestVa(0x1000)..GuestVa(0x4000),
                file_offset: 0,
                source: crate::PrivateFileSource::ImmutableLower,
            }],
            "fork-private metadata must not follow the parent's trim"
        );
        let mut page = [0; 0x1000];
        child
            .begin_private_file_materialization(GuestVa(0x2000))
            .map(|transition| {
                assert_eq!(transition.len(), 0x3000);
                assert!(!transition.is_empty());
                transition
                    .copy_pristine(GuestVa(0x2000), &mut page)
                    .unwrap();
            })
            .unwrap();
        assert_eq!(page, [2; 0x1000]);
        child
            .begin_private_file_materialization(GuestVa(0x2000))
            .unwrap()
            .commit_range(GuestVa(0x2000), 0x1000)
            .unwrap();
        assert_eq!(
            child.snapshot().private_file,
            vec![
                DeferredPrivateFileSnapshot {
                    range: GuestVa(0x1000)..GuestVa(0x2000),
                    file_offset: 0,
                    source: crate::PrivateFileSource::ImmutableLower,
                },
                DeferredPrivateFileSnapshot {
                    range: GuestVa(0x3000)..GuestVa(0x4000),
                    file_offset: 0x2000,
                    source: crate::PrivateFileSource::ImmutableLower,
                },
            ]
        );
        state
            .begin_private_file_materialization(GuestVa(0x3000))
            .unwrap()
            .commit();
        assert_eq!(state.snapshot().private_file.len(), 1);
    }

    #[test]
    fn materialized_subranges_enumerates_gaps_in_pristine_state() {
        let state = DeferredAnonymousState::new();
        let base = GuestVa(0x1000_0000);
        let len = 64 * 1024 * 1024; // 64 MiB
        state.reserve_fresh(base, len).unwrap();

        // Initially pristine: 0 materialized subranges.
        assert_eq!(state.materialized_subranges(base, len), vec![]);

        // Touch first page (0x1000_0000), middle page (0x1200_0000), and last page (0x13ff_f000).
        state.begin_materialization(base, 0x1000).unwrap().commit();
        state
            .begin_materialization(GuestVa(0x1200_0000), 0x1000)
            .unwrap()
            .commit();
        state
            .begin_materialization(GuestVa(0x13ff_f000), 0x1000)
            .unwrap()
            .commit();

        let subranges = state.materialized_subranges(base, len);
        assert_eq!(
            subranges,
            vec![
                GuestVa(0x1000_0000)..GuestVa(0x1000_1000),
                GuestVa(0x1200_0000)..GuestVa(0x1200_1000),
                GuestVa(0x13ff_f000)..GuestVa(0x1400_0000),
            ]
        );
    }
}
