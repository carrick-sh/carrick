use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[cfg(feature = "conformance-metrics")]
use parking_lot::Mutex;
#[cfg(feature = "conformance-metrics")]
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
#[cfg(feature = "conformance-metrics")]
use std::sync::{Arc, Weak};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Deserialize, Serialize)]
pub struct WorkScopeId {
    pub raw: u64,
    pub generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkMetric {
    KernelDispatches,
    KernelRedispatches,
    ContinuationEnrollments,
    ContinuationParks,
    WakePublications,
    ContinuationResumes,
    GuestMemoryReadBytes,
    GuestMemoryWriteBytes,
    GuestMemoryCopyBytes,
    GuestMemoryZeroBytes,
    BackingMaterializedBytes,
    VfsBackendOperations,
    DirectoryEntriesVisited,
    HostBackendCalls,
    PageTableEdits,
    PageTableInvalidations,
    /// Fresh host-heap allocations of a stage-1 page-table software image
    /// (one 1.75 MiB arena set). A child process needs an image, but a
    /// fork storm must recycle retired images rather than allocate per fork.
    PageTableImageAllocations,
    /// Fresh host anonymous mappings (`mmap`) created on behalf of one guest
    /// operation, such as a forked child's per-mm kernel-state backing. Pooled
    /// or recycled host backing does not count.
    HostMappingAllocations,
    /// Mapping and alias rows visited while (re)computing a fork's COW
    /// projection. A cached projection visits none; an invalidated one must
    /// visit rows proportional to what changed, never the whole process.
    ForkProjectionRowsVisited,
    BackingAllocations,
    TaskAdmissions,
    VcpuAdmissions,
    VcpuReleases,
    VcpuMigrations,
    FutexQueueVisits,
    FutexWaitersWoken,
}

impl WorkMetric {
    pub const COUNT: usize = 26;
    pub const ALL: [WorkMetric; Self::COUNT] = [
        Self::KernelDispatches,
        Self::KernelRedispatches,
        Self::ContinuationEnrollments,
        Self::ContinuationParks,
        Self::WakePublications,
        Self::ContinuationResumes,
        Self::GuestMemoryReadBytes,
        Self::GuestMemoryWriteBytes,
        Self::GuestMemoryCopyBytes,
        Self::GuestMemoryZeroBytes,
        Self::BackingMaterializedBytes,
        Self::VfsBackendOperations,
        Self::DirectoryEntriesVisited,
        Self::HostBackendCalls,
        Self::PageTableEdits,
        Self::PageTableInvalidations,
        Self::PageTableImageAllocations,
        Self::HostMappingAllocations,
        Self::ForkProjectionRowsVisited,
        Self::BackingAllocations,
        Self::TaskAdmissions,
        Self::VcpuAdmissions,
        Self::VcpuReleases,
        Self::VcpuMigrations,
        Self::FutexQueueVisits,
        Self::FutexWaitersWoken,
    ];
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct WorkSnapshot {
    pub values: BTreeMap<WorkMetric, u64>,
    pub dropped_events: u64,
    pub unknown_metrics: Vec<String>,
}

impl Default for WorkSnapshot {
    fn default() -> Self {
        Self::new()
    }
}

impl WorkSnapshot {
    pub fn new() -> Self {
        Self {
            values: BTreeMap::new(),
            dropped_events: 0,
            unknown_metrics: Vec::new(),
        }
    }

    pub fn with_dropped_events(mut self, dropped_events: u64) -> Self {
        self.dropped_events = dropped_events;
        self
    }

    pub fn with_unknown_metrics(mut self, unknown: Vec<String>) -> Self {
        self.unknown_metrics = unknown;
        self
    }

    pub fn insert(&mut self, metric: WorkMetric, value: u64) -> Result<(), WorkMeterError> {
        if self.values.insert(metric, value).is_some() {
            return Err(WorkMeterError::DuplicateMetric(metric));
        }
        Ok(())
    }

    pub fn get(&self, metric: WorkMetric) -> Option<u64> {
        self.values.get(&metric).copied()
    }

    pub fn values(&self) -> &BTreeMap<WorkMetric, u64> {
        &self.values
    }

    pub fn dropped_events(&self) -> u64 {
        self.dropped_events
    }

    pub fn unknown_metrics(&self) -> &[String] {
        &self.unknown_metrics
    }
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum WorkMeterError {
    #[error("work meter scope is retired")]
    RetiredScope,
    #[error("work meter counter arithmetic overflow")]
    Overflow,
    #[error("work meter has dropped events: {0}")]
    DroppedEvents(u64),
    #[error("work meter conformance-metrics feature is disabled")]
    Disabled,
    #[error("duplicate metric {0:?}")]
    DuplicateMetric(WorkMetric),
}

#[derive(Clone, Debug, Default)]
pub struct WorkMeter {
    #[cfg(feature = "conformance-metrics")]
    inner: Arc<MeterInner>,
}

#[cfg(feature = "conformance-metrics")]
#[derive(Debug, Default)]
struct MeterInner {
    next_raw: AtomicU64,
    generation: AtomicU64,
    retired_raws: Mutex<Vec<u64>>,
}

#[cfg(feature = "conformance-metrics")]
impl MeterInner {
    fn return_raw(&self, raw: u64) {
        let mut raws = self.retired_raws.lock();
        raws.push(raw);
    }
}

#[cfg(feature = "conformance-metrics")]
#[derive(Debug)]
struct ScopeState {
    retired: AtomicBool,
    overflow: AtomicBool,
    dropped_events: AtomicU64,
    slots: [AtomicU64; WorkMetric::COUNT],
}

#[cfg(feature = "conformance-metrics")]
impl Default for ScopeState {
    fn default() -> Self {
        Self {
            retired: AtomicBool::new(false),
            overflow: AtomicBool::new(false),
            dropped_events: AtomicU64::new(0),
            slots: std::array::from_fn(|_| AtomicU64::new(0)),
        }
    }
}

#[cfg(feature = "conformance-metrics")]
#[derive(Clone, Debug)]
pub struct WorkScope {
    id: WorkScopeId,
    state: Arc<ScopeState>,
    meter: Weak<MeterInner>,
}

#[cfg(not(feature = "conformance-metrics"))]
#[derive(Clone, Debug)]
pub struct WorkScope {
    id: WorkScopeId,
}

impl WorkMeter {
    #[cfg(feature = "conformance-metrics")]
    pub fn new_scope(&self) -> WorkScope {
        let raw = {
            let mut raws = self.inner.retired_raws.lock();
            raws.pop()
                .unwrap_or_else(|| self.inner.next_raw.fetch_add(1, Ordering::SeqCst))
        };
        let generation = self.inner.generation.fetch_add(1, Ordering::SeqCst);
        WorkScope {
            id: WorkScopeId { raw, generation },
            state: Arc::new(ScopeState::default()),
            meter: Arc::downgrade(&self.inner),
        }
    }

    #[cfg(not(feature = "conformance-metrics"))]
    pub fn new_scope(&self) -> WorkScope {
        WorkScope {
            id: WorkScopeId {
                raw: 0,
                generation: 0,
            },
        }
    }
}

impl WorkScope {
    pub fn id(&self) -> WorkScopeId {
        self.id
    }

    #[cfg(feature = "conformance-metrics")]
    pub fn is_retired(&self) -> bool {
        self.state.retired.load(Ordering::SeqCst)
    }

    #[cfg(not(feature = "conformance-metrics"))]
    pub fn is_retired(&self) -> bool {
        false
    }

    #[cfg(feature = "conformance-metrics")]
    pub fn add(&self, metric: WorkMetric, amount: u64) -> Result<(), WorkMeterError> {
        if self.state.retired.load(Ordering::SeqCst) {
            return Err(WorkMeterError::RetiredScope);
        }
        let slot = &self.state.slots[metric as usize];
        let res = slot.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
            v.checked_add(amount)
        });
        if res.is_err() {
            self.state.overflow.store(true, Ordering::SeqCst);
            return Err(WorkMeterError::Overflow);
        }
        Ok(())
    }

    #[cfg(not(feature = "conformance-metrics"))]
    pub fn add(&self, _metric: WorkMetric, _amount: u64) -> Result<(), WorkMeterError> {
        Ok(())
    }

    #[cfg(feature = "conformance-metrics")]
    pub fn snapshot(&self) -> Result<WorkSnapshot, WorkMeterError> {
        if self.state.overflow.load(Ordering::SeqCst) {
            return Err(WorkMeterError::Overflow);
        }
        let dropped = self.state.dropped_events.load(Ordering::SeqCst);
        if dropped > 0 {
            return Err(WorkMeterError::DroppedEvents(dropped));
        }
        let mut values = BTreeMap::new();
        for metric in WorkMetric::ALL {
            let count = self.state.slots[metric as usize].load(Ordering::Relaxed);
            values.insert(metric, count);
        }
        Ok(WorkSnapshot {
            values,
            dropped_events: 0,
            unknown_metrics: Vec::new(),
        })
    }

    #[cfg(not(feature = "conformance-metrics"))]
    pub fn snapshot(&self) -> Result<WorkSnapshot, WorkMeterError> {
        Err(WorkMeterError::Disabled)
    }

    #[cfg(feature = "conformance-metrics")]
    pub fn retire(&self) {
        if !self.state.retired.swap(true, Ordering::SeqCst)
            && let Some(meter) = self.meter.upgrade()
        {
            meter.return_raw(self.id.raw);
        }
    }

    #[cfg(not(feature = "conformance-metrics"))]
    pub fn retire(&self) {}

    #[cfg(feature = "conformance-metrics")]
    pub fn record_dropped(&self, count: u64) {
        self.state
            .dropped_events
            .fetch_add(count, Ordering::Relaxed);
    }

    #[cfg(not(feature = "conformance-metrics"))]
    pub fn record_dropped(&self, _count: u64) {}
}
