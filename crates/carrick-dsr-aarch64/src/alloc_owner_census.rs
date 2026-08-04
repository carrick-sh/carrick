use crate::alloc_owner_wire::{
    AllocationFlushReason, AllocationOwner, AllocationOwnerCensusFile, AllocationOwnerWireError,
    OwnerSnapshot,
};
use std::alloc::{Layout, System};
use std::cell::Cell;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};

/// Internal host-self-reexec transport. This is consumed at main entry and
/// never forwarded into the guest environment.
pub const EXEC_EPOCH_ENV: &str = "CARRICK_ALLOC_OWNER_EXEC_EPOCH";

#[cfg(test)]
#[global_allocator]
static TEST_ALLOC_OWNER_CENSUS: TaggedSystem = TaggedSystem;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum CensusState {
    Disabled = 0,
    Armed = 1,
    ObserverPaused = 2,
    Transition = 3,
    Terminal = 4,
}

impl CensusState {
    fn from_raw(raw: u8) -> Option<Self> {
        match raw {
            0 => Some(Self::Disabled),
            1 => Some(Self::Armed),
            2 => Some(Self::ObserverPaused),
            3 => Some(Self::Transition),
            4 => Some(Self::Terminal),
            _ => None,
        }
    }
}

thread_local! {
    static CURRENT_OWNER: Cell<AllocationOwner> =
        const { Cell::new(AllocationOwner::Other) };
}

struct OwnerCounters {
    requested_bytes: AtomicU64,
    alloc_calls: AtomicU64,
    zeroed_calls: AtomicU64,
    realloc_calls: AtomicU64,
}

impl OwnerCounters {
    const fn new() -> Self {
        Self {
            requested_bytes: AtomicU64::new(0),
            alloc_calls: AtomicU64::new(0),
            zeroed_calls: AtomicU64::new(0),
            realloc_calls: AtomicU64::new(0),
        }
    }

    fn snapshot(&self) -> OwnerSnapshot {
        OwnerSnapshot {
            requested_bytes: self.requested_bytes.load(Ordering::Relaxed),
            alloc_calls: self.alloc_calls.load(Ordering::Relaxed),
            zeroed_calls: self.zeroed_calls.load(Ordering::Relaxed),
            realloc_calls: self.realloc_calls.load(Ordering::Relaxed),
        }
    }

    fn reset(&self) {
        self.requested_bytes.store(0, Ordering::Relaxed);
        self.alloc_calls.store(0, Ordering::Relaxed);
        self.zeroed_calls.store(0, Ordering::Relaxed);
        self.realloc_calls.store(0, Ordering::Relaxed);
    }
}

static COUNTERS: [OwnerCounters; AllocationOwner::COUNT] =
    [const { OwnerCounters::new() }; AllocationOwner::COUNT];
static OVERFLOW: AtomicBool = AtomicBool::new(false);
static LIFECYCLE_ERROR: AtomicBool = AtomicBool::new(false);
static CONFIGURED: AtomicBool = AtomicBool::new(false);
// Main-entry configuration is inherited into native fork children, but the
// launch supervisor itself has no NATIVEPERF process epoch and must never
// enter the portfolio. Initial/guest fork repair or exec-epoch transport turns
// this on for precisely the DSR process images the authority can join.
static PROCESS_PARTICIPATES: AtomicBool = AtomicBool::new(false);
static EXEC_EPOCH: AtomicU64 = AtomicU64::new(0);
static FRAGMENT_SEQUENCE: AtomicU64 = AtomicU64::new(0);
static STATE: AtomicU8 = AtomicU8::new(CensusState::Disabled as u8);
static OUTPUT_DIR: OnceLock<PathBuf> = OnceLock::new();
static AEXIT_REGISTERED: AtomicBool = AtomicBool::new(false);

#[cfg(any(test, feature = "test-hooks"))]
static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
static TEST_MONOTONIC_NS: AtomicU64 = AtomicU64::new(0);
#[cfg(test)]
static TEST_EXPORT_FAILURE: AtomicU8 = AtomicU8::new(0);

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum TestExportFailure {
    None = 0,
    ShortWrite = 1,
    Sync = 2,
    Rename = 3,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AllocationOperation {
    Alloc,
    AllocZeroed,
    Realloc,
}

/// Restores the prior semantic allocation owner when the scope ends.
pub struct OwnerScope {
    prior: AllocationOwner,
}

impl Drop for OwnerScope {
    fn drop(&mut self) {
        CURRENT_OWNER.set(self.prior);
    }
}

/// Attribute successful allocations in the current thread to `owner`.
pub fn scope(owner: AllocationOwner) -> OwnerScope {
    let prior = CURRENT_OWNER.replace(owner);
    OwnerScope { prior }
}

/// A diagnostic allocator that delegates requests unchanged to `System`.
pub struct TaggedSystem;

unsafe impl std::alloc::GlobalAlloc for TaggedSystem {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { std::alloc::GlobalAlloc::alloc(&System, layout) };
        record_non_null(ptr, AllocationOperation::Alloc, layout.size());
        ptr
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { std::alloc::GlobalAlloc::alloc_zeroed(&System, layout) };
        record_non_null(ptr, AllocationOperation::AllocZeroed, layout.size());
        ptr
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let next = unsafe { std::alloc::GlobalAlloc::realloc(&System, ptr, layout, new_size) };
        record_non_null(next, AllocationOperation::Realloc, new_size);
        next
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { std::alloc::GlobalAlloc::dealloc(&System, ptr, layout) };
    }
}

fn record_non_null(ptr: *mut u8, operation: AllocationOperation, requested_bytes: usize) {
    if !ptr.is_null() {
        record_success(operation, requested_bytes);
    }
}

fn record_success(operation: AllocationOperation, requested_bytes: usize) {
    if STATE.load(Ordering::Relaxed) != CensusState::Armed as u8
        || !PROCESS_PARTICIPATES.load(Ordering::Relaxed)
    {
        return;
    }
    let Ok(requested_bytes) = u64::try_from(requested_bytes) else {
        OVERFLOW.store(true, Ordering::Relaxed);
        return;
    };
    CURRENT_OWNER.with(|current| {
        let counters = &COUNTERS[current.get() as usize];
        checked_add(&counters.requested_bytes, requested_bytes);
        let operation_counter = match operation {
            AllocationOperation::Alloc => &counters.alloc_calls,
            AllocationOperation::AllocZeroed => &counters.zeroed_calls,
            AllocationOperation::Realloc => &counters.realloc_calls,
        };
        checked_add(operation_counter, 1);
    });
}

fn checked_add(counter: &AtomicU64, delta: u64) {
    let old = counter.fetch_add(delta, Ordering::Relaxed);
    if old.checked_add(delta).is_none() {
        OVERFLOW.store(true, Ordering::Relaxed);
    }
}

fn snapshot() -> [OwnerSnapshot; AllocationOwner::COUNT] {
    std::array::from_fn(|index| COUNTERS[index].snapshot())
}

fn reset_counters_and_tls() {
    for counters in &COUNTERS {
        counters.reset();
    }
    CURRENT_OWNER.set(AllocationOwner::Other);
    OVERFLOW.store(false, Ordering::Relaxed);
}

/// Fail-closed diagnostic configuration, lifecycle, wire, or export error.
#[derive(Debug, thiserror::Error)]
pub enum CensusError {
    #[error("allocation-owner census lifecycle error: {0}")]
    Lifecycle(&'static str),
    #[error("allocation-owner census has no configured output directory")]
    MissingOutputDirectory,
    #[error("allocation-owner census output path contains a NUL byte")]
    PathContainsNul,
    #[error("allocation-owner census monotonic clock failed: {0}")]
    Clock(std::io::Error),
    #[error("allocation-owner census configuration error: {0}")]
    Configuration(&'static str),
    #[error("allocation-owner census atexit registration failed")]
    AtexitRegistration,
    #[error("allocation-owner census {operation} failed for {path}: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error(transparent)]
    Wire(#[from] AllocationOwnerWireError),
}

fn lifecycle_error(message: &'static str) -> CensusError {
    LIFECYCLE_ERROR.store(true, Ordering::Relaxed);
    CensusError::Lifecycle(message)
}

/// Resolve feature-only environment authority and arm at the main-entry seam.
pub fn init_main_from_environment() -> Result<bool, CensusError> {
    init_main_from_environment_with(|| unsafe { libc::atexit(allocation_owner_atexit) })
}

fn init_main_from_environment_with(
    register_atexit: impl FnOnce() -> i32,
) -> Result<bool, CensusError> {
    if STATE.load(Ordering::Acquire) != CensusState::Disabled as u8 {
        return Err(lifecycle_error("main initialization was not first"));
    }
    let Some(directory) = std::env::var_os("CARRICK_ALLOC_OWNER_CENSUS_DIR") else {
        CONFIGURED.store(false, Ordering::Relaxed);
        PROCESS_PARTICIPATES.store(false, Ordering::Relaxed);
        return Ok(false);
    };
    let directory =
        std::fs::canonicalize(PathBuf::from(directory)).map_err(|source| CensusError::Io {
            operation: "resolve output directory",
            path: PathBuf::from("CARRICK_ALLOC_OWNER_CENSUS_DIR"),
            source,
        })?;
    if !directory.is_dir() {
        return Err(CensusError::Configuration(
            "CARRICK_ALLOC_OWNER_CENSUS_DIR is not a directory",
        ));
    }
    if let Some(configured) = OUTPUT_DIR.get() {
        if configured != &directory {
            return Err(CensusError::Configuration(
                "output directory changed within one process",
            ));
        }
    } else {
        OUTPUT_DIR
            .set(directory)
            .map_err(|_| CensusError::Configuration("output directory initialized concurrently"))?;
    }
    let (exec_epoch, process_participates) = match std::env::var_os(EXEC_EPOCH_ENV) {
        None => (0, false),
        Some(raw) => (
            raw.to_str()
                .ok_or(CensusError::Configuration(
                    "CARRICK_ALLOC_OWNER_EXEC_EPOCH is not UTF-8",
                ))?
                .parse::<u64>()
                .map_err(|_| {
                    CensusError::Configuration("CARRICK_ALLOC_OWNER_EXEC_EPOCH is not a u64")
                })?,
            true,
        ),
    };
    reset_counters_and_tls();
    LIFECYCLE_ERROR.store(false, Ordering::Relaxed);
    EXEC_EPOCH.store(exec_epoch, Ordering::Relaxed);
    FRAGMENT_SEQUENCE.store(0, Ordering::Relaxed);
    CONFIGURED.store(true, Ordering::Relaxed);
    PROCESS_PARTICIPATES.store(process_participates, Ordering::Relaxed);
    if let Err(error) = register_atexit_with(register_atexit) {
        CONFIGURED.store(false, Ordering::Relaxed);
        PROCESS_PARTICIPATES.store(false, Ordering::Relaxed);
        return Err(error);
    }
    STATE.store(CensusState::Armed as u8, Ordering::Release);
    Ok(true)
}

extern "C" fn allocation_owner_atexit() {
    let _ = drain_terminal(AllocationFlushReason::AtexitBackstop);
}

fn register_atexit_with(register: impl FnOnce() -> i32) -> Result<bool, CensusError> {
    if !CONFIGURED.load(Ordering::Relaxed) {
        return Ok(false);
    }
    if AEXIT_REGISTERED
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return Ok(false);
    }
    if register() != 0 {
        AEXIT_REGISTERED.store(false, Ordering::Release);
        return Err(CensusError::AtexitRegistration);
    }
    Ok(true)
}

/// Register the idempotent terminal backstop once for a configured process.
pub fn register_atexit_backstop() -> Result<bool, CensusError> {
    register_atexit_with(|| unsafe { libc::atexit(allocation_owner_atexit) })
}

/// Restores allocation counting after an observer-only pause.
pub struct ObserverPause {
    active: bool,
}

impl Drop for ObserverPause {
    fn drop(&mut self) {
        if self.active
            && STATE
                .compare_exchange(
                    CensusState::ObserverPaused as u8,
                    CensusState::Armed as u8,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_err()
        {
            LIFECYCLE_ERROR.store(true, Ordering::Relaxed);
        }
    }
}

/// Pause counting around an existing diagnostic serializer without draining.
pub fn observer_pause() -> ObserverPause {
    match CensusState::from_raw(STATE.load(Ordering::Acquire)) {
        Some(CensusState::Disabled | CensusState::Terminal) => ObserverPause { active: false },
        Some(CensusState::Armed) => {
            let active = STATE
                .compare_exchange(
                    CensusState::Armed as u8,
                    CensusState::ObserverPaused as u8,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok();
            if !active {
                LIFECYCLE_ERROR.store(true, Ordering::Relaxed);
            }
            ObserverPause { active }
        }
        Some(CensusState::ObserverPaused | CensusState::Transition) | None => {
            LIFECYCLE_ERROR.store(true, Ordering::Relaxed);
            ObserverPause { active: false }
        }
    }
}

fn expected_next_epoch(next_exec_epoch: u64) -> Result<(), CensusError> {
    let current = EXEC_EPOCH.load(Ordering::Relaxed);
    let expected = current
        .checked_add(1)
        .ok_or_else(|| lifecycle_error("exec epoch overflow"))?;
    if next_exec_epoch != expected {
        return Err(lifecycle_error("exec epoch handoff mismatch"));
    }
    Ok(())
}

fn begin_transition(reason: AllocationFlushReason) -> Result<(), CensusError> {
    STATE
        .compare_exchange(
            CensusState::Armed as u8,
            CensusState::Transition as u8,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .map_err(|_| lifecycle_error("drain did not start from armed state"))?;
    let result = export_record(reason);
    if result.is_err() {
        LIFECYCLE_ERROR.store(true, Ordering::Relaxed);
    }
    result
}

/// Guard spanning the final host `execve` attempt.
pub struct HostExecAttempt {
    active: bool,
    epoch: u64,
    next_fragment: u64,
}

impl Drop for HostExecAttempt {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        if STATE.load(Ordering::Acquire) != CensusState::Transition as u8 {
            LIFECYCLE_ERROR.store(true, Ordering::Relaxed);
            return;
        }
        reset_counters_and_tls();
        EXEC_EPOCH.store(self.epoch, Ordering::Relaxed);
        FRAGMENT_SEQUENCE.store(self.next_fragment, Ordering::Relaxed);
        STATE.store(CensusState::Armed as u8, Ordering::Release);
    }
}

/// Drain immediately before host `execve`; dropping the guard means it returned.
pub fn begin_host_exec_attempt(next_exec_epoch: u64) -> Result<HostExecAttempt, CensusError> {
    if STATE.load(Ordering::Acquire) == CensusState::Disabled as u8
        || !PROCESS_PARTICIPATES.load(Ordering::Acquire)
    {
        return Ok(HostExecAttempt {
            active: false,
            epoch: 0,
            next_fragment: 0,
        });
    }
    expected_next_epoch(next_exec_epoch)?;
    let next_fragment = FRAGMENT_SEQUENCE
        .load(Ordering::Relaxed)
        .checked_add(1)
        .ok_or_else(|| lifecycle_error("fragment sequence overflow"))?;
    let epoch = EXEC_EPOCH.load(Ordering::Relaxed);
    begin_transition(AllocationFlushReason::HostSelfReexecAttempt)?;
    Ok(HostExecAttempt {
        active: true,
        epoch,
        next_fragment,
    })
}

/// Guard for the result-free in-process translator exec commit.
pub struct InProcessExecTransition {
    active: bool,
    next_exec_epoch: u64,
    rearmed: bool,
}

impl InProcessExecTransition {
    /// Reset the outgoing counters and arm the committed successor epoch.
    pub fn rearm_successor(mut self) -> Result<(), CensusError> {
        if !self.active {
            self.rearmed = true;
            return Ok(());
        }
        if STATE.load(Ordering::Acquire) != CensusState::Transition as u8 {
            return Err(lifecycle_error(
                "in-process successor did not follow transition",
            ));
        }
        reset_counters_and_tls();
        EXEC_EPOCH.store(self.next_exec_epoch, Ordering::Relaxed);
        FRAGMENT_SEQUENCE.store(0, Ordering::Relaxed);
        STATE.store(CensusState::Armed as u8, Ordering::Release);
        self.rearmed = true;
        Ok(())
    }
}

impl Drop for InProcessExecTransition {
    fn drop(&mut self) {
        if self.active && !self.rearmed {
            LIFECYCLE_ERROR.store(true, Ordering::Relaxed);
        }
    }
}

/// Drain the outgoing allocation epoch at the in-process exec commit.
pub fn begin_in_process_exec(next_exec_epoch: u64) -> Result<InProcessExecTransition, CensusError> {
    if STATE.load(Ordering::Acquire) == CensusState::Disabled as u8
        || !PROCESS_PARTICIPATES.load(Ordering::Acquire)
    {
        return Ok(InProcessExecTransition {
            active: false,
            next_exec_epoch,
            rearmed: false,
        });
    }
    expected_next_epoch(next_exec_epoch)?;
    begin_transition(AllocationFlushReason::InProcessExec)?;
    Ok(InProcessExecTransition {
        active: true,
        next_exec_epoch,
        rearmed: false,
    })
}

/// Export an armed terminal image exactly once.
pub fn drain_terminal(reason: AllocationFlushReason) -> Result<bool, CensusError> {
    match CensusState::from_raw(STATE.load(Ordering::Acquire)) {
        Some(CensusState::Disabled | CensusState::Terminal) => Ok(false),
        Some(CensusState::Armed) if !PROCESS_PARTICIPATES.load(Ordering::Acquire) => {
            STATE
                .compare_exchange(
                    CensusState::Armed as u8,
                    CensusState::Terminal as u8,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .map_err(|_| lifecycle_error("non-participant terminal drain lost armed state"))?;
            Ok(false)
        }
        Some(CensusState::Armed) => {
            STATE
                .compare_exchange(
                    CensusState::Armed as u8,
                    CensusState::Transition as u8,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .map_err(|_| lifecycle_error("terminal drain lost armed state"))?;
            let result = export_record(reason);
            if result.is_err() {
                LIFECYCLE_ERROR.store(true, Ordering::Relaxed);
            }
            STATE.store(CensusState::Terminal as u8, Ordering::Release);
            result.map(|()| true)
        }
        Some(CensusState::ObserverPaused | CensusState::Transition) | None => {
            Err(lifecycle_error("terminal drain from invalid state"))
        }
    }
}

/// First child-only action after `fork`: discard every inherited observation.
pub fn reset_after_fork_child_first_action() {
    if !CONFIGURED.load(Ordering::Relaxed) {
        PROCESS_PARTICIPATES.store(false, Ordering::Relaxed);
        STATE.store(CensusState::Disabled as u8, Ordering::Relaxed);
        return;
    }
    STATE.store(CensusState::Disabled as u8, Ordering::Relaxed);
    PROCESS_PARTICIPATES.store(false, Ordering::Relaxed);
    reset_counters_and_tls();
    LIFECYCLE_ERROR.store(false, Ordering::Relaxed);
    EXEC_EPOCH.store(0, Ordering::Relaxed);
    FRAGMENT_SEQUENCE.store(0, Ordering::Relaxed);
    PROCESS_PARTICIPATES.store(true, Ordering::Relaxed);
    STATE.store(CensusState::Armed as u8, Ordering::Release);
}

fn export_record(reason: AllocationFlushReason) -> Result<(), CensusError> {
    let output_dir = OUTPUT_DIR
        .get()
        .ok_or(CensusError::MissingOutputDirectory)?;
    let pid = unsafe { libc::getpid() };
    let record = AllocationOwnerCensusFile {
        pid,
        exec_epoch: EXEC_EPOCH.load(Ordering::Relaxed),
        fragment_sequence: FRAGMENT_SEQUENCE.load(Ordering::Relaxed),
        reason,
        overflow: OVERFLOW.load(Ordering::Relaxed),
        lifecycle_error: LIFECYCLE_ERROR.load(Ordering::Relaxed),
        owners: snapshot(),
    };
    let rendered = record.render()?;
    let monotonic = monotonic_ns()?;
    let stem = format!(
        "alloc-owner-{pid}-{monotonic}-{}-{}",
        record.exec_epoch, record.fragment_sequence
    );
    let temporary = output_dir.join(format!("{stem}.txt.tmp"));
    let final_path = output_dir.join(format!("{stem}.txt"));
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temporary)
        .map_err(|source| CensusError::Io {
            operation: "create",
            path: temporary.clone(),
            source,
        })?;
    #[cfg(test)]
    if TEST_EXPORT_FAILURE.load(Ordering::Relaxed) == TestExportFailure::ShortWrite as u8 {
        let partial = rendered.len() / 2;
        file.write_all(&rendered.as_bytes()[..partial])
            .map_err(|source| CensusError::Io {
                operation: "injected short write",
                path: temporary.clone(),
                source,
            })?;
        return Err(CensusError::Io {
            operation: "injected short write",
            path: temporary,
            source: std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "injected partial allocation census write",
            ),
        });
    }
    file.write_all(rendered.as_bytes())
        .map_err(|source| CensusError::Io {
            operation: "write",
            path: temporary.clone(),
            source,
        })?;
    #[cfg(test)]
    if TEST_EXPORT_FAILURE.load(Ordering::Relaxed) == TestExportFailure::Sync as u8 {
        return Err(CensusError::Io {
            operation: "injected sync",
            path: temporary,
            source: std::io::Error::other("injected allocation census sync failure"),
        });
    }
    file.sync_all().map_err(|source| CensusError::Io {
        operation: "sync",
        path: temporary.clone(),
        source,
    })?;
    drop(file);
    #[cfg(test)]
    if TEST_EXPORT_FAILURE.load(Ordering::Relaxed) == TestExportFailure::Rename as u8 {
        return Err(CensusError::Io {
            operation: "injected rename",
            path: final_path,
            source: std::io::Error::other("injected allocation census rename failure"),
        });
    }
    rename_noreplace(&temporary, &final_path)?;
    Ok(())
}

fn monotonic_ns() -> Result<u64, CensusError> {
    #[cfg(test)]
    {
        let injected = TEST_MONOTONIC_NS.load(Ordering::Relaxed);
        if injected != 0 {
            return Ok(injected);
        }
    }
    let mut now = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut now) } != 0 {
        return Err(CensusError::Clock(std::io::Error::last_os_error()));
    }
    let seconds = u64::try_from(now.tv_sec)
        .ok()
        .and_then(|seconds| seconds.checked_mul(1_000_000_000))
        .ok_or_else(|| lifecycle_error("monotonic clock overflow"))?;
    let nanoseconds = u64::try_from(now.tv_nsec)
        .map_err(|_| lifecycle_error("negative monotonic nanoseconds"))?;
    seconds
        .checked_add(nanoseconds)
        .ok_or_else(|| lifecycle_error("monotonic clock overflow"))
}

#[cfg(target_os = "macos")]
fn rename_noreplace(temporary: &Path, final_path: &Path) -> Result<(), CensusError> {
    use std::os::unix::ffi::OsStrExt as _;

    let temporary_c = std::ffi::CString::new(temporary.as_os_str().as_bytes())
        .map_err(|_| CensusError::PathContainsNul)?;
    let final_c = std::ffi::CString::new(final_path.as_os_str().as_bytes())
        .map_err(|_| CensusError::PathContainsNul)?;
    if unsafe { libc::renamex_np(temporary_c.as_ptr(), final_c.as_ptr(), libc::RENAME_EXCL) } != 0 {
        return Err(CensusError::Io {
            operation: "rename",
            path: final_path.to_path_buf(),
            source: std::io::Error::last_os_error(),
        });
    }
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn rename_noreplace(temporary: &Path, final_path: &Path) -> Result<(), CensusError> {
    std::fs::hard_link(temporary, final_path).map_err(|source| CensusError::Io {
        operation: "link",
        path: final_path.to_path_buf(),
        source,
    })?;
    std::fs::remove_file(temporary).map_err(|source| CensusError::Io {
        operation: "unlink temporary",
        path: temporary.to_path_buf(),
        source,
    })?;
    Ok(())
}

#[cfg(any(test, feature = "test-hooks"))]
fn test_lock() -> std::sync::MutexGuard<'static, ()> {
    TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
fn reset_for_test() {
    STATE.store(CensusState::Disabled as u8, Ordering::Relaxed);
    PROCESS_PARTICIPATES.store(false, Ordering::Relaxed);
    reset_counters_and_tls();
    LIFECYCLE_ERROR.store(false, Ordering::Relaxed);
    EXEC_EPOCH.store(0, Ordering::Relaxed);
    FRAGMENT_SEQUENCE.store(0, Ordering::Relaxed);
    TEST_MONOTONIC_NS.store(0, Ordering::Relaxed);
    TEST_EXPORT_FAILURE.store(TestExportFailure::None as u8, Ordering::Relaxed);
}

#[cfg(test)]
fn set_armed_for_test(epoch: u64) {
    CONFIGURED.store(true, Ordering::Relaxed);
    PROCESS_PARTICIPATES.store(true, Ordering::Relaxed);
    EXEC_EPOCH.store(epoch, Ordering::Relaxed);
    FRAGMENT_SEQUENCE.store(0, Ordering::Relaxed);
    STATE.store(CensusState::Armed as u8, Ordering::Relaxed);
}

#[cfg(test)]
fn current_owner_for_test() -> AllocationOwner {
    CURRENT_OWNER.get()
}

#[cfg(test)]
fn record_success_for_test(operation: AllocationOperation, requested_bytes: usize) {
    record_success(operation, requested_bytes);
}

#[cfg(test)]
fn record_result_for_test(operation: AllocationOperation, requested_bytes: usize, succeeded: bool) {
    if succeeded {
        record_success(operation, requested_bytes);
    }
}

#[cfg(test)]
fn dealloc_for_test() {}

#[cfg(test)]
fn snapshot_for_test() -> [OwnerSnapshot; AllocationOwner::COUNT] {
    snapshot()
}

#[cfg(test)]
fn set_requested_bytes_for_test(owner: AllocationOwner, requested_bytes: u64) {
    COUNTERS[owner as usize]
        .requested_bytes
        .store(requested_bytes, Ordering::Relaxed);
}

#[cfg(test)]
fn overflowed_for_test() -> bool {
    OVERFLOW.load(Ordering::Relaxed)
}

#[cfg(test)]
fn configure_output_dir_for_test(path: &Path) {
    let path = std::fs::canonicalize(path).expect("canonical census test output");
    if let Some(configured) = OUTPUT_DIR.get() {
        assert_eq!(configured, &path);
    } else {
        OUTPUT_DIR
            .set(path)
            .expect("configure allocation census test output");
    }
    CONFIGURED.store(true, Ordering::Relaxed);
}

#[cfg(test)]
fn state_for_test() -> CensusState {
    CensusState::from_raw(STATE.load(Ordering::Relaxed)).expect("valid census state")
}

#[cfg(test)]
fn lifecycle_error_for_test() -> bool {
    LIFECYCLE_ERROR.load(Ordering::Relaxed)
}

#[cfg(test)]
fn identity_for_test() -> (u64, u64) {
    (
        EXEC_EPOCH.load(Ordering::Relaxed),
        FRAGMENT_SEQUENCE.load(Ordering::Relaxed),
    )
}

#[cfg(test)]
fn set_identity_for_test(epoch: u64, fragment: u64) {
    EXEC_EPOCH.store(epoch, Ordering::Relaxed);
    FRAGMENT_SEQUENCE.store(fragment, Ordering::Relaxed);
}

#[cfg(test)]
fn invoke_atexit_for_test() {
    allocation_owner_atexit();
}

#[cfg(test)]
fn reset_atexit_registration_for_test() {
    AEXIT_REGISTERED.store(false, Ordering::Relaxed);
}

#[cfg(test)]
fn register_atexit_with_for_test(register: impl FnOnce() -> i32) -> Result<bool, CensusError> {
    register_atexit_with(register)
}

#[cfg(test)]
fn set_monotonic_ns_for_test(value: u64) {
    TEST_MONOTONIC_NS.store(value, Ordering::Relaxed);
}

#[cfg(test)]
fn set_export_failure_for_test(failure: TestExportFailure) {
    TEST_EXPORT_FAILURE.store(failure as u8, Ordering::Relaxed);
}

#[cfg(test)]
fn init_main_from_environment_with_for_test(
    register_atexit: impl FnOnce() -> i32,
) -> Result<bool, CensusError> {
    init_main_from_environment_with(register_atexit)
}

/// Feature/test-hooks-only state seam for cross-crate lifecycle integration tests.
#[cfg(any(test, feature = "test-hooks"))]
#[allow(clippy::expect_used, clippy::panic)]
pub mod test_support {
    use super::*;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum State {
        Disabled,
        Armed,
        ObserverPaused,
        Transition,
        Terminal,
    }

    pub fn lock() -> std::sync::MutexGuard<'static, ()> {
        test_lock()
    }

    pub fn configure_output_dir(path: &Path) {
        let path = std::fs::canonicalize(path).expect("canonical census test output");
        if let Some(configured) = OUTPUT_DIR.get() {
            assert_eq!(configured, &path);
        } else {
            OUTPUT_DIR
                .set(path)
                .expect("configure allocation census test output");
        }
        CONFIGURED.store(true, Ordering::Relaxed);
    }

    pub fn reset_and_arm(epoch: u64, fragment: u64) {
        STATE.store(CensusState::Disabled as u8, Ordering::Relaxed);
        reset_counters_and_tls();
        LIFECYCLE_ERROR.store(false, Ordering::Relaxed);
        CONFIGURED.store(true, Ordering::Relaxed);
        PROCESS_PARTICIPATES.store(true, Ordering::Relaxed);
        EXEC_EPOCH.store(epoch, Ordering::Relaxed);
        FRAGMENT_SEQUENCE.store(fragment, Ordering::Relaxed);
        STATE.store(CensusState::Armed as u8, Ordering::Release);
    }

    pub fn reset_disabled() {
        STATE.store(CensusState::Disabled as u8, Ordering::Relaxed);
        PROCESS_PARTICIPATES.store(false, Ordering::Relaxed);
        reset_counters_and_tls();
        LIFECYCLE_ERROR.store(false, Ordering::Relaxed);
        EXEC_EPOCH.store(0, Ordering::Relaxed);
        FRAGMENT_SEQUENCE.store(0, Ordering::Relaxed);
    }

    pub fn state() -> State {
        match CensusState::from_raw(STATE.load(Ordering::Acquire)) {
            Some(CensusState::Disabled) => State::Disabled,
            Some(CensusState::Armed) => State::Armed,
            Some(CensusState::ObserverPaused) => State::ObserverPaused,
            Some(CensusState::Transition) => State::Transition,
            Some(CensusState::Terminal) => State::Terminal,
            None => panic!("invalid allocation census state"),
        }
    }

    pub fn identity() -> (u64, u64) {
        (
            EXEC_EPOCH.load(Ordering::Relaxed),
            FRAGMENT_SEQUENCE.load(Ordering::Relaxed),
        )
    }

    pub fn record(owner: AllocationOwner, bytes: usize) {
        let _scope = scope(owner);
        record_success(AllocationOperation::Alloc, bytes);
    }

    pub fn snapshot() -> [OwnerSnapshot; AllocationOwner::COUNT] {
        super::snapshot()
    }

    pub fn requested_bytes(owner: AllocationOwner) -> u64 {
        COUNTERS[owner as usize]
            .requested_bytes
            .load(Ordering::Relaxed)
    }

    pub fn assert_only_requested_bytes_increased(
        before: &[OwnerSnapshot; AllocationOwner::COUNT],
        after: &[OwnerSnapshot; AllocationOwner::COUNT],
        expected: &[AllocationOwner],
    ) {
        for owner in AllocationOwner::ALL {
            let before = before[owner as usize].requested_bytes;
            let after = after[owner as usize].requested_bytes;
            if expected.contains(&owner) {
                assert!(after > before, "{} did not increase", owner.token());
            } else {
                assert_eq!(after, before, "{} changed unexpectedly", owner.token());
            }
        }
    }

    pub fn lifecycle_error() -> bool {
        LIFECYCLE_ERROR.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alloc_owner_wire::{
        AllocationFlushReason, AllocationOwner, AllocationOwnerCensusFile,
    };
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::sync::atomic::AtomicUsize;

    fn prepare_output_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "carrick-alloc-owner-census-tests-{}",
            std::process::id()
        ));
        match std::fs::remove_dir_all(&dir) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => panic!("remove census test directory: {error}"),
        }
        std::fs::create_dir_all(&dir).expect("create census test directory");
        configure_output_dir_for_test(&dir);
        dir
    }

    fn records(dir: &Path) -> Vec<AllocationOwnerCensusFile> {
        let mut paths: Vec<PathBuf> = std::fs::read_dir(dir)
            .expect("read census directory")
            .map(|entry| entry.expect("read census entry").path())
            .filter(|path| path.extension().is_some_and(|extension| extension == "txt"))
            .collect();
        paths.sort();
        paths
            .into_iter()
            .map(|path| {
                AllocationOwnerCensusFile::parse(
                    &std::fs::read_to_string(path).expect("read census record"),
                )
                .expect("parse census record")
            })
            .collect()
    }

    #[test]
    fn nested_scope_restores_the_prior_owner() {
        let _test = test_lock();
        reset_for_test();
        set_armed_for_test(7);
        assert_eq!(current_owner_for_test(), AllocationOwner::Other);
        {
            let _outer = scope(AllocationOwner::DecodeReadBuffers);
            assert_eq!(current_owner_for_test(), AllocationOwner::DecodeReadBuffers);
            {
                let _inner = scope(AllocationOwner::PublicationMap);
                assert_eq!(current_owner_for_test(), AllocationOwner::PublicationMap);
            }
            assert_eq!(current_owner_for_test(), AllocationOwner::DecodeReadBuffers);
        }
        assert_eq!(current_owner_for_test(), AllocationOwner::Other);
    }

    #[test]
    fn scope_restores_after_unwind() {
        let _test = test_lock();
        reset_for_test();
        set_armed_for_test(0);
        let result = std::panic::catch_unwind(|| {
            let _owner = scope(AllocationOwner::PublicationRecovery);
            panic!("test unwind");
        });
        assert!(result.is_err());
        assert_eq!(current_owner_for_test(), AllocationOwner::Other);
    }

    #[test]
    fn realloc_charges_the_full_new_request() {
        let _test = test_lock();
        reset_for_test();
        set_armed_for_test(0);
        record_success_for_test(AllocationOperation::Realloc, 8192);
        let row = snapshot_for_test()[AllocationOwner::Other as usize];
        assert_eq!(row.requested_bytes, 8192);
        assert_eq!(row.realloc_calls, 1);
        assert_eq!(row.alloc_calls, 0);
        assert_eq!(row.zeroed_calls, 0);
    }

    #[test]
    fn operation_accounting_requires_success_and_keeps_call_kinds_disjoint() {
        let _test = test_lock();
        reset_for_test();
        set_armed_for_test(0);
        record_result_for_test(AllocationOperation::Alloc, 1024, false);
        record_result_for_test(AllocationOperation::Alloc, 64, true);
        record_result_for_test(AllocationOperation::AllocZeroed, 128, true);
        dealloc_for_test();
        let row = snapshot_for_test()[AllocationOwner::Other as usize];
        assert_eq!(row.requested_bytes, 192);
        assert_eq!(row.alloc_calls, 1);
        assert_eq!(row.zeroed_calls, 1);
        assert_eq!(row.realloc_calls, 0);
    }

    #[test]
    fn tagged_system_delegates_real_requests_and_records_each_success() {
        let _test = test_lock();
        reset_for_test();
        set_armed_for_test(0);
        let layout32 = Layout::from_size_align(32, 8).unwrap();
        let ptr = unsafe { std::alloc::GlobalAlloc::alloc(&TaggedSystem, layout32) };
        assert!(!ptr.is_null());
        let layout64 = Layout::from_size_align(64, 8).unwrap();
        let ptr = unsafe { std::alloc::GlobalAlloc::realloc(&TaggedSystem, ptr, layout32, 64) };
        assert!(!ptr.is_null());
        let layout16 = Layout::from_size_align(16, 8).unwrap();
        let zeroed = unsafe { std::alloc::GlobalAlloc::alloc_zeroed(&TaggedSystem, layout16) };
        assert!(!zeroed.is_null());
        assert!(
            unsafe { std::slice::from_raw_parts(zeroed, 16) }
                .iter()
                .all(|byte| *byte == 0)
        );

        let before_dealloc = snapshot_for_test()[AllocationOwner::Other as usize];
        unsafe {
            std::alloc::GlobalAlloc::dealloc(&TaggedSystem, ptr, layout64);
            std::alloc::GlobalAlloc::dealloc(&TaggedSystem, zeroed, layout16);
        }
        let after_dealloc = snapshot_for_test()[AllocationOwner::Other as usize];
        assert_eq!(before_dealloc, after_dealloc);
        assert_eq!(after_dealloc.requested_bytes, 32 + 64 + 16);
        assert_eq!(after_dealloc.alloc_calls, 1);
        assert_eq!(after_dealloc.zeroed_calls, 1);
        assert_eq!(after_dealloc.realloc_calls, 1);
    }

    #[test]
    fn overflow_invalidates_instead_of_wrapping() {
        let _test = test_lock();
        reset_for_test();
        set_armed_for_test(0);
        set_requested_bytes_for_test(AllocationOwner::Other, u64::MAX);
        record_success_for_test(AllocationOperation::Alloc, 1);
        assert!(overflowed_for_test());
        assert_eq!(
            snapshot_for_test()[AllocationOwner::Other as usize].requested_bytes,
            0
        );
    }

    #[test]
    fn thread_local_owners_feed_distinct_process_global_rows() {
        let _test = test_lock();
        reset_for_test();
        let ready = Arc::new(AtomicUsize::new(0));
        let go = Arc::new(AtomicBool::new(false));
        let recorded = Arc::new(AtomicUsize::new(0));
        let release = Arc::new(AtomicBool::new(false));
        let first_ready = Arc::clone(&ready);
        let first_go = Arc::clone(&go);
        let first_recorded = Arc::clone(&recorded);
        let first_release = Arc::clone(&release);
        let first = std::thread::spawn(move || {
            first_ready.fetch_add(1, Ordering::Release);
            while !first_go.load(Ordering::Acquire) {
                std::hint::spin_loop();
            }
            {
                let _owner = scope(AllocationOwner::DecodeReadBuffers);
                record_success_for_test(AllocationOperation::Alloc, 100);
            }
            first_recorded.fetch_add(1, Ordering::Release);
            while !first_release.load(Ordering::Acquire) {
                std::hint::spin_loop();
            }
        });
        let second_ready = Arc::clone(&ready);
        let second_go = Arc::clone(&go);
        let second_recorded = Arc::clone(&recorded);
        let second_release = Arc::clone(&release);
        let second = std::thread::spawn(move || {
            second_ready.fetch_add(1, Ordering::Release);
            while !second_go.load(Ordering::Acquire) {
                std::hint::spin_loop();
            }
            {
                let _owner = scope(AllocationOwner::PublicationIndexes);
                record_success_for_test(AllocationOperation::AllocZeroed, 200);
            }
            second_recorded.fetch_add(1, Ordering::Release);
            while !second_release.load(Ordering::Acquire) {
                std::hint::spin_loop();
            }
        });

        while ready.load(Ordering::Acquire) != 2 {
            std::hint::spin_loop();
        }
        set_armed_for_test(0);
        go.store(true, Ordering::Release);
        while recorded.load(Ordering::Acquire) != 2 {
            std::hint::spin_loop();
        }
        STATE.store(CensusState::Disabled as u8, Ordering::Release);
        let snapshot = snapshot_for_test();
        release.store(true, Ordering::Release);
        first.join().expect("first owner thread");
        second.join().expect("second owner thread");

        assert_eq!(
            snapshot[AllocationOwner::DecodeReadBuffers as usize].requested_bytes,
            100
        );
        assert_eq!(
            snapshot[AllocationOwner::PublicationIndexes as usize].requested_bytes,
            200
        );
        assert_eq!(snapshot[AllocationOwner::Other as usize].requested_bytes, 0);
        assert_eq!(current_owner_for_test(), AllocationOwner::Other);
    }

    #[test]
    fn observer_pause_excludes_observer_work_without_draining() {
        let _test = test_lock();
        let dir = prepare_output_dir();
        reset_for_test();
        set_armed_for_test(2);
        record_success_for_test(AllocationOperation::Alloc, 10);
        {
            let _pause = observer_pause();
            assert_eq!(state_for_test(), CensusState::ObserverPaused);
            record_success_for_test(AllocationOperation::Alloc, 1000);
        }
        assert_eq!(state_for_test(), CensusState::Armed);
        record_success_for_test(AllocationOperation::Alloc, 20);
        assert!(drain_terminal(AllocationFlushReason::ProcessExit).unwrap());
        let accepted = records(&dir);
        assert_eq!(accepted.len(), 1);
        assert_eq!(accepted[0].total_bytes().unwrap(), 30);
    }

    #[test]
    fn disabled_observer_pause_is_a_noop() {
        let _test = test_lock();
        reset_for_test();
        {
            let _pause = observer_pause();
            assert_eq!(state_for_test(), CensusState::Disabled);
        }
        assert_eq!(state_for_test(), CensusState::Disabled);
        assert!(!lifecycle_error_for_test());
    }

    #[test]
    fn terminal_drain_makes_atexit_backstop_idempotent() {
        let _test = test_lock();
        let dir = prepare_output_dir();
        reset_for_test();
        set_armed_for_test(0);
        record_success_for_test(AllocationOperation::Alloc, 64);
        assert!(drain_terminal(AllocationFlushReason::ProcessExit).unwrap());
        assert!(!drain_terminal(AllocationFlushReason::AtexitBackstop).unwrap());
        let accepted = records(&dir);
        assert_eq!(accepted.len(), 1);
        assert_eq!(accepted[0].reason, AllocationFlushReason::ProcessExit);
    }

    #[test]
    fn returned_host_exec_rearms_same_epoch_at_next_fragment() {
        let _test = test_lock();
        let dir = prepare_output_dir();
        reset_for_test();
        set_armed_for_test(4);
        record_success_for_test(AllocationOperation::Alloc, 128);
        {
            let _attempt = begin_host_exec_attempt(5).unwrap();
            assert_eq!(state_for_test(), CensusState::Transition);
            assert_eq!(identity_for_test(), (4, 0));
        }
        assert_eq!(state_for_test(), CensusState::Armed);
        assert_eq!(identity_for_test(), (4, 1));
        assert_eq!(
            snapshot_for_test()[AllocationOwner::Other as usize].requested_bytes,
            0
        );
        record_success_for_test(AllocationOperation::Alloc, 32);
        assert!(drain_terminal(AllocationFlushReason::ProcessExit).unwrap());
        let accepted = records(&dir);
        assert_eq!(accepted.len(), 2);
        assert_eq!(
            accepted[0].reason,
            AllocationFlushReason::HostSelfReexecAttempt
        );
        assert_eq!(accepted[0].fragment_sequence, 0);
        assert_eq!(accepted[0].total_bytes().unwrap(), 128);
        assert_eq!(accepted[1].reason, AllocationFlushReason::ProcessExit);
        assert_eq!(accepted[1].fragment_sequence, 1);
        assert_eq!(accepted[1].total_bytes().unwrap(), 32);
    }

    #[test]
    fn successful_host_exec_simulation_never_rearms_old_image() {
        let _test = test_lock();
        let _dir = prepare_output_dir();
        reset_for_test();
        set_armed_for_test(6);
        let attempt = begin_host_exec_attempt(7).unwrap();
        std::mem::forget(attempt);
        assert_eq!(state_for_test(), CensusState::Transition);
        record_success_for_test(AllocationOperation::Alloc, 100);
        assert_eq!(
            snapshot_for_test()[AllocationOwner::Other as usize].requested_bytes,
            0
        );
    }

    #[test]
    fn in_process_exec_rearms_only_explicit_successor_epoch() {
        let _test = test_lock();
        let dir = prepare_output_dir();
        reset_for_test();
        set_armed_for_test(7);
        record_success_for_test(AllocationOperation::Alloc, 256);
        let transition = begin_in_process_exec(8).unwrap();
        assert_eq!(state_for_test(), CensusState::Transition);
        record_success_for_test(AllocationOperation::Alloc, 1000);
        transition.rearm_successor().unwrap();
        assert_eq!(state_for_test(), CensusState::Armed);
        assert_eq!(identity_for_test(), (8, 0));
        assert_eq!(
            snapshot_for_test()[AllocationOwner::Other as usize].requested_bytes,
            0
        );
        let accepted = records(&dir);
        assert_eq!(accepted.len(), 1);
        assert_eq!(accepted[0].reason, AllocationFlushReason::InProcessExec);
        assert_eq!(accepted[0].exec_epoch, 7);
        assert_eq!(accepted[0].total_bytes().unwrap(), 256);
    }

    #[test]
    fn identity_overflow_is_a_lifecycle_error_not_a_wrap() {
        let _test = test_lock();
        let _dir = prepare_output_dir();
        reset_for_test();
        set_armed_for_test(u64::MAX);
        assert!(begin_in_process_exec(0).is_err());
        assert!(lifecycle_error_for_test());
        assert_eq!(identity_for_test(), (u64::MAX, 0));

        reset_for_test();
        set_armed_for_test(1);
        set_identity_for_test(1, u64::MAX);
        assert!(begin_host_exec_attempt(2).is_err());
        assert!(lifecycle_error_for_test());
        assert_eq!(identity_for_test(), (1, u64::MAX));
    }

    #[test]
    fn fork_child_reset_clears_inherited_state_before_rearming_epoch_zero() {
        let _test = test_lock();
        reset_for_test();
        set_armed_for_test(9);
        set_identity_for_test(9, 3);
        let _owner = scope(AllocationOwner::PublicationMap);
        record_success_for_test(AllocationOperation::Alloc, 512);
        OVERFLOW.store(true, Ordering::Relaxed);
        reset_after_fork_child_first_action();
        assert_eq!(state_for_test(), CensusState::Armed);
        assert_eq!(identity_for_test(), (0, 0));
        assert!(PROCESS_PARTICIPATES.load(Ordering::Relaxed));
        assert_eq!(current_owner_for_test(), AllocationOwner::Other);
        assert!(!overflowed_for_test());
        assert_eq!(
            snapshot_for_test()[AllocationOwner::PublicationMap as usize].requested_bytes,
            0
        );
    }

    #[test]
    fn fork_child_reset_is_cow_private_and_preserves_the_parent_census() {
        let _test = test_lock();
        reset_for_test();
        set_armed_for_test(9);
        set_identity_for_test(9, 3);
        let _owner = scope(AllocationOwner::PublicationMap);
        record_success_for_test(AllocationOperation::Alloc, 512);

        let mut pipe = [-1; 2];
        assert_eq!(unsafe { libc::pipe(pipe.as_mut_ptr()) }, 0);
        let child = unsafe { libc::fork() };
        assert!(
            child >= 0,
            "fork failed: {}",
            std::io::Error::last_os_error()
        );
        if child == 0 {
            unsafe { libc::close(pipe[0]) };
            reset_after_fork_child_first_action();
            let (epoch, fragment) = identity_for_test();
            let report = [
                epoch,
                fragment,
                snapshot_for_test()[AllocationOwner::PublicationMap as usize].requested_bytes,
                current_owner_for_test() as u64,
            ];
            let written = unsafe {
                libc::write(
                    pipe[1],
                    report.as_ptr().cast(),
                    std::mem::size_of_val(&report),
                )
            };
            unsafe {
                libc::_exit(i32::from(
                    written != std::mem::size_of_val(&report) as isize,
                ))
            }
        }

        unsafe { libc::close(pipe[1]) };
        let mut child_report = [u64::MAX; 4];
        let read = unsafe {
            libc::read(
                pipe[0],
                child_report.as_mut_ptr().cast(),
                std::mem::size_of_val(&child_report),
            )
        };
        unsafe { libc::close(pipe[0]) };
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);

        assert_eq!(read, std::mem::size_of_val(&child_report) as isize);
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 0);
        assert_eq!(child_report, [0, 0, 0, AllocationOwner::Other as u64]);
        assert_eq!(identity_for_test(), (9, 3));
        assert_eq!(current_owner_for_test(), AllocationOwner::PublicationMap);
        assert_eq!(
            snapshot_for_test()[AllocationOwner::PublicationMap as usize].requested_bytes,
            512
        );
    }

    #[test]
    fn main_environment_arms_explicit_epoch_and_rejects_malformed_epoch() {
        let _test = test_lock();
        let dir = prepare_output_dir();
        reset_for_test();
        unsafe {
            std::env::set_var("CARRICK_ALLOC_OWNER_CENSUS_DIR", &dir);
            std::env::set_var("CARRICK_ALLOC_OWNER_EXEC_EPOCH", "12");
        }
        assert!(init_main_from_environment().unwrap());
        assert_eq!(state_for_test(), CensusState::Armed);
        assert_eq!(identity_for_test(), (12, 0));
        assert!(PROCESS_PARTICIPATES.load(Ordering::Relaxed));

        reset_for_test();
        unsafe {
            std::env::set_var("CARRICK_ALLOC_OWNER_EXEC_EPOCH", "not-an-epoch");
        }
        assert!(init_main_from_environment().is_err());
        assert_eq!(state_for_test(), CensusState::Disabled);
        unsafe {
            std::env::remove_var("CARRICK_ALLOC_OWNER_CENSUS_DIR");
            std::env::remove_var("CARRICK_ALLOC_OWNER_EXEC_EPOCH");
        }
    }

    #[test]
    fn absent_main_environment_leaves_census_disabled() {
        let _test = test_lock();
        reset_for_test();
        unsafe {
            std::env::remove_var("CARRICK_ALLOC_OWNER_CENSUS_DIR");
            std::env::remove_var("CARRICK_ALLOC_OWNER_EXEC_EPOCH");
        }
        assert!(!init_main_from_environment().unwrap());
        assert_eq!(state_for_test(), CensusState::Disabled);
        assert!(!PROCESS_PARTICIPATES.load(Ordering::Relaxed));
    }

    #[test]
    fn configured_main_that_never_enters_native_dsr_exports_nothing() {
        let _test = test_lock();
        let dir = prepare_output_dir();
        reset_for_test();
        reset_atexit_registration_for_test();
        unsafe {
            std::env::set_var("CARRICK_ALLOC_OWNER_CENSUS_DIR", &dir);
            std::env::remove_var("CARRICK_ALLOC_OWNER_EXEC_EPOCH");
        }
        assert!(init_main_from_environment_with_for_test(|| 0).unwrap());
        assert!(!PROCESS_PARTICIPATES.load(Ordering::Relaxed));
        record_success_for_test(AllocationOperation::Alloc, 4096);

        invoke_atexit_for_test();

        assert!(records(&dir).is_empty());
        unsafe {
            std::env::remove_var("CARRICK_ALLOC_OWNER_CENSUS_DIR");
        }
    }

    #[test]
    fn disabled_exec_transitions_are_noops() {
        let _test = test_lock();
        reset_for_test();

        drop(begin_host_exec_attempt(1).expect("disabled host exec is a no-op"));
        begin_in_process_exec(1)
            .expect("disabled in-process exec is a no-op")
            .rearm_successor()
            .expect("disabled successor rearm is a no-op");

        assert_eq!(state_for_test(), CensusState::Disabled);
        assert!(!lifecycle_error_for_test());
    }

    #[test]
    fn main_initialization_registers_atexit_while_still_unarmed() {
        let _test = test_lock();
        let dir = prepare_output_dir();
        reset_for_test();
        reset_atexit_registration_for_test();
        unsafe {
            std::env::set_var("CARRICK_ALLOC_OWNER_CENSUS_DIR", &dir);
            std::env::remove_var("CARRICK_ALLOC_OWNER_EXEC_EPOCH");
        }
        let mut observed_registration = false;
        assert!(
            init_main_from_environment_with_for_test(|| {
                observed_registration = true;
                assert_eq!(state_for_test(), CensusState::Disabled);
                0
            })
            .unwrap()
        );
        assert!(observed_registration);
        assert_eq!(state_for_test(), CensusState::Armed);
        unsafe {
            std::env::remove_var("CARRICK_ALLOC_OWNER_CENSUS_DIR");
        }
    }

    #[test]
    fn atexit_callback_exports_once_and_registration_is_idempotent() {
        let _test = test_lock();
        let dir = prepare_output_dir();
        reset_for_test();
        set_armed_for_test(0);
        record_success_for_test(AllocationOperation::Alloc, 77);
        invoke_atexit_for_test();
        invoke_atexit_for_test();
        let accepted = records(&dir);
        assert_eq!(accepted.len(), 1);
        assert_eq!(accepted[0].reason, AllocationFlushReason::AtexitBackstop);
        assert_eq!(accepted[0].total_bytes().unwrap(), 77);

        reset_atexit_registration_for_test();
        let registrations = AtomicU64::new(0);
        assert!(
            register_atexit_with_for_test(|| {
                registrations.fetch_add(1, Ordering::Relaxed);
                0
            })
            .unwrap()
        );
        assert!(
            !register_atexit_with_for_test(|| {
                registrations.fetch_add(1, Ordering::Relaxed);
                0
            })
            .unwrap()
        );
        assert_eq!(registrations.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn overflowed_record_is_durable_but_never_interpretable() {
        let _test = test_lock();
        let dir = prepare_output_dir();
        reset_for_test();
        set_armed_for_test(0);
        set_requested_bytes_for_test(AllocationOwner::Other, u64::MAX);
        record_success_for_test(AllocationOperation::Alloc, 1);
        assert!(drain_terminal(AllocationFlushReason::ProcessExit).unwrap());
        let path = std::fs::read_dir(&dir)
            .expect("read overflow directory")
            .map(|entry| entry.expect("read overflow entry").path())
            .find(|path| path.extension().is_some_and(|extension| extension == "txt"))
            .expect("overflow record");
        let text = std::fs::read_to_string(path).expect("read overflow record");
        assert!(text.contains("|overflow=1|"));
        assert!(AllocationOwnerCensusFile::parse(&text).is_err());
    }

    #[test]
    fn existing_final_record_is_never_overwritten() {
        let _test = test_lock();
        let dir = prepare_output_dir();
        reset_for_test();
        set_armed_for_test(0);
        set_monotonic_ns_for_test(4242);
        let pid = unsafe { libc::getpid() };
        let final_path = dir.join(format!("alloc-owner-{pid}-4242-0-0.txt"));
        std::fs::write(&final_path, b"sentinel").expect("write collision sentinel");
        assert!(drain_terminal(AllocationFlushReason::ProcessExit).is_err());
        assert_eq!(
            std::fs::read(&final_path).expect("read collision sentinel"),
            b"sentinel"
        );
        assert!(
            dir.join(format!("alloc-owner-{pid}-4242-0-0.txt.tmp"))
                .exists()
        );
        assert!(lifecycle_error_for_test());
    }

    #[test]
    fn every_partial_export_failure_leaves_a_visible_temp_marker() {
        let _test = test_lock();
        for (index, failure) in [
            TestExportFailure::ShortWrite,
            TestExportFailure::Sync,
            TestExportFailure::Rename,
        ]
        .into_iter()
        .enumerate()
        {
            let dir = prepare_output_dir();
            reset_for_test();
            set_armed_for_test(0);
            set_monotonic_ns_for_test(5000 + index as u64);
            set_export_failure_for_test(failure);
            record_success_for_test(AllocationOperation::Alloc, 99);
            assert!(drain_terminal(AllocationFlushReason::ProcessExit).is_err());
            assert_eq!(state_for_test(), CensusState::Terminal);
            let paths: Vec<PathBuf> = std::fs::read_dir(&dir)
                .expect("read failed-export directory")
                .map(|entry| entry.expect("read failed-export entry").path())
                .collect();
            assert_eq!(paths.len(), 1);
            assert_eq!(
                paths[0].extension().and_then(|value| value.to_str()),
                Some("tmp")
            );
            assert!(lifecycle_error_for_test());
        }
    }

    #[test]
    fn abandoned_in_process_transition_is_invalid_and_stays_disarmed() {
        let _test = test_lock();
        let _dir = prepare_output_dir();
        reset_for_test();
        set_armed_for_test(1);
        let transition = begin_in_process_exec(2).unwrap();
        drop(transition);
        assert_eq!(state_for_test(), CensusState::Transition);
        assert!(lifecycle_error_for_test());
    }
}
