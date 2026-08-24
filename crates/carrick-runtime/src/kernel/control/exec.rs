//! Bounded logical-exec request and same-carrier admission boundary.
//!
//! Every path in this DTO is a guest-namespace path resolved by the carrier's
//! existing container filesystem authority. The protocol carries no host path,
//! file descriptor, host PID, or other ambient host authority.

use super::ControlNonce;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::mpsc::{Receiver, SyncSender, TrySendError};
use std::time::Duration;

const MAX_ARGV: usize = 32;
const MAX_ENV: usize = 64;
const MAX_SUPPLEMENTARY_GIDS: usize = 32;
const MAX_ITEM_BYTES: usize = 1_024;
const MAX_REQUEST_STRING_BYTES: usize = 3_072;

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecRequest {
    pub argv: Vec<String>,
    pub env: Vec<ExecEnvVar>,
    /// Absolute path in the container filesystem namespace.
    pub workdir: Option<String>,
    pub user: Option<ExecUser>,
    pub tty: bool,
    pub attach: ExecAttach,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecEnvVar {
    pub key: String,
    pub value: String,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecUser {
    pub uid: u32,
    pub gid: u32,
    pub supplementary_gids: Vec<u32>,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExecAttach {
    Detached,
    Capture,
}

/// Opaque 128-bit handle for the admitted logical job. It is intentionally not
/// a Linux task id or host process id. A later result/I/O operation can consume
/// this capability without weakening the carrier's exact task authority.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct ExecCapability(ControlNonce);

impl From<ControlNonce> for ExecCapability {
    fn from(value: ControlNonce) -> Self {
        Self(value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecResult {
    pub exit_code: i32,
    pub terminating_signal: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub output_truncated: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExecStatus {
    Unknown,
    Pending,
    Running,
    Complete(ExecResult),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ExecAdmissionError {
    #[error("logical exec admission is not installed in this carrier")]
    Unavailable,
    #[error("logical exec admission rejected the request")]
    Rejected,
}

/// Same-carrier bridge implemented by the HVPatch logical-job scheduler.
/// Implementations must treat `request_id` as the idempotency identity and may
/// return it as the job capability only after exact logical-task admission.
pub trait CarrierExecAdmission: Send + Sync + std::fmt::Debug + 'static {
    fn admit(
        &self,
        request_id: ExecCapability,
        request: ExecRequest,
    ) -> Result<ExecCapability, ExecAdmissionError>;

    fn query(&self, _capability: ExecCapability) -> ExecStatus {
        ExecStatus::Unknown
    }

    fn wait(&self, capability: ExecCapability) -> ExecStatus {
        self.query(capability)
    }
}

#[derive(Debug, Default)]
pub struct ExecAdmissionSlot {
    installed: parking_lot::RwLock<Option<Arc<dyn CarrierExecAdmission>>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("logical exec admission is already installed")]
pub struct ExecAdmissionInstallError;

impl ExecAdmissionSlot {
    pub fn install(
        &self,
        admission: Arc<dyn CarrierExecAdmission>,
    ) -> Result<(), ExecAdmissionInstallError> {
        let mut installed = self.installed.write();
        if installed.is_some() {
            return Err(ExecAdmissionInstallError);
        }
        *installed = Some(admission);
        Ok(())
    }
}

impl CarrierExecAdmission for ExecAdmissionSlot {
    fn admit(
        &self,
        request_id: ExecCapability,
        request: ExecRequest,
    ) -> Result<ExecCapability, ExecAdmissionError> {
        let admission = self
            .installed
            .read()
            .as_ref()
            .cloned()
            .ok_or(ExecAdmissionError::Unavailable)?;
        admission.admit(request_id, request)
    }

    fn query(&self, capability: ExecCapability) -> ExecStatus {
        self.installed
            .read()
            .as_ref()
            .map_or(ExecStatus::Unknown, |admission| admission.query(capability))
    }

    fn wait(&self, capability: ExecCapability) -> ExecStatus {
        self.installed
            .read()
            .as_ref()
            .map_or(ExecStatus::Unknown, |admission| admission.wait(capability))
    }
}

const ADMISSION_DEADLINE: Duration = Duration::from_secs(2);
const COMPLETED_RESULT_TTL: Duration = Duration::from_secs(5 * 60);
pub const MAX_CAPTURE_BYTES: usize = 2 * 1024;

#[derive(Debug)]
enum ExecRecord {
    Pending,
    Claimed,
    CancelRequested,
    Publishing,
    Running {
        task: super::ControlTaskKey,
    },
    Complete {
        result: ExecResult,
        completed_at: std::time::Instant,
    },
}

#[derive(Debug, Default)]
struct ExecTable {
    records: HashMap<ExecCapability, ExecRecord>,
}

struct ExecRuntimeInner {
    sender: SyncSender<ExecWork>,
    receiver: parking_lot::Mutex<Receiver<ExecWork>>,
    table: parking_lot::Mutex<ExecTable>,
    changed: parking_lot::Condvar,
    waker: parking_lot::RwLock<Option<Arc<dyn Fn() + Send + Sync>>>,
    record_capacity: usize,
    admission_deadline: Duration,
    completed_result_ttl: Duration,
}

impl std::fmt::Debug for ExecRuntimeInner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ExecRuntimeInner")
            .field("table", &self.table)
            .field("waker_installed", &self.waker.read().is_some())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug)]
pub struct ExecRuntime {
    inner: Arc<ExecRuntimeInner>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("logical exec wake route is already installed")]
pub struct ExecWakerInstallError;

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ExecWorkError {
    #[error("logical exec work was not admitted")]
    NotAdmitted,
    #[error("logical exec request was already consumed")]
    RequestConsumed,
}

#[derive(Debug)]
pub struct ExecWork {
    runtime: ExecRuntime,
    capability: ExecCapability,
    request: Option<ExecRequest>,
    publishing: bool,
    admitted: bool,
    completed: bool,
}

impl ExecRuntime {
    pub fn new(queue_capacity: usize) -> Self {
        Self::with_limits(queue_capacity, ADMISSION_DEADLINE, COMPLETED_RESULT_TTL)
    }

    fn with_limits(
        queue_capacity: usize,
        admission_deadline: Duration,
        completed_result_ttl: Duration,
    ) -> Self {
        let capacity = queue_capacity.max(1);
        let (sender, receiver) = std::sync::mpsc::sync_channel(capacity);
        Self {
            inner: Arc::new(ExecRuntimeInner {
                sender,
                receiver: parking_lot::Mutex::new(receiver),
                table: parking_lot::Mutex::new(ExecTable::default()),
                changed: parking_lot::Condvar::new(),
                waker: parking_lot::RwLock::new(None),
                record_capacity: capacity,
                admission_deadline,
                completed_result_ttl,
            }),
        }
    }

    #[cfg(test)]
    pub(super) fn new_for_test(queue_capacity: usize, admission_deadline: Duration) -> Self {
        Self::with_limits(queue_capacity, admission_deadline, COMPLETED_RESULT_TTL)
    }

    #[cfg(test)]
    pub(super) fn new_for_test_with_result_ttl(
        queue_capacity: usize,
        admission_deadline: Duration,
        completed_result_ttl: Duration,
    ) -> Self {
        Self::with_limits(queue_capacity, admission_deadline, completed_result_ttl)
    }

    pub fn install_waker(
        &self,
        waker: Arc<dyn Fn() + Send + Sync>,
    ) -> Result<(), ExecWakerInstallError> {
        let mut installed = self.inner.waker.write();
        if installed.is_some() {
            return Err(ExecWakerInstallError);
        }
        *installed = Some(waker);
        Ok(())
    }

    pub fn try_take(&self) -> Option<ExecWork> {
        loop {
            let work = self.inner.receiver.lock().try_recv().ok()?;
            if self.mark_claimed(work.capability) {
                return Some(work);
            }
        }
    }

    pub fn consume_result(&self, capability: ExecCapability) -> Option<ExecResult> {
        let mut table = self.inner.table.lock();
        self.purge_expired_results(&mut table, std::time::Instant::now());
        match table.records.remove(&capability) {
            Some(ExecRecord::Complete { result, .. }) => Some(result),
            Some(other) => {
                table.records.insert(capability, other);
                None
            }
            None => None,
        }
    }

    pub fn wait(&self, capability: ExecCapability) -> ExecStatus {
        let mut table = self.inner.table.lock();
        self.purge_expired_results(&mut table, std::time::Instant::now());
        match table.records.get(&capability) {
            None => ExecStatus::Unknown,
            Some(
                ExecRecord::Pending
                | ExecRecord::Claimed
                | ExecRecord::CancelRequested
                | ExecRecord::Publishing,
            ) => ExecStatus::Pending,
            Some(ExecRecord::Running { .. }) => ExecStatus::Running,
            Some(ExecRecord::Complete { .. }) => {
                let Some(ExecRecord::Complete { result, .. }) = table.records.remove(&capability)
                else {
                    return ExecStatus::Unknown;
                };
                ExecStatus::Complete(result)
            }
        }
    }

    pub fn query(&self, capability: ExecCapability) -> ExecStatus {
        let mut table = self.inner.table.lock();
        self.purge_expired_results(&mut table, std::time::Instant::now());
        match table.records.get(&capability) {
            None => ExecStatus::Unknown,
            Some(
                ExecRecord::Pending
                | ExecRecord::Claimed
                | ExecRecord::CancelRequested
                | ExecRecord::Publishing,
            ) => ExecStatus::Pending,
            Some(ExecRecord::Running { task }) => {
                let _ = task;
                ExecStatus::Running
            }
            Some(ExecRecord::Complete { result, .. }) => ExecStatus::Complete(result.clone()),
        }
    }

    fn purge_expired_results(&self, table: &mut ExecTable, now: std::time::Instant) {
        let ttl = self.inner.completed_result_ttl;
        table.records.retain(|_, record| {
            !matches!(
                record,
                ExecRecord::Complete { completed_at, .. }
                    if now.saturating_duration_since(*completed_at) >= ttl
            )
        });
    }

    fn evict_oldest_complete(table: &mut ExecTable) -> bool {
        let oldest = table
            .records
            .iter()
            .filter_map(|(capability, record)| match record {
                ExecRecord::Complete { completed_at, .. } => Some((*capability, *completed_at)),
                _ => None,
            })
            .min_by_key(|(_, completed_at)| *completed_at)
            .map(|(capability, _)| capability);
        oldest.is_some_and(|capability| table.records.remove(&capability).is_some())
    }

    fn mark_running(&self, capability: ExecCapability, task: super::ControlTaskKey) -> bool {
        let mut table = self.inner.table.lock();
        let Some(record) = table.records.get_mut(&capability) else {
            return false;
        };
        if !matches!(record, ExecRecord::Claimed | ExecRecord::Publishing) {
            return false;
        }
        *record = ExecRecord::Running { task };
        drop(table);
        self.inner.changed.notify_all();
        true
    }

    fn mark_claimed(&self, capability: ExecCapability) -> bool {
        let mut table = self.inner.table.lock();
        let Some(record) = table.records.get_mut(&capability) else {
            return false;
        };
        if !matches!(record, ExecRecord::Pending) {
            return false;
        }
        *record = ExecRecord::Claimed;
        drop(table);
        self.inner.changed.notify_all();
        true
    }

    fn begin_publication(&self, capability: ExecCapability) -> bool {
        let mut table = self.inner.table.lock();
        match table.records.get_mut(&capability) {
            Some(record @ ExecRecord::Claimed) => {
                *record = ExecRecord::Publishing;
                true
            }
            Some(ExecRecord::CancelRequested) => {
                table.records.remove(&capability);
                drop(table);
                self.inner.changed.notify_all();
                false
            }
            _ => false,
        }
    }

    fn mark_rejected(&self, capability: ExecCapability) {
        let mut table = self.inner.table.lock();
        if table.records.get(&capability).is_some_and(|record| {
            matches!(
                record,
                ExecRecord::Pending
                    | ExecRecord::Claimed
                    | ExecRecord::CancelRequested
                    | ExecRecord::Publishing
            )
        }) {
            table.records.remove(&capability);
            drop(table);
            self.inner.changed.notify_all();
        }
    }

    fn complete(&self, capability: ExecCapability, mut result: ExecResult) {
        let stdout_original = result.stdout.len();
        let stderr_original = result.stderr.len();
        result.stdout.truncate(MAX_CAPTURE_BYTES);
        result.stderr.truncate(MAX_CAPTURE_BYTES);
        result.output_truncated |=
            stdout_original > result.stdout.len() || stderr_original > result.stderr.len();
        let mut table = self.inner.table.lock();
        if let std::collections::hash_map::Entry::Occupied(mut entry) =
            table.records.entry(capability)
        {
            entry.insert(ExecRecord::Complete {
                result,
                completed_at: std::time::Instant::now(),
            });
            drop(table);
            self.inner.changed.notify_all();
        }
    }
}

impl CarrierExecAdmission for ExecRuntime {
    fn admit(
        &self,
        request_id: ExecCapability,
        request: ExecRequest,
    ) -> Result<ExecCapability, ExecAdmissionError> {
        {
            let mut table = self.inner.table.lock();
            self.purge_expired_results(&mut table, std::time::Instant::now());
            if table.records.len() >= self.inner.record_capacity {
                Self::evict_oldest_complete(&mut table);
                if table.records.len() >= self.inner.record_capacity {
                    return Err(ExecAdmissionError::Unavailable);
                }
            }
            match table.records.entry(request_id) {
                std::collections::hash_map::Entry::Occupied(_) => {
                    return Err(ExecAdmissionError::Rejected);
                }
                std::collections::hash_map::Entry::Vacant(entry) => {
                    entry.insert(ExecRecord::Pending);
                }
            }
        }
        let work = ExecWork {
            runtime: self.clone(),
            capability: request_id,
            request: Some(request),
            publishing: false,
            admitted: false,
            completed: false,
        };
        match self.inner.sender.try_send(work) {
            Ok(()) => {}
            Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => {
                self.mark_rejected(request_id);
                return Err(ExecAdmissionError::Unavailable);
            }
        }
        if let Some(waker) = self.inner.waker.read().as_ref().cloned() {
            waker();
        }
        let mut table = self.inner.table.lock();
        let deadline = std::time::Instant::now() + self.inner.admission_deadline;
        loop {
            match table.records.get(&request_id) {
                Some(ExecRecord::Running { .. } | ExecRecord::Complete { .. }) => {
                    return Ok(request_id);
                }
                None => return Err(ExecAdmissionError::Rejected),
                Some(ExecRecord::Pending | ExecRecord::Claimed) => {}
                Some(ExecRecord::CancelRequested) => {
                    return Err(ExecAdmissionError::Unavailable);
                }
                // Publication is the crossed-no-return boundary: the fork
                // transaction owns this request and will publish Running (or
                // a terminal result). Return the capability immediately so a
                // slow peer-root materialization cannot wedge the control
                // endpoint or be mistaken for a cancellable admission.
                Some(ExecRecord::Publishing) => return Ok(request_id),
            }
            let now = std::time::Instant::now();
            if now >= deadline {
                match table.records.get_mut(&request_id) {
                    Some(record @ ExecRecord::Claimed) => {
                        *record = ExecRecord::CancelRequested;
                    }
                    _ => {
                        table.records.remove(&request_id);
                    }
                }
                return Err(ExecAdmissionError::Unavailable);
            }
            self.inner.changed.wait_for(&mut table, deadline - now);
        }
    }

    fn query(&self, capability: ExecCapability) -> ExecStatus {
        ExecRuntime::query(self, capability)
    }

    fn wait(&self, capability: ExecCapability) -> ExecStatus {
        ExecRuntime::wait(self, capability)
    }
}

impl ExecWork {
    pub fn request(&self) -> Result<&ExecRequest, ExecWorkError> {
        self.request.as_ref().ok_or(ExecWorkError::RequestConsumed)
    }

    pub fn take_request(&mut self) -> Result<ExecRequest, ExecWorkError> {
        self.request.take().ok_or(ExecWorkError::RequestConsumed)
    }

    pub fn capability(&self) -> ExecCapability {
        self.capability
    }

    pub fn admit(&mut self, task: super::ControlTaskKey) -> bool {
        self.admitted = self.runtime.mark_running(self.capability, task);
        self.admitted
    }

    /// Cross the final rollback boundary. A caller deadline may cancel claimed
    /// work before this point; once publishing begins, admission waits for the
    /// exact task rather than invalidating an authoritative child.
    pub fn begin_publication(&mut self) -> bool {
        self.publishing = self.runtime.begin_publication(self.capability);
        self.publishing
    }

    pub fn complete(mut self, result: ExecResult) -> Result<(), ExecWorkError> {
        if !self.admitted {
            self.runtime.mark_rejected(self.capability);
            self.completed = true;
            return Err(ExecWorkError::NotAdmitted);
        }
        self.runtime.complete(self.capability, result);
        self.completed = true;
        Ok(())
    }
}

impl Drop for ExecWork {
    fn drop(&mut self) {
        if self.completed {
            return;
        }
        if self.admitted {
            self.runtime.complete(
                self.capability,
                ExecResult {
                    exit_code: 125,
                    terminating_signal: None,
                    stdout: Vec::new(),
                    stderr: b"logical exec retired without terminal result".to_vec(),
                    output_truncated: false,
                },
            );
        } else if self.publishing {
            self.runtime.complete(
                self.capability,
                ExecResult {
                    exit_code: 125,
                    terminating_signal: None,
                    stdout: Vec::new(),
                    stderr: b"logical exec retired during publication without exact task admission"
                        .to_vec(),
                    output_truncated: false,
                },
            );
        } else {
            self.runtime.mark_rejected(self.capability);
        }
    }
}

impl ExecRequest {
    pub(super) fn validate(&self) -> bool {
        if self.tty
            || self.attach != ExecAttach::Capture
            || self.argv.is_empty()
            || self.argv.len() > MAX_ARGV
            || self.env.len() > MAX_ENV
            || self
                .user
                .as_ref()
                .is_some_and(|user| user.supplementary_gids.len() > MAX_SUPPLEMENTARY_GIDS)
        {
            return false;
        }
        let mut total = 0_usize;
        let mut accept = |value: &str, allow_empty: bool| {
            if (!allow_empty && value.is_empty())
                || value.as_bytes().contains(&0)
                || value.len() > MAX_ITEM_BYTES
            {
                return false;
            }
            total = match total.checked_add(value.len()) {
                Some(total) => total,
                None => return false,
            };
            total <= MAX_REQUEST_STRING_BYTES
        };
        for arg in &self.argv {
            if !accept(arg, false) {
                return false;
            }
        }
        for variable in &self.env {
            if !valid_env_key(&variable.key)
                || !accept(&variable.key, false)
                || !accept(&variable.value, true)
            {
                return false;
            }
        }
        if let Some(workdir) = &self.workdir
            && (!workdir.starts_with('/') || !accept(workdir, false))
        {
            return false;
        }
        true
    }
}

fn valid_env_key(key: &str) -> bool {
    let mut bytes = key.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    (first == b'_' || first.is_ascii_alphabetic())
        && bytes.all(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::control::ControlTaskKey;

    fn request() -> ExecRequest {
        ExecRequest {
            argv: vec!["/bin/true".to_owned()],
            env: Vec::new(),
            workdir: None,
            user: None,
            tty: false,
            attach: ExecAttach::Capture,
        }
    }

    fn take_claimed(runtime: &ExecRuntime) -> ExecWork {
        loop {
            if let Some(work) = runtime.try_take() {
                return work;
            }
            std::thread::yield_now();
        }
    }

    #[test]
    fn claimed_work_cancels_cleanly_before_publication_deadline() {
        let runtime = ExecRuntime::new_for_test(1, Duration::from_millis(10));
        let submit = runtime.clone();
        let capability = ExecCapability(ControlNonce([9; 16]));
        let thread = std::thread::spawn(move || submit.admit(capability, request()));
        while runtime.query(capability) != ExecStatus::Pending {
            std::thread::yield_now();
        }
        let mut work = take_claimed(&runtime);
        std::thread::sleep(Duration::from_millis(20));
        assert_eq!(
            thread.join().expect("submitter"),
            Err(ExecAdmissionError::Unavailable)
        );
        assert!(!work.begin_publication());
        assert!(!work.admit(ControlTaskKey { pid: 2, serial: 1 }));
    }

    #[test]
    fn publishing_work_acknowledges_without_waiting_for_exact_admission() {
        let runtime = ExecRuntime::new_for_test(1, Duration::from_millis(10));
        let submit = runtime.clone();
        let capability = ExecCapability(ControlNonce([10; 16]));
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let thread = std::thread::spawn(move || {
            done_tx
                .send(submit.admit(capability, request()))
                .expect("publish admission result");
        });
        while runtime.query(capability) != ExecStatus::Pending {
            std::thread::yield_now();
        }
        let mut work = take_claimed(&runtime);
        assert!(work.begin_publication());
        assert_eq!(
            done_rx
                .recv_timeout(Duration::from_millis(50))
                .expect("Publishing must not wait for child materialization"),
            Ok(capability)
        );
        assert_eq!(runtime.query(capability), ExecStatus::Pending);
        assert!(work.admit(ControlTaskKey { pid: 3, serial: 1 }));
        thread.join().expect("submitter");
    }

    #[test]
    fn dropped_publishing_work_completes_acknowledged_capability_with_terminal_failure() {
        let runtime = ExecRuntime::new_for_test(1, Duration::from_millis(250));
        let submit = runtime.clone();
        let capability = ExecCapability(ControlNonce([20; 16]));
        let thread = std::thread::spawn(move || submit.admit(capability, request()));
        while runtime.query(capability) != ExecStatus::Pending {
            std::thread::yield_now();
        }
        let mut work = take_claimed(&runtime);
        assert!(work.begin_publication());
        assert_eq!(thread.join().expect("submitter"), Ok(capability));

        drop(work);

        let ExecStatus::Complete(result) = runtime.wait(capability) else {
            panic!("acknowledged Publishing work did not retain a terminal result");
        };
        assert_eq!(result.exit_code, 125);
        assert_eq!(result.terminating_signal, None);
        assert!(result.stdout.is_empty());
        assert_eq!(
            result.stderr,
            b"logical exec retired during publication without exact task admission"
        );
        assert!(!result.output_truncated);
    }

    #[test]
    fn coalesced_control_wakes_retain_every_simultaneous_exec_request() {
        let runtime = ExecRuntime::new_for_test(3, Duration::from_millis(250));
        let wakes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let wake_count = Arc::clone(&wakes);
        runtime
            .install_waker(Arc::new(move || {
                wake_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }))
            .expect("install waker");
        let capabilities = [
            ExecCapability(ControlNonce([21; 16])),
            ExecCapability(ControlNonce([22; 16])),
            ExecCapability(ControlNonce([23; 16])),
        ];
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let submitters: Vec<_> = capabilities
            .into_iter()
            .map(|capability| {
                let runtime = runtime.clone();
                let done_tx = done_tx.clone();
                std::thread::spawn(move || {
                    done_tx
                        .send((capability, runtime.admit(capability, request())))
                        .expect("send admission result");
                })
            })
            .collect();
        drop(done_tx);
        while wakes.load(std::sync::atomic::Ordering::SeqCst) != capabilities.len() {
            std::thread::yield_now();
        }

        let mut claimed = Vec::new();
        for serial in 1..=capabilities.len() as u64 {
            let mut work = take_claimed(&runtime);
            let capability = work.capability();
            assert!(work.begin_publication());
            assert!(work.admit(ControlTaskKey {
                pid: 20 + serial as i32,
                serial,
            }));
            claimed.push((capability, work));
        }
        let admitted: std::collections::HashMap<_, _> = done_rx.iter().collect();
        for capability in capabilities {
            assert_eq!(admitted.get(&capability), Some(&Ok(capability)));
        }
        for submitter in submitters {
            submitter.join().expect("submitter");
        }
        for (_, work) in claimed {
            drop(work);
        }
    }

    #[test]
    fn wait_is_a_nonblocking_consume_poll_for_running_work() {
        let runtime = ExecRuntime::new_for_test(1, Duration::from_millis(250));
        let submit = runtime.clone();
        let capability = ExecCapability(ControlNonce([11; 16]));
        let thread = std::thread::spawn(move || submit.admit(capability, request()));
        while runtime.query(capability) != ExecStatus::Pending {
            std::thread::yield_now();
        }
        let mut work = take_claimed(&runtime);
        assert!(work.admit(ControlTaskKey { pid: 4, serial: 1 }));
        assert_eq!(thread.join().expect("submitter"), Ok(capability));

        let started = std::time::Instant::now();
        assert_eq!(runtime.wait(capability), ExecStatus::Running);
        assert!(
            started.elapsed() < Duration::from_millis(50),
            "WaitExec monopolized the serial control endpoint"
        );
    }

    #[test]
    fn abandoned_complete_result_expires_and_releases_capacity() {
        let runtime = ExecRuntime::new_for_test_with_result_ttl(
            1,
            Duration::from_millis(250),
            Duration::from_millis(5),
        );
        let first = ExecCapability(ControlNonce([12; 16]));
        let submit = runtime.clone();
        let thread = std::thread::spawn(move || submit.admit(first, request()));
        while runtime.query(first) != ExecStatus::Pending {
            std::thread::yield_now();
        }
        let mut work = take_claimed(&runtime);
        assert!(work.admit(ControlTaskKey { pid: 5, serial: 1 }));
        assert_eq!(thread.join().expect("submitter"), Ok(first));
        work.complete(ExecResult {
            exit_code: 0,
            terminating_signal: None,
            stdout: Vec::new(),
            stderr: Vec::new(),
            output_truncated: false,
        })
        .expect("complete");

        std::thread::sleep(Duration::from_millis(10));
        assert_eq!(runtime.query(first), ExecStatus::Unknown);

        let second = ExecCapability(ControlNonce([13; 16]));
        let submit = runtime.clone();
        let thread = std::thread::spawn(move || submit.admit(second, request()));
        while runtime.query(second) != ExecStatus::Pending {
            std::thread::yield_now();
        }
        drop(take_claimed(&runtime));
        assert_eq!(
            thread.join().expect("submitter"),
            Err(ExecAdmissionError::Rejected)
        );
    }
}
