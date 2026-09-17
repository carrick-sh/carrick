//! Report and observation records from a completed harness run.

use carrick_abi::LinuxErrno;

/// Record of a completed syscall.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Completion {
    /// The Linux PID of the task that issued the syscall.
    pub pid: i32,
    /// The diagnostic label of the syscall.
    pub label: &'static str,
    /// The outcome: Ok(return_value) or Err(errno).
    pub result: Result<i64, LinuxErrno>,
}

/// Record of an output buffer captured after a syscall completed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Output {
    /// The Linux PID of the task.
    pub pid: i32,
    /// The diagnostic label of the syscall.
    pub label: &'static str,
    /// The argument index (0..5) of the operand.
    pub arg: usize,
    /// An optional diagnostic / indexing tag.
    pub tag: Option<&'static str>,
    /// The captured bytes.
    pub bytes: Vec<u8>,
}

/// The report returned by [`crate::ScriptedBackend::run_root`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunReport {
    pub(crate) exit_code: i32,
    pub(crate) completions: Vec<Completion>,
    pub(crate) outputs: Vec<Output>,
    pub(crate) deaths: Vec<(i32, i32)>,
    pub(crate) tasks_started: usize,
    pub(crate) dispatches: usize,
    pub(crate) dispatch_events: Vec<(i32, &'static str)>,
}

impl RunReport {
    /// The root task's exit code.
    pub const fn exit_code(&self) -> i32 {
        self.exit_code
    }

    /// All completed syscalls in order of completion.
    pub fn completions(&self) -> &[Completion] {
        &self.completions
    }

    /// All captured output buffers in order of completion.
    pub fn outputs(&self) -> &[Output] {
        &self.outputs
    }

    /// All task deaths recorded as `(pid, signal)`.
    pub fn deaths(&self) -> &[(i32, i32)] {
        &self.deaths
    }

    /// How many Linux tasks ran: the root plus every published child.
    pub const fn tasks_started(&self) -> usize {
        self.tasks_started
    }

    /// Total number of `dispatcher.dispatch` calls across all tasks.
    pub const fn dispatches(&self) -> usize {
        self.dispatches
    }

    /// Total number of `dispatcher.dispatch` calls for a specific task `pid` and syscall `label`.
    pub fn dispatches_for(&self, pid: i32, label: &str) -> usize {
        self.dispatch_events
            .iter()
            .filter(|(p, l)| *p == pid && *l == label)
            .count()
    }

    /// Return all captured outputs for a given syscall `label`.
    pub fn outputs_for(&self, label: &str) -> Vec<&Output> {
        self.outputs.iter().filter(|o| o.label == label).collect()
    }

    /// The bytes of the first output captured for `label` (panics if none).
    #[allow(clippy::panic)]
    pub fn output(&self, label: &str) -> &[u8] {
        self.outputs
            .iter()
            .find(|o| o.label == label)
            .map(|o| o.bytes.as_slice())
            .unwrap_or_else(|| panic!("no output captured for label {label}"))
    }

    /// The bytes of the first output captured with `tag` (panics if none).
    #[allow(clippy::panic)]
    pub fn output_tagged(&self, tag: &str) -> &[u8] {
        self.outputs
            .iter()
            .find(|o| o.tag == Some(tag))
            .map(|o| o.bytes.as_slice())
            .unwrap_or_else(|| panic!("no output captured for tag {tag}"))
    }

    /// The return value of the first completion for `label` (panics if none or errno).
    #[allow(clippy::panic)]
    pub fn ret(&self, label: &str) -> i64 {
        self.completions
            .iter()
            .find(|c| c.label == label)
            .and_then(|c| c.result.ok())
            .unwrap_or_else(|| panic!("no successful completion for label {label}"))
    }
}
