//! A recording venue over the one-task Kernel exec: the driver's step order,
//! and the neutral steps it owns, observed from the hooks that bracket them.

use std::cell::RefCell;
use std::task::{Context, Poll, Waker};

use super::*;
use crate::kernel::PreparedExec;

const ALTSTACK: carrick_abi::LinuxSigaltstack = carrick_abi::LinuxSigaltstack {
    ss_sp: 0x4000,
    ss_flags: 0,
    __pad: 0,
    ss_size: 0x2000,
};

struct RecordingVenue {
    dispatcher: SyscallDispatcher,
    image: AddressSpace,
    context: KernelContext,
    steps: RefCell<Vec<String>>,
    fail_at: Option<&'static str>,
}

struct RecordingTransaction<'a> {
    steps: &'a RefCell<Vec<String>>,
    fail_at: Option<&'static str>,
}

impl RecordingVenue {
    fn new(fail_at: Option<&'static str>) -> Self {
        let dispatcher = SyscallDispatcher::new();
        let context = dispatcher
            .capture_one_task_context()
            .expect("one-task context");
        context
            .thread()
            .update_signal_state(|state| state.set_altstack(Some(ALTSTACK)));
        let image = AddressSpace::from_regions(0x1_0000, Vec::new())
            .expect("empty image")
            .with_linux_initial_stack([b"tool".as_slice()], [b"STEP=exec".as_slice()])
            .expect("initial stack");
        Self {
            dispatcher,
            image,
            context,
            steps: RefCell::new(Vec::new()),
            fail_at,
        }
    }

    fn record(&self, step: &str) -> ExecStep<(), String> {
        self.steps.borrow_mut().push(step.to_owned());
        record_failure(self.fail_at, step)
    }

    /// Whether the driver has published the image identity and reset the
    /// caller's per-thread signal state yet.
    fn proc_state_published(&self) -> bool {
        let env_published = self.dispatcher.current_exec_env() == [b"STEP=exec".to_vec()];
        let signals_reset = self.context.thread().altstack().is_none();
        assert_eq!(
            env_published, signals_reset,
            "proc state publishes as one step"
        );
        env_published
    }
}

fn record_failure(fail_at: Option<&'static str>, step: &str) -> ExecStep<(), String> {
    if fail_at == Some(step) {
        return Err(ExecExit::new(Ok(Some(format!("{step} failed")))));
    }
    Ok(())
}

impl ImageReplacement<RecordingVenue> for RecordingTransaction<'_> {
    fn arm_no_return(
        &mut self,
        prepared: PreparedExec,
        dispatch_mm: Option<&PreparedDispatchMmExec>,
    ) -> ExecStep<PreparedExec, String> {
        assert!(
            dispatch_mm.is_some(),
            "the /proc generation is staged before the arm"
        );
        self.steps.borrow_mut().push("arm_no_return".to_owned());
        record_failure(self.fail_at, "arm_no_return")?;
        Ok(prepared)
    }

    fn install_image(&mut self, armed: PreparedExec) -> ExecStep<PreparedExec, String> {
        self.steps.borrow_mut().push("install_image".to_owned());
        record_failure(self.fail_at, "install_image")?;
        Ok(armed)
    }

    fn publish_mm(&mut self, installed: PreparedExec) -> ExecStep<PreparedExec, String> {
        self.steps.borrow_mut().push("publish_mm".to_owned());
        record_failure(self.fail_at, "publish_mm")?;
        Ok(installed)
    }
}

impl RootExecVenue for RecordingVenue {
    type Outcome = String;
    type Prepared = PreparedExec;
    type Envelope = ();
    type Armed = PreparedExec;
    type Installed = PreparedExec;
    type Replaced = PreparedExec;
    type Committed = ();
    type Resident = ();
    type Entry = ();

    fn dispatcher(&self) -> &SyscallDispatcher {
        &self.dispatcher
    }

    fn image(&self) -> &AddressSpace {
        &self.image
    }

    fn exec_context(&self) -> &KernelContext {
        &self.context
    }

    fn renames_host_process(&self) -> bool {
        false
    }

    fn record_stage(&self, phase: HvpatchExecRuntimeStagePhase, _started: Instant) {
        self.steps.borrow_mut().push(format!("stage:{phase:?}"));
    }

    fn fail_past_no_return(&mut self, cause: &str) -> ExecExit<String> {
        self.steps
            .borrow_mut()
            .push("fail_past_no_return".to_owned());
        ExecExit::new(Ok(Some(cause.to_owned())))
    }

    fn prepare_mm(&mut self) -> ExecStep<(PreparedExec, ()), String> {
        assert!(
            !self.proc_state_published(),
            "Kernel preparation precedes proc-state mutation"
        );
        self.record("prepare_mm")?;
        let prepared = self
            .dispatcher
            .prepare_one_task_kernel_exec(&self.context)
            .expect("prepare one-task exec");
        Ok((prepared, ()))
    }

    fn replace_image<R>(
        &mut self,
        prepared: PreparedExec,
        _topology_lock_started: Instant,
        replace: impl FnOnce(&mut dyn ImageReplacement<Self>, PreparedExec) -> ExecStep<R, String>,
    ) -> ExecStep<R, String> {
        assert!(
            self.proc_state_published(),
            "the signal reset and /proc generation precede the MM transaction"
        );
        self.record("replace_image")?;
        self.record_stage(HvpatchExecRuntimeStagePhase::TopologyLock, Instant::now());
        let mut transaction = RecordingTransaction {
            steps: &self.steps,
            fail_at: self.fail_at,
        };
        let replaced = replace(&mut transaction, prepared)?;
        self.record("settle_inventory")?;
        Ok(replaced)
    }

    fn commit(
        &mut self,
        replaced: PreparedExec,
        dispatch_mm: &mut Option<PreparedDispatchMmExec>,
    ) -> ExecStep<(KernelContext, ()), String> {
        self.record("commit")?;
        let committed = self
            .dispatcher
            .commit_one_task_kernel_exec(replaced)
            .expect("commit one-task exec");
        dispatch_mm
            .take()
            .expect("staged /proc generation")
            .commit();
        Ok((committed, ()))
    }

    fn adopt_successor_context(
        &mut self,
        committed_context: &KernelContext,
    ) -> ExecStep<(), String> {
        self.context = committed_context.retain_exact();
        self.record("adopt_successor_context")
    }

    fn load_successor_mm(&mut self, _: &KernelContext, (): &mut ()) -> ExecStep<(), String> {
        self.record("load_successor_mm")
    }

    fn entry_state(&mut self, _: &KernelContext, (): ()) -> ExecStep<(), String> {
        self.record("entry_state")
    }

    fn bind_successor_memory(&mut self, _: &KernelContext) -> ExecStep<(), String> {
        self.record("bind_successor_memory")
    }

    fn rebind_identity(&mut self, _: &KernelContext) {
        self.steps.borrow_mut().push("rebind_identity".to_owned());
    }

    fn verify_image(&mut self) -> ExecStep<(), String> {
        self.record("verify_image")
    }

    fn stamp_port(&mut self, _: &KernelContext) -> ExecStep<(), String> {
        self.record("stamp_port")
    }

    fn publish_replacement(&mut self, _: &KernelContext, (): (), (): ()) -> ExecStep<(), String> {
        self.record("publish_replacement")
    }
}

fn drive(venue: &mut RecordingVenue) -> Result<Option<String>, RuntimeError> {
    let identity = ExecImageIdentity {
        path: "/bin/tool".to_owned(),
        argv: vec!["tool".to_owned()],
        env: vec![b"STEP=exec".to_vec()],
        source: ExecSource::host(
            tempfile::tempfile().expect("executable"),
            "/bin/tool".into(),
        )
        .expect("host exec source"),
        binfmt_argv: None,
        command_line: "tool".to_owned(),
    };
    let mut future = Box::pin(drive_root_exec(
        venue,
        Drained::new(Instant::now()),
        identity,
    ));
    match future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(result) => result,
        Poll::Pending => panic!("the root exec driver never suspends"),
    }
}

fn steps(venue: &RecordingVenue) -> Vec<String> {
    venue.steps.borrow().clone()
}

#[test]
fn driver_runs_the_hvpatch_order_with_neutral_steps_between_venue_hooks() {
    let mut venue = RecordingVenue::new(None);

    assert!(matches!(drive(&mut venue), Ok(None)));

    assert_eq!(
        steps(&venue),
        [
            "stage:SiblingDrain",
            "prepare_mm",
            "stage:ProcState",
            "replace_image",
            "stage:TopologyLock",
            "arm_no_return",
            "install_image",
            "publish_mm",
            "settle_inventory",
            "commit",
            "adopt_successor_context",
            "load_successor_mm",
            "entry_state",
            "bind_successor_memory",
            "stage:EngineReplace",
            "stage:CloseCloexec",
            "rebind_identity",
            "verify_image",
            "stamp_port",
            "stage:Publication",
            "publish_replacement",
        ]
    );
    assert!(venue.proc_state_published());
}

#[test]
fn a_failure_past_the_no_return_arm_stops_the_driver_with_the_venue_outcome() {
    let mut venue = RecordingVenue::new(Some("install_image"));

    let outcome = drive(&mut venue).expect("a kill, not a runtime fault");

    assert_eq!(outcome.as_deref(), Some("install_image failed"));
    let steps = steps(&venue);
    assert_eq!(
        steps.last().map(String::as_str),
        Some("install_image"),
        "nothing after the failed hook runs: {steps:?}"
    );
    assert!(!steps.iter().any(|step| step == "commit"));
}

#[test]
fn proc_maps_projects_linux_initial_stack_vma_not_full_rlimit_backing() {
    let image = AddressSpace::from_regions(0x1_0000, Vec::new())
        .expect("empty image")
        .with_linux_initial_stack([b"tool".as_slice()], [b"KEY=value".as_slice()])
        .expect("initial stack");
    let initial_sp = image.initial_stack_pointer().expect("initial SP");
    let maps = proc_maps_from_address_space(&image);
    let stack = maps
        .iter()
        .find(|mapping| mapping.path == "[stack]")
        .expect("Linux-visible stack VMA");
    let expected_start =
        initial_sp.saturating_sub(128 * 1024) & !(crate::linux_abi::LINUX_PAGE_SIZE - 1);

    assert_eq!(stack.start, expected_start);
    assert_eq!(stack.end, crate::memory::LINUX_STACK_TOP);
    assert!(
        stack.start > crate::memory::LINUX_STACK_TOP - crate::memory::LINUX_STACK_SIZE,
        "the full RLIMIT-sized backing is not the initially grown Linux VMA"
    );
}
