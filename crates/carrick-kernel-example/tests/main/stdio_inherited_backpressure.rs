#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use carrick_abi::LinuxCloneFlags;
use carrick_hal::NullHostSignalBridge;
use carrick_hal::threaded::{Aarch64TaskCpuStateV1, GuestCpuState};
use carrick_hal::{GuestCpuId, GuestCpuPolicy, ThreadId};
use carrick_kernel::compat::{CompatReporter, SyscallArgs};
use carrick_kernel::dispatch::routing::OrdinaryDispatchRoute;
use carrick_kernel::dispatch::{
    DispatchOutcome, HostWaitContext, LinearMemory, PreparedDispatch, StdioSink, SyscallDispatcher,
    SyscallRequest, ThreadCtx,
};
use carrick_kernel::kernel::objects::MigratableTaskState;
use carrick_kernel::kernel::{
    ClonePlan, ExecutorBinding, ExecutorKick, ExecutorKickToken, Kernel, KernelContext, Scheduler,
};
use carrick_kernel::thread::{FutexTable, ThreadRegistry};

#[derive(Debug, Default)]
struct TestKick {
    binding: parking_lot::Mutex<Option<ExecutorBinding>>,
    tokens: parking_lot::Mutex<Vec<ExecutorKickToken>>,
    changed: parking_lot::Condvar,
    kicked: AtomicBool,
}

impl ExecutorKick for TestKick {
    fn try_bind(&self, binding: ExecutorBinding) -> bool {
        let mut current = self.binding.lock();
        if current.is_some() {
            return false;
        }
        *current = Some(binding);
        true
    }

    fn unbind(&self, binding: ExecutorBinding) {
        let mut current = self.binding.lock();
        if *current == Some(binding) {
            *current = None;
        }
    }

    fn rebind_exact_with(
        &self,
        predecessor: ExecutorBinding,
        successor: ExecutorBinding,
        publish: &mut dyn FnMut() -> bool,
    ) -> bool {
        let mut current = self.binding.lock();
        if *current != Some(predecessor) {
            return false;
        }
        if !publish() {
            return false;
        }
        *current = Some(successor);
        true
    }

    fn deliver_exact(&self, token: ExecutorKickToken) -> bool {
        let current = self.binding.lock();
        if !current.is_some_and(|binding| {
            binding.executor() == token.executor()
                && binding.executor_epoch() == token.executor_epoch()
                && binding.thread() == token.thread()
                && binding.generation() == token.generation()
        }) {
            return false;
        }
        self.kicked.store(true, Ordering::Release);
        self.tokens.lock().push(token);
        self.changed.notify_all();
        true
    }

    fn current_binding(&self) -> Option<ExecutorBinding> {
        *self.binding.lock()
    }
}

fn create_sibling_thread(
    kernel: &Arc<Kernel>,
    parent: &KernelContext,
    host_tid: i32,
) -> KernelContext {
    let plan = ClonePlan::from_flags(
        LinuxCloneFlags::THREAD | LinuxCloneFlags::SIGHAND | LinuxCloneFlags::VM,
    )
    .expect("thread plan");
    kernel
        .reserve_thread_clone(parent, plan, None)
        .expect("reserve thread clone")
        .prepare(ThreadId::synthetic_for_tests(host_tid))
        .expect("prepare thread clone")
        .commit()
        .expect("publish thread clone")
        .start_thread()
        .expect("start thread")
        .into_context()
}

fn publish_task(context: &KernelContext, marker: u64) {
    let mm = context.shared().mm().id();
    let state = MigratableTaskState {
        cpu: GuestCpuState::from_aarch64_v1(Aarch64TaskCpuStateV1 {
            gprs: std::array::from_fn(|index| marker + index as u64),
            pc: marker + 0x1000,
            pstate: marker + 0x2000,
            trap_pc: marker + 0x2100,
            trap_pstate: marker + 0x2200,
            sp_el0: marker + 0x3000,
            elr_el1: marker + 0x3100,
            spsr_el1: marker + 0x3200,
            ttbr0: marker + 0x4000,
            ttbr1: marker + 0x5000,
            tcr: marker + 0x6000,
            sctlr_el1: marker + 0x6100,
            mair_el1: marker + 0x6200,
            vbar_el1: marker + 0x6300,
            cpacr_el1: marker + 0x6400,
            cntkctl_el1: marker + 0x6500,
            tpidr_el1: marker + 0x6600,
            actlr_el1: marker + 0x7000,
            tpidr_el0: marker + 0x8000,
            tpidrro_el0: marker + 0x9000,
            contextidr_el1: marker + 0xa000,
            vregs: std::array::from_fn(|index| marker as u128 + index as u128),
            fpsr: marker as u32,
            fpcr: marker as u32 + 1,
            pending_resume_pc: Some(marker + 0xb000),
            last_syscall_nr: Some(marker),
            last_syscall_orig_x0: marker + 2,
            last_fault_esr: marker + 3,
            last_exit_class: marker,
            is_forked_child: false,
            syscall_continuation: None,
            mm_generation: mm.raw(),
            asid_generation: mm.raw(),
        }),
        mm,
        asid_generation: mm.raw(),
    };
    context
        .thread()
        .publish_initial_task_state(state)
        .expect("publish task state");
}

/// RAII guard that redirects a target host file descriptor (e.g. stderr fd 2)
/// to a replacement descriptor, restoring the original descriptor on drop.
struct StdioRedirectGuard {
    target_fd: i32,
    saved_fd: i32,
}

impl StdioRedirectGuard {
    fn redirect(target_fd: i32, to_fd: i32) -> Self {
        // SAFETY: dup saves the current host descriptor to an internal number.
        let saved_fd = unsafe { libc::dup(target_fd) };
        assert!(saved_fd >= 0, "failed to save target_fd {target_fd}");
        // SAFETY: dup2 atomically replaces target_fd with to_fd.
        let rc = unsafe { libc::dup2(to_fd, target_fd) };
        assert!(rc >= 0, "failed to dup2 {to_fd} onto {target_fd}");
        Self {
            target_fd,
            saved_fd,
        }
    }
}

impl Drop for StdioRedirectGuard {
    fn drop(&mut self) {
        // SAFETY: restore the original target_fd and close saved_fd.
        unsafe {
            libc::dup2(self.saved_fd, self.target_fd);
            libc::close(self.saved_fd);
        }
    }
}

#[test]
fn inherited_stdio_backpressure_and_pinning_in_host_wait() {
    // Create an OS pipe for testing inherited backpressure.
    let mut fds = [0i32; 2];
    // SAFETY: creating standard pipe for test endpoints.
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
    let pipe_read = fds[0];
    let pipe_write = fds[1];

    // Set write end to O_NONBLOCK so write_all_stdio encounters EAGAIN and enters poll.
    // SAFETY: querying flags.
    let flags = unsafe { libc::fcntl(pipe_write, libc::F_GETFL, 0) };
    assert!(flags >= 0);
    // SAFETY: setting O_NONBLOCK on pipe_write.
    assert_eq!(
        unsafe { libc::fcntl(pipe_write, libc::F_SETFL, flags | libc::O_NONBLOCK) },
        0
    );

    // Pre-fill the pipe buffer completely with filler bytes so the next write encounters EAGAIN.
    let filler_chunk = [0x5au8; 1024];
    let mut filler_total = 0usize;
    loop {
        // SAFETY: writing filler chunk to pipe_write until pipe buffer is completely full.
        let n = unsafe {
            libc::write(
                pipe_write,
                filler_chunk.as_ptr() as *const libc::c_void,
                filler_chunk.len(),
            )
        };
        if n > 0 {
            filler_total += n as usize;
        } else {
            let err = std::io::Error::last_os_error().raw_os_error().unwrap();
            assert!(
                err == libc::EAGAIN || err == libc::EWOULDBLOCK,
                "unexpected pipe write error: {err}"
            );
            break;
        }
    }
    assert!(filler_total > 0, "pipe must have non-zero capacity");

    // Redirect host stderr (fd 2) to pipe_write using our RAII guard.
    let _redirect_guard = StdioRedirectGuard::redirect(2, pipe_write);

    // Set up Carrick dispatcher with StdioSink::Inherit.
    let dispatcher = SyscallDispatcher::with_bridges(carrick_kernel::dispatch::CarrierBridges {
        host_signal: Arc::new(NullHostSignalBridge::default()),
        timers: Arc::new(carrick_hal::NullGuestTimerBridge::default()),
    });
    dispatcher.set_stdio_sink(StdioSink::Inherit);

    let root = dispatcher.capture_one_task_context().unwrap();
    let kernel = Arc::clone(root.kernel());
    let sibling = create_sibling_thread(&kernel, &root, 59_301);

    publish_task(&root, 2100);
    publish_task(&sibling, 2200);

    let dispatcher = Arc::new(dispatcher);
    // 1 guest CPU (CPU 0)
    let scheduler = Arc::new(Scheduler::new_with_policy(
        kernel,
        Arc::new(GuestCpuPolicy::new(1)),
    ));

    // Bound owner executor for Task A on CPU 0
    let owner = scheduler
        .register_executor_bound(
            Arc::new(TestKick::default()),
            Some(GuestCpuId::new(0)),
            false,
        )
        .unwrap();

    // Spare executor for Task B
    let spare = scheduler
        .register_executor_bound(Arc::new(TestKick::default()), None, true)
        .unwrap();

    // Make both tasks runnable
    scheduler.make_runnable(root.thread().key()).unwrap();
    let running_a = scheduler.take(&owner).unwrap();
    scheduler.make_runnable(sibling.thread().key()).unwrap();

    let (drained_tx, drained_rx) = mpsc::channel();
    let worker_scheduler = Arc::clone(&scheduler);
    let worker_dispatcher = Arc::clone(&dispatcher);
    let worker_spare = spare.clone();
    let sibling_context = sibling.retain_exact();

    // Payload Task A will write: 4096 bytes of 0x42
    let payload = vec![0x42u8; 4096];

    // Background thread: waits for Task A to enter host wait, verifies CPU 0 is freed,
    // runs Task B on spare executor (MM mutation), then drains pipe to wake Task A.
    let drain_thread = thread::spawn(move || -> Result<(), String> {
        let start = Instant::now();
        loop {
            if let Some(census) = worker_scheduler.host_wait_census()
                && census.entered >= 1
                && !census.slots.is_empty()
                && census.slots[0].waiters.len() == 1
            {
                break;
            }
            if start.elapsed() > Duration::from_secs(5) {
                return Err("timed out waiting for Task A to enter host wait".to_string());
            }
            thread::sleep(Duration::from_millis(1));
        }

        // Task A is in host wait! CPU 0 is free. Claim it on worker_spare.
        let replacement = worker_scheduler
            .take(&worker_spare)
            .map_err(|e| format!("take spare: {e:?}"))?;

        let tid_b = ThreadId::synthetic_for_tests(59_301);
        let registry_b = ThreadRegistry::new(tid_b);
        let futex_b = FutexTable::new();
        let mut memory_b = LinearMemory::new(0x10000, vec![0; 4096]);
        let mut mm_b = worker_dispatcher
            .enter_mm_executor()
            .map_err(|e| format!("enter MM: {e:?}"))?;

        // Perform brk MM mutation
        let outcome_b = worker_dispatcher
            .dispatch_threaded_with_mm_executor(
                &mut mm_b,
                &sibling_context,
                SyscallRequest::new(214, SyscallArgs::from([0; 6])),
                &mut memory_b,
                &CompatReporter::default(),
                ThreadCtx::new(tid_b, &registry_b, &futex_b),
            )
            .map_err(|e| format!("dispatch brk: {e:?}"))?;

        drop(mm_b);
        worker_scheduler
            .settle_exited(replacement)
            .map_err(|e| format!("settle replacement: {e:?}"))?;

        if !matches!(outcome_b, DispatchOutcome::Returned { .. }) {
            return Err(format!("unexpected brk outcome: {outcome_b:?}"));
        }

        // Drain the filler bytes that originally filled the pipe.
        let mut drain_buf = vec![0u8; filler_total];
        let mut drained = 0usize;
        while drained < filler_total {
            // SAFETY: reading from pipe_read to drain filler bytes.
            let n = unsafe {
                libc::read(
                    pipe_read,
                    drain_buf[drained..].as_mut_ptr() as *mut libc::c_void,
                    filler_total - drained,
                )
            };
            if n > 0 {
                drained += n as usize;
            } else if n == 0 {
                return Err("unexpected EOF draining filler".to_string());
            } else {
                let err = std::io::Error::last_os_error().raw_os_error().unwrap();
                if err != libc::EINTR {
                    return Err(format!("read error draining filler: {err}"));
                }
            }
        }
        assert_eq!(drained, filler_total);

        // Now read the 4096 payload bytes written by Task A.
        let mut read_payload = vec![0u8; 4096];
        let mut payload_read_count = 0usize;
        let drain_deadline = Instant::now() + Duration::from_secs(5);
        while payload_read_count < 4096 {
            // SAFETY: reading payload from pipe_read.
            let n = unsafe {
                libc::read(
                    pipe_read,
                    read_payload[payload_read_count..].as_mut_ptr() as *mut libc::c_void,
                    4096 - payload_read_count,
                )
            };
            if n > 0 {
                payload_read_count += n as usize;
            } else if n == 0 {
                return Err("unexpected EOF reading payload".to_string());
            } else {
                let err = std::io::Error::last_os_error().raw_os_error().unwrap();
                if err != libc::EINTR && err != libc::EAGAIN {
                    return Err(format!("read error reading payload: {err}"));
                }
            }
            if Instant::now() > drain_deadline {
                return Err("timed out reading payload bytes".to_string());
            }
        }

        assert_eq!(read_payload, vec![0x42u8; 4096]);
        let _ = drained_tx.send(());

        Ok(())
    });

    // Run Task A on bound owner executor
    let tid_a = ThreadId::synthetic_for_tests(59_300);
    let registry_a = ThreadRegistry::new(tid_a);
    let futex_a = FutexTable::new();
    let reporter_a = CompatReporter::default();
    let mut memory_a = LinearMemory::new(0x10000, payload.clone());
    let mut participation_a = dispatcher.enter_mm_executor().unwrap();

    // Syscall 64: write(2, 0x10000, 4096)
    let PreparedDispatch::Invoke(prepared_a) = dispatcher
        .prepare_syscall(
            &root,
            SyscallRequest::new(64, SyscallArgs::from([2, 0x10000, 4096, 0, 0, 0])),
            &reporter_a,
        )
        .unwrap()
    else {
        panic!("write must dispatch for Task A");
    };

    let outcome_a = dispatcher.dispatch_threaded_prepared_with_mm_executor_and_lease(
        &root,
        prepared_a,
        &mut memory_a,
        &reporter_a,
        ThreadCtx::new(tid_a, &registry_a, &futex_a),
        OrdinaryDispatchRoute {
            host_wait: Some(HostWaitContext {
                scheduler: &scheduler,
                registration: &owner,
            }),
            lease: Some(running_a.lease()),
            mm_executor: Some(&mut participation_a),
        },
    );
    drop(participation_a);
    scheduler.settle_exited(running_a).unwrap();

    // Wait for drain thread to finish
    let drain_res = drain_thread.join().expect("join drain thread");
    drain_res.expect("drain thread succeeded");
    let _ = drained_rx.recv_timeout(Duration::from_secs(1));

    // Verify Task A succeeded and returned full count 4096
    assert_eq!(
        outcome_a.unwrap(),
        DispatchOutcome::Returned { value: 4096 }
    );

    // Verify Capture-Bypass: dispatcher captured stdout/stderr buffers must remain empty!
    assert!(
        dispatcher.stdout().is_empty(),
        "captured stdout must remain empty under StdioRoute::Inherit"
    );
    assert!(
        dispatcher.stderr().is_empty(),
        "captured stderr must remain empty under StdioRoute::Inherit"
    );

    // Verify Host-Wait Census: entered=1, resumed=1, no waiters remaining
    let final_census = scheduler.host_wait_census().expect("final census");
    assert_eq!((final_census.entered, final_census.resumed), (1, 1));
    assert!(
        final_census.slots.is_empty() || final_census.slots[0].waiters.is_empty(),
        "all waiters must have resumed"
    );

    // Verify Pinning Survival: the underlying pipe_write host descriptor is STILL OPEN and valid,
    // proving HostFdRef's drop only closed its internal duplicated descriptor, not the host fd!
    // SAFETY: checking F_GETFD on pipe_write.
    let fcntl_res = unsafe { libc::fcntl(pipe_write, libc::F_GETFD) };
    assert!(
        fcntl_res >= 0,
        "underlying host pipe_write descriptor must remain valid and open after HostFdRef drop"
    );

    // Cleanup scheduler
    scheduler.close();
    scheduler.unregister_executor(&spare).unwrap();
    scheduler.unregister_executor(&owner).unwrap();

    // Close test pipe ends
    // SAFETY: closing test pipes.
    unsafe {
        libc::close(pipe_read);
        libc::close(pipe_write);
    }
}
