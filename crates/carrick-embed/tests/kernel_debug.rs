//! Live socket regression for successive embed carriers in one host process.
//! Run through `RUST_TEST_THREADS=1 just test-embed embed_kernel_debug`.
#![allow(clippy::expect_used, clippy::panic)]

mod common;

use std::sync::{Arc, mpsc};
use std::time::Duration;

use carrick_embed::{
    ContainerBuilder, InterceptAction, InterceptedSyscall, ProcessInfo, PullPolicy,
    SyscallInterceptor,
};
use carrick_kernel::kernel::kernel_debug_fetch;

struct SleepReady(mpsc::Sender<()>);

impl SyscallInterceptor for SleepReady {
    fn intercept(&self, _: &ProcessInfo<'_>, call: &InterceptedSyscall<'_>) -> InterceptAction {
        if matches!(call.name(), "clock_nanosleep" | "nanosleep") {
            self.0.send(()).expect("sleep rendezvous");
        }
        InterceptAction::Continue
    }
}

#[test]
fn embed_kernel_debug_follows_live_carrier_generation() {
    let _guest = common::guest_lock();
    let watchdog = common::Watchdog::start(Duration::from_secs(90));
    let runtime = tokio::runtime::Runtime::new().expect("tokio runtime");

    // A first completed run must not leave a socket serving its retired graph.
    let first = common::run_or_fail(
        runtime.block_on(
            ContainerBuilder::from_image(common::SMOKE_IMAGE)
                .pull_policy(PullPolicy::Never)
                .command(["/bin/true"])
                .run(),
        ),
    );
    assert_eq!(first.exit_code, 0);

    let (sender, receiver) = mpsc::channel();
    let guest = std::thread::spawn(move || {
        common::run_or_fail(
            runtime.block_on(
                ContainerBuilder::from_image(common::SMOKE_IMAGE)
                    .pull_policy(PullPolicy::Never)
                    .command(["/bin/sleep", "5"])
                    .interceptor(Arc::new(SleepReady(sender)))
                    .run(),
            ),
        )
    });
    receiver
        .recv_timeout(Duration::from_secs(30))
        .expect("second guest reached sleep");
    // Use the same authenticated client and CARRICK_RUN_ID as the CLI debugger.
    let snapshot = kernel_debug_fetch(&common::run_id(), None);
    let result = guest.join().expect("guest thread");
    assert_eq!(result.exit_code, 0);
    let snapshot = snapshot.expect("live kernel socket snapshot");
    assert_eq!(snapshot.provider_absent, Some(false), "{snapshot:#?}");
    let tasks = snapshot.tasks.expect("task table");
    let executors = snapshot.executors.expect("executor table");
    let scheduler = snapshot.scheduler.expect("scheduler table");
    assert!(!tasks.is_empty());
    assert!(!executors.is_empty());
    assert!(!scheduler.is_empty());
    println!(
        "live embed kernel: provider_absent=false tasks={} executors={} scheduler={}",
        tasks.len(),
        executors.len(),
        scheduler.len()
    );
    assert!(matches!(
        kernel_debug_fetch(&common::run_id(), None),
        Err(carrick_kernel::kernel::debug::ClientError::NotListening { .. })
    ));
    watchdog.disarm();
}
