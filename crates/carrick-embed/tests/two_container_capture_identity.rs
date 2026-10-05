//! Signed proof that two live containers retain their common carrier scope in
//! the one persisted abort. Its own process: aborted guest workers are reaped
//! by scripts/test-signed.sh under the exact run id.
#![cfg(feature = "test-support")]

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use carrick_embed::{Carrier, EmbedError, InterceptAction, InterceptedSyscall, ProcessInfo};
use carrick_image::PullPolicy;

struct Ready {
    sent: AtomicBool,
    sender: std::sync::mpsc::Sender<()>,
}
impl carrick_embed::SyscallInterceptor for Ready {
    fn intercept(&self, _: &ProcessInfo<'_>, _: &InterceptedSyscall<'_>) -> InterceptAction {
        if !self.sent.swap(true, Ordering::AcqRel) {
            assert!(self.sender.send(()).is_ok(), "live container rendezvous");
        }
        InterceptAction::Continue
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::await_holding_lock)]
async fn two_live_containers_abort_with_the_common_carrier_scope() {
    let _guest = common::guest_lock();
    let capture_dir = tempfile::tempdir().expect("capture directory");
    let carrier = Carrier::new().expect("carrier");
    let (sender, receiver) = std::sync::mpsc::channel();
    let builder = || {
        carrier
            .container(common::SMOKE_IMAGE)
            .pull_policy(PullPolicy::Missing)
            .command(["/bin/sleep", "3600"])
            .post_mortem_dir(capture_dir.path())
            .interceptor(Arc::new(Ready {
                sent: AtomicBool::new(false),
                sender: sender.clone(),
            }))
    };
    let first = tokio::spawn(builder().run());
    let second = tokio::spawn(builder().run());
    for _ in 0..2 {
        receiver
            .recv_timeout(Duration::from_secs(30))
            .expect("both live guests reached a syscall");
    }
    let snapshot = carrick_embed::testing::carrier_snapshot(&carrier).expect("live snapshot");
    assert_eq!(snapshot.live_containers, 2);
    assert_eq!(snapshot.kernel_graphs, 1);
    let scope = carrick_runtime::carrier::active_carrier_scope().expect("current carrier scope");
    carrick_kernel::kernel::debug::request_abort(
        carrick_kernel::kernel::debug::AbortReason::ContainerDeadline {
            elapsed_ms: 0,
            budget_ms: 0,
        },
    );
    let (first, second) = tokio::time::timeout(Duration::from_secs(30), async {
        tokio::join!(first, second)
    })
    .await
    .expect("both abort waiters complete");
    for outcome in [first, second] {
        let Err(EmbedError::KernelAborted { post_mortem, .. }) = outcome.expect("run task") else {
            panic!("both containers must receive the carrier abort");
        };
        assert_eq!(post_mortem.run_id.as_deref(), Some(scope.as_str()));
        assert!(post_mortem.kernel.is_some());
    }
    let persisted: serde_json::Value = serde_json::from_slice(
        &std::fs::read(capture_dir.path().join("post-mortem.json")).expect("persisted capture"),
    )
    .expect("capture JSON");
    assert_eq!(persisted["run_id"], scope.as_str());
    assert_eq!(scope.as_str(), common::run_id());
}
