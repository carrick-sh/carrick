//! Race reproducers for the carrier scheduler, run in-process through the
//! embed API with `SyscallJitter` stretching the boundaries a race needs.
//! Signed lane only (`just test-embed scheduler_race`).
//!
//! `go_types_survives_exec_exit_jitter`: the load-coupled carrier abort
//! `scheduler generation observer lost exact transition … AuthorityMismatch`
//! reproduced 4 of 6 times under cargo-build host load on 2026-09-07 with
//! `go_types.test` (fork+exec storms of `go build`). This test replaces the
//! host load with deterministic jitter on the syscalls that move execution
//! generations. It is RED when the carrier aborts (the process dies, so the
//! harness reports the test as failed) and green when the run completes,
//! whatever the guest's own verdict.
mod common;

use std::sync::Arc;

use carrick_embed::testing::SyscallJitter;
use carrick_embed::{ContainerBuilder, ImageStore, PullPolicy, SyscallInterceptor};

const GO_IMAGE: &str = "localhost:5005/carrick-go-conformance:1.24";

#[test]
fn go_types_survives_exec_exit_jitter() {
    let _guest = common::guest_lock();
    let jitter = Arc::new(SyscallJitter::new(
        [
            "execve",
            "exit_group",
            "exit",
            "wait4",
            "waitid",
            "futex",
            "clone",
            "clone3",
        ],
        2_000,
    ));
    let result = ContainerBuilder::from_image(GO_IMAGE)
        .image_store(ImageStore::default_for_user())
        .pull_policy(PullPolicy::Missing)
        .workdir("/usr/local/go/src/go/types")
        .command([
            "/conformance/go_types.test",
            "-test.run",
            "TestCheck|TestMapping|TestIssue",
            "-test.short",
        ])
        .interceptor(Arc::clone(&jitter) as Arc<dyn SyscallInterceptor>)
        .run_blocking()
        .expect("container ran to completion without a carrier abort");
    assert!(
        jitter.matched() > 100,
        "jitter never engaged: {} matching syscalls",
        jitter.matched()
    );
    assert!(
        result.signal.is_none(),
        "guest killed by signal {:?}",
        result.signal
    );
}
