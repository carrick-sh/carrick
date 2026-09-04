//! Focused ecosystem failures executed through the public embedding path.
//! Run with scripts/test-signed.sh carrick-conformance-next ecosystem_cpython_forkserver --nocapture.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use carrick_conformance_next::{PullPolicy, ResultAssert, TestContainer};

#[test]
fn ecosystem_cpython_forkserver_result_pickle() {
    let _guard = common::guest_lock();
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_ansi(false)
        .with_writer(std::io::stderr)
        .try_init();
    let mut container = TestContainer::new("localhost:5050/cpython-test:3.12.13")
        .pull_policy(PullPolicy::Never)
        .env("PYTHONFAULTHANDLER", "1");
    if let Some(path) = std::env::var_os("CARRICK_REDUCER_ARTIFACT_DIR") {
        std::fs::create_dir_all(&path).expect("create reducer artifact directory");
        container = container
            .mount(path.to_string_lossy(), "/evidence")
            .workdir("/evidence");
    }
    let result = common::run_or_fail(container.run([
        "/usr/local/bin/python3",
        "-m",
        "unittest",
        "-v",
        "test.test_concurrent_futures.test_deadlock.ProcessPoolForkserverExecutorDeadlockTest.test_error_during_result_pickle_on_worker",
    ]));
    result.assert_success();
    assert!(
        result.stderr_utf8().contains("Ran 1 test"),
        "{}",
        result.stderr_utf8()
    );
    assert!(
        result.stderr_utf8().contains("\nOK\n"),
        "{}",
        result.stderr_utf8()
    );
}
