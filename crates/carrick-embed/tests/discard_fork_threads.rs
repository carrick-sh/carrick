//! `kernel.mm.anonymous-discard-fork-reuse`, signed embed layer.
//!
//! Two live guest processes: the fixture forks while four threads run on
//! glibc-shaped 8 MiB stacks, then the child and every parent thread discard
//! the same unaligned thread-stack range (`MADV_DONTNEED` from one page above
//! the guard), over three rounds that reuse the stacks. This is the reduction
//! of the cpython-fork1 / cpython-wait4 carrier abort
//! "anonymous discard publication uncertain .. COW compound IPA .. has no
//! exact inventory coverage".
//!
//! Run ONLY through `scripts/test-signed.sh carrick-embed discard_fork_threads`
//! after `scripts/build-linux-fixtures.sh`: the test executable must carry the
//! hypervisor entitlement, and `HV_DENIED` is a failure, never a skip.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use carrick_conformance_contract::{
    Completeness, ContractId, ContractObservation, ContractRegistry, ExecutionLayer,
    SemanticAssertion, WorkSnapshot, evaluate,
};
use carrick_embed::{Carrier, EmbedError, PullPolicy};
use sha2::{Digest, Sha256};

const FIXTURE: &str = "carrick-linux-aarch64-discard-fork-threads";

fn carrier_or_fail() -> Carrier {
    for _ in 0..50 {
        match Carrier::new() {
            Ok(carrier) => return carrier,
            Err(EmbedError::Entitlement) => panic!(
                "HV_DENIED (0xfae94007): this test executable lacks \
                 com.apple.security.hypervisor. Run it through \
                 scripts/test-signed.sh; a bare cargo test can never boot a guest."
            ),
            Err(EmbedError::CarrierAlreadyActive) => {
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            Err(error) => panic!("carrier initialization failed: {error}"),
        }
    }
    panic!("carrier initialization timed out waiting for a prior carrier to retire");
}

#[test]
fn discard_fork_threads_contract() {
    let _guest = common::guest_lock();
    let fixture = common::repo_root().join(format!(
        "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/{FIXTURE}"
    ));
    let bytes = std::fs::read(&fixture).unwrap_or_else(|error| {
        panic!(
            "read {}: {error}; run scripts/build-linux-fixtures.sh first",
            fixture.display()
        )
    });
    let fixture_dir = fixture.parent().expect("fixture directory");

    let carrier = carrier_or_fail();
    let result = common::run_or_fail(
        carrier
            .container(common::SMOKE_IMAGE)
            .pull_policy(PullPolicy::Missing)
            .command([format!("/p/{FIXTURE}")])
            .mount_readonly(fixture_dir.to_string_lossy(), "/p")
            .run_blocking(),
    );
    let stdout = result.stdout_utf8();
    let observation = ContractObservation {
        contract_id: ContractId::new("kernel.mm.anonymous-discard-fork-reuse")
            .expect("contract id"),
        layer: ExecutionLayer::EmbedStructural,
        implementation_revision: format!("sha256:{:x}", Sha256::digest(&bytes)),
        fixture_identity: "fixture:discard-fork-threads".into(),
        scale: 1,
        semantic_assertions: vec![
            SemanticAssertion {
                name: "both_processes_see_linux_discard_semantics".into(),
                passed: result.exit_code == 0 && result.signal.is_none(),
                detail: Some(format!(
                    "fixture exit {} signal {:?} (1xx = child check failed; \
                     see discard_fork_threads.rs for the codes)",
                    result.exit_code, result.signal
                )),
            },
            SemanticAssertion {
                name: "fixture_reports_completion".into(),
                passed: stdout.contains("discard fork threads ok"),
                detail: Some(format!("guest stdout: {stdout:?}")),
            },
        ],
        work: Some(WorkSnapshot::new()),
        timing: None,
        completeness: Completeness::Complete,
    };
    let registry = ContractRegistry::load(&common::repo_root()).expect("contract registry");
    evaluate(
        registry
            .require("kernel.mm.anonymous-discard-fork-reuse")
            .expect("contract"),
        &[observation],
    )
    .expect("kernel.mm.anonymous-discard-fork-reuse embed contract");
}
