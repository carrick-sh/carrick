//! Every vCPU lives for its VM's whole life (EL1 plan 1a, decision D2).
//!
//! Hypervisor.framework's in-kernel GIC treats a VM's topology as final once
//! its vCPUs run (`hv_gic.h`: "Destroy vcpus only when you are tearing down
//! the virtual machine"). A carrier keeps one VM across containers, so a second
//! container's root boots while the first one's executor vCPUs are live. This
//! test boots two roots in one carrier and asserts that no vCPU is created or
//! destroyed between them, and that carrier teardown destroys exactly the
//! vCPUs the carrier created. Contract `kernel.vcpu.vm-lifetime`.
//!
//! Run ONLY through `just test-embed` (scripts/test-signed.sh): it signs the
//! test executable with the hypervisor entitlement, exports `CARRICK_RUN_ID`,
//! and runs it under `RUST_TEST_THREADS=1`. Bare `cargo test` fails here with
//! `EmbedError::Entitlement` (HV_DENIED), by design, never a skip.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use carrick_embed::{Carrier, ContainerResult, EmbedError, ImageStore, PullPolicy};
use carrick_runtime::VcpuLifecycleSnapshot;

fn lifecycle() -> VcpuLifecycleSnapshot {
    carrick_runtime::vcpu_lifecycle_snapshot().expect("HVF carrier reports vCPU lifecycle totals")
}

fn assert_ran(label: &str, outcome: Result<ContainerResult, EmbedError>) {
    assert!(
        !matches!(outcome, Err(EmbedError::Entitlement)),
        "HV_DENIED (0xfae94007): this test executable lacks \
         com.apple.security.hypervisor. Run it through `just test-embed`."
    );
    let result = outcome.unwrap_or_else(|error| panic!("{label} container failed: {error:?}"));
    assert!(
        result.success(),
        "{label} exit={} signal={:?} stderr={}",
        result.exit_code,
        result.signal,
        result.stderr_utf8()
    );
    assert_eq!(result.stdout_utf8(), format!("{label}\n"), "{label} output");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::await_holding_lock)]
async fn el1_vcpus_live_for_the_vm_lifetime_across_a_second_root() {
    let _guard = common::guest_lock();
    let carrier = match Carrier::new() {
        Ok(carrier) => carrier,
        Err(EmbedError::Entitlement) => panic!(
            "HV_DENIED (0xfae94007): run this test through `just test-embed`, which signs it"
        ),
        Err(error) => panic!("carrier create failed: {error:?}"),
    };
    let store = ImageStore::default_for_user();
    let run = |label: &'static str| {
        carrier
            .container(common::SMOKE_IMAGE)
            .image_store(store.clone())
            .pull_policy(PullPolicy::Missing)
            .command(["/bin/echo", label])
            .run()
    };

    let before = lifecycle();
    assert_ran("first-root", run("first-root").await);
    let after_first = lifecycle();
    assert_ran("second-root", run("second-root").await);
    let after_second = lifecycle();

    assert_eq!(
        after_second.destroyed - before.destroyed,
        0,
        "a vCPU was destroyed before carrier teardown: before={before:?} \
         after_first={after_first:?} after_second={after_second:?}"
    );
    assert_eq!(
        after_second.created, after_first.created,
        "the second root created a vCPU in the live VM: after_first={after_first:?} \
         after_second={after_second:?}"
    );
    assert!(
        after_first.created > before.created,
        "the first root started no executor vCPUs: before={before:?} after_first={after_first:?}"
    );

    carrier.shutdown().await.expect("carrier shutdown");
    let closed = lifecycle();
    assert_eq!(
        closed.destroyed - before.destroyed,
        closed.created - before.created,
        "carrier teardown must destroy exactly the vCPUs the carrier created: \
         before={before:?} closed={closed:?}"
    );
}
