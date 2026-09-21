// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Signed structural gate for the private-rootfs inotify09 reduction.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use carrick_conformance_contract::{ContractObservation, ContractRegistry, WorkMetric, evaluate};
use carrick_embed::inotify_hotpath_structural_contract;

fn observations() -> Vec<ContractObservation> {
    [1, 8, 32, 128]
        .into_iter()
        .map(|scale| {
            let observation = inotify_hotpath_structural_contract(scale)
                .expect("signed inotify hotpath observation");
            observation.validate().expect("complete measurement");
            assert!(
                observation
                    .semantic_assertions
                    .iter()
                    .all(|item| item.passed),
                "{:?}",
                observation.semantic_assertions
            );
            eprintln!(
                "inotify-hotpath scale={scale} host_backend_calls={:?}",
                observation.work_value(WorkMetric::HostBackendCalls)
            );
            observation
        })
        .collect()
}

#[test]
fn inotify_hotpath_contract_observations() {
    let observations = observations();
    let output = std::env::var("CARRICK_INOTIFY_HOTPATH_OBSERVATIONS")
        .expect("explicit observation output path");
    std::fs::write(output, serde_json::to_vec_pretty(&observations).unwrap()).unwrap();
}

#[test]
fn inotify_hotpath_contract_budget() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .unwrap();
    let registry = ContractRegistry::load(root).unwrap();
    evaluate(
        registry
            .require("kernel.inotify.mark-race-hotpath")
            .unwrap(),
        &observations(),
    )
    .expect("inotify hotpath structural budget");
}
