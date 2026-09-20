//! Signed observation and strict budget checks are separate: successful capture
//! never means that the structural contract passed. Run through test-signed.sh.
#![allow(clippy::unwrap_used, clippy::expect_used)]
use carrick_conformance_contract::{ContractObservation, ContractRegistry, WorkMetric, evaluate};
use carrick_embed::contracts::write_seek_structural_contract;

fn observations() -> Vec<ContractObservation> {
    [1, 8, 32, 128]
        .into_iter()
        .map(|scale| {
            let observation =
                write_seek_structural_contract(scale).expect("signed write/seek observation");
            observation.validate().expect("complete measurement");
            assert!(
                observation.semantic_assertions.iter().all(|a| a.passed),
                "{:?}",
                observation.semantic_assertions
            );
            eprintln!(
                "write-seek scale={scale} position_queries={:?}",
                observation.work_value(WorkMetric::HostWritePositionQueries)
            );
            observation
        })
        .collect()
}

#[test]
fn write_seek_contract_observations() {
    let observations = observations();
    let output =
        std::env::var("CARRICK_WRITE_SEEK_OBSERVATIONS").expect("explicit observation output path");
    std::fs::write(output, serde_json::to_vec_pretty(&observations).unwrap()).unwrap();
}

#[test]
fn write_seek_contract_budget() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .unwrap();
    let registry = ContractRegistry::load(root).unwrap();
    evaluate(
        registry.require("kernel.fs.write-seek").unwrap(),
        &observations(),
    )
    .expect("write/seek structural budget");
}
