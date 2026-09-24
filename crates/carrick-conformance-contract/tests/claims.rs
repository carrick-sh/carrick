use carrick_conformance_contract::{
    CapabilityClass, Claim, ClaimId, ContractId, CoverageState, ExecutionLayer, ModelError,
};

#[test]
fn claim_id_accepts_valid_format() {
    let valid_ids = [
        "kernel.futex.contention.wake-cardinality",
        "kernel.fork.stage1-image.image-pool-bound",
        "syscall.inotify-add-watch.descriptor-limit",
    ];

    for id_str in valid_ids {
        let claim_id = ClaimId::new(id_str);
        assert!(claim_id.is_ok(), "expected {id_str} to be valid");
        assert_eq!(claim_id.unwrap().as_str(), id_str);
    }
}

#[test]
fn claim_id_rejects_invalid_format() {
    let invalid_ids = [
        "",
        "UPPERCASE.claim",
        "kernel..double-dot",
        "kernel.claim_with_underscore",
        "trailing-dot.",
        ".leading-dot",
    ];

    for id_str in invalid_ids {
        assert!(
            matches!(ClaimId::new(id_str), Err(ModelError::InvalidClaimId(_))),
            "expected {id_str} to be rejected"
        );
    }
}

#[test]
fn claim_serialization_round_trip() {
    let claim = Claim {
        id: ClaimId::new("kernel.futex.contention.wake-cardinality").unwrap(),
        contract: ContractId::new("kernel.futex.contention").unwrap(),
        description: "Wake cardinality must match woken waiters exactly".to_string(),
        linux_authority: vec!["man 2 futex".to_string()],
        fixture_requirements: vec!["probe:futexpingpong".to_string()],
        related_contracts: vec![ContractId::new("kernel.futex.requeue").unwrap()],
        related_ecosystem_rows: vec!["go:sync".to_string()],
        capability: CapabilityClass::VmFreeExisting {
            capability: "carrick-kernel-example::futex_wake".to_string(),
        },
        coverage: CoverageState::ViolationDemonstrated {
            layer: ExecutionLayer::VmFree,
            known_bad_revision: "bad_rev_12345".to_string(),
        },
    };

    let serialized = toml::to_string(&claim).expect("failed to serialize claim");
    let deserialized: Claim = toml::from_str(&serialized).expect("failed to deserialize claim");
    assert_eq!(claim, deserialized);
}

#[test]
fn violation_demonstrated_requires_known_bad_revision() {
    let invalid_toml = r#"
id = "kernel.futex.contention.wake-cardinality"
contract = "kernel.futex.contention"
description = "Wake cardinality"
linux_authority = ["man 2 futex"]
capability = { class = "vm-free-existing", capability = "futex" }
coverage = { status = "violation-demonstrated", layer = "vm-free", known_bad_revision = "   " }
"#;

    let res: Result<Claim, _> = toml::from_str(invalid_toml);
    assert!(
        res.is_err(),
        "expected blank known_bad_revision to be rejected"
    );
}

#[test]
fn registry_loads_claims_successfully() {
    let temp = tempfile::tempdir().unwrap();
    let conf_contracts = temp.path().join("conformance-contracts");
    let contracts_dir = conf_contracts.join("contracts");
    let claims_dir = conf_contracts.join("claims");
    std::fs::create_dir_all(&contracts_dir).unwrap();
    std::fs::create_dir_all(&claims_dir).unwrap();

    let contract_toml = r#"
schema_version = 1
id = "test.contract"
title = "Test Contract"
guest_surfaces = ["syscall:test"]
semantic_authority = ["test authority"]
fixture = "test_fixture"
scale_points = [1]
rationale = "test rationale"
structural_budgets = []

[bindings]
vm_free = "crate::binding"
embed = "crate::embed"
docker = "image:tag"
"#;
    std::fs::write(contracts_dir.join("test.toml"), contract_toml).unwrap();

    let surfaces_toml = r#"
schema_version = 1
[[surfaces]]
path = "some/path.rs"
contracts = ["test.contract"]
"#;
    std::fs::write(conf_contracts.join("surfaces.toml"), surfaces_toml).unwrap();

    let claims_toml = r#"
[[claims]]
id = "test.contract.claim-one"
contract = "test.contract"
description = "First test claim"
linux_authority = ["test auth"]
capability = { class = "vm-free-existing", capability = "test_cap" }
coverage = { status = "declared" }
"#;
    std::fs::write(claims_dir.join("test_claims.toml"), claims_toml).unwrap();

    let registry = carrick_conformance_contract::ContractRegistry::load(temp.path()).unwrap();
    assert_eq!(registry.contracts().len(), 1);
    assert_eq!(registry.claims().len(), 1);

    let claim = registry
        .get_claim(&ClaimId::new("test.contract.claim-one").unwrap())
        .expect("claim should exist");
    assert_eq!(claim.description, "First test claim");
}

#[test]
fn live_registry_loads_all_claims() {
    let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let registry = carrick_conformance_contract::ContractRegistry::load(repo_root)
        .expect("live registry should load");
    assert_eq!(registry.contracts().len(), 44);
    for id in [
        "kernel.execution.native-synchronous-syscall",
        "kernel.execution.native-data-demand",
        "kernel.mm.native-execution-scope",
        "kernel.mm.native-data-activation",
        "kernel.mm.native-syscall-buffers",
        "kernel.mm.current-read-reuse",
    ] {
        registry
            .require(id)
            .expect("native contract must be registered");
    }
    assert_eq!(registry.claims().len(), 15);
}
