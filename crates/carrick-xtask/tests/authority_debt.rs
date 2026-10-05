#![allow(clippy::unwrap_used, clippy::expect_used)]
use carrick_xtask::authority_debt::{AuthorityDebtCeilings, Counter, Family, Lane};

fn ceilings(count: u64) -> AuthorityDebtCeilings {
    AuthorityDebtCeilings {
        schema: 1,
        counters: vec![Counter {
            family: Family::K1EpollWait,
            operation: "read_open_files".into(),
            owner: "carrick_kernel::poll".into(),
            lane: Lane::Shared,
            ceiling: count,
        }],
    }
}

#[test]
fn same_patch_increase_cannot_bless_added_debt() {
    assert!(
        ceilings(4)
            .ratchet(&ceilings(3))
            .unwrap_err()
            .to_string()
            .contains("increase")
    );
}
#[test]
fn removed_nonzero_counter_and_new_cohort_fail() {
    let empty = AuthorityDebtCeilings {
        schema: 1,
        counters: vec![],
    };
    assert!(empty.ratchet(&ceilings(1)).is_err());
    assert!(ceilings(1).ratchet(&empty).is_err());
    assert!(empty.ratchet(&ceilings(0)).is_ok());
}
#[test]
fn unknown_families_positions_and_fingerprints_cannot_be_deserialized() {
    let value = serde_json::to_value(ceilings(1)).unwrap();
    for (field, new_value) in [
        ("family", serde_json::json!("new_family")),
        ("line", serde_json::json!(1)),
        ("column", serde_json::json!(1)),
        ("byte_start", serde_json::json!(1)),
        ("fingerprint", serde_json::json!("ambient")),
    ] {
        let mut bad = value.clone();
        bad["counters"][0][field] = new_value;
        assert!(
            serde_json::from_value::<AuthorityDebtCeilings>(bad).is_err(),
            "{field}"
        );
    }
}
#[test]
fn family_reassignment_duplicate_and_zero_global_debt_fail() {
    let mut head = ceilings(1);
    head.counters[0].family = Family::K1InspectMisc;
    assert!(head.ratchet(&ceilings(1)).is_err());
    let mut duplicate = ceilings(1);
    duplicate.counters.push(duplicate.counters[0].clone());
    assert!(duplicate.validate().is_err());
    let mut global = ceilings(1);
    global.counters[0].family = Family::GlobalContainerDebt;
    assert!(global.validate().is_err());
}

fn source_fixture() -> tempfile::TempDir {
    use std::fs;
    let root = tempfile::tempdir().unwrap();
    let src = root.path().join("crates/carrick-kernel/src");
    fs::create_dir_all(src.join("dispatch/sysv")).unwrap();
    fs::write(
        src.join("dispatch/sysv.rs"),
        r#"
impl IpcView {
    pub(in crate::dispatch::sysv) fn with_state() {}
    pub(in crate::dispatch::sysv) fn with_state_mut() {}
    pub(in crate::dispatch::sysv) fn lock_sysv_process() {}
    pub(in crate::dispatch::sysv) fn with_sysv_process() {}
    pub(in crate::dispatch::sysv) fn with_sysv_process_mut() {}
}"#,
    )
    .unwrap();
    fs::write(
        src.join("dispatch/sysv/lock_authority.rs"),
        "impl SysvNamespacePermit { fn lock_paired() {} }",
    )
    .unwrap();
    fs::write(
        src.join("lib.rs"),
        "pub fn poll(table: &Table) { table.read_open_files(); }",
    )
    .unwrap();
    root
}
fn tools_root() -> &'static std::path::Path {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
}
#[test]
fn relocation_is_read_only_and_real_api_additions_fail() {
    use carrick_xtask::authority_debt::verify_source;
    use std::fs;
    let root = source_fixture();
    let source = root.path().join("crates/carrick-kernel/src/lib.rs");
    let policy = ceilings(1);
    verify_source(root.path(), tools_root(), &policy).unwrap();
    let moved = root.path().join("crates/carrick-kernel/src/relocated.rs");
    fs::write(
        &moved,
        format!("\n\n{}", fs::read_to_string(&source).unwrap()),
    )
    .unwrap();
    fs::remove_file(source).unwrap();
    let before = fs::read(&moved).unwrap();
    verify_source(root.path(), tools_root(), &policy).unwrap();
    assert_eq!(before, fs::read(&moved).unwrap());
    fs::write(
        &moved,
        "pub fn poll(table: &Table) { table.read_open_files(); table.read_open_files(); }",
    )
    .unwrap();
    assert!(
        verify_source(root.path(), tools_root(), &policy)
            .unwrap_err()
            .to_string()
            .contains("exceeds ceiling")
    );
    fs::write(
        &moved,
        "pub fn renamed(table: &Table) { table.read_open_files(); }",
    )
    .unwrap();
    assert!(
        verify_source(root.path(), tools_root(), &policy)
            .unwrap_err()
            .to_string()
            .contains("unknown authority")
    );
}
#[test]
fn comments_test_scopes_and_definitions_are_not_legacy_debt() {
    use carrick_xtask::authority_debt::verify_source;
    let root = source_fixture();
    std::fs::write(
        root.path().join("crates/carrick-kernel/src/lib.rs"),
        r#"
// table.read_open_files();
#[cfg(test)] mod tests { fn test(table: &Table) { table.read_open_files(); } }
pub fn poll(table: &Table) { table.read_open_files(); }
"#,
    )
    .unwrap();
    verify_source(root.path(), tools_root(), &ceilings(1)).unwrap();
}
#[test]
fn added_raw_lock_and_missing_owner_are_rejected() {
    use carrick_xtask::authority_debt::verify_source;
    let root = source_fixture();
    let path = root
        .path()
        .join("crates/carrick-kernel/src/dispatch/proc.rs");
    std::fs::write(
        &path,
        "pub fn poll(this: &Dispatcher) { this.proc.lock(); }",
    )
    .unwrap();
    assert!(
        verify_source(root.path(), tools_root(), &ceilings(1))
            .unwrap_err()
            .to_string()
            .contains("unknown authority")
    );
    std::fs::remove_file(path).unwrap();
    std::fs::remove_file(
        root.path()
            .join("crates/carrick-kernel/src/dispatch/sysv.rs"),
    )
    .unwrap();
    assert!(
        verify_source(root.path(), tools_root(), &ceilings(1))
            .unwrap_err()
            .to_string()
            .contains("missing SysV rule owner")
    );
}

#[test]
#[cfg(target_os = "linux")]
fn live_linux_breaker_alias_macro_and_cfg_cannot_use_stored_evidence() {
    use carrick_xtask::authority_debt::verify_host;
    use carrick_xtask::authority_source::SourceCensus;
    let root = tempfile::tempdir().unwrap();
    let output = std::process::Command::new("python3")
        .arg(tools_root().join("scripts/migrate/tests/check_host_authority_linux_breaker.py"))
        .arg("--fixture-root")
        .arg(root.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let source = SourceCensus::load(root.path()).unwrap();
    let empty = AuthorityDebtCeilings {
        schema: 1,
        counters: vec![],
    };
    let mut owners = std::collections::BTreeSet::new();
    for row in result["rows"].as_array().unwrap() {
        let one = serde_json::json!({"rows": [row]});
        let error = verify_host(&one, &empty, &source).unwrap_err().to_string();
        assert!(
            error.contains("unknown authority API/owner cohort"),
            "{error}"
        );
        assert!(error.contains("std::process::id"), "{error}");
        owners.insert(error);
    }
    assert_eq!(
        owners.len(),
        4,
        "all four owners must be independently denied"
    );
}
#[test]
fn unrecognized_guard_accessor_definition_fails_closed() {
    let root = source_fixture();
    std::fs::write(
        root.path().join("crates/carrick-kernel/src/new.rs"),
        "impl FileTable { fn unclassified_escape(&self) -> FileTableWriteGuard { todo!() } }",
    )
    .unwrap();
    assert!(carrick_xtask::authority_source::SourceCensus::load(root.path()).is_err());
}

#[test]
fn nested_and_path_test_modules_and_test_expressions_are_not_debt() {
    let root = source_fixture();
    let src = root.path().join("crates/carrick-kernel/src");
    std::fs::write(
        src.join("lib.rs"),
        r#"
mod production {
    #[cfg(test)] #[path = "fixtures.rs"] mod fixtures;
}
#[test] fn ignored(table: &Table) { table.read_open_files(); }
pub fn poll(table: &Table) {
    table.read_open_files();
    #[cfg(test)] { table.read_open_files(); }
}
"#,
    )
    .unwrap();
    std::fs::create_dir_all(src.join("production")).unwrap();
    std::fs::write(
        src.join("production/fixtures.rs"),
        "fn ignored(table: &Table) { table.read_open_files(); }",
    )
    .unwrap();
    let census = carrick_xtask::authority_source::SourceCensus::load(root.path()).unwrap();
    assert_eq!(census.k1.len(), 1);
}

#[test]
fn item_macro_calls_are_counted_and_cfg_expressions_are_excluded() {
    let root = source_fixture();
    let path = root.path().join("crates/carrick-kernel/src/lib.rs");
    std::fs::write(
        &path,
        r#"
emit! { pub fn poll(table: &Table) { table.read_open_files(); } }
#[cfg(test)] emit! { pub fn ignored(table: &Table) { table.read_open_files(); } }
pub fn no_debt(table: &Table) {
    #[cfg(test)] table.read_open_files();
    #[cfg(test)] if true { table.read_open_files(); }
}
"#,
    )
    .unwrap();
    let census = carrick_xtask::authority_source::SourceCensus::load(root.path()).unwrap();
    assert_eq!(census.k1.len(), 1);
    assert_eq!(census.k1[0].owner, "carrick_kernel::poll");
}

#[test]
fn ufcs_and_function_references_cannot_escape_k1_counts() {
    let root = source_fixture();
    let path = root.path().join("crates/carrick-kernel/src/lib.rs");
    std::fs::write(path, "pub fn poll(table: &Table) { FileTable::read_open_files(table); let call = FileTable::read_open_files; call(table); }").unwrap();
    let census = carrick_xtask::authority_source::SourceCensus::load(root.path()).unwrap();
    assert_eq!(census.k1.len(), 2);
}

#[test]
fn macro_rules_authority_wrappers_fail_closed() {
    let root = source_fixture();
    let path = root.path().join("crates/carrick-kernel/src/lib.rs");
    std::fs::write(path, "macro_rules! access { ($table:expr) => { $table.read_open_files() }; } pub fn poll(table: &Table) { access!(table); }").unwrap();
    assert!(carrick_xtask::authority_source::SourceCensus::load(root.path()).is_err());
}

#[test]
fn relocating_debt_into_definition_paths_cannot_hide_additions() {
    use carrick_xtask::authority_debt::verify_source;
    let root = source_fixture();
    let src = root.path().join("crates/carrick-kernel/src");
    std::fs::create_dir_all(src.join("kernel")).unwrap();
    std::fs::rename(src.join("lib.rs"), src.join("kernel/objects.rs")).unwrap();
    let census = carrick_xtask::authority_source::SourceCensus::load(root.path()).unwrap();
    assert_eq!(census.k1.len(), 1);
    std::fs::write(
        src.join("kernel/objects.rs"),
        "pub fn poll(table: &Table) { table.read_open_files(); table.read_open_files(); }",
    )
    .unwrap();
    assert!(verify_source(root.path(), tools_root(), &ceilings(1)).is_err());
}

#[test]
fn relocating_raw_lock_outside_dispatch_cannot_hide_additions() {
    use carrick_xtask::authority_debt::verify_source;
    let root = source_fixture();
    let policy = AuthorityDebtCeilings {
        schema: 1,
        counters: vec![
            ceilings(1).counters[0].clone(),
            Counter {
                family: Family::RawLock,
                operation: "proc".into(),
                owner: "carrick_kernel::raw".into(),
                lane: Lane::Shared,
                ceiling: 1,
            },
        ],
    };
    let src = root.path().join("crates/carrick-kernel/src");
    std::fs::write(
        src.join("elsewhere.rs"),
        "pub fn raw(this: &Dispatcher) { this.proc.lock(); this.proc.lock(); }",
    )
    .unwrap();
    assert!(verify_source(root.path(), tools_root(), &policy).is_err());
}

#[test]
fn occurrence_ordinals_are_not_authority_owners() {
    let mut policy = ceilings(1);
    policy.counters[0].owner.push_str("#2");
    assert!(policy.validate().is_err());
}

#[test]
fn repeated_global_reads_are_one_symbol_counter() {
    use carrick_xtask::authority_debt::verify_source;
    let root = source_fixture();
    let path = root.path().join("crates/carrick-kernel/src/lib.rs");
    std::fs::write(&path, "pub fn poll(table: &Table) { table.read_open_files(); std::env::var(\"DEBUG\"); std::env::var(\"DEBUG\"); }").unwrap();
    let mut policy = ceilings(1);
    policy.counters.push(Counter {
        family: Family::GlobalConfigDebug,
        operation: "global:env_var".into(),
        owner: "carrick_kernel::poll::DEBUG".into(),
        lane: Lane::Shared,
        ceiling: 2,
    });
    verify_source(root.path(), tools_root(), &policy).unwrap();
    policy.counters[1].ceiling = 1;
    assert!(verify_source(root.path(), tools_root(), &policy).is_err());
}
