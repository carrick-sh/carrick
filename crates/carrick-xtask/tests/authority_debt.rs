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

fn write_source(
    path: impl AsRef<std::path::Path>,
    source: impl AsRef<[u8]>,
) -> std::io::Result<()> {
    let path = path.as_ref();
    let mut source = source.as_ref().to_vec();
    if path.ends_with("crates/carrick-kernel/src/lib.rs") {
        source.extend_from_slice(b"\nmod kernel; mod dispatch;\n");
    }
    std::fs::write(path, source)
}

fn source_fixture() -> tempfile::TempDir {
    use std::fs;
    let root = tempfile::tempdir().unwrap();
    let src = root.path().join("crates/carrick-kernel/src");
    fs::create_dir_all(src.join("dispatch/sysv")).unwrap();
    write_source(
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
    write_source(
        src.join("dispatch/sysv/lock_authority.rs"),
        "impl SysvNamespacePermit { fn lock_paired() {} }",
    )
    .unwrap();
    write_source(
        src.join("lib.rs"),
        "pub fn poll(table: &Table) { table.read_open_files(); }",
    )
    .unwrap();
    for (file, source) in [
        (
            "crates/carrick-kernel/src/kernel/crash_capture.rs",
            "impl CrashQuorum { fn poll(&self) {} }",
        ),
        (
            "crates/carrick-kernel/src/dispatch/mm_quiesce.rs",
            "fn drain_exact_mm() {}",
        ),
        (
            "crates/carrick-runtime/src/vcpu_loop/quiesce.rs",
            "fn try_begin_hvpatch_process_fork_with_admission() {}",
        ),
        (
            "crates/carrick-kernel/src/dispatch/mm_authority.rs",
            "impl MmExecutorAdmissionRecipe { fn enter(&self) {} }",
        ),
        (
            "crates/carrick-kernel/src/kernel/objects.rs",
            "impl Thread { fn enter_crash_safe_point_participation(&self) {} }",
        ),
    ] {
        let path = root.path().join(file);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        write_source(path, source).unwrap();
    }
    for (file, source) in [
        (
            "crates/carrick-kernel/src/kernel/mod.rs",
            "mod crash_capture; mod objects;",
        ),
        (
            "crates/carrick-kernel/src/dispatch/mod.rs",
            "mod sysv; mod mm_authority; mod mm_quiesce;",
        ),
        ("crates/carrick-runtime/src/lib.rs", "mod vcpu_loop;"),
        (
            "crates/carrick-runtime/src/vcpu_loop/mod.rs",
            "mod quiesce;",
        ),
    ] {
        let path = root.path().join(file);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        write_source(path, source).unwrap();
    }
    root
}

fn assert_dialect_rejection(root: &std::path::Path, expected: &str) {
    let error = carrick_xtask::authority_source::SourceCensus::load(root)
        .unwrap_err()
        .to_string();
    assert!(error.contains(expected), "expected {expected}, got {error}");
}

fn restricted_dialect_error(source: &str, expected: &str) {
    let root = source_fixture();
    let src = root.path().join("crates/carrick-kernel/src");
    if source.contains("selected.rs") {
        std::fs::create_dir_all(src.join("parent")).unwrap();
        write_source(
            src.join("parent/selected.rs"),
            "fn hidden(table: &Table) { table.read_open_files(); }",
        )
        .unwrap();
    }
    write_source(src.join("lib.rs"), source).unwrap();
    let error = carrick_xtask::authority_source::SourceCensus::load(root.path())
        .unwrap_err()
        .to_string();
    assert!(
        error.contains(expected),
        "expected {expected:?}, got {error}"
    );
    assert!(
        error.contains("lib.rs:"),
        "missing precise source location: {error}"
    );
    let verification_error =
        carrick_xtask::authority_debt::verify_source(root.path(), tools_root(), &ceilings(1))
            .unwrap_err()
            .to_string();
    assert!(
        verification_error.contains(expected),
        "zero/structural gate must reject the dialect input: {verification_error}"
    );
}

#[test]
fn restricted_dialect_cfg_attr_path_is_rejected() {
    restricted_dialect_error(
        r#"mod parent { #[cfg_attr(all(), path="selected.rs")] mod child; }
#[cfg(test)] #[path="parent/selected.rs"] mod test_copy;"#,
        "conditional module path is unsupported",
    );
}

#[test]
fn restricted_dialect_rebound_test_is_rejected() {
    restricted_dialect_error(
        "use tracing::instrument as test; #[test] fn hidden(table: &Table) { table.read_open_files(); }",
        "import may rebind built-in test",
    );
}

#[test]
fn restricted_dialect_glob_test_is_rejected() {
    restricted_dialect_error(
        "use tracing::*; #[test] fn hidden(table: &Table) { table.read_open_files(); }",
        "glob import makes test exclusion ambiguous",
    );
}

#[test]
fn restricted_dialect_qualified_test_is_rejected() {
    restricted_dialect_error(
        "#[tracing::test] fn hidden(table: &Table) { table.read_open_files(); }",
        "qualified test attribute is unsupported",
    );
}

#[test]
fn restricted_dialect_cfg_attr_test_is_rejected() {
    restricted_dialect_error(
        "#[cfg_attr(all(), test)] fn hidden(table: &Table) { table.read_open_files(); }",
        "conditional test attribute is unsupported",
    );
}

#[test]
fn restricted_dialect_attribute_expression_is_rejected() {
    restricted_dialect_error(
        "#[tracing::instrument(fields(count = table.read_open_files().len()))] fn hidden(table: &Table) {}",
        "unaudited attribute arguments",
    );
}

#[test]
fn restricted_dialect_renamed_operation_is_rejected() {
    restricted_dialect_error(
        "use x::read_open_files as r; fn hidden() { r(); }",
        "renamed protected import read_open_files as r",
    );
}

#[test]
fn restricted_dialect_reexported_termination_is_rejected() {
    restricted_dialect_error(
        "mod x { pub use std::process::abort as read_open_files; }",
        "renamed protected import abort as read_open_files",
    );
}

#[test]
fn restricted_dialect_renamed_authority_type_is_rejected() {
    restricted_dialect_error(
        "use OpenDescriptionRef as R; fn hidden(x: X) { R::clone(x); }",
        "renamed protected import OpenDescriptionRef as R",
    );
}

#[test]
fn restricted_dialect_renamed_environment_is_rejected() {
    restricted_dialect_error(
        "use std::env as e; fn hidden() { e::var(\"CARRICK_MODE\"); }",
        "renamed protected import env as e",
    );
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
    let src = root.path().join("crates/carrick-kernel/src");
    write_source(
        src.join("lib.rs"),
        "#[path = \"initial.rs\"] mod stable;".replace("\\", ""),
    )
    .unwrap();
    let source = src.join("initial.rs");
    write_source(
        &source,
        "pub fn poll(table: &Table) { table.read_open_files(); }",
    )
    .unwrap();
    let mut policy = ceilings(1);
    policy.counters[0].owner = "carrick_kernel::stable::poll".into();
    verify_source(root.path(), tools_root(), &policy).unwrap();
    let moved = src.join("relocated.rs");
    write_source(
        &moved,
        format!("\n\n{}", fs::read_to_string(&source).unwrap()),
    )
    .unwrap();
    fs::remove_file(source).unwrap();
    write_source(
        src.join("lib.rs"),
        "#[path = \"relocated.rs\"] mod stable;".replace("\\", ""),
    )
    .unwrap();
    let before = fs::read(&moved).unwrap();
    verify_source(root.path(), tools_root(), &policy).unwrap();
    assert_eq!(before, fs::read(&moved).unwrap());
    write_source(
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
    write_source(
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
    write_source(
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
    write_source(
        root.path()
            .join("crates/carrick-kernel/src/dispatch/mod.rs"),
        "mod sysv; mod mm_authority; mod mm_quiesce; mod proc;",
    )
    .unwrap();
    write_source(
        &path,
        "pub fn poll(this: &Dispatcher) { this.proc.lock(); }",
    )
    .unwrap();
    let error = verify_source(root.path(), tools_root(), &ceilings(1))
        .unwrap_err()
        .to_string();
    assert!(error.contains("unknown authority"), "{error}");
    std::fs::remove_file(path).unwrap();
    write_source(
        root.path()
            .join("crates/carrick-kernel/src/dispatch/mod.rs"),
        "mod sysv; mod mm_authority; mod mm_quiesce;",
    )
    .unwrap();
    std::fs::remove_file(
        root.path()
            .join("crates/carrick-kernel/src/dispatch/sysv.rs"),
    )
    .unwrap();
    assert!(
        verify_source(root.path(), tools_root(), &ceilings(1))
            .unwrap_err()
            .to_string()
            .contains("missing production module owner")
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
    write_source(
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
    write_source(
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
    write_source(
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
    write_source(
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
    write_source(path, "pub fn poll(table: &Table) { FileTable::read_open_files(table); let call = FileTable::read_open_files; call(table); }").unwrap();
    let census = carrick_xtask::authority_source::SourceCensus::load(root.path()).unwrap();
    assert_eq!(census.k1.len(), 2);
}

#[test]
fn macro_rules_authority_wrappers_fail_closed() {
    let root = source_fixture();
    let path = root.path().join("crates/carrick-kernel/src/lib.rs");
    write_source(path, "macro_rules! access { ($table:expr) => { $table.read_open_files() }; } pub fn poll(table: &Table) { access!(table); }").unwrap();
    assert!(carrick_xtask::authority_source::SourceCensus::load(root.path()).is_err());
}

#[test]
fn relocating_debt_into_definition_paths_cannot_hide_additions() {
    use carrick_xtask::authority_debt::verify_source;
    let root = source_fixture();
    let src = root.path().join("crates/carrick-kernel/src");
    std::fs::create_dir_all(src.join("kernel")).unwrap();
    write_source(src.join("kernel/objects.rs"), "impl Thread { fn enter_crash_safe_point_participation(&self) {} } pub fn poll(table: &Table) { table.read_open_files(); }").unwrap();
    write_source(src.join("lib.rs"), "").unwrap();
    let census = carrick_xtask::authority_source::SourceCensus::load(root.path()).unwrap();
    assert_eq!(census.k1.len(), 1);
    write_source(
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
    write_source(
        src.join("lib.rs"),
        "mod elsewhere; pub fn poll(table: &Table) { table.read_open_files(); }",
    )
    .unwrap();
    write_source(
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
    write_source(&path, "pub fn poll(table: &Table) { table.read_open_files(); std::env::var(\"DEBUG\"); std::env::var(\"DEBUG\"); }").unwrap();
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

#[test]
fn review_same_count_global_substitution_between_modules_is_rejected() {
    use carrick_xtask::{authority_debt::verify_source, authority_source::SourceCensus};
    let root = source_fixture();
    let src = root.path().join("crates/carrick-kernel/src");
    write_source(src.join("lib.rs"), "mod fifo_beacon; mod unreviewed;").unwrap();
    write_source(
        src.join("fifo_beacon.rs"),
        "static STATE: AtomicBool = AtomicBool::new(false);",
    )
    .unwrap();
    write_source(src.join("unreviewed.rs"), "").unwrap();
    let census = SourceCensus::load(root.path()).unwrap();
    let policy = AuthorityDebtCeilings {
        schema: 1,
        counters: vec![Counter {
            family: Family::GlobalCarrierInfra,
            operation: "global:static".into(),
            owner: census
                .owner_at("crates/carrick-kernel/src/fifo_beacon.rs", 1, 0)
                .unwrap(),
            lane: Lane::Shared,
            ceiling: 1,
        }],
    };
    verify_source(root.path(), tools_root(), &policy).unwrap();
    write_source(src.join("fifo_beacon.rs"), "").unwrap();
    write_source(
        src.join("unreviewed.rs"),
        "static STATE: AtomicBool = AtomicBool::new(false);",
    )
    .unwrap();
    assert!(
        verify_source(root.path(), tools_root(), &policy).is_err(),
        "an unreviewed module must not replace fifo_beacon::STATE"
    );
}

#[test]
fn exact_column_zero_does_not_merge_same_line_owners() {
    use carrick_xtask::authority_source::SourceCensus;
    let root = source_fixture();
    let src = root.path().join("crates/carrick-kernel/src/lib.rs");
    write_source(&src, "static REVIEWED_STATE: AtomicBool = AtomicBool::new(false); static STATE: AtomicBool = AtomicBool::new(false);").unwrap();
    let census = SourceCensus::load(root.path()).unwrap();
    assert_eq!(
        census
            .owner_at("crates/carrick-kernel/src/lib.rs", 1, 0)
            .unwrap(),
        "carrick_kernel::REVIEWED_STATE"
    );
    assert!(
        census
            .owner_on_line("crates/carrick-kernel/src/lib.rs", 1)
            .is_err()
    );
}

#[test]
fn declared_root_owns_modules_physically_relocated_into_another_crate() {
    use carrick_xtask::authority_source::SourceCensus;
    let root = source_fixture();
    let src = root.path().join("crates/carrick-kernel/src");
    std::fs::create_dir_all(root.path().join("crates/carrick-vmm-hvf/src")).unwrap();
    write_source(
        src.join("lib.rs"),
        "#[path = \"../../carrick-vmm-hvf/src/relocated.rs\"] mod moved;",
    )
    .unwrap();
    write_source(root.path().join("crates/carrick-vmm-hvf/src/lib.rs"), "").unwrap();
    write_source(
        root.path().join("crates/carrick-vmm-hvf/src/relocated.rs"),
        "fn poll(table: &FileTable) { table.read_open_files(); }",
    )
    .unwrap();
    let census = SourceCensus::load(root.path()).unwrap();
    assert_eq!(census.k1.len(), 1);
    assert_eq!(census.k1[0].owner, "carrick_kernel::moved::poll");
    assert_eq!(census.k1[0].lane, Lane::Shared);
    write_source(
        root.path().join("crates/carrick-vmm-hvf/src/relocated.rs"),
        "fn poll(this: &Dispatcher) { this.proc.lock(); }",
    )
    .unwrap();
    assert!(
        carrick_xtask::authority_debt::verify_source(root.path(), tools_root(), &ceilings(0))
            .is_err(),
        "relocated raw access must still require an owner counter"
    );
}

#[test]
fn macro_item_scopes_keep_modules_and_impl_traits() {
    let root = source_fixture();
    let src = root.path().join("crates/carrick-kernel/src/lib.rs");
    write_source(src, "items! { mod first { impl First for Thing { fn access() { table.read_open_files(); } } } mod second { impl Second for Thing { fn access() { table.read_open_files(); } } } }").unwrap();
    let census = carrick_xtask::authority_source::SourceCensus::load(root.path()).unwrap();
    assert_eq!(census.k1.len(), 2);
    assert_eq!(
        census.k1[0].owner,
        "carrick_kernel::first::<Thing as First>::access"
    );
    assert_eq!(
        census.k1[1].owner,
        "carrick_kernel::second::<Thing as Second>::access"
    );
    write_source(root.path().join("crates/carrick-kernel/src/lib.rs"), "impl FileTable { items! { fn raw_slots(&self) -> &RwLock<FileSlotMap> { &self.open_files } } }").unwrap();
    assert!(
        carrick_xtask::authority_source::SourceCensus::load(root.path()).is_err(),
        "macro-declared raw accessors must remain closed"
    );
}

#[test]
fn function_local_modules_and_impls_keep_distinct_owners() {
    let root = source_fixture();
    write_source(root.path().join("crates/carrick-kernel/src/lib.rs"), "fn outer() { mod first { fn access() { table.read_open_files(); } } mod second { fn access() { table.read_open_files(); } } impl First for Thing { fn access() { table.read_open_files(); } } impl Second for Thing { fn access() { table.read_open_files(); } } }").unwrap();
    let census = carrick_xtask::authority_source::SourceCensus::load(root.path()).unwrap();
    let owners: std::collections::BTreeSet<_> =
        census.k1.iter().map(|site| site.owner.as_str()).collect();
    assert_eq!(
        owners.len(),
        4,
        "nested module and trait identities must not merge"
    );
    assert!(owners.contains("carrick_kernel::outer::first::access"));
    assert!(owners.contains("carrick_kernel::outer::<Thing as First>::access"));
}

#[test]
fn associated_aliases_cannot_hide_raw_table_storage() {
    let root = source_fixture();
    write_source(root.path().join("crates/carrick-kernel/src/lib.rs"), "impl Expose for FileTable { type Slots = RwLock<FileSlotMap>; fn raw_slots(&self) -> &Self::Slots { &self.open_files } }").unwrap();
    assert!(
        carrick_xtask::authority_source::SourceCensus::load(root.path()).is_err(),
        "associated storage aliases must remain closed"
    );
}

#[test]
fn cfg_alias_alternatives_cannot_hide_raw_table_storage() {
    let root = source_fixture();
    write_source(root.path().join("crates/carrick-kernel/src/lib.rs"), "#[cfg(target_os = \"linux\")] type Slots = RwLock<FileSlotMap>; #[cfg(target_os = \"macos\")] type Slots = Vec<u8>; impl FileTable { #[cfg(target_os = \"linux\")] fn raw_slots(&self) -> &Slots { &self.open_files } }").unwrap();
    assert!(
        carrick_xtask::authority_source::SourceCensus::load(root.path()).is_err(),
        "every production alias alternative must be checked"
    );
}

#[test]
fn review_out_of_line_modules_and_impl_traits_have_distinct_owners() {
    use carrick_xtask::authority_source::SourceCensus;
    let root = source_fixture();
    let src = root.path().join("crates/carrick-kernel/src");
    write_source(src.join("lib.rs"), "mod outer;").unwrap();
    write_source(src.join("outer.rs"), "#[path = \"leaf.rs\"] mod inner;").unwrap();
    write_source(src.join("leaf.rs"), "impl First for Thing { fn access() { table.read_open_files(); } } impl Second for Thing { fn access() { table.read_open_files(); } }").unwrap();
    let census = SourceCensus::load(root.path()).unwrap();
    assert_eq!(census.k1.len(), 2);
    assert_eq!(
        census.k1[0].owner,
        "carrick_kernel::outer::inner::<Thing as First>::access"
    );
    assert_ne!(census.k1[0].owner, census.k1[1].owner);
}

#[test]
fn review_macro_turbofish_and_function_references_are_counted() {
    let root = source_fixture();
    let src = root.path().join("crates/carrick-kernel/src/lib.rs");
    write_source(
        src,
        r#"pub fn poll(description: &Description) {
        matches!(description.concrete_backing::<IoUringBacking>(), Some(_));
        assert!(predicate(FileTable::read_open_files));
        format!("{:?}", FileTable::write_open_files);
        matches!(FileTable::read_epoll_fds, _);
        assert!(predicate(FileDescription::read_for_io));
        format!("{:?}", FileDescription::write_for_io);
    }"#,
    )
    .unwrap();
    let census = carrick_xtask::authority_source::SourceCensus::load(root.path()).unwrap();
    assert_eq!(
        census
            .k1
            .iter()
            .map(|s| s.operation.as_str())
            .collect::<Vec<_>>(),
        vec![
            "concrete_backing",
            "read_open_files",
            "write_open_files",
            "read_epoll_fds",
            "read_for_io",
            "write_for_io"
        ]
    );
}

#[test]
fn review_raw_table_lock_references_and_aliases_fail_closed() {
    for return_type in [
        "&RwLock<FileSlotMap>",
        "&Mutex<FileSlotMap>",
        "&Slots",
        "SlotsGuard",
    ] {
        let root = source_fixture();
        let src = root.path().join("crates/carrick-kernel/src/lib.rs");
        write_source(src, format!("type Slots = RwLock<FileSlotMap>; type SlotsGuard = RwLockReadGuard<'static, FileSlotMap>; impl FileTable {{ fn raw_slots(&self) -> {return_type} {{ &self.open_files }} }} pub fn poll(table: &FileTable) {{ table.raw_slots().read(); }}")).unwrap();
        assert!(
            carrick_xtask::authority_source::SourceCensus::load(root.path()).is_err(),
            "unclassified raw_slots returning {return_type}"
        );
    }
}

#[test]
fn review_task_structural_owner_moves_and_missing_owners_fail_closed() {
    use carrick_xtask::authority_debt::verify_source;
    for (file, source) in [
        (
            "kernel/renamed_crash_capture.rs",
            "impl CrashQuorum { fn poll(&self) { for thread in self.task.threads() {} } }",
        ),
        (
            "dispatch/renamed_mm_quiesce.rs",
            "fn drain_exact_mm(census: &GuestExecutorCensus) { census.live(); }",
        ),
        ("kernel/missing.rs", ""),
    ] {
        let root = source_fixture();
        let src = root.path().join("crates/carrick-kernel/src");
        write_source(src.join("lib.rs"), "").unwrap();
        std::fs::create_dir_all(src.join("kernel")).unwrap();
        if file.contains("crash_capture") {
            std::fs::remove_file(src.join("kernel/crash_capture.rs")).unwrap();
        } else {
            std::fs::remove_file(src.join("dispatch/mm_quiesce.rs")).unwrap();
        }
        write_source(src.join(file), source).unwrap();
        let empty = AuthorityDebtCeilings {
            schema: 1,
            counters: vec![],
        };
        assert!(
            verify_source(root.path(), tools_root(), &empty).is_err(),
            "missing or moved structural owner: {file}"
        );
    }
}

#[test]
fn task_structural_rules_follow_symbols_after_physical_relocation() {
    use carrick_xtask::authority_debt::verify_source;
    for crash in [true, false] {
        let root = source_fixture();
        let src = root.path().join("crates/carrick-kernel/src");
        if crash {
            std::fs::rename(
                src.join("kernel/crash_capture.rs"),
                src.join("kernel/moved.rs"),
            )
            .unwrap();
            write_source(
                src.join("kernel/mod.rs"),
                "#[path=\"moved.rs\"] mod crash_capture; mod objects;",
            )
            .unwrap();
            write_source(
                src.join("kernel/moved.rs"),
                "impl CrashQuorum { fn poll(&self) { for thread in self.task.threads() {} } }",
            )
            .unwrap();
        } else {
            std::fs::rename(
                src.join("dispatch/mm_quiesce.rs"),
                src.join("dispatch/moved.rs"),
            )
            .unwrap();
            write_source(
                src.join("dispatch/mod.rs"),
                "mod sysv; mod mm_authority; #[path=\"moved.rs\"] mod mm_quiesce;",
            )
            .unwrap();
            write_source(
                src.join("dispatch/moved.rs"),
                "fn drain_exact_mm(census: &GuestExecutorCensus) { census.live(); }",
            )
            .unwrap();
        }
        let error = verify_source(root.path(), tools_root(), &ceilings(1))
            .unwrap_err()
            .to_string();
        assert!(error.contains("forbidden task authority"), "{error}");
    }
}

#[test]
fn undeclared_files_cannot_satisfy_structural_owner_discovery() {
    use carrick_xtask::authority_debt::verify_source;
    let root = source_fixture();
    write_source(
        root.path().join("crates/carrick-kernel/src/kernel/mod.rs"),
        "mod objects;",
    )
    .unwrap();
    let error = verify_source(root.path(), tools_root(), &ceilings(1))
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("missing task structural rule owner"),
        "{error}"
    );
}

#[test]
fn imported_aliases_and_trait_impls_cannot_expose_raw_table_storage() {
    let root = source_fixture();
    let src = root.path().join("crates/carrick-kernel/src");
    write_source(
        src.join("locks.rs"),
        "pub type Storage = parking_lot::RwLock<FileSlotMap>;",
    )
    .unwrap();
    for implementation in ["FileTable", "<T> FileTable<T>", "Escape for FileTable"] {
        write_source(src.join("lib.rs"), format!("mod locks; use crate::locks::Storage as Slots; impl {implementation} {{ fn raw_slots(&self) -> &Slots {{ &self.open_files }} }}")).unwrap();
        assert!(
            carrick_xtask::authority_source::SourceCensus::load(root.path()).is_err(),
            "{implementation}"
        );
    }
}

#[test]
fn local_statics_keep_the_enclosing_function_identity() {
    let root = source_fixture();
    write_source(root.path().join("crates/carrick-kernel/src/lib.rs"), "fn first() { static STATE: AtomicBool = AtomicBool::new(false); }\nfn second() { static STATE: AtomicBool = AtomicBool::new(false); }").unwrap();
    let census = carrick_xtask::authority_source::SourceCensus::load(root.path()).unwrap();
    assert_eq!(
        census
            .owner_at("crates/carrick-kernel/src/lib.rs", 1, 20)
            .unwrap(),
        "carrick_kernel::first::STATE"
    );
    assert_eq!(
        census
            .owner_at("crates/carrick-kernel/src/lib.rs", 2, 21)
            .unwrap(),
        "carrick_kernel::second::STATE"
    );
}

#[test]
fn raw_crash_participation_requires_the_exact_licensed_owner() {
    use carrick_xtask::authority_debt::verify_source;
    for operation in [
        "enter_crash_safe_point_participation",
        "leave_crash_safe_point_participation",
    ] {
        let root = source_fixture();
        write_source(root.path().join("crates/carrick-kernel/src/lib.rs"), format!("pub fn poll(table: &Table, thread: &Thread) {{ table.read_open_files(); thread.{operation}(); }}")).unwrap();
        let error = verify_source(root.path(), tools_root(), &ceilings(1))
            .unwrap_err()
            .to_string();
        assert!(error.contains("forbidden task authority"), "{error}");
    }
}

#[test]
fn round3_shared_test_declaration_cannot_hide_production_k1() {
    let root = source_fixture();
    let src = root.path().join("crates/carrick-kernel/src");
    write_source(
        src.join("lib.rs"),
        r#"
#[path = "shared.rs"] mod production;
#[cfg(test)] #[path = "shared.rs"] mod tests_copy;
"#,
    )
    .unwrap();
    write_source(
        src.join("shared.rs"),
        "fn access(table: &FileTable) { table.read_open_files(); }",
    )
    .unwrap();
    let census = carrick_xtask::authority_source::SourceCensus::load(root.path()).unwrap();
    assert_eq!(
        census.k1.len(),
        1,
        "a test declaration cannot erase a production incarnation"
    );
    assert_eq!(census.k1[0].owner, "carrick_kernel::production::access");
    assert!(!census.is_test_at("crates/carrick-kernel/src/shared.rs", 1, 0));
}

#[test]
fn round3_shared_test_declaration_cannot_hide_production_raw_locks() {
    let root = source_fixture();
    let src = root.path().join("crates/carrick-kernel/src");
    write_source(
        src.join("lib.rs"),
        r#"
#[path = "shared.rs"] mod production;
#[cfg(test)] #[path = "shared.rs"] mod tests_copy;
pub fn poll(table: &Table) { table.read_open_files(); }
"#,
    )
    .unwrap();
    write_source(
        src.join("shared.rs"),
        "fn access(this: &Dispatcher) { this.proc.lock(); }",
    )
    .unwrap();
    assert!(
        carrick_xtask::authority_debt::verify_source(root.path(), tools_root(), &ceilings(1))
            .is_err(),
        "shared production raw lock requires an assigned counter"
    );
}

#[test]
fn round3_macro_rules_crash_participation_is_rejected() {
    let root = source_fixture();
    write_source(
        root.path().join("crates/carrick-kernel/src/lib.rs"),
        r#"
macro_rules! enter { ($thread:expr) => { $thread.enter_crash_safe_point_participation() }; }
fn unlicensed(thread: &Thread) { enter!(thread); }
"#,
    )
    .unwrap();
    assert!(
        carrick_xtask::authority_source::SourceCensus::load(root.path())
            .and_then(|census| census.verify_task_rules())
            .is_err(),
        "macro body cannot hide unlicensed crash participation"
    );
}

#[test]
fn round3_macro_rules_crash_projection_is_rejected() {
    let root = source_fixture();
    write_source(
        root.path()
            .join("crates/carrick-kernel/src/kernel/crash_capture.rs"),
        r#"
macro_rules! threads { ($task:expr) => { $task.threads() }; }
impl CrashQuorum { fn poll(&self) { for thread in threads!(self.task) {} } }
"#,
    )
    .unwrap();
    assert!(
        carrick_xtask::authority_source::SourceCensus::load(root.path())
            .and_then(|census| census.verify_task_rules())
            .is_err(),
        "macro body cannot hide generic crash membership"
    );
}

#[test]
fn round3_macro_rules_exact_mm_live_is_rejected() {
    let root = source_fixture();
    write_source(
        root.path()
            .join("crates/carrick-kernel/src/dispatch/mm_quiesce.rs"),
        r#"
macro_rules! live { ($census:expr) => { $census.live() }; }
fn drain_exact_mm(census: &GuestExecutorCensus) { live!(census); }
"#,
    )
    .unwrap();
    assert!(
        carrick_xtask::authority_source::SourceCensus::load(root.path())
            .and_then(|census| census.verify_task_rules())
            .is_err(),
        "macro body cannot hide exact-MM census access"
    );
}

#[test]
fn round3_qualified_associated_storage_is_rejected() {
    for projection in ["<Self as EscapeSlots>::Slots", "EscapeSlots::Slots"] {
        let root = source_fixture();
        write_source(
            root.path().join("crates/carrick-kernel/src/lib.rs"),
            format!(
                r#"
impl EscapeSlots for FileTable {{
    type Slots = RwLock<FileSlotMap>;
    fn raw_slots(&self) -> &{projection} {{ &self.open_files }}
}}
fn unlicensed(table: &FileTable) {{ EscapeSlots::raw_slots(table).read(); }}
"#
            ),
        )
        .unwrap();
        assert!(
            carrick_xtask::authority_source::SourceCensus::load(root.path()).is_err(),
            "qualified raw-storage projection {projection} must be classified"
        );
    }
}

#[test]
fn round3_trait_helper_name_cannot_borrow_an_inherent_exemption() {
    for method in [
        "rw_write",
        "mutex_write",
        "try_mutex_write",
        "try_lock_next_fd",
        "lock_reserved_slots",
        "stdio_guard",
        "read_open_files",
    ] {
        let root = source_fixture();
        write_source(root.path().join("crates/carrick-kernel/src/lib.rs"), format!(r#"
impl EscapeSlots for FileTable {{ fn {method}(&self) -> &RwLock<FileSlotMap> {{ &self.open_files }} }}
fn unlicensed(table: &FileTable) {{ let slots = EscapeSlots::{method}(table); slots.read(); }}
"#)).unwrap();
        assert!(
            carrick_xtask::authority_source::SourceCensus::load(root.path()).is_err(),
            "trait accessor {method} cannot inherit the inherent helper exemption"
        );
    }
}

#[test]
fn round3_inherent_helper_exemptions_require_the_approved_module_and_signature() {
    let root = source_fixture();
    write_source(
        root.path().join("crates/carrick-kernel/src/lib.rs"),
        "impl FileTable { fn rw_write(&self) -> &RwLock<FileSlotMap> { &self.open_files } }",
    )
    .unwrap();
    assert!(
        carrick_xtask::authority_source::SourceCensus::load(root.path()).is_err(),
        "same method name in another module is not an approved helper"
    );
    write_source(root.path().join("crates/carrick-kernel/src/lib.rs"), "").unwrap();
    for signature in [
        "fn rw_write(&self) -> &RwLock<FileSlotMap>",
        "pub fn rw_write<'a, T>(&'a self, lock: &'a RwLock<T>) -> FileTableRwWriteGuard<'a, T>",
    ] {
        write_source(
            root.path()
                .join("crates/carrick-kernel/src/kernel/objects.rs"),
            format!("impl FileTable {{ {signature} {{ todo!() }} }}"),
        )
        .unwrap();
        assert!(
            carrick_xtask::authority_source::SourceCensus::load(root.path()).is_err(),
            "changed approved helper signature/visibility must fail: {signature}"
        );
    }
}

#[test]
fn production_declarations_override_test_directory_and_alias_exclusions() {
    let root = source_fixture();
    let src = root.path().join("crates/carrick-kernel/src");
    std::fs::create_dir_all(src.join("fixtures")).unwrap();
    write_source(
        src.join("lib.rs"),
        r#"
#[cfg(test)] mod fixtures;
#[path = "fixtures/shared.rs"] mod production;
impl FileTable { fn raw_slots(&self) -> &crate::production::Slots { todo!() } }
"#,
    )
    .unwrap();
    write_source(src.join("fixtures/mod.rs"), "mod shared;").unwrap();
    write_source(
        src.join("fixtures/shared.rs"),
        "pub type Slots = RwLock<FileSlotMap>;",
    )
    .unwrap();
    assert!(
        carrick_xtask::authority_source::SourceCensus::load(root.path()).is_err(),
        "a test directory cannot hide a production storage alias"
    );
    write_source(
        src.join("fixtures/shared.rs"),
        "fn access(table: &FileTable) { table.read_open_files(); }",
    )
    .unwrap();
    let census = carrick_xtask::authority_source::SourceCensus::load(root.path()).unwrap();
    assert_eq!(census.k1.len(), 1);
    assert_eq!(census.k1[0].owner, "carrick_kernel::production::access");
}

#[test]
fn qualified_projections_keep_all_impl_alternatives_and_resolve_plain_data() {
    let root = source_fixture();
    let path = root.path().join("crates/carrick-kernel/src/lib.rs");
    write_source(
        &path,
        r#"
impl EscapeSlots<u8> for FileTable { type Slots = RwLock<FileSlotMap>; }
impl EscapeSlots<u16> for FileTable { type Slots = Vec<u8>; }
impl FileTable { fn raw_slots(&self) -> &<Self as EscapeSlots<u8>>::Slots { todo!() } }
"#,
    )
    .unwrap();
    assert!(
        carrick_xtask::authority_source::SourceCensus::load(root.path()).is_err(),
        "one plain-data impl alternative cannot erase a storage projection"
    );
    write_source(
        &path,
        r#"
impl EscapeSlots for FileTable {
    type Slots = Vec<u8>;
    fn data(&self) -> &<Self as EscapeSlots>::Slots { todo!() }
}
impl FileTable { fn data(&self) -> &EscapeSlots::Slots { todo!() } }
"#,
    )
    .unwrap();
    carrick_xtask::authority_source::SourceCensus::load(root.path()).unwrap();
    write_source(
        &path,
        "impl FileTable { fn opaque(&self) -> &<Self as Unresolved>::Slots { todo!() } }",
    )
    .unwrap();
    assert!(
        carrick_xtask::authority_source::SourceCensus::load(root.path()).is_err(),
        "unresolved qualified return projections cannot hide storage"
    );
}

#[test]
fn exact_inherent_guard_boundary_accepts_layout_and_parameter_name_changes() {
    let root = source_fixture();
    write_source(root.path().join("crates/carrick-kernel/src/lib.rs"), "").unwrap();
    write_source(
        root.path()
            .join("crates/carrick-kernel/src/kernel/objects.rs"),
        r#"
impl FileTable {
    fn rw_write<'a, T>(
        &'a self,
        renamed_lock: &'a RwLock<T>,
    ) -> FileTableRwWriteGuard<'a, T> { todo!() }
}
"#,
    )
    .unwrap();
    carrick_xtask::authority_source::SourceCensus::load(root.path()).unwrap();
}

#[test]
fn harmless_and_test_only_macro_definitions_remain_usable() {
    let root = source_fixture();
    write_source(root.path().join("crates/carrick-kernel/src/lib.rs"), r#"
macro_rules! identity { ($value:expr) => { $value }; }
macro_rules! metadata { () => { mod constants { const NUMBER: u32 = 17; } }; }
#[cfg(test)] macro_rules! test_access { ($thread:expr) => { $thread.enter_crash_safe_point_participation() }; }
fn data() { identity!(17); }
"#).unwrap();
    carrick_xtask::authority_source::SourceCensus::load(root.path())
        .unwrap()
        .verify_task_rules()
        .unwrap();
}

#[test]
fn every_production_declaration_including_function_and_literal_macro_is_followed() {
    for declaration in [
        "fn launch() { #[path=\"shared.rs\"] mod production; }",
        "items! { #[path=\"shared.rs\"] mod production; }",
    ] {
        let root = source_fixture();
        let src = root.path().join("crates/carrick-kernel/src");
        write_source(
            src.join("lib.rs"),
            format!("{declaration}\n#[cfg(test)] #[path=\"shared.rs\"] mod tests_copy;"),
        )
        .unwrap();
        write_source(
            src.join("shared.rs"),
            "fn access(table: &FileTable) { table.read_open_files(); }",
        )
        .unwrap();
        if declaration.starts_with("items!") {
            assert_dialect_rejection(root.path(), "module path in macro input is unsupported");
            continue;
        }
        let census = carrick_xtask::authority_source::SourceCensus::load(root.path()).unwrap();
        assert_eq!(census.k1.len(), 1, "production declaration: {declaration}");
        assert!(!census.is_test_at("crates/carrick-kernel/src/shared.rs", 1, 0));
    }
}

#[test]
fn unexpanded_module_declarations_cannot_hide_production_files() {
    let root = source_fixture();
    let src = root.path().join("crates/carrick-kernel/src");
    write_source(
        src.join("lib.rs"),
        r#"
macro_rules! declare { () => { #[path="shared.rs"] mod production; }; }
declare!();
#[cfg(test)] #[path="shared.rs"] mod tests_copy;
"#,
    )
    .unwrap();
    write_source(
        src.join("shared.rs"),
        "fn access(table: &FileTable) { table.read_open_files(); }",
    )
    .unwrap();
    assert!(
        carrick_xtask::authority_source::SourceCensus::load(root.path()).is_err(),
        "unresolved production declarations cannot confer test-only classification"
    );
}

#[test]
fn round4_shared_production_includes_cannot_hide_k1() {
    for inclusion in ["include", "include_str"] {
        let root = source_fixture();
        let src = root.path().join("crates/carrick-kernel/src");
        let declaration = if inclusion == "include" {
            "include!(\"shared.rs\");"
        } else {
            "const SOURCE: &str = include_str!(\"shared.rs\");"
        };
        write_source(
            src.join("lib.rs"),
            format!("{declaration}\n#[cfg(test)] #[path=\"shared.rs\"] mod tests_copy;"),
        )
        .unwrap();
        write_source(
            src.join("shared.rs"),
            "fn access(table: &FileTable) { table.read_open_files(); }",
        )
        .unwrap();
        let census = carrick_xtask::authority_source::SourceCensus::load(root.path()).unwrap();
        assert_eq!(
            census.k1.len(),
            1,
            "production {inclusion}! incarnation must survive"
        );
        assert!(!census.is_test_at("crates/carrick-kernel/src/shared.rs", 1, 0));
        assert_eq!(
            census.k1[0].owner,
            if inclusion == "include" {
                "carrick_kernel::access"
            } else {
                "carrick_kernel::SOURCE::access"
            }
        );
    }
}

#[test]
fn round4_shared_production_include_cannot_hide_raw_locks() {
    let root = source_fixture();
    let src = root.path().join("crates/carrick-kernel/src");
    write_source(src.join("lib.rs"), "include!(\"shared.rs\");\n#[cfg(test)] #[path=\"shared.rs\"] mod tests_copy;\npub fn poll(table: &Table) { table.read_open_files(); }").unwrap();
    write_source(
        src.join("shared.rs"),
        "fn access(this: &Dispatcher) { this.proc.lock(); }",
    )
    .unwrap();
    assert!(
        carrick_xtask::authority_debt::verify_source(root.path(), tools_root(), &ceilings(1))
            .is_err(),
        "included production raw lock requires an assigned counter"
    );
}

#[test]
fn round4_nonliteral_source_inclusions_fail_closed() {
    for inclusion in ["include", "include_str"] {
        let root = source_fixture();
        let invocation = format!("{inclusion}!(concat!(env!(\"OUT_DIR\"), \"/shared.rs\"))");
        let source = if inclusion == "include" {
            format!("{invocation};")
        } else {
            format!("const SOURCE: &str = {invocation};")
        };
        write_source(root.path().join("crates/carrick-kernel/src/lib.rs"), source).unwrap();
        assert!(
            carrick_xtask::authority_source::SourceCensus::load(root.path()).is_err(),
            "unresolved {inclusion}! must fail closed"
        );
    }
}

fn check_round4_inspection_macro(operation: &str) {
    {
        let root = source_fixture();
        write_source(root.path().join("crates/carrick-kernel/src/lib.rs"), format!("macro_rules! legacy_access {{ ($slot:expr) => {{ $slot.description.{operation}() }}; }}\nfn unlicensed(slot: &FileSlot) {{ legacy_access!(slot); }}")).unwrap();
        assert!(
            carrick_xtask::authority_source::SourceCensus::load(root.path()).is_err(),
            "description.{operation}() in macro must not escape K1 admission"
        );
    }
}

#[test]
fn round4_description_inspect_macro_body_fails_closed() {
    check_round4_inspection_macro("inspect");
}
#[test]
fn round4_description_try_inspect_macro_body_fails_closed() {
    check_round4_inspection_macro("try_inspect");
}

#[test]
fn round4_macro_and_main_scanners_share_the_authority_vocabulary() {
    let vocabulary: std::collections::BTreeMap<String, Vec<String>> = serde_json::from_str(
        include_str!("../../../scripts/migrate/authority-vocabulary.json"),
    )
    .unwrap();
    for (kind, operations) in vocabulary {
        if kind.starts_with("source_") {
            continue;
        }
        for operation in operations {
            let root = source_fixture();
            let path = root.path().join("crates/carrick-kernel/src/lib.rs");
            write_source(&path, format!("macro_rules! hidden {{ ($slot:expr) => {{ $slot.description.{operation}() }}; }}")).unwrap();
            assert!(
                carrick_xtask::authority_source::SourceCensus::load(root.path()).is_err(),
                "macro must recognize shared {kind} operation {operation}"
            );
            if ["k1", "description_io", "description_guard"].contains(&kind.as_str()) {
                write_source(
                    &path,
                    format!("fn access(slot: &FileSlot) {{ slot.description.{operation}(); }}"),
                )
                .unwrap();
                let census =
                    carrick_xtask::authority_source::SourceCensus::load(root.path()).unwrap();
                assert_eq!(
                    census.k1.len(),
                    1,
                    "main census must use shared operation {operation}"
                );
                assert_eq!(census.k1[0].operation, operation);
            } else if kind == "raw_lock" {
                write_source(&path, format!("pub fn poll(table: &Table) {{ table.read_open_files(); }}\nfn access(this: &Dispatcher) {{ this.proc.{operation}(); }}")).unwrap();
                assert!(
                    carrick_xtask::authority_debt::verify_source(
                        root.path(),
                        tools_root(),
                        &ceilings(1)
                    )
                    .is_err(),
                    "raw census must use shared operation {operation}"
                );
            }
        }
    }
}

#[test]
fn source_inclusions_keep_physical_lookup_and_logical_owner() {
    let root = source_fixture();
    let src = root.path().join("crates/carrick-kernel/src");
    write_source(
        src.join("lib.rs"),
        "mod logical { include!(\"shared.rs\"); }",
    )
    .unwrap();
    write_source(src.join("shared.rs"), "include!(\"leaf.rs\");").unwrap();
    write_source(
        src.join("leaf.rs"),
        "fn access(table: &FileTable) { table.read_open_files(); }",
    )
    .unwrap();
    let census = carrick_xtask::authority_source::SourceCensus::load(root.path()).unwrap();
    assert_eq!(census.k1.len(), 1);
    assert_eq!(census.k1[0].owner, "carrick_kernel::logical::access");
    std::fs::rename(src.join("leaf.rs"), src.join("moved.rs")).unwrap();
    write_source(src.join("shared.rs"), "include!(\"moved.rs\");").unwrap();
    let moved = carrick_xtask::authority_source::SourceCensus::load(root.path()).unwrap();
    assert_eq!(moved.k1[0].owner, census.k1[0].owner);
}

#[test]
fn source_inclusions_in_macro_inputs_cannot_hide_production_files() {
    let root = source_fixture();
    let src = root.path().join("crates/carrick-kernel/src");
    write_source(src.join("lib.rs"), "fn access() { concat!(include_str!(\"shared.rs\"), \"suffix\"); }\n#[cfg(test)] #[path=\"shared.rs\"] mod tests_copy;").unwrap();
    write_source(
        src.join("shared.rs"),
        "fn inner(table: &FileTable) { table.read_open_files(); }",
    )
    .unwrap();
    assert_dialect_rejection(root.path(), "unresolved source reference in macro input");
}

#[test]
fn unresolved_inclusion_templates_and_outside_source_files_fail_closed() {
    let root = source_fixture();
    let src = root.path().join("crates/carrick-kernel/src");
    for source in [
        "macro_rules! hidden { () => { include!(\"shared.rs\"); }; }",
        "fn access() { include!(\"missing.rs\"); }",
        "include!(\"../outside.rs\");",
    ] {
        write_source(src.join("lib.rs"), source).unwrap();
        write_source(
            src.join("../outside.rs"),
            "fn hidden(table: &FileTable) { table.read_open_files(); }",
        )
        .unwrap();
        assert!(
            carrick_xtask::authority_source::SourceCensus::load(root.path()).is_err(),
            "inclusion must resolve to discoverable source: {source}"
        );
    }
}

#[test]
fn renamed_source_inclusions_cannot_hide_production_files() {
    let root = source_fixture();
    let src = root.path().join("crates/carrick-kernel/src");
    write_source(src.join("lib.rs"), "use std::include as compiled; use compiled as indirect; indirect!(\"shared.rs\",);\n#[cfg(test)] #[path=\"shared.rs\"] mod tests_copy;").unwrap();
    write_source(
        src.join("shared.rs"),
        "fn access(table: &FileTable) { table.read_open_files(); }",
    )
    .unwrap();
    assert_dialect_rejection(root.path(), "renamed protected import include");
    write_source(src.join("lib.rs"), "use std::include as compiled; macro_rules! hidden { () => { compiled!(\"shared.rs\"); }; }").unwrap();
    assert!(carrick_xtask::authority_source::SourceCensus::load(root.path()).is_err());
}

fn macro_input_alias_source(invocation: &str) -> String {
    format!(
        r#"
macro_rules! passthrough {{ ($($item:item)*) => {{ $($item)* }}; }}
passthrough! {{
    use std::include as retirement_include;
    retirement_include!({invocation});
}}
#[cfg(test)] #[path="shared.rs"] mod tests_copy;
pub fn poll(table: &Table) {{ table.read_open_files(); }}
"#
    )
}

#[test]
fn review_macro_input_inclusion_alias_cannot_hide_k1() {
    let root = source_fixture();
    let src = root.path().join("crates/carrick-kernel/src");
    write_source(
        src.join("lib.rs"),
        macro_input_alias_source(r#""shared.rs""#),
    )
    .unwrap();
    write_source(
        src.join("shared.rs"),
        "fn hidden(table: &Table) { table.read_open_files(); }",
    )
    .unwrap();
    assert_dialect_rejection(root.path(), "renamed protected import include");
}

#[test]
fn review_macro_input_inclusion_alias_cannot_hide_raw_locks() {
    let root = source_fixture();
    let src = root.path().join("crates/carrick-kernel/src");
    write_source(
        src.join("lib.rs"),
        macro_input_alias_source(r#""shared.rs""#),
    )
    .unwrap();
    write_source(
        src.join("shared.rs"),
        "fn hidden(this: &Dispatcher) { this.proc.lock(); }",
    )
    .unwrap();
    let error =
        carrick_xtask::authority_debt::verify_source(root.path(), tools_root(), &ceilings(1))
            .unwrap_err()
            .to_string();
    assert!(
        error.contains("renamed protected import include"),
        "{error}"
    );
}

#[test]
fn review_macro_input_inclusion_alias_rejects_nonliteral_paths() {
    let root = source_fixture();
    let src = root.path().join("crates/carrick-kernel/src");
    write_source(
        src.join("lib.rs"),
        macro_input_alias_source(r#"concat!("shared", ".rs")"#),
    )
    .unwrap();
    write_source(
        src.join("shared.rs"),
        "fn hidden(table: &Table) { table.read_open_files(); }",
    )
    .unwrap();
    let error = carrick_xtask::authority_source::SourceCensus::load(root.path())
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("renamed protected import include"),
        "{error}"
    );
}

#[test]
fn review_dsl_inclusion_alias_cannot_hide_authority() {
    for hidden in [
        "fn hidden(table: &Table) { table.read_open_files(); }",
        "fn hidden(this: &Dispatcher) { this.proc.lock(); }",
    ] {
        let root = source_fixture();
        let src = root.path().join("crates/carrick-kernel/src");
        write_source(
            src.join("lib.rs"),
            r#"
pass! { @ use std::include as x; x!("shared.rs"); }
#[cfg(test)] #[path="shared.rs"] mod tests_copy;
pub fn poll(table: &Table) { table.read_open_files(); }
"#,
        )
        .unwrap();
        write_source(src.join("shared.rs"), hidden).unwrap();
        assert!(
            carrick_xtask::authority_debt::verify_source(root.path(), tools_root(), &ceilings(1))
                .is_err(),
            "an arbitrary DSL cannot confer a test-only authority exemption: {hidden}"
        );
    }
}

#[test]
fn review_dsl_source_literals_mark_production_in_every_token_position() {
    for invocation in [
        r#"pass! { @ "shared.rs" => marker; }"#,
        r##"pass! { @ [(key => { r#"./shared.rs"# })] }"##,
        r#"pass! { @ "shared\u{2e}rs"; }"#,
        r#"#[cfg(test)] pass! { @ "shared.rs"; }"#,
        r#"macro_rules! data { () => { @ "shared.rs"; }; }"#,
        r#"fn data() { pass! { @ "shared.rs"; } }"#,
        r#"#[doc = pass! { @ "shared.rs" }] fn data() {}"#,
        r#"#[pass(@ "shared.rs")] fn data() {}"#,
    ] {
        let root = source_fixture();
        let src = root.path().join("crates/carrick-kernel/src");
        write_source(
            src.join("lib.rs"),
            format!("{invocation}\n#[cfg(test)] #[path=\"shared.rs\"] mod tests_copy;"),
        )
        .unwrap();
        write_source(src.join("shared.rs"), "fn data() {}").unwrap();
        if invocation.starts_with("#[cfg(test)]") {
            let census = carrick_xtask::authority_source::SourceCensus::load(root.path()).unwrap();
            assert!(census.is_test_file("crates/carrick-kernel/src/shared.rs"));
        } else {
            assert_dialect_rejection(root.path(), "restricted census dialect");
        }
    }
}

#[test]
fn review_dsl_source_literals_resolve_from_each_invoking_file() {
    for (invoking_file, literal, shared_file) in [
        ("nested/caller.rs", "../shared.rs", "shared.rs"),
        ("caller.rs", "../shared.rs", "../shared.rs"),
        ("caller.rs", "bin/shared.rs", "bin/shared.rs"),
    ] {
        let root = source_fixture();
        let src = root.path().join("crates/carrick-kernel/src");
        write_source(
            src.join("lib.rs"),
            format!(
                "#[cfg(test)] #[path=\"{shared_file}\"] mod tests_copy;\n\
                 pub fn poll(table: &Table) {{ table.read_open_files(); }}"
            ),
        )
        .unwrap();
        let invoking = src.join(invoking_file);
        std::fs::create_dir_all(invoking.parent().unwrap()).unwrap();
        write_source(invoking, format!("pass! {{ @ [\"{literal}\"] }}")).unwrap();
        let shared = src.join(shared_file);
        std::fs::create_dir_all(shared.parent().unwrap()).unwrap();
        write_source(
            shared,
            "fn hidden(table: &Table) { table.read_open_files(); }",
        )
        .unwrap();
        assert!(
            carrick_xtask::authority_debt::verify_source(root.path(), tools_root(), &ceilings(1))
                .is_err(),
            "source references resolve relative to {invoking_file}, including files under crates outside src"
        );
    }
}

#[test]
fn review_dsl_reference_outside_scanner_scope_cannot_hide_raw_locks() {
    let root = source_fixture();
    let src = root.path().join("crates/carrick-kernel/src");
    write_source(
        src.join("lib.rs"),
        r#"
pass! { @ "../shared.rs"; }
#[cfg(test)] #[path="../shared.rs"] mod tests_copy;
pub fn poll(table: &Table) { table.read_open_files(); }
"#,
    )
    .unwrap();
    write_source(
        src.join("../shared.rs"),
        "fn hidden(this: &Dispatcher) { this.proc.lock(); }",
    )
    .unwrap();
    assert!(
        carrick_xtask::authority_debt::verify_source(root.path(), tools_root(), &ceilings(1))
            .is_err(),
        "an undiscoverable production reference cannot bypass retained raw-lock checks"
    );
}

#[test]
fn review_production_closure_promotes_the_shared_module_child() {
    for hidden in [
        "fn hidden(table: &Table) { table.read_open_files(); }",
        "fn hidden(this: &Dispatcher) { this.proc.lock(); }",
    ] {
        let root = source_fixture();
        let src = root.path().join("crates/carrick-kernel/src");
        write_source(
            src.join("lib.rs"),
            r#"
pass! { @ use std::include as x; x!("shared.rs"); }
#[cfg(test)] #[path="shared.rs"] mod tests_copy;
pub fn poll(table: &Table) { table.read_open_files(); }
"#,
        )
        .unwrap();
        write_source(
            src.join("shared.rs"),
            "#[path=\"census_child.rs\"] pub mod child;",
        )
        .unwrap();
        write_source(src.join("census_child.rs"), "fn data() {}").unwrap();
        assert_dialect_rejection(root.path(), "restricted census dialect");
        let original = std::fs::read_to_string(src.join("lib.rs")).unwrap();
        let lines = original
            .lines()
            .filter(|line| !line.contains("pass!"))
            .collect::<Vec<_>>()
            .join("\n");
        write_source(
            src.join("lib.rs"),
            format!("const SOURCE: &str = include_str!(\"shared.rs\");\n{lines}"),
        )
        .unwrap();
        let census = carrick_xtask::authority_source::SourceCensus::load(root.path()).unwrap();
        assert!(!census.is_test_file("crates/carrick-kernel/src/census_child.rs"));
        write_source(src.join("census_child.rs"), hidden).unwrap();
        assert!(
            carrick_xtask::authority_debt::verify_source(root.path(), tools_root(), &ceilings(1))
                .is_err(),
            "a promoted production file cannot confer a test-only exemption on its child: {hidden}"
        );
    }
}

#[test]
fn review_production_closure_promotes_two_level_descendants() {
    for hidden in [
        "fn hidden(table: &Table) { table.read_open_files(); }",
        "fn hidden(this: &Dispatcher) { this.proc.lock(); }",
    ] {
        let root = source_fixture();
        let src = root.path().join("crates/carrick-kernel/src");
        write_source(
            src.join("lib.rs"),
            r#"
pass! { @ "shared.rs"; }
#[cfg(test)] #[path="shared.rs"] mod tests_copy;
pub fn poll(table: &Table) { table.read_open_files(); }
"#,
        )
        .unwrap();
        write_source(
            src.join("shared.rs"),
            "#[path=\"census_child.rs\"] pub mod child;",
        )
        .unwrap();
        write_source(
            src.join("census_child.rs"),
            "#[path=\"census_grandchild.rs\"] pub mod grandchild;",
        )
        .unwrap();
        write_source(src.join("census_grandchild.rs"), "fn data() {}").unwrap();
        assert_dialect_rejection(root.path(), "restricted census dialect");
        let original = std::fs::read_to_string(src.join("lib.rs")).unwrap();
        let lines = original
            .lines()
            .filter(|line| !line.contains("pass!"))
            .collect::<Vec<_>>()
            .join("\n");
        write_source(
            src.join("lib.rs"),
            format!("const SOURCE: &str = include_str!(\"shared.rs\");\n{lines}"),
        )
        .unwrap();
        let census = carrick_xtask::authority_source::SourceCensus::load(root.path()).unwrap();
        assert!(!census.is_test_file("crates/carrick-kernel/src/census_child.rs"));
        assert!(!census.is_test_file("crates/carrick-kernel/src/census_grandchild.rs"));
        write_source(src.join("census_grandchild.rs"), hidden).unwrap();
        assert!(
            carrick_xtask::authority_debt::verify_source(root.path(), tools_root(), &ceilings(1))
                .is_err(),
            "production reachability must continue beyond one child: {hidden}"
        );
    }
}

#[test]
fn review_production_closure_follows_plain_modules_and_macro_edges() {
    for (shared_file, shared, child_file) in [
        ("shared.rs", "pub mod census_child;", "census_child.rs"),
        (
            "shared.rs",
            "pass! { @ \"census_child.rs\"; }",
            "census_child.rs",
        ),
        (
            "shared.rs",
            "fn launch() { #[path=\"census_child.rs\"] mod child; }",
            "census_child.rs",
        ),
        (
            "shared.rs",
            "items! { #[path=\"census_child.rs\"] mod child; }",
            "census_child.rs",
        ),
        (
            "shared.rs",
            "#[path=\"inline_sources\"] mod inline { pub mod census_child; }",
            "inline_sources/census_child.rs",
        ),
        (
            "nested/entry.rs",
            "pub mod census_child;",
            "nested/entry/census_child.rs",
        ),
    ] {
        let root = source_fixture();
        let src = root.path().join("crates/carrick-kernel/src");
        let child = src.join(child_file);
        let grandchild = child.with_extension("").join("grandchild.rs");
        let grandchild_file = grandchild.strip_prefix(&src).unwrap().to_string_lossy();
        write_source(
            src.join("lib.rs"),
            format!(
                r#"
pass! {{ @ "{shared_file}"; }}
#[cfg(test)] #[path="{shared_file}"] mod tests_copy;
#[cfg(test)] #[path="{child_file}"] mod child_tests_copy;
#[cfg(test)] #[path="{grandchild_file}"] mod grandchild_tests_copy;
pub fn poll(table: &Table) {{ table.read_open_files(); }}
"#
            ),
        )
        .unwrap();
        let shared_path = src.join(shared_file);
        std::fs::create_dir_all(shared_path.parent().unwrap()).unwrap();
        write_source(shared_path, shared).unwrap();
        std::fs::create_dir_all(child.parent().unwrap()).unwrap();
        write_source(child, "pub mod grandchild;").unwrap();
        std::fs::create_dir_all(grandchild.parent().unwrap()).unwrap();
        write_source(&grandchild, "fn data() {}").unwrap();
        assert_dialect_rejection(root.path(), "unresolved source reference in macro input");
        write_source(
            &grandchild,
            "fn hidden(table: &Table) { table.read_open_files(); }",
        )
        .unwrap();
        assert_dialect_rejection(root.path(), "unresolved source reference in macro input");
    }
}

#[test]
fn review_production_closure_converges_without_promoting_test_modules() {
    let root = source_fixture();
    let src = root.path().join("crates/carrick-kernel/src");
    write_source(
        src.join("lib.rs"),
        r#"
pass! { @ "shared.rs"; }
#[cfg(test)] #[path="shared.rs"] mod tests_copy;
pub fn poll(table: &Table) { table.read_open_files(); }
"#,
    )
    .unwrap();
    write_source(
        src.join("shared.rs"),
        r#"
#[path="census_child.rs"] pub mod child;
#[cfg(test)] #[path="only_tests.rs"] mod tests;
"#,
    )
    .unwrap();
    write_source(
        src.join("census_child.rs"),
        "#[path=\"shared.rs\"] pub mod back;",
    )
    .unwrap();
    write_source(
        src.join("only_tests.rs"),
        r#"
pass! { @ "only_tests.rs"; }
fn test(table: &Table) { table.read_open_files(); }
"#,
    )
    .unwrap();
    assert_dialect_rejection(root.path(), "unresolved source reference in macro input");
    let source = std::fs::read_to_string(src.join("lib.rs")).unwrap();
    write_source(
        src.join("lib.rs"),
        source.replace(
            "pass! { @ \"shared.rs\"; }",
            "const SOURCE: &str = include_str!(\"shared.rs\");",
        ),
    )
    .unwrap();
    let error = carrick_xtask::authority_source::SourceCensus::load(root.path()).unwrap_err();
    assert!(
        error.to_string().contains("recursive module graph"),
        "{error}"
    );
}

#[test]
fn review_fail_closed_macro_attributes_cannot_exclude_module_references() {
    let root = source_fixture();
    let src = root.path().join("crates/carrick-kernel/src");
    write_source(
        src.join("lib.rs"),
        r#"
macro_rules! production { (#[cfg(test)] $item:item) => { $item }; }
production! { #[cfg(test)] pub mod hidden; }
#[cfg(test)] #[path="hidden.rs"] mod test_copy;
pub fn poll(table: &Table) { table.read_open_files(); }
"#,
    )
    .unwrap();
    write_source(
        src.join("hidden.rs"),
        "fn hidden(table: &Table) { table.read_open_files(); }",
    )
    .unwrap();
    assert_dialect_rejection(root.path(), "test exclusion in macro input");
}

#[test]
fn review_fail_closed_macro_attributes_cannot_exclude_inline_authority() {
    let root = source_fixture();
    let src = root.path().join("crates/carrick-kernel/src");
    write_source(
        src.join("lib.rs"),
        r#"
macro_rules! production { (#[cfg(test)] $item:item) => { $item }; }
production! { #[cfg(test)] fn hidden(table: &Table) { table.read_open_files(); } }
pub fn poll(table: &Table) { table.read_open_files(); }
"#,
    )
    .unwrap();
    assert_dialect_rejection(root.path(), "test exclusion in macro input");
}

#[test]
fn review_fail_closed_raw_identifier_methods_and_ufcs_are_counted() {
    for call in [
        "table.r#read_open_files()",
        "Table::r#read_open_files(table)",
        "<Table as Access>::r#read_open_files(table)",
    ] {
        let root = source_fixture();
        write_source(
            root.path().join("crates/carrick-kernel/src/lib.rs"),
            format!("pub fn r#poll(table: &Table) {{ {call}; }}"),
        )
        .unwrap();
        let census = carrick_xtask::authority_source::SourceCensus::load(root.path()).unwrap();
        assert_eq!(census.k1.len(), 1, "{call}");
        assert_eq!(census.k1[0].operation, "read_open_files");
        assert_eq!(census.k1[0].owner, "carrick_kernel::poll");
    }
}

#[test]
fn review_fail_closed_raw_identifier_macro_definition_is_guarded() {
    let root = source_fixture();
    write_source(
        root.path().join("crates/carrick-kernel/src/lib.rs"),
        r#"
macro_rules! access { ($table:expr) => { $table.r#read_open_files() }; }
pub fn poll(table: &Table) { table.read_open_files(); }
"#,
    )
    .unwrap();
    assert!(carrick_xtask::authority_source::SourceCensus::load(root.path()).is_err());
}

#[test]
fn review_fail_closed_raw_identifiers_reach_retained_lock_scanner() {
    for call in ["this.proc.r#lock()", "this.r#proc.r#lock()"] {
        let root = source_fixture();
        write_source(root.path().join("crates/carrick-kernel/src/dispatch/mod.rs"), format!("mod sysv; mod mm_authority; mod mm_quiesce; fn r#hidden(this: &Dispatcher) {{ {call}; }}")).unwrap();
        let census = carrick_xtask::authority_source::SourceCensus::load(root.path()).unwrap();
        assert!(!census.is_test_file("crates/carrick-kernel/src/dispatch/mod.rs"));
        assert!(
            carrick_xtask::authority_debt::verify_source(root.path(), tools_root(), &ceilings(1))
                .is_err(),
            "{call}"
        );
    }
}

#[test]
fn review_fail_closed_raw_identifiers_reach_global_and_termination_scanners() {
    for call in [
        r#"std::r#env::r#var("CARRICK_GUEST_STATE")"#,
        "std::r#process::r#abort()",
    ] {
        let root = source_fixture();
        write_source(
            root.path()
                .join("crates/carrick-kernel/src/dispatch/mod.rs"),
            format!("mod sysv; mod mm_authority; mod mm_quiesce; fn hidden() {{ {call}; }}"),
        )
        .unwrap();
        carrick_xtask::authority_source::SourceCensus::load(root.path()).unwrap();
        assert!(
            carrick_xtask::authority_debt::verify_source(root.path(), tools_root(), &ceilings(1))
                .is_err(),
            "{call}"
        );
    }
}

#[test]
fn review_fail_closed_test_include_cycle_does_not_seed_production() {
    let root = source_fixture();
    let src = root.path().join("crates/carrick-kernel/src");
    write_source(
        src.join("lib.rs"),
        "#[cfg(test)] mod a; pub fn poll(table: &Table) { table.read_open_files(); }",
    )
    .unwrap();
    write_source(
        src.join("a.rs"),
        "include!(\"b.rs\"); fn helper(table: &Table) { table.read_open_files(); }",
    )
    .unwrap();
    write_source(
        src.join("b.rs"),
        "const SOURCE: &str = include_str!(\"a.rs\");",
    )
    .unwrap();
    let census = carrick_xtask::authority_source::SourceCensus::load(root.path()).unwrap();
    assert!(census.is_test_file("crates/carrick-kernel/src/a.rs"));
    assert!(census.is_test_file("crates/carrick-kernel/src/b.rs"));
    assert_eq!(census.k1.len(), 1);
    carrick_xtask::authority_debt::verify_source(root.path(), tools_root(), &ceilings(1)).unwrap();
    // An unresolved production literal is rejected, never promoted.
    write_source(src.join("lib.rs"), "#[cfg(test)] mod a; pass! { @ \"b.rs\" } pub fn poll(table: &Table) { table.read_open_files(); }").unwrap();
    write_source(src.join("a.rs"), "include!(\"b.rs\"); fn helper() {}").unwrap();
    assert_dialect_rejection(root.path(), "unresolved source reference in macro input");
    // Production promotion cannot manufacture a logical authority owner.
    write_source(
        src.join("a.rs"),
        "include!(\"b.rs\"); fn helper(table: &Table) { table.read_open_files(); }",
    )
    .unwrap();
    assert!(
        carrick_xtask::authority_debt::verify_source(root.path(), tools_root(), &ceilings(1))
            .is_err()
    );
}

#[test]
fn review_fail_closed_macro_attributes_cannot_hide_retained_authorities() {
    for call in [
        "this.proc.lock()",
        "std::env::var(\"CARRICK_GUEST_STATE\")",
        "std::process::abort()",
    ] {
        let root = source_fixture();
        write_source(
            root.path()
                .join("crates/carrick-kernel/src/dispatch/mod.rs"),
            format!(
                r#"
mod sysv; mod mm_authority; mod mm_quiesce;
macro_rules! production {{ (#[cfg(test)] $item:item) => {{ $item }}; }}
production! {{ #[cfg(test)] fn hidden(this: &Dispatcher) {{ {call}; }} }}
"#
            ),
        )
        .unwrap();
        assert_dialect_rejection(root.path(), "test exclusion in macro input");
        assert!(
            carrick_xtask::authority_debt::verify_source(root.path(), tools_root(), &ceilings(1))
                .is_err(),
            "{call}"
        );
    }
}

#[test]
fn review_fail_closed_opaque_path_attributes_cannot_exclude_default_modules() {
    for (declaration, default_file, selected_file) in [
        (
            r#"#[path="decoy.rs"] pub mod hidden;"#,
            "hidden.rs",
            "decoy.rs",
        ),
        (
            r#"#[path="decoy"] pub mod hidden { pub mod child; }"#,
            "hidden/child.rs",
            "decoy/child.rs",
        ),
    ] {
        let root = source_fixture();
        let src = root.path().join("crates/carrick-kernel/src");
        write_source(
            src.join("lib.rs"),
            format!(
                r#"
macro_rules! production {{ (#[path=$path:literal] $item:item) => {{ $item }}; }}
production! {{ {declaration} }}
#[cfg(test)] #[path="{default_file}"] mod test_copy;
pub fn poll(table: &Table) {{ table.read_open_files(); }}
"#
            ),
        )
        .unwrap();
        for file in [default_file, selected_file] {
            let path = src.join(file);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            write_source(path, "fn data() {}").unwrap();
        }
        assert_dialect_rejection(root.path(), "restricted census dialect");
        write_source(
            src.join(default_file),
            "fn hidden(table: &Table) { table.read_open_files(); }",
        )
        .unwrap();
        assert_dialect_rejection(root.path(), "restricted census dialect");
    }
}

fn git_fixture(root: &std::path::Path, args: &[&str]) -> String {
    let output = std::process::Command::new("git")
        .args(args)
        .current_dir(root)
        .env("GIT_AUTHOR_NAME", "Authority fixture")
        .env("GIT_AUTHOR_EMAIL", "fixture@example.invalid")
        .env("GIT_COMMITTER_NAME", "Authority fixture")
        .env("GIT_COMMITTER_EMAIL", "fixture@example.invalid")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

fn authority_cli_fixture() -> (tempfile::TempDir, String) {
    let root = source_fixture();
    let scripts = root.path().join("scripts/migrate");
    std::fs::create_dir_all(&scripts).unwrap();
    for checker in [
        "check-dispatch-lock-authority.py",
        "check-runtime-global-state.py",
        "check-runtime-aborts.py",
    ] {
        std::os::unix::fs::symlink(
            tools_root().join("scripts/migrate").join(checker),
            scripts.join(checker),
        )
        .unwrap();
    }
    let path = root
        .path()
        .join(carrick_xtask::authority_debt::CEILINGS_PATH);
    std::fs::write(&path, serde_json::to_vec(&ceilings(1)).unwrap()).unwrap();
    git_fixture(root.path(), &["init", "-q"]);
    git_fixture(root.path(), &["add", "."]);
    git_fixture(root.path(), &["commit", "-qm", "baseline"]);
    let base = git_fixture(root.path(), &["rev-parse", "HEAD"]);
    // A coordinated ceiling increase must fail only when a range is supplied.
    std::fs::write(&path, serde_json::to_vec(&ceilings(2)).unwrap()).unwrap();
    git_fixture(root.path(), &["add", "."]);
    git_fixture(root.path(), &["commit", "-qm", "increase ceiling"]);
    git_fixture(
        root.path(),
        &["update-ref", "refs/remotes/github/main", "HEAD"],
    );
    (root, base)
}

fn authority_cli(
    root: &std::path::Path,
    base: Option<&str>,
    env_base: Option<&str>,
    source_only: bool,
) -> std::process::Output {
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_carrick-xtask"));
    cmd.args(["--root", root.to_str().unwrap(), "authority-debt"]);
    cmd.env_remove("CARRICK_AUTHORITY_BASE");
    if let Some(base) = base {
        cmd.args(["--base", base]);
    }
    if let Some(base) = env_base {
        cmd.env("CARRICK_AUTHORITY_BASE", base);
    }
    if source_only {
        cmd.arg("--source-only");
    }
    cmd.output().unwrap()
}

fn assert_one_authority_skip(output: &std::process::Output) {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let skip: Vec<_> = stdout
        .lines()
        .chain(stderr.lines())
        .filter(|line| line.contains("no change range"))
        .collect();
    assert_eq!(
        skip,
        ["authority debt delta: no change range (no base provided); delta ratchet not applicable"]
    );
    assert!(!stdout.contains("PR-base ratchet passed"));
}

#[test]
fn review_no_change_range_skips_only_ratchet_and_enforces_absolute_ceilings() {
    let (root, base) = authority_cli_fixture();
    for absent in [None, Some(""), Some("   ")] {
        let output = authority_cli(root.path(), None, absent, true);
        assert!(output.status.success(), "{output:?}");
        assert_one_authority_skip(&output);
    }
    let output = authority_cli(root.path(), Some(""), None, true);
    assert!(output.status.success(), "{output:?}");
    assert_one_authority_skip(&output);
    for (explicit, environment) in [
        (Some(base.as_str()), None),
        (None, Some(base.as_str())),
        (Some(""), Some(base.as_str())),
    ] {
        let output = authority_cli(root.path(), explicit, environment, true);
        assert!(!output.status.success());
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("increase"),
            "{output:?}"
        );
        assert!(!String::from_utf8_lossy(&output.stdout).contains("no change range"));
    }
    std::fs::write(
        root.path()
            .join(carrick_xtask::authority_debt::CEILINGS_PATH),
        serde_json::to_vec(&ceilings(0)).unwrap(),
    )
    .unwrap();
    let output = authority_cli(root.path(), None, Some(""), true);
    assert!(!output.status.success());
    assert_one_authority_skip(&output);
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("exceeds ceiling"),
        "{output:?}"
    );
}

#[test]
fn review_explicit_self_comparison_and_invalid_base_fail_closed() {
    let (root, _) = authority_cli_fixture();
    for base in ["HEAD", "github/main", "missing-revision"] {
        let output = authority_cli(root.path(), Some(base), None, true);
        assert!(
            !output.status.success(),
            "explicit {base} must fail: {output:?}"
        );
        assert!(!String::from_utf8_lossy(&output.stdout).contains("no change range"));
    }
}

#[test]
fn review_no_change_range_still_applies_live_host_ceilings() {
    let (root, _) = authority_cli_fixture();
    let mut policy = ceilings(2);
    policy.counters.push(Counter {
        family: Family::HostForbiddenSemantic,
        operation: "std::process::id".into(),
        owner: "carrick_kernel::poll".into(),
        lane: Lane::LinuxCli,
        ceiling: 0,
    });
    std::fs::write(
        root.path()
            .join(carrick_xtask::authority_debt::CEILINGS_PATH),
        serde_json::to_vec(&policy).unwrap(),
    )
    .unwrap();
    // A fixture diagnostic checks the full CLI dispatch and policy consumer;
    // live_linux_breaker_alias_macro_and_cfg_cannot_use_stored_evidence above
    // separately proves actual compiler discovery and owner binding.
    std::fs::write(root.path().join("scripts/migrate/check-host-authority-transitions.py"), r#"
import json
print(json.dumps({"rows": [{"source": {"file": "crates/carrick-kernel/src/lib.rs", "line_start": 1, "column_start": 1}, "operation": "std::process::id", "profiles": ["linux-cli"]}]}))
"#).unwrap();
    for base in [None, Some("")] {
        let output = authority_cli(root.path(), None, base, false);
        assert!(!output.status.success());
        assert_one_authority_skip(&output);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("exceeds ceiling 0") && stderr.contains("std::process::id"),
            "{output:?}"
        );
    }
}

#[test]
fn review_macos_census_checkout_fetches_the_event_base() {
    let source = std::fs::read_to_string(tools_root().join(".github/workflows/ci.yml")).unwrap();
    let workflow = yaml_rust2::YamlLoader::load_from_str(&source).unwrap();
    for job in ["lint", "macos-clippy"] {
        let steps = workflow[0]["jobs"][job]["steps"].as_vec().unwrap();
        let checkout = steps
            .iter()
            .find(|step| {
                step["uses"]
                    .as_str()
                    .is_some_and(|uses| uses.starts_with("actions/checkout@"))
            })
            .unwrap();
        assert_eq!(checkout["with"]["fetch-depth"].as_i64(), Some(0), "{job}");
        assert!(
            steps
                .iter()
                .any(|step| step["run"].as_str() == Some("just ci-probe-coverage-base")),
            "{job} must fetch the actual event base"
        );
    }
}

#[test]
fn restricted_dialect_inline_literal_path_uses_inline_directory() {
    let root = source_fixture();
    let src = root.path().join("crates/carrick-kernel/src");
    std::fs::create_dir_all(src.join("parent")).unwrap();
    write_source(
        src.join("lib.rs"),
        r#"mod parent { #[path="selected.rs"] mod child; }
#[cfg(test)] #[path="parent/selected.rs"] mod test_copy;"#,
    )
    .unwrap();
    write_source(
        src.join("parent/selected.rs"),
        "fn access(table: &Table) { table.read_open_files(); }",
    )
    .unwrap();
    let census = carrick_xtask::authority_source::SourceCensus::load(root.path()).unwrap();
    assert_eq!(census.k1.len(), 1);
    assert_eq!(census.k1[0].owner, "carrick_kernel::parent::child::access");
    assert!(!census.is_test_file("crates/carrick-kernel/src/parent/selected.rs"));
}

#[test]
fn restricted_dialect_test_scope_glob_cannot_exclude_production() {
    let root = source_fixture();
    let src = root.path().join("crates/carrick-kernel/src");
    write_source(src.join("lib.rs"), "#[cfg(test)] mod tests { use tracing::*; #[test] fn helper(table: &Table) { table.read_open_files(); } } pub fn poll(table: &Table) { table.read_open_files(); }").unwrap();
    let census = carrick_xtask::authority_source::SourceCensus::load(root.path()).unwrap();
    assert_eq!(census.k1.len(), 1);
    assert_eq!(census.k1[0].owner, "carrick_kernel::poll");
    carrick_xtask::authority_debt::verify_source(root.path(), tools_root(), &ceilings(1)).unwrap();
}

#[test]
fn restricted_dialect_type_alias_chain_cannot_rename_authority() {
    restricted_dialect_error(
        "type Hidden = OpenDescriptionRef; type Other = Hidden; use Other as R; fn hidden(x: X) { R::clone(x); }",
        "renamed protected import Other as R",
    );
}

#[test]
fn restricted_dialect_audited_attributes_do_not_allow_authority_or_blocks() {
    for source in [
        "#[error(\"bad\", table.read_open_files())] struct Error;",
        "#[error(\"bad\", { std::process::abort(); })] struct Error;",
        "#[arg(default_value_t = { std::env::var(\"X\") })] struct Args;",
        "#[arg(default_value_t = std::process::abort())] struct Args;",
    ] {
        restricted_dialect_error(source, "unaudited attribute arguments");
    }
}

#[test]
fn restricted_dialect_schema_base_never_enters_legacy_census() {
    let (root, _) = authority_cli_fixture();
    let policy = root
        .path()
        .join(carrick_xtask::authority_debt::CEILINGS_PATH);
    std::fs::write(&policy, serde_json::to_vec(&ceilings(1)).unwrap()).unwrap();
    let lib = root.path().join("crates/carrick-kernel/src/lib.rs");
    write_source(&lib, "not rust at all").unwrap();
    git_fixture(root.path(), &["add", "."]);
    git_fixture(
        root.path(),
        &["commit", "-qm", "schema base with unreadable source"],
    );
    let base = git_fixture(root.path(), &["rev-parse", "HEAD"]);
    write_source(
        &lib,
        "pub fn poll(table: &Table) { table.read_open_files(); }",
    )
    .unwrap();
    git_fixture(root.path(), &["add", "."]);
    git_fixture(root.path(), &["commit", "-qm", "strict working source"]);
    let output = authority_cli(root.path(), Some(&base), None, true);
    assert!(output.status.success(), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stdout).contains("PR-base ratchet passed"));
    write_source(&lib, "use tracing::instrument as test; #[test] fn poll(table: &Table) { table.read_open_files(); }").unwrap();
    let output = authority_cli(root.path(), Some(&base), None, true);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("import may rebind built-in test"));
}

#[test]
fn restricted_dialect_external_test_scope_proof_never_overrides_production() {
    let root = source_fixture();
    let src = root.path().join("crates/carrick-kernel/src");
    write_source(
        src.join("lib.rs"),
        "#[cfg(test)] mod tests; pub fn poll(table: &Table) { table.read_open_files(); }",
    )
    .unwrap();
    write_source(
        src.join("tests.rs"),
        "use tracing::*; #[test] fn helper(table: &Table) { table.read_open_files(); }",
    )
    .unwrap();
    carrick_xtask::authority_debt::verify_source(root.path(), tools_root(), &ceilings(1)).unwrap();
    write_source(src.join("lib.rs"), "#[cfg(test)] mod tests; const SOURCE: &str = include_str!(\"tests.rs\"); pub fn poll(table: &Table) { table.read_open_files(); }").unwrap();
    assert_dialect_rejection(root.path(), "glob import makes test exclusion ambiguous");
}

#[test]
fn restricted_dialect_attribute_audits_cannot_hide_callbacks_or_unknown_derives() {
    restricted_dialect_error(
        "#[serde(default = \"std::process::abort\")] struct Data;",
        "protected callback in audited attribute metadata",
    );
    restricted_dialect_error(
        "#[derive(Unknown)] struct Data;",
        "unaudited derive macro Unknown",
    );
    restricted_dialect_error(
        "#[unknown] fn helper() {}",
        "unaudited attribute macro unknown",
    );
    restricted_dialect_error(
        "use serde::Serialize; use unknown::Serialize; #[derive(Serialize)] struct Data;",
        "import may rebind an audited derive macro",
    );
    restricted_dialect_error(
        "use unknown::serde; #[derive(serde::Serialize)] struct Data;",
        "import may rebind an audited macro provider",
    );
}

#[test]
fn restricted_dialect_final_production_closure_rejects_descendant_attributes() {
    let root = source_fixture();
    let src = root.path().join("crates/carrick-kernel/src");
    write_source(src.join("lib.rs"), "const SOURCE: &[u8] = include_bytes!(\"shared.rs\"); #[cfg(test)] #[path=\"shared.rs\"] mod test_copy; pub fn poll(table: &Table) { table.read_open_files(); }").unwrap();
    write_source(src.join("shared.rs"), "#[path=\"child.rs\"] mod child;").unwrap();
    write_source(src.join("child.rs"), "#[tracing::instrument(fields(count = table.read_open_files().len()))] fn hidden(table: &Table) {}").unwrap();
    assert_dialect_rejection(root.path(), "unaudited attribute macro tracing::instrument");
}

#[test]
fn restricted_dialect_globs_cannot_rebind_audited_macros() {
    for source in [
        "use external::*; #[usdt::provider] mod probes {}",
        "use external::*; #[derive(serde::Serialize)] struct Data;",
        "use external::*; #[error(\"bad\")] fn helper() {}",
    ] {
        restricted_dialect_error(source, "glob import makes audited macro binding ambiguous");
    }
}

#[test]
fn restricted_dialect_absolute_providers_prove_helpers_despite_globs() {
    let root = source_fixture();
    let src = root.path().join("crates/carrick-kernel/src");
    write_source(src.join("lib.rs"), "use external::*; #[derive(::serde::Serialize)] #[serde(rename = \"Data\")] struct Data { #[serde(skip)] value: usize } #[::usdt::provider] mod probes {}").unwrap();
    let census = carrick_xtask::authority_source::SourceCensus::load(root.path()).unwrap();
    assert!(census.k1.is_empty());
    for source in [
        "#[derive(::serde::Serialize)] #[error(\"bad\")] struct Data;",
        "pass! { #[derive(::serde::Serialize)] #[serde(rename = \"Data\")] struct Data; }",
    ] {
        restricted_dialect_error(source, "unresolved derive helper");
    }
}

#[test]
fn restricted_dialect_external_module_selection_is_rejected() {
    let root = source_fixture();
    let src = root.path().join("crates/carrick-kernel/src");
    std::fs::create_dir_all(src.join("parent")).unwrap();
    write_source(
        src.join("lib.rs"),
        r#"
macro_rules! retirement_wrap_module { ($item:item) => { mod parent { $item } }; }
retirement_wrap_module! { mod hidden; }
#[cfg(test)] #[path="parent/hidden.rs"] mod test_copy;
"#,
    )
    .unwrap();
    write_source(src.join("hidden.rs"), "fn harmless() {}").unwrap();
    write_source(
        src.join("parent/hidden.rs"),
        "fn hidden(table: &Table) { table.read_open_files(); }",
    )
    .unwrap();
    assert_dialect_rejection(
        root.path(),
        "module selection in macro input is unsupported",
    );
    for declaration in [
        "macro_rules! pass { (@ $item:item) => { $item }; } pass! { @ mod hidden; }",
        "macro_rules! retirement_bind_module { ($name:ident) => { mod $name; }; } retirement_bind_module!(hidden);",
    ] {
        let root = source_fixture();
        let src = root.path().join("crates/carrick-kernel/src");
        write_source(
            src.join("lib.rs"),
            format!("{declaration}\n#[cfg(test)] #[path=\"hidden.rs\"] mod test_copy;"),
        )
        .unwrap();
        write_source(
            src.join("hidden.rs"),
            "fn hidden(table: &Table) { table.read_open_files(); }",
        )
        .unwrap();
        assert_dialect_rejection(
            root.path(),
            "module selection in macro input is unsupported",
        );
    }
}

#[test]
fn review_restricted_macro_use_test_binding_is_rejected() {
    for import in [
        "#[macro_use(test)] extern crate custom_test;",
        "#[macro_use] extern crate custom_test;",
    ] {
        restricted_dialect_error(
            &format!(
                "{import} #[test] fn hidden(table: &Table) {{ table.read_open_files(); this.proc.lock(); std::process::abort(); }}"
            ),
            "macro_use import is unresolved",
        );
    }
}

#[test]
fn review_restricted_sensitive_self_glob_and_calls_are_rejected() {
    for source in [
        "use std::process::{self}; fn hidden() { process::abort(); }",
        "use std::env::*; fn hidden() { var(\"CARRICK_RUN_ID\"); }",
        "use std::process::*; fn hidden() { abort(); }",
        "use std::env::{self}; fn hidden() { env::var(\"CARRICK_RUN_ID\"); }",
        "fn hidden() { var(\"CARRICK_RUN_ID\"); }",
        "fn hidden() { abort(); }",
        "fn hidden() { (abort)(); }",
        "fn hidden() { (var)(\"CARRICK_RUN_ID\"); }",
    ] {
        restricted_dialect_error(source, "canonical path");
    }
}

#[test]
fn review_restricted_clap_environment_metadata_is_rejected() {
    for helper in ["arg", "clap"] {
        restricted_dialect_error(
            &format!(
                "#[derive(::clap::Parser)] struct Data {{ #[{helper}(long, env = \"CARRICK_RUN_ID\")] run: String }}"
            ),
            "generated environment read",
        );
    }
}

#[test]
fn review_restricted_compiler_derive_bindings_are_rejected() {
    for source in [
        "use custom_derive::Clone; #[derive(Clone)] struct Data;",
        "use custom_derive::Other as Clone; #[derive(Clone)] struct Data;",
        "use custom_derive::Clone as Other; #[derive(Other)] struct Data;",
        "#[macro_use(Clone)] extern crate custom_derive; #[derive(Clone)] struct Data;",
        "use custom_derive::*; #[derive(Clone)] struct Data;",
    ] {
        restricted_dialect_error(source, "restricted census dialect");
    }
}

#[test]
fn review_generated_metadata_requires_the_declared_owner() {
    use carrick_xtask::authority_source::SourceCensus;
    let root = source_fixture();
    let cli = root.path().join("crates/carrick-cli/src");
    std::fs::create_dir_all(&cli).unwrap();
    write_source(cli.join("main.rs"), "mod args;").unwrap();
    write_source(
        cli.join("args.rs"),
        r#"#[derive(::clap::Parser)] struct Cli { #[arg(env="CARRICK_HOME")] home: String }"#,
    )
    .unwrap();
    SourceCensus::load(root.path()).unwrap();
    write_source(
        root.path().join("crates/carrick-kernel/src/lib.rs"),
        r#"#[path="../../carrick-cli/src/args.rs"] mod injected;"#,
    )
    .unwrap();
    assert_dialect_rejection(root.path(), "generated environment read");
}

#[test]
fn review_verdict_records_item_scope_and_rejects_changed_inputs() {
    use carrick_xtask::authority_source::SourceCensus;
    let root = source_fixture();
    let file = "crates/carrick-kernel/src/lib.rs";
    write_source(
        root.path().join(file),
        "#[cfg(test)] fn hidden() { this.proc.lock(); } fn shown() { this.proc.lock(); }",
    )
    .unwrap();
    let source = SourceCensus::load(root.path()).unwrap();
    let verdict = source.verdict(root.path()).unwrap();
    assert_eq!(verdict["dialect"], "strict");
    assert_eq!(verdict["rejections"], serde_json::json!([]));
    let items = verdict["files"][file]["items"].as_array().unwrap();
    assert!(items.iter().any(|i| i["production"] == false));
    assert!(items.iter().any(|i| i["production"] == true));
    write_source(root.path().join(file), "fn changed() {}").unwrap();
    assert!(
        source
            .verdict(root.path())
            .unwrap_err()
            .to_string()
            .contains("source changed during census")
    );
}

#[test]
fn review_retained_verdict_transport_exceeds_one_argument() {
    let root = source_fixture();
    let mut source = "pub fn poll(table: &Table) { table.read_open_files(); }\n".to_owned();
    for index in 0..5000 {
        source.push_str(&format!("fn helper_{index}() {{}}\n"));
    }
    write_source(root.path().join("crates/carrick-kernel/src/lib.rs"), source).unwrap();
    let census = carrick_xtask::authority_source::SourceCensus::load(root.path()).unwrap();
    let proof = serde_json::to_vec(&census.verdict(root.path()).unwrap()).unwrap();
    assert!(
        proof.len() > 131_072,
        "fixture must exceed Linux's single-argument limit"
    );
    carrick_xtask::authority_debt::verify_source(root.path(), tools_root(), &ceilings(1)).unwrap();
}
