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
    let census = carrick_xtask::authority_source::SourceCensus::load(root.path()).unwrap();
    assert_eq!(census.k1.len(), 1);
    assert_eq!(census.k1[0].owner, "carrick_kernel::access::inner");
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
    let census = carrick_xtask::authority_source::SourceCensus::load(root.path()).unwrap();
    assert_eq!(census.k1.len(), 1);
    assert_eq!(census.k1[0].owner, "carrick_kernel::access");
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
    let census = carrick_xtask::authority_source::SourceCensus::load(root.path()).unwrap();
    assert!(!census.is_test_at("crates/carrick-kernel/src/shared.rs", 1, 0));
    assert!(
        census
            .k1
            .iter()
            .any(|site| site.owner == "carrick_kernel::hidden")
    );
    assert!(
        carrick_xtask::authority_debt::verify_source(root.path(), tools_root(), &ceilings(1))
            .is_err()
    );
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
    assert!(error.contains("unknown authority"), "{error}");
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
    assert!(error.contains("nonliteral source inclusion"), "{error}");
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
