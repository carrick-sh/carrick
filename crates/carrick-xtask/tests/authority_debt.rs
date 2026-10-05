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
