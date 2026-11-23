//! The HVF stage-2 calls go through `carrick_aarch64::stage2::Stage2Backend`
//! (#2814, step S0 of the staged custody move).
//!
//! `carrick-vmm-hvf` compiles only for macOS on aarch64, so these source
//! gates run here, on every Linux CI lane, instead of beside the code.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};

fn workspace() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn rust_sources(dir: &Path, out: &mut Vec<(PathBuf, String)>) {
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .unwrap_or_else(|error| panic!("read {}: {error}", dir.display()))
        .map(|entry| entry.unwrap().path())
        .collect();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            rust_sources(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            let source = std::fs::read_to_string(&path).unwrap();
            out.push((path, source));
        }
    }
}

fn hvf_sources() -> Vec<(PathBuf, String)> {
    let mut out = Vec::new();
    rust_sources(&workspace().join("crates/carrick-vmm-hvf/src"), &mut out);
    assert!(out.len() > 50, "carrick-vmm-hvf sources not found");
    out
}

fn count(sources: &[(PathBuf, String)], needle: &str) -> usize {
    sources
        .iter()
        .map(|(_, source)| source.matches(needle).count())
        .sum()
}

/// The body of HVF's `Stage2Backend` implementation.
fn hvf_backend_impl(sources: &[(PathBuf, String)]) -> String {
    let header = "impl carrick_aarch64::stage2::Stage2Backend for HvfStage2 {";
    let (_, source) = sources
        .iter()
        .find(|(path, _)| path.ends_with("trap/stage2_backend.rs"))
        .expect("trap/stage2_backend.rs");
    source
        .split(header)
        .nth(1)
        .and_then(|tail| tail.split("\n}\n").next())
        .unwrap_or_else(|| panic!("stage2_backend.rs must hold `{header}`"))
        .to_owned()
}

#[test]
fn raw_hvf_stage2_calls_live_only_in_the_backend_impl() {
    let sources = hvf_sources();
    let backend = hvf_backend_impl(&sources);
    for call in ["map(", "unmap(", "destroy()"] {
        let raw = format!("applevisor_sys::hv_vm_{call}");
        assert_eq!(
            count(&sources, &raw),
            1,
            "raw `{raw}` must appear exactly once in carrick-vmm-hvf"
        );
        assert_eq!(
            backend.matches(&raw).count(),
            1,
            "raw `{raw}` must be inside `impl Stage2Backend for HvfStage2`"
        );
    }
}

/// Custody speaks neutral permissions: `carrick_hal::MemPerms`, or the
/// recorded word through `carrick_aarch64::stage2`. Only the HVF backend
/// module converts them to applevisor's enum for the host call (#2814, S0b).
#[test]
fn applevisor_permissions_live_only_in_the_backend_module() {
    let sources = hvf_sources();
    let applevisor_perms = concat!("applevisor::memory::", "MemPerms");
    let outside: Vec<_> = sources
        .iter()
        .filter(|(path, source)| {
            !path.ends_with("trap/stage2_backend.rs") && source.contains(applevisor_perms)
        })
        .map(|(path, source)| {
            format!(
                "{} ({})",
                path.display(),
                source.matches(applevisor_perms).count()
            )
        })
        .collect();
    assert!(
        outside.is_empty(),
        "custody must hold `carrick_hal::MemPerms` or the recorded stage-2 word, \
         never `{applevisor_perms}`, outside trap/stage2_backend.rs: {outside:?}"
    );
}

#[test]
fn custody_names_no_hvf_vcpu_types() {
    let sources = hvf_sources();
    let mut raw = Vec::new();
    for (path, source) in &sources {
        let custody =
            if path.ends_with("trap/carrier_custody.rs") || path.ends_with("trap/cow_engine.rs") {
                source.as_str()
            } else if path.ends_with("trap.rs") {
                source
                    .split_once("enum PersistentCarrierCellEntry {")
                    .and_then(|(_, body)| body.split_once("\n}"))
                    .map(|(body, _)| body)
                    .and_then(|body| body.split_once("CreateCleanup {"))
                    .and_then(|(_, variant)| variant.split_once("\n    }"))
                    .map(|(variant, _)| variant)
                    .expect("PersistentCarrierCellEntry::CreateCleanup")
            } else {
                continue;
            };
        for name in [
            "applevisor_sys::hv_vcpu_t",
            "applevisor_sys::hv_return_t",
            "applevisor::vcpu::Vcpu",
        ] {
            let occurrences = custody.matches(name).count();
            if occurrences != 0 {
                raw.push(format!("{}: {name} ({occurrences})", path.display()));
            }
        }
    }
    assert!(raw.is_empty(), "HVF vCPU types in custody: {raw:?}");
}

/// A stage-2 map or destroy that custody takes as a closure returns
/// `carrick_aarch64::stage2::Stage2Status`, the backend's status, never a
/// bare integer or applevisor's `hv_return_t` (#2814, S0b).
#[test]
fn custody_stage2_closures_return_the_neutral_status() {
    let sources = hvf_sources();
    let raw_returns = ["i32", "applevisor_sys::hv_return_t", "hv_return_t"];
    let mut raw = Vec::new();
    for (path, source) in &sources {
        for (index, line) in source.lines().enumerate() {
            let Some((_, ret)) = line
                .split_once("impl Fn")
                .and_then(|(_, tail)| tail.rsplit_once("->"))
            else {
                continue;
            };
            let ret = ret.trim().trim_end_matches(',').trim();
            if raw_returns.contains(&ret) {
                raw.push(format!("{}:{}: {}", path.display(), index + 1, line.trim()));
            }
        }
    }
    assert!(
        raw.is_empty(),
        "stage-2 closures must return `Stage2Status`, not a raw integer: {raw:?}"
    );
}

#[test]
fn custody_reaches_stage2_only_through_the_inventory_wrappers() {
    let sources = hvf_sources();
    let old_wrappers = concat!("inventory_hv_", "vm_");
    let stale: Vec<_> = sources
        .iter()
        .filter(|(_, source)| source.contains(old_wrappers))
        .map(|(path, _)| path.display().to_string())
        .collect();
    assert!(
        stale.is_empty(),
        "the HVF-named stage-2 wrappers are gone; use `inventory_stage2_*`: {stale:?}"
    );
    let (_, backend) = sources
        .iter()
        .find(|(path, _)| path.ends_with("trap/stage2_backend.rs"))
        .expect("trap/stage2_backend.rs");
    for (wrapper, call) in [
        ("inventory_stage2_map", "backend.map("),
        ("inventory_stage2_map_replay", "inventory_stage2_map("),
        ("inventory_stage2_unmap", "backend.unmap("),
        ("inventory_stage2_destroy", "backend.destroy()"),
    ] {
        let header = format!("fn {wrapper}(");
        let (_, wrapper_body) = backend.split_once(&header).expect("wrapper definition");
        let (wrapper_body, _) = wrapper_body.split_once("\n}").expect("wrapper end");
        assert_eq!(
            wrapper_body.matches(call).count(),
            1,
            "{wrapper} calls {call}"
        );
    }
    // Both lazy replay paths keep the exact serialized replay.
    for backend in ["custody", "self.stage2.custody()"] {
        let call = format!("inventory_stage2_map_replay({backend}.stage2_backend(), b)");
        assert_eq!(
            count(&sources, &call),
            1,
            "missing lazy replay through {backend}"
        );
    }
    // VM destruction stays a custody transaction.
    assert_eq!(
        count(&sources, concat!("inventory_stage2_", "destroy(")),
        2,
        "inventory_stage2_destroy must appear only in its definition and the custody wrapper"
    );
}

fn struct_fields(source: &str, name: &str) -> Vec<String> {
    let header = format!("struct {name} {{");
    let (_, body) = source
        .split_once(&header)
        .unwrap_or_else(|| panic!("missing {header}"));
    let (body, _) = body.split_once("\n}").expect("unclosed struct body");
    body.lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.starts_with('/') || line.starts_with('#') {
                return None;
            }
            let (declaration, _) = line.split_once(':')?;
            Some(declaration.split_whitespace().last()?.to_owned())
        })
        .collect()
}

#[test]
fn hvf_task_state_owns_custody_through_stage2_state() {
    let hvf = workspace().join("crates/carrick-vmm-hvf/src");
    let task_source = std::fs::read_to_string(hvf.join("trap.rs")).unwrap();
    let task_fields = struct_fields(&task_source, "HvfTaskState");
    let custody_fields = [
        "custody",
        "mappings",
        "mm_root_slot",
        "container_root",
        "pending_exec_mm_root_slot",
        "pending_exec_asid",
        "pending_exec_predecessor_identity",
        "pending_exec_stage2_cleanup",
        "shared_process_mm",
        "mm_access",
        "persistent_vm_lifecycle",
        "cow_authority",
        "cow_identity",
        "pending_fork_frame_receipts",
        "pending_process_aliases",
        "cow_rollback_scratch",
        "fail_next_begin_exec_inventory",
    ];
    for field in custody_fields {
        assert!(
            !task_fields.iter().any(|name| name == field),
            "HvfTaskState still declares custody field {field}"
        );
    }
    let stage2_source = std::fs::read_to_string(hvf.join("trap/stage2_state.rs")).unwrap();
    let stage2_fields = struct_fields(&stage2_source, "Stage2State");
    assert_eq!(stage2_fields.len(), custody_fields.len());
    for field in custody_fields {
        assert!(
            stage2_fields.iter().any(|name| name == field),
            "Stage2State must declare custody field {field}"
        );
    }
}

/// The parameter list of `fn <name>(` in `source`, up to its return arrow.
fn fn_params<'a>(source: &'a str, name: &str) -> Option<&'a str> {
    let header = format!("fn {name}(");
    let tail = source.split(header.as_str()).nth(1)?;
    tail.split_once(") ->").map(|(params, _)| params)
}

/// The stage-2 inventory wrappers reach the backend that the carrier VM's
/// custody holds, never the HVF unit struct by name, so the soft VM can hand
/// its own backend to the same custody code (#1236, M2b of the custody move).
#[test]
fn inventory_wrappers_reach_the_held_backend() {
    let sources = hvf_sources();
    let (_, backend_source) = sources
        .iter()
        .find(|(path, _)| path.ends_with("trap/stage2_backend.rs"))
        .expect("trap/stage2_backend.rs");
    let by_name: Vec<_> = ["HvfStage2.map(", "HvfStage2.unmap(", "HvfStage2.destroy()"]
        .into_iter()
        .filter(|call| count(&sources, call) > 0)
        .collect();
    assert!(
        by_name.is_empty(),
        "the inventory wrappers must call the held `&dyn Stage2Backend`, not {by_name:?}"
    );
    for wrapper in [
        "inventory_stage2_map",
        "inventory_stage2_map_replay",
        "inventory_stage2_unmap",
        "inventory_stage2_destroy",
    ] {
        let params = fn_params(backend_source, wrapper)
            .unwrap_or_else(|| panic!("trap/stage2_backend.rs must define `fn {wrapper}(`"));
        assert!(
            params.contains("dyn ") && params.contains("Stage2Backend"),
            "`{wrapper}` must take the backend as `&dyn Stage2Backend`, has ({params})"
        );
    }
    // Outside its own definition and trait impl, the HVF backend is named
    // only where the carrier VM's custody is built.
    let named_elsewhere: Vec<_> = sources
        .iter()
        .filter(|(path, _)| !path.ends_with("trap/carrier_custody.rs"))
        .flat_map(|(path, source)| {
            source
                .lines()
                .enumerate()
                .filter(|(_, line)| {
                    line.contains("HvfStage2")
                        && !line.contains("struct HvfStage2;")
                        && !line.contains("Stage2Backend for HvfStage2 {")
                        && !line.trim_start().starts_with("//")
                })
                .map(move |(index, line)| {
                    format!("{}:{}: {}", path.display(), index + 1, line.trim())
                })
        })
        .collect();
    assert!(
        named_elsewhere.is_empty(),
        "only trap/carrier_custody.rs may build the HVF backend: {named_elsewhere:?}"
    );
}

/// Tests run custody on the production path: `Stage2State` holds its
/// carrier VM's custody in every build, and no process-wide test custody
/// stands in for it, so parallel tests stop sharing one stage-2 record table
/// (#1236, M2c of the custody move).
#[test]
fn stage2_state_holds_its_custody_in_tests_too() {
    let sources = hvf_sources();
    let (_, stage2_source) = sources
        .iter()
        .find(|(path, _)| path.ends_with("trap/stage2_state.rs"))
        .expect("trap/stage2_state.rs");
    let (_, after_header) = stage2_source
        .split_once("struct Stage2State {")
        .expect("trap/stage2_state.rs must define `struct Stage2State`");
    let declares_custody = |line: &str| {
        let line = line.trim_start();
        let line = line
            .strip_prefix("pub(crate) ")
            .or_else(|| line.strip_prefix("pub(super) "))
            .unwrap_or(line);
        line.starts_with("custody:")
    };
    assert!(
        after_header.lines().any(declares_custody),
        "`Stage2State` must declare `custody`"
    );
    let custody_decl: Vec<&str> = after_header
        .lines()
        .take_while(|line| !declares_custody(line))
        .collect();
    let gated = custody_decl
        .iter()
        .rev()
        .take_while(|line| {
            let line = line.trim_start();
            line.starts_with('#') || line.starts_with("///")
        })
        .any(|line| line.contains("cfg("));
    assert!(
        !gated,
        "`Stage2State::custody` must exist in every build, not behind a cfg"
    );
    for accessor in ["custody", "custody_arc"] {
        let body = stage2_source
            .split_once(format!("fn {accessor}(").as_str())
            .and_then(|(_, tail)| tail.split_once("\n    }\n"))
            .map(|(body, _)| body)
            .unwrap_or_else(|| panic!("trap/stage2_state.rs must define `fn {accessor}(`"));
        assert!(
            !body.contains("cfg(test)") && !body.contains("cfg(not(test))"),
            "`Stage2State::{accessor}..)` must read the held custody in tests too"
        );
    }
    let legacy = count(&sources, "legacy_test_carrier_vm_custody");
    assert_eq!(
        legacy, 0,
        "test fixtures must own their custody; `legacy_test_carrier_vm_custody` is named {legacy} times"
    );
}
