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

/// A stage-2 map or destroy that custody takes as a closure returns
/// `carrick_aarch64::stage2::Stage2Status`, the backend's status, never a
/// bare integer or applevisor's `hv_return_t` (#2814, S0b). vCPU operations
/// (closures over `hv_vcpu_t`) move behind their own type in the next layer.
#[test]
fn custody_stage2_closures_return_the_neutral_status() {
    let sources = hvf_sources();
    let raw_returns = ["i32", "applevisor_sys::hv_return_t", "hv_return_t"];
    let mut raw = Vec::new();
    for (path, source) in &sources {
        for (index, line) in source.lines().enumerate() {
            let Some((params, ret)) = line
                .split_once("impl Fn")
                .and_then(|(_, tail)| tail.rsplit_once("->"))
            else {
                continue;
            };
            if params.contains("hv_vcpu_t") {
                continue;
            }
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
    // Each wrapper reaches the backend once, through the trait.
    let backend_calls = count(&sources, "HvfStage2.map(")
        + count(&sources, "HvfStage2.unmap(")
        + count(&sources, "HvfStage2.destroy()");
    assert_eq!(
        backend_calls, 3,
        "only the three inventory wrappers may call the HVF backend"
    );
    // Both lazy replay paths keep the exact serialized replay.
    assert_eq!(
        count(&sources, concat!("inventory_stage2_map_replay", "(b)")),
        2,
        "both lazy replay paths must use exact serialized replay"
    );
    // VM destruction stays a custody transaction: the wrapper's definition
    // and the custody transaction's one call.
    assert_eq!(
        count(&sources, concat!("inventory_stage2_", "destroy()")),
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
