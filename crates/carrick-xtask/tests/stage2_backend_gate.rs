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
    // Each wrapper reaches the backend once, through the trait.
    let backend_calls = count(&sources, "HvfStage2.map(")
        + count(&sources, "HvfStage2.unmap(")
        + count(&sources, "HvfStage2.destroy()");
    assert_eq!(
        backend_calls, 3,
        "only the three inventory wrappers may call the HVF backend"
    );
    // Both lazy replay paths resolve and map under Stage2Custody's generation guard.
    assert_eq!(
        count(&sources, "stage2_map_replay(custody, expected_generation")
            + count(&sources, "stage2_map_replay(&custody, expected_generation"),
        2,
        "both lazy replay paths must use exact generation-guarded serialized replay"
    );
    assert_eq!(
        count(&sources, "pub(crate) unsafe fn inventory_stage2_")
            + count(&sources, "pub(crate) fn inventory_stage2_")
            + count(&sources, "unmap_global_frame_stage2_record"),
        0,
        "raw stage-2 wrappers and unguarded global-frame unmap must not escape stage2_backend.rs"
    );
    // VM destruction stays a custody transaction: the carrier backend is
    // built once, inside the custody that owns it, so its raw destroy is
    // reachable only through the custody's generation guard.
    assert_eq!(
        count(&sources, concat!("inventory_stage2_", "destroy")),
        0,
        "the free stage-2 destroy wrapper is gone; destroy through Stage2Custody"
    );
    assert_eq!(
        count(&sources, concat!("HvfCarrierStage2::", "custody_backend()")),
        1,
        "only CarrierVmCustody may own the carrier stage-2 backend"
    );
}
