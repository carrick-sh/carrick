//! `--debug-state-path` guest-layout snapshots.
//!
//! Platform-NEUTRAL (moved out of the macOS-only `runtime.rs` arm): a
//! JSON-serialisable snapshot of the guest layout a run is about to execute,
//! written before launch so the lldb plugin / `carrick debug inspect-state`
//! can resolve guest addresses back to image / segment context. Both
//! `runtime` arms re-export these under the original `crate::runtime::…`
//! paths so call sites (including the CLI's `debug.rs`) are unchanged.

use std::path::{Path, PathBuf};

use carrick_mem::memory::AddressSpace;
use serde::Serialize;

/// JSON-serialisable snapshot of the guest layout the trap engine is about
/// to run. Written by `run-elf --debug-state-path` / `run --debug-state-path`
/// before vCPU launch so the lldb plugin can resolve guest addresses back
/// to image / segment context.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct DebugStateSnapshot {
    pub entry: u64,
    pub initial_stack_pointer: Option<u64>,
    pub el0_trampoline_entry: Option<u64>,
    pub el1_vectors_base: Option<u64>,
    pub stage1_page_tables_base: Option<u64>,
    pub regions: Vec<DebugRegionSnapshot>,
}

#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct DebugRegionSnapshot {
    pub start: u64,
    pub end: u64,
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

impl DebugStateSnapshot {
    pub fn from_address_space(image: &AddressSpace) -> Self {
        Self {
            entry: image.entry(),
            initial_stack_pointer: image.initial_stack_pointer(),
            el0_trampoline_entry: image.el0_trampoline_entry(),
            el1_vectors_base: image.el1_vectors_base(),
            stage1_page_tables_base: image.stage1_page_tables_base(),
            regions: image
                .regions()
                .iter()
                .map(|region| DebugRegionSnapshot {
                    start: region.start,
                    end: region.end,
                    read: region.perms.read,
                    write: region.perms.write,
                    execute: region.perms.execute,
                })
                .collect(),
        }
    }

    pub fn write_to(&self, path: &Path) -> std::io::Result<()> {
        let bytes = serde_json::to_vec_pretty(self)
            .map_err(|e| std::io::Error::other(format!("serialize: {e}")))?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, bytes)
    }
}

/// Write a debug-state snapshot iff a path was provided. Returns the path
/// back so the CLI can mention it.
pub fn maybe_dump_debug_state(image: &AddressSpace, path: Option<&PathBuf>) -> Option<PathBuf> {
    let path = path?;
    let snapshot = DebugStateSnapshot::from_address_space(image);
    if let Err(err) = snapshot.write_to(path) {
        eprintln!("warning: failed to write debug state to {path:?}: {err}");
        return None;
    }
    Some(path.clone())
}
