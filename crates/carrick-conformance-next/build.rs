use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let repo_root = manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .expect("manifest dir must be within crates/carrick-conformance-next");
    let inventory_path = repo_root.join("conformance-probes/probe-inventory.json");

    println!("cargo:rerun-if-changed={}", inventory_path.display());

    let inventory = carrick_xtask::probe_inventory::load_inventory(&inventory_path)
        .expect("failed to load probe inventory in build.rs");
    let partition = carrick_xtask::probe_inventory::derive_partition(&inventory);

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
    let dest_path = out_dir.join("shard_arrays.rs");

    let mut content = String::new();
    for (i, shard) in partition.shards.iter().enumerate() {
        content.push_str(&format!("pub const SHARD_{i}_PROBES: &[&str] = &[\n"));
        for probe in shard {
            content.push_str(&format!("    \"{probe}\",\n"));
        }
        content.push_str("];\n\n");
    }

    fs::write(&dest_path, content).expect("failed to write shard_arrays.rs");
}
