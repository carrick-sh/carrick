//! Attribute native shared-cache manifest bytes to their top-level owners.

use std::path::{Path, PathBuf};

use carrick_dsr_aarch64::shared_cache::{
    TranslationUnitManifest, decode_translation_unit_metadata,
};

const SCHEMA: &str = "carrick.native-manifest-census.v3";

fn manifest_paths(arguments: impl IntoIterator<Item = String>) -> Result<Vec<PathBuf>, String> {
    let mut paths = Vec::new();
    for argument in arguments {
        let path = PathBuf::from(argument);
        if path.is_dir() {
            let entries = std::fs::read_dir(&path)
                .map_err(|error| format!("read {}: {error}", path.display()))?;
            for entry in entries {
                let entry =
                    entry.map_err(|error| format!("read entry in {}: {error}", path.display()))?;
                let candidate = entry.path();
                if candidate
                    .extension()
                    .is_some_and(|extension| extension == "manifest")
                {
                    paths.push(candidate);
                }
            }
        } else {
            paths.push(path);
        }
    }
    paths.sort();
    paths.dedup();
    if paths.is_empty() {
        return Err("usage: native_manifest_census <manifest-or-directory> [...]".to_string());
    }
    Ok(paths)
}

/// Decode through THE runtime wire (`decode_translation_unit_metadata`), not
/// a private bincode config: this example once carried its own fixed-int
/// decode and silently rotted when the store moved to the magic-prefixed
/// varint wire — an offline tool that cannot read the real store measures
/// nothing.
fn decode_manifest(bytes: Vec<u8>) -> Result<TranslationUnitManifest, String> {
    decode_translation_unit_metadata(std::sync::Arc::new(bytes))
        .map_err(|reason| format!("decode unit metadata: {reason:?}"))
}

fn census(path: &Path) -> Result<serde_json::Value, String> {
    let bytes = std::fs::read(path).map_err(|error| format!("read {}: {error}", path.display()))?;
    let file_bytes = bytes.len();
    let manifest = decode_manifest(bytes)?;
    manifest
        .validate_ranges()
        .map_err(|reason| format!("validate {}: {reason:?}", path.display()))?;
    manifest
        .validate_deep()
        .map_err(|defect| format!("deep-validate {}: {defect:?}", path.display()))?;

    let block_count = manifest.blocks().len();
    let sensitive_block_count = manifest
        .blocks()
        .iter()
        .filter(|block| block.requires_sensitive_metadata)
        .count();
    // The v5 wire attributes itself: every payload byte belongs to exactly
    // one block's HOT (replay) or COLD (fault-reconstruction) blob.
    let hot_blob_bytes: usize = manifest
        .blocks()
        .iter()
        .map(|block| block.hot_blob_len())
        .sum();
    let cold_blob_bytes: usize = manifest
        .blocks()
        .iter()
        .map(|block| block.cold_blob_len())
        .sum();
    let block_metadata_bytes = hot_blob_bytes + cold_blob_bytes;
    let other_manifest_bytes = file_bytes
        .checked_sub(block_metadata_bytes)
        .ok_or_else(|| "manifest attribution exceeds file size".to_string())?;
    let mut metadata_counts = carrick_dsr_aarch64::artifact_spike::ArtifactTemplateMetadataCounts {
        words: 0,
        pc_map_entries: 0,
        recovery_entries: 0,
        recovery_runs: 0,
        direct_links: 0,
        relocations: 0,
        source_words: 0,
    };
    for at in 0..block_count {
        let record = manifest
            .block_record(at)
            .map_err(|reason| format!("decode block {at} of {}: {reason:?}", path.display()))?;
        let counts = record.template.metadata_counts();
        metadata_counts.words += counts.words;
        metadata_counts.pc_map_entries += counts.pc_map_entries;
        metadata_counts.recovery_entries += counts.recovery_entries;
        metadata_counts.recovery_runs += counts.recovery_runs;
        metadata_counts.direct_links += counts.direct_links;
        metadata_counts.relocations += counts.relocations;
        metadata_counts.source_words += counts.source_words;
    }

    Ok(serde_json::json!({
        "schema": SCHEMA,
        "path": path,
        "manifest_bytes": file_bytes,
        "code_bytes": manifest.code_len,
        "manifest_to_code_ratio": file_bytes as f64 / manifest.code_len as f64,
        "block_count": block_count,
        "sensitive_block_count": sensitive_block_count,
        "block_metadata_bytes": block_metadata_bytes,
        "block_metadata_fraction": block_metadata_bytes as f64 / file_bytes as f64,
        "hot_blob_bytes": hot_blob_bytes,
        "cold_blob_bytes": cold_blob_bytes,
        "retained_word_count": metadata_counts.words,
        "pc_map_entry_count": metadata_counts.pc_map_entries,
        "recovery_entry_count": metadata_counts.recovery_entries,
        "recovery_run_count": metadata_counts.recovery_runs,
        "retained_direct_link_count": metadata_counts.direct_links,
        "retained_relocation_count": metadata_counts.relocations,
        "retained_source_word_count": metadata_counts.source_words,
        "other_manifest_bytes": other_manifest_bytes,
    }))
}

fn main() -> Result<(), String> {
    // Referencing this package's library keeps its C shim link directive in
    // the standalone example. The DSR gateway object names the shim's ABI
    // switching symbols even though this offline tool never enters guest code.
    let _native_darwin_link_anchor =
        std::mem::size_of::<carrick_native_darwin::aot_cache::LoadedTranslationUnit>();
    let paths = manifest_paths(std::env::args().skip(1))?;
    for path in paths {
        println!(
            "{}",
            serde_json::to_string(&census(&path)?)
                .map_err(|error| format!("encode census JSON: {error}"))?
        );
    }
    Ok(())
}
