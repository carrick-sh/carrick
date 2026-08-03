//! Attribute native shared-cache manifest bytes to their top-level owners.

use std::path::{Path, PathBuf};

use carrick_dsr_aarch64::shared_cache::TranslationUnitManifest;

const MANIFEST_DECODE_LIMIT: usize = 256 * 1024 * 1024;
const SCHEMA: &str = "carrick.native-manifest-census.v1";

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

fn decode_manifest(bytes: &[u8]) -> Result<TranslationUnitManifest, String> {
    let (manifest, consumed): (TranslationUnitManifest, usize) = bincode::serde::decode_from_slice(
        bytes,
        bincode::config::standard()
            .with_fixed_int_encoding()
            .with_limit::<MANIFEST_DECODE_LIMIT>(),
    )
    .map_err(|error| format!("decode fixed-width manifest: {error}"))?;
    if consumed != bytes.len() {
        return Err(format!(
            "manifest has {} trailing bytes",
            bytes.len().saturating_sub(consumed)
        ));
    }
    Ok(manifest)
}

fn encoded_len(manifest: &TranslationUnitManifest) -> Result<usize, String> {
    bincode::serde::encode_to_vec(
        manifest,
        bincode::config::standard()
            .with_fixed_int_encoding()
            .with_limit::<MANIFEST_DECODE_LIMIT>(),
    )
    .map(|bytes| bytes.len())
    .map_err(|error| format!("re-encode fixed-width manifest: {error}"))
}

fn removed_len(
    total: usize,
    manifest: &mut TranslationUnitManifest,
    remove: impl FnOnce(&mut TranslationUnitManifest),
) -> Result<usize, String> {
    remove(manifest);
    let remainder = encoded_len(manifest)?;
    total
        .checked_sub(remainder)
        .ok_or_else(|| "component removal increased the encoded manifest".to_string())
}

fn census(path: &Path) -> Result<serde_json::Value, String> {
    let bytes = std::fs::read(path).map_err(|error| format!("read {}: {error}", path.display()))?;
    let mut manifest = decode_manifest(&bytes)?;
    manifest
        .validate_ranges()
        .map_err(|reason| format!("validate {}: {reason:?}", path.display()))?;
    let encoded = encoded_len(&manifest)?;
    if encoded != bytes.len() {
        return Err(format!(
            "{} re-encoded to {encoded} bytes instead of {}",
            path.display(),
            bytes.len()
        ));
    }

    let block_count = manifest.blocks.len();
    let metadata_counts = manifest.blocks.iter().fold(
        carrick_dsr_aarch64::artifact_spike::ArtifactTemplateMetadataCounts {
            words: 0,
            pc_map_entries: 0,
            recovery_entries: 0,
            recovery_runs: 0,
            direct_links: 0,
            relocations: 0,
            source_words: 0,
        },
        |mut total, block| {
            let counts = block.template.metadata_counts();
            total.words += counts.words;
            total.pc_map_entries += counts.pc_map_entries;
            total.recovery_entries += counts.recovery_entries;
            total.recovery_runs += counts.recovery_runs;
            total.direct_links += counts.direct_links;
            total.relocations += counts.relocations;
            total.source_words += counts.source_words;
            total
        },
    );
    let blocks = std::mem::take(&mut manifest.blocks);
    let block_metadata_bytes = removed_len(encoded, &mut manifest, |_| {})?;
    manifest.blocks = blocks;

    let attributed = block_metadata_bytes;
    let other_manifest_bytes = encoded
        .checked_sub(attributed)
        .ok_or_else(|| "manifest attribution exceeds file size".to_string())?;

    Ok(serde_json::json!({
        "schema": SCHEMA,
        "path": path,
        "manifest_bytes": encoded,
        "code_bytes": manifest.code_len,
        "manifest_to_code_ratio": encoded as f64 / manifest.code_len as f64,
        "block_count": block_count,
        "block_metadata_bytes": block_metadata_bytes,
        "block_metadata_fraction": block_metadata_bytes as f64 / encoded as f64,
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
