// A benchmark example, not shipped code: every `expect` here is a setup step
// whose failure invalidates the measurement, so panicking with the reason is the
// correct response and an `Err` return would only obscure it. The workspace
// no-panic gate targets the runtime, which this is not.
#![allow(clippy::expect_used, clippy::unwrap_used)]
//! Benchmark the raw-code shared-unit transport: publish and per-process load.
//!
//! The question this answers: what does one process pay to LOAD a published
//! translation unit through the copy transport (openat + mmap + SHA-256
//! digest + binding-cell allocation), as a function of unit size? The
//! superseded signed-dylib + `dlopen` transport paid ~2.4 ms/MB (page-fault
//! plus code-signature validation of the whole image,
//! `docs/perf-results/2026-08-02-exec-cost-decomposed.jsonl`); the number
//! printed here is what replaced it. The translator's install adds one
//! `memcpy` of the same bytes into its `MAP_JIT` cache on top of this.
//!
//! Run: `cargo run -p carrick-native-darwin --example aot_bench --release`
//! Keep the box quiet, and treat single-run numbers as "suggests".

use std::time::Instant;

use carrick_dsr::address::NativeHostBias;
use carrick_dsr_aarch64::artifact_spike::{ArtifactBindings, ArtifactTemplate};
use carrick_dsr_aarch64::emit::PcMapEntry;
use carrick_dsr_aarch64::shared_cache::TranslationUnitStore as _;
use carrick_dsr_aarch64::shared_cache::{
    AddressModeIdentity, DirectBindingLayout, ExecutableIdentity, GuestCodeLen, ImageFileLen,
    ImageFileOffset, NativePageProfileIdentity, PendingTranslationUnit, PortableBlockRecord,
    SourceFingerprint, TranslationUnitKey,
};
use carrick_dsr_aarch64::types::CacheOffset;
use carrick_guest_mem::GuestVa;
use carrick_native_darwin::aot_cache::{ActiveContainerUnitStore, begin_container_cache};

/// `mov w0, #42 ; ret`
const MOV42_RET: [u8; 8] = [0x40, 0x05, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6];
/// `nop` — pads a unit out to a realistic size without changing behaviour.
const NOP: [u8; 4] = [0x1f, 0x20, 0x03, 0xd5];

fn unit_code(bytes: usize) -> Vec<u8> {
    let mut code = Vec::with_capacity(bytes);
    code.extend_from_slice(&MOV42_RET);
    while code.len() < bytes {
        code.extend_from_slice(&NOP);
    }
    code
}

fn pending_of_size(bytes: usize, seed: u8) -> PendingTranslationUnit {
    let code = unit_code(bytes);
    let source_words = [u32::from_le_bytes(MOV42_RET[..4].try_into().expect("word"))];
    let template = ArtifactTemplate::normalize(
        Vec::new(),
        vec![PcMapEntry {
            guest: GuestVa(0x40_0000),
            cache: CacheOffset::published(0),
        }],
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        &ArtifactBindings::from_values([]).expect("empty artifact bindings"),
    )
    .expect("bench block metadata")
    .into_runtime_metadata_only();
    PendingTranslationUnit {
        key: TranslationUnitKey::for_segment(
            ExecutableIdentity::Digest([seed; 32]),
            ImageFileOffset::new(0),
            ImageFileLen::new(bytes as u64).expect("nonzero file length"),
            GuestVa(0x40_0000),
            GuestCodeLen::new(bytes as u64).expect("nonzero guest length"),
            SourceFingerprint::from_words(&source_words),
            NativePageProfileIdentity::Native16k,
            AddressModeIdentity::biased(
                NativeHostBias::new(0x8000_0000, 16 * 1024).expect("aligned bias"),
            ),
        ),
        code: code.clone(),
        blocks: vec![PortableBlockRecord {
            guest_start: GuestVa(0x40_0000),
            generation_binding: 0,
            entry_offset: 0,
            code_len: u32::try_from(code.len()).expect("bench unit fits u32"),
            requires_sensitive_metadata: false,
            template,
        }],
        binding_layout: DirectBindingLayout::Disabled,
        binding_export: String::new(),
        binding_data_len: 0,
        cell_size: 0,
        bindings: Vec::new(),
        binding_relocations: Vec::new(),
        binding_data: Vec::new(),
    }
}

fn median(mut v: Vec<u128>) -> u128 {
    v.sort_unstable();
    v[v.len() / 2]
}

fn main() {
    let _session = begin_container_cache().expect("begin bench cache session");
    let store = ActiveContainerUnitStore;
    println!("size_mb publish_ms load_cold_ms load_warm_p50_ms load_warm_mb_per_s");
    for (index, size_mb) in [1_usize, 6, 16].into_iter().enumerate() {
        let bytes = size_mb * 1024 * 1024;
        let pending = pending_of_size(bytes, 0x11 + index as u8);
        let source_words = [u32::from_le_bytes(MOV42_RET[..4].try_into().expect("word"))];

        let t0 = Instant::now();
        store.publish(&pending).expect("publish bench unit");
        let publish_ms = t0.elapsed().as_secs_f64() * 1e3;

        let t0 = Instant::now();
        let cold = store
            .load(&pending.key, &source_words)
            .expect("cold load")
            .expect("published bench unit");
        let cold_ms = t0.elapsed().as_secs_f64() * 1e3;
        drop(cold);

        let mut samples = Vec::new();
        for _ in 0..21 {
            let t0 = Instant::now();
            let loaded = store
                .load(&pending.key, &source_words)
                .expect("warm load")
                .expect("published bench unit");
            samples.push(t0.elapsed().as_nanos());
            drop(loaded);
        }
        let warm_ns = median(samples);
        let warm_ms = warm_ns as f64 / 1e6;
        let mb_per_s = (bytes as f64 / (1024.0 * 1024.0)) / (warm_ns as f64 / 1e9);
        println!("{size_mb} {publish_ms:.2} {cold_ms:.2} {warm_ms:.3} {mb_per_s:.0}");
    }
    println!();
    println!(
        "note: dylib-era load was ~2.4 ms/MB (14.76 ms median for a 6 MB unit); \
         single-run numbers above are load-sensitive and only 'suggest'."
    );
}
