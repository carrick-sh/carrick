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
use carrick_dsr_aarch64::pending_augmentation::RecordingOwner;
use carrick_dsr_aarch64::shared_cache::TranslationUnitStore as _;
use carrick_dsr_aarch64::shared_cache::{
    AddressModeIdentity, ExecutableIdentity, GuestCodeLen, ImageFileLen, ImageFileOffset,
    NativePageProfileIdentity, PendingTranslationUnit, PortableBlockCandidate, SourceFingerprint,
    TranslationUnitKey,
};
use carrick_dsr_aarch64::types::{CacheOffset, CodeGeneration};
use carrick_guest_mem::GuestVa;
use carrick_native_darwin::aot_cache::{ActiveContainerUnitStore, begin_container_cache_at};

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
    let words = code
        .chunks_exact(4)
        .map(|word| u32::from_le_bytes(word.try_into().expect("word")))
        .collect();
    let template = ArtifactTemplate::normalize(
        words,
        vec![PcMapEntry {
            guest: GuestVa(0x40_0000),
            cache: CacheOffset::published(0),
        }],
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        None,
        &ArtifactBindings::from_values([]).expect("empty artifact bindings"),
    )
    .expect("bench block metadata");
    let key = TranslationUnitKey::for_segment(
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
    );
    PendingTranslationUnit::pack(
        key,
        vec![PortableBlockCandidate {
            guest_start: GuestVa(0x40_0000),
            source_end: GuestVa(0x40_0000 + bytes as u64),
            generation: CodeGeneration::INITIAL,
            requires_sensitive_metadata: false,
            template,
        }],
    )
    .expect("pack bench pending unit")
}

fn median(mut v: Vec<u128>) -> u128 {
    v.sort_unstable();
    v[v.len() / 2]
}

fn main() {
    // A private store root: bench keys are deterministic, and a warm real
    // store would turn every publish into Existing and skew the numbers.
    let bench_root = tempfile::tempdir().expect("create bench store root");
    let _session = begin_container_cache_at(bench_root.path()).expect("begin bench cache session");
    let store = ActiveContainerUnitStore;
    println!("size_mb publish_ms load_cold_ms load_warm_p50_ms load_warm_mb_per_s");
    for (index, size_mb) in [1_usize, 6, 16].into_iter().enumerate() {
        let bytes = size_mb * 1024 * 1024;
        let pending = pending_of_size(bytes, 0x11 + index as u8);
        let source_words = [u32::from_le_bytes(MOV42_RET[..4].try_into().expect("word"))];

        let t0 = Instant::now();
        let owner = RecordingOwner {
            pid: std::process::id() as i32,
            incarnation: [0x5a; 16],
        };
        let claim = match store
            .claim_recording(&pending.key, &owner)
            .expect("claim bench unit")
        {
            carrick_dsr_aarch64::shared_cache::ClaimOutcome::Won(claim) => claim,
            outcome => {
                eprintln!("bench claim was not won: {outcome:?}");
                std::process::exit(2);
            }
        };
        store.merge(&pending, &claim).expect("publish bench unit");
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
