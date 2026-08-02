//! `carrick debug xlat-census` — aggregate the per-process translation census.
//!
//! # What this answers
//!
//! The native (DSR) lane translates the same guest code once per process. A
//! cold `go build` spends hundreds of thousands of translations across dozens
//! of short-lived processes, and the shared-translation lane exists to serve
//! the repeats from a published unit. Whether that is worth building at all
//! turns on three numbers, and this subcommand is where they are computed:
//!
//! 1. **How redundant is the work?** `translations / distinct blocks`.
//! 2. **How much of it could a translation unit ever serve?** The share of
//!    blocks that land inside a *configured* segment — blocks outside every
//!    segment (a guest-`ld.so`-mapped library, say) can never be served by any
//!    unit of any design, so they bound the whole workstream from above.
//! 3. **How many distinct unit keys are there?** A handful means per-unit
//!    publication cost amortises trivially; thousands means it does not.
//! 4. **Where does the one key go?** A shared-translation cache directory that
//!    holds exactly one key can mean three unrelated things: the store was
//!    never consulted, it was consulted by a process that held no authority, or
//!    it was consulted and genuinely missed. The `store` section separates
//!    them, because each implies a different fix — respectively wider segment
//!    coverage, fixing authority inheritance across the host self-re-exec, and
//!    persistence.
//!
//! # Why it is a Rust subcommand and not a script
//!
//! The census file format has exactly one definition, `carrick_runtime::
//! xlat_census::CensusFile` — the same types the runtime renders with are the
//! types this parses with, re-exported through the runtime facade because
//! `carrick-cli` does not depend on `carrick-dsr-aarch64` directly. A Python
//! aggregator would be a second, drifting definition of the format.
//!
//! # Honesty constraints the report encodes
//!
//! - **Distinctness is bracketed, not exact.** The native lane loads PIE guests
//!   at a FIXED base, so two different guest binaries translate overlapping
//!   VAs: a union over bare VAs under-counts distinct code and therefore
//!   over-states redundancy. Scoping each VA by the content-addressed unit stem
//!   removes that aliasing, but a block *outside* every segment has no stem and
//!   falls back to the process image identity, which over-counts distinct code
//!   for a library shared between two different executables. The two numbers
//!   bracket the truth; the report emits both and names which is which.
//! - **Coverage is three-valued.** A unit *lookup* keys on the block's entry VA
//!   alone, while today's *producer* additionally requires the block's whole
//!   range to fit inside one segment. Quoting one fraction would either
//!   overstate the ceiling or understate the geometry, so both are reported —
//!   and neither is a publication forecast, since recording is gated on a won
//!   recorder election as well as on geometry.
//! - **A missing census file is invisible.** A process killed by a fatal signal
//!   never flushes. The process section derives what it can from flush lineage
//!   — every incarnation should end in a terminal flush or hand off to a
//!   re-exec successor — but a process that translated and then died before its
//!   first flush leaves no trace at all. Those checks are lower bounds on loss,
//!   and `--processes-observed` exists so an operator who counted the run's
//!   processes by other means can supply the real denominator.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anyhow::{Context, Result, bail};
use carrick_runtime::GuestVa;
use carrick_runtime::xlat_census::{
    CensusFile, CensusFlush, LookupSkip, SegmentCoverage, UnitMissReason,
};
use serde::Serialize;

/// Schema tag on the emitted JSON. Bump when a field's meaning changes.
const REPORT_SCHEMA: &str = "carrick.xlat-census.v2";

/// Filename prefix `xlat_census::flush` writes (`xlat-<pid>-<stamp>-<seq>.txt`).
const CENSUS_FILE_PREFIX: &str = "xlat-";
const CENSUS_FILE_SUFFIX: &str = ".txt";

/// The census's "not available" token. On a `SEG` line's stem column it means
/// the `TranslationUnitKey` could not be serialized — such a segment can never
/// be published, so it is counted separately rather than as one more key. In
/// the header's `image=` field it means the image was identified by host file
/// rather than by content digest.
const ABSENT_TOKEN: &str = "-";

/// A census file that did not parse. Reported rather than skipped: silently
/// averaging over fewer processes is exactly the failure mode this instrument
/// exists to detect.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct FileFailure {
    pub path: String,
    pub error: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct FilesSection {
    /// Census files that parsed.
    pub parsed: u64,
    /// Census files that did not. Non-empty makes the subcommand exit non-zero.
    pub failed: Vec<FileFailure>,
    /// Records naming a segment index their own file does not define. Always 0
    /// for a file the runtime wrote; non-zero means corruption.
    pub dangling_segment_references: u64,
    /// Files whose header `total` disagrees with the sum of their records'
    /// translation counts. Always 0 for a file the runtime wrote.
    pub inconsistent_totals: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct TranslationsSection {
    /// Sum of every file's header `total`: fresh translations the census saw.
    pub total: u64,
    /// Sum over every record. Equals `total` for files the runtime wrote.
    pub recorded: u64,
    /// Distinct entry VAs unioned across all processes. The fixed PIE base
    /// aliases VAs across different binaries, so this UNDER-counts distinct
    /// code — making `redundancy_upper` an upper bound.
    pub distinct_guest_vas: u64,
    /// Distinct (scope, entry VA) pairs, where scope is the containing unit
    /// stem, or the process image identity for a block outside every segment.
    /// Removes PIE aliasing but OVER-counts distinct code for a library shared
    /// between two executables — making `redundancy_lower` a lower bound.
    pub distinct_scoped_blocks: u64,
    /// `total / distinct_guest_vas`.
    pub redundancy_upper: f64,
    /// `total / distinct_scoped_blocks`.
    pub redundancy_lower: f64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct CoverageBucket {
    /// Distinct (scope, entry VA) pairs in this bucket.
    pub blocks: u64,
    /// Fresh translations spent on them.
    pub translations: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct CoverageSection {
    /// Whole block inside one configured segment. Geometry only — the
    /// NECESSARY condition for `record_portable_block_artifact`, never the
    /// sufficient one (see `contained_share_of_translations`).
    pub contained: CoverageBucket,
    /// Entry VA inside a segment, block runs past its end: a unit lookup would
    /// hit, today's producer refuses to record it.
    pub entry_only: CoverageBucket,
    /// Entry VA outside every configured segment. No unit of any design can
    /// serve these.
    pub outside: CoverageBucket,
    /// `(contained + entry_only) / total`, weighted by translations. The upper
    /// bound on what any unit design could serve — the Phase 0 kill number.
    pub inside_segment_share_of_translations: f64,
    /// The same fraction weighted by distinct blocks rather than translations.
    pub inside_segment_share_of_blocks: f64,
    /// `contained / total`, weighted by translations.
    ///
    /// This is a GEOMETRIC share, not a publication forecast. It says the block
    /// fits wholly inside one segment, which is necessary for
    /// `record_portable_block_artifact` and nowhere near sufficient: recording
    /// also needs an `INITIAL` generation, a WON recorder election for that
    /// segment, source words, and a terminal exit outside the
    /// `Unsupported`/`ExclusiveRegion` set. With the lane off — the shipped
    /// default — no segment is ever claimed, so the actually-published share is
    /// **zero** however high this number reads. Read `store.recording_claimed`
    /// and `store.loaded` for what the producer did.
    pub contained_share_of_translations: f64,
    /// The same fraction weighted by distinct blocks, with the same caveat.
    pub contained_share_of_blocks: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct UnitKeyTally {
    /// Hex `TranslationUnitKey::file_stem()` — content-addressed, so it does not
    /// alias across images the way a bare guest VA does.
    pub stem: String,
    /// Hex executable identity of the image this key belongs to.
    pub image: String,
    pub guest_start: String,
    pub guest_len: u64,
    /// Distinct entry VAs translated inside this segment.
    pub blocks: u64,
    /// Fresh translations spent on them, summed over every process.
    pub translations: u64,
    /// Census files that translated at least one block into this key. This is
    /// the reuse count a published unit would have served.
    pub incarnations: u64,
    /// `translations / blocks`.
    pub redundancy: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct UnitKeysSection {
    /// Distinct stems appearing on a `SEG` line: what the lane would key on.
    pub configured: u64,
    /// Distinct stems with at least one translated block.
    pub translated_into: u64,
    /// Configured segments whose key could not be serialized (`-`). These can
    /// never be published and are excluded from `configured`.
    pub unserializable_segments: u64,
    /// Per-key tallies, most translations first, truncated to `--top`.
    pub per_key: Vec<UnitKeyTally>,
    /// Keys omitted from `per_key` by that truncation.
    pub per_key_omitted: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct ProcessesSection {
    /// Census files that parsed — one per flush, not one per process.
    pub census_files: u64,
    pub distinct_pids: u64,
    /// Process incarnations, counted as flush-sequence restarts. carrick's
    /// guest `execve` is a host self-re-exec: the successor keeps the pid and
    /// restarts the sequence at 0, so one pid can hold several incarnations.
    pub incarnations: u64,
    /// Flush count by reason token.
    pub flushes: BTreeMap<String, u64>,
    /// `incarnations - (terminal flushes + re-exec handoffs)`. Every incarnation
    /// either ends in a terminal flush or hands off to a re-exec successor, so
    /// this is 0 when the instrument saw every incarnation out.
    ///
    /// * **Positive** — an incarnation died between flushes: a fatal signal, or
    ///   one of the thread-loop `_exit` paths the census does not cover.
    /// * **Negative** — a file was written by a process that left no `seq=0`
    ///   start, so `incarnations` under-counts. Either the writer's flush
    ///   ordinal leaked across a lineage boundary (it did, once: a `fork` child
    ///   used to inherit a non-zero `FLUSH_SEQUENCE` from a parent that had
    ///   already `execve`d in place), or the directory mixes runs.
    ///
    /// Both signs are LOWER bounds: a process that translated and died before
    /// its first flush contributes nothing to either side and is invisible.
    pub flush_balance: i64,
    /// Re-exec handoffs whose successor incarnation left no file. A LOWER bound
    /// on lost successors: pid reuse can mask one.
    pub reexec_successors_missing: u64,
    /// Files whose flush sequence is not a contiguous staircase within its pid.
    pub sequence_anomalies: u64,
    /// Process INCARNATIONS the operator counted by other means, via
    /// `--processes-observed`. Must be counted in the same unit as
    /// `incarnations` (process-image lifetimes, not pids and not guest
    /// programs) or the ratio below is meaningless.
    pub observed: Option<u64>,
    /// `incarnations / observed`, when `observed` was supplied. It is NOT an
    /// independent cross-check unless the denominator came from an instrument
    /// with a different flush discipline — supplying a number derived from the
    /// census itself makes it 1.0 by construction.
    pub coverage: Option<f64>,
}

/// What the shared-translation store did, summed over every process.
///
/// This is the section that discriminates the three explanations for a cache
/// directory with one key in it. Read it top-down:
///
/// * `lookups` is every shared-unit lookup the runtime attempted — one per
///   fresh translation. `consulted` is the subset that actually reached the
///   store; `skipped` is the rest, broken down by which guard returned early.
/// * `processes_that_consulted` versus `processes_that_translated` is the
///   coarsest signal available: a run where most processes translate and none
///   consult is a coverage or configuration problem, not a store problem.
/// * `misses.no-authority` counts lookups from a process that held no container
///   cache authority at all. It used to be indistinguishable from
///   `missing-pair` (a genuine file miss), which is precisely why "where did
///   the one key go" was unanswerable.
/// * `recording_claimed` versus `recording_declined` says whether the recorder
///   election — which declines the FIRST sighting of every key — is where
///   publication stops.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct StoreSection {
    /// Shared-unit lookups attempted: `consulted + skipped_total`.
    ///
    /// `lookups == translations.total` holds only while `loaded` is 0: a lookup
    /// that RETURNS a unit short-circuits before the block is recorded, and a
    /// translation that errors out after its lookup is counted here and never
    /// recorded. It is a property of the lane failing, not an invariant — do
    /// not use it as a cross-check once the lane works.
    pub lookups: u64,
    /// Lookups that reached `TranslationUnitStore::load`.
    pub consulted: u64,
    /// Lookups that returned before touching the store, by reason token.
    pub skipped: BTreeMap<String, u64>,
    pub skipped_total: u64,
    /// `consulted / lookups`.
    pub consulted_share_of_lookups: f64,
    /// Lookups that returned a unit — the lane actually working.
    pub loaded: u64,
    /// Lookups whose unit files were absent: a genuine cache miss.
    pub file_miss: u64,
    /// Store refusals by typed reason token, `no-authority` among them.
    pub misses: BTreeMap<String, u64>,
    pub miss_total: u64,
    /// File misses where the recorder election picked this process.
    pub recording_claimed: u64,
    /// File misses where it declined.
    pub recording_declined: u64,
    /// Census files (process incarnations) that attempted at least one lookup.
    pub processes_that_translated: u64,
    /// Census files that reached the store at least once.
    pub processes_that_consulted: u64,
    /// Census files whose lookups hit `no-authority` at least once: processes
    /// that could never have contributed coverage, whatever the store holds.
    pub processes_without_authority: u64,
    /// Census files that loaded at least one unit.
    pub processes_that_loaded: u64,
    /// Census files that won at least one recording election.
    pub processes_that_claimed_recording: u64,
    /// Milliseconds summed across processes inside store `load`. This is
    /// CONCURRENT across processes, so it is a CPU-cost total and not a wall
    /// term - compare it against the run's total CPU, never its wall.
    pub load_ms_total: u64,
    /// Milliseconds summed across processes inside store `publish`.
    pub publish_ms_total: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct CensusReport {
    pub schema: &'static str,
    pub files: FilesSection,
    pub translations: TranslationsSection,
    pub coverage: CoverageSection,
    pub unit_keys: UnitKeysSection,
    pub store: StoreSection,
    pub processes: ProcessesSection,
}

/// A census directory read into memory: the files that parsed, and the ones
/// that did not.
#[derive(Debug, Default)]
pub(crate) struct CensusScan {
    pub files: Vec<CensusFile>,
    pub failures: Vec<FileFailure>,
}

/// Read every `xlat-*.txt` in `dir`.
///
/// Fails closed on an empty directory: an aggregator that reports zeros for a
/// run that never armed the census is worse than no aggregator.
pub(crate) fn scan_dir(dir: &Path) -> Result<CensusScan> {
    let entries = std::fs::read_dir(dir)
        .with_context(|| format!("failed to read census directory {}", dir.display()))?;
    let mut paths = Vec::new();
    for entry in entries {
        let entry =
            entry.with_context(|| format!("failed to read an entry of {}", dir.display()))?;
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if name.starts_with(CENSUS_FILE_PREFIX) && name.ends_with(CENSUS_FILE_SUFFIX) {
            paths.push(path);
        }
    }
    // Deterministic order so the report (and its per-key ties) do not depend on
    // directory iteration order.
    paths.sort();
    if paths.is_empty() {
        bail!(
            "no {CENSUS_FILE_PREFIX}*{CENSUS_FILE_SUFFIX} files in {} — was the run armed with \
             CARRICK_XLAT_CENSUS_DIR?",
            dir.display()
        );
    }
    let mut scan = CensusScan::default();
    for path in paths {
        let display = path.display().to_string();
        match std::fs::read_to_string(&path) {
            Ok(text) => match CensusFile::parse(&text) {
                Ok(file) => scan.files.push(file),
                Err(error) => scan.failures.push(FileFailure {
                    path: display,
                    error: error.to_string(),
                }),
            },
            Err(error) => scan.failures.push(FileFailure {
                path: display,
                error: error.to_string(),
            }),
        }
    }
    Ok(scan)
}

/// The scope a block's distinctness is measured in: the containing unit stem
/// when the block is inside a configured segment, otherwise the process image
/// identity. Never a bare VA — that is what aliases under a fixed PIE base.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum BlockScope {
    Unit(String),
    Image(String),
}

struct KeyTally {
    image: String,
    guest_start: GuestVa,
    guest_len: u64,
    blocks: BTreeSet<GuestVa>,
    translations: u64,
    incarnations: u64,
}

impl Default for KeyTally {
    fn default() -> Self {
        Self {
            image: String::new(),
            // `GuestVa` deliberately has no `Default`: a zero guest address is
            // a real address, not an absence. The real extent is filled in from
            // the file's own `SEG` line before the tally is reported.
            guest_start: GuestVa(0),
            guest_len: 0,
            blocks: BTreeSet::new(),
            translations: 0,
            incarnations: 0,
        }
    }
}

/// Ratio that reads as 0.0 rather than NaN/inf on an empty denominator, so a
/// report over an empty census is still valid JSON a consumer can compare.
fn ratio(numerator: u64, denominator: u64) -> f64 {
    if denominator == 0 {
        return 0.0;
    }
    numerator as f64 / denominator as f64
}

/// Aggregate parsed census files into the report.
pub(crate) fn aggregate(scan: &CensusScan, top: usize, observed: Option<u64>) -> CensusReport {
    let mut total = 0u64;
    let mut recorded = 0u64;
    let mut dangling = 0u64;
    let mut inconsistent = 0u64;
    let mut distinct_vas: BTreeSet<GuestVa> = BTreeSet::new();
    let mut scoped_blocks: BTreeSet<(BlockScope, GuestVa)> = BTreeSet::new();
    let mut buckets: BTreeMap<SegmentCoverage, (BTreeSet<(BlockScope, GuestVa)>, u64)> =
        BTreeMap::new();
    let mut keys: BTreeMap<String, KeyTally> = BTreeMap::new();
    let mut configured_stems: BTreeSet<String> = BTreeSet::new();
    let mut unserializable_segments = 0u64;

    for file in &scan.files {
        total = total.saturating_add(file.total);
        let mut file_recorded = 0u64;
        // Scope for blocks OUTSIDE every segment, which have no unit stem of
        // their own. The image's content digest is the right discriminator; when
        // the image was identified by host file instead, fall back to its first
        // segment stem, which is still content-addressed. Only an image with
        // neither collapses with its peers, and then this under-counts distinct
        // code rather than silently over-counting it.
        let image_identity = file.image.as_ref().map_or(ABSENT_TOKEN, |image| {
            if image.identity == ABSENT_TOKEN {
                image
                    .segments
                    .first()
                    .map_or(ABSENT_TOKEN, |segment| segment.unit_stem.as_str())
            } else {
                image.identity.as_str()
            }
        });
        if let Some(image) = &file.image {
            for segment in &image.segments {
                if segment.unit_stem == ABSENT_TOKEN {
                    unserializable_segments = unserializable_segments.saturating_add(1);
                    continue;
                }
                configured_stems.insert(segment.unit_stem.clone());
                let tally = keys.entry(segment.unit_stem.clone()).or_default();
                tally.image = image.identity.clone();
                tally.guest_start = segment.guest_start;
                tally.guest_len = segment.guest_len;
            }
        }
        // Which keys this one file translated into, so `incarnations` counts
        // processes rather than blocks.
        let mut touched: BTreeSet<String> = BTreeSet::new();
        for record in &file.records {
            file_recorded = file_recorded.saturating_add(record.translations);
            distinct_vas.insert(record.guest_va);
            let segment = record.segment.and_then(|index| {
                file.image.as_ref().and_then(|image| {
                    usize::try_from(index)
                        .ok()
                        .and_then(|i| image.segments.get(i))
                })
            });
            if record.segment.is_some() && segment.is_none() {
                dangling = dangling.saturating_add(1);
            }
            let scope = match segment {
                Some(segment) if segment.unit_stem != ABSENT_TOKEN => {
                    let tally = keys.entry(segment.unit_stem.clone()).or_default();
                    tally.blocks.insert(record.guest_va);
                    tally.translations = tally.translations.saturating_add(record.translations);
                    touched.insert(segment.unit_stem.clone());
                    BlockScope::Unit(segment.unit_stem.clone())
                }
                _ => BlockScope::Image(image_identity.to_string()),
            };
            let block = (scope, record.guest_va);
            scoped_blocks.insert(block.clone());
            let bucket = buckets.entry(record.coverage).or_default();
            bucket.0.insert(block);
            bucket.1 = bucket.1.saturating_add(record.translations);
        }
        for stem in touched {
            let tally = keys.entry(stem).or_default();
            tally.incarnations = tally.incarnations.saturating_add(1);
        }
        recorded = recorded.saturating_add(file_recorded);
        if file_recorded != file.total {
            inconsistent = inconsistent.saturating_add(1);
        }
    }

    let bucket_of = |coverage: SegmentCoverage| -> CoverageBucket {
        buckets.get(&coverage).map_or(
            CoverageBucket {
                blocks: 0,
                translations: 0,
            },
            |(blocks, translations)| CoverageBucket {
                blocks: blocks.len() as u64,
                translations: *translations,
            },
        )
    };
    let contained = bucket_of(SegmentCoverage::Contained);
    let entry_only = bucket_of(SegmentCoverage::EntryOnly);
    let outside = bucket_of(SegmentCoverage::Outside);
    let inside_translations = contained
        .translations
        .saturating_add(entry_only.translations);
    let inside_blocks = contained.blocks.saturating_add(entry_only.blocks);
    let all_blocks = scoped_blocks.len() as u64;

    let mut per_key: Vec<UnitKeyTally> = keys
        .iter()
        .filter(|(_, tally)| !tally.blocks.is_empty())
        .map(|(stem, tally)| UnitKeyTally {
            stem: stem.clone(),
            image: tally.image.clone(),
            guest_start: format!("{:#x}", tally.guest_start.raw()),
            guest_len: tally.guest_len,
            blocks: tally.blocks.len() as u64,
            translations: tally.translations,
            incarnations: tally.incarnations,
            redundancy: ratio(tally.translations, tally.blocks.len() as u64),
        })
        .collect();
    // Most expensive key first; stem breaks ties so the output is stable.
    per_key.sort_by(|a, b| {
        b.translations
            .cmp(&a.translations)
            .then_with(|| a.stem.cmp(&b.stem))
    });
    let translated_into = per_key.len() as u64;
    let per_key_omitted = per_key.len().saturating_sub(top) as u64;
    per_key.truncate(top);

    CensusReport {
        schema: REPORT_SCHEMA,
        files: FilesSection {
            parsed: scan.files.len() as u64,
            failed: scan.failures.clone(),
            dangling_segment_references: dangling,
            inconsistent_totals: inconsistent,
        },
        translations: TranslationsSection {
            total,
            recorded,
            distinct_guest_vas: distinct_vas.len() as u64,
            distinct_scoped_blocks: all_blocks,
            redundancy_upper: ratio(total, distinct_vas.len() as u64),
            redundancy_lower: ratio(total, all_blocks),
        },
        coverage: CoverageSection {
            inside_segment_share_of_translations: ratio(inside_translations, total),
            inside_segment_share_of_blocks: ratio(inside_blocks, all_blocks),
            contained_share_of_translations: ratio(contained.translations, total),
            contained_share_of_blocks: ratio(contained.blocks, all_blocks),
            contained,
            entry_only,
            outside,
        },
        unit_keys: UnitKeysSection {
            configured: configured_stems.len() as u64,
            translated_into,
            unserializable_segments,
            per_key,
            per_key_omitted,
        },
        store: store_section(&scan.files),
        processes: process_section(&scan.files, observed),
    }
}

/// Sum the per-process store counters and derive the per-process incidences.
///
/// Every count here is a LOWER bound in the same way the rest of the report is:
/// a process that died on a fatal signal never flushed, so its lookups are
/// absent rather than zero.
fn store_section(files: &[CensusFile]) -> StoreSection {
    let mut consulted = 0u64;
    let mut loaded = 0u64;
    let mut file_miss = 0u64;
    let mut recording_claimed = 0u64;
    let mut recording_declined = 0u64;
    let mut skipped: BTreeMap<LookupSkip, u64> = BTreeMap::new();
    let mut misses: BTreeMap<UnitMissReason, u64> = BTreeMap::new();
    let mut processes_that_translated = 0u64;
    let mut processes_that_consulted = 0u64;
    let mut processes_without_authority = 0u64;
    let mut processes_that_loaded = 0u64;
    let mut load_ns_total = 0u64;
    let mut publish_ns_total = 0u64;
    let mut processes_that_claimed_recording = 0u64;

    for file in files {
        let store = &file.store;
        consulted = consulted.saturating_add(store.consulted);
        loaded = loaded.saturating_add(store.loaded);
        file_miss = file_miss.saturating_add(store.file_miss);
        recording_claimed = recording_claimed.saturating_add(store.recording_claimed);
        load_ns_total = load_ns_total.saturating_add(store.load_ns);
        publish_ns_total = publish_ns_total.saturating_add(store.publish_ns);
        recording_declined = recording_declined.saturating_add(store.recording_declined);
        for (skip, count) in &store.skipped {
            let entry = skipped.entry(*skip).or_insert(0);
            *entry = entry.saturating_add(*count);
        }
        for (reason, count) in &store.misses {
            let entry = misses.entry(*reason).or_insert(0);
            *entry = entry.saturating_add(*count);
        }
        if !store.is_empty() {
            processes_that_translated = processes_that_translated.saturating_add(1);
        }
        if store.consulted > 0 {
            processes_that_consulted = processes_that_consulted.saturating_add(1);
        }
        if store
            .misses
            .get(&UnitMissReason::NoAuthority)
            .is_some_and(|count| *count > 0)
        {
            processes_without_authority = processes_without_authority.saturating_add(1);
        }
        if store.loaded > 0 {
            processes_that_loaded = processes_that_loaded.saturating_add(1);
        }
        if store.recording_claimed > 0 {
            processes_that_claimed_recording = processes_that_claimed_recording.saturating_add(1);
        }
    }

    let skipped_total = skipped
        .values()
        .fold(0u64, |sum, count| sum.saturating_add(*count));
    let miss_total = misses
        .values()
        .fold(0u64, |sum, count| sum.saturating_add(*count));
    let lookups = consulted.saturating_add(skipped_total);

    StoreSection {
        lookups,
        consulted,
        skipped: skipped
            .into_iter()
            .map(|(skip, count)| (skip.token().to_string(), count))
            .collect(),
        skipped_total,
        consulted_share_of_lookups: ratio(consulted, lookups),
        loaded,
        file_miss,
        misses: misses
            .into_iter()
            .map(|(reason, count)| (reason.token().to_string(), count))
            .collect(),
        miss_total,
        recording_claimed,
        recording_declined,
        processes_that_translated,
        processes_that_consulted,
        processes_without_authority,
        processes_that_loaded,
        processes_that_claimed_recording,
        load_ms_total: load_ns_total / 1_000_000,
        publish_ms_total: publish_ns_total / 1_000_000,
    }
}

/// Derive what the flush lineage says about how many processes the census
/// missed.
///
/// The sequence number restarts at 0 in each new incarnation (a host self-
/// re-exec is a fresh process image, so the counter is fresh too) and advances
/// only when a file is actually written, so within one incarnation the written
/// sequences are contiguous from 0. That gives two checks:
///
/// * every incarnation ends either in a terminal flush or in a handoff to a
///   re-exec successor, so `incarnations == terminal + handoffs`;
/// * a pid that performed `h` handoffs must hold at least `h + 1` incarnations.
///
/// Both are LOWER bounds on loss: an incarnation that translated and died
/// before its first flush writes nothing and is invisible to both, and pid
/// reuse can mask a missing successor.
fn process_section(files: &[CensusFile], observed: Option<u64>) -> ProcessesSection {
    let mut flushes: BTreeMap<String, u64> = BTreeMap::new();
    let mut per_pid: BTreeMap<i32, (BTreeMap<u64, u64>, u64)> = BTreeMap::new();
    let mut terminal = 0u64;
    let mut handoffs = 0u64;

    for file in files {
        let counter = flushes.entry(file.reason.token().to_string()).or_insert(0);
        *counter = counter.saturating_add(1);
        match file.reason {
            CensusFlush::ProcessExit | CensusFlush::AtexitBackstop => {
                terminal = terminal.saturating_add(1);
            }
            CensusFlush::HostSelfReexec => handoffs = handoffs.saturating_add(1),
            CensusFlush::InProcessExec => {}
        }
        let entry = per_pid.entry(file.pid).or_default();
        let sequence = entry.0.entry(file.sequence).or_insert(0);
        *sequence = sequence.saturating_add(1);
        if matches!(file.reason, CensusFlush::HostSelfReexec) {
            entry.1 = entry.1.saturating_add(1);
        }
    }

    let mut incarnations = 0u64;
    let mut sequence_anomalies = 0u64;
    let mut reexec_successors_missing = 0u64;
    for (sequences, pid_handoffs) in per_pid.values() {
        let starts = sequences.get(&0).copied().unwrap_or(0);
        incarnations = incarnations.saturating_add(starts);
        // Within a pid the per-sequence counts must form a staircase: a file at
        // sequence n+1 implies a file at sequence n in the same incarnation.
        for (sequence, count) in sequences {
            let previous = match sequence.checked_sub(1) {
                Some(previous) => sequences.get(&previous).copied().unwrap_or(0),
                None => continue,
            };
            if *count > previous {
                sequence_anomalies =
                    sequence_anomalies.saturating_add(count.saturating_sub(previous));
            }
        }
        // A pid that handed off `h` times must hold at least `h + 1`
        // incarnations: the one that handed off, plus each successor.
        reexec_successors_missing = reexec_successors_missing
            .saturating_add(pid_handoffs.saturating_add(1).saturating_sub(starts));
    }

    let accounted = terminal.saturating_add(handoffs);
    let flush_balance = i64::try_from(incarnations)
        .unwrap_or(i64::MAX)
        .saturating_sub(i64::try_from(accounted).unwrap_or(i64::MAX));

    ProcessesSection {
        census_files: files.len() as u64,
        distinct_pids: per_pid.len() as u64,
        incarnations,
        flushes,
        flush_balance,
        reexec_successors_missing,
        sequence_anomalies,
        observed,
        coverage: observed.map(|observed| ratio(incarnations, observed)),
    }
}

/// `carrick debug xlat-census <dir>`: aggregate and print, then fail if any
/// file in the directory did not parse.
pub(crate) fn run_xlat_census(dir: &Path, top: usize, observed: Option<u64>) -> Result<()> {
    let scan = scan_dir(dir)?;
    let report = aggregate(&scan, top, observed);
    println!("{}", serde_json::to_string_pretty(&report)?);
    if !scan.failures.is_empty() {
        bail!(
            "{} census file(s) in {} did not parse (see files.failed); the numbers above cover \
             the rest",
            scan.failures.len(),
            dir.display()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use carrick_runtime::xlat_census::{CensusImage, CensusRecord, CensusSegment, CensusStore};

    fn stem(byte: u8) -> String {
        format!("{byte:02x}").repeat(32)
    }

    /// The default-path shape: the lane is opt-in, so every lookup returns at
    /// the `shared_translation is None` guard and the store is never touched.
    fn lane_off_store(lookups: u64) -> CensusStore {
        CensusStore {
            skipped: BTreeMap::from([(LookupSkip::LaneUnconfigured, lookups)]),
            ..CensusStore::default()
        }
    }

    fn image(identity: &str) -> CensusImage {
        CensusImage {
            identity: identity.to_string(),
            segments: vec![
                CensusSegment {
                    guest_start: GuestVa(0x40_0000),
                    guest_len: 0x1_0000,
                    unit_stem: stem(0xaa),
                },
                CensusSegment {
                    guest_start: GuestVa(0x50_0000),
                    guest_len: 0x1000,
                    unit_stem: stem(0xbb),
                },
            ],
        }
    }

    fn record(va: u64, segment: Option<u32>, coverage: SegmentCoverage, n: u64) -> CensusRecord {
        CensusRecord {
            guest_va: GuestVa(va),
            segment,
            coverage,
            translations: n,
        }
    }

    /// Two processes running the SAME image over the SAME blocks: the whole
    /// point of the instrument is that this reads as redundancy a shared unit
    /// could have served, not as twice the distinct code.
    fn two_process_scan() -> CensusScan {
        let records = vec![
            record(0x40_0010, Some(0), SegmentCoverage::Contained, 1),
            record(0x40_0080, Some(0), SegmentCoverage::Contained, 1),
            record(0x50_0f00, Some(1), SegmentCoverage::EntryOnly, 1),
            record(0x7f_0000, None, SegmentCoverage::Outside, 1),
        ];
        CensusScan {
            files: vec![
                CensusFile {
                    pid: 10,
                    sequence: 0,
                    reason: CensusFlush::ProcessExit,
                    total: 4,
                    image: Some(image("cafe")),
                    records: records.clone(),
                    store: lane_off_store(4),
                },
                CensusFile {
                    pid: 11,
                    sequence: 0,
                    reason: CensusFlush::ProcessExit,
                    total: 4,
                    image: Some(image("cafe")),
                    records,
                    store: lane_off_store(4),
                },
            ],
            failures: Vec::new(),
        }
    }

    #[test]
    fn redundancy_is_bracketed_by_the_two_distinctness_scopes() {
        let report = aggregate(&two_process_scan(), 8, None);
        assert_eq!(report.translations.total, 8);
        assert_eq!(report.translations.recorded, 8);
        // Four distinct VAs, four distinct scoped blocks (one image), so both
        // ends of the bracket agree here: 8 translations over 4 blocks.
        assert_eq!(report.translations.distinct_guest_vas, 4);
        assert_eq!(report.translations.distinct_scoped_blocks, 4);
        assert!((report.translations.redundancy_upper - 2.0).abs() < f64::EPSILON);
        assert!((report.translations.redundancy_lower - 2.0).abs() < f64::EPSILON);
    }

    #[test]
    fn distinct_scoping_separates_two_images_that_alias_the_same_pie_vas() {
        let mut scan = two_process_scan();
        // Same VAs, DIFFERENT image: the fixed PIE base makes the VA union
        // under-count distinct code, so `distinct_guest_vas` must stay 4 while
        // the scoped count doubles.
        if let Some(file) = scan.files.get_mut(1) {
            let mut other = image("beef");
            if let Some(segment) = other.segments.get_mut(0) {
                segment.unit_stem = stem(0xcc);
            }
            if let Some(segment) = other.segments.get_mut(1) {
                segment.unit_stem = stem(0xdd);
            }
            file.image = Some(other);
        }
        let report = aggregate(&scan, 8, None);
        assert_eq!(report.translations.distinct_guest_vas, 4);
        assert_eq!(report.translations.distinct_scoped_blocks, 8);
        assert!(report.translations.redundancy_lower < report.translations.redundancy_upper);
    }

    #[test]
    fn coverage_reports_the_lookup_ceiling_and_the_contained_share_separately() {
        let report = aggregate(&two_process_scan(), 8, None);
        assert_eq!(report.coverage.contained.translations, 4);
        assert_eq!(report.coverage.contained.blocks, 2);
        assert_eq!(report.coverage.entry_only.translations, 2);
        assert_eq!(report.coverage.outside.translations, 2);
        // 6 of 8 translations have their entry inside a segment; only 4 of 8
        // are wholly contained. Reporting either alone would misstate the
        // ceiling in one direction or the other.
        assert!((report.coverage.inside_segment_share_of_translations - 0.75).abs() < 1e-9);
        assert!((report.coverage.contained_share_of_translations - 0.5).abs() < 1e-9);
        assert!((report.coverage.inside_segment_share_of_blocks - 0.75).abs() < 1e-9);
        assert!((report.coverage.contained_share_of_blocks - 0.5).abs() < 1e-9);
    }

    #[test]
    fn unit_keys_count_configured_and_translated_into_separately() {
        let report = aggregate(&two_process_scan(), 8, None);
        // Both segments are configured; both were translated into.
        assert_eq!(report.unit_keys.configured, 2);
        assert_eq!(report.unit_keys.translated_into, 2);
        assert_eq!(report.unit_keys.unserializable_segments, 0);
        let top = report.unit_keys.per_key.first().cloned();
        let top = match top {
            Some(top) => top,
            None => panic!("expected a per-key tally"),
        };
        assert_eq!(top.stem, stem(0xaa));
        assert_eq!(top.translations, 4);
        assert_eq!(top.blocks, 2);
        // Two processes translated into it: that is the reuse a published unit
        // would have served.
        assert_eq!(top.incarnations, 2);
    }

    #[test]
    fn a_segment_whose_key_could_not_be_serialized_is_not_counted_as_a_key() {
        let mut scan = two_process_scan();
        for file in &mut scan.files {
            if let Some(image) = file.image.as_mut()
                && let Some(segment) = image.segments.get_mut(1)
            {
                segment.unit_stem = ABSENT_TOKEN.to_string();
            }
        }
        let report = aggregate(&scan, 8, None);
        assert_eq!(report.unit_keys.configured, 1);
        assert_eq!(report.unit_keys.translated_into, 1);
        assert_eq!(report.unit_keys.unserializable_segments, 2);
        // The blocks are still counted — they just cannot be attributed to a
        // publishable key, so they fall back to the image scope.
        assert_eq!(report.translations.total, 8);
    }

    #[test]
    fn per_key_truncation_reports_what_it_omitted() {
        let report = aggregate(&two_process_scan(), 1, None);
        assert_eq!(report.unit_keys.per_key.len(), 1);
        assert_eq!(report.unit_keys.per_key_omitted, 1);
        // The count itself is never truncated: it is the Phase 0 answer.
        assert_eq!(report.unit_keys.translated_into, 2);
    }

    /// The shape the live fixture produced: one pid-1 exit, plus two fork+exec
    /// children that each flush before the host self-re-exec and again at exit
    /// under the SAME pid.
    fn fork_exec_scan() -> CensusScan {
        let one = |pid: i32, sequence: u64, reason: CensusFlush| CensusFile {
            pid,
            sequence,
            reason,
            total: 1,
            image: Some(image("cafe")),
            records: vec![record(0x40_0010, Some(0), SegmentCoverage::Contained, 1)],
            store: lane_off_store(1),
        };
        CensusScan {
            files: vec![
                one(1, 0, CensusFlush::ProcessExit),
                one(2, 0, CensusFlush::HostSelfReexec),
                one(2, 0, CensusFlush::ProcessExit),
                one(3, 0, CensusFlush::HostSelfReexec),
                one(3, 0, CensusFlush::ProcessExit),
            ],
            failures: Vec::new(),
        }
    }

    #[test]
    fn flush_lineage_balances_when_every_incarnation_was_seen_out() {
        let report = aggregate(&fork_exec_scan(), 8, None);
        assert_eq!(report.processes.census_files, 5);
        assert_eq!(report.processes.distinct_pids, 3);
        assert_eq!(report.processes.incarnations, 5);
        assert_eq!(report.processes.flush_balance, 0);
        assert_eq!(report.processes.reexec_successors_missing, 0);
        assert_eq!(report.processes.sequence_anomalies, 0);
        assert_eq!(report.processes.flushes.get("process-exit"), Some(&3));
        assert_eq!(report.processes.flushes.get("host-self-reexec"), Some(&2));
    }

    #[test]
    fn a_re_exec_successor_that_never_flushed_is_reported_not_swallowed() {
        let mut scan = fork_exec_scan();
        // Drop pid 3's post-exec incarnation: it translated and then died by a
        // fatal signal, which the census cannot cover.
        scan.files
            .retain(|file| !(file.pid == 3 && matches!(file.reason, CensusFlush::ProcessExit)));
        let report = aggregate(&scan, 8, None);
        assert_eq!(report.processes.incarnations, 4);
        assert_eq!(report.processes.reexec_successors_missing, 1);
        // The balance identity alone would NOT catch this one — the handoff
        // accounts for the incarnation — which is why both checks exist.
        assert_eq!(report.processes.flush_balance, 0);
    }

    #[test]
    fn an_incarnation_that_died_after_an_in_process_exec_shows_as_a_balance_deficit() {
        let mut scan = fork_exec_scan();
        if let Some(file) = scan.files.get_mut(0) {
            file.reason = CensusFlush::InProcessExec;
        }
        let report = aggregate(&scan, 8, None);
        assert_eq!(report.processes.flush_balance, 1);
    }

    /// The shape the writer used to produce: a `fork` child inheriting a
    /// non-zero `FLUSH_SEQUENCE` from a parent that had already `execve`d in
    /// place. It leaves a pid with a `seq=1` file and no `seq=0` start.
    ///
    /// The writer bug is fixed (`xlat_census::reset_after_fork` now zeroes the
    /// ordinal), so this can only arrive from a directory mixing runs — but it
    /// must read as LOSS, loudly, in both directions. It used to read as three
    /// silent lies at once: fewer incarnations, a negative balance, and phantom
    /// missing successors, with `sequence_anomalies` staying 0 throughout.
    #[test]
    fn a_file_with_no_seq_zero_start_reads_as_loss_in_both_directions() {
        let mut scan = fork_exec_scan();
        // pid 1 exits at seq=1 having never written a seq=0 start.
        if let Some(file) = scan.files.get_mut(0) {
            file.sequence = 1;
        }
        let report = aggregate(&scan, 8, None);
        assert_eq!(report.processes.census_files, 5);
        assert_eq!(report.processes.incarnations, 4);
        assert_eq!(report.processes.flush_balance, -1);
        assert_eq!(report.processes.reexec_successors_missing, 1);
        assert_eq!(
            report.processes.coverage, None,
            "coverage stays absent unless an operator supplies a denominator"
        );
    }

    #[test]
    fn a_sequence_gap_within_one_pid_is_flagged() {
        let mut scan = fork_exec_scan();
        if let Some(file) = scan.files.get_mut(2) {
            file.sequence = 2;
        }
        let report = aggregate(&scan, 8, None);
        assert_eq!(report.processes.sequence_anomalies, 1);
    }

    #[test]
    fn supplying_an_external_denominator_reports_process_coverage() {
        let report = aggregate(&fork_exec_scan(), 8, Some(10));
        assert_eq!(report.processes.observed, Some(10));
        match report.processes.coverage {
            Some(coverage) => assert!((coverage - 0.5).abs() < 1e-9),
            None => panic!("expected a coverage fraction"),
        }
        let without = aggregate(&fork_exec_scan(), 8, None);
        assert_eq!(without.processes.coverage, None);
    }

    #[test]
    fn a_file_whose_records_disagree_with_its_header_total_is_flagged() {
        let mut scan = two_process_scan();
        if let Some(file) = scan.files.get_mut(0) {
            file.total = 99;
        }
        let report = aggregate(&scan, 8, None);
        assert_eq!(report.files.inconsistent_totals, 1);
        // The header total is still what `total` sums: it is the runtime's own
        // translation count, and the records are the derived view.
        assert_eq!(report.translations.total, 103);
        assert_eq!(report.translations.recorded, 8);
    }

    #[test]
    fn a_record_naming_a_segment_its_file_does_not_define_is_flagged() {
        let mut scan = two_process_scan();
        if let Some(file) = scan.files.get_mut(0) {
            file.records
                .push(record(0x60_0000, Some(9), SegmentCoverage::Contained, 1));
            file.total = file.total.saturating_add(1);
        }
        let report = aggregate(&scan, 8, None);
        assert_eq!(report.files.dangling_segment_references, 1);
    }

    #[test]
    fn scan_dir_round_trips_what_the_runtime_renders_and_fails_closed_on_junk() {
        let dir = match tempfile::tempdir() {
            Ok(dir) => dir,
            Err(error) => panic!("tempdir: {error}"),
        };
        let scan = two_process_scan();
        for (index, file) in scan.files.iter().enumerate() {
            let path = dir.path().join(format!("xlat-{}-0-{index}.txt", file.pid));
            if let Err(error) = std::fs::write(&path, file.render()) {
                panic!("write {}: {error}", path.display());
            }
        }
        // A non-census file in the directory is ignored, a malformed census
        // file is reported.
        if let Err(error) = std::fs::write(dir.path().join("notes.md"), "ignore me") {
            panic!("write notes: {error}");
        }
        if let Err(error) = std::fs::write(dir.path().join("xlat-bogus.txt"), "NOTACENSUS|\n") {
            panic!("write bogus: {error}");
        }
        let read = match scan_dir(dir.path()) {
            Ok(read) => read,
            Err(error) => panic!("scan_dir: {error}"),
        };
        assert_eq!(read.files, scan.files);
        assert_eq!(read.failures.len(), 1);
        let report = aggregate(&read, 8, None);
        assert_eq!(report.files.parsed, 2);
        assert_eq!(report.files.failed.len(), 1);
        // The aggregate over what parsed still matches the in-memory one.
        assert_eq!(report.translations.total, 8);
        // …and the subcommand as a whole fails, so a gate cannot read a partial
        // census as a complete one.
        assert!(run_xlat_census(dir.path(), 8, None).is_err());
    }

    #[test]
    fn an_empty_directory_is_an_error_not_a_report_of_zeros() {
        let dir = match tempfile::tempdir() {
            Ok(dir) => dir,
            Err(error) => panic!("tempdir: {error}"),
        };
        assert!(scan_dir(dir.path()).is_err());
    }

    /// The default path: the shared lane is opt-in, so the store is never
    /// reached at all. This must NOT read as "the store missed" — the fix for
    /// one is configuration, the fix for the other is persistence.
    #[test]
    fn a_run_that_never_consulted_the_store_is_not_a_run_that_missed() {
        let report = aggregate(&two_process_scan(), 8, None);
        assert_eq!(report.store.lookups, 8);
        assert_eq!(report.store.consulted, 0);
        assert_eq!(report.store.skipped_total, 8);
        assert_eq!(
            report
                .store
                .skipped
                .get(LookupSkip::LaneUnconfigured.token()),
            Some(&8)
        );
        assert!(report.store.consulted_share_of_lookups.abs() < f64::EPSILON);
        assert_eq!(report.store.miss_total, 0);
        assert_eq!(report.store.file_miss, 0);
        assert_eq!(report.store.processes_that_translated, 2);
        assert_eq!(report.store.processes_that_consulted, 0);
        assert_eq!(report.store.processes_without_authority, 0);
    }

    /// The three explanations for "one key in the cache directory", side by
    /// side in one run: a process that held no authority, a process that
    /// consulted and missed on disk, and a process that never consulted.
    #[test]
    fn store_outcomes_separate_no_authority_from_a_file_miss() {
        let mut scan = two_process_scan();
        if let Some(file) = scan.files.get_mut(0) {
            file.store = CensusStore {
                consulted: 2,
                loaded: 0,
                file_miss: 0,
                recording_claimed: 0,
                recording_declined: 0,
                skipped: BTreeMap::from([(LookupSkip::SegmentRepeat, 2)]),
                misses: BTreeMap::from([(UnitMissReason::NoAuthority, 2)]),
                load_ns: 0,
                publish_ns: 0,
            };
        }
        if let Some(file) = scan.files.get_mut(1) {
            file.store = CensusStore {
                consulted: 2,
                loaded: 1,
                file_miss: 1,
                recording_claimed: 0,
                recording_declined: 1,
                skipped: BTreeMap::from([(LookupSkip::OutsideSegment, 2)]),
                misses: BTreeMap::new(),
                load_ns: 3_000_000,
                publish_ns: 0,
            };
        }
        let report = aggregate(&scan, 8, None);
        assert_eq!(report.store.lookups, 8);
        assert_eq!(report.store.consulted, 4);
        assert_eq!(report.store.skipped_total, 4);
        assert!((report.store.consulted_share_of_lookups - 0.5).abs() < 1e-9);
        // The whole point: these are different buckets, not one.
        assert_eq!(
            report.store.misses.get(UnitMissReason::NoAuthority.token()),
            Some(&2)
        );
        assert_eq!(report.store.file_miss, 1);
        assert_eq!(report.store.loaded, 1);
        assert_eq!(report.store.processes_without_authority, 1);
        assert_eq!(report.store.processes_that_loaded, 1);
        assert_eq!(report.store.processes_that_consulted, 2);
        // …and the recorder election declined the only miss it saw, which is
        // the answer to "why was nothing published" for this run.
        assert_eq!(report.store.recording_claimed, 0);
        assert_eq!(report.store.recording_declined, 1);
        assert_eq!(report.store.processes_that_claimed_recording, 0);
        // Both skip reasons survive aggregation under their own tokens.
        assert_eq!(
            report.store.skipped.get(LookupSkip::SegmentRepeat.token()),
            Some(&2)
        );
        assert_eq!(
            report.store.skipped.get(LookupSkip::OutsideSegment.token()),
            Some(&2)
        );
    }

    /// A process whose lookups all HIT performs no fresh translation, so its
    /// header total is 0. It still has to be counted, or the successful arm is
    /// the one the report loses.
    #[test]
    fn a_process_that_only_loaded_units_is_still_counted() {
        let mut scan = two_process_scan();
        scan.files.push(CensusFile {
            pid: 12,
            sequence: 0,
            reason: CensusFlush::ProcessExit,
            total: 0,
            image: Some(image("cafe")),
            records: Vec::new(),
            store: CensusStore {
                consulted: 1,
                loaded: 1,
                ..CensusStore::default()
            },
        });
        let report = aggregate(&scan, 8, None);
        assert_eq!(report.translations.total, 8);
        assert_eq!(report.store.loaded, 1);
        assert_eq!(report.store.processes_that_loaded, 1);
        assert_eq!(report.store.processes_that_translated, 3);
        // It contributed no records, so the coverage numbers are unmoved.
        assert_eq!(report.translations.distinct_scoped_blocks, 4);
    }

    #[test]
    fn the_report_serializes_under_its_schema_tag() {
        let report = aggregate(&two_process_scan(), 8, None);
        let json = match serde_json::to_value(&report) {
            Ok(json) => json,
            Err(error) => panic!("serialize: {error}"),
        };
        assert_eq!(json["schema"], REPORT_SCHEMA);
        assert_eq!(json["translations"]["total"], 8);
        assert_eq!(json["unit_keys"]["configured"], 2);
        assert_eq!(json["processes"]["incarnations"], 2);
        assert_eq!(json["store"]["lookups"], 8);
        assert_eq!(json["store"]["skipped"]["lane-unconfigured"], 8);
    }
}
