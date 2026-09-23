//! Completed host-service census for the pinned, three-million-pair inotify09.
//! These counts exclude EL1/engine fast paths and are not elapsed-time evidence.

use std::collections::BTreeMap;

use anyhow::{Result, anyhow, bail};
use sha2::{Digest, Sha256};

pub(crate) const BUNDLED_PROGRAM: &str =
    include_str!("../../../scripts/dtrace/hvpatch-inotify09-completed-population.d");
const PROGRAM_SHA256_PLACEHOLDER: &str = "/* CARRICK_SYSCALLPOP_PROGRAM_SHA256 */";
const EXPECTED_PAIRS: u64 = 3_000_000;

pub(crate) fn program_sha256() -> String {
    format!("{:x}", Sha256::digest(BUNDLED_PROGRAM.as_bytes()))
}

pub(crate) fn render_profile_script() -> Result<String> {
    if BUNDLED_PROGRAM.matches(PROGRAM_SHA256_PLACEHOLDER).count() != 1 {
        bail!("SYSCALLPOP1 template must contain one program digest placeholder");
    }
    Ok(BUNDLED_PROGRAM.replacen(PROGRAM_SHA256_PLACEHOLDER, &program_sha256(), 1))
}

fn canonical_u64(field: &str, prefix: &str) -> Result<u64> {
    let text = field
        .strip_prefix(prefix)
        .ok_or_else(|| anyhow!("SYSCALLPOP1 missing field prefix {prefix}"))?;
    let value = text.parse::<u64>()?;
    if value.to_string() != text {
        bail!("SYSCALLPOP1 noncanonical integer {text:?}");
    }
    Ok(value)
}

/// Validate every emitted row, including startup syscalls. A missing service
/// end is an error for this profile, not a row to discard. Other workloads may
/// legitimately leave waits unmatched and require a different contract.
pub(crate) fn validate(raw: &str) -> Result<BTreeMap<u64, u64>> {
    let expected_header = format!("SYSCALLPOP1|header|program_sha256={}", program_sha256());
    let mut header_seen = false;
    let mut completion_seen = false;
    let mut rows: BTreeMap<u64, [Option<u64>; 3]> = BTreeMap::new();
    for line in raw.lines().filter(|line| !line.trim().is_empty()) {
        if !header_seen {
            if line != expected_header {
                bail!("SYSCALLPOP1 missing or stale program digest header");
            }
            header_seen = true;
            continue;
        }
        if !completion_seen {
            if line != "SYSCALLPOP1|seen=1|errors=0|root_exited=1" {
                bail!("SYSCALLPOP1 missing clean completed-root receipt");
            }
            completion_seen = true;
            continue;
        }
        let fields: Vec<_> = line.split('|').collect();
        let ["SYSCALLPOP1", tag, nr, count] = fields.as_slice() else {
            bail!("SYSCALLPOP1 malformed population row {line:?}");
        };
        let slot = match *tag {
            "begin" => 0,
            "args" => 1,
            "end" => 2,
            _ => bail!("SYSCALLPOP1 unknown population tag {tag:?}"),
        };
        let nr = canonical_u64(nr, "nr=")?;
        let count = canonical_u64(count, "count=")?;
        if count == 0 {
            bail!("SYSCALLPOP1 zero population for syscall {nr}");
        }
        let row = rows.entry(nr).or_default();
        if row[slot].replace(count).is_some() {
            bail!("SYSCALLPOP1 duplicate {tag} row for syscall {nr}");
        }
    }
    if !header_seen || !completion_seen || rows.is_empty() {
        bail!("SYSCALLPOP1 incomplete or empty capture");
    }
    let mut closed = BTreeMap::new();
    let mut total = 0_u64;
    for (nr, row) in rows {
        let [Some(begin), Some(args), Some(end)] = row else {
            bail!("SYSCALLPOP1 missing population phase for syscall {nr}");
        };
        if begin != args || begin != end {
            bail!("SYSCALLPOP1 population mismatch for syscall {nr}");
        }
        total = total
            .checked_add(begin)
            .ok_or_else(|| anyhow!("SYSCALLPOP1 total population overflow"))?;
        closed.insert(nr, begin);
    }
    for nr in [27, 28] {
        if closed.get(&nr) != Some(&EXPECTED_PAIRS) {
            bail!(
                "SYSCALLPOP1 syscall {nr} must complete {EXPECTED_PAIRS} services for pinned inotify09"
            );
        }
    }
    Ok(closed)
}
