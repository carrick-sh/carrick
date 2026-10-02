//! Strict namespace census reader. Counts use DTrace aggregations, never
//! concurrently incremented global scalar counters.
use anyhow::{Result, anyhow, bail};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub(crate) const BUNDLED_PROGRAM: &str =
    include_str!("../../../scripts/dtrace/host-namespace-work.d");
pub(crate) fn program_sha256() -> String {
    format!("{:x}", Sha256::digest(BUNDLED_PROGRAM.as_bytes()))
}

/// The fixture pins one distinct guest directory fd for each live actor.
/// These numbers are guest capabilities, never host descriptor identities.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct NamespaceActorFd(u32);
impl NamespaceActorFd {
    pub(crate) fn from_positive(value: u32) -> Result<Self> {
        if value == 0 || value > i32::MAX as u32 {
            bail!("invalid actor directory capability");
        }
        Ok(Self(value))
    }
}
fn actor(field: &str) -> Result<NamespaceActorFd> {
    let text = field
        .strip_prefix("actor=")
        .ok_or_else(|| anyhow!("missing actor capability"))?;
    let value = text.parse::<u32>()?;
    if value.to_string() != text {
        bail!("noncanonical actor capability");
    }
    NamespaceActorFd::from_positive(value)
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct NamespaceCensus {
    pub(crate) calls: BTreeMap<(NamespaceActorFd, String), u64>,
    pub(crate) host_calls: BTreeMap<(NamespaceActorFd, String, String), u64>,
    pub(crate) visits: BTreeMap<(NamespaceActorFd, String, String), u64>,
}

fn count(field: &str) -> Result<u64> {
    let value = field
        .strip_prefix("count=")
        .ok_or_else(|| anyhow!("missing count"))?;
    let parsed = value.parse::<u64>()?;
    if parsed.to_string() != value {
        bail!("noncanonical count");
    }
    Ok(parsed)
}

fn operation(field: &str) -> Result<String> {
    let op = field
        .strip_prefix("op=")
        .ok_or_else(|| anyhow!("missing operation"))?;
    if !["renameat", "unlinkat", "linkat", "openat"].contains(&op) {
        bail!("unknown namespace operation {op}");
    }
    Ok(op.to_owned())
}

pub(crate) fn validate(raw: &str, scale: u64) -> Result<NamespaceCensus> {
    if ![1, 8, 32, 128].contains(&scale) {
        bail!("unregistered namespace scale");
    }
    let header = format!("NSWORK1|header|program_sha256={}", program_sha256());
    let mut header_seen = false;
    let mut summary = false;
    let mut calls = BTreeMap::<(NamespaceActorFd, String), [Option<u64>; 3]>::new();
    let mut host = BTreeMap::<(NamespaceActorFd, String, String), [Option<u64>; 2]>::new();
    let mut visits = BTreeMap::new();
    for line in raw.lines().filter(|line| !line.is_empty()) {
        if !header_seen {
            if line != header {
                bail!("namespace census has no qualified program digest");
            }
            header_seen = true;
            continue;
        }
        if line == "NSWORK1|summary|seen=1|errors=0|code=0|bounded=0" {
            if summary {
                bail!("duplicate namespace terminal receipt");
            }
            summary = true;
            continue;
        }
        if !summary {
            bail!("namespace census lacks clean terminal receipt");
        }
        let fields = line.split('|').collect::<Vec<_>>();
        match fields.as_slice() {
            [
                "NSWORK1",
                phase @ ("begin" | "end" | "armed"),
                anchor,
                op,
                value,
            ] => {
                let op = operation(op)?;
                let value = count(value)?;
                if value == 0 {
                    bail!("empty namespace request population");
                }
                let row = calls.entry((actor(anchor)?, op)).or_default();
                let slot = match *phase {
                    "begin" => 0,
                    "end" => 1,
                    _ => 2,
                };
                if row[slot].replace(value).is_some() {
                    bail!("duplicate request phase");
                }
            }
            [
                "NSWORK1",
                phase @ ("host-begin" | "host-end"),
                anchor,
                op,
                name,
                value,
            ] => {
                let op = operation(op)?;
                let name = name
                    .strip_prefix("name=")
                    .ok_or_else(|| anyhow!("missing host call name"))?;
                if name.is_empty() || !name.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_')
                {
                    bail!("invalid host call name");
                }
                let value = count(value)?;
                if value == 0 {
                    bail!("empty host call population");
                }
                let row = host
                    .entry((actor(anchor)?, op, name.to_owned()))
                    .or_default();
                let slot = usize::from(*phase == "host-end");
                if row[slot].replace(value).is_some() {
                    bail!("duplicate host phase");
                }
            }
            ["NSWORK1", "visit", anchor, op, stage, value] => {
                let op = operation(op)?;
                let stage = stage
                    .strip_prefix("stage=")
                    .ok_or_else(|| anyhow!("missing path stage"))?;
                if !["dentry", "host-parent", "host-leaf"].contains(&stage) {
                    bail!("unknown path stage");
                }
                if visits
                    .insert((actor(anchor)?, op, stage.to_owned()), count(value)?)
                    .is_some()
                {
                    bail!("duplicate path census");
                }
            }
            _ => bail!("malformed namespace census row {line:?}"),
        }
    }
    if !summary || calls.len() != 8 || host.is_empty() || visits.len() != 24 {
        bail!("incomplete namespace census");
    }
    let mut closed = BTreeMap::new();
    let actors = calls
        .keys()
        .map(|(actor, _)| *actor)
        .collect::<BTreeSet<_>>();
    if actors.len() != 2 {
        bail!("namespace census requires exactly two actor capabilities");
    }
    for ((actor, op), phases) in calls {
        let [Some(begin), Some(end), Some(armed)] = phases else {
            bail!("missing namespace request phase");
        };
        let expected = scale;
        if begin != end || begin != armed || begin != expected {
            bail!("namespace {op} request population does not close at scale {scale}");
        }
        for stage in ["dentry", "host-parent", "host-leaf"] {
            if !visits.contains_key(&(actor, op.clone(), stage.to_owned())) {
                bail!("missing namespace path census");
            }
        }
        closed.insert((actor, op), begin);
    }
    let mut host_calls = BTreeMap::new();
    for (key, phases) in host {
        let [Some(begin), Some(end)] = phases else {
            bail!("missing host call phase");
        };
        if begin != end {
            bail!("host call phases do not close");
        }
        host_calls.insert(key, begin);
    }
    for actor in actors {
        for op in ["renameat", "unlinkat", "linkat", "openat"] {
            if !closed.contains_key(&(actor, op.to_owned())) {
                bail!("missing actor operation");
            }
        }
        if host_calls.get(&(actor, "openat".to_owned(), "openat".to_owned())) != Some(&scale) {
            bail!("namespace open requires one real backend open per completed request");
        }
    }
    Ok(NamespaceCensus {
        calls: closed,
        host_calls,
        visits,
    })
}

pub(crate) fn render_profile_script() -> Result<String> {
    const PLACEHOLDER: &str = "/* CARRICK_NSWORK_PROGRAM_SHA256 */";
    if BUNDLED_PROGRAM.matches(PLACEHOLDER).count() != 1 {
        bail!("namespace template digest marker is not unique");
    }
    Ok(BUNDLED_PROGRAM.replacen(PLACEHOLDER, &program_sha256(), 1))
}

pub(crate) fn fixture_scale(command: &[String]) -> Result<u64> {
    let [.., image, shell, flag, payload] = command else {
        bail!("namespace census requires the shell fixture command");
    };
    if command.first().map(String::as_str) != Some("run")
        || !image.split_once("@sha256:").is_some_and(|(_, digest)| {
            digest.len() == 64
                && digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
    {
        bail!("namespace census requires a digest-pinned run image");
    }
    if shell != "/bin/sh" || flag != "-c" {
        bail!("namespace census requires /bin/sh -c");
    }
    let parts = payload.split_ascii_whitespace().collect::<Vec<_>>();
    let ["/p/perf_namespace_scale", scale, population, parents] = parts.as_slice() else {
        bail!("namespace census requires perf_namespace_scale with three arguments");
    };
    let n = scale.parse::<u64>()?;
    if ![1, 8, 32, 128].contains(&n)
        || n.to_string() != *scale
        || !["0", "128"].contains(population)
        || !["same", "unrelated"].contains(parents)
    {
        bail!("unregistered namespace census fixture parameters");
    }
    Ok(n)
}
