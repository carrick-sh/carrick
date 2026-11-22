//! `carrick debug venue-gaps` (#1906): diff a workload's native-oracle
//! syscall profile against Carrick's routing, for the run root and for a
//! native child, on both ISAs.
//!
//! The profile is the map dump of `scripts/bpftrace/oracle-venue-profile.bt`
//! (`scripts/conformance/oracle-venue-profile.sh` records it). Each key is a
//! caller (root or native child), a native syscall number and the two
//! arguments that choose Carrick's route (mmap flags and prot, socket domain
//! and type, ...). The route is the personality's own static decision: the
//! ring family a native task's venue selects (`ServiceOwner::family_for_venue`), the native host-file venue
//! ([`HostFileCall::decode_native`] and `admitted_for`), then the crossing
//! allowlist. A native child has no host fallback, so a crossing it cannot
//! stage is a gap. A ring family can still decline a shape at run time (an
//! mmap flag the reservation owner does not carry), so a census of the same
//! workload, when given, adds the counted refusals Carrick actually made.
use carrick_guest_arch::{GuestIsa, NativeOrdinal};
use carrick_personality_linux::crossing::{AllowedHostCrossing, HostCrossingKind};
use carrick_personality_linux::dispatch::{Family, service_owner};
use carrick_personality_linux::native_host_file::HostFileCall;
use carrick_spec::syscall_census::{CallerClass, CensusIsa};
use carrick_syscall_abi::CanonicalNr;
use std::collections::BTreeMap;
use std::fmt::Write as _;

/// The profile's ISA code (`<isa>` argument of the bpftrace script).
fn isa_of_code(code: u64) -> Option<GuestIsa> {
    match code {
        0 => Some(GuestIsa::X86_64),
        1 => Some(GuestIsa::Aarch64),
        _ => None,
    }
}

pub fn isa_name(isa: GuestIsa) -> &'static str {
    match isa {
        GuestIsa::X86_64 => "x86_64",
        GuestIsa::Aarch64 => "aarch64",
    }
}

fn caller_name(caller: CallerClass) -> &'static str {
    match caller {
        CallerClass::Root => "root",
        CallerClass::NativeChild => "child",
    }
}

/// One profile key: who called what, with which route-choosing arguments.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ShapeKey {
    pub child: bool,
    pub nr: u64,
    pub s0: u64,
    pub s1: u64,
}

impl ShapeKey {
    pub fn caller(self) -> CallerClass {
        if self.child {
            CallerClass::NativeChild
        } else {
            CallerClass::Root
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ShapeCounts {
    pub calls: u64,
    pub enosys: u64,
    pub errors: u64,
}

/// One recorded oracle profile.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Profile {
    pub isa_code: u64,
    pub shapes: BTreeMap<ShapeKey, ShapeCounts>,
    /// Exits with no traced entry, by (child, nr, return): Docker's seccomp
    /// refusals, plus the root's stopping `kill` and each child's first
    /// return from `clone`/`fork`.
    pub unentered: BTreeMap<(bool, u64, i64), u64>,
    /// bpftrace warnings (a lost first insert can undercount a key by one).
    pub warnings: usize,
}

fn parse_key(text: &str) -> Result<Vec<i64>, String> {
    text.split(',')
        .map(|part| {
            part.trim()
                .parse::<i64>()
                .or_else(|_| part.trim().parse::<u64>().map(|v| v as i64))
                .map_err(|e| format!("bad key `{part}`: {e}"))
        })
        .collect()
}

/// Parse the map dump. Fails closed on a profile that did not complete
/// naturally (bound hit, observer error, or no ready/complete markers).
pub fn parse_profile(text: &str) -> Result<Profile, String> {
    let mut profile = Profile::default();
    let mut ready = None;
    let mut complete = false;
    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("VENUEPROFILE1|") {
            if rest.starts_with("error") {
                return Err(format!("profile did not complete: {line}"));
            }
            if rest.starts_with("ready") {
                let isa = rest
                    .split('|')
                    .find_map(|f| f.strip_prefix("isa="))
                    .ok_or("ready marker has no isa")?;
                ready = Some(isa.parse::<u64>().map_err(|e| e.to_string())?);
            }
            if rest.starts_with("complete") {
                complete = true;
            }
            continue;
        }
        if line.contains("WARNING") {
            profile.warnings += 1;
            continue;
        }
        let Some((map, rest)) = line.split_once('[') else {
            continue;
        };
        let Some((key, value)) = rest.split_once("]:") else {
            continue;
        };
        let value: u64 = value
            .trim()
            .parse()
            .map_err(|e| format!("bad count in `{line}`: {e}"))?;
        let key = parse_key(key)?;
        match (map, key.as_slice()) {
            ("@calls" | "@enosys" | "@errors", [caller, nr, s0, s1]) => {
                let shape = ShapeKey {
                    child: *caller != 0,
                    nr: *nr as u64,
                    s0: *s0 as u64,
                    s1: *s1 as u64,
                };
                let entry = profile.shapes.entry(shape).or_default();
                match map {
                    "@calls" => entry.calls += value,
                    "@enosys" => entry.enosys += value,
                    _ => entry.errors += value,
                }
            }
            ("@unentered", [caller, nr, ret]) => {
                *profile
                    .unentered
                    .entry((*caller != 0, *nr as u64, *ret))
                    .or_default() += value;
            }
            _ => return Err(format!("unexpected profile line `{line}`")),
        }
    }
    profile.isa_code = ready.ok_or("profile has no VENUEPROFILE1|ready marker")?;
    if !complete {
        return Err("profile has no VENUEPROFILE1|complete marker".into());
    }
    Ok(profile)
}

/// Where Carrick serves one call for one caller.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Route {
    /// A wired in-ring family.
    Ring(String),
    /// Staged through the caller's native host-file venue.
    HostFile,
    /// A host crossing the root may take.
    Crossing(HostCrossingKind),
    /// An ISA-private call the backend serves itself (x86 `arch_prctl`).
    IsaNative,
    /// An ISA-private call another ISA's build never makes.
    NotOnIsa,
    /// A refusal the ring-coverage registry (#1906) accepts: the libc
    /// falls back on ENOSYS (`rseq`).
    AcceptedEnosys,
    /// A crossing a native child cannot take: answered ENOSYS.
    RootOnlyCrossing(HostCrossingKind),
    /// Neither ring nor crossing: a counted ENOSYS.
    CountedEnosys,
}

impl Route {
    pub fn is_gap(&self) -> bool {
        matches!(self, Self::RootOnlyCrossing(_) | Self::CountedEnosys)
    }

    pub fn label(&self) -> String {
        match self {
            Self::Ring(family) => format!("ring {family}"),
            Self::HostFile => "host-file venue".into(),
            Self::Crossing(kind) => format!("crossing ({kind:?})"),
            Self::IsaNative => "ISA-native".into(),
            Self::NotOnIsa => "n/a (other ISA's call)".into(),
            Self::AcceptedEnosys => "ENOSYS (accepted, #1906)".into(),
            Self::RootOnlyCrossing(kind) => format!("**ENOSYS** (root-only {kind:?} crossing)"),
            Self::CountedEnosys => "**ENOSYS** (unrouted)".into(),
        }
    }
}

pub fn syscall_name(isa: GuestIsa, nr: u64) -> String {
    let name = match isa {
        GuestIsa::X86_64 => X86_LEGACY_NAMES
            .iter()
            .find(|(n, _)| *n == nr)
            .map(|(_, name)| *name)
            .or_else(|| carrick_syscall_abi::syscall_x86_64::lookup_x86_64(nr).map(|s| s.name)),
        GuestIsa::Aarch64 => carrick_abi::syscall::lookup_aarch64(nr).map(|s| s.name),
    };
    name.map_or_else(|| format!("nr{nr}"), str::to_owned)
}

/// x86 legacy calls `normalize_legacy` and the entry decode lower to an
/// `*at` or canonical owner, absent from the x86 table by design.
const X86_LEGACY_NAMES: &[(u64, &str)] = &[
    (2, "open"),
    (4, "stat"),
    (6, "lstat"),
    (21, "access"),
    (22, "pipe"),
    (33, "dup2"),
    (57, "fork"),
    (58, "vfork"),
    (82, "rename"),
    (83, "mkdir"),
    (84, "rmdir"),
    (85, "creat"),
    (86, "link"),
    (87, "unlink"),
    (88, "symlink"),
    (89, "readlink"),
    (90, "chmod"),
    (92, "chown"),
    (94, "lchown"),
    (111, "getpgrp"),
    (133, "mknod"),
    (201, "time"),
    (232, "epoll_wait"),
    (284, "eventfd"),
];

/// Canonical `rseq`: accepted as ENOSYS by the #1906 registry.
const ACCEPTED_RSEQ: u64 = 293;

/// Calls Linux serves in the vDSO, so the oracle's kernel never sees them,
/// as (x86 nr, aarch64 nr). A guest without that vDSO path makes them as
/// syscalls; the table lists their routes separately.
const VDSO_CALLS: &[(u64, u64)] = &[
    (228, 113),
    (229, 114),
    (96, 169),
    (201, u64::MAX),
    (309, 168),
];

/// The canonical number of a native call on its own ISA, if it has one.
fn canonical_of_profile(isa: GuestIsa, nr: u64) -> Option<u64> {
    match isa {
        GuestIsa::X86_64 => {
            let c = carrick_personality_linux::entry::decode_x86_64(nr, [0; 6], 0)
                .canonical
                .raw();
            (c != u64::MAX).then_some(c)
        }
        GuestIsa::Aarch64 => Some(nr),
    }
}

/// Native arguments carrying the recorded shape in the positions the
/// bpftrace script read it from (named, so one table serves both ISAs), a
/// non-stdio descriptor elsewhere. Pointers do not choose a route.
fn native_arguments(name: &str, shape: ShapeKey) -> [u64; 6] {
    const AT_FDCWD: u64 = -100i64 as u64;
    let mut a = [3, 0, 0, 0, 0, 0];
    match name {
        "mmap" => {
            a = [0, 4096, shape.s1 & 0xf, shape.s0, u64::MAX, 0];
            if shape.s1 & 0x100 != 0 {
                a[4] = 3;
            }
        }
        "mprotect" | "madvise" | "msync" => a[2] = shape.s0,
        "mremap" => a[3] = shape.s0,
        "ioctl" | "fcntl" | "futex" | "epoll_ctl" | "prlimit64" | "pipe2" | "eventfd2" => {
            a[1] = shape.s0
        }
        "socket" | "socketpair" => a = [shape.s0, shape.s1, 0, 0, 0, 0],
        "setsockopt" | "getsockopt" => {
            a[1] = shape.s0;
            a[2] = shape.s1;
        }
        "clone" | "prctl" | "arch_prctl" | "clock_gettime" | "clock_getres" | "clock_nanosleep"
        | "timerfd_create" | "select" | "pselect6" | "waitid" => a[0] = shape.s0,
        "fadvise64" | "sendmmsg" | "recvmmsg" => a[3] = shape.s0,
        "openat" => a = [AT_FDCWD, 0, shape.s0, 0, 0, 0],
        "open" => a = [0, shape.s0, 0, 0, 0, 0],
        "poll" | "ppoll" => a[1] = shape.s0,
        "wait4" | "getrandom" | "sendmsg" | "recvmsg" => a[2] = shape.s0,
        _ => {}
    }
    a
}

/// The route of `shape` (recorded on `profile_isa`) when run on `isa`. The
/// x86 call goes through the production entry decode
/// (`carrick_personality_linux::entry::decode_x86_64`: legacy lowering,
/// fork/vfork, dup2, ...), so an x86 profile also answers the ARM route of
/// the same canonical operation.
pub fn route(profile_isa: GuestIsa, isa: GuestIsa, shape: ShapeKey) -> Route {
    let name = syscall_name(profile_isa, shape.nr);
    let native_args = native_arguments(&name, shape);
    let (canonical, args) = match profile_isa {
        GuestIsa::X86_64 => {
            if shape.nr == 158 {
                // arch_prctl: FS/GS base is the backend's hidden state.
                return if isa == GuestIsa::X86_64 {
                    Route::IsaNative
                } else {
                    Route::NotOnIsa
                };
            }
            let call = carrick_personality_linux::entry::decode_x86_64(shape.nr, native_args, 0);
            if call.canonical.raw() == u64::MAX {
                return Route::CountedEnosys;
            }
            (call.canonical, call.args)
        }
        GuestIsa::Aarch64 => {
            if carrick_abi::syscall::lookup_aarch64(shape.nr).is_none() {
                return Route::CountedEnosys;
            }
            (CanonicalNr::new(shape.nr), native_args)
        }
    };
    // An x86 private layout (fstat, poll, select, dup2, ...) runs on ARM as
    // its canonical twin, which is what an ARM build of the workload calls.
    let (canonical, native) = if isa == profile_isa {
        (canonical, shape.nr)
    } else {
        match isa {
            GuestIsa::Aarch64 => {
                let twin = carrick_personality_linux::dispatch::owner_ordinal(canonical);
                (twin, twin.raw())
            }
            // An ARM profile on x86: the canonical number is the identity.
            GuestIsa::X86_64 => (canonical, u64::MAX),
        }
    };
    if canonical.raw() == ACCEPTED_RSEQ {
        return Route::AcceptedEnosys;
    }
    let owner = service_owner(canonical, u64::MAX);
    // A native task's descriptor and poll owners are available on both ISAs.
    let family = owner.family_for_venue(isa, canonical, u64::MAX, true, true);
    if family != Family::Unported {
        return Route::Ring(format!("{family:?}"));
    }
    let origin = if shape.child {
        carrick_core_abi::service::ServiceOrigin::Descendant
    } else {
        carrick_core_abi::service::ServiceOrigin::Initial
    };
    if HostFileCall::decode_native(isa, NativeOrdinal::new(native), canonical, &args)
        .is_some_and(|call| call.admitted_for(origin, |fd| (0..=2).contains(&fd)))
    {
        return Route::HostFile;
    }
    let crossing = match isa {
        GuestIsa::X86_64 => AllowedHostCrossing::from_canonical_x86(canonical),
        GuestIsa::Aarch64 => AllowedHostCrossing::from_canonical_aarch64(canonical),
    };
    match (crossing.and_then(AllowedHostCrossing::kind), shape.child) {
        (Some(kind), false) => Route::Crossing(kind),
        // A child's exit and exit_group are served by its process owner.
        (Some(HostCrossingKind::Terminal), true) => Route::Ring("Lifecycle".into()),
        (Some(kind), true) => Route::RootOnlyCrossing(kind),
        // Unrouted, or owned by a ring family this ISA has not wired.
        (None, _) => Route::CountedEnosys,
    }
}

/// A shape's argument text, decoded for the calls whose route depends on it.
pub fn shape_text(isa: GuestIsa, shape: ShapeKey) -> String {
    let name = syscall_name(isa, shape.nr);
    match name.as_str() {
        "mmap" => {
            let mut flags = Vec::new();
            for (bit, n) in [
                (0x1, "SHARED"),
                (0x2, "PRIVATE"),
                (0x10, "FIXED"),
                (0x20, "ANON"),
                (0x100, "GROWSDOWN"),
                (0x4000, "NORESERVE"),
                (0x8000, "POPULATE"),
                (0x20000, "STACK"),
                (0x100000, "FIXED_NOREPLACE"),
            ] {
                if shape.s0 & bit != 0 {
                    flags.push(n);
                }
            }
            let file = if shape.s1 & 0x100 != 0 { " file" } else { "" };
            format!("{} prot={:#x}{file}", flags.join("|"), shape.s1 & 0xf)
        }
        "socket" | "socketpair" => {
            let domain = match shape.s0 {
                1 => "AF_UNIX".to_owned(),
                2 => "AF_INET".to_owned(),
                10 => "AF_INET6".to_owned(),
                16 => "AF_NETLINK".to_owned(),
                d => format!("domain={d}"),
            };
            format!("{domain} type={}", shape.s1)
        }
        _ if shape.s0 == 0 && shape.s1 == 0 => String::new(),
        _ if shape.s1 == 0 => format!("{:#x}", shape.s0),
        _ => format!("{:#x},{:#x}", shape.s0, shape.s1),
    }
}

/// Counted refusals from a census of the same workload, by (ISA, native
/// nr, caller).
pub type CensusRefusals = BTreeMap<(&'static str, u64, bool), u64>;

pub fn census_refusals(censuses: &[carrick_runtime::el1_census::Census]) -> CensusRefusals {
    let mut out = CensusRefusals::new();
    for census in censuses {
        let isa = match census.refusal_evidence.isa {
            CensusIsa::X86_64 => "x86_64",
            CensusIsa::Aarch64 => "aarch64",
        };
        for row in &census.refusal_evidence.rows {
            let child = row.caller == CallerClass::NativeChild;
            *out.entry((isa, row.nr, child)).or_default() += row.refused + row.venue_refused;
        }
    }
    out
}

/// One table row.
#[derive(Debug)]
pub struct GapRow {
    pub key: ShapeKey,
    pub name: String,
    pub shape: String,
    pub counts: ShapeCounts,
    pub routes: [(GuestIsa, Route); 2],
}

pub fn gap_rows(profile: &Profile) -> Result<Vec<GapRow>, String> {
    let isa = isa_of_code(profile.isa_code).ok_or("unknown profile isa")?;
    Ok(profile
        .shapes
        .iter()
        .map(|(key, counts)| GapRow {
            key: *key,
            name: syscall_name(isa, key.nr),
            shape: shape_text(isa, *key),
            counts: *counts,
            routes: [
                (GuestIsa::X86_64, route(isa, GuestIsa::X86_64, *key)),
                (GuestIsa::Aarch64, route(isa, GuestIsa::Aarch64, *key)),
            ],
        })
        .collect())
}

/// Render one workload's table: gaps first (most-called first), then a
/// count of the calls served. `all` also lists every served shape.
pub fn render(
    row: &str,
    profile: &Profile,
    census: Option<&CensusRefusals>,
    all: bool,
) -> Result<String, String> {
    let isa = isa_of_code(profile.isa_code).ok_or("unknown profile isa")?;
    let mut rows = gap_rows(profile)?;
    rows.sort_by(|a, b| b.counts.calls.cmp(&a.counts.calls).then(a.key.cmp(&b.key)));
    let mut out = String::new();
    let total: u64 = rows.iter().map(|r| r.counts.calls).sum();
    let _ = writeln!(
        out,
        "### {row} (oracle {}; {} calls in {} shapes)\n",
        isa_name(isa),
        total,
        rows.len()
    );
    let _ = write!(
        out,
        "| syscall | nr | shape | caller | oracle calls | oracle errno (ENOSYS/other) | x86_64 route | aarch64 route |"
    );
    let _ = writeln!(out, " gap |");
    let _ = writeln!(out, "|---|---:|---|---|---:|---|---|---|---|");
    let mut served = 0usize;
    for r in &rows {
        let linux_refused = r.counts.enosys == r.counts.calls && r.counts.calls > 0;
        let gaps: Vec<&str> = r
            .routes
            .iter()
            .filter(|(_, route)| route.is_gap())
            .map(|(isa, _)| isa_name(*isa))
            .collect();
        let gap = if linux_refused {
            "none (Linux refuses it too)".to_owned()
        } else if gaps.is_empty() {
            String::new()
        } else {
            format!("**{}**", gaps.join(", "))
        };
        if gap.is_empty() && !all {
            served += 1;
            continue;
        }
        let _ = write!(
            out,
            "| {} | {} | {} | {} | {} | {}/{} | {} | {} |",
            r.name,
            r.key.nr,
            r.shape,
            caller_name(r.key.caller()),
            r.counts.calls,
            r.counts.enosys,
            r.counts.errors,
            r.routes[0].1.label(),
            r.routes[1].1.label(),
        );
        let _ = writeln!(out, " {gap} |");
    }
    if !all {
        let _ = writeln!(
            out,
            "\n{served} more shapes are routed on both ISAs (`--all` lists them)."
        );
    }
    if let Some(census) = census {
        let rows: Vec<_> = census
            .iter()
            .filter(|((i, _, _), n)| *i == isa_name(isa) && **n > 0)
            .collect();
        let _ = writeln!(
            out,
            "\nCarrick's own census of this row ({} run): counted refusals by call and caller. \
             `predicted` means the table above lists the call as a gap; `decline` means its \
             owner is routed but refused a shape at run time.\n",
            isa_name(isa)
        );
        let _ = writeln!(out, "| syscall | nr | caller | refused | static verdict |");
        let _ = writeln!(out, "|---|---:|---|---:|---|");
        for ((_, nr, child), n) in rows {
            let predicted = profile
                .shapes
                .keys()
                .filter(|k| k.nr == *nr && k.child == *child)
                .any(|k| route(isa, isa, *k).is_gap())
                || VDSO_CALLS.iter().any(|&(x, a)| {
                    (if isa == GuestIsa::X86_64 { x } else { a }) == *nr
                        && route(
                            isa,
                            isa,
                            ShapeKey {
                                child: *child,
                                nr: *nr,
                                s0: 0,
                                s1: 0,
                            },
                        )
                        .is_gap()
                });
            let accepted = canonical_of_profile(isa, *nr) == Some(ACCEPTED_RSEQ);
            let verdict = if accepted {
                "accepted (#1906)"
            } else if predicted {
                "predicted"
            } else if *nr == 512 {
                "overflow bucket (unknown number)"
            } else {
                "**decline** (routed owner refused a shape)"
            };
            let _ = writeln!(
                out,
                "| {} | {nr} | {} | {n} | {verdict} |",
                syscall_name(isa, *nr),
                if *child { "child" } else { "root" }
            );
        }
    }
    let mut vdso = Vec::new();
    for &(x86, arm) in VDSO_CALLS {
        let nr = if isa == GuestIsa::X86_64 { x86 } else { arm };
        if nr == u64::MAX {
            continue;
        }
        for child in [false, true] {
            let k = ShapeKey {
                child,
                nr,
                s0: 0,
                s1: 0,
            };
            let routes: Vec<String> = [GuestIsa::X86_64, GuestIsa::Aarch64]
                .into_iter()
                .map(|t| format!("{} {}", isa_name(t), route(isa, t, k).label()))
                .collect();
            let refused = census
                .and_then(|c| c.get(&(isa_name(isa), nr, child)).copied())
                .map_or(String::new(), |n| format!("; census refused {n}"));
            vdso.push(format!(
                "{} {}: {}{refused}",
                syscall_name(isa, nr),
                caller_name(k.caller()),
                routes.join(", ")
            ));
        }
    }
    let _ = writeln!(
        out,
        "\nvDSO calls (Linux never enters the kernel for them, so the oracle cannot count them): {}.",
        vdso.join("; ")
    );
    let seccomp: Vec<String> = profile
        .unentered
        .iter()
        .filter(|((_, _, ret), _)| *ret < 0)
        .map(|((child, nr, ret), n)| {
            format!(
                "{} {} ret={ret} ×{n}",
                if *child { "child" } else { "root" },
                syscall_name(isa, *nr)
            )
        })
        .collect();
    if !seccomp.is_empty() {
        let _ = writeln!(
            out,
            "\nRefused by Docker's seccomp profile before entry (no shape): {}.",
            seccomp.join(", ")
        );
    }
    if profile.warnings > 0 {
        let _ = writeln!(
            out,
            "\nbpftrace printed {} warnings (a raced first insert undercounts a key by one).",
            profile.warnings
        );
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The recorder's known-answer run (x86_64, docker 26.1.5, bpftrace
    /// 0.23.2): root `syscall(511)` and `socket(AF_INET, SOCK_DGRAM)`, then a
    /// forked child's two `syscall(510)` and one `socket(AF_UNIX,
    /// SOCK_STREAM)`.
    const KNOWN_ANSWER: &str = "Attaching 8 probes...
VENUEPROFILE1|ready|root=19767|isa=0
VENUEPROFILE1|complete|root=19767

@calls[1, 41, 1, 1]: 1
@calls[0, 41, 2, 2]: 1
@calls[0, 9, 34, 3]: 10
@calls[1, 228, 1, 0]: 3
@errors[0, 257, 0, 0]: 19
@unentered[0, 511, -38]: 1
@unentered[1, 56, 0]: 1
@unentered[1, 510, -38]: 2
";

    fn key(child: bool, nr: u64, s0: u64, s1: u64) -> ShapeKey {
        ShapeKey { child, nr, s0, s1 }
    }

    #[test]
    fn known_answer_profile_parses_to_its_counts() {
        let p = parse_profile(KNOWN_ANSWER).unwrap();
        assert_eq!(p.isa_code, 0);
        assert_eq!(p.shapes[&key(true, 41, 1, 1)].calls, 1);
        assert_eq!(p.shapes[&key(false, 41, 2, 2)].calls, 1);
        assert_eq!(p.unentered[&(false, 511, -38)], 1);
        assert_eq!(p.unentered[&(true, 510, -38)], 2);
        assert_eq!(p.shapes[&key(false, 257, 0, 0)].errors, 19);
    }

    #[test]
    fn incomplete_or_bounded_profiles_fail_closed() {
        assert!(parse_profile("VENUEPROFILE1|ready|root=1|isa=0\n").is_err());
        assert!(
            parse_profile("VENUEPROFILE1|ready|root=1|isa=0\nVENUEPROFILE1|error=bound\n").is_err()
        );
    }

    #[test]
    fn a_childs_unix_socket_is_a_gap_and_an_inet_socket_crosses() {
        let unix = route(GuestIsa::X86_64, GuestIsa::X86_64, key(true, 41, 1, 1));
        assert!(unix.is_gap(), "{unix:?}");
        let inet = route(GuestIsa::X86_64, GuestIsa::X86_64, key(true, 41, 2, 2));
        assert_eq!(inet, Route::HostFile);
        // The ARM root crosses `socket`; the x86 crossing flag is off.
        let root_unix = route(GuestIsa::X86_64, GuestIsa::Aarch64, key(false, 41, 1, 1));
        assert_eq!(root_unix, Route::Crossing(HostCrossingKind::Permanent));
        let x86_root_unix = route(GuestIsa::X86_64, GuestIsa::X86_64, key(false, 41, 1, 1));
        assert_eq!(x86_root_unix, Route::CountedEnosys);
    }

    #[test]
    fn a_childs_madvise_is_a_root_only_crossing_on_arm() {
        // #1846: madvise is a Temporary crossing; a native child has none.
        let arm = route(GuestIsa::X86_64, GuestIsa::Aarch64, key(true, 28, 4, 0));
        assert_eq!(arm, Route::RootOnlyCrossing(HostCrossingKind::Temporary));
        let root = route(GuestIsa::X86_64, GuestIsa::Aarch64, key(false, 28, 4, 0));
        assert_eq!(root, Route::Crossing(HostCrossingKind::Temporary));
    }

    #[test]
    fn ring_families_and_x86_private_twins_route_on_both_isas() {
        // x86 read (0) is canonical 63; mmap is the anonymous family.
        for isa in [GuestIsa::X86_64, GuestIsa::Aarch64] {
            assert!(matches!(
                route(GuestIsa::X86_64, isa, key(true, 0, 0, 0)),
                Route::Ring(_)
            ));
            assert!(matches!(
                route(GuestIsa::X86_64, isa, key(true, 9, 0x22, 3)),
                Route::Ring(_)
            ));
        }
        // x86 arch_prctl is the backend's own.
        assert_eq!(
            route(
                GuestIsa::X86_64,
                GuestIsa::X86_64,
                key(false, 158, 0x1002, 0)
            ),
            Route::IsaNative
        );
    }

    #[test]
    fn descriptor_calls_and_x86_legacy_paths_route_through_their_owners() {
        for isa in [GuestIsa::X86_64, GuestIsa::Aarch64] {
            // close(3), fcntl(F_GETFL), dup2: the descriptor owner.
            for (nr, s0) in [(3, 0), (72, 3), (33, 0)] {
                let r = route(GuestIsa::X86_64, isa, key(true, nr, s0, 0));
                assert_eq!(r, Route::Ring("Descriptor".into()), "nr {nr} on {isa:?}");
            }
            // x86 unlink(87) and mkdir(83) lower to the *at host-file venue.
            for nr in [87, 83] {
                assert_eq!(
                    route(GuestIsa::X86_64, isa, key(true, nr, 0, 0)),
                    Route::HostFile
                );
            }
        }
        assert_eq!(syscall_name(GuestIsa::X86_64, 87), "unlink");
    }

    #[test]
    fn render_lists_the_gap_and_the_seccomp_refusals() {
        let p = parse_profile(KNOWN_ANSWER).unwrap();
        let text = render("known-answer", &p, None, false).unwrap();
        assert!(
            text.contains("| socket | 41 | AF_UNIX type=1 | child |"),
            "{text}"
        );
        assert!(text.contains("root nr511 ret=-38 ×1"), "{text}");
        assert!(text.contains("child nr510 ret=-38 ×2"), "{text}");
    }
}
