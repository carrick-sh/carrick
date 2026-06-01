//! User-namespace map files in a default container: `/proc/self/uid_map`,
//! `/proc/self/gid_map`, `/proc/self/setgroups`, and the CapEff/CapBnd/CapPrm
//! lines of `/proc/self/status`. carrick must present the SAME view a default
//! `docker run` does (docs/namespaces-design.md §1.2, §4.4): the identity map
//! `0 0 4294967295`, `setgroups=allow`, and the Docker default bounded
//! capability set 0x00000000a80425fb — NOT all-zero caps.
//!
//! All assertions are deterministic booleans/strings so they diff byte-exact
//! against the Docker oracle.

use conformance_probes::report;

fn read(path: &str) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}

/// First whitespace-collapsed line of a file (the maps render with padded
/// columns; collapse runs of spaces so the comparison is column-width-agnostic
/// AND matches between carrick and Docker, which both pad to width 10).
fn first_line_fields(s: &str) -> String {
    s.lines()
        .next()
        .unwrap_or("")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn status_field(status: &str, key: &str) -> String {
    status
        .lines()
        .find_map(|l| l.strip_prefix(key))
        .unwrap_or("")
        .trim()
        .to_string()
}

fn main() {
    let uid_map = read("/proc/self/uid_map");
    let gid_map = read("/proc/self/gid_map");
    let setgroups = read("/proc/self/setgroups");
    let status = read("/proc/self/status");

    // Identity map: `0 0 4294967295` (whitespace-normalized).
    report!(
        uid_map_identity = first_line_fields(&uid_map) == "0 0 4294967295",
        gid_map_identity = first_line_fields(&gid_map) == "0 0 4294967295",
        setgroups_allow = setgroups.trim() == "allow",
    );

    // Capabilities: a default container has a non-zero bounded set; assert it is
    // exactly the observed Docker default and the three sets agree. Printing the
    // literal value would also match, but comparing keeps the probe robust if a
    // future kernel/docker default shifts (the booleans still diff identically).
    let cap_eff = status_field(&status, "CapEff:");
    let cap_bnd = status_field(&status, "CapBnd:");
    let cap_prm = status_field(&status, "CapPrm:");
    report!(
        capeff = cap_eff,
        capeff_nonzero = cap_eff != "0000000000000000" && !cap_eff.is_empty(),
        capbnd_eq_capeff = cap_bnd == cap_eff,
        capprm_eq_capeff = cap_prm == cap_eff,
    );
}
