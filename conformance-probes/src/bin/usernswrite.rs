//! Writing the user-namespace map files in a DEFAULT container (the initial
//! user namespace, which is already identity-mapped). Per user_namespaces(7) a
//! uid_map/gid_map is write-once, so writing it again is rejected and the map
//! stays the identity map. carrick must agree with `docker run` on the
//! reject-and-unchanged contract (docs/namespaces-design.md §4.3).
//!
//! We assert the BEHAVIOR (write rejected; map unchanged) rather than a specific
//! errno: a bare-shell redirect reports EIO while a kernel write reports EPERM,
//! and the exact code is environment-coupled — but "the write fails and the map
//! is still `0 0 4294967295`" holds identically on Linux and carrick, so it
//! diffs byte-exact.

use conformance_probes::report;

fn write_file(path: &str, data: &[u8]) -> bool {
    // Returns true on success, false on any error (rejected).
    use std::io::Write;
    match std::fs::OpenOptions::new().write(true).open(path) {
        Ok(mut f) => f.write_all(data).is_ok(),
        Err(_) => false,
    }
}

fn first_line_fields(path: &str) -> String {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .next()
        .unwrap_or("")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn main() {
    // The initial userns is already mapped → a second uid_map/gid_map write is
    // rejected (write-once), and the map is unchanged.
    let uid_written = write_file("/proc/self/uid_map", b"0 0 1");
    let gid_written = write_file("/proc/self/gid_map", b"0 0 1");
    report!(
        uid_map_write_rejected = !uid_written,
        gid_map_write_rejected = !gid_written,
        uid_map_unchanged = first_line_fields("/proc/self/uid_map") == "0 0 4294967295",
        gid_map_unchanged = first_line_fields("/proc/self/gid_map") == "0 0 4294967295",
    );
}
