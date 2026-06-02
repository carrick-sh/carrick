//! `/etc/hostname` must contain the running hostname — the same name `uname(2)`
//! / `gethostname()` / `/proc/sys/kernel/hostname` report. Every Linux system
//! and Docker container keeps these in agreement (Docker writes the container
//! hostname into /etc/hostname at create). Config parsers, logging, and service
//! discovery read the file and expect it to match the live hostname.
//!
//! carrick adopted the macOS host's short name as the guest hostname (uname /
//! proc / the /etc/hosts self-map all updated), but `/etc/hostname` was still
//! served verbatim from the rootfs image (e.g. a build-time `debuerreotype`),
//! so the file disagreed with every other identity surface. Fix: synthesize
//! /etc/hostname from the single guest-hostname source. INVARIANT: trimmed
//! /etc/hostname equals gethostname().

use conformance_probes::report;

fn main() {
    let mut buf = [0 as libc::c_char; 256];
    unsafe { libc::gethostname(buf.as_mut_ptr(), buf.len() - 1) };
    let gethostname = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr()) }
        .to_string_lossy()
        .into_owned();

    let file = std::fs::read_to_string("/etc/hostname").unwrap_or_default();
    let file = file.trim();

    report!(
        etc_hostname_present = !file.is_empty(),
        etc_hostname_matches_gethostname = !file.is_empty() && file == gethostname,
    );
}
