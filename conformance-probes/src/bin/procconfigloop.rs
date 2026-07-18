//! Reducer for LTP ioctl_loop setup: the Linux oracle exposes loop-device
//! support through `/proc/config.gz`.
//!
//! Decode the proc file in-process so the probe tests the kernel-facing surface
//! itself rather than depending on `/bin/sh`, `gzip`, and `grep` being installed
//! in a minimal standalone rootfs.

use conformance_probes::report;
use flate2::read::GzDecoder;
use std::io::Read;

fn main() {
    let mut config = String::new();
    let decoded = std::fs::File::open("/proc/config.gz")
        .ok()
        .and_then(|file| {
            let mut decoder = GzDecoder::new(file);
            decoder.read_to_string(&mut config).ok()
        })
        .is_some();
    let loop_enabled = decoded && config.lines().any(|line| line == "CONFIG_BLK_DEV_LOOP=y");
    report!(
        proc_config_decoded = decoded,
        proc_config_loop_enabled = loop_enabled,
    );
}
