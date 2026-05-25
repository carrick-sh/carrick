// Test code: gzip/tar helpers are plain `fn`s (not `#[test]`/`#[cfg(test)]`), so
// clippy's allow-unwrap-in-tests heuristic does not exempt them. The no-panic gate
// targets production code, so allow unwrap/expect across this integration test file.
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "common/syscall_support.rs"]
mod support;

use carrick_runtime::rootfs::{LayerSource, RootFs};
use support::{gzip_tar, gzip_tar_with_links};

#[test]
fn reads_file_from_uppermost_layer() {
    let rootfs = RootFs::from_layers([
        LayerSource::TarGz(gzip_tar([("etc/os-release", b"NAME=base\n".as_slice())])),
        LayerSource::TarGz(gzip_tar([("etc/os-release", b"NAME=upper\n".as_slice())])),
    ])
    .unwrap();

    assert_eq!(
        rootfs.read_to_string("/etc/os-release").unwrap(),
        "NAME=upper\n"
    );
}

#[test]
fn applies_oci_whiteout_files() {
    let rootfs = RootFs::from_layers([
        LayerSource::TarGz(gzip_tar([
            ("bin/busybox", b"busybox".as_slice()),
            ("bin/sh", b"shell".as_slice()),
        ])),
        LayerSource::TarGz(gzip_tar([("bin/.wh.busybox", b"".as_slice())])),
    ])
    .unwrap();

    assert!(rootfs.read("/bin/busybox").is_err());
    assert_eq!(rootfs.read_to_string("/bin/sh").unwrap(), "shell");
}

#[test]
fn applies_opaque_directory_whiteout() {
    let rootfs = RootFs::from_layers([
        LayerSource::TarGz(gzip_tar([
            ("etc/profile", b"profile".as_slice()),
            ("etc/motd", b"motd".as_slice()),
        ])),
        LayerSource::TarGz(gzip_tar([
            ("etc/.wh..wh..opq", b"".as_slice()),
            ("etc/os-release", b"NAME=upper\n".as_slice()),
        ])),
    ])
    .unwrap();

    assert_eq!(rootfs.list_dir("/etc").unwrap(), vec!["os-release"]);
    assert!(rootfs.read("/etc/profile").is_err());
}

#[test]
fn follows_relative_symlinks_within_rootfs() {
    let rootfs = RootFs::from_layers([LayerSource::TarGz(gzip_tar_with_links(
        [("bin/busybox", b"busybox".as_slice())],
        [("bin/sh", "busybox")],
    ))])
    .unwrap();

    assert_eq!(rootfs.read_to_string("/bin/sh").unwrap(), "busybox");
    assert_eq!(rootfs.list_dir("/bin").unwrap(), vec!["busybox", "sh"]);
}

#[test]
fn read_link_preserves_symlink_target_text() {
    let rootfs = RootFs::from_layers([LayerSource::TarGz(gzip_tar_with_links(
        [("bin/busybox", b"busybox".as_slice())],
        [("bin/sh", "busybox")],
    ))])
    .unwrap();

    assert_eq!(rootfs.read_link("/bin/sh").unwrap(), "busybox");
}

#[test]
fn symlink_with_parent_dir_in_target_resolves_across_layers() {
    // Alpine ships /etc/mtab -> ../proc/mounts. Layer 1 provides /proc/mounts,
    // layer 2 lays down the /etc/mtab symlink with a `..` in the target.
    let rootfs = RootFs::from_layers([
        LayerSource::TarGz(gzip_tar([(
            "proc/mounts",
            b"rootfs / rootfs rw 0 0\n".as_slice(),
        )])),
        LayerSource::TarGz(gzip_tar_with_links([], [("etc/mtab", "../proc/mounts")])),
    ])
    .unwrap();

    // read_link returns the original target text verbatim.
    assert_eq!(rootfs.read_link("/etc/mtab").unwrap(), "../proc/mounts");

    // Following the symlink reads the layer-1 contents.
    assert_eq!(
        rootfs.read_to_string("/etc/mtab").unwrap(),
        "rootfs / rootfs rw 0 0\n"
    );
}

#[test]
fn rejects_paths_that_escape_root() {
    let rootfs = RootFs::from_layers([LayerSource::TarGz(gzip_tar([(
        "safe.txt",
        b"safe".as_slice(),
    )]))])
    .unwrap();

    assert!(rootfs.read("/../safe.txt").is_err());
}
