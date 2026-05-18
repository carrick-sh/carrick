use std::io::Write;

use carrick::rootfs::{LayerSource, RootFs};
use flate2::Compression;
use flate2::write::GzEncoder;

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
fn rejects_paths_that_escape_root() {
    let rootfs = RootFs::from_layers([LayerSource::TarGz(gzip_tar([(
        "safe.txt",
        b"safe".as_slice(),
    )]))])
    .unwrap();

    assert!(rootfs.read("/../safe.txt").is_err());
}

fn gzip_tar_with_links<const N: usize, const M: usize>(
    files: [(&str, &[u8]); N],
    links: [(&str, &str); M],
) -> Vec<u8> {
    let mut tar_bytes = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut tar_bytes);
        for (path, contents) in files {
            let mut header = tar::Header::new_gnu();
            header.set_size(contents.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append_data(&mut header, path, contents).unwrap();
        }
        for (path, target) in links {
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Symlink);
            header.set_size(0);
            header.set_mode(0o777);
            header.set_cksum();
            builder.append_link(&mut header, path, target).unwrap();
        }
        builder.finish().unwrap();
    }

    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&tar_bytes).unwrap();
    encoder.finish().unwrap()
}

fn gzip_tar<const N: usize>(files: [(&str, &[u8]); N]) -> Vec<u8> {
    let mut tar_bytes = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut tar_bytes);
        for (path, contents) in files {
            let mut header = tar::Header::new_gnu();
            header.set_size(contents.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append_data(&mut header, path, contents).unwrap();
        }
        builder.finish().unwrap();
    }

    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&tar_bytes).unwrap();
    encoder.finish().unwrap()
}
