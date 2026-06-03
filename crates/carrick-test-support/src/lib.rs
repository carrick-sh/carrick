//! Shared helpers for carrick integration and CLI tests.
//!
//! carrick boots a guest from a container-style rootfs assembled out of OCI
//! layers — each layer a gzipped tar. The end-to-end tests (`carrick-cli`'s
//! `cli.rs`, `carrick-runtime`'s integration suites) need to synthesise those
//! layers in-memory rather than ship binary fixtures on disk: a one-file
//! `etc/motd`, a directory tree, a symlink graph. This crate is just the tar+gzip
//! builders that do that — [`gzip_tar`] (files at mode 0644), [`gzip_tar_with_modes`]
//! (explicit per-file modes, for the chmod/exec-bit cases), and
//! [`gzip_tar_with_links`] (files plus symlinks, for the path-resolution tests).
//!
//! It is a separate crate, rather than a `#[cfg(test)]` module, for one reason:
//! the same fixture builders are consumed from MULTIPLE crates' test targets
//! (`carrick-cli/tests/cli.rs`, `carrick-runtime/tests/...`), and a test-only
//! module can't be shared across crate boundaries. Pulling them here also keeps
//! the dev-dependencies they need (`tar`, `flate2`) out of the production crates'
//! graphs. Because it is test-only support, `clippy::unwrap_used` is allowed
//! crate-wide — these helpers run only in tests, where a panic IS the failure
//! report and propagating a `Result` would only add noise.

#![allow(clippy::unwrap_used)]

use flate2::Compression;
use flate2::write::GzEncoder;
use std::io::Write;

pub fn gzip_tar<const N: usize>(files: [(&str, &[u8]); N]) -> Vec<u8> {
    gzip_tar_with_modes(files.map(|(path, contents)| (path, contents, 0o644)))
}

pub fn gzip_tar_with_modes<const N: usize>(files: [(&str, &[u8], u32); N]) -> Vec<u8> {
    let mut tar_bytes = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut tar_bytes);
        for (path, contents, mode) in files {
            let mut header = tar::Header::new_gnu();
            header.set_size(contents.len() as u64);
            header.set_mode(mode);
            header.set_cksum();
            builder.append_data(&mut header, path, contents).unwrap();
        }
        builder.finish().unwrap();
    }

    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&tar_bytes).unwrap();
    encoder.finish().unwrap()
}

pub fn gzip_tar_with_links<const N: usize, const M: usize>(
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
