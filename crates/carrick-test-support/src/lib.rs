//! Shared helpers for Carrick integration and CLI tests.

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
