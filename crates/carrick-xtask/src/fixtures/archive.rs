//! Mode-preserving transport; only declared regular bundle files may unpack.
use super::{
    CommitSha, ContentHash, RestoreWork, Result, fail, hash_file, inspect_bundle, safe_path,
};
use flate2::{Compression, read::MultiGzDecoder, write::GzEncoder};
use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};

pub fn pack(manifest: &Path, output: &Path) -> Result<PathBuf> {
    let identity = inspect_bundle(manifest, None)?;
    let bundle = manifest
        .parent()
        .ok_or_else(|| fail("manifest has no parent"))?;
    let digest = hash_file(manifest)?;
    let destination = output.join(String::from(identity.source_head.clone()));
    fs::create_dir_all(&destination)?;
    let mut temp = tempfile::NamedTempFile::new_in(&destination)?;
    {
        let gzip = GzEncoder::new(temp.as_file_mut(), Compression::fast());
        let mut archive = tar::Builder::new(gzip);
        let mut files = BTreeSet::from(["manifest.json".to_owned()]);
        for executable in identity.executables {
            files.insert(format!("objects/{}", String::from(executable.sha256)));
        }
        for relative in files {
            let mut file = File::open(safe_path(bundle, &relative)?)?;
            let mut header = tar::Header::new_gnu();
            header.set_size(file.metadata()?.len());
            header.set_mode(if relative == "manifest.json" {
                0o644
            } else {
                0o755
            });
            header.set_uid(0);
            header.set_gid(0);
            header.set_mtime(0);
            header.set_cksum();
            archive.append_data(
                &mut header,
                format!("{}/{relative}", String::from(digest.clone())),
                &mut file,
            )?;
        }
        archive.into_inner()?.finish()?;
    }
    verify(temp.path(), &String::from(identity.source_head))?;
    let artifact = destination.join(format!("{}.tar.gz", String::from(digest)));
    if artifact.exists() {
        if hash_file(&artifact)? != hash_file(temp.path())? {
            return Err(fail(
                "immutable fixture artifact already exists with different bytes",
            ));
        }
    } else {
        temp.persist(&artifact).map_err(|e| e.error)?;
    }
    Ok(artifact)
}

struct Unpacked {
    _directory: tempfile::TempDir,
    manifest: PathBuf,
}

fn unpack(bundle: &Path) -> Result<Unpacked> {
    let directory = tempfile::tempdir()?;
    let mut archive = tar::Archive::new(MultiGzDecoder::new(File::open(bundle)?));
    let mut seen = BTreeSet::new();
    let mut root: Option<ContentHash> = None;
    let mut manifest = None;
    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.into_owned();
        let parts: Vec<_> = path.components().collect();
        let Some(Component::Normal(first)) = parts.first() else {
            return Err(fail("unsafe fixture archive root"));
        };
        let hash = ContentHash::try_from(first.to_string_lossy().into_owned())?;
        if root.as_ref().is_some_and(|root| root != &hash) {
            return Err(fail("multiple fixture archive roots"));
        }
        root = Some(hash);
        let kind = entry.header().entry_type();
        let valid = match parts.as_slice() {
            [_] => kind.is_dir(),
            [_, Component::Normal(name)] if *name == "objects" => kind.is_dir(),
            [_, Component::Normal(name)] if *name == "manifest.json" => kind.is_file(),
            [_, Component::Normal(objects), Component::Normal(name)] if *objects == "objects" => {
                ContentHash::try_from(name.to_string_lossy().into_owned())?;
                kind.is_file()
            }
            _ => false,
        };
        if !valid || !seen.insert(path.clone()) {
            return Err(fail(
                "unsafe, duplicate, or non-regular fixture archive entry",
            ));
        }
        let target = safe_path(directory.path(), &path.to_string_lossy())?;
        if kind.is_dir() {
            fs::create_dir_all(&target)?;
            continue;
        }
        fs::create_dir_all(
            target
                .parent()
                .ok_or_else(|| fail("archive file has no parent"))?,
        )?;
        let mode = entry.header().mode()? & 0o777;
        let mut file = File::create(&target)?;
        io::copy(&mut entry, &mut file)?;
        fs::set_permissions(&target, fs::Permissions::from_mode(mode))?;
        if parts.len() == 2 {
            manifest = Some(target);
        }
    }
    Ok(Unpacked {
        _directory: directory,
        manifest: manifest.ok_or_else(|| fail("fixture archive has no manifest"))?,
    })
}

pub fn restore(root: &Path, bundle: &Path, sha: Option<&str>) -> Result<RestoreWork> {
    let unpacked = unpack(bundle)?;
    super::restore(root, &unpacked.manifest, sha)
}

/// Verify transport identity without borrowing the sender checkout's HEAD.
pub fn verify(bundle: &Path, sha: &str) -> Result<()> {
    let expected = CommitSha::try_from(sha.to_owned())?;
    let unpacked = unpack(bundle)?;
    inspect_bundle(&unpacked.manifest, Some(&expected))?;
    Ok(())
}
