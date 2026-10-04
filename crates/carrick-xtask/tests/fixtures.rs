#![allow(clippy::unwrap_used, clippy::expect_used)]
use carrick_xtask::fixtures::{
    self, CommitSha, ContentHash, Executable, GuestTarget, Manifest, Toolchain,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

fn git(root: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .current_dir(root)
        .args(args)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap().trim().to_owned()
}
fn write(root: &Path, path: &str, bytes: &[u8]) {
    let path = root.join(path);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, bytes).unwrap();
}
fn hash(bytes: &[u8]) -> ContentHash {
    format!("{:x}", Sha256::digest(bytes)).try_into().unwrap()
}
fn elf(target: GuestTarget, marker: u8) -> Vec<u8> {
    let mut bytes = vec![0; 160];
    bytes[..4].copy_from_slice(b"\x7fELF");
    bytes[4] = 2;
    bytes[5] = 1;
    bytes[18..20].copy_from_slice(&183u16.to_le_bytes());
    bytes[32..40].copy_from_slice(&64u64.to_le_bytes());
    bytes[54..56].copy_from_slice(&56u16.to_le_bytes());
    if target == GuestTarget::Gnu {
        bytes[56..58].copy_from_slice(&1u16.to_le_bytes());
        bytes[64..68].copy_from_slice(&3u32.to_le_bytes());
        bytes[72..80].copy_from_slice(&120u64.to_le_bytes());
        let interpreter = b"/lib/ld-linux-aarch64.so.1\0";
        bytes[96..104].copy_from_slice(&(interpreter.len() as u64).to_le_bytes());
        bytes[120..120 + interpreter.len()].copy_from_slice(interpreter);
    }
    bytes[159] = marker;
    bytes
}
struct Fixture {
    repo: tempfile::TempDir,
    store: tempfile::TempDir,
    manifest: Manifest,
    path: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let repo = tempfile::tempdir().unwrap();
        let root = repo.path();
        git(root, &["init", "-q"]);
        git(root, &["config", "user.name", "fixture test"]);
        git(root, &["config", "user.email", "fixture@example.test"]);
        write(root, ".gitignore", b"target/\n");
        write(
            root,
            "rust-toolchain.toml",
            b"[toolchain]\nchannel = \"1.96.0\"\n",
        );
        write(
            root,
            "scripts/build-linux-fixtures.sh",
            b"build_fixture \"main.rs\" \"hello\"\n",
        );
        write(
            root,
            "fixtures/linux-aarch64-hello/src/main.rs",
            b"raw fixture\n",
        );
        write(root, "conformance-probes/src/bin/probeinit.rs", b"helper\n");
        write(root, "conformance-probes/src/bin/hello.rs", b"probe\n");
        write(root, "conformance-probes/probe-inventory.json", br#"{"probeinit":{"class":"helper","runner":"generic","excluded":false},"hello":{"class":"conformance","runner":"generic","excluded":false}}"#);
        git(root, &["add", "."]);
        git(root, &["commit", "-qm", "fixture inputs"]);
        let sha = git(root, &["rev-parse", "HEAD"]);
        let mut sources = BTreeMap::new();
        for path in git(root, &["ls-files"])
            .lines()
            .filter(|p| *p != ".gitignore")
        {
            sources.insert(path.to_owned(), hash(&fs::read(root.join(path)).unwrap()));
        }
        let store = tempfile::tempdir().unwrap();
        let mut executables = Vec::new();
        for (index, (path, target)) in fixtures::executable_inventory(root)
            .unwrap()
            .into_iter()
            .enumerate()
        {
            let data = elf(target, index as u8);
            let digest = hash(&data);
            let name: String = digest.clone().into();
            write(store.path(), &format!("objects/{name}"), &data);
            fs::set_permissions(
                store.path().join("objects").join(name),
                fs::Permissions::from_mode(0o755),
            )
            .unwrap();
            executables.push(Executable {
                path,
                target,
                sha256: digest,
            });
        }
        let manifest = Manifest {
            schema: "carrick.fixtures.v1".into(),
            source_head: sha.try_into().unwrap(),
            sources,
            toolchain: Toolchain {
                rustc: "release: 1.96.0\nhost: aarch64-unknown-linux-gnu\n".into(),
                cargo: "cargo 1.96.0".into(),
                gnu_linker: "GNU gcc".into(),
            },
            executables,
        };
        let mut fixture = Self {
            repo,
            store,
            manifest,
            path: PathBuf::new(),
        };
        fixture.republish();
        fixture
    }
    fn republish(&mut self) {
        let bytes = serde_json::to_vec_pretty(&self.manifest).unwrap();
        let digest: String = hash(&bytes).into();
        let directory = self.store.path().join(digest);
        fs::create_dir_all(&directory).unwrap();
        if !directory.join("objects").exists() {
            // Each publication gets its own object directory.
            fs::create_dir(directory.join("objects")).unwrap();
            for entry in fs::read_dir(self.store.path().join("objects")).unwrap() {
                let entry = entry.unwrap();
                fs::copy(
                    entry.path(),
                    directory.join("objects").join(entry.file_name()),
                )
                .unwrap();
            }
        }
        self.path = directory.join("manifest.json");
        fs::write(&self.path, bytes).unwrap();
    }
    fn object(&self) -> PathBuf {
        let digest: String = self.manifest.executables[0].sha256.clone().into();
        self.path.parent().unwrap().join("objects").join(digest)
    }
    fn rejected(&self, expected: &str) {
        let error = fixtures::restore(self.repo.path(), &self.path, None)
            .unwrap_err()
            .to_string();
        assert!(error.contains(expected), "{error}");
        assert!(!self.repo.path().join(fixtures::INSTALLED_MANIFEST).exists());
        assert!(
            !self
                .repo
                .path()
                .join(&self.manifest.executables[0].path)
                .exists()
        );
    }
}
#[test]
fn roundtrip_restores_exact_paths_and_verifies_installed_bytes() {
    let f = Fixture::new();
    fixtures::verify_bundle(f.repo.path(), &f.path, None).unwrap();
    fixtures::restore(f.repo.path(), &f.path, None).unwrap();
    assert_eq!(
        fixtures::verify_installed(f.repo.path())
            .unwrap()
            .executables
            .len(),
        9
    );
    for e in &f.manifest.executables {
        assert_eq!(
            hash(&fs::read(f.repo.path().join(&e.path)).unwrap()),
            e.sha256
        );
    }
    write(
        f.repo.path(),
        &f.manifest.executables[0].path,
        b"stale executable",
    );
    assert!(
        fixtures::verify_installed(f.repo.path())
            .unwrap_err()
            .to_string()
            .contains("hash mismatch")
    );
}
#[test]
fn tampered_object_is_rejected_before_any_install() {
    let f = Fixture::new();
    fs::write(f.object(), b"tampered").unwrap();
    f.rejected("hash mismatch");
}
#[test]
fn missing_object_is_rejected_before_any_install() {
    let f = Fixture::new();
    fs::remove_file(f.object()).unwrap();
    f.rejected("No such file");
}
#[test]
fn wrong_sha_is_rejected_even_with_valid_content_address() {
    let mut f = Fixture::new();
    f.manifest.source_head = "a".repeat(40).try_into().unwrap();
    f.republish();
    f.rejected("wrong SHA");
}
#[test]
fn expected_sha_must_match_checkout() {
    let f = Fixture::new();
    let error = fixtures::restore(f.repo.path(), &f.path, Some(&"b".repeat(40))).unwrap_err();
    assert!(error.to_string().contains("wrong SHA"));
}
#[test]
fn manifest_tamper_is_rejected() {
    let f = Fixture::new();
    fs::write(&f.path, b"{}").unwrap();
    f.rejected("content address mismatch");
}
#[test]
fn source_tamper_and_untracked_input_are_rejected() {
    let f = Fixture::new();
    write(
        f.repo.path(),
        "conformance-probes/src/bin/hello.rs",
        b"changed source",
    );
    f.rejected("dirty fixture source");
    git(
        f.repo.path(),
        &["restore", "conformance-probes/src/bin/hello.rs"],
    );
    write(
        f.repo.path(),
        "conformance-probes/src/bin/extra.rs",
        b"untracked source",
    );
    f.rejected("dirty fixture source");
}
#[test]
fn missing_source_hash_and_missing_executable_row_are_rejected() {
    let mut f = Fixture::new();
    f.manifest.sources.remove("rust-toolchain.toml");
    f.republish();
    f.rejected("source hashes or inventory mismatch");
    let mut f = Fixture::new();
    f.manifest.executables.pop();
    f.republish();
    f.rejected("executable inventory");
}
#[test]
fn duplicate_or_traversing_destination_is_rejected() {
    let mut f = Fixture::new();
    f.manifest
        .executables
        .push(f.manifest.executables[0].clone());
    f.republish();
    f.rejected("executable inventory");
    let mut f = Fixture::new();
    f.manifest.executables[0].path = "../escape".into();
    f.republish();
    f.rejected("executable inventory");
}
#[test]
fn wrong_target_and_toolchain_are_rejected() {
    let mut f = Fixture::new();
    f.manifest.executables[0].target = GuestTarget::Musl;
    f.republish();
    f.rejected("executable inventory");
    let mut f = Fixture::new();
    f.manifest.toolchain.rustc = "release: 0.0.0".into();
    f.republish();
    f.rejected("toolchain identity");
}
#[test]
fn non_executable_and_symlink_object_are_rejected() {
    let f = Fixture::new();
    fs::set_permissions(f.object(), fs::Permissions::from_mode(0o644)).unwrap();
    f.rejected("not executable");
    let f = Fixture::new();
    let object = f.object();
    let copied = f.store.path().join("external-object");
    fs::rename(&object, &copied).unwrap();
    std::os::unix::fs::symlink(copied, object).unwrap();
    f.rejected("symlink fixture path");
}
#[test]
fn destination_symlink_is_rejected_without_touching_external_directory() {
    let f = Fixture::new();
    let external = tempfile::tempdir().unwrap();
    std::os::unix::fs::symlink(external.path(), f.repo.path().join("target")).unwrap();
    f.rejected("symlink fixture path");
    assert_eq!(fs::read_dir(external.path()).unwrap().count(), 0);
}
#[test]
fn installed_manifest_and_missing_installed_file_fail_closed() {
    let f = Fixture::new();
    assert!(fixtures::verify_installed(f.repo.path()).is_err());
    fixtures::restore(f.repo.path(), &f.path, None).unwrap();
    fs::remove_file(f.repo.path().join(&f.manifest.executables[0].path)).unwrap();
    assert!(fixtures::verify_installed(f.repo.path()).is_err());
    write(f.repo.path(), fixtures::INSTALLED_MANIFEST, b"{}");
    assert!(fixtures::verify_installed(f.repo.path()).is_err());
}

#[test]
fn signed_preflight_rejects_existing_directories_without_manifest() {
    let f = Fixture::new();
    for target in ["aarch64-unknown-linux-musl", "aarch64-unknown-linux-gnu"] {
        fs::create_dir_all(
            f.repo
                .path()
                .join("conformance-probes/target")
                .join(target)
                .join("release"),
        )
        .unwrap();
    }
    assert!(carrick_xtask::accept::verify_signed_fixtures(f.repo.path()).is_err());
}

#[test]
fn signed_preflight_rehashes_restored_executables() {
    let f = Fixture::new();
    fixtures::restore(f.repo.path(), &f.path, None).unwrap();
    carrick_xtask::accept::verify_signed_fixtures(f.repo.path()).unwrap();
    write(
        f.repo.path(),
        &f.manifest.executables[0].path,
        b"stale executable",
    );
    assert!(carrick_xtask::accept::verify_signed_fixtures(f.repo.path()).is_err());
}
#[test]
fn identities_reject_abbreviations_and_non_hex_values() {
    assert!(CommitSha::try_from("HEAD".to_owned()).is_err());
    assert!(ContentHash::try_from("g".repeat(64)).is_err());
}
