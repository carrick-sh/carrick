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

struct RestoreChild(std::process::Child);

impl RestoreChild {
    fn finish(&mut self) -> std::process::ExitStatus {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            if let Some(status) = self.0.try_wait().unwrap() {
                return status;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "restore child did not finish"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }
}

impl Drop for RestoreChild {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

fn restore_command(f: &Fixture, lock: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_carrick-xtask"));
    command
        .current_dir(f.repo.path())
        .args(["fixtures", "restore", "--manifest"])
        .arg(&f.path)
        .env("CARRICK_HOST_LEASE_PATH", lock)
        .env_remove("CARRICK_HOST_LEASE_FD")
        .env_remove("CARRICK_HOST_LEASE_MODE");
    command
}

#[test]
fn standalone_restore_waits_for_gate_before_publishing() {
    use carrick_xtask::host_lease::{HostLease, HostLeaseMode};
    use std::io::BufRead;
    let f = Fixture::new();
    let lock = f.store.path().join("host.lock");
    let gate = HostLease::acquire_path(&lock, HostLeaseMode::Gate).unwrap();
    let mut child = RestoreChild(
        restore_command(&f, &lock)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let stderr = child.0.stderr.take().unwrap();
    let (sender, receiver) = std::sync::mpsc::channel();
    let reader = std::thread::spawn(move || {
        let mut waiting = false;
        let mut log = String::new();
        for line in std::io::BufReader::new(stderr).lines() {
            let line = line.unwrap();
            if !waiting && line.contains("host-lease: waiting for gate") {
                waiting = true;
                sender.send(true).unwrap();
            }
            log.push_str(&line);
            log.push('\n');
        }
        if !waiting {
            sender.send(false).unwrap();
        }
        log
    });
    let waiting = receiver
        .recv_timeout(std::time::Duration::from_secs(5))
        .unwrap();
    assert!(
        !f.repo.path().join(fixtures::INSTALLED_MANIFEST).exists(),
        "standalone restore published while another process holds gate admission"
    );
    assert!(waiting, "restore never requested exclusive gate admission");
    for executable in &f.manifest.executables {
        assert!(!f.repo.path().join(&executable.path).exists());
    }
    assert!(child.0.try_wait().unwrap().is_none());
    drop(gate);
    let status = child.finish();
    let log = reader.join().unwrap();
    assert!(status.success(), "restore failed after admission: {log}");
    fixtures::verify_installed(f.repo.path()).unwrap();
}

#[test]
fn restore_reuses_inherited_gate_and_rejects_shared_upgrade() {
    use carrick_xtask::host_lease::{HostLease, HostLeaseMode};
    let f = Fixture::new();
    let lock = f.store.path().join("host.lock");
    for mode in [HostLeaseMode::Carrick, HostLeaseMode::Gate] {
        let lease = HostLease::acquire_path(&lock, mode).unwrap();
        let mut command = restore_command(&f, &lock);
        lease.configure_command(&mut command).unwrap();
        let mut child = RestoreChild(command.spawn().unwrap());
        let status = child.finish();
        assert_eq!(status.success(), mode == HostLeaseMode::Gate);
        assert_eq!(
            f.repo.path().join(fixtures::INSTALLED_MANIFEST).exists(),
            mode == HostLeaseMode::Gate
        );
    }
    fixtures::verify_installed(f.repo.path()).unwrap();
}

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
        Self::with_probe_count(1)
    }

    fn with_probe_count(count: usize) -> Self {
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
        write(
            root,
            "crates/carrick-el1-abi/src/lib.rs",
            b"local fixture dependency\n",
        );
        write(root, "conformance-probes/probe-inventory.json", br#"{"probeinit":{"class":"helper","runner":"generic","excluded":false},"hello":{"class":"conformance","runner":"generic","excluded":false}}"#);
        let mut inventory: serde_json::Value = serde_json::from_slice(
            &fs::read(root.join("conformance-probes/probe-inventory.json")).unwrap(),
        )
        .unwrap();
        for index in 1..count {
            let name = format!("hello{index}");
            write(
                root,
                &format!("conformance-probes/src/bin/{name}.rs"),
                b"additional probe\n",
            );
            inventory[&name] =
                serde_json::json!({"class":"conformance","runner":"generic","excluded":false});
        }
        write(
            root,
            "conformance-probes/probe-inventory.json",
            &serde_json::to_vec(&inventory).unwrap(),
        );
        std::os::unix::fs::symlink(
            "src/lib.rs",
            root.join("crates/carrick-el1-abi/source-link"),
        )
        .unwrap();
        // Real, registry-free Cargo graphs exercise direct and transitive closure.
        for name in [
            "carrick-el1-abi",
            "fixture-transitive",
            "fixture-builder",
            "carrick-runtime",
        ] {
            let dependency = if name == "carrick-el1-abi" {
                "[dependencies]\nfixture-transitive = { path = \"../fixture-transitive\" }\n"
            } else {
                ""
            };
            write(root, &format!("crates/{name}/Cargo.toml"),
                format!("[package]\nname = \"{name}\"\nversion = \"0.0.0\"\nedition = \"2021\"\n{dependency}").as_bytes());
            if name != "carrick-el1-abi" {
                write(root, &format!("crates/{name}/src/lib.rs"), b"// source\n");
            }
        }
        write(
            root,
            "Cargo.toml",
            b"[workspace]\nresolver = \"2\"\nmembers = [\"crates/*\"]\n",
        );
        for directory in [
            "conformance-probes",
            "fixtures/linux-aarch64-hello",
            "fixtures/embed-interceptor-probe",
            "fixtures/embed-zone-readers",
            "fixtures/embed-icache-reuse",
            "fixtures/embed-el1-sched",
        ] {
            let name = directory.rsplit('/').next().unwrap();
            let dependency = if name == "embed-el1-sched" {
                "[dependencies]\ncarrick-el1-abi = { path = \"../../crates/carrick-el1-abi\" }\n[build-dependencies]\nfixture-builder = { path = \"../../crates/fixture-builder\" }\n[dev-dependencies]\ncarrick-runtime = { path = \"../../crates/carrick-runtime\" }\n"
            } else {
                ""
            };
            write(root, &format!("{directory}/Cargo.toml"),
                format!("[workspace]\n[package]\nname = \"{name}\"\nversion = \"0.0.0\"\nedition = \"2021\"\n{dependency}").as_bytes());
            write(root, &format!("{directory}/src/lib.rs"), b"// source\n");
            if name == "embed-el1-sched" {
                write(root, &format!("{directory}/build.rs"), b"fn main() {}\n");
            }
            let output = Command::new("cargo")
                .current_dir(root)
                .args(["generate-lockfile", "--offline", "--manifest-path"])
                .arg(format!("{directory}/Cargo.toml"))
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        git(root, &["add", "."]);
        git(root, &["commit", "-qm", "fixture inputs"]);
        let sha = git(root, &["rev-parse", "HEAD"]);
        let mut sources = BTreeMap::new();
        for path in git(root, &["ls-files"])
            .lines()
            .filter(|p| *p != ".gitignore" && !p.starts_with("crates/carrick-runtime/"))
        {
            let source = root.join(path);
            let digest = if fs::symlink_metadata(&source)
                .unwrap()
                .file_type()
                .is_symlink()
            {
                hash(
                    fs::read_link(source)
                        .unwrap()
                        .as_os_str()
                        .as_encoded_bytes(),
                )
            } else {
                hash(&fs::read(source).unwrap())
            };
            sources.insert(path.to_owned(), digest);
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
            schema: "carrick.fixtures.v2".into(),
            source_head: sha.try_into().unwrap(),
            sources,
            build_policy: fixtures::BuildPolicy::default(),
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
fn restore_durability_flush_budget_does_not_scale_with_executable_count() {
    for probes in [1, 32] {
        let f = Fixture::with_probe_count(probes);
        let work = fixtures::restore(f.repo.path(), &f.path, None).unwrap();
        assert_eq!(work.executable_publications, f.manifest.executables.len());
        assert_eq!(
            work.durability_flushes, 1,
            "one receipt durability boundary per restore"
        );
        fixtures::verify_installed(f.repo.path()).unwrap();
    }
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
fn local_workspace_dependency_sources_are_verified() {
    let f = Fixture::new();
    fixtures::restore(f.repo.path(), &f.path, None).unwrap();
    write(
        f.repo.path(),
        "crates/carrick-el1-abi/src/lib.rs",
        b"changed dependency",
    );
    assert!(
        fixtures::verify_installed(f.repo.path())
            .unwrap_err()
            .to_string()
            .contains("dirty fixture source")
    );
}
#[test]
fn clean_restore_then_unrelated_edit_preserves_fixtures() {
    let mut f = Fixture::new();
    // Use the publisher's inventory for this behavioral witness. The other
    // tests retain their independent expected inventory to check scope.
    f.manifest.sources = fixtures::source_hashes(f.repo.path()).unwrap();
    f.republish();
    fixtures::restore(f.repo.path(), &f.path, None).unwrap();
    println!("clean restore succeeded before unrelated edit");
    write(
        f.repo.path(),
        "crates/carrick-runtime/src/lib.rs",
        b"// temporary diagnostic\n",
    );
    println!("introduced only crates/carrick-runtime/src/lib.rs edit");
    fixtures::verify_installed(f.repo.path()).unwrap();
}

#[test]
fn acceptance_rejects_untracked_host_test_even_with_valid_fixtures() {
    let f = Fixture::new();
    fixtures::restore(f.repo.path(), &f.path, None).unwrap();
    carrick_xtask::accept::verify_signed_fixtures(f.repo.path()).unwrap();
    write(
        f.repo.path(),
        "crates/carrick-embed/tests/local_icache.rs",
        b"#[test] fn extra() {}\n",
    );
    git(
        f.repo.path(),
        &["config", "status.showUntrackedFiles", "no"],
    );
    fixtures::verify_installed(f.repo.path()).unwrap();
    assert!(carrick_xtask::accept::verify_signed_fixtures(f.repo.path()).is_err());
    let output = Command::new(env!("CARGO_BIN_EXE_carrick-xtask"))
        .current_dir(f.repo.path())
        .args(["accept", "--phase", "signed"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("fully clean checkout"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn fixture_verification_rejects_ambient_profile_override() {
    let f = Fixture::new();
    fixtures::restore(f.repo.path(), &f.path, None).unwrap();
    for (name, value) in [
        ("CARGO_PROFILE_RELEASE_OPT_LEVEL", "0"),
        ("CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS", "true"),
        (
            "CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_RUSTFLAGS",
            "-C opt-level=0",
        ),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_carrick-xtask"))
            .current_dir(f.repo.path())
            .args(["fixtures", "verify"])
            .env(name, value)
            .output()
            .unwrap();
        assert!(
            !output.status.success(),
            "old bundle accepted changed {name}"
        );
        assert!(String::from_utf8_lossy(&output.stderr).contains("build policy"));
    }
}

#[test]
fn fixture_policy_identity_rejects_changed_policy() {
    let mut f = Fixture::new();
    f.manifest
        .build_policy
        .fixed_environment
        .insert("CARGO_PROFILE_RELEASE_OPT_LEVEL".into(), "0".into());
    f.republish();
    f.rejected("build policy mismatch");
}

#[test]
fn cargo_home_and_parent_config_are_isolated() {
    let f = Fixture::new();
    let outside = tempfile::tempdir().unwrap();
    let checkout = outside.path().join("checkout");
    git(
        outside.path(),
        &[
            "clone",
            "--quiet",
            f.repo.path().to_str().unwrap(),
            "checkout",
        ],
    );
    fixtures::restore(&checkout, &f.path, None).unwrap();
    write(
        outside.path(),
        ".cargo/config.toml",
        b"this is invalid TOML\n",
    );
    write(
        outside.path(),
        "cargo-home/config.toml",
        b"this is invalid TOML\n",
    );
    let output = Command::new(env!("CARGO_BIN_EXE_carrick-xtask"))
        .current_dir(&checkout)
        .args(["fixtures", "verify"])
        .env("CARGO_HOME", outside.path().join("cargo-home"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    // The same configuration inside the checkout is an input, not host policy.
    write(
        &checkout,
        ".cargo/config.toml",
        b"[build]\nrustflags = []\n",
    );
    let output = Command::new(env!("CARGO_BIN_EXE_carrick-xtask"))
        .current_dir(&checkout)
        .args(["fixtures", "verify"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("requires tracked Cargo configuration")
    );
}

#[test]
fn unrelated_workspace_edits_preserve_fixture_identity() {
    let f = Fixture::new();
    fixtures::restore(f.repo.path(), &f.path, None).unwrap();
    write(
        f.repo.path(),
        "crates/carrick-runtime/src/lib.rs",
        b"// diagnostic\n",
    );
    write(
        f.repo.path(),
        "crates/carrick-runtime/src/diagnostic.rs",
        b"// untracked\n",
    );
    fixtures::verify_installed(f.repo.path()).unwrap();
    fixtures::verify_bundle(f.repo.path(), &f.path, None).unwrap();
    let receipt = f.store.path().join("verification.json");
    let result = Command::new(env!("CARGO_BIN_EXE_carrick-xtask"))
        .current_dir(f.repo.path())
        .args(["fixtures", "verify", "--receipt"])
        .arg(&receipt)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let validation: serde_json::Value =
        serde_json::from_slice(&fs::read(receipt).unwrap()).unwrap();
    assert_eq!(validation["validation_method"], "input_identity");
    assert_eq!(validation["checkout_dirty"], true);
    assert_eq!(
        validation["checkout_head"],
        validation["bundle_source_head"]
    );
    assert_eq!(
        validation["inputs_sha256"],
        String::from(hash(
            &serde_json::to_vec(&(&f.manifest.sources, &f.manifest.build_policy)).unwrap()
        ))
    );
    assert!(carrick_xtask::accept::verify_signed_fixtures(f.repo.path()).is_err());
    fixtures::restore(f.repo.path(), &f.path, None).unwrap();
    let installed: serde_json::Value = serde_json::from_slice(
        &fs::read(f.repo.path().join(fixtures::INSTALLED_MANIFEST)).unwrap(),
    )
    .unwrap();
    assert_eq!(installed["validation"], validation);
}

#[test]
fn unresolved_fixture_closure_fails_closed() {
    let f = Fixture::new();
    fixtures::restore(f.repo.path(), &f.path, None).unwrap();
    write(
        f.repo.path(),
        "fixtures/embed-el1-sched/Cargo.toml",
        b"not a manifest",
    );
    assert!(
        fixtures::verify_installed(f.repo.path())
            .unwrap_err()
            .to_string()
            .contains("controlled fixture command failed")
    );
    git(
        f.repo.path(),
        &["restore", "fixtures/embed-el1-sched/Cargo.toml"],
    );
    fs::remove_file(f.repo.path().join("fixtures/embed-el1-sched/Cargo.lock")).unwrap();
    assert!(
        fixtures::verify_installed(f.repo.path())
            .unwrap_err()
            .to_string()
            .contains("missing fixture manifest or lockfile")
    );
}

#[test]
fn transitive_fixture_dependency_edits_are_rejected() {
    let f = Fixture::new();
    fixtures::restore(f.repo.path(), &f.path, None).unwrap();
    write(
        f.repo.path(),
        "crates/fixture-transitive/src/lib.rs",
        b"// changed\n",
    );
    assert!(fixtures::verify_installed(f.repo.path()).is_err());
    git(
        f.repo.path(),
        &["restore", "crates/fixture-transitive/src/lib.rs"],
    );
    fixtures::verify_installed(f.repo.path()).unwrap();
    write(
        f.repo.path(),
        "crates/fixture-builder/src/lib.rs",
        b"// changed builder\n",
    );
    assert!(fixtures::verify_installed(f.repo.path()).is_err());
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

// Real Git cleanup, just recipes, archive transport and xtask verification.
// Only guest/HVF acceptance is replaced with the fixture preflight it needs.
struct Preparation {
    scratch: tempfile::TempDir,
    archive: PathBuf,
    checkout: PathBuf,
    lock: PathBuf,
    bin: PathBuf,
}

impl Preparation {
    fn new(f: &Fixture) -> Self {
        let scratch = tempfile::tempdir().unwrap();
        let archive = scratch.path().join("fixtures.tar.gz");
        let bundle = f.path.parent().unwrap();
        assert!(
            Command::new("tar")
                .args(["-czf"])
                .arg(&archive)
                .arg("-C")
                .arg(bundle.parent().unwrap())
                .arg(bundle.file_name().unwrap())
                .status()
                .unwrap()
                .success()
        );
        let checkout = scratch.path().join("checkout");
        let lock = scratch.path().join("checkout.lock");
        fs::create_dir(&lock).unwrap();
        let bin = scratch.path().join("bin");
        fs::create_dir(&bin).unwrap();
        write(
            &bin,
            "cargo",
            br#"#!/bin/sh
if [ "$1" = metadata ]; then exec "$FIXTURE_TEST_CARGO" "$@"; fi
while [ "$#" -gt 0 ] && [ "$1" != -- ]; do shift; done
[ "$#" -gt 0 ] || exit 91
shift
exec "$FIXTURE_TEST_XTASK" "$@"
"#,
        );
        write(&bin, "just", br#"#!/bin/sh
if [ "$1" = accept ]; then
    "$FIXTURE_TEST_XTASK" fixtures verify || exit $?
    [ "$CARRICK_HOST_LEASE_MODE" = gate ] || exit 92
    [ -d "$FIXTURE_TEST_CHECKOUT_LOCK" ] || exit 93
    touch "$FIXTURE_TEST_ACCEPTED"
    receipt_dir="target/el1-gate/$(git rev-parse --short HEAD)"
    mkdir -p "$receipt_dir"
    printf '{"head":"%s","phase":"signed","overall":"PASS"}\n' "$(git rev-parse HEAD)" > "$receipt_dir/receipt.json"
    printf '%s\n' '==================== ACCEPT GATE SUMMARY ====================' 'fixture preparation preflight passed (HVF acceptance replaced in this test)' '============================================================='
else
    exec "$FIXTURE_TEST_JUST" --justfile "$FIXTURE_TEST_JUSTFILE" --working-directory "$PWD" "$@"
fi
"#);
        for name in ["cargo", "just"] {
            fs::set_permissions(bin.join(name), fs::Permissions::from_mode(0o755)).unwrap();
        }
        Self {
            scratch,
            archive,
            checkout,
            lock,
            bin,
        }
    }

    fn command(&self, program: &str) -> Command {
        let mut command = Command::new(program);
        let just = Command::new("sh")
            .args(["-c", "command -v just"])
            .output()
            .unwrap();
        assert!(just.status.success());
        command
            .env(
                "PATH",
                format!("{}:{}", self.bin.display(), std::env::var("PATH").unwrap()),
            )
            .env("FIXTURE_TEST_XTASK", env!("CARGO_BIN_EXE_carrick-xtask"))
            .env("FIXTURE_TEST_CARGO", env!("CARGO"))
            .env(
                "FIXTURE_TEST_JUST",
                String::from_utf8(just.stdout).unwrap().trim(),
            )
            .env(
                "FIXTURE_TEST_JUSTFILE",
                Path::new(env!("CARGO_MANIFEST_DIR")).join("../../justfile"),
            )
            .env("FIXTURE_TEST_CHECKOUT_LOCK", &self.lock)
            .env(
                "FIXTURE_TEST_ACCEPTED",
                self.scratch.path().join("accepted"),
            )
            .env(
                "CARRICK_HOST_LEASE_PATH",
                self.scratch.path().join("host.lock"),
            )
            .env_remove("CARRICK_HOST_LEASE_FD")
            .env_remove("CARRICK_HOST_LEASE_MODE");
        command
    }

    fn setup(&self, f: &Fixture) {
        let sha = git(f.repo.path(), &["rev-parse", "HEAD"]);
        let script = carrick_xtask::remote_accept::build_worktree_setup_cmd(
            f.repo.path().to_str().unwrap(),
            self.checkout.to_str().unwrap(),
            &sha,
        );
        let out = self.command("sh").args(["-c", &script]).output().unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    fn remote_job(&self) -> (String, String) {
        let log = self.scratch.path().join("accept.log");
        let exit = self.scratch.path().join("exit");
        let script = carrick_xtask::remote_accept::build_accept_job_script(
            self.checkout.to_str().unwrap(),
            carrick_xtask::accept::AcceptPhase::Signed,
            log.to_str().unwrap(),
            exit.to_str().unwrap(),
            self.lock.to_str().unwrap(),
            Some(self.archive.to_str().unwrap()),
        )
        .unwrap();
        let out = self.command("sh").args(["-c", &script]).output().unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        (
            fs::read_to_string(exit).unwrap().trim().to_owned(),
            fs::read_to_string(log).unwrap(),
        )
    }
}

#[test]
fn remote_preparation_restores_empty_checkout_before_signed_preflight() {
    let f = Fixture::new();
    let p = Preparation::new(&f);
    p.setup(&f);
    let (exit, log) = p.remote_job();
    assert_eq!(exit, "0", "empty checkout preparation failed:\n{log}");
    carrick_xtask::accept::verify_signed_fixtures(&p.checkout).unwrap();
}

#[test]
fn remote_preparation_restores_raw_fixtures_after_same_sha_cleanup() {
    let f = Fixture::new();
    let p = Preparation::new(&f);
    p.setup(&f);
    fixtures::restore(&p.checkout, &f.path, None).unwrap();
    p.setup(&f);
    // Reuse must reinstall missing ignored outputs even when HEAD is unchanged.
    fs::remove_dir_all(p.checkout.join("fixtures/linux-aarch64-hello/target")).unwrap();
    let (exit, log) = p.remote_job();
    assert_eq!(exit, "0", "same-SHA checkout preparation failed:\n{log}");
    carrick_xtask::accept::verify_signed_fixtures(&p.checkout).unwrap();
}

#[test]
fn remote_preparation_rejects_stale_sha_before_acceptance() {
    let f = Fixture::new();
    let p = Preparation::new(&f);
    write(
        f.repo.path(),
        "README.md",
        b"a new commit with the same fixture sources\n",
    );
    git(f.repo.path(), &["add", "README.md"]);
    git(f.repo.path(), &["commit", "-qm", "next commit"]);
    p.setup(&f);
    let (exit, _) = p.remote_job();
    assert_ne!(exit, "0");
    assert!(!p.scratch.path().join("accepted").exists());
    assert!(carrick_xtask::accept::verify_signed_fixtures(&p.checkout).is_err());
}

#[test]
fn actions_restore_entrypoint_preserves_modes_and_passes_fixture_preflight() {
    let f = Fixture::new();
    let p = Preparation::new(&f);
    p.setup(&f);
    let out = p
        .command("just")
        .current_dir(&p.checkout)
        .arg("fixtures-restore")
        .arg(&p.archive)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "Actions restore failed:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    carrick_xtask::accept::verify_signed_fixtures(&p.checkout).unwrap();
}

#[test]
fn trusted_hardware_workflow_prepares_exact_sha_fixtures_before_signed_execution() {
    use yaml_rust2::{Yaml, YamlLoader};
    let workflow = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.github/workflows/kernel-runtime.yml"),
    )
    .unwrap();
    let documents = YamlLoader::load_from_str(&workflow).unwrap();
    let jobs = &documents[0]["jobs"];
    let step = |job: &Yaml, name: &str| -> Yaml {
        job["steps"]
            .as_vec()
            .unwrap()
            .iter()
            .find(|step| step["name"].as_str() == Some(name))
            .unwrap_or_else(|| panic!("missing workflow step: {name}"))
            .clone()
    };
    let mut f = Fixture::new();
    // The fake cleanup helper is still a build input: commit it before creating
    // the exact-SHA bundle/checkout instead of relying on untracked admission.
    write(
        f.repo.path(),
        "scripts/sudo/kill.sh",
        br#"#!/bin/sh
[ "$1" = "$CARRICK_RUN_ID" ] || exit 95
[ "$CARRICK_HOST_LEASE_MODE" = gate ] || exit 92
printf '%s\n' "$1" > "$FIXTURE_TEST_CLEANED"
"#,
    );
    fs::set_permissions(
        f.repo.path().join("scripts/sudo/kill.sh"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    git(f.repo.path(), &["add", "scripts/sudo/kill.sh"]);
    git(
        f.repo.path(),
        &["commit", "-qm", "track workflow cleanup helper"],
    );
    f.manifest.source_head = git(f.repo.path(), &["rev-parse", "HEAD"])
        .try_into()
        .unwrap();
    f.republish();
    let p = Preparation::new(&f);
    p.setup(&f);
    // Only Linux compilation, signing and HVF execution are replaced here.
    // Run the workflow's actual shell, just lease/restore recipes, archive
    // extraction, source validation and signed fixture preflight.
    write(&p.bin, "just", br#"#!/bin/sh
case "$1" in
    fixtures-publish)
        [ "$2" = "$GITHUB_SHA" ] || exit 94
        "$FIXTURE_TEST_XTASK" fixtures verify --manifest "$FIXTURE_TEST_MANIFEST" --sha "$2" || exit $?
        mkdir -p "target/fixtures/published/$2"
        cp "$FIXTURE_TEST_ARCHIVE" "target/fixtures/published/$2/bundle.tar.gz"
        ;;
    ci) : ;;
    build|test-embed|conformance-probes)
        "$FIXTURE_TEST_XTASK" fixtures verify || exit $?
        [ "$CARRICK_HOST_LEASE_MODE" = gate ] || exit 92
        printf '%s\n' "$1" >> "$FIXTURE_TEST_EXECUTIONS"
        ;;
    *) exec "$FIXTURE_TEST_JUST" --justfile "$FIXTURE_TEST_JUSTFILE" --working-directory "$PWD" "$@" ;;
esac
"#);
    write(
        &p.bin,
        "codesign",
        b"#!/bin/sh\nprintf 'com.apple.security.hypervisor\\n'\n",
    );
    write(&p.bin, "otool", b"#!/bin/sh\nprintf '__dof_carrick\\n'\n");
    for name in ["just", "codesign", "otool"] {
        fs::set_permissions(p.bin.join(name), fs::Permissions::from_mode(0o755)).unwrap();
    }
    let executions = p.scratch.path().join("executions");
    let cleaned = p.scratch.path().join("cleaned");
    let sha = git(&p.checkout, &["rev-parse", "HEAD"]);
    let run = |script: &str| {
        p.command("bash")
            .current_dir(&p.checkout)
            .args(["-e", "-c", script])
            .env("GITHUB_SHA", &sha)
            .env("GITHUB_RUN_ID", "fixture-workflow-test")
            .env("GITHUB_RUN_ATTEMPT", "1")
            .env("FIXTURE_TEST_ARCHIVE", &p.archive)
            .env("FIXTURE_TEST_MANIFEST", &f.path)
            .env("FIXTURE_TEST_EXECUTIONS", &executions)
            .env("FIXTURE_TEST_CLEANED", &cleaned)
            .output()
            .unwrap()
    };
    let producer = &jobs["signed-fixtures"];
    if !producer.is_badvalue() {
        assert_eq!(producer["runs-on"].as_str(), Some("ubuntu-24.04-arm"));
        assert_eq!(producer["if"], jobs["hvf-kernel"]["if"]);
        let publish = step(producer, "Publish exact-SHA fixture bundle");
        let out = run(publish["run"].as_str().unwrap());
        assert!(
            out.status.success(),
            "publisher failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let upload = step(producer, "Upload exact-SHA fixture bundle");
        let download = step(&jobs["hvf-kernel"], "Download exact-SHA fixture bundle");
        assert_eq!(upload["uses"].as_str(), Some("actions/upload-artifact@v4"));
        assert_eq!(
            download["uses"].as_str(),
            Some("actions/download-artifact@v4")
        );
        assert_eq!(
            upload["with"]["name"].as_str(),
            Some("signed-fixtures-${{ github.sha }}")
        );
        assert_eq!(download["with"]["name"], upload["with"]["name"]);
        assert_eq!(
            upload["with"]["path"].as_str(),
            Some("target/fixtures/published/${{ github.sha }}/*.tar.gz")
        );
        assert_eq!(upload["with"]["if-no-files-found"].as_str(), Some("error"));
        assert_eq!(
            jobs["hvf-kernel"]["needs"].as_vec().unwrap(),
            &[Yaml::String("signed-fixtures".into())]
        );
        let incoming = download["with"]["path"].as_str().unwrap();
        assert_eq!(incoming, "target/fixtures/incoming");
        fs::create_dir_all(p.checkout.join(incoming)).unwrap();
        fs::copy(
            p.checkout
                .join(format!("target/fixtures/published/{sha}/bundle.tar.gz")),
            p.checkout.join(incoming).join("bundle.tar.gz"),
        )
        .unwrap();
    }
    assert!(fixtures::verify_installed(&p.checkout).is_err());
    let signed = step(&jobs["hvf-kernel"], "Signed embedded guest tests");
    let out = run(signed["run"].as_str().unwrap());
    assert!(
        out.status.success(),
        "workflow signed preparation failed:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !producer.is_badvalue(),
        "native ARM fixture producer is required"
    );
    assert_eq!(
        fs::read_to_string(&executions).unwrap(),
        "build\ntest-embed\nconformance-probes\n"
    );
    assert_eq!(
        fs::read_to_string(&cleaned).unwrap(),
        "signed-fixtures-fixture-workflow-test-1\n"
    );
    carrick_xtask::accept::verify_signed_fixtures(&p.checkout).unwrap();
    // Same-SHA cleanup removes raw fixtures; the workflow must reinstall them.
    fs::remove_dir_all(p.checkout.join("fixtures/linux-aarch64-hello/target")).unwrap();
    assert!(fixtures::verify_installed(&p.checkout).is_err());
    let out = run(signed["run"].as_str().unwrap());
    assert!(
        out.status.success(),
        "same-SHA preparation failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    carrick_xtask::accept::verify_signed_fixtures(&p.checkout).unwrap();
    let cleanup_script = p.checkout.join("scripts/sudo/kill.sh");
    let cleanup_bytes = fs::read(&cleanup_script).unwrap();
    fs::write(&cleanup_script, b"#!/bin/sh\nexit 1\n").unwrap();
    let out = run(signed["run"].as_str().unwrap());
    assert!(
        !out.status.success(),
        "failed cleanup must fail the signed workflow"
    );
    fs::write(&cleanup_script, cleanup_bytes).unwrap();
    // A new checkout cannot consume the previous SHA's downloaded artifact.
    write(&p.checkout, "README.md", b"next workflow commit\n");
    git(&p.checkout, &["add", "README.md"]);
    git(&p.checkout, &["commit", "-qm", "next workflow commit"]);
    let before = fs::read(&executions).unwrap();
    let out = run(signed["run"].as_str().unwrap());
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("wrong SHA"));
    assert_eq!(fs::read(&executions).unwrap(), before);
}

#[test]
fn fixture_preparation_lease_preserves_shell_argument_boundaries() {
    let f = Fixture::new();
    let p = Preparation::new(&f);
    p.setup(&f);
    let out = p
        .command("just")
        .current_dir(&p.checkout)
        .args([
            "lease",
            "gate",
            "sh",
            "-c",
            "printf '%s' \"$1\"",
            "fixture-test",
            "two words",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(out.stdout, b"two words");
}

#[test]
fn remote_accept_cli_transfers_the_bundle_and_prepares_a_fresh_checkout() {
    let f = Fixture::new();
    let mut p = Preparation::new(&f);
    let sha = git(f.repo.path(), &["rev-parse", "HEAD"]);
    let source = f.path.parent().unwrap();
    let stored = f
        .repo
        .path()
        .join("target/fixtures/bundles")
        .join(&sha)
        .join(source.file_name().unwrap());
    fs::create_dir_all(stored.join("objects")).unwrap();
    fs::copy(&f.path, stored.join("manifest.json")).unwrap();
    for entry in fs::read_dir(source.join("objects")).unwrap() {
        let entry = entry.unwrap();
        fs::copy(entry.path(), stored.join("objects").join(entry.file_name())).unwrap();
    }
    let remote = p.scratch.path().join("remote");
    fs::create_dir(&remote).unwrap();
    assert!(
        Command::new("git")
            .args(["clone", "--bare", "--quiet"])
            .arg(f.repo.path())
            .arg(remote.join("carrick.git"))
            .status()
            .unwrap()
            .success()
    );
    p.checkout = remote.join("gate-worktree");
    fs::remove_dir(&p.lock).unwrap();
    p.lock = remote.join("gate-worktree.lock");
    // Only the SSH network boundary is replaced. Real Git and rsync servers
    // execute in scratch; detached acceptance is joined to avoid test polling.
    write(
        &p.bin,
        "ssh",
        br#"#!/bin/sh
[ "$1" != -G ] || exit 0
while [ "$#" -gt 0 ]; do
    case "$1" in
        -o|-p|-l) shift 2 ;;
        -o*) shift ;;
        *) break ;;
    esac
done
shift
script="$*"
case "$script" in
    'df -Pk '*)
        printf '%s\n' 'Filesystem 1024-blocks Used Available Capacity Mounted on' 'fixture-volume 104857600 0 104857600 0% /fixture-test'
        exit 0 ;;
    *nohup*) script="$script
wait" ;;
esac
exec sh -c "$script"
"#,
    );
    fs::set_permissions(p.bin.join("ssh"), fs::Permissions::from_mode(0o755)).unwrap();
    let out = p
        .command(env!("CARGO_BIN_EXE_carrick-xtask"))
        .arg("--root")
        .arg(f.repo.path())
        .args([
            "remote-accept",
            "--phase",
            "signed",
            "--ref",
            &sha,
            "--host",
            "fixture-test-local",
        ])
        .arg("--remote-root")
        .arg(&remote)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "normal remote preparation failed:\n{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    carrick_xtask::accept::verify_signed_fixtures(&p.checkout).unwrap();
    assert!(
        !p.lock.exists(),
        "checkout admission was not released after completion"
    );
}

#[test]
fn fixture_artifact_is_immutable_and_retains_executable_modes() {
    let f = Fixture::new();
    let output = tempfile::tempdir().unwrap();
    let artifact = fixtures::archive::pack(&f.path, output.path()).unwrap();
    let original = fs::read(&artifact).unwrap();
    assert_eq!(
        fixtures::archive::pack(&f.path, output.path()).unwrap(),
        artifact
    );
    assert_eq!(fs::read(&artifact).unwrap(), original);
    fixtures::archive::restore(f.repo.path(), &artifact, None).unwrap();
    carrick_xtask::accept::verify_signed_fixtures(f.repo.path()).unwrap();
    fs::write(&artifact, b"tampered artifact").unwrap();
    assert!(fixtures::archive::pack(&f.path, output.path()).is_err());
}

#[test]
fn archived_missing_tampered_or_linked_objects_fail_before_publication() {
    for case in ["missing", "tampered", "symlink", "mode"] {
        let f = Fixture::new();
        match case {
            "missing" => fs::remove_file(f.object()).unwrap(),
            "tampered" => fs::write(f.object(), b"tampered").unwrap(),
            "symlink" => {
                let object = f.object();
                fs::remove_file(&object).unwrap();
                std::os::unix::fs::symlink("/etc/passwd", object).unwrap();
            }
            "mode" => fs::set_permissions(f.object(), fs::Permissions::from_mode(0o644)).unwrap(),
            _ => unreachable!(),
        }
        let p = Preparation::new(&f);
        p.setup(&f);
        let error = fixtures::archive::restore(&p.checkout, &p.archive, None).unwrap_err();
        assert!(
            !p.checkout.join(fixtures::INSTALLED_MANIFEST).exists(),
            "{case}: {error}"
        );
        assert!(
            !p.checkout.join(&f.manifest.executables[0].path).exists(),
            "{case}: {error}"
        );
    }
}

#[test]
fn remote_bundle_selection_rejects_missing_ambiguous_and_wrong_sha_inputs() {
    let f = Fixture::new();
    let sha = git(f.repo.path(), &["rev-parse", "HEAD"]);
    assert!(fixtures::resolve_bundle(f.repo.path(), &sha, None).is_err());
    assert!(fixtures::resolve_bundle(f.repo.path(), &"a".repeat(40), Some(&f.path)).is_err());
    assert_eq!(
        fixtures::resolve_bundle(f.repo.path(), &sha, Some(&f.path)).unwrap(),
        f.path
    );
    for name in ["one", "two"] {
        let path = f
            .repo
            .path()
            .join("target/fixtures/bundles")
            .join(&sha)
            .join(name);
        fs::create_dir_all(&path).unwrap();
        fs::copy(&f.path, path.join("manifest.json")).unwrap();
    }
    assert!(
        fixtures::resolve_bundle(f.repo.path(), &sha, None)
            .unwrap_err()
            .to_string()
            .contains("found 2")
    );
}

#[test]
fn signed_preparation_requires_a_bundle_and_checkout_admission() {
    for phase in [
        carrick_xtask::accept::AcceptPhase::Signed,
        carrick_xtask::accept::AcceptPhase::All,
    ] {
        assert!(
            carrick_xtask::remote_accept::build_accept_job_script(
                "/checkout",
                phase,
                "/log",
                "/exit",
                "/lock",
                None,
            )
            .is_err()
        );
    }
    let f = Fixture::new();
    let p = Preparation::new(&f);
    p.setup(&f);
    fs::remove_dir(&p.lock).unwrap();
    let (exit, _) = p.remote_job();
    assert_ne!(exit, "0");
    assert!(!p.checkout.join(fixtures::INSTALLED_MANIFEST).exists());
    assert!(!p.scratch.path().join("accepted").exists());
}
