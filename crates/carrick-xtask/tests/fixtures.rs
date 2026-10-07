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

// tempfile may return a path under macOS's symlinked /var. Keep ownership
// for cleanup, but construct all fixture paths from the physical root. Test
// symlinks are created beneath this root and deliberately remain unresolved.
struct CanonicalTempDir {
    _owner: tempfile::TempDir,
    path: PathBuf,
}

impl CanonicalTempDir {
    fn new() -> Self {
        let owner = tempfile::tempdir().unwrap();
        let path = fs::canonicalize(owner.path()).unwrap();
        Self {
            _owner: owner,
            path,
        }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

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
        .env_remove("CARRICK_HOST_LEASE_MODE")
        .env_remove("CARRICK_HOST_LEASE_SOCKET")
        .env_remove("CARRICK_HOST_LEASE_SCOPE_FD");
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
/// The reviewed build-code list: the fixture graph's one build script
/// (`embed-el1-sched/build.rs`, `fn main() {}`) plus `extra` entries.
fn write_reviewed_build_code(root: &Path, extra: &[serde_json::Value]) {
    let mut entries = vec![serde_json::json!({
        "package": "embed-el1-sched",
        "location": "path:fixtures/embed-el1-sched/Cargo.toml",
        "kind": "custom-build",
        "source": "build.rs",
        "sha256": String::from(source_hash(b"fn main() {}\n")),
    })];
    entries.extend(extra.iter().cloned());
    entries.sort_by_key(|e| e.to_string());
    write(
        root,
        "fixtures/reviewed-build-code.json",
        &serde_json::to_vec_pretty(&serde_json::json!({
            "schema": "carrick.fixtures.reviewed-build-code.v1",
            "entries": entries,
        }))
        .unwrap(),
    );
}
fn hash(bytes: &[u8]) -> ContentHash {
    format!("{:x}", Sha256::digest(bytes)).try_into().unwrap()
}
/// Independent statement of the source entry framing: domain with the entry
/// type, big-endian u64 length, then the bytes.
fn source_hash(bytes: &[u8]) -> ContentHash {
    let mut digest = Sha256::new();
    digest.update(b"carrick.fixtures.source.v1\0regular\0");
    digest.update((bytes.len() as u64).to_be_bytes());
    digest.update(bytes);
    format!("{:x}", digest.finalize()).try_into().unwrap()
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
    repo: CanonicalTempDir,
    store: CanonicalTempDir,
    manifest: Manifest,
    path: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        Self::with_probe_count(1)
    }

    fn with_probe_count(count: usize) -> Self {
        let repo = CanonicalTempDir::new();
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
            "scripts/lib/build-env.sh",
            include_bytes!("../../../scripts/lib/build-env.sh"),
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
        // Real, registry-free Cargo graphs exercise direct and transitive closure.
        for name in [
            "carrick-el1-abi",
            "fixture-transitive",
            "fixture-builder",
            "carrick-runtime",
            "fixture-host-helper",
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
        write(root, "shared/banner.txt", b"fixture banner\n");
        write_reviewed_build_code(root, &[]);
        // Same bytes as a symlink to `actual.txt` would hash under link text.
        write(root, "conformance-probes/actual.txt", b"actual\n");
        write(root, "conformance-probes/alias.txt", b"actual.txt");
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
                "[dependencies]\ncarrick-el1-abi = { path = \"../../crates/carrick-el1-abi\" }\n[build-dependencies]\nfixture-builder = { path = \"../../crates/fixture-builder\" }\n[dev-dependencies]\ncarrick-runtime = { path = \"../../crates/carrick-runtime\" }\n[target.'cfg(target_arch = \"x86_64\")'.build-dependencies]\nfixture-host-helper = { path = \"../../crates/fixture-host-helper\" }\n"
            } else {
                ""
            };
            write(root, &format!("{directory}/Cargo.toml"),
                format!("[workspace]\n[package]\nname = \"{name}\"\nversion = \"0.0.0\"\nedition = \"2021\"\n{dependency}").as_bytes());
            if name == "conformance-probes" {
                // A compiler input outside every resolved package directory.
                write(
                    root,
                    &format!("{directory}/src/lib.rs"),
                    b"pub const BANNER: &str = include_str!(\"../../shared/banner.txt\");\n",
                );
            } else {
                write(root, &format!("{directory}/src/lib.rs"), b"// source\n");
            }
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
        for path in git(root, &["ls-files"]).lines().filter(|p| {
            *p != ".gitignore"
                && *p != "scripts/lib/build-env.sh"
                && !p.starts_with("crates/carrick-runtime/")
        }) {
            let source = root.join(path);
            sources.insert(path.to_owned(), source_hash(&fs::read(source).unwrap()));
        }
        let store = CanonicalTempDir::new();
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
            schema: "carrick.fixtures.v3".into(),
            source_head: sha.try_into().unwrap(),
            // What dep-info reports beyond the Cargo closure: the include_str!.
            compiler_inputs: vec!["shared/banner.txt".into()],
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
fn bundle_source_head_is_provenance_not_an_admission_key() {
    let mut f = Fixture::new();
    f.manifest.source_head = "a".repeat(40).try_into().unwrap();
    f.republish();
    fixtures::restore(f.repo.path(), &f.path, None).unwrap();
    let validation = fixtures::verify_installed_receipt(f.repo.path()).unwrap();
    assert_eq!(String::from(validation.bundle_source_head), "a".repeat(40));
    assert_eq!(
        String::from(validation.checkout_head),
        git(f.repo.path(), &["rev-parse", "HEAD"])
    );
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
    f.manifest.sources =
        fixtures::source_hashes(f.repo.path(), &f.manifest.compiler_inputs).unwrap();
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
        .env("CARRICK_HOST_LEASE_PATH", f.store.path().join("host.lock"))
        .env_remove("CARRICK_HOST_LEASE_FD")
        .env_remove("CARRICK_HOST_LEASE_MODE")
        .env_remove("CARRICK_HOST_LEASE_SOCKET")
        .env_remove("CARRICK_HOST_LEASE_SCOPE_FD")
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
    let outside = CanonicalTempDir::new();
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
    // The tree names the dirty working state; the real index is untouched.
    let tree = validation["checkout_tree"].as_str().unwrap();
    assert_ne!(tree, git(f.repo.path(), &["rev-parse", "HEAD^{tree}"]));
    assert_eq!(
        git(
            f.repo.path(),
            &[
                "ls-tree",
                "--name-only",
                tree,
                "crates/carrick-runtime/src/"
            ]
        ),
        "crates/carrick-runtime/src/diagnostic.rs\ncrates/carrick-runtime/src/lib.rs"
    );
    assert!(
        git(f.repo.path(), &["status", "--porcelain"])
            .contains("?? crates/carrick-runtime/src/diagnostic.rs")
    );
    assert_eq!(
        validation["inputs_sha256"],
        String::from(input_identity(&f.manifest))
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

fn commit(root: &Path, path: &str, bytes: &[u8], message: &str) -> String {
    write(root, path, bytes);
    git(root, &["add", "--", path]);
    git(root, &["commit", "-qm", message]);
    git(root, &["rev-parse", "HEAD"])
}

fn input_identity(manifest: &Manifest) -> ContentHash {
    hash(
        &serde_json::to_vec(&(
            &manifest.sources,
            &manifest.compiler_inputs,
            &manifest.build_policy,
        ))
        .unwrap(),
    )
}

fn assert_identity_refusal(f: &Fixture, case: &str) {
    for error in [
        fixtures::verify_installed(f.repo.path()).unwrap_err(),
        fixtures::verify_bundle(f.repo.path(), &f.path, None).unwrap_err(),
    ] {
        let error = error.to_string();
        assert!(error.contains("input identity mismatch"), "{case}: {error}");
    }
    assert!(
        carrick_xtask::accept::verify_signed_fixtures(f.repo.path()).is_err(),
        "{case}: acceptance admitted changed fixture inputs"
    );
}

#[test]
fn committed_unrelated_edit_keeps_bundle_admissible_by_input_identity() {
    let f = Fixture::new();
    let root = f.repo.path();
    let built_at = git(root, &["rev-parse", "HEAD"]);
    let head = commit(
        root,
        "crates/carrick-runtime/src/lib.rs",
        b"// unrelated runtime change\n",
        "unrelated runtime change",
    );
    assert_ne!(head, built_at);
    fixtures::verify_bundle(root, &f.path, Some(&head)).unwrap();
    fixtures::restore(root, &f.path, Some(&head)).unwrap();
    // Acceptance admission: clean checkout, matching input identity.
    let validation = carrick_xtask::accept::verify_signed_fixtures(root).unwrap();
    assert_eq!(String::from(validation.checkout_head), head);
    assert_eq!(String::from(validation.bundle_source_head), built_at);
    assert!(!validation.checkout_dirty);
    assert_eq!(validation.inputs_sha256, input_identity(&f.manifest));
    assert_eq!(
        String::from(validation.checkout_tree),
        git(root, &["rev-parse", "HEAD^{tree}"])
    );
}

#[test]
fn workspace_lockfile_is_not_a_fixture_input() {
    // Fixture workspaces carry their own Cargo.lock; the host workspace lock
    // cannot change fixture bytes and churns with every host dependency.
    let f = Fixture::new();
    let root = f.repo.path();
    fixtures::restore(root, &f.path, None).unwrap();
    write(root, "Cargo.lock", b"# host workspace lock\nversion = 4\n");
    fixtures::verify_installed(root).unwrap();
    commit(
        root,
        "Cargo.lock",
        b"# host workspace lock, new host dependency\nversion = 4\n",
        "host dependency bump",
    );
    fixtures::verify_installed(root).unwrap();
    carrick_xtask::accept::verify_signed_fixtures(root).unwrap();
}

#[test]
fn committed_fixture_input_edits_refuse_by_input_identity() {
    for path in [
        // Fixture source.
        "conformance-probes/src/bin/hello.rs",
        // Direct, transitive and build-dependency path closure members.
        "crates/carrick-el1-abi/src/lib.rs",
        "crates/fixture-transitive/src/lib.rs",
        "crates/fixture-builder/src/lib.rs",
    ] {
        let f = Fixture::new();
        fixtures::restore(f.repo.path(), &f.path, None).unwrap();
        commit(
            f.repo.path(),
            path,
            b"// changed fixture input\n",
            "fixture input change",
        );
        assert_identity_refusal(&f, path);
    }
}

#[test]
fn fixture_lockfile_change_refuses_by_input_identity() {
    let f = Fixture::new();
    let root = f.repo.path();
    fixtures::restore(root, &f.path, None).unwrap();
    let path = "fixtures/embed-el1-sched/Cargo.lock";
    let lock = fs::read_to_string(root.join(path)).unwrap();
    // A still-valid `--locked` lockfile with different bytes.
    let changed = lock.replace("\nversion = 4\n", "\nversion = 3\n");
    assert_ne!(changed, lock);
    commit(root, path, changed.as_bytes(), "fixture lockfile change");
    assert_identity_refusal(&f, path);
}

#[test]
fn toolchain_pin_change_refuses() {
    let f = Fixture::new();
    let root = f.repo.path();
    fixtures::restore(root, &f.path, None).unwrap();
    commit(
        root,
        "rust-toolchain.toml",
        b"[toolchain]\nchannel = \"1.96.0\"\ntargets = [\"aarch64-unknown-linux-musl\"]\n",
        "toolchain pin declaration change",
    );
    assert_identity_refusal(&f, "rust-toolchain.toml declaration");
    let f = Fixture::new();
    let root = f.repo.path();
    fixtures::restore(root, &f.path, None).unwrap();
    commit(
        root,
        "rust-toolchain.toml",
        b"[toolchain]\nchannel = \"1.97.0\"\n",
        "toolchain channel bump",
    );
    // An uninstalled channel may fail before hashing; either way it refuses.
    assert!(fixtures::verify_installed(root).is_err());
    assert!(fixtures::verify_bundle(root, &f.path, None).is_err());
    assert!(carrick_xtask::accept::verify_signed_fixtures(root).is_err());
}

#[test]
fn compiler_input_outside_package_directories_refuses() {
    // `conformance-probes/src/lib.rs` include_str!s `shared/banner.txt`.
    let f = Fixture::new();
    let root = f.repo.path();
    fixtures::restore(root, &f.path, None).unwrap();
    commit(
        root,
        "shared/banner.txt",
        b"changed banner\n",
        "change an included file",
    );
    assert_identity_refusal(&f, "shared/banner.txt");
}

#[test]
fn symlink_with_identical_link_text_refuses() {
    // Regular `alias.txt` holds the bytes `actual.txt`; replacing it with a
    // symlink to `actual.txt` must not keep the same identity.
    let f = Fixture::new();
    let root = f.repo.path();
    fixtures::restore(root, &f.path, None).unwrap();
    fs::remove_file(root.join("conformance-probes/alias.txt")).unwrap();
    std::os::unix::fs::symlink("actual.txt", root.join("conformance-probes/alias.txt")).unwrap();
    git(root, &["add", "--", "conformance-probes/alias.txt"]);
    git(root, &["commit", "-qm", "alias becomes a symlink"]);
    assert!(fixtures::verify_installed(root).is_err());
    assert!(fixtures::verify_bundle(root, &f.path, None).is_err());
    assert!(carrick_xtask::accept::verify_signed_fixtures(root).is_err());
}

#[test]
fn target_cfg_build_dependency_is_a_fixture_input() {
    // `embed-el1-sched` has an x86_64-only build-dependency: a publisher on
    // x86_64 compiles it, so it is an input whatever the verifier's host.
    let f = Fixture::new();
    let root = f.repo.path();
    fixtures::restore(root, &f.path, None).unwrap();
    commit(
        root,
        "crates/fixture-host-helper/src/lib.rs",
        b"// changed host-only build helper\n",
        "change target-cfg build helper",
    );
    assert_identity_refusal(&f, "crates/fixture-host-helper/src/lib.rs");
}

fn copy_bundle(from: &Path, to: &Path) {
    fs::create_dir_all(to.join("objects")).unwrap();
    fs::copy(from.join("manifest.json"), to.join("manifest.json")).unwrap();
    for entry in fs::read_dir(from.join("objects")).unwrap() {
        let entry = entry.unwrap();
        let destination = to.join("objects").join(entry.file_name());
        fs::copy(entry.path(), &destination).unwrap();
        fs::set_permissions(destination, fs::Permissions::from_mode(0o755)).unwrap();
    }
}

#[test]
fn bundle_selection_follows_fixture_input_identity_across_commits() {
    let f = Fixture::new();
    let root = f.repo.path();
    let built_at = git(root, &["rev-parse", "HEAD"]);
    let bundle = f.path.parent().unwrap();
    let stored = root
        .join("target/fixtures/bundles")
        .join(&built_at)
        .join(bundle.file_name().unwrap());
    copy_bundle(bundle, &stored);
    let head = commit(
        root,
        "crates/carrick-runtime/src/lib.rs",
        b"// unrelated\n",
        "unrelated change",
    );
    assert_eq!(
        fixtures::resolve_bundle(root, &head, None).unwrap(),
        stored.join("manifest.json")
    );
    let head = commit(
        root,
        "crates/fixture-transitive/src/lib.rs",
        b"// fixture input\n",
        "fixture input change",
    );
    let error = fixtures::resolve_bundle(root, &head, None)
        .unwrap_err()
        .to_string();
    assert!(error.contains("found 0"), "{error}");
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
    let external = CanonicalTempDir::new();
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
    scratch: CanonicalTempDir,
    archive: PathBuf,
    checkout: PathBuf,
    lock: PathBuf,
    bin: PathBuf,
}

impl Preparation {
    fn new(f: &Fixture) -> Self {
        let scratch = CanonicalTempDir::new();
        let archive = scratch.path().join("fixtures.tar.gz");
        let bundle = f.path.parent().unwrap();
        // macOS bsdtar otherwise emits `._*` AppleDouble members for files
        // carrying extended attributes (e.g. provenance), which the strict
        // bundle unpacker correctly rejects as undeclared entries.
        assert!(
            Command::new("tar")
                .env("COPYFILE_DISABLE", "1")
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
if [ "$1" = --config ]; then shift 2; fi
if [ "$1" = metadata ]; then exec "$FIXTURE_TEST_CARGO" "$@"; fi
while [ "$#" -gt 0 ] && [ "$1" != -- ]; do shift; done
[ "$#" -gt 0 ] || exit 91
shift
exec "$FIXTURE_TEST_XTASK" "$@"
"#,
        );
        write(&bin, "just", br#"#!/bin/sh
if [ "$1" = accept ]; then
    "$FIXTURE_TEST_XTASK" fixtures verify --receipt "$FIXTURE_TEST_ACCEPTED_DIR/validation.json" || exit $?
    "$FIXTURE_TEST_XTASK" host-lease --mode gate -- true || exit $?
    [ -d "$FIXTURE_TEST_CHECKOUT_LOCK" ] || exit 93
    if [ "$FIXTURE_TEST_REQUIRE_PROVENANCE" = 1 ]; then
        provenance_dir="$FIXTURE_TEST_ACCEPTED_DIR"
        for path in "$provenance_dir"/remote/gate-runs/*; do
            [ ! -d "$path" ] || provenance_dir="$path"
        done
        [ -f "$provenance_dir/fixture-bundle.json" ] || exit 95
    fi
    touch "$FIXTURE_TEST_ACCEPTED"
    receipt_dir="target/el1-gate/$(git rev-parse --short HEAD)"
    mkdir -p "$receipt_dir"
    receipt_path="$receipt_dir/receipt.json"
    while [ "$#" -gt 0 ]; do
        if [ "$1" = --receipt ]; then
            shift
            receipt_path="$1"
        fi
        shift
    done
    printf '{"schema_version":1,"timestamp":"test","head":"%s","clean_tree":true,"phase":"signed","profile":"no-docker","overall":"PASS","steps":[],"skipped_steps":[],"artifact":null,"el1":null,"probe_diffs":[],"cleanup_counts":[],"host_load":{"allow_load":false,"generators":[]},"failures":[],"fixture_bundle":null,"fixture_validation":%s}\n' "$(git rev-parse HEAD)" "$(cat "$FIXTURE_TEST_ACCEPTED_DIR/validation.json")" > "$receipt_path"
    [ "$FIXTURE_TEST_INVALID_RECEIPT" != 1 ] || printf '{}' > "$receipt_path"
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
            .env("FIXTURE_TEST_ACCEPTED_DIR", self.scratch.path())
            .env(
                "FIXTURE_TEST_ACCEPTED",
                self.scratch.path().join("accepted"),
            )
            .env(
                "CARRICK_HOST_LEASE_PATH",
                self.scratch.path().join("host.lock"),
            )
            .env_remove("CARRICK_HOST_LEASE_FD")
            .env_remove("CARRICK_HOST_LEASE_MODE")
            .env_remove("CARRICK_HOST_LEASE_SOCKET")
            .env_remove("CARRICK_HOST_LEASE_SCOPE_FD");
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
        self.remote_job_with_bundle(Some(carrick_xtask::remote_accept::FixtureBundle::local(
            self.archive.to_str().unwrap(),
        )))
    }

    fn remote_job_with_bundle(
        &self,
        bundle: Option<carrick_xtask::remote_accept::FixtureBundle>,
    ) -> (String, String) {
        let log = self.scratch.path().join("accept.log");
        let exit = self.scratch.path().join("exit");
        let script = carrick_xtask::remote_accept::build_accept_job_script(
            self.checkout.to_str().unwrap(),
            carrick_xtask::accept::AcceptPhase::Signed,
            log.to_str().unwrap(),
            exit.to_str().unwrap(),
            self.lock.to_str().unwrap(),
            bundle,
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
fn remote_preparation_restores_empty_checkout_with_remote_bundle() {
    let f = Fixture::new();
    let p = Preparation::new(&f);
    p.setup(&f);
    let (exit, log) = p.remote_job_with_bundle(Some(
        carrick_xtask::remote_accept::FixtureBundle::remote(p.archive.to_str().unwrap()),
    ));
    assert_eq!(exit, "0", "empty checkout preparation failed:\n{log}");
    carrick_xtask::accept::verify_signed_fixtures(&p.checkout).unwrap();
    assert!(log.contains("fixtures: verified"));
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
fn remote_preparation_admits_new_commit_with_same_fixture_inputs() {
    let f = Fixture::new();
    let p = Preparation::new(&f);
    let built_at = git(f.repo.path(), &["rev-parse", "HEAD"]);
    commit(
        f.repo.path(),
        "README.md",
        b"a new commit with the same fixture sources\n",
        "next commit",
    );
    p.setup(&f);
    let (exit, log) = p.remote_job();
    assert_eq!(exit, "0", "same-input bundle refused:\n{log}");
    assert!(p.scratch.path().join("accepted").exists());
    let validation = carrick_xtask::accept::verify_signed_fixtures(&p.checkout).unwrap();
    assert_eq!(String::from(validation.bundle_source_head), built_at);
    assert_eq!(
        String::from(validation.checkout_head),
        git(&p.checkout, &["rev-parse", "HEAD"])
    );
}

#[test]
fn remote_preparation_rejects_changed_fixture_inputs_before_acceptance() {
    let f = Fixture::new();
    let p = Preparation::new(&f);
    commit(
        f.repo.path(),
        "conformance-probes/src/bin/hello.rs",
        b"changed probe source\n",
        "fixture input change",
    );
    p.setup(&f);
    let (exit, log) = p.remote_job();
    assert_ne!(exit, "0");
    assert!(
        log.contains("input identity mismatch"),
        "wrong rejection reason: {log}"
    );
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
fn cache_selection_preserves_ambient_wrapper_rejection_at_fixture_entrypoint() {
    let f = Fixture::new();
    let p = Preparation::new(&f);
    p.setup(&f);
    for cache in ["0", "1"] {
        let out = p
            .command("just")
            .current_dir(&p.checkout)
            .arg("fixtures-restore")
            .arg(&p.archive)
            .env("CARRICK_SCCACHE", cache)
            .env(
                "CARRICK_SCCACHE_BIN",
                p.scratch.path().join("absent-sccache"),
            )
            .env_remove("CARRICK_CARGO_CACHE_CONFIG")
            .env_remove("CARRICK_SCCACHE_RESOLVED")
            .env("RUSTC_WRAPPER", "/ambient/compiler-wrapper")
            .output()
            .unwrap();
        assert!(
            !out.status.success(),
            "cache selection {cache} hid an ambient compiler wrapper"
        );
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.contains("ambient RUSTC_WRAPPER"), "{stderr}");
        assert!(carrick_xtask::accept::verify_signed_fixtures(&p.checkout).is_err());
    }
}

#[test]
fn cache_selection_preserves_ambient_wrapper_rejection_at_fixture_publish() {
    let f = Fixture::new();
    let p = Preparation::new(&f);
    p.setup(&f);
    let sha = git(f.repo.path(), &["rev-parse", "HEAD"]);
    for cache in ["0", "1"] {
        let out = p
            .command("just")
            .current_dir(&p.checkout)
            .arg("fixtures-publish")
            .arg(&sha)
            .env("CARRICK_SCCACHE", cache)
            .env(
                "CARRICK_SCCACHE_BIN",
                p.scratch.path().join("absent-sccache"),
            )
            .env_remove("CARRICK_CARGO_CACHE_CONFIG")
            .env_remove("CARRICK_SCCACHE_RESOLVED")
            .env("RUSTC_WRAPPER", "/ambient/compiler-wrapper")
            .output()
            .unwrap();
        assert!(
            !out.status.success(),
            "cache selection {cache} hid an ambient compiler wrapper"
        );
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.contains("ambient RUSTC_WRAPPER"), "{stderr}");
        assert!(!p.checkout.join("target/fixtures/published").exists());
    }
}

#[test]
fn signed_build_environment_preserves_ambient_wrapper_when_cache_disabled() {
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/lib/build-env.sh");
    for (cache, wrapper) in [
        ("0", "/ambient/compiler-wrapper"),
        ("0", ""),
        ("1", "/ambient/compiler-wrapper"),
        ("1", ""),
    ] {
        let out = Command::new("sh")
            .args([
                "-c",
                ". \"$1\"; test \"${RUSTC_WRAPPER+x}\" = x && test \"$RUSTC_WRAPPER\" = \"$2\"",
                "test",
            ])
            .arg(&script)
            .arg(wrapper)
            .env("CARRICK_SCCACHE", cache)
            .env("RUSTC_WRAPPER", wrapper)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "build environment erased an ambient wrapper: {wrapper:?}"
        );
    }
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
"$FIXTURE_TEST_XTASK" host-lease --mode gate -- true || exit $?
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
        "$FIXTURE_TEST_XTASK" host-lease --mode gate -- true || exit $?
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
    // A new checkout cannot consume an artifact built from different fixture
    // inputs; admission is by input identity, not by commit.
    commit(
        &p.checkout,
        "conformance-probes/src/bin/hello.rs",
        b"next workflow fixture input\n",
        "next workflow commit",
    );
    let before = fs::read(&executions).unwrap();
    let out = run(signed["run"].as_str().unwrap());
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("input identity mismatch"));
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
    check_remote_accept_cli(false, false);
}

#[test]
fn remote_accept_cli_attach_recovers_remote_bundle_provenance() {
    check_remote_accept_cli(true, false);
}

#[test]
fn remote_accept_cli_propagates_receipt_annotation_failure() {
    check_remote_accept_cli(false, true);
}

fn check_remote_accept_cli(remote_bundle: bool, invalid_receipt: bool) {
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
    let real_rsync = Command::new("sh")
        .args(["-c", "command -v rsync"])
        .output()
        .unwrap();
    write(
        &p.bin,
        "rsync",
        br#"#!/bin/sh
if [ "$FIXTURE_TEST_INTERRUPT_FETCH" = 1 ]; then
    for arg in "$@"; do
        case "$arg" in *:*/target/el1-gate/*) exit 94 ;; esac
    done
fi
exec "$FIXTURE_TEST_RSYNC" "$@"
"#,
    );
    fs::set_permissions(p.bin.join("rsync"), fs::Permissions::from_mode(0o755)).unwrap();
    let mut cli = p.command(env!("CARGO_BIN_EXE_carrick-xtask"));
    cli.env("FIXTURE_TEST_REQUIRE_PROVENANCE", "1");
    cli.env(
        "FIXTURE_TEST_RSYNC",
        String::from_utf8_lossy(&real_rsync.stdout).trim(),
    );
    cli.arg("--root")
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
        .arg(&remote);
    if remote_bundle {
        cli.arg("--remote-bundle").arg(&p.archive);
    }
    if invalid_receipt {
        cli.env("FIXTURE_TEST_INVALID_RECEIPT", "1");
    }
    let out = cli.output().unwrap();
    if invalid_receipt {
        assert!(
            !out.status.success(),
            "annotation failure returned zero: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        return;
    }
    assert!(
        out.status.success(),
        "normal remote preparation failed:\n{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let run_id = fs::read_dir(remote.join("gate-runs"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .file_name();
    let local_receipt =
        carrick_xtask::remote_accept::local_receipt_path(f.repo.path(), run_id.to_str().unwrap());
    let mut receipt: serde_json::Value =
        serde_json::from_slice(&fs::read(&local_receipt).unwrap()).unwrap();
    let validation = receipt["fixture_validation"].clone();
    assert_eq!(validation["validation_method"], "input_identity");
    assert_eq!(validation["checkout_dirty"], false);
    let provenance = receipt["fixture_bundle"].clone();
    assert!(!provenance.is_null(), "fresh run lacks verified provenance");
    receipt["fixture_bundle"] = serde_json::Value::Null;
    fs::write(&local_receipt, serde_json::to_vec(&receipt).unwrap()).unwrap();
    let interrupted = p
        .command(env!("CARGO_BIN_EXE_carrick-xtask"))
        .env(
            "FIXTURE_TEST_RSYNC",
            String::from_utf8_lossy(&real_rsync.stdout).trim(),
        )
        .env("FIXTURE_TEST_INTERRUPT_FETCH", "1")
        .arg("--root")
        .arg(f.repo.path())
        .args(["remote-accept", "--host", "fixture-test-local", "--attach"])
        .arg(&run_id)
        .arg("--remote-root")
        .arg(&remote)
        .output()
        .unwrap();
    assert!(
        !interrupted.status.success(),
        "interrupted fetch returned zero"
    );
    fs::remove_dir_all(local_receipt.parent().unwrap()).unwrap();
    // A later run may reuse the same worktree and SHA. Attach must recover
    // this run's receipt, rather than pairing its provenance with a new gate.
    let worktree_receipt = p
        .checkout
        .join("target/el1-gate")
        .join(git(&p.checkout, &["rev-parse", "--short", "HEAD"]))
        .join("receipt.json");
    receipt["timestamp"] = serde_json::json!("another-run");
    fs::write(worktree_receipt, serde_json::to_vec(&receipt).unwrap()).unwrap();
    let attach = p
        .command(env!("CARGO_BIN_EXE_carrick-xtask"))
        .env(
            "FIXTURE_TEST_RSYNC",
            String::from_utf8_lossy(&real_rsync.stdout).trim(),
        )
        .arg("--root")
        .arg(f.repo.path())
        .args(["remote-accept", "--host", "fixture-test-local", "--attach"])
        .arg(&run_id)
        .arg("--remote-root")
        .arg(&remote)
        .output()
        .unwrap();
    assert!(
        attach.status.success(),
        "attach failed: {}",
        String::from_utf8_lossy(&attach.stderr)
    );
    let attached: serde_json::Value =
        serde_json::from_slice(&fs::read(&local_receipt).unwrap()).unwrap();
    assert_eq!(
        attached["fixture_validation"], validation,
        "attach lost input validation"
    );
    assert_eq!(
        attached["fixture_bundle"], provenance,
        "attach lost run provenance"
    );
    assert_eq!(
        attached["timestamp"], "test",
        "attach fetched another run's receipt"
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
    let output = CanonicalTempDir::new();
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
    assert!(fixtures::resolve_bundle(f.repo.path(), "HEAD", Some(&f.path)).is_err());
    // An explicit bundle is selected as given; the receiver admits it by
    // input identity against its own exact checkout.
    assert_eq!(
        fixtures::resolve_bundle(f.repo.path(), &"a".repeat(40), Some(&f.path)).unwrap(),
        f.path
    );
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

#[test]
fn remote_preparation_rejects_unpublished_or_linked_archives() {
    for case in ["symlink", "parent-symlink", "partial", "directory"] {
        let f = Fixture::new();
        let p = Preparation::new(&f);
        p.setup(&f);
        let input = p.scratch.path().join(if case == "partial" {
            "bundle.partial-upload.tar.gz"
        } else {
            "input"
        });
        match case {
            "symlink" => std::os::unix::fs::symlink(&p.archive, &input).unwrap(),
            "parent-symlink" => std::os::unix::fs::symlink(p.scratch.path(), &input).unwrap(),
            "partial" => {
                fs::copy(&p.archive, &input).unwrap();
            }
            "directory" => fs::create_dir(&input).unwrap(),
            _ => unreachable!(),
        }
        let input = if case == "parent-symlink" {
            input.join("fixtures.tar.gz")
        } else {
            input
        };
        let error = carrick_xtask::remote_accept::capture_fixture_bundle(
            &p.checkout,
            &input,
            p.scratch.path(),
            carrick_xtask::remote_accept::FixtureBundleSource::Remote,
        )
        .unwrap_err();
        match (case, &error) {
            ("symlink", fixtures::FixturesError::Io(error)) => {
                assert_eq!(error.raw_os_error(), Some(libc::ELOOP))
            }
            ("parent-symlink", fixtures::FixturesError::Io(error)) => assert!(matches!(
                error.raw_os_error(),
                Some(libc::ELOOP | libc::ENOTDIR)
            )),
            ("partial", fixtures::FixturesError::Invalid(reason)) => {
                assert_eq!(reason, "unfinished archive publication")
            }
            ("directory", fixtures::FixturesError::Invalid(reason)) => {
                assert_eq!(reason, "fixture archive source is not a regular file")
            }
            _ => panic!("{case}: wrong rejection reason: {error}"),
        }
        let (exit, log) = p.remote_job_with_bundle(Some(
            carrick_xtask::remote_accept::FixtureBundle::remote(input.to_str().unwrap()),
        ));
        assert!(
            log.contains(&error.to_string()),
            "{case}: wrong remote rejection: {log}"
        );
        assert_ne!(exit, "0", "{case} admitted: {log}");
        assert!(!p.scratch.path().join("accepted").exists());
        assert!(!p.scratch.path().join("fixture-bundle.json").exists());
    }
}

fn check_gzip_transport(case: &str) {
    let f = Fixture::new();
    let p = Preparation::new(&f);
    p.setup(&f);
    let mut bytes = fs::read(&p.archive).unwrap();
    let n = bytes.len();
    match case {
        "trailer" => bytes.truncate(n - 8),
        "crc" => bytes[n - 8] ^= 1,
        "length" => bytes[n - 4] ^= 1,
        "garbage" => bytes.extend_from_slice(b"trailing garbage"),
        _ => unreachable!(),
    }
    fs::write(&p.archive, bytes).unwrap();
    let sha = git(&p.checkout, &["rev-parse", "HEAD"]);
    let reason = fixtures::archive::verify(&p.checkout, &p.archive, &sha)
        .unwrap_err()
        .to_string();
    let out = p
        .command(env!("CARGO_BIN_EXE_carrick-xtask"))
        .current_dir(&p.checkout)
        .args(["fixtures", "verify", "--bundle"])
        .arg(&p.archive)
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "{case} verified: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains(&reason),
        "{case}: wrong CLI rejection"
    );
    let (exit, log) = p.remote_job_with_bundle(Some(
        carrick_xtask::remote_accept::FixtureBundle::remote(p.archive.to_str().unwrap()),
    ));
    assert_ne!(exit, "0", "{case} admitted: {log}");
    assert!(
        log.contains(&reason),
        "{case}: wrong remote rejection: {log}"
    );
    assert!(!p.checkout.join(fixtures::INSTALLED_MANIFEST).exists());
}

#[test]
fn fixture_verification_rejects_truncated_trailer() {
    check_gzip_transport("trailer");
}
#[test]
fn fixture_verification_rejects_corrupted_crc() {
    check_gzip_transport("crc");
}
#[test]
fn fixture_verification_rejects_corrupted_length() {
    check_gzip_transport("length");
}
#[test]
fn fixture_verification_rejects_trailing_garbage() {
    check_gzip_transport("garbage");
}

#[test]
fn remote_preparation_persists_verified_provenance_for_both_sources() {
    for remote in [false, true] {
        let f = Fixture::new();
        let p = Preparation::new(&f);
        p.setup(&f);
        let bundle = if remote {
            carrick_xtask::remote_accept::FixtureBundle::remote(p.archive.to_str().unwrap())
        } else {
            carrick_xtask::remote_accept::FixtureBundle::local(p.archive.to_str().unwrap())
        };
        let (exit, log) = p.remote_job_with_bundle(Some(bundle));
        assert_eq!(exit, "0", "{log}");
        let value: serde_json::Value = serde_json::from_slice(
            &fs::read(p.scratch.path().join("fixture-bundle.json"))
                .expect("run provenance missing"),
        )
        .unwrap();
        assert_eq!(value["source"], if remote { "remote" } else { "local" });
        assert_eq!(value["path"], p.archive.to_str().unwrap());
        let captured = value["captured_path"].as_str().unwrap();
        assert_ne!(captured, p.archive.to_str().unwrap());
        assert_eq!(fs::read(captured).unwrap(), fs::read(&p.archive).unwrap());
        assert_eq!(
            value["archive_sha256"],
            format!("{:x}", Sha256::digest(fs::read(captured).unwrap()))
        );
    }
}

#[test]
fn replacing_shared_archive_after_verification_restores_captured_bytes() {
    let mut f = Fixture::new();
    let p = Preparation::new(&f);
    p.setup(&f);
    let original = fs::read(f.object()).unwrap();
    let original_archive = fs::read(&p.archive).unwrap();
    let provenance = carrick_xtask::remote_accept::capture_fixture_bundle(
        &p.checkout,
        &p.archive,
        p.scratch.path(),
        carrick_xtask::remote_accept::FixtureBundleSource::Remote,
    )
    .unwrap();
    let sha = git(f.repo.path(), &["rev-parse", "HEAD"]);
    let identity = provenance.identity;
    let captured_path = PathBuf::from(provenance.captured_path);
    let captured_sha = provenance.archive_sha256;

    let replacement = elf(f.manifest.executables[0].target, 240);
    let digest = hash(&replacement);
    let object_name: String = digest.clone().into();
    write(
        f.store.path(),
        &format!("objects/{object_name}"),
        &replacement,
    );
    fs::set_permissions(
        f.store.path().join("objects").join(&object_name),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    f.manifest.executables[0].sha256 = digest;
    f.republish();
    let output = CanonicalTempDir::new();
    let second = fixtures::archive::pack(&f.path, output.path()).unwrap();
    assert_ne!(
        fixtures::archive::verify(&p.checkout, &second, &sha)
            .unwrap()
            .1,
        identity
    );
    fs::rename(second, &p.archive).unwrap();
    assert_ne!(fs::read(&p.archive).unwrap(), original_archive);
    fixtures::archive::restore(&p.checkout, &captured_path, None).unwrap();
    assert_eq!(
        fs::read(p.checkout.join(&f.manifest.executables[0].path)).unwrap(),
        original
    );
    assert_eq!(
        format!("{:x}", Sha256::digest(fs::read(&captured_path).unwrap())),
        captured_sha
    );
}

#[test]
fn remote_preparation_provenance_write_failure_stops_acceptance() {
    let f = Fixture::new();
    let p = Preparation::new(&f);
    p.setup(&f);
    fs::create_dir(p.scratch.path().join("fixture-bundle.json")).unwrap();
    let (exit, log) = p.remote_job();
    assert_ne!(exit, "0", "provenance write failure ignored: {log}");
    assert!(
        log.contains("Is a directory"),
        "wrong rejection reason: {log}"
    );
    assert!(!p.scratch.path().join("accepted").exists());
    assert!(!p.checkout.join(fixtures::INSTALLED_MANIFEST).exists());
}

fn check_archive_input_identity(case: &str, expected: &str) {
    let mut f = Fixture::new();
    if case == "policy" {
        f.manifest
            .build_policy
            .fixed_environment
            .insert("CARGO_PROFILE_RELEASE_OPT_LEVEL".into(), "0".into());
        f.republish();
    }
    let p = Preparation::new(&f);
    p.setup(&f);
    if case == "source" {
        write(
            &p.checkout,
            "conformance-probes/src/bin/probeinit.rs",
            b"// changed fixture input\n",
        );
    }
    for action in ["prepare", "verify"] {
        let run_dir = p.scratch.path().join(action);
        let mut command = p.command(env!("CARGO_BIN_EXE_carrick-xtask"));
        command
            .current_dir(&p.checkout)
            .args(["fixtures", action, "--bundle"])
            .arg(&p.archive);
        if action == "verify" {
            command
                .arg("--receipt")
                .arg(p.scratch.path().join("validation.json"));
        } else {
            command
                .arg("--run-dir")
                .arg(&run_dir)
                .args(["--source", "remote"]);
        }
        if case == "ambient" {
            command.env("CARGO_PROFILE_RELEASE_OPT_LEVEL", "0");
        }
        let output = command.output().unwrap();
        assert!(
            !output.status.success(),
            "{case} {action} admitted invalid fixture inputs"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains(expected),
            "{case} {action}: wrong rejection: {stderr}"
        );
        assert!(!run_dir.join("fixture-bundle.json").exists());
        assert!(!p.scratch.path().join("validation.json").exists());
        assert!(!p.checkout.join(fixtures::INSTALLED_MANIFEST).exists());
    }
}

#[test]
fn archive_verification_rejects_changed_build_policy_before_provenance() {
    check_archive_input_identity("policy", "build policy mismatch");
}

#[test]
fn archive_verification_rejects_changed_scoped_inputs_before_provenance() {
    check_archive_input_identity("source", "dirty fixture source inputs");
}

#[test]
fn archive_verification_rejects_ambient_override_before_provenance() {
    check_archive_input_identity("ambient", "build policy forbids ambient");
}

#[test]
fn archive_verification_records_scoped_evidence_atomically() {
    let f = Fixture::new();
    let p = Preparation::new(&f);
    p.setup(&f);
    write(
        &p.checkout,
        "crates/carrick-runtime/src/lib.rs",
        b"// unrelated diagnostic\n",
    );
    let receipt = p.scratch.path().join("validation.json");
    fs::write(&receipt, b"previous receipt").unwrap();
    let mut previous = fs::File::open(&receipt).unwrap();
    let output = p
        .command(env!("CARGO_BIN_EXE_carrick-xtask"))
        .current_dir(&p.checkout)
        .args(["fixtures", "verify", "--bundle"])
        .arg(&p.archive)
        .arg("--receipt")
        .arg(&receipt)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let validation: serde_json::Value =
        serde_json::from_slice(&fs::read(&receipt).unwrap()).unwrap();
    assert_eq!(validation["validation_method"], "input_identity");
    assert_eq!(validation["checkout_dirty"], true);
    assert_eq!(
        validation["checkout_head"],
        validation["bundle_source_head"]
    );
    let mut old_bytes = Vec::new();
    std::io::Read::read_to_end(&mut previous, &mut old_bytes).unwrap();
    assert_eq!(
        old_bytes, b"previous receipt",
        "verification overwrote a published receipt inode"
    );
}

#[test]
fn cargo_dep_info_records_out_of_package_compiler_inputs() {
    // A real Cargo build reports `#[path]` modules, `include_str!` targets
    // outside the package and build-script `rerun-if-changed` files.
    let snapshot = CanonicalTempDir::new();
    let root = snapshot.path();
    write(root, "shared/banner.txt", b"banner\n");
    write(root, "shared/build-input.txt", b"build input\n");
    write(root, "outside/abi.rs", b"pub const ABI: u32 = 1;\n");
    write(
        root,
        "fixtures/probe/Cargo.toml",
        b"[workspace]\n[package]\nname = \"probe\"\nversion = \"0.0.0\"\nedition = \"2021\"\nbuild = \"build.rs\"\n",
    );
    write(
        root,
        "fixtures/probe/build.rs",
        b"fn main() { println!(\"cargo:rerun-if-changed=../../shared/build-input.txt\"); }\n",
    );
    write(
        root,
        "fixtures/probe/src/main.rs",
        b"#[path = \"../../../outside/abi.rs\"]\nmod abi;\nconst BANNER: &str = include_str!(\"../../../shared/banner.txt\");\nfn main() { println!(\"{} {}\", abi::ABI, BANNER); }\n",
    );
    let output = Command::new(env!("CARGO"))
        .current_dir(root.join("fixtures/probe"))
        .args(["build", "--offline", "--quiet"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let dep_info = root.join("fixtures/probe/target/debug/probe.d");
    let sysroot = Command::new("rustc")
        .args(["--print", "sysroot"])
        .output()
        .unwrap();
    let sysroot = PathBuf::from(String::from_utf8(sysroot.stdout).unwrap().trim());
    let recorded = fixtures::dep_info::classify(root, &[dep_info], &[sysroot]).unwrap();
    assert_eq!(
        recorded,
        [
            "fixtures/probe/build.rs",
            "fixtures/probe/src/main.rs",
            "outside/abi.rs",
            "shared/banner.txt",
            "shared/build-input.txt",
        ]
    );
}

#[test]
fn dep_info_classification_fails_closed() {
    let snapshot = CanonicalTempDir::new();
    let root = snapshot.path();
    let elsewhere = CanonicalTempDir::new();
    write(root, "src/main.rs", b"");
    write(root, "target/release/build/out/generated.rs", b"");
    write(elsewhere.path(), "foreign.rs", b"");
    let case = |name: &str, body: String| {
        write(root, &format!("dep/{name}.d"), body.as_bytes());
        fixtures::dep_info::classify(root, &[root.join(format!("dep/{name}.d"))], &[])
            .unwrap_err()
            .to_string()
    };
    let main = root.join("src/main.rs").display().to_string();
    assert!(
        case(
            "generated",
            format!(
                "out: {main} {}\n",
                root.join("target/release/build/out/generated.rs").display()
            )
        )
        .contains("under target/")
    );
    assert!(
        case(
            "foreign",
            format!(
                "out: {main} {}\n",
                elsewhere.path().join("foreign.rs").display()
            )
        )
        .contains("outside the checkout")
    );
    assert!(case("relative", "out: src/main.rs\n".into()).contains("relative compiler input"));
    assert!(case("empty", "out:\n".into()).contains("names no inputs"));
    assert!(
        fixtures::dep_info::classify(root, &[root.join("dep/missing.d")], &[])
            .unwrap_err()
            .to_string()
            .contains("missing or unreadable fixture dep-info")
    );
    // Escaped spaces, continuations and comments parse as Make does.
    assert_eq!(
        fixtures::dep_info::parse("out: /a\\ b.rs \\\n /c.rs\n# env-dep:X=1\n/a\\ b.rs:\n"),
        [PathBuf::from("/a b.rs"), PathBuf::from("/c.rs")]
    );
}

#[test]
fn every_executable_has_a_declared_dep_info_location() {
    let f = Fixture::new();
    let embed = [
        ("embed-interceptor-probe", "interceptor-probe"),
        ("embed-zone-readers", "zone-readers"),
        ("embed-icache-reuse", "icache-reuse"),
        ("embed-el1-sched", "el1-sched"),
    ];
    for path in fixtures::executable_inventory(f.repo.path())
        .unwrap()
        .keys()
    {
        let dep_info = fixtures::dep_info::dep_info_path(path, &embed).unwrap();
        if path == "target/embed-fixtures/el1-sched-aarch64" {
            assert_eq!(
                dep_info,
                "fixtures/embed-el1-sched/target/aarch64-unknown-linux-musl/release/el1-sched.d"
            );
        } else if !path.starts_with("target/embed-fixtures/") {
            assert_eq!(dep_info, format!("{path}.d"));
        }
    }
    assert!(
        fixtures::dep_info::dep_info_path("target/embed-fixtures/unknown-aarch64", &embed).is_err()
    );
}

#[test]
fn recorded_compiler_inputs_must_be_tracked_sources() {
    for (inputs, expected) in [
        (vec!["target/generated.rs".to_owned()], "under target/"),
        (vec!["shared/missing.txt".to_owned()], "not a tracked file"),
        (vec!["../escape.rs".to_owned()], "unsafe fixture path"),
        (
            vec![
                "shared/banner.txt".to_owned(),
                "conformance-probes/actual.txt".to_owned(),
            ],
            "noncanonical",
        ),
    ] {
        let mut f = Fixture::new();
        f.manifest.compiler_inputs = inputs;
        f.republish();
        f.rejected(expected);
    }
    // Deleting a recorded input is a dirty input, never a silent omission.
    let f = Fixture::new();
    fixtures::restore(f.repo.path(), &f.path, None).unwrap();
    fs::remove_file(f.repo.path().join("shared/banner.txt")).unwrap();
    assert!(
        fixtures::verify_installed(f.repo.path())
            .unwrap_err()
            .to_string()
            .contains("dirty fixture source")
    );
}

#[test]
fn source_entries_hash_with_type_and_length_framing() {
    let f = Fixture::new();
    let root = f.repo.path();
    assert_eq!(
        fixtures::hash_source(root, "conformance-probes/alias.txt").unwrap(),
        source_hash(b"actual.txt")
    );
    assert_ne!(
        fixtures::hash_source(root, "conformance-probes/alias.txt").unwrap(),
        hash(b"actual.txt"),
        "source digests carry a type domain, not raw content hashes"
    );
    fs::remove_file(root.join("conformance-probes/alias.txt")).unwrap();
    std::os::unix::fs::symlink("actual.txt", root.join("conformance-probes/alias.txt")).unwrap();
    assert!(
        fixtures::hash_source(root, "conformance-probes/alias.txt")
            .unwrap_err()
            .to_string()
            .contains("not a regular file")
    );
}

#[test]
fn unfiltered_graph_includes_host_only_build_dependencies() {
    let f = Fixture::new();
    let sources = fixtures::source_hashes(f.repo.path(), &[]).unwrap();
    assert!(sources.contains_key("crates/fixture-host-helper/src/lib.rs"));
    assert!(sources.contains_key("crates/fixture-host-helper/Cargo.toml"));
    // The include_str! target is not in the Cargo closure; only dep-info
    // (the manifest's compiler_inputs) brings it in.
    assert!(!sources.contains_key("shared/banner.txt"));
}

#[test]
fn dep_info_refuses_compiler_inputs_reached_through_symlinks() {
    // `shared/current.txt -> a.txt`: recording only the canonical `a.txt`
    // would let a retarget to `b.txt` keep the identity.
    let snapshot = CanonicalTempDir::new();
    let root = snapshot.path();
    write(root, "src/main.rs", b"");
    write(root, "shared/a.txt", b"a\n");
    write(root, "shared/b.txt", b"b\n");
    std::os::unix::fs::symlink("a.txt", root.join("shared/current.txt")).unwrap();
    std::os::unix::fs::symlink("shared", root.join("linked-dir")).unwrap();
    for reported in ["shared/current.txt", "linked-dir/a.txt"] {
        write(
            root,
            "dep/main.d",
            format!(
                "out: {} {}\n",
                root.join("src/main.rs").display(),
                root.join(reported).display()
            )
            .as_bytes(),
        );
        let result = fixtures::dep_info::classify(root, &[root.join("dep/main.d")], &[]);
        assert!(
            result
                .as_ref()
                .is_err_and(|e| e.to_string().contains("symlink")),
            "{reported}: {result:?}"
        );
    }
}

#[test]
fn unreviewed_build_script_refuses_publish_and_admission() {
    // A build script can read any file without telling dep-info.
    let f = Fixture::new();
    let root = f.repo.path();
    commit(
        root,
        "fixtures/embed-zone-readers/build.rs",
        b"fn main() { let b = std::fs::read_to_string(\"../../shared/banner.txt\").unwrap(); println!(\"cargo:rustc-env=BANNER={}\", b.trim()); }\n",
        "new build script reading an outside file",
    );
    let result = fixtures::source_hashes(root, &f.manifest.compiler_inputs);
    assert!(
        result
            .as_ref()
            .is_err_and(|e| e.to_string().contains("unreviewed build code")),
        "{result:?}"
    );
    // Reviewing it (recording its hash) admits it; the list is an input.
    let build_rs = fs::read(root.join("fixtures/embed-zone-readers/build.rs")).unwrap();
    let reviewed = serde_json::json!({
        "package": "embed-zone-readers",
        "location": "path:fixtures/embed-zone-readers/Cargo.toml",
        "kind": "custom-build",
        "source": "build.rs",
        "sha256": String::from(source_hash(&build_rs)),
    });
    write_reviewed_build_code(root, std::slice::from_ref(&reviewed));
    git(root, &["commit", "-qam", "review the build script"]);
    let sources = fixtures::source_hashes(root, &f.manifest.compiler_inputs).unwrap();
    assert!(sources.contains_key("fixtures/reviewed-build-code.json"));
    // Changing the reviewed script refuses until it is reviewed again.
    commit(
        root,
        "fixtures/embed-zone-readers/build.rs",
        b"fn main() {}\n",
        "edit reviewed build script",
    );
    assert!(
        fixtures::source_hashes(root, &f.manifest.compiler_inputs)
            .unwrap_err()
            .to_string()
            .contains("unreviewed build code")
    );
    // A stale entry (reviewed code no longer in the graph) also refuses.
    fs::remove_file(root.join("fixtures/embed-zone-readers/build.rs")).unwrap();
    git(root, &["commit", "-qam", "drop the build script"]);
    assert!(
        fixtures::source_hashes(root, &f.manifest.compiler_inputs)
            .unwrap_err()
            .to_string()
            .contains("stale reviewed entries: [custom-build path:fixtures/embed-zone-readers")
    );
}

#[test]
fn unreviewed_proc_macro_refuses() {
    let f = Fixture::new();
    let root = f.repo.path();
    write(
        root,
        "crates/fixture-macro/Cargo.toml",
        b"[package]\nname = \"fixture-macro\"\nversion = \"0.0.0\"\nedition = \"2021\"\n[lib]\nproc-macro = true\n",
    );
    write(root, "crates/fixture-macro/src/lib.rs", b"// macro\n");
    let manifest = "fixtures/embed-icache-reuse/Cargo.toml";
    let mut text = fs::read_to_string(root.join(manifest)).unwrap();
    text.push_str("[dependencies]\nfixture-macro = { path = \"../../crates/fixture-macro\" }\n");
    write(root, manifest, text.as_bytes());
    let output = Command::new("cargo")
        .current_dir(root)
        .args([
            "generate-lockfile",
            "--offline",
            "--manifest-path",
            manifest,
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    git(root, &["add", "."]);
    git(root, &["commit", "-qm", "proc-macro dependency"]);
    let error = fixtures::source_hashes(root, &f.manifest.compiler_inputs)
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("proc-macro path:crates/fixture-macro/Cargo.toml src/lib.rs"),
        "{error}"
    );
}

#[test]
fn linker_references_resolve_only_to_inventoried_inputs() {
    let inventory: std::collections::BTreeSet<&str> =
        ["conformance-probes/link.ld", "scripts/link.ld"].into();
    let check = |origin: &str, text: &str| fixtures::linker::check(origin, text, &inventory);
    // Inside an inventoried package directory: admitted.
    check(
        "conformance-probes/.cargo/config.toml",
        "rustflags = [\"-C\", \"link-arg=-Tlink.ld\"]",
    )
    .unwrap();
    check(
        "scripts/build-x.sh",
        "\"$lld\" -flavor gnu -T link.ld -o out obj.o",
    )
    .unwrap();
    for (origin, text) in [
        ("scripts/build-x.sh", "\"$lld\" -T \"$repo_root/other.ld\""),
        ("scripts/build-x.sh", "cc -Wl,-T,/abs/link.ld"),
        ("scripts/build-x.sh", "cc -Wl,--script=missing.ld"),
        ("scripts/build-x.sh", "cc -Wl,@response.txt"),
        ("scripts/build-x.sh", "cc foo.lds"),
        ("scripts/build-x.sh", "ld -T"),
    ] {
        assert!(
            check(origin, text)
                .unwrap_err()
                .to_string()
                .contains("linker input reference"),
            "{text}"
        );
    }
    // The real builder scripts and Cargo configuration carry no reference.
    let real = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    for path in [
        ".cargo/config.toml",
        "scripts/build-linux-fixtures.sh",
        "scripts/build-embed-interceptor-probe.sh",
        "scripts/build-embed-zone-readers.sh",
        "scripts/build-embed-icache-reuse.sh",
        "scripts/build-embed-el1-sched.sh",
    ] {
        let text = fs::read_to_string(real.join(path)).unwrap();
        assert_eq!(
            fixtures::linker::references(&text),
            Vec::<String>::new(),
            "{path}"
        );
    }
}

#[test]
fn inventoried_linker_script_change_refuses_by_identity() {
    let f = Fixture::new();
    let root = f.repo.path();
    write(root, "conformance-probes/link.ld", b"SECTIONS {}\n");
    write(
        root,
        "conformance-probes/.cargo/config.toml",
        b"[target.aarch64-unknown-linux-musl]\nrustflags = [\"-C\", \"link-arg=-Tlink.ld\"]\n",
    );
    git(root, &["add", "."]);
    git(root, &["commit", "-qm", "package linker script"]);
    let before = fixtures::source_hashes(root, &f.manifest.compiler_inputs).unwrap();
    commit(
        root,
        "conformance-probes/link.ld",
        b"SECTIONS { . = 0x1000; }\n",
        "change linker script",
    );
    let after = fixtures::source_hashes(root, &f.manifest.compiler_inputs).unwrap();
    assert_ne!(
        before["conformance-probes/link.ld"],
        after["conformance-probes/link.ld"]
    );
}

#[test]
fn linker_script_reference_must_be_an_inventoried_input() {
    // A repo-root linker script named by tracked Cargo configuration is read
    // by the linker, which dep-info does not report.
    let f = Fixture::new();
    let root = f.repo.path();
    write(root, "link.ld", b"SECTIONS {}\n");
    write(
        root,
        "conformance-probes/.cargo/config.toml",
        b"[target.aarch64-unknown-linux-musl]\nrustflags = [\"-C\", \"link-arg=-T../link.ld\"]\n",
    );
    git(
        root,
        &["add", "link.ld", "conformance-probes/.cargo/config.toml"],
    );
    git(root, &["commit", "-qm", "repo-root linker script"]);
    let result = fixtures::source_hashes(root, &f.manifest.compiler_inputs);
    assert!(
        result
            .as_ref()
            .is_err_and(|e| e.to_string().contains("linker input")),
        "{result:?}"
    );
}

#[test]
fn build_script_link_arg_outputs_follow_the_linker_rule() {
    let snapshot = CanonicalTempDir::new();
    let root = snapshot.path();
    let output = "fixtures/embed-x/target/aarch64-unknown-linux-musl/release/build/x-0123/output";
    write(
        root,
        output,
        b"cargo:rustc-cfg=foo\ncargo:rerun-if-changed=build.rs\n",
    );
    let inventory = std::collections::BTreeSet::new();
    fixtures::linker::check_build_script_outputs(root, &["fixtures/embed-x"], &inventory).unwrap();
    write(
        root,
        output,
        b"cargo:rustc-link-arg-bins=-T../../shared/link.ld\n",
    );
    assert!(
        fixtures::linker::check_build_script_outputs(root, &["fixtures/embed-x"], &inventory)
            .unwrap_err()
            .to_string()
            .contains("linker input reference")
    );
}
