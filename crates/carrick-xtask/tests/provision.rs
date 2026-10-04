#![allow(clippy::unwrap_used, clippy::expect_used)]

use carrick_xtask::provision::{
    self, CommandRunner, FixtureDeclaration, FixtureValidationError, ProbeValidationError,
    ProvisionAction, ProvisioningReceipt,
};
use std::collections::HashMap;
use std::ffi::OsStr;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Mutex;

struct StubCommandRunner {
    #[allow(clippy::type_complexity)]
    handlers: Mutex<
        HashMap<
            String,
            Box<
                dyn FnMut(
                        &[&OsStr],
                        Option<&Path>,
                    ) -> Result<
                        carrick_xtask::command::CommandOutput,
                        carrick_xtask::command::CommandError,
                    > + Send,
            >,
        >,
    >,
    recorded_commands: Mutex<Vec<(String, Vec<String>)>>,
}

impl StubCommandRunner {
    fn new() -> Self {
        Self {
            handlers: Mutex::new(HashMap::new()),
            recorded_commands: Mutex::new(Vec::new()),
        }
    }

    fn register<F>(&self, prog: &str, handler: F)
    where
        F: FnMut(
                &[&OsStr],
                Option<&Path>,
            ) -> Result<
                carrick_xtask::command::CommandOutput,
                carrick_xtask::command::CommandError,
            > + Send
            + 'static,
    {
        self.handlers
            .lock()
            .unwrap()
            .insert(prog.to_string(), Box::new(handler));
    }
}

impl CommandRunner for StubCommandRunner {
    fn run_checked(
        &self,
        program: &OsStr,
        argv: &[&OsStr],
        cwd: Option<&Path>,
    ) -> Result<carrick_xtask::command::CommandOutput, carrick_xtask::command::CommandError> {
        let prog_str = program.to_string_lossy().to_string();
        let argv_strings: Vec<String> = argv
            .iter()
            .map(|a| a.to_string_lossy().to_string())
            .collect();
        self.recorded_commands
            .lock()
            .unwrap()
            .push((prog_str.clone(), argv_strings));

        let mut handlers = self.handlers.lock().unwrap();
        if let Some(handler) = handlers.get_mut(&prog_str) {
            handler(argv, cwd)
        } else {
            // Default success exit
            Ok(carrick_xtask::command::CommandOutput {
                status: exit_status_success(),
                stdout: String::new(),
                stderr: String::new(),
            })
        }
    }
}

fn exit_status_success() -> std::process::ExitStatus {
    std::process::Command::new("true")
        .status()
        .expect("spawn true")
}

fn exit_status_failure() -> std::process::ExitStatus {
    std::process::Command::new("false")
        .status()
        .expect("spawn false")
}

fn create_mock_elf(path: &Path, is_aarch64: bool, is_static: bool) {
    let mut data = Vec::with_capacity(128);
    // 0..4 Magic
    data.extend_from_slice(b"\x7fELF");
    // 4 Class (64-bit = 2)
    data.push(2);
    // 5 Endianness (little-endian = 1)
    data.push(1);
    // 6 Version = 1
    data.push(1);
    // 7..16 Padding
    data.extend_from_slice(&[0u8; 9]);
    // 16..18 Type (ET_EXEC = 2)
    data.extend_from_slice(&2u16.to_le_bytes());
    // 18..20 Machine (AArch64 = 183 / 0xB7, x86_64 = 62 / 0x3E)
    let machine: u16 = if is_aarch64 { 0x00B7 } else { 0x003E };
    data.extend_from_slice(&machine.to_le_bytes());
    // 20..24 Version = 1
    data.extend_from_slice(&1u32.to_le_bytes());
    // 24..32 Entry = 0x1000
    data.extend_from_slice(&0x1000u64.to_le_bytes());
    // 32..40 phoff = 64
    data.extend_from_slice(&64u64.to_le_bytes());
    // 40..48 shoff = 0
    data.extend_from_slice(&0u64.to_le_bytes());
    // 48..52 flags = 0
    data.extend_from_slice(&0u32.to_le_bytes());
    // 52..54 ehsize = 64
    data.extend_from_slice(&64u16.to_le_bytes());
    // 54..56 phentsize = 56
    data.extend_from_slice(&56u16.to_le_bytes());
    // 56..58 phnum = if is_static { 1 } else { 2 }
    let phnum: u16 = if is_static { 1 } else { 2 };
    data.extend_from_slice(&phnum.to_le_bytes());
    // 58..60 shentsize = 0
    data.extend_from_slice(&0u16.to_le_bytes());
    // 60..62 shnum = 0
    data.extend_from_slice(&0u16.to_le_bytes());
    // 62..64 shstrndx = 0
    data.extend_from_slice(&0u16.to_le_bytes());

    // Program header 0: PT_LOAD (type = 1)
    data.extend_from_slice(&1u32.to_le_bytes()); // p_type = PT_LOAD
    data.extend_from_slice(&5u32.to_le_bytes()); // p_flags = r-x
    data.extend_from_slice(&0u64.to_le_bytes()); // p_offset
    data.extend_from_slice(&0x1000u64.to_le_bytes()); // p_vaddr
    data.extend_from_slice(&0x1000u64.to_le_bytes()); // p_paddr
    data.extend_from_slice(&120u64.to_le_bytes()); // p_filesz
    data.extend_from_slice(&120u64.to_le_bytes()); // p_memsz
    data.extend_from_slice(&0x1000u64.to_le_bytes()); // p_align

    // Program header 1 (if dynamic): PT_INTERP (type = 3)
    if !is_static {
        data.extend_from_slice(&3u32.to_le_bytes()); // p_type = PT_INTERP
        data.extend_from_slice(&4u32.to_le_bytes()); // p_flags = r--
        data.extend_from_slice(&120u64.to_le_bytes()); // p_offset
        data.extend_from_slice(&0x2000u64.to_le_bytes()); // p_vaddr
        data.extend_from_slice(&0x2000u64.to_le_bytes()); // p_paddr
        let interp = b"/lib/ld-linux-aarch64.so.1\0";
        data.extend_from_slice(&(interp.len() as u64).to_le_bytes()); // p_filesz
        data.extend_from_slice(&(interp.len() as u64).to_le_bytes()); // p_memsz
        data.extend_from_slice(&1u64.to_le_bytes()); // p_align
        data.extend_from_slice(interp);
    }

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(path, &data).unwrap();
    let mut perms = fs::metadata(path).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(path, perms).unwrap();
}

fn setup_disposable_env(root: &Path) {
    // Create minimal repo structure
    fs::create_dir_all(root.join("scripts")).unwrap();
    fs::create_dir_all(root.join("fixtures/linux-aarch64-hello/src")).unwrap();
    fs::create_dir_all(root.join("fixtures/embed-interceptor-probe/src")).unwrap();
    fs::create_dir_all(root.join("fixtures/embed-zone-readers/src")).unwrap();
    fs::create_dir_all(root.join("fixtures/embed-el1-sched/src")).unwrap();
    fs::create_dir_all(root.join("conformance-probes/src/bin")).unwrap();

    // Scripts
    fs::write(
        root.join("scripts/build-linux-fixtures.sh"),
        "#!/bin/sh\nbuild_fixture \"main.rs\" \"carrick-linux-aarch64-hello\"\n",
    )
    .unwrap();
    fs::write(
        root.join("scripts/build-embed-interceptor-probe.sh"),
        "#!/bin/sh\n",
    )
    .unwrap();
    fs::write(
        root.join("scripts/build-embed-zone-readers.sh"),
        "#!/bin/sh\n",
    )
    .unwrap();
    fs::write(root.join("scripts/build-embed-el1-sched.sh"), "#!/bin/sh\n").unwrap();
    fs::write(root.join("scripts/build-probes.sh"), "#!/bin/sh\n").unwrap();
    fs::write(
        root.join("scripts/probe-inventory.py"),
        "#!/usr/bin/env python3\n",
    )
    .unwrap();

    // Manifests
    fs::write(
        root.join("fixtures/linux-aarch64-hello/Cargo.toml"),
        "[package]\nname = \"carrick-linux-aarch64-hello\"\n",
    )
    .unwrap();
    fs::write(
        root.join("fixtures/embed-interceptor-probe/Cargo.toml"),
        "[package]\nname = \"interceptor-probe\"\n",
    )
    .unwrap();
    fs::write(
        root.join("fixtures/embed-zone-readers/Cargo.toml"),
        "[package]\nname = \"zone-readers\"\n",
    )
    .unwrap();
    fs::write(
        root.join("fixtures/embed-el1-sched/Cargo.toml"),
        "[package]\nname = \"el1-sched\"\n",
    )
    .unwrap();
    fs::write(
        root.join("conformance-probes/Cargo.toml"),
        "[package]\nname = \"conformance-probes\"\n",
    )
    .unwrap();

    // Sources
    fs::write(
        root.join("fixtures/linux-aarch64-hello/src/main.rs"),
        "fn main() {}\n",
    )
    .unwrap();
    fs::write(
        root.join("fixtures/embed-interceptor-probe/src/main.rs"),
        "fn main() {}\n",
    )
    .unwrap();
    fs::write(
        root.join("fixtures/embed-zone-readers/src/main.rs"),
        "fn main() {}\n",
    )
    .unwrap();
    fs::write(
        root.join("fixtures/embed-el1-sched/src/main.rs"),
        "fn main() {}\n",
    )
    .unwrap();
    fs::write(
        root.join("conformance-probes/src/bin/probeinit.rs"),
        "fn main() {}\n",
    )
    .unwrap();
    fs::write(
        root.join("conformance-probes/src/bin/probe1.rs"),
        "fn main() {}\n",
    )
    .unwrap();

    // Probe inventory
    let inventory = serde_json::json!({
        "probeinit": {
            "class": "helper",
            "runner": "in_process",
            "excluded": false
        },
        "probe1": {
            "class": "conformance",
            "runner": "in_process",
            "excluded": false
        }
    });
    fs::write(
        root.join("conformance-probes/probe-inventory.json"),
        serde_json::to_string_pretty(&inventory).unwrap(),
    )
    .unwrap();
}

#[test]
fn empty_targets_are_provisioned() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    setup_disposable_env(root);

    let runner = StubCommandRunner::new();
    let root_clone = root.to_path_buf();
    runner.register("scripts/build-linux-fixtures.sh", move |_, _| {
        create_mock_elf(
            &root_clone.join("fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-hello"),
            true,
            true,
        );
        Ok(carrick_xtask::command::CommandOutput {
            status: exit_status_success(),
            stdout: String::new(),
            stderr: String::new(),
        })
    });
    let root_clone = root.to_path_buf();
    runner.register("scripts/build-embed-interceptor-probe.sh", move |_, _| {
        create_mock_elf(
            &root_clone.join("target/embed-fixtures/interceptor-probe-aarch64"),
            true,
            true,
        );
        Ok(carrick_xtask::command::CommandOutput {
            status: exit_status_success(),
            stdout: String::new(),
            stderr: String::new(),
        })
    });
    let root_clone = root.to_path_buf();
    runner.register("scripts/build-embed-zone-readers.sh", move |_, _| {
        create_mock_elf(
            &root_clone.join("target/embed-fixtures/zone-readers-aarch64"),
            true,
            true,
        );
        Ok(carrick_xtask::command::CommandOutput {
            status: exit_status_success(),
            stdout: String::new(),
            stderr: String::new(),
        })
    });
    let root_clone = root.to_path_buf();
    runner.register("scripts/build-embed-el1-sched.sh", move |_, _| {
        create_mock_elf(
            &root_clone.join("target/embed-fixtures/el1-sched-aarch64"),
            true,
            true,
        );
        Ok(carrick_xtask::command::CommandOutput {
            status: exit_status_success(),
            stdout: String::new(),
            stderr: String::new(),
        })
    });
    let root_clone = root.to_path_buf();
    runner.register("scripts/build-probes.sh", move |_, _| {
        for target in ["aarch64-unknown-linux-musl", "aarch64-unknown-linux-gnu"] {
            create_mock_elf(
                &root_clone.join(format!(
                    "conformance-probes/target/{target}/release/probeinit"
                )),
                true,
                target.ends_with("musl"),
            );
            create_mock_elf(
                &root_clone.join(format!("conformance-probes/target/{target}/release/probe1")),
                true,
                target.ends_with("musl"),
            );
        }
        Ok(carrick_xtask::command::CommandOutput {
            status: exit_status_success(),
            stdout: String::new(),
            stderr: String::new(),
        })
    });
    runner.register("git", |argv, _| {
        if argv.contains(&OsStr::new("HEAD")) {
            Ok(carrick_xtask::command::CommandOutput {
                status: exit_status_success(),
                stdout: "0123456789abcdef0123456789abcdef01234567\n".into(),
                stderr: String::new(),
            })
        } else {
            Ok(carrick_xtask::command::CommandOutput {
                status: exit_status_success(),
                stdout: String::new(),
                stderr: String::new(),
            })
        }
    });
    runner.register("rustc", |_, _| {
        Ok(carrick_xtask::command::CommandOutput {
            status: exit_status_success(),
            stdout: "rustc 1.96.0\nrelease: 1.96.0\ncommit-hash: abc\nhost: aarch64-apple-darwin\n"
                .into(),
            stderr: String::new(),
        })
    });
    runner.register("rustup", |_, _| {
        Ok(carrick_xtask::command::CommandOutput {
            status: exit_status_success(),
            stdout: "aarch64-unknown-linux-musl\naarch64-unknown-linux-gnu\n".into(),
            stderr: String::new(),
        })
    });
    runner.register("docker", |_, _| {
        Ok(carrick_xtask::command::CommandOutput {
            status: exit_status_success(),
            stdout: "Server Version: 29.0\n".into(),
            stderr: String::new(),
        })
    });

    let mut out = Vec::new();
    let res = provision::run_with_runner(Some(root), ProvisionAction::All, &runner, &mut out);
    if !matches!(std::env::consts::ARCH, "aarch64" | "arm64") {
        assert!(
            matches!(res, Err(provision::ProvisionError::Prerequisite(ref message))
            if message == "--closure-arm64 requires an arm64 host")
        );
        assert!(!root.join("target/test-results/provisioning.json").exists());
        assert!(
            runner
                .recorded_commands
                .lock()
                .unwrap()
                .iter()
                .all(|(program, _)| !program.starts_with("scripts/build-") && program != "docker")
        );
        return;
    }
    assert!(res.is_ok(), "provision::run_with_runner failed: {:?}", res);

    let receipt_path = root.join("target/test-results/provisioning.json");
    assert!(
        receipt_path.exists(),
        "receipt not published at {:?}",
        receipt_path
    );
    let receipt_content = fs::read_to_string(&receipt_path).unwrap();
    let receipt: ProvisioningReceipt = serde_json::from_str(&receipt_content).unwrap();
    assert_eq!(
        receipt.source_head,
        "0123456789abcdef0123456789abcdef01234567"
    );
    assert!(!receipt.executables.is_empty());
}

#[test]
fn fixture_builder_failure_stops_before_execution() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    setup_disposable_env(root);

    let runner = StubCommandRunner::new();
    runner.register("rustc", |_, _| {
        Ok(carrick_xtask::command::CommandOutput {
            status: exit_status_success(),
            stdout: "rustc 1.96.0\nrelease: 1.96.0\ncommit-hash: abc\nhost: aarch64-apple-darwin\n"
                .into(),
            stderr: String::new(),
        })
    });
    runner.register("rustup", |_, _| {
        Ok(carrick_xtask::command::CommandOutput {
            status: exit_status_success(),
            stdout: "aarch64-unknown-linux-musl\n".into(),
            stderr: String::new(),
        })
    });
    runner.register("scripts/build-linux-fixtures.sh", |_, _| {
        Err(carrick_xtask::command::CommandError::NonZeroExit {
            program: "scripts/build-linux-fixtures.sh".into(),
            status: exit_status_failure(),
            stdout: String::new(),
            stderr: "compilation failed".into(),
        })
    });

    let mut out = Vec::new();
    let res = provision::run_with_runner(Some(root), ProvisionAction::Fixtures, &runner, &mut out);
    assert!(res.is_err(), "expected failure when fixture builder fails");
    assert!(!root.join("target/test-results/provisioning.json").exists());
}

#[test]
fn missing_fixture_fails() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    setup_disposable_env(root);

    let decls = vec![FixtureDeclaration {
        source: "main.rs".into(),
        name: "carrick-linux-aarch64-hello".into(),
        is_pie: false,
    }];

    let res = provision::validate_fixtures(root, &decls);
    match res {
        Err(FixtureValidationError::Missing(p)) => {
            assert!(p.to_string_lossy().contains("carrick-linux-aarch64-hello"));
        }
        other => panic!("expected Missing error, got {:?}", other),
    }
}

#[test]
fn wrong_arch_fixture_fails() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    setup_disposable_env(root);

    create_mock_elf(
        &root.join("target/embed-fixtures/interceptor-probe-aarch64"),
        true,
        true,
    );
    create_mock_elf(
        &root.join("target/embed-fixtures/zone-readers-aarch64"),
        true,
        true,
    );
    create_mock_elf(
        &root.join("target/embed-fixtures/el1-sched-aarch64"),
        true,
        true,
    );

    let fixture_path = root.join("fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-hello");
    create_mock_elf(&fixture_path, false, true); // wrong arch: x86_64

    let decls = vec![FixtureDeclaration {
        source: "main.rs".into(),
        name: "carrick-linux-aarch64-hello".into(),
        is_pie: false,
    }];

    let res = provision::validate_fixtures(root, &decls);
    match res {
        Err(FixtureValidationError::WrongArchitecture { found, .. }) => {
            assert_eq!(found, 0x003E);
        }
        other => panic!("expected WrongArchitecture error, got {:?}", other),
    }
}

#[test]
fn dynamic_fixture_fails() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    setup_disposable_env(root);

    create_mock_elf(
        &root.join("target/embed-fixtures/interceptor-probe-aarch64"),
        true,
        true,
    );
    create_mock_elf(
        &root.join("target/embed-fixtures/zone-readers-aarch64"),
        true,
        true,
    );
    create_mock_elf(
        &root.join("target/embed-fixtures/el1-sched-aarch64"),
        true,
        true,
    );

    let fixture_path = root.join("fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-hello");
    create_mock_elf(&fixture_path, true, false); // dynamic (contains PT_INTERP)

    let decls = vec![FixtureDeclaration {
        source: "main.rs".into(),
        name: "carrick-linux-aarch64-hello".into(),
        is_pie: false,
    }];

    let res = provision::validate_fixtures(root, &decls);
    match res {
        Err(FixtureValidationError::DynamicInterpreter { .. }) => {}
        other => panic!("expected DynamicInterpreter error, got {:?}", other),
    }
}

#[test]
fn missing_gnu_probe_fails() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    setup_disposable_env(root);

    // Only create musl probes
    create_mock_elf(
        &root.join("conformance-probes/target/aarch64-unknown-linux-musl/release/probeinit"),
        true,
        true,
    );
    create_mock_elf(
        &root.join("conformance-probes/target/aarch64-unknown-linux-musl/release/probe1"),
        true,
        true,
    );

    let inventory_path = root.join("conformance-probes/probe-inventory.json");
    let res = provision::validate_probes(root, &inventory_path);
    match res {
        Err(ProbeValidationError::MissingBinary { target, name, .. }) => {
            assert_eq!(target, "aarch64-unknown-linux-gnu");
            assert!(name == "probeinit" || name == "probe1");
        }
        other => panic!("expected MissingBinary on GNU probe, got {:?}", other),
    }
}

#[test]
fn missing_probeinit_fails() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    setup_disposable_env(root);

    // Create probe1 in both, but omit probeinit
    create_mock_elf(
        &root.join("conformance-probes/target/aarch64-unknown-linux-musl/release/probe1"),
        true,
        true,
    );
    create_mock_elf(
        &root.join("conformance-probes/target/aarch64-unknown-linux-gnu/release/probe1"),
        true,
        false,
    );

    let inventory_path = root.join("conformance-probes/probe-inventory.json");
    let res = provision::validate_probes(root, &inventory_path);
    match res {
        Err(ProbeValidationError::MissingProbeinit { target, .. }) => {
            assert!(target.contains("aarch64-unknown-linux"));
        }
        Err(ProbeValidationError::MissingBinary { name, .. }) if name == "probeinit" => {}
        other => panic!("expected MissingProbeinit error, got {:?}", other),
    }
}

#[test]
fn changed_source_changes_receipt() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    setup_disposable_env(root);

    let runner = StubCommandRunner::new();
    let root_clone = root.to_path_buf();
    runner.register("scripts/build-linux-fixtures.sh", move |_, _| {
        create_mock_elf(
            &root_clone.join("fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-hello"),
            true,
            true,
        );
        Ok(carrick_xtask::command::CommandOutput {
            status: exit_status_success(),
            stdout: String::new(),
            stderr: String::new(),
        })
    });
    let root_clone = root.to_path_buf();
    runner.register("scripts/build-embed-interceptor-probe.sh", move |_, _| {
        create_mock_elf(
            &root_clone.join("target/embed-fixtures/interceptor-probe-aarch64"),
            true,
            true,
        );
        Ok(carrick_xtask::command::CommandOutput {
            status: exit_status_success(),
            stdout: String::new(),
            stderr: String::new(),
        })
    });
    let root_clone = root.to_path_buf();
    runner.register("scripts/build-embed-zone-readers.sh", move |_, _| {
        create_mock_elf(
            &root_clone.join("target/embed-fixtures/zone-readers-aarch64"),
            true,
            true,
        );
        Ok(carrick_xtask::command::CommandOutput {
            status: exit_status_success(),
            stdout: String::new(),
            stderr: String::new(),
        })
    });
    let root_clone = root.to_path_buf();
    runner.register("scripts/build-embed-el1-sched.sh", move |_, _| {
        create_mock_elf(
            &root_clone.join("target/embed-fixtures/el1-sched-aarch64"),
            true,
            true,
        );
        Ok(carrick_xtask::command::CommandOutput {
            status: exit_status_success(),
            stdout: String::new(),
            stderr: String::new(),
        })
    });
    runner.register("git", |argv, _| {
        if argv.contains(&OsStr::new("HEAD")) {
            Ok(carrick_xtask::command::CommandOutput {
                status: exit_status_success(),
                stdout: "0123456789abcdef0123456789abcdef01234567\n".into(),
                stderr: String::new(),
            })
        } else {
            Ok(carrick_xtask::command::CommandOutput {
                status: exit_status_success(),
                stdout: String::new(),
                stderr: String::new(),
            })
        }
    });
    runner.register("rustc", |_, _| {
        Ok(carrick_xtask::command::CommandOutput {
            status: exit_status_success(),
            stdout: "rustc 1.96.0\nrelease: 1.96.0\ncommit-hash: abc\nhost: aarch64-apple-darwin\n"
                .into(),
            stderr: String::new(),
        })
    });
    runner.register("rustup", |_, _| {
        Ok(carrick_xtask::command::CommandOutput {
            status: exit_status_success(),
            stdout: "aarch64-unknown-linux-musl\n".into(),
            stderr: String::new(),
        })
    });

    let mut out = Vec::new();
    provision::run_with_runner(Some(root), ProvisionAction::Fixtures, &runner, &mut out).unwrap();
    let r1 = fs::read_to_string(root.join("target/test-results/provisioning.json")).unwrap();

    // Modify source
    fs::write(
        root.join("fixtures/linux-aarch64-hello/src/main.rs"),
        "fn main() { /* changed */ }\n",
    )
    .unwrap();

    provision::run_with_runner(Some(root), ProvisionAction::Fixtures, &runner, &mut out).unwrap();
    let r2 = fs::read_to_string(root.join("target/test-results/provisioning.json")).unwrap();

    assert_ne!(r1, r2, "receipt should change when source file changes");
}

#[test]
fn receipt_not_published_on_partial_failure() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    setup_disposable_env(root);

    let runner = StubCommandRunner::new();
    runner.register("rustc", |_, _| {
        Ok(carrick_xtask::command::CommandOutput {
            status: exit_status_success(),
            stdout: "rustc 1.96.0\nrelease: 1.96.0\ncommit-hash: abc\nhost: aarch64-apple-darwin\n"
                .into(),
            stderr: String::new(),
        })
    });
    runner.register("rustup", |_, _| {
        Ok(carrick_xtask::command::CommandOutput {
            status: exit_status_success(),
            stdout: "aarch64-unknown-linux-musl\n".into(),
            stderr: String::new(),
        })
    });
    runner.register("scripts/build-linux-fixtures.sh", |_, _| {
        Err(carrick_xtask::command::CommandError::NonZeroExit {
            program: "scripts/build-linux-fixtures.sh".into(),
            status: exit_status_failure(),
            stdout: String::new(),
            stderr: "fail".into(),
        })
    });

    let mut out = Vec::new();
    let _ = provision::run_with_runner(Some(root), ProvisionAction::Fixtures, &runner, &mut out);
    assert!(!root.join("target/test-results/provisioning.json").exists());
}
