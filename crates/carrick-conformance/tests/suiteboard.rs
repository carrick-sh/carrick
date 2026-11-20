use std::fs;
use std::process::Command;

use serde_json::Value;

#[test]
fn suiteboard_known_answer() {
    let directory = tempfile::tempdir().unwrap();
    let fixture = std::path::Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/suiteboard-carrick"
    ));
    let state = directory.path().join("sampled");
    let manifest = directory.path().join("suites.toml");
    let cache = directory.path().join("oracle.jsonl");
    let results = directory.path().join("observations.jsonl");
    let mut specs = String::new();
    let mut rows = String::new();
    for name in ["fixture-verdicts", "fixture-hang"] {
        specs.push_str(&format!(
            r#"
[[suite]]
name = "{name}"
ecosystem = "node"
image = "localhost:5005/fixture@sha256:0000000000000000000000000000000000000000000000000000000000000000"
cmd = ["{name}"]
verdict = "tap"
tier = "smoke"
weight = "light"
timeout_s = 1
carrick_flags = ["--fs", "host"]
"#
        ));
        let key = format!(
            r#"{{"docker_platform":"linux/amd64","image":"localhost:5005/fixture@sha256:0000000000000000000000000000000000000000000000000000000000000000","cmd":["{name}"],"docker_flags":[],"entrypoint":null,"bind_mounts":[],"env":[],"workdir":null,"verdict":"tap","parser_profile":"suiteboard-v1","timeout_s":1}}"#
        );
        rows.push_str(
            &serde_json::json!({
                "name": name, "key": key, "served_ordinals": [],
                "result": {
                    "result": "success",
                    "totals": {"n": 2, "passed": 2, "failed": 0, "broken": 0, "skipped": 1},
                    "ids": {
                        "tap:1:planted failure#1": "ok",
                        "tap:2:planted skip#1": "skipped",
                        "tap:3:planted flake#1": "ok"
                    }
                }
            })
            .to_string(),
        );
        rows.push('\n');
    }
    fs::write(&manifest, specs).unwrap();

    let run = || {
        Command::new(env!("CARGO_BIN_EXE_carrick-conformance"))
            .args([
                "--lane",
                "kvm-local",
                "--slice",
                "smoke",
                "--runs",
                "2",
                "--require-cached-oracle",
            ])
            .args(["--no-image-refresh", "--workers", "2"])
            .arg("--carrick-bin")
            .arg(fixture)
            .env("CARRICK_SUITEBOARD_FIXTURE_STATE", &state)
            .arg("--manifest")
            .arg(&manifest)
            .arg("--oracle-cache")
            .arg(&cache)
            .arg("--jsonl")
            .arg(&results)
            .output()
            .unwrap()
    };

    let missing = run();
    let stderr = String::from_utf8_lossy(&missing.stderr);
    assert_eq!(missing.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("uncached: fixture-hang"), "{stderr}");
    assert!(!results.exists());
    assert!(!state.exists());

    // The CLI's live KVM preflight requires the device even though this
    // fixture exercises only the host command runner and never opens it.
    if !std::path::Path::new("/dev/kvm").exists() {
        eprintln!("suiteboard live fixture requires /dev/kvm");
        return;
    }

    fs::write(&cache, rows).unwrap();
    let measured = run();
    let stderr = String::from_utf8_lossy(&measured.stderr);
    assert_eq!(measured.status.code(), Some(1), "{stderr}");
    let observations: Vec<Value> = fs::read_to_string(&results)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(observations.len(), 4);
    let verdicts: Vec<_> = observations
        .iter()
        .filter(|row| row["name"] == "fixture-verdicts")
        .collect();
    assert_eq!(verdicts[0]["pairs"]["tap:1:planted failure#1"][0], "fail");
    assert_eq!(verdicts[0]["pairs"]["tap:2:planted skip#1"][0], "skipped");
    assert_eq!(verdicts[0]["pairs"]["tap:3:planted flake#1"][0], "ok");
    assert_eq!(verdicts[1]["pairs"]["tap:3:planted flake#1"][0], "fail");
    for row in observations
        .iter()
        .filter(|row| row["name"] == "fixture-hang")
    {
        assert_eq!(row["verdict"], "hung", "{row}");
    }
    let receipt: Value =
        serde_json::from_slice(&fs::read(results.with_extension("suiteboard.json")).unwrap())
            .unwrap();
    assert_eq!(receipt["schema"], "carrick.suiteboard.v1");
    assert_eq!(receipt["head"].as_str().unwrap().len(), 40);
    assert_eq!(receipt["artifact"]["sha256"].as_str().unwrap().len(), 64);
    assert_eq!(receipt["carrick"]["suites_started"], 4);
    assert_eq!(receipt["carrick"]["suites_finished"], 2);
    assert_eq!(receipt["carrick"]["tests_observed"], 6);
    assert_eq!(receipt["oracle"]["tests_observed"], 6);
    let unstable = receipt["unstable"].as_array().unwrap();
    assert_eq!(unstable.len(), 1);
    assert_eq!(unstable[0]["test"], "tap:3:planted flake#1");
    for (sample, row) in unstable[0]["observations"]
        .as_array()
        .unwrap()
        .iter()
        .zip(verdicts)
    {
        assert_eq!(sample["run_id"], row["carrick_run_id"]);
    }
}

#[test]
fn suiteboard_arm64_plan() {
    let directory = tempfile::tempdir().unwrap();
    let pins = directory.path().join("images.toml");
    let digest = "a".repeat(64);
    fs::write(
        &pins,
        format!(
            r#"
"localhost:5050/cpython-test:3.12.13" = "localhost:5050/cpython-test@sha256:{digest}"
"localhost:5005/carrick-nodejs-conformance:24.16.0-26.2.0" = "localhost:5005/carrick-nodejs-conformance@sha256:{digest}"
"#
        ),
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_carrick-conformance"))
        .args([
            "--lane",
            "hvf",
            "--slice",
            "py-fs",
            "--slice",
            "node-libuv",
            "--require-cached-oracle",
            "--dry-run",
            "--suiteboard-images",
        ])
        .arg(pins)
        .current_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/../.."))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let plan = String::from_utf8(output.stdout).unwrap();
    assert!(plan.contains("--platform linux/arm64"));
    assert!(plan.contains("# cpython-posix "));
    assert!(plan.contains("# node-libuv "));
    assert!(plan.contains(&format!("carrick-nodejs-conformance@sha256:{digest}")));
    assert!(!plan.contains("# cpython-subprocess "));
    assert!(!plan.contains("# node-v8-smoke "));
}
