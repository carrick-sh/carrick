#![cfg(target_os = "linux")]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;

use serde_json::Value;

#[test]
fn suiteboard_known_answer() {
    let directory = tempfile::tempdir().unwrap();
    let fixture = directory.path().join("fixture-carrick");
    fs::write(
        &fixture,
        r#"#!/bin/sh
case "$*" in
  *fixture-hang*) exec sleep 30 ;;
esac
printf 'TAP version 13\n1..3\nnot ok 1 - planted failure\nok 2 - planted skip # SKIP fixture\n'
if [ -e "$0.sampled" ]; then
  printf 'not ok 3 - planted flake\n'
else
  touch "$0.sampled"
  printf 'ok 3 - planted flake\n'
fi
exit 1
"#,
    )
    .unwrap();
    fs::set_permissions(&fixture, fs::Permissions::from_mode(0o755)).unwrap();
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
image = "localhost:5005/fixture:v1"
cmd = ["{name}"]
verdict = "tap"
tier = "full"
weight = "light"
timeout_s = 1
"#
        ));
        let key = format!(
            r#"{{"docker_platform":"linux/amd64","image":"localhost:5005/fixture:v1","cmd":["{name}"],"docker_flags":[],"entrypoint":null,"bind_mounts":[],"env":[],"workdir":null,"verdict":"tap","parser_profile":"suiteboard-v1","timeout_s":1}}"#
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
                "--runs",
                "2",
                "--require-cached-oracle",
            ])
            .args(["--no-image-refresh", "--workers", "2"])
            .arg("--carrick-bin")
            .arg(&fixture)
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
    assert!(!fixture.with_extension("sampled").exists());

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
