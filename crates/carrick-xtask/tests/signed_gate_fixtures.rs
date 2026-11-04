#![allow(clippy::unwrap_used)]
use std::{fs, path::Path};

/// The Signed gate builds its fixtures for the exact authorized SHA in the
/// same run and hands that archive to the Mac gate (#1581). The workflow half
/// landed as #1602, so this checks the live workflow; the director's patch
/// file is retired once applied.
#[test]
fn signed_gate_wires_same_run_authorized_fixture_artifact() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let text = fs::read_to_string(root.join(".github/workflows/signed-gate.yml")).unwrap();
    let docs = yaml_rust2::YamlLoader::load_from_str(&text).unwrap();
    let jobs = &docs[0]["jobs"];
    let publisher = &jobs["signed-fixtures"];
    assert_eq!(publisher["needs"].as_str(), Some("authorize"));
    assert_eq!(publisher["runs-on"].as_str(), Some("ubuntu-24.04-arm"));
    let steps = publisher["steps"].as_vec().unwrap();
    assert_eq!(
        steps[0]["with"]["ref"].as_str(),
        Some("${{ needs.authorize.outputs.sha }}")
    );
    let upload = steps
        .iter()
        .find(|s| s["uses"].as_str() == Some("actions/upload-artifact@v4"))
        .unwrap();
    assert!(
        upload["with"]["path"]
            .as_str()
            .unwrap()
            .contains("needs.authorize.outputs.sha")
    );
    assert!(
        upload["with"]["name"]
            .as_str()
            .unwrap()
            .contains("github.run_attempt")
    );
    let gate = &jobs["gate"];
    assert!(
        gate["needs"]
            .as_vec()
            .unwrap()
            .iter()
            .any(|s| s.as_str() == Some("signed-fixtures"))
    );
    let download = gate["steps"]
        .as_vec()
        .unwrap()
        .iter()
        .find(|s| s["with"]["name"] == upload["with"]["name"])
        .unwrap();
    assert_eq!(
        download["uses"].as_str(),
        Some("actions/download-artifact@v4")
    );
    assert!(!text.contains("vars.CARRICK_SIGNED_FIXTURE_BUNDLE"));
    // The publisher runs the same commands as main's own fixture publisher,
    // for the authorized SHA instead of the pushed one.
    let kernel = fs::read_to_string(root.join(".github/workflows/kernel-runtime.yml")).unwrap();
    let kernel = yaml_rust2::YamlLoader::load_from_str(&kernel).unwrap();
    for step in steps.iter().filter(|s| !s["run"].is_badvalue()) {
        let name = step["name"].as_str().unwrap();
        let original = kernel[0]["jobs"]["signed-fixtures"]["steps"]
            .as_vec()
            .unwrap()
            .iter()
            .find(|s| s["name"].as_str() == Some(name))
            .unwrap();
        assert_eq!(
            step["run"].as_str().unwrap(),
            original["run"]
                .as_str()
                .unwrap()
                .replace("$GITHUB_SHA", "$FIXTURE_SHA")
        );
    }
}
