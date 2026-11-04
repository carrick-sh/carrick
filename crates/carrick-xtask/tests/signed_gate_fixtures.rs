#![allow(clippy::unwrap_used)]
use std::{fs, path::Path, process::Command};

#[test]
fn director_patch_builds_fixtures_in_pr_scope_and_binds_transport() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let temp = tempfile::tempdir().unwrap();
    let workflow = temp.path().join(".github/workflows/signed-gate.yml");
    fs::create_dir_all(workflow.parent().unwrap()).unwrap();
    fs::copy(root.join(".github/workflows/signed-gate.yml"), &workflow).unwrap();
    let applied = Command::new("git")
        .current_dir(temp.path())
        .arg("apply")
        .arg(root.join("docs/ci/patches/1581-signed-fixtures-v2.patch"))
        .output()
        .unwrap();
    assert!(
        applied.status.success(),
        "{}",
        String::from_utf8_lossy(&applied.stderr)
    );
    let text = fs::read_to_string(workflow).unwrap();
    let docs = yaml_rust2::YamlLoader::load_from_str(&text).unwrap();
    let jobs = &docs[0]["jobs"];
    // Candidate fixture code must never run in pull_request_target's scope.
    assert!(jobs["signed-fixtures"].is_badvalue());
    let producer_text =
        fs::read_to_string(temp.path().join(".github/workflows/signed-fixtures-pr.yml")).unwrap();
    let producer = yaml_rust2::YamlLoader::load_from_str(&producer_text).unwrap();
    assert!(!producer[0]["on"]["pull_request"].is_badvalue());
    assert!(producer[0]["on"]["pull_request_target"].is_badvalue());
    assert_eq!(
        producer[0]["permissions"]["contents"].as_str(),
        Some("read")
    );
    let publisher = &producer[0]["jobs"]["fixtures"];
    assert_eq!(publisher["runs-on"].as_str(), Some("ubuntu-24.04-arm"));
    let steps = publisher["steps"].as_vec().unwrap();
    assert_eq!(
        steps[0]["with"]["ref"].as_str(),
        Some("${{ github.event.pull_request.head.sha }}")
    );
    assert_eq!(
        steps[0]["with"]["persist-credentials"].as_bool(),
        Some(false)
    );
    assert!(!producer_text.contains("secrets."));
    assert!(!producer_text.contains("rust-cache"));
    assert!(!text.contains("vars.CARRICK_SIGNED_FIXTURE_BUNDLE"));
    assert!(!text.contains("actions/download-artifact@"));
    assert_eq!(
        jobs["gate"]["outputs"]["result-id"].as_str(),
        Some("${{ steps.result-upload.outputs.artifact-id }}")
    );
    assert_eq!(
        jobs["gate"]["outputs"]["result-digest"].as_str(),
        Some("${{ steps.result-upload.outputs.artifact-digest }}")
    );
    let publish = jobs["publish"]["steps"].as_vec().unwrap();
    let fetch = publish
        .iter()
        .find(|step| {
            step["name"].as_str() == Some("Fetch only the gate upload step's immutable evidence")
        })
        .unwrap();
    assert_eq!(
        fetch["env"]["ARTIFACT_ID"].as_str(),
        Some("${{ needs.gate.outputs.result-id }}")
    );
    assert_eq!(
        fetch["env"]["DIGEST"].as_str(),
        Some("sha256:${{ needs.gate.outputs.result-digest }}")
    );
    let command = fetch["run"].as_str().unwrap();
    assert!(command.contains("--run-id \"$GITHUB_RUN_ID\""));
    assert!(command.contains("--artifact-id \"$ARTIFACT_ID\""));
    assert!(command.contains("--digest \"$DIGEST\""));
    // These bindings only prevent name substitution. Same-user runner
    // isolation is still a blocking review finding, documented with the patch.
    for document in [&docs[0], &producer[0]] {
        for (_, job) in document["jobs"].as_hash().unwrap() {
            assert_eq!(
                job["permissions"]["contents"]
                    .as_str()
                    .or(document["permissions"]["contents"].as_str()),
                Some("read")
            );
            for step in job["steps"].as_vec().unwrap() {
                if let Some(action) = step["uses"].as_str() {
                    let pin = action.split_once('@').unwrap().1;
                    assert_eq!(pin.len(), 40, "{action}");
                    assert!(pin.bytes().all(|byte| byte.is_ascii_hexdigit()), "{action}");
                }
            }
        }
    }
    let kernel = fs::read_to_string(root.join(".github/workflows/kernel-runtime.yml")).unwrap();
    let kernel = yaml_rust2::YamlLoader::load_from_str(&kernel).unwrap();
    for step in steps.iter().filter(|step| !step["run"].is_badvalue()) {
        let name = step["name"].as_str().unwrap();
        let original = kernel[0]["jobs"]["signed-fixtures"]["steps"]
            .as_vec()
            .unwrap()
            .iter()
            .find(|step| step["name"].as_str() == Some(name))
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
