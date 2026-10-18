#![allow(clippy::unwrap_used, clippy::expect_used)]

#[test]
fn hosted_caches_keep_profiles_compiler_data_and_bootstrap_artifacts() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let text = std::fs::read_to_string(root.join(".github/workflows/ci.yml")).unwrap();
    let documents = yaml_rust2::YamlLoader::load_from_str(&text).unwrap();
    let workflow = &documents[0];
    let mut cached_jobs = 0;
    for (job, body) in workflow["jobs"].as_hash().unwrap() {
        if job.as_str() == Some("commit-trailers") {
            // commit-trailers reuses the cheap gate-xtask-release cache without sccache.
            continue;
        }
        let Some(steps) = body["steps"].as_vec() else {
            continue;
        };
        let Some(cache) = steps.iter().find(|s| {
            s["uses"]
                .as_str()
                .is_some_and(|s| s.starts_with("Swatinem/rust-cache@"))
        }) else {
            continue;
        };
        cached_jobs += 1;
        let configured = steps
            .iter()
            .position(|s| {
                s["run"].as_str()
                    == Some("echo \"SCCACHE_DIR=$RUNNER_TEMP/carrick-sccache\" >> \"$GITHUB_ENV\"")
            })
            .unwrap();
        let restored = steps.iter().position(|s| s == cache).unwrap();
        assert!(
            configured < restored,
            "compiler cache path must be set before restore"
        );
        assert_eq!(
            cache["with"]["shared-key"].as_str(),
            Some("${{ github.job }}-debug"),
            "{job:?}"
        );
        assert_eq!(
            cache["with"]["cache-directories"].as_str(),
            Some("${{ env.SCCACHE_DIR }}")
        );
        assert_eq!(
            cache["with"]["cache-workspace-crates"].as_str(),
            Some("true")
        );
        assert!(
            steps
                .iter()
                .any(|s| s["run"].as_str() == Some("just ci-prebuild-xtask"))
        );
        assert!(
            steps
                .iter()
                .any(|s| s["run"].as_str() == Some("just build-cache")
                    && s["if"].as_str() == Some("${{ always() }}"))
        );
    }
    assert!(
        cached_jobs > 0,
        "hosted compiler caches must remain enabled"
    );
    let text = std::fs::read_to_string(root.join(".github/workflows/kernel-runtime.yml")).unwrap();
    let documents = yaml_rust2::YamlLoader::load_from_str(&text).unwrap();
    let steps = documents[0]["jobs"]["hvf-kernel"]["steps"]
        .as_vec()
        .unwrap();
    let cache = steps
        .iter()
        .find(|s| {
            s["uses"]
                .as_str()
                .is_some_and(|s| s.starts_with("Swatinem/rust-cache@"))
        })
        .unwrap();
    assert!(cache["with"]["save-if"].is_badvalue());
}
