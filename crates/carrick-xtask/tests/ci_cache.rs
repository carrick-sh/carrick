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

#[test]
fn cross_toolchain_installs_restore_their_package_cache_first() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let text = std::fs::read_to_string(root.join(".github/workflows/ci.yml")).unwrap();
    let workflow = &yaml_rust2::YamlLoader::load_from_str(&text).unwrap()[0];
    let mut installs = 0;
    for (job, body) in workflow["jobs"].as_hash().unwrap() {
        let Some(steps) = body["steps"].as_vec() else {
            continue;
        };
        for (index, step) in steps.iter().enumerate() {
            let Some(recipe) = step["run"]
                .as_str()
                .and_then(|run| run.strip_prefix("just "))
                .filter(|recipe| recipe.starts_with("ci-install-") && recipe.ends_with("-cross"))
            else {
                continue;
            };
            installs += 1;
            let restore = &steps[index - 1];
            assert!(
                restore["uses"]
                    .as_str()
                    .is_some_and(|uses| uses.starts_with("actions/cache/restore@")),
                "{job:?}: {recipe} must follow its package cache"
            );
            assert_eq!(
                restore["with"]["path"].as_str(),
                Some("${{ runner.temp }}/apt-cross")
            );
            let key = restore["with"]["key"].as_str().unwrap();
            assert!(key.starts_with(&format!("apt-{recipe}-")), "{key}");
            assert!(
                key.contains("${{ steps.runner-image.outputs.id }}"),
                "{key}"
            );
            assert!(key.contains("hashFiles('scripts/ci/apt-cached-install.sh')"));
            assert_eq!(steps[index - 2]["id"].as_str(), Some("runner-image"));
            // A throttled mirror's partial progress resumes on the next run.
            let partial = format!("{key}-partial-");
            assert_eq!(
                restore["with"]["restore-keys"].as_str(),
                Some(partial.as_str())
            );
            let choose = &steps[index + 1];
            assert_eq!(choose["id"].as_str(), Some("apt-cross-key"));
            let choose = choose["run"].as_str().unwrap();
            assert!(choose.contains(&format!("echo \"key={key}\"")), "{choose}");
            assert!(
                choose.contains(&format!("key={partial}${{{{ github.run_id }}}}")),
                "{choose}"
            );
            let save = &steps[index + 2];
            assert!(
                save["uses"]
                    .as_str()
                    .is_some_and(|uses| uses.starts_with("actions/cache/save@"))
            );
            // Saved after a failed install too: only cancellation skips it.
            assert_eq!(save["if"].as_str(), Some("${{ !cancelled() }}"));
            assert_eq!(
                save["with"]["key"].as_str(),
                Some("${{ steps.apt-cross-key.outputs.key }}")
            );
        }
    }
    assert_eq!(installs, 4, "every cross toolchain install is cached");
}

#[test]
// The script runs on hosted Ubuntu; GNU timeout is absent from stock macOS.
#[cfg(target_os = "linux")]
fn warm_apt_cache_installs_without_contacting_the_mirror() {
    // #615: a crawling mirror failed `portable` seven times in one day.
    use std::os::unix::fs::PermissionsExt;
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let script = root.join("scripts/ci/apt-cached-install.sh");
    let temp = tempfile::tempdir().unwrap();
    let bin = temp.path().join("bin");
    std::fs::create_dir(&bin).unwrap();
    let log = temp.path().join("apt.log");
    for (name, body) in [
        ("sudo", "#!/bin/sh\nexec \"$@\"\n".to_owned()),
        (
            "dpkg",
            format!("#!/bin/sh\necho \"dpkg $*\" >> '{}'\n", log.display()),
        ),
        (
            "apt-get",
            format!(
                "#!/bin/sh\necho \"$*\" >> '{}'\ncase \"$*\" in *--download-only*)\n  [ -n \"$APT_STUB_FAIL_DOWNLOAD\" ] && exit 100\n  for a in \"$@\"; do case \"$a\" in Dir::Cache::archives=*) touch \"${{a#Dir::Cache::archives=}}/pkg_1.0_amd64.deb\";; esac; done;;\nesac\n",
                log.display()
            ),
        ),
    ] {
        let path = bin.join(name);
        std::fs::write(&path, body).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let cache = temp.path().join("apt-cross");
    let run = |packages: &[&str]| {
        let _ = std::fs::remove_file(&log);
        let status = std::process::Command::new(&script)
            .arg(&cache)
            .args(packages)
            .env(
                "PATH",
                format!("{}:{}", bin.display(), std::env::var("PATH").unwrap()),
            )
            .status()
            .unwrap();
        assert!(status.success());
        std::fs::read_to_string(&log).unwrap()
    };
    let cold = run(&["gcc-aarch64-linux-gnu"]);
    assert!(cold.contains("update"), "{cold}");
    assert!(cold.contains("--download-only"), "{cold}");
    let warm = run(&["gcc-aarch64-linux-gnu"]);
    assert!(
        !warm.contains("update"),
        "warm cache contacted the mirror: {warm}"
    );
    assert!(!warm.contains("--download-only"), "{warm}");
    assert!(warm.contains("dpkg -i "), "{warm}");
    assert!(warm.contains("pkg_1.0_amd64.deb"), "{warm}");
    let changed = run(&["clang", "llvm"]);
    assert!(
        changed.contains("update"),
        "a different package set must refetch: {changed}"
    );

    // A download that dies part-way keeps what it fetched and is not marked
    // complete; the next run resumes instead of starting over.
    let partial = temp.path().join("partial-cache");
    std::fs::create_dir(&partial).unwrap();
    std::fs::write(partial.join("kept_1.0_amd64.deb"), "").unwrap();
    let failed = std::process::Command::new(&script)
        .arg(&partial)
        .arg("gcc-aarch64-linux-gnu")
        .env(
            "PATH",
            format!("{}:{}", bin.display(), std::env::var("PATH").unwrap()),
        )
        .env("APT_STUB_FAIL_DOWNLOAD", "1")
        .status()
        .unwrap();
    assert!(!failed.success());
    assert!(partial.join("kept_1.0_amd64.deb").exists());
    assert!(!partial.join("complete").exists());
}
