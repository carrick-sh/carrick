#![allow(clippy::unwrap_used, clippy::expect_used)]

#[test]
fn only_trusted_warmer_publishes_bounded_shared_compiler_caches() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let text = std::fs::read_to_string(root.join(".github/workflows/ci.yml")).unwrap();
    let documents = yaml_rust2::YamlLoader::load_from_str(&text).unwrap();
    let workflow = &documents[0];
    assert_eq!(workflow["env"]["SCCACHE_CACHE_SIZE"].as_str(), Some("3G"));
    let jobs = workflow["jobs"].as_hash().unwrap();
    for (job, body) in jobs {
        let Some(steps) = body["steps"].as_vec() else {
            continue;
        };
        for step in steps {
            let Some(action) = step["uses"].as_str() else {
                continue;
            };
            assert!(
                !action.starts_with("actions/cache@"),
                "cache readers must use restore-only actions"
            );
            if action.starts_with("actions/cache/save@") && job.as_str() != Some("cache-warm") {
                let condition = step["if"].as_str().unwrap();
                assert!(condition.contains("refs/heads/main"));
                assert!(condition.contains("'schedule'"));
                assert!(condition.contains("'workflow_dispatch'"));
            }
            if action.starts_with("Swatinem/rust-cache@") {
                assert_eq!(step["with"]["save-if"].as_bool(), Some(false), "{job:?}");
                assert!(step["with"]["cache-directories"].is_badvalue());
                assert_eq!(
                    step["with"]["cache-targets"].as_bool(),
                    Some(matches!(job.as_str(), Some("lint" | "macos-clippy")))
                );
            }
            if step["with"]["key"]
                .as_str()
                .is_some_and(|k| k.starts_with("sccache-"))
            {
                assert!(
                    step["with"]["key"]
                        .as_str()
                        .unwrap()
                        .contains("hashFiles('Cargo.lock', 'rust-toolchain.toml')")
                );
                if action.starts_with("actions/cache/save@") {
                    assert_eq!(job.as_str(), Some("cache-warm"));
                } else {
                    assert!(action.starts_with("actions/cache/restore@"));
                }
            }
        }
    }
    let warmer = &workflow["jobs"]["cache-warm"];
    let condition = warmer["if"].as_str().unwrap();
    assert!(condition.contains("'schedule'"));
    assert!(condition.contains("'workflow_dispatch'"));
    assert!(condition.contains("refs/heads/main"));
    let families = warmer["strategy"]["matrix"]["include"].as_vec().unwrap();
    assert_eq!(families.len(), 3);
    assert!(
        families
            .iter()
            .all(|f| !f["runner"].as_str().unwrap().contains("self-hosted"))
    );
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
            // Trusted main runs retain partial installs; PR/queue readers never publish.
            let condition = save["if"].as_str().unwrap();
            assert!(condition.contains("!cancelled()"));
            assert!(condition.contains("refs/heads/main"));
            assert!(condition.contains("'schedule'"));
            assert!(condition.contains("'workflow_dispatch'"));
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
