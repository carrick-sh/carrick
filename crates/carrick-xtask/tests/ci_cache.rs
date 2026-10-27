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
                if matches!(job.as_str(), Some("lint-clippy" | "macos-clippy")) {
                    let condition = step["with"]["save-if"].as_str().unwrap();
                    assert!(condition.contains("refs/heads/main"));
                    assert!(condition.contains("'schedule'"));
                    assert!(condition.contains("'workflow_dispatch'"));
                } else {
                    assert_eq!(step["with"]["save-if"].as_bool(), Some(false), "{job:?}");
                }
                assert!(
                    step["with"]["shared-key"]
                        .as_str()
                        .unwrap()
                        .ends_with("-v2")
                );
                assert!(step["with"]["cache-directories"].is_badvalue());
                assert_eq!(
                    step["with"]["cache-targets"].as_bool(),
                    Some(matches!(job.as_str(), Some("lint-clippy" | "macos-clippy")))
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
                let key = step["with"]["key"].as_str().unwrap();
                assert!(key.ends_with("-${{ github.run_id }}"));
                if action.starts_with("actions/cache/save@") {
                    assert_eq!(job.as_str(), Some("cache-warm"));
                } else {
                    assert!(action.starts_with("actions/cache/restore@"));
                    let prefixes: Vec<_> = step["with"]["restore-keys"]
                        .as_str()
                        .unwrap()
                        .lines()
                        .collect();
                    assert_eq!(prefixes.len(), 2);
                    assert_eq!(
                        prefixes[0],
                        key.strip_suffix("${{ github.run_id }}").unwrap()
                    );
                    assert_eq!(
                        prefixes[1],
                        format!("{}-", key.split("-${{ hashFiles").next().unwrap())
                    );
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

#[test]
fn linux_test_consumers_share_one_artifact_and_clippy_union() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let text = std::fs::read_to_string(root.join(".github/workflows/ci.yml")).unwrap();
    let docs = yaml_rust2::YamlLoader::load_from_str(&text).unwrap();
    assert_eq!(docs[0]["env"]["CARGO_INCREMENTAL"].as_str(), Some("0"));
    let jobs = &docs[0]["jobs"];
    assert!(
        jobs["xtask-tests-build"]["steps"]
            .as_vec()
            .unwrap()
            .iter()
            .any(|s| s["run"].as_str() == Some("just ci-build-xtask-tests"))
    );
    for job in ["lint-gates", "lint-domains", "portable"] {
        assert!(
            jobs[job]["needs"]
                .as_vec()
                .unwrap()
                .iter()
                .any(|n| n.as_str() == Some("xtask-tests-build"))
        );
        assert!(
            jobs[job]["steps"]
                .as_vec()
                .unwrap()
                .iter()
                .any(|s| s["with"]["name"].as_str() == Some("xtask-tests-linux-x64"))
        );
    }
    let changes = &jobs["changes"];
    assert!(
        changes["needs"].is_badvalue(),
        "early checks must not wait on xtask-build"
    );
    assert!(!changes["steps"].as_vec().unwrap().iter().any(|s| {
        s["uses"]
            .as_str()
            .is_some_and(|action| action.starts_with("actions/download-artifact@"))
    }));
    assert!(
        !changes["steps"]
            .as_vec()
            .unwrap()
            .iter()
            .any(|s| s["run"].as_str() == Some("just ci-prebuild-xtask"))
    );
    let steps = jobs["lint-clippy"]["steps"].as_vec().unwrap();
    assert!(
        steps
            .iter()
            .any(|s| s["run"].as_str() == Some("just clippy"))
    );
    assert!(
        !steps
            .iter()
            .any(|s| s["run"].as_str() == Some("just clippy-linux"))
    );
}

#[test]
fn warm_tail_replays_consumer_xtask_builds_after_eviction_pressure() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let text = std::fs::read_to_string(root.join(".github/workflows/ci.yml")).unwrap();
    let documents = yaml_rust2::YamlLoader::load_from_str(&text).unwrap();
    let warmer = &documents[0]["jobs"]["cache-warm"];
    let families = warmer["strategy"]["matrix"]["include"].as_vec().unwrap();
    for (family, cap) in [
        ("linux-x64", "3G"),
        ("darwin-hosted", "2G"),
        ("linux-arm64", "512M"),
    ] {
        assert_eq!(
            families
                .iter()
                .find(|f| f["family"].as_str() == Some(family))
                .unwrap()["cache-size"]
                .as_str(),
            Some(cap)
        );
    }
    let script = warmer["steps"]
        .as_vec()
        .unwrap()
        .iter()
        .filter_map(|s| s["run"].as_str())
        .find(|run| run.contains("case \"$FAMILY\""))
        .unwrap();
    for (family, last) in [
        ("linux-x64", "just ci-build-xtask-tests"),
        ("darwin-hosted", "just test-xtask --no-run"),
    ] {
        let block = script
            .split(&format!("{family})"))
            .nth(1)
            .unwrap()
            .split(";;")
            .next()
            .unwrap();
        let commands: Vec<_> = block
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect();
        let clean = commands
            .iter()
            .position(|l| *l == "cargo clean")
            .expect("Cargo freshness must not bypass sccache LRU refresh");
        let lean = commands
            .iter()
            .position(|l| *l == "just ci-prebuild-xtask")
            .unwrap();
        let finish = commands.iter().position(|l| *l == last).unwrap();
        assert!(clean < lean && lean < finish);
        for graph in [
            "just xtask test-batch --no-run test",
            "just xtask test-batch --no-run test-integration",
        ] {
            let position = commands
                .iter()
                .position(|command| *command == graph)
                .unwrap();
            assert!(
                lean < position && position < finish,
                "{family}: shard graphs must survive overflow"
            );
        }

        assert_eq!(
            commands.last().copied(),
            Some(last),
            "nothing may evict the critical tail"
        );
        assert!(commands[lean + 1].starts_with("export CARRICK_XTASK_BIN="));
        assert!(
            !block.contains("CARGO_TARGET_DIR="),
            "cache keys must match consumers"
        );
    }
    let arm = script
        .split("linux-arm64)")
        .nth(1)
        .unwrap()
        .split(";;")
        .next()
        .unwrap();
    assert!(
        arm.lines()
            .any(|line| line.trim() == "just ci-prebuild-xtask"),
        "ARM consumers cannot use the x64 artifact"
    );
    let justfile = std::fs::read_to_string(root.join("justfile")).unwrap();
    assert!(justfile.contains("test-batch --export target/xtask-tests.tar.gz _test-xtask-ci"));
    for recipe in [
        "_test-xtask *ARGS:",
        "_test-xtask-shards:",
        "_test-xtask-domain-unit:",
        "_test-xtask-domain-integration:",
    ] {
        let body = justfile
            .split(recipe)
            .nth(1)
            .unwrap()
            .split("\n\n")
            .next()
            .unwrap();
        assert!(
            body.contains("--all-features"),
            "{recipe}: consumer feature set drift"
        );
    }
}

#[test]
fn hosted_jobs_read_the_r2_compiler_cache_and_only_the_warmer_writes() {
    // #858: the bounded GitHub cache thrashed (the linux-x64 warmer hit 29% of
    // its own unchanged replay at 3 GiB). Hosted jobs read R2 with a read-only
    // token; only cache-warm writes; forks fall back to the GitHub cache.
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let text = std::fs::read_to_string(root.join(".github/workflows/ci.yml")).unwrap();
    let workflow = &yaml_rust2::YamlLoader::load_from_str(&text).unwrap()[0];
    let env = &workflow["env"];
    assert_eq!(
        env["CARRICK_SCCACHE_R2_BUCKET"].as_str(),
        Some("carrick-sccache")
    );
    assert!(env["SCCACHE_BUCKET"].is_badvalue(), "selected per job");
    let mut readers = 0;
    for (job, body) in workflow["jobs"].as_hash().unwrap() {
        let job = job.as_str().unwrap();
        let Some(steps) = body["steps"].as_vec() else {
            continue;
        };
        for (index, step) in steps.iter().enumerate() {
            let Some(key) = step["with"]["key"]
                .as_str()
                .filter(|k| k.starts_with("sccache-"))
            else {
                continue;
            };
            let family = key
                .strip_prefix("sccache-")
                .unwrap()
                .split("-${{ hashFiles")
                .next()
                .unwrap();
            assert_eq!(
                step["if"].as_str(),
                Some("steps.compiler-cache.outputs.backend == 'gha'"),
                "{job}: GitHub cache steps run only on the fallback backend"
            );
            if step["uses"]
                .as_str()
                .is_some_and(|uses| uses.starts_with("actions/cache/save@"))
            {
                continue;
            }
            readers += 1;
            let configure = &steps[index - 1];
            assert_eq!(configure["id"].as_str(), Some("compiler-cache"), "{job}");
            assert_eq!(
                configure["env"]["RUNNER_ENVIRONMENT"].as_str(),
                Some("${{ runner.environment }}"),
                "{job}"
            );
            let mode = if job == "cache-warm" {
                "read-write"
            } else {
                "read-only"
            };
            assert_eq!(
                configure["run"].as_str(),
                Some(format!("scripts/ci/compiler-cache-env.sh {family} {mode}").as_str()),
                "{job}"
            );
            let writer = body["env"]["AWS_ACCESS_KEY_ID"].as_str();
            if job == "cache-warm" {
                assert_eq!(body["environment"].as_str(), Some("sccache-writer"));
                assert_eq!(
                    writer,
                    Some("${{ secrets.SCCACHE_R2_WRITER_ACCESS_KEY_ID }}")
                );
                assert_eq!(
                    body["env"]["AWS_SECRET_ACCESS_KEY"].as_str(),
                    Some("${{ secrets.SCCACHE_R2_WRITER_SECRET_ACCESS_KEY }}")
                );
            } else {
                assert!(
                    !writer.is_some_and(|w| w.contains("WRITER")),
                    "{job}: only cache-warm gets the writer"
                );
                assert!(body["environment"].is_badvalue(), "{job}");
                assert!(
                    !body["env"]["AWS_SECRET_ACCESS_KEY"]
                        .as_str()
                        .is_some_and(|w| w.contains("WRITER")),
                    "{job}"
                );
            }
        }
    }
    assert_eq!(
        readers, 21,
        "every compiler cache consumer selects a backend"
    );
}

#[test]
fn compiler_cache_env_selects_r2_only_for_credentialed_hosted_runners() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let script = root.join("scripts/ci/compiler-cache-env.sh");
    let secret = "not-a-real-secret-value";
    let run = |args: &[&str], vars: &[(&str, &str)]| {
        let temp = tempfile::tempdir().unwrap();
        let env_file = temp.path().join("env");
        let out_file = temp.path().join("out");
        std::fs::write(&env_file, "").unwrap();
        std::fs::write(&out_file, "").unwrap();
        let mut command = std::process::Command::new(&script);
        command
            .args(args)
            .env_clear()
            .env("PATH", std::env::var("PATH").unwrap())
            .env("GITHUB_ENV", &env_file)
            .env("GITHUB_OUTPUT", &out_file)
            .env("RUNNER_TEMP", temp.path())
            .env("CARRICK_SCCACHE_R2_BUCKET", "carrick-sccache")
            .env(
                "CARRICK_SCCACHE_R2_ENDPOINT",
                "https://example.r2.cloudflarestorage.com",
            );
        for (key, value) in vars {
            command.env(key, value);
        }
        let output = command.output().unwrap();
        let stdout = String::from_utf8(output.stdout).unwrap();
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(!stdout.contains(secret) && !stderr.contains(secret));
        (
            output.status.code(),
            std::fs::read_to_string(&env_file).unwrap(),
            std::fs::read_to_string(&out_file).unwrap(),
            temp.path().join("carrick-sccache"),
        )
    };
    let creds = [
        ("AWS_ACCESS_KEY_ID", "id"),
        ("AWS_SECRET_ACCESS_KEY", secret),
    ];
    let hosted_creds = [creds[0], creds[1], ("RUNNER_ENVIRONMENT", "github-hosted")];

    // Fork pull requests: empty secrets keep the GitHub cache.
    let (code, env, out, dir) = run(
        &["linux-x64", "read-only"],
        &[
            ("AWS_ACCESS_KEY_ID", ""),
            ("AWS_SECRET_ACCESS_KEY", ""),
            ("RUNNER_ENVIRONMENT", "github-hosted"),
        ],
    );
    assert_eq!(code, Some(0));
    assert_eq!(out, "backend=gha\n");
    assert_eq!(env, format!("SCCACHE_DIR={}\n", dir.display()));

    // Self-hosted runners hash different absolute paths: never R2.
    let (_, env, out, _) = run(
        &["darwin-hosted", "read-only"],
        &[creds[0], creds[1], ("RUNNER_ENVIRONMENT", "self-hosted")],
    );
    assert_eq!(out, "backend=gha\n");
    assert!(!env.contains("SCCACHE_BUCKET"));

    let (code, env, out, _) = run(&["linux-arm64", "read-only"], &hosted_creds);
    assert_eq!(code, Some(0));
    assert_eq!(out, "backend=r2\n");
    for line in [
        "SCCACHE_BUCKET=carrick-sccache",
        "SCCACHE_ENDPOINT=https://example.r2.cloudflarestorage.com",
        "SCCACHE_REGION=auto",
        "SCCACHE_S3_USE_SSL=true",
        "SCCACHE_S3_KEY_PREFIX=sccache/linux-arm64/",
        "SCCACHE_S3_RW_MODE=READ_ONLY",
    ] {
        assert!(env.lines().any(|l| l == line), "{line} in {env}");
    }
    assert!(
        !env.contains(secret),
        "credentials stay in the job env only"
    );

    let (_, env, _, _) = run(&["linux-x64", "read-write"], &hosted_creds);
    assert!(env.lines().any(|l| l == "SCCACHE_S3_RW_MODE=READ_WRITE"));

    for args in [["linux", "read-only"], ["linux-x64", "write"]] {
        let (code, _, out, _) = run(&args, &hosted_creds);
        assert_eq!(code, Some(2), "{args:?}");
        assert!(out.is_empty());
    }
}

/// Every string in `value` that names an R2 secret.
fn r2_secret_references(value: &yaml_rust2::Yaml, found: &mut Vec<String>) {
    match value {
        yaml_rust2::Yaml::String(text) if text.contains("secrets.SCCACHE_R2_") => {
            found.push(text.clone());
        }
        yaml_rust2::Yaml::Array(items) => {
            for item in items {
                r2_secret_references(item, found);
            }
        }
        yaml_rust2::Yaml::Hash(map) => {
            for (key, item) in map {
                r2_secret_references(key, found);
                r2_secret_references(item, found);
            }
        }
        _ => {}
    }
}

#[test]
fn r2_reader_credentials_reach_only_hosted_compiling_jobs() {
    // #889 follow-up: workflow-level credentials reached every job, including
    // jobs that never compile and jobs on the persistent self-hosted Mac.
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let text = std::fs::read_to_string(root.join(".github/workflows/ci.yml")).unwrap();
    let workflow = &yaml_rust2::YamlLoader::load_from_str(&text).unwrap()[0];
    let mut workflow_refs = Vec::new();
    r2_secret_references(&workflow["env"], &mut workflow_refs);
    assert!(
        workflow_refs.is_empty(),
        "workflow-level: {workflow_refs:?}"
    );
    assert!(workflow["env"]["AWS_ACCESS_KEY_ID"].is_badvalue());
    assert!(workflow["env"]["AWS_SECRET_ACCESS_KEY"].is_badvalue());

    // A self-hosted runner is chosen only for same-repository PRs; the
    // credential expression must resolve empty exactly then.
    let hosted_only = |secret: &str| {
        format!(
            "${{{{ needs.changes.outputs.macos_runner == '\"macos-15\"' && secrets.{secret} || '' }}}}"
        )
    };
    let mut readers = 0;
    for (job, body) in workflow["jobs"].as_hash().unwrap() {
        let job = job.as_str().unwrap();
        let compiles = body["steps"].as_vec().unwrap().iter().any(|step| {
            step["run"]
                .as_str()
                .is_some_and(|run| run.starts_with("scripts/ci/compiler-cache-env.sh "))
        });
        let mut refs = Vec::new();
        r2_secret_references(body, &mut refs);
        if job == "cache-warm" {
            assert!(refs.iter().all(|r| r.contains("_WRITER_")), "{refs:?}");
            continue;
        }
        if !compiles {
            assert!(refs.is_empty(), "{job} never compiles but sees {refs:?}");
            continue;
        }
        readers += 1;
        assert_eq!(refs.len(), 2, "{job}: only the job-level pair: {refs:?}");
        let runner = body["runs-on"].as_str().unwrap();
        let (id, secret) = if runner.contains("macos_runner") {
            (
                hosted_only("SCCACHE_R2_ACCESS_KEY_ID"),
                hosted_only("SCCACHE_R2_SECRET_ACCESS_KEY"),
            )
        } else {
            assert!(
                !runner.contains("self-hosted") && !runner.contains("${{"),
                "{job}: {runner}"
            );
            (
                "${{ secrets.SCCACHE_R2_ACCESS_KEY_ID }}".to_owned(),
                "${{ secrets.SCCACHE_R2_SECRET_ACCESS_KEY }}".to_owned(),
            )
        };
        assert_eq!(
            body["env"]["AWS_ACCESS_KEY_ID"].as_str(),
            Some(id.as_str()),
            "{job}"
        );
        assert_eq!(
            body["env"]["AWS_SECRET_ACCESS_KEY"].as_str(),
            Some(secret.as_str()),
            "{job}"
        );
    }
    assert_eq!(readers, 20, "every hosted compiler cache reader");
    for job in ["linked-issue", "commit-trailers", "actionlint", "ci-ok"] {
        assert!(workflow["jobs"][job]["env"]["AWS_ACCESS_KEY_ID"].is_badvalue());
    }
    // The self-hosted runner choice still lives in one place.
    assert!(
        workflow["jobs"]["changes"]["outputs"]["macos_runner"]
            .as_str()
            .unwrap()
            .ends_with("|| '\"macos-15\"' }}")
    );
}
