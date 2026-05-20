//! Differential syscall conformance: carrick vs real Linux.
//!
//! Each case is a `/bin/sh -c` snippet exercising syscall-observable
//! behaviour. We run the IDENTICAL snippet under carrick (`--fs host`) and
//! inside a real arm64 Linux container (via the `bollard` Docker client) and
//! diff the output. A difference is a candidate gap in carrick's syscall
//! layer — surfaced by name immediately instead of via downstream
//! archaeology ("dpkg returned 100").
//!
//! The test self-skips (passes) when the carrick release binary isn't built
//! or Docker isn't reachable, so `cargo test` stays green everywhere. Run it
//! deliberately with Docker running and the signed release binary present:
//!   cargo test --test conformance -- --nocapture

use std::path::PathBuf;
use std::process::Command;

use bollard::container::{
    Config, CreateContainerOptions, LogsOptions, RemoveContainerOptions,
};
use bollard::image::CreateImageOptions;
use bollard::Docker;
use futures_util::StreamExt;

const IMAGE: &str = "docker.io/library/ubuntu:24.04";
const PLATFORM: &str = "linux/arm64";

struct Case {
    name: &'static str,
    snippet: &'static str,
}

/// Snippets must be deterministic: no timestamps, pids, or hashes.
const CASES: &[Case] = &[
    Case { name: "getcwd", snippet: "cd /tmp && mkdir -p a/b && cd a/b && pwd" },
    Case { name: "mkdir_chdir", snippet: "mkdir -p /x/y/z && cd /x/y/z && pwd" },
    Case { name: "access_root", snippet: "test -w /var/lib/dpkg && echo W || echo noW; test -r /etc/passwd && echo R || echo noR; test -x /bin/sh && echo X || echo noX" },
    Case { name: "readdir_created", snippet: "cd /tmp && touch zz_newfile && ls zz_newfile && ls | grep -c zz_newfile" },
    Case { name: "pipe_cat", snippet: "echo hello | cat" },
    Case { name: "rename", snippet: "cd /tmp && echo content > a.txt && mv a.txt b.txt && cat b.txt && (ls a.txt 2>&1 | sed 's/.*: //')" },
    Case { name: "symlink", snippet: "cd /tmp && ln -sf /etc/hostname lnk && readlink lnk" },
    Case { name: "hardlink", snippet: "cd /tmp && echo hl > f1 && ln f1 f2 && cat f2" },
    Case { name: "stat", snippet: "stat -c '%s %F %a' /etc/passwd" },
    Case { name: "copy_file_range", snippet: "cp /etc/hostname /tmp/h2 && cat /tmp/h2 >/dev/null && echo cp_ok" },
    Case { name: "fd_redirect", snippet: "exec 3>/tmp/fd3.txt; echo via3 >&3; exec 3>&-; cat /tmp/fd3.txt" },
    Case { name: "chmod", snippet: "cd /tmp && touch m && chmod 640 m && stat -c '%a' m" },
    Case { name: "truncate", snippet: "cd /tmp && printf 'abcdef' > t && truncate -s 3 t && cat t && echo" },
    Case { name: "append", snippet: "cd /tmp && echo one > ap && echo two >> ap && cat ap" },
    Case { name: "mkdir_rmdir", snippet: "cd /tmp && mkdir rd && rmdir rd && (ls rd 2>&1 | sed 's/.*: //')" },
    Case { name: "id_root", snippet: "id -u; id -g" },
];

fn carrick_bin() -> Option<PathBuf> {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target/release/carrick");
    p.exists().then_some(p)
}

/// Drop carrick's scratch warning so output lines up with Docker's.
fn normalize(s: &str) -> String {
    s.lines()
        .filter(|l| {
            !l.contains("case-insensitive; defaulting")
                && !l.contains("Pass `--fs host`")
        })
        .map(|l| l.trim_end())
        .collect::<Vec<_>>()
        .join("\n")
        .trim_end()
        .to_string()
}

fn run_carrick(bin: &PathBuf, snippet: &str) -> String {
    let out = Command::new(bin)
        .args(["run", IMAGE, "--raw", "--fs", "host", "/bin/sh", "-c", snippet])
        .output()
        .expect("spawn carrick");
    let mut combined = String::from_utf8_lossy(&out.stdout).into_owned();
    combined.push_str(&String::from_utf8_lossy(&out.stderr));
    normalize(&combined)
}

async fn ensure_image(docker: &Docker) -> anyhow::Result<()> {
    if docker.inspect_image(IMAGE).await.is_ok() {
        return Ok(());
    }
    let mut stream = docker.create_image(
        Some(CreateImageOptions { from_image: IMAGE, platform: PLATFORM, ..Default::default() }),
        None,
        None,
    );
    while let Some(item) = stream.next().await {
        item?;
    }
    Ok(())
}

async fn run_docker(docker: &Docker, snippet: &str) -> anyhow::Result<String> {
    let config = Config {
        image: Some(IMAGE.to_string()),
        cmd: Some(vec!["/bin/sh".into(), "-c".into(), snippet.to_string()]),
        ..Default::default()
    };
    let created = docker
        .create_container(
            Some(CreateContainerOptions {
                name: format!("carrick-conf-{}", std::process::id()),
                platform: Some(PLATFORM.to_string()),
            }),
            config,
        )
        .await?;
    let id = created.id;
    let result = async {
        docker.start_container::<String>(&id, None).await?;
        let mut wait = docker.wait_container::<String>(&id, None);
        while let Some(w) = wait.next().await {
            // Non-zero container exit is fine — we compare output, and the
            // wait stream surfaces it as an Err we deliberately ignore.
            let _ = w;
        }
        let mut logs = docker.logs::<String>(
            &id,
            Some(LogsOptions { stdout: true, stderr: true, ..Default::default() }),
        );
        let mut buf = String::new();
        while let Some(item) = logs.next().await {
            if let Ok(out) = item {
                buf.push_str(&out.to_string());
            }
        }
        Ok::<_, anyhow::Error>(normalize(&buf))
    }
    .await;
    let _ = docker
        .remove_container(&id, Some(RemoveContainerOptions { force: true, ..Default::default() }))
        .await;
    result
}

#[test]
fn conformance() {
    let Some(bin) = carrick_bin() else {
        eprintln!("SKIP conformance: target/release/carrick not built");
        return;
    };
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    rt.block_on(async {
        let docker = match Docker::connect_with_local_defaults() {
            Ok(d) => match d.ping().await {
                Ok(_) => d,
                Err(e) => {
                    eprintln!("SKIP conformance: Docker not reachable: {e}");
                    return;
                }
            },
            Err(e) => {
                eprintln!("SKIP conformance: Docker connect failed: {e}");
                return;
            }
        };
        if let Err(e) = ensure_image(&docker).await {
            eprintln!("SKIP conformance: cannot pull {IMAGE}: {e}");
            return;
        }

        let mut failures = Vec::new();
        for case in CASES {
            let carrick_out = run_carrick(&bin, case.snippet);
            let docker_out = match run_docker(&docker, case.snippet).await {
                Ok(o) => o,
                Err(e) => {
                    eprintln!("FAIL  {} (docker error: {e})", case.name);
                    failures.push(case.name);
                    continue;
                }
            };
            if carrick_out == docker_out {
                eprintln!("PASS  {}", case.name);
            } else {
                eprintln!(
                    "FAIL  {}\n  --- carrick ---\n{}\n  --- linux ---\n{}",
                    case.name,
                    indent(&carrick_out),
                    indent(&docker_out)
                );
                failures.push(case.name);
            }
        }
        assert!(failures.is_empty(), "conformance gaps: {failures:?}");
    });
}

fn indent(s: &str) -> String {
    s.lines().map(|l| format!("    {l}")).collect::<Vec<_>>().join("\n")
}
