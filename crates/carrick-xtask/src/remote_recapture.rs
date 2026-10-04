//! Position-only macOS recapture using the remote acceptance checkout authority.
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;
use thiserror::Error;

use crate::command::{self, CommandError};
use crate::remote_accept::{self as remote, RemoteAcceptError, shell_quote};

const CAPTURE: &str = "scripts/migrate/host-authority-macos-capture.json";
const INVENTORY: &str = "scripts/migrate/host-authority-transition-inventory.json";

#[derive(clap::Args, Debug, Clone)]
pub struct RemoteRecaptureArgs {
    #[arg(
        long = "ref",
        default_value = "HEAD",
        help = "Exact commit to recapture"
    )]
    pub git_ref: String,
    #[arg(long, help = "SSH host (same default as remote-accept)")]
    pub host: Option<String>,
    #[arg(long, help = "Remote root (same default as remote-accept)")]
    pub remote_root: Option<String>,
}

#[derive(Debug, Error)]
pub enum RecaptureError {
    #[error(transparent)]
    Remote(#[from] RemoteAcceptError),
    #[error(transparent)]
    Command(#[from] CommandError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error("refused recapture patch: {0}")]
    InvalidPatch(String),
}

fn refused(message: impl Into<String>) -> RecaptureError {
    RecaptureError::InvalidPatch(message.into())
}

fn reviews_by_id(rows: &Value) -> Result<BTreeMap<&str, &Value>, RecaptureError> {
    let mut result = BTreeMap::new();
    for row in rows
        .as_array()
        .ok_or_else(|| refused("inventory is not an array"))?
    {
        let id = row["review_id"]
            .as_str()
            .ok_or_else(|| refused("missing review_id"))?;
        if result.insert(id, row).is_some() {
            return Err(refused(format!("duplicate review_id {id}")));
        }
    }
    if result.is_empty() {
        return Err(refused("empty inventory"));
    }
    Ok(result)
}

/// Compare the whole reviewed row, including unknown future fields, by stable
/// review ID. Only numeric source coordinates and the exact leading site
/// reference may move. No row removals, profile narrowing, or review re-bless.
fn validate_reviews(before: &Value, after: &Value) -> Result<(), RecaptureError> {
    let old_rows = reviews_by_id(before)?;
    let new_rows = reviews_by_id(after)?;
    if old_rows.keys().ne(new_rows.keys()) {
        return Err(refused("review IDs added or removed"));
    }
    for (id, old) in old_rows {
        let new = new_rows[id];
        let old_source = old["source"]
            .as_object()
            .ok_or_else(|| refused("missing source"))?;
        let new_source = new["source"]
            .as_object()
            .ok_or_else(|| refused("missing source"))?;
        if old_source.keys().ne(new_source.keys())
            || old_source.get("file") != new_source.get("file")
        {
            return Err(refused(format!("{id}: source shape or file changed")));
        }
        for (field, value) in new_source {
            if field != "file"
                && value != &old_source[field]
                && (!matches!(
                    field.as_str(),
                    "line"
                        | "line_start"
                        | "line_end"
                        | "column"
                        | "column_start"
                        | "column_end"
                        | "byte_start"
                        | "byte_end"
                ) || value.as_u64().is_none())
            {
                return Err(refused(format!("{id}: invalid source coordinate {field}")));
            }
        }

        let file = old["source"]["file"]
            .as_str()
            .ok_or_else(|| refused("missing source file"))?;
        let old_line = old["source"]["line"]
            .as_u64()
            .ok_or_else(|| refused("missing source line"))?;
        let new_line = new["source"]["line"]
            .as_u64()
            .ok_or_else(|| refused("missing source line"))?;
        let prefix = format!("At {file}:{old_line}");
        let prose = old["rationale"]
            .as_str()
            .ok_or_else(|| refused("missing rationale"))?;
        // Require a delimiter so line 10 cannot bind a line-100 review.
        let tail = prose
            .strip_prefix(&prefix)
            .filter(|tail| tail.starts_with(' ') || tail.starts_with(','))
            .ok_or_else(|| refused(format!("{id}: rationale lacks exact site prefix")))?;
        let mut expected = old.clone();
        expected["source"] = new["source"].clone();
        expected["rationale"] = Value::String(format!("At {file}:{new_line}{tail}"));
        if &expected != new {
            return Err(refused(format!("{id}: reviewed fields changed")));
        }
    }
    Ok(())
}

fn indexed_git(root: &Path, index: &Path, args: &[&str]) -> Result<String, RecaptureError> {
    let output = Command::new("git")
        .current_dir(root)
        .env("GIT_INDEX_FILE", index)
        .args(args)
        .output()?;
    if !output.status.success() {
        return Err(refused(format!(
            "git {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    String::from_utf8(output.stdout).map_err(|e| refused(e.to_string()))
}

/// Apply to a disposable index seeded from the requested commit, never the
/// caller's worktree/index. Git validates patch syntax and context; raw diff
/// validates the complete changed path/mode set, not just patch header text.
fn validate_patch(root: &Path, sha: &str, patch: &Path) -> Result<(), RecaptureError> {
    let temporary = tempfile::tempdir()?;
    let index = temporary.path().join("index");
    indexed_git(root, &index, &["read-tree", sha])?;
    let patch_path = patch
        .to_str()
        .ok_or_else(|| refused("non-UTF8 patch path"))?;
    if fs::metadata(patch)?.len() != 0 {
        indexed_git(
            root,
            &index,
            &["apply", "--cached", "--whitespace=error", patch_path],
        )?;
    }
    let raw = indexed_git(
        root,
        &index,
        &["diff", "--cached", "--raw", "--no-renames", sha],
    )?;
    for line in raw.lines() {
        let (metadata, path) = line
            .split_once('\t')
            .ok_or_else(|| refused("invalid raw diff"))?;
        let fields: Vec<_> = metadata.split_whitespace().collect();
        if !matches!(path, CAPTURE | INVENTORY)
            || fields.len() != 5
            || fields[0] != ":100644"
            || fields[1] != "100644"
            || fields[4] != "M"
        {
            return Err(refused(format!("unexpected path, mode or status: {line}")));
        }
    }
    let before: Value = serde_json::from_str(&indexed_git(
        root,
        &index,
        &["show", &format!("{sha}:{INVENTORY}")],
    )?)?;
    let after: Value = serde_json::from_str(&indexed_git(
        root,
        &index,
        &["show", &format!(":{INVENTORY}")],
    )?)?;
    validate_reviews(&before, &after)?;
    let capture: Value = serde_json::from_str(&indexed_git(
        root,
        &index,
        &["show", &format!(":{CAPTURE}")],
    )?)?;
    if capture["source_head"] != sha {
        return Err(refused(
            "capture source_head does not match requested commit",
        ));
    }
    let original: Value = serde_json::from_str(&indexed_git(
        root,
        &index,
        &["show", &format!("{sha}:{CAPTURE}")],
    )?)?;
    for field in [
        "schema",
        "kind",
        "executed_profiles",
        "pending_profiles",
        "profiles",
        "profiles_sha256",
        "catalog_sha256",
        "toolchain",
    ] {
        if original.get(field).is_none() || original[field] != capture[field] {
            return Err(refused(format!("capture {field} changed")));
        }
    }
    Ok(())
}

fn build_recapture_script(worktree: &str, sha: &str, run_dir: &str) -> String {
    let q_wt = shell_quote(worktree);
    let q_sha = shell_quote(sha);
    let q_candidate = shell_quote(&format!("{run_dir}/candidate.json"));
    let q_patch = shell_quote(&format!("{run_dir}/recapture.patch"));
    let q_inventory = shell_quote(INVENTORY);
    let q_capture = shell_quote(CAPTURE);
    // Always restore our two generated files before releasing the checkout
    // lock, including on checker/reconciler failures. Preserve other changes.
    format!(
        "set -eu\ncd {q_wt}\n[ \"$(git rev-parse HEAD)\" = {q_sha} ]\n[ -z \"$(git status --porcelain --untracked-files=all)\" ]\ntrap 'git restore --source=HEAD --worktree -- {q_inventory} {q_capture}' EXIT\nrc=0\npython3 scripts/migrate/check-host-authority-transitions.py --refresh-candidate {q_candidate} || rc=$?\n[ \"$rc\" = 1 ]\n[ -s {q_candidate} ]\npython3 scripts/migrate/reconcile-host-authority-positions.py {q_candidate}\npython3 scripts/migrate/check-host-authority-transitions.py --static\n[ \"$(git rev-parse HEAD)\" = {q_sha} ]\ngit diff --no-ext-diff --no-textconv --binary -- {q_capture} {q_inventory} > {q_patch}\n"
    )
}

fn build_launch_command(remote_root: &str, worktree: &str, run_dir: &str, script: &str) -> String {
    let env = shell_quote(&format!("{remote_root}/env.sh"));
    let exit = shell_quote(&format!("{run_dir}/exit"));
    let exit_tmp = shell_quote(&format!("{run_dir}/exit.tmp"));
    let completion =
        format!("rc=$?; echo \"$rc\" > {exit_tmp} && mv {exit_tmp} {exit}; exit \"$rc\"");
    // Invoke the lease CLI directly: just's variadic CMD interpolation joins
    // shell text and loses the single argv boundary around a multiline script.
    format!(
        "set -eu; mkdir {}; trap {} EXIT; [ ! -f {env} ] || . {env}; cd {}; cargo run --locked -p carrick-xtask -- host-lease --mode gate -- sh -c {} > {} 2>&1",
        shell_quote(run_dir),
        shell_quote(&completion),
        shell_quote(worktree),
        shell_quote(script),
        shell_quote(&format!("{run_dir}/recapture.log"))
    )
}

pub fn run(root: Option<&Path>, args: RemoteRecaptureArgs) -> Result<PathBuf, RecaptureError> {
    let root = crate::cli::resolve_repo_info(root)
        .map_err(|e| refused(e.to_string()))?
        .repository_root;
    let commit = format!("{}^{{commit}}", args.git_ref);
    let sha = command::run_checked(
        "git",
        ["rev-parse", "--verify", "--end-of-options", &commit],
        Some(&root),
    )?
    .stdout
    .trim()
    .to_string();
    if sha.len() != 40 || !sha.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(refused("ref did not resolve to a full commit hash"));
    }
    let status = command::run_checked("git", ["status", "--porcelain"], Some(&root))?;
    let (_, tracked) = crate::accept::check_git_status(&status.stdout);
    if remote::should_refuse_dirty(&args.git_ref, tracked) {
        return Err(refused("local HEAD has uncommitted tracked changes"));
    }
    let host = remote::resolve_host(args.host.as_deref());
    let remote_root = remote::resolve_remote_root(args.remote_root.as_deref());
    remote::check_remote_disk_space(&host, &remote_root)?;
    let run_id = format!(
        "{}-recapture-{}",
        &sha[..12],
        crate::accept::generate_timestamp()
    );
    let lock_dir = remote::remote_lock_dir(Path::new(&remote_root))
        .to_string_lossy()
        .into_owned();
    remote::acquire_remote_lock(&host, &remote_root, &lock_dir, &run_id)?;
    let mut guard = remote::RemoteLockGuard::new(&host, lock_dir);
    let worktree = remote::prepare_remote_worktree(
        &root,
        &host,
        &remote_root,
        &sha,
        remote::WorktreePolicy::RequireClean,
    )?;
    let run_dir = remote::remote_run_dir(Path::new(&remote_root), &run_id)
        .to_string_lossy()
        .into_owned();
    let script = build_recapture_script(&worktree, &sha, &run_dir);
    // Checkout lock -> host lease -> compiler work, just like remote-accept.
    let launch = build_launch_command(&remote_root, &worktree, &run_dir, &script);
    println!("Recapturing {sha} on {host}; remote log: {run_dir}/recapture.log");
    if let Err(error) = remote::run_ssh_command(&host, &launch) {
        // A transport failure does not prove the remote compiler stopped.
        // Retain the checkout lock; remote-accept's stale-lock recovery can
        // reclaim it only after the remote completion trap publishes `exit`.
        guard.disarm();
        return Err(error.into());
    }
    // Fetch failures propagate before touching any local output. Never read an
    // old patch after a failed transfer (the same fail-closed rule as accept).
    let patch = remote::run_ssh_command(
        &host,
        &format!("cat {}", shell_quote(&format!("{run_dir}/recapture.patch"))),
    )?;
    let destination = root.join("target/remote-recapture").join(&run_id);
    fs::create_dir_all(&destination)?;
    let temporary = destination.join("unvalidated.patch");
    fs::write(&temporary, patch)?;
    validate_patch(&root, &sha, &temporary)?;
    let output = destination.join("recapture.patch");
    fs::rename(&temporary, &output)?;
    println!(
        "Validated patch: {}\nApply with: git apply {}\nThen review and commit locally.",
        output.display(),
        shell_quote(&output.to_string_lossy())
    );
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn inventory() -> Value {
        json!([{
            "review_id": "HA-000001", "catalog_id": "HA-CATALOG-PROCESS-ID",
            "operation": "std::process::id", "classification": "declared_substrate",
            "profiles": ["macos-cli-default"], "expansion": null,
            "evidence": {"authority": "carrier", "resource": "reviewed carrier identity"},
            "source": {"file": "crates/example/src/lib.rs", "line": 10, "byte_start": 20, "byte_end": 30},
            "rationale": "At crates/example/src/lib.rs:10 in `carrier`, read carrier identity."
        }])
    }

    fn moved() -> Value {
        let mut rows = inventory();
        rows[0]["source"]["line"] = json!(12);
        rows[0]["source"]["byte_start"] = json!(22);
        rows[0]["source"]["byte_end"] = json!(32);
        rows[0]["rationale"] =
            json!("At crates/example/src/lib.rs:12 in `carrier`, read carrier identity.");
        rows
    }

    #[test]
    fn position_move_and_reordering_preserve_reviews() {
        validate_reviews(&inventory(), &moved()).unwrap();
        let mut before = inventory();
        let mut extra = before[0].clone();
        extra["review_id"] = json!("HA-000002");
        before.as_array_mut().unwrap().push(extra);
        let mut after = before.clone();
        after.as_array_mut().unwrap().reverse();
        validate_reviews(&before, &after).unwrap();
        let mut comma = inventory();
        comma[0]["rationale"] = json!("At crates/example/src/lib.rs:10, read carrier identity.");
        let mut comma_moved = moved();
        comma_moved[0]["rationale"] =
            json!("At crates/example/src/lib.rs:12, read carrier identity.");
        validate_reviews(&comma, &comma_moved).unwrap();
    }

    #[test]
    fn every_reviewed_field_is_guarded_including_future_fields() {
        for (field, value) in [
            ("classification", json!("declared_backing")),
            (
                "evidence",
                json!({"authority": "guest", "resource": "re-blessed"}),
            ),
            ("operation", json!("libc::getpid")),
            ("catalog_id", json!("different")),
            ("profiles", json!(["linux-cli"])),
            ("expansion", json!({"file": "macro.rs"})),
            ("review_id", json!("HA-000999")),
            (
                "rationale",
                json!("At crates/example/src/lib.rs:12 in `carrier`, changed review."),
            ),
            ("future_review_field", json!("new")),
        ] {
            let mut after = moved();
            after[0][field] = value;
            assert!(validate_reviews(&inventory(), &after).is_err(), "{field}");
        }
    }

    #[test]
    fn removals_additions_duplicate_ids_and_source_rehomes_are_refused() {
        for after in [json!([]), json!([inventory()[0], inventory()[0]])] {
            assert!(validate_reviews(&inventory(), &after).is_err());
        }
        let mut extra = inventory();
        let mut row = extra[0].clone();
        row["review_id"] = json!("HA-000002");
        extra.as_array_mut().unwrap().push(row);
        assert!(validate_reviews(&inventory(), &extra).is_err());
        for (field, value) in [
            ("file", json!("another.rs")),
            ("line", json!(-1)),
            ("future_scope", json!("guest")),
        ] {
            let mut after = moved();
            after[0]["source"][field] = value;
            assert!(validate_reviews(&inventory(), &after).is_err());
        }
    }

    #[test]
    fn rationale_line_prefix_cannot_match_a_longer_line_number() {
        let mut before = inventory();
        before[0]["rationale"] =
            json!("At crates/example/src/lib.rs:100 in `carrier`, read carrier identity.");
        assert!(validate_reviews(&before, &moved()).is_err());
    }

    struct Fixture {
        dir: tempfile::TempDir,
        sha: String,
    }

    impl Fixture {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let root = dir.path();
            command::run_checked("git", ["init", "-q"], Some(root)).unwrap();
            fs::create_dir_all(root.join("scripts/migrate")).unwrap();
            fs::write(
                root.join(INVENTORY),
                serde_json::to_string_pretty(&inventory()).unwrap(),
            )
            .unwrap();
            fs::write(
                root.join(CAPTURE),
                serde_json::to_string_pretty(&json!({
                    "source_head": "initial", "schema": 1, "kind": "host-authority-macos-capture",
                    "executed_profiles": ["macos-cli-default"], "pending_profiles": ["linux-cli"],
                    "profiles": [], "profiles_sha256": "p", "catalog_sha256": "c", "toolchain": {}
                }))
                .unwrap(),
            )
            .unwrap();
            fs::write(root.join("other.txt"), "outside fence\n").unwrap();
            command::run_checked("git", ["add", "."], Some(root)).unwrap();
            command::run_checked(
                "git",
                [
                    "-c",
                    "user.name=Test",
                    "-c",
                    "user.email=test@example.com",
                    "commit",
                    "-qm",
                    "fixture",
                ],
                Some(root),
            )
            .unwrap();
            let sha = command::run_checked("git", ["rev-parse", "HEAD"], Some(root))
                .unwrap()
                .stdout
                .trim()
                .to_string();
            let mut capture: Value =
                serde_json::from_slice(&fs::read(root.join(CAPTURE)).unwrap()).unwrap();
            capture["source_head"] = json!(sha);
            fs::write(
                root.join(CAPTURE),
                serde_json::to_string_pretty(&capture).unwrap(),
            )
            .unwrap();
            fs::write(
                root.join(INVENTORY),
                serde_json::to_string_pretty(&moved()).unwrap(),
            )
            .unwrap();
            Self { dir, sha }
        }

        fn patch(&self) -> PathBuf {
            let patch = self.dir.path().join("returned.patch");
            let diff = command::run_checked("git", ["diff", "--binary"], Some(self.dir.path()))
                .unwrap()
                .stdout;
            fs::write(&patch, diff).unwrap();
            patch
        }

        fn validate(&self) -> Result<(), RecaptureError> {
            validate_patch(self.dir.path(), &self.sha, &self.patch())
        }
    }

    #[test]
    fn real_git_patch_validates_without_changing_caller_index_or_worktree() {
        let fixture = Fixture::new();
        let root = fixture.dir.path();
        let patch = fixture.patch();
        let before = command::run_checked("git", ["status", "--porcelain"], Some(root))
            .unwrap()
            .stdout;
        validate_patch(root, &fixture.sha, &patch).unwrap();
        assert_eq!(
            before,
            command::run_checked("git", ["status", "--porcelain"], Some(root))
                .unwrap()
                .stdout
        );
        assert_eq!(
            fs::read(root.join(INVENTORY)).unwrap(),
            serde_json::to_string_pretty(&moved()).unwrap().as_bytes()
        );
    }

    #[test]
    fn patch_rejects_review_changes_outside_paths_modes_deletion_and_wrong_ref() {
        for case in [
            "review",
            "outside",
            "mode",
            "delete",
            "wrong-ref",
            "capture-scope",
        ] {
            let fixture = Fixture::new();
            let root = fixture.dir.path();
            match case {
                "review" => {
                    let mut rows = moved();
                    rows[0]["classification"] = json!("unreviewed");
                    fs::write(
                        root.join(INVENTORY),
                        serde_json::to_string_pretty(&rows).unwrap(),
                    )
                    .unwrap();
                }
                "outside" => fs::write(root.join("other.txt"), "changed\n").unwrap(),
                "mode" => {
                    use std::os::unix::fs::PermissionsExt;
                    fs::set_permissions(root.join(INVENTORY), fs::Permissions::from_mode(0o755))
                        .unwrap();
                }
                "delete" => fs::remove_file(root.join(INVENTORY)).unwrap(),
                "wrong-ref" | "capture-scope" => {
                    let mut capture: Value =
                        serde_json::from_slice(&fs::read(root.join(CAPTURE)).unwrap()).unwrap();
                    if case == "wrong-ref" {
                        capture["source_head"] = json!("wrong");
                    } else {
                        capture["executed_profiles"] = json!(["linux-cli"]);
                    }
                    fs::write(
                        root.join(CAPTURE),
                        serde_json::to_string_pretty(&capture).unwrap(),
                    )
                    .unwrap();
                }
                _ => unreachable!(),
            }
            assert!(fixture.validate().is_err(), "{case}");
        }
    }

    #[test]
    fn malformed_patch_and_missing_transfer_are_refused() {
        let fixture = Fixture::new();
        let patch = fixture.dir.path().join("bad.patch");
        fs::write(&patch, "not a diff\n").unwrap();
        assert!(validate_patch(fixture.dir.path(), &fixture.sha, &patch).is_err());
        fs::remove_file(&patch).unwrap();
        assert!(validate_patch(fixture.dir.path(), &fixture.sha, &patch).is_err());
    }

    #[test]
    fn remote_script_checks_identity_cleanliness_expected_partial_exit_and_cleanup() {
        let script = build_recapture_script("/tmp/work tree", "0123456789abcdef", "/tmp/run's dir");
        let clean = script.find("git status --porcelain").unwrap();
        let refresh = script.find("--refresh-candidate").unwrap();
        assert!(clean < refresh);
        assert!(script.contains("[ \"$rc\" = 1 ]"));
        assert!(script.contains("trap 'git restore --source=HEAD --worktree"));
        assert!(script.contains("--static"));
        assert!(script.contains("cd '/tmp/work tree'"));
        assert!(script.contains("run'\\''s dir"));
        assert_eq!(script.matches("git rev-parse HEAD").count(), 2);
    }

    #[test]
    fn launch_preserves_multiline_script_argv_and_lease_refusal() {
        use std::os::unix::fs::PermissionsExt;
        for reject in [false, true] {
            let temporary = tempfile::tempdir().unwrap();
            let root = temporary.path();
            let worktree = root.join("work tree");
            fs::create_dir(&worktree).unwrap();
            let run_dir = root.join("run's dir");
            fs::write(
                root.join("env.sh"),
                "export CARRICK_RECAPTURE_FIXTURE=quoted-value\n",
            )
            .unwrap();
            let cargo = root.join("cargo");
            let stub = if reject {
                "#!/bin/sh\nexit 73\n"
            } else {
                "#!/bin/sh\n[ \"$#\" = 12 ] || exit 71\n[ \"$6\" = host-lease ] || exit 72\nshift 9\nexec \"$@\"\n"
            };
            fs::write(&cargo, stub).unwrap();
            fs::set_permissions(&cargo, fs::Permissions::from_mode(0o755)).unwrap();
            let witness = worktree.join("executed");
            let script = format!(
                "set -eu\nprintf '%s' \"$CARRICK_RECAPTURE_FIXTURE\" > {}\n",
                shell_quote(&witness.to_string_lossy())
            );
            let launch = build_launch_command(
                &root.to_string_lossy(),
                &worktree.to_string_lossy(),
                &run_dir.to_string_lossy(),
                &script,
            );
            let output = Command::new("sh")
                .args(["-c", &launch])
                .env("PATH", format!("{}:/usr/bin:/bin", root.display()))
                .output()
                .unwrap();
            assert_eq!(output.status.success(), !reject);
            assert_eq!(witness.exists(), !reject);
            assert_eq!(
                fs::read_to_string(run_dir.join("exit")).unwrap().trim(),
                if reject { "73" } else { "0" }
            );
            if !reject {
                assert_eq!(fs::read_to_string(&witness).unwrap(), "quoted-value");
            }
        }
    }
}
