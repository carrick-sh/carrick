#![allow(clippy::unwrap_used, clippy::expect_used)]
use carrick_xtask::workorder::{parse, validate_provenance};
use serde_json::{Value, json};
use std::collections::BTreeSet;

fn valid() -> String {
    "work-order v1\n```yaml\nacceptance:\n  red_first: cargo test -p carrick-xtask --test claims\n  checks: [exactly one concurrent claimant]\nfence: [crates/carrick-xtask/**]\nroute: infra\ndepends: []\nbase: main\ngates: [portable]\nsize_budget: 4000\ndecisions: [https://github.com/carrick-sh/carrick/issues/231#issuecomment-1]\n```".into()
}

#[test]
fn workorder_v1_is_strict_and_bounded() {
    let order = parse(&valid()).unwrap();
    assert_eq!(order.size_budget, 4000);
    for invalid in [
        valid().replace("4000", "4001"),
        valid().replace("4000", "-1"),
        valid().replace("route: infra", "route: unknown"),
        valid().replace("route: infra", "route: [infra, kvm]"),
        valid().replace("base: main", "base: work/undeclared-parent"),
        valid().replace("gates: [portable]", "gates: [mystery]"),
        valid().replace("gates: [portable]", "gates: []"),
        valid().replace("crates/carrick-xtask/**", "../**"),
        valid().replace("crates/carrick-xtask/**", "/etc/**"),
        valid().replace("crates/carrick-xtask/**", "crates/["),
        valid().replace("route: infra", "route: infra\nroute: mechanical"),
        valid().replace("size_budget:", "unknown: x\nsize_budget:"),
        valid().replace("checks: [exactly one concurrent claimant]", "checks: []"),
        valid().replace(
            "red_first: cargo test -p carrick-xtask --test claims",
            "red_first: ''",
        ),
        valid().replace("route: infra", "route: hvf"),
        valid().replace("work-order v1", "work-order v2"),
        format!("{}\n{}", valid(), valid()),
        format!("{}\n```yaml\nroute: infra\n```", valid()),
        format!("{}\n{}", valid(), "x".repeat(16384)),
    ] {
        assert!(parse(&invalid).is_err(), "accepted: {invalid}");
    }
    assert!(
        parse(&valid().replace(
            "depends: []\nbase: main",
            "stack-on: https://github.com/carrick-sh/carrick/pull/571\nbase: work/parent"
        ))
        .is_ok()
    );
}

fn comment(login: &str) -> Value {
    json!({"id": 1, "user": {"id": 146447, "login": login}, "created_at": "2026-10-17T00:00:00Z",
        "updated_at": "2026-10-17T00:00:00Z", "lastEditedAt": null, "body": valid()})
}
fn event(label: &str, login: &str) -> Value {
    json!({"id": 2, "event": "labeled", "label": {"name": label}, "actor": {"login": login}})
}

#[test]
fn provenance_requires_current_authorized_labels_and_unedited_order() {
    let owners = BTreeSet::from(["tjfontaine".to_owned()]);
    let permissions = BTreeSet::from(["tjfontaine".to_owned(), "writer".to_owned()]);
    let labels = vec!["ready".into(), "route:infra".into()];
    let comments = vec![comment("tjfontaine")];
    let events = vec![
        event("ready", "tjfontaine"),
        event("route:infra", "tjfontaine"),
    ];
    assert!(validate_provenance(&labels, &comments, &events, &owners, &permissions).is_ok());
    for forged in ["carrick-workers[bot]", "outsider", "writer"] {
        assert!(
            validate_provenance(&labels, &[comment(forged)], &events, &owners, &permissions)
                .is_err()
        );
        let mut history = events.clone();
        history.push(event("ready", forged));
        assert!(validate_provenance(&labels, &comments, &history, &owners, &permissions).is_err());
        history = events.clone();
        history.push(event("route:infra", forged));
        assert!(validate_provenance(&labels, &comments, &history, &owners, &permissions).is_err());

        // Hold-label removal (blocked / needs-owner / stalled) after ready by non-allowlisted actor is refused.
        for hold in ["blocked", "needs-owner", "stalled"] {
            let mut hold_removed = events.clone();
            hold_removed.push(json!({
                "id": 10,
                "event": "unlabeled",
                "label": {"name": hold},
                "actor": {"login": forged}
            }));
            assert!(
                validate_provenance(&labels, &comments, &hold_removed, &owners, &permissions)
                    .is_err(),
                "accepted {hold} removal by {forged}"
            );
        }

        // Issue reopened after ready by non-allowlisted actor is refused.
        let mut reopened = events.clone();
        reopened.push(json!({
            "id": 11,
            "event": "reopened",
            "actor": {"login": forged}
        }));
        assert!(
            validate_provenance(&labels, &comments, &reopened, &owners, &permissions).is_err(),
            "accepted reopen by {forged}"
        );

        // Deletion of a comment after ready by non-allowlisted actor is refused.
        let mut deleted = events.clone();
        deleted.push(json!({
            "id": 12,
            "event": "comment_deleted",
            "actor": {"login": forged}
        }));
        assert!(
            validate_provenance(&labels, &comments, &deleted, &owners, &permissions).is_err(),
            "accepted comment_deleted by {forged}"
        );
    }

    // Allowlisted actor may remove hold labels, reopen, or delete a superseded comment.
    let mut trusted_transitions = events.clone();
    trusted_transitions.push(json!({"id": 20, "event": "unlabeled", "label": {"name": "blocked"}, "actor": {"login": "tjfontaine"}}));
    trusted_transitions
        .push(json!({"id": 21, "event": "reopened", "actor": {"login": "tjfontaine"}}));
    trusted_transitions
        .push(json!({"id": 22, "event": "comment_deleted", "actor": {"login": "tjfontaine"}}));
    assert!(
        validate_provenance(
            &labels,
            &comments,
            &trusted_transitions,
            &owners,
            &permissions
        )
        .is_ok()
    );

    let mut edited = comments.clone();
    edited[0]["updated_at"] = json!("2026-10-17T01:00:00Z");
    assert!(validate_provenance(&labels, &edited, &events, &owners, &permissions).is_err());
    assert!(validate_provenance(&labels, &comments, &events, &owners, &BTreeSet::new()).is_err());
    let mut removed = events.clone();
    removed.push(json!({"event": "unlabeled", "label":{"name":"ready"}}));
    assert!(validate_provenance(&labels, &comments, &removed, &owners, &permissions).is_err());
    for labels in [
        vec!["route:infra".into()],
        vec!["ready".into(), "route:kvm".into()],
        vec!["ready".into(), "route:infra".into(), "route:kvm".into()],
        vec!["ready".into(), "route:infra".into(), "needs-owner".into()],
    ] {
        assert!(validate_provenance(&labels, &comments, &events, &owners, &permissions).is_err());
    }
    // Public or unrelated PR-bus comments are not work-order inputs.
    let mut noise = comments.clone();
    noise.push(json!({"user":{"id": 9, "login":"outsider"}, "body": "work-order v1\nmalicious"}));
    noise.push(
        json!({"user":{"id": 146447, "login":"tjfontaine"}, "body": "/carrick-helper v1\n```json\n{}\n```"}),
    );
    noise.push(
        json!({"user":{"id": 146447, "login":"tjfontaine"}, "body": "work-order v1 lint: **ok**"}),
    );
    assert!(validate_provenance(&labels, &noise, &events, &owners, &permissions).is_ok());
    let mut ambiguous = comments.clone();
    ambiguous.push(comment("tjfontaine"));
    assert!(validate_provenance(&labels, &ambiguous, &events, &owners, &permissions).is_err());
    let mut same_second_edit = comments.clone();
    same_second_edit[0]["lastEditedAt"] = json!("2026-10-17T00:00:00Z");
    assert!(
        validate_provenance(&labels, &same_second_edit, &events, &owners, &permissions).is_err()
    );
}

#[cfg(unix)]
mod serial_host {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    use std::process::Command;

    fn git(root: &Path, args: &[&str]) {
        let out = Command::new("git")
            .current_dir(root)
            .args(args)
            .output()
            .unwrap();
        assert!(out.status.success(), "{out:?}");
    }

    #[test]
    fn serial_host_lint_and_labels_orchestration_over_recorded_github_responses() {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path().join("repo");
        std::fs::create_dir_all(repo.join(".github")).unwrap();
        git(&repo, &["init", "-b", "main"]);
        git(&repo, &["config", "user.name", "Carrick Test"]);
        git(&repo, &["config", "user.email", "test@carrick.sh"]);
        std::fs::write(
            repo.join(".github/pull-claims.toml"),
            "allowlist = [\"tjfontaine\"]\nrepositories = [\"carrick-sh/carrick\", \"carrick-sh/carrick-nt\"]\n",
        )
        .unwrap();
        git(&repo, &["add", ".github/pull-claims.toml"]);
        git(&repo, &["commit", "-m", "add policy"]);
        git(&repo, &["update-ref", "refs/remotes/origin/main", "HEAD"]);

        let bin_dir = dir.path().join("bin");
        std::fs::create_dir(&bin_dir).unwrap();
        let fixture_path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/workorder_github_api.json");
        let log_path = dir.path().join("posted.jsonl");
        let fake_gh = bin_dir.join("gh");
        std::fs::write(
            &fake_gh,
            r#"#!/usr/bin/env python3
import json, os, sys
fixture = json.loads(open(os.environ['WORKORDER_FIXTURE'], encoding='utf-8').read())
args = sys.argv[1:]
method = args[args.index('--method') + 1] if '--method' in args else 'GET'
endpoint = [a for a in args[1:] if not a.startswith('-') and a != method][-1]
paginated = '--paginate' in args
if method == 'GET' and endpoint == 'repos/carrick-sh/carrick/issues/572':
    print(json.dumps(fixture['issue']))
elif method == 'GET' and endpoint == 'repos/carrick-sh/carrick/collaborators/tjfontaine/permission':
    print(json.dumps(fixture['permission']))
elif method == 'GET' and endpoint == 'repos/carrick-sh/carrick/issues/572/comments?per_page=100':
    print(json.dumps([fixture['comments_list']] if paginated else fixture['comments_list']))
elif method == 'GET' and endpoint == 'repos/carrick-sh/carrick/issues/comments/6237219430':
    print(json.dumps(fixture['comment_single']))
elif method == 'GET' and endpoint == 'repos/carrick-sh/carrick/issues/572/events?per_page=100':
    print(json.dumps([fixture['events']] if paginated else fixture['events']))
elif method == 'POST' and endpoint == 'graphql':
    _ = sys.stdin.read()
    print(json.dumps(fixture['graphql_unedited']))
elif method == 'POST' and endpoint == 'repos/carrick-sh/carrick/issues/572/comments':
    body = json.loads(sys.stdin.read())
    with open(os.environ['WORKORDER_LOG'], 'a', encoding='utf-8') as f:
        f.write(json.dumps({'endpoint': endpoint, 'body': body}) + '\n')
    print(json.dumps({'id': 99}))
elif method == 'GET' and endpoint.endswith('/labels?per_page=100'):
    existing = json.loads(os.environ.get('WORKORDER_EXISTING_LABELS', '[]'))
    print(json.dumps([existing]))
elif method in ('POST', 'PATCH') and '/labels' in endpoint:
    body = json.loads(sys.stdin.read())
    with open(os.environ['WORKORDER_LOG'], 'a', encoding='utf-8') as f:
        f.write(json.dumps({'method': method, 'endpoint': endpoint, 'body': body}) + '\n')
    print(json.dumps(body))
else:
    raise SystemExit(f'unexpected gh call: {args}')
"#,
        )
        .unwrap();
        std::fs::set_permissions(&fake_gh, std::fs::Permissions::from_mode(0o755)).unwrap();

        let path_env = std::env::join_paths(
            std::iter::once(bin_dir)
                .chain(std::env::split_paths(&std::env::var_os("PATH").unwrap())),
        )
        .unwrap();

        // Even if the checkout is on a worker branch with a tampered local policy,
        // `lint` reads `.github/pull-claims.toml` from `origin/main`.
        git(&repo, &["checkout", "-b", "work/tampered"]);
        std::fs::write(
            repo.join(".github/pull-claims.toml"),
            "allowlist = [\"outsider\"]\nrepositories = [\"carrick-sh/carrick\"]\n",
        )
        .unwrap();

        let out = Command::new(env!("CARGO_BIN_EXE_carrick-xtask"))
            .arg("--root")
            .arg(&repo)
            .args([
                "workorder",
                "lint",
                "572",
                "--repo",
                "carrick-sh/carrick",
                "--post",
            ])
            .env("PATH", &path_env)
            .env("WORKORDER_FIXTURE", &fixture_path)
            .env("WORKORDER_LOG", &log_path)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "lint failed: stdout={} stderr={}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        let admission: Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(admission["comment_id"], 6237219430_u64);
        let posted = std::fs::read_to_string(&log_path).unwrap();
        assert!(posted.contains("work-order v1 lint: **ok**"), "{posted}");

        // Without `origin/main`, a dirty or non-main checkout is refused.
        git(&repo, &["update-ref", "-d", "refs/remotes/origin/main"]);
        let refused = Command::new(env!("CARGO_BIN_EXE_carrick-xtask"))
            .arg("--root")
            .arg(&repo)
            .args(["workorder", "lint", "572", "--repo", "carrick-sh/carrick"])
            .env("PATH", &path_env)
            .env("WORKORDER_FIXTURE", &fixture_path)
            .env("WORKORDER_LOG", &log_path)
            .output()
            .unwrap();
        assert!(
            !refused.status.success(),
            "dirty non-main policy was accepted"
        );

        // Clean `main` checkout is accepted when `origin/main` is absent.
        git(&repo, &["checkout", "-f", "main"]);
        let clean_main = Command::new(env!("CARGO_BIN_EXE_carrick-xtask"))
            .arg("--root")
            .arg(&repo)
            .args(["workorder", "lint", "572", "--repo", "carrick-sh/carrick"])
            .env("PATH", &path_env)
            .env("WORKORDER_FIXTURE", &fixture_path)
            .env("WORKORDER_LOG", &log_path)
            .output()
            .unwrap();
        assert!(clean_main.status.success(), "{clean_main:?}");

        // Labels subcommand refuses to overwrite differing existing label definitions without --overwrite.
        std::fs::write(&log_path, "").unwrap();
        let conflict = Command::new(env!("CARGO_BIN_EXE_carrick-xtask"))
            .arg("--root")
            .arg(&repo)
            .args(["workorder", "labels"])
            .env("PATH", &path_env)
            .env("WORKORDER_FIXTURE", &fixture_path)
            .env("WORKORDER_LOG", &log_path)
            .env(
                "WORKORDER_EXISTING_LABELS",
                r#"[{"name":"ready","color":"000000","description":"wrong"}]"#,
            )
            .output()
            .unwrap();
        assert!(
            !conflict.status.success(),
            "overwrote existing label without --overwrite"
        );
        assert!(std::fs::read_to_string(&log_path).unwrap().is_empty());

        let overwrite = Command::new(env!("CARGO_BIN_EXE_carrick-xtask"))
            .arg("--root")
            .arg(&repo)
            .args(["workorder", "labels", "--overwrite"])
            .env("PATH", &path_env)
            .env("WORKORDER_FIXTURE", &fixture_path)
            .env("WORKORDER_LOG", &log_path)
            .env(
                "WORKORDER_EXISTING_LABELS",
                r#"[{"name":"ready","color":"000000","description":"wrong"}]"#,
            )
            .output()
            .unwrap();
        assert!(overwrite.status.success(), "{overwrite:?}");
        let log = std::fs::read_to_string(&log_path).unwrap();
        assert!(log.contains("\"method\": \"PATCH\""), "{log}");
        assert!(log.contains("\"method\": \"POST\""), "{log}");
    }
}
