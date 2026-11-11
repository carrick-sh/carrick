//! Known-answer cases for the trusted-step check (#2092).
//!
//! The workflow files under `fixtures/trusted_steps` are verbatim `git show`
//! output from the real heads that lost merge-queue passes on 2026-11-11.

#![allow(clippy::expect_used)]

use carrick_xtask::trusted_steps::{GitTree, Tree, TrustedStepsError, check, check_report};
use std::collections::HashMap;
use std::path::Path;
use std::process::Command;

const BASE_WF: &str = include_str!("fixtures/trusted_steps/base.signed-gate.yml");
const HEAD_2064_WF: &str = include_str!("fixtures/trusted_steps/head-2064.signed-gate.yml");
const HEAD_2061_WF: &str = include_str!("fixtures/trusted_steps/head-2061.signed-gate.yml");
const PREBUILT_SH: &str = include_str!("fixtures/trusted_steps/head-2064.xtask-prebuilt.sh");

/// The part of xtask's clap tree the signed-gate workflow reaches, as it stood
/// on main at 118c67f52 (excerpt of `cli.rs` and `signed_gate.rs`).
const BASE_CLI: &str = r#"
use clap::{Parser, Subcommand};
#[derive(Parser, Debug)]
#[command(name = "carrick-xtask", about = "Carrick xtask maintenance tool")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}
#[derive(Subcommand, Debug)]
pub enum Commands {
    CiReceipt(ReceiptArgs),
    SignedGate(SignedGateArgs),
    Fixtures(FixturesArgs),
}
#[derive(clap::Args, Debug)]
pub struct SignedGateArgs {
    #[command(subcommand)]
    pub action: SignedGateAction,
}
#[derive(clap::Subcommand, Debug)]
pub enum SignedGateAction {
    Prepare { event: PathBuf },
    BaseFixtures { request: PathBuf },
    CandidateProbes { request: PathBuf },
    Execute { request: PathBuf },
    Publish { request: PathBuf },
}
#[derive(clap::Args, Debug)]
pub struct ReceiptArgs {
    #[command(subcommand)]
    pub action: ReceiptAction,
}
#[derive(clap::Subcommand, Debug)]
pub enum ReceiptAction { SelectBaseline {}, Compare {} }
#[derive(clap::Args, Debug)]
pub struct FixturesArgs {
    #[command(subcommand)]
    pub action: FixturesAction,
}
#[derive(clap::Subcommand, Debug)]
pub enum FixturesAction { Fetch {}, Build {} }
"#;

const BASE_JUSTFILE: &str = "set shell := [\"bash\", \"-c\"]\nrepo := \"x\"\n\nbuild ARGS='':\n    cargo build\n\n@xtask +ARGS:\n    cargo run -p carrick-xtask -- {{ARGS}}\n";

#[derive(Default)]
struct MemTree(HashMap<String, HashMap<String, Vec<u8>>>);

impl MemTree {
    fn put(&mut self, rev: &str, path: &str, text: &str) {
        self.0
            .entry(rev.into())
            .or_default()
            .insert(path.into(), text.as_bytes().to_vec());
    }

    /// A base tree with the workflow, clap tree and justfile every case shares.
    fn with_base() -> Self {
        let mut t = Self::default();
        t.put("base", ".github/workflows/signed-gate.yml", BASE_WF);
        t.put("base", "crates/carrick-xtask/src/cli.rs", BASE_CLI);
        t.put("base", "justfile", BASE_JUSTFILE);
        t
    }

    /// The head starts as a copy of the base, as a PR does.
    fn fork_head(mut self) -> Self {
        let base = self.0.get("base").cloned().unwrap_or_default();
        self.0.insert("head".into(), base);
        self
    }
}

impl Tree for MemTree {
    fn read(&self, rev: &str, path: &str) -> Result<Option<Vec<u8>>, TrustedStepsError> {
        Ok(self.0.get(rev).and_then(|t| t.get(path)).cloned())
    }

    fn list(&self, rev: &str, prefix: &str) -> Result<Vec<String>, TrustedStepsError> {
        let mut out: Vec<String> = self
            .0
            .get(rev)
            .map(|t| {
                t.keys()
                    .filter(|p| prefix == "." || p.starts_with(prefix))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();
        out.sort();
        Ok(out)
    }
}

fn messages(tree: &dyn Tree) -> Vec<String> {
    check(tree, "base", "head")
        .expect("check runs")
        .iter()
        .map(ToString::to_string)
        .collect()
}

fn trusted_workflow(run: &str) -> String {
    format!(
        "name: t\non: push\njobs:\n  gate:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: main\n      - name: go\n        run: |\n          {run}\n"
    )
}

#[test]
fn unchanged_workflow_passes() {
    let tree = MemTree::with_base().fork_head();
    assert_eq!(messages(&tree), Vec::<String>::new());
}

#[test]
fn pr_2064_original_head_names_the_added_script() {
    let mut tree = MemTree::with_base().fork_head();
    tree.put("head", ".github/workflows/signed-gate.yml", HEAD_2064_WF);
    tree.put("head", "scripts/ci/xtask-prebuilt.sh", PREBUILT_SH);
    let msgs = messages(&tree);
    assert!(
        msgs.iter()
            .any(|m| m.contains("scripts/ci/xtask-prebuilt.sh")
                && m.contains("trusted step authorize/Build carrick-xtask once for this run")
                && m.contains("land it first in a separate PR (#2092)")),
        "{msgs:#?}"
    );
    // Only the added script is at fault: every xtask subcommand it runs exists.
    assert!(
        msgs.iter().all(|m| m.contains("xtask-prebuilt.sh")),
        "{msgs:#?}"
    );
}

#[test]
fn pr_2061_head_names_the_added_subcommand() {
    let mut tree = MemTree::with_base().fork_head();
    tree.put("head", ".github/workflows/signed-gate.yml", HEAD_2061_WF);
    let msgs = messages(&tree);
    assert!(
        msgs.iter().any(|m| m.contains("reuse-lookup")
            && m.contains("trusted step gate/Look up reusable sealed base receipt")),
        "{msgs:#?}"
    );
    assert!(
        msgs.iter().any(|m| m.contains("prepare-reuse-upload")),
        "{msgs:#?}"
    );
}

#[test]
fn landing_the_subcommand_first_passes() {
    let mut tree = MemTree::with_base().fork_head();
    tree.put("head", ".github/workflows/signed-gate.yml", HEAD_2061_WF);
    // The same head once the base already has the new subcommands.
    let cli = BASE_CLI.replace(
        "Publish { request: PathBuf },",
        "Publish { request: PathBuf }, ReuseLookup {}, PrepareReuseUpload {},",
    );
    tree.put("base", "crates/carrick-xtask/src/cli.rs", &cli);
    assert_eq!(messages(&tree), Vec::<String>::new());
}

#[test]
fn absent_script_and_missing_recipe_are_refused_but_untrusted_steps_are_not() {
    let run = "scripts/ci/a.sh --x\n          just nope\n          just build\n          just xtask signed-gate bogus";
    let mut tree = MemTree::with_base().fork_head();
    tree.put("head", "scripts/ci/a.sh", "new");
    tree.put("head", ".github/workflows/t.yml", &trusted_workflow(run));
    let msgs = messages(&tree);
    assert_eq!(msgs.len(), 3, "{msgs:#?}");
    assert!(msgs.iter().any(|m| m.contains("runs scripts/ci/a.sh,")));
    assert!(msgs.iter().any(|m| m.contains("just recipe nope")));
    assert!(
        msgs.iter()
            .any(|m| m.contains("carrick-xtask signed-gate bogus"))
    );

    // The same steps after a checkout of the PR's own merge ref are fine.
    let untrusted = trusted_workflow(run).replace("ref: main", "ref: ${{ github.sha }}");
    tree.put("head", ".github/workflows/t.yml", &untrusted);
    assert_eq!(messages(&tree), Vec::<String>::new());
}

/// The merge group runs base's tree, so editing a script base already has is
/// not a failure: it warns that base's copy runs until the PR lands.
#[test]
fn changed_existing_script_warns_without_failing() {
    let mut tree = MemTree::with_base().fork_head();
    tree.put("base", "scripts/ci/a.sh", "old");
    tree.put("head", "scripts/ci/a.sh", "new");
    tree.put(
        "head",
        ".github/workflows/t.yml",
        &trusted_workflow("scripts/ci/a.sh --x"),
    );
    let report = check_report(&tree, "base", "head").expect("check runs");
    assert_eq!(report.violations, vec![]);
    assert_eq!(report.warnings.len(), 1, "{:?}", report.warnings);
    assert_eq!(
        report.warnings[0].to_string(),
        "trusted step gate/go will run base's copy of scripts/ci/a.sh until this PR lands"
    );
}

/// After #2091 and #2064 land, a PR that edits only `xtask-prebuilt.sh` must
/// pass (with warnings), not demand the separate PR it already is.
#[test]
fn editing_only_a_script_trusted_steps_already_run_passes_with_warnings() {
    let mut tree = MemTree::with_base();
    tree.put("base", ".github/workflows/signed-gate.yml", HEAD_2064_WF);
    tree.put("base", "scripts/ci/xtask-prebuilt.sh", PREBUILT_SH);
    let mut tree = tree.fork_head();
    tree.put(
        "head",
        "scripts/ci/xtask-prebuilt.sh",
        &format!("{PREBUILT_SH}\n# comment only\n"),
    );
    let report = check_report(&tree, "base", "head").expect("check runs");
    assert_eq!(report.violations, vec![], "{:?}", report.violations);
    assert!(
        report
            .warnings
            .iter()
            .any(|w| w.path == "scripts/ci/xtask-prebuilt.sh"),
        "{:?}",
        report.warnings
    );
}

/// A workflow with a trusted checkout at `selector` and `baseline` and no
/// checkout at the workspace root, like the `ci-receipt gate` steps.
fn two_checkout_workflow(working_directory: &str, run: &str) -> String {
    format!(
        "name: t\non: push\njobs:\n  gate:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          path: selector\n          ref: main\n      - uses: actions/checkout@v4\n        with:\n          path: baseline\n          ref: ${{{{ steps.select.outputs.base_sha }}}}\n      - name: gate\n        working-directory: {working_directory}\n        run: |\n          {run}\n"
    )
}

#[test]
fn expression_working_directory_is_not_skipped() {
    for wd in [
        "${{ steps.select.outputs.source == 'main' && 'selector' || 'baseline' }}",
        "${{ inputs.dir }}",
    ] {
        let mut tree = MemTree::with_base().fork_head();
        tree.put(
            "head",
            ".github/workflows/t.yml",
            &two_checkout_workflow(wd, "target/release/carrick-xtask signed-gate brand-new"),
        );
        let msgs = messages(&tree);
        assert!(
            msgs.iter()
                .any(|m| m.contains("carrick-xtask signed-gate brand-new")),
            "{wd}: {msgs:#?}"
        );
        // The same step with a subcommand base has passes.
        tree.put(
            "head",
            ".github/workflows/t.yml",
            &two_checkout_workflow(wd, "target/release/carrick-xtask signed-gate execute"),
        );
        assert_eq!(messages(&tree), Vec::<String>::new(), "{wd}");
    }
}

#[test]
fn expression_working_directory_naming_only_untrusted_checkouts_is_skipped() {
    let mut tree = MemTree::with_base().fork_head();
    let wf = two_checkout_workflow(
        "${{ x && 'pr' || 'pr2' }}",
        "target/release/carrick-xtask signed-gate brand-new",
    )
    .replace("path: selector", "path: pr")
    .replace("path: baseline", "path: pr2")
    .replace("ref: main", "ref: ${{ github.sha }}")
    .replace(
        "ref: ${{ steps.select.outputs.base_sha }}",
        "ref: ${{ github.sha }}",
    );
    tree.put("head", ".github/workflows/t.yml", &wf);
    assert_eq!(messages(&tree), Vec::<String>::new());
}

/// Each invocation shape the first review found slipping through.
#[test]
fn invocation_shapes_that_once_slipped_through_are_refused() {
    let shapes = [
        "cargo run -p carrick-xtask --locked -- signed-gate brand-new",
        "cargo run --locked -p carrick-xtask --features smoke-signed -- signed-gate brand-new",
        "cargo run --package carrick-xtask -- signed-gate brand-new",
        "cargo run --package=carrick-xtask -- signed-gate brand-new",
        "target/release/carrick-xtask --root . signed-gate brand-new",
        "\"$CARRICK_XTASK_BIN\" --root \"$GITHUB_WORKSPACE\" signed-gate brand-new",
        "cargo build --locked --release -p carrick-xtask && target/release/carrick-xtask signed-gate brand-new",
        "if test -x target/release/carrick-xtask; then target/release/carrick-xtask signed-gate brand-new; fi",
        "if true; then\n          :\n          else target/release/carrick-xtask signed-gate brand-new\n          fi",
        "for i in 1; do target/release/carrick-xtask signed-gate brand-new; done",
        "FOO=1 target/release/carrick-xtask signed-gate brand-new",
        "FOO=1 BAR=2 $CARRICK_XTASK_BIN signed-gate brand-new",
        "FOO=1 just xtask signed-gate brand-new",
        "CARRICK_DISK_FLOOR_GIB=35 just brand-new",
        "FOO=1 scripts/ci/added.sh",
        "FOO=1 bash scripts/ci/added.sh",
    ];
    for shape in shapes {
        let mut tree = MemTree::with_base().fork_head();
        tree.put("head", "scripts/ci/added.sh", "new");
        tree.put(
            "head",
            ".github/workflows/t.yml",
            &trusted_workflow(&shape.replace('\n', "\n          ")),
        );
        let msgs = messages(&tree);
        assert_eq!(msgs.len(), 1, "{shape}: {msgs:#?}");
        assert!(
            msgs[0].contains("brand-new") || msgs[0].contains("added.sh"),
            "{shape}: {msgs:#?}"
        );
    }
}

#[test]
fn folded_scalar_run_is_analyzed() {
    let wf = "name: t\non: push\njobs:\n  gate:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: main\n      - name: go\n        run: >-\n          cargo build --locked --release -p carrick-xtask &&\n          target/release/carrick-xtask signed-gate brand-new\n";
    let mut tree = MemTree::with_base().fork_head();
    tree.put("head", ".github/workflows/t.yml", wf);
    let msgs = messages(&tree);
    assert_eq!(msgs.len(), 1, "{msgs:#?}");
    assert!(msgs[0].contains("signed-gate brand-new"));
}

#[test]
fn cargo_build_of_xtask_is_not_an_invocation() {
    let mut tree = MemTree::with_base().fork_head();
    tree.put(
        "head",
        ".github/workflows/t.yml",
        &trusted_workflow("cargo build --locked -p carrick-xtask brand-new"),
    );
    assert_eq!(messages(&tree), Vec::<String>::new());
}

#[test]
fn identical_script_passes_and_positional_arguments_are_not_subcommands() {
    let mut tree = MemTree::with_base().fork_head();
    tree.put("base", "scripts/ci/a.sh", "same");
    tree.put("head", "scripts/ci/a.sh", "same");
    tree.put(
        "head",
        ".github/workflows/t.yml",
        &trusted_workflow("bash scripts/ci/a.sh\n          cargo run -p carrick-xtask -- signed-gate execute --request r"),
    );
    assert_eq!(messages(&tree), Vec::<String>::new());
}

/// #2091's shape: the PR adds the script and wires it only into untrusted PR CI.
#[test]
fn pr_2091_shape_adds_script_behind_an_untrusted_checkout_and_passes() {
    let mut tree = MemTree::with_base().fork_head();
    tree.put("head", "scripts/ci/xtask-prebuilt.sh", PREBUILT_SH);
    let wf = trusted_workflow("scripts/ci/xtask-prebuilt.sh verify out")
        .replace("ref: main", "persist-credentials: false");
    tree.put("head", ".github/workflows/ci.yml", &wf);
    assert_eq!(messages(&tree), Vec::<String>::new());
}

fn git(dir: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .env("GIT_AUTHOR_NAME", "t")
        .env("GIT_AUTHOR_EMAIL", "t@example.com")
        .env("GIT_COMMITTER_NAME", "t")
        .env("GIT_COMMITTER_EMAIL", "t@example.com")
        .output()
        .expect("git runs");
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_owned()
}

#[test]
fn real_git_repository_added_script_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    git(root, &["init", "-q", "-b", "main"]);
    for (path, text) in [
        (".github/workflows/signed-gate.yml", BASE_WF),
        ("crates/carrick-xtask/src/cli.rs", BASE_CLI),
        ("justfile", BASE_JUSTFILE),
    ] {
        let full = root.join(path);
        std::fs::create_dir_all(full.parent().expect("parent")).expect("mkdir");
        std::fs::write(full, text).expect("write");
    }
    git(root, &["add", "."]);
    git(root, &["commit", "-q", "-m", "base"]);
    let base = git(root, &["rev-parse", "HEAD"]);
    std::fs::create_dir_all(root.join("scripts/ci")).expect("mkdir");
    std::fs::write(root.join("scripts/ci/xtask-prebuilt.sh"), PREBUILT_SH).expect("write");
    std::fs::write(root.join(".github/workflows/signed-gate.yml"), HEAD_2064_WF).expect("write");
    git(root, &["add", "."]);
    git(root, &["commit", "-q", "-m", "head"]);
    let tree = GitTree::new(root);
    let found = check(&tree, &base, "HEAD").expect("check runs");
    assert!(
        found
            .iter()
            .any(|v| v.thing == "scripts/ci/xtask-prebuilt.sh"),
        "{found:?}"
    );
    assert_eq!(check(&tree, "HEAD", "HEAD").expect("check runs"), vec![]);
}

/// Current main (this checkout) must pass against itself: every xtask
/// subcommand and `just` recipe its trusted steps invoke resolves in the real
/// clap tree and justfile.
#[test]
fn current_tree_passes_against_itself() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let tree = GitTree::new(&root);
    assert_eq!(check(&tree, "HEAD", "HEAD").expect("check runs"), vec![]);
}
