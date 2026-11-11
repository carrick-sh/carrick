//! Refuse a trusted-ref workflow step that runs something the same PR adds (#2092).
//!
//! A job whose `actions/checkout` pins a trusted ref (`main`, a base SHA)
//! runs the *merge base's* tree, not the PR's. A PR that adds a script, an
//! xtask subcommand or a `just` recipe and wires a trusted step to it passes PR
//! CI, then fails in the merge queue because the trusted tree lacks the new
//! thing (three queue passes lost on 2026-11-11: #2064 once, #2061 twice).
//!
//! The check reads the head workflows and compares what their trusted `run:`
//! steps execute with the merge base's tree, using `git show`/`git ls-tree`
//! only: the base's clap definitions are parsed statically with `syn`, the base
//! `justfile` by its recipe headers. Nothing is built.

use clap::Args;
use regex::Regex;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use thiserror::Error;
use yaml_rust2::{Yaml, YamlLoader};

#[derive(Args, Debug, Clone)]
pub struct TrustedStepsArgs {
    /// The PR's merge base (the tree trusted steps will actually run).
    #[arg(long)]
    pub base: String,
    /// The PR head whose workflows are checked.
    #[arg(long, default_value = "HEAD")]
    pub head: String,
}

#[derive(Debug, Error)]
pub enum TrustedStepsError {
    #[error("git {args}: {detail}")]
    Git { args: String, detail: String },
    #[error("{path} at {rev}: {detail}")]
    Parse {
        rev: String,
        path: String,
        detail: String,
    },
    #[error("{0}")]
    Violations(String),
    #[error("write: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Violation {
    pub job: String,
    pub step: String,
    pub thing: String,
}

impl std::fmt::Display for Violation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "trusted step {}/{} runs {}, which the merge base lacks; land it first in a separate PR (#2092)",
            self.job, self.step, self.thing
        )
    }
}

/// Read access to two trees of one repository.
pub trait Tree {
    fn read(&self, rev: &str, path: &str) -> Result<Option<Vec<u8>>, TrustedStepsError>;
    /// Every file path under `prefix` at `rev`.
    fn list(&self, rev: &str, prefix: &str) -> Result<Vec<String>, TrustedStepsError>;
}

pub struct GitTree {
    root: PathBuf,
}

impl GitTree {
    pub fn new(root: &Path) -> Self {
        Self {
            root: root.to_path_buf(),
        }
    }

    fn git(&self, args: &[&str]) -> Result<std::process::Output, TrustedStepsError> {
        Command::new("git")
            .arg("-C")
            .arg(&self.root)
            .args(args)
            .output()
            .map_err(|e| TrustedStepsError::Git {
                args: args.join(" "),
                detail: e.to_string(),
            })
    }
}

impl Tree for GitTree {
    fn read(&self, rev: &str, path: &str) -> Result<Option<Vec<u8>>, TrustedStepsError> {
        let spec = format!("{rev}:{path}");
        let out = self.git(&["cat-file", "blob", &spec])?;
        if out.status.success() {
            return Ok(Some(out.stdout));
        }
        // Distinguish "absent at this rev" from a bad rev.
        let probe = self.git(&[
            "rev-parse",
            "--verify",
            "--quiet",
            &format!("{rev}^{{tree}}"),
        ])?;
        if !probe.status.success() {
            return Err(TrustedStepsError::Git {
                args: format!("cat-file blob {spec}"),
                detail: format!("unknown revision {rev}"),
            });
        }
        Ok(None)
    }

    fn list(&self, rev: &str, prefix: &str) -> Result<Vec<String>, TrustedStepsError> {
        let out = self.git(&["ls-tree", "-r", "--name-only", rev, "--", prefix])?;
        if !out.status.success() {
            return Err(TrustedStepsError::Git {
                args: format!("ls-tree -r {rev} -- {prefix}"),
                detail: String::from_utf8_lossy(&out.stderr).into_owned(),
            });
        }
        Ok(String::from_utf8_lossy(&out.stdout)
            .lines()
            .map(str::to_owned)
            .collect())
    }
}

pub fn run<W: Write>(
    root: &Path,
    args: &TrustedStepsArgs,
    writer: &mut W,
) -> Result<(), TrustedStepsError> {
    let report = check_report(&GitTree::new(root), &args.base, &args.head)?;
    for warning in &report.warnings {
        writeln!(writer, "warning: {warning}")?;
    }
    if report.violations.is_empty() {
        writeln!(writer, "trusted-steps: ok")?;
        return Ok(());
    }
    let text: Vec<String> = report.violations.iter().map(ToString::to_string).collect();
    Err(TrustedStepsError::Violations(text.join("\n")))
}

/// What the check found: `violations` fail the merge group, `warnings` do not.
#[derive(Debug, Default)]
pub struct Report {
    pub violations: Vec<Violation>,
    pub warnings: Vec<Warning>,
}

/// A trusted step that references something present on the merge base whose
/// content differs on head. The merge group runs base's copy until the PR lands.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Warning {
    pub job: String,
    pub step: String,
    pub path: String,
}

impl std::fmt::Display for Warning {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "trusted step {}/{} will run base's copy of {} until this PR lands",
            self.job, self.step, self.path
        )
    }
}

#[derive(Default)]
struct Found {
    violations: BTreeSet<Violation>,
    warnings: BTreeSet<Warning>,
}

/// Only what fails the merge group; see [`check_report`] for warnings.
pub fn check(tree: &dyn Tree, base: &str, head: &str) -> Result<Vec<Violation>, TrustedStepsError> {
    Ok(check_report(tree, base, head)?.violations)
}

pub fn check_report(tree: &dyn Tree, base: &str, head: &str) -> Result<Report, TrustedStepsError> {
    let base_cli = ClapModel::load(tree, base)?;
    let base_recipes = justfile_recipes(tree, base)?;
    let head_files: HashSet<String> = tree.list(head, ".")?.into_iter().collect();
    let mut found = Found::default();
    for wf in tree.list(head, ".github/workflows")? {
        if !(wf.ends_with(".yml") || wf.ends_with(".yaml")) {
            continue;
        }
        let Some(bytes) = tree.read(head, &wf)? else {
            continue;
        };
        let text = String::from_utf8_lossy(&bytes);
        let docs = YamlLoader::load_from_str(&text).map_err(|e| TrustedStepsError::Parse {
            rev: head.into(),
            path: wf.clone(),
            detail: e.to_string(),
        })?;
        for doc in &docs {
            let Some(jobs) = doc["jobs"].as_hash() else {
                continue;
            };
            for (job_id, job) in jobs {
                let job_id = job_id.as_str().unwrap_or("?");
                check_job(
                    job_id,
                    job,
                    &Ctx {
                        tree,
                        base,
                        head,
                        head_files: &head_files,
                        cli: &base_cli,
                        recipes: &base_recipes,
                    },
                    &mut found,
                )?;
            }
        }
    }
    Ok(Report {
        violations: found.violations.into_iter().collect(),
        warnings: found.warnings.into_iter().collect(),
    })
}

struct Ctx<'a> {
    tree: &'a dyn Tree,
    base: &'a str,
    head: &'a str,
    head_files: &'a HashSet<String>,
    cli: &'a ClapModel,
    recipes: &'a HashSet<String>,
}

fn is_trusted_ref(r: &str) -> bool {
    let r = r.trim();
    r == "main"
        || r == "refs/heads/main"
        || [
            "base_sha",
            "base.sha",
            "event.before",
            "merge_group.base",
            "baseline",
        ]
        .iter()
        .any(|k| r.contains(k))
}

fn norm_dir(p: &str) -> String {
    let p = p.trim().trim_start_matches("./").trim_end_matches('/');
    if p.is_empty() { ".".into() } else { p.into() }
}

/// Checkout directories a step's `working-directory:` may name. A literal is
/// itself; an expression yields its quoted literals, or, when none can be read,
/// every checkout (fail closed: never skip a step we cannot resolve).
fn step_dirs(wd: Option<&str>, trust: &HashMap<String, bool>) -> Vec<String> {
    let Some(wd) = wd else {
        return vec![".".into()];
    };
    if !wd.contains("${{") {
        return vec![norm_dir(wd)];
    }
    let lit = Regex::new(r"'([^']*)'").ok();
    let mut dirs: Vec<String> = lit
        .iter()
        .flat_map(|re| re.captures_iter(wd).map(|c| norm_dir(&c[1])))
        .collect();
    if dirs.is_empty() {
        dirs = trust.keys().cloned().collect();
        dirs.push(".".into());
    }
    dirs
}

/// Whether a step running in `dir` sees a trusted checkout.
fn dir_trusted(dir: &str, trust: &HashMap<String, bool>) -> bool {
    if let Some(t) = trust.get(dir) {
        return *t;
    }
    // A subdirectory of a checkout, else the workspace-root checkout.
    trust
        .iter()
        .filter(|(k, _)| k.as_str() != "." && dir.starts_with(&format!("{k}/")))
        .map(|(_, t)| *t)
        .next()
        .or_else(|| trust.get(".").copied())
        .unwrap_or(false)
}

fn check_job(
    job_id: &str,
    job: &Yaml,
    ctx: &Ctx<'_>,
    found: &mut Found,
) -> Result<(), TrustedStepsError> {
    let Some(steps) = job["steps"].as_vec() else {
        return Ok(());
    };
    // Checkout directory -> whether it holds a trusted ref.
    let mut trust: HashMap<String, bool> = HashMap::new();
    for (idx, step) in steps.iter().enumerate() {
        let uses = step["uses"].as_str().unwrap_or("");
        if uses.starts_with("actions/checkout") {
            let dir = norm_dir(step["with"]["path"].as_str().unwrap_or("."));
            let trusted = step["with"]["ref"].as_str().is_some_and(is_trusted_ref);
            trust.insert(dir, trusted);
            continue;
        }
        let in_trusted = step_dirs(step["working-directory"].as_str(), &trust)
            .iter()
            .any(|d| dir_trusted(d, &trust));
        if !in_trusted {
            continue;
        }
        let label = step["name"]
            .as_str()
            .map(str::to_owned)
            .or_else(|| (!uses.is_empty()).then(|| uses.to_owned()))
            .unwrap_or_else(|| format!("step {}", idx + 1));
        let mut things = Findings::default();
        if let Some(dir) = uses.strip_prefix("./") {
            for path in ctx.tree.list(ctx.head, dir)? {
                things.path(ctx, &path)?;
            }
        }
        if let Some(script) = step["run"].as_str() {
            analyze_script(script, ctx, &mut things)?;
        }
        for thing in things.fail {
            found.violations.insert(Violation {
                job: job_id.into(),
                step: label.clone(),
                thing,
            });
        }
        for path in things.warn {
            found.warnings.insert(Warning {
                job: job_id.into(),
                step: label.clone(),
                path,
            });
        }
    }
    Ok(())
}

/// What one step references that the merge base lacks (`fail`) or has with
/// other content (`warn`).
#[derive(Default)]
struct Findings {
    fail: Vec<String>,
    warn: Vec<String>,
}

impl Findings {
    /// A repository file the step runs: absent on base fails, changed warns.
    fn path(&mut self, ctx: &Ctx<'_>, path: &str) -> Result<(), TrustedStepsError> {
        let on_base = ctx.tree.read(ctx.base, path)?;
        if on_base.is_none() {
            self.fail.push(path.to_owned());
        } else if on_base != ctx.tree.read(ctx.head, path)? {
            self.warn.push(path.to_owned());
        }
        Ok(())
    }
}

fn is_word(w: &str) -> bool {
    let mut cs = w.chars();
    cs.next()
        .is_some_and(|c| c.is_ascii_lowercase() || c == '_')
        && cs.all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

fn unquote(t: &str) -> &str {
    t.trim_matches(|c| c == '"' || c == '\'')
}

/// The subcommand words that follow the xtask binary, past its global
/// `--root`, up to the first flag, quote or expansion.
fn xtask_words(toks: &[&str]) -> Vec<String> {
    let mut it = toks.iter().copied().peekable();
    let mut words = Vec::new();
    while let Some(t) = it.peek().copied() {
        if t == "--root" {
            it.next();
            it.next();
        } else if t.starts_with("--root=") {
            it.next();
        } else if is_word(t) {
            words.push(t.to_owned());
            it.next();
        } else {
            break;
        }
    }
    words
}

/// Simple commands of a shell script: split on separators, drop comments.
fn split_commands(script: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in script.replace("\\\n", " ").lines() {
        let line = line.trim_start();
        if line.starts_with('#') {
            continue;
        }
        let line = line.split(" #").next().unwrap_or(line);
        out.extend(
            line.split([';', '&', '|', '(', ')', '`', '{', '}'])
                .map(|c| c.trim().to_owned())
                .filter(|c| !c.is_empty()),
        );
    }
    out
}

fn is_assignment(t: &str) -> Option<&str> {
    let (name, _) = t.split_once('=')?;
    let mut cs = name.chars();
    (cs.next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && cs.all(|c| c.is_ascii_alphanumeric() || c == '_'))
    .then_some(name)
}

fn analyze_script(
    script: &str,
    ctx: &Ctx<'_>,
    out: &mut Findings,
) -> Result<(), TrustedStepsError> {
    let ws = Regex::new(r"\$\{\{\s*github\.workspace\s*\}\}").map_err(regex_err)?;
    let text = ws.replace_all(script, "$$GITHUB_WORKSPACE");
    let commands = split_commands(&text);

    // Variables standing for the xtask binary.
    let mut aliases: HashSet<String> = ["CARRICK_XTASK_PREBUILT", "CARRICK_XTASK_BIN"]
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
    for c in &commands {
        for t in c.split_whitespace() {
            if let Some(name) = is_assignment(t)
                && (t.contains("carrick-xtask")
                    || t.contains("XTASK_PREBUILT")
                    || t.contains("XTASK_BIN"))
            {
                aliases.insert(name.to_owned());
            }
        }
    }

    let mut invocations: Vec<Vec<String>> = Vec::new();
    let mut seen = HashSet::new();
    for cmd in &commands {
        let all: Vec<&str> = cmd.split_whitespace().collect();
        let mut i = 0;
        // Leading keywords, wrappers and `VAR=val` prefixes.
        while i < all.len() {
            let t = all[i];
            if matches!(
                t,
                "then"
                    | "else"
                    | "do"
                    | "if"
                    | "elif"
                    | "while"
                    | "until"
                    | "!"
                    | "time"
                    | "exec"
                    | "nohup"
                    | "command"
                    | "export"
            ) || is_assignment(t).is_some()
            {
                i += 1;
            } else if matches!(t, "sudo" | "env") {
                i += 1;
                while all.get(i).is_some_and(|f| f.starts_with('-')) {
                    i += 1;
                }
            } else {
                break;
            }
        }
        let Some(&first) = all.get(i) else { continue };
        let mut rest = &all[i + 1..];
        let mut head = unquote(first);
        // Interpreters: the first non-flag argument is the script.
        if matches!(head, "bash" | "sh" | "python" | "python3" | "source" | ".") {
            let n = rest.iter().take_while(|t| t.starts_with('-')).count();
            let Some(&script) = rest.get(n) else { continue };
            head = unquote(script);
            rest = &[];
        }
        if head == "just" {
            let mut toks = rest.iter().copied();
            let mut recipe = None;
            while let Some(t) = toks.next() {
                if matches!(
                    t,
                    "--justfile" | "-f" | "--working-directory" | "-d" | "--set"
                ) {
                    toks.next();
                } else if t.starts_with('-') {
                    continue;
                } else {
                    recipe = Some(t.to_owned());
                    break;
                }
            }
            let Some(recipe) = recipe else { continue };
            if !is_word(&recipe) {
                continue;
            }
            if !ctx.recipes.contains(&recipe) {
                out.fail.push(format!("just recipe {recipe}"));
            } else if recipe == "xtask" {
                invocations.push(xtask_words(&toks.collect::<Vec<_>>()));
            }
        } else if head == "cargo" {
            let sub = rest
                .iter()
                .copied()
                .find(|t| !t.starts_with('-') && !t.starts_with('+'));
            if sub != Some("run") {
                continue;
            }
            let (flags, args) = match rest.iter().position(|t| *t == "--") {
                Some(p) => (&rest[..p], &rest[p + 1..]),
                None => (rest, &rest[rest.len()..]),
            };
            let names_xtask = flags.windows(2).any(|w| {
                matches!(w[0], "-p" | "--package" | "--bin") && unquote(w[1]) == "carrick-xtask"
            }) || flags.iter().any(|t| {
                matches!(
                    *t,
                    "--package=carrick-xtask" | "--bin=carrick-xtask" | "-pcarrick-xtask"
                )
            });
            if names_xtask {
                invocations.push(xtask_words(args));
            }
        } else if head.ends_with("carrick-xtask") {
            invocations.push(xtask_words(rest));
        } else if let Some(var) = head
            .strip_prefix("${")
            .and_then(|v| v.strip_suffix('}'))
            .or_else(|| head.strip_prefix('$'))
            && aliases.contains(var)
        {
            invocations.push(xtask_words(rest));
        } else {
            let path = ["$GITHUB_WORKSPACE/", "${GITHUB_WORKSPACE}/", "./"]
                .iter()
                .fold(head, |p, pre| p.strip_prefix(pre).unwrap_or(p));
            if ctx.head_files.contains(path) && seen.insert(path.to_owned()) {
                out.path(ctx, path)?;
            }
        }
    }

    for words in invocations {
        if let Some(missing) = ctx.cli.first_missing(&words) {
            out.fail.push(format!("carrick-xtask {missing}"));
        }
    }
    Ok(())
}

fn regex_err(e: regex::Error) -> TrustedStepsError {
    TrustedStepsError::Parse {
        rev: String::new(),
        path: "regex".into(),
        detail: e.to_string(),
    }
}

/// Recipe and alias names defined by the justfile at `rev`.
fn justfile_recipes(tree: &dyn Tree, rev: &str) -> Result<HashSet<String>, TrustedStepsError> {
    let Some(bytes) = tree.read(rev, "justfile")? else {
        return Ok(HashSet::new());
    };
    let text = String::from_utf8_lossy(&bytes);
    let recipe = Regex::new(r"(?m)^@?([A-Za-z_][A-Za-z0-9_-]*)(?:[ \t]+[^:\n]*)?:(?:[^=\n]|$)")
        .map_err(regex_err)?;
    let alias =
        Regex::new(r"(?m)^alias[ \t]+([A-Za-z_][A-Za-z0-9_-]*)[ \t]*:=").map_err(regex_err)?;
    let mut out: HashSet<String> = recipe
        .captures_iter(&text)
        .map(|c| c[1].to_owned())
        .collect();
    out.extend(alias.captures_iter(&text).map(|c| c[1].to_owned()));
    Ok(out)
}

/// One subcommand: the names clap accepts and the enum it nests, if any.
#[derive(Debug)]
struct VariantInfo {
    names: Vec<String>,
    child: Option<String>,
}

/// The subcommand tree declared by `#[derive(Subcommand)]` enums.
#[derive(Debug, Default)]
pub struct ClapModel {
    /// Enum name -> (accepted names, child enum if the variant nests one).
    enums: HashMap<String, Vec<VariantInfo>>,
    root: Option<String>,
}

impl ClapModel {
    pub fn load(tree: &dyn Tree, rev: &str) -> Result<Self, TrustedStepsError> {
        let mut sources = Vec::new();
        for path in tree.list(rev, "crates/carrick-xtask/src")? {
            if !path.ends_with(".rs") {
                continue;
            }
            if let Some(bytes) = tree.read(rev, &path)? {
                sources.push((path, String::from_utf8_lossy(&bytes).into_owned()));
            }
        }
        Self::parse(rev, &sources)
    }

    pub fn parse(rev: &str, sources: &[(String, String)]) -> Result<Self, TrustedStepsError> {
        let mut raw_enums: Vec<syn::ItemEnum> = Vec::new();
        // Args/Parser struct name -> the subcommand enum it nests.
        let mut structs: HashMap<String, String> = HashMap::new();
        let mut root_struct = None;
        for (path, src) in sources {
            let file = syn::parse_file(src).map_err(|e| TrustedStepsError::Parse {
                rev: rev.into(),
                path: path.clone(),
                detail: e.to_string(),
            })?;
            collect_items(&file.items, &mut raw_enums, &mut structs, &mut root_struct);
        }
        let mut model = ClapModel::default();
        for e in raw_enums.iter().filter(|e| derives(&e.attrs, "Subcommand")) {
            let variants: Vec<VariantInfo> = e
                .variants
                .iter()
                .map(|v| {
                    let mut names = variant_names(v);
                    names.sort();
                    let child = variant_child(v, &structs);
                    VariantInfo { names, child }
                })
                .collect();
            // Same-named enums in different modules merge: permissive, never a
            // false "missing".
            model
                .enums
                .entry(e.ident.to_string())
                .or_default()
                .extend(variants);
        }
        model.root = root_struct.and_then(|s| structs.get(&s).cloned());
        Ok(model)
    }

    /// The path up to and including the first word that is not a subcommand at
    /// its level, or `None` when every word resolves (or nests no further).
    pub fn first_missing(&self, words: &[String]) -> Option<String> {
        let mut cur = self.root.as_ref()?;
        let mut path: Vec<&str> = Vec::new();
        for w in words {
            let variants = self.enums.get(cur)?;
            path.push(w);
            let Some(variant) = variants.iter().find(|v| v.names.contains(w)) else {
                return Some(path.join(" "));
            };
            match &variant.child {
                Some(c) if self.enums.contains_key(c) => cur = c,
                _ => return None,
            }
        }
        None
    }
}

fn collect_items(
    items: &[syn::Item],
    enums: &mut Vec<syn::ItemEnum>,
    structs: &mut HashMap<String, String>,
    root_struct: &mut Option<String>,
) {
    for item in items {
        match item {
            syn::Item::Enum(e) => enums.push(e.clone()),
            syn::Item::Struct(s) => {
                if let Some(child) = s.fields.iter().find_map(subcommand_field) {
                    structs.insert(s.ident.to_string(), child);
                    if derives(&s.attrs, "Parser") && names_xtask(&s.attrs) {
                        *root_struct = Some(s.ident.to_string());
                    }
                }
            }
            syn::Item::Mod(m) => {
                if let Some((_, inner)) = &m.content {
                    collect_items(inner, enums, structs, root_struct);
                }
            }
            _ => {}
        }
    }
}

fn derives(attrs: &[syn::Attribute], name: &str) -> bool {
    attrs.iter().any(|a| {
        a.path().is_ident("derive")
            && a.parse_nested_meta(|m| {
                if m.path.segments.last().is_some_and(|s| s.ident == name) {
                    Err(m.error("found"))
                } else {
                    Ok(())
                }
            })
            .is_err()
    })
}

fn names_xtask(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|a| {
        a.path().is_ident("command")
            && a.meta
                .require_list()
                .is_ok_and(|l| l.tokens.to_string().contains("\"carrick-xtask\""))
    })
}

fn has_subcommand_attr(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|a| {
        (a.path().is_ident("command") || a.path().is_ident("clap"))
            && a.meta.require_list().is_ok_and(|l| {
                l.tokens
                    .to_string()
                    .split(',')
                    .any(|t| t.trim() == "subcommand")
            })
    })
}

fn type_ident(ty: &syn::Type) -> Option<String> {
    match ty {
        syn::Type::Path(p) => {
            let seg = p.path.segments.last()?;
            // `Option<Enum>` nests the enum too.
            if seg.ident == "Option"
                && let syn::PathArguments::AngleBracketed(a) = &seg.arguments
                && let Some(syn::GenericArgument::Type(inner)) = a.args.first()
            {
                return type_ident(inner);
            }
            Some(seg.ident.to_string())
        }
        _ => None,
    }
}

fn subcommand_field(f: &syn::Field) -> Option<String> {
    has_subcommand_attr(&f.attrs)
        .then(|| type_ident(&f.ty))
        .flatten()
}

fn variant_child(v: &syn::Variant, structs: &HashMap<String, String>) -> Option<String> {
    if let Some(c) = v.fields.iter().find_map(subcommand_field) {
        return Some(c);
    }
    let mut fields = v.fields.iter();
    let only = fields.next()?;
    if fields.next().is_some() {
        return None;
    }
    structs.get(&type_ident(&only.ty)?).cloned()
}

fn variant_names(v: &syn::Variant) -> Vec<String> {
    let mut names = Vec::new();
    let mut explicit = false;
    for a in &v.attrs {
        if !(a.path().is_ident("command") || a.path().is_ident("clap")) {
            continue;
        }
        let _ = a.parse_nested_meta(|m| {
            let key = m
                .path
                .get_ident()
                .map(ToString::to_string)
                .unwrap_or_default();
            if m.input.peek(syn::Token![=]) {
                let value: syn::Expr = m.value()?.parse()?;
                if let syn::Expr::Lit(syn::ExprLit {
                    lit: syn::Lit::Str(s),
                    ..
                }) = value
                {
                    match key.as_str() {
                        "name" => {
                            explicit = true;
                            names.push(s.value());
                        }
                        "alias" | "visible_alias" => names.push(s.value()),
                        _ => {}
                    }
                }
            } else if m.input.peek(syn::token::Paren) {
                let content;
                syn::parenthesized!(content in m.input);
                let _ = content.parse::<proc_macro2::TokenStream>();
            }
            Ok(())
        });
    }
    if !explicit {
        names.push(kebab(&v.ident.to_string()));
    }
    names
}

fn kebab(ident: &str) -> String {
    let chars: Vec<char> = ident.chars().collect();
    let mut out = String::new();
    for (i, c) in chars.iter().enumerate() {
        if c.is_ascii_uppercase() && i > 0 {
            let prev = chars[i - 1];
            let next_lower = chars.get(i + 1).is_some_and(char::is_ascii_lowercase);
            if prev.is_ascii_lowercase()
                || prev.is_ascii_digit()
                || (prev.is_ascii_uppercase() && next_lower)
            {
                out.push('-');
            }
        }
        out.push(c.to_ascii_lowercase());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kebab_matches_clap() {
        assert_eq!(kebab("CompilerCacheStart"), "compiler-cache-start");
        assert_eq!(kebab("Board"), "board");
        assert_eq!(kebab("CIReceipt"), "ci-receipt");
    }
}
