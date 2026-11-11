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
            "trusted step {}/{} runs {}, which this PR adds or changes; land it first in a separate PR (#2092)",
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
    let violations = check(&GitTree::new(root), &args.base, &args.head)?;
    if violations.is_empty() {
        writeln!(writer, "trusted-steps: ok")?;
        return Ok(());
    }
    let text: Vec<String> = violations.iter().map(ToString::to_string).collect();
    Err(TrustedStepsError::Violations(text.join("\n")))
}

pub fn check(tree: &dyn Tree, base: &str, head: &str) -> Result<Vec<Violation>, TrustedStepsError> {
    let base_cli = ClapModel::load(tree, base)?;
    let base_recipes = justfile_recipes(tree, base)?;
    let head_files: HashSet<String> = tree.list(head, ".")?.into_iter().collect();
    let mut found = BTreeSet::new();
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
    Ok(found.into_iter().collect())
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

fn check_job(
    job_id: &str,
    job: &Yaml,
    ctx: &Ctx<'_>,
    found: &mut BTreeSet<Violation>,
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
        let wd = norm_dir(step["working-directory"].as_str().unwrap_or("."));
        let in_trusted = trust
            .get(&wd)
            .or_else(|| trust.get("."))
            .copied()
            .unwrap_or(false);
        if !in_trusted {
            continue;
        }
        let label = step["name"]
            .as_str()
            .map(str::to_owned)
            .or_else(|| (!uses.is_empty()).then(|| uses.to_owned()))
            .unwrap_or_else(|| format!("step {}", idx + 1));
        let mut things = Vec::new();
        if let Some(dir) = uses.strip_prefix("./") {
            things.extend(changed_under(ctx, dir)?);
        }
        if let Some(script) = step["run"].as_str() {
            things.extend(analyze_script(script, ctx)?);
        }
        for thing in things {
            found.insert(Violation {
                job: job_id.into(),
                step: label.clone(),
                thing,
            });
        }
    }
    Ok(())
}

/// Files of a local action directory that differ from the merge base.
fn changed_under(ctx: &Ctx<'_>, dir: &str) -> Result<Vec<String>, TrustedStepsError> {
    let mut out = Vec::new();
    for path in ctx.tree.list(ctx.head, dir)? {
        if differs(ctx, &path)? {
            out.push(path);
        }
    }
    Ok(out)
}

fn differs(ctx: &Ctx<'_>, path: &str) -> Result<bool, TrustedStepsError> {
    Ok(ctx.tree.read(ctx.base, path)? != ctx.tree.read(ctx.head, path)?)
}

fn is_word(w: &str) -> bool {
    let mut cs = w.chars();
    cs.next()
        .is_some_and(|c| c.is_ascii_lowercase() || c == '_')
        && cs.all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// The leading bare words of `rest`, up to the first flag, quote or expansion.
fn leading_words(rest: &str) -> Vec<String> {
    rest.split_whitespace()
        .take_while(|w| is_word(w))
        .map(str::to_owned)
        .collect()
}

fn analyze_script(script: &str, ctx: &Ctx<'_>) -> Result<Vec<String>, TrustedStepsError> {
    let text = script.replace("\\\n", " ");
    let mut things = Vec::new();

    // Repository paths executed directly or through an interpreter.
    let path_re = Regex::new(
        r#"(?m)(?:^|[;&|(`]|\b(?:then|else|do|if|exec|sudo|source|bash|sh|python3?)\b|(?:^|\s)\.)(?:[ \t]+-[A-Za-z-]+)*[ \t]*["']?(?:\./|\$\{\{\s*github\.workspace\s*\}\}/|\$GITHUB_WORKSPACE/|\$\{GITHUB_WORKSPACE\}/)?([A-Za-z0-9_][A-Za-z0-9_./-]*)"#,
    )
    .map_err(regex_err)?;
    let mut seen = HashSet::new();
    for cap in path_re.captures_iter(&text) {
        let path = &cap[1];
        if ctx.head_files.contains(path) && seen.insert(path.to_owned()) && differs(ctx, path)? {
            things.push(path.to_owned());
        }
    }

    // Variables standing for the xtask binary.
    let mut aliases: HashSet<String> = ["CARRICK_XTASK_PREBUILT", "CARRICK_XTASK_BIN"]
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
    let assign_re = Regex::new(
        r"(?m)(?:^|[;&]|\bthen\b)[ \t]*(\w+)=[^\n]*(?:carrick-xtask|XTASK_PREBUILT|XTASK_BIN)",
    )
    .map_err(regex_err)?;
    for cap in assign_re.captures_iter(&text) {
        aliases.insert(cap[1].to_owned());
    }

    let mut invocations: Vec<Vec<String>> = Vec::new();
    let direct = Regex::new(
        r#"(?m)(?:-p[ \t]+carrick-xtask|(?:^|&&|\|\||[;|(])[ \t]*"?[^\s"]*carrick-xtask"?)(?:[ \t]+--)?(?:[ \t]|$)([^\n]*)"#,
    )
    .map_err(regex_err)?;
    for cap in direct.captures_iter(&text) {
        invocations.push(leading_words(&cap[1]));
    }
    let var = Regex::new(
        r#"(?m)(?:^|&&|\|\||[;|(]|\bthen\b)[ \t]*"?\$\{?(\w+)(?:\[@\])?\}?"?[ \t]([^\n]*)"#,
    )
    .map_err(regex_err)?;
    for cap in var.captures_iter(&text) {
        if aliases.contains(&cap[1]) {
            invocations.push(leading_words(&cap[2]));
        }
    }
    let just = Regex::new(r"(?m)(?:^|&&|\|\||[;|(]|\bthen\b)[ \t]*just[ \t]+([^\n]*)")
        .map_err(regex_err)?;
    for cap in just.captures_iter(&text) {
        let mut toks = cap[1].split_whitespace();
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
            things.push(format!("just recipe {recipe}"));
        } else if recipe == "xtask" {
            let rest: Vec<&str> = toks.collect();
            invocations.push(leading_words(&rest.join(" ")));
        }
    }

    for words in invocations {
        if let Some(missing) = ctx.cli.first_missing(&words) {
            things.push(format!("carrick-xtask {missing}"));
        }
    }
    Ok(things)
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
