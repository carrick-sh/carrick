use crate::authority_debt::DebtError;
use crate::command;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use syn::ext::IdentExt;
use syn::visit::Visit;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct BuildRoot {
    pub package: String,
    pub source: String,
}

pub(super) fn metadata_roots(root: &Path) -> Result<Vec<BuildRoot>, DebtError> {
    let output = command::run_checked(
        "cargo",
        [
            "metadata",
            "--locked",
            "--offline",
            "--no-deps",
            "--format-version",
            "1",
        ],
        Some(root),
    )?;
    let metadata: serde_json::Value = serde_json::from_str(&output.stdout)?;
    let members = metadata["workspace_members"]
        .as_array()
        .ok_or_else(|| DebtError::Policy("missing Cargo workspace members".into()))?;
    let mut roots = Vec::new();
    for package in metadata["packages"]
        .as_array()
        .ok_or_else(|| DebtError::Policy("missing Cargo packages".into()))?
    {
        if !members.contains(&package["id"]) {
            continue;
        }
        for target in package["targets"]
            .as_array()
            .ok_or_else(|| DebtError::Policy("missing Cargo targets".into()))?
        {
            if target["kind"]
                .as_array()
                .is_some_and(|kinds| kinds.iter().any(|kind| kind == "custom-build"))
            {
                let source = Path::new(
                    target["src_path"]
                        .as_str()
                        .ok_or_else(|| DebtError::Policy("missing build target source".into()))?,
                )
                .canonicalize()?;
                let source = source
                    .strip_prefix(root)
                    .map_err(|_| {
                        DebtError::Policy("build program source escapes workspace".into())
                    })?
                    .to_string_lossy()
                    .to_string();
                roots.push(BuildRoot {
                    package: package["name"]
                        .as_str()
                        .ok_or_else(|| DebtError::Policy("missing build package name".into()))?
                        .to_owned(),
                    source,
                });
            }
        }
    }
    roots.sort_by(|a, b| (&a.package, &a.source).cmp(&(&b.package, &b.source)));
    Ok(roots)
}

pub(super) fn load(
    root: &Path,
    roots: &[BuildRoot],
) -> Result<BTreeMap<PathBuf, syn::File>, DebtError> {
    struct Edges {
        file: PathBuf,
        directory: PathBuf,
        explicit_directory: PathBuf,
        paths: Vec<(PathBuf, bool)>,
        error: Option<String>,
    }
    impl<'ast> Visit<'ast> for Edges {
        fn visit_item_mod(&mut self, module: &'ast syn::ItemMod) {
            let explicit = module.attrs.iter().find_map(|attr| {
                if !attr.path().is_ident("path") {
                    return None;
                }
                let syn::Meta::NameValue(value) = &attr.meta else {
                    self.error = Some("unresolved build module path".into());
                    return None;
                };
                let syn::Expr::Lit(value) = &value.value else {
                    self.error = Some("nonliteral build module path".into());
                    return None;
                };
                let syn::Lit::Str(value) = &value.lit else {
                    self.error = Some("nonliteral build module path".into());
                    return None;
                };
                Some(self.explicit_directory.join(value.value()))
            });
            let name = module.ident.unraw().to_string();
            if let Some((_, items)) = &module.content {
                let old_directory = self.directory.clone();
                let old_explicit = self.explicit_directory.clone();
                self.directory = explicit.unwrap_or_else(|| old_directory.join(&name));
                self.explicit_directory = self.directory.clone();
                for item in items {
                    self.visit_item(item);
                }
                self.directory = old_directory;
                self.explicit_directory = old_explicit;
            } else {
                let selected = explicit.is_some();
                let path = explicit.unwrap_or_else(|| {
                    let direct = self.directory.join(format!("{name}.rs"));
                    if direct.is_file() {
                        direct
                    } else {
                        self.directory.join(name).join("mod.rs")
                    }
                });
                self.paths.push((path, selected));
            }
        }
        fn visit_macro(&mut self, mac: &'ast syn::Macro) {
            let name = mac
                .path
                .segments
                .iter()
                .map(|s| s.ident.unraw().to_string())
                .collect::<Vec<_>>()
                .join("::");
            let executable = matches!(name.as_str(), "include" | "std::include" | "core::include");
            let string_data = matches!(
                name.as_str(),
                "include_str"
                    | "std::include_str"
                    | "core::include_str"
                    | "include_bytes"
                    | "std::include_bytes"
                    | "core::include_bytes"
            );
            if executable || string_data {
                match syn::parse2::<syn::LitStr>(mac.tokens.clone()) {
                    Ok(literal) => {
                        let path = self
                            .file
                            .parent()
                            .unwrap_or(&self.file)
                            .join(literal.value());
                        if executable
                            || std::fs::read_to_string(&path)
                                .is_ok_and(|source| syn::parse_file(&source).is_ok())
                        {
                            self.paths.push((path, true));
                        }
                    }
                    Err(_) => self.error = Some("nonliteral build source inclusion".into()),
                }
            }
        }
    }
    let mut pending: Vec<_> = roots
        .iter()
        .map(|entry| (root.join(&entry.source), true))
        .collect();
    let mut seen = BTreeSet::new();
    let mut parsed = BTreeMap::new();
    while let Some((path, explicit)) = pending.pop() {
        let path = path.canonicalize()?;
        if !path.starts_with(root) {
            return Err(DebtError::Policy(
                "build source inclusion escapes workspace".into(),
            ));
        }
        if path.starts_with(root.join("crates"))
            && path.strip_prefix(root).is_ok_and(|relative| {
                relative
                    .components()
                    .nth(2)
                    .is_some_and(|c| c.as_os_str() == "src")
            })
        {
            return Err(DebtError::Policy(format!(
                "build-time/production source overlap: {}",
                path.display()
            )));
        }
        if !seen.insert((path.clone(), explicit)) {
            continue;
        }
        let syntax = syn::parse_file(&std::fs::read_to_string(&path)?)
            .map_err(|error| DebtError::Policy(format!("{}: {error}", path.display())))?;
        let parent = path
            .parent()
            .ok_or_else(|| DebtError::Policy("missing build module directory".into()))?;
        let mut edges = Edges {
            file: path.clone(),
            directory: if explicit || path.file_name().is_some_and(|n| n == "mod.rs") {
                parent.to_path_buf()
            } else {
                path.with_extension("")
            },
            explicit_directory: parent.to_path_buf(),
            paths: Vec::new(),
            error: None,
        };
        edges.visit_file(&syntax);
        if let Some(error) = edges.error {
            return Err(DebtError::Policy(format!("{}: {error}", path.display())));
        }
        pending.extend(edges.paths);
        parsed.insert(path, syntax);
    }
    Ok(parsed)
}
