//! Evaluate the image build profiles, rather than the spelling of cfg.
use super::{Arch, Assembly, Key};
use std::collections::{BTreeMap, BTreeSet};

/// Declared package features and their image-local activation graph, read from
/// each Git revision. Missing metadata and unsupported forwarding stay unknown.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FeatureSet {
    definitions: Option<BTreeMap<String, Vec<String>>>,
}
impl FeatureSet {
    pub(super) fn from_manifest(source: &str) -> Result<Self, toml::de::Error> {
        #[derive(serde::Deserialize)]
        struct Manifest {
            #[serde(default)]
            features: BTreeMap<String, Vec<String>>,
        }
        let manifest: Manifest = toml::from_str(source)?;
        Ok(Self {
            definitions: Some(manifest.features),
        })
    }
    fn enabled(&self, allocator_control: bool) -> Option<BTreeSet<String>> {
        let definitions = self.definitions.as_ref()?;
        let mut pending = vec!["default".to_string()];
        if allocator_control && definitions.contains_key("allocator-test-control") {
            pending.push("allocator-test-control".into());
        }
        let mut enabled = BTreeSet::new();
        while let Some(name) = pending.pop() {
            if !enabled.insert(name.clone()) {
                continue;
            }
            if name == "default" && !definitions.contains_key(&name) {
                continue;
            }
            // Dependency forwarding is not a package-local feature: it needs
            // Cargo's resolver. Keep feature predicates unknown in that case.
            pending.extend(definitions.get(&name)?.iter().cloned());
        }
        Some(enabled)
    }
    fn evaluate(&self, name: &str, allocator_control: bool) -> Truth {
        let Some(definitions) = &self.definitions else {
            return Truth::Unknown;
        };
        if !definitions.contains_key(name) {
            return Truth::Unknown;
        }
        match self.enabled(allocator_control) {
            Some(enabled) => Truth::from(enabled.contains(name)),
            None => Truth::Unknown,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Truth {
    Yes,
    No,
    Unknown,
}
impl From<bool> for Truth {
    fn from(value: bool) -> Self {
        if value { Self::Yes } else { Self::No }
    }
}
impl Truth {
    fn not(self) -> Self {
        match self {
            Self::Yes => Self::No,
            Self::No => Self::Yes,
            Self::Unknown => Self::Unknown,
        }
    }
    fn all(values: impl Iterator<Item = Self>) -> Self {
        values.fold(Self::Yes, |a, b| match (a, b) {
            (Self::No, _) | (_, Self::No) => Self::No,
            (Self::Unknown, _) | (_, Self::Unknown) => Self::Unknown,
            _ => Self::Yes,
        })
    }
    fn any(values: impl Iterator<Item = Self>) -> Self {
        Self::all(values.map(Self::not)).not()
    }
}

struct Target {
    os: &'static str,
    allocator_control: bool,
}
fn arguments(meta: &syn::MetaList) -> Option<Vec<syn::Meta>> {
    use syn::parse::Parser;
    syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated
        .parse2(meta.tokens.clone())
        .ok()
        .map(|args| args.into_iter().collect())
}
fn condition(meta: &syn::Meta, target: &Target, features: &FeatureSet) -> Truth {
    match meta {
        syn::Meta::Path(path) if path.is_ident("test") => Truth::No,
        syn::Meta::NameValue(value) => {
            let syn::Expr::Lit(literal) = &value.value else {
                return Truth::Unknown;
            };
            let syn::Lit::Str(string) = &literal.lit else {
                return Truth::Unknown;
            };
            let value_string = string.value();
            if value.path.is_ident("target_arch") {
                Truth::from(value_string == "aarch64")
            } else if value.path.is_ident("target_os") {
                Truth::from(value_string == target.os)
            } else if value.path.is_ident("feature") {
                features.evaluate(&value_string, target.allocator_control)
            } else {
                Truth::Unknown
            }
        }
        syn::Meta::List(list) => {
            let Some(args) = arguments(list) else {
                return Truth::Unknown;
            };
            if list.path.is_ident("all") {
                Truth::all(args.iter().map(|meta| condition(meta, target, features)))
            } else if list.path.is_ident("any") {
                Truth::any(args.iter().map(|meta| condition(meta, target, features)))
            } else if list.path.is_ident("not") && args.len() == 1 {
                condition(&args[0], target, features).not()
            } else {
                Truth::Unknown
            }
        }
        _ => Truth::Unknown,
    }
}
fn attribute_condition(meta: &syn::Meta, target: &Target, features: &FeatureSet) -> Truth {
    let syn::Meta::List(list) = meta else {
        return Truth::Unknown;
    };
    let Some(args) = arguments(list) else {
        return Truth::Unknown;
    };
    if list.path.is_ident("cfg") && args.len() == 1 {
        condition(&args[0], target, features)
    } else if list.path.is_ident("cfg_attr") && args.len() >= 2 {
        let enabled = condition(&args[0], target, features);
        let restrictions = Truth::all(args[1..].iter().map(|attr| {
            if attr.path().is_ident("cfg") || attr.path().is_ident("cfg_attr") {
                attribute_condition(attr, target, features)
            } else {
                Truth::Yes
            }
        }));
        Truth::any([enabled.not(), restrictions].into_iter())
    } else {
        Truth::Unknown
    }
}
fn reachability(key: &Key, asm: &Assembly) -> Vec<Truth> {
    if matches!(key.krate.as_str(), "carrick-x86" | "carrick-x86-cpl0")
        || key
            .module
            .split("::")
            .any(|part| part == "x86" || part.starts_with("x86_"))
    {
        return vec![Truth::No];
    }
    // carrick-el1-image/build.rs builds the default release image and an
    // optional allocator-test-control variant. sysreg.rs executes on the host.
    let targets = if key.krate == "carrick-vmm-hvf" {
        vec![Target {
            os: "macos",
            allocator_control: false,
        }]
    } else {
        vec![
            Target {
                os: "none",
                allocator_control: false,
            },
            Target {
                os: "none",
                allocator_control: key.krate == "carrick-el1",
            },
        ]
    };
    targets
        .iter()
        .map(|target| {
            Truth::all(asm.cfg.iter().map(|cfg| {
                syn::parse_str::<syn::Meta>(cfg)
                    .map(|meta| attribute_condition(&meta, target, &asm.features))
                    .unwrap_or(Truth::Unknown)
            }))
        })
        .collect()
}
pub(super) fn guarded(key: &Key, asm: &Assembly, arch: Arch) -> bool {
    matches!(arch, Arch::All)
        || reachability(key, asm)
            .iter()
            .any(|state| *state != Truth::No)
}
pub(super) fn cfg_equivalent(
    old_key: &Key,
    old: &Assembly,
    new_key: &Key,
    new: &Assembly,
    arch: Arch,
) -> bool {
    if matches!(arch, Arch::All) {
        return old.cfg == new.cfg && old.features == new.features;
    }
    let old_states = reachability(old_key, old);
    let new_states = reachability(new_key, new);
    old_states == new_states
        && (!old_states.contains(&Truth::Unknown)
            || (old.cfg == new.cfg && old.features == new.features))
}
