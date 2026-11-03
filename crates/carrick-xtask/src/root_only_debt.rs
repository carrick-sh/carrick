//! Position-free, base-relative retirement ratchet for #1393's compatibility.
use crate::authority_debt::DebtError;
use crate::command;
use std::path::Path;
use syn::parse::Parser;

const SOURCE: &str = "crates/carrick-kernel/src/dispatch/root_only.rs";

fn counts(source: &str) -> Result<[usize; 2], DebtError> {
    let mut counts = [0; 2];
    let mut seen = [false; 2];
    for item in syn::parse_file(source)?.items {
        let syn::Item::Macro(item) = item else {
            continue;
        };
        let index = if item.mac.path.is_ident("root_only") {
            0
        } else if item.mac.path.is_ident("root_only_state") {
            1
        } else {
            continue;
        };
        if seen[index] {
            return Err(DebtError::Policy("duplicate RootOnly declaration".into()));
        }
        seen[index] = true;
        let entries = syn::punctuated::Punctuated::<syn::Path, syn::Token![,]>::parse_terminated
            .parse2(item.mac.tokens)?;
        counts[index] = entries.len();
    }
    if seen != [true, true] {
        return Err(DebtError::Policy(
            "missing RootOnly declaration in retained module".into(),
        ));
    }
    Ok(counts)
}

fn ratchet(base: [usize; 2], head: [usize; 2]) -> Result<(), DebtError> {
    for (name, (old, new)) in ["handlers", "ambient state"]
        .into_iter()
        .zip(base.into_iter().zip(head))
    {
        if new > old {
            return Err(DebtError::Policy(format!(
                "RootOnly {name} grew: {old} -> {new}"
            )));
        }
    }
    Ok(())
}

fn retains_root_resolution(directory: &Path) -> Result<bool, DebtError> {
    if !directory.exists() {
        return Ok(false);
    }
    for entry in std::fs::read_dir(directory)? {
        let entry = entry?;
        let path = entry.path();
        if entry.file_type()?.is_dir() {
            if entry.file_name() != "target" && retains_root_resolution(&path)? {
                return Ok(true);
            }
        } else if path.extension().is_some_and(|extension| extension == "rs")
            && std::fs::read_to_string(path)?.contains("root_only::resolve")
        {
            return Ok(true);
        }
    }
    Ok(false)
}

const OWNER_SOURCE: &str = "crates/carrick-personality-linux/src/dispatch.rs";

fn wiring_ceiling(source: &str) -> Result<usize, DebtError> {
    for item in syn::parse_file(source)?.items {
        if let syn::Item::Const(item) = item
            && item.ident == "ISA_WIRING_GAP_CEILING"
            && let syn::Expr::Lit(value) = *item.expr
            && let syn::Lit::Int(value) = value.lit
        {
            return Ok(value.base10_parse()?);
        }
    }
    Err(DebtError::Policy("missing ISA wiring gap ceiling".into()))
}

pub(crate) fn check(root: &Path, base: Option<&str>) -> Result<(), DebtError> {
    let source = root.join(SOURCE);
    let head = if source.exists() {
        counts(&std::fs::read_to_string(source)?)?
    } else {
        if retains_root_resolution(&root.join("crates/carrick-kernel/src"))? {
            return Err(DebtError::Policy(
                "RootOnly module missing while compatibility entry is retained".into(),
            ));
        }
        [0; 2]
    };
    if let Some(base) = base {
        let exists = command::run_checked("git", ["ls-tree", base, "--", SOURCE], Some(root))?;
        let previous = if exists.stdout.trim().is_empty() {
            // First admission of the census. Thereafter compare with the actual
            // PR base, so removing a row cannot leave room to add another later.
            [283, 21]
        } else {
            let previous =
                command::run_checked("git", ["show", &format!("{base}:{SOURCE}")], Some(root))?;
            counts(&previous.stdout)?
        };
        ratchet(previous, head)?;
    }
    if !root.join(OWNER_SOURCE).exists() && head == [0, 0] {
        return Ok(());
    }
    let current_wiring = wiring_ceiling(&std::fs::read_to_string(root.join(OWNER_SOURCE))?)?;
    let old_wiring = if let Some(base) = base {
        let previous = command::run_checked(
            "git",
            ["show", &format!("{base}:{OWNER_SOURCE}")],
            Some(root),
        )?;
        // First admission is the twelve gaps documented in #1091/#1092/#1093.
        if previous.stdout.contains("ISA_WIRING_GAP_CEILING") {
            wiring_ceiling(&previous.stdout)?
        } else {
            12
        }
    } else {
        12
    };
    if current_wiring > old_wiring {
        return Err(DebtError::Policy(format!(
            "ISA wiring gaps grew: {old_wiring} -> {current_wiring}"
        )));
    }
    println!("ISA wiring gaps: {current_wiring}");
    println!(
        "RootOnly: {} retained handlers, {} ambient-state obligations",
        head[0], head[1]
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retirement_cannot_be_reused_for_another_handler_or_state() {
        assert!(ratchet([3, 2], [2, 1]).is_ok());
        assert!(ratchet([2, 1], [3, 1]).is_err());
        assert!(ratchet([2, 1], [2, 2]).is_err());
        assert!(ratchet([0, 0], [0, 0]).is_ok());
    }

    #[test]
    fn moved_module_cannot_hide_retained_resolution() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(
            directory.path().join("routing.rs"),
            "root_only::resolve(number, legacy)",
        )
        .unwrap();
        assert!(retains_root_resolution(directory.path()).unwrap());
        std::fs::remove_file(directory.path().join("routing.rs")).unwrap();
        assert!(!retains_root_resolution(directory.path()).unwrap());
    }

    #[test]
    fn wiring_ceiling_is_typed_and_required() {
        assert_eq!(
            wiring_ceiling("pub const ISA_WIRING_GAP_CEILING: usize = 12;").unwrap(),
            12
        );
        assert!(wiring_ceiling("").is_err());
    }

    #[test]
    fn census_counts_identities_without_source_positions() {
        let source = "root_only! { nr::READ, nr::WRITE, } root_only_state! { Fs, Creds, }";
        assert_eq!(counts(source).unwrap(), [2, 2]);
        assert!(counts("").is_err());
        assert!(counts("root_only! { nr::READ } root_only! { nr::WRITE }").is_err());
    }
}
