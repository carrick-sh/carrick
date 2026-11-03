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

pub(crate) fn check(root: &Path, base: Option<&str>) -> Result<(), DebtError> {
    let source = root.join(SOURCE);
    let head = if source.exists() {
        counts(&std::fs::read_to_string(source)?)?
    } else {
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
    fn census_counts_identities_without_source_positions() {
        let source = "root_only! { nr::READ, nr::WRITE, } root_only_state! { Fs, Creds, }";
        assert_eq!(counts(source).unwrap(), [2, 2]);
        assert!(counts("").is_err());
        assert!(counts("root_only! { nr::READ } root_only! { nr::WRITE }").is_err());
    }
}
