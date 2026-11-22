//! `carrick debug venue-gaps`: diff native-oracle syscall profiles against
//! Carrick's routing for the root and a native child (#1906). The diff
//! itself lives in `crate::venue_gaps`.

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

fn censuses(inputs: &[PathBuf]) -> Result<Vec<carrick_runtime::el1_census::Census>> {
    crate::debug_el1_census::collect_json(inputs)?
        .iter()
        .map(|file| crate::debug_el1_census::load(file))
        .collect()
}

/// The row name of a profile: its parent directory (`<out>/<row>/profile.txt`).
fn row_name(profile: &Path) -> String {
    profile.parent().and_then(|p| p.file_name()).map_or_else(
        || profile.display().to_string(),
        |n| n.to_string_lossy().into_owned(),
    )
}

/// A census is one Carrick run of one workload, and its refusals join only
/// that workload's profile: with `--census`, exactly one profile is allowed.
fn check_census_join(profiles: &[PathBuf], census: &[PathBuf]) -> Result<()> {
    if !census.is_empty() && profiles.len() != 1 {
        anyhow::bail!(
            "--census joins one workload's run: give exactly one profile with it, not {} \
             (run venue-gaps once per row)",
            profiles.len()
        );
    }
    Ok(())
}

pub(crate) fn run_venue_gaps(profiles: &[PathBuf], census: &[PathBuf], all: bool) -> Result<()> {
    check_census_join(profiles, census)?;
    let census = if census.is_empty() {
        None
    } else {
        Some(crate::venue_gaps::census_refusals(&censuses(census)?))
    };
    for path in profiles {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("read profile {}", path.display()))?;
        let profile = crate::venue_gaps::parse_profile(&text)
            .map_err(anyhow::Error::msg)
            .with_context(|| format!("profile {}", path.display()))?;
        print!(
            "{}",
            crate::venue_gaps::render(&row_name(path), &profile, census.as_ref(), all)
                .map_err(anyhow::Error::msg)?
        );
        println!();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::run_venue_gaps;

    const PROFILE: &str = "VENUEPROFILE1|ready|root=1|isa=0
VENUEPROFILE1|complete|root=1

@calls[1, 41, 1, 1]: 1
";

    fn rows(dir: &std::path::Path, names: &[&str]) -> Vec<std::path::PathBuf> {
        names
            .iter()
            .map(|row| {
                let d = dir.join(row);
                std::fs::create_dir_all(&d).unwrap();
                let p = d.join("profile.txt");
                std::fs::write(&p, PROFILE).unwrap();
                p
            })
            .collect()
    }

    #[test]
    fn census_refuses_more_than_one_profile() {
        let dir = tempfile::tempdir().unwrap();
        let census = dir.path().join("census");
        std::fs::create_dir_all(&census).unwrap();
        let two = rows(dir.path(), &["shell", "npm"]);
        let err = run_venue_gaps(&two, std::slice::from_ref(&census), false)
            .expect_err("one census applied to two rows must be refused");
        assert!(err.to_string().contains("exactly one profile"), "{err:#}");
        // One profile with its own census, or many without one, still runs.
        run_venue_gaps(&two[..1], std::slice::from_ref(&census), false).unwrap();
        run_venue_gaps(&two, &[], false).unwrap();
    }
}
