//! Reviewed moves of debt cohorts between owners or crates.
//!
//! The authority-debt and terminal-custody ratchets key debt by owner path
//! or crate name, so moving code (a crate split, a module rename) would read
//! as one removed cohort plus one new cohort. A move listed here is
//! transferred instead: both sides of the comparison name every moved key by
//! its destination before comparing, so the moved cohort's total must stay
//! equal or fall, while unmapped removals and new keys stay errors.
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::Path;

pub const MOVES_PATH: &str = "scripts/migrate/authority-moves.json";

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DebtMove {
    pub from: String,
    pub to: String,
    /// The issue whose reviewed change performed the move.
    pub issue: u32,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DebtMoves {
    pub schema: u32,
    #[serde(default)]
    pub authority_debt: Vec<DebtMove>,
    #[serde(default)]
    pub terminal_custody: Vec<DebtMove>,
}

/// A validated one-to-one map from a moved key to its destination.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MoveMap(BTreeMap<String, String>);

impl MoveMap {
    pub fn new(moves: &[DebtMove]) -> Result<Self, String> {
        let mut map = BTreeMap::new();
        for entry in moves {
            if entry.from.is_empty() || entry.to.is_empty() || entry.from == entry.to {
                return Err(format!("invalid debt move: {entry:?}"));
            }
            if map.insert(entry.from.clone(), entry.to.clone()).is_some() {
                return Err(format!("debt move source listed twice: {}", entry.from));
            }
        }
        if let Some(chained) = map.values().find(|to| map.contains_key(*to)) {
            return Err(format!(
                "debt move destination is itself moved (chains hide the cohort): {chained}"
            ));
        }
        Ok(Self(map))
    }

    /// The name a key is compared under: its destination when moved.
    pub fn canonical<'a>(&'a self, key: &'a str) -> &'a str {
        self.0.get(key).map_or(key, String::as_str)
    }

    /// Sum `counts` under canonical names, so a moved cohort compares as one.
    pub fn transfer<K: Ord>(
        &self,
        counts: impl IntoIterator<Item = (K, u64)>,
        rename: impl Fn(&K, &str) -> K,
        name: impl Fn(&K) -> &str,
    ) -> BTreeMap<K, u64> {
        let mut transferred = BTreeMap::new();
        for (key, count) in counts {
            let canonical = self.canonical(name(&key)).to_owned();
            let key = if canonical == name(&key) {
                key
            } else {
                rename(&key, &canonical)
            };
            *transferred.entry(key).or_insert(0) += count;
        }
        transferred
    }
}

impl DebtMoves {
    /// Load the checked-in map; an absent file lists no moves.
    pub fn load(root: &Path) -> Result<Self, String> {
        let path = root.join(MOVES_PATH);
        if !path.exists() {
            return Ok(Self {
                schema: 1,
                ..Self::default()
            });
        }
        let moves: Self = serde_json::from_slice(
            &std::fs::read(&path).map_err(|error| format!("{}: {error}", path.display()))?,
        )
        .map_err(|error| format!("{}: {error}", path.display()))?;
        if moves.schema != 1 {
            return Err(format!("unknown debt move schema {}", moves.schema));
        }
        Ok(moves)
    }

    pub fn authority_debt(&self) -> Result<MoveMap, String> {
        MoveMap::new(&self.authority_debt)
    }

    pub fn terminal_custody(&self) -> Result<MoveMap, String> {
        MoveMap::new(&self.terminal_custody)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(from: &str, to: &str) -> DebtMove {
        DebtMove {
            from: from.into(),
            to: to.into(),
            issue: 673,
        }
    }

    #[test]
    fn duplicate_self_and_chained_moves_are_refused() {
        assert!(MoveMap::new(&[entry("a", "a")]).is_err());
        assert!(MoveMap::new(&[entry("a", "b"), entry("a", "c")]).is_err());
        assert!(MoveMap::new(&[entry("a", "b"), entry("b", "c")]).is_err());
        assert!(MoveMap::new(&[entry("a", "c"), entry("b", "c")]).is_ok());
    }

    #[test]
    fn transfer_sums_a_moved_cohort_under_its_destination() {
        let map = MoveMap::new(&[entry("old", "new")]).unwrap();
        let counts = map.transfer(
            [
                ("old".to_owned(), 6),
                ("new".to_owned(), 22),
                ("other".to_owned(), 1),
            ],
            |_, name| name.to_owned(),
            |key| key.as_str(),
        );
        assert_eq!(
            counts,
            BTreeMap::from([("new".to_owned(), 28), ("other".to_owned(), 1)])
        );
    }
}
