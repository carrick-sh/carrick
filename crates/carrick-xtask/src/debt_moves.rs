//! Reviewed moves of debt cohorts between owners or crates, for one change.
//!
//! The authority-debt and terminal-custody ratchets key debt by owner path
//! or crate name, so moving code (a crate split, a module rename) reads as a
//! removed cohort plus a new one. An entry here admits exactly that change
//! and nothing else:
//! - it applies only while its source exists in the PR base and its
//!   destination does not. An entry this change adds (absent from the base
//!   revision's own move file) that does not apply is stale and fails; an
//!   entry inherited from the base's file that no longer applies is a no-op
//!   that settles nothing, so landed moves cannot be reused and a follow-up
//!   change empties the file (delete-at-zero);
//! - the source key is compared on its own (head ≤ base), and the new
//!   destination key is admitted only up to what the source gave up
//!   (`base(source) − head(source)`), so a split cannot pool its halves and a
//!   move cannot hide growth in an existing destination.
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

pub const MOVES_PATH: &str = "scripts/migrate/authority-moves.json";

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DebtMove {
    pub from: String,
    pub to: String,
    /// The issue whose reviewed change performs the move.
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct Move {
    from: String,
    to: String,
    /// Listed identically in the base revision's move file.
    inherited: bool,
}

/// A validated one-to-one list of moves.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MoveMap(Vec<Move>);

impl MoveMap {
    /// `moves` is the head's list; `inherited` is the base revision's list.
    pub fn new(moves: &[DebtMove], inherited: &[DebtMove]) -> Result<Self, String> {
        let mut sources = BTreeSet::new();
        let mut destinations = BTreeSet::new();
        for entry in moves {
            if entry.from.is_empty() || entry.to.is_empty() || entry.from == entry.to {
                return Err(format!("invalid debt move: {entry:?}"));
            }
            if !sources.insert(entry.from.as_str()) {
                return Err(format!("debt move source listed twice: {}", entry.from));
            }
            if !destinations.insert(entry.to.as_str()) {
                return Err(format!("debt move destination listed twice: {}", entry.to));
            }
        }
        if let Some(chained) = destinations.intersection(&sources).next() {
            return Err(format!("debt move destination is itself moved: {chained}"));
        }
        Ok(Self(
            moves
                .iter()
                .map(|entry| Move {
                    from: entry.from.clone(),
                    to: entry.to.clone(),
                    inherited: inherited
                        .iter()
                        .any(|old| old.from == entry.from && old.to == entry.to),
                })
                .collect(),
        ))
    }

    /// Check every move against `base` and `head` and return the keys it
    /// settled; the caller compares every other key with its usual rules.
    ///
    /// `name` reads a key's owner or crate and `rename` builds the same key
    /// under another one, so one source key maps to one destination key.
    pub fn settle<K: Ord + Clone + std::fmt::Debug>(
        &self,
        base: &BTreeMap<K, u64>,
        head: &BTreeMap<K, u64>,
        name: impl Fn(&K) -> &str,
        rename: impl Fn(&K, &str) -> K,
    ) -> Result<BTreeSet<K>, String> {
        let mut settled = BTreeSet::new();
        for Move {
            from,
            to,
            inherited,
        } in &self.0
        {
            let destination_exists = base.keys().any(|key| name(key) == to);
            let sources: Vec<_> = base.keys().filter(|key| name(key) == from).collect();
            if destination_exists || sources.is_empty() {
                if *inherited {
                    // Landed before this change: it admits nothing now.
                    continue;
                }
                return Err(if destination_exists {
                    format!(
                        "stale debt move {from} -> {to}: the destination already exists in the \
                         base; a new move must name a new destination"
                    )
                } else {
                    format!("stale debt move {from} -> {to}: the source does not exist in the base")
                });
            }
            for source in sources {
                let destination = rename(source, to);
                let given = base[source];
                let kept = head.get(source).copied().unwrap_or(0);
                let moved = head.get(&destination).copied().unwrap_or(0);
                if kept > given {
                    return Err(format!(
                        "debt move source grew: {source:?}: {given} -> {kept}"
                    ));
                }
                if moved > given - kept {
                    return Err(format!(
                        "debt move destination exceeds what the source gave up: \
                         {destination:?}: {moved} > {given} - {kept}"
                    ));
                }
                settled.insert(source.clone());
                settled.insert(destination);
            }
        }
        Ok(settled)
    }
}

impl DebtMoves {
    /// Load the checked-in list; an absent file lists no moves.
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

    /// The moves file at `base`, the revision the ratchet compares against;
    /// absent there, it lists no moves.
    pub fn load_at(root: &Path, base: &str) -> Result<Self, String> {
        let listed =
            crate::command::run_checked("git", ["ls-tree", base, "--", MOVES_PATH], Some(root))
                .map_err(|error| error.to_string())?;
        if listed.stdout.trim().is_empty() {
            return Ok(Self {
                schema: 1,
                ..Self::default()
            });
        }
        let source = crate::command::run_checked(
            "git",
            ["show", &format!("{base}:{MOVES_PATH}")],
            Some(root),
        )
        .map_err(|error| error.to_string())?;
        let moves: Self = serde_json::from_str(&source.stdout)
            .map_err(|error| format!("{base}:{MOVES_PATH}: {error}"))?;
        if moves.schema != 1 {
            return Err(format!("unknown debt move schema {}", moves.schema));
        }
        Ok(moves)
    }

    pub fn authority_debt(&self, base: &Self) -> Result<MoveMap, String> {
        MoveMap::new(&self.authority_debt, &base.authority_debt)
    }

    pub fn terminal_custody(&self, base: &Self) -> Result<MoveMap, String> {
        MoveMap::new(&self.terminal_custody, &base.terminal_custody)
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

    fn counts(pairs: &[(&str, u64)]) -> BTreeMap<String, u64> {
        pairs.iter().map(|(k, v)| ((*k).to_owned(), *v)).collect()
    }

    fn settle(map: &MoveMap, base: &[(&str, u64)], head: &[(&str, u64)]) -> Result<(), String> {
        map.settle(
            &counts(base),
            &counts(head),
            |k| k.as_str(),
            |_, n| n.to_owned(),
        )
        .map(|_| ())
    }

    #[test]
    fn duplicate_self_and_chained_moves_are_refused() {
        assert!(MoveMap::new(&[entry("a", "a")], &[]).is_err());
        assert!(MoveMap::new(&[entry("a", "b"), entry("a", "c")], &[]).is_err());
        assert!(MoveMap::new(&[entry("a", "c"), entry("b", "c")], &[]).is_err());
        assert!(MoveMap::new(&[entry("a", "b"), entry("b", "c")], &[]).is_err());
    }

    #[test]
    fn a_split_is_bounded_by_what_the_source_gave_up() {
        let map = MoveMap::new(&[entry("lane", "lane-linux")], &[]).unwrap();
        assert!(settle(&map, &[("lane", 28)], &[("lane", 6), ("lane-linux", 22)]).is_ok());
        assert!(settle(&map, &[("lane", 28)], &[("lane-linux", 28)]).is_ok());
        // The source grows while the destination shrinks to keep the total.
        assert!(settle(&map, &[("lane", 28)], &[("lane", 29), ("lane-linux", 0)]).is_err());
        assert!(settle(&map, &[("lane", 28)], &[("lane", 7), ("lane-linux", 22)]).is_err());
    }

    #[test]
    fn an_inherited_entry_that_no_longer_applies_is_a_no_op() {
        let inherited = [entry("a", "b")];
        let map = MoveMap::new(&inherited, &inherited).unwrap();
        // (a) After landing, the base names the destination: no error.
        assert_eq!(
            map.settle(
                &counts(&[("b", 3)]),
                &counts(&[("b", 3)]),
                |k| k.as_str(),
                |_, n| n.to_owned()
            ),
            Ok(BTreeSet::new()),
            "an inherited stale entry settles nothing and passes"
        );
        // (b) The same entry newly added by this change is stale.
        let added = MoveMap::new(&inherited, &[]).unwrap();
        assert!(settle(&added, &[("b", 3)], &[("b", 3)]).is_err());
        // An inherited entry that still applies keeps its bound.
        assert!(settle(&map, &[("a", 3)], &[("b", 4)]).is_err());
    }

    #[test]
    fn an_existing_destination_or_a_landed_move_is_stale() {
        let map = MoveMap::new(&[entry("a", "b")], &[]).unwrap();
        // Moving into an existing cohort would hide its new debt.
        assert!(settle(&map, &[("a", 3), ("b", 2)], &[("b", 5)]).is_err());
        // After landing the base names the destination: the entry is stale.
        assert!(settle(&map, &[("b", 3)], &[("b", 3)]).is_err());
        assert!(settle(&map, &[("c", 3)], &[("c", 3)]).is_err());
    }
}
