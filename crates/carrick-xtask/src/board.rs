//! Project 1 reconciliation: a read-only snapshot produces the complete write plan.
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
enum Status {
    Todo,
    #[serde(rename = "In progress")]
    InProgress,
    #[serde(rename = "In review")]
    InReview,
    Blocked,
    Done,
}

fn desired(
    _node: &Value,
    current: Option<Status>,
    _running: &BTreeSet<u64>,
    _open: &BTreeSet<u64>,
    _cutoff: u64,
) -> Option<(Status, String)> {
    current.map(|status| (status, "unchanged".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn running_round_887_overrides_blocked() {
        let fixture: Value =
            serde_json::from_str(include_str!("fixtures/board/running-887.json")).unwrap();
        assert_eq!(
            desired(
                &fixture,
                Some(Status::Blocked),
                &BTreeSet::from([887]),
                &BTreeSet::from([887]),
                0
            )
            .unwrap()
            .0,
            Status::InProgress
        );
    }
}
