//! Project 1 reconciliation: a read-only snapshot produces the complete write plan.
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

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
    node: &Value,
    current: Option<Status>,
    running: &BTreeSet<u64>,
    open: &BTreeSet<u64>,
    cutoff: u64,
) -> Option<(Status, String)> {
    let decide = |status, reason: &str| Some((status, reason.into()));
    if current == Some(Status::Done) {
        return decide(Status::Done, "Done is never reopened");
    }
    if node["closed"] == true {
        return decide(Status::Done, "repository item is closed or merged");
    }
    let pr = node["__typename"] == "PullRequest";
    let approved = pr
        && node["reviews"]["nodes"].as_array().is_some_and(|reviews| {
            reviews.iter().any(|review| {
                review["submittedAt"].as_str().is_some()
                    && matches!(
                        review["state"].as_str(),
                        Some("COMMENTED" | "APPROVED" | "CHANGES_REQUESTED")
                    )
                    && review["commit"]["oid"]
                        .as_str()
                        .is_some_and(|oid| Some(oid) == node["headRefOid"].as_str())
                    && review["body"].as_str().is_some_and(|body| {
                        body.lines().any(|line| line.trim() == "Verdict: APPROVE")
                    })
            })
        });
    if pr && node["isDraft"] == false {
        return decide(Status::InReview, "ready PR");
    }
    if approved {
        return decide(
            Status::InReview,
            "published Verdict: APPROVE on current head",
        );
    }
    if node["number"]
        .as_u64()
        .is_some_and(|number| running.contains(&number))
    {
        return decide(Status::InProgress, "dispatch workflow round is running");
    }
    if pr
        && node["isDraft"] == true
        && node["updatedAt"]
            .as_str()
            .and_then(timestamp)
            .is_some_and(|updated| updated >= cutoff)
    {
        return decide(Status::InProgress, "draft PR updated within 24 hours");
    }
    if let Some(number) = blocker(node) {
        if open.contains(&number) {
            return Some((
                Status::Blocked,
                format!("newest director comment waits on #{number} (open)"),
            ));
        }
        if current == Some(Status::Blocked) {
            return Some((
                Status::Todo,
                format!("blocker #{number} closed; clear Blocked"),
            ));
        }
        return None;
    }
    let outcome = node["comments"]["nodes"].as_array().and_then(|comments| {
        comments
            .iter()
            .filter(|comment| {
                matches!(
                    comment["author"]["login"].as_str(),
                    Some("github-actions[bot]" | "carrick-workers[bot]")
                )
            })
            .filter_map(|comment| {
                let status =
                    crate::dispatch_worker::published_outcome_status(comment["body"].as_str()?)?;
                Some((comment["createdAt"].as_str()?, status))
            })
            .max_by_key(|(created, _)| *created)
    });
    if outcome.is_some_and(|(_, status)| status == "Blocked") {
        return decide(Status::Blocked, "latest dispatch outcome is Blocked");
    }
    None
}

use crate::ci_scaler::{DISPATCH_OWNER, Github, REPOSITORY, ScalerError};
use serde_json::json;
use std::io::Write;

#[derive(clap::Args, Debug)]
pub struct Args {
    #[command(subcommand)]
    command: BoardCommand,
}
#[derive(clap::Subcommand, Debug)]
enum BoardCommand {
    /// Print a complete plan; --apply executes precisely that plan.
    Reconcile {
        #[arg(long)]
        apply: bool,
    },
}

trait Api {
    fn request(
        &mut self,
        method: &str,
        endpoint: &str,
        body: Option<Value>,
        paginate: bool,
    ) -> Result<Value, ScalerError>;
}
impl Api for Github {
    fn request(
        &mut self,
        method: &str,
        endpoint: &str,
        body: Option<Value>,
        paginate: bool,
    ) -> Result<Value, ScalerError> {
        Github::request(self, method, endpoint, body, paginate)
    }
}
fn graphql(api: &mut impl Api, query: &str, variables: Value) -> Result<Value, ScalerError> {
    let value = api.request(
        "POST",
        "graphql",
        Some(json!({"query":query,"variables":variables})),
        false,
    )?;
    if value.get("errors").is_some() || value.get("data").is_none() {
        return Err(ScalerError::Guard("board GraphQL response contains errors"));
    }
    Ok(value["data"].clone())
}
fn has_next(connection: &Value) -> Result<bool, ScalerError> {
    connection["pageInfo"]["hasNextPage"]
        .as_bool()
        .ok_or(ScalerError::Guard("missing board page metadata"))
}

fn next_cursor(connection: &Value, previous: &Value) -> Result<Value, ScalerError> {
    let cursor = string(&connection["pageInfo"]["endCursor"])?;
    if cursor.is_empty() || previous.as_str() == Some(cursor) {
        return Err(ScalerError::Guard("board pagination did not advance"));
    }
    Ok(Value::String(cursor.into()))
}

fn array(value: &Value) -> Result<&Vec<Value>, ScalerError> {
    value
        .as_array()
        .ok_or(ScalerError::Guard("missing board connection nodes"))
}
fn string(value: &Value) -> Result<&str, ScalerError> {
    value
        .as_str()
        .ok_or(ScalerError::Guard("missing board field"))
}

#[derive(Debug, Clone, Serialize)]
struct Change {
    number: u64,
    content: String,
    item: Option<String>,
    from: Option<Status>,
    to: Option<Status>,
    reason: String,
}
struct Snapshot {
    project: String,
    field: String,
    options: BTreeMap<String, String>,
    items: BTreeMap<String, (String, Option<Status>)>,
    nodes: BTreeMap<u64, Value>,
    running: BTreeSet<u64>,
}

const CONTENT: &str = r#"content { ... on Issue { id number repository { nameWithOwner } } ... on PullRequest { id number repository { nameWithOwner } } }"#;
// IssueState and PullRequestState are different GraphQL enum types. Use
// Closable.closed (Boolean! on both) so their response fields can merge.
const DETAILS: &str = r#"
... on Issue { id __typename number closed updatedAt comments(first:100) { pageInfo { hasNextPage endCursor } nodes { author { login } body createdAt } } }
... on PullRequest { id __typename number closed updatedAt isDraft headRefOid
 comments(first:100) { pageInfo { hasNextPage endCursor } nodes { author { login } body createdAt } }
 reviews(first:100) { pageInfo { hasNextPage endCursor } nodes { state body submittedAt commit { oid } } }
 closingIssuesReferences(first:100) { pageInfo { hasNextPage endCursor } nodes { id number repository { nameWithOwner } } }
}
"#;

impl Snapshot {
    fn load(api: &mut impl Api) -> Result<Self, ScalerError> {
        let mut snapshot = Self {
            project: String::new(),
            field: String::new(),
            options: BTreeMap::new(),
            items: BTreeMap::new(),
            nodes: BTreeMap::new(),
            running: BTreeSet::new(),
        };
        let mut ids = BTreeSet::new();
        let mut cursor = Value::Null;
        // Exactly one project page walk, including closed items already on the board.
        loop {
            let query = format!(
                r#"query($cursor:String) {{ organization(login:"carrick-sh") {{ projectV2(number:1) {{ id fields(first:100) {{ pageInfo {{ hasNextPage }} nodes {{ ... on ProjectV2SingleSelectField {{ id name options {{ id name }} }} }} }} items(first:100,after:$cursor) {{ pageInfo {{ hasNextPage endCursor }} nodes {{ id {CONTENT} fieldValueByName(name:"Status") {{ ... on ProjectV2ItemFieldSingleSelectValue {{ name }} }} }} }} }} }} }}"#
            );
            let data = graphql(api, &query, json!({"cursor":cursor}))?;
            let project = &data["organization"]["projectV2"];
            snapshot.project = string(&project["id"])?.into();
            if has_next(&project["fields"])? {
                return Err(ScalerError::Guard("project fields truncated"));
            }
            for field in array(&project["fields"]["nodes"])? {
                if field["name"] == "Status" {
                    snapshot.field = string(&field["id"])?.into();
                    for option in array(&field["options"])? {
                        snapshot.options.insert(
                            string(&option["name"])?.into(),
                            string(&option["id"])?.into(),
                        );
                    }
                }
            }
            for item in array(&project["items"]["nodes"])? {
                if item["content"]["repository"]["nameWithOwner"] != REPOSITORY {
                    continue;
                }
                let id = string(&item["content"]["id"])?.to_owned();
                ids.insert(id.clone());
                let status = if item["fieldValueByName"].is_null() {
                    None
                } else {
                    Some(serde_json::from_value(
                        item["fieldValueByName"]["name"].clone(),
                    )?)
                };
                if snapshot
                    .items
                    .insert(id, (string(&item["id"])?.into(), status))
                    .is_some()
                {
                    return Err(ScalerError::Guard("duplicate repository item on board"));
                }
            }
            if !has_next(&project["items"])? {
                break;
            }
            cursor = next_cursor(&project["items"], &cursor)?;
        }
        if snapshot.field.is_empty() {
            return Err(ScalerError::Guard("project Status field missing"));
        }
        for status in [
            Status::Todo,
            Status::InProgress,
            Status::InReview,
            Status::Blocked,
            Status::Done,
        ] {
            if !snapshot.options.contains_key(&status.name()) {
                return Err(ScalerError::Guard("project Status option missing"));
            }
        }
        let mut open_prs = BTreeSet::new();
        for connection in ["issues", "pullRequests"] {
            let mut cursor = Value::Null;
            loop {
                let query = format!(
                    r#"query($cursor:String) {{ repository(owner:"carrick-sh",name:"carrick") {{ {connection}(first:100,after:$cursor,states:OPEN) {{ pageInfo {{ hasNextPage endCursor }} nodes {{ id }} }} }} }}"#
                );
                let data = graphql(api, &query, json!({"cursor":cursor}))?;
                let rows = &data["repository"][connection];
                for node in array(&rows["nodes"])? {
                    let id = string(&node["id"])?;
                    ids.insert(id.into());
                    if connection == "pullRequests" {
                        open_prs.insert(id.to_owned());
                    }
                }
                if !has_next(rows)? {
                    break;
                }
                cursor = next_cursor(rows, &cursor)?;
            }
        }
        // Immutable Done issues need no history. Open PRs still supply facts
        // for their closing issues even if the PR board item is protected.
        ids.retain(|id| {
            open_prs.contains(id)
                || !snapshot
                    .items
                    .get(id)
                    .is_some_and(|item| item.1 == Some(Status::Done))
        });
        let ids: Vec<_> = ids.into_iter().collect();
        for batch in ids.chunks(25) {
            let data = graphql(
                api,
                &format!("query($ids:[ID!]!) {{ nodes(ids:$ids) {{ {DETAILS} }} }}"),
                json!({"ids":batch}),
            )?;
            for node in array(&data["nodes"])?.clone() {
                let number = node["number"]
                    .as_u64()
                    .ok_or(ScalerError::Guard("missing repository item number"))?;
                node["closed"]
                    .as_bool()
                    .ok_or(ScalerError::Guard("missing repository closure fact"))?;
                snapshot.nodes.insert(number, node);
            }
        }
        snapshot.complete_connections(api)?;
        snapshot.running = running_issues(api)?;
        Ok(snapshot)
    }
}

fn running_issues(api: &mut impl Api) -> Result<BTreeSet<u64>, ScalerError> {
    let pages = api.request("GET", &format!("repos/{REPOSITORY}/actions/workflows/dispatch-worker.yml/runs?status=in_progress&per_page=100"), None, true)?;
    let mut issues = BTreeSet::new();
    for page in array(&pages)? {
        for run in array(&page["workflow_runs"])? {
            let id = run["id"]
                .as_u64()
                .ok_or(ScalerError::Guard("missing dispatch run id"))?;
            let jobs = api.request(
                "GET",
                &format!("repos/{REPOSITORY}/actions/runs/{id}/jobs?per_page=100"),
                None,
                true,
            )?;
            for page in array(&jobs)? {
                for job in array(&page["jobs"])? {
                    // This is the existing workflow guard's structured identity
                    // record, also consumed by the dispatch GitHub client.
                    for step in array(&job["steps"])? {
                        if step["conclusion"] == "success"
                            && let Some(number) = step["name"]
                                .as_str()
                                .and_then(|s| s.strip_prefix("Dispatch issue "))
                                .and_then(|s| s.parse::<u64>().ok())
                        {
                            issues.insert(number);
                        }
                    }
                }
            }
        }
    }
    Ok(issues)
}

impl Status {
    fn name(self) -> String {
        match self {
            Self::Todo => "Todo",
            Self::InProgress => "In progress",
            Self::InReview => "In review",
            Self::Blocked => "Blocked",
            Self::Done => "Done",
        }
        .into()
    }
}

fn blocker(node: &Value) -> Option<u64> {
    let latest = node["comments"]["nodes"]
        .as_array()?
        .iter()
        .filter(|c| c["author"]["login"] == DISPATCH_OWNER)
        .max_by_key(|c| c["createdAt"].as_str().unwrap_or_default())?;
    // Documented director grammar. Do not infer status from arbitrary prose.
    let body = latest["body"].as_str()?;
    let pattern = regex::Regex::new(r"\bwaits on #([1-9][0-9]*)\b").ok()?;
    pattern.captures(body)?.get(1)?.as_str().parse().ok()
}

/// GitHub UTC timestamps have a fixed RFC3339 representation. Return None for
/// malformed dates rather than treating them as recently updated.
fn timestamp(text: &str) -> Option<u64> {
    if text.len() != 20
        || text.as_bytes()[4] != b'-'
        || text.as_bytes()[7] != b'-'
        || text.as_bytes()[10] != b'T'
        || text.as_bytes()[13] != b':'
        || text.as_bytes()[16] != b':'
        || !text.ends_with('Z')
    {
        return None;
    }
    let year: u64 = text.get(0..4)?.parse().ok()?;
    let month: usize = text.get(5..7)?.parse().ok()?;
    let day: u64 = text.get(8..10)?.parse().ok()?;
    let hour: u64 = text.get(11..13)?.parse().ok()?;
    let minute: u64 = text.get(14..16)?.parse().ok()?;
    let second: u64 = text.get(17..19)?.parse().ok()?;
    if !(1970..=9999).contains(&year)
        || !(1..=12).contains(&month)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return None;
    }
    let leap = |y: u64| {
        u64::from(y.is_multiple_of(4) && (!y.is_multiple_of(100) || y.is_multiple_of(400)))
    };
    let months = [31, 28 + leap(year), 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    if day == 0 || day > months[month - 1] {
        return None;
    }
    let days: u64 = (1970..year).map(|y| 365 + leap(y)).sum::<u64>()
        + months[..month - 1].iter().sum::<u64>()
        + day
        - 1;
    Some(days * 86400 + hour * 3600 + minute * 60 + second)
}

impl Snapshot {
    fn plan(&self, cutoff: u64, open: &BTreeSet<u64>) -> Vec<Change> {
        let mut decisions = BTreeMap::new();
        for (number, node) in &self.nodes {
            let current = self
                .items
                .get(node["id"].as_str().unwrap_or_default())
                .and_then(|i| i.1);
            if let Some(decision) = desired(node, current, &self.running, open, cutoff) {
                decisions.insert(*number, decision);
            }
        }
        // A PR's review/progress state also advances the issues GitHub says it
        // closes. Never guess closing relationships from PR body text.
        for (number, node) in &self.nodes {
            if node["__typename"] != "PullRequest" {
                continue;
            }
            let Some((status, _)) = desired(node, None, &self.running, open, cutoff) else {
                continue;
            };
            if !matches!(status, Status::InReview | Status::InProgress) {
                continue;
            }
            if let Some(issues) = node["closingIssuesReferences"]["nodes"].as_array() {
                for issue in issues {
                    if issue["repository"]["nameWithOwner"] != REPOSITORY {
                        continue;
                    }
                    let Some(issue_number) = issue["number"].as_u64() else {
                        continue;
                    };
                    if !self.nodes.contains_key(&issue_number) {
                        continue;
                    }
                    let existing = decisions.get(&issue_number).map(|d| d.0);
                    if existing == Some(Status::Done) || existing == Some(Status::InReview) {
                        continue;
                    }
                    decisions.insert(
                        issue_number,
                        (status, format!("closing PR #{number} is {}", status.name())),
                    );
                }
            }
        }
        self.nodes
            .iter()
            .filter_map(|(number, node)| {
                let content = node["id"].as_str()?;
                let item = self.items.get(content);
                let from = item.and_then(|i| i.1);
                let decision = decisions.get(number);
                let to = decision.map(|d| d.0);
                if item.is_some() && (to.is_none() || to == from) {
                    return None;
                }
                // Closed repository items outside this board are not in the census.
                Some(Change {
                    number: *number,
                    content: content.into(),
                    item: item.map(|i| i.0.clone()),
                    from,
                    to,
                    reason: decision.map_or_else(
                        || "open repository item missing from board; leave status unset".into(),
                        |d| d.1.clone(),
                    ),
                })
            })
            .collect()
    }

    fn open_numbers(&self, api: &mut impl Api) -> Result<BTreeSet<u64>, ScalerError> {
        let mut open: BTreeSet<_> = self
            .nodes
            .iter()
            .filter(|(_, n)| n["closed"] == false)
            .map(|(n, _)| *n)
            .collect();
        let missing: BTreeSet<_> = self
            .nodes
            .values()
            .filter_map(blocker)
            .filter(|n| !self.nodes.contains_key(n))
            .collect();
        let numbers: Vec<_> = missing.into_iter().collect();
        for batch in numbers.chunks(50) {
            let fields = batch.iter().map(|n| format!("n{n}:issueOrPullRequest(number:{n}) {{ ... on Issue {{ closed }} ... on PullRequest {{ closed }} }}")).collect::<Vec<_>>().join(" ");
            let data = graphql(
                api,
                &format!(
                    r#"query {{ repository(owner:"carrick-sh",name:"carrick") {{ {fields} }} }}"#
                ),
                json!({}),
            )?;
            for number in batch {
                let closed = data["repository"][format!("n{number}")]["closed"]
                    .as_bool()
                    .ok_or(ScalerError::Guard("director blocker does not resolve"))?;
                if !closed {
                    open.insert(*number);
                }
            }
        }
        Ok(open)
    }
}

fn execute_plan(
    snapshot: &Snapshot,
    plan: &[Change],
    apply: bool,
    writer: &mut dyn Write,
    mut mutate: impl FnMut(&str, Value) -> Result<Value, ScalerError>,
) -> Result<(), ScalerError> {
    // Print every proposed change before the first mutation. The same immutable
    // plan drives both modes; apply does not perform a second, divergent census.
    for change in plan {
        writeln!(writer, "{}", serde_json::to_string(change)?)?;
    }
    writer.flush()?;
    if !apply {
        return Ok(());
    }
    for change in plan {
        let item = if let Some(item) = &change.item {
            item.clone()
        } else {
            let data = mutate(
                "mutation($project:ID!,$content:ID!) { addProjectV2ItemById(input:{projectId:$project,contentId:$content}) { item { id } } }",
                json!({"project":snapshot.project,"content":change.content}),
            )?;
            string(&data["addProjectV2ItemById"]["item"]["id"])?.into()
        };
        if let Some(status) = change.to {
            let option = snapshot
                .options
                .get(&status.name())
                .ok_or(ScalerError::Guard("missing planned Status option"))?;
            mutate(
                "mutation($project:ID!,$item:ID!,$field:ID!,$option:String!) { updateProjectV2ItemFieldValue(input:{projectId:$project,itemId:$item,fieldId:$field,value:{singleSelectOptionId:$option}}) { projectV2Item { id } } }",
                json!({"project":snapshot.project,"item":item,"field":snapshot.field,"option":option}),
            )?;
        }
    }
    Ok(())
}

pub fn run(args: Args, writer: &mut dyn Write) -> Result<(), ScalerError> {
    let BoardCommand::Reconcile { apply } = args.command;
    let mut api = Github;
    let snapshot = Snapshot::load(&mut api)?;
    let open = snapshot.open_numbers(&mut api)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| ScalerError::Guard("clock before Unix epoch"))?
        .as_secs();
    let plan = snapshot.plan(now.saturating_sub(86400), &open);
    execute_plan(&snapshot, &plan, apply, writer, |query, variables| {
        graphql(&mut api, query, variables)
    })
}

impl Snapshot {
    fn complete_connections(&mut self, api: &mut impl Api) -> Result<(), ScalerError> {
        loop {
            let mut pending = Vec::new();
            for (number, node) in &self.nodes {
                for connection in ["comments", "reviews", "closingIssuesReferences"] {
                    if node.get(connection).is_some() && has_next(&node[connection])? {
                        pending.push((*number, connection));
                    }
                }
            }
            if pending.is_empty() {
                return Ok(());
            }
            // Nested connection continuations remain batched issue queries too.
            for batch in pending.chunks(25) {
                let mut definitions = Vec::new();
                let mut fields = Vec::new();
                let mut variables = serde_json::Map::new();
                for (index, (number, connection)) in batch.iter().enumerate() {
                    let node = &self.nodes[number];
                    let typename = match node["__typename"].as_str() {
                        Some("Issue") => "Issue",
                        Some("PullRequest") => "PullRequest",
                        _ => return Err(ScalerError::Guard("invalid board content type")),
                    };
                    let selection = match *connection {
                        "comments" => "author { login } body createdAt",
                        "reviews" => "state body submittedAt commit { oid }",
                        _ => "id number repository { nameWithOwner }",
                    };
                    definitions.push(format!("$id{index}:ID!,$cursor{index}:String!"));
                    variables.insert(format!("id{index}"), node["id"].clone());
                    variables.insert(
                        format!("cursor{index}"),
                        Value::String(string(&node[connection]["pageInfo"]["endCursor"])?.into()),
                    );
                    fields.push(format!("n{index}:node(id:$id{index}) {{ ... on {typename} {{ {connection}(first:100,after:$cursor{index}) {{ pageInfo {{ hasNextPage endCursor }} nodes {{ {selection} }} }} }} }}"));
                }
                let data = graphql(
                    api,
                    &format!(
                        "query({}) {{ {} }}",
                        definitions.join(","),
                        fields.join(" ")
                    ),
                    variables.into(),
                )?;
                for (index, (number, connection)) in batch.iter().enumerate() {
                    let next = &data[format!("n{index}")][connection];
                    has_next(next)?;
                    let node = self
                        .nodes
                        .get_mut(number)
                        .ok_or(ScalerError::Guard("missing paginated item"))?;
                    if node[connection]["pageInfo"]["endCursor"] == next["pageInfo"]["endCursor"]
                        && has_next(next)?
                    {
                        return Err(ScalerError::Guard("board pagination did not advance"));
                    }
                    let next_rows = array(&next["nodes"])?;
                    node[*connection]["nodes"]
                        .as_array_mut()
                        .ok_or(ScalerError::Guard("missing accumulated board nodes"))?
                        .extend(next_rows.iter().cloned());
                    node[*connection]["pageInfo"] = next["pageInfo"].clone();
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
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
                timestamp("2026-11-06T00:00:00Z").unwrap()
            )
            .unwrap()
            .0,
            Status::InProgress
        );
        let mut snapshot = snapshot();
        snapshot.nodes.remove(&100);
        let plan = snapshot.plan(0, &BTreeSet::from([887]));
        assert_eq!(plan.len(), 1);
        assert_eq!(plan[0].number, 887);
        assert_eq!(plan[0].to, Some(Status::InProgress));
    }
    #[test]
    fn recorded_rule_fixtures() {
        let fixtures: Vec<Value> =
            serde_json::from_str(include_str!("fixtures/board/rules.json")).unwrap();
        for case in fixtures {
            let current: Option<Status> = serde_json::from_value(case["current"].clone()).unwrap();
            let expected: Option<Status> =
                serde_json::from_value(case["expected"].clone()).unwrap();
            let running: BTreeSet<u64> = serde_json::from_value(case["running"].clone()).unwrap();
            let open: BTreeSet<u64> = serde_json::from_value(case["open"].clone()).unwrap();
            let actual = desired(
                &case["node"],
                current,
                &running,
                &open,
                timestamp("2026-11-06T00:00:00Z").unwrap(),
            )
            .map(|d| d.0);
            assert_eq!(actual, expected, "{}", case["name"]);
        }
    }

    fn snapshot() -> Snapshot {
        let issue: Value =
            serde_json::from_str(include_str!("fixtures/board/running-887.json")).unwrap();
        let cases: Vec<Value> =
            serde_json::from_str(include_str!("fixtures/board/rules.json")).unwrap();
        let pr = cases
            .iter()
            .find(|case| case["name"] == "ready PR")
            .unwrap()["node"]
            .clone();
        Snapshot {
            project: "project".into(),
            field: "field".into(),
            options: [
                Status::Todo,
                Status::InProgress,
                Status::InReview,
                Status::Blocked,
                Status::Done,
            ]
            .into_iter()
            .map(|s| (s.name(), format!("option-{}", s.name())))
            .collect(),
            items: BTreeMap::from([("I_887".into(), ("item-887".into(), Some(Status::Blocked)))]),
            nodes: BTreeMap::from([(887, issue), (100, pr)]),
            running: BTreeSet::from([887]),
        }
    }

    #[test]
    fn closing_issue_advances_and_missing_pr_is_added() {
        let snapshot = snapshot();
        let plan = snapshot.plan(
            timestamp("2026-11-06T00:00:00Z").unwrap(),
            &BTreeSet::from([887, 100]),
        );
        assert_eq!(plan.len(), 2);
        assert!(plan.iter().all(|c| c.to == Some(Status::InReview)));
        assert!(
            plan.iter()
                .find(|c| c.number == 100)
                .unwrap()
                .item
                .is_none()
        );
        assert!(
            plan.iter()
                .find(|c| c.number == 887)
                .unwrap()
                .reason
                .contains("#100")
        );
    }

    #[test]
    fn closing_pr_never_reopens_done_issue() {
        let mut snapshot = snapshot();
        snapshot.items.get_mut("I_887").unwrap().1 = Some(Status::Done);
        let plan = snapshot.plan(0, &BTreeSet::from([887, 100]));
        assert_eq!(plan.len(), 1);
        assert_eq!(plan[0].number, 100);
    }

    #[test]
    fn done_pr_protection_does_not_hide_review_facts_from_its_issue() {
        let mut snapshot = snapshot();
        snapshot
            .items
            .insert("PR_test".into(), ("item-pr".into(), Some(Status::Done)));
        let plan = snapshot.plan(0, &BTreeSet::from([887, 100]));
        assert_eq!(plan.len(), 1);
        assert_eq!(plan[0].number, 887);
        assert_eq!(plan[0].to, Some(Status::InReview));
    }

    #[test]
    fn dry_run_never_writes_apply_only_writes_the_printed_plan() {
        let snapshot = snapshot();
        let plan = snapshot.plan(0, &BTreeSet::from([887, 100]));
        let mut dry = Vec::new();
        execute_plan(&snapshot, &plan, false, &mut dry, |_, _| {
            Err(ScalerError::Guard("dry run attempted mutation"))
        })
        .unwrap();
        let printed: Vec<Value> = String::from_utf8(dry.clone())
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(printed.len(), plan.len());
        let mut calls = Vec::new();
        let mut applied = Vec::new();
        execute_plan(&snapshot, &plan, true, &mut applied, |query, variables| {
            calls.push((query.to_owned(), variables));
            Ok(json!({"addProjectV2ItemById":{"item":{"id":"added-pr"}}}))
        })
        .unwrap();
        assert_eq!(applied, dry);
        assert_eq!(calls.len(), 3);
        assert_eq!(calls[0].1["content"], "PR_test");
        assert_eq!(calls[1].1["item"], "added-pr");
        assert_eq!(calls[2].1["item"], "item-887");
        assert!(
            calls[1..]
                .iter()
                .all(|c| c.1["option"] == "option-In review")
        );
    }

    #[test]
    fn progress_propagates_and_unclassified_items_keep_status() {
        let mut snapshot = snapshot();
        snapshot.nodes.get_mut(&100).unwrap()["isDraft"] = true.into();
        snapshot.nodes.get_mut(&100).unwrap()["updatedAt"] = "2026-11-07T00:00:00Z".into();
        assert!(
            snapshot
                .plan(0, &BTreeSet::from([887, 100]))
                .iter()
                .all(|c| c.to == Some(Status::InProgress))
        );
        snapshot.running.clear();
        snapshot.nodes.remove(&100);
        snapshot.nodes.get_mut(&887).unwrap()["comments"] = json!({"nodes":[]});
        assert!(snapshot.plan(0, &BTreeSet::from([887])).is_empty());
        snapshot.items.clear();
        let plan = snapshot.plan(0, &BTreeSet::from([887]));
        assert_eq!(plan.len(), 1);
        assert_eq!(plan[0].to, None);
    }

    #[test]
    fn timestamp_rejects_malformed_dates_and_handles_leap_days() {
        assert_eq!(timestamp("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(
            timestamp("2024-03-01T00:00:00Z").unwrap() - timestamp("2024-02-28T00:00:00Z").unwrap(),
            172800
        );
        assert_eq!(timestamp("2026-02-29T00:00:00Z"), None);
        assert_eq!(timestamp("2026-11-07T24:00:00Z"), None);
    }
    struct Replay {
        steps: std::collections::VecDeque<Value>,
    }
    impl Api for Replay {
        fn request(
            &mut self,
            method: &str,
            endpoint: &str,
            body: Option<Value>,
            paginate: bool,
        ) -> Result<Value, ScalerError> {
            let expected = self.steps.pop_front().unwrap();
            assert_eq!(method, expected["method"].as_str().unwrap());
            assert_eq!(endpoint, expected["endpoint"].as_str().unwrap());
            if endpoint == "graphql" {
                assert!(!paginate);
                let body = body.unwrap();
                let query = body["query"].as_str().unwrap();
                assert!(
                    query.contains(expected["contains"].as_str().unwrap()),
                    "{query}"
                );
                assert!(!query.contains("mutation"), "census must be read-only");
                if !expected["variables"].is_null() {
                    assert_eq!(body["variables"], expected["variables"]);
                }
            } else {
                assert!(paginate);
            }
            Ok(expected["response"].clone())
        }
    }

    #[test]
    fn recorded_api_census_paginates_batches_and_builds_known_plan() {
        let steps = serde_json::from_str(include_str!("fixtures/board/api-replay.json")).unwrap();
        let mut api = Replay { steps };
        let snapshot = Snapshot::load(&mut api).unwrap();
        assert!(api.steps.is_empty());
        assert_eq!(snapshot.running, BTreeSet::from([887]));
        assert!(
            !snapshot.nodes.contains_key(&777),
            "Done items need no history queries"
        );
        let open = snapshot.open_numbers(&mut api).unwrap();
        let plan = snapshot.plan(timestamp("2026-11-06T00:00:00Z").unwrap(), &open);
        assert_eq!(
            plan.iter().map(|c| (c.number, c.to)).collect::<Vec<_>>(),
            vec![
                (100, Some(Status::InReview)),
                (887, Some(Status::InReview)),
                (999, Some(Status::Done))
            ]
        );
        let mut output = Vec::new();
        execute_plan(&snapshot, &plan, false, &mut output, |_, _| {
            Err(ScalerError::Guard("dry run wrote"))
        })
        .unwrap();
        assert_eq!(String::from_utf8(output).unwrap().lines().count(), 3);
    }
    #[test]
    fn protected_open_pr_still_participates_in_the_api_census() {
        let mut steps: std::collections::VecDeque<Value> =
            serde_json::from_str(include_str!("fixtures/board/api-replay.json")).unwrap();
        steps[0]["response"]["data"]["organization"]["projectV2"]["items"]["nodes"].as_array_mut().unwrap().push(json!({"id":"item-pr", "content":{"id":"PR_test","number":100,"repository":{"nameWithOwner":REPOSITORY}}, "fieldValueByName":{"name":"Done"}}));
        let mut api = Replay { steps };
        let snapshot = Snapshot::load(&mut api).unwrap();
        let open = snapshot.open_numbers(&mut api).unwrap();
        let plan = snapshot.plan(0, &open);
        assert_eq!(
            plan.iter().map(|c| c.number).collect::<Vec<_>>(),
            vec![887, 999]
        );
        assert_eq!(plan[0].to, Some(Status::InReview));
        assert!(api.steps.is_empty());
    }

    #[test]
    fn closed_blocker_is_looked_up_even_when_not_on_board() {
        let mut snapshot = snapshot();
        snapshot.nodes.remove(&100);
        snapshot.running.clear();
        snapshot.nodes.get_mut(&887).unwrap()["comments"]["nodes"].as_array_mut().unwrap().push(json!({"author":{"login":DISPATCH_OWNER},"createdAt":"2026-11-07T00:00:00Z","body":"waits on #200"}));
        let mut api = Replay {
            steps: std::collections::VecDeque::from([
                json!({"method":"POST","endpoint":"graphql","contains":"n200:issueOrPullRequest(number:200)","response":{"data":{"repository":{"n200":{"closed":true}}}}}),
            ]),
        };
        let open = snapshot.open_numbers(&mut api).unwrap();
        let plan = snapshot.plan(0, &open);
        assert_eq!(plan.len(), 1);
        assert_eq!(plan[0].to, Some(Status::Todo));
        assert!(plan[0].reason.contains("#200"));
        assert!(api.steps.is_empty());
    }

    #[test]
    fn pagination_refuses_missing_or_repeated_cursors() {
        assert!(next_cursor(&json!({"pageInfo":{"endCursor":"same"}}), &json!("same")).is_err());
        assert!(next_cursor(&json!({"pageInfo":{"endCursor":null}}), &Value::Null).is_err());
    }
}
