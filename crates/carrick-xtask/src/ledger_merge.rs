use serde::de::{MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use thiserror::Error;
pub const ALLOWED_PROBE_INVENTORY_PATH: &str = "conformance-probes/probe-inventory.json";

pub fn normalize_repo_path(path: &str) -> String {
    let mut p = path.replace('\\', "/");
    while let Some(stripped) = p.strip_prefix("./") {
        p = stripped.to_string();
    }
    p
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParsedValue {
    Null,
    Bool(bool),
    Number(serde_json::Number),
    String(String),
    Array(Vec<ParsedValue>),
    Object(BTreeMap<String, ParsedValue>),
}

impl ParsedValue {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Self::Number(n) => n.as_u64(),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(b) => Some(*b),
            _ => None,
        }
    }

    pub fn as_object(&self) -> Option<&BTreeMap<String, ParsedValue>> {
        match self {
            Self::Object(m) => Some(m),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&Vec<ParsedValue>> {
        match self {
            Self::Array(a) => Some(a),
            _ => None,
        }
    }
}

impl Serialize for ParsedValue {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Null => serializer.serialize_unit(),
            Self::Bool(b) => serializer.serialize_bool(*b),
            Self::Number(n) => n.serialize(serializer),
            Self::String(s) => serializer.serialize_str(s),
            Self::Array(a) => a.serialize(serializer),
            Self::Object(o) => o.serialize(serializer),
        }
    }
}

struct ParsedValueVisitor;

impl<'de> Visitor<'de> for ParsedValueVisitor {
    type Value = ParsedValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("any valid JSON value")
    }

    fn visit_bool<E>(self, v: bool) -> Result<Self::Value, E> {
        Ok(ParsedValue::Bool(v))
    }

    fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E> {
        Ok(ParsedValue::Number(serde_json::Number::from(v)))
    }

    fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E> {
        Ok(ParsedValue::Number(serde_json::Number::from(v)))
    }

    fn visit_f64<E>(self, v: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        serde_json::Number::from_f64(v)
            .map(ParsedValue::Number)
            .ok_or_else(|| serde::de::Error::custom("invalid float value"))
    }

    fn visit_i128<E>(self, v: i128) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        if let Ok(v64) = i64::try_from(v) {
            Ok(ParsedValue::Number(serde_json::Number::from(v64)))
        } else {
            use std::str::FromStr;
            serde_json::Number::from_str(&v.to_string())
                .map(ParsedValue::Number)
                .map_err(serde::de::Error::custom)
        }
    }

    fn visit_u128<E>(self, v: u128) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        if let Ok(v64) = u64::try_from(v) {
            Ok(ParsedValue::Number(serde_json::Number::from(v64)))
        } else {
            use std::str::FromStr;
            serde_json::Number::from_str(&v.to_string())
                .map(ParsedValue::Number)
                .map_err(serde::de::Error::custom)
        }
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E> {
        Ok(ParsedValue::String(v.to_owned()))
    }

    fn visit_string<E>(self, v: String) -> Result<Self::Value, E> {
        Ok(ParsedValue::String(v))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(ParsedValue::Null)
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        Deserialize::deserialize(deserializer)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(ParsedValue::Null)
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut list = Vec::new();
        while let Some(elem) = seq.next_element::<ParsedValue>()? {
            list.push(elem);
        }
        Ok(ParsedValue::Array(list))
    }

    fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
    where
        M: MapAccess<'de>,
    {
        let mut obj = BTreeMap::new();
        while let Some(key) = map.next_key::<String>()? {
            if obj.contains_key(&key) {
                return Err(serde::de::Error::custom(format!("duplicate key `{key}`")));
            }
            let val = map.next_value::<ParsedValue>()?;
            obj.insert(key, val);
        }
        Ok(ParsedValue::Object(obj))
    }
}

impl<'de> Deserialize<'de> for ParsedValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(ParsedValueVisitor)
    }
}

pub fn parse_json_with_duplicate_rejection(
    side: &str,
    input: &str,
) -> Result<ParsedValue, MergeConflict> {
    let mut de = serde_json::Deserializer::from_str(input);
    let val = ParsedValue::deserialize(&mut de).map_err(|err| {
        let msg = err.to_string();
        if let Some(pos) = msg.find("duplicate key `") {
            let rest = &msg[pos + "duplicate key `".len()..];
            if let Some(end_pos) = rest.find('`') {
                return MergeConflict::DuplicateJsonKey {
                    side: side.to_string(),
                    key: rest[..end_pos].to_string(),
                };
            }
        }
        MergeConflict::InvalidJson {
            side: side.to_string(),
            details: msg,
        }
    })?;
    de.end().map_err(|err| MergeConflict::InvalidJson {
        side: side.to_string(),
        details: err.to_string(),
    })?;
    Ok(val)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemanticSummary {
    pub rows_added: usize,
    pub rows_modified: usize,
    pub rows_deleted: usize,
    pub debt_ceiling_change: Option<(u64, u64)>,
}

impl fmt::Display for SemanticSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} added, {} modified, {} deleted",
            self.rows_added, self.rows_modified, self.rows_deleted
        )?;
        if let Some((old_ceiling, new_ceiling)) = self.debt_ceiling_change {
            write!(
                f,
                ", debt ceiling changed from {old_ceiling} to {new_ceiling}"
            )?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MergedLedger {
    pub json: String,
    pub summary: SemanticSummary,
}

impl MergedLedger {
    pub fn to_json(&self) -> &str {
        &self.json
    }

    pub fn summary(&self) -> &SemanticSummary {
        &self.summary
    }
}

impl fmt::Display for MergedLedger {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.json)
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum MergeConflict {
    #[error("unsupported ledger path '{0}'")]
    UnsupportedPath(String),

    #[error("invalid json in {side}: {details}")]
    InvalidJson { side: String, details: String },

    #[error("duplicate key '{key}' in {side} at object level")]
    DuplicateJsonKey { side: String, key: String },

    #[error("row validation failed in {side} for key '{key}': {reason}")]
    InvalidRow {
        side: String,
        key: String,
        reason: String,
    },

    #[error("conflict on row '{key}': ours={ours:?}, theirs={theirs:?}, base={base:?}")]
    RowConflict {
        key: String,
        base: Option<String>,
        ours: Option<String>,
        theirs: Option<String>,
    },

    #[error(
        "conflict on metadata field '{field}': ours={ours:?}, theirs={theirs:?}, base={base:?}"
    )]
    MetadataConflict {
        field: String,
        base: Option<String>,
        ours: Option<String>,
        theirs: Option<String>,
    },
}


fn validate_probe_row(side: &str, name: &str, row: &ParsedValue) -> Result<(), MergeConflict> {
    let obj = row.as_object().ok_or_else(|| MergeConflict::InvalidRow {
        side: side.to_string(),
        key: name.to_string(),
        reason: "probe row must be an object".to_string(),
    })?;

    let class = obj.get("class").and_then(|v| v.as_str());
    if class.is_none() {
        return Err(MergeConflict::InvalidRow {
            side: side.to_string(),
            key: name.to_string(),
            reason: "missing or invalid 'class' string".to_string(),
        });
    }

    let excluded = obj.get("excluded").and_then(|v| v.as_bool());
    if excluded.is_none() {
        return Err(MergeConflict::InvalidRow {
            side: side.to_string(),
            key: name.to_string(),
            reason: "missing or invalid 'excluded' boolean".to_string(),
        });
    }

    let runner = obj.get("runner").and_then(|v| v.as_str());
    if runner.is_none() {
        return Err(MergeConflict::InvalidRow {
            side: side.to_string(),
            key: name.to_string(),
            reason: "missing or invalid 'runner' string".to_string(),
        });
    }

    if let Some(contract_ids) = obj.get("contract_ids") {
        let arr = contract_ids
            .as_array()
            .ok_or_else(|| MergeConflict::InvalidRow {
                side: side.to_string(),
                key: name.to_string(),
                reason: "'contract_ids' must be an array".to_string(),
            })?;
        for elem in arr {
            if elem.as_str().is_none() {
                return Err(MergeConflict::InvalidRow {
                    side: side.to_string(),
                    key: name.to_string(),
                    reason: "'contract_ids' elements must be strings".to_string(),
                });
            }
        }
    }

    Ok(())
}

fn format_value_preview(val: &Option<ParsedValue>) -> Option<String> {
    val.as_ref()
        .map(|v| serde_json::to_string(v).unwrap_or_else(|_| "<unprintable>".to_string()))
}

struct ProbeFileLayout {
    prefix: String,
    suffix: String,
    entries: Vec<(String, String)>,
}

fn extract_probe_file_layout(text: &str) -> Option<ProbeFileLayout> {
    let open_brace = text.find('{')?;
    let close_brace = text.rfind('}')?;

    let mut pos = open_brace + 1;
    let mut items = Vec::new();
    while pos < close_brace {
        while pos < close_brace
            && text[pos..]
                .chars()
                .next()
                .is_some_and(|c| c.is_whitespace())
        {
            if let Some(ch) = text[pos..].chars().next() {
                pos += ch.len_utf8();
            } else {
                break;
            }
        }
        if pos >= close_brace {
            break;
        }
        let line_start = text[..pos].rfind('\n').map_or(0, |nl| nl + 1);
        let item_start = line_start;

        let colon_idx = text[pos..close_brace].find(':')? + pos;
        let val_open = text[colon_idx..close_brace].find('{')? + colon_idx;

        let mut depth = 0;
        let mut in_str = false;
        let mut esc = false;
        let mut item_end = None;
        for (i, c) in text[val_open..close_brace].char_indices() {
            let abs_i = val_open + i;
            if in_str {
                if esc {
                    esc = false;
                } else if c == '\\' {
                    esc = true;
                } else if c == '"' {
                    in_str = false;
                }
            } else if c == '"' {
                in_str = true;
            } else if c == '{' {
                depth += 1;
            } else if c == '}' {
                depth -= 1;
                if depth == 0 {
                    item_end = Some(abs_i + 1);
                    break;
                }
            }
        }
        let item_end = item_end?;
        let raw_snippet = text[item_start..item_end].to_string();

        let key_str = text[pos..colon_idx].trim().trim_matches('"').to_string();
        items.push((key_str, raw_snippet, item_start, item_end));

        pos = item_end;
        while pos < close_brace
            && text[pos..]
                .chars()
                .next()
                .is_some_and(|c| c.is_whitespace() || c == ',')
        {
            if let Some(ch) = text[pos..].chars().next() {
                pos += ch.len_utf8();
            } else {
                break;
            }
        }
    }

    if items.is_empty() {
        let prefix = text[..open_brace + 1].to_string();
        let suffix = text[close_brace..].to_string();
        Some(ProbeFileLayout {
            prefix,
            suffix,
            entries: Vec::new(),
        })
    } else {
        let first_start = items[0].2;
        let last_end = items.last().map_or(first_start, |it| it.3);
        let prefix = text[..first_start].to_string();
        let suffix = text[last_end..].to_string();
        let entries = items.into_iter().map(|(k, s, _, _)| (k, s)).collect();
        Some(ProbeFileLayout {
            prefix,
            suffix,
            entries,
        })
    }
}

pub fn merge_ledger(
    path: &str,
    base: &str,
    ours: &str,
    theirs: &str,
) -> Result<MergedLedger, MergeConflict> {
    let norm_path = normalize_repo_path(path);

    if norm_path == ALLOWED_PROBE_INVENTORY_PATH {
        return merge_probe_inventory(base, ours, theirs);
    }

    Err(MergeConflict::UnsupportedPath(norm_path))
}

fn merge_probe_inventory(
    base: &str,
    ours: &str,
    theirs: &str,
) -> Result<MergedLedger, MergeConflict> {
    let base_parsed = parse_json_with_duplicate_rejection("base", base)?;
    let ours_parsed = parse_json_with_duplicate_rejection("ours", ours)?;
    let theirs_parsed = parse_json_with_duplicate_rejection("theirs", theirs)?;

    let base_obj = base_parsed
        .as_object()
        .ok_or_else(|| MergeConflict::InvalidRow {
            side: "base".to_string(),
            key: "<root>".to_string(),
            reason: "probe inventory must be an object".to_string(),
        })?;
    let ours_obj = ours_parsed
        .as_object()
        .ok_or_else(|| MergeConflict::InvalidRow {
            side: "ours".to_string(),
            key: "<root>".to_string(),
            reason: "probe inventory must be an object".to_string(),
        })?;
    let theirs_obj = theirs_parsed
        .as_object()
        .ok_or_else(|| MergeConflict::InvalidRow {
            side: "theirs".to_string(),
            key: "<root>".to_string(),
            reason: "probe inventory must be an object".to_string(),
        })?;

    for (k, v) in base_obj {
        validate_probe_row("base", k, v)?;
    }
    for (k, v) in ours_obj {
        validate_probe_row("ours", k, v)?;
    }
    for (k, v) in theirs_obj {
        validate_probe_row("theirs", k, v)?;
    }

    let mut all_keys = BTreeSet::new();
    all_keys.extend(base_obj.keys());
    all_keys.extend(ours_obj.keys());
    all_keys.extend(theirs_obj.keys());

    let mut merged_probes = BTreeMap::new();
    let mut rows_added = 0;
    let mut rows_modified = 0;
    let mut rows_deleted = 0;

    for key in all_keys {
        let b = base_obj.get(key);
        let o = ours_obj.get(key);
        let t = theirs_obj.get(key);

        if o == t {
            if let Some(val) = o {
                if b.is_none() {
                    rows_added += 1;
                } else if b != Some(val) {
                    rows_modified += 1;
                }
                merged_probes.insert(key.clone(), val.clone());
            } else if b.is_some() {
                rows_deleted += 1;
            }
        } else if o == b {
            // Ours equals base, take theirs
            if let Some(val) = t {
                if b.is_none() {
                    rows_added += 1;
                } else {
                    rows_modified += 1;
                }
                merged_probes.insert(key.clone(), val.clone());
            } else {
                rows_deleted += 1;
            }
        } else if t == b {
            // Theirs equals base, take ours
            if let Some(val) = o {
                if b.is_none() {
                    rows_added += 1;
                } else {
                    rows_modified += 1;
                }
                merged_probes.insert(key.clone(), val.clone());
            } else {
                rows_deleted += 1;
            }
        } else {
            // Divergent conflict
            return Err(MergeConflict::RowConflict {
                key: key.clone(),
                base: format_value_preview(&b.cloned()),
                ours: format_value_preview(&o.cloned()),
                theirs: format_value_preview(&t.cloned()),
            });
        }
    }

    let ours_layout = extract_probe_file_layout(ours);
    let theirs_layout = extract_probe_file_layout(theirs);

    let output_json = match (ours_layout, theirs_layout) {
        (Some(ours_lay), Some(theirs_lay)) => {
            let ours_snippets: BTreeMap<String, String> =
                ours_lay.entries.iter().cloned().collect();
            let theirs_snippets: BTreeMap<String, String> =
                theirs_lay.entries.iter().cloned().collect();

            let mut merged_keys: Vec<String> = Vec::new();
            for (k, _) in &ours_lay.entries {
                if merged_probes.contains_key(k) {
                    merged_keys.push(k.clone());
                }
            }

            let theirs_keys: Vec<String> =
                theirs_lay.entries.iter().map(|(k, _)| k.clone()).collect();
            for (t_idx, t_add) in theirs_keys.iter().enumerate() {
                if merged_keys.contains(t_add) {
                    continue;
                }
                if !merged_probes.contains_key(t_add) {
                    continue;
                }

                let mut found_preceding = None;
                for p_idx in (0..t_idx).rev() {
                    let candidate = &theirs_keys[p_idx];
                    if merged_keys.contains(candidate) {
                        found_preceding = Some(candidate.clone());
                        break;
                    }
                }

                match found_preceding {
                    None => merged_keys.push(t_add.clone()),
                    Some(p) => {
                        let p_pos = merged_keys
                            .iter()
                            .position(|k| k == &p)
                            .unwrap_or(merged_keys.len());
                        let insert_pos = if p_pos < merged_keys.len() {
                            p_pos + 1
                        } else {
                            merged_keys.len()
                        };
                        merged_keys.insert(insert_pos, t_add.clone());
                    }
                }
            }

            let mut snippets = Vec::new();
            for k in &merged_keys {
                if let Some(snip) = ours_snippets.get(k) {
                    // Check if ours value was modified
                    if ours_obj.get(k) == merged_probes.get(k) {
                        snippets.push(snip.clone());
                    } else if let Some(th_snip) = theirs_snippets.get(k) {
                        snippets.push(th_snip.clone());
                    } else {
                        let val = &merged_probes[k];
                        let val_str = serde_json::to_string_pretty(val).unwrap_or_default();
                        snippets.push(format!("  \"{k}\": {val_str}"));
                    }
                } else if let Some(snip) = theirs_snippets.get(k) {
                    snippets.push(snip.clone());
                } else {
                    let val = &merged_probes[k];
                    let val_str = serde_json::to_string_pretty(val).unwrap_or_default();
                    snippets.push(format!("  \"{k}\": {val_str}"));
                }
            }

            let mut out = String::new();
            out.push_str(&ours_lay.prefix);
            for (i, s) in snippets.iter().enumerate() {
                if i > 0 {
                    out.push_str(",\n");
                }
                out.push_str(s);
            }
            out.push_str(&ours_lay.suffix);
            out
        }
        _ => {
            let serialized = serde_json::to_string_pretty(&merged_probes).map_err(|e| {
                MergeConflict::InvalidJson {
                    side: "merged".to_string(),
                    details: e.to_string(),
                }
            })?;
            format!("{serialized}\n")
        }
    };

    Ok(MergedLedger {
        json: output_json,
        summary: SemanticSummary {
            rows_added,
            rows_modified,
            rows_deleted,
            debt_ceiling_change: None,
        },
    })
}

