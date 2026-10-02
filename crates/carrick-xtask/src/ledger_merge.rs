use serde::de::{MapAccess, SeqAccess, Visitor};
use serde::ser::SerializeMap;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::Path;
use thiserror::Error;

use crate::command::{CommandError, CommandOutput};

pub const ALLOWED_PROBE_INVENTORY_PATH: &str = "conformance-probes/probe-inventory.json";
pub const CONTRACTS_INVENTORY_PATH: &str = "conformance-contracts/inventory.json";

pub const ALLOWED_ABORT_SHARDS: &[(&str, &str)] = &[
    ("scripts/migrate/runtime-aborts/hvf.json", "hvf.json"),
    (
        "scripts/migrate/runtime-aborts/vcpu-loop.json",
        "vcpu-loop.json",
    ),
    (
        "scripts/migrate/runtime-aborts/runtime.json",
        "runtime.json",
    ),
    ("scripts/migrate/runtime-aborts/other.json", "other.json"),
];

const EXCLUDED_CRATE_PREFIXES: &[&str] = &[
    "crates/carrick-conformance",
    "crates/carrick-fatal",
    "crates/carrick-dsr",
    "crates/carrick-native-darwin",
];

pub fn normalize_repo_path(path: &str) -> String {
    let mut p = path.replace('\\', "/");
    while let Some(stripped) = p.strip_prefix("./") {
        p = stripped.to_string();
    }
    p
}

pub fn route_shard(file_path: &str) -> Result<&'static str, String> {
    let posix_str = file_path.replace('\\', "/");
    for ex in EXCLUDED_CRATE_PREFIXES {
        if posix_str.starts_with(ex) {
            return Err(format!("file is in excluded crate: {file_path}"));
        }
    }
    if posix_str.contains("crates/carrick-runtime/src/vcpu_loop") {
        return Ok("vcpu-loop.json");
    }
    if posix_str.contains("crates/carrick-kernel/src") {
        return Ok("runtime.json");
    }
    if posix_str.contains("crates/carrick-runtime/src") {
        return Ok("runtime.json");
    }
    if posix_str.contains("crates/carrick-vmm-hvf/src") {
        return Ok("hvf.json");
    }
    if posix_str.starts_with("crates/") {
        return Ok("other.json");
    }
    Err(format!("unknown shard for file: {file_path}"))
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
    #[error(
        "conformance-contracts/inventory.json is a generated artifact that requires regeneration via `ledger-regenerate-contracts`"
    )]
    GeneratedArtifactNeedsRegeneration { path: String },

    #[error("unsupported ledger path '{0}'")]
    UnsupportedPath(String),

    #[error("invalid json in {side}: {details}")]
    InvalidJson { side: String, details: String },

    #[error("duplicate key '{key}' in {side} at object level")]
    DuplicateJsonKey { side: String, key: String },

    #[error("duplicate abort row identity ({file}, {function}, {ordinal}) in {side}")]
    DuplicateAbortIdentity {
        side: String,
        file: String,
        function: String,
        ordinal: u64,
    },

    #[error("incompatible schema in {side}: expected 1, found {found}")]
    IncompatibleSchema { side: String, found: String },

    #[error("shard mismatch for '{path}': expected shard '{expected}', found '{actual}' in {side}")]
    WrongShard {
        side: String,
        path: String,
        expected: String,
        actual: String,
    },

    #[error("row validation failed in {side} for key '{key}': {reason}")]
    InvalidRow {
        side: String,
        key: String,
        reason: String,
    },

    #[error("divergent debt ceiling changes: base={base}, ours={ours}, theirs={theirs}")]
    DivergentDebtCeiling { base: u64, ours: u64, theirs: u64 },

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

#[derive(Debug, Error)]
pub enum RegenerateError {
    #[error("invalid path: {0}")]
    InvalidPath(String),

    #[error("generation failed during {stage}: {error}")]
    GenerationFailed { stage: &'static str, error: String },
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AbortKey {
    pub file: String,
    pub function: String,
    pub ordinal_in_function: u64,
}

impl fmt::Display for AbortKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}:{}",
            self.file, self.function, self.ordinal_in_function
        )
    }
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

fn validate_abort_row(
    side: &str,
    path: &str,
    expected_shard: &str,
    row: &ParsedValue,
) -> Result<(AbortKey, ParsedValue), MergeConflict> {
    let obj = row.as_object().ok_or_else(|| MergeConflict::InvalidRow {
        side: side.to_string(),
        key: "<unknown>".to_string(),
        reason: "row must be an object".to_string(),
    })?;

    let file =
        obj.get("file")
            .and_then(|v| v.as_str())
            .ok_or_else(|| MergeConflict::InvalidRow {
                side: side.to_string(),
                key: "<unknown>".to_string(),
                reason: "missing or invalid 'file'".to_string(),
            })?;
    if file.is_empty() {
        return Err(MergeConflict::InvalidRow {
            side: side.to_string(),
            key: "<unknown>".to_string(),
            reason: "'file' cannot be empty".to_string(),
        });
    }

    let function = obj
        .get("function")
        .and_then(|v| v.as_str())
        .ok_or_else(|| MergeConflict::InvalidRow {
            side: side.to_string(),
            key: file.to_string(),
            reason: "missing or invalid 'function'".to_string(),
        })?;
    if function.is_empty() {
        return Err(MergeConflict::InvalidRow {
            side: side.to_string(),
            key: file.to_string(),
            reason: "'function' cannot be empty".to_string(),
        });
    }

    let ordinal = obj
        .get("ordinal_in_function")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MergeConflict::InvalidRow {
            side: side.to_string(),
            key: format!("{file}:{function}"),
            reason: "missing or invalid 'ordinal_in_function' (must be integer >= 1)".to_string(),
        })?;
    if ordinal < 1 {
        return Err(MergeConflict::InvalidRow {
            side: side.to_string(),
            key: format!("{file}:{function}"),
            reason: "'ordinal_in_function' must be >= 1".to_string(),
        });
    }

    let key = AbortKey {
        file: file.to_string(),
        function: function.to_string(),
        ordinal_in_function: ordinal,
    };
    let key_str = key.to_string();

    let fp = obj
        .get("fingerprint")
        .and_then(|v| v.as_str())
        .ok_or_else(|| MergeConflict::InvalidRow {
            side: side.to_string(),
            key: key_str.clone(),
            reason: "missing or invalid 'fingerprint'".to_string(),
        })?;
    if fp.is_empty() {
        return Err(MergeConflict::InvalidRow {
            side: side.to_string(),
            key: key_str.clone(),
            reason: "'fingerprint' cannot be empty".to_string(),
        });
    }

    let routed = route_shard(file).map_err(|_| MergeConflict::WrongShard {
        side: side.to_string(),
        path: path.to_string(),
        expected: expected_shard.to_string(),
        actual: "unknown".to_string(),
    })?;
    if routed != expected_shard {
        return Err(MergeConflict::WrongShard {
            side: side.to_string(),
            path: path.to_string(),
            expected: expected_shard.to_string(),
            actual: routed.to_string(),
        });
    }

    let verdict =
        obj.get("verdict")
            .and_then(|v| v.as_str())
            .ok_or_else(|| MergeConflict::InvalidRow {
                side: side.to_string(),
                key: key_str.clone(),
                reason: "missing or invalid 'verdict'".to_string(),
            })?;
    if verdict != "carrier_fault" && verdict != "typed_error_debt" {
        return Err(MergeConflict::InvalidRow {
            side: side.to_string(),
            key: key_str.clone(),
            reason: format!("invalid verdict '{verdict}'"),
        });
    }

    let rationale = obj
        .get("rationale")
        .and_then(|v| v.as_str())
        .ok_or_else(|| MergeConflict::InvalidRow {
            side: side.to_string(),
            key: key_str.clone(),
            reason: "missing or invalid 'rationale'".to_string(),
        })?;
    if rationale.trim().is_empty() {
        return Err(MergeConflict::InvalidRow {
            side: side.to_string(),
            key: key_str.clone(),
            reason: "'rationale' cannot be empty".to_string(),
        });
    }

    let failure_domain = obj
        .get("failure_domain")
        .and_then(|v| v.as_str())
        .ok_or_else(|| MergeConflict::InvalidRow {
            side: side.to_string(),
            key: key_str.clone(),
            reason: "missing or invalid 'failure_domain'".to_string(),
        })?;
    if failure_domain.trim().is_empty() {
        return Err(MergeConflict::InvalidRow {
            side: side.to_string(),
            key: key_str.clone(),
            reason: "'failure_domain' cannot be empty".to_string(),
        });
    }

    let sink =
        obj.get("sink")
            .and_then(|v| v.as_str())
            .ok_or_else(|| MergeConflict::InvalidRow {
                side: side.to_string(),
                key: key_str.clone(),
                reason: "missing or invalid 'sink'".to_string(),
            })?;
    if sink != "raw" && sink != "fatal" {
        return Err(MergeConflict::InvalidRow {
            side: side.to_string(),
            key: key_str.clone(),
            reason: format!("invalid sink '{sink}'"),
        });
    }

    let domain = obj.get("domain");
    if sink == "fatal" {
        let d = domain
            .and_then(|v| v.as_str())
            .ok_or_else(|| MergeConflict::InvalidRow {
                side: side.to_string(),
                key: key_str.clone(),
                reason: "fatal sink requires non-empty string 'domain'".to_string(),
            })?;
        if d.trim().is_empty() {
            return Err(MergeConflict::InvalidRow {
                side: side.to_string(),
                key: key_str.clone(),
                reason: "'domain' cannot be empty".to_string(),
            });
        }
    } else if let Some(d) = domain
        && !matches!(d, ParsedValue::Null)
    {
        return Err(MergeConflict::InvalidRow {
            side: side.to_string(),
            key: key_str.clone(),
            reason: "raw sink must not specify 'domain'".to_string(),
        });
    }

    let typed_error = obj.get("typed_error");
    if verdict == "typed_error_debt" {
        let te = typed_error
            .and_then(|v| v.as_str())
            .ok_or_else(|| MergeConflict::InvalidRow {
                side: side.to_string(),
                key: key_str.clone(),
                reason: "typed_error_debt requires non-empty string 'typed_error'".to_string(),
            })?;
        if te.trim().is_empty() {
            return Err(MergeConflict::InvalidRow {
                side: side.to_string(),
                key: key_str.clone(),
                reason: "'typed_error' cannot be empty".to_string(),
            });
        }
    } else if let Some(te) = typed_error
        && !matches!(te, ParsedValue::Null)
    {
        return Err(MergeConflict::InvalidRow {
            side: side.to_string(),
            key: key_str,
            reason: "carrier_fault must not specify 'typed_error'".to_string(),
        });
    }

    Ok((key, row.clone()))
}

struct ParsedAbortLedger {
    schema: u64,
    shard: String,
    debt_ceiling: u64,
    extra_meta: BTreeMap<String, ParsedValue>,
    rows: BTreeMap<AbortKey, ParsedValue>,
}

fn parse_abort_ledger(
    side: &str,
    path: &str,
    expected_shard: &str,
    input: &str,
) -> Result<ParsedAbortLedger, MergeConflict> {
    let parsed = parse_json_with_duplicate_rejection(side, input)?;
    let obj = parsed
        .as_object()
        .ok_or_else(|| MergeConflict::InvalidRow {
            side: side.to_string(),
            key: "<root>".to_string(),
            reason: "top-level must be an object".to_string(),
        })?;

    let schema_val = obj
        .get("schema")
        .ok_or_else(|| MergeConflict::IncompatibleSchema {
            side: side.to_string(),
            found: "missing".to_string(),
        })?;
    let schema = schema_val
        .as_u64()
        .ok_or_else(|| MergeConflict::IncompatibleSchema {
            side: side.to_string(),
            found: serde_json::to_string(schema_val).unwrap_or_default(),
        })?;
    if schema != 1 {
        return Err(MergeConflict::IncompatibleSchema {
            side: side.to_string(),
            found: schema.to_string(),
        });
    }

    let shard_val = obj.get("shard").ok_or_else(|| MergeConflict::WrongShard {
        side: side.to_string(),
        path: path.to_string(),
        expected: expected_shard.to_string(),
        actual: "missing".to_string(),
    })?;
    let shard = shard_val
        .as_str()
        .ok_or_else(|| MergeConflict::WrongShard {
            side: side.to_string(),
            path: path.to_string(),
            expected: expected_shard.to_string(),
            actual: serde_json::to_string(shard_val).unwrap_or_default(),
        })?;
    if shard != expected_shard {
        return Err(MergeConflict::WrongShard {
            side: side.to_string(),
            path: path.to_string(),
            expected: expected_shard.to_string(),
            actual: shard.to_string(),
        });
    }

    let debt_ceiling_val =
        obj.get("typed_error_debt_ceiling")
            .ok_or_else(|| MergeConflict::InvalidRow {
                side: side.to_string(),
                key: "typed_error_debt_ceiling".to_string(),
                reason: "missing typed_error_debt_ceiling".to_string(),
            })?;
    let debt_ceiling = debt_ceiling_val
        .as_u64()
        .ok_or_else(|| MergeConflict::InvalidRow {
            side: side.to_string(),
            key: "typed_error_debt_ceiling".to_string(),
            reason: "typed_error_debt_ceiling must be a non-negative integer".to_string(),
        })?;

    let rows_val = obj.get("rows").ok_or_else(|| MergeConflict::InvalidRow {
        side: side.to_string(),
        key: "rows".to_string(),
        reason: "missing 'rows' array".to_string(),
    })?;
    let rows_arr = rows_val
        .as_array()
        .ok_or_else(|| MergeConflict::InvalidRow {
            side: side.to_string(),
            key: "rows".to_string(),
            reason: "'rows' must be an array".to_string(),
        })?;

    let mut rows_map = BTreeMap::new();
    for row in rows_arr {
        let (key, validated_row) = validate_abort_row(side, path, expected_shard, row)?;
        if rows_map.contains_key(&key) {
            return Err(MergeConflict::DuplicateAbortIdentity {
                side: side.to_string(),
                file: key.file,
                function: key.function,
                ordinal: key.ordinal_in_function,
            });
        }
        rows_map.insert(key, validated_row);
    }

    let mut extra_meta = BTreeMap::new();
    for (k, v) in obj {
        if k != "schema" && k != "shard" && k != "typed_error_debt_ceiling" && k != "rows" {
            extra_meta.insert(k.clone(), v.clone());
        }
    }

    Ok(ParsedAbortLedger {
        schema,
        shard: shard.to_string(),
        debt_ceiling,
        extra_meta,
        rows: rows_map,
    })
}

fn format_value_preview(val: &Option<ParsedValue>) -> Option<String> {
    val.as_ref()
        .map(|v| serde_json::to_string(v).unwrap_or_else(|_| "<unprintable>".to_string()))
}

struct AbortFileLayout {
    prefix: String,
    suffix: String,
    entries: Vec<(AbortKey, String)>,
}

fn extract_abort_file_layout(text: &str) -> Option<AbortFileLayout> {
    let rows_idx = text.find("\"rows\"")?;
    let colon_idx = text[rows_idx..].find(':')? + rows_idx;
    let open_bracket = text[colon_idx..].find('[')? + colon_idx;

    let mut depth = 0;
    let mut in_string = false;
    let mut escape = false;
    let mut close_bracket = None;
    for (i, c) in text[open_bracket..].char_indices() {
        let abs_i = open_bracket + i;
        if in_string {
            if escape {
                escape = false;
            } else if c == '\\' {
                escape = true;
            } else if c == '"' {
                in_string = false;
            }
        } else if c == '"' {
            in_string = true;
        } else if c == '[' {
            depth += 1;
        } else if c == ']' {
            depth -= 1;
            if depth == 0 {
                close_bracket = Some(abs_i);
                break;
            }
        }
    }
    let close_bracket = close_bracket?;

    let mut pos = open_bracket + 1;
    let mut items = Vec::new();
    while pos < close_bracket {
        while pos < close_bracket
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
        if pos >= close_bracket {
            break;
        }
        let line_start = text[..pos].rfind('\n').map_or(0, |nl| nl + 1);
        let item_start = line_start;

        let mut obj_depth = 0;
        let mut in_str = false;
        let mut esc = false;
        let mut item_end = None;
        for (i, c) in text[pos..close_bracket].char_indices() {
            let abs_i = pos + i;
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
                obj_depth += 1;
            } else if c == '}' {
                obj_depth -= 1;
                if obj_depth == 0 {
                    item_end = Some(abs_i + 1);
                    break;
                }
            }
        }
        let item_end = item_end?;
        let raw_snippet = text[item_start..item_end].to_string();

        let parsed_val: serde_json::Value = serde_json::from_str(&raw_snippet).ok()?;
        let file = parsed_val.get("file")?.as_str()?.to_string();
        let function = parsed_val.get("function")?.as_str()?.to_string();
        let ordinal = parsed_val.get("ordinal_in_function")?.as_u64()?;
        let key = AbortKey {
            file,
            function,
            ordinal_in_function: ordinal,
        };
        items.push((key, raw_snippet, item_start, item_end));

        pos = item_end;
        while pos < close_bracket
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
        let prefix = text[..open_bracket + 1].to_string();
        let suffix = text[close_bracket..].to_string();
        Some(AbortFileLayout {
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
        Some(AbortFileLayout {
            prefix,
            suffix,
            entries,
        })
    }
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

fn update_debt_ceiling_in_prefix(prefix: &str, old_val: u64, new_val: u64) -> String {
    if old_val == new_val {
        return prefix.to_string();
    }
    if let Some(pos) = prefix.find("\"typed_error_debt_ceiling\"")
        && let Some(colon_pos) = prefix[pos..].find(':')
    {
        let num_start_search = pos + colon_pos + 1;
        let mut num_start = None;
        let mut num_end = None;
        for (i, c) in prefix[num_start_search..].char_indices() {
            let abs_i = num_start_search + i;
            if c.is_ascii_digit() {
                if num_start.is_none() {
                    num_start = Some(abs_i);
                }
            } else if num_start.is_some() {
                num_end = Some(abs_i);
                break;
            }
        }
        if let (Some(start), Some(end)) = (num_start, num_end) {
            let mut updated = prefix[..start].to_string();
            updated.push_str(&new_val.to_string());
            updated.push_str(&prefix[end..]);
            return updated;
        }
    }
    prefix.to_string()
}

pub fn merge_ledger(
    path: &str,
    base: &str,
    ours: &str,
    theirs: &str,
) -> Result<MergedLedger, MergeConflict> {
    let norm_path = normalize_repo_path(path);

    if norm_path == CONTRACTS_INVENTORY_PATH {
        return Err(MergeConflict::GeneratedArtifactNeedsRegeneration { path: norm_path });
    }

    if norm_path == ALLOWED_PROBE_INVENTORY_PATH {
        return merge_probe_inventory(base, ours, theirs);
    }

    for (allowed_path, shard_name) in ALLOWED_ABORT_SHARDS {
        if norm_path == *allowed_path {
            return merge_abort_shard(&norm_path, shard_name, base, ours, theirs);
        }
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

fn merge_abort_shard(
    path: &str,
    expected_shard: &str,
    base: &str,
    ours: &str,
    theirs: &str,
) -> Result<MergedLedger, MergeConflict> {
    let base_parsed = parse_abort_ledger("base", path, expected_shard, base)?;
    let ours_parsed = parse_abort_ledger("ours", path, expected_shard, ours)?;
    let theirs_parsed = parse_abort_ledger("theirs", path, expected_shard, theirs)?;

    if ours_parsed.schema != base_parsed.schema {
        return Err(MergeConflict::IncompatibleSchema {
            side: "ours".to_string(),
            found: ours_parsed.schema.to_string(),
        });
    }
    if theirs_parsed.schema != base_parsed.schema {
        return Err(MergeConflict::IncompatibleSchema {
            side: "theirs".to_string(),
            found: theirs_parsed.schema.to_string(),
        });
    }

    if ours_parsed.shard != base_parsed.shard {
        return Err(MergeConflict::WrongShard {
            side: "ours".to_string(),
            path: path.to_string(),
            expected: base_parsed.shard,
            actual: ours_parsed.shard,
        });
    }
    if theirs_parsed.shard != base_parsed.shard {
        return Err(MergeConflict::WrongShard {
            side: "theirs".to_string(),
            path: path.to_string(),
            expected: base_parsed.shard,
            actual: theirs_parsed.shard,
        });
    }

    // Merge debt ceiling
    let merged_debt_ceiling = if ours_parsed.debt_ceiling == theirs_parsed.debt_ceiling {
        ours_parsed.debt_ceiling
    } else if ours_parsed.debt_ceiling == base_parsed.debt_ceiling {
        theirs_parsed.debt_ceiling
    } else if theirs_parsed.debt_ceiling == base_parsed.debt_ceiling {
        ours_parsed.debt_ceiling
    } else {
        return Err(MergeConflict::DivergentDebtCeiling {
            base: base_parsed.debt_ceiling,
            ours: ours_parsed.debt_ceiling,
            theirs: theirs_parsed.debt_ceiling,
        });
    };

    let debt_ceiling_change = if merged_debt_ceiling != base_parsed.debt_ceiling {
        Some((base_parsed.debt_ceiling, merged_debt_ceiling))
    } else {
        None
    };

    // Merge extra metadata fields
    let mut all_meta_keys = BTreeSet::new();
    all_meta_keys.extend(base_parsed.extra_meta.keys());
    all_meta_keys.extend(ours_parsed.extra_meta.keys());
    all_meta_keys.extend(theirs_parsed.extra_meta.keys());

    let mut merged_meta = BTreeMap::new();
    for key in all_meta_keys {
        let b = base_parsed.extra_meta.get(key);
        let o = ours_parsed.extra_meta.get(key);
        let t = theirs_parsed.extra_meta.get(key);

        if o == t {
            if let Some(val) = o {
                merged_meta.insert(key.clone(), val.clone());
            }
        } else if o == b {
            if let Some(val) = t {
                merged_meta.insert(key.clone(), val.clone());
            }
        } else if t == b {
            if let Some(val) = o {
                merged_meta.insert(key.clone(), val.clone());
            }
        } else {
            return Err(MergeConflict::MetadataConflict {
                field: key.clone(),
                base: format_value_preview(&b.cloned()),
                ours: format_value_preview(&o.cloned()),
                theirs: format_value_preview(&t.cloned()),
            });
        }
    }

    // Merge rows
    let mut all_row_keys = BTreeSet::new();
    all_row_keys.extend(base_parsed.rows.keys().cloned());
    all_row_keys.extend(ours_parsed.rows.keys().cloned());
    all_row_keys.extend(theirs_parsed.rows.keys().cloned());

    let mut merged_rows = BTreeMap::new();
    let mut rows_added = 0;
    let mut rows_modified = 0;
    let mut rows_deleted = 0;

    for key in all_row_keys {
        let b = base_parsed.rows.get(&key);
        let o = ours_parsed.rows.get(&key);
        let t = theirs_parsed.rows.get(&key);

        if o == t {
            if let Some(val) = o {
                if b.is_none() {
                    rows_added += 1;
                } else if b != Some(val) {
                    rows_modified += 1;
                }
                merged_rows.insert(key, val.clone());
            } else if b.is_some() {
                rows_deleted += 1;
            }
        } else if o == b {
            if let Some(val) = t {
                if b.is_none() {
                    rows_added += 1;
                } else {
                    rows_modified += 1;
                }
                merged_rows.insert(key, val.clone());
            } else {
                rows_deleted += 1;
            }
        } else if t == b {
            if let Some(val) = o {
                if b.is_none() {
                    rows_added += 1;
                } else {
                    rows_modified += 1;
                }
                merged_rows.insert(key, val.clone());
            } else {
                rows_deleted += 1;
            }
        } else {
            return Err(MergeConflict::RowConflict {
                key: key.to_string(),
                base: format_value_preview(&b.cloned()),
                ours: format_value_preview(&o.cloned()),
                theirs: format_value_preview(&t.cloned()),
            });
        }
    }

    let ours_layout = extract_abort_file_layout(ours);
    let theirs_layout = extract_abort_file_layout(theirs);

    let output_json = match (ours_layout, theirs_layout) {
        (Some(ours_lay), Some(theirs_lay)) => {
            let ours_snippets: BTreeMap<AbortKey, String> =
                ours_lay.entries.iter().cloned().collect();
            let theirs_snippets: BTreeMap<AbortKey, String> =
                theirs_lay.entries.iter().cloned().collect();

            let mut merged_keys: Vec<AbortKey> = Vec::new();
            for (k, _) in &ours_lay.entries {
                if merged_rows.contains_key(k) {
                    merged_keys.push(k.clone());
                }
            }

            let theirs_keys: Vec<AbortKey> =
                theirs_lay.entries.iter().map(|(k, _)| k.clone()).collect();
            for (t_idx, t_add) in theirs_keys.iter().enumerate() {
                if merged_keys.contains(t_add) {
                    continue;
                }
                if !merged_rows.contains_key(t_add) {
                    continue;
                }

                // Find nearest preceding neighbour in theirs that is already in merged_keys
                let mut found_preceding = None;
                for p_idx in (0..t_idx).rev() {
                    let candidate = &theirs_keys[p_idx];
                    if merged_keys.contains(candidate) {
                        found_preceding = Some(candidate.clone());
                        break;
                    }
                }

                match found_preceding {
                    None => {
                        merged_keys.push(t_add.clone());
                    }
                    Some(p) => {
                        let p_pos = merged_keys
                            .iter()
                            .position(|k| k == &p)
                            .unwrap_or(merged_keys.len());
                        let mut insert_pos = if p_pos < merged_keys.len() {
                            p_pos + 1
                        } else {
                            merged_keys.len()
                        };

                        while insert_pos < merged_keys.len() {
                            let next_k = &merged_keys[insert_pos];
                            let in_theirs_after =
                                theirs_keys.iter().skip(t_idx + 1).any(|k| k == next_k);
                            if in_theirs_after {
                                break;
                            }
                            if next_k.file == t_add.file
                                && next_k.function == t_add.function
                                && next_k.ordinal_in_function < t_add.ordinal_in_function
                            {
                                insert_pos += 1;
                            } else {
                                break;
                            }
                        }
                        merged_keys.insert(insert_pos, t_add.clone());
                    }
                }
            }

            let mut snippets = Vec::new();
            for k in &merged_keys {
                if let Some(snip) = ours_snippets.get(k) {
                    if ours_parsed.rows.get(k) == merged_rows.get(k) {
                        snippets.push(snip.clone());
                    } else if let Some(th_snip) = theirs_snippets.get(k) {
                        snippets.push(th_snip.clone());
                    } else {
                        let val = &merged_rows[k];
                        let val_str = serde_json::to_string_pretty(val).unwrap_or_default();
                        snippets.push(indent_row(&val_str, 4));
                    }
                } else if let Some(snip) = theirs_snippets.get(k) {
                    snippets.push(snip.clone());
                } else {
                    let val = &merged_rows[k];
                    let val_str = serde_json::to_string_pretty(val).unwrap_or_default();
                    snippets.push(indent_row(&val_str, 4));
                }
            }

            let updated_prefix = update_debt_ceiling_in_prefix(
                &ours_lay.prefix,
                ours_parsed.debt_ceiling,
                merged_debt_ceiling,
            );

            let mut out = String::new();
            out.push_str(&updated_prefix);
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
            struct OrderedAbortLedger<'a> {
                schema: u64,
                shard: &'a str,
                debt_ceiling: u64,
                extra_meta: &'a BTreeMap<String, ParsedValue>,
                rows: Vec<&'a ParsedValue>,
            }

            impl Serialize for OrderedAbortLedger<'_> {
                fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
                where
                    S: Serializer,
                {
                    let mut map = serializer.serialize_map(None)?;
                    map.serialize_entry("schema", &self.schema)?;
                    map.serialize_entry("shard", &self.shard)?;
                    map.serialize_entry("typed_error_debt_ceiling", &self.debt_ceiling)?;
                    for (k, v) in self.extra_meta {
                        map.serialize_entry(k, v)?;
                    }
                    map.serialize_entry("rows", &self.rows)?;
                    map.end()
                }
            }

            let rows_sorted: Vec<&ParsedValue> = merged_rows.values().collect();
            let ordered = OrderedAbortLedger {
                schema: base_parsed.schema,
                shard: &base_parsed.shard,
                debt_ceiling: merged_debt_ceiling,
                extra_meta: &merged_meta,
                rows: rows_sorted,
            };

            let serialized =
                serde_json::to_string_pretty(&ordered).map_err(|e| MergeConflict::InvalidJson {
                    side: "merged".to_string(),
                    details: e.to_string(),
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
            debt_ceiling_change,
        },
    })
}

fn indent_row(s: &str, spaces: usize) -> String {
    let pad = " ".repeat(spaces);
    let mut out = String::new();
    for (i, line) in s.lines().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        out.push_str(&pad);
        out.push_str(line);
    }
    out
}

pub fn regenerate_contracts_with_runner<F>(root: &Path, runner: F) -> Result<(), RegenerateError>
where
    F: Fn(&str, &[&str], Option<&Path>) -> Result<CommandOutput, CommandError>,
{
    let root_str = root.to_str().ok_or_else(|| {
        RegenerateError::InvalidPath(format!(
            "root path contains invalid UTF-8: {}",
            root.display()
        ))
    })?;

    // Step 1: generate inventory with --root
    runner(
        "cargo",
        &[
            "run",
            "-p",
            "carrick-conformance-contract",
            "--bin",
            "generate-inventory",
            "--",
            "--root",
            root_str,
        ],
        None,
    )
    .map_err(|err| RegenerateError::GenerationFailed {
        stage: "generate",
        error: err.to_string(),
    })?;

    // Step 2: verify inventory drift with --root <root> --check
    runner(
        "cargo",
        &[
            "run",
            "-p",
            "carrick-conformance-contract",
            "--bin",
            "generate-inventory",
            "--",
            "--root",
            root_str,
            "--check",
        ],
        None,
    )
    .map_err(|err| RegenerateError::GenerationFailed {
        stage: "check",
        error: err.to_string(),
    })?;

    Ok(())
}

pub fn regenerate_contracts(root: &Path) -> Result<(), RegenerateError> {
    regenerate_contracts_with_runner(root, |prog, args, cwd| {
        crate::command::run_checked(prog, args, cwd)
    })
}
