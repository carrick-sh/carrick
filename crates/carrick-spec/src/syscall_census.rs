//! Wire evidence shared by the carrier and acceptance runners.

pub const MARKER: &str = "CARRICK_SYSCALL_CENSUS ";
pub const SCHEMA: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CensusIsa {
    Aarch64,
    X86_64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallerClass {
    Root,
    NativeChild,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RefusalRow {
    /// Native ordinal. 512 is the explicitly incomplete overflow bucket.
    pub nr: u64,
    pub caller: CallerClass,
    pub refused: u64,
    pub venue_refused: u64,
    /// Derived from the personality's single crossing table at publication.
    pub allowlisted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RefusalEvidence {
    pub schema: u32,
    pub isa: CensusIsa,
    pub complete: bool,
    pub rows: Vec<RefusalRow>,
}

impl RefusalEvidence {
    /// A missing oracle shape is not proof that Linux refused a call. It is
    /// needed only for non-allowlisted refusals; allowlisted refusals fail
    /// independently of any oracle. Counts include failed venue admission,
    /// not ordinary Linux errno returns from a served operation.
    pub fn check(&self, oracle_served: Option<&[u64]>) -> Result<(), String> {
        if self.schema != SCHEMA || !self.complete {
            return Err("incomplete syscall refusal census".into());
        }
        for row in &self.rows {
            if row.refused == 0 && row.venue_refused == 0 {
                continue;
            }
            let context = format!(
                "{:?} {:?} ordinal {}: refused={} venue_refused={}",
                self.isa, row.caller, row.nr, row.refused, row.venue_refused
            );
            if row.nr >= 512 {
                return Err(format!("{context}: unknown ordinal"));
            }
            if row.allowlisted {
                return Err(format!("{context}: allowlisted syscall refused"));
            }
            // Coverage debt is counted by the runner until Docker shapes
            // have been captured. Missing shape never excuses allowlisted
            // refusals or a malformed/incomplete census above.
            let Some(served) = oracle_served else {
                continue;
            };
            if served.contains(&row.nr) {
                return Err(format!("{context}: Docker served this syscall"));
            }
        }
        Ok(())
    }
}

/// Load explicitly requested carrier files into the same wire transcript
/// used by gate receipts. Callers keep this evidence beside their run logs.
pub fn read_directory(directory: &std::path::Path) -> std::io::Result<String> {
    let mut paths = std::fs::read_dir(directory)?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<Result<Vec<_>, _>>()?;
    paths.sort();
    let mut log = String::new();
    for path in paths {
        if path
            .extension()
            .is_some_and(|extension| extension == "json")
        {
            let body = std::fs::read_to_string(path)?;
            // Collapse the pretty-printed file into exactly one wire line.
            let body: serde_json::Value = serde_json::from_str(&body)?;
            log.push_str(MARKER);
            log.push_str(&body.to_string());
            log.push('\n');
        }
    }
    Ok(log)
}

/// Read all carrier censuses in a subprocess log. Missing, malformed and
/// incomplete evidence fail closed, including when the guest exited zero.
pub fn check_log(log: &str, oracle_served: Option<&[u64]>) -> Result<(), String> {
    let mut count = 0;
    for line in log.lines() {
        if let Some(body) = line.strip_prefix(MARKER) {
            #[derive(serde::Deserialize)]
            struct Envelope {
                refusal_evidence: RefusalEvidence,
            }
            let envelope: Envelope = serde_json::from_str(body)
                .map_err(|error| format!("malformed syscall census: {error}"))?;
            envelope.refusal_evidence.check(oracle_served)?;
            count += 1;
        }
    }
    if count == 0 {
        return Err("missing syscall refusal census".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refused_child_mkdirat_fails_even_without_oracle_shape() {
        let evidence = RefusalEvidence {
            schema: SCHEMA,
            isa: CensusIsa::Aarch64,
            complete: true,
            rows: vec![RefusalRow {
                nr: 34,
                caller: CallerClass::NativeChild,
                refused: 1,
                venue_refused: 0,
                allowlisted: true,
            }],
        };
        let log = format!(
            "{MARKER}{}",
            serde_json::to_string(&serde_json::json!({"refusal_evidence": evidence})).unwrap()
        );
        assert!(check_log(&log, None).unwrap_err().contains("allowlisted"));
        let mut evidence = evidence;
        evidence.rows[0].allowlisted = false;
        assert!(evidence.check(None).is_ok());
        assert!(evidence.check(Some(&[34])).is_err());
        assert!(evidence.check(Some(&[56])).is_ok());
        evidence.rows[0].refused = 0;
        evidence.rows[0].venue_refused = 1;
        assert!(evidence.check(Some(&[34])).is_err());
    }

    #[test]
    fn missing_malformed_incomplete_and_overflow_are_not_green() {
        assert!(check_log("exit=0", None).is_err());
        assert!(check_log(&format!("{MARKER}{{}}"), None).is_err());
        let mut evidence = RefusalEvidence {
            schema: SCHEMA,
            isa: CensusIsa::X86_64,
            complete: false,
            rows: vec![],
        };
        assert!(evidence.check(None).is_err());
        evidence.complete = true;
        assert!(evidence.check(None).is_ok());
        evidence.rows.push(RefusalRow {
            nr: 512,
            caller: CallerClass::Root,
            refused: 1,
            venue_refused: 0,
            allowlisted: false,
        });
        assert!(evidence.check(Some(&[])).is_err());
    }
}
