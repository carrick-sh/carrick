#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(usize)]
pub enum AllocationOwner {
    Other = 0,
    PublicationMap = 1,
    PublicationRecovery = 2,
    BlockAssemblerTransient = 3,
    DecodeReadBuffers = 4,
    IndirectTargetCache = 5,
    SharedTranslationSupport = 6,
    PublicationIndexes = 7,
    TranslationSourcePreparation = 8,
}

impl AllocationOwner {
    pub const ALL: [Self; 9] = [
        Self::Other,
        Self::PublicationMap,
        Self::PublicationRecovery,
        Self::BlockAssemblerTransient,
        Self::DecodeReadBuffers,
        Self::IndirectTargetCache,
        Self::SharedTranslationSupport,
        Self::PublicationIndexes,
        Self::TranslationSourcePreparation,
    ];
    pub const COUNT: usize = Self::ALL.len();

    pub const fn token(self) -> &'static str {
        match self {
            Self::Other => "other",
            Self::PublicationMap => "publication-map",
            Self::PublicationRecovery => "publication-recovery",
            Self::BlockAssemblerTransient => "block-assembler-transient",
            Self::DecodeReadBuffers => "decode-read-buffers",
            Self::IndirectTargetCache => "indirect-target-cache",
            Self::SharedTranslationSupport => "shared-translation-support",
            Self::PublicationIndexes => "publication-indexes",
            Self::TranslationSourcePreparation => "translation-source-preparation",
        }
    }

    pub fn from_token(token: &str) -> Option<Self> {
        match token {
            "other" => Some(Self::Other),
            "publication-map" => Some(Self::PublicationMap),
            "publication-recovery" => Some(Self::PublicationRecovery),
            "block-assembler-transient" => Some(Self::BlockAssemblerTransient),
            "decode-read-buffers" => Some(Self::DecodeReadBuffers),
            "indirect-target-cache" => Some(Self::IndirectTargetCache),
            "shared-translation-support" => Some(Self::SharedTranslationSupport),
            "publication-indexes" => Some(Self::PublicationIndexes),
            "translation-source-preparation" => Some(Self::TranslationSourcePreparation),
            _ => None,
        }
    }
}

/// A quiescent boundary that exported one allocation-owner fragment.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum AllocationFlushReason {
    HostSelfReexecAttempt,
    InProcessExec,
    ProcessExit,
    AtexitBackstop,
}

impl AllocationFlushReason {
    pub const fn token(self) -> &'static str {
        match self {
            Self::HostSelfReexecAttempt => "host-self-reexec-attempt",
            Self::InProcessExec => "in-process-exec",
            Self::ProcessExit => "process-exit",
            Self::AtexitBackstop => "atexit-backstop",
        }
    }

    pub fn from_token(token: &str) -> Option<Self> {
        match token {
            "host-self-reexec-attempt" => Some(Self::HostSelfReexecAttempt),
            "in-process-exec" => Some(Self::InProcessExec),
            "process-exit" => Some(Self::ProcessExit),
            "atexit-backstop" => Some(Self::AtexitBackstop),
            _ => None,
        }
    }
}

/// Cumulative successful allocation requests attributed to one semantic owner.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct OwnerSnapshot {
    pub requested_bytes: u64,
    pub alloc_calls: u64,
    pub zeroed_calls: u64,
    pub realloc_calls: u64,
}

impl OwnerSnapshot {
    fn total_calls(self) -> Result<u64, AllocationOwnerWireError> {
        self.alloc_calls
            .checked_add(self.zeroed_calls)
            .and_then(|calls| calls.checked_add(self.realloc_calls))
            .ok_or(AllocationOwnerWireError::CounterOverflow)
    }
}

/// One deterministic `ALLOCOWNER2` process-image fragment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllocationOwnerCensusFile {
    pub pid: i32,
    pub exec_epoch: u64,
    pub fragment_sequence: u64,
    pub reason: AllocationFlushReason,
    pub overflow: bool,
    pub lifecycle_error: bool,
    pub owners: [OwnerSnapshot; AllocationOwner::COUNT],
}

#[derive(Debug, thiserror::Error)]
pub enum AllocationOwnerWireError {
    #[error("invalid ALLOCOWNER2 record: {0}")]
    Invalid(&'static str),
    #[error("invalid ALLOCOWNER2 integer field {0}")]
    InvalidInteger(&'static str),
    #[error("ALLOCOWNER2 counter overflow")]
    CounterOverflow,
    #[error("ALLOCOWNER2 record reports counter overflow")]
    RecordedOverflow,
    #[error("ALLOCOWNER2 record reports a lifecycle error")]
    RecordedLifecycleError,
    #[error("failed to format ALLOCOWNER2 record")]
    Format,
}

impl AllocationOwnerCensusFile {
    pub fn total_bytes(&self) -> Result<u64, AllocationOwnerWireError> {
        self.owners.iter().try_fold(0u64, |total, owner| {
            total
                .checked_add(owner.requested_bytes)
                .ok_or(AllocationOwnerWireError::CounterOverflow)
        })
    }

    pub fn total_calls(&self) -> Result<u64, AllocationOwnerWireError> {
        self.owners.iter().try_fold(0u64, |total, owner| {
            total
                .checked_add(owner.total_calls()?)
                .ok_or(AllocationOwnerWireError::CounterOverflow)
        })
    }

    pub fn render(&self) -> Result<String, AllocationOwnerWireError> {
        use sha2::{Digest as _, Sha256};
        use std::fmt::Write as _;

        let mut payload = String::new();
        writeln!(
            payload,
            "ALLOCOWNER2|pid={}|exec_epoch={}|fragment={}|reason={}|armed_at=main-entry|overflow={}|lifecycle_error={}",
            self.pid,
            self.exec_epoch,
            self.fragment_sequence,
            self.reason.token(),
            u8::from(self.overflow),
            u8::from(self.lifecycle_error),
        )
        .map_err(|_| AllocationOwnerWireError::Format)?;
        for owner in AllocationOwner::ALL {
            let snapshot = self.owners[owner as usize];
            writeln!(
                payload,
                "OWNER|name={}|bytes={}|alloc={}|zeroed={}|realloc={}",
                owner.token(),
                snapshot.requested_bytes,
                snapshot.alloc_calls,
                snapshot.zeroed_calls,
                snapshot.realloc_calls,
            )
            .map_err(|_| AllocationOwnerWireError::Format)?;
        }
        writeln!(
            payload,
            "TOTAL|bytes={}|calls={}",
            self.total_bytes()?,
            self.total_calls()?,
        )
        .map_err(|_| AllocationOwnerWireError::Format)?;
        let checksum = Sha256::digest(payload.as_bytes());
        writeln!(payload, "END|sha256={checksum:x}")
            .map_err(|_| AllocationOwnerWireError::Format)?;
        Ok(payload)
    }

    pub fn parse(text: &str) -> Result<Self, AllocationOwnerWireError> {
        use sha2::{Digest as _, Sha256};

        if !text.ends_with('\n') {
            return Err(AllocationOwnerWireError::Invalid("missing final newline"));
        }
        let lines: Vec<&str> = text[..text.len() - 1].split('\n').collect();
        let expected_lines = AllocationOwner::COUNT + 3;
        if lines.len() != expected_lines {
            return Err(AllocationOwnerWireError::Invalid("wrong line count"));
        }

        let footer = exact_fields(lines[expected_lines - 1], 2, "footer")?;
        if footer[0] != "END" {
            return Err(AllocationOwnerWireError::Invalid("missing footer"));
        }
        let expected_checksum = exact_value(footer[1], "sha256", "footer checksum")?;
        if expected_checksum.len() != 64
            || !expected_checksum
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(AllocationOwnerWireError::Invalid("invalid footer checksum"));
        }
        let footer_offset = text
            .rfind("END|sha256=")
            .ok_or(AllocationOwnerWireError::Invalid("missing footer"))?;
        let actual_checksum = Sha256::digest(&text.as_bytes()[..footer_offset]);
        if format!("{actual_checksum:x}") != expected_checksum {
            return Err(AllocationOwnerWireError::Invalid("checksum mismatch"));
        }

        let header = exact_fields(lines[0], 8, "header")?;
        if header[0] != "ALLOCOWNER2" {
            return Err(AllocationOwnerWireError::Invalid("unknown schema"));
        }
        let pid = parse_i32(exact_value(header[1], "pid", "pid")?, "pid")?;
        let exec_epoch = parse_u64(
            exact_value(header[2], "exec_epoch", "exec epoch")?,
            "exec_epoch",
        )?;
        let fragment_sequence =
            parse_u64(exact_value(header[3], "fragment", "fragment")?, "fragment")?;
        let reason =
            AllocationFlushReason::from_token(exact_value(header[4], "reason", "flush reason")?)
                .ok_or(AllocationOwnerWireError::Invalid("unknown flush reason"))?;
        if header[5] != "armed_at=main-entry" {
            return Err(AllocationOwnerWireError::Invalid("invalid arming boundary"));
        }
        let overflow = parse_bool01(exact_value(header[6], "overflow", "overflow")?, "overflow")?;
        let lifecycle_error = parse_bool01(
            exact_value(header[7], "lifecycle_error", "lifecycle error")?,
            "lifecycle_error",
        )?;

        let mut owners = [OwnerSnapshot::default(); AllocationOwner::COUNT];
        for (index, expected_owner) in AllocationOwner::ALL.into_iter().enumerate() {
            let fields = exact_fields(lines[index + 1], 6, "owner row")?;
            if fields[0] != "OWNER" {
                return Err(AllocationOwnerWireError::Invalid("invalid owner row"));
            }
            let owner = AllocationOwner::from_token(exact_value(fields[1], "name", "owner name")?)
                .ok_or(AllocationOwnerWireError::Invalid("unknown owner"))?;
            if owner != expected_owner {
                return Err(AllocationOwnerWireError::Invalid("owner order mismatch"));
            }
            owners[index] = OwnerSnapshot {
                requested_bytes: parse_u64(
                    exact_value(fields[2], "bytes", "owner bytes")?,
                    "bytes",
                )?,
                alloc_calls: parse_u64(
                    exact_value(fields[3], "alloc", "owner alloc calls")?,
                    "alloc",
                )?,
                zeroed_calls: parse_u64(
                    exact_value(fields[4], "zeroed", "owner zeroed calls")?,
                    "zeroed",
                )?,
                realloc_calls: parse_u64(
                    exact_value(fields[5], "realloc", "owner realloc calls")?,
                    "realloc",
                )?,
            };
        }

        let total = exact_fields(lines[AllocationOwner::COUNT + 1], 3, "total row")?;
        if total[0] != "TOTAL" {
            return Err(AllocationOwnerWireError::Invalid("missing total row"));
        }
        let recorded_bytes = parse_u64(
            exact_value(total[1], "bytes", "total bytes")?,
            "total bytes",
        )?;
        let recorded_calls = parse_u64(
            exact_value(total[2], "calls", "total calls")?,
            "total calls",
        )?;
        let file = Self {
            pid,
            exec_epoch,
            fragment_sequence,
            reason,
            overflow,
            lifecycle_error,
            owners,
        };
        if file.total_bytes()? != recorded_bytes || file.total_calls()? != recorded_calls {
            return Err(AllocationOwnerWireError::Invalid("total mismatch"));
        }
        if overflow {
            return Err(AllocationOwnerWireError::RecordedOverflow);
        }
        if lifecycle_error {
            return Err(AllocationOwnerWireError::RecordedLifecycleError);
        }
        Ok(file)
    }
}

fn exact_fields<'a>(
    line: &'a str,
    expected: usize,
    context: &'static str,
) -> Result<Vec<&'a str>, AllocationOwnerWireError> {
    let fields: Vec<&str> = line.split('|').collect();
    if fields.len() != expected {
        return Err(AllocationOwnerWireError::Invalid(context));
    }
    Ok(fields)
}

fn exact_value<'a>(
    field: &'a str,
    key: &'static str,
    context: &'static str,
) -> Result<&'a str, AllocationOwnerWireError> {
    field
        .strip_prefix(key)
        .and_then(|value| value.strip_prefix('='))
        .ok_or(AllocationOwnerWireError::Invalid(context))
}

fn parse_u64(value: &str, field: &'static str) -> Result<u64, AllocationOwnerWireError> {
    value
        .parse()
        .map_err(|_| AllocationOwnerWireError::InvalidInteger(field))
}

fn parse_i32(value: &str, field: &'static str) -> Result<i32, AllocationOwnerWireError> {
    value
        .parse()
        .map_err(|_| AllocationOwnerWireError::InvalidInteger(field))
}

fn parse_bool01(value: &str, field: &'static str) -> Result<bool, AllocationOwnerWireError> {
    match value {
        "0" => Ok(false),
        "1" => Ok(true),
        _ => Err(AllocationOwnerWireError::Invalid(field)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest as _, Sha256};

    #[test]
    fn owner_tokens_are_closed_and_stable() {
        let expected = [
            "other",
            "publication-map",
            "publication-recovery",
            "block-assembler-transient",
            "decode-read-buffers",
            "indirect-target-cache",
            "shared-translation-support",
            "publication-indexes",
            "translation-source-preparation",
        ];
        assert_eq!(AllocationOwner::COUNT, expected.len());
        for (owner, token) in AllocationOwner::ALL.into_iter().zip(expected) {
            assert_eq!(owner.token(), token);
            assert_eq!(AllocationOwner::from_token(token), Some(owner));
        }
        assert_eq!(AllocationOwner::from_token("future-owner"), None);
    }

    #[test]
    fn flush_reason_tokens_are_closed_and_stable() {
        let expected = [
            (
                AllocationFlushReason::HostSelfReexecAttempt,
                "host-self-reexec-attempt",
            ),
            (AllocationFlushReason::InProcessExec, "in-process-exec"),
            (AllocationFlushReason::ProcessExit, "process-exit"),
            (AllocationFlushReason::AtexitBackstop, "atexit-backstop"),
        ];
        for (reason, token) in expected {
            assert_eq!(reason.token(), token);
            assert_eq!(AllocationFlushReason::from_token(token), Some(reason));
        }
        assert_eq!(AllocationFlushReason::from_token("future-reason"), None);
    }

    fn fixture() -> AllocationOwnerCensusFile {
        let mut owners = [OwnerSnapshot::default(); AllocationOwner::COUNT];
        owners[AllocationOwner::PublicationMap as usize] = OwnerSnapshot {
            requested_bytes: 4096,
            alloc_calls: 2,
            zeroed_calls: 1,
            realloc_calls: 3,
        };
        AllocationOwnerCensusFile {
            pid: 42,
            exec_epoch: 3,
            fragment_sequence: 1,
            reason: AllocationFlushReason::ProcessExit,
            overflow: false,
            lifecycle_error: false,
            owners,
        }
    }

    #[test]
    fn record_round_trip_is_deterministic_and_checked() {
        let file = fixture();
        let first = file.render().expect("render fixture");
        let second = file.render().expect("render fixture twice");
        assert_eq!(first, second);
        assert!(first.starts_with("ALLOCOWNER2|"));
        assert_eq!(AllocationOwnerCensusFile::parse(&first).unwrap(), file);
        assert_eq!(file.total_bytes().unwrap(), 4096);
        assert_eq!(file.total_calls().unwrap(), 6);
    }

    #[test]
    fn v2_parser_rejects_a_checksum_valid_v1_record() {
        let v1 = with_recomputed_checksum(fixture().render().expect("render fixture").replacen(
            "ALLOCOWNER2|",
            "ALLOCOWNER1|",
            1,
        ));
        assert!(AllocationOwnerCensusFile::parse(&v1).is_err());
    }

    fn with_recomputed_checksum(mut text: String) -> String {
        let end = text.find("END|sha256=").expect("fixture checksum line");
        text.truncate(end);
        let checksum = Sha256::digest(text.as_bytes());
        format!("{text}END|sha256={checksum:x}\n")
    }

    fn remove_line(text: &str, prefix: &str) -> String {
        text.lines()
            .filter(|line| !line.starts_with(prefix))
            .map(|line| format!("{line}\n"))
            .collect()
    }

    #[test]
    fn parser_rejects_every_ambiguous_or_invalid_record_shape() {
        let valid = fixture().render().expect("render valid fixture");
        let mut reordered_lines: Vec<&str> = valid.lines().collect();
        reordered_lines.swap(1, 2);
        let reordered = with_recomputed_checksum(format!("{}\n", reordered_lines.join("\n")));

        let cases = [
            (
                "unknown header field",
                with_recomputed_checksum(
                    valid.replace("|lifecycle_error=0\n", "|lifecycle_error=0|future=1\n"),
                ),
            ),
            (
                "unknown owner",
                with_recomputed_checksum(valid.replacen("name=other", "name=future-owner", 1)),
            ),
            (
                "duplicate owner",
                with_recomputed_checksum(valid.replace("name=publication-indexes", "name=other")),
            ),
            (
                "missing owner",
                with_recomputed_checksum(remove_line(&valid, "OWNER|name=publication-indexes|")),
            ),
            ("reordered owner", reordered),
            (
                "mismatched total",
                with_recomputed_checksum(
                    valid.replace("TOTAL|bytes=4096|calls=6", "TOTAL|bytes=4097|calls=6"),
                ),
            ),
            ("stale checksum", valid.replacen("pid=42", "pid=43", 1)),
            ("truncated footer", remove_line(&valid, "END|sha256=")),
            (
                "overflow",
                with_recomputed_checksum(valid.replace("|overflow=0|", "|overflow=1|")),
            ),
            (
                "lifecycle error",
                with_recomputed_checksum(
                    valid.replace("|lifecycle_error=0\n", "|lifecycle_error=1\n"),
                ),
            ),
        ];

        for (name, text) in cases {
            assert!(
                AllocationOwnerCensusFile::parse(&text).is_err(),
                "accepted {name}"
            );
        }
    }
}
