//! Credential masking for bounded scaler command diagnostics. No publication gate.
use crate::ci_scaler::ScalerError;
use std::os::unix::fs::OpenOptionsExt;

const MAX_FILE_BYTES: u64 = 1024 * 1024;
const REFUSAL: &str = "diagnostic redaction refused unsafe credential state";
pub(crate) struct DiagnosticSecrets {
    secrets: Vec<String>,
}
impl DiagnosticSecrets {
    fn add(&mut self, value: &str) {
        if !value.is_empty() && !self.secrets.iter().any(|s| s == value) {
            self.secrets.push(value.to_owned());
        }
        if !value.trim().is_empty() && value.trim() != value {
            self.secrets.push(value.trim().to_owned());
        }
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(value) {
            self.json_values(&json);
        }
    }
    fn json_values(&mut self, value: &serde_json::Value) {
        match value {
            serde_json::Value::String(s) => {
                if !s.is_empty() && !self.secrets.contains(s) {
                    self.secrets.push(s.clone());
                }
            }
            serde_json::Value::Object(m) => {
                for (key, v) in m {
                    let key = key.to_ascii_lowercase();
                    if v.is_object()
                        || v.is_array()
                        || ((key.contains("token") && key != "token_type")
                            || key.contains("key")
                            || key.contains("secret")
                            || key.contains("password"))
                    {
                        self.json_values(v);
                    }
                }
            }
            serde_json::Value::Array(a) => {
                for v in a {
                    self.json_values(v);
                }
            }
            _ => {}
        }
    }
    /// Capture once before agent execution, never from agent-modified state.
    pub(crate) fn capture() -> Result<Self, ScalerError> {
        let mut gate = Self { secrets: vec![] };
        for key in [
            "GH_TOKEN",
            "GITHUB_TOKEN",
            "AGENT_DIRECTOR_TOKEN",
            "DISPATCH_BOARD_TOKEN",
            "DISPATCH_PUBLISH_TOKEN",
        ] {
            if let Ok(value) = std::env::var(key) {
                gate.add(&value);
            }
        }
        if let Ok(state) = crate::agent_runner::state() {
            for path in [
                "redaction-secrets.json",
                "home/.codex/auth.json",
                "home/.gemini/antigravity-cli/antigravity-oauth-token",
                "loop-home/.gemini/antigravity-cli/antigravity-oauth-token",
            ] {
                let path = state.join(path);
                match std::fs::symlink_metadata(&path) {
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                    Err(e) => return Err(e.into()),
                    Ok(meta) if meta.is_file() && meta.len() <= MAX_FILE_BYTES => {}
                    _ => return Err(ScalerError::Guard(REFUSAL)),
                }
                let value = std::fs::read_to_string(&path)?;
                if path.ends_with("redaction-secrets.json") {
                    gate.json_values(
                        &serde_json::from_str(&value).map_err(|_| ScalerError::Guard(REFUSAL))?,
                    );
                } else {
                    gate.add(&value);
                }
            }
        }
        Ok(gate)
    }
    pub(crate) fn check(&self, bytes: &[u8]) -> Result<(), ScalerError> {
        let lower = bytes.to_ascii_lowercase();
        let sensitive = self.secrets.iter().any(|s| contains(bytes, s.as_bytes()))
            || token_shape(bytes, b"eyJ", true)
            || [b"ghs_".as_slice(), b"ghp_", b"github_pat_"]
                .iter()
                .any(|prefix| token_shape(bytes, prefix, false))
            || ["refresh_token", "authorization: bearer", "pveapitoken="]
                .iter()
                .any(|s| contains(&lower, s.as_bytes()));
        if sensitive {
            Err(ScalerError::Guard(REFUSAL))
        } else {
            Ok(())
        }
    }
    pub(crate) fn diagnostic(&self, bytes: &[u8]) -> String {
        let text = String::from_utf8_lossy(bytes);
        let mut output = String::new();
        for line in text.split_inclusive('\n') {
            if self.check(line.as_bytes()).is_err() {
                output.push_str("[REDACTED]\n");
            } else {
                output.push_str(line);
            }
        }
        if self.check(output.as_bytes()).is_err() {
            "[REDACTED]".into()
        } else {
            output
        }
    }
}
fn contains(bytes: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && bytes.windows(needle.len()).any(|s| s == needle)
}
fn token_shape(bytes: &[u8], prefix: &[u8], jwt: bool) -> bool {
    bytes
        .windows(prefix.len())
        .enumerate()
        .any(|(offset, window)| {
            if window != prefix {
                return false;
            }
            let suffix = &bytes[offset + prefix.len()..];
            let length = suffix
                .iter()
                .take_while(|b| b.is_ascii_alphanumeric() || b"_-".contains(b))
                .count();
            length >= 8 && (!jwt || suffix.get(length) == Some(&b'.'))
        })
}
/// Persist earlier-step secrets outside artifacts; the run captures them once.
pub(crate) fn remember() -> Result<(), ScalerError> {
    let gate = DiagnosticSecrets::capture()?;
    let path = crate::agent_runner::state()?.join("redaction-secrets.json");
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(path)?;
    use std::io::Write;
    file.write_all(&serde_json::to_vec(&gate.secrets)?)?;
    Ok(())
}
pub(crate) fn redact(bytes: &[u8]) -> String {
    DiagnosticSecrets::capture()
        .map(|gate| gate.diagnostic(bytes))
        .unwrap_or_else(|_| "[REDACTED: credential state unavailable]".into())
}
#[cfg(test)]
mod tests {
    #[test]
    fn incomplete_prefixes_in_binary_objects_are_not_credentials()
    -> Result<(), crate::ci_scaler::ScalerError> {
        assert!(
            super::DiagnosticSecrets::capture()?
                .check(b"\0eyJ\0ghs_\0ghp_\0github_pat_\0")
                .is_ok()
        );
        Ok(())
    }
    #[test]
    fn credential_shapes_are_removed_from_diagnostics() {
        for value in [
            "ghs_fakecredential",
            "ghp_fakecredential",
            "github_pat_fakecredential",
            "eyJhbGciOiJub25lIn0.payload.signature",
            "refresh_token=opaque",
            "Authorization: Bearer opaque",
            "PVEAPIToken=opaque",
        ] {
            assert!(
                !super::redact(value.as_bytes()).contains(value),
                "credential-bearing diagnostic survived"
            );
        }
        assert_eq!(
            super::redact(b"curl: connection refused"),
            "curl: connection refused"
        );
    }
}
