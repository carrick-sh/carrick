use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};
use serde::Serialize;
use sha2::{Digest, Sha256};

pub(crate) const AMPLIFICATION_RAW_SCHEMA: &str = "carrick.amplification.raw.v1";

/// The capture-bound placeholder slot in the AMP1 amplification template.
pub(crate) const AMP1_BOUND_PLACEHOLDER: &str = "/* CARRICK_AMP1_BOUND */";

/// The largest bound a capture may request, in seconds (six hours).
pub(crate) const MAX_BOUND_SECONDS: u64 = 6 * 60 * 60;

/// Override a profile template's capture bound.
pub(crate) fn render_profile_capture_bound(
    profile: TraceProfileKind,
    template: &str,
    seconds: u64,
) -> Result<String> {
    let Some(placeholder) = profile.capture_bound_placeholder() else {
        bail!(
            "profile {} does not declare a capture bound",
            profile.as_str()
        );
    };
    if seconds == 0 {
        bail!("profile capture bound must be positive");
    }
    if !seconds.is_multiple_of(10) {
        bail!(
            "profile capture bound must be a multiple of the 10 s accumulation granularity, got {seconds}"
        );
    }
    if seconds > MAX_BOUND_SECONDS {
        bail!("profile capture bound {seconds}s exceeds the {MAX_BOUND_SECONDS}s ceiling");
    }
    let slots = template.match_indices(placeholder).count();
    if slots != 1 {
        bail!("profile template must contain exactly one capture-bound placeholder, found {slots}");
    }
    let action = format!("bound_limit_s = (uint64_t){seconds};");
    Ok(template.replacen(placeholder, &action, 1))
}

#[allow(dead_code)]
fn validate_percent_token(value: &str, field: &str) -> Result<()> {
    if value.is_empty() {
        bail!("{field} token must not be empty");
    }
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'%' => {
                if index + 2 >= bytes.len()
                    || !bytes[index + 1].is_ascii_hexdigit()
                    || !bytes[index + 2].is_ascii_hexdigit()
                {
                    bail!("{field} contains an invalid percent escape");
                }
                index += 3;
            }
            byte if byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':') => {
                index += 1;
            }
            _ => bail!("{field} contains an unescaped byte"),
        }
    }
    Ok(())
}

#[allow(dead_code)]
fn validate_header_token(value: &str, field: &str) -> Result<()> {
    if value.is_empty() {
        bail!("{field} token must not be empty");
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_graphic() && !matches!(byte, b'|' | b'%' | b'"' | b'\\'))
    {
        bail!("{field} contains a byte that cannot survive a D printf or a `|`-delimited record");
    }
    Ok(())
}

#[allow(dead_code)]
fn validate_sha256(value: &str, field: &str) -> Result<()> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("{field} must be a 64-hex SHA-256 digest, got {value:?}");
    }
    Ok(())
}

#[allow(dead_code)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct V2ProfileAuthority {
    profile: TraceProfileKind,
    os_build: String,
    program_sha256: String,
    birth_qualification_sha256: String,
    terminal_qualification_sha256: String,
    terminal_qualifications: BTreeSet<(String, String, String)>,
    amplification_target: Option<crate::amplification_profile::NativeShapeTarget>,
    preflight: Option<crate::quiet_host::QuietHostReceipt>,
}

#[derive(Debug)]
pub(crate) struct V2ProfileAuthorityArgs<'a, I> {
    pub(crate) profile: TraceProfileKind,
    pub(crate) os_build: &'a str,
    pub(crate) program_sha256: &'a str,
    pub(crate) birth_qualification_sha256: &'a str,
    pub(crate) terminal_qualification_sha256: &'a str,
    pub(crate) terminal_qualifications: I,
    pub(crate) amplification_target: Option<crate::amplification_profile::NativeShapeTarget>,
    pub(crate) preflight: Option<crate::quiet_host::QuietHostReceipt>,
}

#[allow(dead_code)]
impl V2ProfileAuthority {
    pub(crate) fn new_for_profile(
        args: V2ProfileAuthorityArgs<'_, impl IntoIterator<Item = (String, String, String)>>,
    ) -> Result<Self> {
        let V2ProfileAuthorityArgs {
            profile,
            os_build,
            program_sha256,
            birth_qualification_sha256,
            terminal_qualification_sha256,
            terminal_qualifications,
            amplification_target,
            preflight,
        } = args;
        if profile != TraceProfileKind::NativeAmplification {
            bail!("profile {:?} does not use native launch authority", profile);
        }
        if amplification_target.is_none() {
            bail!(
                "the amplification ledger's launch authority requires a digest-pinned native run target; without it a comparison cannot refuse to cross a fixture"
            );
        }
        validate_percent_token(os_build, "authority os_build")?;
        for (value, field) in [
            (program_sha256, "authority program_sha256"),
            (
                birth_qualification_sha256,
                "authority birth_qualification_sha256",
            ),
            (
                terminal_qualification_sha256,
                "authority terminal_qualification_sha256",
            ),
        ] {
            validate_sha256(value, field)?;
        }
        let mut terminals = BTreeSet::new();
        for (provider, function, scope) in terminal_qualifications {
            if !matches!(provider.as_str(), "syscall" | "mach_trap") {
                bail!("authority contains unknown terminal provider {provider:?}");
            }
            validate_percent_token(&function, "authority terminal function")?;
            if !matches!(scope.as_str(), "thread" | "process") {
                bail!("authority contains unknown terminal scope {scope:?}");
            }
            if !terminals.insert((provider, function, scope)) {
                bail!("authority contains a duplicate terminal qualification");
            }
        }
        if !terminals.iter().any(|(_, _, scope)| scope == "thread")
            || !terminals.iter().any(|(_, _, scope)| scope == "process")
        {
            bail!("authority must qualify both thread and process termination");
        }
        Ok(Self {
            profile,
            os_build: os_build.to_owned(),
            program_sha256: program_sha256.to_owned(),
            birth_qualification_sha256: birth_qualification_sha256.to_owned(),
            terminal_qualification_sha256: terminal_qualification_sha256.to_owned(),
            terminal_qualifications: terminals,
            amplification_target,
            preflight,
        })
    }

    pub(crate) fn program_sha256(&self) -> &str {
        &self.program_sha256
    }

    #[allow(dead_code)]
    pub(crate) fn os_build(&self) -> &str {
        &self.os_build
    }

    #[allow(dead_code)]
    pub(crate) fn birth_qualification_sha256(&self) -> &str {
        &self.birth_qualification_sha256
    }

    #[allow(dead_code)]
    pub(crate) fn terminal_qualification_sha256(&self) -> &str {
        &self.terminal_qualification_sha256
    }

    pub(crate) fn header_record(&self) -> Result<String> {
        match self.profile {
            TraceProfileKind::NativeAmplification => {
                let Some(target) = self.amplification_target.as_ref() else {
                    bail!(
                        "the amplification header names a run target the authority does not carry"
                    );
                };
                validate_header_token(&target.image, "authority image")?;
                validate_sha256(&target.argv_sha256, "authority target_argv_sha256")?;
                Ok(format!(
                    "AMP1|header|profile=native-amplification|raw_schema={AMPLIFICATION_RAW_SCHEMA}|os_build={}|program_sha256={}|birth_qualification_sha256={}|terminal_qualification_sha256={}|joins=syscall,mach,fault|aggsize=64m|dynvarsize=256m|bufsize=32m|image={}|target_argv_sha256={}{}",
                    self.os_build,
                    self.program_sha256(),
                    self.birth_qualification_sha256,
                    self.terminal_qualification_sha256,
                    target.image,
                    target.argv_sha256,
                    self.preflight
                        .as_ref()
                        .map(crate::quiet_host::QuietHostReceipt::header_fields)
                        .unwrap_or_default(),
                ))
            }
            _ => bail!("non-native profile cannot construct V2ProfileAuthority"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, clap::ValueEnum, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum TraceProfileKind {
    HvpatchFrameCow,
    HvpatchExecRuntimeStages,
    HvpatchCoreLifecycle,
    HvpatchIdentityHostSafety,
    HvpatchK1Lifecycle,
    NativeAmplification,
}

impl TraceProfileKind {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::HvpatchFrameCow => "hvpatch-frame-cow",
            Self::HvpatchExecRuntimeStages => "hvpatch-exec-runtime-stages",
            Self::HvpatchCoreLifecycle => "hvpatch-core-lifecycle",
            Self::HvpatchIdentityHostSafety => "hvpatch-identity-host-safety",
            Self::HvpatchK1Lifecycle => "hvpatch-k1-lifecycle",
            Self::NativeAmplification => "native-amplification",
        }
    }

    #[allow(dead_code)]
    pub(crate) const fn requires_runtime_profile(self) -> bool {
        false
    }

    pub(crate) const fn capture_bound_placeholder(self) -> Option<&'static str> {
        match self {
            Self::NativeAmplification => Some(AMP1_BOUND_PLACEHOLDER),
            Self::HvpatchFrameCow
            | Self::HvpatchExecRuntimeStages
            | Self::HvpatchCoreLifecycle
            | Self::HvpatchIdentityHostSafety
            | Self::HvpatchK1Lifecycle => None,
        }
    }

    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    pub(crate) fn bundled_script(self) -> &'static str {
        match self {
            Self::HvpatchFrameCow => carrick_runtime::dtrace_consumer::BUNDLED_HVPATCH_FRAME_COW_D,
            Self::HvpatchExecRuntimeStages => {
                carrick_runtime::dtrace_consumer::BUNDLED_HVPATCH_EXEC_RUNTIME_STAGES_D
            }
            Self::HvpatchCoreLifecycle => {
                carrick_runtime::dtrace_consumer::BUNDLED_HVPATCH_CORE_LIFECYCLE_D
            }
            Self::HvpatchIdentityHostSafety => {
                carrick_runtime::dtrace_consumer::BUNDLED_HVPATCH_IDENTITY_HOST_SAFETY_D
            }
            Self::HvpatchK1Lifecycle => {
                carrick_runtime::dtrace_consumer::BUNDLED_HVPATCH_K1_LIFECYCLE_D
            }
            Self::NativeAmplification => {
                carrick_runtime::dtrace_consumer::BUNDLED_NATIVE_AMPLIFICATION_D
            }
        }
    }

    #[allow(dead_code)]
    fn parse_protocol(value: &str) -> Result<Self> {
        match value {
            "hvpatch-frame-cow" => Ok(Self::HvpatchFrameCow),
            "hvpatch-exec-runtime-stages" => Ok(Self::HvpatchExecRuntimeStages),
            "hvpatch-core-lifecycle" => Ok(Self::HvpatchCoreLifecycle),
            "hvpatch-identity-host-safety" => Ok(Self::HvpatchIdentityHostSafety),
            "hvpatch-k1-lifecycle" => Ok(Self::HvpatchK1Lifecycle),
            "native-amplification" => Ok(Self::NativeAmplification),
            other => bail!("unknown profile {other:?}"),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub(crate) struct ProfileCaptureStatus {
    pub(crate) principal_drops: u64,
    pub(crate) aggregation_drops: u64,
    pub(crate) dynamic_drops: u64,
    pub(crate) dynamic_rinse_drops: u64,
    pub(crate) dynamic_dirty_drops: u64,
    pub(crate) other_drops: u64,
    pub(crate) interrupted: bool,
}

#[cfg(any(target_os = "macos", target_os = "freebsd"))]
impl From<carrick_runtime::dtrace_consumer::DTraceRunReport> for ProfileCaptureStatus {
    fn from(report: carrick_runtime::dtrace_consumer::DTraceRunReport) -> Self {
        Self {
            principal_drops: report.principal_drops,
            aggregation_drops: report.aggregation_drops,
            dynamic_drops: report.dynamic_drops,
            dynamic_rinse_drops: report.dynamic_rinse_drops,
            dynamic_dirty_drops: report.dynamic_dirty_drops,
            other_drops: report.other_drops,
            interrupted: report.interrupted,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct ProfileProvenance {
    pub(crate) run_id: String,
    pub(crate) git_sha: String,
    pub(crate) git_dirty: Option<bool>,
    pub(crate) binary_sha256: String,
    pub(crate) command: Vec<String>,
    pub(crate) host: String,
}

pub(crate) fn capture_provenance(binary: &Path, command: &[String]) -> Result<ProfileProvenance> {
    let binary_bytes =
        fs::read(binary).with_context(|| format!("read traced binary {}", binary.display()))?;
    let binary_sha256 = format!("{:x}", Sha256::digest(binary_bytes));
    let git_sha = command_output("git", &["rev-parse", "HEAD"]).unwrap_or_else(|| "unknown".into());
    let git_dirty = git_dirty();
    let host = command_output("hostname", &[]).unwrap_or_else(|| "unknown".into());
    let run_id = std::env::var("CARRICK_RUN_ID").unwrap_or_else(|_| {
        format!(
            "amp-{}-{}",
            chrono::Utc::now().format("%Y%m%dT%H%M%S%.3fZ"),
            std::process::id()
        )
    });
    Ok(ProfileProvenance {
        run_id,
        git_sha,
        git_dirty,
        binary_sha256,
        command: command.to_vec(),
        host,
    })
}

fn git_dirty() -> Option<bool> {
    let output = std::process::Command::new("git")
        .args(["status", "--porcelain"])
        .output()
        .ok()?;
    output.status.success().then_some(!output.stdout.is_empty())
}

fn command_output(program: &str, args: &[&str]) -> Option<String> {
    let output = std::process::Command::new(program)
        .args(args)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8(output.stdout).ok()?;
    let value = value.trim();
    (!value.is_empty()).then(|| value.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capture_bound_is_substituted_per_profile_slot() {
        let rendered = render_profile_capture_bound(
            TraceProfileKind::NativeAmplification,
            crate::amplification_profile::BUNDLED_NATIVE_AMPLIFICATION_D,
            1800,
        )
        .expect("render");
        assert!(rendered.contains("bound_limit_s = (uint64_t)1800;"));
        assert!(!rendered.contains(AMP1_BOUND_PLACEHOLDER));
        assert!(rendered.contains("bound_limit_s = (uint64_t)600;"));

        let error = render_profile_capture_bound(
            TraceProfileKind::HvpatchCoreLifecycle,
            "BEGIN\n{\n}\n",
            900,
        )
        .expect_err("hvpatch-core-lifecycle declares no capture bound");
        assert!(
            format!("{error:#}").contains("does not declare a capture bound"),
            "unexpected error: {error:#}"
        );
    }

    #[test]
    fn capture_bound_refuses_a_template_without_exactly_one_slot() {
        for template in [
            "BEGIN\n{\n}\n",
            "BEGIN\n{\n\t/* CARRICK_AMP1_BOUND */\n\t/* CARRICK_AMP1_BOUND */\n}\n",
        ] {
            let error =
                render_profile_capture_bound(TraceProfileKind::NativeAmplification, template, 900)
                    .expect_err("only an exact single slot may be substituted");
            assert!(
                format!("{error:#}").contains("exactly one capture-bound placeholder"),
                "unexpected error: {error:#}"
            );
        }
    }

    #[test]
    fn capture_bound_refuses_values_the_program_cannot_honour() {
        let template = "/* CARRICK_AMP1_BOUND */";
        assert!(
            format!(
                "{:#}",
                render_profile_capture_bound(TraceProfileKind::NativeAmplification, template, 0)
                    .expect_err("zero")
            )
            .contains("must be positive")
        );
        assert!(
            format!(
                "{:#}",
                render_profile_capture_bound(TraceProfileKind::NativeAmplification, template, 185)
                    .expect_err("non-multiple")
            )
            .contains("multiple of the 10 s accumulation granularity")
        );
        assert!(
            format!(
                "{:#}",
                render_profile_capture_bound(
                    TraceProfileKind::NativeAmplification,
                    template,
                    MAX_BOUND_SECONDS + 10
                )
                .expect_err("excessive")
            )
            .contains("exceeds the")
        );
    }

    #[test]
    fn trace_profile_kind_strings_and_runtime_profile() {
        for (kind, expected) in [
            (TraceProfileKind::HvpatchFrameCow, "hvpatch-frame-cow"),
            (
                TraceProfileKind::HvpatchExecRuntimeStages,
                "hvpatch-exec-runtime-stages",
            ),
            (
                TraceProfileKind::HvpatchCoreLifecycle,
                "hvpatch-core-lifecycle",
            ),
            (
                TraceProfileKind::HvpatchIdentityHostSafety,
                "hvpatch-identity-host-safety",
            ),
            (TraceProfileKind::HvpatchK1Lifecycle, "hvpatch-k1-lifecycle"),
            (
                TraceProfileKind::NativeAmplification,
                "native-amplification",
            ),
        ] {
            assert_eq!(kind.as_str(), expected);
            assert_eq!(TraceProfileKind::parse_protocol(expected).unwrap(), kind);
            assert!(!kind.requires_runtime_profile());
        }
    }
}
