//! DTrace privilege-handoff helpers for `carrick trace`.
//!
//! # Theory of operation
//!
//! `carrick trace` has two irreconcilable privilege requirements: libdtrace must
//! run as **root** to open `/dev/dtrace` and arm the carrick USDT providers, but
//! the **traced guest** must run as the *original* user (root would taint file
//! ownership, scratch permissions, and any uid-sensitive guest behaviour). The
//! resolution is a split: the trace PARENT stays root and owns the dtrace
//! consumer; the traced CHILD drops back to the caller's full identity before it
//! ever dispatches a carrick subcommand.
//!
//! This module is the child-side of that split (the parent-side auto-sudo
//! re-exec lives in [`crate::commands`], `Commands::Trace`). When the parent
//! re-execs under `sudo`, it forwards the caller's original
//! uid/gid/supplementary-groups as explicit CLI args (`--trace-uid`/`-gid`/
//! `-groups`) — CLI args survive `sudo`'s `env_reset` where env vars don't, and
//! need no `SETENV` in sudoers. `current_supplementary_groups` captures them on
//! the way in; `trace_drop_credentials` reconstructs them (falling back to
//! `SUDO_UID`/`SUDO_GID` when the explicit args are absent) into the
//! `TraceDropCredentials` the dtrace consumer applies to the spawned child.
//!
//! `exec_trace_child` is the hidden `__trace-child` entry point: it drops
//! privilege in the mandatory order — `setgroups` → `setgid` → `setuid` (groups
//! and gid first, because once uid is dropped you can no longer change them) —
//! then re-parses and dispatches the forwarded carrick command via
//! [`crate::commands::run_cli`] as the unprivileged user.
//!
//! The whole module is `cfg(target_os = "macos")`: libdtrace is the only tracer,
//! and it is macOS-only.

// Used only by the macOS-only (`cfg(target_os = "macos")`) tracer functions below
// — the whole module is effectively macOS-only (libdtrace is the only tracer).
#[cfg(target_os = "macos")]
use anyhow::{Context, bail};

#[cfg(target_os = "macos")]
use crate::args::Cli;

#[cfg(target_os = "macos")]
use clap::Parser;
#[cfg(target_os = "macos")]
use std::ffi::{OsStr, OsString};
#[cfg(target_os = "macos")]
use std::path::Path;

#[cfg(target_os = "macos")]
use crate::trace_profile::TraceProfileKind;

#[cfg(target_os = "macos")]
pub(crate) struct TraceSudoInvocation<'a> {
    pub(crate) executable: &'a Path,
    pub(crate) flowindent: bool,
    pub(crate) script: Option<&'a Path>,
    pub(crate) profile: Option<TraceProfileKind>,
    pub(crate) summary_jsonl: Option<&'a Path>,
    pub(crate) trace_out: Option<&'a Path>,
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    pub(crate) groups: &'a [u32],
    pub(crate) forwarded_env: &'a [(OsString, OsString)],
    pub(crate) command: &'a [String],
}

#[cfg(target_os = "macos")]
pub(crate) fn trace_sudo_argv(invocation: &TraceSudoInvocation<'_>) -> Vec<OsString> {
    let mut argv = vec![
        invocation.executable.as_os_str().to_owned(),
        OsString::from("trace"),
    ];
    if invocation.flowindent {
        argv.push(OsString::from("--flowindent"));
    }
    if let Some(script) = invocation.script {
        argv.push(OsString::from("--script"));
        argv.push(script.as_os_str().to_owned());
    }
    if let Some(profile) = invocation.profile {
        argv.push(OsString::from("--profile"));
        argv.push(OsString::from(profile.as_str()));
    }
    if let Some(path) = invocation.summary_jsonl {
        argv.push(OsString::from("--summary-jsonl"));
        argv.push(path.as_os_str().to_owned());
    }
    if let Some(path) = invocation.trace_out {
        argv.push(OsString::from("--trace-out"));
        argv.push(path.as_os_str().to_owned());
    }
    argv.push(OsString::from("--trace-uid"));
    argv.push(OsString::from(invocation.uid.to_string()));
    argv.push(OsString::from("--trace-gid"));
    argv.push(OsString::from(invocation.gid.to_string()));
    if !invocation.groups.is_empty() {
        argv.push(OsString::from("--trace-groups"));
        argv.push(OsString::from(
            invocation
                .groups
                .iter()
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join(","),
        ));
    }
    for (key, value) in invocation.forwarded_env {
        argv.push(OsString::from("--forward-env"));
        let mut pair = key.clone();
        pair.push(OsStr::new("="));
        pair.push(value);
        argv.push(pair);
    }
    argv.push(OsString::from("--"));
    argv.extend(invocation.command.iter().map(OsString::from));
    argv
}

#[cfg(target_os = "macos")]
pub(crate) fn current_supplementary_groups() -> Vec<u32> {
    let count = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
    if count <= 0 {
        return Vec::new();
    }
    let mut groups = vec![0 as libc::gid_t; count as usize];
    let n = unsafe { libc::getgroups(count, groups.as_mut_ptr()) };
    if n <= 0 {
        return Vec::new();
    }
    groups.truncate(n as usize);
    groups.into_iter().collect()
}

#[cfg(target_os = "macos")]
pub(crate) fn trace_drop_credentials(
    trace_uid: Option<u32>,
    trace_gid: Option<u32>,
    trace_groups: &[u32],
) -> Option<carrick_runtime::dtrace_consumer::TraceDropCredentials> {
    let (uid, gid) = match (trace_uid, trace_gid) {
        (Some(uid), Some(gid)) => (uid, gid),
        _ => {
            let uid = std::env::var("SUDO_UID").ok()?.parse().ok()?;
            let gid = std::env::var("SUDO_GID").ok()?.parse().ok()?;
            (uid, gid)
        }
    };

    Some(carrick_runtime::dtrace_consumer::TraceDropCredentials {
        uid,
        gid,
        groups: normalize_trace_groups(gid, trace_groups),
    })
}

#[cfg(target_os = "macos")]
fn normalize_trace_groups(primary_gid: u32, groups: &[u32]) -> Vec<u32> {
    let mut normalized = if groups.is_empty() {
        vec![primary_gid]
    } else {
        groups.to_vec()
    };
    if !normalized.contains(&primary_gid) {
        normalized.insert(0, primary_gid);
    }
    normalized
}

#[cfg(target_os = "macos")]
pub(crate) fn exec_trace_child(
    trace_uid: u32,
    trace_gid: u32,
    trace_groups: &[u32],
    command: &[String],
) -> anyhow::Result<()> {
    if command.is_empty() {
        bail!("trace child needs a carrick subcommand to dispatch");
    }

    let groups = normalize_trace_groups(trace_gid, trace_groups);
    let groups: Vec<libc::gid_t> = groups.into_iter().map(|g| g as libc::gid_t).collect();
    if unsafe { libc::setgroups(groups.len() as libc::c_int, groups.as_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error())
            .context("trace child failed to set supplementary groups");
    }
    if unsafe { libc::setgid(trace_gid as libc::gid_t) } != 0 {
        return Err(std::io::Error::last_os_error()).context("trace child failed to set gid");
    }
    if unsafe { libc::setuid(trace_uid as libc::uid_t) } != 0 {
        return Err(std::io::Error::last_os_error()).context("trace child failed to set uid");
    }

    let mut argv = Vec::with_capacity(command.len() + 1);
    argv.push("carrick".to_owned());
    argv.extend(command.iter().cloned());
    crate::commands::run_cli(Cli::parse_from(argv))
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;

    #[test]
    fn sudo_argv_preserves_profile_paths_identity_and_environment() {
        let environment = [(OsString::from("CARRICK_DSR_PROFILE"), OsString::from("1"))];
        let command = ["run-elf".to_owned(), "/tmp/probe".to_owned()];
        let argv = trace_sudo_argv(&TraceSudoInvocation {
            executable: Path::new("/tmp/carrick"),
            flowindent: false,
            script: None,
            profile: Some(TraceProfileKind::DsrIndirect),
            summary_jsonl: Some(Path::new("/tmp/summary.jsonl")),
            trace_out: Some(Path::new("/tmp/raw.trace")),
            uid: 501,
            gid: 20,
            groups: &[20, 12],
            forwarded_env: &environment,
            command: &command,
        });
        let strings: Vec<_> = argv
            .iter()
            .map(|value| value.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            strings,
            [
                "/tmp/carrick",
                "trace",
                "--profile",
                "dsr-indirect",
                "--summary-jsonl",
                "/tmp/summary.jsonl",
                "--trace-out",
                "/tmp/raw.trace",
                "--trace-uid",
                "501",
                "--trace-gid",
                "20",
                "--trace-groups",
                "20,12",
                "--forward-env",
                "CARRICK_DSR_PROFILE=1",
                "--",
                "run-elf",
                "/tmp/probe",
            ]
        );
    }
}
