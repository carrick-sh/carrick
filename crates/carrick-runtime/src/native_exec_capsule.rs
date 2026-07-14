//! Versioned kernel-backed handoff for a native fork-child host self-exec.

use std::ffi::{CStr, CString};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::FileExt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const CAPSULE_MAGIC: [u8; 8] = *b"CRKNEXE\0";
const CONSUMED_MAGIC: [u8; 8] = [0; 8];
const CAPSULE_VERSION: u16 = 1;
const HEADER_LEN: usize = 68;
const MAX_PAYLOAD_LEN: usize = 16 * 1024 * 1024;
const MAX_VECTOR_ITEMS: usize = 4096;
const MAX_ITEM_LEN: usize = 1024 * 1024;
const MAX_PATH_LEN: usize = 4096;

/// First schema carried by the native host-self-exec transport.
///
/// Process, filesystem, and descriptor records are added to this typed payload
/// as their snapshot APIs land. These launch fields are sufficient to prove the
/// transport and PID-preserving host exec without making the framing generic or
/// exposing an untyped byte-bag at its trust boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct NativeExecCapsuleV1 {
    pub(crate) producer_pid: u32,
    pub(crate) purpose: NativeExecCapsulePurposeV1,
    pub(crate) host_executable_path: Vec<u8>,
    pub(crate) argv: Vec<Vec<u8>>,
    pub(crate) env: Vec<Vec<u8>>,
    pub(crate) guest_exec: Option<NativeGuestExecV1>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum NativeExecCapsulePurposeV1 {
    PidProbe,
    GuestExec,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct NativeGuestExecV1 {
    pub(crate) resolved_path: String,
    pub(crate) executable_digest: [u8; 32],
    pub(crate) rootfs: crate::fs_backend::HostFsReexecAuthority,
    pub(crate) cwd: String,
    pub(crate) stream_stdio: bool,
    pub(crate) exec_host_fs_fallback: bool,
    pub(crate) max_traps: u64,
    pub(crate) native_page_profile: carrick_spec::NativePageProfileRequest,
    pub(crate) fd_table: crate::dispatch::fd_table::NativeReexecFdTableV1,
    pub(crate) xsig: NativeReexecXsigV1,
    pub(crate) process_state: NativeReexecProcessStateV1,
    pub(crate) prepared_image: Option<crate::native_prepared_image::NativePreparedImageV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct NativeReexecXsigV1 {
    pub(crate) host_fd: i32,
    pub(crate) original_host_fd_flags: i32,
    pub(crate) host_device: u64,
    pub(crate) host_inode: u64,
    pub(crate) host_size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct NativeReexecProcessStateV1 {
    pub(crate) credentials: NativeReexecCredentialsV1,
    pub(crate) supplementary_groups_override: Option<Vec<u32>>,
    pub(crate) ignored_signals: u64,
    pub(crate) nofile_soft: u64,
    pub(crate) rlimit_overrides: Vec<Option<NativeReexecRlimitV1>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct NativeReexecCredentialsV1 {
    pub(crate) ruid: u32,
    pub(crate) euid: u32,
    pub(crate) suid: u32,
    pub(crate) rgid: u32,
    pub(crate) egid: u32,
    pub(crate) sgid: u32,
    pub(crate) fsuid: u32,
    pub(crate) fsgid: u32,
    pub(crate) umask: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct NativeReexecRlimitV1 {
    pub(crate) current: u64,
    pub(crate) maximum: u64,
}

impl NativeExecCapsuleV1 {
    fn validate(&self) -> Result<(), NativeExecCapsuleError> {
        if self.host_executable_path.is_empty() || self.host_executable_path.len() > MAX_PATH_LEN {
            return Err(NativeExecCapsuleError::InvalidField("host_executable_path"));
        }
        validate_byte_vector("argv", &self.argv)?;
        validate_byte_vector("env", &self.env)?;
        match (self.purpose, &self.guest_exec) {
            (NativeExecCapsulePurposeV1::PidProbe, None) => {}
            (NativeExecCapsulePurposeV1::GuestExec, Some(guest)) => guest.validate()?,
            _ => return Err(NativeExecCapsuleError::InvalidField("purpose")),
        }
        Ok(())
    }
}

impl NativeGuestExecV1 {
    fn validate(&self) -> Result<(), NativeExecCapsuleError> {
        if self.resolved_path.is_empty()
            || self.resolved_path.len() > MAX_PATH_LEN
            || self.cwd.is_empty()
            || self.cwd.len() > MAX_PATH_LEN
            || self.rootfs.root_path.is_empty()
            || self.rootfs.root_path.len() > MAX_PATH_LEN
            || self.max_traps == 0
            || self.fd_table.files.len() > MAX_VECTOR_ITEMS
            || self.fd_table.descriptions.len() > MAX_VECTOR_ITEMS
            || self.fd_table.close_on_exec_host_fds.len() > MAX_VECTOR_ITEMS
            || self.xsig.host_fd < 0
            || self
                .process_state
                .supplementary_groups_override
                .as_ref()
                .is_some_and(|groups| groups.len() > 65_536)
            || self.process_state.credentials.umask & !0o777 != 0
            || self.process_state.rlimit_overrides.len() != 16
        {
            return Err(NativeExecCapsuleError::InvalidField("guest_exec"));
        }
        Ok(())
    }
}

pub(crate) fn begin_pid_probe() -> anyhow::Result<()> {
    let executable = std::env::current_exe()?;
    let executable_bytes = executable.as_os_str().as_bytes().to_vec();
    let producer_pid = unsafe { libc::getpid() as u32 };
    let payload = NativeExecCapsuleV1 {
        producer_pid,
        purpose: NativeExecCapsulePurposeV1::PidProbe,
        host_executable_path: executable_bytes,
        argv: Vec::new(),
        env: Vec::new(),
        guest_exec: None,
    };
    let mut nonce = [0_u8; 16];
    getrandom::fill(&mut nonce)
        .map_err(|error| anyhow::anyhow!("generate native exec capsule nonce: {error}"))?;
    exec_capsule(payload, nonce, None)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn begin_guest_exec(
    dispatcher: &crate::dispatch::SyscallDispatcher,
    image: &crate::memory::AddressSpace,
    relative_relocations: &[crate::native_prepared_image::NativeRelativeRelocation],
    resolved_path: String,
    argv: Vec<Vec<u8>>,
    env: Vec<Vec<u8>>,
    executable_digest: [u8; 32],
    max_traps: usize,
    plan: &crate::page_profile::ExecutionPlan,
) -> anyhow::Result<()> {
    emit_lifecycle(
        unsafe { libc::getpid() },
        crate::probes::DsrCacheLifecyclePhase::HostSelfReexecCapsulePrepareBegin,
    );
    let executable = std::env::current_exe()?;
    let native_page_profile = match plan.page_geometry.native_profile {
        Some(carrick_spec::NativePageProfile::Native16k) => {
            carrick_spec::NativePageProfileRequest::Native16k
        }
        Some(carrick_spec::NativePageProfile::Linux4kOn16k) => {
            carrick_spec::NativePageProfileRequest::Linux4k
        }
        None => anyhow::bail!("native guest exec has no native page profile"),
    };
    let rootfs = dispatcher
        .native_fs_reexec_authority()
        .map_err(|error| anyhow::anyhow!("native guest exec rootfs is ineligible: {error:?}"))?;
    let fd_table = dispatcher
        .snapshot_native_reexec_fd_table()
        .map_err(|error| anyhow::anyhow!("native guest exec fd table is ineligible: {error}"))?;
    let xsig = snapshot_xsig()?;
    let process_state = dispatcher.snapshot_native_reexec_process_state();
    let mut payload = NativeExecCapsuleV1 {
        producer_pid: unsafe { libc::getpid() as u32 },
        purpose: NativeExecCapsulePurposeV1::GuestExec,
        host_executable_path: executable.as_os_str().as_bytes().to_vec(),
        argv,
        env,
        guest_exec: Some(NativeGuestExecV1 {
            resolved_path,
            executable_digest,
            rootfs,
            cwd: dispatcher.cwd(),
            stream_stdio: dispatcher.stream_stdio_enabled(),
            exec_host_fs_fallback: dispatcher.exec_host_fs_fallback(),
            max_traps: u64::try_from(max_traps)?,
            native_page_profile,
            fd_table,
            xsig,
            process_state,
            prepared_image: None,
        }),
    };
    let prepared_artifact = attach_prepared_image(
        &mut payload,
        image,
        relative_relocations,
        plan.page_geometry.host_page_size,
    );
    let mut nonce = [0_u8; 16];
    getrandom::fill(&mut nonce)
        .map_err(|error| anyhow::anyhow!("generate native exec capsule nonce: {error}"))?;
    exec_capsule(payload, nonce, prepared_artifact)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PreparedImageFailpoint {
    #[cfg(test)]
    Ineligible,
    #[cfg(test)]
    ArtifactCreation,
    #[cfg(test)]
    PreExecValidation,
}

fn attach_prepared_image(
    payload: &mut NativeExecCapsuleV1,
    image: &crate::memory::AddressSpace,
    relative_relocations: &[crate::native_prepared_image::NativeRelativeRelocation],
    host_page_size: u64,
) -> Option<crate::native_prepared_image::PreparedImageArtifact> {
    attach_prepared_image_inner(payload, image, relative_relocations, host_page_size, None)
}

#[cfg(test)]
fn attach_prepared_image_with_failpoint(
    payload: &mut NativeExecCapsuleV1,
    image: &crate::memory::AddressSpace,
    relative_relocations: &[crate::native_prepared_image::NativeRelativeRelocation],
    host_page_size: u64,
    failpoint: PreparedImageFailpoint,
) -> Option<crate::native_prepared_image::PreparedImageArtifact> {
    attach_prepared_image_inner(
        payload,
        image,
        relative_relocations,
        host_page_size,
        Some(failpoint),
    )
}

fn attach_prepared_image_inner(
    payload: &mut NativeExecCapsuleV1,
    image: &crate::memory::AddressSpace,
    relative_relocations: &[crate::native_prepared_image::NativeRelativeRelocation],
    host_page_size: u64,
    failpoint: Option<PreparedImageFailpoint>,
) -> Option<crate::native_prepared_image::PreparedImageArtifact> {
    #[cfg(not(test))]
    let _ = failpoint;
    #[cfg(test)]
    if failpoint == Some(PreparedImageFailpoint::Ineligible) {
        tracing::debug!(
            reason = "test failpoint",
            "native prepared image is ineligible; using legacy self-reexec reload"
        );
        return None;
    }
    #[cfg(test)]
    if failpoint == Some(PreparedImageFailpoint::ArtifactCreation) {
        tracing::warn!(
            error = "test artifact creation failpoint",
            "native prepared image construction failed; using legacy self-reexec reload"
        );
        return None;
    }

    let disposition =
        match crate::native_prepared_image::prepare(image, relative_relocations, host_page_size) {
            Ok(disposition) => disposition,
            Err(error) => {
                tracing::warn!(
                    %error,
                    "native prepared image construction failed; using legacy self-reexec reload"
                );
                return None;
            }
        };
    let artifact = match disposition {
        crate::native_prepared_image::PreparedImageDisposition::Prepared(artifact) => artifact,
        crate::native_prepared_image::PreparedImageDisposition::Ineligible(reason) => {
            tracing::debug!(
                ?reason,
                "native prepared image is ineligible; using legacy self-reexec reload"
            );
            return None;
        }
    };
    #[cfg(test)]
    if failpoint == Some(PreparedImageFailpoint::PreExecValidation) {
        let artifact_fd = artifact.file.as_raw_fd();
        let mut identity = std::mem::MaybeUninit::<libc::stat>::uninit();
        let identity_ok = unsafe { libc::fstat(artifact_fd, identity.as_mut_ptr()) } == 0;
        let identity = identity_ok.then(|| unsafe { identity.assume_init() });
        tracing::warn!(
            error = "test pre-exec validation failpoint",
            "native prepared image self-validation failed; using legacy self-reexec reload"
        );
        drop(artifact);
        let artifact_was_closed = identity.is_some_and(|identity| {
            fd_no_longer_refers_to(artifact_fd, identity.st_dev as u64, identity.st_ino)
        });
        LAST_PREEXEC_VALIDATION_ARTIFACT
            .with(|captured| captured.set(Some((artifact_fd, artifact_was_closed))));
        return None;
    }
    let Some(guest) = payload.guest_exec.as_mut() else {
        tracing::warn!(
            "native prepared image has no guest capsule owner; using legacy self-reexec reload"
        );
        return None;
    };
    guest.prepared_image = Some(artifact.record.clone());
    Some(artifact)
}

fn exec_capsule(
    payload: NativeExecCapsuleV1,
    nonce: [u8; 16],
    prepared_artifact: Option<crate::native_prepared_image::PreparedImageArtifact>,
) -> anyhow::Result<()> {
    exec_capsule_with(payload, nonce, prepared_artifact, |request| {
        unsafe {
            libc::execve(
                request.executable.as_ptr(),
                request.argv.as_ptr(),
                request.env.as_ptr(),
            );
        }
        std::io::Error::last_os_error()
    })
}

struct HostExecRequest<'a> {
    executable: &'a CStr,
    argv: &'a [*const libc::c_char],
    env: &'a [*const libc::c_char],
    #[cfg(test)]
    capsule_fd: RawFd,
}

fn exec_capsule_with<F>(
    payload: NativeExecCapsuleV1,
    nonce: [u8; 16],
    prepared_artifact: Option<crate::native_prepared_image::PreparedImageArtifact>,
    invoke_exec: F,
) -> anyhow::Result<()>
where
    F: FnOnce(HostExecRequest<'_>) -> std::io::Error,
{
    let payload_prepared_record = payload
        .guest_exec
        .as_ref()
        .and_then(|guest| guest.prepared_image.as_ref());
    let owned_prepared_record = prepared_artifact.as_ref().map(|artifact| &artifact.record);
    if payload_prepared_record != owned_prepared_record {
        anyhow::bail!("native prepared image capsule record has no matching fd owner");
    }
    let capsule = tempfile::tempfile()?;
    write_capsule(capsule.as_raw_fd(), nonce, &payload)?;

    let nonce_hex = encode_nonce(nonce);
    let fd_arg = capsule.as_raw_fd().to_string();
    let executable_c = CString::new(payload.host_executable_path.clone())?;
    let argv = [
        executable_c.clone(),
        CString::new("__native-exec-resume")?,
        CString::new("--capsule-fd")?,
        CString::new(fd_arg)?,
        CString::new("--nonce")?,
        CString::new(nonce_hex)?,
    ];
    let argv_ptrs = argv
        .iter()
        .map(|value| value.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect::<Vec<_>>();
    let env = std::env::vars_os()
        .map(|(key, value)| {
            let mut entry = key.as_os_str().as_bytes().to_vec();
            entry.push(b'=');
            entry.extend_from_slice(value.as_os_str().as_bytes());
            CString::new(entry)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let env_ptrs = env
        .iter()
        .map(|value| value.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect::<Vec<_>>();

    let mut prepared_host_fds = HostFdFlagTransaction::default();
    if let Some(guest) = &payload.guest_exec {
        prepared_host_fds.prepare(
            guest.xsig.host_fd,
            guest.xsig.original_host_fd_flags,
            guest.xsig.original_host_fd_flags & !libc::FD_CLOEXEC,
        )?;
        for (fd, expected_flags) in guest.fd_table.survivor_host_fds() {
            prepared_host_fds.prepare(fd, expected_flags, expected_flags & !libc::FD_CLOEXEC)?;
        }
        for fd in &guest.fd_table.close_on_exec_host_fds {
            let flags = unsafe { libc::fcntl(*fd, libc::F_GETFD) };
            if flags < 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            prepared_host_fds.prepare(*fd, flags, flags | libc::FD_CLOEXEC)?;
        }
    }

    let old_flags = unsafe { libc::fcntl(capsule.as_raw_fd(), libc::F_GETFD) };
    if old_flags < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    prepared_host_fds.prepare(
        capsule.as_raw_fd(),
        old_flags,
        old_flags & !libc::FD_CLOEXEC,
    )?;
    if let Some(artifact) = &prepared_artifact {
        let (fd, flags) = artifact.transport_fd_snapshot();
        prepared_host_fds.prepare(fd, flags, flags & !libc::FD_CLOEXEC)?;
    }

    emit_lifecycle(
        unsafe { libc::getpid() },
        crate::probes::DsrCacheLifecyclePhase::HostSelfReexecBegin,
    );
    let exec_error = invoke_exec(HostExecRequest {
        executable: &executable_c,
        argv: &argv_ptrs,
        env: &env_ptrs,
        #[cfg(test)]
        capsule_fd: capsule.as_raw_fd(),
    });
    Err(exec_error.into())
}

#[derive(Default)]
struct HostFdFlagTransaction {
    prepared: Vec<(RawFd, i32)>,
}

impl HostFdFlagTransaction {
    fn prepare(
        &mut self,
        fd: RawFd,
        expected_flags: i32,
        desired_flags: i32,
    ) -> anyhow::Result<()> {
        prepare_host_fd_flags(fd, expected_flags, desired_flags, &mut self.prepared)
    }
}

impl Drop for HostFdFlagTransaction {
    fn drop(&mut self) {
        restore_host_fd_flags(&self.prepared);
    }
}

#[cfg(test)]
thread_local! {
    static FAIL_ARTIFACT_FD_FLAG_PREPARATION: std::cell::Cell<Option<RawFd>> = const {
        std::cell::Cell::new(None)
    };
    static LAST_PREEXEC_VALIDATION_ARTIFACT: std::cell::Cell<Option<(RawFd, bool)>> = const {
        std::cell::Cell::new(None)
    };
}

#[cfg(test)]
fn fail_next_artifact_fd_flag_preparation(fd: RawFd) {
    FAIL_ARTIFACT_FD_FLAG_PREPARATION.with(|failpoint| failpoint.set(Some(fd)));
}

#[cfg(test)]
fn take_last_preexec_validation_artifact() -> Option<(RawFd, bool)> {
    LAST_PREEXEC_VALIDATION_ARTIFACT.with(std::cell::Cell::take)
}

#[cfg(test)]
fn fd_no_longer_refers_to(fd: RawFd, expected_device: u64, expected_inode: u64) -> bool {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(fd, stat.as_mut_ptr()) } < 0 {
        return true;
    }
    let stat = unsafe { stat.assume_init() };
    stat.st_dev as u64 != expected_device || stat.st_ino != expected_inode
}

fn prepare_host_fd_flags(
    fd: i32,
    expected_flags: i32,
    desired_flags: i32,
    prepared: &mut Vec<(i32, i32)>,
) -> anyhow::Result<()> {
    #[cfg(test)]
    if FAIL_ARTIFACT_FD_FLAG_PREPARATION.with(|failpoint| {
        if failpoint.get() == Some(fd) {
            failpoint.take();
            true
        } else {
            false
        }
    }) {
        anyhow::bail!("test artifact fd flag preparation failpoint for fd {fd}");
    }
    let current = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if current < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if current != expected_flags {
        anyhow::bail!("native reexec host fd {fd} flags changed during preparation");
    }
    if current != desired_flags {
        if unsafe { libc::fcntl(fd, libc::F_SETFD, desired_flags) } < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        prepared.push((fd, current));
    }
    Ok(())
}

fn restore_host_fd_flags(prepared: &[(i32, i32)]) {
    for (fd, flags) in prepared.iter().rev() {
        unsafe {
            libc::fcntl(*fd, libc::F_SETFD, *flags);
        }
    }
}

pub(crate) fn resume(fd: RawFd, nonce_hex: &str) -> anyhow::Result<crate::NativeSelfReexecOutcome> {
    let current_pid = unsafe { libc::getpid() };
    emit_lifecycle(
        current_pid,
        crate::probes::DsrCacheLifecyclePhase::HostSelfReexecEnd,
    );
    emit_lifecycle(
        current_pid,
        crate::probes::DsrCacheLifecyclePhase::HostSelfReexecCapsuleBegin,
    );
    let nonce = decode_nonce(nonce_hex)?;
    let payload = read_capsule_once(fd, nonce)?;
    let current_pid = current_pid as u32;
    if payload.producer_pid != current_pid {
        anyhow::bail!(
            "native self-reexec changed PID from {} to {}",
            payload.producer_pid,
            current_pid
        );
    }
    let current_executable = std::env::current_exe()?;
    if current_executable.as_os_str().as_bytes() != payload.host_executable_path {
        anyhow::bail!("native self-reexec resumed through a different executable");
    }
    unsafe {
        libc::close(fd);
    }
    emit_lifecycle(
        current_pid as i32,
        crate::probes::DsrCacheLifecyclePhase::HostSelfReexecCapsuleEnd,
    );
    match payload.purpose {
        NativeExecCapsulePurposeV1::PidProbe => Ok(crate::NativeSelfReexecOutcome::PidProbe {
            before: payload.producer_pid,
            after: current_pid,
        }),
        NativeExecCapsulePurposeV1::GuestExec => {
            let guest = payload
                .guest_exec
                .ok_or_else(|| anyhow::anyhow!("native guest exec capsule has no guest state"))?;
            adopt_xsig(&guest.xsig)?;
            emit_lifecycle(
                current_pid as i32,
                crate::probes::DsrCacheLifecyclePhase::HostSelfReexecRestoreBegin,
            );
            let exit_code =
                crate::native_darwin::resume_guest_from_capsule(guest, payload.argv, payload.env)?;
            Ok(crate::NativeSelfReexecOutcome::GuestExit(exit_code))
        }
    }
}

fn emit_lifecycle(tid: i32, phase: crate::probes::DsrCacheLifecyclePhase) {
    crate::probes::dsr_cache_lifecycle(tid, phase, 0, 0, 0);
}

fn snapshot_xsig() -> anyhow::Result<NativeReexecXsigV1> {
    let host_fd = carrick_signal_core::xsig::xsig_reexec_fd()
        .ok_or_else(|| anyhow::anyhow!("native guest exec has no xsignal ring backing fd"))?;
    let original_host_fd_flags = unsafe { libc::fcntl(host_fd, libc::F_GETFD) };
    if original_host_fd_flags < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(host_fd, stat.as_mut_ptr()) } < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let stat = unsafe { stat.assume_init() };
    Ok(NativeReexecXsigV1 {
        host_fd,
        original_host_fd_flags,
        host_device: stat.st_dev as u64,
        host_inode: stat.st_ino,
        host_size: stat.st_size as u64,
    })
}

fn adopt_xsig(snapshot: &NativeReexecXsigV1) -> anyhow::Result<()> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(snapshot.host_fd, stat.as_mut_ptr()) } < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let stat = unsafe { stat.assume_init() };
    if stat.st_dev as u64 != snapshot.host_device
        || stat.st_ino != snapshot.host_inode
        || stat.st_size as u64 != snapshot.host_size
    {
        anyhow::bail!("native xsignal ring backing identity changed across self-reexec");
    }
    if unsafe {
        libc::fcntl(
            snapshot.host_fd,
            libc::F_SETFD,
            snapshot.original_host_fd_flags,
        )
    } < 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    if !carrick_signal_core::xsig::xsig_adopt_reexec_fd(snapshot.host_fd) {
        anyhow::bail!("native xsignal ring backing could not be adopted after self-reexec");
    }
    Ok(())
}

fn encode_nonce(nonce: [u8; 16]) -> String {
    use std::fmt::Write;

    let mut encoded = String::with_capacity(32);
    for byte in nonce {
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

fn decode_nonce(encoded: &str) -> anyhow::Result<[u8; 16]> {
    if encoded.len() != 32 || !encoded.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        anyhow::bail!("native exec capsule nonce must contain exactly 32 hex digits");
    }
    let mut nonce = [0_u8; 16];
    for (index, chunk) in encoded.as_bytes().chunks_exact(2).enumerate() {
        let digits = std::str::from_utf8(chunk)?;
        nonce[index] = u8::from_str_radix(digits, 16)?;
    }
    Ok(nonce)
}

fn validate_byte_vector(
    field: &'static str,
    values: &[Vec<u8>],
) -> Result<(), NativeExecCapsuleError> {
    if values.len() > MAX_VECTOR_ITEMS || values.iter().any(|value| value.len() > MAX_ITEM_LEN) {
        return Err(NativeExecCapsuleError::InvalidField(field));
    }
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum NativeExecCapsuleError {
    #[error("native exec capsule fd is not a regular file")]
    NotRegular,
    #[error("native exec capsule has an invalid or consumed magic value")]
    InvalidMagic,
    #[error("native exec capsule version {0} is unsupported")]
    UnsupportedVersion(u16),
    #[error("native exec capsule nonce does not match the resume request")]
    NonceMismatch,
    #[error("native exec capsule payload length is invalid")]
    InvalidLength,
    #[error("native exec capsule checksum does not match")]
    ChecksumMismatch,
    #[error("native exec capsule field {0} exceeds its bound")]
    InvalidField(&'static str),
    #[error("native exec capsule payload is malformed: {0}")]
    Malformed(#[from] serde_json::Error),
    #[error("native exec capsule I/O failed: {0}")]
    Io(#[from] std::io::Error),
}

pub(crate) fn write_capsule(
    fd: RawFd,
    nonce: [u8; 16],
    payload: &NativeExecCapsuleV1,
) -> Result<(), NativeExecCapsuleError> {
    payload.validate()?;
    let encoded = serde_json::to_vec(payload)?;
    if encoded.len() > MAX_PAYLOAD_LEN {
        return Err(NativeExecCapsuleError::InvalidLength);
    }

    let file = duplicate_regular_file(fd)?;
    let encoded_len =
        u64::try_from(encoded.len()).map_err(|_| NativeExecCapsuleError::InvalidLength)?;
    let total_len = HEADER_LEN
        .checked_add(encoded.len())
        .ok_or(NativeExecCapsuleError::InvalidLength)?;
    file.set_len(u64::try_from(total_len).map_err(|_| NativeExecCapsuleError::InvalidLength)?)?;

    let mut header = [0_u8; HEADER_LEN];
    header[..8].copy_from_slice(&CAPSULE_MAGIC);
    header[8..10].copy_from_slice(&CAPSULE_VERSION.to_le_bytes());
    header[12..20].copy_from_slice(&encoded_len.to_le_bytes());
    header[20..52].copy_from_slice(&Sha256::digest(&encoded));
    header[52..68].copy_from_slice(&nonce);
    write_all_at(&file, &header, 0)?;
    write_all_at(&file, &encoded, HEADER_LEN as u64)?;
    Ok(())
}

pub(crate) fn read_capsule_once(
    fd: RawFd,
    expected_nonce: [u8; 16],
) -> Result<NativeExecCapsuleV1, NativeExecCapsuleError> {
    let file = duplicate_regular_file(fd)?;
    let mut header = [0_u8; HEADER_LEN];
    read_exact_at(&file, &mut header, 0)?;
    if header[..8] != CAPSULE_MAGIC {
        return Err(NativeExecCapsuleError::InvalidMagic);
    }
    let version = u16::from_le_bytes([header[8], header[9]]);
    if version != CAPSULE_VERSION {
        return Err(NativeExecCapsuleError::UnsupportedVersion(version));
    }
    if header[52..68] != expected_nonce {
        return Err(NativeExecCapsuleError::NonceMismatch);
    }
    let payload_len = u64::from_le_bytes(
        header[12..20]
            .try_into()
            .map_err(|_| NativeExecCapsuleError::InvalidLength)?,
    );
    let payload_len =
        usize::try_from(payload_len).map_err(|_| NativeExecCapsuleError::InvalidLength)?;
    if payload_len > MAX_PAYLOAD_LEN {
        return Err(NativeExecCapsuleError::InvalidLength);
    }
    let expected_file_len = HEADER_LEN
        .checked_add(payload_len)
        .ok_or(NativeExecCapsuleError::InvalidLength)?;
    if file.metadata()?.len()
        != u64::try_from(expected_file_len).map_err(|_| NativeExecCapsuleError::InvalidLength)?
    {
        return Err(NativeExecCapsuleError::InvalidLength);
    }

    let mut encoded = vec![0_u8; payload_len];
    read_exact_at(&file, &mut encoded, HEADER_LEN as u64)?;
    if header[20..52] != Sha256::digest(&encoded)[..] {
        return Err(NativeExecCapsuleError::ChecksumMismatch);
    }
    let payload: NativeExecCapsuleV1 = serde_json::from_slice(&encoded)?;
    payload.validate()?;

    // Invalidate only after the complete payload has passed framing, checksum,
    // schema, and semantic validation. A failed attempt can be diagnosed or
    // retried by the same fresh process, while a successful adoption is one-shot.
    write_all_at(&file, &CONSUMED_MAGIC, 0)?;
    Ok(payload)
}

fn duplicate_regular_file(fd: RawFd) -> Result<std::fs::File, NativeExecCapsuleError> {
    let duplicated = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
    if duplicated < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let file = unsafe { std::fs::File::from_raw_fd(duplicated) };
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file() {
        return Err(NativeExecCapsuleError::NotRegular);
    }
    Ok(file)
}

fn write_all_at(file: &std::fs::File, mut bytes: &[u8], mut offset: u64) -> std::io::Result<()> {
    while !bytes.is_empty() {
        let written = file.write_at(bytes, offset)?;
        if written == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "native exec capsule write made no progress",
            ));
        }
        bytes = &bytes[written..];
        offset = offset.saturating_add(written as u64);
    }
    Ok(())
}

fn read_exact_at(
    file: &std::fs::File,
    mut bytes: &mut [u8],
    mut offset: u64,
) -> std::io::Result<()> {
    while !bytes.is_empty() {
        let read = file.read_at(bytes, offset)?;
        if read == 0 {
            return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
        }
        let (_, rest) = bytes.split_at_mut(read);
        bytes = rest;
        offset = offset.saturating_add(read as u64);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::os::fd::{AsRawFd, RawFd};
    use std::os::unix::fs::FileExt;

    use super::{
        HEADER_LEN, MAX_ITEM_LEN, NativeExecCapsulePurposeV1, NativeExecCapsuleV1,
        NativeGuestExecV1, PreparedImageFailpoint, attach_prepared_image,
        attach_prepared_image_with_failpoint, exec_capsule_with,
        fail_next_artifact_fd_flag_preparation, fd_no_longer_refers_to, read_capsule_once,
        take_last_preexec_validation_artifact, write_capsule,
    };

    const HOST_PAGE_SIZE: u64 = 16 * 1024;

    fn sample() -> NativeExecCapsuleV1 {
        NativeExecCapsuleV1 {
            producer_pid: 42,
            purpose: NativeExecCapsulePurposeV1::GuestExec,
            host_executable_path: b"/bin/probe".to_vec(),
            argv: vec![b"probe".to_vec(), b"stage2".to_vec()],
            env: vec![b"A=B".to_vec()],
            guest_exec: Some(NativeGuestExecV1 {
                resolved_path: "/bin/probe".to_owned(),
                executable_digest: [0x11; 32],
                rootfs: crate::fs_backend::HostFsReexecAuthority {
                    root_path: b"/tmp/root".to_vec(),
                    device: 1,
                    inode: 2,
                    cleanup_on_drop: false,
                },
                cwd: "/".to_owned(),
                stream_stdio: true,
                exec_host_fs_fallback: false,
                max_traps: 100,
                native_page_profile: carrick_spec::NativePageProfileRequest::Native16k,
                fd_table: crate::dispatch::fd_table::NativeReexecFdTableV1 {
                    files: Vec::new(),
                    descriptions: Vec::new(),
                    close_on_exec_host_fds: Vec::new(),
                    closed_stdio: [false; 3],
                },
                xsig: super::NativeReexecXsigV1 {
                    host_fd: 7,
                    original_host_fd_flags: libc::FD_CLOEXEC,
                    host_device: 1,
                    host_inode: 2,
                    host_size: 4096,
                },
                process_state: super::NativeReexecProcessStateV1 {
                    credentials: super::NativeReexecCredentialsV1 {
                        ruid: 1,
                        euid: 2,
                        suid: 3,
                        rgid: 4,
                        egid: 5,
                        sgid: 6,
                        fsuid: 7,
                        fsgid: 8,
                        umask: 0o027,
                    },
                    supplementary_groups_override: Some(vec![9, 10]),
                    ignored_signals: 1 << 12,
                    nofile_soft: 1024,
                    rlimit_overrides: vec![None; 16],
                },
                prepared_image: None,
            }),
        }
    }

    fn synthetic_elf() -> Vec<u8> {
        const ET_EXEC: u16 = 2;
        const EM_AARCH64: u16 = 183;
        const PT_LOAD: u32 = 1;
        const PF_R_X: u32 = 5;
        let mut elf = vec![0_u8; 0x1000];
        elf[0..4].copy_from_slice(b"\x7fELF");
        elf[4] = 2;
        elf[5] = 1;
        elf[6] = 1;
        elf[16..18].copy_from_slice(&ET_EXEC.to_le_bytes());
        elf[18..20].copy_from_slice(&EM_AARCH64.to_le_bytes());
        elf[20..24].copy_from_slice(&1_u32.to_le_bytes());
        elf[24..32].copy_from_slice(&0x400000_u64.to_le_bytes());
        elf[32..40].copy_from_slice(&64_u64.to_le_bytes());
        elf[52..54].copy_from_slice(&64_u16.to_le_bytes());
        elf[54..56].copy_from_slice(&56_u16.to_le_bytes());
        elf[56..58].copy_from_slice(&1_u16.to_le_bytes());
        let ph = 64;
        elf[ph..ph + 4].copy_from_slice(&PT_LOAD.to_le_bytes());
        elf[ph + 4..ph + 8].copy_from_slice(&PF_R_X.to_le_bytes());
        elf[ph + 16..ph + 24].copy_from_slice(&0x400000_u64.to_le_bytes());
        elf[ph + 24..ph + 32].copy_from_slice(&0x400000_u64.to_le_bytes());
        let file_len = elf.len() as u64;
        elf[ph + 32..ph + 40].copy_from_slice(&file_len.to_le_bytes());
        elf[ph + 40..ph + 48].copy_from_slice(&0x4000_u64.to_le_bytes());
        elf[ph + 48..ph + 56].copy_from_slice(&0x1000_u64.to_le_bytes());
        elf[0x800..0x810].copy_from_slice(b"capsule-payload!");
        elf
    }

    fn synthetic_image() -> crate::memory::AddressSpace {
        crate::memory::AddressSpace::load_elf_bytes_with_reader_at_pie_base_without_runtime_regions(
            &synthetic_elf(),
            &|_| None,
            0x400000,
            HOST_PAGE_SIZE,
        )
        .expect("load synthetic executable")
        .with_linux_initial_stack_page_size(
            [b"prepared-capsule".as_slice()],
            [b"MODE=test".as_slice()],
            HOST_PAGE_SIZE,
        )
        .expect("build synthetic stack")
    }

    fn set_fd_flags(fd: RawFd, flags: i32) {
        assert_eq!(unsafe { libc::fcntl(fd, libc::F_SETFD, flags) }, 0);
    }

    fn fd_flags(fd: RawFd) -> i32 {
        unsafe { libc::fcntl(fd, libc::F_GETFD) }
    }

    fn host_identity(fd: RawFd) -> libc::stat {
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        assert_eq!(unsafe { libc::fstat(fd, stat.as_mut_ptr()) }, 0);
        unsafe { stat.assume_init() }
    }

    fn install_transport_fds(
        payload: &mut NativeExecCapsuleV1,
        xsig: &std::fs::File,
        survivor: &std::fs::File,
        close_on_exec: &std::fs::File,
    ) {
        use crate::dispatch::fd_table::{NativeReexecDescriptionV1, NativeReexecFdV1};

        set_fd_flags(xsig.as_raw_fd(), libc::FD_CLOEXEC);
        set_fd_flags(survivor.as_raw_fd(), libc::FD_CLOEXEC);
        set_fd_flags(close_on_exec.as_raw_fd(), 0);
        let xsig_stat = host_identity(xsig.as_raw_fd());
        let survivor_stat = host_identity(survivor.as_raw_fd());
        let guest = payload.guest_exec.as_mut().expect("guest payload");
        guest.xsig = super::NativeReexecXsigV1 {
            host_fd: xsig.as_raw_fd(),
            original_host_fd_flags: libc::FD_CLOEXEC,
            host_device: xsig_stat.st_dev as u64,
            host_inode: xsig_stat.st_ino,
            host_size: xsig_stat.st_size as u64,
        };
        guest.fd_table.files = vec![NativeReexecFdV1 {
            guest_fd: 9,
            fd_flags: 0,
            description_id: 0,
        }];
        guest.fd_table.descriptions = vec![NativeReexecDescriptionV1::File {
            host_fd: survivor.as_raw_fd(),
            original_host_fd_flags: libc::FD_CLOEXEC,
            host_device: survivor_stat.st_dev as u64,
            host_inode: survivor_stat.st_ino,
            host_mode: survivor_stat.st_mode as u32,
            status_flags: 0,
            guest_path: b"/tmp/survivor".to_vec(),
            guest_mode: 0o600,
            guest_size: survivor_stat.st_size as u64,
            writable: false,
        }];
        guest.fd_table.close_on_exec_host_fds = vec![close_on_exec.as_raw_fd()];
    }

    #[test]
    fn prepared_record_round_trips_without_embedding_payload_bytes() {
        let mut payload = sample();
        let artifact = attach_prepared_image(&mut payload, &synthetic_image(), &[], HOST_PAGE_SIZE)
            .expect("eligible prepared artifact");
        let artifact_len = artifact.file.metadata().expect("artifact metadata").len();
        let capsule = tempfile::tempfile().expect("temporary capsule");
        let nonce = [0x44; 16];
        write_capsule(capsule.as_raw_fd(), nonce, &payload).expect("write capsule");
        let capsule_len = capsule.metadata().expect("capsule metadata").len();

        let decoded = read_capsule_once(capsule.as_raw_fd(), nonce).expect("read capsule");
        assert_eq!(decoded, payload);
        assert!(
            decoded
                .guest_exec
                .expect("guest payload")
                .prepared_image
                .is_some()
        );
        assert!(capsule_len < artifact_len / 8);
    }

    #[test]
    fn artifact_ineligibility_and_preexec_errors_select_legacy_before_host_exec() {
        for failpoint in [
            PreparedImageFailpoint::Ineligible,
            PreparedImageFailpoint::ArtifactCreation,
            PreparedImageFailpoint::PreExecValidation,
        ] {
            let mut payload = sample();
            let artifact = attach_prepared_image_with_failpoint(
                &mut payload,
                &synthetic_image(),
                &[],
                HOST_PAGE_SIZE,
                failpoint,
            );
            assert!(artifact.is_none());
            assert!(
                payload
                    .guest_exec
                    .as_ref()
                    .expect("guest payload")
                    .prepared_image
                    .is_none()
            );
            if failpoint == PreparedImageFailpoint::PreExecValidation {
                let (_artifact_fd, artifact_was_closed) = take_last_preexec_validation_artifact()
                    .expect("captured failed validation artifact");
                assert!(artifact_was_closed);
            }
        }
    }

    #[test]
    fn fallback_capsule_reaches_host_exec_without_a_prepared_record() {
        let mut payload = sample();
        assert!(
            attach_prepared_image_with_failpoint(
                &mut payload,
                &synthetic_image(),
                &[],
                HOST_PAGE_SIZE,
                PreparedImageFailpoint::Ineligible,
            )
            .is_none()
        );
        let xsig = tempfile::tempfile().expect("xsignal file");
        let survivor = tempfile::tempfile().expect("survivor file");
        let close_on_exec = tempfile::tempfile().expect("close-on-exec file");
        install_transport_fds(&mut payload, &xsig, &survivor, &close_on_exec);
        let nonce = [0x66; 16];

        let result = exec_capsule_with(payload, nonce, None, |request| {
            let decoded =
                read_capsule_once(request.capsule_fd, nonce).expect("read fallback capsule");
            assert!(
                decoded
                    .guest_exec
                    .expect("guest payload")
                    .prepared_image
                    .is_none()
            );
            std::io::Error::from_raw_os_error(libc::ENOENT)
        });

        assert!(result.is_err());
    }

    #[test]
    fn capsule_validation_failure_keeps_artifact_cloexec_and_closes_owner() {
        let mut payload = sample();
        let artifact = attach_prepared_image(&mut payload, &synthetic_image(), &[], HOST_PAGE_SIZE)
            .expect("eligible prepared artifact");
        let artifact_fd = artifact.file.as_raw_fd();
        let artifact_flags = fd_flags(artifact_fd);
        let artifact_identity = host_identity(artifact_fd);
        payload.argv = vec![vec![0; MAX_ITEM_LEN + 1]];

        let result = exec_capsule_with(payload, [0x77; 16], Some(artifact), |_| {
            panic!("invalid capsule must not reach host exec")
        });

        assert!(result.is_err());
        assert_ne!(artifact_flags & libc::FD_CLOEXEC, 0);
        assert!(fd_no_longer_refers_to(
            artifact_fd,
            artifact_identity.st_dev as u64,
            artifact_identity.st_ino,
        ));
    }

    #[test]
    fn fd_flag_transaction_restores_capsule_style_descriptor() {
        let capsule = tempfile::tempfile().expect("capsule file");
        set_fd_flags(capsule.as_raw_fd(), libc::FD_CLOEXEC);
        {
            let mut transaction = super::HostFdFlagTransaction::default();
            transaction
                .prepare(capsule.as_raw_fd(), libc::FD_CLOEXEC, 0)
                .expect("prepare capsule flags");
            assert_eq!(fd_flags(capsule.as_raw_fd()), 0);
        }
        assert_eq!(fd_flags(capsule.as_raw_fd()), libc::FD_CLOEXEC);
    }

    #[test]
    fn returned_host_exec_restores_every_fd_flag_and_closes_artifact() {
        let mut payload = sample();
        let artifact = attach_prepared_image(&mut payload, &synthetic_image(), &[], HOST_PAGE_SIZE)
            .expect("eligible prepared artifact");
        let artifact_fd = artifact.file.as_raw_fd();
        let artifact_original_flags = fd_flags(artifact_fd);
        let artifact_identity = host_identity(artifact_fd);
        let xsig = tempfile::tempfile().expect("xsignal file");
        let survivor = tempfile::tempfile().expect("survivor file");
        let close_on_exec = tempfile::tempfile().expect("close-on-exec file");
        install_transport_fds(&mut payload, &xsig, &survivor, &close_on_exec);
        let mut saw_exec = false;

        let result = exec_capsule_with(payload, [0x33; 16], Some(artifact), |request| {
            saw_exec = true;
            assert_eq!(fd_flags(request.capsule_fd), 0);
            assert_eq!(
                fd_flags(artifact_fd),
                artifact_original_flags & !libc::FD_CLOEXEC
            );
            assert_eq!(fd_flags(xsig.as_raw_fd()), 0);
            assert_eq!(fd_flags(survivor.as_raw_fd()), 0);
            assert_eq!(fd_flags(close_on_exec.as_raw_fd()), libc::FD_CLOEXEC);
            std::io::Error::from_raw_os_error(libc::ENOENT)
        });

        assert!(saw_exec);
        assert!(result.is_err());
        assert!(fd_no_longer_refers_to(
            artifact_fd,
            artifact_identity.st_dev as u64,
            artifact_identity.st_ino,
        ));
        assert_eq!(fd_flags(xsig.as_raw_fd()), libc::FD_CLOEXEC);
        assert_eq!(fd_flags(survivor.as_raw_fd()), libc::FD_CLOEXEC);
        assert_eq!(fd_flags(close_on_exec.as_raw_fd()), 0);
    }

    #[test]
    fn artifact_flag_failure_rolls_back_prior_flags_and_closes_artifact() {
        let mut payload = sample();
        let artifact = attach_prepared_image(&mut payload, &synthetic_image(), &[], HOST_PAGE_SIZE)
            .expect("eligible prepared artifact");
        let artifact_fd = artifact.file.as_raw_fd();
        let artifact_identity = host_identity(artifact_fd);
        let xsig = tempfile::tempfile().expect("xsignal file");
        let survivor = tempfile::tempfile().expect("survivor file");
        let close_on_exec = tempfile::tempfile().expect("close-on-exec file");
        install_transport_fds(&mut payload, &xsig, &survivor, &close_on_exec);
        fail_next_artifact_fd_flag_preparation(artifact_fd);

        let result = exec_capsule_with(payload, [0x22; 16], Some(artifact), |_| {
            panic!("host exec must not run after artifact flag failure")
        });

        assert!(result.is_err());
        assert!(fd_no_longer_refers_to(
            artifact_fd,
            artifact_identity.st_dev as u64,
            artifact_identity.st_ino,
        ));
        assert_eq!(fd_flags(xsig.as_raw_fd()), libc::FD_CLOEXEC);
        assert_eq!(fd_flags(survivor.as_raw_fd()), libc::FD_CLOEXEC);
        assert_eq!(fd_flags(close_on_exec.as_raw_fd()), 0);
    }

    #[test]
    fn prepared_record_survives_capsule_read_for_resume_adoption() {
        let mut payload = sample();
        let artifact = attach_prepared_image(&mut payload, &synthetic_image(), &[], HOST_PAGE_SIZE)
            .expect("eligible prepared artifact");
        let inherited_fd = unsafe { libc::fcntl(artifact.file.as_raw_fd(), libc::F_DUPFD, 0) };
        assert!(inherited_fd >= 0);
        let inherited_identity = host_identity(inherited_fd);
        payload
            .guest_exec
            .as_mut()
            .expect("guest payload")
            .prepared_image = Some(artifact.record.with_artifact_fd_for_test(inherited_fd));
        let capsule = tempfile::tempfile().expect("temporary capsule");
        let nonce = [0x45; 16];
        write_capsule(capsule.as_raw_fd(), nonce, &payload).expect("write prepared capsule");
        let decoded = read_capsule_once(capsule.as_raw_fd(), nonce).expect("read prepared capsule");

        assert!(
            decoded
                .guest_exec
                .as_ref()
                .and_then(|guest| guest.prepared_image.as_ref())
                .is_some()
        );
        assert!(!fd_no_longer_refers_to(
            inherited_fd,
            inherited_identity.st_dev as u64,
            inherited_identity.st_ino,
        ));
        assert_eq!(unsafe { libc::close(inherited_fd) }, 0);
    }

    #[test]
    fn native_exec_capsule_round_trips_once() {
        let file = tempfile::tempfile().expect("temporary capsule");
        let nonce = [0x5a; 16];
        write_capsule(file.as_raw_fd(), nonce, &sample()).expect("write capsule");

        let decoded = read_capsule_once(file.as_raw_fd(), nonce).expect("read capsule");
        assert_eq!(decoded, sample());
        assert!(read_capsule_once(file.as_raw_fd(), nonce).is_err());
    }

    #[test]
    fn native_exec_capsule_rejects_wrong_nonce_without_consuming() {
        let file = tempfile::tempfile().expect("temporary capsule");
        let nonce = [0x5a; 16];
        write_capsule(file.as_raw_fd(), nonce, &sample()).expect("write capsule");

        assert!(read_capsule_once(file.as_raw_fd(), [0x6b; 16]).is_err());
        assert_eq!(
            read_capsule_once(file.as_raw_fd(), nonce).expect("read with correct nonce"),
            sample()
        );
    }

    #[test]
    fn native_exec_capsule_rejects_corruption_and_trailing_data() {
        let nonce = [0x5a; 16];
        let corrupted = tempfile::tempfile().expect("temporary capsule");
        write_capsule(corrupted.as_raw_fd(), nonce, &sample()).expect("write capsule");
        corrupted
            .write_at(&[0xff], HEADER_LEN as u64)
            .expect("corrupt payload");
        assert!(read_capsule_once(corrupted.as_raw_fd(), nonce).is_err());

        let trailing = tempfile::tempfile().expect("temporary capsule");
        write_capsule(trailing.as_raw_fd(), nonce, &sample()).expect("write capsule");
        trailing
            .write_at(&[0xaa], trailing.metadata().expect("metadata").len())
            .expect("append byte");
        assert!(read_capsule_once(trailing.as_raw_fd(), nonce).is_err());
    }

    #[test]
    fn native_exec_capsule_rejects_bad_version_and_non_regular_fd() {
        let file = tempfile::tempfile().expect("temporary capsule");
        let nonce = [0x5a; 16];
        write_capsule(file.as_raw_fd(), nonce, &sample()).expect("write capsule");
        file.write_at(&2_u16.to_le_bytes(), 8)
            .expect("replace version");
        assert!(read_capsule_once(file.as_raw_fd(), nonce).is_err());

        let (socket, _peer) = std::os::unix::net::UnixStream::pair().expect("socket pair");
        assert!(write_capsule(socket.as_raw_fd(), nonce, &sample()).is_err());
    }

    #[test]
    fn native_exec_capsule_rejects_oversized_nested_values() {
        let file = tempfile::tempfile().expect("temporary capsule");
        let nonce = [0x5a; 16];
        let mut payload = sample();
        payload.argv = vec![vec![0; MAX_ITEM_LEN + 1]];
        assert!(write_capsule(file.as_raw_fd(), nonce, &payload).is_err());
    }
}
