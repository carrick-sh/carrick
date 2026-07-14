//! Versioned kernel-backed handoff for a native fork-child host self-exec.

use std::ffi::CString;
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
    exec_capsule(payload, nonce)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn begin_guest_exec(
    dispatcher: &crate::dispatch::SyscallDispatcher,
    resolved_path: String,
    argv: Vec<Vec<u8>>,
    env: Vec<Vec<u8>>,
    executable_digest: [u8; 32],
    max_traps: usize,
    plan: &crate::page_profile::ExecutionPlan,
) -> anyhow::Result<()> {
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
    let payload = NativeExecCapsuleV1 {
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
        }),
    };
    let mut nonce = [0_u8; 16];
    getrandom::fill(&mut nonce)
        .map_err(|error| anyhow::anyhow!("generate native exec capsule nonce: {error}"))?;
    exec_capsule(payload, nonce)
}

fn exec_capsule(payload: NativeExecCapsuleV1, nonce: [u8; 16]) -> anyhow::Result<()> {
    let capsule = tempfile::tempfile()?;
    write_capsule(capsule.as_raw_fd(), nonce, &payload)?;

    let mut prepared_host_fds = Vec::new();
    if let Some(guest) = &payload.guest_exec {
        if let Err(error) = prepare_host_fd_flags(
            guest.xsig.host_fd,
            guest.xsig.original_host_fd_flags,
            guest.xsig.original_host_fd_flags & !libc::FD_CLOEXEC,
            &mut prepared_host_fds,
        ) {
            restore_host_fd_flags(&prepared_host_fds);
            return Err(error);
        }
        for (fd, expected_flags) in guest.fd_table.survivor_host_fds() {
            if let Err(error) = prepare_host_fd_flags(
                fd,
                expected_flags,
                expected_flags & !libc::FD_CLOEXEC,
                &mut prepared_host_fds,
            ) {
                restore_host_fd_flags(&prepared_host_fds);
                return Err(error);
            }
        }
        for fd in &guest.fd_table.close_on_exec_host_fds {
            let flags = unsafe { libc::fcntl(*fd, libc::F_GETFD) };
            if flags < 0 {
                restore_host_fd_flags(&prepared_host_fds);
                return Err(std::io::Error::last_os_error().into());
            }
            if let Err(error) =
                prepare_host_fd_flags(*fd, flags, flags | libc::FD_CLOEXEC, &mut prepared_host_fds)
            {
                restore_host_fd_flags(&prepared_host_fds);
                return Err(error);
            }
        }
    }

    let old_flags = unsafe { libc::fcntl(capsule.as_raw_fd(), libc::F_GETFD) };
    if old_flags < 0 {
        restore_host_fd_flags(&prepared_host_fds);
        return Err(std::io::Error::last_os_error().into());
    }
    if unsafe {
        libc::fcntl(
            capsule.as_raw_fd(),
            libc::F_SETFD,
            old_flags & !libc::FD_CLOEXEC,
        )
    } < 0
    {
        restore_host_fd_flags(&prepared_host_fds);
        return Err(std::io::Error::last_os_error().into());
    }

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

    unsafe {
        libc::execve(executable_c.as_ptr(), argv_ptrs.as_ptr(), env_ptrs.as_ptr());
    }
    let exec_error = std::io::Error::last_os_error();
    unsafe {
        libc::fcntl(capsule.as_raw_fd(), libc::F_SETFD, old_flags);
    }
    restore_host_fd_flags(&prepared_host_fds);
    Err(exec_error.into())
}

fn prepare_host_fd_flags(
    fd: i32,
    expected_flags: i32,
    desired_flags: i32,
    prepared: &mut Vec<(i32, i32)>,
) -> anyhow::Result<()> {
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
    let nonce = decode_nonce(nonce_hex)?;
    let payload = read_capsule_once(fd, nonce)?;
    let current_pid = unsafe { libc::getpid() as u32 };
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
            let exit_code =
                crate::native_darwin::resume_guest_from_capsule(guest, payload.argv, payload.env)?;
            Ok(crate::NativeSelfReexecOutcome::GuestExit(exit_code))
        }
    }
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
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::FileExt;

    use super::{
        HEADER_LEN, MAX_ITEM_LEN, NativeExecCapsulePurposeV1, NativeExecCapsuleV1,
        NativeGuestExecV1, read_capsule_once, write_capsule,
    };

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
            }),
        }
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
