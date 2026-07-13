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
    pub(crate) executable_path: Vec<u8>,
    pub(crate) argv: Vec<Vec<u8>>,
    pub(crate) env: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum NativeExecCapsulePurposeV1 {
    PidProbe,
    GuestExec,
}

impl NativeExecCapsuleV1 {
    fn validate(&self) -> Result<(), NativeExecCapsuleError> {
        if self.executable_path.is_empty() || self.executable_path.len() > MAX_PATH_LEN {
            return Err(NativeExecCapsuleError::InvalidField("executable_path"));
        }
        validate_byte_vector("argv", &self.argv)?;
        validate_byte_vector("env", &self.env)?;
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
        executable_path: executable_bytes.clone(),
        argv: Vec::new(),
        env: Vec::new(),
    };
    let mut nonce = [0_u8; 16];
    getrandom::fill(&mut nonce)
        .map_err(|error| anyhow::anyhow!("generate native exec capsule nonce: {error}"))?;
    let capsule = tempfile::tempfile()?;
    write_capsule(capsule.as_raw_fd(), nonce, &payload)?;

    let old_flags = unsafe { libc::fcntl(capsule.as_raw_fd(), libc::F_GETFD) };
    if old_flags < 0 {
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
        return Err(std::io::Error::last_os_error().into());
    }

    let nonce_hex = encode_nonce(nonce);
    let fd_arg = capsule.as_raw_fd().to_string();
    let executable_c = CString::new(executable_bytes)?;
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
    Err(exec_error.into())
}

pub(crate) fn resume_pid_probe(fd: RawFd, nonce_hex: &str) -> anyhow::Result<(u32, u32)> {
    let nonce = decode_nonce(nonce_hex)?;
    let payload = read_capsule_once(fd, nonce)?;
    if payload.purpose != NativeExecCapsulePurposeV1::PidProbe {
        anyhow::bail!("native exec capsule purpose is not a PID probe");
    }
    let current_pid = unsafe { libc::getpid() as u32 };
    if payload.producer_pid != current_pid {
        anyhow::bail!(
            "native self-reexec changed PID from {} to {}",
            payload.producer_pid,
            current_pid
        );
    }
    let current_executable = std::env::current_exe()?;
    if current_executable.as_os_str().as_bytes() != payload.executable_path {
        anyhow::bail!("native self-reexec resumed through a different executable");
    }
    unsafe {
        libc::close(fd);
    }
    Ok((payload.producer_pid, current_pid))
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
    file.sync_data()?;
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
    file.sync_data()?;
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
        read_capsule_once, write_capsule,
    };

    fn sample() -> NativeExecCapsuleV1 {
        NativeExecCapsuleV1 {
            producer_pid: 42,
            purpose: NativeExecCapsulePurposeV1::GuestExec,
            executable_path: b"/bin/probe".to_vec(),
            argv: vec![b"probe".to_vec(), b"stage2".to_vec()],
            env: vec![b"A=B".to_vec()],
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
