//! Small Darwin filesystem primitives used by Linux syscall emulation.

use crate::dispatch::host_errno;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CopyfileResult {
    Cloned(u64),
    Copied(u64),
}

impl CopyfileResult {
    pub(crate) fn bytes(self) -> u64 {
        match self {
            CopyfileResult::Cloned(bytes) | CopyfileResult::Copied(bytes) => bytes,
        }
    }
}

pub(crate) fn copyfile_clone_or_data(
    src_fd: i32,
    dst_fd: i32,
    expected_len: u64,
) -> Result<Option<CopyfileResult>, i32> {
    if let Some(bytes) = run_fcopyfile(src_fd, dst_fd, libc::COPYFILE_DATA, expected_len)? {
        return Ok(Some(CopyfileResult::Copied(bytes)));
    }
    if let Some(bytes) = run_fcopyfile(src_fd, dst_fd, libc::COPYFILE_CLONE, expected_len)? {
        return Ok(Some(CopyfileResult::Cloned(bytes)));
    }
    Ok(None)
}

fn run_fcopyfile(
    src_fd: i32,
    dst_fd: i32,
    flags: libc::copyfile_flags_t,
    expected_len: u64,
) -> Result<Option<u64>, i32> {
    let state = CopyfileState::new()?;
    let rc = unsafe { libc::fcopyfile(src_fd, dst_fd, state.raw, flags) };
    if rc < 0 {
        return Ok(None);
    }
    Ok(Some(
        state
            .copied_bytes()
            .filter(|bytes| *bytes > 0)
            .unwrap_or(expected_len),
    ))
}

struct CopyfileState {
    raw: libc::copyfile_state_t,
}

impl CopyfileState {
    fn new() -> Result<Self, i32> {
        let raw = unsafe { libc::copyfile_state_alloc() };
        if raw.is_null() {
            return Err(host_errno());
        }
        Ok(Self { raw })
    }

    fn copied_bytes(&self) -> Option<u64> {
        let mut copied: libc::off_t = 0;
        let rc = unsafe {
            libc::copyfile_state_get(
                self.raw,
                libc::COPYFILE_STATE_COPIED as u32,
                (&mut copied as *mut libc::off_t).cast::<libc::c_void>(),
            )
        };
        if rc == 0 && copied >= 0 {
            Some(copied as u64)
        } else {
            None
        }
    }
}

impl Drop for CopyfileState {
    fn drop(&mut self) {
        unsafe {
            libc::copyfile_state_free(self.raw);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;

    #[test]
    fn copyfile_clone_or_data_copies_between_file_descriptors() {
        let dir = tempfile::TempDir::new().unwrap();
        let src_path = dir.path().join("src");
        let dst_path = dir.path().join("dst");
        std::fs::write(&src_path, b"darwin copyfile fast path\n").unwrap();
        let src = std::fs::File::open(&src_path).unwrap();
        let dst = std::fs::OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&dst_path)
            .unwrap();

        let result = copyfile_clone_or_data(src.as_raw_fd(), dst.as_raw_fd(), 26)
            .unwrap()
            .expect("copyfile fast path should copy regular files");
        assert_eq!(result.bytes(), 26);
        drop(dst);
        assert_eq!(
            std::fs::read(&dst_path).unwrap(),
            b"darwin copyfile fast path\n"
        );
    }
}
