extern crate alloc;

use crate::file::UserCopy;
use alloc::{boxed::Box, vec::Vec};
use carrick_core_abi::service::{
    EXEC_ARGUMENT_BYTES_MAX, EXEC_PAYLOAD_HEADER_BYTES, ExecCall, MAX_ARG_STRLEN,
    MAX_EXEC_PATH_BYTES, encode_exec_payload_header,
};
use carrick_syscall_abi::{
    LINUX_E2BIG, LINUX_EFAULT, LINUX_ENAMETOOLONG, LINUX_ENOMEM, LinuxErrno,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecStageRequest {
    pub call: ExecCall,
    pub path: u64,
    pub argv: u64,
    pub envp: u64,
}

fn reserve(output: &mut Vec<u8>, additional: usize) -> Result<(), LinuxErrno> {
    output.try_reserve(additional).map_err(|_| LINUX_ENOMEM)
}

fn copy_c_string(
    user: &mut impl UserCopy,
    address: u64,
    limit: usize,
    overflow: LinuxErrno,
    output: &mut Vec<u8>,
) -> Result<usize, LinuxErrno> {
    let start = output.len();
    while output.len() - start < limit {
        let copied = output.len() - start;
        let remaining = limit - copied;
        let current = address.checked_add(copied as u64).ok_or(LINUX_EFAULT)?;
        let page_remaining = 4096 - (current as usize & 4095);
        let chunk = remaining.min(page_remaining).min(256);
        reserve(output, chunk)?;
        output.resize(output.len() + chunk, 0);
        let chunk_start = output.len() - chunk;
        if !user.copy_in(&mut output[chunk_start..], current) {
            output.truncate(chunk_start);
            reserve(output, 1)?;
            output.push(0);
            let last = output.len() - 1;
            if !user.copy_in(&mut output[last..], current) {
                output.truncate(start);
                return Err(LINUX_EFAULT);
            }
            if output[last] == 0 {
                return Ok(output.len() - start);
            }
            continue;
        }
        if let Some(nul) = output[chunk_start..].iter().position(|byte| *byte == 0) {
            output.truncate(chunk_start + nul + 1);
            return Ok(output.len() - start);
        }
    }
    output.truncate(start);
    Err(overflow)
}

fn copy_pointer(user: &mut impl UserCopy, address: u64) -> Result<u64, LinuxErrno> {
    let mut raw = [0; 8];
    if !user.copy_in(&mut raw, address) {
        return Err(LINUX_EFAULT);
    }
    Ok(u64::from_le_bytes(raw))
}

fn stage_vector(
    user: &mut impl UserCopy,
    vector: u64,
    output: &mut Vec<u8>,
    accounting: &mut usize,
) -> Result<usize, LinuxErrno> {
    if vector == 0 {
        return Ok(0);
    }
    let mut count = 0usize;
    loop {
        let pointer_address = vector
            .checked_add((count as u64).checked_mul(8).ok_or(LINUX_EFAULT)?)
            .ok_or(LINUX_EFAULT)?;
        let string = copy_pointer(user, pointer_address)?;
        if string == 0 {
            return Ok(count);
        }
        *accounting = accounting.checked_add(8).ok_or(LINUX_E2BIG)?;
        if *accounting >= EXEC_ARGUMENT_BYTES_MAX {
            return Err(LINUX_E2BIG);
        }
        let length_offset = output.len();
        reserve(output, 4)?;
        output.extend_from_slice(&[0; 4]);
        let length = copy_c_string(user, string, MAX_ARG_STRLEN, LINUX_E2BIG, output)?;
        *accounting = accounting.checked_add(length).ok_or(LINUX_E2BIG)?;
        if *accounting > EXEC_ARGUMENT_BYTES_MAX {
            return Err(LINUX_E2BIG);
        }
        output[length_offset..length_offset + 4].copy_from_slice(
            &u32::try_from(length)
                .map_err(|_| LINUX_E2BIG)?
                .to_le_bytes(),
        );
        count = count.checked_add(1).ok_or(LINUX_E2BIG)?;
    }
}

/// Consume all scattered EL0 pointers while the calling task owns its live
/// stage-1 translation, producing one request-owned contiguous record. The
/// returned box is retained by the native service continuation.
pub fn stage_exec_payload(
    user: &mut impl UserCopy,
    request: ExecStageRequest,
) -> Result<Box<[u8]>, LinuxErrno> {
    let mut output = Vec::new();
    reserve(&mut output, EXEC_PAYLOAD_HEADER_BYTES)?;
    output.resize(EXEC_PAYLOAD_HEADER_BYTES, 0);
    let path_len = copy_c_string(
        user,
        request.path,
        MAX_EXEC_PATH_BYTES,
        LINUX_ENAMETOOLONG,
        &mut output,
    )?;
    // Linux counts both terminating vector pointers even for NULL argv/envp.
    let mut accounting = 16usize;
    let argc = stage_vector(user, request.argv, &mut output, &mut accounting)?;
    let envc = stage_vector(user, request.envp, &mut output, &mut accounting)?;
    encode_exec_payload_header(&mut output, request.call, path_len, argc, envc)
        .map_err(|_| LINUX_E2BIG)?;
    Ok(output.into_boxed_slice())
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::file::UserCopy;
    use carrick_core_abi::service::{ExecCall, ExecPayloadView, MAX_ARG_STRLEN};
    use carrick_syscall_abi::{LINUX_E2BIG, LINUX_EFAULT};
    use std::vec;
    use std::vec::Vec;

    const BASE: u64 = 0x10_0000;

    struct Memory(Vec<u8>);

    impl Memory {
        fn new(bytes: usize) -> Self {
            Self(vec![0; bytes])
        }

        fn put(&mut self, offset: usize, bytes: &[u8]) -> u64 {
            self.0[offset..offset + bytes.len()].copy_from_slice(bytes);
            BASE + offset as u64
        }

        fn put_ptrs(&mut self, offset: usize, pointers: &[u64]) -> u64 {
            for (index, pointer) in pointers.iter().enumerate() {
                let start = offset + index * 8;
                self.0[start..start + 8].copy_from_slice(&pointer.to_le_bytes());
            }
            BASE + offset as u64
        }
    }

    impl UserCopy for Memory {
        fn copy_out(&mut self, _dst_va: u64, _src: &[u8]) -> bool {
            false
        }

        fn copy_in(&mut self, dst: &mut [u8], src_va: u64) -> bool {
            let Some(offset) = src_va
                .checked_sub(BASE)
                .and_then(|raw| usize::try_from(raw).ok())
            else {
                return false;
            };
            let Some(source) = self.0.get(offset..offset.saturating_add(dst.len())) else {
                return false;
            };
            dst.copy_from_slice(source);
            true
        }
    }

    #[test]
    fn stages_one_contiguous_execve_payload_from_scattered_user_strings() {
        let mut memory = Memory::new(4096);
        let path = memory.put(0x100, b"/bin/static\0");
        let arg0 = memory.put(0x180, b"static\0");
        let arg1 = memory.put(0x1c0, b"hello\0");
        let env0 = memory.put(0x200, b"A=B\0");
        let argv = memory.put_ptrs(0x300, &[arg0, arg1, 0]);
        let envp = memory.put_ptrs(0x340, &[env0, 0]);

        let payload = stage_exec_payload(
            &mut memory,
            ExecStageRequest {
                call: ExecCall::Execve,
                path,
                argv,
                envp,
            },
        )
        .unwrap();
        let view = ExecPayloadView::parse(&payload).unwrap();
        assert_eq!(view.call(), ExecCall::Execve);
        assert_eq!(view.path(), b"/bin/static");
        assert_eq!(
            view.argv().collect::<Vec<_>>(),
            [b"static".as_slice(), b"hello"]
        );
        assert_eq!(view.envp().collect::<Vec<_>>(), [b"A=B".as_slice()]);
        assert_eq!(view.encoded_len(), payload.len());
    }

    #[test]
    fn preserves_execveat_directory_and_flags_in_the_wire_record() {
        let mut memory = Memory::new(1024);
        let path = memory.put(0x80, b"tool\0");
        let argv = memory.put_ptrs(0x100, &[0]);
        let envp = memory.put_ptrs(0x120, &[0]);
        let call = ExecCall::Execveat {
            dirfd: -100,
            flags: 0x1000,
        };
        let payload = stage_exec_payload(
            &mut memory,
            ExecStageRequest {
                call,
                path,
                argv,
                envp,
            },
        )
        .unwrap();
        assert_eq!(ExecPayloadView::parse(&payload).unwrap().call(), call);
    }

    #[test]
    fn bad_path_vector_and_string_pointers_are_efault_14() {
        for invalid in [0, 1, 2] {
            let mut memory = Memory::new(1024);
            let path = memory.put(0x80, b"/bin/static\0");
            let arg = memory.put(0xc0, b"static\0");
            let argv = memory.put_ptrs(0x100, &[arg, 0]);
            let envp = memory.put_ptrs(0x140, &[0]);
            let bad = BASE + 0x4000;
            let request = ExecStageRequest {
                call: ExecCall::Execve,
                path: if invalid == 0 { bad } else { path },
                argv: if invalid == 1 { bad } else { argv },
                envp,
            };
            if invalid == 2 {
                memory.put_ptrs(0x100, &[bad, 0]);
            }
            assert_eq!(stage_exec_payload(&mut memory, request), Err(LINUX_EFAULT));
        }
    }

    #[test]
    fn one_string_at_max_arg_strlen_without_nul_is_e2big_7() {
        let mut memory = Memory::new(MAX_ARG_STRLEN + 0x1000);
        let path = memory.put(0x40, b"/bin/static\0");
        let argument = BASE + 0x800;
        memory.0[0x800..0x800 + MAX_ARG_STRLEN].fill(b'x');
        let argv = memory.put_ptrs(0x100, &[argument, 0]);
        let envp = memory.put_ptrs(0x140, &[0]);
        assert_eq!(
            stage_exec_payload(
                &mut memory,
                ExecStageRequest {
                    call: ExecCall::Execve,
                    path,
                    argv,
                    envp,
                },
            ),
            Err(LINUX_E2BIG)
        );
    }

    #[test]
    fn argv_and_env_accounting_over_arg_max_is_e2big_7() {
        let mut memory = Memory::new(EXEC_ARGUMENT_BYTES_MAX + 0x1000);
        let path = memory.put(0x40, b"/bin/static\0");
        let empty = memory.put(0x80, b"\0");
        // An unterminated pointer vector cannot evade ARG_MAX through empty
        // strings: each pointer consumes Linux argument accounting space.
        for offset in (0x100..memory.0.len() - 7).step_by(8) {
            memory.0[offset..offset + 8].copy_from_slice(&empty.to_le_bytes());
        }
        assert_eq!(
            stage_exec_payload(
                &mut memory,
                ExecStageRequest {
                    call: ExecCall::Execve,
                    path,
                    argv: BASE + 0x100,
                    envp: BASE + 0x80,
                },
            ),
            Err(LINUX_E2BIG)
        );
    }
}
