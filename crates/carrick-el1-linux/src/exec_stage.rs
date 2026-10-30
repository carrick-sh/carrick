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

enum CopyStep {
    Copied,
    Terminated(usize),
    Fault,
}

fn try_copy_slice(
    user: &mut impl UserCopy,
    address: u64,
    len: usize,
    start: usize,
    output: &mut Vec<u8>,
) -> Result<CopyStep, LinuxErrno> {
    let slice_start = output.len();
    if let Err(err) = reserve(output, len) {
        output.truncate(start);
        return Err(err);
    }
    output.resize(slice_start + len, 0);
    if !user.copy_in(&mut output[slice_start..], address) {
        output.truncate(slice_start);
        return Ok(CopyStep::Fault);
    }
    if let Some(nul) = output[slice_start..].iter().position(|byte| *byte == 0) {
        output.truncate(slice_start + nul + 1);
        return Ok(CopyStep::Terminated(output.len() - start));
    }
    Ok(CopyStep::Copied)
}

fn narrow_partial_chunk(
    user: &mut impl UserCopy,
    address: u64,
    current: u64,
    chunk: usize,
    start: usize,
    output: &mut Vec<u8>,
) -> Result<Option<usize>, LinuxErrno> {
    if chunk <= 1 {
        output.truncate(start);
        return Err(LINUX_EFAULT);
    }
    // Probe one byte first so a fault at `current` itself (bad pointer or
    // unmapped page start) fails in one extra probe instead of log2(chunk).
    match try_copy_slice(user, current, 1, start, output)? {
        CopyStep::Terminated(total) => return Ok(Some(total)),
        CopyStep::Fault => {
            output.truncate(start);
            return Err(LINUX_EFAULT);
        }
        CopyStep::Copied => {}
    }

    let mut window = chunk - 1;
    let mut step_one_faulted = false;
    while window > 1 {
        let half = window.div_ceil(2);
        let Some(pos) = address.checked_add((output.len() - start) as u64) else {
            output.truncate(start);
            return Err(LINUX_EFAULT);
        };
        match try_copy_slice(user, pos, half, start, output)? {
            CopyStep::Terminated(total) => return Ok(Some(total)),
            CopyStep::Copied => {
                window -= half;
                step_one_faulted = false;
            }
            CopyStep::Fault => {
                window = half;
                step_one_faulted = half == 1;
            }
        }
    }

    if step_one_faulted {
        output.truncate(start);
        return Err(LINUX_EFAULT);
    }
    let Some(pos) = address.checked_add((output.len() - start) as u64) else {
        output.truncate(start);
        return Err(LINUX_EFAULT);
    };
    match try_copy_slice(user, pos, 1, start, output)? {
        CopyStep::Terminated(total) => Ok(Some(total)),
        CopyStep::Copied => Ok(None),
        CopyStep::Fault => {
            output.truncate(start);
            Err(LINUX_EFAULT)
        }
    }
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
        let Some(current) = address.checked_add(copied as u64) else {
            output.truncate(start);
            return Err(LINUX_EFAULT);
        };
        let page_remaining = 4096 - (current as usize & 4095);
        let chunk = remaining.min(page_remaining).min(256);
        match try_copy_slice(user, current, chunk, start, output)? {
            CopyStep::Terminated(total) => return Ok(total),
            CopyStep::Copied => {}
            CopyStep::Fault => {
                if let Some(total) =
                    narrow_partial_chunk(user, address, current, chunk, start, output)?
                {
                    return Ok(total);
                }
            }
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

    struct CountingMemory {
        bytes: Vec<u8>,
        segment_boundary: Option<(u64, usize)>,
        copy_in_calls: usize,
        probed_bytes: usize,
        succeeded_ranges: Vec<(u64, usize)>,
    }

    impl CountingMemory {
        fn new(bytes: usize) -> Self {
            Self {
                bytes: vec![0; bytes],
                segment_boundary: None,
                copy_in_calls: 0,
                probed_bytes: 0,
                succeeded_ranges: Vec::new(),
            }
        }

        fn with_segments(bytes: usize, anchor: u64, segment_bytes: usize) -> Self {
            Self {
                bytes: vec![0; bytes],
                segment_boundary: Some((anchor, segment_bytes)),
                copy_in_calls: 0,
                probed_bytes: 0,
                succeeded_ranges: Vec::new(),
            }
        }

        fn put(&mut self, offset: usize, slice: &[u8]) -> u64 {
            self.bytes[offset..offset + slice.len()].copy_from_slice(slice);
            BASE + offset as u64
        }

        fn put_ptrs(&mut self, offset: usize, pointers: &[u64]) -> u64 {
            for (index, pointer) in pointers.iter().enumerate() {
                let start = offset + index * 8;
                self.bytes[start..start + 8].copy_from_slice(&pointer.to_le_bytes());
            }
            BASE + offset as u64
        }

        fn reset_counts(&mut self) {
            self.copy_in_calls = 0;
            self.probed_bytes = 0;
            self.succeeded_ranges.clear();
        }

        fn assert_disjoint_contiguous_cover(&self, start_va: u64, expected_len: usize) {
            let end_va = start_va + expected_len as u64;
            let mut cursor = start_va;
            for &(va, len) in &self.succeeded_ranges {
                if len == 0 || va + len as u64 <= start_va || va >= end_va {
                    continue;
                }
                assert_eq!(
                    va, cursor,
                    "copy resumed at {va:#x} instead of known-good offset {cursor:#x}"
                );
                cursor += len as u64;
            }
            assert!(
                cursor >= end_va,
                "succeeded copy ranges stopped at {cursor:#x} before {end_va:#x}"
            );
        }
    }

    impl UserCopy for CountingMemory {
        fn copy_out(&mut self, _dst_va: u64, _src: &[u8]) -> bool {
            false
        }

        fn copy_in(&mut self, dst: &mut [u8], src_va: u64) -> bool {
            self.copy_in_calls += 1;
            let Some(offset) = src_va
                .checked_sub(BASE)
                .and_then(|raw| usize::try_from(raw).ok())
            else {
                return false;
            };
            if offset >= self.bytes.len() {
                return false;
            }
            if let Some((anchor, segment_bytes)) = self.segment_boundary
                && dst.len() > 1
                && src_va >= anchor
            {
                let rel = (src_va - anchor) as usize;
                let seg_remaining = segment_bytes - (rel % segment_bytes);
                if dst.len() > seg_remaining {
                    self.probed_bytes += seg_remaining.min(self.bytes.len() - offset);
                    return false;
                }
            }
            let end = offset.saturating_add(dst.len());
            let Some(source) = self.bytes.get(offset..end) else {
                self.probed_bytes += self.bytes.len() - offset;
                return false;
            };
            self.probed_bytes += dst.len();
            self.succeeded_ranges.push((src_va, dst.len()));
            dst.copy_from_slice(source);
            true
        }
    }

    #[test]
    fn partial_chunk_fault_narrows_from_known_good_offset_without_recopying() {
        // Row 1: 64 KiB + 255-byte string whose final 256-byte chunk faults at
        // byte 255 immediately after the terminating NUL at byte 254.
        let prefix_chunks = 256usize;
        let tail_len = 255usize;
        let arg_total = prefix_chunks * 256 + tail_len;
        let arg_offset = 0x1000usize;
        let mut memory = CountingMemory::new(arg_offset + arg_total);
        let path = memory.put(0x100, b"/bin/static\0");
        let argv = memory.put_ptrs(0x200, &[BASE + arg_offset as u64, 0]);
        let envp = memory.put_ptrs(0x240, &[0]);
        memory.bytes[arg_offset..arg_offset + arg_total - 1].fill(b'a');
        memory.bytes[arg_offset + arg_total - 1] = 0;
        memory.reset_counts();

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
        assert_eq!(view.argv().next().unwrap().len(), arg_total - 1);
        memory.assert_disjoint_contiguous_cover(BASE + arg_offset as u64, arg_total);
        assert!(
            memory.copy_in_calls <= prefix_chunks + 16,
            "partial-chunk tail fault took {} copy_in calls (budget <= {})",
            memory.copy_in_calls,
            prefix_chunks + 16
        );
        assert!(
            memory.probed_bytes <= arg_total + 600,
            "partial-chunk tail fault probed {} bytes for {}-byte string",
            memory.probed_bytes,
            arg_total
        );

        // Row 2: 64 KiB string spanning 300-byte internal translation segments,
        // forcing mid-string partial-chunk faults that must narrow and resume
        // from the known-good offset without re-copying prior bytes.
        let seg_arg_total = 65_536usize;
        let seg_arg_offset = 0x1011usize;
        let seg_anchor = BASE + seg_arg_offset as u64;
        let mut segmented =
            CountingMemory::with_segments(seg_arg_offset + seg_arg_total, seg_anchor, 300);
        let seg_path = segmented.put(0x100, b"/bin/static\0");
        let seg_argv = segmented.put_ptrs(0x200, &[seg_anchor, 0]);
        let seg_envp = segmented.put_ptrs(0x240, &[0]);
        segmented.bytes[seg_arg_offset..seg_arg_offset + seg_arg_total - 1].fill(b'b');
        segmented.bytes[seg_arg_offset + seg_arg_total - 1] = 0;
        segmented.reset_counts();

        let seg_payload = stage_exec_payload(
            &mut segmented,
            ExecStageRequest {
                call: ExecCall::Execve,
                path: seg_path,
                argv: seg_argv,
                envp: seg_envp,
            },
        )
        .unwrap();
        let seg_view = ExecPayloadView::parse(&seg_payload).unwrap();
        assert_eq!(seg_view.argv().next().unwrap().len(), seg_arg_total - 1);
        segmented.assert_disjoint_contiguous_cover(seg_anchor, seg_arg_total);
        assert!(
            segmented.copy_in_calls <= 3_000,
            "segmented mid-string partial faults took {} copy_in calls (budget <= 3000)",
            segmented.copy_in_calls
        );

        // Row 3: Unterminated strings faulting at interior chunk offsets return
        // EFAULT (14) in logarithmic calls rather than linear byte-by-byte retries.
        for valid_tail in [0usize, 1, 17, 127, 128, 200, 255] {
            let mut fault_mem = CountingMemory::new(0x1000 + valid_tail);
            let fault_path = fault_mem.put(0x100, b"/bin/static\0");
            let fault_argv = fault_mem.put_ptrs(0x200, &[BASE + 0x1000, 0]);
            let fault_envp = fault_mem.put_ptrs(0x240, &[0]);
            fault_mem.bytes[0x1000..0x1000 + valid_tail].fill(b'z');
            fault_mem.reset_counts();

            assert_eq!(
                stage_exec_payload(
                    &mut fault_mem,
                    ExecStageRequest {
                        call: ExecCall::Execve,
                        path: fault_path,
                        argv: fault_argv,
                        envp: fault_envp,
                    },
                ),
                Err(LINUX_EFAULT)
            );
            let call_budget = if valid_tail == 0 { 5 } else { 14 };
            assert!(
                fault_mem.copy_in_calls <= call_budget,
                "unterminated fault at offset {valid_tail} took {} copy_in calls (budget <= {call_budget})",
                fault_mem.copy_in_calls
            );
        }
    }

    #[test]
    fn long_string_at_page_boundary_and_huge_argv_stay_within_copy_budget() {
        // Adversarial row 1a: MAX_ARG_STRLEN string starting at an unaligned
        // address and ending right before an unmapped 4 KiB page boundary.
        let unaligned_start = 0x1025usize;
        let aligned_end =
            unaligned_start + MAX_ARG_STRLEN + (4096 - ((unaligned_start + MAX_ARG_STRLEN) & 4095));
        let page_str_start = aligned_end - MAX_ARG_STRLEN;
        let mut page_mem = CountingMemory::new(aligned_end);
        let path = page_mem.put(0x100, b"/bin/static\0");
        let argv = page_mem.put_ptrs(0x200, &[BASE + page_str_start as u64, 0]);
        let envp = page_mem.put_ptrs(0x240, &[0]);
        page_mem.bytes[page_str_start..aligned_end - 1].fill(b'p');
        page_mem.bytes[aligned_end - 1] = 0;
        page_mem.reset_counts();

        let payload = stage_exec_payload(
            &mut page_mem,
            ExecStageRequest {
                call: ExecCall::Execve,
                path,
                argv,
                envp,
            },
        )
        .unwrap();
        let view = ExecPayloadView::parse(&payload).unwrap();
        assert_eq!(view.argv().next().unwrap().len(), MAX_ARG_STRLEN - 1);
        page_mem.assert_disjoint_contiguous_cover(BASE + page_str_start as u64, MAX_ARG_STRLEN);
        assert!(
            page_mem.copy_in_calls <= (MAX_ARG_STRLEN / 256) + 8,
            "page-boundary MAX_ARG_STRLEN string took {} copy_in calls",
            page_mem.copy_in_calls
        );

        // Adversarial row 1b: MAX_ARG_STRLEN - 1 string ending at an unmapped
        // sub-page boundary so the final chunk suffers a 255-byte partial fault.
        let straddle_len = MAX_ARG_STRLEN - 1;
        let straddle_start = 0x1000usize;
        let mut straddle_mem = CountingMemory::new(straddle_start + straddle_len);
        let path = straddle_mem.put(0x100, b"/bin/static\0");
        let argv = straddle_mem.put_ptrs(0x200, &[BASE + straddle_start as u64, 0]);
        let envp = straddle_mem.put_ptrs(0x240, &[0]);
        straddle_mem.bytes[straddle_start..straddle_start + straddle_len - 1].fill(b'q');
        straddle_mem.bytes[straddle_start + straddle_len - 1] = 0;
        straddle_mem.reset_counts();

        let payload = stage_exec_payload(
            &mut straddle_mem,
            ExecStageRequest {
                call: ExecCall::Execve,
                path,
                argv,
                envp,
            },
        )
        .unwrap();
        let view = ExecPayloadView::parse(&payload).unwrap();
        assert_eq!(view.argv().next().unwrap().len(), straddle_len - 1);
        straddle_mem.assert_disjoint_contiguous_cover(BASE + straddle_start as u64, straddle_len);
        assert!(
            straddle_mem.copy_in_calls <= (MAX_ARG_STRLEN / 256) + 16,
            "sub-page-boundary MAX_ARG_STRLEN-1 string took {} copy_in calls",
            straddle_mem.copy_in_calls
        );

        // Adversarial row 2: huge argv scaling across 4 points (1..=2048 args),
        // each pointing to a 255-byte C-string immediately before an unmapped
        // address so every argv element triggers a partial-chunk fault.
        for argc in [1usize, 16, 256, 2048] {
            let argv_offset = 0x1000usize;
            let envp_offset = argv_offset + (argc + 1) * 8;
            let tail_arg_len = 255usize;
            let tail_arg_offset = ((envp_offset + 16) + 4095) & !4095;
            let mut huge_mem = CountingMemory::new(tail_arg_offset + tail_arg_len);
            let path = huge_mem.put(0x100, b"/bin/static\0");
            let arg_ptr = BASE + tail_arg_offset as u64;
            let mut ptrs = vec![arg_ptr; argc];
            ptrs.push(0);
            let argv = huge_mem.put_ptrs(argv_offset, &ptrs);
            let envp = huge_mem.put_ptrs(envp_offset, &[0]);
            huge_mem.bytes[tail_arg_offset..tail_arg_offset + tail_arg_len - 1].fill(b'x');
            huge_mem.bytes[tail_arg_offset + tail_arg_len - 1] = 0;
            huge_mem.reset_counts();

            let payload = stage_exec_payload(
                &mut huge_mem,
                ExecStageRequest {
                    call: ExecCall::Execve,
                    path,
                    argv,
                    envp,
                },
            )
            .unwrap();
            let view = ExecPayloadView::parse(&payload).unwrap();
            assert_eq!(view.argv().count(), argc);
            if argc == 1 {
                huge_mem.assert_disjoint_contiguous_cover(arg_ptr, tail_arg_len);
            }
            let budget = 4 + argc * 11;
            assert!(
                huge_mem.copy_in_calls <= budget,
                "huge argv (argc={argc}) took {} copy_in calls (budget <= {budget})",
                huge_mem.copy_in_calls
            );
            let probed_budget = 288 + argc * (8 + 2 * tail_arg_len);
            assert!(
                huge_mem.probed_bytes <= probed_budget,
                "huge argv (argc={argc}) probed {} bytes (budget <= {probed_budget})",
                huge_mem.probed_bytes
            );
        }

        // Adversarial row 3: near-ARG_MAX argv of 15 MAX_ARG_STRLEN-1 strings
        // (~1.96 MiB payload) ending at an unmapped boundary.
        let near_max_argc = 15usize;
        let near_str_len = MAX_ARG_STRLEN - 1;
        let near_str_offset = 0x2000usize;
        let mut near_mem = CountingMemory::new(near_str_offset + near_str_len);
        let path = near_mem.put(0x100, b"/bin/static\0");
        let near_ptr = BASE + near_str_offset as u64;
        let mut near_ptrs = vec![near_ptr; near_max_argc];
        near_ptrs.push(0);
        let argv = near_mem.put_ptrs(0x400, &near_ptrs);
        let envp = near_mem.put_ptrs(0x600, &[0]);
        near_mem.bytes[near_str_offset..near_str_offset + near_str_len - 1].fill(b'm');
        near_mem.bytes[near_str_offset + near_str_len - 1] = 0;
        near_mem.reset_counts();

        let payload = stage_exec_payload(
            &mut near_mem,
            ExecStageRequest {
                call: ExecCall::Execve,
                path,
                argv,
                envp,
            },
        )
        .unwrap();
        let view = ExecPayloadView::parse(&payload).unwrap();
        assert_eq!(view.argv().count(), near_max_argc);
        let per_arg_budget = 1 + (near_str_len / 256) + 12;
        let near_budget = 4 + near_max_argc * per_arg_budget;
        assert!(
            near_mem.copy_in_calls <= near_budget,
            "near-ARG_MAX huge argv took {} copy_in calls (budget <= {near_budget})",
            near_mem.copy_in_calls
        );
    }
}
