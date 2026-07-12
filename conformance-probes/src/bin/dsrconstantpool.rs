//! DSR executable-byte integrity probe. A Linux AArch64 `svc #0` word lives as
//! read-only data inside an executable section, behind an unconditional branch.
//! Translation must preserve the literal and must never patch the original
//! executable mapping.

use conformance_probes::report;

#[cfg(target_arch = "aarch64")]
core::arch::global_asm!(
    ".pushsection .text.dsrconstantpool,\"ax\",@progbits",
    ".balign 4",
    ".global dsr_constant_pool_start",
    "dsr_constant_pool_start:",
    "b 1f",
    ".word 0xd4000001",
    "1:",
    "ret",
    ".global dsr_constant_pool_end",
    "dsr_constant_pool_end:",
    ".popsection",
);

#[cfg(target_arch = "x86_64")]
core::arch::global_asm!(
    ".pushsection .text.dsrconstantpool,\"ax\",@progbits",
    ".global dsr_constant_pool_start",
    "dsr_constant_pool_start:",
    ".byte 0xeb, 0x04",
    ".long 0xd4000001",
    "ret",
    ".global dsr_constant_pool_end",
    "dsr_constant_pool_end:",
    ".popsection",
);

unsafe extern "C" {
    #[link_name = "dsr_constant_pool_start"]
    fn execute_constant_pool_section();
    #[link_name = "dsr_constant_pool_start"]
    static CONSTANT_POOL_START: u8;
    #[link_name = "dsr_constant_pool_end"]
    static CONSTANT_POOL_END: u8;
}

#[cfg(target_arch = "aarch64")]
const CONSTANT_OFFSET: usize = 4;
#[cfg(target_arch = "x86_64")]
const CONSTANT_OFFSET: usize = 2;

fn fnv1a(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8422_2325, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(0x1000_0000_01b3)
    })
}

fn main() {
    unsafe {
        let start = core::ptr::addr_of!(CONSTANT_POOL_START);
        let end = core::ptr::addr_of!(CONSTANT_POOL_END);
        let len = end.offset_from(start) as usize;
        let before = core::slice::from_raw_parts(start, len);
        let before_hash = fnv1a(before);
        let constant = start.add(CONSTANT_OFFSET).cast::<u32>().read_unaligned();

        execute_constant_pool_section();
        let pid = libc::syscall(libc::SYS_getpid);

        let after = core::slice::from_raw_parts(start, len);
        report!(
            constant_word_match = constant == 0xd400_0001,
            executable_hash_unchanged = fnv1a(after) == before_hash,
            section_executed = pid > 0,
        );
    }
}
