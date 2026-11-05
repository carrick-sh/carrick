//! Real root-MM input supply: the first read of a readonly file mapping is
//! rt_sigprocmask's in-ring copy, rather than an EL0 load or host dispatcher.
use carrick_embed::{ContainerBuilder, PullPolicy};

struct ArmProgram {
    words: Vec<u32>,
    failures: Vec<(usize, u8)>,
}

impl ArmProgram {
    fn new() -> Self {
        Self {
            words: Vec::new(),
            failures: Vec::new(),
        }
    }

    fn word(&mut self, word: u32) {
        self.words.push(word);
    }

    fn constant(&mut self, reg: u32, value: u64) {
        self.word(0xd2800000 | (((value & 0xffff) as u32) << 5) | reg);
        for shift in 1..4 {
            let half = ((value >> (shift * 16)) & 0xffff) as u32;
            if half != 0 {
                self.word(0xf2800000 | (shift << 21) | (half << 5) | reg);
            }
        }
    }

    fn syscall(&mut self, nr: u64) {
        self.constant(8, nr);
        self.word(0xd4000001);
    }

    fn require_zero(&mut self, failure: u8) {
        let at = self.words.len();
        self.word(0xb5000000); // cbnz x0, failure
        self.failures.push((at, failure));
    }

    fn require_nonnegative(&mut self, failure: u8) {
        let at = self.words.len();
        self.word(0xb7f80000); // tbnz x0, #63, failure
        self.failures.push((at, failure));
    }

    fn mask_call(&mut self, how: u64, set: Option<u32>, old_offset: Option<u32>) {
        self.constant(0, how);
        match set {
            Some(reg) => self.word(0xaa0003e1 | (reg << 16)), // mov x1, reg
            None => self.constant(1, 0),
        }
        match old_offset {
            Some(offset) => self.word(0x910003e2 | (offset << 10)), // add x2, sp, offset
            None => self.constant(2, 0),
        }
        self.constant(3, 8);
        self.syscall(135);
    }

    fn finish(mut self) -> Vec<u8> {
        self.constant(0, 0);
        self.syscall(93);
        for (at, failure) in self.failures.clone() {
            let target = self.words.len();
            self.words[at] |= ((target - at) as u32) << 5;
            self.constant(0, u64::from(failure));
            self.syscall(93);
        }
        self.words.into_iter().flat_map(u32::to_le_bytes).collect()
    }
}

fn signal_copy_elf() -> Vec<u8> {
    const BASE: u64 = 0x0040_0000;
    const CODE: usize = 0x100;
    const PATH: usize = 0xf00;
    let mut p = ArmProgram::new();
    p.word(0xd10083ff); // sub sp, sp, #32
    p.word(0xf90003ff); // str xzr, [sp]: known initial mask
    p.word(0x910003f5); // mov x21, sp
    p.mask_call(2, Some(21), None); // SIG_SETMASK(empty)
    p.require_zero(10);
    p.constant(0, (-100i64) as u64); // AT_FDCWD
    p.constant(1, BASE + PATH as u64);
    p.constant(2, 0); // O_RDONLY
    p.constant(3, 0);
    p.syscall(56); // openat
    p.require_nonnegative(11);
    p.word(0xaa0003e4); // mov x4, x0 (fd)
    p.constant(0, 0);
    p.constant(1, 4096);
    p.constant(2, 1); // PROT_READ
    p.constant(3, 2); // MAP_PRIVATE
    p.constant(5, 0);
    p.syscall(222); // mmap; no load from this mapping before mask_call
    p.require_nonnegative(12);
    p.word(0xaa0003f4); // mov x20, x0
    p.word(0x92800000); // mov x0, #-1
    p.word(0xf90007e0); // str x0, [sp, #8]: oldset sentinel
    p.mask_call(0, Some(20), Some(8)); // glibc shape: SIG_BLOCK(set, old, 8)
    p.require_zero(14); // errno14 on the pre-fix root physical refusal
    p.word(0xf94007e0); // ldr x0, [sp, #8]
    p.require_zero(15); // original mask must have been copied out
    p.mask_call(0, None, Some(16));
    p.require_zero(16);
    p.word(0xf9400be0); // ldr x0, [sp, #16]
    p.word(0xd1080000); // sub x0, x0, #512 (SIGUSR1)
    p.require_zero(17);
    p.mask_call(2, Some(21), None); // restore original empty mask
    p.require_zero(18);
    p.mask_call(0, None, Some(16));
    p.require_zero(19);
    p.word(0xf9400be0);
    p.require_zero(20);
    let code = p.finish();
    assert!(CODE + code.len() < PATH);
    let mut elf = vec![0; 4096];
    elf[..16].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    elf[16..18].copy_from_slice(&2u16.to_le_bytes());
    elf[18..20].copy_from_slice(&183u16.to_le_bytes());
    elf[20..24].copy_from_slice(&1u32.to_le_bytes());
    elf[24..32].copy_from_slice(&(BASE + CODE as u64).to_le_bytes());
    elf[32..40].copy_from_slice(&64u64.to_le_bytes());
    elf[52..54].copy_from_slice(&64u16.to_le_bytes());
    elf[54..56].copy_from_slice(&56u16.to_le_bytes());
    elf[56..58].copy_from_slice(&1u16.to_le_bytes());
    elf[64..68].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD
    elf[68..72].copy_from_slice(&5u32.to_le_bytes()); // PF_R | PF_X
    elf[80..88].copy_from_slice(&BASE.to_le_bytes());
    elf[88..96].copy_from_slice(&BASE.to_le_bytes());
    elf[96..104].copy_from_slice(&4096u64.to_le_bytes());
    elf[104..112].copy_from_slice(&4096u64.to_le_bytes());
    elf[112..120].copy_from_slice(&4096u64.to_le_bytes());
    elf[CODE..CODE + code.len()].copy_from_slice(&code);
    elf[PATH..PATH + 8].copy_from_slice(b"/p/mask\0");
    elf
}

#[test]
#[ignore = "requires signed HVF; run through scripts/test-signed.sh"]
fn root_sigprocmask_reads_untouched_readonly_file_mapping() {
    let _guard = crate::common::guest_lock();
    let watchdog = crate::common::Watchdog::start(std::time::Duration::from_secs(45));
    let dir = tempfile::tempdir().expect("signal copy fixture directory");
    let executable = dir.path().join("signal-copy");
    std::fs::write(&executable, signal_copy_elf()).expect("generated signal-copy ELF");
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o755)).unwrap();
    let mut mask = vec![0u8; 4096];
    mask[..8].copy_from_slice(&512u64.to_le_bytes());
    std::fs::write(dir.path().join("mask"), mask).expect("readonly file-backed mask");
    let result = crate::common::run_or_fail(
        ContainerBuilder::from_image(crate::common::SMOKE_IMAGE)
            .pull_policy(PullPolicy::Missing)
            .mount_readonly(dir.path().to_string_lossy().into_owned(), "/p")
            .command(["/p/signal-copy"])
            .run_blocking(),
    );
    watchdog.disarm();
    let counters = carrick_embed::read_el1_counters().expect("retained root syscall census");
    use std::sync::atomic::Ordering;
    let served = counters.served[135].load(Ordering::Relaxed);
    let forwarded = counters.forwarded[135].load(Ordering::Relaxed);
    assert_eq!(forwarded, 0, "signal-mask calls must stay in ring");
    assert!(
        served >= 5,
        "all five logical signal-mask calls must complete in ring: {served}"
    );
    assert_eq!(
        result.exit_code,
        0,
        "root readonly mask copy failed: 14=setup refused, 15=oldset unwritten, 17=wrong mask; stdout={} stderr={}",
        result.stdout_utf8(),
        result.stderr_utf8()
    );
}
