use std::path::Path;
use std::process::Command;

pub const ENTRY_SNAPSHOT_LEN: usize = 1152;

pub fn compile_static_fixture(source: &Path, output: &Path, flags: &[&str]) {
    let build = Command::new("timeout")
        .args(["15", "cc", "-static", "-no-pie", "-Wl,--build-id=none"])
        .args(flags)
        .arg(source)
        .arg("-o")
        .arg(output)
        .output()
        .expect("compile x86 process entry fixture");
    assert!(
        build.status.success(),
        "compile {}: {}",
        source.display(),
        String::from_utf8_lossy(&build.stderr)
    );
}

pub fn assert_clean_first_user_entry(stdout: &[u8], context: &str) {
    assert_eq!(stdout.len(), ENTRY_SNAPSHOT_LEN, "{context}");

    let fxsave = &stdout[..512];
    let ymms = &stdout[512..1024];
    let gprs = &stdout[1024..1152];

    let registers = [
        "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "r8", "r9", "r10", "r11", "r12", "r13",
        "r14", "r15", "rflags",
    ];
    for (register, bytes) in registers.into_iter().zip(gprs.chunks_exact(8)) {
        let value = u64::from_le_bytes(bytes.try_into().expect("register width"));
        let expected = if register == "rflags" { 0x202 } else { 0 };
        assert_eq!(
            value, expected,
            "first user {register} = {value:#x} ({context})"
        );
    }

    let fcw = u16::from_le_bytes([fxsave[0], fxsave[1]]);
    let fsw = u16::from_le_bytes([fxsave[2], fxsave[3]]);
    let ftw = fxsave[4];
    let fop = u16::from_le_bytes([fxsave[6], fxsave[7]]);
    let fip = u64::from_le_bytes(fxsave[8..16].try_into().expect("fip width"));
    let fdp = u64::from_le_bytes(fxsave[16..24].try_into().expect("fdp width"));
    let mxcsr = u32::from_le_bytes(fxsave[24..28].try_into().expect("mxcsr width"));

    assert_eq!(fcw, 0x037f, "first user x87 FCW = {fcw:#x} ({context})");
    assert_eq!(fsw, 0, "first user x87 FSW = {fsw:#x} ({context})");
    assert_eq!(ftw, 0, "first user x87 FTW = {ftw:#x} ({context})");
    assert_eq!(fop, 0, "first user x87 FOP = {fop:#x} ({context})");
    assert_eq!(fip, 0, "first user x87 FIP = {fip:#x} ({context})");
    assert_eq!(fdp, 0, "first user x87 FDP = {fdp:#x} ({context})");
    assert_eq!(mxcsr, 0x1f80, "first user MXCSR = {mxcsr:#x} ({context})");

    for (index, slot) in fxsave[32..160].chunks_exact(16).enumerate() {
        assert_eq!(
            &slot[..10],
            &[0u8; 10],
            "first user x87 ST{index} = {:02x?} ({context})",
            &slot[..10]
        );
    }

    for (index, slot) in fxsave[160..416].chunks_exact(16).enumerate() {
        let value = u128::from_le_bytes(slot.try_into().expect("xmm width"));
        assert_eq!(
            value, 0,
            "first user FXSAVE XMM{index} = {value:#034x} ({context})"
        );
    }

    for (index, slot) in ymms.chunks_exact(32).enumerate() {
        let low = u128::from_le_bytes(slot[..16].try_into().expect("xmm width"));
        let high = u128::from_le_bytes(slot[16..32].try_into().expect("ymm high width"));
        assert_eq!(low, 0, "first user XMM{index} = {low:#034x} ({context})");
        assert_eq!(
            high, 0,
            "first user YMM{index}[255:128] = {high:#034x} ({context})"
        );
    }
}
