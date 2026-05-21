//! Minimal HVF stage-1 MMU repro for lldb-driven iteration.
//!
//! Reads knobs from env vars (see scripts/stage1_sweep.sh) and configures
//! a single vCPU with stage-1 MMU enabled. Then either:
//!   * vcpu.run() returns cleanly (success — HVC #0 fired) and we park
//!     in a sleep so lldb can inspect the post-run sysregs; OR
//!   * vcpu.run() hangs (failure — recursive fault) and lldb is still
//!     able to attach and read the hung sysreg state via
//!     hv_vcpu_get_sys_reg.
//!
//! No logging by design: state inspection is the debugger's job.
//!
//! This is a developer-only lldb repro harness, not supervisor code that hosts a
//! guest, so the no-panic gate does not apply: unwrap/expect on missing knobs is
//! the intended fail-fast, and the explicit `0u64 & MASK` documents a PA-0 mapping
//! in parallel with the surrounding page-table entries.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::erasing_op)]

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use applevisor::prelude::*;

    fn env_u64(name: &str, default: u64) -> u64 {
        std::env::var(name)
            .ok()
            .and_then(|v| {
                let v = v.trim();
                if let Some(hex) = v.strip_prefix("0x") {
                    u64::from_str_radix(hex, 16).ok()
                } else if v.chars().all(|c| matches!(c, '0' | '1')) {
                    u64::from_str_radix(v, 2).ok()
                } else {
                    v.parse().ok()
                }
            })
            .unwrap_or(default)
    }

    const CODE_BASE: u64 = 0x10000;
    const CODE_SIZE: usize = 16 * 1024;
    const PT_BASE: u64 = 0x20000;
    const PT_SIZE: usize = 16 * 1024;

    let ap = env_u64("REPRO_AP", 0b01) & 0b11;
    let sh = env_u64("REPRO_SH", 0b11) & 0b11;
    let attr = env_u64("REPRO_ATTR", 0) & 0b111;
    let mair = env_u64("REPRO_MAIR_HEX", 0xFF);
    let t0sz = env_u64("REPRO_TCR_T0SZ", 25) & 0x3F;
    let irgn = env_u64("REPRO_TCR_IRGN", 0b11) & 0b11;
    let orgn = env_u64("REPRO_TCR_ORGN", 0b11) & 0b11;
    let tcr_sh = env_u64("REPRO_TCR_SH", 0b11) & 0b11;
    let sctlr_res1 = env_u64("REPRO_SCTLR_RES1", 0) != 0;
    let span = env_u64("REPRO_SCTLR_SPAN", 0) != 0;
    let uxn = env_u64("REPRO_UXN", 0) != 0;
    let pxn = env_u64("REPRO_PXN", 0) != 0;
    let vbar_base = env_u64("REPRO_VBAR_BASE", 0);

    let mut l1_flags: u64 =
        (1 << 10) | (sh << 8) | (ap << 6) | (attr << 2) | 0b01;
    if uxn {
        l1_flags |= 1u64 << 54;
    }
    if pxn {
        l1_flags |= 1u64 << 53;
    }

    let max_ipa = VirtualMachineConfig::get_max_ipa_size()?;
    let mut config = VirtualMachineConfig::new();
    config.set_ipa_size(max_ipa)?;
    let vm = VirtualMachine::with_config(config)?;
    let vcpu = vm.vcpu_create()?;

    let mut code_mem = vm.memory_create(CODE_SIZE)?;
    code_mem.map(CODE_BASE, MemPerms::ReadWriteExec)?;
    let mut code = vec![0u8; CODE_SIZE];
    let nop: u32 = 0xd503_201f;
    let hvc0: u32 = 0xd400_0002;
    for i in 0..(CODE_SIZE / 4) {
        let opcode = if i == 4 { hvc0 } else { nop };
        code[i * 4..i * 4 + 4].copy_from_slice(&opcode.to_le_bytes());
    }
    code_mem.write(CODE_BASE, &code)?;

    let mut pt_mem = vm.memory_create(PT_SIZE)?;
    pt_mem.map(PT_BASE, MemPerms::ReadWriteExec)?;
    let mut pt = vec![0u8; PT_SIZE];
    let l1_0: u64 = l1_flags;
    pt[0..8].copy_from_slice(&l1_0.to_le_bytes());
    let l1_1: u64 = (0x4000_0000u64 & 0x0000_FFFF_C000_0000) | l1_flags;
    pt[8..16].copy_from_slice(&l1_1.to_le_bytes());
    pt_mem.write(PT_BASE, &pt)?;

    vcpu.set_sys_reg(SysReg::MAIR_EL1, mair)?;

    let tcr: u64 = t0sz
        | (irgn << 8)
        | (orgn << 10)
        | (tcr_sh << 12)
        | (1u64 << 23)
        | (0b010u64 << 32);
    vcpu.set_sys_reg(SysReg::TCR_EL1, tcr)?;
    vcpu.set_sys_reg(SysReg::TTBR0_EL1, PT_BASE)?;

    let mut sctlr: u64 = 1 | (1 << 2) | (1 << 12);
    if sctlr_res1 {
        sctlr |= (1 << 11) | (1 << 20) | (1 << 22) | (1 << 23);
    }
    if span {
        // SCTLR_EL1.SPAN (bit 23) = 1 disables the implicit
        // "set PSTATE.PAN on exception entry to EL1" rule that
        // ARMv8.1-PAN otherwise enforces with SPAN=0.
        sctlr |= 1 << 23;
    }
    vcpu.set_sys_reg(SysReg::SCTLR_EL1, sctlr)?;
    vcpu.set_sys_reg(SysReg::VBAR_EL1, vbar_base)?;
    vcpu.set_reg(Reg::CPSR, 0x3c5)?;
    vcpu.set_reg(Reg::PC, CODE_BASE)?;

    // Either returns (success/error from HVF), or hangs forever.
    let _ = vcpu.run();

    // Park here so lldb can attach and read post-run sysreg state too.
    std::thread::sleep(std::time::Duration::from_secs(3600));
    Ok(())
}

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
fn main() {
    eprintln!("stage1_repro requires macOS aarch64");
    std::process::exit(1);
}
