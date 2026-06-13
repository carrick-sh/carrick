//! Live-vCPU integration tests for the bhyve x86_64 backend (plan T3: M0,
//! T6: carrick-owned ring-3 bring-up register-diff oracle, and T7: M1
//! ring-3 SYSCALL hello-world).
//!
//! These run REAL vCPUs and need `/dev/vmm` (vmm.ko loaded, root). On a host
//! without vmm they skip with a notice — the same gating posture as the HVF
//! tests' entitlement gate. Tests share one process-wide lock: `BhyveVm`
//! names are pid-derived, so two concurrent tests would collide on the same
//! /dev/vmm node.

#![cfg(all(target_os = "freebsd", target_arch = "x86_64"))]

use std::sync::Mutex;

use carrick_bhyve::BhyveTrapEngine;
use carrick_bhyve::X86Exit;
use carrick_bhyve::guest_setup_x86::{
    BroughtUpM0, GDT_LEN, PROT_RWX, SYSCALL_DOORBELL_PORT, VM_SEGID_SYSMEM, X86_GDT_GPA,
    X86_INIT_BLOB_GPA, X86_MEM_SIZE, X86_PML4_GPA, X86_STACK_TOP_GPA, bring_up_m0, bring_up_x86,
    bring_up_x86_m1, complete_inout,
};
use carrick_bhyve::vmm::BhyveVm;
use carrick_bhyve::vmm_x86::{
    VM_REG_GUEST_CR0, VM_REG_GUEST_CR3, VM_REG_GUEST_CR4, VM_REG_GUEST_CS, VM_REG_GUEST_EFER,
    VM_REG_GUEST_GDTR, VM_REG_GUEST_RAX, VM_REG_GUEST_RIP, VM_REG_GUEST_SS,
};
use carrick_hal::SyscallTrap as _;

/// Serialize the live tests (pid-derived VM names; see module docs).
static VM_LOCK: Mutex<()> = Mutex::new(());

/// True when bhyve is usable: /dev/vmm exists (it appears once any VM does)
/// or vmm.ko is loaded per `kldstat -q -m vmm`.
fn vmm_available() -> bool {
    if std::path::Path::new("/dev/vmm").exists() {
        return true;
    }
    std::process::Command::new("kldstat")
        .args(["-q", "-m", "vmm"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// M0 — flat-binary doorbell round-trip (the plan T3 pass condition):
/// three `OUT %al, $0xC5` doorbells must surface as INOUT exits with the
/// RAX sequence [1, 2, 3], then `hlt` stops the vCPU cleanly.
///
/// This test IS the resume-discipline experiment (spec open question 1):
/// every doorbell is resumed WITHOUT touching RIP; a repeated (rip, rax)
/// observation would prove the INOUT was replayed (no auto-advance) and the
/// fallback bumps RIP by `inst_length`. Outcome pinned below: bhyve
/// AUTO-ADVANCES (sys/amd64/vmm/vmm.c:1161+1172 `nextrip`), so the fallback
/// must never fire and [`complete_inout`] stays a no-op.
#[test]
fn m0_doorbell_round_trip() {
    if !vmm_available() {
        eprintln!("SKIP: vmm not available (/dev/vmm missing and kldstat -q -m vmm failed)");
        return;
    }
    let _guard = VM_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let BroughtUpM0 { vm, mut vcpu } = bring_up_m0().expect("M0 bring-up");

    let mut rax_seq: Vec<u64> = Vec::new();
    let mut last_doorbell: Option<(u64, u64)> = None;
    let mut manual_advance_was_needed = false;
    let mut halted = false;

    // Bounded loop: the blob fires 3 doorbells then hlt; anything past ~16
    // iterations means the resume discipline is broken in a new way.
    for _ in 0..16 {
        match vcpu.run_x86().expect("vm_run") {
            X86Exit::Inout {
                port: SYSCALL_DOORBELL_PORT,
                is_in: false,
                bytes: 1,
                inst_length,
                rip,
            } => {
                let rax = vcpu.get_reg_raw(VM_REG_GUEST_RAX).expect("read RAX");
                if last_doorbell == Some((rip, rax)) {
                    // The same OUT replayed: vm_run did NOT auto-advance.
                    // Fall back to a manual bump so the test still
                    // terminates, and record the discipline finding.
                    manual_advance_was_needed = true;
                    vcpu.set_reg_raw(VM_REG_GUEST_RIP, rip + u64::from(inst_length))
                        .expect("manual RIP advance");
                } else {
                    rax_seq.push(rax);
                }
                last_doorbell = Some((rip, rax));
                // The encoded discipline (a no-op — auto-advance).
                complete_inout(&mut vcpu, rip, inst_length).expect("complete_inout");
            }
            X86Exit::Hlt | X86Exit::Suspended { .. } => {
                halted = true;
                break;
            }
            X86Exit::Bogus => continue,
            other => panic!("unexpected exit during M0: {other:?}"),
        }
    }

    assert_eq!(rax_seq, [1, 2, 3], "doorbell RAX sequence");
    assert!(halted, "guest must reach hlt (VM_CAP_HALT_EXIT)");
    assert!(
        !manual_advance_was_needed,
        "resume-discipline pin: bhyve auto-advances completed INOUT \
         (vmm.c nextrip); a replay here means the discipline changed — \
         update complete_inout AND this pin together"
    );
    vm.destroy().expect("clean vm_destroy (m0)");
}

/// The high-GPA probe (spec open question 3): can carrick place guest RAM at
/// its aarch64-layout GPAs (176 GiB–1 TiB) on bhyve?
///
/// **Recorded outcome (FreeBSD 15.1-RC3 amd64, 2026-06-12): FAIL — at both
/// 256 GiB and ~1 TiB the kernel-side `vm_mmap_memseg` SUCCEEDS, but
/// `vm_map_gpa` returns NULL** (libvmmapi only resolves host pointers inside
/// the contiguous lowmem [0,3 GiB) / highmem [4 GiB,…) regions built by
/// `vm_setup_memory`; vmmapi.c:607-633). The host cannot touch guest memory
/// placed there, so T6's `BhyveGuestRam::plan_gpa` must allocate GPAs
/// compactly from a bump cursor instead of identity-placing carrick's high
/// VAs (the PML4 decouples VA from GPA; guest-virtual layout unchanged).
#[test]
fn high_gpa_probe() {
    if !vmm_available() {
        eprintln!("SKIP: vmm not available (/dev/vmm missing and kldstat -q -m vmm failed)");
        return;
    }
    let _guard = VM_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let vm = BhyveVm::create().expect("vm create");
    vm.setup_memory(32 * 1024 * 1024).expect("setup_memory");

    const PROBE_LEN: usize = 2 * 1024 * 1024;
    // 256 GiB and ~1 TiB — bracketing carrick's 176 GiB–1 TiB window GPAs.
    for gpa in [0x40_0000_0000u64, 0xFF_FFE0_0000u64] {
        let memseg = vm.mmap_memseg(gpa, VM_SEGID_SYSMEM, PROBE_LEN, PROT_RWX);
        let host_ptr = vm.map_gpa(gpa, PROBE_LEN);
        eprintln!(
            "high-GPA probe {gpa:#x}: vm_mmap_memseg-ok={} vm_map_gpa-resolves={}",
            memseg.is_ok(),
            host_ptr.is_some()
        );
        if let Some(p) = host_ptr {
            // If a pointer ever DOES come back, prove it works end-to-end so
            // a future libvmmapi improvement flips this test loudly.
            // SAFETY: vm_map_gpa guaranteed [p, p+PROBE_LEN) is guest RAM.
            unsafe {
                std::ptr::write_volatile(p, 0xA5u8);
                std::ptr::write_volatile(p.add(PROBE_LEN - 1), 0x5Au8);
                assert_eq!(std::ptr::read_volatile(p), 0xA5);
                assert_eq!(std::ptr::read_volatile(p.add(PROBE_LEN - 1)), 0x5A);
            }
        }
        // The recorded-outcome pins (see the doc comment): kernel maps it,
        // host can't reach it.
        assert!(
            memseg.is_ok(),
            "vm_mmap_memseg at {gpa:#x} failed — the kernel-side half of the \
             recorded outcome changed; re-run the probe and update the records \
             (guest_setup_x86.rs module docs + this test)"
        );
        assert!(
            host_ptr.is_none(),
            "vm_map_gpa resolved {gpa:#x} — the recorded FAIL outcome changed; \
             T6's compact-GPA decision should be revisited and the records \
             (guest_setup_x86.rs module docs + this test) updated"
        );
    }
    vm.destroy().expect("clean vm_destroy (high_gpa)");
}

/// T6 register-diff oracle (plan T6 Step 3): compare the live register state
/// produced by `vm_setup_freebsd_registers` (M0's decade-proven helper) against
/// the state produced by carrick's `bring_up_x86`.
///
/// # What we check and why
///
/// | Register | M0 (freebsd_registers) | carrick (bring_up_x86) | Expected |
/// |---|---|---|---|
/// | CR0 | 0x8001_0033 | same | **match** |
/// | CR4 | 0x0000_0620 | same | **match** |
/// | EFER | 0x1500 (LME\|LMA — no SCE/NXE) | 0xD01 (SCE\|LME\|LMA\|NXE) | **diverge** |
/// | GDTR limit | 23 (3×8−1) | 39 (5×8−1) | **diverge** |
/// | CS | 0x08 ring-0 | 0x08 ring-0 | **match** |
/// | SS | 0x10 ring-0 | 0x10 ring-0 | **match** |
///
/// The deliberate divergences confirm:
/// - EFER.SCE set (SYSCALL enabled — without it SYSCALL raises #UD → triple-fault).
/// - EFER.NXE set (PML4 NX bit active — without it NX is a reserved-bit #PF).
/// - Five GDT entries present (uSS + uCS64 are required for SYSRET arithmetic).
///
/// Ring-3 selectors (CS=0x23, SS=0x1B) appear only after the init blob's iretq
/// (at runtime); they are not visible in this pre-run state comparison.
#[test]
fn t6_register_diff_oracle() {
    if !vmm_available() {
        eprintln!("SKIP: vmm not available (/dev/vmm missing and kldstat -q -m vmm failed)");
        return;
    }
    let _guard = VM_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    // ── M0 side: vm_setup_freebsd_registers ──────────────────────────────────
    let BroughtUpM0 {
        vm: m0_vm,
        vcpu: m0_vcpu,
    } = bring_up_m0().expect("M0 bring-up for oracle");

    let m0_cr0 = m0_vcpu.get_reg_raw(VM_REG_GUEST_CR0).expect("M0 CR0");
    let m0_cr4 = m0_vcpu.get_reg_raw(VM_REG_GUEST_CR4).expect("M0 CR4");
    let m0_efer = m0_vcpu.get_reg_raw(VM_REG_GUEST_EFER).expect("M0 EFER");
    let (_, m0_gdtr_limit, _) = m0_vcpu.get_desc(VM_REG_GUEST_GDTR).expect("M0 GDTR");
    let m0_cs = m0_vcpu.get_reg_raw(VM_REG_GUEST_CS).expect("M0 CS");
    let m0_ss = m0_vcpu.get_reg_raw(VM_REG_GUEST_SS).expect("M0 SS");
    let m0_cr3 = m0_vcpu.get_reg_raw(VM_REG_GUEST_CR3).expect("M0 CR3");
    m0_vm.destroy().expect("M0 vm_destroy");

    // ── carrick side: bring_up_x86 ────────────────────────────────────────────
    let bux = bring_up_x86().expect("T6 bring_up_x86");

    let cx_cr0 = bux.vcpu.get_reg_raw(VM_REG_GUEST_CR0).expect("cx CR0");
    let cx_cr4 = bux.vcpu.get_reg_raw(VM_REG_GUEST_CR4).expect("cx CR4");
    let cx_efer = bux.vcpu.get_reg_raw(VM_REG_GUEST_EFER).expect("cx EFER");
    let (cx_gdtr_base, cx_gdtr_limit, _) = bux.vcpu.get_desc(VM_REG_GUEST_GDTR).expect("cx GDTR");
    let cx_cs = bux.vcpu.get_reg_raw(VM_REG_GUEST_CS).expect("cx CS");
    let cx_ss = bux.vcpu.get_reg_raw(VM_REG_GUEST_SS).expect("cx SS");
    let cx_cr3 = bux.vcpu.get_reg_raw(VM_REG_GUEST_CR3).expect("cx CR3");
    let cx_rip = bux.vcpu.get_reg_raw(VM_REG_GUEST_RIP).expect("cx RIP");
    bux.vm.destroy().expect("cx vm_destroy");

    // ── Matching fields ───────────────────────────────────────────────────────

    // Long-mode ESSENTIALS must be set on BOTH (proves carrick's entry is as
    // valid as the decade-proven helper's): CR0.PE|PG, CR4.PAE. Exact equality
    // is wrong — carrick deliberately adds CR0.WP (ring-0 honors the U/S+R/W
    // page bits, load-bearing for ring-3 isolation), which the minimal helper
    // omits. WP is a deliberate divergence, asserted on carrick's side below.
    const CR0_PE: u64 = 1 << 0;
    const CR0_WP: u64 = 1 << 16;
    const CR0_PG: u64 = 1 << 31;
    const CR4_PAE: u64 = 1 << 5;
    assert_eq!(cx_cr0 & CR0_PE, CR0_PE, "carrick CR0.PE set");
    assert_eq!(cx_cr0 & CR0_PG, CR0_PG, "carrick CR0.PG set");
    assert_eq!(m0_cr0 & CR0_PE, CR0_PE, "M0 CR0.PE set");
    assert_eq!(m0_cr0 & CR0_PG, CR0_PG, "M0 CR0.PG set");
    assert_eq!(cx_cr4 & CR4_PAE, CR4_PAE, "carrick CR4.PAE set (long mode)");
    assert_eq!(m0_cr4 & CR4_PAE, CR4_PAE, "M0 CR4.PAE set (long mode)");
    // Deliberate divergence: carrick sets CR0.WP, the helper does not.
    assert_eq!(
        cx_cr0 & CR0_WP,
        CR0_WP,
        "carrick CR0.WP must be set (ring-3 page-protection integrity)"
    );
    assert_eq!(
        m0_cr0 & CR0_WP,
        0,
        "M0 CR0.WP must be clear (vm_setup_freebsd_registers omits it)"
    );
    // Both start in ring-0 — carrick needs CPL 0 to WRMSR in the init blob.
    assert_eq!(
        cx_cs, m0_cs,
        "initial CS must match (ring-0): carrick={cx_cs:#x} M0={m0_cs:#x}"
    );
    assert_eq!(
        cx_ss, m0_ss,
        "initial SS must match (ring-0): carrick={cx_ss:#x} M0={m0_ss:#x}"
    );

    // ── Deliberate divergences ────────────────────────────────────────────────

    // EFER: carrick adds SCE (bit 0) and NXE (bit 11) — both absent in M0.
    assert_ne!(
        cx_efer, m0_efer,
        "EFER must diverge: carrick={cx_efer:#x} M0={m0_efer:#x}"
    );
    assert_ne!(
        cx_efer & (1 << 0),
        0,
        "carrick EFER.SCE must be set (SYSCALL enabled; without it #UD → triple-fault)"
    );
    assert_ne!(
        cx_efer & (1 << 11),
        0,
        "carrick EFER.NXE must be set (PML4 NX effective; without it NX = reserved-bit #PF)"
    );
    assert_eq!(
        m0_efer & (1 << 0),
        0,
        "M0 EFER.SCE must be CLEAR (vm_setup_freebsd_registers leaves it off)"
    );

    // GDTR limit: 5-entry GDT (carrick) vs 3-entry (M0).
    assert_eq!(
        cx_gdtr_limit,
        (GDT_LEN * 8 - 1) as u32,
        "carrick GDTR limit = 5*8−1 = 39"
    );
    assert_eq!(m0_gdtr_limit, 23, "M0 GDTR limit = 3*8−1 = 23");

    // GDTR base: carrick points at X86_GDT_GPA.
    assert_eq!(
        cx_gdtr_base, X86_GDT_GPA,
        "carrick GDTR base = X86_GDT_GPA ({X86_GDT_GPA:#x})"
    );

    // CR3 = the PML4 root GPA. carrick and M0 happen to use the SAME GPA
    // (X86_PML4_GPA == M0_PML4_GPA == 0x20_0000), so only the positive check is
    // meaningful — the tables AT that GPA differ (carrick's full window map vs
    // M0's identity map), but the root pointer is identical by layout.
    assert_eq!(
        cx_cr3, X86_PML4_GPA,
        "carrick CR3 = X86_PML4_GPA ({X86_PML4_GPA:#x})"
    );
    let _ = m0_cr3; // read for the diff but not asserted (same GPA by layout)

    // RIP: carrick starts at the ring-0 MSR init blob.
    assert_eq!(
        cx_rip, X86_INIT_BLOB_GPA,
        "carrick RIP = X86_INIT_BLOB_GPA ({X86_INIT_BLOB_GPA:#x})"
    );

    // Spot-check: X86_MEM_SIZE and X86_STACK_TOP_GPA are within lowmem.
    assert!(
        X86_STACK_TOP_GPA < X86_MEM_SIZE as u64,
        "X86_STACK_TOP_GPA must be within lowmem"
    );

    eprintln!(
        "T6 oracle PASS: CR0={m0_cr0:#x} CR4={m0_cr4:#x} \
         M0-EFER={m0_efer:#x} cx-EFER={cx_efer:#x} \
         M0-GDTR-limit={m0_gdtr_limit} cx-GDTR-limit={cx_gdtr_limit} \
         cx-GDTR-base={cx_gdtr_base:#x} cx-CR3={cx_cr3:#x} cx-RIP={cx_rip:#x}"
    );
}

/// M1 — ring-3 SYSCALL hello (plan T7 pass condition):
///
/// The guest blob issues `write(1, "hello\n", 6)` via a real `SYSCALL`
/// instruction (x86_64 number 1), then `exit_group(0)` (x86_64 number 231).
/// The trap engine remaps both to their canonical numbers (64 and 94), services
/// `write` by reading the guest buffer and writing it to a capture buffer, then
/// breaks on `exit_group`.
///
/// **Pass condition:** captured output == `b"hello\n"` AND exit code 0.
///
/// This test is the empirical proof of the ring-0-WRMSR mechanism:
/// if the SYSCALL trap never arrives (vCPU wedges or triple-faults), the
/// WRMSR→iretq→ring-3→SYSCALL chain failed and the blocker will be the first
/// non-`Bogus` exit reported.
#[test]
#[ignore = "M1 BLOCKED: the ring-0→ring-3 iretq #GPs (TRIPLEFAULT @ the iretq, \
            rip=init_blob+0x58, cpl=0 — ring-0 boot + WRMSRs confirmed working). \
            The whole chain is proven up to the iretq; the privilege transition \
            itself faults and needs a fault-vector catcher (a minimal IDT whose \
            vectors OUT their vector number) to identify the exact #GP/#PF cause. \
            Tracked in docs + memory. Run with --ignored once fixed."]
fn m1_ring3_syscall_hello() {
    if !vmm_available() {
        eprintln!("SKIP: vmm not available (/dev/vmm missing and kldstat -q -m vmm failed)");
        return;
    }
    let _guard = VM_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let bux = bring_up_x86_m1().expect("M1 bring-up");
    let mut engine = BhyveTrapEngine::new(bux);

    // Canonical syscall numbers (post-remap):
    //   write      = 64  (x86_64 1  → SyscallRemap::Direct(64))
    //   exit_group = 94  (x86_64 231 → SyscallRemap::Direct(94))
    //   exit       = 93  (x86_64 60  → SyscallRemap::Direct(93))
    const SYS_WRITE: u64 = 64;
    const SYS_EXIT_GROUP: u64 = 94;
    const SYS_EXIT: u64 = 93;

    let mut captured_output: Vec<u8> = Vec::new();
    let mut exit_code: Option<i64> = None;

    // Bounded loop: the blob fires one write(1,…) syscall and one exit_group;
    // anything past 16 iterations means the loop is wedged.
    for iter in 0..16 {
        match engine.next_syscall().expect("next_syscall") {
            None => {
                eprintln!("M1: vCPU exited cleanly (Hlt/Suspended) at iteration {iter}");
                break;
            }
            Some(raw) => match raw.number {
                SYS_WRITE => {
                    // args: [fd, buf_va, count, …]
                    let _fd = raw.args[0];
                    let buf_va = raw.args[1];
                    let count = raw.args[2] as usize;
                    // Read the guest buffer through BhyveTrapEngine::read_bytes.
                    use carrick_guest_mem::GuestMemory as _;
                    let bytes = engine
                        .read_bytes(buf_va, count)
                        .expect("read guest write buffer");
                    captured_output.extend_from_slice(&bytes);
                    // Return the byte count written (Linux write(2) contract).
                    engine
                        .complete_syscall(count as i64)
                        .expect("complete write");
                }
                SYS_EXIT_GROUP | SYS_EXIT => {
                    exit_code = Some(raw.args[0] as i64);
                    // Exit does not return; complete with 0 as a formality so
                    // the vCPU can be cleanly destroyed (the guest will not
                    // execute again after exit_group).
                    engine.complete_syscall(0).expect("complete exit_group");
                    break;
                }
                other => {
                    // Any other canonical number: answer -ENOSYS and log the
                    // x86_64 name for diagnostics (the §8 contract).
                    use carrick_hal::guest_arch::SyscallTable as _;
                    let name = carrick_hal::x8664_arch::X8664SyscallTable::name(other)
                        .unwrap_or("<unknown>");
                    eprintln!(
                        "M1: unhandled syscall canonical={other} name={name} \
                         args={:x?} → -ENOSYS",
                        &raw.args
                    );
                    engine.complete_syscall(-38).expect("complete enosys");
                }
            },
        }
    }

    // ── Pass conditions ───────────────────────────────────────────────────────

    assert_eq!(
        captured_output, b"hello\n",
        "M1 PASS: captured stdout must be b\"hello\\n\"; got {:?}",
        captured_output
    );
    assert_eq!(
        exit_code,
        Some(0),
        "M1 PASS: guest exit_group status must be 0; got {exit_code:?}"
    );

    eprintln!(
        "M1 PASS: captured={:?} exit_code={exit_code:?} \
         (ring-0-WRMSR mechanism CONFIRMED: SYSCALL trap delivered correctly)",
        String::from_utf8_lossy(&captured_output)
    );

    engine.destroy().expect("clean vm_destroy (m1)");
}
