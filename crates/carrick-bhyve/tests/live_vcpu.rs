//! Live-vCPU integration tests for the bhyve x86_64 backend (plan T3: M0).
//!
//! These run REAL vCPUs and need `/dev/vmm` (vmm.ko loaded, root). On a host
//! without vmm they skip with a notice — the same gating posture as the HVF
//! tests' entitlement gate. Tests share one process-wide lock: `BhyveVm`
//! names are pid-derived, so two concurrent tests would collide on the same
//! /dev/vmm node.

#![cfg(all(target_os = "freebsd", target_arch = "x86_64"))]

use std::sync::Mutex;

use carrick_bhyve::X86Exit;
use carrick_bhyve::guest_setup_x86::{
    BroughtUpM0, PROT_RWX, SYSCALL_DOORBELL_PORT, VM_SEGID_SYSMEM, bring_up_m0, complete_inout,
};
use carrick_bhyve::vmm::BhyveVm;
use carrick_bhyve::vmm_x86::{VM_REG_GUEST_RAX, VM_REG_GUEST_RIP};

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
    vm.destroy().expect("clean vm_destroy");
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
    vm.destroy().expect("clean vm_destroy");
}
