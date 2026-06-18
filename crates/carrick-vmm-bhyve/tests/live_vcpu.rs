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

use carrick_vmm_bhyve::X86Exit;
use carrick_vmm_bhyve::guest_setup_x86::{
    BroughtUpM0, FAULT_DOORBELL_PORT, FaultScratchRecord, GDT_LEN, M1_BLOB_VA, PROT_RWX,
    SYSCALL_DOORBELL_PORT, VM_SEGID_SYSMEM, X86_GDT_GPA, X86_INIT_BLOB_GPA, X86_MEM_SIZE,
    X86_PML4_GPA, X86_STACK_TOP_GPA, bring_up_m0, bring_up_x86, bring_up_x86_m1, complete_inout,
    fault_scratch_gpa, fault_scratch_record_from_bytes,
};
use carrick_vmm_bhyve::vmm::BhyveVm;
use carrick_vmm_bhyve::vmm_x86::{
    VM_REG_GUEST_CR0, VM_REG_GUEST_CR2, VM_REG_GUEST_CR3, VM_REG_GUEST_CR4, VM_REG_GUEST_CS,
    VM_REG_GUEST_EFER, VM_REG_GUEST_GDTR, VM_REG_GUEST_RAX, VM_REG_GUEST_RIP, VM_REG_GUEST_SS,
};

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

/// SP4.3 gate: a ring-3 page fault must vector through carrick's guest IDT,
/// switch to a real TSS.RSP0 stack, and reach the ring-0 fault doorbell
/// (`OUT %al,$0xC7`) instead of triple-faulting through the empty IDT.
#[test]
fn sp4_page_fault_reaches_fault_doorbell() {
    if !vmm_available() {
        eprintln!("SKIP: vmm not available (/dev/vmm missing and kldstat -q -m vmm failed)");
        return;
    }
    let _guard = VM_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let mut bux = bring_up_x86_m1().expect("M1 bring-up for #PF probe");
    let probe_gpa = bux
        .ram
        .windows_snapshot()
        .iter()
        .find(|w| w.va == M1_BLOB_VA)
        .map(|w| w.gpa)
        .expect("M1 blob window");
    let probe = [
        0x31, 0xC0, // xor %eax,%eax
        0x48, 0x89, 0x00, // mov %rax,(%rax) => #PF at VA 0
        0xEB, 0xFE, // jmp .
    ];
    let host = bux
        .vm
        .map_gpa(probe_gpa, probe.len())
        .expect("map probe blob GPA");
    // SAFETY: vm_map_gpa proved [host, host+probe.len()) is live guest RAM.
    unsafe { std::ptr::copy_nonoverlapping(probe.as_ptr(), host, probe.len()) };

    let mut saw_fault_doorbell = false;
    for _ in 0..16 {
        match bux.vcpu.run_x86().expect("vm_run #PF probe") {
            X86Exit::Inout {
                port: FAULT_DOORBELL_PORT,
                is_in: false,
                bytes: 1,
                ..
            } => {
                saw_fault_doorbell = true;
                break;
            }
            X86Exit::Bogus => continue,
            other => panic!("expected #PF fault doorbell on 0xC7, got {other:?}"),
        }
    }

    assert!(saw_fault_doorbell, "#PF probe did not reach fault doorbell");
    let scratch_gpa = fault_scratch_gpa(0).expect("fault scratch GPA");
    let mut scratch = [0u8; std::mem::size_of::<FaultScratchRecord>()];
    let scratch_host = bux
        .vm
        .map_gpa(scratch_gpa, scratch.len())
        .expect("map fault scratch GPA");
    // SAFETY: vm_map_gpa proved [scratch_host, scratch_host+len) is live guest RAM.
    unsafe { std::ptr::copy_nonoverlapping(scratch_host, scratch.as_mut_ptr(), scratch.len()) };
    let scratch = fault_scratch_record_from_bytes(&scratch).expect("decode fault scratch");
    assert_eq!(scratch.vector(), 14, "#PF probe must report vector 14");
    let cr2 = bux.vcpu.get_reg_raw(VM_REG_GUEST_CR2).expect("CR2");
    assert_eq!(cr2, 0, "#PF probe CR2 must be the null VA");
    bux.vm.destroy().expect("clean vm_destroy (#PF probe)");
}

/// SPIKE (SP1.1): does `minherit(INHERIT_COPY)` give a forked child a
/// COW-FROZEN view of a bhyve guest-RAM (`vm_map_gpa`) host mapping, or does the
/// device/SG VM pager silently force INHERIT_SHARE (the child then ALIASES the
/// parent's LIVE pages)?
///
/// `BhyveVmm::freeze_ram()` currently freezes the parent's whole guest RAM into
/// a heap `Vec<u8>` BEFORE `libc::fork`, because bhyve guest RAM is kernel-owned
/// and (unlike KVM's MAP_PRIVATE|ANON) is NOT copy-on-write across fork — the
/// inherited mapping aliases the parent's live pages, so a post-fork parent that
/// resumes its vCPU tears the child's image mid-copy. The proposed optimization
/// is to `minherit(host_ptr, len, INHERIT_COPY)` the parent's mapping before
/// fork so the child inherits a frozen COW copy and can copy from its OWN
/// inherited view, dropping the eager heap freeze. That optimization is ONLY
/// valid if COW is actually honored on this device mapping — which this test
/// decides empirically.
///
/// Method (host-level; no vCPU run): map a small sysmem segment, write sentinel
/// `0xAAAA_AAAA_AAAA_AAAA` at offset 0, `minherit(INHERIT_COPY)`, `fork`. The
/// PARENT overwrites offset 0 with `0xBBBB...` then signals the child via a
/// pipe; the CHILD waits for that signal, then reads offset 0 through the
/// inherited mapping. Child sees `0xAAAA` ⇒ COW FROZEN (exit 0); `0xBBBB` ⇒
/// ALIASED LIVE / COW NOT honored (exit 1); anything else ⇒ exit 2.
#[test]
fn minherit_cow_frozen_across_fork() {
    use std::ffi::c_void;

    if !vmm_available() {
        eprintln!("SKIP: vmm not available (/dev/vmm missing and kldstat -q -m vmm failed)");
        return;
    }
    let _guard = VM_LOCK.lock().unwrap();

    // FreeBSD sys/mman.h: INHERIT_SHARE=0, INHERIT_COPY=1, INHERIT_NONE=2.
    // libc 0.2.186 does NOT expose these (nor minherit) for FreeBSD, so declare
    // the value + prototype here (verified against /usr/include/sys/mman.h on the
    // 15.1-RC3 box: `#define INHERIT_COPY 1`, `int minherit(void *, size_t, int)`).
    const INHERIT_COPY: libc::c_int = 1;
    unsafe extern "C" {
        fn minherit(addr: *mut c_void, len: libc::size_t, inherit: libc::c_int) -> libc::c_int;
    }

    // A small multiple of the page size that vm_map_gpa resolves at GPA 0.
    const SZ: usize = 0x40_0000; // 4 MiB
    const SENTINEL_A: u64 = 0xAAAA_AAAA_AAAA_AAAA;
    const SENTINEL_B: u64 = 0xBBBB_BBBB_BBBB_BBBB;

    let vm = BhyveVm::create().expect("vm create");
    vm.setup_memory(SZ).expect("setup_memory");
    vm.mmap_memseg(0, VM_SEGID_SYSMEM, SZ, PROT_RWX)
        .expect("mmap_memseg");
    let p = vm.map_gpa(0, SZ).expect("map_gpa(0, SZ)");

    // Write the sentinel through the host pointer (the parent's live mapping).
    // SAFETY: p spans [0, SZ) of guest RAM (vm_map_gpa contract); offset 0 fits.
    unsafe { (p as *mut u64).write_volatile(SENTINEL_A) };

    // Request COPY (frozen) inheritance for the whole mapping.
    // SAFETY: p/SZ describe the live vm_map_gpa region; minherit only sets an
    // inheritance attribute on it.
    let mrc = unsafe { minherit(p as *mut c_void, SZ, INHERIT_COPY) };
    assert_eq!(
        mrc,
        0,
        "minherit(INHERIT_COPY) returned {mrc} (errno={})",
        std::io::Error::last_os_error()
    );

    // Pipe handshake so the parent's overwrite strictly precedes the child read.
    let mut fds = [0i32; 2];
    // SAFETY: fds is a valid 2-int array.
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "pipe");
    let (rd, wr) = (fds[0], fds[1]);

    // SAFETY: single-threaded test body; fork here is well-defined.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork failed: {}", std::io::Error::last_os_error());

    if pid == 0 {
        // CHILD: close the write end, wait for the parent's one-byte go signal,
        // then read offset 0 through the INHERITED mapping `p`.
        // SAFETY: rd/wr are valid fds owned by this process.
        unsafe { libc::close(wr) };
        let mut go = [0u8; 1];
        // SAFETY: reading 1 byte into a valid buffer; blocks until the parent
        // has overwritten the sentinel and written the go byte.
        let n = unsafe { libc::read(rd, go.as_mut_ptr() as *mut c_void, 1) };
        // SAFETY: p is the inherited mapping; offset 0 holds the (frozen-or-live) u64.
        let seen = unsafe { (p as *const u64).read_volatile() };
        let code = if n != 1 {
            3 // handshake failed
        } else if seen == SENTINEL_A {
            0 // COW FROZEN — child kept the pre-fork value
        } else if seen == SENTINEL_B {
            1 // ALIASED LIVE — child saw the parent's post-fork overwrite
        } else {
            2 // unexpected
        };
        // SAFETY: _exit is async-signal-safe and skips Drops (correct in a child
        // that must NOT vm_destroy the parent's VM).
        unsafe { libc::_exit(code) };
    }

    // PARENT: overwrite the sentinel through `p` (the LIVE parent mapping), then
    // release the child.
    // SAFETY: p is the parent's live mapping; offset 0 fits.
    unsafe { (p as *mut u64).write_volatile(SENTINEL_B) };
    unsafe { libc::close(rd) };
    let go = [1u8; 1];
    // SAFETY: writing 1 byte from a valid buffer to the pipe's write end.
    let wn = unsafe { libc::write(wr, go.as_ptr() as *const c_void, 1) };
    assert_eq!(wn, 1, "parent pipe write");
    // SAFETY: wr is a valid fd.
    unsafe { libc::close(wr) };

    let mut status: libc::c_int = 0;
    // SAFETY: pid is the live child; status is a valid out-pointer.
    let w = unsafe { libc::waitpid(pid, &mut status, 0) };
    assert_eq!(w, pid, "waitpid");
    assert!(
        libc::WIFEXITED(status),
        "child did not exit normally (status={status:#x})"
    );
    let code = libc::WEXITSTATUS(status);

    let verdict = match code {
        0 => "COW FROZEN (child saw 0xAAAA — INHERIT_COPY honored)",
        1 => "ALIASED LIVE (child saw 0xBBBB — INHERIT_COPY NOT honored, forced SHARE)",
        2 => "UNEXPECTED sentinel value",
        3 => "handshake failed",
        other => panic!("child exit code {other} is not in the protocol"),
    };
    eprintln!("SP1.1 minherit-COW VERDICT: exit={code} → {verdict}");

    vm.destroy().expect("clean vm_destroy (minherit spike)");

    assert_eq!(
        code, 0,
        "minherit(INHERIT_COPY) did NOT give a frozen child view of bhyve \
         vm_map_gpa memory (verdict: {verdict}); the eager pre-fork heap freeze \
         in BhyveVmm::freeze_ram() is required and must not be removed"
    );
}

/// SPIKE diagnostic (SP1.1 follow-up): faithfully reproduce the REAL fork path's
/// child sequence — after fork the child CREATES A SECOND VM (vm_create +
/// setup_memory + mmap_memseg + map_gpa) and only THEN reads the inherited
/// (minherit-COW) parent mapping as the copy source. The plain spike kept the
/// SAME inherited pointer and never built a child VM; this checks whether the
/// child's own VM-creation work disturbs the frozen view (re-mmap, address-space
/// churn, or the inherited mapping being re-resolved to a live alias).
///
/// Verdict via child exit: 0 = inherited source still FROZEN (0xAAAA) after the
/// child built its VM and the parent overwrote the page; 1 = source went LIVE
/// (0xBBBB); 4 = the COPIED-IN child-VM byte was wrong; other = setup failure.
#[test]
fn minherit_cow_frozen_across_fork_with_child_vm() {
    use std::ffi::c_void;

    if !vmm_available() {
        eprintln!("SKIP: vmm not available");
        return;
    }
    let _guard = VM_LOCK.lock().unwrap();

    const INHERIT_COPY: libc::c_int = 1;
    unsafe extern "C" {
        fn minherit(addr: *mut c_void, len: libc::size_t, inherit: libc::c_int) -> libc::c_int;
    }
    const SZ: usize = 0x40_0000;
    const SENTINEL_A: u64 = 0xAAAA_AAAA_AAAA_AAAA;
    const SENTINEL_B: u64 = 0xBBBB_BBBB_BBBB_BBBB;

    let vm = BhyveVm::create().expect("parent vm create");
    vm.setup_memory(SZ).expect("parent setup_memory");
    vm.mmap_memseg(0, VM_SEGID_SYSMEM, SZ, PROT_RWX)
        .expect("parent mmap_memseg");
    let p = vm.map_gpa(0, SZ).expect("parent map_gpa");
    // SAFETY: p spans [0, SZ).
    unsafe { (p as *mut u64).write_volatile(SENTINEL_A) };
    // SAFETY: live region; set inheritance attr only.
    let mrc = unsafe { minherit(p as *mut c_void, SZ, INHERIT_COPY) };
    assert_eq!(mrc, 0, "minherit (with-child-vm)");

    let mut fds = [0i32; 2];
    // SAFETY: valid 2-int array.
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "pipe");
    let (rd, wr) = (fds[0], fds[1]);

    // SAFETY: single-threaded test fork.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork");

    if pid == 0 {
        // CHILD: build a SECOND VM first (the real fork path's child work), THEN
        // wait for the parent's overwrite signal and read the inherited source.
        // SAFETY: pipe fds owned by this process.
        unsafe { libc::close(wr) };
        let child_code = (|| -> i32 {
            let child_vm = match BhyveVm::create() {
                Ok(v) => v,
                Err(_) => return 10,
            };
            if child_vm.setup_memory(SZ).is_err() {
                return 11;
            }
            if child_vm
                .mmap_memseg(0, VM_SEGID_SYSMEM, SZ, PROT_RWX)
                .is_err()
            {
                return 12;
            }
            let dst = match child_vm.map_gpa(0, SZ) {
                Some(d) => d,
                None => return 13,
            };
            // Now read the inherited (frozen-or-live) source AFTER all the child
            // VM-creation work, mirroring the real fork ordering.
            let mut go = [0u8; 1];
            // SAFETY: 1-byte read; blocks until parent overwrote + signaled.
            let n = unsafe { libc::read(rd, go.as_mut_ptr() as *mut c_void, 1) };
            if n != 1 {
                return 3;
            }
            // SAFETY: p is the inherited mapping (the copy SOURCE in the real path).
            let src_seen = unsafe { (p as *const u64).read_volatile() };
            // Do the real copy: inherited source → child VM, then read it back.
            // SAFETY: src=p spans SZ; dst spans SZ; distinct VMs' kernel RAM.
            unsafe { std::ptr::copy_nonoverlapping(p as *const u8, dst, SZ) };
            // SAFETY: dst spans SZ; offset 0 is the copied u64.
            let dst_seen = unsafe { (dst as *const u64).read_volatile() };
            let _ = child_vm.destroy();
            if src_seen == SENTINEL_B {
                1 // inherited source went LIVE
            } else if src_seen != SENTINEL_A {
                2 // inherited source garbage
            } else if dst_seen != SENTINEL_A {
                4 // copy landed wrong
            } else {
                0 // frozen source + correct copy
            }
        })();
        // SAFETY: async-signal-safe exit, skips Drops.
        unsafe { libc::_exit(child_code) };
    }

    // PARENT: overwrite the page, then release the child.
    // SAFETY: p is the live parent mapping.
    unsafe { (p as *mut u64).write_volatile(SENTINEL_B) };
    // SAFETY: rd valid.
    unsafe { libc::close(rd) };
    let go = [1u8; 1];
    // SAFETY: 1-byte write to the pipe.
    let wn = unsafe { libc::write(wr, go.as_ptr() as *const c_void, 1) };
    assert_eq!(wn, 1, "parent write");
    // SAFETY: wr valid.
    unsafe { libc::close(wr) };

    let mut status: libc::c_int = 0;
    // SAFETY: pid live; status valid.
    let w = unsafe { libc::waitpid(pid, &mut status, 0) };
    assert_eq!(w, pid, "waitpid");
    let code = libc::WEXITSTATUS(status);
    eprintln!(
        "SP1.1 with-child-VM VERDICT: exit={code} ({})",
        match code {
            0 => "FROZEN source + correct copy",
            1 => "inherited source went LIVE (0xBBBB)",
            2 => "inherited source garbage",
            3 => "handshake failed",
            4 => "copy landed wrong byte",
            _ => "child VM setup failure",
        }
    );
    vm.destroy().expect("clean vm_destroy (with-child spike)");
    assert_eq!(
        code, 0,
        "minherit COW must survive the child building its own VM"
    );
}
