#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::print_stdout
)]
//! Decisive K0 probe for Carrick's kernel-first single-VM memory model.
//!
//! WHAT IT MEASURES: one HVF VM hosts two non-zero-ASID stage-1 roots. The
//! roots initially share lower table pages and one globally mapped 16 KiB data
//! frame. A child write must raise an L3 permission fault. The probe then copies
//! one 16 KiB data frame and only the child table path, performs an ASID-scoped
//! TLBI, resumes the exact store, and proves that the parent stayed byte-exact.
//! It also qualifies concurrent disjoint stage-2 map/unmap calls and records
//! raw latency samples for ASID switches, faults, table-path copies, frame
//! map/unmap calls, and complete COW recovery.
//!
//! PASS CONTRACT: every expected exit, fault identity, descriptor attribute,
//! sample population, byte value, and parent table byte is checked. Missing or
//! ambiguous evidence panics; there is no empty-success path.
//!
//! PERTURBATION: this is a self-contained micro-VM. Its timings qualify the HAL
//! mechanism only; they are not workload performance authority.

const COMPOUND_FRAME_SIZE: usize = 0x4000;
const STAGE1_PAGE_SIZE: usize = 0x1000;
const TABLE_ENTRIES: usize = STAGE1_PAGE_SIZE / 8;

const TRAMPOLINE_VA: u64 = 0x0040_0000;
const VECTOR_VA: u64 = 0x0040_4000;
const CODE_VA: u64 = 0x0040_8000;
const DATA_VA: u64 = 0x0040_c000;
const MAINTENANCE_VA: u64 = 0x0041_0000;
const WRITE_CODE_VA: u64 = CODE_VA + 0x100;

const TRAMPOLINE_IPA: u64 = 0x0100_0000;
const VECTOR_IPA: u64 = 0x0100_4000;
const CODE_IPA: u64 = 0x0100_8000;
const SHARED_DATA_IPA: u64 = 0x0100_c000;
const PRIVATE_DATA_IPA: u64 = 0x0101_0000;
const MAINTENANCE_IPA: u64 = 0x0101_4000;

const PARENT_L0_IPA: u64 = 0x0200_0000;
const PARENT_L1_IPA: u64 = 0x0200_4000;
const PARENT_L2_IPA: u64 = 0x0200_8000;
const PARENT_L3_IPA: u64 = 0x0200_c000;
const CHILD_L0_IPA: u64 = 0x0201_0000;
const CHILD_L1_IPA: u64 = 0x0201_4000;
const CHILD_L2_IPA: u64 = 0x0201_8000;
const CHILD_L3_IPA: u64 = 0x0201_c000;

const PARENT_ASID: u16 = 0x41;
const CHILD_ASID: u16 = 0x42;

const VALID: u64 = 1;
const TABLE_OR_PAGE: u64 = 0b11;
const AP_MASK: u64 = 0b11 << 6;
const AP_RW_EL0: u64 = 0b01 << 6;
const AP_RO_EL0: u64 = 0b11 << 6;
const INNER_SHAREABLE: u64 = 0b11 << 8;
const ACCESS_FLAG: u64 = 1 << 10;
const NOT_GLOBAL: u64 = 1 << 11;
const PXN: u64 = 1 << 53;
const UXN: u64 = 1 << 54;
const PA_MASK: u64 = 0x0000_ffff_ffff_f000;

const KERNEL_RX_PAGE: u64 = UXN | ACCESS_FLAG | INNER_SHAREABLE | TABLE_OR_PAGE;
const USER_RX_PAGE: u64 =
    PXN | NOT_GLOBAL | ACCESS_FLAG | INNER_SHAREABLE | AP_RW_EL0 | TABLE_OR_PAGE;
const USER_RO_DATA_PAGE: u64 =
    PXN | UXN | NOT_GLOBAL | ACCESS_FLAG | INNER_SHAREABLE | AP_RO_EL0 | TABLE_OR_PAGE;
const USER_RW_DATA_PAGE: u64 =
    PXN | UXN | NOT_GLOBAL | ACCESS_FLAG | INNER_SHAREABLE | AP_RW_EL0 | TABLE_OR_PAGE;

const AARCH64_SVC0: u32 = 0xd400_0001;
const AARCH64_B_SELF: u32 = 0x1400_0000;
const AARCH64_LDR_X0_X20: u32 = 0xf940_0280;
const AARCH64_STR_X1_X20: u32 = 0xf900_0281;
const AARCH64_DSB_ISHST: u32 = 0xd503_3a9f;
const AARCH64_TLBI_ASIDE1IS_X0: u32 = 0xd508_8340;
const AARCH64_DSB_ISH: u32 = 0xd503_3b9f;
const AARCH64_ISB: u32 = 0xd503_3fdf;
const AARCH64_HVC1: u32 = 0xd400_0022;

#[derive(Clone, Copy)]
struct TableIpas {
    l1: u64,
    l2: u64,
    l3: u64,
}

const PARENT_TABLE_IPAS: TableIpas = TableIpas {
    l1: PARENT_L1_IPA,
    l2: PARENT_L2_IPA,
    l3: PARENT_L3_IPA,
};

const CHILD_TABLE_IPAS: TableIpas = TableIpas {
    l1: CHILD_L1_IPA,
    l2: CHILD_L2_IPA,
    l3: CHILD_L3_IPA,
};

#[derive(Clone)]
struct TablePath {
    l0: Vec<u8>,
    l1: Vec<u8>,
    l2: Vec<u8>,
    l3: Vec<u8>,
}

fn indices(va: u64) -> [usize; 4] {
    [
        ((va >> 39) & 0x1ff) as usize,
        ((va >> 30) & 0x1ff) as usize,
        ((va >> 21) & 0x1ff) as usize,
        ((va >> 12) & 0x1ff) as usize,
    ]
}

fn table_descriptor(next_ipa: u64) -> u64 {
    (next_ipa & PA_MASK) | TABLE_OR_PAGE
}

fn leaf_descriptor(ipa: u64, flags: u64) -> u64 {
    assert_ne!(flags & VALID, 0, "probe leaf must be valid");
    (ipa & PA_MASK) | flags
}

fn read_descriptor(table: &[u8], index: usize) -> u64 {
    assert!(index < TABLE_ENTRIES);
    let offset = index * 8;
    u64::from_le_bytes(
        table[offset..offset + 8]
            .try_into()
            .expect("descriptor width"),
    )
}

fn write_descriptor(table: &mut [u8], index: usize, value: u64) {
    assert!(index < TABLE_ENTRIES);
    let offset = index * 8;
    table[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn map_compound_leaf(table: &mut [u8], va: u64, ipa: u64, flags: u64) {
    let first = indices(va)[3];
    assert!(first + 4 <= TABLE_ENTRIES);
    for page in 0..4usize {
        write_descriptor(
            table,
            first + page,
            leaf_descriptor(ipa + (page * STAGE1_PAGE_SIZE) as u64, flags),
        );
    }
}

fn build_parent_tables() -> TablePath {
    let mut path = TablePath {
        l0: vec![0; COMPOUND_FRAME_SIZE],
        l1: vec![0; COMPOUND_FRAME_SIZE],
        l2: vec![0; COMPOUND_FRAME_SIZE],
        l3: vec![0; COMPOUND_FRAME_SIZE],
    };
    let path_index = indices(DATA_VA);
    for va in [TRAMPOLINE_VA, VECTOR_VA, CODE_VA, DATA_VA, MAINTENANCE_VA] {
        let current = indices(va);
        assert_eq!(
            current[..3],
            path_index[..3],
            "probe VAs must share one L3 path"
        );
    }
    write_descriptor(
        &mut path.l0,
        path_index[0],
        table_descriptor(PARENT_TABLE_IPAS.l1),
    );
    write_descriptor(
        &mut path.l1,
        path_index[1],
        table_descriptor(PARENT_TABLE_IPAS.l2),
    );
    write_descriptor(
        &mut path.l2,
        path_index[2],
        table_descriptor(PARENT_TABLE_IPAS.l3),
    );
    map_compound_leaf(&mut path.l3, TRAMPOLINE_VA, TRAMPOLINE_IPA, KERNEL_RX_PAGE);
    map_compound_leaf(&mut path.l3, VECTOR_VA, VECTOR_IPA, KERNEL_RX_PAGE);
    map_compound_leaf(&mut path.l3, CODE_VA, CODE_IPA, USER_RX_PAGE);
    map_compound_leaf(&mut path.l3, DATA_VA, SHARED_DATA_IPA, USER_RO_DATA_PAGE);
    map_compound_leaf(
        &mut path.l3,
        MAINTENANCE_VA,
        MAINTENANCE_IPA,
        KERNEL_RX_PAGE,
    );
    path
}

fn build_child_root(parent: &TablePath) -> Vec<u8> {
    let mut root = parent.l0.clone();
    let index = indices(DATA_VA)[0];
    assert_eq!(
        read_descriptor(&root, index) & PA_MASK,
        PARENT_TABLE_IPAS.l1,
        "forked child root must initially share the parent L1"
    );
    root.shrink_to_fit();
    root
}

#[cfg(test)]
fn copy_child_table_path(
    parent: &TablePath,
    child_root: &mut [u8],
    child_l1: &mut [u8],
    child_l2: &mut [u8],
    child_l3: &mut [u8],
) {
    child_l1.copy_from_slice(&parent.l1);
    child_l2.copy_from_slice(&parent.l2);
    child_l3.copy_from_slice(&parent.l3);

    let index = indices(DATA_VA);
    write_descriptor(child_l1, index[1], table_descriptor(CHILD_TABLE_IPAS.l2));
    write_descriptor(child_l2, index[2], table_descriptor(CHILD_TABLE_IPAS.l3));
    map_compound_leaf(child_l3, DATA_VA, PRIVATE_DATA_IPA, USER_RW_DATA_PAGE);

    // Publish the new root edge last. The live implementation must use release
    // stores; this pure builder is also used by unit tests before publication.
    std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
    write_descriptor(child_root, index[0], table_descriptor(CHILD_TABLE_IPAS.l1));
    std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
}

fn code_frame() -> Vec<u8> {
    let mut bytes = vec![0; COMPOUND_FRAME_SIZE];
    for (offset, word) in [AARCH64_LDR_X0_X20, AARCH64_SVC0, AARCH64_B_SELF]
        .into_iter()
        .enumerate()
    {
        bytes[offset * 4..offset * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    for (offset, word) in [AARCH64_STR_X1_X20, AARCH64_SVC0, AARCH64_B_SELF]
        .into_iter()
        .enumerate()
    {
        let byte = 0x100 + offset * 4;
        bytes[byte..byte + 4].copy_from_slice(&word.to_le_bytes());
    }
    bytes
}

fn scoped_tlbi_frame() -> Vec<u8> {
    let mut bytes = vec![0; COMPOUND_FRAME_SIZE];
    for (offset, word) in [
        AARCH64_DSB_ISHST,
        AARCH64_TLBI_ASIDE1IS_X0,
        AARCH64_DSB_ISH,
        AARCH64_ISB,
        AARCH64_HVC1,
        AARCH64_B_SELF,
    ]
    .into_iter()
    .enumerate()
    {
        bytes[offset * 4..offset * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    bytes
}

fn ttbr(root: u64, asid: u16) -> u64 {
    root | (u64::from(asid) << 48)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod platform {
    use std::ffi::c_void;
    use std::process::Command;
    use std::ptr;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Barrier, Mutex};
    use std::time::Instant;

    use applevisor_sys::{
        HV_MEMORY_EXEC, HV_MEMORY_READ, HV_MEMORY_WRITE, hv_exit_reason_t, hv_memory_flags_t,
        hv_reg_t, hv_return_t, hv_sys_reg_t, hv_vcpu_create, hv_vcpu_destroy, hv_vcpu_exit_t,
        hv_vcpu_get_reg, hv_vcpu_get_sys_reg, hv_vcpu_run, hv_vcpu_set_reg, hv_vcpu_set_sys_reg,
        hv_vcpu_t, hv_vm_config_create, hv_vm_config_get_max_ipa_size, hv_vm_config_set_ipa_size,
        hv_vm_create, hv_vm_destroy, hv_vm_map, hv_vm_unmap, os_release,
    };
    use carrick_mem::arch_sysregs::{
        CPACR_EL1_BOOTSTRAP, MAIR_EL1_BOOTSTRAP, SCTLR_EL1_BOOTSTRAP, TCR_EL1_BOOTSTRAP,
    };
    use carrick_mem::memory::{el0_trampoline_bytes, el1_vectors_bytes};

    use super::*;

    const HV_SUCCESS: hv_return_t = 0;
    const HV_DENIED: hv_return_t = 0xfae9_4007_u32 as hv_return_t;
    const PSTATE_EL1H_DAIF_MASKED: u64 = 0x3c5;
    const PSTATE_EL0T_DAIF_MASKED: u64 = 0x3c0;
    const COW_ITERATIONS: usize = 32;
    const MAP_THREADS: usize = 4;
    const MAP_ITERATIONS: usize = 32;

    struct HostFrame {
        host: *mut c_void,
        size: usize,
    }

    impl HostFrame {
        fn zeroed() -> Self {
            // SAFETY: anonymous private mmap with a null hint; the result is
            // checked before use and released exactly once in Drop.
            let host = unsafe {
                libc::mmap(
                    ptr::null_mut(),
                    COMPOUND_FRAME_SIZE,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_ANON | libc::MAP_PRIVATE,
                    -1,
                    0,
                )
            };
            assert_ne!(host, libc::MAP_FAILED, "host compound-frame mmap failed");
            assert_eq!(host as usize % COMPOUND_FRAME_SIZE, 0);
            Self {
                host,
                size: COMPOUND_FRAME_SIZE,
            }
        }

        fn from_bytes(bytes: &[u8]) -> Self {
            assert!(bytes.len() <= COMPOUND_FRAME_SIZE);
            let frame = Self::zeroed();
            // SAFETY: both ranges are valid and non-overlapping for bytes.len().
            unsafe {
                ptr::copy_nonoverlapping(bytes.as_ptr(), frame.host.cast::<u8>(), bytes.len())
            };
            frame
        }

        fn ptr(&self) -> *mut u8 {
            self.host.cast::<u8>()
        }

        fn write_u64(&self, value: u64) {
            // SAFETY: mmap returned at least eight writable bytes and is aligned.
            unsafe { self.ptr().cast::<u64>().write_volatile(value) };
        }

        fn copy_from(&self, source: &Self) {
            // SAFETY: both mappings are valid for one compound frame and distinct.
            unsafe { ptr::copy_nonoverlapping(source.ptr(), self.ptr(), COMPOUND_FRAME_SIZE) };
        }

        fn snapshot(&self) -> Vec<u8> {
            // SAFETY: the owned mapping is readable for one compound frame.
            unsafe { std::slice::from_raw_parts(self.ptr(), COMPOUND_FRAME_SIZE) }.to_vec()
        }

        fn fill_pattern(&self, seed: u8) {
            // SAFETY: the owned mapping is writable for one compound frame.
            let bytes = unsafe { std::slice::from_raw_parts_mut(self.ptr(), COMPOUND_FRAME_SIZE) };
            for (index, byte) in bytes.iter_mut().enumerate() {
                *byte = seed.wrapping_add((index as u8).wrapping_mul(17));
            }
        }
    }

    // SAFETY: HostFrame uniquely owns its mapping. Moving that ownership to a
    // worker is safe; no worker shares a frame with another worker.
    unsafe impl Send for HostFrame {}

    impl Drop for HostFrame {
        fn drop(&mut self) {
            // SAFETY: this mapping was created by HostFrame::zeroed and is owned.
            unsafe { libc::munmap(self.host, self.size) };
        }
    }

    struct ProbeVm {
        vcpu: hv_vcpu_t,
        exit: *const hv_vcpu_exit_t,
        frames: Vec<(u64, HostFrame)>,
        vcpu_live: bool,
        vm_live: bool,
    }

    #[derive(Clone, Copy, Debug)]
    struct ExitRecord {
        host_syndrome: u64,
        underlying_syndrome: u64,
        elr: u64,
        far: u64,
    }

    impl ProbeVm {
        fn create() -> Result<Self, hv_return_t> {
            let mut max_ipa = 0_u32;
            // SAFETY: HVF writes one u32 to the supplied valid pointer.
            let rc = unsafe { hv_vm_config_get_max_ipa_size(&mut max_ipa) };
            if rc != HV_SUCCESS {
                return Err(rc);
            }
            // SAFETY: creates a retained HVF configuration object.
            let config = unsafe { hv_vm_config_create() };
            if config.is_null() {
                return Err(HV_DENIED);
            }
            // SAFETY: config is live until os_release below.
            let rc = unsafe { hv_vm_config_set_ipa_size(config, max_ipa) };
            if rc != HV_SUCCESS {
                // SAFETY: release the retained config on the error path.
                unsafe { os_release(config.cast::<c_void>()) };
                return Err(rc);
            }
            // SAFETY: process has no existing HVF VM; this probe creates one.
            let rc = unsafe { hv_vm_create(config) };
            // SAFETY: the configuration is no longer needed after create.
            unsafe { os_release(config.cast::<c_void>()) };
            if rc != HV_SUCCESS {
                return Err(rc);
            }

            let mut vcpu = 0;
            let mut exit = ptr::null();
            // SAFETY: output pointers are valid and the VM is live.
            let rc = unsafe { hv_vcpu_create(&mut vcpu, &mut exit, ptr::null_mut()) };
            if rc != HV_SUCCESS {
                // SAFETY: no vCPU was created, so the VM can be destroyed.
                let _ = unsafe { hv_vm_destroy() };
                return Err(rc);
            }
            Ok(Self {
                vcpu,
                exit,
                frames: Vec::new(),
                vcpu_live: true,
                vm_live: true,
            })
        }

        fn map_frame(&mut self, ipa: u64, frame: HostFrame, flags: hv_memory_flags_t) -> usize {
            assert_eq!(ipa as usize % COMPOUND_FRAME_SIZE, 0);
            // SAFETY: frame is live, aligned, and retained in self until VM destroy.
            let rc = unsafe { hv_vm_map(frame.host, ipa, frame.size, flags) };
            assert_eq!(rc, HV_SUCCESS, "hv_vm_map({ipa:#x}) -> {}", rc_label(rc));
            self.frames.push((ipa, frame));
            self.frames.len() - 1
        }

        fn map_bytes(&mut self, ipa: u64, bytes: &[u8], flags: hv_memory_flags_t) -> usize {
            self.map_frame(ipa, HostFrame::from_bytes(bytes), flags)
        }

        fn frame(&self, index: usize) -> &HostFrame {
            &self.frames[index].1
        }

        fn set_reg(&self, reg: hv_reg_t, value: u64) {
            // SAFETY: vCPU is live and the register enum is supplied by HVF.
            let rc = unsafe { hv_vcpu_set_reg(self.vcpu, reg, value) };
            assert_eq!(rc, HV_SUCCESS, "set_reg {reg:?} -> {}", rc_label(rc));
        }

        fn get_reg(&self, reg: hv_reg_t) -> u64 {
            let mut value = 0;
            // SAFETY: vCPU and output pointer are live.
            let rc = unsafe { hv_vcpu_get_reg(self.vcpu, reg, &mut value) };
            assert_eq!(rc, HV_SUCCESS, "get_reg {reg:?} -> {}", rc_label(rc));
            value
        }

        fn set_sys(&self, reg: hv_sys_reg_t, value: u64) {
            // SAFETY: vCPU is live and the system-register enum is valid.
            let rc = unsafe { hv_vcpu_set_sys_reg(self.vcpu, reg, value) };
            assert_eq!(rc, HV_SUCCESS, "set_sys {reg:?} -> {}", rc_label(rc));
        }

        fn get_sys(&self, reg: hv_sys_reg_t) -> u64 {
            let mut value = 0;
            // SAFETY: vCPU and output pointer are live.
            let rc = unsafe { hv_vcpu_get_sys_reg(self.vcpu, reg, &mut value) };
            assert_eq!(rc, HV_SUCCESS, "get_sys {reg:?} -> {}", rc_label(rc));
            value
        }

        fn set_ttbr(&self, root: u64, asid: u16) -> u64 {
            let started = Instant::now();
            self.set_sys(hv_sys_reg_t::TTBR0_EL1, ttbr(root, asid));
            started.elapsed().as_nanos() as u64
        }

        fn boot_el0(&self, root: u64, asid: u16, entry: u64) {
            self.set_reg(hv_reg_t::CPSR, PSTATE_EL1H_DAIF_MASKED);
            self.set_reg(hv_reg_t::PC, TRAMPOLINE_VA);
            self.set_sys(hv_sys_reg_t::SPSR_EL1, PSTATE_EL0T_DAIF_MASKED);
            self.set_sys(hv_sys_reg_t::ELR_EL1, entry);
            self.set_sys(hv_sys_reg_t::VBAR_EL1, VECTOR_VA);
            self.set_sys(hv_sys_reg_t::CPACR_EL1, CPACR_EL1_BOOTSTRAP);
            self.set_sys(hv_sys_reg_t::MAIR_EL1, MAIR_EL1_BOOTSTRAP);
            self.set_sys(hv_sys_reg_t::TCR_EL1, TCR_EL1_BOOTSTRAP);
            self.set_sys(hv_sys_reg_t::TTBR0_EL1, ttbr(root, asid));
            self.set_sys(hv_sys_reg_t::TTBR1_EL1, ttbr(root, asid));
            self.set_sys(hv_sys_reg_t::SCTLR_EL1, SCTLR_EL1_BOOTSTRAP | 1);
        }

        fn enter_el0(&self, entry: u64) {
            self.set_reg(hv_reg_t::CPSR, PSTATE_EL0T_DAIF_MASKED);
            self.set_reg(hv_reg_t::PC, entry);
        }

        fn run_once(&self) -> ExitRecord {
            // SAFETY: vCPU is live; every returned exit is inspected below.
            let rc = unsafe { hv_vcpu_run(self.vcpu) };
            assert_eq!(rc, HV_SUCCESS, "hv_vcpu_run -> {}", rc_label(rc));
            // SAFETY: HVF owns this pointer for the vCPU lifetime.
            let exit = unsafe { self.exit.as_ref() }.expect("null HVF exit pointer");
            assert_eq!(
                exit.reason,
                hv_exit_reason_t::EXCEPTION,
                "unexpected HVF exit reason {:?}",
                exit.reason
            );
            let host_syndrome = exit.exception.syndrome;
            let host_ec = (host_syndrome >> 26) & 0x3f;
            assert_eq!(
                host_ec, 0x16,
                "expected vector/maintenance HVC, got {host_syndrome:#x}"
            );
            ExitRecord {
                host_syndrome,
                underlying_syndrome: self.get_sys(hv_sys_reg_t::ESR_EL1),
                elr: self.get_sys(hv_sys_reg_t::ELR_EL1),
                far: self.get_sys(hv_sys_reg_t::FAR_EL1),
            }
        }

        fn run_expect_svc(&self) -> ExitRecord {
            let exit = self.run_once();
            assert_eq!(exit.host_syndrome & 0xffff, 2, "expected vector hvc #2");
            assert_eq!(
                (exit.underlying_syndrome >> 26) & 0x3f,
                0x15,
                "expected underlying EL0 SVC"
            );
            exit
        }

        fn run_expect_write_permission_fault(&self) -> ExitRecord {
            let exit = self.run_once();
            assert_eq!(
                exit.host_syndrome & 0xffff,
                2,
                "fault did not traverse vector hvc #2"
            );
            let esr = exit.underlying_syndrome;
            assert_eq!((esr >> 26) & 0x3f, 0x24, "expected lower-EL data abort");
            assert_eq!(esr & 0x3f, 0x0f, "expected L3 permission fault DFSC");
            assert_ne!(esr & (1 << 6), 0, "fault was not a write");
            assert_eq!(
                exit.elr, WRITE_CODE_VA,
                "fault did not name the exact store"
            );
            assert_eq!(exit.far, DATA_VA, "fault did not name the COW VA");
            exit
        }

        fn scoped_tlbi(&self, asid: u16) -> u64 {
            self.set_reg(hv_reg_t::X0, u64::from(asid) << 48);
            self.set_reg(hv_reg_t::CPSR, PSTATE_EL1H_DAIF_MASKED);
            self.set_reg(hv_reg_t::PC, MAINTENANCE_VA);
            let started = Instant::now();
            let exit = self.run_once();
            let elapsed = started.elapsed().as_nanos() as u64;
            assert_eq!(
                exit.host_syndrome & 0xffff,
                1,
                "scoped TLBI did not end at hvc #1"
            );
            elapsed
        }

        fn shutdown(&mut self) {
            if self.vcpu_live {
                // SAFETY: this probe owns the live vCPU and destroys it once.
                let rc = unsafe { hv_vcpu_destroy(self.vcpu) };
                assert_eq!(rc, HV_SUCCESS, "hv_vcpu_destroy -> {}", rc_label(rc));
                self.vcpu_live = false;
            }
            if self.vm_live {
                // SAFETY: all stage-2 workers have joined and the vCPU is gone.
                let rc = unsafe { hv_vm_destroy() };
                assert_eq!(rc, HV_SUCCESS, "hv_vm_destroy -> {}", rc_label(rc));
                self.vm_live = false;
            }
        }
    }

    impl Drop for ProbeVm {
        fn drop(&mut self) {
            if self.vcpu_live {
                // SAFETY: best-effort cleanup after a pre-GO failure.
                let _ = unsafe { hv_vcpu_destroy(self.vcpu) };
                self.vcpu_live = false;
            }
            if self.vm_live {
                // SAFETY: best-effort cleanup after a pre-GO failure.
                let _ = unsafe { hv_vm_destroy() };
                self.vm_live = false;
            }
            self.frames.clear();
        }
    }

    fn rc_label(rc: hv_return_t) -> String {
        match rc as u32 {
            0 => "HV_SUCCESS".to_owned(),
            0xfae9_4001 => "HV_ERROR(0xfae94001)".to_owned(),
            0xfae9_4002 => "HV_BUSY(0xfae94002)".to_owned(),
            0xfae9_4005 => "HV_NO_RESOURCES(0xfae94005)".to_owned(),
            0xfae9_4006 => "HV_NO_DEVICE(0xfae94006)".to_owned(),
            0xfae9_4007 => "HV_DENIED(0xfae94007)".to_owned(),
            0xfae9_4008 => "HV_FAULT(0xfae94008)".to_owned(),
            0xfae9_400f => "HV_UNSUPPORTED(0xfae9400f)".to_owned(),
            other => format!("HV_UNKNOWN(0x{other:08x})"),
        }
    }

    fn percentile(samples: &[u64], numerator: usize, denominator: usize) -> u64 {
        assert!(!samples.is_empty(), "latency sample population is empty");
        let mut sorted = samples.to_vec();
        sorted.sort_unstable();
        let rank = (sorted.len() - 1) * numerator / denominator;
        sorted[rank]
    }

    fn print_summary(name: &str, samples: &[u64]) {
        assert!(!samples.is_empty(), "{name} produced no samples");
        println!(
            "{{\"probe\":\"k0-latency-summary\",\"operation\":\"{name}\",\"samples\":{},\"min_ns\":{},\"p50_ns\":{},\"p95_ns\":{},\"max_ns\":{}}}",
            samples.len(),
            percentile(samples, 0, 1),
            percentile(samples, 50, 100),
            percentile(samples, 95, 100),
            percentile(samples, 100, 100),
        );
    }

    struct Stage2Wave {
        map_samples: Vec<u64>,
        unmap_samples: Vec<u64>,
        failures: Vec<hv_return_t>,
        max_in_flight: usize,
        // Retain every backing until checked VM destruction. On an unmap
        // failure, dropping it earlier would leave HVF pointing at freed host VA.
        _frames: Vec<HostFrame>,
    }

    struct Stage2Qualification {
        mode: &'static str,
        map_samples: Vec<u64>,
        unmap_samples: Vec<u64>,
        concurrent_failures: usize,
        max_in_flight: usize,
        _frames: Vec<HostFrame>,
    }

    fn stage2_wave(serialized: bool, base_ipa: u64) -> Stage2Wave {
        // Allocation happens before worker launch, so an mmap failure cannot
        // strand peers forever at the barrier.
        let frames: Vec<_> = (0..MAP_THREADS).map(|_| HostFrame::zeroed()).collect();
        let barrier = Arc::new(Barrier::new(MAP_THREADS));
        let lock = Arc::new(Mutex::new(()));
        let in_flight = Arc::new(AtomicUsize::new(0));
        let max_in_flight = Arc::new(AtomicUsize::new(0));
        let mut workers = Vec::with_capacity(MAP_THREADS);
        for (worker, frame) in frames.into_iter().enumerate() {
            let barrier = Arc::clone(&barrier);
            let lock = Arc::clone(&lock);
            let in_flight = Arc::clone(&in_flight);
            let max_in_flight = Arc::clone(&max_in_flight);
            workers.push(std::thread::spawn(move || {
                let ipa = base_ipa + (worker as u64) * 0x10_0000;
                let mut map_samples = Vec::with_capacity(MAP_ITERATIONS);
                let mut unmap_samples = Vec::with_capacity(MAP_ITERATIONS);
                let mut failures = Vec::new();
                for _ in 0..MAP_ITERATIONS {
                    // Align every individual call wave, not only thread startup.
                    barrier.wait();
                    let guard = serialized.then(|| {
                        lock.lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                    });
                    let active = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                    max_in_flight.fetch_max(active, Ordering::SeqCst);
                    let started = Instant::now();
                    // SAFETY: the frame is live and each worker uses a disjoint IPA.
                    let map_rc = unsafe {
                        hv_vm_map(
                            frame.host,
                            ipa,
                            COMPOUND_FRAME_SIZE,
                            HV_MEMORY_READ | HV_MEMORY_WRITE,
                        )
                    };
                    map_samples.push(started.elapsed().as_nanos() as u64);
                    in_flight.fetch_sub(1, Ordering::SeqCst);
                    drop(guard);
                    if map_rc != HV_SUCCESS {
                        failures.push(map_rc);
                    }

                    // Do not begin any unmap until every disjoint map call has
                    // returned. A failed map still participates, preventing hangs.
                    barrier.wait();
                    if map_rc == HV_SUCCESS {
                        let guard = serialized.then(|| {
                            lock.lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner)
                        });
                        let active = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                        max_in_flight.fetch_max(active, Ordering::SeqCst);
                        let started = Instant::now();
                        // SAFETY: this worker just mapped this exact disjoint range.
                        let unmap_rc = unsafe { hv_vm_unmap(ipa, COMPOUND_FRAME_SIZE) };
                        unmap_samples.push(started.elapsed().as_nanos() as u64);
                        in_flight.fetch_sub(1, Ordering::SeqCst);
                        drop(guard);
                        if unmap_rc != HV_SUCCESS {
                            failures.push(unmap_rc);
                        }
                    }
                    // Finish every unmap before the next map wave.
                    barrier.wait();
                }
                (map_samples, unmap_samples, failures, frame)
            }));
        }

        let mut map_samples = Vec::new();
        let mut unmap_samples = Vec::new();
        let mut failures = Vec::new();
        let mut retained_frames = Vec::new();
        let mut panic_seen = false;
        for worker in workers {
            match worker.join() {
                Ok((mut maps, mut unmaps, mut worker_failures, frame)) => {
                    map_samples.append(&mut maps);
                    unmap_samples.append(&mut unmaps);
                    failures.append(&mut worker_failures);
                    retained_frames.push(frame);
                }
                Err(_) => panic_seen = true,
            }
        }
        assert!(!panic_seen, "stage2 map worker panicked");
        Stage2Wave {
            map_samples,
            unmap_samples,
            failures,
            max_in_flight: max_in_flight.load(Ordering::SeqCst),
            _frames: retained_frames,
        }
    }

    fn qualify_stage2() -> Stage2Qualification {
        let concurrent = stage2_wave(false, 0x0400_0000);
        if concurrent.failures.is_empty() {
            assert_eq!(
                concurrent.map_samples.len(),
                MAP_THREADS * MAP_ITERATIONS,
                "concurrent stage2 map sample population is incomplete"
            );
            assert_eq!(
                concurrent.unmap_samples.len(),
                MAP_THREADS * MAP_ITERATIONS,
                "concurrent stage2 unmap sample population is incomplete"
            );
            assert!(
                concurrent.max_in_flight > 1,
                "scheduler never produced overlapping HVF map/unmap calls"
            );
            return Stage2Qualification {
                mode: "concurrent",
                map_samples: concurrent.map_samples,
                unmap_samples: concurrent.unmap_samples,
                concurrent_failures: 0,
                max_in_flight: concurrent.max_in_flight,
                _frames: concurrent._frames,
            };
        }

        println!(
            "{{\"probe\":\"k0-stage2-concurrency\",\"status\":\"SERIALIZATION_REQUIRED\",\"failures\":{},\"first_rc\":\"{}\",\"max_in_flight\":{}}}",
            concurrent.failures.len(),
            rc_label(concurrent.failures[0]),
            concurrent.max_in_flight,
        );
        let serialized = stage2_wave(true, 0x0500_0000);
        assert!(
            serialized.failures.is_empty(),
            "serialized disjoint stage2 map/unmap still failed: {}",
            rc_label(serialized.failures[0])
        );
        assert_eq!(
            serialized.max_in_flight, 1,
            "serialization lock did not serialize HVF calls"
        );
        assert_eq!(serialized.map_samples.len(), MAP_THREADS * MAP_ITERATIONS);
        assert_eq!(serialized.unmap_samples.len(), MAP_THREADS * MAP_ITERATIONS);
        let mut frames = concurrent._frames;
        frames.extend(serialized._frames);
        Stage2Qualification {
            mode: "serialized",
            map_samples: serialized.map_samples,
            unmap_samples: serialized.unmap_samples,
            concurrent_failures: concurrent.failures.len(),
            max_in_flight: serialized.max_in_flight,
            _frames: frames,
        }
    }

    fn publish_live_table(frame: &HostFrame, bytes: &[u8]) {
        assert_eq!(bytes.len(), COMPOUND_FRAME_SIZE);
        // SAFETY: frame is writable for exactly bytes.len() and does not overlap bytes.
        unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), frame.ptr(), bytes.len()) };
        std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
    }

    fn publish_descriptor(frame: &HostFrame, index: usize, descriptor: u64) {
        assert!(index < TABLE_ENTRIES);
        // SAFETY: table entries are naturally aligned AtomicU64 slots within
        // the owned writable compound frame.
        let slot = unsafe {
            frame
                .ptr()
                .add(index * 8)
                .cast::<std::sync::atomic::AtomicU64>()
        };
        // SAFETY: slot points at a live AtomicU64-compatible table entry.
        unsafe { (*slot).store(descriptor, Ordering::SeqCst) };
        std::sync::atomic::fence(Ordering::SeqCst);
    }

    fn publish_compound_leaf(frame: &HostFrame, va: u64, ipa: u64, attributes: u64) {
        let first = indices(va)[3];
        for page in 0..(COMPOUND_FRAME_SIZE / STAGE1_PAGE_SIZE) {
            publish_descriptor(
                frame,
                first + page,
                leaf_descriptor(ipa + (page * STAGE1_PAGE_SIZE) as u64, attributes),
            );
        }
    }

    fn read_guest(vm: &ProbeVm, root: u64, asid: u16, first_boot: bool) -> (u64, u64) {
        let switch_ns = if first_boot {
            vm.boot_el0(root, asid, CODE_VA);
            0
        } else {
            let sample = vm.set_ttbr(root, asid);
            vm.enter_el0(CODE_VA);
            sample
        };
        vm.set_reg(hv_reg_t::X20, DATA_VA);
        vm.run_expect_svc();
        (vm.get_reg(hv_reg_t::X0), switch_ns)
    }

    fn command_output(program: &str, arguments: &[&str]) -> String {
        let output = Command::new(program)
            .args(arguments)
            .output()
            .unwrap_or_else(|error| panic!("run {program}: {error}"));
        assert!(
            output.status.success(),
            "{program} {:?} failed: {}",
            arguments,
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout)
            .expect("provenance command output must be UTF-8")
            .trim()
            .to_owned()
    }

    fn binary_provenance() -> (String, String, bool) {
        let executable = std::env::current_exe().expect("resolve current probe binary");
        let executable_text = executable.to_string_lossy();
        let shasum = command_output("/usr/bin/shasum", &["-a", "256", &executable_text]);
        let sha256 = shasum
            .split_whitespace()
            .next()
            .expect("shasum omitted the digest")
            .to_owned();
        assert_eq!(sha256.len(), 64, "shasum returned a non-SHA-256 digest");
        let uuid = command_output("xcrun", &["dwarfdump", "--uuid", &executable_text]);
        let entitlements =
            command_output("codesign", &["-d", "--entitlements", "-", &executable_text]);
        (
            sha256,
            uuid,
            entitlements.contains("com.apple.security.hypervisor"),
        )
    }

    pub fn run() {
        // A process-wide alarm is the fail-closed watchdog for an unexpected
        // guest spin or host barrier deadlock. A timeout cannot emit GO.
        // SAFETY: alarm installs the process's standard SIGALRM deadline.
        unsafe { libc::alarm(30) };
        let run_id = std::env::var("CARRICK_RUN_ID")
            .expect("CARRICK_RUN_ID is required for a qualified K0 capture");
        assert!(!run_id.is_empty(), "CARRICK_RUN_ID must not be empty");
        let source_commit = std::env::var("CARRICK_SOURCE_COMMIT")
            .expect("CARRICK_SOURCE_COMMIT is required for a qualified K0 capture");
        let mut load = [0_f64; 3];
        // SAFETY: getloadavg writes at most three f64 values to a valid array.
        let load_count = unsafe { libc::getloadavg(load.as_mut_ptr(), 3) };
        assert_eq!(load_count, 3, "getloadavg did not return three samples");
        let (binary_sha256, binary_uuid, hypervisor_entitlement) = binary_provenance();
        assert!(
            hypervisor_entitlement,
            "signed probe lacks the HVF entitlement"
        );
        let provenance = serde_json::json!({
            "probe": "k0-provenance",
            "schema": "carrick.hvpatch.k0-memory.v2",
            "run_id": run_id,
            "pid": std::process::id(),
            "source_commit": source_commit,
            "binary_sha256": binary_sha256,
            "binary_uuid": binary_uuid,
            "hypervisor_entitlement": hypervisor_entitlement,
            "hypervisor_api": "Hypervisor.framework",
            "host_model": command_output("sysctl", &["-n", "hw.model"]),
            "host_arch": std::env::consts::ARCH,
            "macos_product": command_output("sw_vers", &["-productName"]),
            "macos_version": command_output("sw_vers", &["-productVersion"]),
            "macos_build": command_output("sw_vers", &["-buildVersion"]),
            "kernel": command_output("uname", &["-srvmp"]),
            "argv": std::env::args().collect::<Vec<_>>(),
            "host_page_size": unsafe { libc::sysconf(libc::_SC_PAGESIZE) },
            "loadavg1": load[0],
            "cow_iterations": COW_ITERATIONS,
            "map_threads": MAP_THREADS,
            "map_iterations": MAP_ITERATIONS,
        });
        println!(
            "{}",
            serde_json::to_string(&provenance).expect("serialize K0 provenance")
        );
        assert_eq!(
            // SAFETY: sysconf is a read-only libc query.
            unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize,
            COMPOUND_FRAME_SIZE,
            "K0 probe is qualified only for a 16 KiB Darwin host"
        );

        let mut vm = match ProbeVm::create() {
            Ok(vm) => vm,
            Err(rc) => {
                println!(
                    "{{\"probe\":\"k0-kernel-memory\",\"status\":\"ERROR\",\"operation\":\"hv_vm_create\",\"rc\":\"{}\"}}",
                    rc_label(rc)
                );
                if rc == HV_DENIED {
                    eprintln!(
                        "HV_DENIED: sign this probe with scripts/entitlements.plist before trusting a negative"
                    );
                }
                std::process::exit(2);
            }
        };

        let stage2 = qualify_stage2();
        for (sample, elapsed_ns) in stage2.map_samples.iter().enumerate() {
            println!(
                "{{\"probe\":\"k0-latency\",\"operation\":\"frame-map\",\"sample\":{sample},\"elapsed_ns\":{elapsed_ns}}}"
            );
        }
        for (sample, elapsed_ns) in stage2.unmap_samples.iter().enumerate() {
            println!(
                "{{\"probe\":\"k0-latency\",\"operation\":\"frame-unmap\",\"sample\":{sample},\"elapsed_ns\":{elapsed_ns}}}"
            );
        }

        let parent = build_parent_tables();
        let parent_snapshot = parent.clone();
        let child_root = build_child_root(&parent);

        vm.map_bytes(
            TRAMPOLINE_IPA,
            &el0_trampoline_bytes(),
            HV_MEMORY_READ | HV_MEMORY_EXEC,
        );
        vm.map_bytes(
            VECTOR_IPA,
            &el1_vectors_bytes(),
            HV_MEMORY_READ | HV_MEMORY_EXEC,
        );
        vm.map_bytes(CODE_IPA, &code_frame(), HV_MEMORY_READ | HV_MEMORY_EXEC);
        let shared_frame = vm.map_frame(
            SHARED_DATA_IPA,
            HostFrame::zeroed(),
            HV_MEMORY_READ | HV_MEMORY_WRITE,
        );
        let private_frame = vm.map_frame(
            PRIVATE_DATA_IPA,
            HostFrame::zeroed(),
            HV_MEMORY_READ | HV_MEMORY_WRITE,
        );
        vm.map_bytes(
            MAINTENANCE_IPA,
            &scoped_tlbi_frame(),
            HV_MEMORY_READ | HV_MEMORY_EXEC,
        );
        let parent_l0 = vm.map_bytes(PARENT_L0_IPA, &parent.l0, HV_MEMORY_READ | HV_MEMORY_WRITE);
        let parent_l1 = vm.map_bytes(PARENT_L1_IPA, &parent.l1, HV_MEMORY_READ | HV_MEMORY_WRITE);
        let parent_l2 = vm.map_bytes(PARENT_L2_IPA, &parent.l2, HV_MEMORY_READ | HV_MEMORY_WRITE);
        let parent_l3 = vm.map_bytes(PARENT_L3_IPA, &parent.l3, HV_MEMORY_READ | HV_MEMORY_WRITE);
        let child_l0 = vm.map_bytes(CHILD_L0_IPA, &child_root, HV_MEMORY_READ | HV_MEMORY_WRITE);
        let child_l1 = vm.map_frame(
            CHILD_L1_IPA,
            HostFrame::zeroed(),
            HV_MEMORY_READ | HV_MEMORY_WRITE,
        );
        let child_l2 = vm.map_frame(
            CHILD_L2_IPA,
            HostFrame::zeroed(),
            HV_MEMORY_READ | HV_MEMORY_WRITE,
        );
        let child_l3 = vm.map_frame(
            CHILD_L3_IPA,
            HostFrame::zeroed(),
            HV_MEMORY_READ | HV_MEMORY_WRITE,
        );

        let shared_a = 0x1122_3344_5566_7788;
        let shared_b = 0x8877_6655_4433_2211;
        vm.frame(shared_frame).write_u64(shared_a);
        let (parent_value, _) = read_guest(&vm, PARENT_L0_IPA, PARENT_ASID, true);
        assert_eq!(parent_value, shared_a);
        let (child_value, _) = read_guest(&vm, CHILD_L0_IPA, CHILD_ASID, false);
        assert_eq!(child_value, shared_a);
        vm.frame(shared_frame).write_u64(shared_b);
        let (parent_value, _) = read_guest(&vm, PARENT_L0_IPA, PARENT_ASID, false);
        assert_eq!(parent_value, shared_b);
        let (child_value, _) = read_guest(&vm, CHILD_L0_IPA, CHILD_ASID, false);
        assert_eq!(child_value, shared_b);
        println!(
            "{{\"probe\":\"k0-shared-frame\",\"status\":\"PASS\",\"vm_count\":1,\"parent_asid\":{PARENT_ASID},\"child_asid\":{CHILD_ASID},\"parent_root\":\"{PARENT_L0_IPA:#x}\",\"child_root\":\"{CHILD_L0_IPA:#x}\",\"shared_ipa\":\"{SHARED_DATA_IPA:#x}\"}}"
        );

        let data_index = indices(DATA_VA)[3];
        let parent_leaf = read_descriptor(&parent.l3, data_index);
        assert_ne!(
            parent_leaf & NOT_GLOBAL,
            0,
            "ASID test requires nG user leaves"
        );
        assert_eq!(
            parent_leaf & AP_MASK,
            AP_RO_EL0,
            "COW source must be read-only"
        );

        let mut fault_ns = Vec::with_capacity(COW_ITERATIONS);
        let mut recovery_ns = Vec::with_capacity(COW_ITERATIONS);
        let mut table_copy_ns = Vec::with_capacity(COW_ITERATIONS);
        let mut asid_switch_ns = Vec::with_capacity(COW_ITERATIONS * 2);
        let mut tlbi_ns = Vec::with_capacity(COW_ITERATIONS * 4);
        let root_index = indices(DATA_VA)[0];
        let shared_root_edge = table_descriptor(PARENT_TABLE_IPAS.l1);
        let private_root_edge = table_descriptor(CHILD_TABLE_IPAS.l1);

        for iteration in 0..COW_ITERATIONS {
            let original = 0xa000_0000_0000_0000 | iteration as u64;
            let written = 0xb000_0000_0000_0000 | iteration as u64;
            vm.frame(shared_frame).fill_pattern(iteration as u8);
            vm.frame(shared_frame).write_u64(original);
            vm.frame(private_frame).fill_pattern(0x5a);
            let shared_snapshot = vm.frame(shared_frame).snapshot();

            asid_switch_ns.push(vm.set_ttbr(CHILD_L0_IPA, CHILD_ASID));
            assert_eq!(
                vm.get_sys(hv_sys_reg_t::TTBR0_EL1),
                ttbr(CHILD_L0_IPA, CHILD_ASID),
                "fault was not bound to the child mm/ASID"
            );
            vm.set_reg(hv_reg_t::X20, DATA_VA);
            vm.set_reg(hv_reg_t::X1, written);
            vm.enter_el0(WRITE_CODE_VA);
            let recovery_started = Instant::now();
            let fault_started = Instant::now();
            let fault = vm.run_expect_write_permission_fault();
            let one_fault_ns = fault_started.elapsed().as_nanos() as u64;
            assert_eq!(vm.get_reg(hv_reg_t::X1), written);
            assert_eq!(vm.get_reg(hv_reg_t::X20), DATA_VA);

            // Move maintenance onto the unaffected parent root before breaking
            // the child root edge. Executing TLBI through the invalidated child
            // root would make success depend on a stale instruction translation.
            let _maintenance_switch_ns = vm.set_ttbr(PARENT_L0_IPA, PARENT_ASID);
            assert_eq!(
                vm.get_sys(hv_sys_reg_t::TTBR0_EL1),
                ttbr(PARENT_L0_IPA, PARENT_ASID),
                "break-before-make maintenance did not use the parent root"
            );

            // Architecturally valid break-before-make: invalidate the live child
            // root edge and complete a scoped TLBI before publishing a descriptor
            // with a different output address. The parent root stays mapped.
            publish_descriptor(vm.frame(child_l0), root_index, 0);
            tlbi_ns.push(vm.scoped_tlbi(CHILD_ASID));

            vm.frame(private_frame).copy_from(vm.frame(shared_frame));
            let path_started = Instant::now();
            publish_live_table(vm.frame(child_l1), &parent.l1);
            publish_live_table(vm.frame(child_l2), &parent.l2);
            publish_live_table(vm.frame(child_l3), &parent.l3);
            let private_index = indices(DATA_VA);
            publish_descriptor(
                vm.frame(child_l1),
                private_index[1],
                table_descriptor(CHILD_TABLE_IPAS.l2),
            );
            publish_descriptor(
                vm.frame(child_l2),
                private_index[2],
                table_descriptor(CHILD_TABLE_IPAS.l3),
            );
            publish_compound_leaf(
                vm.frame(child_l3),
                DATA_VA,
                PRIVATE_DATA_IPA,
                USER_RW_DATA_PAGE,
            );
            publish_descriptor(vm.frame(child_l0), root_index, private_root_edge);
            let one_table_copy_ns = path_started.elapsed().as_nanos() as u64;
            tlbi_ns.push(vm.scoped_tlbi(CHILD_ASID));

            // Scoped maintenance uses only x0; the exact fault-time store
            // operands must survive without host reconstruction. Restore the
            // now-valid child root only after the make-side TLBI completes.
            assert_eq!(vm.get_reg(hv_reg_t::X1), written);
            assert_eq!(vm.get_reg(hv_reg_t::X20), DATA_VA);
            let _resume_switch_ns = vm.set_ttbr(CHILD_L0_IPA, CHILD_ASID);
            vm.enter_el0(fault.elr);
            let completion = vm.run_expect_svc();
            assert_eq!(
                completion.elr,
                WRITE_CODE_VA + 8,
                "resumed store did not advance exactly to the following SVC"
            );
            let one_recovery_ns = recovery_started.elapsed().as_nanos() as u64;

            let mut expected_private = shared_snapshot.clone();
            expected_private[..8].copy_from_slice(&written.to_le_bytes());
            assert_eq!(
                vm.frame(private_frame).snapshot(),
                expected_private,
                "COW private frame differs outside the exact guest store"
            );
            assert_eq!(
                vm.frame(shared_frame).snapshot(),
                shared_snapshot,
                "child COW write changed any byte of the shared parent frame"
            );
            let child_l3_snapshot = vm.frame(child_l3).snapshot();
            let child_leaf = read_descriptor(&child_l3_snapshot, data_index);
            assert_eq!(child_leaf & PA_MASK, PRIVATE_DATA_IPA);
            assert_eq!(child_leaf & AP_MASK, AP_RW_EL0);
            assert_ne!(child_leaf & NOT_GLOBAL, 0);

            asid_switch_ns.push(vm.set_ttbr(PARENT_L0_IPA, PARENT_ASID));
            vm.set_reg(hv_reg_t::X20, DATA_VA);
            vm.enter_el0(CODE_VA);
            vm.run_expect_svc();
            assert_eq!(
                vm.get_reg(hv_reg_t::X0),
                original,
                "parent root stopped seeing the original shared frame"
            );

            // Restore the child root to its fork-time shared-L1 state using the
            // same break-before-make discipline, ready for the next sample.
            publish_descriptor(vm.frame(child_l0), root_index, 0);
            tlbi_ns.push(vm.scoped_tlbi(CHILD_ASID));
            publish_descriptor(vm.frame(child_l0), root_index, shared_root_edge);
            tlbi_ns.push(vm.scoped_tlbi(CHILD_ASID));

            fault_ns.push(one_fault_ns);
            table_copy_ns.push(one_table_copy_ns);
            recovery_ns.push(one_recovery_ns);
            println!(
                "{{\"probe\":\"k0-cow-sample\",\"iteration\":{iteration},\"status\":\"PASS\",\"fault_ns\":{one_fault_ns},\"table_path_copy_ns\":{one_table_copy_ns},\"recovery_ns\":{one_recovery_ns},\"fault_esr\":\"{:#x}\",\"fault_va\":\"{:#x}\",\"compared_bytes\":{COMPOUND_FRAME_SIZE},\"copied_data_frames\":1,\"copied_table_frames\":3,\"cow_root_descriptor_updates\":2,\"reset_root_descriptor_updates\":2}}",
                fault.underlying_syndrome, fault.far,
            );
        }

        // The host-side source objects and every live parent table frame must
        // remain byte-identical after all child path copies.
        assert_eq!(parent.l0, parent_snapshot.l0);
        assert_eq!(parent.l1, parent_snapshot.l1);
        assert_eq!(parent.l2, parent_snapshot.l2);
        assert_eq!(parent.l3, parent_snapshot.l3);
        for (index, expected) in [
            (parent_l0, &parent_snapshot.l0),
            (parent_l1, &parent_snapshot.l1),
            (parent_l2, &parent_snapshot.l2),
            (parent_l3, &parent_snapshot.l3),
        ] {
            // SAFETY: frame is readable for one compound frame.
            let actual =
                unsafe { std::slice::from_raw_parts(vm.frame(index).ptr(), COMPOUND_FRAME_SIZE) };
            assert_eq!(
                actual,
                expected.as_slice(),
                "live parent table bytes changed"
            );
        }

        for (sample, elapsed_ns) in asid_switch_ns.iter().enumerate() {
            println!(
                "{{\"probe\":\"k0-latency\",\"operation\":\"asid-switch\",\"sample\":{sample},\"elapsed_ns\":{elapsed_ns}}}"
            );
        }
        for (sample, elapsed_ns) in tlbi_ns.iter().enumerate() {
            println!(
                "{{\"probe\":\"k0-latency\",\"operation\":\"asid-tlbi\",\"sample\":{sample},\"elapsed_ns\":{elapsed_ns}}}"
            );
        }
        print_summary("frame-map", &stage2.map_samples);
        print_summary("frame-unmap", &stage2.unmap_samples);
        print_summary("asid-switch", &asid_switch_ns);
        print_summary("asid-tlbi", &tlbi_ns);
        print_summary("cow-fault", &fault_ns);
        print_summary("table-path-copy", &table_copy_ns);
        print_summary("cow-recovery", &recovery_ns);

        assert_eq!(fault_ns.len(), COW_ITERATIONS);
        assert_eq!(table_copy_ns.len(), COW_ITERATIONS);
        assert_eq!(recovery_ns.len(), COW_ITERATIONS);
        assert_eq!(asid_switch_ns.len(), COW_ITERATIONS * 2);
        assert_eq!(tlbi_ns.len(), COW_ITERATIONS * 4);
        assert_eq!(stage2.map_samples.len(), MAP_THREADS * MAP_ITERATIONS);
        assert_eq!(stage2.unmap_samples.len(), MAP_THREADS * MAP_ITERATIONS);
        let stage2_samples = stage2.map_samples.len() + stage2.unmap_samples.len();
        vm.shutdown();
        // SAFETY: cancel the process-wide fail-closed watchdog after checked teardown.
        unsafe { libc::alarm(0) };
        println!(
            "{{\"probe\":\"k0-kernel-memory\",\"status\":\"GO\",\"vm_create_count\":1,\"vm_destroy_checked\":true,\"shared_frame_isolation\":true,\"compared_bytes_per_cow\":{COMPOUND_FRAME_SIZE},\"cow_recovery\":true,\"parent_byte_identity\":true,\"break_before_make\":true,\"scoped_asid_tlbi\":true,\"frame_hal_mode\":\"{}\",\"max_stage2_calls_in_flight\":{},\"concurrent_stage2_failures\":{},\"cow_samples\":{COW_ITERATIONS},\"asid_switch_samples\":{},\"asid_tlbi_samples\":{},\"stage2_samples\":{stage2_samples}}}",
            stage2.mode,
            stage2.max_in_flight,
            stage2.concurrent_failures,
            asid_switch_ns.len(),
            tlbi_ns.len(),
        );
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn main() {
    platform::run();
}

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
fn main() {
    eprintln!("hvf_kernel_memory_probe requires macOS arm64");
    std::process::exit(1);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scoped_tlbi_sequence_is_exact() {
        assert_eq!(
            [
                AARCH64_DSB_ISHST,
                AARCH64_TLBI_ASIDE1IS_X0,
                AARCH64_DSB_ISH,
                AARCH64_ISB,
                AARCH64_HVC1,
            ],
            [
                0xd503_3a9f,
                0xd508_8340,
                0xd503_3b9f,
                0xd503_3fdf,
                0xd400_0022
            ]
        );
        let frame = scoped_tlbi_frame();
        assert_eq!(&frame[4..8], &0xd508_8340_u32.to_le_bytes());
    }

    #[test]
    fn user_leaf_is_non_global_and_cow_source_is_read_only() {
        let parent = build_parent_tables();
        let leaf = read_descriptor(&parent.l3, indices(DATA_VA)[3]);
        assert_eq!(leaf & PA_MASK, SHARED_DATA_IPA);
        assert_ne!(leaf & VALID, 0);
        assert_ne!(leaf & NOT_GLOBAL, 0);
        assert_eq!(leaf & AP_MASK, AP_RO_EL0);
        assert_ne!(leaf & UXN, 0);
    }

    #[test]
    fn fork_root_shares_lower_tables_until_child_path_copy() {
        let parent = build_parent_tables();
        let mut child_root = build_child_root(&parent);
        let index = indices(DATA_VA);
        assert_eq!(
            read_descriptor(&child_root, index[0]) & PA_MASK,
            PARENT_TABLE_IPAS.l1
        );

        let mut child_l1 = vec![0; COMPOUND_FRAME_SIZE];
        let mut child_l2 = vec![0; COMPOUND_FRAME_SIZE];
        let mut child_l3 = vec![0; COMPOUND_FRAME_SIZE];
        copy_child_table_path(
            &parent,
            &mut child_root,
            &mut child_l1,
            &mut child_l2,
            &mut child_l3,
        );
        assert_eq!(
            read_descriptor(&child_root, index[0]) & PA_MASK,
            CHILD_TABLE_IPAS.l1
        );
        assert_eq!(
            read_descriptor(&child_l1, index[1]) & PA_MASK,
            CHILD_TABLE_IPAS.l2
        );
        assert_eq!(
            read_descriptor(&child_l2, index[2]) & PA_MASK,
            CHILD_TABLE_IPAS.l3
        );
        let child_leaf = read_descriptor(&child_l3, index[3]);
        assert_eq!(child_leaf & PA_MASK, PRIVATE_DATA_IPA);
        assert_eq!(child_leaf & AP_MASK, AP_RW_EL0);
        assert_ne!(child_leaf & NOT_GLOBAL, 0);

        let parent_leaf = read_descriptor(&parent.l3, index[3]);
        assert_eq!(parent_leaf & PA_MASK, SHARED_DATA_IPA);
        assert_eq!(parent_leaf & AP_MASK, AP_RO_EL0);
    }

    #[test]
    fn asid_lives_in_ttbr_high_half() {
        assert_eq!(ttbr(PARENT_L0_IPA, PARENT_ASID), 0x0041_0000_0200_0000);
        assert_eq!(ttbr(CHILD_L0_IPA, CHILD_ASID), 0x0042_0000_0201_0000);
    }

    #[test]
    fn read_and_write_routines_name_the_expected_registers() {
        let frame = code_frame();
        assert_eq!(&frame[..4], &AARCH64_LDR_X0_X20.to_le_bytes());
        assert_eq!(&frame[4..8], &AARCH64_SVC0.to_le_bytes());
        assert_eq!(&frame[0x100..0x104], &AARCH64_STR_X1_X20.to_le_bytes());
        assert_eq!(&frame[0x104..0x108], &AARCH64_SVC0.to_le_bytes());
    }
}
