//! KVM execution of the shared APIC fixture, only compiled in the required KVM lane.

use super::apic_fixture::*;
use carrick_softcpu_x86::LAPIC_DEFAULT_PHYS_BASE;
use std::fs::OpenOptions;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::{thread, time::Duration};

const KVM_CREATE_VM: libc::c_ulong = 0xae01;
const KVM_GET_VCPU_MMAP_SIZE: libc::c_ulong = 0xae04;
const KVM_CREATE_VCPU: libc::c_ulong = 0xae41;
const KVM_SET_USER_MEMORY_REGION: libc::c_ulong = 0x4020_ae46;
const KVM_SET_TSS_ADDR: libc::c_ulong = 0xae47;
const KVM_CREATE_IRQCHIP: libc::c_ulong = 0xae60;
const KVM_SET_MP_STATE: libc::c_ulong = 0x4004_ae99;
const KVM_RUN: libc::c_ulong = 0xae80;
const KVM_SET_REGS: libc::c_ulong = 0x4090_ae82;
const KVM_GET_SREGS: libc::c_ulong = 0x8138_ae83;
const KVM_SET_SREGS: libc::c_ulong = 0x4138_ae84;

const KVM_EXIT_IO: u32 = 2;
const KVM_EXIT_INTR: u32 = 10;

#[repr(C)]
#[derive(Default)]
struct KvmUserspaceMemoryRegion {
    slot: u32,
    flags: u32,
    guest_phys_addr: u64,
    memory_size: u64,
    userspace_addr: u64,
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct KvmRegs {
    rax: u64,
    rbx: u64,
    rcx: u64,
    rdx: u64,
    rsi: u64,
    rdi: u64,
    rsp: u64,
    rbp: u64,
    r8: u64,
    r9: u64,
    r10: u64,
    r11: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
    rip: u64,
    rflags: u64,
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct KvmSegment {
    base: u64,
    limit: u32,
    selector: u16,
    type_: u8,
    present: u8,
    dpl: u8,
    db: u8,
    s: u8,
    l: u8,
    g: u8,
    avl: u8,
    unusable: u8,
    padding: u8,
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct KvmDtable {
    base: u64,
    limit: u16,
    padding: [u16; 3],
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct KvmSregs {
    cs: KvmSegment,
    ds: KvmSegment,
    es: KvmSegment,
    fs: KvmSegment,
    gs: KvmSegment,
    ss: KvmSegment,
    tr: KvmSegment,
    ldt: KvmSegment,
    gdt: KvmDtable,
    idt: KvmDtable,
    cr0: u64,
    cr2: u64,
    cr3: u64,
    cr4: u64,
    cr8: u64,
    efer: u64,
    apic_base: u64,
    interrupt_bitmap: [u64; 4],
}

#[repr(C)]
struct KvmRunIo {
    direction: u8,
    size: u8,
    port: u16,
    count: u32,
    data_offset: u64,
}

pub(super) fn run_two_vcpu_fixture_on_kvm() -> TwoVcpuFixtureOutcome {
    let kvm_file = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/kvm")
        .expect("KVM parity requires accessible /dev/kvm");

    // SAFETY: standard KVM ioctls on fresh file descriptors.
    unsafe {
        let mmap_size = libc::ioctl(kvm_file.as_raw_fd(), KVM_GET_VCPU_MMAP_SIZE, 0);
        assert!(mmap_size >= 4096, "KVM_GET_VCPU_MMAP_SIZE failed");

        let vm_raw = libc::ioctl(kvm_file.as_raw_fd(), KVM_CREATE_VM, 0);
        assert!(vm_raw >= 0, "KVM_CREATE_VM failed");
        let vm_fd = OwnedFd::from_raw_fd(vm_raw);

        let _ = libc::ioctl(vm_fd.as_raw_fd(), KVM_SET_TSS_ADDR, 0xfffb_d000usize);
        assert_eq!(
            libc::ioctl(vm_fd.as_raw_fd(), KVM_CREATE_IRQCHIP, 0),
            0,
            "KVM_CREATE_IRQCHIP failed"
        );

        // Allocate page-aligned guest RAM via mmap so KVM_SET_USER_MEMORY_REGION accepts it.
        let ram_ptr = libc::mmap(
            std::ptr::null_mut(),
            TWO_VCPU_RAM_SIZE,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        );
        assert_ne!(ram_ptr, libc::MAP_FAILED, "mmap guest RAM failed");
        let initial_image = build_two_vcpu_guest_image();
        std::ptr::copy_nonoverlapping(
            initial_image.as_ptr(),
            ram_ptr.cast::<u8>(),
            TWO_VCPU_RAM_SIZE,
        );

        let region = KvmUserspaceMemoryRegion {
            slot: 0,
            flags: 0,
            guest_phys_addr: 0,
            memory_size: TWO_VCPU_RAM_SIZE as u64,
            userspace_addr: ram_ptr as u64,
        };
        assert_eq!(
            libc::ioctl(vm_fd.as_raw_fd(), KVM_SET_USER_MEMORY_REGION, &region),
            0,
            "KVM_SET_USER_MEMORY_REGION failed"
        );

        let vcpu0_raw = libc::ioctl(vm_fd.as_raw_fd(), KVM_CREATE_VCPU, 0usize);
        assert!(vcpu0_raw >= 0, "KVM_CREATE_VCPU(0) failed");
        let vcpu0_fd = OwnedFd::from_raw_fd(vcpu0_raw);

        let vcpu1_raw = libc::ioctl(vm_fd.as_raw_fd(), KVM_CREATE_VCPU, 1usize);
        assert!(vcpu1_raw >= 0, "KVM_CREATE_VCPU(1) failed");
        let vcpu1_fd = OwnedFd::from_raw_fd(vcpu1_raw);

        let setup_kvm_vcpu = |vcpu_fd: &OwnedFd, rip: u64, rsp: u64, idt_base: u64| {
            let mut sregs = KvmSregs::default();
            assert_eq!(
                libc::ioctl(vcpu_fd.as_raw_fd(), KVM_GET_SREGS, &mut sregs),
                0,
                "KVM_GET_SREGS failed"
            );
            sregs.cr0 = 0x8005_0033;
            sregs.cr3 = TWO_VCPU_PML4_GPA;
            sregs.cr4 = 0x0000_0020; // PAE
            sregs.efer = 0x0000_0d01; // SCE | LME | LMA | NXE
            sregs.cs = KvmSegment {
                base: 0,
                limit: 0xffff_ffff,
                selector: 0x08,
                type_: 11,
                present: 1,
                dpl: 0,
                db: 0,
                s: 1,
                l: 1,
                g: 1,
                avl: 0,
                unusable: 0,
                padding: 0,
            };
            let data_seg = KvmSegment {
                base: 0,
                limit: 0xffff_ffff,
                selector: 0x10,
                type_: 3,
                present: 1,
                dpl: 0,
                db: 1,
                s: 1,
                l: 0,
                g: 1,
                avl: 0,
                unusable: 0,
                padding: 0,
            };
            sregs.ss = data_seg;
            sregs.ds = data_seg;
            sregs.es = data_seg;
            sregs.gdt = KvmDtable {
                base: TWO_VCPU_GDT_GPA,
                limit: 23,
                padding: [0; 3],
            };
            sregs.idt = KvmDtable {
                base: idt_base,
                limit: 0x0fff,
                padding: [0; 3],
            };
            assert_eq!(
                libc::ioctl(vcpu_fd.as_raw_fd(), KVM_SET_SREGS, &sregs),
                0,
                "KVM_SET_SREGS failed"
            );

            let regs = KvmRegs {
                rip,
                rsp,
                rsi: LAPIC_DEFAULT_PHYS_BASE,
                rdi: TWO_VCPU_SHARED_GPA,
                rflags: 0x2,
                ..KvmRegs::default()
            };
            assert_eq!(
                libc::ioctl(vcpu_fd.as_raw_fd(), KVM_SET_REGS, &regs),
                0,
                "KVM_SET_REGS failed"
            );
            // This fixture enters both CPUs directly in long mode. In-kernel
            // irqchip creation otherwise leaves APs waiting for INIT/SIPI.
            let runnable: u32 = 0;
            assert_eq!(
                libc::ioctl(vcpu_fd.as_raw_fd(), KVM_SET_MP_STATE, &runnable),
                0,
                "KVM_SET_MP_STATE(RUNNABLE) failed"
            );
        };

        setup_kvm_vcpu(
            &vcpu0_fd,
            TWO_VCPU_BSP_CODE_GPA,
            TWO_VCPU_BSP_STACK_GPA + 0x800,
            TWO_VCPU_IDT0_GPA,
        );
        setup_kvm_vcpu(
            &vcpu1_fd,
            TWO_VCPU_AP_CODE_GPA,
            TWO_VCPU_AP_STACK_GPA + 0x800,
            TWO_VCPU_IDT1_GPA,
        );

        let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
        let run_kvm_vcpu = move |vcpu_fd: OwnedFd, mmap_len: usize| -> u32 {
            let run_ptr = libc::mmap(
                std::ptr::null_mut(),
                mmap_len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                vcpu_fd.as_raw_fd(),
                0,
            );
            assert_ne!(run_ptr, libc::MAP_FAILED, "mmap kvm_run failed");
            let port_val = loop {
                let rc = libc::ioctl(vcpu_fd.as_raw_fd(), KVM_RUN, 0);
                if rc < 0 {
                    let err = std::io::Error::last_os_error();
                    if err.raw_os_error() == Some(libc::EINTR)
                        || err.raw_os_error() == Some(libc::EAGAIN)
                    {
                        continue;
                    }
                    panic!("KVM_RUN failed: {err}");
                }
                let exit_reason = *(run_ptr.cast::<u8>().add(8).cast::<u32>());
                if exit_reason == KVM_EXIT_INTR {
                    continue;
                }
                assert_eq!(
                    exit_reason, KVM_EXIT_IO,
                    "expected KVM_EXIT_IO on exit port, got exit_reason={exit_reason}"
                );
                let io = &*(run_ptr.cast::<u8>().add(32).cast::<KvmRunIo>());
                if io.port == 0xf3 {
                    ready_tx.send(()).unwrap();
                    continue;
                }
                assert_eq!(io.port, EXIT_PORT);
                let val = *(run_ptr.cast::<u8>().add(io.data_offset as usize));
                break u32::from(val);
            };
            let _ = libc::munmap(run_ptr, mmap_len);
            port_val
        };

        let mmap_len = mmap_size as usize;
        let run_ap = run_kvm_vcpu.clone();
        let ap_thread = thread::spawn(move || run_ap(vcpu1_fd, mmap_len));
        ready_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("KVM AP enrollment");
        let bsp_thread = thread::spawn(move || run_kvm_vcpu(vcpu0_fd, mmap_len));

        let ap_port_val = ap_thread.join().expect("KVM AP thread join");
        let bsp_port_val = bsp_thread.join().expect("KVM BSP thread join");

        let ram_slice = std::slice::from_raw_parts(ram_ptr.cast::<u8>(), TWO_VCPU_RAM_SIZE);
        let outcome = decode_shared_outcome(ram_slice, bsp_port_val, ap_port_val);
        let _ = libc::munmap(ram_ptr, TWO_VCPU_RAM_SIZE);
        outcome
    }
}
