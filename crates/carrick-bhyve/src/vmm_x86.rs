//! amd64 vmmapi model: x86 `vm_exit`/`vm_inout`, the amd64 register/exitcode
//! enums, and the raw-register/descriptor/capability wrappers the x86 backend
//! uses instead of the aarch64-named `HvVcpu` surface.
//!
//! Every constant and layout here is transcribed from the TARGET BOX's headers
//! (FreeBSD 15.1-RC3 amd64, root@<lab-ip>): `/usr/include/machine/vmm.h`
//! and `/usr/include/vmmapi.h` — cited by line number — and cross-checked by a
//! compiled-on-box C probe (sizeof/offsetof/bitfield packing, 2026-06-12).
//! FreeBSD headers are the *host* API and explicitly allowed (clean-room
//! policy covers the Linux guest ABI only).

use std::ffi::{c_int, c_uint, c_void};

use carrick_hal::OsError;

use crate::vmm::{
    BhyveVcpu, VmRun, os_err, vm_get_desc, vm_get_register, vm_get_register_set,
    vm_restart_instruction, vm_run, vm_set_capability, vm_set_desc, vm_set_register,
    vm_setup_freebsd_registers,
};

// amd64 `enum vm_reg_name` (machine/vmm.h:56-107; values are the plain enum
// ordinals, confirmed by a compiled-on-box probe). The full enum also carries
// DR7=18, PDPTE0..3=34..37, INTR_SHADOW=38, DR0..DR3=39..42, DR6=43,
// ENTRY_INST_LENGTH=44, TPR=48 — transcribe those if a consumer appears.
pub const VM_REG_GUEST_RAX: c_int = 0; // vmm.h:57
pub const VM_REG_GUEST_RBX: c_int = 1; // vmm.h:58
pub const VM_REG_GUEST_RCX: c_int = 2; // vmm.h:59
pub const VM_REG_GUEST_RDX: c_int = 3; // vmm.h:60
pub const VM_REG_GUEST_RSI: c_int = 4; // vmm.h:61
pub const VM_REG_GUEST_RDI: c_int = 5; // vmm.h:62
pub const VM_REG_GUEST_RBP: c_int = 6; // vmm.h:63
pub const VM_REG_GUEST_R8: c_int = 7; // vmm.h:64
pub const VM_REG_GUEST_R9: c_int = 8; // vmm.h:65
pub const VM_REG_GUEST_R10: c_int = 9; // vmm.h:66
pub const VM_REG_GUEST_R11: c_int = 10; // vmm.h:67
pub const VM_REG_GUEST_R12: c_int = 11; // vmm.h:68
pub const VM_REG_GUEST_R13: c_int = 12; // vmm.h:69
pub const VM_REG_GUEST_R14: c_int = 13; // vmm.h:70
pub const VM_REG_GUEST_R15: c_int = 14; // vmm.h:71
pub const VM_REG_GUEST_CR0: c_int = 15; // vmm.h:72
pub const VM_REG_GUEST_CR3: c_int = 16; // vmm.h:73
pub const VM_REG_GUEST_CR4: c_int = 17; // vmm.h:74
pub const VM_REG_GUEST_RSP: c_int = 19; // vmm.h:76 (DR7=18 sits between)
pub const VM_REG_GUEST_RIP: c_int = 20; // vmm.h:77
pub const VM_REG_GUEST_RFLAGS: c_int = 21; // vmm.h:78
pub const VM_REG_GUEST_ES: c_int = 22; // vmm.h:79
pub const VM_REG_GUEST_CS: c_int = 23; // vmm.h:80
pub const VM_REG_GUEST_SS: c_int = 24; // vmm.h:81
pub const VM_REG_GUEST_DS: c_int = 25; // vmm.h:82
pub const VM_REG_GUEST_FS: c_int = 26; // vmm.h:83
pub const VM_REG_GUEST_GS: c_int = 27; // vmm.h:84
pub const VM_REG_GUEST_LDTR: c_int = 28; // vmm.h:85
pub const VM_REG_GUEST_TR: c_int = 29; // vmm.h:86
pub const VM_REG_GUEST_IDTR: c_int = 30; // vmm.h:87
pub const VM_REG_GUEST_GDTR: c_int = 31; // vmm.h:88
pub const VM_REG_GUEST_EFER: c_int = 32; // vmm.h:89
pub const VM_REG_GUEST_CR2: c_int = 33; // vmm.h:90
pub const VM_REG_GUEST_FS_BASE: c_int = 45; // vmm.h:102
pub const VM_REG_GUEST_GS_BASE: c_int = 46; // vmm.h:103
pub const VM_REG_GUEST_KGS_BASE: c_int = 47; // vmm.h:104
pub const VM_REG_LAST: c_int = 49; // vmm.h:106 (TPR=48 precedes it)

// SYSCALL MSR slots: searched the box's machine/vmm.h, machine/vmm_dev.h, and
// vmmapi.h for LSTAR/STAR/SFMASK/SEPC — `enum vm_reg_name` has NO slots for
// them (the enum ends at TPR=48/VM_REG_LAST=49; EFER is the only MSR-backed
// register exposed, vmm.h:89). The MSR *numbers* exist in x86/specialreg.h
// (MSR_STAR=0xc0000081 :1232, MSR_LSTAR=0xc0000082 :1233,
// MSR_SF_MASK=0xc0000084 :1235), so programming LSTAR/STAR/SFMASK must go
// through bhyve's MSR path, not vm_set_register — resolves the first half of
// spec open question 2 (the T6 bring-up owns picking the ioctl/FFI route).

// amd64 `enum vm_exitcode` (machine/vmm.h:508-536; plain ordinals, confirmed
// by the on-box probe).
pub const VM_EXITCODE_INOUT: c_int = 0; // vmm.h:509
pub const VM_EXITCODE_VMX: c_int = 1; // vmm.h:510
pub const VM_EXITCODE_BOGUS: c_int = 2; // vmm.h:511
pub const VM_EXITCODE_RDMSR: c_int = 3; // vmm.h:512
pub const VM_EXITCODE_WRMSR: c_int = 4; // vmm.h:513
pub const VM_EXITCODE_HLT: c_int = 5; // vmm.h:514
pub const VM_EXITCODE_MTRAP: c_int = 6; // vmm.h:515
pub const VM_EXITCODE_PAUSE: c_int = 7; // vmm.h:516
pub const VM_EXITCODE_PAGING: c_int = 8; // vmm.h:517
pub const VM_EXITCODE_INST_EMUL: c_int = 9; // vmm.h:518
pub const VM_EXITCODE_SPINUP_AP: c_int = 10; // vmm.h:519
pub const VM_EXITCODE_DEPRECATED1: c_int = 11; // vmm.h:520 (was SPINDOWN_CPU)
pub const VM_EXITCODE_RENDEZVOUS: c_int = 12; // vmm.h:521
pub const VM_EXITCODE_IOAPIC_EOI: c_int = 13; // vmm.h:522
pub const VM_EXITCODE_SUSPENDED: c_int = 14; // vmm.h:523
pub const VM_EXITCODE_INOUT_STR: c_int = 15; // vmm.h:524
pub const VM_EXITCODE_TASK_SWITCH: c_int = 16; // vmm.h:525
pub const VM_EXITCODE_MONITOR: c_int = 17; // vmm.h:526
pub const VM_EXITCODE_MWAIT: c_int = 18; // vmm.h:527
pub const VM_EXITCODE_SVM: c_int = 19; // vmm.h:528
pub const VM_EXITCODE_REQIDLE: c_int = 20; // vmm.h:529
pub const VM_EXITCODE_DEBUG: c_int = 21; // vmm.h:530
pub const VM_EXITCODE_VMINSN: c_int = 22; // vmm.h:531
pub const VM_EXITCODE_BPT: c_int = 23; // vmm.h:532
pub const VM_EXITCODE_IPI: c_int = 24; // vmm.h:533
pub const VM_EXITCODE_DB: c_int = 25; // vmm.h:534
pub const VM_EXITCODE_MAX: c_int = 26; // vmm.h:535

/// `enum vm_cap_type` (machine/vmm.h:374-387): `VM_CAP_HALT_EXIT` is the
/// first ordinal. (Others — MTRAP_EXIT=1, PAUSE_EXIT=2, UNRESTRICTED_GUEST=3,
/// … BPT_EXIT=5 — transcribe when consumed.)
pub const VM_CAP_HALT_EXIT: c_int = 0; // vmm.h:375

// `enum vm_suspend_how` (machine/vmm.h:43-51): the payload of a SUSPENDED
// exit (`u.suspended.how`, vmm.h:647-649).
pub const VM_SUSPEND_NONE: c_int = 0; // vmm.h:44
pub const VM_SUSPEND_RESET: c_int = 1; // vmm.h:45
pub const VM_SUSPEND_POWEROFF: c_int = 2; // vmm.h:46
pub const VM_SUSPEND_HALT: c_int = 3; // vmm.h:47
pub const VM_SUSPEND_TRIPLEFAULT: c_int = 4; // vmm.h:48
pub const VM_SUSPEND_DESTROY: c_int = 5; // vmm.h:49

/// `struct vm_inout` (machine/vmm.h:538-545):
/// `{ uint16_t bytes:3, in:1, string:1, rep:1; uint16_t port; uint32_t eax; }`
/// — 8 bytes. The C bitfields share one `uint16_t`, modeled here as a plain
/// `flags` word with accessors; the bit positions (bytes=bits 0..2, in=bit 3,
/// string=bit 4, rep=bit 5) were verified by a compiled-on-box probe
/// (clang amd64 allocates bitfields LSB-first).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct VmInout {
    pub flags: u16,
    pub port: u16,
    /// Valid for OUT (vmm.h:544).
    pub eax: u32,
}

impl VmInout {
    /// Access width in bytes: 1, 2, or 4 (vmm.h:539 `bytes:3`).
    pub fn width(&self) -> u8 {
        (self.flags & 0x7) as u8
    }
    /// Direction: IN (guest reads the port) when set (vmm.h:540 `in:1`).
    pub fn is_in(&self) -> bool {
        self.flags & 0x8 != 0
    }
    /// String variant `ins`/`outs` (vmm.h:541 `string:1`).
    pub fn is_string(&self) -> bool {
        self.flags & 0x10 != 0
    }
    /// REP-prefixed (vmm.h:542 `rep:1`).
    pub fn is_rep(&self) -> bool {
        self.flags & 0x20 != 0
    }
}

/// The `paging` arm of the `vm_exit` union (machine/vmm.h:584-587):
/// `{ uint64_t gpa; int fault_type; }`.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct VmExitPaging {
    pub gpa: u64,
    pub fault_type: c_int,
}

/// The `suspended` arm (machine/vmm.h:647-649): `{ enum vm_suspend_how how; }`.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct VmExitSuspended {
    pub how: c_int,
}

/// amd64 `struct vm_exit`'s union (machine/vmm.h:581-660). The largest arm is
/// `inst_emul` (gpa+gla+cs_base+cs_d+vm_guest_paging+64-byte `struct vie`);
/// on-box probe: the whole union is 120 bytes (15 u64 words) and 8-aligned, so
/// `_pad` pins both size and alignment. carrick decodes only the arms below;
/// `inst_emul`/`vmx`/`svm`/`msr`/… are read as raw exit codes (fatal paths).
#[repr(C)]
pub union VmExitUnion {
    pub inout: VmInout,
    pub paging: VmExitPaging,
    pub suspended: VmExitSuspended,
    pub _pad: [u64; 15],
}

/// amd64 `struct vm_exit` (machine/vmm.h:577-661): `{ enum vm_exitcode
/// exitcode; int inst_length; uint64_t rip; union { … } u; }`. On-box probe:
/// sizeof 136; exitcode@0, inst_length@4 ("0 means unknown", vmm.h:579),
/// rip@8, u@16.
#[repr(C)]
pub struct VmExit {
    pub exitcode: c_int,
    pub inst_length: c_int,
    pub rip: u64,
    pub u: VmExitUnion,
}

/// Typed decode of the amd64 exits the Phase 2 backend handles. Everything
/// not listed surfaces as `Other` and the caller fails loudly with the code
/// (spec §8: a libc `rdmsr` surprise must be a 5-minute triage, never a
/// silent resume).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X86Exit {
    /// `VM_EXITCODE_INOUT` on the syscall-doorbell `OUT`. The vCPU is parked
    /// ON the instruction; the resume discipline (RIP advance vs auto) is
    /// resolved empirically at M0 (plan T3) and owned by the caller.
    Inout {
        port: u16,
        bytes: u8,
        is_in: bool,
        inst_length: u8,
        rip: u64,
    },
    /// `VM_EXITCODE_HLT` (requires `VM_CAP_HALT_EXIT`).
    Hlt,
    /// `VM_EXITCODE_BOGUS` / `VM_EXITCODE_REQIDLE`: spurious, re-run (the KVM
    /// `Kicked` analogue).
    Bogus,
    /// `VM_EXITCODE_PAGING`: nested-page fault the host must resolve or treat
    /// as a fatal guest fault (Phase 2: fatal with a page-walk dump).
    Paging { gpa: u64, fault_type: i32, rip: u64 },
    /// `VM_EXITCODE_SUSPENDED`; `how` is `enum vm_suspend_how`
    /// (`VM_SUSPEND_TRIPLEFAULT` = the empty-IDT fatal-fault funnel).
    Suspended { how: i32 },
    /// Any other exitcode, surfaced raw for loud failure.
    Other { code: i32, rip: u64 },
}

impl BhyveVcpu {
    /// Run the vCPU and decode the amd64 exit (the x86 sibling of the aarch64
    /// `HvVcpu::run`).
    pub fn run_x86(&mut self) -> Result<X86Exit, OsError> {
        // SAFETY: VmExit is repr(C) plain-old-data (ints + a POD union);
        // the all-zero bit pattern is a valid value for every field.
        let mut exit: VmExit = unsafe { std::mem::zeroed() };
        let mut run = VmRun {
            cpuid: 0,
            cpuset: std::ptr::null_mut(),
            cpusetsize: 0,
            vm_exit: std::ptr::from_mut(&mut exit).cast::<c_void>(),
        };
        // SAFETY: `self.vcpu` is live; `run`/`exit` outlive the call.
        let rc = unsafe { vm_run(self.vcpu, &mut run) };
        if rc != 0 {
            return Err(os_err("vm_run", rc));
        }
        Ok(match exit.exitcode {
            VM_EXITCODE_INOUT => {
                // SAFETY: the INOUT exitcode selects the `inout` union arm
                // (machine/vmm.h:582).
                let io = unsafe { exit.u.inout };
                X86Exit::Inout {
                    port: io.port,
                    bytes: io.width(),
                    is_in: io.is_in(),
                    inst_length: exit.inst_length as u8,
                    rip: exit.rip,
                }
            }
            VM_EXITCODE_HLT => X86Exit::Hlt,
            VM_EXITCODE_BOGUS | VM_EXITCODE_REQIDLE => X86Exit::Bogus,
            VM_EXITCODE_PAGING => {
                // SAFETY: the PAGING exitcode selects the `paging` union arm
                // (machine/vmm.h:584-587).
                let pg = unsafe { exit.u.paging };
                X86Exit::Paging {
                    gpa: pg.gpa,
                    fault_type: pg.fault_type,
                    rip: exit.rip,
                }
            }
            VM_EXITCODE_SUSPENDED => {
                // SAFETY: the SUSPENDED exitcode selects the `suspended` union
                // arm (machine/vmm.h:647-649).
                let s = unsafe { exit.u.suspended };
                X86Exit::Suspended { how: s.how }
            }
            other => X86Exit::Other {
                code: other,
                rip: exit.rip,
            },
        })
    }

    /// Read one register by raw amd64 `vm_reg_name` ordinal.
    pub fn get_reg_raw(&self, id: c_int) -> Result<u64, OsError> {
        let mut val = 0u64;
        // SAFETY: `self.vcpu` is live; `val` is a valid out-pointer.
        let rc = unsafe { vm_get_register(self.vcpu, id, &mut val) };
        if rc != 0 {
            return Err(os_err("vm_get_register", rc));
        }
        Ok(val)
    }

    /// Write one register by raw amd64 `vm_reg_name` ordinal.
    pub fn set_reg_raw(&mut self, id: c_int, val: u64) -> Result<(), OsError> {
        // SAFETY: `self.vcpu` is live.
        let rc = unsafe { vm_set_register(self.vcpu, id, val) };
        if rc != 0 {
            return Err(os_err("vm_set_register", rc));
        }
        Ok(())
    }

    /// Batched register read (vmmapi.h:158): one ioctl for the whole syscall
    /// frame instead of seven `vm_get_register` round-trips.
    pub fn get_register_set(&self, ids: &[c_int]) -> Result<Vec<u64>, OsError> {
        let mut vals = vec![0u64; ids.len()];
        // SAFETY: `self.vcpu` is live; `ids`/`vals` are `count` elements each.
        let rc = unsafe {
            vm_get_register_set(
                self.vcpu,
                ids.len() as c_uint,
                ids.as_ptr(),
                vals.as_mut_ptr(),
            )
        };
        if rc != 0 {
            return Err(os_err("vm_get_register_set", rc));
        }
        Ok(vals)
    }

    /// Program a segment descriptor's hidden state (vmmapi.h:148): `reg` is a
    /// `VM_REG_GUEST_{ES..GS,LDTR,TR,IDTR,GDTR}` ordinal; `access` uses the
    /// Intel SDM vol. 3 Table 21-2 format (machine/vmm.h:394-405 note).
    pub fn set_desc(
        &mut self,
        reg: c_int,
        base: u64,
        limit: u32,
        access: u32,
    ) -> Result<(), OsError> {
        // SAFETY: `self.vcpu` is live.
        let rc = unsafe { vm_set_desc(self.vcpu, reg, base, limit, access) };
        if rc != 0 {
            return Err(os_err("vm_set_desc", rc));
        }
        Ok(())
    }

    /// Read back a segment descriptor as `(base, limit, access)` (vmmapi.h:150).
    pub fn get_desc(&self, reg: c_int) -> Result<(u64, u32, u32), OsError> {
        let (mut base, mut limit, mut access) = (0u64, 0u32, 0u32);
        // SAFETY: `self.vcpu` is live; the three out-pointers are valid.
        let rc = unsafe { vm_get_desc(self.vcpu, reg, &mut base, &mut limit, &mut access) };
        if rc != 0 {
            return Err(os_err("vm_get_desc", rc));
        }
        Ok((base, limit, access))
    }

    /// Enable/disable a `vm_cap_type` capability (vmmapi.h:201), e.g.
    /// `VM_CAP_HALT_EXIT`.
    pub fn set_capability(&mut self, cap: c_int, val: c_int) -> Result<(), OsError> {
        // SAFETY: `self.vcpu` is live.
        let rc = unsafe { vm_set_capability(self.vcpu, cap, val) };
        if rc != 0 {
            return Err(os_err("vm_set_capability", rc));
        }
        Ok(())
    }

    /// `vm_restart_instruction` (vmmapi.h:268): arrange for the current
    /// instruction to be restarted on the next `vm_run` (the existence of this
    /// API implies completed instructions are NOT auto-restarted; the M0
    /// doorbell experiment pins the resume discipline).
    pub fn restart_instruction(&mut self) -> Result<(), OsError> {
        // SAFETY: `self.vcpu` is live.
        let rc = unsafe { vm_restart_instruction(self.vcpu) };
        if rc != 0 {
            return Err(os_err("vm_restart_instruction", rc));
        }
        Ok(())
    }

    /// `vm_setup_freebsd_registers` (vmmapi.h:279-281, "FreeBSD specific
    /// APIs"): the bhyveload-proven one-call long-mode ring-0 entry
    /// (CR0/CR4/EFER/CS/SS/GDTR + RIP/CR3/RSP). M0 uses it; carrick-owned
    /// programming replaces it from M1 (ring 3 + SYSCALL MSRs need more).
    pub fn setup_freebsd_registers(
        &mut self,
        rip: u64,
        cr3: u64,
        gdtbase: u64,
        rsp: u64,
    ) -> Result<(), OsError> {
        // SAFETY: `self.vcpu` is live.
        let rc = unsafe { vm_setup_freebsd_registers(self.vcpu, rip, cr3, gdtbase, rsp) };
        if rc != 0 {
            return Err(os_err("vm_setup_freebsd_registers", rc));
        }
        Ok(())
    }
}

#[cfg(all(test, target_arch = "x86_64"))]
mod tests {
    use super::*;
    use std::mem::{offset_of, size_of};

    /// `struct vm_inout` (machine/vmm.h:538-545):
    /// `{ uint16_t bytes:3, in:1, string:1, rep:1; uint16_t port; uint32_t eax; }`
    /// — 8 bytes total. Bitfield packing verified by a compiled-on-box probe:
    /// bytes = bits 0..2, in = bit 3, string = bit 4, rep = bit 5
    /// (clang amd64 packs LSB-first; e.g. bytes=5,in=1,rep=1 → flags 0x002D).
    #[test]
    fn vm_inout_layout_matches_header() {
        assert_eq!(size_of::<VmInout>(), 8);
        // Hand-packed against the on-box probe: bytes=5, in=1, string=0, rep=1
        // packs to flags_word 0x002D with port/eax untouched.
        let io = VmInout {
            flags: 0x002D,
            port: 0x00C5,
            eax: 0xDEAD_BEEF,
        };
        assert_eq!(io.width(), 5);
        assert!(io.is_in());
        assert!(!io.is_string());
        assert!(io.is_rep());
        assert_eq!(io.port, 0xC5);
        assert_eq!(io.eax, 0xDEAD_BEEF);
        // Each flag bit in isolation (probe-verified packed values).
        let just = |flags: u16| VmInout {
            flags,
            port: 0,
            eax: 0,
        };
        assert_eq!(just(0x0001).width(), 1); // bytes=1 -> flags 0x0001
        assert!(just(0x0008).is_in()); // in=1 -> flags 0x0008
        assert!(just(0x0010).is_string()); // string=1 -> flags 0x0010
        assert!(just(0x0020).is_rep()); // rep=1 -> flags 0x0020
        assert!(!just(0x0007).is_in()); // width bits never bleed into `in`
    }

    /// amd64 `enum vm_exitcode` (machine/vmm.h:508-536), every value pinned
    /// (values confirmed by the on-box probe).
    #[test]
    fn exitcode_constants_match_header() {
        assert_eq!(VM_EXITCODE_INOUT, 0);
        assert_eq!(VM_EXITCODE_VMX, 1);
        assert_eq!(VM_EXITCODE_BOGUS, 2);
        assert_eq!(VM_EXITCODE_RDMSR, 3);
        assert_eq!(VM_EXITCODE_WRMSR, 4);
        assert_eq!(VM_EXITCODE_HLT, 5);
        assert_eq!(VM_EXITCODE_MTRAP, 6);
        assert_eq!(VM_EXITCODE_PAUSE, 7);
        assert_eq!(VM_EXITCODE_PAGING, 8);
        assert_eq!(VM_EXITCODE_INST_EMUL, 9);
        assert_eq!(VM_EXITCODE_SPINUP_AP, 10);
        assert_eq!(VM_EXITCODE_DEPRECATED1, 11);
        assert_eq!(VM_EXITCODE_RENDEZVOUS, 12);
        assert_eq!(VM_EXITCODE_IOAPIC_EOI, 13);
        assert_eq!(VM_EXITCODE_SUSPENDED, 14);
        assert_eq!(VM_EXITCODE_INOUT_STR, 15);
        assert_eq!(VM_EXITCODE_TASK_SWITCH, 16);
        assert_eq!(VM_EXITCODE_MONITOR, 17);
        assert_eq!(VM_EXITCODE_MWAIT, 18);
        assert_eq!(VM_EXITCODE_SVM, 19);
        assert_eq!(VM_EXITCODE_REQIDLE, 20);
        assert_eq!(VM_EXITCODE_DEBUG, 21);
        assert_eq!(VM_EXITCODE_VMINSN, 22);
        assert_eq!(VM_EXITCODE_BPT, 23);
        assert_eq!(VM_EXITCODE_IPI, 24);
        assert_eq!(VM_EXITCODE_DB, 25);
        assert_eq!(VM_EXITCODE_MAX, 26);
    }

    /// amd64 `struct vm_exit` (machine/vmm.h:577-661): common prefix
    /// `{ enum vm_exitcode; int inst_length; uint64_t rip; }` then the arch
    /// union. On-box probe: sizeof 136, exitcode@0, inst_length@4, rip@8,
    /// u@16, union 120 bytes (dominated by the `inst_emul` arm's
    /// 64-byte `struct vie`).
    #[test]
    fn vm_exit_layout_matches_header() {
        assert_eq!(size_of::<VmExit>(), 136);
        assert_eq!(offset_of!(VmExit, exitcode), 0);
        assert_eq!(offset_of!(VmExit, inst_length), 4);
        assert_eq!(offset_of!(VmExit, rip), 8);
        assert_eq!(offset_of!(VmExit, u), 16);
        assert_eq!(size_of::<VmExitUnion>(), 120);
        assert_eq!(size_of::<VmExitPaging>(), 16);
    }

    /// amd64 `enum vm_reg_name` (machine/vmm.h:56-107), values confirmed by
    /// the on-box probe (RAX=0 .. TPR=48, VM_REG_LAST=49).
    #[test]
    fn reg_name_constants_match_header() {
        assert_eq!(VM_REG_GUEST_RAX, 0);
        assert_eq!(VM_REG_GUEST_RBX, 1);
        assert_eq!(VM_REG_GUEST_RCX, 2);
        assert_eq!(VM_REG_GUEST_RDX, 3);
        assert_eq!(VM_REG_GUEST_RSI, 4);
        assert_eq!(VM_REG_GUEST_RDI, 5);
        assert_eq!(VM_REG_GUEST_RBP, 6);
        assert_eq!(VM_REG_GUEST_R8, 7);
        assert_eq!(VM_REG_GUEST_R9, 8);
        assert_eq!(VM_REG_GUEST_R10, 9);
        assert_eq!(VM_REG_GUEST_R11, 10);
        assert_eq!(VM_REG_GUEST_R12, 11);
        assert_eq!(VM_REG_GUEST_R13, 12);
        assert_eq!(VM_REG_GUEST_R14, 13);
        assert_eq!(VM_REG_GUEST_R15, 14);
        assert_eq!(VM_REG_GUEST_CR0, 15);
        assert_eq!(VM_REG_GUEST_CR3, 16);
        assert_eq!(VM_REG_GUEST_CR4, 17);
        assert_eq!(VM_REG_GUEST_RSP, 19);
        assert_eq!(VM_REG_GUEST_RIP, 20);
        assert_eq!(VM_REG_GUEST_RFLAGS, 21);
        assert_eq!(VM_REG_GUEST_ES, 22);
        assert_eq!(VM_REG_GUEST_CS, 23);
        assert_eq!(VM_REG_GUEST_SS, 24);
        assert_eq!(VM_REG_GUEST_DS, 25);
        assert_eq!(VM_REG_GUEST_FS, 26);
        assert_eq!(VM_REG_GUEST_GS, 27);
        assert_eq!(VM_REG_GUEST_LDTR, 28);
        assert_eq!(VM_REG_GUEST_TR, 29);
        assert_eq!(VM_REG_GUEST_IDTR, 30);
        assert_eq!(VM_REG_GUEST_GDTR, 31);
        assert_eq!(VM_REG_GUEST_EFER, 32);
        assert_eq!(VM_REG_GUEST_CR2, 33);
        assert_eq!(VM_REG_GUEST_FS_BASE, 45);
        assert_eq!(VM_REG_GUEST_GS_BASE, 46);
        assert_eq!(VM_REG_GUEST_KGS_BASE, 47);
        assert_eq!(VM_REG_LAST, 49);
    }

    /// `enum vm_cap_type` (machine/vmm.h:374-387) and `enum vm_suspend_how`
    /// (machine/vmm.h:43-51) values the backend consumes.
    #[test]
    fn cap_and_suspend_constants_match_header() {
        assert_eq!(VM_CAP_HALT_EXIT, 0);
        assert_eq!(VM_SUSPEND_HALT, 3);
        assert_eq!(VM_SUSPEND_TRIPLEFAULT, 4);
    }
}
