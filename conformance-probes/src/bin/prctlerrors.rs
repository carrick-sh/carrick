//! `prctl(2)` error semantics for known sandbox/capability options.
//!
//! LTP prctl02 treats `EINVAL` from a valid form as "unsupported" and skips the
//! negative assertion. This probe keeps the supported valid forms and the
//! privilege-gated error paths line-exact against Linux.

use conformance_probes::{errno, report};

const PR_SET_SECCOMP: libc::c_int = 22;
const PR_CAPBSET_DROP: libc::c_int = 24;
const PR_SET_SECUREBITS: libc::c_int = 28;
const PR_SET_THP_DISABLE: libc::c_int = 41;
const PR_GET_THP_DISABLE: libc::c_int = 42;
const PR_CAP_AMBIENT: libc::c_int = 47;
const PR_GET_SPECULATION_CTRL: libc::c_int = 52;

const SECCOMP_MODE_FILTER: libc::c_ulong = 2;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const BPF_RET: u16 = 0x06;
const BPF_K: u16 = 0x00;

const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;
const CAP_CHOWN: libc::c_ulong = 0;
const CAP_SETPCAP: usize = 8;
const PR_CAP_AMBIENT_IS_SET: libc::c_ulong = 1;
const PR_SPEC_STORE_BYPASS: libc::c_ulong = 0;

#[repr(C)]
#[derive(Clone, Copy)]
struct CapHeader {
    version: u32,
    pid: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

fn prctl_errno(option: libc::c_int, arg2: libc::c_ulong, arg3: libc::c_ulong) -> Option<i32> {
    let rc = unsafe { libc::prctl(option, arg2, arg3, 0, 0) };
    (rc == -1).then(errno)
}

fn seccomp_without_nnp_is_eacces() -> bool {
    let mut filter = [libc::sock_filter {
        code: BPF_RET | BPF_K,
        jt: 0,
        jf: 0,
        k: SECCOMP_RET_ALLOW,
    }];
    let prog = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_mut_ptr(),
    };
    let rc = unsafe {
        libc::prctl(
            PR_SET_SECCOMP,
            SECCOMP_MODE_FILTER,
            &prog as *const libc::sock_fprog as libc::c_ulong,
            0,
            0,
        )
    };
    rc == -1 && errno() == libc::EACCES
}

fn drop_cap_setpcap() -> bool {
    let mut header = CapHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let mut data = [CapData {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; 2];
    let get_rc = unsafe {
        libc::syscall(
            libc::SYS_capget,
            &mut header as *mut CapHeader,
            data.as_mut_ptr(),
        )
    };
    if get_rc != 0 {
        return false;
    }
    let bit = !(1u32 << CAP_SETPCAP);
    data[0].effective &= bit;
    data[0].permitted &= bit;
    data[0].inheritable &= bit;
    let set_rc = unsafe {
        libc::syscall(
            libc::SYS_capset,
            &mut header as *mut CapHeader,
            data.as_mut_ptr(),
        )
    };
    set_rc == 0
}

fn main() {
    report!(thp_valid_forms_supported = unsafe {
        libc::prctl(PR_SET_THP_DISABLE, 0, 0, 0, 0) == 0
            && libc::prctl(PR_GET_THP_DISABLE, 0, 0, 0, 0) >= 0
    });
    report!(ambient_valid_form_supported = unsafe {
        libc::prctl(
            PR_CAP_AMBIENT,
            PR_CAP_AMBIENT_IS_SET,
            CAP_CHOWN,
            0,
            0,
        ) >= 0
    });
    report!(speculation_valid_form_supported = unsafe {
        libc::prctl(PR_GET_SPECULATION_CTRL, PR_SPEC_STORE_BYPASS, 0, 0, 0) >= 0
    });
    report!(thp_set_bad_arg_einval = prctl_errno(PR_SET_THP_DISABLE, 0, 1) == Some(libc::EINVAL));
    report!(thp_get_bad_arg_einval = prctl_errno(PR_GET_THP_DISABLE, 1, 0) == Some(libc::EINVAL));
    report!(ambient_bad_subcmd_einval = prctl_errno(PR_CAP_AMBIENT, 999, 0) == Some(libc::EINVAL));
    report!(speculation_extra_arg_einval =
        prctl_errno(PR_GET_SPECULATION_CTRL, PR_SPEC_STORE_BYPASS, 1) == Some(libc::EINVAL));
    report!(seccomp_filter_bad_pointer_efault =
        prctl_errno(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, 1) == Some(libc::EFAULT));
    report!(seccomp_filter_without_nnp_eacces = seccomp_without_nnp_is_eacces());

    let dropped = drop_cap_setpcap();
    report!(securebits_without_setpcap_eperm =
        dropped && prctl_errno(PR_SET_SECUREBITS, 0, 0) == Some(libc::EPERM));
    report!(capbset_drop_without_setpcap_eperm =
        dropped && prctl_errno(PR_CAPBSET_DROP, CAP_CHOWN, 0) == Some(libc::EPERM));
}
