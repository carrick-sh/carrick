//! seccomp(2) ENFORCEMENT conformance: an installed filter must actually take
//! effect, matching Linux. Guards three carrick fixes that were all silent
//! (a guest's filter installed but did nothing / mis-fired):
//!
//!   * RET_KILL_PROCESS is enforced. `SECCOMP_RET_KILL_PROCESS` is 0x8000_0000 —
//!     the LARGEST action word — so the old "numerically-smallest action wins"
//!     compare never selected it, and every kill filter was ignored on all lanes.
//!   * The filter sees the guest's NATIVE arch (an x86_64 guest reported aarch64,
//!     so its own `arch != AUDIT_ARCH_X86_64 -> KILL` Docker/libseccomp prologue
//!     killed it on the first syscall).
//!   * The filter sees the guest's NATIVE syscall number (not carrick's canonical
//!     aarch64 number), so a number-keyed rule matches the right call.
//!
//! Each leg forks a child that installs a filter and makes a syscall; the PARENT
//! observes the child's wait status (SIGSYS-killed / exit code / errno), so the
//! probe process itself always survives and prints deterministic booleans.
//!
//! Stands in for the seccomp(2) enforcement LTP family (seccomp_bpf / seccomp01).
//!
//! Deterministic booleans, diffed line-exact carrick-vs-Linux.

use libc::{c_int, c_long};

// cBPF opcodes (libc does not expose the BPF_STMT/BPF_JUMP C macros).
const BPF_LD: u16 = 0x00;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_JMP: u16 = 0x05;
const BPF_JEQ: u16 = 0x10;
const BPF_RET: u16 = 0x06;
const BPF_K: u16 = 0x00;

const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;

// seccomp_data field byte offsets: nr@0, arch@4.
const OFF_NR: u32 = 0;
const OFF_ARCH: u32 = 4;

#[cfg(target_arch = "x86_64")]
const NATIVE_AUDIT_ARCH: u32 = 0xC000_003E; // AUDIT_ARCH_X86_64
#[cfg(target_arch = "aarch64")]
const NATIVE_AUDIT_ARCH: u32 = 0xC000_00B7; // AUDIT_ARCH_AARCH64

fn sf(code: u16, jt: u8, jf: u8, k: u32) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
}

/// Install `prog` as a seccomp filter on the calling thread. Returns 0 on success.
unsafe fn install(prog: &mut [libc::sock_filter]) -> c_int {
    if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
        return -1;
    }
    let fprog = libc::sock_fprog {
        len: prog.len() as u16,
        filter: prog.as_mut_ptr(),
    };
    libc::prctl(
        libc::PR_SET_SECCOMP,
        libc::SECCOMP_MODE_FILTER as c_long,
        &fprog as *const libc::sock_fprog as c_long,
        0,
        0,
    ) as c_int
}

/// Run `child` in a forked process and return its raw wait status.
unsafe fn in_child<F: FnOnce()>(child: F) -> c_int {
    let pid = libc::fork();
    if pid == 0 {
        child();
        libc::_exit(0);
    }
    let mut status: c_int = 0;
    libc::waitpid(pid, &mut status, 0);
    status
}

fn main() {
    unsafe {
        // 1. Unconditional RET_KILL_PROCESS -> the next syscall SIGSYS-kills.
        let st = in_child(|| {
            let mut f = [sf(BPF_RET | BPF_K, 0, 0, SECCOMP_RET_KILL_PROCESS)];
            if install(&mut f) != 0 {
                libc::_exit(42);
            }
            libc::syscall(libc::SYS_getpid); // dies here under real enforcement
            libc::_exit(0);
        });
        let killed = libc::WIFSIGNALED(st) && libc::WTERMSIG(st) == libc::SIGSYS;
        println!("kill_process_filter_kills_with_sigsys={killed}");

        // 2. Arch gate `arch != NATIVE -> KILL` must ALLOW (the guest's arch IS
        //    its native ISA), so the child survives and exits 7.
        let st = in_child(|| {
            let mut f = [
                sf(BPF_LD | BPF_W | BPF_ABS, 0, 0, OFF_ARCH),
                sf(BPF_JMP | BPF_JEQ | BPF_K, 1, 0, NATIVE_AUDIT_ARCH),
                sf(BPF_RET | BPF_K, 0, 0, SECCOMP_RET_KILL_PROCESS),
                sf(BPF_RET | BPF_K, 0, 0, SECCOMP_RET_ALLOW),
            ];
            if install(&mut f) != 0 {
                libc::_exit(42);
            }
            libc::syscall(libc::SYS_getpid);
            libc::_exit(7);
        });
        let arch_ok = libc::WIFEXITED(st) && libc::WEXITSTATUS(st) == 7;
        println!("arch_gate_allows_native_isa={arch_ok}");

        // 3. Native-number deny: deny getpid by its NATIVE number with EPERM; the
        //    child sees EPERM (exit 1), not a kill and not success.
        let st = in_child(|| {
            let nr = libc::SYS_getpid as u32;
            let mut f = [
                sf(BPF_LD | BPF_W | BPF_ABS, 0, 0, OFF_NR),
                sf(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, nr),
                sf(
                    BPF_RET | BPF_K,
                    0,
                    0,
                    SECCOMP_RET_ERRNO | (libc::EPERM as u32),
                ),
                sf(BPF_RET | BPF_K, 0, 0, SECCOMP_RET_ALLOW),
            ];
            if install(&mut f) != 0 {
                libc::_exit(42);
            }
            *libc::__errno_location() = 0;
            let r = libc::syscall(libc::SYS_getpid);
            let e = *libc::__errno_location();
            libc::_exit(if r == -1 && e == libc::EPERM { 1 } else { 0 });
        });
        let nr_deny_ok = libc::WIFEXITED(st) && libc::WEXITSTATUS(st) == 1;
        println!("native_number_deny_eperm={nr_deny_ok}");
    }
}
