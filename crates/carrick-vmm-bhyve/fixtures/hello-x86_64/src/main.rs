//! M2 fixture: a minimal std hello-world. Cross-compiled to
//! x86_64-unknown-linux-musl (static, non-PIE ET_EXEC) by build.sh. Running it
//! under carrick on bhyve exercises real musl libc startup (the M2 point):
//! arch_prctl(SET_FS), set_tid_address, brk/mmap, then write + exit_group.
fn main() {
    // A fixed, single-line message → a small, deterministic oracle (oracle.expected).
    print!("hello, x86_64 world\n");
}
