# x86 KVM: a static glibc binary dies with SIGSEGV at exit (pc 0xd7)

Found while working on #2217 (main 70a498456, release build, real KVM).

**What happens.** Any static glibc (Debian 13, glibc 2.41) x86_64 program
run under `carrick run` on x86 KVM exits 139. `int main(){exit(0);}` built
with `gcc -static` is enough; `puts("hi")` loses its output because the
crash comes before stdio's exit flush. The same binaries exit 0 natively,
and the same programs built dynamically exit 0 under carrick.

**Guest fault** (read from the CPU binding's fault frame with a temporary,
unshipped host dump): instruction fetch (#PF error 0x14) at pc 0xd7,
rsp 0x7ffefb58, rax 0xd7, r11 0x202 (just after a syscall return),
r13 0x4a4100, r14 0x4a63c8, r15 0x4a63e0. So the exit path made an
indirect call through rax = 0xd7: a function pointer glibc read during
exit handlers (`__run_exit_handlers`, `__call_tls_dtors`, `_IO_cleanup`)
holds 0xd7. Not root-caused; candidates are a wrong TLS/fs-relative read
or a mangled pointer read back wrong after a syscall.

**Repro.**
```
printf '#include <stdlib.h>\nint main(void){exit(0);}\n' > ex.c
gcc -static -O1 -o exit_static ex.c
CARRICK_RUN_ID=s1 carrick run --rm -v $PWD:/fx python:3.12-slim /fx/exit_static; echo $?   # 139
```

**Acceptance.** Root cause with the faulting instruction's source, a
red-first static-glibc KVM witness, and exit 0.
