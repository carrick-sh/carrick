# exec-target-exit0 — freestanding KVM execve(2) target

A minimal, libc-free aarch64 Linux ELF that is the `execve` TARGET for the
`../fork-execve-true` driver (Phase 2, Task 4). After `KvmTrapEngine::execve_into`
replaces the guest image in place (slot remap + sysreg reprogram, no VM
teardown), the replaced child resumes at this image's `_start` and issues a
single `exit_group(0)` — nothing else.

The smoke script (`scripts/kvm-smoke-lima.sh`) stages this binary at
`/tmp/carrick-exec-target-true`, the absolute path baked into the driver.

## Build (Mac-native, no extra toolchain)

```sh
./build.sh        # clang integrated assembler + bundled rust-lld
file ./exec-target-exit0
# ELF 64-bit LSB executable, ARM aarch64, statically linked
```
