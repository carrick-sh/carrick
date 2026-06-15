# hello-aarch64 — freestanding KVM-MVP test fixture

A hand-written, libc-free aarch64 Linux ELF that issues exactly
`write(1, "ok\n", 3)` then `exit_group(0)`. It is the L2 success criterion
for the carrick-linux KVM aarch64 MVP: `just kvm-smoke` runs it under
`carrick-linux` and diffs the output against `oracle.expected`.

## Build (Mac-native, no extra toolchain)

```sh
./build.sh        # clang integrated assembler + bundled rust-lld
file ./hello-aarch64
# ELF 64-bit LSB executable, ARM aarch64, statically linked
```

## Oracle (native Linux, inside the nested-KVM VM)

A static aarch64 Linux ELF cannot exec on macOS, so the oracle runs inside
the M3-nested HVF Linux VM:

```sh
./hello-aarch64; echo "exit=$?"
# ok
# exit=0
```

`oracle.expected` holds that stdout (`ok\n`); the exit code is asserted
separately by `just kvm-smoke`.
