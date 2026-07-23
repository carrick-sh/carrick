# x86_64 DSR test fixtures

`tinyguest-x86_64-linux` — a `#![no_std]` static-pie Linux x86_64 ELF used by
`tests/native_static_elf.rs` to prove the DSR lane runs REAL compiler output
(not hand-assembly). Source: `tinyguest.rs`.

It is checked in (rather than built during `cargo test`) so the test needs no
Linux cross-linker; the source and the exact build recipe live here for
review and regeneration. On the FreeBSD rig (rustc 1.96.0 with the
`x86_64-unknown-linux-musl` rust-std installed):

```sh
rustc --edition 2021 --target x86_64-unknown-linux-musl \
      -O -C panic=abort -C relocation-model=pic \
      --emit obj -o tinyguest.o tinyguest.rs
# Link a bare static-pie ELF with no CRT (rust-lld ships with the toolchain):
rust-lld -flavor gnu -static -pie -e _start -o tinyguest-x86_64-linux tinyguest.o
```

The guest computes a loop sum, `write(1, msg, len)` (msg reached
RIP-relatively — the emitter's absolute-VA rewrite), and `exit_group(sum)`
(sum == 0+1+…+6 == 21). It has no relocations (pure RIP-relative codegen) and
no TLS, so the loader needs no relocation pass and no `arch_prctl` servicing.

`computeloop-x86_64-linux` — a `#![no_std]` guest (`computeloop.rs`, built the
same way) running a 50-million-iteration PURE compute loop (no syscall inside
the loop) then `exit_group(sum & 0xff)`. It is the direct-branch-chaining
regression: the runtime test asserts `traps == 1` (the loop's conditional
back-edge ran natively in the JIT every iteration — unchained it would
round-trip to Rust 50M times) and `exit_code == 192` (the correct
`sum(3i+1, i in 0..50M) mod 256`, proving chaining preserved control flow and
register state).

`dynamic-main-x86_64-linux` carries a `PT_INTERP` whose main entry is an
intentional `ud2` sentinel. `dynamic-interpreter-x86_64-linux` is a
relocation-free static PIE that walks the kernel entry stack, requires nonzero
`AT_PHDR`, `AT_PHNUM`, `AT_BASE`, and `AT_ENTRY`, writes `dynamic-elf ok`, and
exits 23. Regenerate both with FreeBSD clang/lld:

```sh
clang --target=x86_64-linux-musl -nostdlib -fuse-ld=lld -pie \
  -Wl,--no-dynamic-linker -Wl,-e,_start \
  -o dynamic-interpreter-x86_64-linux dynamic-interpreter.S
clang --target=x86_64-linux-musl -nostdlib -fuse-ld=lld -pie \
  -Wl,--dynamic-linker,/lib/carrick-dynamic-interpreter -Wl,-e,_start \
  -o dynamic-main-x86_64-linux dynamic-main.S
```

The `exitgroup-sibling-*-x86_64-linux` binaries come from one bare-static
assembly fixture. Private/shared modes park the initial thread indefinitely in
the corresponding `FUTEX_WAIT` while a sibling calls `exit_group(37)`; immediate
mode makes that call directly after clone to race handle publication; busy mode
has a sibling spin forever in chained JIT code while the initial thread calls
`exit_group(0)`. Together they prove blocking-wait release, clone teardown, and
asynchronous translated-code kicks before native arena teardown. Regenerate
them with FreeBSD clang/lld:

```sh
clang --target=x86_64-linux-gnu -nostdlib -static -Wl,--build-id=none \
  -o exitgroup-sibling-futex-x86_64-linux exitgroup-sibling-futex.S
clang --target=x86_64-linux-gnu -DSHARED_FUTEX -nostdlib -static \
  -Wl,--build-id=none -o exitgroup-sibling-shared-futex-x86_64-linux \
  exitgroup-sibling-futex.S
clang --target=x86_64-linux-gnu -DIMMEDIATE_CHILD -nostdlib -static \
  -Wl,--build-id=none -o exitgroup-sibling-immediate-x86_64-linux \
  exitgroup-sibling-futex.S
clang --target=x86_64-linux-gnu -DBUSY_SIBLING -nostdlib -static \
  -Wl,--build-id=none -o exitgroup-sibling-busy-x86_64-linux \
  exitgroup-sibling-futex.S
```

`fork-child-sibling-exitgroup-output-x86_64-linux` covers the fork-child
lifecycle path: a sibling publishes `exit_group` while the child's initial
thread is parked, and 128 KiB of buffered output must survive terminal cleanup.

```sh
clang --target=x86_64-linux-gnu -nostdlib -static -Wl,--build-id=none \
  -o fork-child-sibling-exitgroup-output-x86_64-linux \
  fork-child-sibling-exitgroup-output.S
```

`native-service-fork-multithread-x86_64-linux` is the production
`service_fork` lock-inheritance gate. A raw `clone(CLONE_THREAD)` worker remains
active in `getpid` and blocking `nanosleep` calls while the main guest thread
performs 32 forks. Every child exercises fresh runtime state through
`getpid` + `pipe2` + pipe I/O + `close` + `nanosleep`, exits, and is reaped
before the next iteration. This is intentionally multithreaded at the actual
fork boundary (unlike the post-exec `forkexecpthread` lifecycle probe) while
remaining a fast mandatory integration fixture.

```sh
clang --target=x86_64-linux-gnu -nostdlib -static -Wl,--build-id=none \
  -o native-service-fork-multithread-x86_64-linux \
  native-service-fork-multithread.S
```

Checked fixture SHA-256 digest:

- `native-service-fork-multithread-x86_64-linux`:
  `fc9755db997d044d8cd524c499f894187b3a5d50496cec43ce764a73415c289f`

`identity-loop-x86_64-linux` executes 1,000 `getpid` and 1,000 `gettid`
syscalls before `exit_group`. The native integration gate requires one Rust
trap total, proving both identity calls remain inside the chained JIT path.

```sh
clang --target=x86_64-linux-gnu -nostdlib -static -Wl,--build-id=none \
  -o identity-loop-x86_64-linux identity-loop.S
```

`identity-seccomp-x86_64-linux` installs an allow-all seccomp filter before 20
identity calls. Its integration test requires all 23 syscalls to trap, proving
the live atomic gate disables already-translated identity paths immediately.

```sh
clang --target=x86_64-linux-gnu -nostdlib -static -Wl,--build-id=none \
  -o identity-seccomp-x86_64-linux identity-seccomp.S
```

`signal-xstate-roundtrip-x86_64-linux` drives asynchronous, synchronous-fault,
and nested Linux signal returns. It seeds x87/MXCSR/YMM1/virtual-PKRU state
(and K1/ZMM2 when host CPUID+XCR0 permit AVX-512), writes distinct state in each
handler, and exits 37 only when every standard-format XSAVE component survives;
a host without AVX-512 exits 38 after proving the base components.

```sh
clang --target=x86_64-linux-gnu -nostdlib -static -Wl,--build-id=none \
  -o signal-xstate-roundtrip-x86_64-linux signal-xstate-roundtrip.S
```

SHA-256:
`7b7eb05a0481494ae19503bf0be11b4ee85201cfc043662f639d82e1c9970a96`.

`signal-xstate-malformed-trailer-x86_64-linux` corrupts the private trailer
magic from a live SA_SIGINFO handler. Its `rt_sigreturn` must be rejected as a
bad frame and force guest SIGSEGV (exit 139) without aborting Carrick.

```sh
clang --target=x86_64-linux-gnu -nostdlib -static -Wl,--build-id=none \
  -o signal-xstate-malformed-trailer-x86_64-linux \
  signal-xstate-malformed-trailer.S
```

SHA-256:
`fa38d08e2cbd4eb3f64185d8e6a1ffd3f6d827f65fb640ef03670cec83f5de33`.

`x87-selectors-x86_64-linux` is the exact virtual non-REX FCS/FDS gate. It
imports distinct selectors through plain XRSTOR while placing hostile sentinels
in both reserved 16-bit halves, then proves plain XSAVE writes only the virtual
selectors and preserves the sentinels. XRSTOR64 replaces both complete 64-bit
pointers without changing selectors; a requested-absent plain XRSTOR restores
Carrick's Linux/x86_64 initial selectors (`0x23`/`0x1b`). Finally it restores the
custom selectors and virtual PKRU, takes a real signal, and has the handler copy
the fpstate to a new aligned buffer using exactly Linux's advertised
`extended_size`. `rt_sigreturn` must recover both private states from that
relocated extent. Every plain operand uses a low register so its encoding has no
REX prefix (`0f ae` in the disassembly); only
the deliberate XRSTOR64 form begins `48 0f ae`. The exact five dispatcher traps
are `rt_sigaction`, `tgkill`, `rt_sigreturn`, the success write, and
`exit_group`; optimized `getpid`/`gettid` remain in translated code.

```sh
clang --target=x86_64-linux-gnu -nostdlib -static -Wl,--build-id=none \
  -o x87-selectors-x86_64-linux x87-selectors.S
tmp=$(mktemp -d)
clang --target=x86_64-linux-gnu -nostdlib -static -Wl,--build-id=none \
  -o "$tmp/x87-selectors" x87-selectors.S
cmp x87-selectors-x86_64-linux "$tmp/x87-selectors"
objdump -d x87-selectors-x86_64-linux | grep -E 'xsave|xrstor'
```

Checked fixture SHA-256 digest:

- `x87-selectors-x86_64-linux`:
  `45a1703af43f0d822de79c7493437cef99b80f86d31f6c5a99ce54477345ef41`

`xrstor-state-x86_64-linux` is the checked memory-aware XRSTOR integration
fixture. Its blocker is the literal byte sequence `0f ae 6c 24 40`
(`xrstor 0x40(%rsp)`). A standard aligned source image restores distinct
requested-present x87/YMM state. For requested-absent SSE it replaces a seeded
non-default MXCSR with architectural initial `0x1f80` and initializes XMM1 while
retaining the existing YMM-upper check. It preserves unrequested K1/ZMM20 when
host CPUID+XCR0 permit AVX-512, exiting 37 only after those checks execute and 38
for the base-only path; the Rust integration derives and requires the matching
host receipt so AVX-512 suppression cannot pass silently. It also verifies every
GPR, RFLAGS, RSP, and Carrick's virtual PKRU while requiring exactly one syscall
trap (`exit_group`).

`xrstor-retry-x86_64-linux` covers the synchronous error contract. A SA_SIGINFO
alternate-stack handler observes exact header-byte addresses for a PROT_NONE
`SEGV_ACCERR`, a true unmapped `SEGV_MAPERR`, and `SIGBUS/BUS_ADRERR` from a
readable `MAP_SHARED` file page truncated past EOF after mapping. The MAPERR
handler installs anonymous `MAP_FIXED` memory; the BUS handler regrows the same
file, writes a distinct x87 control word plus a valid header, and proves the
exact retried XRSTOR imports those repaired bytes without a host crash. It then
checks `SI_KERNEL`/address-zero for an unsafe PKRU header and a misaligned
operand. Every phase verifies the original RIP/RSP and returns through the
normal restorer without advancing RIP. The counters before the restart RIP are
site-entry counters, not attempt counters: exactly one handler fault plus the
successful continuation proves one failed attempt and one successful retry.
The pure
`xstate_restore::tests::exact_read_census_is_one_read_per_required_range_per_service_attempt`
reader census separately proves that one service attempt reads each required
architectural source range exactly once. Virtual PKRU remains nonzero throughout
without reaching host PKRU.

```sh
clang --target=x86_64-linux-gnu -nostdlib -static -Wl,--build-id=none \
  -o xrstor-state-x86_64-linux xrstor-state.S
clang --target=x86_64-linux-gnu -nostdlib -static -Wl,--build-id=none \
  -o xrstor-retry-x86_64-linux xrstor-retry.S
```

Checked fixture SHA-256 digests:

- `xrstor-state-x86_64-linux`:
  `994fc16bcba14bcc871fd5fa9535796a5a76e7cadcf3859493693df51f5aa45d`
- `xrstor-retry-x86_64-linux`:
  `3218e5745a685ba38d7b4add567f1746418216176ffb75287b0032eea06e6c9f`

`xsave-roundtrip-x86_64-linux` is the mandatory checked XSAVE-family transfer
fixture. It executes translated `XSAVE`, `XSAVE64`, `XSAVEOPT`, `XSAVEOPT64`,
`XSAVEC`, and `XSAVEC64` against 64-byte-aligned guest images; the XSAVE64
receipt uses the literal `%rsp+0x40` addressing form. The live state contains a
distinct x87 value, a non-default MXCSR built from the runtime-observed
`MXCSR_MASK` (including supported DAZ/FZ bits), YMM1, virtual PKRU=3, and, when
host CPUID+XCR0 enable AVX-512, K1/ZMM2/ZMM20. Every request includes hostile
bit 9, which must neither save nor restore physical PKRU.

The fixture verifies standard old-`XSTATE_BV` read/modify/write, untouched
`XCOMP_BV`, requested-present payload, plain-XSAVE materialization of requested
initial state, XSAVEOPT initial-state omission, exact MXCSR/MXCSR_MASK, legacy
reserved bytes and dynamic standard/compacted alignment gaps, plus XSAVEC's
complete compacted header and CPUID-derived offsets. Full standard and compacted
images are restored through translated XRSTOR64, after which all live xstate,
GPRs, RFLAGS, RSP, and virtual PKRU must match exactly. The broad save-family fixture keeps x87 payload coverage on its REX.W standard
and compacted round trips; the focused `x87-selectors` fixture above owns the
non-REX pointer/selector distinction, reserved halves, initialization, and
signal preservation without depending on host FCS/FDS capability bits.
Exit 37 proves the AVX-512 checks ran; exit 38 proves the base x87/SSE/AVX path.
Only `exit_group` is a syscall trap, so the exact census is one.

`xsave-retry-x86_64-linux` is the mandatory `service_xstate_save` checked-writer
retry fixture. Four XSAVEC64 sites use SA_SIGINFO on an alternate stack. The
first writes an actually unmapped destination and requires `SEGV_MAPERR` plus a
`MAP_FIXED` repair; the second writes a read-only mapping and requires
`SEGV_ACCERR` plus `mprotect`; the third writes a writable `MAP_SHARED` page
whose complete file backing was truncated and requires `SIGBUS/BUS_ADRERR` plus
a backing-file grow; the fourth repairs a misaligned operand reported as
`SI_KERNEL` with address zero. Each handler verifies exact `si_addr`, original
RIP/RSP, and one entry for its phase, returns without advancing RIP, and the
continuation validates the retried compacted header and x87 payload. The exact
18 syscall traps are: one anonymous mmap, one setup mprotect, one munmap,
`sigaltstack`, two `rt_sigaction`s, `openat`, two setup `ftruncate`s, one shared
mmap, three handler repair syscalls, four `rt_sigreturn`s, and `exit_group`.

Regenerate both raw static Linux/amd64 fixtures on FreeBSD with clang/lld:

```sh
clang --target=x86_64-linux-gnu -nostdlib -static -Wl,--build-id=none \
  -o xsave-roundtrip-x86_64-linux xsave-roundtrip.S
clang --target=x86_64-linux-gnu -nostdlib -static -Wl,--build-id=none \
  -o xsave-retry-x86_64-linux xsave-retry.S
```

A reproducibility check must rebuild to separate paths and compare bytes before
updating the checked digests. The disassembly check must show all six save
mnemonics, both restored image paths, and four retrying XSAVEC64 sites:

```sh
tmp=$(mktemp -d)
clang --target=x86_64-linux-gnu -nostdlib -static -Wl,--build-id=none \
  -o "$tmp/xsave-roundtrip" xsave-roundtrip.S
clang --target=x86_64-linux-gnu -nostdlib -static -Wl,--build-id=none \
  -o "$tmp/xsave-retry" xsave-retry.S
cmp xsave-roundtrip-x86_64-linux "$tmp/xsave-roundtrip"
cmp xsave-retry-x86_64-linux "$tmp/xsave-retry"
objdump -d xsave-roundtrip-x86_64-linux | grep -E 'xsave|xrstor'
objdump -d xsave-retry-x86_64-linux | grep 'xsavec64'
```

Checked fixture SHA-256 digests:

- `xsave-roundtrip-x86_64-linux`:
  `a5b3c8d29ddfc76b4acffb5c537ccceae7892b11fd1d502c33e32fc8d58e0a4b`
- `xsave-retry-x86_64-linux`:
  `28ae5ffd498017dce42a183f1a82af84bb4fc4790748812496bf53dafbc981da`

`instruction-fetch-retry-x86_64-linux` is the translation-time fetch gate. A
two-byte `data16 ret` straddles a page boundary in three mappings. The first
mapping denies execute permission on the continuation page; its SA_SIGINFO
handler requires `SIGSEGV/SEGV_ACCERR`, the exact continuation-byte `si_addr`,
and the original instruction-start RIP/RSP before adding `PROT_EXEC`. The
second mapping unmaps the continuation and requires `SIGSEGV/SEGV_MAPERR` at
the same exact boundary before a `MAP_FIXED` population plus `mprotect` repair.
The third mapping is an RX `MAP_SHARED` file truncated at the boundary; its
handler requires contained `SIGBUS/BUS_ADRERR` at the same exact byte, regrows
and repopulates the file, and returns without advancing RIP. All three exact
retries must execute the prefixed return once. The integration receipt requires
exactly 23 syscall traps: setup and repair calls, three `rt_sigreturn`s, one
success write, and `exit_group`. A complete one-byte instruction at the same
boundary is covered separately by the runtime unit test, preventing an
implementation that obtains safety by overfetching beyond the decoded length.

`blocked-instruction-fetch-segv-x86_64-linux` blocks SIGSEGV before the same
cross-page ACCERR fetch. The synchronous fault must take the fatal action (exit
139) without entering the installed handler or queuing a later delivery.

```sh
clang --target=x86_64-linux-gnu -nostdlib -static -Wl,--build-id=none \
  -o instruction-fetch-retry-x86_64-linux instruction-fetch-retry.S
clang --target=x86_64-linux-gnu -nostdlib -static -Wl,--build-id=none \
  -o blocked-instruction-fetch-segv-x86_64-linux \
  blocked-instruction-fetch-segv.S
tmp=$(mktemp -d)
clang --target=x86_64-linux-gnu -nostdlib -static -Wl,--build-id=none \
  -o "$tmp/instruction-fetch-retry" instruction-fetch-retry.S
clang --target=x86_64-linux-gnu -nostdlib -static -Wl,--build-id=none \
  -o "$tmp/blocked-instruction-fetch-segv" blocked-instruction-fetch-segv.S
cmp instruction-fetch-retry-x86_64-linux "$tmp/instruction-fetch-retry"
cmp blocked-instruction-fetch-segv-x86_64-linux \
  "$tmp/blocked-instruction-fetch-segv"
```

Checked fixture SHA-256 digests:

- `instruction-fetch-retry-x86_64-linux`:
  `1a3fbf54b0618a45470b5ab8b3fecaaea8f2201d2e21f2d2792e9c370d111dda`
- `blocked-instruction-fetch-segv-x86_64-linux`:
  `3223f7016434b0f28888898e7fe7c321ed3e6616c381880070d2529525a5cec2`

`cflow-call-stack-write-fault-x86_64-linux` and
`cflow-indirect-target-read-fault-x86_64-linux` are retryability gates for cold
control-flow memory faults. The first executes direct `call` pushes on both a
read-only anonymous page and a writable `MAP_SHARED` page whose file was
truncated past the return slot. Its alternate-stack SIGSEGV/SIGBUS handlers
verify `SEGV_ACCERR` or `BUS_ADRERR` plus the original RIP/RSP and exact stack
address, repair the permission/backing, and require each exact call to retry
once. The second calls through an unmapped target slot, then executes a `ret`
through the same unmapped page. Its alternate-stack handler verifies
`SEGV_MAPERR` plus original RIP/RSP at both boundaries, remaps and populates the
slot without reading it, and requires one exact retry of each instruction.
Together with the callback-counting `cflow` unit tests, these prove failed cflow
memory accesses do not become fatal Carrick faults, mutate architectural state,
or perform an extra memory observation; truncated write backing is contained by
FreeBSD copyout rather than host SIGBUS.

```sh
clang --target=x86_64-linux-gnu -nostdlib -static -Wl,--build-id=none \
  -o cflow-call-stack-write-fault-x86_64-linux \
  cflow-call-stack-write-fault.S
clang --target=x86_64-linux-gnu -nostdlib -static -Wl,--build-id=none \
  -o cflow-indirect-target-read-fault-x86_64-linux \
  cflow-indirect-target-read-fault.S
```

Checked fixture SHA-256 digests:

- `cflow-call-stack-write-fault-x86_64-linux`:
  `33d1969548a9cc5b8301ed65be94507b7e112e0d23c2b00d4ddd52e3b1e408d3`
- `cflow-indirect-target-read-fault-x86_64-linux`:
  `b51ead361b1b0b7269d3f025ba56909f41ae9d245693890a9eb1694191fb8a2e`

`blocked-sync-segv-x86_64-linux` installs and then blocks a SIGSEGV handler
before a translated load from unmapped address zero. The native runner must
report exit 139 without entering the handler. `fork-detached-sync-segv-x86_64-linux`
forks, creates a detached guest thread in the descendant, faults that thread in
translated code, and requires the parent `wait4` status to encode
WIFSIGNALED/SIGSEGV rather than WIFEXITED(139).

```sh
clang --target=x86_64-linux-gnu -nostdlib -static -Wl,--build-id=none \
  -o blocked-sync-segv-x86_64-linux blocked-sync-segv.S
clang --target=x86_64-linux-gnu -nostdlib -static -Wl,--build-id=none \
  -o fork-detached-sync-segv-x86_64-linux fork-detached-sync-segv.S
```

Checked fixture SHA-256 digests:

- `blocked-sync-segv-x86_64-linux`:
  `12f8d4e4518019ad3acc44b31967734d5335d2baad8b200f2ce3c3669a1e5427`
- `fork-detached-sync-segv-x86_64-linux`:
  `390082dbbb61bde403158652287a5ca8cb183773731d5091da4e4e0187ba30c4`

`rdssp-disabled-x86_64-linux` covers the disabled-CET compatibility semantics
used by CET-aware libraries even when guest CPUID masks `CET_SS`. It seeds
nonzero 64-bit destinations and flags, executes both `rdsspd` and `rdsspq`, and
exits 37 only if both instructions preserve the complete destination register
and RFLAGS. Other CET shadow-stack instructions remain unsupported.

```sh
clang --target=x86_64-linux-gnu -nostdlib -static -Wl,--build-id=none \
  -o rdssp-disabled-x86_64-linux rdssp-disabled.S
```

SHA-256:
`37557605839475c700d54671aadc7011470d40ed69512a0def33b084fad7cd85`.

`fsbase-zero-isolation-x86_64-linux` proves zero is guest FS state rather than a
gateway sentinel. It reads a marker through a nonzero `ARCH_SET_FS` base, calls
`ARCH_SET_FS(0)`, and requires the same copied `fs:` access to deliver
`SIGSEGV/SEGV_MAPERR` at guest address zero instead of exposing host TLS.

```sh
clang --target=x86_64-linux-gnu -nostdlib -static -Wl,--build-id=none \
  -o fsbase-zero-isolation-x86_64-linux fsbase-zero-isolation.S
```

SHA-256:
`09bd3b79255137a901be5f78af67eaba5b7ba8341acc50bb6c174f23f9240d5d`.

`pkru-virtual-x86_64-linux` writes PKRU=3 (deny read/write for pkey 0), reads
it back, resets it, and exits 37. Carrick must sensitive-emulate those
instructions: executing the write physically would revoke the user-mode
gateway's context and host-stack access. This proves gateway safety and the
virtual register round trip, not guest-memory pkey enforcement (still
unsupported).

```sh
clang --target=x86_64-linux-gnu -nostdlib -static -Wl,--build-id=none \
  -o pkru-virtual-x86_64-linux pkru-virtual.S
```

`pkru-invalid-retry-x86_64-linux` raises synchronous general protection from
invalid RDPKRU and WRPKRU operands. Its SA_SIGINFO handler verifies
SIGSEGV/SI_KERNEL/address zero, repairs saved ECX/EDX, and returns so both
still-unexecuted instructions retry successfully.

```sh
clang --target=x86_64-linux-gnu -nostdlib -static -Wl,--build-id=none \
  -o pkru-invalid-retry-x86_64-linux pkru-invalid-retry.S
```

SHA-256:
`ecea3027b544da72cb9db8e507411e80ba61360a4daa200b53c646e2530b3fe6`.

`return-cache-loop-x86_64-linux` executes 10,000 direct calls to one leaf
`ret`. Calls still use the authoritative Rust resolver, while the leaf return
exercises the gateway's monomorphic cache after warm-up. The runtime gate runs
this under both conservative and neutral-domain xstate ownership; the focused
native-execution test proves a hit reaches the next syscall without returning
to Rust.

```sh
clang --target=x86_64-linux-gnu -nostdlib -static -Wl,--build-id=none \
  -o return-cache-loop-x86_64-linux return-cache-loop.S
```

`xstate-chain-boundary-x86_64-linux` is the red-first xstate-ownership reducer.
It materializes guest `xmm0=37`, then enters an integer-only block directly
chained to an XMM consumer. The conservative policy exits 37. The explicit
`unsafe-local-diagnostic` policy exposes host XMM state and must fail the value
check; adding `CARRICK_NATIVE_X86_EDGE_BARRIER=all` makes the edge cold and
restores exit 37. This pins the hidden transitive dependency without enabling
unsafe local gating in production.

```sh
clang --target=x86_64-linux-gnu -nostdlib -static -Wl,--build-id=none \
  -o xstate-chain-boundary-x86_64-linux xstate-chain-boundary.S
```

`exec-main-retires-siblings-x86_64-linux` and
`exec-worker-retires-siblings-x86_64-linux` are checked-in Linux/amd64 static
fixtures for native terminal-exec integration. The first makes the main thread
replace an image with 32 busy siblings; the second makes a non-leader worker
replace the image while the main thread remains live. Both self-exec and require
stage 2 to observe exactly one thread. The worker then creates a fresh stage-2
thread and verifies the survivor's `gettid()` remains `getpid()`, proving exec
rethreading is permanent rather than a live-count alias.

The main fixture is the musl build of
`conformance-probes/src/bin/execthreads.rs`. The worker's minimal checked reducer
is `exec-worker-retires-siblings.S`; the full workload source remains
`conformance-probes/src/bin/execfromthread.rs`.

```sh
cargo build --manifest-path conformance-probes/Cargo.toml \
  --target x86_64-unknown-linux-musl --release --bin execthreads
cp conformance-probes/target/x86_64-unknown-linux-musl/release/execthreads \
  crates/carrick-dsr-x86/tests/fixtures/exec-main-retires-siblings-x86_64-linux
clang --target=x86_64-linux-gnu -nostdlib -static -Wl,--build-id=none \
  -o crates/carrick-dsr-x86/tests/fixtures/exec-worker-retires-siblings-x86_64-linux \
  crates/carrick-dsr-x86/tests/fixtures/exec-worker-retires-siblings.S
```

Checked fixture SHA-256 digests:

- `exec-main-retires-siblings-x86_64-linux`:
  `dcfa3563ef4d95e4e5b190cd189f4877ed36f12e493e9c5798018640e572588e`
- `exec-worker-retires-siblings-x86_64-linux`:
  `968feafb5d12495d351159723f4ccfcea5489de051ed9be28d99d4efe7508257`

`clone-thread-tid-transaction-x86_64-linux` is the native CLONE_THREAD
publication fixture. A test-only host-pthread spawn failure makes clone return
`-EAGAIN`; the guest verifies both PARENT_SETTID and CHILD_SETTID sentinels stay
unchanged and that no child body becomes visible.

```sh
clang --target=x86_64-linux-gnu -nostdlib -static -Wl,--build-id=none \
  -o clone-thread-tid-transaction-x86_64-linux clone-thread-tid-transaction.S
```

SHA-256:
`c46436c8a0542bab2c8e257669d72c0bf2bcc101fac6dbbc1bc6304e7372631b`.

`shared-exec-mutation-x86_64-linux` is the mandatory native-x86 mutable
`MAP_SHARED` executable regression. It creates one unnamed host-backed file,
maps distinct RW and RX views, and calls a six-byte function in the RX view
after changing its immediate through the RW view, `pwrite(2)`, and a
synchronized fork child. Every call must observe the new value, proving that
read-only shared executable translations, edges, cflow plans, and return sites
remain permanently ephemeral. Regenerate it on FreeBSD with:

```sh
clang --target=x86_64-linux-gnu -nostdlib -static -Wl,--build-id=none \
  -o shared-exec-mutation-x86_64-linux shared-exec-mutation.S
```

Checked fixture SHA-256 digest:

- `shared-exec-mutation-x86_64-linux`:
  `c19bfd6035e99d36206a72fee55b95bcd72c5f6f303481b1b64886a96aae846e`

`legacy-x87-state-x86_64-linux` covers checked FXSAVE/FXRSTOR and legacy x87
state transfers without executing a guest state-transfer opcode physically. It
pins plain virtual FCS/FDS versus REX.W full pointers, 14/28-byte environment
layouts, reserved words, FNSTENV/FSTENV mask-after-success, FLDENV, 94/108-byte
full-state payloads, full/abridged tags, and FNSAVE/FSAVE initialization.
Generated FIP/FDP after ordinary copied x87 data instructions remains an open
native correctness item; see `handoff.md`.

`fxstate-retry-x86_64-linux` exercises exact retry through real destination
`SEGV_MAPERR`, `SEGV_ACCERR`, and writable-MAP_SHARED `BUS_ADRERR` faults, then
repairs an invalid-MXCSR `FXRSTOR64` #GP in its SA_SIGINFO handler. Every normal
handler return retries the original sensitive instruction.

```sh
clang --target=x86_64-linux-gnu -nostdlib -static -Wl,--build-id=none \
  -o legacy-x87-state-x86_64-linux legacy-x87-state.S
clang --target=x86_64-linux-gnu -nostdlib -static -Wl,--build-id=none \
  -o fxstate-retry-x86_64-linux fxstate-retry.S
```

Checked fixture SHA-256 digests:

- `legacy-x87-state-x86_64-linux`:
  `6fc915d3347ecf9fbf5f617a890374a826457236daee646f28a526c06ee9252f`
- `fxstate-retry-x86_64-linux`:
  `a1ba627da2f2a9a085ebff8d8a148ff2398bee2a438ef128b93002a2f109ac23`
