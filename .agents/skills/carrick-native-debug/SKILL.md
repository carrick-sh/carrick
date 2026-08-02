---
name: carrick-native-debug
description: >-
  Bring up and debug Carrick's no-VMM native backends on Darwin/arm64 and
  FreeBSD/amd64. Use when `--exec-backend native`, `CARRICK_EXEC_BACKEND=native`,
  `native16k`, or `linux4k` crashes, exits early, hangs, runs slowly, returns a
  wrong process status, faults in a dynamic loader, or diverges from a VMM lane.
  Covers safe live FreeBSD DSR profiling, fork/exec lifecycle, native trap
  records, Darwin fixed-address collisions, and 4K-on-16K protection triage.
---

# Debugging Carrick native backends

Treat the mature VMM path as Carrick's executable specification for Linux
process behavior, not as the native mechanism. Audit the relevant lifecycle
before inventing a native path, then prove the host-native mechanism
independently.

## FreeBSD/amd64: profile a running DSR process

Use the supported profiler; do not recreate its DTrace program by hand:

```sh
sudo scripts/native-x86-profile.py <carrick-pid> --seconds 5
sudo scripts/native-x86-profile.py <pid> --guest-elf /path/to/guest --json
```

It discovers the existing process tree, follows new forks through the kernel
`proc` provider, discovers ASLR/JIT mappings with `procstat`, asks the matching
Carrick binary for its versioned `X86DsrContext` layout, and reports syscall
mix, symbolicated host PCs, raw/symbolicated guest PCs, and sampled `memcpy`
callers/sizes. A successful capture must end with `tracee_alive=true`,
`executable_mappings_stable=true`, and `dtrace_clean=true`.

**USDT and `pid$PID` probes against a continuing native process are allowed.**
The hazard to respect is fasttrap DETACH, which once killed a live Kaniko build
with a leaked `SIGTRAP` — so let a session exit on its own, and reach for the
kernel-provider profiler below when the tracee is a long run you cannot afford
to lose. That profiler deliberately uses only kernel `profile`, `syscall`, and
`proc` providers filtered through a numeric PID set.

For an unexplained fatal signal in a long build, start the reusable
kernel-provider trace before the relevant descendants are created:

```sh
sudo dtrace -q -s scripts/dtrace/native-x86-signal-lifecycle.d ROOT_PID \
  > /tmp/native-x86-signals.out
```

It follows future children, records sender/target/signum for `proc:::signal-send`,
and exits with the root. It is safe for a continuing tracee because it enables
no pid provider, USDT, or fasttrap probes. It initially knows only `ROOT_PID`,
so starting after the child of interest already exists will miss that child.

`ustack()` is not authoritative while guest code runs: DSR installs the guest
RSP, so host unwinding stops or follows guest data. The profiler samples host
RIP directly and reads the current guest PC through R15 using the layout from
`carrick debug native-x86-layout`; never hardcode the offset (XSAVE expansion
moved it from 720 to 33024). For a spin, use the reported guest-PC census; for a
host hotspot, use its PIE-normalized `addr2line` result.

The profiler is for an already-running process. `carrick trace --profile dsr`
is the separate launch-time USDT phase profiler and must own the target for its
whole lifetime.

For xstate-chain corruption, use the launch-time targeted edge trace only:

```sh
CARRICK_NATIVE_X86_TRACE_PC=0xSOURCE,0xTARGET \
  target/release/carrick trace \
  --script scripts/dtrace/native-x86-pc.d -- run ...
```

It records selected edge/patch decisions and FCW/MXCSR/XSTATE_BV/PKRU plus
bounded component hashes. `CARRICK_NATIVE_X86_EDGE_BARRIER` accepts `all`, a
source PC, or `source->target` and leaves that edge cold for a transition
bisect. `CARRICK_NATIVE_X86_XSTATE_POLICY=unsafe-local-diagnostic` deliberately
clobbers skipped local entries for a deterministic red control. The experimental
`neutral-domains` policy keeps state-user targets cold and guards neutral entry
on virtual guest PKRU. RDPKRU/WRPKRU are sensitive-emulated outside the hardware
XSAVE image so key-0 rights cannot revoke gateway access; guest-memory pkey
enforcement remains incomplete. `unsafe-target-barrier-diagnostic` remains an alias for replaying
the rejected experiment. Only the unsafe-local mode deliberately corrupts
state. To discover candidate edges first, set
`CARRICK_NATIVE_X86_TRACE_XSTATE_GRAPH=1` and launch with
`scripts/dtrace/native-x86-xstate-graph.d`; it aggregates patch lifecycle events
without per-entry probes or component hashing. Do not attach these USDT probes
to a continuing process—the launch-time tracer must own the target.

Treat repeated 16,384/16,576-byte copies as a gateway regression. Native x86
keeps one persistent `X86DsrContext` per host guest thread; the block loop calls
`prepare_entry()` and updates only scalar inputs. Never reconstruct the 33 KiB
context or move its embedded snapshot per entry. Snapshot cloning is reserved
for the semantic Linux `clone` boundary, not ordinary translated execution.

## FreeBSD/amd64: launch-time tracing and ground truth

`carrick trace` targets the container/VMM run, not the bare in-process native
runner, so use the tools below for the DSR lane. **Don't timeout-and-grep; get
ground truth.** (Worked example: a real std Rust binary spun; these tools pinned
it to a `jmp .` self-loop from an empty page-spanning `Continue` block in one
pass, after hours of grep-guessing got nowhere.)

`cargo run -p carrick-runtime --example native_run -- <elf>` is the standalone
single-run driver to attach a debugger or tracer to (build with
`--no-default-features --features platform-freebsd`). It registers the carrick
USDT provider, so probes are live.

For launch-time dtrace USDT — the event observability path, no env logging —
probe names use HYPHENS: `carrick<PID>:::syscall-return`, not `syscall__return`.
USDT probes register after process start, so use `-Z` and `-c` to launch and own
the target for its whole lifetime. Guest syscall census:

```sh
dtrace -Zq -c "…/native_run <elf>" \
  -n 'carrick*:::syscall-return { @[copyinstr(arg1)] = count(); } tick-3s { exit(0); }'
```

`syscall-entry` arg0 is the CANONICAL number post-normalization. Per the note
above, pid-provider and USDT probes are permitted here; only fasttrap detach on
an unrepeatable run warrants falling back to kernel providers.

**gcore + disassemble the JIT.** `gcore -c core PID`, then:

```sh
lldb …/native_run -c core -o "register read rip r15" -o "disassemble -b -s \$rip"
```

lldb can't unwind the JIT frame yet, BUT the core holds the guest's **live**
registers (the gateway loaded them into the real CPU) and the JIT bytes at `rip`
are the translated guest instructions — disassembling them shows exactly what
the guest is doing. NOTE: the core is ~34 GB (the 32 GiB mmap arena); export
`CARRICK_MMAP_ARENA_GIB=1` to shrink it.

**Make unhandled scenarios LOUD.** The driver's no-progress and unsupported
paths print a breadcrumb (recent block VAs, the mapped segments, the raw guest
bytes at the fault). Keep extending that to every unhandled path — a rich fault
string beats a debugger round-trip. Never let a failure surface as an empty
result a `grep` can hide.

**TODO (unwind through the JIT):** teach the carrick lldb scripts to unwind the
JIT→gateway→Rust frames (synthesize unwind info from the gateway's saved
`host_rsp`/`host_callee` in the ctx at `%r15`), so `bt` reaches
`run_static_x86_elf` and its locals (`next`, `image.segments`, the block cache).

## Darwin/arm64 first pass

1. Build and sign with `just build`; verify with
   `codesign --verify --verbose=2 target/release/carrick`.
2. Reproduce the exact command with a unique `CARRICK_RUN_ID`. Never run the
   Docker oracle concurrently with Carrick.
3. Reduce container failures to `--pid host` when PID supervision is not under
   test, and reduce shell workflows to one child plus one `wait4`.
4. For a fatal AArch64 record, decode `esr` first:

   ```sh
   target/release/carrick debug decode-esr 0x8200000f
   ```

5. For a hang or deadline, use the built-in runner before raw lldb:

   ```sh
   target/release/carrick debug lldb-run \
     --deadline-seconds 20 --run-id <run-id> -- \
     --exec-backend native --native-page-profile native16k \
     --raw --fs host <image> <command> ...
   ```

Immediate fork-child exits can finish before lldb attaches. In that case use
the native fatal record (`pc`, `sp`, `lr`, `esr`, `far`, TPIDR), a focused
`carrick trace`, or temporary opt-in `CARRICK_NATIVE_TRACE_SYSCALLS=1` evidence.
The native fatal record currently covers `SIGSEGV`, `SIGBUS`, and `SIGILL`, not
`SIGABRT`; use a raw lldb launch/breakpoint or a core for a host abort.
For instruction-abort EC `0x20`/`0x21`, interpret `decode-esr`'s currently
labelled `dfsc` field as IFSC. Do not add unconditional print debugging.

## HVF contract audit

For fork, vfork, or exec failures, compare native against the shared/HVF path
before changing code. Check every item:

- prepare the child process record before host `fork`;
- abort it on fork failure, complete it in the child, and publish it in the
  parent before the guest can wait;
- allocate/return namespace PIDs while retaining host PIDs for host syscalls;
- share only private guest-writable regions for `CLONE_VM|CLONE_VFORK`;
- suspend the vfork parent until child exec or exit;
- reset child signal, futex, process, run-state, and thread identity state;
- replace the image, close CLOEXEC fds, reset registers/TLS, and release the
  vfork parent only after successful exec replacement;
- preserve Linux wait-status encoding and child-exit notification.

Relevant references are `crates/carrick-runtime/src/vcpu_loop/quiesce.rs`,
`crates/carrick-runtime/src/vcpu_loop/exec.rs`,
`crates/carrick-aarch64/src/engine.rs`, and
`crates/carrick-vmm-hvf/src/trap.rs`. Compare them to native
`handle_native_fork`, native exec replacement and wait readiness in
`crates/carrick-runtime/src/native_darwin.rs`, plus common `wait4` in
`crates/carrick-runtime/src/dispatch/proc.rs`.

## Native-only hazards

### Fixed guest addresses

Darwin `MAP_FIXED` replaces existing mappings. A successful `mmap` does not
prove the range was vacant. Before selecting or moving a direct guest window:

- inspect a representative process with `vmmap -w <pid>`;
- add a forked regression that maps the complete native range and then forks;
- sample repeated fresh processes because Darwin malloc zones are randomized;
- keep backend-specific mmap arenas out of the shared HVF alias classifier.

A later crash in libobjc, malloc, or an atfork callback can be delayed evidence
that an earlier guest `MAP_FIXED` overwrote host runtime state. Test that
hypothesis independently from unsafe post-fork host work: allocator use,
locking, Objective-C calls, or inherited multithreaded state before exec can
also fail in a fork child.

### Page profiles

`native16k` can apply Darwin protections directly. `linux4k` cannot silently
widen one 4K subpage to the containing 16K host page. Classify each host page:

- uniform 16K state: direct `mprotect` fast path;
- composable backing with compatible permissions: intended future materialized
  host-page path; `Composed16k` is currently policy vocabulary only;
- mixed 4K permissions or fault boundaries: guarded precise slow path;
- executable mixed page: emulate supported data accesses, but reject an actual
  instruction fetch from a guarded subpage with a typed diagnostic.

Metadata-only `PROT_NONE`/read-only tracking is sufficient for syscall-buffer
checks, but not for direct guest loads, stores, or instruction fetches.

The current implementation applies direct host protection to uniform pages and
uses `PROT_NONE` plus the Darwin signal bridge for mixed pages. The bridge
decodes and emulates a bounded set of scalar, SIMD, and pair loads/stores while
temporarily reopening the host page for backing copies. Do not widen a page or
silently treat an unknown instruction as supported.

When a guarded instruction fails, preserve its disassembly in the reducer. A
fault inside host `memcpy`/`memset` after a successful decode usually means the
backing-copy path did not temporarily reopen that logical region. The brk-heap
regression is
`native_linux4k_guarded_heap_allows_adjacent_subpage_backing_write`.

Known bring-up signatures include unsupported exclusive atomics such as
`ldaxr`, non-guarded faults after a forked fixed mapping, and dynamic-loader
symbol errors such as `_res@GLIBC_2.17`. Treat the symbol error as possible
mapping/relocation corruption and compare source ELF bytes with mapped guest
bytes before changing symbol lookup behavior.

## Proof order

Use the narrowest red-to-green sequence:

1. forked host unit test for the Darwin primitive or address layout;
2. native static-PIE `run-elf` probe on `native16k` and `linux4k`;
3. OCI `/bin/sh` child-exec/wait reducer;
4. `native_conformance_container_executes_libc_probe`;
5. the full native probe lane, one page profile at a time.

Keep Carrick and Docker phases separate. A static probe that exits before the
parent parks does not prove the child registry or asynchronous wait path.
