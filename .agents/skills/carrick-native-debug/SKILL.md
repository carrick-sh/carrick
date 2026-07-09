---
name: carrick-native-debug
description: >-
  Bring up and debug Carrick's no-VMM Darwin-native arm64 backend. Use when
  `--exec-backend native`, `CARRICK_EXEC_BACKEND=native`, `native16k`, or
  `linux4k` crashes, exits early, returns wrong process status, faults in a
  dynamic loader, or diverges from HVF. Covers the HVF contract audit, signed
  live repros, `carrick debug`, native trap records, Darwin fixed-address
  collisions, fork/exec lifecycle, and 4K-on-16K protection triage.
---

# Debugging the Darwin-native backend

Treat HVF as Carrick's executable specification for Linux process behavior, not
as the native mechanism. Audit the relevant HVF lifecycle before inventing a
native path, then prove the Darwin-specific mechanism independently.

## First pass

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
