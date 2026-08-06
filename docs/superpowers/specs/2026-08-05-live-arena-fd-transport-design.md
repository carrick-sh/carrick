# Live arena fd-backed transport design

**Date:** 2026-08-05
**Status:** Probe-backed design, approved direction after the Task 6C2 blocker
**Backend:** Darwin/AArch64 native (DSR) only
**Supersedes:** the "Proven Darwin Mechanism" section and the Mach-transit
paragraphs of "Authority and lifetime" in
`2026-08-05-native-live-translation-arena-design.md`. The V2 protocol, wire
layout, state machine, W^X/I-cache authority, and every consumer-facing
contract in that document are unchanged.
**Controller finding:** Task 6C2 proved the Mach memory-entry transport does
not survive `fork(2)` (`.superpowers/sdd/2026-08-05-native-live-translation-arena-task6/task-6c2-report.md`
§1): a forked guest child inherits the arena's `VM_INHERIT_SHARE` bytes but no
Mach rights, so it cannot carry the arena through its own host self-exec, and
every forked-then-exec'd guest process failed `execve` with EIO.

## Verdict

Replace the Mach transport (memory-entry send rights + registered ports) with
**two unlinked regular files** — the `kernel_arena` idiom already used by four
fork-crossing subsystems in the same capsule — dual-mapped per process as an
RW alias and an RX alias, with the RX alias created by
`mmap(PROT_READ)` + `mprotect(PROT_READ|PROT_EXEC)` and both aliases'
**maximum** protections clamped by `mach_vm_protect(set_maximum)`.

Every hard constraint is satisfied with no trade-off, so per the decision rule
this design commits rather than reporting BLOCKED:

- **(a) one shared object, zero-copy attach** — same records/cursors/bytes
  observed cross-process and cross-exec; successor attach measured 8.6–17.6 µs
  end-to-end, and 10.1–16.6 µs at full V2 geometry (64 MiB code + 68 MiB
  control), ~60x under the <1 ms campaign gate;
- **(b) W^X** — RW alias for the claim-bound writer, RX alias for consumers,
  never W|X; on this backing the kernel itself refuses a simultaneous W|X
  mapping (measured), which is *stronger* than the Mach-entry design;
- **(c) identity/authentication** — fd inheritance (capability) +
  `fstat` dev/ino/size (object identity, `kernel_arena` precedent) + the
  unchanged V2 directory nonce/schema/ABI/layout validation (protocol
  identity);
- **(d) both boundaries** — the full lifecycle probe crossed guest `fork(2)`
  AND `POSIX_SPAWN_SETEXEC`, executed pre-fork code, then observed a control
  write and executed a code publication the creator made *after* the exec;
- **(e) fork-safe teardown** — no Mach name exists anywhere in the design, so
  the 6C2 §8 `MachSendRight::drop` hazard dissolves rather than needing a fix.

## Probe receipts

House rule: every Darwin capability claim below was probed on this host before
being designed against. Probe crate (uncommitted, scratchpad):
`/private/tmp/claude-501/-Volumes-CaseSensitive-carrick/19d86d41-81ac-493e-9794-a6f874d6e07e/scratchpad/fd-transport-probes/`
(`src/main.rs`, driver `run-probes.sh`, raw output `receipts.txt`).

Host: macOS 27.0 (build 26A5388g), Darwin 27.0.0 xnu-13432.0.94.501.4~1
RELEASE_ARM64_T8132. Probe binary signing state matches the carrick native
lane: `flags=0x20002(adhoc,linker-signed)`, no hardened runtime, no
entitlements — a plain `cargo build` product.

| # | question | result |
|---|---|---|
| P1 | `shm_open` fd across `fork` + `POSIX_SPAWN_SETEXEC` (CLOEXEC cleared), successor re-maps | **PASS** — fstat ok, 256-byte pattern validated (`exit=0`) |
| P2-shm | dual RW/RX `MAP_SHARED` aliases of one shm fd | **FAIL, permanently** — `mmap(R\|X)` *succeeds but silently strips EXEC* (region `cur=r-- max=rw-`); `mprotect(R\|X)` → `EACCES`; execution → SIGBUS. shm can never be executable on this host |
| P2-file | same with a regular `O_RDWR` file (unlinked temp) | **PASS via route B** — direct `mmap(R\|X)` → `EPERM` (the AMFI refusal `aot_cache.rs` recorded), but `mmap(PROT_READ)` + `mprotect(R\|X)` → `cur=r-x max=rwx`; executes 42 in-child and in-process |
| P2-file coherence | write through RW alias → RX alias, `sys_icache_invalidate` on RX | **PASS** — append to an already-executed page → 43; overwrite executed code → 44; no remap needed |
| P2-file revocation | `mprotect(PROT_NONE)` the RX alias page, then restore R\|X | **PASS** — revoked exec faults (SIGBUS, signal 10), restore → 44. Task-7 revoke/restore mechanics work on fd backing |
| P4-shm | full lifecycle on shm | FAIL at first execution (SIGBUS), consistent with P2-shm; attach itself worked (2.1 µs) |
| P4-file | full lifecycle: creator writes code → `fork(2)` child clears CLOEXEC → SETEXEC self-exec → successor maps RW+RX from the inherited fd | **PASS end-to-end** (`exit=0`) — attach 8,584 ns; executed creator's pre-fork code (42); observed creator's post-exec control write (GEN 1→2); executed code the creator published *after* the exec (43). Ongoing shared coherence, not a snapshot |
| P-timing | attach at V2 geometry, 64 MiB code (RW+RX) + 68 MiB control (RW) + 8 KiB validation read, 8 samples | shm 8.2–11.8 µs; file 10.1–16.6 µs. Gate is <1 ms/process |
| P5 | `mach_make_memory_entry_64(VM_PROT_READ\|EXECUTE)` over an fd-backed RW mapping (local-aliasing fallback) | **FAIL** — `KERN_PROTECTION_FAILURE` (kr=2) for both shm and file. Consistent with the substrate design's prior finding that only `MAP_JIT` backings mint RX-capable entries. Not needed |
| P6 | `mach_vm_protect(set_maximum)` clamp: RW alias max→`rw-`, RX alias max→`r-x` | **PASS** — regions read back exactly clamped; `mprotect` escalation of either alias refused `EACCES`; exec, revoke, and restore all still work inside the clamped max |
| P6 honesty | can an *unclamped* mapper reach W\|X? `mprotect(RWX)` on a fresh `max=rwx` file mapping | **refused `EACCES`** — the kernel denies simultaneous W\|X on this backing outright; there is no route to a W\|X mapping of the arena, clamped or not |
| MAP_JIT+fd | `mmap(MAP_SHARED\|MAP_JIT, fd)` | refused `EINVAL` (both backings), as expected — recorded for completeness |

Fault-shape receipt: on this host, executing a revoked (PROT_NONE) fd-backed
RX page and executing never-executable shm pages both deliver **SIGBUS
(signal 10)**, not SIGSEGV. Task 7's stale-code classifier predicates (ESR
class, PC==FAR inside a revoked chunk) must be re-proven against this
backing's exact Mach exception shape; the revoke/restore *mechanics* are
proven above.

## What was verified by reading (and one hypothesis corrected)

**The 6C2 tractability hypothesis — "`aot_cache` already maps executable
pages from a file" — is FALSE as stated, but the conclusion survives.**
`crates/carrick-native-darwin/src/aot_cache.rs` (module doc, "The transport")
maps its code file `MAP_PRIVATE|PROT_READ` and **replays** blocks into the
per-process `MAP_JIT` cache; nothing maps that file executable. Its previous
transport (ad-hoc-signed dylibs + `dlopen`) did map executable file pages but
needed two `codesign` spawns per publication and paid 14.76 ms/process in
signature-validation faults — and its doc records "AMFI refuses
`mmap(PROT_EXEC)` of unsigned files", which P2-file confirms at mmap time.
What the aot_cache era never recorded is that the **`mprotect` route is open**
for an ad-hoc, non-hardened process: `mmap(PROT_READ)` then
`mprotect(R|X)` succeeds and executes, with none of the dylib transport's
signing or validation cost. That measured route, not the aot_cache mechanism,
is what makes this design tractable.

**The V2 wire is transport-agnostic, as the 6C2 report assumed.** The portable
protocol (`carrick-dsr-aarch64::live_arena`) is adopted from a base pointer +
length and contains no Mach concept. The 64-byte object headers carry only
magic/kind/schema/code_len/control_len/nonce (`object_header`,
`carrick-native-darwin/src/live_arena.rs`), and `LiveArenaTransitV2` is
schema/lengths/nonce. Nothing in the *protocol* bakes in Mach assumptions;
the only Mach-flavored residue is naming — the substrate design calls the
header "the authenticated Mach transport header" — which this design renames
in prose only. Everything Mach is confined to the transport layer:
`MachSendRight`, memory-entry creation, `VmMapping::map_entry`,
`RegisteredPortVector`/`OolPortArray`/`register_port_names`,
`RegisteredPortExecPlan`, `LiveArenaTransitRights`, and the
`posix_spawnattr_set_registered_ports_np` / `mach_port_get_refs` SPI
declarations.

## Chosen backing object

Two **unlinked regular files** (code object, control object), preserving the
existing two-object split and the exact V2 wire:

- created in `std::env::temp_dir()` (the `KernelArena::create` convention)
  with pid+serial names and `O_EXCL`, unlinked immediately — the fds are the
  only handles, the filesystem reclaims the extents at last close, and no
  stale path can ever be re-attached;
- `ftruncate` once to `LiveArenaControlLayout` lengths (APFS keeps them
  sparse until written; the current-workload census writes ~36 MiB of the
  64 MiB code capacity);
- the arena owner retains both `OwnedFd`s for the process lifetime.

shm is refuted (P2-shm: EXEC silently stripped, `EACCES` on every escalation
route). The Mach local-aliasing hybrid (P5) is refuted
(`KERN_PROTECTION_FAILURE`). MAP_JIT cannot be fd-backed (`EINVAL`). The
regular file is the only mechanism that passed, and it passed everything.

## Mapping and aliasing lifecycle

**Creator (the container's initial guest process, `pid == 0` arm of
`run_image_in_child`, unchanged creation point from 6C2):**

1. create + size both backing files; record `fstat` dev/ino/size per fd;
2. control: `mmap(RW, MAP_SHARED)`, clamp max→`rw-`;
3. code RW alias: `mmap(RW, MAP_SHARED)`, clamp max→`rw-`;
4. code RX alias: `mmap(PROT_READ, MAP_SHARED)`, `mprotect(R|X)`, clamp
   max→`r-x`;
5. validate every region with the existing
   `VmMapping::validate_protections` equality check (current == max ==
   requested) — which now holds *verbatim* post-clamp (P6 receipts) and is
   the mandatory fail-closed guard against the silent-EXEC-strip failure
   shape P2-shm measured;
6. write object headers, initialize the protocol in place, exactly as today.

The `MapJitBootstrap` constructor-only RWX mapping is **deleted** — the fd
design never holds W|X anywhere, not even privately during construction.

**`clone(CLONE_THREAD)` siblings:** `Arc` clone, unchanged (6C2 §5).

**guest `fork(2)` children (using the arena):** `MAP_SHARED` file mappings are
inherited shared; the inherited `Arc` is a private refcount over inherited
mappings plus now two inherited fds — all process-local state. No
`native/fork_child.rs` step, unchanged (6C2 §5).

**guest `fork(2)` children (transporting the arena) — the boundary that was
broken:** before the host self-exec, the child adds both arena fds to the
existing `HostFdFlagTransaction` (`prepared_host_fds`) exactly as
`kernel_arena`, `shared_futex_waiters`, `xsig`, and `aot_cache` already do:
clear `FD_CLOEXEC` for the spawn, restore the original flags if `execve`
returns. There is no per-child right-minting step at all — the fd *is*
inherited capability. P4-file proves this crossing end-to-end.

**SETEXEC successor (adoption):**

1. capsule metadata (`NativeReexecLiveArenaV2`) carries the unchanged
   `LiveArenaTransitV2` {schema, code_len, control_len, nonce} **plus** both
   fd numbers, their original fd flags, and per-fd `fstat` identity
   (dev/ino/size) — the `KernelArenaReexecAuthority` shape;
2. successor validates fd flags (`flags == original & !FD_CLOEXEC`), fstat
   identity, then `F_DUPFD_CLOEXEC`s each fd into the owner and restores the
   transport fds' flags — the exact `KernelArena::attach_reexec` sequence;
3. maps fresh aliases at arbitrary addresses by the same
   map→mprotect→clamp→validate route;
4. runs the **unchanged** V2 validation: outer object headers, then
   `LiveTranslationArenaView::adopt_discovered_in_place` nonce/schema/ABI/
   count/stride/alignment/overlap/bounds checks;
5. closes the transport fds after adoption (the dup is the retained handle).

Adoption is *authenticated*, not merely inherited: a wrong, recycled, or
tampered fd fails the fstat identity check, the header check, or the nonce
check, each with its existing named reason.

## W^X and I-cache authority — what changes, what is untouched

**Untouched:** the publisher-flush / consumer-local-invalidate authority
(preflight correction 5), the claim-bound RW write permit, the sole
token-gated READY store, `revoke_rx`/`protect_rx` on the RX alias
(`mach_vm_protect` operates on any mapping; P2/P6 prove revoke+restore on
this backing), the refusal to construct any W|X mapping, and the
post-mapping protection equality validation.

**Changed:**

- aliases come from `mmap`+`mprotect` of a shared file instead of
  `mach_vm_map` of a memory entry;
- both aliases' **max** protections are clamped (`set_maximum`), which the
  Mach design could not do — its code entry was minted RWX and only
  carrick's own guard kept W|X out. Here escalation of either alias is
  refused by the kernel (P6), and independently the kernel refuses
  simultaneous W|X on this backing at all (P6 honesty receipt). Net: W^X is
  strictly stronger than before;
- the RX alias transiently exists as `PROT_READ` (never writable) between
  `mmap` and `mprotect(R|X)`; no W|X window exists at any point.

## Teardown — the §8 hazard dissolves

The 6C2 §8(a) hazard was `MachSendRight::drop` unconditionally calling
`mach_port_deallocate` in whatever task runs it, so an `Arc<DarwinLiveArena>`
unwinding in a fork child would deallocate a parent-space name in the child's
IPC space, silently corrupting an unrelated small-integer port name.

In this design **no Mach name exists to deallocate**. Teardown is `munmap`
(address-space-local) plus `close` (fd-table-local): a fork child that
unwinds its inherited `Arc` unmaps *its own* inherited mappings and closes
*its own* fd-table entries, with zero effect on the parent's mappings, fds,
or the underlying object (which lives until every holder closes). The hazard
is dissolved by construction, not fixed by discipline; a
`fd_arena_teardown_in_fork_child_is_local` test pins it.

## What dies, what survives

**Dies (delete, no compatibility path — AGENTS.md "no backward compat"):**

- `MachSendRight` (and with it the §8 drop hazard), `VmMapping::map_entry`,
  `create_code_memory_entry`, `create_control_memory_entry`,
  `MapJitBootstrap` + `OwnedMmap`'s JIT-bootstrap use;
- `RegisteredPortVector`, `OolPortArray`, `register_port_names`,
  `RegisteredPortExecPlan`, `LiveArenaTransitRights`,
  `duplicate_transit_rights`, `transit_send_right_user_refs`,
  `send_right_user_refs`;
- the `posix_spawnattr_set_registered_ports_np` and `mach_port_get_refs`
  SPI declarations (nothing else uses them);
- the three-registered-slot constraint (`TASK_PORT_REGISTER_MAX`) and the
  slot-0 bootstrap-preservation choreography;
- the SETEXEC proofs whose *subject* dies:
  `failed_setexec_leaves_the_registered_port_vector_unchanged` (already
  demoted to kernel-behavior evidence by 6C2 §8(b)) and
  `failed_setexec_releases_the_duplicated_send_rights`;
- the fork-boundary blocker test's *refusal* assertion — the test survives
  inverted, asserting the child CAN now build the transport.

**Survives (per 6C2 §7, confirmed):**

- the entire V2 wire and portable protocol, untouched — geometry, directory,
  records, cursors, claims, tokens, the B3 census results;
- the 64-byte object headers and `LiveArenaTransitV2` (schema/lengths/nonce);
- `LiveArenaProcessView`, `DarwinLivePublishClaim`, the B2 publication
  authority, `revoke_rx`;
- all mechanism-agnostic 6C2 ownership plumbing: `OwnedNativeLiveArena`,
  `NativeLiveArenaEntry::{Launch, Resume}`, the single creation point, `Arc`
  retention through both tiers and clone threads, both `begin_guest_exec`
  forwarding sites, the capsule's `NativeReexecLiveArenaV2` field (extended
  with fds + identity);
- `failed_setexec_restores_the_prepared_fd_flags` — its subject
  (`HostFdFlagTransaction`) is now the arena's own transport, so it graduates
  from adjacent-subsystem proof to the arena's own failed-exec guard;
- `native/fork_child.rs` stays untouched.

## Failure modes (each fails closed with a named reason)

| failure | behavior |
|---|---|
| backing file create/`ftruncate`/mmap/mprotect/clamp fails (e.g. a future AMFI policy returning `EPERM`/`EACCES`) | named `io::Error` with the failing operation and errno; under the explicit `compiler` evidence policy the entry refuses before guest start (the C1/C2 fail-closed posture); in eventual default-on production the spec's rule applies — the arena is an optional accelerator, so creation failure falls through to the arena-absent run |
| region validation mismatch after mapping (the P2-shm silent-EXEC-strip shape, or an unexpected max) | named refusal from the existing `validate_protections` equality check; the candidate is unmapped and deallocated (transactional install, unchanged) |
| inherited fd flags drifted, fstat identity mismatch, wrong/recycled fd | named refusal (`kernel_arena` precedent strings), adoption fails, capsule resume fails closed |
| object header / nonce / directory / ABI mismatch | the existing named V2 refusals, unchanged |
| `posix_spawn` fails after fd preparation | `HostFdFlagTransaction` restores every prepared flag — guarded by the surviving SETEXEC test |
| fork child unwinds mid-teardown | process-local munmap/close only; no cross-process effect (pinned by test) |

## What would invalidate this design

- **A future macOS closing the `mprotect(R|X)` route for unsigned file pages
  in non-hardened ad-hoc processes.** This host is macOS 27.0 *beta*
  (26A5388g); the route is policy, not architecture. The mandatory
  post-mapping validation makes any such change fail closed with a named
  errno rather than corrupt, and the scratchpad probe crate is the per-OS
  requalification tool. Mitigation if it ever closes: the aot_cache replay
  transport (copy into `MAP_JIT`) remains the correctness fallback at the
  cost of zero-copy.
- **Adopting the hardened runtime** for the carrick binary: route B then
  requires `com.apple.security.cs.allow-unsigned-executable-memory`. Today
  carrick native explicitly runs ad-hoc without hardened runtime
  (`crates/carrick-native-darwin/src/jit.rs` states the same constraint for
  `MAP_JIT`), so this is an existing, not new, coupling.
- **Unified-buffer-cache writeback**: dirty pages of the unlinked backing
  files may generate background disk I/O that the anonymous Mach objects
  never did. Unmeasured in this round; Task 8's ABBA wall/CPU gate is the
  authority, and `F_GLOBAL_NOCACHE` or an APFS-purgeable strategy is the
  follow-up lever if it shows up. It cannot corrupt; it can only cost.
- **Task 7 fault classification**: the revoked-chunk abort on this backing
  must present as an instruction abort with PC==FAR exactly as the Mach-alias
  proof did; the BSD-visible signal is SIGBUS here. If the Mach exception
  shape differs in a way the classifier predicates cannot express, Task 7
  must re-derive them on this backing before any gate opening.
- **Attach-cost growth**: 10–17 µs today includes only an 8 KiB validation
  read; if adoption validation grows page-touching work, re-measure against
  the <1 ms gate.

## Implementation surface (pointer, not a plan)

The implementation slices, red-first test names, and gates live in the
amendment appended to
`docs/superpowers/plans/2026-08-05-native-live-translation-arena-task6.md`
(Tasks 6T1/6T2 and the reopened 6C2 completion). Tasks 6D/6E/6F/7 are
unaffected in scope and keep inheriting the same "no runtime-on evidence
before Task 7" rule.
