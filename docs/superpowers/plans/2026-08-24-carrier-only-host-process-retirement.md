# Carrier-only host-process retirement implementation plan

**Controller:** `handoff.md`

**Architecture source:** `docs/hvpatch-carrier-only-process-plan.md`
**Owner directive (2026-08-24):** retire Carrick-created helper and guest host
subprocesses now that the Carrick kernel owns process semantics.

## Outcome and fail-closed invariant

Carrick has one process model: guest tasks, processes, address spaces, exec,
waits, signals, sessions, process groups, tty ownership, and PID namespaces are
objects in the Carrick kernel graph and execute in one VM carrier.

- A foreground run has exactly one Carrick host process: its carrier.
- A detached launch may create one carrier, but after the initiating CLI exits
  exactly one long-lived process is attributable to the container.
- The Docker API has one server plus one carrier per live container. It does not
  create helper descendants or peer carriers for guest `exec`.
- No runtime path creates an NsSupervisor, FileAuthority helper, interactive
  supervisor, winsize watcher, cleanup reaper, debugger, or guest host process.
- Guest identifiers never flow to host `kill`, `wait`, process-group,
  credential, namespace, or path-authority operations. Host containment remains
  the primary boundary; typed intra-guest authority remains co-equal.

Carrier birth, explicit operator tooling (LLDB/DTrace/APFS administration), and
external conformance orchestration are not guest subprocesses. They must live
behind typed CLI/orchestrator boundaries and cannot be called from the carrier.

## Phase 0: make topology measurable and fail closed

1. Add a compiler/source gate that rejects production runtime/VMM references to
   host process creation and the retired host-fork ABI. It must distinguish
   unit fixtures and explicit operator tools from product execution.
2. Add a run-ID-scoped topology gate covering foreground raw/private, TTY,
   detached, guest fork storm, and container exec. Each steady-state sample must
   contain exactly one carrier; scoped cleanup must leave zero.
3. Preserve exact artifact receipts: source HEAD, binary SHA-256, CDHash,
   LC_UUID, hypervisor entitlement, and `__dof_carrick`.

## Phase 1: delete helper topology already made obsolete by HVPatch

1. Delete the FileAuthority detached placement, environment hatch, IPC helper,
   double fork, and cross-process transport tests. Keep one direct serialized
   `FileAuthorityCore` capability and its semantic/model coverage.
2. Collapse NsSupervisor for normal and raw HVPatch runs. Initialize namespace
   and kernel state in the carrier; publish Running/Exited from carrier boot and
   terminal finalization. Retain the legacy region only as a temporary read
   compatibility surface until carrier control replaces cross-carrier exec.
3. Reduce `HostForkCoordinator` to start-only signal-pump control, then use the
   compiler to enumerate and delete every obsolete restart/fork hook.
4. Replace carrier-spawned deadlock LLDB with a durable diagnostic trigger for
   external `carrick debug` collection.

Each item is a separate logical commit after focused tests and review.

## Phase 2: add the authenticated carrier control plane

Create a private, versioned Unix endpoint beside container state. The endpoint
directory is mode 0700 and the socket mode 0600. Every request authenticates the
peer UID, container identity, carrier generation, and nonce before it can mint
kernel authority. A stale generation fails closed.

Initial commands:

1. health and immutable carrier identity;
2. kernel process snapshot/top;
3. exact guest task/process-group signal;
4. wait for container/task terminal state;
5. create a logical exec task with a new MM and inherited/selected file table;
6. framed stdin/stdout/stderr and detached-log attachment;
7. allocate/adopt a PTY and publish winsize;
8. archive read/write through VFS capability handles;
9. graceful container shutdown.

The endpoint accepts no host PID, fd number, raw path, or ambient credential as
guest authority. Requests lower into typed kernel/VFS capabilities.

## Phase 3: route lifecycle and Docker API through the carrier

1. Replace `carrick exec`'s `CARRICK_JOIN_REGION` peer VM with logical task
   admission through carrier control.
2. Route stop, kill, wait, and rm through exact Linux signal and wait semantics
   in the kernel. Host SIGKILL is containment fallback only after an
   authenticated carrier is irrecoverably unresponsive.
3. Route Docker exec, archive, and top directly through carrier control.
4. Replace lifecycle/image self-spawn wrappers with library calls. Only a typed
   `CarrierLauncher` may create a carrier.
5. Migrate state from `supervisor_pid`/`init_pid` to `carrier_pid`, generation,
   control endpoint, and terminal receipt. Read old records transactionally;
   never treat a reused host PID as the recorded carrier.
6. Delete the file-backed PID join region once no control path consumes it.

## Phase 4: move interactive job control into the kernel

1. Allocate the PTY in the carrier and run `PtyRelay` as a carrier thread.
2. Store controlling terminal, session, foreground process group, and winsize in
   the kernel graph/TTY object.
3. Lower `TIOCSCTTY`, `TIOCSPGRP`, `TIOCGPGRP`, `setsid`, `setpgid`, SIGTTIN,
   SIGTTOU, Ctrl-C, and Ctrl-Z without addressing host process groups by guest
   identifiers.
4. Poll host winsize from the relay thread; delete the watcher process.
5. Delete `interactive_supervisor.rs` and every launcher/supervisor/runtime
   child handshake while preserving the complete interactive TTY test suite.

## Phase 5: excise the latent host-fork ABI and standalone runners

Compiler-drive deletion in this order:

1. old single-thread/split runtime loop fork callers;
2. `SyscallTrap::fork`, `ForkOutcome`, and fork admission compatibility;
3. `ThreadedEngine` host-fork/vfork rebuild hooks;
4. `HostForkCoordinator`, `PreparedHostFork`, and pump fork state;
5. AArch64 and x86 `libc::fork` implementations;
6. VMM freeze/rebuild/shared-vfork hooks and host-fork child state;
7. the standalone KVM runner's host-fork path, by moving it to the shared
   kernel loop or retiring the standalone product entrypoint;
8. host-fork-only no-unwind exits, reset hooks, comments, and telemetry.

Keep logical `ProcessForkRequest`, kernel transactions, task/MM cloning,
vfork suspension/release, and logical wake-registry creation.

## Phase 6: remove remaining runtime-spawned utilities

1. Replace detached `/bin/rm -rf` with rename-to-trash, bounded in-carrier
   cleanup, and next-start orphan sweeping. Measure exit wall and disk residue;
   do not silently restore the historical ~1.3 s synchronous teardown.
2. Replace `scutil` DNS discovery with an in-process SystemConfiguration
   provider or an authenticated launch snapshot prepared outside the carrier.
3. Replace platform availability subprocess probes with direct device/sysctl
   checks.
4. Isolate APFS, debuggers, trace tools, Docker/Lima, and compiler helpers in
   explicit operator/orchestrator modules that cannot link into carrier launch.

## Verification order

At every slice:

1. red-first focused unit/static test;
2. focused crate tests and all-target checks;
3. `just fmt-check`, `just lint-domains`, then serialized `just ci`;
4. signed build and exact provenance receipt;
5. one-carrier topology gate;
6. `carrick trace` for reproducible lifecycle behavior and `carrick debug`
   (live/core) for carrier-only state and Heisenbugs;
7. fork/exec/exit, PID namespace/subreaper, wait, session/process-group, and TTY
   reducer batteries;
8. full exact conformance probes, then ecosystem closure, serialized against
   the native-arm64 Docker oracle;
9. canonical performance measurement, with correctness closed before the
   within-2x gate is claimed.

## Non-completion conditions

The program is not complete while any of these remain:

- a steady-state run has more than one Carrick process;
- `carrick exec` creates another VM/carrier;
- a guest identifier reaches a host process-control syscall;
- any production runtime/VMM path can call `fork`, `vfork`, `posix_spawn`, or
  process `Command`;
- TTY/job-control success depends on a host supervisor or host process group;
- helper-free topology passes only static checks but fails a signed reducer;
- exact conformance, ecosystem closure, or the within-2x gate is unmeasured.
