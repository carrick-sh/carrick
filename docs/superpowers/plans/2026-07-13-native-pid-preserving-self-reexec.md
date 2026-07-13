# Native PID-Preserving Self-Reexec Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILLS: Use
> `superpowers:executing-plans`, `superpowers:test-driven-development`,
> `superpowers:systematic-debugging`, and `carrick-native-debug`. Preserve the
> fail-closed production guard until the promotion task passes.

**Goal:** Replace a fork-child native guest `execve` with a host self-`execve`
that preserves PID and Linux exec-surviving state while resetting Darwin
libpthread/libdispatch state.

**Architecture:** Before the guest exec point of no return, snapshot an eligible
post-exec process into a versioned anonymous-file capsule and prepare ordinary
host-backed survivor fds. The same Carrick binary host-execs into a private
resume entry, validates the capsule, reattaches the durable host filesystem,
reconstructs a fresh dispatcher and native DSR image, then enters the guest.
Unsupported surviving emulated descriptors return `EOPNOTSUPP` before mutation.

**Tech stack:** Rust 1.96, serde/JSON, SHA-256, Darwin `execve`/`fcntl`/`fstat`,
cap-std host filesystem backend, Carrick native DSR, static AArch64 musl probes,
signed conformance lanes, and native arm64 Docker oracle evidence.

**Controller design:**
[`docs/superpowers/specs/2026-07-13-native-pid-preserving-self-reexec-design.md`](../specs/2026-07-13-native-pid-preserving-self-reexec-design.md)

## Global constraints

- Never expose post-fork guest thread creation by default before self-reexec is
  repeatably proved.
- Preserve host PID; do not delegate resume to a child or supervisor process.
- Do not serialize Rust object layouts or unsafe pointers.
- Validate eligibility without mutating the live dispatcher.
- Do not run destructors between the final handoff preparation and host exec.
- Reject memory-fs and unsupported non-`CLOEXEC` state before sibling teardown.
- Never run Carrick and Docker concurrently. Stamp and reap every run.
- Build and sign through `just build` before any guest execution.
- Keep measured evidence in `docs/native-default-conformance-campaign.md`.
- Commit behavior changes and their red/green proof in narrow logical commits.

## Task 1: Add and harden the capsule codec

**Files:**

- Add: `crates/carrick-runtime/src/native_exec_capsule.rs`
- Modify: `crates/carrick-runtime/src/lib.rs`
- Modify: `crates/carrick-runtime/Cargo.toml`

**Interfaces:**

- `NativeExecCapsuleHeader` with magic, version, payload length, digest, nonce.
- Typed `NativeExecCapsuleV1` payload and bounded nested records.
- `write_capsule(fd, payload)` and `read_capsule_once(fd, nonce)`.

- [ ] Write codec tests first for round trip, wrong magic/version/nonce,
  checksum corruption, truncation, trailing data, oversized lengths/counts,
  non-regular fds, and second consumption.
- [ ] Run the focused tests and preserve the RED caused by the missing codec.
- [ ] Implement the smallest bounded codec. Use existing maintained crates;
  never add an ad-hoc crypto implementation or raw FFI.
- [ ] Run focused tests, runtime clippy, and fmt-check.

## Task 2: Prove host PID-preserving reexec independently

**Files:**

- Modify: `crates/carrick-cli/src/args.rs`
- Modify: `crates/carrick-cli/src/commands.rs`
- Modify: `crates/carrick-runtime/src/lib.rs`
- Add/modify: focused CLI integration tests

**Interfaces:**

- Hidden `__native-exec-resume --capsule-fd <typed-fd> --nonce <nonce>` entry.
- `carrick_runtime::resume_native_exec_capsule(...)` runtime entry.

- [ ] Add a test-only minimal capsule mode that records PID before host exec,
  enters the hidden resume path, and reports PID after resume.
- [ ] Prove RED before the private entry exists.
- [ ] Dispatch the hidden command before normal engine/container setup. It must
  validate a capsule and must never appear in normal help.
- [ ] Invoke the current Carrick executable with `execve`, using an argv/env
  built before the handoff boundary.
- [ ] Prove the PID is identical, the capsule is one-shot, and invalid resume
  invocations fail closed.

## Task 3: Export and reattach host-filesystem authority

**Files:**

- Modify: `crates/carrick-runtime/src/fs_backend.rs`
- Modify: `crates/carrick-runtime/src/dispatch/fs.rs`
- Modify: `crates/carrick-runtime/src/dispatch/mod.rs`
- Modify: `crates/carrick-runtime/src/native_exec_capsule.rs`

**Interfaces:**

- `HostFsReexecAuthority` with an inherited root anchor, stable scratch
  identity, and cleanup-lock transfer data.
- Read-only dispatcher snapshot and fresh-dispatcher restore APIs.

- [ ] Add tests that an ephemeral host backend exports authority, survives host
  reexec without early deletion, reattaches to the exact same root, preserves a
  mutation, and is cleaned once by the resumed owner.
- [ ] Add a red test proving an unrelated directory cannot be substituted.
- [ ] Implement ownership transfer without weakening cap-std containment.
- [ ] Make memory-fs export return typed `EOPNOTSUPP`.
- [ ] Verify focused fs tests and targeted clippy.

## Task 4: Snapshot supported descriptors without mutation

**Files:**

- Modify: `crates/carrick-runtime/src/dispatch/fd_table.rs`
- Modify: `crates/carrick-runtime/src/dispatch/fs.rs`
- Modify: `crates/carrick-runtime/src/dispatch/fs/state.rs`
- Modify: `crates/carrick-runtime/src/native_exec_capsule.rs`

**Interfaces:**

- `snapshot_post_exec_fd_table()` producing stable description IDs, guest fd
  flags, inherited host fds, and original host `FD_CLOEXEC` flags.
- `restore_post_exec_fd_table(snapshot)` for a fresh dispatcher.

- [ ] Add red tests for stdio, regular file offset, pipe communication, socket,
  dup aliasing, guest `FD_CLOEXEC`, and shared open-description flags.
- [ ] Add table-driven rejection tests for every unsupported surviving
  `OpenDescription` variant; the same variants with guest `CLOEXEC` must not
  block exec.
- [ ] Implement the read-only eligibility walk and typed records.
- [ ] Implement transactional host-fd flag preparation and rollback.
- [ ] Implement fresh-dispatcher adoption with type validation.
- [ ] Run fd-table/fs tests, runtime clippy, and fmt-check.

## Task 5: Snapshot Linux exec-surviving process state

**Files:**

- Modify: `crates/carrick-runtime/src/dispatch/{mod.rs,proc.rs,creds.rs,signal.rs,fs.rs}`
- Modify: `crates/carrick-runtime/src/seccomp.rs`
- Modify: `crates/carrick-runtime/src/native_exec_capsule.rs`

**Interfaces:**

- `snapshot_native_exec_state()` computes the logical post-exec state.
- `restore_native_exec_state()` installs it into a fresh dispatcher.

- [ ] Add subsystem tests covering cwd/root, umask, uid/gid variants,
  supplementary groups, rlimits, comm/executable identity, ignored versus
  caught signal dispositions, mask/pending state, and policy/seccomp survival.
- [ ] Add explicit tests that altstack, caught handlers, memory mappings,
  per-thread state, and robust-list state reset rather than survive.
- [ ] Implement named typed snapshot/restore methods in each owning subsystem;
  do not expose raw locks or whole dispatcher serialization.
- [ ] Verify unit tests, lint-domains, clippy, and fmt-check.

## Task 6: Reconstruct a fresh native guest from the capsule

**Files:**

- Modify: `crates/carrick-runtime/src/native_darwin.rs`
- Modify: `crates/carrick-runtime/src/native_exec_capsule.rs`
- Modify: `crates/carrick-runtime/src/execute.rs`

**Interfaces:**

- A resume launch context captured at the initial native boot.
- Fresh-process ELF resolution, content identity verification, image mapping,
  DSR translator creation, namespace attachment, and guest entry.

- [ ] Add a focused resume test with a minimal host-fs guest image.
- [ ] Reattach the exact overlay and rebuild the runtime network/namespace
  authority without creating a new guest process.
- [ ] Resolve the executable and interpreter again and verify the recorded
  identity before mapping.
- [ ] Construct a fresh dispatcher and install all snapshot state.
- [ ] Map the replacement image and enter DSR with one guest thread.
- [ ] Add stage-specific fatal records for every post-host-exec failure.
- [ ] Verify the fresh path under the signed CLI.

## Task 7: Integrate self-reexec at the guest exec boundary

**Files:**

- Modify: `crates/carrick-runtime/src/native_darwin.rs`
- Modify: `crates/carrick-runtime/src/native_exec_capsule.rs`
- Modify: `crates/carrick-runtime/src/namespace/pid.rs`

**Interfaces:**

- `prepare_native_fork_child_exec(...)` before sibling teardown.
- `commit_native_fork_child_exec(...) -> !` for successful host exec.

- [ ] Extend `forkexecpthread` or add `forkexecstate` to report host/guest PID,
  cwd, umask, ignored signal, mask, duped pipe/file behavior, `CLOEXEC` closure,
  parent wait, and worker/join success.
- [ ] Prove the probe RED on the guarded production binary and GREEN only when
  routed through actual host self-reexec.
- [ ] Prepare the target image and complete capsule eligibility before sibling
  termination.
- [ ] Route only native fork-child exec through the new boundary.
- [ ] On host `execve` failure, restore every fd flag and return a Linux errno
  to the intact old guest.
- [ ] Prove ordinary in-process exec and all non-native backends are unchanged.

## Task 8: Close vfork and namespace lifecycle semantics

**Files:**

- Modify: `crates/carrick-runtime/src/native_darwin.rs`
- Modify: `crates/carrick-runtime/src/namespace/pid.rs`
- Modify: relevant conformance probes/tests

- [ ] Add red-first tests for parent wait, guest PID continuity, `/proc/self`,
  child-watch continuity, and vfork parent release after successful host exec.
- [ ] Transfer vfork completion through a kernel-backed inheritable authority;
  do not depend on old-process destructors or in-memory callbacks.
- [ ] Mark the same namespace member execed in the resumed image.
- [ ] Run the focused namespace and vfork suites repeatedly.

## Task 9: Promote the supported path

**Files:**

- Modify: `crates/carrick-runtime/src/native_darwin.rs`
- Modify: `docs/native-default-conformance-campaign.md`

- [ ] Run `forkexecpthread` and state/PID probes at least ten times serially and
  under the smoke lane's normal load.
- [ ] Run the signed native probe gate.
- [ ] Run Node V8/app, Go build/runtime/sync, and CPython threading/subprocess
  lanes serially, then at four workers, sampling any flip at least three times.
- [ ] If a priority workload exposes an unsupported survivor class, implement
  that class with red-first tests before promotion.
- [ ] Remove `CARRICK_NATIVE_UNSAFE_POSTFORK_THREADS` and the blanket post-fork
  clone rejection so the tested and production paths are identical.
- [ ] Re-run all focused and ecosystem gates without any bypass.
- [ ] Record exact revisions, commands, worker counts, verdicts, and artifact
  paths in the campaign ledger.

## Task 10: Resume the complete native conformance ladder

- [ ] Run `just ci`.
- [ ] Run native smoke at one worker and four workers, with loaded repeats.
- [ ] Run Node, Go, CPython, then full LTP, fixing broad blockers before isolated
  assertions.
- [ ] Run the complete 2,127-suite native candidate serially and at four workers.
- [ ] Classify every non-MATCH row under the approved bless policy.
- [ ] Bless `scripts/conformance/baseline.native-dsr.jsonl` only from the
  reviewed full run.
- [ ] Run the full post-bless gate and update the campaign ledger with final
  measured proof.

