# Native PID-Preserving Self-Reexec Design

**Date:** 2026-07-13

**Status:** approved implementation design

## Purpose

After a real host `fork(2)`, Darwin permits only a narrow child-side API surface
until `execve(2)`. Carrick currently performs a guest `execve` by replacing the
emulated Linux image inside the same Darwin process. That preserves Linux state,
but it does not reset copied Apple userspace runtime state.

The unsafe post-fork-thread experiment proved that one small pthread reducer can
work, while Node, Go, and CPython repeatedly trap in `libdispatch` after their
fork-to-exec children create threads. The stable fatal record resolves to a
libdispatch client trap with `_dispatch_sema4_wait` as the caller. This is not a
Carrick-owned lock or registry that Carrick can safely reconstruct.

For a fork-child guest `execve`, Carrick will therefore `execve` the Carrick host
binary itself. A host exec preserves the host PID while creating fresh libc,
libpthread, and libdispatch state. A versioned inherited capsule reconstructs
only the Linux process state that survives exec.

This design prioritizes ordinary `--fs host` workloads and host-backed files,
pipes, sockets, and stdio. Unsupported surviving emulated descriptor classes
fail before the point of no return. They remain explicit parity work rather than
blocking the real-workload closure.

## Goals

- Preserve the guest and host PID across a fork-child guest `execve`.
- Start the replacement guest image in a fresh Darwin process runtime.
- Preserve the same host-backed root filesystem overlay and Linux exec-surviving
  process state.
- Preserve non-`CLOEXEC` ordinary host-backed descriptors, including descriptor
  aliases and open-file-description sharing.
- Reject unsupported survivor state before terminating siblings or retiring the
  old image.
- Keep malformed or stale internal resume requests fail-closed.
- Remove the post-fork thread guard only after reducers and real workloads prove
  the supported path.

## Non-goals for the first implementation

- Serializing the in-memory filesystem backend.
- Preserving non-`CLOEXEC` epoll, eventfd, timerfd, signalfd, inotify, pidfd,
  io_uring, AIO, synthetic netlink, or other emulated anonymous-inode state.
- Making a public checkpoint/restore format.
- Improving HVF/VMM performance or changing non-native execution.
- Claiming complete Linux exec parity before the remaining state classes are
  implemented and proved.

## Selected boundary

Self-reexec is used only when all of these are true:

1. the active backend is native Darwin;
2. the current host process is a guest-fork child;
3. the guest reaches a successful, already-validated `execve`; and
4. the process state is eligible for the capsule version implemented by the
   binary.

Initial-process exec and native exec before any guest fork continue through the
in-process replacement path. Other backends are unchanged.

The existing post-fork clone guard remains fail-closed during development. The
unsafe diagnostic bypass is not the production mechanism and is removed when
self-reexec passes its promotion gates.

## Capsule transport and trust boundary

The old Carrick image creates a kernel-backed anonymous regular file, writes the
capsule, rewinds it, and clears `FD_CLOEXEC` on that fd only for the host exec.
The new Carrick image receives the fd number through a private, exact internal
argument and enters a runtime resume function directly. It must not run the
normal engine resolution or container supervisor path, because either could
fork a replacement host process and change the PID.

The capsule has a small fixed header:

- magic identifying a Carrick native exec capsule;
- schema version;
- payload length with a conservative upper bound;
- SHA-256 of the payload; and
- a one-shot nonce bound to the private resume argument.

The resume path validates the fd with `fstat`, requires a regular file, checks
the header, length, checksum, version, and nonce, consumes the payload once, and
closes the capsule fd. Invalid input exits with a fatal internal-resume error; it
never falls through to a user command. The format is internal and version-locked
to the producing binary, not a compatibility promise.

The payload contains typed semantic records, never a dump of Rust object memory.
It includes:

- the resolved guest executable request, argv, env, and a content identity used
  to detect a changed target during reconstruction;
- the native execution plan and bounded runtime options needed to enter DSR;
- the durable host-filesystem overlay authority;
- cwd, root/chroot view, umask, credentials, supplementary groups, rlimits,
  process identity, and launch policy that Linux preserves across exec;
- Linux signal mask, pending state, and dispositions that survive exec (caught
  handlers reset to default; ignored dispositions remain ignored);
- namespace/process-arena attachment identifiers required to retain the same
  guest PID and parent/child relationships; and
- supported non-`CLOEXEC` descriptor records.

Memory mappings, alternate signal stack, caught signal handlers, thread-local
state, robust-list state, and per-thread DSR state are intentionally absent or
reset because Linux exec replaces them.

## Root filesystem lifetime

The selected first slice supports `FsBackendKind::Host`. The on-disk scratch is
already Carrick's single filesystem source of truth, and
`HostFsBackend::attach` can reopen an existing scratch without extraction.

The backend will expose a reexec authority for its current contained root. For
an ephemeral `TempDir`, handoff must transfer ownership so dropping the old Rust
backend during host exec preparation cannot remove the scratch. The resumed
backend reopens the same directory, reacquires the per-run lock, and becomes its
new cleanup owner. A directory fd may be inherited as an additional containment
anchor; the resumed path still verifies the resolved root and lock identity
before attachment.

The memory backend is rejected before the point of no return in capsule version
1. This is an explicit limitation: native conformance and the priority
ecosystems use `--fs host`, while serializing a fork-coherent in-memory overlay
would be a separate checkpoint/restore project.

## Descriptor eligibility and identity

Eligibility is evaluated against the logical post-exec fd table without first
mutating the live dispatcher. `CLOEXEC` descriptors are omitted. Each surviving
guest fd records its descriptor flags and a stable open-description ID so duped
guest fds reconstruct as aliases of one description.

Capsule version 1 accepts:

- stdio;
- host-backed regular files;
- host pipes and ptys whose kernel fd is inheritable;
- host sockets; and
- host-backed message queues only if their existing path/metadata contract can
  be reconstructed without creating a second queue identity.

For each accepted description, Carrick clears host `FD_CLOEXEC` only during the
final handoff and records the inherited host fd plus Linux metadata that Darwin
cannot provide. The resumed process immediately duplicates/adopts the handles
into owned Carrick descriptions and restores host close-on-exec policy.

Any surviving unsupported description rejects the guest exec with
`EOPNOTSUPP` before siblings or the old image are retired. This is deliberately
narrow and honest. Most runtime-private watchers are already `CLOEXEC`, so they
disappear under normal Linux exec semantics and do not block ordinary workload
handoff.

## State reconstruction

The private runtime resume entry performs these steps in the fresh host image:

1. validate and consume the capsule;
2. adopt inherited overlay and host fd authorities;
3. construct a new `SyscallDispatcher` and runtime network attachment;
4. restore exec-surviving process, credential, signal, namespace, policy, and fd
   state through typed subsystem APIs;
5. resolve and reload the executable from the reattached guest filesystem;
6. verify its recorded content identity;
7. build the new address space, vDSO/vvar, stack, and fresh DSR translator;
8. publish `/proc` identity and notify a waiting vfork parent if applicable;
9. mark the namespace member execed; and
10. enter the guest at the replacement entry point with one guest thread.

Construction is transactional inside the new process: no guest code runs until
all validation and reconstruction succeeds. A failure here is fatal because the
host exec has already crossed the rollback boundary; it is reported by the
async-safe native fatal path with a capsule stage identifier.

## Point of no return and rollback

Before changing the old image, Carrick must:

- resolve and validate the target ELF and interpreter;
- compute and validate the post-exec state snapshot;
- reject unsupported surviving state;
- create, write, checksum, rewind, and reread the capsule;
- verify the current executable path and construct host argv/env;
- prepare every inherited fd and record its original `FD_CLOEXEC` flag; and
- prove the replacement native address-space plan is representable by the fresh
  process.

Only then does the exec-winning thread terminate guest siblings. Immediately
before host `execve`, it clears `FD_CLOEXEC` on the capsule and approved survivor
fds. If host `execve` returns an error, it restores every changed fd flag, closes
the capsule, and returns the corresponding Linux errno to the intact old guest
image. The old mapped image and dispatcher are not retired in place.

Successful host exec is the point of no return. The fresh process either enters
the new guest image or exits loudly with a stage-specific fatal record.

## Security and containment

- The private resume command is hidden from normal help and requires a valid
  one-shot capsule; possession of an arbitrary fd number is insufficient.
- All lengths, counts, fd numbers, enum tags, strings, and vectors are bounded
  before allocation or adoption.
- No raw host path from an unvalidated capsule grants filesystem authority.
  Attachment is checked against the inherited root anchor and lock identity.
- Surviving host fds are validated with `fstat`/socket inspection against their
  declared semantic type before adoption.
- The resume process inherits the same container policy and seccomp model; it
  may not silently become unconfined.

Carrick remains experimental and is not a hardened boundary. These checks keep
the private path fail-closed and prevent accidental exposure from weakening the
existing containment model.

## Verification and promotion

Implementation is promoted in this order:

1. capsule codec corruption, version, bounds, and one-shot unit tests;
2. a host-only PID-preserving self-reexec reducer;
3. red-first `forkexecpthread`, proving host PID stability and post-exec thread
   creation;
4. a state probe covering cwd, umask, ignored signal, signal mask, one duped
   non-`CLOEXEC` pipe/file, `CLOEXEC` closure, parent wait, and vfork completion;
5. signed native probe gate;
6. repeated Node, Go, and CPython lanes, serial and loaded;
7. removal of the unsafe bypass and post-fork thread guard; and
8. the campaign's complete conformance and bless ladder.

The campaign ledger records only measured results. Any unsupported descriptor
encountered by a real workload becomes the next implementation slice rather
than a reason to weaken validation.

