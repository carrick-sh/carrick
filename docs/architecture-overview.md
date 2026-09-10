# Carrick Kernel Architecture

Carrick runs Linux user space above Carrick's own kernel graph. There is no
guest Linux kernel and no one-Darwin-process-per-Linux-process mapping. On the
reference macOS/Apple Silicon lane, one carrier owns one HVF VM; Linux
processes, threads, address spaces, namespaces, descriptors, waits, and signals
are objects and transactions inside Carrick.

The host operating system and virtualization framework are hardware and
facility providers. They execute guest instructions, back memory, store files,
wait for readiness, and transmit bytes. They do not define Linux identity,
lifecycle, or policy. That separation is the central architectural rule.

This page describes the current HVPatch unified-kernel model. See
[the HAL guide](hal.md) for platform-specific backend details,
[the syscall map](syscalls-emulation-map.md) for interface coverage, and
[the conformance guide](conformance-testing.md) for what each test lane proves.

> [!NOTE]
> Carrick is experimental and incomplete. The macOS/HVF AArch64 lane is the
> reference implementation; Linux/KVM, FreeBSD/bhyve, NetBSD/NVMM, and x86_64
> support remain active bring-up work. None of these paths is a hardened trust
> boundary.

---

## 1. One Carrier, One VM, One Kernel Graph

A Carrick runtime instance has three different kinds of state:

- the **carrier**, a host process that owns process-wide host facilities;
- the **VM**, supplied by HVF, KVM, bhyve, or NVMM and used to execute guest
  instructions and project physical memory;
- the **kernel graph**, Carrick-owned objects for containers, namespaces,
  processes, tasks, threads, address spaces, files, signals, waits, and IPC.

Multiple container roots and Linux process trees can coexist in that graph. A
Linux PID is a Carrick ID scoped to its container, not the carrier's host PID.
Creating a guest process does not create another carrier or another VM. Each
container owns its initial UTS and network namespace objects before its root is
published, and `uname`, `/sys/class/net`, rtnetlink, and `/proc/net` resolve
those views through the calling task. This isolates those namespace surfaces;
it does not turn the experimental runtime into a hardened trust boundary.

```text
host application or carrick CLI
  -> RunRequest / RunSpec
  -> carrier + selected VMM
  -> Carrick kernel graph
       |- container / namespace trees
       |- tasks, threads, process groups, sessions
       |- address spaces and frame authority
       |- file descriptions, VFS, sockets, IPC
       `- waits, signals, timers, and observations
```

The kernel is BKL-free. Subsystems use their own locks and typed transaction
boundaries rather than a global dispatch lock. Operations that span
subsystems—fork, exec, address-space publication, task exit—prepare state,
validate identities and generations, then commit or roll back as one logical
kernel transition.

Non-interactive workloads can overlap inside the carrier. Interactive `-t`
sessions still depend on process-wide host terminal and SIGWINCH facilities,
so Carrick admits only one interactive session at a time rather than allowing
one container to overwrite another's route.

## 2. Guest Execution and the Trap Boundary

Carrick loads an unmodified Linux ELF image, builds its Linux stack and
auxiliary vector, and enters guest user mode. On macOS/Apple Silicon, the
reference path uses `Hypervisor.framework` to execute AArch64 instructions at
guest EL0. A small Carrick-owned EL1 environment supplies exception vectors,
page-table maintenance, and selected syscall-shim fast paths; it is not a Linux
kernel.

The ordinary control flow is:

```text
guest EL0 instruction stream
  -> Linux syscall or architectural fault
  -> Carrick EL1 vector/shim when required
  -> VMM exit into the carrier
  -> architecture-neutral syscall/fault frame
  -> Carrick kernel dispatch
  -> guest-visible return value, signal, block, or lifecycle transition
```

The VMM backend owns register access, VM entry/exit, interrupt or kick
mechanics, and stage-2 projection. The shared guest-ISA engines normalize that
machine state into Carrick's trap contract. The runtime then evaluates kernel
policy and dispatches the operation against the current task, address space,
credentials, file table, namespaces, and other kernel objects.

Syscalls are not forwarded blindly to the host. A handler implements Linux
semantics and may use a typed host facility underneath—for example kqueue or
epoll as a wake source, a host socket as a byte transport, or an APFS file as
storage. Linux error precedence, identity, readiness, and lifetime stay in
Carrick.

## 3. Kernel-Owned Identity and Lifecycle

Carrick keeps host and guest identity in separate domains. Important identities
include:

- `TaskKey` and `ThreadKey`, generation-bearing kernel object identities;
- `MmId`, the identity of a Linux address space;
- Linux-visible PID, TID, TGID, PGID, and SID values;
- unrelated host process and pthread identities used only to operate the
  carrier.

Cross-task operations authenticate the live kernel object and generation
before acting. A numeric Linux ID is not permission to target a same-numbered
host process.

Guest `fork`, `clone`, and `clone3` create or share Carrick objects according to
Linux flag semantics. Process fork prepares child identity, address-space
inheritance, file descriptions, signals, credentials, namespaces, waits, and
backend projection before the child becomes runnable. Failure unwinds the
prepared transaction; it does not leave a half-published task.

`exec` replaces the calling task's image while preserving the Linux process
identity and applying Linux sibling, signal, close-on-exec, and publication
rules. Exit and wait publish Carrick-owned lifecycle events. Signal routing,
process groups, sessions, `/proc`, resource limits, and child accounting read
the kernel graph rather than synthesizing Linux state from host process tables.

## 4. Non-Identity Memory and Transactional Publication

HVPatch memory is deliberately non-identity. The following domains must never
be substituted for one another:

- **guest virtual address (VA):** the address Linux user space observes;
- **stage-1 IPA:** the output of the current Linux address space's stage-1
  translation;
- **global-frame IPA:** a reusable VM-wide physical identity for a frame;
- **host address/backing object:** the carrier resource that stores the bytes;
- **owner generation:** the authority proving that the current host owner may
  act on the frame.

A lookup begins with the live address space and its stage-1 translation, then
authenticates the exact current frame owner generation. Feeding a guest VA into
an IPA lookup, treating an old alias as current, or accepting an unqualified
host address would cross authority domains and can corrupt another task.

Anonymous reservations are semantic VMA metadata and materialize private
backing on demand. Carrick does not reserve a full physical arena per Linux
process and does not use a VM-wide shared-zero frame as an implicit COW source.
Fork inheritance records whether each range is shared, copied, preserved,
zeroed, or omitted. Writable private inheritance is projected through
stage-1 permission state and Carrick's frame/COW authority.

Publishing a mapping is one rollback-capable transaction across:

1. semantic VMA state;
2. stage-1 translation;
3. stage-2/global-frame projection;
4. frame inventory and owner-generation state.

Page-table coalescing additionally requires both contiguous children and an
output address aligned for the parent block. A partially published or
generation-mismatched mapping is an invariant failure, not a best-effort
condition.

## 5. Threads, Executors, and vCPU Leases

Each logical guest thread has a host pthread representation so it can block on
host facilities without a global scheduler lock. Hardware vCPUs are different:
they are bounded, reclaimable leases managed by the carrier rather than
permanent property of a Linux thread.

A runnable guest thread acquires an appropriate vCPU lease, projects its task
and address-space state, enters the guest, and returns to Carrick on a trap,
fault, kick, or lifecycle boundary. Selected long blocking waits release their
lease even when capacity currently appears available, allowing later runnable
threads to make progress. The thread reacquires and revalidates execution state
before returning to guest code.

Fork and exec participate in explicit admission, quiescence, and cancellation
protocols. Process-fork admission must win before waiting for a child vCPU
lease; otherwise competing fork operations can consume capacity while each
waits for another slot. Identity-aware drain/freeze operations prevent new or
stale registrations from crossing a lifecycle transaction.

Host pthreads and VMM vCPUs are execution resources. Carrick's task registry,
run state, wait queues, signal state, and scheduler decisions remain the Linux
authority.

## 6. VFS, Networking, Events, and Host Capabilities

Carrick's VFS merges OCI layers, supplies synthetic kernel filesystems, tracks
mount and path state, and owns Linux file descriptions and descriptor tables.
The optional host filesystem mode is capability-scoped through `cap-std`; a
host path or descriptor is backing, not a substitute for Linux path or file
lifetime semantics.

Sockets follow the same rule. Host BSD/Linux sockets may carry bytes, while
Carrick translates Linux address families, options, credentials, descriptor
sharing, and error precedence. Synthetic interfaces such as `AF_NETLINK` live
entirely in the runtime.

kqueue and epoll host facilities are readiness sensors and wake mechanisms.
Carrick owns guest epoll registrations, interest masks, edge/level behavior,
one-shot state, cross-task visibility, and close semantics. A host wake causes
the kernel to re-evaluate Carrick state; it is not itself the Linux readiness
verdict.

The same capability boundary applies to timers, signals, credentials, process
metadata, and storage. Host calls must sit behind reviewed host-capability or
HAL seams, while kernel decisions remain keyed by Carrick identity and
generation.

## 7. Platform HALs and Guest ISAs

The unified kernel is projected through platform-selected backends:

| Host | VMM | Current guest focus | Role |
| --- | --- | --- | --- |
| macOS / Apple Silicon | HVF | AArch64 | Release-quality reference lane |
| Linux | KVM | AArch64 and x86_64 bring-up | Linux host/VMM projection |
| FreeBSD | bhyve | x86_64 bring-up | BSD host/VMM projection |
| NetBSD | NVMM | x86_64 bring-up | BSD host/VMM projection |

`carrick-hal` defines the neutral trap, vCPU, memory, timer, signal, and event
contracts. `carrick-aarch64` and `carrick-x86` own guest-ISA mechanics shared by
the relevant VMMs. Host crates implement operating-system facilities without
pulling platform-specific VMM policy back into the kernel.

Cross-compiling a backend proves source and feature closure. It does not prove
that a guest executed. Runtime claims require real target hardware and the
named VMM capability.

## 8. Embedding and Conformance

`carrick-embed` is the library front door to the same kernel architecture used
by the CLI. It resolves a Docker-shaped request, prepares a container object on
the kernel graph, and executes it in the carrier. Embedded guest processes are
still Carrick tasks; they are not host subprocesses.

`ContainerBuilder::from_image` owns an implicit, single-use carrier. The public
`Carrier` API instead admits multiple non-interactive container roots into the
same VM and kernel graph. Container IDs, root process trees, PID/UTS/network
namespace views, dispatch extensions, VFS mounts, clocks, stdio, and lifecycle
are per-container. The VM, vCPU lease pool, frame inventory, kernel graph,
runtime directory, and shutdown state are carrier-wide. Sharing a host `Arc`
between builders is deliberate application-level sharing, not an identity
shortcut inside the kernel.

The signed in-process tests in
[`../crates/carrick-embed/tests/guest_smoke.rs`](../crates/carrick-embed/tests/guest_smoke.rs)
exercise two live containers in one VM, isolated hostname/VFS/syscall policy,
sibling survival after early exit or interceptor panic, and cancellation of a
live guest during deterministic carrier shutdown. These are focused behavioral
proofs on entitled hardware, not a claim that the experimental runtime is a
hardened security boundary.

Carrick uses several evidence layers:

| Evidence | Hardware required | What it proves |
| --- | --- | --- |
| Compile-time ABI assertions | No | Linux wire layout and constant invariants |
| Host unit/integration tests | No | Kernel data structures and host semantics without guest execution |
| Signed embed/probe tests | Yes | Guest execution through the selected VMM and focused behavioral contracts |
| Docker differential suites | Yes | Observable Carrick-versus-Linux behavior for the declared workloads |
| Strict closure mode | Yes | Complete, baseline-free accounting of the frozen 2,127-suite surface |

Committed Docker oracle rows make the ordinary in-process probe loop faster;
they do not remove the Carrick-side VMM requirement. A skip-capable developer
test is convenience, not runtime proof. See
[conformance-testing.md](conformance-testing.md) for commands and CI boundaries.

## See also

- [hal.md](hal.md) — platform and VMM boundaries
- [host-facility-boundary.md](host-facility-boundary.md) — host capability
  ownership rules
- [conformance-testing.md](conformance-testing.md) — testing and oracle method
- [diagnostics-and-debugging.md](diagnostics-and-debugging.md) — tracing, event
  ring, LLDB, and crash evidence
- [syscalls-emulation-map.md](syscalls-emulation-map.md) — syscall support map
- [`../crates/README.md`](../crates/README.md) — workspace crate map
