# One syscall service owner (#1393, slice a)

The owner classifies a canonical ordinal, without a task class or an ISA input:
`Ring(Family)`, `Crossing(OperandSpec)` or `CountedEnosys`. The declarations in
`dispatch::route_aarch64`, `dispatch::route_x86` and `crossing::host_crossings!`
remain the sources. Existing ring families take precedence over allowlist
membership. Descriptor and ppoll families are classified before their venue
availability is checked. `OperandSpec` currently binds the typed crossing
identity only; #1396 supplies the operand schema and #1363 the transport. It
provides neither a memory permit nor authority to act for another task.

This implements the design posted on #1393, with an independent design review
before implementation. It does not flip the root or claim root/child semantic
parity. The shared classifier describes ownership; existing ISA wiring, venue
availability, family declines, refusal counters, handbacks and completion work
retain their current behavior. In particular, a ring owner does not remove a
valid host-file fallback, and the x86 allowlist remains narrower than ARM's.

Both the shared native dispatcher and the host root's ordinary, mutation and
independent threaded paths consult this owner. The root keeps its current host
handlers through `RootOnly` compatibility. The registry initially names all
283 retained handler identities, conservatively including real crossings whose
handlers still have ambient host-task dependencies. This counts retained code
paths, not 283 observed guest failures. A root handler outside the crossing set
cannot be added without explicit compatibility admission. Tests independently
enumerate the Linux and private x86 namespaces and compare both root resolver
populations with the preexisting module chains. The bitmap membership lookup
is populated through those same resolvers.

The initial compatibility list is deliberately broader than the observed
missing-op population. Retire an entry when its root handler is removed or its
crossing no longer needs the host task implementation. The following census
explains what must converge before that deletion is justified:

| #1335 census | Retained divergence |
|---|---|
| F1–F4, F9–F13 | Captured filesystem context; relative and dirfd paths; metadata, namespace and xattr handlers |
| F5–F7 | Input/output staging, short transfer shapes and fault/effect ordering |
| F8 | Separate root fd resolution even when the host seek operation agrees |
| F14–F16 | ioctl, fcntl and descriptor-table operation coverage and ownership |
| F17–F18 | Pipe lifetime and in-zone creation, timer, readiness and release ownership |
| F19–F21 | Socket, entropy, clock and blocking-time service coverage |
| F22 | Separate exec service and its filesystem/credential admission |
| F23–F24 | Memory-owner delegation and host-file mapping coverage |

`RootOnlyState` separately names the cross-cutting obligations from the
[#1335 census](https://github.com/carrick-sh/carrick/issues/1335#issuecomment-6566328965)
and its [independent ambient-state review](https://github.com/carrick-sh/carrick/issues/1335#issuecomment-6566449496):
captured fs, credentials, fd table, pipe lifetime, exec, user memory, pending
host work, signals/SIGPIPE, process identity, record-lock owner, rlimits, umask,
SysV scope, child CPU times, `/proc/self`, network/container view, attribution,
resource scope, execution lease and host wait. The twenty-first obligation is
`GRANT_OP_ROOT_FORK_SEED` / `RootForkSeed` (#1409), explicitly retired at slice
(c), when the root owns its ring filesystem row. This list grants no child
crossing access to any of that ambient state.

The handler and state declarations generate their own test populations. Unit
checks require their ceilings to track removals. `xtask authority-debt` compares
both populations with the actual PR base and rejects growth independently of
edited ceilings, so retirement cannot create reusable headroom. Identities
have no source line or SHA in their keys. Missing/duplicate declarations and
syntax errors fail the scanner; deleting the completed compatibility module
reduces both counts to zero.

The applicable contracts are `core.entry.completion` and
`kernel.el1.arm-ring-first-crossing`. VM-free characterization checks the two
ISA projections, owner precedence, TSV crossing membership and complete root
handler populations. Classification and compatibility admission are bounded
ordinal matches with no allocation or user-memory access. No Linux answer or
work budget changes. Signed guest behavior, runtime ratios and the later
native-root flip remain separate acceptance obligations; this slice makes no
runtime parity claim.
