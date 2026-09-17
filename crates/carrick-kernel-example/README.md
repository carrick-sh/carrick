# carrick-kernel-example

This crate is the VM-free kernel conformance harness and a template for a
bring-your-own execution backend. Scripts issue Linux syscalls through the
public `carrick-kernel` API. Host threads execute the scripts over bounded,
`Vec`-backed guest memory; they do not execute guest instructions or fork host
processes.

Use `just test-kernel` for the inner loop. It runs the kernel's parallel lib
lane and this crate's integration suites without a VM, codesign, or Docker.
`just test` also runs the `serial_host` kernel and VFS cases and the other host
suites. Host results do not replace the signed guest conformance gates.

## Writing a script

A `Step::Sys(Syscall)` contains a canonical syscall number, six `Operand`s,
optional `Save`s, and an `Expect`. The constructors in `sys` are conveniences;
the generic vocabulary can express other syscalls without adding an interpreter
variant.

- `Operand::Lit`, `Slot`, and `LastChild` supply scalar values. Slots contain
  values saved earlier in the task and are inherited by fork children.
- `Bytes` and `CStr` allocate input memory; `Out` allocates a zeroed output;
  `InOut` initializes memory and captures its final contents.
- `Save::Ret` saves a successful return; `Save::OutI32` saves an element from
  an output buffer, such as a descriptor returned by `pipe2`.
- `Expect::Ret`, `Errno`, and `Death` assert the syscall's outcome. `Any`
  accepts a successful return, not an unexpected errno. Failures identify the
  task and syscall label.
- A fork syscall is followed by `Step::ChildMarker` with the child's script.
  `await_parked(pid, label)` establishes that another task enrolled its wait
  before the next action. Do not sleep to arrange execution order.

Give separate labels to calls whose outputs you need to distinguish.
`RunReport` exposes completions, output bytes, deaths, task counts, and
`dispatches_for(pid, label)`. A blocked read awakened by a writer dispatches
exactly twice. A continuation that returns its result directly, such as a
successful futex wait, must not redispatch the original request.

Every semantic expectation must cite a man-page section or a committed Docker
oracle alongside the assertion. A new test that exposes a kernel defect remains
visible: fix a small dispatch defect with red/green evidence, or record a named
`defect:` ignore and its reason in the implementation ledger. Missing harness
support is not a kernel conformance defect.

## Implementation map

| File | Responsibility |
|---|---|
| `src/operand.rs`, `src/sys.rs` | Generic vocabulary and syscall constructors. |
| `src/memory.rs` | Bounded guest-memory allocation and output access. |
| `src/report.rs` | Per-task completions, outputs, and dispatch accounting. |
| `src/scripted.rs` | Script execution, process construction, fork, and retirement through public kernel operations. |
| `src/driver.rs` | Outcome handling and kernel continuation enrollment; bounded parking on `CarrierWaitService`. |
| `src/process.rs` | `CarrierProcess`, `MmBackend`, and `Stage1MmProjection` implementations with exact kernel identity and address-space bindings. |
| `tests/fork_pipe_wait.rs` | Harness contracts, including lost-wake bounds and dispatch counts. |
| `tests/semantics/` | Linux semantics across processes and threads, grouped by syscall domain. |

The driver shares continuation completion and signal policy with the real
carrier. It does not poll and redispatch a blocked syscall until it happens to
succeed. `WAIT_BOUND` is five seconds; a missing wake is a named timeout.
Signals that need no guest handler and kernel timer waits can be tested without
an instruction stream. Process fork copies memory; threads share the process's
dispatcher and address space and use their own kernel thread context.

## Boundaries

The harness does not emulate a CPU, execute an image with `execve`, or run guest
signal handlers. It has no real page tables or frame inventory and no foreign-mm
endpoint for `process_vm_readv`-style access. Unsupported outcomes fail by name;
a passing script proves the kernel behavior it actually exercises.

This experimental crate uses public items of `carrick-kernel`, `carrick-hal`,
`carrick-guest-mem`, and `carrick-abi`. It is outside the product path.
`just check-layering` excludes runtime/VMM dependencies from the harness and
keeps its `test-support` dependencies out of the product selection. The root
manifest's `default-members` selects only `carrick-cli`, preventing accidental
feature unification into the shipped binary.
