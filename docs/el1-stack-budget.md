# ARM EL1 entry stack budget

The release `aarch64-unknown-none-softfloat` image build disassembles the exact
ELF it embeds, using the selected Rust toolchain's LLVM tools. It checks
compiled frames, rather than Rust record sizes or a debug host build.
`cargo build -p carrick-el1-image` runs the check in ordinary CI builds;
`cargo test -p carrick-xtask --test el1_image_sysroot` exercises its parser and
rejection cases through the existing build-script test binding.

The unchanged ABI supplies a 16,384-byte stack and a 288-byte vector record.
Each registered entry-chain envelope must use at most 12,288 bytes, including
the vector record, leaving at least 4,096 bytes free. Every individual emitted
function must also fit in 3,072 bytes. The existing retained-frame checks remain
in force. Missing retained functions, malformed frame immediates and unknown
stack realignment fail the build. The parser includes page probes, pre-indexed
register saves, shrink-wrapped prologues and worst-case 64-byte alignment slack.
It never reads the following symbol's prologue into a tail wrapper's frame.

`frame_budget.rs` states the nesting as additive envelopes. Each component is
the maximum compiled frame across all matching monomorphizations; mutually
exclusive branches take their maximum. Inlined leaves need no additional
frame. Retained entry functions are mandatory and cannot disappear silently.
The envelopes cover native admission, fork preparation, publication and
settlement, wait status copy, signal delivery/return/terminal exit, anonymous
munmap, metadata grant, backing retirement and descriptor draining. They include
callees
reached through trait objects and copy callbacks: a direct `bl`-only call graph
would omit those frames.

Fork settlement includes the retained `fork_owned` owner and the compiled
`settle_mm` frame, where the 128-byte Commit record is copied to the stopped
CPU's stack. It also charges allocator and notification work that opening the
child's space gate can trigger. An inlined `consume` is included in its caller's
compiled frame.

The descriptor envelope charges four table/entry levels and four descent
frames, plus journal/store/unlink and allocator service work. Signal delivery
charges two delivery frames: failure of a caught signal may force SIGSEGV, and
failure of SIGSEGV terminates rather than recursively delivering another one.
Scheduler-selected checkpoints can service pending exit directly. Handler
publication occurs after scheduler return has dropped that selected process
entry, so terminal exit takes the maximum of these two prefixes. Notification
release and metadata return can wake a guest with the outer owner/editor still
live; their complete scheduling tail is charged. Allocator mailbox processing
publishes host work; it does not recursively invoke the hardware grant entry on
the current Rust stack.

This is a contract for the registered entry-chain compositions, not a complete
whole-program call-graph proof. Data-dependent reservation-tree traversals,
all indirect-call target discovery, arbitrary new compositions, asynchronous
current-EL exceptions and the x86 image still require the broader #369 work.
The individual-frame ceiling also rejects oversized functions outside the
registered chains. Changing a composition or recursive bound requires reviewing
the envelope; silently increasing a budget is not a baseline update. Guard
pages remain separate work in #369; this change does not move or enlarge stacks.

The root failure was ARM signal encoding's by-value `LinuxSignalContext`,
`LinuxUcontext`, `SignalFrame`, and aggregate return buffers. The signal setup
function alone allocated 19,520 bytes. The codec now fills caller-owned admitted
storage and borrows FPSIMD; the EL1 adapter allocates that storage fallibly and
copies it before publishing handler registers. Native process contexts, fork
preparation, wait authorization/results and exit results retain heap custody
across nested work. Loaned lifecycle pages initialize by borrowing the canonical
constructor template, avoiding page-sized copies and 4 KiB stack realignment
when compiler copy elision changes. The same initializer serves ARM and CPL0.
The template occupies one page plus linker alignment in the image, included in
the existing image-extent gate. A compile-time no-drop assertion prevents
future owning fields from acquiring raw-copy semantics. Exit's child iteration
uses the `BTreeSet` order directly without a sort scratch frame.

Existing `kernel.el1.signal-delivery-owner` and `kernel.el1.thread-lifecycle`
semantic witnesses remain applicable. Their structural binding is the compiled
frame gate, red on the combined fork/signals image before these corrections.
The signed `el1_anonymous_mapping_retirement_returns_and_reuses_frames` witness
and the complete signed gate remain required on the exact final macOS artifact.
Linux-only compilation and VM-free tests do not confer signed acceptance.

The native service continuation envelope includes both fresh capture and
resumption, the exact owner-entry borrow, park/completion, and notification
allocation tails. The completed-work variant preserves the saved result;
its carrier acknowledgment cannot replay an already completed syscall.

Native owner waits include the direct service admission frame and both
parking paths. Native backing replies additionally charge the retained
service continuation, grant authentication and the descriptor executor,
including its four table levels and allocation/notification tails.

FD inheritance has its own envelope, separate from page-table descriptor work.
It retains the native fork entry, the FD service and shared-core fork/storage
frames, including publication refusal and storage/reference rollback. Native
FD retirement runs after exit publication returns, so its envelope takes the
exit or failed-fork prefix without nesting underneath `finish_exit`. It charges
namespace revocation, final-description callbacks, object/epoll release, and
the larger of queue notification and wake delivery. Optional helpers may inline
in one image feature closure and remain emitted in another; both forms are
charged. Synthetic cumulative-overflow tests reject both FD paths even when
every individual frame remains below its separate ceiling.

## Headroom measurement for the #740 stack (2026-10-24)

On ctb-w4, with the pinned Rust 1.96.0 toolchain and the slice 3b base,
**both** the ordinary and `allocator-test-control` images measured 11,343
checked bytes. The task brief's 12,175-byte observation did not reproduce
on this host. Both builds used `env -u RUSTC_WRAPPER CARRICK_SCCACHE=0`.
The 12,288-byte envelope ceiling and 3,072-byte individual ceiling are unchanged.

These are the five largest baseline envelopes, identical in both images:

| Envelope | Checked bytes |
|---|---:|
| signal terminal exit | 11343 |
| native backing reply | 10975 |
| native wait copy | 10879 |
| native fork descriptors | 10573 |
| signal delivery copy | 9951 |

The table below expands **every nonzero frame** charged by those five
compositions. Columns give the multiplicity (a dash means absent). `T` is
terminal exit, `B` backing reply, `W` wait copy, `F` fork descriptors and `S`
signal delivery copy. Sizes include the checker's worst-case alignment slack;
LLVM hashes and generic parameters are omitted from symbol names. This is
an expansion of `frame_budget.rs`'s conservative sums/maxima, including
indirect calls and exclusive-branch maxima, rather than an observed backtrace.

| Frame | Bytes | T | B | W | F | S |
|---|---:|---:|---:|---:|---:|---:|
| `vector record` | 288 | 1 | 1 | 1 | 1 | 1 |
| `carrick_el1_syscall` | 112 | 1 | 1 | 1 | 1 | 1 |
| `dispatch_entry` | 96 | 1 | 1 | 1 | 1 | 1 |
| `dispatch_syscall` | 560 | 1 | — | — | 1 | 1 |
| `with_process_entry` | 511 | 1 | — | — | 1 | 1 |
| `deliver_on_user_return` | 608 | 1 | — | — | — | 1 |
| `deliver_signal_on_syscall_return` | 608 | 2 | — | — | — | 2 |
| `force_delivery_fault` | 208 | 1 | — | — | — | 1 |
| `exit_with_status` | 1424 | 1 | — | — | — | — |
| `publish_exit` | 1296 | 1 | — | — | — | — |
| `finish_exit` | 1744 | 1 | — | — | — | — |
| `publish_exit_receipt` | 704 | 1 | — | — | — | — |
| `BTreeMap::insert_recursing` | 1440 | 1 | — | — | — | — |
| `deallocate` | 144 | 1 | 1 | — | 1 | — |
| `service_mailbox` | 160 | 1 | 1 | — | 1 | — |
| `ObjectWaitGuard::drop` | 336 | 1 | 1 | 1 | 1 | 1 |
| `place_in_guest` | 208 | 1 | 1 | 1 | 1 | 1 |
| `find_idle_except` | 64 | 1 | 1 | 1 | 1 | 1 |
| `accepts` | 64 | 1 | 1 | 1 | 1 | 1 |
| `running_raw` | 16 | 1 | 1 | 1 | 1 | 1 |
| `panic_bounds_check` | 64 | 1 | 1 | 1 | 1 | 1 |
| `panic_fmt` | 64 | 1 | 1 | 1 | 1 | 1 |
| `rust_begin_unwind` | 16 | 1 | 1 | 1 | 1 | 1 |
| `interrupt` | 160 | — | 1 | 1 | — | — |
| `preempt_record` | 128 | — | 1 | 1 | — | — |
| `idle` | 256 | — | 1 | 1 | — | — |
| `load` | 208 | — | 1 | 1 | — | — |
| `resume_production` | 319 | — | 1 | 1 | — | — |
| `resume_selected` | 192 | — | 1 | 1 | — | — |
| `resume_checkpoint` | 512 | — | 1 | 1 | — | — |
| `resume_pending_lifecycle` | 928 | — | 1 | 1 | — | — |
| `park_owner_wait` | 384 | — | 1 | — | — | — |
| `finish_owner_wait` | 560 | — | 1 | — | — | — |
| `finish_service` | 528 | — | 1 | — | — | — |
| `apply_fault_reply` | 864 | — | 1 | — | — | — |
| `apply_grant` | 1312 | — | 1 | — | — | — |
| `execute_descriptor_txn` | 592 | — | 1 | — | 1 | — |
| `visit_live_table` | 144 | — | 4 | — | 4 | — |
| `visit_entry` | 128 | — | 4 | — | 4 | — |
| `descend` | 272 | — | 4 | — | 4 | — |
| `store` | 128 | — | 1 | — | 1 | — |
| `unlink` | 96 | — | 1 | — | 1 | — |
| `wait_query` | 1520 | — | — | 1 | — | — |
| `copy_with` | 96 | — | — | 1 | — | — |
| `copy_signal_bytes` | 416 | — | — | 1 | — | 1 |
| `write_user_bytes` | 2240 | — | — | 1 | — | 1 |
| `authorize` | 688 | — | — | 1 | — | 1 |
| `root_for` | 480 | — | — | 1 | — | 1 |
| `root_any` | 576 | — | — | 1 | — | 1 |
| `lock_using` | 352 | — | — | 1 | — | 1 |
| `Reservations::drop_in_place` | 80 | — | — | 1 | — | 1 |
| `SpaceNotificationLease::release_retiring_resource` | 80 | — | — | 1 | — | 1 |
| `SpaceNotificationLease::release_resource` | 320 | — | — | 1 | — | 1 |
| `fork_owned` | 703 | — | — | — | 1 | — |
| `prepare_mm` | 2879 | — | — | — | 1 | — |
| `prepare_fork` | 1296 | — | — | — | 1 | — |
| `setup_arm_signal_frame` | 288 | — | — | — | — | 1 |

`GuestReservedExit::begin` now keeps the pending topology, reservation and
member/resource effects in one box through `finish_exit`. Its rollback owner
and drop behavior are unchanged. `GuestPendingExit::publish` returns the
published record in its existing box directly, eliminating the aggregate return
buffer in `finish_exit`. There is one additional fixed-size allocation per
pending exit; the published-result allocation already existed. No new unsafe
code, Linux behavior, stack layout or chain accounting is introduced.

| Measurement | Before (both images) | After (both images) |
|---|---:|---:|
| Maximum checked envelope | 11,343 | 10,975 |
| Signal terminal exit | 11,343 | 10,959 |
| `publish_exit` frame | 1,296 | 1,040 |
| `finish_exit` frame | 1,744 | 1,616 |

The deepest remaining standalone envelope is native backing reply. The macOS
cross-check reports 10,975 in one image closure and 11,263 in its broader
closures. Linux clippy feature closures produce different compiled frames and
reach 11,311 bytes. These results are distinct from the two standalone
measurements above and still pass 12,288.

Slice 4 keeps 11,311 bytes as a chain-specific ceiling for native backing
reply, so exec service growth cannot consume the headroom recovered above.
Keeping `PendingService` boxed while it leaves the owner table avoids moving
the request, reply, payload, claim, and control custody through both
`finish_owner_wait` and `finish_service`. With exec argument staging present,
the Linux clippy closure measures 11,071 bytes for backing reply; its broad
maximum is the separate 11,327-byte signal-terminal-exit envelope. The
ordinary test closure measures 10,735 bytes for backing reply.

### Lane B after composition with main (2026-10-25)

The rebased slice 4 Linux clippy closure at `6da2a514be` rejected native
backing reply at 11,422 bytes against the unchanged 11,311-byte ceiling.
Disassembly showed the 64-byte-aligned `NativeDescriptorSettlement` moving
through a 128-byte `Option` return and intermediate error-adapter buffers.
The nested service functions also passed the 120-byte `ServiceRequest` by
value despite already retaining the pending service in a box.

Settlement now initializes one caller-owned wire slot in place and returns
only success/failure. Private park/completion functions borrow the request
snapshot retained by their caller. The exact pending-request comparison,
owner/MM/sequence checks, one-shot settlement and terminal claim remain in
place. Wire size, alignment and layout are unchanged. This adds no allocation,
unsafe code or new execution path, and changes no stack or frame budget.

| Linux clippy measurement | Before | After |
|---|---:|---:|
| Native backing reply | 11,422 | 11,070 |
| `apply_fault_reply` frame | 1,279 | 1,023 |
| `resume_checkpoint` frame | 544 | 448 |

The corrected closure recovers 352 bytes, leaving 241 bytes under the stricter
backing-reply ceiling. All its other registered envelopes remain below their
12,288-byte ceiling. These are compiled-image measurements; the other portable
feature closures must also pass before handoff. They do not establish signed
HVF execution or a complete whole-program stack proof.

A tighter limit is mechanically possible by replacing `stack_size * 3 / 4`
in `Frames::check` with a lower ceiling. An 11 KiB ceiling (11,264 bytes)
leaves 289 bytes above the standalone maximum but would reject the Linux
clippy feature closures; those need further headroom first. This is a proposal
for the director, not a budget change. The ARM gate still does not prove CPL0
chain depth or guard pages; shared ownership changes compile for CPL0 through
`clippy-linux`.
