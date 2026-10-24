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
