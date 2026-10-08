# Native CPL0 standard descriptors and poll

Implementation is deferred until the fork-stock lane lands. This note does not
change launch, boot exports, frame loans or apertures.

Launch must admit descriptors 0..2 as host-backed open descriptions in the
existing guest file owner, keyed by `(FileTableId, fd)`. The table identity is
retained by the exact process custody; fork inherits the table according to
the shared file-table policy. A descriptor number alone, the carrier PID, or a
parallel private map is not authority. Closed standard descriptors stay absent;
launch must not silently reopen them.

Guest poll validates and copies its bounded pollfd array, resolves each entry
through that table, ignores negative descriptors, and returns POLLNVAL for
absent nonnegative descriptors. It writes revents for every entry and counts
ready entries, including unconditional ERR/HUP/NVAL independently of requested
events. Startup's events-zero/timeout-zero call follows this same policy.

Host-backed readiness uses the existing allowed epoll_pwait crossing after
guest admission translates description handles. Native poll is never forwarded.
Duplicate guest descriptors need independent pollfd results even when they
refer to one open description. The guest owns timeout conversion, interruption
and completion; a blocking wait releases execution capacity through an owned
continuation rather than parking the executor. Existing in-zone pipe/eventfd
readiness remains with its owner.

Red-first coverage must include 0..2 open and closed at launch, an absent fd,
negative and duplicate entries, events zero with ERR/HUP, and two live process
tables with the same numbers but different descriptions. Prove exact results
with native Linux static ELFs and VM-free table/continuation tests, then rerun
the unchanged same-source startup and lifecycle/IPC bindings on required KVM.
The shared policy is ISA-neutral; launch and crossing adapters need separate
ARM signed verification. No allowlist widening is needed.
