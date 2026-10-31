# x86 signal resume validation

`signal.x86.resume-validation` owns x86 signal-context publication and
invalid-frame SIGSEGV. Authority: sigreturn(2), sigaction(2), and signal(7).
The VM-free return contract rejects a normal errno outcome on frame failure;
scheduler tests check the RFLAGS privilege boundary. The native/KVM flags and
bad-RIP witnesses both failed before correction and compare to native Linux.
The bad-RIP witness also found that root completion rejected signal wait
statuses; its ABI test now admits only exited or signaled terminal states.

Publication validates RIP/RSP and flags before writing any saved register.
Frame failure queues one exact-thread forced SIGSEGV; disposition and queue
changes use the retained task's sighand lock. The budget is constant-time
validation and one queue admission, without retry, polling or timeout growth.
C3's native/KVM fault witness additionally checks architectural RIP, MAPERR,
saved mask, handler mask, and mask restoration. Its synchronous-SEGV policy
binding checks blocked and ignored actions in the VM-free EL1 library.
Signed ARM acceptance remains outstanding and these witnesses do not claim it.
