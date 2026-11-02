#pragma D option quiet
/*
 * WHICH DESCRIPTOR CEILING DOES THE EL1 VECTOR'S close/fstat FAST PATH SEE?
 * (a) Measures every publication of the carrier-wide descriptor ceiling, the
 *     word the EL1 lower-EL sync vector compares close(57)/fstat(80) fds
 *     against before any EL1 dispatch (`write_fstat_ceiling_handler` in
 *     crates/carrick-mem/src/memory.rs): every candidate maximum offered to
 *     `FdCeilingAuthority::publish` (arg1 = fd; the authority raises the
 *     carrier word only above its running maximum, initially 2), publisher
 *     registration and permanent disable. The carrier publisher's own
 *     demangled name is truncated by DTrace before `raise`/`disable`, so the
 *     authority is the unambiguous probe point. Host-served close returns (syscall-return nr 57) are printed
 *     so a vector-answered close shows up as a guest EBADF with no event.
 * (b) pid provider on the in-process HVPatch carrier ($target); guest fork
 *     creates no host process, so no progenyof is needed. `??` stands for
 *     `::` in the demangled names. Live-qualified 2026-11-01 on main
 *     9a43470ea9 (#1398): a perl root raised the ceiling to 3 only; its
 *     native child's in-ring dup(0) x3 (fds 3, 4, 5) published nothing, and
 *     its close(4)/close(5) returned EBADF with no syscall-return event and no
 *     EL1 counter (`carrick el1-counters`: nr 57 served 0).
 *     Positive control on the same binary: a root that first dup'd fds 3..5
 *     on the host raised the ceiling to 5 and the same child closes all
 *     returned 0. CARRICK_FD_CEILING=0 (the publisher's opt-out hatch) also
 *     made them return 0. A vector-answered call never enters EL1 dispatch,
 *     so it shows no EL1 counter, no syscall-return and no event here.
 *     Since #1398 the ring raises the same word by fetch_max for numbers a
 *     ring-owned table makes live (`carrick_el1_abi::cover_guest_descriptor`);
 *     those guest-side raises are invisible to this host-side script.
 * (c) Light: one line per publication; host closes are the root's few.
 */
dtrace:::BEGIN { secs = 0; printf("FDCEIL|begin\n"); }
pid$target::*FdCeilingAuthority??publish*:entry
{ printf("FDCEIL|%d|host-install|fd=%d\n", timestamp, (int)arg1); }
pid$target::*FdCeilingAuthority??register*:entry
{ printf("FDCEIL|%d|register\n", timestamp); }
pid$target::*FdCeilingAuthority??disable*:entry
{ printf("FDCEIL|%d|disable\n", timestamp); }
carrick*:::syscall-return
/pid == $target && arg0 == 57/
{ printf("FDCEIL|%d|host-close-return|rv=%d\n", timestamp, (int)arg2); }
tick-1s { secs++; }
tick-1s /secs >= 8/ { exit(0); }
