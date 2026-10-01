// carrick vDSO clock functions (aarch64). Assembled once with the host
// toolchain to obtain the instruction encodings, which are embedded as a Rust
// const; the ELF wrapper around them is built in Rust. Position-independent
// only in that it hardcodes the carrick-chosen vvar data-page VA (0x2E_0000_0000)
// via a single movz — carrick maps the data page there.
//
// Data page layout (carrick fills it; little-endian u64s):
//   [0x00] seq               (seqlock; even = stable)
//   [0x08] freq              (CNTFRQ_EL0, Hz)
//   [0x10] realtime_off_ns   (wall_clock_ns - monotonic_ns)
//
// Linux clockids handled in-vDSO: REALTIME(0), MONOTONIC(1), MONOTONIC_RAW(4),
// REALTIME_COARSE(5), MONOTONIC_COARSE(6), BOOTTIME(7). The CPU-time clocks
// (2, 3) and every other id fall back to the real syscall. Membership is one
// bitmask test: bit N of SERVED (0xF3) set <=> clock N is served here.
//
// COARSE semantics (clean-room, clock_gettime(2) and clock_getres(2)): a
// COARSE clock is its base clock (REALTIME or MONOTONIC) truncated down to a
// multiple of its resolution, CLOCK_COARSE_RES_NS = 1 ms, which is
// LINUX_CLOCK_RESOLUTION_NSEC and what clock_getres reports for both COARSE
// ids on either path. Truncation is monotonic and never rounds up, so a COARSE
// read is never ahead of a fine read of its base clock taken after it, and
// MONOTONIC_COARSE never goes backwards. The dispatcher's clock_gettime
// applies the same truncation to the same base value, so vDSO and syscall
// COARSE reads interleave without going backwards.

	.text
	.align 4

	.global __kernel_clock_gettime
__kernel_clock_gettime:
	// w0 = clockid, x1 = timespec*
	cmp	w0, #7
	b.hi	1f				// >7 -> syscall fallback
	mov	w9, #0xF3			// SERVED: ids 0,1,4,5,6,7
	lsr	w9, w9, w0
	tbnz	w9, #0, 8f
	// 2,3 (process/thread cputime) -> syscall
1:	mov	x8, #113			// __NR_clock_gettime
	svc	#0
	ret
8:	mov	x15, #1				// x15 = sub-second divisor (ns -> ns)
	// Shared with __kernel_gettimeofday, which enters here with w0 = 0,
	// x1 = timeval* and x15 = 1000 (ns -> us).
2:
	movz	x9, #0x2E, lsl #32		// x9 = vvar data page VA (0x2E_0000_0000)
	mrs	x2, cntvct_el0			// x2 = cycle
	mrs	x10, cntfrq_el0			// x10 = freq
	// sec = cycle / freq ; rem = cycle - sec*freq
	udiv	x3, x2, x10
	msub	x4, x3, x10, x2			// x4 = rem cycles (< freq)
	// nsec_frac = rem * 1e9 / freq
	mov	x11, #0xCA00
	movk	x11, #0x3B9A, lsl #16		// x11 = 1e9
	mul	x4, x4, x11
	udiv	x4, x4, x10			// x4 = nsec fraction (< 1e9)
	// monotonic ns = sec*1e9 + nsec_frac
	madd	x5, x3, x11, x4			// x5 = mono ns
	// REALTIME family (0, 5): add the realtime offset
	mov	w12, #0x21
	lsr	w12, w12, w0
	tbz	w12, #0, 3f
	ldr	x12, [x9, #16]
	add	x5, x5, x12
3:
	// COARSE family (5, 6): truncate to CLOCK_COARSE_RES_NS (1 ms)
	mov	w13, #0x60
	lsr	w13, w13, w0
	tbz	w13, #0, 4f
	mov	x13, #0x4240
	movk	x13, #0xF, lsl #16		// x13 = 1_000_000
	udiv	x14, x5, x13
	mul	x5, x14, x13
4:
	// split x5 -> [x1]
	udiv	x7, x5, x11			// sec = ns/1e9
	msub	x4, x7, x11, x5			// nsec = ns - sec*1e9
	udiv	x4, x4, x15			// tv_nsec, or tv_usec for gettimeofday
	str	x7, [x1]
	str	x4, [x1, #8]
	mov	w0, #0
	ret

	.global __kernel_gettimeofday
__kernel_gettimeofday:
	// x0 = timeval*, x1 = timezone* (ignored). REALTIME through the shared
	// __kernel_clock_gettime fast path, reported in microseconds.
	cbz	x0, 5f
	mov	x1, x0				// x1 = timeval*
	mov	w0, #0				// CLOCK_REALTIME
	mov	x15, #1000			// ns -> us
	b	2b
5:	mov	w0, #0
	ret

	.global __kernel_clock_getres
__kernel_clock_getres:
	// w0 = clockid, x1 = timespec*. For the clocks __kernel_clock_gettime
	// serves, report the resolution the clock_getres syscall reports for
	// them (LINUX_CLOCK_RESOLUTION_NSEC, 1 ms); a NULL x1 is a successful
	// no-op. Everything else asks the syscall.
	cmp	w0, #7
	b.hi	6f
	mov	w9, #0xF3			// SERVED, as in __kernel_clock_gettime
	lsr	w9, w9, w0
	tbz	w9, #0, 6f
	cbz	x1, 7f
	str	xzr, [x1]			// tv_sec = 0
	mov	x2, #0x4240
	movk	x2, #0xF, lsl #16		// 1_000_000
	str	x2, [x1, #8]			// tv_nsec = 1 ms
7:	mov	w0, #0
	ret
6:	mov	x8, #114			// __NR_clock_getres
	svc	#0
	ret

	// The canonical aarch64 sigreturn trampoline. carrick normally returns from
	// a signal handler via its own injected EL0 trampoline page, but the vDSO
	// must still EXPORT this symbol so unwinders/debuggers (libgcc, libunwind,
	// gdb, Go traceback) can recognise a signal frame by name and by matching
	// this exact `mov x8,#139 ; svc #0` instruction pair at the PC.
	.global __kernel_rt_sigreturn
__kernel_rt_sigreturn:
	mov	x8, #139			// __NR_rt_sigreturn
	svc	#0
	// never returns; the kernel restores the interrupted context.

	// __kernel_getrandom is NOT here: it's a Rust no_std blob compiled +
	// embedded separately (crates/carrick-runtime/tools/vdso_getrandom_blob.rs +
	// build-vdso-getrandom.sh; core in carrick-mem/src/vdso_getrandom_chacha.rs).
