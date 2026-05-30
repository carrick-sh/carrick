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
// BOOTTIME(7). Anything else falls back to the real syscall.

	.text
	.align 4

	.global __kernel_clock_gettime
__kernel_clock_gettime:
	// w0 = clockid, x1 = timespec*
	cmp	w0, #7
	b.hi	1f				// >7 -> syscall fallback
	cmp	w0, #4
	b.eq	2f				// MONOTONIC_RAW ok
	cmp	w0, #1
	b.eq	2f				// MONOTONIC ok
	cmp	w0, #7
	b.eq	2f				// BOOTTIME ok (== monotonic here)
	cmp	w0, #0
	b.eq	2f				// REALTIME ok
	// 2,3,5,6 (process/thread cputime, coarse) -> syscall
1:	mov	x8, #113			// __NR_clock_gettime
	svc	#0
	ret
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
	// REALTIME: add realtime offset
	cmp	w0, #0
	b.ne	3f
	ldr	x12, [x9, #16]
	add	x5, x5, x12
3:
	// split x5 -> [x1]
	udiv	x7, x5, x11			// sec = ns/1e9
	msub	x4, x7, x11, x5			// nsec = ns - sec*1e9
	str	x7, [x1]
	str	x4, [x1, #8]
	mov	w0, #0
	ret

	.global __kernel_gettimeofday
__kernel_gettimeofday:
	// x0 = timeval*, x1 = timezone* (ignored). Use REALTIME.
	cbz	x0, 5f
	mov	x13, x0				// save timeval*
	movz	x9, #0x2E, lsl #32
	mrs	x2, cntvct_el0
	mrs	x10, cntfrq_el0
	udiv	x3, x2, x10
	msub	x4, x3, x10, x2
	mov	x11, #0xCA00
	movk	x11, #0x3B9A, lsl #16		// 1e9
	mul	x4, x4, x11
	udiv	x4, x4, x10
	madd	x5, x3, x11, x4			// mono ns
	ldr	x12, [x9, #16]
	add	x5, x5, x12			// real ns
	udiv	x7, x5, x11			// sec
	msub	x4, x7, x11, x5			// nsec
	mov	x14, #1000
	udiv	x4, x4, x14			// usec = nsec/1000
	str	x7, [x13]			// tv_sec
	str	x4, [x13, #8]			// tv_usec
5:	mov	w0, #0
	ret

	.global __kernel_clock_getres
__kernel_clock_getres:
	// w0 = clockid, x1 = timespec*. Report 1ns resolution for the clocks we
	// serve; fall back to syscall otherwise.
	cmp	w0, #7
	b.hi	6f
	cbz	x1, 7f
	str	xzr, [x1]			// tv_sec = 0
	mov	x2, #1
	str	x2, [x1, #8]			// tv_nsec = 1
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
