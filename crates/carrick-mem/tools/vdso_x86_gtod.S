/* x86_64 vDSO __vdso_gettimeofday + __vdso_time fast paths.
 * Position-independent (movabs absolute vvar VA + PC-relative branches only),
 * matching __vdso_clock_gettime's realtime math:
 *   total_ns = tsc*1e9/freq + REALTIME_OFF_NS ; sec = total_ns/1e9 ; nsec = rem
 * Assembled, not hand-encoded; bytes extracted into carrick-mem/src/vdso.rs.
 * vvar: FREQ @ 0x2e00000008, REALTIME_OFF_NS @ 0x2e00000010.
 */
	.text
	.intel_syntax noprefix

	.globl __vdso_gettimeofday
__vdso_gettimeofday:           /* rdi = timeval*, rsi = timezone* (ignored) */
	test rdi, rdi
	jz   2f                    /* NULL tv -> return 0, no write */
	movabs r11, 0x2e00000008
	mov  r8, [r11]             /* freq */
	test r8, r8
	jz   1f                    /* freq==0 -> syscall fallback */
	movabs r11, 0x2e00000010
	mov  r9, [r11]             /* realtime_off */
	lfence
	rdtsc
	shl  rdx, 32
	or   rax, rdx              /* rax = tsc */
	mov  r10d, 1000000000
	mul  r10                   /* rdx:rax = tsc*1e9 */
	div  r8                    /* rax = tsc_ns */
	add  rax, r9               /* total_ns */
	xor  edx, edx
	div  r10                   /* rax=sec, rdx=nsec */
	mov  [rdi], rax            /* tv_sec */
	mov  rax, rdx              /* nsec */
	xor  edx, edx
	mov  r10d, 1000
	div  r10                   /* rax = usec */
	mov  [rdi+8], rax          /* tv_usec */
2:
	xor  eax, eax
	ret
1:
	mov  eax, 96               /* SYS_gettimeofday */
	syscall
	ret

	.globl __vdso_time
__vdso_time:                   /* rdi = time_t* (may be NULL) */
	movabs r11, 0x2e00000008
	mov  r8, [r11]
	test r8, r8
	jz   3f
	movabs r11, 0x2e00000010
	mov  r9, [r11]
	lfence
	rdtsc
	shl  rdx, 32
	or   rax, rdx
	mov  r10d, 1000000000
	mul  r10
	div  r8
	add  rax, r9               /* total_ns */
	xor  edx, edx
	div  r10                   /* rax = sec */
	test rdi, rdi
	jz   4f
	mov  [rdi], rax
4:
	ret
3:
	mov  eax, 201              /* SYS_time */
	syscall
	ret
