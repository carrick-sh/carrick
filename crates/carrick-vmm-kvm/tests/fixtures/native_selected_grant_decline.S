/* #2579: a declined owner-selected grant publication takes the shared
 * policy's next action through the production #PF entry. The descriptor
 * executor refuses the next selected window before any store:
 *   -DCAPACITY  TablesExhausted: the serve reruns with the fault page alone,
 *               which publishes; the window's other pages fault later.
 *   -DINHERITED Occupied, in a fork child that holds inherited prepared
 *               outputs: the access reruns, the replan publishes, and the
 *               inherited pages keep their parent's data.
 *   -DTERMINAL  StaleRoot: no rerun and no replan; the access never
 *               completes (exit 7 means it wrongly did).
 * Exit 7 is success; 90-99 name the failed step.
 */
#define INJECT_GRANT_CAPACITY_REFUSAL_ONCE -432
#define INJECT_GRANT_OCCUPIED_REFUSAL_ONCE -431
#define INJECT_GRANT_TERMINAL_REFUSAL_ONCE -430
#define INJECT_GRANT_REFUSAL_CENSUS -429

.global _start
.text
_start:
    /* Lazy 6 MiB arena; %r14 is its first 2 MiB-aligned grant window,
     * %r15 the next one. */
    xor %edi, %edi
    mov $0x600000, %esi
    mov $3, %edx
    mov $0x22, %r10d
    mov $-1, %r8
    xor %r9d, %r9d
    mov $9, %eax
    syscall
    test %rax, %rax
    js fail_arena
    lea 0x1fffff(%rax), %r14
    and $-0x200000, %r14
    lea 0x200000(%r14), %r15

#if defined(CAPACITY)
    mov $INJECT_GRANT_CAPACITY_REFUSAL_ONCE, %rax
    syscall
    test %rax, %rax
    jnz fail_arm
    /* The refused window is the whole lazy span; the rerun is one page. */
    movq $0x11, 0x101000(%r14)
    mov $INJECT_GRANT_REFUSAL_CENSUS, %rax
    syscall
    movabs $0x100000001, %rcx
    cmp %rcx, %rax
    jne fail_census
    /* Pages the one-page rerun left unserved still fault and publish. */
    movq $0x22, (%r14)
    movq $0x33, 0x1ff000(%r14)
    cmpq $0x11, 0x101000(%r14)
    jne fail_value
    cmpq $0x22, (%r14)
    jne fail_value
    cmpq $0x33, 0x1ff000(%r14)
    jne fail_value
    mov $7, %edi
    jmp die
#elif defined(INHERITED)
    /* The parent's first touch prepares %r14's window; one page resident. */
    movq $0x11, (%r14)
    mov $57, %eax
    syscall
    test %eax, %eax
    js fail_fork
    jz child
    mov %eax, %r12d
    mov %r12d, %edi
    lea -24(%rsp), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $61, %eax
    syscall
    cmp %r12d, %eax
    jne fail_wait
    cmpq $0x11, (%r14)
    jne fail_value
    /* The child's exit code is the run's. */
    movzbl -23(%rsp), %edi
    jmp die
child:
    /* Inherited outputs: the resident page and a prepared one. */
    cmpq $0x11, (%r14)
    jne fail_value
    movq $0x22, 0x1000(%r14)
    mov $INJECT_GRANT_OCCUPIED_REFUSAL_ONCE, %rax
    syscall
    test %rax, %rax
    jnz fail_arm
    /* A fresh window: its first publication is refused as occupied. */
    movq $0x33, 0x5000(%r15)
    mov $INJECT_GRANT_REFUSAL_CENSUS, %rax
    syscall
    mov %rax, %rcx
    shr $32, %rcx
    cmp $1, %rcx
    jne fail_census
    /* The replan published a window, not a single page. */
    cmp $1, %eax
    jbe fail_census
    cmpq $0x22, 0x1000(%r14)
    jne fail_value
    cmpq $0x33, 0x5000(%r15)
    jne fail_value
    movq $0x44, 0x6000(%r15)
    cmpq $0x44, 0x6000(%r15)
    jne fail_value
    mov $7, %edi
    jmp die
#elif defined(TERMINAL)
    mov $INJECT_GRANT_TERMINAL_REFUSAL_ONCE, %rax
    syscall
    test %rax, %rax
    jnz fail_arm
    movq $0x11, 0x101000(%r14)
    mov $7, %edi
    jmp die
#else
#error "define CAPACITY, INHERITED or TERMINAL"
#endif

fail_arena:  mov $90, %edi; jmp die
fail_arm:    mov $91, %edi; jmp die
fail_census: mov $92, %edi; jmp die
fail_value:  mov $93, %edi; jmp die
fail_fork:   mov $94, %edi; jmp die
fail_wait:   mov $95, %edi; jmp die

die:
    mov $231, %eax
    syscall
    ud2
