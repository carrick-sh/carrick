/* #2295: a host exclusion on another vCPU raises an address space's gate
 * between a record's switch-in and its space install. The install is
 * refused once ("not now"); the record keeps its owned result and reruns
 * once the holder lowers the gate. The main thread clones a worker that
 * raw-exits, arms the injected gate, and parks in a timed FUTEX_WAIT whose
 * timer wake is the switch-in the gate refuses: it must still return
 * ETIMEDOUT. Exits 7; 91 a failed check, 92 a lost or wrong futex result,
 * 93 an install that was never refused, or refused more than once. */
#define INJECT_INSTALL_GATE_ONCE -460 /* 0x...fe34 */
#define INJECT_INSTALL_GATE_CENSUS -459 /* 0x...fe35 */
.global _start
.text
_start:
    /* Nonzero until the worker's exit clears it (CLONE_CHILD_CLEARTID). */
    movl $1, child_tid(%rip)
    /* glibc's thread flags: VM|FS|FILES|SIGHAND|THREAD|SYSVSEM|SETTLS|
     * PARENT_SETTID|CHILD_CLEARTID. */
    mov $0x3d0f00, %edi
    lea thread_stack_top(%rip), %rsi
    lea parent_tid(%rip), %rdx
    lea child_tid(%rip), %r10
    lea tls(%rip), %r8
    mov $56, %eax
    syscall
    test %rax, %rax
    jz worker
    js failure
    mov $INJECT_INSTALL_GATE_ONCE, %rax
    syscall
    test %rax, %rax
    jnz failure
    /* FUTEX_WAIT_PRIVATE on never == 0 for 1 ms: always parks. */
    lea never(%rip), %rdi
    mov $128, %esi
    xor %edx, %edx
    lea timeout(%rip), %r10
    mov $202, %eax
    syscall
    cmp $-110, %rax
    jne failure_result
    /* Wait for the worker's raw exit to clear child_tid. */
1:
    mov child_tid(%rip), %edx
    test %edx, %edx
    jz 2f
    lea child_tid(%rip), %rdi
    xor %esi, %esi /* FUTEX_WAIT (shared): CHILD_CLEARTID wakes it */
    xor %r10d, %r10d
    mov $202, %eax
    syscall
    jmp 1b
2:
    mov $INJECT_INSTALL_GATE_CENSUS, %rax
    syscall
    mov $0x100000001, %rcx
    cmp %rcx, %rax
    jne failure_census
    mov $7, %edi
    jmp exit
worker:
    /* Raw exit: only this thread ends. */
    xor %edi, %edi
    mov $60, %eax
    syscall
    ud2
failure:
    mov $91, %edi
    jmp exit
failure_result:
    mov $92, %edi
    jmp exit
failure_census:
    mov $93, %edi
exit:
    mov $231, %eax
    syscall
    ud2

.data
.balign 8
timeout:
    .quad 0
    .quad 1000000
never:
    .long 0
child_tid:
    .long 0
parent_tid:
    .long 0
.balign 64
tls:
    .zero 256
.balign 16
thread_stack:
    .zero 16384
thread_stack_top:
