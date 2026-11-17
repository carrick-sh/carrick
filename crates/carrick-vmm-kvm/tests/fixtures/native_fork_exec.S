/* Production fork-child exec witness. The successor is a real static ELF.
 * Exit with the exec errno if replacement returns; parent propagates status.
 * #2441: CYCLES rounds of LIVE concurrently live children (default 1 x 1),
 * each forked (vfork with VFORK) and exec'd, then all reaped: a fork, exec
 * or exit that leaked stock, scratch or heap refuses a later round. */
#ifndef CYCLES
#define CYCLES 1
#endif
#ifndef LIVE
#define LIVE 1
#endif
#define CLONE_VM 0x100
#define CLONE_VFORK 0x4000
#define SIGCHLD 17
.global _start
.text
_start:
    mov $CYCLES, %r12d
round:
    mov $LIVE, %r13d
spawn:
#if defined(VFORK)
    mov $(CLONE_VM | CLONE_VFORK | SIGCHLD), %edi
    xor %esi, %esi
    xor %edx, %edx
    xor %r10d, %r10d
    xor %r8d, %r8d
    mov $56, %eax
#else
    mov $57, %eax
#endif
    syscall
    test %eax, %eax
    js failure
    jz child
    dec %r13d
    jnz spawn
    mov $LIVE, %r13d
reap:
    /* wait4(-1, &status, 0, NULL) */
    mov $-1, %edi
    lea status(%rip), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $61, %eax
    syscall
    test %eax, %eax
    js failure
    mov status(%rip), %edi
    test $127, %edi
    jnz failure
    shr $8, %edi
    jnz exit
    dec %r13d
    jnz reap
    dec %r12d
    jnz round
    xor %edi, %edi
    jmp exit
child:
    lea successor(%rip), %rdi
    lea argv(%rip), %rsi
    xor %edx, %edx
    mov $59, %eax
    syscall
    neg %eax
    mov %eax, %edi
    jmp exit
failure:
    mov $91, %edi
exit:
    mov $231, %eax
    syscall
    ud2
.section .rodata
successor: .asciz SUCCESSOR_PATH
.balign 8
argv: .quad successor, 0
.section .bss
.balign 4
status: .space 4
