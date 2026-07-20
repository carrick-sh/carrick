// Deterministic native process-exit fixture.
//
// By default the initial thread parks forever in FUTEX_WAIT_PRIVATE (or shared
// FUTEX_WAIT with -DSHARED_FUTEX), then its sibling issues exit_group(37).
// With -DBUSY_SIBLING, the sibling instead spins forever in chained JIT code
// while the initial thread issues exit_group(0). Together these modes prove
// both host-wait interruption and asynchronous translated-code kicks.
.global _start
.section .text
_start:
    lea child_stack_end(%rip), %rsi
    mov $0x50f00, %rdi              // VM|FS|FILES|SIGHAND|THREAD|SYSVSEM
    xor %rdx, %rdx                  // parent_tid
    xor %r10, %r10                  // child_tid
    xor %r8, %r8                    // tls
    mov $56, %rax                   // clone
    syscall
    test %rax, %rax
    jz child

parent:
#ifdef BUSY_SIBLING
    lea delay(%rip), %rdi
    xor %rsi, %rsi
    mov $35, %rax                   // nanosleep
    syscall
    xor %rdi, %rdi
    mov $231, %rax                  // exit_group(0)
    syscall
#else
    lea futex_word(%rip), %rdi
#ifdef SHARED_FUTEX
    mov $0, %rsi                    // FUTEX_WAIT
#else
    mov $128, %rsi                  // FUTEX_WAIT_PRIVATE
#endif
    xor %rdx, %rdx                  // expected = 0
    xor %r10, %r10                  // timeout = NULL
    xor %r8, %r8
    xor %r9, %r9
    mov $202, %rax                  // futex
    syscall
    mov $99, %rdi                   // reached only if process exit was broken
    mov $231, %rax                  // exit_group
    syscall
#endif

child:
#ifdef BUSY_SIBLING
1:
    jmp 1b                          // no syscall/gateway boundary
#else
#ifndef IMMEDIATE_CHILD
    lea delay(%rip), %rdi
    xor %rsi, %rsi
    mov $35, %rax                   // nanosleep
    syscall
#endif
    mov $37, %rdi
    mov $231, %rax                  // exit_group
    syscall
#endif

.section .rodata
.align 8
delay:
    .quad 0, 100000000

.section .bss
.align 4
futex_word:
    .long 0
.align 16
.skip 65536
child_stack_end:
