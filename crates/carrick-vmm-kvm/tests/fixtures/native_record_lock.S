/* Two processes contend POSIX record locks and flock(2) on one file (#231:
 * apt's lock files, taken by the run root and by fork children). Every step
 * writes one byte: 0 for success, the errno for a failure, or the value a
 * query returns (0x80 | errno if it failed). The child writes its bytes and
 * exits; the parent then writes its own. The native oracle writes the same.
 *   LOCK_PATH  a path that does not exist yet (created by step P1).
 * Parent, before fork:
 *   P1 openat(LOCK_PATH, O_RDWR|O_CREAT, 0640)       fd a
 *   P2 fcntl(a, F_SETLK, F_WRLCK whole file)
 *   P3 openat(LOCK_PATH, O_RDWR)                     fd b, its own OFD
 *   P4 flock(b, LOCK_EX|LOCK_NB)
 *   P5 pipe2(ready), pipe2(go)
 * Child (fork):
 *   C1 fcntl(a, F_SETLK, F_WRLCK)                     EAGAIN: the parent's
 *   C2 fcntl(a, F_GETLK, F_WRLCK): l_type             1 (F_WRLCK)
 *   C3 that l_pid == getppid()                        1
 *   C4 openat(LOCK_PATH, O_RDWR)                      fd c, its own OFD
 *   C5 flock(c, LOCK_EX|LOCK_NB)                      EWOULDBLOCK: b's
 *   C6 write(ready): the child is about to wait
 *   C7 fcntl(a, F_SETLKW, F_WRLCK)                    0 once P8 unlocks
 *   C8 close(c): releases the child's record lock (any fd of the file)
 *   C9 write(ready)
 *  C10 read(go)
 *  C11 fcntl(a, F_SETLK, F_WRLCK)                     0; held at exit
 * Parent, after fork:
 *   P6 read(ready)
 *   P7 futex(FUTEX_WAIT) on a private word for 50 ms: let the child
 *      reach its wait in C7 (not required for the verdict; it only makes
 *      the wait in C7 park rather than find the lock already free)
 *   P8 fcntl(a, F_SETLK, F_UNLCK)
 *   P9 read(ready)
 *  P10 fcntl(a, F_GETLK, F_WRLCK): l_type             2: C8's close released
 *  P11 fcntl(a, F_SETLK, F_WRLCK)                     0
 *  P12 fcntl(a, F_SETLK, F_UNLCK)
 *  P13 write(go)
 *  P14 wait4(child): exit code                        0
 *  P15 fcntl(a, F_GETLK, F_WRLCK): l_type             2: exit released C11
 *  P16 openat(LOCK_PATH, O_RDWR)                      fd d, its own OFD
 *  P17 flock(d, LOCK_EX|LOCK_NB)                      EWOULDBLOCK: b's
 *  P18 close(b): the last reference of b's OFD
 *  P19 flock(d, LOCK_EX|LOCK_NB)                      0 */
.global _start
.text

.macro record_status
    call status_byte
.endm

/* fcntl(%r12, cmd, &flk) with flk = {type, SEEK_SET, 0, 0}. */
.macro record_lock cmd, type
    movw $\type, flk(%rip)
    movw $0, flk+2(%rip)
    movq $0, flk+8(%rip)
    movq $0, flk+16(%rip)
    movl $0, flk+24(%rip)
    mov %r12, %rdi
    mov $\cmd, %esi
    lea flk(%rip), %rdx
    mov $72, %eax
    syscall
.endm

/* The l_type a F_GETLK reported, or 0x80 | errno. */
.macro getlk_type
    record_lock 5, 1
    test %rax, %rax
    js 1f
    movzwl flk(%rip), %eax
1:  call value_byte
.endm

_start:
    lea out(%rip), %r15

    mov $-100, %edi                 /* P1: openat(lock, O_RDWR|O_CREAT, 0640) */
    lea lock(%rip), %rsi
    mov $0x42, %edx
    mov $0640, %r10d
    mov $257, %eax
    syscall
    mov %rax, %r12
    record_status

    record_lock 6, 1                /* P2: F_SETLK F_WRLCK */
    record_status

    call open_lock                  /* P3: fd b */
    mov %rax, %r13
    record_status

    mov %r13, %rdi                  /* P4: flock(b, LOCK_EX|LOCK_NB) */
    mov $6, %esi
    mov $73, %eax
    syscall
    record_status

    lea ready(%rip), %rdi           /* P5: pipe2(ready), pipe2(go) */
    xor %esi, %esi
    mov $293, %eax
    syscall
    test %rax, %rax
    js 1f
    lea go(%rip), %rdi
    xor %esi, %esi
    mov $293, %eax
    syscall
1:  record_status

    mov $57, %eax                   /* fork */
    syscall
    test %rax, %rax
    js fork_failed
    jz child
    mov %rax, %rbx

    movl ready(%rip), %edi          /* P6: read(ready) */
    call read_byte
    record_status

    lea pause_word(%rip), %rdi      /* P7: futex(FUTEX_WAIT, 0, 50 ms) */
    xor %esi, %esi
    xor %edx, %edx
    lea pause_time(%rip), %r10
    xor %r8d, %r8d
    xor %r9d, %r9d
    mov $202, %eax
    syscall

    record_lock 6, 2                /* P8: F_SETLK F_UNLCK */
    record_status

    movl ready(%rip), %edi          /* P9: read(ready) */
    call read_byte
    record_status

    getlk_type                      /* P10: F_GETLK l_type */

    record_lock 6, 1                /* P11: F_SETLK F_WRLCK */
    record_status

    record_lock 6, 2                /* P12: F_SETLK F_UNLCK */
    record_status

    movl go+4(%rip), %edi           /* P13: write(go) */
    call write_byte
    record_status

    mov %rbx, %rdi                  /* P14: wait4(child, &status, 0, NULL) */
    lea status(%rip), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $61, %eax
    syscall
    cmp %rbx, %rax
    jne fork_failed
    mov status(%rip), %eax
    shr $8, %eax
    and $0xff, %eax
    call value_byte

    getlk_type                      /* P15: F_GETLK l_type */

    call open_lock                  /* P16: fd d */
    mov %rax, %r14
    record_status

    mov %r14, %rdi                  /* P17: flock(d, LOCK_EX|LOCK_NB) */
    mov $6, %esi
    mov $73, %eax
    syscall
    record_status

    mov %r13, %rdi                  /* P18: close(b) */
    mov $3, %eax
    syscall
    record_status

    mov %r14, %rdi                  /* P19: flock(d, LOCK_EX|LOCK_NB) */
    mov $6, %esi
    mov $73, %eax
    syscall
    record_status

    call report
    xor %edi, %edi
    jmp exit

child:
    record_lock 6, 1                /* C1: F_SETLK F_WRLCK */
    record_status

    getlk_type                      /* C2: F_GETLK l_type */

    movslq flk+24(%rip), %rbx       /* C3: l_pid == getppid() */
    mov $110, %eax
    syscall
    cmp %rax, %rbx
    sete %al
    movzbl %al, %eax
    call value_byte

    call open_lock                  /* C4: fd c */
    mov %rax, %r14
    record_status

    mov %r14, %rdi                  /* C5: flock(c, LOCK_EX|LOCK_NB) */
    mov $6, %esi
    mov $73, %eax
    syscall
    record_status

    movl ready+4(%rip), %edi        /* C6: write(ready) */
    call write_byte
    record_status

    record_lock 7, 1                /* C7: F_SETLKW F_WRLCK */
    record_status

    mov %r14, %rdi                  /* C8: close(c) */
    mov $3, %eax
    syscall
    record_status

    movl ready+4(%rip), %edi        /* C9: write(ready) */
    call write_byte
    record_status

    movl go(%rip), %edi             /* C10: read(go) */
    call read_byte
    record_status

    record_lock 6, 1                /* C11: F_SETLK F_WRLCK, held at exit */
    record_status

    call report
    xor %edi, %edi
    jmp exit

fork_failed:
    mov $90, %edi
exit:
    mov $231, %eax
    syscall
    ud2

/* openat(AT_FDCWD, lock, O_RDWR) */
open_lock:
    mov $-100, %edi
    lea lock(%rip), %rsi
    mov $2, %edx
    xor %r10d, %r10d
    mov $257, %eax
    syscall
    ret

/* read(%edi, &byte, 1); 0 bytes is EPIPE-like failure (byte 0xff). */
read_byte:
    lea byte(%rip), %rsi
    mov $1, %edx
    xor %eax, %eax
    syscall
    test %rax, %rax
    jg 1f
    js 1f
    mov $-255, %rax
1:  ret

/* write(%edi, &byte, 1) */
write_byte:
    lea byte(%rip), %rsi
    mov $1, %edx
    mov $1, %eax
    syscall
    ret

/* write(1, out, steps) */
report:
    mov $1, %edi
    lea out(%rip), %rsi
    mov %r15, %rdx
    sub %rsi, %rdx
    mov $1, %eax
    syscall
    ret

/* Append errno (or 0) for a syscall result in %rax. */
status_byte:
    test %rax, %rax
    js 1f
    xor %eax, %eax
    jmp 2f
1:  neg %rax
2:  movb %al, (%r15)
    inc %r15
    ret

/* Append a query's value; a failure appends 0x80 | errno. */
value_byte:
    test %rax, %rax
    jns 1f
    neg %rax
    or $0x80, %eax
1:  movb %al, (%r15)
    inc %r15
    ret

.section .rodata
.balign 8
pause_time: .quad 0, 50000000
lock: .asciz LOCK_PATH
.section .bss
.balign 64
status: .skip 8
ready: .skip 8
go: .skip 8
byte: .skip 8
flk: .skip 32
out: .skip 64
pause_word: .skip 8
.section .note.GNU-stack,"",@progbits
