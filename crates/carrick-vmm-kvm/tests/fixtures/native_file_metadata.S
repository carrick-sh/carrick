/* File-metadata calls on ring-held host files (the pip and apt parity
 * workloads, #231). Every step writes one byte to stdout: 0 for success,
 * the errno for a failure, or the value a query returns; the native oracle
 * writes the same bytes. The run exits 0 after the report.
 *   FILE_PATH  an existing regular file.
 *   LOCK_PATH  a path that does not exist yet (created by step 9).
 *   -DCHILD    a fork child runs the steps; the parent exits with its
 *              status.
 * Steps:
 *   1 openat(FILE_PATH, O_RDONLY)              CPython's fopen of a script
 *   2 ioctl(fd, FIOCLEX)                       CPython's set_inheritable
 *   3 fcntl(fd, F_GETFD)                       1
 *   4 ioctl(fd, FIONCLEX)
 *   5 fcntl(fd, F_GETFD)                       0
 *   6 fchmod(fd, 0640)
 *   7 fchown(fd, -1, -1)
 *   8 fchmodat(AT_FDCWD, FILE_PATH, 0644, 0)   apt's chmod
 *   9 fchownat(AT_FDCWD, FILE_PATH, -1, -1, AT_SYMLINK_NOFOLLOW)  apt's lchown
 *  10 openat(LOCK_PATH, O_RDWR|O_CREAT|O_NOFOLLOW, 0640)          apt's lock
 *  11 fcntl(lock, F_SETLK, F_WRLCK whole file)
 *  12 fcntl(lock, F_GETLK, F_WRLCK): l_type is F_UNLCK (2), own lock
 *  13 flock(lock, LOCK_EX|LOCK_NB)
 *  14 fchmodat(AT_FDCWD, LOCK_PATH, 0600, 0) after create */
.global _start
.text

/* Record %rax as the step's byte: errno when negative, else 0. */
.macro record_status
    call status_byte
.endm

_start:
    lea out(%rip), %r15
#ifdef CHILD
    mov $57, %eax                   /* fork */
    syscall
    test %rax, %rax
    js fork_failed
    jz steps
    mov %rax, %rbx
    mov %rbx, %rdi                  /* wait4(pid, &status, 0, NULL) */
    lea status(%rip), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $61, %eax
    syscall
    cmp %rbx, %rax
    jne fork_failed
    mov status(%rip), %edi
    shr $8, %edi
    and $0xff, %edi
    jmp exit
fork_failed:
    mov $90, %edi
    jmp exit
#endif
steps:
    mov $-100, %edi                 /* 1: openat(AT_FDCWD, file, O_RDONLY) */
    lea file(%rip), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $257, %eax
    syscall
    mov %rax, %r12
    record_status

    mov %r12, %rdi                  /* 2: ioctl(fd, FIOCLEX) */
    mov $0x5451, %esi
    xor %edx, %edx
    mov $16, %eax
    syscall
    record_status

    mov %r12, %rdi                  /* 3: fcntl(fd, F_GETFD) */
    mov $1, %esi
    mov $72, %eax
    syscall
    call value_byte

    mov %r12, %rdi                  /* 4: ioctl(fd, FIONCLEX) */
    mov $0x5450, %esi
    xor %edx, %edx
    mov $16, %eax
    syscall
    record_status

    mov %r12, %rdi                  /* 5: fcntl(fd, F_GETFD) */
    mov $1, %esi
    mov $72, %eax
    syscall
    call value_byte

    mov %r12, %rdi                  /* 6: fchmod(fd, 0640) */
    mov $0640, %esi
    mov $91, %eax
    syscall
    record_status

    mov %r12, %rdi                  /* 7: fchown(fd, -1, -1) */
    mov $-1, %esi
    mov $-1, %edx
    mov $93, %eax
    syscall
    record_status

    mov $-100, %edi                 /* 8: fchmodat(AT_FDCWD, file, 0644, 0) */
    lea file(%rip), %rsi
    mov $0644, %edx
    xor %r10d, %r10d
    mov $268, %eax
    syscall
    record_status

    mov $-100, %edi                 /* 9: fchownat(AT_FDCWD, file, -1, -1, NOFOLLOW) */
    lea file(%rip), %rsi
    mov $-1, %edx
    mov $-1, %r10d
    mov $0x100, %r8d
    mov $260, %eax
    syscall
    record_status

    mov $-100, %edi                 /* 10: openat(lock, O_RDWR|O_CREAT|O_NOFOLLOW, 0640) */
    lea lock(%rip), %rsi
    mov $0x20042, %edx
    mov $0640, %r10d
    mov $257, %eax
    syscall
    mov %rax, %r13
    record_status

    movw $1, flk(%rip)              /* 11: fcntl(lock, F_SETLK, F_WRLCK, SEEK_SET, 0, 0) */
    mov %r13, %rdi
    mov $6, %esi
    lea flk(%rip), %rdx
    mov $72, %eax
    syscall
    record_status

    movw $1, flk(%rip)              /* 12: fcntl(lock, F_GETLK): own lock is F_UNLCK */
    mov %r13, %rdi
    mov $5, %esi
    lea flk(%rip), %rdx
    mov $72, %eax
    syscall
    test %rax, %rax
    js 1f
    movzwl flk(%rip), %eax
1:  call value_byte

    mov %r13, %rdi                  /* 13: flock(lock, LOCK_EX|LOCK_NB) */
    mov $6, %esi
    mov $73, %eax
    syscall
    record_status

    mov $-100, %edi                 /* 14: fchmodat(AT_FDCWD, lock, 0600, 0) */
    lea lock(%rip), %rsi
    mov $0600, %edx
    xor %r10d, %r10d
    mov $268, %eax
    syscall
    record_status

    mov $1, %edi                    /* write(1, out, steps) */
    lea out(%rip), %rsi
    mov %r15, %rdx
    sub %rsi, %rdx
    mov $1, %eax
    syscall
    xor %edi, %edi
exit:
    mov $231, %eax
    syscall
    ud2

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
file: .asciz FILE_PATH
lock: .asciz LOCK_PATH
.section .bss
.balign 64
status: .skip 8
flk: .skip 32
out: .skip 64
.section .note.GNU-stack,"",@progbits
