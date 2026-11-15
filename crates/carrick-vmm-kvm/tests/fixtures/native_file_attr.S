/* chmod and chown on ring-held host files and paths (apt's "chown ...
 * (38)" and "chmod 0755 ... (38)", #231). Every step writes one byte to
 * stdout: 0 for success, the errno for a failure, or the value a query
 * returns; the native oracle writes the same bytes. The run exits 0 after
 * the report.
 *   FILE_PATH     an existing regular file the caller owns, mode 0644.
 *   LINK_PATH     a path that does not exist yet (a symlink, step 7).
 *   MISSING_PATH  a path that never exists.
 *   -DCHILD       a fork child runs the steps; the parent exits with its
 *                 status.
 * Steps:
 *   1 openat(FILE_PATH, O_RDWR)
 *   2 fchmod(fd, 0640)
 *   3 fstat(fd): st_mode & 077                          040
 *   4 fchown(fd, -1, -1)
 *   5 fchmodat(AT_FDCWD, FILE_PATH, 0600, 0)
 *   6 newfstatat(FILE_PATH): st_mode & 077              0
 *   7 symlinkat(FILE_PATH, AT_FDCWD, LINK_PATH)
 *   8 fchownat(AT_FDCWD, LINK_PATH, -1, -1, AT_SYMLINK_NOFOLLOW)  apt's lchown
 *   9 fchmodat2(AT_FDCWD, LINK_PATH, 0600, AT_SYMLINK_NOFOLLOW)   EOPNOTSUPP
 *  10 fchmodat(AT_FDCWD, MISSING_PATH, 0600)            ENOENT
 *  11 fchownat(AT_FDCWD, MISSING_PATH, -1, -1, 0)       ENOENT
 *  12 fchmod(999, 0600)                                 EBADF
 *  13 fchown(999, -1, -1)                               EBADF
 *  14 openat(FILE_PATH, O_PATH); fchmod(path fd, 0600)  EBADF
 *  15 chmod(FILE_PATH, 0644)                            legacy x86 90
 *  16 newfstatat(FILE_PATH): st_mode & 077              044
 *  17 chown(FILE_PATH, -1, -1)                          legacy x86 92
 *  18 lchown(LINK_PATH, -1, -1)                         legacy x86 94
 *  -- a root caller drops to uid/gid 65534 (the oracle is not root) --
 *  19 fchown(fd, 0, -1)                                 EPERM
 *  20 fchownat(AT_FDCWD, FILE_PATH, 0, -1, 0)           EPERM */
.global _start
.text

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
    mov $-100, %edi                 /* 1: openat(AT_FDCWD, file, O_RDWR) */
    lea file(%rip), %rsi
    mov $2, %edx
    xor %r10d, %r10d
    mov $257, %eax
    syscall
    mov %rax, %r12
    call status_byte

    mov %r12, %rdi                  /* 2: fchmod(fd, 0640) */
    mov $0640, %esi
    mov $91, %eax
    syscall
    call status_byte

    mov %r12, %rdi                  /* 3: fstat(fd): group/other bits */
    lea st(%rip), %rsi
    mov $5, %eax
    syscall
    call mode_byte

    mov %r12, %rdi                  /* 4: fchown(fd, -1, -1) */
    mov $-1, %esi
    mov $-1, %edx
    mov $93, %eax
    syscall
    call status_byte

    mov $-100, %edi                 /* 5: fchmodat(AT_FDCWD, file, 0600, 0) */
    lea file(%rip), %rsi
    mov $0600, %edx
    xor %r10d, %r10d
    mov $268, %eax
    syscall
    call status_byte

    lea file(%rip), %rsi            /* 6: newfstatat(file): group/other bits */
    call path_mode_byte

    lea file(%rip), %rdi            /* 7: symlinkat(file, AT_FDCWD, link) */
    mov $-100, %esi
    lea link(%rip), %rdx
    mov $266, %eax
    syscall
    call status_byte

    mov $-100, %edi                 /* 8: fchownat(AT_FDCWD, link, -1, -1, NOFOLLOW) */
    lea link(%rip), %rsi
    mov $-1, %edx
    mov $-1, %r10d
    mov $0x100, %r8d
    mov $260, %eax
    syscall
    call status_byte

    mov $-100, %edi                 /* 9: fchmodat2(AT_FDCWD, link, 0600, NOFOLLOW) */
    lea link(%rip), %rsi
    mov $0600, %edx
    mov $0x100, %r10d
    mov $452, %eax
    syscall
    call status_byte

    mov $-100, %edi                 /* 10: fchmodat(AT_FDCWD, missing, 0600) */
    lea missing(%rip), %rsi
    mov $0600, %edx
    xor %r10d, %r10d
    mov $268, %eax
    syscall
    call status_byte

    mov $-100, %edi                 /* 11: fchownat(AT_FDCWD, missing, -1, -1, 0) */
    lea missing(%rip), %rsi
    mov $-1, %edx
    mov $-1, %r10d
    xor %r8d, %r8d
    mov $260, %eax
    syscall
    call status_byte

    mov $999, %edi                  /* 12: fchmod(999, 0600) */
    mov $0600, %esi
    mov $91, %eax
    syscall
    call status_byte

    mov $999, %edi                  /* 13: fchown(999, -1, -1) */
    mov $-1, %esi
    mov $-1, %edx
    mov $93, %eax
    syscall
    call status_byte

    mov $-100, %edi                 /* 14: openat(file, O_PATH); fchmod(it, 0600) */
    lea file(%rip), %rsi
    mov $0x200000, %edx
    xor %r10d, %r10d
    mov $257, %eax
    syscall
    test %rax, %rax
    js 1f
    mov %rax, %rdi
    mov $0600, %esi
    mov $91, %eax
    syscall
1:  call status_byte

    lea file(%rip), %rdi            /* 15: chmod(file, 0644) */
    mov $0644, %esi
    mov $90, %eax
    syscall
    call status_byte

    lea file(%rip), %rsi            /* 16: newfstatat(file): group/other bits */
    call path_mode_byte

    lea file(%rip), %rdi            /* 17: chown(file, -1, -1) */
    mov $-1, %esi
    mov $-1, %edx
    mov $92, %eax
    syscall
    call status_byte

    lea link(%rip), %rdi            /* 18: lchown(link, -1, -1) */
    mov $-1, %esi
    mov $-1, %edx
    mov $94, %eax
    syscall
    call status_byte

    mov $102, %eax                  /* getuid(): a root caller drops */
    syscall
    test %rax, %rax
    jnz 2f
    mov $65534, %edi                /* setresgid(65534, 65534, 65534) */
    mov $65534, %esi
    mov $65534, %edx
    mov $119, %eax
    syscall
    test %rax, %rax
    jnz drop_failed
    mov $65534, %edi                /* setresuid(65534, 65534, 65534) */
    mov $65534, %esi
    mov $65534, %edx
    mov $117, %eax
    syscall
    test %rax, %rax
    jnz drop_failed
2:
    mov %r12, %rdi                  /* 19: fchown(fd, 0, -1) */
    xor %esi, %esi
    mov $-1, %edx
    mov $93, %eax
    syscall
    call status_byte

    mov $-100, %edi                 /* 20: fchownat(AT_FDCWD, file, 0, -1, 0) */
    lea file(%rip), %rsi
    xor %edx, %edx
    mov $-1, %r10d
    xor %r8d, %r8d
    mov $260, %eax
    syscall
    call status_byte

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
drop_failed:
    mov $91, %edi
    jmp exit

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

/* Append st_mode & 077 for a stat result in %rax; a failure appends
 * 0x80 | errno. */
mode_byte:
    test %rax, %rax
    jns 1f
    neg %rax
    or $0x80, %eax
    jmp 2f
1:  mov st+24(%rip), %eax
    and $077, %eax
2:  movb %al, (%r15)
    inc %r15
    ret

/* newfstatat(AT_FDCWD, %rsi, &st, 0), then mode_byte. */
path_mode_byte:
    mov $-100, %edi
    lea st(%rip), %rdx
    xor %r10d, %r10d
    mov $262, %eax
    syscall
    jmp mode_byte

.section .rodata
file: .asciz FILE_PATH
link: .asciz LINK_PATH
missing: .asciz MISSING_PATH
.section .bss
.balign 64
status: .skip 8
st: .skip 144
out: .skip 64
.section .note.GNU-stack,"",@progbits
