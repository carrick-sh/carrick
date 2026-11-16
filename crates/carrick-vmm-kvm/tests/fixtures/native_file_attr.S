/* chmod and chown on ring-held host files and paths (apt's "chown ...
 * (38)" and "chmod 0755 ... (38)", #231). Every step writes one byte to
 * stdout: 0 for success, the errno for a failure, or the value a query
 * returns; the native oracle writes the same bytes. The run exits 0 after
 * the report.
 *   FILE_PATH     an existing regular file the caller owns, mode 0644.
 *   LINK_PATH     a path that does not exist yet (a symlink, step 7).
 *   MISSING_PATH  a path that never exists.
 *   NOTDIR_PATH   FILE_PATH followed by a component (ENOTDIR).
 *   NOSEARCH_PATH a name in a mode-0600 directory (EACCES: no search).
 *   DROP_GID, ALT_GID  the oracle user's egid and another of its groups
 *                 (its egid again when it has no other). A root caller
 *                 takes both as its groups and drops to uid 65534, gid
 *                 DROP_GID; the oracle is not root.
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
 *  The legacy calls' path errors (uid = getuid(), gid = getegid()):
 *  19 chmod(MISSING_PATH, 0644)                         ENOENT
 *  20 chown(MISSING_PATH, uid, -1)                      ENOENT
 *  21 lchown(MISSING_PATH, -1, gid)                     ENOENT
 *  22 chmod(NOTDIR_PATH, 0644)                          ENOTDIR
 *  23 chown(NOTDIR_PATH, uid, -1)                       ENOTDIR
 *  24 lchown(NOTDIR_PATH, -1, gid)                      ENOTDIR
 *  25 chmod(1, 0644)                                    EFAULT
 *  26 chown(1, uid, -1)                                 EFAULT
 *  27 lchown(1, -1, gid)                                EFAULT
 *  28 chmod(a 300-byte component, 0644)                 ENAMETOOLONG
 *  29 chown(a 300-byte component, uid, -1)              ENAMETOOLONG
 *  30 lchown(a 300-byte component, -1, gid)             ENAMETOOLONG
 *  -- a root caller gives the file and the link to 65534:ALT_GID and drops
 *  to them; the oracle moves both to its ALT_GID (the caller then owns
 *  both, each in ALT_GID). uid/gid are the dropped ids. --
 *  31 fchown(fd, uid, -1)                  the owner keeps its own uid
 *  32 chown(FILE_PATH, uid, -1)
 *  33 lchown(FILE_PATH, uid, -1)
 *  34 lchown(LINK_PATH, -1, gid)           changes the link, not the file
 *  35 owner byte: 1 if lstat(LINK).gid == gid, | 2 if stat(FILE).gid == gid
 *  36 chown(LINK_PATH, uid, gid)           follows the link to the file
 *  37 owner byte                                        3
 *  38 fchown(fd, -1, ALT_GID)              a group the caller is in
 *  39 owner byte                       1 (3 when ALT_GID is the egid)
 *  40 fchown(fd, 0, -1)                                 EPERM
 *  41 fchownat(AT_FDCWD, FILE_PATH, 0, -1, 0)           EPERM
 *  42 chown(FILE_PATH, 0, -1)                           EPERM
 *  43 chown(FILE_PATH, -1, 0)              not in group 0: EPERM
 *  44 lchown(LINK_PATH, 0, gid)                         EPERM
 *  45 chmod("/tmp", 01777)                 not the owner: EPERM
 *  46 chown("/tmp", uid, -1)               not the owner: EPERM
 *  47 lchown("/tmp", -1, gid)                           EPERM
 *  48 chmod(NOSEARCH_PATH, 0644)                        EACCES
 *  49 chown(NOSEARCH_PATH, uid, -1)                     EACCES
 *  50 lchown(NOSEARCH_PATH, -1, gid)                    EACCES */
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

    mov $102, %eax                  /* uid = getuid(), gid = getegid() */
    syscall
    mov %rax, %r13
    mov $108, %eax
    syscall
    mov %rax, %r14

    lea missing(%rip), %rbx         /* 19-21: ENOENT */
    call legacy_trio
    lea notdir(%rip), %rbx          /* 22-24: ENOTDIR */
    call legacy_trio
    mov $1, %ebx                    /* 25-27: EFAULT */
    call legacy_trio
    lea toolong(%rip), %rbx         /* 28-30: ENAMETOOLONG */
    call legacy_trio

    test %r13, %r13                 /* a root caller gives the file away */
    jnz 3f
    mov $2, %edi                    /* setgroups(2, {DROP_GID, ALT_GID}) */
    lea groups(%rip), %rsi
    mov $116, %eax
    syscall
    test %rax, %rax
    jnz drop_failed
    mov $65534, %edx
    call own_file_and_link
    mov $DROP_GID, %edi             /* setresgid(DROP_GID x3) */
    mov $DROP_GID, %esi
    mov $DROP_GID, %edx
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
    jmp 4f
3:  mov $-1, %edx                   /* the oracle moves both to ALT_GID */
    call own_file_and_link
4:
    mov $102, %eax                  /* the dropped uid and egid */
    syscall
    mov %rax, %r13
    mov $108, %eax
    syscall
    mov %rax, %r14

    mov %r12, %rdi                  /* 31: fchown(fd, uid, -1) */
    mov %r13, %rsi
    mov $-1, %edx
    mov $93, %eax
    syscall
    call status_byte

    lea file(%rip), %rdi            /* 32: chown(file, uid, -1) */
    mov %r13, %rsi
    mov $-1, %edx
    mov $92, %eax
    syscall
    call status_byte

    lea file(%rip), %rdi            /* 33: lchown(file, uid, -1) */
    mov %r13, %rsi
    mov $-1, %edx
    mov $94, %eax
    syscall
    call status_byte

    lea link(%rip), %rdi            /* 34: lchown(link, -1, gid) */
    mov $-1, %esi
    mov %r14, %rdx
    mov $94, %eax
    syscall
    call status_byte
    call owner_byte                 /* 35 */

    lea link(%rip), %rdi            /* 36: chown(link, uid, gid) */
    mov %r13, %rsi
    mov %r14, %rdx
    mov $92, %eax
    syscall
    call status_byte
    call owner_byte                 /* 37 */

    mov %r12, %rdi                  /* 38: fchown(fd, -1, ALT_GID) */
    mov $-1, %esi
    mov $ALT_GID, %edx
    mov $93, %eax
    syscall
    call status_byte
    call owner_byte                 /* 39 */

    mov %r12, %rdi                  /* 40: fchown(fd, 0, -1) */
    xor %esi, %esi
    mov $-1, %edx
    mov $93, %eax
    syscall
    call status_byte

    mov $-100, %edi                 /* 41: fchownat(AT_FDCWD, file, 0, -1, 0) */
    lea file(%rip), %rsi
    xor %edx, %edx
    mov $-1, %r10d
    xor %r8d, %r8d
    mov $260, %eax
    syscall
    call status_byte

    lea file(%rip), %rdi            /* 42: chown(file, 0, -1) */
    xor %esi, %esi
    mov $-1, %edx
    mov $92, %eax
    syscall
    call status_byte

    lea file(%rip), %rdi            /* 43: chown(file, -1, 0) */
    mov $-1, %esi
    xor %edx, %edx
    mov $92, %eax
    syscall
    call status_byte

    lea link(%rip), %rdi            /* 44: lchown(link, 0, gid) */
    xor %esi, %esi
    mov %r14, %rdx
    mov $94, %eax
    syscall
    call status_byte

    lea tmpdir(%rip), %rdi          /* 45: chmod("/tmp", 01777) */
    mov $01777, %esi
    mov $90, %eax
    syscall
    call status_byte

    lea tmpdir(%rip), %rdi          /* 46: chown("/tmp", uid, -1) */
    mov %r13, %rsi
    mov $-1, %edx
    mov $92, %eax
    syscall
    call status_byte

    lea tmpdir(%rip), %rdi          /* 47: lchown("/tmp", -1, gid) */
    mov $-1, %esi
    mov %r14, %rdx
    mov $94, %eax
    syscall
    call status_byte

    lea nosearch(%rip), %rbx        /* 48-50: EACCES */
    call legacy_trio

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

/* chmod(%rbx, 0644), chown(%rbx, uid, -1), lchown(%rbx, -1, gid): three
 * status bytes. */
legacy_trio:
    mov %rbx, %rdi
    mov $0644, %esi
    mov $90, %eax
    syscall
    call status_byte
    mov %rbx, %rdi
    mov %r13, %rsi
    mov $-1, %edx
    mov $92, %eax
    syscall
    call status_byte
    mov %rbx, %rdi
    mov $-1, %esi
    mov %r14, %rdx
    mov $94, %eax
    syscall
    call status_byte
    ret

/* fchownat the file, then the link itself, to (%edx, ALT_GID); a failure
 * exits 91. */
own_file_and_link:
    mov %edx, %ebx
    mov $-100, %edi
    lea file(%rip), %rsi
    mov $ALT_GID, %r10d
    xor %r8d, %r8d
    mov $260, %eax
    syscall
    test %rax, %rax
    jnz 1f
    mov $-100, %edi
    lea link(%rip), %rsi
    mov %ebx, %edx
    mov $ALT_GID, %r10d
    mov $0x100, %r8d
    mov $260, %eax
    syscall
    test %rax, %rax
    jnz 1f
    ret
1:  add $8, %rsp
    jmp drop_failed

/* Append 1 if lstat(link).st_gid == gid, | 2 if stat(file).st_gid == gid;
 * a failed stat appends 0x80 | errno. */
owner_byte:
    mov $-100, %edi
    lea link(%rip), %rsi
    lea st(%rip), %rdx
    mov $0x100, %r10d
    mov $262, %eax
    syscall
    test %rax, %rax
    js 3f
    xor %ebx, %ebx
    cmp st+32(%rip), %r14d
    jne 1f
    or $1, %ebx
1:  mov $-100, %edi
    lea file(%rip), %rsi
    lea st(%rip), %rdx
    xor %r10d, %r10d
    mov $262, %eax
    syscall
    test %rax, %rax
    js 3f
    cmp st+32(%rip), %r14d
    jne 2f
    or $2, %ebx
2:  mov %ebx, %eax
    jmp 4f
3:  neg %rax
    or $0x80, %eax
4:  movb %al, (%r15)
    inc %r15
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
notdir: .asciz NOTDIR_PATH
nosearch: .asciz NOSEARCH_PATH
tmpdir: .asciz "/tmp"
toolong: .fill 300, 1, 'a'
    .byte 0
.section .data
.balign 4
groups: .long DROP_GID, ALT_GID
.section .bss
.balign 64
status: .skip 8
st: .skip 144
out: .skip 128
.section .note.GNU-stack,"",@progbits
