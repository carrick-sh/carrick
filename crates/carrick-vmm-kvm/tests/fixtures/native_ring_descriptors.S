/* #1714: ring-namespace descriptor calls on the production CPL0 path. Each
 * failed step exits with its number; the native oracle exits 0.
 *   -DBAD_FD     the run root's writev, getdents64 and statx(AT_EMPTY_PATH)
 *                on fd -1 and on a closed descriptor each return -EBADF.
 *   -DROOT_DIR   the run root opens DIR_PATH and getdents64 lists "library".
 *   -DCHILD      the run root opens FILE_PATH and DIR_PATH in its ring
 *                namespace and forks; the child reads, preads, seeks,
 *                fstats and getdents64s the inherited descriptors. The
 *                parent exits with the child's status. */
.global _start
.text
_start:
#ifdef BAD_FD
    mov $-100, %edi                 /* openat(AT_FDCWD, file, O_RDONLY|O_CLOEXEC) */
    lea file(%rip), %rsi
    mov $0x80000, %edx
    xor %r10d, %r10d
    mov $257, %eax
    syscall
    mov $10, %edi
    test %rax, %rax
    js exit
    mov %rax, %r12
    mov %r12, %rdi                  /* close(fd): its number is now closed */
    mov $3, %eax
    syscall
    mov $11, %edi
    test %rax, %rax
    jne exit
    mov $-1, %rbx
    mov $20, %r14d
    call bad_fd_calls               /* steps 20-22: fd -1 */
    mov %r12, %rbx
    mov $30, %r14d
    call bad_fd_calls               /* steps 30-32: the closed descriptor */
    xor %edi, %edi
    jmp exit
#elif defined(ROOT_DIR)
    mov $30, %r14d
    call list_directory             /* steps 30-33 */
    xor %edi, %edi
    jmp exit
#elif defined(CHILD) || defined(DIRFD)
    mov $-100, %edi                 /* openat(AT_FDCWD, file, O_RDONLY|O_CLOEXEC) */
    lea file(%rip), %rsi
    mov $0x80000, %edx
    xor %r10d, %r10d
    mov $257, %eax
    syscall
    mov $38, %edi
    test %rax, %rax
    js exit
    mov %rax, %r12
    mov $-100, %edi                 /* openat(AT_FDCWD, dir, O_RDONLY|O_DIRECTORY|O_CLOEXEC) */
    lea dir(%rip), %rsi
    mov $0x90000, %edx
    xor %r10d, %r10d
    mov $257, %eax
    syscall
    mov $39, %edi
    test %rax, %rax
    js exit
    mov %rax, %r13
    mov $57, %eax                   /* fork */
    syscall
    mov $40, %edi
    test %rax, %rax
    js exit
    jz child
    mov %rax, %rbx
#ifdef DIRFD
    /* The parent removes a sibling while the child walks the same directory. */
    mov %r13, %rdi
    lea parent_sibling(%rip), %rsi
    xor %edx, %edx
    mov $263, %eax
    syscall
    mov %rax, %r15
#endif
    mov %rbx, %rdi                  /* wait4(pid, &status, 0, NULL) == pid */
    lea status(%rip), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $61, %eax
    syscall
    mov $41, %edi
    cmp %rbx, %rax
    jne exit
    mov $42, %edi                   /* the child exited, not signalled */
    testl $0x7f, status(%rip)
    jne exit
    mov status(%rip), %edi
    shr $8, %edi
    and $0xff, %edi
#ifdef DIRFD
    jne exit
    test %r15, %r15
    jz exit
    mov $77, %edi
#endif
    jmp exit
child:
#ifdef DIRFD
    mov %r13, %rdi
    lea subdir(%rip), %rsi
    mov $0755, %edx
    mov $258, %eax                 /* mkdirat */
    syscall
    mov $70, %edi
    test %rax, %rax
    jne exit

    mov %r13, %rdi
    lea relative_file(%rip), %rsi
    mov $0x42, %edx
    mov $0600, %r10d
    mov $257, %eax                 /* openat */
    syscall
    mov $71, %edi
    test %rax, %rax
    js exit

    mov %r13, %rdi
    lea relative_file(%rip), %rsi
    lea st(%rip), %rdx
    xor %r10d, %r10d
    mov $262, %eax                 /* newfstatat */
    syscall
    mov $72, %edi
    test %rax, %rax
    jne exit

    mov %r13, %rdi
    lea subdir(%rip), %rsi
    mov $0x10000, %edx
    xor %r10d, %r10d
    mov $257, %eax                 /* a distinct destination dirfd */
    syscall
    mov $76, %edi
    test %rax, %rax
    js exit
    mov %rax, %r14

    mov %r13, %rdi
    lea relative_file(%rip), %rsi
    mov %r14, %rdx
    lea moved(%rip), %r10
    mov $264, %eax                 /* renameat */
    syscall
    mov $73, %edi
    test %rax, %rax
    jne exit

    lea moved(%rip), %rdi
    mov %r14, %rsi
    lea symlink_name(%rip), %rdx
    mov $266, %eax                 /* symlinkat */
    syscall
    mov $87, %edi
    test %rax, %rax
    jne exit

    mov %r14, %rdi
    lea symlink_name(%rip), %rsi
    lea buf(%rip), %rdx
    mov $64, %r10d
    mov $267, %eax                 /* readlinkat */
    syscall
    mov $88, %edi
    cmp $5, %rax
    jne exit
    cmpl $0x65766f6d, buf(%rip)    /* "move" */
    jne exit
    cmpb $0x64, buf+4(%rip)       /* "d" */
    jne exit

    mov %r14, %rdi
    lea symlink_name(%rip), %rsi
    xor %edx, %edx
    mov $263, %eax
    syscall
    mov $89, %edi
    test %rax, %rax
    jne exit

    mov %r14, %rdi
    lea moved(%rip), %rsi
    xor %edx, %edx
    mov $263, %eax                 /* unlinkat file */
    syscall
    mov $74, %edi
    test %rax, %rax
    jne exit

    mov %r13, %rdi
    lea subdir(%rip), %rsi
    mov $0x200, %edx
    mov $263, %eax                 /* unlinkat(AT_REMOVEDIR) */
    syscall
    mov $75, %edi
    test %rax, %rax
    jne exit
    xor %edi, %edi
    jmp exit
#else
    mov %r12, %rdi                  /* read(fd, buf, 64) == 14, "loader library" */
    lea buf(%rip), %rsi
    mov $64, %edx
    xor %eax, %eax
    syscall
    mov $51, %edi
    cmp $14, %rax
    jne exit
    cmpb $0x6c, buf(%rip)
    jne exit

    mov %r12, %rdi                  /* pread64(fd, buf, 6, 7) == 6, "librar" */
    lea buf(%rip), %rsi
    mov $6, %edx
    mov $7, %r10d
    mov $17, %eax
    syscall
    mov $52, %edi
    cmp $6, %rax
    jne exit
    cmpb $0x62, buf+2(%rip)
    jne exit

    mov %r12, %rdi                  /* lseek(fd, 0, SEEK_CUR) == 14: pread kept the cursor */
    xor %esi, %esi
    mov $1, %edx
    mov $8, %eax
    syscall
    mov $53, %edi
    cmp $14, %rax
    jne exit

    mov %r12, %rdi                  /* lseek(fd, 2, SEEK_SET), read(fd, buf, 4) == "ader" */
    mov $2, %esi
    xor %edx, %edx
    mov $8, %eax
    syscall
    mov $54, %edi
    cmp $2, %rax
    jne exit
    mov %r12, %rdi
    lea buf(%rip), %rsi
    mov $4, %edx
    xor %eax, %eax
    syscall
    cmp $4, %rax
    jne exit
    cmpl $0x72656461, buf(%rip)
    jne exit

    mov %r12, %rdi                  /* fstat(fd, &st): x86 st_size@48, st_mode@24 */
    lea st(%rip), %rsi
    mov $5, %eax
    syscall
    mov $55, %edi
    test %rax, %rax
    jne exit
    cmpq $14, st+48(%rip)
    jne exit
    mov $56, %edi
    mov st+24(%rip), %eax
    and $0170000, %eax
    cmp $0100000, %eax
    jne exit

    mov $61, %r14d
    call list_open_directory        /* steps 61-63 */
    xor %edi, %edi
    jmp exit
#endif
#endif

#ifdef BAD_FD
/* writev, getdents64 and statx(fd, "", AT_EMPTY_PATH) on %rbx each return
 * -EBADF (9); a mismatch exits with %r14 plus the call's index. */
bad_fd_calls:
    mov %rbx, %rdi                  /* writev(fd, iov, 1) */
    lea iov(%rip), %rsi
    mov $1, %edx
    mov $20, %eax
    syscall
    mov %r14d, %edi
    cmp $-9, %rax
    jne exit
    mov %rbx, %rdi                  /* getdents64(fd, dents, 4096) */
    lea dents(%rip), %rsi
    mov $4096, %edx
    mov $217, %eax
    syscall
    lea 1(%r14), %edi
    cmp $-9, %rax
    jne exit
    mov %rbx, %rdi                  /* statx(fd, "", AT_EMPTY_PATH, STATX_BASIC_STATS, &stx) */
    lea empty(%rip), %rsi
    mov $0x1000, %edx
    mov $0x7ff, %r10d
    lea st(%rip), %r8
    mov $332, %eax
    syscall
    lea 2(%r14), %edi
    cmp $-9, %rax
    jne exit
    ret
#else
/* Open DIR_PATH, getdents64 it and find "library"; a second getdents64 is
 * at the end (0). A failure exits with %r14 plus the step's index. */
list_directory:
    mov $-100, %edi                 /* openat(AT_FDCWD, dir, O_RDONLY|O_DIRECTORY|O_CLOEXEC) */
    lea dir(%rip), %rsi
    mov $0x90000, %edx
    xor %r10d, %r10d
    mov $257, %eax
    syscall
    mov %r14d, %edi
    test %rax, %rax
    js exit
    mov %rax, %r13
    inc %r14d
/* getdents64 the directory open at %r13, steps %r14 to %r14 + 2. */
list_open_directory:
    mov %r13, %rdi                  /* getdents64(fd, dents, 4096) > 0 */
    lea dents(%rip), %rsi
    mov $4096, %edx
    mov $217, %eax
    syscall
    mov %r14d, %edi
    test %rax, %rax
    jle exit
    mov %rax, %rcx                  /* walk linux_dirent64: d_reclen@16, d_name@19 */
    xor %edx, %edx
    movabs $0x007972617262696c, %r8 /* "library\0" */
    lea 1(%r14), %edi
1:  cmp %rcx, %rdx
    jae exit
    lea dents(%rip), %rsi
    add %rdx, %rsi
    cmp 19(%rsi), %r8
    je 2f
    movzwl 16(%rsi), %eax
    test %eax, %eax
    jz exit
    add %rax, %rdx
    jmp 1b
2:  mov %r13, %rdi                  /* getdents64 again: the end, 0 */
    lea dents(%rip), %rsi
    mov $4096, %edx
    mov $217, %eax
    syscall
    lea 2(%r14), %edi
    test %rax, %rax
    jne exit
    ret
#endif
exit:
    mov $231, %eax
    syscall
    ud2
.section .rodata
file: .asciz FILE_PATH
#ifndef BAD_FD
dir: .asciz DIR_PATH
#endif
#ifdef DIRFD
subdir: .asciz "subdir"
relative_file: .asciz "file"
moved: .asciz "moved"
symlink_name: .asciz "symlink"
parent_sibling: .asciz "parent-sibling"
#endif
empty: .asciz ""
msg: .ascii "x"
.section .data
.balign 16
iov: .quad msg, 1
.section .bss
.balign 64
status: .skip 8
buf: .skip 64
st: .skip 256
dents: .skip 4096
.section .note.GNU-stack,"",@progbits
