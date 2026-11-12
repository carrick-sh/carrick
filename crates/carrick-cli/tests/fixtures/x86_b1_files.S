/* #2157 B1, files family: mkdirat, openat, ftruncate, fallocate, fsync,
 * fdatasync, flock, fadvise64, symlinkat, readlinkat, linkat, renameat,
 * getdents64, unlinkat. The script runs in a scratch working directory.
 *
 *   (none)  the run root performs every call; each returns its native
 *           Linux result. Expected stdout "F\n", exit 7.
 *   CHILD   a forked child: a path call is a counted ENOSYS in ring (no host
 *           task) and leaves no host effect, which the parent proves by
 *           creating the directory afterwards; a closed descriptor is EBADF. */
#include "x86_b1_common.h"

.equ SYS_openat, 257
.equ SYS_mkdirat, 258
.equ SYS_unlinkat, 263
.equ SYS_renameat, 264
.equ SYS_linkat, 265
.equ SYS_symlinkat, 266
.equ SYS_readlinkat, 267
.equ SYS_getdents64, 217
.equ SYS_ftruncate, 77
.equ SYS_fsync, 74
.equ SYS_fdatasync, 75
.equ SYS_flock, 73
.equ SYS_fallocate, 285
.equ SYS_fadvise64, 221
.equ O_RDWR_CREAT, 0x42
.equ O_RDONLY_DIRECTORY, 0x10000
.equ AT_REMOVEDIR, 0x200

.macro AT_PATH reg, sym
    lea \sym(%rip), \reg
.endm

#ifdef CHILD
child_script:
    mov $AT_FDCWD, %edi
    AT_PATH %rsi, dir
    mov $0755, %edx
    SYS SYS_mkdirat
    EXPECT 11, -ENOSYS
    /* A closed descriptor is the ring's own EBADF, never a crossing. */
    mov $2, %edi
    SYS SYS_close
    EXPECT 12, 0
    mov $2, %edi
    xor %esi, %esi
    SYS SYS_ftruncate
    EXPECT 13, -9
    mov $2, %edi
    SYS SYS_fsync
    EXPECT 14, -9
    mov $2, %edi
    SYS SYS_fdatasync
    EXPECT 15, -9
    mov $2, %edi
    mov $2, %esi
    SYS SYS_flock
    EXPECT 16, -9
    mov $2, %edi
    xor %esi, %esi
    xor %edx, %edx
    xor %r10d, %r10d
    SYS SYS_fadvise64
    EXPECT 17, -9
    mov $2, %edi
    xor %esi, %esi
    xor %edx, %edx
    mov $8, %r10d
    xor %r8d, %r8d
    SYS SYS_fallocate
    EXPECT 18, -9
    mov $2, %edi
    PATH %rsi, scratch
    mov $512, %edx
    SYS SYS_getdents64
    EXPECT 19, -9
    jmp child_done

parent_script:
    /* The child's mkdirat never reached the host: the name is still free. */
    mov $AT_FDCWD, %edi
    AT_PATH %rsi, dir
    mov $0755, %edx
    SYS SYS_mkdirat
    EXPECT 21, 0
    mov $AT_FDCWD, %edi
    AT_PATH %rsi, dir
    mov $AT_REMOVEDIR, %edx
    SYS SYS_unlinkat
    EXPECT 22, 0
    jmp pass
#else
root_script:
    mov $AT_FDCWD, %edi
    AT_PATH %rsi, dir
    mov $0755, %edx
    SYS SYS_mkdirat
    EXPECT 11, 0
    mov $AT_FDCWD, %edi
    AT_PATH %rsi, dir
    mov $0755, %edx
    SYS SYS_mkdirat
    EXPECT 12, -17
    mov $AT_FDCWD, %edi
    AT_PATH %rsi, file
    mov $O_RDWR_CREAT, %edx
    mov $0644, %r10d
    SYS SYS_openat
    EXPECT_OK 13
    mov %rax, %r12
    mov %r12, %rdi
    AT_PATH %rsi, data
    mov $4, %edx
    SYS SYS_write
    EXPECT 14, 4
    mov %r12, %rdi
    mov $2, %esi
    SYS SYS_ftruncate
    EXPECT 15, 0
    mov %r12, %rdi
    xor %esi, %esi
    mov $2, %edx
    SYS SYS_lseek
    EXPECT 16, 2
    mov %r12, %rdi
    xor %esi, %esi
    xor %edx, %edx
    mov $8, %r10d
    SYS SYS_fallocate
    EXPECT 17, 0
    mov %r12, %rdi
    xor %esi, %esi
    mov $2, %edx
    SYS SYS_lseek
    EXPECT 18, 8
    mov %r12, %rdi
    SYS SYS_fsync
    EXPECT 19, 0
    mov %r12, %rdi
    SYS SYS_fdatasync
    EXPECT 20, 0
    mov %r12, %rdi
    mov $2, %esi
    SYS SYS_flock
    EXPECT 21, 0
    mov %r12, %rdi
    xor %esi, %esi
    xor %edx, %edx
    xor %r10d, %r10d
    SYS SYS_fadvise64
    EXPECT 22, 0
    /* symlinkat(target, newdirfd, linkpath) */
    AT_PATH %rdi, link_target
    mov $AT_FDCWD, %esi
    AT_PATH %rdx, link
    SYS SYS_symlinkat
    EXPECT 23, 0
    mov $AT_FDCWD, %edi
    AT_PATH %rsi, link
    PATH %rdx, scratch
    mov $16, %r10d
    SYS SYS_readlinkat
    EXPECT 24, 1
    cmpb $'f', scratch(%rip)
    je 1f
    mov $25, %edi
    jmp fail
1:
    mov $AT_FDCWD, %edi
    AT_PATH %rsi, file
    mov $AT_FDCWD, %edx
    AT_PATH %r10, hard
    xor %r8d, %r8d
    SYS SYS_linkat
    EXPECT 26, 0
    mov $AT_FDCWD, %edi
    AT_PATH %rsi, hard
    mov $AT_FDCWD, %edx
    AT_PATH %r10, renamed
    SYS SYS_renameat
    EXPECT 27, 0
    mov $AT_FDCWD, %edi
    AT_PATH %rsi, dir
    mov $O_RDONLY_DIRECTORY, %edx
    xor %r10d, %r10d
    SYS SYS_openat
    EXPECT_OK 28
    mov %rax, %rdi
    PATH %rsi, scratch
    mov $512, %edx
    SYS SYS_getdents64
    EXPECT_OK 29
    test %rax, %rax
    jnz 2f
    mov $30, %edi
    jmp fail
2:
    mov $AT_FDCWD, %edi
    AT_PATH %rsi, file
    xor %edx, %edx
    SYS SYS_unlinkat
    EXPECT 31, 0
    mov $AT_FDCWD, %edi
    AT_PATH %rsi, link
    xor %edx, %edx
    SYS SYS_unlinkat
    EXPECT 32, 0
    mov $AT_FDCWD, %edi
    AT_PATH %rsi, renamed
    xor %edx, %edx
    SYS SYS_unlinkat
    EXPECT 33, 0
    mov $AT_FDCWD, %edi
    AT_PATH %rsi, dir
    mov $AT_REMOVEDIR, %edx
    SYS SYS_unlinkat
    EXPECT 34, 0
    mov $AT_FDCWD, %edi
    AT_PATH %rsi, dir
    xor %edx, %edx
    SYS SYS_unlinkat
    EXPECT 35, -2
    jmp pass
#endif

.section .rodata
dir: .asciz "b1dir"
file: .asciz "b1dir/f"
hard: .asciz "b1dir/h"
renamed: .asciz "b1dir/r"
link: .asciz "b1dir/l"
link_target: .asciz "f"
data: .ascii "abcd"
