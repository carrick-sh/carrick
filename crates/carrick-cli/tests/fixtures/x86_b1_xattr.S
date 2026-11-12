/* #2157 B1, xattr family: setxattr, lsetxattr, getxattr, lgetxattr,
 * listxattr, llistxattr, removexattr, lremovexattr. The script runs in the
 * root file system's writable layer (a bind mount has no user.* attributes
 * under carrick) on a native filesystem that has them.
 *
 *   (none)  the run root performs every call; each returns its native
 *           Linux result and the value or list it writes. Expected stdout
 *           "F\n", exit 7.
 *   CHILD   a forked child owns no host task: a path call is a counted ENOSYS
 *           in ring and leaves no host effect (the parent proves the file
 *           still carries no attribute); a closed descriptor is EBADF. */
#include "x86_b1_common.h"

.equ SYS_openat, 257
.equ SYS_unlinkat, 263
.equ SYS_dup2, 33
.equ SYS_setxattr, 188
.equ SYS_lsetxattr, 189
.equ SYS_fsetxattr, 190
.equ SYS_getxattr, 191
.equ SYS_lgetxattr, 192
.equ SYS_fgetxattr, 193
.equ SYS_listxattr, 194
.equ SYS_llistxattr, 195
.equ SYS_flistxattr, 196
.equ SYS_removexattr, 197
.equ SYS_lremovexattr, 198
.equ SYS_fremovexattr, 199
.equ O_RDWR_CREAT, 0x42
.equ ENODATA, 61
.equ LIST_LEN, 14 /* "user.k\0user.l\0" */

#ifdef CHILD
child_script:
    PATH %rdi, file
    PATH %rsi, name_k
    PATH %rdx, value_k
    mov $2, %r10d
    xor %r8d, %r8d
    SYS SYS_setxattr
    EXPECT 11, -ENOSYS
    PATH %rdi, file
    PATH %rsi, name_k
    PATH %rdx, scratch
    mov $16, %r10d
    SYS SYS_getxattr
    EXPECT 12, -ENOSYS
    PATH %rdi, file
    PATH %rsi, scratch
    mov $64, %edx
    SYS SYS_listxattr
    EXPECT 13, -ENOSYS
    PATH %rdi, file
    PATH %rsi, name_k
    SYS SYS_removexattr
    EXPECT 14, -ENOSYS
    jmp child_done

parent_script:
    /* The child's setxattr never reached the host: the file is absent. */
    PATH %rdi, file
    PATH %rsi, name_k
    PATH %rdx, scratch
    mov $16, %r10d
    SYS SYS_getxattr
    EXPECT 21, -2
    jmp pass
#else
root_script:
    MMAP_UNTOUCHED 40
    mov $AT_FDCWD, %edi
    PATH %rsi, file
    mov $O_RDWR_CREAT, %edx
    mov $0644, %r10d
    SYS SYS_openat
    EXPECT_OK 11
    /* set through the path and the no-follow path. */
    PATH %rdi, file
    PATH %rsi, name_k
    PATH %rdx, value_k
    mov $2, %r10d
    xor %r8d, %r8d
    SYS SYS_setxattr
    EXPECT 12, 0
    PATH %rdi, file
    PATH %rsi, name_l
    PATH %rdx, value_l
    mov $1, %r10d
    xor %r8d, %r8d
    SYS SYS_lsetxattr
    EXPECT 13, 0
    /* get returns the length and writes the value. */
    PATH %rdi, file
    PATH %rsi, name_k
    mov %r13, %rdx
    mov $16, %r10d
    SYS SYS_getxattr
    EXPECT 15, 2
    cmpw $0x3156, (%r13) /* "V1" */
    je 1f
    mov $16, %edi
    jmp fail
1:
    PATH %rdi, file
    PATH %rsi, name_l
    PATH %rdx, scratch
    mov $16, %r10d
    SYS SYS_lgetxattr
    EXPECT 17, 1
2:
    /* A buffer too small is ERANGE; a zero size asks for the length. */
    PATH %rdi, file
    PATH %rsi, name_k
    PATH %rdx, scratch
    mov $1, %r10d
    SYS SYS_getxattr
    EXPECT 20, -34
    PATH %rdi, file
    PATH %rsi, name_k
    xor %edx, %edx
    xor %r10d, %r10d
    SYS SYS_getxattr
    EXPECT 21, 2
    /* list: the three names, NUL separated. */
    PATH %rdi, file
    xor %esi, %esi
    xor %edx, %edx
    SYS SYS_listxattr
    EXPECT 22, LIST_LEN
    PATH %rdi, file
    lea 4096(%r13), %rsi
    mov $64, %edx
    SYS SYS_listxattr
    EXPECT 23, LIST_LEN
    PATH %rdi, file
    PATH %rsi, scratch
    mov $64, %edx
    SYS SYS_llistxattr
    EXPECT 24, LIST_LEN
    /* remove through each form; a second removal is ENODATA. */
    PATH %rdi, file
    PATH %rsi, name_k
    SYS SYS_removexattr
    EXPECT 26, 0
    PATH %rdi, file
    PATH %rsi, name_l
    SYS SYS_lremovexattr
    EXPECT 27, 0
    PATH %rdi, file
    PATH %rsi, name_k
    SYS SYS_removexattr
    EXPECT 29, -ENODATA
    PATH %rdi, file
    PATH %rsi, name_k
    PATH %rdx, scratch
    mov $16, %r10d
    SYS SYS_getxattr
    EXPECT 30, -ENODATA
    PATH %rdi, file
    xor %esi, %esi
    xor %edx, %edx
    SYS SYS_listxattr
    EXPECT 31, 0
    mov $AT_FDCWD, %edi
    PATH %rsi, file
    xor %edx, %edx
    SYS SYS_unlinkat
    EXPECT 32, 0
    jmp pass
#endif

.section .rodata
file: .asciz "b1xattr"
name_k: .asciz "user.k"
name_l: .asciz "user.l"
name_f: .asciz "user.f"
value_k: .ascii "V1"
value_l: .ascii "L"
value_f: .ascii "FF"
