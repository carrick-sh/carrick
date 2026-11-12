/* #2157 B1, files family: mkdirat, ftruncate, fallocate,
 * sync, symlinkat, readlinkat, linkat, renameat, renameat2, mknodat,
 * chdir, getcwd, unlinkat. The script runs in a scratch working
 * directory. Descriptor calls name standard output's host object (a pipe).
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
.equ SYS_readahead, 187
.equ SYS_sync_file_range, 277
.equ SYS_syncfs, 306
.equ SYS_sync, 162
.equ SYS_renameat2, 316
.equ SYS_mknodat, 259
.equ SYS_chdir, 80
.equ SYS_fchdir, 81
.equ SYS_getcwd, 79
.equ SYS_dup2, 33
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
    /* The parent's pages are copy-on-write after the fork: a result copied
     * into one is made writable by the ring first. */
    movb $1, scratch(%rip)
    PATH %rdi, scratch
    mov $256, %esi
    SYS SYS_getcwd
    EXPECT_OK 20
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
    MMAP_UNTOUCHED 59
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
    /* The descriptor calls below name the host object standard output is
     * bound to, as 1 and as the duplicate 5 (a rewritten operand). A file the
     * root opened lives in the ring's table; the ring's venue owns it. */
    mov $1, %edi
    mov $5, %esi
    SYS SYS_dup2
    EXPECT 17, 5
    mov $5, %edi
    xor %esi, %esi
    xor %edx, %edx
    mov $8, %r10d
    SYS SYS_fallocate
    EXPECT 18, -29
    mov $1, %edi
    xor %esi, %esi
    xor %edx, %edx
    mov $8, %r10d
    SYS SYS_fallocate
    EXPECT 19, -29
    SYS SYS_sync
    EXPECT 56, 0
    /* symlinkat(target, newdirfd, linkpath) */
    AT_PATH %rdi, link_target
    mov $AT_FDCWD, %esi
    AT_PATH %rdx, link
    SYS SYS_symlinkat
    EXPECT 23, 0
    mov $AT_FDCWD, %edi
    AT_PATH %rsi, link
    lea 4096(%r13), %rdx
    mov $16, %r10d
    SYS SYS_readlinkat
    EXPECT 24, 1
    cmpb $'f', 4096(%r13)
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
    AT_PATH %rsi, renamed
    mov $AT_FDCWD, %edx
    AT_PATH %r10, renamed2
    xor %r8d, %r8d
    SYS SYS_renameat2
    EXPECT 44, 0
    /* mknodat: a fifo needs no privilege. */
    mov $AT_FDCWD, %edi
    AT_PATH %rsi, node
    mov $010600, %edx
    xor %r10d, %r10d
    SYS SYS_mknodat
    EXPECT 45, 0
    mov $AT_FDCWD, %edi
    AT_PATH %rsi, node
    xor %edx, %edx
    SYS SYS_unlinkat
    EXPECT 46, 0
    /* The working directory follows chdir and fchdir. */
    AT_PATH %rdi, dir
    SYS SYS_chdir
    EXPECT 50, 0
    mov %r13, %rdi
    mov $256, %esi
    SYS SYS_getcwd
    cmp $7, %rax
    jge 3f
    mov $51, %edi
    jmp fail
3:
    cmpl $0x72696431, -5(%r13,%rax) /* "1dir" before the NUL */
    je 4f
    mov $52, %edi
    jmp fail
4:
    /* A result that straddles two never-touched pages: both are made
     * writable, as Linux faults each in as the copy reaches it. */
    lea 12285(%r13), %rdi
    mov $256, %esi
    SYS SYS_getcwd
    cmp $7, %rax
    jge 5f
    mov $60, %edi
    jmp fail
5:
    lea 12285(%r13), %rcx
    cmpl $0x72696431, -5(%rcx,%rax) /* "1dir" before the NUL */
    je 6f
    mov $61, %edi
    jmp fail
6:
    /* A relative open resolves against the new working directory. */
    mov $AT_FDCWD, %edi
    AT_PATH %rsi, member
    xor %edx, %edx
    xor %r10d, %r10d
    SYS SYS_openat
    EXPECT_OK 57
    mov %rax, %rdi
    SYS SYS_close
    EXPECT 58, 0
    AT_PATH %rdi, parent
    SYS SYS_chdir
    EXPECT 54, 0
    mov $AT_FDCWD, %edi
    AT_PATH %rsi, dir
    mov $O_RDONLY_DIRECTORY, %edx
    xor %r10d, %r10d
    SYS SYS_openat
    EXPECT_OK 28
    mov %rax, %r14
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
    /* %r14 is a directory the ring's staged openat holds; its number names
     * nothing in the root's host task. An absolute path ignores it. */
    mov %r14, %rdi
    AT_PATH %rsi, root_path
    mov $0755, %edx
    SYS SYS_mkdirat
    EXPECT 62, -17
#ifdef RING_DIRFD
    /* A relative path through it needs that directory as the base, which the
     * shared path staging does not serve yet: the ring's counted ENOSYS,
     * never the path resolved against another descriptor (this fixture runs
     * under carrick only; native Linux creates the directory). */
    mov %r14, %rdi
    AT_PATH %rsi, member
    mov $0755, %edx
    SYS SYS_mkdirat
    EXPECT 63, -ENOSYS
    mov %r14, %rdi
    AT_PATH %rsi, member
    xor %edx, %edx
    SYS SYS_unlinkat
    EXPECT 64, -ENOSYS
    mov %r14, %rdi
    AT_PATH %rsi, member
    lea 4096(%r13), %rdx
    mov $16, %r10d
    SYS SYS_readlinkat
    EXPECT 65, -ENOSYS
#endif
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
    AT_PATH %rsi, renamed2
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
renamed2: .asciz "b1dir/s"
node: .asciz "b1dir/n"
missing: .asciz "b1missing"
parent: .asciz ".."
member: .asciz "f"
root_path: .asciz "/"
link: .asciz "b1dir/l"
link_target: .asciz "f"
data: .ascii "abcd"
