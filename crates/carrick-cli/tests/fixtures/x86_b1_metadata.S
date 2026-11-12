/* #2157 B1, metadata family: fstat, newfstatat, statx, fchmod, fchmodat,
 * fchmodat2, fchownat, fchown, utimensat, truncate, statfs, fstatfs,
 * faccessat2. The script runs in a scratch working directory.
 *
 *   (none)  the run root performs every call; each returns its native
 *           Linux result and the values it writes to the stat buffers match.
 *           Expected stdout "F\n", exit 7.
 *   CHILD   a forked child owns no host task: a path call is a counted ENOSYS
 *           in ring and leaves no host effect (the parent proves the file
 *           still has its size); a closed descriptor is EBADF. */
#include "x86_b1_common.h"

.equ SYS_openat, 257
.equ SYS_fstat, 5
.equ SYS_newfstatat, 262
.equ SYS_statx, 332
.equ SYS_fchmod, 91
.equ SYS_fchmodat, 268
.equ SYS_fchmodat2, 452
.equ SYS_fchownat, 260
.equ SYS_fchown, 93
.equ SYS_utimensat, 280
.equ SYS_truncate, 76
.equ SYS_statfs, 137
.equ SYS_fstatfs, 138
.equ SYS_faccessat2, 439
.equ SYS_unlinkat, 263
.equ O_RDWR_CREAT, 0x42
.equ ST_MODE, 24
.equ ST_SIZE, 48
.equ ST_MTIME, 88
.equ STX_MODE, 28
.equ STX_SIZE, 40

.macro STAT_SIZE step, expect
    mov %r12, %rdi
    PATH %rsi, stat
    SYS SYS_fstat
    EXPECT \step, 0
    cmpq $\expect, stat+ST_SIZE(%rip)
    je 8f
    mov $\step+1, %edi
    jmp fail
8:
.endm

.macro STAT_PERM step, expect
    mov %r12, %rdi
    PATH %rsi, stat
    SYS SYS_fstat
    EXPECT \step, 0
    mov stat+ST_MODE(%rip), %eax
    and $07777, %eax
    cmp $\expect, %eax
    je 8f
    mov $\step+1, %edi
    jmp fail
8:
.endm

#ifdef CHILD
child_script:
    mov $AT_FDCWD, %edi
    PATH %rsi, file
    mov $0600, %edx
    SYS SYS_fchmodat
    EXPECT 11, -ENOSYS
    PATH %rdi, file
    mov $1, %esi
    SYS SYS_truncate
    EXPECT 12, -ENOSYS
    mov $AT_FDCWD, %edi
    PATH %rsi, file
    PATH %rdx, stat
    xor %r10d, %r10d
    SYS SYS_newfstatat
    EXPECT 13, -ENOSYS
    /* A closed descriptor is the ring's own EBADF, never a crossing. */
    mov $2, %edi
    SYS SYS_close
    EXPECT 14, 0
    mov $2, %edi
    PATH %rsi, stat
    SYS SYS_fstat
    EXPECT 15, -9
    mov $2, %edi
    PATH %rsi, stat
    SYS SYS_fstatfs
    EXPECT 16, -9
    mov $2, %edi
    mov $0600, %esi
    SYS SYS_fchmod
    EXPECT 17, -9
    mov $2, %edi
    mov $-1, %esi
    mov $-1, %edx
    SYS SYS_fchown
    EXPECT 18, -9
    jmp child_done

parent_script:
    /* The child's truncate and chmod never reached the host: still absent. */
    mov $AT_FDCWD, %edi
    PATH %rsi, file
    PATH %rdx, stat
    xor %r10d, %r10d
    SYS SYS_newfstatat
    EXPECT 21, -2
    jmp pass
#else
root_script:
    mov $AT_FDCWD, %edi
    PATH %rsi, file
    mov $O_RDWR_CREAT, %edx
    mov $0644, %r10d
    SYS SYS_openat
    EXPECT_OK 11
    mov %rax, %r12
    mov %r12, %rdi
    PATH %rsi, data
    mov $4, %edx
    SYS SYS_write
    EXPECT 12, 4
    /* fstat: size and file type. */
    STAT_SIZE 13, 4
    mov stat+ST_MODE(%rip), %eax
    and $0170000, %eax
    cmp $0100000, %eax
    je 1f
    mov $15, %edi
    jmp fail
1:
    /* newfstatat by path agrees. */
    mov $AT_FDCWD, %edi
    PATH %rsi, file
    PATH %rdx, stat
    xor %r10d, %r10d
    SYS SYS_newfstatat
    EXPECT 16, 0
    cmpq $4, stat+ST_SIZE(%rip)
    je 2f
    mov $17, %edi
    jmp fail
2:
    /* statx: STATX_BASIC_STATS. */
    mov $AT_FDCWD, %edi
    PATH %rsi, file
    xor %edx, %edx
    mov $0x7ff, %r10d
    PATH %r8, statx_buf
    SYS SYS_statx
    EXPECT 18, 0
    cmpq $4, statx_buf+STX_SIZE(%rip)
    je 3f
    mov $19, %edi
    jmp fail
3:
    /* Permission bits follow fchmod, fchmodat and fchmodat2. */
    mov %r12, %rdi
    mov $0600, %esi
    SYS SYS_fchmod
    EXPECT 20, 0
    STAT_PERM 21, 0600
    mov $AT_FDCWD, %edi
    PATH %rsi, file
    mov $0640, %edx
    SYS SYS_fchmodat
    EXPECT 23, 0
    STAT_PERM 24, 0640
    mov $AT_FDCWD, %edi
    PATH %rsi, file
    mov $0604, %edx
    xor %r10d, %r10d
    SYS SYS_fchmodat2
    EXPECT 26, 0
    STAT_PERM 27, 0604
    /* Ownership unchanged (-1, -1) through both forms. */
    mov $AT_FDCWD, %edi
    PATH %rsi, file
    mov $-1, %edx
    mov $-1, %r10d
    xor %r8d, %r8d
    SYS SYS_fchownat
    EXPECT 29, 0
    mov %r12, %rdi
    mov $-1, %esi
    mov $-1, %edx
    SYS SYS_fchown
    EXPECT 30, 0
    /* Timestamps follow utimensat. */
    mov $AT_FDCWD, %edi
    PATH %rsi, file
    PATH %rdx, times
    xor %r10d, %r10d
    SYS SYS_utimensat
    EXPECT 31, 0
    mov %r12, %rdi
    PATH %rsi, stat
    SYS SYS_fstat
    EXPECT 32, 0
    cmpq $2000, stat+ST_MTIME(%rip)
    je 4f
    mov $33, %edi
    jmp fail
4:
    /* truncate by path shrinks the file. */
    PATH %rdi, file
    mov $1, %esi
    SYS SYS_truncate
    EXPECT 34, 0
    STAT_SIZE 35, 1
    /* faccessat2: present, absent. */
    mov $AT_FDCWD, %edi
    PATH %rsi, file
    mov $4, %edx
    xor %r10d, %r10d
    SYS SYS_faccessat2
    EXPECT 37, 0
    mov $AT_FDCWD, %edi
    PATH %rsi, missing
    mov $4, %edx
    xor %r10d, %r10d
    SYS SYS_faccessat2
    EXPECT 38, -2
    /* statfs and fstatfs: f_type is nonzero for any mounted filesystem. */
    PATH %rdi, dot
    PATH %rsi, statfs_buf
    SYS SYS_statfs
    EXPECT 39, 0
    cmpq $0, statfs_buf(%rip)
    jne 5f
    mov $40, %edi
    jmp fail
5:
    mov %r12, %rdi
    PATH %rsi, statfs_buf
    SYS SYS_fstatfs
    EXPECT 41, 0
    /* Standard output is a pipe: the host object's fstat is the pipe's. */
    mov $1, %edi
    PATH %rsi, stat
    SYS SYS_fstat
    EXPECT 42, 0
    mov stat+ST_MODE(%rip), %eax
    and $0170000, %eax
    cmp $0010000, %eax
    je 6f
    mov $43, %edi
    jmp fail
6:
    /* A closed standard descriptor is EBADF, not a crossing. */
    mov $2, %edi
    SYS SYS_close
    EXPECT 44, 0
    mov $2, %edi
    PATH %rsi, stat
    SYS SYS_fstat
    EXPECT 45, -9
    mov $AT_FDCWD, %edi
    PATH %rsi, file
    xor %edx, %edx
    SYS SYS_unlinkat
    EXPECT 46, 0
    jmp pass
#endif

.section .rodata
file: .asciz "b1meta"
missing: .asciz "b1missing"
dot: .asciz "."
data: .ascii "abcd"
.balign 8
times: .quad 1000, 0, 2000, 0

.section .bss
.balign 16
stat: .skip 144
statx_buf: .skip 256
statfs_buf: .skip 120
