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
 *  P19 flock(d, LOCK_EX|LOCK_NB)                      0
 *
 * -DLIFECYCLE: the record lock's owner is the process, across its threads
 * and its exits (fcntl(2)). Parent P1 open (fd a), P2 pipe2(ready), (go),
 * fork. Child:
 *   L1 openat(LOCK_PATH, O_RDWR)                      fd c
 *   L2 a CLONE_THREAD worker takes F_SETLK F_WRLCK on c, then raw-exits
 *      (a non-last thread's exit(2)); the child joins it: the worker's
 *      status
 *   L3 write(ready)    L4 read(go)
 *   L5 openat(LOCK_PATH, O_RDWR)                      fd e
 *   L6 dup2(e, c): the replaced c was a descriptor of the file
 *   L7 write(ready)    L8 read(go)
 *   L9 F_SETLK F_WRLCK on e                           0
 *  L10 write(ready), then a worker that keeps calling getpid, and
 *      exit_group(0)
 * Parent after fork:
 *   M1 read(ready)
 *   M2 F_GETLK l_type                                 1: the lock outlived
 *      the worker that took it
 *   M3 l_pid == the child                             1
 *   M4 write(go)       M5 read(ready)
 *   M6 F_GETLK l_type                                 2: dup2 released it
 *   M7 write(go)       M7b read(ready)
 *  M7c F_SETLKW F_WRLCK                               0: parked until the
 *      child's exit_group (a worker still running) released L9
 *   M8 wait4(child): exit code                        0
 *   M9 F_GETLK l_type                                 2: the parent's own
 *      lock never conflicts with itself
 *
 * -DEXEC (with SUCCESSOR_PATH, this fixture's own path): exec's
 * close-on-exec sweep and advisory locks (fcntl(2), flock(2), execve(2)).
 * Parent E1 open (fd a), E2 pipe2(ready), (go), fork. Child:
 *   X1 openat(LOCK_PATH, O_RDWR)                      fd c, kept by exec
 *   X2 F_SETLK F_WRLCK [0, 10) on c                   0
 *   X3 openat(LOCK_PATH, O_RDWR|O_CLOEXEC)            fd e, another
 *      descriptor of the file, closed by exec
 *   X4 openat (fd f), flock(f, LOCK_EX)               0, kept by exec
 *   X5 openat (fd g), F_OFD_SETLK F_WRLCK [100, 110)  0, kept by exec
 *   X6 dup2(ready[1], 20), dup2(go[0], 21)            0
 *   then write(ready), read(go), execve(SUCCESSOR_PATH, {path, "s"}): the
 *   successor (argc 2) writes fd 20, reads fd 21 and exits 0.
 * Parent after fork:
 *   E3 read(ready)
 *   E4 F_GETLK F_WRLCK [0, 10) l_type                 1: the child's lock
 *   E5 l_pid == the child                             1
 *   E6 write(go)       E7 read(ready): the successor runs
 *   E8 F_GETLK F_WRLCK [0, 10) l_type                 2: exec closed e, a
 *      descriptor of the file, so the process's record lock ended
 *   E9 openat (fd h), flock(h, LOCK_EX|LOCK_NB)       EWOULDBLOCK: f's
 *      description, kept across exec, still holds its flock
 *  E10 F_OFD_GETLK F_WRLCK [100, 110) l_type          1: g's OFD lock too
 *  E11 write(go)       E12 wait4(child): exit code    0
 *  E13 flock(h, LOCK_EX|LOCK_NB)                      0: the successor's
 *      exit closed f
 *  E14 F_OFD_GETLK F_WRLCK [100, 110) l_type          2 */
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

/* fcntl(%r12, cmd, &flk) with flk = {type, SEEK_SET, start, len}. */
.macro range_lock cmd, type, start, len
    movw $\type, flk(%rip)
    movw $0, flk+2(%rip)
    movq $\start, flk+8(%rip)
    movq $\len, flk+16(%rip)
    movl $0, flk+24(%rip)
    mov %r12, %rdi
    mov $\cmd, %esi
    lea flk(%rip), %rdx
    mov $72, %eax
    syscall
.endm

/* The l_type a range query reported, or 0x80 | errno. */
.macro range_type cmd, start, len
    range_lock \cmd, 1, \start, \len
    test %rax, %rax
    js 1f
    movzwl flk(%rip), %eax
1:  call value_byte
.endm

/* The l_type a F_GETLK reported, or 0x80 | errno. */
.macro getlk_type
    record_lock 5, 1
    test %rax, %rax
    js 1f
    movzwl flk(%rip), %eax
1:  call value_byte
.endm

#if !defined(LIFECYCLE) && !defined(POOL) && !defined(EXEC)
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

#endif /* !LIFECYCLE && !POOL && !EXEC */

#ifdef POOL
#define WAITERS 6
_start:
    lea out(%rip), %r15

    mov $-100, %edi                 /* Q1: openat(lock, O_RDWR|O_CREAT, 0640) */
    lea lock(%rip), %rsi
    mov $0x42, %edx
    mov $0640, %r10d
    mov $257, %eax
    syscall
    mov %rax, %r12
    record_status

    record_lock 6, 1                /* Q2: F_SETLK F_WRLCK */
    record_status

    lea ready(%rip), %rdi           /* Q3: pipe2(ready), pipe2(go) */
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

    mov $WAITERS, %r13d             /* fork the waiters */
1:  mov $57, %eax
    syscall
    test %rax, %rax
    js fork_failed
    jz pool_waiter
    dec %r13d
    jnz 1b

    call wait_50ms                  /* Q4: let every waiter park */
#ifdef PIPE
    mov $WAITERS, %r14d             /* the control: one byte per reader */
6:  movl go+4(%rip), %edi
    call write_byte
    call wait_50ms
    dec %r14d
    jnz 6b
#endif
    record_lock 6, 2                /* Q5: F_SETLK F_UNLCK */
    record_status

    xor %r13d, %r13d                /* Q6: one byte per waiter */
    mov $WAITERS, %r14d
2:  movl ready(%rip), %edi
    call read_byte
    cmp $1, %rax
    jne 3f
    inc %r13d
    dec %r14d
    jnz 2b
3:  mov %r13d, %eax
    call value_byte

    xor %ebx, %ebx                  /* Q7: wait4 every waiter */
    mov $WAITERS, %r14d
4:  mov $-1, %rdi
    lea status(%rip), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $61, %eax
    syscall
    test %rax, %rax
    js fork_failed
    or status(%rip), %ebx
    dec %r14d
    jnz 4b
    mov %ebx, %eax
    shr $8, %eax
    or %ebx, %eax
    and $0xff, %eax
    call value_byte

    call report
    xor %edi, %edi
    jmp exit

pool_waiter:
#ifdef PIPE
    movl go(%rip), %edi             /* read(go) parks until a byte comes */
    call read_byte
    cmp $1, %rax
    jne 5f
    xor %eax, %eax
#else
    record_lock 7, 1                /* F_SETLKW F_WRLCK */
#endif
    test %rax, %rax
    jnz 5f
    movl ready+4(%rip), %edi
    call write_byte
    xor %edi, %edi
    jmp exit
5:  neg %eax
    mov %eax, %edi
    jmp exit

/* futex(FUTEX_WAIT) on a private word for 50 ms */
wait_50ms:
    lea pause_word(%rip), %rdi
    xor %esi, %esi
    xor %edx, %edx
    lea pause_time(%rip), %r10
    xor %r8d, %r8d
    xor %r9d, %r9d
    mov $202, %eax
    syscall
    ret
#endif /* POOL */

#ifdef LIFECYCLE
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

    lea ready(%rip), %rdi           /* P2: pipe2(ready), pipe2(go) */
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
    jz lchild
    mov %rax, %rbx

    movl ready(%rip), %edi          /* M1: read(ready) */
    call read_byte
    record_status

    getlk_type                      /* M2: F_GETLK l_type */

    movslq flk+24(%rip), %rax       /* M3: l_pid == the child */
    cmp %rax, %rbx
    sete %al
    movzbl %al, %eax
    call value_byte

    movl go+4(%rip), %edi           /* M4: write(go) */
    call write_byte
    record_status

    movl ready(%rip), %edi          /* M5: read(ready) */
    call read_byte
    record_status

    getlk_type                      /* M6: F_GETLK l_type */

    movl go+4(%rip), %edi           /* M7: write(go) */
    call write_byte
    record_status

    movl ready(%rip), %edi          /* M7b: read(ready): L9 holds the lock */
    call read_byte
    record_status

    record_lock 7, 1                /* M7c: F_SETLKW parks until the child's */
    record_status                   /* exit_group releases L9 */

    mov %rbx, %rdi                  /* M8: wait4(child, &status, 0, NULL) */
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

    getlk_type                      /* M9: F_GETLK l_type */

    call report
    xor %edi, %edi
    jmp exit

lchild:
    call open_lock                  /* L1: fd c */
    mov %rax, %r12
    record_status

    movl $1, tstatus(%rip)          /* L2: worker F_SETLK, raw exit */
    lea lock_worker(%rip), %rbx
    call spawn
    lea tid(%rip), %rdi
    call join
    movl tstatus(%rip), %eax
    call value_byte

    movl ready+4(%rip), %edi        /* L3: write(ready) */
    call write_byte
    record_status

    movl go(%rip), %edi             /* L4: read(go) */
    call read_byte
    record_status

    call open_lock                  /* L5: fd e */
    mov %rax, %r13
    record_status

    mov %r13, %rdi                  /* L6: dup2(e, c) */
    mov %r12, %rsi
    mov $33, %eax
    syscall
    record_status
    mov %r13, %r12

    movl ready+4(%rip), %edi        /* L7: write(ready) */
    call write_byte
    record_status

    movl go(%rip), %edi             /* L8: read(go) */
    call read_byte
    record_status

    record_lock 6, 1                /* L9: F_SETLK F_WRLCK on e */
    record_status

    movl ready+4(%rip), %edi        /* L10: write(ready) */
    call write_byte
    record_status

    call report                     /* a running worker, then exit_group */
    lea spin_worker(%rip), %rbx
    call spawn
    xor %edi, %edi
    jmp exit

/* clone(CLONE_VM|FS|FILES|SIGHAND|THREAD|SYSVSEM|PARENT_SETTID|
 * CHILD_CLEARTID) onto `stack`, running %rbx; tid in `tid`. */
spawn:
    mov $0x00350f00, %edi
    lea stack_top(%rip), %rsi
    lea tid(%rip), %rdx
    mov %rdx, %r10
    xor %r8d, %r8d
    mov $56, %eax
    syscall
    test %rax, %rax
    jz 1f
    ret
1:  jmp *%rbx

/* Wait until the CLEARTID word at %rdi is zero, as pthread_join does. */
join:
    mov (%rdi), %edx
    test %edx, %edx
    jz 1f
    xor %esi, %esi
    xor %r10d, %r10d
    mov $202, %eax
    syscall
    jmp join
1:  ret

lock_worker:
    record_lock 6, 1
    test %rax, %rax
    js 1f
    xor %eax, %eax
1:  neg %eax
    movl %eax, tstatus(%rip)
    xor %edi, %edi                  /* exit(2): this thread only */
    mov $60, %eax
    syscall
    ud2

spin_worker:
    mov $39, %eax
    syscall
    jmp spin_worker
#endif /* LIFECYCLE */

#ifdef EXEC
_start:
    cmpq $2, (%rsp)                 /* argc 2: the exec successor */
    je successor
    lea out(%rip), %r15

    mov $-100, %edi                 /* E1: openat(lock, O_RDWR|O_CREAT, 0640) */
    lea lock(%rip), %rsi
    mov $0x42, %edx
    mov $0640, %r10d
    mov $257, %eax
    syscall
    mov %rax, %r12
    record_status

    lea ready(%rip), %rdi           /* E2: pipe2(ready), pipe2(go) */
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
    jz echild
    mov %rax, %rbx

    movl ready(%rip), %edi          /* E3: read(ready) */
    call read_byte
    record_status

    range_type 5, 0, 10             /* E4: F_GETLK [0, 10) l_type */

    movslq flk+24(%rip), %rax       /* E5: l_pid == the child */
    cmp %rax, %rbx
    sete %al
    movzbl %al, %eax
    call value_byte

    movl go+4(%rip), %edi           /* E6: write(go) */
    call write_byte
    record_status

    movl ready(%rip), %edi          /* E7: read(ready), from the successor */
    call read_byte
    record_status

    range_type 5, 0, 10             /* E8: F_GETLK [0, 10) l_type */

    call open_lock                  /* E9: fd h, flock(h, LOCK_EX|LOCK_NB) */
    mov %rax, %r14
    mov %r14, %rdi
    mov $6, %esi
    mov $73, %eax
    syscall
    record_status

    range_type 36, 100, 10          /* E10: F_OFD_GETLK [100, 110) l_type */

    movl go+4(%rip), %edi           /* E11: write(go) */
    call write_byte
    record_status

    mov %rbx, %rdi                  /* E12: wait4(child, &status, 0, NULL) */
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

    mov %r14, %rdi                  /* E13: flock(h, LOCK_EX|LOCK_NB) */
    mov $6, %esi
    mov $73, %eax
    syscall
    record_status

    range_type 36, 100, 10          /* E14: F_OFD_GETLK [100, 110) l_type */

    call report
    xor %edi, %edi
    jmp exit

echild:
    call open_lock                  /* X1: fd c */
    mov %rax, %r12
    record_status

    range_lock 6, 1, 0, 10          /* X2: F_SETLK F_WRLCK [0, 10) */
    record_status

    mov $-100, %edi                 /* X3: openat(lock, O_RDWR|O_CLOEXEC) */
    lea lock(%rip), %rsi
    mov $0x80002, %edx
    xor %r10d, %r10d
    mov $257, %eax
    syscall
    record_status

    call open_lock                  /* X4: fd f, flock(f, LOCK_EX) */
    mov %rax, %rdi
    mov $2, %esi
    mov $73, %eax
    syscall
    record_status

    call open_lock                  /* X5: fd g, F_OFD_SETLK [100, 110) */
    mov %rax, %r12
    range_lock 37, 1, 100, 10
    record_status

    movl ready+4(%rip), %edi        /* X6: dup2(ready[1], 20), (go[0], 21) */
    mov $20, %esi
    mov $33, %eax
    syscall
    test %rax, %rax
    js 1f
    movl go(%rip), %edi
    mov $21, %esi
    mov $33, %eax
    syscall
1:  record_status

    call report
    mov $20, %edi                   /* the parent probes, then lets go */
    call write_byte
    mov $21, %edi
    call read_byte

    lea successor_path(%rip), %rdi  /* execve(SUCCESSOR_PATH, {path, "s"}) */
    lea successor_argv(%rip), %rsi
    lea successor_envp(%rip), %rdx
    mov $59, %eax
    syscall
    neg %eax                        /* exec returned: its errno is the exit */
    mov %eax, %edi
    jmp exit

successor:
    mov $20, %edi                   /* write(20): exec is done */
    call write_byte
    mov $21, %edi                   /* read(21): the parent has probed */
    call read_byte
    xor %edi, %edi
    jmp exit

.section .rodata
successor_path: .asciz SUCCESSOR_PATH
successor_arg: .asciz "s"
.balign 8
successor_argv: .quad successor_path, successor_arg, 0
successor_envp: .quad 0
.text
#endif /* EXEC */

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
tid: .skip 8
tstatus: .skip 8
.balign 16
stack: .skip 4096
stack_top:
.section .note.GNU-stack,"",@progbits
