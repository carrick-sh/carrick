/* #2620 part A: parent forks; child execs a successor binary that runs 20
 * rounds of poll(fd, POLLIN, 50ms) on a never-ready host UDP socket (or, with
 * PEER_PORT, 20 rounds where a delayed loopback UDP responder makes the socket
 * ready after the initial non-blocking probe parks on host readiness), then
 * calls _exit(7). The parent's wait4(-1) must reap status 7. */

#define SYS_POLL 7
#define SYS_SOCKET 41
#define SYS_SENDTO 44
#define SYS_RECVFROM 45
#define SYS_BIND 49
#define SYS_FORK 57
#define SYS_EXECVE 59
#define SYS_EXIT 60
#define SYS_WAIT4 61
#define SYS_EXIT_GROUP 231

.global _start
.text
_start:
#ifdef SUCCESSOR
    /* socket(AF_INET = 2, SOCK_DGRAM = 2, 0) */
    mov $2, %edi
    mov $2, %esi
    xor %edx, %edx
    mov $SYS_SOCKET, %eax
    syscall
    test %rax, %rax
    js fail_sock
    mov %rax, %r12

    /* bind(s, 127.0.0.1:0, 16) */
    mov %r12, %rdi
    lea bind_addr(%rip), %rsi
    mov $16, %edx
    mov $SYS_BIND, %eax
    syscall
    test %rax, %rax
    jnz fail_bind

    mov $20, %r13d

poll_loop:
#ifdef PEER_PORT
    /* Trigger the host responder, which sleeps 10 ms before replying so the
     * child's first poll probe sees EAGAIN and parks on host readiness. */
    mov %r12, %rdi
    lea query_byte(%rip), %rsi
    mov $1, %edx
    xor %r10d, %r10d
    lea peer_addr(%rip), %r8
    mov $16, %r9d
    mov $SYS_SENDTO, %eax
    syscall
    cmp $1, %rax
    jne fail_send

    mov %r12d, pfd_fd(%rip)
    movw $1, pfd_events(%rip)
    movw $0x7fff, pfd_revents(%rip)
    lea pfd(%rip), %rdi
    mov $1, %esi
    mov $500, %edx
    mov $SYS_POLL, %eax
    syscall
    cmp $1, %rax
    jne fail_poll
    movzwl pfd_revents(%rip), %eax
    test $1, %eax
    jz fail_revents

    movb $0, rx_byte(%rip)
    mov %r12, %rdi
    lea rx_byte(%rip), %rsi
    mov $1, %edx
    xor %r10d, %r10d
    xor %r8d, %r8d
    xor %r9d, %r9d
    mov $SYS_RECVFROM, %eax
    syscall
    cmp $1, %rax
    jne fail_recv
    cmpb $'a', rx_byte(%rip)
    jne fail_recv
#else
    mov %r12d, pfd_fd(%rip)
    movw $1, pfd_events(%rip)
    movw $0x7fff, pfd_revents(%rip)
    lea pfd(%rip), %rdi
    mov $1, %esi
    mov $50, %edx
    mov $SYS_POLL, %eax
    syscall
    test %rax, %rax
    jnz fail_poll
    cmpw $0, pfd_revents(%rip)
    jne fail_revents
#endif

    dec %r13d
    jnz poll_loop

    /* _exit(7) */
    mov $7, %edi
    mov $SYS_EXIT, %eax
    syscall
    ud2

fail_sock:
    mov $81, %edi
    jmp raw_exit
fail_bind:
    mov $82, %edi
    jmp raw_exit
fail_send:
    mov $83, %edi
    jmp raw_exit
fail_poll:
    mov $84, %edi
    jmp raw_exit
fail_revents:
    mov $85, %edi
    jmp raw_exit
fail_recv:
    mov $86, %edi
raw_exit:
    mov $SYS_EXIT, %eax
    syscall
    ud2

.section .rodata
bind_addr:
    .short 2
    .short 0
    .byte 127, 0, 0, 1
    .zero 8
#ifdef PEER_PORT
peer_addr:
    .short 2
    .short PEER_PORT
    .byte 127, 0, 0, 1
    .zero 8
query_byte:
    .byte 'q'
#endif

.section .bss
.align 4
pfd:
pfd_fd:      .long 0
pfd_events:  .short 0
pfd_revents: .short 0
rx_byte:     .byte 0

#else
    /* Parent forks; child execs SUCCESSOR_PATH; parent wait4(-1)s. */
    mov $SYS_FORK, %eax
    syscall
    test %eax, %eax
    js fail_fork
    jz do_exec

    mov %eax, %r12d
    mov $-1, %rdi
    lea wait_status(%rip), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $SYS_WAIT4, %eax
    syscall
    cmp %r12, %rax
    jne fail_wait
    movl wait_status(%rip), %eax
    test $0x7f, %eax
    jnz fail_status
    shr $8, %eax
    movzbl %al, %edi
    mov $SYS_EXIT_GROUP, %eax
    syscall
    ud2

do_exec:
    lea successor_path(%rip), %rdi
    lea argv_vec(%rip), %rsi
    lea envp_vec(%rip), %rdx
    mov $SYS_EXECVE, %eax
    syscall
    mov $92, %edi
    mov $SYS_EXIT, %eax
    syscall
    ud2

fail_fork:
    mov $91, %edi
    jmp group_exit
fail_wait:
    mov $93, %edi
    jmp group_exit
fail_status:
    mov $94, %edi
group_exit:
    mov $SYS_EXIT_GROUP, %eax
    syscall
    ud2

.section .rodata
successor_path:
    .asciz SUCCESSOR_PATH
.align 8
argv_vec:
    .quad successor_path
    .quad 0
envp_vec:
    .quad 0

.section .bss
.align 4
wait_status:
    .long 0
#endif
