# Native x86 Linux oracle for POSIX message queue round trip with O_NONBLOCK EAGAIN.
# Expected stdout: Q\n; expected exit: 7.
.global _start
.text
_start:
    # 1. mq_open("carrick_test_mq", O_RDWR | O_CREAT | O_NONBLOCK, 0666, NULL)
    # O_RDWR = 2, O_CREAT = 64, O_NONBLOCK = 2048 -> 2114
    # mode = 0666 = 438
    lea mq_name(%rip), %rdi     # name = "carrick_test_mq"
    mov $2114, %rsi             # oflag
    mov $438, %rdx              # mode
    xor %r10, %r10              # attr = NULL
    mov $240, %rax              # SYS_mq_open
    syscall
    test %rax, %rax
    js fail_mq_open
    mov %rax, %r12              # r12 = mqd

    # 2. mq_timedreceive on empty queue -> must return -EAGAIN (-11)
    mov %r12, %rdi              # mqdes
    lea rx_buf(%rip), %rsi      # msg_ptr
    mov $8192, %rdx             # msg_len
    lea rx_prio(%rip), %r10     # msg_prio
    xor %r8, %r8                # abs_timeout = NULL
    mov $243, %rax              # SYS_mq_timedreceive
    syscall
    cmp $-11, %rax              # -EAGAIN = -11
    jne fail_empty_receive

    # 3. mq_timedsend(mqd, "MQOK", 4, 10, NULL)
    mov %r12, %rdi              # mqdes
    lea msg_text(%rip), %rsi    # msg_ptr
    mov $4, %rdx                # msg_len = 4
    mov $10, %r10               # msg_prio = 10
    xor %r8, %r8                # abs_timeout = NULL
    mov $242, %rax              # SYS_mq_timedsend
    syscall
    test %rax, %rax
    jnz fail_mq_send

    # 4. mq_timedreceive -> must return 4, text "MQOK", prio 10
    mov %r12, %rdi
    lea rx_buf(%rip), %rsi
    mov $8192, %rdx
    lea rx_prio(%rip), %r10
    xor %r8, %r8
    mov $243, %rax              # SYS_mq_timedreceive
    syscall
    cmp $4, %rax
    jne fail_mq_rcv_len
    cmpl $0x4b4f514d, rx_buf(%rip)   # 'M', 'Q', 'O', 'K'
    jne fail_mq_rcv_data
    cmpl $10, rx_prio(%rip)          # prio == 10
    jne fail_mq_rcv_prio

    # 5. mq_timedreceive again on now-empty queue -> must return -EAGAIN (-11)
    mov %r12, %rdi
    lea rx_buf(%rip), %rsi
    mov $8192, %rdx
    lea rx_prio(%rip), %r10
    xor %r8, %r8
    mov $243, %rax              # SYS_mq_timedreceive
    syscall
    cmp $-11, %rax
    jne fail_empty_receive2

    # 6. mq_unlink("carrick_test_mq")
    lea mq_name(%rip), %rdi
    mov $241, %rax              # SYS_mq_unlink
    syscall
    test %rax, %rax
    jnz fail_mq_unlink

    # Success: write "Q\n" and exit 7
    mov $1, %rax
    mov $1, %rdi
    lea ok(%rip), %rsi
    mov $2, %rdx
    syscall
    mov $7, %rdi
    jmp exit

fail_mq_open:
    mov $91, %rdi
    jmp exit
fail_empty_receive:
    mov $92, %rdi
    jmp exit
fail_mq_send:
    mov $93, %rdi
    jmp exit
fail_mq_rcv_len:
    mov $94, %rdi
    jmp exit
fail_mq_rcv_data:
    mov $95, %rdi
    jmp exit
fail_mq_rcv_prio:
    mov $96, %rdi
    jmp exit
fail_empty_receive2:
    mov $97, %rdi
    jmp exit
fail_mq_unlink:
    mov $98, %rdi
    jmp exit
fail_close:
    mov $99, %rdi
    jmp exit

exit:
    mov $231, %rax
    syscall
    ud2

.section .rodata
mq_name: .asciz "carrick_test_mq"
msg_text: .ascii "MQOK"
ok: .ascii "Q\n"

.section .bss
.align 8
rx_buf: .space 8200
rx_prio: .space 8
