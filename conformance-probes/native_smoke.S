.text
.global _start
.type _start,%function
_start:
    mov x0, #1
    adrp x1, msg
    add x1, x1, :lo12:msg
    mov x2, #msg_len
    mov x8, #64
    svc #0
    mov x3, #msg_len
    cmp x0, x3
    b.ne fail
    mov x0, #0
    b exit
fail:
    mov x0, #1
exit:
    mov x8, #93
    svc #0
1:
    b 1b

.section .rodata
msg:
    .ascii "native-smoke: ok\n"
.set msg_len, . - msg
