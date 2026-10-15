# Deliberately park forever in poll with no descriptors and no deadline.
# The host test captures the live carrier, then kills its scoped process group.
.global _start
.text
_start:
    mov $7, %eax          # SYS_poll
    xor %edi, %edi        # fds = NULL
    xor %esi, %esi        # nfds = 0
    mov $-1, %edx        # timeout = infinite
    syscall
    ud2
