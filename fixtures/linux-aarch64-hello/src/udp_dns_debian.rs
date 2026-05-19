// DNS query for deb.debian.org A record to 1.1.1.1:53.
// Same shape as udp_dns.rs but for the specific name apt update
// tries to resolve. If this prints OK, our UDP DNS pass-through is
// sufficient for apt's getaddrinfo. If FAIL, the response is bad.

#![no_main]
#![no_std]

use core::arch::global_asm;
use core::panic::PanicInfo;

global_asm!(
    r#"
    .global _start
    .type _start, %function
_start:
    sub sp, sp, #512

    mov x0, #2
    mov x1, #2
    mov x2, #0
    mov x8, #198
    svc #0
    mov w19, w0

    mov w0, #2
    strh w0, [sp]
    mov w0, #0x3500
    strh w0, [sp, #2]
    mov w0, #0x101
    movk w0, #0x101, lsl #16
    str w0, [sp, #4]
    str xzr, [sp, #8]

    adr x0, dns_query
    add x1, sp, #32
    mov x2, #33
    bl copy_bytes

    mov w0, w19
    add x1, sp, #32
    mov x2, #33
    mov x3, #0
    mov x4, sp
    mov x5, #16
    mov x8, #206
    svc #0
    cmp x0, #0
    b.lt fail

    mov w0, w19
    add x1, sp, #128
    mov x2, #256
    mov x3, #0
    mov x4, #0
    mov x5, #0
    mov x8, #207
    svc #0
    cmp x0, #0
    b.lt fail
    cmp x0, #12
    b.lt fail
    mov w20, w0          // total bytes received

    // verify txid 0xAA55
    ldrb w21, [sp, #128]
    cmp w21, #0xAA
    b.ne fail
    ldrb w21, [sp, #129]
    cmp w21, #0x55
    b.ne fail

    // verify rcode == 0
    ldrb w21, [sp, #131]
    and w21, w21, #0xF
    cmp w21, #0
    b.ne fail

    // verify ancount > 0 (response bytes 6-7 big-endian)
    ldrb w21, [sp, #134]
    ldrb w22, [sp, #135]
    orr w21, w22, w21, lsl #8
    cmp w21, #0
    b.eq fail

    // write decimal answer count then OK
    mov w0, #1
    adr x1, msg_ok
    mov x2, #3
    mov x8, #64
    svc #0
    mov x0, #0
    mov x8, #94
    svc #0

fail:
    mov w0, #1
    adr x1, msg_fail
    mov x2, #5
    mov x8, #64
    svc #0
    mov x0, #1
    mov x8, #94
    svc #0

copy_bytes:
    cbz x2, copy_done
1:  ldrb w3, [x0], #1
    strb w3, [x1], #1
    sub x2, x2, #1
    cbnz x2, 1b
copy_done:
    ret

msg_ok:   .ascii "OK\n"
msg_fail: .ascii "FAIL\n"

dns_query:
    .byte 0xAA, 0x55       // txid
    .byte 0x01, 0x00       // flags
    .byte 0x00, 0x01       // qdcount
    .byte 0x00, 0x00
    .byte 0x00, 0x00
    .byte 0x00, 0x00
    .byte 3
    .ascii "deb"
    .byte 6
    .ascii "debian"
    .byte 3
    .ascii "org"
    .byte 0
    .byte 0x00, 0x01       // qtype = A
    .byte 0x00, 0x01       // qclass = IN
    "#
);

#[panic_handler]
fn panic(_: &PanicInfo) -> ! { loop {} }
