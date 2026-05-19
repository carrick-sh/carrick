// Minimal DNS-over-UDP query to prove our AF_INET SOCK_DGRAM pass-
// through works end-to-end. Sends an A-record query for example.com
// to 1.1.1.1:53, reads the response, prints "OK" if the response is
// well-formed (matches transaction id + has a non-error rcode), "FAIL"
// otherwise.
//
// The DNS packet bytes below are a hand-built standard query for
// "example.com" type A — easier to ship than a parser and small
// enough that the asm fits without a lookup table.

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

    // socket(AF_INET=2, SOCK_DGRAM=2, 0)
    mov x0, #2
    mov x1, #2
    mov x2, #0
    mov x8, #198
    svc #0
    mov w19, w0          // sockfd

    // Build sockaddr_in at sp+0: family=2, port=htons(53)=0x3500, addr=1.1.1.1
    mov w0, #2
    strh w0, [sp]
    mov w0, #0x3500
    strh w0, [sp, #2]
    mov w0, #0x101
    movk w0, #0x101, lsl #16
    str w0, [sp, #4]
    str xzr, [sp, #8]

    // Copy the DNS query bytes to sp+32.
    adr x0, dns_query
    add x1, sp, #32
    mov x2, #29
    bl copy_bytes

    // sendto(sockfd, sp+32, 29, 0, sp, 16)
    mov w0, w19
    add x1, sp, #32
    mov x2, #29
    mov x3, #0
    mov x4, sp
    mov x5, #16
    mov x8, #206         // SYS_sendto
    svc #0
    cmp x0, #0
    b.lt fail

    // recvfrom(sockfd, sp+128, 256, 0, NULL, NULL)
    mov w0, w19
    add x1, sp, #128
    mov x2, #256
    mov x3, #0
    mov x4, #0
    mov x5, #0
    mov x8, #207         // SYS_recvfrom
    svc #0
    cmp x0, #0
    b.lt fail
    cmp x0, #12
    b.lt fail           // response shorter than the DNS header → fail

    // Compare transaction id: query is 0xAA55, so response[0]=0xAA, [1]=0x55.
    ldrb w20, [sp, #128]
    cmp w20, #0xAA
    b.ne fail
    ldrb w20, [sp, #129]
    cmp w20, #0x55
    b.ne fail

    // Check rcode (low 4 bits of response[3]): 0 = NOERROR.
    ldrb w20, [sp, #131]
    and w20, w20, #0xF
    cmp w20, #0
    b.ne fail

    // write(1, "OK\n", 3)
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

// DNS query: txid=0xAA55, flags=0x0100 (standard query, RD=1),
// qd=1 an=0 ns=0 ar=0, qname=7"example"3"com"0, qtype=1 (A),
// qclass=1 (IN). Total: 12 (header) + 13 (qname) + 4 (qtype+qclass) = 29.
dns_query:
    .byte 0xAA, 0x55       // transaction id
    .byte 0x01, 0x00       // flags: standard query, RD
    .byte 0x00, 0x01       // qdcount
    .byte 0x00, 0x00       // ancount
    .byte 0x00, 0x00       // nscount
    .byte 0x00, 0x00       // arcount
    .byte 7
    .ascii "example"
    .byte 3
    .ascii "com"
    .byte 0
    .byte 0x00, 0x01       // qtype = A
    .byte 0x00, 0x01       // qclass = IN
    "#
);

#[panic_handler]
fn panic(_: &PanicInfo) -> ! { loop {} }
