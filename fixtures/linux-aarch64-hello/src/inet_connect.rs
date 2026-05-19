// AF_INET socket+connect test. If our BSD passthrough is wired, this
// should connect to 1.1.1.1:80 and exit 0; if not, ECONNREFUSED or
// ENOSYS or EHOSTUNREACH.

#![no_main]
#![no_std]

use core::arch::global_asm;
use core::panic::PanicInfo;

global_asm!(
    r#"
    .global _start
    .type _start, %function
_start:
    sub sp, sp, #64

    // socket(AF_INET=2, SOCK_STREAM=1, 0)
    mov x0, #2
    mov x1, #1
    mov x2, #0
    mov x8, #198
    svc #0
    mov w19, w0          // sockfd

    // build sockaddr_in at sp: family=AF_INET(2), port=htons(80)=0x5000, addr=1.1.1.1=0x01010101
    mov w0, #2
    strh w0, [sp]
    mov w0, #0x5000      // htons(80)
    strh w0, [sp, #2]
    mov w0, #0x101       // low half of 1.1.1.1 in network byte order
    movk w0, #0x101, lsl #16
    str w0, [sp, #4]
    // padding
    str xzr, [sp, #8]

    // connect(sockfd, sp, 16)
    mov w0, w19
    mov x1, sp
    mov x2, #16
    mov x8, #203
    svc #0

    // exit_group(retval-of-connect's sign — 0 if success, nonzero otherwise but
    // we want stdout to say something visible). Use the return value:
    //   x0 == 0  -> write "OK\n"
    //   x0 != 0  -> write "FAIL " + the errno digit
    cmp x0, #0
    b.eq write_ok
    // negative errno; write 'F' for clarity
    mov w0, #1
    adr x1, msg_fail
    mov x2, #5
    mov x8, #64
    svc #0
    mov x0, #1
    mov x8, #94
    svc #0

write_ok:
    mov w0, #1
    adr x1, msg_ok
    mov x2, #3
    mov x8, #64
    svc #0
    mov x0, #0
    mov x8, #94
    svc #0

msg_ok: .ascii "OK\n"
msg_fail: .ascii "FAIL\n"
    "#
);

#[panic_handler]
fn panic(_: &PanicInfo) -> ! { loop {} }
