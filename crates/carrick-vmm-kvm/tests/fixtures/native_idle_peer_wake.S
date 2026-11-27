/* #3053: a wake published while the other CPU's idle pass is between two
 * of its steps must still end that pass's sleep. The fixture image stops
 * the peer CPU at an exact point of its production idle pass, this CPU
 * publishes, and only then lets the peer go on. No sleeps: every step
 * orders on a word the other side publishes.
 *
 * -DAFTER_IDLE_READ: the peer stops right after its pass has read its
 * conditions. This CPU then arms the peer's scan hold (the condition,
 * then its reschedule vector), and the peer goes on only once that vector
 * is pending in its IRR. The peer must take the hold: its vector is the
 * only wake it has, so a pass that drains vectors after reading sleeps
 * past it.
 *
 * -DBEFORE_IDLE_HLT: the peer stops once its slot is published IdleWfi,
 * right before HLT. This CPU then publishes host work on the peer's task
 * with no vector, as the host does for a CPU stopped in a crossing. The
 * peer must settle it: only the durable word announces it, so a pass
 * that sleeps without rechecking it never rings the host.
 *
 * -DBUSY_RESCHED (#3083): as AFTER_IDLE_READ, but the scan hold's
 * reschedule IPI finds this CPU's ICR busy, once, by injection. A busy
 * ICR is "not now": the IPI is owed by this CPU and resent at its next
 * delivery point (here, the hold's own return to user), so the peer still
 * gets its only wake. Exit 93: the census, read right after the busy send's
 * syscall returned (and again once the hold is taken), does not show
 * exactly one busy send and one resend.
 *
 * Exit 7: the peer took the publication, and the ordered pass ran once.
 * 81: arming failed; 82: the peer never reached its stop; 83: the
 * publication failed; 84: releasing the peer failed; 90: the ordered pass
 * ran once and the peer slept past the publication; 91: the peer took the
 * publication but the ordered pass did not run exactly once; 92: the peer
 * slept, but the ordered pass did not run exactly once.
 */
#define INJECT_PEER_SCAN_HELD              0xfffffffffffffe2b
#define INJECT_HOLD_PEER_SCAN              0xfffffffffffffe2a
#define INJECT_ORDER_PEER_AFTER_IDLE_READ  0xfffffffffffffe5c
#define INJECT_ORDER_PEER_BEFORE_IDLE_HLT  0xfffffffffffffe56
#define INJECT_ORDER_PEER_REACHED          0xfffffffffffffe57
#define INJECT_ORDER_PEER_PUBLISHED        0xfffffffffffffe58
#define INJECT_ORDER_PEER_CENSUS           0xfffffffffffffe59
#define INJECT_MARK_PEER_HOST_WORK         0xfffffffffffffe5a
#define INJECT_PEER_HOST_WORK_PENDING      0xfffffffffffffe5b
#define INJECT_RESCHED_BUSY_ONCE           0xfffffffffffffe5d
#define INJECT_RESCHED_BUSY_CENSUS         0xfffffffffffffe5e
#define POLL_LIMIT                         0x1000000

#ifdef BUSY_RESCHED
#define AFTER_IDLE_READ 1
#endif

.global _start
.text
_start:
#ifdef AFTER_IDLE_READ
    mov $INJECT_ORDER_PEER_AFTER_IDLE_READ, %rax
#else
    mov $INJECT_ORDER_PEER_BEFORE_IDLE_HLT, %rax
#endif
    syscall
    test %rax, %rax
    jnz fail_arm

    mov $POLL_LIMIT, %r13
reach_loop:
    mov $INJECT_ORDER_PEER_REACHED, %rax
    syscall
    cmp $1, %rax
    je reached
    dec %r13
    jz fail_reach
    pause
    jmp reach_loop
reached:

#ifdef BUSY_RESCHED
    mov $INJECT_RESCHED_BUSY_ONCE, %rax
    syscall
    test %rax, %rax
    jnz fail_publish
#endif
#ifdef AFTER_IDLE_READ
    mov $INJECT_HOLD_PEER_SCAN, %rax
#else
    mov $INJECT_MARK_PEER_HOST_WORK, %rax
#endif
    syscall
    test %rax, %rax
    jnz fail_publish

#ifdef BUSY_RESCHED
    /* The hold's own return to user is the next delivery point: by this
     * syscall's entry the busy IPI must already be resent, once. */
    mov $INJECT_RESCHED_BUSY_CENSUS, %rax
    syscall
    mov $0x100000001, %rcx
    cmp %rcx, %rax
    jne fail_busy_census
#endif

    mov $INJECT_ORDER_PEER_PUBLISHED, %rax
    syscall
    test %rax, %rax
    jnz fail_release

    mov $POLL_LIMIT, %r13
taken_loop:
#ifdef AFTER_IDLE_READ
    mov $INJECT_PEER_SCAN_HELD, %rax
    syscall
    cmp $1, %rax
#else
    mov $INJECT_PEER_HOST_WORK_PENDING, %rax
    syscall
    cmp $0, %rax
#endif
    je taken
    dec %r13
    jz fail_slept
    pause
    jmp taken_loop
taken:

    mov $INJECT_ORDER_PEER_CENSUS, %rax
    syscall
    cmp $1, %rax
    jne fail_census
#ifdef BUSY_RESCHED
    mov $INJECT_RESCHED_BUSY_CENSUS, %rax
    syscall
    mov $0x100000001, %rcx
    cmp %rcx, %rax
    jne fail_busy_census
#endif
    mov $7, %edi
    jmp die

fail_arm:
    mov $81, %edi
    jmp die
fail_reach:
    mov $82, %edi
    jmp die
fail_publish:
    mov $83, %edi
    jmp die
fail_release:
    mov $84, %edi
    jmp die
fail_slept:
    mov $INJECT_ORDER_PEER_CENSUS, %rax
    syscall
    cmp $1, %rax
    jne fail_slept_unordered
    mov $90, %edi
    jmp die
fail_slept_unordered:
    mov $92, %edi
    jmp die
fail_busy_census:
    mov $93, %edi
    jmp die
fail_census:
    mov $91, %edi
die:
    mov $231, %eax
    syscall
    ud2
