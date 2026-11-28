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
 * -DLAST_RETURN (#3083): as BUSY_RESCHED, but the IPI's resend at the
 * hold's return to user finds the ICR busy too, and this CPU then runs a
 * syscall-free loop: that return is the last delivery point before it.
 * The peer is released before the hold, so no later syscall comes between
 * the hold and the loop. The ICR stays busy until a wait sees it go idle
 * (its first poll reads busy, the next idle). The return must wait for
 * that and then send: the census right after the loop must read exactly
 * two busy sends (a resend before the transition would be a third), one
 * resend, one busy-to-idle transition, and the resend at the syscall's own
 * return (exit 93 otherwise).
 *
 * -DLAST_RETURN_STALLED (#3083): as LAST_RETURN, but the ICR recovers
 * while the last-chance wait is stalled past its bound before its first
 * poll (a host descheduling the vCPU). A stall is not a broken APIC: the
 * poll reads idle and the resend goes out (exit 93 or a fatal otherwise).
 *
 * -DLAST_RETURN_STALLED_AFTER_POLL (#3083): as LAST_RETURN, but the
 * vCPU stalls past the bound right after the wait's poll read the ICR
 * busy, and the ICR recovers meanwhile. That stale busy result started
 * inside the bound: the next poll reads idle and the resend goes out, the
 * census as LAST_RETURN's (exit 93 or a fatal otherwise).
 *
 * -DLAST_RETURN_STALLED_AFTER_SEND (#3083): as LAST_RETURN, but with no
 * busy poll: the first send and two resends at the return find the ICR
 * busy, and the vCPU stalls past the bound right after the third, while
 * the ICR recovers. The next resend goes out: the census must read three
 * busy sends, one resend, no transition, at the syscall's own return
 * (exit 93 or a fatal otherwise).
 *
 * -DICR_FLAPPING (#3083): as LAST_RETURN, but every send finds the ICR
 * busy while every idle-ICR poll reads it idle, a local APIC that never
 * accepts its send. The hold's return must end the run with a CPL0 fatal
 * at the bounded wait, never loop; the fixture never reaches its exit.
 *
 * -DTWO_OWED_STALLED (#3129 P0 1): as LAST_RETURN, but the hold's busy
 * send also owes this CPU's own slot (a self-kick that found the ICR
 * busy), so the return's resend pass sends two. Its first send goes out
 * after a stall past the bound; its second finds the ICR busy with that
 * fresh IPI; one poll then reads busy, the next idle. The fresh IPI's
 * busy result is not a broken APIC: the census must read two busy sends,
 * two resends, one transition, at the syscall's own return, and one stall
 * (exit 93 or a fatal otherwise).
 *
 * -DLATE_ARM (#3136): as AFTER_IDLE_READ, but the arming completes only
 * once a peer pass begun after the arming vector went out (so its drain
 * took it) has found the arming incomplete with no wake pending, as a host
 * that deschedules this vCPU right after the send allows. That same pass
 * must stop at its ordering point: a pass that went on and slept has no
 * wake left, and the bounded child reaches its bound. Exit 92: the pass
 * that stopped is not the one that took the vector.
 *
 * -DIDLE_OWED (#3129 P0 2): every send of this CPU finds the ICR busy, and
 * the scheduler owes the other CPU a reschedule when this CPU's task parks
 * (in a FUTEX_WAIT nobody ends), as a waker whose syscall then blocks
 * would. The idle pass is the next delivery point, with no return to user
 * after it. The idle sender must end the run with a CPL0 fatal past the
 * bound at the idle pass, never spin; the fixture never reaches its exit
 * (94: the park returned).
 *
 * Exit 7: the peer took the publication, and the ordered pass ran once.
 * 81: arming failed; 83: the publication failed; 84: releasing the peer
 * failed; 91: the peer took the publication but the ordered pass did not
 * run exactly once. A peer that slept past the publication never takes
 * it: the bounded child reaches its bound (no exit code).
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

/* Census: sends found busy | resent << 16 | busy-to-idle transitions a
 * wait saw << 32 | the last resend's return to user << 48 (1: the
 * syscall's own) | injected stalls that ran << 56. The bound runs on the
 * witness clock under injection (one tick per ICR operation, twice the
 * bound per stall), so host load never moves a verdict. */
#ifdef ICR_FLAPPING
#define LAST_RETURN 1
#define BUSY_INJECT     INJECT_RESCHED_ICR_FLAPPING
#elif defined(TWO_OWED_STALLED)
#define LAST_RETURN 1
#define BUSY_INJECT     INJECT_RESCHED_TWO_OWED_STALLED
#elif defined(LAST_RETURN_STALLED)
#define LAST_RETURN 1
#define BUSY_INJECT     INJECT_RESCHED_STALL_AT_LAST_RETURN
#elif defined(LAST_RETURN_STALLED_AFTER_POLL)
#define LAST_RETURN 1
#define BUSY_INJECT     INJECT_RESCHED_STALL_AFTER_BUSY_POLL
#elif defined(LAST_RETURN_STALLED_AFTER_SEND)
#define LAST_RETURN 1
#define BUSY_INJECT     INJECT_RESCHED_STALL_AFTER_BUSY_SEND
#elif defined(LAST_RETURN)
#define BUSY_INJECT     INJECT_RESCHED_BUSY_THROUGH_LAST_RETURN
#else
#define BUSY_INJECT     INJECT_RESCHED_BUSY_ONCE
#endif
#if defined(TWO_OWED_STALLED)
#define BUSY_RESCHED 1
#define BUSY_AFTER_HOLD 0x0101000100020002
#define BUSY_AT_END     0x0101000100020002
#elif defined(LAST_RETURN_STALLED_AFTER_SEND)
#define BUSY_RESCHED 1
#define BUSY_AFTER_HOLD 0x0101000000010003
#define BUSY_AT_END     0x0101000000010003
#elif defined(LAST_RETURN_STALLED_AFTER_POLL)
#define BUSY_RESCHED 1
#define BUSY_AFTER_HOLD 0x0101000100010002
#define BUSY_AT_END     0x0101000100010002
#elif defined(LAST_RETURN_STALLED)
#define BUSY_RESCHED 1
#define BUSY_AFTER_HOLD 0x0101000000010002
#define BUSY_AT_END     0x0101000000010002
#elif defined(LAST_RETURN)
#define BUSY_RESCHED 1
#define BUSY_AFTER_HOLD 0x0001000100010002
#define BUSY_AT_END     0x0001000100010002
#else
#define BUSY_AFTER_HOLD 0x0001000000010001
#define BUSY_AT_END     0x0001000000010001
#endif
#define INJECT_RESCHED_BUSY_THROUGH_LAST_RETURN 0xfffffffffffffe5f
#define INJECT_RESCHED_ICR_FLAPPING        0xfffffffffffffe60
#define INJECT_RESCHED_STALL_AT_LAST_RETURN 0xfffffffffffffe61
#define INJECT_RESCHED_STALL_AFTER_BUSY_POLL 0xfffffffffffffe62
#define INJECT_RESCHED_STALL_AFTER_BUSY_SEND 0xfffffffffffffe63
#define INJECT_RESCHED_TWO_OWED_STALLED    0xfffffffffffffe64
#define INJECT_RESCHED_OWED_AT_PARK        0xfffffffffffffe65
#define INJECT_ORDER_PEER_AFTER_IDLE_READ_LATE_ARM 0xfffffffffffffe70
#define INJECT_ORDER_PEER_LATE_ARM_CENSUS  0xfffffffffffffe71
#define SPIN_USER                          0x1000000
#ifdef LATE_ARM
#define AFTER_IDLE_READ 1
#endif
#ifdef BUSY_RESCHED
#define AFTER_IDLE_READ 1
#endif

.global _start
.text
_start:
#ifdef IDLE_OWED
    mov $INJECT_RESCHED_OWED_AT_PARK, %rax
    syscall
    test %rax, %rax
    jnz fail_arm
    /* FUTEX_WAIT_PRIVATE on idle_word == 0, which nobody wakes: the
     * park owes the other CPU its reschedule. */
    lea idle_word(%rip), %rdi
    mov $128, %esi
    xor %edx, %edx
    xor %r10d, %r10d
    mov $202, %eax
    syscall
    mov $94, %edi
    jmp die
#endif
#if defined(LATE_ARM)
    mov $INJECT_ORDER_PEER_AFTER_IDLE_READ_LATE_ARM, %rax
#elif defined(AFTER_IDLE_READ)
    mov $INJECT_ORDER_PEER_AFTER_IDLE_READ, %rax
#else
    mov $INJECT_ORDER_PEER_BEFORE_IDLE_HLT, %rax
#endif
    syscall
    test %rax, %rax
    jnz fail_arm

    /* Wait for the peer's own stop, the event itself (#3136): a count of
     * polls ran out under load while the peer vCPU was unscheduled. The
     * bounded child is the hang bound. */
reach_loop:
    mov $INJECT_ORDER_PEER_REACHED, %rax
    syscall
    cmp $1, %rax
    je reached
    pause
    jmp reach_loop
reached:

#ifdef BUSY_RESCHED
    mov $BUSY_INJECT, %rax
    syscall
    test %rax, %rax
    jnz fail_publish
#endif
#ifdef LAST_RETURN
    /* Release the peer first: it goes on only once the hold's vector is
     * pending, and no syscall then follows the hold before the loop. */
    mov $INJECT_ORDER_PEER_PUBLISHED, %rax
    syscall
    test %rax, %rax
    jnz fail_release
#endif
#ifdef AFTER_IDLE_READ
    mov $INJECT_HOLD_PEER_SCAN, %rax
#else
    mov $INJECT_MARK_PEER_HOST_WORK, %rax
#endif
    syscall
    test %rax, %rax
    jnz fail_publish

#ifdef LAST_RETURN
    /* A syscall-free user loop: no later delivery point than the hold's
     * own return to user. */
    mov $SPIN_USER, %r13
spin_user:
    pause
    dec %r13
    jnz spin_user
#endif
#ifdef BUSY_RESCHED
    /* The hold's own return to user is the next delivery point: by this
     * syscall's entry the busy IPI must already be resent, once. */
    mov $INJECT_RESCHED_BUSY_CENSUS, %rax
    syscall
    mov $BUSY_AFTER_HOLD, %rcx
    cmp %rcx, %rax
    jne fail_busy_census
#endif

#ifndef LAST_RETURN
    mov $INJECT_ORDER_PEER_PUBLISHED, %rax
    syscall
    test %rax, %rax
    jnz fail_release
#endif

    /* Wait for the peer to take the publication, the event itself, as
     * the reach loop does: a count of polls is a clock that a loaded host
     * moves (#3136). A peer that slept past the publication never takes
     * it, and the bounded child reaches its bound with a post-mortem. */
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
    pause
    jmp taken_loop
taken:

    mov $INJECT_ORDER_PEER_CENSUS, %rax
    syscall
    cmp $1, %rax
    jne fail_census
#ifdef LATE_ARM
    mov $INJECT_ORDER_PEER_LATE_ARM_CENSUS, %rax
    syscall
    cmp $1, %rax
    jne fail_late_census
#endif
#ifdef BUSY_RESCHED
    mov $INJECT_RESCHED_BUSY_CENSUS, %rax
    syscall
    mov $BUSY_AT_END, %rcx
    cmp %rcx, %rax
    jne fail_busy_census
#endif
    mov $7, %edi
    jmp die

fail_arm:
    mov $81, %edi
    jmp die
fail_publish:
    mov $83, %edi
    jmp die
fail_release:
    mov $84, %edi
    jmp die
fail_busy_census:
    mov $93, %edi
    jmp die
fail_census:
    mov $91, %edi
    jmp die
fail_late_census:
    mov $92, %edi
die:
    mov $231, %eax
    syscall
    ud2

.bss
.balign 8
idle_word: .space 8
