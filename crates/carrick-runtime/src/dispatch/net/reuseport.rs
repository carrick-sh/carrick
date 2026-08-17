//! Linux `SO_REUSEPORT` load distribution.
//!
//! # Why this exists
//!
//! Linux and Darwin both let several sockets bind one `addr:port` when they all
//! set `SO_REUSEPORT`, and there the agreement ends. Linux spreads incoming
//! work across the group — hashing the connection's 4-tuple to pick a listener
//! at SYN time, and a datagram's source to pick a receiver. Darwin does not
//! distribute at all: **the last binder takes everything.**
//!
//! Measured on macOS 27 / Apple Silicon, two sockets on `127.0.0.1:PORT`:
//!
//! ```text
//! TCP: 10 connections -> listener0=0  listener1=10
//! UDP: 10 datagrams   -> receiver0=0  receiver1=10
//! ```
//!
//! libuv's `tcp_reuseport` and `udp_reuseport` assert `ASSERT_GT(..., 0)` on
//! BOTH listeners, so a Darwin passthrough fails them outright, and any guest
//! that scales by forking N reuseport workers silently runs on one.
//!
//! # The model
//!
//! Every member keeps its own host socket — Darwin binds them happily. What
//! Carrick adds is *whose turn it is*:
//!
//! * a member is reported READABLE only when the group's cursor points at it
//!   and some member's host socket actually has work pending;
//! * an `accept`/`recv` that finds its own host socket empty may take work from
//!   a sibling's, so the connection Darwin parked on the wrong socket still
//!   reaches the member whose turn it is;
//! * a successful take advances the cursor.
//!
//! Two symmetric workers therefore alternate strictly, which is what makes the
//! result DETERMINISTIC rather than a wake race that "usually" spreads. That
//! matters: a conformance assertion that passes on most runs is not passing.
//!
//! This is turn-taking, not Linux's 4-tuple hash. Both satisfy "every member
//! receives work"; neither guest can observe the difference except by
//! correlating peer addresses to workers, which nothing portable does. What a
//! guest CAN observe — that all N workers make progress — is now true.
//!
//! # Scope
//!
//! The table is **carrier-wide** and keyed by the HOST bind address, because
//! that is the thing being grouped: one real BSD socket bound to one host
//! `addr:port`. Under HVPatch every logical Linux process shares one carrier,
//! and two Linux processes that both bind `127.0.0.1:9123` with `SO_REUSEPORT`
//! must land in the SAME group — a per-process table would silently split them
//! and reintroduce the bug for the multi-process case, which is the common one.
//! Per `docs/identity-and-scope-domains.md` a `static` carries no mark saying
//! which scope it means, so this one says it here: carrier-wide, deliberately,
//! keyed by a host object's identity, exactly like the FIFO beacon's
//! `(st_dev, st_ino)` table.
//!
//! Membership is removed EXPLICITLY when a socket closes. Host fds are reused,
//! so a stale entry would hand a later unrelated socket's traffic to this
//! group.
//!
//! # Known limitation, stated rather than hidden
//!
//! If the cursor's member stops calling `accept`/`recv` entirely, the group
//! waits for it: its siblings are not told they are readable. Linux has no such
//! coupling, because each socket owns a real kernel queue. In exchange, a
//! member that is merely slow still cannot starve the others, since any member
//! that does call in takes the pending work and advances the cursor.

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};

/// A host bind address, as the key the host kernel itself groups on.
///
/// Held as the raw `sockaddr` bytes actually returned by `getsockname(2)` so
/// there is no family-specific parsing to get wrong, and so an address family
/// Carrick does not model can never collide with one it does.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct GroupKey {
    /// Linux `SOCK_STREAM` / `SOCK_DGRAM`: a TCP and a UDP socket on the same
    /// port are different groups, as on Linux.
    socket_type: i32,
    host_addr: Vec<u8>,
}

impl GroupKey {
    pub(super) fn new(socket_type: i32, host_addr: Vec<u8>) -> Self {
        Self {
            socket_type,
            host_addr,
        }
    }
}

#[derive(Debug, Default)]
struct Group {
    /// Host fds of the live members, in join order.
    members: Vec<i32>,
    /// Index into `members` whose turn it is. Always `< members.len()` while
    /// the group is non-empty.
    cursor: usize,
}

/// CARRIER-WIDE reuseport groups. See the module header for why this scope is
/// the correct one and not an accident.
static GROUPS: LazyLock<Mutex<HashMap<GroupKey, Group>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Add `host_fd` to the group for `key`, creating it if needed. Idempotent.
pub(super) fn join(key: GroupKey, host_fd: i32) {
    let mut groups = GROUPS.lock().unwrap_or_else(|e| e.into_inner());
    let group = groups.entry(key).or_default();
    if !group.members.contains(&host_fd) {
        group.members.push(host_fd);
    }
}

/// Drop `host_fd` from every group. Called when a socket closes.
///
/// Sweeps all groups rather than requiring the caller to recompute the key: at
/// close time the socket may already be unbound, and a membership that outlives
/// its fd is worse than a linear scan over what is normally a handful of
/// groups.
pub(super) fn leave(host_fd: i32) {
    let mut groups = GROUPS.lock().unwrap_or_else(|e| e.into_inner());
    groups.retain(|_, group| {
        if let Some(index) = group.members.iter().position(|&fd| fd == host_fd) {
            group.members.remove(index);
            // Keep the cursor inside the (now shorter) member list, and do not
            // let removing a member before the cursor silently skip a turn.
            if group.members.is_empty() {
                group.cursor = 0;
            } else {
                if index < group.cursor {
                    group.cursor -= 1;
                }
                group.cursor %= group.members.len();
            }
        }
        !group.members.is_empty()
    });
}

/// The other live members of `host_fd`'s group, in turn order starting at the
/// cursor. Empty when `host_fd` is in no group or is the only member — in which
/// case the caller must behave exactly as it did before reuseport existed.
pub(super) fn siblings(host_fd: i32) -> Vec<i32> {
    let groups = GROUPS.lock().unwrap_or_else(|e| e.into_inner());
    for group in groups.values() {
        if !group.members.contains(&host_fd) {
            continue;
        }
        if group.members.len() < 2 {
            return Vec::new();
        }
        let len = group.members.len();
        return (0..len)
            .map(|offset| group.members[(group.cursor + offset) % len])
            .filter(|&fd| fd != host_fd)
            .collect();
    }
    Vec::new()
}

/// The siblings this member may take work from RIGHT NOW: empty unless it is
/// this member's turn.
///
/// Draining one's OWN socket is always allowed and deliberately not gated — a
/// member owns whatever the host queued to it, exactly as on Linux, and
/// `recvmmsg` legitimately drains until empty. Turn-taking governs only the
/// taking of a SIBLING's work, which is the part Darwin gets wrong. Without
/// this distinction the first member to wake steals the entire backlog in one
/// `recvmmsg` and its sibling still receives nothing.
pub(super) fn steal_targets(host_fd: i32) -> Vec<i32> {
    if !is_turn(host_fd) {
        return Vec::new();
    }
    siblings(host_fd)
}

/// Whether it is `host_fd`'s turn. A socket in no group, or the only member of
/// its group, is always its own turn.
pub(super) fn is_turn(host_fd: i32) -> bool {
    let groups = GROUPS.lock().unwrap_or_else(|e| e.into_inner());
    for group in groups.values() {
        if let Some(index) = group.members.iter().position(|&fd| fd == host_fd) {
            return group.members.len() < 2 || index == group.cursor;
        }
    }
    true
}

/// Whether `host_fd` belongs to a group with more than one member. Callers use
/// this to stay entirely on the pre-existing path for ordinary sockets.
pub(super) fn is_shared(host_fd: i32) -> bool {
    let groups = GROUPS.lock().unwrap_or_else(|e| e.into_inner());
    groups
        .values()
        .any(|group| group.members.len() > 1 && group.members.contains(&host_fd))
}

/// Hand the turn to the next member after `host_fd`. Called after a member
/// successfully takes work.
pub(super) fn advance_turn(host_fd: i32) {
    let mut groups = GROUPS.lock().unwrap_or_else(|e| e.into_inner());
    for group in groups.values_mut() {
        if let Some(index) = group.members.iter().position(|&fd| fd == host_fd) {
            if !group.members.is_empty() {
                group.cursor = (index + 1) % group.members.len();
            }
            return;
        }
    }
}

#[cfg(test)]
pub(super) fn reset_for_tests() {
    GROUPS.lock().unwrap_or_else(|e| e.into_inner()).clear();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> GroupKey {
        GroupKey::new(1, vec![2, 0, 0x23, 0x8b, 127, 0, 0, 1])
    }

    /// A socket in no group must behave exactly as before: always its turn,
    /// never shared, no siblings. Every call site is gated on this, so getting
    /// it wrong would change ordinary sockets.
    #[test]
    fn an_ungrouped_socket_is_untouched() {
        reset_for_tests();
        assert!(is_turn(42));
        assert!(!is_shared(42));
        assert!(siblings(42).is_empty());
    }

    /// One member is not a group. Darwin already delivers everything to a lone
    /// socket, so it must stay on the untouched path.
    #[test]
    fn a_lone_member_is_not_shared() {
        reset_for_tests();
        join(key(), 10);
        assert!(is_turn(10));
        assert!(!is_shared(10));
        assert!(siblings(10).is_empty());
    }

    /// The property the libuv rows actually assert: with two members, turns
    /// strictly alternate, so BOTH receive work. Darwin alone gives one of them
    /// zero.
    #[test]
    fn two_members_alternate_deterministically() {
        reset_for_tests();
        join(key(), 10);
        join(key(), 11);
        assert!(is_shared(10) && is_shared(11));

        let mut turns = Vec::new();
        for _ in 0..6 {
            let taker = if is_turn(10) { 10 } else { 11 };
            turns.push(taker);
            advance_turn(taker);
        }
        assert_eq!(turns, vec![10, 11, 10, 11, 10, 11]);
    }

    /// A member may drain its OWN socket freely but may take a sibling's work
    /// only on its turn. Otherwise the first member to wake steals the whole
    /// backlog in one `recvmmsg` and its sibling still gets nothing — which is
    /// exactly the failure `udp_reuseport` reported before this split.
    #[test]
    fn stealing_is_gated_on_the_turn_but_own_draining_is_not() {
        reset_for_tests();
        join(key(), 10);
        join(key(), 11);
        assert_eq!(steal_targets(10), vec![11], "10 has the turn");
        assert!(
            steal_targets(11).is_empty(),
            "11 must not steal out of turn"
        );
        advance_turn(10);
        assert!(steal_targets(10).is_empty());
        assert_eq!(steal_targets(11), vec![10]);
    }

    /// Whoever's turn it is must be able to find the sibling holding the work,
    /// because Darwin parks everything on the last binder.
    #[test]
    fn siblings_exclude_self_and_start_at_the_cursor() {
        reset_for_tests();
        for fd in [10, 11, 12] {
            join(key(), fd);
        }
        assert_eq!(siblings(10), vec![11, 12]);
        advance_turn(10); // cursor -> 11
        assert_eq!(siblings(10), vec![11, 12]);
        assert_eq!(siblings(11), vec![12, 10]);
    }

    /// Host fds are REUSED. A membership that outlived its socket would hand a
    /// later, unrelated socket's traffic to this group, so close must remove it
    /// and an emptied group must disappear entirely.
    #[test]
    fn leaving_prunes_the_member_and_empty_groups() {
        reset_for_tests();
        join(key(), 10);
        join(key(), 11);
        leave(11);
        assert!(!is_shared(10), "one survivor is no longer a group");
        assert!(is_turn(10));
        leave(10);
        // A brand-new socket that happens to reuse fd 10 must be ungrouped.
        assert!(!is_shared(10));
        assert!(siblings(10).is_empty());
    }

    /// Removing a member must not skip the surviving members' turns, and must
    /// never leave the cursor pointing past the end.
    #[test]
    fn leaving_keeps_the_cursor_in_range() {
        reset_for_tests();
        for fd in [10, 11, 12] {
            join(key(), fd);
        }
        advance_turn(10);
        advance_turn(11); // cursor -> index 2 (fd 12)
        assert!(is_turn(12));
        leave(10); // members [11, 12], the removed index was before the cursor
        assert!(
            is_turn(12),
            "12 keeps its turn after an earlier member left"
        );
        leave(12);
        assert!(is_turn(11), "the last survivor always has the turn");
    }

    /// A TCP and a UDP socket on the same port are different groups, as on
    /// Linux.
    #[test]
    fn socket_type_separates_groups() {
        reset_for_tests();
        let addr = vec![2, 0, 0x23, 0x8b, 127, 0, 0, 1];
        join(GroupKey::new(1, addr.clone()), 10);
        join(GroupKey::new(2, addr), 11);
        assert!(!is_shared(10));
        assert!(!is_shared(11));
    }
}
