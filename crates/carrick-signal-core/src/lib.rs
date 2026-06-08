//! Platform-NEUTRAL signal pending bookkeeping, shared by every backend: the
//! UNBLOCKED async-arrival store (THREAD_PENDING + PROC_PENDING) and SENDER_PID.
//! The dispatcher's blocked-signal/queued-siginfo store is SEPARATE (see the
//! design doc's two-slot invariant). Functions are filled in by Task 2.

/// Bit for `signum` in a u64 pending mask (`signum-1`), or `None` if out of 1..=64.
pub fn pending_bit(signum: i32) -> Option<u64> {
    (1..=64).contains(&signum).then(|| 1u64 << (signum - 1))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pending_bit_basics() {
        assert_eq!(pending_bit(1), Some(1));
        assert_eq!(pending_bit(64), Some(1 << 63));
        assert_eq!(pending_bit(0), None);
        assert_eq!(pending_bit(65), None);
    }
}
