//! ARM ring-first flip opt-out hatch.
//!
//! Controlled by `CARRICK_ARM_RING_FIRST`:
//! - Default (unset or != "0"): strict ring-first forward allowlist is enforced.
//! - "0": opt-out hatch active; pre-flip host forwarding is restored.

/// Single owner of the ARM ring-first flip opt-out policy.
pub struct ArmRingFirstHatch;

impl ArmRingFirstHatch {
    /// Returns true if ARM EL1 enforces the strict forward allowlist (default: true).
    /// Disabled only when `CARRICK_ARM_RING_FIRST=0`.
    #[inline]
    pub fn is_strict() -> bool {
        match std::env::var_os("CARRICK_ARM_RING_FIRST") {
            Some(val) => val != "0",
            None => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hatch_env_var_semantics() {
        // Safe lock or scope is implied for env vars in single-threaded test
        let prev = std::env::var_os("CARRICK_ARM_RING_FIRST");

        unsafe {
            std::env::remove_var("CARRICK_ARM_RING_FIRST");
        }
        assert!(ArmRingFirstHatch::is_strict());

        unsafe {
            std::env::set_var("CARRICK_ARM_RING_FIRST", "1");
        }
        assert!(ArmRingFirstHatch::is_strict());

        unsafe {
            std::env::set_var("CARRICK_ARM_RING_FIRST", "true");
        }
        assert!(ArmRingFirstHatch::is_strict());

        unsafe {
            std::env::set_var("CARRICK_ARM_RING_FIRST", "0");
        }
        assert!(!ArmRingFirstHatch::is_strict());

        unsafe {
            match prev {
                Some(val) => std::env::set_var("CARRICK_ARM_RING_FIRST", val),
                None => std::env::remove_var("CARRICK_ARM_RING_FIRST"),
            }
        }
    }
}
