//! Host-portable policy for the Darwin copyfile fast path.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CopyMethod {
    Clone,
    Data,
}

pub const fn attempt_order() -> [CopyMethod; 2] {
    [CopyMethod::Clone, CopyMethod::Data]
}

pub fn reported_len(copied_bytes: Option<u64>, expected_len: u64) -> u64 {
    copied_bytes.unwrap_or(expected_len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clone_precedes_data_copy() {
        assert_eq!(attempt_order(), [CopyMethod::Clone, CopyMethod::Data]);
    }

    #[test]
    fn genuine_zero_byte_copy_stays_zero() {
        assert_eq!(reported_len(Some(0), 8192), 0);
        assert_eq!(reported_len(None, 8192), 8192);
    }
}
