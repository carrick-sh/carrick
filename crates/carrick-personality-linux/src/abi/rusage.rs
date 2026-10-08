//! Native Linux 64-bit rusage projection of the guest process owner's totals.
use carrick_sched_core::process::TaskRusage;
use core::time::Duration;

pub struct OwnedRusageOutput {
    bytes: [u8; carrick_syscall_abi::LINUX_RUSAGE_BYTES],
}
impl OwnedRusageOutput {
    pub fn from_usage(usage: TaskRusage) -> Option<Self> {
        fn timeval(bytes: &mut [u8], duration: Duration) -> Option<()> {
            let seconds = i64::try_from(duration.as_secs()).ok()?;
            let micros = i64::from(duration.subsec_micros());
            bytes[..8].copy_from_slice(&seconds.to_ne_bytes());
            bytes[8..16].copy_from_slice(&micros.to_ne_bytes());
            Some(())
        }
        let mut result = Self {
            bytes: [0; carrick_syscall_abi::LINUX_RUSAGE_BYTES],
        };
        timeval(&mut result.bytes[..16], usage.user_time)?;
        timeval(&mut result.bytes[16..32], usage.system_time)?;
        // The shared process owner currently accounts CPU duration only.
        // Untracked resource counters remain zero, never host/carrier values.
        Some(result)
    }
    pub fn as_bytes(&self) -> &[u8; carrick_syscall_abi::LINUX_RUSAGE_BYTES] {
        &self.bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn owned_usage_is_normalized_without_fabricating_untracked_counters() {
        let usage = TaskRusage {
            user_time: Duration::from_micros(1_000_007),
            system_time: Duration::from_micros(3),
        };
        let record = OwnedRusageOutput::from_usage(usage).unwrap();
        let words: alloc::vec::Vec<_> = record.as_bytes()[..32]
            .chunks_exact(8)
            .map(|word| i64::from_ne_bytes(word.try_into().unwrap()))
            .collect();
        assert_eq!(words, [1, 7, 0, 3]);
        assert!(record.as_bytes()[32..].iter().all(|byte| *byte == 0));
    }
}
