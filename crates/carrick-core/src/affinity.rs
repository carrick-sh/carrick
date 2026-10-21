//! Pure CPU affinity representations, validation and conversions.
//!
//! Shared across the host dispatcher and in-ring syscall handling.
extern crate alloc;
use alloc::vec::Vec;

pub const MAX_GUEST_CPUS: usize = 64;
pub const AFFINITY_WORDS: usize = MAX_GUEST_CPUS.div_ceil(64);

pub use carrick_sched_core::affinity::{
    AffinityAuthority, AffinityNotification, AffinityNotifier, AffinityResidencyToken,
};

/// Which guest CPUs a task may run on.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CpuAffinity {
    words: [u64; AFFINITY_WORDS],
}

impl CpuAffinity {
    /// Every CPU below `ncpu` allowed (`ncpu` is clamped to [`MAX_GUEST_CPUS`]).
    pub const fn all(ncpu: usize) -> Self {
        let mut words = [0u64; AFFINITY_WORDS];
        let max = if ncpu < MAX_GUEST_CPUS {
            ncpu
        } else {
            MAX_GUEST_CPUS
        };
        let mut cpu = 0;
        while cpu < max {
            words[cpu / 64] |= 1u64 << (cpu % 64);
            cpu += 1;
        }
        Self { words }
    }

    /// Exactly one CPU allowed.
    pub const fn single(cpu: u32) -> Self {
        let mut words = [0u64; AFFINITY_WORDS];
        let idx = cpu as usize;
        if idx < MAX_GUEST_CPUS {
            words[idx / 64] |= 1u64 << (idx % 64);
        }
        Self { words }
    }

    /// The low `MAX_GUEST_CPUS` bits of a guest `cpu_set_t` word mask.
    pub const fn from_words(mask: &[u64]) -> Self {
        let mut words = [0u64; AFFINITY_WORDS];
        let mut i = 0;
        while i < AFFINITY_WORDS && i < mask.len() {
            words[i] = mask[i];
            i += 1;
        }
        Self { words }
    }

    pub const fn words(&self) -> &[u64] {
        &self.words
    }

    pub const fn is_allowed(&self, cpu: u32) -> bool {
        let idx = cpu as usize;
        if idx >= MAX_GUEST_CPUS {
            return false;
        }
        self.words[idx / 64] & (1u64 << (idx % 64)) != 0
    }

    pub fn count_allowed(&self) -> usize {
        self.words.iter().map(|w| w.count_ones() as usize).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.words.iter().all(|w| *w == 0)
    }

    pub fn intersect(&self, other: &Self) -> Self {
        let mut words = [0u64; AFFINITY_WORDS];
        for (i, slot) in words.iter_mut().enumerate() {
            *slot = self.words[i] & other.words[i];
        }
        Self { words }
    }

    pub fn first_allowed(&self, ncpu: usize) -> Option<u32> {
        let max = ncpu.min(MAX_GUEST_CPUS);
        (0..max as u32).find(|&cpu| self.is_allowed(cpu))
    }

    /// Parse a little-endian CPU bitmask from user bytes.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut words = [0u64; AFFINITY_WORDS];
        for (i, w) in words.iter_mut().enumerate() {
            let off = i * 8;
            if off >= bytes.len() {
                break;
            }
            let mut wb = [0u8; 8];
            let n = (bytes.len() - off).min(8);
            wb[..n].copy_from_slice(&bytes[off..off + n]);
            *w = u64::from_le_bytes(wb);
        }
        Self { words }
    }

    /// Write little-endian bytes to a destination buffer. Returns bytes written.
    pub fn write_bytes(&self, out: &mut [u8]) -> usize {
        affinity_write_bytes(&self.words, out)
    }
}

impl Default for CpuAffinity {
    fn default() -> Self {
        Self::all(MAX_GUEST_CPUS)
    }
}

/// Compute the kernel's expected cpumask size in bytes for a given cpu count.
#[inline]
pub const fn kernel_cpumask_bytes(ncpu: usize) -> usize {
    let n = if ncpu == 0 { 1 } else { ncpu };
    n.div_ceil(64) * 8
}

/// Validate the minimum carrier kernel mask size for sched_getaffinity.
/// sched_setaffinity accepts shorter masks and zero-extends missing bits.
#[inline]
pub const fn validate_getaffinity_size(size: usize, ncpu: usize) -> bool {
    size >= kernel_cpumask_bytes(ncpu)
}

/// Serialize an affinity word-mask into exactly `out_len` little-endian bytes.
pub fn affinity_to_bytes(mask: &[u64], out_len: usize) -> Vec<u8> {
    let mut buf = alloc::vec![0u8; out_len];
    affinity_write_bytes(mask, &mut buf);
    buf
}

/// Write an affinity word-mask into `out` as little-endian bytes.
pub fn affinity_write_bytes(mask: &[u64], out: &mut [u8]) -> usize {
    let out_len = out.len();
    for (i, word) in mask.iter().enumerate() {
        let off = i * 8;
        if off >= out_len {
            break;
        }
        let wb = word.to_le_bytes();
        let n = (out_len - off).min(8);
        out[off..off + n].copy_from_slice(&wb[..n]);
    }
    out_len
}

/// Parse a little-endian CPU bitmask from user bytes into `words` 64-bit words.
pub fn affinity_from_bytes(bytes: &[u8], words: usize) -> Vec<u64> {
    let mut mask = alloc::vec![0u64; words.max(1)];
    for (i, w) in mask.iter_mut().enumerate() {
        let off = i * 8;
        if off >= bytes.len() {
            break;
        }
        let mut wb = [0u8; 8];
        let n = (bytes.len() - off).min(8);
        wb[..n].copy_from_slice(&bytes[off..off + n]);
        *w = u64::from_le_bytes(wb);
    }
    mask
}

/// Intersect requested affinity with the online CPU set. Returns `None`
/// if the effective mask is empty.
pub fn compute_effective_affinity(
    requested: &CpuAffinity,
    online: &CpuAffinity,
) -> Option<CpuAffinity> {
    let effective = online.intersect(requested);
    if effective.is_empty() {
        None
    } else {
        Some(effective)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn test_kernel_cpumask_bytes() {
        assert_eq!(kernel_cpumask_bytes(0), 8);
        assert_eq!(kernel_cpumask_bytes(1), 8);
        assert_eq!(kernel_cpumask_bytes(64), 8);
        assert_eq!(kernel_cpumask_bytes(65), 16);
    }

    #[test]
    fn test_validate_getaffinity_size() {
        assert!(!validate_getaffinity_size(0, 4));
        assert!(!validate_getaffinity_size(7, 4));
        assert!(validate_getaffinity_size(8, 4));
        assert!(validate_getaffinity_size(128, 4));
    }

    #[test]
    fn test_affinity_bytes_round_trip() {
        let mask = [0x0123_4567_89ab_cdef_u64];
        let bytes = affinity_to_bytes(&mask, 8);
        assert_eq!(bytes, mask[0].to_le_bytes());
        let parsed = affinity_from_bytes(&bytes, 1);
        assert_eq!(parsed, mask);

        let aff = CpuAffinity::from_bytes(&bytes);
        assert_eq!(aff.words(), &mask);
        let mut out = [0u8; 8];
        assert_eq!(aff.write_bytes(&mut out), 8);
        assert_eq!(out, bytes.as_slice());
    }

    #[test]
    fn test_affinity_to_bytes_padding_and_truncation() {
        let mask = [!0u64; 2];
        let truncated = affinity_to_bytes(&mask, 8);
        assert_eq!(truncated.len(), 8);
        assert_eq!(truncated, vec![0xff; 8]);

        let padded = affinity_to_bytes(&[0x1], 16);
        assert_eq!(padded.len(), 16);
        assert_eq!(&padded[..8], &1u64.to_le_bytes());
        assert_eq!(&padded[8..], &[0u8; 8]);
    }

    #[test]
    fn test_compute_effective_affinity() {
        let requested = CpuAffinity::single(0);
        let effective = compute_effective_affinity(&requested, &CpuAffinity::all(4)).unwrap();
        assert_eq!(effective, requested);

        let out_of_range = CpuAffinity::single(5);
        assert_eq!(
            compute_effective_affinity(&out_of_range, &CpuAffinity::all(4)),
            None
        );

        let empty = CpuAffinity::from_words(&[0]);
        assert_eq!(
            compute_effective_affinity(&empty, &CpuAffinity::all(4)),
            None
        );
    }

    #[test]
    fn test_cpu_affinity_methods() {
        let all = CpuAffinity::all(4);
        assert_eq!(all.count_allowed(), 4);
        assert!(all.is_allowed(0));
        assert!(all.is_allowed(3));
        assert!(!all.is_allowed(4));
        assert_eq!(all.first_allowed(4), Some(0));

        let one = CpuAffinity::single(2);
        assert_eq!(one.count_allowed(), 1);
        assert!(!one.is_allowed(0));
        assert!(one.is_allowed(2));
        assert_eq!(one.first_allowed(4), Some(2));

        let intersection = all.intersect(&one);
        assert_eq!(intersection, one);
    }

    #[test]
    fn sparse_online_set_excludes_holes_and_high_cpus() {
        let online = CpuAffinity::from_words(&[0b1010]);
        let requested = CpuAffinity::from_words(&[0b1111 | (1 << 63)]);
        assert_eq!(
            compute_effective_affinity(&requested, &online),
            Some(online)
        );
        assert_eq!(
            compute_effective_affinity(&CpuAffinity::single(2), &online),
            None
        );
    }
}
