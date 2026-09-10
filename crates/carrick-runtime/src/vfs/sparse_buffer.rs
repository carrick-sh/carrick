use std::collections::BTreeMap;

/// A memory-efficient sparse byte buffer supporting large logical file sizes with
/// sparse allocation of written extents. Unwritten holes read back as zeros without
/// materializing physical host memory.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SparseBuffer {
    len: usize,
    chunks: BTreeMap<usize, Vec<u8>>,
}

impl SparseBuffer {
    #[must_use]
    pub fn new() -> Self {
        Self {
            len: 0,
            chunks: BTreeMap::new(),
        }
    }

    #[must_use]
    pub fn from_vec(data: Vec<u8>) -> Self {
        let len = data.len();
        let mut chunks = BTreeMap::new();
        if !data.is_empty() {
            chunks.insert(0, data);
        }
        Self { len, chunks }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Sum of physical bytes held by materialized chunks.
    #[must_use]
    pub fn allocated_bytes(&self) -> usize {
        self.chunks.values().map(Vec::len).sum()
    }

    /// Set the logical length of the sparse buffer, pruning any chunks beyond `new_len`.
    pub fn set_len(&mut self, new_len: usize) {
        self.len = new_len;
        self.prune_chunks(new_len);
    }

    /// Truncate the buffer to at most `new_len`.
    pub fn truncate(&mut self, new_len: usize) {
        if new_len < self.len {
            self.set_len(new_len);
        }
    }

    /// Clear all data and reset length to 0.
    pub fn clear(&mut self) {
        self.len = 0;
        self.chunks.clear();
    }

    fn prune_chunks(&mut self, bound: usize) {
        let keys_to_remove: Vec<usize> = self.chunks.range(bound..).map(|(&k, _)| k).collect();
        for k in keys_to_remove {
            self.chunks.remove(&k);
        }
        if let Some((&start, chunk)) = self.chunks.range_mut(..bound).next_back() {
            let keep = bound.saturating_sub(start);
            if keep < chunk.len() {
                chunk.truncate(keep);
            }
        }
    }

    /// Write bytes at `offset`, expanding logical length if necessary.
    pub fn write_range(&mut self, offset: usize, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        let end = match offset.checked_add(bytes.len()) {
            Some(e) => e,
            None => return,
        };
        if end > self.len {
            self.len = end;
        }

        // 1. Inspect predecessor chunk starting before `offset`
        if let Some((&pred_start, pred_chunk)) = self.chunks.range_mut(..offset).next_back() {
            let pred_end = pred_start.saturating_add(pred_chunk.len());
            if pred_end > offset {
                if pred_end > end {
                    // Predecessor spans across the entire write range: split into prefix + suffix
                    let suffix = pred_chunk[end - pred_start..].to_vec();
                    pred_chunk.truncate(offset - pred_start);
                    self.chunks.insert(end, suffix);
                } else {
                    // Predecessor tail is overwritten: truncate in place with zero cloning
                    pred_chunk.truncate(offset - pred_start);
                }
            }
        }

        // 2. Inspect chunks starting in `offset..end`
        let keys_in_range: Vec<usize> = self.chunks.range(offset..end).map(|(&k, _)| k).collect();
        for k in keys_in_range {
            if let Some(chunk) = self.chunks.remove(&k) {
                let chunk_end = k.saturating_add(chunk.len());
                if chunk_end > end {
                    let suffix = chunk[end - k..].to_vec();
                    self.chunks.insert(end, suffix);
                }
            }
        }

        self.chunks.insert(offset, bytes.to_vec());
    }

    /// Read a subrange from `offset` of length `length`. Unpopulated holes return zeros.
    #[must_use]
    pub fn read_range(&self, offset: usize, length: usize) -> Vec<u8> {
        if offset >= self.len || length == 0 {
            return Vec::new();
        }
        let take_len = length.min(self.len.saturating_sub(offset));
        let read_end = offset.saturating_add(take_len);
        let mut out = vec![0_u8; take_len];

        let pred = self.chunks.range(..offset).next_back();
        let pred_iter = pred
            .into_iter()
            .filter(|&(chunk_start, chunk)| chunk_start.saturating_add(chunk.len()) > offset);
        let inside_iter = self.chunks.range(offset..read_end);

        for (&chunk_start, chunk) in pred_iter.chain(inside_iter) {
            let chunk_end = chunk_start.saturating_add(chunk.len());
            let overlap_start = chunk_start.max(offset);
            let overlap_end = chunk_end.min(read_end);
            if overlap_end > overlap_start {
                let src_start = overlap_start - chunk_start;
                let src_end = overlap_end - chunk_start;
                let dst_start = overlap_start - offset;
                let dst_end = overlap_end - offset;
                out[dst_start..dst_end].copy_from_slice(&chunk[src_start..src_end]);
            }
        }
        out
    }

    /// Materialize the entire logical contents as a dense byte vector.
    #[must_use]
    pub fn to_vec(&self) -> Vec<u8> {
        self.read_range(0, self.len)
    }

    /// Append bytes to the end of the buffer.
    pub fn extend_from_slice(&mut self, bytes: &[u8]) {
        self.write_range(self.len, bytes);
    }
}

impl From<Vec<u8>> for SparseBuffer {
    fn from(data: Vec<u8>) -> Self {
        Self::from_vec(data)
    }
}

impl From<&[u8]> for SparseBuffer {
    fn from(data: &[u8]) -> Self {
        Self::from_vec(data.to_vec())
    }
}

impl PartialEq<[u8]> for SparseBuffer {
    fn eq(&self, other: &[u8]) -> bool {
        if self.len != other.len() {
            return false;
        }
        if self.chunks.is_empty() {
            return other.iter().all(|&b| b == 0);
        }
        let mut last_end = 0;
        for (&start, chunk) in &self.chunks {
            if start > last_end && !other[last_end..start].iter().all(|&b| b == 0) {
                return false;
            }
            let chunk_end = start.saturating_add(chunk.len());
            if other[start..chunk_end] != *chunk {
                return false;
            }
            last_end = chunk_end;
        }
        if self.len > last_end && !other[last_end..self.len].iter().all(|&b| b == 0) {
            return false;
        }
        true
    }
}

impl PartialEq<&[u8]> for SparseBuffer {
    fn eq(&self, other: &&[u8]) -> bool {
        self.eq(*other)
    }
}

impl<const N: usize> PartialEq<[u8; N]> for SparseBuffer {
    fn eq(&self, other: &[u8; N]) -> bool {
        self.eq(other.as_slice())
    }
}

impl<const N: usize> PartialEq<&[u8; N]> for SparseBuffer {
    fn eq(&self, other: &&[u8; N]) -> bool {
        self.eq(other.as_slice())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sparse_buffer_preserves_holes_and_bounded_allocation() {
        let mut buf = SparseBuffer::new();
        let sparse_size = 64 * 1024 * 1024 * 1024; // 64 GiB
        buf.set_len(sparse_size);

        assert_eq!(buf.len(), sparse_size);
        assert_eq!(buf.allocated_bytes(), 0);

        let p1 = [0xaa_u8; 4096];
        let p2 = [0xbb_u8; 4096];
        let p3 = [0xcc_u8; 4096];

        buf.write_range(0, &p1);
        buf.write_range(32 * 1024 * 1024 * 1024, &p2);
        buf.write_range(sparse_size - 4096, &p3);

        assert_eq!(buf.len(), sparse_size);
        assert_eq!(buf.allocated_bytes(), 3 * 4096);

        // First page read
        assert_eq!(buf.read_range(0, 4096), p1);
        // Hole read returns zeros
        assert_eq!(buf.read_range(4096, 4096), vec![0_u8; 4096]);
        assert_eq!(buf.read_range(1024 * 1024, 4096), vec![0_u8; 4096]);
        // Middle page read
        assert_eq!(buf.read_range(32 * 1024 * 1024 * 1024, 4096), p2);
        // Last page read
        assert_eq!(buf.read_range(sparse_size - 4096, 4096), p3);
        // Straddling read across hole and data
        let straddle = buf.read_range(32 * 1024 * 1024 * 1024 - 2, 4);
        assert_eq!(straddle, vec![0, 0, 0xbb, 0xbb]);

        // Truncate drops last page
        buf.truncate(32 * 1024 * 1024 * 1024 + 4096);
        assert_eq!(buf.len(), 32 * 1024 * 1024 * 1024 + 4096);
        assert_eq!(buf.allocated_bytes(), 2 * 4096);
        assert!(buf.read_range(sparse_size - 4096, 4096).is_empty());
    }

    #[test]
    fn sequential_page_writes_and_distant_reads_perform_bounded_work() {
        let mut buf = SparseBuffer::new();
        let page_count = 2000;
        let page_size = 4096;
        let page = [0x5a_u8; 4096];

        // 2000 sequential page writes: must be fast (bounded O(log N) per write)
        for i in 0..page_count {
            buf.write_range(i * page_size * 2, &page); // leave a 4096-byte hole between each page
        }

        assert_eq!(buf.len(), (page_count * 2 - 1) * page_size);
        assert_eq!(buf.allocated_bytes(), page_count * page_size);

        // Read last page: must find predecessor in O(log N) without scanning 0..N
        let last_read = buf.read_range((page_count - 1) * page_size * 2, page_size);
        assert_eq!(last_read, page);

        // Read hole near end: must return zeros
        let hole_read = buf.read_range((page_count - 1) * page_size * 2 - page_size, page_size);
        assert_eq!(hole_read, vec![0_u8; page_size]);
    }

    #[test]
    fn chunk_overwrite_split_and_middle_mutation() {
        let mut buf = SparseBuffer::from_vec(vec![0x11; 100]);
        // Overwrite bytes 40..60 with 0x22
        buf.write_range(40, &[0x22; 20]);

        assert_eq!(buf.len(), 100);
        assert_eq!(buf.read_range(0, 40), vec![0x11; 40]);
        assert_eq!(buf.read_range(40, 20), vec![0x22; 20]);
        assert_eq!(buf.read_range(60, 40), vec![0x11; 40]);

        // Overwrite bytes 10..90 with 0x33 spanning multiple chunks
        buf.write_range(10, &[0x33; 80]);
        assert_eq!(buf.len(), 100);
        assert_eq!(buf.read_range(0, 10), vec![0x11; 10]);
        assert_eq!(buf.read_range(10, 80), vec![0x33; 80]);
        assert_eq!(buf.read_range(90, 10), vec![0x11; 10]);
    }

    #[test]
    fn partial_eq_without_dense_allocation() {
        let mut buf = SparseBuffer::new();
        buf.set_len(10);
        buf.write_range(2, &[0xaa, 0xbb]);
        buf.write_range(6, &[0xcc]);

        let reference = vec![0_u8, 0, 0xaa, 0xbb, 0, 0, 0xcc, 0, 0, 0];
        assert_eq!(buf, reference.as_slice());

        let mut mismatched = reference.clone();
        mismatched[0] = 1; // non-zero in hole
        assert_ne!(buf, mismatched.as_slice());
    }

    #[test]
    fn bounded_traversal_and_sparse_chunk_accounting() {
        let mut buf = SparseBuffer::new();
        const N: usize = 5000;
        const PAGE: usize = 4096;
        let data = [0x7f_u8; PAGE];

        // Insert N non-contiguous pages
        for i in 0..N {
            buf.write_range(i * 2 * PAGE, &data);
        }

        assert_eq!(buf.len(), (2 * N - 1) * PAGE);
        assert_eq!(buf.allocated_bytes(), N * PAGE);

        // Subrange read deep in the buffer (chunk index 4500)
        let offset = 4500 * 2 * PAGE;
        let read = buf.read_range(offset, PAGE);
        assert_eq!(read, data);

        // Read across a hole between chunk 4500 and 4501
        let hole_offset = offset + PAGE;
        let hole_read = buf.read_range(hole_offset, PAGE);
        assert_eq!(hole_read, vec![0_u8; PAGE]);

        // Straddled read across chunk 4500, hole, and chunk 4501
        let straddle_read = buf.read_range(offset + PAGE - 2, PAGE + 4);
        let mut expected = vec![0x7f_u8; 2];
        expected.resize(PAGE + 2, 0);
        expected.extend_from_slice(&[0x7f, 0x7f]);
        assert_eq!(straddle_read, expected);

        // Overwrite middle of chunk 4500 with split
        let overwrite = [0x33_u8; 100];
        buf.write_range(offset + 100, &overwrite);
        // Original chunk is split into prefix (100 bytes) + new chunk (100 bytes) + suffix (PAGE - 200 bytes)
        // Total allocated bytes remains identical
        assert_eq!(buf.allocated_bytes(), N * PAGE);
        assert_eq!(buf.read_range(offset + 100, 100), overwrite);
        assert_eq!(buf.read_range(offset, 100), vec![0x7f_u8; 100]);
        assert_eq!(
            buf.read_range(offset + 200, PAGE - 200),
            vec![0x7f_u8; PAGE - 200]
        );
    }
}
