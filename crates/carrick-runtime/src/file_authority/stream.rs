use std::collections::VecDeque;

use super::{AuthorityError, PipeCapacity, PipeEnd};

#[derive(Debug)]
pub(super) struct PipeStreamState {
    bytes: VecDeque<u8>,
    capacity: PipeCapacity,
    reader_descriptions: u64,
    writer_descriptions: u64,
}

impl PipeStreamState {
    pub(super) fn new(capacity: PipeCapacity) -> Self {
        Self {
            bytes: VecDeque::new(),
            capacity,
            reader_descriptions: 1,
            writer_descriptions: 1,
        }
    }

    pub(super) const fn capacity(&self) -> PipeCapacity {
        self.capacity
    }

    pub(super) fn set_capacity(&mut self, capacity: PipeCapacity) -> Result<(), AuthorityError> {
        if usize::try_from(capacity.raw()).map_or(true, |capacity| capacity < self.bytes.len()) {
            return Err(AuthorityError::InvalidPipeCapacity);
        }
        self.capacity = capacity;
        Ok(())
    }

    pub(super) fn release(&mut self, end: PipeEnd) {
        let refs = match end {
            PipeEnd::Reader => &mut self.reader_descriptions,
            PipeEnd::Writer => &mut self.writer_descriptions,
        };
        *refs = refs.checked_sub(1).unwrap_or_else(|| {
            tracing::error!("pipe-end reference underflow");
            std::process::abort();
        });
    }

    pub(super) const fn is_unreferenced(&self) -> bool {
        self.reader_descriptions == 0 && self.writer_descriptions == 0
    }

    pub(super) fn readable_bytes(&self) -> u64 {
        u64::try_from(self.bytes.len()).unwrap_or(u64::MAX)
    }

    pub(super) fn write(&mut self, bytes: &[u8]) -> Result<usize, AuthorityError> {
        if self.reader_descriptions == 0 {
            return Err(AuthorityError::BrokenPipe);
        }
        let capacity = usize::try_from(self.capacity.raw()).unwrap_or(usize::MAX);
        let available = capacity.saturating_sub(self.bytes.len());
        if available == 0 && !bytes.is_empty() {
            return Err(AuthorityError::WouldBlock);
        }
        let written = available.min(bytes.len());
        self.bytes.extend(bytes[..written].iter().copied());
        Ok(written)
    }

    pub(super) fn read(&mut self, maximum: usize) -> Result<Vec<u8>, AuthorityError> {
        if self.bytes.is_empty() && self.writer_descriptions != 0 {
            return Err(AuthorityError::WouldBlock);
        }
        let count = maximum.min(self.bytes.len());
        Ok(self.bytes.drain(..count).collect())
    }

    pub(super) fn readiness(&self, end: PipeEnd) -> carrick_abi::LinuxEpollEvents {
        use carrick_abi::LinuxEpollEvents as Events;
        match end {
            PipeEnd::Reader => {
                let mut ready = Events::empty();
                if !self.bytes.is_empty() {
                    ready |= Events::IN;
                }
                if self.writer_descriptions == 0 {
                    ready |= Events::HUP;
                }
                ready
            }
            PipeEnd::Writer => {
                let mut ready = Events::empty();
                if self.reader_descriptions == 0 {
                    ready |= Events::ERR;
                } else if self.bytes.len()
                    < usize::try_from(self.capacity.raw()).unwrap_or(usize::MAX)
                {
                    ready |= Events::OUT;
                }
                ready
            }
        }
    }
}
