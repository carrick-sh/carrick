use carrick_fatal::carrick_fatal;
use carrick_pipe_core::{End, Error, Page, Pipe, PipeRecord};

use super::{AuthorityError, PipeCapacity, PipeEnd};

#[derive(Debug)]
pub(super) struct PipeStreamState {
    record: PipeRecord,
    bytes: Box<[u8]>,
    pages: Box<[Page]>,
}

impl PipeStreamState {
    pub(super) fn new(capacity: PipeCapacity) -> Result<Self, AuthorityError> {
        let capacity = Pipe::rounded_capacity(carrick_pipe_core::PIPE_BUF, capacity.raw() as usize)
            .map_err(map_capacity_error)?;
        Ok(Self {
            record: PipeRecord::new(
                capacity,
                capacity / carrick_pipe_core::PIPE_BUF,
                carrick_pipe_core::PIPE_BUF,
                capacity,
            )
            .map_err(map_capacity_error)?,
            bytes: vec![0; capacity].into_boxed_slice(),
            pages: vec![Page::default(); capacity / carrick_pipe_core::PIPE_BUF].into_boxed_slice(),
        })
    }

    fn pipe(&mut self) -> Result<Pipe<'_, &mut PipeRecord>, AuthorityError> {
        Ok(
            Pipe::attach(&mut self.record, &mut self.bytes, &mut self.pages)
                .unwrap_or_else(|error| abort_integrity_error(error)),
        )
    }

    pub(super) fn capacity(&self) -> PipeCapacity {
        PipeCapacity::bounded(self.record.capacity() as u32).unwrap_or_else(|_| {
            super::core::abort_fatal(super::AuthorityFatal::InvariantViolation(
                "pipe core exposed an out-of-domain capacity",
            ))
        })
    }

    pub(super) fn set_capacity(&mut self, capacity: PipeCapacity) -> Result<(), AuthorityError> {
        let requested = capacity.raw() as usize;
        let rounded = Pipe::rounded_capacity(carrick_pipe_core::PIPE_BUF, requested)
            .map_err(map_capacity_error)?;
        if rounded > self.bytes.len() {
            let mut bytes = vec![0; rounded].into_boxed_slice();
            let mut pages =
                vec![Page::default(); rounded / carrick_pipe_core::PIPE_BUF].into_boxed_slice();
            self.pipe()?
                .replace_storage(&mut bytes, &mut pages)
                .unwrap_or_else(|error| abort_integrity_error(error));
            self.bytes = bytes;
            self.pages = pages;
        }
        self.pipe()?
            .set_capacity(requested, PipeCapacity::MAX as usize)
            .result
            .map(|_| ())
            .map_err(map_capacity_error)
    }

    pub(super) fn release(&mut self, end: PipeEnd) {
        let result = self
            .pipe()
            .and_then(|mut pipe| pipe.release(core_end(end)).result.map_err(map_io_error));
        result.unwrap_or_else(|_| {
            tracing::error!("pipe-end reference underflow");
            carrick_fatal!(
                "file_authority::pipe_stream",
                "pipe-end reference underflow"
            );
        });
    }

    pub(super) fn is_unreferenced(&self) -> bool {
        self.record.references(End::Reader) == 0 && self.record.references(End::Writer) == 0
    }

    pub(super) fn readable_bytes(&self) -> u64 {
        self.record.unread_bytes() as u64
    }

    pub(super) fn write(&mut self, bytes: &[u8]) -> Result<usize, AuthorityError> {
        self.pipe()?.try_write(bytes).result.map_err(map_io_error)
    }

    pub(super) fn read(&mut self, maximum: usize) -> Result<Vec<u8>, AuthorityError> {
        let readable = maximum.min(self.record.unread_bytes());
        let mut bytes = Vec::with_capacity(readable);
        let count = self
            .pipe()?
            .read_with(maximum, |chunk| {
                bytes.extend_from_slice(chunk);
                chunk.len()
            })
            .result
            .map_err(map_io_error)?;
        debug_assert_eq!(count, bytes.len());
        Ok(bytes)
    }

    pub(super) fn readiness(&self, end: PipeEnd) -> carrick_abi::LinuxEpollEvents {
        use carrick_abi::LinuxEpollEvents as Events;
        let readiness = self.record.readiness(core_end(end));
        match end {
            PipeEnd::Reader => {
                let mut ready = Events::empty();
                if readiness.readable {
                    ready |= Events::IN;
                }
                if readiness.hup {
                    ready |= Events::HUP;
                }
                ready
            }
            PipeEnd::Writer => {
                let mut ready = Events::empty();
                if readiness.err {
                    ready |= Events::ERR;
                }
                if readiness.writable {
                    ready |= Events::OUT;
                }
                ready
            }
        }
    }
}

const fn core_end(end: PipeEnd) -> End {
    match end {
        PipeEnd::Reader => End::Reader,
        PipeEnd::Writer => End::Writer,
    }
}

fn map_capacity_error(error: Error) -> AuthorityError {
    match error {
        Error::Busy | Error::Invalid | Error::Permission | Error::Storage => {
            AuthorityError::InvalidPipeCapacity
        }
        other => abort_integrity_error(other),
    }
}

fn map_io_error(error: Error) -> AuthorityError {
    match error {
        Error::WouldBlock(_) => AuthorityError::WouldBlock,
        Error::BrokenPipe => AuthorityError::BrokenPipe,
        other => abort_integrity_error(other),
    }
}

fn abort_integrity_error(error: Error) -> ! {
    tracing::error!(?error, "pipe core integrity failure");
    super::core::abort_fatal(super::AuthorityFatal::InvariantViolation(
        "pipe core integrity failure",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn huge_read_allocates_only_the_readable_bytes() {
        let mut stream = PipeStreamState::new(PipeCapacity::bounded(4096).expect("capacity"))
            .expect("pipe stream");
        assert_eq!(stream.write(b"abc"), Ok(3));

        let bytes = stream.read(usize::MAX).expect("read");

        assert_eq!(bytes, b"abc");
        assert!(bytes.capacity() <= 3, "capacity was {}", bytes.capacity());
    }
}
