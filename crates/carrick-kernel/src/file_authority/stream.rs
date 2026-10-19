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
            .map_err(map_pipe_error)?;
        Ok(Self {
            record: PipeRecord::new(
                capacity,
                capacity / carrick_pipe_core::PIPE_BUF,
                carrick_pipe_core::PIPE_BUF,
                capacity,
            )
            .map_err(map_pipe_error)?,
            bytes: vec![0; capacity].into_boxed_slice(),
            pages: vec![Page::default(); capacity / carrick_pipe_core::PIPE_BUF].into_boxed_slice(),
        })
    }

    fn pipe(&mut self) -> Result<Pipe<'_, &mut PipeRecord>, AuthorityError> {
        Pipe::attach(&mut self.record, &mut self.bytes, &mut self.pages).map_err(map_pipe_error)
    }

    pub(super) fn capacity(&self) -> Result<PipeCapacity, AuthorityError> {
        PipeCapacity::bounded(self.record.capacity() as u32)
    }

    pub(super) fn set_capacity(&mut self, capacity: PipeCapacity) -> Result<(), AuthorityError> {
        let requested = capacity.raw() as usize;
        let rounded = Pipe::rounded_capacity(carrick_pipe_core::PIPE_BUF, requested)
            .map_err(map_pipe_error)?;
        if rounded > self.bytes.len() {
            let mut bytes = vec![0; rounded].into_boxed_slice();
            let mut pages =
                vec![Page::default(); rounded / carrick_pipe_core::PIPE_BUF].into_boxed_slice();
            self.pipe()?
                .replace_storage(&mut bytes, &mut pages)
                .map_err(map_pipe_error)?;
            self.bytes = bytes;
            self.pages = pages;
        }
        self.pipe()?
            .set_capacity(requested, PipeCapacity::MAX as usize)
            .result
            .map(|_| ())
            .map_err(map_pipe_error)
    }

    pub(super) fn release(&mut self, end: PipeEnd) {
        let result = self
            .pipe()
            .and_then(|mut pipe| pipe.release(core_end(end)).result.map_err(map_pipe_error));
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
        self.pipe()?.try_write(bytes).result.map_err(map_pipe_error)
    }

    pub(super) fn read(&mut self, maximum: usize) -> Result<Vec<u8>, AuthorityError> {
        let mut bytes = vec![0; maximum];
        let count = self
            .pipe()?
            .try_read(&mut bytes)
            .result
            .map_err(map_pipe_error)?;
        bytes.truncate(count);
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

fn map_pipe_error(error: Error) -> AuthorityError {
    match error {
        Error::WouldBlock(_) => AuthorityError::WouldBlock,
        Error::BrokenPipe => AuthorityError::BrokenPipe,
        Error::Busy | Error::Invalid | Error::Permission | Error::Storage => {
            AuthorityError::InvalidPipeCapacity
        }
        Error::Fault
        | Error::Refcount
        | Error::Corrupt
        | Error::RevisionExhausted
        | Error::RevisionUnavailable => AuthorityError::InvalidPipeCapacity,
    }
}
