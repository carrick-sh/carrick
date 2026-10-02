//! Exact-process runtime capacity leased before an EL1 thread can be born.

use std::any::Any;
use std::fmt;

use super::objects::{TaskKey, ThreadKey};

/// Installed by the execution lane for one exact process, never the carrier.
pub trait ThreadBirthAdoptionFactory: fmt::Debug + Send + Sync {
    fn executable_births(&self) -> bool {
        false
    }
    fn adopt_first_host_entry(
        &self,
        _context: &super::KernelContext,
        _reservation: ThreadBirthAdoptionReservation,
        _frame: &carrick_el1_abi::ThreadCtx,
    ) -> Result<(), String> {
        Err("execution lane has no born-thread adoption binding".into())
    }
    fn owner(&self) -> TaskKey;
    fn reserve(&self, thread: ThreadKey) -> Option<ThreadBirthAdoptionReservation>;
}

/// Unique custody of the runtime state needed at a born thread's first host
/// entry. Dropping an unconsumed reservation releases that capacity.
pub struct ThreadBirthAdoptionReservation {
    owner: TaskKey,
    thread: ThreadKey,
    payload: Box<dyn Any + Send>,
}

impl fmt::Debug for ThreadBirthAdoptionReservation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ThreadBirthAdoptionReservation")
            .field("owner", &self.owner)
            .field("thread", &self.thread)
            .finish_non_exhaustive()
    }
}

impl ThreadBirthAdoptionReservation {
    pub fn new<T: Any + Send>(owner: TaskKey, thread: ThreadKey, payload: T) -> Self {
        Self {
            owner,
            thread,
            payload: Box::new(payload),
        }
    }

    pub const fn owner(&self) -> TaskKey {
        self.owner
    }
    pub const fn thread(&self) -> ThreadKey {
        self.thread
    }

    pub fn consume<T: Any + Send>(self) -> Result<T, Self> {
        let Self {
            owner,
            thread,
            payload,
        } = self;
        match payload.downcast::<T>() {
            Ok(payload) => Ok(*payload),
            Err(payload) => Err(Self {
                owner,
                thread,
                payload,
            }),
        }
    }
}
