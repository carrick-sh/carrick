//! Unpublished description custody, including resources not yet wrapped in an
//! OFD. Admission may stop at a store-growth request without losing the prefix
//! already admitted. The venue owns growth and physical release.

use crate::{Authority, Description, Error, Fd, LockWait, OfdPin, PIN, SlotBacking, TableId};

#[derive(Debug)]
enum State {
    Backing(Description),
    Pinned(OfdPin),
    Released,
}

/// An owned preparation, suitable for retaining across a canonical growth
/// request. No table lock or borrowed storage survives an admission attempt.
/// On abort, drain [`Self::release_next`] and release each returned backing.
/// On publication, drain it too: installed descriptor references then keep the
/// backing alive. This follows OfdPin's explicit settlement protocol.
#[derive(Debug)]
#[must_use = "retain preparation until publication or drain all physical releases"]
pub struct PreparedDescriptions<const N: usize> {
    authority: Option<u64>,
    states: [State; N],
    published: bool,
}

impl<const N: usize> PreparedDescriptions<N> {
    /// Takes custody of every backing immediately, before OFD admission.
    pub fn new(descriptions: [Description; N]) -> Self {
        Self {
            authority: None,
            states: descriptions.map(State::Backing),
            published: false,
        }
    }

    /// Admit the remaining descriptions. NeedsOfds leaves all custody here;
    /// the venue must request its canonical store growth before retrying.
    pub fn admit<B: SlotBacking, W: LockWait, const T: usize>(
        &mut self,
        authority: &Authority<'_, B, W, T>,
    ) -> Result<(), Error> {
        if self.published {
            return Err(Error::StalePin);
        }
        self.authenticate(authority)?;
        for state in &mut self.states {
            match state {
                State::Backing(description) => {
                    *state = State::Pinned(authority.create_pinned(*description)?);
                }
                State::Pinned(_) => {}
                // A settled preparation cannot be admitted a second time.
                State::Released => return Err(Error::StalePin),
            }
        }
        Ok(())
    }

    fn authenticate<B: SlotBacking, W: LockWait, const T: usize>(
        &mut self,
        authority: &Authority<'_, B, W, T>,
    ) -> Result<(), Error> {
        let identity = authority.identity()?;
        match self.authority {
            Some(expected) if expected != identity => Err(Error::StalePin),
            _ => {
                self.authority = Some(identity);
                Ok(())
            }
        }
    }

    /// Release preparation holds outside any table transaction. Returns the
    /// next backing whose final hold ended, including a backing never admitted
    /// to an OFD. None means settlement is complete. Refusal retains custody.
    pub fn release_next<B: SlotBacking, W: LockWait, const T: usize>(
        &mut self,
        authority: &Authority<'_, B, W, T>,
    ) -> Result<Option<Description>, Error> {
        self.authenticate(authority)?;
        for state in &mut self.states {
            let released = match state {
                State::Backing(description) => Some(*description),
                State::Pinned(pin) => {
                    authority.check_pin(pin)?;
                    authority.drop_hold(pin.key.index, PIN)?
                }
                State::Released => continue,
            };
            *state = State::Released;
            if released.is_some() {
                return Ok(released);
            }
        }
        Ok(None)
    }
}

impl PreparedDescriptions<2> {
    /// Publish the prepared pair through the single fd-core transaction. A
    /// refusal publishes neither slot and leaves both pins in this owner.
    /// Success consumes publication authority: subsequent attempts refuse,
    /// even in another table. The remaining pins are settlement custody only.
    /// Provision slots and secure final output before entering this method;
    /// no guest copy or provisioning runs under its table lock.
    pub fn install_pair<B: SlotBacking, W: LockWait, const T: usize>(
        &mut self,
        authority: &Authority<'_, B, W, T>,
        table: TableId,
        min: Fd,
        cloexec: bool,
    ) -> Result<[Fd; 2], Error> {
        if self.published {
            return Err(Error::StalePin);
        }
        let [State::Pinned(reader), State::Pinned(writer)] = &self.states else {
            return Err(Error::StalePin);
        };
        let pair = authority
            .transaction(table)?
            .install_pair(min, [reader, writer], cloexec)?;
        self.published = true;
        Ok(pair)
    }

    /// Transfer a fully admitted pair to another explicit description owner.
    /// Refusal retains the unchanged preparation, including raw backings.
    pub fn take_pair(&mut self) -> Result<[OfdPin; 2], Error> {
        match core::mem::replace(&mut self.states, [State::Released, State::Released]) {
            [State::Pinned(reader), State::Pinned(writer)] => Ok([reader, writer]),
            states => {
                self.states = states;
                Err(Error::StalePin)
            }
        }
    }
}
