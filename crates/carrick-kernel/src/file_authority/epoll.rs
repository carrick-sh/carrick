use std::collections::BTreeMap;

use carrick_abi::LinuxEpollEvents;

use super::{
    EpollEventLimit, EpollInterestKey, EpollReadyEvent, EpollRegistration, InterestGeneration,
};

#[derive(Clone, Copy, Debug)]
pub(super) struct ReadinessSnapshot {
    pub(super) ready: LinuxEpollEvents,
    pub(super) read_available: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct EpollInterestState {
    pub(super) registration: EpollRegistration,
    pub(super) generation: InterestGeneration,
    pub(super) last_ready: LinuxEpollEvents,
    pub(super) last_read_available: u64,
    pub(super) write_backpressured: bool,
    pub(super) armed: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(super) struct EpollState {
    interests: BTreeMap<EpollInterestKey, EpollInterestState>,
}

impl EpollState {
    pub(super) fn len(&self) -> usize {
        self.interests.len()
    }

    pub(super) fn contains(&self, key: EpollInterestKey) -> bool {
        self.interests.contains_key(&key)
    }

    pub(super) fn interest(&self, key: EpollInterestKey) -> Option<&EpollInterestState> {
        self.interests.get(&key)
    }

    pub(super) fn target_descriptions(
        &self,
    ) -> impl Iterator<Item = super::FileDescriptionId> + '_ {
        self.interests.keys().map(|key| key.target_description)
    }

    pub(super) fn keys(&self) -> impl Iterator<Item = EpollInterestKey> + '_ {
        self.interests.keys().copied()
    }

    pub(super) fn add(
        &mut self,
        key: EpollInterestKey,
        registration: EpollRegistration,
        generation: InterestGeneration,
    ) {
        self.interests.insert(
            key,
            EpollInterestState {
                registration,
                generation,
                last_ready: LinuxEpollEvents::empty(),
                last_read_available: 0,
                write_backpressured: false,
                armed: true,
            },
        );
    }

    pub(super) fn modify(
        &mut self,
        key: EpollInterestKey,
        registration: EpollRegistration,
    ) -> Option<InterestGeneration> {
        let state = self.interests.get_mut(&key)?;
        state.registration = registration;
        state.last_ready = LinuxEpollEvents::empty();
        state.last_read_available = 0;
        state.write_backpressured = false;
        state.armed = true;
        Some(state.generation)
    }

    pub(super) fn delete(&mut self, key: EpollInterestKey) -> Option<EpollInterestState> {
        self.interests.remove(&key)
    }

    pub(super) fn acknowledge_io(
        &mut self,
        target: super::FileDescriptionId,
        consumed: LinuxEpollEvents,
        read_available: u64,
        write_backpressured: bool,
    ) -> bool {
        let mut changed = false;
        for (key, state) in &mut self.interests {
            if key.target_description != target {
                continue;
            }
            state.last_ready.remove(consumed);
            state.last_read_available = read_available;
            state.write_backpressured |= write_backpressured;
            changed = true;
        }
        changed
    }

    pub(super) fn collect(
        &mut self,
        readiness: &BTreeMap<super::FileDescriptionId, ReadinessSnapshot>,
        maximum: EpollEventLimit,
    ) -> Vec<EpollReadyEvent> {
        let mut events = Vec::new();
        for (key, state) in &mut self.interests {
            if events.len() >= usize::from(maximum.raw()) {
                break;
            }
            if !state.armed {
                continue;
            }
            let observed =
                readiness
                    .get(&key.target_description)
                    .copied()
                    .unwrap_or(ReadinessSnapshot {
                        ready: LinuxEpollEvents::empty(),
                        read_available: 0,
                    });
            let requested = state.registration.events;
            let mut readiness_mask = requested;
            readiness_mask.remove(
                LinuxEpollEvents::ET
                    | LinuxEpollEvents::ONESHOT
                    | LinuxEpollEvents::EXCLUSIVE
                    | LinuxEpollEvents::WAKEUP,
            );
            let always = LinuxEpollEvents::ERR | LinuxEpollEvents::HUP;
            let raw = observed.ready & (readiness_mask | always);
            let deliver = if requested.contains(LinuxEpollEvents::ET) {
                let read_bits = LinuxEpollEvents::IN
                    | LinuxEpollEvents::PRI
                    | LinuxEpollEvents::RDHUP
                    | LinuxEpollEvents::HUP
                    | LinuxEpollEvents::ERR;
                let growth = if observed.read_available > state.last_read_available {
                    raw & read_bits
                } else {
                    LinuxEpollEvents::empty()
                };
                let mut edge = (raw & !state.last_ready) | growth;
                if state.write_backpressured {
                    edge |= raw & LinuxEpollEvents::OUT;
                }
                edge
            } else {
                raw
            };
            state.last_ready = raw;
            state.last_read_available = observed.read_available;
            if deliver.contains(LinuxEpollEvents::OUT) {
                state.write_backpressured = false;
            }
            if deliver.is_empty() {
                continue;
            }
            if requested.contains(LinuxEpollEvents::ONESHOT) {
                state.armed = false;
            }
            events.push(EpollReadyEvent {
                events: deliver,
                data: state.registration.data,
            });
        }
        events
    }
}
