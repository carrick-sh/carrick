//! Task-owned execution slices, independent of host processes and wall waits.
use super::TaskRusage;
use carrick_guest_arch::{CounterFrequency, CounterTick};
use core::time::Duration;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CpuMode {
    User,
    System,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CpuSample {
    pub tick: CounterTick,
    pub frequency: CounterFrequency,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CpuAccountingError {
    AlreadyRunning,
    NotRunning,
    ClockChanged,
    Overflow,
}

#[derive(Debug, Default)]
pub struct TaskCpuAccounting {
    usage: TaskRusage,
    running: Option<(CpuSample, CpuMode)>,
}
impl TaskCpuAccounting {
    pub fn usage(&self) -> TaskRusage {
        self.usage
    }
    pub fn is_running(&self) -> bool {
        self.running.is_some()
    }
    pub fn running_mode(&self) -> Option<CpuMode> {
        self.running.map(|(_, mode)| mode)
    }
    pub fn resume(&mut self, sample: CpuSample, mode: CpuMode) -> Result<(), CpuAccountingError> {
        if self.running.is_some() {
            return Err(CpuAccountingError::AlreadyRunning);
        }
        self.running = Some((sample, mode));
        Ok(())
    }
    pub fn stop(&mut self, sample: CpuSample) -> Result<(), CpuAccountingError> {
        let (start, mode) = self.running.ok_or(CpuAccountingError::NotRunning)?;
        if sample.frequency != start.frequency {
            return Err(CpuAccountingError::ClockChanged);
        }
        let ticks = sample
            .tick
            .raw()
            .checked_sub(start.tick.raw())
            .ok_or(CpuAccountingError::ClockChanged)?;
        let nanos = u128::from(ticks) * 1_000_000_000 / u128::from(sample.frequency.raw().get());
        let delta =
            Duration::from_nanos(u64::try_from(nanos).map_err(|_| CpuAccountingError::Overflow)?);
        let total = match mode {
            CpuMode::User => &mut self.usage.user_time,
            CpuMode::System => &mut self.usage.system_time,
        };
        *total = total
            .checked_add(delta)
            .ok_or(CpuAccountingError::Overflow)?;
        self.running = None;
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use core::num::NonZeroU64;
    fn sample(tick: u64) -> CpuSample {
        CpuSample {
            tick: CounterTick::new(tick),
            frequency: CounterFrequency::new(NonZeroU64::new(1_000_000).unwrap()),
        }
    }
    #[test]
    fn owned_slices_exclude_parked_time_and_split_user_system() {
        let mut task = TaskCpuAccounting::default();
        task.resume(sample(10), CpuMode::User).unwrap();
        assert_eq!(
            task.resume(sample(11), CpuMode::User),
            Err(CpuAccountingError::AlreadyRunning)
        );
        task.stop(sample(17)).unwrap();
        task.resume(sample(10_000), CpuMode::System).unwrap();
        task.stop(sample(10_003)).unwrap();
        assert_eq!(
            task.usage(),
            TaskRusage {
                user_time: Duration::from_micros(7),
                system_time: Duration::from_micros(3)
            }
        );
        assert_eq!(
            task.stop(sample(20_000)),
            Err(CpuAccountingError::NotRunning)
        );
    }
    #[test]
    fn refused_clock_change_preserves_the_owned_slice() {
        let mut task = TaskCpuAccounting::default();
        task.resume(sample(20), CpuMode::User).unwrap();
        assert_eq!(task.stop(sample(19)), Err(CpuAccountingError::ClockChanged));
        assert!(task.is_running());
        assert_eq!(task.usage(), TaskRusage::default());
        task.stop(sample(21)).unwrap();
        assert_eq!(task.usage().user_time, Duration::from_micros(1));
    }
}
