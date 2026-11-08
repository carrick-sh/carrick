use super::*;
use alloc::vec;
use core::cell::Cell;

#[derive(Clone, Copy)]
struct Mapping {
    start: u64,
    end: u64,
    class: Class,
    droppable: bool,
}
impl Segment for Mapping {
    fn range(&self) -> Range {
        Range {
            start: GuestVa::new(self.start),
            end: GuestVa::new(self.end),
        }
    }
    fn class(&self) -> Class {
        self.class
    }
    fn droppable(&self) -> bool {
        self.droppable
    }
}
struct Maps {
    segments: Vec<Mapping>,
    locked: bool,
    guard: Result<(), LinuxErrno>,
    checks: Cell<usize>,
    snapshots: Cell<usize>,
}
impl Maps {
    fn new(segments: Vec<Mapping>) -> Self {
        Self {
            segments,
            locked: false,
            guard: Ok(()),
            checks: Cell::new(0),
            snapshots: Cell::new(0),
        }
    }
    fn plan(&self, start: u64, len: u64, advice: Advice) -> Result<Plan<Mapping>, LinuxErrno> {
        plan(
            self,
            GuestVa::new(start),
            GuestLen::new(len),
            advice,
            GuestLen::new(4096),
        )
    }
    fn assert_unobserved(&self) {
        assert_eq!(self.checks.get(), 0);
        assert_eq!(self.snapshots.get(), 0);
    }
}
impl Coverage for Maps {
    type Segment = Mapping;
    fn check_range(&self, _: Range) -> Result<(), LinuxErrno> {
        self.checks.set(self.checks.get() + 1);
        self.guard
    }
    fn snapshot(&self, range: Range) -> Snapshot<Mapping> {
        self.snapshots.set(self.snapshots.get() + 1);
        Snapshot::new(range, self.segments.clone(), self.locked)
    }
}
fn mapping(start: u64, end: u64, class: Class) -> Mapping {
    Mapping {
        start,
        end,
        class,
        droppable: false,
    }
}
fn error(result: Result<Plan<Mapping>, LinuxErrno>) -> LinuxErrno {
    match result {
        Err(errno) => errno,
        Ok(_) => panic!("unexpected executable plan"),
    }
}

// madvise(2) requires page alignment and valid advice. Like the old host
// handler, these checks win even for length zero; coverage must not be queried.
#[test]
fn zero_length_follows_alignment_and_advice_validation() {
    let maps = Maps::new(vec![]);
    assert_eq!(error(maps.plan(0x1001, 0, Advice::DontNeed)), LINUX_EINVAL);
    assert_eq!(
        error(maps.plan(0x1000, 0, Advice::Unsupported)),
        LINUX_EINVAL
    );
    let plan = maps.plan(0x1000, 0, Advice::DontNeed).unwrap();
    assert!(plan.steps.is_empty());
    assert_eq!(plan.result, Ok(()));
    maps.assert_unobserved();
}

#[test]
fn misaligned_and_unknown_nonempty_requests_are_einval() {
    let maps = Maps::new(vec![]);
    assert_eq!(error(maps.plan(1, 4096, Advice::DontNeed)), LINUX_EINVAL);
    assert_eq!(
        error(maps.plan(0, 4096, Advice::from_guest_arg(u64::MAX))),
        LINUX_EINVAL
    );
    maps.assert_unobserved();
}

#[test]
fn overflowing_endpoint_and_rounding_are_enomem_before_venue_guard() {
    let mut maps = Maps::new(vec![]);
    maps.guard = Err(LINUX_EPERM);
    assert_eq!(
        error(maps.plan(u64::MAX - 4095, 4096, Advice::DontNeed)),
        LINUX_ENOMEM
    );
    assert_eq!(
        error(maps.plan(u64::MAX - 4095, 1, Advice::DontNeed)),
        LINUX_ENOMEM
    );
    maps.assert_unobserved();
}

#[test]
fn length_rounds_up_before_coverage() {
    let maps = Maps::new(vec![mapping(0x1000, 0x2000, Class::PrivateAnonymous)]);
    let plan = maps.plan(0x1000, 1, Advice::DontNeed).unwrap();
    assert_eq!(plan.range.end, GuestVa::new(0x2000));
    assert_eq!(plan.result, Ok(()));
    assert_eq!(plan.steps[0].action, Action::DiscardPrivateAnonymous);
}

#[test]
fn venue_guard_precedes_missing_coverage_but_follows_empty_success() {
    let mut maps = Maps::new(vec![]);
    maps.guard = Err(LINUX_EPERM);
    assert_eq!(
        maps.plan(0x1000, 0, Advice::DontNeed).unwrap().result,
        Ok(())
    );
    assert_eq!(
        error(maps.plan(0x1000, 4096, Advice::DontNeed)),
        LINUX_EPERM
    );
    assert_eq!(maps.checks.get(), 1);
    assert_eq!(maps.snapshots.get(), 0);
}

#[test]
fn no_coverage_is_enomem() {
    let maps = Maps::new(vec![]);
    assert_eq!(
        error(maps.plan(0x1000, 4096, Advice::DontNeed)),
        LINUX_ENOMEM
    );
}

#[test]
fn per_vma_rejections_precede_hole_enomem_in_either_order() {
    for start in [0x1000, 0x3000] {
        for (advice, class, droppable) in [
            (Advice::Free, Class::Shared, false),
            (Advice::WipeOnFork, Class::Shared, false),
            (Advice::WipeOnFork, Class::PrivateFile, false),
            (Advice::DoFork, Class::Special, false),
            (Advice::KeepOnFork, Class::PrivateAnonymous, true),
        ] {
            let maps = Maps::new(vec![Mapping {
                start,
                end: start + 4096,
                class,
                droppable,
            }]);
            assert_eq!(error(maps.plan(0x1000, 3 * 4096, advice)), LINUX_EINVAL);
        }
    }
}

#[test]
fn covered_segments_on_both_sides_of_hole_precede_final_enomem() {
    let maps = Maps::new(vec![
        mapping(0x1000, 0x2000, Class::PrivateAnonymous),
        mapping(0x3000, 0x4000, Class::PrivateAnonymous),
    ]);
    let plan = maps.plan(0x1000, 3 * 4096, Advice::DontNeed).unwrap();
    assert_eq!(plan.steps.len(), 2);
    assert_eq!(
        plan.steps
            .iter()
            .map(|step| (step.segment.start, step.action))
            .collect::<Vec<_>>(),
        vec![
            (0x1000, Action::DiscardPrivateAnonymous),
            (0x3000, Action::DiscardPrivateAnonymous)
        ]
    );
    assert_eq!(plan.result, Err(LINUX_ENOMEM));
}

#[test]
fn free_with_any_shared_segment_rejects_the_entire_plan() {
    let maps = Maps::new(vec![
        mapping(0x1000, 0x2000, Class::PrivateAnonymous),
        mapping(0x2000, 0x3000, Class::Shared),
    ]);
    assert_eq!(error(maps.plan(0x1000, 8192, Advice::Free)), LINUX_EINVAL);
}

#[test]
fn locked_dontneed_rejects_before_any_effect_even_with_hole() {
    let mut maps = Maps::new(vec![
        mapping(0x1000, 0x2000, Class::PrivateAnonymous),
        mapping(0x3000, 0x4000, Class::PrivateAnonymous),
    ]);
    maps.locked = true;
    assert_eq!(
        error(maps.plan(0x1000, 3 * 4096, Advice::DontNeed)),
        LINUX_EINVAL
    );
}

// Preserve the existing handler's divergence from madvise(2): FREE accepts
// locked and private-file ranges and keeps contents. This extraction must not
// silently fix that gap, nor turn accepted THP hints into actual collapse.
#[test]
fn free_retains_private_file_and_locked_acceptance() {
    for class in [Class::PrivateAnonymous, Class::PrivateFile, Class::Special] {
        let mut maps = Maps::new(vec![mapping(0x1000, 0x2000, class)]);
        maps.locked = true;
        let plan = maps.plan(0x1000, 4096, Advice::Free).unwrap();
        assert_eq!(plan.result, Ok(()));
        assert_eq!(plan.steps[0].action, Action::None);
    }
}

#[test]
fn discard_actions_preserve_backing_classes() {
    let maps = Maps::new(vec![
        mapping(0x1000, 0x2000, Class::PrivateAnonymous),
        mapping(0x2000, 0x3000, Class::Shared),
        mapping(0x3000, 0x4000, Class::PrivateFile),
        mapping(0x4000, 0x5000, Class::Special),
    ]);
    let plan = maps.plan(0x1000, 4 * 4096, Advice::DontNeed).unwrap();
    assert_eq!(
        plan.steps
            .iter()
            .map(|step| step.action)
            .collect::<Vec<_>>(),
        vec![
            Action::DiscardPrivateAnonymous,
            Action::None,
            Action::RestorePrivateFile,
            Action::None
        ]
    );
    assert_eq!(plan.result, Ok(()));
}

#[test]
fn hints_and_attributes_preserve_hole_result_and_host_classification() {
    let maps = Maps::new(vec![mapping(0x1000, 0x2000, Class::PrivateAnonymous)]);
    for advice in [
        Advice::Normal,
        Advice::Random,
        Advice::Sequential,
        Advice::WillNeed,
        Advice::HugePage,
        Advice::NoHugePage,
        Advice::Collapse,
        Advice::Free,
        Advice::DontFork,
        Advice::DoFork,
        Advice::WipeOnFork,
        Advice::KeepOnFork,
        Advice::DontDump,
        Advice::DoDump,
    ] {
        let plan = maps.plan(0x1000, 8192, advice).unwrap();
        assert_eq!(plan.result, Err(LINUX_ENOMEM));
        assert_eq!(
            plan.steps[0].action,
            if advice.requires_host_attributes() {
                Action::UpdateAttributes(advice)
            } else {
                Action::None
            }
        );
    }
}

#[test]
fn supported_advice_set_is_unchanged() {
    for raw in 0..=26 {
        assert_eq!(
            Advice::from_guest_arg(raw) != Advice::Unsupported,
            matches!(raw, 0..=4 | 8 | 10 | 11 | 14..=19 | 25)
        );
    }
}
