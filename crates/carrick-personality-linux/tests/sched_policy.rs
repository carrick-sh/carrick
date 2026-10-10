use carrick_guest_arch::UserVa;
use carrick_personality_linux::{
    dispatch::FamilyCompletion,
    sched::{SchedCall, SchedVenue, serve_sched},
};

struct Venue {
    pid: u64,
    exists: Option<bool>,
    copies: bool,
}
impl SchedVenue for Venue {
    fn argument(&self, index: usize) -> u64 {
        if index == 0 { self.pid } else { 4096 }
    }
    fn current_pid(&self) -> Option<u32> {
        Some(1)
    }
    fn pid_exists(&self, pid: u32) -> Option<bool> {
        if pid == 1 { Some(true) } else { self.exists }
    }
    fn copy_out(&mut self, _: UserVa, _: &[u8]) -> bool {
        self.copies
    }
}
#[test]
fn unavailable_copy_declines_instead_of_inventing_efault() {
    let mut venue = Venue {
        pid: 0,
        exists: None,
        copies: false,
    };
    assert_eq!(
        serve_sched(SchedCall::RrGetInterval, &mut venue),
        FamilyCompletion::Forward
    );
}

#[test]
fn existing_child_and_absent_pid_use_the_namespace_authority() {
    for (exists, expected) in [
        (Some(true), FamilyCompletion::Complete(0)),
        (Some(false), FamilyCompletion::Complete(-3)),
        (None, FamilyCompletion::Forward),
    ] {
        let mut venue = Venue {
            pid: 72,
            exists,
            copies: true,
        };
        assert_eq!(serve_sched(SchedCall::RrGetInterval, &mut venue), expected);
    }
}
