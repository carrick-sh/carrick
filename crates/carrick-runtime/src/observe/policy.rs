use super::{FastPathVisibility, ProcessInfo, SyscallAction, SyscallInfo, SyscallObserver};
use crate::dispatch::Signal;
use carrick_abi::{CanonicalNr, LinuxErrno};

/// An argument filter evaluated against a syscall argument.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArgFilter {
    /// Argument at `index` must equal `value`.
    Exact { index: usize, value: u64 },
    /// `(arg[index] & mask) == value`.
    MaskEquals { index: usize, mask: u64, value: u64 },
    /// `(arg[index] & mask) != 0`.
    MaskNotZero { index: usize, mask: u64 },
}

impl ArgFilter {
    pub const fn exact(index: usize, value: u64) -> Self {
        Self::Exact { index, value }
    }

    pub const fn mask_equals(index: usize, mask: u64, value: u64) -> Self {
        Self::MaskEquals { index, mask, value }
    }

    pub const fn mask_not_zero(index: usize, mask: u64) -> Self {
        Self::MaskNotZero { index, mask }
    }

    pub fn matches(&self, s: &SyscallInfo<'_>) -> bool {
        match *self {
            Self::Exact { index, value } => s.arg(index) == value,
            Self::MaskEquals { index, mask, value } => (s.arg(index) & mask) == value,
            Self::MaskNotZero { index, mask } => (s.arg(index) & mask) != 0,
        }
    }
}

/// A single rule in a [`PolicyObserver`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyRule {
    /// Target canonical syscall number (if `None`, matches any syscall).
    pub canonical_nr: Option<CanonicalNr>,
    /// Additional scalar argument filters that all must match.
    pub arg_filters: Vec<ArgFilter>,
    /// Action to take if the rule matches.
    pub action: SyscallAction,
}

impl PolicyRule {
    pub const fn new(canonical_nr: CanonicalNr, action: SyscallAction) -> Self {
        Self {
            canonical_nr: Some(canonical_nr),
            arg_filters: Vec::new(),
            action,
        }
    }

    pub const fn any_syscall(action: SyscallAction) -> Self {
        Self {
            canonical_nr: None,
            arg_filters: Vec::new(),
            action,
        }
    }

    pub const fn deny(canonical_nr: CanonicalNr, errno: LinuxErrno) -> Self {
        Self::new(canonical_nr, SyscallAction::Deny(errno))
    }

    pub const fn kill(canonical_nr: CanonicalNr, signal: Signal) -> Self {
        Self::new(canonical_nr, SyscallAction::Kill(signal))
    }

    pub const fn allow(canonical_nr: CanonicalNr) -> Self {
        Self::new(canonical_nr, SyscallAction::Allow)
    }

    pub fn with_arg_filter(mut self, filter: ArgFilter) -> Self {
        self.arg_filters.push(filter);
        self
    }

    pub fn matches(&self, s: &SyscallInfo<'_>) -> bool {
        if let Some(nr) = self.canonical_nr {
            if s.canonical_number() != nr {
                return false;
            }
        }
        for filter in &self.arg_filters {
            if !filter.matches(s) {
                return false;
            }
        }
        true
    }
}

/// Canonical syscall numbers served by the guest EL1 shim or vDSO fast paths.
pub(crate) const FAST_PATH_SYSCALL_NUMBERS: &[u64] = &[
    172, // getpid
    173, // getppid
    174, // getuid
    175, // geteuid
    176, // getgid
    177, // getegid
    178, // gettid
    113, // clock_gettime
    114, // clock_getres
    169, // gettimeofday
];

fn is_fast_path_syscall(nr: CanonicalNr) -> bool {
    FAST_PATH_SYSCALL_NUMBERS.contains(&nr.raw())
}

/// Policy observer applying typed rules over canonical syscall numbers and scalar arguments.
#[derive(Debug, Clone, Default)]
pub struct PolicyObserver {
    rules: Vec<PolicyRule>,
    default_action: SyscallAction,
    blind_spot_accepted: bool,
}

impl PolicyObserver {
    pub const fn new() -> Self {
        Self {
            rules: Vec::new(),
            default_action: SyscallAction::Allow,
            blind_spot_accepted: false,
        }
    }

    pub const fn with_default_action(default_action: SyscallAction) -> Self {
        Self {
            rules: Vec::new(),
            default_action,
            blind_spot_accepted: false,
        }
    }

    pub fn add_rule(&mut self, rule: PolicyRule) -> &mut Self {
        self.rules.push(rule);
        self
    }

    pub fn with_rule(mut self, rule: PolicyRule) -> Self {
        self.rules.push(rule);
        self
    }

    pub fn deny(mut self, nr: CanonicalNr, errno: LinuxErrno) -> Self {
        self.rules.push(PolicyRule::deny(nr, errno));
        self
    }

    pub fn kill(mut self, nr: CanonicalNr, signal: Signal) -> Self {
        self.rules.push(PolicyRule::kill(nr, signal));
        self
    }

    pub fn allow(mut self, nr: CanonicalNr) -> Self {
        self.rules.push(PolicyRule::allow(nr));
        self
    }

    /// Explicitly opt out of mandatory fast-path visibility, accepting that
    /// the EL1 shim and vDSO fast paths may handle identity/clock calls without
    /// consulting this observer.
    pub fn accept_fast_path_blind_spot(mut self) -> Self {
        self.blind_spot_accepted = true;
        self
    }

    pub fn rules(&self) -> &[PolicyRule] {
        &self.rules
    }
}

impl SyscallObserver for PolicyObserver {
    fn on_syscall(&self, _p: &ProcessInfo<'_>, s: &SyscallInfo<'_>) -> SyscallAction {
        for rule in &self.rules {
            if rule.matches(s) {
                return rule.action;
            }
        }
        self.default_action
    }

    fn wants_fast_path_visibility(&self) -> FastPathVisibility {
        if self.blind_spot_accepted {
            return FastPathVisibility::Blind;
        }
        if self.default_action != SyscallAction::Allow {
            return FastPathVisibility::Required;
        }
        for rule in &self.rules {
            if rule.action != SyscallAction::Allow {
                match rule.canonical_nr {
                    None => return FastPathVisibility::Required,
                    Some(nr) if is_fast_path_syscall(nr) => return FastPathVisibility::Required,
                    _ => {}
                }
            }
        }
        FastPathVisibility::Blind
    }
}
