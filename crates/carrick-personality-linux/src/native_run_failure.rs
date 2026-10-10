//! Terminal lifecycle causes carried by both native execution lanes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u64)]
pub enum NativeRunFailureReason {
    X86GroupExitCustody = 1,
    NativeInvalid = 2,
    NativeStale = 3,
    NativeExhausted = 4,
    NativeFault = 5,
    NativeUnsupported = 6,
    NativeBusy = 7,
    NativeQuarantined = 8,
    NativeNoChild = 9,
    BirthSettlement = 10,
    ClaimRollback = 11,
}
impl NativeRunFailureReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::X86GroupExitCustody => "x86 group exit custody",
            Self::NativeInvalid => "native process invalid",
            Self::NativeStale => "native process stale",
            Self::NativeExhausted => "native process exhausted",
            Self::NativeFault => "native process fault",
            Self::NativeUnsupported => "native process unsupported",
            Self::NativeBusy => "native process busy",
            Self::NativeQuarantined => "native process quarantined",
            Self::NativeNoChild => "native process no child",
            Self::BirthSettlement => "native birth settlement",
            Self::ClaimRollback => "native claim rollback",
        }
    }
    pub const fn from_raw(raw: u64) -> Option<Self> {
        match raw {
            1 => Some(Self::X86GroupExitCustody),
            2 => Some(Self::NativeInvalid),
            3 => Some(Self::NativeStale),
            4 => Some(Self::NativeExhausted),
            5 => Some(Self::NativeFault),
            6 => Some(Self::NativeUnsupported),
            7 => Some(Self::NativeBusy),
            8 => Some(Self::NativeQuarantined),
            9 => Some(Self::NativeNoChild),
            10 => Some(Self::BirthSettlement),
            11 => Some(Self::ClaimRollback),
            _ => None,
        }
    }
}
