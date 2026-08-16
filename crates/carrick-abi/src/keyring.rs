//! Linux kernel keyring ABI: `add_key(2)`, `request_key(2)`, `keyctl(2)`,
//! `keyrings(7)` and `keyutils(7)`.
//!
//! Everything guest-visible about the keyring subsystem lives here as a typed
//! domain rather than as loose integers in the dispatch layer:
//!
//! * [`KeySerial`] — `key_serial_t`. A key id and a *special* keyring id share
//!   one 32-bit type on the wire, but they are different domains: the special
//!   ids are NEGATIVE and are resolved per-caller. [`KeySpec`] names them, so a
//!   handler that means "the caller's session keyring" cannot accidentally pass
//!   the literal `-3` where a real serial is expected.
//! * [`KeyctlOp`] — an ordinal enum over the `KEYCTL_*` command numbers. Linux
//!   answers an unknown command with `EOPNOTSUPP`, which is exactly what a
//!   failed [`KeyctlOp::from_raw`] means.
//! * [`KeyPerm`] — the four-nibble-per-actor permission word, as `bitflags!`.
//!   The possessor/user/group/other bytes are the same six rights shifted, and
//!   spelling them as separate hand-numbered constants is how a `KEY_USR_*`
//!   value ends up compared against a `KEY_POS_*` mask.
//! * [`KeyRequestDefault`] — the `KEY_REQKEY_DEFL_*` default-destination
//!   selector for `KEYCTL_SET_REQKEY_KEYRING`.
//!
//! Derived from the man pages (`add_key(2)`, `request_key(2)`, `keyctl(2)`,
//! `keyrings(7)`, `keyutils(7)`) — never from kernel source.

/// A key or keyring identifier, Linux's `key_serial_t`.
///
/// POSITIVE values are real, allocated key ids. NEGATIVE values are the
/// [`KeySpec`] special keyring selectors, which name a keyring *relative to the
/// calling task* and must be resolved before use. Zero is never a valid id.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct KeySerial(i32);

impl KeySerial {
    /// The wire value of a serial that arrived from the guest, or that carrick's
    /// own allocator produced. Deliberately spelled `from_raw` (rather than a
    /// named constructor) because the keyring wire domain has no polarity to
    /// get backwards — [`KeySpec::from_serial`] is what separates the two
    /// meanings, and it cannot be bypassed by construction alone.
    pub const fn from_raw(value: i32) -> Self {
        Self(value)
    }

    /// The 32-bit wire value, for the guest return register and for `keyctl`
    /// arguments that carry a serial.
    pub const fn get(self) -> i32 {
        self.0
    }

    /// The value `add_key`/`request_key`/`KEYCTL_GET_KEYRING_ID` return to the
    /// guest. Serials are positive, so the widening is unambiguous.
    pub const fn guest_retval(self) -> u64 {
        self.0 as u64
    }

    /// Whether this is a real allocated id rather than a special selector or the
    /// never-valid zero.
    pub const fn is_allocated(self) -> bool {
        self.0 > 0
    }
}

/// The `KEY_SPEC_*` special keyring ids (`keyrings(7)`). Each names a keyring
/// belonging to the CALLING task, so resolution is per-caller and cannot be
/// cached across tasks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i32)]
pub enum KeySpec {
    /// `KEY_SPEC_THREAD_KEYRING`: this thread's anonymous keyring.
    Thread = -1,
    /// `KEY_SPEC_PROCESS_KEYRING`: this thread group's anonymous keyring.
    Process = -2,
    /// `KEY_SPEC_SESSION_KEYRING`: the session keyring, shared with children
    /// across `fork(2)` until `KEYCTL_JOIN_SESSION_KEYRING` replaces it.
    Session = -3,
    /// `KEY_SPEC_USER_KEYRING`: the UID-specific keyring.
    User = -4,
    /// `KEY_SPEC_USER_SESSION_KEYRING`: the UID-specific session keyring.
    UserSession = -5,
    /// `KEY_SPEC_GROUP_KEYRING`: the GID-specific keyring. Never implemented by
    /// Linux itself — every use is `ENOKEY`.
    Group = -6,
    /// `KEY_SPEC_REQKEY_AUTH_KEY`: the authorisation key of an in-progress
    /// `request_key(2)` upcall.
    ReqkeyAuthKey = -7,
    /// `KEY_SPEC_REQUESTOR_KEYRING`: the `request_key(2)` requestor's
    /// destination keyring, valid only inside an upcall.
    Requestor = -8,
}

impl KeySpec {
    /// Every special id, in wire order. The ordinal enum plus this table is what
    /// keeps a new selector from being hand-numbered at a use site.
    pub const ALL: &'static [KeySpec] = &[
        KeySpec::Thread,
        KeySpec::Process,
        KeySpec::Session,
        KeySpec::User,
        KeySpec::UserSession,
        KeySpec::Group,
        KeySpec::ReqkeyAuthKey,
        KeySpec::Requestor,
    ];

    /// Classify a wire serial: `Some` for the special selectors, `None` for a
    /// real (or invalid) id. THE seam between the two domains.
    pub fn from_serial(serial: KeySerial) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|spec| spec.serial() == serial)
    }

    /// This selector's wire serial.
    pub const fn serial(self) -> KeySerial {
        KeySerial::from_raw(self as i32)
    }
}

/// The `KEYCTL_*` command numbers (`keyctl(2)`).
///
/// An ordinal enum rather than a constant table: `keyctl(2)` answers an
/// unrecognised command with `EOPNOTSUPP`, so [`KeyctlOp::from_raw`] returning
/// `None` IS that error path, and no arm can silently alias another.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum KeyctlOp {
    GetKeyringId = 0,
    JoinSessionKeyring = 1,
    Update = 2,
    Revoke = 3,
    Chown = 4,
    SetPerm = 5,
    Describe = 6,
    Clear = 7,
    Link = 8,
    Unlink = 9,
    Search = 10,
    Read = 11,
    Instantiate = 12,
    Negate = 13,
    SetReqkeyKeyring = 14,
    SetTimeout = 15,
    AssumeAuthority = 16,
    GetSecurity = 17,
    SessionToParent = 18,
    Reject = 19,
    InstantiateIov = 20,
    Invalidate = 21,
    GetPersistent = 22,
    DhCompute = 23,
    PkeyQuery = 24,
    PkeyEncrypt = 25,
    PkeyDecrypt = 26,
    PkeySign = 27,
    PkeyVerify = 28,
    RestrictKeyring = 29,
    Move = 30,
    Capabilities = 31,
    WatchKey = 32,
}

impl KeyctlOp {
    /// Every command, in wire order. Index `i` MUST hold the command whose wire
    /// number is `i`, which the dense-table compile-time assert below proves.
    pub const ALL: &'static [KeyctlOp] = &[
        KeyctlOp::GetKeyringId,
        KeyctlOp::JoinSessionKeyring,
        KeyctlOp::Update,
        KeyctlOp::Revoke,
        KeyctlOp::Chown,
        KeyctlOp::SetPerm,
        KeyctlOp::Describe,
        KeyctlOp::Clear,
        KeyctlOp::Link,
        KeyctlOp::Unlink,
        KeyctlOp::Search,
        KeyctlOp::Read,
        KeyctlOp::Instantiate,
        KeyctlOp::Negate,
        KeyctlOp::SetReqkeyKeyring,
        KeyctlOp::SetTimeout,
        KeyctlOp::AssumeAuthority,
        KeyctlOp::GetSecurity,
        KeyctlOp::SessionToParent,
        KeyctlOp::Reject,
        KeyctlOp::InstantiateIov,
        KeyctlOp::Invalidate,
        KeyctlOp::GetPersistent,
        KeyctlOp::DhCompute,
        KeyctlOp::PkeyQuery,
        KeyctlOp::PkeyEncrypt,
        KeyctlOp::PkeyDecrypt,
        KeyctlOp::PkeySign,
        KeyctlOp::PkeyVerify,
        KeyctlOp::RestrictKeyring,
        KeyctlOp::Move,
        KeyctlOp::Capabilities,
        KeyctlOp::WatchKey,
    ];

    /// Decode the `keyctl(2)` first argument. `None` is Linux's `EOPNOTSUPP`.
    pub fn from_raw(raw: u64) -> Option<Self> {
        let index = usize::try_from(raw).ok()?;
        Self::ALL.get(index).copied()
    }

    /// This command's wire number.
    pub const fn raw(self) -> u32 {
        self as u32
    }
}

/// Compile-time proof that [`KeyctlOp::ALL`] is dense and correctly ordered, so
/// `from_raw` can index it directly. A misplaced or duplicated arm fails the
/// build rather than silently decoding to the wrong command.
const KEYCTL_OP_TABLE_IS_DENSE: () = {
    let mut i = 0usize;
    while i < KeyctlOp::ALL.len() {
        assert!(KeyctlOp::ALL[i] as usize == i);
        i += 1;
    }
};
const _: () = KEYCTL_OP_TABLE_IS_DENSE;

/// The `KEY_REQKEY_DEFL_*` selector for `KEYCTL_SET_REQKEY_KEYRING`
/// (`keyctl(2)`): which keyring `request_key(2)` links a newly constructed key
/// into when the caller names no explicit destination.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(i32)]
pub enum KeyRequestDefault {
    /// `KEY_REQKEY_DEFL_NO_CHANGE` — query only; never stored.
    NoChange = -1,
    /// `KEY_REQKEY_DEFL_DEFAULT` — the kernel's own preference order
    /// (thread, then process, then session, then user-session).
    #[default]
    Default = 0,
    ThreadKeyring = 1,
    ProcessKeyring = 2,
    SessionKeyring = 3,
    UserKeyring = 4,
    UserSessionKeyring = 5,
    /// Never implemented by Linux; `KEYCTL_SET_REQKEY_KEYRING` rejects it.
    GroupKeyring = 6,
    RequestorKeyring = 7,
}

impl KeyRequestDefault {
    /// Every selector, in wire order.
    pub const ALL: &'static [KeyRequestDefault] = &[
        KeyRequestDefault::NoChange,
        KeyRequestDefault::Default,
        KeyRequestDefault::ThreadKeyring,
        KeyRequestDefault::ProcessKeyring,
        KeyRequestDefault::SessionKeyring,
        KeyRequestDefault::UserKeyring,
        KeyRequestDefault::UserSessionKeyring,
        KeyRequestDefault::GroupKeyring,
        KeyRequestDefault::RequestorKeyring,
    ];

    /// Decode the `KEYCTL_SET_REQKEY_KEYRING` argument. `None` is `EINVAL`.
    pub fn from_raw(raw: i32) -> Option<Self> {
        Self::ALL.iter().copied().find(|d| d.raw() == raw)
    }

    /// This selector's wire value.
    pub const fn raw(self) -> i32 {
        self as i32
    }
}

bitflags::bitflags! {
    /// A key's permission word (`keyctl(2)` `KEYCTL_SETPERM`, `keyrings(7)`).
    ///
    /// Four actor bytes — possessor (bits 24-31), user (16-23), group (8-15),
    /// other (0-7) — each carrying the same six rights. Expressing them as one
    /// `bitflags` type rather than four hand-numbered constant families is what
    /// stops a `USR` mask being tested against a `POS` value.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct KeyPerm: u32 {
        const POS_VIEW = 0x0100_0000;
        const POS_READ = 0x0200_0000;
        const POS_WRITE = 0x0400_0000;
        const POS_SEARCH = 0x0800_0000;
        const POS_LINK = 0x1000_0000;
        const POS_SETATTR = 0x2000_0000;

        const USR_VIEW = 0x0001_0000;
        const USR_READ = 0x0002_0000;
        const USR_WRITE = 0x0004_0000;
        const USR_SEARCH = 0x0008_0000;
        const USR_LINK = 0x0010_0000;
        const USR_SETATTR = 0x0020_0000;

        const GRP_VIEW = 0x0000_0100;
        const GRP_READ = 0x0000_0200;
        const GRP_WRITE = 0x0000_0400;
        const GRP_SEARCH = 0x0000_0800;
        const GRP_LINK = 0x0000_1000;
        const GRP_SETATTR = 0x0000_2000;

        const OTH_VIEW = 0x0000_0001;
        const OTH_READ = 0x0000_0002;
        const OTH_WRITE = 0x0000_0004;
        const OTH_SEARCH = 0x0000_0008;
        const OTH_LINK = 0x0000_0010;
        const OTH_SETATTR = 0x0000_0020;
    }
}

impl KeyPerm {
    /// Every right the possessor may hold.
    pub const POS_ALL: KeyPerm = KeyPerm::from_bits_truncate(0x3f00_0000);
    /// Every right the owning user may hold.
    pub const USR_ALL: KeyPerm = KeyPerm::from_bits_truncate(0x003f_0000);
    /// Every right the owning group may hold.
    pub const GRP_ALL: KeyPerm = KeyPerm::from_bits_truncate(0x0000_3f00);
    /// Every right any other process may hold.
    pub const OTH_ALL: KeyPerm = KeyPerm::from_bits_truncate(0x0000_003f);

    /// The bits `KEYCTL_SETPERM` accepts. Anything outside is `EINVAL`.
    pub const VALID: KeyPerm = KeyPerm::from_bits_truncate(0x3f3f_3f3f);

    /// Wire value.
    pub const fn raw(self) -> u32 {
        self.bits()
    }
}

/// The single right a permission check is asking about, independent of WHICH
/// actor byte answers it. `keyctl(2)` describes permissions this way (view,
/// read, write, search, link, setattr), and a check is always "does the caller,
/// in whichever role applies, hold THIS right".
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyRight {
    View,
    Read,
    Write,
    Search,
    Link,
    SetAttr,
}

impl KeyRight {
    /// This right's bit within each actor byte (`KEY_OTH_*` values).
    const fn bit(self) -> u32 {
        match self {
            KeyRight::View => 0x01,
            KeyRight::Read => 0x02,
            KeyRight::Write => 0x04,
            KeyRight::Search => 0x08,
            KeyRight::Link => 0x10,
            KeyRight::SetAttr => 0x20,
        }
    }

    /// The mask that grants this right to the key's owning user.
    pub const fn user_mask(self) -> KeyPerm {
        KeyPerm::from_bits_truncate(self.bit() << 16)
    }

    /// The mask that grants this right to the key's owning group.
    pub const fn group_mask(self) -> KeyPerm {
        KeyPerm::from_bits_truncate(self.bit() << 8)
    }

    /// The mask that grants this right to everyone else.
    pub const fn other_mask(self) -> KeyPerm {
        KeyPerm::from_bits_truncate(self.bit())
    }

    /// The mask that grants this right to a possessor of the key.
    pub const fn possessor_mask(self) -> KeyPerm {
        KeyPerm::from_bits_truncate(self.bit() << 24)
    }
}

/// Longest key TYPE name Linux accepts, excluding the terminating NUL
/// (`add_key(2)`: "the type ... may be no more than 31 characters").
pub const LINUX_KEY_TYPE_MAX_LEN: usize = 31;

/// Longest key DESCRIPTION Linux accepts, excluding the terminating NUL
/// (`add_key(2)`: "no more than 4095 bytes").
pub const LINUX_KEY_DESC_MAX_LEN: usize = 4095;

/// Payload ceiling for the `user` and `logon` key types (`add_key(2)`:
/// "the payload must be no larger than 32767 bytes").
pub const LINUX_KEY_USER_PAYLOAD_MAX: usize = 32767;

/// Default `/proc/sys/kernel/keys/maxkeys`: how many keys ONE non-root user may
/// own before `add_key(2)` returns `EDQUOT`.
pub const LINUX_KEY_QUOTA_MAXKEYS: u32 = 200;

/// Default `/proc/sys/kernel/keys/maxbytes`: the total payload bytes ONE
/// non-root user may own before `add_key(2)` returns `EDQUOT`.
pub const LINUX_KEY_QUOTA_MAXBYTES: u32 = 20000;

/// Default `/proc/sys/kernel/keys/root_maxkeys`, the root-user counterpart of
/// [`LINUX_KEY_QUOTA_MAXKEYS`].
pub const LINUX_KEY_QUOTA_ROOT_MAXKEYS: u32 = 1_000_000;

/// Default `/proc/sys/kernel/keys/root_maxbytes`, the root-user counterpart of
/// [`LINUX_KEY_QUOTA_MAXBYTES`].
pub const LINUX_KEY_QUOTA_ROOT_MAXBYTES: u32 = 25_000_000;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keyctl_op_decodes_by_wire_number() {
        assert_eq!(KeyctlOp::from_raw(0), Some(KeyctlOp::GetKeyringId));
        assert_eq!(KeyctlOp::from_raw(1), Some(KeyctlOp::JoinSessionKeyring));
        assert_eq!(KeyctlOp::from_raw(11), Some(KeyctlOp::Read));
        assert_eq!(KeyctlOp::from_raw(21), Some(KeyctlOp::Invalidate));
        assert_eq!(KeyctlOp::from_raw(32), Some(KeyctlOp::WatchKey));
        // Beyond the table is Linux's EOPNOTSUPP path, not a panic.
        assert_eq!(KeyctlOp::from_raw(33), None);
        assert_eq!(KeyctlOp::from_raw(u64::MAX), None);
    }

    #[test]
    fn key_spec_round_trips_through_its_wire_serial() {
        for spec in KeySpec::ALL {
            assert_eq!(KeySpec::from_serial(spec.serial()), Some(*spec));
        }
        // A real (positive) serial is NOT a special selector.
        assert_eq!(KeySpec::from_serial(KeySerial::from_raw(42)), None);
        // Neither is zero, which is never a valid id.
        assert_eq!(KeySpec::from_serial(KeySerial::from_raw(0)), None);
        assert!(!KeySerial::from_raw(0).is_allocated());
        assert!(!KeySpec::Session.serial().is_allocated());
        assert!(KeySerial::from_raw(1).is_allocated());
    }

    #[test]
    fn key_right_masks_are_the_same_bit_in_each_actor_byte() {
        assert_eq!(KeyRight::View.user_mask(), KeyPerm::USR_VIEW);
        assert_eq!(KeyRight::Read.user_mask(), KeyPerm::USR_READ);
        assert_eq!(KeyRight::Write.group_mask(), KeyPerm::GRP_WRITE);
        assert_eq!(KeyRight::Search.other_mask(), KeyPerm::OTH_SEARCH);
        assert_eq!(KeyRight::Link.possessor_mask(), KeyPerm::POS_LINK);
        assert_eq!(KeyRight::SetAttr.possessor_mask(), KeyPerm::POS_SETATTR);
    }

    #[test]
    fn actor_all_masks_are_exactly_their_six_rights() {
        let rights = [
            KeyRight::View,
            KeyRight::Read,
            KeyRight::Write,
            KeyRight::Search,
            KeyRight::Link,
            KeyRight::SetAttr,
        ];
        let pos = rights
            .iter()
            .fold(KeyPerm::empty(), |acc, r| acc | r.possessor_mask());
        let usr = rights
            .iter()
            .fold(KeyPerm::empty(), |acc, r| acc | r.user_mask());
        let grp = rights
            .iter()
            .fold(KeyPerm::empty(), |acc, r| acc | r.group_mask());
        let oth = rights
            .iter()
            .fold(KeyPerm::empty(), |acc, r| acc | r.other_mask());
        assert_eq!(pos, KeyPerm::POS_ALL);
        assert_eq!(usr, KeyPerm::USR_ALL);
        assert_eq!(grp, KeyPerm::GRP_ALL);
        assert_eq!(oth, KeyPerm::OTH_ALL);
        assert_eq!(pos | usr | grp | oth, KeyPerm::VALID);
    }

    #[test]
    fn reqkey_default_decodes_including_the_negative_query_value() {
        assert_eq!(
            KeyRequestDefault::from_raw(-1),
            Some(KeyRequestDefault::NoChange)
        );
        assert_eq!(
            KeyRequestDefault::from_raw(0),
            Some(KeyRequestDefault::Default)
        );
        assert_eq!(
            KeyRequestDefault::from_raw(7),
            Some(KeyRequestDefault::RequestorKeyring)
        );
        assert_eq!(KeyRequestDefault::from_raw(8), None);
        assert_eq!(KeyRequestDefault::from_raw(-2), None);
        assert_eq!(KeyRequestDefault::default(), KeyRequestDefault::Default);
    }
}
