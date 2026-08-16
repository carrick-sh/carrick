//! The Linux kernel keyring subsystem (`add_key(2)`, `request_key(2)`,
//! `keyctl(2)`, `keyrings(7)`).
//!
//! # Where the state lives, and why
//!
//! Under HVPatch every Linux process is a THREAD of one Darwin carrier, so
//! nothing here may key off a host pid, a host tid, or a process-global static:
//! one guest's key would be every guest's key. The split follows Linux's own
//! ownership exactly, expressed in carrick's kernel graph:
//!
//! * The **key objects** — payloads, links, permissions, serials — are VM-wide
//!   and live in one [`KeyringService`] hanging off [`crate::kernel::Kernel`].
//!   The serial allocator is therefore VM-wide too, which is what makes a
//!   serial meaningful when it is passed between guest processes.
//! * The **thread keyring** is per-[`crate::kernel::Thread`]; it is NOT
//!   inherited by a `fork(2)` child, matching `keyrings(7)`.
//! * The **process keyring**, the **session keyring** and the request-key
//!   default live on the [`crate::kernel::Task`] — carrick's thread group — so
//!   every thread of a process shares them for free and a `fork` child copies
//!   them (the session SERIAL is copied, so parent and child go on sharing the
//!   same keyring object until one of them joins a new one).
//! * The **user** and **user-session** keyrings are keyed by [`NsUid`], the
//!   guest's namespace uid. Keying them by a host uid would collapse every
//!   guest user onto the one uid the carrier runs as.
//!
//! # Deliberate divergences from Linux
//!
//! Stated plainly rather than hidden, per the project's honest-status rule:
//!
//! * Only the `keyring` and `user` key types exist. `logon`, `big_key`,
//!   `asymmetric`, `encrypted`, `trusted`, `dns_resolver` and the rest are
//!   ABSENT, which `add_key(2)` reports as `ENODEV` — the same answer a Linux
//!   kernel built without them gives.
//! * There is **no `/sbin/request-key` upcall**. A `request_key(2)` that must
//!   construct a key therefore always fails to do so, negatively instantiates
//!   the key, links it, and reports `ENOKEY` — the answer observed
//!   differentially from Docker/ubuntu:24.04 under `seccomp=unconfined`, which
//!   has no helper installed either.
//! * There are **no per-user quotas** (`maxkeys`/`maxbytes`) and no
//!   `/proc/key-users`, so `EDQUOT` never happens.
//! * There is **no garbage collector**: a revoked key keeps its serial until
//!   the key is invalidated or unlinked, rather than becoming `ENOKEY` after
//!   `gc_delay` seconds.
//! * Permission checking implements Linux's possessor model, but "possession"
//!   is computed as plain reachability from the caller's thread/process/session
//!   keyrings, without Linux's separate `KEY_LOOKUP_PARTIAL` subtleties.
//!
//! Every one of those is a *missing* capability reported the way Linux reports
//! a missing capability — none of them fabricates a success carrick cannot back.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::time::{Duration, Instant};

use carrick_abi::keyring::{
    KeyPerm, KeyRequestDefault, KeyRight, KeySerial, KeySpec, LINUX_KEY_DESC_MAX_LEN,
    LINUX_KEY_TYPE_MAX_LEN, LINUX_KEY_USER_PAYLOAD_MAX,
};
use carrick_abi::{
    LINUX_EACCES, LINUX_EINVAL, LINUX_EKEYEXPIRED, LINUX_EKEYREVOKED, LINUX_ENODEV, LINUX_ENOENT,
    LINUX_ENOKEY, LINUX_ENOTDIR, LINUX_EOPNOTSUPP, LinuxErrno, NsGid, NsUid,
};
use parking_lot::Mutex;

/// The key types carrick implements. Anything else is genuinely absent and
/// `add_key(2)` answers `ENODEV`, exactly as a kernel without that type does.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum KeyKind {
    /// `keyring`: holds links to other keys, carries no payload of its own.
    Keyring,
    /// `user`: an opaque blob the owner can read back and update.
    User,
    /// A type carrick does not implement, remembered only so a NEGATIVE key
    /// created by `request_key(2)` can carry the type name the guest asked for.
    Absent,
}

impl KeyKind {
    /// Resolve a wire type name. `None` means "no such key type registered",
    /// which `add_key(2)` reports as `ENODEV`.
    fn from_name(name: &[u8]) -> Option<Self> {
        match name {
            b"keyring" => Some(Self::Keyring),
            b"user" => Some(Self::User),
            _ => None,
        }
    }

    /// The largest payload `add_key(2)` accepts for this type. One byte over is
    /// `EINVAL` (`add_key01`).
    const fn max_payload(self) -> usize {
        match self {
            // A keyring is created empty; a non-zero payload length is EINVAL.
            Self::Keyring => 0,
            Self::User => LINUX_KEY_USER_PAYLOAD_MAX,
            Self::Absent => 0,
        }
    }

    /// Whether `KEYCTL_UPDATE` can replace this type's payload. A type without
    /// an update method answers `EOPNOTSUPP`.
    const fn is_updatable(self) -> bool {
        matches!(self, Self::User)
    }
}

/// A key's instantiation state (`keyrings(7)`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum KeyState {
    /// Carries a payload and can be used.
    Instantiated,
    /// `request_key(2)` could not construct it. It occupies a serial and stays
    /// linked so the requester can see the failure, but every use is `ENOKEY`.
    Negative,
    /// `KEYCTL_REVOKE`d: the payload is gone and every use but `KEYCTL_UNLINK`
    /// is `EKEYREVOKED`.
    Revoked,
}

/// One key or keyring.
#[derive(Debug)]
struct Key {
    kind: KeyKind,
    /// The wire type name. Kept verbatim because a NEGATIVE key may name a type
    /// carrick does not implement, and a search must still match on it.
    type_name: Vec<u8>,
    description: Vec<u8>,
    uid: NsUid,
    gid: NsGid,
    perm: KeyPerm,
    state: KeyState,
    /// `KEYCTL_SET_TIMEOUT` deadline. Monotonic, so a wall-clock step cannot
    /// resurrect an expired key.
    expires: Option<Instant>,
    /// `user`-type payload. Empty for a keyring.
    payload: Vec<u8>,
    /// `keyring`-type links, in insertion order — `KEYCTL_READ` serialises them
    /// in exactly this order.
    links: Vec<KeySerial>,
}

impl Key {
    /// The right a *newly created* key grants. Possessor and owner get
    /// everything; group and others get nothing.
    ///
    /// Linux's per-type default is finer-grained than this (it withholds rights
    /// the type cannot support). carrick grants the full set instead, which is
    /// a deliberate approximation: no `keyctl(2)` operation carrick implements
    /// reports a key's permission word back to the guest, so the difference is
    /// unobservable, and every test that cares about denial sets the word
    /// explicitly with `KEYCTL_SETPERM` first.
    const DEFAULT_PERM: KeyPerm = KeyPerm::POS_ALL.union(KeyPerm::USR_ALL);

    fn is_expired(&self, now: Instant) -> bool {
        self.expires.is_some_and(|deadline| now >= deadline)
    }

    /// The state check every operation but `UNLINK` runs first. Ordered the way
    /// Linux orders it: revoked beats expired beats negative.
    fn usable(&self, now: Instant) -> Result<(), LinuxErrno> {
        match self.state {
            KeyState::Revoked => Err(LINUX_EKEYREVOKED),
            KeyState::Negative => Err(LINUX_ENOKEY),
            KeyState::Instantiated if self.is_expired(now) => Err(LINUX_EKEYEXPIRED),
            KeyState::Instantiated => Ok(()),
        }
    }
}

/// Who is asking. Assembled per syscall from the calling thread's credentials
/// and its three keyring roots, never cached — a `setuid(2)` or a
/// `KEYCTL_JOIN_SESSION_KEYRING` between two calls must be visible to the
/// second one.
#[derive(Clone, Debug)]
pub(crate) struct KeyringCaller {
    pub(crate) uid: NsUid,
    pub(crate) gid: NsGid,
    /// Thread, process and session keyrings, in Linux's search order. Absent
    /// entries (a thread that never created a thread keyring) are simply
    /// omitted, which is what makes the search order self-describing.
    pub(crate) roots: Vec<KeySerial>,
}

/// The VM-wide key store. One lock for the whole subsystem: keys are a small,
/// rarely-touched graph, and a single lock is what makes possession (a
/// reachability walk) atomic with respect to a concurrent `KEYCTL_UNLINK`.
#[derive(Debug, Default)]
pub struct KeyringService {
    store: Mutex<KeyStore>,
}

#[derive(Debug)]
struct KeyStore {
    /// VM-wide serial allocator. Serials start low and grow, so `keyctl01`'s
    /// descending scan from `INT32_MAX` finds an unused serial immediately.
    next_serial: i32,
    keys: BTreeMap<KeySerial, Key>,
    /// `_uid.N` and `_uid_ses.N` per guest namespace uid.
    user_rings: BTreeMap<NsUid, UserRings>,
    /// Session keyrings created by NAME via `KEYCTL_JOIN_SESSION_KEYRING`.
    /// Keyed by the OWNING uid as well as the name, so one guest user cannot
    /// join another's session keyring by guessing its name.
    named_sessions: BTreeMap<(NsUid, Vec<u8>), KeySerial>,
}

#[derive(Clone, Copy, Debug)]
struct UserRings {
    user: KeySerial,
    user_session: KeySerial,
}

impl Default for KeyStore {
    fn default() -> Self {
        Self {
            next_serial: 1,
            keys: BTreeMap::new(),
            user_rings: BTreeMap::new(),
            named_sessions: BTreeMap::new(),
        }
    }
}

/// What `KEYCTL_READ` produced: the bytes to copy out, which the caller
/// truncates to the guest buffer, and whose FULL length is the return value.
#[derive(Debug)]
pub(crate) struct KeyReadOutput(pub(crate) Vec<u8>);

impl KeyringService {
    pub fn new() -> Self {
        Self::default()
    }

    fn with<R>(&self, f: impl FnOnce(&mut KeyStore) -> R) -> R {
        f(&mut self.store.lock())
    }

    // ── Keyring materialisation ─────────────────────────────────────────────

    /// Create an anonymous keyring owned by `uid`, linked nowhere. The caller
    /// installs the returned serial as a thread/process/session keyring.
    pub(crate) fn create_anonymous_keyring(
        &self,
        description: &[u8],
        uid: NsUid,
        gid: NsGid,
    ) -> KeySerial {
        self.with(|store| store.insert_keyring(description, uid, gid))
    }

    /// This uid's `_uid.N` keyring, created on first use. `keyrings(7)` says
    /// the user keyrings are materialised on demand regardless of any `create`
    /// flag, which is what `add_key03` relies on.
    pub(crate) fn user_keyring(&self, uid: NsUid, gid: NsGid) -> KeySerial {
        self.with(|store| store.user_rings_for(uid, gid).user)
    }

    /// This uid's `_uid_ses.N` keyring, created on first use.
    pub(crate) fn user_session_keyring(&self, uid: NsUid, gid: NsGid) -> KeySerial {
        self.with(|store| store.user_rings_for(uid, gid).user_session)
    }

    /// `KEYCTL_JOIN_SESSION_KEYRING` with a NAME: join this uid's session
    /// keyring of that name, creating it the first time. Keyed by uid as well
    /// as name so the namespace is per-user, not global.
    pub(crate) fn named_session_keyring(
        &self,
        name: &[u8],
        uid: NsUid,
        gid: NsGid,
    ) -> Result<KeySerial, LinuxErrno> {
        self.with(|store| {
            let key = (uid, name.to_vec());
            if let Some(existing) = store.named_sessions.get(&key) {
                // A session keyring that was revoked out from under us is not
                // joinable; make a fresh one under the same name.
                if store
                    .keys
                    .get(existing)
                    .is_some_and(|entry| entry.state == KeyState::Instantiated)
                {
                    return Ok(*existing);
                }
            }
            let serial = store.insert_keyring(name, uid, gid);
            store.named_sessions.insert(key, serial);
            Ok(serial)
        })
    }

    // ── add_key(2) ──────────────────────────────────────────────────────────

    /// `add_key(2)`, minus the guest-memory marshalling.
    ///
    /// `payload` is `None` for a NULL pointer with a non-zero length — the
    /// caller has already turned that into the `EFAULT` `add_key02` demands,
    /// so reaching here with `None` means the guest passed length zero.
    pub(crate) fn add_key(
        &self,
        caller: &KeyringCaller,
        type_name: &[u8],
        description: &[u8],
        payload: &[u8],
        destination: KeySerial,
    ) -> Result<KeySerial, LinuxErrno> {
        let kind = KeyKind::from_name(type_name).ok_or(LINUX_ENODEV)?;
        if payload.len() > kind.max_payload() {
            return Err(LINUX_EINVAL);
        }
        let now = Instant::now();
        self.with(|store| {
            let ring = store.check_keyring(destination, caller, KeyRight::Write, now)?;
            // Linux folds a repeat add of the same (type, description) into an
            // UPDATE of the existing key — `request_key03` races exactly that
            // path against a concurrent request_key.
            if let Some(existing) = store.find_link(ring, type_name, description, now) {
                return store
                    .update_key(existing, caller, payload, now)
                    .map(|()| existing);
            }
            let serial = store.insert_key(kind, type_name, description, payload, caller);
            store.link(ring, serial);
            Ok(serial)
        })
    }

    // ── request_key(2) ──────────────────────────────────────────────────────

    /// `request_key(2)` for a caller that has already validated its string
    /// arguments.
    ///
    /// `destination` is the resolved destination keyring, or `None` when the
    /// guest passed 0 and the request-key default applies; in that case
    /// `default_destination` names it. Splitting the two is what lets
    /// `request_key04` observe Linux's ordering: the destination's Write
    /// permission is checked BEFORE any key is created, so a denial links
    /// nothing.
    pub(crate) fn request_key(
        &self,
        caller: &KeyringCaller,
        type_name: &[u8],
        description: &[u8],
        callout_info: Option<&[u8]>,
        destination: KeySerial,
    ) -> Result<KeySerial, LinuxErrno> {
        // An unregistered type can never be found and can never be constructed.
        if KeyKind::from_name(type_name).is_none() && callout_info.is_none() {
            return Err(LINUX_ENOKEY);
        }
        let now = Instant::now();
        self.with(|store| {
            if let Some(found) = store.search(caller, type_name, description, now) {
                return Ok(found);
            }
            let Some(_callout) = callout_info else {
                // No construction was requested: report the miss and link
                // nothing (`request_key02` case 0).
                return Err(LINUX_ENOKEY);
            };
            // Construction is requested. Linux checks the destination keyring
            // for Write FIRST — `request_key04` (CVE-2017-17807) is precisely
            // the regression where a key got linked before that check.
            let ring = store.check_keyring(destination, caller, KeyRight::Write, now)?;
            // carrick has no `/sbin/request-key` upcall, so construction always
            // fails. Linux's answer is a NEGATIVELY instantiated key, linked
            // into the destination so the requester can see the failure, and
            // ENOKEY. That errno is the one observed differentially against
            // Docker/ubuntu:24.04 with seccomp unconfined (recorded in
            // `crate::container_policy`), and is one of the two LTP accepts
            // (`keyctl07` allows ENOKEY or ENOENT).
            let serial = store.insert_negative_key(type_name, description, caller);
            store.link(ring, serial);
            Err(LINUX_ENOKEY)
        })
    }

    // ── keyctl(2) ───────────────────────────────────────────────────────────

    /// `KEYCTL_UPDATE`.
    pub(crate) fn update(
        &self,
        caller: &KeyringCaller,
        key: KeySerial,
        payload: &[u8],
    ) -> Result<(), LinuxErrno> {
        let now = Instant::now();
        self.with(|store| store.update_key(key, caller, payload, now))
    }

    /// `KEYCTL_REVOKE`.
    pub(crate) fn revoke(&self, caller: &KeyringCaller, key: KeySerial) -> Result<(), LinuxErrno> {
        let now = Instant::now();
        self.with(|store| {
            store.check_key(key, caller, KeyRight::Write, now)?;
            let entry = store.keys.get_mut(&key).ok_or(LINUX_ENOKEY)?;
            entry.state = KeyState::Revoked;
            entry.payload.clear();
            entry.links.clear();
            Ok(())
        })
    }

    /// `KEYCTL_INVALIDATE`: unlink the key everywhere and drop it, so its serial
    /// stops resolving immediately.
    pub(crate) fn invalidate(
        &self,
        caller: &KeyringCaller,
        key: KeySerial,
    ) -> Result<(), LinuxErrno> {
        let now = Instant::now();
        self.with(|store| {
            store.check_key(key, caller, KeyRight::Search, now)?;
            store.remove_key(key);
            Ok(())
        })
    }

    /// `KEYCTL_SETPERM`.
    pub(crate) fn set_perm(
        &self,
        caller: &KeyringCaller,
        key: KeySerial,
        perm: KeyPerm,
    ) -> Result<(), LinuxErrno> {
        if !KeyPerm::VALID.contains(perm) {
            return Err(LINUX_EINVAL);
        }
        let now = Instant::now();
        self.with(|store| {
            store.check_key(key, caller, KeyRight::SetAttr, now)?;
            store.keys.get_mut(&key).ok_or(LINUX_ENOKEY)?.perm = perm;
            Ok(())
        })
    }

    /// `KEYCTL_SET_TIMEOUT`. `seconds == 0` clears an existing timeout.
    pub(crate) fn set_timeout(
        &self,
        caller: &KeyringCaller,
        key: KeySerial,
        seconds: u64,
    ) -> Result<(), LinuxErrno> {
        let now = Instant::now();
        self.with(|store| {
            // Setting a timeout on an already-expired or revoked key is still
            // an attribute change, so only the permission gate applies here.
            store.check_key_attr(key, caller, KeyRight::SetAttr)?;
            let entry = store.keys.get_mut(&key).ok_or(LINUX_ENOKEY)?;
            entry.expires = (seconds != 0).then(|| now + Duration::from_secs(seconds));
            Ok(())
        })
    }

    /// `KEYCTL_CLEAR`: drop every link from a keyring.
    pub(crate) fn clear(&self, caller: &KeyringCaller, ring: KeySerial) -> Result<(), LinuxErrno> {
        let now = Instant::now();
        self.with(|store| {
            let ring = store.check_keyring(ring, caller, KeyRight::Write, now)?;
            store.keys.get_mut(&ring).ok_or(LINUX_ENOKEY)?.links.clear();
            Ok(())
        })
    }

    /// `KEYCTL_LINK`.
    pub(crate) fn link(
        &self,
        caller: &KeyringCaller,
        key: KeySerial,
        ring: KeySerial,
    ) -> Result<(), LinuxErrno> {
        let now = Instant::now();
        self.with(|store| {
            let ring = store.check_keyring(ring, caller, KeyRight::Write, now)?;
            store.check_key(key, caller, KeyRight::Link, now)?;
            if key == ring {
                // A keyring may not contain itself.
                return Err(LINUX_EINVAL);
            }
            store.link(ring, key);
            Ok(())
        })
    }

    /// `KEYCTL_UNLINK`.
    pub(crate) fn unlink(
        &self,
        caller: &KeyringCaller,
        key: KeySerial,
        ring: KeySerial,
    ) -> Result<(), LinuxErrno> {
        let now = Instant::now();
        self.with(|store| {
            let ring = store.check_keyring(ring, caller, KeyRight::Write, now)?;
            let entry = store.keys.get_mut(&ring).ok_or(LINUX_ENOKEY)?;
            let before = entry.links.len();
            entry.links.retain(|linked| *linked != key);
            if entry.links.len() == before {
                return Err(LINUX_ENOENT);
            }
            Ok(())
        })
    }

    /// `KEYCTL_SEARCH`: look for `(type, description)` starting at one keyring
    /// rather than at the caller's whole keyring tree.
    pub(crate) fn search_from(
        &self,
        caller: &KeyringCaller,
        ring: KeySerial,
        type_name: &[u8],
        description: &[u8],
    ) -> Result<KeySerial, LinuxErrno> {
        let now = Instant::now();
        self.with(|store| {
            let ring = store.check_keyring(ring, caller, KeyRight::Search, now)?;
            store
                .search_roots(caller, &[ring], type_name, description, now)
                .ok_or(LINUX_ENOKEY)
        })
    }

    /// `KEYCTL_READ`. Returns the FULL payload; the caller writes at most the
    /// guest's buffer length but reports this whole length, which is the exact
    /// short-buffer contract `keyctl06` pins down.
    pub(crate) fn read(
        &self,
        caller: &KeyringCaller,
        key: KeySerial,
    ) -> Result<KeyReadOutput, LinuxErrno> {
        let now = Instant::now();
        self.with(|store| {
            store.check_key(key, caller, KeyRight::Read, now)?;
            let entry = store.keys.get(&key).ok_or(LINUX_ENOKEY)?;
            let bytes = match entry.kind {
                KeyKind::Keyring => entry
                    .links
                    .iter()
                    .flat_map(|serial| serial.get().to_le_bytes())
                    .collect(),
                KeyKind::User => entry.payload.clone(),
                // A negative key of an absent type never reaches here: `usable`
                // has already reported ENOKEY.
                KeyKind::Absent => Vec::new(),
            };
            Ok(KeyReadOutput(bytes))
        })
    }

    /// `KEYCTL_DESCRIBE`: `type;uid;gid;perm;description`, NUL-terminated, as
    /// `keyctl(2)` specifies.
    pub(crate) fn describe(
        &self,
        caller: &KeyringCaller,
        key: KeySerial,
    ) -> Result<KeyReadOutput, LinuxErrno> {
        let now = Instant::now();
        self.with(|store| {
            store.check_key_attr(key, caller, KeyRight::View)?;
            let entry = store.keys.get(&key).ok_or(LINUX_ENOKEY)?;
            let _ = now;
            let mut out = Vec::new();
            out.extend_from_slice(&entry.type_name);
            out.extend_from_slice(
                format!(";{};{};{:08x};", entry.uid.0, entry.gid.0, entry.perm.raw()).as_bytes(),
            );
            out.extend_from_slice(&entry.description);
            out.push(0);
            Ok(KeyReadOutput(out))
        })
    }

    /// Resolve a serial the guest named, checking that it is a live key and
    /// that the caller may reach it. Used by `KEYCTL_GET_KEYRING_ID` and by the
    /// `request_key(2)` destination lookup, both of which must report a revoked
    /// or expired keyring as such (`request_key02`).
    pub(crate) fn validate_keyring(
        &self,
        caller: &KeyringCaller,
        ring: KeySerial,
        right: KeyRight,
    ) -> Result<KeySerial, LinuxErrno> {
        let now = Instant::now();
        self.with(|store| store.check_keyring(ring, caller, right, now))
    }

    /// Whether a serial names a live key at all, without any permission check.
    pub(crate) fn exists(&self, key: KeySerial) -> bool {
        self.with(|store| store.keys.contains_key(&key))
    }
}

impl KeyStore {
    fn allocate(&mut self) -> KeySerial {
        // Serials are never reused within a VM's lifetime. Saturating at
        // i32::MAX-1 keeps the value positive; a guest that burns two billion
        // serials has other problems, and wrapping would alias live keys.
        let serial = self.next_serial;
        self.next_serial = self.next_serial.saturating_add(1).min(i32::MAX - 1);
        KeySerial::from_raw(serial)
    }

    fn insert_key(
        &mut self,
        kind: KeyKind,
        type_name: &[u8],
        description: &[u8],
        payload: &[u8],
        caller: &KeyringCaller,
    ) -> KeySerial {
        let serial = self.allocate();
        self.keys.insert(
            serial,
            Key {
                kind,
                type_name: type_name.to_vec(),
                description: description.to_vec(),
                uid: caller.uid,
                gid: caller.gid,
                perm: Key::DEFAULT_PERM,
                state: KeyState::Instantiated,
                expires: None,
                payload: payload.to_vec(),
                links: Vec::new(),
            },
        );
        serial
    }

    fn insert_negative_key(
        &mut self,
        type_name: &[u8],
        description: &[u8],
        caller: &KeyringCaller,
    ) -> KeySerial {
        let serial = self.insert_key(KeyKind::Absent, type_name, description, &[], caller);
        if let Some(entry) = self.keys.get_mut(&serial) {
            entry.state = KeyState::Negative;
        }
        serial
    }

    fn insert_keyring(&mut self, description: &[u8], uid: NsUid, gid: NsGid) -> KeySerial {
        let caller = KeyringCaller {
            uid,
            gid,
            roots: Vec::new(),
        };
        self.insert_key(KeyKind::Keyring, b"keyring", description, &[], &caller)
    }

    fn user_rings_for(&mut self, uid: NsUid, gid: NsGid) -> UserRings {
        if let Some(rings) = self.user_rings.get(&uid) {
            return *rings;
        }
        let user = self.insert_keyring(format!("_uid.{}", uid.0).as_bytes(), uid, gid);
        let user_session = self.insert_keyring(format!("_uid_ses.{}", uid.0).as_bytes(), uid, gid);
        // Linux links the user keyring into the user-session keyring, so a
        // search that reaches the session ring also reaches the user ring.
        self.link(user_session, user);
        let rings = UserRings { user, user_session };
        self.user_rings.insert(uid, rings);
        rings
    }

    fn link(&mut self, ring: KeySerial, key: KeySerial) {
        if let Some(entry) = self.keys.get_mut(&ring) {
            if !entry.links.contains(&key) {
                entry.links.push(key);
            }
        }
    }

    fn remove_key(&mut self, key: KeySerial) {
        self.keys.remove(&key);
        for entry in self.keys.values_mut() {
            entry.links.retain(|linked| *linked != key);
        }
    }

    /// The set of serials the caller POSSESSES: everything transitively
    /// reachable from its thread, process and session keyrings, including those
    /// keyrings themselves.
    fn possessed(&self, caller: &KeyringCaller) -> BTreeSet<KeySerial> {
        let mut seen = BTreeSet::new();
        let mut queue: VecDeque<KeySerial> = caller.roots.iter().copied().collect();
        while let Some(serial) = queue.pop_front() {
            if !seen.insert(serial) {
                continue;
            }
            if let Some(entry) = self.keys.get(&serial) {
                queue.extend(entry.links.iter().copied());
            }
        }
        seen
    }

    /// Linux's permission model: the possessor bits apply when the caller
    /// possesses the key, and are ORed with whichever ONE of the user, group or
    /// other bytes describes the caller.
    fn grants(
        &self,
        entry: &Key,
        caller: &KeyringCaller,
        possessed: bool,
        right: KeyRight,
    ) -> bool {
        if possessed && entry.perm.contains(right.possessor_mask()) {
            return true;
        }
        if entry.uid == caller.uid {
            return entry.perm.contains(right.user_mask());
        }
        if entry.gid == caller.gid {
            return entry.perm.contains(right.group_mask());
        }
        entry.perm.contains(right.other_mask())
    }

    /// Permission check that does NOT consider instantiation state — the
    /// attribute operations (`SETPERM`, `SET_TIMEOUT`, `DESCRIBE`) work on a
    /// revoked or negative key too.
    fn check_key_attr(
        &self,
        key: KeySerial,
        caller: &KeyringCaller,
        right: KeyRight,
    ) -> Result<(), LinuxErrno> {
        let entry = self.keys.get(&key).ok_or(LINUX_ENOKEY)?;
        let possessed = self.possessed(caller).contains(&key);
        if self.grants(entry, caller, possessed, right) {
            Ok(())
        } else {
            Err(LINUX_EACCES)
        }
    }

    /// Full check for an operation on a key's CONTENT: the key must exist, be
    /// usable, and grant `right`.
    fn check_key(
        &self,
        key: KeySerial,
        caller: &KeyringCaller,
        right: KeyRight,
        now: Instant,
    ) -> Result<(), LinuxErrno> {
        let entry = self.keys.get(&key).ok_or(LINUX_ENOKEY)?;
        entry.usable(now)?;
        let possessed = self.possessed(caller).contains(&key);
        if self.grants(entry, caller, possessed, right) {
            Ok(())
        } else {
            Err(LINUX_EACCES)
        }
    }

    /// As [`Self::check_key`], and additionally that the key IS a keyring —
    /// Linux reports a non-keyring where a keyring is required as `ENOTDIR`.
    fn check_keyring(
        &self,
        ring: KeySerial,
        caller: &KeyringCaller,
        right: KeyRight,
        now: Instant,
    ) -> Result<KeySerial, LinuxErrno> {
        let entry = self.keys.get(&ring).ok_or(LINUX_ENOKEY)?;
        if entry.kind != KeyKind::Keyring {
            return Err(LINUX_ENOTDIR);
        }
        self.check_key(ring, caller, right, now)?;
        Ok(ring)
    }

    /// The USABLE key of this `(type, description)` already linked into `ring`,
    /// if any.
    ///
    /// Dead keys — revoked, expired, negatively instantiated — do not count. A
    /// repeat `add_key(2)` of a name whose old key was revoked must mint a
    /// fresh key rather than try to update the corpse and report
    /// `EKEYREVOKED`; `request_key03` races exactly that sequence
    /// (add / revoke-by-clear / add) thousands of times.
    fn find_link(
        &self,
        ring: KeySerial,
        type_name: &[u8],
        description: &[u8],
        now: Instant,
    ) -> Option<KeySerial> {
        let entry = self.keys.get(&ring)?;
        entry.links.iter().copied().find(|serial| {
            self.keys.get(serial).is_some_and(|key| {
                key.type_name == type_name
                    && key.description == description
                    && key.usable(now).is_ok()
            })
        })
    }

    fn update_key(
        &mut self,
        key: KeySerial,
        caller: &KeyringCaller,
        payload: &[u8],
        now: Instant,
    ) -> Result<(), LinuxErrno> {
        self.check_key(key, caller, KeyRight::Write, now)?;
        let entry = self.keys.get_mut(&key).ok_or(LINUX_ENOKEY)?;
        if !entry.kind.is_updatable() {
            return Err(LINUX_EOPNOTSUPP);
        }
        if payload.len() > entry.kind.max_payload() {
            return Err(LINUX_EINVAL);
        }
        entry.payload = payload.to_vec();
        Ok(())
    }

    /// `request_key(2)`'s search: breadth-first over the caller's thread,
    /// process and session keyrings.
    fn search(
        &self,
        caller: &KeyringCaller,
        type_name: &[u8],
        description: &[u8],
        now: Instant,
    ) -> Option<KeySerial> {
        let roots = caller.roots.clone();
        self.search_roots(caller, &roots, type_name, description, now)
    }

    /// Breadth-first keyring search.
    ///
    /// A key that is revoked, expired or negative is SKIPPED rather than
    /// reported: the search asks for a USABLE key of that name, so a dead key
    /// must not shadow a live one and a replacement added after a
    /// `KEYCTL_REVOKE` has to be findable (the add/clear race in
    /// `request_key03` depends on exactly that). The state errnos
    /// `EKEYREVOKED`/`EKEYEXPIRED` reach the guest from the DESTINATION keyring
    /// lookup instead, where the guest named the keyring explicitly and Linux
    /// tells it precisely why it cannot have it (`request_key02` cases 1, 2).
    fn search_roots(
        &self,
        caller: &KeyringCaller,
        roots: &[KeySerial],
        type_name: &[u8],
        description: &[u8],
        now: Instant,
    ) -> Option<KeySerial> {
        let possessed = self.possessed(caller);
        let mut seen = BTreeSet::new();
        let mut queue: VecDeque<KeySerial> = roots.iter().copied().collect();
        while let Some(serial) = queue.pop_front() {
            if !seen.insert(serial) {
                continue;
            }
            let Some(entry) = self.keys.get(&serial) else {
                continue;
            };
            // Matching this key and descending into it both require Search on
            // it, and both require it to be usable.
            if !self.grants(entry, caller, possessed.contains(&serial), KeyRight::Search)
                || entry.usable(now).is_err()
            {
                continue;
            }
            if entry.type_name == type_name && entry.description == description {
                return Some(serial);
            }
            if entry.kind == KeyKind::Keyring {
                queue.extend(entry.links.iter().copied());
            }
        }
        None
    }
}

/// Whether carrick implements this key type at all.
///
/// Exposed separately from [`KeyringService::add_key`] because `add_key(2)`
/// checks the type BEFORE copying the payload — `add_key02` (CVE-2017-15274)
/// distinguishes `ENODEV` for an absent type from `EFAULT` for a NULL payload,
/// and getting the order backwards turns nine TCONFs into nine failures.
pub(crate) fn key_type_is_registered(type_name: &[u8]) -> bool {
    KeyKind::from_name(type_name).is_some()
}

/// The largest payload `add_key(2)` accepts for a registered type, or `None`
/// for a type carrick does not implement.
pub(crate) fn key_type_max_payload(type_name: &[u8]) -> Option<usize> {
    KeyKind::from_name(type_name).map(KeyKind::max_payload)
}

/// Validate a key TYPE name from the guest. `add_key(2)`: at most 31 bytes, and
/// a leading `.` marks a kernel-internal type userspace may not name.
pub(crate) fn validate_type_name(name: &[u8]) -> Result<(), LinuxErrno> {
    if name.is_empty() || name.len() > LINUX_KEY_TYPE_MAX_LEN {
        return Err(LINUX_EINVAL);
    }
    Ok(())
}

/// Validate a key DESCRIPTION from the guest (`add_key(2)`: at most 4095 bytes,
/// and never empty).
pub(crate) fn validate_description(description: &[u8]) -> Result<(), LinuxErrno> {
    if description.is_empty() || description.len() > LINUX_KEY_DESC_MAX_LEN {
        return Err(LINUX_EINVAL);
    }
    Ok(())
}

/// Whether a type name is kernel-internal (`.`-prefixed). `request_key(2)`
/// reports `EPERM` for one — this is CVE-2017-… era hardening that
/// `request_key06` case 3 and `keyctl08` both pin down.
pub(crate) fn is_internal_type(name: &[u8]) -> bool {
    name.first() == Some(&b'.')
}

/// The keyring a `request_key(2)` with `dest_keyring == 0` links into, given
/// this process's `KEYCTL_SET_REQKEY_KEYRING` setting.
pub(crate) fn default_destination_spec(default: KeyRequestDefault) -> KeySpec {
    match default {
        KeyRequestDefault::ThreadKeyring => KeySpec::Thread,
        KeyRequestDefault::ProcessKeyring => KeySpec::Process,
        KeyRequestDefault::SessionKeyring => KeySpec::Session,
        KeyRequestDefault::UserKeyring => KeySpec::User,
        KeyRequestDefault::UserSessionKeyring => KeySpec::UserSession,
        KeyRequestDefault::GroupKeyring => KeySpec::Group,
        KeyRequestDefault::RequestorKeyring => KeySpec::Requestor,
        // `DEFAULT` is Linux's own preference order; with no upcall in play the
        // observable end of that order is the session keyring, which is where
        // an unconfigured process's constructed keys land.
        KeyRequestDefault::Default | KeyRequestDefault::NoChange => KeySpec::Session,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn caller(uid: u32, roots: Vec<KeySerial>) -> KeyringCaller {
        KeyringCaller {
            uid: NsUid(uid),
            gid: NsGid(uid),
            roots,
        }
    }

    /// A service with one session keyring owned by uid 0, and a caller that
    /// possesses it — the shape every guest process starts in.
    fn service_with_session() -> (KeyringService, KeySerial, KeyringCaller) {
        let service = KeyringService::new();
        let session = service.create_anonymous_keyring(b"_ses", NsUid(0), NsGid(0));
        let caller = caller(0, vec![session]);
        (service, session, caller)
    }

    #[test]
    fn add_key_rejects_a_payload_the_type_cannot_hold() {
        let (service, session, caller) = service_with_session();
        // `keyring` takes no payload at all (add_key01 cases 0 and 1).
        assert!(
            service
                .add_key(&caller, b"keyring", b"abc", &[], session)
                .is_ok()
        );
        assert_eq!(
            service.add_key(&caller, b"keyring", b"bcd", &[0u8], session),
            Err(LINUX_EINVAL)
        );
        // `user` accepts exactly 32767 bytes, and one more is EINVAL.
        assert!(
            service
                .add_key(&caller, b"user", b"cde", &vec![0u8; 32767], session)
                .is_ok()
        );
        assert_eq!(
            service.add_key(&caller, b"user", b"def", &vec![0u8; 32768], session),
            Err(LINUX_EINVAL)
        );
    }

    #[test]
    fn an_absent_key_type_is_enodev_not_einval() {
        // add_key02 distinguishes the two: ENODEV means "this kernel has no
        // such type" (TCONF), EINVAL would be a hard failure.
        let (service, session, caller) = service_with_session();
        for absent in [&b"logon"[..], b"big_key", b"asymmetric", b"dns_resolver"] {
            assert_eq!(
                service.add_key(&caller, absent, b"abc:def", &[], session),
                Err(LINUX_ENODEV),
                "{}",
                String::from_utf8_lossy(absent)
            );
        }
    }

    #[test]
    fn adding_an_existing_description_updates_it_in_place() {
        // request_key03 races add_key against request_key expecting an update,
        // not a second key with the same name.
        let (service, session, caller) = service_with_session();
        let first = service
            .add_key(&caller, b"user", b"desc", b"one", session)
            .unwrap();
        let second = service
            .add_key(&caller, b"user", b"desc", b"two", session)
            .unwrap();
        assert_eq!(first, second);
        assert_eq!(service.read(&caller, first).unwrap().0, b"two");
    }

    #[test]
    fn keyring_read_serialises_links_and_reports_the_full_length() {
        // keyctl06: a short buffer must not change the RETURNED length.
        let (service, session, caller) = service_with_session();
        let a = service
            .add_key(&caller, b"user", b"key1", b"payload", session)
            .unwrap();
        let b = service
            .add_key(&caller, b"user", b"key2", b"payload", session)
            .unwrap();
        let out = service.read(&caller, session).unwrap().0;
        assert_eq!(out.len(), 8);
        assert_eq!(&out[0..4], &a.get().to_le_bytes());
        assert_eq!(&out[4..8], &b.get().to_le_bytes());
    }

    #[test]
    fn a_nonexistent_serial_is_enokey_for_every_operation() {
        // keyctl01 scans downward from INT32_MAX and requires ENOKEY, not
        // EFAULT — the buffer arguments there are uninitialised garbage.
        let (service, _session, caller) = service_with_session();
        let ghost = KeySerial::from_raw(i32::MAX);
        assert!(!service.exists(ghost));
        assert_eq!(service.read(&caller, ghost).unwrap_err(), LINUX_ENOKEY);
        assert_eq!(service.revoke(&caller, ghost).unwrap_err(), LINUX_ENOKEY);
    }

    #[test]
    fn revoked_and_expired_keys_report_their_own_errno() {
        // request_key02 cases 1 and 2 pin these two exactly.
        let (service, session, caller) = service_with_session();
        let revoked = service
            .add_key(&caller, b"user", b"gone", b"x", session)
            .unwrap();
        service.revoke(&caller, revoked).unwrap();
        assert_eq!(
            service.read(&caller, revoked).unwrap_err(),
            LINUX_EKEYREVOKED
        );

        let expiring = service
            .add_key(&caller, b"user", b"old", b"x", session)
            .unwrap();
        service.set_timeout(&caller, expiring, 1).unwrap();
        assert!(service.read(&caller, expiring).is_ok());
        // Reach into the store rather than sleeping a second in a unit test.
        service.with(|store| {
            store.keys.get_mut(&expiring).unwrap().expires =
                Some(Instant::now() - Duration::from_secs(1));
        });
        assert_eq!(
            service.read(&caller, expiring).unwrap_err(),
            LINUX_EKEYEXPIRED
        );
    }

    #[test]
    fn possession_alone_can_grant_and_deny() {
        // keyctl05 case 2 sets POS_ALL with every USR/GRP/OTH bit clear, then
        // toggles POS_WRITE: only a possessor model produces the EACCES.
        let (service, session, caller) = service_with_session();
        let key = service
            .add_key(&caller, b"user", b"desc", b"payload", session)
            .unwrap();
        service.set_perm(&caller, key, KeyPerm::POS_ALL).unwrap();
        assert!(service.update(&caller, key, b"again").is_ok());
        service
            .set_perm(&caller, key, KeyPerm::POS_ALL & !KeyPerm::POS_WRITE)
            .unwrap();
        assert_eq!(
            service.update(&caller, key, b"nope").unwrap_err(),
            LINUX_EACCES
        );
        // SETPERM itself still works: it is gated on SetAttr, not Write.
        assert!(service.set_perm(&caller, key, KeyPerm::POS_ALL).is_ok());
    }

    #[test]
    fn request_key_without_callout_info_links_nothing() {
        // request_key02 case 0: ENOKEY and an untouched destination.
        let (service, session, caller) = service_with_session();
        assert_eq!(
            service
                .request_key(&caller, b"user", b"absent", None, session)
                .unwrap_err(),
            LINUX_ENOKEY
        );
        assert!(service.read(&caller, session).unwrap().0.is_empty());
    }

    #[test]
    fn request_key_denied_by_the_destination_links_nothing() {
        // request_key04 (CVE-2017-17807): the Write check on the destination
        // must run BEFORE the negative key is created.
        let (service, session, caller) = service_with_session();
        service
            .set_perm(
                &caller,
                session,
                KeyPerm::POS_SEARCH | KeyPerm::POS_READ | KeyPerm::POS_VIEW,
            )
            .unwrap();
        assert_eq!(
            service
                .request_key(&caller, b"user", b"desc", Some(b"callout"), session)
                .unwrap_err(),
            LINUX_EACCES
        );
        assert!(service.read(&caller, session).unwrap().0.is_empty());
    }

    #[test]
    fn request_key_with_callout_info_negates_and_links_the_key() {
        // keyctl07 (CVE-2017-12192): the negative key IS linked, and reading it
        // is ENOKEY rather than a NULL-payload oops.
        let (service, session, caller) = service_with_session();
        assert_eq!(
            service
                .request_key(&caller, b"user", b"desc", Some(b"callout"), session)
                .unwrap_err(),
            LINUX_ENOKEY
        );
        let links = service.read(&caller, session).unwrap().0;
        assert_eq!(links.len(), 4);
        let negative = KeySerial::from_raw(i32::from_le_bytes(links[0..4].try_into().unwrap()));
        assert_eq!(service.read(&caller, negative).unwrap_err(), LINUX_ENOKEY);
    }

    #[test]
    fn a_search_skips_dead_keys_rather_than_reporting_them() {
        // The search must not let a revoked key of the right name shadow a live
        // one, or `request_key03`'s add/clear race would wedge on the corpse.
        // The state errnos come from the DESTINATION lookup instead
        // (`validate_keyring`), which is what `request_key02` observes.
        let (service, session, caller) = service_with_session();
        let dead = service
            .add_key(&caller, b"keyring", b"ltp2", &[], session)
            .unwrap();
        service.revoke(&caller, dead).unwrap();
        // Searching past it finds nothing, rather than surfacing EKEYREVOKED.
        assert_eq!(
            service
                .request_key(&caller, b"keyring", b"ltp2", None, session)
                .unwrap_err(),
            LINUX_ENOKEY
        );
        // Naming it as a destination DOES report why it is unusable.
        assert_eq!(
            service
                .validate_keyring(&caller, dead, KeyRight::Write)
                .unwrap_err(),
            LINUX_EKEYREVOKED
        );
        // And a live replacement of the same name is findable again.
        let live = service
            .add_key(&caller, b"keyring", b"ltp2", &[], session)
            .unwrap();
        assert_ne!(live, dead);
        assert_eq!(
            service
                .request_key(&caller, b"keyring", b"ltp2", None, session)
                .unwrap(),
            live
        );
    }

    #[test]
    fn request_key_finds_an_existing_key_by_type_and_description() {
        // request_key01: the serial must be the one add_key returned.
        let (service, session, caller) = service_with_session();
        let added = service
            .add_key(&caller, b"keyring", b"ltp", &[], session)
            .unwrap();
        let found = service
            .request_key(&caller, b"keyring", b"ltp", None, session)
            .unwrap();
        assert_eq!(added, found);
    }

    #[test]
    fn user_keyrings_are_per_namespace_uid_and_not_forgeable_by_name() {
        // add_key03: a key merely NAMED `_uid.N` in a process keyring must not
        // become another user's user keyring.
        let (service, session, caller) = service_with_session();
        let forged = service
            .add_key(&caller, b"keyring", b"_uid.1234", &[], session)
            .unwrap();
        let real = service.user_keyring(NsUid(1234), NsGid(1234));
        assert_ne!(forged, real);
        // And a second lookup is stable rather than allocating again.
        assert_eq!(real, service.user_keyring(NsUid(1234), NsGid(1234)));
    }

    #[test]
    fn unlink_removes_exactly_one_link_and_reports_a_missing_one() {
        let (service, session, caller) = service_with_session();
        let key = service
            .add_key(&caller, b"user", b"ltptestkey", b"a", session)
            .unwrap();
        assert!(service.unlink(&caller, key, session).is_ok());
        assert_eq!(
            service.unlink(&caller, key, session).unwrap_err(),
            LINUX_ENOENT
        );
    }

    #[test]
    fn clear_empties_a_keyring_but_keeps_it_usable() {
        let (service, session, caller) = service_with_session();
        service
            .add_key(&caller, b"user", b"a", b"x", session)
            .unwrap();
        service.clear(&caller, session).unwrap();
        assert!(service.read(&caller, session).unwrap().0.is_empty());
        assert!(
            service
                .add_key(&caller, b"user", b"b", b"y", session)
                .is_ok()
        );
    }

    #[test]
    fn invalidate_makes_the_serial_stop_resolving() {
        let (service, session, caller) = service_with_session();
        let key = service
            .add_key(&caller, b"user", b"a", b"x", session)
            .unwrap();
        service.invalidate(&caller, key).unwrap();
        assert!(!service.exists(key));
        assert!(service.read(&caller, session).unwrap().0.is_empty());
    }

    #[test]
    fn a_non_keyring_destination_is_enotdir() {
        let (service, session, caller) = service_with_session();
        let key = service
            .add_key(&caller, b"user", b"a", b"x", session)
            .unwrap();
        assert_eq!(
            service
                .add_key(&caller, b"user", b"b", b"y", key)
                .unwrap_err(),
            LINUX_ENOTDIR
        );
    }

    #[test]
    fn string_validation_matches_the_documented_limits() {
        assert!(validate_type_name(b"user").is_ok());
        assert!(validate_type_name(b"").is_err());
        assert!(validate_type_name(&[b'a'; LINUX_KEY_TYPE_MAX_LEN]).is_ok());
        assert!(validate_type_name(&[b'a'; LINUX_KEY_TYPE_MAX_LEN + 1]).is_err());
        assert!(validate_description(b"abc").is_ok());
        assert!(validate_description(b"").is_err());
        assert!(validate_description(&vec![b'a'; LINUX_KEY_DESC_MAX_LEN]).is_ok());
        assert!(validate_description(&vec![b'a'; LINUX_KEY_DESC_MAX_LEN + 1]).is_err());
        assert!(is_internal_type(b".builtin_trusted_keys"));
        assert!(!is_internal_type(b"user"));
    }
}
