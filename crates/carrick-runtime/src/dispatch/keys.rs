//! `add_key(2)`, `request_key(2)` and `keyctl(2)`: the guest-ABI face of
//! [`crate::keyring`].
//!
//! This module owns only the marshalling — reading strings and payloads out of
//! guest memory, resolving `KEY_SPEC_*` selectors against the calling thread's
//! own keyrings, and copying results back. Every keyring decision (permission,
//! possession, instantiation state, search order) belongs to the service.
//!
//! # Argument-validation ORDER is part of the ABI here
//!
//! Two LTP regression tests pin opposite orders, and both are load-bearing:
//!
//! * `add_key02` (CVE-2017-15274) passes a NULL payload with a non-zero length
//!   for nine key types. An absent type must report `ENODEV` (the test TCONFs
//!   on it) while a REGISTERED type must report `EFAULT` — so the type lookup
//!   runs BEFORE the payload copy.
//! * `request_key06` passes `(char *)-1` for `description` and for
//!   `callout_info` while naming the *unregistered* type `"type"`, and still
//!   demands `EFAULT` — so there, every string is copied BEFORE the type is
//!   looked up.
//!
//! Neither order is a detail that can be "cleaned up" later without breaking
//! the other test.

use super::*;
use crate::keyring::{
    KeyringCaller, key_type_is_registered, key_type_max_payload, validate_description,
    validate_type_name,
};
use carrick_abi::keyring::{
    KeyPerm, KeyRequestDefault, KeyRight, KeySerial, KeySpec, KeyctlOp, LINUX_KEY_DESC_MAX_LEN,
};
use carrick_abi::{LINUX_EACCES, LINUX_ENOKEY, LINUX_EOPNOTSUPP};

syscall_table! {
    /// Routing for the kernel-keyring family. Its own table (rather than arms
    /// bolted onto `dispatch_proc`) because the three syscalls share one
    /// subsystem and one set of helpers.
    pub(crate) fn dispatch_keys;
    217 => add_key,
    218 => request_key,
    219 => keyctl,
}

/// The calling thread's view of the keyring world for the duration of ONE
/// syscall.
///
/// Never cached across syscalls: a `setuid(2)` or a
/// `KEYCTL_JOIN_SESSION_KEYRING` in between must be visible to the next call,
/// and the uid is what selects the user keyrings.
struct KeyScope<'a> {
    kernel: &'a crate::kernel::Kernel,
    task: &'a crate::kernel::TaskRef,
    thread: &'a crate::kernel::ThreadRef,
    uid: carrick_abi::NsUid,
    gid: carrick_abi::NsGid,
}

impl<'a> KeyScope<'a> {
    fn capture<M: GuestMemory>(cx: &'a SyscallCtx<'_, M>) -> Self {
        let credentials = cx.kernel.resources().credentials();
        Self {
            kernel: cx.kernel.kernel(),
            task: cx.kernel.task(),
            thread: cx.kernel.thread(),
            // The FILESYSTEM uid is what Linux charges a key to; it tracks the
            // effective uid except where a guest has deliberately split them.
            uid: credentials.fsuid(),
            gid: credentials.fsgid(),
        }
    }

    fn service(&self) -> &crate::keyring::KeyringService {
        self.kernel.keyrings()
    }

    /// This uid's `_uid.N` keyring. Always materialised: `keyrings(7)` has the
    /// user keyrings spring into existence on demand regardless of any `create`
    /// flag, which is what `add_key03` relies on after its `setuid`.
    fn user_ring(&self) -> KeySerial {
        self.service().user_keyring(self.uid, self.gid)
    }

    /// This uid's `_uid_ses.N` keyring.
    fn user_session_ring(&self) -> KeySerial {
        self.service().user_session_keyring(self.uid, self.gid)
    }

    /// This process's session keyring: the one it joined, or — for a process
    /// that never joined one — its user-session keyring, exactly as Linux
    /// defaults it.
    fn session_ring(&self) -> KeySerial {
        match self.task.keyrings().session {
            Some(session) if self.service().exists(session) => session,
            _ => self.user_session_ring(),
        }
    }

    /// This process's process keyring, materialising it when `create`.
    fn process_ring(&self, create: bool) -> Option<KeySerial> {
        let existing = self.task.keyrings().process;
        if let Some(process) = existing {
            if self.service().exists(process) {
                return Some(process);
            }
        }
        if !create {
            return None;
        }
        // Allocate outside the task lock, then publish under it, so two threads
        // racing here agree on one keyring rather than leaking the loser's.
        let fresh = self
            .service()
            .create_anonymous_keyring(b"_pid", self.uid, self.gid);
        Some(
            self.task
                .with_keyrings(|keyrings| *keyrings.process.get_or_insert(fresh)),
        )
    }

    /// This thread's thread keyring, materialising it when `create`.
    fn thread_ring(&self, create: bool) -> Option<KeySerial> {
        if let Some(thread) = self.thread.thread_keyring() {
            if self.service().exists(thread) {
                return Some(thread);
            }
        }
        if !create {
            return None;
        }
        let fresh = self
            .service()
            .create_anonymous_keyring(b"_tid", self.uid, self.gid);
        Some(
            self.thread
                .with_thread_keyring(|slot| *slot.get_or_insert(fresh)),
        )
    }

    /// Install a new session keyring for this process, replacing whatever it
    /// had. `KEYCTL_JOIN_SESSION_KEYRING` REPLACES rather than mutates, which
    /// is what keeps an already-forked child on the old keyring.
    fn join_session(&self, session: KeySerial) {
        self.task
            .with_keyrings(|keyrings| keyrings.session = Some(session));
    }

    /// The caller identity a service call needs, including its search roots in
    /// Linux's order (thread, process, session). Materialises nothing: a search
    /// must not conjure a thread keyring as a side effect.
    fn caller(&self) -> KeyringCaller {
        let mut roots = Vec::with_capacity(3);
        roots.extend(self.thread_ring(false));
        roots.extend(self.process_ring(false));
        roots.push(self.session_ring());
        KeyringCaller {
            uid: self.uid,
            gid: self.gid,
            roots,
        }
    }

    /// Resolve a wire serial — real id or `KEY_SPEC_*` selector — to a live
    /// key. `create` materialises the thread/process keyrings, matching Linux's
    /// `KEY_LOOKUP_CREATE`.
    fn resolve(&self, serial: KeySerial, create: bool) -> Result<KeySerial, LinuxErrno> {
        if let Some(spec) = KeySpec::from_serial(serial) {
            return match spec {
                KeySpec::Thread => self.thread_ring(create).ok_or(LINUX_ENOKEY),
                KeySpec::Process => self.process_ring(create).ok_or(LINUX_ENOKEY),
                KeySpec::Session => Ok(self.session_ring()),
                KeySpec::User => Ok(self.user_ring()),
                KeySpec::UserSession => Ok(self.user_session_ring()),
                // The group keyring was never implemented by Linux, and the
                // two request-key upcall selectors are only meaningful inside
                // an upcall carrick never performs.
                KeySpec::Group | KeySpec::ReqkeyAuthKey | KeySpec::Requestor => Err(LINUX_ENOKEY),
            };
        }
        if !serial.is_allocated() || !self.service().exists(serial) {
            return Err(LINUX_ENOKEY);
        }
        Ok(serial)
    }

    /// The keyring a `request_key(2)` with destination 0 links into.
    fn request_key_default_ring(&self) -> Result<KeySerial, LinuxErrno> {
        let default = self.task.keyrings().request_key_default;
        self.resolve(
            crate::keyring::default_destination_spec(default).serial(),
            true,
        )
    }
}

/// Read a NUL-terminated guest string that is NOT a path.
///
/// [`read_guest_c_string`] runs the bytes through `pathcodec`, which is right
/// for filenames and wrong for a key description: a key's description is opaque
/// bytes that must round-trip to the search unchanged.
fn read_key_string<M: GuestMemory>(
    memory: &M,
    address: GuestPtr,
) -> Result<Vec<u8>, DispatchError> {
    Ok(read_guest_c_string_bytes(memory, address.0)?)
}

/// Copy a keyctl/add_key payload out of the guest.
///
/// A zero length never touches memory (Linux does not fault a NULL payload of
/// length zero), and a NULL pointer with a non-zero length is the `EFAULT`
/// `add_key02` is written to catch.
fn read_payload<M: GuestMemory>(
    memory: &M,
    address: GuestPtr,
    length: usize,
) -> Result<Vec<u8>, DispatchError> {
    if length == 0 {
        return Ok(Vec::new());
    }
    if address.0 == 0 {
        return Err(LINUX_EFAULT.into());
    }
    Ok(memory.read_bytes(address.0, length)?)
}

/// Copy a service result back into the guest's buffer and produce the syscall's
/// return value.
///
/// The return value is the FULL length, even when the buffer was too small to
/// hold it — `keyctl06` fails an implementation that reports the truncated
/// count instead, and fails one that overruns the buffer.
fn write_truncated<M: GuestMemory>(
    memory: &mut M,
    address: GuestPtr,
    buffer_len: usize,
    bytes: &[u8],
) -> Result<DispatchOutcome, DispatchError> {
    let full = bytes.len();
    if address.0 != 0 && buffer_len != 0 {
        let copied = full.min(buffer_len);
        memory.write_bytes(address.0, &bytes[..copied])?;
    }
    Ok(DispatchOutcome::Returned { value: full as i64 })
}

/// A `key_serial_t` argument: the wire value is 32-bit and signed, so the
/// negative `KEY_SPEC_*` selectors survive the widening the syscall ABI does.
fn serial_arg(raw: u64) -> KeySerial {
    KeySerial::from_raw(raw as u32 as i32)
}

impl SyscallDispatcher {
    define_syscall! {
        /// `add_key(2)`.
        fn add_key(
            this,
            cx,
            type_ptr: GuestPtr,
            description_ptr: GuestPtr,
            payload_ptr: GuestPtr,
            payload_len: u64,
            ring_id: u64,
        ) {
            let _ = this;
            let type_name = read_key_string(&*cx.memory, type_ptr)?;
            validate_type_name(&type_name)?;
            let description = read_key_string(&*cx.memory, description_ptr)?;
            validate_description(&description)?;

            // ENODEV BEFORE the payload copy — see the module docs.
            if !key_type_is_registered(&type_name) {
                return Ok(DispatchOutcome::errno(LINUX_ENODEV));
            }
            let max_payload = key_type_max_payload(&type_name).unwrap_or(0);
            let payload_len = usize::try_from(payload_len).unwrap_or(usize::MAX);
            // The size check precedes the copy both because Linux answers a
            // too-large payload with EINVAL regardless of the pointer, and
            // because it is what stops a bogus length becoming a huge host
            // allocation.
            if payload_len > max_payload {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let payload = read_payload(&*cx.memory, payload_ptr, payload_len)?;

            let scope = KeyScope::capture(cx);
            let caller = scope.caller();
            let destination = scope.resolve(serial_arg(ring_id), true)?;
            let serial = scope
                .service()
                .add_key(&caller, &type_name, &description, &payload, destination)?;
            Ok(DispatchOutcome::Returned {
                value: serial.guest_retval() as i64,
            })
        }

        /// `request_key(2)`.
        ///
        /// carrick has no `/sbin/request-key` upcall, so a request that must
        /// CONSTRUCT a key always fails to; the service negatively instantiates
        /// the key, links it into the destination, and reports `ENOENT` — the
        /// same shape a Linux system with no helper installed produces.
        fn request_key(
            this,
            cx,
            type_ptr: GuestPtr,
            description_ptr: GuestPtr,
            callout_ptr: GuestPtr,
            dest_ring_id: u64,
        ) {
            let _ = this;
            let type_name = read_key_string(&*cx.memory, type_ptr)?;
            validate_type_name(&type_name)?;
            // A `.`-prefixed type names a kernel-internal type userspace may
            // not request (`request_key06` case 3). The check precedes every
            // other lookup, so an internal type never even reveals whether it
            // exists.
            if crate::keyring::is_internal_type(&type_name) {
                return Ok(DispatchOutcome::errno(LINUX_EPERM));
            }
            // Both remaining strings are copied BEFORE the type is resolved —
            // `request_key06` cases 1 and 2 name an unregistered type and still
            // require EFAULT.
            let description = read_key_string(&*cx.memory, description_ptr)?;
            validate_description(&description)?;
            let callout = if callout_ptr.0 == 0 {
                None
            } else {
                let bytes = read_key_string(&*cx.memory, callout_ptr)?;
                if bytes.len() > LINUX_KEY_DESC_MAX_LEN {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                }
                Some(bytes)
            };

            let scope = KeyScope::capture(cx);
            let caller = scope.caller();
            let destination = if serial_arg(dest_ring_id).get() == 0 {
                // Destination 0 defers to the request-key default, and its
                // Write check happens only if construction is actually needed —
                // `request_key04` requires the deferred order.
                scope.request_key_default_ring()?
            } else {
                // A destination the guest named EXPLICITLY is validated up
                // front, so a revoked or expired keyring reports itself
                // (`request_key02` cases 1 and 2 expect EKEYREVOKED and
                // EKEYEXPIRED, not the search's ENOKEY). `request_key(2)`
                // documents Write as the permission required here.
                let named = scope.resolve(serial_arg(dest_ring_id), true)?;
                scope
                    .service()
                    .validate_keyring(&caller, named, KeyRight::Write)?
            };
            let serial = scope.service().request_key(
                &caller,
                &type_name,
                &description,
                callout.as_deref(),
                destination,
            )?;
            Ok(DispatchOutcome::Returned {
                value: serial.guest_retval() as i64,
            })
        }

        /// `keyctl(2)`.
        ///
        /// Note the argument discipline: glibc's and LTP's `keyctl()` wrappers
        /// are variadic and always issue a FIVE-argument syscall, so a call
        /// written as `keyctl(KEYCTL_REVOKE, key)` passes uninitialised garbage
        /// in the remaining registers. Every command therefore reads only the
        /// arguments it actually uses and must never validate the others —
        /// `keyctl01` depends on `KEYCTL_READ` reporting `ENOKEY` for an absent
        /// serial WITHOUT looking at its garbage buffer pointer.
        fn keyctl(this, cx, command: u64, arg2: u64, arg3: u64, arg4: u64, arg5: u64) {
            let _ = this;
            let Some(op) = KeyctlOp::from_raw(command) else {
                // Linux's answer for a command it does not recognise.
                return Ok(DispatchOutcome::errno(LINUX_EOPNOTSUPP));
            };
            keyctl_op(cx, op, [arg2, arg3, arg4, arg5])
        }
    }
}

/// The `keyctl(2)` command switch, split out so each arm stays readable.
fn keyctl_op<M: GuestMemory>(
    cx: &mut SyscallCtx<'_, M>,
    op: KeyctlOp,
    args: [u64; 4],
) -> Result<DispatchOutcome, DispatchError> {
    let [arg2, arg3, arg4, arg5] = args;
    let scope = KeyScope::capture(cx);
    let caller = scope.caller();
    let service = scope.service();
    let ok = || Ok(DispatchOutcome::Returned { value: 0 });

    match op {
        KeyctlOp::GetKeyringId => {
            // arg3 is the `create` flag. LTP calls this with only two arguments
            // (`keyctl01`), so arg3 is garbage there — any non-zero value means
            // create, which is exactly Linux's own `if (create)`.
            let resolved = scope.resolve(serial_arg(arg2), arg3 != 0)?;
            // A named key still has to be reachable by the caller.
            service.validate_keyring(&caller, resolved, KeyRight::Search)?;
            Ok(DispatchOutcome::Returned {
                value: resolved.guest_retval() as i64,
            })
        }

        KeyctlOp::JoinSessionKeyring => {
            let session = if arg2 == 0 {
                // A NULL name means "an anonymous new session keyring", which
                // is how `add_key04` and `keyctl05` isolate themselves.
                service.create_anonymous_keyring(b"_ses", scope.uid, scope.gid)
            } else {
                let name = read_key_string(&*cx.memory, GuestPtr(arg2))?;
                if name.is_empty() || name.len() > LINUX_KEY_DESC_MAX_LEN {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                }
                // `.`-prefixed keyrings are kernel-internal. Joining one would
                // hand the guest the kernel's own trusted keyring, which is
                // CVE-2016-9604 — `keyctl08` is its regression test.
                if crate::keyring::is_internal_type(&name) {
                    return Ok(DispatchOutcome::errno(LINUX_EPERM));
                }
                service.named_session_keyring(&name, scope.uid, scope.gid)?
            };
            scope.join_session(session);
            Ok(DispatchOutcome::Returned {
                value: session.guest_retval() as i64,
            })
        }

        KeyctlOp::Update => {
            let key = scope.resolve(serial_arg(arg2), false)?;
            let length = usize::try_from(arg4).unwrap_or(usize::MAX);
            // Bound the copy the same way `add_key` does, so a garbage length
            // cannot become a host allocation before the permission check.
            if length > carrick_abi::keyring::LINUX_KEY_USER_PAYLOAD_MAX {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let payload = read_payload(&*cx.memory, GuestPtr(arg3), length)?;
            service.update(&caller, key, &payload)?;
            ok()
        }

        KeyctlOp::Revoke => {
            let key = scope.resolve(serial_arg(arg2), false)?;
            service.revoke(&caller, key)?;
            ok()
        }

        KeyctlOp::SetPerm => {
            let key = scope.resolve(serial_arg(arg2), false)?;
            let Some(perm) = KeyPerm::from_bits(arg3 as u32) else {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            };
            service.set_perm(&caller, key, perm)?;
            ok()
        }

        KeyctlOp::Describe => {
            let key = scope.resolve(serial_arg(arg2), false)?;
            let described = service.describe(&caller, key)?;
            let length = usize::try_from(arg4).unwrap_or(usize::MAX);
            write_truncated(cx.memory, GuestPtr(arg3), length, &described.0)
        }

        KeyctlOp::Clear => {
            let ring = scope.resolve(serial_arg(arg2), false)?;
            service.clear(&caller, ring)?;
            ok()
        }

        KeyctlOp::Link => {
            let key = scope.resolve(serial_arg(arg2), false)?;
            let ring = scope.resolve(serial_arg(arg3), false)?;
            service.link(&caller, key, ring)?;
            ok()
        }

        KeyctlOp::Unlink => {
            let key = scope.resolve(serial_arg(arg2), false)?;
            let ring = scope.resolve(serial_arg(arg3), false)?;
            service.unlink(&caller, key, ring)?;
            ok()
        }

        KeyctlOp::Search => {
            let ring = scope.resolve(serial_arg(arg2), false)?;
            let type_name = read_key_string(&*cx.memory, GuestPtr(arg3))?;
            validate_type_name(&type_name)?;
            let description = read_key_string(&*cx.memory, GuestPtr(arg4))?;
            validate_description(&description)?;
            let found = service.search_from(&caller, ring, &type_name, &description)?;
            if serial_arg(arg5).get() != 0 {
                let destination = scope.resolve(serial_arg(arg5), false)?;
                service.link(&caller, found, destination)?;
            }
            Ok(DispatchOutcome::Returned {
                value: found.guest_retval() as i64,
            })
        }

        KeyctlOp::Read => {
            // The resolve MUST come first: `keyctl01` probes serials with a
            // garbage buffer pointer and requires ENOKEY, not EFAULT.
            let key = scope.resolve(serial_arg(arg2), false)?;
            let payload = service.read(&caller, key)?;
            let length = usize::try_from(arg4).unwrap_or(usize::MAX);
            write_truncated(cx.memory, GuestPtr(arg3), length, &payload.0)
        }

        KeyctlOp::SetReqkeyKeyring => {
            let requested = arg2 as u32 as i32;
            let Some(default) = KeyRequestDefault::from_raw(requested) else {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            };
            // The group keyring was never implemented by Linux, so selecting it
            // is EINVAL rather than a setting that would silently never apply.
            if default == KeyRequestDefault::GroupKeyring {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            // This is a pure SETTING change. It must not materialise any
            // keyring: `keyctl04` (CVE-2017-7472) is exactly the regression
            // where it replaced — and leaked — the caller's thread keyring.
            let previous = scope.task.with_keyrings(|keyrings| {
                let previous = keyrings.request_key_default;
                if default != KeyRequestDefault::NoChange {
                    keyrings.request_key_default = default;
                }
                previous
            });
            Ok(DispatchOutcome::Returned {
                value: i64::from(previous.raw()),
            })
        }

        KeyctlOp::SetTimeout => {
            let key = scope.resolve(serial_arg(arg2), false)?;
            service.set_timeout(&caller, key, arg3 as u32 as u64)?;
            ok()
        }

        KeyctlOp::Invalidate => {
            let key = scope.resolve(serial_arg(arg2), false)?;
            service.invalidate(&caller, key)?;
            ok()
        }

        KeyctlOp::Chown => {
            // Changing a key's owner needs privileges carrick does not model,
            // and Linux itself refuses a non-root chown to another user.
            let key = scope.resolve(serial_arg(arg2), false)?;
            service.validate_keyring(&caller, key, KeyRight::SetAttr)?;
            Ok(DispatchOutcome::errno(LINUX_EACCES))
        }

        // Commands whose backing capability carrick genuinely does not have:
        // key instantiation from an upcall, DH/public-key crypto, persistent
        // keyrings, LSM labels, keyring restrictions and key watches. Linux
        // reports an unsupported keyctl command as EOPNOTSUPP, which is the
        // honest answer for each of these.
        KeyctlOp::Instantiate
        | KeyctlOp::Negate
        | KeyctlOp::AssumeAuthority
        | KeyctlOp::GetSecurity
        | KeyctlOp::SessionToParent
        | KeyctlOp::Reject
        | KeyctlOp::InstantiateIov
        | KeyctlOp::GetPersistent
        | KeyctlOp::DhCompute
        | KeyctlOp::PkeyQuery
        | KeyctlOp::PkeyEncrypt
        | KeyctlOp::PkeyDecrypt
        | KeyctlOp::PkeySign
        | KeyctlOp::PkeyVerify
        | KeyctlOp::RestrictKeyring
        | KeyctlOp::Move
        | KeyctlOp::Capabilities
        | KeyctlOp::WatchKey => Ok(DispatchOutcome::errno(LINUX_EOPNOTSUPP)),
    }
}
