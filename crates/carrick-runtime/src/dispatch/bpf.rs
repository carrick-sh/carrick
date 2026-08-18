//! `bpf(2)`: eBPF maps (hash + array) and structurally-validated program
//! loading.
//!
//! # Scope, honestly stated
//!
//! carrick implements the map surface for real — `BPF_MAP_CREATE`
//! (`BPF_MAP_TYPE_HASH` and `BPF_MAP_TYPE_ARRAY`), `BPF_MAP_LOOKUP_ELEM`,
//! `BPF_MAP_UPDATE_ELEM`, `BPF_MAP_DELETE_ELEM`, `BPF_MAP_GET_NEXT_KEY` —
//! with Linux's element semantics (pre-allocated zeroed arrays, `BPF_ANY`/
//! `BPF_NOEXIST`/`BPF_EXIST`, `E2BIG`/`EEXIST`/`ENOENT` per `bpf(2)`).
//!
//! `BPF_PROG_LOAD` accepts `BPF_PROG_TYPE_SOCKET_FILTER` and validates the
//! instruction stream STRUCTURALLY (encoding, register bounds, `ld_imm64`
//! pairing, jump targets, fall-off-the-end) but performs NO data-flow
//! verification and NEVER EXECUTES a program: the returned fd is a loaded
//! object that can be held, dup'd and closed — the surface the LTP bpf suites
//! exercise short of attachment. A program Linux's verifier would reject on
//! semantic grounds (pointer arithmetic, helper contracts) loads successfully
//! here; a program that needs to RUN (`SO_ATTACH_BPF`) finds no support in
//! carrick's setsockopt. Commands beyond the list above (`BPF_OBJ_PIN`,
//! `BPF_PROG_ATTACH`, …) answer `EINVAL`, the shape of an older kernel
//! without them.
//!
//! # Privilege model
//!
//! The oracle kernel (linuxkit, `unprivileged_bpf_disabled=0`) allows
//! unprivileged map creation and socket-filter loading; the `EPERM` the LTP
//! bpf suites observe under plain `docker run` comes from DOCKER'S DEFAULT
//! SECCOMP PROFILE, not from a kernel capability check (verified 2026-08-18:
//! `--security-opt seccomp=unconfined` with default caps runs all eight
//! suites to full TPASS). carrick mirrors that split exactly as the keyring
//! subsystem does: these handlers answer with real kernel semantics, and the
//! Docker-default `EPERM` lives in [`crate::container_policy`] — the launch
//! policy seam — never here.
//!
//! # State authority
//!
//! Map contents live in an `Arc`'d object inside the fd's `OpenDescription`,
//! so `dup`/`fork` inside one HVPatch carrier share one map, as Linux shares
//! the kernel object behind the fd. On the lanes where a guest fork is a HOST
//! fork the copies diverge — the same limitation as any in-memory fd state;
//! the LTP bpf suites are single-process. Divergences from exact Linux
//! behaviour (unchecked attr tail bytes, no `BPF_F_*` map flags, no memlock
//! accounting) are named at their sites.

use super::*;
use crate::linux_abi::LinuxErrno;
use carrick_abi::bpf::{
    BPF_INSN_SIZE, BPF_MAX_REG, BpfCmd, BpfElemAttr, BpfInsn, BpfMapCreateAttr, BpfMapType,
    BpfProgLoadAttr, BpfProgType, BpfUpdateFlags, LINUX_BPF_MAXINSNS,
};
use std::collections::BTreeMap;

syscall_table! {
    /// Routing for `bpf(2)` (canonical/aarch64 280; x86_64 321 remaps at the
    /// GuestArch seam).
    pub(crate) fn dispatch_bpf;
    280 => bpf,
}

/// The attr prefix carrick reads: through `kern_version`@40 (the last
/// `BPF_PROG_LOAD` field it consults). Linux additionally demands the bytes
/// BEYOND the fields a command uses be zero; carrick does not check the tail
/// (divergence — a nonzero stray field that Linux would `EINVAL` is ignored).
const MAX_ATTR_BYTES: usize = 48;

/// Guard rails on map geometry, in place of Linux's allocator/memlock limits
/// (carrick does no memlock accounting). Oversize geometry answers `E2BIG`
/// like a map that exceeds the kernel's limits.
const MAX_KEY_SIZE: u32 = 4096;
const MAX_VALUE_SIZE: u32 = 1 << 22; // 4 MiB
const MAX_TOTAL_BYTES: u64 = 256 << 20; // 256 MiB per map

/// A live eBPF map: immutable geometry plus mutex-guarded contents. Shared
/// (`Arc`) by every fd slot that refers to the map object.
#[derive(Debug)]
pub(crate) struct BpfMap {
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    contents: Mutex<BpfMapContents>,
}

/// Map contents. Hash keys iterate in byte-sorted order (a `BTreeMap`), which
/// satisfies `BPF_MAP_GET_NEXT_KEY`'s contract — some stable order visiting
/// every element — without matching Linux's (unspecified) bucket order.
#[derive(Debug)]
enum BpfMapContents {
    /// Every element pre-allocated and zero-initialised at create
    /// (`max_entries * value_size` bytes), as Linux array maps are.
    Array(Vec<u8>),
    Hash(BTreeMap<Vec<u8>, Vec<u8>>),
}

impl BpfMap {
    /// Validate geometry and build the map. Errno choices are `bpf(2)`'s:
    /// invalid attributes `EINVAL`, over-limit geometry `E2BIG`.
    fn create(attr: &BpfMapCreateAttr, map_type: BpfMapType) -> Result<Self, LinuxErrno> {
        // carrick models no BPF_F_* map flags; an unknown-to-this-kernel flag
        // is EINVAL on Linux too. (Divergence: flags Linux DOES know, e.g.
        // BPF_F_NO_PREALLOC, are also refused here.)
        if attr.map_flags != 0 {
            return Err(LINUX_EINVAL);
        }
        match map_type {
            // Array maps index by a 4-byte key exactly (bpf(2)).
            BpfMapType::Array if attr.key_size != 4 => return Err(LINUX_EINVAL),
            BpfMapType::Hash if attr.key_size == 0 => return Err(LINUX_EINVAL),
            _ => {}
        }
        if attr.value_size == 0 || attr.max_entries == 0 {
            return Err(LINUX_EINVAL);
        }
        if attr.key_size > MAX_KEY_SIZE || attr.value_size > MAX_VALUE_SIZE {
            return Err(crate::linux_abi::LINUX_E2BIG);
        }
        let per_entry = u64::from(attr.key_size) + u64::from(attr.value_size);
        if per_entry.saturating_mul(u64::from(attr.max_entries)) > MAX_TOTAL_BYTES {
            return Err(crate::linux_abi::LINUX_E2BIG);
        }
        let contents = match map_type {
            BpfMapType::Array => {
                BpfMapContents::Array(vec![0u8; (attr.value_size * attr.max_entries) as usize])
            }
            BpfMapType::Hash => BpfMapContents::Hash(BTreeMap::new()),
        };
        Ok(Self {
            key_size: attr.key_size,
            value_size: attr.value_size,
            max_entries: attr.max_entries,
            contents: Mutex::new(contents),
        })
    }

    pub(crate) fn key_size(&self) -> u32 {
        self.key_size
    }

    /// An array key is a 4-byte little-endian index (`bpf(2)`).
    fn array_index(key: &[u8]) -> u64 {
        let mut raw = [0u8; 4];
        raw.copy_from_slice(&key[..4]);
        u64::from(u32::from_le_bytes(raw))
    }

    /// `BPF_MAP_LOOKUP_ELEM`: the element's bytes, or `ENOENT`.
    fn lookup(&self, key: &[u8]) -> Result<Vec<u8>, LinuxErrno> {
        let contents = self.contents.lock();
        match &*contents {
            BpfMapContents::Array(values) => {
                let index = Self::array_index(key);
                if index >= u64::from(self.max_entries) {
                    return Err(crate::linux_abi::LINUX_ENOENT);
                }
                let start = (index * u64::from(self.value_size)) as usize;
                Ok(values[start..start + self.value_size as usize].to_vec())
            }
            BpfMapContents::Hash(entries) => entries
                .get(key)
                .cloned()
                .ok_or(crate::linux_abi::LINUX_ENOENT),
        }
    }

    /// `BPF_MAP_UPDATE_ELEM` (`bpf(2)`): array — out-of-range `E2BIG`,
    /// `BPF_NOEXIST` `EEXIST` (every array element always exists); hash —
    /// `BPF_NOEXIST`+present `EEXIST`, `BPF_EXIST`+absent `ENOENT`, a fresh
    /// insert beyond `max_entries` `E2BIG`.
    fn update(&self, key: &[u8], value: &[u8], flags: BpfUpdateFlags) -> Result<(), LinuxErrno> {
        let mut contents = self.contents.lock();
        match &mut *contents {
            BpfMapContents::Array(values) => {
                let index = Self::array_index(key);
                if index >= u64::from(self.max_entries) {
                    return Err(crate::linux_abi::LINUX_E2BIG);
                }
                if flags == BpfUpdateFlags::NoExist {
                    return Err(crate::linux_abi::LINUX_EEXIST);
                }
                let start = (index * u64::from(self.value_size)) as usize;
                values[start..start + self.value_size as usize].copy_from_slice(value);
                Ok(())
            }
            BpfMapContents::Hash(entries) => {
                let present = entries.contains_key(key);
                match flags {
                    BpfUpdateFlags::NoExist if present => {
                        return Err(crate::linux_abi::LINUX_EEXIST);
                    }
                    BpfUpdateFlags::Exist if !present => {
                        return Err(crate::linux_abi::LINUX_ENOENT);
                    }
                    _ => {}
                }
                if !present && entries.len() as u64 >= u64::from(self.max_entries) {
                    return Err(crate::linux_abi::LINUX_E2BIG);
                }
                entries.insert(key.to_vec(), value.to_vec());
                Ok(())
            }
        }
    }

    /// `BPF_MAP_DELETE_ELEM`: hash removes (`ENOENT` when absent); array
    /// elements cannot be deleted — `EINVAL` (`bpf(2)`).
    fn delete(&self, key: &[u8]) -> Result<(), LinuxErrno> {
        let mut contents = self.contents.lock();
        match &mut *contents {
            BpfMapContents::Array(_) => Err(LINUX_EINVAL),
            BpfMapContents::Hash(entries) => match entries.remove(key) {
                Some(_) => Ok(()),
                None => Err(crate::linux_abi::LINUX_ENOENT),
            },
        }
    }

    /// `BPF_MAP_GET_NEXT_KEY` (`bpf(2)`): the key after `key`; a `key` not in
    /// the map yields the FIRST key; the last key (or an empty map) is
    /// `ENOENT`.
    fn next_key(&self, key: &[u8]) -> Result<Vec<u8>, LinuxErrno> {
        let contents = self.contents.lock();
        match &*contents {
            BpfMapContents::Array(_) => {
                let index = Self::array_index(key);
                let max = u64::from(self.max_entries);
                let next = if index >= max { 0 } else { index + 1 };
                if next >= max {
                    return Err(crate::linux_abi::LINUX_ENOENT);
                }
                Ok((next as u32).to_le_bytes().to_vec())
            }
            BpfMapContents::Hash(entries) => {
                let next = if entries.contains_key(key) {
                    entries
                        .range::<[u8], _>((
                            std::ops::Bound::Excluded(key),
                            std::ops::Bound::Unbounded,
                        ))
                        .next()
                } else {
                    // Absent key ⇒ start of the iteration.
                    entries.iter().next()
                };
                next.map(|(next_key, _)| next_key.clone())
                    .ok_or(crate::linux_abi::LINUX_ENOENT)
            }
        }
    }
}

/// A loaded eBPF program object: metadata only. carrick never executes eBPF —
/// the object exists so the fd lifecycle (`dup`/`close`/proc introspection)
/// behaves; attachment surfaces reject it honestly.
#[derive(Debug)]
pub(crate) struct BpfProg {
    #[allow(dead_code)]
    prog_type: BpfProgType,
    #[allow(dead_code)]
    insn_count: u32,
}

/// A program rejection: the errno plus the one-line log message written to the
/// caller's verifier log buffer. Errno split per `bpf(2)` ERRORS: malformed
/// encodings are `EINVAL` ("the program is invalid"); ill-formed control flow
/// is `EACCES` ("deemed unsafe" — the verifier-rejection shape).
struct ProgRejection {
    errno: LinuxErrno,
    log: &'static str,
}

/// Structural validation of an instruction stream. NOT a verifier: no
/// data-flow, no pointer tracking, no helper contracts — see the module docs
/// for what that means for semantically-unsafe programs.
fn validate_program(insns: &[BpfInsn]) -> Result<(), ProgRejection> {
    let count = insns.len();
    let mut i = 0usize;
    while i < count {
        let insn = insns[i];
        if insn.dst_reg() > BPF_MAX_REG || insn.src_reg() > BPF_MAX_REG {
            return Err(ProgRejection {
                errno: LINUX_EINVAL,
                log: "invalid register number",
            });
        }
        if insn.is_ld_imm64() {
            // 16-byte immediate load: the next slot is its continuation.
            if i + 1 >= count {
                return Err(ProgRejection {
                    errno: LINUX_EINVAL,
                    log: "incomplete ld_imm64 instruction",
                });
            }
            i += 2;
            continue;
        }
        if insn.class().is_jump() && !insn.is_call() && !insn.is_exit() {
            let target = i as i64 + 1 + i64::from(insn.off);
            if target < 0 || target >= count as i64 {
                return Err(ProgRejection {
                    errno: crate::linux_abi::LINUX_EACCES,
                    log: "jump out of range",
                });
            }
        }
        i += 1;
    }
    // Execution must not fall off the end: the final instruction has to be an
    // exit or an unconditional jump (`BPF_JMP | BPF_JA` = 0x05).
    let last = insns[count - 1];
    if !last.is_exit() && last.code != 0x05 {
        return Err(ProgRejection {
            errno: crate::linux_abi::LINUX_EACCES,
            log: "program does not end with exit",
        });
    }
    Ok(())
}

/// Write the load log into the guest's buffer (NUL-terminated, truncated to
/// `log_size`), when one was requested. Best-effort: the load's own verdict
/// is not displaced by a log-write fault.
fn write_prog_log<M: GuestMemory>(memory: &mut M, attr: &BpfProgLoadAttr, message: &str) {
    if attr.log_level == 0 || attr.log_buf == 0 || attr.log_size == 0 {
        return;
    }
    let capacity = attr.log_size as usize;
    let mut bytes = message.as_bytes()[..message.len().min(capacity - 1)].to_vec();
    bytes.push(0);
    let _ = memory.write_bytes(attr.log_buf, &bytes);
}

impl SyscallDispatcher {
    /// Resolve a guest fd to its live map object. Not an open fd → `EBADF`;
    /// an fd of some other kind → `EINVAL` (it is a valid descriptor, just
    /// not a bpf map).
    fn bpf_map_fd(&self, fd: i32) -> Result<Arc<BpfMap>, LinuxErrno> {
        let open_file = self.open_file(fd).ok_or(LINUX_EBADF)?;
        let open = open_file.description.read();
        match &*open {
            OpenDescription::BpfMap { map, .. } => Ok(map.clone()),
            _ => Err(LINUX_EINVAL),
        }
    }

    /// Install an anonymous bpf object fd. Linux creates bpf fds
    /// close-on-exec (`bpf(2)`).
    fn install_bpf_fd(&self, description: OpenDescription) -> Result<i32, LinuxErrno> {
        let open_file = OpenFile::from_open_description(
            std::sync::Arc::new(parking_lot::RwLock::new(description)),
            linux_fd_flags_from_open_flags(carrick_abi::LINUX_O_CLOEXEC),
        );
        self.install_fd_at_or_above(0, open_file)
            .map_err(|_| crate::dispatch::linux_errno::EMFILE)
    }

    define_syscall! {
        /// `bpf(cmd, attr, size)`. Commands beyond the implemented set answer
        /// `EINVAL` (the older-kernel shape); see the module docs for the
        /// exact surface and its honesty boundaries.
        fn bpf(this, cx, cmd: u64, attr_ptr: GuestPtr, size: u64) {
            let Some(cmd) = BpfCmd::from_raw(cmd) else {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            };
            if attr_ptr.0 == 0 {
                return Ok(DispatchOutcome::errno(LINUX_EFAULT));
            }
            // Read the prefix of the guest's attr that carrick consults; a
            // guest passing a SHORTER attr (older userspace headers) gets the
            // absent fields as zero, like Linux. Bytes past MAX_ATTR_BYTES
            // are not examined (divergence noted at MAX_ATTR_BYTES).
            let attr_len = usize::try_from(size).unwrap_or(usize::MAX).min(MAX_ATTR_BYTES);
            let attr_bytes = cx.memory.read_bytes(attr_ptr.0, attr_len)?;

            match cmd {
                BpfCmd::MapCreate => {
                    let attr = BpfMapCreateAttr::parse(&attr_bytes);
                    // Type lookup precedes geometry checks: an unknown map
                    // type is EINVAL regardless of the other fields.
                    let Some(map_type) = BpfMapType::from_raw(attr.map_type) else {
                        return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                    };
                    let map = BpfMap::create(&attr, map_type)?;
                    let description = OpenDescription::BpfMap {
                        base: OpenDescriptionBase::new(carrick_abi::LINUX_O_RDWR),
                        map: Arc::new(map),
                    };
                    let fd = this.install_bpf_fd(description)?;
                    Ok(DispatchOutcome::Returned { value: fd as i64 })
                }

                BpfCmd::MapLookupElem => {
                    let attr = BpfElemAttr::parse(&attr_bytes);
                    let map = this.bpf_map_fd(attr.map_fd as i32)?;
                    let key = cx.memory.read_bytes(attr.key, map.key_size() as usize)?;
                    let value = map.lookup(&key)?;
                    cx.memory.write_bytes(attr.value_or_next_key, &value)?;
                    Ok(DispatchOutcome::Returned { value: 0 })
                }

                BpfCmd::MapUpdateElem => {
                    let attr = BpfElemAttr::parse(&attr_bytes);
                    let Some(flags) = BpfUpdateFlags::from_raw(attr.flags) else {
                        return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                    };
                    let map = this.bpf_map_fd(attr.map_fd as i32)?;
                    let key = cx.memory.read_bytes(attr.key, map.key_size() as usize)?;
                    let value = cx
                        .memory
                        .read_bytes(attr.value_or_next_key, map.value_size as usize)?;
                    map.update(&key, &value, flags)?;
                    Ok(DispatchOutcome::Returned { value: 0 })
                }

                BpfCmd::MapDeleteElem => {
                    let attr = BpfElemAttr::parse(&attr_bytes);
                    let map = this.bpf_map_fd(attr.map_fd as i32)?;
                    let key = cx.memory.read_bytes(attr.key, map.key_size() as usize)?;
                    map.delete(&key)?;
                    Ok(DispatchOutcome::Returned { value: 0 })
                }

                BpfCmd::MapGetNextKey => {
                    let attr = BpfElemAttr::parse(&attr_bytes);
                    let map = this.bpf_map_fd(attr.map_fd as i32)?;
                    let key = cx.memory.read_bytes(attr.key, map.key_size() as usize)?;
                    let next = map.next_key(&key)?;
                    cx.memory.write_bytes(attr.value_or_next_key, &next)?;
                    Ok(DispatchOutcome::Returned { value: 0 })
                }

                BpfCmd::ProgLoad => {
                    let attr = BpfProgLoadAttr::parse(&attr_bytes);
                    let Some(prog_type) = BpfProgType::from_raw(attr.prog_type) else {
                        return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                    };
                    if attr.insn_cnt == 0 {
                        return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                    }
                    if attr.insn_cnt > LINUX_BPF_MAXINSNS {
                        return Ok(DispatchOutcome::errno(crate::linux_abi::LINUX_E2BIG));
                    }
                    let raw = cx
                        .memory
                        .read_bytes(attr.insns, attr.insn_cnt as usize * BPF_INSN_SIZE)?;
                    // The license string is read (and must be readable —
                    // EFAULT otherwise) but not interpreted: carrick models no
                    // GPL-gated helpers.
                    let _license = read_guest_c_string_bytes(&*cx.memory, attr.license)?;
                    let insns: Vec<BpfInsn> = raw
                        .chunks_exact(BPF_INSN_SIZE)
                        .map(|chunk| {
                            let mut bytes = [0u8; BPF_INSN_SIZE];
                            bytes.copy_from_slice(chunk);
                            BpfInsn::parse(&bytes)
                        })
                        .collect();
                    match validate_program(&insns) {
                        Err(rejection) => {
                            write_prog_log(cx.memory, &attr, rejection.log);
                            Ok(DispatchOutcome::errno(rejection.errno))
                        }
                        Ok(()) => {
                            // Loaded. An empty log tells the caller validation
                            // recorded nothing (Linux writes its verifier
                            // trace here; carrick has none to give).
                            write_prog_log(cx.memory, &attr, "");
                            let description = OpenDescription::BpfProg {
                                base: OpenDescriptionBase::new(carrick_abi::LINUX_O_RDWR),
                                prog: Arc::new(BpfProg {
                                    prog_type,
                                    insn_count: attr.insn_cnt,
                                }),
                            };
                            let fd = this.install_bpf_fd(description)?;
                            Ok(DispatchOutcome::Returned { value: fd as i64 })
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn array_map(max_entries: u32, value_size: u32) -> BpfMap {
        BpfMap::create(
            &BpfMapCreateAttr {
                map_type: BpfMapType::Array as u32,
                key_size: 4,
                value_size,
                max_entries,
                map_flags: 0,
            },
            BpfMapType::Array,
        )
        .expect("array map geometry is valid")
    }

    fn hash_map(max_entries: u32, key_size: u32, value_size: u32) -> BpfMap {
        BpfMap::create(
            &BpfMapCreateAttr {
                map_type: BpfMapType::Hash as u32,
                key_size,
                value_size,
                max_entries,
                map_flags: 0,
            },
            BpfMapType::Hash,
        )
        .expect("hash map geometry is valid")
    }

    #[test]
    fn create_validates_geometry() {
        // Array demands a 4-byte key.
        let bad_key = BpfMapCreateAttr {
            map_type: 2,
            key_size: 8,
            value_size: 8,
            max_entries: 1,
            map_flags: 0,
        };
        assert_eq!(
            BpfMap::create(&bad_key, BpfMapType::Array).err(),
            Some(LINUX_EINVAL)
        );
        // Zero geometry is EINVAL.
        let zero_entries = BpfMapCreateAttr {
            max_entries: 0,
            key_size: 4,
            ..bad_key
        };
        assert_eq!(
            BpfMap::create(&zero_entries, BpfMapType::Array).err(),
            Some(LINUX_EINVAL)
        );
        // Unmodeled map flags are EINVAL.
        let flags = BpfMapCreateAttr {
            key_size: 4,
            map_flags: 1,
            ..bad_key
        };
        assert_eq!(
            BpfMap::create(&flags, BpfMapType::Array).err(),
            Some(LINUX_EINVAL)
        );
        // Over-guard-rail geometry is E2BIG.
        let huge = BpfMapCreateAttr {
            map_type: 1,
            key_size: 8,
            value_size: 1 << 20,
            max_entries: 1 << 20,
            map_flags: 0,
        };
        assert_eq!(
            BpfMap::create(&huge, BpfMapType::Hash).err(),
            Some(crate::linux_abi::LINUX_E2BIG)
        );
    }

    #[test]
    fn array_map_is_preallocated_and_zeroed() {
        // bpf_map01's array assertions: a fresh array element reads back
        // all-zero, an update round-trips.
        let map = array_map(1, 1024);
        let key = 0u32.to_le_bytes();
        assert_eq!(map.lookup(&key).expect("index 0 exists"), vec![0u8; 1024]);
        let value: Vec<u8> = (0..1024u32).map(|i| (i % 256) as u8).collect();
        map.update(&key, &value, BpfUpdateFlags::Any)
            .expect("update in range");
        assert_eq!(map.lookup(&key).expect("index 0 exists"), value);
    }

    #[test]
    fn array_map_errno_shape() {
        let map = array_map(2, 8);
        let oob = 2u32.to_le_bytes();
        // Lookup past the end: ENOENT. Update past the end: E2BIG (bpf(2)).
        assert_eq!(map.lookup(&oob).err(), Some(crate::linux_abi::LINUX_ENOENT));
        assert_eq!(
            map.update(&oob, &[0u8; 8], BpfUpdateFlags::Any).err(),
            Some(crate::linux_abi::LINUX_E2BIG)
        );
        // Every array element always exists: NOEXIST is EEXIST, delete EINVAL.
        let key = 0u32.to_le_bytes();
        assert_eq!(
            map.update(&key, &[0u8; 8], BpfUpdateFlags::NoExist).err(),
            Some(crate::linux_abi::LINUX_EEXIST)
        );
        assert_eq!(map.delete(&key).err(), Some(LINUX_EINVAL));
        // EXIST on an in-range element succeeds.
        map.update(&key, &[7u8; 8], BpfUpdateFlags::Exist)
            .expect("array elements always exist");
    }

    #[test]
    fn hash_map_state_machine() {
        // bpf_map01's hash assertions: empty lookup ENOENT, update+lookup
        // round-trips.
        let map = hash_map(2, 8, 16);
        let key = *b"12345678";
        assert_eq!(map.lookup(&key).err(), Some(crate::linux_abi::LINUX_ENOENT));
        // EXIST on a missing key: ENOENT.
        assert_eq!(
            map.update(&key, &[1u8; 16], BpfUpdateFlags::Exist).err(),
            Some(crate::linux_abi::LINUX_ENOENT)
        );
        map.update(&key, &[1u8; 16], BpfUpdateFlags::Any)
            .expect("fresh insert");
        assert_eq!(map.lookup(&key).expect("present"), vec![1u8; 16]);
        // NOEXIST on a present key: EEXIST.
        assert_eq!(
            map.update(&key, &[2u8; 16], BpfUpdateFlags::NoExist).err(),
            Some(crate::linux_abi::LINUX_EEXIST)
        );
        // Fill to max_entries, then a fresh insert is E2BIG.
        map.update(b"aaaaaaaa", &[3u8; 16], BpfUpdateFlags::NoExist)
            .expect("second insert fits");
        assert_eq!(
            map.update(b"bbbbbbbb", &[4u8; 16], BpfUpdateFlags::Any)
                .err(),
            Some(crate::linux_abi::LINUX_E2BIG)
        );
        // Delete: present ok, absent ENOENT.
        map.delete(&key).expect("present");
        assert_eq!(map.delete(&key).err(), Some(crate::linux_abi::LINUX_ENOENT));
    }

    #[test]
    fn get_next_key_iterates_and_terminates() {
        // Hash: absent key starts iteration; the last key is ENOENT.
        let map = hash_map(4, 4, 4);
        assert_eq!(
            map.next_key(&[0u8; 4]).err(),
            Some(crate::linux_abi::LINUX_ENOENT),
            "empty map has no first key"
        );
        for byte in [3u8, 1, 2] {
            map.update(&[byte; 4], &[0u8; 4], BpfUpdateFlags::Any)
                .expect("inserts fit");
        }
        let mut seen = Vec::new();
        let mut cursor = vec![0xffu8; 4]; // not a member: yields the first key
        while let Ok(next) = map.next_key(&cursor) {
            seen.push(next.clone());
            cursor = next;
        }
        assert_eq!(seen, vec![vec![1u8; 4], vec![2u8; 4], vec![3u8; 4]]);

        // Array: index+1 until the end; an out-of-range cursor restarts.
        let map = array_map(3, 4);
        assert_eq!(
            map.next_key(&0u32.to_le_bytes()).expect("has next"),
            1u32.to_le_bytes().to_vec()
        );
        assert_eq!(
            map.next_key(&9u32.to_le_bytes()).expect("restarts"),
            0u32.to_le_bytes().to_vec()
        );
        assert_eq!(
            map.next_key(&2u32.to_le_bytes()).err(),
            Some(crate::linux_abi::LINUX_ENOENT)
        );
    }

    /// Encode (code, regs, off, imm) the wire way.
    fn insn(code: u8, dst: u8, src: u8, off: i16, imm: i32) -> BpfInsn {
        let mut bytes = [0u8; BPF_INSN_SIZE];
        bytes[0] = code;
        bytes[1] = (src << 4) | (dst & 0x0f);
        bytes[2..4].copy_from_slice(&off.to_le_bytes());
        bytes[4..8].copy_from_slice(&imm.to_le_bytes());
        BpfInsn::parse(&bytes)
    }

    #[test]
    fn validator_accepts_the_ltp_return_zero_program() {
        // bpf_prog01's shape: mov r0, 0; exit (plus a map write via
        // ld_imm64+call in the full version).
        let prog = vec![
            insn(0xb7, 0, 0, 0, 0), // MOV64_IMM r0, 0
            insn(0x95, 0, 0, 0, 0), // EXIT
        ];
        assert!(validate_program(&prog).is_ok());
        // With an ld_imm64 pair and a helper call, as BPF_MAP_ARRAY_STX emits.
        let prog = vec![
            insn(0x18, 1, 1, 0, 3),  // LD_MAP_FD r1, 3 (first half)
            insn(0x00, 0, 0, 0, 0),  //   continuation
            insn(0xbf, 2, 10, 0, 0), // MOV64_REG r2, r10
            insn(0x07, 2, 0, 0, -4), // ALU64_IMM add r2, -4
            insn(0x62, 2, 0, 0, 0),  // ST_MEM w [r2+0], 0
            insn(0x85, 0, 0, 0, 1),  // CALL map_lookup_elem
            insn(0x55, 0, 0, 1, 0),  // JNE r0, 0, +1
            insn(0x95, 0, 0, 0, 0),  // EXIT
            insn(0x7b, 0, 8, 0, 0),  // STX_MEM dw [r0+0], r8
            insn(0xb7, 0, 0, 0, 0),  // MOV64_IMM r0, 0
            insn(0x95, 0, 0, 0, 0),  // EXIT
        ];
        assert!(validate_program(&prog).is_ok());
    }

    #[test]
    fn validator_rejects_structural_garbage() {
        // Register out of range: EINVAL (malformed encoding).
        let bad_reg = vec![insn(0xb7, 12, 0, 0, 0), insn(0x95, 0, 0, 0, 0)];
        assert_eq!(
            validate_program(&bad_reg).err().map(|r| r.errno),
            Some(LINUX_EINVAL)
        );
        // ld_imm64 with no continuation slot: EINVAL.
        let short_ld = vec![insn(0x18, 1, 0, 0, 3)];
        assert_eq!(
            validate_program(&short_ld).err().map(|r| r.errno),
            Some(LINUX_EINVAL)
        );
        // Jump past the end: EACCES (verifier-rejection shape).
        let wild_jump = vec![insn(0x55, 0, 0, 5, 0), insn(0x95, 0, 0, 0, 0)];
        assert_eq!(
            validate_program(&wild_jump).err().map(|r| r.errno),
            Some(crate::linux_abi::LINUX_EACCES)
        );
        // Falling off the end: EACCES.
        let no_exit = vec![insn(0xb7, 0, 0, 0, 0)];
        assert_eq!(
            validate_program(&no_exit).err().map(|r| r.errno),
            Some(crate::linux_abi::LINUX_EACCES)
        );
    }
}
