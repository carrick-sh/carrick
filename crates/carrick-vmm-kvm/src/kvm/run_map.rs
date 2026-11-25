//! One vCPU fd and its mmap'd `kvm_run`, owned as one unit (#2962).
//!
//! While a run admits kicks, another host thread may store the mapping's
//! `immediate_exit` byte at any moment (an atomic store under the HAL's run
//! window lock). A Rust reference to the whole `kvm_run` that overlaps such a
//! store is undefined behaviour, and kvm-ioctls forms exactly that reference in
//! `VcpuFd::run`, `get_kvm_run`, `set_kvm_immediate_exit`, `sync_regs` and the
//! sync-register setters. So:
//!
//! - [`KvmVcpuFd`] is built once from a fresh `VcpuFd`. Its fields are private,
//!   so no code outside this module can reach a `&mut VcpuFd`, which makes every
//!   `&mut self` kvm-ioctls accessor over the mapping unreachable. The fd and its
//!   mapping move together (into the vCPU slot, the recycle pool and the
//!   reclaim swap) and cannot be separated.
//! - [`KvmRunMap`] is the only code that touches the mapping. It reaches it
//!   through raw field projections, and `immediate_exit` only as an atomic.
//! - `VcpuFd::sync_regs`, the one `&self` kvm-ioctls accessor over the mapping,
//!   is never called. `tests::kvm_run_is_reached_only_through_run_map` holds
//!   that, and every other accessor, at zero uses outside this module.

use std::os::fd::AsRawFd;
use std::ptr::NonNull;
use std::sync::atomic::{AtomicU8, Ordering};

use kvm_ioctls::VcpuFd;

/// `KVM_RUN`, `_IO(KVMIO, 0x80)` with `KVMIO = 0xAE` (Linux KVM API, 4.10).
/// [`KvmVcpuFd::enter`] issues it directly: `kvm_ioctls::VcpuFd::run` decodes
/// the exit through a `&mut kvm_run` that covers `immediate_exit`.
const KVM_RUN_REQUEST: u64 = 0xAE80;

/// A vCPU fd and the `kvm_run` mapping it owns, inseparable.
pub(crate) struct KvmVcpuFd {
    fd: VcpuFd,
    run: KvmRunMap,
}

impl Drop for KvmVcpuFd {
    fn drop(&mut self) {
        // Before `fd` unmaps the mapping: no kick window may keep its byte.
        self.run.revoke_kick();
    }
}

impl KvmVcpuFd {
    /// Take ownership of a vCPU fd no run has entered yet.
    ///
    /// No run of `fd` has admitted a kick, so nothing else can store its
    /// mapping now: this is the one place a reference to the whole `kvm_run`
    /// exists, and it ends before this returns.
    pub(crate) fn new(mut fd: VcpuFd) -> Self {
        let run = KvmRunMap {
            run: NonNull::from(fd.get_kvm_run()),
            #[cfg(target_arch = "x86_64")]
            published: std::sync::Mutex::new(None),
        };
        Self { fd, run }
    }

    /// The fd, for the ioctls that do not touch the mapping
    /// (`KVM_GET_REGS`, `KVM_SET_SREGS`, …).
    pub(crate) fn fd(&self) -> &VcpuFd {
        &self.fd
    }

    /// The fd's `kvm_run` mapping.
    pub(crate) fn run_map(&self) -> &KvmRunMap {
        &self.run
    }

    /// Issue one `KVM_RUN` and copy out the exit it completed.
    ///
    /// The single owning thread calls this; kicks may store `immediate_exit`
    /// throughout, which is why the exit is read field by field.
    pub(crate) fn enter(&self) -> std::io::Result<RawKvmExit> {
        // SAFETY: `fd` is this vCPU's open fd and KVM_RUN takes no argument;
        // the kernel writes the exit record into this fd's mapping.
        let ret = unsafe { libc::ioctl(self.fd.as_raw_fd(), KVM_RUN_REQUEST as _, 0) };
        if ret != 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: KVM_RUN returned 0, so the mapping holds a complete exit
        // record naming its valid union member.
        Ok(unsafe { RawKvmExit::copy_out(self.run.run.as_ptr()) })
    }
}

/// The mmap'd `kvm_run` of the [`KvmVcpuFd`] that holds it.
///
/// Only a [`KvmVcpuFd`] constructs one, from its own fd, and it is reachable
/// only by borrowing that `KvmVcpuFd`, so the mapping outlives every use.
pub(crate) struct KvmRunMap {
    run: NonNull<kvm_bindings::kvm_run>,
    /// The kick window this mapping's `immediate_exit` byte was last
    /// published into ([`Self::arm_kick`]). Revoked when the pair is
    /// recycled ([`Self::revoke_kick`]) or dropped, so no window outlives the
    /// mapping or reaches its next owner, on any path out of a run.
    #[cfg(target_arch = "x86_64")]
    published: std::sync::Mutex<Option<carrick_hal::posix_signal_kick::RunPublication>>,
}

// SAFETY: the pointer targets the mapping owned by the `VcpuFd` this map is
// paired with in a `KvmVcpuFd`; the two move between threads together, and the
// mapping is reached only through raw projections and atomics.
unsafe impl Send for KvmRunMap {}

impl KvmRunMap {
    fn immediate_exit_ptr(&self) -> *mut u8 {
        // SAFETY: a field projection of the live mapping; no reference.
        unsafe { &raw mut (*self.run.as_ptr()).immediate_exit }
    }

    /// The run's `immediate_exit` byte, which kicks store concurrently.
    pub(crate) fn immediate_exit(&self) -> &AtomicU8 {
        // SAFETY: the byte is mapped while `self` is borrowed (see the type
        // doc) and every access to it, here and in the HAL, is atomic.
        unsafe { AtomicU8::from_ptr(self.immediate_exit_ptr()) }
    }

    /// Request (or withdraw) the next `KVM_RUN`'s immediate exit.
    pub(crate) fn set_immediate_exit(&self, exit: bool) {
        self.immediate_exit()
            .store(u8::from(exit), Ordering::SeqCst);
    }

    /// Publish this run's `immediate_exit` byte to `kick` before the
    /// scheduler's last runnable check.
    #[cfg(target_arch = "x86_64")]
    pub(crate) fn arm_kick(&self, kick: &crate::KvmKickHandle) {
        let mut published = self
            .published
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        // Withdraw an earlier publication first (it may sit in another
        // thread's window); revoking after the new arm would clear it.
        if let Some(earlier) = published.take() {
            earlier.revoke();
        }
        // SAFETY: the mapping lives until `revoke_kick` (on recycle) or the
        // `KvmVcpuFd` drop revokes this publication.
        *published = Some(unsafe { kick.arm_run(self.immediate_exit()) });
    }

    /// Withdraw this byte from the kick window it was last armed in, if it is
    /// still published there. Called before the pair is reused or unmapped.
    pub(crate) fn revoke_kick(&self) {
        #[cfg(target_arch = "x86_64")]
        if let Some(publication) = self
            .published
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .take()
        {
            publication.revoke();
        }
    }

    /// Admit kicks into the next run until the returned guard drops. A run a
    /// caller armed already ([`Self::arm_kick`]) keeps its owner.
    ///
    /// # Safety
    /// The [`KvmVcpuFd`] holding this map must stay alive until the guard
    /// drops.
    pub(crate) unsafe fn open_kick_window(
        &self,
    ) -> carrick_hal::posix_signal_kick::CurrentThreadRun {
        // SAFETY: the caller's contract keeps the byte mapped for the guard.
        unsafe { carrick_hal::posix_signal_kick::CurrentThreadRun::open(self.immediate_exit_ptr()) }
    }

    /// Ask the next `KVM_RUN` to sync the GPRs and system registers out into
    /// `s.regs` on exit, so the syscall doorbell reads them without an ioctl.
    #[cfg(target_arch = "x86_64")]
    pub(crate) fn request_sync_regs(&self) {
        use kvm_ioctls::SyncReg;
        // SAFETY: `kvm_valid_regs` is a different field from the byte kicks
        // store, and only the owning thread writes it.
        unsafe {
            let valid = &raw mut (*self.run.as_ptr()).kvm_valid_regs;
            valid.write(valid.read() | SyncReg::Register as u64 | SyncReg::SystemRegister as u64);
        }
    }

    /// The `s.regs` mirror the kernel synced out on the last exit.
    #[cfg(target_arch = "x86_64")]
    pub(crate) fn synced_regs(&self) -> kvm_bindings::kvm_sync_regs {
        // SAFETY: `s.regs` is a different field from the byte kicks store,
        // and only KVM_RUN on the owning thread writes it.
        unsafe { (&raw const (*self.run.as_ptr()).s.regs).read() }
    }

    /// Append the `KVM_EXIT_INTERNAL_ERROR` record of the last exit to `msg`.
    #[cfg(target_arch = "x86_64")]
    pub(crate) fn append_internal_error(&self, msg: &mut String) {
        use kvm_bindings::{
            KVM_INTERNAL_ERROR_DELIVERY_EV, KVM_INTERNAL_ERROR_EMULATION,
            KVM_INTERNAL_ERROR_EMULATION_FLAG_INSTRUCTION_BYTES, KVM_INTERNAL_ERROR_SIMUL_EX,
            KVM_INTERNAL_ERROR_UNEXPECTED_EXIT_REASON,
        };

        fn suberror_name(suberror: u32) -> &'static str {
            match suberror {
                KVM_INTERNAL_ERROR_EMULATION => "EMULATION",
                KVM_INTERNAL_ERROR_SIMUL_EX => "SIMUL_EX",
                KVM_INTERNAL_ERROR_DELIVERY_EV => "DELIVERY_EV",
                KVM_INTERNAL_ERROR_UNEXPECTED_EXIT_REASON => "UNEXPECTED_EXIT_REASON",
                _ => "UNKNOWN",
            }
        }

        let run = self.run.as_ptr();
        // SAFETY: KVM_EXIT_INTERNAL_ERROR selects the `internal` union member.
        // Raw field reads here and below: a kick may still store
        // `immediate_exit`, so no reference to the whole `kvm_run` is formed.
        let internal = unsafe { (&raw const (*run).__bindgen_anon_1.internal).read() };
        let ndata = internal.ndata.min(internal.data.len() as u32) as usize;
        msg.push_str(&format!(
            " kvm_internal={{suberror={}({}) ndata={} data={:x?}}}",
            internal.suberror,
            suberror_name(internal.suberror),
            internal.ndata,
            &internal.data[..ndata]
        ));
        // SAFETY: when KVM_CAP_EXIT_ON_EMULATION_FAILURE is enabled,
        // KVM_EXIT_INTERNAL_ERROR overlays the emulation_failure union member.
        let emulation = unsafe { (&raw const (*run).__bindgen_anon_1.emulation_failure).read() };
        let has_insn =
            emulation.flags & u64::from(KVM_INTERNAL_ERROR_EMULATION_FLAG_INSTRUCTION_BYTES) != 0;
        if has_insn {
            // SAFETY: the instruction-byte flag marks this union arm valid.
            let insn = unsafe { emulation.__bindgen_anon_1.__bindgen_anon_1 };
            let size = usize::from(insn.insn_size).min(insn.insn_bytes.len());
            msg.push_str(&format!(
                " emulation_failure={{suberror={}({}) ndata={} flags=0x{:x} insn_size={} insn_bytes={:02x?}}}",
                emulation.suberror,
                suberror_name(emulation.suberror),
                emulation.ndata,
                emulation.flags,
                insn.insn_size,
                &insn.insn_bytes[..size],
            ));
        } else {
            msg.push_str(&format!(
                " emulation_failure={{suberror={}({}) ndata={} flags=0x{:x}}}",
                emulation.suberror,
                suberror_name(emulation.suberror),
                emulation.ndata,
                emulation.flags,
            ));
        }
    }
}

/// One completed `KVM_RUN` exit, copied out of the mapping field by field, so
/// no Rust reference to the mapping outlives (or overlaps) a kick.
pub(crate) enum RawKvmExit {
    Intr,
    IoOut { port: u16, data: Vec<u8> },
    MmioWrite { gpa: u64, data: [u8; 8], len: u8 },
    Halt,
    Debug(kvm_bindings::kvm_debug_exit_arch),
    InternalError,
    Other(&'static str, u32),
}

impl RawKvmExit {
    /// # Safety
    /// `run` is a vCPU's live `kvm_run` mapping and its last `KVM_RUN`
    /// returned 0, so `exit_reason` names the valid union member.
    unsafe fn copy_out(run: *mut kvm_bindings::kvm_run) -> Self {
        // SAFETY: the caller's contract; every access is a raw field read.
        unsafe {
            let reason = (&raw const (*run).exit_reason).read();
            match reason {
                kvm_bindings::KVM_EXIT_INTR => Self::Intr,
                kvm_bindings::KVM_EXIT_IO => {
                    let io = (&raw const (*run).__bindgen_anon_1.io).read();
                    if u32::from(io.direction) != kvm_bindings::KVM_EXIT_IO_OUT {
                        return Self::Other("IoIn", reason);
                    }
                    let len = usize::from(io.size) * io.count as usize;
                    // The data lies `data_offset` bytes into the mapping,
                    // which the kernel sized to hold it.
                    let start = run.cast::<u8>().add(io.data_offset as usize);
                    let mut data = vec![0_u8; len];
                    std::ptr::copy_nonoverlapping(start, data.as_mut_ptr(), len);
                    Self::IoOut {
                        port: io.port,
                        data,
                    }
                }
                kvm_bindings::KVM_EXIT_MMIO => {
                    let mmio = (&raw const (*run).__bindgen_anon_1.mmio).read();
                    if mmio.is_write == 0 {
                        return Self::Other("MmioRead", reason);
                    }
                    let len = (mmio.len as usize).min(mmio.data.len());
                    let mut data = [0_u8; 8];
                    data[..len].copy_from_slice(&mmio.data[..len]);
                    Self::MmioWrite {
                        gpa: mmio.phys_addr,
                        data,
                        len: len as u8,
                    }
                }
                kvm_bindings::KVM_EXIT_SYSTEM_EVENT
                | kvm_bindings::KVM_EXIT_SHUTDOWN
                | kvm_bindings::KVM_EXIT_HLT => Self::Halt,
                kvm_bindings::KVM_EXIT_DEBUG => {
                    Self::Debug((&raw const (*run).__bindgen_anon_1.debug).read().arch)
                }
                kvm_bindings::KVM_EXIT_INTERNAL_ERROR => Self::InternalError,
                other => Self::Other("exit", other),
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::path::{Path, PathBuf};

    /// Every kvm-ioctls `VcpuFd` method that reaches a vCPU's `kvm_run`
    /// through a Rust reference. Matched as a method call (`.name(`) or a
    /// path (`::name(`), across whitespace and line breaks.
    const MAPPING_METHODS: &[&str] = &[
        "get_kvm_run",
        "set_kvm_immediate_exit",
        "sync_regs",
        "sync_regs_mut",
        "set_sync_valid_reg",
        "clear_sync_valid_reg",
        "set_sync_dirty_reg",
        "clear_sync_dirty_reg",
    ];

    /// Raw `kvm_run` fields a kick-racing run must not touch outside
    /// [`super::KvmRunMap`], and the deleted `&mut VcpuFd` accessor. `fd.run(`
    /// catches a bare `VcpuFd` run before the fd is wrapped (`new_fd.run()`,
    /// `parked.fd.run()`); once wrapped, `VcpuFd::run`'s `&mut VcpuFd` can
    /// only be formed in this module.
    const MAPPING_TOKENS: &[&str] = &[
        "fd.run(",
        "VcpuFd::run(",
        "fd_mut(",
        "kvm_valid_regs",
        ".immediate_exit",
        "__bindgen_anon_1",
    ];

    fn rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
        for entry in std::fs::read_dir(dir).expect("read source dir") {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                rust_sources(&path, out);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                out.push(path);
            }
        }
    }

    /// A file's code with `//` comments and all whitespace removed, so a
    /// call split by spaces or line breaks still matches.
    fn flat_code(text: &str) -> String {
        text.lines()
            .map(|line| line.split("//").next().unwrap_or_default())
            .flat_map(str::chars)
            .filter(|c| !c.is_whitespace())
            .collect()
    }

    /// The uses of `MAPPING_METHODS` and `MAPPING_TOKENS` in the crate's code
    /// outside this module, as `file: access xN`.
    fn mapping_accesses_outside_run_map() -> Vec<String> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let this = root.join("src/kvm/run_map.rs");
        let mut files = Vec::new();
        rust_sources(&root.join("src"), &mut files);
        rust_sources(&root.join("tests"), &mut files);
        let patterns: Vec<String> = MAPPING_METHODS
            .iter()
            .flat_map(|method| [format!(".{method}("), format!("::{method}(")])
            .chain(MAPPING_TOKENS.iter().map(|token| token.to_string()))
            .collect();
        let mut found = Vec::new();
        for file in files.iter().filter(|file| **file != this) {
            let code = flat_code(&std::fs::read_to_string(file).expect("read source"));
            for pattern in &patterns {
                let count = code.matches(pattern.as_str()).count();
                if count > 0 {
                    found.push(format!(
                        "{}: {pattern} x{count}",
                        file.strip_prefix(root).unwrap_or(file).display()
                    ));
                }
            }
        }
        found
    }

    /// The scan itself sees through spacing, line breaks and paths.
    #[test]
    fn the_mapping_scan_matches_split_and_path_calls() {
        let code = flat_code(
            "let r = vcpu.fd()\n    .sync_regs ();\nVcpuFd::sync_regs(fd); // .get_kvm_run(\n",
        );
        assert!(code.contains(".sync_regs("));
        assert!(code.contains("::sync_regs("));
        assert!(!code.contains("get_kvm_run"), "comments are not code");
    }

    #[test]
    fn kvm_run_is_reached_only_through_run_map() {
        let found = mapping_accesses_outside_run_map();
        assert!(
            found.is_empty(),
            "kvm_run must be reached only through KvmRunMap (#2962); found {} use(s):\n{}",
            found.len(),
            found.join("\n")
        );
    }
}
