//! Whether this host can run a test that needs KVM.
//!
//! A KVM test needs to *open* `/dev/kvm`, not merely to find it. A hosted CI
//! runner ships the device node as `root:kvm 0660` and runs the job outside
//! the `kvm` group, so the node exists and every open is `EACCES`. A check
//! that asks only whether the path exists then runs the test, and it fails
//! on its first `KVM_CREATE_VM` fixture instead of skipping.
//!
//! [`KvmHost::probe`] opens the device read-write, as the carrier does, and
//! answers with a type: [`KvmHost::Usable`], or [`KvmHost::Unusable`] with
//! the reason. [`require_kvm!`](crate::require_kvm) is the one skip used by
//! every KVM test: it returns from the test with a `SKIP kvm` line on the
//! process's real stderr (libtest hides a passing test's output), numbered
//! per process, so a log shows how many tests did not run and why.
//!
//! The KVM gate (`just test-kvm`) exports `CARRICK_REQUIRE_KVM=1`. Under it
//! an unusable device is a failure, never a skip.

use std::ffi::CStr;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};

/// The device every KVM carrier opens.
pub const KVM_DEVICE: &CStr = c"/dev/kvm";

/// Why a host cannot run a KVM test.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KvmUnusable {
    /// There is no device node: not a Linux host, or no KVM.
    Absent,
    /// The node exists and opening it read-write failed with this errno
    /// (`EACCES` outside the `kvm` group).
    NotOpenable { errno: i32 },
}

impl core::fmt::Display for KvmUnusable {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Absent => f.write_str("/dev/kvm is absent"),
            Self::NotOpenable { errno } => write!(
                f,
                "/dev/kvm is present but not openable: {} (os error {errno})",
                std::io::Error::from_raw_os_error(*errno).kind()
            ),
        }
    }
}

/// Whether this host can run a KVM test.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KvmHost {
    /// `/dev/kvm` opened read-write.
    Usable,
    Unusable(KvmUnusable),
}

impl KvmHost {
    /// Probe `/dev/kvm` once per process.
    pub fn probe() -> Self {
        static HOST: OnceLock<KvmHost> = OnceLock::new();
        *HOST.get_or_init(|| Self::probe_device(KVM_DEVICE))
    }

    /// Open `device` read-write, as a carrier opens `/dev/kvm`, and close it.
    pub fn probe_device(device: &CStr) -> Self {
        // SAFETY: `device` is a NUL-terminated path; the descriptor is
        // closed below and never shared.
        let fd = unsafe { libc::open(device.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
        if fd >= 0 {
            // SAFETY: closes only the descriptor opened above.
            unsafe { libc::close(fd) };
            return Self::Usable;
        }
        match std::io::Error::last_os_error().raw_os_error() {
            Some(libc::ENOENT) => Self::Unusable(KvmUnusable::Absent),
            errno => Self::Unusable(KvmUnusable::NotOpenable {
                errno: errno.unwrap_or(0),
            }),
        }
    }

    pub fn is_usable(self) -> bool {
        self == Self::Usable
    }
}

/// Whether `CARRICK_REQUIRE_KVM=1` forbids skipping (the KVM gate).
pub fn kvm_required() -> bool {
    std::env::var_os("CARRICK_REQUIRE_KVM").is_some_and(|value| value == "1")
}

static SKIPPED: AtomicU64 = AtomicU64::new(0);

/// How many tests in this process skipped for want of KVM.
pub fn skipped() -> u64 {
    SKIPPED.load(Ordering::Relaxed)
}

/// The decision for one test on a host in state `host`: `true` to run it.
///
/// An unusable device fails the test when `required`; otherwise the skip is
/// counted and reported on the real stderr, and the answer is `false`.
pub fn admit(host: KvmHost, required: bool, test: &str) -> bool {
    let reason = match host {
        KvmHost::Usable => return true,
        KvmHost::Unusable(reason) => reason,
    };
    assert!(
        !required,
        "CARRICK_REQUIRE_KVM=1 but {reason}: the KVM gate must not skip ({test})"
    );
    let count = SKIPPED.fetch_add(1, Ordering::Relaxed) + 1;
    let line = format!("SKIP kvm #{count}: {test}: {reason}\n");
    // SAFETY: writes an owned buffer to the process's stderr; a short write
    // only truncates this diagnostic.
    unsafe { libc::write(libc::STDERR_FILENO, line.as_ptr().cast(), line.len()) };
    false
}

/// Whether the calling test may use KVM on this host. Prefer
/// [`require_kvm!`](crate::require_kvm), which also returns from the test.
pub fn usable_or_skip() -> bool {
    let thread = std::thread::current();
    admit(
        KvmHost::probe(),
        kvm_required(),
        thread.name().unwrap_or("<unnamed test thread>"),
    )
}

/// First statement of a test that needs KVM: return, with a counted
/// `SKIP kvm` line, when `/dev/kvm` cannot be opened; fail instead under
/// `CARRICK_REQUIRE_KVM=1`.
#[macro_export]
macro_rules! require_kvm {
    () => {
        if !$crate::kvm_host::usable_or_skip() {
            return;
        }
    };
}

/// The policy file of the host kernel's transparent huge pages.
pub const THP_POLICY: &str = "/sys/kernel/mm/transparent_hugepage/enabled";

/// The host kernel's transparent huge page policy: the bracketed word of
/// [`THP_POLICY`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ThpPolicy {
    /// Every anonymous mapping may take a huge page on first touch.
    Always,
    /// Only a mapping advised with `MADV_HUGEPAGE` may.
    Madvise,
    Never,
}

/// Whether a carrier's unadvised anonymous host mapping can be backed by
/// huge pages, so the hypervisor can map a 2 MiB guest window with one
/// large stage-2 entry. Carrick gives its host mappings no huge page advice,
/// so only [`ThpPolicy::Always`] can.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostHugePages {
    Policy(ThpPolicy),
    /// The policy file is absent or names no policy: no THP in this kernel.
    Unknown,
}

impl HostHugePages {
    /// Read [`THP_POLICY`].
    pub fn probe() -> Self {
        Self::parse(&std::fs::read_to_string(THP_POLICY).unwrap_or_default())
    }

    /// The policy of a [`THP_POLICY`] text such as `always [madvise] never`.
    pub fn parse(text: &str) -> Self {
        let chosen = text
            .split_whitespace()
            .find_map(|word| word.strip_prefix('[')?.strip_suffix(']'));
        match chosen {
            Some("always") => Self::Policy(ThpPolicy::Always),
            Some("madvise") => Self::Policy(ThpPolicy::Madvise),
            Some("never") => Self::Policy(ThpPolicy::Never),
            _ => Self::Unknown,
        }
    }

    pub fn backs_unadvised_mappings(self) -> bool {
        self == Self::Policy(ThpPolicy::Always)
    }
}

static SKIPPED_HUGE_PAGES: AtomicU64 = AtomicU64::new(0);

/// The decision for one test that needs unadvised huge host pages, on a
/// host in state `host`: `true` to run it.
///
/// The policy is always written to the process's real stderr, so a KVM-lane
/// log records the host it ran on. A host that can't back unadvised mappings
/// fails the test when `required` (the KVM gate must not skip); otherwise
/// the skip is counted and reported as a `SKIP thp` line.
pub fn admit_huge_pages(host: HostHugePages, required: bool, test: &str) -> bool {
    let usable = host.backs_unadvised_mappings();
    let line = if usable {
        format!("HOST thp {host:?}: {test}\n")
    } else {
        assert!(
            !required,
            "CARRICK_REQUIRE_KVM=1 but the host's transparent huge page policy is \
             {host:?}, not Always: unadvised host mappings get no huge pages, and \
             the KVM gate must not skip ({test})"
        );
        let count = SKIPPED_HUGE_PAGES.fetch_add(1, Ordering::Relaxed) + 1;
        format!("SKIP thp #{count}: {test}: transparent huge page policy {host:?}\n")
    };
    // SAFETY: writes an owned buffer to the process's stderr; a short write
    // only truncates this diagnostic.
    unsafe { libc::write(libc::STDERR_FILENO, line.as_ptr().cast(), line.len()) };
    usable
}

/// Whether the calling test may rely on unadvised huge host pages here.
/// Prefer [`require_huge_pages!`](crate::require_huge_pages).
pub fn huge_pages_or_skip() -> bool {
    let thread = std::thread::current();
    admit_huge_pages(
        HostHugePages::probe(),
        kvm_required(),
        thread.name().unwrap_or("<unnamed test thread>"),
    )
}

/// A statement of a test whose claim needs the host to back unadvised
/// anonymous mappings with huge pages: return, with a counted `SKIP thp`
/// line, when its policy isn't `always`; fail instead under
/// `CARRICK_REQUIRE_KVM=1`.
#[macro_export]
macro_rules! require_huge_pages {
    () => {
        if !$crate::kvm_host::huge_pages_or_skip() {
            return;
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::PermissionsExt;

    fn c_path(path: &std::path::Path) -> CString {
        CString::new(path.as_os_str().as_bytes()).unwrap()
    }

    #[test]
    fn a_present_device_that_cannot_be_opened_is_unusable_not_available() {
        let dir = tempfile::tempdir().unwrap();
        let node = dir.path().join("kvm");
        assert_eq!(
            KvmHost::probe_device(&c_path(&node)),
            KvmHost::Unusable(KvmUnusable::Absent)
        );

        std::fs::write(&node, b"").unwrap();
        assert_eq!(KvmHost::probe_device(&c_path(&node)), KvmHost::Usable);

        // The hosted-runner shape: the node exists, and the open is refused.
        // A directory refuses a read-write open for every user, root too.
        let refused = dir.path().join("refused");
        std::fs::create_dir(&refused).unwrap();
        assert!(refused.exists());
        assert_eq!(
            KvmHost::probe_device(&c_path(&refused)),
            KvmHost::Unusable(KvmUnusable::NotOpenable {
                errno: libc::EISDIR
            })
        );

        // And the exact errno a runner outside the `kvm` group sees, where
        // the test user is one that permission bits bind.
        std::fs::set_permissions(&node, std::fs::Permissions::from_mode(0o000)).unwrap();
        // SAFETY: reads the effective uid.
        if unsafe { libc::geteuid() } != 0 {
            assert_eq!(
                KvmHost::probe_device(&c_path(&node)),
                KvmHost::Unusable(KvmUnusable::NotOpenable {
                    errno: libc::EACCES
                })
            );
        }
    }

    #[test]
    fn an_unusable_device_skips_with_a_count_and_fails_when_required() {
        let refused = KvmHost::Unusable(KvmUnusable::NotOpenable {
            errno: libc::EACCES,
        });
        assert!(admit(KvmHost::Usable, true, "usable"));
        let before = skipped();
        assert!(!admit(refused, false, "refused"));
        assert!(!admit(
            KvmHost::Unusable(KvmUnusable::Absent),
            false,
            "absent"
        ));
        assert!(skipped() >= before + 2);
        let required = std::panic::catch_unwind(|| admit(refused, true, "gate"));
        let message = *required.unwrap_err().downcast::<String>().unwrap();
        assert!(
            message.contains("present but not openable") && message.contains("must not skip"),
            "{message}"
        );
    }

    #[test]
    fn only_an_always_thp_policy_admits_and_the_gate_fails_on_any_other() {
        let always = HostHugePages::parse("[always] madvise never\n");
        let madvise = HostHugePages::parse("always [madvise] never\n");
        assert_eq!(always, HostHugePages::Policy(ThpPolicy::Always));
        assert_eq!(madvise, HostHugePages::Policy(ThpPolicy::Madvise));
        assert_eq!(
            HostHugePages::parse("always madvise [never]"),
            HostHugePages::Policy(ThpPolicy::Never)
        );
        assert_eq!(HostHugePages::parse(""), HostHugePages::Unknown);

        assert!(admit_huge_pages(always, true, "always"));
        assert!(!admit_huge_pages(madvise, false, "madvise"));
        assert!(!admit_huge_pages(HostHugePages::Unknown, false, "unknown"));
        let required = std::panic::catch_unwind(|| admit_huge_pages(madvise, true, "gate"));
        let message = *required.unwrap_err().downcast::<String>().unwrap();
        assert!(
            message.contains("Madvise") && message.contains("must not skip"),
            "{message}"
        );
    }
}
