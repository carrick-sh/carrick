use super::*;
use carrick_syscall_abi::LinuxCapabilitySet;

#[test]
fn rule1_drops_all_capabilities_when_all_uids_become_nonzero() {
    let mut creds = TaskCredentials::ROOT;
    assert_eq!(creds.cap_permitted, LinuxCapabilitySet::FULL);
    assert_eq!(creds.cap_effective, LinuxCapabilitySet::FULL);

    let prev_r = creds.ruid;
    let prev_e = creds.euid;
    let prev_s = creds.suid;
    let prev_f = creds.fsuid;

    let non_root = TaskUid::new(1000);
    creds.ruid = non_root;
    creds.euid = non_root;
    creds.suid = non_root;
    creds.fsuid = non_root;

    creds.on_uid_change(prev_r, prev_e, prev_s, prev_f);

    assert_eq!(creds.cap_permitted, LinuxCapabilitySet::empty());
    assert_eq!(creds.cap_effective, LinuxCapabilitySet::empty());
    assert!(!creds.is_privileged());
}

#[test]
fn rule2_drops_effective_capabilities_when_euid_becomes_nonzero_while_retaining_permitted() {
    let mut creds = TaskCredentials::ROOT;

    let prev_r = creds.ruid;
    let prev_e = creds.euid;
    let prev_s = creds.suid;
    let prev_f = creds.fsuid;

    // Drop effective UID to non-root, but keep saved UID as root
    let non_root = TaskUid::new(1000);
    creds.euid = non_root;
    creds.fsuid = non_root;

    creds.on_uid_change(prev_r, prev_e, prev_s, prev_f);

    // Rule 1 does not fire because suid is still root (0).
    // Rule 2 fires: effective set cleared.
    assert_eq!(creds.cap_effective, LinuxCapabilitySet::empty());
    assert_eq!(creds.cap_permitted, LinuxCapabilitySet::FULL);
    assert!(!creds.is_privileged());
}

#[test]
fn rule3_restores_effective_capabilities_from_permitted_when_euid_becomes_zero() {
    let mut creds = TaskCredentials::ROOT;

    // Drop effective UID
    let prev_r = creds.ruid;
    let prev_e = creds.euid;
    let prev_s = creds.suid;
    let prev_f = creds.fsuid;

    let non_root = TaskUid::new(1000);
    creds.euid = non_root;
    creds.fsuid = non_root;
    creds.on_uid_change(prev_r, prev_e, prev_s, prev_f);
    assert_eq!(creds.cap_effective, LinuxCapabilitySet::empty());

    // Regain effective root
    let prev_r = creds.ruid;
    let prev_e = creds.euid;
    let prev_s = creds.suid;
    let prev_f = creds.fsuid;

    creds.euid = TaskUid::ROOT;
    creds.fsuid = TaskUid::ROOT;
    creds.on_uid_change(prev_r, prev_e, prev_s, prev_f);

    // Rule 3 fires: effective set copied from permitted set.
    assert_eq!(creds.cap_effective, LinuxCapabilitySet::FULL);
    assert!(creds.is_privileged());
}

#[test]
fn rule4_fsuid_change_from_zero_to_nonzero_drops_only_fs_capabilities() {
    let mut creds = TaskCredentials::ROOT;
    assert_eq!(creds.cap_effective, LinuxCapabilitySet::FULL);

    let prev_fsuid = creds.fsuid;
    creds.fsuid = TaskUid::new(1000);
    creds.on_fsuid_change(prev_fsuid);

    // FS capabilities are cleared from effective set
    assert!(!creds.cap_effective.intersects(LinuxCapabilitySet::FS_MASK));
    // Non-FS capabilities remain in effective set
    assert!(
        creds
            .cap_effective
            .contains(LinuxCapabilitySet::CAP_SYS_ADMIN)
    );
    assert!(creds.cap_effective.contains(LinuxCapabilitySet::CAP_SETUID));
    assert!(creds.cap_effective.contains(LinuxCapabilitySet::CAP_SETGID));
    assert!(
        creds
            .cap_effective
            .contains(LinuxCapabilitySet::CAP_SYS_RESOURCE)
    );
    // Permitted set is unchanged
    assert_eq!(creds.cap_permitted, LinuxCapabilitySet::FULL);
}

#[test]
fn rule4_fsuid_change_from_nonzero_to_zero_restores_fs_capabilities_from_permitted() {
    let mut creds = TaskCredentials::ROOT;

    // First change fsuid to non-root
    let prev_fsuid = creds.fsuid;
    creds.fsuid = TaskUid::new(1000);
    creds.on_fsuid_change(prev_fsuid);
    assert!(!creds.cap_effective.intersects(LinuxCapabilitySet::FS_MASK));

    // Restore fsuid to root
    let prev_fsuid = creds.fsuid;
    creds.fsuid = TaskUid::ROOT;
    creds.on_fsuid_change(prev_fsuid);

    // FS capabilities enabled in permitted are re-enabled in effective
    assert_eq!(creds.cap_effective, LinuxCapabilitySet::FULL);
}

#[test]
fn rule4_fsuid_change_does_not_restore_fs_capabilities_not_in_permitted() {
    let mut creds = TaskCredentials::ROOT;
    // Remove DAC_OVERRIDE from permitted
    creds.cap_permitted.remove(LinuxCapabilitySet::DAC_OVERRIDE);
    creds.cap_effective = creds.cap_permitted;

    let prev_fsuid = creds.fsuid;
    creds.fsuid = TaskUid::new(1000);
    creds.on_fsuid_change(prev_fsuid);
    assert!(!creds.cap_effective.intersects(LinuxCapabilitySet::FS_MASK));

    // Restore fsuid to root
    let prev_fsuid = creds.fsuid;
    creds.fsuid = TaskUid::ROOT;
    creds.on_fsuid_change(prev_fsuid);

    // All FS capabilities except DAC_OVERRIDE restored
    assert!(
        !creds
            .cap_effective
            .contains(LinuxCapabilitySet::DAC_OVERRIDE)
    );
    assert!(creds.cap_effective.contains(LinuxCapabilitySet::CHOWN));
    assert!(
        creds
            .cap_effective
            .contains(LinuxCapabilitySet::DAC_READ_SEARCH)
    );
    assert!(creds.cap_effective.contains(LinuxCapabilitySet::FOWNER));
}

#[test]
fn privilege_checks_depend_on_effective_capabilities_not_euid() {
    let mut creds = TaskCredentials::ROOT;
    assert_eq!(creds.euid, TaskUid::ROOT);
    creds.cap_effective = LinuxCapabilitySet::empty();

    // Even though euid is ROOT, with no effective capabilities privilege checks must be false!
    assert!(!creds.is_privileged());
    assert!(!creds.is_gid_privileged());
    assert!(!creds.is_admin_privileged());
    assert!(!creds.is_resource_privileged());

    // With non-root euid but specific capability present, the check succeeds
    creds.euid = TaskUid::new(1000);
    creds.cap_effective = LinuxCapabilitySet::CAP_SETUID;
    assert!(creds.is_privileged());
    assert!(!creds.is_gid_privileged());
    assert!(!creds.is_admin_privileged());
    assert!(!creds.is_resource_privileged());
}

#[test]
fn on_uid_change_between_nonzero_uids_preserves_permitted_capabilities() {
    let mut creds = TaskCredentials::ROOT;
    let non_root_1 = TaskUid::new(1000);
    let non_root_2 = TaskUid::new(2000);

    // Initial transition from root drops capabilities per rule 1
    let prev_r = creds.ruid;
    let prev_e = creds.euid;
    let prev_s = creds.suid;
    let prev_f = creds.fsuid;
    creds.ruid = non_root_1;
    creds.euid = non_root_1;
    creds.suid = non_root_1;
    creds.fsuid = non_root_1;
    creds.on_uid_change(prev_r, prev_e, prev_s, prev_f);
    assert_eq!(creds.cap_permitted, LinuxCapabilitySet::empty());

    // Suppose task had CAP_NET_BIND_SERVICE in permitted
    creds.cap_permitted = LinuxCapabilitySet::CAP_NET_BIND_SERVICE;
    creds.cap_effective = LinuxCapabilitySet::CAP_NET_BIND_SERVICE;

    // Transition between two non-zero UIDs (neither was root before)
    let prev_r = creds.ruid;
    let prev_e = creds.euid;
    let prev_s = creds.suid;
    let prev_f = creds.fsuid;
    creds.ruid = non_root_2;
    creds.euid = non_root_2;
    creds.suid = non_root_2;
    creds.fsuid = non_root_2;
    creds.on_uid_change(prev_r, prev_e, prev_s, prev_f);

    // Rule 1 does NOT fire because none of the previous IDs was 0!
    assert_eq!(
        creds.cap_permitted,
        LinuxCapabilitySet::CAP_NET_BIND_SERVICE
    );
    // Rule 2 does not fire because prev_euid was not 0
    assert_eq!(
        creds.cap_effective,
        LinuxCapabilitySet::CAP_NET_BIND_SERVICE
    );
}
