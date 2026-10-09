//! Linux capabilities (capabilities(7)).
use bitflags::bitflags;

pub const CAP_CHOWN: u32 = 0;
pub const CAP_DAC_OVERRIDE: u32 = 1;
pub const CAP_DAC_READ_SEARCH: u32 = 2;
pub const CAP_FOWNER: u32 = 3;
pub const CAP_FSETID: u32 = 4;
pub const CAP_KILL: u32 = 5;
pub const CAP_SETGID: u32 = 6;
pub const CAP_SETUID: u32 = 7;
pub const CAP_SETPCAP: u32 = 8;
pub const CAP_LINUX_IMMUTABLE: u32 = 9;
pub const CAP_NET_BIND_SERVICE: u32 = 10;
pub const CAP_NET_BROADCAST: u32 = 11;
pub const CAP_NET_ADMIN: u32 = 12;
pub const CAP_NET_RAW: u32 = 13;
pub const CAP_IPC_LOCK: u32 = 14;
pub const CAP_IPC_OWNER: u32 = 15;
pub const CAP_SYS_MODULE: u32 = 16;
pub const CAP_SYS_RAWIO: u32 = 17;
pub const CAP_SYS_CHROOT: u32 = 18;
pub const CAP_SYS_PTRACE: u32 = 19;
pub const CAP_SYS_PACCT: u32 = 20;
pub const CAP_SYS_ADMIN: u32 = 21;
pub const CAP_SYS_BOOT: u32 = 22;
pub const CAP_SYS_NICE: u32 = 23;
pub const CAP_SYS_RESOURCE: u32 = 24;
pub const CAP_SYS_TIME: u32 = 25;
pub const CAP_SYS_TTY_CONFIG: u32 = 26;
pub const CAP_MKNOD: u32 = 27;
pub const CAP_LEASE: u32 = 28;
pub const CAP_AUDIT_WRITE: u32 = 29;
pub const CAP_AUDIT_CONTROL: u32 = 30;
pub const CAP_SETFCAP: u32 = 31;
pub const CAP_MAC_OVERRIDE: u32 = 32;
pub const CAP_MAC_ADMIN: u32 = 33;
pub const CAP_SYSLOG: u32 = 34;
pub const CAP_WAKE_ALARM: u32 = 35;
pub const CAP_BLOCK_SUSPEND: u32 = 36;
pub const CAP_AUDIT_READ: u32 = 37;
pub const CAP_PERFMON: u32 = 38;
pub const CAP_BPF: u32 = 39;
pub const CAP_CHECKPOINT_RESTORE: u32 = 40;
pub const CAP_LAST_CAP: u32 = CAP_CHECKPOINT_RESTORE;

bitflags! {
    /// 64-bit Linux capability bitmask.
    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    pub struct LinuxCapabilitySet: u64 {
        const CAP_CHOWN = 1 << CAP_CHOWN;
        const CAP_DAC_OVERRIDE = 1 << CAP_DAC_OVERRIDE;
        const CAP_DAC_READ_SEARCH = 1 << CAP_DAC_READ_SEARCH;
        const CAP_FOWNER = 1 << CAP_FOWNER;
        const CAP_FSETID = 1 << CAP_FSETID;
        const CAP_KILL = 1 << CAP_KILL;
        const CAP_SETGID = 1 << CAP_SETGID;
        const CAP_SETUID = 1 << CAP_SETUID;
        const CAP_SETPCAP = 1 << CAP_SETPCAP;
        const CAP_LINUX_IMMUTABLE = 1 << CAP_LINUX_IMMUTABLE;
        const CAP_NET_BIND_SERVICE = 1 << CAP_NET_BIND_SERVICE;
        const CAP_NET_BROADCAST = 1 << CAP_NET_BROADCAST;
        const CAP_NET_ADMIN = 1 << CAP_NET_ADMIN;
        const CAP_NET_RAW = 1 << CAP_NET_RAW;
        const CAP_IPC_LOCK = 1 << CAP_IPC_LOCK;
        const CAP_IPC_OWNER = 1 << CAP_IPC_OWNER;
        const CAP_SYS_MODULE = 1 << CAP_SYS_MODULE;
        const CAP_SYS_RAWIO = 1 << CAP_SYS_RAWIO;
        const CAP_SYS_CHROOT = 1 << CAP_SYS_CHROOT;
        const CAP_SYS_PTRACE = 1 << CAP_SYS_PTRACE;
        const CAP_SYS_PACCT = 1 << CAP_SYS_PACCT;
        const CAP_SYS_ADMIN = 1 << CAP_SYS_ADMIN;
        const CAP_SYS_BOOT = 1 << CAP_SYS_BOOT;
        const CAP_SYS_NICE = 1 << CAP_SYS_NICE;
        const CAP_SYS_RESOURCE = 1 << CAP_SYS_RESOURCE;
        const CAP_SYS_TIME = 1 << CAP_SYS_TIME;
        const CAP_SYS_TTY_CONFIG = 1 << CAP_SYS_TTY_CONFIG;
        const CAP_MKNOD = 1 << CAP_MKNOD;
        const CAP_LEASE = 1 << CAP_LEASE;
        const CAP_AUDIT_WRITE = 1 << CAP_AUDIT_WRITE;
        const CAP_AUDIT_CONTROL = 1 << CAP_AUDIT_CONTROL;
        const CAP_SETFCAP = 1 << CAP_SETFCAP;
        const CAP_MAC_OVERRIDE = 1 << CAP_MAC_OVERRIDE;
        const CAP_MAC_ADMIN = 1 << CAP_MAC_ADMIN;
        const CAP_SYSLOG = 1 << CAP_SYSLOG;
        const CAP_WAKE_ALARM = 1 << CAP_WAKE_ALARM;
        const CAP_BLOCK_SUSPEND = 1 << CAP_BLOCK_SUSPEND;
        const CAP_AUDIT_READ = 1 << CAP_AUDIT_READ;
        const CAP_PERFMON = 1 << CAP_PERFMON;
        const CAP_BPF = 1 << CAP_BPF;
        const CAP_CHECKPOINT_RESTORE = 1 << CAP_CHECKPOINT_RESTORE;

        // Aliases without CAP_ prefix where they do not trigger substrate forbidden prefix checks.
        const CHOWN = 1 << CAP_CHOWN;
        const DAC_OVERRIDE = 1 << CAP_DAC_OVERRIDE;
        const DAC_READ_SEARCH = 1 << CAP_DAC_READ_SEARCH;
        const FOWNER = 1 << CAP_FOWNER;
        const FSETID = 1 << CAP_FSETID;
        const KILL = 1 << CAP_KILL;
        const SETGID = 1 << CAP_SETGID;
        const SETUID = 1 << CAP_SETUID;
        const SETPCAP = 1 << CAP_SETPCAP;
        const NET_BIND_SERVICE = 1 << CAP_NET_BIND_SERVICE;
        const NET_BROADCAST = 1 << CAP_NET_BROADCAST;
        const NET_ADMIN = 1 << CAP_NET_ADMIN;
        const NET_RAW = 1 << CAP_NET_RAW;
        const IPC_LOCK = 1 << CAP_IPC_LOCK;
        const IPC_OWNER = 1 << CAP_IPC_OWNER;
        const MKNOD = 1 << CAP_MKNOD;
        const LEASE = 1 << CAP_LEASE;
        const AUDIT_WRITE = 1 << CAP_AUDIT_WRITE;
        const AUDIT_CONTROL = 1 << CAP_AUDIT_CONTROL;
        const SETFCAP = 1 << CAP_SETFCAP;
        const MAC_OVERRIDE = 1 << CAP_MAC_OVERRIDE;
        const MAC_ADMIN = 1 << CAP_MAC_ADMIN;
        const SYSLOG = 1 << CAP_SYSLOG;
        const WAKE_ALARM = 1 << CAP_WAKE_ALARM;
        const BLOCK_SUSPEND = 1 << CAP_BLOCK_SUSPEND;
        const AUDIT_READ = 1 << CAP_AUDIT_READ;
        const PERFMON = 1 << CAP_PERFMON;
        const BPF = 1 << CAP_BPF;
        const CHECKPOINT_RESTORE = 1 << CAP_CHECKPOINT_RESTORE;
    }
}

impl LinuxCapabilitySet {
    /// Bitmask covering all defined capabilities up to CAP_LAST_CAP.
    pub const ALL_CAPS_MASK: u64 = (1u64 << (CAP_LAST_CAP + 1)) - 1;

    /// Full capability set with every capability bit enabled.
    pub const FULL: Self = Self::from_bits_retain(Self::ALL_CAPS_MASK);

    /// Filesystem-related capabilities affected by setfsuid transitions (capabilities(7)).
    pub const FS_MASK: Self = Self::from_bits_retain(
        (1 << CAP_CHOWN)
            | (1 << CAP_DAC_OVERRIDE)
            | (1 << CAP_DAC_READ_SEARCH)
            | (1 << CAP_FOWNER)
            | (1 << CAP_FSETID)
            | (1 << CAP_LINUX_IMMUTABLE)
            | (1 << CAP_MAC_OVERRIDE)
            | (1 << CAP_MKNOD),
    );
}
