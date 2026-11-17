//! Linux socket family and type values (`socket(2)`), shared by the ring's
//! socket staging and the carrier's host network service.

/// Linux AF_* values for the families we support. Linux constants happen
/// to overlap with macOS's only for AF_UNSPEC / AF_UNIX / AF_INET — the
/// AF_INET6 numeric value differs (Linux: 10, macOS: 30).
pub const LINUX_AF_UNSPEC: i32 = 0;
pub const LINUX_AF_UNIX: i32 = 1;
pub const LINUX_AF_INET: i32 = 2;
pub const LINUX_AF_INET6: i32 = 10;
pub const LINUX_AF_NETLINK: i32 = 16;
pub const LINUX_AF_PACKET: i32 = 17;
pub const LINUX_SOCK_STREAM: i32 = 1;
pub const LINUX_SOCK_DGRAM: i32 = 2;
pub const LINUX_SOCK_RAW: i32 = 3;
pub const LINUX_SOCK_RDM: i32 = 4;
pub const LINUX_SOCK_SEQPACKET: i32 = 5;

/// Linux `struct msghdr` on an LP64 ABI: `msg_name` (8), `msg_namelen`
/// (4, then 4 of padding), `msg_iov` (8), `msg_iovlen` (8), `msg_control`
/// (8), `msg_controllen` (8), `msg_flags` (4, then 4 of padding).
pub const LINUX_MSGHDR_BYTES: usize = 56;
/// Linux `struct mmsghdr`: a `struct msghdr`, then `msg_len` (4, then 4 of
/// padding).
pub const LINUX_MMSGHDR_BYTES: usize = 64;
/// Linux `struct sockaddr_storage`: the largest socket address a call
/// reads or writes.
pub const LINUX_SOCKADDR_STORAGE_BYTES: usize = 128;
