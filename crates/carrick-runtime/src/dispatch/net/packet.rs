//! Synthetic AF_PACKET socket implementation and TPACKET receive-ring emulation.
//!
//! macOS has no native AF_PACKET socket family. This module models in-memory
//! synthetic AF_PACKET fds (`OpenDescription::Packet`), handles packet receive
//! rings (`TPACKET_V1`, `TPACKET_V2`, and `TPACKET_V3`), and loopback frame
//! delivery.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU16, AtomicU64, Ordering};
use std::sync::{Arc, Weak};

use carrick_abi::*;
use parking_lot::Mutex as PlMutex;
use zerocopy::{FromBytes, IntoBytes};

use super::support::write_sockopt_value;
use super::*;
use crate::linux_abi::LinuxErrno;

#[derive(Debug)]
pub struct PacketRing {
    version: i32,
    block_size: usize,
    block_nr: usize,
    #[allow(dead_code)]
    frame_size: usize,
    #[allow(dead_code)]
    frame_nr: usize,
    #[allow(dead_code)]
    retire_blk_tov: u32,
    #[allow(dead_code)]
    pub(crate) total_size: usize,
    bytes: PlMutex<Vec<u8>>,
    current_block: PlMutex<usize>,
    seq_num: PlMutex<u64>,
}

impl PacketRing {
    pub(crate) fn new_v3(req: &LinuxTpacketReq3) -> Result<Self, LinuxErrno> {
        let block_size = req.tp_block_size as usize;
        let block_nr = req.tp_block_nr as usize;
        let frame_size = req.tp_frame_size as usize;
        let frame_nr = req.tp_frame_nr as usize;
        if block_size == 0 || !block_size.is_power_of_two() || block_size < 4096 {
            return Err(LINUX_EINVAL);
        }
        if block_nr == 0 {
            return Err(LINUX_EINVAL);
        }
        if frame_size < core::mem::size_of::<LinuxTpacket3Hdr>() || frame_size > block_size {
            return Err(LINUX_EINVAL);
        }
        let total_size = block_size.checked_mul(block_nr).ok_or(LINUX_EINVAL)?;
        let mut buf = vec![0u8; total_size];
        for i in 0..block_nr {
            let offset = i * block_size;
            let desc = LinuxTpacketBlockDesc {
                version: LINUX_TPACKET_V3 as u32,
                offset_to_priv: 0,
                hdr: LinuxTpacketHdrV1 {
                    block_status: LINUX_TP_STATUS_KERNEL,
                    num_pkts: 0,
                    offset_to_first_pkt: core::mem::size_of::<LinuxTpacketBlockDesc>() as u32,
                    blk_len: core::mem::size_of::<LinuxTpacketBlockDesc>() as u32,
                    seq_num: 0,
                    ts_first_pkt: LinuxTpacketBdTs {
                        ts_sec: 0,
                        ts_usec: 0,
                    },
                    ts_last_pkt: LinuxTpacketBdTs {
                        ts_sec: 0,
                        ts_usec: 0,
                    },
                },
            };
            let desc_bytes = desc.as_bytes();
            buf[offset..offset + desc_bytes.len()].copy_from_slice(desc_bytes);
        }
        Ok(Self {
            version: LINUX_TPACKET_V3,
            block_size,
            block_nr,
            frame_size,
            frame_nr,
            retire_blk_tov: req.tp_retire_blk_tov,
            total_size,
            bytes: PlMutex::new(buf),
            current_block: PlMutex::new(0),
            seq_num: PlMutex::new(1),
        })
    }

    pub(crate) fn new_v1_v2(version: i32, req: &LinuxTpacketReq) -> Result<Self, LinuxErrno> {
        let block_size = req.tp_block_size as usize;
        let block_nr = req.tp_block_nr as usize;
        let frame_size = req.tp_frame_size as usize;
        let frame_nr = req.tp_frame_nr as usize;
        if block_size == 0 || !block_size.is_power_of_two() || block_size < 4096 {
            return Err(LINUX_EINVAL);
        }
        if block_nr == 0 || frame_size == 0 || frame_nr == 0 {
            return Err(LINUX_EINVAL);
        }
        let total_size = block_size.checked_mul(block_nr).ok_or(LINUX_EINVAL)?;
        let buf = vec![0u8; total_size];
        Ok(Self {
            version,
            block_size,
            block_nr,
            frame_size,
            frame_nr,
            retire_blk_tov: 0,
            total_size,
            bytes: PlMutex::new(buf),
            current_block: PlMutex::new(0),
            seq_num: PlMutex::new(1),
        })
    }

    pub(crate) fn initial_bytes(&self) -> Vec<u8> {
        self.bytes.lock().clone()
    }

    pub(crate) fn bytes(&self) -> Vec<u8> {
        self.bytes.lock().clone()
    }

    pub(crate) fn deliver_frame(&self, frame: &[u8]) {
        let mut buf = self.bytes.lock();
        let mut seq = self.seq_num.lock();
        let mut blk_idx = self.current_block.lock();
        let block_offset = *blk_idx * self.block_size;
        *blk_idx = (*blk_idx + 1) % self.block_nr;

        if self.version == LINUX_TPACKET_V3 {
            let desc_len = core::mem::size_of::<LinuxTpacketBlockDesc>();
            let hdr_len = core::mem::size_of::<LinuxTpacket3Hdr>();
            let mac_offset = hdr_len as u16;
            let net_offset = mac_offset + 14;
            let total_pkt_len = hdr_len + frame.len();
            let blk_len = (desc_len + total_pkt_len) as u32;

            let pkt_hdr = LinuxTpacket3Hdr {
                tp_next_offset: 0,
                tp_sec: 0,
                tp_nsec: 0,
                tp_snaplen: frame.len() as u32,
                tp_len: frame.len() as u32,
                tp_status: LINUX_TP_STATUS_USER,
                tp_mac: mac_offset,
                tp_net: net_offset,
                hv1: LinuxTpacketHdrVariant1 {
                    rxhash: 0,
                    vlan_tci: 0,
                    vlan_tpid: 0,
                    padding: 0,
                },
                tp_padding: [0u8; 8],
            };

            let desc = LinuxTpacketBlockDesc {
                version: LINUX_TPACKET_V3 as u32,
                offset_to_priv: 0,
                hdr: LinuxTpacketHdrV1 {
                    block_status: LINUX_TP_STATUS_USER,
                    num_pkts: 1,
                    offset_to_first_pkt: desc_len as u32,
                    blk_len,
                    seq_num: *seq,
                    ts_first_pkt: LinuxTpacketBdTs {
                        ts_sec: 0,
                        ts_usec: 0,
                    },
                    ts_last_pkt: LinuxTpacketBdTs {
                        ts_sec: 0,
                        ts_usec: 0,
                    },
                },
            };
            *seq += 1;

            let payload_offset = block_offset + desc_len + hdr_len;
            if payload_offset + frame.len() <= buf.len() {
                buf[payload_offset..payload_offset + frame.len()].copy_from_slice(frame);
            }

            let pkt_hdr_offset = block_offset + desc_len;
            if pkt_hdr_offset + hdr_len <= buf.len() {
                buf[pkt_hdr_offset..pkt_hdr_offset + hdr_len].copy_from_slice(pkt_hdr.as_bytes());
            }

            if block_offset + desc_len <= buf.len() {
                buf[block_offset..block_offset + desc_len].copy_from_slice(desc.as_bytes());
            }
        }
    }
}

#[derive(Debug)]
pub struct PacketSocket {
    pub(crate) sock_type: i32,
    pub(crate) protocol: u16,
    pub(crate) version: AtomicI32,
    pub(crate) bound_ifindex: AtomicI32,
    pub(crate) bound_protocol: AtomicU16,
    pub(crate) ring: PlMutex<Option<PacketRing>>,
    pub(crate) mapped_va: AtomicU64,
    pub(crate) raw_queue: PlMutex<VecDeque<Vec<u8>>>,
    pub(crate) wait_queue: Arc<crate::kernel::WaitQueue>,
    pub(crate) has_pending: AtomicBool,
}

impl PacketSocket {
    pub(crate) fn new(sock_type: i32, protocol: u16) -> Self {
        Self {
            sock_type,
            protocol,
            version: AtomicI32::new(LINUX_TPACKET_V1),
            bound_ifindex: AtomicI32::new(0),
            bound_protocol: AtomicU16::new(0),
            ring: PlMutex::new(None),
            mapped_va: AtomicU64::new(0),
            raw_queue: PlMutex::new(VecDeque::new()),
            wait_queue: Arc::new(crate::kernel::WaitQueue::new()),
            has_pending: AtomicBool::new(false),
        }
    }

    pub(crate) fn set_mapped_va(&self, va: GuestVa) {
        self.mapped_va.store(va.0, Ordering::Release);
    }

    pub(crate) fn initial_ring_bytes(&self) -> Option<Vec<u8>> {
        self.ring.lock().as_ref().map(|r| r.initial_bytes())
    }

    #[allow(dead_code)]
    pub(crate) fn has_pending_rx(&self) -> bool {
        self.has_pending.load(Ordering::Acquire)
    }

    pub(crate) fn readiness(&self, interest: LinuxEpollEvents) -> LinuxEpollEvents {
        let mut ready = LinuxEpollEvents::empty();
        if self.has_pending.load(Ordering::Acquire) {
            ready |= LinuxEpollEvents::IN;
        }
        ready |= LinuxEpollEvents::OUT;
        ready & (interest | LinuxEpollEvents::ERR | LinuxEpollEvents::HUP)
    }

    pub(crate) fn deliver_frame<M: CurrentMmMemory>(&self, memory: &mut M, frame: &[u8]) {
        let mut ring_guard = self.ring.lock();
        if let Some(ring) = ring_guard.as_mut() {
            ring.deliver_frame(frame);
            let bytes = ring.bytes();
            let va = self.mapped_va.load(Ordering::Acquire);
            if va != 0 {
                let _ = memory.write_bytes(va, &bytes);
            }
            self.has_pending.store(true, Ordering::Release);
            self.wait_queue.wake_all();
            return;
        }
        self.raw_queue.lock().push_back(frame.to_vec());
        self.has_pending.store(true, Ordering::Release);
        self.wait_queue.wake_all();
    }

    pub(crate) fn bind<M: CurrentMmMemory>(
        &self,
        memory: &M,
        addr_addr: u64,
        addrlen: u32,
    ) -> DispatchOutcome {
        if (addrlen as usize) < 8 {
            return DispatchOutcome::errno(LINUX_EINVAL);
        }
        let bytes = match memory.read_bytes(
            addr_addr,
            (addrlen as usize).min(core::mem::size_of::<LinuxSockaddrLl>()),
        ) {
            Ok(b) => b,
            Err(_) => return DispatchOutcome::errno(LINUX_EFAULT),
        };
        let family = u16::from_ne_bytes([bytes[0], bytes[1]]);
        if family as i32 != LINUX_AF_PACKET {
            return DispatchOutcome::errno(LINUX_EINVAL);
        }
        let protocol = u16::from_ne_bytes([bytes[2], bytes[3]]);
        let ifindex = i32::from_ne_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        self.bound_ifindex.store(ifindex, Ordering::SeqCst);
        self.bound_protocol.store(protocol, Ordering::SeqCst);
        DispatchOutcome::Returned { value: 0 }
    }

    pub(crate) fn sendto<M: CurrentMmMemory>(
        &self,
        memory: &mut M,
        bytes: &[u8],
        _flags: i32,
        addr_addr: u64,
        addrlen: u64,
    ) -> DispatchOutcome {
        let (dest_ifindex, dest_proto) = if addr_addr != 0 && addrlen >= 8 {
            let addr_bytes = match memory.read_bytes(
                addr_addr,
                (addrlen as usize).min(core::mem::size_of::<LinuxSockaddrLl>()),
            ) {
                Ok(b) => b,
                Err(_) => return DispatchOutcome::errno(LINUX_EFAULT),
            };
            let family = u16::from_ne_bytes([addr_bytes[0], addr_bytes[1]]);
            if family as i32 != LINUX_AF_PACKET {
                return DispatchOutcome::errno(LINUX_EINVAL);
            }
            let protocol = u16::from_ne_bytes([addr_bytes[2], addr_bytes[3]]);
            let ifindex =
                i32::from_ne_bytes([addr_bytes[4], addr_bytes[5], addr_bytes[6], addr_bytes[7]]);
            (ifindex, protocol)
        } else {
            (
                self.bound_ifindex.load(Ordering::SeqCst),
                self.bound_protocol.load(Ordering::SeqCst),
            )
        };
        let ifindex = if dest_ifindex != 0 {
            dest_ifindex
        } else {
            1 // default loopback
        };
        let proto = if dest_proto != 0 {
            dest_proto
        } else {
            self.protocol
        };
        broadcast_frame(memory, ifindex, proto, bytes);
        DispatchOutcome::returned_len_or_errno(bytes.len())
    }

    pub(crate) fn recvfrom<M: CurrentMmMemory>(
        &self,
        memory: &mut M,
        buf_addr: u64,
        len: usize,
        _flags: i32,
        _addr_addr: u64,
        _addrlen_addr: u64,
    ) -> DispatchOutcome {
        let mut queue = self.raw_queue.lock();
        let Some(pkt) = queue.pop_front() else {
            return DispatchOutcome::errno(LINUX_EAGAIN);
        };
        if queue.is_empty() {
            self.has_pending.store(false, Ordering::Release);
        }
        let copy_len = pkt.len().min(len);
        if memory.write_bytes(buf_addr, &pkt[..copy_len]).is_err() {
            return DispatchOutcome::errno(LINUX_EFAULT);
        }
        DispatchOutcome::returned_len_or_errno(copy_len)
    }

    pub(crate) fn getsockopt<M: CurrentMmMemory>(
        &self,
        memory: &mut M,
        optname: i32,
        optval_addr: u64,
        optlen_addr: u64,
    ) -> Result<DispatchOutcome, DispatchError> {
        match optname {
            LINUX_PACKET_VERSION => {
                let ver = self.version.load(Ordering::SeqCst);
                write_sockopt_value(memory, optval_addr, optlen_addr, &ver.to_ne_bytes())
            }
            _ => Ok(DispatchOutcome::errno(LINUX_ENOPROTOOPT)),
        }
    }

    pub(crate) fn setsockopt<M: CurrentMmMemory>(
        &self,
        memory: &M,
        level: i32,
        optname: i32,
        optval_addr: u64,
        optlen: u32,
    ) -> DispatchOutcome {
        if level != LINUX_SOL_PACKET {
            if level == LINUX_SOL_SOCKET {
                return DispatchOutcome::Returned { value: 0 };
            }
            return DispatchOutcome::errno(LINUX_ENOPROTOOPT);
        }
        match optname {
            LINUX_PACKET_VERSION => {
                if optlen < 4 {
                    return DispatchOutcome::errno(LINUX_EINVAL);
                }
                let bytes = match memory.read_bytes(optval_addr, 4) {
                    Ok(b) => b,
                    Err(_) => return DispatchOutcome::errno(LINUX_EFAULT),
                };
                let ver = i32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
                if ver != LINUX_TPACKET_V1 && ver != LINUX_TPACKET_V2 && ver != LINUX_TPACKET_V3 {
                    return DispatchOutcome::errno(LINUX_EINVAL);
                }
                if self.ring.lock().is_some() {
                    return DispatchOutcome::errno(LINUX_EBUSY);
                }
                self.version.store(ver, Ordering::SeqCst);
                DispatchOutcome::Returned { value: 0 }
            }
            LINUX_PACKET_RX_RING => {
                let ver = self.version.load(Ordering::SeqCst);
                if ver == LINUX_TPACKET_V3 {
                    if (optlen as usize) < core::mem::size_of::<LinuxTpacketReq3>() {
                        return DispatchOutcome::errno(LINUX_EINVAL);
                    }
                    let bytes = match memory
                        .read_bytes(optval_addr, core::mem::size_of::<LinuxTpacketReq3>())
                    {
                        Ok(b) => b,
                        Err(_) => return DispatchOutcome::errno(LINUX_EFAULT),
                    };
                    let req: LinuxTpacketReq3 = match LinuxTpacketReq3::read_from_bytes(&bytes) {
                        Ok(r) => r,
                        Err(_) => return DispatchOutcome::errno(LINUX_EINVAL),
                    };
                    match PacketRing::new_v3(&req) {
                        Ok(ring) => {
                            *self.ring.lock() = Some(ring);
                            DispatchOutcome::Returned { value: 0 }
                        }
                        Err(errno) => DispatchOutcome::errno(errno),
                    }
                } else {
                    if (optlen as usize) < core::mem::size_of::<LinuxTpacketReq>() {
                        return DispatchOutcome::errno(LINUX_EINVAL);
                    }
                    let bytes = match memory
                        .read_bytes(optval_addr, core::mem::size_of::<LinuxTpacketReq>())
                    {
                        Ok(b) => b,
                        Err(_) => return DispatchOutcome::errno(LINUX_EFAULT),
                    };
                    let req: LinuxTpacketReq = match LinuxTpacketReq::read_from_bytes(&bytes) {
                        Ok(r) => r,
                        Err(_) => return DispatchOutcome::errno(LINUX_EINVAL),
                    };
                    match PacketRing::new_v1_v2(ver, &req) {
                        Ok(ring) => {
                            *self.ring.lock() = Some(ring);
                            DispatchOutcome::Returned { value: 0 }
                        }
                        Err(errno) => DispatchOutcome::errno(errno),
                    }
                }
            }
            _ => DispatchOutcome::errno(LINUX_ENOPROTOOPT),
        }
    }

    pub(crate) fn getsockname<M: CurrentMmMemory>(
        &self,
        memory: &mut M,
        addr_addr: u64,
        addrlen_addr: u64,
    ) -> DispatchOutcome {
        if addr_addr == 0 || addrlen_addr == 0 {
            return DispatchOutcome::errno(LINUX_EFAULT);
        }
        let mut sll = LinuxSockaddrLl {
            sll_family: LINUX_AF_PACKET as u16,
            sll_protocol: self.bound_protocol.load(Ordering::SeqCst),
            sll_ifindex: self.bound_ifindex.load(Ordering::SeqCst),
            sll_hatype: 0,
            sll_pkttype: 0,
            sll_halen: 6,
            sll_addr: [0; 8],
        };
        if sll.sll_protocol == 0 {
            sll.sll_protocol = self.protocol;
        }
        let sll_bytes = sll.as_bytes();
        if super::support::write_linux_sockaddr(memory, addr_addr, addrlen_addr, sll_bytes).is_err()
        {
            return DispatchOutcome::errno(LINUX_EFAULT);
        }
        DispatchOutcome::Returned { value: 0 }
    }
}

static PACKET_SOCKETS: PlMutex<Vec<Weak<PacketSocket>>> = PlMutex::new(Vec::new());

pub(crate) fn register_packet_socket(socket: &Arc<PacketSocket>) {
    let mut guard = PACKET_SOCKETS.lock();
    guard.retain(|weak| weak.strong_count() > 0);
    guard.push(Arc::downgrade(socket));
}

pub(crate) fn broadcast_frame<M: CurrentMmMemory>(
    memory: &mut M,
    dest_ifindex: i32,
    dest_protocol: u16,
    frame: &[u8],
) {
    let sockets: Vec<Arc<PacketSocket>> = {
        let mut guard = PACKET_SOCKETS.lock();
        guard.retain(|weak| weak.strong_count() > 0);
        guard.iter().filter_map(|weak| weak.upgrade()).collect()
    };
    for sock in sockets {
        let bound_if = sock.bound_ifindex.load(Ordering::Relaxed);
        if bound_if != 0 && bound_if != dest_ifindex {
            continue;
        }
        let bound_proto = sock.bound_protocol.load(Ordering::Relaxed);
        let sock_proto = sock.protocol;
        let proto_to_check = if bound_proto != 0 {
            bound_proto
        } else {
            sock_proto
        };
        if proto_to_check != 0
            && proto_to_check != 0x0300 /* ETH_P_ALL in net order */
            && proto_to_check != dest_protocol
        {
            continue;
        }
        sock.deliver_frame(memory, frame);
    }
}

impl<'a> NetView<'a> {
    pub(in crate::dispatch) fn packet_socket(
        &self,
        kernel: &crate::kernel::KernelContext,
        type_: i32,
        protocol: i32,
    ) -> DispatchOutcome {
        if !super::creds::has_effective_capability(kernel, crate::namespace::process::CAP_NET_RAW) {
            return DispatchOutcome::errno(LINUX_EPERM);
        }
        let socket_flags = LinuxSocketTypeFlags::from_bits_retain(type_);
        let nonblock = socket_flags.contains(LinuxSocketTypeFlags::NONBLOCK);
        let cloexec = socket_flags.contains(LinuxSocketTypeFlags::CLOEXEC);
        let base_type = type_ & !LinuxSocketTypeFlags::SUPPORTED_MASK;
        if base_type != LINUX_SOCK_RAW && base_type != LINUX_SOCK_DGRAM {
            return DispatchOutcome::errno(LINUX_ESOCKTNOSUPPORT);
        }
        let proto = (protocol as u32 & 0xFFFF) as u16;
        let socket = Arc::new(PacketSocket::new(base_type, proto));
        register_packet_socket(&socket);
        let status_flags = LINUX_O_RDWR | if nonblock { LINUX_O_NONBLOCK } else { 0 };
        let fd_flags = if cloexec { LINUX_FD_CLOEXEC } else { 0 };
        self.install_fd_with_status_flags(
            OpenDescription::Packet {
                base: OpenDescriptionBase::new(status_flags),
                socket,
            },
            status_flags,
            fd_flags,
        )
    }
}
