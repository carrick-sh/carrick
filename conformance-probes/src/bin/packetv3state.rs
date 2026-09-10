//! Bounded TPACKET_V3 receive-ring ownership and descriptor lifetime reducer.
//! Native fixture: Linux arm64, CAP_NET_RAW, isolated network namespace with lo.
//! ABI reference: https://www.kernel.org/doc/html/latest/networking/packet_mmap.html
//! Only sends a private experimental Ethernet type on loopback; no external traffic.
use conformance_probes::{errno, report};
use std::sync::atomic::{AtomicU32, Ordering};

fn error(rc: i64) -> i32 {
    if rc < 0 {
        errno()
    } else {
        0
    }
}
unsafe fn option<T>(fd: i32, name: i32, value: &T) -> i32 {
    libc::setsockopt(
        fd,
        263,
        name,
        (value as *const T).cast(),
        std::mem::size_of::<T>() as u32,
    )
}
fn main() {
    unsafe {
        let protocol = 0x88b5u16.to_be();
        let fd = libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            protocol as i32,
        );
        let socket_errno = error(fd as i64);
        let mut version = -1i32;
        let mut len = 4u32;
        let initial_get =
            libc::getsockopt(fd, 263, 10, (&mut version as *mut i32).cast(), &mut len);
        let initial_errno = error(initial_get as i64);
        let initial_version = version;
        let set = option(fd, 10, &2i32);
        let set_errno = error(set as i64);
        version = -1;
        len = 4;
        let get = libc::getsockopt(fd, 263, 10, (&mut version as *mut i32).cast(), &mut len);
        let get_errno = error(get as i64);
        let req = libc::tpacket_req3 {
            tp_block_size: 4096,
            tp_block_nr: 1,
            tp_frame_size: 2048,
            tp_frame_nr: 2,
            tp_retire_blk_tov: 10,
            tp_sizeof_priv: 0,
            tp_feature_req_word: 0,
        };
        let ring = option(fd, 5, &req);
        let ring_errno = error(ring as i64);
        let map = if ring == 0 {
            libc::mmap(
                std::ptr::null_mut(),
                4096,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                0,
            )
        } else {
            libc::MAP_FAILED
        };
        let map_errno = if ring != 0 {
            -1
        } else if map == libc::MAP_FAILED {
            errno()
        } else {
            0
        };
        let index = libc::if_nametoindex(c"lo".as_ptr());
        let mut address: libc::sockaddr_ll = std::mem::zeroed();
        address.sll_family = libc::AF_PACKET as u16;
        address.sll_protocol = protocol;
        address.sll_ifindex = index as i32;
        address.sll_halen = 6;
        let bind = libc::bind(
            fd,
            (&address as *const libc::sockaddr_ll).cast(),
            std::mem::size_of_val(&address) as u32,
        );
        let bind_errno = error(bind as i64);
        let duplicate = libc::dup(fd);
        let dup_errno = error(duplicate as i64);
        let close_original = libc::close(fd);
        let close_original_errno = error(close_original as i64);
        let tx = libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            protocol as i32,
        );
        let tx_errno = error(tx as i64);
        let mut frame = [0x5au8; 64];
        frame[..12].fill(0);
        frame[12..14].copy_from_slice(&0x88b5u16.to_be_bytes());
        frame[14..30].copy_from_slice(b"carrick-ring-v3!");
        let sent = libc::sendto(
            tx,
            frame.as_ptr().cast(),
            frame.len(),
            libc::MSG_DONTWAIT,
            (&address as *const libc::sockaddr_ll).cast(),
            std::mem::size_of_val(&address) as u32,
        );
        let send_errno = error(sent as i64);
        let mut pollfd = libc::pollfd {
            fd: duplicate,
            events: libc::POLLIN,
            revents: 0,
        };
        let polled = libc::poll(&mut pollfd, 1, 2000);
        let poll_errno = error(polled as i64);
        let mut user_owned = false;
        let mut block_version = -1i32;
        let mut packet_found = false;
        let mut bounds_valid = false;
        let mut released = false;
        if map != libc::MAP_FAILED {
            let base = map.cast::<u8>();
            let block = map.cast::<libc::tpacket_block_desc>();
            let status = &*std::ptr::addr_of!((*block).hdr.bh1.block_status).cast::<AtomicU32>();
            user_owned = status.load(Ordering::Acquire) & 1 != 0;
            if user_owned {
                block_version =
                    std::ptr::read_volatile(std::ptr::addr_of!((*block).version)) as i32;
                let header = std::ptr::read_volatile(std::ptr::addr_of!((*block).hdr.bh1));
                let mut offset = header.offset_to_first_pkt as usize;
                bounds_valid =
                    header.blk_len <= 4096 && header.num_pkts > 0 && header.num_pkts <= 64;
                for _ in 0..header.num_pkts.min(64) {
                    if offset
                        .checked_add(std::mem::size_of::<libc::tpacket3_hdr>())
                        .is_none_or(|end| end > 4096)
                    {
                        bounds_valid = false;
                        break;
                    }
                    let packet =
                        std::ptr::read_unaligned(base.add(offset).cast::<libc::tpacket3_hdr>());
                    let start = offset + packet.tp_mac as usize;
                    let end = start.checked_add(packet.tp_snaplen as usize);
                    if end.is_none_or(|end| end > 4096) {
                        bounds_valid = false;
                        break;
                    }
                    if packet.tp_snaplen as usize == frame.len()
                        && std::slice::from_raw_parts(base.add(start), frame.len()) == frame
                    {
                        packet_found = true;
                    }
                    if packet.tp_next_offset == 0 {
                        break;
                    }
                    if (packet.tp_next_offset as usize) < std::mem::size_of::<libc::tpacket3_hdr>()
                    {
                        bounds_valid = false;
                        break;
                    }
                    offset += packet.tp_next_offset as usize;
                }
                status.store(0, Ordering::Release);
                released = status.load(Ordering::Acquire) == 0;
            }
        }
        libc::close(tx);
        let close_last = libc::close(duplicate);
        let close_last_errno = error(close_last as i64);
        let mut mapped_after_close = false;
        let mut unmap_rc = -1;
        if map != libc::MAP_FAILED {
            mapped_after_close = std::ptr::read_volatile(map.cast::<u32>()) == 2;
            unmap_rc = libc::munmap(map, 4096);
        }
        report!(
            socket_errno = socket_errno,
            initial_get_rc = initial_get,
            initial_get_errno = initial_errno,
            initial_version = initial_version,
            set_version_rc = set,
            set_version_errno = set_errno,
            get_version_rc = get,
            get_version_errno = get_errno,
            version = version,
            ring_rc = ring,
            ring_errno = ring_errno,
            mmap_errno = map_errno,
            loopback_present = index > 0,
            bind_rc = bind,
            bind_errno = bind_errno,
            dup_errno = dup_errno,
            close_original_rc = close_original,
            close_original_errno = close_original_errno,
            tx_errno = tx_errno,
            sent = sent,
            send_errno = send_errno,
            poll_rc = polled,
            poll_errno = poll_errno,
            readable = pollfd.revents & libc::POLLIN != 0,
            user_owned = user_owned,
            block_version = block_version,
            packet_bounds_valid = bounds_valid,
            exact_payload = packet_found,
            released_to_kernel = released,
            close_last_rc = close_last,
            close_last_errno = close_last_errno,
            mapping_survives_close = mapped_after_close,
            munmap_rc = unmap_rc
        );
    }
}
