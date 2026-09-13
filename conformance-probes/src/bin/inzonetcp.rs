//! Conformance probe for guest loopback TCP stream semantics.
//!
//! Pins Linux semantics for in-zone loopback TCP connections:
//!   1. `listen` on `0.0.0.0:0`, SO_ACCEPTCONN on listening and fresh sockets;
//!   2. `blocking_connect`: address reflection (`getpeername`, `getsockname`),
//!      loopback identity (127.0.0.1);
//!   3. `nonblocking_connect`: immediate return / errno, poll(POLLOUT) readiness,
//!      SO_ERROR readback, and listener accept;
//!   4. `echo64k`: 64 KiB bidirectional stream transfer with deterministic
//!      payload pattern, FNV-1a checksum validation, and short-write detection;
//!   5. `fionread`: `ioctl(FIONREAD)` pending byte count after write;
//!   6. `shutdown_wr`: POLLRDHUP / POLLIN on half-close, EOF read, EPIPE on
//!      write after SHUT_WR, full shutdown readback;
//!   7. `listener_close_with_backlog`: unaccepted connection reset behavior
//!      when listener closes with pending connections in backlog;
//!   8. `tcp_nodelay`: TCP_NODELAY default and set round-trip;
//!   9. `connect_refused`: connect to an unbound port;
//!   10. `getsockopt_types`: SO_TYPE, SO_DOMAIN, SO_PROTOCOL on accepted socket.
//!
//! Output is deterministic `key=value` lines only. Every wait is bounded by a
//! `poll` with a 5 s cap so a lost wake is a false line, never a hang.

use conformance_probes::{errno, report};

const POLLRDHUP: libc::c_short = 0x2000;
const SO_DOMAIN: libc::c_int = 39;
const SO_PROTOCOL: libc::c_int = 38;

const ECHO_TOTAL: usize = 65536;

fn fnv1a(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8422_2325, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(0x1000_0000_01b3)
    })
}

fn set_nonblock(fd: i32) {
    unsafe {
        let fl = libc::fcntl(fd, libc::F_GETFL);
        if fl >= 0 {
            libc::fcntl(fd, libc::F_SETFL, fl | libc::O_NONBLOCK);
        }
    }
}

fn main() {
    unsafe {
        conformance_probes::install_ign(libc::SIGPIPE);

        // ---------------------------------------------------------------------
        // Case 1: listen
        // ---------------------------------------------------------------------
        let listener = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
        let mut sin: libc::sockaddr_in = std::mem::zeroed();
        sin.sin_family = libc::AF_INET as libc::sa_family_t;
        sin.sin_addr.s_addr = libc::INADDR_ANY.to_be();
        sin.sin_port = 0;

        let b_rc = if listener >= 0 {
            libc::bind(
                listener,
                &sin as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        } else {
            -1
        };

        let l_rc = if b_rc == 0 {
            libc::listen(listener, 8)
        } else {
            -1
        };
        let listen_ok = listener >= 0 && b_rc == 0 && l_rc == 0;

        let mut bound_sin: libc::sockaddr_in = std::mem::zeroed();
        let mut slen = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        if listen_ok {
            libc::getsockname(
                listener,
                &mut bound_sin as *mut _ as *mut libc::sockaddr,
                &mut slen,
            );
        }
        let listen_port_be = bound_sin.sin_port;

        let mut val_l: libc::c_int = 0;
        let mut optlen = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        let so_acceptconn_listener = if listen_ok
            && libc::getsockopt(
                listener,
                libc::SOL_SOCKET,
                libc::SO_ACCEPTCONN,
                &mut val_l as *mut _ as *mut libc::c_void,
                &mut optlen,
            ) == 0
        {
            val_l
        } else {
            errno()
        };

        let unlistened = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
        let mut val_u: libc::c_int = 0;
        let mut optlen_u = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        let so_acceptconn_unlistened = if unlistened >= 0
            && libc::getsockopt(
                unlistened,
                libc::SOL_SOCKET,
                libc::SO_ACCEPTCONN,
                &mut val_u as *mut _ as *mut libc::c_void,
                &mut optlen_u,
            ) == 0
        {
            val_u
        } else {
            errno()
        };
        if unlistened >= 0 {
            libc::close(unlistened);
        }

        report!(
            listen_ok = listen_ok,
            so_acceptconn_listener = so_acceptconn_listener,
            so_acceptconn_unlistened = so_acceptconn_unlistened,
        );

        // ---------------------------------------------------------------------
        // Case 2: blocking_connect
        // ---------------------------------------------------------------------
        let client_thread = std::thread::spawn(move || {
            let client_fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
            let mut c_sin: libc::sockaddr_in = std::mem::zeroed();
            c_sin.sin_family = libc::AF_INET as libc::sa_family_t;
            c_sin.sin_addr.s_addr = u32::from_ne_bytes([127, 0, 0, 1]);
            c_sin.sin_port = listen_port_be;
            let c_rc = if client_fd >= 0 {
                libc::connect(
                    client_fd,
                    &c_sin as *const _ as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                )
            } else {
                -1
            };
            (client_fd, c_rc)
        });

        let mut pfd_listen = libc::pollfd {
            fd: listener,
            events: libc::POLLIN,
            revents: 0,
        };
        let p_rc = libc::poll(&mut pfd_listen, 1, 5000);
        let accepted_fd = if p_rc > 0 && (pfd_listen.revents & libc::POLLIN) != 0 {
            libc::accept(listener, std::ptr::null_mut(), std::ptr::null_mut())
        } else {
            -1
        };

        let (client_fd, c_rc) = client_thread.join().unwrap_or((-1, -1));
        let accept_ok = accepted_fd >= 0 && c_rc == 0;

        let mut client_sin: libc::sockaddr_in = std::mem::zeroed();
        let mut slen_c = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        let gsn_c = if client_fd >= 0 {
            libc::getsockname(
                client_fd,
                &mut client_sin as *mut _ as *mut libc::sockaddr,
                &mut slen_c,
            )
        } else {
            -1
        };

        let mut accepted_peer_sin: libc::sockaddr_in = std::mem::zeroed();
        let mut slen_ap = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        let gpn_a = if accepted_fd >= 0 {
            libc::getpeername(
                accepted_fd,
                &mut accepted_peer_sin as *mut _ as *mut libc::sockaddr,
                &mut slen_ap,
            )
        } else {
            -1
        };

        let peer_eq_client_sockname = accept_ok
            && gsn_c == 0
            && gpn_a == 0
            && accepted_peer_sin.sin_family == client_sin.sin_family
            && accepted_peer_sin.sin_port == client_sin.sin_port
            && accepted_peer_sin.sin_addr.s_addr == client_sin.sin_addr.s_addr;

        let mut accepted_sin: libc::sockaddr_in = std::mem::zeroed();
        let mut slen_a = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        let gsn_a = if accepted_fd >= 0 {
            libc::getsockname(
                accepted_fd,
                &mut accepted_sin as *mut _ as *mut libc::sockaddr,
                &mut slen_a,
            )
        } else {
            -1
        };

        let loopback_addr = u32::from_ne_bytes([127, 0, 0, 1]);
        let accepted_sockname_ip_loopback =
            accept_ok && gsn_a == 0 && accepted_sin.sin_addr.s_addr == loopback_addr;
        let accepted_sockname_port_eq_listen =
            accept_ok && gsn_a == 0 && accepted_sin.sin_port == listen_port_be;

        let mut client_peer_sin: libc::sockaddr_in = std::mem::zeroed();
        let mut slen_cp = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        let gpn_c = if client_fd >= 0 {
            libc::getpeername(
                client_fd,
                &mut client_peer_sin as *mut _ as *mut libc::sockaddr,
                &mut slen_cp,
            )
        } else {
            -1
        };
        let client_peername_ip_loopback =
            accept_ok && gpn_c == 0 && client_peer_sin.sin_addr.s_addr == loopback_addr;

        report!(
            accept_ok = accept_ok,
            peer_eq_client_sockname = peer_eq_client_sockname,
            accepted_sockname_ip_loopback = accepted_sockname_ip_loopback,
            accepted_sockname_port_eq_listen = accepted_sockname_port_eq_listen,
            client_peername_ip_loopback = client_peername_ip_loopback,
        );

        // ---------------------------------------------------------------------
        // Case 3: nonblocking_connect
        // ---------------------------------------------------------------------
        let nb_sock = libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_NONBLOCK, 0);
        let mut nb_target: libc::sockaddr_in = std::mem::zeroed();
        nb_target.sin_family = libc::AF_INET as libc::sa_family_t;
        nb_target.sin_addr.s_addr = loopback_addr;
        nb_target.sin_port = listen_port_be;

        let nb_rc = if nb_sock >= 0 {
            libc::connect(
                nb_sock,
                &nb_target as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        } else {
            -1
        };
        let nb_connect_ret = if nb_rc == 0 { 0 } else { errno() };

        let mut pfd_nb = libc::pollfd {
            fd: nb_sock,
            events: libc::POLLOUT,
            revents: 0,
        };
        let _ = libc::poll(&mut pfd_nb, 1, 5000);
        let nb_connect_pollout_revents = format!("0x{:x}", pfd_nb.revents);

        let mut so_err: libc::c_int = 0;
        let mut optlen_err = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        let gso_rc = if nb_sock >= 0 {
            libc::getsockopt(
                nb_sock,
                libc::SOL_SOCKET,
                libc::SO_ERROR,
                &mut so_err as *mut _ as *mut libc::c_void,
                &mut optlen_err,
            )
        } else {
            -1
        };
        let nb_so_error = if gso_rc == 0 { so_err } else { errno() };

        let mut pfd_l = libc::pollfd {
            fd: listener,
            events: libc::POLLIN,
            revents: 0,
        };
        let _ = libc::poll(&mut pfd_l, 1, 5000);
        let nb_acc_fd = libc::accept(listener, std::ptr::null_mut(), std::ptr::null_mut());
        let nb_accept_ok = nb_acc_fd >= 0;

        if nb_sock >= 0 {
            libc::close(nb_sock);
        }
        if nb_acc_fd >= 0 {
            libc::close(nb_acc_fd);
        }

        report!(
            nb_connect_ret = nb_connect_ret,
            nb_connect_pollout_revents = nb_connect_pollout_revents,
            nb_so_error = nb_so_error,
            nb_accept_ok = nb_accept_ok,
        );

        // ---------------------------------------------------------------------
        // Case 4: echo64k
        // ---------------------------------------------------------------------
        set_nonblock(client_fd);
        set_nonblock(accepted_fd);

        let sent_pattern: Vec<u8> = (0..ECHO_TOTAL).map(|i| (i * 7 + 3) as u8).collect();

        // Direction 1: client writes, server reads
        let pattern_c = sent_pattern.clone();
        let writer_handle = std::thread::spawn(move || {
            let mut sent = 0usize;
            let mut short = false;
            while sent < ECHO_TOTAL {
                let mut pfd = libc::pollfd {
                    fd: client_fd,
                    events: libc::POLLOUT,
                    revents: 0,
                };
                if libc::poll(&mut pfd, 1, 5000) <= 0 {
                    break;
                }
                let want = ECHO_TOTAL - sent;
                let n = libc::write(
                    client_fd,
                    pattern_c[sent..].as_ptr().cast(),
                    want,
                );
                if n > 0 {
                    let n = n as usize;
                    if n < want {
                        short = true;
                    }
                    sent += n;
                } else if n < 0 {
                    let e = errno();
                    if e != libc::EAGAIN && e != libc::EWOULDBLOCK && e != libc::EINTR {
                        break;
                    }
                } else {
                    break;
                }
            }
            short
        });

        let mut server_buf = vec![0u8; ECHO_TOTAL];
        let mut recvd = 0usize;
        while recvd < ECHO_TOTAL {
            let mut pfd = libc::pollfd {
                fd: accepted_fd,
                events: libc::POLLIN,
                revents: 0,
            };
            if libc::poll(&mut pfd, 1, 5000) <= 0 {
                break;
            }
            let want = ECHO_TOTAL - recvd;
            let n = libc::read(
                accepted_fd,
                server_buf[recvd..].as_mut_ptr().cast(),
                want,
            );
            if n > 0 {
                recvd += n as usize;
            } else if n < 0 {
                let e = errno();
                if e != libc::EAGAIN && e != libc::EWOULDBLOCK && e != libc::EINTR {
                    break;
                }
            } else {
                break;
            }
        }
        let client_short_write = writer_handle.join().unwrap_or(false);
        let echo_bytes_out = recvd;

        // Direction 2: server echoes back, client reads
        let reader_handle = std::thread::spawn(move || {
            let mut client_buf = vec![0u8; ECHO_TOTAL];
            let mut recvd_back = 0usize;
            while recvd_back < ECHO_TOTAL {
                let mut pfd = libc::pollfd {
                    fd: client_fd,
                    events: libc::POLLIN,
                    revents: 0,
                };
                if libc::poll(&mut pfd, 1, 5000) <= 0 {
                    break;
                }
                let want = ECHO_TOTAL - recvd_back;
                let n = libc::read(
                    client_fd,
                    client_buf[recvd_back..].as_mut_ptr().cast(),
                    want,
                );
                if n > 0 {
                    recvd_back += n as usize;
                } else if n < 0 {
                    let e = errno();
                    if e != libc::EAGAIN && e != libc::EWOULDBLOCK && e != libc::EINTR {
                        break;
                    }
                } else {
                    break;
                }
            }
            (client_buf, recvd_back)
        });

        let mut sent_back = 0usize;
        let mut server_short_write = false;
        while sent_back < echo_bytes_out {
            let mut pfd = libc::pollfd {
                fd: accepted_fd,
                events: libc::POLLOUT,
                revents: 0,
            };
            if libc::poll(&mut pfd, 1, 5000) <= 0 {
                break;
            }
            let want = echo_bytes_out - sent_back;
            let n = libc::write(
                accepted_fd,
                server_buf[sent_back..echo_bytes_out].as_ptr().cast(),
                want,
            );
            if n > 0 {
                let n = n as usize;
                if n < want {
                    server_short_write = true;
                }
                sent_back += n;
            } else if n < 0 {
                let e = errno();
                if e != libc::EAGAIN && e != libc::EWOULDBLOCK && e != libc::EINTR {
                    break;
                }
            } else {
                break;
            }
        }
        let (client_buf, echo_bytes_back) = reader_handle.join().unwrap_or((vec![], 0));
        let echo_checksum_ok =
            echo_bytes_back == ECHO_TOTAL && fnv1a(&client_buf) == fnv1a(&sent_pattern);
        let short_writes_seen = client_short_write || server_short_write;

        report!(
            echo_bytes_out = echo_bytes_out,
            echo_bytes_back = echo_bytes_back,
            echo_checksum_ok = echo_checksum_ok,
            short_writes_seen = short_writes_seen,
        );

        // ---------------------------------------------------------------------
        // Case 5: fionread
        // ---------------------------------------------------------------------
        let fion_payload = [0x5au8; 1000];
        let mut written_fion = 0usize;
        while written_fion < 1000 {
            let mut pfd = libc::pollfd {
                fd: accepted_fd,
                events: libc::POLLOUT,
                revents: 0,
            };
            if libc::poll(&mut pfd, 1, 5000) <= 0 {
                break;
            }
            let n = libc::write(
                accepted_fd,
                fion_payload[written_fion..].as_ptr().cast(),
                1000 - written_fion,
            );
            if n > 0 {
                written_fion += n as usize;
            } else if n < 0 {
                let e = errno();
                if e != libc::EAGAIN && e != libc::EWOULDBLOCK && e != libc::EINTR {
                    break;
                }
            } else {
                break;
            }
        }

        let mut pfd_client = libc::pollfd {
            fd: client_fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let _ = libc::poll(&mut pfd_client, 1, 5000);

        let mut avail: libc::c_int = 0;
        let ioctl_rc = libc::ioctl(
            client_fd,
            libc::FIONREAD as _,
            &mut avail as *mut libc::c_int,
        );
        let fionread_after_write = if ioctl_rc == 0 { avail } else { errno() };

        let mut drain = [0u8; 1024];
        let mut drained = 0usize;
        while drained < 1000 {
            let mut pfd = libc::pollfd {
                fd: client_fd,
                events: libc::POLLIN,
                revents: 0,
            };
            if libc::poll(&mut pfd, 1, 5000) <= 0 {
                break;
            }
            let n = libc::read(client_fd, drain.as_mut_ptr().cast(), drain.len());
            if n > 0 {
                drained += n as usize;
            } else if n < 0 {
                let e = errno();
                if e != libc::EAGAIN && e != libc::EWOULDBLOCK && e != libc::EINTR {
                    break;
                }
            } else {
                break;
            }
        }

        report!(fionread_after_write = fionread_after_write);

        // ---------------------------------------------------------------------
        // Case 6: shutdown_wr
        // ---------------------------------------------------------------------
        libc::shutdown(client_fd, libc::SHUT_WR);

        let mut pfd_server = libc::pollfd {
            fd: accepted_fd,
            events: libc::POLLIN | POLLRDHUP,
            revents: 0,
        };
        let _ = libc::poll(&mut pfd_server, 1, 5000);
        let rdhup_revents = format!("0x{:x}", pfd_server.revents);

        let mut s_buf = [0u8; 16];
        let s_rc = libc::recv(accepted_fd, s_buf.as_mut_ptr().cast(), s_buf.len(), 0);
        let (recv_after_shutdown_ret, recv_after_shutdown_errno) = if s_rc >= 0 {
            (s_rc as i64, 0)
        } else {
            (s_rc as i64, errno())
        };

        let w_byte = [1u8];
        let w_rc = libc::write(client_fd, w_byte.as_ptr().cast(), 1);
        let write_after_shut_wr_errno = if w_rc < 0 { errno() } else { 0 };

        libc::shutdown(accepted_fd, libc::SHUT_RDWR);
        let mut c_buf = [0u8; 16];
        let c_rc = libc::recv(client_fd, c_buf.as_mut_ptr().cast(), c_buf.len(), 0);
        let (client_recv_after_peer_shutdown_ret, client_recv_after_peer_shutdown_errno) =
            if c_rc >= 0 {
                (c_rc as i64, 0)
            } else {
                (c_rc as i64, errno())
            };

        report!(
            rdhup_revents = rdhup_revents,
            recv_after_shutdown_ret = recv_after_shutdown_ret,
            recv_after_shutdown_errno = recv_after_shutdown_errno,
            write_after_shut_wr_errno = write_after_shut_wr_errno,
            client_recv_after_peer_shutdown_ret = client_recv_after_peer_shutdown_ret,
            client_recv_after_peer_shutdown_errno = client_recv_after_peer_shutdown_errno,
        );

        // ---------------------------------------------------------------------
        // Case 7: listener_close_with_backlog
        // ---------------------------------------------------------------------
        let l7 = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
        let mut sin7: libc::sockaddr_in = std::mem::zeroed();
        sin7.sin_family = libc::AF_INET as libc::sa_family_t;
        sin7.sin_addr.s_addr = libc::INADDR_ANY.to_be();
        sin7.sin_port = 0;
        let _ = libc::bind(
            l7,
            &sin7 as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        );
        let _ = libc::listen(l7, 8);
        let mut bound7: libc::sockaddr_in = std::mem::zeroed();
        let mut slen7 = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        let _ = libc::getsockname(
            l7,
            &mut bound7 as *mut _ as *mut libc::sockaddr,
            &mut slen7,
        );
        let port7_be = bound7.sin_port;

        let c7 = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
        let mut target7: libc::sockaddr_in = std::mem::zeroed();
        target7.sin_family = libc::AF_INET as libc::sa_family_t;
        target7.sin_addr.s_addr = loopback_addr;
        target7.sin_port = port7_be;
        let _ = libc::connect(
            c7,
            &target7 as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        );

        libc::close(l7);

        let mut pfd7 = libc::pollfd {
            fd: c7,
            events: libc::POLLIN | libc::POLLHUP | libc::POLLERR,
            revents: 0,
        };
        let _ = libc::poll(&mut pfd7, 1, 5000);
        let backlog_client_revents = format!("0x{:x}", pfd7.revents);

        let mut b7 = [0u8; 16];
        let r7_rc = libc::recv(c7, b7.as_mut_ptr().cast(), b7.len(), 0);
        let (backlog_client_recv_ret, backlog_client_recv_errno) = if r7_rc >= 0 {
            (r7_rc as i64, 0)
        } else {
            (r7_rc as i64, errno())
        };

        let w7 = [1u8];
        let w7_rc = libc::write(c7, w7.as_ptr().cast(), 1);
        let (backlog_client_write_ret, backlog_client_write_errno) = if w7_rc >= 0 {
            (w7_rc as i64, 0)
        } else {
            (w7_rc as i64, errno())
        };
        libc::close(c7);

        report!(
            backlog_client_revents = backlog_client_revents,
            backlog_client_recv_ret = backlog_client_recv_ret,
            backlog_client_recv_errno = backlog_client_recv_errno,
            backlog_client_write_ret = backlog_client_write_ret,
            backlog_client_write_errno = backlog_client_write_errno,
        );

        // ---------------------------------------------------------------------
        // Case 8: tcp_nodelay
        // ---------------------------------------------------------------------
        let mut nodelay: libc::c_int = 0;
        let mut optlen_nd = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        let g_rc = libc::getsockopt(
            accepted_fd,
            libc::IPPROTO_TCP,
            libc::TCP_NODELAY,
            &mut nodelay as *mut _ as *mut libc::c_void,
            &mut optlen_nd,
        );
        let nodelay_default = if g_rc == 0 { nodelay } else { errno() };

        let one: libc::c_int = 1;
        let s_rc = libc::setsockopt(
            accepted_fd,
            libc::IPPROTO_TCP,
            libc::TCP_NODELAY,
            &one as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
        let mut nodelay2: libc::c_int = 0;
        let mut optlen_nd2 = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        let g2_rc = libc::getsockopt(
            accepted_fd,
            libc::IPPROTO_TCP,
            libc::TCP_NODELAY,
            &mut nodelay2 as *mut _ as *mut libc::c_void,
            &mut optlen_nd2,
        );
        let nodelay_after_set = if s_rc == 0 && g2_rc == 0 {
            nodelay2
        } else {
            errno()
        };

        report!(
            nodelay_default = nodelay_default,
            nodelay_after_set = nodelay_after_set,
        );

        // ---------------------------------------------------------------------
        // Case 9: connect_refused
        // ---------------------------------------------------------------------
        let dummy = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
        let mut d_sin: libc::sockaddr_in = std::mem::zeroed();
        d_sin.sin_family = libc::AF_INET as libc::sa_family_t;
        d_sin.sin_addr.s_addr = loopback_addr;
        d_sin.sin_port = 0;
        let _ = libc::bind(
            dummy,
            &d_sin as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        );
        let mut d_bound: libc::sockaddr_in = std::mem::zeroed();
        let mut slen_d = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        let _ = libc::getsockname(
            dummy,
            &mut d_bound as *mut _ as *mut libc::sockaddr,
            &mut slen_d,
        );
        let unbound_port_be = d_bound.sin_port;
        if dummy >= 0 {
            libc::close(dummy);
        }

        let s_refused = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
        let mut target_refused: libc::sockaddr_in = std::mem::zeroed();
        target_refused.sin_family = libc::AF_INET as libc::sa_family_t;
        target_refused.sin_addr.s_addr = loopback_addr;
        target_refused.sin_port = unbound_port_be;
        let cr_rc = libc::connect(
            s_refused,
            &target_refused as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        );
        let refused_errno = if cr_rc < 0 { errno() } else { 0 };
        if s_refused >= 0 {
            libc::close(s_refused);
        }

        report!(refused_errno = refused_errno);

        // ---------------------------------------------------------------------
        // Case 10: getsockopt_types
        // ---------------------------------------------------------------------
        let mut so_type_val: libc::c_int = 0;
        let mut optlen = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        let rc1 = libc::getsockopt(
            accepted_fd,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            &mut so_type_val as *mut _ as *mut libc::c_void,
            &mut optlen,
        );
        let so_type = if rc1 == 0 { so_type_val } else { errno() };

        let mut so_domain_val: libc::c_int = 0;
        let mut optlen = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        let rc2 = libc::getsockopt(
            accepted_fd,
            libc::SOL_SOCKET,
            SO_DOMAIN,
            &mut so_domain_val as *mut _ as *mut libc::c_void,
            &mut optlen,
        );
        let so_domain = if rc2 == 0 { so_domain_val } else { errno() };

        let mut so_proto_val: libc::c_int = 0;
        let mut optlen = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        let rc3 = libc::getsockopt(
            accepted_fd,
            libc::SOL_SOCKET,
            SO_PROTOCOL,
            &mut so_proto_val as *mut _ as *mut libc::c_void,
            &mut optlen,
        );
        let so_protocol = if rc3 == 0 { so_proto_val } else { errno() };

        report!(
            so_type = so_type,
            so_domain = so_domain,
            so_protocol = so_protocol,
        );

        if client_fd >= 0 {
            libc::close(client_fd);
        }
        if accepted_fd >= 0 {
            libc::close(accepted_fd);
        }
        if listener >= 0 {
            libc::close(listener);
        }
    }
}
