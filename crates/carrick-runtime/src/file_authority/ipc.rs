use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixDatagram;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use parking_lot::Mutex;

use super::protocol::{
    MAX_FRAME_LEN, decode_request, decode_response, encode_request_with_fd_count,
    encode_response_with_fd_count,
};
use super::{
    AuthorityCall, AuthorityEpoch, AuthorityFatal, AuthorityReply, ClientId, ClientIdentity,
    FileAuthorityBinding, FileAuthorityCore, FileAuthorityTransport, ObjectGeneration, Outcome,
    Request, RequestId,
};
use carrick_kernel::domains::{HostPid, ProcessGeneration};

const TRANSPORT_TIMEOUT: Duration = Duration::from_secs(5);
const CONTROL_BYTES: usize = 256;

#[repr(C, align(8))]
struct AlignedControl([u8; CONTROL_BYTES]);

struct ReceivedFrame {
    bytes: Vec<u8>,
    descriptors: Vec<OwnedFd>,
}

/// Versioned datagram client for the per-run authority endpoint.
///
/// Requests are serialized deliberately: one client endpoint has one
/// outstanding request, which is the acknowledgement rule used by the core's
/// bounded terminal-response ledger.
#[derive(Clone)]
pub(crate) struct IpcFileAuthority {
    inner: Arc<IpcInner>,
}

struct IpcInner {
    socket: Mutex<UnixDatagram>,
    server: Mutex<Option<JoinHandle<()>>>,
}

impl std::fmt::Debug for IpcFileAuthority {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("IpcFileAuthority")
            .finish_non_exhaustive()
    }
}

impl IpcFileAuthority {
    /// Start a dedicated per-run authority helper before any guest host fork.
    ///
    /// The parent returns one CLOEXEC endpoint. The helper owns the only core
    /// and never returns; all later guest processes inherit or receive client
    /// endpoints, never mutable authority state.
    pub(crate) fn spawn_per_run(
        core: FileAuthorityCore,
        epoch: AuthorityEpoch,
    ) -> Result<(Self, FileAuthorityBinding), AuthorityFatal> {
        let (client, server) = cloexec_datagram_pair()?;
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            return Err(AuthorityFatal::TransportUnavailable);
        }
        if pid == 0 {
            drop(client);
            serve(server, core);
            unsafe { libc::_exit(0) };
        }
        drop(server);
        configure_client(&client)?;
        let transport = Self {
            inner: Arc::new(IpcInner {
                socket: Mutex::new(client),
                server: Mutex::new(None),
            }),
        };
        let client_identity = ClientIdentity::registered(
            ClientId::for_process_client(1).map_err(|_| AuthorityFatal::IdentityExhausted)?,
            HostPid::new(std::process::id()),
            ProcessGeneration::new(1),
        )
        .map_err(|_| AuthorityFatal::IdentityExhausted)?;
        let register = Request {
            epoch,
            client: client_identity,
            request_id: RequestId::from_client_sequence(1)
                .map_err(|_| AuthorityFatal::IdentityExhausted)?,
            expected_generation: ObjectGeneration::INITIAL,
            command: super::Command::RegisterClient,
        };
        let registered = transport.execute(register)?;
        if !matches!(registered.outcome, Outcome::ClientRegistered) {
            return Err(AuthorityFatal::InvariantViolation(
                "per-run authority rejected its root client",
            ));
        }
        let create = Request {
            epoch,
            client: client_identity,
            request_id: RequestId::from_client_sequence(2)
                .map_err(|_| AuthorityFatal::IdentityExhausted)?,
            expected_generation: ObjectGeneration::INITIAL,
            command: super::Command::CreateTable,
        };
        let table = match transport.execute(create)?.outcome {
            Outcome::TableCreated {
                table, generation, ..
            } => (table, generation),
            _ => {
                return Err(AuthorityFatal::InvariantViolation(
                    "per-run authority failed to create its root table",
                ));
            }
        };
        Ok((
            transport,
            FileAuthorityBinding {
                epoch,
                client: client_identity,
                table: table.0,
                generation: table.1,
            },
        ))
    }

    /// Run the exact datagram protocol against a dedicated server thread.
    /// Production helper startup replaces only this launcher; the socket,
    /// protocol, server loop, and core transaction boundary remain identical.
    #[cfg(test)]
    pub(super) fn for_model_tests(core: FileAuthorityCore) -> Result<Self, AuthorityFatal> {
        let (client, server) = cloexec_datagram_pair()?;
        configure_client(&client)?;
        let server_thread = std::thread::Builder::new()
            .name("carrick-file-authority-model".to_owned())
            .spawn(move || serve(server, core))
            .map_err(|_| AuthorityFatal::TransportUnavailable)?;
        Ok(Self {
            inner: Arc::new(IpcInner {
                socket: Mutex::new(client),
                server: Mutex::new(Some(server_thread)),
            }),
        })
    }

    #[cfg(test)]
    pub(super) fn terminate_model_server(&self) {
        {
            let socket = self.inner.socket.lock();
            let _ = socket.send(&[0]);
        }
        if let Some(server) = self.inner.server.lock().take() {
            server.join().expect("model authority server");
        }
    }
}

impl FileAuthorityTransport for IpcFileAuthority {
    fn transact(&self, call: AuthorityCall) -> Result<AuthorityReply, AuthorityFatal> {
        let frame = encode_request_with_fd_count(&call.request, call.capabilities.len())?;
        let socket = self.inner.socket.lock();
        send_frame(&socket, &frame, &call.capabilities)?;
        let received = recv_frame(&socket)?;
        let response = decode_response(&call.request, &received.bytes, received.descriptors.len())?;
        Ok(AuthorityReply {
            response,
            capabilities: received.descriptors,
        })
    }
}

impl Drop for IpcInner {
    fn drop(&mut self) {
        let socket = self.socket.get_mut();
        // A zero-length private datagram cannot decode as a protocol frame and
        // wakes the server from recvmsg so its loop terminates before join.
        let _ = socket.send(&[]);
        if let Some(server) = self.server.get_mut().take() {
            let _ = server.join();
        }
    }
}

fn serve(socket: UnixDatagram, mut core: FileAuthorityCore) {
    while let Ok(received) = recv_frame(&socket) {
        let request = match decode_request(&received.bytes, received.descriptors.len()) {
            Ok(request) => request,
            Err(_) => break,
        };
        let reply = match core.execute_call(AuthorityCall {
            request: request.clone(),
            capabilities: received.descriptors,
        }) {
            Ok(reply) => reply,
            Err(_) => break,
        };
        let response = match encode_response_with_fd_count(
            &request,
            &reply.response,
            reply.capabilities.len(),
        ) {
            Ok(response) => response,
            Err(_) => break,
        };
        if send_frame(&socket, &response, &reply.capabilities).is_err() {
            break;
        }
    }
}

fn configure_client(client: &UnixDatagram) -> Result<(), AuthorityFatal> {
    client
        .set_read_timeout(Some(TRANSPORT_TIMEOUT))
        .map_err(|_| AuthorityFatal::TransportUnavailable)?;
    client
        .set_write_timeout(Some(TRANSPORT_TIMEOUT))
        .map_err(|_| AuthorityFatal::TransportUnavailable)
}

fn cloexec_datagram_pair() -> Result<(UnixDatagram, UnixDatagram), AuthorityFatal> {
    let mut fds = [-1; 2];
    let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, fds.as_mut_ptr()) };
    if rc != 0 {
        return Err(AuthorityFatal::TransportUnavailable);
    }
    let first = unsafe { OwnedFd::from_raw_fd(fds[0]) };
    let second = unsafe { OwnedFd::from_raw_fd(fds[1]) };
    set_cloexec(first.as_raw_fd())?;
    set_cloexec(second.as_raw_fd())?;
    Ok((UnixDatagram::from(first), UnixDatagram::from(second)))
}

fn set_cloexec(fd: RawFd) -> Result<(), AuthorityFatal> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
        return Err(AuthorityFatal::TransportUnavailable);
    }
    Ok(())
}

fn send_frame(
    socket: &UnixDatagram,
    frame: &[u8],
    descriptors: &[OwnedFd],
) -> Result<(), AuthorityFatal> {
    if frame.len() > MAX_FRAME_LEN {
        return Err(AuthorityFatal::MalformedFrame(
            "outbound frame exceeds bound",
        ));
    }
    if descriptors.is_empty() {
        return match socket.send(frame) {
            Ok(written) if written == frame.len() => Ok(()),
            _ => Err(AuthorityFatal::TransportUnavailable),
        };
    }
    let descriptor_bytes = descriptors
        .len()
        .checked_mul(std::mem::size_of::<RawFd>())
        .ok_or(AuthorityFatal::CapabilityMismatch)?;
    let descriptor_bytes =
        libc::c_uint::try_from(descriptor_bytes).map_err(|_| AuthorityFatal::CapabilityMismatch)?;
    let control_len = unsafe { libc::CMSG_SPACE(descriptor_bytes) } as usize;
    if control_len > CONTROL_BYTES {
        return Err(AuthorityFatal::CapabilityMismatch);
    }
    let mut control = AlignedControl([0; CONTROL_BYTES]);
    let mut iov = libc::iovec {
        iov_base: frame.as_ptr().cast_mut().cast(),
        iov_len: frame.len(),
    };
    let mut message = unsafe { MaybeUninit::<libc::msghdr>::zeroed().assume_init() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    message.msg_control = control.0.as_mut_ptr().cast();
    message.msg_controllen = control_len
        .try_into()
        .map_err(|_| AuthorityFatal::CapabilityMismatch)?;
    let header = unsafe { libc::CMSG_FIRSTHDR(&message) };
    if header.is_null() {
        return Err(AuthorityFatal::CapabilityMismatch);
    }
    unsafe {
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN(descriptor_bytes) as _;
        let data = libc::CMSG_DATA(header).cast::<RawFd>();
        for (index, descriptor) in descriptors.iter().enumerate() {
            data.add(index).write_unaligned(descriptor.as_raw_fd());
        }
    }
    let written = unsafe { libc::sendmsg(socket.as_raw_fd(), &message, 0) };
    if written == frame.len() as isize {
        Ok(())
    } else {
        Err(AuthorityFatal::TransportUnavailable)
    }
}

fn recv_frame(socket: &UnixDatagram) -> Result<ReceivedFrame, AuthorityFatal> {
    let mut bytes = vec![0_u8; MAX_FRAME_LEN];
    let mut control = AlignedControl([0; CONTROL_BYTES]);
    let mut iov = libc::iovec {
        iov_base: bytes.as_mut_ptr().cast(),
        iov_len: bytes.len(),
    };
    let mut message = MaybeUninit::<libc::msghdr>::zeroed();
    let message = unsafe {
        let message = message.assume_init_mut();
        message.msg_iov = &mut iov;
        message.msg_iovlen = 1;
        message.msg_control = control.0.as_mut_ptr().cast();
        message.msg_controllen = control
            .0
            .len()
            .try_into()
            .map_err(|_| AuthorityFatal::CapabilityMismatch)?;
        message
    };
    let received = unsafe { libc::recvmsg(socket.as_raw_fd(), message, 0) };
    if received <= 0 {
        return Err(AuthorityFatal::TransportUnavailable);
    }
    if message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0 {
        close_received_rights(message);
        return Err(AuthorityFatal::MalformedFrame("truncated datagram"));
    }
    let mut descriptors = receive_rights(message)?;
    for descriptor in &descriptors {
        if set_cloexec(descriptor.as_raw_fd()).is_err() {
            descriptors.clear();
            return Err(AuthorityFatal::MalformedFrame(
                "received descriptor could not be made close-on-exec",
            ));
        }
    }
    bytes.truncate(usize::try_from(received).map_err(|_| AuthorityFatal::TransportUnavailable)?);
    Ok(ReceivedFrame { bytes, descriptors })
}

fn receive_rights(message: &libc::msghdr) -> Result<Vec<OwnedFd>, AuthorityFatal> {
    let mut raw_descriptors = Vec::new();
    let mut header = unsafe { libc::CMSG_FIRSTHDR(message) };
    while !header.is_null() {
        let current = unsafe { &*header };
        if current.cmsg_level != libc::SOL_SOCKET || current.cmsg_type != libc::SCM_RIGHTS {
            close_received_rights(message);
            return Err(AuthorityFatal::MalformedFrame(
                "unexpected ancillary record",
            ));
        }
        let header_bytes = unsafe { libc::CMSG_LEN(0) } as usize;
        let record_bytes = current.cmsg_len as usize;
        let Some(payload_bytes) = record_bytes.checked_sub(header_bytes) else {
            close_received_rights(message);
            return Err(AuthorityFatal::MalformedFrame("invalid ancillary length"));
        };
        if !payload_bytes.is_multiple_of(std::mem::size_of::<RawFd>()) {
            close_received_rights(message);
            return Err(AuthorityFatal::MalformedFrame(
                "unaligned descriptor record",
            ));
        }
        let count = payload_bytes / std::mem::size_of::<RawFd>();
        let data = unsafe { libc::CMSG_DATA(header).cast::<RawFd>() };
        for index in 0..count {
            let fd = unsafe { data.add(index).read_unaligned() };
            if fd < 0 {
                close_received_rights(message);
                return Err(AuthorityFatal::MalformedFrame(
                    "negative received descriptor",
                ));
            }
            raw_descriptors.push(fd);
        }
        header = unsafe { libc::CMSG_NXTHDR(message, header) };
    }
    Ok(raw_descriptors
        .into_iter()
        .map(|fd| unsafe { OwnedFd::from_raw_fd(fd) })
        .collect())
}

fn close_received_rights(message: &libc::msghdr) {
    let mut header = unsafe { libc::CMSG_FIRSTHDR(message) };
    while !header.is_null() {
        let current = unsafe { &*header };
        if current.cmsg_level == libc::SOL_SOCKET && current.cmsg_type == libc::SCM_RIGHTS {
            let header_bytes = unsafe { libc::CMSG_LEN(0) } as usize;
            let record_bytes = current.cmsg_len as usize;
            if let Some(payload_bytes) = record_bytes.checked_sub(header_bytes) {
                let count = payload_bytes / std::mem::size_of::<RawFd>();
                let data = unsafe { libc::CMSG_DATA(header).cast::<RawFd>() };
                for index in 0..count {
                    let fd = unsafe { data.add(index).read_unaligned() };
                    if fd >= 0 {
                        unsafe {
                            libc::close(fd);
                        }
                    }
                }
            }
        }
        header = unsafe { libc::CMSG_NXTHDR(message, header) };
    }
}
