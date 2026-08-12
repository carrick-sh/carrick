use std::num::{NonZeroI32, NonZeroU64};

use carrick_abi::LinuxEpollEvents;
use carrick_kernel::domains::{HostPid, ProcessGeneration};

use super::{
    AccessMode, AuthorityEpoch, AuthorityError, AuthorityFatal, ByteCount, CanonicalPath,
    CapabilityLeaseDisposition, CapabilityLeaseId, CapabilityLeasePurpose, ClientIdentity, Command,
    DescriptionBackingSnapshot, DescriptionSnapshot, DescriptorFlags, EpollEventLimit,
    EpollHostPlan, EpollHostPlanAction, EpollInterestKey, EpollReadyEvent, EpollRegistration,
    EpollUserData, FileDescriptionId, FileOffset, FileSlotNumber, FileTableId, HostErrno,
    InterestGeneration, MappingAttachmentId, MappingLeaseDisposition, MappingRange, MappingRelease,
    NofileAllocationCeiling, ObjectGeneration, Outcome, PipeCapacity, PipeEnd, PipeId, Request,
    RequestId, Response, Revision, SameSlotBehavior, SeekWhence, SlotPageLimit, SlotRangeAction,
    SlotSnapshot, StatusFlags, VfsObjectId,
};

const MAGIC: u32 = 0x4341_4641;
const VERSION: u16 = 1;
const REQUEST_KIND: u8 = 1;
const RESPONSE_KIND: u8 = 2;
const HEADER_LEN: usize = 56;
pub(super) const MAX_FRAME_LEN: usize = ByteCount::MAX_FRAME_BYTES as usize + 4096;

#[derive(Clone, Copy, Debug)]
struct Header {
    kind: u8,
    operation: u8,
    payload_len: u32,
    fd_count: u16,
    epoch: u64,
    client_id: u64,
    host_pid: u32,
    process_generation: u32,
    request_id: u64,
    expected_generation: u64,
}

pub(super) fn encode_request(request: &Request) -> Result<Vec<u8>, AuthorityFatal> {
    encode_request_with_fd_count(request, 0)
}

pub(super) fn encode_request_with_fd_count(
    request: &Request,
    fd_count: usize,
) -> Result<Vec<u8>, AuthorityFatal> {
    let operation = command_tag(&request.command);
    let mut payload = Writer::default();
    encode_command(&mut payload, &request.command)?;
    encode_frame(
        Header {
            kind: REQUEST_KIND,
            operation,
            payload_len: payload.len_u32()?,
            fd_count: u16::try_from(fd_count).map_err(|_| AuthorityFatal::CapabilityMismatch)?,
            epoch: request.epoch.raw(),
            client_id: request.client.id.raw(),
            host_pid: request.client.host_pid.raw(),
            process_generation: request.client.process_generation.raw(),
            request_id: request.request_id.raw(),
            expected_generation: request.expected_generation.raw(),
        },
        payload.finish(),
    )
}

pub(super) fn decode_request(
    frame: &[u8],
    received_fd_count: usize,
) -> Result<Request, AuthorityFatal> {
    let (header, payload) = decode_frame(frame, received_fd_count)?;
    if header.kind != REQUEST_KIND {
        return malformed("expected a request frame");
    }
    let client = ClientIdentity::registered(
        super::ClientId::for_process_client(header.client_id)
            .map_err(|_| AuthorityFatal::MalformedFrame("invalid client id"))?,
        HostPid::new(header.host_pid),
        ProcessGeneration::new(header.process_generation),
    )
    .map_err(|_| AuthorityFatal::MalformedFrame("invalid client identity"))?;
    let mut reader = Reader::new(payload);
    let command = decode_command(header.operation, &mut reader)?;
    reader.finish()?;
    Ok(Request {
        epoch: AuthorityEpoch::for_run(header.epoch)
            .map_err(|_| AuthorityFatal::MalformedFrame("invalid authority epoch"))?,
        client,
        request_id: RequestId::from_client_sequence(header.request_id)
            .map_err(|_| AuthorityFatal::MalformedFrame("invalid request id"))?,
        expected_generation: ObjectGeneration::from_snapshot(header.expected_generation)
            .map_err(|_| AuthorityFatal::MalformedFrame("invalid object generation"))?,
        command,
    })
}

pub(super) fn encode_response(
    request: &Request,
    response: &Response,
) -> Result<Vec<u8>, AuthorityFatal> {
    encode_response_with_fd_count(request, response, 0)
}

pub(super) fn encode_response_with_fd_count(
    request: &Request,
    response: &Response,
    fd_count: usize,
) -> Result<Vec<u8>, AuthorityFatal> {
    let mut payload = Writer::default();
    payload.u64(response.authority_revision.raw());
    encode_outcome(&mut payload, &response.outcome)?;
    encode_frame(
        Header {
            kind: RESPONSE_KIND,
            operation: command_tag(&request.command),
            payload_len: payload.len_u32()?,
            fd_count: u16::try_from(fd_count).map_err(|_| AuthorityFatal::CapabilityMismatch)?,
            epoch: request.epoch.raw(),
            client_id: request.client.id.raw(),
            host_pid: request.client.host_pid.raw(),
            process_generation: request.client.process_generation.raw(),
            request_id: response.request_id.raw(),
            expected_generation: request.expected_generation.raw(),
        },
        payload.finish(),
    )
}

pub(super) fn decode_response(
    request: &Request,
    frame: &[u8],
    received_fd_count: usize,
) -> Result<Response, AuthorityFatal> {
    let (header, payload) = decode_frame(frame, received_fd_count)?;
    if header.kind != RESPONSE_KIND
        || header.operation != command_tag(&request.command)
        || header.epoch != request.epoch.raw()
        || header.client_id != request.client.id.raw()
        || header.host_pid != request.client.host_pid.raw()
        || header.process_generation != request.client.process_generation.raw()
        || header.request_id != request.request_id.raw()
        || header.expected_generation != request.expected_generation.raw()
    {
        return Err(AuthorityFatal::ResponseMismatch);
    }
    let mut reader = Reader::new(payload);
    let authority_revision = Revision::from_wire(reader.u64()?);
    let outcome = decode_outcome(&mut reader)?;
    reader.finish()?;
    Ok(Response {
        request_id: request.request_id,
        authority_revision,
        outcome,
    })
}

fn encode_frame(header: Header, payload: Vec<u8>) -> Result<Vec<u8>, AuthorityFatal> {
    let frame_len = HEADER_LEN
        .checked_add(payload.len())
        .ok_or(AuthorityFatal::EncodingFailure("frame length overflow"))?;
    if payload.len() != header.payload_len as usize || frame_len > MAX_FRAME_LEN {
        return Err(AuthorityFatal::EncodingFailure("frame exceeds its bound"));
    }
    let mut writer = Writer::with_capacity(frame_len);
    writer.u32(MAGIC);
    writer.u16(VERSION);
    writer.u8(header.kind);
    writer.u8(header.operation);
    writer.u32(header.payload_len);
    writer.u16(header.fd_count);
    writer.u16(0);
    writer.u64(header.epoch);
    writer.u64(header.client_id);
    writer.u32(header.host_pid);
    writer.u32(header.process_generation);
    writer.u64(header.request_id);
    writer.u64(header.expected_generation);
    writer.bytes.extend_from_slice(&payload);
    Ok(writer.finish())
}

fn decode_frame(frame: &[u8], received_fd_count: usize) -> Result<(Header, &[u8]), AuthorityFatal> {
    if frame.len() < HEADER_LEN || frame.len() > MAX_FRAME_LEN {
        return malformed("invalid frame length");
    }
    let mut reader = Reader::new(frame);
    if reader.u32()? != MAGIC || reader.u16()? != VERSION {
        return malformed("unknown protocol magic or version");
    }
    let header = Header {
        kind: reader.u8()?,
        operation: reader.u8()?,
        payload_len: reader.u32()?,
        fd_count: reader.u16()?,
        epoch: {
            if reader.u16()? != 0 {
                return malformed("nonzero reserved header field");
            }
            reader.u64()?
        },
        client_id: reader.u64()?,
        host_pid: reader.u32()?,
        process_generation: reader.u32()?,
        request_id: reader.u64()?,
        expected_generation: reader.u64()?,
    };
    if usize::from(header.fd_count) != received_fd_count {
        return malformed("descriptor count mismatch");
    }
    if reader.remaining() != header.payload_len as usize {
        return malformed("payload length mismatch");
    }
    Ok((header, reader.rest()))
}

fn command_tag(command: &Command) -> u8 {
    match command {
        Command::RegisterClient => 1,
        Command::ExitClient => 2,
        Command::CreateTable => 3,
        Command::CreateVfsFile { .. } => 4,
        Command::ResolveVfs { .. } => 5,
        Command::LinkVfs { .. } => 6,
        Command::UnlinkVfs { .. } => 7,
        Command::RenameVfs { .. } => 8,
        Command::OpenVfsAndInstall { .. } => 9,
        Command::CreateSyntheticAndInstall { .. } => 10,
        Command::ResolveSlot { .. } => 11,
        Command::Read { .. } => 12,
        Command::Write { .. } => 13,
        Command::Seek { .. } => 14,
        Command::Close { .. } => 15,
        Command::Dup { .. } => 16,
        Command::ForkCopy { .. } => 17,
        Command::ShareTable { .. } => 18,
        Command::ExecSuccessor { .. } => 19,
        Command::InspectDescription { .. } => 20,
        Command::AdoptHostFileAndInstall { .. } => 21,
        Command::AcquireCapabilityLease { .. } => 22,
        Command::ReleaseCapabilityLease { .. } => 23,
        Command::ListSlots { .. } => 24,
        Command::SetDescriptorFlags { .. } => 25,
        Command::ReplaceSlot { .. } => 26,
        Command::MutateSlotRange { .. } => 27,
        Command::CreateEpollAndInstall { .. } => 28,
        Command::CreateEventCounterAndInstall { .. } => 29,
        Command::EpollCtlAdd { .. } => 30,
        Command::EpollCtlModify { .. } => 31,
        Command::EpollCtlDelete { .. } => 32,
        Command::ObserveReadiness { .. } => 33,
        Command::EpollCollect { .. } => 34,
        Command::EpollAcknowledgeIo { .. } => 35,
        Command::EventCounterRead { .. } => 36,
        Command::EventCounterWrite { .. } => 37,
        Command::CreatePipeAndInstall { .. } => 38,
        Command::SetPipeCapacity { .. } => 39,
        Command::EpollRevalidateHostPlan { .. } => 40,
        Command::FinalizeMappingLease { .. } => 41,
        Command::ReleaseMappingAttachment { .. } => 42,
        Command::ForkCopyMappings { .. } => 43,
    }
}

fn encode_command(writer: &mut Writer, command: &Command) -> Result<(), AuthorityFatal> {
    match command {
        Command::RegisterClient | Command::ExitClient | Command::CreateTable => {}
        Command::CreatePipeAndInstall {
            table,
            minimum,
            ceiling,
            descriptor_flags,
            status_flags,
            capacity,
        } => {
            writer.u64(table.raw());
            writer.i32(minimum.raw());
            writer.u32(ceiling.raw());
            writer.u32(descriptor_flags.raw());
            writer.u64(status_flags.raw());
            writer.u32(capacity.raw());
        }
        Command::SetPipeCapacity {
            table,
            fd,
            capacity,
        } => {
            writer.u64(table.raw());
            writer.i32(fd.raw());
            writer.u32(capacity.raw());
        }
        Command::CreateEpollAndInstall {
            table,
            minimum,
            ceiling,
            descriptor_flags,
        } => {
            writer.u64(table.raw());
            writer.i32(minimum.raw());
            writer.u32(ceiling.raw());
            writer.u32(descriptor_flags.raw());
        }
        Command::CreateEventCounterAndInstall {
            table,
            initial,
            semaphore,
            minimum,
            ceiling,
            descriptor_flags,
            status_flags,
        } => {
            writer.u64(table.raw());
            writer.u64(*initial);
            writer.bool(*semaphore);
            writer.i32(minimum.raw());
            writer.u32(ceiling.raw());
            writer.u32(descriptor_flags.raw());
            writer.u64(status_flags.raw());
        }
        Command::CreateVfsFile {
            path,
            mode,
            contents,
        } => {
            writer.path(path)?;
            writer.u32(*mode);
            writer.blob(contents)?;
        }
        Command::ResolveVfs { path } | Command::UnlinkVfs { path } => writer.path(path)?,
        Command::LinkVfs { object, path } => {
            writer.u64(object.raw());
            writer.path(path)?;
        }
        Command::RenameVfs { from, to } => {
            writer.path(from)?;
            writer.path(to)?;
        }
        Command::OpenVfsAndInstall {
            table,
            object,
            object_generation,
            minimum,
            ceiling,
            descriptor_flags,
            access_mode,
            status_flags,
            path,
        } => {
            writer.u64(table.raw());
            writer.u64(object.raw());
            writer.u64(object_generation.raw());
            writer.i32(minimum.raw());
            writer.u32(ceiling.raw());
            writer.u32(descriptor_flags.raw());
            writer.u8(access_mode_tag(*access_mode));
            writer.u64(status_flags.raw());
            writer.optional_path(path.as_ref())?;
        }
        Command::CreateSyntheticAndInstall {
            table,
            contents,
            minimum,
            ceiling,
            descriptor_flags,
            access_mode,
            status_flags,
            path,
        } => {
            writer.u64(table.raw());
            writer.blob(contents)?;
            writer.i32(minimum.raw());
            writer.u32(ceiling.raw());
            writer.u32(descriptor_flags.raw());
            writer.u8(access_mode_tag(*access_mode));
            writer.u64(status_flags.raw());
            writer.optional_path(path.as_ref())?;
        }
        Command::AdoptHostFileAndInstall {
            table,
            minimum,
            ceiling,
            descriptor_flags,
            access_mode,
            status_flags,
            writable,
            path,
        } => {
            writer.u64(table.raw());
            writer.i32(minimum.raw());
            writer.u32(ceiling.raw());
            writer.u32(descriptor_flags.raw());
            writer.u8(access_mode_tag(*access_mode));
            writer.u64(status_flags.raw());
            writer.bool(*writable);
            writer.optional_path(path.as_ref())?;
        }
        Command::AcquireCapabilityLease { table, fd, purpose } => {
            writer.u64(table.raw());
            writer.i32(fd.raw());
            writer.u8(capability_purpose_tag(*purpose));
        }
        Command::ReleaseCapabilityLease { lease, disposition } => {
            writer.u64(lease.raw());
            writer.u8(capability_disposition_tag(*disposition));
        }
        Command::FinalizeMappingLease { lease, disposition } => {
            writer.u64(lease.raw());
            writer.mapping_lease_disposition(*disposition);
        }
        Command::ReleaseMappingAttachment {
            attachment,
            release,
        } => {
            writer.u64(attachment.raw());
            writer.mapping_release(*release);
        }
        Command::ListSlots {
            table,
            after,
            maximum,
        } => {
            writer.u64(table.raw());
            writer.optional_slot(*after);
            writer.u16(maximum.raw());
        }
        Command::SetDescriptorFlags { table, fd, flags } => {
            writer.u64(table.raw());
            writer.i32(fd.raw());
            writer.u32(flags.raw());
        }
        Command::ReplaceSlot {
            table,
            source,
            target,
            ceiling,
            flags,
            same_slot,
        } => {
            writer.u64(table.raw());
            writer.i32(source.raw());
            writer.i32(target.raw());
            writer.u32(ceiling.raw());
            writer.u32(flags.raw());
            writer.u8(same_slot_tag(*same_slot));
        }
        Command::MutateSlotRange {
            table,
            first,
            last,
            action,
        } => {
            writer.u64(table.raw());
            writer.i32(first.raw());
            writer.i32(last.raw());
            writer.u8(slot_range_action_tag(*action));
        }
        Command::EpollCtlAdd {
            table,
            epoll_fd,
            target_fd,
            registration,
        }
        | Command::EpollCtlModify {
            table,
            epoll_fd,
            target_fd,
            registration,
        } => {
            writer.u64(table.raw());
            writer.i32(epoll_fd.raw());
            writer.i32(target_fd.raw());
            writer.epoll_registration(*registration);
        }
        Command::EpollCtlDelete {
            table,
            epoll_fd,
            target_fd,
        } => {
            writer.u64(table.raw());
            writer.i32(epoll_fd.raw());
            writer.i32(target_fd.raw());
        }
        Command::EpollRevalidateHostPlan { plan } => writer.epoll_host_plan(*plan),
        Command::ObserveReadiness {
            table,
            fd,
            ready,
            read_available,
        } => {
            writer.u64(table.raw());
            writer.i32(fd.raw());
            writer.u32(ready.bits());
            writer.u64(*read_available);
        }
        Command::EpollCollect {
            table,
            epoll_fd,
            maximum,
        } => {
            writer.u64(table.raw());
            writer.i32(epoll_fd.raw());
            writer.u16(maximum.raw());
        }
        Command::EpollAcknowledgeIo {
            table,
            fd,
            consumed,
            read_available,
            write_backpressured,
        } => {
            writer.u64(table.raw());
            writer.i32(fd.raw());
            writer.u32(consumed.bits());
            writer.u64(*read_available);
            writer.bool(*write_backpressured);
        }
        Command::EventCounterRead { table, fd } => {
            writer.u64(table.raw());
            writer.i32(fd.raw());
        }
        Command::EventCounterWrite { table, fd, value } => {
            writer.u64(table.raw());
            writer.i32(fd.raw());
            writer.u64(*value);
        }
        Command::ResolveSlot { table, fd } | Command::Close { table, fd } => {
            writer.u64(table.raw());
            writer.i32(fd.raw());
        }
        Command::Read { table, fd, maximum } => {
            writer.u64(table.raw());
            writer.i32(fd.raw());
            writer.u32(maximum.raw());
        }
        Command::Write { table, fd, bytes } => {
            writer.u64(table.raw());
            writer.i32(fd.raw());
            writer.blob(bytes)?;
        }
        Command::Seek {
            table,
            fd,
            offset,
            whence,
        } => {
            writer.u64(table.raw());
            writer.i32(fd.raw());
            writer.i64(*offset);
            writer.u8(match whence {
                SeekWhence::Start => 0,
                SeekWhence::Current => 1,
                SeekWhence::End => 2,
            });
        }
        Command::Dup {
            table,
            source,
            minimum,
            ceiling,
            flags,
        } => {
            writer.u64(table.raw());
            writer.i32(source.raw());
            writer.i32(minimum.raw());
            writer.u32(ceiling.raw());
            writer.u32(flags.raw());
        }
        Command::ForkCopy { source, owner } => {
            writer.u64(source.raw());
            writer.client(*owner);
        }
        Command::ForkCopyMappings {
            source_owner,
            owner,
        } => {
            writer.client(*source_owner);
            writer.client(*owner);
        }
        Command::ShareTable { table, owner } => {
            writer.u64(table.raw());
            writer.client(*owner);
        }
        Command::ExecSuccessor { source } => writer.u64(source.raw()),
        Command::InspectDescription { description } => writer.u64(description.raw()),
    }
    Ok(())
}

fn decode_command(tag: u8, reader: &mut Reader<'_>) -> Result<Command, AuthorityFatal> {
    Ok(match tag {
        1 => Command::RegisterClient,
        2 => Command::ExitClient,
        3 => Command::CreateTable,
        4 => Command::CreateVfsFile {
            path: reader.path()?,
            mode: reader.u32()?,
            contents: reader.blob()?,
        },
        5 => Command::ResolveVfs {
            path: reader.path()?,
        },
        6 => Command::LinkVfs {
            object: reader.vfs_object()?,
            path: reader.path()?,
        },
        7 => Command::UnlinkVfs {
            path: reader.path()?,
        },
        8 => Command::RenameVfs {
            from: reader.path()?,
            to: reader.path()?,
        },
        9 => Command::OpenVfsAndInstall {
            table: reader.table_id()?,
            object: reader.vfs_object()?,
            object_generation: reader.generation()?,
            minimum: reader.slot()?,
            ceiling: NofileAllocationCeiling::from_captured_soft_limit(reader.u32()?),
            descriptor_flags: DescriptorFlags::from_linux_bits(reader.u32()?)
                .map_err(|_| AuthorityFatal::MalformedFrame("invalid descriptor flags"))?,
            access_mode: reader.access_mode()?,
            status_flags: StatusFlags::from_linux_bits(reader.u64()?),
            path: reader.optional_path()?,
        },
        10 => Command::CreateSyntheticAndInstall {
            table: reader.table_id()?,
            contents: reader.blob()?,
            minimum: reader.slot()?,
            ceiling: NofileAllocationCeiling::from_captured_soft_limit(reader.u32()?),
            descriptor_flags: DescriptorFlags::from_linux_bits(reader.u32()?)
                .map_err(|_| AuthorityFatal::MalformedFrame("invalid descriptor flags"))?,
            access_mode: reader.access_mode()?,
            status_flags: StatusFlags::from_linux_bits(reader.u64()?),
            path: reader.optional_path()?,
        },
        11 => Command::ResolveSlot {
            table: reader.table_id()?,
            fd: reader.slot()?,
        },
        12 => Command::Read {
            table: reader.table_id()?,
            fd: reader.slot()?,
            maximum: ByteCount::bounded(reader.u32()?)
                .map_err(|_| AuthorityFatal::MalformedFrame("unbounded read length"))?,
        },
        13 => Command::Write {
            table: reader.table_id()?,
            fd: reader.slot()?,
            bytes: reader.blob()?,
        },
        14 => Command::Seek {
            table: reader.table_id()?,
            fd: reader.slot()?,
            offset: reader.i64()?,
            whence: match reader.u8()? {
                0 => SeekWhence::Start,
                1 => SeekWhence::Current,
                2 => SeekWhence::End,
                _ => return malformed("invalid seek origin"),
            },
        },
        15 => Command::Close {
            table: reader.table_id()?,
            fd: reader.slot()?,
        },
        16 => Command::Dup {
            table: reader.table_id()?,
            source: reader.slot()?,
            minimum: reader.slot()?,
            ceiling: NofileAllocationCeiling::from_captured_soft_limit(reader.u32()?),
            flags: DescriptorFlags::from_linux_bits(reader.u32()?)
                .map_err(|_| AuthorityFatal::MalformedFrame("invalid descriptor flags"))?,
        },
        17 => Command::ForkCopy {
            source: reader.table_id()?,
            owner: reader.client()?,
        },
        18 => Command::ShareTable {
            table: reader.table_id()?,
            owner: reader.client()?,
        },
        19 => Command::ExecSuccessor {
            source: reader.table_id()?,
        },
        20 => Command::InspectDescription {
            description: reader.description_id()?,
        },
        21 => Command::AdoptHostFileAndInstall {
            table: reader.table_id()?,
            minimum: reader.slot()?,
            ceiling: NofileAllocationCeiling::from_captured_soft_limit(reader.u32()?),
            descriptor_flags: DescriptorFlags::from_linux_bits(reader.u32()?)
                .map_err(|_| AuthorityFatal::MalformedFrame("invalid descriptor flags"))?,
            access_mode: reader.access_mode()?,
            status_flags: StatusFlags::from_linux_bits(reader.u64()?),
            writable: reader.bool()?,
            path: reader.optional_path()?,
        },
        22 => Command::AcquireCapabilityLease {
            table: reader.table_id()?,
            fd: reader.slot()?,
            purpose: reader.capability_purpose()?,
        },
        23 => Command::ReleaseCapabilityLease {
            lease: reader.capability_lease_id()?,
            disposition: reader.capability_disposition()?,
        },
        24 => Command::ListSlots {
            table: reader.table_id()?,
            after: reader.optional_slot()?,
            maximum: SlotPageLimit::bounded(reader.u16()?)
                .map_err(|_| AuthorityFatal::MalformedFrame("invalid slot page limit"))?,
        },
        25 => Command::SetDescriptorFlags {
            table: reader.table_id()?,
            fd: reader.slot()?,
            flags: DescriptorFlags::from_linux_bits(reader.u32()?)
                .map_err(|_| AuthorityFatal::MalformedFrame("invalid descriptor flags"))?,
        },
        26 => Command::ReplaceSlot {
            table: reader.table_id()?,
            source: reader.slot()?,
            target: reader.slot()?,
            ceiling: NofileAllocationCeiling::from_captured_soft_limit(reader.u32()?),
            flags: DescriptorFlags::from_linux_bits(reader.u32()?)
                .map_err(|_| AuthorityFatal::MalformedFrame("invalid descriptor flags"))?,
            same_slot: reader.same_slot_behavior()?,
        },
        27 => Command::MutateSlotRange {
            table: reader.table_id()?,
            first: reader.slot()?,
            last: reader.slot()?,
            action: reader.slot_range_action()?,
        },
        28 => Command::CreateEpollAndInstall {
            table: reader.table_id()?,
            minimum: reader.slot()?,
            ceiling: NofileAllocationCeiling::from_captured_soft_limit(reader.u32()?),
            descriptor_flags: DescriptorFlags::from_linux_bits(reader.u32()?)
                .map_err(|_| AuthorityFatal::MalformedFrame("invalid descriptor flags"))?,
        },
        29 => Command::CreateEventCounterAndInstall {
            table: reader.table_id()?,
            initial: reader.u64()?,
            semaphore: reader.bool()?,
            minimum: reader.slot()?,
            ceiling: NofileAllocationCeiling::from_captured_soft_limit(reader.u32()?),
            descriptor_flags: DescriptorFlags::from_linux_bits(reader.u32()?)
                .map_err(|_| AuthorityFatal::MalformedFrame("invalid descriptor flags"))?,
            status_flags: StatusFlags::from_linux_bits(reader.u64()?),
        },
        30 => Command::EpollCtlAdd {
            table: reader.table_id()?,
            epoll_fd: reader.slot()?,
            target_fd: reader.slot()?,
            registration: reader.epoll_registration()?,
        },
        31 => Command::EpollCtlModify {
            table: reader.table_id()?,
            epoll_fd: reader.slot()?,
            target_fd: reader.slot()?,
            registration: reader.epoll_registration()?,
        },
        32 => Command::EpollCtlDelete {
            table: reader.table_id()?,
            epoll_fd: reader.slot()?,
            target_fd: reader.slot()?,
        },
        33 => Command::ObserveReadiness {
            table: reader.table_id()?,
            fd: reader.slot()?,
            ready: LinuxEpollEvents::from_bits_retain(reader.u32()?),
            read_available: reader.u64()?,
        },
        34 => Command::EpollCollect {
            table: reader.table_id()?,
            epoll_fd: reader.slot()?,
            maximum: EpollEventLimit::bounded(reader.u16()?)
                .map_err(|_| AuthorityFatal::MalformedFrame("invalid epoll event limit"))?,
        },
        35 => Command::EpollAcknowledgeIo {
            table: reader.table_id()?,
            fd: reader.slot()?,
            consumed: LinuxEpollEvents::from_bits_retain(reader.u32()?),
            read_available: reader.u64()?,
            write_backpressured: reader.bool()?,
        },
        36 => Command::EventCounterRead {
            table: reader.table_id()?,
            fd: reader.slot()?,
        },
        37 => Command::EventCounterWrite {
            table: reader.table_id()?,
            fd: reader.slot()?,
            value: reader.u64()?,
        },
        38 => Command::CreatePipeAndInstall {
            table: reader.table_id()?,
            minimum: reader.slot()?,
            ceiling: NofileAllocationCeiling::from_captured_soft_limit(reader.u32()?),
            descriptor_flags: DescriptorFlags::from_linux_bits(reader.u32()?)
                .map_err(|_| AuthorityFatal::MalformedFrame("invalid descriptor flags"))?,
            status_flags: StatusFlags::from_linux_bits(reader.u64()?),
            capacity: PipeCapacity::bounded(reader.u32()?)
                .map_err(|_| AuthorityFatal::MalformedFrame("invalid pipe capacity"))?,
        },
        39 => Command::SetPipeCapacity {
            table: reader.table_id()?,
            fd: reader.slot()?,
            capacity: PipeCapacity::bounded(reader.u32()?)
                .map_err(|_| AuthorityFatal::MalformedFrame("invalid pipe capacity"))?,
        },
        40 => Command::EpollRevalidateHostPlan {
            plan: reader.epoll_host_plan()?,
        },
        41 => Command::FinalizeMappingLease {
            lease: reader.capability_lease_id()?,
            disposition: reader.mapping_lease_disposition()?,
        },
        42 => Command::ReleaseMappingAttachment {
            attachment: reader.mapping_attachment_id()?,
            release: reader.mapping_release()?,
        },
        43 => Command::ForkCopyMappings {
            source_owner: reader.client()?,
            owner: reader.client()?,
        },
        _ => return malformed("unknown operation"),
    })
}

fn encode_outcome(writer: &mut Writer, outcome: &Outcome) -> Result<(), AuthorityFatal> {
    match outcome {
        Outcome::ClientRegistered => writer.u8(1),
        Outcome::ClientExited => writer.u8(2),
        Outcome::TableCreated {
            table,
            generation,
            revision,
        } => {
            writer.u8(3);
            writer.u64(table.raw());
            writer.u64(generation.raw());
            writer.u64(revision.raw());
        }
        Outcome::PipeCreated {
            table,
            pipe,
            read_fd,
            write_fd,
            read_description,
            write_description,
            generation,
            table_revision,
            stream_revision,
        } => {
            writer.u8(35);
            writer.u64(table.raw());
            writer.u64(pipe.raw());
            writer.i32(read_fd.raw());
            writer.i32(write_fd.raw());
            writer.u64(read_description.raw());
            writer.u64(write_description.raw());
            writer.u64(generation.raw());
            writer.u64(table_revision.raw());
            writer.u64(stream_revision.raw());
        }
        Outcome::PipeCapacitySet {
            pipe,
            capacity,
            stream_revision,
        } => {
            writer.u8(36);
            writer.u64(pipe.raw());
            writer.u32(capacity.raw());
            writer.u64(stream_revision.raw());
        }
        Outcome::EpollCreated {
            table,
            fd,
            description,
            generation,
            table_revision,
            description_revision,
        } => {
            writer.u8(25);
            writer.u64(table.raw());
            writer.i32(fd.raw());
            writer.u64(description.raw());
            writer.u64(generation.raw());
            writer.u64(table_revision.raw());
            writer.u64(description_revision.raw());
        }
        Outcome::EventCounterCreated {
            table,
            fd,
            description,
            generation,
            table_revision,
            description_revision,
        } => {
            writer.u8(26);
            writer.u64(table.raw());
            writer.i32(fd.raw());
            writer.u64(description.raw());
            writer.u64(generation.raw());
            writer.u64(table_revision.raw());
            writer.u64(description_revision.raw());
        }
        Outcome::VfsObjectCreated {
            object,
            namespace_revision,
        } => {
            writer.u8(4);
            writer.u64(object.raw());
            writer.u64(namespace_revision.raw());
        }
        Outcome::VfsObjectResolved {
            object,
            mode,
            object_revision,
            namespace_revision,
        } => {
            writer.u8(5);
            writer.u64(object.raw());
            writer.u32(*mode);
            writer.u64(object_revision.raw());
            writer.u64(namespace_revision.raw());
        }
        Outcome::VfsNamespaceChanged {
            object,
            namespace_revision,
            object_reclaimed,
        } => {
            writer.u8(6);
            writer.u64(object.raw());
            writer.u64(namespace_revision.raw());
            writer.bool(*object_reclaimed);
        }
        Outcome::Installed {
            table,
            fd,
            description,
            description_generation,
            table_revision,
            description_revision,
        } => {
            writer.u8(7);
            writer.u64(table.raw());
            writer.i32(fd.raw());
            writer.u64(description.raw());
            writer.u64(description_generation.raw());
            writer.u64(table_revision.raw());
            writer.u64(description_revision.raw());
        }
        Outcome::Slot(slot) => {
            writer.u8(8);
            writer.slot_snapshot(slot)?;
        }
        Outcome::SlotPage {
            table,
            slots,
            next_after,
            table_revision,
        } => {
            writer.u8(21);
            writer.u64(table.raw());
            writer.slot_snapshots(slots)?;
            writer.optional_slot(*next_after);
            writer.u64(table_revision.raw());
        }
        Outcome::DescriptorFlagsSet {
            table,
            fd,
            flags,
            table_revision,
        } => {
            writer.u8(22);
            writer.u64(table.raw());
            writer.i32(fd.raw());
            writer.u32(flags.raw());
            writer.u64(table_revision.raw());
        }
        Outcome::SlotReplaced {
            table,
            source,
            target,
            replaced_description,
            description_reclaimed,
            object_reclaimed,
            table_revision,
        } => {
            writer.u8(23);
            writer.u64(table.raw());
            writer.i32(source.raw());
            writer.i32(target.raw());
            writer.optional_description(*replaced_description);
            writer.bool(*description_reclaimed);
            writer.bool(*object_reclaimed);
            writer.u64(table_revision.raw());
        }
        Outcome::SlotRangeMutated {
            table,
            action,
            affected,
            table_revision,
        } => {
            writer.u8(24);
            writer.u64(table.raw());
            writer.u8(slot_range_action_tag(*action));
            writer.u32(*affected);
            writer.u64(table_revision.raw());
        }
        Outcome::EpollInterestAdded {
            key,
            generation,
            description_revision,
            host_plan,
        } => {
            writer.u8(27);
            writer.epoll_key(*key);
            writer.u32(generation.raw());
            writer.u64(description_revision.raw());
            writer.epoll_host_plan(*host_plan);
        }
        Outcome::EpollInterestModified {
            key,
            generation,
            description_revision,
            host_plan,
        } => {
            writer.u8(28);
            writer.epoll_key(*key);
            writer.u32(generation.raw());
            writer.u64(description_revision.raw());
            writer.epoll_host_plan(*host_plan);
        }
        Outcome::EpollInterestDeleted {
            key,
            description_revision,
            host_plan,
        } => {
            writer.u8(29);
            writer.epoll_key(*key);
            writer.u64(description_revision.raw());
            writer.epoll_host_plan(*host_plan);
        }
        Outcome::EpollHostPlanValidated {
            valid,
            current_revision,
        } => {
            writer.u8(39);
            writer.bool(*valid);
            writer.u64(current_revision.raw());
        }
        Outcome::ReadinessObserved {
            description,
            description_revision,
        } => {
            writer.u8(30);
            writer.u64(description.raw());
            writer.u64(description_revision.raw());
        }
        Outcome::EpollEvents {
            events,
            description_revision,
        } => {
            writer.u8(31);
            writer.epoll_events(events)?;
            writer.u64(description_revision.raw());
        }
        Outcome::EpollIoAcknowledged {
            description,
            description_revision,
        } => {
            writer.u8(32);
            writer.u64(description.raw());
            writer.u64(description_revision.raw());
        }
        Outcome::EventCounterRead {
            value,
            description_revision,
        } => {
            writer.u8(33);
            writer.u64(*value);
            writer.u64(description_revision.raw());
        }
        Outcome::EventCounterWritten {
            value,
            counter,
            description_revision,
        } => {
            writer.u8(34);
            writer.u64(*value);
            writer.u64(*counter);
            writer.u64(description_revision.raw());
        }
        Outcome::StreamBytes {
            pipe,
            bytes,
            description_revision,
            stream_revision,
        } => {
            writer.u8(37);
            writer.u64(pipe.raw());
            writer.blob(bytes)?;
            writer.u64(description_revision.raw());
            writer.u64(stream_revision.raw());
        }
        Outcome::StreamWritten {
            pipe,
            count,
            description_revision,
            stream_revision,
        } => {
            writer.u8(38);
            writer.u64(pipe.raw());
            writer.u32(count.raw());
            writer.u64(description_revision.raw());
            writer.u64(stream_revision.raw());
        }
        Outcome::Bytes {
            bytes,
            offset,
            description_revision,
        } => {
            writer.u8(9);
            writer.blob(bytes)?;
            writer.u64(offset.raw());
            writer.u64(description_revision.raw());
        }
        Outcome::Written {
            count,
            offset,
            description_revision,
            object_revision,
        } => {
            writer.u8(10);
            writer.u32(count.raw());
            writer.u64(offset.raw());
            writer.u64(description_revision.raw());
            writer.optional_revision(*object_revision);
        }
        Outcome::Seeked {
            offset,
            description_revision,
        } => {
            writer.u8(11);
            writer.u64(offset.raw());
            writer.u64(description_revision.raw());
        }
        Outcome::Closed {
            description,
            description_reclaimed,
            object_reclaimed,
            table_revision,
        } => {
            writer.u8(12);
            writer.u64(description.raw());
            writer.bool(*description_reclaimed);
            writer.bool(*object_reclaimed);
            writer.u64(table_revision.raw());
        }
        Outcome::Duplicated {
            source,
            fd,
            table_revision,
        } => {
            writer.u8(13);
            writer.i32(source.raw());
            writer.i32(fd.raw());
            writer.u64(table_revision.raw());
        }
        Outcome::ForkCopied {
            source,
            table,
            generation,
            revision,
        } => {
            writer.u8(14);
            writer.u64(source.raw());
            writer.u64(table.raw());
            writer.u64(generation.raw());
            writer.u64(revision.raw());
        }
        Outcome::MappingAttachmentsCopied {
            source_owner,
            owner,
            attachments,
            revision,
        } => {
            writer.u8(42);
            writer.client(*source_owner);
            writer.client(*owner);
            writer.mapping_attachments(attachments)?;
            writer.u64(revision.raw());
        }
        Outcome::TableShared { table, revision } => {
            writer.u8(15);
            writer.u64(table.raw());
            writer.u64(revision.raw());
        }
        Outcome::ExecSucceeded {
            source,
            table,
            generation,
            closed_on_exec,
            revision,
        } => {
            writer.u8(16);
            writer.u64(source.raw());
            writer.u64(table.raw());
            writer.u64(generation.raw());
            writer.slots(closed_on_exec)?;
            writer.u64(revision.raw());
        }
        Outcome::Description(description) => {
            writer.u8(17);
            writer.description_snapshot(description)?;
        }
        Outcome::CapabilityLeaseGranted {
            lease,
            description,
            description_generation,
            purpose,
            revision,
        } => {
            writer.u8(19);
            writer.u64(lease.raw());
            writer.u64(description.raw());
            writer.u64(description_generation.raw());
            writer.u8(capability_purpose_tag(*purpose));
            writer.u64(revision.raw());
        }
        Outcome::CapabilityLeaseReleased {
            lease,
            disposition,
            description_reclaimed,
            object_reclaimed,
            revision,
        } => {
            writer.u8(20);
            writer.u64(lease.raw());
            writer.u8(capability_disposition_tag(*disposition));
            writer.bool(*description_reclaimed);
            writer.bool(*object_reclaimed);
            writer.u64(revision.raw());
        }
        Outcome::MappingLeaseFinalized {
            lease,
            attachment,
            description,
            disposition,
            description_reclaimed,
            object_reclaimed,
            revision,
        } => {
            writer.u8(40);
            writer.u64(lease.raw());
            writer.optional_mapping_attachment(*attachment);
            writer.u64(description.raw());
            writer.mapping_lease_disposition(*disposition);
            writer.bool(*description_reclaimed);
            writer.bool(*object_reclaimed);
            writer.u64(revision.raw());
        }
        Outcome::MappingAttachmentReleased {
            attachment,
            remaining,
            description_reclaimed,
            object_reclaimed,
            revision,
        } => {
            writer.u8(41);
            writer.u64(attachment.raw());
            writer.mapping_ranges(remaining)?;
            writer.bool(*description_reclaimed);
            writer.bool(*object_reclaimed);
            writer.u64(revision.raw());
        }
        Outcome::Rejected(error) => {
            writer.u8(18);
            encode_error(writer, error);
        }
    }
    Ok(())
}

fn decode_outcome(reader: &mut Reader<'_>) -> Result<Outcome, AuthorityFatal> {
    Ok(match reader.u8()? {
        1 => Outcome::ClientRegistered,
        2 => Outcome::ClientExited,
        3 => Outcome::TableCreated {
            table: reader.table_id()?,
            generation: reader.generation()?,
            revision: reader.revision()?,
        },
        4 => Outcome::VfsObjectCreated {
            object: reader.vfs_object()?,
            namespace_revision: reader.revision()?,
        },
        5 => Outcome::VfsObjectResolved {
            object: reader.vfs_object()?,
            mode: reader.u32()?,
            object_revision: reader.revision()?,
            namespace_revision: reader.revision()?,
        },
        6 => Outcome::VfsNamespaceChanged {
            object: reader.vfs_object()?,
            namespace_revision: reader.revision()?,
            object_reclaimed: reader.bool()?,
        },
        7 => Outcome::Installed {
            table: reader.table_id()?,
            fd: reader.slot()?,
            description: reader.description_id()?,
            description_generation: reader.generation()?,
            table_revision: reader.revision()?,
            description_revision: reader.revision()?,
        },
        8 => Outcome::Slot(reader.slot_snapshot()?),
        9 => Outcome::Bytes {
            bytes: reader.blob()?,
            offset: FileOffset::from_start(reader.u64()?),
            description_revision: reader.revision()?,
        },
        10 => Outcome::Written {
            count: ByteCount::bounded(reader.u32()?)
                .map_err(|_| AuthorityFatal::MalformedFrame("invalid byte count"))?,
            offset: FileOffset::from_start(reader.u64()?),
            description_revision: reader.revision()?,
            object_revision: reader.optional_revision()?,
        },
        11 => Outcome::Seeked {
            offset: FileOffset::from_start(reader.u64()?),
            description_revision: reader.revision()?,
        },
        12 => Outcome::Closed {
            description: reader.description_id()?,
            description_reclaimed: reader.bool()?,
            object_reclaimed: reader.bool()?,
            table_revision: reader.revision()?,
        },
        13 => Outcome::Duplicated {
            source: reader.slot()?,
            fd: reader.slot()?,
            table_revision: reader.revision()?,
        },
        14 => Outcome::ForkCopied {
            source: reader.table_id()?,
            table: reader.table_id()?,
            generation: reader.generation()?,
            revision: reader.revision()?,
        },
        15 => Outcome::TableShared {
            table: reader.table_id()?,
            revision: reader.revision()?,
        },
        16 => Outcome::ExecSucceeded {
            source: reader.table_id()?,
            table: reader.table_id()?,
            generation: reader.generation()?,
            closed_on_exec: reader.slots()?,
            revision: reader.revision()?,
        },
        17 => Outcome::Description(reader.description_snapshot()?),
        18 => Outcome::Rejected(decode_error(reader)?),
        19 => Outcome::CapabilityLeaseGranted {
            lease: reader.capability_lease_id()?,
            description: reader.description_id()?,
            description_generation: reader.generation()?,
            purpose: reader.capability_purpose()?,
            revision: reader.revision()?,
        },
        20 => Outcome::CapabilityLeaseReleased {
            lease: reader.capability_lease_id()?,
            disposition: reader.capability_disposition()?,
            description_reclaimed: reader.bool()?,
            object_reclaimed: reader.bool()?,
            revision: reader.revision()?,
        },
        21 => Outcome::SlotPage {
            table: reader.table_id()?,
            slots: reader.slot_snapshots()?,
            next_after: reader.optional_slot()?,
            table_revision: reader.revision()?,
        },
        22 => Outcome::DescriptorFlagsSet {
            table: reader.table_id()?,
            fd: reader.slot()?,
            flags: DescriptorFlags::from_linux_bits(reader.u32()?)
                .map_err(|_| AuthorityFatal::MalformedFrame("invalid descriptor flags"))?,
            table_revision: reader.revision()?,
        },
        23 => Outcome::SlotReplaced {
            table: reader.table_id()?,
            source: reader.slot()?,
            target: reader.slot()?,
            replaced_description: reader.optional_description()?,
            description_reclaimed: reader.bool()?,
            object_reclaimed: reader.bool()?,
            table_revision: reader.revision()?,
        },
        24 => Outcome::SlotRangeMutated {
            table: reader.table_id()?,
            action: reader.slot_range_action()?,
            affected: reader.u32()?,
            table_revision: reader.revision()?,
        },
        25 => Outcome::EpollCreated {
            table: reader.table_id()?,
            fd: reader.slot()?,
            description: reader.description_id()?,
            generation: reader.generation()?,
            table_revision: reader.revision()?,
            description_revision: reader.revision()?,
        },
        26 => Outcome::EventCounterCreated {
            table: reader.table_id()?,
            fd: reader.slot()?,
            description: reader.description_id()?,
            generation: reader.generation()?,
            table_revision: reader.revision()?,
            description_revision: reader.revision()?,
        },
        27 => Outcome::EpollInterestAdded {
            key: reader.epoll_key()?,
            generation: reader.interest_generation()?,
            description_revision: reader.revision()?,
            host_plan: reader.epoll_host_plan()?,
        },
        28 => Outcome::EpollInterestModified {
            key: reader.epoll_key()?,
            generation: reader.interest_generation()?,
            description_revision: reader.revision()?,
            host_plan: reader.epoll_host_plan()?,
        },
        29 => Outcome::EpollInterestDeleted {
            key: reader.epoll_key()?,
            description_revision: reader.revision()?,
            host_plan: reader.epoll_host_plan()?,
        },
        30 => Outcome::ReadinessObserved {
            description: reader.description_id()?,
            description_revision: reader.revision()?,
        },
        31 => Outcome::EpollEvents {
            events: reader.epoll_events()?,
            description_revision: reader.revision()?,
        },
        32 => Outcome::EpollIoAcknowledged {
            description: reader.description_id()?,
            description_revision: reader.revision()?,
        },
        33 => Outcome::EventCounterRead {
            value: reader.u64()?,
            description_revision: reader.revision()?,
        },
        34 => Outcome::EventCounterWritten {
            value: reader.u64()?,
            counter: reader.u64()?,
            description_revision: reader.revision()?,
        },
        35 => Outcome::PipeCreated {
            table: reader.table_id()?,
            pipe: reader.pipe_id()?,
            read_fd: reader.slot()?,
            write_fd: reader.slot()?,
            read_description: reader.description_id()?,
            write_description: reader.description_id()?,
            generation: reader.generation()?,
            table_revision: reader.revision()?,
            stream_revision: reader.revision()?,
        },
        36 => Outcome::PipeCapacitySet {
            pipe: reader.pipe_id()?,
            capacity: PipeCapacity::bounded(reader.u32()?)
                .map_err(|_| AuthorityFatal::MalformedFrame("invalid pipe capacity"))?,
            stream_revision: reader.revision()?,
        },
        37 => Outcome::StreamBytes {
            pipe: reader.pipe_id()?,
            bytes: reader.blob()?,
            description_revision: reader.revision()?,
            stream_revision: reader.revision()?,
        },
        38 => Outcome::StreamWritten {
            pipe: reader.pipe_id()?,
            count: ByteCount::bounded(reader.u32()?)
                .map_err(|_| AuthorityFatal::MalformedFrame("invalid byte count"))?,
            description_revision: reader.revision()?,
            stream_revision: reader.revision()?,
        },
        39 => Outcome::EpollHostPlanValidated {
            valid: reader.bool()?,
            current_revision: reader.revision()?,
        },
        40 => Outcome::MappingLeaseFinalized {
            lease: reader.capability_lease_id()?,
            attachment: reader.optional_mapping_attachment()?,
            description: reader.description_id()?,
            disposition: reader.mapping_lease_disposition()?,
            description_reclaimed: reader.bool()?,
            object_reclaimed: reader.bool()?,
            revision: reader.revision()?,
        },
        41 => Outcome::MappingAttachmentReleased {
            attachment: reader.mapping_attachment_id()?,
            remaining: reader.mapping_ranges()?,
            description_reclaimed: reader.bool()?,
            object_reclaimed: reader.bool()?,
            revision: reader.revision()?,
        },
        42 => Outcome::MappingAttachmentsCopied {
            source_owner: reader.client()?,
            owner: reader.client()?,
            attachments: reader.mapping_attachments()?,
            revision: reader.revision()?,
        },
        _ => return malformed("unknown response outcome"),
    })
}

fn encode_error(writer: &mut Writer, error: &AuthorityError) {
    match error {
        AuthorityError::StaleEpoch { expected, actual } => {
            writer.u8(1);
            writer.u64(expected.raw());
            writer.u64(actual.raw());
        }
        AuthorityError::ClientNotRegistered => writer.u8(2),
        AuthorityError::ClientAlreadyRegistered => writer.u8(3),
        AuthorityError::StaleClientGeneration => writer.u8(4),
        AuthorityError::StaleObjectGeneration => writer.u8(5),
        AuthorityError::TableNotFound => writer.u8(6),
        AuthorityError::DescriptionNotFound => writer.u8(7),
        AuthorityError::SlotNotFound => writer.u8(8),
        AuthorityError::TableNotBound => writer.u8(9),
        AuthorityError::NofileExceeded => writer.u8(10),
        AuthorityError::InvalidDescriptorFlags => writer.u8(11),
        AuthorityError::InvalidCanonicalPath => writer.u8(12),
        AuthorityError::VfsPathExists => writer.u8(13),
        AuthorityError::VfsNotFound => writer.u8(14),
        AuthorityError::VfsRootMutation => writer.u8(15),
        AuthorityError::PayloadTooLarge => writer.u8(16),
        AuthorityError::InvalidOffset => writer.u8(17),
        AuthorityError::NotReadable => writer.u8(18),
        AuthorityError::NotWritable => writer.u8(19),
        AuthorityError::NotSeekable => writer.u8(20),
        AuthorityError::NotHostBacked => writer.u8(21),
        AuthorityError::CapabilityLeaseNotFound => writer.u8(22),
        AuthorityError::HostIo(errno) => {
            writer.u8(23);
            writer.i32(errno.raw());
        }
        AuthorityError::BackingReadOnly => writer.u8(24),
        AuthorityError::HostBackingTypeMismatch => writer.u8(25),
        AuthorityError::HostAccessMismatch => writer.u8(26),
        AuthorityError::InvalidPageLimit => writer.u8(27),
        AuthorityError::SameSlotRejected => writer.u8(28),
        AuthorityError::InvalidSlotRange => writer.u8(29),
        AuthorityError::NotEpoll => writer.u8(30),
        AuthorityError::NotEpollable => writer.u8(31),
        AuthorityError::EpollInterestExists => writer.u8(32),
        AuthorityError::EpollInterestNotFound => writer.u8(33),
        AuthorityError::EpollLoop => writer.u8(34),
        AuthorityError::InvalidEpollEventLimit => writer.u8(35),
        AuthorityError::NotEventCounter => writer.u8(36),
        AuthorityError::WouldBlock => writer.u8(37),
        AuthorityError::InvalidEventCounterValue => writer.u8(38),
        AuthorityError::WrongOperationFamily => writer.u8(39),
        AuthorityError::NotPipe => writer.u8(40),
        AuthorityError::InvalidPipeCapacity => writer.u8(41),
        AuthorityError::BrokenPipe => writer.u8(42),
        AuthorityError::PairAllocationFailed => writer.u8(43),
        AuthorityError::InvalidMappingRange => writer.u8(44),
        AuthorityError::MappingAttachmentNotFound => writer.u8(45),
        AuthorityError::MappingReleaseOutsideAttachment => writer.u8(46),
    }
}

fn decode_error(reader: &mut Reader<'_>) -> Result<AuthorityError, AuthorityFatal> {
    Ok(match reader.u8()? {
        1 => AuthorityError::StaleEpoch {
            expected: reader.epoch()?,
            actual: reader.epoch()?,
        },
        2 => AuthorityError::ClientNotRegistered,
        3 => AuthorityError::ClientAlreadyRegistered,
        4 => AuthorityError::StaleClientGeneration,
        5 => AuthorityError::StaleObjectGeneration,
        6 => AuthorityError::TableNotFound,
        7 => AuthorityError::DescriptionNotFound,
        8 => AuthorityError::SlotNotFound,
        9 => AuthorityError::TableNotBound,
        10 => AuthorityError::NofileExceeded,
        11 => AuthorityError::InvalidDescriptorFlags,
        12 => AuthorityError::InvalidCanonicalPath,
        13 => AuthorityError::VfsPathExists,
        14 => AuthorityError::VfsNotFound,
        15 => AuthorityError::VfsRootMutation,
        16 => AuthorityError::PayloadTooLarge,
        17 => AuthorityError::InvalidOffset,
        18 => AuthorityError::NotReadable,
        19 => AuthorityError::NotWritable,
        20 => AuthorityError::NotSeekable,
        21 => AuthorityError::NotHostBacked,
        22 => AuthorityError::CapabilityLeaseNotFound,
        23 => AuthorityError::HostIo(HostErrno::from_host(
            NonZeroI32::new(reader.i32()?)
                .filter(|errno| errno.get() > 0)
                .ok_or(AuthorityFatal::MalformedFrame("invalid host errno"))?,
        )),
        24 => AuthorityError::BackingReadOnly,
        25 => AuthorityError::HostBackingTypeMismatch,
        26 => AuthorityError::HostAccessMismatch,
        27 => AuthorityError::InvalidPageLimit,
        28 => AuthorityError::SameSlotRejected,
        29 => AuthorityError::InvalidSlotRange,
        30 => AuthorityError::NotEpoll,
        31 => AuthorityError::NotEpollable,
        32 => AuthorityError::EpollInterestExists,
        33 => AuthorityError::EpollInterestNotFound,
        34 => AuthorityError::EpollLoop,
        35 => AuthorityError::InvalidEpollEventLimit,
        36 => AuthorityError::NotEventCounter,
        37 => AuthorityError::WouldBlock,
        38 => AuthorityError::InvalidEventCounterValue,
        39 => AuthorityError::WrongOperationFamily,
        40 => AuthorityError::NotPipe,
        41 => AuthorityError::InvalidPipeCapacity,
        42 => AuthorityError::BrokenPipe,
        43 => AuthorityError::PairAllocationFailed,
        44 => AuthorityError::InvalidMappingRange,
        45 => AuthorityError::MappingAttachmentNotFound,
        46 => AuthorityError::MappingReleaseOutsideAttachment,
        _ => return malformed("unknown authority error"),
    })
}

const fn access_mode_tag(mode: AccessMode) -> u8 {
    match mode {
        AccessMode::ReadOnly => 0,
        AccessMode::WriteOnly => 1,
        AccessMode::ReadWrite => 2,
        AccessMode::PathOnly => 3,
    }
}

const fn same_slot_tag(behavior: SameSlotBehavior) -> u8 {
    match behavior {
        SameSlotBehavior::ReturnUnchanged => 0,
        SameSlotBehavior::Reject => 1,
    }
}

const fn slot_range_action_tag(action: SlotRangeAction) -> u8 {
    match action {
        SlotRangeAction::Close => 0,
        SlotRangeAction::SetCloseOnExec => 1,
    }
}

const fn capability_purpose_tag(purpose: CapabilityLeasePurpose) -> u8 {
    match purpose {
        CapabilityLeasePurpose::MappingSource => 0,
    }
}

const fn capability_disposition_tag(disposition: CapabilityLeaseDisposition) -> u8 {
    match disposition {
        CapabilityLeaseDisposition::Commit => 0,
        CapabilityLeaseDisposition::Abort => 1,
    }
}

fn malformed<T>(message: &'static str) -> Result<T, AuthorityFatal> {
    Err(AuthorityFatal::MalformedFrame(message))
}

#[derive(Default)]
struct Writer {
    bytes: Vec<u8>,
}

impl Writer {
    fn with_capacity(capacity: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(capacity),
        }
    }
    fn finish(self) -> Vec<u8> {
        self.bytes
    }
    fn len_u32(&self) -> Result<u32, AuthorityFatal> {
        u32::try_from(self.bytes.len())
            .map_err(|_| AuthorityFatal::EncodingFailure("payload length overflow"))
    }
    fn u8(&mut self, value: u8) {
        self.bytes.push(value);
    }
    fn bool(&mut self, value: bool) {
        self.u8(u8::from(value));
    }
    fn u16(&mut self, value: u16) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }
    fn u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }
    fn i32(&mut self, value: i32) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }
    fn u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }
    fn i64(&mut self, value: i64) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }
    fn blob(&mut self, value: &[u8]) -> Result<(), AuthorityFatal> {
        self.u32(
            u32::try_from(value.len())
                .map_err(|_| AuthorityFatal::EncodingFailure("blob length overflow"))?,
        );
        self.bytes.extend_from_slice(value);
        Ok(())
    }
    fn path(&mut self, path: &CanonicalPath) -> Result<(), AuthorityFatal> {
        self.blob(path.as_str().as_bytes())
    }
    fn optional_path(&mut self, path: Option<&CanonicalPath>) -> Result<(), AuthorityFatal> {
        match path {
            Some(path) => {
                self.bool(true);
                self.path(path)
            }
            None => {
                self.bool(false);
                Ok(())
            }
        }
    }
    fn client(&mut self, client: ClientIdentity) {
        self.u64(client.id.raw());
        self.u32(client.host_pid.raw());
        self.u32(client.process_generation.raw());
    }
    fn epoll_registration(&mut self, registration: EpollRegistration) {
        self.u32(registration.events.bits());
        self.u64(registration.data.raw());
    }

    fn mapping_range(&mut self, range: MappingRange) {
        self.u64(range.start());
        self.u64(range.length());
    }

    fn mapping_attachments(
        &mut self,
        attachments: &[MappingAttachmentId],
    ) -> Result<(), AuthorityFatal> {
        self.u16(
            u16::try_from(attachments.len())
                .map_err(|_| AuthorityFatal::EncodingFailure("too many mapping attachments"))?,
        );
        for attachment in attachments {
            self.u64(attachment.raw());
        }
        Ok(())
    }

    fn mapping_ranges(&mut self, ranges: &[MappingRange]) -> Result<(), AuthorityFatal> {
        self.u16(
            u16::try_from(ranges.len())
                .map_err(|_| AuthorityFatal::EncodingFailure("too many mapping fragments"))?,
        );
        for range in ranges {
            self.mapping_range(*range);
        }
        Ok(())
    }

    fn mapping_lease_disposition(&mut self, disposition: MappingLeaseDisposition) {
        match disposition {
            MappingLeaseDisposition::Commit { range } => {
                self.u8(0);
                self.mapping_range(range);
            }
            MappingLeaseDisposition::Abort => self.u8(1),
        }
    }

    fn mapping_release(&mut self, release: MappingRelease) {
        match release {
            MappingRelease::Whole => self.u8(0),
            MappingRelease::Range(range) => {
                self.u8(1);
                self.mapping_range(range);
            }
        }
    }

    fn optional_mapping_attachment(&mut self, attachment: Option<MappingAttachmentId>) {
        match attachment {
            Some(attachment) => {
                self.bool(true);
                self.u64(attachment.raw());
            }
            None => self.bool(false),
        }
    }

    fn epoll_host_plan(&mut self, plan: EpollHostPlan) {
        self.u64(plan.epoll_description.raw());
        self.u64(plan.target_description.raw());
        self.i32(plan.registered_slot.raw());
        self.u32(plan.generation.raw());
        self.u8(match plan.action {
            EpollHostPlanAction::RegisterOrModify => 0,
            EpollHostPlanAction::Delete => 1,
        });
        self.u32(plan.events.bits());
        self.u64(plan.plan_revision.raw());
    }
    fn epoll_key(&mut self, key: EpollInterestKey) {
        self.i32(key.registered_slot.raw());
        self.u64(key.target_description.raw());
    }
    fn epoll_events(&mut self, events: &[EpollReadyEvent]) -> Result<(), AuthorityFatal> {
        self.u16(
            u16::try_from(events.len())
                .map_err(|_| AuthorityFatal::EncodingFailure("epoll event count overflow"))?,
        );
        for event in events {
            self.u32(event.events.bits());
            self.u64(event.data.raw());
        }
        Ok(())
    }
    fn optional_slot(&mut self, slot: Option<FileSlotNumber>) {
        match slot {
            Some(slot) => {
                self.bool(true);
                self.i32(slot.raw());
            }
            None => self.bool(false),
        }
    }
    fn optional_description(&mut self, description: Option<FileDescriptionId>) {
        match description {
            Some(description) => {
                self.bool(true);
                self.u64(description.raw());
            }
            None => self.bool(false),
        }
    }
    fn optional_revision(&mut self, revision: Option<Revision>) {
        match revision {
            Some(revision) => {
                self.bool(true);
                self.u64(revision.raw());
            }
            None => self.bool(false),
        }
    }
    fn slots(&mut self, slots: &[FileSlotNumber]) -> Result<(), AuthorityFatal> {
        self.u32(
            u32::try_from(slots.len())
                .map_err(|_| AuthorityFatal::EncodingFailure("slot count overflow"))?,
        );
        for slot in slots {
            self.i32(slot.raw());
        }
        Ok(())
    }
    fn slot_snapshots(&mut self, slots: &[SlotSnapshot]) -> Result<(), AuthorityFatal> {
        self.u16(
            u16::try_from(slots.len())
                .map_err(|_| AuthorityFatal::EncodingFailure("slot snapshot count overflow"))?,
        );
        for slot in slots {
            self.slot_snapshot(slot)?;
        }
        Ok(())
    }
    fn slot_snapshot(&mut self, slot: &SlotSnapshot) -> Result<(), AuthorityFatal> {
        self.i32(slot.fd.raw());
        self.u64(slot.description.raw());
        self.u64(slot.description_generation.raw());
        self.u32(slot.flags.raw());
        self.optional_path(slot.path.as_ref())
    }
    fn description_snapshot(&mut self, value: &DescriptionSnapshot) -> Result<(), AuthorityFatal> {
        self.u64(value.description.raw());
        self.u64(value.generation.raw());
        self.u64(value.revision.raw());
        self.u64(value.offset.raw());
        self.u8(access_mode_tag(value.access_mode));
        self.u64(value.status_flags.raw());
        self.u64(value.logical_slot_refs);
        match &value.backing {
            DescriptionBackingSnapshot::Synthetic { length } => {
                self.u8(0);
                self.u64(*length);
            }
            DescriptionBackingSnapshot::VfsFile { object } => {
                self.u8(1);
                self.u64(object.raw());
            }
            DescriptionBackingSnapshot::HostFile { writable } => {
                self.u8(2);
                self.bool(*writable);
            }
            DescriptionBackingSnapshot::Epoll { interests } => {
                self.u8(3);
                self.u32(*interests);
            }
            DescriptionBackingSnapshot::EventCounter { counter, semaphore } => {
                self.u8(4);
                self.u64(*counter);
                self.bool(*semaphore);
            }
            DescriptionBackingSnapshot::PipeEnd { pipe, end } => {
                self.u8(5);
                self.u64(pipe.raw());
                self.u8(match end {
                    PipeEnd::Reader => 0,
                    PipeEnd::Writer => 1,
                });
            }
        }
        Ok(())
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }
    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.offset)
    }
    fn rest(&self) -> &'a [u8] {
        &self.bytes[self.offset..]
    }
    fn finish(&self) -> Result<(), AuthorityFatal> {
        if self.remaining() == 0 {
            Ok(())
        } else {
            malformed("trailing payload bytes")
        }
    }
    fn take<const N: usize>(&mut self) -> Result<[u8; N], AuthorityFatal> {
        let end = self
            .offset
            .checked_add(N)
            .ok_or(AuthorityFatal::MalformedFrame("frame offset overflow"))?;
        let slice = self
            .bytes
            .get(self.offset..end)
            .ok_or(AuthorityFatal::MalformedFrame("truncated frame"))?;
        self.offset = end;
        Ok(slice.try_into().expect("fixed-size frame field"))
    }
    fn u8(&mut self) -> Result<u8, AuthorityFatal> {
        Ok(self.take::<1>()?[0])
    }
    fn bool(&mut self) -> Result<bool, AuthorityFatal> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => malformed("invalid boolean"),
        }
    }
    fn u16(&mut self) -> Result<u16, AuthorityFatal> {
        Ok(u16::from_be_bytes(self.take()?))
    }
    fn u32(&mut self) -> Result<u32, AuthorityFatal> {
        Ok(u32::from_be_bytes(self.take()?))
    }
    fn i32(&mut self) -> Result<i32, AuthorityFatal> {
        Ok(i32::from_be_bytes(self.take()?))
    }
    fn u64(&mut self) -> Result<u64, AuthorityFatal> {
        Ok(u64::from_be_bytes(self.take()?))
    }
    fn i64(&mut self) -> Result<i64, AuthorityFatal> {
        Ok(i64::from_be_bytes(self.take()?))
    }
    fn blob(&mut self) -> Result<Vec<u8>, AuthorityFatal> {
        let length = usize::try_from(self.u32()?)
            .map_err(|_| AuthorityFatal::MalformedFrame("blob length overflow"))?;
        let end = self
            .offset
            .checked_add(length)
            .ok_or(AuthorityFatal::MalformedFrame("blob end overflow"))?;
        let bytes = self
            .bytes
            .get(self.offset..end)
            .ok_or(AuthorityFatal::MalformedFrame("truncated blob"))?;
        self.offset = end;
        Ok(bytes.to_vec())
    }
    fn path(&mut self) -> Result<CanonicalPath, AuthorityFatal> {
        let bytes = self.blob()?;
        let path = String::from_utf8(bytes)
            .map_err(|_| AuthorityFatal::MalformedFrame("path is not UTF-8"))?;
        CanonicalPath::absolute(path)
            .map_err(|_| AuthorityFatal::MalformedFrame("path is not canonical"))
    }
    fn optional_path(&mut self) -> Result<Option<CanonicalPath>, AuthorityFatal> {
        if self.bool()? {
            Ok(Some(self.path()?))
        } else {
            Ok(None)
        }
    }
    fn epoch(&mut self) -> Result<AuthorityEpoch, AuthorityFatal> {
        AuthorityEpoch::for_run(self.u64()?)
            .map_err(|_| AuthorityFatal::MalformedFrame("invalid authority epoch"))
    }
    fn generation(&mut self) -> Result<ObjectGeneration, AuthorityFatal> {
        ObjectGeneration::from_snapshot(self.u64()?)
            .map_err(|_| AuthorityFatal::MalformedFrame("invalid object generation"))
    }
    fn revision(&mut self) -> Result<Revision, AuthorityFatal> {
        Ok(Revision::from_wire(self.u64()?))
    }
    fn table_id(&mut self) -> Result<FileTableId, AuthorityFatal> {
        NonZeroU64::new(self.u64()?)
            .map(FileTableId::from_registry_allocation)
            .ok_or(AuthorityFatal::MalformedFrame("invalid file table id"))
    }
    fn description_id(&mut self) -> Result<FileDescriptionId, AuthorityFatal> {
        NonZeroU64::new(self.u64()?)
            .map(FileDescriptionId::from_registry_allocation)
            .ok_or(AuthorityFatal::MalformedFrame(
                "invalid file description id",
            ))
    }
    fn vfs_object(&mut self) -> Result<VfsObjectId, AuthorityFatal> {
        VfsObjectId::from_snapshot(self.u64()?)
            .map_err(|_| AuthorityFatal::MalformedFrame("invalid VFS object id"))
    }
    fn pipe_id(&mut self) -> Result<PipeId, AuthorityFatal> {
        PipeId::from_snapshot(self.u64()?)
            .map_err(|_| AuthorityFatal::MalformedFrame("invalid pipe id"))
    }

    fn capability_lease_id(&mut self) -> Result<CapabilityLeaseId, AuthorityFatal> {
        CapabilityLeaseId::from_snapshot(self.u64()?)
            .map_err(|_| AuthorityFatal::MalformedFrame("invalid capability lease id"))
    }
    fn slot(&mut self) -> Result<FileSlotNumber, AuthorityFatal> {
        FileSlotNumber::for_open_fd(self.i32()?)
            .map_err(|_| AuthorityFatal::MalformedFrame("invalid file slot"))
    }
    fn epoll_registration(&mut self) -> Result<EpollRegistration, AuthorityFatal> {
        Ok(EpollRegistration {
            events: LinuxEpollEvents::from_bits_retain(self.u32()?),
            data: EpollUserData::from_guest(self.u64()?),
        })
    }
    fn epoll_key(&mut self) -> Result<EpollInterestKey, AuthorityFatal> {
        Ok(EpollInterestKey {
            registered_slot: self.slot()?,
            target_description: self.description_id()?,
        })
    }

    fn mapping_attachment_id(&mut self) -> Result<MappingAttachmentId, AuthorityFatal> {
        MappingAttachmentId::from_snapshot(self.u64()?)
            .map_err(|_| AuthorityFatal::MalformedFrame("invalid mapping attachment id"))
    }

    fn optional_mapping_attachment(
        &mut self,
    ) -> Result<Option<MappingAttachmentId>, AuthorityFatal> {
        if self.bool()? {
            self.mapping_attachment_id().map(Some)
        } else {
            Ok(None)
        }
    }

    fn mapping_range(&mut self) -> Result<MappingRange, AuthorityFatal> {
        MappingRange::bounded(self.u64()?, self.u64()?)
            .map_err(|_| AuthorityFatal::MalformedFrame("invalid mapping range"))
    }

    fn mapping_attachments(&mut self) -> Result<Vec<MappingAttachmentId>, AuthorityFatal> {
        let count = usize::from(self.u16()?);
        let mut attachments = Vec::with_capacity(count);
        for _ in 0..count {
            attachments.push(self.mapping_attachment_id()?);
        }
        Ok(attachments)
    }

    fn mapping_ranges(&mut self) -> Result<Vec<MappingRange>, AuthorityFatal> {
        let count = usize::from(self.u16()?);
        let mut ranges = Vec::with_capacity(count);
        for _ in 0..count {
            ranges.push(self.mapping_range()?);
        }
        Ok(ranges)
    }

    fn mapping_lease_disposition(&mut self) -> Result<MappingLeaseDisposition, AuthorityFatal> {
        match self.u8()? {
            0 => Ok(MappingLeaseDisposition::Commit {
                range: self.mapping_range()?,
            }),
            1 => Ok(MappingLeaseDisposition::Abort),
            _ => malformed("invalid mapping lease disposition"),
        }
    }

    fn mapping_release(&mut self) -> Result<MappingRelease, AuthorityFatal> {
        match self.u8()? {
            0 => Ok(MappingRelease::Whole),
            1 => self.mapping_range().map(MappingRelease::Range),
            _ => malformed("invalid mapping release"),
        }
    }

    fn epoll_host_plan(&mut self) -> Result<EpollHostPlan, AuthorityFatal> {
        Ok(EpollHostPlan {
            epoll_description: self.description_id()?,
            target_description: self.description_id()?,
            registered_slot: self.slot()?,
            generation: self.interest_generation()?,
            action: match self.u8()? {
                0 => EpollHostPlanAction::RegisterOrModify,
                1 => EpollHostPlanAction::Delete,
                _ => return malformed("invalid epoll host-plan action"),
            },
            events: LinuxEpollEvents::from_bits_retain(self.u32()?),
            plan_revision: self.revision()?,
        })
    }
    fn interest_generation(&mut self) -> Result<InterestGeneration, AuthorityFatal> {
        InterestGeneration::from_snapshot(self.u32()?)
            .map_err(|_| AuthorityFatal::MalformedFrame("invalid interest generation"))
    }
    fn epoll_events(&mut self) -> Result<Vec<EpollReadyEvent>, AuthorityFatal> {
        let count = usize::from(self.u16()?);
        if count > usize::from(EpollEventLimit::MAX) {
            return malformed("epoll event vector exceeds bound");
        }
        (0..count)
            .map(|_| {
                Ok(EpollReadyEvent {
                    events: LinuxEpollEvents::from_bits_retain(self.u32()?),
                    data: EpollUserData::from_guest(self.u64()?),
                })
            })
            .collect()
    }
    fn optional_slot(&mut self) -> Result<Option<FileSlotNumber>, AuthorityFatal> {
        if self.bool()? {
            Ok(Some(self.slot()?))
        } else {
            Ok(None)
        }
    }
    fn optional_description(&mut self) -> Result<Option<FileDescriptionId>, AuthorityFatal> {
        if self.bool()? {
            Ok(Some(self.description_id()?))
        } else {
            Ok(None)
        }
    }
    fn access_mode(&mut self) -> Result<AccessMode, AuthorityFatal> {
        match self.u8()? {
            0 => Ok(AccessMode::ReadOnly),
            1 => Ok(AccessMode::WriteOnly),
            2 => Ok(AccessMode::ReadWrite),
            3 => Ok(AccessMode::PathOnly),
            _ => malformed("invalid access mode"),
        }
    }
    fn same_slot_behavior(&mut self) -> Result<SameSlotBehavior, AuthorityFatal> {
        match self.u8()? {
            0 => Ok(SameSlotBehavior::ReturnUnchanged),
            1 => Ok(SameSlotBehavior::Reject),
            _ => malformed("invalid same-slot behavior"),
        }
    }
    fn slot_range_action(&mut self) -> Result<SlotRangeAction, AuthorityFatal> {
        match self.u8()? {
            0 => Ok(SlotRangeAction::Close),
            1 => Ok(SlotRangeAction::SetCloseOnExec),
            _ => malformed("invalid slot range action"),
        }
    }
    fn capability_purpose(&mut self) -> Result<CapabilityLeasePurpose, AuthorityFatal> {
        match self.u8()? {
            0 => Ok(CapabilityLeasePurpose::MappingSource),
            _ => malformed("invalid capability lease purpose"),
        }
    }
    fn capability_disposition(&mut self) -> Result<CapabilityLeaseDisposition, AuthorityFatal> {
        match self.u8()? {
            0 => Ok(CapabilityLeaseDisposition::Commit),
            1 => Ok(CapabilityLeaseDisposition::Abort),
            _ => malformed("invalid capability lease disposition"),
        }
    }
    fn client(&mut self) -> Result<ClientIdentity, AuthorityFatal> {
        let id = super::ClientId::for_process_client(self.u64()?)
            .map_err(|_| AuthorityFatal::MalformedFrame("invalid client id"))?;
        let pid = self.u32()?;
        let generation = self.u32()?;
        ClientIdentity::registered(id, HostPid::new(pid), ProcessGeneration::new(generation))
            .map_err(|_| AuthorityFatal::MalformedFrame("invalid client identity"))
    }
    fn optional_revision(&mut self) -> Result<Option<Revision>, AuthorityFatal> {
        if self.bool()? {
            Ok(Some(self.revision()?))
        } else {
            Ok(None)
        }
    }
    fn slots(&mut self) -> Result<Vec<FileSlotNumber>, AuthorityFatal> {
        let count = usize::try_from(self.u32()?)
            .map_err(|_| AuthorityFatal::MalformedFrame("slot count overflow"))?;
        if count > self.remaining() / std::mem::size_of::<i32>() {
            return malformed("slot vector exceeds frame");
        }
        (0..count).map(|_| self.slot()).collect()
    }
    fn slot_snapshots(&mut self) -> Result<Vec<SlotSnapshot>, AuthorityFatal> {
        let count = usize::from(self.u16()?);
        if count > usize::from(SlotPageLimit::MAX) {
            return malformed("slot snapshot page exceeds bound");
        }
        (0..count).map(|_| self.slot_snapshot()).collect()
    }
    fn slot_snapshot(&mut self) -> Result<SlotSnapshot, AuthorityFatal> {
        Ok(SlotSnapshot {
            fd: self.slot()?,
            description: self.description_id()?,
            description_generation: self.generation()?,
            flags: DescriptorFlags::from_linux_bits(self.u32()?)
                .map_err(|_| AuthorityFatal::MalformedFrame("invalid descriptor flags"))?,
            path: self.optional_path()?,
        })
    }
    fn description_snapshot(&mut self) -> Result<DescriptionSnapshot, AuthorityFatal> {
        let description = self.description_id()?;
        let generation = self.generation()?;
        let revision = self.revision()?;
        let offset = FileOffset::from_start(self.u64()?);
        let access_mode = self.access_mode()?;
        let status_flags = StatusFlags::from_linux_bits(self.u64()?);
        let logical_slot_refs = self.u64()?;
        let backing = match self.u8()? {
            0 => DescriptionBackingSnapshot::Synthetic {
                length: self.u64()?,
            },
            1 => DescriptionBackingSnapshot::VfsFile {
                object: self.vfs_object()?,
            },
            2 => DescriptionBackingSnapshot::HostFile {
                writable: self.bool()?,
            },
            3 => DescriptionBackingSnapshot::Epoll {
                interests: self.u32()?,
            },
            4 => DescriptionBackingSnapshot::EventCounter {
                counter: self.u64()?,
                semaphore: self.bool()?,
            },
            5 => DescriptionBackingSnapshot::PipeEnd {
                pipe: self.pipe_id()?,
                end: match self.u8()? {
                    0 => PipeEnd::Reader,
                    1 => PipeEnd::Writer,
                    _ => return malformed("invalid pipe end"),
                },
            },
            _ => return malformed("invalid description backing"),
        };
        Ok(DescriptionSnapshot {
            description,
            generation,
            revision,
            offset,
            access_mode,
            status_flags,
            logical_slot_refs,
            backing,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client() -> ClientIdentity {
        ClientIdentity::registered(
            super::super::ClientId::for_process_client(1).expect("client id"),
            HostPid::new(99),
            ProcessGeneration::new(1),
        )
        .expect("client")
    }

    #[test]
    fn request_and_response_frames_round_trip() {
        let request = Request {
            epoch: AuthorityEpoch::for_run(7).expect("epoch"),
            client: client(),
            request_id: RequestId::from_client_sequence(3).expect("request id"),
            expected_generation: ObjectGeneration::INITIAL,
            command: Command::CreateVfsFile {
                path: CanonicalPath::absolute("/wire").expect("path"),
                mode: 0o640,
                contents: b"payload".to_vec(),
            },
        };
        let encoded = encode_request(&request).expect("encode request");
        assert_eq!(
            decode_request(&encoded, 0).expect("decode request"),
            request
        );

        let response = Response {
            request_id: request.request_id,
            authority_revision: Revision::from_wire(4),
            outcome: Outcome::VfsObjectCreated {
                object: VfsObjectId::from_snapshot(9).expect("object"),
                namespace_revision: Revision::from_wire(4),
            },
        };
        let encoded = encode_response(&request, &response).expect("encode response");
        assert_eq!(
            decode_response(&request, &encoded, 0).expect("decode response"),
            response
        );
    }

    #[test]
    fn every_command_and_outcome_variant_round_trips() {
        let table = FileTableId::from_registry_allocation(NonZeroU64::new(2).expect("table"));
        let description =
            FileDescriptionId::from_registry_allocation(NonZeroU64::new(3).expect("description"));
        let object = VfsObjectId::from_snapshot(4).expect("object");
        let lease = CapabilityLeaseId::from_snapshot(5).expect("lease");
        let attachment = MappingAttachmentId::from_snapshot(6).expect("attachment");
        let pipe = PipeId::from_snapshot(7).expect("pipe");
        let path = CanonicalPath::absolute("/all-variants").expect("path");
        let registration = EpollRegistration {
            events: LinuxEpollEvents::IN | LinuxEpollEvents::ET,
            data: EpollUserData::from_guest(0x1234),
        };
        let host_plan = EpollHostPlan {
            epoll_description: description,
            target_description: description,
            registered_slot: FileSlotNumber::for_open_fd(3).expect("fd"),
            generation: InterestGeneration::from_snapshot(1).expect("generation"),
            action: EpollHostPlanAction::RegisterOrModify,
            events: registration.events,
            plan_revision: Revision::from_wire(8),
        };
        let commands = vec![
            Command::RegisterClient,
            Command::ExitClient,
            Command::CreateTable,
            Command::CreatePipeAndInstall {
                table,
                minimum: FileSlotNumber::for_open_fd(3).expect("fd"),
                ceiling: NofileAllocationCeiling::from_captured_soft_limit(9),
                descriptor_flags: DescriptorFlags::CLOSE_ON_EXEC,
                status_flags: StatusFlags::from_linux_bits(0x800),
                capacity: PipeCapacity::bounded(4096).expect("capacity"),
            },
            Command::SetPipeCapacity {
                table,
                fd: FileSlotNumber::for_open_fd(3).expect("fd"),
                capacity: PipeCapacity::bounded(8192).expect("capacity"),
            },
            Command::EpollRevalidateHostPlan { plan: host_plan },
            Command::FinalizeMappingLease {
                lease,
                disposition: MappingLeaseDisposition::Commit {
                    range: MappingRange::bounded(0x1000, 0x3000).expect("range"),
                },
            },
            Command::ReleaseMappingAttachment {
                attachment,
                release: MappingRelease::Range(
                    MappingRange::bounded(0x2000, 0x1000).expect("range"),
                ),
            },
            Command::CreateEpollAndInstall {
                table,
                minimum: FileSlotNumber::for_open_fd(3).expect("fd"),
                ceiling: NofileAllocationCeiling::from_captured_soft_limit(9),
                descriptor_flags: DescriptorFlags::CLOSE_ON_EXEC,
            },
            Command::CreateEventCounterAndInstall {
                table,
                initial: 7,
                semaphore: true,
                minimum: FileSlotNumber::for_open_fd(4).expect("fd"),
                ceiling: NofileAllocationCeiling::from_captured_soft_limit(9),
                descriptor_flags: DescriptorFlags::NONE,
                status_flags: StatusFlags::from_linux_bits(0x800),
            },
            Command::CreateVfsFile {
                path: path.clone(),
                mode: 0o600,
                contents: b"x".to_vec(),
            },
            Command::ResolveVfs { path: path.clone() },
            Command::LinkVfs {
                object,
                path: path.clone(),
            },
            Command::UnlinkVfs { path: path.clone() },
            Command::RenameVfs {
                from: path.clone(),
                to: CanonicalPath::absolute("/to").expect("to"),
            },
            Command::OpenVfsAndInstall {
                table,
                object,
                object_generation: ObjectGeneration::INITIAL,
                minimum: FileSlotNumber::for_open_fd(3).expect("fd"),
                ceiling: NofileAllocationCeiling::from_captured_soft_limit(9),
                descriptor_flags: DescriptorFlags::CLOSE_ON_EXEC,
                access_mode: AccessMode::ReadOnly,
                status_flags: StatusFlags::from_linux_bits(0x800),
                path: Some(path.clone()),
            },
            Command::CreateSyntheticAndInstall {
                table,
                contents: b"synthetic".to_vec(),
                minimum: FileSlotNumber::for_open_fd(4).expect("fd"),
                ceiling: NofileAllocationCeiling::from_captured_soft_limit(9),
                descriptor_flags: DescriptorFlags::NONE,
                access_mode: AccessMode::WriteOnly,
                status_flags: StatusFlags::default(),
                path: None,
            },
            Command::AdoptHostFileAndInstall {
                table,
                minimum: FileSlotNumber::for_open_fd(4).expect("fd"),
                ceiling: NofileAllocationCeiling::from_captured_soft_limit(9),
                descriptor_flags: DescriptorFlags::NONE,
                access_mode: AccessMode::ReadWrite,
                status_flags: StatusFlags::default(),
                writable: true,
                path: Some(path.clone()),
            },
            Command::AcquireCapabilityLease {
                table,
                fd: FileSlotNumber::for_open_fd(3).expect("fd"),
                purpose: CapabilityLeasePurpose::MappingSource,
            },
            Command::ReleaseCapabilityLease {
                lease,
                disposition: CapabilityLeaseDisposition::Abort,
            },
            Command::ListSlots {
                table,
                after: Some(FileSlotNumber::for_open_fd(3).expect("fd")),
                maximum: SlotPageLimit::bounded(8).expect("page"),
            },
            Command::SetDescriptorFlags {
                table,
                fd: FileSlotNumber::for_open_fd(3).expect("fd"),
                flags: DescriptorFlags::CLOSE_ON_EXEC,
            },
            Command::ReplaceSlot {
                table,
                source: FileSlotNumber::for_open_fd(3).expect("fd"),
                target: FileSlotNumber::for_open_fd(5).expect("fd"),
                ceiling: NofileAllocationCeiling::from_captured_soft_limit(9),
                flags: DescriptorFlags::NONE,
                same_slot: SameSlotBehavior::Reject,
            },
            Command::MutateSlotRange {
                table,
                first: FileSlotNumber::for_open_fd(3).expect("fd"),
                last: FileSlotNumber::for_open_fd(8).expect("fd"),
                action: SlotRangeAction::SetCloseOnExec,
            },
            Command::EpollCtlAdd {
                table,
                epoll_fd: FileSlotNumber::for_open_fd(3).expect("fd"),
                target_fd: FileSlotNumber::for_open_fd(4).expect("fd"),
                registration,
            },
            Command::EpollCtlModify {
                table,
                epoll_fd: FileSlotNumber::for_open_fd(3).expect("fd"),
                target_fd: FileSlotNumber::for_open_fd(4).expect("fd"),
                registration,
            },
            Command::EpollCtlDelete {
                table,
                epoll_fd: FileSlotNumber::for_open_fd(3).expect("fd"),
                target_fd: FileSlotNumber::for_open_fd(4).expect("fd"),
            },
            Command::ObserveReadiness {
                table,
                fd: FileSlotNumber::for_open_fd(4).expect("fd"),
                ready: LinuxEpollEvents::IN,
                read_available: 8,
            },
            Command::EpollCollect {
                table,
                epoll_fd: FileSlotNumber::for_open_fd(3).expect("fd"),
                maximum: EpollEventLimit::bounded(4).expect("event limit"),
            },
            Command::EpollAcknowledgeIo {
                table,
                fd: FileSlotNumber::for_open_fd(4).expect("fd"),
                consumed: LinuxEpollEvents::IN,
                read_available: 0,
                write_backpressured: true,
            },
            Command::EventCounterRead {
                table,
                fd: FileSlotNumber::for_open_fd(4).expect("fd"),
            },
            Command::EventCounterWrite {
                table,
                fd: FileSlotNumber::for_open_fd(4).expect("fd"),
                value: 9,
            },
            Command::ResolveSlot {
                table,
                fd: FileSlotNumber::for_open_fd(3).expect("fd"),
            },
            Command::Read {
                table,
                fd: FileSlotNumber::for_open_fd(3).expect("fd"),
                maximum: ByteCount::bounded(7).expect("bytes"),
            },
            Command::Write {
                table,
                fd: FileSlotNumber::for_open_fd(3).expect("fd"),
                bytes: b"write".to_vec(),
            },
            Command::Seek {
                table,
                fd: FileSlotNumber::for_open_fd(3).expect("fd"),
                offset: -2,
                whence: SeekWhence::End,
            },
            Command::Close {
                table,
                fd: FileSlotNumber::for_open_fd(3).expect("fd"),
            },
            Command::Dup {
                table,
                source: FileSlotNumber::for_open_fd(3).expect("fd"),
                minimum: FileSlotNumber::for_open_fd(5).expect("fd"),
                ceiling: NofileAllocationCeiling::from_captured_soft_limit(9),
                flags: DescriptorFlags::CLOSE_ON_EXEC,
            },
            Command::ForkCopy {
                source: table,
                owner: client(),
            },
            Command::ForkCopyMappings {
                source_owner: client(),
                owner: client(),
            },
            Command::ShareTable {
                table,
                owner: client(),
            },
            Command::ExecSuccessor { source: table },
            Command::InspectDescription { description },
        ];
        for (index, command) in commands.into_iter().enumerate() {
            let request = Request {
                epoch: AuthorityEpoch::for_run(7).expect("epoch"),
                client: client(),
                request_id: RequestId::from_client_sequence(u64::try_from(index + 1).expect("id"))
                    .expect("request id"),
                expected_generation: ObjectGeneration::INITIAL,
                command,
            };
            let fd_count = usize::from(matches!(
                request.command,
                Command::AdoptHostFileAndInstall { .. }
            ));
            let encoded = encode_request_with_fd_count(&request, fd_count).expect("encode request");
            assert_eq!(
                decode_request(&encoded, fd_count).expect("decode request"),
                request
            );
        }

        let slot = FileSlotNumber::for_open_fd(3).expect("fd");
        let outcomes = vec![
            Outcome::ClientRegistered,
            Outcome::ClientExited,
            Outcome::TableCreated {
                table,
                generation: ObjectGeneration::INITIAL,
                revision: Revision::from_wire(1),
            },
            Outcome::EpollCreated {
                table,
                fd: slot,
                description,
                generation: ObjectGeneration::INITIAL,
                table_revision: Revision::from_wire(2),
                description_revision: Revision::from_wire(2),
            },
            Outcome::EventCounterCreated {
                table,
                fd: slot,
                description,
                generation: ObjectGeneration::INITIAL,
                table_revision: Revision::from_wire(2),
                description_revision: Revision::from_wire(2),
            },
            Outcome::VfsObjectCreated {
                object,
                namespace_revision: Revision::from_wire(2),
            },
            Outcome::VfsObjectResolved {
                object,
                mode: 0o600,
                object_revision: Revision::from_wire(2),
                namespace_revision: Revision::from_wire(2),
            },
            Outcome::VfsNamespaceChanged {
                object,
                namespace_revision: Revision::from_wire(3),
                object_reclaimed: true,
            },
            Outcome::Installed {
                table,
                fd: slot,
                description,
                description_generation: ObjectGeneration::INITIAL,
                table_revision: Revision::from_wire(4),
                description_revision: Revision::from_wire(4),
            },
            Outcome::Slot(SlotSnapshot {
                fd: slot,
                description,
                description_generation: ObjectGeneration::INITIAL,
                flags: DescriptorFlags::CLOSE_ON_EXEC,
                path: Some(path.clone()),
            }),
            Outcome::SlotPage {
                table,
                slots: vec![SlotSnapshot {
                    fd: slot,
                    description,
                    description_generation: ObjectGeneration::INITIAL,
                    flags: DescriptorFlags::NONE,
                    path: None,
                }],
                next_after: Some(slot),
                table_revision: Revision::from_wire(4),
            },
            Outcome::DescriptorFlagsSet {
                table,
                fd: slot,
                flags: DescriptorFlags::CLOSE_ON_EXEC,
                table_revision: Revision::from_wire(5),
            },
            Outcome::SlotReplaced {
                table,
                source: slot,
                target: FileSlotNumber::for_open_fd(4).expect("fd"),
                replaced_description: Some(description),
                description_reclaimed: true,
                object_reclaimed: false,
                table_revision: Revision::from_wire(6),
            },
            Outcome::SlotRangeMutated {
                table,
                action: SlotRangeAction::Close,
                affected: 2,
                table_revision: Revision::from_wire(7),
            },
            Outcome::EpollInterestAdded {
                key: EpollInterestKey {
                    registered_slot: slot,
                    target_description: description,
                },
                generation: InterestGeneration::from_snapshot(1).expect("generation"),
                description_revision: Revision::from_wire(8),
                host_plan,
            },
            Outcome::EpollInterestModified {
                key: EpollInterestKey {
                    registered_slot: slot,
                    target_description: description,
                },
                generation: InterestGeneration::from_snapshot(1).expect("generation"),
                description_revision: Revision::from_wire(9),
                host_plan: EpollHostPlan {
                    plan_revision: Revision::from_wire(9),
                    ..host_plan
                },
            },
            Outcome::EpollInterestDeleted {
                key: EpollInterestKey {
                    registered_slot: slot,
                    target_description: description,
                },
                description_revision: Revision::from_wire(10),
                host_plan: EpollHostPlan {
                    action: EpollHostPlanAction::Delete,
                    events: LinuxEpollEvents::empty(),
                    plan_revision: Revision::from_wire(10),
                    ..host_plan
                },
            },
            Outcome::EpollHostPlanValidated {
                valid: true,
                current_revision: Revision::from_wire(10),
            },
            Outcome::ReadinessObserved {
                description,
                description_revision: Revision::from_wire(11),
            },
            Outcome::EpollEvents {
                events: vec![EpollReadyEvent {
                    events: LinuxEpollEvents::IN,
                    data: EpollUserData::from_guest(0x1234),
                }],
                description_revision: Revision::from_wire(12),
            },
            Outcome::EpollIoAcknowledged {
                description,
                description_revision: Revision::from_wire(13),
            },
            Outcome::EventCounterRead {
                value: 7,
                description_revision: Revision::from_wire(14),
            },
            Outcome::PipeCreated {
                table,
                pipe,
                read_fd: slot,
                write_fd: FileSlotNumber::for_open_fd(4).expect("fd"),
                read_description: description,
                write_description: FileDescriptionId::from_registry_allocation(
                    NonZeroU64::new(7).expect("description"),
                ),
                generation: ObjectGeneration::INITIAL,
                table_revision: Revision::from_wire(14),
                stream_revision: Revision::from_wire(15),
            },
            Outcome::PipeCapacitySet {
                pipe,
                capacity: PipeCapacity::bounded(8192).expect("capacity"),
                stream_revision: Revision::from_wire(16),
            },
            Outcome::StreamBytes {
                pipe,
                bytes: b"abc".to_vec(),
                description_revision: Revision::from_wire(17),
                stream_revision: Revision::from_wire(18),
            },
            Outcome::StreamWritten {
                pipe,
                count: ByteCount::bounded(3).expect("count"),
                description_revision: Revision::from_wire(19),
                stream_revision: Revision::from_wire(20),
            },
            Outcome::EventCounterWritten {
                value: 3,
                counter: 10,
                description_revision: Revision::from_wire(21),
            },
            Outcome::Bytes {
                bytes: b"bytes".to_vec(),
                offset: FileOffset::from_start(5),
                description_revision: Revision::from_wire(5),
            },
            Outcome::Written {
                count: ByteCount::bounded(5).expect("count"),
                offset: FileOffset::from_start(10),
                description_revision: Revision::from_wire(6),
                object_revision: Some(Revision::from_wire(6)),
            },
            Outcome::Seeked {
                offset: FileOffset::from_start(1),
                description_revision: Revision::from_wire(7),
            },
            Outcome::Closed {
                description,
                description_reclaimed: true,
                object_reclaimed: false,
                table_revision: Revision::from_wire(8),
            },
            Outcome::Duplicated {
                source: slot,
                fd: FileSlotNumber::for_open_fd(4).expect("fd"),
                table_revision: Revision::from_wire(9),
            },
            Outcome::ForkCopied {
                source: table,
                table,
                generation: ObjectGeneration::INITIAL,
                revision: Revision::from_wire(10),
            },
            Outcome::MappingAttachmentsCopied {
                source_owner: client(),
                owner: client(),
                attachments: vec![attachment],
                revision: Revision::from_wire(11),
            },
            Outcome::TableShared {
                table,
                revision: Revision::from_wire(11),
            },
            Outcome::ExecSucceeded {
                source: table,
                table,
                generation: ObjectGeneration::INITIAL,
                closed_on_exec: vec![slot],
                revision: Revision::from_wire(12),
            },
            Outcome::Description(DescriptionSnapshot {
                description,
                generation: ObjectGeneration::INITIAL,
                revision: Revision::from_wire(13),
                offset: FileOffset::from_start(3),
                access_mode: AccessMode::PathOnly,
                status_flags: StatusFlags::from_linux_bits(1),
                logical_slot_refs: 2,
                backing: DescriptionBackingSnapshot::Synthetic { length: 9 },
            }),
            Outcome::Description(DescriptionSnapshot {
                description,
                generation: ObjectGeneration::INITIAL,
                revision: Revision::from_wire(13),
                offset: FileOffset::from_start(3),
                access_mode: AccessMode::ReadWrite,
                status_flags: StatusFlags::from_linux_bits(1),
                logical_slot_refs: 2,
                backing: DescriptionBackingSnapshot::VfsFile { object },
            }),
            Outcome::Description(DescriptionSnapshot {
                description,
                generation: ObjectGeneration::INITIAL,
                revision: Revision::from_wire(13),
                offset: FileOffset::from_start(3),
                access_mode: AccessMode::ReadOnly,
                status_flags: StatusFlags::from_linux_bits(1),
                logical_slot_refs: 1,
                backing: DescriptionBackingSnapshot::HostFile { writable: false },
            }),
            Outcome::Description(DescriptionSnapshot {
                description,
                generation: ObjectGeneration::INITIAL,
                revision: Revision::from_wire(13),
                offset: FileOffset::from_start(0),
                access_mode: AccessMode::PathOnly,
                status_flags: StatusFlags::default(),
                logical_slot_refs: 1,
                backing: DescriptionBackingSnapshot::Epoll { interests: 2 },
            }),
            Outcome::Description(DescriptionSnapshot {
                description,
                generation: ObjectGeneration::INITIAL,
                revision: Revision::from_wire(13),
                offset: FileOffset::from_start(0),
                access_mode: AccessMode::ReadWrite,
                status_flags: StatusFlags::default(),
                logical_slot_refs: 1,
                backing: DescriptionBackingSnapshot::EventCounter {
                    counter: 7,
                    semaphore: true,
                },
            }),
            Outcome::CapabilityLeaseGranted {
                lease,
                description,
                description_generation: ObjectGeneration::INITIAL,
                purpose: CapabilityLeasePurpose::MappingSource,
                revision: Revision::from_wire(14),
            },
            Outcome::CapabilityLeaseReleased {
                lease,
                disposition: CapabilityLeaseDisposition::Commit,
                description_reclaimed: true,
                object_reclaimed: false,
                revision: Revision::from_wire(15),
            },
            Outcome::MappingLeaseFinalized {
                lease,
                attachment: Some(attachment),
                description,
                disposition: MappingLeaseDisposition::Commit {
                    range: MappingRange::bounded(0x1000, 0x3000).expect("range"),
                },
                description_reclaimed: false,
                object_reclaimed: false,
                revision: Revision::from_wire(16),
            },
            Outcome::MappingAttachmentReleased {
                attachment,
                remaining: vec![
                    MappingRange::bounded(0x1000, 0x1000).expect("range"),
                    MappingRange::bounded(0x3000, 0x1000).expect("range"),
                ],
                description_reclaimed: false,
                object_reclaimed: false,
                revision: Revision::from_wire(17),
            },
            Outcome::Rejected(AuthorityError::StaleEpoch {
                expected: AuthorityEpoch::for_run(7).expect("epoch"),
                actual: AuthorityEpoch::for_run(8).expect("epoch"),
            }),
            Outcome::Rejected(AuthorityError::ClientNotRegistered),
            Outcome::Rejected(AuthorityError::ClientAlreadyRegistered),
            Outcome::Rejected(AuthorityError::StaleClientGeneration),
            Outcome::Rejected(AuthorityError::StaleObjectGeneration),
            Outcome::Rejected(AuthorityError::TableNotFound),
            Outcome::Rejected(AuthorityError::DescriptionNotFound),
            Outcome::Rejected(AuthorityError::SlotNotFound),
            Outcome::Rejected(AuthorityError::TableNotBound),
            Outcome::Rejected(AuthorityError::NofileExceeded),
            Outcome::Rejected(AuthorityError::InvalidDescriptorFlags),
            Outcome::Rejected(AuthorityError::InvalidCanonicalPath),
            Outcome::Rejected(AuthorityError::VfsPathExists),
            Outcome::Rejected(AuthorityError::VfsNotFound),
            Outcome::Rejected(AuthorityError::VfsRootMutation),
            Outcome::Rejected(AuthorityError::PayloadTooLarge),
            Outcome::Rejected(AuthorityError::InvalidOffset),
            Outcome::Rejected(AuthorityError::NotReadable),
            Outcome::Rejected(AuthorityError::NotWritable),
            Outcome::Rejected(AuthorityError::NotSeekable),
            Outcome::Rejected(AuthorityError::NotHostBacked),
            Outcome::Rejected(AuthorityError::CapabilityLeaseNotFound),
            Outcome::Rejected(AuthorityError::HostIo(HostErrno::from_host(
                NonZeroI32::new(libc::EIO).expect("errno"),
            ))),
            Outcome::Rejected(AuthorityError::BackingReadOnly),
            Outcome::Rejected(AuthorityError::HostBackingTypeMismatch),
            Outcome::Rejected(AuthorityError::HostAccessMismatch),
            Outcome::Rejected(AuthorityError::InvalidPageLimit),
            Outcome::Rejected(AuthorityError::SameSlotRejected),
            Outcome::Rejected(AuthorityError::InvalidSlotRange),
            Outcome::Rejected(AuthorityError::NotEpoll),
            Outcome::Rejected(AuthorityError::NotEpollable),
            Outcome::Rejected(AuthorityError::EpollInterestExists),
            Outcome::Rejected(AuthorityError::EpollInterestNotFound),
            Outcome::Rejected(AuthorityError::EpollLoop),
            Outcome::Rejected(AuthorityError::InvalidEpollEventLimit),
            Outcome::Rejected(AuthorityError::NotEventCounter),
            Outcome::Rejected(AuthorityError::WouldBlock),
            Outcome::Rejected(AuthorityError::InvalidEventCounterValue),
            Outcome::Rejected(AuthorityError::WrongOperationFamily),
        ];
        let request = Request {
            epoch: AuthorityEpoch::for_run(7).expect("epoch"),
            client: client(),
            request_id: RequestId::from_client_sequence(1).expect("request id"),
            expected_generation: ObjectGeneration::INITIAL,
            command: Command::RegisterClient,
        };
        for outcome in outcomes {
            let response = Response {
                request_id: request.request_id,
                authority_revision: Revision::from_wire(20),
                outcome,
            };
            let fd_count = usize::from(matches!(
                &response.outcome,
                Outcome::CapabilityLeaseGranted { .. }
            ));
            let encoded = encode_response_with_fd_count(&request, &response, fd_count)
                .expect("encode response");
            assert_eq!(
                decode_response(&request, &encoded, fd_count).expect("decode response"),
                response
            );
        }
    }

    #[test]
    fn protocol_rejects_truncation_and_descriptor_count_mismatch() {
        let request = Request {
            epoch: AuthorityEpoch::for_run(7).expect("epoch"),
            client: client(),
            request_id: RequestId::from_client_sequence(1).expect("request id"),
            expected_generation: ObjectGeneration::INITIAL,
            command: Command::RegisterClient,
        };
        let encoded = encode_request(&request).expect("encode request");
        assert!(matches!(
            decode_request(&encoded[..encoded.len() - 1], 0),
            Err(AuthorityFatal::MalformedFrame(_))
        ));
        assert!(matches!(
            decode_request(&encoded, 1),
            Err(AuthorityFatal::MalformedFrame(_))
        ));
        let mut bad_magic = encoded.clone();
        bad_magic[0] ^= 0xff;
        assert!(matches!(
            decode_request(&bad_magic, 0),
            Err(AuthorityFatal::MalformedFrame(_))
        ));
        let mut bad_version = encoded;
        bad_version[5] = 2;
        assert!(matches!(
            decode_request(&bad_version, 0),
            Err(AuthorityFatal::MalformedFrame(_))
        ));
    }
}
