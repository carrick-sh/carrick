use std::num::NonZeroU64;

use carrick_kernel::domains::{HostPid, ProcessGeneration};

use super::{
    AccessMode, AuthorityEpoch, AuthorityError, AuthorityFatal, ByteCount, CanonicalPath,
    ClientIdentity, Command, DescriptionBackingSnapshot, DescriptionSnapshot, DescriptorFlags,
    FileDescriptionId, FileOffset, FileSlotNumber, FileTableId, NofileAllocationCeiling,
    ObjectGeneration, Outcome, Request, RequestId, Response, Revision, SeekWhence, SlotSnapshot,
    StatusFlags, VfsObjectId,
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
    let operation = command_tag(&request.command);
    let mut payload = Writer::default();
    encode_command(&mut payload, &request.command)?;
    encode_frame(
        Header {
            kind: REQUEST_KIND,
            operation,
            payload_len: payload.len_u32()?,
            fd_count: 0,
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
    let mut payload = Writer::default();
    payload.u64(response.authority_revision.raw());
    encode_outcome(&mut payload, &response.outcome)?;
    encode_frame(
        Header {
            kind: RESPONSE_KIND,
            operation: command_tag(&request.command),
            payload_len: payload.len_u32()?,
            fd_count: 0,
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
    if payload.len() != header.payload_len as usize || HEADER_LEN + payload.len() > MAX_FRAME_LEN {
        return malformed("frame exceeds its bound");
    }
    let mut writer = Writer::with_capacity(HEADER_LEN + payload.len());
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
    }
}

fn encode_command(writer: &mut Writer, command: &Command) -> Result<(), AuthorityFatal> {
    match command {
        Command::RegisterClient | Command::ExitClient | Command::CreateTable => {}
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
            .map_err(|_| AuthorityFatal::MalformedFrame("payload length overflow"))
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
                .map_err(|_| AuthorityFatal::MalformedFrame("blob length overflow"))?,
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
                .map_err(|_| AuthorityFatal::MalformedFrame("slot count overflow"))?,
        );
        for slot in slots {
            self.i32(slot.raw());
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
    fn slot(&mut self) -> Result<FileSlotNumber, AuthorityFatal> {
        FileSlotNumber::for_open_fd(self.i32()?)
            .map_err(|_| AuthorityFatal::MalformedFrame("invalid file slot"))
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
        let path = CanonicalPath::absolute("/all-variants").expect("path");
        let commands = vec![
            Command::RegisterClient,
            Command::ExitClient,
            Command::CreateTable,
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
            let encoded = encode_request(&request).expect("encode request");
            assert_eq!(
                decode_request(&encoded, 0).expect("decode request"),
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
            let encoded = encode_response(&request, &response).expect("encode response");
            assert_eq!(
                decode_response(&request, &encoded, 0).expect("decode response"),
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
