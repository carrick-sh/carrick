"""Pure validated reader/exporter for Carrick's pending-translation core ABI."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
import struct
import tempfile
from typing import Callable


ROOT_MAGIC = b"CXLATP1\0"
UNIT_MAGIC = b"CXLATU1\0"
CHUNK_MAGIC = b"CXLATC1\0"
EXPORT_MAGIC = b"CXLATE1\0"
SCHEMA = 1
ROOT_LEN = 56
UNIT_LEN = 96
CHUNK_LEN = 1312
RECORD_LEN = 80
RECORDS_PER_CHUNK = 16
MAX_UNITS = 1 << 16
MAX_KEY_BYTES = 1 << 20
MAX_CODE_BYTES = 64 * 1024 * 1024
MAX_METADATA_BYTES = 256 * 1024 * 1024
MAX_EXPORTED_RECORDS = 1 << 20
MAX_USER_POINTER = 0x0000_FFFF_FFFF_FFFF


class PendingReadError(RuntimeError):
    pass


class MemoryReadError(PendingReadError):
    def __init__(self, address: int, length: int, reason: str):
        self.address = address
        self.length = length
        super().__init__(f"read {length} bytes at {address:#x}: {reason}")


@dataclass(frozen=True)
class PendingExport:
    summary: dict
    binary: bytes


def _pointer(value: int, name: str, *, aligned: bool = False) -> int:
    if value == 0 or value > MAX_USER_POINTER or (aligned and value % 8 != 0):
        raise PendingReadError(f"invalid {name} pointer {value:#x}")
    return value


def _read(read_memory: Callable[[int, int], bytes], address: int, length: int) -> bytes:
    try:
        data = read_memory(address, length)
    except MemoryReadError:
        raise
    except Exception as error:
        raise MemoryReadError(address, length, str(error)) from error
    if len(data) != length:
        raise MemoryReadError(address, length, f"short read: {len(data)} bytes")
    return bytes(data)


def _header(data: bytes, magic: bytes, expected_len: int, name: str) -> None:
    actual_magic, schema, encoded_len = struct.unpack_from("<8sII", data)
    if actual_magic != magic:
        raise PendingReadError(f"bad {name} magic {actual_magic!r}")
    if schema != SCHEMA:
        raise PendingReadError(f"bad {name} schema {schema}")
    if encoded_len != expected_len:
        raise PendingReadError(f"bad {name} length {encoded_len}, expected {expected_len}")


def read_pending(
    read_memory: Callable[[int, int], bytes],
    root_address: int,
    *,
    source_identity: str,
    mach_o_uuid: str,
    executable_sha256: str,
) -> PendingExport:
    """Read the release-committed prefix from a stopped live target or core."""
    try:
        root = _read(read_memory, root_address, ROOT_LEN)
    except MemoryReadError as error:
        raise PendingReadError(
            "pending-translation root is unreadable; a stack-only core is insufficient. "
            "Capture a modified-memory or full core and retry"
        ) from error
    _header(root, ROOT_MAGIC, ROOT_LEN, "root")
    pid = struct.unpack_from("<i", root, 16)[0]
    incarnation_hi, incarnation_lo, first_unit, committed_units = struct.unpack_from(
        "<QQQQ", root, 24
    )
    if committed_units > MAX_UNITS:
        raise PendingReadError(f"root committed unit count {committed_units} exceeds limit")
    if committed_units and not first_unit:
        raise PendingReadError("root has committed units but a null first-unit pointer")
    if first_unit:
        _pointer(first_unit, "first-unit", aligned=True)

    complete = True
    first_unreadable = None
    units = []
    binary_records = []
    unit_address = first_unit
    visited_units = set()
    for unit_index in range(committed_units):
        if unit_address in visited_units:
            raise PendingReadError("pending unit list contains a pointer cycle")
        visited_units.add(unit_address)
        try:
            unit = _read(read_memory, _pointer(unit_address, "unit", aligned=True), UNIT_LEN)
        except MemoryReadError as error:
            complete, first_unreadable = False, error.address
            break
        _header(unit, UNIT_MAGIC, UNIT_LEN, "unit")
        key_ptr, key_len, segment_start, segment_end = struct.unpack_from("<QQQQ", unit, 16)
        claim_state, owner_pid = struct.unpack_from("<Ii", unit, 48)
        owner_hi, owner_lo, first_chunk, committed_chunks, next_unit = struct.unpack_from(
            "<QQQQQ", unit, 56
        )
        if claim_state != 3:
            raise PendingReadError(f"unit {unit_index} is not in ClaimWon state")
        if (owner_pid, owner_hi, owner_lo) != (pid, incarnation_hi, incarnation_lo):
            raise PendingReadError(f"unit {unit_index} owner does not match root")
        if segment_end <= segment_start:
            raise PendingReadError(f"unit {unit_index} has an empty segment")
        if key_len == 0 or key_len > MAX_KEY_BYTES:
            raise PendingReadError(f"unit {unit_index} has invalid key length {key_len}")
        if committed_chunks == 0 or committed_chunks > MAX_UNITS:
            raise PendingReadError(f"unit {unit_index} has invalid chunk count {committed_chunks}")
        try:
            key = _read(read_memory, _pointer(key_ptr, "key"), key_len)
        except MemoryReadError as error:
            complete, first_unreadable = False, error.address
            break
        unit_summary = {
            "key_sha256": hashlib.sha256(key).hexdigest(),
            "key_hex": key.hex(),
            "segment_start": hex(segment_start),
            "segment_end": hex(segment_end),
            "records": [],
        }
        chunk_address = first_chunk
        unit_complete = True
        visited_chunks = set()
        for chunk_index in range(committed_chunks):
            if chunk_address in visited_chunks:
                raise PendingReadError("pending chunk list contains a pointer cycle")
            visited_chunks.add(chunk_address)
            try:
                chunk = _read(
                    read_memory,
                    _pointer(chunk_address, "chunk", aligned=True),
                    CHUNK_LEN,
                )
            except MemoryReadError as error:
                complete, unit_complete, first_unreadable = False, False, error.address
                break
            _header(chunk, CHUNK_MAGIC, CHUNK_LEN, "chunk")
            next_chunk, committed_records, capacity = struct.unpack_from("<QII", chunk, 16)
            if capacity != RECORDS_PER_CHUNK or committed_records > capacity:
                raise PendingReadError(
                    f"unit {unit_index} chunk {chunk_index} has invalid committed/capacity count"
                )
            if len(binary_records) + committed_records > MAX_EXPORTED_RECORDS:
                raise PendingReadError("pending record count exceeds diagnostic limit")
            for record_index in range(committed_records):
                offset = 32 + record_index * RECORD_LEN
                (
                    guest_start,
                    source_end,
                    generation,
                    flags,
                    reserved,
                    code_ptr,
                    code_len,
                    hot_ptr,
                    hot_len,
                    cold_ptr,
                    cold_len,
                ) = struct.unpack_from("<QQQIIQQQQQQ", chunk, offset)
                if reserved != 0 or flags & ~1:
                    raise PendingReadError("record has unknown flags or nonzero reserved field")
                if generation != 0:
                    raise PendingReadError("record generation is not INITIAL")
                if not (segment_start <= guest_start < source_end <= segment_end):
                    raise PendingReadError("record source extent lies outside its unit")
                if code_len == 0 or code_len > MAX_CODE_BYTES or code_len % 4:
                    raise PendingReadError(f"record has invalid code length {code_len}")
                if hot_len + cold_len > MAX_METADATA_BYTES:
                    raise PendingReadError("record metadata exceeds diagnostic limit")
                try:
                    code = _read(read_memory, _pointer(code_ptr, "code"), code_len)
                    hot = _read(read_memory, _pointer(hot_ptr, "hot"), hot_len) if hot_len else b""
                    cold = (
                        _read(read_memory, _pointer(cold_ptr, "cold"), cold_len)
                        if cold_len
                        else b""
                    )
                except MemoryReadError as error:
                    complete, unit_complete, first_unreadable = False, False, error.address
                    break
                binary_records.append((guest_start, source_end, generation, flags, code, hot, cold))
                unit_summary["records"].append({
                    "guest_start": hex(guest_start),
                    "source_end": hex(source_end),
                    "generation": generation,
                    "sensitive": bool(flags & 1),
                    "code_sha256": hashlib.sha256(code).hexdigest(),
                    "hot_sha256": hashlib.sha256(hot).hexdigest(),
                    "cold_sha256": hashlib.sha256(cold).hexdigest(),
                })
            if not unit_complete:
                break
            if chunk_index + 1 < committed_chunks:
                chunk_address = _pointer(next_chunk, "next-chunk", aligned=True)
            elif next_chunk != 0:
                raise PendingReadError("last committed chunk has a non-null next pointer")
        units.append(unit_summary)
        if not unit_complete:
            break
        if unit_index + 1 < committed_units:
            unit_address = _pointer(next_unit, "next-unit", aligned=True)
        elif next_unit != 0:
            raise PendingReadError("last committed unit has a non-null next pointer")

    binary = bytearray(struct.pack("<8sII", EXPORT_MAGIC, SCHEMA, len(binary_records)))
    for guest_start, source_end, generation, flags, code, hot, cold in binary_records:
        binary.extend(
            struct.pack(
                "<QQQIIQQQ",
                guest_start,
                source_end,
                generation,
                flags,
                0,
                len(code),
                len(hot),
                len(cold),
            )
        )
        binary.extend(code)
        binary.extend(hot)
        binary.extend(cold)
    binary = bytes(binary)
    summary = {
        "schema": "carrick.xlat-pending-export.v1",
        "complete": complete,
        "first_unreadable_address": hex(first_unreadable) if first_unreadable else None,
        "pid": pid,
        "incarnation": f"{incarnation_hi:016x}{incarnation_lo:016x}",
        "source_identity": source_identity,
        "mach_o_uuid": mach_o_uuid,
        "executable_sha256": executable_sha256,
        "units": units,
        "record_count": len(binary_records),
        "binary_len": len(binary),
        "binary_sha256": hashlib.sha256(binary).hexdigest(),
    }
    return PendingExport(summary=summary, binary=binary)


def _atomic_write(path: str, data: bytes) -> None:
    directory = os.path.dirname(os.path.abspath(path))
    descriptor, temporary = tempfile.mkstemp(prefix=f".{os.path.basename(path)}.", suffix=".tmp", dir=directory)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
        directory_fd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def write_export(export: PendingExport, output_base: str) -> tuple[str, str]:
    if not os.path.isabs(output_base) or not os.path.basename(output_base):
        raise ValueError("output base must be an absolute path with a nonempty stem")
    parent = os.path.dirname(output_base)
    if not os.path.isdir(parent):
        raise ValueError(f"output parent does not exist: {parent}")
    json_path = output_base + ".json"
    binary_path = output_base + ".bin"
    _atomic_write(binary_path, export.binary)
    encoded = (json.dumps(export.summary, indent=2, sort_keys=True) + "\n").encode("utf-8")
    _atomic_write(json_path, encoded)
    return json_path, binary_path
