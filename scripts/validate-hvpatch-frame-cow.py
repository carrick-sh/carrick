#!/usr/bin/env python3
"""Fail-closed validator for scripts/dtrace/hvpatch-frame-cow.d output."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import sys
from collections import Counter, defaultdict

PREFIX = "HVPATCHFRAMECOW5|"
PA_MASK_4K = 0x0000_FFFF_FFFF_F000
AP_MASK = 0b11 << 6
COMPOUND_MASK = ~((16 * 1024) - 1)


class ReceiptError(ValueError):
    pass


def parse_number(value: str, *, hexadecimal: bool = False) -> int:
    try:
        return int(value, 16 if hexadecimal else 10)
    except ValueError as error:
        raise ReceiptError(f"invalid numeric field {value!r}") from error


def parse_record(line: str) -> tuple[str, dict[str, str]]:
    fields = line.rstrip("\n").split("|")
    if len(fields) < 3 or fields[0] != "HVPATCHFRAMECOW5":
        raise ReceiptError(f"malformed receipt record: {line.rstrip()!r}")
    values: dict[str, str] = {}
    for field in fields[2:]:
        if "=" not in field:
            raise ReceiptError(f"malformed receipt field {field!r}")
        key, value = field.split("=", 1)
        if not key or key in values:
            raise ReceiptError(f"empty or duplicate receipt key {key!r}")
        values[key] = value
    return fields[1], values


def require_keys(kind: str, values: dict[str, str], keys: set[str]) -> None:
    if set(values) != keys:
        raise ReceiptError(
            f"{kind} keys differ: missing={sorted(keys - set(values))} "
            f"extra={sorted(set(values) - keys)}"
        )


def terminal_descriptor(descriptors: tuple[int, int, int, int]) -> tuple[int, int]:
    """Return the first AArch64 stage-1 block/page (or invalid) descriptor."""
    for level, descriptor in enumerate(descriptors):
        if level < 3 and descriptor & 0b11 == 0b11:
            continue
        return descriptor, level
    return descriptors[3], 3


def validate(
    raw: bytes, *, require_shared: bool, require_permission_fault: bool = True
) -> dict[str, object]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ReceiptError("receipt is not UTF-8") from error

    records: list[tuple[str, dict[str, str]]] = []
    for line in text.splitlines():
        if line.startswith(PREFIX):
            records.append(parse_record(line))
    kinds = Counter(kind for kind, _ in records)
    if kinds["header"] != 1 or kinds["summary"] != 1:
        raise ReceiptError(
            f"receipt needs exactly one header and summary, got {dict(kinds)}"
        )

    header = next(values for kind, values in records if kind == "header")
    require_keys("header", header, {"version"})
    if header["version"] != "5":
        raise ReceiptError(f"unsupported receipt version {header['version']!r}")

    summary = next(values for kind, values in records if kind == "summary")
    summary_keys = {
        "events",
        "identities",
        "intents",
        "triggers",
        "trigger_identities",
        "permission_triggers",
        "fork_identities",
        "fork_frames",
        "stage2_maps",
        "stage2_unmaps",
        "vm_events",
        "ptes",
        "copies",
        "fault_sequences",
        "fault_ptes",
        "fault_ttbrs",
        "errors",
        "drops",
        "bounded",
        "target_exited",
    }
    require_keys("summary", summary, summary_keys)
    counts = {key: parse_number(value) for key, value in summary.items()}
    if counts["errors"] or counts["drops"] or counts["bounded"]:
        raise ReceiptError(f"capture reported an unsafe terminal state: {counts}")
    if counts["target_exited"] != 1:
        raise ReceiptError("target did not exit under the bounded trace consumer")
    if (
        counts["events"] != kinds["event"]
        or counts["ptes"] != kinds["pte"]
        or counts["copies"] != kinds["copy"]
    ):
        raise ReceiptError("summary event/PTE/copy counts do not match serialized records")
    if counts["fork_frames"] != kinds["fork_frame"]:
        raise ReceiptError("summary fork-frame count does not match serialized records")
    if counts["stage2_maps"] + counts["stage2_unmaps"] != kinds["stage2"]:
        raise ReceiptError("summary stage-2 counts do not match serialized records")
    if counts["vm_events"] != kinds["vm"]:
        raise ReceiptError("summary VM-lifecycle count does not match serialized records")
    if counts["triggers"] != kinds["trigger"]:
        raise ReceiptError("summary trigger count does not match serialized records")
    if counts["fault_ptes"] != kinds["fault_pte"]:
        raise ReceiptError("summary fault-PTE count does not match serialized records")
    if counts["fault_ttbrs"] != kinds["fault_ttbr"]:
        raise ReceiptError("summary fault-TTBR count does not match serialized records")
    if counts["identities"] != counts["events"]:
        raise ReceiptError("COW identity/data probes are missing or unbalanced")
    if counts["intents"] != counts["events"]:
        raise ReceiptError("COW intent/data probes are missing or unbalanced")
    if counts["fork_identities"] != counts["fork_frames"]:
        raise ReceiptError("fork-frame identity/data probes are missing or unbalanced")
    if counts["trigger_identities"] != counts["triggers"]:
        raise ReceiptError("COW trigger identity/data probes are missing or unbalanced")
    if not (
        counts["fault_sequences"]
        == counts["fault_ptes"]
        == counts["fault_ttbrs"]
        == counts["permission_triggers"]
    ):
        raise ReceiptError("permission-fault sequence/PTE/TTBR counts are unbalanced")
    if (
        not kinds["event"]
        or not kinds["fork_frame"]
        or not kinds["pte"]
        or not kinds["copy"]
        or not kinds["stage2"]
        or not kinds["vm"]
        or not kinds["trigger"]
    ):
        raise ReceiptError("zero COW, fork-frame, VM, stage-2, or PTE structural events")

    stage2_keys = {"ts", "host_pid", "vm", "phase", "ipa", "length", "host", "perms"}
    vm_keys = {"host_pid", "operation", "admission", "generation"}
    vm_keys.add("ts")
    current_vm: dict[int, tuple[int, bool]] = {}
    active_stage2: dict[tuple[int, int, int, int], tuple[int, int]] = {}
    stage2_lifetimes: list[tuple[int, int, int, int, int, int]] = []
    lifetime_records = sorted(
        (
            parse_number(values["ts"]),
            record_index,
            kind,
            values,
        )
        for record_index, (kind, values) in enumerate(records)
        if kind in ("vm", "stage2")
    )
    for timestamp, _record_index, kind, values in lifetime_records:
        if kind == "vm":
            require_keys(kind, values, vm_keys)
            host_pid = parse_number(values["host_pid"])
            operation = parse_number(values["operation"])
            parse_number(values["admission"])
            generation = parse_number(values["generation"])
            previous_generation, active = current_vm.get(host_pid, (0, False))
            if host_pid <= 0 or operation not in (0, 1, 2, 3):
                raise ReceiptError("invalid VM lifecycle identity or operation")
            if operation == 0:
                if active or generation != previous_generation:
                    raise ReceiptError("VM create attempt overlaps an active generation")
            elif operation == 1:
                if active or generation != previous_generation + 1:
                    raise ReceiptError("VM create success has invalid generation")
                current_vm[host_pid] = (generation, True)
            elif operation == 2:
                if not active or generation != previous_generation:
                    raise ReceiptError("VM destroy attempt has no matching active generation")
            else:
                if not active or generation != previous_generation:
                    raise ReceiptError("VM destroy success has no matching active generation")
                for key in [key for key in active_stage2 if key[:2] == (host_pid, generation)]:
                    mapped_at, _host = active_stage2.pop(key)
                    stage2_lifetimes.append((*key, mapped_at, timestamp))
                current_vm[host_pid] = (generation, False)
        elif kind == "stage2":
            require_keys(kind, values, stage2_keys)
            host_pid = parse_number(values["host_pid"])
            vm = parse_number(values["vm"])
            phase = parse_number(values["phase"])
            ipa = parse_number(values["ipa"], hexadecimal=True)
            length = parse_number(values["length"], hexadecimal=True)
            host = parse_number(values["host"], hexadecimal=True)
            perms = parse_number(values["perms"], hexadecimal=True)
            if not ipa or not length:
                raise ReceiptError("global-frame stage-2 extent is empty")
            if current_vm.get(host_pid) != (vm, True):
                raise ReceiptError("global-frame stage-2 edge has no active VM generation")
            key = (host_pid, vm, ipa, length)
            if phase == 0:
                if not host:
                    raise ReceiptError("global-frame stage-2 map lacks host backing")
                end = ipa + length
                if any(
                    existing_ipa < end and ipa < existing_ipa + existing_length
                    for existing_pid, existing_vm, existing_ipa, existing_length in active_stage2
                    if (existing_pid, existing_vm) == (host_pid, vm)
                ):
                    raise ReceiptError("global-frame stage-2 map overlaps a live extent")
                host_end = host + length
                if any(
                    existing_host < host_end
                    and host < existing_host + existing_length
                    for (
                        existing_pid,
                        existing_vm,
                        _existing_ipa,
                        existing_length,
                    ), (_mapped_at, existing_host) in active_stage2.items()
                    if (existing_pid, existing_vm) == (host_pid, vm)
                ):
                    raise ReceiptError(
                        "one live physical host extent is mapped at multiple global IPAs"
                    )
                active_stage2[key] = (timestamp, host)
            elif phase == 1:
                if host or perms:
                    raise ReceiptError("global-frame stage-2 unmap carries map provenance")
                if key not in active_stage2:
                    raise ReceiptError("global-frame stage-2 unmap has no exact live map")
                mapped_at, _mapped_host = active_stage2.pop(key)
                stage2_lifetimes.append((*key, mapped_at, timestamp))
            else:
                raise ReceiptError(f"unknown global-frame stage-2 phase {phase}")
    if active_stage2:
        raise ReceiptError("global-frame stage-2 extents remain live at target exit")

    def stage2_contains(timestamp: int, host_pid: int, ipa: int, length: int) -> bool:
        end = ipa + length
        return any(
            base <= ipa and end <= base + extent_length
            and mapped_at <= timestamp < unmapped_at
            for active_pid, _vm, base, extent_length, mapped_at, unmapped_at in stage2_lifetimes
            if active_pid == host_pid
        )

    fork_keys = {
        "ts",
        "host_pid",
        "linux_pid",
        "linux_tid",
        "mm",
        "asid",
        "kind",
        "parent_mapping",
        "child_mapping",
        "frame",
        "ipa",
        "length",
        "identity",
    }
    private_frame_extents: list[tuple[int, int, int]] = []
    shared_count = 0
    child_mappings: set[int] = set()
    for record_index, (kind, values) in enumerate(records):
        if kind != "fork_frame":
            continue
        require_keys(kind, values, fork_keys)
        decimal = {
            key: parse_number(values[key])
            for key in (
                "host_pid",
                "linux_pid",
                "linux_tid",
                "mm",
                "asid",
                "kind",
                "parent_mapping",
                "child_mapping",
                "frame",
                "identity",
            )
        }
        ipa = parse_number(values["ipa"], hexadecimal=True)
        length = parse_number(values["length"], hexadecimal=True)
        timestamp = parse_number(values["ts"])
        if any(decimal[key] <= 0 for key in ("linux_pid", "linux_tid", "mm", "asid")):
            raise ReceiptError(f"fork-frame identity is incomplete: {values}")
        if decimal["identity"] != 1:
            raise ReceiptError("fork-frame data was not paired with its identity probe")
        if decimal["parent_mapping"] == decimal["child_mapping"]:
            raise ReceiptError("parent and child must own distinct MappingIds")
        if decimal["child_mapping"] in child_mappings:
            raise ReceiptError("duplicate child MappingId in fork-frame receipt")
        child_mappings.add(decimal["child_mapping"])
        if not decimal["frame"] or not ipa or not length:
            raise ReceiptError("fork-frame physical identity is zero")
        if not stage2_contains(timestamp, decimal["host_pid"], ipa, length):
            raise ReceiptError("fork-frame identity lacks a live exact stage-2 extent")
        if decimal["kind"] == 0:
            private_frame_extents.append((decimal["frame"], ipa, ipa + length))
        elif decimal["kind"] == 1:
            shared_count += 1
        else:
            raise ReceiptError(f"unknown fork-frame kind {decimal['kind']}")
    if not private_frame_extents:
        raise ReceiptError("no inherited private COW frame was observed")
    if require_shared and shared_count == 0:
        raise ReceiptError("no inherited Linux-shared frame was observed")

    fault_pte_keys = {
        "ts",
        "host_pid",
        "host_tid",
        "seq",
        "va",
        "l0",
        "l1",
        "l2",
        "l3",
    }
    fault_ptes: dict[tuple[int, int, int], tuple[int, int, int, int]] = {}
    for kind, values in records:
        if kind != "fault_pte":
            continue
        require_keys(kind, values, fault_pte_keys)
        timestamp = parse_number(values["ts"])
        host_pid = parse_number(values["host_pid"])
        host_tid = parse_number(values["host_tid"])
        sequence = parse_number(values["seq"])
        va = parse_number(values["va"], hexadecimal=True)
        descriptors = tuple(
            parse_number(values[key], hexadecimal=True)
            for key in ("l0", "l1", "l2", "l3")
        )
        leaf, terminal_level = terminal_descriptor(descriptors)
        if min(host_pid, host_tid, sequence) <= 0:
            raise ReceiptError("fault-PTE record lacks host execution identity")
        key = (host_pid, host_tid, sequence)
        if key in fault_ptes:
            raise ReceiptError("duplicate fault-PTE attempt sequence")
        if not stage2_contains(timestamp, host_pid, leaf & PA_MASK_4K, 4 * 1024):
            raise ReceiptError("fault-PTE leaf lacks a live stage-2 lifetime")
        fault_ptes[key] = (timestamp, va, leaf, terminal_level)

    fault_ttbr_keys = {"ts", "host_pid", "host_tid", "seq", "va", "ttbr0"}
    fault_ttbrs: dict[tuple[int, int, int], tuple[int, int, int]] = {}
    for kind, values in records:
        if kind != "fault_ttbr":
            continue
        require_keys(kind, values, fault_ttbr_keys)
        timestamp = parse_number(values["ts"])
        host_pid = parse_number(values["host_pid"])
        host_tid = parse_number(values["host_tid"])
        sequence = parse_number(values["seq"])
        va = parse_number(values["va"], hexadecimal=True)
        ttbr0 = parse_number(values["ttbr0"], hexadecimal=True)
        if min(host_pid, host_tid, sequence) <= 0 or ttbr0 == 0:
            raise ReceiptError("fault-TTBR record lacks host execution identity or TTBR0")
        key = (host_pid, host_tid, sequence)
        if key in fault_ttbrs:
            raise ReceiptError("duplicate fault-TTBR attempt sequence")
        fault_ttbrs[key] = (timestamp, va, ttbr0)

    trigger_keys = {
        "ts",
        "host_pid",
        "host_tid",
        "linux_pid",
        "linux_tid",
        "mm",
        "asid",
        "class",
        "fault_seq",
        "va",
        "syndrome",
        "far",
        "ttbr0",
        "identity",
    }
    triggers: list[dict[str, int]] = []
    permission_trigger_count = 0
    for kind, values in records:
        if kind != "trigger":
            continue
        require_keys(kind, values, trigger_keys)
        trigger = {
            "ts": parse_number(values["ts"]),
            "host_pid": parse_number(values["host_pid"]),
            "host_tid": parse_number(values["host_tid"]),
            "linux_pid": parse_number(values["linux_pid"]),
            "linux_tid": parse_number(values["linux_tid"]),
            "mm": parse_number(values["mm"]),
            "asid": parse_number(values["asid"]),
            "class": parse_number(values["class"]),
            "fault_seq": parse_number(values["fault_seq"]),
            "va": parse_number(values["va"], hexadecimal=True),
            "syndrome": parse_number(values["syndrome"], hexadecimal=True),
            "far": parse_number(values["far"], hexadecimal=True),
            "ttbr0": parse_number(values["ttbr0"], hexadecimal=True),
            "identity": parse_number(values["identity"]),
        }
        if any(
            trigger[key] <= 0
            for key in (
                "host_pid",
                "host_tid",
                "linux_pid",
                "linux_tid",
                "mm",
                "asid",
                "identity",
            )
        ):
            raise ReceiptError("COW trigger identity is incomplete")
        if trigger["class"] not in (0, 1, 2, 3):
            raise ReceiptError("unknown COW trigger class")
        if trigger["class"] == 0:
            permission_trigger_count += 1
            if trigger["fault_seq"] <= 0:
                raise ReceiptError("permission COW trigger lacks a fault attempt sequence")
            syndrome = trigger["syndrome"]
            exception_class = (syndrome >> 26) & 0x3F
            fault_status = syndrome & 0x3F
            if (
                exception_class not in (0x24, 0x25)
                or syndrome & (1 << 6) == 0
                or fault_status not in range(0x0D, 0x10)
            ):
                raise ReceiptError("COW permission trigger is not a write-permission abort")
            stripped_far = trigger["far"] & ((1 << 56) - 1)
            if stripped_far & ~0xFFF != trigger["va"]:
                raise ReceiptError("COW permission trigger VA does not match FAR")
            if trigger["ttbr0"] >> 48 != trigger["asid"]:
                raise ReceiptError("COW permission trigger TTBR0 does not encode its ASID")
            fault_key = (
                trigger["host_pid"],
                trigger["host_tid"],
                trigger["fault_seq"],
            )
            matching_pte = fault_ptes.get(fault_key)
            matching_ttbr = fault_ttbrs.get(fault_key)
            if matching_pte is None or matching_ttbr is None:
                raise ReceiptError("COW permission trigger lacks its exact fault sequence")
            pte_ts, pte_va, leaf, terminal_level = matching_pte
            ttbr_ts, ttbr_va, fault_ttbr = matching_ttbr
            if not pte_ts <= ttbr_ts <= trigger["ts"]:
                raise ReceiptError("COW fault sequence is temporally out of order")
            if pte_va != trigger["far"] or ttbr_va != trigger["far"]:
                raise ReceiptError("COW fault sequence VA does not match trigger FAR")
            if fault_ttbr != trigger["ttbr0"]:
                raise ReceiptError("COW fault sequence TTBR does not match trigger TTBR")
            valid_terminal = (
                terminal_level == 3 and leaf & 0b11 == 0b11
            ) or (
                terminal_level in (1, 2) and leaf & 0b11 == 0b01
            )
            if (
                not valid_terminal
                or leaf & AP_MASK not in (0b10 << 6, 0b11 << 6)
                or leaf & (1 << 11) == 0
            ):
                raise ReceiptError(
                    "COW permission trigger PTE is not a valid non-global read-only leaf"
                )
            trigger["fault_leaf"] = leaf
        elif trigger["fault_seq"] or trigger["syndrome"] or trigger["ttbr0"]:
            raise ReceiptError("non-fault COW trigger carries fault-only provenance")
        triggers.append(trigger)
    if require_permission_fault and permission_trigger_count == 0:
        raise ReceiptError("no guest stage-1 permission-fault COW trigger was observed")
    if counts["permission_triggers"] != permission_trigger_count:
        raise ReceiptError("summary permission-trigger count does not match records")
    consumed_faults = {
        (trigger["host_pid"], trigger["host_tid"], trigger["fault_seq"])
        for trigger in triggers
        if trigger["class"] == 0
    }
    if len(consumed_faults) != permission_trigger_count:
        raise ReceiptError("a fault attempt sequence was consumed by multiple triggers")
    if consumed_faults != set(fault_ptes) or consumed_faults != set(fault_ttbrs):
        raise ReceiptError("fault PTE/TTBR records were not consumed one-for-one")

    event_keys = {
        "ts",
        "host_pid",
        "linux_pid",
        "linux_tid",
        "mm",
        "asid",
        "intent",
        "phase",
        "va",
        "old_frame",
        "new_frame",
        "old_ipa",
        "new_ipa",
        "identity",
    }
    transactions: dict[tuple[int, ...], list[tuple[int, int]]] = defaultdict(list)
    for record_index, (kind, values) in enumerate(records):
        if kind != "event":
            continue
        require_keys(kind, values, event_keys)
        host_pid = parse_number(values["host_pid"])
        timestamp = parse_number(values["ts"])
        pid = parse_number(values["linux_pid"])
        tid = parse_number(values["linux_tid"])
        mm = parse_number(values["mm"])
        asid = parse_number(values["asid"])
        intent = parse_number(values["intent"])
        phase = parse_number(values["phase"])
        va = parse_number(values["va"], hexadecimal=True)
        old_frame = parse_number(values["old_frame"])
        new_frame = parse_number(values["new_frame"])
        old_ipa = parse_number(values["old_ipa"], hexadecimal=True)
        new_ipa = parse_number(values["new_ipa"], hexadecimal=True)
        identity = parse_number(values["identity"])
        if min(host_pid, pid, tid, mm, asid, identity) <= 0:
            raise ReceiptError(f"COW event identity is incomplete: {values}")
        if intent not in (0, 1, 2):
            raise ReceiptError(f"unknown COW write intent {intent}")
        if old_frame == new_frame or old_ipa == new_ipa:
            raise ReceiptError("writer COW did not change both FrameId and global IPA")
        # The source must remain live through stage-1 publication (phases 0/1).
        # Exact-last-reference retirement intentionally occurs between that
        # publication and the terminal committed receipt (phase 2).
        if phase in (0, 1) and not stage2_contains(
            timestamp, host_pid, old_ipa, 16 * 1024
        ):
            raise ReceiptError("COW source IPA is not live in stage-2")
        if not stage2_contains(timestamp, host_pid, new_ipa, 16 * 1024):
            raise ReceiptError("COW destination IPA is not live in stage-2")
        if not any(
            frame == old_frame and start <= old_ipa and old_ipa + 16 * 1024 <= end
            for frame, start, end in private_frame_extents
        ):
            raise ReceiptError("COW old frame/IPA was not authenticated at fork")
        key = (pid, tid, mm, asid, intent, va, old_frame, new_frame, old_ipa, new_ipa)
        transactions[key].append((timestamp, phase))
    for key, observed in transactions.items():
        phases = [phase for _timestamp, phase in sorted(observed)]
        if phases != [0, 1, 2]:
            raise ReceiptError(f"COW phases are missing, duplicate, or out of order: {key} {phases}")

    winner_counts: Counter[tuple[int, int, int, int, int]] = Counter(
        (key[2], key[3], key[5] & COMPOUND_MASK, key[6], key[8])
        for key in transactions
    )
    if any(count != 1 for count in winner_counts.values()):
        raise ReceiptError("more than one COW winner exists for an mm/frame generation")

    triggered_transactions: Counter[tuple[int, ...]] = Counter()
    trigger_intent = {0: 0, 1: 0, 2: 1, 3: 2}
    for trigger in triggers:
        candidates = [
            key
            for key, observed in transactions.items()
            if key[0] == trigger["linux_pid"]
            and key[1] == trigger["linux_tid"]
            and key[2] == trigger["mm"]
            and key[3] == trigger["asid"]
            and key[4] == trigger_intent[trigger["class"]]
            and key[5] == trigger["va"]
            and trigger["ts"] <= min(timestamp for timestamp, _phase in observed)
        ]
        next_timestamp = min(
            (
                min(timestamp for timestamp, _phase in transactions[key])
                for key in candidates
            ),
            default=None,
        )
        matches = [
            key
            for key in candidates
            if min(timestamp for timestamp, _phase in transactions[key]) == next_timestamp
        ]
        if len(matches) != 1:
            raise ReceiptError(
                "COW trigger does not join one exact committed transaction: "
                f"pid={trigger['linux_pid']} tid={trigger['linux_tid']} "
                f"mm={trigger['mm']} asid={trigger['asid']} class={trigger['class']} "
                f"va=0x{trigger['va']:x} matches={len(matches)}"
            )
        transaction = matches[0]
        triggered_transactions[transaction] += 1
        if trigger["class"] == 0:
            leaf_ipa = trigger["fault_leaf"] & PA_MASK_4K
            if not any(
                frame == transaction[6] and start <= leaf_ipa < end
                for frame, start, end in private_frame_extents
            ):
                raise ReceiptError(
                    "permission-fault PTE does not name the authenticated inherited frame"
                )
    if set(triggered_transactions) != set(transactions) or any(
        count != 1 for count in triggered_transactions.values()
    ):
        raise ReceiptError("each committed COW transaction needs one exact trigger")

    copy_keys = {
        "ts",
        "host_pid",
        "old_frame",
        "old_ipa",
        "source_hash",
        "dest_hash",
        "length",
    }
    copy_sources: Counter[tuple[int, int]] = Counter()
    transaction_sources: Counter[tuple[int, int]] = Counter(
        (key[6], key[8]) for key in transactions
    )
    old_frame_hashes: dict[tuple[int, int], set[int]] = defaultdict(set)
    for kind, values in records:
        if kind != "copy":
            continue
        require_keys(kind, values, copy_keys)
        parse_number(values["ts"])
        parse_number(values["host_pid"])
        old_frame = parse_number(values["old_frame"])
        old_ipa = parse_number(values["old_ipa"], hexadecimal=True)
        source_hash = parse_number(values["source_hash"], hexadecimal=True)
        dest_hash = parse_number(values["dest_hash"], hexadecimal=True)
        length = parse_number(values["length"])
        if source_hash != dest_hash or length != 16 * 1024:
            raise ReceiptError("COW byte copy is incomplete or content-divergent")
        source = (old_frame, old_ipa)
        copy_sources[source] += 1
        old_frame_hashes[source].add(source_hash)
    if copy_sources != transaction_sources:
        raise ReceiptError(
            f"COW byte-copy receipts do not pair one-for-one with transactions: "
            f"copies={copy_sources} transactions={transaction_sources}"
        )
    if any(len(hashes) != 1 for hashes in old_frame_hashes.values()):
        raise ReceiptError("a shared old frame changed between child and parent COW copies")

    pte_keys = {
        "ts",
        "host_pid",
        "va",
        "leaf",
        "expected_ipa",
        "expected_ap",
        "phase",
    }
    non_global = 1 << 11
    ptes_by_phase: dict[int, set[tuple[int, int]]] = defaultdict(set)
    pte_records_by_phase: dict[int, list[tuple[int, int, int, int]]] = defaultdict(list)
    for kind, values in records:
        if kind != "pte":
            continue
        require_keys(kind, values, pte_keys)
        timestamp = parse_number(values["ts"])
        parse_number(values["host_pid"])
        va = parse_number(values["va"], hexadecimal=True)
        leaf = parse_number(values["leaf"], hexadecimal=True)
        expected_ipa = parse_number(values["expected_ipa"], hexadecimal=True)
        expected_ap = parse_number(values["expected_ap"], hexadecimal=True)
        phase = parse_number(values["phase"])
        if phase not in (0, 1, 2, 3, 4, 5, 6):
            raise ReceiptError(f"unknown PTE receipt phase {phase}")
        if leaf & PA_MASK_4K != expected_ipa & PA_MASK_4K:
            raise ReceiptError("live PTE does not name the independently expected IPA")
        if leaf & AP_MASK != expected_ap:
            raise ReceiptError("live PTE AP bits do not match the independently expected AP")
        if leaf & non_global == 0:
            raise ReceiptError(
                "per-mm live PTE is global; ASID cannot isolate same-VA fork translations"
            )
        ptes_by_phase[phase].add((va, expected_ipa))
        pte_records_by_phase[phase].append(
            (timestamp, va, expected_ipa & COMPOUND_MASK, leaf)
        )
        if phase in (2, 4, 5) and leaf & 0b11 != 0b11:
            raise ReceiptError("published accessible PTE receipt is not a valid page")
        if phase == 6 and leaf & 1:
            raise ReceiptError("published inaccessible PTE receipt remained valid")
    if not all(ptes_by_phase[phase] for phase in (0, 1)):
        raise ReceiptError("missing parent-arm or child-inherit PTE receipt")
    if not (ptes_by_phase[0] & ptes_by_phase[1]):
        raise ReceiptError("parent and child did not serialize a same-VA/same-IPA prewrite leaf")

    guest_visible_transactions = 0
    backing_maintenance_transactions = 0
    privileged_internal_transactions = 0
    for key, observed in transactions.items():
        intent = key[4]
        va = key[5]
        new_ipa = key[9] & COMPOUND_MASK
        committed_at = max(timestamp for timestamp, phase in observed if phase == 2)

        def matching(phase: int, *, after: int = 0) -> list[tuple[int, int, int, int]]:
            return [
                record
                for record in pte_records_by_phase[phase]
                if record[0] >= after and record[1] == va and record[2] == new_ipa
            ]

        if intent == 0:
            guest_visible_transactions += 1
            if not matching(2):
                raise ReceiptError(
                    "a committed guest-visible COW global IPA lacks an authenticated writer PTE"
                )
        elif intent == 1:
            backing_maintenance_transactions += 1
            denied = matching(3, after=committed_at)
            if not denied or all(leaf & 1 for _ts, _va, _ipa, leaf in denied):
                raise ReceiptError(
                    "backing-maintenance COW lacks a committed preserved-invalid PTE"
                )
            denied_at = min(timestamp for timestamp, _va, _ipa, _leaf in denied)
            if not any(matching(phase, after=denied_at) for phase in (4, 5, 6)):
                raise ReceiptError(
                    "backing-maintenance COW lacks later authenticated permission publication"
                )
        else:
            privileged_internal_transactions += 1
            if not matching(3, after=committed_at):
                raise ReceiptError(
                    "privileged-internal COW lacks authenticated protection preservation"
                )

    return {
        "schema": "carrick.hvpatch-frame-cow-receipt.v5",
        "raw_sha256": hashlib.sha256(raw).hexdigest(),
        "cow_transactions": len(transactions),
        "guest_visible_transactions": guest_visible_transactions,
        "backing_maintenance_transactions": backing_maintenance_transactions,
        "privileged_internal_transactions": privileged_internal_transactions,
        "private_fork_frames": len(private_frame_extents),
        "shared_fork_frames": shared_count,
        "stage2_maps": counts["stage2_maps"],
        "stage2_unmaps": counts["stage2_unmaps"],
        "pte_receipts": kinds["pte"],
        "status": "validated",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("capture", type=pathlib.Path)
    parser.add_argument("--require-shared", action="store_true")
    parser.add_argument("--output", type=pathlib.Path)
    args = parser.parse_args()
    try:
        receipt = validate(args.capture.read_bytes(), require_shared=args.require_shared)
    except (OSError, ReceiptError) as error:
        print(f"hvpatch-frame-cow receipt rejected: {error}", file=sys.stderr)
        return 1
    rendered = json.dumps(receipt, sort_keys=True) + "\n"
    if args.output is not None:
        args.output.write_text(rendered, encoding="utf-8")
    sys.stdout.write(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
