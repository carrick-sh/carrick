#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import pathlib
import unittest

VALIDATOR_PATH = pathlib.Path(__file__).with_name("validate-hvpatch-frame-cow.py")
SPEC = importlib.util.spec_from_file_location("hvpatch_frame_cow_validator", VALIDATOR_PATH)
assert SPEC is not None and SPEC.loader is not None
VALIDATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VALIDATOR)


def capture(
    *,
    phases: tuple[int, ...] = (0, 1, 2),
    drops: int = 0,
    bad_pte: bool = False,
    global_pte: bool = False,
    bad_copy: bool = False,
    cow_offset: int = 0,
    intent: int = 0,
    deferred_phase: int | None = None,
) -> bytes:
    lines = ["HVPATCHFRAMECOW3|header|version=3"]
    lines.extend(
        [
            "HVPATCHFRAMECOW3|vm|ts=1|host_pid=10|operation=0|admission=4|generation=0",
            "HVPATCHFRAMECOW3|vm|ts=2|host_pid=10|operation=1|admission=4|generation=1",
        ]
    )
    lines.append(
        "HVPATCHFRAMECOW3|stage2|ts=3|host_pid=10|vm=1|phase=0|ipa=a000000000|length=8000|host=12000000|perms=7"
    )
    lines.append(
        "HVPATCHFRAMECOW3|fork_frame|ts=4|host_pid=10|linux_pid=2|linux_tid=1|mm=2|asid=2|kind=0|parent_mapping=11|child_mapping=12|frame=21|ipa=a000000000|length=8000|identity=1"
    )
    lines.append(
        "HVPATCHFRAMECOW3|stage2|ts=5|host_pid=10|vm=1|phase=0|ipa=a000010000|length=4000|host=13000000|perms=7"
    )
    for phase in phases:
        lines.append(
            f"HVPATCHFRAMECOW3|event|ts={6 + phase}|host_pid=10|linux_pid=2|linux_tid=2|mm=2|asid=2|intent={intent}|phase={phase}|va=400000|old_frame=21|new_frame=22|old_ipa={0xA000000000 + cow_offset:x}|new_ipa=a000010000|identity=1"
        )
    source_hash = 0x1234
    dest_hash = source_hash ^ int(bad_copy)
    lines.append(
        f"HVPATCHFRAMECOW3|copy|ts=5|host_pid=10|old_frame=21|old_ipa={0xA000000000 + cow_offset:x}|source_hash={source_hash:x}|dest_hash={dest_hash:x}|length=16384"
    )
    non_global = 0 if global_pte else 1 << 11
    leaf0 = 0xA000000000 | non_global | 0xC0 | 3
    leaf2 = 0xA000010000 | non_global | 0x40 | 3
    if bad_pte:
        leaf2 = 0xA000008000 | 0x40 | 3
    lines.extend(
        [
            f"HVPATCHFRAMECOW3|pte|ts=4|host_pid=10|va=400000|leaf={leaf0:x}|expected_ipa=a000000000|expected_ap=c0|phase=0",
            f"HVPATCHFRAMECOW3|pte|ts=4|host_pid=11|va=400000|leaf={leaf0:x}|expected_ipa=a000000000|expected_ap=c0|phase=1",
        ]
    )
    if intent == 0:
        lines.append(
            f"HVPATCHFRAMECOW3|pte|ts=8|host_pid=11|va=400000|leaf={leaf2:x}|expected_ipa=a000010000|expected_ap=40|phase=2"
        )
    else:
        denied_leaf = 0xA000010000 | non_global | 0xC0
        lines.append(
            f"HVPATCHFRAMECOW3|pte|ts=9|host_pid=11|va=400000|leaf={denied_leaf:x}|expected_ipa=a000010000|expected_ap=c0|phase=3"
        )
        if deferred_phase is not None:
            published_leaf = leaf2 if deferred_phase == 4 else leaf0 + 0x10000
            lines.append(
                f"HVPATCHFRAMECOW3|pte|ts=10|host_pid=11|va=400000|leaf={published_leaf:x}|expected_ipa=a000010000|expected_ap={0x40 if deferred_phase == 4 else 0xc0:x}|phase={deferred_phase}"
            )
    lines.extend(
        [
            "HVPATCHFRAMECOW3|stage2|ts=11|host_pid=10|vm=1|phase=1|ipa=a000010000|length=4000|host=0|perms=0",
            "HVPATCHFRAMECOW3|stage2|ts=12|host_pid=10|vm=1|phase=1|ipa=a000000000|length=8000|host=0|perms=0",
            "HVPATCHFRAMECOW3|vm|ts=13|host_pid=10|operation=2|admission=-1|generation=1",
            "HVPATCHFRAMECOW3|vm|ts=14|host_pid=10|operation=3|admission=-1|generation=1",
        ]
    )
    lines.append(
        "HVPATCHFRAMECOW3|summary|"
        f"events={len(phases)}|identities={len(phases)}|intents={len(phases)}|fork_identities=1|fork_frames=1|stage2_maps=2|stage2_unmaps=2|vm_events=4|ptes={2 + (1 if intent == 0 else 1 + int(deferred_phase is not None))}|copies=1|"
        f"faults=1|fault_ptes=1|fault_ttbrs=1|errors=0|drops={drops}|bounded=0|target_exited=1"
    )
    return ("\n".join(lines) + "\n").encode()


class ValidatorTests(unittest.TestCase):
    def test_accepts_complete_ordered_receipt(self) -> None:
        receipt = VALIDATOR.validate(capture(), require_shared=False)
        self.assertEqual(receipt["status"], "validated")
        self.assertEqual(receipt["cow_transactions"], 1)

    def test_accepts_cow_page_inside_authenticated_fork_extent(self) -> None:
        receipt = VALIDATOR.validate(capture(cow_offset=0x4000), require_shared=False)
        self.assertEqual(receipt["status"], "validated")

    def test_accepts_backing_maintenance_with_denied_then_writable_pte(self) -> None:
        receipt = VALIDATOR.validate(
            capture(intent=1, deferred_phase=4), require_shared=False
        )
        self.assertEqual(receipt["backing_maintenance_transactions"], 1)

    def test_rejects_backing_maintenance_without_final_permission_publication(self) -> None:
        with self.assertRaises(VALIDATOR.ReceiptError):
            VALIDATOR.validate(capture(intent=1), require_shared=False)

    def test_rejects_missing_cow_phase(self) -> None:
        with self.assertRaises(VALIDATOR.ReceiptError):
            VALIDATOR.validate(capture(phases=(0, 2)), require_shared=False)

    def test_rejects_consumer_drop(self) -> None:
        with self.assertRaises(VALIDATOR.ReceiptError):
            VALIDATOR.validate(capture(drops=1), require_shared=False)

    def test_rejects_live_pte_expected_ipa_mismatch(self) -> None:
        with self.assertRaises(VALIDATOR.ReceiptError):
            VALIDATOR.validate(capture(bad_pte=True), require_shared=False)

    def test_rejects_global_per_mm_pte(self) -> None:
        with self.assertRaises(VALIDATOR.ReceiptError):
            VALIDATOR.validate(capture(global_pte=True), require_shared=False)

    def test_rejects_divergent_cow_copy(self) -> None:
        with self.assertRaises(VALIDATOR.ReceiptError):
            VALIDATOR.validate(capture(bad_copy=True), require_shared=False)

    def test_rejects_global_ipa_reuse_before_exact_unmap(self) -> None:
        raw = capture().decode()
        duplicate = (
            "HVPATCHFRAMECOW3|stage2|ts=8|host_pid=10|vm=1|phase=0|ipa=a000000000|"
            "length=4000|host=14000000|perms=7\n"
        )
        raw = raw.replace(
            "HVPATCHFRAMECOW3|stage2|ts=11|host_pid=10|vm=1|phase=1|ipa=a000010000",
            duplicate
            + "HVPATCHFRAMECOW3|stage2|ts=11|host_pid=10|vm=1|phase=1|ipa=a000010000",
        )
        raw = raw.replace("stage2_maps=2", "stage2_maps=3")
        with self.assertRaises(VALIDATOR.ReceiptError):
            VALIDATOR.validate(raw.encode(), require_shared=False)


if __name__ == "__main__":
    unittest.main()
