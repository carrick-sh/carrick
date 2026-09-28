#!/usr/bin/env python3
"""Unit tests for the pure helpers in carrick_lldb.py."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import types
import unittest


def _load_plugin():
    fake_lldb = types.ModuleType("lldb")
    setattr(fake_lldb, "LLDB_INVALID_ADDRESS", (1 << 64) - 1)
    sys.modules.setdefault("lldb", fake_lldb)
    path = Path(__file__).with_name("carrick_lldb.py")
    spec = importlib.util.spec_from_file_location("carrick_lldb_under_test", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


PLUGIN = _load_plugin()


class CarrickLldbHelperTests(unittest.TestCase):
    def test_guest_thread_identity_accepts_process_aware_name(self):
        self.assertEqual(
            PLUGIN._guest_thread_identity("guest-pid-123-tid-456"),
            (123, 456),
        )

    def test_guest_thread_identity_treats_process_leader_tid_as_pid(self):
        self.assertEqual(PLUGIN._guest_thread_identity("guest-pid-123"), (123, 123))

    def test_guest_thread_identity_preserves_legacy_unowned_tid(self):
        self.assertEqual(PLUGIN._guest_thread_identity("guest-tid-456"), (None, 456))

    def test_guest_thread_identity_rejects_unrelated_host_thread(self):
        self.assertIsNone(PLUGIN._guest_thread_identity("carrick-eventring"))

    def test_eventring_default_is_a_concise_tail(self):
        self.assertEqual(PLUGIN._EVENTRING_DEFAULT_COUNT, 128)
        self.assertEqual(PLUGIN._EVENTRING_SLOT_BYTES, 24)
        self.assertLess(PLUGIN._EVENTRING_DEFAULT_COUNT, PLUGIN._EVENTRING_N)

    def test_eventring_generation_validation_reports_every_failure_shape(self):
        logical = 51
        complete = PLUGIN._eventring_complete_generation(logical)
        self.assertIsNone(PLUGIN._eventring_slot_error(logical, complete, complete))
        self.assertEqual(
            PLUGIN._eventring_slot_error(logical, complete - 1, complete - 1),
            f"BUSY generation={complete - 1}",
        )
        self.assertEqual(
            PLUGIN._eventring_slot_error(logical, 0, 0),
            f"GAP expected_gen={complete} observed_gen=0",
        )
        self.assertEqual(
            PLUGIN._eventring_slot_error(logical, complete + 2, complete + 2),
            f"OVERWRITTEN expected_gen={complete} observed_gen={complete + 2}",
        )
        self.assertEqual(
            PLUGIN._eventring_slot_error(logical, complete, complete + 2),
            f"TORN before_gen={complete} after_gen={complete + 2}",
        )

        high = 1 << 63
        high_generation = PLUGIN._eventring_complete_generation(high)
        self.assertIsNone(
            PLUGIN._eventring_slot_error(high, high_generation, high_generation)
        )
        self.assertGreater(
            PLUGIN._eventring_complete_generation((1 << 64) - 1),
            high_generation,
        )

    def test_eventring_formats_futex_lifecycle_with_full_width_address(self):
        low = 0x89ABCDEF
        high = 0x00000137
        address = 0x0000013789ABCDEF

        self.assertEqual(
            PLUGIN._EVENTRING_KINDS[23][1](low, high, 53664),
            f"addr={address:#018x} tid=53664",
        )
        self.assertEqual(
            PLUGIN._EVENTRING_KINDS[24][1](low, high, 3),
            f"addr={address:#018x} woken=3",
        )
        self.assertEqual(
            PLUGIN._EVENTRING_KINDS[25][1](low, high, 2),
            f"addr={address:#018x} outcome=timed-out",
        )

    def test_eventring_formats_hvpatch_thread_teardown_phase(self):
        self.assertEqual(
            PLUGIN._EVENTRING_KINDS[26][1](56172, 56099, 3),
            "pid=56172 tid=56099 phase=kicker-unregistered",
        )

    def test_eventring_formats_hvpatch_wait_lifecycle(self):
        detail = 3 | (1 << 8) | (2 << 16)
        self.assertEqual(
            PLUGIN._EVENTRING_KINDS[27][1](57499, 57520, detail),
            "pid=57499 tid=57520 wait=poll phase=begin fds=2",
        )
        futex_detail = 7 | (1 << 8)
        self.assertEqual(
            PLUGIN._EVENTRING_KINDS[27][1](57499, 57520, futex_detail),
            "pid=57499 tid=57520 wait=futex phase=begin fds=0",
        )

    def test_eventring_formats_correlated_hvpatch_wait_snapshot(self):
        wait_id = 0x123456
        detail = wait_id | (3 << 24) | (1 << 28)
        self.assertEqual(
            PLUGIN._EVENTRING_KINDS[28][1](57499, 57520, detail),
            "pid=57499 tid=57520 id=0x123456 wait=poll phase=begin",
        )
        self.assertEqual(
            PLUGIN._EVENTRING_KINDS[29][1](0x12345678, 0x40, wait_id),
            "id=0x123456 pc=0x0000004012345678",
        )
        self.assertEqual(
            PLUGIN._EVENTRING_KINDS[30][1](0x89ABCDEF, 0x7F, wait_id),
            "id=0x123456 sp=0x0000007f89abcdef",
        )
        self.assertEqual(
            PLUGIN._EVENTRING_KINDS[31][1](0xDEADBEEF, 0x40, wait_id),
            "id=0x123456 lr=0x00000040deadbeef",
        )
        self.assertEqual(
            PLUGIN._EVENTRING_KINDS[32][1](wait_id, 16408, 1),
            "id=0x123456 fd=16408 events=0x1",
        )

    def test_eventring_formats_hvpatch_process_exit_publication(self):
        self.assertEqual(
            PLUGIN._EVENTRING_KINDS[33][1](62809, 62809, 0),
            "pid=62809 tid=62809 exit=0 publication=begin",
        )
        self.assertEqual(
            PLUGIN._EVENTRING_KINDS[34][1](62809, 62809, 0),
            "pid=62809 tid=62809 exit=0 publication=complete",
        )

    def test_eventring_formats_hvpatch_child_wait_target(self):
        self.assertEqual(
            PLUGIN._EVENTRING_KINDS[35][1](0x123456, 62809, 0),
            "id=0x123456 target_pid=62809",
        )

    def test_eventring_formats_epoll_result_membership(self):
        self.assertEqual(
            PLUGIN._EVENTRING_KINDS[36][1](16408, 25, 0x2001),
            "epfd=16408 gfd=25 events=0x2001",
        )

    def test_eventring_formats_rejected_epoll_generation(self):
        self.assertEqual(
            PLUGIN._EVENTRING_KINDS[37][1](25, 91, 92),
            "gfd=25 observed_gen=91 live_gen=92",
        )

    def test_eventring_formats_process_qualified_fd_close(self):
        self.assertEqual(
            PLUGIN._EVENTRING_KINDS[38][1](73014, 73021, 17),
            "pid=73014 tid=73021 gfd=17",
        )
        self.assertEqual(
            PLUGIN._EVENTRING_KINDS[39][1](73014, 17, 4),
            "pid=73014 gfd=17 refs_before=4",
        )

    def _fmt(self, kind, a, b, c):
        """Decode as `cmd_eventring` does: sign-extend each 32-bit word."""
        s32 = PLUGIN._signed32
        name, fmt = PLUGIN._EVENTRING_KINDS[kind]
        return f"{name} {fmt(s32(a), s32(b), s32(c))}"

    def test_eventring_decodes_every_fault_forensics_kind(self):
        # Kinds 68..80 must all be known: an unknown kind reads as ERROR.
        for kind in range(68, 81):
            self.assertIn(kind, PLUGIN._EVENTRING_KINDS)
        self.assertNotIn(81, PLUGIN._EVENTRING_KINDS)

    def test_eventring_formats_el1_frame_grant_claim_and_decision(self):
        # Same packed words the Rust round-trip test publishes.
        claim = 2 | (2 << 2) | ((0x1_2345_6789 & 0x0FFF_FFFF) << 4)
        self.assertEqual(
            self._fmt(68, 71001, 7, claim),
            "EL1GRANT_CLAIM tid=71001 mm=7 outcome=accepted access=write generation=54880137",
        )
        self.assertEqual(
            self._fmt(69, 0x80001234, 0x0000FFFF, 71001),
            "FAULT_VA tid=71001 va=0x0000ffff80001234",
        )
        self.assertEqual(
            self._fmt(70, 72001, 41, 4 | (3 << 4) | (16 << 8)),
            "EL1GRANT_DECISION tid=72001 generation=41 decision=ready prot=0x3 pages=16",
        )
        self.assertEqual(
            self._fmt(70, 72002, 42, 1 | (0xFFFFFF << 8)),
            "EL1GRANT_DECISION tid=72002 generation=42 decision=refused/no-plan prot=0x0 pages=16777215",
        )
        self.assertEqual(
            self._fmt(71, 0, 0x0000AAAA, 72001),
            "EL1GRANT_BASE tid=72001 base=0x0000aaaa00000000",
        )
        self.assertEqual(
            self._fmt(72, 0x12345000, 0x40, 72001),
            "EL1GRANT_IPA tid=72001 ipa=0x0000004012345000",
        )

    def test_eventring_formats_first_touch(self):
        packed = 4 | (3 << 3) | (2 << 5) | (3 << 7)
        self.assertEqual(
            self._fmt(73, 73001, 9, packed),
            "FIRST_TOUCH tid=73001 mm=9 resident=backend-refused growdown=protect-failed stale=not-retried access=exec",
        )

    def test_eventring_formats_fault_signal_group(self):
        packed = (
            11
            | (2 << 8)
            | (1 << 16)
            | (1 << 17)
            | (1 << 18)
            | (3 << 20)
            | (2 << 22)
            | (1 << 24)
        )
        self.assertEqual(
            self._fmt(74, 74001, 17, packed),
            "FAULTSIG tid=74001 mm=17 signal=11 si_code=2 mutating=true walk=L3-valid-denies access=write direct=true",
        )
        self.assertEqual(
            self._fmt(74, 74002, 0, 11 | (2 << 8)),
            "FAULTSIG tid=74002 mm=0 signal=11 si_code=2 mutating=false walk=unavailable access=unknown direct=false",
        )
        self.assertEqual(
            self._fmt(75, 0xDEADB000, 0x0000FFFF, 0x9200004F),
            "FAULTSIG_ADDR far=0x0000ffffdeadb000 esr=0x9200004f",
        )
        self.assertEqual(
            self._fmt(76, 0x1000, 0x0000AAAA, 74001),
            "FAULTSIG_PC tid=74001 pc=0x0000aaaa00001000",
        )
        self.assertEqual(
            self._fmt(77, 0x12345F43, 0x00600000, 74001),
            "FAULTSIG_LEAF tid=74001 leaf=0x0060000012345f43",
        )
        self.assertEqual(
            self._fmt(78, 74001, 12 | (3 << 16), 0x49249249),
            "FAULTSIG_MBOXES tid=74001 busy=12 own_slot=2 mask0_31=0x49249249",
        )
        self.assertEqual(
            self._fmt(78, 74002, 0, 0),
            "FAULTSIG_MBOXES tid=74002 busy=0 own_slot=none mask0_31=0x00000000",
        )
        self.assertEqual(
            self._fmt(79, 74001, 21, 3),
            "FAULTSIG_MBOX tid=74001 slot=21 state=host-working",
        )

    def test_eventring_high_rate_kinds_match_rust_routing(self):
        """The plugin's split must be the runtime's `is_high_rate` exactly."""
        import re

        source = (
            Path(__file__).resolve().parents[1]
            / "crates/carrick-kernel/src/event_ring.rs"
        ).read_text()
        constants = {
            name: int(value)
            for name, value in re.findall(r"pub const ([A-Z0-9_]+): u8 = (\d+);", source)
        }
        body = re.search(
            r"pub const fn is_high_rate\(kind: u8\) -> bool \{\s*matches!\(\s*kind,(.*?)\)\s*\}",
            source,
            re.S,
        )
        self.assertIsNotNone(body)
        names = [name.strip() for name in body.group(1).split("|")]
        rust = {constants[name] for name in names}
        self.assertEqual(rust, set(PLUGIN._EVENTRING_HIGH_RATE_KINDS))
        for kind in rust:
            self.assertIn(kind, PLUGIN._EVENTRING_KINDS)

    def test_eventring_arguments_select_ring_and_window(self):
        parse = PLUGIN._parse_eventring_args
        self.assertEqual(parse(""), ("lifecycle", PLUGIN._EVENTRING_DEFAULT_COUNT, None))
        self.assertEqual(parse("8192"), ("lifecycle", 8192, None))
        self.assertEqual(parse("--high-rate 8192"), ("high-rate", 8192, None))
        self.assertEqual(parse("--sched 10:5"), ("high-rate", 5, 10))
        self.assertEqual(parse("7 --sched"), ("high-rate", 7, None))
        for bad in ("0", "-3", "x", "1 2", "--sched 1:0"):
            with self.assertRaises(ValueError):
                parse(bad)
        self.assertEqual(
            PLUGIN._EVENTRING_RINGS,
            {"lifecycle": ("RING", "IDX"), "high-rate": ("SCHED_RING", "SCHED_IDX")},
        )

    def test_eventring_formats_mm_occupancy_refusal(self):
        self.assertEqual(
            self._fmt(80, 75, 4, 9),
            "MMOCC_REFUSE slot=75 running_mm=4 requested_mm=9",
        )


if __name__ == "__main__":
    unittest.main()
