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


if __name__ == "__main__":
    unittest.main()
