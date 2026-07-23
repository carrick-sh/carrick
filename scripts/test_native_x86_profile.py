#!/usr/bin/env python3

from collections import Counter
import importlib.util
from pathlib import Path
import sys
import unittest
from unittest import mock

SCRIPT = Path(__file__).with_name("native-x86-profile.py")
SPEC = importlib.util.spec_from_file_location("native_x86_profile", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
PROFILE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = PROFILE
SPEC.loader.exec_module(PROFILE)


PROCSTAT = """\
  PID              START                END PRT  RES PRES REF SHD FLAG  TP PATH
1234           0x400000          0x500000 r--    1    1   1   0 ----- vn /tmp/carrick
1234           0x500000          0x700000 r-x    1    1   1   0 ----- vn /tmp/carrick
1234       0x6000000000       0x6040000000 r-x    1    1   1   0 --S-- sw posixshm@
1234     0x700000000000     0x700000100000 r-x    1    1   1   0 ----- vn /lib/libc.so.7
"""


class NativeX86ProfileTests(unittest.TestCase):
    def test_parses_mappings_and_finds_jit_without_fixed_addresses(self) -> None:
        mappings = PROFILE.parse_procstat_mappings(PROCSTAT, 1234)
        self.assertEqual(len(mappings), 4)
        self.assertEqual(mappings[1].path, "/tmp/carrick")
        self.assertEqual(
            PROFILE.jit_mappings(mappings),
            [PROFILE.Mapping(0x6000000000, 0x6040000000, "r-x", "posixshm@")],
        )

    def test_collects_private_jit_ranges_from_existing_children(self) -> None:
        root = [PROFILE.Mapping(0x6000, 0x7000, "r-x", "posixshm@")]
        child = root + [PROFILE.Mapping(0x8000, 0x9000, "r-x", "posixshm@")]
        with mock.patch.object(PROFILE, "process_mappings", side_effect=[root, child]):
            combined = PROFILE.initial_tree_mappings([10, 11], 10)
        self.assertEqual(PROFILE.jit_mappings(combined), child)

    def test_loads_matching_binary_layout_contract(self) -> None:
        payload = """{
          "schema":"carrick.native-x86-profiler-layout.v1",
          "version":1,
          "context_register":"R_R15",
          "context_size":33160,
          "exit_resume_offset":33024
        }"""
        with mock.patch.object(PROFILE, "run_text", return_value=payload):
            layout = PROFILE.load_layout(Path("/tmp/carrick"))
        self.assertEqual(layout.exit_resume_offset, 33024)
        self.assertEqual(layout.context_register, "R_R15")

    def test_rejects_layout_offset_outside_context(self) -> None:
        payload = """{
          "schema":"carrick.native-x86-profiler-layout.v1",
          "version":1,
          "context_register":"R_R15",
          "context_size":100,
          "exit_resume_offset":100
        }"""
        with mock.patch.object(PROFILE, "run_text", return_value=payload):
            with self.assertRaises(PROFILE.ProfileError):
                PROFILE.load_layout(Path("/tmp/carrick"))

    def test_generated_trace_is_bounded_and_never_grabs_or_patches_tracee(self) -> None:
        layout = PROFILE.Layout(1, "R_R15", 33160, 33024)
        jit = [PROFILE.Mapping(0x6000000000, 0x6040000000, "r-x", "posixshm@")]
        script = PROFILE.build_d_script(
            [1234, 1235], 7, 997, layout, jit, (0x700000010000, 0x700000010200)
        )
        self.assertIn("tick-7s", script)
        self.assertIn("tracked[1234] = 1", script)
        self.assertIn("tracked[1235] = 1", script)
        self.assertIn("proc:::create", script)
        self.assertIn("args[0]->p_pid", script)
        self.assertNotIn("pr_pid", script)
        self.assertIn("uregs[R_R15] + 33024", script)
        self.assertIn("0x6000000000", script)
        self.assertIn("syscall:freebsd::entry", script)
        self.assertNotIn("pid$", script)
        self.assertNotIn("carrick*:::", script)
        self.assertNotIn("dtrace_proc_", script)
        self.assertNotIn("-p 1234", script)

    def test_generated_trace_omits_undefined_memcpy_aggregations(self) -> None:
        layout = PROFILE.Layout(1, "R_R15", 33160, 33024)
        jit = [PROFILE.Mapping(0x6000000000, 0x6040000000, "r-x", "posixshm@")]
        script = PROFILE.build_d_script([1234], 5, 997, layout, jit, None)
        self.assertNotIn("@memcpy_caller", script)
        self.assertNotIn("@memcpy_size", script)

    def test_parses_machine_records(self) -> None:
        capture = PROFILE.parse_capture(
            "\n".join(
                [
                    "NXPROF1|syscall|name=getpid|count=9",
                    "NXPROF1|new-child|pid=1235|count=1",
                    "NXPROF1|host-pc|pc=0x401000|count=4",
                    "NXPROF1|guest-pc|pc=0x6a63bb|count=3",
                    "NXPROF1|memcpy-caller|pc=0x402000|count=2",
                    "NXPROF1|memcpy-size|bytes=16384|count=2",
                ]
            )
        )
        self.assertEqual(capture.syscalls, Counter({"getpid": 9}))
        self.assertEqual(capture.new_children, Counter({1235: 1}))
        self.assertEqual(capture.host_pcs, Counter({0x401000: 4}))
        self.assertEqual(capture.guest_pcs, Counter({0x6A63BB: 3}))
        self.assertEqual(capture.memcpy_sizes, Counter({16384: 2}))

    def test_process_tree_includes_existing_descendants(self) -> None:
        tree = PROFILE.parse_process_tree(
            "1 0\n10 1\n11 10\n12 1\n99 50\n", 1
        )
        self.assertEqual(tree, [1, 10, 12, 11])

    def test_mapping_drift_only_compares_executable_ranges(self) -> None:
        before = PROFILE.parse_procstat_mappings(PROCSTAT, 1234)
        after = list(before)
        after[0] = PROFILE.Mapping(0x400000, 0x4F0000, "r--", "/tmp/carrick")
        self.assertTrue(PROFILE.same_mappings(before, after))
        after[1] = PROFILE.Mapping(0x500000, 0x710000, "r-x", "/tmp/carrick")
        self.assertFalse(PROFILE.same_mappings(before, after))


if __name__ == "__main__":
    unittest.main()
