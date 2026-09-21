# SPDX-License-Identifier: Apache-2.0 OR MIT
import importlib.util
from pathlib import Path
import unittest

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("report", HERE / "inotify-service-report.py")
REPORT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REPORT)
CAPTURE = (HERE.parents[1] / "docs/perf-results/2026-09-20-hvpatch-syscall-portal/inotify-timed-host-join.trace").read_text()


def synthetic_capture():
    lines = ["INOTIFYHOT1|bound_s=10|saw_selected=1|nested=0|mismatch=0|errors=0|complete=1",
             "INOTIFYHOT1|host_mismatch=0|boundary_censored=1",
             "INOTIFYHOT1|selected_total=4"]
    for nr in (27, 28, 62, 64):
        for key, value in dict(begins=1, services=1, clears=1, open_services=0,
                               duration_ns=100, service_cpu_ns=nr).items():
            lines.append(f"INOTIFYHOT1|nr={nr}|{key}={value}")
        for key, value in dict(count=1, returns=1, open_hosts=0, wall_ns=20, cpu_ns=10).items():
            lines.append(f"INOTIFYHOT1|nr={nr}|host=example|{key}={value}")
    return "\n".join(lines)


SYNTHETIC = synthetic_capture()


class TimingReportTests(unittest.TestCase):
    def test_qualified_capture(self):
        result = REPORT.summarize(SYNTHETIC)
        self.assertEqual(len(result["services"]), 4)
        self.assertEqual(result["services"][0]["syscall"], "write")
        self.assertFalse(result["vm_transition_time_measured"])

    def test_live_drained_capture(self):
        capture = (HERE.parents[1] / "docs/perf-results/2026-09-20-hvpatch-syscall-portal/inotify-accounting-drained.trace").read_text()
        result = REPORT.summarize(capture)
        self.assertEqual(sum(row["calls"] for row in result["services"]), 574075)

    def test_rejects_historical_scalar_accounting(self):
        with self.assertRaisesRegex(ValueError, "aggregated selected total"):
            REPORT.summarize(CAPTURE)

    def test_rejects_corrupted_evidence(self):
        mutations = [
            SYNTHETIC.replace("complete=1", "complete=0"),
            SYNTHETIC.replace("host_mismatch=0", "host_mismatch=1"),
            SYNTHETIC.replace("open_services=0", "open_services=1", 1),
            SYNTHETIC.replace("open_hosts=0", "open_hosts=1", 1),
            SYNTHETIC.replace("returns=1", "returns=0"),
            "\n".join(l for l in SYNTHETIC.splitlines() if "service_cpu_ns=" not in l),
            SYNTHETIC + "\nINOTIFYHOT1|nr=64|services=1\n",
            SYNTHETIC.replace("selected_total=4", "selected_total=3"),
        ]
        for mutation in mutations:
            with self.subTest(mutation=mutations.index(mutation)):
                with self.assertRaises(ValueError):
                    REPORT.summarize(mutation)


if __name__ == "__main__":
    unittest.main()
