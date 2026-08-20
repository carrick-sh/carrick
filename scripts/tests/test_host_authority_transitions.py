#!/usr/bin/env python3
"""Tests for the checked guest-facing host-transition inventory."""

import importlib.util
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "scripts" / "migrate" / "check-host-authority-transitions.py"


def load_host_authority():
    if not MODULE.exists():
        raise AssertionError(f"checker is absent: {MODULE}")
    spec = importlib.util.spec_from_file_location("host_authority", MODULE)
    assert spec is not None
    assert spec.loader is not None
    host_authority = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(host_authority)
    return host_authority


class HostAuthorityInventoryTest(unittest.TestCase):
    def fixture(self, body: str) -> Path:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        path = root / "crates/carrick-runtime/src/dispatch/proc.rs"
        path.parent.mkdir(parents=True)
        path.write_text(body, encoding="utf-8")
        return root

    def test_detects_semantic_host_process_calls(self):
        host_authority = load_host_authority()
        rows = host_authority.generate(
            self.fixture("fn bad(pid: i32) { unsafe { libc::kill(pid, 0); } }\n")
        )
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["kind"], "host_process_control")

    def test_rejects_unreviewed_or_empty_rationale(self):
        host_authority = load_host_authority()
        rows = host_authority.generate(
            self.fixture("fn bad() { let _ = std::process::id(); }\n")
        )
        expected = [{**rows[0], "classification": "unreviewed", "rationale": ""}]
        with self.assertRaises(host_authority.InventoryError):
            host_authority.validate(rows, expected)

    def test_ignores_std_net_type_annotations_but_detects_socket_operations(self):
        host_authority = load_host_authority()
        rows = host_authority.generate(
            self.fixture(
                "fn type_only(addr: std::net::SocketAddr) {}\n"
                "fn connects() { let _ = std::net::TcpStream::connect(\"127.0.0.1:1\"); }\n"
            )
        )
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["kind"], "ambient_network")
        self.assertEqual(rows[0]["line"], 2)

    def test_accepts_an_exact_reviewed_inventory_and_rejects_drift(self):
        host_authority = load_host_authority()
        root = self.fixture("fn carrier() { std::thread::yield_now(); }\n")
        rows = host_authority.generate(root)
        expected = [
            {
                **rows[0],
                "classification": "declared_substrate",
                "rationale": "host CPU yielding is carrier execution, not guest identity",
            }
        ]
        host_authority.validate(rows, expected)
        path = root / "crates/carrick-runtime/src/dispatch/proc.rs"
        path.write_text(path.read_text() + "fn id() { let _ = std::process::id(); }\n")
        with self.assertRaises(host_authority.InventoryError):
            host_authority.validate(host_authority.generate(root), expected)

    def test_ignores_comments_and_balanced_cfg_test_module_bodies(self):
        host_authority = load_host_authority()
        rows = host_authority.generate(
            self.fixture(
                "// libc::kill(1, 0);\n"
                "#[cfg(test)] mod ignored { fn probe() { let _ = \"{\"; libc::kill(1, 0); } }\n"
                "#[cfg(test)] pub(crate) mod hidden { libc::kill(1, 0); }\n"
                "fn live() { libc::kill(1, 0); }\n"
                "fn literal() { let url = \"http://example\"; libc::kill(1, 0); }\n"
            )
        )
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["line"], 4)
        self.assertEqual(rows[1]["line"], 5)


if __name__ == "__main__":
    unittest.main()
