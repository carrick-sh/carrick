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

    def test_requires_a_classification_specific_authority_rationale(self):
        host_authority = load_host_authority()
        rows = host_authority.generate(
            self.fixture("fn carrier() { std::thread::yield_now(); }\n")
        )
        generic = [
            {
                **rows[0],
                "classification": "declared_substrate",
                "rationale": "host CPU yielding is carrier execution",
            }
        ]
        with self.assertRaises(host_authority.InventoryError):
            host_authority.validate(rows, generic)
        concrete = [
            {
                **rows[0],
                "classification": "declared_substrate",
                "rationale": (
                    "authenticated carrier: yields the current vCPU worker's host "
                    "thread without accepting a process identifier"
                ),
            }
        ]
        host_authority.validate(rows, concrete)

    def test_rejects_a_prefixed_generic_or_disjunctive_rationale(self):
        host_authority = load_host_authority()
        rows = host_authority.generate(
            self.fixture("fn carrier() { std::thread::yield_now(); }\n")
        )
        for rationale in (
            (
                "authenticated carrier: performs a carrier-side operation; "
                "Carrick created that resource"
            ),
            "authenticated carrier: schedules a timer or a worker",
        ):
            expected = [
                {
                    **rows[0],
                    "classification": "declared_substrate",
                    "rationale": rationale,
                }
            ]
            with self.subTest(rationale=rationale):
                with self.assertRaises(host_authority.InventoryError):
                    host_authority.validate(rows, expected)

    def test_legacy_requires_a_compile_or_standalone_target_exclusion(self):
        host_authority = load_host_authority()
        rows = host_authority.generate(
            self.fixture("fn current() { let _ = std::process::id(); }\n")
        )
        runtime_waiver = [
            {
                **rows[0],
                "classification": "legacy_unreachable",
                "rationale": "no active dispatch context reaches this fallback",
            }
        ]
        with self.assertRaises(host_authority.InventoryError):
            host_authority.validate(rows, runtime_waiver)
        compile_exclusion = [
            {
                **rows[0],
                "classification": "legacy_unreachable",
                "rationale": (
                    "compile-time exclusion: cfg(test) path module is absent from "
                    "the HVPatch product target"
                ),
            }
        ]
        host_authority.validate(rows, compile_exclusion)

    def test_detects_qualified_and_multiline_aliased_filesystem_operations(self):
        host_authority = load_host_authority()
        rows = host_authority.generate(
            self.fixture(
                "use std::fs::{\n"
                "    File as HostFile,\n"
                "    OpenOptions,\n"
                "    metadata as host_metadata,\n"
                "};\n"
                "struct Types { qualified: std::fs::File, imported: HostFile }\n"
                "fn qualified() {\n"
                "    let _: Option<std::fs::File> = None;\n"
                "    let _ = std::fs::File::open(\"/tmp/qualified\");\n"
                "}\n"
                "fn imported() {\n"
                "    let _: Option<HostFile> = None;\n"
                "    let _ = HostFile::open(\"/tmp/imported\");\n"
                "    let _ = OpenOptions::new();\n"
                "    let _ = host_metadata(\"/tmp/imported\");\n"
                "}\n"
            )
        )
        self.assertEqual([(row["line"], row["kind"]) for row in rows], [
            (9, "ambient_filesystem"),
            (13, "ambient_filesystem"),
            (14, "ambient_filesystem"),
            (15, "ambient_filesystem"),
        ])
        self.assertEqual(
            [row.get("operations") for row in rows],
            [
                ["std::fs::File::open"],
                ["std::fs::File::open"],
                ["std::fs::OpenOptions::new"],
                ["std::fs::metadata"],
            ],
        )

    def test_detects_multiline_aliased_network_socket_operations(self):
        host_authority = load_host_authority()
        rows = host_authority.generate(
            self.fixture(
                "use std::net::{\n"
                "    TcpStream as Stream,\n"
                "    TcpListener,\n"
                "    UdpSocket as Datagram,\n"
                "};\n"
                "struct Types { address: std::net::SocketAddr, stream: Stream }\n"
                "fn sockets() {\n"
                "    let _ = Stream::connect(\"127.0.0.1:1\");\n"
                "    let _ = TcpListener::bind(\"127.0.0.1:2\");\n"
                "    let _ = Datagram::bind(\"127.0.0.1:3\");\n"
                "}\n"
            )
        )
        self.assertEqual([(row["line"], row["kind"]) for row in rows], [
            (8, "ambient_network"),
            (9, "ambient_network"),
            (10, "ambient_network"),
        ])
        self.assertEqual(
            [row.get("operations") for row in rows],
            [
                ["std::net::TcpStream::connect"],
                ["std::net::TcpListener::bind"],
                ["std::net::UdpSocket::bind"],
            ],
        )

    def test_block_local_import_alias_expires_at_its_closing_brace(self):
        host_authority = load_host_authority()
        rows = host_authority.generate(
            self.fixture(
                "fn scoped() {\n"
                "    {\n"
                "        use std::net::TcpStream as ScopedStream;\n"
                "        let _ = ScopedStream::connect(\"127.0.0.1:1\");\n"
                "    }\n"
                "}\n"
                "fn outside() {\n"
                "    let _ = ScopedStream::connect(\"127.0.0.1:2\");\n"
                "}\n"
            )
        )
        self.assertEqual(
            [(row["line"], row["kind"]) for row in rows],
            [(4, "ambient_network")],
        )

    def test_inventory_contains_calls_not_imports_or_type_mentions(self):
        host_authority = load_host_authority()
        rows = host_authority.generate(
            self.fixture(
                "use applevisor_sys::{hv_vcpu_t, hv_vcpus_exit};\n"
                "use std::fs::{File as HostFile, OpenOptions};\n"
                "use std::net::TcpStream as Stream;\n"
                "use std::thread::{spawn, JoinHandle};\n"
                "type Stop = unsafe fn(*const hv_vcpu_t, u32);\n"
                "struct Types { file: HostFile, options: OpenOptions, stream: Stream }\n"
                "fn takes(_: JoinHandle<()>, _: Stop) {}\n"
            )
        )
        self.assertEqual(rows, [])

    def test_accepts_an_exact_reviewed_inventory_and_rejects_drift(self):
        host_authority = load_host_authority()
        root = self.fixture("fn carrier() { std::thread::yield_now(); }\n")
        rows = host_authority.generate(root)
        expected = [
            {
                **rows[0],
                "classification": "declared_substrate",
                "rationale": (
                    "authenticated carrier: yields the current vCPU worker's host "
                    "thread without accepting a process identifier"
                ),
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

    def test_masks_multiline_restricted_modules_when_cfg_implies_test(self):
        host_authority = load_host_authority()
        rows = host_authority.generate(
            self.fixture(
                "#[cfg(\n"
                "    all(\n"
                "        test,\n"
                "        target_os = \"macos\",\n"
                "    )\n"
                ")]\n"
                "pub(in crate::dispatch)\n"
                "mod\n"
                "    hidden\n"
                "{\n"
                "    fn hidden() { libc::kill(1, 0); }\n"
                "}\n"
                "#[cfg(any(test, target_os = \"macos\"))]\n"
                "mod reachable_without_test {\n"
                "    fn live_on_macos() { libc::kill(2, 0); }\n"
                "}\n"
                "fn live() { libc::kill(3, 0); }\n"
            )
        )
        self.assertEqual(
            [(row["line"], row["text"]) for row in rows],
            [
                (15, "fn live_on_macos() { libc::kill(2, 0); }"),
                (17, "fn live() { libc::kill(3, 0); }"),
            ],
        )


if __name__ == "__main__":
    unittest.main()
