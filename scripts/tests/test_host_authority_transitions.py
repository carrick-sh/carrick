#!/usr/bin/env python3
"""Tests for the checked guest-facing host-transition inventory."""

import importlib.util
import json
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

    def write_source(self, root: Path, relative: str, body: str) -> Path:
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")
        return path

    def test_detects_semantic_host_process_calls(self):
        host_authority = load_host_authority()
        rows = host_authority.generate(
            self.fixture("fn bad(pid: i32) { unsafe { libc::kill(pid, 0); } }\n")
        )
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["kind"], "host_process_control")

    def test_scans_the_complete_runtime_source_tree(self):
        host_authority = load_host_authority()
        root = self.fixture("")
        self.write_source(
            root,
            "crates/carrick-runtime/src/network/dns.rs",
            "fn dns() { let _ = std::net::UdpSocket::bind(\"127.0.0.1:0\"); }\n",
        )
        self.write_source(
            root,
            "crates/carrick-runtime/src/fs_backend.rs",
            "fn bytes() { let _ = std::fs::read(\"/authorized\"); }\n",
        )
        self.write_source(
            root,
            "crates/carrick-runtime/src/new_guest_surface.rs",
            "fn identity() { let _ = std::process::id(); }\n",
        )
        rows = host_authority.generate(root)
        self.assertEqual(
            [(row["file"], row["kind"]) for row in rows],
            [
                (
                    "crates/carrick-runtime/src/fs_backend.rs",
                    "ambient_filesystem",
                ),
                (
                    "crates/carrick-runtime/src/network/dns.rs",
                    "ambient_network",
                ),
                (
                    "crates/carrick-runtime/src/new_guest_surface.rs",
                    "host_identity",
                ),
            ],
        )

    def test_rejects_unreviewed_or_empty_rationale(self):
        host_authority = load_host_authority()
        rows = host_authority.generate(
            self.fixture("fn bad() { let _ = std::process::id(); }\n")
        )
        expected = [{**rows[0], "classification": "unreviewed", "rationale": ""}]
        with self.assertRaises(host_authority.InventoryError):
            host_authority.validate(rows, expected)

    def test_requires_structured_authority_evidence(self):
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
                "evidence": {
                    "authority": "authenticated_carrier",
                    "resource": "current vCPU worker host thread",
                },
                "rationale": (
                    "The call yields the current vCPU worker host thread without "
                    "accepting a process identifier."
                ),
            }
        ]
        host_authority.validate(rows, concrete)

    def test_rejects_generic_or_disjunctive_review_claims(self):
        host_authority = load_host_authority()
        rows = host_authority.generate(
            self.fixture("fn carrier() { std::thread::yield_now(); }\n")
        )
        for resource, rationale in (
            (
                "carrier resource",
                "The call yields the current worker thread.",
            ),
            (
                "current timer OR current worker",
                "The call schedules the selected helper.",
            ),
            (
                "current vCPU worker host thread",
                "The call schedules a timer Versus a worker.",
            ),
        ):
            expected = [
                {
                    **rows[0],
                    "classification": "declared_substrate",
                    "evidence": {
                        "authority": "authenticated_carrier",
                        "resource": resource,
                    },
                    "rationale": rationale,
                }
            ]
            with self.subTest(resource=resource, rationale=rationale):
                with self.assertRaises(host_authority.InventoryError):
                    host_authority.validate(rows, expected)

    def test_rejects_empty_and_prefix_only_structured_claims(self):
        host_authority = load_host_authority()
        rows = host_authority.generate(
            self.fixture("fn carrier() { std::thread::yield_now(); }\n")
        )
        for resource, rationale in (
            ("", "The call yields the current worker thread."),
            ("authenticated carrier:", "The call yields the current worker thread."),
            ("current vCPU worker host thread", "guest answer:"),
        ):
            expected = [
                {
                    **rows[0],
                    "classification": "declared_substrate",
                    "evidence": {
                        "authority": "authenticated_carrier",
                        "resource": resource,
                    },
                    "rationale": rationale,
                }
            ]
            with self.subTest(resource=resource, rationale=rationale):
                with self.assertRaises(host_authority.InventoryError):
                    host_authority.validate(rows, expected)

    def test_legacy_rejects_runtime_and_unrecognized_compile_claims(self):
        host_authority = load_host_authority()
        rows = host_authority.generate(
            self.fixture("fn current() { let _ = std::process::id(); }\n")
        )
        for evidence, rationale in (
            (
                {
                    "authority": "compile_time_exclusion",
                    "resource": "no active dispatch context",
                    "exclusion": {"kind": "runtime_context"},
                },
                "No active dispatch context reaches this fallback.",
            ),
            (
                {
                    "authority": "compile_time_exclusion",
                    "resource": "claimed cfg(test) proc module",
                    "exclusion": {
                        "kind": "cfg_path_module",
                        "declaration_file": "crates/carrick-runtime/src/dispatch/mod.rs",
                        "module": "proc",
                        "predicate": "test",
                    },
                },
                "The production proc source is claimed to be test-only.",
            ),
        ):
            expected = [
                {
                    **rows[0],
                    "classification": "legacy_unreachable",
                    "evidence": evidence,
                    "rationale": rationale,
                }
            ]
            with self.subTest(evidence=evidence):
                with self.assertRaises(host_authority.InventoryError):
                    host_authority.validate(rows, expected)

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

    def test_cfg_test_import_cannot_replace_the_production_binding(self):
        host_authority = load_host_authority()
        rows = host_authority.generate(
            self.fixture(
                "#[cfg(not(test))]\n"
                "use std::fs::File as Selected;\n"
                "#[cfg(test)]\n"
                "use std::net::TcpStream as Selected;\n"
                "fn production() { let _ = Selected::open(\"/tmp/x\"); }\n"
            )
        )
        self.assertEqual(
            [(row["line"], row["kind"], row["operations"]) for row in rows],
            [(5, "ambient_filesystem", ["std::fs::File::open"])],
        )

    def test_detects_a_bare_glob_inside_a_braced_use_tree(self):
        host_authority = load_host_authority()
        rows = host_authority.generate(
            self.fixture(
                "use std::fs::{*};\n"
                "fn imported() { let _ = read(\"/tmp/x\"); }\n"
            )
        )
        self.assertEqual(
            [(row["line"], row["kind"], row["operations"]) for row in rows],
            [(2, "ambient_filesystem", ["std::fs::read"])],
        )

    def test_resolves_self_qualified_import_alias_chains(self):
        host_authority = load_host_authority()
        rows = host_authority.generate(
            self.fixture(
                "use std::fs::File as HostFile;\n"
                "use self::HostFile as LocalFile;\n"
                "fn imported() { let _ = LocalFile::open(\"/tmp/x\"); }\n"
            )
        )
        self.assertEqual(
            [(row["line"], row["kind"], row["operations"]) for row in rows],
            [(3, "ambient_filesystem", ["std::fs::File::open"])],
        )

    def test_local_value_binding_shadows_an_imported_function(self):
        host_authority = load_host_authority()
        rows = host_authority.generate(
            self.fixture(
                "use std::fs::read as load;\n"
                "fn before() { let _ = load(\"/tmp/x\"); }\n"
                "fn shadowed() { let load = || Vec::<u8>::new(); let _ = load(); }\n"
            )
        )
        self.assertEqual(
            [(row["line"], row["kind"], row["operations"]) for row in rows],
            [(2, "ambient_filesystem", ["std::fs::read"])],
        )

    def test_detects_grouped_watched_callees(self):
        host_authority = load_host_authority()
        rows = host_authority.generate(
            self.fixture(
                "use std::fs::read as load;\n"
                "fn qualified() { let _ = (std::fs::read)(\"/tmp/x\"); }\n"
                "fn imported() { let _ = ((load))(\"/tmp/y\"); }\n"
            )
        )
        self.assertEqual(
            [(row["line"], row["kind"], row["operations"]) for row in rows],
            [
                (2, "ambient_filesystem", ["std::fs::read"]),
                (3, "ambient_filesystem", ["std::fs::read"]),
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
                "evidence": {
                    "authority": "authenticated_carrier",
                    "resource": "current vCPU worker host thread",
                },
                "rationale": (
                    "The call yields the current vCPU worker host thread without "
                    "accepting a process identifier."
                ),
            }
        ]
        host_authority.validate(rows, expected)
        path = root / "crates/carrick-runtime/src/dispatch/proc.rs"
        path.write_text(path.read_text() + "fn id() { let _ = std::process::id(); }\n")
        with self.assertRaises(host_authority.InventoryError):
            host_authority.validate(host_authority.generate(root), expected)

    def test_operation_retarget_does_not_preserve_stale_review(self):
        host_authority = load_host_authority()
        rows = host_authority.generate(
            self.fixture("fn open() { let _ = std::fs::File::open(\"/tmp/x\"); }\n")
        )
        reviewed = [
            {
                **rows[0],
                "classification": "declared_backing",
                "evidence": {
                    "authority": "authorized_backing",
                    "resource": "selected file beneath configured root",
                },
                "rationale": (
                    "The call opens the selected file beneath the configured root."
                ),
            }
        ]
        retargeted = [{**rows[0], "operations": ["std::fs::metadata"]}]
        rewritten = host_authority.reviewed_rows(retargeted, reviewed)
        self.assertEqual(rewritten[0]["classification"], "unreviewed")
        self.assertEqual(rewritten[0]["evidence"], {})
        self.assertEqual(rewritten[0]["rationale"], "")

    def test_duplicate_review_identity_is_rejected_as_ambiguous(self):
        host_authority = load_host_authority()
        rows = host_authority.generate(
            self.fixture("fn open() { let _ = std::fs::File::open(\"/tmp/x\"); }\n")
        )
        reviewed = {
            **rows[0],
            "classification": "declared_backing",
            "evidence": {
                "authority": "authorized_backing",
                "resource": "selected file beneath configured root",
            },
            "rationale": (
                "The call opens the selected file beneath the configured root."
            ),
        }
        with self.assertRaises(host_authority.InventoryError):
            host_authority.reviewed_rows(rows, [reviewed, reviewed])

    def test_recognizes_real_cfg_path_and_standalone_target_exclusions(self):
        host_authority = load_host_authority()
        root = self.fixture("")
        self.write_source(
            root,
            "crates/carrick-runtime/src/dispatch/fs.rs",
            "#[cfg(test)]\n#[path = \"fs/tests.rs\"]\nmod tests;\n",
        )
        self.write_source(
            root,
            "crates/carrick-runtime/src/dispatch/fs/tests.rs",
            "fn test_only() { let _ = std::process::id(); }\n",
        )
        self.write_source(
            root,
            "crates/carrick-vmm-hvf/Cargo.toml",
            "[package]\nname = \"fixture-hvf\"\nversion = \"0.0.0\"\n",
        )
        self.write_source(
            root,
            "crates/carrick-vmm-hvf/src/bin/demo_probe.rs",
            "fn main() { std::thread::yield_now(); }\n",
        )
        rows = host_authority.generate(root)
        by_file = {row["file"]: row for row in rows}
        self.assertEqual(
            by_file[
                "crates/carrick-runtime/src/dispatch/fs/tests.rs"
            ].get("product_exclusion"),
            {
                "kind": "cfg_path_module",
                "declaration_file": "crates/carrick-runtime/src/dispatch/fs.rs",
                "module": "tests",
                "predicate": "test",
            },
        )
        self.assertEqual(
            by_file[
                "crates/carrick-vmm-hvf/src/bin/demo_probe.rs"
            ].get("product_exclusion"),
            {
                "kind": "standalone_cargo_target",
                "manifest": "crates/carrick-vmm-hvf/Cargo.toml",
                "targets": ["demo_probe"],
            },
        )
        for file, authority, resource in (
            (
                "crates/carrick-runtime/src/dispatch/fs/tests.rs",
                "compile_time_exclusion",
                "cfg(test) path module fs/tests.rs",
            ),
            (
                "crates/carrick-vmm-hvf/src/bin/demo_probe.rs",
                "standalone_target_exclusion",
                "standalone Cargo target demo_probe",
            ),
        ):
            row = by_file[file]
            reviewed = {
                **row,
                "classification": "legacy_unreachable",
                "evidence": {
                    "authority": authority,
                    "resource": resource,
                    "exclusion": row["product_exclusion"],
                },
                "rationale": "The recognized build boundary excludes this source from the product.",
            }
            host_authority.validate([row], [reviewed])
            mismatched = {
                **reviewed,
                "evidence": {
                    **reviewed["evidence"],
                    "exclusion": {"kind": "runtime_context"},
                },
            }
            with self.assertRaises(host_authority.InventoryError):
                host_authority.validate([row], [mismatched])

    def test_unchanged_write_is_byte_identical(self):
        host_authority = load_host_authority()
        root = self.fixture("fn carrier() { std::thread::yield_now(); }\n")
        rows = host_authority.generate(root)
        reviewed = [
            {
                **rows[0],
                "classification": "declared_substrate",
                "evidence": {
                    "authority": "authenticated_carrier",
                    "resource": "current vCPU worker host thread",
                },
                "rationale": "The call yields only the current worker thread.",
            }
        ]
        inventory = root / "inventory.json"
        before = json.dumps(reviewed, indent=2) + "\n"
        inventory.write_text(before, encoding="utf-8")
        original_root = host_authority.ROOT
        original_inventory = host_authority.INVENTORY
        host_authority.ROOT = root
        host_authority.INVENTORY = inventory
        try:
            self.assertEqual(host_authority.main(["--write"]), 0)
        finally:
            host_authority.ROOT = original_root
            host_authority.INVENTORY = original_inventory
        self.assertEqual(inventory.read_text(encoding="utf-8"), before)

    def test_valid_structured_authority_evidence_does_not_need_a_prose_prefix(self):
        host_authority = load_host_authority()
        rows = host_authority.generate(
            self.fixture("fn carrier() { std::thread::yield_now(); }\n")
        )
        expected = [
            {
                **rows[0],
                "classification": "declared_substrate",
                "evidence": {
                    "authority": "authenticated_carrier",
                    "resource": "current vCPU worker host thread",
                },
                "rationale": "The call yields only that worker thread.",
            }
        ]
        host_authority.validate(rows, expected)

    def test_guest_wait_readiness_rows_are_forbidden_semantic(self):
        inventory = json.loads(
            (
                ROOT
                / "scripts/migrate/host-authority-transition-inventory.json"
            ).read_text(encoding="utf-8")
        )
        expected = {
            ("crates/carrick-vmm-hvf/src/host_signal.rs", 488),
            ("crates/carrick-vmm-hvf/src/io_wait.rs", 168),
            ("crates/carrick-vmm-hvf/src/io_wait.rs", 188),
            ("crates/carrick-vmm-hvf/src/io_wait.rs", 217),
            ("crates/carrick-vmm-hvf/src/io_wait.rs", 229),
            ("crates/carrick-vmm-hvf/src/io_wait.rs", 906),
            ("crates/carrick-vmm-hvf/src/io_wait.rs", 914),
            ("crates/carrick-runtime/src/lib.rs", 1256),
            ("crates/carrick-runtime/src/lib.rs", 1308),
            ("crates/carrick-runtime/src/lib.rs", 1318),
        }
        actual = {
            (row["file"], row["line"])
            for row in inventory
            if row["classification"] == "forbidden_semantic"
        }
        self.assertTrue(expected <= actual, expected - actual)

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

    def test_masks_nonmodule_items_when_cfg_implies_test(self):
        host_authority = load_host_authority()
        rows = host_authority.generate(
            self.fixture(
                "fn production() {\n"
                "    #[cfg(test)]\n"
                "    let test_pid = std::process::id();\n"
                "    let live_pid = std::process::id();\n"
                "}\n"
                "#[cfg(all(test, target_os = \"macos\"))]\n"
                "fn test_helper() { libc::kill(1, 0); }\n"
            )
        )
        self.assertEqual(
            [(row["line"], row["kind"], row["operations"]) for row in rows],
            [(4, "host_identity", ["std::process::id"])],
        )


if __name__ == "__main__":
    unittest.main()
