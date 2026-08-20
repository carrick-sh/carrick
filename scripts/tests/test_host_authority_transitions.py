#!/usr/bin/env python3
"""Tests for compiler-resolved host-authority diagnostic reviews."""

import copy
import contextlib
import hashlib
import importlib.util
import io
import json
import os
import pwd
import subprocess
import tempfile
import tomllib
import unittest
from collections import Counter
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "scripts" / "migrate" / "check-host-authority-transitions.py"
MATRIX = ROOT / "scripts" / "migrate" / "host-authority-build-matrix.json"
MESSAGES = (
    ROOT
    / "scripts"
    / "tests"
    / "fixtures"
    / "host-authority-census"
    / "messages.jsonl"
)
CLIPPY_CONFIG = ROOT / "clippy.toml"
INVENTORY = ROOT / "scripts" / "migrate" / "host-authority-transition-inventory.json"
CATALOG_MANIFEST = ROOT / "scripts" / "migrate" / "host-authority-catalog.json"
MACOS_CAPTURE = ROOT / "scripts" / "migrate" / "host-authority-macos-capture.json"

# Literal snapshot of every canonical operation in the rejected lexical
# inventory.  This must not be derived from either production artifact: the
# point of the contract is to catch an omitted operation during migration.
REJECTED_INVENTORY_OPERATIONS = {
    "applevisor_sys::hv_vcpus_exit",
    "libc::fork",
    "libc::geteuid",
    "libc::getpgrp",
    "libc::getpid",
    "libc::getppid",
    "libc::getrlimit",
    "libc::getsid",
    "libc::getuid",
    "libc::kill",
    "libc::killpg",
    "libc::setrlimit",
    "libc::wait4",
    "libc::waitid",
    "std::fs::File::create",
    "std::fs::File::open",
    "std::fs::OpenOptions::new",
    "std::fs::copy",
    "std::fs::create_dir",
    "std::fs::create_dir_all",
    "std::fs::hard_link",
    "std::fs::metadata",
    "std::fs::read",
    "std::fs::read_dir",
    "std::fs::read_link",
    "std::fs::read_to_string",
    "std::fs::remove_dir",
    "std::fs::remove_dir_all",
    "std::fs::remove_file",
    "std::fs::rename",
    "std::fs::set_permissions",
    "std::fs::symlink_metadata",
    "std::fs::write",
    "std::net::TcpListener::bind",
    "std::net::UdpSocket::bind",
    "std::process::id",
    "std::thread::Builder::new",
    "std::thread::sleep",
    "std::thread::spawn",
    "std::thread::yield_now",
}
REQUIRED_CATALOG_ADDITIONS = {
    "libc::dlopen",
    "libc::dlsym",
    "libc::syscall",
    "libc::waitpid",
    "std::fs::OpenOptions::open",
}
EXPECTED_PRODUCTION_OPERATIONS = (
    REJECTED_INVENTORY_OPERATIONS | REQUIRED_CATALOG_ADDITIONS
)
FIXTURE_CATALOG = {
    "libc::waitpid": "HA-CATALOG-FIXTURE-PROCESS-WAITPID",
    "std::fs::metadata": "HA-CATALOG-FIXTURE-FS-METADATA",
    "std::fs::read": "HA-CATALOG-FIXTURE-FS-READ",
    "std::process::id": "HA-CATALOG-FIXTURE-PROCESS-ID",
    "std::thread::yield_now": "HA-CATALOG-FIXTURE-THREAD-YIELD-NOW",
}

REQUIRED_PROFILES = [
    "macos-cli-default",
    "macos-runtime-default",
    "macos-hvf-default",
    "linux-cli",
    "linux-runtime",
    "freebsd-cli",
    "freebsd-runtime",
    "netbsd-cli",
    "netbsd-runtime",
]

HOST_TRIPLES = {
    "macos": "aarch64-apple-darwin",
    "linux": "x86_64-unknown-linux-gnu",
    "freebsd": "x86_64-unknown-freebsd",
    "netbsd": "x86_64-unknown-netbsd",
}

EXPECTED_COMMANDS = {
    "macos-cli-default": [
        "cargo",
        "clippy",
        "-p",
        "carrick-cli",
        "--target",
        HOST_TRIPLES["macos"],
        "--bin",
        "carrick",
        "--message-format=json",
        "--",
        "--force-warn",
        "clippy::disallowed_methods",
    ],
    "macos-runtime-default": [
        "cargo",
        "clippy",
        "-p",
        "carrick-runtime",
        "--target",
        HOST_TRIPLES["macos"],
        "--lib",
        "--message-format=json",
        "--",
        "--force-warn",
        "clippy::disallowed_methods",
    ],
    "macos-hvf-default": [
        "cargo",
        "clippy",
        "-p",
        "carrick-vmm-hvf",
        "--target",
        HOST_TRIPLES["macos"],
        "--lib",
        "--message-format=json",
        "--",
        "--force-warn",
        "clippy::disallowed_methods",
    ],
}

AMBIENT_BUILD_AUTHORITY = {
    "CARGO_BUILD_TARGET": "attacker-target",
    "RUSTFLAGS": "--cfg attacker",
    "CARGO_ENCODED_RUSTFLAGS": "--cfg\x1fattacker",
    "RUSTC": "/tmp/attacker-rustc",
    "RUSTC_WRAPPER": "/tmp/attacker-wrapper",
    "RUSTC_WORKSPACE_WRAPPER": "/tmp/attacker-workspace-wrapper",
    "CARGO_BUILD_RUSTC": "/tmp/attacker-build-rustc",
    "CARGO_BUILD_RUSTC_WRAPPER": "/tmp/attacker-build-wrapper",
    "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER": "/tmp/attacker-build-workspace-wrapper",
    "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS": "--cfg target_override",
    "CARGO_PROFILE_DEV_LTO": "true",
    "CARGO_CONFIG": "/tmp/attacker-config.toml",
    "RUSTUP_TOOLCHAIN": "stable-attacker-target",
}

for host, features in (
    ("linux", "syscall-shim,platform-linux"),
    ("freebsd", "platform-freebsd"),
    ("netbsd", "platform-netbsd"),
):
    for target, package, target_args in (
        ("cli", "carrick-cli", ["--bin", "carrick"]),
        ("runtime", "carrick-runtime", ["--lib"]),
    ):
        EXPECTED_COMMANDS[f"{host}-{target}"] = [
            "cargo",
            "clippy",
            "-p",
            package,
            "--no-default-features",
            "--features",
            features,
            "--target",
            HOST_TRIPLES[host],
            *target_args,
            "--message-format=json",
            "--",
            "--force-warn",
            "clippy::disallowed_methods",
        ]


def expected_profile_command(profile_id: str, root: Path = ROOT):
    return [
        "cargo",
        "--config",
        str((root / ".cargo" / "config.toml").resolve()),
        "clippy",
        "--manifest-path",
        str((root / "Cargo.toml").resolve()),
        *EXPECTED_COMMANDS[profile_id][2:],
    ]


def expected_clippy_version_command(root: Path = ROOT):
    return [
        "cargo",
        "--config",
        str((root / ".cargo" / "config.toml").resolve()),
        "clippy",
        "-V",
    ]


def load_host_authority():
    if not MODULE.exists():
        raise AssertionError(f"checker is absent: {MODULE}")
    spec = importlib.util.spec_from_file_location("host_authority", MODULE)
    assert spec is not None
    assert spec.loader is not None
    host_authority = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(host_authority)
    return host_authority


def source(
    file: str = "crates/example/src/lib.rs",
    line: int = 10,
    column: int = 5,
    *,
    byte_start: int = 100,
    byte_end: int = 120,
    line_end: int | None = None,
    column_end: int | None = None,
):
    return {
        "file": file,
        "byte_start": byte_start,
        "byte_end": byte_end,
        "line": line,
        "column": column,
        "line_start": line,
        "line_end": line if line_end is None else line_end,
        "column_start": column,
        "column_end": column + 10 if column_end is None else column_end,
    }


def compiler_span(
    file_name: str,
    line: int,
    column: int,
    *,
    byte_start: int,
    byte_end: int,
    line_end: int | None = None,
    column_end: int | None = None,
    primary: bool = False,
    expansion: dict[str, object] | None = None,
):
    return {
        "file_name": file_name,
        "byte_start": byte_start,
        "byte_end": byte_end,
        "line_start": line,
        "line_end": line if line_end is None else line_end,
        "column_start": column,
        "column_end": column + 10 if column_end is None else column_end,
        "is_primary": primary,
        "expansion": expansion,
    }


def actual_row(
    *,
    operation: str = "std::process::id",
    location: dict[str, object] | None = None,
    expansion: dict[str, object] | None = None,
    profiles: list[str] | None = None,
    catalog_id: str | None = "HA-CATALOG-PROCESS-ID",
):
    return {
        "catalog_id": catalog_id,
        "operation": operation,
        "source": location or source(),
        "expansion": expansion,
        "profiles": profiles or ["macos-hvf-default"],
    }


def reviewed_row(
    *,
    review_id: str = "HA-000001",
    operation: str = "std::process::id",
    location: dict[str, object] | None = None,
    expansion: dict[str, object] | None = None,
    profiles: list[str] | None = None,
    catalog_id: str | None = "HA-CATALOG-PROCESS-ID",
    classification: str = "forbidden_semantic",
    evidence: dict[str, object] | None = None,
    rationale: str = (
        "At crates/example/src/lib.rs:10, std::process::id would otherwise "
        "answer guest getpid semantics."
    ),
):
    if evidence is None:
        evidence = {
            "authority": "guest_answer",
            "resource": "guest-visible process identity",
        }
    return {
        "review_id": review_id,
        **actual_row(
            operation=operation,
            location=location,
            expansion=expansion,
            profiles=profiles,
            catalog_id=catalog_id,
        ),
        "classification": classification,
        "evidence": evidence,
        "rationale": rationale,
    }


def injected_receipt(reviewed):
    return {
        "rows": [
            {field: row[field] for field in load_host_authority().ACTUAL_FIELDS}
            for row in reviewed
        ]
    }


def diagnostic(
    operation: str = "std::process::id",
    *,
    file_name: str = "ROOT/crates/example/src/lib.rs",
    line: int = 10,
    column: int = 5,
    primary: bool = True,
    expansion: dict[str, object] | None = None,
    children: list[dict[str, object]] | None = None,
):
    return {
        "reason": "compiler-message",
        "message": {
            "code": {"code": "clippy::disallowed_methods", "explanation": None},
            "message": f"use of a disallowed method `{operation}`",
            "spans": [
                compiler_span(
                    file_name,
                    line,
                    column,
                    byte_start=100,
                    byte_end=120,
                    primary=primary,
                    expansion=expansion,
                )
            ],
            "children": children or [],
        },
    }


class DiagnosticNormalizationTest(unittest.TestCase):
    def setUp(self):
        self.host_authority = load_host_authority()

    def normalize(self, messages, operation_catalog=None):
        return self.host_authority.normalize_messages(
            messages,
            "macos-hvf-default",
            ROOT,
            FIXTURE_CATALOG if operation_catalog is None else operation_catalog,
        )

    def test_recorded_messages_normalize_all_resolved_operations(self):
        lines = MESSAGES.read_text(encoding="utf-8").splitlines()
        rows = self.normalize(lines)
        self.assertEqual(len(rows), 7)
        self.assertEqual(
            [row["operation"] for row in rows],
            [
                "libc::waitpid",
                "std::fs::metadata",
                "std::fs::read",
                "std::process::id",
                "std::process::id",
                "std::process::id",
                "std::thread::yield_now",
            ],
        )
        row = next(
            row
            for row in rows
            if row["operation"] == "std::process::id"
            and row["source"]["line"] == 11
        )
        self.assertEqual(row["catalog_id"], "HA-CATALOG-FIXTURE-PROCESS-ID")
        self.assertEqual(row["operation"], "std::process::id")
        self.assertEqual(row["profiles"], ["macos-hvf-default"])
        self.assertEqual(
            row["source"],
            source(
                "scripts/tests/fixtures/host-authority-census/src/lib.rs",
                11,
                5,
                byte_start=193,
                byte_end=209,
                column_end=21,
            ),
        )
        self.assertIn("line", row["source"])
        self.assertIn("column", row["source"])
        self.assertIsNone(row["expansion"])

    def test_recorded_messages_are_path_independent_and_ignore_non_clippy_rows(self):
        raw = MESSAGES.read_text(encoding="utf-8")
        self.assertNotIn(str(ROOT), raw)
        self.assertNotIn("/Volumes/", raw)
        self.assertEqual(len(raw.splitlines()), 10)
        self.assertEqual(len(self.normalize(raw.splitlines())), 7)

    def test_accepts_cargo_json_objects_and_extracts_optional_catalog_reason(self):
        row = self.normalize(
            [
                diagnostic(
                    children=[
                        {
                            "level": "note",
                            "message": (
                                "HA-CATALOG-FIXTURE-PROCESS-ID: host process "
                                "identity requires reviewed authority"
                            ),
                        }
                    ]
                )
            ]
        )[0]
        self.assertEqual(row["catalog_id"], "HA-CATALOG-FIXTURE-PROCESS-ID")

    def test_normalization_requires_explicit_operation_catalog(self):
        with self.assertRaises(TypeError):
            self.host_authority.normalize_messages(
                [diagnostic()], "macos-hvf-default", ROOT
            )

    def test_rejects_missing_unknown_or_conflicting_operation_catalog(self):
        cases = {
            "empty mapping": {},
            "missing operation": {
                "std::fs::read": "HA-CATALOG-FIXTURE-FS-READ"
            },
            "unknown operation": {
                "not a canonical operation": "HA-CATALOG-FIXTURE-UNKNOWN"
            },
            "invalid ID": {"std::process::id": "catalog-process-id"},
            "conflicting ID": {
                "std::process::id": "HA-CATALOG-FIXTURE-CONFLICT",
                "std::fs::read": "HA-CATALOG-FIXTURE-CONFLICT",
            },
        }
        for label, operation_catalog in cases.items():
            with self.subTest(label=label):
                with self.assertRaisesRegex(
                    self.host_authority.InventoryError, "catalog"
                ):
                    self.normalize([diagnostic()], operation_catalog)

    def test_rejects_diagnostic_child_id_mismatched_with_operation_catalog(self):
        message = diagnostic(
            children=[
                {
                    "level": "note",
                    "message": "HA-CATALOG-OTHER-ID: stale configured reason",
                }
            ]
        )
        with self.assertRaisesRegex(self.host_authority.InventoryError, "mismatch"):
            self.normalize([message])

    def test_rejects_unstable_catalog_reason_id_syntax(self):
        message = diagnostic(
            children=[
                {
                    "level": "note",
                    "message": "HA-CATALOG-PROCESS-ID-lower: invalid stable ID",
                }
            ]
        )
        with self.assertRaisesRegex(self.host_authority.InventoryError, "catalog"):
            self.normalize([message])

    def test_normalizes_outermost_workspace_macro_callsite(self):
        expansion = {
            "span": {
                **compiler_span(
                    "ROOT/crates/example/src/local_macro.rs",
                    20,
                    7,
                    byte_start=200,
                    byte_end=220,
                ),
                "expansion": {
                    "span": {
                        **compiler_span(
                            "/private/tmp/cargo-registry/dependency-macro.rs",
                            25,
                            3,
                            byte_start=250,
                            byte_end=270,
                        ),
                        "expansion": {
                            "span": compiler_span(
                                "ROOT/crates/example/src/caller.rs",
                                30,
                                9,
                                byte_start=300,
                                byte_end=330,
                            )
                        },
                    }
                },
            }
        }
        row = self.normalize([diagnostic(expansion=expansion)])[0]
        self.assertEqual(row["source"], source())
        self.assertEqual(
            row["expansion"],
            source(
                "crates/example/src/caller.rs",
                30,
                9,
                byte_start=300,
                byte_end=330,
            ),
        )

    def test_rejects_expansion_chain_with_no_workspace_callsite(self):
        expansion = {
            "span": {
                **compiler_span(
                    "/private/tmp/cargo-registry/dependency-macro.rs",
                    25,
                    3,
                    byte_start=250,
                    byte_end=270,
                ),
                "expansion": {
                    "span": compiler_span(
                        "/private/tmp/cargo-registry/outer-macro.rs",
                        40,
                        4,
                        byte_start=400,
                        byte_end=440,
                    )
                },
            }
        }
        with self.assertRaisesRegex(
            self.host_authority.InventoryError, "no workspace callsite"
        ):
            self.normalize([diagnostic(expansion=expansion)])

    def test_rejects_missing_malformed_and_reversed_span_coordinates(self):
        cases = {}
        missing = diagnostic()
        del missing["message"]["spans"][0]["byte_end"]
        cases["missing"] = missing
        reversed_bytes = diagnostic()
        reversed_bytes["message"]["spans"][0]["byte_end"] = 99
        cases["reversed bytes"] = reversed_bytes
        reversed_columns = diagnostic()
        reversed_columns["message"]["spans"][0]["column_end"] = 4
        cases["reversed columns"] = reversed_columns
        malformed = diagnostic()
        malformed["message"]["spans"][0]["line_end"] = "10"
        cases["malformed"] = malformed
        malformed_expansion = diagnostic(
            expansion={
                "span": compiler_span(
                    "ROOT/crates/example/src/caller.rs",
                    30,
                    9,
                    byte_start=300,
                    byte_end=330,
                )
            }
        )
        del malformed_expansion["message"]["spans"][0]["expansion"]["span"][
            "column_end"
        ]
        cases["missing expansion coordinate"] = malformed_expansion
        for label, message in cases.items():
            with self.subTest(label=label):
                with self.assertRaisesRegex(
                    self.host_authority.InventoryError, "span"
                ):
                    self.normalize([message])

    def test_rejects_unknown_clippy_operation_message(self):
        message = diagnostic()
        message["message"]["message"] = "disallowed host operation changed shape"
        with self.assertRaisesRegex(self.host_authority.InventoryError, "operation"):
            self.normalize([message])

    def test_disallowed_message_shape_with_missing_or_renamed_code_fails_closed(self):
        missing = diagnostic()
        del missing["message"]["code"]
        renamed = diagnostic()
        renamed["message"]["code"] = {
            "code": "clippy::renamed_disallowed_methods",
            "explanation": None,
        }
        for label, message in (("missing", missing), ("renamed", renamed)):
            with self.subTest(label=label):
                with self.assertRaisesRegex(
                    self.host_authority.InventoryError, "interface drift"
                ):
                    self.normalize([message])

    def test_rejects_missing_primary_span(self):
        with self.assertRaisesRegex(self.host_authority.InventoryError, "primary span"):
            self.normalize([diagnostic(primary=False)])

    def test_rejects_duplicate_primary_spans(self):
        message = diagnostic()
        message["message"]["spans"].append(
            copy.deepcopy(message["message"]["spans"][0])
        )
        with self.assertRaisesRegex(self.host_authority.InventoryError, "primary span"):
            self.normalize([message])

    def test_rejects_paths_outside_workspace_root(self):
        with self.assertRaisesRegex(self.host_authority.InventoryError, "outside root"):
            self.normalize([diagnostic(file_name="/private/tmp/outside.rs")])

    def test_rejects_malformed_json(self):
        with self.assertRaisesRegex(self.host_authority.InventoryError, "malformed JSON"):
            self.normalize(["{"])

    def test_rejects_duplicate_diagnostic_identity(self):
        message = diagnostic()
        with self.assertRaisesRegex(self.host_authority.InventoryError, "duplicate"):
            self.normalize([message, copy.deepcopy(message)])

    def test_rejects_conflicting_catalog_reason_children(self):
        message = diagnostic(
            children=[
                {"level": "note", "message": "HA-CATALOG-PROCESS-ID: first"},
                {"level": "note", "message": "HA-CATALOG-OTHER-ID: second"},
            ]
        )
        with self.assertRaisesRegex(self.host_authority.InventoryError, "catalog"):
            self.normalize([message])


class ProfileMergeTest(unittest.TestCase):
    def setUp(self):
        self.host_authority = load_host_authority()

    def test_merges_profiles_only_for_exact_diagnostic_identity(self):
        first = actual_row(profiles=["macos-hvf-default"])
        second = actual_row(profiles=["macos-runtime-default"])
        other = actual_row(
            operation="libc::waitpid",
            location=source(line=20),
            profiles=["macos-runtime-default"],
        )
        self.assertEqual(
            self.host_authority.merge_profiles([[first], [second, other]]),
            [
                other,
                actual_row(
                    profiles=["macos-hvf-default", "macos-runtime-default"]
                ),
            ],
        )

    def test_rejects_duplicate_identity_in_one_profile(self):
        row = actual_row()
        with self.assertRaisesRegex(self.host_authority.InventoryError, "duplicate"):
            self.host_authority.merge_profiles([[row, copy.deepcopy(row)]])

    def test_rejects_catalog_disagreement_for_same_identity(self):
        first = actual_row(
            catalog_id="HA-CATALOG-PROCESS-ID", profiles=["macos-hvf-default"]
        )
        second = actual_row(
            catalog_id="HA-CATALOG-OTHER", profiles=["macos-runtime-default"]
        )
        with self.assertRaisesRegex(self.host_authority.InventoryError, "catalog"):
            self.host_authority.merge_profiles([[first], [second]])


class ReviewValidationTest(unittest.TestCase):
    def setUp(self):
        self.host_authority = load_host_authority()
        self.executed = ["macos-hvf-default"]
        self.required = ["linux-runtime", "macos-hvf-default"]

    def validate(self, actual, expected):
        self.host_authority.validate(actual, expected, self.executed, self.required)

    def test_accepts_exact_review_shape(self):
        self.validate([actual_row()], [reviewed_row()])

    def test_null_catalog_id_is_rejected_without_bypass(self):
        actual = [actual_row(catalog_id=None)]
        expected = [reviewed_row(catalog_id=None)]
        with self.assertRaisesRegex(self.host_authority.InventoryError, "catalog ID"):
            self.validate(actual, expected)

    def test_partial_check_compares_only_executed_profile_membership(self):
        expected = reviewed_row(profiles=["linux-runtime", "macos-hvf-default"])
        self.validate([actual_row()], [expected])

    def test_accepts_nonempty_executed_subset_of_required_profiles(self):
        self.host_authority.validate(
            [actual_row()],
            [reviewed_row()],
            ["macos-hvf-default"],
            ["linux-runtime", "macos-hvf-default"],
        )

    def test_rejects_executed_profile_outside_required_profiles(self):
        with self.assertRaisesRegex(
            self.host_authority.InventoryError, "outside required"
        ):
            self.host_authority.validate(
                [actual_row()],
                [reviewed_row()],
                ["macos-hvf-default", "undeclared-profile"],
                ["macos-hvf-default"],
            )

    def test_rejects_actual_or_expected_profile_outside_required_profiles(self):
        cases = {
            "actual": (
                [actual_row(profiles=["undeclared-profile"])],
                [reviewed_row()],
            ),
            "expected": (
                [actual_row()],
                [reviewed_row(profiles=["undeclared-profile"])],
            ),
        }
        for label, (actual, expected) in cases.items():
            with self.subTest(label=label):
                with self.assertRaisesRegex(
                    self.host_authority.InventoryError, "outside required"
                ):
                    self.host_authority.validate(
                        actual,
                        expected,
                        ["macos-hvf-default"],
                        ["macos-hvf-default"],
                    )

    def test_rejects_new_removed_and_retargeted_rows(self):
        cases = {
            "new": (
                [
                    actual_row(),
                    actual_row(operation="libc::waitpid", location=source(line=20)),
                ],
                [reviewed_row()],
            ),
            "removed": ([], [reviewed_row()]),
            "retargeted": ([actual_row(location=source(line=11))], [reviewed_row()]),
        }
        for label, (actual, expected) in cases.items():
            with self.subTest(label=label):
                with self.assertRaisesRegex(
                    self.host_authority.InventoryError, "inventory drift"
                ):
                    self.validate(actual, expected)

    def test_rejects_review_id_collision_across_operations(self):
        first_actual = actual_row()
        second_actual = actual_row(
            operation="libc::waitpid", location=source(line=20)
        )
        first_review = reviewed_row()
        second_review = reviewed_row(
            review_id="HA-000001",
            operation="libc::waitpid",
            location=source(line=20),
        )
        with self.assertRaisesRegex(self.host_authority.InventoryError, "review ID"):
            self.validate(
                [first_actual, second_actual], [first_review, second_review]
            )

    def test_rejects_legacy_unreachable_for_compiled_product_row(self):
        row = reviewed_row(
            classification="legacy_unreachable",
            evidence={
                "authority": "compile_time_exclusion",
                "resource": "claimed compile-time exclusion",
            },
        )
        with self.assertRaisesRegex(self.host_authority.InventoryError, "legacy"):
            self.validate([actual_row()], [row])

    def test_rejects_empty_extra_generic_and_schema_mismatched_evidence(self):
        cases = {
            "empty": {},
            "extra": {
                "authority": "guest_answer",
                "resource": "guest-visible process identity",
                "claim": "extra",
            },
            "generic": {"authority": "guest_answer", "resource": "guest answer"},
            "schema-mismatch": {
                "authority": "authenticated_carrier",
                "resource": "current vCPU worker host thread",
            },
        }
        for label, evidence in cases.items():
            with self.subTest(label=label):
                with self.assertRaisesRegex(
                    self.host_authority.InventoryError, "evidence"
                ):
                    self.validate([actual_row()], [reviewed_row(evidence=evidence)])

    def test_rejects_empty_rationale(self):
        with self.assertRaisesRegex(self.host_authority.InventoryError, "rationale"):
            self.validate([actual_row()], [reviewed_row(rationale="")])

    def test_accepts_each_nonlegacy_evidence_schema(self):
        cases = [
            (
                "forbidden_semantic",
                {"authority": "host_target", "resource": "selected host child PID"},
            ),
            (
                "declared_backing",
                {
                    "authority": "authorized_backing",
                    "resource": "validated rootfs directory entry",
                },
            ),
            (
                "declared_substrate",
                {
                    "authority": "authenticated_carrier",
                    "resource": "current vCPU worker host thread",
                },
            ),
        ]
        for classification, evidence in cases:
            with self.subTest(classification=classification):
                self.validate(
                    [actual_row()],
                    [
                        reviewed_row(
                            classification=classification,
                            evidence=evidence,
                            rationale="This call acts on the one named resource.",
                        )
                    ],
                )


class RefreshTest(unittest.TestCase):
    def setUp(self):
        self.host_authority = load_host_authority()

    def test_new_row_refreshes_unreviewed_with_next_monotonic_id(self):
        old = reviewed_row(review_id="HA-000007")
        new = actual_row(operation="libc::waitpid", location=source(line=20))
        refreshed = self.host_authority.refresh([actual_row(), new], [old], True)
        self.assertEqual(refreshed[1], old)
        self.assertEqual(
            refreshed[0],
            reviewed_row(
                review_id="HA-000008",
                operation="libc::waitpid",
                location=source(line=20),
                classification="unreviewed",
                evidence={},
                rationale="",
            ),
        )

    def test_same_identity_preserves_review_and_updates_profiles(self):
        old = reviewed_row(profiles=["macos-hvf-default"])
        actual = actual_row(profiles=["linux-runtime", "macos-hvf-default"])
        refreshed = self.host_authority.refresh([actual], [old], True)
        self.assertEqual(
            refreshed,
            [{**old, "profiles": ["linux-runtime", "macos-hvf-default"]}],
        )

    def test_catalog_id_is_part_of_exact_review_identity(self):
        old = reviewed_row(catalog_id="HA-CATALOG-PROCESS-ID")
        changed = actual_row(catalog_id="HA-CATALOG-PROCESS-ID-V2")
        self.assertNotEqual(
            self.host_authority.diagnostic_identity(old),
            self.host_authority.diagnostic_identity(changed),
        )

    def test_same_start_changed_end_span_does_not_inherit_review(self):
        changed_end = actual_row(location=source(byte_end=121))
        refreshed = self.host_authority.refresh(
            [changed_end], [reviewed_row(review_id="HA-000003")], True
        )
        self.assertEqual(refreshed[0]["classification"], "unreviewed")
        self.assertEqual(refreshed[0]["review_id"], "HA-000004")

    def test_changed_operation_source_or_expansion_never_inherits_review(self):
        changed = [
            actual_row(operation="libc::waitpid"),
            actual_row(location=source(line=11)),
            actual_row(
                expansion=source(
                    "crates/example/src/macro.rs",
                    30,
                    9,
                    byte_start=300,
                    byte_end=330,
                )
            ),
        ]
        for actual in changed:
            with self.subTest(actual=actual):
                refreshed = self.host_authority.refresh(
                    [actual], [reviewed_row(review_id="HA-000003")], True
                )
                self.assertEqual(refreshed[0]["classification"], "unreviewed")
                self.assertEqual(refreshed[0]["review_id"], "HA-000004")

    def test_catalog_id_change_cannot_inherit_or_implicitly_remove_review(self):
        changed = actual_row(catalog_id="HA-CATALOG-PROCESS-ID-V2")
        refreshed = self.host_authority.refresh(
            [changed],
            [reviewed_row(catalog_id="HA-CATALOG-PROCESS-ID")],
            True,
        )
        self.assertEqual(refreshed[0]["classification"], "unreviewed")
        self.assertNotEqual(refreshed[0]["review_id"], "HA-000001")

    def test_complete_refresh_omits_removed_reviewed_rows(self):
        self.assertEqual(
            self.host_authority.refresh([], [reviewed_row()], True), []
        )

    def test_partial_refresh_fails_closed(self):
        with self.assertRaisesRegex(self.host_authority.InventoryError, "partial"):
            self.host_authority.refresh([actual_row()], [reviewed_row()], False)

    def test_complete_refresh_drops_removed_rows_and_unreviews_retargeted_rows(self):
        prior = reviewed_row(review_id="HA-000007")
        retargeted = actual_row(location=source(line=11))
        refreshed = self.host_authority.refresh([retargeted], [prior], True)
        self.assertEqual(len(refreshed), 1)
        self.assertEqual(refreshed[0]["source"]["line"], 11)
        self.assertEqual(refreshed[0]["classification"], "unreviewed")
        self.assertEqual(refreshed[0]["evidence"], {})
        self.assertEqual(refreshed[0]["rationale"], "")
        self.assertNotEqual(refreshed[0]["review_id"], prior["review_id"])


class FakeRunner:
    def __init__(self, cargo_stdout: str | None = None):
        self.calls = []
        self.cargo_stdout = (
            json.dumps({"reason": "build-finished", "success": True}) + "\n"
            if cargo_stdout is None
            else cargo_stdout
        )
        self.cargo_returncode = 0
        self.cargo_stderr = ""
        self.rustc_version = (
            "rustc 1.96.0 (abcdef 2026-08-01)\n"
            "binary: rustc\n"
            "commit-hash: abcdef\n"
            "commit-date: 2026-08-01\n"
            "host: aarch64-apple-darwin\n"
            "release: 1.96.0\n"
            "LLVM version: 21.1.0\n"
        )
        self.clippy_version = "clippy 0.1.96 (abcdef 2026-08-01)\n"

    def __call__(self, argv, **kwargs):
        argv = list(argv)
        self.calls.append((argv, kwargs))
        if argv == ["rustc", "-Vv"]:
            return subprocess.CompletedProcess(argv, 0, self.rustc_version, "")
        if (
            argv[0] == "cargo"
            and argv[-2:] == ["clippy", "-V"]
            and "--manifest-path" not in argv
        ):
            return subprocess.CompletedProcess(argv, 0, self.clippy_version, "")
        return subprocess.CompletedProcess(
            argv,
            self.cargo_returncode,
            self.cargo_stdout,
            self.cargo_stderr,
        )


class MatrixOrchestrationTest(unittest.TestCase):
    def setUp(self):
        self.host_authority = load_host_authority()

    def load(self):
        return self.host_authority.load_matrix(MATRIX)

    def write_matrix(self, payload):
        temporary = tempfile.TemporaryDirectory()
        path = Path(temporary.name) / "matrix.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        self.addCleanup(temporary.cleanup)
        return path

    def canonical_payload(self):
        return {
            "schema": 1,
            "toolchain": {
                "rustc_release": "1.96.0",
                "clippy_release": "0.1.96",
            },
            "required_profiles": list(REQUIRED_PROFILES),
            "profiles": [
                {
                    "id": profile_id,
                    "host": profile_id.split("-", 1)[0],
                    "host_triple": HOST_TRIPLES[profile_id.split("-", 1)[0]],
                    "command": list(EXPECTED_COMMANDS[profile_id]),
                }
                for profile_id in REQUIRED_PROFILES
            ],
        }

    def write_minimal_workspace(self, root, channel="1.96.0"):
        root.mkdir(parents=True, exist_ok=True)
        (root / "Cargo.toml").write_text("[workspace]\n", encoding="utf-8")
        checked_config = root / ".cargo" / "config.toml"
        checked_config.parent.mkdir()
        checked_config.write_text("[build]\n", encoding="utf-8")
        if channel is not None:
            (root / "rust-toolchain.toml").write_text(
                f'[toolchain]\nchannel = "{channel}"\n', encoding="utf-8"
            )
        return root

    def test_checked_matrix_declares_exact_nine_product_profiles(self):
        matrix = self.load()
        self.assertEqual(list(matrix.required_profiles), REQUIRED_PROFILES)
        self.assertEqual(list(matrix.profiles), REQUIRED_PROFILES)
        self.assertEqual(matrix.rustc_release, "1.96.0")
        self.assertEqual(matrix.clippy_release, "0.1.96")
        self.assertEqual(
            {
                profile_id: profile.host_triple
                for profile_id, profile in matrix.profiles.items()
            },
            {
                profile_id: HOST_TRIPLES[profile_id.split("-", 1)[0]]
                for profile_id in REQUIRED_PROFILES
            },
        )
        self.assertEqual(
            {profile_id: list(profile.command) for profile_id, profile in matrix.profiles.items()},
            EXPECTED_COMMANDS,
        )

    def test_matrix_rejects_duplicate_or_missing_profile_ids(self):
        duplicate_required = self.canonical_payload()
        duplicate_required["required_profiles"].append("macos-cli-default")
        duplicate_profile = self.canonical_payload()
        duplicate_profile["profiles"].append(
            copy.deepcopy(duplicate_profile["profiles"][0])
        )
        missing_profile = self.canonical_payload()
        missing_profile["profiles"].pop()
        for label, payload in (
            ("duplicate required", duplicate_required),
            ("duplicate profile", duplicate_profile),
            ("missing profile", missing_profile),
        ):
            with self.subTest(label=label):
                with self.assertRaisesRegex(
                    self.host_authority.InventoryError, "profile"
                ):
                    self.host_authority.load_matrix(self.write_matrix(payload))

    def test_matrix_rejects_commands_missing_json_or_force_warn(self):
        cases = {
            "json": "--message-format=json",
            "force-warn": "--force-warn",
        }
        for label, argument in cases.items():
            payload = self.canonical_payload()
            payload["profiles"][0]["command"].remove(argument)
            with self.subTest(label=label):
                with self.assertRaisesRegex(
                    self.host_authority.InventoryError, f"(?i){label}"
                ):
                    self.host_authority.load_matrix(self.write_matrix(payload))

    def test_run_profile_uses_exact_argv_workspace_and_isolated_target(self):
        profile = self.load().profiles["macos-hvf-default"]
        runner = FakeRunner()
        messages = self.host_authority.run_profile(
            profile, runner=runner, root=ROOT, current_host="macos"
        )
        self.assertEqual(messages, [{"reason": "build-finished", "success": True}])
        self.assertEqual(
            runner.calls[0][0], expected_profile_command(profile.id)
        )
        kwargs = runner.calls[0][1]
        self.assertFalse(Path(kwargs["cwd"]).is_relative_to(ROOT))
        self.assertFalse(kwargs["shell"])
        self.assertTrue(kwargs["capture_output"])
        self.assertTrue(kwargs["text"])
        self.assertFalse(kwargs["check"])
        self.assertEqual(
            kwargs["env"]["CARGO_TARGET_DIR"],
            str(ROOT / "target" / "host-authority-census" / profile.id),
        )

    def test_every_runner_environment_removes_ambient_build_authority(self):
        matrix = self.load()
        profile = matrix.profiles["macos-hvf-default"]
        runner = FakeRunner()
        with mock.patch.dict(os.environ, AMBIENT_BUILD_AUTHORITY, clear=False):
            self.host_authority.verify_toolchain(matrix, runner=runner)
            self.host_authority.run_profile(
                profile, runner=runner, root=ROOT, current_host="macos"
            )
        for argv, kwargs in runner.calls:
            with self.subTest(argv=argv):
                environment = kwargs["env"]
                self.assertIn("PATH", environment)
                self.assertIn("CARGO_HOME", environment)
                for variable in AMBIENT_BUILD_AUTHORITY:
                    if variable != "RUSTUP_TOOLCHAIN":
                        self.assertNotIn(variable, environment)
                self.assertEqual(environment["RUSTUP_TOOLCHAIN"], "1.96.0")
                self.assertNotIn(
                    "aarch64-apple-darwin", environment["RUSTUP_TOOLCHAIN"]
                )
        profile_environment = runner.calls[-1][1]["env"]
        self.assertEqual(
            profile_environment["CARGO_TARGET_DIR"],
            str(ROOT / "target" / "host-authority-census" / profile.id),
        )

    def test_profile_uses_only_isolated_cargo_home_and_checked_config(self):
        matrix = self.load()
        profile = matrix.profiles["macos-hvf-default"]
        original_command = profile.command
        with tempfile.TemporaryDirectory() as directory:
            ancestor = Path(directory) / "ancestor"
            root = ancestor / "nested" / "worktree"
            self.write_minimal_workspace(root)
            checked_config = root / ".cargo" / "config.toml"
            checked_config.parent.mkdir(exist_ok=True)
            checked_config.write_text(
                '[build]\nrustflags = ["-C", "force-frame-pointers=yes"]\n',
                encoding="utf-8",
            )
            checked_config_text = checked_config.read_text(encoding="utf-8")
            ancestor_config = ancestor / ".cargo" / "config.toml"
            ancestor_config.parent.mkdir()
            ancestor_config.write_text(
                '[build]\nrustc = "/tmp/ancestor-rustc"\n', encoding="utf-8"
            )
            ambient_home = Path(directory) / "ambient-cargo-home"
            ambient_home.mkdir()
            (ambient_home / "config.toml").write_text(
                '[build]\nrustc = "/tmp/ambient-rustc"\n', encoding="utf-8"
            )
            (ambient_home / "credentials.toml").write_text(
                "[registry]\ntoken = 'secret'\n", encoding="utf-8"
            )
            canonical_home = Path(directory) / "canonical-user-home"
            canonical_cargo = canonical_home / ".cargo"
            for cache_name in ("registry", "git"):
                cache = canonical_cargo / cache_name
                cache.mkdir(parents=True)
                (cache / "cache-sentinel").write_text(
                    cache_name, encoding="utf-8"
                )
            for forbidden in ("config.toml", "credentials.toml", "env", "bin"):
                path = canonical_cargo / forbidden
                if "." in forbidden:
                    path.write_text("forbidden\n", encoding="utf-8")
                else:
                    path.mkdir()
            fake = FakeRunner()
            observations = []

            def runner(argv, **kwargs):
                cargo_home = Path(kwargs["env"]["CARGO_HOME"])
                observations.append(
                    {
                        "argv": list(argv),
                        "cwd": Path(kwargs["cwd"]),
                        "cargo_home": cargo_home,
                        "rustup_home": Path(kwargs["env"]["RUSTUP_HOME"]),
                        "home_entries": sorted(
                            path.relative_to(cargo_home).as_posix()
                            for path in cargo_home.rglob("*")
                        ),
                        "cache_targets": {
                            name: (cargo_home / name).resolve()
                            for name in ("registry", "git")
                            if (cargo_home / name).exists()
                        },
                    }
                )
                return fake(argv, **kwargs)

            with mock.patch.object(
                pwd,
                "getpwuid",
                return_value=mock.Mock(pw_dir=str(canonical_home)),
            ), mock.patch.dict(
                os.environ,
                {
                    "HOME": str(ambient_home),
                    "CARGO_HOME": str(ambient_home),
                    "RUSTUP_HOME": str(ambient_home / "rustup"),
                },
                clear=False,
            ):
                self.host_authority.run_profile(
                    profile,
                    runner=runner,
                    root=root,
                    current_host="macos",
                )

        self.assertEqual(profile.command, original_command)
        self.assertEqual(len(observations), 1)
        observed = observations[0]
        self.assertNotEqual(observed["cargo_home"], ambient_home)
        self.assertEqual(observed["home_entries"], ["git", "registry"])
        self.assertEqual(
            observed["cache_targets"],
            {
                "registry": (canonical_cargo / "registry").resolve(),
                "git": (canonical_cargo / "git").resolve(),
            },
        )
        self.assertEqual(
            observed["rustup_home"], canonical_home.resolve() / ".rustup"
        )
        self.assertFalse(observed["cwd"].is_relative_to(ancestor))
        self.assertEqual(
            observed["argv"][:4],
            ["cargo", "--config", str(checked_config.resolve()), "clippy"],
        )
        manifest_index = observed["argv"].index("--manifest-path")
        self.assertEqual(
            observed["argv"][manifest_index + 1],
            str((root / "Cargo.toml").resolve()),
        )
        self.assertIn("force-frame-pointers=yes", checked_config_text)

    def test_hostile_temp_ancestor_cannot_choose_cargo_cwd_or_home(self):
        matrix = self.load()
        profile = matrix.profiles["macos-hvf-default"]
        with tempfile.TemporaryDirectory() as directory:
            temporary = Path(directory)
            root = temporary / "worktree"
            self.write_minimal_workspace(root)
            checked_config = root / ".cargo" / "config.toml"
            checked_config.parent.mkdir(exist_ok=True)
            checked_config.write_text(
                '[build]\nrustflags = ["-C", "force-frame-pointers=yes"]\n',
                encoding="utf-8",
            )
            hostile_parent = temporary / "hostile-temp-parent"
            hostile_tmp = hostile_parent / "tmp"
            hostile_tmp.mkdir(parents=True)
            hostile_config = hostile_parent / ".cargo" / "config.toml"
            hostile_config.parent.mkdir()
            hostile_config.write_text(
                '[build]\nrustc = "/tmp/hostile-rustc"\n', encoding="utf-8"
            )
            canonical_home = temporary / "canonical-home"
            canonical_home.mkdir()
            fake = FakeRunner()
            observations = []

            def runner(argv, **kwargs):
                observations.append(
                    {
                        "cwd": Path(kwargs["cwd"]),
                        "environment": dict(kwargs["env"]),
                    }
                )
                return fake(argv, **kwargs)

            with mock.patch.object(
                pwd,
                "getpwuid",
                return_value=mock.Mock(pw_dir=str(canonical_home)),
            ), mock.patch.object(tempfile, "tempdir", None), mock.patch.dict(
                os.environ,
                {
                    "TMPDIR": str(hostile_tmp),
                    "TEMP": str(hostile_tmp),
                    "TMP": str(hostile_tmp),
                },
                clear=False,
            ):
                self.host_authority.run_profile(
                    profile,
                    runner=runner,
                    root=root,
                    current_host="macos",
                )

        self.assertEqual(len(observations), 1)
        observed = observations[0]
        self.assertEqual(observed["cwd"], Path("/"))
        cargo_home = Path(observed["environment"]["CARGO_HOME"])
        target_dir = Path(observed["environment"]["CARGO_TARGET_DIR"])
        census_root = root.resolve() / "target" / "host-authority-census"
        self.assertTrue(cargo_home.is_relative_to(census_root))
        self.assertTrue(target_dir.is_absolute())
        self.assertTrue(target_dir.is_relative_to(census_root))
        self.assertFalse(cargo_home.is_relative_to(hostile_parent))
        for variable in ("TMPDIR", "TEMP", "TMP"):
            self.assertNotIn(variable, observed["environment"])

    def test_cargo_root_cwd_rejects_configs_nonunix_and_nondirectory(self):
        self.assertEqual(self.host_authority.CARGO_CWD, Path("/"))
        with tempfile.TemporaryDirectory() as directory:
            fake_root = Path(directory) / "root"
            fake_root.mkdir()
            for config_name in ("config", "config.toml"):
                cargo = fake_root / ".cargo"
                cargo.mkdir(exist_ok=True)
                config = cargo / config_name
                config.write_text("hostile\n", encoding="utf-8")
                with self.subTest(config_name=config_name):
                    with self.assertRaisesRegex(
                        self.host_authority.InventoryError, "Cargo config"
                    ):
                        self.host_authority._authenticated_cargo_cwd(fake_root)
                config.unlink()
            not_directory = Path(directory) / "not-a-directory"
            not_directory.write_text("file\n", encoding="utf-8")
            with self.assertRaisesRegex(
                self.host_authority.InventoryError, "directory"
            ):
                self.host_authority._authenticated_cargo_cwd(not_directory)
        with mock.patch.object(self.host_authority.os, "name", "nt"):
            with self.assertRaisesRegex(
                self.host_authority.InventoryError, "Unix"
            ):
                self.host_authority._authenticated_cargo_cwd(Path("/"))

    def test_run_profile_preserves_stderr_on_compile_failure(self):
        profile = self.load().profiles["macos-hvf-default"]
        runner = FakeRunner()
        runner.cargo_returncode = 17
        runner.cargo_stderr = "specific compiler failure\n"
        with self.assertRaisesRegex(
            self.host_authority.InventoryError, "specific compiler failure"
        ):
            self.host_authority.run_profile(
                profile, runner=runner, root=ROOT, current_host="macos"
            )

    def test_run_profile_rejects_malformed_or_empty_json_stdout(self):
        profile = self.load().profiles["macos-hvf-default"]
        for label, stdout in (("malformed", "not json\n"), ("empty", "")):
            with self.subTest(label=label):
                with self.assertRaisesRegex(
                    self.host_authority.InventoryError, "JSON"
                ):
                    self.host_authority.run_profile(
                        profile,
                        runner=FakeRunner(stdout),
                        root=ROOT,
                        current_host="macos",
                    )

    def test_host_mismatch_is_unavailable_without_running(self):
        profile = self.load().profiles["linux-cli"]
        runner = FakeRunner()
        with self.assertRaisesRegex(self.host_authority.InventoryError, "unavailable"):
            self.host_authority.run_profile(
                profile, runner=runner, root=ROOT, current_host="macos"
            )
        self.assertEqual(runner.calls, [])

    def test_tool_identities_are_pinned_and_checked_before_profiles(self):
        matrix = self.load()
        runner = FakeRunner()
        identities = self.host_authority.verify_toolchain(matrix, runner=runner)
        self.assertEqual(
            identities,
            {
                "rustc": runner.rustc_version.strip(),
                "clippy": "clippy 0.1.96 (abcdef 2026-08-01)",
                "host_triple": "aarch64-apple-darwin",
            },
        )
        self.assertEqual(
            [call[0] for call in runner.calls],
            [["rustc", "-Vv"], expected_clippy_version_command()],
        )
        for _argv, kwargs in runner.calls:
            self.assertEqual(kwargs["env"]["RUSTUP_TOOLCHAIN"], "1.96.0")
        mismatch = FakeRunner()
        mismatch.clippy_version = "clippy 0.1.95 (stale)\n"
        with self.assertRaisesRegex(
            self.host_authority.InventoryError, "0.1.96"
        ):
            self.host_authority.verify_toolchain(matrix, runner=mismatch)

    def test_checked_toolchain_channel_is_required_and_matches_matrix_before_runner(
        self,
    ):
        matrix = self.load()
        selected = ["macos-hvf-default"]
        cases = (
            ("missing", None, matrix),
            ("malformed", "__MALFORMED__", matrix),
            (
                "matrix mismatch",
                "1.96.0",
                matrix._replace(rustc_release="1.96.1"),
            ),
        )
        for label, channel, checked_matrix in cases:
            with self.subTest(
                label=label
            ), tempfile.TemporaryDirectory() as directory:
                root = Path(directory) / "worktree"
                self.write_minimal_workspace(
                    root,
                    None if channel in (None, "__MALFORMED__") else channel,
                )
                if channel == "__MALFORMED__":
                    (root / "rust-toolchain.toml").write_text(
                        "[toolchain\nchannel = 1.96.0\n", encoding="utf-8"
                    )
                runner = FakeRunner(json.dumps(diagnostic()) + "\n")
                with self.assertRaisesRegex(
                    self.host_authority.InventoryError, "toolchain|TOML|channel"
                ):
                    self.host_authority.run_census(
                        checked_matrix,
                        selected,
                        FIXTURE_CATALOG,
                        runner=runner,
                        root=root,
                        current_host="macos",
                    )
                self.assertEqual(runner.calls, [])

    def test_tool_release_tokens_and_rustc_host_must_match_exactly(self):
        matrix = self.load()
        cases = []
        for version in ("0.1.960", "0.1.96-nightly", "0.1.96.1"):
            runner = FakeRunner()
            runner.clippy_version = f"clippy {version} (attacker)\n"
            cases.append((f"clippy {version}", runner))
        for version in ("1.96.00", "1.96.0-nightly", "1.96.0.1"):
            runner = FakeRunner()
            runner.rustc_version = runner.rustc_version.replace(
                "release: 1.96.0", f"release: {version}"
            )
            cases.append((f"rustc {version}", runner))
        wrong_host = FakeRunner()
        wrong_host.rustc_version = wrong_host.rustc_version.replace(
            "host: aarch64-apple-darwin", "host: x86_64-apple-darwin"
        )
        cases.append(("wrong host", wrong_host))
        for label, runner in cases:
            with self.subTest(label=label):
                with self.assertRaises(self.host_authority.InventoryError):
                    self.host_authority.verify_toolchain(
                        matrix,
                        runner=runner,
                        required_host_triple="aarch64-apple-darwin",
                    )

    def test_profile_selection_is_nonempty_local_and_supports_globs(self):
        matrix = self.load()
        expected = REQUIRED_PROFILES[:3]
        self.assertEqual(
            self.host_authority.select_profiles(matrix, None, "macos"),
            expected,
        )
        self.assertEqual(
            self.host_authority.select_profiles(matrix, "macos-*", "macos"),
            expected,
        )
        for selector in ("", "does-not-exist"):
            with self.subTest(selector=selector):
                with self.assertRaisesRegex(
                    self.host_authority.InventoryError, "profile"
                ):
                    self.host_authority.select_profiles(matrix, selector, "macos")
        with self.assertRaisesRegex(self.host_authority.InventoryError, "unavailable"):
            self.host_authority.select_profiles(matrix, "linux-*", "macos")

    def test_census_uses_fake_catalog_and_records_pending_profiles(self):
        matrix = self.load()
        runner = FakeRunner(json.dumps(diagnostic()) + "\n")
        selected = self.host_authority.select_profiles(
            matrix, "macos-hvf-default", "macos"
        )
        result = self.host_authority.run_census(
            matrix,
            selected,
            FIXTURE_CATALOG,
            runner=runner,
            root=ROOT,
            current_host="macos",
        )
        self.assertEqual(result["executed_profiles"], ["macos-hvf-default"])
        self.assertEqual(
            result["pending_profiles"],
            [profile for profile in REQUIRED_PROFILES if profile != "macos-hvf-default"],
        )
        self.assertEqual(
            result["rows"],
            [actual_row(catalog_id="HA-CATALOG-FIXTURE-PROCESS-ID")],
        )
        self.assertEqual(
            [call[0] for call in runner.calls[:3]],
            [
                ["rustc", "-Vv"],
                expected_clippy_version_command(),
                expected_profile_command("macos-hvf-default"),
            ],
        )
        for _argv, kwargs in runner.calls:
            self.assertEqual(kwargs["env"]["RUSTUP_TOOLCHAIN"], "1.96.0")

    def test_census_rejects_rustc_host_before_profile_execution(self):
        matrix = self.load()
        runner = FakeRunner(json.dumps(diagnostic()) + "\n")
        runner.rustc_version = runner.rustc_version.replace(
            "host: aarch64-apple-darwin", "host: x86_64-apple-darwin"
        )
        selected = self.host_authority.select_profiles(
            matrix, "macos-hvf-default", "macos"
        )
        with self.assertRaisesRegex(
            self.host_authority.InventoryError, "host triple mismatch"
        ):
            self.host_authority.run_census(
                matrix,
                selected,
                FIXTURE_CATALOG,
                runner=runner,
                root=ROOT,
                current_host="macos",
            )
        self.assertEqual(len(runner.calls), 2)

    def test_census_resolves_profile_ids_from_the_checked_matrix(self):
        matrix = self.load()
        forged = self.host_authority.Profile(
            "macos-hvf-default",
            "macos",
            "aarch64-apple-darwin",
            (
                "cargo",
                "clippy",
                "-p",
                "attacker-package",
                "--target",
                "aarch64-apple-darwin",
                "--lib",
                "--message-format=json",
                "--",
                "--force-warn",
                "clippy::disallowed_methods",
            ),
        )
        runner = FakeRunner(json.dumps(diagnostic()) + "\n")
        with self.assertRaisesRegex(
            self.host_authority.InventoryError, "profile IDs"
        ):
            self.host_authority.run_census(
                matrix,
                [forged],
                FIXTURE_CATALOG,
                runner=runner,
                root=ROOT,
                current_host="macos",
            )
        self.assertEqual(runner.calls, [])

    def test_partial_candidate_is_unreviewed_marked_partial_and_nonzero(self):
        matrix = self.load()
        runner = FakeRunner(json.dumps(diagnostic()) + "\n")
        expected = [
            reviewed_row(
                review_id="HA-999999",
                profiles=["linux-runtime", "macos-hvf-default"],
            )
        ]
        with tempfile.TemporaryDirectory() as directory:
            candidate = Path(directory) / "candidate.json"
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                status = self.host_authority.main(
                    [
                        "--profiles",
                        "macos-hvf-default",
                        "--refresh-candidate",
                        str(candidate),
                    ],
                    runner=runner,
                    matrix=matrix,
                    operation_catalog=FIXTURE_CATALOG,
                    catalog_manifest=FIXTURE_CATALOG,
                    expected=expected,
                    capture_receipt=injected_receipt(expected),
                    current_host="macos",
                    root=ROOT,
                )
            document = json.loads(candidate.read_text(encoding="utf-8"))
        self.assertNotEqual(status, 0)
        self.assertFalse(document["complete"])
        self.assertEqual(document["executed_profiles"], ["macos-hvf-default"])
        self.assertEqual(document["rows"][0]["classification"], "unreviewed")
        self.assertEqual(document["rows"][0]["evidence"], {})
        self.assertEqual(document["rows"][0]["rationale"], "")
        self.assertNotEqual(document["rows"][0]["review_id"], "HA-999999")
        self.assertIn("partial", stderr.getvalue())

    def test_refresh_candidate_replaces_stale_receipt_after_running_compiler(self):
        matrix = self.load()
        runner = FakeRunner(json.dumps(diagnostic()) + "\n")
        inventory = [
            reviewed_row(
                location=source(line=11),
                profiles=["macos-hvf-default"],
                catalog_id="HA-CATALOG-FIXTURE-PROCESS-ID",
                rationale=(
                    "At crates/example/src/lib.rs:11, std::process::id acts on "
                    "the reviewed guest-visible process identity."
                ),
            )
        ]
        stale_receipt = injected_receipt(
            [
                reviewed_row(
                    location=source(line=12),
                    profiles=["macos-hvf-default"],
                    catalog_id="HA-CATALOG-FIXTURE-PROCESS-ID",
                )
            ]
        )

        static_runner = FakeRunner()
        static_status = self.host_authority.main(
            ["--static"],
            runner=static_runner,
            matrix=matrix,
            operation_catalog=FIXTURE_CATALOG,
            catalog_manifest=FIXTURE_CATALOG,
            expected=inventory,
            capture_receipt=stale_receipt,
            current_host="macos",
            root=ROOT,
        )
        self.assertNotEqual(static_status, 0)
        self.assertEqual(static_runner.calls, [])

        check_runner = FakeRunner(json.dumps(diagnostic()) + "\n")
        check_status = self.host_authority.main(
            ["--check", "--profiles", "macos-hvf-default"],
            runner=check_runner,
            matrix=matrix,
            operation_catalog=FIXTURE_CATALOG,
            catalog_manifest=FIXTURE_CATALOG,
            expected=inventory,
            capture_receipt=stale_receipt,
            current_host="macos",
            root=ROOT,
        )
        self.assertNotEqual(check_status, 0)
        self.assertEqual(check_runner.calls, [])

        with tempfile.TemporaryDirectory() as directory:
            candidate = Path(directory) / "candidate.json"
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                refresh_status = self.host_authority.main(
                    [
                        "--refresh-candidate",
                        str(candidate),
                        "--profiles",
                        "macos-hvf-default",
                    ],
                    runner=runner,
                    matrix=matrix,
                    operation_catalog=FIXTURE_CATALOG,
                    catalog_manifest=FIXTURE_CATALOG,
                    expected=inventory,
                    capture_receipt=stale_receipt,
                    current_host="macos",
                    root=ROOT,
                )
            document = json.loads(candidate.read_text(encoding="utf-8"))

        self.assertNotEqual(refresh_status, 0)
        self.assertEqual(len(runner.calls), 3)
        self.assertFalse(document["complete"])
        self.assertEqual(document["rows"][0]["classification"], "unreviewed")
        capture = document["capture_receipt"]
        self.assertEqual(capture["kind"], "host-authority-compiler-capture")
        self.assertEqual(capture["rows"], [actual_row(catalog_id="HA-CATALOG-FIXTURE-PROCESS-ID")])
        self.assertEqual(
            capture["diagnostic_counts"],
            {"macos-hvf-default": 1, "merged": 1},
        )
        self.assertEqual(
            capture["profiles"],
            [
                {
                    "id": "macos-hvf-default",
                    "host": "macos",
                    "host_triple": "aarch64-apple-darwin",
                    "command": EXPECTED_COMMANDS["macos-hvf-default"],
                }
            ],
        )
        canonical = lambda value: hashlib.sha256(
            json.dumps(
                value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
            ).encode("utf-8")
        ).hexdigest()
        self.assertEqual(capture["rows_sha256"], canonical(capture["rows"]))
        self.assertEqual(
            capture["profiles_sha256"], canonical(capture["profiles"])
        )
        self.assertEqual(
            capture["toolchain_sha256"], canonical(capture["toolchain"])
        )
        self.assertEqual(document["capture_sha256"], canonical(capture))
        self.assertRegex(capture["source_head"], r"^[0-9a-f]{40}$")
        self.assertIn("partial", stderr.getvalue())

    def test_refresh_candidate_cannot_overwrite_checked_capture_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            temporary_root = Path(directory)
            inventory = (
                temporary_root
                / "scripts"
                / "migrate"
                / "host-authority-transition-inventory.json"
            )
            capture = (
                temporary_root
                / "scripts"
                / "migrate"
                / "host-authority-macos-capture.json"
            )
            capture.parent.mkdir(parents=True)
            capture.write_text("checked capture sentinel\n", encoding="utf-8")
            inventory.write_text("checked inventory sentinel\n", encoding="utf-8")
            protected = self.host_authority.protected_candidate_paths(
                temporary_root
            )
            with self.assertRaises(self.host_authority.InventoryError):
                with self.host_authority._candidate_destination(
                    capture, protected
                ):
                    pass
            preserved = capture.read_text(encoding="utf-8")
        self.assertEqual(preserved, "checked capture sentinel\n")

    def test_candidate_path_cannot_equal_or_alias_canonical_inventory(self):
        matrix = self.load()
        for alias_kind in ("direct", "symlink", "hardlink"):
            with self.subTest(alias_kind=alias_kind), tempfile.TemporaryDirectory() as directory:
                temporary_root = Path(directory)
                inventory = (
                    temporary_root
                    / "scripts"
                    / "migrate"
                    / "host-authority-transition-inventory.json"
                )
                inventory.parent.mkdir(parents=True)
                inventory.write_text("canonical sentinel\n", encoding="utf-8")
                if alias_kind == "direct":
                    candidate = inventory
                else:
                    candidate = temporary_root / f"{alias_kind}-candidate.json"
                    if alias_kind == "symlink":
                        candidate.symlink_to(inventory)
                    else:
                        os.link(inventory, candidate)
                runner = FakeRunner()
                stderr = io.StringIO()
                with contextlib.redirect_stderr(stderr):
                    result = self.host_authority.main(
                        ["--refresh-candidate", str(candidate)],
                        runner=runner,
                        matrix=matrix,
                        operation_catalog=FIXTURE_CATALOG,
                        catalog_manifest=FIXTURE_CATALOG,
                        expected=[],
                        capture_receipt=injected_receipt([]),
                        current_host="macos",
                        root=temporary_root,
                    )
                self.assertEqual(result, 2)
                self.assertEqual(
                    inventory.read_text(encoding="utf-8"), "canonical sentinel\n"
                )
                self.assertEqual(runner.calls, [])
                expected_error = (
                    "symlink"
                    if alias_kind == "symlink"
                    else "checked authority artifact"
                )
                self.assertIn(expected_error, stderr.getvalue())

    def test_candidate_parent_swap_cannot_redirect_publication_to_inventory(self):
        matrix = self.load()
        with tempfile.TemporaryDirectory() as directory:
            temporary = Path(directory)
            root = temporary / "worktree"
            self.write_minimal_workspace(root)
            checked_config = root / ".cargo" / "config.toml"
            checked_config.parent.mkdir(exist_ok=True)
            checked_config.write_text(
                '[build]\nrustflags = ["-C", "force-frame-pointers=yes"]\n',
                encoding="utf-8",
            )
            inventory = (
                root
                / "scripts"
                / "migrate"
                / "host-authority-transition-inventory.json"
            )
            inventory.parent.mkdir(parents=True)
            inventory.write_text("canonical sentinel\n", encoding="utf-8")
            candidate_parent = temporary / "candidate-parent"
            candidate_parent.mkdir()
            moved_parent = temporary / "authenticated-parent"
            candidate = candidate_parent / inventory.name
            fake = FakeRunner()
            swapped = False

            def runner(argv, **kwargs):
                nonlocal swapped
                if "--manifest-path" in argv and not swapped:
                    candidate_parent.rename(moved_parent)
                    candidate_parent.symlink_to(
                        inventory.parent, target_is_directory=True
                    )
                    swapped = True
                return fake(argv, **kwargs)

            real_open = self.host_authority.os.open
            directory_fds = []

            def capturing_open(path, flags, mode=0o777, *, dir_fd=None):
                descriptor = real_open(path, flags, mode, dir_fd=dir_fd)
                if flags & self.host_authority.os.O_DIRECTORY:
                    directory_fds.append(descriptor)
                return descriptor

            with mock.patch.object(
                self.host_authority.os, "open", side_effect=capturing_open
            ):
                result = self.host_authority.main(
                    ["--refresh-candidate", str(candidate)],
                    runner=runner,
                    matrix=matrix,
                    operation_catalog=FIXTURE_CATALOG,
                    catalog_manifest=FIXTURE_CATALOG,
                    expected=[],
                    capture_receipt=injected_receipt([]),
                    source_head="0" * 40,
                    current_host="macos",
                    root=root,
                )

            self.assertEqual(result, 1)
            self.assertTrue(swapped)
            self.assertEqual(
                inventory.read_text(encoding="utf-8"), "canonical sentinel\n"
            )
            published = moved_parent / inventory.name
            self.assertTrue(published.is_file())
            self.assertFalse(published.is_symlink())
            self.assertTrue(directory_fds)
            for descriptor in directory_fds:
                with self.assertRaises(OSError):
                    os.fstat(descriptor)

    def test_atomic_candidate_write_leaves_existing_file_on_replace_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            candidate = Path(directory) / "candidate.json"
            canonical = Path(directory) / "canonical.json"
            candidate.write_text("existing candidate\n", encoding="utf-8")
            canonical.write_text("canonical\n", encoding="utf-8")
            with self.host_authority._candidate_destination(
                candidate, [canonical]
            ) as destination:
                directory_fd = destination.directory_fd
                with mock.patch.object(
                    self.host_authority.os,
                    "replace",
                    side_effect=OSError("injected replace failure"),
                ):
                    with self.assertRaisesRegex(
                        OSError, "injected replace failure"
                    ):
                        self.host_authority._write_candidate_atomically(
                            destination, {"schema": 1}
                        )
            self.assertEqual(
                candidate.read_text(encoding="utf-8"), "existing candidate\n"
            )
            with self.assertRaises(OSError):
                os.fstat(directory_fd)

    def test_complete_candidate_requires_every_required_profile(self):
        matrix = self.load()
        all_profiles = sorted(REQUIRED_PROFILES)
        actual = [
            actual_row(
                profiles=all_profiles,
                catalog_id="HA-CATALOG-FIXTURE-PROCESS-ID",
            )
        ]
        expected = [
            reviewed_row(
                profiles=all_profiles,
                catalog_id="HA-CATALOG-FIXTURE-PROCESS-ID",
            )
        ]
        complete = self.host_authority.candidate_document(
            actual,
            expected,
            all_profiles,
            REQUIRED_PROFILES,
            {
                "rustc": "rustc pinned",
                "clippy": "clippy pinned",
                "host_triple": "aarch64-apple-darwin",
            },
            matrix,
            FIXTURE_CATALOG,
            "0" * 40,
        )
        self.assertTrue(complete["complete"])
        self.assertEqual(complete["rows"], expected)
        partial = self.host_authority.candidate_document(
            [actual_row(catalog_id="HA-CATALOG-FIXTURE-PROCESS-ID")],
            expected,
            ["macos-hvf-default"],
            REQUIRED_PROFILES,
            {
                "rustc": "rustc pinned",
                "clippy": "clippy pinned",
                "host_triple": "aarch64-apple-darwin",
            },
            matrix,
            FIXTURE_CATALOG,
            "0" * 40,
        )
        self.assertFalse(partial["complete"])
        self.assertTrue(
            all(row["classification"] == "unreviewed" for row in partial["rows"])
        )

    def test_candidate_capture_rejects_wrong_catalog_binding(self):
        matrix = self.load()
        with self.assertRaisesRegex(
            self.host_authority.InventoryError, "catalog binding"
        ):
            self.host_authority.compiler_capture_receipt(
                matrix,
                FIXTURE_CATALOG,
                [actual_row(catalog_id="HA-CATALOG-WRONG")],
                ["macos-hvf-default"],
                sorted(set(REQUIRED_PROFILES) - {"macos-hvf-default"}),
                {
                    "rustc": "rustc pinned",
                    "clippy": "clippy pinned",
                    "host_triple": "aarch64-apple-darwin",
                },
                "0" * 40,
            )

    def test_partial_check_projects_reviewed_rows_without_writing(self):
        matrix = self.load()
        runner = FakeRunner(json.dumps(diagnostic()) + "\n")
        expected = [
            reviewed_row(
                profiles=["linux-runtime", "macos-hvf-default"],
                catalog_id="HA-CATALOG-FIXTURE-PROCESS-ID",
            )
        ]
        status = self.host_authority.main(
            ["--check", "--profiles", "macos-hvf-default"],
            runner=runner,
            matrix=matrix,
            operation_catalog=FIXTURE_CATALOG,
            catalog_manifest=FIXTURE_CATALOG,
            expected=expected,
            capture_receipt=injected_receipt(expected),
            current_host="macos",
            root=ROOT,
        )
        self.assertEqual(status, 0)

    def test_production_catalog_has_complete_unique_stable_operation_bindings(self):
        configuration = tomllib.loads(CLIPPY_CONFIG.read_text(encoding="utf-8"))
        entries = configuration.get("disallowed-methods")
        self.assertIsInstance(entries, list)
        self.assertTrue(entries)

        by_operation = {}
        catalog_ids = set()
        allow_invalid = []
        for entry in entries:
            self.assertIsInstance(entry, dict)
            self.assertTrue(
                set(entry) <= {"path", "reason", "allow-invalid"},
                entry,
            )
            operation = entry.get("path")
            reason = entry.get("reason")
            self.assertIsInstance(operation, str)
            self.assertIsInstance(reason, str)
            catalog_id, separator, explanation = reason.partition(":")
            self.assertEqual(separator, ":", reason)
            self.assertTrue(explanation.strip(), reason)
            self.assertRegex(
                catalog_id,
                r"^HA-CATALOG-[A-Z0-9]+(?:-[A-Z0-9]+)*$",
            )
            self.assertNotIn(operation, by_operation)
            self.assertNotIn(catalog_id, catalog_ids)
            by_operation[operation] = catalog_id
            catalog_ids.add(catalog_id)
            if entry.get("allow-invalid") is True:
                allow_invalid.append(operation)

        self.assertEqual(set(by_operation), EXPECTED_PRODUCTION_OPERATIONS)
        self.assertEqual(allow_invalid, [])
        manifest = self.host_authority.load_catalog_manifest(CATALOG_MANIFEST)
        self.assertEqual(manifest, by_operation)
        self.assertEqual(
            self.host_authority.load_production_catalog(CLIPPY_CONFIG, manifest),
            by_operation,
        )


class ProductionInventoryTest(unittest.TestCase):
    def setUp(self):
        self.host_authority = load_host_authority()
        self.rows = json.loads(INVENTORY.read_text(encoding="utf-8"))
        self.assertTrue(
            self.rows
            and all(
                {"review_id", "operation", "source", "profiles"} <= set(row)
                for row in self.rows
            ),
            "canonical inventory still uses the rejected lexical schema",
        )

    def row_at(self, file, line, operation):
        matches = [
            row
            for row in self.rows
            if row["source"]["file"] == file
            and row["source"]["line"] == line
            and row["operation"] == operation
        ]
        self.assertEqual(len(matches), 1, (file, line, operation, matches))
        return matches[0]

    def test_inventory_uses_compiler_resolved_schema_and_catalog_bindings(self):
        self.assertEqual(len(self.rows), 682)
        manifest = self.host_authority.load_catalog_manifest(CATALOG_MANIFEST)
        catalog = self.host_authority.load_production_catalog(
            CLIPPY_CONFIG, manifest
        )
        identities = set()
        for row in self.rows:
            self.assertEqual(
                set(row),
                {
                    "review_id",
                    "catalog_id",
                    "operation",
                    "source",
                    "expansion",
                    "profiles",
                    "classification",
                    "evidence",
                    "rationale",
                },
            )
            self.assertEqual(row["catalog_id"], catalog[row["operation"]])
            actual = {
                field: row[field]
                for field in self.host_authority.ACTUAL_FIELDS
            }
            identity = self.host_authority.diagnostic_identity(actual)
            self.assertNotIn(identity, identities)
            identities.add(identity)

    def test_inventory_has_only_complete_unique_reviews(self):
        self.assertEqual(
            [row["review_id"] for row in self.rows],
            [f"HA-{number:06d}" for number in range(1, 683)],
        )
        self.assertEqual(len({row["review_id"] for row in self.rows}), 682)
        self.assertEqual(
            Counter(row["classification"] for row in self.rows),
            Counter(
                {
                    "forbidden_semantic": 173,
                    "declared_backing": 318,
                    "declared_substrate": 191,
                }
            ),
        )
        self.assertFalse(
            {
                row["classification"]
                for row in self.rows
            }
            & {"legacy_unreachable", "unreviewed"}
        )

    def test_inventory_profile_membership_matches_real_macos_capture(self):
        self.assertEqual(
            Counter(tuple(row["profiles"]) for row in self.rows),
            Counter(
                {
                    ("macos-cli-default",): 180,
                    ("macos-cli-default", "macos-runtime-default"): 390,
                    (
                        "macos-cli-default",
                        "macos-hvf-default",
                        "macos-runtime-default",
                    ): 112,
                }
            ),
        )

    def test_waitpid_openoptions_and_hvf_operations_are_bound(self):
        operation_counts = Counter(row["operation"] for row in self.rows)
        self.assertEqual(operation_counts["libc::waitpid"], 7)
        self.assertEqual(operation_counts["std::fs::OpenOptions::new"], 19)
        self.assertEqual(operation_counts["std::fs::OpenOptions::open"], 19)
        self.assertEqual(operation_counts["applevisor_sys::hv_vcpus_exit"], 1)
        self.assertEqual(
            {
                (row["source"]["file"], row["source"]["line"])
                for row in self.rows
                if row["operation"] == "libc::waitpid"
            },
            {
                ("crates/carrick-cli/src/commands.rs", 237),
                ("crates/carrick-runtime/src/file_authority/ipc.rs", 102),
                ("crates/carrick-runtime/src/interactive_supervisor.rs", 324),
                ("crates/carrick-runtime/src/interactive_supervisor.rs", 340),
                ("crates/carrick-runtime/src/interactive_supervisor.rs", 508),
                ("crates/carrick-runtime/src/namespace/supervisor.rs", 269),
                ("crates/carrick-runtime/src/namespace/supervisor.rs", 283),
            },
        )
        hvf_exit = self.row_at(
            "crates/carrick-vmm-hvf/src/vcpu_kick.rs",
            99,
            "applevisor_sys::hv_vcpus_exit",
        )
        self.assertEqual(hvf_exit["classification"], "declared_substrate")
        self.assertEqual(
            hvf_exit["profiles"],
            [
                "macos-cli-default",
                "macos-hvf-default",
                "macos-runtime-default",
            ],
        )

    def test_liveness_wait_and_permit_sites_have_strict_classifications(self):
        forbidden = {
            ("crates/carrick-runtime/src/container.rs", 392, "libc::kill"),
            (
                "crates/carrick-runtime/src/namespace/supervisor.rs",
                179,
                "libc::kill",
            ),
            (
                "crates/carrick-runtime/src/namespace/supervisor.rs",
                269,
                "libc::waitpid",
            ),
            (
                "crates/carrick-runtime/src/namespace/supervisor.rs",
                283,
                "libc::waitpid",
            ),
            ("crates/carrick-vmm-hvf/src/host_signal.rs", 488, "libc::waitid"),
            ("crates/carrick-vmm-hvf/src/io_wait.rs", 168, "libc::waitid"),
            ("crates/carrick-vmm-hvf/src/io_wait.rs", 188, "std::process::id"),
            ("crates/carrick-vmm-hvf/src/io_wait.rs", 217, "std::process::id"),
            ("crates/carrick-vmm-hvf/src/io_wait.rs", 229, "libc::waitid"),
            ("crates/carrick-vmm-hvf/src/io_wait.rs", 906, "std::process::id"),
            ("crates/carrick-vmm-hvf/src/io_wait.rs", 914, "std::process::id"),
        }
        for file, line, operation in forbidden:
            with self.subTest(file=file, line=line, operation=operation):
                self.assertEqual(
                    self.row_at(file, line, operation)["classification"],
                    "forbidden_semantic",
                )

        substrate = {
            (
                "crates/carrick-vmm-hvf/src/vcpu_permit_reaper.rs",
                74,
                "libc::waitid",
            ),
            (
                "crates/carrick-vmm-hvf/src/vcpu_permit_reaper.rs",
                107,
                "libc::kill",
            ),
            (
                "crates/carrick-vmm-hvf/src/vcpu_permit_reaper.rs",
                346,
                "std::thread::Builder::new",
            ),
            (
                "crates/carrick-runtime/src/interactive_supervisor.rs",
                508,
                "libc::waitpid",
            ),
        }
        for file, line, operation in substrate:
            with self.subTest(file=file, line=line, operation=operation):
                self.assertEqual(
                    self.row_at(file, line, operation)["classification"],
                    "declared_substrate",
                )

    def test_reviewer_identified_semantic_channels_are_classified_from_source(self):
        semantic = {
            ("crates/carrick-runtime/src/exec_helpers.rs", 349, "std::fs::read"):
                "guest child signal wait status",
            ("crates/carrick-runtime/src/exec_helpers.rs", 350, "std::fs::remove_file"):
                "guest child signal wait status",
            ("crates/carrick-runtime/src/exec_helpers.rs", 412, "std::fs::write"):
                "guest child signal wait status",
            ("crates/carrick-runtime/src/exec_helpers.rs", 430, "std::fs::write"):
                "guest child signal wait status",
            ("crates/carrick-runtime/src/exec_helpers.rs", 412, "std::process::id"):
                "guest child signal wait status",
            ("crates/carrick-runtime/src/exec_helpers.rs", 430, "std::process::id"):
                "guest child signal wait status",
            ("crates/carrick-runtime/src/cred_ipc.rs", 91, "std::fs::metadata"):
                "guest cross-process signal permission",
            ("crates/carrick-runtime/src/cred_ipc.rs", 112, "std::fs::read"):
                "guest cross-process signal permission",
            ("crates/carrick-runtime/src/dispatch/mod.rs", 4703, "std::process::id"):
                "guest PTY entry lifetime",
            ("crates/carrick-runtime/src/dispatch/mod.rs", 4895, "std::process::id"):
                "guest controlling PTY identity",
            ("crates/carrick-runtime/src/vfs/dev.rs", 150, "std::process::id"):
                "guest PTY entry ownership",
            ("crates/carrick-runtime/src/vfs/devpts.rs", 263, "std::process::id"):
                "guest PTY entry ownership",
            ("crates/carrick-runtime/src/network/socket_namespace.rs", 1648, "std::process::id"):
                "guest service-name record liveness",
            ("crates/carrick-runtime/src/network/socket_namespace.rs", 1665, "std::process::id"):
                "guest listener-reservation liveness",
            ("crates/carrick-runtime/src/network/socket_namespace.rs", 1731, "std::process::id"):
                "guest endpoint-record liveness",
        }
        for (file, line, operation), resource in semantic.items():
            with self.subTest(file=file, line=line, operation=operation):
                row = self.row_at(file, line, operation)
                self.assertEqual(row["classification"], "forbidden_semantic")
                self.assertIn(resource, row["evidence"]["resource"])

        diagnostic = {
            ("crates/carrick-runtime/src/network/socket_namespace.rs", 1685):
                "diagnostic instance identity",
            ("crates/carrick-runtime/src/network/socket_namespace.rs", 1874):
                "NSREJECT diagnostic event",
        }
        for (file, line), resource in diagnostic.items():
            with self.subTest(file=file, line=line):
                row = self.row_at(file, line, "std::process::id")
                self.assertEqual(row["classification"], "declared_substrate")
                self.assertIn(resource, row["evidence"]["resource"])

        rosetta = self.row_at(
            "crates/carrick-runtime/src/lib.rs",
            364,
            "std::fs::read_to_string",
        )
        self.assertEqual(rosetta["classification"], "declared_backing")
        self.assertIn("binfmt_misc Rosetta registration", rosetta["evidence"]["resource"])

    def test_sysv_message_queue_fork_caches_are_carrier_substrate(self):
        expected = {
            "HA-000034": "message-queue descriptor cache fork ownership",
            "HA-000035": "inherited message-queue descriptors",
            "HA-000036": "message-queue wait-word mapping cache fork ownership",
            "HA-000037": "inherited message-queue wait-word mappings",
        }
        for review_id, resource in expected.items():
            with self.subTest(review_id=review_id):
                row = next(row for row in self.rows if row["review_id"] == review_id)
                self.assertEqual(row["classification"], "declared_substrate")
                self.assertEqual(row["evidence"]["authority"], "authenticated_carrier")
                self.assertIn(resource, row["evidence"]["resource"])

        for review_id in ("HA-000533", "HA-000534", "HA-000535"):
            with self.subTest(sibling=review_id):
                row = next(row for row in self.rows if row["review_id"] == review_id)
                self.assertEqual(row["classification"], "declared_backing")
                self.assertEqual(row["evidence"]["authority"], "authorized_backing")

    def test_every_review_is_source_specific_without_blanket_templates(self):
        rationales = set()
        resources = set()
        for row in self.rows:
            source_identity = f'{row["source"]["file"]}:{row["source"]["line"]}'
            self.assertIn(source_identity, row["rationale"])
            self.assertIn(row["operation"], row["rationale"])
            self.assertNotIn(
                "filesystem artifact explicitly authorized by the active CLI command",
                row["evidence"]["resource"],
            )
            self.assertNotIn(row["rationale"], rationales)
            rationales.add(row["rationale"])
            resources.add(row["evidence"]["resource"])
        self.assertGreaterEqual(len(resources), 350)

        grouped = {}
        for row in self.rows:
            grouped.setdefault(row["evidence"]["resource"], set()).add(
                (row["classification"], row["evidence"]["authority"])
            )
        self.assertTrue(all(len(roles) == 1 for roles in grouped.values()))


class IndependentAuthorityArtifactsTest(unittest.TestCase):
    def setUp(self):
        self.host_authority = load_host_authority()

    def require_interface(self, name):
        self.assertTrue(
            hasattr(self.host_authority, name),
            f"production checker lacks independent {name} interface",
        )
        return getattr(self.host_authority, name)

    def write_json(self, payload):
        temporary = tempfile.TemporaryDirectory()
        path = Path(temporary.name) / "artifact.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        self.addCleanup(temporary.cleanup)
        return path

    def write_toml(self, configuration):
        temporary = tempfile.TemporaryDirectory()
        path = Path(temporary.name) / "clippy.toml"
        lines = ["disallowed-methods = ["]
        for entry in configuration["disallowed-methods"]:
            fields = [
                f'path = {json.dumps(entry["path"])}',
                f'reason = {json.dumps(entry["reason"])}',
            ]
            if "allow-invalid" in entry:
                fields.append(
                    f'allow-invalid = {str(entry["allow-invalid"]).lower()}'
                )
            if "unexpected" in entry:
                fields.append(f'unexpected = {json.dumps(entry["unexpected"])}')
            lines.append("  { " + ", ".join(fields) + " },")
        lines.append("]")
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        self.addCleanup(temporary.cleanup)
        return path

    def test_independent_catalog_manifest_binds_exact_strict_clippy_entries(self):
        load_manifest = self.require_interface("load_catalog_manifest")
        manifest = load_manifest(CATALOG_MANIFEST)
        self.assertEqual(set(manifest), EXPECTED_PRODUCTION_OPERATIONS)
        self.assertEqual(len(manifest), 45)
        production = self.host_authority.load_production_catalog(
            CLIPPY_CONFIG, manifest
        )
        self.assertEqual(production, manifest)

        configuration = tomllib.loads(CLIPPY_CONFIG.read_text(encoding="utf-8"))
        for label, mutate in (
            (
                "missing unused escape",
                lambda entries: [e for e in entries if e["path"] != "libc::syscall"],
            ),
            (
                "retargeted operation",
                lambda entries: [
                    ({**e, "path": "libc::printf"} if e["path"] == "libc::syscall" else e)
                    for e in entries
                ],
            ),
            (
                "changed stable ID",
                lambda entries: [
                    (
                        {
                            **e,
                            "reason": e["reason"].replace(
                                "HA-CATALOG-ESCAPE-SYSCALL",
                                "HA-CATALOG-ESCAPE-DLOPEN",
                            ),
                        }
                        if e["path"] == "libc::syscall"
                        else e
                    )
                    for e in entries
                ],
            ),
            (
                "allow invalid false",
                lambda entries: [{**entries[0], "allow-invalid": False}, *entries[1:]],
            ),
            (
                "allow invalid true",
                lambda entries: [{**entries[0], "allow-invalid": True}, *entries[1:]],
            ),
            (
                "unexpected key",
                lambda entries: [{**entries[0], "unexpected": "value"}, *entries[1:]],
            ),
        ):
            mutated = {**configuration, "disallowed-methods": mutate(copy.deepcopy(configuration["disallowed-methods"]))}
            with self.subTest(label=label):
                with self.assertRaises(self.host_authority.InventoryError):
                    self.host_authority.load_production_catalog(
                        self.write_toml(mutated), manifest
                    )

        manifest_payload = json.loads(CATALOG_MANIFEST.read_text(encoding="utf-8"))
        missing = copy.deepcopy(manifest_payload)
        missing["operations"] = [
            row for row in missing["operations"] if row["operation"] != "libc::dlsym"
        ]
        with self.assertRaises(self.host_authority.InventoryError):
            load_manifest(self.write_json(missing))

    def test_independent_capture_receipt_exactly_binds_inventory_projection(self):
        load_manifest = self.require_interface("load_catalog_manifest")
        load_receipt = self.require_interface("load_capture_receipt")
        validate_receipt = self.require_interface("validate_inventory_against_receipt")
        matrix = self.host_authority.load_matrix(MATRIX)
        catalog = load_manifest(CATALOG_MANIFEST)
        receipt = load_receipt(MACOS_CAPTURE, matrix, catalog)
        inventory = self.host_authority.load_inventory(INVENTORY)
        validate_receipt(inventory, receipt)
        self.assertEqual(len(receipt["rows"]), 682)
        self.assertEqual(
            receipt["executed_profiles"],
            ["macos-cli-default", "macos-hvf-default", "macos-runtime-default"],
        )

        mutations = []
        changed_operation = copy.deepcopy(inventory)
        changed_operation[0]["operation"] = "libc::fork"
        mutations.append(("operation", changed_operation))
        changed_catalog = copy.deepcopy(inventory)
        changed_catalog[0]["catalog_id"] = "HA-CATALOG-PROCESS-FORK"
        mutations.append(("catalog", changed_catalog))
        changed_source = copy.deepcopy(inventory)
        changed_source[0]["source"]["line"] += 1
        mutations.append(("source", changed_source))
        changed_profiles = copy.deepcopy(inventory)
        changed_profiles[0]["profiles"] = ["macos-cli-default"]
        mutations.append(("profiles", changed_profiles))
        empty_review = copy.deepcopy(inventory)
        empty_review[0]["rationale"] = ""
        mutations.append(("empty review", empty_review))
        for label, rows in mutations:
            with self.subTest(label=label):
                with self.assertRaises(self.host_authority.InventoryError):
                    validate_receipt(rows, receipt)

        receipt_payload = json.loads(MACOS_CAPTURE.read_text(encoding="utf-8"))
        receipt_payload["rows"][0]["profiles"] = ["macos-cli-default"]
        with self.assertRaises(self.host_authority.InventoryError):
            load_receipt(self.write_json(receipt_payload), matrix, catalog)

        substituted_profile = json.loads(
            MACOS_CAPTURE.read_text(encoding="utf-8")
        )
        substituted_profile["profiles"][0]["command"][2] = "carrick-runtime"
        substituted_profile["profiles_sha256"] = (
            self.host_authority._canonical_digest(substituted_profile["profiles"])
        )
        with self.assertRaises(self.host_authority.InventoryError):
            load_receipt(self.write_json(substituted_profile), matrix, catalog)

        substituted_toolchain = json.loads(
            MACOS_CAPTURE.read_text(encoding="utf-8")
        )
        substituted_toolchain["toolchain"]["clippy"] = "clippy 0.1.95"
        with self.assertRaises(self.host_authority.InventoryError):
            load_receipt(self.write_json(substituted_toolchain), matrix, catalog)

    def test_static_checker_validates_independent_artifacts_without_cargo(self):
        self.require_interface("load_capture_receipt")
        calls = []

        def reject_cargo(*args, **kwargs):
            calls.append((args, kwargs))
            self.fail("static authority validation invoked Cargo")

        self.assertEqual(
            self.host_authority.main(
                ["--static"], root=ROOT, runner=reject_cargo
            ),
            0,
        )
        self.assertEqual(calls, [])

    def test_production_review_validation_rejects_non_source_specific_reviews(self):
        validate = self.require_interface("validate_inventory_against_receipt")
        base = reviewed_row(
            rationale=(
                "At crates/example/src/lib.rs:10, std::process::id acts on "
                "the guest-visible process identity."
            )
        )
        mutations = {
            "wrong file": "At crates/wrong/src/lib.rs:10, std::process::id acts on the identity.",
            "wrong line": "At crates/example/src/lib.rs:11, std::process::id acts on the identity.",
            "wrong operation": "At crates/example/src/lib.rs:10, libc::getpid acts on the identity.",
        }
        for label, rationale in mutations.items():
            row = {**base, "rationale": rationale}
            with self.subTest(label=label):
                with self.assertRaises(self.host_authority.InventoryError):
                    validate([row], injected_receipt([row]))

        blanket_rows = []
        for number in range(1, 14):
            line = number + 20
            blanket_rows.append(
                reviewed_row(
                    review_id=f"HA-{number:06d}",
                    location=source(line=line, byte_start=line * 10, byte_end=line * 10 + 5),
                    evidence={
                        "authority": "authorized_backing",
                        "resource": "filesystem artifact selected by the active CLI command",
                    },
                    classification="declared_backing",
                    rationale=(
                        f"At crates/example/src/lib.rs:{line}, std::process::id "
                        "accesses the selected filesystem artifact."
                    ),
                )
            )
        with self.assertRaises(self.host_authority.InventoryError):
            validate(blanket_rows, injected_receipt(blanket_rows))

    def test_production_review_validation_requires_unique_rationales(self):
        validate = self.require_interface("validate_inventory_against_receipt")
        rationale = (
            "At crates/example/src/lib.rs:10, std::process::id and libc::getpid "
            "act on one concrete process identity."
        )
        rows = [
            reviewed_row(rationale=rationale),
            reviewed_row(
                review_id="HA-000002",
                operation="libc::getpid",
                catalog_id="HA-CATALOG-PROCESS-GETPID",
                rationale=rationale,
            ),
        ]
        with self.assertRaises(self.host_authority.InventoryError):
            validate(rows, injected_receipt(rows))


if __name__ == "__main__":
    unittest.main()
