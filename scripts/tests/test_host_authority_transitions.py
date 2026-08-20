#!/usr/bin/env python3
"""Tests for compiler-resolved host-authority diagnostic reviews."""

import copy
import contextlib
import importlib.util
import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path


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

EXPECTED_COMMANDS = {
    "macos-cli-default": [
        "cargo",
        "clippy",
        "-p",
        "carrick-cli",
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
        "--lib",
        "--message-format=json",
        "--",
        "--force-warn",
        "clippy::disallowed_methods",
    ],
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
            *target_args,
            "--message-format=json",
            "--",
            "--force-warn",
            "clippy::disallowed_methods",
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
        "The carrier PID would otherwise answer guest getpid semantics."
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
        with self.assertRaisesRegex(
            self.host_authority.InventoryError, "missing expected identity"
        ):
            self.host_authority.refresh(
                [changed_end], [reviewed_row(review_id="HA-000003")], True
            )

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
                with self.assertRaisesRegex(
                    self.host_authority.InventoryError, "missing expected identity"
                ):
                    self.host_authority.refresh(
                        [actual], [reviewed_row(review_id="HA-000003")], True
                    )

    def test_catalog_id_change_cannot_inherit_or_implicitly_remove_review(self):
        changed = actual_row(catalog_id="HA-CATALOG-PROCESS-ID-V2")
        with self.assertRaisesRegex(
            self.host_authority.InventoryError, "missing expected identity"
        ):
            self.host_authority.refresh(
                [changed],
                [reviewed_row(catalog_id="HA-CATALOG-PROCESS-ID")],
                True,
            )

    def test_complete_refresh_rejects_removed_reviewed_rows(self):
        with self.assertRaisesRegex(
            self.host_authority.InventoryError, "missing expected identity"
        ):
            self.host_authority.refresh([], [reviewed_row()], True)

    def test_partial_refresh_fails_closed(self):
        with self.assertRaisesRegex(self.host_authority.InventoryError, "partial"):
            self.host_authority.refresh([actual_row()], [reviewed_row()], False)


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
        self.rustc_version = "rustc 1.96.0 (abcdef 2026-08-01)\n"
        self.clippy_version = "clippy 0.1.96 (abcdef 2026-08-01)\n"

    def __call__(self, argv, **kwargs):
        argv = list(argv)
        self.calls.append((argv, kwargs))
        if argv == ["rustc", "-V"]:
            return subprocess.CompletedProcess(argv, 0, self.rustc_version, "")
        if argv == ["cargo", "clippy", "-V"]:
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
                    "command": list(EXPECTED_COMMANDS[profile_id]),
                }
                for profile_id in REQUIRED_PROFILES
            ],
        }

    def test_checked_matrix_declares_exact_nine_product_profiles(self):
        matrix = self.load()
        self.assertEqual(list(matrix.required_profiles), REQUIRED_PROFILES)
        self.assertEqual(list(matrix.profiles), REQUIRED_PROFILES)
        self.assertEqual(matrix.rustc_release, "1.96.0")
        self.assertEqual(matrix.clippy_release, "0.1.96")
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
        self.assertEqual(runner.calls[0][0], EXPECTED_COMMANDS[profile.id])
        kwargs = runner.calls[0][1]
        self.assertEqual(kwargs["cwd"], ROOT)
        self.assertFalse(kwargs["shell"])
        self.assertTrue(kwargs["capture_output"])
        self.assertTrue(kwargs["text"])
        self.assertFalse(kwargs["check"])
        self.assertEqual(
            kwargs["env"]["CARGO_TARGET_DIR"],
            str(ROOT / "target" / "host-authority-census" / profile.id),
        )

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
                "rustc": "rustc 1.96.0 (abcdef 2026-08-01)",
                "clippy": "clippy 0.1.96 (abcdef 2026-08-01)",
            },
        )
        self.assertEqual(
            [call[0] for call in runner.calls],
            [["rustc", "-V"], ["cargo", "clippy", "-V"]],
        )
        mismatch = FakeRunner()
        mismatch.clippy_version = "clippy 0.1.95 (stale)\n"
        with self.assertRaisesRegex(
            self.host_authority.InventoryError, "0.1.96"
        ):
            self.host_authority.verify_toolchain(matrix, runner=mismatch)

    def test_profile_selection_is_nonempty_local_and_supports_globs(self):
        matrix = self.load()
        expected = REQUIRED_PROFILES[:3]
        self.assertEqual(
            [profile.id for profile in self.host_authority.select_profiles(matrix, None, "macos")],
            expected,
        )
        self.assertEqual(
            [
                profile.id
                for profile in self.host_authority.select_profiles(
                    matrix, "macos-*", "macos"
                )
            ],
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
                ["rustc", "-V"],
                ["cargo", "clippy", "-V"],
                EXPECTED_COMMANDS["macos-hvf-default"],
            ],
        )

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
                    expected=expected,
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

    def test_complete_candidate_requires_every_required_profile(self):
        matrix = self.load()
        all_profiles = sorted(REQUIRED_PROFILES)
        actual = [actual_row(profiles=all_profiles)]
        expected = [reviewed_row(profiles=all_profiles)]
        complete = self.host_authority.candidate_document(
            actual,
            expected,
            all_profiles,
            REQUIRED_PROFILES,
            {"rustc": "rustc pinned", "clippy": "clippy pinned"},
        )
        self.assertTrue(complete["complete"])
        self.assertEqual(complete["rows"], expected)
        partial = self.host_authority.candidate_document(
            [actual_row()],
            expected,
            ["macos-hvf-default"],
            REQUIRED_PROFILES,
            {"rustc": "rustc pinned", "clippy": "clippy pinned"},
        )
        self.assertFalse(partial["complete"])
        self.assertTrue(
            all(row["classification"] == "unreviewed" for row in partial["rows"])
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
            expected=expected,
            current_host="macos",
            root=ROOT,
        )
        self.assertEqual(status, 0)

    def test_real_execution_fails_when_production_catalog_is_unavailable(self):
        with self.assertRaisesRegex(self.host_authority.InventoryError, "Task 4"):
            self.host_authority.load_production_catalog(ROOT / "clippy.toml")


if __name__ == "__main__":
    unittest.main()
