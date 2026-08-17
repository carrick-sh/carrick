#!/usr/bin/env python3

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "scripts" / "conformance" / "closure-scope.py"
SPEC = importlib.util.spec_from_file_location("closure_scope", MODULE_PATH)
closure_scope = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(closure_scope)


class ClosureScopeTest(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.manifest = self.root / "suites.toml"
        self.binary = self.root / "carrick"
        self.binary.write_bytes(b"signed-carrick-fixture")
        self.image_refs = [
            f"registry.invalid/carrick-fixture:{index}" for index in range(1, 5)
        ]
        self.images = {
            image: {
                "docker_id": "sha256:" + "1" * 64,
                "repo_digests": [
                    f"{image.rsplit(':', 1)[0]}@sha256:" + "2" * 64
                ],
                "registry_digest": "sha256:" + "3" * 64,
            }
            for image in self.image_refs
        }
        self._write_manifest(2127)

    def tearDown(self):
        self.temp_dir.cleanup()

    def _write_manifest(self, count, image_refs=None):
        image_refs = image_refs or self.image_refs
        rows = []
        for index in range(count):
            ecosystem = "go" if index % 2 == 0 else "ltp"
            rows.append(
                "\n".join(
                    [
                        "[[suite]]",
                        f'name = "suite-{index:04d}"',
                        f'ecosystem = "{ecosystem}"',
                        f'image = "{image_refs[index % len(image_refs)]}"',
                    ]
                )
            )
        self.manifest.write_text("\n\n".join(rows) + "\n", encoding="utf-8")

    def _freeze(self):
        return closure_scope.freeze_scope(
            self.manifest,
            self.images,
            source_head="a" * 40,
            tooling_source_head="b" * 40,
            binary_path=self.binary,
        )

    def test_scope_requires_exact_manifest_names_and_count(self):
        scope = self._freeze()
        self.assertEqual(scope["suite_count"], 2127)
        self.assertEqual(len(scope["suite_names"]), 2127)

        self._write_manifest(2126)
        with self.assertRaises(closure_scope.ScopeError):
            closure_scope.check_scope(
                scope,
                self.manifest,
                self.images,
                source_head="a" * 40,
                binary_path=self.binary,
                require_clean=False,
            )

    def test_scope_records_source_binary_manifest_and_image_identities(self):
        scope = self._freeze()
        for key in [
            "source_head",
            "tooling_source_head",
            "binary_sha256",
            "manifest_sha256",
            "images",
        ]:
            self.assertIn(key, scope)
        self.assertEqual(scope["source_head"], "a" * 40)
        self.assertEqual(scope["tooling_source_head"], "b" * 40)
        self.assertEqual(
            scope["suite_counts_by_ecosystem"], {"go": 1064, "ltp": 1063}
        )

    def test_scope_rejects_unresolved_image_digest(self):
        unresolved = json.loads(json.dumps(self.images))
        unresolved["registry.invalid/carrick-fixture:1"]["registry_digest"] = None
        with self.assertRaises(closure_scope.ScopeError):
            closure_scope.freeze_scope(
                self.manifest,
                unresolved,
                source_head="a" * 40,
                tooling_source_head="b" * 40,
                binary_path=self.binary,
            )

    def test_scope_requires_exactly_four_distinct_declared_images(self):
        for image_count in [3, 5]:
            with self.subTest(image_count=image_count):
                image_refs = [
                    f"registry.invalid/cardinality:{index}"
                    for index in range(image_count)
                ]
                images = {
                    image: {
                        "docker_id": "sha256:" + "1" * 64,
                        "repo_digests": [],
                        "registry_digest": "sha256:" + "2" * 64,
                    }
                    for image in image_refs
                }
                self._write_manifest(2127, image_refs)
                with self.assertRaises(closure_scope.ScopeError):
                    closure_scope.freeze_scope(
                        self.manifest,
                        images,
                        source_head="a" * 40,
                        tooling_source_head="b" * 40,
                        binary_path=self.binary,
                    )


if __name__ == "__main__":
    unittest.main()
