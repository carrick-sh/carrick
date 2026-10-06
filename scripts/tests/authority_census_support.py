"""Test inputs get their scope proof from the production Rust census executable."""

import atexit
from contextlib import contextmanager
from functools import lru_cache
import json
from pathlib import Path
import subprocess
import sys
import tempfile

_directories = []
atexit.register(lambda: [directory.cleanup() for directory in _directories])

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/migrate"))
import authority_census_verdict


def census_json(root):
    result = subprocess.run(
        [
            str(ROOT / "target/debug/carrick-xtask"),
            "--root",
            str(root),
            "authority-census",
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    return json.loads(result.stdout)


@contextmanager
def census_tree(sources):
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        for path, source in sources.items():
            file = root / path
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_text(source)
        yield root, authority_census_verdict.CensusVerdict(census_json(root))


@lru_cache(maxsize=512)
def source_verdict(path, source):
    directory = tempfile.TemporaryDirectory()
    root = Path(directory.name)
    file = root / path
    file.parent.mkdir(parents=True, exist_ok=True)
    file.write_text(source)
    try:
        verdict = authority_census_verdict.CensusVerdict(census_json(root))
    except BaseException:
        directory.cleanup()
        raise
    _directories.append(directory)
    verdict._fixture_directory = directory
    return verdict


def scan_source(scanner, path, source):
    return scanner(path, source, verdict=source_verdict(str(path), source))


def scan_locks(scanner, path, source):
    return scanner.scan_tokens(
        scanner.lex_rust(source),
        path,
        source=source,
        verdict=source_verdict(path, source),
    )
