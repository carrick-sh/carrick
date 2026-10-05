#!/usr/bin/env python3
"""Live Linux direct/alias/macro/cfg breaker using the production profile runner.

A small dependency-free crate keeps the compiler witness cheap. Rust's count
consumer checks each resolved operation against an empty approved boundary.
No stored compiler evidence is read; the JSON is consumed ephemerally.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import platform
import shutil
import sys

ROOT = Path(__file__).resolve().parents[3]
CHECKER = ROOT / 'scripts/migrate/check-host-authority-transitions.py'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fixture-root', type=Path, required=True)
    args = parser.parse_args()
    if platform.system() != 'Linux':
        parser.error('live Linux breaker requires a Linux host')
    spec = importlib.util.spec_from_file_location('live_authority_breaker', CHECKER)
    gate = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = gate
    spec.loader.exec_module(gate)
    root = args.fixture_root
    (root / 'crates/carrick-runtime/src').mkdir(parents=True)
    (root / '.cargo').mkdir()
    (root / 'Cargo.toml').write_text('''[workspace]
members = ["crates/carrick-runtime"]
resolver = "2"
''')
    (root / 'crates/carrick-runtime/Cargo.toml').write_text('''[package]
name = "carrick-runtime"
version = "0.1.0"
edition = "2024"
[features]
syscall-shim = []
platform-linux = []
''')
    for path in ['.cargo/config.toml', 'rust-toolchain.toml', 'clippy.toml']:
        shutil.copyfile(ROOT / path, root / path)
    (root / 'crates/carrick-runtime/src/lib.rs').write_text('''
pub fn direct_breaker() -> u32 { std::process::id() }
use std::process::id as aliased_id;
pub fn alias_breaker() -> u32 { aliased_id() }
macro_rules! host_id { () => { std::process::id() }; }
pub fn macro_breaker() -> u32 { host_id!() }
#[cfg(target_os = "linux")]
pub fn cfg_breaker() -> u32 { std::process::id() }
''')
    matrix = gate.load_matrix(ROOT / 'scripts/migrate/host-authority-build-matrix.json')
    catalog = gate.load_catalog_manifest(ROOT / 'scripts/migrate/host-authority-catalog.json')
    messages = gate.run_profile(matrix.profiles['linux-runtime'], root=root)
    rows = gate.normalize_messages(messages, 'linux-runtime', root, catalog)
    if len(rows) != 4 or any(row['operation'] != 'std::process::id' for row in rows):
        raise RuntimeError(f'compiler did not resolve all four breakers: {rows}')
    print(json.dumps({'rows': rows}))


if __name__ == '__main__':
    main()
