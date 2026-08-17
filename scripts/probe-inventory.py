#!/usr/bin/env python3
"""Validate Carrick's explicit conformance-probe source and binary inventory."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_INVENTORY = ROOT / "conformance-probes/probe-inventory.json"
DEFAULT_SOURCES = ROOT / "conformance-probes/src/bin"
VALID_CLASSES = {"conformance", "helper", "performance"}
SELECTED_CLASSES = {"conformance", "helper"}
DEDICATED_RUNNERS = {
    "bridge_compose_client": "conformance_bridge_compose_pair",
    "bridge_compose_server": "conformance_bridge_compose_pair",
    "bridge_loopback_isolation": "conformance_bridge_loopback_isolation",
    "bridge_net_identity": "conformance_bridge_net_identity",
    "bridge_publish_tcp": "conformance_bridge_publish_tcp",
    "bridge_reuse_sockopts": "conformance_bridge_reuse_sockopts",
    "bridge_tcp_nonblocking_refused": "conformance_bridge_tcp_nonblocking_refused",
    "bridge_tcp_peer": "conformance_bridge_tcp_peer",
    "bridge_udp_connected_unreachable": "conformance_bridge_udp_connected_unreachable",
    "bridge_udp_peer": "conformance_bridge_udp_peer",
    "bridge_udp_sendto_unreachable": "conformance_bridge_udp_sendto_unreachable",
    "host_gateway_client": "conformance_native_host_gateway",
    "multi_network_client": "conformance_native_multi_network_roles",
    "multi_network_dns_client": "conformance_native_multi_network_roles",
    "multi_network_server": "conformance_native_multi_network_roles",
    "sidecar_loopback_client": "docker_compose_shared_network_namespace_smoke",
    "sidecar_loopback_isolated_client": "docker_compose_shared_network_namespace_smoke",
    "sidecar_loopback_server": "docker_compose_shared_network_namespace_smoke",
    "udp_published_client": "conformance_native_udp_service_pair",
    "udp_published_server": "conformance_native_udp_service_pair",
}


class ProbeInventoryError(RuntimeError):
    """The probe source or binary inventory is incomplete."""


def source_names(source_dir: Path = DEFAULT_SOURCES) -> set[str]:
    return {path.stem for path in Path(source_dir).glob("*.rs") if path.is_file()}


def load_inventory(path: Path = DEFAULT_INVENTORY) -> dict[str, dict[str, Any]]:
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ProbeInventoryError(f"cannot read probe inventory {path}: {error}") from error
    if not isinstance(value, dict):
        raise ProbeInventoryError("probe inventory must be a JSON object keyed by source name")
    return value


def validate_inventory(
    inventory: dict[str, dict[str, Any]], source_dir: Path = DEFAULT_SOURCES
) -> None:
    sources = source_names(source_dir)
    names = set(inventory)
    if sources != names:
        raise ProbeInventoryError(
            f"probe source inventory drift (missing={sorted(sources - names)}, "
            f"absent_from_disk={sorted(names - sources)})"
        )
    for name, row in inventory.items():
        if not isinstance(row, dict) or set(row) != {"class", "runner", "excluded"}:
            raise ProbeInventoryError(f"probe inventory row is malformed: {name}")
        probe_class = row["class"]
        runner = row["runner"]
        excluded = row["excluded"]
        if probe_class not in VALID_CLASSES:
            raise ProbeInventoryError(f"probe {name} has invalid class {probe_class!r}")
        if not isinstance(runner, str) or not runner:
            raise ProbeInventoryError(f"probe {name} has no runner")
        if not isinstance(excluded, bool):
            raise ProbeInventoryError(f"probe {name} has non-boolean exclusion")
        expected_class = (
            "performance"
            if name.startswith("perf_")
            else "helper"
            if name == "probeinit"
            else "conformance"
        )
        if probe_class != expected_class:
            raise ProbeInventoryError(
                f"probe {name} is {probe_class}, expected {expected_class}"
            )
        expected_runner = DEDICATED_RUNNERS.get(name, "generic")
        if runner != expected_runner:
            raise ProbeInventoryError(
                f"probe {name} uses runner {runner!r}, expected {expected_runner!r}"
            )


def selected_names(inventory: dict[str, dict[str, Any]]) -> list[str]:
    return sorted(
        name
        for name, row in inventory.items()
        if row["class"] in SELECTED_CLASSES and not row["excluded"]
    )


def freeze_inventory(source_dir: Path = DEFAULT_SOURCES) -> dict[str, dict[str, Any]]:
    inventory: dict[str, dict[str, Any]] = {}
    for name in sorted(source_names(source_dir)):
        probe_class = (
            "performance"
            if name.startswith("perf_")
            else "helper"
            if name == "probeinit"
            else "conformance"
        )
        inventory[name] = {
            "class": probe_class,
            "runner": DEDICATED_RUNNERS.get(name, "generic"),
            "excluded": False,
        }
    return inventory


def _binary_names(target_dir: Path) -> set[str]:
    if not Path(target_dir).is_dir():
        raise ProbeInventoryError(f"probe target directory is missing: {target_dir}")
    return {
        path.name
        for path in Path(target_dir).iterdir()
        if path.is_file() and "." not in path.name and path.stat().st_mode & 0o111
    }


def check_binaries(
    inventory: dict[str, dict[str, Any]], target_dir: Path, target_label: str
) -> None:
    expected = set(selected_names(inventory))
    source_backed = set(inventory)
    actual = _binary_names(Path(target_dir)) & source_backed
    missing = sorted(expected - actual)
    unexpected = sorted(actual - expected)
    if missing or unexpected:
        raise ProbeInventoryError(
            f"{target_label} binary inventory drift "
            f"(missing={missing}, unexpected_source_backed={unexpected})"
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="action", required=True)
    subparsers.add_parser("check")
    subparsers.add_parser("freeze")
    subparsers.add_parser("selected")
    binary_parser = subparsers.add_parser("check-binaries")
    binary_parser.add_argument("target_dir", type=Path)
    binary_parser.add_argument("target_label")
    args = parser.parse_args(argv)

    try:
        if args.action == "freeze":
            inventory = freeze_inventory()
            DEFAULT_INVENTORY.write_text(
                json.dumps(inventory, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
        else:
            inventory = load_inventory()
        validate_inventory(inventory)
        if args.action == "freeze":
            print(f"froze probe inventory: {len(inventory)} sources")
        elif args.action == "selected":
            print("\n".join(selected_names(inventory)))
        elif args.action == "check-binaries":
            check_binaries(inventory, args.target_dir, args.target_label)
            print(
                f"probe binaries checked: {args.target_label} "
                f"({len(selected_names(inventory))} selected)"
            )
        else:
            classes = {
                probe_class: sum(
                    row["class"] == probe_class for row in inventory.values()
                )
                for probe_class in sorted(VALID_CLASSES)
            }
            print(f"probe inventory checked: {len(inventory)} sources {classes}")
    except ProbeInventoryError as error:
        print(f"probe inventory error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
