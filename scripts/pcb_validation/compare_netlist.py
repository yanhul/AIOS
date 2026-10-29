#!/usr/bin/env python3
"""Compare two KiCad XML netlists without depending on net names.

Adapted from the public pcb-agent-workflow project:
https://github.com/John-owo/pcb-agent-workflow
Kept as a read-only validation helper; it does not authorize or mutate designs.
"""
from __future__ import annotations

import argparse
import json
import sys
import xml.etree.ElementTree as ET
from pathlib import Path


def load_netlist(path: str | Path) -> tuple[dict[frozenset[str], str], dict[str, tuple]]:
    root = ET.parse(path).getroot()
    components_node, nets_node = root.find("components"), root.find("nets")
    if components_node is None or nets_node is None:
        raise ValueError(f"{path}: missing components/nets in KiCad XML netlist")

    nets: dict[frozenset[str], str] = {}
    for net in nets_node.findall("net"):
        nodes = frozenset(
            f"{node.get('ref')}.{node.get('pin')}"
            for node in net.findall("node")
        )
        if nodes in nets:
            raise ValueError(f"{path}: duplicate connectivity group in netlist")
        nets[nodes] = net.get("name") or ""

    components: dict[str, tuple] = {}
    for comp in components_node.findall("comp"):
        ref = comp.get("ref")
        if not ref:
            raise ValueError(f"{path}: component without reference")
        fields = tuple(sorted(
            (field.get("name") or "", field.text or "")
            for field in comp.iter("field")
        ))
        props = tuple(sorted(
            (prop.get("name") or "", prop.get("value") or "")
            for prop in comp.findall("property")
            if prop.get("name") in {
                "dnp", "exclude_from_bom", "exclude_from_board"
            }
        ))
        value = comp.findtext("value") or ""
        footprint = comp.findtext("footprint") or ""
        components[ref] = (value, footprint, fields, props)
    return nets, components


def compare(base_path: str | Path, new_path: str | Path, check_names: bool = False) -> list[str]:
    base_nets, base_components = load_netlist(base_path)
    new_nets, new_components = load_netlist(new_path)
    differences: list[str] = []

    for group in sorted(set(base_nets) - set(new_nets), key=lambda g: sorted(g)):
        differences.append(f"connectivity only in BASE: {sorted(group)}")
    for group in sorted(set(new_nets) - set(base_nets), key=lambda g: sorted(g)):
        differences.append(f"connectivity only in NEW: {sorted(group)}")
    if check_names:
        for group in sorted(set(base_nets) & set(new_nets), key=lambda g: sorted(g)):
            if base_nets[group] != new_nets[group]:
                differences.append(f"net name differs: {base_nets[group]} -> {new_nets[group]}")

    for ref in sorted(set(base_components) | set(new_components)):
        if base_components.get(ref) != new_components.get(ref):
            differences.append(
                f"component differs: {ref}: BASE={base_components.get(ref)!r}; "
                f"NEW={new_components.get(ref)!r}"
            )
    return differences


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("base", help="baseline KiCad XML netlist")
    parser.add_argument("new", help="candidate KiCad XML netlist")
    parser.add_argument("--names", action="store_true", help="also require net names to match")
    args = parser.parse_args(argv)
    try:
        differences = compare(args.base, args.new, args.names)
    except (OSError, ET.ParseError, ValueError) as exc:
        print(json.dumps({"status": "INCONCLUSIVE", "reason": str(exc)}, sort_keys=True))
        return 2
    print(json.dumps({
        "status": "PASS" if not differences else "BLOCKED",
        "differences": differences,
    }, sort_keys=True))
    return 0 if not differences else 1


if __name__ == "__main__":
    raise SystemExit(main())
