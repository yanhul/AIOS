#!/usr/bin/env python3
"""Check KiCad schematic pin numbers against placed PCB footprint pad numbers.

Adapted from John-owo/pcb-agent-workflow's readable-schematic-layout check.
Read-only: it reports mismatches and never edits the schematic or board.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

PAD_RE = re.compile(r'\(pad\s+"((?:[^"\\\\]|\\\\.)*)"')
REF_RE = re.compile(
    r'\(property\s+"Reference"\s+"((?:[^"\\\\]|\\\\.)*)"'
    r'|\(fp_text\s+reference\s+"((?:[^"\\\\]|\\\\.)*)"'
)


def netlist_pin_sets(path: str | Path) -> dict[str, set[str]]:
    root = ET.parse(path).getroot()
    components = root.find("components")
    nets = root.find("nets")
    if components is None or nets is None:
        raise ValueError(f"{path}: missing components/nets")
    refs: set[str] = set()
    for comp in components.findall("comp"):
        ref = comp.get("ref")
        if ref and not ref.startswith("#"):
            refs.add(ref)
    pins = {ref: set() for ref in refs}
    for net in nets.findall("net"):
        for node in net.findall("node"):
            ref, pin = node.get("ref"), node.get("pin")
            if ref in pins and pin is not None:
                pins[ref].add(pin)
    return pins


def _sexpr_blocks(text: str, head: str):
    token = "(" + head
    pos = 0
    while True:
        start = text.find(token, pos)
        if start < 0:
            return
        next_char = text[start + len(token):start + len(token) + 1]
        if next_char and not next_char.isspace():
            pos = start + 1
            continue
        depth, i, in_string = 0, start, False
        while i < len(text):
            char = text[i]
            if in_string:
                if char == "\\\\":
                    i += 1
                elif char == '"':
                    in_string = False
            elif char == '"':
                in_string = True
            elif char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        if depth != 0:
            raise ValueError(f"unbalanced KiCad s-expression starting at byte {start}")
        yield text[start:i + 1]
        pos = i + 1


def board_pad_sets(path: str | Path) -> dict[str, set[str]]:
    text = Path(path).read_text(encoding="utf-8")
    result: dict[str, set[str]] = {}
    for block in _sexpr_blocks(text, "footprint"):
        match = REF_RE.search(block)
        if not match:
            continue
        ref = match.group(1) if match.group(1) is not None else match.group(2)
        pads = {m.group(1) for m in PAD_RE.finditer(block) if m.group(1) != ""}
        if ref in result:
            raise ValueError(f"duplicate footprint reference on board: {ref}")
        result[ref] = pads
    return result


def check(netlist_path: str | Path, board_path: str | Path) -> list[dict[str, object]]:
    pins = netlist_pin_sets(netlist_path)
    pads = board_pad_sets(board_path)
    findings: list[dict[str, object]] = []
    for ref in sorted(set(pins) | set(pads)):
        if ref not in pads:
            findings.append({"ref": ref, "status": "BLOCKED", "reason": "no placed footprint"})
            continue
        missing_pads = sorted(pins.get(ref, set()) - pads[ref])
        extra_pads = sorted(pads[ref] - pins.get(ref, set()))
        if missing_pads or extra_pads:
            findings.append({
                "ref": ref, "status": "BLOCKED",
                "pins_without_pads": missing_pads,
                "pads_without_pins": extra_pads,
            })
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("netlist", help="KiCad XML netlist exported from the schematic")
    parser.add_argument("--pcb", required=True, help="candidate .kicad_pcb file")
    args = parser.parse_args(argv)
    try:
        findings = check(args.netlist, args.pcb)
    except (OSError, ET.ParseError, ValueError) as exc:
        print(json.dumps({"status": "INCONCLUSIVE", "reason": str(exc)}, sort_keys=True))
        return 2
    print(json.dumps({
        "status": "PASS" if not findings else "BLOCKED",
        "findings": findings,
        "scope": "pin-number/pad-number set equality only",
    }, sort_keys=True))
    return 0 if not findings else 1


if __name__ == "__main__":
    raise SystemExit(main())
