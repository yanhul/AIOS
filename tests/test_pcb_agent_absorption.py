"""Regression tests for the PCB-agent validation helpers absorbed into AIOS."""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COMPARE = ROOT / "scripts" / "pcb_validation" / "compare_netlist.py"
PIN_PAD = ROOT / "scripts" / "pcb_validation" / "check_pin_pad.py"


def netlist(a_pin: str = "1", b_pin: str = "2", value: str = "10k") -> str:
    return f'''<?xml version="1.0" encoding="utf-8"?>
<export><components>
 <comp ref="R1"><value>{value}</value><footprint>Resistor_SMD:R_0603_1608Metric</footprint></comp>
 <comp ref="J1"><value>Conn_01x02</value><footprint>Connector_PinHeader_2.54mm:PinHeader_1x02_P2.54mm_Vertical</footprint></comp>
</components><nets>
 <net name="GND" code="1"><node ref="R1" pin="{a_pin}"/><node ref="J1" pin="1"/></net>
 <net name="SIG" code="2"><node ref="R1" pin="2"/><node ref="J1" pin="{b_pin}"/></net>
</nets></export>'''


def board(pads: str = '"1" "2"') -> str:
    return f'''(kicad_pcb (version 20250114) (general)
 (footprint "Resistor_SMD:R_0603_1608Metric"
  (property "Reference" "R1")
  (pad "1" smd rect (at 0 0) (size 1 1) (layers "F.Cu"))
  (pad "2" smd rect (at 1 0) (size 1 1) (layers "F.Cu")))
 (footprint "Connector_PinHeader_2.54mm:PinHeader_1x02_P2.54mm_Vertical"
  (property "Reference" "J1")
  (pad {pads.split()[0]} thru_hole circle (at 0 0) (size 1 1) (drill 0.5) (layers "*.Cu" "*.Mask"))
  (pad {pads.split()[1]} thru_hole circle (at 0 2.54) (size 1 1) (drill 0.5) (layers "*.Cu" "*.Mask"))))'''


class PcbAgentAbsorptionTests(unittest.TestCase):
    def run_json(self, script: Path, *args: str) -> tuple[int, dict]:
        proc = subprocess.run(
            [sys.executable, str(script), *args],
            text=True, capture_output=True, check=False,
        )
        self.assertTrue(proc.stdout.strip(), proc.stderr)
        return proc.returncode, json.loads(proc.stdout)

    def test_netlist_comparison_passes_for_identical_connectivity(self):
        with tempfile.TemporaryDirectory() as td:
            base, new = Path(td) / "base.xml", Path(td) / "new.xml"
            base.write_text(netlist(), encoding="utf-8")
            new.write_text(netlist(), encoding="utf-8")
            rc, result = self.run_json(COMPARE, str(base), str(new))
            self.assertEqual(rc, 0)
            self.assertEqual(result["status"], "PASS")

    def test_netlist_comparison_blocks_connectivity_or_component_change(self):
        with tempfile.TemporaryDirectory() as td:
            base, new = Path(td) / "base.xml", Path(td) / "new.xml"
            base.write_text(netlist(), encoding="utf-8")
            new.write_text(netlist(a_pin="2", value="12k"), encoding="utf-8")
            rc, result = self.run_json(COMPARE, str(base), str(new))
            self.assertEqual(rc, 1)
            self.assertEqual(result["status"], "BLOCKED")
            self.assertTrue(result["differences"])

    def test_pin_pad_check_passes_matching_pad_sets(self):
        with tempfile.TemporaryDirectory() as td:
            nl, pcb = Path(td) / "netlist.xml", Path(td) / "board.kicad_pcb"
            nl.write_text(netlist(), encoding="utf-8")
            pcb.write_text(board(), encoding="utf-8")
            rc, result = self.run_json(PIN_PAD, str(nl), "--pcb", str(pcb))
            self.assertEqual(rc, 0, result)
            self.assertEqual(result["status"], "PASS")

    def test_pin_pad_check_blocks_missing_pad(self):
        with tempfile.TemporaryDirectory() as td:
            nl, pcb = Path(td) / "netlist.xml", Path(td) / "board.kicad_pcb"
            nl.write_text(netlist(), encoding="utf-8")
            pcb.write_text(board('"1" "3"'), encoding="utf-8")
            rc, result = self.run_json(PIN_PAD, str(nl), "--pcb", str(pcb))
            self.assertEqual(rc, 1)
            self.assertEqual(result["status"], "BLOCKED")
            self.assertTrue(result["findings"])


if __name__ == "__main__":
    unittest.main()
