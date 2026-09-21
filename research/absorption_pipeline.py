"""Convert source-backed research findings into governed absorption candidates.

This module does NOT copy external code or self-promote anything. It creates
candidate records and bounded implementation tasks for AIOS-controlled review.
"""
from __future__ import annotations
import hashlib, json, os
from pathlib import Path

SCAN = Path(os.environ.get("AIOS_RESEARCH_SCAN", "research/artifacts/daily-scan.json"))
OUT = Path(os.environ.get("AIOS_ABSORPTION_OUT", "research/artifacts/absorption-candidates.json"))
ALLOWED = ("harness","research","memory","provenance","governance","execution","agent")

def _digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()

def _primitive(text: str) -> str:
    t = text.lower()
    if "provenance" in t or "evidence" in t:
        return "evidence_provenance"
    if "research" in t or "experiment" in t:
        return "research_harness"
    if "memory" in t:
        return "memory"
    if "execution" in t or "durable" in t or "retry" in t:
        return "durable_execution"
    return "agent_harness"

def build(scan: dict) -> dict:
    candidates = []
    for r in scan.get("records", []):
        text = " ".join(str(r.get(k,"")) for k in ("repo","description","query"))
        if not any(k in text.lower() for k in ALLOWED):
            continue
        candidate = {
            "candidate_id": "cand-" + _digest({"source_ref":r["source_ref"],"digest":r["source_digest"]})[:16],
            "source_ref": r["source_ref"],
            "source_digest": r["source_digest"],
            "primitive": _primitive(text),
            "status": "UNTRUSTED_EVIDENCE",
            "mutation_authority": "AIOS",
            "external_code_copy": False,
            "next_action": "RESEARCH_AND_VERIFY",
            "bounded_surface": ["new AIOS adapter/task only"],
            "promotion_required": True,
        }
        candidates.append(candidate)
    result = {"schema_version":1, "kind":"AIOS_ABSORPTION_CANDIDATES",
              "candidates":candidates}
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(result, indent=2, sort_keys=True)+"\n", encoding="utf-8")
    return result

if __name__ == "__main__":
    build(json.loads(SCAN.read_text(encoding="utf-8")))
