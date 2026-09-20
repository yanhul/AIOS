"""Gemini-backed repair proposal adapter.

This module stops at structured proposals. It never grants authority,
executes shell commands, mutates receipts, or declares PASS.
"""
from __future__ import annotations
import json, os, urllib.request
from dataclasses import dataclass
from typing import Any, Mapping

class GeminiRepairError(RuntimeError):
    pass

@dataclass(frozen=True)
class RepairProposal:
    root_cause: str
    proposed_fix: str
    files: tuple[Mapping[str, Any], ...]
    regression_tests: tuple[str, ...]
    confidence: float | None

class GeminiRepairProvider:
    def __init__(self, api_key: str | None = None, model: str | None = None):
        self.api_key = api_key or os.environ.get("GEMINI_API_KEY")
        self.model = model or os.environ.get("GEMINI_MODEL", "gemini-2.5-flash")
        if not self.api_key:
            raise GeminiRepairError("GEMINI_API_KEY is required")

    def propose(self, *, failure: Mapping[str, Any], repository_snapshot: str) -> RepairProposal:
        prompt = {
            "task": "Diagnose a software failure and propose a minimal repair.",
            "rules": [
                "Do not claim tests passed.",
                "Do not invent evidence.",
                "Return only necessary files.",
                "Do not weaken authority, receipt, or policy semantics.",
                "Include regression tests.",
            ],
            "failure": failure,
            "repository_snapshot": repository_snapshot,
            "output_schema": {
                "root_cause": "string",
                "proposed_fix": "string",
                "files": [{"path": "string", "content": "string"}],
                "regression_tests": ["string"],
                "confidence": "number|null",
            },
        }
        url = ("https://generativelanguage.googleapis.com/v1beta/models/"
               f"{self.model}:generateContent?key={self.api_key}")
        body = json.dumps({
            "contents": [{"parts": [{"text": json.dumps(prompt, sort_keys=True)}]}],
            "generationConfig": {"responseMimeType": "application/json"},
        }).encode()
        request = urllib.request.Request(url, data=body,
            headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                payload = json.loads(response.read().decode())
        except Exception as exc:
            raise GeminiRepairError(f"Gemini request failed: {exc}") from exc
        try:
            text = payload["candidates"][0]["content"]["parts"][0]["text"]
            result = json.loads(text)
            files = tuple(result.get("files", ()))
            tests = tuple(result.get("regression_tests", ()))
            if not result.get("root_cause") or not result.get("proposed_fix"):
                raise ValueError("missing diagnosis/fix")
            if any(not isinstance(x, Mapping) or not x.get("path") or "content" not in x for x in files):
                raise ValueError("invalid file proposal")
            return RepairProposal(result["root_cause"], result["proposed_fix"],
                                  files, tests, result.get("confidence"))
        except (KeyError, IndexError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise GeminiRepairError(f"invalid structured Gemini response: {exc}") from exc
