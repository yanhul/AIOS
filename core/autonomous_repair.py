"""Durable autonomous repair controller.

The controller orchestrates run -> diagnose -> local fix -> external search ->
adapt -> retest -> verify. It does not grant authority, mutate execution
receipts, or self-attest PASS. Concrete runners/fixers/search providers are
injected and must return evidence-bearing records.
"""
from __future__ import annotations

import json
import os
import tempfile
from dataclasses import asdict, dataclass, field
from typing import Any, Mapping, Protocol

TERMINAL = frozenset({"PASS", "BLOCKED"})

class RepairControllerError(RuntimeError):
    pass

@dataclass(frozen=True)
class RunEvidence:
    status: str
    evidence_refs: tuple[str, ...]
    details: Mapping[str, Any] = field(default_factory=dict)

@dataclass(frozen=True)
class Diagnosis:
    root_cause: str
    local_fix: str
    external_search: str
    evidence_refs: tuple[str, ...]

@dataclass(frozen=True)
class RepairResult:
    applied: bool
    patch_ref: str
    evidence_refs: tuple[str, ...]
    details: Mapping[str, Any] = field(default_factory=dict)

@dataclass(frozen=True)
class Verification:
    verified: bool
    evidence_refs: tuple[str, ...]
    reason: str

class Runner(Protocol):
    def run(self) -> RunEvidence: ...

class Diagnoser(Protocol):
    def diagnose(self, run: RunEvidence) -> Diagnosis: ...

class LocalFixer(Protocol):
    def fix(self, diagnosis: Diagnosis) -> RepairResult: ...

class SearchProvider(Protocol):
    def search(self, diagnosis: Diagnosis) -> RepairResult: ...

class Adapter(Protocol):
    def adapt(self, candidate: RepairResult, diagnosis: Diagnosis) -> RepairResult: ...

class Verifier(Protocol):
    def verify(self, run: RunEvidence, history: tuple[Mapping[str, Any], ...]) -> Verification: ...

class DurableRepairStore:
    """Crash-safe JSON state store. State is advisory; authority stays in AIOS."""
    def __init__(self, path: str):
        self.path = path

    def load(self) -> dict[str, Any] | None:
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except FileNotFoundError:
            return None

    def save(self, state: Mapping[str, Any]) -> None:
        directory = os.path.dirname(os.path.abspath(self.path))
        os.makedirs(directory, exist_ok=True)
        fd, tmp = tempfile.mkstemp(prefix=".repair-", dir=directory)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(dict(state), fh, sort_keys=True, indent=2)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, self.path)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)

@dataclass
class AutonomousRepairController:
    runner: Runner
    diagnoser: Diagnoser
    local_fixer: LocalFixer
    search_provider: SearchProvider
    adapter: Adapter
    verifier: Verifier
    store: DurableRepairStore
    max_repairs: int = 3
    max_external_repairs: int = 2

    def _save(self, state: dict[str, Any]) -> None:
        self.store.save(state)

    @staticmethod
    def _append(state: dict[str, Any], phase: str, payload: Mapping[str, Any]) -> None:
        state.setdefault("history", []).append({"phase": phase, **dict(payload)})

    def run(self) -> dict[str, Any]:
        state = self.store.load() or {
            "phase": "RUN", "repair_attempts": 0, "external_attempts": 0, "history": []
        }
        if state.get("phase") in TERMINAL:
            return state

        while state["phase"] not in TERMINAL:
            phase = state["phase"]

            if phase == "RUN":
                run = self.runner.run()
                state["last_run"] = asdict(run)
                self._append(state, phase, {"status": run.status, "evidence_refs": list(run.evidence_refs)})
                state["phase"] = "VERIFY" if run.status == "PASS" else "DIAGNOSE"
                self._save(state)

            elif phase == "DIAGNOSE":
                diagnosis = self.diagnoser.diagnose(RunEvidence(**state["last_run"]))
                if not diagnosis.evidence_refs:
                    raise RepairControllerError("diagnosis requires evidence_refs")
                state["diagnosis"] = asdict(diagnosis)
                state["phase"] = "LOCAL_FIX"
                self._append(state, phase, {"root_cause": diagnosis.root_cause,
                                            "evidence_refs": list(diagnosis.evidence_refs)})
                self._save(state)

            elif phase == "LOCAL_FIX":
                diagnosis = Diagnosis(**state["diagnosis"])
                if state["repair_attempts"] >= self.max_repairs:
                    state["phase"] = "EXTERNAL_SEARCH"
                    self._save(state)
                    continue
                result = self.local_fixer.fix(diagnosis)
                state["repair_attempts"] += 1
                state["last_repair"] = asdict(result)
                state["phase"] = "RETEST" if result.applied and result.evidence_refs else "EXTERNAL_SEARCH"
                self._append(state, phase, {"applied": result.applied, "patch_ref": result.patch_ref,
                                            "evidence_refs": list(result.evidence_refs)})
                self._save(state)

            elif phase == "EXTERNAL_SEARCH":
                if state["external_attempts"] >= self.max_external_repairs:
                    state["phase"] = "BLOCKED"
                    state["block_reason"] = "repair budget exhausted"
                    self._save(state)
                    continue
                candidate = self.search_provider.search(Diagnosis(**state["diagnosis"]))
                state["external_attempts"] += 1
                if not candidate.evidence_refs:
                    state["phase"] = "BLOCKED"
                    state["block_reason"] = "external candidate has no evidence"
                else:
                    state["candidate"] = asdict(candidate)
                    state["phase"] = "ADAPT"
                self._append(state, phase, {"patch_ref": candidate.patch_ref,
                                            "evidence_refs": list(candidate.evidence_refs)})
                self._save(state)

            elif phase == "ADAPT":
                adapted = self.adapter.adapt(RepairResult(**state["candidate"]), Diagnosis(**state["diagnosis"]))
                if not adapted.applied or not adapted.evidence_refs:
                    state["phase"] = "BLOCKED"
                    state["block_reason"] = "adapted external solution lacks patch/evidence"
                else:
                    state["last_repair"] = asdict(adapted)
                    state["phase"] = "RETEST"
                self._append(state, phase, {"patch_ref": adapted.patch_ref,
                                            "evidence_refs": list(adapted.evidence_refs)})
                self._save(state)

            elif phase == "RETEST":
                run = self.runner.run()
                state["last_run"] = asdict(run)
                state["phase"] = "VERIFY"
                self._append(state, phase, {"status": run.status,
                                            "evidence_refs": list(run.evidence_refs)})
                self._save(state)

            elif phase == "VERIFY":
                run = RunEvidence(**state["last_run"])
                verification = self.verifier.verify(run, tuple(state.get("history", [])))
                self._append(state, phase, {"verified": verification.verified,
                                            "reason": verification.reason,
                                            "evidence_refs": list(verification.evidence_refs)})
                if verification.verified and verification.evidence_refs:
                    state["phase"] = "PASS"
                elif state["repair_attempts"] < self.max_repairs:
                    state["phase"] = "DIAGNOSE"
                elif state["external_attempts"] < self.max_external_repairs:
                    state["phase"] = "EXTERNAL_SEARCH"
                else:
                    state["phase"] = "BLOCKED"
                    state["block_reason"] = verification.reason
                self._save(state)

        return state

__all__ = ["AutonomousRepairController", "DurableRepairStore", "Diagnosis",
           "RepairControllerError", "RepairResult", "RunEvidence", "Verification"]
