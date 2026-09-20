"""Bounded coding-agent loop for autonomous repair.

The model is a planner only. Tools are typed capabilities. Mutation is delegated
to AgentRepairWorker, so model output never becomes shell input or authority.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Protocol, Sequence

from .agent_repair_worker import (
    AgentRepairWorker,
    ProposedFile,
    RepairProposal,
    WorkerEvidence,
)


class AgentLoopError(RuntimeError):
    pass


@dataclass(frozen=True)
class ToolCall:
    name: str
    args: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class AgentTurn:
    calls: tuple[ToolCall, ...]
    done: bool = False
    reason: str = ""


class AgentPlanner(Protocol):
    def next_turn(
        self, *, failure: Mapping[str, Any], observations: Sequence[Mapping[str, Any]]
    ) -> AgentTurn: ...


class RepairTools(Protocol):
    def inspect(self, path: str) -> Mapping[str, Any]: ...
    def search(self, query: str) -> Mapping[str, Any]: ...


class RepairAgent:
    """Run a bounded observe/search/patch/test loop.

    The planner can request only typed tools. It cannot execute arbitrary shell
    commands, grant authority, or declare PASS. PASS is returned only from a
    trusted test result.
    """

    _READ_ONLY = frozenset({"inspect", "search"})
    _ACTIONABLE = frozenset({"patch", "test", "finish"})

    def __init__(
        self,
        *,
        planner: AgentPlanner,
        tools: RepairTools,
        worker: AgentRepairWorker,
        base_sha: str,
        failure: Mapping[str, Any],
        repository_snapshot: str = "",
        max_turns: int = 12,
    ) -> None:
        if len(base_sha) != 40:
            raise AgentLoopError("base_sha must be a full commit SHA")
        if max_turns < 1:
            raise AgentLoopError("max_turns must be positive")
        self.planner = planner
        self.tools = tools
        self.worker = worker
        self.base_sha = base_sha
        self.failure = dict(failure)
        self.repository_snapshot = repository_snapshot
        self.max_turns = max_turns

    def _call_read_only(self, call: ToolCall) -> Mapping[str, Any]:
        if call.name == "inspect":
            path = call.args.get("path")
            if not isinstance(path, str) or not path.strip():
                raise AgentLoopError("inspect requires a path")
            return dict(self.tools.inspect(path))
        if call.name == "search":
            query = call.args.get("query")
            if not isinstance(query, str) or not query.strip():
                raise AgentLoopError("search requires a query")
            return dict(self.tools.search(query))
        raise AgentLoopError(f"unknown read-only tool: {call.name}")

    @staticmethod
    def _proposal(call: ToolCall) -> RepairProposal:
        files = call.args.get("files")
        if not isinstance(files, list) or not files:
            raise AgentLoopError("patch requires a non-empty files list")
        proposed = []
        for item in files:
            if not isinstance(item, Mapping):
                raise AgentLoopError("patch file must be an object")
            path, content = item.get("path"), item.get("content")
            if not isinstance(path, str) or not isinstance(content, str):
                raise AgentLoopError("patch file requires string path/content")
            proposed.append(ProposedFile(path, content))
        root = call.args.get("root_cause", "agent repair")
        fix = call.args.get("proposed_fix", "agent patch")
        if not isinstance(root, str) or not root.strip() or not isinstance(fix, str) or not fix.strip():
            raise AgentLoopError("patch requires root_cause and proposed_fix")
        return RepairProposal(root, fix, tuple(proposed))

    def run(self) -> Mapping[str, Any]:
        observations: list[Mapping[str, Any]] = []
        for turn_index in range(self.max_turns):
            turn = self.planner.next_turn(
                failure=dict(self.failure), observations=tuple(observations)
            )
            if not isinstance(turn, AgentTurn):
                raise AgentLoopError("planner returned invalid turn")
            if turn.done:
                raise AgentLoopError("planner cannot self-declare PASS")

            for call in turn.calls:
                if call.name in self._READ_ONLY:
                    observations.append({
                        "turn": turn_index,
                        "tool": call.name,
                        "result": self._call_read_only(call),
                    })
                    continue

                if call.name == "patch":
                    proposal = self._proposal(call)
                    if self.worker.aios_dir:
                        applied = self.worker.apply_via_aios(
                            base_sha=self.base_sha,
                            files=proposal.files,
                            logical_operation_id=f"repair:{self.base_sha}:{turn_index}",
                        )
                        observations.append({
                            "turn": turn_index,
                            "tool": "patch",
                            "result": {
                                "status": "OBSERVED_SUCCESS",
                                "aios": True,
                                "result": dict(applied),
                            },
                        })
                        continue
                    applied = self.worker.apply(
                        base_sha=self.base_sha, files=proposal.files
                    )
                    observations.append({
                        "turn": turn_index,
                        "tool": "patch",
                        "result": {
                            "status": applied.status,
                            "evidence_refs": list(applied.evidence_refs),
                            "details": dict(applied.details),
                        },
                    })
                    continue

                if call.name == "test":
                    tested = self.worker.test()
                    observations.append({
                        "turn": turn_index,
                        "tool": "test",
                        "result": {
                            "status": tested.status,
                            "evidence_refs": list(tested.evidence_refs),
                            "details": dict(tested.details),
                        },
                    })
                    if tested.status == "PASS":
                        return {
                            "status": "PASS",
                            "turns": turn_index + 1,
                            "evidence_refs": list(tested.evidence_refs),
                            "observations": observations,
                        }
                    continue

                if call.name == "finish":
                    raise AgentLoopError("planner cannot declare terminal success")

                raise AgentLoopError(f"unsupported tool call: {call.name}")

        return {
            "status": "BLOCKED",
            "reason": "agent turn budget exhausted",
            "turns": self.max_turns,
            "observations": observations,
        }


__all__ = ["AgentLoopError", "AgentPlanner", "AgentRepairWorker", "AgentTurn",
           "RepairAgent", "RepairTools", "ToolCall"]
