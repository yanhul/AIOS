from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from core.agent_repair_worker import AgentRepairWorker
from core.repair_agent import AgentLoopError, AgentRepairWorker, AgentTurn, RepairAgent, ToolCall


class Authority:
    def authorize_patch(self, *, base_sha, paths):
        return "PERMIT-1"


class Tools:
    def inspect(self, path):
        return {"path": path, "content": Path(path).read_text()}

    def search(self, query):
        return {"query": query, "matches": ["candidate-1"]}


class Planner:
    def __init__(self):
        self.i = 0

    def next_turn(self, *, failure, observations):
        self.i += 1
        if self.i == 1:
            return AgentTurn((ToolCall("inspect", {"path": "module.py"}), ToolCall("search", {"query": "VALUE mismatch"})))
        if self.i == 2:
            return AgentTurn((ToolCall("patch", {
                "root_cause": "wrong value",
                "proposed_fix": "set expected value",
                "files": [{"path": "module.py", "content": "VALUE = 2\n"}],
            }), ToolCall("test")))
        raise AssertionError("agent should have passed")


def init_repo(tmp_path: Path) -> str:
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "user.name", "AIOS Test"], cwd=tmp_path, check=True)
    (tmp_path / "module.py").write_text("VALUE = 1\n")
    subprocess.run(["git", "add", "module.py"], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-qm", "base"], cwd=tmp_path, check=True)
    return subprocess.run(["git", "rev-parse", "HEAD"], cwd=tmp_path, text=True, capture_output=True, check=True).stdout.strip()


def make_agent(tmp_path, planner):
    base = init_repo(tmp_path)
    trusted = ("python", "-c", "assert open('module.py').read().strip() == 'VALUE = 2'")
    worker = AgentRepairWorker(tmp_path, Authority(), allowed_test_commands=(trusted,))
    return RepairAgent(
        planner=planner, tools=Tools(), worker=worker, base_sha=base,
        failure={"error": "VALUE mismatch"}, max_turns=4
    )


def test_agent_repairs_then_tests(tmp_path):
    result = make_agent(tmp_path, Planner()).run()
    assert result["status"] == "PASS"
    assert (tmp_path / "module.py").read_text() == "VALUE = 2\n"


class BadPlanner:
    def next_turn(self, **_):
        return AgentTurn((ToolCall("shell", {"command": "rm -rf ."}),))


def test_agent_has_no_shell_tool(tmp_path):
    with pytest.raises(AgentLoopError, match="unsupported tool"):
        make_agent(tmp_path, BadPlanner()).run()


class SelfAttestingPlanner:
    def next_turn(self, **_):
        return AgentTurn((), done=True, reason="looks good")


def test_agent_cannot_self_declare_pass(tmp_path):
    with pytest.raises(AgentLoopError, match="self-declare"):
        make_agent(tmp_path, SelfAttestingPlanner()).run()
