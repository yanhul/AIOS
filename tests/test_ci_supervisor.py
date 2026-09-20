from __future__ import annotations

import json

import pytest

from core.ci_supervisor import CIEvent, CIEventError, DurableCIInbox


def event(**overrides):
    data = dict(
        repository="yanhul/AIOS",
        workflow="CI",
        run_id=12345,
        sha="a" * 40,
        conclusion="failure",
        ref="refs/heads/feat/x",
        pr_number=22,
    )
    data.update(overrides)
    return CIEvent(**data)


def test_receive_is_durable_and_deduplicated(tmp_path):
    inbox = DurableCIInbox(str(tmp_path))
    first = inbox.receive(event(), "yanhul/AIOS")
    second = inbox.receive(event(), "yanhul/AIOS")
    assert first == second
    files = list(tmp_path.glob("*.json"))
    assert len(files) == 1
    payload = json.loads(files[0].read_text())
    assert payload["event"]["run_id"] == 12345


def test_rejects_wrong_repository(tmp_path):
    with pytest.raises(CIEventError, match="repository mismatch"):
        DurableCIInbox(str(tmp_path)).receive(event(), "attacker/AIOS")


def test_rejects_invalid_sha(tmp_path):
    with pytest.raises(CIEventError, match="sha"):
        DurableCIInbox(str(tmp_path)).receive(event(sha="bad"), "yanhul/AIOS")


def test_failure_wakes_repair_path(tmp_path):
    state = DurableCIInbox(str(tmp_path)).receive(event(), "yanhul/AIOS")
    assert state.status == "RECEIVED"
    assert state.next_action == "REPAIR_OR_DIAGNOSE"


def test_success_wakes_verification(tmp_path):
    state = DurableCIInbox(str(tmp_path)).receive(
        event(conclusion="success"), "yanhul/AIOS"
    )
    assert state.next_action == "VERIFY"


def test_malformed_conclusion_fails_closed(tmp_path):
    with pytest.raises(CIEventError, match="conclusion"):
        DurableCIInbox(str(tmp_path)).receive(
            event(conclusion="PASS"), "yanhul/AIOS"
        )
