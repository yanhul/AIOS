import json

import pytest

from core.effect_authority import (
    begin_dispatch,
    create_effect,
    mark_dispatched,
    reconcile_inflight,
    retry_dispatch,
    observe,
)
from core.mutation import TransitionError


def test_provider_intent_is_durable_before_dispatch(tmp_path):
    effect = create_effect(str(tmp_path), "CONTRACT-1", "op-1", "control-plane")
    pending = begin_dispatch(
        str(tmp_path), effect["effect_id"], "control-plane",
        f'{effect["effect_id"]}:attempt:1', "provider-a",
    )
    assert pending["state"] == "DISPATCHING"
    stored = json.loads((tmp_path / "effects" / f'{effect["effect_id"]}.json').read_text())
    assert stored["state"] == "DISPATCHING"
    assert stored["attempt"] == 1


def test_restart_reconciles_inflight_to_unknown_and_blocks_blind_retry(tmp_path):
    effect = create_effect(str(tmp_path), "CONTRACT-1", "op-1", "control-plane")
    begin_dispatch(
        str(tmp_path), effect["effect_id"], "control-plane",
        f'{effect["effect_id"]}:attempt:1', "provider-a",
    )

    reconciled = reconcile_inflight(str(tmp_path), "recovery", "process restarted")
    assert len(reconciled) == 1
    assert reconciled[0]["state"] == "UNKNOWN"

    with pytest.raises(TransitionError):
        mark_dispatched(str(tmp_path), effect["effect_id"], "recovery")

    retried = retry_dispatch(
        str(tmp_path), effect["effect_id"], "control-plane",
        f'{effect["effect_id"]}:attempt:2', "provider-a", 2,
    )
    assert retried["state"] == "DISPATCHING"
    assert retried["attempt"] == 2


def test_explicit_provider_observation_resolves_unknown_before_terminal_retry(tmp_path):
    effect = create_effect(str(tmp_path), "CONTRACT-1", "op-1", "control-plane")
    begin_dispatch(
        str(tmp_path), effect["effect_id"], "control-plane",
        f'{effect["effect_id"]}:attempt:1', "provider-a",
    )
    reconcile_inflight(str(tmp_path), "recovery")
    observed = observe(
        str(tmp_path), effect["effect_id"], "provider-a",
        "OBSERVED_SUCCESS", {"provider": "provider-a", "remote_id": "r-1"},
    )
    assert observed["state"] == "OBSERVED_SUCCESS"

    with pytest.raises(TransitionError):
        retry_dispatch(
            str(tmp_path), effect["effect_id"], "control-plane",
            f'{effect["effect_id"]}:attempt:2', "provider-a", 2,
        )
