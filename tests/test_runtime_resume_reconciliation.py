"""Crash recovery reconciles a dispatched provider attempt; it never replays it."""

from core.authority import load_contract
from core.effect_authority import ProviderKeyring, dispatch
from core.runtime import ProviderReceipt, resume_attempt
from tests.provider_keys import KEYRING_SPEC, signed
from tests.test_m6_effect_authority import _effect

ACTOR = "agent-1"
PROVIDER = "provider-1"
KEYRING = ProviderKeyring(KEYRING_SPEC)


def _dispatched(tmp_path):
    effect = _effect(tmp_path)
    return dispatch(str(tmp_path), effect["effect_id"], ACTOR,
                    f"{effect['effect_id']}:attempt:1", PROVIDER)


class _NoReplayAdapter:
    name = PROVIDER

    def __init__(self, receipt):
        self.receipt = receipt
        self.execute_calls = 0
        self.reconcile_calls = 0

    def execute(self, **kwargs):
        self.execute_calls += 1
        raise AssertionError("resume must never replay execute")

    def reconcile(self, *, contract, effect, attempt_id):
        self.reconcile_calls += 1
        assert attempt_id == effect["attempt_id"]
        return self.receipt


def test_resume_reconciles_signed_receipt_without_reexecuting(tmp_path):
    effect = _dispatched(tmp_path)
    raw = ProviderReceipt(PROVIDER, effect["effect_id"], effect["attempt_id"],
                          "provider-op-1", "OBSERVED_SUCCESS", {"status": "committed"})
    adapter = _NoReplayAdapter(signed(raw, effect))
    contract = load_contract(str(tmp_path), effect["contract_id"])

    result = resume_attempt(str(tmp_path), contract, effect, ACTOR, adapter, None,
                            provider_keyring=KEYRING)

    assert result["state"] == "OBSERVED_SUCCESS"
    assert adapter.reconcile_calls == 1
    assert adapter.execute_calls == 0


def test_resume_without_reconcile_fails_closed_to_unknown(tmp_path):
    effect = _dispatched(tmp_path)
    contract = load_contract(str(tmp_path), effect["contract_id"])

    class NoReconcile:
        name = PROVIDER
        execute_calls = 0

        def execute(self, **kwargs):
            self.execute_calls += 1
            raise AssertionError("must not execute")

    adapter = NoReconcile()
    result = resume_attempt(str(tmp_path), contract, effect, ACTOR, adapter, None)

    assert result["state"] == "UNKNOWN"
    assert "refusing to replay" in result["unknown_reason"]
    assert adapter.execute_calls == 0


def test_resume_with_no_provider_record_remains_unknown(tmp_path):
    effect = _dispatched(tmp_path)
    contract = load_contract(str(tmp_path), effect["contract_id"])

    class NoRecord:
        name = PROVIDER
        execute_calls = 0

        def execute(self, **kwargs):
            self.execute_calls += 1
            raise AssertionError("must not execute")

        def reconcile(self, **kwargs):
            return None

    adapter = NoRecord()
    result = resume_attempt(str(tmp_path), contract, effect, ACTOR, adapter, None)

    assert result["state"] == "UNKNOWN"
    assert "no authoritative result" in result["unknown_reason"]
    assert adapter.execute_calls == 0
