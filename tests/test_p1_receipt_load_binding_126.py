# AIOS-CONTRACT: load_receipt() reads the effect through the same validated loader as every state
#                transition (PR #126 re-review @9ce0f2d P1)
# AIOS-REGRESSION: A persisted receipt must not be accepted when its effect record (a) names a provider that
#                  is not a contract capability, even one holding a valid trusted key, (b) diverges from the
#                  authorized contract (policy digest, attempt budget, permit), (c) carries an attempt identity
#                  that is not the derived id, or (d) stores an effect_id different from its path. A receipt's
#                  effect_id / receipt_id must never steer a filesystem read outside the state tree.
# AIOS-OWNER: AIOS control-plane durable execution
# AIOS-COVERAGE-GAP: Unsealed receipts (require_sealed=False) remain integrity-only; key custody is out of scope.
# AIOS-BASELINE: 9ce0f2d (589 passed, 1 skipped)

import json
import os

import pytest

import core.runtime as runtime
from core.effect_authority import load_receipt, receipt_id_for
from core.mutation import TransitionError
from core.provider_trust import trusted_keys
from core.record_seal import unsealed_body
from core.runtime import execute
from tests.provider_trust_helpers import signed_receipt
from tests.test_m6_runtime import setup_authority
from tests.test_p0_receipt_lineage_crash_recovery import ACTOR, Provider

OUTSIDER = "provider-a"  # holds a trusted test key (conftest) but is NOT a contract capability


def _paths(aios, done):
    return (os.path.join(aios, "effects", done["effect_id"] + ".json"),
            os.path.join(aios, "receipts", done["receipt_id"] + ".json"))


def _done(tmp_path):
    aios = str(tmp_path)
    _, cid, pid = setup_authority(tmp_path)
    done = execute(aios, cid, pid, "op-1", ACTOR, Provider())
    assert done["state"] == "OBSERVED_SUCCESS"
    assert load_receipt(aios, done["receipt_id"])["receipt_id"] == done["receipt_id"]  # baseline is loadable
    return aios, done


def _edit_effect(aios, done, **fields):
    epath, _ = _paths(aios, done)
    eff = json.load(open(epath))
    eff.update(fields)
    json.dump(eff, open(epath, "w"))
    return eff


# ------------------------------------------------------------------ sealed receipt, tampered effect record

@pytest.mark.parametrize("field,value", [
    ("policy_digest", "sha256:" + "0" * 64),
    ("max_attempts", 99),
    ("permit_id", "PM-forged"),
])
def test_receipt_is_refused_when_its_effect_diverges_from_the_authorized_contract(tmp_path, field, value):
    aios, done = _done(tmp_path)
    _edit_effect(aios, done, **{field: value})
    with pytest.raises(TransitionError):
        load_receipt(aios, done["receipt_id"])


def test_receipt_is_refused_when_effect_record_identity_differs_from_its_path(tmp_path):
    aios, done = _done(tmp_path)
    _edit_effect(aios, done, effect_id="EF-" + "1" * 64)
    with pytest.raises(TransitionError):
        load_receipt(aios, done["receipt_id"])


def test_receipt_is_refused_when_effect_attempt_identity_is_not_derived(tmp_path):
    aios, done = _done(tmp_path)
    _edit_effect(aios, done, attempt=2)  # receipt also says attempt 1 -> mismatch either way
    with pytest.raises(TransitionError):
        load_receipt(aios, done["receipt_id"])


# ------------------------------------------------------------------ unsealed receipt: provider swap exploit

def _forge_outsider_receipt(aios, done):
    """Rewrite effect + unsealed receipt so both name OUTSIDER, signed with OUTSIDER's trusted key.

    Every check the pre-fix load_receipt() performed (content address, evidence binding, receipt<->effect
    field equality, outcome, provider attestation) is satisfied; only the contract capability is not.
    """
    epath, rpath = _paths(aios, done)
    eff = json.load(open(epath))
    rec = signed_receipt(OUTSIDER, eff["effect_id"], eff["attempt_id"], "op-x")
    po = runtime._provider_observation(rec)
    body = {k: v for k, v in unsealed_body(json.load(open(rpath))).items() if k not in ("receipt_id", "sealed")}
    body.update(provider=OUTSIDER, provider_operation_id="op-x", evidence=po["evidence"],
                attestation=po["attestation"])
    rid = receipt_id_for(body)
    os.remove(rpath)
    json.dump({**body, "receipt_id": rid, "sealed": False},
              open(os.path.join(aios, "receipts", rid + ".json"), "w"))
    eff.update(provider=OUTSIDER, provider_observation=po, receipt_id=rid)
    json.dump(eff, open(epath, "w"))
    return rid


def test_unsealed_receipt_for_outsider_provider_with_valid_key_is_refused(tmp_path):
    # A caller that opts out of the seal (require_sealed=False) reads an attacker-writable receipt file.
    aios, done = _done(tmp_path)
    assert trusted_keys(OUTSIDER)
    rid = _forge_outsider_receipt(aios, done)
    with pytest.raises(TransitionError, match="not an authorized contract capability"):
        load_receipt(aios, rid, require_sealed=False)
    with pytest.raises(TransitionError, match="not an authorized contract capability"):
        load_receipt(aios, rid, require_sealed=False, require_provider_signed=True)


def test_unsealed_receipt_effect_id_cannot_steer_the_effect_read(tmp_path):
    aios, done = _done(tmp_path)
    _, rpath = _paths(aios, done)
    epath, _ = _paths(aios, done)
    # Plant a copy of the genuine effect outside effects/ and point the receipt at it.
    os.makedirs(os.path.join(aios, "elsewhere"))
    with open(epath, encoding="utf-8") as src, \
            open(os.path.join(aios, "elsewhere", done["effect_id"] + ".json"), "w", encoding="utf-8") as dst:
        dst.write(src.read())
    body = {k: v for k, v in unsealed_body(json.load(open(rpath))).items() if k not in ("receipt_id", "sealed")}
    body["effect_id"] = os.path.join("..", "elsewhere", done["effect_id"])
    rid = receipt_id_for(body)
    json.dump({**body, "receipt_id": rid, "sealed": False},
              open(os.path.join(aios, "receipts", rid + ".json"), "w"))
    with pytest.raises(TransitionError, match="well-formed effect id"):
        load_receipt(aios, rid, require_sealed=False)


@pytest.mark.parametrize("bad", ["../effects/x", "RC-zz", "RC-" + "a" * 63, "rc-" + "a" * 64])
def test_malformed_receipt_id_is_refused_before_any_read(tmp_path, bad):
    with pytest.raises(ValueError, match="well-formed receipt id"):
        load_receipt(str(tmp_path), bad)


def test_evaluation_consumer_inherits_the_validated_receipt_load(tmp_path):
    from core.evaluation_plane import evaluate_persisted_receipt
    aios, done = _done(tmp_path)
    _edit_effect(aios, done, policy_digest="sha256:" + "0" * 64)
    with pytest.raises(TransitionError):
        evaluate_persisted_receipt(aios, done["receipt_id"], evaluator_version="e", rubric_version="r",
                                   verdict="PASS", result={"ok": True})
    assert not os.path.isdir(os.path.join(aios, "evaluations")) or not os.listdir(os.path.join(aios, "evaluations"))


@pytest.mark.parametrize("effect_id,attempt", [("../receipts/x", 1), ("EF-" + "a" * 64, 0),
                                               ("EF-" + "a" * 64, True), ("EF-" + "A" * 64, 1)])
def test_load_reconciliation_refuses_malformed_identity_before_any_read(tmp_path, effect_id, attempt):
    from core.effect_authority import load_reconciliation
    with pytest.raises(ValueError):
        load_reconciliation(str(tmp_path), effect_id, attempt)
