# AIOS-CONTRACT: Shared test fixture/helper for effect authority + provider attestation suites
# AIOS-REGRESSION: Fixtures must configure trust exactly as a deployment would (seal secret, provider keys)
# AIOS-OWNER: AIOS control-plane durable execution
# AIOS-COVERAGE-GAP: Helper module; behaviour is asserted by the suites that import it
# AIOS-BASELINE: 218070b (574 passed, 1 skipped)
"""Test helper: record a provider-evidenced NOT_APPLIED reconciliation.

Retrying an UNKNOWN effect requires AIOS to hold this record first; tests that
exercise the retry path must go through it explicitly rather than handing
``retry_dispatch`` a self-issued authorization dictionary.
"""
import json
import os

from core.effect_authority import reconcile_effect
from core.evidence import EvidenceRecord
from tests.provider_trust_helpers import sign_reconciliation


def provider_status_evidence(effect, claim="provider status query: operation not applied"):
    return EvidenceRecord(
        evidence_id="EV-reconcile-" + effect["attempt_id"].rsplit(":", 1)[-1],
        level="OBSERVED",
        source_ref=f"provider://{effect['provider']}/status/{effect['attempt_id']}",
        claim=claim,
        run_id=effect["attempt_id"],
        provider=effect["provider"],
    ).as_record()


def reconcile_not_applied(aios_dir, effect_id, actor):
    with open(os.path.join(str(aios_dir), "effects", effect_id + ".json"), encoding="utf-8") as fh:
        effect = json.load(fh)
    ev = provider_status_evidence(effect)
    return reconcile_effect(str(aios_dir), effect_id, actor, "NOT_APPLIED", ev,
                            attestation=sign_reconciliation(effect, "NOT_APPLIED", ev))
