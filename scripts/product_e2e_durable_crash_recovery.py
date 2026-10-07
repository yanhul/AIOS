#!/usr/bin/env python3
"""Product E2E crash/recovery proof for exact DISPATCHED attempt identity."""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from core.authority import load_contract, persist_contract, persist_permit
from core.capabilities import Capability, CapabilityRegistry
from core.contract import contract_identity
from core.effect_authority import create_effect, dispatch
from core.policy_registry import persist_policy
from core.durable_runtime import RuntimeSubmission
from core.runtime import ProviderReceipt, resume_attempt


ACTOR = "agent:product-e2e"
PROVIDER = "crash-provider"


def contract_fixture():
    return {
        "contract_type": "EXECUTION_CONTRACT",
        "task_id": "product-e2e-crash-recovery",
        "scope": "product-e2e",
        "actor": ACTOR,
        "capabilities": [f"{PROVIDER}@1"],
        "input_digest": "product-e2e-crash-recovery-input",
        "allowed_effects": ["external_effect"],
        "evidence_required": ["provider_receipt"],
        "max_attempts": 1,
        "terminal_states": ["SUCCESS", "FAILURE"],
        "policy_digest": "",
    }


def child_main(root: Path, marker: Path) -> None:
    registry = CapabilityRegistry()
    registry.register(Capability(PROVIDER, "1", "product-e2e", "product-e2e", status="ACTIVE"))
    registry.persist(str(root), "product-e2e")
    policy = persist_policy(str(root), {
        "policy_type": "GOVERNING_POLICY",
        "name": "product-e2e-crash-recovery",
    })
    contract = contract_fixture()
    contract["policy_digest"] = policy
    cid = contract_identity(contract)
    persist_contract(str(root), contract)
    permit = persist_permit(str(root), contract, "root")
    pid = permit["permit_id"]

    effect = create_effect(str(root), cid, "crash-recovery-op", ACTOR, pid, "external_effect")
    attempt_id = f"{effect['effect_id']}:attempt:1"
    effect = dispatch(str(root), effect["effect_id"], ACTOR, attempt_id, PROVIDER)

    marker.write_text(json.dumps({
        "contract_id": cid,
        "permit_id": pid,
        "effect_id": effect["effect_id"],
        "attempt_id": attempt_id,
        "state_after_crash_boundary": effect["state"],
        "attempt_after_crash_boundary": effect["attempt"],
    }, sort_keys=True), encoding="utf-8")

    # Simulate an actual process death immediately after durable DISPATCHED.
    os._exit(42)


class RecordingRuntime:
    name = "product-e2e-runtime"

    def __init__(self):
        self.resumed = None

    def resume(self, *, effect, attempt_id):
        self.resumed = (effect["effect_id"], attempt_id)
        return RuntimeSubmission(effect["effect_id"], attempt_id, PROVIDER)

    def submit(self, **kwargs):
        raise AssertionError("resume proof must not submit a new attempt")

    def retry(self, **kwargs):
        raise AssertionError("resume proof must not retry")


class Provider:
    name = PROVIDER

    def execute(self, *, contract, effect, attempt_id):
        return ProviderReceipt(
            self.name,
            effect["effect_id"],
            attempt_id,
            "provider-op-after-restart",
            "OBSERVED_SUCCESS",
            {"status": "observed-after-restart", "restarted": True},
        )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--artifact", default="artifacts/conformance/durable-crash-recovery.json")
    args = ap.parse_args()

    with tempfile.TemporaryDirectory(prefix="aios-product-e2e-crash-") as td:
        root = Path(td)
        marker = root / "crash-marker.json"
        proc = subprocess.run(
            [sys.executable, __file__, "--child-root", str(root), "--marker", str(marker)],
            text=True,
            capture_output=True,
        )
        if proc.returncode != 42:
            raise RuntimeError(f"crash fixture did not die at the intended boundary: rc={proc.returncode}")

        proof = json.loads(marker.read_text(encoding="utf-8"))
        assert proof["state_after_crash_boundary"] == "DISPATCHED"
        assert proof["attempt_after_crash_boundary"] == 1

        effect_path = root / "effects" / f"{proof['effect_id']}.json"
        effect = json.loads(effect_path.read_text(encoding="utf-8"))
        assert effect["state"] == "DISPATCHED"
        assert effect["attempt_id"] == proof["attempt_id"]

        contract = load_contract(str(root), proof["contract_id"])
        runtime = RecordingRuntime()
        result = resume_attempt(
            str(root), contract, effect, ACTOR, Provider(), runtime
        )

        assert runtime.resumed == (proof["effect_id"], proof["attempt_id"])
        assert result["state"] == "OBSERVED_SUCCESS"
        assert result["attempt"] == 1
        assert result["attempt_id"] == proof["attempt_id"]

        artifact = {
            "status": "PASS",
            "scenario": "process-death-after-DISPATCHED",
            "effect_id": proof["effect_id"],
            "attempt_id": proof["attempt_id"],
            "crash_exit_code": proc.returncode,
            "durable_state_before_resume": "DISPATCHED",
            "resume_state": "OBSERVED_SUCCESS",
            "same_attempt_identity": True,
            "duplicate_retry": False,
            "evidence_refs": [
                f"effect://{proof['effect_id']}",
                f"attempt://{proof['attempt_id']}",
            ],
            "verification_refs": ["product-e2e://durable-crash-recovery"],
        }
        out = Path(args.artifact)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(artifact, indent=2, sort_keys=True), encoding="utf-8")
        print(json.dumps({"PRODUCT_E2E_DURABLE_CRASH_RECOVERY": artifact}, sort_keys=True))
        return 0


if __name__ == "__main__":
    if "--child-root" in sys.argv:
        p = argparse.ArgumentParser()
        p.add_argument("--child-root", required=True)
        p.add_argument("--marker", required=True)
        a = p.parse_args()
        child_main(Path(a.child_root), Path(a.marker))
        raise SystemExit("child unexpectedly returned")
    raise SystemExit(main())
