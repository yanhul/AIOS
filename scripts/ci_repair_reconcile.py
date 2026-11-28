#!/usr/bin/env python3
"""Reconcile apply, authority, receipt and separate trusted-test artifacts."""
from __future__ import annotations

import json
import os
from pathlib import Path

from core.effect_authority import ProviderKeyring
from core.repair_reconcile import reconcile_repair


def main() -> int:
    run_id = int(os.environ["AIOS_REPAIR_RUN_ID"])
    base = os.environ["AIOS_REPAIR_SHA"]
    repository = os.environ["GITHUB_REPOSITORY"]
    apply_result = json.loads(Path("repair-apply-result.json").read_text(encoding="utf-8"))
    test = json.loads(Path("repair-test-result.json").read_text(encoding="utf-8"))
    proposals = [json.loads(Path(x).read_text(encoding="utf-8"))
                 for x in os.environ["AIOS_REPAIR_PROPOSALS"].split(",") if x]
    if apply_result.get("schema") != 1 or apply_result.get("status") != "PATCH_APPLIED_RECEIPTS_ACCEPTED":
        raise SystemExit("missing AIOS-accepted patch result")
    if (apply_result.get("run_id") != run_id or apply_result.get("base_sha") != base
            or apply_result.get("repository") != repository):
        raise SystemExit("apply result repository/run/base binding mismatch")
    if (test.get("run_id") != run_id or test.get("repository") != repository
            or test.get("base_sha") != base):
        raise SystemExit("trusted test repository/run/base binding mismatch")

    result = {
        "schema": 3, "run_id": run_id, "repository": repository, "base_sha": base,
        "contract_id": apply_result["contract_id"], "permit_id": apply_result["permit_id"],
        "attempts": apply_result["attempts"], "effects": apply_result["effects"],
        "applied": apply_result["applied"], "test": test, "reconciliation": None,
    }
    if test.get("status") == "UNKNOWN":
        result["status"] = "REPAIR_ATTEMPT_TEST_UNKNOWN"
        Path("repair-result.json").write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
        print(json.dumps({"status": result["status"], "trusted_tests": "UNKNOWN"}))
        status = "UNKNOWN"
    elif test.get("status") != "PASS":
        result["status"] = "REPAIR_ATTEMPT_TEST_FAIL"
        Path("repair-result.json").write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
        print(json.dumps({"status": result["status"], "trusted_tests": test.get("status")}))
        status = "FAIL"
    else:
        provider_keyring = ProviderKeyring.from_env()
        if provider_keyring is None:
            raise SystemExit("trusted AIOS_PROVIDER_KEYRING is required for reconciliation")
        result["reconciliation"] = reconcile_repair(
            os.environ["AIOS_REPAIR_AUTHORITY_DIR"], contract_id=result["contract_id"],
            permit_id=result["permit_id"], actor="ci-repair-worker", repository=repository,
            run_id=run_id, base_sha=base, effects=result["effects"], proposals=proposals, test=test,
            provider_keyring=provider_keyring,
        )
        result["status"] = "REPAIR_E2E_PASS"
        Path("repair-result.json").write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
        print(json.dumps({"status": result["status"], "trusted_tests": "PASS",
                          "reconciliation": result["reconciliation"]["status"]}))
        status = "PASS"
    output = os.environ.get("GITHUB_OUTPUT")
    if output:
        with open(output, "a", encoding="utf-8") as fh:
            fh.write(f"status={status}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
