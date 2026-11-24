"""Translate an AIOS workload contract into the external gateway effect contract.

The adapter is deliberately not an authority provider. It validates that an
already-authorized workload contract contains the capability/effect requested
by the caller and requires an AIOS-issued permit plus deployment-bound
attestation before crossing into the external gateway.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import subprocess
import sys
import time
from collections.abc import Mapping
from pathlib import Path

from .attestation import verify_attestation
from .authority import authorize, load_attestation, load_contract, load_permit
from .contract import verify_permit
from .effect_authority import (
    dispatch as dispatch_aios_effect, observe as observe_aios_effect,
    unknown as mark_aios_unknown, issue_retry_authorization,
    gateway_retry_dispatch as map_gateway_retry_dispatch,
)
from .authority_store import recover_authority_store, commit_authority_batch
from .mutation import canonical_json
from .try_operation_receipt import verify_try_operation_receipt
from .gateway_retry_permit import GatewayRetryPermitSigner

GATEWAY_PROTOCOL_VERSION = 5
REQUIRED_WORKLOAD_FIELDS = (
    "contract_type", "task_id", "scope", "actor", "capabilities",
    "input_digest", "allowed_effects", "evidence_required", "max_attempts",
    "terminal_states", "policy_digest",
)


def _required_text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be non-empty")
    return value.strip()


def _validate_workload_contract(contract: Mapping[str, object]) -> None:
    for field in REQUIRED_WORKLOAD_FIELDS:
        if field not in contract:
            raise ValueError(f"missing workload contract field: {field}")
    capabilities = contract["capabilities"]
    if not isinstance(capabilities, (list, tuple)) or not capabilities:
        raise ValueError("capabilities must be a non-empty sequence")
    for ref in capabilities:
        if not isinstance(ref, str) or "@" not in ref or ref.endswith("@"):
            raise ValueError("capabilities must contain versioned refs")
    allowed_effects = contract["allowed_effects"]
    if not isinstance(allowed_effects, (list, tuple, set, frozenset)):
        raise ValueError("allowed_effects must be a sequence")
    max_attempts = contract["max_attempts"]
    if not isinstance(max_attempts, int) or isinstance(max_attempts, bool) or max_attempts < 1:
        raise ValueError("max_attempts must be a positive integer")


def _load_persisted_effect(aios_dir: str, effect_id: str) -> dict[str, object]:
    # Resolve an interrupted authority-store batch before trusting the snapshot.
    recover_authority_store(aios_dir)
    path = os.path.join(aios_dir, "effects", effect_id + ".json")
    if not os.path.exists(path):
        raise KeyError(f"unknown effect: {effect_id}")
    with open(path, "r", encoding="utf-8") as fh:
        effect = json.load(fh)
    if not isinstance(effect, dict):
        raise ValueError("persisted effect record must be an object")
    if effect.get("effect_id") != effect_id:
        raise ValueError("persisted effect identity does not match requested effect")
    return effect


def build_gateway_effect_contract(
    workload_contract: Mapping[str, object],
    *,
    aios_dir: str,
    persisted_effect: Mapping[str, object],
    effect_id: str,
    action: str,
    capability_ref: str,
    authority_ref: str,
    authority_permit: Mapping[str, object],
    authority_attestation: Mapping[str, object],
    attestation_secret: str,
    evidence_ref: str,
    lineage_ref: str,
    idempotency_key: str,
) -> dict[str, object]:
    """Build a v5 gateway contract from the current persisted authority/effect state.

    Caller-supplied contract/permit/effect data is treated as an assertion,
    never as the source of truth. The adapter reloads the persisted effect,
    contract, permit and attestation and re-runs current authorization before
    crossing into the external gateway.
    """
    if not isinstance(persisted_effect, Mapping):
        raise ValueError("persisted_effect must be a mapping")
    _validate_workload_contract(workload_contract)
    effect_id = _required_text(effect_id, "effect_id")
    action = _required_text(action, "action")
    capability_ref = _required_text(capability_ref, "capability_ref")
    authority_ref = _required_text(authority_ref, "authority_ref")
    evidence_ref = _required_text(evidence_ref, "evidence_ref")
    lineage_ref = _required_text(lineage_ref, "lineage_ref")
    idempotency_key = _required_text(idempotency_key, "idempotency_key")

    current_effect = _load_persisted_effect(aios_dir, effect_id)
    supplied_effect = dict(persisted_effect)
    if supplied_effect != current_effect:
        raise ValueError("persisted effect assertion does not match authoritative effect")

    stored_effect_id = _required_text(current_effect.get("effect_id"), "persisted effect.effect_id")
    stored_contract_id = _required_text(current_effect.get("contract_id"), "persisted effect.contract_id")
    stored_permit_id = _required_text(current_effect.get("permit_id"), "persisted effect.permit_id")
    stored_actor = _required_text(current_effect.get("actor"), "persisted effect.actor")
    stored_action = _required_text(current_effect.get("effect_type"), "persisted effect.effect_type")
    if current_effect.get("state") != "PLANNED" or current_effect.get("attempt") != 0:
        raise ValueError("Gateway ticket creation requires a PLANNED effect with attempt=0")
    if effect_id != stored_effect_id:
        raise ValueError("effect_id does not match persisted effect")
    if action != stored_action:
        raise ValueError("action does not match persisted effect")
    if authority_ref != stored_permit_id:
        raise ValueError("authority_ref does not match persisted effect permit")

    authorize(aios_dir, stored_contract_id, stored_permit_id)
    current_contract = load_contract(aios_dir, stored_contract_id)
    current_permit = load_permit(aios_dir, stored_permit_id)
    current_attestation = load_attestation(aios_dir, stored_permit_id)
    verify_permit(current_contract, current_permit)
    verify_attestation(current_contract, current_permit, current_attestation, attestation_secret)

    if dict(current_contract) != dict(workload_contract):
        raise ValueError("workload contract does not match persisted authority contract")
    if not isinstance(authority_permit, Mapping) or dict(authority_permit) != dict(current_permit):
        raise ValueError("authority permit does not match current persisted permit")
    if not isinstance(authority_attestation, Mapping) or dict(authority_attestation) != dict(current_attestation):
        raise ValueError("authority attestation does not match current persisted attestation")
    if stored_actor != current_contract["actor"]:
        raise ValueError("persisted effect actor does not match current contract actor")
    if capability_ref not in current_contract["capabilities"]:
        raise ValueError("capability_ref is not granted by workload contract")
    if action not in current_contract["allowed_effects"]:
        raise ValueError("action is not allowed by workload contract")
    if current_effect.get("policy_digest") != current_contract["policy_digest"]:
        raise ValueError("persisted effect policy digest differs from current authority")

    return {
        "protocol_version": GATEWAY_PROTOCOL_VERSION,
        "effect_id": effect_id,
        "contract_id": stored_contract_id,
        "actor": stored_actor,
        "action": action,
        "capability_ref": capability_ref,
        "authority_ref": stored_permit_id,
        "evidence_ref": evidence_ref,
        "lineage_ref": lineage_ref,
        "idempotency_key": idempotency_key,
    }


class GatewayTransportError(RuntimeError):
    """Gateway transport or protocol failure; callers must not retry effects."""


class GatewayCLITransport:
    """Restart-safe JSONL client for harness-gateway protocol v5.

    Each command starts a fresh CLI process. Durable state and replay fencing
    therefore live in Gateway, not in this adapter process. This client never
    invokes a provider or interprets a missing response as success.
    """

    def __init__(self, *, cli_path: str | Path, state_path: str | Path,
                 human_identity: str, governance: Mapping[str, str],
                 python: str = sys.executable) -> None:
        self.cli_path = str(cli_path)
        self.state_path = str(state_path)
        self.human_identity = _required_text(human_identity, "human_identity")
        self.governance = dict(governance)
        required = ("policy", "evidence_criteria", "promotion_criteria",
                    "terminal_conditions", "trust_roots")
        missing = [key for key in required if not self.governance.get(key)]
        if missing:
            raise ValueError("missing protected governance: " + ",".join(missing))
        self.python = python

    def request(self, command: str, **fields: object) -> dict[str, object]:
        payload = {"command": command, **fields}
        try:
            completed = subprocess.run(
                [self.python, self.cli_path, "--state", self.state_path,
                 "--human-identity", self.human_identity,
                 "--governance", json.dumps(self.governance, sort_keys=True)],
                input=json.dumps(payload, sort_keys=True) + "\n",
                text=True, capture_output=True, check=False, timeout=30,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise GatewayTransportError(f"Gateway transport unavailable: {exc}") from exc
        if completed.returncode != 0:
            raise GatewayTransportError(
                f"Gateway CLI exited {completed.returncode}: {completed.stderr.strip()}"
            )
        lines = [line for line in completed.stdout.splitlines() if line.strip()]
        if len(lines) != 1:
            raise GatewayTransportError("Gateway CLI returned an invalid response count")
        try:
            response = json.loads(lines[0])
        except ValueError as exc:
            raise GatewayTransportError("Gateway CLI returned invalid JSON") from exc
        if not isinstance(response, dict) or response.get("ok") is not True:
            reason = response.get("error", "Gateway rejected request") if isinstance(response, dict) else "invalid response"
            raise GatewayTransportError(str(reason))
        return response

    def create_ticket(self, *, ticket: str, repository: str, target_sha: str,
                      nonce: str, ttl_seconds: int, effect_contract: Mapping[str, object]) -> dict[str, object]:
        if effect_contract.get("protocol_version") != GATEWAY_PROTOCOL_VERSION:
            raise GatewayTransportError("effect contract protocol_version must be 5")
        return self.request("CREATE", ticket=ticket, repository=repository,
                            target_sha=target_sha, nonce=nonce, ttl_seconds=ttl_seconds,
                            effect_contract=dict(effect_contract))["ticket"]

    def authorize(self, *, ticket: str, nonce: str, sender: str, target_sha: str) -> dict[str, object]:
        return self.request("SUA", ticket=ticket, nonce=nonce, sender=sender,
                            target_sha=target_sha)["ticket"]

    def begin_effect(self, *, ticket: str, target_sha: str) -> dict[str, object]:
        effect = self.request("BEGIN_EFFECT", ticket=ticket, target_sha=target_sha)["effect"]
        if effect.get("execute_allowed") not in (True, False):
            raise GatewayTransportError("Gateway attempt response lacks execute_allowed fence")
        if effect.get("replayed") is True and effect.get("execute_allowed") is not False:
            raise GatewayTransportError("replayed Gateway attempt cannot be executable")
        return effect

    def retry_effect(self, *, ticket: str, retry_permit: Mapping[str, object]) -> dict[str, object]:
        effect = self.request("RETRY_EFFECT", ticket=ticket, retry_permit=dict(retry_permit))["effect"]
        if effect.get("execute_allowed") not in (True, False) or effect.get("replayed") not in (True, False):
            raise GatewayTransportError("Gateway retry response lacks execution/replay fence")
        if effect.get("replayed") is True and effect.get("execute_allowed") is not False:
            raise GatewayTransportError("replayed Gateway retry attempt cannot be executable")
        return effect

    def record_receipt(self, *, ticket: str, receipt: Mapping[str, object]) -> dict[str, object]:
        if receipt.get("status") not in {"UNKNOWN", "OBSERVED", "FAILED", "COMPLETED"}:
            raise GatewayTransportError("receipt status is invalid")
        return self.request("RECEIPT", ticket=ticket, receipt=dict(receipt))["ticket"]

    def status(self) -> dict[str, object]:
        return self.request("STATUS")["status"]


def begin_and_dispatch_aios_effect(
    transport: GatewayCLITransport, *, ticket: str, target_sha: str,
    aios_dir: str, effect: Mapping[str, object], actor: str, provider: str,
    evidence_ref: str, lineage_ref: str, idempotency_key: str,
) -> dict[str, object]:
    """Cross the Gateway fence and durably map its attempt into AIOS.

    The Gateway allocates the attempt first. If the process dies before AIOS
    persists that mapping, a repeated BEGIN_EFFECT is non-executable; this
    adapter records the recovered attempt as UNKNOWN instead of dropping the
    identity or replaying provider execution.
    """
    required = ("effect_id", "state", "actor", "attempt")
    if any(effect.get(key) in (None, "") for key in required):
        raise GatewayTransportError("AIOS effect is missing dispatch identity/state")
    if effect.get("state") != "PLANNED" or effect.get("attempt") != 0:
        raise GatewayTransportError("AIOS effect snapshot must be PLANNED attempt=0 before Gateway dispatch")
    target_sha = _required_text(target_sha, "target_sha")
    provider = _required_text(provider, "provider")
    evidence_ref = _required_text(evidence_ref, "evidence_ref")
    lineage_ref = _required_text(lineage_ref, "lineage_ref")
    idempotency_key = _required_text(idempotency_key, "idempotency_key")
    effect_id = _required_text(effect.get("effect_id"), "effect.effect_id")

    response = transport.begin_effect(ticket=ticket, target_sha=target_sha)
    gateway_attempt_id = _required_text(response.get("attempt_id"), "Gateway attempt_id")
    fence = response.get("fence")
    if not isinstance(fence, int) or isinstance(fence, bool) or fence < 1:
        raise GatewayTransportError("Gateway returned an invalid attempt fence")
    if response.get("effect_id") != effect_id:
        raise GatewayTransportError("Gateway effect_id does not match AIOS effect")
    if response.get("idempotency_key") != idempotency_key:
        raise GatewayTransportError("Gateway idempotency_key does not match AIOS effect")
    if response.get("target_sha") != target_sha:
        raise GatewayTransportError("Gateway target_sha does not match requested worker revision")
    if response.get("ticket_id") != ticket:
        raise GatewayTransportError("Gateway ticket identity mismatch")
    if response.get("attempt_number") != 1:
        raise GatewayTransportError("Gateway returned an unsupported attempt number")
    replayed = response.get("replayed") is True
    execute_allowed = response.get("execute_allowed") is True
    if response.get("replayed") not in (True, False) or response.get("execute_allowed") not in (True, False):
        raise GatewayTransportError("Gateway attempt response lacks boolean replay/execution fence")
    if replayed and execute_allowed:
        raise GatewayTransportError("replayed Gateway attempt cannot be executable")
    if not replayed and not execute_allowed:
        raise GatewayTransportError("Gateway did not authorize a new effect attempt")

    binding = {
        "gateway_attempt_id": gateway_attempt_id, "attempt_fence": fence,
        "target_sha": target_sha, "evidence_ref": evidence_ref,
        "lineage_ref": lineage_ref, "idempotency_key": idempotency_key,
    }
    current = _load_persisted_effect(aios_dir, effect_id)
    if current.get("actor") != actor or current.get("actor") != effect.get("actor"):
        raise GatewayTransportError("AIOS effect actor does not match dispatch actor")

    mapped_now = False
    if current.get("state") == "PLANNED" and current.get("attempt") == 0:
        aios_attempt_id = f"{effect_id}:attempt:1"
        try:
            current = dispatch_aios_effect(
                aios_dir, effect_id, actor, aios_attempt_id, provider, **binding,
            )
            mapped_now = True
        except Exception:
            # A concurrent caller may have committed the same mapping. Reload
            # and accept only an exact match; never overwrite a different attempt.
            current = _load_persisted_effect(aios_dir, effect_id)
    else:
        aios_attempt_id = current.get("attempt_id")

    for key, value in binding.items():
        if current.get(key) != value:
            raise GatewayTransportError(f"persisted AIOS {key} differs from Gateway attempt")
    if current.get("attempt_id") != f"{effect_id}:attempt:1":
        raise GatewayTransportError("persisted AIOS attempt identity does not match Gateway attempt")

    if replayed or not mapped_now:
        if current.get("state") == "DISPATCHED":
            current = mark_aios_unknown(
                aios_dir, effect_id, actor,
                "Gateway returned a replayed/non-executable attempt; original execution outcome requires reconciliation",
            )
        if current.get("state") not in {"UNKNOWN", "OBSERVED_SUCCESS", "OBSERVED_FAILURE"}:
            raise GatewayTransportError("replayed Gateway attempt could not be reconciled safely")
        return {
            "effect": current, "execute_allowed": False,
            "gateway_attempt_id": gateway_attempt_id,
            "aios_attempt_id": aios_attempt_id, "attempt_fence": fence,
            "reconciliation": "REPLAYED_ATTEMPT_RECORDED_UNKNOWN" if current.get("state") == "UNKNOWN" else "ALREADY_RECONCILED",
        }

    return {
        "effect": current, "execute_allowed": True,
        "gateway_attempt_id": gateway_attempt_id,
        "aios_attempt_id": aios_attempt_id, "attempt_fence": fence,
    }


def _gateway_ticket_snapshot(transport: GatewayCLITransport, ticket: str) -> dict[str, object]:
    status = transport.status()
    tickets = status.get("tickets") if isinstance(status, Mapping) else None
    raw = tickets.get(ticket) if isinstance(tickets, Mapping) else None
    if not isinstance(raw, dict):
        raise GatewayTransportError("Gateway ticket is missing from durable status")
    return raw


def prepare_gateway_retry_permit(
    transport: GatewayCLITransport, *, ticket: str, aios_dir: str, effect_id: str, actor: str,
    operation_receipt: Mapping[str, object], issuer: str, reason: str, issuer_secret: str,
    retry_keyring, signer: GatewayRetryPermitSigner, operation_keyring=None, now: float | None = None,
) -> dict[str, object]:
    """Reconcile a signed TRY operation receipt and issue one Gateway RetryPermit.

    This function accepts only a trusted TRY FAILED/NOT_SUBMITTED receipt bound
    to the current AIOS attempt. UNKNOWN, COMPLETED and ambiguous failures cannot
    produce a permit, even when a human issuer asks for one.
    """
    current = _load_persisted_effect(aios_dir, effect_id)
    if current.get("actor") != actor or current.get("state") != "UNKNOWN":
        raise GatewayTransportError("Gateway retry permit requires the actor's UNKNOWN effect")
    if current.get("provider") != "try.repair":
        raise GatewayTransportError("TRY operation receipt cannot authorize a different provider")
    binding = current.get("try_operation_binding")
    if not isinstance(binding, Mapping):
        raise GatewayTransportError("current AIOS attempt has no pre-submission TRY request binding")
    try:
        verified = verify_try_operation_receipt(
            operation_receipt,
            request_id=binding["request_id"], request_digest=binding["request_digest"],
            repository=binding["repository"], sha=binding["sha"], attempt=binding["attempt"],
            keyring=operation_keyring,
        )
    except Exception as exc:
        raise GatewayTransportError(f"TRY operation receipt verification failed: {exc}") from exc
    if not verified["proven_not_submitted"]:
        raise GatewayTransportError("TRY receipt does not prove Gemini was never submitted; UNKNOWN remains blocked")

    ticket_state = _gateway_ticket_snapshot(transport, ticket)
    contract = ticket_state.get("effect_contract")
    if not isinstance(contract, Mapping):
        raise GatewayTransportError("Gateway ticket lacks the immutable AIOS effect contract")
    expected_contract = {
        "effect_id": effect_id, "contract_id": current.get("contract_id"),
        "actor": actor, "authority_ref": current.get("permit_id"),
        "action": current.get("effect_type"),
        "target_sha": current.get("target_sha"), "evidence_ref": current.get("evidence_ref"),
        "lineage_ref": current.get("lineage_ref"), "idempotency_key": current.get("idempotency_key"),
    }
    for key, value in expected_contract.items():
        if (contract.get("effect_id") if key == "effect_id" else
            contract.get("contract_id") if key == "contract_id" else
            contract.get("actor") if key == "actor" else
            contract.get("authority_ref") if key == "authority_ref" else
            ticket_state.get("target_sha") if key == "target_sha" else contract.get(key)) != value:
            raise GatewayTransportError(f"Gateway ticket {key} binding mismatch")
    if ticket_state.get("repository") != binding.get("repository"):
        raise GatewayTransportError("Gateway ticket repository differs from the TRY operation request")
    capability_ref = contract.get("capability_ref")
    if not isinstance(capability_ref, str) or capability_ref.split("@", 1)[0] != current.get("provider"):
        raise GatewayTransportError("Gateway ticket capability does not bind the dispatched TRY provider")
    if ticket_state.get("state") not in {"AUTHORIZED", "FAILED"}:
        raise GatewayTransportError("Gateway ticket is not eligible for a governed retry")
    attempts = ticket_state.get("attempt_history", [])
    receipts = ticket_state.get("receipt_history", [])
    prior_attempt = next((item for item in reversed(attempts)
                          if item.get("attempt_id") == current.get("gateway_attempt_id")), None)
    prior_receipt = next((item for item in reversed(receipts)
                          if item.get("receipt", {}).get("attempt_id") == current.get("gateway_attempt_id")), None)
    if prior_attempt is None or prior_receipt is None:
        raise GatewayTransportError("Gateway prior attempt/receipt history is incomplete")
    prior_receipt_body = prior_receipt.get("receipt")
    if (prior_attempt.get("fence") != current.get("attempt_fence")
            or prior_attempt.get("attempt_number") != current.get("attempt")
            or prior_attempt.get("status") not in {"UNKNOWN", "FAILED"}
            or not isinstance(prior_receipt_body, Mapping)
            or prior_receipt_body.get("status") not in {"UNKNOWN", "FAILED"}
            or prior_receipt_body.get("ticket_id") != ticket
            or prior_receipt_body.get("attempt_id") != current.get("gateway_attempt_id")
            or prior_receipt_body.get("attempt_fence") != current.get("attempt_fence")
            or prior_receipt_body.get("target_sha") != current.get("target_sha")
            or prior_receipt_body.get("effect_id") != effect_id
            or prior_receipt_body.get("evidence_ref") != current.get("evidence_ref")
            or prior_receipt_body.get("lineage_ref") != current.get("lineage_ref")):
        raise GatewayTransportError("Gateway prior attempt/receipt is not bound to the current unresolved effect")
    prior_receipt_digest = prior_receipt.get("digest")
    computed_prior_receipt_digest = hashlib.sha256(canonical_json(dict(prior_receipt_body)).encode("utf-8")).hexdigest()
    if not isinstance(prior_receipt_digest, str) or prior_receipt_digest != computed_prior_receipt_digest:
        raise GatewayTransportError("Gateway prior receipt digest is invalid or does not match its body")

    next_attempt = int(current.get("attempt", 0)) + 1
    retry_auth = issue_retry_authorization(
        aios_dir, effect_id, actor, next_attempt, issuer, reason,
        issuer_secret=issuer_secret, keyring=retry_keyring, now=now,
    )
    evidence = {
        "type": "AIOS_TRY_NON_SUBMISSION_RECONCILIATION_V1",
        "effect_id": effect_id, "contract_id": current["contract_id"],
        "authority_permit_id": current["permit_id"], "actor": actor,
        "aios_attempt_id": current["attempt_id"],
        "gateway_ticket_id": ticket, "gateway_attempt_id": current["gateway_attempt_id"],
        "gateway_fence": current["attempt_fence"],
        "gateway_receipt_digest": prior_receipt_digest,
        "try_receipt_id": verified["receipt"]["receipt_id"],
        "try_operation_receipt_digest": verified["receipt_digest"],
        "try_request_id": binding["request_id"], "try_request_digest": binding["request_digest"],
        "execution_state": "NOT_SUBMITTED", "reconciliation_outcome": "PROVEN_NOT_SUBMITTED",
        "issuer": issuer, "retry_authorization_id": retry_auth["authorization_id"],
        "reason": reason, "reconciled_at": float(time.time() if now is None else now),
    }
    evidence_digest = hashlib.sha256(canonical_json(evidence).encode("utf-8")).hexdigest()
    issued_at = float(time.time() if now is None else now)
    fields = {
        "effect_id": effect_id, "contract_id": current["contract_id"],
        "authority_ref": current["permit_id"], "actor": actor,
        "issuer": issuer, "retry_authorization_id": retry_auth["authorization_id"],
        "ticket_id": ticket, "target_sha": current["target_sha"],
        "prior_gateway_attempt_id": current["gateway_attempt_id"],
        "prior_fence": current["attempt_fence"],
        "prior_gateway_receipt_digest": prior_receipt_digest,
        "operation_receipt_digest": verified["receipt_digest"],
        "reconciliation_evidence_digest": evidence_digest,
        "reconciliation_outcome": "PROVEN_NOT_SUBMITTED",
        "decision_id": retry_auth["authorization_id"],
        "next_attempt_number": next_attempt,
        "next_attempt_id": f"{ticket}:{next_attempt}",
        "next_fence": int(current["attempt_fence"]) + 1,
        "nonce": secrets.token_hex(16), "issued_at": issued_at, "expires_at": issued_at + 300,
    }
    permit = signer.sign(fields)
    permit_id = permit["permit_id"]
    permit_rel = os.path.join("gateway_retry_permits", permit_id + ".json")
    evidence_rel = os.path.join("gateway_retry_permits", permit_id + ".evidence.json")
    event_rel = os.path.join("events", "gateway-retry-permit-" + permit_id + ".json")
    expected_effect = canonical_json(current)
    def precondition(root):
        with open(os.path.join(root, "effects", effect_id + ".json"), "r", encoding="utf-8") as fh:
            actual = canonical_json(json.load(fh))
        if actual != expected_effect:
            raise GatewayTransportError("AIOS effect changed while retry permit was being issued")
        if os.path.lexists(os.path.join(root, permit_rel)):
            raise GatewayTransportError("Gateway retry permit ID collision")
    event = {"kind": "external_effect", "action": "gateway_retry_permit_issued",
             "effect_id": effect_id, "permit_id": permit_id,
             "operation_receipt_digest": verified["receipt_digest"],
             "reconciliation_evidence_digest": evidence_digest,
             "retry_authorization_id": retry_auth["authorization_id"], "issuer": issuer}
    commit_authority_batch(aios_dir, [(permit_rel, permit), (evidence_rel, evidence), (event_rel, event)],
                           precondition=precondition)
    return permit


def retry_gateway_effect(
    transport: GatewayCLITransport, *, ticket: str, aios_dir: str, effect_id: str, actor: str,
    provider: str, retry_permit: Mapping[str, object], signer: GatewayRetryPermitSigner,
    retry_keyring=None, now: float | None = None,
) -> dict[str, object]:
    """Consume the AIOS permit at Gateway, then persist the same new attempt in AIOS."""
    current = _load_persisted_effect(aios_dir, effect_id)
    if current.get("state") != "UNKNOWN" or current.get("actor") != actor:
        raise GatewayTransportError("Gateway retry requires the actor's current UNKNOWN effect")
    permit_id = retry_permit.get("permit_id") if isinstance(retry_permit, Mapping) else None
    if not isinstance(permit_id, str):
        raise GatewayTransportError("Gateway retry permit ID is missing")
    permit_path = os.path.join(aios_dir, "gateway_retry_permits", permit_id + ".json")
    try:
        with open(permit_path, "r", encoding="utf-8") as fh:
            persisted = json.load(fh)
    except (OSError, ValueError) as exc:
        raise GatewayTransportError("Gateway retry permit is not persisted in AIOS") from exc
    if canonical_json(persisted) != canonical_json(dict(retry_permit)) or not signer.verify(persisted):
        raise GatewayTransportError("Gateway retry permit is not the exact signed AIOS record")
    response = transport.retry_effect(ticket=ticket, retry_permit=persisted)
    if response.get("effect_id") != effect_id or response.get("ticket_id") != ticket:
        raise GatewayTransportError("Gateway retry response effect/ticket mismatch")
    if response.get("retry_permit_id") != permit_id:
        raise GatewayTransportError("Gateway retry response permit mismatch")
    if response.get("replayed") is True or response.get("execute_allowed") is not True:
        # Crash gap: Gateway consumed/allocated the attempt but replay is never
        # executable. Do not map it as DISPATCHED or call the provider.
        raise GatewayTransportError("Gateway retry was replayed/non-executable; execution remains blocked for reconciliation")
    try:
        updated = map_gateway_retry_dispatch(
            aios_dir, effect_id, actor, provider, response, persisted,
            signer=signer, retry_keyring=retry_keyring, now=now,
        )
    except Exception as exc:
        raise GatewayTransportError(f"Gateway retry attempt could not be durably mapped in AIOS: {exc}") from exc
    return {"effect": updated, "execute_allowed": True,
            "gateway_attempt_id": response["attempt_id"], "aios_attempt_id": updated["attempt_id"],
            "attempt_fence": response["fence"], "retry_permit_id": permit_id}


def record_gateway_receipt(
    transport: GatewayCLITransport, *, ticket: str, aios_dir: str,
    effect_id: str, actor: str, receipt: Mapping[str, object],
    provider_observation: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Persist a Gateway receipt first, then reconcile only evidence-backed AIOS state.

    UNKNOWN is reflected into AIOS as UNKNOWN. OBSERVED remains non-terminal.
    COMPLETED/FAILED without a verifiable AIOS observation remain DISPATCHED or
    UNKNOWN and are explicitly reported as pending reconciliation.
    """
    current = _load_persisted_effect(aios_dir, effect_id)
    if current.get("actor") != actor:
        raise GatewayTransportError("receipt actor does not own the AIOS effect")
    if current.get("state") not in {"DISPATCHED", "UNKNOWN"}:
        raise GatewayTransportError("Gateway receipt requires a dispatched or unresolved AIOS effect")
    required = ("ticket_id", "attempt_id", "attempt_fence", "target_sha",
                "effect_id", "status", "evidence_ref", "lineage_ref")
    if any(receipt.get(key) in (None, "") for key in required):
        raise GatewayTransportError("Gateway receipt is missing required binding fields")
    expected = {
        "ticket_id": ticket, "attempt_id": current.get("gateway_attempt_id"),
        "attempt_fence": current.get("attempt_fence"),
        "target_sha": current.get("target_sha"), "effect_id": effect_id,
        "evidence_ref": current.get("evidence_ref"),
        "lineage_ref": current.get("lineage_ref"),
    }
    for key, value in expected.items():
        if receipt.get(key) != value:
            raise GatewayTransportError(f"Gateway receipt {key} binding mismatch")
    status = receipt.get("status")
    if status not in {"UNKNOWN", "OBSERVED", "FAILED", "COMPLETED"}:
        raise GatewayTransportError("Gateway receipt status is invalid")

    # Gateway is the durable receipt ledger. Do not mutate AIOS until this write succeeds.
    ticket_state = transport.record_receipt(ticket=ticket, receipt=receipt)
    if status == "UNKNOWN":
        if current["state"] == "DISPATCHED":
            updated = mark_aios_unknown(aios_dir, effect_id, actor, "Gateway recorded UNKNOWN receipt")
            return {"ticket": ticket_state, "aios_effect": updated, "reconciliation": "UNKNOWN_RECORDED"}
        return {"ticket": ticket_state, "aios_effect": current, "reconciliation": "ALREADY_UNKNOWN"}

    if status == "OBSERVED":
        return {"ticket": ticket_state, "aios_effect": current, "reconciliation": "WAITING_FOR_TERMINAL_RECEIPT"}

    if provider_observation is None:
        return {"ticket": ticket_state, "aios_effect": current, "reconciliation": "PENDING_AIOS_EVIDENCE"}
    if not isinstance(provider_observation, Mapping):
        raise GatewayTransportError("provider_observation must be a mapping")
    for key in ("gateway_attempt_id", "attempt_id", "provider"):
        expected_value = current.get("gateway_attempt_id") if key == "gateway_attempt_id" else current.get(key)
        if provider_observation.get(key) != expected_value:
            raise GatewayTransportError(f"provider observation {key} binding mismatch")
    _required_text(provider_observation.get("provider_operation_id"), "provider_operation_id")
    if not isinstance(provider_observation.get("observation"), Mapping) or not provider_observation.get("observation"):
        raise GatewayTransportError("provider observation must include non-empty raw observation")
    normalized_observation = {
        "provider": provider_observation["provider"],
        "provider_operation_id": provider_observation["provider_operation_id"],
        "effect_id": effect_id,
        "attempt_id": current["attempt_id"],
        "gateway_attempt_id": current["gateway_attempt_id"],
        "observation": dict(provider_observation["observation"]),
    }
    if provider_observation.get("authentication") is not None:
        normalized_observation["authentication"] = provider_observation["authentication"]
    outcome = "OBSERVED_SUCCESS" if status == "COMPLETED" else "OBSERVED_FAILURE"
    updated = observe_aios_effect(aios_dir, effect_id, actor, outcome, normalized_observation)
    return {"ticket": ticket_state, "aios_effect": updated, "reconciliation": "RECONCILED"}