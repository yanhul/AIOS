"""Translate an AIOS workload contract into the external gateway effect contract.

The adapter is deliberately not an authority provider. It validates that an
already-authorized workload contract contains the capability/effect requested
by the caller and requires an AIOS-issued permit plus deployment-bound
attestation before crossing into the external gateway.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from collections.abc import Mapping
from pathlib import Path

from .attestation import verify_attestation
from .authority import authorize, load_attestation, load_contract, load_permit
from .contract import verify_permit
from .effect_authority import dispatch as dispatch_aios_effect

GATEWAY_PROTOCOL_VERSION = 4
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
    """Build a v4 gateway contract from the current persisted authority/effect state.

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
    """Restart-safe JSONL client for harness-gateway protocol v4.

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
            raise GatewayTransportError("effect contract protocol_version must be 4")
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
    """Cross the Gateway fence, then persist its exact attempt binding in AIOS.

    This function never executes the provider. Callers may execute only when
    the returned execute_allowed flag is true. A replayed Gateway attempt is
    fail-closed: it is not copied into a new executable AIOS dispatch.
    """
    required = ("effect_id", "state", "actor", "attempt")
    if any(effect.get(key) in (None, "") for key in required):
        raise GatewayTransportError("AIOS effect is missing dispatch identity/state")
    if effect.get("state") != "PLANNED" or effect.get("attempt") != 0:
        raise GatewayTransportError("AIOS effect must be PLANNED attempt=0 before Gateway dispatch")
    target_sha = _required_text(target_sha, "target_sha")
    provider = _required_text(provider, "provider")
    response = transport.begin_effect(ticket=ticket, target_sha=target_sha)
    if response.get("execute_allowed") is not True or response.get("replayed") is True:
        raise GatewayTransportError("Gateway attempt is replayed or not authorized for first execution")
    gateway_attempt_id = _required_text(response.get("attempt_id"), "Gateway attempt_id")
    fence = response.get("fence")
    if not isinstance(fence, int) or isinstance(fence, bool) or fence < 1:
        raise GatewayTransportError("Gateway returned an invalid attempt fence")
    effect_id = _required_text(effect.get("effect_id"), "effect.effect_id")
    aios_attempt_id = f"{effect_id}:attempt:1"
    persisted = dispatch_aios_effect(
        aios_dir, effect_id, actor, aios_attempt_id, provider,
        target_sha=target_sha, evidence_ref=evidence_ref,
        lineage_ref=lineage_ref, idempotency_key=idempotency_key,
        attempt_fence=fence, gateway_attempt_id=gateway_attempt_id,
    )
    return {
        "effect": persisted, "execute_allowed": True,
        "gateway_attempt_id": gateway_attempt_id,
        "aios_attempt_id": aios_attempt_id, "attempt_fence": fence,
    }