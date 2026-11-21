"""Read-only export of a validated UNKNOWN effect for an external state attestor.

This module does not sign, publish, or authorize a retry. The caller must send
its output through a separately controlled state-export channel; an agent-writable
copy is not a trust anchor.
"""
from __future__ import annotations
import json, os
from .effect_authority import _load, _path, _validate_persisted_effect
from .mutation import TransitionError

def export_unknown_effect_snapshot(aios_dir: str, effect_id: str, actor: str) -> dict:
    if not isinstance(effect_id, str) or not effect_id.strip() or not isinstance(actor, str) or not actor.strip():
        raise ValueError("effect_id and actor are required")
    staging = os.path.join(aios_dir, ".staging")
    if os.path.isdir(staging) and os.listdir(staging):
        raise TransitionError("effect state has pending journal work; read-only exporter will not recover or attest it")
    path = _path(aios_dir, effect_id)
    if os.path.islink(path) or not os.path.isfile(path):
        raise TransitionError("effect snapshot is missing or symlinked")
    try:
        effect = _load(path)
    except (OSError, ValueError) as exc:
        raise TransitionError(f"effect snapshot is unreadable: {exc}") from exc
    if not isinstance(effect, dict) or effect.get("effect_id") != effect_id:
        raise TransitionError("effect snapshot identity mismatch")
    _validate_persisted_effect(aios_dir, effect)
    if effect.get("actor") != actor:
        raise TransitionError("effect snapshot actor mismatch")
    if effect.get("state") != "UNKNOWN":
        raise TransitionError("only UNKNOWN effects can be exported for retry attestation")
    if not isinstance(effect.get("provider"), str) or not effect["provider"].strip():
        raise TransitionError("UNKNOWN effect has no bound provider")
    return dict(effect)
