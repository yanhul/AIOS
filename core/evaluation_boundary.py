"""Canonical execution->receipt adapter for the evaluation plane.

Receipt creation is owned by the authoritative observation transition. This
adapter only returns the receipt that observation already committed.
"""
from __future__ import annotations

from typing import Any, Mapping

from .effect_authority import observe
from .evaluation import receipt_path


def observe_with_receipt(
    aios_dir: str,
    effect_id: str,
    actor: str,
    outcome: str,
    provider_observation: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    observation = observe(aios_dir, effect_id, actor, outcome, dict(provider_observation))
    with open(receipt_path(aios_dir, observation["receipt_id"]), "r", encoding="utf-8") as fh:
        import json
        receipt = json.load(fh)
    return observation, receipt


__all__ = ["observe_with_receipt"]
