"""Canonical execution->receipt adapter for the evaluation plane.

This is intentionally a thin composition over the existing authoritative
observation transition. It adds no authority and cannot dispatch effects.
"""
from __future__ import annotations

from typing import Any, Mapping

from .effect_authority import observe
from .evaluation import make_receipt


def observe_with_receipt(
    aios_dir: str,
    effect_id: str,
    actor: str,
    outcome: str,
    provider_observation: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Observe a dispatched attempt and durably bind its execution receipt."""
    observation = observe(aios_dir, effect_id, actor, outcome, dict(provider_observation))
    receipt = make_receipt(aios_dir, observation, provider_observation)
    return observation, receipt


__all__ = ["observe_with_receipt"]
