"""Deterministic, governance-neutral skill routing.

A skill can propose a workload route, but it cannot authorize execution,
change policy, redefine evidence requirements, or select terminal criteria.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Mapping


@dataclass(frozen=True)
class SkillSpec:
    skill_id: str
    description: str
    keywords: tuple[str, ...]
    capability_id: str


@dataclass(frozen=True)
class RoutePlan:
    skill_id: str | None
    capability_id: str | None
    matched_keywords: tuple[str, ...]
    dry_run: bool = True


def _normalise(value: str) -> str:
    return " ".join(value.lower().split())


def route(problem: str, skills: Iterable[SkillSpec], *, dry_run: bool = True) -> RoutePlan:
    """Return a deterministic proposal; never grants execution authority.

    Ties are resolved by the lexicographically smallest skill_id.
    """
    text = _normalise(problem)
    candidates: list[tuple[int, SkillSpec, tuple[str, ...]]] = []
    for skill in skills:
        matches = tuple(sorted({k for k in skill.keywords if _normalise(k) in text}))
        if matches:
            candidates.append((len(matches), skill, matches))
    if not candidates:
        return RoutePlan(None, None, (), dry_run=dry_run)
    _, selected, matches = min(
        candidates,
        key=lambda item: (-item[0], item[1].skill_id),
    )
    return RoutePlan(selected.skill_id, selected.capability_id, matches, dry_run=dry_run)


def plan_report(problem: str, plan: RoutePlan, *, evidence_required: bool = True) -> Mapping[str, object]:
    """Produce a non-authoritative plan artifact suitable for later governance."""
    return {
        "problem": problem,
        "route": plan.skill_id,
        "capability": plan.capability_id,
        "matched_keywords": list(plan.matched_keywords),
        "dry_run": plan.dry_run,
        "evidence_required": evidence_required,
        "authority_granted": False,
    }


DEFAULT_SKILLS: tuple[SkillSpec, ...] = (
    SkillSpec("authorized-artifact-auditor", "Authorized artifact analysis and defensive audit", ("artifact", "source recovery", "security audit", "dependency", "defensive remediation"), "software.audit"),
    SkillSpec("research", "Governed research and experiment evaluation", ("research", "experiment", "backtest", "strategy", "validation"), "try.research"),
    SkillSpec("android", "Android software/device workload", ("android", "phone", "accessibility", "gesture", "app"), "android.assistant"),
    SkillSpec("hardware", "Hardware engineering workload", ("hardware", "schematic", "circuit", "electrical", "measurement"), "rx50.engineering"),
)

__all__ = ["SkillSpec", "RoutePlan", "route", "plan_report", "DEFAULT_SKILLS"]
