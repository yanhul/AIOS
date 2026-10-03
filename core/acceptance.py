"""AIOS declarative acceptance predicates (A2).

Predicates are deliberately small and closed-world: unknown operators,
malformed paths, and missing values fail closed. No arbitrary Python
expression is executed.
"""

from dataclasses import dataclass
from typing import Any, Mapping, Sequence


OPERATORS = ("eq", "ne", "in", "not_in", "exists")


@dataclass(frozen=True)
class AcceptancePredicate:
    predicate_id: str
    path: str
    operator: str
    expected: Any = None

    def __post_init__(self) -> None:
        if not isinstance(self.predicate_id, str) or not self.predicate_id.strip():
            raise ValueError("predicate_id must be a non-empty string")
        if not isinstance(self.path, str) or not self.path.strip():
            raise ValueError("path must be a non-empty string")
        if self.operator not in OPERATORS:
            raise ValueError("unsupported acceptance operator")
        if self.operator == "exists" and self.expected is not None:
            raise ValueError("exists predicate must not define expected")

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "AcceptancePredicate":
        if not isinstance(value, Mapping):
            raise ValueError("predicate must be a mapping")
        return cls(
            predicate_id=value.get("predicate_id"),
            path=value.get("path"),
            operator=value.get("operator"),
            expected=value.get("expected"),
        )

    def as_record(self) -> dict[str, Any]:
        record = {
            "predicate_id": self.predicate_id,
            "path": self.path,
            "operator": self.operator,
        }
        if self.operator != "exists":
            record["expected"] = self.expected
        return record


@dataclass(frozen=True)
class AcceptanceResult:
    predicate_id: str
    passed: bool
    observed: Any = None
    reason: str = ""


def _resolve(context: Any, path: str) -> tuple[bool, Any]:
    current = context
    for part in path.split("."):
        if not part:
            return False, None
        if isinstance(current, Mapping):
            if part not in current:
                return False, None
            current = current[part]
        elif isinstance(current, Sequence) and not isinstance(current, (str, bytes)):
            try:
                current = current[int(part)]
            except (ValueError, IndexError, TypeError):
                return False, None
        else:
            return False, None
    return True, current


def evaluate_predicate(predicate: AcceptancePredicate, context: Mapping[str, Any]) -> AcceptanceResult:
    if not isinstance(context, Mapping):
        raise ValueError("predicate context must be a mapping")
    exists, observed = _resolve(context, predicate.path)

    if predicate.operator == "exists":
        return AcceptanceResult(predicate.predicate_id, exists, observed,
                                "path exists" if exists else "path missing")

    if not exists:
        return AcceptanceResult(predicate.predicate_id, False, None,
                                "path missing; acceptance fails closed")

    if predicate.operator == "eq":
        passed = observed == predicate.expected
    elif predicate.operator == "ne":
        passed = observed != predicate.expected
    elif predicate.operator == "in":
        passed = isinstance(predicate.expected, (list, tuple, set, frozenset)) and observed in predicate.expected
    elif predicate.operator == "not_in":
        passed = isinstance(predicate.expected, (list, tuple, set, frozenset)) and observed not in predicate.expected
    else:
        raise ValueError("unsupported acceptance operator")

    return AcceptanceResult(
        predicate.predicate_id,
        passed,
        observed,
        "predicate satisfied" if passed else "predicate not satisfied",
    )


def evaluate_acceptance(
    predicates: Sequence[AcceptancePredicate],
    context: Mapping[str, Any],
) -> tuple[AcceptanceResult, ...]:
    if not isinstance(predicates, Sequence):
        raise ValueError("predicates must be a sequence")
    if not predicates:
        raise ValueError("acceptance requires at least one predicate")
    results = tuple(evaluate_predicate(p, context) for p in predicates)
    if len({r.predicate_id for r in results}) != len(results):
        raise ValueError("predicate_id values must be unique")
    return results


__all__ = [
    "OPERATORS",
    "AcceptancePredicate",
    "AcceptanceResult",
    "evaluate_predicate",
    "evaluate_acceptance",
]
