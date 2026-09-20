"""Repository mutation adapter bound to the AIOS effect/runtime boundary.

This is deliberately separate from the coding-agent planner. The planner may
describe a patch; this adapter is the provider that performs an already
authorized repository mutation through core.runtime.execute().
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence

from .effect_authority import create_effect
from .evidence import EvidenceRecord
from .runtime import ProviderReceipt, execute


@dataclass(frozen=True)
class RepositoryPatch:
    files: tuple[ProposedFile, ...]


class RepositoryPatchAdapter:
    """Trusted provider for repository patch effects.

    It does not authorize itself. The caller must supply a persisted AIOS
    contract + permit whose capability names this provider and whose allowed
    effects contain external_effect.
    """

    name = "repo_patch"

    def __init__(self, repository_root: str | Path):
        self.root = Path(repository_root).resolve()
        self._plans: dict[str, tuple[ProposedFile, ...]] = {}

    def register(self, effect_id: str, files: Sequence[ProposedFile]) -> None:
        if not effect_id or effect_id in self._plans:
            raise ValueError("effect plan must have a unique non-empty effect_id")
        proposed = tuple(files)
        if not proposed:
            raise ValueError("effect plan contains no files")
        self._plans[effect_id] = proposed

    def execute(self, *, contract: dict, effect: dict, attempt_id: str) -> ProviderReceipt:
        files = self._plans.pop(effect["effect_id"], None)
        if files is None:
            raise RuntimeError("no registered repository patch for effect")
        changed = []
        for item in files:
            target = _safe_repo_path(self.root, item.path)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(item.content, encoding="utf-8")
            changed.append({
                "path": item.path,
                "content_sha256": hashlib.sha256(item.content.encode("utf-8")).hexdigest(),
            })
        evidence = EvidenceRecord(
            evidence_id="EV-" + hashlib.sha256(
                (effect["effect_id"] + ":" + attempt_id).encode()
            ).hexdigest()[:24],
            level="OBSERVED",
            source_ref=f"aios://effect/{effect['effect_id']}/{attempt_id}",
            claim="repository patch provider observed the authorized file mutation",
            run_id=effect["effect_id"],
            provider=self.name,
        ).as_record()
        return ProviderReceipt(
            provider=self.name,
            effect_id=effect["effect_id"],
            attempt_id=attempt_id,
            provider_operation_id=f"{effect['effect_id']}:{attempt_id}",
            outcome="OBSERVED_SUCCESS",
            observation={"changed": changed, "evidence": evidence},
        )


def _safe_repo_path(root: Path, raw: str) -> Path:
    if not isinstance(raw, str) or not raw.strip() or "\x00" in raw:
        raise ValueError("invalid repository patch path")
    path = raw.replace("\\", "/")
    p = Path(path)
    if p.is_absolute() or ".." in p.parts or path.startswith("../") or "/../" in path:
        raise ValueError("repository patch path escapes root")
    target = (root / p).resolve()
    try:
        target.relative_to(root)
    except ValueError as exc:
        raise ValueError("repository patch path escapes root") from exc
    if target.exists() and target.is_symlink():
        raise ValueError("refusing to overwrite symlink")
    return target


def apply_via_aios(
    *,
    aios_dir: str | Path,
    contract_id: str,
    permit_id: str,
    logical_operation_id: str,
    actor: str,
    repository_root: str | Path,
    files: Sequence[ProposedFile],
) -> Mapping[str, object]:
    """Create, dispatch and execute one repository mutation through AIOS."""
    adapter = RepositoryPatchAdapter(repository_root)
    effect = create_effect(
        str(aios_dir), contract_id, logical_operation_id, actor, permit_id,
        "external_effect",
    )
    adapter.register(effect["effect_id"], files)
    return execute(
        str(aios_dir), contract_id, permit_id, logical_operation_id,
        actor, adapter,
    )


__all__ = ["RepositoryPatchAdapter", "RepositoryPatch", "apply_via_aios"]
