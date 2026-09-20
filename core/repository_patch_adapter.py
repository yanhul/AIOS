"""Repository mutation provider bound to the AIOS effect/runtime boundary."""

from __future__ import annotations

import hashlib
import os
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence

from .agent_repair_worker import ProposedFile
from .effect_authority import create_effect
from .evidence import EvidenceRecord
from .runtime import ProviderReceipt, execute


@dataclass(frozen=True)
class RepositoryPatch:
    files: tuple[ProposedFile, ...]


class RepositoryPatchAdapter:
    """Trusted provider for repository patch effects.

    It never grants authority. AIOS runtime.execute() performs contract,
    permit, capability and effect authorization before this provider mutates.
    """

    name = "repo_patch"
    _DENIED_PREFIXES = (".git/", ".github/workflows/", ".aios/", "secrets/")
    _DENIED_FILES = frozenset({".env", ".env.local", ".env.production", "credentials.json"})

    def __init__(self, repository_root: str | Path):
        self.root = Path(repository_root).resolve()
        if not self.root.is_dir():
            raise ValueError("repository root does not exist")
        self._plans: dict[str, tuple[tuple[ProposedFile, ...], str, frozenset[str]]] = {}

    def register(
        self, effect_id: str, files: Sequence[ProposedFile], *, base_sha: str | None = None,
        allowed_dirty_paths: frozenset[str] = frozenset(),
    ) -> None:
        if not isinstance(effect_id, str) or not effect_id.strip() or effect_id in self._plans:
            raise ValueError("effect plan must have a unique non-empty effect_id")
        proposed = tuple(files)
        if not proposed:
            raise ValueError("effect plan contains no files")
        paths = tuple(item.path for item in proposed)
        if len(set(paths)) != len(paths):
            raise ValueError("effect plan contains duplicate paths")
        for item in proposed:
            _safe_repo_path(self.root, item.path)
            if not isinstance(item.content, str):
                raise ValueError("patch content must be text")
        if base_sha is not None:
            _require_clean_base(self.root, base_sha, allowed_dirty_paths=allowed_dirty_paths)
        self._plans[effect_id] = (proposed, base_sha or "", frozenset(allowed_dirty_paths))

    def execute(self, *, contract: dict, effect: dict, attempt_id: str) -> ProviderReceipt:
        effect_id = effect["effect_id"]
        plan = self._plans.get(effect_id)
        if plan is None:
            raise RuntimeError("no registered repository patch for effect")
        files, base_sha, allowed_dirty_paths = plan
        if base_sha:
            _require_clean_base(self.root, base_sha, allowed_dirty_paths=allowed_dirty_paths)

        changed = []
        for item in files:
            target = _safe_repo_path(self.root, item.path)
            _atomic_write(target, item.content)
            changed.append({
                "path": item.path,
                "content_sha256": _sha256_text(item.content),
            })

        self._plans.pop(effect_id, None)
        patch_digest = _sha256_patch(files)
        evidence = EvidenceRecord(
            evidence_id="EV-" + hashlib.sha256(
                f"{effect_id}:{attempt_id}:{patch_digest}".encode("utf-8")
            ).hexdigest()[:24],
            level="OBSERVED",
            source_ref=f"aios://effect/{effect_id}/{attempt_id}",
            claim="repository patch provider observed the authorized file mutation",
            run_id=attempt_id,
            provider=self.name,
            artifact_ref=patch_digest,
        ).as_record()
        return ProviderReceipt(
            provider=self.name,
            effect_id=effect_id,
            attempt_id=attempt_id,
            provider_operation_id=f"{effect_id}:{attempt_id}",
            outcome="OBSERVED_SUCCESS",
            observation={
                "changed": changed,
                "patch_digest": patch_digest,
                "base_sha": base_sha or None,
                "evidence": evidence,
            },
        )


def _sha256_text(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def _sha256_patch(files: Sequence[ProposedFile]) -> str:
    payload = "".join(
        f"{item.path}\0{_sha256_text(item.content)}\0" for item in files
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _safe_repo_path(root: Path, raw: str) -> Path:
    if not isinstance(raw, str) or not raw.strip() or "\x00" in raw:
        raise ValueError("invalid repository patch path")
    path = raw.replace("\\", "/")
    p = Path(path)
    if p.is_absolute() or path.startswith("/") or ".." in p.parts:
        raise ValueError("repository patch path escapes root")
    if p.name in _DENIED_FILES or any(
        path == prefix[:-1] or path.startswith(prefix) for prefix in _DENIED_PREFIXES
    ):
        raise ValueError("repository patch path is protected")
    target = (root / p).resolve()
    try:
        target.relative_to(root)
    except ValueError as exc:
        raise ValueError("repository patch path escapes root") from exc
    if target.exists() and target.is_symlink():
        raise ValueError("refusing to overwrite symlink")
    return target


def _require_clean_base(root: Path, base_sha: str, *, allowed_dirty_paths: frozenset[str] = frozenset()) -> None:
    if not isinstance(base_sha, str) or len(base_sha) != 40:
        raise ValueError("repair base must be a full commit SHA")
    head = subprocess.run(
        ("git", "rev-parse", "--verify", "HEAD"),
        cwd=root, text=True, capture_output=True, check=False,
    )
    if head.returncode or head.stdout.strip() != base_sha:
        raise RuntimeError("stale repair base")
    status = subprocess.run(
        ("git", "status", "--porcelain"),
        cwd=root, text=True, capture_output=True, check=False,
    )
    if status.returncode:
        raise RuntimeError("unable to verify repository status")
    dirty = set()
    for line in status.stdout.splitlines():
        if len(line) >= 4:
            dirty.add(line[3:].replace("\\\\", "/"))
    if dirty and not dirty.issubset(allowed_dirty_paths):
        raise RuntimeError("repository contains unowned dirty paths before AIOS mutation")


def _atomic_write(target: Path, content: str) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{target.name}.repair-", dir=target.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as fh:
            fh.write(content)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_name, target)
    finally:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)


def apply_via_aios(
    *,
    aios_dir: str | Path,
    contract_id: str,
    permit_id: str,
    logical_operation_id: str,
    actor: str,
    repository_root: str | Path,
    files: Sequence[ProposedFile],
    base_sha: str,
    durable_runtime=None,
    allowed_dirty_paths: frozenset[str] = frozenset(),
) -> Mapping[str, object]:
    """Create, dispatch and execute one repository mutation through AIOS."""
    root = Path(repository_root).resolve()
    adapter = RepositoryPatchAdapter(root)
    effect = create_effect(
        str(aios_dir), contract_id, logical_operation_id, actor, permit_id,
        "external_effect",
    )
    adapter.register(effect["effect_id"], files, base_sha=base_sha, allowed_dirty_paths=allowed_dirty_paths)
    return execute(
        str(aios_dir), contract_id, permit_id, logical_operation_id,
        actor, adapter, durable_runtime=durable_runtime,
    )


__all__ = ["RepositoryPatchAdapter", "RepositoryPatch", "apply_via_aios"]
