"""Trusted repair execution worker.

The worker is the missing execution substrate between a repair proposal and
AIOS verification. It may inspect/apply bounded source patches and run a
trusted deterministic test plan. It never grants authority, edits receipts,
declares PASS, or executes commands supplied by the model.

Security boundary:
- model output is data, not shell input;
- patch paths are repository-relative and deny control-plane files by default;
- the caller supplies the trusted test commands;
- an injected authority gate must approve mutation before files are changed;
- every apply/test result is returned as evidence-bearing data.
"""
from __future__ import annotations

import hashlib
import os
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Protocol, Sequence


class RepairWorkerError(RuntimeError):
    pass


@dataclass(frozen=True)
class ProposedFile:
    path: str
    content: str


@dataclass(frozen=True)
class RepairProposal:
    root_cause: str
    proposed_fix: str
    files: tuple[ProposedFile, ...]
    regression_tests: tuple[str, ...] = ()


@dataclass(frozen=True)
class WorkerEvidence:
    action: str
    status: str
    evidence_refs: tuple[str, ...]
    details: Mapping[str, object]


class PatchAuthority(Protocol):
    def authorize_patch(self, *, base_sha: str, paths: tuple[str, ...]) -> str: ...


class RepairProposer(Protocol):
    def propose(
        self, *, failure: Mapping[str, object], repository_snapshot: str
    ) -> RepairProposal: ...


class AgentRepairWorker:
    """Apply a bounded proposal and execute only a trusted test plan."""

    # These files can change the authority/security boundary and therefore
    # require a separate explicit mechanism. The worker fails closed.
    _DENIED_PREFIXES = (
        ".git/",
        ".github/workflows/",
        ".aios/",
        "secrets/",
    )
    _DENIED_FILES = frozenset(
        {".env", ".env.local", ".env.production", "credentials.json"}
    )

    def __init__(
        self,
        repository_root: str | os.PathLike[str],
        authority: PatchAuthority,
        *,
        allowed_test_commands: Sequence[Sequence[str]] = (),
        timeout_seconds: int = 900,
    ) -> None:
        self.root = Path(repository_root).resolve()
        self.authority = authority
        self.allowed_test_commands = tuple(
            tuple(command) for command in allowed_test_commands
        )
        self.timeout_seconds = timeout_seconds
        if not self.root.is_dir():
            raise RepairWorkerError(f"repository root does not exist: {self.root}")
        if timeout_seconds <= 0:
            raise RepairWorkerError("timeout_seconds must be positive")

    @staticmethod
    def _sha256_text(content: str) -> str:
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    def _safe_path(self, raw: str) -> Path:
        if not isinstance(raw, str) or not raw.strip():
            raise RepairWorkerError("patch path must be a non-empty string")
        if "\x00" in raw:
            raise RepairWorkerError("patch path contains NUL")
        path = raw.replace("\\", "/")
        if path.startswith("/") or path.startswith("../") or "/../" in path:
            raise RepairWorkerError(f"patch path escapes repository: {raw!r}")
        normalized = Path(path)
        if normalized.is_absolute() or ".." in normalized.parts:
            raise RepairWorkerError(f"patch path escapes repository: {raw!r}")
        if normalized.name in self._DENIED_FILES or any(
            path == prefix.rstrip("/") or path.startswith(prefix)
            for prefix in self._DENIED_PREFIXES
        ):
            raise RepairWorkerError(f"patch path is protected: {raw!r}")
        target = (self.root / normalized).resolve()
        try:
            target.relative_to(self.root)
        except ValueError as exc:
            raise RepairWorkerError(f"patch path escapes repository: {raw!r}") from exc
        if target.exists() and target.is_symlink():
            raise RepairWorkerError(f"refusing to overwrite symlink: {raw!r}")
        return target

    def _git(self, *args: str) -> str:
        proc = subprocess.run(
            ("git", *args),
            cwd=self.root,
            text=True,
            capture_output=True,
            timeout=self.timeout_seconds,
            check=False,
        )
        if proc.returncode:
            raise RepairWorkerError(
                f"git command failed ({proc.returncode}): {proc.stderr.strip()}"
            )
        return proc.stdout.strip()

    def _require_clean_base(self, base_sha: str) -> None:
        if not isinstance(base_sha, str) or len(base_sha) != 40:
            raise RepairWorkerError("base_sha must be a 40-character commit SHA")
        head = self._git("rev-parse", "HEAD")
        if head != base_sha:
            raise RepairWorkerError(
                f"stale repair base: worker={head}, proposal={base_sha}"
            )
        status = self._git("status", "--porcelain")
        if status:
            raise RepairWorkerError("repository is not clean before repair")

    def _atomic_write(self, target: Path, content: str) -> None:
        target.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(
            prefix=f".{target.name}.repair-", dir=target.parent
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="") as fh:
                fh.write(content)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp_name, target)
        finally:
            if os.path.exists(tmp_name):
                os.unlink(tmp_name)

    def apply(
        self, *, base_sha: str, files: Sequence[ProposedFile]
    ) -> WorkerEvidence:
        self._require_clean_base(base_sha)
        if not files:
            raise RepairWorkerError("repair proposal contains no files")

        proposed = tuple(files)
        paths = tuple(item.path for item in proposed)
        if len(set(paths)) != len(paths):
            raise RepairWorkerError("repair proposal contains duplicate paths")

        targets = tuple(self._safe_path(path) for path in paths)

        # Authority is consulted before the first filesystem mutation.
        permit_id = self.authority.authorize_patch(
            base_sha=base_sha, paths=paths
        )
        if not isinstance(permit_id, str) or not permit_id.strip():
            raise RepairWorkerError("authority returned no permit")

        changed = []
        for item, target in zip(proposed, targets):
            if not isinstance(item.content, str):
                raise RepairWorkerError(f"patch content must be text: {item.path!r}")
            self._atomic_write(target, item.content)
            changed.append(
                {
                    "path": item.path,
                    "content_sha256": self._sha256_text(item.content),
                }
            )

        return WorkerEvidence(
            action="APPLY_PATCH",
            status="APPLIED",
            evidence_refs=(
                f"repair:base:{base_sha}",
                f"repair:permit:{permit_id}",
            ),
            details={"paths": changed, "permit_id": permit_id},
        )

    def test(
        self, commands: Sequence[Sequence[str]] | None = None
    ) -> WorkerEvidence:
        selected = tuple(tuple(c) for c in (commands or self.allowed_test_commands))
        if not selected:
            raise RepairWorkerError("no trusted test command configured")
        for command in selected:
            if not command or any(not isinstance(arg, str) for arg in command):
                raise RepairWorkerError("invalid trusted test command")
            if command not in self.allowed_test_commands:
                raise RepairWorkerError(
                    "test command is not in the trusted worker allowlist"
                )

        results = []
        all_passed = True
        for command in selected:
            proc = subprocess.run(
                command,
                cwd=self.root,
                text=True,
                capture_output=True,
                timeout=self.timeout_seconds,
                check=False,
            )
            passed = proc.returncode == 0
            all_passed = all_passed and passed
            results.append(
                {
                    "command": list(command),
                    "returncode": proc.returncode,
                    "stdout_sha256": self._sha256_text(proc.stdout),
                    "stderr_sha256": self._sha256_text(proc.stderr),
                    "stdout_tail": proc.stdout[-4000:],
                    "stderr_tail": proc.stderr[-4000:],
                }
            )
            if not passed:
                break

        status = "PASS" if all_passed else "FAIL"
        return WorkerEvidence(
            action="TEST",
            status=status,
            evidence_refs=tuple(
                f"test:{i}:{r['returncode']}" for i, r in enumerate(results)
            ),
            details={"results": results},
        )

    def repair(
        self,
        *,
        base_sha: str,
        failure: Mapping[str, object],
        repository_snapshot: str,
        proposer: RepairProposer,
        test_commands: Sequence[Sequence[str]] | None = None,
    ) -> tuple[RepairProposal, WorkerEvidence, WorkerEvidence]:
        proposal = proposer.propose(
            failure=failure, repository_snapshot=repository_snapshot
        )
        if not proposal.root_cause or not proposal.proposed_fix:
            raise RepairWorkerError("proposal lacks diagnosis/fix")
        applied = self.apply(base_sha=base_sha, files=proposal.files)
        tested = self.test(test_commands)
        return proposal, applied, tested


__all__ = [
    "AgentRepairWorker",
    "PatchAuthority",
    "ProposedFile",
    "RepairProposal",
    "RepairWorkerError",
    "RepairProposer",
    "WorkerEvidence",
]
