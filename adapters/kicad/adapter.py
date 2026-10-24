"""Read-only KiCad CLI provider for AIOS.

This adapter is intentionally limited to project inspection, ERC, and DRC.
It never edits the source project, exports manufacturing data, or decides
whether an EDA result is acceptable. AIOS remains the authority boundary.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from core.runtime import ProviderReceipt

CAPABILITY = "kicad.eda"
SUPPORTED_OPERATIONS = {"project_inspect", "erc_check", "drc_check"}
PROJECT_SUFFIXES = {".kicad_pro", ".kicad_sch", ".kicad_pcb"}


def _required_text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty string")
    return value


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _inside(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


@dataclass(frozen=True)
class KicadAdapter:
    """Execute one allowlisted, bounded, read-only KiCad CLI operation."""

    name: str = CAPABILITY
    executable: str = "kicad-cli"
    timeout_seconds: float = 120.0
    max_output_bytes: int = 2 * 1024 * 1024
    # Deployment-bound workspace configuration is outside the immutable AIOS contract schema.
    workspace_root: str | None = None
    project_path: str | None = None

    def __post_init__(self) -> None:
        if self.name != CAPABILITY:
            raise ValueError(f"provider name is fixed to {CAPABILITY}")
        if not isinstance(self.executable, str) or not self.executable.strip():
            raise ValueError("executable must be a non-empty string")
        if not isinstance(self.timeout_seconds, (int, float)) or isinstance(self.timeout_seconds, bool) or self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if not isinstance(self.max_output_bytes, int) or isinstance(self.max_output_bytes, bool) or self.max_output_bytes < 1:
            raise ValueError("max_output_bytes must be a positive integer")
        if self.workspace_root is not None and (not isinstance(self.workspace_root, str) or not self.workspace_root.strip()):
            raise ValueError("workspace_root must be a non-empty string when configured")
        if self.project_path is not None and (not isinstance(self.project_path, str) or not self.project_path.strip()):
            raise ValueError("project_path must be a non-empty string when configured")

    def _command(self, operation: str, project: Path, report: Path) -> list[str]:
        if operation == "project_inspect":
            # Inspection is filesystem metadata only; no subprocess is needed.
            return []
        if operation == "erc_check":
            if project.suffix != ".kicad_sch":
                raise ValueError("erc_check requires a .kicad_sch input")
            return [self.executable, "sch", "erc", "--severity-all",
                    "--output", str(report), str(project)]
        if operation == "drc_check":
            if project.suffix != ".kicad_pcb":
                raise ValueError("drc_check requires a .kicad_pcb input")
            return [self.executable, "pcb", "drc", "--severity-all",
                    "--output", str(report), str(project)]
        raise PermissionError(f"operation is not allowlisted: {operation}")

    def execute(self, *, contract: dict, effect: dict, attempt_id: str) -> ProviderReceipt:
        effect_id = _required_text(effect.get("effect_id"), "effect.effect_id")
        _required_text(attempt_id, "attempt_id")
        if effect.get("attempt_id") != attempt_id:
            raise ValueError("attempt_id does not match dispatched effect")

        # Prefer explicit deployment-bound config. Contract-carried config is retained
        # only for standalone adapter use; AIOS contracts intentionally reject ad-hoc fields.
        config = {"workspace_root": self.workspace_root, "project_path": self.project_path}
        if self.workspace_root is None or self.project_path is None:
            contract_config = contract.get("kicad")
            if not isinstance(contract_config, dict):
                raise ValueError("KiCad adapter requires workspace_root and project_path configuration")
            config = contract_config
        root = Path(_required_text(config.get("workspace_root"), "workspace_root")).resolve()
        project_arg = Path(_required_text(config.get("project_path"), "project_path"))
        project = (root / project_arg).resolve() if not project_arg.is_absolute() else project_arg.resolve()
        if not root.is_dir():
            raise ValueError("workspace_root must be an existing directory")
        if not _inside(project, root):
            raise PermissionError("project path escapes authorized workspace")
        if not project.is_file() or project.suffix not in PROJECT_SUFFIXES:
            raise ValueError("project_path must be an existing KiCad project/schematic/PCB file")

        # AIOS effect records bind the requested operation as logical_operation_id.
        # Standalone adapter tests may still supply an explicit operation field.
        operation = _required_text(
            effect.get("operation", effect.get("logical_operation_id")),
            "effect.logical_operation_id",
        )
        if operation not in SUPPORTED_OPERATIONS:
            raise PermissionError(f"operation is not allowlisted: {operation}")

        input_hash = _sha256(project)
        observation = {
            "operation": operation,
            "project_path": project.relative_to(root).as_posix(),
            "project_sha256_before": input_hash,
            "project_sha256_after": input_hash,
            "process_exit_code": 0,
            "report_sha256": None,
            "report_bytes": 0,
            "finding_count": None,
            "quality_verdict": "NOT_ASSESSED",
        }

        provider_operation_id = f"{effect_id}:{attempt_id}:{operation}"
        if operation == "project_inspect":
            observation["project_suffix"] = project.suffix
            observation["project_size_bytes"] = project.stat().st_size
            return ProviderReceipt(
                provider=self.name, effect_id=effect_id, attempt_id=attempt_id,
                provider_operation_id=provider_operation_id,
                outcome="OBSERVED_SUCCESS", observation=observation,
            )

        cli = shutil.which(self.executable) if os.path.sep not in self.executable else self.executable
        if not cli or not Path(cli).is_file():
            raise FileNotFoundError(f"KiCad CLI not found: {self.executable}")

        report_dir = root / ".aios-kicad-reports"
        report_dir.mkdir(mode=0o700, exist_ok=True)
        report_dir = report_dir.resolve()
        if not _inside(report_dir, root):
            raise PermissionError("report directory escapes authorized workspace")
        report = report_dir / f"{hashlib.sha256(provider_operation_id.encode()).hexdigest()}.rpt"
        # Never accept a stale report from an earlier/replayed attempt as evidence.
        if report.exists():
            report.unlink()
        command = self._command(operation, project, report)
        command[0] = cli
        try:
            completed = subprocess.run(
                command, capture_output=True, timeout=self.timeout_seconds,
                check=False, shell=False, cwd=str(root),
            )
        except subprocess.TimeoutExpired as exc:
            raise TimeoutError("KiCad CLI timed out; effect outcome requires reconciliation") from exc

        stdout = completed.stdout or b""
        stderr = completed.stderr or b""
        if len(stdout) + len(stderr) > self.max_output_bytes:
            raise ValueError("KiCad CLI output exceeds configured limit")

        observation["process_exit_code"] = completed.returncode
        observation["stdout_sha256"] = hashlib.sha256(stdout).hexdigest()
        observation["stderr_sha256"] = hashlib.sha256(stderr).hexdigest()
        observation["project_sha256_after"] = _sha256(project)
        if observation["project_sha256_after"] != input_hash:
            raise RuntimeError("read-only KiCad operation changed the source project")
        if report.is_file():
            report_size = report.stat().st_size
            if report_size > self.max_output_bytes:
                raise ValueError("KiCad report exceeds configured output limit")
            observation["report_sha256"] = _sha256(report)
            observation["report_bytes"] = report_size
            try:
                report_text = report.read_text(encoding="utf-8", errors="replace")
                # This is diagnostic metadata only; never use a heuristic as PASS.
                observation["finding_count"] = sum(
                    1 for line in report_text.splitlines()
                    if any(token in line.lower() for token in ("violation", "severity", "error", "warning"))
                )
            except OSError:
                observation["finding_count"] = None
        else:
            observation["report_missing"] = True
        # ERC/DRC success requires both a zero exit code and its expected report.
        # A missing report is an observed provider failure, never a quality PASS.
        observation["quality_verdict"] = "NOT_ASSESSED"
        outcome = (
            "OBSERVED_SUCCESS"
            if completed.returncode == 0 and report.is_file()
            else "OBSERVED_FAILURE"
        )
        return ProviderReceipt(
            provider=self.name, effect_id=effect_id, attempt_id=attempt_id,
            provider_operation_id=provider_operation_id,
            outcome=outcome, observation=observation,
        )


__all__ = ["KicadAdapter", "CAPABILITY", "SUPPORTED_OPERATIONS"]
