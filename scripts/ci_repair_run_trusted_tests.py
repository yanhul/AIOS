#!/usr/bin/env python3
"""Run the fixed trusted test command in a step that receives no trust secrets."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

from core.repair_reconcile import patch_digest, compute_test_evidence_digest


def main() -> int:
    run_id = int(os.environ["AIOS_REPAIR_RUN_ID"])
    base = os.environ["AIOS_REPAIR_SHA"]
    repository = os.environ["GITHUB_REPOSITORY"]
    apply_result = json.loads(Path("repair-apply-result.json").read_text(encoding="utf-8"))
    if apply_result.get("schema") != 1 or apply_result.get("status") != "PATCH_APPLIED_RECEIPTS_ACCEPTED":
        raise SystemExit("trusted tests require an AIOS-accepted patch result")
    if (apply_result.get("run_id") != run_id or apply_result.get("base_sha") != base
            or apply_result.get("repository") != repository):
        raise SystemExit("apply result repository/run/base binding mismatch")
    proposal_paths = [Path(x) for x in os.environ["AIOS_REPAIR_PROPOSALS"].split(",") if x]
    proposals = [json.loads(p.read_text(encoding="utf-8")) for p in proposal_paths]
    if [int(p.get("attempt", -1)) for p in proposals] != list(range(1, len(proposals) + 1)):
        raise SystemExit("trusted test proposals are not a contiguous attempt sequence")
    files = {}
    for proposal in proposals:
        if (proposal.get("schema") != 2 or proposal.get("run_id") != run_id
                or proposal.get("repository") != repository or proposal.get("base_sha") != base):
            raise SystemExit("proposal lineage mismatch before trusted tests")
        for item in proposal["files"]:
            files[item["path"]] = item["content"]
    expected_patch = patch_digest([{"path": k, "content": v} for k, v in sorted(files.items())])

    command = ["python", "-m", "pytest", "-q"]
    clean_env = os.environ.copy()
    for name in tuple(clean_env):
        upper = name.upper()
        if upper.startswith("AIOS_REPAIR_") or any(marker in upper for marker in (
            "SECRET", "TOKEN", "API_KEY", "SIGNING_KEY", "SIGNING_KEYS",
            "PRIVATE_KEY", "KEYRING", "CREDENTIAL",
        )):
            clean_env.pop(name, None)
    repo_root = Path.cwd().resolve()
    with tempfile.TemporaryDirectory(prefix="aios-repair-tests-") as temp_dir:
        test_root = Path(temp_dir) / "repo"
        subprocess.run(
            ["git", "worktree", "add", "--detach", str(test_root), base],
            cwd=repo_root, text=True, capture_output=True, check=True,
        )
        try:
            for path, content in files.items():
                relative = Path(path)
                if relative.is_absolute() or ".." in relative.parts:
                    raise SystemExit(f"unsafe trusted-test patch path: {path}")
                target = (test_root / relative).resolve()
                try:
                    target.relative_to(test_root.resolve())
                except ValueError as exc:
                    raise SystemExit(f"trusted-test patch path escapes worktree: {path}") from exc
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(content, encoding="utf-8")
            clean_env["GITHUB_WORKSPACE"] = str(test_root)
            clean_env["PYTHONPATH"] = str(test_root)
            try:
                proc = subprocess.run(command, cwd=test_root, text=True, capture_output=True,
                                      timeout=900, check=False, env=clean_env)
                returncode = proc.returncode
                stdout, stderr = proc.stdout, proc.stderr
            except subprocess.TimeoutExpired as exc:
                returncode = 124
                stdout = exc.stdout.decode("utf-8", "replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
                stderr = exc.stderr.decode("utf-8", "replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
                stderr += "\ntrusted test command timed out after 900 seconds"
        finally:
            cleanup = subprocess.run(
                ["git", "worktree", "remove", "--force", str(test_root)],
                cwd=repo_root, text=True, capture_output=True, check=False,
            )
            if cleanup.returncode:
                raise SystemExit(
                    "trusted test worktree cleanup failed: " + cleanup.stderr.strip()
                )
    result = {
        "status": "PASS" if returncode == 0 else "FAIL", "run_id": run_id,
        "repository": repository, "base_sha": base,
        "patch_digest": expected_patch,
        "evidence_refs": [f"test:0:{returncode}"],
        "results": [{
            "command": command, "returncode": returncode,
            "stdout_sha256": hashlib.sha256(stdout.encode("utf-8")).hexdigest(),
            "stderr_sha256": hashlib.sha256(stderr.encode("utf-8")).hexdigest(),
            "stdout_tail": stdout[-4000:], "stderr_tail": stderr[-4000:],
        }],
    }
    result["digest"] = compute_test_evidence_digest(result)
    Path("repair-test-result.json").write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps({"status": result["status"], "returncode": returncode,
                      "patch_digest": expected_patch}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
