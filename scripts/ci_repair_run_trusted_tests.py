#!/usr/bin/env python3
"""Run candidate tests with a minimal environment and an optional mandatory OS sandbox."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile

from core.repair_reconcile import patch_digest, compute_test_evidence_digest


def _trusted_test_env(*, test_root: Path, home: Path, tmp: Path,
                      run_id: int, repository: str, source_env=None) -> dict[str, str]:
    """Construct an allowlisted environment; never inherit the runner environment."""
    source = os.environ if source_env is None else source_env
    env = {
        "PATH": source.get("PATH", "/usr/bin:/bin"),
        "HOME": str(home),
        "TMPDIR": str(tmp),
        "TEMP": str(tmp),
        "TMP": str(tmp),
        "LANG": source.get("LANG", "C.UTF-8"),
        "LC_ALL": source.get("LC_ALL", "C.UTF-8"),
        "CI": "true",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONPATH": str(test_root),
        "GITHUB_WORKSPACE": str(test_root),
        "GITHUB_RUN_ID": str(run_id),
        "GITHUB_REPOSITORY": repository,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
    }
    # These are toolchain locations, not authentication material.
    for name in ("JAVA_HOME", "ANDROID_HOME", "ANDROID_SDK_ROOT", "GRADLE_HOME"):
        if source.get(name):
            env[name] = source[name]
    return env


def _run_pytest(command: list[str], *, cwd: Path, env: dict[str, str],
                timeout: int, require_os_sandbox: bool, sandbox_root: Path) -> subprocess.CompletedProcess:
    if not require_os_sandbox:
        return subprocess.run(command, cwd=cwd, text=True, capture_output=True,
                              timeout=timeout, check=False, env=env)

    # The trusted-test process receives a fresh UID, PID namespace and network
    # namespace. It cannot inspect host processes or reach external services.
    # Missing sudo/unshare/setpriv or namespace support is a hard failure.
    sandbox_path = "/usr/sbin:/usr/bin:/sbin:/bin"
    allowed = [f"{key}={value}" for key, value in sorted(env.items())]
    isolated = [
        "sudo", "-n", "env", "-i", f"PATH={sandbox_path}", f"HOME={env['HOME']}",
        "unshare", "--net", "--pid", "--mount-proc", "--fork",
        "setpriv", "--reuid=65534", "--regid=65534", "--clear-groups",
        "env", "-i", f"PATH={env['PATH']}", *allowed,
        *command,
    ]
    return subprocess.run(isolated, cwd=cwd, text=True, capture_output=True,
                          timeout=timeout, check=False)


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

    command = [sys.executable, "-m", "pytest", "-q"]
    repo_root = Path.cwd().resolve()
    require_sandbox = os.environ.get("AIOS_REPAIR_REQUIRE_OS_SANDBOX") == "1"
    returncode = 1
    stdout = ""
    stderr = ""
    with tempfile.TemporaryDirectory(prefix="aios-repair-tests-") as temp_dir:
        temp_root = Path(temp_dir)
        test_root = temp_root / "repo"
        home = temp_root / "home"
        tmp = temp_root / "tmp"
        test_root.mkdir()
        home.mkdir()
        tmp.mkdir()
        os.chmod(temp_root, 0o755)

        # Export only the trusted base tree, not a Git worktree. The test process
        # therefore has no .git pointer into the secret-bearing apply checkout.
        archive_path = temp_root / "base.tar"
        git_env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": str(home),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
        }
        with archive_path.open("wb") as archive_file:
            subprocess.run(["git", "archive", "--format=tar", base], cwd=repo_root,
                           env=git_env, stdout=archive_file, check=True)
        with tarfile.open(archive_path, "r:") as archive:
            archive.extractall(test_root, filter="data")

        for path, content in files.items():
            relative = Path(path)
            if relative.is_absolute() or ".." in relative.parts:
                raise SystemExit(f"unsafe trusted-test patch path: {path}")
            target = test_root / relative
            cursor = test_root
            for part in relative.parts:
                cursor = cursor / part
                if cursor.is_symlink():
                    raise SystemExit(f"trusted-test patch path traverses symlink: {path}")
            resolved = target.resolve()
            try:
                resolved.relative_to(test_root.resolve())
            except ValueError as exc:
                raise SystemExit(f"trusted-test patch path escapes source tree: {path}") from exc
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")

        test_env = _trusted_test_env(
            test_root=test_root, home=home, tmp=tmp,
            run_id=run_id, repository=repository,
        )
        if require_sandbox:
            # The namespace process drops to nobody. Give it write access only to
            # its private extracted source tree, HOME and TMPDIR.
            os.chmod(home, 0o700)
            os.chmod(tmp, 0o700)
            subprocess.run(["sudo", "-n", "chown", "-R", "65534:65534", str(test_root),
                            str(home), str(tmp)], check=True, capture_output=True, text=True)
        try:
            proc = _run_pytest(command, cwd=test_root, env=test_env, timeout=900,
                               require_os_sandbox=require_sandbox, sandbox_root=temp_root)
            returncode, stdout, stderr = proc.returncode, proc.stdout, proc.stderr
        except subprocess.TimeoutExpired as exc:
            returncode = 124
            stdout = exc.stdout.decode("utf-8", "replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
            stderr = exc.stderr.decode("utf-8", "replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
            stderr += "\\ntrusted test command timed out after 900 seconds"
        finally:
            if require_sandbox:
                # Restore ownership so TemporaryDirectory can securely remove the tree.
                owner = f"{os.getuid()}:{os.getgid()}"
                subprocess.run(["sudo", "-n", "chown", "-R", owner,
                                str(test_root), str(home), str(tmp)],
                               check=True, capture_output=True, text=True)

    result = {
        "status": "PASS" if returncode == 0 else "FAIL", "run_id": run_id,
        "repository": repository, "base_sha": base,
        "patch_digest": expected_patch,
        "isolation": {
            "environment": "ALLOWLIST_ONLY",
            "source_checkout_git_metadata": "NOT_EXPOSED",
            "os_sandbox": "REQUIRED_AND_USED" if require_sandbox else "NOT_REQUIRED_FOR_LOCAL_TEST",
            "network": "DENIED" if require_sandbox else "NOT_ISOLATED",
            "uid": 65534 if require_sandbox else os.getuid(),
            "pid_namespace": "ISOLATED" if require_sandbox else "NOT_ISOLATED",
        },
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
                      "patch_digest": expected_patch, "isolation": result["isolation"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
