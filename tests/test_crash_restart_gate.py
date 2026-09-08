import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path


def test_central_runner_crash_restart_does_not_reuse_incomplete_execution(tmp_path):
    root = tmp_path / "workload"
    (root / "aios").mkdir(parents=True)
    (root / "aios" / "workload.json").write_text(json.dumps({
        "protocol_version": 1,
        "capability": "try.research@1",
        "owner": "yanhul/try",
        "aios_authority": "yanhul/AIOS",
        "adapter": "aios/adapter.py",
        "entrypoint": "execute",
        "terminal_states": ["BLOCKED"],
        "verification_classes": ["provenance"],
    }), encoding="utf-8")
    marker = root / "effect.marker"
    adapter = root / "aios" / "adapter.py"
    adapter.write_text(
        "import json, time\n"
        f"open({str(marker)!r}, 'a', encoding='utf-8').write('effect\\n')\n"
        "time.sleep(30)\n"
        "print(json.dumps({'status':'BLOCKED','evidence_refs':['effect'],"
        "'verification_refs':['crash-gate'], 'provenance':{'producer':'yanhul/try'}}))\n",
        encoding="utf-8",
    )
    receipt = tmp_path / "receipt.json"
    runner = Path(__file__).parents[1] / "scripts" / "run_workload_adapter.py"
    base = [sys.executable, str(runner), "--workload-id", "yanhul/try",
            "--execution-id", "crash-gate", "--cwd", str(root), "--problem", "crash-gate",
            "--timeout-seconds", "60", "--receipt-path", str(receipt), "--",
            sys.executable, "aios/adapter.py"]

    first = subprocess.Popen(base, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    deadline = time.time() + 10
    while time.time() < deadline and not marker.exists():
        time.sleep(0.05)
    assert marker.exists(), "adapter never reached durable side effect"
    os.kill(first.pid, signal.SIGKILL)
    first.wait(timeout=5)
    assert not receipt.exists(), "crashed execution must not publish a terminal receipt"

    second = subprocess.run(base, capture_output=True, text=True, timeout=10)
    assert second.returncode == 0, second.stdout + second.stderr
    assert receipt.exists()
    saved = json.loads(receipt.read_text(encoding="utf-8"))
    assert saved["execution_id"] == "crash-gate"
    assert saved["status"] == "BLOCKED"
    assert marker.read_text(encoding="utf-8").splitlines() == ["effect", "effect"]
