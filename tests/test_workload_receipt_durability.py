import json
import subprocess
import sys
from pathlib import Path


def test_workload_runner_fails_closed_before_adapter_or_receipt(tmp_path):
    aios = tmp_path / "aios"
    aios.mkdir()
    (aios / "workload.json").write_text(json.dumps({
        "protocol_version": 1,
        "capability": "try.research@1",
        "owner": "yanhul/try",
        "aios_authority": "yanhul/AIOS",
        "adapter": "aios/adapter.py",
        "entrypoint": "execute",
        "terminal_states": ["BLOCKED"],
        "verification_classes": ["provenance"],
    }))
    marker = tmp_path / "executions.txt"
    (aios / "adapter.py").write_text(
        "from pathlib import Path\n"
        "p=Path('executions.txt')\n"
        "p.write_text(p.read_text()+'x' if p.exists() else 'x')\n"
        "import json\n"
        "print(json.dumps({'status':'BLOCKED','evidence_refs':['e'],"
        "'verification_refs':['provenance'],"
        "'provenance':{'producer':'yanhul/try','adapter':'try.research@1'}}, indent=2))\n"
    )
    runner = Path(__file__).parents[1] / "scripts" / "run_workload_adapter.py"
    receipt = tmp_path / "receipt.json"
    command = [sys.executable, str(runner), "--workload-id", "yanhul/try",
               "--execution-id", "durable-1", "--cwd", str(tmp_path), "--problem", "p",
               "--receipt-path", str(receipt), "--", sys.executable, "aios/adapter.py"]
    first = subprocess.run(command, capture_output=True, text=True)
    assert first.returncode == 2, first.stdout + first.stderr
    assert "independent actor issuer" in first.stdout
    assert not marker.exists()
    assert not receipt.exists()

    second = subprocess.run(command, capture_output=True, text=True)
    assert second.returncode == 2, second.stdout + second.stderr
    assert "independent actor issuer" in second.stdout
    assert not marker.exists()
    assert not receipt.exists()
