import json
import subprocess
import sys
from pathlib import Path


def test_terminal_receipt_is_reused_without_reexecuting_adapter(tmp_path):
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
    assert first.returncode == 0, first.stdout
    assert marker.read_text() == "x"
    first_receipt = json.loads(first.stdout)

    second = subprocess.run(command, capture_output=True, text=True)
    assert second.returncode == 0, second.stdout
    assert marker.read_text() == "x"
    assert json.loads(second.stdout) == first_receipt
