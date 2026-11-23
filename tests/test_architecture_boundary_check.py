import importlib.util
from pathlib import Path

SPEC = importlib.util.spec_from_file_location(
    "architecture_boundary_check",
    Path(__file__).resolve().parents[1] / "scripts" / "architecture_boundary_check.py",
)
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)


def test_l5_boundary_checker_rejects_provider_dependency(tmp_path):
    (tmp_path / "core").mkdir()
    (tmp_path / "core" / "mutation.py").write_text(
        "import json\nfrom adapters.foo import Provider\n", encoding="utf-8"
    )
    findings = CHECK.inspect_file(tmp_path, "core/mutation.py")
    assert len(findings) == 1
    assert findings[0]["rule"] == "L5-NO-EXECUTION-DEPENDENCY"
    assert "adapters.foo" in findings[0]["detail"]


def test_l5_boundary_checker_accepts_persistence_only_module(tmp_path):
    (tmp_path / "core").mkdir()
    (tmp_path / "core" / "mutation.py").write_text(
        "import json\nfrom pathlib import Path\n", encoding="utf-8"
    )
    assert CHECK.inspect_file(tmp_path, "core/mutation.py") == []


def test_l5_boundary_checker_reports_missing_file_fail_closed(tmp_path):
    (tmp_path / "core").mkdir()
    findings = CHECK.inspect_file(tmp_path, "core/mutation.py")
    assert len(findings) == 1
    assert findings[0]["rule"] == "L5-SOURCE-READ"
