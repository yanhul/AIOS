from __future__ import annotations

from scripts import ci_repair_propose as propose


def test_referenced_source_paths_extracts_traceback_and_pytest_forms():
    tracked = [
        "core/ci_supervisor.py",
        "scripts/ci_repair_propose.py",
        "tests/test_ci_supervisor.py",
    ]
    log = '''
      File "/home/runner/work/AIOS/AIOS/core/ci_supervisor.py", line 78, in receive
      core/ci_supervisor.py:78: CIEventError
      FAILED tests/test_ci_supervisor.py::test_receive
    '''

    assert propose.referenced_source_paths(tracked, log) == [
        "core/ci_supervisor.py"
    ]


def test_bounded_source_prioritizes_referenced_file_before_file_limit(monkeypatch):
    paths = [f"core/{index:02d}_module.py" for index in range(45)]
    paths.append("core/z_failure_target.py")
    monkeypatch.setattr(propose, "git", lambda *args: "\n".join(paths))
    monkeypatch.setattr(propose, "show_complete", lambda sha, path: f"# {path}\n")

    source = propose.bounded_source(
        "a" * 40,
        'File "/home/runner/work/AIOS/AIOS/core/z_failure_target.py", line 9',
    )

    assert "core/z_failure_target.py" in source
    assert len(source) == propose.MAX_SOURCE_FILES



def test_bounded_source_prioritizes_module_imported_by_failed_test(monkeypatch):
    paths = ["core/absorption_authority.py", "core/repair_e2e_probe.py"]
    tracked = paths + ["tests/test_repair_e2e_probe.py"]
    monkeypatch.setattr(propose, "git", lambda *args: "\n".join(tracked))
    monkeypatch.setattr(
        propose, "show_complete",
        lambda sha, path: "from core.repair_e2e_probe import repair_probe_value\n"
        if path == "tests/test_repair_e2e_probe.py" else f"# complete {path}\n",
    )

    referenced = propose.referenced_source_paths(
        tracked,
        "FAILED tests/test_repair_e2e_probe.py::test_governed_repair_probe",
        sha="a" * 40,
    )

    assert referenced == ["core/repair_e2e_probe.py"]


def test_bounded_source_preserves_complete_large_referenced_file(monkeypatch):
    target = "core/repair_e2e_probe.py"
    content = "VALUE = 1\n" + ("# context\n" * 1400)
    monkeypatch.setattr(propose, "git", lambda *args: target)
    monkeypatch.setattr(propose, "show_complete", lambda sha, path: content)

    source = propose.bounded_source(
        "a" * 40,
        "core/repair_e2e_probe.py:1: AssertionError",
    )

    assert source[target] == content
    assert len(source[target].encode("utf-8")) > 8_000


def test_bounded_source_fails_closed_instead_of_truncating_required_test_module(monkeypatch):
    target = "core/repair_e2e_probe.py"
    test_path = "tests/test_repair_e2e_probe.py"
    content = "x" * (propose.MAX_FILE_BYTES + 1)
    tracked = [target, test_path]
    monkeypatch.setattr(propose, "git", lambda *args: "\n".join(tracked))
    monkeypatch.setattr(
        propose, "show_complete",
        lambda sha, path: "from core.repair_e2e_probe import repair_probe_value\n"
        if path == test_path else content,
    )

    import pytest
    with pytest.raises(SystemExit, match="failed-test source file"):
        propose.bounded_source(
            "a" * 40,
            "FAILED tests/test_repair_e2e_probe.py::test_governed_repair_probe",
        )



def test_bounded_source_skips_noisy_references_after_required_test_module(monkeypatch):
    target = "core/repair_e2e_probe.py"
    noisy = "core/runtime.py"
    test_path = "tests/test_repair_e2e_probe.py"
    monkeypatch.setattr(propose, "MAX_SOURCE_BYTES", 100)
    monkeypatch.setattr(propose, "git", lambda *args: "\n".join([target, noisy, test_path]))
    def read(sha, path):
        if path == test_path:
            return "from core.repair_e2e_probe import repair_probe_value\n"
        if path == noisy:
            return "x" * 200
        return "def repair_probe_value(): return 'BROKEN'\n"
    monkeypatch.setattr(propose, "show_complete", read)

    source = propose.bounded_source(
        "a" * 40,
        "FAILED tests/test_repair_e2e_probe.py::test_governed_repair_probe\n"
        "core/runtime.py:1: incidental traceback",
    )

    assert target in source
    assert noisy not in source



def test_failed_test_import_discovery_ignores_warning_paths(monkeypatch):
    paths = ["core/runtime.py", "core/repair_e2e_probe.py"]
    test_sources = {
        "tests/test_runtime.py": "from core.runtime import Runtime\n",
        "tests/test_repair_e2e_probe.py": "from core.repair_e2e_probe import repair_probe_value\n",
    }
    monkeypatch.setattr(
        propose, "show_complete",
        lambda sha, path: test_sources.get(path, ""),
    )
    log = (
        "tests/test_runtime.py:271: PytestUnknownMarkWarning\n"
        "FAILED tests/test_repair_e2e_probe.py::test_governed_repair_probe\n"
    )

    assert propose.failed_test_import_paths(
        paths, log, sha="a" * 40
    ) == ["core/repair_e2e_probe.py"]
