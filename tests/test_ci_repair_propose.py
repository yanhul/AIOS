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
    monkeypatch.setattr(propose, "show", lambda sha, path: f"# {path}\n")

    source = propose.bounded_source(
        "a" * 40,
        'File "/home/runner/work/AIOS/AIOS/core/z_failure_target.py", line 9',
    )

    assert "core/z_failure_target.py" in source
    assert len(source) == propose.MAX_SOURCE_FILES
