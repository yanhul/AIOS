"""Regression tests for the MiniMind signer/receipt-runner process boundary."""
import subprocess


def test_receipt_runner_uses_live_bounded_output_supervision(monkeypatch):
    from adapters import bounded_process
    from adapters.minimind import workload_entry

    observed = {}

    monkeypatch.setattr(
        workload_entry,
        "validate_receipt_command",
        lambda *args, **kwargs: {"receipt_launcher": "/usr/lib/aios/receipt-launcher"},
    )
    monkeypatch.setattr(workload_entry, "resolve_trusted_symlinks", lambda path, **kwargs: path)
    monkeypatch.setattr(workload_entry, "check_trusted_path", lambda *args, **kwargs: None)
    monkeypatch.setattr(workload_entry, "check_sudo_rules", lambda *args, **kwargs: None)

    def sudo_listing(command, **kwargs):
        assert command == [workload_entry.SUDO, "-n", "-l"]
        return subprocess.CompletedProcess(command, 0, stdout=b"", stderr=b"")

    monkeypatch.setattr(workload_entry.subprocess, "run", sudo_listing)

    def bounded(command, **kwargs):
        observed["command"] = command
        observed.update(kwargs)
        return subprocess.CompletedProcess(command, 0, stdout=b'{"minimind_receipt":{}}', stderr=b"")

    monkeypatch.setattr(bounded_process, "run_bounded", bounded)

    output = workload_entry.run_receipt_command({"runner_user": "aios-minimind-run"}, b"{}", 7)

    assert output == b'{"minimind_receipt":{}}'
    assert observed["command"] == [
        workload_entry.SUDO, "-n", "-u", "aios-minimind-run", "--",
        "/usr/lib/aios/receipt-launcher",
    ]
    assert observed["input"] == b"{}"
    assert observed["timeout"] == 7
    assert observed["max_stdout_bytes"] == workload_entry.MAX_RECEIPT_BYTES
    assert observed["max_stderr_bytes"] == workload_entry.MAX_RECEIPT_STDERR_BYTES
    assert observed["cwd"] == "/"
    assert observed["env"] == workload_entry._ENV
