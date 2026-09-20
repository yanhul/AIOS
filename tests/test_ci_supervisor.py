from core.ci_supervisor import CISupervisor, DurableSupervisorState


class Client:
    def __init__(self, payloads):
        self.payloads = iter(payloads)

    def get_json(self, path):
        return next(self.payloads)


def test_emits_new_failure_once(tmp_path):
    client = Client([
        {"head": {"sha": "abc"}},
        {"workflow_runs": [{"id": 10, "name": "CI", "status": "completed", "conclusion": "failure", "run_number": 5}]},
        {"head": {"sha": "abc"}},
        {"workflow_runs": [{"id": 10, "name": "CI", "status": "completed", "conclusion": "failure", "run_number": 5}]},
    ])
    supervisor = CISupervisor(client, DurableSupervisorState(str(tmp_path / "state.json")))
    event = supervisor.poll("yanhul/AIOS", 22)
    assert event.next_action == "REPAIR"
    assert event.run_id == 10
    assert supervisor.poll("yanhul/AIOS", 22) is None


def test_success_emits_verify_merge(tmp_path):
    client = Client([
        {"head": {"sha": "def"}},
        {"workflow_runs": [{"id": 11, "name": "CI", "status": "completed", "conclusion": "success", "run_number": 6}]},
    ])
    event = CISupervisor(client, DurableSupervisorState(str(tmp_path / "state.json"))).poll("yanhul/AIOS", 22)
    assert event.next_action == "VERIFY_MERGE"
