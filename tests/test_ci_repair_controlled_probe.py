from core.ci_repair_controlled_probe import controlled_probe


def test_controlled_probe_is_repaired() -> None:
    assert controlled_probe() == "REPAIRED"
