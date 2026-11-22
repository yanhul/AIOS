from core.repair_e2e_probe import repair_probe_value


def test_governed_repair_probe():
    assert repair_probe_value() == "REPAIRED"
