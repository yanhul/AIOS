from research.absorbed_capabilities import run_conformance


def test_absorbed_capability_implementations_conform():
    result = run_conformance()
    assert result["overall"] == "PASS"
    assert result["implemented_count"] == result["total_count"]
    assert result["total_count"] == 7
