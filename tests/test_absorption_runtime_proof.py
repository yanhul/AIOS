from research.absorption_runtime_proof import run

def test_absorption_runtime_proof():
    result = run()
    assert result["overall"] == "PASS"
    assert result["passed_count"] == result["total_count"] == 3
