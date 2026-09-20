import scripts.g4a_fixture


def test_g4a_fixture_imports_after_repair():
    assert scripts.g4a_fixture.VALUE == "FIXED"
