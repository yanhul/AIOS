from pathlib import Path

import pytest

from core.capability_catalog import load_catalog


def test_catalog_loads_registered_capabilities_and_edges():
    registry = load_catalog("capabilities/registry.yaml")
    assert registry.get("try.research") is not None
    assert registry.get("android.assistant") is not None
    assert registry.get("rx50.engineering") is not None
    assert registry.get("minimind.model") is not None
    assert registry.get("software.audit") is not None


def test_catalog_edges_have_registered_endpoints():
    registry = load_catalog("capabilities/registry.yaml")
    for edge in registry.relationships():
        source_id, source_version = edge.source.rsplit("@", 1)
        target_id, target_version = edge.target.rsplit("@", 1)
        assert registry.get(source_id, source_version) is not None
        assert registry.get(target_id, target_version) is not None


def test_aios_local_manifests_exist():
    registry_path = Path("capabilities/registry.yaml")
    registry_text = registry_path.read_text(encoding="utf-8")
    assert "manifest: adapters/minimind/workload.json" in registry_text
    assert "manifest: external/skill/authorized-artifact-auditor/workload.json" in registry_text
    assert Path("adapters/minimind/workload.json").is_file()
    assert Path("external/skill/authorized-artifact-auditor/workload.json").is_file()


def test_missing_aios_local_manifest_fails_closed(tmp_path):
    catalog = tmp_path / "registry.yaml"
    catalog.write_text(
        """schema_version: 1\nstatus: normative\ncapabilities:\n"
        "  - capability_id: broken\n"
        "    version: \"1\"\n"
        "    kind: test\n"
        "    owner: test/test\n"
        "    manifest: adapters/missing/workload.json\n"
        "relationships: []\n""",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="missing AIOS-local manifest"):
        load_catalog(catalog)
