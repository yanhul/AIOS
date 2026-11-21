import os

import pytest

from core.authority import load_attestation, load_contract, load_permit
from core.mutation import TransitionError


@pytest.mark.parametrize("loader,name", [
    (load_contract, "contract_id"),
    (load_permit, "permit_id"),
    (load_attestation, "permit_id"),
])
@pytest.mark.parametrize("identifier", ["../outside", "x", "CT-" + "A" * 64, "PT-" + "g" * 64])
def test_authority_loaders_reject_noncanonical_identifiers(tmp_path, loader, name, identifier):
    with pytest.raises(ValueError, match="canonical identifier"):
        loader(str(tmp_path), identifier)


def test_authority_loader_rejects_symlinked_record_directory(tmp_path):
    authority = tmp_path / "authority"
    authority.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (authority / "permits").symlink_to(outside, target_is_directory=True)

    with pytest.raises(TransitionError, match="directory must not be symlinked"):
        load_permit(str(tmp_path), "PT-" + "a" * 64)


def test_authority_loader_rejects_symlinked_record_file(tmp_path):
    permits = tmp_path / "authority" / "permits"
    permits.mkdir(parents=True)
    outside = tmp_path / "outside.json"
    outside.write_text('{"sensitive":"outside"}', encoding="utf-8")
    (permits / ("PT-" + "a" * 64 + ".json")).symlink_to(outside)

    with pytest.raises(TransitionError, match="record must not be symlinked"):
        load_permit(str(tmp_path), "PT-" + "a" * 64)
