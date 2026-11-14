from pathlib import Path

import pytest

from scripts.ci_repair_apply_attempt import authority as apply_authority
from scripts.ci_repair_publish import authority as publish_authority


@pytest.mark.parametrize("authority_fn", [apply_authority, publish_authority])
def test_repair_authority_fails_closed_without_external_issuer(authority_fn, tmp_path):
    with pytest.raises(SystemExit, match="external AIOS authority issuer/store is not provisioned"):
        authority_fn(Path(tmp_path), "ci-repair-worker", 12345)

# Keep this gate test in the full-suite CI contract.
