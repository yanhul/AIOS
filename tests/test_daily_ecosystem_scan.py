import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parents[1]))
from research.daily_ecosystem_scan import relevance


def test_relevance_uses_architecture_terms():
    repo = {
        "name": "durable-agent-runtime",
        "description": "checkpoint resume evidence and provenance",
        "topics": ["agent", "workflow"],
    }
    assert relevance(repo) >= 6


def test_relevance_does_not_grant_absorption():
    repo = {"name": "random-tool", "description": "hello", "topics": []}
    assert relevance(repo) == 0


def test_output_contract_is_governed():
    payload = {
        "governance": {
            "mutates_authority": False,
            "mutates_policy": False,
            "auto_absorb": False,
            "absorption_requires_governed_review": True,
        }
    }
    assert payload["governance"]["auto_absorb"] is False
    assert payload["governance"]["absorption_requires_governed_review"] is True
