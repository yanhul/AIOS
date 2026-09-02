"""AIOS per-project state directory layout.

This module owns the on-disk LAYOUT of ``.aios/<type>/`` only. It performs
no entity or event writes: since M1.5 every state mutation MUST go through
the authoritative boundary in :mod:`core.mutation` (``apply_mutations``).
"""

import os

STATE_DIRS = [
    "requirements",
    "decisions",
    "evidence",
    "issues",
    "tasks",
    "verifications",   # AIOS-native verification attempt records (M2)
    "snapshots",
    "events",
]

ENTITY_TO_DIR = {
    "REQUIREMENT": "requirements",
    "DECISION": "decisions",
    "EVIDENCE": "evidence",
    "ISSUE": "issues",
    "GATE": "issues",      # gates recorded alongside issues for visibility
    "CONTRADICTION": "issues",
}


def ensure_state_dirs(project_aios_dir):
    """Create the standard .aios state directories; returns their paths."""
    created = []
    for name in STATE_DIRS:
        d = os.path.join(project_aios_dir, name)
        os.makedirs(d, exist_ok=True)
        created.append(d)
    return created
