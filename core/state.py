"""AIOS per-project state directory layout.

This module owns the on-disk LAYOUT of ``.aios/<type>/`` only. It performs
no entity or event writes: every state mutation MUST go through the
authoritative boundary in :mod:`core.mutation` (or its shared atomic commit
primitive).
"""

import os

from .secure_fs import secure_makedirs_beneath

STATE_DIRS = [
    "requirements",
    "decisions",
    "evidence",
    "issues",
    "tasks",
    "verifications",
    "snapshots",
    "events",
]

ENTITY_TO_DIR = {
    "REQUIREMENT": "requirements",
    "DECISION": "decisions",
    "EVIDENCE": "evidence",
    "ISSUE": "issues",
    "GATE": "issues",
    "CONTRADICTION": "issues",
}


def ensure_state_dirs(project_aios_dir):
    """Create the standard .aios state directories; returns their paths.

    Uses descriptor-relative, no-follow creation (core.secure_fs): ancestors
    of ``project_aios_dir`` are trusted (created by pathname if missing);
    a symlinked/non-directory state root or state subdirectory, or one not
    owned by the effective uid / group- or world-writable, is refused with
    SecureWriteError. There is no pathname ``os.makedirs`` fallback; on
    non-POSIX platforms this fails closed (UnsupportedPlatformError).
    """
    created = []
    for name in STATE_DIRS:
        secure_makedirs_beneath(project_aios_dir, name)
        created.append(os.path.join(project_aios_dir, name))
    return created
