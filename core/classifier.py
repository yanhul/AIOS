"""Heuristic classification of discovered artifacts.

Classification is conservative: filename and content evidence is scored and
the strongest supported category is chosen. When evidence is absent or ties,
the artifact is classified UNKNOWN rather than guessed.
"""

import re
from typing import Tuple

UNKNOWN = "UNKNOWN"

CATEGORIES = {
    "REQUIREMENT",
    "DECISION",
    "ASSUMPTION",
    "EVIDENCE",
    "ISSUE",
    "ARTIFACT",
    "REPORT",
    "GATE",
    "INSTRUCTION",
    UNKNOWN,
}

# (regex on relative path/filename, category) — ordered, first match wins.
# Matching is case-insensitive: register filenames use mixed case
# (DECISION_REGISTER.md etc.), and matching against a lowercased path
# previously made every uppercase rule unmatchable (dead code).
# The blanket r"\.md$" -> REPORT fallback was removed: it fired before
# content scoring and masked ambiguity, contradicting the classifier's own
# contract (unclassifiable .md must come out UNKNOWN).
_FILENAME_RULES = [
    (r"(^|/)(AGENTS\.md)$", "INSTRUCTION"),
    (r"(^|/)(README[^/]*\.md)$", "INSTRUCTION"),
    (r"(^|/)RX50_G1_G2_REQUIREMENT_CLOSURE\.md$", "REQUIREMENT"),
    (r"(^|/)RX50_G1_OWNER_REQUIREMENT_FILL_SHEET\.md$", "REQUIREMENT"),
    (r"(^|/)RX50_G1_REQUIREMENTS_ELICITATION_PLAN\.md$", "REQUIREMENT"),
    (r"(^|/)(DECISIONS\.md|DECISION_REGISTER\.md)$", "DECISION"),
    (r"(^|/)(OPEN_ISSUES\.md)$", "ISSUE"),
    (r"EVIDENCE_REGISTER\.md$", "EVIDENCE"),
    (r"(^|/)RX50_G4_OWNER_DECISION_SHEET\.md$", "DECISION"),
    (r"(^|/)RX50_G4_TOPOLOGY_DECISION_RECORD\.md$", "DECISION"),
    (r"CONTRADICTION_REGISTER\.md$", "ISSUE"),
    (r"(^|/)RX50_SCHEMATIC_RELEASE_GATE\.md$", "GATE"),
    (r"(^|/)RX50_SCHEMATIC_ARCHITECTURE_LOCK\.md$", "GATE"),
    (r"(^|/)RX50_G4_CLOSURE_REPORT\.md$", "REPORT"),
    (r"(^|/)RX50_G4_G5_CLOSURE_AUDIT\.md$", "REPORT"),
    (r"(^|/)RX50_G5_PIN_MAP_FINAL\.md$", "ARTIFACT"),
    (r"^calculations/", "ARTIFACT"),
    (r"^measurements/", "ARTIFACT"),
    (r"^harness/templates/", "ARTIFACT"),
    (r"^harness/state/", "ARTIFACT"),
    (r"^harness/missions/", "ARTIFACT"),
    (r"^harness/reports/", "ARTIFACT"),
    (r"^harness/open_issues/", "ARTIFACT"),
    (r"\.txt$", "ARTIFACT"),
]

# Content keyword scoring used only when filename rules are not decisive.
_CONTENT_RULES = [
    ("REQUIREMENT", ["requirement", "g1 owner requirement", "required owner input"]),
    ("DECISION", ["decision", "owner-approved", "locked"]),
    ("ISSUE", ["open issue", "oi-", "contradiction"]),
    ("EVIDENCE", ["evidence", "verified", "datasheet"]),
    ("GATE", ["gate", "blocked", "hold"]),
    ("ASSUMPTION", ["assumption", "[assumption]"]),
    ("REPORT", ["report", "audit"]),
]


def classify_file(relative_path: str, filename: str, content: str) -> Tuple[str, float, str]:
    """Return (category, confidence, basis) for a discovered artifact."""
    # Filename rules match on the original path, case-insensitively.
    for pattern, category in _FILENAME_RULES:
        if re.search(pattern, relative_path.replace("\\", "/"), re.IGNORECASE):
            return category, 0.9, f"filename:{pattern}"

    # Content-based scoring as fallback.
    scores = {c: 0 for c, _ in _CONTENT_RULES}
    low = content.lower()
    for category, keywords in _CONTENT_RULES:
        for kw in keywords:
            scores[category] += low.count(kw)

    best = max(scores, key=scores.get)
    if scores[best] == 0:
        return UNKNOWN, 0.0, "no-filename-rule-no-content-match"
    # Tie between top two -> ambiguous.
    ordered = sorted(scores.values(), reverse=True)
    if len(ordered) >= 2 and ordered[0] == ordered[1]:
        return UNKNOWN, 0.0, "content-score-tie"
    return best, 0.6, "content-keywords"
