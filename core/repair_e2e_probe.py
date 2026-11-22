def repair_probe_value() -> str:
    """Temporary deterministic fault used only to verify the governed repair loop."""
    return "REPAIRED"

# E2E probe remains intentionally failing until the governed repair publishes a candidate.