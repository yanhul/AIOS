# AIOS — AI Operating System

AIOS is an external orchestration and state layer for engineering projects.

## Position

1. **AIOS is an external orchestration/state layer.** It does not replace or own any project source.
2. **RX50 remains an independent engineering repository.** RX50 continues to be managed under its own rules (`E:\Projects\RX50\AGENTS.md`).
3. **AIOS does not own RX50 source files.** AIOS references RX50 by path only.
4. **AIOS state and RX50 source are separate.** AIOS keeps AIOS-side state under `projects/RX50/.aios/`; RX50 files are never copied, moved, or rewritten by AIOS.
5. **RX50 is the first AIOS integration project.**
6. **M1 is implemented** (inspection, provenance-preserving import, cross-file contradiction detection, immutable snapshots) and **M1.5 writer enforcement** (single validated mutation boundary `core/mutation.py`: entity contracts, undefined-transition rejection, mandatory actor, deterministic SHA-256 event IDs, atomic entity+event commit with roll-forward recovery). Still absent: state-machine transitions (M2), gates, policy, verification, agents.

## Layout

```
AIOS/
    core/
        state/      # future state model + validation (docs only)
        tasks/      # future task lifecycle
        agents/     # future agent roles (specs only)
        policy/     # future policy/permission rules
        evidence/   # future evidence pipeline
        gates/      # future gate evaluation
    adapters/
        openclaw/   # future runtime adapter boundary (docs only)
    models/         # future model registry (docs only)
    projects/
        RX50/       # AIOS-side metadata + .aios state dirs (empty)
    tests/          # future test suites (docs only)
    cli/            # future CLI (empty)
    docs/           # architecture, roadmap, state model, agent spec
```

See `docs/ARCHITECTURE.md`, `docs/STATE_MODEL.md`, `core/agents/AGENTS_SPEC.md`, `docs/ROADMAP.md`.

## Rules

- Zero runtime dependencies. No packages installed, no virtual environments, no credentials.
- AIOS never mutates `E:\Projects\RX50`.
- All future state transitions must be validated and auditable.
