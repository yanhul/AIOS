# AIOS Architecture

Status: M1 implemented (read-only inspection/import/snapshot pipeline) plus M1.5 writer enforcement (`core/mutation.py` — the single validated mutation boundary). State-machine transitions, gates, policy, verification and agents remain future work (see docs/ROADMAP.md).

## 1. What AIOS is

AIOS is an external orchestration and state layer that manages engineering projects by reference. A project (e.g. RX50) remains an independent repository; AIOS keeps only AIOS-side metadata and state.

## 2. Core principle: source vs state separation

- **RX50 source**: `E:\Projects\RX50` — authoritative engineering files (reports, registers, missions, decisions, evidence). Owned by the RX50 repository and its rules.
- **AIOS state**: `E:\Projects\AIOS\projects\RX50\.aios\` — AIOS-side records (requirements, decisions, evidence, issues, tasks, snapshots, events). Created and owned by AIOS.
- The two trees are distinct. AIOS references the RX50 path via `projects/RX50/project.yaml`. AIOS never writes to, moves, copies, renames, or deletes RX50 files.

## 3. Reference model

- `project.yaml` (in `projects/RX50/`) is the only reference to the external repository. It contains the discovered actual path (`E:\Projects\RX50`).
- No RX50 content is duplicated inside AIOS.

## 4. Entity types (documented, not implemented)

Future state entities AIOS will record: `requirement`, `decision`, `assumption`, `evidence`, `issue`, `task`, `artifact`, `gate`, `event`. See `docs/STATE_MODEL.md`.

## 5. State model semantics

- `FACT` (measured or directly sourced) is distinct from `ASSUMPTION` (unverified placeholder), `DECISION` (approved choice), and `VERIFIED` (checked against evidence).
- Future transitions between these classes must be validated and auditable; AIOS does not silently promote one class to another.

## 6. Task → runtime boundary (future)

```
AIOS task
→ OpenClaw adapter
→ runtime
→ tools
→ structured result
→ AIOS validation
```

The adapter boundary is specified in `adapters/openclaw/README.md`. Not installed or configured in M0.

## 7. Roles (future)

Planned agent roles: `explorer`, `engineer`, `critic`, `verifier`, `gatekeeper`. Specs only — see `core/agents/AGENTS_SPEC.md`. No agents are implemented or connected.

## 8. Non-goals (M0)

No state engine, no importer, no CLI, no context builder, no agents, no model router, no OpenClaw adapter, no autonomous execution. These belong to later milestones (see `docs/ROADMAP.md`).
