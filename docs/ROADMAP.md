# AIOS Roadmap

Status: M1 + M1.5 implemented. M2+ below is FUTURE work — none implemented.

## M0 — Bootstrap scaffold (DONE, scaffold only)

- External AIOS directory at `E:\Projects\AIOS`.
- `projects/RX50/project.yaml` referencing the actual RX50 repository.
- Empty `.aios/` state directories (requirements, decisions, evidence, issues, tasks, snapshots, events).
- Documentation only: architecture, state model, agent spec, project README, models README, OpenClaw README, tests README.
- Zero runtime dependencies. No packages, no credentials, no API calls.

## M1 — State inspection + controlled RX50 state import (DONE)

- Inspect authoritative RX50 registers, import-map to AIOS entity types WITHOUT mutating RX50.
- Import only into AIOS `.aios/` dirs; RX50 unchanged.
- NOTE: the human-reconciliation step for uncertain provenance is still NOT implemented; imports commit directly through the M1.5 boundary.

## M1.5 — Writer enforcement (DONE)

- Single authoritative mutation boundary: `core/mutation.py::apply_mutations`.
- Entity contracts per type (required fields, ID formats, structural status rules); unknown types and malformed entities fail loudly; unknown types are never silently dropped.
- Transition legality: creation and byte-identical replay only; ANY change to a committed entity is rejected as an UNDEFINED transition (no transition rules are invented before M2).
- Mandatory actor identity on every mutation event.
- Deterministic content-derived event IDs: SHA-256 over canonicalized event values (full digest; no Python `hash()`).
- Atomic entity+event commit: staged temps -> write-ahead journal -> atomic renames, with roll-forward recovery (`recover_pending`) on every mutation entry.
- Consecutive snapshots with changed provenance (new snapshot_id) are rejected as undefined transitions by design until M2 defines refresh semantics.

## M2 — Authority / verification foundation (PARTIALLY DONE)

- DONE: snapshot semantics OBSERVED/COMMITTED derived from the audit log (snapshots immutable; failed/rejected mutations stay OBSERVED).
- DONE: machine-checkable reconciliation (`core/reconcile.py`): entity/event pairing, digest mismatches, committed-snapshot references, staging/journal state, foreign schemas. Detection only — no auto-repair.
- DONE: AIOS-native verification records (`core/verification.py`): append-only attempts, outcome computed by resolving evidence refs against persisted EVIDENCE entities; missing/dangling refs can never yield VERIFIED; every record paired with an auditable event through the shared atomic kernel.
- DONE: authority separation: imported register status text ("RX50 says X") is never treated as AIOS verification ("AIOS determined Y from evidence E").
- NOT DONE: general entity status-transition table (M2 scope kept deliberately absent), gates, policy, contradiction resolution, agents.

## M2 legacy placeholder (superseded by the section above)

Entity schema (requirement, decision, assumption, evidence, issue, task, artifact, gate, event).
Validated, auditable transitions (FACT / ASSUMPTION / DECISION / VERIFIED).
No silent class promotion.

## M3 — Importer + context builder (PARTIALLY DONE)

- DONE (M3 minimal, detection only): source/store divergence detection —
  `reconcile(aios_dir, source_root=...)` re-derives entities through the
  existing read-only import pipeline and reports `H.source_divergence.{added,
  changed,missing,ambiguous}` findings. Neither side is ever mutated; no
  audit event is created for divergence; repair does not exist.
- Refresh posture: a new source observation produces a new OBSERVED snapshot
  plus divergence findings for human review. Provenance-changing re-imports
  remain REJECTED under M1.5 transition semantics (`TransitionError`).
  Automatic refresh/overwrite of the entity store does not exist.
- REMAINING: deterministic importer hardening (duplicate register IDs across
  files currently abort batches via entity contracts) and context assembly
  from AIOS state.

## M4 — Agents

- Role specs (explorer, engineer, critic, verifier, gatekeeper) become real, permission-scoped agents.

## M5 — Model routing

- Model registry with capability-based routing. No keys or credentials stored in repo.

## M6 — OpenClaw adapter

- AIOS task → OpenClaw adapter → runtime → tools → structured result → AIOS validation.

## M7 — CLI + automation

- CLI surface and optional autonomous execution under policy.

## Policy

- RX50 is read-only to AIOS at all milestones.
- No invention of state; no fabricated tests; every import logged.
