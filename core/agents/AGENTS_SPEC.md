# AIOS Agent Roles — Specification Placeholders

Status: M0 — specifications ONLY. No agents are implemented, connected to models, or run.

## Planned roles

| Role | Documented responsibility (future) |
|------|------------------------------------|
| explorer | Read-only discovery: inspect repositories/registers, report findings without mutation. |
| engineer | Perform approved work under policy; produce artifacts with provenance. |
| critic | Challenge proposals/evidence; surface conflicts rather than resolving silently. |
| verifier | Check claims against required evidence; no "verified" claims without evidence. |
| gatekeeper | Enforce gates: evaluate required evidence and approve/deny transitions. |

## Principles

- Roles are permission-scoped (explorer = read-only, etc.).
- No role may invent facts, decisions, or evidence.
- No role may silently choose a winner between conflicting evidence.
- Role behavior must be specified before implementation.

Implementation, model wiring, and execution belong to M4+ (see `docs/ROADMAP.md`).
