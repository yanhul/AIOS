# AIOS State Model

Status: M0 — documentation only. The state engine is NOT implemented.

## 1. Entity types (future)

AIOS will record these entity types per project:

| Entity | Meaning (documented intent) |
|--------|-----------------------------|
| requirement | A stated need or constraint the project must satisfy. Sourced from owner/requirements files, never invented. |
| decision | An approved choice (who/what/when + provenance). Distinct from a proposal. |
| assumption | A working placeholder that is NOT verified. Must be labeled as such. |
| evidence | A fact or artifact traceable to a source (datasheet, measurement, register). |
| issue | An open problem, blocker, or contradiction to be resolved. |
| task | A unit of work with status and lifecycle. |
| artifact | A file or deliverable the project produces. |
| gate | A review point with a decision outcome and required evidence. |
| event | An auditable record of a state transition or external action. |

## 2. Class distinction

```
FACT        ≠  ASSUMPTION   ≠  DECISION   ≠  VERIFIED
measured        unverified      approved       checked against
or directly     placeholder     choice         evidence
sourced
```

- A **FACT** is a measurement or directly sourced value.
- An **ASSUMPTION** is an unverified placeholder and must remain labeled.
- A **DECISION** is an approved choice with provenance (who, when, basis).
- **VERIFIED** is a status: the item was checked against required evidence.
- These four classes are NOT interchangeable. AIOS must never silently promote e.g. an assumption to a fact, or a derived value to a measured value.

## 3. Transition rules (documented intent)

- Every state transition must record: entity id, previous class/status, new class/status, basis, actor, timestamp.
- Transitions are **validated** (must be legal per the model) and **auditable** (reconstructible from the event log).
- Unsupported transitions are rejected, not silently coerced.
- No entity may be created, changed, or deleted without an auditable event.

## 4. Relationship to RX50

- RX50 already maintains authoritative registers (EVIDENCE_REGISTER, DECISION_REGISTER, OPEN_ISSUES, CONTRADICTION_REGISTER, project_state). AIOS will import and reflect those sources; it does not invent or supersede them.
- Any divergence between AIOS state and RX50 registers is itself a first-class event/issue.
- OBSERVED means "source observation": it is NOT committed AIOS state. Only a
  successful mutation transaction (its paired notice in the audit log) makes a
  snapshot COMMITTED.
- Source/store divergence is a first-class DETECTION finding
  (`core/reconcile.py`, check family `H.source_divergence.*`). Detection never
  repairs, never refreshes, and never writes an audit event by itself.
- Refresh does NOT automatically mutate the entity store. The M3 flow is:
  new observation → OBSERVED snapshot → divergence findings → human review →
  explicit future mutation workflow.
- Provenance-changing re-import remains rejected under M1.5 transition
  semantics: any content difference against a committed entity raises
  `TransitionError` (UNDEFINED). This is deliberate; no RX50 status
  transition table exists.
- Human/operator review is required before any future state transition;
  AIOS records and detects but does not decide.
- M3 does not resolve contradictions, make decisions, or authorize actions;
  imported DECISION/GATE fields stay observations of RX50's own registers.
