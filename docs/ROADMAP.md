# AIOS Roadmap

Status: M1 + M1.5 implemented; parts of M2/M3 implemented. This roadmap separates implemented foundation from the target architecture in `docs/TARGET_ARCHITECTURE.md`.

## Phase A — Governance kernel

### M0 — Bootstrap scaffold (DONE)
- External AIOS project structure.
- Project references without copying or owning workload source.
- Architecture/state/agent specifications.
- Zero runtime credentials/dependencies by default.

### M1 — State inspection + controlled import (DONE)
- Inspect authoritative workload registers.
- Import into AIOS-side state without mutating workload repositories.
- Preserve provenance.

### M1.5 — Writer enforcement (DONE)
- Single validated mutation boundary.
- Entity contracts and malformed-state rejection.
- Mandatory actor identity.
- Deterministic event IDs.
- Atomic entity+event commit and recovery.
- Undefined transitions rejected until explicitly modeled.

### M2 — Authority / verification foundation (PARTIALLY DONE)
- Immutable snapshot/audit semantics.
- Machine-checkable reconciliation.
- Append-only verification records.
- Evidence-reference resolution; missing evidence cannot produce VERIFIED.
- Authority separation between imported source claims and AIOS verification.
- Remaining: general transition table, policy engine, gates, contradiction resolution workflow, agent execution.

### M3 — Import/context (PARTIALLY DONE)
- Source/store divergence detection.
- OBSERVED snapshot + findings without automatic repair.
- Remaining: importer hardening and deterministic context assembly.

## Phase B — AIOS capability operating system

### M4 — Capability identity + registry
- Stable `capability_id` and version contracts.
- Capability input/output, permissions, environment, evidence and verification metadata.
- Register agents, tools, software workloads, devices and services.
- Capability trust/history derived from evidence, not arbitrary ratings.

### M5 — Capability graph
- Relationship edges: `requires`, `produces`, `composes_with`, `validated_by`, `works_under`.
- Record verified composition history.
- Use graph evidence for capability discovery and planning.

### M6 — Contract/policy/task engine
- Natural-language problem intake -> machine-checkable contract.
- Explicit requirements, constraints, evidence requirements, acceptance criteria and forbidden assumptions.
- Agent cannot change governing policy, evidence requirements, promotion criteria, budget or terminal conditions.

### M7 — Agent/runtime adapters
- Role-scoped explorer/engineer/critic/verifier/gatekeeper.
- Stable runtime adapter contract.
- Model registry and capability-based routing.
- OpenClaw and other runtimes remain adapters, not the authority layer.

## Phase C — Autonomous execution

### M8 — Durable closed loop
`OBSERVE -> DECIDE/PLAN -> ACT -> VERIFY -> PERSIST -> RESUME`

- Bounded retries.
- Crash/interruption recovery.
- External-effect state machine.
- Structured execution results.
- No silent state promotion.

### M9 — Evidence / contradiction / promotion
- Evidence graph and provenance.
- Contradiction search and explicit resolution workflow.
- Verification levels: OBSERVED, EVIDENCED, VERIFIED_DIGITAL, VERIFIED_PHYSICAL, PROMOTED.
- Fixed PASS/BLOCKED/INCONCLUSIVE gates.

### M10 — Experience / contribution / relationship memory
- Record task -> capability -> action -> evidence -> result lineage.
- Measure contribution/utility from verified outcomes.
- Preserve negative evidence and failure history.
- Learn capability relationships without treating model memory as truth.

### M11 — Capability evolution
- Candidate capability/version generation.
- Regression and comparative evaluation.
- Evidence review and promotion gate.
- Versioned rollback.
- No self-promotion.

## Phase D — Real-world AIOS

### M12 — Context and physical-world interfaces
- Device, software, network, time, permission and physical context as first-class inputs.
- Device/sensor/robot/lab adapters.
- Separate digital vs physical verification.
- Physical observations feed the evidence/experience loop.

### M13 — Interoperable agent network
- Agent-to-agent, agent-to-tool, agent-to-device and agent-to-service contracts.
- Identity, capability discovery, authorization, context, invocation, result and provenance.
- Interoperate with emerging agent-interconnection standards without weakening AIOS governance.

## Proof-of-system workloads

The four repositories are intentionally different:

- `AIOS` — control/governance/capability plane.
- `try` — autonomous research and strategy-evaluation workload.
- `android-ai-assistant` — software + device-agent workload.
- `RX50` — hardware-engineering + physical-evidence workload.

The objective is not to merge their source trees. The objective is to make them registered, governed capabilities of one AIOS while preserving independent ownership.

## AIOS v1 Definition of Done

Do not declare v1 complete because CI is green or because the control repository contains many modules.

Declare v1 complete only when three independent workload classes demonstrate end-to-end:

`natural-language problem -> contract -> capability discovery -> bounded execution -> evidence -> verification -> reconciliation -> artifact -> provenance -> promotion/blocked terminal state -> durable resume/reuse`.

Required terminal outcomes are fixed: `PASS`, `BLOCKED`, `INCONCLUSIVE`.

## Permanent invariants

- No fabricated evidence, measurements, tests, or specifications.
- No silent promotion of assumptions/observations into facts or verification.
- No agent-controlled governing policy or terminal criteria.
- No uncontrolled autonomous retry loop.
- Workload source remains independently owned.
- Every material state mutation is auditable and recoverable.
- Verification claims must resolve to evidence or deterministic checks appropriate to the claim.
