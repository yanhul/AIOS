# AIOS — AI Operating System

AIOS is the governed control, state, evidence, capability, and orchestration layer around autonomous AI workloads.

## Mission

AIOS turns a human problem into a durable, verifiable execution process and a reusable outcome:

`Problem -> Contract -> Discover -> Plan -> Execute -> Observe -> Verify -> Reconcile -> Promote/Block -> Persist -> Reuse/Evolve`

AIOS is not a model and not a single agent. It governs agents, tools, software, devices, services, and physical-world workloads while keeping workload source independently owned.

## Architecture

- **Governance / Control Plane:** contract, authority, policy, durable state, evidence, provenance, contradiction handling, verification, gates, audit history, capability registration and promotion.
- **Capability / Workload Plane:** registered agents, tools, research, software, hardware, devices and services.
- **Capability Graph:** evidence-bound relationships between capabilities; relationships are never assumed merely because two capabilities exist.
- **Experience / Evolution:** verified task-to-capability history, negative evidence, versioned candidate capabilities and governed promotion.
- **Context:** task, identity, device/software, permissions, resources, time, location and physical state are first-class execution inputs.

See `docs/TARGET_ARCHITECTURE.md` for the normative target and `docs/ROADMAP.md` for implementation status. See `docs/HARNESS_REFERENCE.md` for the Claude Code/Jarvis-style durable-harness boundary adopted by AIOS.

## Proof-of-system workloads

The four repositories are deliberately independent:

- `AIOS` — control, governance and capability plane.
- `try` — autonomous research and strategy-evaluation workload.
- `android-ai-assistant` — software/device-agent workload.
- `RX50` — hardware-engineering and physical-evidence workload.

AIOS references and governs workloads; it does not copy, merge, or silently rewrite their source.

Initial workload registrations live in `capabilities/registry.yaml`.

## Safety / governance invariants

- No fabricated evidence, measurements, tests, or specifications.
- No silent promotion of assumptions or observations into facts or verification.
- Agents cannot modify governing policy, evidence requirements, promotion criteria, budgets, or terminal conditions.
- Autonomous retries are bounded by external policy.
- Every material state mutation is auditable and recoverable.
- Verification claims must resolve to evidence or deterministic checks appropriate to the claim.
- Digital verification and physical verification remain distinct.

## Current implementation

The repository contains the M1/M1.5 state and mutation foundation plus implemented authority, verification, reconciliation, contract, runtime and durable-execution components. A dependency-free governed durable loop is now implemented in `core/durable_loop.py` with coverage for bounded execution, persistence, terminal gating and resume. Capability identity/registry and first-class execution context are now established as the next control-plane foundation; capability-graph persistence, full task orchestration and end-to-end cross-repository execution remain governed implementation work.
