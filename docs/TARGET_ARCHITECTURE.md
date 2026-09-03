# AIOS Target Architecture

Status: TARGET / normative architecture for post-M2 development.

This document defines the direction for AIOS as an AI Operating System. It does not claim that all target components are implemented.

## 1. Mission

AIOS turns a human problem into a governed, durable, verifiable execution process and a reusable outcome:

`Problem -> Contract -> Discover -> Plan -> Execute -> Observe -> Verify -> Reconcile -> Promote/Block -> Persist -> Reuse/Evolve`

AIOS is not a model and not a single agent. It is the control, capability, evidence, state, and orchestration layer around agents, tools, software, devices, and physical-world workloads.

## 2. Two-plane architecture

### Governance / Control Plane

AIOS owns:

- problem intake and contract
- policy and authority
- task lifecycle and durable state
- evidence requirements and provenance
- contradiction detection/reconciliation
- verification records
- promotion gates and terminal conditions
- audit/event history
- capability registration and trust metadata
- capability/version promotion

Agents MUST NOT modify governing policy, evidence requirements, promotion criteria, budgets, or terminal conditions.

### Capability / Workload Plane

External or registered capabilities perform work:

- research (`try`)
- software/Android (`android-ai-assistant`)
- hardware engineering (`RX50`)
- future agents, tools, simulators, devices, services, and physical interfaces

A workload remains independently owned. AIOS governs the interaction through an explicit contract and adapter boundary.

## 3. Core objects

Every registered capability has an identity and machine-readable contract:

- `capability_id`
- version
- owner/source
- input/output contract
- required permissions
- execution environment/context
- verification methods
- evidence requirements
- provenance
- reliability/history
- dependencies
- relationships to other capabilities

The registry should evolve into a **Capability Graph**, where nodes are capabilities and edges record observed, verified relationships such as `requires`, `produces`, `composes_with`, `validated_by`, and `works_under`.

## 4. Evidence and experience graph

AIOS stores more than conversation memory. It records:

`task -> capability -> action -> evidence -> verification -> result -> contribution -> relationship -> capability version`

Experience is reusable only when provenance and verification permit reuse. Failed, blocked, and contradictory experiences are retained as negative evidence rather than erased.

## 5. Context

Execution context is first-class:

- task/problem context
- user/operator context
- agent identity
- device/software environment
- permissions/authority
- network/resources
- time/version
- physical location and hardware state where applicable

A capability match must consider context, not only semantic similarity.

## 6. Durable execution loop

All autonomous workloads follow:

`OBSERVE -> DECIDE/PLAN -> ACT -> VERIFY -> PERSIST STATE -> RESUME`

A retry may continue only inside the fixed governing policy. Interruption, crash, timeout, or partial execution must leave recoverable state.

## 7. Verification levels

AIOS distinguishes at least:

- `OBSERVED` — observed from a source/runtime
- `EVIDENCED` — supported by recorded evidence
- `VERIFIED_DIGITAL` — passed applicable deterministic/test verification
- `VERIFIED_PHYSICAL` — validated against physical-world observations where applicable
- `PROMOTED` — accepted by the governing gate for reuse/release

Verification never upgrades an item merely because an agent asserted it.

## 8. Evolution

A capability may propose a new version from accumulated experience:

`existing version -> candidate version -> evaluation -> regression -> evidence review -> promotion gate -> active version`

Self-modification cannot directly promote itself.

## 9. Interoperability

AIOS should expose stable contracts for agent-to-agent, agent-to-tool, agent-to-device, and agent-to-service invocation. The protocol layer must carry identity, capability declaration, authorization, context, invocation, result, and provenance.

The implementation may adopt or interoperate with emerging agent-interconnection standards; protocol choice must not weaken AIOS authority and verification boundaries.

## 10. Physical-world extension

AIOS is designed to extend from digital execution to devices, sensors, robots, laboratories, and other physical systems. Digital verification and physical verification remain distinct evidence classes.

## 11. Target end state

A user should be able to submit a problem in natural language. AIOS should be able to:

1. normalize it into a contract;
2. identify missing requirements/evidence;
3. discover suitable capabilities;
4. compose and execute a bounded plan;
5. observe and persist every meaningful state change;
6. verify outputs and search for contradictions;
7. repair/replan within policy when allowed;
8. produce artifacts, evidence, provenance, and verification records;
9. terminate with `PASS`, `BLOCKED`, or `INCONCLUSIVE` under externally governed criteria;
10. reuse verified experience without silently importing unverified assumptions.

## 12. Four-repository integration

The repositories are capability domains, not four competing control planes:

- `AIOS`: governance, state, authority, evidence, verification, orchestration, capability registry/graph.
- `try`: research capability/workload.
- `android-ai-assistant`: software/device-agent capability/workload.
- `RX50`: hardware-engineering capability/workload.

Each workload remains independently testable and source-owned. AIOS owns the cross-workload contract and governance boundary.

## 13. Definition of Done for AIOS v1

AIOS v1 is complete when at least three independent workload classes can execute the governed loop end-to-end and demonstrate:

- contract intake
- bounded autonomous execution
- capability discovery/registration
- evidence and provenance
- deterministic or explicitly scoped verification
- contradiction handling
- durable resume
- tamper/authority resistance
- promotion gating
- PASS/BLOCKED/INCONCLUSIVE terminal states
- reusable versioned capability history

This is a proof-of-system criterion, not a claim of general AGI or universal correctness.
