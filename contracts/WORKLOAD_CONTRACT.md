# AIOS Workload Contract v1

This is the normative cross-repository boundary. Workload repositories are capability providers, not policy owners.

## Required identity

Each workload MUST expose exactly one active versioned capability reference:

`<capability_id>@<version>`

The reference MUST resolve in the AIOS Capability Registry before execution is authorized.

## Required contract flow

`Problem -> Contract -> Capability Resolve -> Authority/Permit -> Execute -> Observe -> Verify -> Reconcile -> Terminal -> Persist`

## Required contract fields

- `contract_type`
- `task_id`
- `scope`
- `actor`
- `capabilities`
- `input_digest`
- `allowed_effects`
- `evidence_required`
- `max_attempts`
- `terminal_states`
- `policy_digest`

`capabilities` MUST contain versioned references. A workload MUST NOT authorize an unregistered, deprecated, or unversioned capability.

## Invariants

1. AIOS is the authority boundary.
2. Workload code may execute only capabilities granted by the resolved contract/permit.
3. Workload agents cannot change policy, evidence requirements, promotion criteria, budgets, permissions, or terminal states.
4. Missing/invalid evidence produces `BLOCKED` or `INCONCLUSIVE`, never an implicit `PASS`.
5. Digital and physical verification remain distinct.
6. State is durable and resumable after interruption.
7. External effects require observable receipts and reconciliation before promotion.
8. Capability versions are immutable identities; evolution creates a new version and requires promotion by AIOS governance.

## Workload declaration

Each workload repository MUST publish `aios/workload.json` containing its canonical capability reference, owner repository, protocol version, and declared terminal states. This file is descriptive; activation remains governed by AIOS authority.
