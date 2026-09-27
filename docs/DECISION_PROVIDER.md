# AIOS Decision Provider Boundary

Absorbed primitive from compact non-generative decision-model architectures.

## Contract

AIOS may ask a provider to evaluate a runtime-defined candidate set. The
provider returns a typed, immutable DecisionResult.

Supported decision modes are:

- choice: select one candidate when the provider can decide.
- score: return ordinal/numeric scores for policy evaluation.
- boolean: represent a two-way decision using the same candidate contract.

The provider may return ABSTAINED or INCONCLUSIVE; these are not failures
and are never silently converted into a selection.

## Governance boundary

DecisionResult is advisory. It is not:

- authority or permission;
- execution;
- verification;
- authoritative evidence;
- a memory-write instruction.

Intended path:

DecisionRequest -> DecisionProvider -> DecisionResult -> deterministic
policy/evidence gate -> authority -> permit -> effect -> attempt -> receipt -> evidence

Model probabilities are preserved as distribution data. They are not treated
as calibrated confidence unless an explicit calibration_ref exists and the
downstream policy accepts it.

## Absorption gate

| Primitive | Decision |
|---|---|
| Runtime-defined candidates | ABSORB |
| Provider boundary | ABSORB |
| Distribution / scores | ABSORB |
| Calibration metadata | ABSORB |
| Abstention / INCONCLUSIVE | ABSORB |
| Pinned provider revision + input hash | ABSORB |
| Julia-1 model weights | REJECT |
| Provider output -> authority | REJECT |
| Provider output -> evidence | REJECT |
| Probability -> trusted confidence by default | REJECT |

No Julia-1 weights or runtime dependency are introduced by this change.
