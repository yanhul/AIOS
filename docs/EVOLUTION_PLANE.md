# Evolution Plane

The Evolution Plane proposes and evaluates changes without owning runtime authority.

## Boundary

```text
DISCOVERED
   -> CANDIDATE
   -> CHALLENGER
   -> EVALUATED
   -> PROMOTABLE
   -> ACTIVE
```

Terminal states are `ACTIVE`, `REJECTED`, and `BLOCKED`.

A candidate cannot jump directly to `ACTIVE`. Evaluation must carry:

- an evaluator digest identifying the evaluator contract;
- non-empty held-in evidence;
- non-empty held-out evidence;
- at least one durable evidence reference.

Promotion is deliberately an external authority operation. The candidate state
machine cannot authorize itself.

## Relationship to durable execution

The Evolution Plane sits above the existing durable execution loop:

```text
candidate/evolution
        |
        v
authority gate
        |
        v
contract -> effect -> attempt -> receipt -> verify -> persist/resume
```

The evolution layer must never bypass the Control Plane or turn an `UNKNOWN`
execution receipt into a successful promotion.

## Research mapping

For `try`, this maps to:

```text
hypothesis
  -> strategy candidate
  -> challenger
  -> IS evaluation
  -> validation gate
  -> OOS LOCKED evidence
  -> promotion authority
```

OOS evidence is evidence for admission, not input to candidate generation.

## Provenance rule

A child candidate carries `parent_id` and `lineage_depth`. Candidate state is
represented by immutable dataclass values; state transitions create a new value
instead of mutating an authoritative record in place.
