# Evaluation Plane and Rollout Integrity

Status: NORMATIVE ARCHITECTURE / absorbed from observed MiMo-V2.6 RL design patterns.

This document records architecture and invariants that AIOS adopts from public MiMo evidence. It does not copy MiMo implementation details and does not imply that unpublished internals are known.

## 1. Plane separation

AIOS separates execution from evaluation:

`CONTRACT -> PERMIT -> EFFECT -> EXECUTE_ATTEMPT -> RECEIPT -> OBSERVATION -> EVALUATION -> DECISION`

The workload/harness performs execution. The evaluation plane consumes execution evidence and produces an evaluation record. Evaluation is not execution authority.

An evaluator MUST NOT directly dispatch an external effect. Any follow-up action still requires the normal AIOS authority chain.

## 2. Evaluation receipt

An evaluation MUST be represented as a durable, provenance-bound record containing at least:

- `evaluation_id`
- target `effect_id`
- target `attempt_id`
- target `receipt_id` where applicable
- evaluator identity/version
- evaluation policy/rubric version
- evidence references
- deterministic test results where applicable
- rubric/graded results where applicable
- verdict
- timestamp and provenance

An evaluation without resolvable target lineage is invalid for promotion or terminal decisions.

## 3. Evidence precedence

Raw execution evidence is authoritative. Evaluation is a derived interpretation of that evidence.

The following direction is forbidden:

`EVALUATION/PASS -> infer missing RECEIPT/EVIDENCE`

Required direction:

`VALID RECEIPT + RESOLVABLE EVIDENCE -> EVALUATION`

A grader cannot manufacture evidence for the workload it evaluates.

## 4. Fine-grained evaluation

Evaluation MAY contain multiple independently auditable components:

- test-case results;
- rubric dimensions;
- environment-specific checks;
- partial outcomes;
- attribution metadata.

A single scalar reward, score, or aggregate verdict is never by itself an authority grant or promotion decision.

## 5. Multi-harness boundary

AIOS may govern heterogeneous harnesses/environments through one stable contract boundary:

`AIOS CONTROL PLANE -> HARNESS ADAPTER -> EXECUTION ENVIRONMENT`

Harnesses remain workload/execution providers. They do not become a second control plane.

The common boundary MUST preserve identity, capability, authorization, context, invocation, result, evidence, and provenance.

## 6. Rollout / attempt identity

A retry is a new execution attempt, not a rewritten version of the previous attempt.

Every evaluation MUST bind to the exact attempt and receipt it evaluates. Implementations MUST NOT reconstruct a successful-looking trajectory from later state and attach it to an earlier attempt.

The durable chain is:

`effect_id -> attempt_id -> receipt_id -> evaluation_id`

Any missing or mismatched binding is `BLOCKED`/invalid for downstream promotion.

## 7. Evaluation lineage

Evaluation lineage is separate from execution lineage but references it explicitly:

`contract -> effect -> attempt -> receipt -> evaluation -> decision`

A decision MUST be able to resolve the evaluation, the evidence used by the evaluation, and the execution artifact being evaluated.

## 8. Attribution boundary

Future agentic/in-group credit assignment may attribute contribution across multiple rollouts, but AIOS does not treat an attribution algorithm as authority.

Until an attribution implementation is independently specified and verified:

- preserve group/trajectory/attempt identity;
- preserve per-attempt evidence;
- keep attribution derived and auditable;
- do not convert attribution directly into execution permission;
- do not infer an unpublished algorithm from public MiMo descriptions.

## 9. Grader isolation

An evaluator/grader is a capability with bounded authority. It may inspect permitted evidence and produce evaluation records. It MUST NOT:

- rewrite execution receipts;
- alter governing policy;
- weaken evidence requirements;
- approve its own authority;
- silently modify terminal criteria;
- promote an unverified capability version.

## 10. Reward/evaluation integrity

Learning reward is a signal, not promotion authority.

`reward/score -> evaluation artifact -> governed decision`

never:

`reward/score -> direct execution/promotion`

Potential grader gaming or reward hacking MUST be treated as an evaluation-integrity concern. Tests and rubrics MUST be versioned/provenanced where they influence a governed decision.

## 11. Rollout/training consistency

When an execution artifact is reused for evaluation or learning, the system MUST preserve the identity and provenance of the artifact actually produced. It MUST NOT silently substitute a reconstructed or differently routed trajectory while claiming it is the original execution.

This is the AIOS invariant for rollout/evaluation consistency; any future learning adapter must implement it without making the learning subsystem an authority layer.

## 12. What is intentionally not absorbed yet

AIOS does not currently absorb:

- a specific MiMo credit-assignment algorithm;
- MiMo-specific RL training code;
- unpublished grader internals;
- MiMo-specific reward formulas;
- benchmark or cost claims as architectural requirements.

Those remain external research until independently specified and verified.
