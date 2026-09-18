# Cognitive Plane Absorption

Status: ABSORBED / normative runtime invariant.

AIOS may host or receive asynchronous cognitive modules (planner, critic,
risk assessor, memory, perception, desire, predictor, meta-monitor). These
modules are **non-authoritative by default**.

## Boundary

`cognitive observation/proposal -> AIOS governance -> permit/effect -> execution`

Cognitive output may contain observations, claims, desires, preferences,
plans, candidate actions, risk/continuity assessments, critiques, predictions,
and memory-derived context.

It MUST NOT carry or manufacture authority grants, permits/issuer authority,
policy overrides, promotion authorization, or terminal authorization.

The durable loop rejects authority-bearing fields in decision output before
the action-authorizer is invoked. This protects the existing
`contract -> permit -> effect -> attempt -> receipt -> observation` boundary.

## Invariants

1. **COGNITION_IS_NON_AUTHORITATIVE_BY_DEFAULT** — model/module output is a proposal, not authority.
2. **DESIRE_IS_NOT_DECISION** — desire, survival/continuity pressure, risk, or preference cannot directly execute.
3. **RISK_IS_NOT_AUTHORITY** — risk may request block/replan/escalation; only governing policy and authority decide consequential execution.
4. **MODEL_CLAIM_IS_NOT_OBSERVATION** — generated reasoning/self-description is not runtime evidence.
5. **COGNITIVE_OUTPUT_CANNOT_SMUGGLE_GOVERNANCE** — authority/promotion/terminal override fields fail closed before authorization.
6. **MEMORY_IS_NOT_AUTHORITY** — memory can provide context but cannot replay an old permit, approval, or policy decision.
7. **META_CONTROL_CANNOT_GRANT_AUTHORITY** — monitoring/reconfiguration may propose pause/replan/degrade, but cannot grant permission or promotion.
8. **CONFLICT_MUST_BE_GOVERNED** — task vs. risk/continuity conflicts become explicit governance inputs; no silent LLM override.

## Absorption boundary

CoMA-style concurrency, specialist modules, shared cognitive workspace and
failure isolation are reusable cognitive-plane patterns. They do not replace
AIOS authority, evidence, durable effect identity, receipt binding, or promotion gates.
