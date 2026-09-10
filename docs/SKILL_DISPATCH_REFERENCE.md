# Skill Dispatch Reference

Status: IMPLEMENTED BOUNDARY

AIOS absorbs the useful control-plane pattern from `ptn1411/skill` without making that repository, its dispatcher, or any external skill an authority.

## Absorbed pattern

`Skill Registry -> deterministic Route/Plan -> Permit -> Act -> Verify -> Evidence/Report -> Persist -> Resume`

The skill layer may:

- identify an applicable skill;
- propose a capability route;
- produce a dry-run plan;
- generate analysis/report artifacts.

The skill layer may **not**:

- grant execution authority;
- broaden authorization scope;
- change evidence requirements;
- change budgets or retry limits;
- redefine terminal states or promotion criteria;
- promote its own output to verified truth.

## Deterministic routing

`core/skill_router.py` provides a small dependency-free routing boundary. Routing is a proposal, not an execution decision. A dry-run plan explicitly records `authority_granted: false`.

Unknown work receives no route rather than an invented capability. Ties are deterministic so repeated routing of the same input does not depend on model sampling or dictionary order.

## Evidence/report contract

External analysis skills should return structured findings and provenance that can be consumed by the AIOS evidence layer. Reports are derived artifacts; raw evidence remains authoritative. A report cannot bypass AIOS verification or promotion gates.

## Security boundary

The source skill's defensive authorization boundary is retained as a workload constraint: authorized analysis can be performed, while bypassing or weakening access, licensing, payment, DRM, or other protections is not converted into an AIOS capability.

## Relationship to the durable loop

Skill routing is inserted before authorized action:

`OBSERVE -> ROUTE/PLAN -> PERMIT -> ACT -> VERIFY -> PERSIST -> RESUME`

The canonical AIOS durable loop remains externally governed. Skill routing is therefore a capability-discovery/planning mechanism, not a second control plane.
