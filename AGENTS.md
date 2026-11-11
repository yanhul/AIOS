# AIOS Agent / Contributor Instructions

## Architectural boundary
- AIOS is the authority, policy, evidence, verification and reconciliation control plane.
- Do not turn AIOS into an agent runtime, browser engine, scheduler, or skills host. Reuse external execution substrates.
- Follow `docs/ARCHITECTURE_CURRENT.md` and `docs/ROADMAP_CURRENT.md`. Documents marked historical are not normative.

## Authority and state safety
- Caller-supplied fields, dictionaries, runtime output, and agent claims are not authority.
- Never self-issue, self-approve, self-promote, or bypass the independent authority store.
- UNKNOWN is ambiguous, not permission to retry. UNKNOWN retry remains BLOCKED until independent issuer verification is implemented and proven.
- Preserve Contract → Plan → Execute → Observe → Verify → Reconcile → Promote/Block → Persist.
- Keep CANDIDATE separate from ACTIVE. Missing, stale, conflicting, or unverifiable evidence must fail closed.
- A state read, transition precondition, single-use claim, and durable write must share one linearization boundary.
- Never report PASS without evidence tied to the exact commit, run, and artifact.

## Evidence and reporting
- Label claims FACT, VERIFIED, INFERRED, ASSUMPTION, or UNKNOWN.
- Distinguish source inspection, local tests, CI, and live end-to-end verification.
- Do not invent test counts, CI results, run IDs, receipts, or provider observations.
- Keep unresolved work BLOCKED; do not upgrade inference to verification.

## Change procedure
1. Inspect current implementation and tests before editing.
2. Add a regression test that fails on the vulnerable behavior.
3. Make the smallest safe change; retain historical material unless there is proof it should be removed.
4. Run focused tests, then the full suite and relevant gates when available.
5. Record exact SHA, commands, outputs, and gates not run.
6. Never merge, deploy, alter secrets, or promote policy without explicit authorization.
