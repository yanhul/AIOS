# Holmes-Kit absorption

Status: absorbed as architecture, not as a runtime dependency.

Source: `holmes-kit/holmes-kit`, current public README/package surface.

## Verified primitives worth carrying into AIOS

1. **Spec chain provenance**
   - REQ -> H-SPEC -> A-SPEC -> T-SPEC.
   - Implementation files carry an explicit implementation anchor.
   - AIOS mapping: contract -> authority/permit -> effect -> execution attempt -> receipt/evidence. Do not collapse these into prompt state.

2. **Approval is a state transition, not a prompt instruction**
   - Holmes separates draft/sealed state and keeps approval history in a ledger.
   - AIOS mapping: authority/policy remain outside the model; a model cannot manufacture approval/evidence.

3. **Observe-first advisories**
   - Holmes' graph impact, architecture, anchor-density and cycle information is advisory and explicitly excluded from verdicts/ranking when evidence is insufficient.
   - AIOS rule: advisory signals may inform DECIDE but cannot silently become authority, terminal criteria, or promotion gates.

4. **Evidence-gated verification**
   - Holmes records RED-first evidence and distinguishes a real failing assertion from a test that failed to run.
   - AIOS/TRY rule: `ERROR`, `UNKNOWN`, and `NOT_RUN` are never promoted to PASS merely because a later step succeeded.

5. **Policy/risk boundary outside autonomy**
   - Holmes bounds autonomous approval and routes high-risk/irreversible governance decisions to an external approval path.
   - AIOS mapping: the agent may operate inside an immutable policy envelope; it cannot grant itself authority or rewrite terminal conditions.

6. **Durable audit / provenance**
   - Holmes keeps governance actions, session attribution and observations ledgered.
   - AIOS mapping: preserve lineage and evidence across resume; no replay-key/provider data belongs in authority/evidence semantics.

7. **Process-level enforcement is stronger than prompt-level enforcement**
   - Holmes uses agent/OS hooks and CI gates to deny unauthorized writes.
   - AIOS implication: where the environment supports it, enforcement belongs at the execution boundary, not only in agent instructions.

## Explicitly NOT absorbed

- Holmes-Kit is not made an AIOS dependency.
- Holmes' TypeScript/tree-sitter/CPG implementation is not copied wholesale.
- Holmes-specific CLI/MCP configuration is not promoted into AIOS authority semantics.
- Advisory graph metrics are not converted into numeric gates without independent evidence.

## AIOS implementation priority

P0: preserve the existing immutable authority/policy/terminal model.

P1: expose a generic non-blocking governance-advisory interface for impact/scope/drift/cycle findings.

P1: strengthen evidence classification so NOT_RUN/ERROR/UNKNOWN cannot satisfy verification predicates.

P2: add optional execution-boundary hooks for providers that support deny-before-write enforcement.

P2: add spec/decision lineage surfaces only where they bind to existing AIOS contract/evidence lineage; avoid a parallel governance database.

## Relationship to TRY

TRY should consume these primitives through the AIOS boundary rather than implementing a second authority system. Research-specific gates remain in TRY; AIOS remains the control plane.
