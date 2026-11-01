# Javis OS — AIOS Absorption Packet

**Status:** PROPOSED / UNTRUSTED EVIDENCE  
**Decision:** ADAPT selectively; do not fork or import Javis runtime code  
**Source repository:** https://github.com/blogminhquy/javis-os  
**Audited source snapshot:** `7f82f3bf2a9d43e9a96ad005abd403aaf85d27a3`  
**AIOS target baseline:** `main` at packet creation  
**Authority:** AIOS control plane only  
**External code copy/execution:** prohibited  
**Promotion:** blocked pending independent source re-check, AIOS conformance tests, and runtime proof

> This packet records an engineering decision from a source-level audit. It is not evidence that any Javis feature has been implemented in AIOS, and it does not promote Javis as a trusted workload or capability.

## 1. Executive decision

Javis OS is useful as a reference for a self-hosted agent application: MCP connector mediation, once-only write tracking, task leases, resumable workflows, retrieval-oriented memory, and user-facing orchestration.

It is **not** a replacement for AIOS. Its runtime combines model-facing tools, server-side plugins, connector permissions, task execution, and application state. AIOS has a different responsibility: independently govern contracts, permits, effects, evidence, reconciliation, promotion, and durable recovery.

The correct treatment is:

- **ABSORB as design patterns:** task lifecycle/lease mechanics, once-ledger state model, workflow checkpoint/revision concepts, retrieval-memory separation.
- **ADAPT behind AIOS boundaries:** MCP connector mediation, native CLI execution, audit/observability, token-authenticated local service edges.
- **HOLD pending hardening:** plugin execution, secret persistence, permission fallback, unknown-tool classification, and multi-process once-only claims.
- **REJECT:** treating Javis's application audit log, chat history, worker lease, connector permission, or model decision as an AIOS authority record or terminal receipt.

No Javis source code should be copied into AIOS. Re-implement only independently specified interfaces and tests.

## 2. Evidence scope and confidence

### Audited source areas

The source audit at the pinned snapshot inspected or located these areas:

| Javis source | Audited behavior | Confidence |
|---|---|---|
| `server/mcp_hub.py`, `server/mcp_catalog.py` | Connector dispatch, permission resolution, tool classification, rate limit and JSONL audit | Source-level finding |
| `server/once_ledger.py` | STARTED/SUCCEEDED/FAILED/UNKNOWN and retry handling | Source-level finding |
| `server/tasks.py`, `server/task_store.py` | Task dispatch, SQLite state, claim/lease/heartbeat/event history | Source-level finding |
| `server/workflow_runtime.py`, `server/context_runtime.py`, `server/agent_runtime.py` | Workflow graph/revision, checkpoint/resume, capability-constrained replanning | Source-level finding; rollout is policy-dependent |
| `server/plugins_host.py` | Python plugin loading and in-process tool/hook registration | Source-level finding |
| `server/secrets_store.py` | Fernet-backed storage and plaintext fallback path | Source-level finding |
| `server/agent_ledger.py` and MCP audit path | Application activity/audit records | Source-level finding |
| README / `CLAUDE.md` | CLI-native tool surface differs from API-engine surface; plugin execution and security caveats | Documentation finding |

### Confidence labels

- **FACT (source snapshot):** a behavior directly visible in the pinned Javis source or documentation.
- **INFERRED RISK:** a consequence that follows from the code path under stated deployment conditions; not proof of a live exploit.
- **NOT VERIFIED:** deployed configuration, multi-process race reproduction, provider-side idempotency, or operational crash/recovery behavior not demonstrated by the source audit.
- **AIOS VERIFIED:** only the existing AIOS code paths named in §3 were inspected for this packet. This is not a test result.

The source snapshot is pinned because upstream may change. Re-audit before implementation if the Javis default branch has advanced.

## 3. Mapping into existing AIOS primitives

AIOS already has native authority and durability components. Javis should strengthen their test coverage and adapter design, not create a parallel authority subsystem.

| Javis pattern | AIOS target | Treatment | Required invariant |
|---|---|---|---|
| MCP connector permission mediation | `core/capabilities.py`, `core/authority.py`, `core/effect_authority.py`; workload-specific adapter | ADAPT | Connector metadata is descriptive; contract + permit + capability resolution authorizes every effect. Unknown action or invalid permission fails closed. |
| Action/tool classification | Capability manifest and adapter validation | ADAPT | Unknown tool is UNKNOWN/DENY, never implicitly read-only. Classification must be action-specific and versioned. |
| Once ledger | `core/effect_authority.py`, `core/external_effect.py`, `core/durable_wal.py`, receipt/evidence path | ABSORB the state model; do not duplicate | Stable effect identity, distinct attempt identity, provider identity/idempotency where supported; UNKNOWN never becomes an automatic retry. |
| SQLite task claims, leases, heartbeat, events | `core/durable_runtime.py`, `core/durable_loop.py`, `core/durable_wal.py`, `core/continue_contract.py` | ABSORB selectively | Lease expiry is not proof of no side effect. Reconcile effect/receipt before retry or reclaim. |
| Workflow graph, checkpoint, resume, pinned subworkflow revision | `core/durable_loop.py`, `core/snapshot.py`, `core/continue_contract.py`, `core/wal_state_store.py` | ABSORB selectively | Completed nodes remain completed only when their receipts/evidence validate; resume must pin the authorized graph and policy revision. |
| Capability-constrained replanning | Contract/capability resolution in `core/authority.py` and `core/capabilities.py` | ABSORB | Replanning cannot enlarge the original contract's capability set, scope, budget, or terminal conditions. |
| In-process Python plugin host | No direct AIOS core target; isolate through a narrow adapter/process boundary | HOLD | Untrusted plugin code must not share the AIOS authority process, environment, filesystem, or credentials. |
| Secret store with plaintext fallback | Existing deployment secret boundary; do not introduce a Javis-like store | HOLD | Missing crypto/key/configuration means DENY; never persist plaintext as a fallback. Separate key custody from ciphertext storage. |
| JSONL MCP audit log | `core/evidence.py`, `core/attestation.py`, `core/mutation.py`, receipt/reconciliation path | ADAPT | Operational logs are observability only. A log append is not a provider receipt or proof of committed effect. Audit failure must be visible and must not be silently reported as durable success. |
| CLI-native shell and tools | `adapters/process.py` plus `core/runtime.py` / effect authority | ADAPT | Every mutating native command must cross the same AIOS permit/effect/attempt/receipt boundary; no direct agent shell bypass. |
| Retrieval/Second Brain | `core/governed_memory.py` and evidence references | ADAPT | Memory is a derived, versioned record with provenance; summaries and retrieved text never grant authority or become facts without evidence. |
| Local hub token generation and constant-time comparison | Service-edge authentication only | ADAPT | Authentication is not authorization. A valid service token still cannot bypass AIOS contracts, permits, capabilities, or effect checks. |

### Existing AIOS code reviewed for this mapping

- `core/effect_authority.py` and `core/external_effect.py`: contract/permit-bound external-effect lifecycle; distinct effect/attempt/provider fields; UNKNOWN and observation transitions.
- `core/execution_lineage.py`: immutable execution context and digest validation.
- `core/authority.py`: persisted contract, permit, attestation, capability and policy resolution.
- `core/evidence_gate.py`: fail-closed evidence-level promotion checks.
- `core/governed_memory.py`: memory persistence bound to MEMORY_WRITE authority and evidence references.
- `core/workload_registry.py`: metadata-only workload discovery; no authority grant.
- `core/repository_patch_adapter.py`: repository mutation provider behind AIOS runtime/effect boundary.
- `docs/HARNESS_REFERENCE.md` and `docs/ABSORPTION_MAP.md`: existing durable-harness and absorption policy.

These are source inspections, not newly executed tests. Do not interpret this mapping as proof that every runtime entry point is already mediated.

## 4. Findings that must become explicit regression tests

The following are acceptance tests for a future AIOS-native adapter/design change. They have **not** been run as part of this packet.

| ID | Severity | Test | Expected result |
|---|---|---|---|
| JAVIS-01 | P0 | Connector action has no trusted metadata/rule and its name does not match a write heuristic | UNKNOWN/DENY; never classify as read-only |
| JAVIS-02 | P0 | Stored permission is absent, malformed, or outside the permission enum | DENY; no fallback to full/admin |
| JAVIS-03 | P0 | CLI engine attempts a mutating shell command outside AIOS runtime/effect authority | Blocked; no process side effect |
| JAVIS-04 | P0 | Plugin attempts to read process environment or arbitrary host files | Isolated from AIOS authority process; denied unless an explicit narrow capability exists |
| JAVIS-05 | P0 | Secret encryption dependency/key is unavailable | Fail closed; no plaintext persistence |
| JAVIS-06 | P0 | Provider commits an effect, then worker crashes before recording receipt | Effect becomes UNKNOWN; no blind replay; reconciliation required |
| JAVIS-07 | P0 | Two workers concurrently claim the same effect in a shared store | Exactly one valid claim/dispatch; database-level atomicity, not process-local locking |
| JAVIS-08 | P0 | Same logical external effect is invoked through two differently named tools | Shared effect identity/idempotency prevents duplicate mutation |
| JAVIS-09 | P1 | Task lease expires after provider dispatch but before receipt persistence | Reconcile effect before reclaim/retry |
| JAVIS-10 | P1 | Workflow graph or subworkflow revision changes during a suspended run | Resume only under the pinned authorized revision or block for re-authorization |
| JAVIS-11 | P1 | A completed workflow node is resumed after restart | Do not repeat the node's external effect; validate durable receipt first |
| JAVIS-12 | P1 | Audit/log storage fails after a provider mutation | Never claim durable receipt/success; record an explicit evidence gap and reconcile |
| JAVIS-13 | P1 | Retrieved memory contains instructions or claims that conflict with policy/evidence | Treat as untrusted input; no authority or factual promotion |
| JAVIS-14 | P1 | Local hub token is valid but request lacks a matching AIOS permit | Authentication may pass; effect authorization must still deny |

A test is PASS only with executable test output and the exact code revision. A design statement or static checklist is not test evidence.

## 5. Implementation sequence

### Phase A — conformance audit only (no runtime changes)

1. Trace every AIOS adapter entry point, including process/CLI and MCP-like integrations, to prove whether it reaches `runtime.execute` and `effect_authority`.
2. Trace effect identity and provider idempotency through dispatch, UNKNOWN, receipt, restart, and reconciliation.
3. Verify whether the WAL/store claim operation is atomic across processes, not merely threads.
4. Trace workflow checkpoint/revision data through crash/restart and confirm completed nodes are receipt-backed.
5. Trace secret handling from configuration to provider process; identify any plaintext path.

**Exit:** a path-by-path evidence table with code references and tests. No capability promotion.

### Phase B — close P0 gaps

Implement only demonstrated gaps, each in a separate bounded AIOS-native change:

1. deny unknown connector actions and invalid permission states;
2. close native process/shell bypasses;
3. isolate plugin-like extension code outside the authority process;
4. fail closed on missing encryption/key material;
5. make effect claims atomic and provider idempotency explicit where supported;
6. ensure crash-after-provider-commit resolves to UNKNOWN + reconciliation, never blind retry.

**Exit:** JAVIS-01 through JAVIS-08 pass with reproducible test logs and no external Javis code copied/executed.

### Phase C — P1 durability and memory

1. Verify lease expiry and reclaim against effect receipts.
2. Pin workflow revision and authorization context across suspend/resume.
3. Make completed-node reuse receipt-backed.
4. Keep operational logs separate from cryptographic evidence and provider receipts.
5. Ensure memory retrieval cannot modify policy, authority, or evidence level.

**Exit:** JAVIS-09 through JAVIS-14 pass; crash/restart tests prove the state transitions.

### Phase D — promotion gate

Promotion is a separate AIOS decision. It requires:

- source re-check at a pinned Javis commit and source/evidence digests;
- independent AIOS implementation review;
- all applicable regression tests with exact run IDs and output digests;
- runtime proof across restart/recovery, including UNKNOWN and duplicate-dispatch cases;
- evidence-gate approval from AIOS control plane.

Until then, this packet remains **PROPOSED / UNTRUSTED EVIDENCE**. It must not create or activate a capability, change a policy, authorize a provider, or register `repo_patch@1`.

## 6. Explicit non-goals

- No Javis fork or wholesale port.
- No copying or executing Javis plugin code.
- No treating Javis's MCP permission as an AIOS permit.
- No treating task lease expiry as proof that an external effect did not happen.
- No claim of exactly-once execution without atomic claim plus provider idempotency/reconciliation evidence.
- No conversion of application logs, chat history, or memory summaries into authoritative receipts.
- No change to AIOS policy, capability registry, promotion criteria, or terminal conditions.
- No activation or widening of `repo_patch@1`.

## 7. Provenance and implementation record

| Field | Value |
|---|---|
| Source repository | `https://github.com/blogminhquy/javis-os` |
| Source snapshot audited | `7f82f3bf2a9d43e9a96ad005abd403aaf85d27a3` |
| Audit type | Source-level review; not a deployment penetration test |
| AIOS baseline inspected | `main`, latest commit observed during packet preparation: `55693505f36def8c3f43c3fb46e648d7fe7a9d04` |
| AIOS files changed by this packet | Documentation only |
| Javis code copied/executed | No |
| Runtime tests executed for this packet | No |
| Capability promoted | No |
| Policy/authority changed | No |
| `repo_patch@1` activated | No |

## 8. References

### Javis OS source snapshot

- [Repository](https://github.com/blogminhquy/javis-os/tree/7f82f3bf2a9d43e9a96ad005abd403aaf85d27a3)
- [MCP Hub](https://github.com/blogminhquy/javis-os/blob/7f82f3bf2a9d43e9a96ad005abd403aaf85d27a3/server/mcp_hub.py)
- [MCP Catalog](https://github.com/blogminhquy/javis-os/blob/7f82f3bf2a9d43e9a96ad005abd403aaf85d27a3/server/mcp_catalog.py)
- [Once Ledger](https://github.com/blogminhquy/javis-os/blob/7f82f3bf2a9d43e9a96ad005abd403aaf85d27a3/server/once_ledger.py)
- [Task Store](https://github.com/blogminhquy/javis-os/blob/7f82f3bf2a9d43e9a96ad005abd403aaf85d27a3/server/task_store.py)
- [Workflow Runtime](https://github.com/blogminhquy/javis-os/blob/7f82f3bf2a9d43e9a96ad005abd403aaf85d27a3/server/workflow_runtime.py)
- [Context Runtime](https://github.com/blogminhquy/javis-os/blob/7f82f3bf2a9d43e9a96ad005abd403aaf85d27a3/server/context_runtime.py)
- [Agent Runtime](https://github.com/blogminhquy/javis-os/blob/7f82f3bf2a9d43e9a96ad005abd403aaf85d27a3/server/agent_runtime.py)
- [Plugin Host](https://github.com/blogminhquy/javis-os/blob/7f82f3bf2a9d43e9a96ad005abd403aaf85d27a3/server/plugins_host.py)
- [Secrets Store](https://github.com/blogminhquy/javis-os/blob/7f82f3bf2a9d43e9a96ad005abd403aaf85d27a3/server/secrets_store.py)
- [Security notes](https://github.com/blogminhquy/javis-os/blob/7f82f3bf2a9d43e9a96ad005abd403aaf85d27a3/SECURITY.md)

### AIOS baseline

- [Absorption map](https://github.com/yanhul/AIOS/blob/main/docs/ABSORPTION_MAP.md)
- [Harness reference](https://github.com/yanhul/AIOS/blob/main/docs/HARNESS_REFERENCE.md)
- [Effect authority](https://github.com/yanhul/AIOS/blob/main/core/effect_authority.py)
- [Execution lineage](https://github.com/yanhul/AIOS/blob/main/core/execution_lineage.py)
- [Durable runtime](https://github.com/yanhul/AIOS/blob/main/core/durable_runtime.py)
- [Governed memory](https://github.com/yanhul/AIOS/blob/main/core/governed_memory.py)
- [Evidence gate](https://github.com/yanhul/AIOS/blob/main/core/evidence_gate.py)
