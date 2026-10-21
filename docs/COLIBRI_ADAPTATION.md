# Colibri → AIOS adaptation assessment

Status: **ADAPT (provider boundary only); ABSORB engine = REJECT**.

Assessment is pinned to upstream Colibri commit
`bf2442915d6e3dd4cdfd2eb9c2a3d2aa44a25850`. This is an architecture decision
and a capability proposal, not a claim that a real model has been launched.

## What Colibri contributes

| Finding | Evidence at pinned source | Decision | Reason |
|---|---|---|---|
| Local inference server with OpenAI-compatible API | `README.md` documents the OpenAI base URL at `http://127.0.0.1:8000/v1` | **ADAPT** | AIOS can route inference through a provider contract without owning model execution. |
| Large MoE inference with RAM-resident dense weights and disk-streamed experts | `README.md`, model-family docs and engine implementations | **ADAPT as a workload option** | Useful for CPU-only/low-GPU environments. AIOS must treat model fit and latency as context/evidence, not assume it is universally faster or suitable. |
| Hardware detection and resource-based model recommendation | `c/setup_hw.py`, `c/resource_plan.py`, `c/setup_catalog.py` | **WATCH / integrate as observed inputs later** | Hardware/resource observations can inform planning, but recommendation output cannot grant execution authority or change budgets. |
| Resumable downloads and per-file hash checks | `c/setup_download.py` | **ADAPT selectively; separate integrity audit** | Keep downloading in the workload plane. The independent candidate hardening remains in [temp PR #23](https://github.com/yanhul/temp/pull/23), not silently imported as upstream code. |
| MCP tools that install, start, stop, and inspect Colibri | `docs/MCP_SERVER.md`, `c/mcp_server.py`, `c/setup_flow.py` | **REJECT as authority; possible future narrow capabilities** | These tools perform external side effects. A generic MCP bridge would bypass AIOS unless each operation has a distinct contract, permit, effect/attempt identity, receipt and reconciliation. |
| Colibri engine, model-family C implementations, cache/runtime internals | source tree and family registry | **REJECT ABSORB** | Independent engine ownership and rapid upstream changes make copying it into the control plane unnecessary and costly. AIOS should govern it through an adapter. |

## AIOS boundary implemented in PR #99

- Capability: `colibri.inference@1`; upstream source revision recorded in the
  registry and workload manifest.
- Adapter speaks one non-streaming OpenAI-compatible chat-completions request.
- Default endpoint is loopback only. Remote endpoints are rejected by design
  until a separate authenticated/authorized remote-provider policy exists.
- Request and response sizes and timeout are bounded; roles, token limits,
  response schema, and effect/attempt binding are validated.
- Receipt carries response ID, request SHA-256, endpoint, and model identifier.
- Adapter does not install/download/start/stop Colibri and cannot promote a
  result. AIOS runtime remains the authority and persistence boundary.
- Ambiguous network outcomes must become `UNKNOWN`; do not auto-retry a
  dispatched inference as if the first call definitely had no effect.

## Proof levels

1. **Hermetic contract tests:** validate adapter input, authorization fields,
   output schema, bounds and receipt identity using a fake HTTP response.
2. **AIOS CI:** full repository tests, authoring gate and workload conformance
   must pass for the exact PR head.
3. **Real integration — still required:** install the pinned Colibri revision,
   record exact model/revision/digest and environment, send a bounded request
   to the actual local server through the AIOS runtime, and preserve the
   resulting receipt/logs. Verify a timeout-after-dispatch yields `UNKNOWN`
   and does not create an ungoverned retry. Until this is evidenced, real
   Colibri runtime integration is **UNKNOWN**, not PASS.

## Decision

**ADAPT the inference provider boundary; do not absorb Colibri's engine or MCP
control surface.** Keep PR #99 Draft until the exact-head CI is green and a
real-server integration receipt is available. PR #23 is a separate downloader
integrity candidate and does not prove this adapter's runtime integration.
