# Claude Mythos 5.1 — AIOS Absorption Receipt

Source: jungjin0003/Claude-Mythos-5.1-System-Prompt

## Decision

ADAPT, not copy.

Useful patterns are converted into AIOS-owned primitives and remain subordinate
to AIOS authority, evidence, receipt, and promotion gates.

| Source pattern | AIOS action | Implemented boundary |
|---|---|---|
| Volatility-aware discovery | ABSORB | core.epistemic.requires_discovery |
| Unknown/current claims require discovery | ABSORB | Volatility.UNKNOWN/CURRENT/RECENT |
| Explicit epistemic uncertainty | ABSORB | ClaimStatus |
| Tool result is not proof of world state | ABSORB | ToolResult -> Observation -> verification |
| Capability-based tool routing | ABSORB | route_capabilities |
| Conversation history as state | ADAPT | existing durable CONTINUE_CONTRACT; history is context, not authority |
| Prompt-only governance | REJECT | code-level evidence/authority gates remain authoritative |
| Provider/product-specific behavior | REJECT | no Claude-specific authority is introduced |

## Invariants

1. A model guess cannot become FACT or VERIFIED by confidence alone.
2. A successful provider/tool response cannot become world-state verification by itself.
3. Observation promotion requires explicit verification evidence.
4. Capability routing only produces candidates; it never grants permission or execution authority.
5. Current/recent/unknown information requires discovery before authoritative assertion.
6. Durable continuation remains an AIOS contract projection, not reconstructed chat memory.

## Verification

Regression coverage is in tests/test_claude_mythos_adaptation.py.

This source pattern is not considered absorbed merely because this document exists:
implementation and tests must pass in CI.
