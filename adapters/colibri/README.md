# Colibri governed inference adapter

## Decision

- **ADAPT:** use Colibri as a local inference provider for large open models, including CPU/disk-streamed MoE workloads. Keep Colibri's engine, model catalog, and setup independently owned.
- **Do not absorb:** do not copy Colibri's C engine, model implementation, or setup logic into the AIOS control plane.
- **Governance boundary:** AIOS must authorize the exact capability/effect before calling `ColibriAdapter.execute`; the adapter is not an authorization or promotion service.

## Contract

Capability: `colibri.inference@1`

The adapter accepts an already-dispatched effect with `effect_id`, `attempt_id`, and a payload containing `messages`, optional `max_tokens` (1–8192), and optional `temperature` (0–2). The contract must grant `colibri.inference@1` and `external_effect`.

The adapter defaults to `http://127.0.0.1:8000/v1`, rejects non-loopback endpoints, bounds request/response sizes and timeout, validates the OpenAI-compatible response, and returns an AIOS `ProviderReceipt` bound to the same effect and attempt. Network failures and ambiguous execution must be handled by AIOS runtime as `UNKNOWN`, not silently retried as a new dispatch.

This adapter does not start, stop, install, download models, or invoke Colibri's MCP management tools. Those operations have materially different side effects and need separate explicit capabilities, permits, receipts, and reconciliation rules.

## Proof

Run `pytest -q tests/test_colibri_adapter.py`. Tests use a fake HTTP response and do not claim that a real Colibri server or model was launched. End-to-end validation requires a pinned Colibri installation/model and must record source revision, model digest, endpoint, request/response receipt, and independent runtime evidence.
