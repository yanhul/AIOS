# Kyojin inference adapter

This adapter exposes Kyojin as an AIOS `ProviderAdapter` without importing
or absorbing the Kyojin engine. Kyojin is an external provider; AIOS remains the
authority and durable-state owner.

## Contract

- Register capability `kyojin.inference@1` and grant it in the execution contract.
- The already-authorized contract's `scope` is used as the prompt text.
- Model, endpoint, timeout, generation limit, and temperature are deployment
  configuration. Configure `KYOJIN_MODEL` and optionally
  `KYOJIN_BASE_URL`; the default endpoint is
  `http://127.0.0.1:8000/v1`.
- If needed, provide the server key through the `KYOJIN_API_KEY` environment variable.
- The adapter makes exactly one request and never retries. It returns
  `ProviderReceipt(outcome='OBSERVED_SUCCESS')` only for a successful HTTP
  response with a valid chat-completions response shape.
- Transport failure, non-success HTTP status, or malformed output raises to
  `core.runtime.execute_attempt`; the AIOS runtime records the ambiguous
  operation as `UNKNOWN` rather than converting it to success.
- The returned output digest and provider usage are observations only. They do
  not prove semantic correctness or authorize promotion.

## CPU-only tests

```sh
python -m pytest -q tests/test_kyojin_adapter_contract.py
```

The tests include both deterministic fake-transport cases and a real local
HTTP round trip using Python's standard-library HTTP server. They do not require
ROCm, GPU hardware, Kyojin, or model weights. This validates HTTP framing,
request serialization, response parsing, and receipt binding, but is not proof
of compatibility with a live Kyojin server.

## Absorb gate

Acceptance is split into two tracks:

- **CPU-only integration capability:** contract tests plus a real local HTTP
  round trip, AIOS authorization/dispatch/runtime path, receipt validation,
  durable persistence, and restart/reconciliation of an ambiguous attempt.
  This track does not require GPU hardware and is the gate for declaring the
  software integration usable against a compatible OpenAI-style endpoint.
- **Kyojin deployment qualification:** a live response from the target Kyojin
  version is an interoperability check when an endpoint becomes available.
  Benchmarking on AMD Strix Halo/ROCm is optional performance evidence, not a
  blocker for the CPU-only integration capability. Do not claim Kyojin-specific
  interoperability or hardware performance before those checks are actually run.

No performance claims are made by these adapter tests.

## Runtime boundary

Invoke through the existing `core.runtime.execute_attempt` path only after
AIOS has authorized and dispatched the effect. Do not call `KyojinAdapter.execute`
as an authorization substitute. The runtime validates the returned
`ProviderReceipt`, persists an observation, and converts adapter exceptions into
`UNKNOWN`; retries require a separately authorized retry attempt.
