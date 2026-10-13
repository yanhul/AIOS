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

The tests use a fake transport; they do not require ROCm, GPU hardware, Kyojin,
or model weights. A live smoke test and benchmark on supported AMD Strix Halo
hardware remain separate acceptance gates.

## Absorb gate

Do not treat this provider as fully absorbed until AIOS authorization and
durable execution are exercised end-to-end, including restart/reconciliation
of an ambiguous attempt, a live Kyojin response, and independently verified
output evidence. No performance claims are made by these adapter tests.
