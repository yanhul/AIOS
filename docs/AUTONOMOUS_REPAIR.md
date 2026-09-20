# Autonomous Repair Controller

AIOS now has a durable orchestration state machine for:

run -> verify -> diagnose -> local fix -> retest -> external search -> adapt -> retest -> verify.

The controller is not an authority plane. It cannot authorize an effect,
mutate a receipt, or self-attest PASS.

PASS is reachable only from VERIFY when the independent verifier returns
verified=true and at least one evidence reference. Otherwise the controller
continues within bounded repair/search budgets or becomes BLOCKED.

State is atomically persisted after every transition, so restart resumes from
the last durable phase.

Providers are narrow boundaries: Runner, Diagnoser, LocalFixer, SearchProvider,
Adapter, and Verifier. An LLM may implement a provider and propose diagnosis
or patches, but the verifier controls PASS and AIOS authority remains outside
the controller.
