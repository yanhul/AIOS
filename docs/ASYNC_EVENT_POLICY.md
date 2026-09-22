# Async Event Policy

Status: implementation guidance.

## Objective

Prevent long-running agents from spending LLM turns on polling when the runtime already supports asynchronous completion events.

## Model-facing rule

When an asynchronous tool or job provides a completion event:

1. submit the work;
2. persist effect/attempt/provider-job identifiers;
3. yield or suspend the session;
4. wait for the completion event;
5. resume the session;
6. verify the received result before any terminal decision.

Do not call `sleep`, `wait`, or status-polling tools repeatedly to simulate an event subscription.

Polling is permitted only when no completion event is available. Such polling must be bounded by an explicit timeout and execution budget.

## Runtime invariant

The runtime should enforce:

`ASYNC_SUBMITTED -> SUSPENDED -> EVENT_RECEIVED -> RESUMED`

and reject/flag an unbounded:

`ASYNC_SUBMITTED -> POLL -> SLEEP -> POLL -> ...`

sequence when event-driven completion is available.

## Cost accounting

A sleep tool may have no direct tool price while still causing additional LLM turns. Therefore optimization must measure:

- LLM turns;
- input/output tokens;
- cache-read/cache-write tokens where exposed;
- wall-clock time;
- polling count;
- async completion latency.

Do not assume a percentage savings without a controlled before/after benchmark on the same workload.

## Governance

Async wake-up does not grant new authority. Completion events remain ordinary execution evidence and must pass the same receipt, authorization, verification, and lineage checks as synchronous execution.

## Conformance test

A compliant harness should be able to run a long-running mock job with a completion event and demonstrate that the waiting interval produces no LLM polling turns. The resulting receipt must preserve effect identity, attempt identity, provider/job identity, completion event provenance, and resume linkage.
