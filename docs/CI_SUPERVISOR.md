# Autonomous CI supervisor

`core.ci_supervisor` is the wake boundary between GitHub Actions and the durable repair controller.

Flow:

```text
GitHub CI completed
  -> CISupervisor.poll()
  -> durable deduplication
  -> CIEvent(REPAIR | VERIFY_MERGE)
  -> wake worker
  -> AutonomousRepairController
```

The supervisor is deliberately not an authority plane. It does not authorize effects, mutate receipts, merge code, or declare a repair PASS.

`GITHUB_TOKEN` is required for the polling client. A deployment can use GitHub webhook/workflow events for immediate wake-up; a scheduled runner can call `poll()` as a fallback. The durable state prevents the same completed run from being emitted repeatedly.
