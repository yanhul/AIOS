# Absorb/adapt integration boundary

Decision: ADAPT, not fork. This records the 2026-11-08 audits.

Accepted patterns:
- AgentKit: task brief/plan, isolated worktree reference, diff reconciliation,
  independent fresh review and cleanup.
- Javis OS: durable task identity, transactional claim, lease/heartbeat,
  monotonic checkpoint, resumable state and capability/MCP separation.
- Browser-worker audit of worldonlyu/Google_AI_Pro_2Year_ZeroCost_Auto:
  worker lifecycle, bounded batch handling, cancellation/isolation and evidence
  collection only as design patterns after security controls exist.

Ownership:
- AIOS alone owns contracts, permits, policy, effect authorization, evidence,
  verification, reconciliation and promotion/block.
- Orchestration plans are advisory and may request only contract-authorized
  capabilities. Review approval means ready for AIOS verification, never PASS.
- TRY owns its research semantics and worker payloads. Runtime operations must
  bind to AIOS contract/permit identities.

Reject: untrusted in-process plugins, unrestricted shell, plaintext secrets,
unauthenticated sensitive APIs, checkout/request tampering, promotional-token
manipulation, self-review, self-modifying acceptance criteria, unlimited retries,
and claims of exactly-once external effects.

CI PASS proves only that checks executed successfully. It does not prove
research validity, profitability, or independent verification.
