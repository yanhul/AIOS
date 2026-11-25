# TRY algorithm execution receipt v1

## Purpose and trust boundary

TRY may produce a deterministic algorithm candidate and a content-addressed
execution receipt. SHA-256 fields are integrity checks, not signatures and not
proof that a particular worker executed the code. AIOS independently validates
the exact input, specification, executor revision/source digest, candidate
route, and shortest-path optimality using its own implementation.

The caller must obtain the expected input digest, specification, executor
revision, and executor source digest from the governing execution contract or
deployment policy. Never take the expected values from the receipt itself.

## Accepted operation

P0 accepts only `maze.shortest_path@1`, with a bounded expansion budget.
AIOS uses a separate Dijkstra implementation to check route endpoints, bounds,
walls, adjacency, reachability, and optimality. TRY's nested verification
message is informational and is not trusted.

## Decision semantics

- `INDEPENDENTLY_VERIFIED`: AIOS independently recomputed and accepted this
  exact candidate against the caller-supplied contract bindings.
- `BLOCKED`: malformed, mismatched, unpinned, or incorrect candidate.
- `NOT_AUTHORIZED`: always the promotion result of this verifier. It does not
  issue permits, attestations, evidence promotion, or capability absorption.

This verifier does not authenticate worker identity or prove execution
provenance. A future signed worker receipt requires a separate asymmetric
issuer/keyring contract; do not treat this checksum as a substitute.
