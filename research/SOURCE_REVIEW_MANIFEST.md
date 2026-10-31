# Candidate source-review manifest

```json
{
  "schema_version": 1,
  "reviews": [
    {
      "candidate_id": "exact-candidate-id-from-absorption-executor.json",
      "source_commit": "40-character immutable commit SHA",
      "reviewer": "reviewer identity",
      "reviewed_at": "ISO-8601 timestamp",
      "review_decision": "ACCEPTED",
      "candidate_primitive": "exact primitive proposed by the executor",
      "reviewed_files": ["path/to/source_file.py"],
      "implementation_refs": ["core/implemented_adapter.py"],
      "candidate_test_refs": ["tests/test_candidate_adapter.py"],
      "log_digest": "64-character SHA-256 of the source/conformance review log",
      "authority_receipt_lineage": {
        "effect_id": "effect id",
        "attempt_id": "attempt id",
        "receipt_id": "receipt id",
        "evidence_digest": "64-character SHA-256 evidence digest"
      }
    }
  ]
}
```

## Rules

- Save the actual manifest as `research/source_review_manifest.json`. Do not put placeholder values in the live manifest.
- `source_commit` must be a full commit SHA in the candidate's GitHub repository. The collector fetches every listed source file at that exact commit and computes the SHA-256 hashes; it does not trust supplied hashes.
- `review_decision` must be explicitly `ACCEPTED`; a reviewer identity and review timestamp are required. The collector does not infer approval from a README or a successful test run.
- `implementation_refs` must point to actual AIOS-owned files. `candidate_test_refs` must point to actual Python test files under `tests/`; those tests are executed at verification and runtime-proof stages.
- `authority_receipt_lineage` must bind effect, attempt, receipt, and evidence. Missing or malformed lineage blocks verification and absorption.
- The manifest is an approval input, not proof by itself. A candidate is not absorbed unless candidate-specific tests pass again and runtime proof matches the same source digest, test digest, and receipt lineage.
- Current limitation: this pipeline validates receipt-lineage fields and consistency but does not yet cryptographically authenticate the receipt against the deployed authority verifier. Until that integration is added and exercised end-to-end, do not treat a candidate as authority-verified or enable `repo_patch@1`.
