# TRY proposal operation receipt v1

## Trust boundary

`GET /v1/repair/proposal/{request_id}` returns a signed operation receipt in addition to the cached operation state. The receipt is authenticated independently of the bearer transport token using HMAC-SHA256. TRY stores `TRY_OPERATION_RECEIPT_SECRET` and `TRY_OPERATION_RECEIPT_KEY_ID`; AIOS pins the same issuer/key ID/secret under `AIOS_TRY_OPERATION_KEYRING` with scope `try.operation.receipt.verify`.

The signed body binds: receipt type, issuer, key ID, receipt ID, request ID, canonical request digest, repository, target SHA, attempt, status, execution classification, failure code, proposal digest, issued/expiry timestamps, and algorithm. AIOS rejects an unsigned response, unknown/revoked key, key-ID mismatch, invalid signature, expired/future receipt, request identity mismatch, or a response whose status differs from the signed receipt.

HMAC is symmetric: the Worker and AIOS verifier both hold the secret. It authenticates the Worker to components that do not possess that secret, but is not asymmetric non-repudiation. The Gateway does not receive this secret. Gateway trust is a separate AIOS Ed25519 public-key verification of the RetryPermit.

## Execution classification

| Signed state | Meaning | RetryPermit eligibility |
|---|---|---|
| `COMPLETED / COMPLETED` | Proposal result durably cached; proposal digest bound | No |
| `UNKNOWN / IN_PROGRESS_OR_AMBIGUOUS` | Request may have reached Gemini or response/result persistence was ambiguous | No |
| `FAILED / NOT_SUBMITTED` | Only local configuration preflight failed before Gemini POST was sent | Eligible for reconciliation + separate AIOS issuer approval |

Gemini HTTP errors (including 4xx/429), timeouts, malformed responses, 5xx, crashes after submission, and result-persistence gaps remain `UNKNOWN`. They do not prove non-execution. `retry_allowed` in the Worker response is always false; the Worker never grants retry authority.

## Request ordering

AIOS persists the exact TRY request binding in the current dispatched effect before POST: request ID (equal to the AIOS attempt ID), request digest, repository, target SHA, and attempt. A receipt is useful for reconciliation only when all of these match the persisted binding.
