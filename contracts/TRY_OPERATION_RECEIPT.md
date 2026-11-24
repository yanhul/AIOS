# TRY proposal operation receipt v1

## Trust boundary

`GET /v1/repair/proposal/{request_id}` returns a signed operation receipt in addition to the cached operation state. The receipt is authenticated independently of the bearer transport token using Ed25519. TRY stores a base64-encoded PKCS#8 private key in `TRY_OPERATION_RECEIPT_PRIVATE_KEY` and its identifier in `TRY_OPERATION_RECEIPT_KEY_ID`; AIOS pins only the matching base64-encoded raw 32-byte public key under `AIOS_TRY_OPERATION_KEYRING` with scope `try.operation.receipt.verify`.

The signed body binds: receipt type, issuer, key ID, receipt ID, request ID, canonical request digest, repository, target SHA, attempt, status, execution classification, failure code, proposal digest, issued/expiry timestamps, and algorithm. AIOS rejects an unsigned response, unknown/revoked key, key-ID mismatch, invalid signature, expired/future receipt, request identity mismatch, or a response whose status differs from the signed receipt.

Ed25519 is asymmetric: the Worker alone holds the private key, while AIOS holds only the pinned public key. The Gateway does not receive either key. Gateway trust is a separate AIOS Ed25519 public-key verification of the RetryPermit. HMAC-SHA256 operation receipts are rejected; there is no algorithm downgrade or shared-secret fallback.

## Execution classification

| Signed state | Meaning | RetryPermit eligibility |
|---|---|---|
| `COMPLETED / COMPLETED` | Proposal result durably cached; proposal digest bound | No |
| `UNKNOWN / IN_PROGRESS_OR_AMBIGUOUS` | Request may have reached Gemini or response/result persistence was ambiguous | No |
| `FAILED / NOT_SUBMITTED` | Only local configuration preflight failed before Gemini POST was sent | Eligible for reconciliation + separate AIOS issuer approval |

Gemini HTTP errors (including 4xx/429), timeouts, malformed responses, 5xx, crashes after submission, and result-persistence gaps remain `UNKNOWN`. They do not prove non-execution. `retry_allowed` in the Worker response is always false; the Worker never grants retry authority.

## Request ordering

AIOS persists the exact TRY request binding in the current dispatched effect before POST: request ID (equal to the AIOS attempt ID), request digest, repository, target SHA, and attempt. A receipt is useful for reconciliation only when all of these match the persisted binding.
