"""Provider-specific adapter contract for deployment-owned reconciliation code."""
from __future__ import annotations

from typing import Any, Protocol

from core.runtime import ProviderReceipt


class ReadOnlyReconciliationAdapter(Protocol):
    """Adapter used after a worker crash; reconcile must be read-only.

    Implementations query the provider using the exact persisted idempotency
    key/operation identity. They must never submit, replay, or mutate a provider
    operation. Return None when the provider cannot prove an outcome.
    """

    name: str

    def reconcile(
        self, *, contract: dict[str, Any], effect: dict[str, Any], attempt_id: str,
    ) -> ProviderReceipt | None:
        ...


__all__ = ["ReadOnlyReconciliationAdapter"]
