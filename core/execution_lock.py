"""Fail-closed deployment gate for all provider-facing external effects.

Actor authentication is not independently provisioned in this deployment.
This module intentionally exposes no environment-variable or caller-controlled
override: only a reviewed code change integrating the independent issuer may
remove this block.
"""

class ExternalExecutionBlocked(PermissionError):
    """Raised whenever provider-facing execution is attempted without trust root."""


def require_external_execution_enabled() -> None:
    raise ExternalExecutionBlocked(
        "external-effect execution is disabled: independent actor issuer is not configured"
    )
