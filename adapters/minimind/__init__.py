"""Governed boundary for the external MiniMind learning workload.

Keep package initialization inert: importing a submodule such as isolation
must not import the provider, contract, or runner before signer trust checks.
The public names remain lazily available for existing callers.
"""

import importlib as _importlib

__all__ = ["MINIMIND_CAPABILITY", "MiniMindAdapter", "validate_receipt"]


def __getattr__(name):
    if name in ("MINIMIND_CAPABILITY", "validate_receipt"):
        module = _importlib.import_module(".contract", __name__)
        return getattr(module, name)
    if name == "MiniMindAdapter":
        module = _importlib.import_module(".runner", __name__)
        return module.MiniMindAdapter
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
