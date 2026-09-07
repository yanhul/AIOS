"""Governed boundary for the external MiniMind learning workload."""

from .contract import MINIMIND_CAPABILITY, validate_receipt
from .runner import MiniMindAdapter

__all__ = ["MINIMIND_CAPABILITY", "MiniMindAdapter", "validate_receipt"]
