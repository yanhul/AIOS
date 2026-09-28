"""AIOS governed boundary for the external PCB/EDA workload."""

from .contract import PCB_CAPABILITY, validate_receipt
from .runner import PcbEdaAdapter

__all__ = ["PCB_CAPABILITY", "PcbEdaAdapter", "validate_receipt"]
