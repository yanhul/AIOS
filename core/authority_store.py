"""L5 persistence adapter for L6 authority/effect transitions.

This module owns the storage mechanics only. It does not authorize a command,
validate a permit, select a provider, or decide whether an effect may move.
L6 supplies already-validated records and an optional compare-and-swap
precondition; this adapter commits the complete batch through the shared
journaled mutation primitive.
"""
from __future__ import annotations

from collections.abc import Callable, Sequence
import os
from typing import Any, Protocol

from .mutation import commit_batch as _commit_batch
from .mutation import recover_pending as _recover_pending

Precondition = Callable[[str], None]
Payload = tuple[str, Any]


class AuthorityStore(Protocol):
    """Minimal L5 contract consumed by L6 command handlers."""

    def commit(self, payloads: Sequence[Payload], *,
               precondition: Precondition | None = None) -> list[str]:
        """Atomically persist all records or raise without partial commit."""
        ...

    def recover(self) -> None:
        """Recover journaled commits before a read/transition."""
        ...


class FileAuthorityStore:
    """Single-tree file-backed L5 adapter using AIOS's journaled commit engine."""

    def __init__(self, aios_dir: str | os.PathLike[str]):
        path = os.fspath(aios_dir)
        if not isinstance(path, str) or not path.strip():
            raise ValueError("aios_dir must be a non-empty path")
        self.aios_dir = path

    def commit(self, payloads: Sequence[Payload], *,
               precondition: Precondition | None = None) -> list[str]:
        if not isinstance(payloads, (list, tuple)) or not payloads:
            raise ValueError("authority commit requires a non-empty payload batch")
        return _commit_batch(self.aios_dir, payloads, precondition=precondition)

    def recover(self) -> None:
        _recover_pending(self.aios_dir)


def commit_authority_batch(aios_dir: str, payloads: Sequence[Payload],
                           precondition: Precondition | None = None) -> list[str]:
    """Compatibility entry point: L6 command -> L5 atomic batch commit."""
    return FileAuthorityStore(aios_dir).commit(payloads, precondition=precondition)


def recover_authority_store(aios_dir: str) -> None:
    """Compatibility entry point for L5 journal recovery."""
    FileAuthorityStore(aios_dir).recover()


__all__ = [
    "AuthorityStore", "FileAuthorityStore",
    "commit_authority_batch", "recover_authority_store",
]
