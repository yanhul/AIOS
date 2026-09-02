"""Read-only recursive inspection of an external repository.

The inspector walks a resolved source path, computes per-file metadata
(size, mtime, SHA-256, line count) and delegates classification to the
classifier. It never writes anything.
"""

import datetime
import hashlib
import os
from dataclasses import dataclass, field
from typing import Callable, List

from .classifier import classify_file

_SKIP_DIRS = {".git", "__pycache__", ".venv", "node_modules", ".aios"}
_ENCODINGS = ("utf-8", "latin-1")


@dataclass
class Artifact:
    source_path: str
    relative_path: str
    file_type: str
    size_bytes: int
    mtime_utc: str
    sha256: str
    line_count: int
    category: str
    confidence: float
    basis: str
    extractable: bool = False

    def to_dict(self) -> dict:
        return {
            "source_path": self.source_path,
            "relative_path": self.relative_path,
            "file_type": self.file_type,
            "size_bytes": self.size_bytes,
            "mtime_utc": self.mtime_utc,
            "sha256": self.sha256,
            "line_count": self.line_count,
            "category": self.category,
            "confidence": self.confidence,
            "classification_basis": self.basis,
            "extractable": self.extractable,
        }


def _sha256_of(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _read_text(path: str) -> str:
    """Best-effort text read that tolerates unknown encodings."""
    for enc in _ENCODINGS:
        try:
            with open(path, "r", encoding=enc) as fh:
                return fh.read()
        except (UnicodeDecodeError, OSError):
            continue
    return ""


def _line_count(path: str) -> int:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return sum(1 for _ in fh)
    except OSError:
        return 0


def inspect_repository(
    root: str, classifier: Callable[[str, str, str], tuple] = classify_file
) -> List[Artifact]:
    """Recursively inspect `root` and return Artifact records.

    `classifier` is ``classify_file`` by default; tests may substitute one.
    """
    root = os.path.abspath(root)
    artifacts: List[Artifact] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for fname in sorted(filenames):
            full = os.path.join(dirpath, fname)
            rel = os.path.relpath(full, root).replace("\\", "/")
            if not os.path.isfile(full):
                continue
            try:
                stat = os.stat(full)
            except OSError:
                continue
            ftype = os.path.splitext(fname)[1].lower() or "(none)"
            mtime = datetime.datetime.fromtimestamp(
                stat.st_mtime, tz=datetime.timezone.utc
            ).strftime("%Y-%m-%dT%H:%M:%SZ")
            content = _read_text(full) if ftype in (".md", ".txt", ".yaml", ".json") else ""
            category, confidence, basis = classifier(rel, fname, content)
            artifacts.append(
                Artifact(
                    source_path=full,
                    relative_path=rel,
                    file_type=ftype,
                    size_bytes=stat.st_size,
                    mtime_utc=mtime,
                    sha256=_sha256_of(full),
                    line_count=_line_count(full),
                    category=category,
                    confidence=confidence,
                    basis=basis,
                    extractable=ftype in (".md", ".txt"),
                )
            )
    return artifacts
