#!/usr/bin/env python3
"""Report-only static checks for the AIOS six-layer boundary baseline.

The initial gate is intentionally narrow: L5 persistence modules must not
import adapter/provider/network execution surfaces. It is report-only by
default; --strict is reserved for a reviewed, clean baseline.
"""
from __future__ import annotations

import argparse
import ast
import json
from pathlib import Path
from typing import Iterable

L5_MODULES = (
    "core/mutation.py",
    "core/durable_wal.py",
    "core/wal_state_store.py",
    "core/capability_store.py",
    "core/authority_store.py",
)
FORBIDDEN_ROOTS = frozenset({
    "adapters", "subprocess", "socket", "requests", "httpx", "urllib",
})
FORBIDDEN_EXACT = frozenset({
    "core.runtime", "core.durable_runtime", "core.provider_authority",
    "core.effect_authority",
})


DYNAMIC_IMPORTS = frozenset({"importlib", "__import__"})


def _resolve_relative(relative: str, level: int, module: str | None) -> str:
    """Resolve ``from .x import y`` against the module's package path."""
    package = Path(relative).with_suffix("").parts[:-1]
    base = package[: len(package) - (level - 1)] if level > 1 else package
    return ".".join([*base, *([module] if module else [])])


def _imports(tree: ast.AST, relative: str = "") -> Iterable[tuple[str, int]]:
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                yield alias.name, node.lineno
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                base = _resolve_relative(relative, node.level, node.module)
                if node.module:
                    yield base, node.lineno
                # ``from . import runtime`` imports submodules by name.
                for alias in node.names:
                    yield f"{base}.{alias.name}" if base else alias.name, node.lineno
            elif node.module:
                yield node.module, node.lineno
                for alias in node.names:
                    yield f"{node.module}.{alias.name}", node.lineno
        elif isinstance(node, ast.Call):
            func = node.func
            name = func.id if isinstance(func, ast.Name) else func.attr if isinstance(func, ast.Attribute) else None
            if name in {"__import__", "import_module"}:
                yield "__import__", node.lineno


def inspect_file(root: Path, relative: str) -> list[dict[str, object]]:
    path = root / relative
    try:
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(path))
    except (OSError, SyntaxError) as exc:
        return [{"rule": "L5-SOURCE-READ", "path": relative, "line": 0,
                 "detail": str(exc)}]
    findings = []
    flagged_lines: set[int] = set()  # one finding per import statement
    for module, line in _imports(tree, relative):
        if line in flagged_lines:
            continue
        top = module.split(".", 1)[0]
        if top in FORBIDDEN_ROOTS or module in FORBIDDEN_EXACT or module in DYNAMIC_IMPORTS:
            flagged_lines.add(line)
            findings.append({
                "rule": "L5-NO-EXECUTION-DEPENDENCY",
                "path": relative,
                "line": line,
                "detail": f"forbidden dependency: {module}",
            })
    return findings


def audit(root: Path) -> list[dict[str, object]]:
    findings: list[dict[str, object]] = []
    for relative in L5_MODULES:
        findings.extend(inspect_file(root, relative))
    return findings


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path,
                        default=Path(__file__).resolve().parents[1])
    parser.add_argument("--strict", action="store_true",
                        help="fail when the reviewed L5 dependency baseline has findings")
    args = parser.parse_args()
    findings = audit(args.root)
    print(json.dumps({
        "gate": "six-layer-l5-dependency-boundary",
        "mode": "strict" if args.strict else "report-only",
        "finding_count": len(findings),
        "findings": findings,
    }, indent=2, sort_keys=True))
    return 1 if args.strict and findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
