"""AIOS project metadata loading and source-path resolution.

Reads an AIOS project descriptor (project.yaml, minimal YAML subset) and
resolves the external repository it references. Never writes to the source.
"""

import os
from typing import Any, Dict, List


class ProjectError(Exception):
    """Raised when the AIOS project descriptor is invalid or unresolvable."""


def _strip_comment(line: str) -> str:
    """Remove a full-line or inline comment marker from a line.

    Handles lines whose first non-space char is '#'. Inline comments are not
    stripped because a '#' can legitimately appear inside a path/URL.
    """
    stripped = line.lstrip()
    if stripped.startswith("#"):
        return ""
    return line


def _split_key_value(line: str):
    """Split 'key: value' at the first colon. Returns (indent, key, value)."""
    indent = len(line) - len(line.lstrip(" "))
    content = line.strip()
    if content.startswith("- "):
        content = content[2:].strip()
    if ":" not in content:
        raise ProjectError(f"Unparseable project.yaml line: {line!r}")
    key, _, value = content.partition(":")
    return indent, key.strip(), value.strip()


def load_mini_yaml(path: str) -> Dict[str, Any]:
    """Parse the minimal YAML subset used by AIOS project descriptors.

    Supports:
      - comment lines (#)
      - flat ``key: value``
      - list-style ``- key: value`` (list marker dropped; treated as a key)
      - one nesting level of 4-space indented ``key: value`` children
    """
    if not os.path.isfile(path):
        raise ProjectError(f"project.yaml not found: {path}")
    data: Dict[str, Any] = {}
    with open(path, "r", encoding="utf-8") as fh:
        raw_lines = fh.readlines()

    stack: List[tuple] = []  # (indent, dict) of open parents
    for raw in raw_lines:
        line = _strip_comment(raw.rstrip("\r\n"))
        if not line.strip():
            continue
        indent, key, value = _split_key_value(line)
        while stack and indent <= stack[-1][0]:
            stack.pop()
        parent = stack[-1][1] if stack else data
        if value:
            parent[key] = value
        else:
            child: Dict[str, Any] = {}
            parent[key] = child
            stack.append((indent, child))
    return data


def resolve_source_path(source_path: str) -> str:
    """Resolve and validate an external repository path.

    The path must exist and be a directory. This is the only place source
    paths are validated before inspection.
    """
    if not source_path:
        raise ProjectError("project.yaml has no source.path")
    path = os.path.abspath(source_path)
    if not os.path.exists(path):
        raise ProjectError(f"Source path does not exist: {path}")
    if not os.path.isdir(path):
        raise ProjectError(f"Source path is not a directory: {path}")
    return path


def load_project(project_dir: str) -> Dict[str, Any]:
    """Load an AIOS project descriptor and resolve its source repository."""
    yaml_path = os.path.join(project_dir, "project.yaml")
    meta = load_mini_yaml(yaml_path)
    source = meta.get("source", {})
    source_path = resolve_source_path(source.get("path", ""))
    return {
        "project_dir": project_dir,
        "yaml_path": yaml_path,
        "metadata": meta,
        "source_path": source_path,
    }
