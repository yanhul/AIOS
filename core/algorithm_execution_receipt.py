"""Independent verification of TRY's deterministic algorithm receipts.

This verifier does not authenticate that TRY executed code. It independently
checks the exact input/specification bindings and recomputes the result with a
separate shortest-path implementation. A successful result is not a permit,
attestation, evidence promotion, or capability absorption.
"""
from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable, Mapping
from heapq import heappop, heappush
from typing import Any

from .mutation import canonical_json

SCHEMA = "try.algorithm-execution-receipt.v1"
_OPERATION = "maze.shortest_path"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_GIT_REVISION = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")


class AlgorithmExecutionReceiptError(ValueError):
    """The receipt cannot be independently verified against its contract."""


def _digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _parse_grid(grid: Iterable[str]):
    if isinstance(grid, (str, bytes)):
        raise AlgorithmExecutionReceiptError("grid must be a sequence of row strings")
    try:
        rows = tuple(grid)
    except TypeError as exc:
        raise AlgorithmExecutionReceiptError("grid must be iterable") from exc
    if not rows or any(not isinstance(row, str) for row in rows):
        raise AlgorithmExecutionReceiptError("grid must contain non-empty string rows")
    width = len(rows[0])
    if width == 0 or any(len(row) != width for row in rows):
        raise AlgorithmExecutionReceiptError("grid must be rectangular and non-empty")
    if len(rows) * width > 1_000_000:
        raise AlgorithmExecutionReceiptError("grid exceeds 1,000,000 cells")
    if any(ch not in "#.SG" for row in rows for ch in row):
        raise AlgorithmExecutionReceiptError("grid contains unsupported cell values")
    starts = [(r, c) for r, row in enumerate(rows) for c, ch in enumerate(row) if ch == "S"]
    goals = [(r, c) for r, row in enumerate(rows) for c, ch in enumerate(row) if ch == "G"]
    if len(starts) != 1 or len(goals) != 1:
        raise AlgorithmExecutionReceiptError("grid must contain exactly one S and one G")
    return rows, starts[0], goals[0]


def _independent_shortest_distance(rows, start, goal):
    """Dijkstra oracle with independent state and traversal implementation."""
    distances = {start: 0}
    pending = [(0, start[0], start[1])]
    moves = ((0, 1), (1, 0), (0, -1), (-1, 0))
    while pending:
        distance, row, col = heappop(pending)
        point = (row, col)
        if distances.get(point) != distance:
            continue
        if point == goal:
            return distance
        for dr, dc in moves:
            nr, nc = row + dr, col + dc
            neighbor = (nr, nc)
            if (0 <= nr < len(rows) and 0 <= nc < len(rows[0])
                    and rows[nr][nc] != "#"):
                candidate = distance + 1
                if candidate < distances.get(neighbor, 1 << 60):
                    distances[neighbor] = candidate
                    heappush(pending, (candidate, nr, nc))
    return None


def verify_algorithm_execution_receipt(
    receipt: Mapping[str, Any],
    *,
    grid: Iterable[str],
    spec: Mapping[str, Any],
    expected_executor_revision: str,
    expected_executor_sha256: str,
) -> dict[str, Any]:
    """Independently verify a TRY receipt for a contract-pinned execution.

    Callers must supply the expected grid/spec and immutable executor revision
    and source digest from their governing contract/policy. No receipt field is
    trusted merely because TRY labels it VERIFIED.
    """
    required = {
        "schema", "spec", "spec_sha256", "input_sha256", "executor_revision",
        "executor_sha256", "candidate", "candidate_sha256", "verification",
        "decision", "promotion", "receipt_sha256",
    }
    if not isinstance(receipt, Mapping) or set(receipt) != required:
        raise AlgorithmExecutionReceiptError("receipt schema mismatch")
    if receipt.get("schema") != SCHEMA:
        raise AlgorithmExecutionReceiptError("receipt schema version mismatch")
    if not isinstance(spec, Mapping) or dict(spec) != receipt.get("spec"):
        raise AlgorithmExecutionReceiptError("specification binding mismatch")
    if set(spec) != {"operation", "version", "max_expansions"}:
        raise AlgorithmExecutionReceiptError("specification schema mismatch")
    if spec.get("operation") != _OPERATION or type(spec.get("version")) is not int or spec["version"] != 1:
        raise AlgorithmExecutionReceiptError("unsupported algorithm specification")
    budget = spec.get("max_expansions")
    if type(budget) is not int or not 1 <= budget <= 1_000_000:
        raise AlgorithmExecutionReceiptError("specification expansion budget is invalid")
    rows, start, goal = _parse_grid(grid)
    canonical_grid = list(rows)
    if receipt.get("spec_sha256") != _digest(dict(spec)):
        raise AlgorithmExecutionReceiptError("specification digest mismatch")
    if receipt.get("input_sha256") != _digest(canonical_grid):
        raise AlgorithmExecutionReceiptError("input digest mismatch")
    if (not isinstance(expected_executor_revision, str)
            or not _GIT_REVISION.fullmatch(expected_executor_revision)
            or receipt.get("executor_revision") != expected_executor_revision):
        raise AlgorithmExecutionReceiptError("executor revision is not bound to contract")
    if (not isinstance(expected_executor_sha256, str)
            or not _SHA256.fullmatch(expected_executor_sha256)
            or receipt.get("executor_sha256") != expected_executor_sha256):
        raise AlgorithmExecutionReceiptError("executor source digest is not bound to contract")
    candidate = receipt.get("candidate")
    if not isinstance(candidate, Mapping) or set(candidate) != {"path", "expansions"}:
        raise AlgorithmExecutionReceiptError("candidate schema mismatch")
    if type(candidate.get("expansions")) is not int or not 1 <= candidate["expansions"] <= budget:
        raise AlgorithmExecutionReceiptError("candidate expansion count exceeds contract budget")
    if receipt.get("candidate_sha256") != _digest(dict(candidate)):
        raise AlgorithmExecutionReceiptError("candidate digest mismatch")
    if receipt.get("decision") != "VERIFIED" or receipt.get("promotion") != "NOT_REQUESTED":
        raise AlgorithmExecutionReceiptError("receipt decision or promotion state is not acceptable")
    # The nested TRY verification object is informational only. Recompute it here.
    path = candidate.get("path")
    oracle_distance = _independent_shortest_distance(rows, start, goal)
    if path is None:
        if oracle_distance is not None:
            raise AlgorithmExecutionReceiptError("candidate omitted a reachable path")
        candidate_distance = None
    else:
        if not isinstance(path, list) or not path:
            raise AlgorithmExecutionReceiptError("candidate path schema is invalid")
        points = []
        for point in path:
            if (not isinstance(point, list) or len(point) != 2
                    or any(type(value) is not int for value in point)):
                raise AlgorithmExecutionReceiptError("candidate coordinates are invalid")
            row, col = point
            if not (0 <= row < len(rows) and 0 <= col < len(rows[0])):
                raise AlgorithmExecutionReceiptError("candidate coordinate is out of bounds")
            if rows[row][col] == "#":
                raise AlgorithmExecutionReceiptError("candidate path crosses a wall")
            points.append((row, col))
        if points[0] != start or points[-1] != goal:
            raise AlgorithmExecutionReceiptError("candidate endpoints do not match grid")
        for left, right in zip(points, points[1:]):
            if abs(left[0] - right[0]) + abs(left[1] - right[1]) != 1:
                raise AlgorithmExecutionReceiptError("candidate path has non-adjacent steps")
        candidate_distance = len(points) - 1
        if oracle_distance is None or candidate_distance != oracle_distance:
            raise AlgorithmExecutionReceiptError("candidate is not a shortest path")
    unsigned = {key: value for key, value in receipt.items() if key != "receipt_sha256"}
    if receipt.get("receipt_sha256") != _digest(unsigned):
        raise AlgorithmExecutionReceiptError("receipt checksum mismatch")
    return {
        "status": "INDEPENDENTLY_VERIFIED",
        "oracle_distance": oracle_distance,
        "candidate_distance": candidate_distance,
        "input_sha256": receipt["input_sha256"],
        "spec_sha256": receipt["spec_sha256"],
        "executor_revision": expected_executor_revision,
        "executor_sha256": expected_executor_sha256,
        "promotion": "NOT_AUTHORIZED",
    }


__all__ = ["AlgorithmExecutionReceiptError", "verify_algorithm_execution_receipt"]
