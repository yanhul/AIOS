"""AIOS verification of signed algorithm-worker artifacts.

The worker signature authenticates provenance and content digests. This module
then hashes the exact artifact bytes and independently checks the shortest path;
neither step grants promotion or retry authority.
"""
from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from heapq import heappop, heappush
from typing import Any, Iterable

from .algorithm_worker_receipt import verify_algorithm_worker_receipt
from .mutation import canonical_json

MAX_ARTIFACT_BYTES = 256_000
_ARTIFACT_SCHEMA = "try.algorithm-artifact.v1"
_OPERATION = "maze.shortest_path"


class AlgorithmWorkerArtifactError(ValueError):
    """The signed worker artifact is missing, malformed, or incorrect."""


def _reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise AlgorithmWorkerArtifactError("artifact contains duplicate JSON keys")
        result[key] = value
    return result


def _parse_grid(grid: Iterable[str]):
    if isinstance(grid, (str, bytes)):
        raise AlgorithmWorkerArtifactError("grid must be a sequence of row strings")
    try:
        rows = tuple(grid)
    except TypeError as exc:
        raise AlgorithmWorkerArtifactError("grid must be iterable") from exc
    if not rows or any(not isinstance(row, str) for row in rows):
        raise AlgorithmWorkerArtifactError("grid must contain string rows")
    width = len(rows[0])
    if width < 1 or any(len(row) != width for row in rows):
        raise AlgorithmWorkerArtifactError("grid must be rectangular and non-empty")
    if len(rows) * width > 10_000:
        raise AlgorithmWorkerArtifactError("grid exceeds worker runtime limit")
    if any(cell not in "#.SG" for row in rows for cell in row):
        raise AlgorithmWorkerArtifactError("grid contains unsupported cells")
    starts = [(r, c) for r, row in enumerate(rows) for c, cell in enumerate(row) if cell == "S"]
    goals = [(r, c) for r, row in enumerate(rows) for c, cell in enumerate(row) if cell == "G"]
    if len(starts) != 1 or len(goals) != 1:
        raise AlgorithmWorkerArtifactError("grid must contain exactly one S and one G")
    return rows, starts[0], goals[0]


def _shortest_distance(rows, start, goal):
    distances = {start: 0}
    pending = [(0, start[0], start[1])]
    # Independent Dijkstra ordering, separate from the worker's BFS implementation.
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


def verify_algorithm_worker_artifact(
    receipt: Mapping[str, Any],
    artifact_bytes: bytes,
    *,
    expected: Mapping[str, Any],
    grid: Iterable[str],
    spec: Mapping[str, Any],
    expected_executor_revision: str,
    expected_executor_sha256: str,
    keyring=None,
    now=None,
) -> dict[str, Any]:
    """Authenticate worker provenance, hash exact bytes, and verify result optimality.

    `expected` must be reconstructed from AIOS contract, permit, effect,
    dispatch and attempt records—not copied from the worker response.
    """
    if not isinstance(artifact_bytes, bytes) or not artifact_bytes or len(artifact_bytes) > MAX_ARTIFACT_BYTES:
        raise AlgorithmWorkerArtifactError("artifact byte length is invalid")
    if not isinstance(spec, Mapping) or set(spec) != {"operation", "version", "max_expansions"}:
        raise AlgorithmWorkerArtifactError("algorithm spec schema mismatch")
    if (spec.get("operation") != _OPERATION or type(spec.get("version")) is not int
            or spec.get("version") != 1):
        raise AlgorithmWorkerArtifactError("unsupported algorithm spec")
    budget = spec.get("max_expansions")
    if type(budget) is not int or not 1 <= budget <= 100_000:
        raise AlgorithmWorkerArtifactError("algorithm expansion budget is invalid")
    rows, start, goal = _parse_grid(grid)
    canonical_input = {"grid": list(rows)}
    spec_digest = hashlib.sha256(canonical_json(dict(spec)).encode("utf-8")).hexdigest()
    input_digest = hashlib.sha256(canonical_json(canonical_input).encode("utf-8")).hexdigest()
    if expected.get("spec_sha256") != spec_digest or expected.get("input_sha256") != input_digest:
        raise AlgorithmWorkerArtifactError("AIOS expected spec/input digests do not match supplied input")
    if expected.get("executor_revision") != expected_executor_revision:
        raise AlgorithmWorkerArtifactError("AIOS expected executor revision mismatch")
    if expected.get("executor_sha256") != expected_executor_sha256:
        raise AlgorithmWorkerArtifactError("AIOS expected executor source digest mismatch")

    authenticated = verify_algorithm_worker_receipt(
        receipt, expected=expected, keyring=keyring, now=now
    )
    if authenticated.get("status") != "INDEPENDENTLY_AUTHENTICATED":
        raise AlgorithmWorkerArtifactError("worker receipt is UNKNOWN; artifact cannot be promoted")
    exact_digest = hashlib.sha256(artifact_bytes).hexdigest()
    if exact_digest != receipt.get("artifact_sha256"):
        raise AlgorithmWorkerArtifactError("artifact bytes do not match signed artifact_sha256")
    try:
        artifact = json.loads(
            artifact_bytes.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                AlgorithmWorkerArtifactError("artifact contains non-finite JSON number")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AlgorithmWorkerArtifactError("artifact JSON is invalid") from exc
    if not isinstance(artifact, dict) or set(artifact) != {
        "schema", "operation", "version", "path", "expansions"
    }:
        raise AlgorithmWorkerArtifactError("artifact schema mismatch")
    if (artifact.get("schema") != _ARTIFACT_SCHEMA
            or artifact.get("operation") != _OPERATION
            or type(artifact.get("version")) is not int
            or artifact.get("version") != 1):
        raise AlgorithmWorkerArtifactError("artifact operation identity mismatch")
    expansions = artifact.get("expansions")
    if type(expansions) is not int or not 1 <= expansions <= budget:
        raise AlgorithmWorkerArtifactError("artifact expansion count exceeds budget")
    canonical_artifact = canonical_json(artifact).encode("utf-8")
    if canonical_artifact != artifact_bytes:
        raise AlgorithmWorkerArtifactError("artifact bytes are not canonical JSON")
    output_digest = hashlib.sha256(canonical_artifact).hexdigest()
    if output_digest != receipt.get("output_sha256"):
        raise AlgorithmWorkerArtifactError("artifact output digest does not match signed output_sha256")

    oracle_distance = _shortest_distance(rows, start, goal)
    path = artifact.get("path")
    if path is None:
        if oracle_distance is not None:
            raise AlgorithmWorkerArtifactError("artifact omitted a reachable path")
        path_distance = None
    else:
        if not isinstance(path, list) or not path:
            raise AlgorithmWorkerArtifactError("artifact path schema is invalid")
        points = []
        for point in path:
            if (not isinstance(point, list) or len(point) != 2
                    or any(type(value) is not int for value in point)):
                raise AlgorithmWorkerArtifactError("artifact path coordinate is invalid")
            row, col = point
            if not (0 <= row < len(rows) and 0 <= col < len(rows[0])):
                raise AlgorithmWorkerArtifactError("artifact path coordinate is out of bounds")
            if rows[row][col] == "#":
                raise AlgorithmWorkerArtifactError("artifact path crosses a wall")
            points.append((row, col))
        if points[0] != start or points[-1] != goal:
            raise AlgorithmWorkerArtifactError("artifact path endpoints are invalid")
        for left, right in zip(points, points[1:]):
            if abs(left[0] - right[0]) + abs(left[1] - right[1]) != 1:
                raise AlgorithmWorkerArtifactError("artifact path has non-adjacent steps")
        path_distance = len(points) - 1
        if oracle_distance is None or path_distance != oracle_distance:
            raise AlgorithmWorkerArtifactError("artifact path is not shortest")

    return {
        "status": "INDEPENDENTLY_VERIFIED",
        "receipt_id": authenticated["receipt_id"],
        "artifact_sha256": exact_digest,
        "output_sha256": output_digest,
        "spec_sha256": spec_digest,
        "input_sha256": input_digest,
        "oracle_distance": oracle_distance,
        "candidate_distance": path_distance,
        "retry_authorized": False,
        "promotion": "NOT_AUTHORIZED",
    }


__all__ = ["AlgorithmWorkerArtifactError", "verify_algorithm_worker_artifact"]
