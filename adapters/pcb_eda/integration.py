"""AIOS runtime bridge for governed PCB/EDA workloads."""

from __future__ import annotations

from pathlib import Path

from core.runtime import execute


def execute_pcb_eda(
    aios_dir: Path,
    contract_id: str,
    permit_id: str,
    logical_operation_id: str,
    actor: str,
    adapter,
    *,
    input_dir: Path,
    output_dir: Path,
    durable_runtime=None,
):
    """Run one PCB/EDA operation through the normal AIOS effect/attempt boundary.

    The adapter remains domain-owned; AIOS owns authorization, effect creation,
    dispatch, observation and durable-runtime submission.
    """
    # The adapter contract carries the filesystem locations as effect metadata.
    # The standard runtime remains the authority boundary.
    class BoundAdapter:
        name = adapter.name

        def execute(self, *, contract, effect, attempt_id):
            bound_effect = dict(effect)
            bound_effect["input_dir"] = str(input_dir)
            bound_effect["output_dir"] = str(output_dir)
            return adapter.execute(
                contract=contract,
                effect=bound_effect,
                attempt_id=attempt_id,
                input_dir=input_dir,
                output_dir=output_dir,
            )

    return execute(
        aios_dir,
        contract_id,
        permit_id,
        logical_operation_id,
        actor,
        BoundAdapter(),
        durable_runtime=durable_runtime,
    )


__all__ = ["execute_pcb_eda"]
