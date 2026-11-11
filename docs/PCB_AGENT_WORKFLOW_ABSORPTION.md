# PCB agent workflow absorption — validation helpers

Source reviewed: https://github.com/John-owo/pcb-agent-workflow

## Decision

- **ABSORB (adapted, read-only):** compare baseline and candidate KiCad XML netlists; compare schematic pin numbers with placed footprint pad numbers.
- **ABSORB (existing AIOS behavior, not duplicated here):** keep EDA verification behind AIOS-owned capability/receipt boundaries; keep release artifacts versioned and hashed.
- **ADAPT / not yet enabled:** call these helpers from a governed PCB task only after the workflow has an explicit baseline, candidate, and exported KiCad XML netlist. They are not automatically run against Altium source documents.
- **REJECT:** treating an agent's natural-language claim, a clean 3D render, a successful parser exit, or a single DRC result as proof that a physical board works.

## Commands

Export the schematic netlist using the KiCad CLI, then run:

```sh
python scripts/pcb_validation/compare_netlist.py baseline.xml candidate.xml
python scripts/pcb_validation/compare_netlist.py baseline.xml candidate.xml --names
python scripts/pcb_validation/check_pin_pad.py candidate.xml --pcb board.kicad_pcb
```

Exit contract:

- `0`: PASS for the exact narrow check performed.
- `1`: BLOCKED due to detected differences.
- `2`: INCONCLUSIVE because input could not be parsed or required structure was absent.

JSON output is intended for a caller to attach to an AIOS receipt. These scripts do not create authority permits, write design files, issue release approvals, or promote a capability.

## Limits and fail-closed interpretation

1. Netlist comparison checks connectivity groups and component metadata (value, footprint, fields and selected DNP/exclusion properties). Net names are optional. It does not prove the baseline design is correct.
2. Pin/pad comparison checks number-set equality for each reference. It cannot determine whether a symbol pin's electrical meaning is correct, whether a footprint is the right physical part, or whether extra pads are intentionally mechanical/NC. Every reported extra pad needs an explicit design-level disposition; do not silently waive it.
3. The pin/pad helper uses a conservative S-expression scanner for the placed board file. If a future KiCad syntax variant is not handled, treat the result as INCONCLUSIVE and update tests before using it in a gate.
4. A PASS applies only to these checks and these exact input bytes. It is not ERC, DRC, routing closure, CAM review, electrical validation, RF/EMC validation, or physical hardware verification.
5. Do not run this against a PDF-derived reconstruction as if it were ground truth. First preserve source provenance and mark uncertain pin/net mappings; uncertain inputs remain BLOCKED/INCONCLUSIVE.
6. This adaptation is not a copy of the upstream release-package or CAM-review scripts. Those should be considered separately after their dependency, input, and evidence contracts are audited.

## Evidence and lineage expected from the future governed caller

Record input paths and SHA-256 digests, baseline/candidate revision, KiCad version, command line, exit code, stdout/stderr, and script revision. Bind the receipt to the exact task/effect/attempt. After interruption, re-read the files and revalidate hashes before deciding whether the attempt completed. Never reinterpret missing output or a nonzero process exit as PASS.

## Upstream attribution

The design of these two narrow checks was adapted from the public repository above. AIOS keeps its own interfaces and terminal semantics; the upstream project is a reference, not an authority source.
