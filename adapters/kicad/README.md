# KiCad provider for AIOS (candidate)

This provider is deliberately read-only and is not activated in the capability
registry. AIOS must authorize the provider via the existing contract/permit and
must validate the returned `ProviderReceipt` through `core.runtime`.

Supported operations:
- `project_inspect`: record file metadata and SHA-256 without invoking KiCad.
- `erc_check`: invoke `kicad-cli sch erc` for a `.kicad_sch` input.
- `drc_check`: invoke `kicad-cli pcb drc` for a `.kicad_pcb` input.

The deployment must pass `workspace_root` and `project_path`
to the adapter configuration (for example,
`KicadAdapter(workspace_root="/workspace", project_path="design.kicad_sch")`).
Do not add provider-specific fields to the immutable AIOS execution contract.

The dispatched effect must bind `effect_id`, `attempt_id` and an allowlisted
operation via AIOS's `logical_operation_id`. The source file must be inside the
authorized workspace. The adapter uses `shell=False`, bounded timeout/output,
and verifies the source hash remains unchanged. ERC/DRC reports are written
under `.aios-kicad-reports/` inside that workspace; this is a bounded provider
artifact write, not a source-project mutation.

Important limitations:
- This adapter does not create or authorize contracts or permits.
- `OBSERVED_SUCCESS` means the CLI process returned zero; it does NOT mean
  the schematic/PCB passed electrical acceptance. `quality_verdict` remains
  `NOT_ASSESSED` until an independent verifier interprets the report.
- CLI timeout/exception leaves outcome ambiguous and must be reconciled by the
  AIOS durable runtime; do not blindly replay.
- No repair, Gerber export, promotion, merge, deployment, or production action
  is enabled. The manifest is a candidate only and registry activation is a
  separate governed decision.
