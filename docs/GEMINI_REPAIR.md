# Gemini repair provider

core.gemini_repair.GeminiRepairProvider is the model boundary for autonomous repair.

It accepts failure evidence plus a repository snapshot and returns a structured
repair proposal. It does not execute commands, modify repository state,
authorize effects, modify receipts, or decide PASS.

The returned proposal must flow through a LocalFixer enforcing file/path policy
and an independent Verifier executing regression/runtime checks.

Configuration:
- GEMINI_API_KEY: required
- GEMINI_MODEL: optional, defaults to gemini-2.5-flash

Gemini remains replaceable; model output never becomes authority.
