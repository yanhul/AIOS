# AIOS Daily Ecosystem Research

This lane is separate from TRY's autonomous trading research.

Daily flow:

`DISCOVER -> DEDUP -> RESEARCH METADATA -> PROVENANCE -> GOVERNED REVIEW -> ABSORB`

The scanner may discover and research public repositories. It must not automatically
change AIOS policy, authority, evidence requirements, gates, terminal conditions, or
source code.

Each run writes `latest.json` as a provenance-bearing research artifact. An
absorption decision is a separate governed action.

## Evidence boundary

Repository metadata and README digest are discovery evidence, not proof that a
pattern works in AIOS. Any proposed absorption must be independently verified
against the AIOS acceptance suite before promotion.
