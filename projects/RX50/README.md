# AIOS — RX50 Project Reference

## What this directory is

This directory contains AIOS-side metadata ONLY for the RX50 project. It is NOT a copy of the RX50 repository.

- The actual RX50 engineering repository lives at `E:\Projects\RX50` (referenced by `project.yaml`).
- RX50 remains an independent engineering repository governed by its own rules (`E:\Projects\RX50\AGENTS.md`).
- AIOS does not own, copy, move, rename, or modify RX50 source files.
- AIOS state and RX50 source are separate.

## Contents

- `project.yaml` — external repository reference (the only pointer to RX50).
- `.aios/` — future AIOS state directories, currently EMPTY (requirements, decisions, evidence, issues, tasks, snapshots, events).

## Current status

- M0: scaffolding only. No RX50 data has been imported. No `.aios/` state has been written.
- M1 (next): controlled, read-only import of RX50 authoritative registers into AIOS state.
