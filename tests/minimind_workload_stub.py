"""Test-only MiniMind workload process (provider side).

Holds its own signing key (passed via a config file = the workload's own
secret store), never via the AIOS parent environment.
Usage: python minimind_workload_stub.py <repo_root> <config.json>
"""
import json
import os
import sys

repo, cfg_path = sys.argv[1], sys.argv[2]
sys.path.insert(0, repo)
with open(cfg_path, encoding="utf-8") as fh:
    cfg = json.load(fh)
request = json.load(sys.stdin)
if cfg.get("env_report"):
    with open(cfg["env_report"], "w", encoding="utf-8") as fh:
        json.dump(sorted(k for k in os.environ if k.startswith("AIOS_")), fh)
if cfg.get("replay"):
    with open(cfg["replay"], encoding="utf-8") as fh:
        sys.stdout.write(fh.read())
    sys.exit(0)
if "raw_stdout" in cfg:
    sys.stdout.write(cfg["raw_stdout"])
    sys.exit(0)

contract, effect, attempt = request["contract"], dict(request["effect"]), request["attempt_id"]
receipt = cfg["receipt"]
outcome = cfg.get("outcome") or ("OBSERVED_SUCCESS" if receipt["terminal_state"] == "PROMOTE" else "OBSERVED_FAILURE")
opid = cfg.get("operation_id") or f"minimind:{contract['task_id']}:{attempt}"
envelope = {"minimind_receipt": receipt, "outcome": outcome, "provider_operation_id": opid}
if cfg.get("key"):
    from core.provider_authority import ProviderReceiptSigner
    effect.update(cfg.get("sign_effect", {}))
    signer = ProviderReceiptSigner(cfg.get("sign_as", "minimind"), cfg["key"], ttl_seconds=cfg.get("ttl", 300))
    envelope["authentication"] = signer.sign(
        effect=effect, attempt_id=cfg.get("sign_attempt", attempt), provider_operation_id=opid,
        outcome=cfg.get("sign_outcome", outcome),
        observation={"minimind_receipt": cfg.get("sign_receipt", receipt)}, now=cfg.get("now"))
if "authentication" in cfg:
    envelope["authentication"] = cfg["authentication"]
for key in cfg.get("drop", []):
    envelope.pop(key, None)
envelope.update(cfg.get("extra", {}))
if cfg.get("save"):
    with open(cfg["save"], "w", encoding="utf-8") as fh:
        json.dump(envelope, fh)
sys.stdout.write(json.dumps(envelope))
