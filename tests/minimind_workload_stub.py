"""Test-only MiniMind workload process (provider side, audit F-04/F-04.1).

Signs with its own Ed25519 private key read from its own key file (the
workload's secret store). The key never travels via argv, env or stdout.
Usage: python -I minimind_workload_stub.py <repo_root> <config.json>
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
sign_kwargs = dict(attempt_id=cfg.get("sign_attempt", attempt), provider_operation_id=cfg.get("sign_operation_id", opid),
                   outcome=cfg.get("sign_outcome", outcome),
                   observation={"minimind_receipt": cfg.get("sign_receipt", receipt)}, now=cfg.get("now"))
effect.update(cfg.get("sign_effect", {}))
if cfg.get("key_file"):
    from core.provider_ed25519 import Ed25519ReceiptSigner
    signer = Ed25519ReceiptSigner.from_pem_file(cfg.get("sign_as", "minimind"), cfg["key_file"], cfg.get("ttl", 300))
    envelope["authentication"] = signer.sign(effect=effect, **sign_kwargs)
elif cfg.get("hmac_key"):  # legacy HMAC receipt: must never be accepted for MiniMind
    from core.provider_authority import ProviderReceiptSigner
    signer = ProviderReceiptSigner(cfg.get("sign_as", "minimind"), cfg["hmac_key"], ttl_seconds=cfg.get("ttl", 300))
    envelope["authentication"] = signer.sign(effect=effect, **sign_kwargs)
if "authentication" in cfg:
    envelope["authentication"] = cfg["authentication"]
if cfg.get("mutate_auth"):
    envelope["authentication"].update(cfg["mutate_auth"])
for key in cfg.get("drop", []):
    envelope.pop(key, None)
envelope.update(cfg.get("extra", {}))
if cfg.get("save"):
    with open(cfg["save"], "w", encoding="utf-8") as fh:
        json.dump(envelope, fh)
sys.stdout.write(json.dumps(envelope))
