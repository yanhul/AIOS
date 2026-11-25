#!/usr/bin/env python3
"""AIOS authority signer: the ONLY process that holds the Ed25519 private key.

Run under a dedicated service account, outside execution runtimes and outside
GitHub Actions. Commands:

  keygen  --out PATH                 operator-only; writes a 0600 PEM key, prints
                                     the PUBLIC keyring entry (never the key)
  sign    --aios-dir D --permit-id P [--reissue]
  migrate --aios-dir D               re-issue every legacy HMAC attestation

``sign``/``migrate`` read the key from ``AIOS_AUTHORITY_SIGNING_KEY_FILE``.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.attestation import LEGACY_ALGORITHM, AttestationError, AuthoritySigner  # noqa: E402
from core.authority import (ATTESTATIONS_DIR, AUTHORITY_DIR, load_contract, load_permit,  # noqa: E402
                            persist_attestation)


def _keygen(out: str) -> int:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption())
    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)  # never overwrite a key
    with os.fdopen(fd, "wb") as fh:
        fh.write(pem)
    signer = AuthoritySigner(key)
    print(json.dumps({signer.key_id: {"public_key": signer.public_key_hex(), "status": "active"}}))
    return 0


def _sign(aios_dir: str, permit_id: str, signer: AuthoritySigner, reissue: bool) -> dict:
    permit = load_permit(aios_dir, permit_id)
    contract = load_contract(aios_dir, permit["contract_id"])
    return persist_attestation(aios_dir, contract, permit, signer, reissue=reissue)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="cmd", required=True)
    k = sub.add_parser("keygen"); k.add_argument("--out", required=True)
    s = sub.add_parser("sign"); s.add_argument("--aios-dir", required=True)
    s.add_argument("--permit-id", required=True); s.add_argument("--reissue", action="store_true")
    m = sub.add_parser("migrate"); m.add_argument("--aios-dir", required=True)
    args = parser.parse_args(argv)
    if args.cmd == "keygen":
        return _keygen(args.out)
    try:
        signer = AuthoritySigner.from_env()
    except AttestationError as exc:
        print(f"BLOCKED: {exc}", file=sys.stderr)
        return 2
    if args.cmd == "sign":
        att = _sign(args.aios_dir, args.permit_id, signer, args.reissue)
        print(json.dumps({"permit_id": att["permit_id"], "key_id": att["key_id"]}))
        return 0
    results = []
    root = Path(args.aios_dir) / AUTHORITY_DIR / ATTESTATIONS_DIR
    for path in sorted(root.glob("*.json")) if root.is_dir() else []:
        if json.loads(path.read_text(encoding="utf-8")).get("algorithm") != LEGACY_ALGORITHM:
            continue
        try:
            att = _sign(args.aios_dir, path.stem, signer, False)
            results.append({"permit_id": path.stem, "status": "REISSUED", "key_id": att["key_id"]})
        except Exception as exc:  # invalid/unauthorized permits stay unattested -> fail closed
            results.append({"permit_id": path.stem, "status": "BLOCKED", "reason": str(exc)})
    print(json.dumps({"migrated": results}, indent=2))
    return 1 if any(r["status"] == "BLOCKED" for r in results) else 0


if __name__ == "__main__":
    raise SystemExit(main())
