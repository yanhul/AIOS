"""Fail-closed reconciliation for the AIOS autonomous repository-repair flow.

This is deliberately separate from core.reconcile, whose scope is the entity /
verification snapshot store. Here we reconcile persisted authority/effect/receipt
records with the exact proposal patch and the trusted test result.
"""
from __future__ import annotations

import hashlib
import json
import os
from typing import Mapping, Sequence

from .authority import authorize, load_contract, load_permit
from .effect_authority import (
    ProviderKeyring, _effect_rel, _load,
    _verify_provider_receipt,
)
from .evidence import verify_evidence
from .mutation import TransitionError, canonical_json


def patch_digest(files: Sequence[Mapping[str, str]]) -> str:
    payload = "".join(
        f"{item['path']}\0{hashlib.sha256(item['content'].encode('utf-8')).hexdigest()}\0"
        for item in files
    ).encode('utf-8')
    return hashlib.sha256(payload).hexdigest()


def compute_test_evidence_digest(test: Mapping[str, object]) -> str:
    body = {k: v for k, v in test.items() if k != 'digest'}
    return hashlib.sha256(canonical_json(body).encode('utf-8')).hexdigest()


def reconcile_repair(
    aios_dir: str | os.PathLike[str], *, contract_id: str, permit_id: str,
    actor: str, repository: str, run_id: int, base_sha: str, effects: Sequence[Mapping[str, object]],
    proposals: Sequence[Mapping[str, object]], test: Mapping[str, object],
    provider_keyring: ProviderKeyring | None = None,
) -> dict:
    """Verify permit, every persisted effect/receipt, exact patch and trusted tests.

    Raises TransitionError on any mismatch. Returns a compact, deterministic
    reconciliation record only when every link in the chain is verified.
    """
    root = str(aios_dir)
    authorize(root, contract_id, permit_id)
    contract = load_contract(root, contract_id)
    permit = load_permit(root, permit_id)
    if contract.get('actor') != actor or permit.get('actor') != actor:
        raise TransitionError('repair actor does not match persisted contract and permit')
    if not isinstance(run_id, int) or isinstance(run_id, bool) or run_id <= 0:
        raise TransitionError('repair run_id must be a positive integer')
    if not isinstance(repository, str) or repository.count('/') != 1 or any(not part for part in repository.split('/')):
        raise TransitionError('repair repository must be owner/name')
    expected_input = 'sha256:' + hashlib.sha256(f'ci-failure:{repository}:{run_id}:{base_sha}'.encode()).hexdigest()
    if contract.get('input_digest') != expected_input:
        raise TransitionError('execution contract is not bound to this repository/run/base')
    if not isinstance(base_sha, str) or len(base_sha) != 40:
        raise TransitionError('repair base_sha must be a full commit SHA')
    if provider_keyring is None:
        provider_keyring = ProviderKeyring.from_env()
    if not isinstance(provider_keyring, ProviderKeyring):
        raise TransitionError('trusted provider keyring is required for repair reconciliation')
    if not effects or len(effects) != len(proposals):
        raise TransitionError('effect/proposal cardinality mismatch')

    reconciled_effects = []
    final_paths: dict[str, str] = {}
    for effect_item, proposal in zip(effects, proposals):
        if effect_item.get('attempt') != proposal.get('attempt'):
            raise TransitionError('effect/proposal attempt binding mismatch')
        if (proposal.get('run_id') != run_id or proposal.get('repository') != repository
                or proposal.get('base_sha') != base_sha or proposal.get('schema') != 2):
            raise TransitionError('proposal repository/run/schema/base binding mismatch')
        effect_id = effect_item.get('effect_id')
        if not isinstance(effect_id, str) or not effect_id:
            raise TransitionError('missing effect_id in repair result')
        effect_path = os.path.join(root, _effect_rel(effect_id))
        effect = _load(effect_path)
        if effect.get('effect_id') != effect_id or effect.get('state') != 'OBSERVED_SUCCESS':
            raise TransitionError(f'effect {effect_id} is not OBSERVED_SUCCESS')
        if effect.get('actor') != actor or effect.get('contract_id') != contract_id or effect.get('permit_id') != permit_id:
            raise TransitionError(f'effect {effect_id} authority binding mismatch')
        if effect.get('provider') != 'repo_patch':
            raise TransitionError(f'effect {effect_id} provider mismatch')
        observed = effect.get('provider_observation')
        if not isinstance(observed, dict) or observed.get('provider') != 'repo_patch':
            raise TransitionError(f'effect {effect_id} has no accepted provider observation')
        raw = observed.get('observation')
        auth = observed.get('provider_authentication')
        if not isinstance(raw, dict) or not isinstance(auth, dict):
            raise TransitionError(f'effect {effect_id} receipt authentication is missing')
        verifier_input = {
            'provider': observed.get('provider'),
            'provider_operation_id': observed.get('provider_operation_id'),
            'observation': raw,
            'authentication': auth,
        }
        # Reconciliation is an authority decision, not a historical signature
        # check. Verify against the current clock: replaying a once-valid receipt
        # after its signed validity window must fail closed, even if the stored
        # effect claims OBSERVED_SUCCESS.
        _verify_provider_receipt(effect, 'OBSERVED_SUCCESS', verifier_input, provider_keyring, None)
        ev = observed.get('evidence')
        if not isinstance(ev, dict) or not verify_evidence(ev):
            raise TransitionError(f'effect {effect_id} AIOS-minted evidence is invalid')
        if ev.get('run_id') != effect.get('attempt_id') or ev.get('provider') != 'repo_patch':
            raise TransitionError(f'effect {effect_id} evidence lineage mismatch')
        files = proposal.get('files')
        if not isinstance(files, list) or not files:
            raise TransitionError(f'effect {effect_id} proposal files are missing')
        expected_digest = patch_digest(files)
        if raw.get('patch_digest') != expected_digest or raw.get('base_sha') != base_sha:
            raise TransitionError(f'effect {effect_id} receipt does not bind the proposal patch/base')
        changed = raw.get('changed')
        expected = sorted(({'path': x['path'], 'content_sha256': hashlib.sha256(x['content'].encode('utf-8')).hexdigest()}
                           for x in files), key=lambda x: x['path'])
        if not isinstance(changed, list) or sorted(changed, key=lambda x: x.get('path', '')) != expected:
            raise TransitionError(f'effect {effect_id} receipt changed-path evidence mismatch')
        for item in files:
            final_paths[item['path']] = item['content']
        reconciled_effects.append({
            'effect_id': effect_id, 'attempt_id': effect.get('attempt_id'),
            'state': effect.get('state'), 'receipt_id': auth.get('receipt_id'),
            'patch_digest': expected_digest, 'evidence_id': ev.get('evidence_id'),
        })

    if not isinstance(test, dict) or test.get('status') != 'PASS':
        raise TransitionError('trusted tests did not PASS')
    if (test.get('base_sha') != base_sha or test.get('run_id') != run_id
            or test.get('repository') != repository):
        raise TransitionError('trusted test evidence repository/run/base binding mismatch')
    cumulative_digest = patch_digest([{'path': k, 'content': v} for k, v in sorted(final_paths.items())])
    if test.get('patch_digest') != cumulative_digest:
        raise TransitionError('trusted test evidence is not bound to the final cumulative patch')
    results = test.get('results')
    if not isinstance(results, list) or not results:
        raise TransitionError('trusted test evidence has no command results')
    for result in results:
        if result.get('command') != ['python', '-m', 'pytest', '-q'] or result.get('returncode') != 0:
            raise TransitionError('test command is not trusted or did not exit successfully')
    expected_refs = [f"test:{index}:{result['returncode']}" for index, result in enumerate(results)]
    if test.get('evidence_refs') != expected_refs:
        raise TransitionError('trusted test evidence references do not match command results')
    if test.get('digest') != compute_test_evidence_digest(test):
        raise TransitionError('trusted test evidence digest mismatch')

    return {
        'status': 'RECONCILED', 'run_id': run_id, 'base_sha': base_sha,
        'contract_id': contract_id, 'permit_id': permit_id,
        'effects': reconciled_effects, 'patch_digest': cumulative_digest,
        'test_digest': test['digest'], 'changed_paths': sorted(final_paths),
    }


__all__ = ['patch_digest', 'compute_test_evidence_digest', 'reconcile_repair']
