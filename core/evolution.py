"""AIOS-native evolution facade for governed TRY admission.

This is intentionally small: it exposes the adapter contract while delegating
the real authority boundary to explicit state, evidence, and authorization
checks. It is not a training framework.
"""
from __future__ import annotations
from dataclasses import dataclass, field, replace
from hashlib import sha256
import json
from typing import Any, Callable, Mapping

def _digest(v:Any)->str:
    return sha256(json.dumps(v,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()).hexdigest()

@dataclass(frozen=True)
class EvaluationEvidence:
    evaluator_digest:str
    held_in:Mapping[str,Any]
    held_out:Mapping[str,Any]
    evidence_refs:tuple[str,...]
    def __post_init__(self):
        if not self.evaluator_digest.strip(): raise ValueError("evaluator_digest required")
        if not self.evidence_refs or any(not x.strip() for x in self.evidence_refs):
            raise ValueError("evidence_refs required")

@dataclass(frozen=True)
class Candidate:
    candidate_id:str
    parent_id:str|None
    artifact_ref:str
    lineage_depth:int
    metadata:Mapping[str,Any]
    state:str="DISCOVERED"
    evaluation:EvaluationEvidence|None=None
    evidence_digest:str|None=None

_ALLOWED={
    "DISCOVERED":"CHALLENGER",
    "CHALLENGER":"EVALUATED",
    "EVALUATED":"ADMITTED",
    "ADMITTED":"ACTIVE",
}

def transition(candidate:Candidate,target:str)->Candidate:
    if _ALLOWED.get(candidate.state)!=target:
        raise ValueError(f"invalid evolution transition {candidate.state}->{target}")
    return replace(candidate,state=target)

def record_evaluation(candidate:Candidate,evidence:EvaluationEvidence,*,evaluator_digest:str)->Candidate:
    if candidate.state!="EVALUATED" and candidate.state!="CHALLENGER":
        raise ValueError("candidate is not evaluation-ready")
    if evaluator_digest!=evidence.evaluator_digest:
        raise ValueError("evaluator digest mismatch")
    if evidence.held_in.get("status")!="PASS" or evidence.held_out.get("status")!="PASS":
        raise ValueError("evaluation evidence is not PASS")
    d=_digest({
        "candidate_id":candidate.candidate_id,
        "evaluator_digest":evidence.evaluator_digest,
        "held_in":dict(evidence.held_in),
        "held_out":dict(evidence.held_out),
        "evidence_refs":list(evidence.evidence_refs),
    })
    return replace(candidate,state="EVALUATED",evaluation=evidence,evidence_digest=d)

def admit(candidate:Candidate,*,required_status:str="PASS")->Candidate:
    if candidate.state!="EVALUATED" or candidate.evaluation is None:
        raise ValueError("candidate lacks governed evaluation")
    if required_status!="PASS": raise ValueError("unsupported admission requirement")
    if candidate.evaluation.held_in.get("status")!="PASS" or candidate.evaluation.held_out.get("status")!="PASS":
        raise ValueError("admission requires PASS evaluation")
    return transition(candidate,"ADMITTED")

def promote(candidate:Candidate,*,authorize:Callable[[Candidate],Any])->Candidate:
    if candidate.state!="ADMITTED" or candidate.evidence_digest is None:
        raise ValueError("promotion requires admitted candidate with evidence")
    if authorize(candidate) is False:
        raise PermissionError("promotion authorization denied")
    return transition(candidate,"ACTIVE")

def candidate_digest(candidate:Candidate)->str:
    return _digest({
        "candidate_id":candidate.candidate_id,"parent_id":candidate.parent_id,
        "artifact_ref":candidate.artifact_ref,"lineage_depth":candidate.lineage_depth,
        "metadata":dict(candidate.metadata),"state":candidate.state,
        "evidence_digest":candidate.evidence_digest,
    })
