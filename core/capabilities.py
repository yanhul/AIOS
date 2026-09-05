"""AIOS capability identity, registry, graph, and durable persistence."""
from __future__ import annotations
import json
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Iterable
from .mutation import commit_batch
ALLOWED_EDGE_TYPES=frozenset({"requires","produces","composes_with","validated_by","works_under"})
VERIFICATION_LEVELS=frozenset({"OBSERVED","EVIDENCED","VERIFIED_DIGITAL","VERIFIED_PHYSICAL","PROMOTED"})
CAPABILITY_STATE_FILE="capabilities/capability_registry.json"
class CapabilityError(ValueError): pass
@dataclass(frozen=True)
class Capability:
 capability_id:str; version:str; owner:str; kind:str; inputs:tuple[str,...]=(); outputs:tuple[str,...]=(); permissions:tuple[str,...]=(); environments:tuple[str,...]=(); verification_methods:tuple[str,...]=(); evidence_requirements:tuple[str,...]=(); provenance:tuple[str,...]=(); dependencies:tuple[str,...]=(); status:str="CANDIDATE"; metadata:tuple[tuple[str,str],...]=()
 def __post_init__(self):
  for n,v in (("capability_id",self.capability_id),("version",self.version),("owner",self.owner),("kind",self.kind)):
   if not isinstance(v,str) or not v: raise CapabilityError(f"{n} must be a non-empty string")
  if self.status not in {"CANDIDATE","ACTIVE","DEPRECATED"}: raise CapabilityError("invalid capability status")
 @property
 def key(self): return f"{self.capability_id}@{self.version}"
 def as_dict(self): return {"capability_id":self.capability_id,"version":self.version,"owner":self.owner,"kind":self.kind,"inputs":list(self.inputs),"outputs":list(self.outputs),"permissions":list(self.permissions),"environments":list(self.environments),"verification_methods":list(self.verification_methods),"evidence_requirements":list(self.evidence_requirements),"provenance":list(self.provenance),"dependencies":list(self.dependencies),"status":self.status,"metadata":[list(x) for x in self.metadata]}
 @classmethod
 def from_dict(cls,v):
  try: return cls(v["capability_id"],v["version"],v["owner"],v["kind"],tuple(v.get("inputs",())),tuple(v.get("outputs",())),tuple(v.get("permissions",())),tuple(v.get("environments",())),tuple(v.get("verification_methods",())),tuple(v.get("evidence_requirements",())),tuple(v.get("provenance",())),tuple(v.get("dependencies",())),v.get("status","CANDIDATE"),tuple(tuple(x) for x in v.get("metadata",())))
  except (KeyError,TypeError,ValueError) as e: raise CapabilityError(f"invalid persisted capability: {e}") from e
@dataclass(frozen=True)
class CapabilityEdge:
 source:str; relation:str; target:str; evidence_refs:tuple[str,...]=(); verification_level:str="OBSERVED"
 def __post_init__(self):
  if self.relation not in ALLOWED_EDGE_TYPES: raise CapabilityError(f"unsupported relationship: {self.relation}")
  if not self.source or not self.target: raise CapabilityError("edge endpoints are required")
  if not self.evidence_refs or any(not isinstance(r,str) or not r.strip() for r in self.evidence_refs): raise CapabilityError("capability relationships require explicit evidence references")
  if self.verification_level not in VERIFICATION_LEVELS: raise CapabilityError("invalid verification level")
 def as_dict(self): return {"source":self.source,"relation":self.relation,"target":self.target,"evidence_refs":list(self.evidence_refs),"verification_level":self.verification_level}
 @classmethod
 def from_dict(cls,v):
  try: return cls(v["source"],v["relation"],v["target"],tuple(v.get("evidence_refs",())),v.get("verification_level","OBSERVED"))
  except (KeyError,TypeError,ValueError) as e: raise CapabilityError(f"invalid persisted capability edge: {e}") from e
class CapabilityRegistry:
 def __init__(self): self._capabilities={}; self._edges={}
 def register(self,c):
  e=self._capabilities.get(c.key)
  if e is not None and e!=c: raise CapabilityError(f"capability version already registered: {c.key}")
  self._capabilities[c.key]=c; return c
 def activate(self,key):
  c=self.require(key)
  if c.status=="DEPRECATED": raise CapabilityError(f"deprecated capability cannot be activated: {key}")
  c=replace(c,status="ACTIVE"); self._capabilities[key]=c; return c
 def get(self,capability_id,version=None):
  if version is not None: return self._capabilities.get(f"{capability_id}@{version}")
  m=[c for c in self._capabilities.values() if c.capability_id==capability_id]; a=[c for c in m if c.status=="ACTIVE"]; return sorted(a or m,key=lambda c:c.version)[-1] if m else None
 def require(self,key):
  if not isinstance(key,str) or "@" not in key: raise CapabilityError(f"capability reference must be versioned: {key!r}")
  c=self._capabilities.get(key)
  if c is None: raise CapabilityError(f"capability is not registered: {key}")
  return c
 def require_active(self,key):
  c=self.require(key)
  if c.status!="ACTIVE": raise CapabilityError(f"capability is not active: {key}")
  return c
 def resolve_contract(self,contract):
  if not isinstance(contract,dict) or not isinstance(contract.get("capabilities"),list): raise CapabilityError("contract capabilities must be a list")
  return tuple(self.require_active(k) for k in contract["capabilities"])
 def discover(self,*,kind=None,required_inputs=(),required_outputs=(),environment=None,permission=None):
  ri=set(required_inputs); ro=set(required_outputs); out=[]
  for c in self._capabilities.values():
   if c.status=="DEPRECATED" or (kind is not None and c.kind!=kind) or not ri.issubset(c.inputs) or not ro.issubset(c.outputs) or (environment is not None and environment not in c.environments) or (permission is not None and permission not in c.permissions): continue
   out.append(c)
  return sorted(out,key=lambda c:c.key)
 def add_edge(self,e):
  if e.source not in self._capabilities or e.target not in self._capabilities: raise CapabilityError("capability relationship endpoints must be registered")
  self._edges[(e.source,e.relation,e.target)]=e; return e
 def graph(self): return tuple(self._edges[k] for k in sorted(self._edges))
 def relationships(self,*,source=None,relation=None,target=None): return tuple(e for e in self.graph() if (source is None or e.source==source) and (relation is None or e.relation==relation) and (target is None or e.target==target))
 def snapshot(self): return {"capabilities":[c.as_dict() for c in sorted(self._capabilities.values(),key=lambda c:c.key)],"edges":[e.as_dict() for e in self.graph()]}
 def persist(self,aios_dir,actor):
  _=actor
  committed=commit_batch(aios_dir,[(CAPABILITY_STATE_FILE,self.snapshot())])
  return committed[0]
 @classmethod
 def load(cls,aios_dir):
  p=Path(aios_dir)/CAPABILITY_STATE_FILE
  if not p.exists(): raise CapabilityError(f"capability registry is missing: {p}")
  try: record=json.loads(p.read_text(encoding="utf-8"))
  except (OSError,json.JSONDecodeError) as e: raise CapabilityError(f"invalid capability registry JSON: {e}") from e
  try:
   r=cls()
   for v in record["capabilities"]: r.register(Capability.from_dict(v))
   for v in record.get("edges",()): r.add_edge(CapabilityEdge.from_dict(v))
   return r
  except (KeyError,TypeError,ValueError) as e: raise CapabilityError(f"invalid persisted capability registry: {e}") from e
__all__=["Capability","CapabilityEdge","CapabilityError","CapabilityRegistry"]