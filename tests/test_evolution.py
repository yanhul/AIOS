# AIOS-CONTRACT: evolution cannot bypass evaluation or authorization
# AIOS-REGRESSION: admission/promotion require explicit predecessor evidence
# AIOS-OWNER: AIOS control-plane evolution authority
# AIOS-COVERAGE-GAP: TRY adapter referenced an evolution API absent from current core
# AIOS-BASELINE: no strict compatibility facade existed
import pytest
from core.evolution import Candidate, EvaluationEvidence, admit, promote, record_evaluation, transition

def candidate():
    return Candidate("c1",None,"try://c1",0,{"consumer":"TRY"})

def evidence(status="PASS"):
    return EvaluationEvidence("eval:v1",{"status":status},{"status":status},("try://evidence/1",))

def test_full_governed_path():
    c=transition(candidate(),"CHALLENGER")
    c=record_evaluation(c,evidence(),evaluator_digest="eval:v1")
    c=admit(c)
    c=promote(c,authorize=lambda _: True)
    assert c.state=="ACTIVE"

def test_missing_evaluation_blocks_admission():
    with pytest.raises(ValueError,match="evaluation"): admit(candidate())

def test_failed_evaluation_blocks():
    c=transition(candidate(),"CHALLENGER")
    with pytest.raises(ValueError,match="PASS"): record_evaluation(c,evidence("FAIL"),evaluator_digest="eval:v1")

def test_authorization_denial_blocks_promotion():
    c=transition(candidate(),"CHALLENGER")
    c=record_evaluation(c,evidence(),evaluator_digest="eval:v1")
    c=admit(c)
    with pytest.raises(PermissionError): promote(c,authorize=lambda _: False)
