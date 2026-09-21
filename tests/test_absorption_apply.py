from research.absorption_apply import absorb

def test_absorb_requires_promotion_and_verification():
    e={"records":[{"candidate_id":"c1","source_ref":"s","source_digest":"sd","evidence_digest":"ed","adaptation":{"primitive":"durable_execution","signals":["retry"],"proposal":"p","target_surface":"new AIOS adapter/task only"}}]}
    v={"records":[{"candidate_id":"c1","claim":"AIOS_NATIVE_ADAPTATION_PROPOSAL_CONFORMS","test_digest":"td"}]}
    p={"decisions":[{"candidate_id":"c1","allowed":True,"verdict":"PROMOTE"}],"blocked":[]}
    r=absorb(e,v,p,run_id="r1")
    assert r["overall"]=="PASS" and r["absorbed_count"]==1
    assert r["records"][0]["status"]=="ABSORBED"
    assert r["records"][0]["source_mutation"] is False

def test_absorb_blocks_missing_lineage():
    r=absorb({"records":[]},{"records":[]},{"decisions":[{"candidate_id":"c1","allowed":True,"verdict":"PROMOTE"}],"blocked":[]},run_id="r2")
    assert r["overall"]=="BLOCKED" and r["absorbed_count"]==0