from core.ci_watchdog import CIWatch, CIWatchError, classify_watch


def w(**kw):
    data = dict(
        repository="yanhul/AIOS",
        workflow="CI",
        run_id=1,
        sha="a" * 40,
        status="in_progress",
        conclusion=None,
        age_seconds=10,
    )
    data.update(kw)
    return CIWatch(**data)


def test_in_progress_is_watched():
    assert classify_watch(w()) == "WATCH"


def test_queued_run_has_bounded_timeout():
    assert classify_watch(w(status="queued", age_seconds=600)) == "CANCEL_AND_RETRY"


def test_running_run_has_bounded_timeout():
    assert classify_watch(w(age_seconds=1800)) == "CANCEL_AND_RETRY"


def test_retry_budget_exhaustion_blocks():
    assert classify_watch(w(age_seconds=1800, retry_count=2)) == "BLOCKED"


def test_success_without_evidence_cannot_pass():
    assert classify_watch(w(status="completed", conclusion="success")) == "VERIFY_EVIDENCE"


def test_success_with_evidence_can_verify():
    assert classify_watch(w(status="completed", conclusion="success", evidence_present=True)) == "VERIFY"


def test_failure_goes_to_diagnosis():
    assert classify_watch(w(status="completed", conclusion="failure")) == "DIAGNOSE"


def test_invalid_status_fails_closed():
    try:
        classify_watch(w(status="PASS"))
    except CIWatchError:
        pass
    else:
        raise AssertionError("invalid status accepted")
