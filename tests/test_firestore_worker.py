import pytest

from core.firestore_worker import (
    WorkerBootstrapBlocked,
    create_firestore_effect_store,
    create_production_worker,
)


def test_adc_factory_requires_explicit_firestore_only_guard():
    with pytest.raises(WorkerBootstrapBlocked, match="guard"):
        create_firestore_effect_store(environ={"AIOS_FIRESTORE_PROJECT_ID": "test"})


def test_adc_factory_requires_explicit_project():
    with pytest.raises(WorkerBootstrapBlocked, match="PROJECT_ID"):
        create_firestore_effect_store(environ={"AIOS_REQUIRE_FIRESTORE_EFFECT_STORE": "true"})


def test_production_worker_never_accepts_filesystem_authority():
    with pytest.raises(WorkerBootstrapBlocked, match="filesystem authority"):
        create_production_worker(environ={"AIOS_AUTHORITY_BACKEND": "filesystem"})


def test_production_worker_does_not_treat_backend_label_as_implementation():
    with pytest.raises(WorkerBootstrapBlocked, match="not implemented"):
        create_production_worker(environ={"AIOS_AUTHORITY_BACKEND": "firestore"})
