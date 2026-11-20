"""Gunicorn WSGI entrypoint for the private Cloud Run worker."""
from core.cloud_run_worker import create_production_app

app = create_production_app()
