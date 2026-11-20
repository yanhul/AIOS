"""Extension namespace for deployment-owned, provider-specific read-only adapters.

The base repository intentionally ships no provider adapter implementation.
A deployment must install its reviewed adapter module under this namespace.
"""
from pkgutil import extend_path

__path__ = extend_path(__path__, __name__)
