"""Shared pytest setup.

Sets dummy env vars BEFORE any backend module is imported, so `backend.config`
doesn't raise KeyError when tests import auth/clients/etc.
"""
import os

os.environ.setdefault("ANTHROPIC_API_KEY", "test-anthropic-key")
os.environ.setdefault("VIRUSTOTAL_API_KEY", "test-virustotal-key")
os.environ.setdefault("SAFEBROWSING_API_KEY", "test-safebrowsing-key")
os.environ.setdefault("URLSCAN_API_KEY", "test-urlscan-key")
os.environ.setdefault("ALLOWED_USERS", "test@example.com")
os.environ.setdefault("OIDC_AUDIENCE", "http://localhost:8080")
