"""Test env: prefix + header auth mirror the original duplet deployment so the
ported tests keep their URLs/redirect expectations. SQLite is never touched —
db functions are stubbed per test."""

import os

os.environ.setdefault("KAIROS_PREFIX", "/scheduler")
os.environ.setdefault("KAIROS_AUTH", "header")
os.environ.setdefault("KAIROS_LOGIN_URL", "/login")
os.environ.setdefault("SESSION_SECRET", "dummy")
os.environ.setdefault("KAIROS_DB_URL", "sqlite:///:memory:")
