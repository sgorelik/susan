"""Postgres connect_args for Railway and other hosts."""
from __future__ import annotations

import db


def test_railway_internal_no_ssl() -> None:
    url = "postgresql://postgres:pw@postgres.railway.internal:5432/railway"
    assert db._postgres_connect_args(url) == {}


def test_railway_public_proxy_insecure_ssl() -> None:
    url = "postgresql://postgres:pw@roundhouse.proxy.rlwy.net:12345/railway"
    args = db._postgres_connect_args(url)
    assert "ssl" in args
    assert args["ssl"].verify_mode.name == "CERT_NONE"


def test_localhost_no_ssl() -> None:
    assert db._postgres_connect_args("postgresql://u:p@localhost:5432/db") == {}
