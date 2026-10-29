import os

import pytest

pytestmark = pytest.mark.db

DSN = os.environ.get("PG_DSN")


@pytest.fixture
def conn():  # type: ignore[no-untyped-def]
    if not DSN:
        pytest.skip("PG_DSN not set (copy .env.example to .env and run `make up`)")
    import psycopg

    # Deliberately not caught: PG_DSN set but DB down must FAIL, not skip.
    with psycopg.connect(DSN, connect_timeout=5) as c:
        yield c


def test_postgres_16(conn) -> None:  # type: ignore[no-untyped-def]
    version = conn.execute("SHOW server_version_num").fetchone()[0]
    assert int(version) // 10000 == 16


def test_scratch_schema_exists(conn) -> None:  # type: ignore[no-untyped-def]
    row = conn.execute(
        "SELECT 1 FROM information_schema.schemata WHERE schema_name = 'scratch'"
    ).fetchone()
    assert row is not None
