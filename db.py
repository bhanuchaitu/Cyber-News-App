import os
from contextlib import contextmanager
from typing import Iterator, Any

try:
    import psycopg2
    from psycopg2.extensions import connection as _PGConnection
except Exception:  # pragma: no cover - environment may not have psycopg2 installed
    psycopg2 = None
    _PGConnection = object

@contextmanager
def get_db_connection() -> Iterator[Any]:
    """Context manager that yields a psycopg2 connection.

    Expects a `DATABASE_URL` environment variable (DSN). Raises RuntimeError if not set.
    """
    dsn = os.environ.get("DATABASE_URL")
    if not dsn:
        raise RuntimeError("DATABASE_URL not set in environment")
    if psycopg2 is None:
        raise RuntimeError("psycopg2 is not installed in the current environment")

    conn = psycopg2.connect(dsn)
    try:
        yield conn
    finally:
        try:
            conn.close()
        except Exception:
            pass
