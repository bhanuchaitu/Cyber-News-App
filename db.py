from __future__ import annotations

import os
from typing import Optional

import psycopg2


def _get_secret_value(key: str) -> Optional[str]:
    value = os.environ.get(key)
    if value:
        return value

    try:
        import streamlit as st

        if key in st.secrets:
            return st.secrets[key]
    except Exception:
        return None

    return None


def get_db_connection() -> psycopg2.extensions.connection:
    try:
        from dotenv import load_dotenv

        load_dotenv()
    except Exception:
        pass

    conn_str = _get_secret_value("DB_CONNECTION_STRING")
    if not conn_str:
        raise RuntimeError("DB_CONNECTION_STRING not set in environment or secrets")

    return psycopg2.connect(conn_str, connect_timeout=10)
