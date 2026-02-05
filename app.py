from __future__ import annotations

import os
from typing import List, Optional

from google import genai
import streamlit as st
from pgvector.psycopg2 import register_vector

from db import get_db_connection

SUMMARY_MODEL = os.environ.get("GEMINI_SUMMARY_MODEL", "gemini-2.0-flash")
EMBED_MODEL = os.environ.get("GEMINI_EMBED_MODEL", "text-embedding-004")

_GENAI_CLIENT: Optional[genai.Client] = None


st.set_page_config(page_title="Cyber-Daily", page_icon="🛡️", layout="wide")


def _get_secret_value(key: str) -> Optional[str]:
    value = os.environ.get(key)
    if value:
        return value
    if key in st.secrets:
        return st.secrets[key]
    return None


def get_genai_client() -> Optional[genai.Client]:
    global _GENAI_CLIENT
    if _GENAI_CLIENT is not None:
        return _GENAI_CLIENT

    api_key = _get_secret_value("GEMINI_API_KEY")
    if not api_key:
        return None

    _GENAI_CLIENT = genai.Client(api_key=api_key)
    return _GENAI_CLIENT


def create_embedding(text: str) -> List[float]:
    client = get_genai_client()
    if not client:
        return [0.0] * 768
    # Update: Add [:9000] to match collector.py safety
    response = client.models.embed_content(model=EMBED_MODEL, contents=text[:9000])
    if response.embeddings:
        return response.embeddings[0].values
    return [0.0] * 768


@st.cache_data(ttl=300)
def fetch_daily_brief(limit: int = 100):
    with get_db_connection() as conn:
        register_vector(conn)
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT source, title, url, published_at, summary, action_items, date_added
                FROM daily_brief
                ORDER BY date_added DESC
                LIMIT %s
                """,
                (limit,),
            )
            return cur.fetchall()


@st.cache_data(ttl=300)
def search_briefs(query: str, limit: int = 20):
    embedding = create_embedding(query)
    with get_db_connection() as conn:
        register_vector(conn)
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT source, title, url, published_at, summary, action_items, date_added
                FROM daily_brief
                ORDER BY embedding <-> %s
                LIMIT %s
                """,
                (embedding, limit),
            )
            return cur.fetchall()


st.title("Cyber-Daily Threat Intelligence")
st.caption("Daily briefings generated from public sources with Blue Team action items.")

ai_ready = get_genai_client() is not None
if not ai_ready:
    st.warning("GEMINI_API_KEY is not set. Search is disabled until the key is configured in Streamlit secrets or environment variables.")

search_query = st.text_input(
    "Search past vulnerabilities and fixes",
    "",
    disabled=not ai_ready,
)

if ai_ready and search_query.strip():
    results = search_briefs(search_query.strip())
    st.subheader("Search Results")
else:
    results = fetch_daily_brief()
    st.subheader("Daily Briefing")

for source, title, url, published_at, summary, action_items, date_added in results:
    with st.container(border=True):
        st.markdown(f"**{title}**")
        st.write(f"Source: {source}")
        if published_at:
            st.write(f"Published: {published_at}")
        st.write(f"Added: {date_added}")
        if url:
            st.link_button("Open Source", url)
        if summary:
            st.markdown("**Summary**")
            st.write(summary)
        if action_items:
            st.markdown("**Blue Team Action Items**")
            st.write(action_items)
