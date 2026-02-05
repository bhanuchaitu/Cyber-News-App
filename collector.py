from __future__ import annotations

import datetime as dt
import json
import logging
import os
from typing import Iterable, List, Optional

import feedparser
import google.generativeai as genai
import requests
from pgvector.psycopg2 import register_vector

from db import get_db_connection

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

RSS_FEEDS = {
    "Hacker News": "https://hnrss.org/frontpage",
    "BleepingComputer": "https://www.bleepingcomputer.com/feed/",
}
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

SUMMARY_MODEL = "gemini-1.5-flash"
EMBED_MODEL = "models/embedding-001"


def _get_secret_value(key: str) -> Optional[str]:
    value = os.environ.get(key)
    if value:
        return value
    return None


def configure_genai() -> None:
    api_key = _get_secret_value("GEMINI_API_KEY")
    if not api_key:
        raise RuntimeError("GEMINI_API_KEY not set in environment")
    genai.configure(api_key=api_key)


def ensure_schema() -> None:
    with get_db_connection() as conn:
        register_vector(conn)
        with conn.cursor() as cur:
            cur.execute("CREATE EXTENSION IF NOT EXISTS vector")
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS daily_brief (
                    id SERIAL PRIMARY KEY,
                    source TEXT NOT NULL,
                    title TEXT NOT NULL,
                    url TEXT NOT NULL UNIQUE,
                    published_at TIMESTAMPTZ,
                    summary TEXT,
                    action_items TEXT,
                    embedding VECTOR(768),
                    date_added TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
                """
            )
        conn.commit()


def fetch_rss_items() -> Iterable[dict]:
    for source, url in RSS_FEEDS.items():
        try:
            parsed = feedparser.parse(url)
            if parsed.bozo:
                logging.warning("Feed parse issue for %s: %s", url, parsed.bozo_exception)
            for entry in parsed.entries[:25]:
                yield {
                    "source": source,
                    "title": entry.get("title", ""),
                    "url": entry.get("link", ""),
                    "published": entry.get("published", ""),
                    "summary": entry.get("summary", ""),
                }
        except Exception as exc:
            logging.exception("Failed to fetch RSS feed %s: %s", url, exc)
            continue


def fetch_cisa_kev_items() -> Iterable[dict]:
    try:
        response = requests.get(CISA_KEV_URL, timeout=20)
        response.raise_for_status()
        payload = response.json()
        for item in payload.get("vulnerabilities", [])[:50]:
            yield {
                "source": "CISA KEV",
                "title": f"{item.get('cveID', '')} - {item.get('vulnerabilityName', '')}",
                "url": item.get("notes", ""),
                "published": item.get("dateAdded", ""),
                "summary": json.dumps(
                    {
                        "vendorProject": item.get("vendorProject"),
                        "product": item.get("product"),
                        "shortDescription": item.get("shortDescription"),
                        "requiredAction": item.get("requiredAction"),
                        "dueDate": item.get("dueDate"),
                    }
                ),
            }
    except Exception as exc:
        logging.exception("Failed to fetch CISA KEV: %s", exc)


def parse_published(published: str) -> Optional[dt.datetime]:
    if not published:
        return None
    for fmt in (
        "%a, %d %b %Y %H:%M:%S %z",
        "%Y-%m-%d",
        "%Y-%m-%dT%H:%M:%SZ",
    ):
        try:
            return dt.datetime.strptime(published, fmt)
        except Exception:
            continue
    return None


def summarize_action_items(title: str, summary: str) -> str:
    prompt = (
        "You are a SOC analyst. Convert the item into concise Blue Team action items. "
        "Output 3-6 bullet points with verbs.\n\n"
        f"Title: {title}\n"
        f"Summary: {summary}\n"
    )
    model = genai.GenerativeModel(SUMMARY_MODEL)
    response = model.generate_content(prompt)
    return response.text.strip()


def create_embedding(text: str) -> List[float]:
    response = genai.embed_content(model=EMBED_MODEL, content=text)
    return response["embedding"]


def upsert_item(item: dict) -> None:
    title = item.get("title", "").strip()
    url = item.get("url", "").strip()
    summary = item.get("summary", "").strip()
    if not title or not url:
        return

    action_items = summarize_action_items(title, summary)
    embedding_text = f"Problem: {title}\nDetails: {summary}\nSolution: {action_items}"
    embedding = create_embedding(embedding_text)
    published_at = parse_published(item.get("published", ""))

    with get_db_connection() as conn:
        register_vector(conn)
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO daily_brief (source, title, url, published_at, summary, action_items, embedding)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (url) DO UPDATE
                SET summary = EXCLUDED.summary,
                    action_items = EXCLUDED.action_items,
                    embedding = EXCLUDED.embedding,
                    published_at = COALESCE(EXCLUDED.published_at, daily_brief.published_at)
                """,
                (
                    item.get("source", ""),
                    title,
                    url,
                    published_at,
                    summary,
                    action_items,
                    embedding,
                ),
            )
        conn.commit()


def collect_all() -> None:
    ensure_schema()
    configure_genai()

    items = list(fetch_rss_items())
    items.extend(list(fetch_cisa_kev_items()))

    logging.info("Processing %s items", len(items))
    for item in items:
        try:
            upsert_item(item)
        except Exception as exc:
            logging.exception("Failed to process item %s: %s", item.get("url"), exc)


if __name__ == "__main__":
    collect_all()
