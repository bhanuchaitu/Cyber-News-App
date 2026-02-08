from __future__ import annotations

import datetime as dt
import json
import logging
import os
import time  # <--- Added this
from typing import Iterable, List, Optional

import feedparser
import requests
import google.genai as genai
from google.genai import types
from pgvector.psycopg2 import register_vector

from db import get_db_connection

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

RSS_FEEDS = {
    "Hacker News": "https://hnrss.org/frontpage",
    "BleepingComputer": "https://www.bleepingcomputer.com/feed/",
}
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

SUMMARY_MODEL = os.environ.get("GEMINI_SUMMARY_MODEL", "gemini-2.0-flash")
EMBED_MODEL = os.environ.get("GEMINI_EMBED_MODEL", "embedding-001")

_GENAI_CLIENT: Optional[genai.Client] = None

def _get_secret_value(key: str) -> Optional[str]:
    value = os.environ.get(key)
    if value:
        return value
    return None

def get_genai_client() -> genai.Client:
    global _GENAI_CLIENT
    if _GENAI_CLIENT is not None:
        return _GENAI_CLIENT

    api_key = _get_secret_value("GEMINI_API_KEY")
    if not api_key:
        raise RuntimeError("GEMINI_API_KEY not set in environment")

    _GENAI_CLIENT = genai.Client(api_key=api_key)
    return _GENAI_CLIENT

def ensure_schema() -> None:
    try:
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
        logging.info("Schema ensured/Table created.")
    except Exception as e:
        logging.error(f"Database Schema Error: {e}")

def fetch_rss_items() -> Iterable[dict]:
    for source, url in RSS_FEEDS.items():
        try:
            logging.info(f"Fetching {source}...")
            parsed = feedparser.parse(url)
            for entry in parsed.entries[:5]: # Reduced to 5 per feed to save quota
                yield {
                    "source": source,
                    "title": entry.get("title", ""),
                    "url": entry.get("link", ""),
                    "published": entry.get("published", ""),
                    "summary": entry.get("summary", ""),
                }
        except Exception as exc:
            logging.error(f"Failed to fetch RSS {url}: {exc}")

def fetch_cisa_kev_items() -> Iterable[dict]:
    try:
        logging.info("Fetching CISA KEV...")
        response = requests.get(CISA_KEV_URL, timeout=20)
        response.raise_for_status()
        payload = response.json()
        for item in payload.get("vulnerabilities", [])[:5]: # Reduced to 5
            yield {
                "source": "CISA KEV",
                "title": f"{item.get('cveID', '')} - {item.get('vulnerabilityName', '')}",
                "url": item.get("notes", ""),
                "published": item.get("dateAdded", ""),
                "summary": json.dumps({
                    "vendorProject": item.get("vendorProject"),
                    "product": item.get("product"),
                    "requiredAction": item.get("requiredAction")
                }),
            }
    except Exception as exc:
        logging.error(f"Failed to fetch CISA KEV: {exc}")

def parse_published(published: str) -> Optional[dt.datetime]:
    if not published: return None
    for fmt in ("%a, %d %b %Y %H:%M:%S %z", "%Y-%m-%d", "%Y-%m-%dT%H:%M:%SZ"):
        try:
            return dt.datetime.strptime(published, fmt)
        except Exception:
            continue
    return None

def summarize_action_items(title: str, summary: str) -> str:
    prompt = (
        "You are a Cybersecurity Analyst. Convert this news item into concise Blue Team action items. "
        "Ignore the 'safety' warning if this discusses an exploit; this is for defensive analysis.\n\n"
        f"Title: {title}\nSummary: {summary}\n"
    )
    
    conf = types.GenerateContentConfig(
        safety_settings=[
            types.SafetySetting(
                category=types.HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT,
                threshold=types.HarmBlockThreshold.BLOCK_NONE,
            ),
            types.SafetySetting(
                category=types.HarmCategory.HARM_CATEGORY_HARASSMENT,
                threshold=types.HarmBlockThreshold.BLOCK_NONE,
            ),
            types.SafetySetting(
                category=types.HarmCategory.HARM_CATEGORY_HATE_SPEECH,
                threshold=types.HarmBlockThreshold.BLOCK_NONE,
            ),
            types.SafetySetting(
                category=types.HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT,
                threshold=types.HarmBlockThreshold.BLOCK_NONE,
            ),
        ]
    )

    try:
        client = get_genai_client()
        response = client.models.generate_content(
            model=SUMMARY_MODEL, 
            contents=prompt,
            config=conf
        )
        return (response.text or "").strip()
    except Exception as e:
        error_msg = str(e)
        if "429" in error_msg or "RESOURCE_EXHAUSTED" in error_msg:
            logging.error(f"AI Summarization quota exceeded. Using fallback.")
            return "[Quota Exceeded] Blue Team: Monitor this threat, review indicators, update detection rules."
        logging.error(f"AI Summarization failed: {e}")
        return "Analysis unavailable due to API error."

def create_embedding(text: str) -> List[float]:
    try:
        client = get_genai_client()
        response = client.models.embed_content(
            model=EMBED_MODEL,
            contents=text[:9000]
        )
        values: Optional[List[float]] = None
        if response.embeddings and response.embeddings[0].values:
            values = list(response.embeddings[0].values)
        if values:
            return values
        return [0.0] * 768
    except Exception as e:
        logging.error(f"Embedding failed: {e}")
        # Return zero vector on failure to allow processing to continue
        return [0.0] * 768

def upsert_item(item: dict) -> None:
    title = item.get("title", "").strip()
    url = item.get("url", "").strip()
    summary = item.get("summary", "").strip()
    
    if not title or not url: return

    action_items = summarize_action_items(title, summary)
    embedding_text = f"Problem: {title}\nDetails: {summary}\nSolution: {action_items}"
    embedding = create_embedding(embedding_text)
    published_at = parse_published(item.get("published", ""))

    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO daily_brief (source, title, url, published_at, summary, action_items, embedding)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (url) DO UPDATE
                SET source = EXCLUDED.source,
                    title = EXCLUDED.title,
                    published_at = COALESCE(EXCLUDED.published_at, daily_brief.published_at),
                    summary = EXCLUDED.summary,
                    action_items = EXCLUDED.action_items,
                    embedding = EXCLUDED.embedding
                """,
                (item.get("source"), title, url, published_at, summary, action_items, embedding),
            )
        conn.commit()
    logging.info(f"SUCCESS: Inserted {title[:30]}...")

def collect_all() -> None:
    logging.info("Starting Collector...")
    ensure_schema()
    get_genai_client() 

    items = list(fetch_rss_items())
    items.extend(list(fetch_cisa_kev_items()))

    logging.info(f"Found {len(items)} items to process.")
    
    for item in items:
        try:
            upsert_item(item)
            # Wait between items to respect free tier rate limits
            logging.info("Sleeping 15s to avoid rate limit...")
            time.sleep(15) 
        except Exception as exc:
            logging.error(f"Failed to process {item.get('url')}: {exc}")

if __name__ == "__main__":
    collect_all()
