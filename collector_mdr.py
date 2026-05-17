"""
Lean Cyber News Collector

Collects RSS items, enriches CVEs, scores signal, and stores a focused
daily brief in Supabase.
"""

from __future__ import annotations

import os
import re
import sys
import time
from datetime import datetime, timedelta, timezone
from typing import Any

import feedparser
import requests
from dotenv import load_dotenv
from supabase import Client, create_client

from attack_mapping import extract_attack_name, map_to_kill_chain, map_to_mitre_attack
from date_utils import parse_feed_date_utc
from mdr_intelligence import (
    build_evidence_list,
    calculate_signal_strength,
    calculate_threat_velocity,
    classify_unknown_reason,
    determine_exploitation_status,
    determine_source_confidence,
    extract_delta_reason,
    extract_pattern_tags,
    extract_technical_method,
    generate_mdr_analyst_take,
    generate_story_hash,
    normalize_event,
)


if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]


load_dotenv()

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")

if not SUPABASE_URL or not SUPABASE_KEY:
    raise RuntimeError("SUPABASE_URL and SUPABASE_KEY are required")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

MAX_ITEMS_PER_SOURCE = int(os.getenv("MAX_ITEMS_PER_SOURCE", "15"))
NVD_DELAY_SECONDS = float(os.getenv("NVD_DELAY_SECONDS", "2"))

RSS_FEEDS = {
    "BleepingComputer": "https://www.bleepingcomputer.com/feed/",
    "Krebs on Security": "https://krebsonsecurity.com/feed/",
    "Schneier on Security": "https://www.schneier.com/feed/atom/",
    "The Hacker News": "https://feeds.feedburner.com/TheHackersNews",
    "Dark Reading": "https://www.darkreading.com/rss.xml",
}

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

_kev_cache: list[dict[str, Any]] | None = None
_kev_fetched_at: datetime | None = None
_session = requests.Session()


def clean_html(text: str) -> str:
    text = re.sub(r"<[^>]+>", "", text or "")
    return re.sub(r"\s+", " ", text).strip()


def extract_cve_id(text: str) -> str | None:
    match = re.search(r"CVE-\d{4}-\d{4,7}", text, re.IGNORECASE)
    return match.group(0).upper() if match else None


def enrich_cve_from_nvd(cve_id: str) -> dict[str, Any]:
    try:
        response = _session.get(NVD_URL, params={"cveId": cve_id}, timeout=15)
        response.raise_for_status()
        payload = response.json()
        vulnerabilities = payload.get("vulnerabilities", [])
        if not vulnerabilities:
            return {"cve_id": cve_id, "cvss_score": None, "cvss_vector": None, "cve_published_date": None}

        cve = vulnerabilities[0].get("cve", {})
        metrics = cve.get("metrics", {})
        cvss_score = None
        cvss_vector = None

        for metric_name in ("cvssMetricV31", "cvssMetricV30"):
            metric = metrics.get(metric_name)
            if metric:
                cvss = metric[0].get("cvssData", {})
                cvss_score = cvss.get("baseScore")
                cvss_vector = cvss.get("vectorString")
                break

        return {
            "cve_id": cve_id,
            "cvss_score": cvss_score,
            "cvss_vector": cvss_vector,
            "cve_published_date": (cve.get("published") or "")[:10] or None,
        }
    except Exception as exc:
        print(f"Warning: NVD lookup failed for {cve_id}: {exc}")
        return {"cve_id": cve_id, "cvss_score": None, "cvss_vector": None, "cve_published_date": None}


def get_cisa_kev() -> list[dict[str, Any]]:
    global _kev_cache, _kev_fetched_at

    now = datetime.now(timezone.utc)
    if _kev_cache is not None and _kev_fetched_at and now - _kev_fetched_at < timedelta(hours=1):
        return _kev_cache

    try:
        response = _session.get(KEV_URL, timeout=20)
        response.raise_for_status()
        _kev_cache = response.json().get("vulnerabilities", [])
        _kev_fetched_at = now
    except Exception as exc:
        print(f"Warning: CISA KEV fetch failed: {exc}")
        _kev_cache = _kev_cache or []

    return _kev_cache


def check_cisa_kev(cve_id: str) -> bool:
    return any(item.get("cveID") == cve_id for item in get_cisa_kev())


def calculate_weaponization_speed(cve_published_date: str | None, article_date: str) -> int | None:
    if not cve_published_date:
        return None

    try:
        disclosure = datetime.fromisoformat(cve_published_date).replace(tzinfo=timezone.utc)
        article = datetime.fromisoformat(article_date)
        return max(0, (article - disclosure).days)
    except Exception:
        return None


def process_entry(source_name: str, entry: Any) -> dict[str, Any] | None:
    title = str(entry.get("title", "")).strip()
    url = str(entry.get("link", "")).strip()
    raw_summary = entry.get("summary", entry.get("description", ""))
    summary = clean_html(str(raw_summary))[:700]

    if not title or not url:
        return None

    if getattr(entry, "published_parsed", None):
        published_at = parse_feed_date_utc(entry.published_parsed)
    elif getattr(entry, "updated_parsed", None):
        published_at = parse_feed_date_utc(entry.updated_parsed)
    else:
        published_at = parse_feed_date_utc(None)

    cve_id = extract_cve_id(f"{title} {summary}")
    cve_data: dict[str, Any] = {}
    cisa_exploited = False

    if cve_id:
        cve_data = enrich_cve_from_nvd(cve_id)
        cisa_exploited = check_cisa_kev(cve_id)
        time.sleep(NVD_DELAY_SECONDS)

    event_data = normalize_event(title, summary, "", cve_id)
    exploitation_status = determine_exploitation_status(title, summary, cisa_exploited, bool(cve_id))
    source_confidence = determine_source_confidence(source_name, url, title)
    attack_name = extract_attack_name(title, summary)
    mitre_mapping = map_to_mitre_attack(title, summary)
    kill_chain_phases = map_to_kill_chain(title, summary)
    technical_method = extract_technical_method(title, summary, event_data["attack_vector"])
    has_technical_detail = len(summary) > 300

    signal_strength, signal_reason = calculate_signal_strength(
        exploitation_status=exploitation_status,
        source_confidence=source_confidence,
        has_cve=bool(cve_id),
        cvss_score=cve_data.get("cvss_score"),
        cisa_exploited=cisa_exploited,
        has_technical_detail=has_technical_detail,
        article_body_length=len(summary),
    )

    first_observed_date = cve_data.get("cve_published_date") or published_at[:10]
    weaponization_speed = calculate_weaponization_speed(cve_data.get("cve_published_date"), published_at)
    evidence_sources, evidence_count = build_evidence_list(
        cisa_exploited,
        source_name,
        cve_data.get("cvss_score"),
        has_technical_detail,
        cve_id,
        exploitation_status,
    )

    return {
        "source": source_name,
        "title": title,
        "url": url,
        "summary": summary,
        "published_at": published_at,
        "event_type": event_data["event_type"],
        "primary_target": event_data["primary_target"],
        "attack_vector": event_data["attack_vector"],
        "impact_outcome": event_data["impact_outcome"],
        "first_observed_date": first_observed_date,
        "exploitation_status": exploitation_status,
        "weaponization_speed": weaponization_speed,
        "mdr_analyst_take": generate_mdr_analyst_take(
            event_data["event_type"],
            event_data["primary_target"],
            event_data["attack_vector"],
            exploitation_status,
            title,
            summary,
            cve_id,
            cve_data.get("cvss_score"),
            attack_name,
        ),
        "technical_method": technical_method,
        "delta_reason": extract_delta_reason(title, summary, exploitation_status),
        "signal_strength": signal_strength,
        "signal_strength_reason": signal_reason,
        "source_confidence": source_confidence,
        "has_technical_detail": has_technical_detail,
        "article_quality_score": min(100, len(summary) // 5),
        "evidence_sources": evidence_sources,
        "evidence_count": evidence_count,
        "threat_velocity": calculate_threat_velocity(
            first_observed_date,
            exploitation_status,
            cve_data.get("cve_published_date"),
        ),
        "unknown_reason": (
            classify_unknown_reason(title, summary, cve_id, source_name)
            if exploitation_status == "unknown"
            else None
        ),
        "last_collector_run": datetime.now(timezone.utc).isoformat(),
        "pattern_tags": extract_pattern_tags(title, summary, event_data["attack_vector"], event_data["event_type"]),
        "story_hash": generate_story_hash(cve_id, None, attack_name, event_data["primary_target"]),
        "cve_id": cve_id,
        "cvss_score": cve_data.get("cvss_score"),
        "cvss_vector": cve_data.get("cvss_vector"),
        "cve_published_date": cve_data.get("cve_published_date"),
        "cisa_exploited": cisa_exploited,
        "attack_name": attack_name,
        "mitre_tactics": mitre_mapping["tactics"],
        "mitre_techniques": mitre_mapping["techniques"],
        "kill_chain_phases": kill_chain_phases,
        "has_iocs": bool(cve_id),
    }


def collect_rss_feeds() -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    print("Collecting cyber news feeds...")

    for source_name, feed_url in RSS_FEEDS.items():
        try:
            feed = feedparser.parse(feed_url)
            entries = getattr(feed, "entries", [])
            count = 0

            for entry in entries[:MAX_ITEMS_PER_SOURCE]:
                try:
                    item = process_entry(source_name, entry)
                    if item:
                        items.append(item)
                        count += 1
                        print(f"  [{item['signal_strength']}] {source_name}: {item['title'][:70]}")
                except Exception as exc:
                    print(f"  Warning: failed to process {source_name} entry: {exc}")

            print(f"Collected {count} items from {source_name}")
        except Exception as exc:
            print(f"Warning: failed to fetch {source_name}: {exc}")

    return items


def apply_escalation_metadata(item: dict[str, Any]) -> dict[str, Any]:
    existing = (
        supabase.table("daily_brief")
        .select("id, exploitation_status, signal_strength")
        .eq("url", item["url"])
        .execute()
    )

    if not existing.data:
        return item

    old_record = existing.data[0]
    old_status = str(old_record.get("exploitation_status") or "unknown")
    old_signal = str(old_record.get("signal_strength") or "Low")
    new_status = str(item.get("exploitation_status") or "unknown")
    new_signal = str(item.get("signal_strength") or "Low")

    status_rank = {"unknown": 0, "theoretical": 1, "poc_available": 2, "actively_exploited": 3}
    signal_rank = {"Low": 0, "Medium": 1, "High": 2}

    if status_rank.get(new_status, 0) > status_rank.get(old_status, 0):
        item["previous_exploitation_status"] = old_status
        item["exploitation_escalated_at"] = datetime.now(timezone.utc).isoformat()

    if signal_rank.get(new_signal, 0) > signal_rank.get(old_signal, 0):
        item["previous_signal_strength"] = old_signal
        item["signal_upgraded_at"] = datetime.now(timezone.utc).isoformat()

    return item


def save_to_supabase(items: list[dict[str, Any]]) -> int:
    saved = 0
    print(f"Saving {len(items)} items to Supabase...")

    for item in items:
        try:
            item = apply_escalation_metadata(item)
            result = supabase.table("daily_brief").upsert(item, on_conflict="url").execute()
            if result.data:
                saved += 1
        except Exception as exc:
            print(f"Warning: failed to save {item.get('title', 'item')[:70]}: {exc}")

    return saved


def print_summary(items: list[dict[str, Any]], saved: int) -> None:
    high = sum(1 for item in items if item.get("signal_strength") == "High")
    medium = sum(1 for item in items if item.get("signal_strength") == "Medium")
    active = sum(1 for item in items if item.get("exploitation_status") == "actively_exploited")
    poc = sum(1 for item in items if item.get("exploitation_status") == "poc_available")

    print("")
    print("Daily brief summary")
    print(f"  Saved: {saved}/{len(items)}")
    print(f"  High signal: {high}")
    print(f"  Medium signal: {medium}")
    print(f"  Actively exploited: {active}")
    print(f"  PoC available: {poc}")


def main() -> None:
    start = time.time()
    items = collect_rss_feeds()
    if not items:
        print("No items collected.")
        return

    saved = save_to_supabase(items)
    print_summary(items, saved)
    print(f"Completed in {time.time() - start:.1f}s")


if __name__ == "__main__":
    main()

