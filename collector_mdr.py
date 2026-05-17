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
from pathlib import Path
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


PROJECT_ROOT = Path(__file__).resolve().parent
load_dotenv(PROJECT_ROOT / ".env")

SUPABASE_URL = os.getenv("SUPABASE_URL") or os.getenv("NEXT_PUBLIC_SUPABASE_URL")
SUPABASE_KEY = (
    os.getenv("SUPABASE_KEY")
    or os.getenv("NEXT_PUBLIC_SUPABASE_ANON_KEY")
    or os.getenv("NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY")
)
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY")
SUPABASE_WRITE_KEY = SUPABASE_SERVICE_ROLE_KEY or SUPABASE_KEY

if not SUPABASE_URL or not SUPABASE_WRITE_KEY:
    raise RuntimeError(
        "Supabase credentials are required. Set SUPABASE_URL plus SUPABASE_SERVICE_ROLE_KEY "
        "for collector writes. NEXT_PUBLIC_SUPABASE_URL and NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY "
        "are supported for read-only app access."
    )

if not SUPABASE_SERVICE_ROLE_KEY:
    print(
        "Warning: SUPABASE_SERVICE_ROLE_KEY is not set. "
        "Collector writes may fail when Row Level Security is enabled."
    )

supabase: Client = create_client(SUPABASE_URL, SUPABASE_WRITE_KEY)

MAX_ITEMS_PER_SOURCE = int(os.getenv("MAX_ITEMS_PER_SOURCE", "15"))
NVD_DELAY_SECONDS = float(os.getenv("NVD_DELAY_SECONDS", "2"))

RSS_FEEDS = {
    "BleepingComputer": "https://www.bleepingcomputer.com/feed/",
    "Krebs on Security": "https://krebsonsecurity.com/feed/",
    "Schneier on Security": "https://www.schneier.com/feed/atom/",
    "The Hacker News": "https://feeds.feedburner.com/TheHackersNews",
    "Dark Reading": "https://www.darkreading.com/rss.xml",
}

WATCHLIST_KEYWORDS = {
    "Microsoft Exchange": ["exchange server", "microsoft exchange"],
    "Windows": ["windows", "windows server", "windows 11"],
    "Cisco": ["cisco", "sd-wan", "ios xe", "catalyst"],
    "Fortinet": ["fortinet", "fortigate", "fortios"],
    "VMware": ["vmware", "esxi", "vcenter"],
    "Chrome": ["chrome", "chromium"],
    "WordPress": ["wordpress", "woocommerce", "plugin"],
    "Supply Chain": ["supply chain", "npm", "pypi", "rubygems", "github token"],
    "OpenAI": ["openai", "chatgpt"],
}

NOISE_KEYWORDS = [
    "speaking engagement",
    "conference",
    "anniversary",
    "celebrates",
    "opinion",
    "pioneers ponder",
    "investments",
    "checkbox assessment",
    "squid blogging",
    "smart glasses",
    "polymarket",
]

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


def normalize_story_text(text: str) -> str:
    words = re.findall(r"[a-z0-9]+", text.lower())
    stop_words = {
        "the", "a", "an", "and", "or", "to", "of", "in", "on", "for", "with",
        "via", "new", "critical", "bug", "flaw", "vulnerability", "attack",
        "attacks", "exploited", "exploitation", "hackers", "security",
    }
    keywords = [word for word in words if len(word) > 2 and word not in stop_words]
    return "-".join(keywords[:8]) or "general-story"


def detect_watchlist_matches(title: str, summary: str) -> list[str]:
    text = f"{title} {summary}".lower()
    matches = [
        name
        for name, keywords in WATCHLIST_KEYWORDS.items()
        if any(keyword in text for keyword in keywords)
    ]
    return matches[:5]


def detect_noise_reason(title: str, summary: str, signal_strength: str, exploitation_status: str) -> str | None:
    if signal_strength != "Low" or exploitation_status in {"actively_exploited", "poc_available"}:
        return None

    text = f"{title} {summary}".lower()
    for keyword in NOISE_KEYWORDS:
        if keyword in text:
            return keyword

    return None


def classify_action_category(
    title: str,
    summary: str,
    event_type: str,
    exploitation_status: str,
    cisa_exploited: bool,
    cve_id: str | None,
) -> str:
    text = f"{title} {summary}".lower()

    if cisa_exploited or exploitation_status == "actively_exploited":
        return "Action Needed"
    if exploitation_status == "poc_available":
        return "Patch Soon"
    if "ransomware" in text or "malware" in text or "backdoor" in text or "botnet" in text:
        return "Malware"
    if "breach" in text or "data theft" in text or "stolen" in text or "leak" in text:
        return "Breach"
    if "supply chain" in text or "npm" in text or "pypi" in text or "rubygems" in text:
        return "Supply Chain"
    if cve_id or event_type == "Vulnerability":
        return "Watch"
    return "Awareness"


def build_story_key(
    title: str,
    cve_id: str | None,
    attack_name: str | None,
    primary_target: str,
) -> str:
    if cve_id:
        return f"cve:{cve_id.lower()}"
    if attack_name and primary_target != "Unspecified":
        return f"attack:{attack_name.lower()}:{primary_target.lower()}"
    if primary_target != "Unspecified":
        return f"target:{primary_target.lower()}:{normalize_story_text(title)}"
    return f"title:{normalize_story_text(title)}"


def build_productive_take(
    base_take: str,
    action_category: str,
    exploitation_status: str,
    cisa_exploited: bool,
    watchlist_matches: list[str],
    primary_target: str,
) -> str:
    checks: list[str] = []

    if action_category == "Action Needed":
        checks.append("prioritize exposure and patch status checks")
    elif action_category == "Patch Soon":
        checks.append("track patch status and monitor for active exploitation")
    elif action_category == "Malware":
        checks.append("review related detections and recent endpoint alerts")
    elif action_category == "Breach":
        checks.append("check whether the affected service or vendor touches your environment")
    elif action_category == "Supply Chain":
        checks.append("review dependency, token, and vendor exposure")
    elif action_category == "Watch":
        checks.append("keep on the watchlist unless exploitation evidence appears")

    if cisa_exploited:
        checks.append("treat CISA KEV listing as urgency signal")
    if watchlist_matches:
        checks.append(f"watchlist match: {', '.join(watchlist_matches[:3])}")
    elif primary_target != "Unspecified" and exploitation_status != "unknown":
        checks.append(f"affected area: {primary_target}")

    if not checks:
        return base_take

    return f"{base_take} Next: {'; '.join(checks)}."


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

    return _kev_cache or []


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
    watchlist_matches = detect_watchlist_matches(title, summary)
    action_category = classify_action_category(
        title,
        summary,
        event_data["event_type"],
        exploitation_status,
        cisa_exploited,
        cve_id,
    )
    noise_reason = detect_noise_reason(title, summary, signal_strength, exploitation_status)
    story_key = build_story_key(title, cve_id, attack_name, event_data["primary_target"])
    base_take = generate_mdr_analyst_take(
        event_data["event_type"],
        event_data["primary_target"],
        event_data["attack_vector"],
        exploitation_status,
        title,
        summary,
        cve_id,
        cve_data.get("cvss_score"),
        attack_name,
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
        "mdr_analyst_take": build_productive_take(
            base_take,
            action_category,
            exploitation_status,
            cisa_exploited,
            watchlist_matches,
            event_data["primary_target"],
        ),
        "technical_method": technical_method,
        "delta_reason": extract_delta_reason(title, summary, exploitation_status),
        "action_category": action_category,
        "watchlist_matches": watchlist_matches,
        "noise_reason": noise_reason,
        "story_key": story_key,
        "review_status": "New",
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
        .select("id, exploitation_status, signal_strength, reviewed_at, bookmarked, follow_up_required, review_status")
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
    item["reviewed_at"] = old_record.get("reviewed_at")
    item["bookmarked"] = bool(old_record.get("bookmarked") or False)
    item["follow_up_required"] = bool(old_record.get("follow_up_required") or False)
    item["review_status"] = old_record.get("review_status") or item.get("review_status") or "New"

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
            if "row-level security" in str(exc).lower() or "'code': '42501'" in str(exc):
                raise RuntimeError(
                    "Supabase blocked collector writes with Row Level Security. "
                    "Add SUPABASE_SERVICE_ROLE_KEY to .env for local collection and to "
                    "GitHub Actions secrets for scheduled collection. The service-role key "
                    "must stay server-side and must not be used in browser/client code."
                ) from exc
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
