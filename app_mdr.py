"""
Lean Cyber News Daily Brief

Streamlit dashboard focused on fast review of high-signal cyber news.
"""

from __future__ import annotations

import html
import os
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import streamlit as st
from dotenv import load_dotenv
from supabase import create_client

from date_utils import format_ist_datetime


PROJECT_ROOT = Path(__file__).resolve().parent
load_dotenv(PROJECT_ROOT / ".env")

SOURCES = [
    "BleepingComputer",
    "The Hacker News",
    "Krebs on Security",
    "Dark Reading",
    "Schneier on Security",
]

REVIEW_STATUSES = ["New", "Monitoring", "Action Needed", "Reviewed", "Ignored"]
PRIORITY_ACTIONS = {"Action Needed", "Patch Soon", "Malware", "Supply Chain", "Breach"}

st.set_page_config(
    page_title="Cyber News Daily Brief",
    page_icon=":newspaper:",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
<style>
:root {
    --bg-card: #151922;
    --bg-soft: #10141d;
    --border: #2b3240;
    --text-muted: #9aa4b2;
    --red: #ef4444;
    --amber: #f59e0b;
    --green: #10b981;
    --blue: #3b82f6;
}
.brief-card {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-left: 5px solid var(--border);
    border-radius: 8px;
    padding: 18px;
    margin: 0 0 14px 0;
}
.brief-card.high { border-left-color: var(--red); }
.brief-card.medium { border-left-color: var(--amber); }
.brief-card.watch { box-shadow: 0 0 0 1px rgba(59,130,246,0.22) inset; }
.badge {
    display: inline-block;
    border-radius: 999px;
    padding: 4px 10px;
    margin: 0 6px 6px 0;
    font-size: 12px;
    font-weight: 700;
    line-height: 1.2;
    border: 1px solid rgba(255,255,255,0.18);
}
.badge.red { background: rgba(239,68,68,0.18); color: #fecaca; border-color: rgba(239,68,68,0.45); }
.badge.amber { background: rgba(245,158,11,0.18); color: #fde68a; border-color: rgba(245,158,11,0.45); }
.badge.green { background: rgba(16,185,129,0.16); color: #bbf7d0; border-color: rgba(16,185,129,0.4); }
.badge.blue { background: rgba(59,130,246,0.16); color: #bfdbfe; border-color: rgba(59,130,246,0.4); }
.badge.gray { background: rgba(148,163,184,0.12); color: #cbd5e1; border-color: rgba(148,163,184,0.3); }
.card-title {
    font-size: 20px;
    line-height: 1.3;
    margin: 4px 0 10px 0;
    font-weight: 750;
}
.summary {
    color: #d5dae3;
    line-height: 1.55;
    margin: 10px 0 12px 0;
}
.analyst-take {
    background: rgba(59,130,246,0.12);
    border-left: 3px solid var(--blue);
    border-radius: 6px;
    padding: 12px;
    margin-top: 12px;
    line-height: 1.5;
}
.meta {
    display: flex;
    flex-wrap: wrap;
    gap: 12px;
    color: var(--text-muted);
    font-size: 13px;
    margin-top: 12px;
}
.story-note {
    color: var(--text-muted);
    font-size: 13px;
    margin-top: 8px;
}
@media (max-width: 640px) {
    .brief-card { padding: 14px; }
    .card-title { font-size: 18px; }
}
</style>
""",
    unsafe_allow_html=True,
)


def safe_text(value: Any, fallback: str = "") -> str:
    if value is None:
        return fallback
    return html.escape(str(value))


def as_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value if item]
    if isinstance(value, str) and value.strip():
        return [value.strip()]
    return []


@st.cache_resource
def init_supabase():
    url = os.getenv("SUPABASE_URL") or os.getenv("NEXT_PUBLIC_SUPABASE_URL")
    key = (
        os.getenv("SUPABASE_KEY")
        or os.getenv("NEXT_PUBLIC_SUPABASE_ANON_KEY")
        or os.getenv("NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY")
    )

    if not url or not key:
        try:
            url = st.secrets.get("SUPABASE_URL") or st.secrets.get("NEXT_PUBLIC_SUPABASE_URL")
            key = (
                st.secrets.get("SUPABASE_KEY")
                or st.secrets.get("NEXT_PUBLIC_SUPABASE_ANON_KEY")
                or st.secrets.get("NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY")
            )
        except Exception:
            pass

    if not url or not key:
        st.error("Missing Supabase credentials.")
        st.info(
            "Set SUPABASE_URL and SUPABASE_KEY, or NEXT_PUBLIC_SUPABASE_URL and "
            "NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY, in Streamlit secrets or a local .env file."
        )
        st.stop()

    return create_client(url, key)


supabase = init_supabase()

st.title("Cyber News Daily Brief")
st.caption("A focused feed for spotting what matters, skipping noise, and keeping daily review short.")

st.sidebar.header("Filters")

quick_view = st.sidebar.selectbox(
    "Quick view",
    ["Priority Queue", "All Items", "Watchlist", "Action Needed", "Follow Up", "Weekly Digest"],
)

time_range = st.sidebar.selectbox(
    "Time range",
    ["Today", "Last 3 Days", "Last 7 Days", "Last 30 Days"],
    index=2,
)

selected_sources = st.sidebar.multiselect("Sources", SOURCES, default=SOURCES)

signal_filter = st.sidebar.multiselect(
    "Signal strength",
    ["High", "Medium", "Low"],
    default=["High", "Medium"] if quick_view != "All Items" else ["High", "Medium", "Low"],
)

exploit_filter = st.sidebar.multiselect(
    "Exploitation status",
    ["actively_exploited", "poc_available", "theoretical", "unknown"],
    default=["actively_exploited", "poc_available"] if quick_view == "Priority Queue" else [
        "actively_exploited",
        "poc_available",
        "theoretical",
        "unknown",
    ],
)

review_filter = st.sidebar.multiselect(
    "Review status",
    REVIEW_STATUSES,
    default=["New", "Monitoring", "Action Needed"],
)

source_confidence_filter = st.sidebar.multiselect(
    "Source confidence",
    ["High", "Medium", "Low"],
    default=["High", "Medium", "Low"],
)

hide_noise = st.sidebar.checkbox("Hide likely noise", value=True)
group_duplicates = st.sidebar.checkbox("Group duplicate stories", value=True)


def range_start(selected_range: str) -> datetime:
    now = datetime.now(timezone.utc)
    if selected_range == "Today":
        return now.replace(hour=0, minute=0, second=0, microsecond=0)
    if selected_range == "Last 3 Days":
        return now - timedelta(days=3)
    if selected_range == "Last 30 Days":
        return now - timedelta(days=30)
    return now - timedelta(days=7)


def fetch_items() -> list[dict[str, Any]]:
    query = supabase.table("daily_brief").select("*")

    if signal_filter:
        query = query.in_("signal_strength", signal_filter)
    if exploit_filter:
        query = query.in_("exploitation_status", exploit_filter)
    if source_confidence_filter:
        query = query.in_("source_confidence", source_confidence_filter)

    query = query.gte("published_at", range_start(time_range).isoformat())
    query = query.order("published_at", desc=True)

    result = query.execute()
    return result.data if isinstance(result.data, list) else []


def item_review_status(item: dict[str, Any]) -> str:
    if item.get("review_status"):
        return str(item["review_status"])
    if item.get("reviewed_at"):
        return "Reviewed"
    if item.get("follow_up_required"):
        return "Action Needed"
    return "New"


def apply_client_filters(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    filtered = []

    for item in items:
        if selected_sources and item.get("source") not in selected_sources:
            continue
        if review_filter and item_review_status(item) not in review_filter:
            continue
        if hide_noise and item.get("noise_reason"):
            continue

        action_category = str(item.get("action_category") or "Awareness")
        watchlist_matches = as_list(item.get("watchlist_matches"))

        if quick_view == "Priority Queue":
            if action_category not in PRIORITY_ACTIONS and not watchlist_matches:
                continue
        elif quick_view == "Watchlist" and not watchlist_matches:
            continue
        elif quick_view == "Action Needed" and action_category != "Action Needed":
            continue
        elif quick_view == "Follow Up" and not item.get("follow_up_required"):
            continue

        filtered.append(item)

    return filtered


def story_groups(items: list[dict[str, Any]]) -> list[list[dict[str, Any]]]:
    if not group_duplicates:
        return [[item] for item in items]

    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in items:
        key = str(item.get("story_key") or item.get("cve_id") or item.get("url") or item.get("id"))
        grouped[key].append(item)

    groups = list(grouped.values())
    groups.sort(key=lambda group: str(group[0].get("published_at") or ""), reverse=True)
    return groups


def badge(text: str, color: str = "gray") -> str:
    return f'<span class="badge {color}">{html.escape(text)}</span>'


def exploitation_badge(status: str) -> str:
    labels = {
        "actively_exploited": ("Actively exploited", "red"),
        "poc_available": ("PoC available", "amber"),
        "theoretical": ("Theoretical", "green"),
        "unknown": ("Unknown", "gray"),
    }
    label, color = labels.get(status, ("Unknown", "gray"))
    return badge(label, color)


def signal_badge(signal: str) -> str:
    colors = {"High": "red", "Medium": "amber", "Low": "gray"}
    return badge(f"{signal} signal", colors.get(signal, "gray"))


def action_badge(action_category: str) -> str:
    colors = {
        "Action Needed": "red",
        "Patch Soon": "amber",
        "Watch": "blue",
        "Breach": "amber",
        "Malware": "red",
        "Supply Chain": "amber",
        "Awareness": "gray",
    }
    return badge(action_category, colors.get(action_category, "gray"))


def primary_item(group: list[dict[str, Any]]) -> dict[str, Any]:
    status_rank = {"actively_exploited": 4, "poc_available": 3, "theoretical": 2, "unknown": 1}
    signal_rank = {"High": 3, "Medium": 2, "Low": 1}
    return sorted(
        group,
        key=lambda item: (
            status_rank.get(str(item.get("exploitation_status")), 0),
            signal_rank.get(str(item.get("signal_strength")), 0),
            str(item.get("published_at") or ""),
        ),
        reverse=True,
    )[0]


def update_item(article_id: Any, payload: dict[str, Any]) -> None:
    supabase.table("daily_brief").update(payload).eq("id", article_id).execute()
    st.rerun()


def render_card(group: list[dict[str, Any]], index: int) -> None:
    item = primary_item(group)
    signal = str(item.get("signal_strength") or "Low")
    status = str(item.get("exploitation_status") or "unknown")
    action_category = str(item.get("action_category") or "Awareness")
    watchlist_matches = as_list(item.get("watchlist_matches"))
    card_weight = "high" if signal == "High" else "medium" if signal == "Medium" else ""
    watch_class = "watch" if watchlist_matches else ""

    chips = [
        action_badge(action_category),
        exploitation_badge(status),
        signal_badge(signal),
        badge(str(item.get("event_type") or "News"), "blue"),
    ]

    if item.get("cve_id"):
        cve_text = str(item["cve_id"])
        if item.get("cvss_score"):
            cve_text = f"{cve_text} / CVSS {item['cvss_score']}"
        chips.append(badge(cve_text, "amber"))

    if item.get("cisa_exploited"):
        chips.append(badge("CISA KEV", "red"))

    for watch in watchlist_matches[:3]:
        chips.append(badge(f"Watch: {watch}", "blue"))

    summary = safe_text(item.get("summary"), "No summary available.")
    analyst_take = safe_text(item.get("mdr_analyst_take"))
    source = safe_text(item.get("source"), "Unknown source")
    published = format_ist_datetime(item.get("published_at"), "%d %b %Y %H:%M IST")
    confidence = safe_text(item.get("source_confidence"), "Unknown")
    target = safe_text(item.get("primary_target"), "Unspecified")
    review_status = safe_text(item_review_status(item))

    duplicate_note = ""
    if len(group) > 1:
        sources = sorted({str(row.get("source") or "Unknown") for row in group})
        duplicate_note = (
            f'<div class="story-note">Grouped story: {len(group)} reports from '
            f'{safe_text(", ".join(sources))}</div>'
        )

    report_html = ""
    if analyst_take:
        report_html = f'<div class="analyst-take"><strong>Analyst take:</strong> {analyst_take}</div>'

    card_html = (
        f'<article class="brief-card {card_weight} {watch_class}">'
        f"<div>{''.join(chips)}</div>"
        f'<div class="card-title">{safe_text(item.get("title"), "Untitled")}</div>'
        f'<div class="summary">{summary}</div>'
        f"{report_html}"
        f"{duplicate_note}"
        '<div class="meta">'
        f"<span>{source}</span>"
        f"<span>{published}</span>"
        f"<span>{confidence} confidence</span>"
        f"<span>Target: {target}</span>"
        f"<span>Status: {review_status}</span>"
        "</div>"
        "</article>"
    )

    st.markdown(card_html, unsafe_allow_html=True)

    with st.expander("Details and actions"):
        if len(group) > 1:
            st.markdown("**Related reports:**")
            for related in group:
                st.markdown(f"- [{related.get('source', 'Unknown')}: {related.get('title', 'Untitled')}]({related.get('url', '#')})")
            st.divider()

        if item.get("signal_strength_reason"):
            st.markdown(f"**Why this signal:** {item['signal_strength_reason']}")
        if item.get("technical_method"):
            st.markdown(f"**Technical method:** {item['technical_method']}")
        if item.get("impact_outcome") and item.get("impact_outcome") != "Unknown":
            st.markdown(f"**Impact:** {item['impact_outcome']}")
        if item.get("noise_reason"):
            st.markdown(f"**Noise reason:** {item['noise_reason']}")
        if item.get("mitre_tactics") or item.get("mitre_techniques"):
            st.markdown("**MITRE ATT&CK:**")
            if item.get("mitre_tactics"):
                st.write(", ".join(as_list(item["mitre_tactics"])))
            if item.get("mitre_techniques"):
                st.write(", ".join(as_list(item["mitre_techniques"])))
        if item.get("kill_chain_phases"):
            st.markdown(f"**Kill chain:** {', '.join(as_list(item['kill_chain_phases']))}")

        article_id = item.get("id")
        col1, col2, col3, col4, col5 = st.columns(5)

        with col1:
            if st.button("Reviewed", key=f"review_{article_id}_{index}", use_container_width=True):
                update_item(article_id, {"reviewed_at": datetime.now(timezone.utc).isoformat(), "review_status": "Reviewed"})
        with col2:
            if st.button("Monitor", key=f"monitor_{article_id}_{index}", use_container_width=True):
                update_item(article_id, {"review_status": "Monitoring"})
        with col3:
            if st.button("Action", key=f"action_{article_id}_{index}", use_container_width=True):
                update_item(article_id, {"follow_up_required": True, "review_status": "Action Needed"})
        with col4:
            if st.button("Ignore", key=f"ignore_{article_id}_{index}", use_container_width=True):
                update_item(article_id, {"reviewed_at": datetime.now(timezone.utc).isoformat(), "review_status": "Ignored"})
        with col5:
            st.link_button("Read", str(item.get("url") or "#"), use_container_width=True)

        if st.button("Bookmark", key=f"bookmark_{article_id}_{index}", use_container_width=True):
            update_item(article_id, {"bookmarked": True})


def render_summary(items: list[dict[str, Any]], groups: list[list[dict[str, Any]]]) -> None:
    high_count = sum(1 for item in items if item.get("signal_strength") == "High")
    active_count = sum(1 for item in items if item.get("exploitation_status") == "actively_exploited")
    watch_count = sum(1 for item in items if as_list(item.get("watchlist_matches")))
    follow_count = sum(1 for item in items if item.get("follow_up_required") or item_review_status(item) == "Action Needed")

    col1, col2, col3, col4, col5 = st.columns(5)
    col1.metric("Stories", len(groups))
    col2.metric("Items", len(items))
    col3.metric("High signal", high_count)
    col4.metric("Actively exploited", active_count)
    col5.metric("Follow-up", follow_count)

    if watch_count:
        st.caption(f"{watch_count} item(s) match your watchlist.")


def render_weekly_digest(items: list[dict[str, Any]]) -> None:
    st.subheader("Weekly Digest")

    action_counts = Counter(str(item.get("action_category") or "Awareness") for item in items)
    vendors = Counter()
    cves = Counter()
    sources = Counter()

    for item in items:
        sources.update([str(item.get("source") or "Unknown")])
        cve = item.get("cve_id")
        if cve:
            cves.update([str(cve)])
        for match in as_list(item.get("watchlist_matches")):
            vendors.update([match])

    col1, col2, col3 = st.columns(3)
    with col1:
        st.markdown("**Action mix**")
        st.write(dict(action_counts.most_common(6)) or "No data")
    with col2:
        st.markdown("**Top watchlist hits**")
        st.write(dict(vendors.most_common(6)) or "No watchlist hits")
    with col3:
        st.markdown("**Top CVEs**")
        st.write(dict(cves.most_common(6)) or "No CVEs")

    st.markdown("**Open follow-ups**")
    followups = [item for item in items if item.get("follow_up_required") or item_review_status(item) == "Action Needed"]
    if followups:
        for item in followups[:10]:
            st.markdown(f"- **{item.get('source', 'Unknown')}**: [{item.get('title', 'Untitled')}]({item.get('url', '#')})")
    else:
        st.caption("No open follow-ups in this range.")


with st.spinner("Loading brief..."):
    try:
        raw_items = fetch_items()
    except Exception as exc:
        st.error(f"Database query failed: {exc}")
        st.stop()

items = apply_client_filters(raw_items)
groups = story_groups(items)

if not items:
    st.warning("No articles match the current filters.")
    st.info("Try widening the filters or run `python collector_mdr.py` to collect fresh news.")
    st.stop()

render_summary(items, groups)

if quick_view == "Weekly Digest":
    st.divider()
    render_weekly_digest(items)
    st.stop()

st.divider()

for idx, group in enumerate(groups):
    render_card(group, idx)
